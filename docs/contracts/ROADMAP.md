# Implementation roadmap contract

## For agents

| Check | Action |
|---|---|
| Phase | **Phase 1 / SLICE-1 complete**; **SLICE-2 pending** (separate human approval) — **no** FastAPI, live adapter, or router I/O |
| Code entry | **SLICE-1 delivered**; **SLICE-2 blocked** until new human approval (`code_may_start=false`; `approved_scope` remains SLICE-1) |
| Gates A–D | Remain **independent switches** — opening one gate does **not** imply certification of another; **no slice implies NC-1812 certification** |
| Sequence | **11** dependency-ordered slices (SLICE-1..11) align ADR-0001/0002/0003/0004 capability ladder — do not reorder without ADR amendment |
| Slices after routes | SLICE-8 TrafficDiscovery → SLICE-9 NetworkPolicy → SLICE-10 Hub (`module_3.0`) → SLICE-11 zone/cutover/rehearsal (ADR-0004 §Capability order) |
| Hub isolation | Router Control failure must not block kiosk, board, printing, or Hub startup ([`ARCHITECTURE.md`](../ARCHITECTURE.md)) |
| Strangler | Legacy `ScanCursorIP` remains fallback until parity, rehearsal, and explicit cutover ([`SCENARIOS.md`](SCENARIOS.md) `SCN-CUT-*`) |
| Trace | [`RCI_POLICY.md`](RCI_POLICY.md), [`HARDWARE_GATES.md`](HARDWARE_GATES.md), [`SECURITY_OPS.md`](SECURITY_OPS.md), [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md), [`API_CONTRACT.md`](API_CONTRACT.md), [`TEST_STRATEGY.md`](TEST_STRATEGY.md), [`SCENARIOS.md`](SCENARIOS.md), [`AI_HANDOFF.md`](AI_HANDOFF.md) |

---

## 1. Purpose and scope

This document is the **normative implementation roadmap** between Phase 0b contracts and future production code. It defines dependency-ordered slices, entry/exit gates, owned deliverables, verification evidence, and rollback/stop conditions.

**Phase 0b:** complete (Wave 7 closeout). **Phase 1 / SLICE-1:** complete (2026-07-21). **Phase 1 / SLICE-2:** pending — separate human approval required.

**Global entry gate (all slices):** Phase 0b `complete: true` **and** `implementation_transition_gate.human_approved=true` **and** `code_may_start=true` in [`STATUS.yaml`](../STATUS.yaml) before any owned product code path is created. **SLICE-1 gate satisfied and delivered** (approved 2026-07-21). **SLICE-2+** require expanded human approval; current `approved_scope` remains SLICE-1.

---

## 2. Global prohibitions (all slices)

| Rule | Enforcement |
|---|---|
| Unknown identity, firmware, capability, or profile | **Fail closed** — no write dispatch ([`HARDWARE_GATES.md`](HARDWARE_GATES.md) §5) |
| Closed applicable gate | Live observe → **403** `gate.a_closed`; write dispatch → **403** `gate.mutation_forbidden` |
| Secrets in repo/docs/fixtures/logs | Forbidden — DPAPI opaque refs only ([`SECURITY_OPS.md`](SECURITY_OPS.md)) |
| Invented RCI JSON bodies | Forbidden — recorded evidence binds sanitized manifests only |
| Hub failure isolation | RC degraded/disabled must not block Hub core services |
| Certification claims | No slice completion may claim AWG/route/firmware certification without gate evidence package |

### 2.1 Hub isolation / strangler (per-slice applicability)

| Slice range | Hub isolation / strangler |
|---|---|
| SLICE-1..9 | **N/A** until SLICE-10 (Hub embed) / SLICE-11 (cutover); global For-agents rows (Hub isolation, strangler) still bind for all work |
| SLICE-10..11 | Hub failure isolation and strangler fallback are **owned deliverables** — see slice tables |

---

## 3. Implementation slices (dependency order)

**Eleven slices** in ADR-0004-aligned order. Portable core through routes (SLICE-1..7) precede TrafficDiscovery and NetworkPolicy; Hub integration and zone/cutover follow.

### SLICE-1 — Portable core + FakeRouterAdapter

| Field | Content |
|---|---|
| **Prerequisites** | Phase 0b closed; human approval to implementation; ADR-0001 accepted |
| **Non-goals** | FastAPI host; SQLite; live network; Hub wiring; hardware gates |
| **Owned deliverables** | Python package `router_control` (domain + application ports); vendor-neutral `RouterControlPort`; in-memory `FakeRouterAdapter` with step kinds per [`RCI_POLICY.md`](RCI_POLICY.md) §5 |
| **Entry gate** | `implementation_transition_gate.human_approved=true` and `code_may_start=true` (human sets after Phase 0b close) |
| **Exit gate** | Domain invariants pass fake-only tests; package importable without FastAPI/network |
| **Verification / evidence** | TEST lane **2** (fake/domain); pyramid unit/domain layer ([`TEST_STRATEGY.md`](TEST_STRATEGY.md) §3) |
| **Rollback / stop** | Stop on invariant violation or gate predicate bug; no partial "live" adapter |

### SLICE-2 — Persistence / jobs (SQLite)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-1 exit; ADR-0002 accepted |
| **Non-goals** | HTTP surface; live router; Hub integration |
| **Owned deliverables** | `data/router_control.sqlite3` schema v0; migrations; revisions/ETag; durable jobs, leases, idempotency, audit per [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) |
| **Entry gate** | SLICE-1 complete **and** new human approval recorded in [`STATUS.yaml`](../STATUS.yaml) with `approved_scope: SLICE-2` **and** `code_may_start=true` (SLICE-1 approval alone does **not** authorize SLICE-2 code) |
| **Exit gate** | Persistence fault matrix (§8.7) passes injected SQLite tests; two-worker claim + fencing demonstrated |
| **Verification / evidence** | TEST lane **2** + fault injection; no secrets in DB dumps |
| **Rollback / stop** | Stop on schema drift without migration; unknown migration → fail closed |

### SLICE-3 — API / FastAPI dev host (prototype; not Hub)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-2 exit; ADR-0001 accepted |
| **Non-goals** | Hub `module_3.0` wiring; production zone policy enforcement; hardware I/O |
| **Owned deliverables** | Separate FastAPI dev-host in canonical repo; routes under `/api/router-control/v1/*` per [`API_CONTRACT.md`](API_CONTRACT.md); auth order §2; mutation gates closed |
| **Entry gate** | SLICE-2 complete |
| **Exit gate** | Contract/static + fake integration tests for auth, idempotency, ETag, error codes; **no** live observe/write dispatch |
| **Verification / evidence** | TEST lanes **1–2**; SCN-OPS/SCN-NEG trace via fake adapter |
| **Rollback / stop** | Stop if OpenAPI diverges from contract without contract amendment; gates remain closed |

### SLICE-4 — Gate A read-only adapter (NC-1812 observe)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-3 exit; dedicated NC-1812 identity tuple; Gate **A** human open per [`HARDWARE_GATES.md`](HARDWARE_GATES.md) |
| **Non-goals** | Write dispatch; Gate B/C/D; certification of mutation families |
| **Owned deliverables** | Read-only `RouterAdapter` transport; enroll/preflight/observe legs; sanitized Gate A evidence package |
| **Entry gate** | Gate **A** explicitly open for exact router identity/firmware tuple |
| **Exit gate** | Recorded read-only evidence; `Enrolled` lifecycle path verified; identity mismatch fail-closed |
| **Verification / evidence** | TEST lane **4**; SCN-OPS-002, SCN-NEG-003/005; **not** write certification |
| **Rollback / stop** | Close Gate A on identity drift, tuple change, or failed read-back; revert to fake/recorded-only |

### SLICE-5 — Vault / credentials (DPAPI CredentialRef)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-3 exit (may parallel SLICE-4 after dev-host); ADR-0003 accepted |
| **Non-goals** | Plaintext API read-back; fleet-wide operator key recovery |
| **Owned deliverables** | Local vault: opaque `CredentialRef` + DPAPI `CurrentUser`; write/rotate/revoke without read-back ([`SECURITY_OPS.md`](SECURITY_OPS.md) §4) |
| **Entry gate** | SLICE-3 complete; Windows Hub user context defined for prototype |
| **Exit gate** | SCN-OPS-003 credentials path; redaction scans pass; no secrets in audit/plan/job payloads |
| **Verification / evidence** | TEST lane **2** + security negatives; SCN-EVT-001/004 trace |
| **Rollback / stop** | Stop on any plaintext leak surface; revoke refs on compromise |

### SLICE-6 — AWG Gate B then Gate C (family writes + lab window)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-4 + SLICE-5 exit; AWG family allowlist certified; Gates **B** then **C** opened separately |
| **Non-goals** | Gate D production enablement; route benchmark; Hub integration |
| **Owned deliverables** | AWG apply/verify sequence on lab router; Fail-safe Configuration narrative; per-family Gate B evidence; time-boxed Gate C lab window |
| **Entry gate** | Gate **B** per AWG family; then Gate **C** lab window with operator approval |
| **Exit gate** | Sanitized lab evidence package; SCN-LAB-001 spec satisfied; read-back verify before `applied_revision` |
| **Verification / evidence** | TEST lanes **5–6**; [`COMPATIBILITY.md`](../COMPATIBILITY.md) AWG unknowns resolved for tuple |
| **Rollback / stop** | Close Gates B/C on failed verify; compensation per RCI §5; **not** Gate D |

### SLICE-7 — Routes benchmark

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-6 exit (AWG path stable); lab router available |
| **Non-goals** | Production route ceiling claim without measured evidence; Gate D |
| **Owned deliverables** | Benchmark protocol 100 → 1k → 5k routes; measured production ceiling; SCN-LAB-002 evidence |
| **Entry gate** | Gate **C** lab window; route family Gate **B** evidence |
| **Exit gate** | Recorded benchmark artifacts; ADR-004 ceiling documented from measurement |
| **Verification / evidence** | TEST lanes **6–7** spec; no assumption of 5000 without benchmark pass |
| **Rollback / stop** | Stop on timeout/degraded management; do not raise production limit without evidence |

### SLICE-8 — TrafficDiscovery (bounded context; proposals only)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-7 exit (routes path stable); ADR-0004 accepted |
| **Non-goals** | Direct route mutation; auto-apply of untrusted proposals; Gate D; Hub `module_3.0` wiring |
| **Owned deliverables** | Separate `TrafficDiscovery` bounded context; timestamped evidence; `RouteProposal` with TTL/confidence; operator review default; auto-apply only for explicitly marked trusted policy with plan/idempotency/ownership/verify gates |
| **Entry gate** | SLICE-7 complete; persistence tables for `traffic_observations` / `route_proposals` per [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) |
| **Exit gate** | Proposals emitted without direct router writes; untrusted auto-apply blocked; legacy strangler path documented until parity |
| **Verification / evidence** | TEST lane **2** + domain; [`LEGACY_MAP.md`](../LEGACY_MAP.md) parity checklist; no hidden direct-push |
| **Rollback / stop** | Stop on dual-writer with legacy monitor; disable auto-apply on policy ambiguity |

### SLICE-9 — NetworkPolicy (four-zone policy)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-8 exit; ADR-0004 accepted; zone scenarios in [`SCENARIOS.md`](SCENARIOS.md) |
| **Non-goals** | Hub `module_3.0` embed; Gate D production enablement; zone substituting `hub_admin` |
| **Owned deliverables** | Guest/Promo/Staff/Admin-Server firewall/VLAN intent; deny paths for Guest/Promo/Staff to RC prefix; Admin zone + auth complementarity; SCN-ZONE-* enforcement spec |
| **Entry gate** | SLICE-8 complete; HTTPS order-page infrastructure prerequisites documented |
| **Exit gate** | Zone matrix verified in lab/staging; **zone ≠ auth** enforced; RC API fail-closed on shared listener |
| **Verification / evidence** | SCN-ZONE-001..005; [`SECURITY_OPS.md`](SECURITY_OPS.md) §8; [`ARCHITECTURE.md`](../ARCHITECTURE.md) §4 |
| **Rollback / stop** | Revert to baseline firewall; do not open Gate D from zone work alone |

### SLICE-10 — Hub integration phase 8 (`module_3.0`)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-3..9 parity on prototype; ADR-0001 integration phase; Hub bootstrap/deps/lifespan patterns understood |
| **Non-goals** | Production cutover; Gate D |
| **Owned deliverables** | Mechanical embed of `router_control` into Hub; shared listener `/api/router-control/v1/*`; UI block in `/settings`; **failure isolation** verified |
| **Entry gate** | Prototype slices 1–9 exit; Hub maintainer approval for integration branch |
| **Exit gate** | Hub starts with RC disabled/degraded without blocking kiosk/board/printing; integration tests on fake adapter |
| **Verification / evidence** | ARCHITECTURE §9 acceptance; SCN-JOB-009 isolation; TEST failure-isolation matrix |
| **Rollback / stop** | Feature flag / RC `Disabled` path; Hub continues if RC DB worker fails |

### SLICE-11 — Zone / cutover / rehearsal (strangler fallback; Gate D separate)

| Field | Content |
|---|---|
| **Prerequisites** | SLICE-10 exit; four-zone network policy deployed (SLICE-9); strangler parity checklist |
| **Non-goals** | Silent production cutover; conflating Gate D with lab Gates B/C |
| **Owned deliverables** | Zone matrix enforcement (Guest/Promo/Staff/Admin); cutover rehearsal; rollback to legacy `ScanCursorIP`; Gate **D** production enablement evidence |
| **Entry gate** | Gate **D** explicitly open for production tuple; operator acceptance of rehearsal |
| **Exit gate** | SCN-CUT-001/002 satisfied; documented fallback; production writes only with Gate D + maintained B |
| **Verification / evidence** | SCN-ZONE-* + SCN-CUT-*; field rehearsal log (no secrets) |
| **Rollback / stop** | **Strangler fallback** to legacy on failed cutover; close Gate D; RC `Disabled` — Hub continues |

---

## 4. Gate ladder reference (independent switches)

| Gate | Opens | Does **not** imply |
|---|---|---|
| **A** | Live read-only observe/preflight | Write certification, B/C/D, AWG support |
| **B** | Per-family automated write dispatch | Lab window (C), production (D), full product certification |
| **C** | Time-boxed lab mutations | Event production writes |
| **D** | Production enablement on enrolled router | Retroactive certification of A/B/C evidence |

See [`HARDWARE_GATES.md`](HARDWARE_GATES.md) for tuple binding and fail-closed table.

---

## 5. Phase 0b Definition of Done (Wave 7 — Phase 0b closed)

Wave 6 satisfied partial Phase 0b exit when roadmap and AI handoff were authored. **Phase 0b is now closed** (Wave 7 closeout). **Phase 1 / SLICE-1 complete** (2026-07-21). **Phase 1 / SLICE-2 pending** — requires separate human approval before persistence code.

---

## 6. Links

- AI agent cold-start and task contracts: [`AI_HANDOFF.md`](AI_HANDOFF.md)
- Hardware gates: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- Test lanes and evidence: [`TEST_STRATEGY.md`](TEST_STRATEGY.md)
- Operator scenarios: [`SCENARIOS.md`](SCENARIOS.md)
- Architecture and Hub isolation: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- Contracts index: [`README.md`](README.md)
- Project status: [`STATUS.yaml`](../STATUS.yaml)
