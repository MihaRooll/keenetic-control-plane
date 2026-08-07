# AI agent handoff contract

## For agents

| Check | Action |
|---|---|
| Phase | **P3 shared typed executor complete** (2026-07-23; offline/default-deny; **Certified registry empty; not live-ready**); both fail-safe trials consumed **completed_failed**; **2026-08-05:** WG **`tunnel_healthy`** + **`SET_IP_ADDRESS`** + **`wireguard_ip_global`** DEVICE-VERIFIED (§M-24..§M-27); traffic via tunnel **reversible**; kill-switch/named policy/IPv6 routes **NOT done**; **2026-08-01 offline sessions (NOT device-verified)** |
| SSOT | Read [`STATUS.yaml`](../STATUS.yaml) **before** any claim about deliverables, phase, or gates |
| Code | SLICE-1..4 + offline mega + SLICE-6 AWG runner delivered; M1–M3 scope = offline/read-only only |
| Gates | **A open** ReadOnlyCertified (SSOT post-WG `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 physical replacement, rebind #2 post-WG identity drift); **B** fail_safe **completed_failed** (trials `110000Z` + prior `094500Z`; historical CertificationTrialAuthorized; not WriteCertified); **C closed** completed_failed; **D closed** — host writes fail-closed |
| Dual-homed lab | Overlapping `192.168.1.0/24` (Ethernet + Wi‑Fi) requires explicit `--source-address 192.168.2.10` on every live observe CLI (historical pre-migration: `192.168.1.144`); **future live mutations** additionally require WAN isolation or physical uplink disconnect — source binding alone does not authorize writes |
| Authorization | User authorization 2026-07-22: M1–M3 offline/read-only only (forbids ungated live mutations, write-gate opens, WriteCertified claims). **Dedicated lab program** (2026-07-22+): project-owned NC-1812 HW validation in scope; Gate A RO + offline harness/fixture/cert prep OK. **Expendable envelope** (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router` + live tuple matches recorded identity): bounded save/reboot/install/firmware/reset, all APs/WG interfaces, SSH enable — **no per-action confirmation** per [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) §1a and [`STATUS.yaml`](../STATUS.yaml) `approvals.dedicated_development_router_lab`. **Non-expendable** standing auth and **carve-outs** still require explicit per-action human confirmation; fail-closed when live device ≠ recorded tuple. Does **not** open Gates B/C/D or claim WriteCertified. Hub `module_3.0` integration and signed central pull remain unauthorized |
| Secrets | Never add passwords, keys, sessions, startup-config, or real device IDs to repo/docs |
| Docs update | Change STATUS + project-state + docs-map + navigation **atomically**; run `scripts/validate-project-docs.ps1` |
| Next task | **`local-hub-vpn-real-peer-autoconnect-continuation`** per [`STATUS.yaml`](../STATUS.yaml) `next_task` — VPN handshake + traffic via tunnel **device-verified** (§M-24..§M-27); station apply **live** (§M-34). **Parallel deferred:** VPN named policy / kill-switch live apply (offline preview only; kill-switch `permit global` **unresolved**; **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** §M-24/M-27) — [`OPERATOR_UI.md`](../OPERATOR_UI.md), [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](../OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md); active handoff [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) |
| Trace | ADR-0005 + eight STATUS contract deliverables (§8) + [`ROADMAP.md`](ROADMAP.md) milestone DAG |

---

## 1. Cold-start read order

Read in this order at session start (after [`AGENTS.md`](../../AGENTS.md)):

1. [`README.md`](../../README.md) — purpose, boundaries, current phase summary
2. [`docs/STATUS.yaml`](../STATUS.yaml) — **authoritative** phase, deliverables, blockers, next task, `implementation_transition_gate`
3. [`docs/DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) — dedicated NC-1812 lab ownership; program vs action; Gate A RO vs T4 mutations
4. [`docs/CANONICAL.md`](../CANONICAL.md) — locked legacy facts and domain invariants
5. [`docs/contracts/README.md`](README.md) — contracts program and Wave navigation
6. **This document** — handoff rules, task template, verification expectations
7. [`docs/SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) — **active** real-router lab handoff (2026-08-01/02 session: Gate A parser recert, guest AP3 live; **capability banner** — superseded Address/handshake/traffic claims → [`STATUS.yaml`](../STATUS.yaml) + `.cursor/plans/main-decisions-local-hub.md` §M-24+); historical methods: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md), [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md), [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md)
   - **Recommended (methodology):** [`docs/ENGINEERING_LESSONS.md`](../ENGINEERING_LESSONS.md) — transferable lab judgement, offline-reliability traps, and agent-delegation lessons (L-1..L-20, D-1..D-5); companion to handoff assumption traps; does **not** override POLICY/STATUS
   - **Recommended (UI):** [`docs/OPERATOR_UI.md`](../OPERATOR_UI.md), [`docs/OPERATOR_ROUTER_CONFIG_UI.md`](../OPERATOR_ROUTER_CONFIG_UI.md), [`docs/OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md`](../OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md), [`docs/contracts/ROADMAP.md`](ROADMAP.md) §3.3 — LOCAL HUB PWA primary; **`next_task`:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](../STATUS.yaml)
8. Task-specific contracts from §8 as needed
9. [`docs/project-state.md`](../project-state.md) — non-competing harness projection only

**New chat orchestrator prompt:** separate living paste-block package — see [`AGENTS.md`](../../AGENTS.md) for current filename; baseline blocks in-repo include [`docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md`](../NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md) (refresh before copy).

Do **not** skip `STATUS.yaml` in favor of README prose or chat history.

---

## 2. SSOT hierarchy

| Priority | Source | Role |
|---|---|---|
| 1 | [`docs/STATUS.yaml`](../STATUS.yaml) | Phase, deliverables completed/pending, blockers, next task, `implementation_transition_gate`, canonical_facts |
| 2 | Phase 0b **contracts** (`docs/contracts/*.md`) | Normative behavior, API, persistence, gates, scenarios, roadmap |
| 3 | Phase 0a docs + ADRs | Architecture evidence; ADRs frozen unless explicitly amended |
| 4 | [`docs/project-state.md`](../project-state.md) | Living projection for hooks — **if diverges from STATUS, follow STATUS** |
| 5 | Chat / plan files | Non-authoritative; verify against STATUS |

**Contracts documented ≠ implementation exists.** Check `STATUS.yaml` `deliverables`, repo tree, and `implementation_transition_gate` before claiming code, package, API, or UI.

---

## 3. Locked invariants (summary)

From [`CANONICAL.md`](../CANONICAL.md) and [`STATUS.yaml`](../STATUS.yaml) `canonical_facts` — do not invent beyond these:

- **Product:** local event booth; first certified router target Netcraze Ultra NC-1812; four zones Guest/Promo/Staff/Admin-Server; Guest gets HTTPS order page only.
- **Identity:** stable `RouterId`; IP/hostname/gateway/interface name are not identity; identity mismatch → hard abort on mutation path.
- **Implementation:** Python 3.11 package `router_control` **exists** (SLICE-1+); FastAPI dev-host **`router_control_host`** **exists** (SLICE-3); Hub `module_3.0` later; prefix `/api/router-control/v1/*`; UI in `/settings` only.
- **Persistence:** `data/router_control.sqlite3`; JSON import/export/artifacts only.
- **Security:** local operator v1; Confirm after redacted plan; DPAPI `CurrentUser` vault; managed merge ownership only.
- **Mutation lifecycle:** preflight → identity → observe → backup → plan → Confirm → Fail-safe Configuration → apply → read-back → verify → save/compensate ([`RCI_POLICY.md`](RCI_POLICY.md)).
- **Unknown firmware/capability/profile:** fail closed for writes.
- **Failure isolation:** Router Control must not block kiosk, board, printing, or Hub startup.
- **VPN v1:** AmneziaWG only; one active assignment per router in first deployment.
- **Routes:** 5000 is stress goal; production ceiling from lab benchmark only.
- **Legacy:** `ScanCursorIP` is behavioral evidence + strangler fallback until parity and cutover.

---

## 4. Current phase and gates

| Item | Value |
|---|---|
| Phase | **P3 shared typed executor complete** (2026-07-23; offline/default-deny; Certified registry empty; **not live-ready**); both fail-safe trials consumed **completed_failed**; **2026-08-05:** first real handshake + traffic via tunnel **device-verified** (§M-24..§M-27); station apply **live** (§M-34) — **NOT WriteCertified** |
| Wave 7 | **Complete** — cross-document review closed Phase 0b |
| Foundation | SLICE-1..4, offline mega, SLICE-6 AWG trial closed failed; packages exist |
| Implementation transition | `human_approved: true`, `code_may_start: true`; M1–M3 offline/read-only authorized 2026-07-22 |
| Gates A/B/C/D | **A open** ReadOnlyCertified (post-WG rebind 2026-07-31, expendable unit); **B** completed_failed (not WriteCertified); **C/D closed** |
| M1–M3 bounds | No router writes; live I/O Gate A RO only; topology discovery read (non-certifying) separate from Gate A allowlist; **default-route discovery read** (GET `/rci/show/ip/route`, DiscoveryRead allowlist) emits default-route/uplink structural evidence only — hashed outbound IDs, gateway private network class (never host), non-default routes dropped; `multiple_default_routes`/`ambiguous`/unknown shape block T4 uplink claims; optional topology correlation never alone promotes `proven_wan_isolated`; **observed keyed parser v2.3** (`topology-interface-v2.3`; v2.2 artifacts readable for correlation when `link_up` is explicit bool) offline-only alongside v1 list wrapper; **`link_up` from `link` only** — `connected` independent (live trap: `connected:true` + `link:down`); correlation uplink hash requires bool `link_up: true` regardless of artifact `parser_version`; per-interface sorted `uncertainty` field names only (no values); malformed optional consumed fields omit fact + record uncertainty; overlap positives may still classify `lan_to_lan_or_overlap` under uncertainty; uncertainty blocks `proven_wan_isolated`; keyed WAN proof requires `link_up:true`; on topology/route parse fail optional **`--shape-out` structural fingerprint** (bounded types/field names only — never raw payload); two-step discovery = Gate A identity → topology/default-route DiscoveryRead; classification is safety evidence not certification; T4 overlapping-LAN mutations still require `proven_wan_isolated` or physical uplink disconnect; no signed pull; no Hub module_3.0; **prototype UI** in `router_control_host/web/` (full operator web UI **`operator-web-ui-full-coverage` NOT delivered**); no generic/raw RCI |
| Blockers | Write certification per family — parallel deferred lanes (AWG trial failed); see STATUS `blockers` |

---

## 5. Prohibited operations

Outside approved offline scope, or without applicable gate open:

| Prohibited | Reason |
|---|---|
| **Ungated** live router **mutations** or gate opens without applicable authorization | Gate **A** open ReadOnlyCertified; Gate **B** completed_failed (not WriteCertified); Gates **C/D** closed — see [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md): **expendable_development_router** envelope when `ROUTER_CONTROL_LAB_CLASS` set and live tuple matches; **non-expendable / carve-outs** require explicit per-action confirmation |
| Live mutation outside applicable envelope without exact T4 Human Gate Packet | Non-expendable standing auth and carve-outs do **not** inherit expendable envelope; program authorization does **not** substitute per-action approval where POLICY requires it |
| SLICE-4+ hardware **writes** without Gate B/C/D open | Fail-closed policy |
| Hub `module_3.0` integration code | SLICE-10 in roadmap; not now |
| Secrets in docs/code/fixtures/logs | SECURITY_OPS + AGENTS rules |
| Claim certification or open gates in prose | Fail-closed policy |
| Expand scope beyond recorded STATUS approvals without explicit human gate | Fail-safe trials consumed **completed_failed** (no replay); M1–M3 offline/read-only forbids ungated writes; expendable envelope applies only when lab_class + tuple match; no Hub `module_3.0`; no WriteCertified |

---

## 6. Task contract template

Use for autonomous work (see `.cursor/skills/autonomous-task/`):

```yaml
contract_id: short-slug
tier: T0|T1|T2|T3|T4
goal: testable outcome
acceptance_criteria:
  - id: AC-1
    text: observable result
owned_files: []          # implementer writes ONLY these
forbidden: []            # explicit exclusions
verify_commands: []      # must exit 0 before done
```

Rules: do not change AC or verify commands; T4/destructive/external writes stop for human approval; findings need path, lines, requirement ref, reproducible evidence.

---

## 7. Owned-path, evidence, review, verify expectations

| Expectation | Rule |
|---|---|
| **Owned paths** | Implementer modifies only `owned_files`; forbidden paths untouched |
| **Evidence** | Commands with exit codes; no model consensus as proof |
| **Review** | Adversarial review on T2+ product writes; blockers must resolve or be waived explicitly |
| **Verify** | All AC pass; required scripts exit 0; `blockers_open: 0` before done |
| **Docs changes** | Update STATUS + project-state + docs-map + nav together; Docs Impact Record when touching docs |
| **Validator** | `pwsh -NoProfile -File scripts/validate-project-docs.ps1` → exit 0 |

---

## 8. Contract catalog (eight STATUS deliverables)

| # | STATUS ID | Contract | Path |
|---|---|---|---|
| 1 | `rci-policy` | RCI policy | [`RCI_POLICY.md`](RCI_POLICY.md) |
| 2 | `security-ops` | Security / operations | [`SECURITY_OPS.md`](SECURITY_OPS.md) |
| 3 | `persistence-contract` | Persistence | [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) |
| 4 | `api-contract` | HTTP/API v0 | [`API_CONTRACT.md`](API_CONTRACT.md) |
| 5 | `test-strategy` | Test strategy | [`TEST_STRATEGY.md`](TEST_STRATEGY.md) |
| 6 | `scenarios` | Operator scenarios | [`SCENARIOS.md`](SCENARIOS.md) |
| 7 | `roadmap` | Implementation roadmap | [`ROADMAP.md`](ROADMAP.md) |
| 8 | `ai-handoff` | AI handoff (this doc) | [`AI_HANDOFF.md`](AI_HANDOFF.md) |

**Supporting (not counted in the eight):** [`HARDWARE_GATES.md`](HARDWARE_GATES.md) (`hardware-gates`); contracts index [`README.md`](README.md) (`contracts-index`).

**Scenario/test trace:** each `SCN-*` maps to API §6, TEST lanes, and contracts — see [`SCENARIOS.md`](SCENARIOS.md) §4 trace matrix and [`TEST_STRATEGY.md`](TEST_STRATEGY.md) §3 coverage matrix.

---

## 9. Atomic documentation updates

When changing listed docs, navigation, or phase status:

1. Edit content files.
2. Update [`docs/STATUS.yaml`](../STATUS.yaml) (`deliverables`, `current_phase`, `next_task`, `links`, exit criteria, `implementation_transition_gate`).
3. Update [`docs/project-state.md`](../project-state.md) milestones and `next_checks`.
4. Update [`docs/docs-map.json`](../docs-map.json) entries for new/changed paths.
5. Sync [`README.md`](../../README.md), [`docs/README.md`](../README.md), [`docs/contracts/README.md`](README.md) as needed.
6. Run `pwsh -NoProfile -File scripts/validate-project-docs.ps1` — must exit **0**.
7. Record Docs Impact Record in task return (see autonomous-task `contracts.md` §8).

Preserve line endings (STATUS.yaml is CRLF). Minimize unrelated churn.

---

## 10. Safe resumption

| Situation | Action |
|---|---|
| New session | Cold-start §1; read STATUS `next_task` |
| Unsure if code exists | List repo; check STATUS `implementation_transition_gate` and deliverables |
| Phase 0b complete / Gate A open | Confirm `STATUS.yaml` gates: **A open** ReadOnlyCertified; **B** fail_safe trial **completed_failed**; **C completed_failed**; **D closed** before live observe or any write work |
| Implementation requested | Confirm human gate open for target slice in STATUS; else stop with Human Gate Packet |
| Doc drift suspected | Run docs validator; reconcile STATUS over project-state |
| Hardware work | Require explicit gate open for exact tuple; never infer from docs; dedicated lab program authorizes **scope**, not undefined writes — [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) |

**Next owner task:** **`local-hub-vpn-real-peer-autoconnect-continuation`** per [`STATUS.yaml`](../STATUS.yaml) `next_task` — honest continuation after device-verified VPN handshake, traffic via tunnel, station apply, main menu. **Parallel deferred:** VPN named connection policy / kill-switch **live apply** (offline preview only; kill-switch `permit global` unresolved; IPv6 allow-ips refused offline; **`tunnel_healthy` + first real handshake DEVICE-CONFIRMED** 2026-08-05). Active narrative: [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md). WriteCertified **NOT** claimed; Gates B/C/D unchanged.

---

## 11. Links

- Project status SSOT: [`STATUS.yaml`](../STATUS.yaml)
- Architecture: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- Domain model: [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md)
- Agent entry: [`AGENTS.md`](../../AGENTS.md)
- Contracts index: [`README.md`](README.md)
