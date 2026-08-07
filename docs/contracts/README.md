# Router Control: contracts program

## For agents

| Check | Action |
|---|---|
| Phase | **P3 topology safety closure complete** (2026-07-23; offline/default-deny); both fail-safe trials consumed **completed_failed**; **2026-07-31 end state:** station uplink persisted; WG **`tunnel_healthy` DEVICE-CONFIRMED**; **2026-08-05:** **`SET_IP_ADDRESS`** + **`wireguard_ip_global`** + traffic via tunnel DEVICE-VERIFIED (§M-24..§M-27); kill-switch/named policy/IPv6 routes **NOT done** |
| Wave 1 | RCI policy, hardware gates, security/operations — **complete** |
| Wave 2 | SQLite persistence, revisions, durable jobs, audit — **complete** |
| Wave 3 | HTTP/API contract (v0) — **complete** |
| Wave 4 | Test strategy and evidence lanes — **complete** |
| Wave 5 | Operator/event scenarios — **complete** |
| Wave 6 | Roadmap + AI handoff — **complete** |
| Wave 7 | Cross-document review/closeout — **complete** |
| Read order | This index → [`RCI_POLICY.md`](RCI_POLICY.md) + [`HARDWARE_GATES.md`](HARDWARE_GATES.md) → [`SECURITY_OPS.md`](SECURITY_OPS.md) → [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) → [`API_CONTRACT.md`](API_CONTRACT.md) → [`TEST_STRATEGY.md`](TEST_STRATEGY.md) → [`SCENARIOS.md`](SCENARIOS.md) → [`ROADMAP.md`](ROADMAP.md) → [`AI_HANDOFF.md`](AI_HANDOFF.md) |
| Trace | [`CANONICAL.md`](../CANONICAL.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`COMPATIBILITY.md`](../COMPATIBILITY.md), ADR-0002/0003/0004, [`LEGACY_MAP.md`](../LEGACY_MAP.md) for RCI evidence limits |
| Do not | Invent certified RCI JSON bodies; normalize raw `5.01` to `5.1`; open or expand hardware gates without exact explicit human approval; **treat `approvals.dedicated_development_router_lab` program authorization as standing write approval** for live mutations, reboots, installs, resets, or capability write/trials — program permits Gate **A** read-only observe/probe/re-cert on exact tuple and offline harness work only; Gate **B** completed_failed / not WriteCertified; Gates **C/D** closed; no standing T4 |
| Lab policy | [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) — project-owned NC-1812; program vs action; active handoff [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) + [`STATUS.yaml`](../STATUS.yaml); historical: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) |

---

## Назначение

Каталог `docs/contracts/` фиксирует формальные контракты Router Control между architecture evidence (Phase 0a) и будущей implementation. Контракты vendor-neutral на границе domain/application; RCI и DPAPI остаются в adapters.

## Программа Waves 1–7

| Wave | Фокус | Статус Phase 0b |
|---|---|---|
| **1** | RCI policy, hardware safety gates, security/operations | **Complete** |
| **2** | SQLite persistence, revisions, durable jobs, audit | **Complete** |
| **3** | HTTP/API contract (prototype host + Hub prefix); based on Waves 1–2 | **Complete** |
| **4** | Test strategy and evidence lanes | **Complete** |
| **5** | Operator/event scenarios (Guest/Promo/Staff/Admin) | **Complete** |
| **6** | Implementation roadmap + AI handoff pack | **Complete** |
| 7 | Cross-document review / Phase 0b closeout | **Complete** |

## Wave 1 — файлы

| Файл | Назначение |
|---|---|
| [`RCI_POLICY.md`](RCI_POLICY.md) | Deny-by-default capability-family allowlist, transport hypotheses, unified mutation lifecycle, managed merge, idempotency |
| [`HARDWARE_GATES.md`](HARDWARE_GATES.md) | Certification tuple, gates A/B/C/D, fail-closed table, lab checklists — **supports** `rci-policy` deliverable (не отдельный ninth pending id) |
| [`SECURITY_OPS.md`](SECURITY_OPS.md) | `hub_admin` fail-closed, Confirm binding, CredentialRef/DPAPI, redaction, audit, replacement/recovery, zone/HTTPS gates |

## Wave 2 — файлы

| Файл | Назначение |
|---|---|
| [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) | Authoritative SQLite store, logical schema v0, revisions/ETag, durable jobs/recovery, idempotency, audit, migration/backup policy |

## Wave 3 — файлы

| Файл | Назначение |
|---|---|
| [`API_CONTRACT.md`](API_CONTRACT.md) | Normative HTTP v0: prefix, auth/feature matrix, endpoints, DTOs, ETag/If-Match, idempotency, errors, gates, exclusions |

## Wave 4 — файлы

| Файл | Назначение |
|---|---|
| [`TEST_STRATEGY.md`](TEST_STRATEGY.md) | Verification lanes, fake/recorded/hardware evidence, pyramid matrix, AWG/route benchmark protocol, persistence fault injection, API/security negatives |

## Wave 5 — файлы

| Файл | Назначение |
|---|---|
| [`SCENARIOS.md`](SCENARIOS.md) | Operator/event scenarios: four zones, happy paths, fail-closed negatives, job recovery, lab/cutover evidence trace matrix |

## Wave 6 — файлы

| Файл | Назначение |
|---|---|
| [`ROADMAP.md`](ROADMAP.md) | Local-first milestone DAG M0–M8; parallel deferred AWG/routes/LTE lanes; SLICE history as reference — **P3 topology safety closure complete** (2026-07-23); **next task:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](../STATUS.yaml) `next_task` §3.3 — **`tunnel_healthy` + Address/ip_global + traffic DEVICE-VERIFIED** (§M-24..§M-27); **parallel deferred:** VPN named policy / kill-switch live apply (offline preview only; kill-switch `permit global` **unresolved**; **`CLEAR_IP_GLOBAL` on teardown** not device-proven; IPv6 allow-ips refused) — [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](../OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md); Gate B / `write_shapes_registered` BLOCKED |
| [`AI_HANDOFF.md`](AI_HANDOFF.md) | AI cold-start, SSOT hierarchy, M1–M3 bounds, 2026-07-22 authorization wording |

## Зависимости

Wave 1 опирается на:

- [`docs/CANONICAL.md`](../CANONICAL.md) — locked invariants, Fail-safe Configuration semantics
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — bounded contexts, trust zones, failure isolation
- [`docs/DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) — entities, certification status, plan/job lifecycle
- [`docs/COMPATIBILITY.md`](../COMPATIBILITY.md) — capability matrix, gate ladder, raw `5.01` unclassified
- [`docs/LEGACY_MAP.md`](../LEGACY_MAP.md) — limits of legacy RCI fixtures (old device shapes ≠ NC-1812 certification)
- [`docs/adrs/0002-persistence-jobs-sqlite.md`](../adrs/0002-persistence-jobs-sqlite.md) — durable jobs, idempotency, audit (Wave 2 contract expands types/FK/indexes)
- [`docs/adrs/0003-security-auth-secrets.md`](../adrs/0003-security-auth-secrets.md) — auth, DPAPI, trust boundaries
- [`docs/adrs/0004-product-capability-scope.md`](../adrs/0004-product-capability-scope.md) — NC-1812 scope, AWG, route benchmark (ordering superseded by ADR-0005)
- [`docs/adrs/0005-local-first-commissioning-roadmap.md`](../adrs/0005-local-first-commissioning-roadmap.md) — M0–M8 milestone DAG, M1–M3 bounds

## Phase 0b Definition of Done (Wave 7 closeout — historical snapshot)

**Historical closeout snapshot (2026-07-20):** Phase 0b is **closed** when:

1. **All eight** STATUS contract deliverable IDs complete with `id` fields: `rci-policy`, `security-ops`, `persistence-contract`, `api-contract`, `test-strategy`, `scenarios`, `roadmap`, `ai-handoff` — plus supporting `hardware-gates` and `contracts-index`.
2. At Wave 7 closeout: `previous_phase.id: 0b`, `pending: []`, `phase_0b_exit_criteria` all true; `implementation_transition_gate` installed pending separate human approval.
3. Navigation synchronized across READMEs, `project-state.md`, `docs-map.json`, contracts index, and cross-links.
4. No implementation artifacts, secrets, or opened hardware gates.
5. Cross-document review complete; reviewer blockers clear.

**Current state:** see [`STATUS.yaml`](../STATUS.yaml) — **P3 topology safety closure complete** (2026-07-23); both consumed fail-safe trials closed **completed_failed** (094500Z + 110000Z; not WriteCertified); Gate A **open/ReadOnlyCertified** (post-WG rebind 2026-07-31; evidence `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`); Gate B **completed_failed**; Gate C **closed** completed_failed; Gate D **closed**; `write_shapes_registered` false; WriteCertified **NOT** claimed; **`tunnel_healthy` DEVICE-CONFIRMED** (first real handshake §M-24..§M-26); **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** (§M-24/M-27); traffic via tunnel **device-verified reversible** (§M-27); **next task:** `local-hub-vpn-real-peer-autoconnect-continuation`; **parallel deferred:** VPN named policy / kill-switch live apply (offline preview only; kill-switch `permit global` **unresolved**; **`CLEAR_IP_GLOBAL` on teardown** not device-proven; IPv6 allow-ips refused) — AWG shape discovery **parallel deferred**.
