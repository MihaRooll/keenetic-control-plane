# Router Control: contracts program

## For agents

| Check | Action |
|---|---|
| Phase | Phase **0b complete**; Phase **1 / SLICE-1 in progress** (authorized) — implementation scope: portable core + `FakeRouterAdapter` only; hardware gates A–D **closed**; no live adapter |
| Wave 1 | RCI policy, hardware gates, security/operations — **complete** |
| Wave 2 | SQLite persistence, revisions, durable jobs, audit — **complete** |
| Wave 3 | HTTP/API contract (v0) — **complete** |
| Wave 4 | Test strategy and evidence lanes — **complete** |
| Wave 5 | Operator/event scenarios — **complete** |
| Wave 6 | Roadmap + AI handoff — **complete** |
| Wave 7 | Cross-document review/closeout — **complete** |
| Read order | This index → [`RCI_POLICY.md`](RCI_POLICY.md) + [`HARDWARE_GATES.md`](HARDWARE_GATES.md) → [`SECURITY_OPS.md`](SECURITY_OPS.md) → [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) → [`API_CONTRACT.md`](API_CONTRACT.md) → [`TEST_STRATEGY.md`](TEST_STRATEGY.md) → [`SCENARIOS.md`](SCENARIOS.md) → [`ROADMAP.md`](ROADMAP.md) → [`AI_HANDOFF.md`](AI_HANDOFF.md) |
| Trace | [`CANONICAL.md`](../CANONICAL.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`COMPATIBILITY.md`](../COMPATIBILITY.md), ADR-0002/0003/0004, [`LEGACY_MAP.md`](../LEGACY_MAP.md) for RCI evidence limits |
| Do not | Invent certified RCI JSON bodies; normalize raw `5.01` to `5.1`; open hardware gates A–D |

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
| [`ROADMAP.md`](ROADMAP.md) | Dependency-ordered implementation slices, entry/exit gates, verification evidence, rollback/stop — SLICE-1 authorized per [`STATUS.yaml`](../STATUS.yaml) `implementation_transition_gate` |
| [`AI_HANDOFF.md`](AI_HANDOFF.md) | AI cold-start, SSOT hierarchy, invariants, task template, atomic doc updates, safe resumption |

## Зависимости

Wave 1 опирается на:

- [`docs/CANONICAL.md`](../CANONICAL.md) — locked invariants, Fail-safe Configuration semantics
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — bounded contexts, trust zones, failure isolation
- [`docs/DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) — entities, certification status, plan/job lifecycle
- [`docs/COMPATIBILITY.md`](../COMPATIBILITY.md) — capability matrix, gate ladder, raw `5.01` unclassified
- [`docs/LEGACY_MAP.md`](../LEGACY_MAP.md) — limits of legacy RCI fixtures (old device shapes ≠ NC-1812 certification)
- [`docs/adrs/0002-persistence-jobs-sqlite.md`](../adrs/0002-persistence-jobs-sqlite.md) — durable jobs, idempotency, audit (Wave 2 contract expands types/FK/indexes)
- [`docs/adrs/0003-security-auth-secrets.md`](../adrs/0003-security-auth-secrets.md) — auth, DPAPI, trust boundaries
- [`docs/adrs/0004-product-capability-scope.md`](../adrs/0004-product-capability-scope.md) — NC-1812 scope, AWG, route benchmark

## Phase 0b Definition of Done (Wave 7 closeout — historical snapshot)

**Historical closeout snapshot (2026-07-20):** Phase 0b is **closed** when:

1. **All eight** STATUS contract deliverable IDs complete with `id` fields: `rci-policy`, `security-ops`, `persistence-contract`, `api-contract`, `test-strategy`, `scenarios`, `roadmap`, `ai-handoff` — plus supporting `hardware-gates` and `contracts-index`.
2. At Wave 7 closeout: `previous_phase.id: 0b`, `pending: []`, `phase_0b_exit_criteria` all true; `implementation_transition_gate` installed pending separate human approval.
3. Navigation synchronized across READMEs, `project-state.md`, `docs-map.json`, contracts index, and cross-links.
4. No implementation artifacts, secrets, or opened hardware gates.
5. Cross-document review complete; reviewer blockers clear.

**Current state:** see [`STATUS.yaml`](../STATUS.yaml) — Phase 1 / SLICE-1 authorized (`implementation_transition_gate` open for portable core + `FakeRouterAdapter` only); hardware gates A–D remain closed.
