# Router Control: contracts program

## For agents

| Check | Action |
|---|---|
| Phase | Phase **0b** — contracts only; no package/API/UI/router mutations |
| Wave 1 (this slice) | RCI policy, hardware gates, security/operations — **complete** |
| Wave 2+ pending | API, persistence, test strategy, scenarios, roadmap, AI handoff — see [`STATUS.yaml`](../STATUS.yaml) |
| Read order | This index → [`RCI_POLICY.md`](RCI_POLICY.md) + [`HARDWARE_GATES.md`](HARDWARE_GATES.md) → [`SECURITY_OPS.md`](SECURITY_OPS.md) |
| Trace | [`CANONICAL.md`](../CANONICAL.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`COMPATIBILITY.md`](../COMPATIBILITY.md), ADR-0002/0003/0004, [`LEGACY_MAP.md`](../LEGACY_MAP.md) for RCI evidence limits |
| Do not | Invent certified RCI JSON bodies; normalize raw `5.01` to `5.1`; open hardware gates in Phase 0b |

---

## Назначение

Каталог `docs/contracts/` фиксирует формальные контракты Router Control между architecture evidence (Phase 0a) и будущей implementation. Контракты vendor-neutral на границе domain/application; RCI и DPAPI остаются в adapters.

## Программа Waves 1–7

| Wave | Фокус | Статус Phase 0b |
|---|---|---|
| **1** | RCI policy, hardware safety gates, security/operations | **Complete** (this slice) |
| 2 | SQLite persistence, revisions, durable jobs, audit | Pending |
| 3 | HTTP/API contract (prototype host + Hub prefix); based on Waves 1–2 | Pending |
| 4 | Test strategy and evidence lanes | Pending |
| 5 | Operator/event scenarios (Guest/Promo/Staff/Admin) | Pending |
| 6 | Implementation roadmap and cutover gates | Pending |
| 7 | AI handoff pack | Pending |

## Wave 1 — файлы

| Файл | Назначение |
|---|---|
| [`RCI_POLICY.md`](RCI_POLICY.md) | Deny-by-default capability-family allowlist, transport hypotheses, unified mutation lifecycle, managed merge, idempotency |
| [`HARDWARE_GATES.md`](HARDWARE_GATES.md) | Certification tuple, gates A/B/C/D, fail-closed table, lab checklists — **supports** `rci-policy` deliverable (не отдельный ninth pending id) |
| [`SECURITY_OPS.md`](SECURITY_OPS.md) | `hub_admin` fail-closed, Confirm binding, CredentialRef/DPAPI, redaction, audit, replacement/recovery, zone/HTTPS gates |

## Зависимости

Wave 1 опирается на:

- [`docs/CANONICAL.md`](../CANONICAL.md) — locked invariants, Fail-safe Configuration semantics
- [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md) — bounded contexts, trust zones, failure isolation
- [`docs/DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) — entities, certification status, plan/job lifecycle
- [`docs/COMPATIBILITY.md`](../COMPATIBILITY.md) — capability matrix, gate ladder, raw `5.01` unclassified
- [`docs/LEGACY_MAP.md`](../LEGACY_MAP.md) — limits of legacy RCI fixtures (old device shapes ≠ NC-1812 certification)
- [`docs/adrs/0002-persistence-jobs-sqlite.md`](../adrs/0002-persistence-jobs-sqlite.md) — durable jobs, idempotency, audit
- [`docs/adrs/0003-security-auth-secrets.md`](../adrs/0003-security-auth-secrets.md) — auth, DPAPI, trust boundaries
- [`docs/adrs/0004-product-capability-scope.md`](../adrs/0004-product-capability-scope.md) — NC-1812 scope, AWG, route benchmark

## Phase 0b Definition of Done (Wave 1 slice)

Wave 1 satisfies partial Phase 0b exit when:

1. Четыре contract-файла существуют и AI-first.
2. [`STATUS.yaml`](../STATUS.yaml) отражает `rci-policy` и `security-ops` как completed; шесть других deliverables остаются pending.
3. ARCHITECTURE, DOMAIN_MODEL, COMPATIBILITY, CANONICAL и navigation синхронизированы ссылками и терминологией.
4. Нет implementation artifacts, secrets или invented certified RCI command bodies.
5. **Ни один hardware gate (A/B/C/D) не открыт** в Phase 0b.

Полное закрытие Phase 0b требует Waves 2–7.
