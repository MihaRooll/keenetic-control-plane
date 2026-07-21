# Router Control

Router Control — самостоятельный проект локальной control plane для безопасного управления роутером **Netcraze Ultra NC-1812** в составе выездного event booth. Проект должен дать оператору проверяемые inventory, plans, durable jobs и audit, не превращая сетевой модуль в точку отказа для заказов, production board и печати.

Этот репозиторий — канонический дом Router Control и будущего прототипа. `ScanCursorIP` используется только как legacy behavioral evidence и strangler-контур; новая реализация не должна создаваться там.

## Статус

**Phase 0a / 0b — complete.** **Phase 1 offline mega (SLICE-2/3/5/8) — complete** (2026-07-21): SQLite persistence, FastAPI host `router_control_host`, CredentialVault, TrafficDiscovery proposals-only. **Next: SLICE-4 Gate A** (requires separate hardware gate). Hardware gates ([`docs/contracts/HARDWARE_GATES.md`](docs/contracts/HARDWARE_GATES.md)) — **A–D remain closed**.

Packages: `router_control` (domain + persistence + vault + traffic) and `router_control_host` (FastAPI `/api/router-control/v1`). Live adapter **not** created. Run host: `uvicorn router_control_host.app:app` (set `HUB_ADMIN_PASSWORD`; mutations fail-closed).

## Архитектура в двух словах

- Переносимое Python 3.11 ядро `router_control` отделено от FastAPI (`router_control_host`) и vendor RCI.
- Prototype FastAPI dev-host живёт в этом репозитории под тем же prefix, что и будущий Hub.
- Состояние — `data/router_control.sqlite3`; secrets — opaque `CredentialRef` + Memory/DPAPI vault (no plaintext API).
- Любая mutation должна пройти unified lifecycle: preflight → identity → observe → backup → plan-preconditions → Confirm → Fail-safe Configuration → apply → read-back → verify → save/compensate ([`docs/contracts/RCI_POLICY.md`](docs/contracts/RCI_POLICY.md)).
- Unknown firmware, capability или profile field блокируют writes.
- Router Control изменяет только ресурсы с подтверждённым ownership.
- Legacy WPF/PowerShell остаётся источником проверяемого поведения до parity и явного cutover.

## Порядок чтения

1. [`README.md`](README.md) — назначение, статус и ограничения.
2. [`docs/STATUS.yaml`](docs/STATUS.yaml) — машиночитаемая phase, deliverables, blockers и next task.
3. [`docs/CANONICAL.md`](docs/CANONICAL.md) — canonical facts, safety invariants и legacy evidence.
4. [`docs/VISION.md`](docs/VISION.md) — продуктовый сценарий и non-goals.
5. [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — bounded contexts, trust boundaries и integration contract.
6. [`docs/DOMAIN_MODEL.md`](docs/DOMAIN_MODEL.md) — entities, revisions, ownership и jobs.
7. [`docs/LEGACY_MAP.md`](docs/LEGACY_MAP.md) — правила использования legacy C#/PowerShell.
8. [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — firmware/capability matrix и hardware gates.
9. [`docs/contracts/`](docs/contracts/) — Phase 0b formal contracts (complete; eight deliverable IDs + index).
10. [`docs/adrs/`](docs/adrs/) — принятые архитектурные решения.

## Будущая интеграция

После fake, recorded и hardware certification gates переносимое ядро планируется механически встроить в существующий Python 3.11 / FastAPI Hub `module_3.0`: API на общем listener под `/api/router-control/v1/*` ([`docs/contracts/API_CONTRACT.md`](docs/contracts/API_CONTRACT.md)), UI — только в защищённом блоке `/settings`, lifecycle — через существующие bootstrap/dependencies/lifespan patterns.

Интеграция в `module_3.0` выполняется позже, а не в Phase 0b и не на текущем переносе документации.

## Ограничения текущего этапа

- Живой роутер не изменяется: никаких write-команд, настройки VPN, routes, firmware или components; live network I/O не авторизован.
- Hardware gates A–D **closed** — до отдельного hardware gate разрешены только документация и позднее контролируемая read-only certification.
- В репозитории запрещены passwords, private keys, raw sessions, startup-config и другие secrets.
- Поддержка AWG и лимиты routes не считаются доказанными до лабораторной сертификации на точном firmware tuple.

Полная навигация по Phase 0a находится в [`docs/README.md`](docs/README.md).
