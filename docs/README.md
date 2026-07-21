# Router Control

Router Control — модуль локального управления роутером **Netcraze Ultra NC-1812** для выездного event booth. Offline mega (SLICE-2/3/5/8) доставил persistence, FastAPI host, vault и TrafficDiscovery proposals-only; живой роутер по-прежнему не изменяется без открытых hardware gates.

## Текущий статус

**Phase 0a / 0b — complete.** **Phase 1 offline mega (SLICE-2/3/5/8) — complete** (2026-07-21): SQLite, `router_control_host`, CredentialVault, TrafficDiscovery proposals-only. **Next: SLICE-4 Gate A** (отдельный hardware gate). Hardware gates ([`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md)) — **A–D closed**. Машиночитаемый источник — [`STATUS.yaml`](STATUS.yaml).

Этот репозиторий — текущий дом проекта и будущего лабораторного prototype. Целевая интеграция — существующий Python 3.11 / FastAPI Hub `module_3.0`, но только после проверки ядра и hardware gates. `ScanCursorIP` остаётся legacy behavioral evidence и рабочим strangler-контуром до достижения parity и отдельного решения о cutover; новую реализацию там не создаём.

## Порядок чтения

Новый участник или AI agent читает документацию в таком порядке:

1. [`README.md`](README.md) — назначение, статус и навигация.
2. [`STATUS.yaml`](STATUS.yaml) — текущая phase, готовые и ожидаемые deliverables, blockers и next task.
3. [`CANONICAL.md`](CANONICAL.md) — подтверждённые факты о legacy-коде и NC-1812; факты модели отделены от domain invariants.
4. [`VISION.md`](VISION.md) — event scenario, пользователи, зоны и границы продукта.
5. [`ARCHITECTURE.md`](ARCHITECTURE.md) — bounded contexts, trust boundaries и путь prototype → Hub.
6. [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) — entities, revisions, desired/observed state, ownership и invariants.
7. [`LEGACY_MAP.md`](LEGACY_MAP.md) — что переносить из C#/PowerShell, что считать golden behavior и что не переиспользовать.
8. [`COMPATIBILITY.md`](COMPATIBILITY.md) — firmware/capability matrix и hardware certification gates.
9. [`contracts/README.md`](contracts/README.md) — Phase 0b contracts program и Wave 1–7 navigation.
10. ADR:
   - [`adrs/0001-python-package-fastapi-host.md`](adrs/0001-python-package-fastapi-host.md)
   - [`adrs/0002-persistence-jobs-sqlite.md`](adrs/0002-persistence-jobs-sqlite.md)
   - [`adrs/0003-security-auth-secrets.md`](adrs/0003-security-auth-secrets.md)
   - [`adrs/0004-product-capability-scope.md`](adrs/0004-product-capability-scope.md)

## Зафиксированное направление

- Domain core создаётся как переносимый Python package `router_control` без зависимости от FastAPI.
- Prototype получает отдельный FastAPI dev-host; позже package механически встраивается в lifecycle и dependency wiring `module_3.0`.
- In Hub API будет жить на общем listener под `/api/router-control/v1/*` ([`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md)), а UI — только в защищённом блоке существующего `/settings`.
- Router Control использует отдельную SQLite database `data/router_control.sqlite3`; JSON допускается для import/export и redacted artifacts, но не как основное state storage.
- Первая VPN capability — только **AmneziaWG**. Unknown firmware, capability или profile field запрещает write operation.
- Любое изменение роутера проходит unified lifecycle: preflight → identity → observe → backup → plan-preconditions → Confirm → Fail-safe Configuration → apply → read-back → verify → save/compensate ([`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md)).
- Mutation jobs сериализуются по стабильному `RouterId`; модуль изменяет или удаляет только ресурсы с собственной ownership record.
- Degraded/disabled Router Control не должен блокировать kiosk, order board, printing или запуск Hub.

Полный продуктовый сценарий и explicit non-goals описаны в [`VISION.md`](VISION.md).

## Границы Phase 0a

Phase 0a создаёт только architecture evidence: code-truth, domain model, security/trust boundaries, compatibility unknowns, integration contract и ADR. На этой phase запрещены:

- реализация package, API или UI;
- подключение к живому NC-1812 и любые router mutations;
- утверждение поддержки firmware/AWG без laboratory evidence;
- перенос в `module_3.0`;
- размещение passwords, private keys, session data или иных secrets в документации.

Phase 0a/0b closed. **Phase 1 offline mega complete** (2026-07-21). **Next SLICE-4** requires Gate A open; hardware gates A–D closed.

## Harness и living docs

Cursor harness (Essential) bootstrapped from cursor-project-toolkit. Дополнительная навигация:

| Документ | Назначение |
|----------|------------|
| [`project-state.md`](project-state.md) | Живая проекция phase/next checks для hooks (SSOT — [`STATUS.yaml`](STATUS.yaml)) |
| [`docs-map.json`](docs-map.json) | Индекс документации; обновлять при изменении listed docs |
| [`living-documentation.md`](living-documentation.md) | Правила living docs и docs-map |
| [`papercuts.md`](papercuts.md) | Workflow friction log (`.papercuts.jsonl`) |
| [`project-environment.md`](project-environment.md) | Doctor/setup surfaces |
| [`docs-map-schema.md`](docs-map-schema.md) | Схема `docs-map.json` |
