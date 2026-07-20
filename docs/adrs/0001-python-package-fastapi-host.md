# ADR-001: Python domain package и FastAPI host

- Status: Accepted
- Date: 2026-07-19
- Decision owners: Router Control / Hub architecture

## Context

Router Control должен заменить legacy-контур управления роутером без переписывания проверенной domain logic при переходе в production Hub.

Целевой `module_3.0` уже является Windows Hub на Python 3.11 и использует:

- FastAPI/Uvicorn application factory в `app/api/factory.py`;
- process-wide resources в `app/core/bootstrap.py`;
- startup/recovery/shutdown workers в `app/core/lifespan.py`;
- typed environment settings в `app/settings.py`;
- authentication и request policy в `app/core/middleware.py`;
- vanilla HTML/JS operator UI в `static/settings.html` и `static/settings.js`;
- elevated Scheduled Task и environment provisioning через `scripts/install_hub.ps1`.

Разработка начинается в canonical repository `keenetic-control-plane`, потому что Router Control ещё должен пройти fake, recorded и live-hardware gates. `ScanCursorIP` остаётся только legacy behavioral evidence. Prototype не должен стать отдельным продуктом, который позднее придётся портировать в Hub.

Legacy implementation использует WPF и PowerShell. Она остаётся полезной как strangler fallback, behavioral evidence и golden oracle, но её platform boundary не совпадает с target Hub.

Дополнительные constraints:

- domain logic не должна зависеть от HTTP framework или vendor protocol;
- Router Control API в production использует существующий Hub LAN listener;
- все Router endpoints требуют existing `hub_admin` session и fail closed, даже если password не настроен;
- failure Router Control не должен останавливать kiosk, board, printing или сам Hub;
- нельзя вводить отдельные scopes для `Promo`: это network zone, не application principal.

Полная схема contexts, ports и Hub touchpoints находится в [ARCHITECTURE.md](../ARCHITECTURE.md).

## Decision

### 1. Final core — Python package

Создать переносимый Python package `router_control` со слоями:

- `domain`: entities, value objects, invariants, desired/observed state и planner;
- `application`: use cases и orchestration;
- `ports`: router, repositories, vault, jobs, audit и clock contracts;
- `adapters`: fake, SQLite, DPAPI и позднее Netcraze RCI;
- `composition`: сборка целостного runtime/facade.

`domain`, `application` и `ports` не импортируют FastAPI, WPF, PowerShell или vendor RCI types. Netcraze JSON и authentication protocol остаются внутри RCI adapter.

### 2. Prototype host — FastAPI dev host

В canonical repository `keenetic-control-plane` будущий package будет запускаться через отдельный FastAPI dev host. Package и dev host ещё не созданы. Dev host:

- преобразует HTTP DTO в application commands;
- предоставляет лабораторный API;
- использует `FakeRouterAdapter` в Phase 1;
- не содержит domain decisions;
- не является отдельным production service.

FastAPI — inbound adapter, а не место хранения core logic.

### 3. Target host — lifecycle `module_3.0`

После certification package механически переносится в `module_3.0/app/services/router_control/`.

Target composition следует существующему lifecycle:

1. `app/core/bootstrap.py` создаёт один process-wide Router Control runtime или явный disabled/degraded facade.
2. `app/api/factory.py` связывает runtime с `app.state` и регистрирует Router Control `APIRouter`.
3. `app/api/deps.py` предоставляет state-first dependency.
4. `app/core/lifespan.py` выполняет durable recovery/start и graceful stop.
5. `app/settings.py` загружает typed/redacted non-secret configuration и secret references.
6. `app/core/middleware.py` защищает весь `/api/router-control/` prefix existing `hub_admin` session.
7. `static/settings.html` и `static/settings.js` добавляют Router Control block в существующую защищённую `/settings`.
8. `scripts/install_hub.ps1` устанавливает dependencies, создаёт local data location и настраивает non-secret defaults.

Production routes используют prefix `/api/router-control/v1/` на том же listener, который обслуживает Hub. Отдельный port, Windows service или sidecar не создаётся.

### 4. Fail-closed authentication и failure isolation

Current Hub admin gate является opt-in и при пустом `HUB_ADMIN_PASSWORD` работает как no-op. Для Router Control это неприемлемо.

Поэтому Router prefix получает специальную fail-closed ветку в `AdminGateMiddleware`:

- любой зарегистрированный Router endpoint при empty `HUB_ADMIN_PASSWORD` → `503`, handler не вызывается;
- password set + invalid/missing `hub_admin` cookie → `401`;
- valid cookie → request может пройти к route;
- source IP, LAN membership и network zone не заменяют authentication.

Если Router Control enabled, empty password является его security startup error и переводит feature в `SecurityBlocked`, но не завершает Hub process.

Ошибки composition, migration, worker recovery или router connection преобразуются в disabled/degraded facade. Они не выходят из Router Control lifecycle boundary и не блокируют остальные Hub services. Writes в degraded state запрещены.

### 5. Legacy остаётся strangler-контуром

WPF/PowerShell не удаляются до:

- behavioral parity;
- successful fake/recorded/live gates;
- Safe Configuration и restore rehearsal;
- явного operator cutover.

Новый Python core не shell-out в legacy PowerShell и не использует WPF assembly как library. Legacy остаётся соседним fallback, а не внутренним adapter final architecture.

## Consequences

### Positive

- Prototype и Hub используют один язык и одни domain contracts.
- Integration является переносом package и заменой composition root, а не port/rewrite.
- Domain тестируется offline без FastAPI и реального роутера.
- Fake и Netcraze adapters реализуют один port, что уменьшает расхождение лабораторного и production behavior.
- Router Control наследует Hub logging, settings, process ownership, admin session и deployment model.
- Один LAN listener упрощает TLS, firewall, UI и operations.
- Feature-local degraded state ограничивает blast radius.

### Negative

- До Hub integration существует небольшой dev host, который нужно поддерживать совместимым с Hub HTTP adapter.
- `module_3.0` middleware требует явного special-case, потому что текущая opt-in admin gate семантика недостаточна.
- Python process остаётся общим failure domain на уровне interpreter; isolation достигается lifecycle boundaries и defensive composition, а не process separation.
- Windows-only DPAPI adapter ограничивает переносимость secret storage, хотя domain package остаётся portable.
- На время strangler периода существуют два operator paths; ownership и cutover discipline обязательны.

### Risks and controls

| Risk | Control |
|---|---|
| FastAPI logic проникает в domain | Import-boundary tests и package layering |
| Пустой admin password открывает Router reads | Unconditional fail-closed middleware branch и regression tests |
| Router startup ломает Hub | Disabled/degraded facade, feature-local exception handling в bootstrap/lifespan |
| Prototype API расходится с Hub | Общие application use cases и contract tests |
| Legacy и Python одновременно меняют один resource | Exclusive ownership и explicit cutover gate |
| Vendor details становятся domain invariants | `RouterControlPort`, capability model и adapter mapping |
| Secrets появляются в logs/UI | Opaque `CredentialRef`, redaction tests, no plaintext API |

## Rejected alternatives

### .NET service или .NET class library как final core

Отклонено. Target Hub — Python process с Python lifecycle и DI pattern. .NET добавляет inter-process boundary, packaging/runtime, duplicated configuration и contract serialization. Перенос в `app/services/router_control/` перестал бы быть механическим.

.NET допустим только как часть legacy evidence до cutover, не как final domain core.

### WPF application как production host

Отклонено. WPF привязывает orchestration к interactive desktop/session, создаёт второй operator UI и не интегрируется с существующей `/settings`, Hub middleware и lifespan. Elevated interactive Hub task не превращает WPF в надёжный service boundary.

WPF остаётся strangler fallback до parity.

### PowerShell scripts как final core

Отклонено. PowerShell подходит для installation и bounded OS operations, но не для domain model, durable jobs, idempotency, revisions, typed plans и testable failure recovery. Shelling-out также затрудняет secret redaction и cancellation semantics.

PowerShell остаётся deployment adapter (`scripts/install_hub.ps1`) и legacy oracle, но не выполняет final Router Control domain logic.

### Отдельный production FastAPI service/listener

Отклонено. Он потребовал бы отдельные auth, TLS, firewall, service management, health и UI integration. Hub уже предоставляет нужный host. Dev host существует только в prototype.

### Реализация Router Control прямо в FastAPI routes

Отклонено. Это связало бы domain с HTTP DTO и затруднило fake tests, durable workers, CLI maintenance и механический перенос.

### Расширение existing API key или новые promo scopes

Отклонено. Existing API key optional и в текущем Hub не защищает reads. `Promo` — network zone, а не identity. Router Control использует только existing `hub_admin` session с усиленной fail-closed семантикой.

## Compliance

Decision соблюдается, если одновременно верно:

- domain package импортируется и тестируется без FastAPI;
- dev host является inbound adapter;
- target path — `module_3.0/app/services/router_control/`;
- production API использует common listener и `/api/router-control/v1/`;
- empty admin password блокирует весь Router prefix;
- Router Control failure не останавливает Hub;
- WPF/.NET/PowerShell отсутствуют в final core dependency graph;
- migration идёт через strangler parity и explicit cutover.
