# Vision: Router Control для event booth

## Зачем нужен модуль

На выездном мероприятии один Windows Hub обслуживает локальную страницу заказа, production board, печать и плоттеры. Router Control должен добавить к этому контуру предсказуемое локальное управление **Netcraze Ultra NC-1812**: видеть состояние роутера, безопасно применять проверенные network/VPN policies и оставлять воспроизводимый audit trail.

Модуль не является универсальной панелью администрирования роутеров. Его задача — поддержать конкретный event-booth deployment, где потеря сети или ошибочная маршрутизация останавливают приём заказов и производство. Поэтому безопасный отказ важнее автоматического «исправления любой ценой».

Текущий статус проекта — **Phase 0a complete**, **Phase 0b complete** (Wave 7 closeout), **Phase 1 / SLICE-1 complete** (2026-07-21). Portable core + `FakeRouterAdapter`, fake-only tests delivered; Python package **`router_control` exists**; **no** live router or network I/O; hardware gates A–D **closed**. **Phase 1 / SLICE-2 blocked** pending separate human approval. Актуальное состояние — [`STATUS.yaml`](STATUS.yaml); порядок slices — [`contracts/ROADMAP.md`](contracts/ROADMAP.md); порядок чтения — [`README.md`](README.md).

## Event scenario

Перед мероприятием оператор разворачивает Hub и NC-1812, проверяет identity/firmware/capabilities роутера и применяет заранее подготовленный event preset. Во время мероприятия посетители открывают по QR-коду стабильный HTTPS URL локальной order page, промоутеры работают с kiosk-интерфейсом, сотрудники следят за order board и производством, а администратор использует защищённые настройки Hub.

Система рассчитана на offline window 1–3 дня: локальные заказы и производство не должны зависеть от доступности внешнего control plane. Интернет и VPN могут быть нужны отдельным рабочим потокам, но их деградация не должна отключать локальную order page.

Если Router Control недоступен, выключен или не может подтвердить compatibility, Hub продолжает обслуживать kiosk, board и printing. Write operation в неизвестном состоянии не выполняется.

## Четыре network zones

### Guest

Открытый Guest Wi-Fi для телефонов посетителей. Единственный разрешённый business flow — HTTPS к локальной order page через стабильный URL, опубликованный на QR-коде/табличке. Guest clients изолированы друг от друга и не получают доступ к Hub settings, router management, Promo, Staff или Admin/Server resources.

### Promo

Управляемые event iPads/устройства с kiosk-интерфейсом. Они могут обращаться только к необходимым Hub endpoints и не получают router credentials, Router Control API, raw RCI или административные функции.

### Staff

Устройства команды для order board и production workflow. Доступ шире, чем у Promo, но network administration и secrets по-прежнему отделены.

### Admin/Server

Hub и локальное administrator device. Только эта trust zone может открывать защищённый `/settings` и инициировать Router Control operations. Нахождение в зоне само по себе не заменяет application authentication и operator confirmation.

Подробные trust boundaries и firewall assumptions зафиксированы в [`ARCHITECTURE.md`](ARCHITECTURE.md), а model-specific support — в [`COMPATIBILITY.md`](COMPATIBILITY.md). Normative zone allow/deny and operator scenarios: [`contracts/SCENARIOS.md`](contracts/SCENARIOS.md).

## Пользовательский результат

Оператор должен уметь:

1. однозначно enroll-ить NC-1812 по стабильному `RouterId` и проверяемому fingerprint, а не только по IP/default gateway;
2. увидеть model, firmware, capabilities и freshness observed state;
3. выполнить preflight и получить понятный fail-closed ответ при wrong network, неизвестной firmware или неподтверждённой capability;
4. просмотреть redacted plan/diff, явно нажать Confirm и наблюдать durable job;
5. получить read-back verification либо ясный статус `Failed`/`RecoveryRequired`, не ложный success;
6. восстановить last-known-good configuration через mandatory Safe Configuration и documented compensation procedure.

Browser/iPad никогда не должен получать router password, VPN private key, raw RCI session или startup-config. Secrets не попадают в plan diff, job payload, audit или diagnostics.

## Развитие capabilities

### VPN profiles

Первая write capability — каталог профилей **AmneziaWG only**. Каталог не имеет искусственного лимита, но первый deployment preset допускает ровно один active assignment на router. Unsupported fields, unknown firmware или неподтверждённые AWG semantics приводят к отказу от write.

Создание и переключение профиля выполняется только через immutable plan, operator Confirm, Safe Configuration, read-back и functional verification. На replacement router создаются новые keys, старые отзываются; перенос private keys по умолчанию не считается безопасным восстановлением.

### Routes

Будущий `RoutingPolicy` управляет `RouteSet`, ownership и desired/observed diff, а не принимает raw RCI commands. Private, RFC1918, CGNAT, link-local и multicast destinations не направляются в VPN. Цель в 5000 routes — performance target, а не обещанный production limit: допустимый предел будет установлен hardware benchmark на NC-1812.

### Traffic capture

Будущий `TrafficDiscovery` — отдельный Python bounded context внутри Hub. Capture превращает process/application evidence в `RouteProposal` с TTL/confidence и не пишет маршруты напрямую. Auto-apply возможен только после явного перевода policy в trusted; default flow — review и proposal.

Эти направления не входят в Phase 0a API или implementation. Их domain boundaries уточняются в [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md).

## Путь к module_3.0

До интеграции ядро разрабатывается в canonical repository `keenetic-control-plane` как переносимый Python package `router_control` (Phase 1 / SLICE-1 complete: domain, application и fake-only adapter). Domain и planner не импортируют FastAPI; отдельный FastAPI dev host — будущий SLICE-3 для prototype и contract tests. `ScanCursorIP` остаётся legacy behavioral evidence, а не домом новой реализации.

После прохождения fake, recorded и live hardware gates package будет перенесён в `module_3.0`:

- wiring через существующие bootstrap/dependencies/lifespan patterns;
- API на общем listener под `/api/router-control/v1/*`;
- fail-closed admin protection всего prefix;
- UI только как защищённый блок существующего `/settings`;
- отдельная `data/router_control.sqlite3`;
- failure isolation: Router Control не мешает запуску и основным event workflows Hub.

Это запланировано на Phase 8, а не на текущую Phase 0a. Legacy WPF/PowerShell продолжает работать до feature parity, полевой репетиции и подтверждённого cutover.

## Product principles

- **Local-first:** основной оператор и state доступны на площадке без обязательного внешнего control plane.
- **Plan before apply:** опасное изменение невозможно без свежего observed state, redacted diff и Confirm.
- **Fail closed for writes:** unknown identity, firmware, capability или stale plan блокируют mutation.
- **Managed ownership:** модуль не удаляет и не переписывает unmanaged resources.
- **Verification over HTTP success:** applied revision меняется только после read-back и postcondition verification.
- **Compensation, not fake atomicity:** rollback — проверяемая compensating operation; полная транзакционность роутера не обещается.
- **Hub survives:** сетевой модуль не является single point of failure для заказов и производства.

## Explicit non-goals

В первом цикле и v1 не планируются:

- настройка или mutation живого NC-1812 в Phase 0;
- автоматическая установка/обновление firmware или components;
- standard WireGuard, OpenVPN и другие VPN protocols кроме AmneziaWG v1;
- multi-vendor writes и универсальный raw RCI endpoint;
- multi-router UI;
- remote management без будущего RMM approval и audit;
- destructive reconciliation или prune unmanaged resources;
- передача secrets в browser, logs, diagnostics, audit или documentation;
- автоматическое изменение routes по Capture evidence без trusted policy;
- обещание поддержки 5000 routes до laboratory benchmark;
- публичная router-management panel или доступ Guest/Promo к Router Control;
- немедленная замена legacy-контуров до parity и field rehearsal;
- перенос prototype в `module_3.0` до завершения предусмотренных gates.

Любое расширение этих границ требует отдельного решения, обновления ADR и отражения в [`STATUS.yaml`](STATUS.yaml).
