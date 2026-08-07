# LOCAL HUB — implementation status

> **Единственный источник правды о состоянии инициативы «редизайн операторского интерфейса в LOCAL HUB».**
> Обновляется после каждого цикла и перед завершением каждой рабочей сессии.
> Живой план работ: [`.cursor/plans/local-hub-redesign.md`](../.cursor/plans/local-hub-redesign.md).
> Политика лаборатории и границы живых операций: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md), фазовый SSOT — [`STATUS.yaml`](STATUS.yaml).

## For agents

**Когда читать:** любой вход в инициативу LOCAL HUB, любой пакет работ, приёмка результата субагента.

**Порядок:** этот файл → раздел «Точка продолжения» → план → только потом код.

**Правила статусов:** `NOT_STARTED` / `IN_PROGRESS` / `IMPLEMENTED_UNVERIFIED` / `VERIFIED` / `BLOCKED` / `DEFERRED`.
`VERIFIED` ставится **только** при наличии фактического доказательства (имя прошедшей проверки/команда/артефакт), указанного в колонке «Проверка».
Формулировки «почти готово», «в основном работает» запрещены.

**Не делать:** живые операции против роутера 192.168.2.1 (их выполняет только ведущий оркестратор Main лично); коммиты и пуши; правки `STATUS.yaml`, `AGENTS.md`, `NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md`; правки старого `router_control_host/web/app.js`.

---

## 1. Текущее состояние

| Параметр | Значение |
|----------|----------|
| Дата обновления | 2026-08-03 |
| Пакет работ | 2 из ~6 (пакет 2: экраны «Обзор»…«VPN»; циклы VPN и «Домен» — `.cursor/plans/local-hub-pkg4-vpn-implementation-plan.md`, `.cursor/plans/local-hub-domain-implementation-plan.md`) |
| Ветка | `main`, рабочее дерево грязное (норма для проекта), коммитов не делалось |
| Новый интерфейс доступен | `http://127.0.0.1:8788/settings/router-control/hub/` (локальный fake-хост) |
| Старый интерфейс | `/settings/router-control` — работает, не изменялся |
| Режим адаптера по умолчанию | `fake` (`RC_ADAPTER_MODE`) |

Кратко: заложены архитектура, дизайн-система, оболочка приложения, навигация по 8 экранам и PWA-обвязка. **Экран «Обзор» (`#/overview`) реализован** — загрузка данных с существующих API, единый модуль проверки готовности, селектор мероприятия в верхней панели; правки вёрстки по макету `1.png`. **Экран «Подключение к роутеру» (`#/connection`) реализован** — трёхшаговый флоу (поиск → доступ → проверка), модель `connection-flow.js`, заполнение сессии оператора, подтверждение отпечатка устройства. **Экран «Рабочая сеть» (`#/staff-wifi`) реализован и переработан** — полноширинная карточка-шапка над двумя колонками, имя сети и бейдж в одной строке, переключатель и кнопка QR в одну линию; общий Wi‑Fi-слой вынесен в `wifi-ap-model.js` и `wifi-screen-parts.js`. **Экран «Гостевой Wi‑Fi» (`#/guest-wifi`) реализован** — `guest-wifi-model.js`, UI `guest-wifi.js`, честные UNSUPPORTED-блоки по ограничениям устройства. **Экран «VPN» (`#/vpn`) реализован** — `vpn-model.js`, UI `vpn.js`, read-only `POST /wireguard/observe`, no-echo на wireguard/vpn-policy/parse-preview маршрутах; три независимые строки статуса (настройка / связь с сервером / трафик через VPN); `HubState.SUCCESS` запрещён; декоративный переключатель заменён бейджем и кнопками подключить/отключить/переподключить. **Экран «Домен и публикация» (`#/domain`) реализован** — `domain-model.js`, UI `domain.js`, `.hub-domain__*`; `POST /keendns/status` (пустое тело → все поля `unknown`), `POST /keendns/preview` (`book`/`drop`, preview only), цепочка event-presets для `local_order_url` (чтение/сохранение новой ревизии с `If-Match` preset ETag + `Idempotency-Key`); три host-side пробы (`POST /lab/host-http-probe`, `/lab/host-tls-probe`, `/lab/host-internet-probe`); публикация — human gate M-5 (копируемый текст заявки, без облачной записи); макетные «Приложение опубликовано», бейдж «Доступно», зелёный чеклист и «Сохранить и опубликовать» **не воспроизводятся**. **Два экрана — заглушки** (Страницы входа, Диагностика). Backend в циклах VPN и «Домен»: read-only observe, host-side пробы (stdlib, allowlist RFC1918/ULA, no-echo), mypy теперь покрывает `router_control_host` (I-26 закрыт). Локальная проверка всех восьми экранов в браузере на fake-хосте выполнена (`scripts/main-verify-hub-screens.py`, iPad-landscape viewport). Живая проверка на реальном роутере **не выполнялась** — её делает человек/ведущий оркестратор.

---

## 2. Инструкция запуска

Локальный fake-хост (порт 8788; порт 8787 занят живым хостом ведущего оркестратора — не занимать):

```powershell
$env:RC_UNSAFE_DISABLE_AUTH="1"; $env:RC_STANDALONE_LOOPBACK_AUTH="1"; $env:RC_ADAPTER_MODE="fake"; $env:RC_PUBLIC_BASE_URL="http://127.0.0.1:8788"; $env:HUB_ADMIN_PASSWORD="x"; py -3.11 -m uvicorn router_control_host.app:app --host 127.0.0.1 --port 8788
```

- Новый интерфейс: `http://127.0.0.1:8788/settings/router-control/hub/`
- Старый интерфейс: `http://127.0.0.1:8788/settings/router-control`

`RC_UNSAFE_DISABLE_AUTH=1` работает только вместе со standalone-loopback профилем и `RC_ADAPTER_MODE=fake`; при live-адаптере он игнорируется (`router_control_host/app.py:237`). Интерфейс обязан показывать предупреждение, когда этот режим активен.

---

## 3. Архитектура

```
Браузер iPad (PWA, standalone)
        │  HTTPS/HTTP, cookie-сессия hub_admin
        ▼
FastAPI-хост router_control_host
        ├── /settings/router-control          старый UI (app.js, не трогаем)
        ├── /settings/router-control/hub/**   LOCAL HUB (новый, buildless ES-модули)
        └── /api/router-control/v1/**         публичный API (переиспользуется как есть)
                │
                ▼
        router_control (домен + порты)
                ├── fake-адаптер   RC_ADAPTER_MODE=fake
                └── live-адаптер   RC_ADAPTER_MODE=live (Gate A, pinned SSH)
```

Разделение UI ↔ устройство обеспечивает существующий слой адаптеров (`router_control/composition.py`, `create_offline_runtime` / `create_live_runtime`) — это и есть `RouterAdapter` из ТЗ §9. Второй адаптер не вводится.

Структура нового фронтенда:

```
router_control_host/web/hub/
├── index.html                 оболочка
├── app.js                     точка входа (ES-модуль)
├── manifest.webmanifest       PWA-манифест
├── sw.js                      service worker (кэш только оболочки)
├── icons/                     PNG/SVG иконки (генерируются скриптом)
├── styles/                    tokens.css, base.css, components.css, states.css, shell.css, screens.css
├── core/                      router.js, shell.js, api.js, errors.js, states.js, session.js
├── features/                  system-check.js, overview-model.js, connection-flow.js; vpn-model.js, domain-model.js (модели без DOM); общий Wi‑Fi-слой: wifi-ap-model.js (модель без DOM), wifi-screen-parts.js (шапка сети, модалки риска/QR, баннер демо, карточка «недоступно» — generic `buildRiskModalBody` и `createDemoBanner`); staff-wifi-model.js и guest-wifi-model.js — тонкие обёртки с operator copy
├── components/                переиспользуемые компоненты
└── screens/                   по одному модулю на экран (overview.js, connection.js, staff-wifi.js, guest-wifi.js, vpn.js, domain.js — реализованы; entry-pages.js, diagnostics.js — заглушки)
```

---

## 4. Карта экранов (макет → экран)

Сопоставлено по содержанию макетов (имена файлов не описательные). Порядок файлов совпал с порядком пунктов бокового меню.

| Файл макета | Экран | Заголовок в макете | Маршрут в SPA | Статус реализации |
|-------------|-------|--------------------|---------------|-------------------|
| `Привью интерфейса/1.png` | Обзор | «Сеть и роутер» | `#/overview` | IMPLEMENTED_UNVERIFIED |
| `Привью интерфейса/2.png` | Подключение к роутеру | «Подключение к роутеру» | `#/connection` | IMPLEMENTED_UNVERIFIED |
| `Привью интерфейса/3.png` | Рабочая сеть | «Рабочая сеть» | `#/staff-wifi` | IMPLEMENTED_UNVERIFIED |
| `Привью интерфейса/4.png` | Гостевой Wi‑Fi | «Гостевой Wi‑Fi» | `#/guest-wifi` | IMPLEMENTED_UNVERIFIED |
| `Привью интерфейса/5.png` | VPN | «VPN» | `#/vpn` | IMPLEMENTED_UNVERIFIED |
| `Привью интерфейса/6.png` | Домен | «Домен и публикация» | `#/domain` | IMPLEMENTED_UNVERIFIED |
| `Привью интерфейса/7.png` | Страницы входа | «Страницы входа» | `#/entry-pages` | NOT_STARTED |
| `Привью интерфейса/8.png` | Диагностика | «Диагностика» | `#/diagnostics` | NOT_STARTED |

Подтверждено человеком: 1 = Обзор, 2 = Подключение, 7 = Страницы входа. Остальные пять сопоставлены оркестратором по содержанию (заголовок экрана и подсветка пункта меню видны на каждом макете).

Общие элементы всех макетов: боковое меню из 8 пунктов, верхняя панель с селектором проекта/мероприятия, индикатор режима, кнопка настроек.

---

## 5. API и интеграции

Публичный префикс: `/api/router-control/v1`. Инвентаризация снята с декораторов `@router.*` в `router_control_host/*_routes.py`.

| Предметная область | Эндпоинты | Модуль |
|--------------------|-----------|--------|
| Состояние хоста | `GET /status`, `GET /observed-interfaces` | `routes.py:588` |
| Роутеры и учётные данные | `GET/POST /routers`, `GET /routers/{id}`, `POST /routers/{id}/preflight`, `GET/PUT /routers/{id}/credentials`, `POST .../rotate`, `POST .../revoke` | `routes.py:621` |
| Обнаружение и связь | `POST /lab/router-discovery`, `POST /lab/connection-health`, `POST /lab/bootstrap-discovery`, `POST /lab/wizard-draft-router`, `POST /lab/host-http-probe`, `POST /lab/host-tls-probe`, `POST /lab/host-internet-probe` (**новые**, read-only host-side; **не проверены на живом роутере**; internet-проба проверена с операторского хоста локально) | `router_discovery_routes.py:39`, `connection_health_routes.py:40`, `bootstrap_discovery_routes.py:38`, `wizard_draft_routes.py:114`, `host_probe_routes.py:179` |
| Ключ SSH | `POST /routers/{id}/ssh-host-key/learn`, `.../confirm` | `ssh_host_key_routes.py:46` |
| Wi‑Fi | `POST /wifi/preview`, `/wifi/apply`, `/wifi/teardown`, `/wifi/observed-state`, `/wifi/site-survey`, `/wifi/station/preview`, `/wifi/station/apply`, `/wifi/station/teardown` | `wifi_apply_routes.py:528`, `wifi_observed_routes.py:256`, `wifi_site_survey_routes.py:222`, `wifi_station_*` |
| VPN / WireGuard | `GET /vpn-profiles`, `POST /vpn-profiles/import`, `.../parse-preview`, `.../{id}/validate`, `POST /wireguard/preview`, `/wireguard/apply`, `/wireguard/teardown`, `POST /wireguard/observe` (**новый**, read-only; **не проверен на живом устройстве**), `POST /vpn/policy-routing/preview` | `routes.py:1620`, `wireguard_apply_routes.py:619`, `vpn_policy_preview_routes.py:64` |
| Домен | `POST /keendns/status`, `POST /keendns/preview`; экран также использует `GET/POST /event-presets/{id}/*` для `local_order_url` и три host-side пробы (см. выше) | `keendns_routes.py:40`, `preset_routes.py:133`, `host_probe_routes.py:179` |
| Сетевые семейства (предпросмотр) | `POST /vlan/preview`, `/dhcp/preview`, `/dns/preview`, `/firewall/preview` | `network_family_preview_routes.py:152` |
| Планы, операции, задания | `POST /routers/{id}/plans`, `.../confirm`, `.../apply`, `GET /operations/{id}`, `GET /jobs/{id}`, `POST /jobs/{id}/resume|compensate|cancel` | `routes.py:1995` |
| Комиссионирование и пресеты | `/sites/{id}/commissioning-runs`, `/commissioning-runs/{id}/*`, `/sites/{id}/event-presets`, `/event-presets/{id}/*` | `commissioning_routes.py:95`, `preset_routes.py:133` |
| RCI-мутации | `POST /routers/{id}/rci/fail-safe/arm|disarm`, `/rci/interface`, `/rci/system/configuration-save`, `/rci/system/reboot` | `rci_mutation_routes.py:245` |

**Пробелы, значимые для новых экранов** (эндпоинта не существует):

- список подключённых Wi‑Fi-клиентов и отключение устройства — нет;
- captive portal / страницы входа — нет ни одного эндпоинта;
- проверка доступности домена **из интернета** (внешняя точка наблюдения) — нет;
- переадресация портов для домена — нет API.

**UI-эндпоинты нового интерфейса** (вне публичного API, `include_in_schema=False`, поэтому OpenAPI-экспорт не меняется):

| Маршрут | Назначение |
|---------|-----------|
| `GET /settings/router-control/hub` и `/hub/` | оболочка LOCAL HUB |
| `GET /settings/router-control/hub/runtime.json` | честный режим работы: `adapter_mode`, `unsafe_auth_disabled`, `hub_version` |
| `GET /settings/router-control/hub/{path}` | статика нового интерфейса с allowlist расширений и защитой от traversal |

Конверт ошибки (`router_control_host/errors.py:550`): `{"error": {"code", "message", "details", "request_id", "correlation_id"}}`. Серверная функция `scrub_error_message` вычищает сообщение; на клиенте действует второй барьер — пользователю показывается объяснение из таблицы кодов, а серверный текст попадает только в свёрнутый блок «Технические подробности».

---

## 6. Реализованные функции

Таблица ведётся по ID. `VERIFIED` — только с доказательством.

| ID | Функция | Статус | Что реализовано | Файлы | Проверка | Блокер | Следующее действие |
|----|---------|--------|-----------------|-------|----------|--------|--------------------|
| H-ARCH-1 | Архитектурное решение (отдельный buildless модуль) | VERIFIED | Решение принято и зафиксировано с обоснованием | `docs/IMPLEMENTATION_STATUS.md` §11, `.cursor/plans/local-hub-redesign.md` §2 | Документ существует, содержит Р-1..Р-5 | — | — |
| H-DOC-1 | Живая документация инициативы | IN_PROGRESS | Создан этот файл, карта экранов, решения | `docs/IMPLEMENTATION_STATUS.md`, `docs/docs-map.json` | `scripts/validate-project-docs.ps1`, `scripts/project-docs.py audit` | — | Обновлять после каждого пакета |
| H-DOC-2 | План 18 циклов | IN_PROGRESS | Каркас, зоны владения, пакеты, задачи P1–P6 | `.cursor/plans/local-hub-redesign.md` | Два прохода ревью плана | — | Детализация задач по пакетам 2–6 при входе в каждый пакет |
| H-ROUTE-1 | Маршрут и отдача статики нового интерфейса | VERIFIED | Роутер `/settings/router-control/hub`, allowlist расширений, MIME, кэш-заголовки, `Service-Worker-Allowed`, защита от traversal | `router_control_host/hub_routes.py`, 2 строки в `router_control_host/app.py` | `tests/test_hub_routes.py`; фактические HTTP-ответы с локального хоста: shell 200 text/html, статика 200 с корректными MIME, `nope.js`/`secret.pem` → 404, `%2e%2e/app.js` → 400 | — | — |
| H-ROUTE-2 | Honesty-эндпоинт режима | VERIFIED | `runtime.json` отдаёт ровно `adapter_mode`, `unsafe_auth_disabled`, `hub_version` (keys-only контракт) | `router_control_host/hub_routes.py:211` (`serve_hub_runtime`) | `tests/test_hub_routes.py::test_hub_runtime_json` — точный набор ключей и типы; значения полей зависят от окружения (в тестовой фикстуре `adapter_mode=fake`, `unsafe_auth_disabled=false`, `hub_version=0.1.0`); в OpenAPI-экспорте маршрутов `/hub` нет (0 совпадений) | — | — |
| H-ROUTE-3 | Старый интерфейс не сломан | VERIFIED | Изменений в старом UI нет | — | `GET /settings/router-control` → 200; `GET /settings/router-control/assets/app.js` → 200 (416255 байт); `node --check router_control_host/web/app.js` → exit 0 | — | — |
| H-DS-1 | Дизайн-токены и базовые стили | IMPLEMENTED_UNVERIFIED | Палитра снята с макетов, 8 групп токенов, тач-области 44px, safe-area, 16px в полях ввода, отказ от hover, reduced-motion | `web/hub/styles/tokens.css`, `base.css` | Структурные тесты `tests/test_hub_frontend_contracts.py` | Визуальная сверка с макетами не проводилась | Визуальная сверка в браузере |
| H-DS-2 | Базовые компоненты | IMPLEMENTED_UNVERIFIED | Иконки, бейдж, кнопка, поля (текст/секрет/список/сегменты), переключатель, карточки, модалка с ловушкой фокуса, тосты, «технические подробности», витрина; **правило анти-растяжения** узких компонентов (бейджи, инлайн-плашки, кнопки) в `components.css` с явным opt-in полной ширины | `web/hub/components/*.js`, `styles/components.css` | `node --check` по всем модулям; `tests/test_hub_frontend_contracts.py` (pill-ширина и анти-растяжение с allowlist) | Визуальная сверка не проводилась | Визуальная сверка |
| H-DS-3 | Единый механизм состояний | IMPLEMENTED_UNVERIFIED | Все 14 состояний ТЗ §3 как данные (`STATE_DESCRIPTORS`), панель/строка/скелет/витрина | `web/hub/core/states.js`, `styles/states.css` | Тест падает при удалении любого из 14 состояний | — | Подключение к экранам в пакетах 2–5 |
| H-API-1 | Клиентский слой запросов и ошибок | IMPLEMENTED_UNVERIFIED | Обёртка `fetch` с таймаутом, разбор конверта ошибки, таблица кодов, no-echo, запрет повторов для POST, хуки потери связи и 401 | `web/hub/core/api.js`, `core/errors.js` | Тесты контрактов; отсутствие `console.log`, хранилищ, `innerHTML` | Поведение под реальными ошибками устройства не проверялось | Проверка на экранах пакета 2 |
| H-SHELL-1 | Оболочка и навигация по 8 экранам | IMPLEMENTED_UNVERIFIED | Боковое меню, верхняя панель, hash-роутер, 2 экрана-заглушки + реализованные «Обзор»…«Домен», служебная витрина, адаптация под вертикальную ориентацию | `web/hub/core/shell.js`, `core/router.js`, `screens/*.js`, `styles/shell.css`, `app.js` | Все модули отдаются по HTTP (200); граф import-спецификаторов разрешается полностью; `node --check` без ошибок; `scripts/main-verify-hub-screens.py` — все 8 экранов clean на fake-хосте (iPad-landscape) | **Визуальная сверка с PNG-макетами не выполнялась** | Визуальная сверка ведущим оркестратором по URL из §2 |
| H-SHELL-2 | Честный индикатор режима и предупреждение об отключённой авторизации | IMPLEMENTED_UNVERIFIED | Индикатор mock/реальное устройство/режим неизвестен; постоянная полоса при `unsafe_auth_disabled` | `web/hub/core/shell.js`, `app.js` | Код читает `runtime.json`; при неопределённом ответе показывает «Режим неизвестен» | Не подтверждено визуально | Визуальная проверка |
| H-PWA-1 | PWA-обвязка | IMPLEMENTED_UNVERIFIED | Манифест (scope/start_url `/settings/router-control/hub/`), service worker с кэшем только оболочки (`CACHE_VERSION=11`, precache включает модули «Обзор»…«VPN», «Домен» (`features/domain-model.js`, `screens/domain.js`) и общий Wi‑Fi-слой), иконки PNG/SVG, детерминированный генератор иконок | `web/hub/manifest.webmanifest`, `sw.js`, `icons/*`, `scripts/generate-hub-icons.py` | `tests/test_hub_pwa.py`, `tests/test_hub_overview.py::test_overview_pwa_shell_urls_updated`, `tests/test_hub_connection_screen.py::test_connection_pwa_shell_urls_updated`, `tests/test_hub_vpn.py`, `tests/test_hub_vpn_screen.py`, `tests/test_hub_domain.py`, `tests/test_hub_domain_screen.py`; каждый URL из precache-списка существует на диске | **Установка на домашний экран iPad не проверялась**; SW не выполнялся в браузере | Проверка установки на устройстве |
| H-TEST-1 | Тесты нового интерфейса | VERIFIED | Тринадцать+ наборов: маршруты и упаковка, PWA, контракты фронтенда (pill-ширина, анти-растяжение с allowlist, external-resource guard с узким исключением для двух scheme-литералов в `domain-model.js`), редирект после входа, экраны «Обзор»…«Домен», host-side пробы, guard mypy-config | `tests/test_hub_routes.py`, `tests/test_hub_pwa.py`, `tests/test_hub_frontend_contracts.py`, `tests/test_hub_overview.py`, `tests/test_hub_connection.py`, `tests/test_hub_connection_screen.py`, `tests/test_hub_staff_wifi.py`, `tests/test_hub_guest_wifi.py`, `tests/test_hub_vpn.py`, `tests/test_hub_vpn_screen.py`, `tests/test_hub_domain.py`, `tests/test_hub_domain_screen.py`, `tests/test_host_probes.py`, `tests/test_mypy_config.py`, дополнения в `tests/test_session_routes.py`, `tests/test_wireguard_apply_api.py`, `tests/test_operator_error_no_echo_guard.py` | Полный прогон pytest на финальной сверке цикла «Домен» (2026-08-03): **4152 passed, 2 skipped, 0 failed**; I-21 закрыт, набор полностью зелёный | — | Расширение по мере появления экранов |
| H-SEC-1 | Возврат в новый интерфейс после входа | VERIFIED | Пути `hub` добавлены в строгий allowlist `next`; allowlist остался перечнем точных путей | `router_control_host/session_routes.py:39` | Тесты: возврат на hub-путь, отклонение внешнего URL и traversal в `next` | — | — |
| H-SEC-2 | Усиленная защита статики от traversal | VERIFIED | Проверяются сырой путь и его одно- и двукратно URL-декодированные варианты, плюс проверка выхода за корень после `resolve()` | `router_control_host/hub_routes.py:108` | Тесты traversal в `tests/test_hub_routes.py`; фактический HTTP-зонд: `%2e%2e/app.js` → 400 | — | — |
| H-PKG-1 | Упаковка нового интерфейса | VERIFIED | `package-data` переведён на рекурсивный шаблон `web/**/*`: без этого вложенные каталоги `web/hub/**` не попадали в устанавливаемый пакет и интерфейс отдавал бы 404 из wheel | `pyproject.toml:36` | Тест-сторож в `tests/test_hub_routes.py`, падающий при возврате нерекурсивного шаблона | — | — |
| H-SESSION-1 | Состояние сессии оператора (память процесса) | IMPLEMENTED_UNVERIFIED | `getSession` / `updateSession` / `resetSession` / `subscribeSession`; `hasCompleteLiveWifiParams` (username/pin могут резолвиться сервером при `hostKeyConfirmed`); без браузерных хранилищ (О-4). **Bootstrap (`app.js`):** `GET /connection-context/restore-candidate` (или legacy fan-out) восстанавливает `routerId`, `routerHost`, `sourceAddress`, `hostKeyConfirmed`, `wifiLive.{host,credentialRefId}` без повторной церемонии; username не возвращается клиенту | `web/hub/core/session.js`, `web/hub/app.js`, `web/hub/screens/connection.js` | `tests/test_connection_context_api.py`, `tests/test_hub_wifi_shared.py`, `tests/test_hub_overview.py` (нет `localStorage`/`sessionStorage`); `tests/test_hub_connection_screen.py::test_connection_password_not_in_session` | Поведение restore на живом устройстве не проверялось (Main) | Экраны Wi‑Fi/VPN переиспользуют `wifiLive` из сессии |
| H-API-CONN-CTX-1 | Чтение контекста подключения (server-side) | IMPLEMENTED_UNVERIFIED | `GET /connection-context/restore-candidate` — один bounded SQL-read лучшего restorable роутера (`restore_candidate: true` + поля connection-context, или `{restore_candidate:false}`); tier: **genuine Enrolled** (в т.ч. без pin) → draft subtier (`live_ready` draft → non-`live_ready` draft); внутри genuine: **confirmed pin** → `live_ready` → `pinned_at` DESC → `created_at` ASC → `router_id` ASC. `GET /routers/{router_id}/connection-context` — только `router_id` в пути; cookie `hub_admin`; отдаёт endpoint host/port/source_address, credential_ref_id, метаданные SSH-пина, `username_available`, `live_ready`, `missing`; **не** отдаёт username, секреты, reachability; `Cache-Control: no-store`. `POST /routers/{router_id}/management-username` — запись username на ту же строку endpoint, что и pin; значение username **не** эхоится; curated в ui-field-manifest (`connection_context` family). `management_username` в SQLite (M12); wizard-draft сохраняет username; pin/username/host резолвятся из `get_connection_binding_endpoint`; live-путь доверяет только stored confirmed pin (`resolve_ssh_host_key_sha256`) | `router_control_host/ssh_host_key_routes.py`, `wifi_live_transport.py`, `persistence/store.py`, `application/ssh_host_key_pin.py` | `tests/test_connection_context_api.py`, `tests/test_ssh_host_key_pin.py`, `tests/test_persistence.py`; OpenAPI/manifest перегенерированы | Live-проверка не выполнялась | Live — Main |
| H-SYSCHECK-1 | Единый модуль проверки готовности системы | IMPLEMENTED_UNVERIFIED | **`features/system-check.js` — единственный источник правды** о готовности: `evaluateSystemCheck` (чистая функция) + `runSystemCheck` (POST `/lab/connection-health`). Экран «Диагностика» **обязан** импортировать этот модуль, а не дублировать логику. `hub_available` из `GET /status` не используется (M-7) | `web/hub/features/system-check.js` | `tests/test_hub_overview.py::test_overview_evaluate_system_check_behavior` (Node); `test_overview_hub_available_not_used`; синхронизация `REASON_CODE_TEXT` с backend | Поведение под live-ошибками устройства не проверялось | Переиспользование на экране «Диагностика» |
| H-OVERVIEW-1 | Экран «Обзор» | IMPLEMENTED_UNVERIFIED | Карточки роутера/VPN/домена/Wi‑Fi/страниц входа/событий; блок готовности системы; автообновление 60 с; `AbortController` + поколения render; данные через `overview-model.js` без DOM. **Правки по макету `1.png`:** заголовок раздела в плитке (`navLabel`) больше не подменяется данными — значение в `hub-overview__tile-value`; статус — компактный чип (`createBadge`); IP — обычная строка; карточка готовности перестроена (иконка и заголовок слева, описание под заголовком, кнопка справа — CSS `hub-overview__summary`); плитки ряда выровнены по высоте (`hub-overview__grid-item`); шкала заголовка экрана приведена к макету | `web/hub/screens/overview.js`, `features/overview-model.js`, `styles/screens.css`, `styles/tokens.css`, `components/card.js`, `field.js`, `modal.js` | `tests/test_hub_overview.py` (контракты, HTTP 200 новых ассетов, отсутствие mock-строк макета, no-echo) | **Визуальная сверка с макетом 1.png не выполнялась**; поведение на живом роутере не проверялось | Визуальная проверка человеком; live-проверка — Main |
| H-CONNECTION-1 | Экран «Подключение к роутеру» | IMPLEMENTED_UNVERIFIED | Трёхшаговый флоу (поиск → доступ → проверка); модель `connection-flow.js` (описание discovery, валидация форм, idempotency key, draft body, fingerprint, чеклист, finish gate, сетевые обёртки); UI в `connection.js`; стили `screens.css`; копирайт отпечатка и коды ошибок в `errors.js`; SW `CACHE_VERSION=4` | `web/hub/screens/connection.js`, `features/connection-flow.js`, `styles/screens.css`, `core/errors.js`, `core/session.js`, `sw.js` | `tests/test_hub_connection.py` (поведение модели через Node, OpenAPI-пути, idempotency, probe=false); `tests/test_hub_connection_screen.py` (структура экрана, no-echo, finish gate, HTTP 200 ассетов); дополнения в `tests/test_hub_frontend_contracts.py` | **Визуальная сверка с макетом 2.png не выполнялась**; поведение на живом роутере не проверялось; станционный Wi‑Fi-пикер сознательно не реализован (I-25) | Визуальная проверка человеком; live-проверка — Main |
| H-STAFF-WIFI-1 | Экран «Рабочая сеть» | IMPLEMENTED_UNVERIFIED | Выбор рабочей сети (AP3–6, `session.wifiRoles.staffApId` → карточка «Обзор»); observed/preview/apply/teardown через `staff-wifi-model.js` (тонкая обёртка над `wifi-ap-model.js`); UI `staff-wifi.js` с общими построителями из `wifi-screen-parts.js`; **переработка вёрстки:** полноширинная карточка-шапка над двумя колонками, имя сети и бейдж в одной строке, переключатель и кнопка QR в одну линию; operator copy без жаргона; QR; риск-модалка обрыва связи; честные UNSUPPORTED-блоки; выключение сети **только** через `POST /wifi/teardown` (`apply` с `enabled:false` даёт пустой план) | `web/hub/screens/staff-wifi.js`, `features/staff-wifi-model.js`, `features/wifi-ap-model.js`, `features/wifi-screen-parts.js`, `core/errors.js`, `styles/screens.css`, `styles/components.css` | `tests/test_hub_staff_wifi.py`; `tests/test_operator_error_no_echo_guard.py` (wifi-маршруты); `tests/test_hub_frontend_contracts.py` (pill/anti-stretch); `node --check`; локальная проверка в браузере (1180/1024 px, две колонки, полноширинная шапка, без ошибок консоли) | **Визуальная сверка с макетом 3.png не выполнялась**; live-проверка не выполнялась | Визуальная проверка человеком; live — Main |
| H-WIFI-SHARED-1 | Общий Wi‑Fi-слой (AP) | IMPLEMENTED_UNVERIFIED | `wifi-ap-model.js` — модель точки доступа без DOM (observed/preview/apply/teardown); `wifi-screen-parts.js` — общие построители: шапка сети, generic `buildRiskModalBody`, generic `createDemoBanner` (ссылка «Подключение» внутри предложения), модалка QR, карточка «недоступно»; Wi‑Fi-обёртки — тонкие; staff/guest builders делегируют generic | `web/hub/features/wifi-ap-model.js`, `features/wifi-screen-parts.js`, `features/staff-wifi-model.js`, `features/guest-wifi-model.js` | `tests/test_hub_staff_wifi.py`, `tests/test_hub_guest_wifi.py`, `tests/test_hub_vpn_screen.py`; `node --check` | Поведение на живом роутере не проверялось | Переиспользование на будущих экранах |
| H-GUEST-WIFI-1 | Экран «Гостевой Wi‑Fi» | IMPLEMENTED_UNVERIFIED | UI `guest-wifi.js`; модель `guest-wifi-model.js` (обёртка над `wifi-ap-model.js`); observed/preview/apply/teardown; общие построители из `wifi-screen-parts.js`; operator copy; QR; риск-модалка; честные UNSUPPORTED-блоки (см. §7); выключение сети **только** через `POST /wifi/teardown`; дубль «Показать QR-код» убран из «Быстрые действия» | `web/hub/screens/guest-wifi.js`, `features/guest-wifi-model.js`, `features/wifi-ap-model.js`, `features/wifi-screen-parts.js`, `styles/screens.css` | `tests/test_hub_guest_wifi.py`; `tests/test_hub_frontend_contracts.py`; `node --check`; локальная проверка в браузере (1180/1024 px, две колонки, полноширинная шапка, без ошибок консоли); `scripts/main-verify-hub-screens.py` | **Визуальная сверка с макетом 4.png не выполнялась**; live-проверка не выполнялась | Визуальная проверка человеком; live — Main |
| H-VPN-1 | Экран «VPN» | IMPLEMENTED_UNVERIFIED | UI `vpn.js`; модель `vpn-model.js` (без DOM): каталог профилей, parse-preview/import/validate, preview/apply/teardown/observe; три строки статуса (настройка на роутере / связь с сервером VPN / трафик через VPN); бейдж + кнопки подключить/отключить/переподключить (декоративный toggle убран); `handshake_settle_seconds: 25` при apply; `HubState.SUCCESS` **запрещён**; честные UNSUPPORTED-блоки (см. §7); стили `.hub-vpn__*`; SW `CACHE_VERSION=9` | `web/hub/screens/vpn.js`, `features/vpn-model.js`, `features/wifi-screen-parts.js`, `styles/screens.css`, `sw.js` | `tests/test_hub_vpn.py`, `tests/test_hub_vpn_screen.py`; `tests/test_operator_error_no_echo_guard.py` (wireguard/vpn-policy/parse-preview); `tests/test_wireguard_apply_api.py`; `node --check`; `scripts/main-verify-hub-screens.py` — экран clean на fake-хосте | **Визуальная сверка с макетом 5.png не выполнялась**; live-проверка не выполнялась; `POST /wireguard/observe` не проверен на живом устройстве | Визуальная проверка человеком; live — Main |
| H-API-WG-OBSERVE-1 | Read-only observe туннеля WireGuard | IMPLEMENTED_UNVERIFIED | `POST /wireguard/observe` — `_readback_show_interface` + `observe_tunnel`; без write, backup, configuration-save и sealed-apply trail; live gating идентичен apply; `WireguardObserveResponse` | `router_control_host/wireguard_apply_routes.py`, `apply_response_models.py` | `tests/test_wireguard_apply_api.py`, `tests/test_wireguard_live_wiring.py`, `tests/test_operator_error_no_echo_guard.py` | **Не проверен на живом устройстве** | Live-проверка — Main |
| H-SHELL-3 | Селектор мероприятия в верхней панели | IMPLEMENTED_UNVERIFIED | `GET /status` → `default_site_id`, затем `GET /sites/{site_id}/event-presets`; выбор сохраняется в сессии (`eventPresetId`, `eventPresetName`) | `web/hub/core/shell.js`, `web/hub/core/session.js` | Код и контрактные тесты shell; HTTP-ответы presets в fake-режиме | Не подтверждено визуально | Визуальная проверка |
| H-DOMAIN-1 | Экран «Домен и публикация» | IMPLEMENTED_UNVERIFIED | UI `domain.js`; модель `domain-model.js` (без DOM): `POST /keendns/status` (пустое тело), `POST /keendns/preview` (`book`/`drop`), цепочка event-presets для `local_order_url` (чтение + `POST /event-presets/{id}/revisions` с preset ETag в `If-Match`, `Idempotency-Key`, документ целиком с заменой только `local_order_url`); три host-side пробы по явному действию; human gate M-5 (копируемый текст заявки, выбор режима доступа, чеклист; без облачной записи); `HubState.SUCCESS` запрещён в зоне публикации; макетные «Приложение опубликовано», «Доступно», зелёный чеклист и «Сохранить и опубликовать» **не воспроизводятся**; QR через `features/wifi-qr.js` (canvas); стили `.hub-domain__*`; SW `CACHE_VERSION=11` | `web/hub/screens/domain.js`, `features/domain-model.js`, `styles/screens.css`, `core/errors.js`, `sw.js` | `tests/test_hub_domain.py`, `tests/test_hub_domain_screen.py` (решения D-DOM-1…D-DOM-12 — каждое с тестом, падающим при намеренном нарушении); `tests/test_operator_error_no_echo_guard.py`; `tests/test_hub_frontend_contracts.py`; `node --check`; `scripts/main-verify-hub-screens.py` — экран clean на fake-хосте | **Визуальная сверка с макетом 6.png не выполнялась человеком** (оркестратор — только скриншоты); live-проверка не выполнялась; host-side пробы не запускались против 192.168.2.1 | Визуальная проверка человеком; live — Main |
| H-API-HOST-PROBE-1 | Host-side пробы (HTTP/TLS/internet) | IMPLEMENTED_UNVERIFIED | `POST /lab/host-http-probe`, `/lab/host-tls-probe`, `/lab/host-internet-probe` — stdlib only; тела несут только `*_ref` + id сохранённых записей (без URL/hostname от клиента); allowlist RFC1918/ULA после резолва; IP пинится; редиректы не следуются; тело ответа не возвращается; bounded DNS; `writes_allowed=false`, `certification_eligible=false`; no-echo; TLS `ok` только при reachable+trusted+hostname+not_expired; leaf-only на Python 3.11 (`chain_inspected: false`) | `router_control_host/host_probes.py`, `host_probe_routes.py`, `apply_response_models.py`, `state.py`, `app.py` | `tests/test_host_probes.py`, `tests/test_operator_error_no_echo_guard.py`; OpenAPI snapshot перегенерирован (три публичных маршрута); `BODY_ROUTE_EXEMPTIONS` в `scripts/export-ui-field-manifest.py`; internet-проба подтверждена с операторского хоста при локальной верификации | **Три пробы не выполнялись против реального роутера**; HTTP/TLS пробы не проверялись на hardware | Live-проверка HTTP/TLS — Main |

### Экран «Обзор» — источники данных (проверено по коду)

| Элемент UI | Источник данных | Поведение без данных |
|------------|-----------------|----------------------|
| Готовность системы («Система готова к работе» и т.п.) | `POST /lab/connection-health` + подтверждённый оператором SSH-пин из сессии (`hostKeyConfirmed`); вердикт только в `features/system-check.js` | «Готовность не определена»; `hub_available` **не используется** |
| Кнопка «Проверить систему» | тот же `runSystemCheck` | — |
| Карточка «Роутер» (название, производитель, модель) | `GET /routers` → `display_name`, `vendor`, `model` | «Роутер не подключён» + переход `#/connection` |
| IP-адрес роутера на карточке | `connection-health.host` из вердикта system-check | «Адрес неизвестен» |
| VPN (имя профиля, тип) | `GET /vpn-profiles` | «Профиль VPN не добавлен» |
| Состояние VPN-туннеля | **нет read-only эндпоинта** | бейдж «Активность VPN сейчас не проверяется»; SUCCESS запрещён |
| Домен | `POST /keendns/status` (без исходных данных classify → `unknown`) | «Состояние домена неизвестно» |
| Имя домена на Обзоре | **нет источника** | не показывается отдельным полем |
| Рабочая сеть (SSID, статус) | `POST /wifi/observed-state` для `session.wifiRoles.staffApId`; роль выбирает оператор на экране «Рабочая сеть» | «Состояние сети — в разделе» + ссылка `#/staff-wifi` |
| Гостевая сеть (SSID, статус) | `POST /wifi/observed-state` для `session.wifiRoles.guestApId`; роль выбирает оператор на экране «Гостевой Wi‑Fi» | «Состояние сети — в разделе» + ссылка `#/guest-wifi` |
| Страницы входа | **нет API** | `UNSUPPORTED`: «Не поддерживается» |
| Последние события | **нет ленты событий** | блок с честным объяснением, что журнал не ведётся |
| Селектор мероприятия (верхняя панель) | `GET /status` → `default_site_id`, затем `GET /sites/{site_id}/event-presets` | «Мероприятие не выбрано» |
| Индикатор режима | `GET /settings/router-control/hub/runtime.json` → `adapter_mode` | «Режим неизвестен» |

**Осознанно не показывается на Обзоре** (решение M-6; источника в backend нет):

- число подключённых устройств;
- скорость канала;
- страна VPN;
- уровень сигнала Wi‑Fi;
- статус «Опубликован» у домена;
- статус страниц входа как «Настроены»;
- QR-код на Обзоре (кнопка ведёт на «Гостевой Wi‑Fi»).

### Экран «Подключение» — источники данных (проверено по коду)

| Элемент UI | Источник данных | Поведение без данных |
|------------|-----------------|----------------------|
| Шаги «1. Поиск / 2. Доступ / 3. Проверка» | локальное состояние `ConnectionStep` в `connection.js` | шаг «Доступ» недоступен до выбора/ввода адреса; шаг «Проверка» — до сохранения доступа и подтверждения отпечатка |
| Список найденных роутеров | `POST /lab/router-discovery` (`probe: false`, `include_default_gateway`, `include_known_endpoints`) → `describeDiscovery` | «Роутеры не найдены» + ручной ввод; честная пометка, что это перебор известных/сохранённых адресов, а не сканирование сети (I-15) |
| Примечание о границах поиска | константа `BOUNDS_NOTE` в `connection-flow.js` | всегда показывается на шаге поиска |
| Деградация источников поиска | `degraded_sources` и `source_diagnostics` ответа discovery | предупреждение «часть источников недоступна» или пояснение по каждому источнику |
| Ручной ввод адреса | поле формы оператора | валидация `validateManualHost` |
| Форма доступа (адрес, пользователь, пароль) | ввод оператора + выбранный кандидат | ошибки валидации `validateAccessForm`; пароль очищается после успешного сохранения |
| Сохранение доступа | `POST /lab/wizard-draft-router` с обязательным заголовком `Idempotency-Key`; пароль уходит один раз, в сессию не попадает | ошибка API → панель состояния + тост; повтор — тот же idempotency key до успеха |
| Пояснение хранения доступа | константа `ACCESS_STORAGE_NOTE` | «Пароль на планшете не хранится…»; фраза «только на этом iPad» **запрещена** (I-13) |
| Поля сессии после сохранения | `updateSession`: `routerId`, `routerHost`, `wifiLive.{host,username,credentialRefId}`; `hostKeyConfirmed: false` | без `routerId`/`credentialRefId` шаг отпечатка недоступен |
| Восстановление при загрузке hub | `app.js` → `GET /connection-context/restore-candidate` (server-side selection) | без пригодного роутера — `{restore_candidate:false}`; live не включается |
| Бейдж «Отпечаток подтверждён на сервере» / «Привязан» / «Неизвестно» / «Отпечаток не совпадает» | `deriveVerifyHostKeyBadge` по `connection-context.ssh_host_key.confirmed`, `session.hostKeyConfirmed` и `health.facts.host_key_match` | без health и с подтверждённым pin на сервере — «Отпечаток подтверждён на сервере» (нейтрально, **не** означает ответ роутера сейчас); после health: `true` → «Привязан»; `false` → «Отпечаток не совпадает»; `null`/отсутствует → «Неизвестно» (нейтрально, **не** негатив) |
| Получение отпечатка | `POST /routers/{id}/ssh-host-key/learn` | ошибка → панель + тост; конфликт → модалка замены |
| Подтверждение отпечатка | `POST /routers/{id}/ssh-host-key/confirm` → `updateSession({ hostKeyConfirmed: true, wifiLive.sshHostKeySha256 })` | без подтверждения finish gate закрыт (fail-closed) |
| Чеклист проверки (5 пунктов) | `POST /lab/connection-health` → `buildConnectionChecklist` по фактам `reachable`, `credentials_present`, `host_key_match`, `tuple_match`, `evidence_fresh` | каждый факт: пройдено / не пройдено / неизвестно; строка «Сохранённый доступ есть» **не** означает подтверждённые права администратора |
| Строки «Локальная сеть», «Интернет», «Уровень сигнала» | **не проверяются backend** — `UNSUPPORTED_CHECKLIST_ITEMS` | всегда нейтральный тон «Система не проверяет…»; SUCCESS запрещён |
| Кнопка «Завершить настройку» | `evaluateFinishGate` (fail-closed): статус ≠ red, все 5 фактов true, `hostKeyConfirmed === true`; в fake — явная пометка демо-режима | причина блокировки показывается в `hub-connection__finish-reason` |
| Индикатор режима | `GET /settings/router-control/hub/runtime.json` → `adapter_mode` | «Режим неизвестен» |

**L-2 (connection context restore):** `GET /connection-context/restore-candidate` (bounded SQL, prefer pinned real router over newer drafts) + bootstrap restore в `app.js`; per-router `GET /routers/{router_id}/connection-context` остаётся для экрана «Подключение»; username и pin резолвятся на сервере по `router_id` (`wifi_live_transport.py`, M12 `management_username`). Fail-closed: без подтверждённого pin live params incomplete (`tests/test_ssh_host_key_pin.py::test_connection_params_missing_when_no_stored_pin_with_username_and_cred`, `tests/test_hub_wifi_shared.py::test_live_params_fail_closed_without_confirmed_pin_in_session`).

**Пробел с отпечатком (legacy UI):** резолвер `resolve_ssh_host_key_sha256` вызывается live Wi‑Fi путями через `wifi_live_transport.py` при переданном `router_id`; хранилище заполняется подтверждением (`/ssh-host-key/confirm`) и wizard-draft (username). Старый UI не проводил confirm. Новый hub проводит learn→confirm и восстанавливает контекст при загрузке. Без подтверждённого pin live-транспорт получает отказ (`SshHostKeyMissing`), а не подставленное значение. Перенос fallback из connection-health в live-транспорт **запрещён**.

**Сознательно не реализовано на этом экране (I-25):** станционный Wi‑Fi-пикер (подключение роутера к чужой сети) — на макете `2.png` его нет; по операторской документации это задача настройки интернет-канала, а не подключения оператора к роутеру. Требование честности выбора защиты (планировщик station поддерживает только `wpa2_psk` и `open`; выбор сети с другой защитой обязан явно предупреждать — I-6) остаётся **открытым** и переходит на экран, где появится пикер.

### Экран «Рабочая сеть» — реализовано и ограничения (проверено по коду)

| Элемент | Статус |
|---------|--------|
| Выбор рабочей сети (AP3–6, 2,4 / 5 ГГц) | `listStaffWifiAccessPoints`; выбор в `session.wifiRoles.staffApId` питает карточку «Обзор» |
| Чтение состояния, сохранение, выключение, перезапуск | `POST /wifi/observed-state`, `/wifi/preview`, `/wifi/apply`, `/wifi/teardown` через `staff-wifi-model.js` |
| QR-код подключения | `features/wifi-qr.js`; пароль не сохраняется в URL |
| Список подключённых клиентов | **нет API** — блок UNSUPPORTED |
| Отключение неизвестного устройства | **нет API** — блок UNSUPPORTED |
| Скрытие названия сети | роутер не отдаёт параметр через управление — пояснение в UI |
| «Разрешить доступ к роутеру» через Wi‑Fi | **нет источника данных** — пояснение в UI |
| Страница персонала (captive portal) | **нет API** — блок UNSUPPORTED |
| Открытая сеть без пароля | роутер не поддерживает — в перечислении режимов защиты нет открытого; честная подпись под полем «Защита» |
| Выключение сети | **только** `POST /wifi/teardown`; `apply` с `enabled:false` даёт пустой план |
| No-echo на wifi-маршрутах | `tests/test_operator_error_no_echo_guard.py` — canary не попадает в ответы preview/apply/observed-state/site-survey |

### Экран «Гостевой Wi‑Fi» — реализовано и ограничения (проверено по коду)

| Элемент | Статус |
|---------|--------|
| Чтение состояния, сохранение, выключение, перезапуск | `POST /wifi/observed-state`, `/wifi/preview`, `/wifi/apply`, `/wifi/teardown` через `guest-wifi-model.js` → `wifi-ap-model.js` |
| QR-код подключения | общий построитель из `wifi-screen-parts.js`; пароль не сохраняется в URL |
| Выключение сети | **только** `POST /wifi/teardown`; `apply` с `enabled:false` даёт пустой план |
| Изоляция гостевых клиентов | **не поддерживается** — планировщик отвергает `guest_isolation=true` с 422 `wifi.guest_isolation_unsupported`; блок UNSUPPORTED в UI |
| Страница после подключения / captive portal | **не поддерживается** — 422 `wifi.captive_portal_unsupported`; блок UNSUPPORTED в UI |
| Сеть без пароля (открытая) | **не поддерживается** — в перечислении режимов защиты нет открытого; честная подпись под полем «Защита» |
| Лимит числа устройств | **нет поля** — блок UNSUPPORTED в UI |
| Список клиентов и счётчик устройств | **нет источника данных** — блоки UNSUPPORTED в UI |
| Проверка сети глазами гостя из панели | **невозможна** — панель управления не может подключиться к гостевой сети; честное пояснение в UI |

### Экран «VPN» — источники данных (проверено по коду)

| Элемент UI | Источник данных | Поведение без данных |
|------------|-----------------|----------------------|
| Бейдж состояния в шапке (не переключатель) | последний известный `tunnel_verification_status` из apply/teardown/observe; `tunnel_healthy` → «Сервер VPN отвечает»; иначе нейтральный/предупреждающий тон | «VPN не подключён» или «Состояние не проверялось» |
| Кнопки «Подключить VPN» / «Отключить VPN» / «Переподключить» | локальное состояние + `evaluateVpnMutationReadiness` (сессия `wifiLive`, `hostKeyConfirmed`, `adapter_mode`) | кнопка disabled + пояснение в `hub-vpn__action-reason`; в fake — баннер демо через `createDemoBanner` |
| Строка 1 «Настройка на роутере» | поля `overall`, `configuration_verification_status`, `interface_verification_status` последнего ответа apply/teardown | «Настройки туннеля на роутер не отправлялись» |
| Строка 2 «Связь с сервером VPN» | `tunnel_verification_status` из apply/teardown/observe (`describeTunnelStatus`) | «Связь с сервером VPN не проверялась»; `HubState.SUCCESS` **запрещён** даже при `tunnel_healthy` |
| Кнопка «Проверить состояние» | `POST /wireguard/observe` (read-only; без записи) | доступна после apply/teardown или по явному действию; автоматического опроса при входе **нет** |
| Строка 3 «Трафик через VPN» | **нет источника** — постоянный UNSUPPORTED (I-2) | «Трафик устройств через VPN не идёт…» |
| Выбор интерфейса туннеля (Wireguard5–9) | локальный выбор оператора + allowlist `vpn-model.js` | первый доступный индекс по умолчанию |
| Каталог профилей VPN | `GET /vpn-profiles` | «Профили VPN не добавлены» + кнопка импорта |
| «Загрузить конфигурацию» (parse) | `POST /vpn-profiles/parse-preview` → `sanitized_dict_for_apply()` (peer routing fields без секретов) | ошибка parse → панель состояния + тост |
| «Сохранить в каталог» | `POST /vpn-profiles/import` | импорт ≠ подключение; пояснение `VPN_CATALOG_IMPORT_NOT_CONNECTION_NOTE` |
| Подключение туннеля | `POST /wireguard/preview` → `POST /wireguard/apply` с `handshake_settle_seconds: 25`, таймаут клиента 60 с | во время apply — `HubState.CONNECTING` + «Договариваемся с сервером VPN…»; вердикт до ответа не показывается |
| Отключение туннеля | `POST /wireguard/teardown` | риск-модалка через `buildRiskModalBody` |
| Технический блок (отвергнутые сигналы) | `verdict_explanation.rejected_signals` из observe/apply | misleading device fields явно помечены ignored |
| Живой туннель (критерий) | handshake timestamp **и** `peer_online=true` **и** `peer_rxbytes>0` (`wireguard_apply_service.py`) | без всех трёх — не `tunnel_healthy` |
| Направление трафика | **нет apply-маршрута** — только `POST /vpn/policy-routing/preview` | блок UNSUPPORTED |
| Kill-switch | I-2: отказ planner не вызывается из preview в рантайме | блок UNSUPPORTED |
| Автопереподключение | **нет источника/API** | блок UNSUPPORTED |
| Резервный профиль / backup channel | **нет источника/API** | блок UNSUPPORTED |
| Страна, задержка, внешний IP, uptime соединения | **нет источника данных** | не показываются; пояснение в UNSUPPORTED-блоке |
| Баннер демо-режима | `GET /settings/router-control/hub/runtime.json` → `adapter_mode=fake` | ссылка «Подключение» внутри предложения |
| Индикатор режима | `runtime.json` → `adapter_mode` | «Режим неизвестен» |

**На экране «Обзор»** карточка VPN по-прежнему использует только `GET /vpn-profiles` и **не** вызывает observe — бейдж «Активность VPN сейчас не проверяется».

### Экран «Домен» — источники данных (проверено по коду)

| Элемент UI | Источник данных | Поведение без данных |
|------------|-----------------|----------------------|
| Шапка «Публикация в облаке не выполнена» (не «Приложение опубликовано») | `POST /keendns/status` с телом `{}` → classify без сырого вывода → все поля `unknown` | «Состояние публикации неизвестно»; бейдж «Состояние неизвестно», `WARNING`; `HubState.SUCCESS` **запрещён** (D-DOM-1) |
| Черновая ссылка (имя + домен accept-list) | локальная сборка из ввода оператора + 7 доменов планировщика; DNS-метка валидируется на клиенте | «Адрес не задан»; кнопки «Открыть»/копировать/QR disabled + причина; пояснение «Ссылка существует только как черновик…» (D-DOM-12) |
| «Локальное приложение» | `EventPresetDocument.local_order_url` выбранного мероприятия (`session.eventPresetId`) | «Мероприятие не выбрано» или «На площадке ещё нет мероприятий» / «Мероприятие есть, но не выбрано» — различаются честно (I-28) |
| «Локальный адрес» (host:port) | `GET /event-presets/{id}` → `current_revision_id` → `GET …/revisions/{rev}` → `canonical_document.local_order_url` | «Адрес приложения не задан» |
| Переключатель HTTPS | схема `local_order_url` (`https://` ↔ `http://`); сохранение — `POST /event-presets/{id}/revisions` (весь документ, заменён только `local_order_url`, preset ETag в `If-Match`, `Idempotency-Key`) | без пресета — disabled; при `http://` — предупреждение о `local_order_url_not_https`; новая ревизия **не публикуется** (D-DOM-5) |
| «Показать, что будет отправлено» | `POST /keendns/preview`, `intent_kind=book` | «Предпросмотр не запрашивался» |
| «Оформить заявку на публикацию» / «Отключить публикацию» | human gate M-5: модалка с копируемым текстом (`ndns book-name` / `ndns drop-name`), выбор режима доступа, чеклист; `POST /keendns/preview` (`drop` для снятия) | облачных вызовов **нет** (D-DOM-7, I-3) |
| «Расширенные настройки» | `preview_ops[].command_text`, `notes`, `verification_status` из последнего preview | «Предпросмотр не запрашивался» |
| Локальная сеть (HTTP с компьютера оператора) | `POST /lab/host-http-probe` (`url_ref=event_preset_local_order_url`) — **только по явному действию** | «не проверялось» |
| Интернет с компьютера оператора | `POST /lab/host-internet-probe` — **только по явному действию** | «не проверялось»; **не** интернет роутера (I-31) |
| Сертификат HTTPS | `POST /lab/host-tls-probe` — **только по явному действию**; leaf-only, `chain_inspected: false` (I-30) | «не проверялось» |
| Переадресация | **нет API** | `UNSUPPORTED` (D-DOM-8) |
| Проверка извне (из интернета) | **нет внешней точки наблюдения** | `UNSUPPORTED` |
| QR-код | `features/wifi-qr.js` (`drawWifiQrCanvas`) от черновика ссылки | disabled + причина; без `blob:` (I-12, D-DOM-11) |
| «Поделиться» | `navigator.share` если есть, иначе копирование | fallback без обещаний |
| Селектор мероприятия (верхняя панель) | `GET /status` → `default_site_id`, затем `GET /sites/{site_id}/event-presets` | «Мероприятие не выбрано» |
| Индикатор режима | `GET /settings/router-control/hub/runtime.json` → `adapter_mode` | «Режим неизвестен» |

**Сознательно не воспроизводится из макета `6.png`:** «Приложение опубликовано», бейдж «Доступно», зелёный четырёхстрочный чеклист, кнопка «Сохранить и опубликовать», подпись «После изменения адреса старая ссылка перестанет работать» (D-DOM-1, D-DOM-7, D-DOM-12).

---

## 7. Нереализованные функции

Два экрана из ТЗ §4 остаются `NOT_STARTED` по функциональности: **Страницы входа**, **Диагностика**. Экраны «Обзор»…«Домен» — `IMPLEMENTED_UNVERIFIED` (см. §6).

### Честные ограничения экрана «VPN» (не реализуются; UI показывает UNSUPPORTED или WARNING)

| Возможность | Причина | Пояснение в UI |
|-------------|---------|----------------|
| Маршрутизация трафика устройств через VPN | адрес VPN-интерфейса не применяется; нет маршрута apply policy-routing (I-2) | постоянная строка 3 «Трафик через VPN» + блок «Направление трафика» |
| Направление трафика (весь / выборочно) | только `POST /vpn/policy-routing/preview` | UNSUPPORTED |
| Kill-switch («остановить трафик при сбое VPN») | planner refusal не wired в preview runtime (I-2) | UNSUPPORTED |
| Автопереподключение | нет API/грамматики | UNSUPPORTED |
| Резервный профиль / backup channel | нет API/грамматики | UNSUPPORTED |
| Страна, задержка, внешний IP, время соединения | роутер не сообщает эти данные (M-6) | не показываются |
| `HubState.SUCCESS` на экране | решение P4-D1: даже `tunnel_healthy` не означает успех оператора | максимум `WARNING` |
| Декоративный toggle «VPN включён» | заменён бейджем и явными кнопками connect/disconnect/reconnect | — |

**Живой туннель** доказывается только handshake timestamp вместе с `peer_online` и ненулевым `peer_rxbytes`; поля `interface up`, `link`, `connected`, `peer enabled`, одиночный `peer_txbytes` — явно отвергаются в technical block.

### Честные ограничения экрана «Гостевой Wi‑Fi» (не реализуются; UI показывает UNSUPPORTED)

| Возможность | Причина | Код ошибки / пояснение |
|-------------|---------|------------------------|
| Изоляция гостевых клиентов | планировщик отвергает `guest_isolation=true` | 422 `wifi.guest_isolation_unsupported` |
| Страница после подключения / captive portal | нет грамматики применения | 422 `wifi.captive_portal_unsupported` |
| Сеть без пароля (открытая) | в перечислении режимов защиты нет открытого | — |
| Лимит числа устройств | поля в API/планировщике нет | — |
| Список подключённых клиентов | нет read-only эндпоинта | — |
| Счётчик устройств | нет источника данных | — |
| Проверка сети глазами гостя из панели | панель управления не может подключиться к гостевой сети | — |

**Выключение гостевой (и рабочей) сети:** только `POST /wifi/teardown`; попытка `apply` с `enabled:false` даёт пустой план — UI не имитирует выключение через apply.

### Честные ограничения экрана «Домен» (не реализуются; UI показывает UNSUPPORTED, WARNING или human gate)

| Возможность | Причина | Пояснение в UI |
|-------------|---------|----------------|
| Облачная публикация / снятие имени KeenDNS | human gate M-5; cloud dispatch path отсутствует (I-3) | «Оформить заявку на публикацию» → модалка с копируемым текстом; без облачной записи |
| Статус «Опубликовано» / «Доступно» | classify без сырого CLI → всегда `unknown`; SUCCESS запрещён (D-DOM-1, I-29) | «Состояние публикации неизвестно»; макетные формулировки не воспроизводятся |
| Классификация `unavailable` из этого экрана | экран не имеет источника сырого вывода роутера; только Main делает live read (I-29) | недостижимо с экрана — показывается `unknown` |
| Локальный адрес без мероприятия | `local_order_url` живёт в event preset (D-DOM-4) | «Мероприятие не выбрано»; на свежей установке пресетов нет (I-28) |
| Создание мероприятия с экрана | вне scope экрана | подсказка на селектор; создать событие отсюда нельзя (I-33) |
| Проверка из интернета | нет внешней точки наблюдения | `UNSUPPORTED` |
| Переадресация портов | нет API | `UNSUPPORTED` |
| Цепочка TLS-сертификатов | Python 3.11 — только leaf (I-30) | `chain_inspected: false` в ответе пробы |
| Интернет-проба как «интернет роутера» | проба идёт с компьютера оператора к публичным адресам (I-31) | строка подписана «Интернет с компьютера оператора» |
| Автоматический прогон проб при открытии | F-9 / D-DOM-8 | пробы только по явному действию оператора |

---

## 8. Тестовая матрица

| Слой | Инструмент | Состояние |
|------|-----------|-----------|
| Python unit/integration | `pytest` (183+ файлов тестов) | базовый прогон: **4152 passed, 2 skipped, 0 failed** (финальная сверка цикла «Домен», 2026-08-03); набор полностью зелёный, I-21 закрыт |
| Lint Python | `ruff` | exit 0 обязателен |
| Типы Python | `mypy` (`files = ["router_control", "router_control_host"]` в `pyproject.toml`) | exit 0 обязателен по обоим пакетам; **I-26 закрыт**; guard `tests/test_mypy_config.py` |
| JS-синтаксис | `node --check` по каждому модулю | node v22.20.0 в PATH |
| JS-поведение | `tests/test_hub_overview.py` исполняет `evaluateSystemCheck` через Node (без jest/vitest/playwright, без `package.json`); остальные проверки JS — текстовые/структурные тесты на Python | поведенческий тест готовности системы есть; e2e/playwright — `DEFERRED` (I-14) |
| Стабильность контрактов | `scripts/export-openapi.py`, `scripts/export-ui-field-manifest.py` (дважды, побайтово) | exit 0 обязателен |
| Документация | `scripts/validate-project-docs.ps1`, `scripts/project-docs.py audit` | exit 0 обязателен |
| LOCAL HUB экраны (fake-хост) | `scripts/main-verify-hub-screens.py` | все 8 экранов clean на iPad-landscape viewport (цикл «Домен») |

Известных падений pytest больше нет: ранее «нечинимые» `test_connection_health_host_api_yellow_without_probe` и `test_live_create_app_wires_soft_candidate_identity_probe` закрыты привязкой синтетического Gate A к текущему времени (I-21). Любое новое падение считать регрессией.

---

## 9. Проверки на реальном роутере

**Живых проверок не выполнялось** (экраны «Обзор»…«Домен», эндпоинты `POST /wireguard/observe`, три host-side пробы против роутера). Internet-проба выполнялась с операторского хоста при локальной верификации и не доказывает доступ роутера в интернет. Любые операции против устройства 192.168.2.1 выполняет только ведущий оркестратор Main лично, в границах [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md).

Сценарий будущей аппаратной проверки нового интерфейса будет подготовлен в пакете 6.

---

## 10. Известные проблемы и честные инварианты

Новый интерфейс **обязан** отражать эти ограничения честно и не имеет права заявлять обратное:

| № | Ограничение | Влияние на UI |
|---|-------------|---------------|
| I-1 | Изоляция клиентов гостевой сети и captive portal: устройство отвечает 422, подтверждённой грамматики нет | Переключатель изоляции и «страница после подключения» на экране «Гостевой Wi‑Fi» — не заявлять применение; показывать «не поддерживается на этом устройстве» |
| I-2 | Маршрутизация трафика через VPN не работает: планировщик отказывает без `address_configured=true` (`router_control/application/vpn_policy_routing_planner.py:199`), маршрута применения политики не существует — только `POST /vpn/policy-routing/preview`. Отказ по kill-switch (`refuse_ip_policy_permit_global`) сейчас вызывается **только из тестов**, а не из пути предпросмотра | Блок «Направление трафика» и «Остановить трафик при сбое VPN» — предпросмотр/недоступно, без имитации успеха. Нельзя утверждать, что kill-switch «защищён отказом» в рантайме |
| I-3 | Публикация домена KeenDNS/CrazeDNS — только чтение и предпросмотр; облачная запись требует человеческого пакета (M-5) | Экран «Домен»: «Оформить заявку на публикацию» открывает human gate с копируемым текстом (`ndns book-name` / `ndns drop-name`); облачных вызовов нет; макетная «Сохранить и опубликовать» **не воспроизводится** |
| I-4 | KeenDNS `#settings` — заглушка без параметров | Экран «Домен»: не показывать несуществующие параметры |
| I-5 | VLAN/DHCP/DNS/firewall/VPN policy — только предпросмотр | «Расширенные настройки» — режим предпросмотра |
| I-6 | **Уточнено по коду 2026-08-02 (первоначальная формулировка была неверной).** Грамматика WPA3 **есть** у планировщика точки доступа: `WifiWpaMode` поддерживает `WPA2`, `WPA3`, `WPA2_WPA3_MIXED` (`router_control/domain/network_intents.py:74`), план собирается через `_wpa3_apply_ops` и подтверждён на устройстве NC‑1812, прошивка 5.01.C.1.0-0 (`router_control/application/wifi_apply_planner.py:38,371`). Ограничение относится к планировщику **клиентского подключения (station)**: `WifiStationAuthMode` допускает только `wpa2_psk` и `open` (`router_control/application/wifi_station_apply_planner.py:200`) | Экраны «Рабочая сеть» и «Гостевой Wi‑Fi» могут честно предлагать WPA3 для точки доступа. Молчаливая подмена по-прежнему запрещена: в старом интерфейсе гостевая точка и uplink‑AP жёстко зашиты на `WPA2` (`router_control_host/web/app.js:2141,8786,10571`) — в новом интерфейсе так делать нельзя. Для подключения к чужой сети WPA3 предлагать нельзя — грамматики нет |
| I-7 | `RC_UNSAFE_DISABLE_AUTH` сейчас предупреждает только в логе | Новый интерфейс показывает предупреждение в оболочке |
| I-8 | **Частично закрыт (цикл VPN).** No-echo: синтезированные сообщения вместо `str(exc)` на wireguard preview/apply/teardown/observe (ответы и sealed-apply audit), `vpn/policy-routing/preview`, `vpn-profiles/parse-preview`. **Остаточный** `message=str(exc)` сохраняется на: `routes.py` (plans/jobs/routers и др.), `wifi_*_routes.py`, `wifi_station_*`, `ssh_host_key_routes.py`, `connection_health_routes.py`, `router_discovery_routes.py`, `bootstrap_discovery_routes.py`, `commissioning_routes.py`, `preset_routes.py`, `rci_mutation_routes.py`, `traffic_discovery_routes.py`, `keendns_routes.py` | Новые экраны не тащат echo дальше; legacy-маршруты чинятся при следующем касании |
| I-9 | `GET /status` возвращает `hub_available: True` жёстко (`router_control_host/routes.py:594`) — это признак живости хоста, а не готовности системы | Запрещено использовать как источник статуса «Система готова к работе» на экране «Обзор» |
| I-10 | Нет API: лента событий, число подключённых клиентов, статус страниц входа, статус «локального приложения», уровень сигнала | Соответствующие блоки макетов 1 и 2 показывают честное состояние «нет данных» / «не поддерживается» |
| I-11 | Состав `ConnectionHealthResponse.facts` (`router_control_host/apply_response_models.py:471`) не совпадает с чеклистом из макета 2 | Рисовать только фактически возвращаемые проверки, не дорисовывать недостающие |
| I-12 | CSP `img-src 'self' data:` не разрешает `blob:` | QR-коды и предпросмотры — через canvas или `data:`-URI |
| I-13 | Подпись макета 2 «Данные доступа сохранены только на этом iPad» противоречит устройству системы: учётные данные хранятся на сервере управления через `credential_ref`/vault | Текст к воспроизведению запрещён |
| I-14 | Из ТЗ §10 в проекте отсутствуют инструменты e2e, визуальных тестов, автопроверки доступности и адаптивности; JS-тестового рантайма и `package.json` нет | Статус этих проверок — `DEFERRED`; ставить по ним `VERIFIED` запрещено |
| I-15 | «Автоматический поиск роутера» — это **не** сканирование сети. `POST /lab/router-discovery` читает локальную таблицу маршрутов Windows (`router_control_host/host_route_table.py:20`) и сохранённые endpoints; сканирования подсети, ARP и ping нет (`bounds.subnet_scan=false`, `router_control/application/router_discovery.py:779`). Модели устройства в ответе тоже нет | Экран «Подключение» не обещает поиск по всей сети; называть вещи своими именами и предусмотреть ручной ввод как полноценный путь |
| I-16 | В fake-режиме identity probe не подключается (`router_control_host/app.py:164`), поэтому `POST /lab/router-discovery` с `probe=true` отвечает **422**, а `/lab/connection-health` даёт `yellow` с `reachability_unknown` | Демонстрационный режим должен честно показывать «проверка недоступна», а не зелёный статус |
| I-17 | `/lab/connection-health` возвращает пять фактов связи и идентичности (`reachable`, `host_key_match`, `tuple_match`, `credentials_present`, `evidence_fresh`), а не девятипунктную диагностику из ТЗ §4. Отдельного эндпоинта диагностики не существует | Экран «Диагностика» строится из нескольких источников, недостающие пункты помечаются честно |
| I-18 | Существующие fake-данные покрывают Wi‑Fi, WireGuard и enrollment; **не** дают реалистичный mock для экранов «Страницы входа» и «Диагностика»; для «Домен» — только при наличии event preset | Либо досоздать фикстуры, либо честно показывать пустое состояние; имитировать успех запрещено; на свежей установке пресетов нет — половина экрана «Домен» недоступна (I-28) |
| I-19 | HTTP-эндпоинта «список поддерживаемых и неподдерживаемых возможностей устройства» **не существует**. Есть `GET /status` (gates, feature_state) и `GET /routers/{id}/family-certifications/status` (строки хранилища сертификаций), но каталога возможностей для интерфейса нет | Состояние «не поддерживается» интерфейс выводит из фактического ответа операции (например 422 с кодом `wifi.guest_isolation_unsupported`), а не из несуществующего справочника |
| I-20 | Клиент обязан ветвиться по `error.code`, а не только по HTTP-статусу (`docs/contracts/API_CONTRACT.md:171`). В старом интерфейсе так сделано ровно в одном месте, остальное — показ `e.message` | Новый клиентский слой уже реализует таблицу кодов; при добавлении экранов ветвление делать по `code` |
| I-21 | Два известных падения pytest вызваны **ходом реального времени**, а не роутером: синтетический Gate A в тестах фиксирует `evidence_recorded_at` на 2026‑08‑01, а окно свежести — 24 часа, поэтому `evidence_fresh=False` и `gate_a.is_open=False` | Не пытаться чинить их как регрессию нового интерфейса |
| I-22 | В старом интерфейсе примерно 250+ англоязычных строк, видимых пользователю | Новый интерфейс переписывается с нуля по-русски; сканирование на латиницу входит в задачу P5-5 |
| I-23 | Состояние сессии оператора живёт **только в памяти вкладки** (`core/session.js`, правило О-4); браузерные хранилища не используются | После перезагрузки страницы `hostKeyConfirmed` и прочие поля сессии сбрасываются — подтверждение отпечатка на экране «Подключение» нужно выполнить заново (на сервере pin при этом сохранён) |
| I-24 | Зелёная готовность в live-режиме дополнительно требует открытого Gate A и совпадения записи устройства (`tuple_match`, `evidence_fresh`) — одного прохождения экрана «Подключение» недостаточно | Экран «Обзор» и finish gate «Подключения» не объявляют полную готовность к записи на устройство без этих фактов |
| I-25 | **Станционный Wi‑Fi-пикер на экране «Подключение» сознательно не реализован** (на макете `2.png` его нет; подключение роутера к uplink-сети — отдельная задача настройки интернет-канала). Требование честности выбора защиты station (I-6: только `wpa2_psk`/`open`; молчаливая подмена запрещена) **остаётся открытым** | При появлении пикера на экране «Рабочая сеть» или отдельном экране uplink — явное предупреждение при несовместимой защите; не считать сделанным на «Подключении» |
| I-26 | **Закрыт (цикл «Домен», 2026-08-03).** `pyproject.toml` задаёт `files = ["router_control", "router_control_host"]`; override `ignore_errors` для `router_control_host.*` **удалён**; 32 ошибки исправлены (9 casts, 0 новых blanket suppressions). Остаётся 16 `# type: ignore[no-any-return]` на house-pattern `_state(request)` (15 до цикла + 1 в `host_probe_routes.py:50`) | Exit 0 `mypy` доказывает типобезопасность обоих пакетов; guard `tests/test_mypy_config.py` падает при повторном исключении host |
| I-27 | Цикл «Домен» **не проверен на реальном роутере** 192.168.2.1: экран, `POST /keendns/*` с live raw, host HTTP/TLS пробы | Любые live-операции — только Main лично; статус экрана и проб остаётся `IMPLEMENTED_UNVERIFIED` |
| I-28 | На свежей установке event presets = 0 → локальный адрес и пробы недоступны до создания мероприятия | Экран различает «мероприятий ещё нет» и «есть, но не выбрано»; создать событие с экрана нельзя |
| I-29 | `POST /keendns/status` с пустым телом **всегда** даёт `unknown` по всем полям; классификация `unavailable` с экрана недостижима — нет источника сырого вывода CLI | Показывать «неизвестно»; получить `unavailable` можно только после live read роутера (Main) |
| I-30 | Python 3.11 в TLS-пробе отдаёт только leaf-сертификат; цепочка не инспектируется | `chain_inspected: false` в ответе; aggregate `ok` — только leaf-критерии (D-DOM-10) |
| I-31 | `POST /lab/host-internet-probe` проверяет интернет **компьютера оператора**, не роутера | Строка подписана «Интернет с компьютера оператора»; не утверждать доступ роутера |
| I-32 | Визуальная сверка экрана «Домен» с макетом `6.png` выполнялась оркестратором по скриншотам, не человеком | Статус визуальной проверки — `IMPLEMENTED_UNVERIFIED`; human visual — Main |
| I-33 | С экрана «Домен» нельзя создать event preset | Подсказка на селектор мероприятия; половина экрана blocked без пресета |

---

## 11. Принятые решения

| ID | Решение | Обоснование |
|----|---------|-------------|
| Р-1 | Новый интерфейс — **отдельный** buildless ES-модульный фронтенд в `router_control_host/web/hub/`, отдаётся новым роутером `router_control_host/hub_routes.py` под префиксом `/settings/router-control/hub`. Старый `app.js` не трогается; P5-разбиение монолита снимается как отдельная задача | Старый UI и завязанные на него регрессионные тесты (`tests/test_config_ui.py`, baseline `node --check router_control_host/web/app.js`) продолжают работать без правок. Префикс — потомок `UI_PREFIX`, поэтому новый интерфейс автоматически попадает под существующий auth-middleware (`router_control_host/app.py:314`) без правки middleware и без нового неаутентифицированного пути. Откат тривиален: удалить модуль, каталог и одну строку `include_router` |
| Р-2 | **Buildless**, без сборщика и без npm-зависимостей | `node` и `npm` в PATH есть, но `package.json`/`node_modules` в репозитории нет; ассеты отдаются из Python-пакета через `importlib.resources`, поэтому сборка потребовала бы коммита dist-артефактов и рассинхронизации source/dist. Старый UI уже грузится как `<script type="module">`. **Честная трактовка ТЗ §11 «production build проходит»: шага сборки нет; эквивалент — `node --check` по каждому модулю плюс тесты маршрутов статики. Имитация сборки запрещена** |
| Р-3 | Маршрутизация внутри SPA — hash-based (`#/overview`, …) | Не требует catch-all-роутов на backend, корректно работает в standalone-PWA и офлайн |
| Р-4 | PWA: `scope` и `start_url` = `/settings/router-control/hub/`; SW по пути `hub/sw.js`; `<link rel="manifest" crossorigin="use-credentials">` | Такой scope не требует заголовка `Service-Worker-Allowed`. Авторизация cookie-based, поэтому без `use-credentials` браузер запросил бы манифест без cookie и получил 401 |
| Р-5 | CSP не ослабляется | Действующая политика (`router_control_host/ui_routes.py:25`) уже разрешает ES-модули, service worker и манифест. Следствие для кода: запрещены inline-`<script>` и атрибуты `style="…"`; динамические стили — только через CSSOM |
| Р-6 | Service worker кэширует **только оболочку**; ответы `/api/**` и `runtime.json` не кэшируются никогда; ответы со статусом ≠200 (в т.ч. 401) в кэш не попадают | Данные о сети и состоянии устройства не должны переживать сессию на диске iPad; закэшированный 401 залипал бы в неавторизованном состоянии |
| Р-7 | Честный индикатор режима — отдельный UI-эндпоинт `GET /settings/router-control/hub/runtime.json` (`include_in_schema=False`), возвращающий только `adapter_mode`, `unsafe_auth_disabled`, `hub_version` | Публичный API и его OpenAPI-экспорт остаются побайтово стабильными; в ответе нет ни одного чувствительного поля |
| Р-8 | **Определение готовности, примиряющее ТЗ §11 с честными инвариантами:** элемент управления считается готовым, если он либо выполняет реальную операцию, либо честно находится в состоянии «не поддерживается»/«предпросмотр» с объяснением причины. Отсутствие элемента — тоже допустимый исход | ТЗ §11 требует «все элементы управления работают» и «нет декоративных кнопок», а инварианты I‑1..I‑6 означают, что часть функций устройство не поддерживает. Без этого правила пакет 6 закрыл бы §11 ложью |
| Р-9 | Текст макетов не является истиной: при противоречии между подписью в макете и фактическим устройством системы побеждает факт. Числа из макетов («8 устройств», «46 мс», «8 из 8») — иллюстрации, а не значения по умолчанию | Макеты рисовались до сверки с реальными возможностями устройства и API |
| Р-10 | **`features/system-check.js` — единственный источник правды о готовности системы.** Экран «Обзор» и будущий экран «Диагностика» обязаны импортировать его (`evaluateSystemCheck`, `runSystemCheck`, `describeFacts`, `REASON_CODE_TEXT`), а не дублировать логику вердикта. `hub_available` из `GET /status` запрещён как индикатор готовности (M-7, I-9) | Дублирование приведёт к расхождению «Обзор» ↔ «Диагностика» и ложному READY |
| D-DOM-1 | `HubState.SUCCESS` **запрещён** в зоне публикации и статуса домена; «Приложение опубликовано» и бейдж «Доступно» из макета не воспроизводятся | M-6, P4-D4; тест в `tests/test_hub_domain.py` |
| D-DOM-2 | `SUCCESS` допустим только: (а) строка группы «проверено с компьютера оператора» при факте `true`; (б) локальная готовность черновика ссылки | не заявление о доступности в облаке |
| D-DOM-3 | Статус домена — только `POST /keendns/status` с `{}`; без инъекции raw CLI из UI | classify → `unknown`; I-29 |
| D-DOM-4 | «Локальное приложение» = `EventPresetDocument.local_order_url`; единственный пункт — «Система заказов» | M-6 |
| D-DOM-5 | Локальный адрес редактируется через цепочку event-presets; сохранение — новая immutable revision с preset ETag | `If-Match` = preset ETag, не revision ETag |
| D-DOM-6 | Черновая ссылка — клиентская DNS-метка + accept-list; preview вызывается и для других имён | блокируется только сборка ссылки |
| D-DOM-7 | «Сохранить и опубликовать» заменена на preview + human gate; облачных вызовов нет | M-5, I-3 |
| D-DOM-8 | Группа проверок — «Проверено с компьютера оператора»; не состояние роутера | host-side пробы |
| D-DOM-9 | Три состояния факта: true / false / null+reason_code | недостижимость ≠ «опровергнуто» |
| D-DOM-10 | TLS aggregate `ok` только при reachable ∧ trusted ∧ hostname ∧ not_expired | самоподписанный — warning |
| D-DOM-11 | QR — `features/wifi-qr.js`, canvas, без `blob:` | I-12 |
| D-DOM-12 | «Старая ссылка перестанет работать» не воспроизводится — в облаке имя не зарегистрировано | черновик ссылки |

---

## 12. Журнал выполненных циклов

| Дата | Пакет | Цикл ТЗ §7 | Что сделано |
|------|-------|------------|-------------|
| 2026-08-02 | 1 | 1 | Аудит репозитория параллельными агентами; сверка макетов; проверка тулчейна |
| 2026-08-02 | 1 | 2 | Создан этот документ и план инициативы |
| 2026-08-02 | 1 | 3 | Архитектурное решение Р-1..Р-7; дизайн-токены и базовые стили |
| 2026-08-02 | 1 | 4 | Маршрут отдачи нового интерфейса, оболочка, навигация, PWA-обвязка |
| 2026-08-02 | 1 | — | Два прохода ревью плана: самопроверка оркестратора и независимый adversarial-рецензент (8 BLOCKER, 9 MAJOR, 4 MINOR); блокирующие находки исправлены, остальные внесены в план §7a |
| 2026-08-03 | 1 | polish-wave1-c2 | Контраст badge/link (primary-text, danger-text), restore connectivity banner on online, SW precache all-or-nothing (CACHE v2), усиленный router contract test, RECOVERING copy host wording |
| 2026-08-03 | 1 | polish-wave1-c3 | Wave2 MAJOR: primary-hover контраст ≥4.5:1, exact Service-Worker-Allowed, structural precache test, showcase h2 outline + div card titles, clearConnectionLost latch |
| 2026-08-03 | 1 | polish-wave1-c3b | Wave3 MAJOR API-Q-W3-01: mergeSignals без утечки abort-listeners (AbortSignal.any / cleanup в finally), SW precache comment all-or-nothing |
| 2026-08-03 | 1 | polish-wave1-c4 | Wave4: residual MAJOR по осям tests/docs (mergeSignals OR-vacuity, H-ROUTE-2 evidence honesty prep) |
| 2026-08-03 | 1 | polish-wave1-c5 | Wave5 MAJOR: TOK-A11Y-W5-01 `a:active` → primary-text без opacity; DOCS-W5-01 H-ROUTE-2 keys-only evidence; mergeSignals test AND-only (fallback + finally) |
| 2026-08-03 | 2 | P2-1 | Экран «Обзор»: `session.js`, `system-check.js`, `overview-model.js`, `screens/overview.js`, `styles/screens.css`; селектор мероприятия в `shell.js`; SW `CACHE_VERSION=3`; тесты `tests/test_hub_overview.py`; backend не менялся |
| 2026-08-03 | 2 | P2-3 | Экран «Рабочая сеть»: `staff-wifi-model.js`, `staff-wifi.js`, operator copy, `tests/test_hub_staff_wifi.py`, no-echo guard wifi; усиление тестов discovery/PWA; `IMPLEMENTATION_STATUS.md`; backend не менялся; визуальная/live-проверка не выполнялись |
| 2026-08-03 | 2 | P2-2 | Экран «Подключение»: `features/connection-flow.js`, `screens/connection.js`, правки `styles/screens.css`, `core/errors.js`, `core/session.js` (заполнение полей); правки «Обзора» по макету `1.png` (`overview.js`, `tokens.css`, `card.js`, `field.js`, `modal.js`); SW `CACHE_VERSION=4` + precache `connection-flow.js`; тесты `tests/test_hub_connection.py`, `tests/test_hub_connection_screen.py`, дополнения в `tests/test_hub_frontend_contracts.py` и `tests/test_hub_overview.py`; backend не менялся; визуальная/live-проверка не выполнялись |
| 2026-08-03 | 2 | P2-4 | Экран «Гостевой Wi‑Fi»: `guest-wifi-model.js`, `guest-wifi.js`; общий Wi‑Fi-слой `wifi-ap-model.js`, `wifi-screen-parts.js`; рефакторинг `staff-wifi-model.js` в тонкую обёртку; переработка вёрстки «Рабочая сеть» (полноширинная шапка, inline badge/toggle/QR); правило анти-растяжения узких компонентов в `components.css`; SW `CACHE_VERSION=8` + precache новых модулей; тесты `tests/test_hub_guest_wifi.py`, дополнения в `tests/test_hub_frontend_contracts.py`; локальная проверка в браузере (1180/1024 px, без ошибок консоли); backend не менялся; live-проверка не выполнялась |
| 2026-08-03 | 2 | P4-VPN | Экран «VPN»: `vpn-model.js`, `vpn.js`, `.hub-vpn__*` стили; read-only `POST /wireguard/observe`; no-echo wireguard/vpn-policy/parse-preview; `sanitized_dict_for_apply()` для peer routing fields; рефакторинг `wifi-screen-parts.js` (generic risk modal + demo banner); правки guest-wifi (дубль QR), staff-wifi (склейка предложений); SW `CACHE_VERSION=9`; тесты `tests/test_hub_vpn.py`, `tests/test_hub_vpn_screen.py` + дополнения wireguard/no-echo/awg; два adversarial review wave; pytest 3944 passed / 2 failed (pre-existing); `scripts/main-verify-hub-screens.py` — 8/8 clean; live-проверка и observe на hardware **не выполнялись** |
| 2026-08-03 | 2 | P4-DOM | Экран «Домен»: `domain-model.js`, `domain.js`, `.hub-domain__*`; host-side пробы `host_probes.py`, `host_probe_routes.py`; mypy scope расширен на `router_control_host` (I-26 закрыт); SW `CACHE_VERSION=11`; тесты `tests/test_hub_domain.py`, `tests/test_hub_domain_screen.py`, `tests/test_host_probes.py`, `tests/test_mypy_config.py` + дополнения no-echo/frontend-contracts; два adversarial review wave (5+6 рецензентов); pytest **4152 passed, 2 skipped, 0 failed**; `ruff`/`mypy`/exports exit 0; `scripts/main-verify-hub-screens.py` — 8/8 clean; live-проверка экрана и проб на hardware **не выполнялись**; internet-проба подтверждена с операторского хоста |
| 2026-08-03 | 2 | P4-DOM-final | Финальная сверка цикла «Домен» силами Main: перезапуск всего протокола (`ruff` 0, `mypy` 0 на 152 файлах, `node --check` по всем модулям hub, оба экспорта побайтово стабильны, оба валидатора docs exit 0). Закрыт **I-21**: фикстуры `_gate_a()` в `tests/test_connection_health.py` и `tests/test_router_discovery.py` привязаны к `datetime.now(UTC)` вместо календарной даты; проверка версии SW в `tests/test_hub_vpn_screen.py` переведена с точного литерала `'10'` на монотонный порог `>= 10`. Итог: **4152 passed, 2 skipped, 0 failed** — впервые полностью зелёный набор. Браузерная проверка: 8/8 экранов clean + отдельная проверка «Домена» с выбранным мероприятием (22 интерактивных элемента, ошибок консоли нет) |

**Polish wave1 — stop (2026-08-03):** после 5 волн L2 (≥4 полных циклов) находки продолжают появляться; закрыты только остаточные wave5 MAJOR. Дальнейшие polish-волны не планируются — переход к пакету 2.

**Residual NIT / deferred (не блокируют пакет 2):**

- CSP/security headers на 401 ответах hub (`app.py` middleware — вне owned polish wave1)
- визуальная сверка оболочки с макетами и установка PWA на iPad (browser visual)
- `a:active` контраст — исправлен в wave5 (primary-text, opacity снята со ссылок)

---

## 13. Точка продолжения для следующего агента

**Состояние после цикла «Домен», очередь «Страницы входа» (2026-08-03).**

Что уже стоит и работает:

- новый интерфейс открывается по `http://127.0.0.1:8788/settings/router-control/hub/` (команда запуска — §2);
- оболочка, боковое меню из 8 экранов, hash-роутер, честный индикатор режима, предупреждение об отключённой авторизации, PWA-обвязка (`CACHE_VERSION=11`);
- дизайн-система: токены, базовые стили, компоненты (в т.ч. правило анти-растяжения узких элементов), единый механизм 14 состояний, клиентский слой API и ошибок;
- **экран «Обзор»** (`#/overview`): загрузка данных с API, блок готовности через `features/system-check.js`, карточки секций, автообновление; правки вёрстки по макету `1.png`;
- **экран «Подключение»** (`#/connection`): трёхшаговый флоу, модель `connection-flow.js`, learn/confirm отпечатка, чеклист connection-health, finish gate;
- **экран «Рабочая сеть»** (`#/staff-wifi`): выбор рабочей точки AP3–6, observed/preview/apply/teardown через общий слой `wifi-ap-model.js`, переработанная вёрстка, QR, operator copy, честные UNSUPPORTED-блоки; выключение только через `POST /wifi/teardown`;
- **экран «Гостевой Wi‑Fi»** (`#/guest-wifi`): `guest-wifi-model.js`, UI `guest-wifi.js`, общие построители `wifi-screen-parts.js`, честные UNSUPPORTED-блоки по I-1;
- **экран «VPN»** (`#/vpn`): `vpn-model.js`, UI `vpn.js`, preview/apply/teardown/observe, три строки статуса, бейдж + connect/disconnect/reconnect, честные UNSUPPORTED по I-2;
- **экран «Домен»** (`#/domain`): `domain-model.js`, UI `domain.js`, keendns status/preview, event-presets для `local_order_url`, host-side пробы, human gate M-5; `scripts/main-verify-hub-screens.py` — clean на fake-хосте;
- **backend циклов VPN и «Домен»:** `POST /wireguard/observe` (read-only, **не проверен на hardware**); три host-side пробы (**не проверены на hardware**); no-echo на wireguard/vpn-policy/parse-preview и host-probe маршрутах;
- **mypy** покрывает `router_control` и `router_control_host` (I-26 закрыт);
- **общий Wi‑Fi-слой:** `wifi-ap-model.js`, `wifi-screen-parts.js` (generic `buildRiskModalBody`, `createDemoBanner`);
- **состояние сессии** в `core/session.js` заполняется экраном «Подключение»; Wi‑Fi/VPN/Домен переиспользуют `wifiLive` / `eventPresetId`;
- **селектор мероприятия** в верхней панели;
- тесты: полный набор hub + domain/host-probes/mypy-config. Последний измеренный прогон Main в конце этапа (2026-08-03) — **4152 passed, 2 skipped, 0 failed**; набор впервые полностью зелёный. Ранее в этом разделе фигурировали срезы 4119 и 4132 passed с двумя падениями — те падения закрыты в рамках I-21 (фикстуры Gate A привязаны к `datetime.now(UTC)`), а не «известные и нечинимые».

Чего нет:

- функциональности **двух** экранов (Страницы входа, Диагностика) — заглушки (`entry-pages.js` — `renderStubScreen`);
- для «Страницы входа»: captive portal API отсутствует (P4-D5, I-1);
- визуальной сверки реализованных экранов с PNG-макетами **человеком** (оркестратор — только скриншоты для «Домен», I-32);
- проверки установки PWA на iPad;
- живой проверки экранов, `POST /wireguard/observe` и host-side проб на реальном роутере (192.168.2.1 — только Main лично);
- станционного Wi‑Fi-пикера и честности выбора защиты station (I-25).

**ВНИМАНИЕ: очередь изменилась после живой кампании Main 2026-08-03.** Следующие в работе — **не** новые экраны, а два блокирующих дефекта, найденных на настоящем роутере. Они описаны с доказательствами в `.cursor/plans/main-decisions-local-hub.md` §M-9 и продублированы в `docs/STATUS.yaml` `next_task`; при расхождении с этим разделом выигрывают они.

- **L-1 — опознанный роутер показывается как неопознанный.** С `probe=true` кандидат `192.168.2.1:22` возвращает `identity_state: known_match` и `probe_tuple_match: true`, но группировка кандидатов по адресу в `features/connection-flow.js` отдаёт итог по худшему состоянию, и устаревшие дубли записей на тот же хост превращают совпадение в «не совпадает с сохранённой записью».
- **L-2 — подтверждение отпечатка не переживает перезагрузку страницы.** Живёт только в памяти вкладки; после перезагрузки живые вызовы Wi‑Fi отвечают 422, хотя пин уже сохранён на сервере (`host_key_match: true` в ответе connection-health, резолвер `_resolve_ssh_host_key_pin`). Нужно серверное чтение контекста подключения и восстановление при загрузке, fail-closed без подтверждённого пина.

**Только после них — «Страницы входа»** (`web/hub/screens/entry-pages.js`, макет `7.png`, маршрут `#/entry-pages`), затем «Диагностика».

**Первые шаги продолжения:**

1. Закрыть L-1 и L-2, затем лично проверить оба на живом роутере (поиск показывает совпадение; после полной перезагрузки страницы Wi‑Fi-экран читает состояние без повторной церемонии).
2. Прочитать `.cursor/plans/local-hub-redesign.md` (задачи по «Страницы входа») и `.cursor/plans/local-hub-pkg4-vpn-domain-entry-spec.md` §5 (P4-D5), плюс `.cursor/plans/local-hub-entry-pages-feasibility.md` — экран реализуется как локальные страницы хоста на **отдельном слушателе**, операторский интерфейс и API в гостевую сеть не выставляются (решение M-4).
3. Реализовать экран «Страницы входа» с честным UNSUPPORTED там, где API нет; не имитировать редактор/превью/QR.
4. Экран «Диагностика» при реализации **импортирует** `features/system-check.js` (Р-10).
5. Перед объявлением подпакета завершённым — протокол верификации §8.

**Что должен сделать человек/ведущий оркестратор лично:** визуально сверить экраны «Обзор» (`1.png`)…«Домен» (`6.png`) с макетами; на роутере 192.168.2.1 проверить VPN apply/teardown/observe, keendns status с live raw, host HTTP/TLS пробы; при возможности — установку PWA на iPad.
