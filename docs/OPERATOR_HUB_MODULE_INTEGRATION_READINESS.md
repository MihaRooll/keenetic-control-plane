# Готовность модуля Router Control к интеграции в Hub `module_3.0`

## For agents

| Факт | Значение |
|---|---|
| Когда читать | Перед днём, когда оператор решает переносить `router_control`/`router_control_host` в реальный Hub (`module_3.0`); перед тем как отвечать «модуль готов к интеграции» |
| Не отменяет | `docs/contracts/ROADMAP.md` (M7 — формальная веха), `docs/ARCHITECTURE.md` §9-§12 (нормативные touchpoints), `docs/STATUS.yaml` (approvals, gates) |
| Честная граница этого документа | Это **не** сама интеграция и не замена M7. `module_3.0` физически отсутствует в этом workspace — это код другого (Hub) репозитория. Этот документ — чек-лист готовности прототипа + маппинг «что уже есть → что предстоит подключить», написанный так, чтобы день интеграции не начинался с чтения всей истории проекта |
| Авторизация M7 | `docs/STATUS.yaml` `approvals` явно фиксирует: «Hub module_3.0 integration... remain unauthorized» (запись от 2026-07-22, не отменена). Сама механическая интеграция требует отдельного разрешения оператора **и** доступа к реальному коду Hub — ни то, ни другое не выдавалось на момент записи этого документа |
| Как обновлять | Обновлять при любом изменении touchpoint-таблицы (§2), баланса тестов (§1) или честных пробелов (§3). Валидатор — `scripts/validate-project-docs.ps1` + `py -3.11 scripts/project-docs.py audit`, оба exit 0 |

---

## 0. Короткий ответ, если оператор спросит «модуль готов?»

**Прототип (этот репозиторий) — да, в своих границах: пакет переносимый, домен без FastAPI, тесты зелёные, main-menu функциональность R‑1..R‑9 живьём подтверждена.** Механическая пересадка в `module_3.0` (M7 по `ROADMAP.md`) — нет, и не может быть «да» из этого репозитория: нужен реальный код Hub, которого здесь физически нет, плюс отдельное разрешение оператора на сам M7 (сейчас явно «unauthorized» в `STATUS.yaml`). Работа этой сессии была направлена на то, чтобы день, когда это разрешение придёт, не начинался с расчистки багов и непонятного кода — а с механического переноса по таблице §2.

---

## 1. Базовая готовность прототипа — команды и ожидаемый результат

Прогнать перед днём интеграции, чтобы иметь свежий, а не вчерашний baseline:

| Команда | Что проверяет | Последний известный результат (эта сессия) |
|---|---|---|
| `py -3.11 -m pytest tests/ -q` | Полный набор — единственный раз в конце, не на каждой итерации (философия тестирования проекта) | `4942 passed, 2 skipped, exit 0` (после пакета R-3..R-6, §M-48) |
| `ruff check .` | Линт Python | чисто на затронутых файлах в последних пакетах; полный прогон по всему репо не переделывался в этой сессии — прогнать перед днём интеграции |
| `mypy router_control router_control_host` | Типы | чисто на затронутых файлах; полный прогон рекомендуется перед днём интеграции |
| `node --check` на изменённые `.js` | Синтаксис фронтенда | чисто на затронутых файлах |
| `powershell -File scripts/validate-project-docs.ps1` | Валидатор доков | `DOCS_VALIDATE_PASS` |
| `py -3.11 scripts/project-docs.py audit` | Аудит доков | `PROJECT_DOCS_AUDIT_PASS` |
| `py -3.11 -m pytest tests/test_hub_module_bindings.py -q` | Экран не падает при монтировании (ловит регрессии, которые не видят тесты самого экрана) | зелёный после каждого пакета этой сессии |

**Архитектурный инвариант, стоит перепроверить в день интеграции:** `router_control` (домен/application/persistence/ports/adapters) не импортирует FastAPI. Быстрая проверка: `rg "^import fastapi|^from fastapi" router_control/` — должно быть пусто (весь FastAPI-код живёт в `router_control_host`).

---

## 2. Touchpoint-таблица — что делает M7, и что уже готово в прототипе

Столбцы 1-2 — буквально из `docs/ARCHITECTURE.md` §10 (нормативный источник, не копировать туда правки — правьте там, а не здесь). Столбец 3 — что реально есть в прототипе на 2026-08-06, чтобы день интеграции начинался с переноса, а не с написания с нуля.

| Touchpoint (Hub, `module_3.0`) | Что делает M7 | Готовность в прототипе сегодня |
|---|---|---|
| `app/services/router_control/` | Перенести Python-пакет, сохранив `domain/application/ports/adapters` | Пакет `router_control/` уже переносим: `pyproject.toml` — `dependencies = []` у core, FastAPI/uvicorn — только в extra `host`, `paramiko` — только в extra `hardware`. Разделение слоёв соблюдено |
| `app/api/routes/router_control.py` | Тонкий `APIRouter` с prefix `/api/router-control/v1`, DTO/ошибки конвертируются здесь | В прототипе — 42 route-модуля в `router_control_host/*_routes.py`, все монтируются в `app.py::create_app` через `app.include_router(...)` (строки ~506-534). Это уже ровно тот шаблон — в Hub нужно просто подключить те же роутеры под тот же prefix через `_register_routes`, а не переписывать |
| `app/api/factory.py::_register_routes` | Один вызов `app.include_router(...)` | В прототипе — `create_app()` делает это сам; при переносе — извлечь список `include_router` вызовов как есть |
| `app/core/bootstrap.py::ProcessResources` | Одно поле `router_control` в process-wide resources | В прототипе нет отдельного `ProcessResources` — состояние живёт в `router_control_host/state.py::HostState` и `app.state`. Хорошая новость: это уже state-first паттерн, совпадающий с тем, что Hub ожидает (`get_singleton` через `app.state`) — маппинг механический, не архитектурный |
| `app/core/bootstrap.py::_build_resources` | Собрать через composition root; ошибки — в disabled/degraded facade, не блокировать Hub | `router_control/composition.py` — уже единая точка сборки runtime. **Требует проверки в день интеграции:** сейчас `create_app()` не оборачивает сборку в явный disabled/degraded facade при ошибке зависимости — это тот участок, который Hub-интеграция обязана добавить (не пропустить, ошибка здесь = блокировка Hub startup, что запрещено §12) |
| `app/api/factory.py::_bind_singletons` | Имя `router_control` в binding | Механический шаг переноса, ничего не готовить заранее |
| `app/api/deps.py` | `get_router_control(request)` | Механический шаг — в прототипе dependency injection делается напрямую в каждом route-модуле через `_state(request)`; в Hub — обернуть в `get_router_control` по существующему паттерну `deps.py` |
| `app/core/lifespan.py::app_lifespan` | Запустить/остановить durable worker, feature-local failures не ломают lifespan | В прототипе `app.py::create_app`'s `lifespan()` (~строка 204) уже запускает/останавливает воркер локально для standalone-хоста — перенести логику, но **обернуть** в boundary handling, которого сейчас нет (тот же честный пробел, что в bootstrap выше) |
| `app/settings.py::Settings` | Typed, redacted флаги/пути/таймауты; секреты — `SecretStr`/opaque ref | **Честный пробел:** отдельного `Settings`-объекта в прототипе нет — переменные окружения (`HUB_ADMIN_PASSWORD`, `RC_ADAPTER_MODE`, `RC_STANDALONE_LOOPBACK_AUTH`, `RC_PUBLIC_BASE_URL`, `ROUTER_CONTROL_LAB_CLASS`, `VPN_WATCHDOG_ENABLED`, `VPN_WATCHDOG_POLL_SECONDS`, `ROUTER_CONTROL_DB_PATH`/`ROUTER_CONTROL_TEST_SESSION`) читаются напрямую через `os.environ` в разных модулях. Список выше — полный набор известных на сегодня переменных; типизированный `Settings` для Hub нужно строить с нуля, но именно из этого списка, не угадывать |
| `app/core/middleware.py::AdminGateMiddleware` | Явная проверка prefix `/api/router-control/v1` **до** общего admin gate; пустой пароль → 503 всегда; невалидный cookie → 401 | В прототипе — `router_control_host/auth.py`: пустой `HUB_ADMIN_PASSWORD` → 503 fail-closed уже реализовано и покрыто тестами (`tests/test_host_auth_unsafe_disable.py` и др.). Логику стоит буквально перенести, а не переписывать — она уже прошла через несколько раундов adversarial-review в этом проекте |
| `static/settings.html` / `static/settings.js` | Панель Router Control внутри существующего защищённого `/settings` | В прототипе — отдельный полноценный LOCAL HUB PWA (`router_control_host/web/hub/`, 9+ экранов). **Решение для дня интеграции, не принятое сейчас:** встраивать ли весь LOCAL HUB как есть (iframe/отдельный маршрут) или сокращать до панели внутри существующего Hub `/settings` буквально по тексту touchpoint — это архитектурное решение, которое должен принять Hub-мейнтейнер, не Main |
| `scripts/install_hub.ps1` | Non-secret defaults, data dir/ACL, backup/restore/uninstall включает `data/router_control.sqlite3` | Не готово — прототип использует свой `scripts/run-prototype-host.ps1` (DPAPI-хранилище пароля), это не установочный скрипт Hub. День интеграции: перенести саму идею (DPAPI, не plaintext) в существующий `install_hub.ps1`, не копировать файл как есть |
| `requirements.txt` | Только реально используемые зависимости; FastAPI уже у host | Из `pyproject.toml`: **paramiko** (SSH read/observe/host-key) — новая для Hub, если там её ещё нет; **fastapi/uvicorn** — уже есть в Hub по условию touchpoint. Больше внешних зависимостей у core-пакета нет (`dependencies = []`) |
| `tests/` | Factory wiring, lifespan isolation, middleware fail-closed, settings redaction, settings-page smoke, no-network unit, degraded-start | Прототип покрывает свои эквиваленты (`tests/test_host_auth_unsafe_disable.py`, `tests/test_db_path_isolation.py`, module-binding guard). **Не покрыто и не может быть покрыто из этого репозитория:** тесты на реальном коде Hub (`_build_resources`, `ProcessResources`, лишние вызовы `_register_routes`) — они физически появятся только с доступом к коду Hub |

### Auth-контракт общего listener (§10, «Auth contract общего listener»)

Уже реализовано и живьём проверено в прототипе — переносить логику, не придумывать заново:
1. Пустой `HUB_ADMIN_PASSWORD` → `503`, без вызова handler.
2. Пароль задан, `hub_admin` cookie отсутствует/невалидна → `401` + ссылка на `/login`.
3. Валидная cookie → запрос идёт дальше.
4. Router Control disabled → аутентифицированный вызывающий получает только ограниченный disabled-статус.

Никаких scope/promo-токенов/IP-based bypass — не добавлять при переносе.

---

## 3. Честные пробелы на сегодня (2026-08-06) — не относится к самому M7, относится к качеству прототипа

| Пробел | Состояние |
|---|---|
| R-2 (интернет): автопереподключение Wi-Fi сторожевым сервисом после реального обрыва | НЕ live-proven |
| R-10 (анимации «на ощупь») | Только беглый визуальный скриншот этой сессией (§M-50) — полноценной приёмки нет |
| Captive-portal через VPN-туннель | `captive_accessible: false` остаётся; MSS-клампинг не доказанно чинит именно эту проверку |
| Провайдер `rockblack` (AWG) | Не отвечает — подтверждено provider-side, не баг продукта |
| `guest_reachable` для страниц входа | Остаётся `null` — нужен реальный телефон в гостевой сети |
| Kill-switch / именованная политика маршрутизации | Осознанно не строится (§M-36) — не пробел, решение |
| Gate B/C/D | Закрыты; `WriteCertified` не заявлен; `write_shapes_registered=false` — не пробел, действующее ограничение проекта |
| Git-гигиена | На начало этой сессии — 1184 незакоммиченных файлов, HEAD на старом состоянии. **Решение оператора, не принятое автономно:** коммитить или нет — правило проекта «не коммитить без явной просьбы» соблюдено, изменения лежат в рабочем дереве |
| UX-пакеты дня 2026-08-06 (мастер подключения, VPN-экран, F-4) | Закрыты, см. §4 |

---

## 4. Пакеты, запущенные в день записи этого документа (2026-08-06)

Обновляется по факту завершения — Main лично проверяет Verification Record перед тем, как отмечать «готово» здесь.

| Пакет | Что чинит | Статус |
|---|---|---|
| `connection-wizard-robustness-2026-08-06` | Необработанное исключение paramiko → 500 вместо честного 422 при обучении SSH host-key; тихая потеря пароля при правке адреса; отсутствие подсказки у поля логина; несогласованный статус шага «Доступ» | **Готово, лично проверено Main** (§M-51) — код сверен построчно, 139 целевых тестов зелёные |
| `vpn-screen-ux-and-cleanup-2026-08-06` | Слепой выбор номера туннеля без подсказки на VPN-экране; плотный жаргон в тексте о рисках; уборка мёртвых веток F-4 в `overview-simple-networks.js` | **Готово, лично проверено Main** (§M-51) — код сверен построчно |

**Итоговая проверка обоих пакетов вместе (2026-08-06, §M-51):** полный `pytest tests/ -q` — 4949 passed, 1 failed (внешний, не регрессия — см. §M-51), 2 skipped; `mypy` чисто; `ruff` — 54 ошибки только в тестовых файлах (стиль), не в продуктовом коде; оба валидатора доков — exit 0.

---

## 5. Чек-лист на сам день интеграции (когда `module_3.0` станет доступен)

1. Прочитать `docs/ARCHITECTURE.md` §9-§12 целиком, не только эту таблицу — там же mermaid-диаграмма strangler-переноса.
2. Получить явное разрешение Hub-мейнтейнера (условие входа M7 в `docs/contracts/ROADMAP.md`) и отдельное разрешение оператора на сам M7 (сейчас — «unauthorized» в `STATUS.yaml`).
3. Прогнать §1 этого документа на свежем `HEAD`, зафиксировать новый baseline.
4. Переносить touchpoints из §2 **в порядке таблицы** — она уже топологически упорядочена (пакет → роуты → factory → bootstrap → deps → lifespan → settings → middleware → UI → install script → requirements → tests).
5. На каждом шаге — до cutover не допускать совместного ownership одного router resource легаси и новым кодом (§9 `ARCHITECTURE.md`); легаси переводится в read-only только после parity и rehearsal.
6. Ни один шаг не должен блокировать Hub kiosk/board/printing/startup — это архитектурный acceptance criterion (§12), а не пожелание.
7. Не заявлять `WriteCertified` и не открывать Gates B/C/D как побочный эффект интеграции — это отдельные, самостоятельные разрешения.

**Docs Impact Record:** `docs_paths_touched: [docs/OPERATOR_HUB_MODULE_INTEGRATION_READINESS.md, docs/docs-map.json]`; `validator_run: yes`.
