# Operator UI — prototype management surface

## For agents

**When to read:** operating or extending the buildless SPA at `/settings/router-control`; UI auth/CSP/security reviews; Browser MCP smoke (optional).

**Apply:** UI is prototype-host only (not Hub `module_3.0`). Same `hub_admin` cookie as API; login form is on **standalone** `/login`, not in management shell. **Simple mode (2026-08-01):** default surface `#simple` — human-language wizard; expert one click away — see [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md). **Broad** catalog/preset Apply/live-write controls stay absent or disabled while Gate B is not WriteCertified; **bounded** Wi-Fi/AWG/station test Apply panels on `#config` / `#uplink` remain available with confirm + per-request connection params (see [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md)). **P3 topology safety closure complete** (2026-07-23): default-deny live mutations for Gate B families; `source_address` bind required on live/ssh_tunnel enroll and preflight; **`tunnel_healthy` + first real handshake DEVICE-CONFIRMED** (§M-24..§M-26); **traffic via tunnel reversible** via `ip_global_priority` (§M-27) — kill-switch/named policy still open. **Current `next_task`:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](STATUS.yaml). **LOCAL HUB PWA** (`/settings/router-control/hub`) is the primary operator surface (eight screens + main menu R-9). **Parallel deferred:** VPN named connection policy / kill-switch **live apply** (offline preview only; kill-switch `permit global` **unresolved**). Gate B **completed_failed**; `write_shapes_registered` false.

**Do not:** claim Hub integration, live commissioning writes, WriteCertified/Commissioned status from UI green states, or standing fail-safe `--execute` without fresh exact T4 authorization.

**Autonomous UI verification (offline):** `tests/support/ui_dom_harness.js` executes real `app.js` panel builders under Node with a minimal DOM (`createElement`, `getElementById`, `<details>.open`, input state, `[data-testid=…]` selectors, focus/activeElement). Covers Wi‑Fi / AWG / station apply **simple + advanced** panels, **Дополнительные настройки** expander, payload defaults vs manifest (`fieldTooltipOpts` → control checked/value/select), tooltip a11y (`aria-describedby` on **control**, not trigger), manifest-backed tooltips from `/settings/router-control/assets/ui-field-manifest.json`, honesty notes, result-markup secret echo, apply toast **path-binding via click handlers** (`APPLY_TOAST_PATHS` registry + `build*ApplyActionHarness` + stubbed `apiFetch`), and no false success on unverified apply — see [`contracts/TEST_STRATEGY.md`](contracts/TEST_STRATEGY.md) §8.6, `tests/test_ui_simple_advanced_forms.py`, `tests/test_ui_honesty_defects.py`. **NOT device-verified.**

**LOCAL HUB motion & PWA (2026-08-05):** controlled service-worker update — dismissible toast «Доступно обновление интерфейса» + action «Обновить» (`timeoutMs=0`, single-flight `updateNoticeShown`); reload only after operator action (`reloading` + `HUB_SKIP_WAITING`); first install silently activates without toast/reload. Global top request progress bar in shell (`subscribeInFlight` / `getInFlightCount`, ~280ms show debounce, ~300ms hide settle; opacity fade via `--hub-duration-normal`; reduced-motion = solid bar, no shimmer). Screen enter: `applyScreenEnter` → `hub-screen-enter` CSS tokens; `#hub-content.scrollTop=0` on route change. Long operations: `createProgressPanel({ mode?, label?, elapsedMs?, expectedMs?, progress? })` → element with `.update(opts)`; demo on `#/dev-showcase`. Toast/modal/badge enter transitions; orphan `.hub-overview__tile` reduced-motion rule removed (no tile transition declared). **Overview auto-connect (R-1, 2026-08-05):** on fresh tab `#/overview` waits for server-side connection restore settle, then runs bounded health probe with `createProgressPanel` — zero clicks when router is already host-key confirmed; inline recoverable gaps (username, restore retry, probe retry); first host-key confirm stays human-gated on `#/connection`. **Bump `CACHE_VERSION` in `sw.js` when shipping hub JS changes** (implementer does not edit `sw.js`).

---

## Назначение

Полноценный операторский UI для прототипного FastAPI host покрывает **M1–M3**:

| Раздел | API (reuse only) | Запись |
|--------|------------------|--------|
| Обзор | `GET /status`, recent ops (session) | — |
| Роутеры | `GET/POST /routers`, preflight | offline/fake enroll; live gated |
| **Добавить роутер** | `#add-router` wizard: `POST /lab/wizard-draft-router` → `POST /lab/bootstrap-discovery` → SSH host-key learn/confirm | draft + read-only discovery; Gate A closed OK; **not** Wi‑Fi-ready |
| Комиссионирование | commissioning-runs CRUD, assess, report, **readiness-checks** | read-only assess; **mode** override + optional **async** assess; Apply disabled |
| Пресеты события | event-presets CRUD, validate, plan, **publications**, deployment-revisions, desired-revisions, plans confirm/apply, jobs/backup-artifact | offline catalog; **domain-aligned editor** (2026-08-01): `canonical_document` load, `AdminServer`, uplink enums, firewall `rules[]`, collections; **P2 fake Confirm/Apply UI shipped** incl. **`risk_acknowledged`**, **GET deployment-revision**, **PUT desired-revision**; `write_ready=false` |
| Операции / Jobs | operations, jobs, cancel | safe boundary |
| VPN-каталог | vpn-profiles list/detail/validate; **catalog import** (`POST /import`); parse-preview | metadata only; import = SQLite/vault catalog **not device apply**; parse-preview vault + sanitized refs |
| Настройки | theme, gates, refresh, logout (POST /logout via topbar) | localStorage theme only |

## URL и assets

| Path | Назначение |
|------|------------|
| `/` | Redirect → `/login` (unauthenticated) or `/settings/router-control` (valid cookie) |
| `/login` | Standalone login HTML (form POST `password`; links `/login.css`, `/login.js`) |
| `/login.css` | Public login stylesheet (CSP `style-src 'self'` without `unsafe-inline`) |
| `/login.js` | Public login helper script (no credential storage) |
| `/logout` | **POST only** — same-origin CSRF check, clears `hub_admin` cookie; **GET → 405** |
| `/favicon.ico` | Local packaged SVG favicon |
| `/settings/router-control` | HTML shell (`include_in_schema=false`) |
| `/settings/router-control/` | То же (slash alias) |
| `/settings/router-control/assets/styles.css` | **Единственный** stylesheet (SSOT) |
| `/settings/router-control/assets/app.js` | ES module client |
| `/settings/router-control/assets/ui-field-manifest.json` | Generated field manifest (tooltips/defaults SSOT for manifest-backed families) |

HTML использует **абсолютные** пути `/settings/router-control/assets/...`, чтобы CSS/JS загружались и при URL без завершающего слэша.

Hash routing (`#simple`, `#dashboard`, `#routers`, `#add-router`, `#uplink`, …) — deep links без дополнительных server routes.

**Simple mode:** `#simple` — step wizard (connect → link → VPN → guest Wi‑Fi → domain); `renderSimpleMode` awaits `loadFieldManifest()`; link step uses `POST /lab/connection-health` (manifest `connection_health` defaults/tooltips in Advanced); connect autodetect uses `POST /lab/router-discovery` (manifest `router_discovery` toggles in Advanced; `probe` default false); green link requires all five facts + status green; mode persisted in `localStorage` key `rc.prototype.uiMode`. Details: [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md).

## Uplink field view (`#uplink`)

Technician-facing portable rack deployment (offline/fake developable):

| Step | API | Notes |
|------|-----|-------|
| Scan venue Wi‑Fi | `POST /wifi/site-survey` | `buildSiteSurveyFormSurface` — **simple:** radio/both; **Advanced:** live ×5 + `allow_insecure_http`; toast `formatSiteSurveyResultToast` (read-only, not join) |
| Enroll venue PSK | `PUT /routers/{id}/credentials` | one-shot `secret` → vault; UI shows `credential_ref_id` only; omitName + preventDefault |
| Preview station join | `POST /wifi/station/preview` | Sealed ops compile only; `grammar_verification_status=device_accepted_grammar`; `planned_uplink_verification_level=planned_uplink_verified_bounded` (compile-time plan label — limits); **UI:** preview + **Apply/Teardown** (`POST /wifi/station/apply`, `/wifi/station/teardown`) with confirm, planned-ops summary, honest `uplink_verification_status` toasts — **device-verified live 2026-08-05** (§M-34: 7/7 ops, internet via station). **Simple apply panel:** read-only intent summary (SSID/band/credential_ref from scan+enroll) + confirm. **Дополнительные настройки:** `mode`, `priority`, `auth_mode` (`open` disabled/unsupported honesty), `bssid` override, `uplink_settle_seconds`, `router_id`, `compensate_on_failure`, `idempotent`, live ×5 — full `WifiStationApplyBody` coverage. |
| Open network | — | UI scan shows **open**; planner message: `not yet supported: no verified open-network authentication grammar` — join not supported |
| Own SSID AP | `POST /wifi/preview`, `/wifi/apply` | Reuses bounded test AP path; `confirm_live_apply` required |
| Uplink status (step 5) | Apply/Teardown response `uplink_readback` + `POST /wifi/observed-state` (AP rebroadcast) | **Venue station table:** filled from last Apply/Teardown `uplink_readback` with per-field verdict role (✓ засчитан / ✗ отвергнут / ℹ наблюдение) from `verdict_explanation`; upstream SSID/secrets **never** in DOM; before apply → honest «данные отсутствуют». **AP rebroadcast sub-table:** Refresh → observed-state; on-air = `link_up` only; never `device_connected` as on-air |

Join upstream Wi‑Fi client: grammar **device-accepted**; first association **uplink_verified_bounded** (one 5 GHz WPA2 network — open/captive/standby/failover unverified); preset planner remains `wifi_wan_not_certified`; HTTP `POST /wifi/station/apply` + `/wifi/station/teardown` **device-verified live 2026-08-05** (§M-34: full apply to real upstream, internet confirmed); **UI wired** with uplink-break warning, settle hint (20–30s), and honest toasts (`uplink_dispatched_unverified` ≠ success; early read may miss `global: true` — §M-35).

## LOCAL HUB «Интернет» (`#/internet-uplink`)

Экран в PWA LOCAL HUB (`router_control_host/web/hub/`) — подключение **роутера как клиента** к внешней Wi‑Fi сети. Не путать с «Рабочая сеть» / «Гостевой Wi‑Fi» (точки доступа, которые роутер раздаёт).

| Шаг | API | Честность |
|------|-----|-----------|
| Скан сетей | `POST /wifi/site-survey` (WifiMaster0 + WifiMaster1) | Read-only; live ×5 + `router_id`; выбор SSID или ручной ввод |
| Пароль | `PUT /routers/{id}/credentials` kind **WifiApPsk** | Одноразовый secret → vault; `credential_ref_id` только на сервере |
| Preview | `POST /wifi/station/preview` | `mode=WifiWan`; `planned_uplink_verification_level` — compile-time, **не** runtime success |
| Apply | `POST /wifi/station/apply` | `confirm_live_apply: true`; `uplink_settle_seconds` 20–30s; risk modal (связь планшет↔роутер может оборваться) |
| Teardown | `POST /wifi/station/teardown` | `confirm_live_teardown: true`; честный verdict по `overall` |
| Success (apply) | — | **Только** `overall=applied` **и** `uplink_verification_status=uplink_verified_bounded`; `uplink_dispatched_unverified` / `uplink_associated_no_global` / HTTP 200 ≠ success |
| OPEN сеть | — | Блок в UI (backend 422) |

Модель: `uplink-wifi-model.js` (`parseUplinkApplyVerdict` — **не** AP `on_air_verified`). Расположение в меню: после «Подключение», перед «Рабочая сеть».

**Internet source block (R-2, 2026-08-05):** reusable `features/internet-source-block.js` — `mountInternetSourceAffordance(container, options)` → `{ root, update, destroy }`. **Current** source plain Russian from `POST /internet-status/observe` only; until read → «источник неизвестен». **Remembered** uplink — separate muted line (`describeRememberedUplink`), never labeled as live gateway. Wired = read-only when `gateway_interface` is ethernet-like; modem = honesty note only (no control). Wi‑Fi action button rendered **only** if `onOpenWifiSetup` provided.

| Surface | API / storage | Honesty |
|---------|---------------|---------|
| Remembered uplink | `GET`/`PUT`/`DELETE /remembered-uplink`; SQLite singleton `remembered_uplink` (migration 15) | **No password column** — only `credential_ref_id`; secret-shaped JSON keys → 422 without echo |
| Uplink watchdog | `UPLINK_WATCHDOG_ENABLED` (default off); `UPLINK_WATCHDOG_POLL_SECONDS` (default 45, floor 5) | Reapply via existing `POST /wifi/station/apply` path when station gateway **absent/mismatch** — skip when gateway matches remembered station even if `internet==false`; suppress 2× poll after manual PUT/DELETE/apply; **station write allowlist gap CLOSED** (§M-32..§M-34); **auto-reconnect after drop NOT live-proven** (reapply when gateway absent ≠ proven reconnect-to-handshake) |
| `#/internet-uplink` screen | mounts affordance + existing scan/apply flows | mount-once / per-slot signature updates; scroll/focus preserve; honest 20–30s settle progress |

**Composition API inputs (`mountInternetSourceAffordance`):** `getObservation`, `getRemembered`, optional `busy`, optional `onOpenWifiSetup` (omit → no Wi‑Fi button), optional `idPrefix`.

**Ship note for Main (required before client release):**

1. Add `` `${HUB_PREFIX}features/internet-source-block.js` `` to `SHELL_URLS` in `sw.js` (adjacent to `uplink-wifi-model.js`).
2. Bump hub `CACHE_VERSION` in `sw.js`.

Overview main-screen `#/overview` uses `overview-internet-simple.js` (not `mountInternetSourceAffordance`) — live source label, remembered line «Сохранено на хосте», honesty when auto-watchdog off or unproven; quiet link `#/internet-uplink`.

## LOCAL HUB «VPN» (`#/vpn`)

Экран в PWA LOCAL HUB — каталог профилей VPN и управление туннелем WireGuard/AmneziaWG на роутере.

| Поверхность | Поведение | Честность |
|-------------|-----------|-----------|
| Каталог | `GET /vpn-profiles`; **live tile status** `POST /vpn-profiles/catalog-status` (один probe активного профиля + один `show internet status` для routing evidence); сетка `createVpnProfileStatusTileGrid` — `describeVpnProfileTileStatus` (stored TVS игнорируется); повторная загрузка **не** очищает список — skeleton только при первой загрузке; при refetch — «Обновляем каталог профилей» над сеткой; после списка — один `catalog-status` + фоновый `GET /vpn-profiles/{id}` для keepalive и `operator_notes` | Импорт в каталог ≠ подключение; зелёный «Работает» только при live `tunnel_healthy` **и** `routed_through_tunnel === true` (default-route interface совпадает с `assigned_wg_id`); иначе amber «Отвечает, не весь трафик»; inactive = «Не подключён»; keepalive («Автоподдержка соединения») ≠ работа туннеля; при ошибке detail — без утверждения «не указана» |
| Parse / import preview | `POST /vpn-profiles/parse-preview` | `operator_notes` и `unsupported_fields` — спокойные информационные строки; пустые поля не добавляют шума |
| Validate | `POST /vpn-profiles/{id}/validate` | Короткий прогресс (~до 15 с); busy-кнопка; без settle-секунд handshake |
| Remove from catalog | `POST /vpn-profiles/{id}/remove` (`confirm_catalog_remove: true`) | Soft-retire (`superseded_at`); **не** teardown на роутере; активный профиль → 409; `openModal` + честный lead; exclusive secret refs revoke; shared/non-VPN live links не revoke |
| Activate / deactivate | `POST .../activate`, `POST .../deactivate` | `mutating` + прогресс до ~70 с; busy-кнопки; мягкий refetch каталога |
| Connect / reconnect | preview → apply (`/wireguard/preview`, `/wireguard/apply`) | `HubState.CONNECTING` **только** здесь; фазы `reconnect_teardown` → `preview` → `apply`; во время apply — `VPN_HANDSHAKE_WAIT_MESSAGE` |
| Disconnect / teardown | `/wireguard/teardown` | Прогресс teardown; risk modal; без CONNECTING |
| Observe / recheck | `/wireguard/observe` | Read-only; inline LOADING **над** строками статуса; строки **остаются**; **не** CONNECTING / handshake |
| Статус (3 строки) | configuration / tunnel / traffic | `tunnel_healthy` ≠ SUCCESS; traffic UNSUPPORTED; без декоративных «активен/подключено» |

Per-slot обновления (status / active-config / catalog / header / footer): смена интерфейса туннеля не перерисовывает каталог. Scroll сохраняется через `#hub-content` (`.hub-shell__content`); focus — через `pendingFocus` (id кнопки действия + захват `activeElement.id` в `rebuildSlot` перед пересборкой слота). Footer пропускает полный rebuild при неизменной подписи и синхронизирует busy in-place.

Модель: `vpn-model.js` (`createVpnProfileStatusTileGrid`, `describeVpnProfileTileStatus`, `fetchVpnCatalogLiveStatus`, `removeVpnProfileFromCatalog`). Экран: `screens/vpn.js`. Backend: `vpn_catalog_status_routes.py` (read probe), `vpn_catalog_remove_routes.py` (catalog remove).

## LOCAL HUB «Домен» (`#/domain`)

Экран в PWA LOCAL HUB — черновик ссылки для приложения заказов и публикация имени. Human Gate KeenDNS — **APPROVED standing 2026-08-08** на expendable lab ([`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md)); агенты не переспрашивают. Offline apply shipped: `POST /keendns/apply`, CTA «Опубликовать», `onPublishApply` → confirm → `applyKeendnsBooking`; live cloud registration **не** device-proven; **not** WriteCertified. Шаблон `promo.netcraze.pro` / `mode=auto`.

| Поверхность | Модуль | Поведение | Честность |
|-------------|--------|-----------|-----------|
| Простой сценарий (R-8, на экране) | `features/domain-simple-publish.js` | `mountDomainSimplePublishAffordance(container, options)` → `{ root, update, destroy, getDraftUrl, isNameValid }` | Стартовое имя `promo` + «Подставить стартовое имя» — **пример**, не host-persisted; primary CTA **«Опубликовать»** → confirm → `onPublishApply` / `applyKeendnsBooking` (`POST /keendns/apply`); post-apply honesty — dispatch ≠ cloud registration |
| Human gate (shared) | `openDomainPublishHumanGate(params)` | SSOT `DOMAIN_PUBLISH_HUMAN_GATE_TEXT` + lead `DOMAIN_SIMPLE_GATE_WHY`; copy toast «Заявка скопирована» ≠ published | `buildPublishRequestSummary` / `buildReleaseRequestSummary`; actions: Закрыть + Скопировать заявку; **не** единственный publish path — apply confirm отдельно |
| Экран | `screens/domain.js` | mount-once / signature gating; typing → `affordance.update()` + `updateDraftDependentUi`, **не** `renderAll` на keystroke | Расширенные поля сохранены; footer «Оформить заявку на публикацию» + simple CTA «Опубликовать» с apply confirm |
| Модель | `domain-model.js` | `describeDomainSimpleNameState`, `resolveDomainSimpleDefaultName`, `applyKeendnsBooking`; keendns status/preview read-only | `keendns/status`, `keendns/preview` RO; **`POST /keendns/apply`** offline shipped — live booking **not** device-proven; **not** WriteCertified |

**Composition API inputs (`mountDomainSimplePublishAffordance`):** `getName`/`setName`, `getDomain`/`setDomain`, `disabled`, `onPreparePublish` (shared human-gate prepare), `onPublishApply` (confirm → `applyKeendnsBooking`), optional `showSuffixSelect`, `idPrefix`.

**Composition API inputs (`openDomainPublishHumanGate`):** `openModal`, `createButton`, `copyTextToClipboard`, `showToast`, `intent` (`book`|`drop`), `name`, `domain`, `mode`, `localOrderUrl`, optional `onClose`.

Overview main-screen wiring (R-9) on `#/overview` — `mountDomainSimplePublishAffordance` + shared human gate; advanced domain fields remain on `#/domain`.

**Ship note for Main (required before client release):**

1. Add `` `${HUB_PREFIX}features/domain-simple-publish.js` `` to `SHELL_URLS` in `sw.js` (adjacent to `domain-model.js`).
2. Bump hub `CACHE_VERSION` in `sw.js`.

## LOCAL HUB standing network preferences (R-3..R-6 foundation, 2026-08-05)

Host-persisted defaults for staff/guest Wi‑Fi screens — **not** tab/session memory. Overview main-screen networks slot (`overview-simple-networks.js`) wired on `#/overview`.

| Surface | API / storage | Honesty & boundaries |
|---------|---------------|----------------------|
| Preferences | `GET`/`PUT /standing-network-preferences`; SQLite singleton `standing_network_preferences` (migration 14) | **No password column** — only `staff_password_credential_ref_id`; `staff_password_configured` iff usable `WifiApPsk` ref (`revoked_at IS NULL`); invalid/revoked refs self-heal to `null` on read; `guest_default_enabled` always **false** in GET (PUT `true` → 422); secret-shaped JSON keys → 422 **without echo** |
| Credential ownership | ref created via existing `PUT routers/{id}/credentials` | Standing ref may outlive owning router — FK `ON DELETE SET NULL`; cross-router reuse intentional for host defaults |
| `#/staff-wifi` | `staff-wifi-model.js` + screen | Standing SSID prefill **only** when `!observed.readable`; readable-but-unknown SSID → empty + note; staff-only standing password reuse; ask-once when unconfigured; after successful save/enable → PUT prefs; disabled-network remediation banner; «Применить обычные настройки» → existing risk modal (**never** auto-apply on mount) |
| `#/guest-wifi` | `guest-wifi-model.js` + screen | Guest SSID default only; **never** staff standing password; fresh setup off-by-default (ignores any stored enabled flag); «Запомнить как обычное» updates `guest_default_ssid` only |

Shared HTTP helpers live in `wifi-ap-model.js` (`fetchStandingNetworkPreferences`, `updateStandingNetworkPreferences`) — **not** wired into shared apply/credential paths.

**Ship note for Main:** bump hub `CACHE_VERSION` when releasing this package to clients.

## Router config (`#config`) — honesty panels (2026-08-01)

| Panel | API | Honesty |
|-------|-----|---------|
| Wi‑Fi AP apply/teardown | `/wifi/preview`, `/wifi/apply`, `/wifi/teardown` | Toast via `toastApplyFamilyResult` + `wifiApplyToastPrefix` / `formatWifiApplyToast`; **#uplink Own SSID** reuses `buildUplinkApApplyToast` (same prefix matrix). Terminal `overall` failure first (`FAILED`, `VERIFY MISMATCH`, …); only `on_air_verified` + `overall=applied` reads as success; **missing/unknown `overall` → `Apply unknown (overall …)` / `unknown (no result)` — never pairs `NOT verified` with positive on-air secondary**; secondary detail in `wifiApplyHonestySummary` (positive on-air only when `overall=applied`); collapsible **`verdict_explanation`** |
| AWG apply/teardown | `/wireguard/preview`, `/wireguard/apply`, `/wireguard/teardown` | Toast via `toastApplyFamilyResult` + `awgApplyToastPrefix` / `formatAwgApplyToast`; terminal `overall` before `tunnel_verification_status`; only `tunnel_healthy` + `overall=applied` reads as success; `awgApplyHonestySummary`; collapsible **`verdict_explanation`** |
| Station apply/teardown (`#uplink`) | `/wifi/station/apply`, `/wifi/station/teardown` | Toast via `toastApplyFamilyResult` + `stationApplyToastPrefix` / `formatStationApplyToast`; terminal `overall` before runtime `uplink_verification_status`; only `uplink_verified_bounded` + `overall=applied` reads as success; `stationApplyHonestySummary`; collapsible **`verdict_explanation`**; step 5 readback table from `uplink_readback` |
| Wi‑Fi observed | `/wifi/observed-state` | `buildWifiObservedFormSurface` — **simple:** AP + compare; **Advanced:** live ×5 + `allow_insecure_http`; toast via `formatWifiObservedSessionToast` (null → unknown, not bare refresh) |
| TrafficDiscovery | `/traffic/observations`, `/traffic/proposals` | `buildTrafficDiscoveryFormSurface` — human `evidence.dst/proto`, `route_intent.prefix`; JSON fallback in Advanced; proposals-only honesty toasts |
| VPN policy-routing preview | `POST /vpn/policy-routing/preview` | **Preview only** — `help_verified_grammar_unapplied`, ops + citation notes + `unknowns`; **no apply** |
| VLAN preview | `POST /vlan/preview` | **Preview only** — `offline_unverified`; simple bridge/zone/vlan/cidr + advanced gateway; **no apply route** |
| DHCP preview | `POST /dhcp/preview` | **Preview only** — `offline_unverified`; simple pool + advanced lease/reservations rows; **no apply** |
| DNS preview | `POST /dns/preview` | **Preview only** — `offline_unverified`; simple fqdn + advanced upstream resolver rows; **no apply** |
| Firewall preview | `POST /firewall/preview` | **Preview only** — `offline_unverified`; simple zone + advanced rules rows; **no apply** |

## Add-router wizard (`#add-router`)

Offline-verified only. Четыре шага: **данные доступа → обнаружение → ключ хоста → итог**.

| Шаг | API | Примечания |
|-----|-----|------------|
| 1 Draft | `POST /lab/wizard-draft-router` | **simple:** host, username, secret, display_name; **Advanced:** port, `allow_insecure_http` (**default false**, unchecked), `source_address` (passed to learn when set); `secret` one-shot → vault; `Idempotency-Key`; Gate A closed OK |
| 2 Discover | `POST /lab/bootstrap-discovery` | `credential_ref_id`; plain-language findings; compact **component count** + **SSH-present fact** in step summary; side-effects rebuild≠version |
| 3 Host key | `POST .../ssh-host-key/learn` + `.../confirm` | Echo exact fingerprint+algorithm; **`allow_overwrite` operator-controllable (Advanced, default false)**; optional `source_address` on learn; pin_conflict warning |
| 4 Handoff | — | `certification_eligible: false`; **not** ready for Wi‑Fi management |

Пароль: `omitName`, cleared after submit, never localStorage/URL/query. UI assets must not contain `management_password` lexicon.

## Аутентификация

- Расширение существующего `auth_gate` (`hub_admin` cookie) на prefix UI **и** API (API order unchanged).
- Без cookie → **401** `auth.required`.
- Пустой `HUB_ADMIN_PASSWORD` → **503** `security.configuration_blocked`.
- **Unsafe dev bypass (prototype only):** `RC_UNSAFE_DISABLE_AUTH=1` отключает cookie/password gate **только** при одновременном `RC_STANDALONE_LOOPBACK_AUTH=1` + `RC_ADAPTER_MODE=fake` (loopback fake host). **Никогда** для Hub, live adapter или без standalone profile. При arm — громкое предупреждение в stderr/log: `AUTH DISABLED — DEV ONLY, LOOPBACK+FAKE ONLY`. Env-only; не хранится в SQLite/config.
- **Standalone bootstrap:** `GET /login` + `POST /login` (`application/x-www-form-urlencoded`, поле `password`); **`POST /logout`** очищает cookie (same-origin required); **`GET /logout` → 405**. Форма логина **не** в management shell (`/settings/router-control`).
- Cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` = session TTL (default **8h**); `Secure` только при HTTPS (loopback HTTP prototype — `Secure=False`).
- Token: `hub_admin:v2|<iat>|<exp>.<hmac>` — tamper-evident; смена `HUB_ADMIN_PASSWORD` или `HUB_ADMIN_SESSION_SECRET` инвалидирует сессии; при password-derived signing — смена пароля (и типично restart с новым паролем); при заданном `HUB_ADMIN_SESSION_SECRET` — restart процесса **не** инвалидирует сессии до истечения TTL или смены secret; multi-worker требует общий secret/password.
- Signing: prefer non-empty `HUB_ADMIN_SESSION_SECRET` (domain `rc-proto-session:v1|`); иначе derive key из password через HMAC-SHA256 (см. ADR-0003 prototype note).
- Пароль: outer whitespace stripped на env и submit (`hmac.compare_digest`); **internal spaces preserved** — leading/trailing пробелы не часть пароля.
- Same-origin: when `Origin` is present, exact match to configured expected origin (standalone profile) or `scheme://host:port` (default); no `localhost` ↔ `127.0.0.1` alias when standalone profile pins authority; else non-empty `Referer` origin match; else on **loopback host only** accept `POST` with Fetch Metadata `Sec-Fetch-Site: same-origin`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`; **Cursor Browser exception:** exact case-sensitive singleton `Origin: null` on `POST /login` or `POST /logout` when standalone profile ON + validated Host/ASGI loopback authority + Referer absent/empty + exact Fetch Metadata trio.
- **Standalone loopback profile (recommended for local operator):** `RC_STANDALONE_LOOPBACK_AUTH=1` + `RC_PUBLIC_BASE_URL=http://127.0.0.1:8787` (HTTP loopback with explicit port; no userinfo/path/query/fragment). Host middleware pins exact `host:port`, rejects aliases/trailing-dot/X-Forwarded-*; ASGI bind must be loopback. Default profile **OFF** — TestClient `http://testserver` unchanged; null-Origin path disabled.
- **Rate limit:** in-process sliding window **10 failed credential attempts / 60 seconds** on `/login` only; identical generic 401 HTML; successful login resets; origin/authority rejects skip password verification (no oracle); logout not throttled.

- Management shell **не** хранит пароль; `localStorage` — только theme key.
- **Logout:** кнопка «Выйти» в topbar — `<form method="post" action="/logout">` (same-origin POST; redirect → `/login`). GET `/logout` → 405.

Подробности auth order: [`SECURITY_OPS.md`](contracts/SECURITY_OPS.md). Closeout handoff: [`SESSION_HANDOFF_UI_AUTH_2026-07-22.md`](SESSION_HANDOFF_UI_AUTH_2026-07-22.md).

## Безопасность UI

- **CSP:** `default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; … frame-ancestors 'none'` — без `unsafe-inline`.
- **Headers:** `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`.
- **Rendering:** `textContent` + `createElement` only; запрет `innerHTML`, `element.style`, inline `<style>`.
- **Fetch:** `credentials: 'same-origin'`, `AbortController` timeout, `Idempotency-Key` / `If-Match` на мутациях.
- **Secrets:** VPN profile body, keys, PSK, endpoint, credential values **не** рендерятся после submit. Enroll credential refs через `#config` panel: PUT с one-shot значением → vault/DPAPI; UI показывает только `credential_ref_id` и metadata (без `management_password` в браузере).

## Motion scale (LOCAL HUB)

Shared motion tokens in `router_control_host/web/hub/styles/tokens.css`:

| Token | Value | Typical use |
|-------|-------|-------------|
| `--hub-duration-instant` | `0ms` | Immediate state flips |
| `--hub-duration-fast` | `180ms` | Micro feedback (nav hover, badges) |
| `--hub-duration-normal` | `280ms` | Primary settle (screen enter, toast/modal, progress-bar opacity) |
| `--hub-duration-slow` | `480ms` | Indeterminate progress shimmer |
| `--hub-ease-standard` | `cubic-bezier(0.25, 0.1, 0.25, 1)` | Default easing |
| `--hub-ease-emphasis` | `cubic-bezier(0.22, 1, 0.36, 1)` | Soft ease-out (screen enter) |

**Progress bar policy:** show debounce **280ms** (`shell.js`); hide settle **300ms** (≥ opacity fade via `--hub-duration-normal` **280ms**) after removing `--visible`. Content stays interactive — no `setTimeout` gating of render/data.

**Tuning:** change tokens first; avoid per-rule ms literals unless justified (progress debounce/settle only). **`prefers-reduced-motion`:** token block zeroes all `--hub-duration-*` to `0ms`; `base.css` kill-switch forces `transition-duration: 0.01ms !important`.

## Тема

- Режимы: **system**, **light**, **dark**.
- Persistence: `localStorage` key `rc.prototype.theme` only.
- `html[data-theme]` + CSS variables; system via `@media (prefers-color-scheme)`.
- `prefers-reduced-motion` respected (see **Motion scale** above).

## Gates и индикаторы

- Dashboard **не** показывает глобальный «всё OK» green когда `feature_state` Degraded/SecurityBlocked или write gates закрыты.
- Gate B **not WriteCertified** → **broad** catalog/preset Apply/live-write отсутствуют или `disabled` с явной причиной; **bounded** Wi-Fi/AWG/station test Apply на `#config` / `#uplink` доступны с confirm + per-request connection params (banner: «Каталог/preset Apply заблокирован…»).
- Gate A labels (RO) в commissioning; never **Commissioned** / **WriteCertified**.

## Запуск (offline lab)

> **Важно:** строка `<your-operator-password>` в примерах — **placeholder**, не literal password. Рекомендуемый путь — DPAPI launcher (plaintext только в process env на время uvicorn):

```powershell
# Первичная настройка (double hidden prompt):
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-prototype-host.ps1 -Action init

# Запуск host на 127.0.0.1:8787 с standalone profile:
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-prototype-host.ps1
```

Ciphertext хранится только в `%LOCALAPPDATA%\RouterControlDev\hub-admin.dpapi`. Скрипт устанавливает `RC_STANDALONE_LOOPBACK_AUTH=1`, `RC_PUBLIC_BASE_URL=http://127.0.0.1:8787`, bind `127.0.0.1:8787`. Действия: `start` (default), `init`, `rotate`, `clear` (явное удаление blob).

Ручной запуск (без DPAPI):

```powershell
$env:HUB_ADMIN_PASSWORD = "<your-operator-password>"
$env:RC_STANDALONE_LOOPBACK_AUTH = "1"
$env:RC_PUBLIC_BASE_URL = "http://127.0.0.1:8787"
uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787
```

**Local fake testing без login (не для Hub/live):**

```powershell
$env:RC_UNSAFE_DISABLE_AUTH = "1"
$env:RC_STANDALONE_LOOPBACK_AUTH = "1"
$env:RC_PUBLIC_BASE_URL = "http://127.0.0.1:8787"
$env:RC_ADAPTER_MODE = "fake"
# HUB_ADMIN_PASSWORD может быть пустым при активном bypass
uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787
```

> `RC_UNSAFE_DISABLE_AUTH=1` без standalone profile или с `RC_ADAPTER_MODE=live` **игнорируется** — auth остаётся обязательным.

> При standalone profile **Host и Origin должны совпадать** с `RC_PUBLIC_BASE_URL` (обычно `http://127.0.0.1:8787`). Cursor Browser может отправлять `Origin: null` — принимается только под standalone profile + exact authority gates (см. выше).

| URL (browser, без cookie) | Ожидаемый результат |
|---|---|
| `http://127.0.0.1:8787/` | **302** → `/login` |
| `http://127.0.0.1:8787/login` | **200** — форма входа |
| `http://127.0.0.1:8787/favicon.ico` | **200** — local SVG |
| `http://127.0.0.1:8787/settings/router-control` | **401** `auth.required` — нужен cookie `hub_admin` |

После успешного входа: `http://127.0.0.1:8787/settings/router-control` или `/` (redirect при valid cookie).

Default `site_id`: поле `default_site_id` в `GET /api/router-control/v1/status` (требует authenticated cookie).

## Тесты

- `tests/test_ui_host.py` — auth, routing, schema exclusion
- `tests/test_ui_assets.py` — packaging, one stylesheet, JS purity
- `tests/test_ui_security.py` — CSP, traversal, vocabulary
- `tests/test_ui_api_contract.py` — API path refs, synthetic smoke
- `tests/test_config_ui.py` — `#config` router settings view + `#add-router` wizard strings; Wi‑Fi AP on-air honesty, VPN policy preview panel, **VLAN/DHCP/DNS/firewall network-family preview panels** (node harness: offline_unverified warning + apply_ops order; **no apply/teardown buttons** — preview-only HTTP), uplink station apply/teardown, **uplink readback status table structural contract** (`renderUplinkStationReadbackInto`, `classifyUplinkSignalEvidence`, `data.uplink_readback` wiring); **DOM runtime** (`tests/support/ui_dom_harness.js` + Node): Wi‑Fi Apply panel render, `<details>` **Дополнительные настройки** closed/open, payload defaults vs `WifiApplyBody`, credential enroll result must not echo form secret, no misleading success text on unverified apply
- `tests/test_network_family_security_scaffold.py` — cross-cutting PreState/compensation/uncovered-op invariants; OpenAPI absence of network-family apply routes
- `tests/test_ui_remaining_surfaces.py` — **primary DOM honesty** for VPN import, sealed RCI, add-router wizard, **site survey**, **observed-state**, **TrafficDiscovery**, **commissioning create** (manifest fetch path, learn/confirm POST body helpers, visible copy)
- `tests/test_ui_honesty_defects.py` — Wi-Fi apply toast **three-state** honesty (unknown overall / null data) via DOM harness
- `tests/test_wizard_draft_api.py` — draft endpoint auth/forbid/Gate A closed/no leak
- `tests/test_host_auth.py` — password verify, v2 token, auth_gate order, classify helpers
- `tests/test_host_auth_unsafe_disable.py` — RC_UNSAFE_DISABLE_AUTH bypass AC proofs (fake+standalone only)
- `tests/test_session_routes.py` — browser-realistic login (127.0.0.1/localhost), logout CSRF, root, favicon, cookie Max-Age

## Non-goals (this milestone)

- Hub `module_3.0` mount under `/settings`
- Hardware writes / Apply on live router
- OAuth / account system
- npm/CDN/framework build chain

**Next product slice:** **M4 recovery substrate** — [`ROADMAP.md`](contracts/ROADMAP.md) (RecoveryRequired/compensation offline).
