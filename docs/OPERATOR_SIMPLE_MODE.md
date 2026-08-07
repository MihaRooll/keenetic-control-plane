# Operator simple mode — human-language wizard



## For agents



**When to read:** implementing or verifying `#simple` wizard, link-state tri-state honesty, mode switcher (`simple`|`expert`), or DOM-harness tests in `tests/test_ui_simple_mode.py`.



**Apply:** Simple mode is the **default** UI surface (`UI_MODE_KEY = rc.prototype.uiMode`, default `simple`). Expert nav remains one click away (topbar switcher + `#config` link in simple sidebar). Offline-only; backend routes for discovery/health exist — UI wires via `apiFetch` with manifest-backed defaults/tooltips (`router_discovery`, `connection_health`, `wifi_station` families).



**Do not:** paint link `unknown` as success-green; grant green from `health_status: green` alone or from fewer than five facts; add publish-domain / VPN traffic-routing / kill-switch success actions; present `guest_isolation` / captive portal as available; invent green from Gate A metadata alone; claim device-verified uplink from grammar-only preview or HTTP apply alone.



**Cross-links:** [`OPERATOR_UI.md`](OPERATOR_UI.md), [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md), [`OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md`](OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md), [`OPERATOR_ROUTER_DISCOVERY_CONNECTION_HEALTH.md`](OPERATOR_ROUTER_DISCOVERY_CONNECTION_HEALTH.md).



---



## Decision table (normative)



| Step | Show | Hide / degrade | Action | Why |

|------|------|----------------|--------|-----|

| 1. Подключение | **Default visible:** адрес, имя пользователя, пароль (`Пароль` label — no vault jargon in body). **Enrolled auto-connect UX** (reuse `fetchSimpleLinkFacts` on `#simple` open — no second health POST) | **Under `<details>`:** display_name, port, allow-insecure-http, source address, discovery toggles, автообнаружение (secondary — not btn-row peer of submit). Vault/one-shot details in tooltips only | **No enrolled:** form expanded. **Enrolled + honest green:** compact summary collapsed; `Изменить настройки` expands form. **Enrolled + non-green/unknown/transport:** auto-fail + form open — never «Подключено» from weak signals | Human-first connect; bounded discovery |

| 2. Связь | Tri-state badge (`is-ok` / `is-fail` / `is-unknown`) + optional reason line on fail | Never green on HTTP 200 alone or `health_status: green` without all five facts | Refresh → `POST /lab/connection-health` (probe default from manifest) | Green needs **all five** health facts true **and** `health_status === "green"` |

| 3. Интернет (Wi‑Fi uplink) | **Primary:** «Найти сети» → site-survey list (SSID, signal RU, security RU) → select → password enroll → preview/apply. **Secondary:** `<details>` «Сеть не в списке? Ввести вручную» (SSID, band, credential_ref). Honesty paragraph preserved | Not operator login; not guest AP (`wifi_ap` ≠ `wifi_station`). Scan empty vs failed vs incomplete connection — distinct diagnostics (`simple-uplink-scan-status`). Open networks: join unsupported warning | `POST /wifi/site-survey`; `PUT /routers/{id}/credentials` (WifiWanPsk); `POST /wifi/station/preview`; `POST /wifi/station/apply` with confirm | Phone-like picker; grammar preview ≠ device-verified uplink |

| 4. VPN | Catalog import (`buildVpnImportFormSurface`) + traffic honesty copy | No «маршрут трафика» / kill-switch button | Import to catalog only | **`SET_IP_ADDRESS` + traffic via tunnel DEVICE-VERIFIED** (§M-24..§M-27); kill-switch rejected; captive via tunnel NOT proven (MSS≠captive); no route/kill-switch UI |

| 5. Гостевая Wi‑Fi | SSID + `credential_ref_id`; manifest tooltips | No guest_isolation / captive as available | `POST /wifi/apply` with `guest_isolation=false` + confirm | API 422 on isolation |

| 6. Публикация домена | Status + preview + apply (offline) | `КОД ГОТОВ` offline; live cloud registration **not** device-proven | `POST /keendns/status`, `POST /keendns/preview`, `POST /keendns/apply` | Cloud booking Human Gate **APPROVED standing 2026-08-08** expendable ([`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md)) — do not re-ask |

| 7+. Сети | Expandable preview-only note + link to `#config` (switches to expert) | No apply | — | Preview routes only |



---



## Link-state model



Pure helper: `deriveSimpleLinkState(facts)` in `router_control_host/web/app.js`.



| Visual | CSS | Label | Requires |

|--------|-----|-------|----------|

| `ok` | `link-state is-ok` | Связь есть | All five facts explicitly `true` **and** `health_status === "green"` (missing/null status → **unknown**, not ok) |

| `fail` | `link-state is-fail` | Связи нет (+ optional `simple-link-reason`) | `explicit_unreachable`, `identity_mismatch`, `host_key_mismatch`, `credentials_missing`, or `health_status === "red"` |

| `unknown` | `link-state is-unknown` | Состояние неизвестно | Any missing required fact; hub/transport errors; yellow health; **never** `is-ok` |



Production stitch: `renderSimpleMode` → `await loadFieldManifest()` → `fetchSimpleLinkFacts()` → `POST /lab/connection-health` (with enrolled `router_id` / endpoint `host` when known; probe/advanced from link step) → `mapConnectionHealthToLinkFacts(healthReport)` + enrolled metadata (`router_id`, `host`, `display_name`, `port`) for Step 1 prefill/summary.



Step 1 UX helper: `deriveSimpleConnectStep1Ux(linkFacts)` — `connected` only when `deriveSimpleLinkState` visual is `ok`; transport/`health_unavailable` → auto-fail path with form open.



| Health `status` | UI visual | Notes |

|-----------------|-----------|-------|

| `green` | `ok` / `is-ok` | **Only when all five backend facts `true`**; mapper sets five link flags |

| `red` | `fail` / `is-fail` | Explicit false on reachable/host-key/tuple/credentials or red status |

| `yellow` or missing/incomplete | `unknown` / `is-unknown` | Partial facts — never green; `health_status: green` with incomplete facts → **unknown** |



Mapper (`mapConnectionHealthToLinkFacts`):



- `facts.reachable === true` → `reachability_ok`; `false` → `explicit_unreachable`

- `facts.host_key_match === true` → `host_key_pinned`; `false` → `host_key_mismatch`

- `facts.tuple_match === true` → `identity_consistent`; `false` → `identity_mismatch`

- `facts.credentials_present === true` → `credentials_present`; `false` → `credentials_missing`

- `facts.evidence_fresh === true` → `evidence_fresh`



Fail reason line (`data-testid="simple-link-reason"`): identity mismatch → «Роутер отвечает, но это не тот, что был сохранён ранее.»



Hub/status/API transport errors → incomplete facts (`health_unavailable`) → **unknown**, not fail-red.



Legacy `buildSimpleLinkFactsFromApis` is demoted: Gate A open alone does **not** set reachability or host-key facts.



Autodetect identity states: `known_match` → success toast; `known_mismatch` / `unknown` / any other or missing → ask credentials (no success toast).



---



## Wi‑Fi uplink honesty (Step 3)



### Step 3 live params — wired vs gaps



| Field | Source | Wired? | Notes |
|-------|--------|--------|-------|
| `host` | Step 1 connect form → `simpleModeWizardState.liveConnection` (via `persistSimpleWizardLiveConnectionFromDraft` on draft success) | **Yes** | Auto from Step 1 submit; survives hash-only wizard navigation |
| `username` | Step 1 connect form → `liveConnection` (same path as `host`) | **Yes** | **Not recoverable on full remount** without re-submitting Step 1 — form DOM alone does not repopulate wizard state |
| `router_credential_ref_id` | Step 1 draft response `credential_ref_id` → `liveConnection` | **Yes** | **Mgmt** router credential (distinct from Step 3 uplink `WifiWanPsk` enroll `credential_ref_id` on `#simple-uplink-credential-ref`) |
| `router_id` | Step 1 draft response `router_id` → `liveConnection` + uplink surface `setRouterId` | **Yes** | Included only when live set is **complete** (see gate below); never sent alone |
| `ssh_host_key_sha256` | Step 2 Advanced `#simple-health-ssh-pin` (DOM) | **Partial** | **NOT from Step 1** wizard state. Read at survey/preview/apply time via `resolveSimpleLiveConnectionParams()` (state pin or live DOM). **Lost on health-step full remount** unless re-entered in Advanced |
| Live gate (survey + preview + apply) | `resolveSimpleLiveConnectionParams()` | — | **All four** of `host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256` required. Incomplete → survey body `{ radio }` only; preview/apply payload omits **all** live fields (radio/intent-only uplink fields still sent). Partial live fields never sent (would 422). Fake/offline fixture works when zero connection fields present |

**Follow-up (out of scope here):** Step 5 guest Wi‑Fi (`buildSimpleGuestWifiStepSurface` / `readPayload`) uses the **same missing-live-params pattern** — payload is SSID/PSK/AP intent only, no `host`/`username`/`router_credential_ref_id`/`ssh_host_key_sha256`. Not fixed in this contract; do not claim guest apply is live-wired.



- **Primary picker:** manual CTA «Найти сети» (no auto-scan on step entry). Scans both `WifiMaster0` + `WifiMaster1`; band inferred on select (`WifiMaster0`→`BAND_2_4GHZ`, `WifiMaster1`→`BAND_5GHZ`). Survey body is `{ radio }` only until the live gate above passes; bare `router_id` alone is never sent.
- **Scan diagnostics (`data-testid="simple-uplink-scan-status"`):** HTTP failure → explicit error; `422 wifi.live_connection_incomplete` / `503` live unavailable → incomplete-connection message (fail-soft, manual fallback); dual-radio scan accumulates per-radio results — if one radio fails but the other returns networks, list shows partial results with explicit partial-scan status (not silent); `200` + zero networks on all radios → «Сети не найдены» — never an ambiguous empty list.
- **Rescan clears form:** «Найти сети» again resets `#simple-uplink-ssid`, `#simple-uplink-credential-ref`, enroll password, open-network UI state, and `#simple-uplink-band` → `BAND_2_4GHZ` (select default / payload fallback) — stale picker data must not survive rescan.
- **Open-network lock release:** selecting an open network disables enroll/preview/apply and shows a hint that open join is unsupported; manual fallback requires a **different** SSID (not the open network’s name left in the field). Editing manual fields clears scan row selection, but buttons stay disabled while `#simple-uplink-ssid` still exactly matches the scan-selected open SSID (no-op focus/input or band/credential-only edits). Changing SSID to a different value re-enables preview/apply/enroll (manual fallback — security unknown).
- **Signal/security labels:** derived from `signal_quality` / `rssi` / `wpa_mode` only — «Отличный/Хороший/Слабый», raw dBm, or «Неизвестно»; security «Открытая/WPA2/WPA3/WPA2/WPA3/Неизвестно» — no fabricated bars or invented types. Band labels in picker: «2,4 ГГц» / «5 ГГц»; hidden SSID display «Скрытая». Scan status RU-only (no English site-survey toast).
- **Enroll:** plaintext password → `PUT /routers/{id}/credentials` `kind: WifiWanPsk` → fills `#simple-uplink-credential-ref`. `router_id` resolved **at enroll time** (not mount snapshot): active uplink surface id after Step 1 draft success, else `linkFacts.router_id`, else first `GET /routers` item — Step 1 draft updates surface + wizard state without remount. Open networks: warn join unsupported; enroll/preview/apply disabled; payload still uses `auth_mode: wpa2_psk`.
- **Manual fallback:** `<details data-testid="simple-uplink-manual-settings">` «Сеть не в списке? Ввести вручную» — same field IDs for preview/apply readers.
- Preview (`POST /wifi/station/preview`): renders `grammar_verification_status`, `planned_uplink_verification_level`, sealed `apply_ops` via `renderStationApplyPlanSummary` — compile-time only.
- Apply (`POST /wifi/station/apply`): requires `confirm_live_apply: true`; result via `renderApplyResultWithVerdict` — `uplink_verification_status` may remain unverified; **not** WriteCertified / device-verified from HTTP alone.
- Simple fields: `ssid`, `band`, `credential_ref_id`; payload always includes `mode: WifiWan`, `auth_mode: wpa2_psk`.



---



## Mode shell



| Key | Values | Default | DOM |

|-----|--------|---------|-----|

| `rc.prototype.uiMode` | `simple`, `expert` | `simple` | `html[data-ui-mode]` |



Topbar: «Простой» / «Эксперт» with `aria-pressed`. Default hash when empty: `#simple` (simple) or `#dashboard` (expert). Sidebar: `nav-simple-only` vs `nav-expert-only` via CSS. Families expert link uses `nav-link-expert-entry` → `applyUiMode("expert")`.



### Wizard shell (`#simple`)



- **One step at a time:** horizontal stepper (7 labels: 6 primary + optional «Сети») + **Назад** / **Далее** (last step → **Готово**). Inactive step panels stay mounted but `hidden` / `aria-hidden`.
- **Hash deep-link:** `#simple/step-N` (1-based); bare `#simple` → step 1. `parseSimpleWizardStep` reads `params[0]` as `step-N` or bare `N`.
- **Done indicators (UI progress only, not certification):** step 1 done when `deriveSimpleConnectStep1Ux(linkFacts).mode === "connected"`; step 2 done **live** when `deriveSimpleLinkState(linkFacts).visual === "ok"` (not sticky across health regression); steps 3–6 done from in-session success paths (uplink apply `overall === "applied"` → 3; VPN catalog import response with truthy `profile_id` → 4; guest apply `overall === "applied"` → 5; domain preview **only** when `verification_status === "documentation_sourced_unconfirmed"` → 6). Stepper uses ○ pending / ✓ done.
- **VPN import:** collapsed `<details>` inside step 4 (`simple-vpn-import-details`, default closed); all `vpn-import-*` testids preserved.
- **In-place step change:** hash-only navigation reuses mounted DOM (form state preserved); health refresh still full remount.
- **Testids:** `simple-wizard-step-1`…`7`, `simple-wizard-back`, `simple-wizard-next`; step panels unchanged (`simple-step-connect`, …).



---



## Verification (offline)



```text

py -3.11 -m pytest tests/test_ui_simple_mode.py -q

node --check router_control_host/web/app.js

```



DOM-harness proves: unknown ≠ success-green; green requires all five facts; contradictory green status ≠ ok; identity mismatch reason; Gate A alone ≠ green; connection-health green/yellow/red mapping; **Step 1 enrolled auto-connect collapse/fail UX**; **Step 1 advanced closed by default**; **Wi‑Fi uplink step DOM + preview endpoint + apply confirm gate**; **wizard one-step visibility + stepper + Next/Back navigation bounds + hash deep-link**; **step 2 live done honesty + step 6 domain preview status honesty**; domain step has no publish button; VPN traffic/kill-switch actions absent; VPN import collapsed by default; mode persistence; password `omitName`; guest apply result sanitized; discovery/health manifest tooltips.



**Docs map:** entry in `docs/docs-map.json`; update via `/maintain-project-docs` when behavior changes.



---



## Backend wishlist (next cycle)



- VPN traffic-ready / policy-routing apply.

- Guest isolation grammar when API accepts it.

- KeenDNS/CrazeDNS (likely T4 external).

