# Operator runbook — Wi-Fi apply / verify (server)

## For agents

| Topic | Rule |
|---|---|
| When to read | Before calling Wi-Fi apply/preview/teardown API, wiring host transport, or operating `#config` Wi-Fi Apply UI |
| Scope | Backend Configure → Apply → Verify for bounded test APs: default **`WifiMaster0/1` + `AccessPoint3`–`AccessPoint6`** (observed hardware max; AP7–9 not present); expendable lab class (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`) additionally allows **`AccessPoint0`–`AccessPoint2`** |
| Default | **Preview** is offline-safe (compile only); **apply/teardown** require `confirm_live_apply` / `confirm_live_teardown` + auth |
| PSK | Request bodies accept **`credential_ref_id` only** — never plaintext `psk` |
| Gates | Does **not** open WriteCertified or flip `write_shapes_registered`; live path still requires per-campaign T4 for real router |
| Transport | Per-request live when win32 + complete connection params on body; else injected factory / fake / 503 |

---

## 1. Flow

1. **Preview** — `POST /api/router-control/v1/wifi/preview` with `WifiIntent` fields + `ap_id`. Returns compiled op plan (op names, non-secret args, `credential_ref_id` for PSK op). No dispatch, no credential resolution. Connection params **not required**.
2. **Apply** — `POST /api/router-control/v1/wifi/apply` with same intent fields + `confirm_live_apply: true`. Optional reliability flags (default safe/compat): `compensate_on_failure: true` (reverse-order compensating rollback on partial dispatch failure or **configuration** verify mismatch — **not** on `on_air_admin_only` / `on_air_unverified`); `idempotent: false` (when `true`, pre-read `show interface` and skip ops already satisfied — PSK op never skipped). Dispatches sealed ops in order (WPA2, WPA3-Personal, and WPA2+WPA3 mixed device-verified), readback `show interface <ap_id>`, verifies SSID + mode-appropriate encryption + **admin up** (`admin_up_ok`); **on-air** verdict from shared `resolve_on_air_signal` (`on_air_verification_status`: `on_air_verified` \| `on_air_admin_only` \| `on_air_unverified` \| `on_air_still_broadcasting` on teardown) — `link` only for wire link; `broadcast`/`broadcasting` supplementary; link/broadcast conflict → unverified — **not** from `state=up` / `connected` alone.
3. **Teardown** — `POST /api/router-control/v1/wifi/teardown` with `ap_id`, **`wpa_mode` required** (no HTTP silent default — matches domain `_parse_wifi`), + `confirm_live_teardown: true` (or `confirm_live_apply: true`). Live path requires Gate A open + startup-config backup before first write (same as apply); backup failure → `503 wifi.live_backup_unavailable` (no writes). **Best-effort:** all teardown ops are attempted in order even if a mid-sequence op fails (`clear_ssid` still runs last); readback verify always runs afterward. `overall=applied` only when every op succeeds and baseline verify passes; any op failure → `overall=failed` (not `applied`).

### Wi-Fi station (WISP) apply / teardown

1. **Preview** — `POST /api/router-control/v1/wifi/station/preview` (offline compile only). Response includes **`planned_uplink_verification_level=planned_uplink_verified_bounded`** (compile-time plan label — machine-distinct from runtime `uplink_verification_status`; **not** runtime uplink observe).
2. **Apply** — `POST /api/router-control/v1/wifi/station/apply` with `UplinkIntent` WifiWan fields + `confirm_live_apply: true`. Optional: `compensate_on_failure`, `idempotent`, `uplink_settle_seconds` (default 25; clamp 20–30 on live observe). Live path requires Gate A open + startup-config backup before first write; response may include `backup_basename`, `backup_content_sha256`. Apply/teardown responses omit compile-time planner `notes` (preview-only). Offline/fake path returns **`uplink_verification_status=uplink_dispatched_unverified`** (runtime; no observe). Live path: runtime **`uplink_verification_status`** from honest observe (`uplink_verified_bounded` \| `uplink_associated_no_global` \| `uplink_dispatched_unverified` \| `uplink_failed`) — **not** preview `planned_uplink_verification_level` and **not** from link/connected alone (`auth-type` stays `none` on associated WPA2 uplink — never a trap signal). **`verdict_explanation`** required on apply/teardown (enum-coded signals; upstream SSID as match boolean only). `compensate_on_failure` rolls back only on dispatch failure or `uplink_failed` — **not** on `uplink_associated_no_global` / `uplink_dispatched_unverified` / other unknown observe verdicts. Rollback may be **`partial`** when `wifi_station_ip_global` succeeded (live planner opts in) — negation grammar **not device-confirmed**; see `rollback.uncovered_ops`. Any live connection field without complete set → **422** `wifi.station.live_connection_incomplete` (before transport/mode checks; no silent offline fallback). Complete live connection params on non-win32 → **503** `wifi.station.live_platform_unsupported`. Backup failure → **503** `wifi.station.live_backup_unavailable`.
3. **Teardown** — `POST /api/router-control/v1/wifi/station/teardown` with same intent fields + confirm flags. Same incomplete-live validation as apply. Live path requires Gate A open + startup-config backup before first write (same as apply). Teardown dispatch is continue-on-error.

**Honest bounds (station HTTP only):** `POST /wifi/station/apply` and `/wifi/station/teardown` routes are delivered and offline-testable (fake transport); **station apply/teardown are NOT device-verified on live unit in this delivery** — distinct from bounded **AP** apply (§2 WPA3/mixed device-verified on NC-1812 2026-07-24). WriteCertified NOT claimed; `wifi_wan_not_certified` preset unchanged.

---

## 2. Safety bounds

| Rule | Enforcement |
|---|---|
| Production APs `AccessPoint0/1/2` | Rejected in **default (non-expendable)** mode at service + API (`422 wifi.ap_forbidden`); **allowed** when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` |
| Non-`WifiMaster0/1` APs | Rejected |
| WPA3-Personal | Device-verified: full sealed op compile + dispatch; `verification_status=device_verified_wpa2` (same literal as WPA2); grammar `authentication wpa-psk` + `encryption wpa3`; evidence [`data/artifacts/wifi-wpa3-live-reverify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa3-live-reverify-192.168.2.1-20260724.json) (NC-1812 firmware 5.01.C.1.0-0, 2026-07-24); WriteCertified NOT claimed |
| WPA2+WPA3 mixed | Device-verified: full sealed op compile + dispatch; `verification_status=device_verified_wpa2` (same literal as WPA2); grammar `authentication wpa-psk` + `encryption wpa2` + `encryption wpa3`; readback `wpa2,wpa3`; evidence [`data/artifacts/wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json) (NC-1812 firmware 5.01.C.1.0-0, 2026-07-24); WriteCertified NOT claimed; `write_shapes_registered` remains false |
| Plaintext PSK in API/logs/responses | Forbidden; resolver used only at dispatch for `SET_WPA_PSK` |
| Missing confirm flag on apply/teardown | `400 wifi.confirm_required` |
| Auth | `hub_admin` cookie required (401 without) |

---

## 3. Response shape (`WifiApplyResult`)

| Field | Values |
|---|---|
| `overall` | `applied` \| `failed` \| `verify_mismatch` \| `rolled_back` (additive: compensation fully succeeded after failure/mismatch). **`applied` = configuration delivered** (SSID + encryption + admin up match intent) — independent of on-air verdict. `verify_mismatch` when config fields fail **or** when on-air is **`on_air_admin_only`** (known deceptive: admin up + link down). Link/broadcast conflict or missing on-air signals → `on_air_unverified` but **`overall` stays `applied`** when config verify passes (no rollback). |
| `on_air_verification_status` | `on_air_verified` \| `on_air_admin_only` \| `on_air_unverified` \| `on_air_still_broadcasting` (teardown) — from shared `resolve_on_air_signal` (`link` only via `parse_up_down_flag`; `broadcast`/`broadcasting` via `parse_broadcast_flag`; conflict → unverified) |
| `verdict_explanation` | Required on apply/teardown: enum-coded `signals_read` / `signals_missing` / `signals_rejected` derived from the same readback as `on_air_verification_status` (e.g. `connected_with_link_down`, `link_broadcast_conflict`); no SSID/secrets in values — UI renders human text. |
| `steps` | `[{op, ok, status_ident?, error?, error_category?, router_message?, command_redacted?}]` — taxonomy fields on failed dispatched ops only; PSK never in `command_redacted` |
| `verification` | `{ssid_ok, encryption_ok, admin_up_ok, on_air_ok, observed}` — `admin_up_ok` = admin `state`/`up`; `on_air_ok` = `true`/`false`/`null` from `resolve_on_air_signal` (`null` = unverified or link/broadcast conflict, not failure); observed sanitized (no secrets/MAC); encryption readback is mode-aware (WPA2 / WPA3 / mixed) |
| `errors`, `logs` | Sanitized strings; **`errors` = apply/dispatch/readback failures only**; never contain PSK |
| `rollback_errors` | Separate from `errors`: populated when compensating rollback dispatch failed (`rollback.outcome` partial/failed); empty when rollback not attempted or succeeded |
| `rollback` | `{attempted, ops, outcome: not_attempted\|noop\|succeeded\|partial\|failed, steps?, uncovered_ops?}` — compensating teardown of succeeded apply ops; original errors preserved; **`overall=rolled_back` only when `outcome=succeeded`**. Station live apply includes `wifi_station_ip_global` when planner opts in — **no sealed negation** (`docs/OPERATOR_WIFI_DISCOVERY.md` §2c: positive `ip global {priority}` device-exercised; negation unverified) → `uncovered_ops` when that op succeeded before failure. **Baseline-aware (2026-08-01):** pre-apply `show interface` / station readback before first write when `compensate_on_failure=true` (bounded by transport `read_timeout`, default 15s — timeout → fail-closed unknown baseline); compensation runs only for state **created or changed** by this apply; pre-existing fields → `uncovered_ops` with `pre-existing configuration…`; unreadable baseline → fail-closed skip (`pre-apply state unknown…`); **open-network PSK absent** inferred via `encryption_indicates_open` (dict `encryption`/`encryption-mode` disabled/none per site-survey readback — not `encryption_empty` alone); **PSK absent from readback while WPA enabled** → `pre-apply PSK state unknown; clear would destroy foreign state` (device readback never returns PSK per `docs/OPERATOR_WIFI_DISCOVERY.md`:130). |
| `skipped_ops` | `[{op, reason}]` when `idempotent=true` — ops skipped because pre-read already matched desired state |
| `backup_basename`, `backup_content_sha256` | Present on live apply/teardown when pre-change startup-config backup succeeded |

Preview returns plan object with `apply_ops`, `teardown_ops`, `verification_status`, `notes`.

**Reliability (offline, 2026-07-30):** apply-path compensating rollback, structured router error taxonomy, and idempotent re-apply are implemented and tested offline only — **not** new device-verified claims; no gate or allowlist changes.

---

## 4. Offline vs live

### Offline tests / fake host

Set `RC_ALLOW_FAKE_MUTATIONS=1` or `allow_fake_mutations=True`; optional `wifi_apply_transport_factory` on `HostState` for custom FAKE. Omit connection params on apply/teardown body → factory/fake path unchanged.

### Per-request live (win32 + DPAPI)

When **all** of the following hold, apply/teardown open a **short-lived** pinned SSH session from request body connection params (no standing live factory in `create_app`):

| Requirement | Body field / host state |
|---|---|
| win32 host | `sys.platform == "win32"` |
| Router reachability | `host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256` (non-empty) |
| Optional source bind | `source_address` |
| Router password | Resolved via `vault.use(router_credential_ref_id)` at session open |
| PSK | Separate `credential_ref_id` on intent — resolved only at `SET_WPA_PSK` dispatch |
| Live apply/teardown backup | Open `host.gate_a_certification` required (`503 wifi.gate_a_required` / `503 wifi.station.gate_a_required` when closed); `backup_startup_config` before first mutating op; result includes backup basename + sha256; backup failure → `503 wifi.live_backup_unavailable` / `503 wifi.station.live_backup_unavailable` |
| Confirm + bounded AP | Unchanged |

Module: `router_control_host/wifi_live_transport.py` (`open_wifi_live_session`).

If connection params absent or incomplete → prior `_resolve_transport` behavior (factory / fake / 503). Complete live connection params on non-win32 → **503** `wifi.live_platform_unsupported` (no silent fake fallback).

**UI:** `#config` → **Wi-Fi Apply (test AP)** — Preview / Apply / Teardown with connection fields and confirm checkbox. **Wi-Fi Status (observed)** — read-only table with match/differs/unknown vs optional Apply-form intent; explicit "Could not read Wi-Fi state" when unreadable. See [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md).

---

## 5. Wi-Fi observed state (read-only)

| Topic | Rule |
|---|---|
| Purpose | Let operators **see** current AP reality (SSID, band, security mode, up/link vs last desired intent) |
| Writes | **None** — read-only `show interface` parse path |
| On-air | `link_up` from device `link` only (shared `parse_up_down_flag` / `resolve_link_up`: `up`/`down`, `enabled`/`disabled`, `true`/`false`, string `"1"`/`"0"`; **not** `yes`/`no`/`on`/`off`; bare int/empty → unknown). Apply on-air uses `resolve_on_air_signal` (`parse_broadcast_flag` for `broadcast`/`broadcasting`: `yes`/`no`/`on`/`off`/`up`/`down`; link/broadcast conflict → unverified); torn-down AP may show `device_connected: true` with `link_up: false` |
| PSK | Never returned; `key_configured` bool/null only when derivable without exposing value |
| Security mode | `not_configured` (empty encryption), `unrecognized` (present but unmapped), `unknown` (unreadable) — none false-match desired WPA modes |
| Compare | Per-field `match` / `differs` / `unknown`; missing observed never false-matches; shares encryption/SSID/up rules with apply idempotency helpers |
| Certification | Always `certification_eligible: false`; `offline_verified_only: true` |
| Live wiring | Same per-request connection fields as apply (`host`, `username`, `router_credential_ref_id` or `credential_ref_id` alias, `ssh_host_key_sha256`, optional `source_address`/`router_id`); open Gate A required; read-only `open_wifi_live_session` — **no** confirm, **no** backup, **no** writes |
| API | `POST /api/router-control/v1/wifi/observed-state` — see [`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) §7.8 |

### 5a. Live evidence note (2026-07-31 sealed path)

| Fact | Value |
|---|---|
| Device / fw | NC-1812 / 5.01.C.1.0-0; Gate A ReadOnlyCertified after authorized rebind 2026-07-31 |
| Host-key pin | `ssh-ed25519 SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`; source `192.168.2.10` |
| Test AP | `WifiMaster0/AccessPoint3` (production AP0 / guest AP1 untouched) |
| Apply modes verified | WPA2, WPA3, WPA2/WPA3-mixed — preview sealed ops, apply=applied, readback match, teardown baseline |
| Idempotent re-apply | Skipped set_ssid/encryption_enable/encryption_wpa2/up; PSK op still dispatched |
| Compensating rollback | Missing PSK credential ref → overall=rolled_back (CLIENT-side VaultError; router-rejection taxonomy unverified) |
| Backup / save / reboot | Pre-change startup-config backup before first write; **no** system configuration save; **no** reboot |
| Evidence | `data/artifacts/wifi-sealed-path-live-gate-a-20260731.json` |
| **Non-claims** | HTTP `POST /wifi/observed-state` returned **503** this run — comparison exercised via `open_wifi_live_session` directly; **NOT** HTTP route live-validated. WriteCertified NOT claimed; `write_shapes_registered` remains false; gates A/B/C/D UNCHANGED. |

**Quality note (2026-07-31):** live RO validation on certified expendable lab router found device `connected` ≠ on-air and HTTP error misclassification — fixed in observed-state/site-survey error paths; offline fixtures alone did not surface torn-down AP shape.

### 5b. Guest Wi‑Fi live campaign (2026-08-02)

| Fact | Value |
|---|---|
| Device / fw | NC-1812 / 5.01.C.1.0-0; Gate A ReadOnlyCertified (evidence `gate-a-probe-post-parser-fix-20260801.json`) |
| Host-key pin | `ssh-ed25519 SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`; source `192.168.2.10` |
| Test AP | `WifiMaster0/AccessPoint3` — campaign targeted AP3 only; no AP0/AP1 mutation recorded in evidence |
| Apply | WPA2 guest test SSID; **`apply_overall=applied`**, **`apply_on_air=on_air_verified`** (link=`up`, connected=`yes`) |
| Teardown | **`teardown_overall=applied`** |
| Backup / save | Pre-change backup basename `startup-192.168.2.1-20260802T065555Z-c790ed29.dpapi`; **`system_configuration_save=false`** |
| Guest isolation | **`guest_isolation_requested=false`** — feature still **unsupported** (422) — **NOT verified** |
| Credentials | Throwaway credential revoked and deleted |
| Evidence | `data/artifacts/guest-wifi-live-campaign-20260802.json` |
| Harness trap | Preview plan key is **`apply_ops`**, not `ops` — wrong key logs empty op list (see handoff §3.3) |
| **Non-claims** | WriteCertified NOT claimed; `write_shapes_registered` remains false; gates A/B/C/D UNCHANGED |

---

## 6. Related docs

- [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) — RO inventory + write-shape verification
- [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md) — `#config` Wi-Fi Apply UI
- [`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) — HTTP contract
- [`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md) — sealed RCI policy
