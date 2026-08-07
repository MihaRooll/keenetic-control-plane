# Operator router config UI — vertical slice 1

## For agents

**When to read:** operating `#config` router settings view, offline AWG `.conf` import CLI, or distinguishing broad Apply gates from the bounded Wi-Fi Apply exception. For the default **simple-mode** wizard (`#simple`), read [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md) first — simple «Дополнительно: сетевые семейства» link switches to expert mode before navigating `#config`.

**Apply (default):** Slice posture is **read-only** on the router except the bounded Wi-Fi and AWG Apply exceptions below. VPN import stores secrets in vault only; UI/API never echo keys, PSK, endpoint host, or raw `.conf`. Broad Apply/live-write stays fail-closed until Gate B WriteCertified **and** exact T4 Human Gate Packet.

**Exception — Wi-Fi Apply (`#config`):** confirm-gated per-request live apply/teardown on bounded test APs (`WifiMaster0/1` + `AccessPoint3`–`6` default; expendable lab class adds `AccessPoint0`–`2` when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` or UI lab-class hint set); optional live connection params (`host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256`, `source_address`) on win32 + DPAPI + pinned SSH when complete; Gate A startup backup before mutation. Does **not** claim WriteCertified or open Gate B/C/D. Gate A **ReadOnlyCertified** (authorized rebind **2026-07-31** rebind #2 post-WG; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`) — **NOT** WriteCertified; Gates B/C/D unchanged; `write_shapes_registered` remains **false**.

**Exception — AWG Apply (`#config`):** confirm-gated per-request live apply/teardown on bounded test interfaces (`Wireguard5`–`9` default; expendable lab class adds `Wireguard0`–`4` when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` or UI lab-class hint set); same optional per-request live connection params as Wi-Fi Apply; reuses `open_wifi_live_session`. Does **not** claim WriteCertified or open Gate B/C/D.

**Do not:** claim WriteCertified, open Gate B/C/D, enable broad Apply from `#config`, or mutate production AP0/1/2 in **default (non-expendable) mode** — expendable lab class (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`) allows AP0–2 per [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §1a.

---

## UI — `#config`

| Path | Назначение |
|------|------------|
| `/settings/router-control#config` | Настройки роутера (RO overview, VPN table, Wi-Fi/DNS validate/preview, VPN policy-routing preview, network-family preview panels, bounded Wi-Fi/AWG apply, apply-gate banner) |

Nav: **Настройки роутера** in sidebar.

Sections:

1. **Обзор (read-only)** — `GET /status` (identity/gates) + `GET /observed-interfaces` (local topology artifact). Empty interfaces → «нет данных, требуется observe».
2. **VPN-профили** — `GET /vpn-profiles` (metadata/digest only).
3. **Credential refs** — list/enroll/revoke via `GET/PUT/POST .../credentials*`; enroll one-shot value → DPAPI/vault; UI shows `credential_ref_id` + metadata only.
3. **VPN catalog import** — `#config` and `#vpn` panels; **simple:** `display_name`, `vpn_kind`, `profile_document` (JSON), optional `profile_text`; **Дополнительные настройки:** write-only `private_key` / `preshared_key` (`password`, `omitName`, cleared after submit) → `POST /vpn-profiles/import` with `Idempotency-Key`; toast **Catalog import OK (SQLite/vault only, not device apply)**; result panel metadata only — **catalog import ≠ device apply**.
4. **VPN/WG parse preview (vault only)** — paste `.conf` → `POST /vpn-profiles/parse-preview` only; sanitized preview (`credential_refs` + field names); textarea cleared after success; toast/copy must not imply device import or catalog import.
5. **Wi-Fi / DNS** — preset select + Validate / Plan preview via `POST /event-presets/{id}/validate` and `.../plan-preview` (empty POST body — preset id only; draft form fields are local preview-only and not submitted); `write_ready=false` always.
6. **VPN policy-routing preview** — `#config` panel; **simple:** `policy_name`, `vpn_interface`. **Дополнительные настройки:** optional `interface_kind`, `address_configured`, `ip_global` (`auto` | priority | order), `name_servers` row editor (address/domain/on_interface) → `POST /vpn/policy-routing/preview`; RESULTS panel shows compiled `apply_ops` / `teardown_ops`, `unknowns`, citation notes; `verification_status=help_verified_grammar_unapplied`; **preview only — no apply route**; honesty banners: not device-verified, does not open Gate B/C/D.
7. **Network-family preview (VLAN / DHCP / DNS / firewall)** — four `#config` panels; **simple/advanced** per family (D1): VLAN gateway advanced; DHCP lease + reservations rows; DNS upstream resolver rows; firewall rules rows; tooltips on all fields. Each Preview → `POST /vlan/preview`, `/dhcp/preview`, `/dns/preview`, or `/firewall/preview`; RESULTS panel shows compiled ops + `verification_status=offline_unverified`; apply_ops forward order, teardown_ops reverse rollback order; 422 → human messages (`*.preview_failed`); **preview only — no apply routes**; honesty banners per panel; does not open Gate B/C/D.
7a. **Event preset editor (`#presets`)** — four-zone offline catalog editor with domain-safe bootstrap; load revision via `canonical_document`; save keeps local built doc (POST revision response has no document); uplink modes `Ethernet|WifiWan|LocalOnly|Lte`; zone `AdminServer`; firewall `rules[]` row editor; full required fields (`ipv6_posture`, `management_allowed`, Wi‑Fi/DHCP/DNS advanced, `rack_assets` rows). Validate/plan/readiness unchanged (`write_ready=false`).
8. **Wi-Fi Apply (test AP)** — bounded test AP (`WifiMaster0/1` + `AccessPoint3`–`6` default; expendable lab class adds AP0–2); Preview → `POST /wifi/preview`; Apply/Teardown → `POST /wifi/apply|/wifi/teardown` with `confirm_live_apply` / `confirm_live_teardown`. **Simple (default):** SSID, PSK `credential_ref_id`, band. **Дополнительные настройки:** `ap_id` (allowlist select), `wpa_mode`, `enabled`, `guest_isolation`, `captive_portal`, `router_id`, `compensate_on_failure`, `idempotent`, live connection ×5, confirm — full `WifiApplyBody` coverage. Honesty: `guest_isolation=true` / `captive_portal=Enabled` accepted by API but **planner rejects** at `compile_wifi_intent_to_ops` (422 `wifi.guest_isolation_unsupported` / `wifi.captive_portal_unsupported`); defaults `false` / `Disabled` compile. Tooltips on fields (`?`, CSP-safe). Teardown requires `wpa_mode` (no HTTP silent default). Optional per-request live connection: `host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256`, `source_address` — win32 + DPAPI + pinned SSH when complete; else fake/factory path. RESULTS/LOGS panel shows `WifiApplyResult` (steps, verification, backup meta). Safety copy: production AP0/1/2 not selectable in default mode; expendable lab class enables AP0–6 via `window.ROUTER_CONTROL_LAB_CLASS` or `data-router-control-lab-class` on `<html>`; confirm required.
9. **AWG Apply (test interface)** — bounded test interfaces (`Wireguard5`–`Wireguard9` default; expendable lab class adds `Wireguard0`–`Wireguard4` when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` or UI lab-class hint set); Preview → `POST /wireguard/preview`; Apply/Teardown → `POST /wireguard/apply|/wireguard/teardown` with confirm flags. **Simple:** `wg_id`, peer public-key/endpoint/allow-ips, private-key `credential_ref_id`, confirm. **Дополнительные настройки:** preshared-key ref, ASC args, keepalive, `peer_rci_shape` (`nested_rci` default; **`path_style` disabled + REJECTED copy**), `handshake_settle_seconds`, `enabled`, `router_id`, live ×5. **No** `compensate_on_failure` / `idempotent` on WireGuard HTTP body. Secrets via credential refs only (no plaintext key inputs). Optional per-request live connection fields same as Wi-Fi Apply; reuses `open_wifi_live_session`. RESULTS/LOGS panel shows `WireguardApplyResult` with honesty split. 16-arg ASC → `unsupported_pending_verification`.
10. **Sealed RCI mutations (FAKE)** — typed enum endpoints only; routes/body ops from manifest (`route_key_by_value`, `body_operation_by_value`); **simple:** `router_id`, operation select (`fieldTooltipOpts("rci_sealed","operation")`, default from manifest), confirm checkbox (+ honesty note on confirm); **Дополнительные настройки:** `interface_id` (manifest `required_when` for interface up/down); fake-gated; banner + toast **RCI FAKE ack (not device)** / **Succeeded = SQLite synthetic ack** — NOT live device RCI; no raw RCI passthrough UI.
11. **TrafficDiscovery (proposals-only)** — `buildTrafficDiscoveryFormSurface`; **simple:** router_id, evidence dst/proto, route prefix, confidence, observation/proposal ids; **Advanced:** source, ttl, trusted_policy, JSON fallbacks; honesty toasts (digest only, auto-apply blocked).
12. **Wi‑Fi observed** — `#config` + `#uplink` step 5 via `buildWifiObservedFormSurface`; **Advanced:** live ×5 + `allow_insecure_http`; `formatWifiObservedSessionToast`.
13. **Site survey (`#uplink`)** — `buildSiteSurveyFormSurface`; **Advanced:** live ×5; `formatSiteSurveyResultToast`.
14. **Apply banner** — catalog/preset Apply blocked while Gate B not WriteCertified: «Каталог/preset Apply заблокирован…»; bounded Wi-Fi/AWG test Apply panels remain available with confirm + per-request connection params. **Deploy Confirm/Apply (FAKE):** `risk_acknowledged` on confirm; GET single deployment-revision; PUT desired-revision overlay; Apply plan enqueues SQLite job — toast **Job queued (SQLite plan queue, not device apply)**; not device-side success.
15. **KeenDNS** — not available in this build (disabled stub; no backend).

**Field manifest (2026-08-01):** `#simple`, `#config`, `#uplink`, `#vpn`, and `#add-router` each `await loadFieldManifest()` once per view render before building manifest-backed forms. Tooltips **and control defaults** for families `wifi_ap`, `wifi_station`, `wireguard`, `vlan`, `dhcp`, `dns`, `firewall`, `vpn_policy_routing`, **`vpn_profile`**, **`rci_sealed`**, **`router_discovery`**, **`connection_health`**, **`wizard_draft`**, **`ssh_host_key`**, **`bootstrap_discovery`**, **`enroll`**, plus **`wifi_site_survey`**, **`wifi_observed`**, **`traffic_discovery`**, **`commissioning`**, **`change_plan`**, **`deployment`**, **`desired_revision`** come from manifest via `lookupFieldMeta` / `fieldTooltipOpts` (`mergeManifestControlDefault`; manifest `default: null` → unchecked/empty, no invented `true`; **`wizard_draft.allow_insecure_http` default `false`** — unchecked in Advanced). Add-router learn/confirm POST bodies built via `buildWizardSshHostKeyLearnBody` / `buildWizardSshHostKeyConfirmBody` (`source_address`, `allow_overwrite`). RCI mutation POST path/body resolved via `resolveRciMutationRequest` (manifest routes with `{router_id}` substitution; API prefix stripped). Apply/catalog toasts route through `APPLY_TOAST_PATHS` (`P-wifi-apply`, …, **`P-vpn-import`** catalog honesty) invoked by shared `execute*Click` handlers. **Wi-Fi apply toast honesty (2026-08-01):** unknown/missing `overall` → `Apply unknown (…)`; null data → `unknown (no result)`; positive on-air secondary only when `overall=applied` — see `tests/test_ui_honesty_defects.py`.

Auth: same `hub_admin` cookie as API.

## CLI — offline AWG import

```powershell
py.exe -3.11 scripts\import-vpn-profile.py `
  --conf path\to\profile.conf `
  --secrets-root data\secrets
```

Options:

| Flag | Default | Notes |
|------|---------|-------|
| `--conf` | — | Repeatable path to `.conf` |
| `--conf-dir` | — | Scan directory |
| `--glob` | `*.conf` | With `--conf-dir` |
| `--secrets-root` | `data/secrets` | DPAPI root on win32 |
| `--catalog-out` | — | Optional sanitized JSON report |
| `--allow-memory-vault` | off | Tests/offline only |

Stdout: JSON report with `sanitized` per file (`interface_field_names`, `peer_field_names`, `credential_refs`, `endpoint_configured`, `awg_param_names`, `profile_digest`) — **never** key values, endpoint host, Address, or raw conf.

Non-win32 without `--allow-memory-vault` → exit 2.

## Observed interfaces API

`GET /api/router-control/v1/observed-interfaces` — reads newest `topology-*.json` under `data/artifacts/` (or `RC_ARTIFACTS_DIR`). No network. Returns `findings.sanitized_interfaces` as `items`.

## Apply / write gates

| Path | Gate posture |
|------|----------------|
| Broad Apply / other live mutation | **Blocked.** Gate B is not WriteCertified; write allowlist and hardware gates unchanged. Requires discovery shape registration + fresh T4 Human Gate Packet per campaign. |
| Wi-Fi Apply / Teardown (`#config`) | **Exception — bounded test AP.** Default `AccessPoint3`–`6` on `WifiMaster0/1`; expendable lab class adds AP0–2. Preview → `POST /wifi/preview`; Apply/Teardown → `POST /wifi/apply` and `POST /wifi/teardown` with `confirm_live_apply` / `confirm_live_teardown`. Per-request live connection params + win32/DPAPI + pinned SSH when complete; Gate A startup backup before mutation. Confirm-gated; production AP0/1/2 not selectable in default mode. **Does not** flip WriteCertified or unblock other Apply paths. Gate A **ReadOnlyCertified** (2026-07-31 rebind #2 post-WG; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`) — **NOT** WriteCertified; Gates B/C/D unchanged. |
| AWG Apply / Teardown (`#config`) | **Exception — bounded test interface only.** `Wireguard5`–`9`; Preview → `POST /wireguard/preview`; Apply/Teardown → `POST /wireguard/apply|/wireguard/teardown` with confirm flags. Intent: `wg_id`, optional 9-int `asc_args`, `enabled` (generic interface up/down), optional peer fields (`peer_public_key`, `peer_endpoint`, `peer_allow_ips`, `peer_keepalive_interval`), `peer_rci_shape` (`nested_rci` default — peer write device-verified accepted 2026-07-24; `path_style` legacy REJECTED). Secrets via `private_key_credential_ref_id` / `preshared_key_credential_ref_id` only (no plaintext). Reuses per-request live session wiring. 16-arg ASC → unsupported. **Does not** flip WriteCertified. |

General Apply banner stays blocked while Gate B is not WriteCertified (catalog/preset paths). Wi-Fi/AWG bounded test Apply uses its own confirm + connection-param gates; success there is not standing authorization for VPN, preset, or other mutations.

## Related

- [`OPERATOR_UI.md`](OPERATOR_UI.md) — prototype SPA overview
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed RCI operator CLIs (separate T4 track)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) — **active** lab handoff (post-rebind unit)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) — **historical** prior-session handoff (superseded)
