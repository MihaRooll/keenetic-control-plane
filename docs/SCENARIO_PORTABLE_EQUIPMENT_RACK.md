# Portable equipment rack — field technician scenario

## For agents

| Check | Action |
|---|---|
| Scope | **Offline foundation** — product doc + gap register + `UplinkIntent`; sealed **offline** station family + site-survey API (2026-07-31); grammar **device-confirmed** (`device_accepted_grammar`); first association **bounded persisted** (`uplink_verified_bounded` — one 5 GHz WPA2 network, saved+reboot-survived); HTTP apply/teardown **delivered** (confirm-gated; **NOT device-verified live** this delivery); `wifi_wan_not_certified` intact; **no** allowlist/write-path/certification claims |
| Gates | **Gate A ReadOnlyCertified** (authorized rebind **2026-07-31** rebind #2 post-WG identity drift; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 `gate-a-probe-newrouter-192.168.2.1-20260731.json` **SUPERSEDED**); **B** `not_write_certified`; **C/D closed** — **WriteCertified NOT claimed**; `write_shapes_registered` remains **false** |
| Uplink truth | `UplinkMode.WIFI_WAN` exists in domain; sealed **offline** station compiler + site-survey read API (2026-07-31); preset planner still marks `support: unsupported` / `wifi_wan_not_certified` even when fully specified; HTTP apply/teardown **delivered** — offline fake + unit tests; **NOT device-verified live apply** |
| Captive portal | Repo `WifiIntent.captive_portal` = **host** Coova-Chilli (we serve guests). `UplinkIntent.captive_portal_client` = **client** direction (venue portal) — **distinct**, not supported |
| Technician rule | Field technician **never** uses router admin panel — all configuration via Router Control API / preset only |
| Roadmap | Ordered work items + hazards: [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.2 |
| Domain | Extended `UplinkIntent`: [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md) |

---

## 1. Actors and context

| Actor | Role |
|---|---|
| **Field technician** | Deploys portable equipment rack at venue; connects uplink; verifies staff/guest Wi‑Fi; **must not** open Keenetic web UI |
| **Router Control operator** | Creates/validates event preset offline; publishes revision; observes readiness (no live writes until gates open) |
| **Venue network** | Provides upstream connectivity — Wi‑Fi (often captive portal), wired Ethernet, or future cellular |
| **Portable rack** | Router (L3/DHCP/DNS/firewall/AP owner) + Hub (apps only) + switch + printers |

**Scenario goal:** rebroadcast **own SSIDs** (Staff/Promo/Guest zones) while upstream may be venue Wi‑Fi, wired WAN, or planned LTE/USB modem.

---

## 2. Uplink modes (target architecture)

| Mode | Intent `mode` | Current status | Notes |
|---|---|---|---|
| **Venue wired Ethernet** | `Ethernet` | **implemented** (domain + planner `supported`) | Primary preferred uplink when venue offers RJ45 |
| **Venue Wi‑Fi client (WISP)** | `WifiWan` | **offline-only** preset planner + **bounded live uplink evidence** on current unit (`uplink_verified_bounded`, 5 GHz WPA2, persisted); sealed station compiler preview + site-survey API + HTTP apply/teardown (not device-verified live) | Requires `ssid` + `credential_ref_id`; optional `bssid` pin; `band` defaults `BAND_2_4GHZ`; OPEN auth **rejected**; planner **unsupported** / `wifi_wan_not_certified` |
| **Cellular / USB modem** | `Lte` | **components installed; hardware-only remaining** | USB stack `usb`/`usbmodem`/`usblte`/`usbqmi`/`usbnet` **already present** on current rebind unit (2026-07-31) — no component download/reboot needed; **modem operation NOT device-verified**; no modem iface objects without physical modem plugged in |
| **Local-only / no WAN** | `LocalOnly` | **implemented** (domain) | Booth isolated operation |

**Multi-uplink preference (modeling only):** `priority` field — lower number = higher preference (e.g. wired `10` preferred over WifiWan `50`). **No** live failover or policy-routing compiler exists.

---

## 3. Own SSID rebroadcast

| Capability | Status | Evidence |
|---|---|---|
| Zone Wi‑Fi AP intents (`WifiIntent` per Guest/Promo/Staff) | **implemented** (offline product model + sealed AP apply on test APs) | `wifi_apply_planner.py`; live AP-only evidence |
| Simultaneous AP + station (WifiWan client) on same radio | **offline-only** (sealed compiler; grammar device-accepted; uplink **bounded verified** on 5 GHz case) | Same-band coupling hazard beyond bounded case; failover unverified |
| Venue SSID as upstream + own SSIDs downstream | **offline compiler** + bounded live uplink evidence | `wifi_station_apply_planner.py` + `wifi_site_survey` API; grammar device-accepted; first association bounded persisted; not WriteCertified |

---

## 4. Captive portal — CLIENT problem (distinct from host portal)

| Direction | Field / mechanism | Status |
|---|---|---|
| **Host** — we serve guests (Coova-Chilli) | `WifiIntent.captive_portal` | Domain accepted; `Enabled` **rejected** at compile (HTTP **422** `wifi.captive_portal_unsupported`); default `Disabled` noop; safe default requires `Disabled` |
| **Client** — router joins venue Wi‑Fi with browser portal | `UplinkIntent.captive_portal_client` | **documented-only**; readiness finding `uplink_captive_portal_client_unsupported`; **no** compiler |

**Problem:** venue Wi‑Fi often requires HTTP captive login before internet. Router-as-station must complete portal **as client** — not implemented; vendor WISP facts are documentation-sourced, **not device-verified**.

---

## 5. VPN selection step

| Capability | Status |
|---|---|
| WireGuard / AWG component on **current** rebind unit | **installed** (2026-07-31 post-WG rebind #2); no Amnezia in catalogue; **no Wireguard* interfaces** currently — end state, not blocker — **NOT** hardware/model limitation |
| WireGuard / AWG profile import + bounded peer writes (sealed apply) | Sealed apply exists (prior-unit + current-unit component present); **`tunnel_healthy` DEVICE-CONFIRMED** (2026-07-31; first real handshake 2026-08-05 §M-24..§M-26); **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** (§M-24/M-27) |
| Routing traffic through VPN | **Default-route via tunnel device-verified reversible** (§M-27) — higher `ip global` priority number wins; deactivate restores prior route. **NOT claimed:** kill-switch/named policy; **`CLEAR_IP_GLOBAL` on teardown** — emitted when intent has `ip_global_*`; device-proven status per STATUS §M-38 / OPERATOR notes |
| Policy-routing grammar | **Offline preview only** (2026-08-01) — `help_verified_grammar_unapplied` planner + preview HTTP; **NOT device-verified**; see [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §2d |
| Kill-switch / policy routing when VPN down | **unresolved** — probe `ip policy permit global` **REJECTED** (`no such command: global`); kill-switch availability **unresolved**; no live apply route in repo |
| Automatic VPN selection tied to uplink mode | **not started** |

Technician selects VPN profile via operator workflow (future); field tech does **not** configure VPN on router UI. **Policy switch live apply is not available** — offline preview compiler exists (`help_verified_grammar_unapplied`); do not imply device-verified route/policy apply.

### Deployment-order dependency — connectivity ↔ component download (field-rack lesson)

**Circular dependency — HISTORICAL on current lab unit (resolved 2026-07-31):** installing WireGuard/AmneziaWG requires vendor component download (NDSS/update catalogue). **Current expendable lab unit:** wireguard component **installed**; station uplink **bounded verified persisted** (`WifiMaster1/WifiStation0`, 5 GHz WPA2). **Still valid for offline field rack shipping** — venue may arrive with no WAN and no pre-provisioned components.

| Way out | Requirement |
|---|---|
| **(1) Wired uplink** | Ethernet cable in WAN port — restores default route and NDSS |
| **(2) Upstream Wi‑Fi** | Venue SSID password + station/WISP association (bounded case verified on lab unit) |
| **(3) Pre-provision before ship** | Install vendor-download components while connectivity exists |

**Product implication:** a field rack may arrive with **no connectivity**. Any capability requiring vendor download (WireGuard component, Coova-Chilli, firmware channel refresh) must be **pre-provisioned before shipping** — do not assume on-site `components install` succeeds.

**Operational lesson:** `Components::Lister error[…] component "<name>" is unavailable` often means **no connectivity / stale catalogue** — not «hardware unsupported».

### Field ordering (before declaring online)

Required sequence — full detail in [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §4:

1. Uplink up → 2. DNS working → 3. Captive portal cleared (if any) → 4. VPN endpoint reachable via uplink → 5. Tunnel up → 6. **Only then** route/policy switch (not in repo) → 7. Verify actual egress → 8. Declare online

---

## 6. Hard rule — technician never uses admin panel

| Rule | Enforcement |
|---|---|
| No Keenetic web UI / CLI for field deployment | Product + operator docs; preset-driven configuration only |
| Management zone | AdminServer only; `hub_admin` auth for Router Control API |
| Gate posture | Live writes fail-closed until WriteCertified families certified |

---

## 7. Honest capability status table

| Capability | Status | Build lane | Live / gate |
|---|---|---|---|
| `UplinkIntent` Ethernet / LocalOnly | **implemented** | Offline | Planner supported (observe-only posture) |
| `UplinkIntent` WifiWan fields (ssid, band, credential_ref, bssid, priority) | **offline-only** | Parse/validate/canonical + sealed station compiler preview | Preset planner **unsupported** / `wifi_wan_not_certified`; no live apply HTTP |
| `UplinkIntent` Lte | **documented-only** (domain/deferred) | USB stack `usb`/`usbmodem`/`usblte`/`usbqmi`/`usbnet` **already installed** on current unit — cellular path is hardware-only; domain `Lte` compiler/planner still deferred | T4 when pursued (modem plug + live path) |
| `UplinkIntent.captive_portal_client` | **documented-only** | Readiness finding | Not supported |
| Wi‑Fi station / WISP client apply | **offline-only** | `wifi_station_rci.py` + planner/service (`grammar_verification_status=device_accepted_grammar`; preview `planned_uplink_verification_level=planned_uplink_verified_bounded` with limits); HTTP apply/teardown **delivered** — **NOT device-verified live** | Gate B + broader association scenarios before live certification claims |
| Wi‑Fi site-survey (venue SSID pick) | **offline-only** | `POST /wifi/site-survey`; `per_network_security_present: true` when parsed RCI rows include encryption data; open networks shown as `wpa_mode: open` (not joinable) | Live read requires Gate A; synthetic fake fixtures |
| Technician `#uplink` SPA (scan/enroll/preview/status) | **offline-only** | `#uplink` view: site-survey + credential enroll + `POST /wifi/station/preview` + observed-state `link_up` | HTTP apply/teardown available but **NOT device-verified live**; preset planner still `wifi_wan_not_certified` |
| Wi‑Fi station preview HTTP | **offline-only** | `POST /wifi/station/preview`; compile sealed ops; OPEN → 422 | Apply/teardown routes exist; live device verification pending |
| Captive portal client automation | **not started** | Docs/hazards first | T4 + unknown RCI |
| VPN tunnel apply (bounded test ifaces) | **tunnel_healthy + Address/ip_global + traffic DEVICE-VERIFIED** (§M-24..§M-27) | Sealed apply + 4-state tunnel honesty; first real handshake 2026-08-05; **`SET_IP_ADDRESS` + `wireguard_ip_global` accepted** | Default-route via tunnel **reversible** (§M-27); **NOT claimed:** kill-switch/named policy; **`CLEAR_IP_GLOBAL` on teardown** — emitted when intent has `ip_global_*`; device-proven status per STATUS §M-38 / OPERATOR notes; no policy-routing compiler |
| Policy-routing / kill-switch | **unresolved** | Help grammar captured 2026-07-31; `permit global` **rejected** | Open questions in discovery doc; no compiler |
| Multi-uplink failover | **not started** | Priority field models preference only | Policy routing TBD |
| LTE / USB modem uplink | **components installed; hardware-only** | `usb`/`usbmodem`/`usblte`/`usbqmi`/`usbnet` present on current unit — no download needed | Modem plug + live path **T4**; operation **not** device-verified |

---

## 8. Gap register (target − current)

| Gap ID | Description | Blocker |
|---|---|---|
| GAP-PR-01 | First association bounded (one 5 GHz WPA2); open/captive/standby/failover unverified | Gate B + live join evidence beyond bounded case; `ip global` negation unverified |
| GAP-PR-02 | WifiWan planner unsupported despite full intent | `wifi_wan_not_certified` — intentional |
| GAP-PR-03 | Captive portal client direction unsupported | Distinct from host Coova-Chilli |
| GAP-PR-04 | Same-band AP+station coupling unverified | Live hardware hazard |
| GAP-PR-05 | No policy-routing / VPN kill-switch; vendor `permit global` probe **rejected**; kill-switch **unresolved** | Grammar visibility only — [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md); design blocked on open questions |
| GAP-PR-06 | LTE/USB modem uplink — components installed; modem path unverified | USB stack present on current unit; physical modem + live path T4 |
| GAP-PR-07 | Vendor WISP documentation not device-verified | Evidence honesty |
| GAP-PR-08 | Field rack may ship offline without pre-provisioned components | **Historical on current lab unit** (WG installed 2026-07-31); still valid for field ship — pre-provision before ship; see §5 |

---

## 9. Hazards (implementers must read before station code)

1. **Management cut-off** — misconfigured station uplink can isolate router from management path.
2. **Same-band coupling** — AP rebroadcast + station client on same radio may be impossible or unstable (vendor-dependent; **unverified**).
3. **Evil-twin / wrong BSSID** — optional `bssid` pin mitigates SSID spoofing; omitting pin increases risk.
4. **DNS hijack on venue Wi‑Fi** — captive portals and venue DNS may break VPN or order-page reachability.
5. **No kill-switch / unresolved policy grammar** — vendor `ip policy permit global` probe **rejected** on firmware 5.01.C.1.0-0 (`no such command: global`); kill-switch availability **unresolved**; repo has no policy-routing compiler; VPN drop may leak traffic. See [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md).
6. **Connectivity ↔ component download** — WireGuard/AmneziaWG install needs NDSS/internet; venue Wi‑Fi path needs station + upstream credentials; field rack may ship with no WAN — pre-provision vendor components before deployment.
7. **Gate A ReadOnlyCertified** — authorized rebind #2 complete **2026-07-31** on expendable lab class; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` (rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**).

See [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.2 for ordered remediation work items.

---

## 10. Links

- Roadmap deferred lane: [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.2
- VPN connection-policy grammar (read-only): [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md)
- Domain model: [`DOMAIN_MODEL.md`](DOMAIN_MODEL.md)
- Lab policy: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)
- Project status projection: [`project-state.md`](project-state.md)
- Scenarios catalog note: [`contracts/SCENARIOS.md`](contracts/SCENARIOS.md) (SCN-PR-*)
