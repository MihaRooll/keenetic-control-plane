# Session handoff — real router lab (2026-07-31)

> **HISTORICAL narrative handoff (2026-07-31) — superseded by [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md).** Prior-unit-session methods and traps below remain useful; for the **current** session narrative, Gate A evidence pointer and live capability status read the 2026-08-02 handoff first. Post-rebind expendable unit at `192.168.2.1`: methods, evidence, assumption traps, and honest capability status for the **current physical router**. **Living policy SSOT** remains [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml) (lab class, expendable envelope, Gate posture, `next_task`, blockers) — this doc does **not** override them. Prior handoffs [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) / [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) are **historical** (prior-unit methods still useful; host-key and WG evidence from prior unit **superseded**).
>
> **Historical capability banner (2026-08-05):** living-limit rows below that cite **interface Address NOT configured**, **NOT traffic-ready**, or **station HTTP apply NOT device-verified** are **superseded** for the current unit by [`STATUS.yaml`](STATUS.yaml) + `.cursor/plans/main-decisions-local-hub.md` §M-24..§M-35. Do not treat those rows as current blockers; read STATUS for honesty markers still open (kill-switch, WriteCertified, etc.).

**Document timestamp:** 2026-07-31 (session closeout + AWG tunnel healthy confirm). Station uplink **DEVICE-VERIFIED + PERSISTED**; WireGuard component **installed**; tunnel dead-peer + **`tunnel_healthy` DEVICE-CONFIRMED** (2026-07-31 evening campaign) — see §5 and §9.

## For agents

| Topic | Rule |
|---|---|
| When to read | Before any NC-1812 live observe, bounded write, backup, or campaign prep on the **post-rebind** unit; new session after real-router work; when code behavior seems surprising after live findings |
| Methodology companion | [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) — transferable process rules (L-1..L-15); **recommended** after this handoff when you need judgement/process, not device facts; does **not** override POLICY/STATUS |
| Delivered | Post-rebind Gate A probe (rebind #1 physical replacement morning; rebind #2 post-WG identity drift afternoon); bring-up trap catalog; assumption-trap reference (AP/station counts, RCI vs CLI, component lookup, site survey JSON); Wi-Fi AP sealed path **device-verified** on `WifiMaster0/AccessPoint3` (WPA2/WPA3/mixed + compensating rollback); station WISP grammar **grammar-accepted** (acks verified); station first upstream association **uplink_verified_bounded** **+ PERSISTED** (config saved; survived reboot); WireGuard component **installed** 2026-07-31 (`wireguard`; also `wireguard-server`; no Amnezia catalogue component — not a blocker for AmneziaWG-1-shaped profiles); authorized Gate A identity-drift rebind after install moved digests to `sha256:23bd35bc…` / `sha256:c34adec…`; tunnel health observe offline + **dead-peer branch DEVICE-CONFIRMED** (revalidate-live evidence) + **`tunnel_healthy` DEVICE-CONFIRMED** (2026-07-31 evening; evidence `data/artifacts/wg-awg-real-tunnel-attempt-20260731.json`); routing/VPN policy grammar partial survey; code-honesty fixes (peer[] extraction, default-route-v1.3, rollback, idempotent re-apply, observed-state session reuse, 503→4xx client faults, WG apply honesty split, show-rc PSK scrub); baseline snapshot §8; circular-dependency note for field rack; **2026-08-01 offline-only addendum:** `source_address` propagation fixed; HTTP station apply/teardown + VPN policy-routing preview layer + teardown Gate A backup + typed OpenAPI verdict models; **2026-08-01 extended offline addendum (NOT device-verified):** `verdict_explanation` on tunnel/uplink/on-air; HTTP `/vlan|dhcp|dns|firewall/preview`; UI station apply/teardown + VPN policy preview + verdict display; unified `link_up` + topology v2.3; family-prefixed error codes (BREAKING); secret-leak scanner by write method; verdict literal runtime validation; jobs cursor paging + schema **v11** (`sealed_apply_runs` trail); hypothesis parser property tests; **2026-08-01 reliability substrate (NOT device-verified):** `sealed_apply_runs` mid-flight trail + audit; state-aware compensating rollback (wifi/station/wg); device-output parser resilience; schema-driven secret scan; closed verdict/overall/error_category literals; `grammar_doc_refs` stable anchors; hypothesis planner property tests; config UI logic tests for preview panels + uplink table + verdict display |
| Not delivered | **Full operator web UI** (`operator-web-ui-full-coverage` — all supported parameters; simple-by-default + Advanced + tooltips); VPN routing / policy-routing **live apply** (offline preview layer only); vendor kill-switch `permit global` pattern; WireGuard interface **Address** apply (no sealed op); IPv6 allow-ips; AmneziaWG 2.x (S3/S4+I1–I5 16-arg unverified); open-network station join; captive-portal station; `standby`; failover/recovery; genuine router-side Wi-Fi rejection taxonomy (only client-side failure exercised); live station HTTP apply device verification; network-family **apply** routes (VLAN/DHCP/DNS/firewall preview only); WriteCertified; Gate B/C/D open; `write_shapes_registered` |
| Superseded | [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) and [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) for **active narrative** — retain for historical methods (sealed ops, prior-unit WG/AWG T4, standing-auth 2026-07-24 context). Paste prompts [`NEW_CHAT_COLD_START_2026-07-24*.md`](NEW_CHAT_COLD_START_2026-07-24b.md) / [`NEW_CHAT_ORCHESTRATOR_HANDOFF_2026-07-24.md`](NEW_CHAT_ORCHESTRATOR_HANDOFF_2026-07-24.md) / [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md) → use [`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md) |
| SSOT | **Policy:** [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml). **Gate A evidence (current):** `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` (source `192.168.2.10`; host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY). **Superseded (pre-WG, same day):** `gate-a-probe-newrouter-192.168.2.1-20260731.json`. **Narrative companion (this doc):** session methods/traps/status only |
| Writes | Expendable envelope when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` and live tuple matches recorded identity — see POLICY §1a. Fail-closed if live device ≠ recorded tuple |
| Topology | Laptop Ethernet source `192.168.2.10` → test NC-1812 `192.168.2.1` on `192.168.2.0/24`; dual NIC → `--source-address 192.168.2.10` **mandatory** on all live CLIs |
| Secrets | Never document passwords, keys, PSK values, cookie values, raw startup-config, neighbour SSIDs, production SSID, MACs, or absolute backup paths |

---

## 1. Honest capability status (post-rebind unit)

Status markers: **device-verified** = end-to-end on unit; **grammar-accepted** = device ack'd commands, capability not proven; **blocked** = cannot proceed; **unverified** = not tested; **unresolved** = open question.

| Topic | Status | Evidence | Notes |
|---|---|---|---|
| Physical unit / Gate A | **device-verified** (identity probe) | `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` | NC-1812, fw 5.01.C.1.0-0 (panel "5.1.1"), region EA, channel Main/stable. **Rebind #1** (morning): physical device replacement. **Rebind #2** (afternoon): WireGuard install identity drift. Host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY. Source `192.168.2.10`. Prior pin SHA256:lU1D6ChV… **historical only**. Gates B/C/D **unchanged**; WriteCertified **NOT** claimed; `write_shapes_registered` **false** |
| SSH bring-up | **device-verified** (workaround) | Non-artifact operator note (STATUS `nc1812_gate_a_authorized_rebind_expendable`); cross-ref [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §6 | SSH **component present** but **service not running** (port 22 refused). Fixed via telnet:23 → `service ssh` + `system configuration save` before Gate A probe. Web panel lists ports 22/23/80/443 as management — **not** service on/off indicators |
| Component vs browser UI | **device-verified** (instrument trust) | `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` (`component_set_digest`) | Browser agent may show "already installed"; trust **instruments** (`component_set_digest` byte-identical), not panel/agent claims alone |
| Wi-Fi AP sealed path | **device-verified** | `data/artifacts/wifi-sealed-path-live-gate-a-20260731.json` | `WifiMaster0/AccessPoint3`: WPA2, WPA3, WPA2/WPA3-mixed applied with readback/comparison; torn down; backup taken; baseline restored. Idempotent re-apply skips satisfied ops but **never** skips PSK op. Compensating rollback preserves original error + rollback outcome. **Limit:** router-rejection taxonomy exercised via **client-side** failure only — not genuine router rejection |
| Station (WISP) grammar | **grammar-accepted** | `data/artifacts/station-wisp-grammar-probe-20260731.json` | Acks: `ssid`→"SSID saved.", `authentication wpa-psk`→"WPA PSK set.", `encryption enable`, `encryption wpa2`, `ip address dhcp`, `up`/`down`, all negation forms. Resolved: encryption **not** required for PSK acceptance; DHCP **not** required for admin up |
| Station first association (bounded) | **uplink_verified_bounded** + **PERSISTED** | `data/artifacts/station-wisp-upstream-uplink-first-association-20260731.json`; backup `data/backups/startup-192.168.2.1-20260731T165628Z-0a63d9f3.dpapi` | **2026-07-31:** `WifiMaster1/WifiStation0` (5 GHz) WPA2 upstream join succeeded; **encryption enable + wpa2 REQUIRED for association** (without → fail: survey-no-bss; PSK accepted without encryption); DHCP yes; `ip global 600`; default route after ~20–30s settle; `show internet status` internet/gateway/DNS yes (no general CLI `ping`); **config SAVED; survived reboot**. On associated station `auth-type` **STAYS `none`** — never use as security/assoc signal. **Limits:** one network; 5 GHz WPA2 only; open/captive/standby/failover unverified; preset `wifi_wan_not_certified` unchanged. **HTTP:** `POST /wifi/station/apply` + `/wifi/station/teardown` **delivered** (confirm-gated, Gate A backup on live apply) — **NOT device-verified on live unit in this delivery** (offline fake + unit tests only). **SECURITY:** `show rc interface` prints PSK plaintext — scrubbed at ingest including error paths |
| Station association / uplink (general) | **uplink_verified_bounded** (one case) | see first-association row | Not a general WriteCertified / multi-scenario certification |
| WireGuard / AWG | **dead-peer + `tunnel_healthy` DEVICE-CONFIRMED** | `data/artifacts/wg-awg-real-tunnel-attempt-20260731.json` (healthy); `data/artifacts/wg-tunnel-health-dead-peer-revalidate-live-20260731.json` (dead-peer) | WG component `wireguard` + `wireguard-server` installed 2026-07-31; plain `wireguard` ASC-9 **ACCEPTED**; Amnezia catalogue absence **NOT a blocker** for AmneziaWG-1-shaped profiles. **Healthy (2026-07-31 evening):** `Wireguard5` via product web API; first readback `tunnel_never_handshaked`; ~25s settle → `tunnel_healthy`; `peer.last-handshake: 28`, `peer.online: true`, `rxbytes: 92`. **Dead-peer:** revalidate-live ~28.6s settle. Interface Address **NOT configured**; routing/kill-switch/IPv6 **NOT done**. WriteCertified **NOT** claimed |
| Port / link survey | **device-verified** | `data/artifacts/vpn-connection-policy-help-20260731/FINAL-REPORT-sanitized.json` §2a (WAN link DOWN) | Only **one** Ethernet port has link (LAN management) — not a wrong-socket issue |
| Routing/VPN policy grammar | **partial offline** / **unresolved kill-switch** | `data/artifacts/vpn-connection-policy-help-20260731/FINAL-REPORT-sanitized.json`; offline `vpn_policy_*` + preview HTTP (2026-08-01) | Device help verified: `ip global ({priority}\|order {order}\|auto)`; `ip policy {name}`; DNS `name-server …`; ping-check; segment `ip hotspot policy …`. Offline planner `help_verified_grammar_unapplied` + `POST /vpn/policy-routing/preview` — **NOT device-verified**; **no apply route**. **`permit global` REJECTED** (`no such command: global`) — kill-switch **unresolved** |
| USB cellular components | **device-verified** (installed) | `data/artifacts/vpn-connection-policy-help-20260731/FINAL-REPORT-sanitized.json` §2a side finding | `usb`, `usbmodem`, `usblte`, `usbqmi`, `usbnet` installed — cellular path needs hardware only; modem operation **not** device-verified |
| Code: Wi-Fi apply stack | **device-verified** (behaviors) | Live campaigns + tests | Compensating rollback, router error taxonomy, idempotent re-apply added after live findings |
| Code: observed-state endpoint | **device-verified** (fix) | Live mode session | Was 503 in live mode — now reuses same live session as apply |
| Code: client fault mapping | **device-verified** (fix) | Tests | Client-side faults reclassified 503→4xx where appropriate |
| Code: `/wireguard/apply` honesty | **device-verified observe path** | [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md); evidence `data/artifacts/wg-awg-real-tunnel-attempt-20260731.json` | Splits configuration-accepted / interface admin / tunnel (`tunnel_no_peer` \| `tunnel_never_handshaked` \| `tunnel_healthy` \| `tunnel_unverified` from `show interface` peer fields — NOT `show rc`); dead-peer + **`tunnel_healthy` DEVICE-CONFIRMED** 2026-07-31; config+iface-up **never** imply egress via VPN; interface Address **NOT configured** |

---

## 2. Assumption traps (device facts — read before guessing)

These burned time on the post-rebind unit. Treat as **hard constraints** until re-proven on a future tuple.

### 2.1 Wi‑Fi inventory

| Trap | Reality |
|---|---|
| AP indices | `AccessPoint0`–`AccessPoint6` **per radio** — **not** 0–9. AP0 = production Wi‑Fi; AP1 = guest |
| Station objects | Only `WifiMaster0/WifiStation0` and `WifiMaster1/WifiStation0` |
| `connected: true` on AP | **≠ on air** — AP can show connected while `link` is down |
| `auth-type` on interface readback | **NOT** WPA/security or association indicator — on associated station **STAYS `none`**; use `encryption`, `link`, `connected`, `state`, `ssid`; site-survey uses `mode`/`channel`/`rssi` |
| CLI connectivity check | No general `ping` — use `show internet status` (internet/gateway/dns/captive-accessible) |
| `show rc interface` secrets | Plaintext PSK may appear — product scrubs at ingest; never log/serialize raw show-rc |

### 2.2 Components and RCI

| Trap | Reality |
|---|---|
| Component list shape | `{id, version}` — **no** `installed` field. Lookup `component.ssh.installed` → **false negative** |
| Site survey | RCI returns `parse.ap_cell` **JSON**, not tabular CLI. Mode in `ieee`; `mode` key = BSS role (always "Master" in survey). JSON includes `encryption` (tabular lacks it) |

### 2.3 Interface / config reads

| Trap | Reality |
|---|---|
| Station SSID location | Configured SSID in `show rc interface`; `show interface` ssid = **ASSOCIATED** (empty if not associated) |
| Missing commands | No `show ipv4 route` → use `show ip route`. No `show running-config interface` → use `show rc interface` |

### 2.4 CLI interaction

| Trap | Reality |
|---|---|
| `command ?` + Enter | Shows help **then executes bare command**. Safe: partial + `?` **without** Enter, then Ctrl-C / Ctrl-U |
| SSH prompt | ANSI `\x1b[K` after prompt breaks naive string matching |

---

## 3. Wi‑Fi AP path (device-verified 2026-07-31)

Bounded test AP `WifiMaster0/AccessPoint3` under expendable envelope:

1. Pre-change backup to `data/backups/`.
2. Applied WPA2, WPA3, WPA2/WPA3-mixed with correct readback/comparison.
3. Full teardown; baseline restored.
4. Idempotent re-apply: skips ops already satisfied; **PSK op never skipped**.
5. Compensating rollback: on partial failure, rollback runs; original error + rollback outcome both preserved.

Evidence: `data/artifacts/wifi-sealed-path-live-gate-a-20260731.json`.

**Honest limit:** rejection taxonomy in code was exercised through **injected client-side** failure paths — not confirmed against genuine router reject responses.

Prior-unit Wi-Fi/AWG sealed-op history: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) §6–§14.

---

## 4. Station (WISP) — grammar-accepted + first association bounded (2026-07-31)

Grammar probe on station interfaces — commands **accepted with acks** on `WifiMaster0/WifiStation0`.

| Command family | Ack observed |
|---|---|
| `ssid …` | "SSID saved." |
| `authentication wpa-psk` | "WPA PSK set." |
| `encryption enable` / `encryption wpa2` | accepted |
| `ip address dhcp` | accepted |
| `up` / `down` + negations | accepted |

**Grammar-probe resolved misconceptions:** encryption **not** required before PSK acceptance; DHCP **not** required before admin `up`.

Evidence: `data/artifacts/station-wisp-grammar-probe-20260731.json`.

### First upstream association (bounded — 2026-07-31)

| Item | Result |
|---|---|
| Interface | `WifiMaster1/WifiStation0` (5 GHz) |
| Security | WPA2 — **`encryption enable` + `encryption wpa2` required for association** (device accepts PSK without them but will not join) |
| IPv4 | DHCP acquired |
| Uplink priority | `ip global 600` device-exercised on station |
| Default route | Appeared after **~20–30s settle** — verify with bounded wait-and-recheck of `show ip route` |
| Internet check | `show internet status`: internet/gateway/DNS yes — **no general CLI `ping`** |
| Persistence | `system configuration save` performed; **survived reboot** |
| Evidence | `data/artifacts/station-wisp-upstream-uplink-first-association-20260731.json` |
| Backup | `data/backups/startup-192.168.2.1-20260731T165628Z-0a63d9f3.dpapi` |

**Honest limits (`uplink_verified_bounded`):** one upstream network; 5 GHz WPA2 only; open/captive/standby/failover/multi-uplink **unverified**; preset planner **`wifi_wan_not_certified`** unchanged; **HTTP** `POST /wifi/station/apply` + `/wifi/station/teardown` **delivered** (confirm-gated; offline fake + unit tests) — **NOT device-verified on live unit**; WireGuard `ip global` still unexercised.

**Product:** offline compiler `planned_uplink_verification_level=planned_uplink_verified_bounded`; show-rc PSK scrub at ingest in `readback_wifi_station_state`.

---

## 5. WireGuard / AWG (component installed — dead-peer + tunnel_healthy DEVICE-CONFIRMED)

On the **current** post-rebind unit (2026-07-31):

| Item | Status |
|---|---|
| Connectivity blocker | **Resolved** — station uplink restored and **persisted**; prior phase-1 failure was no internet / NDSS unreachable, **not** hardware limitation |
| Component | **`wireguard` + `wireguard-server` installed** (no Amnezia catalogue component — **NOT a blocker** for AmneziaWG-1-shaped profiles on plain `wireguard`; ASC-9 via `wireguard_set_asc` → `Wireguard::Interface` **ACCEPTED**) — vendor catalogue required internet; reboot ~87s |
| Tuple | Firmware **unchanged** `5.01.C.1.0-0`; SSH host key **UNCHANGED** `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`; **authorized Gate A identity-drift rebind #2** after install — current digests `sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80` / `sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd` |
| Backups (apply campaign) | Pre-write `data/backups/startup-192.168.2.1-20260731T195344Z-93820572.dpapi`; apply callback `…T195500Z-0e7139ea.dpapi` |
| Tunnel health vocab | `tunnel_no_peer` \| `tunnel_never_handshaked` \| `tunnel_healthy` \| `tunnel_unverified`; INT_MAX `last-handshake==2147483647` = never |
| Dead-peer (DEVICE-CONFIRMED) | Revalidate-live: `overall=applied`, `tunnel_verification_status=tunnel_never_handshaked`, peer key = test peer (not iface own key), ~28.6s settle; evidence `data/artifacts/wg-tunnel-health-dead-peer-revalidate-live-20260731.json` |
| **`tunnel_healthy` (DEVICE-CONFIRMED)** | **2026-07-31 evening:** real AmneziaWG-shaped profile on expendable lab `Wireguard5` via product web API; first readback `tunnel_never_handshaked`; after ~25s settle recheck → `tunnel_healthy`; observed `peer.last-handshake: 28` (NOT 2147483647), `peer.online: true`, `peer.rxbytes: 92`, `peer.txbytes: 491`, `state/link up`, `peer_via: WifiMaster1/WifiStation0`; ASC-9 args (obfuscation ints, NOT secrets): `4 10 50 130 69 149835824 1778159739 1704282148 748462068`; secrets via `credential_ref` only; evidence `data/artifacts/wg-awg-real-tunnel-attempt-20260731.json` (endpoint scrubbed); teardown `overall=applied`, `interface_absent`; known-rejected `wireguard_clear_private_key` failed but removal cleaned up; uplink/internet/default route/production Wi-Fi survived |
| Rejected false positives | `wireguard.status:up`, iface `state:up`, `peer.enabled`, growing `peer.txbytes` — all observed on **dead** tunnel |
| Interface Address | **NOT configured** by product apply — `interface_address_verification_status=interface_address_not_configured`; tunnel handshake ≠ usable VPN traffic routing |
| Teardown | Overall reflects achieved end state (`interface_absent`) while showing rejected `wireguard_clear_private_key` step |
| Routing / policy | **Offline preview only** — live apply/kill-switch/egress **NOT done**; see §6 and [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §2d |

**For agents:**

- **Known:** component present; dead-peer + **`tunnel_healthy` branches device-confirmed**; bounded settle-recheck design correct; config+interface-up **never** imply egress via VPN; readback path is **`show interface` only** (NOT `show rc`); read **`wireguard.peer[]`** only for peer key (not iface `public-key`); interface Address **not applied**.
- **NOT known / not delivered:** routing traffic through VPN; kill-switch; IPv6 allow-ips; interface address apply; AmneziaWG 2.x; WriteCertified; `write_shapes_registered=true`; Gates B/C/D open.
- **Prior physical unit** (pre-rebind) had live WG/AWG T4 write evidence — see [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md). Do **not** assume current unit matches prior-unit tunnel state without fresh observe.

STATUS: blocker resolved; reviews `nc1812_wg_component_installed_20260731`, `nc1812_wg_tunnel_health_observe_offline_20260731`, `nc1812_wg_tunnel_health_live_peer_extraction_defect_20260731`.

---

## 6. Routing / VPN policy grammar (partial offline; kill-switch unresolved)

Device help **verified on unit** (2026-07-31) for:

- `ip global ({priority}|order {order}|auto)` at interface scope
- `ip policy {name}`
- DNS: `name-server {address} [{domain} [on {interface}]]`
- `ping-check profile {name}` — pre-existing profile `default`
- Segment binding: `ip hotspot policy {interface} (permit|deny|{policy})`

**Rejected / unresolved:**

- `permit global` → `no such command: global` — vendor documentation kill-switch pattern **not confirmed** on this firmware; treat as **unresolved** open question.

**Offline product layer (2026-08-01 — NOT device-verified):**

- Code: `vpn_policy_rci.py`, `vpn_policy_probe.py`, `vpn_policy_routing_planner.py`, `vpn_policy_routing_service.py`
- HTTP: `POST /api/router-control/v1/vpn/policy-routing/preview` only — **no apply/dispatch route**
- Planner `verification_status`: **`help_verified_grammar_unapplied`**
- Read parsers for `show ip policy` / `show ip name-server` with honest unknowns
- WG interface **Address** still **NOT configured**; kill-switch **unresolved**; IPv6 allow-ips refused offline

Record any new probes in `data/artifacts/` with sanitized output.

---

## 7. Why the code looks this way (post-live honesty fixes)

| Area | Change | Trigger |
|---|---|---|
| Wi-Fi apply | Compensating rollback, router error taxonomy, idempotent re-apply | Live partial-failure behavior on AP3 |
| Observed-state API | Reuses same live session as apply (was 503 in live mode) | Live session mismatch |
| HTTP errors | Client-side faults 503→4xx where appropriate | Misleading status codes |
| `/wireguard/apply` | Split `configuration_verification_status` / `interface_verification_status` / `tunnel_verification_status` (4-state from `show interface` **`wireguard.peer[]`**; iface `public-key` not peer; NOT `show rc`); optional `handshake_settle_seconds` on apply body | Live peer-extraction defect + settle API gap |
| Default-route probe | `default-route-v1.3` — bare `0.0.0.0/0` via station uplink without `type`/`state` | Live misclassified as `no_default_route` |
| Show-rc PSK scrub | Token regression test; scrub at ingest including error paths (exception chaining suppressed) | `show rc interface` prints PSK plaintext on device |
| `open_pinned_rci_transport` + `source_address` | **Fixed offline 2026-08-01** — propagates validated `source_address` onto tunnel config and transport | Prior live revalidate constructed transport explicitly |
| Gate A backup on teardown | **Added 2026-08-01** for `/wifi/teardown` and `/wireguard/teardown` (previously apply-only) | Parity with apply safety |
| AP on-air honesty | `on_air_verification_status` separates admin-up from on-air (`resolve_link_up` → `parse_up_down_flag` on `link` only; `parse_broadcast_flag` on broadcast; `resolve_on_air_signal` for apply verdicts); **`overall=applied` = config delivered** — link/broadcast conflict → `on_air_unverified` not `verify_mismatch` | Live trap: `connected:true` + `link:down`; no live evidence of `broadcast:true` + `link:false`; fixtures/artifacts use string `up`/`down`/`enabled` only — no int `link` |
| Station preview honesty | Preview returns `planned_uplink_verification_level` — not runtime uplink verdict | Avoid false runtime claims |
| Topology v2.3 | `link_up` from shared `parse_up_down_flag` on `link` only — `connected` independent; present-but-unparseable link → interface kept, `link_up: null`, uncertainty | Correlation no longer treats `connected` as uplink active; topology gate aligned with Wi-Fi helpers (2026-08-01) |

Details: [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md), [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

---

## 8. Baseline state (current live end state)

**As of session closeout 2026-07-31** — persisted on device.

| Item | State |
|---|---|
| Internet / default route | **ONLINE** via Wi‑Fi station uplink `WifiMaster1/WifiStation0` (5 GHz); default route via station after `ip global 600` |
| Wired ISP | `GigabitEthernet1`/`ISP` (`global: yes`, `priority: 700`) — link **DOWN** (cable connected would take precedence over station) |
| WireGuard component | **Installed** (`wireguard`, `wireguard-server`; no Amnezia) |
| WireGuard interfaces | **None** (`Wireguard*` absent — last bounded campaign torn down) |
| Production / guest Wi‑Fi | **Untouched** (AP0 production, AP1 guest) |
| USB modem stack | Components installed (`usb`, `usbmodem`, `usblte`, `usbqmi`, `usbnet`) — needs hardware for cellular path |
| Gate A | **ReadOnlyCertified** on post-install tuple; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` |

Restore baseline after bounded campaigns; expendable envelope still expects evidence + rollback discipline.

---

## 9. Open items (honest — not delivered)

| Item | Status | Notes |
|---|---|---|
| VPN routing / policy-routing **live apply** | **NOT delivered** | Offline preview layer delivered 2026-08-01 (`help_verified_grammar_unapplied`; `POST /vpn/policy-routing/preview`); **NOT device-verified**; no apply/dispatch route; egress via VPN unverified |
| WireGuard interface **Address** apply | **NOT implemented** | No sealed interface-address op; `interface_address_not_configured` on apply |
| IPv6 allow-ips | **refused offline** | Explicit refusal naming unsupported entry; no device grammar verified |
| AmneziaWG 2.x (S3/S4+I1–I5, 16-arg) | **NOT device-verified** | ASC-9 only on expendable lab |
| Open-network station join | **unverified** | No verified CLI grammar |
| Captive-portal station | **unsupported** / unverified | Not exercised |
| Kill-switch / `permit global` | **unresolved** | Device rejects `permit global` — vendor pattern not confirmed |
| `standby` station mode | **unverified** | Not tested |
| Failover / multi-uplink / recovery | **unverified** | Single upstream network only |
| Live station apply device verification (HTTP) | **NOT device-verified live** | `POST /wifi/station/apply` + `/wifi/station/teardown` **delivered offline 2026-08-01** (confirm-gated, Gate A backup on apply **and** teardown); UI station apply/teardown panel — **NOT device-verified**; first association was CLI/manual 2026-07-31 |
| Network-family preview (VLAN/DHCP/DNS/firewall) | **NOT device-verified** | `POST /vlan/preview`, `/dhcp/preview`, `/dns/preview`, `/firewall/preview` delivered offline 2026-08-01; `verification_status=offline_unverified`; **no apply routes** |
| Verdict explanation (tunnel/uplink/on-air) | **NOT device-verified** | Machine-readable `verdict_explanation` on apply/teardown responses + UI render — offline/fake tests only |
| Sealed apply mid-flight trail + audit | **NOT device-verified** | `sealed_apply_runs` durable trail (lease, ops_pending/dispatched, 503 `sealed_apply.trail_begin_failed`, startup orphan `Interrupted`, `list_unfinished_sealed_applies`); sealed apply audit on success/failure/exception with redacted intent + trail snapshot — **no** automatic resume/rollback |
| State-aware compensating rollback (wifi/station/wg) | **NOT device-verified live (HTTP)** | Pre-apply baseline read (timeout-bound); rollback only foreign state; `rollback_errors` separate; `rollback.uncovered_ops` — Wi-Fi AP compensating rollback **device-verified** on AP3 2026-07-31 only |
| Device-output parser resilience | **NOT device-verified (new paths)** | Components `{id,version}` list; read-path encoding corruption fail-closed; write-path strict; handshake INT_MAX never-only; zero hold-time → unverified — prior tunnel/uplink device evidence unchanged |
| Schema-driven secret scan | **NOT device-verified** | `_SECRET_SCAN_TABLES` + `secret_scan_table_columns` from PRAGMA; guard test `test_secret_scan_columns_match_live_schema` |
| Closed verdict/overall/error_category literals | **NOT device-verified** | `apply_response_models.py` Literal enums; HTTP 200 vs `overall` documented API_CONTRACT §13.2.1; UI overall-first toasts |
| Grammar registry stable anchors | **NOT device-verified** | `grammar_doc_refs.py` per-op citations all planner families; property tests in `test_planner_properties.py` |
| Property tests (planners + parsers + UI logic) | **NOT device-verified** | `test_planner_properties.py`, `test_parser_properties.py`, `test_config_ui.py` preview/uplink/verdict contracts |
| Error code family prefixes | **BREAKING (API)** | HTTP `error.code` parity: `wifi.*`, `wifi.station.*`, `wireguard.*` — see [`API_CONTRACT.md`](contracts/API_CONTRACT.md) §13.4–§13.7 |
| Full operator web UI (all configurable parameters) | **NOT delivered** | Next major phase `operator-web-ui-full-coverage` — simple-by-default forms, Advanced settings expander, tooltips, UI contract tests; see §10 |
| Offline verify baseline green | **closed (code)** | pytest **3196 passed / 2 skipped** (exit **0**); ruff exit **0**; mypy exit **0** (**112** files) — re-measured 2026-08-01 docs audit; not a gate change |
| WriteCertified / Gate B/C/D | **NOT claimed / closed** | `write_shapes_registered` **false** |

---

## 10. What to do next (ordered by value)

1. **Full operator web UI (`operator-web-ui-full-coverage`)** — next major phase per [`STATUS.yaml`](STATUS.yaml) `next_task`: **«simple by default, full on demand»** for **all** parameters the project can configure. Default UX: minimal happy-path only (example — Wi-Fi create: SSID + password + band; sealed planner/service + confirm/connection wiring automatic). **Advanced settings** expander on every screen exposes every supported parameter; **tooltips** on all fields (purpose, defaults, device-verified vs offline-only). Coverage rule: backend-configurable parameter → UI surface (simple or advanced). Autonomous verification via `tests/test_config_ui.py` (+ optional browser-verify) — **NOT device-verified** until live campaigns. See [`OPERATOR_UI.md`](OPERATOR_UI.md) and [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.3.
2. **VPN routing / policy-routing live apply** (parallel deferred) — offline preview layer + UI panel delivered 2026-08-01 (`help_verified_grammar_unapplied`); kill-switch `permit global` **unresolved**; interface Address NOT configured; IPv6 refused offline; **`tunnel_healthy` + dead-peer already DEVICE-CONFIRMED** (2026-07-31; tunnel NOT traffic-ready).
3. **Live station HTTP apply verification** (optional) — routes + UI delivered offline 2026-08-01; bounded live device verification on expendable unit still open; open/captive/standby remain out of scope.
4. **Network-family apply routes** (VLAN/DHCP/DNS/firewall) — preview-only HTTP delivered 2026-08-01; Gate B family certification + apply routes still BLOCKED.
5. **Gate B / `write_shapes_registered` formalization** — BLOCKED (not WriteCertified; registries empty).
6. **Pre-provision WG packages before field rack ship** — see §11 circular dependency.

Do **not** reopen stale priorities (offline SSH fail-safe T4 as primary; in-flight station campaign — **complete**; `source_address` propagation — **fixed offline 2026-08-01**).

---

## 11. Circular dependency (field rack)

```
Install WG component  →  needs internet  →  vendor download
Venue Wi‑Fi internet  →  needs station path + upstream credentials
Field rack may ship    →  zero connectivity at venue
```

**Implication:** pre-provision vendor component packages **before shipping** a portable rack with no wired WAN. See [`SCENARIO_PORTABLE_EQUIPMENT_RACK.md`](SCENARIO_PORTABLE_EQUIPMENT_RACK.md).

---

## 12. Ops for next agent

### Lab access

- Wired path: host `192.168.2.10` → router `192.168.2.1`.
- Always pin host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY before live observe.
- Credentials: **`credential_ref` only** — see [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md), [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md). Never paste secrets into chat or docs.

### Environment

- PowerShell env vars **do not persist** between invocations — set env in the **same command** that launches the host process (e.g. `$env:RC_ADAPTER_MODE='live'; py -3.11 -m uvicorn …`).
- Hub-admin DPAPI blob is **ASCII-hex** encoding.

### Verification baseline (offline, at handoff — refreshed 2026-08-01 SSOT sync)

| Command | Expected (2026-08-01 measured) |
|---|---|
| `py -3.11 -m pytest --timeout=60 --timeout-method=thread -q` | **3196 passed, 2 skipped**; exit **0** |
| `py -3.11 -m ruff check .` | exit **0** |
| `py -3.11 -m mypy router_control` | exit **0** (**112** source files) |
| `py -3.11 scripts/export-openapi.py` (twice) | no drift; exit **0** |
| SQLite schema | `CURRENT_USER_VERSION=11` (`router_control/persistence/migrations.py`; migrations v9–v11 = `sealed_apply_runs` trail) |
| `scripts/validate-project-docs.ps1` | exit 0 (`DOCS_VALIDATE_PASS`) — run after doc sync |
| `py -3.11 scripts/project-docs.py audit --project-root .` | exit 0 (`PROJECT_DOCS_AUDIT_PASS`; WARN only for `templates/*` seed copies — intentional) |
| `py -3.11 -m pytest tests/test_project_docs.py --timeout=60 --timeout-method=thread -q` | exit 0 — run after doc sync |

### Safety

- Live device ≠ recorded tuple → **fail-closed** for writes.
- Do **not** open Gates B/C/D or claim WriteCertified.
- Station uplink is **persisted** — bounded campaigns must preserve or explicitly restore baseline.

### Paste prompt for new chat

[`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-01.md)

---

## 13. Related docs

| Doc | Role |
|---|---|
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Living lab policy SSOT (expendable envelope, Gate A rebind) |
| [`STATUS.yaml`](STATUS.yaml) | Machine-readable phase, gates, blockers, `next_task` |
| [`gate-a-certification.json`](gate-a-certification.json) | Gate A certification constants |
| [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) | Gate A operator procedures |
| [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md) | Wi-Fi apply operator guide |
| [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md) | AWG apply (prior-unit live evidence) |
| [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) | Historical — prior unit methods, sealed ops, T4 campaigns |
| [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) | Historical — P1–P3, network migration, fail-safe trials |
| [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) | **Methodology companion** — transferable lab judgement (L-1..L-15); cross-refs this handoff for facts; does not override POLICY/STATUS |

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | docs-audit-ssot-sync-20260801 |
| paths | docs/STATUS.yaml, docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md, docs/project-state.md, docs/docs-map.json, docs/contracts/ROADMAP.md, docs/contracts/API_CONTRACT.md, docs/contracts/AI_HANDOFF.md, docs/gate-a-certification.json, docs/OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md, README.md |
| map_entries | STATUS, project-state, SESSION_HANDOFF 2026-07-31, ROADMAP, API_CONTRACT, AI_HANDOFF, gate-a-certification, OPERATOR_WEB_UI_FULL_COVERAGE_PLAN, README |
| notes | Independent docs audit SSOT sync: verify baseline green (3196/2/0, ruff 0, mypy 112); AI_HANDOFF §4 tunnel_healthy + prototype UI; TrafficDiscovery HTTP+UI; cold-start order unified with AGENTS.md; gate-a nested gates SSOT note; orchestrator prompt link; UI plan sizes approximate; gates unchanged; NOT device-verified |
