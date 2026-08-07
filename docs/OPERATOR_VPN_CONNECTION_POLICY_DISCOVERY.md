# Operator runbook — VPN connection-policy grammar (read-only help/show)

## For agents

| Topic | Rule |
|---|---|
| When to read | Before designing policy-routing, kill-switch, DNS-on-interface, ping-check, or field VPN ordering for portable rack / technician workflows |
| Scope | **READ-ONLY OBSERVED** help/`show` grammar visibility on Gate A ReadOnlyCertified expendable lab — **NOT** functional proof; **no intentional mutation** |
| Firmware / tuple | NC-1812, firmware `5.01.C.1.0-0`, Gate A ReadOnlyCertified expendable class (authorized rebind **2026-07-31**) |
| Evidence | [`data/artifacts/vpn-connection-policy-help-20260731/`](../data/artifacts/vpn-connection-policy-help-20260731/) — SSOT: `FINAL-REPORT-sanitized.json` |
| Gates | A ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified**; `write_shapes_registered` remains **false** |
| Kill-switch | Vendor `permit global` pattern **REJECTED** on this firmware — **unresolved**; do **not** assume policy kill-switch available |
| No Wireguard* inventory | **Current rebind unit:** `wireguard` component **installed** (2026-07-31); post-WG Gate A identity-drift rebind #2. VPN-policy probe inventory had **no** `Wireguard*` objects (**pre-install snapshot** — §2a **historical**). **NOT** hardware capability denial — prior physical unit had live WG/AWG write evidence |
| Component unavailable lesson | `Components::Lister error[24248621] component "<name>" is unavailable` can mean **no connectivity / stale catalogue** — not «unsupported» |
| CLI hazard | `command ?` + Enter shows help **then executes** command without `?` — see §6; safe technique: partial command + `?` **without** CR, then Ctrl-C/Ctrl-U |
| Next | Offline `vpn_policy_*` planner/RCI layer + read allowlist exist (help-verified grammar only); **NOT** device-verified / **NOT** WriteCertified; kill-switch still **unresolved** (§5 open questions) |

---

## 1. Purpose

Per-feature **grammar visibility** discovery for VPN-related connection-policy, interface `ip global`, Hotspot policy binding, DNS, and ping-check on the exact Gate A tuple. Live help/`show` confirms **CLI templates exist in help text** — it does **not** register write shapes, prove routing works, claim WriteCertified, or open Gates B/C/D.

Discovery is **classification only** — help visibility ≠ functional verification.

---

## 2. Evidence summary (2026-07-31)

| Item | Observation |
|---|---|
| Artifact dir | `data/artifacts/vpn-connection-policy-help-20260731/` |
| FINAL report | `FINAL-REPORT-sanitized.json` |
| Contract flags | `mutation_performed_intentional=false`, `no_intentional_config_change=true` |
| Host key | Pinned OK — Gate A rebind expendable class |
| Later sessions | Partial text + `?` without CR + Ctrl-C/Ctrl-U clear; contexts entered for help only and exited |

**Accidental ?+Enter quirk (session 1):** documented in FINAL report — see §6.

---

## 2a. Lab connectivity blocker — WG component install (2026-07-31) — **HISTORICAL / RESOLVED**

> **ARCHAEOLOGY ONLY — pre-install connectivity blocker (same day, before WG install succeeded).** WireGuard component **installed** on current expendable rebind unit later **2026-07-31** (post-WG Gate A rebind #2). **No Wireguard* interfaces** may still be true as end state — not a missing-component claim. For current tuple see [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md).

Attempt to install WireGuard/AmneziaWG on expendable rebind unit (`NC-1812`, firmware `5.01.C.1.0-0`, Gate A ReadOnlyCertified) stopped at **phase-1 with NO mutation**. This was a **lab connectivity blocker at probe time**, **not** a conclusion that hardware cannot run WireGuard (prior physical unit at this management address had live WG/AWG write evidence).

| Symptom | Exact observation |
|---|---|
| Create interface | `Wireguard5` rejected: `unsupported interface type: "Wireguard"` (likewise `AmneziaWG`) |
| Installed components | **NO** `wireguard` / `amneziawg` entry in installed set |
| `components list stable` | Returns only already-installed set; ends `Core::Ndss error[9240615]: [18026] no registered connection.` |
| `install wireguard` / `install amneziawg` / `install awg` | Each `Components::Lister error[24248621]: component "<name>" is unavailable.` |
| Root cause | **No internet** — WAN `GigabitEthernet1` (`ISP`) link **DOWN**; **NO** default route; Keenetic update service (NDSS) unreachable; component catalogue cannot refresh |

**Proof no mutation:** no `components commit`; no rebuild; no reboot. Gate A tuple at probe time: host key `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`; firmware `5.01.C.1.0-0`; `component_set_digest` `sha256:91145a8284d142729b93bb0fd549312134dd669ef7b07f4d2207d2b6a22dd83b` (**superseded** — current post-WG digest `sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80`).

**Backups (pre-probe):** `data/backups/startup-192.168.2.1-20260731T155720Z-dfa1a3d2.dpapi`; `data/backups/startup-192.168.2.1-20260731T161438Z-e35d13d6.dpapi`.

**Side finding (USB cellular stack):** installed components already include `usb`, `usbmodem`, `usblte`, `usbqmi`, `usbnet` — cellular/USB-modem uplink needs **no** component download/reboot; only physical modem. Modem operation **NOT** device-verified; no modem iface objects without modem plugged in.

**Interpretation (historical probe only):** at **pre-install** probe time, absence of `Wireguard*` objects reflected **missing component + no connectivity** — not NC-1812 model lack of WireGuard support. **Current unit:** wireguard component **installed**; inventory may still show no `Wireguard*` interfaces until configured.

---

## 2b. READ-ONLY OBSERVED grammar (verified-from-help)

Gate A ReadOnlyCertified expendable class (`NC-1812`, firmware **5.01.C.1.0-0**, **2026-07-31**). Templates quoted from FINAL-REPORT capture only — **NOT** device-certified write grammar.

### Interface `ip global` (internet source)

| Topic | Observation |
|---|---|
| Status | **VERIFIED-FROM-HELP** on `GigabitEthernet1` / `ISP` |
| Template | `ip global ({priority} \| (order {order}) \| auto)` |
| Help keyword | `global` — set global interface(s) |
| WireGuard form | **`ip global` on WireGuard DEVICE-VERIFIED** (2026-08-05, §M-24/M-27): `wireguard_ip_global` accepted; **higher NDMS `ip global` number wins**; traffic via tunnel reversible via activate `ip_global_priority` + deactivate — kill-switch / named policy still open |

### Top-level connection policy

| Topic | Observation |
|---|---|
| Create | `ip policy {name}` |
| Delete | `no ip policy {name}` |
| Show | `show ip policy` — **empty** (no policies) |
| Interior (reserved-name probe) | Probe via reserved name `permit`: help listed **only** `ipv6`, `route` — **UNKNOWN function** |
| `show rc ip policy` | **Rejected** — `no such command: policy` |

### `ip policy permit global` — REJECTED (kill-switch unresolved)

| Topic | Observation |
|---|---|
| Command | `ip policy permit global` |
| Result | `Command::Base error[7405600]: no such command: global.` |
| Policy-context help | Via reserved name `permit`: only `ipv6` and `route` — **no** `permit`/`global` chooser |
| Conclusion | Vendor kill-switch pattern (`permit global` inside policy) **NOT confirmed** / **unresolved** on this firmware |

### Hotspot policy binding

| Topic | Observation |
|---|---|
| Template | `policy {interface} ({access} \| {policy})` |
| Zero policies | After `interface Home` Choose showed **`Home permit`**, **`Home deny`** only |
| Default policy | `default-policy ({access} \| {policy})` — Choose: `permit` \| `deny` |
| Host binding | `host {mac}` |
| Named policy path | Template mentions `{policy}` — named policies likely appear once created — **unverified** with zero policies |
| Baseline read | `show rc ip hotspot`: `policy interface Home access permit`; `auto-register disable: no` |

### DNS

| Topic | Observation |
|---|---|
| Config level | `ip name-server {address[:port]} [{domain} [on {interface}]]` |
| Interface level | `name-server {name-server[:port]}`; `ip name-servers` — enable name servers obtained through ip interface (no further args in safe help) |
| Show | `show ip name-server` works — **empty** (`Server list is empty.`); `show ip name-servers` **rejected**; `show dns` exists (proxy dump) |
| Config-level `ip name-servers` | **Rejected** — `no such command: name-servers` |

### Ping-check

| Topic | Observation |
|---|---|
| Config level | `ping-check profile {name}` |
| Interface level | `ignore-fail` (flag); `profile {profile}`; `restart [{interface}]` |
| Existing profiles | **`default`** already exists |

---

## 2c. Contradictions vs vendor documentation

| Vendor claim / expectation | Device observation (2026-07-31) |
|---|---|
| `permit global` inside connection policy | **Not present** as CLI command; **rejected** (`no such command: global`) |
| Kill-switch = policy containing ONLY the VPN connection | Cannot confirm policy-interior grammar without creating a policy; available evidence does **not** show a `permit-global` member list |
| Binding via `ip hotspot policy <iface\|segment> <PolicyName>` | Device template is `policy {interface} ({access}\|{policy})`; with zero policies Choose is only permit/deny — named PolicyName path **not demonstrated** |
| `ip global` as internet source | Confirmed at **interface** level (`priority`\|`order`\|`auto`); config-level `ip global` help empty/useless in earlier capture |

**Still unverified (honest):** whether a policy can be restricted to a single connection; whether a policy can be populated without `permit global`; what `ipv6` and `route` inside policy context actually do; kill-switch; named connection policy; **`CLEAR_IP_GLOBAL` on teardown** (not device-proven). **Device-verified (§M-24/M-27):** WireGuard `wireguard_ip_global` accepted; higher priority number wins; default-route via WG **reversible**.

---

## 2d. Offline product layer (NOT device-verified)

| Item | Status |
|---|---|
| Code | `router_control/adapters/netcraze/vpn_policy_rci.py`, `vpn_policy_probe.py`; `router_control/application/vpn_policy_routing_planner.py`, `vpn_policy_routing_service.py`; preview HTTP `POST /api/router-control/v1/vpn/policy-routing/preview` |
| Planner `verification_status` | **`help_verified_grammar_unapplied`** — help-visible grammar compiled offline; **no live apply/dispatch** |
| Refusals | `ip policy permit global` → firmware `no such command: global`; kill-switch **unresolved**; rejected shows (`show rc ip policy`, `show ip name-servers`, `show name-server`, `show hotspot`) not allowlisted; wireguard-like non-canonical interface names (case/separator/`wgN` variants; detection via `allowlist.is_wireguard_like_interface_name`; canonical **`WireguardN`** only via `allowlist.validate_wireguard_id`) → **422** with **canonical WireguardN** message (**before** charset validation for wireguard-like inputs; homoglyphs outside ASCII charset still → charset refusal); sealed Wi-Fi station uplink ids **`WifiMaster0/WifiStation0`**, **`WifiMaster1/WifiStation0`** accepted via `allowlist.validate_interface_id`; WireGuard **`address_configured=true`** required when interface is canonical `WireguardN` or `interface_kind=wireguard` |
| Parsers | `show ip policy` empty → `zero_policies`; `show ip name-server` empty → `Server list is empty.`; non-sample shapes → unknown/unparsed; ANSI erase suffix (`\x1b[K`) stripped **per line as suffix only** (all trailing repeats; CRLF normalized) before sealed-branch match (`sanitize.strip_ssh_cli_ansi_artifacts`); mid-string ANSI and lone `\r` without `\n` preserved — forged phrases fail closed |
| `ip global` bounds | Shared `vpn_policy_rci.validate_ip_global_bound` + preview HTTP `StrictInt` **0..65535** (sealed from `wifi_station_rci._validate_priority`; upper bound **not** device-exhaustive on WireGuard) |
| WriteCertified | **NOT claimed**; Gates A/B/C/D unchanged; `write_shapes_registered` remains **false** |

---

## 3. Baseline routing state (must not disturb)

Recorded baseline from FINAL report — **do not mutate** when re-probing:

| Item | State |
|---|---|
| Internet source | Only **`GigabitEthernet1` / `ISP`**: `global=yes`, `priority=700`, `defaultgw=no`, `link=down`, `state=up` |
| Home / Guest | `global=no` (non-global LAN segments) |
| `show ip route` | Only `192.168.2.0/24` via Home metric 1000 — **NO default route** |
| WireGuard | **No** `Wireguard*` interfaces in inventory **at VPN-policy probe time** (**pre-install**; §2a **historical**) — component **now installed** (2026-07-31); **NOT** hardware limitation |
| Policies | `show ip policy` **empty** |
| Ping-check | Profile **`default`** exists |
| DNS | `show ip name-server` empty |

---

## 4. Field scenario ordering (required before declaring online)

### Deployment-order dependency — connectivity before component download

**First-class circular dependency — HISTORICAL on current lab unit (resolved 2026-07-31):** vendor WireGuard/AmneziaWG install requires internet (NDSS/update catalogue). **Current unit:** wireguard component **installed**; station uplink **bounded verified persisted** (`WifiMaster1/WifiStation0`, 5 GHz WPA2). **Still valid for offline field rack shipping.** Two ways out when connectivity absent:

1. **Wired uplink** — Ethernet cable in WAN port (`GigabitEthernet1`/ISP)
2. **Upstream Wi‑Fi** — venue SSID credentials + station/WISP join (bounded case verified on lab unit)
3. **Pre-provision before ship** — install components while connectivity exists

**Product implication:** field rack may arrive with no connectivity — pre-provision vendor-download capabilities **before shipping**.

**Lesson:** `component "<name>" is unavailable` from `Components::Lister` often means **no connectivity / stale catalogue** — not unsupported hardware.

Technician / preset workflows must follow this sequence — **do not** switch route/policy before upstream path is proven:

1. **Uplink up** — venue wired or station client associated and link up (**was prerequisite for component install when wireguard/amneziawg absent** — resolved 2026-07-31; component now installed)
2. **DNS working** — resolver reachable; venue DNS hijack ruled out or mitigated
3. **Captive portal cleared** — if venue Wi‑Fi requires client portal login
4. **VPN endpoint reachable via uplink** — peer endpoint reachable **before** tunnel bring-up (not via tunnel)
5. **Tunnel up** — WireGuard interface present + link up + **`tunnel_healthy`** when peer online (§M-24..§M-26); **`SET_IP_ADDRESS` device-accepted** (§M-24/M-25); optional **`ip global` priority** for default-route switch (§M-27 — higher number wins)
6. **Only then** route/policy switch — offline `vpn_policy_*` planner/RCI + preview API **delivered** (`help_verified_grammar_unapplied`; **NOT** device-verified for named policy; **no apply/dispatch route**; kill-switch **unresolved**; §5 open questions remain)
7. **Verify actual egress** — traffic path confirmation (external probe / traceroute / leak test) — **default-route via WG device-verified reversible** (§M-27); named kill-switch still open
8. **Only then** declare online

**Premature-success hazard:** `/wireguard/apply` `overall=applied` when interface is present+up verifies **configuration accepted + interface admin state only** (`configuration_verification_status`, `interface_verification_status`) — tunnel status uses 4-state honesty (`tunnel_no_peer` / `tunnel_never_handshaked` / `tunnel_healthy` / `tunnel_unverified`); **`tunnel_healthy` DEVICE-CONFIRMED** on observe path (2026-07-31; first real handshake 2026-08-05 §M-24) — **`overall=applied` + `tunnel_healthy` still NOT kill-switch / named policy**; **`CLEAR_IP_GLOBAL` on teardown NOT device-proven** (teardown omits it). See [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

---

## 5. Open questions (design blocked)

1. How (or whether) a policy can be restricted to a **single connection** on this firmware
2. Whether a policy can be populated **without** `permit global`
3. What **`ipv6`** and **`route`** inside a policy context actually do
4. ~~How a **WireGuard** interface expresses `ip global`~~ — **RESOLVED device-verified (§M-24/M-27):** `wireguard_ip_global` accepted; higher priority number wins; reversible via product activate/deactivate. **Still open:** named connection policy, hotspot binding, kill-switch `permit global`; **`CLEAR_IP_GLOBAL` not emitted on teardown** (not device-proven)

Offline `help_verified_grammar_unapplied` builders (`vpn_policy_rci`, routing planner) and read allowlist entries may compile intent without device apply; **no device-verified writes** for named policy and **no WriteCertified** claims until §5 items 1–3 are resolved with bounded evidence.

---

## 6. CLI `?` + Enter execution hazard

During session 1 help capture, sending `command ?\r` showed help **then executed** the command without `?`:

| Incident | Impact |
|---|---|
| `ip hotspot ?\r` | Entered `(config-hotspot)>` — context enter only; exited; no further hotspot mutation observed |
| `ip name-servers ?\r` on `GigabitEthernet1` | Possible enable of iface DNS accept; no distinct name-servers leaf visible before/after; no save |
| `ip policy permit ?\r` | Error: policy name reserved: `permit` — no policy created |
| `ip policy permit global ?\r` | **`no such command: global`** — valuable rejection |

**Safe technique (later sessions):** partial command + `?` **without** Enter (no CR), read help, then **Ctrl-C** or **Ctrl-U** to reset line before any other input. See also [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md) §8.

This harness uses fixed `show` bytes for sealed discovery ops; agents probing interactively elsewhere must use the safe technique.

---

## 7. Valuable rejections (from capture)

| Command | Result |
|---|---|
| `show rc ip policy` | `no such command: policy` |
| `show ip name-servers` | `no such command: name-servers` |
| `show name-server` | `no such command: name-server` |
| `show hotspot` | `no such command: hotspot` (use `show ip hotspot`) |
| `show interface Wireguard0` | Argument parse error (no such object) |
| `ip name-servers` (config level) | `no such command: name-servers` |
| `ip policy permit global` | `no such command: global` |

---

## 8. Claims discipline

- **READ-ONLY OBSERVED** help/`show` = grammar **visibility**, NOT proof commands work or routing succeeds
- **No intentional mutation** during discovery; accidental ? quirk documented separately
- **WriteCertified NOT claimed**; Gates A/B/C/D **unchanged**; `write_shapes_registered` remains **false**
- **DO claim (device-verified §M-24/M-27):** WireGuard `wireguard_ip_global`/`SET_IP_ADDRESS` accepted; higher `ip global` priority number wins; default-route via tunnel **reversible** via product activate/deactivate
- **Do not claim:** `permit global` works; kill-switch available; named policy routing implemented; WriteCertified; MSS fixes captive portal; rockblack peer healthy; any grammar "works" beyond help visibility
- Portable rack scenario: [`SCENARIO_PORTABLE_EQUIPMENT_RACK.md`](SCENARIO_PORTABLE_EQUIPMENT_RACK.md); roadmap lane: [`contracts/ROADMAP.md`](contracts/ROADMAP.md) §3.2

---

## 9. Links

- Evidence: [`data/artifacts/vpn-connection-policy-help-20260731/`](../data/artifacts/vpn-connection-policy-help-20260731/)
- AWG apply (premature-success): [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md)
- SSH CLI discovery (? hazard): [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md)
- Portable rack scenario: [`SCENARIO_PORTABLE_EQUIPMENT_RACK.md`](SCENARIO_PORTABLE_EQUIPMENT_RACK.md)
- Lab policy: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)

---

## Docs Impact Record

| Field | Value |
|---|---|
| date | 2026-08-01 |
| trigger | Adversarial review rework — WG name refusal, ip global bounds, ANSI strip, preview API schema |
| paths | `docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md` §2d; `docs/docs-map.json` entry tags |
| notes | Documented canonical `WireguardN` refusal, 0..65535 ip global bounds (sealed wifi_station_rci), ANSI `\x1b[K` strip in probe parsers; preview response schema typed |
