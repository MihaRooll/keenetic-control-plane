# Operator runbook — NC-1812 read-only Wi-Fi RCI write-shape discovery

## For agents

| Topic | Rule |
|---|---|
| When to read | Before constructing or executing **read-only Wi-Fi RCI write-shape discovery** or Wi-Fi T4 write-shape verification; after AWG RO evidence (2026-07-23) |
| Scope | Wi-Fi interface inventory from shared RO artifact (`show interface` / `GET show/interface`); **no** write verbs; **no** production SSID mutation in discovery |
| Default | Review sanitized artifact `data/artifacts/awg-shape-192.168.2.1-20260723.json` (shared 32-interface inventory); candidate shapes from documentation — **NOT** device-certified |
| Source bind | `192.168.2.10` (host Ethernet on lab `192.168.2.0/24`); host-key pin must match Gate A SSOT |
| Gates | A open ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified**; `write_shapes_registered` remains **false** |
| Next | Sealed `wifi_rci` op + WRITE_ALLOWLIST delivered (T4 campaigns); offline WifiIntent product model (`wpa_mode`/`band` + `wifi_apply_planner` compiler) delivered — WPA2, WPA3-Personal, and WPA2+WPA3 mixed device-verified; **WriteCertified NOT claimed**; gates unchanged |

---

## 1. Purpose

Per-feature discovery for **Wi-Fi RCI write-shape** classification on the exact Gate A tuple (`NC-1812`, firmware `5.01.C.1.0-0`, pinned SSH tunnel). Live RO inventory confirms AccessPoint field names and unused AP slots — it does **not** register write shapes, claim WriteCertified, or open Gates B/C/D.

Discovery is **classification only** — it does **not** infer write safety or transport promotion beyond existing Gate A ReadOnlyCertified scope.

---

## 2. Live RO evidence (2026-07-23)

Shared artifact from AWG RO probe (same session, same interface inventory):

| Item | Observation |
|---|---|
| Artifact | `data/artifacts/awg-shape-192.168.2.1-20260723.json` |
| Contract flags | `mutation_performed=false`, `write_shapes_registered=false`, `certification_eligible=false` |
| Sanitization | Responses sanitized via `sanitize_mapping` / artifact contract |
| Interface count | **32** interfaces |
| Wi-Fi inventory | WifiMaster0/1; **14** AccessPoints — `AccessPoint`, `GuestWiFi`, `AccessPoint_5G`, `GuestWiFi_5G`; `AccessPoint3`–`AccessPoint6` **down/unused**; WifiStation *(**historical** 2026-07-23 artifact — see §2b for current `AccessPoint0`–`6` hardware-bound inventory)* |
| Bridges | `Bridge0`=Home (includes main APs); `Bridge1`=Guest (includes guest APs) |
| AP fields observed (names only) | `ssid`, `auth-type`, `encryption`, `security-level`, `mac` (redacted in artifact) |
| VPN/tunnel ifaces | **Prior unit (2026-07-23 artifact):** no Wireguard/AmneziaWG/OpenVPN/IKE/L2TP/PPTP in inventory. **Current rebind unit (2026-07-31):** wireguard component **installed**; **no Wireguard* interfaces** currently — end state, not blocker — **NOT** hardware limitation; prior unit at same address had live WG/AWG write evidence. See [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §2a (**historical** pre-install probe). |

**Conclusion:** RO inventory confirms field names and unused AP slots; WRITE grammar must come from **documentation + T4 device-verification** on an unused AccessPoint — not from RO help alone.

---

## 2b. READ-ONLY OBSERVED hardware inventory (2026-07-31)

Gate A ReadOnlyCertified rebind on expendable class (`NC-1812`, firmware `5.01.C.1.0-0`). Sanitized RO facts only — **no** neighbour/production SSIDs, BSSIDs, or MAC values in this doc.

| Topic | Observation |
|---|---|
| AccessPoint indices | **`AccessPoint0`–`AccessPoint6` ONLY** per radio (`WifiMaster0`, `WifiMaster1`); **no** `AccessPoint7`/`8`/`9` objects on device |
| Production/guest APs | **`AccessPoint0`** and **`AccessPoint1`** on both radios — reserved for production/guest roles on non-expendable units; excluded from default sealed allowlist |
| Station interfaces | **`WifiMaster0/WifiStation0`**, **`WifiMaster1/WifiStation0`** only — inventory names recorded; write grammar **device-confirmed** (§2c); uplink **bounded persisted** (`uplink_verified_bounded`, 5 GHz WPA2); HTTP `POST /wifi/station/apply` + `/wifi/station/teardown` **device-verified live 2026-08-05** (§M-34: 14 allowlisted ops, 7/7 live apply, internet via station; 8 deferred ops closed honestly) |
| Site survey (`show interface … site-survey`) | Tabular CLI columns: **`SSID` \| `MAC` \| `Ch` \| `Mode` \| `Q`** (extra columns tolerated when header present; missing/duplicate required columns → `site_survey_malformed`; no header → fail-closed, not positional guess) — no security column in text. Live RCI JSON (`parse.ap_cell`) includes per-row `encryption` / `encryption-mode` when present (2026-07-31 live validation) |
| Unconfigured station `show interface <station>` | Fields observed: **`ap`**, **`auth-type`**, **`encryption`**, **`global`**, **`security-level`**, **`link`**, **`connected`**, **`state`**, **`traits`** — **no `ssid` field** when unconfigured |
| Uplink priority | **`global`** + **`priority`** observed on uplink-related reads; **`standby`** **NOT** observed on this tuple |
| Default route read | Use **`show ip route`** — **not** `show ipv4 route` |
| Station running-config | **`show running-config interface <station>`** **rejected** on device (grammar not available via this path) |
| USB modem interfaces | **`usb`**, **`usbmodem`**, **`usblte`**, **`usbqmi`**, **`usbnet`** **confirmed installed** on current rebind unit (2026-07-31) — no component download needed for cellular path; **no** USB modem interface objects in inventory **without** physical modem plugged in; modem operation **NOT** device-verified |

**Supersedes (partial):** §2 row «14 AccessPoints» / `AccessPoint3`–`AccessPoint6` unused assumed from 2026-07-23 artifact — hardware-bound inventory above is current SSOT for AP index range (`0`–`6` max). Alias names (`GuestWiFi`, `AccessPoint_5G`, etc.) may still appear in older artifacts; allowlist uses canonical `WifiMaster*/AccessPointN` ids.

**Allowlist alignment (offline, 2026-07-31):** default sealed writes **`AccessPoint3`–`6`**; expendable **`AccessPoint0`–`6`**; rejects **`AccessPoint7`–`9`** early. **`AccessPoint3`** remains permitted (concurrent live verification path).

**Guest Wi‑Fi live campaign (2026-08-02, device-verified bounded):** `WifiMaster0/AccessPoint3` — WPA2 apply + on-air verify + teardown; evidence [`data/artifacts/guest-wifi-live-campaign-20260802.json`](../data/artifacts/guest-wifi-live-campaign-20260802.json). **`guest_isolation` still unsupported** (HTTP **422** at preview/apply) — not verified. Campaign evidence targets **AccessPoint3 only** — no AP0/AP1 mutation recorded.

---

## 2c. Wi‑Fi station (WISP client) grammar — device-confirmed + first association bounded (2026-07-31)

Source: bounded expendable lab write-shape probe **2026-07-31** on Gate A ReadOnlyCertified tuple (`192.168.2.1`; firmware **5.01.C.1.0-0**). Grammar evidence: [`data/artifacts/station-wisp-grammar-probe-20260731.json`](../data/artifacts/station-wisp-grammar-probe-20260731.json); first association: [`data/artifacts/station-wisp-upstream-uplink-first-association-20260731.json`](../data/artifacts/station-wisp-upstream-uplink-first-association-20260731.json); backups under `data/backups/`. Station interfaces: **`WifiMaster0/WifiStation0`**, **`WifiMaster1/WifiStation0`** only.

| Topic | Device-confirmed grammar / status |
|---|---|
| SSID | `interface {station} ssid {ssid}` — ack **SSID saved**; negation `no ssid` — ack **SSID reset** |
| WPA-PSK | `interface {station} authentication wpa-psk {psk}` — ack **WPA PSK set**; `no authentication wpa-psk` — **WPA PSK removed** — **PSK via credential_ref only** in product code; **`show rc interface` may contain plaintext PSK — scrub at ingest** |
| Encryption | `encryption enable` (ack **wireless encryption enabled**); `encryption wpa2` (ack **WPA2 algorithms enabled**; readback `encryption: wpa2`); negations `no encryption wpa2` / `no encryption enable` confirmed |
| Encryption vs association | Grammar probe: device **accepts** PSK without `encryption enable`/`wpa2`. **First association (2026-07-31): both required to join real WPA2 upstream** — default compiler emits enable+wpa2 |
| auth-type trap | **`auth-type` is NOT WPA/security or association indicator** — Keenetic may show `auth-type none` with `encryption=wpa2`; use `encryption`, `link`, `connected`, `state`, `ssid`; site-survey uses `mode`/`channel`/`rssi` |
| DHCP client | `ip address dhcp` — ack **Started DHCP client**; optional (default **off** compiler); used on first association |
| Up / down | `up` / `down` — ack **interface is up/down** |
| Uplink priority | `ip global {priority}` — **device-exercised on station** (first association priority 600, 2026-07-31; **product-certified live apply 2026-08-05** §M-34); **product L3 ack phrase `global priority is` certified 2026-08-05** (live station apply; ident `Network::Interface::L3Base`); default route settle **~20–30s** — bounded wait-and-recheck before `show ip route` (§M-35); **WireGuard `ip global` device-verified** (§M-27 — higher number wins); **negation not device-confirmed** on station (grammar probe exercised positive form only — compensating rollback lists `wifi_station_ip_global` in `rollback.uncovered_ops`); **preview / offline apply:** non-default `priority` without `include_ip_global` → **422** `wifi.station_priority_requires_ip_global` (default `100` noop); **offline teardown** compiles with non-default priority (teardown path forces `include_ip_global`); **live apply** consumes via forced `include_ip_global`; **write success ≠ internet** |
| Connectivity check | **No general CLI `ping`** — sanctioned check: `show internet status` (internet/gateway/dns/captive-accessible) |
| BSSID pin | `mac bssid {bssid}` — help-derived; not exercised in bounded probe |
| Standby | `standby enable`, `standby timeout` — help-derived; **not exercised** |
| Readback split | **Configured** SSID/encryption from `show rc interface {station}` (scrubbed); **associated** SSID from `show interface {station}` |
| Site survey | **`show site-survey WifiMaster0`**, **`show site-survey WifiMaster1`** |
| OPEN network | **No verified open-network authentication grammar** — offline planner **rejects** |
| First association limits | One upstream; 5 GHz `WifiMaster1/WifiStation0` WPA2; open/captive/standby/failover unverified |
| Offline compiler | `grammar_verification_status=device_accepted_grammar`; preview `planned_uplink_verification_level=planned_uplink_verified_bounded` (compile-time plan label — machine-distinct from runtime `uplink_verification_status`); live apply overwrites with runtime observe verdict | HTTP apply/teardown **device-verified live 2026-08-05** (§M-34) |
| Teardown | Full confirmed negation reverse (grammar probe); teardown dispatch **continue-on-error** |
| WireGuard show-rc | **No product show-rc consumer for WG** — WG readback uses `show interface` whitelist only |

**Still unverified (honest):** open-network join; standby; captive portal client; multi-uplink failover; 2.4 GHz station path on live upstream; preset planner **`wifi_wan_not_certified`** unchanged.

**Claims discipline:** bounded evidence on expendable lab at Gate A ReadOnlyCertified; **WriteCertified NOT claimed**; gates A/B/C/D unchanged; `write_shapes_registered` remains **false**.

---

## On-device write-shape verification (2026-07-24)

Under human-approved T4 campaign [`T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md) (device owner approved 2026-07-24), a minimal reversible live verification was executed on the **unused** test AP `WifiMaster0/AccessPoint3` via sealed `wifi_rci` op (`scripts/wifi-rci-op.py --execute`).

| Item | Result |
|---|---|
| Gate A preflight | PASS — exact tuple match; preflight artifact `data/artifacts/gate-a-probe-preflight-wifi-20260724.json` |
| Pre-change backup | `startup-192.168.2.1-20260724T054149Z-59eb11d7` under `data/backups/` (DPAPI-encrypted) |
| Steps verified | `ssid <name>`, `up`, `down`, `no ssid` — each `ack_matched=true`, no error status |
| Runtime readback | After `up`: state=up, ssid present, `auth-type none` (open, no WPA) |
| Rollback | Final readback identical to baseline (down, no ssid, disabled) |
| `system configuration save` | **NOT** executed — running-config only; startup-config unchanged |
| Evidence | [`data/artifacts/wifi-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-writeshape-verify-192.168.2.1-20260724.json) |

**Certified on-device write grammar** (firmware `5.01.C.1.0-0`, this campaign scope only):

```text
interface WifiMaster0/AccessPoint3 ssid <name>
interface WifiMaster0/AccessPoint3 up
interface WifiMaster0/AccessPoint3 down
interface WifiMaster0/AccessPoint3 no ssid
```

**Claims discipline:** `mutation_performed=true`; `configuration_saved=false`; **WriteCertified NOT claimed**; gates A/B/C/D **unchanged**; `write_shapes_registered` remains **false**.

### WPA / encryption verification (2026-07-24)

Extends the same human-approved T4 campaign — WPA-PSK + encryption enable/wpa2 on the **unused** test AP `WifiMaster0/AccessPoint3` via sealed `wifi_rci` op (`scripts/wifi-rci-op.py --execute`).

| Item | Result |
|---|---|
| Pre-change backup | Same as ssid/up phase — `startup-192.168.2.1-20260724T054149Z-59eb11d7` (`content_sha256` unchanged; startup-config not modified) |
| PSK handling | Throwaway test PSK generated internally; stored in DPAPI vault via `WindowsDpapiVault.create`; used via `--psk-credential-ref`; **never** printed in argv/logs/artifacts; vault entry deleted after |
| Steps verified | `set-ssid`, `set-wpa-psk`, `encryption-enable`, `encryption-wpa2`, `up` — each `ack_matched=true`, no error status |
| Runtime readback | After `up`: state=up, connected=yes, ssid `<test-ssid>`, `encryption=wpa2`, `auth-type none` (Keenetic shows WPA via encryption field); **PSK not present in readback** |
| Rollback | `down`, `no encryption enable`, `no encryption wpa2`, `no authentication wpa-psk`, `no ssid` — full clean required (`no encryption enable` alone left runtime `encryption=wpa2`); final readback identical to baseline (down, no ssid, encryption empty, disabled) |
| Sealed ops | Sealed `wifi_rci` op now covers `set-wpa-psk`, `encryption-enable`, `encryption-wpa2`, `encryption-wpa2-clear`, `clear-wpa-psk` |
| `system configuration save` | **NOT** executed — running-config only |
| Evidence | [`data/artifacts/wifi-wpa-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa-writeshape-verify-192.168.2.1-20260724.json) |

**Certified on-device write grammar** (firmware `5.01.C.1.0-0`, WPA/encryption scope):

```text
interface WifiMaster0/AccessPoint3 ssid <name>
interface WifiMaster0/AccessPoint3 authentication wpa-psk <vault-credential-ref>
interface WifiMaster0/AccessPoint3 encryption enable
interface WifiMaster0/AccessPoint3 encryption wpa2
interface WifiMaster0/AccessPoint3 up
interface WifiMaster0/AccessPoint3 down
interface WifiMaster0/AccessPoint3 no encryption enable
interface WifiMaster0/AccessPoint3 no encryption wpa2
interface WifiMaster0/AccessPoint3 no authentication wpa-psk
interface WifiMaster0/AccessPoint3 no ssid
```

**Claims discipline:** `mutation_performed=true`; `configuration_saved=false`; **WriteCertified NOT claimed**; gates A/B/C/D **unchanged**; `write_shapes_registered` remains **false**.

---

## 3. Candidate Wi-Fi write-shape (documentation-sourced, NOT certified)

> **Status:** DOCUMENTATION-SOURCED — **NOT** device-certified. Does **not** set `write_shapes_registered=true`. Does **not** imply WriteCertified.

### Main / staff SSID (example: WifiMaster0/AccessPoint0 alias AccessPoint)

```text
interface AccessPoint
  ssid "<ssid>"
  authentication wpa-psk "<SECRET>"
  encryption enable
  encryption wpa2
  [encryption wpa3]
  up
interface Bridge0
  include AccessPoint
  security-level private
system configuration save
```

### Guest SSID (example: WifiMaster0/AccessPoint1 alias GuestWiFi)

```text
interface GuestWiFi
  ssid "<ssid>"
  authentication wpa-psk "<SECRET>"
  encryption enable
  encryption wpa2
  up
interface Bridge1
  include GuestWiFi
  [include GuestWiFi_5G]
  security-level protected
  peer-isolation
  [no peer-isolation]
system configuration save
```

### Captive portal (Coova-Chilli — not an AccessPoint boolean)

Captive portal is **Coova-Chilli**, not an AccessPoint flag:

```text
interface Chilli0
  chilli *
  bind chilli dhcpif Bridge1
system configuration save
```

Extra secret field names: `chilli uamsecret`, `chilli radiussecret`.

### Secret field names (values forbidden in docs)

| Field | Role |
|---|---|
| `authentication wpa-psk` | WPA passphrase — maps to `WifiIntent.credential_ref_id` (vault) |
| `chilli uamsecret` | Captive portal UAM secret — vault |
| `chilli radiussecret` | Captive portal RADIUS secret — vault |

WPA passphrase: ASCII **8–63** chars or **64** hex digits.

### Confidence

| Shape element | Confidence |
|---|---|
| `ssid` / `authentication wpa-psk` / `encryption enable` / `encryption wpa2` / `up` / `system configuration save` | **HIGH** |
| Guest bridge bind + `security-level protected` | **HIGH** |
| `peer-isolation` (guest isolation) | **LOW** — documentation-sourced; **`guest_isolation=true` rejected** (HTTP **422**); not grammar-ready |
| Nested RCI JSON for `wpa-psk` | **LOW–MEDIUM** — prefer sealed typed ops |
| Captive portal as AccessPoint boolean | **LOW** — use Chilli interface model |

### Sources

- Keenetic CLI Reference OS 5.0
- [help.keenetic.com](https://help.keenetic.com) guest/segments/captive/firewall articles
- [Netcraze NC-1812 CLI intro](https://support.netcraze.ru/ultra/nc-1812/en/18480-command-line-interface--cli-.html)

---

## 4. WifiIntent mapping (offline product model, 2026-07-24)

Current `WifiIntent` (`router_control/domain/network_intents.py`):

| Field | Maps to candidate shape |
|---|---|
| `ssid` | `ssid "<ssid>"` |
| `enabled` | `up` / `down` |
| `credential_ref_id` | `authentication wpa-psk` (vault ref — **no** plaintext in product surface) |
| `captive_portal` | Chilli model — **not** a single AP flag; **`Enabled` rejected** at preview/apply until device-verified grammar |
| `guest_isolation` | `peer-isolation` on guest bridge/AP context; **`true` rejected** at preview/apply until device-verified grammar |
| `wpa_mode` | `encryption wpa2` when `WPA2` (device-verified); `WPA3` uses `authentication wpa-psk` + `encryption wpa3` (device-verified on 5.01.C.1.0-0, 2026-07-24); `WPA2_WPA3_MIXED` adds both `encryption wpa2` and `encryption wpa3` — per Keenetic CLI Reference (KN-1812 / KeeneticOS 5.0); no `authentication sae` command; readback `wpa2,wpa3`; device-verified on `5.01.C.1.0-0` (2026-07-24) |
| `band` | `WifiMaster0` (2.4 GHz) or `WifiMaster1` (5 GHz) — compiler enforces against `ap_id` |

**Offline intent → sealed-op compiler:** `router_control/application/wifi_apply_planner.py` (`compile_wifi_intent_to_ops`) maps intent + allowlisted test `ap_id` to ordered sealed `wifi_rci` op descriptors. **No live dispatch**, no vault/PSK resolve. **`guest_isolation=true` and `captive_portal=Enabled` fail-closed** (HTTP **422** `wifi.guest_isolation_unsupported` / `wifi.captive_portal_unsupported`) — no device-verified grammar; do not claim device support.

| Path | Verification status |
|---|---|
| WPA2 apply | `device_verified_wpa2` — sequence matches on-device T4 evidence (2026-07-24) |
| WPA3-Personal apply | `device_verified_wpa2` — same literal as WPA2; sealed ops: `SET_WPA_PSK` + `ENCRYPTION_WPA3`; grammar `authentication wpa-psk` + `encryption wpa3`; device-verified on NC-1812 firmware `5.01.C.1.0-0` (2026-07-24); evidence [`data/artifacts/wifi-wpa3-live-reverify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa3-live-reverify-192.168.2.1-20260724.json); bounded test AP only (`WifiMaster0/AccessPoint3`, `WifiMaster0/AccessPoint4`, `WifiMaster1/AccessPoint3`, `WifiMaster1/AccessPoint4`) |
| WPA2+WPA3 mixed | `device_verified_wpa2` — same literal as WPA2; sealed ops: `SET_WPA_PSK` + `ENCRYPTION_WPA2` + `ENCRYPTION_WPA3`; grammar `authentication wpa-psk` + `encryption wpa2` + `encryption wpa3`; readback `wpa2,wpa3`; device-verified on NC-1812 firmware `5.01.C.1.0-0` (2026-07-24); evidence [`data/artifacts/wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json); bounded test AP only (same as above) |

WriteCertified **NOT** claimed; `write_shapes_registered` remains **false**; gates unchanged.

Sealed write op + WRITE_ALLOWLIST for live apply remain separate from this offline product model slice.

---

## 5. Related references

- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — shared RO artifact and AWG parallel track
- [`T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md) — T4 Human Gate Packet (approved + executed 2026-07-24 for ssid/up/down/no-ssid scope)
- [`data/artifacts/wifi-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-writeshape-verify-192.168.2.1-20260724.json) — sanitized ssid/up live verification evidence
- [`data/artifacts/wifi-wpa-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa-writeshape-verify-192.168.2.1-20260724.json) — sanitized WPA/encryption live verification evidence
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed typed RCI pattern (interface/save; Wi-Fi sealed `wifi_rci` op delivered + offline `wifi_apply_planner` compiler; WriteCertified NOT claimed)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) — **active** lab handoff (2026-08-01/02 session)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) — **historical** methods companion (post-rebind unit through 2026-07-31)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) — **historical** prior-session handoff (superseded)
- [`STATUS.yaml`](STATUS.yaml) — gates unchanged

---

## Next: T4 device-verification

Minimal reversible Wi-Fi write-shape verification on an **unused** AccessPoint: [`T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md).

| Prerequisite | Status |
|---|---|
| T4 Human Gate Packet — ssid/up/down/no-ssid | **Approved + executed** (2026-07-24) — evidence [`wifi-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-writeshape-verify-192.168.2.1-20260724.json) |
| WPA / encryption verification | **Approved + executed** (2026-07-24) — evidence [`wifi-wpa-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/wifi-wpa-writeshape-verify-192.168.2.1-20260724.json) |
| Sealed Wi-Fi write op + WRITE_ALLOWLIST | Delivered (sealed `wifi_rci` op used for campaign) |
| WifiIntent extension (`wpa_mode` / `band`) | **Delivered offline** (2026-07-24) — compiler WPA2 + WPA3-Personal + WPA2+WPA3 mixed device-verified |
| WriteCertified | **Never** implied |
| `write_shapes_registered` | Remains **false** |
| Gates A/B/C/D | **Unchanged** |

**Do not touch** production SSIDs (`AccessPoint0`, `AccessPoint_5G`, home/guest aliases). T4 scope uses down/unused AP only (e.g. `WifiMaster0/AccessPoint3`).

**human approval required; packet creation is not approval.**
