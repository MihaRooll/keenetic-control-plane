# Operator runbook — AWG/WireGuard apply / verify (server)

## For agents

| Topic | Rule |
|---|---|
| When to read | Before calling WireGuard apply/preview/teardown API, wiring host transport, or operating `#config` AWG Apply UI |
| Scope | Backend Configure → Apply → Verify for **bounded test interfaces only** (`Wireguard5`–`Wireguard9`) |
| Default | **Preview** is offline-safe (compile only); **apply/teardown** require `confirm_live_apply` / `confirm_live_teardown` + auth |
| **`overall=applied` meaning** | Sealed ops dispatched without op failure **and** readback matches intent (`id_ok∧up_ok`, where **`up_ok` = observed admin state matches requested `enabled`** — not necessarily interface up). **`configuration_verification_status=device_accepted_configuration`** when dispatch ok; **`interface_verification_status`** reports **observed** admin state separately (`interface_present_up` \| `interface_present_down` \| … — e.g. `enabled=false` success may be `interface_present_down`); **`tunnel_verification_status`** from `show interface` peer fields (`tunnel_no_peer` \| `tunnel_never_handshaked` \| `tunnel_healthy` \| `tunnel_unverified`) — **NOT** `wireguard.status:up` alone; **first real handshake DEVICE-VERIFIED** 2026-08-05 (§M-24..§M-26); **traffic via tunnel** via `ip_global_priority` **DEVICE-VERIFIED reversible** (§M-27) — kill-switch/named policy still open; **`interface_address_verification_status`**: `interface_address_not_configured` when Address not in intent; `address_configured_unverified` when SET_IP planned/dispatched but readback address missing or mismatch; `address_readback_confirmed` when parsed readback address matches intent CIDR — **`SET_IP_ADDRESS` grammar device-accepted** (§M-24/M-25). Planner `verification_status` (ASC/secret axis) unchanged (`pending_live_verification` when secrets). |
| Secrets | Request bodies accept **`credential_ref_id` fields only** (`private_key_credential_ref_id`, optional `preshared_key_credential_ref_id`) — never plaintext private-key/psk. Peer **`peer_public_key`**, **`peer_endpoint`**, **`peer_allow_ips`**, **`peer_keepalive_interval`** are non-secret. **`peer_rci_shape`**: only **`nested_rci`** is accepted (default); explicit **`path_style`** → **422** `wireguard.peer_rci_shape_unsupported` (path-style peer grammar **REJECTED** live 2026-07-24 on NC-1812 5.01.C.1.0-0). |
| Dual-stack `AllowedIPs` | Profile import/parse-preview accepts standard dual-stack `AllowedIPs = 0.0.0.0/0, ::/0`. IPv4 entries are kept for **`peer_allow_ips`** (order preserved); IPv6 routes are **soft-dropped** — response includes **`unsupported_fields=["AllowedIPs"]`** and **`operator_notes`**: `Маршруты IPv6 из профиля не применены. Туннель работает только по IPv4.` **`validation_status` stays `Valid`** (not `UnsupportedFields`). IPv6-only / no usable IPv4 → **422** `profile.validation_failed` field **`AllowedIPs`** (fail-closed; never default to `0.0.0.0/0`). Device allowlist/RCI grammar still refuses IPv6 on apply. |
| Gates | Does **not** open WriteCertified or flip `write_shapes_registered`; live path still requires per-campaign T4 for real router |
| Transport | Per-request live when win32 + complete connection params on body; else injected factory / fake / 503 |
| Up/down | `enabled` maps to generic sealed `interface WireguardN up|down` via `execute_interface_rci` (not `WireguardRciOperation`) |
| Policy routing | **Offline preview only** (`help_verified_grammar_unapplied`; `POST /vpn/policy-routing/preview`) — **NOT device-verified**; no apply route — see [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §2d for field ordering before any live route/policy switch |

---

## 1. Flow

1. **Preview** — `POST /api/router-control/v1/wireguard/preview` with `WireguardIntent` fields. Returns compiled op plan (op names, non-secret args). No dispatch. Connection params **not required**.
2. **Apply** — `POST /api/router-control/v1/wireguard/apply` with intent fields + `confirm_live_apply: true`. Optional **`compensate_on_failure: true`** (default; reverse-order compensating rollback on dispatch failure, readback failure after dispatch, or **configuration** verify mismatch — **not** on `tunnel_unverified` / `tunnel_never_handshaked` / `tunnel_no_peer` when config verify passes). Optional **`handshake_settle_seconds`** (default `0` = no wait; values `>0` clamp to **20–30** inclusive) — one sleep + one tunnel recheck when first readback is `tunnel_never_handshaked` **or** `tunnel_unverified` due to ambiguous unconfirmed last-handshake (`0`/negative; parseable `online`/`rxbytes` required — not missing-field short-circuit); **`0`/negative still not confirmed handshake semantics**; **`never_handshaked` does NOT flip `overall` to failed**. Only **`peer_rci_shape=nested_rci`** (default): create → private-key (if ref) → **SET_IP_ADDRESS** (if `interface_address`; **device-accepted** §M-24/M-25) → sealed nested JSON peer upsert (if configured) → asc-9 (if present) → **IP_GLOBAL** (if `ip_global_auto` or `ip_global_priority`; **device-verified** §M-27 — higher NDMS number wins) → **SET_TCP_MSS** (if `tcp_mss_pmtu`; sealed builder emits `interface {wg} ip tcp adjust-mss pmtu` only — numeric MSS intentionally unsupported; **device ACK** §M-30; **captive efficacy NOT proven**) → up (if enabled). **`interface_address`** / **`ip_global_*`** / **`tcp_mss_pmtu`** are optional intent fields; **`CLEAR_IP_GLOBAL`** teardown grammar `interface {wg} no ip global` — **emitted on teardown when intent has `ip_global_auto` or `ip_global_priority`** (best-effort; grammar documentation-sourced; teardown ACK observed §M-38 — **not separately WriteCertified**); **`CLEAR_TCP_MSS`** grammar `interface {wg} no ip tcp adjust-mss` — **device ACK on clear** (§M-30) without readback requirement. TCP MSS clamp is **NOT tunnel-working evidence** and **NOT proven** to fix router `captive_accessible` (§M-30). Explicit **`peer_rci_shape=path_style`** → **422** `wireguard.peer_rci_shape_unsupported` at domain/API (path-style peer ops compile offline in sealed templates for historical reference only — **REJECTED** live 2026-07-24). Nested peer upsert compiles under `interface.WireguardN.wireguard.peer[]` with `"key"` = pubkey (PSK resolved into nested field at dispatch only) — **device-verified write ACCEPTED** on NC-1812 5.01.C.1.0-0 (2026-07-24 re-verify; evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`). Readback `show interface <wg_id>`, verifies interface id + admin state vs intent. **Peer observe fields** come from **`wireguard.peer[]` only** — interface-level `wireguard.public-key` is the interface identity, **never** a peer; multi-peer: match configured `peer_public_key` when `>1` peers else first peer; empty/missing `peer[]` → `tunnel_no_peer`. Live firmware returns `peer.online` as **boolean** or string (`yes`/`no`); unrecognised tokens are **not** positive evidence. **Premature-success hazard:** `overall=applied` when `id_ok∧up_ok` means readback matches intent (including `enabled=false` with interface administratively down) — **NOT** proof of WireGuard handshake, tunnel connectivity, or traffic egress via VPN. Check **`interface_verification_status`** for observed up/down (`interface_present_up` vs `interface_present_down`). Do **not** treat apply success as VPN routing ready; field ordering and egress verification required before declaring online (see [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §4). Secret ops use **`verification_status=pending_live_verification`** overall (not device-certified for the full secret tunnel); **private-key transport is partially device-verified** (NC-1812 live probe 2026-07-24); **nested_rci peer write device-verified accepted**; preshared-key remains pending.
3. **Catalog activate/deactivate** — `POST /vpn-profiles/{profile_id}/activate` and `POST /vpn-profiles/deactivate` rebuild `WireguardIntent` from stored profile **`metadata_json` + vault refs** (not a re-parse of raw `.conf`; import stores metadata only). On import, when the `.conf` declares `PersistentKeepalive`, **`peer_keepalive_interval`** is persisted in metadata and carried through activate and env-gated watchdog reapply. Profiles imported **before** this field existed in metadata stay keepalive-less until the operator re-imports the `.conf`. **`peer_keepalive_interval` is not tunnel health evidence** — it only sets the WireGuard keepalive timer; verify tunnel state via `tunnel_verification_status`, not keepalive alone. Same **`confirm_live_apply`** gate as apply. **`POST /vpn-profiles/import`** accepts raw `.conf` **`profile_text`** (not `profile_document`). Env-gated watchdog (`VPN_WATCHDOG_ENABLED`, default off) may reapply on unhealthy streak — **reapply live-proven** (`vpn_watchdog.reapply` audit events); **reconnect-to-handshake after drop NOT live-proven**.
4. **Teardown** — `POST /api/router-control/v1/wireguard/teardown` with `wg_id` + same secret/peer ref fields (for compile) + `confirm_live_teardown: true` (or `confirm_live_apply: true`). Live path requires Gate A open + startup-config backup before first write (same as apply); backup failure → `503 wireguard.live_backup_unavailable` (no writes). Sequence: **down → clear ip global (if configured) → clear tcp mss (if configured) → clear ip address (if configured) → remove peer (if configured) → clear private-key best-effort (if ref) → remove interface** (guaranteed cleanup via `no interface`). **`CLEAR_TCP_MSS`** — **device ACK** (§M-30); best-effort only. **`CLEAR_IP_GLOBAL`** — emitted when intent has `ip_global_auto` or `ip_global_priority` (best-effort; grammar documentation-sourced); teardown dispatch **ACK accepted** on lab unit (§M-38) — **not separately WriteCertified**. **Best-effort:** all teardown ops are attempted in order even if a mid-sequence op fails (`wireguard_remove_interface` / `no interface` still runs last); readback verify always runs afterward. **`overall=applied`** when readback confirms **`interface_absent`** and the only dispatch failure is the known **`wireguard_clear_private_key` quirk** (failed step remains visible in `steps`/`errors`); genuine removal failure or interface still present → **`overall=failed`** or **`verify_mismatch`**.

---

## 2. Safety bounds

| Rule | Enforcement |
|---|---|
| Production indices `Wireguard0`–`Wireguard4` | Rejected at service + API (`422 wireguard.wg_forbidden`) |
| `Wireguard10+` / non-WG ids | Rejected |
| 16-arg ASC / I1-I5 encodings | `unsupported_pending_verification`; no dispatch |
| ASC-9 bounds | jc..s2 0..99999; h1..h4 0..4294967295 (`validate_asc_args`); device-verify used small test ints only (2026-07-24); real uint32 header magics compile offline — live obfuscated tunnel **NOT** established; plain `wireguard` honours obfuscation **UNKNOWN** |
| Secret-shaped intent keys (raw `private_key`, `psk`, etc.) | Rejected at domain parse + API `extra=forbid` |
| Secret ops (private-key / peer / psk) | Overall `pending_live_verification`; **private-key transport partially device-verified** (NC-1812 live probe 2026-07-24); **nested_rci peer write device-verified accepted** (2026-07-24 re-verify; evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`); path-style peer grammar **REJECTED** live; explicit **`path_style`** → **422** `wireguard.peer_rci_shape_unsupported`; preshared-key pending; use **`nested_rci` default** |
| Missing confirm flag on apply/teardown | `400 wireguard.confirm_required` |
| Auth | `hub_admin` cookie required (401 without) |

---

## 3. Response shape (`WireguardApplyResult`)

| Field | Values |
|---|---|
| `overall` | `applied` \| `failed` \| `verify_mismatch` \| `rolled_back` (additive: compensation fully succeeded after failure/mismatch — **not** when rollback is `partial` due to uncovered ops). **`applied` = sealed ops ok + readback intent match (`id_ok∧up_ok`)**; never tunnel/egress |
| `configuration_verification_status` | `device_accepted_configuration` when sealed ops dispatched without op failure before verify; omitted on dispatch failure |
| `interface_verification_status` | **Observed** admin state (apply): `interface_present_up` \| `interface_present_down` \| `interface_not_up` \| `interface_id_mismatch`; teardown success → `interface_absent`. Distinct from intent-matched `verification.up_ok`. |
| `interface_address_verification_status` | Apply only when sealed ops dispatched without op failure (`dispatch_ok`): **`interface_address_not_configured`** when intent has no `interface_address`; **`address_configured_unverified`** when SET_IP was planned/dispatched but show-interface address is missing or does not match intent; **`address_readback_confirmed`** when parsed readback address matches intent CIDR — **`SET_IP_ADDRESS` device-accepted** (§M-24/M-25). Omitted on teardown and when dispatch failed before readback. When intent implies traffic routing (`peer_allow_ips` non-empty) **without** `interface_address`, apply **`logs`** carry `traffic-routing intent: interface Address NOT configured` (runtime honesty — not a firmware limit when address is in intent). |
| `tunnel_verification_status` | From **`show interface <wg_id>` `wireguard.peer[]` fields only** (WireGuard path does **NOT** read `show rc`; interface-level `wireguard.public-key` is **not** a peer): `tunnel_no_peer` (interface readable, empty/missing `peer[]`) \| `tunnel_never_handshaked` (peer present; **`last-handshake == 2147483647` (INT_MAX) only** for sentinel never — **DEVICE-CONFIRMED** 2026-07-31; **or** positive non-sentinel timestamp + dead-peer shape with `online` not positive and `rxbytes <= 0` — **status:up + rising txbytes alone do NOT imply healthy**; unparseable/missing handshake, string `"never"`, **`0`**, or **negative** values → `tunnel_unverified`, not never — no confirmed firmware semantics for zero/negative) \| `tunnel_healthy` (positive non-sentinel handshake + positive `peer.online` (`yes`/bool true; unrecognised → not positive) + `rxbytes > 0` — **DEVICE-CONFIRMED** 2026-07-31 on expendable lab `Wireguard5`; evidence `data/artifacts/wg-awg-real-tunnel-attempt-20260731.json`) \| `tunnel_unverified` (missing/unparseable fields; unconfirmed handshake counters; **also** apply with default `handshake_settle_seconds=0` caps initial `tunnel_never_handshaked` to unverified — handshake may need ~20–30s). Optional apply body **`handshake_settle_seconds`** (default `0`; clamp **20–30** when `>0`) — one recheck after first readback is `tunnel_never_handshaked` **or** `tunnel_unverified` from ambiguous unconfirmed last-handshake (`0`/negative with parseable `online`/`rxbytes`); still one sleep + one recheck; **`0`/negative still not confirmed**; **`verification.observed` rebuilt from final recheck observation**; immediate never-handshaked or still-unverified ambiguous handshake after performed settle is **NOT** config failure and does **not** fail `overall`. |
| `verdict_explanation` | Required machine-readable audit of the same signals that produced `tunnel_verification_status`: `signals_read[]` (enum signal + sanitized value — no keys/PSK), `signals_missing[]` (enum codes for stronger verdict), `signals_rejected[]` (deceptive signals ignored, e.g. `interface_state_not_evidence`, `peer_txbytes_alone_not_evidence`). Human labels are UI-only. |
| `verification_status` | Planner axis (ASC/secret certification): `device_verified_asc9` \| `pending_live_verification` \| `unsupported_pending_verification` — **not** tunnel state |
| `steps` | `[{op, ok, status_ident?, error?}]` |
| `verification` | `{id_ok, up_ok, observed}` — observed sanitized (no secrets). **`up_ok` = observed admin state matches requested `enabled`** (drives `overall`); **`id_ok`** = expected interface id. Not handshake, not tunnel connectivity, not egress via VPN — use **`interface_verification_status`** for observed up/down. |
| `errors`, `logs` | Sanitized strings; **`errors` = apply/dispatch/readback failures only** |
| `rollback_errors` | Separate from `errors`: rollback dispatch failures when `rollback.outcome` is partial/failed; empty when rollback not attempted or succeeded |
| `rollback` | `{attempted, ops, outcome: not_attempted\|noop\|succeeded\|partial\|failed, steps?, uncovered_ops?}` — reverse-order compensating teardown of succeeded apply ops from sealed templates (`wireguard_apply_planner.compensate_ops_for_succeeded_wireguard_apply`); original dispatch/readback errors preserved in `errors`; **`overall=rolled_back` only when `outcome=succeeded`**. Uncovered: `wireguard_set_asc` (no sealed ASC negation — **offline only; NOT device-verified on live router**); pre-existing interface/key/peer/admin-up (baseline read before first write) → `uncovered_ops` with `pre-existing configuration…`; unreadable/identity-less baseline → fail-closed (`pre-apply state unknown…`); **foreign-interface readback** (observed `id` ≠ target `wg_id`) → **entire baseline unknown** (foreign field values ignored; no `interface_existed=false` inference); **private-key absent from readback** on matched interface → `pre-apply private-key state unknown; clear would destroy foreign state`. |
| `backup_basename`, `backup_content_sha256` | Present on live apply/teardown when pre-change startup-config backup succeeded |

**Readiness chain (code-adjacent):** uplink → DNS → captive portal cleared → VPN endpoint reachable → tunnel up → route/policy → verified egress → online. Apply result covers **configuration + interface admin state only** — never the end of this chain.

**Do not misread `overall=applied`:** it confirms bounded apply ops succeeded and readback matches intent — not kill-switch/named policy. **Default-route via `ip global` priority** is **device-verified reversible** (§M-27); named connection policy and kill-switch remain **NOT device-verified**; offline VPN policy-routing **preview only** exists (`help_verified_grammar_unapplied`) — no apply/dispatch route.

---

## Sealed path-style peer grammar (offline compiler)

Per Keenetic CLI Reference OS 5.0, peer attributes are nested under `config-wg-peer`; RCI `/rci/parse` uses **one path-style CLI line per request** (not a flat combined add-peer one-liner):

| Op | CLI template |
|---|---|
| SET_PRIVATE_KEY | `interface {wg} wireguard private-key {key}` |
| ADD_PEER | `interface {wg} wireguard peer {pubkey}` (bare create only) |
| SET_PEER_ENDPOINT | `interface {wg} wireguard peer {pubkey} endpoint {host:port}` |
| SET_PEER_ALLOW_IPS | `interface {wg} wireguard peer {pubkey} allow-ips {addr} {mask}` (mask = dotted IPv4 or numeric prefix) |
| SET_PEER_KEEPALIVE | `interface {wg} wireguard peer {pubkey} keepalive-interval {3..3600}` |
| SET_PRESHARED_KEY | `interface {wg} wireguard peer {pubkey} preshared-key {key}` |
| REMOVE_PEER | `interface {wg} no wireguard peer {pubkey}` |

**Compensating apply rollback (offline, 2026-08-01):** reverse-order map — `wireguard_create_interface`→`wireguard_remove_interface`; `wireguard_set_private_key`→`wireguard_clear_private_key`; `wireguard_upsert_peer_nested`→`wireguard_remove_peer`; `interface_up`→`interface_down`. **`wireguard_set_asc` has no sealed negation** — listed in `rollback.uncovered_ops` when succeeded before failure; **NOT device-verified on live router**. **Baseline gate (2026-08-01):** when `compensate_on_failure=true`, service reads `show interface <wg_id>` before first write (bounded by transport `read_timeout`, default 15s); planner skips compensation that would destroy pre-existing interface/key/peer/admin-up; empty or identity-less baseline → no destructive compensation (fail-closed); readback whose `id` does not match target → **entire baseline unknown** (foreign field values ignored; no partial inference). **`rollback_errors`** surfaces rollback dispatch failures separately from apply `errors`.

Teardown best-effort: down → remove peer → clear private-key (best-effort; standalone `clear_private_key` **FAILED** quirk noted on 2026-07-24 re-verify — when readback confirms `interface_absent`, **`overall=applied`** despite visible failed clear step; non-blocking, cleanup guaranteed via `wireguard_remove_interface`) → remove interface. Overall `verification_status=pending_live_verification`; private-key transport partially device-verified; nested_rci peer write device-verified accepted (2026-07-24); path-style **REJECTED** on 5.01.C.1.0-0.

**Default-route probe (discovery read):** `GET /rci/show/ip/route` on live NC-1812 may omit `type`/`state` on usable `0.0.0.0/0` entries (station uplink via `WifiMaster1/WifiStation0` with `flags`/`proto` only). Parser **`default-route-v1.3`** classifies explicit defaults with interface + gateway; empty list → `no_default_route`. Evidence: `data/artifacts/wg-tunnel-health-dead-peer-live-20260731.json` §final_state.default_routes.

## Additive nested-RCI peer shape (default; device-verified write accepted 2026-07-24)

When `peer_rci_shape=nested_rci` (default), peer upsert compiles to **`wireguard_upsert_peer_nested`**: sealed POST `/rci/` body (not `[{"parse":…}]`) with bounded tree. **Live re-verify ACCEPTED 2026-07-24** on NC-1812 5.01.C.1.0-0 — corrected array/`key` nested body (ack matched + interface applied/up); evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`. Prior probe used **OLD** pubkey-keyed flat body and was **REJECTED** (`data/artifacts/awg-peer-nested-rci-live-verify-192.168.2.1-20260724.json`). **NOT** tunnel connectivity; **NOT** WriteCertified; **NOT** `write_shapes_registered=true`.

```json
{
  "interface": {
    "WireguardN": {
      "wireguard": {
        "peer": [
          {
            "key": "<pubkey>",
            "endpoint": { "address": "host:port" },
            "allow-ips": [
              { "address": "10.0.0.0", "mask": "255.255.255.0" }
            ],
            "keepalive-interval": { "interval": 25 },
            "preshared-key": "<vault-resolved at dispatch only>"
          }
        ]
      }
    }
  }
}
```

| Rule | Enforcement |
|---|---|
| Default | `nested_rci` — device-verified write accepted on NC-1812 5.01.C.1.0-0 (2026-07-24); explicit **`path_style`** → **422** `wireguard.peer_rci_shape_unsupported` (path-style peer **REJECTED** live; sealed offline templates retained for historical reference) |
| Bare peer upsert | Nested body may include **only** `"key"` (pubkey) — intentional mirror of path-style bare `ADD_PEER`; allowlist accepts key-only peer objects |
| Allowlist | `Wireguard5`–`Wireguard9` only; peer object keys `key`, `endpoint`, `allow-ips`, `keepalive-interval`, `preshared-key` only; `allow-ips` is array of `{address, mask}` with **dotted** IPv4 netmask; **IPv6 allow-ips entries explicitly refused at device grammar** (profile import may soft-drop IPv6 from dual-stack `AllowedIPs` — see For agents table); fail-closed unknown fields |
| Private-key | Remains path-style `SET_PRIVATE_KEY` (partially device-verified grammar) |
| Teardown remove peer | Path-style `REMOVE_PEER` for both shapes |
| `write_shapes_registered` | Remains **false** — nested peer write device-verified accepted (2026-07-24 re-verify); **NOT** formal Gate B registration; overall secret tunnel still `pending_live_verification`; use **`nested_rci` default** |

---

## 4. Offline vs live

### Offline tests / fake host

Set `RC_ALLOW_FAKE_MUTATIONS=1` or `allow_fake_mutations=True`; optional `wireguard_apply_transport_factory` on `HostState`. Omit connection params on apply/teardown body → factory/fake path.

### Per-request live (win32 + DPAPI)

When connection params are complete on the body, apply/teardown open a **short-lived** pinned SSH session via **`open_wifi_live_session`** (shared module with Wi-Fi apply — no duplicate transport module).

| Requirement | Body field / host state |
|---|---|
| win32 host | `sys.platform == "win32"` |
| Router reachability | `host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256` |
| Optional source bind | `source_address` |
| Live apply/teardown backup | Open `host.gate_a_certification` required (`503 wireguard.gate_a_required` when closed); `backup_startup_config` before first mutating op; backup failure → `503 wireguard.live_backup_unavailable` |
| Confirm + bounded WG id | Unchanged |

Complete live connection params on non-win32 → **503** `wireguard.live_platform_unsupported` (family-prefixed live transport gate; no silent fake fallback).

**UI:** `#config` → **AWG Apply (test interface)** — Preview / Apply / Teardown. See [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md).

### Web-E2E nested-RCI peer probe (bounded driver)

[`scripts/probe-nc1812-awg-peer-nested-rci-web-e2e.py`](../scripts/probe-nc1812-awg-peer-nested-rci-web-e2e.py) — fail-closed campaign driver for live verification of **`peer_rci_shape=nested_rci`** on `Wireguard5`–`Wireguard9` via the running `router_control_host` web API.

| Mode | Behavior |
|---|---|
| Default (no flags) | **Plan-only** — prints sanitized JSON plan (`confirm_live=false`); no vault, no network |
| `--confirm-live` | Enrolls throwaway AWG key refs → preview → apply → teardown → deletes refs; writes sanitized evidence JSON |

Plan-only:

```powershell
python scripts/probe-nc1812-awg-peer-nested-rci-web-e2e.py
```

Live (requires active T4 + running host with `HUB_ADMIN_PASSWORD`):

```powershell
python scripts/probe-nc1812-awg-peer-nested-rci-web-e2e.py --confirm-live --wg-id Wireguard5
```

Optional `--with-psk` enrolls a throwaway preshared-key ref. Plaintext keys exist in-memory only; evidence never contains raw private-key/psk material.

---

## 5. Related docs

- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — RO inventory + write-shape verification + offline extended-ASC encoding harness
- [`T4_GATE_PACKET_AWG_EXTENDED_ASC_I1_I5_2026-07-24.md`](T4_GATE_PACKET_AWG_EXTENDED_ASC_I1_I5_2026-07-24.md) — draft T4 for future extended-ASC I1–I5 live probe (**not approved**)
- [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md) — `#config` AWG Apply UI
- [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md) — parallel Wi-Fi apply vertical (reference)
- [`contracts/API_CONTRACT.md`](contracts/API_CONTRACT.md) — HTTP contract
- [`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md) — sealed RCI policy

---

## Docs Impact Record

| Field | Value |
|---|---|
| trigger | WireGuard compensating apply rollback + station `ip_global` uncovered rollback gap |
| touched | `OPERATOR_AWG_APPLY.md`, `OPERATOR_WIFI_APPLY.md`, `OPERATOR_WIFI_DISCOVERY.md`, `contracts/API_CONTRACT.md`, `docs-map.json`, `apply_response_models.py`, `openapi-v0.json` |
| notes | WG apply rollback offline-tested only (NOT live device-verified); `wireguard_set_asc` + `wifi_station_ip_global` explicit in `rollback.uncovered_ops`; `compensate_on_failure` default true at service layer |
