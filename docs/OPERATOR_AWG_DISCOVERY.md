# Operator runbook — NC-1812 read-only AmneziaWG/WireGuard RCI write-shape discovery

## For agents

| Topic | Rule |
|---|---|
| When to read | Before constructing or executing **read-only AWG/WireGuard RCI write-shape discovery**; after offline harness delivery (2026-07-23) |
| Scope | Fixed RO parse bodies (`help interface`, `help wireguard`, `help AmneziaWG`, `show interface`) plus discovery-allowlisted `GET /rci/show/interface` — **no** write verbs; **no** invented certified AWG token names |
| Default | Offline validate plan JSON to stdout (zero network, zero DPAPI); **no** live I/O without operator `--live-probe` |
| Source bind | `192.168.2.10` (host Ethernet on lab `192.168.2.0/24`); host-key pin must match Gate A SSOT |
| Gates | A open ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified**; `write_shapes_registered` remains **false** |
| Next | Live RO **done** (2026-07-23 on **prior** unit); asc-9 write-shape **device-verified** (2026-07-24 on **prior** unit); **current rebind unit (2026-07-31):** `wireguard` component **installed**; **`tunnel_healthy` DEVICE-CONFIRMED** (2026-07-31); **2026-08-05 (§M-24..§M-27):** first real handshake; `SET_IP_ADDRESS` + `wireguard_ip_global` accepted; traffic via tunnel reversible — kill-switch/named policy still open; **`next_task` id:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](STATUS.yaml); **parallel deferred:** VPN named policy / kill-switch live apply (offline preview only). **Historical (phase-1):** wireguard/amneziawg **absent** until internet — connectivity blocker **resolved**, not hardware gap |

---

## 1. Purpose

Per-feature discovery for **AmneziaWG/WireGuard RCI write-shape** classification on the exact Gate A tuple (`NC-1812`, firmware `5.01.C.1.0-0`, pinned SSH tunnel). This tooling issues **read-only** RCI parse and discovery reads to observe CLI help text and interface type fields — it does **not** register write shapes, claim WriteCertified, or open Gates B/C/D.

Discovery is **classification only** — it does **not** infer handshake success, write safety, or transport promotion beyond existing Gate A ReadOnlyCertified scope.

---

## 2. Offline harness (delivered)

| Component | Path |
|---|---|
| CLI | `scripts/probe-nc1812-awg-shape.py` |
| Tests | `tests/test_probe_nc1812_awg_shape.py` |
| Shared transport | `router_control/adapters/netcraze/rci_live.py` (`open_pinned_rci_transport`) |
| Discovery allowlist | `router_control/adapters/netcraze/allowlist.py` (`SHOW_INTERFACE`) |
| Sanitization | `router_control/adapters/netcraze/sanitize.py` (`sanitize_mapping`) |

Validate-default plan mode (no network, no DPAPI):

```powershell
py.exe -3.11 scripts/probe-nc1812-awg-shape.py
```

Stdout is a JSON plan with `mutation_allowed=false`, `write_shapes_registered=false`, `certification_eligible=false`, and the exact RO commands that **would** be issued in live mode.

---

## 3. Live probe prerequisites (operator-run — not standing approval)

Live `--live-probe` requires **all** of:

1. Dedicated lab router reachable at management IP `192.168.2.1` with host Ethernet source bind `192.168.2.10` (dual-NIC — bind is mandatory).
2. DPAPI `--credential-ref` (no password argv/env). Placeholder id for enrolled test-router credential: `cred_db65665dd59f600bdd23544d85564c83`.
3. `--ssh-host-key-sha256` matching Gate A pin `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY` (current rebind unit; prior pin `SHA256:lU1D6ChV…` historical only).
4. `--source-address 192.168.2.10` (hard-required; other binds refused).
5. win32 host with `WindowsDpapiVault` and hardware extras installed (`pip install -e ".[hardware]"`).

Ready-to-run Gate A RO command:

```powershell
py.exe -3.11 scripts/probe-nc1812-awg-shape.py --live-probe `
  --host 192.168.2.1 `
  --source-address 192.168.2.10 `
  --username admin `
  --credential-ref cred_db65665dd59f600bdd23544d85564c83 `
  --ssh-host-key-sha256 SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY `
  --artifact-out data/artifacts/awg-shape-192.168.2.1-<YYYYMMDD>.json
```

Replace `<YYYYMMDD>` with the UTC capture date. Default artifact path (when `--artifact-out` omitted): `data/artifacts/awg-shape-<host>-<YYYYMMDD>.json`.

**Forbidden:** `--execute`; raw command arguments; `execute_sealed_rci_write`; WRITE_ALLOWLIST edits; opening Gates B/C/D; claiming discovery complete or WriteCertified from this artifact alone.

---

## 4. Gate A tuple (current rebind unit — do not silent rebind)

| Field | Value |
|---|---|
| Model | NC-1812 |
| Firmware | 5.01.C.1.0-0 |
| Transport | ssh_tunnel |
| Source | 192.168.2.10 |
| Evidence sha256 | `86bbcb5866434ca99b930c55db48a54b8edd2a9c1e758c2f771612f0a070a95f` |
| Host key | ssh-ed25519 `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY` |
| component_set_digest | `sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80` |

**Superseded (pre-WG rebind #1 same day):** evidence sha256 `ce76e7ec…`; component_set_digest `sha256:91145a8284…`; device_fingerprint `sha256:13885245…`.

**Historical (prior physical unit, superseded 2026-07-31 rebind #1):** evidence sha256 `24c6df7e…`; host key `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM`; component_set_digest `sha256:de72a7af…` — that unit had WireGuard component present and live WG/AWG write evidence.

---

## 5. Artifact contract

Sanitized JSON written on successful live probe:

| Field | Value / rule |
|---|---|
| `contract_id` | `nc1812-awg-ro-discovery-probe-20260723` |
| `host` | Management host slug (e.g. `192.168.2.1`) |
| `captured_at` | UTC date `YYYY-MM-DD` |
| `gate_a_tuple` | At minimum: `model`, `firmware_version`, `transport`, `ssh_host_key_fingerprint_sha256` |
| `source_address` | `192.168.2.10` |
| `credential_ref` | DPAPI ref id only — never password |
| `mutation_performed` | `false` |
| `mutation_allowed` | `false` |
| `write_shapes_registered` | `false` |
| `certification_eligible` | `false` |
| `commands_issued` | Fixed list: four RO parse bodies + one `GET /rci/show/interface` discovery read |
| `responses` | Sanitized structures / `describe_structure` fingerprints — **never** raw `PrivateKey`, `PresharedKey`, passwords, sessions |

Default path pattern: `data/artifacts/awg-shape-<host>-<YYYYMMDD>.json`.

---

## 6. Related references

- [`OPERATOR_GATE_B_C_AWG.md`](OPERATOR_GATE_B_C_AWG.md) — historical Gate B/C AWG trial (completed_failed; not WriteCertified)
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed write CLIs (`--execute`); distinct from this RO discovery tool
- [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md) — SSH exec/shell channel discovery precedent (`--live-probe`)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) — active lab handoff
- [`STATUS.yaml`](STATUS.yaml) — gates unchanged; live RO discovery executed 2026-07-23
- [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md) — exact T4 Human Gate Packet for minimal reversible AWG write-shape verification (pending human approval)
- [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) — parallel Wi-Fi per-feature discovery runbook

---

## Live RO discovery results (2026-07-23)

Live `--live-probe` executed on dedicated NC-1812 lab router (`192.168.2.1`, source bind `192.168.2.10`).

| Item | Observation |
|---|---|
| Artifact | `data/artifacts/awg-shape-192.168.2.1-20260723.json` |
| Contract flags | `mutation_performed=false`, `write_shapes_registered=false`, `certification_eligible=false` |
| Sanitization | Responses sanitized via `sanitize_mapping` / artifact contract — **no** top-level `sanitized` boolean |
| RCI parse-help | `help interface`, `help wireguard`, `help AmneziaWG` → **empty** completion/hint — parse-help does **not** expose CLI grammar |
| Interface inventory | `show interface` / `GET show/interface`: **32** interfaces — GigabitEthernet, Port, XGigabitEthernet, Vlan, Bridge (`Bridge0`=Home, `Bridge1`=Guest), WifiMaster0/1, 14 AccessPoints, WifiStation — **no** Wireguard/AmneziaWG/OpenVPN/IKE/L2TP/PPTP |
| AP fields (names only) | `ssid`, `auth-type`, `encryption`, `security-level`, `mac` (redacted in artifact) |

**Conclusion:** pure read-only capture of WRITE grammar is **not** achievable on this tuple. Candidate write-shapes must come from **documentation + T4 device-verification** — not from RO help text or interface inventory alone.

---

## Candidate AmneziaWG write-shape (documentation-sourced, NOT certified)

> **Status:** DOCUMENTATION-SOURCED — **NOT** device-certified. Does **not** set `write_shapes_registered=true`. Does **not** imply WriteCertified.

AmneziaWG on KeeneticOS is a normal `interface Wireguard<N>` — **no** separate AmneziaWG iftype; runtime type is `"Wireguard"`.

### Base WireGuard interface

```text
interface Wireguard0
ip address <addr> <mask>
wireguard private-key <SECRET>
wireguard peer <pubkey> {
  endpoint host:port
  keepalive-interval <3..3600>
  allow-ips <addr> <mask>
  [preshared-key <SECRET>]
}
up
system configuration save
```

### Obfuscation (`wireguard asc`)

Nine-argument form (official since OS 4.02; CLI PDF 4.3/5.0):

```text
wireguard asc <jc> <jmin> <jmax> <s1> <s2> <h1> <h2> <h3> <h4>
```

**Allowlist bounds (2026-07-31, offline SSOT — `validate_asc_args`):**

| Positions | Fields | Range | Rationale |
|---|---|---|---|
| 0–4 | jc, jmin, jmax, s1, s2 | 0..99999 | Prior uniform 5-digit cap for small timing/size params |
| 5–8 | h1–h4 | 0..4294967295 | AmneziaWG header magic is unsigned 32-bit |

Real-world AmneziaWG profiles use 9–10 digit `h1`–`h4` values (e.g. `4 10 50 130 69 149835824 1778159739 1704282148 748462068`). **Honesty:** on-device ASC-9 write-shape verification (2026-07-24, prior unit) used **small test integers only** — large header magics compile offline and are allowlisted but **NOT** live-verified at those magnitudes. A **working obfuscated tunnel** with real profile values is **NOT** yet established. Router component catalogue lists plain `wireguard` only (no Amnezia variant); whether plain `wireguard` honours obfuscation params on NC-1812 is **UNKNOWN** — upcoming bounded live attempt required.

Extended AWG 1.5/2.0 trailing `[<s3> <s4> <i1> <i2> <i3> <i4> <i5>]` documented in KeeneticOS 5.1 changelog (NDM-4298) — **not** in CLI PDF 5.0. Firmware `5.01.C.1.0-0` is 5.1 lineage → extended ASC **expected** but **UNVERIFIED** on-device. Product planner **soft-rejects** 16-arg dispatch; allowlist accepts 16 decimal tokens (each 0..4294967295) for shape completeness only.

### Secret field names (values forbidden in docs)

| Field | Role |
|---|---|
| `wireguard private-key` | Interface private key — vault secret |
| `wireguard peer … preshared-key` | Optional peer PSK — vault secret |
| `obfs-key` | Non-AWG obfuscation key (if used) — vault secret |
| Public key | **Not** a secret |

### Confidence

| Shape element | Confidence |
|---|---|
| Base WG + 9-arg `wireguard asc` | **HIGH** (CLI PDF + help.keenetic.com) |
| Extended I/S3/S4 trailing args (5.1 lineage) | **MEDIUM** (changelog; not in CLI PDF 5.0) |
| Nested RCI JSON bodies | **LOW** — prefer `{"parse":"<cli>"}` via sealed typed ops |

### Sources

- Keenetic CLI Reference OS 5.0 (KN-1011) + OS 4.3
- [help.keenetic.com WireGuard](https://help.keenetic.com/hc/en-us/articles/360001272780)
- Amnezia docs (`keenetic-os-awg`, `old-keenetic-os-awg`)
- KeeneticOS 5.1 release notes (NDM-4298 extended ASC)

---

## Next: T4 device-verification

Minimal reversible AWG write-shape verification campaign: [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md).

| Prerequisite | Status |
|---|---|
| T4 Human Gate Packet prepared | Yes — **pending human approval** |
| Sealed AWG write op + WRITE_ALLOWLIST | **Deferred T3** — execution blocked until implemented |
| WriteCertified | **Never** implied |
| `write_shapes_registered` | Remains **false** until verified trial evidence |
| Gates A/B/C/D | **Unchanged** by discovery docs delivery |

**human approval required; packet creation is not approval.**

---

## On-device write-shape verification (2026-07-24 — **prior physical unit**, superseded rebind 2026-07-31)

> **Unit context:** campaign below ran on the **prior** certified physical unit (host-key `SHA256:lU1D6ChV…`, component_set_digest `de72a7af…`). The **current** rebind unit (host-key `SHA256:RUi/peC9…`, digest `sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80`) has **`wireguard` component installed** (2026-07-31) after connectivity restored — superseded pre-WG digest `sha256:91145a82…`; see §Lab connectivity blocker — **historical** (2026-07-31).

Under human-approved T4 campaign [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md) (device owner approved 2026-07-24), a minimal reversible live verification was executed on throwaway test interface `Wireguard5` (test range 5–9; did not exist before; created then removed) via sealed `wireguard_rci` op (`scripts/wireguard-rci-op.py --execute`).

| Item | Result |
|---|---|
| Gate A preflight | PASS — exact tuple match; preflight artifact `data/artifacts/gate-a-probe-preflight-awg-20260724.json` |
| Pre-change backup | `startup-192.168.2.1-20260724T060610Z-576347f8` under `data/backups/` (DPAPI-encrypted) |
| Component install | **NOT needed on prior unit** — WireGuard component already present per `show version` |
| Steps verified | `create-interface`, `set-asc` (9-arg), `remove-interface` — each `ack_matched=true`, no error |
| Extended ASC probe | 16-integer `wireguard asc` (AWG 1.5/2.0 trailing args as plain integers) — **REJECTED** by router (error status) |
| Rollback | `show interface Wireguard5` → argument parse error (interface gone); backup `content_sha256` identical pre/post |
| `system configuration save` | **NOT** executed — running-config only; startup-config unchanged |
| Evidence | [`data/artifacts/awg-writeshape-verify-192.168.2.1-20260724.json`](../data/artifacts/awg-writeshape-verify-192.168.2.1-20260724.json) |

**Certified on-device write grammar** (firmware `5.01.C.1.0-0`, this campaign scope only):

```text
interface Wireguard<N>
interface Wireguard<N> wireguard asc <9 ints>
no interface Wireguard<N>
```

**Finding:** extended 16-integer `wireguard asc` with plain-integer trailing args is **NOT** accepted on firmware `5.01.C.1.0-0`; I1–I5 encoding (CPS/hex per documentation) **UNRESOLVED**. Interface create auto-generates wireguard keypair (public-key + listen-port) — values **not** recorded in evidence.

**Deferred (live device verification):** secret/peer/preshared-key/endpoint/allow-ips/keepalive sealed ops compile offline with path-style peer grammar (one CLI line per RCI parse request per Keenetic CLI Reference OS 5.0) and `verification_status=pending_live_verification` — **not** live-tested in asc-9 campaign. Extended ASC encoding — **not** tested in this campaign.

**Claims discipline:** `mutation_performed=true`; `configuration_saved=false`; **WriteCertified NOT claimed**; gates A/B/C/D **unchanged**; `write_shapes_registered` remains **false**.

---

## Lab connectivity blocker — **historical / resolved** (2026-07-31)

> **Status: RESOLVED.** WireGuard component installed after uplink restored; authorized Gate A identity-drift rebind #2 recorded. Section preserved for phase-1 failure archaeology — **do not** treat as current unit state.

WireGuard/AmneziaWG component install probe on expendable rebind unit **stopped phase-1 with no mutation** (before uplink restored). See [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §2a and [`STATUS.yaml`](STATUS.yaml) blocker `wg-component-lab-connectivity-20260731` (status **resolved**).

| Item | Observation |
|---|---|
| Create `Wireguard5` | Rejected: `unsupported interface type: "Wireguard"` |
| Installed set | **NO** wireguard / amneziawg |
| `components list stable` | Ends `Core::Ndss error[9240615]: [18026] no registered connection.` |
| `install wireguard` / `amneziawg` / `awg` | `Components::Lister error[24248621]: component "<name>" is unavailable.` |
| Root cause | No internet — WAN `GigabitEthernet1`/ISP link DOWN; no default route; NDSS unreachable |
| Unchanged tuple | Host key `SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY`; firmware `5.01.C.1.0-0`; digest at probe time `sha256:91145a8284…` (**superseded** — current `sha256:23bd35bc…` after post-WG rebind) |
| Backups | `data/backups/startup-192.168.2.1-20260731T155720Z-dfa1a3d2.dpapi`; `…T161438Z-e35d13d6.dpapi` |

**NOT** hardware limitation — prior unit at same address had live WG/AWG write evidence. **Lesson:** `component unavailable` ≠ unsupported.

---

## Extended ASC encoding probe (offline-ready)

Firmware `5.01.C.1.0-0` accepts the **9-integer** `wireguard asc` form on throwaway `Wireguard5–9` **when the WireGuard component is installed** — **prior physical unit** evidence (2026-07-24 T4); **current rebind unit** had phase-1 `interface Wireguard5` create rejected before component install (connectivity blocker — **resolved** 2026-07-31; component now installed). A **16-integer** trailing form with plain integers for `s3 s4 i1..i5` was **rejected on-device** (2026-07-24, prior unit). KeeneticOS 5.1 changelog (NDM-4298) suggests alternate encodings for I1–I5 (CPS/hex); these remain **UNRESOLVED** until a bounded live probe on a unit with WG component present.

### Offline candidate harness

Plan-only operator tool: `scripts/probe-nc1812-awg-asc-encoding.py` (default mode; **no** working `--execute`).

```powershell
python scripts/probe-nc1812-awg-asc-encoding.py
python scripts/probe-nc1812-awg-asc-encoding.py --wg-id Wireguard5 --base-asc "5 42 54 0 0 1 2 3 4" --trailing "0 0 10 11 12 13 14"
```

Emits sanitized JSON with Gate A tuple metadata (model `NC-1812`, firmware `5.01.C.1.0-0`, SSH pin, lab source `192.168.2.10`), `credential_ref` (**identifier only** — `cred_db65665dd59f600bdd23544d85564c83`), and a `candidates` list. Each candidate includes `encoding`, full sealed CLI string (`interface Wireguard<N> wireguard asc …`), `allowlisted` computed via existing `validate_asc_args` (fail-closed; per-position bounds jc..s2 0..99999, h1..h4 0..4294967295), and `verification_status` where applicable.

| Encoding hypothesis | Example trailing shape | `allowlisted` | `verification_status` | On-device status |
|---|---|---|---|---|
| `plain_int_9` | 9 space-separated ints | **true** | `device_verified_asc9` | **verified PASS** (2026-07-24) |
| `plain_int_16` | 16 space-separated ints | **true** | `unsupported_pending_verification` | **rejected** (plain integers; 2026-07-24) |
| `hex_i_bare` / `hex_i_0x` | s3 s4 ints + I1–I5 as hex tokens | **false** | `unsupported_pending_verification` | not probed |
| `hex_trailing_bare` / `hex_trailing_0x` | all 7 trailing as hex tokens | **false** | `unsupported_pending_verification` | not probed |
| `cps_i_comma` / `cps_i_colon` | s3 s4 ints + I1–I5 comma/colon-packed | **false** | `unsupported_pending_verification` | not probed |
| `cps_trailing_comma` / `cps_trailing_colon` | all 7 trailing comma/colon-packed | **false** | `unsupported_pending_verification` | not probed |

`--execute` is **refused** with an operator message: live extended-ASC probing requires a **bounded allowlist extension** (hex/CPS args not in current sealed template) plus an **explicit per-campaign T4 Human Gate Packet** — deferred; harness remains plan-only.

### Live extended-ASC probe (deferred T4)

| Prerequisite | Status |
|---|---|
| Offline candidate enumeration | **Ready** — `scripts/probe-nc1812-awg-asc-encoding.py` |
| Allowlist extension for non-integer asc encodings | **Deferred T3** — do not widen without principal review |
| T4 Human Gate Packet for extended-ASC live trial | **Draft prepared** — [`T4_GATE_PACKET_AWG_EXTENDED_ASC_I1_I5_2026-07-24.md`](T4_GATE_PACKET_AWG_EXTENDED_ASC_I1_I5_2026-07-24.md) (**awaiting human approval**; authorizes nothing) |
| WriteCertified | **Never** implied |
| `write_shapes_registered` | Remains **false** until verified trial evidence |

**human approval required; offline harness delivery is not live-write approval.**
