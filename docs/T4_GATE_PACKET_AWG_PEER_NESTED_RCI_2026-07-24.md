# T4 Human Gate Packet — AWG peer nested-RCI live re-probe (NC-1812)

## For agents

| Field | Value |
|---|---|
| `contract_id` | `nc1812-awg-peer-nested-rci-live-probe-20260724` |
| `human_decision` | **EXECUTED 2026-07-24** under explicit human T4 approval — campaign outcome **REJECTED** (see Campaign outcome below) |
| Packet status | **Executed** — human-approved per-campaign T4 ran 2026-07-24; result REJECTED; packet creation **authorized nothing** until human approval (obtained for this campaign) |
| WriteCertified | **Never** implied by this packet |
| Gates | A ReadOnlyCertified unchanged; B/C/D **closed** |
| Prerequisite | Additive `peer_rci_shape=nested_rci` transport **offline-ready (T3 code)**; private-key path-style **partially device-verified** (2026-07-24 prior campaign) |

**human approval required; packet creation is not approval.**

### Campaign outcome (2026-07-24)

| Field | Value |
|---|---|
| Executed | **2026-07-24** under explicit human T4 approval |
| Target | `Wireguard5` on NC-1812 (`192.168.2.1`, source `192.168.2.10`); additive `peer_rci_shape=nested_rci` web-E2E transport |
| Result | **REJECTED** — `wireguard_create_interface` ok; `wireguard_set_private_key` ok (private-key transport re-confirmed); `wireguard_upsert_peer_nested` **FAILED** (op dispatch failed); probe posted **OLD** pubkey-keyed flat nested body (not current array/`key` shape) |
| Teardown | interface_down ok; remove_interface ok → baseline restored (readback `{}`); `clear_private_key`/`remove_peer` dispatch failed but interface removal guaranteed cleanup |
| Config save | **No** — `system_configuration_saved=false` |
| Credentials | Throwaway private-key + preshared-key enrolled for probe only; **deleted** after teardown (confirmed absent); no secrets in evidence |
| Evidence | `data/artifacts/awg-peer-nested-rci-live-verify-192.168.2.1-20260724.json` |
| Gate/cert impact | **None** — WriteCertified NOT claimed; `write_shapes_registered` remains **false**; Gates A/B/C/D unchanged; peer still `pending_live_verification`; nested body **corrected offline 2026-07-24** to array/`key` shape — **NEW live re-verify T4 required** |

---

## Scope

**Campaign goal:** Bounded **reversible** live re-probe of the additive `peer_rci_shape=nested_rci` transport — sealed nested RCI JSON body under `interface.WireguardN.wireguard.peer[]` (array of objects with `"key"` = pubkey; nested `endpoint`/`allow-ips`/`keepalive-interval`/`preshared-key`) — on dedicated lab NC-1812. **Not** WriteCertified pursuit; **not** production VPN deployment; **not** formal Gate B evidence.

**Body shape note (2026-07-24 offline correction):** The 2026-07-24 executed campaign posted the **OLD** wrong shape (`peer.<pubkey>` flat scalars). Offline code now emits the Keenetic-accepted array/`key` nested objects (ivansible/ndm-wireguard show-rc template). Any **new** live probe must use the corrected body — requires a **new T4 Human Gate Packet** (this packet documents the prior REJECTED attempt only).

**Rationale:** Prior AWG secret-tunnel live probe on `Wireguard5` (2026-07-24) **PARTIAL** — `wireguard private-key` (path-style) **ACCEPTED**; path-style `wireguard peer` single-line dispatch **REJECTED** (peer requires nested RCI resource write). Evidence: `data/artifacts/awg-secret-tunnel-wireguard5-live-probe-192.168.2.1-20260724.json` (sanitized; gitignored). This packet authorizes **only** a minimal nested-RCI peer write re-probe under bounded test interface — **if and when explicitly approved by a human**.

**Blast radius:** Additive unbound test `interface Wireguard<N>` only (`Wireguard5`–`Wireguard9`); fully removable; **no** component install, **no** reboot, **no** changes to production Wi-Fi, routes, or home/guest bridges.

**Precondition:** WireGuard/AmneziaWG component **must already be present** on the router (confirmed in prior asc-9 / secret-tunnel campaigns).

**In scope (bounded):**

| Resource | Scope |
|---|---|
| WireGuard test interfaces | `Wireguard5`–`Wireguard9` only (default campaign target: **`Wireguard5`**) |
| Peer transport | `peer_rci_shape=nested_rci` sealed nested JSON upsert only |
| Private-key transport | Path-style `SET_PRIVATE_KEY` (already partially device-verified; same grammar as prior probe) |

**Out of scope / hard-blocked:**

| Resource | Status |
|---|---|
| `Wireguard0`–`Wireguard4` | **Out of scope** |
| All Wi-Fi APs (`WifiMaster0/AccessPoint*`) | **Out of scope** |
| `AccessPoint0` / `AccessPoint1` / `AccessPoint2` | **Hard-blocked** (n/a for this campaign) |
| `system configuration save` | **Forbidden** |
| Generic/raw RCI passthrough | **Forbidden** |

**Forbidden:** WriteCertified claims; opening Gate D; setting `write_shapes_registered=true`; treating a single probe as formal Gate B evidence; embedding plaintext private-key, PSK, password, or session material in packet or evidence.

### Verification sequence (safe pattern)

Use next free throwaway index in **`Wireguard5`–`Wireguard9`** (default: **`Wireguard5`**). Dispatch only via sealed typed ops or operator-approved bounded CLI under this packet — **no** generic/raw RCI.

1. **Sealed op + review** — confirm nested-RCI peer op (`wireguard_upsert_peer_nested`) and allowlist bounds before live dispatch.

2. **Gate A preflight** — identity tuple + host-key pin + source bind (see Identity below). **Any mismatch → STOP (fail-closed).**

3. **Pre-change backup** — `scripts/backup-router-startup.py` → `data/backups/` (relative path only).

4. **Fail-safe arm** (when disruptive steps apply) — `scripts/fail-safe-rci-cycle.py` sealed arm via typed ops.

5. **Create bounded test interface** (minimal):

```text
interface Wireguard5
```

6. **Private-key** (path-style — partially device-verified grammar; vault-resolved at dispatch only):

```text
wireguard private-key <VAULT_RESOLVED_AT_DISPATCH_ONLY>
```

7. **Nested-RCI peer write** (`peer_rci_shape=nested_rci`) — sealed POST `/rci/` body (not `[{"parse":…}]`). **Use corrected array/`key` shape** (not the OLD pubkey-keyed flat body used in the 2026-07-24 REJECTED probe):

```json
{
  "interface": {
    "Wireguard5": {
      "wireguard": {
        "peer": [
          {
            "key": "<TEST_PEER_PUBLIC_KEY>",
            "endpoint": { "address": "test.example.invalid:51820" },
            "allow-ips": [
              { "address": "10.99.99.2", "mask": "255.255.255.255" }
            ],
            "keepalive-interval": { "interval": 25 },
            "preshared-key": "<VAULT_RESOLVED_AT_DISPATCH_ONLY>"
          }
        ]
      }
    }
  }
}
```

`<TEST_PEER_PUBLIC_KEY>` — operator supplies a **non-production** test public key from vault/fixture — **never** embed a real key value in docs. PSK resolved from `preshared_key_credential_ref_id` at dispatch only — **reference id only** in logs/evidence.

8. **Readback verify** — Gate A allowlisted reads; confirm nested peer body presence + `ack_matched=true` on write envelope; responses sanitized via `sanitize_mapping`.

9. **Rollback (teardown best-effort)** — down → remove peer (path-style `REMOVE_PEER`) → clear private-key (best-effort) → `no interface Wireguard5`. **Do NOT run** `system configuration save`.

10. **Post-removal RO read** — confirm no test Wireguard iface remains.

11. **Evidence** — sanitized artifact under `data/artifacts/` — proposed basename: `awg-peer-nested-rci-live-verify-192.168.2.1-YYYYMMDD.json` (secret field names redacted; **no** raw private keys or PSK).

**No generic/raw RCI.** Dispatch only via sealed typed ops or operator-approved bounded CLI under this packet.

---

## Identity

### Pre-flight (mandatory before any write)

| Check | Requirement |
|---|---|
| Enrolled `RouterId` | Matches lab NC-1812 enrollment in prototype host / operator records |
| Model | **`NC-1812`** |
| Firmware | **`5.01.C.1.0-0`** |
| STATUS `gates.A.tuple` | `model=NC-1812`, `firmware_version=5.01.C.1.0-0`, `transport=ssh_tunnel` |
| Host | **`192.168.2.1`** |
| Source bind | **`192.168.2.10`** mandatory on all live CLIs |
| Gate A reprobe | `py.exe -3.11 scripts/probe-gate-a.py --host 192.168.2.1 --ssh-tunnel --ssh-host-key-sha256 SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM --source-address 192.168.2.10` |
| Host-key pin | Must match Gate A SSOT: **`SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM`** |
| Credential ref | `cred_db65665dd59f600bdd23544d85564c83` — **reference id only**; DPAPI vault; valid only under the enrolling OS user; operator supplies via vault/DPAPI; **no** password, PSK, or private-key material in packet or evidence |

**Any** identity, firmware, host-key, source-bind, or host mismatch → **fail-closed**; do not proceed.

### §7a WAN / topology isolation (mandatory)

Before write dispatch, satisfy **one** of:

- `proven_wan_isolated` from non-certifying topology discovery (`scripts/probe-nc1812-topology.py`), **or**
- **Physical uplink disconnect** between working router and test router (cable remains disconnected for campaign duration)

Plus: source-bind `192.168.2.10`; host-key pin match Gate A.

---

## Backup

| Item | Requirement |
|---|---|
| Timing | **Before** first write in this campaign |
| Method | `scripts/backup-router-startup.py` — encrypted startup-config via pinned SSH |
| Storage | Artifacts under **`data/backups/`** only (`.dpapi` + `.meta.json`) — **no** absolute paths in packet or docs |
| Vault | DPAPI `--credential-ref cred_db65665dd59f600bdd23544d85564c83`; record `content_sha256` + `size_bytes` in campaign log |
| SSOT | Backup alone does **not** open Gates B/C/D |

---

## Fail-safe / rollback

### Abort criteria (immediate STOP)

| Condition | Action |
|---|---|
| Identity / host-key / source-bind mismatch | **STOP** — no writes |
| Unexpected ack envelope or `ack_matched=false` | **STOP** + rollback |
| Readback divergence from expected nested peer body | **STOP** + rollback |
| Any dispatch error mid-sequence | **STOP** + rollback |
| Out-of-scope interface targeted (`Wireguard0`–`Wireguard4`, Wi-Fi AP) | **STOP** — campaign violation |

On abort: disarm fail-safe when stable; execute teardown best-effort; restore from pre-change backup under `data/backups/` if compensation insufficient; **do NOT** run `system configuration save`.

### Compensation

| Scenario | Compensation |
|---|---|
| Test iface + peer created | Teardown best-effort: down → remove peer → clear private-key (best-effort) → `no interface Wireguard5` — **no** `system configuration save` |
| Partial apply / error mid-sequence | Disarm fail-safe when stable; restore from pre-change backup under `data/backups/` if compensation insufficient |
| Fail-safe tooling | `scripts/fail-safe-rci-cycle.py` (sealed arm/disarm via typed ops) — arm before disruptive write steps |

**Blast radius:** additive test WireGuard iface + bounded peer only — fully reversible when removal succeeds; **no** install/reboot in this campaign.

---

## Gate C

Time-bounded laboratory window — **opens only after human approval of this packet**.

| Field | Value |
|---|---|
| `opens_at` | **TBD** — set by human operator at approval time (UTC) |
| `expires_at` | **TBD** — recommended ≤ 60 minutes from `opens_at` |
| Scope | Dedicated lab NC-1812 only; no production Gate D |
| Status until approval | Gate C **closed** |

---

## Gate D

**Closed.** Production-only gate — no production dispatch authorized by this packet.

---

## Post-test

**Campaign executed 2026-07-24 (initial probe):** result **REJECTED** (op dispatch failed on `wireguard_upsert_peer_nested`; probe used **OLD** pubkey-keyed flat body); baseline restored; no config save; evidence `data/artifacts/awg-peer-nested-rci-live-verify-192.168.2.1-20260724.json`.

**Re-verify executed 2026-07-24 (corrected array/`key` shape):** result **ACCEPTED (device-verified write)** — `wireguard_upsert_peer_nested` ack matched + interface applied/up; baseline restored via teardown (`wireguard_remove_interface` guaranteed cleanup); standalone `clear_private_key` **FAILED** (KNOWN quirk, non-blocking); no config save; evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`. Private-key transport re-confirmed partially device-verified. **NOT** tunnel connectivity; **NOT** WriteCertified; **NOT** `write_shapes_registered=true`; **NOT** Gate B open.

| Step | Requirement |
|---|---|
| Removal verified | RO read confirms no test Wireguard iface |
| Gate A reprobe | Same tuple + source bind + host-key pin |
| Evidence | Sanitized artifact under `data/artifacts/` — proposed: `awg-peer-nested-rci-live-verify-192.168.2.1-YYYYMMDD.json`; secret field names redacted; **no** raw private keys or PSK |
| STATUS update | **Only** when a gate actually changes — this probe alone does **not** claim WriteCertified or set `write_shapes_registered=true` |
| Shape registration | Nested-RCI peer shape promotion to registry requires separate Gate B evidence path — **not** implied here; a single probe is **not** formal Gate B evidence |

### Explicit post-conditions (this packet alone)

| Field | Post-condition |
|---|---|
| `write_shapes_registered` | Remains **`false`** — success does **not** flip |
| WriteCertified | **NOT** claimed for AWG secret tunnel or WireGuard |
| Gate B | **NOT** opened — single probe ≠ formal Gate B evidence |
| Gate C / Gate D | Remain **closed** unless separate STATUS update after distinct gate authorization |

---

## WriteCertified

**WriteCertified never implied.**

This packet (when approved) would authorize a **single** minimal reversible nested-RCI peer re-probe on dedicated lab hardware. Success does **not**:

- Claim WriteCertified for AmneziaWG or WireGuard secret tunnel
- Set `write_shapes_registered=true`
- Open Gate B/C/D without explicit STATUS update
- Fully device-certify AWG secret tunnel (peer + preshared-key remain subject to evidence review)
- Substitute for deferred formal Gate B write-shape registration

---

## Deferred prerequisites (blocking live execution)

| Item | Tier |
|---|---|
| Human approval of **this** draft packet | **T4** |
| Nested-RCI transport code (`peer_rci_shape=nested_rci`) | **T3** — delivered offline (2026-07-24) |
| Live `--execute` / apply with `confirm_live_apply: true` | **T4** — requires human approval of this packet |

Packet creation ≠ T3 implementation ≠ human approval. All required before live nested-RCI peer re-probe on product surface or bounded operator CLI.

---

## Human approval (operator — leave UNCHECKED until explicit sign-off)

> **DRAFT:** All boxes **unchecked**. Checking boxes without explicit human action **does not** constitute approval. Program authorization ([`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §2) **≠** this campaign.

| Field | Operator entry |
|---|---|
| Operator name | _________________________________ |
| Approval date (UTC) | _________________________________ |

- [ ] I confirm I am physically present at the dedicated NC-1812 lab for this campaign.
- [ ] I confirm network reachability to **`192.168.2.1`** from source bind **`192.168.2.10`** (Ethernet lab path).
- [ ] I confirm the identity tuple matches: **NC-1812** / firmware **5.01.C.1.0-0** / host-key **`SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM`**.
- [ ] I confirm DPAPI credential vault is unlocked for ref **`cred_db65665dd59f600bdd23544d85564c83`** under the enrolling OS user (password **not** in repo).
- [ ] I confirm §7a isolation: `proven_wan_isolated` **or** physical uplink disconnect for campaign duration.
- [ ] I have read this packet scope, bounds (`Wireguard5`–`Wireguard9` only), abort/rollback criteria, and post-conditions.
- [ ] I **explicitly approve** execution of **this** per-campaign T4 packet — **not** program authorization alone.

Until all applicable boxes are checked and dated by the operator, **`human_decision` remains DRAFT** and live execution is **forbidden**.

---

## Related docs

- [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md) — nested-RCI peer shape; apply/teardown; credential-ref-only
- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — RO discovery + prior secret-tunnel deferral
- [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md) — prior asc-9 campaign (executed)
- [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md) — §14.3 partial secret-tunnel evidence; §14.5 next T4
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — §4 packet elements; §7a isolation
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed typed dispatch pattern
- [`contracts/RCI_POLICY.md`](contracts/RCI_POLICY.md) — nested JSON allowlist bounds
- [`STATUS.yaml`](STATUS.yaml) — gates SSOT
