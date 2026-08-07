# T4 Human Gate Packet — Wi-Fi write-shape verification (NC-1812)

## For agents

| Field | Value |
|---|---|
| `contract_id` | `nc1812-wifi-writeshape-verify-20260723` |
| `human_decision` | **approved-and-executed** (2026-07-24, device owner) — **ssid/up/down/no-ssid scope only** |
| Packet status | Approved 2026-07-24; ssid/up/down/no-ssid campaign **executed and rolled back** — see Execution record below |
| WriteCertified | **Never** implied by this packet |
| Gates | A ReadOnlyCertified unchanged; B `completed_failed`; C/D **closed** until this packet is approved and Gate C window opened |
| Prerequisite | **execution requires deferred-T3 sealed write path** (sealed Wi-Fi typed op + WRITE_ALLOWLIST + WifiIntent extension) |

**human approval required; packet creation is not approval.**

---

## Execution record (2026-07-24)

| Field | Value |
|---|---|
| `human_decision` | **approved** by device owner (2026-07-24) |
| Executor | Agent under per-step reporting |
| Gate A preflight | PASS — exact tuple match (`data/artifacts/gate-a-probe-preflight-wifi-20260724.json`) |
| Target | `WifiMaster0/AccessPoint3` (unused test AP) |
| Steps executed | `set-ssid`, `up`, `down`, `clear-ssid` (no ssid) — all PASS, `ack_matched=true` |
| Rollback | Full — final readback identical to baseline (down, no ssid, disabled) |
| `system configuration save` | **NOT** executed |
| Pre-change backup | `startup-192.168.2.1-20260724T054149Z-59eb11d7` under `data/backups/` |
| Evidence | `data/artifacts/wifi-writeshape-verify-192.168.2.1-20260724.json` |
| WPA / encryption | **NOT** executed in ssid/up phase — see WPA phase below |
| WriteCertified | **NOT** claimed |
| Gates | A/B/C/D **unchanged** |

### WPA / encryption phase (2026-07-24)

| Field | Value |
|---|---|
| `contract_id` | `nc1812-wifi-wpa-writeshape-verify-20260724` |
| Scope | Extends approved T4 campaign — WPA-PSK + `encryption enable` + `encryption wpa2` on same unused AP |
| Steps executed | `set-ssid`, `set-wpa-psk` (vault `--psk-credential-ref`), `encryption-enable`, `encryption-wpa2`, `up` — all PASS, `ack_matched=true` |
| PSK handling | Throwaway vault credential; generated internally; never exposed; deleted after |
| Runtime readback | state=up, ssid present, `encryption=wpa2`, PSK **not** in readback |
| Rollback | `down`, `no encryption enable`, `no encryption wpa2`, `no authentication wpa-psk`, `no ssid` — full rollback verified (baseline restored) |
| `system configuration save` | **NOT** executed |
| Pre-change backup | Same as ssid/up phase — startup unchanged (`content_sha256` match) |
| Evidence | `data/artifacts/wifi-wpa-writeshape-verify-192.168.2.1-20260724.json` |
| Sealed ops | `encryption-wpa2-clear` (`no encryption wpa2`) added for complete rollback via sealed ops |
| WriteCertified | **NOT** claimed |
| Gates | A/B/C/D **unchanged** |

---

## Scope

**Campaign goal:** Minimal **reversible** on-device verification of documentation-sourced Wi-Fi AccessPoint CLI write-shape on dedicated lab NC-1812 — **not** WriteCertified pursuit; **not** production SSID deployment.

**Target interface:** **Unused** AccessPoint only — e.g. `WifiMaster0/AccessPoint3` (observed **down/unused** in RO inventory 2026-07-23).

**Forbidden targets:** `AccessPoint0`, `AccessPoint_5G`, `GuestWiFi`, `GuestWiFi_5G`, or any AP bound to Home/Guest production SSIDs.

**Blast radius:** Unused AP only; unbound from Home bridge; fully reversible; **no** captive portal / Chilli changes in this campaign.

**Forbidden:** generic/raw RCI passthrough; plaintext PSK in docs or artifacts; WriteCertified claims; opening Gate D.

### Typed capability family (once T3 sealed op exists)

Prefer sealed typed ops dispatching `{"parse":"<cli>"}` — **no** raw POST passthrough. Until T3 delivery, this packet documents exact CLI strings for allowlist registration.

### Verification sequence

1. **Configure test SSID** on unused AP (vault test credential — **no** plaintext PSK in docs):

```text
interface AccessPoint3
  ssid "RC-TEST-<suffix>"
  authentication wpa-psk <VAULT_TEST_CREDENTIAL_REF>
  encryption enable
  encryption wpa2
  up
```

`<suffix>` — operator-chosen short unique token (e.g. date/hour); must not collide with production SSIDs.

2. **Do NOT bind to Home bridge** — leave unbound or in disposable test context; **no** `interface Bridge0 include AccessPoint3`.

3. **RO read-back** — Gate A allowlisted reads; sanitized artifact (`authentication wpa-psk` / `wpa_psk` / `passphrase` redacted by hardened sanitizer; `ssid` / `encryption` preserved).

4. **Full removal:**

```text
interface AccessPoint3
  no ssid
  no authentication wpa-psk
  down
system configuration save
```

5. **Unbind cleanup** (if any accidental bind occurred):

```text
interface Bridge0
  no include AccessPoint3
system configuration save
```

6. **Post-removal RO read** — confirm AP down/unused state restored.

**No generic/raw RCI.** Dispatch only via sealed typed ops once T3 implements Wi-Fi write family.

---

## Identity

### Pre-flight (mandatory before any write)

| Check | Requirement |
|---|---|
| Enrolled `RouterId` | Matches lab NC-1812 enrollment |
| STATUS `gates.A.tuple` | `model=NC-1812`, `firmware_version=5.01.C.1.0-0`, `transport=ssh_tunnel` |
| Gate A reprobe | `py.exe -3.11 scripts/probe-gate-a.py --host 192.168.2.1 --ssh-tunnel --ssh-host-key-sha256 SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM --source-address 192.168.2.10` |
| Host-key pin | `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM` |
| Source bind | **`192.168.2.10`** mandatory |
| Evidence sha256 | `24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3` |
| AP selection | Confirm target AP is **down/unused** via RO inventory — not production alias |

Tuple drift → **fail-closed**.

### §7a WAN / topology isolation (mandatory)

Before write dispatch, satisfy **one** of:

- `proven_wan_isolated` from `scripts/probe-nc1812-topology.py`, **or**
- **Physical uplink disconnect** (cable stays disconnected for campaign)

Plus: source-bind `192.168.2.10`; host-key pin match Gate A.

---

## Backup

| Item | Requirement |
|---|---|
| Timing | **Before** first write |
| Method | `scripts/backup-router-startup.py` — encrypted startup-config via pinned SSH |
| Storage | **`data/backups/`** only (`.dpapi` + `.meta.json`) — **no** absolute paths |
| Vault | DPAPI `--credential-ref`; record `content_sha256` + `size_bytes` |
| SSOT | Backup alone does **not** open Gates B/C/D |

---

## Fail-safe / rollback

| Scenario | Compensation |
|---|---|
| Test SSID applied | `no ssid` + `no authentication wpa-psk` + `down` + save |
| Accidental bridge bind | `no include AccessPoint3` on Bridge0/Bridge1 + save |
| Error mid-sequence | Disarm fail-safe if armed; restore from pre-change backup under `data/backups/` if needed |
| Fail-safe tooling | `scripts/fail-safe-rci-cycle.py` for disruptive steps (if any) |

**Blast radius:** unused AP only — reversible when removal + save succeed.

---

## Gate C

Time-bounded laboratory window — **opens only after human approval**.

| Field | Value |
|---|---|
| `opens_at` | **TBD** — human sets at approval (UTC) |
| `expires_at` | **TBD** — recommended ≤ 60 minutes |
| Scope | Dedicated lab; unused AP only |
| Status until approval | Gate C **closed** |

---

## Gate D

**Closed.** No production Wi-Fi dispatch.

---

## Post-test

| Step | Requirement |
|---|---|
| AP state restored | RO read confirms unused/down AP; no `RC-TEST-*` SSID |
| Gate A reprobe | Tuple + source bind + host-key pin |
| Evidence | Sanitized artifact under `data/artifacts/` — PSK field names redacted |
| STATUS update | **Only** when a gate actually changes — no WriteCertified; `write_shapes_registered` remains **false** |
| WifiIntent | Domain extension (wpa_mode/encryption/band) remains **deferred T3** even after successful verification |

---

## WriteCertified

**WriteCertified never implied.**

Success does **not** claim WriteCertified for Wi-Fi, set `write_shapes_registered=true`, or open Gate B without separate evidence path.

---

## Deferred T3 prerequisites (blocking execution)

| Item | Tier |
|---|---|
| Sealed Wi-Fi write typed op(s) | **T3** |
| WRITE_ALLOWLIST registration | **T3** |
| `WifiIntent` extension (`wpa_mode`, `encryption`, `band`) | **T3** |
| Operator CLI validate-default + `--execute` | **T3** |

Packet creation ≠ T3 implementation ≠ human approval.

---

## Related docs

- [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) — RO evidence + candidate shape
- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — shared RO artifact reference
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — §4; §7a
- [`STATUS.yaml`](STATUS.yaml) — gates SSOT
