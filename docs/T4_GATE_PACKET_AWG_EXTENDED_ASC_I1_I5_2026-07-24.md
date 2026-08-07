# T4 Human Gate Packet — Extended ASC I1–I5 encoding probe (NC-1812)

## For agents

| Field | Value |
|---|---|
| `contract_id` | `nc1812-awg-extended-asc-i1-i5-encoding-probe-20260724` |
| `human_decision` | **DRAFT — awaiting explicit human T4 approval** |
| Packet status | **Draft** — packet creation **authorizes nothing** |
| WriteCertified | **Never** implied by this packet |
| Gates | A ReadOnlyCertified unchanged; B/C/D **closed** |
| Prerequisite | Offline harness ready (`scripts/probe-nc1812-awg-asc-encoding.py`); 9-arg ASC device-verified per prior campaign |

**human approval required; packet creation is not approval.**

---

## Scope

**Campaign goal:** Bounded **reversible** live probe of extended AmneziaWG `wireguard asc` **encoding hypotheses** (hex/CPS I1–I5 variants and re-confirmation of plain-16 rejection) on dedicated lab NC-1812 — **not** WriteCertified pursuit; **not** production VPN deployment; **not** approving extended-ASC shapes for product allowlist.

**Blast radius:** Additive unbound test `interface Wireguard<N>` only (`Wireguard5`–`Wireguard9`); fully removable; **no** component install, **no** reboot, **no** changes to production Wi-Fi, routes, or home/guest bridges.

**Precondition:** WireGuard/AmneziaWG component **must already be present** on the router (confirmed in prior asc-9 campaign).

**Forbidden:** generic/raw RCI passthrough on product surface; WriteCertified claims; opening Gate D; `system configuration save`; formal production write-shape registration for hex/CPS encodings without separate Gate B evidence path.

### Encoding candidates (from offline harness)

Enumerate with `scripts/probe-nc1812-awg-asc-encoding.py` (plan-only default). **If and when this packet is explicitly approved by a human**, a live trial may attempt candidates marked `verification_status=unsupported_pending_verification` under that approval — results feed evidence; success does **not** auto-register shapes.

| Encoding hypothesis | Allowlisted (current) | Prior on-device |
|---|---|---|
| `plain_int_9` | **true** | **PASS** (2026-07-24) |
| `plain_int_16` | **true** | **REJECTED** (plain integers; 2026-07-24) |
| `hex_i_bare` / `hex_i_0x` | **false** | not probed |
| `hex_trailing_bare` / `hex_trailing_0x` | **false** | not probed |
| `cps_i_comma` / `cps_i_colon` | **false** | not probed |
| `cps_trailing_comma` / `cps_trailing_colon` | **false** | not probed |

### Verification sequence (exact CLI grammar)

Use next free throwaway index in **`Wireguard5`–`Wireguard9`** (default harness: `Wireguard5`).

1. **Gate A preflight** — identity tuple + host-key pin + source bind (see Identity below).

2. **Pre-change backup** — `scripts/backup-router-startup.py` → `data/backups/` (relative path only).

3. **Create test interface** (minimal — no secret peer tunnel required for asc encoding probe):

```text
interface Wireguard5
up
```

4. **9-arg ASC baseline** (confirm prior PASS still holds):

```text
wireguard asc <jc> <jmin> <jmax> <s1> <s2> <h1> <h2> <h3> <h4>
```

5. **Extended ASC encoding trials** — one candidate at a time; record accept/reject per encoding hypothesis from offline harness PLAN output. Example shapes (exact strings from harness `--wg-id` / `--trailing` PLAN):

```text
wireguard asc <9 base ints> <s3> <s4> <i1> <i2> <i3> <i4> <i5>
wireguard asc <9 base ints> <s3> <s4> <hex i1..i5 variants>
wireguard asc <9 base ints> <hex trailing variants>
wireguard asc <9 base ints> <s3> <s4> <i1,i2,... CPS variants>
```

6. **RO read-back** — Gate A allowlisted reads only; responses sanitized via `sanitize_mapping`.

7. **Full removal:**

```text
no interface Wireguard5
```

**Do NOT run** `system configuration save`.

8. **Post-removal RO read** — confirm no test Wireguard iface remains.

**No generic/raw RCI.** Dispatch only via sealed typed ops or operator-approved bounded CLI under this packet.

---

## Identity

### Pre-flight (mandatory before any write)

| Check | Requirement |
|---|---|
| Enrolled `RouterId` | Matches lab NC-1812 enrollment in prototype host / operator records |
| STATUS `gates.A.tuple` | `model=NC-1812`, `firmware_version=5.01.C.1.0-0`, `transport=ssh_tunnel` |
| Gate A reprobe | `py.exe -3.11 scripts/probe-gate-a.py --host 192.168.2.1 --ssh-tunnel --ssh-host-key-sha256 SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM --source-address 192.168.2.10` |
| Host-key pin | Must match Gate A SSOT: `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM` |
| Source bind | **`192.168.2.10`** mandatory on all live CLIs |
| Credential ref | `cred_db65665dd59f600bdd23544d85564c83` — **reference id only**; operator supplies via vault/DPAPI; **no** secret material in packet or evidence |

Tuple drift → **fail-closed**; do not proceed.

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

| Scenario | Compensation |
|---|---|
| Test iface created | `no interface Wireguard<N>` — **no** `system configuration save` |
| Partial apply / error mid-sequence | Disarm fail-safe when stable; restore from pre-change backup under `data/backups/` if compensation insufficient |
| Fail-safe tooling | `scripts/fail-safe-rci-cycle.py` (sealed arm/disarm via typed ops) — arm before disruptive write steps (iface create/remove) |

**Blast radius:** additive test WireGuard iface only — fully reversible when removal succeeds; **no** install/reboot in this campaign.

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

| Step | Requirement |
|---|---|
| Removal verified | RO read confirms no test Wireguard iface |
| Gate A reprobe | Same tuple + source bind + host-key pin |
| Evidence | Sanitized artifact under `data/artifacts/` — secret field names redacted; **no** raw private keys |
| STATUS update | **Only** when a gate actually changes — this probe alone does **not** claim WriteCertified or set `write_shapes_registered=true` |
| Shape registration | Candidate shape promotion to registry requires separate Gate B evidence path — **not** implied here |

---

## WriteCertified

**WriteCertified never implied.**

This packet (when approved) would authorize a **single** minimal reversible extended-ASC encoding probe on dedicated lab hardware. Success does **not**:

- Claim WriteCertified for AmneziaWG or WireGuard
- Set `write_shapes_registered=true`
- Open Gate B/C/D without explicit STATUS update
- Auto-register hex/CPS encodings in production WRITE_ALLOWLIST

---

## Deferred prerequisites (blocking live `--execute`)

| Item | Tier |
|---|---|
| Human approval of **this** draft packet | **T4** |
| Bounded allowlist extension for hex/CPS asc args (if trial proceeds via product path) | **T3** — separate review |
| Harness `--execute` path wired to sealed typed ops | **T3** |

Packet creation ≠ T3 implementation ≠ human approval. All required before live `--execute` on harness or product surface.

---

## Related docs

- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — RO discovery + offline encoding harness
- [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md) — prior asc-9 campaign (executed)
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — §4 packet elements; §7a isolation
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed typed dispatch pattern
- [`STATUS.yaml`](STATUS.yaml) — gates SSOT
