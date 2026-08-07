# T4 Human Gate Packet — AmneziaWG write-shape verification (NC-1812)

## For agents

| Field | Value |
|---|---|
| `contract_id` | `nc1812-awg-writeshape-verify-20260723` |
| `human_decision` | **approved-and-executed** (2026-07-24, device owner) — **create/asc-9/remove scope only** |
| Packet status | Approved 2026-07-24; create/asc-9/remove campaign **executed and rolled back** — see Execution record below |
| WriteCertified | **Never** implied by this packet |
| Gates | A ReadOnlyCertified unchanged; B `completed_failed`; C/D **closed** |
| Prerequisite | Sealed AWG write path delivered (sealed `wireguard_rci` op + WRITE_ALLOWLIST) |

**human approval required; packet creation is not approval.**

---

## Execution record (2026-07-24)

| Field | Value |
|---|---|
| `human_decision` | **approved** by device owner (2026-07-24) |
| Executor | Agent under per-step reporting |
| Component install | **NOT** needed — WireGuard component already present per `show version` |
| Gate A preflight | PASS — exact tuple match (`data/artifacts/gate-a-probe-preflight-awg-20260724.json`) |
| Target | `Wireguard5` (throwaway test interface; test range 5–9; created then removed) |
| Steps executed | `create-interface`, `set-asc` (9-arg), `remove-interface` — all PASS, `ack_matched=true` |
| Extended ASC probe | 16-integer `wireguard asc` — **REJECTED** (error status); I1–I5 plain-integer encoding unresolved |
| Rollback | Full — `show interface Wireguard5` → argument parse error (interface gone); backup `content_sha256` unchanged |
| `system configuration save` | **NOT** executed |
| Pre-change backup | `startup-192.168.2.1-20260724T060610Z-576347f8` under `data/backups/` |
| Evidence | `data/artifacts/awg-writeshape-verify-192.168.2.1-20260724.json` |
| Secret-bearing WG ops | **NOT** executed — deferred (`private-key`, `peer`, `preshared-key`, `endpoint`, `allow-ips`, `keepalive`) |
| WriteCertified | **NOT** claimed |
| Gates | A/B/C/D **unchanged** |

---

## Scope

**Campaign goal:** Minimal **reversible** on-device verification of documentation-sourced AmneziaWG/WireGuard CLI write-shape on dedicated lab NC-1812 — **not** WriteCertified pursuit; **not** production VPN deployment.

**Blast radius:** Additive unbound test `interface Wireguard<N>` only; fully removable; **no** component install, **no** reboot, **no** changes to production Wi-Fi, routes, or home/guest bridges.

**Precondition:** WireGuard/AmneziaWG component **must already be present** on the router before this write-shape verify campaign proceeds.

**Forbidden:** generic/raw RCI passthrough on product surface; WriteCertified claims; opening Gate D; **component install + reboot** (out of scope — see Pre-check below).

### Typed capability family (once T3 sealed op exists)

Prefer sealed typed ops dispatching `{"parse":"<cli>"}` bodies — **no** raw POST passthrough. Until T3 delivery, this packet documents exact CLI strings for allowlist registration.

### Pre-check: WireGuard / AmneziaWG component

| Step | Action |
|---|---|
| RO read | Confirm WireGuard/AmneziaWG component present via Gate A reads |
| If absent | **STOP** — do **not** proceed with this campaign; do **not** install or reboot under this packet |
| If absent (operator path) | Component install + reboot are **OUT OF SCOPE** for this packet and require a **separate exact T4 Human Gate Packet** with exact install commands (typed install family + reboot window) before any write-shape verify campaign may run |

### Verification sequence (exact CLI grammar)

Use next free index if `Wireguard0` occupied (e.g. `Wireguard1`).

1. **Create test interface** (vault test private-key — **no** plaintext in docs):

```text
interface Wireguard0
ip address 10.99.99.1 255.255.255.255
wireguard private-key <VAULT_TEST_PRIVATE_KEY>
wireguard peer <TEST_PEER_PUBLIC_KEY> {
  endpoint test.example.invalid:51820
  keepalive-interval 25
  allow-ips 10.99.99.2 255.255.255.255
}
up
```

`<TEST_PEER_PUBLIC_KEY>` — documented test placeholder only; operator supplies a **non-production** test public key from vault/fixture — **never** invent or embed a real key value in docs.

2. **Obfuscation 9-arg ASC** (documented base shape):

```text
wireguard asc <jc> <jmin> <jmax> <s1> <s2> <h1> <h2> <h3> <h4>
```

Use test obfuscation parameters from operator-approved test vector (not production profile).

3. **Extended ASC probe (5.1 lineage — optional in same window):**

```text
wireguard asc <jc> <jmin> <jmax> <s1> <s2> <h1> <h2> <h3> <h4> <s3> <s4> <i1> <i2> <i3> <i4> <i5>
```

Record accept/reject — confirms or refutes extended AWG 1.5/2.0 trailing args on firmware `5.01.C.1.0-0`.

4. **RO read-back** — Gate A allowlisted reads only; responses sanitized via `sanitize_mapping` (private-key / preshared-key redacted; public-key preserved).

5. **Full removal:**

```text
no interface Wireguard0
system configuration save
```

6. **Post-removal RO read** — confirm no Wireguard test iface remains.

**No generic/raw RCI.** Dispatch only via sealed typed ops once T3 implements AWG write family.

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
| Evidence sha256 | Current SSOT: `24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3` (`gate-a-return-home-192.168.2.1-20260723.json`) |

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
| Vault | DPAPI `--credential-ref`; record `content_sha256` + `size_bytes` in campaign log |
| SSOT | Backup alone does **not** open Gates B/C/D |

---

## Fail-safe / rollback

| Scenario | Compensation |
|---|---|
| Test iface created | `no interface Wireguard<N>` + `system configuration save` |
| Partial apply / error mid-sequence | Disarm fail-safe when stable; restore from pre-change backup under `data/backups/` if compensation insufficient |
| Fail-safe tooling | `scripts/fail-safe-rci-cycle.py` (sealed arm/disarm via typed ops) — arm before disruptive write steps (iface create/remove/save) |

**Blast radius:** additive test WireGuard iface only — fully reversible when removal + save succeed; **no** install/reboot in this campaign.

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
| STATUS update | **Only** when a gate actually changes — this verification alone does **not** claim WriteCertified or set `write_shapes_registered=true` |
| Shape registration | Candidate shape promotion to registry requires separate Gate B evidence path — **not** implied here |

---

## WriteCertified

**WriteCertified never implied.**

This packet authorizes a **single** minimal reversible write-shape verification campaign on dedicated lab hardware. Success does **not**:

- Claim WriteCertified for AmneziaWG or WireGuard
- Set `write_shapes_registered=true`
- Open Gate B/C/D without explicit STATUS update
- Substitute for deferred T3 sealed write op + WRITE_ALLOWLIST implementation

---

## Deferred T3 prerequisites (blocking execution)

| Item | Tier |
|---|---|
| Sealed AWG write typed op(s) | **T3** |
| WRITE_ALLOWLIST registration for exact parse bodies | **T3** |
| Operator CLI validate-default + `--execute` path | **T3** |

Packet creation ≠ T3 implementation ≠ human approval. All three required before live `--execute`.

---

## Related docs

- [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) — RO discovery + candidate shape
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — §4 packet elements; §7a isolation
- [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) — sealed typed dispatch pattern
- [`STATUS.yaml`](STATUS.yaml) — gates SSOT
