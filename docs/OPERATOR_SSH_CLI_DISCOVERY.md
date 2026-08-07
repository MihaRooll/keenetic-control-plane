# Operator runbook — NC-1812 read-only SSH CLI channel discovery

## For agents

| Topic | Rule |
|---|---|
| When to read | Before constructing or executing the **read-only SSH CLI channel discovery** T4 packet; after offline harness delivery (2026-07-23) |
| Scope | Typed ops `ssh_exec_show_interface_home` and `ssh_shell_show_interface_home` only — fixed bytes `show interface Home`; **no** generic CLI API; **no** mutation |
| Default | Offline `--validate` (zero network); **no** live I/O without exact T4 + `--live-probe` |
| Source bind | `192.168.1.144` (laptop Ethernet); host-key pin must match Gate A SSOT |
| Gates | A open ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified** |
| Next after offline prep | Human approval of exact T4 packet → live `--live-probe` with unique `probe_id` |

---

## 1. Purpose

Both fail-safe trials (`fail-safe-20260723T094500Z`, `fail-safe-20260723T110000Z`) failed at `sealed_cli_dispatch` before verified ack. Before any **third** fail-safe mutation attempt, operators must run **read-only SSH CLI channel discovery** to classify:

- **Exec channel:** `exec_supported` | `exec_rejected` | `exec_inconclusive`
- **Interactive shell framing:** `shell_framing_observed` | `shell_rejected` | `shell_inconclusive`

Discovery is **classification only** — it does **not** infer fail-safe ack, write safety, or transport promotion.

---

## 2. Offline harness (delivered)

| Component | Path |
|---|---|
| Library | `router_control/adapters/netcraze/ssh_cli_discovery.py` |
| Sealed SSH helpers | `router_control/adapters/netcraze/ssh_tunnel.py` (`exec_show_interface_home`, `shell_show_interface_home`, `PinnedSshTransport`) |
| Auth schema | `docs/schemas/ssh-cli-discovery-authorization.schema.json` |
| CLI | `scripts/probe-nc1812-ssh-cli.py` |
| PS wrapper | `scripts/probe-nc1812-ssh-cli.ps1` |

Validate authorization only (no network):

```powershell
py.exe -3.11 scripts/probe-nc1812-ssh-cli.py `
  --authorization data/artifacts/ssh-cli-discovery-authorization.json `
  --artifact-out data/artifacts/ssh-cli-discovery-validate.json `
  --status-path docs/STATUS.yaml
```

---

## 3. Live probe prerequisites (T4 — not standing approval)

Live `--live-probe` requires **all** of:

1. Signed authorization JSON (`contract_id=nc1812-ssh-cli-channel-discovery-20260723`, unique `probe_id`, `human_decision=approve`, `mutation_allowed=false`, Gates B/C/D closed, typed ops fixed, Gate A tuple/evidence binding, source `192.168.1.144`, ≤1h window).
2. DPAPI `--credential-ref` (no password argv/env).
3. `--ssh-host-key-sha256` matching Gate A pin `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM`.
4. `--source-address 192.168.1.144`.
5. Atomic `probe_id` consume under `data/artifacts/ssh-cli-discovery-probes/` (empty marker **not** a bypass).

**Forbidden:** `--execute`; raw command arguments; opening Gates B/C/D; third fail-safe mutation before discovery evidence reviewed.

---

## 4. Gate A tuple (do not rebind)

| Field | Value |
|---|---|
| Model | NC-1812 |
| Firmware | 5.01.C.1.0-0 |
| Transport | ssh_tunnel |
| Source | 192.168.1.144 |
| Evidence sha256 | `232bc5ca83c915fe29b037ed886859256fd5c27b29293db104b9b7bacef04c36` |
| Host key | ssh-ed25519 `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM` |

---

## 5. Artifact policy

- `certification_eligible=false`, `mutation_performed=false`
- Allowlisted metadata only: booleans, enums, SHA-256, byte counts, timing bounds, source class, digests, host-key algorithm/fingerprint
- **Never** persist raw stdout/stderr/prompt/body/command text, addresses from response, secrets, sessions, exception free text, backup paths

---

## 6. Official references

- [NC-1812 Command-line interface (CLI)](https://support.netcraze.ru/ultra/nc-1812/en/18480-command-line-interface--cli-.html)
- [Fail-safe configuration mode](https://support.netcraze.ru/ultra/nc-1812/en/26242-fail-safe-configuration-mode.html) (historical fail-safe trials — both `completed_failed`)

---

## 7. Next task

**SSH CLI channel discovery harness — delivered** (2026-07-23; offline validate + gated live probe). This runbook remains reference for bounded read-only ops and the CLI `?` hazard — **not** the program `next_task`.

**Current next (SSOT):** **`next_task` id:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](STATUS.yaml) `next_task`. **Parallel deferred** — VPN named connection policy / kill-switch **live apply** (offline preview layer delivered 2026-08-01; kill-switch `permit global` **unresolved**; **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** §M-24/M-27; traffic via tunnel reversible; IPv6 allow-ips refused; **`tunnel_healthy` + first real handshake DEVICE-CONFIRMED** 2026-08-05). See [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md). Gate B / `write_shapes_registered` BLOCKED (not WriteCertified).

---

## 8. CLI `?` + Enter execution hazard (interactive probing)

This harness uses **fixed bytes** for sealed discovery ops (`show interface Home` only). Agents probing CLI grammar **interactively** elsewhere must know:

| Hazard | Detail |
|---|---|
| Behavior | Sending `command ?\r` (question mark + Enter) may show help **then execute** the command without `?` |
| 2026-07-31 incident | Documented during VPN connection-policy help capture — see [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) §6 and artifact `data/artifacts/vpn-connection-policy-help-20260731/FINAL-REPORT-sanitized.json` |
| Safe technique | Type partial command + `?` **without** Enter (no CR); read help; reset line with **Ctrl-C** or **Ctrl-U** before any other input |
| Later sessions | FINAL report confirms partial + `?` without CR + Ctrl-C/Ctrl-U was used successfully for help-only context entry |

**Claims discipline:** accidental accepts from session 1 are documented; no intentional mutation claimed; gates unchanged.
