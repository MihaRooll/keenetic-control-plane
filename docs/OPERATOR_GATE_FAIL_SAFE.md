# Gate B fail-safe timer discovery — operator runbook (code-only prep)

## For agents

| Rule | Action |
|---|---|
| Gate A coexistence | [`gate-a-certification.json`](gate-a-certification.json) keeps **B/C/D closed** so `GateACertification.is_open` stays valid |
| Gate D | **Closed** — fail-safe discovery does **not** open production writes |
| WriteCertified | **Never** claimed by this runner — `not_write_certified: true` in evidence |
| Trial consume | Execute path atomically creates `data/artifacts/fail-safe-trials/<trial_id>.consumed` via exclusive create — replay rejected |
| Session close | After command ack, runner must close exec channel, RCI HTTP session, local forwarder, Paramiko transport **before** outage poll |
| Outage poll | TCP reachability only — **no** SSH/RCI/tunnel during wait |
| Command | Typed op `fail_safe_timer_reboot_60` only — sealed CLI bytes internal; no raw command API |
| STATUS | **Already closed** in [`STATUS.yaml`](STATUS.yaml): Gate B/C **completed_failed** for both consumed trials (`fail-safe-20260723T094500Z`, `fail-safe-20260723T110000Z`) (§6); **not WriteCertified**; registries empty. Do **not** edit STATUS outside owned closeout or a future Main + exact T4 campaign |
| CLI | `scripts/certify-gate-b-fail-safe.py` — **`--dry-run` / `--validate` default**; rejects password env vars; **`--execute` requires `--source-address`** on overlapping-subnet labs |
| Schema | [`schemas/fail-safe-trial-authorization.schema.json`](schemas/fail-safe-trial-authorization.schema.json) |
| Session handoff | Active lab context: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) — backup metadata, topology, Gate A SSOT |

---

## 1. Purpose

Single-purpose NC-1812 fail-safe timer discovery for exact vendor CLI:

`system configuration fail-safe timer reboot 60`

This documents the **code-only** runner prepared under contract `fail-safe-discovery-nc1812-20260722`. Live execution requires an exact T4 Human Gate Packet plus trial authorization JSON; program lab authorization is **not** standing write approval.

---

## 2. Authorization

Trial authorization binds:

- `contract_id`
- unique `trial_id` (replay guard)
- Gate A tuple + `evidence_sha256`
- `capability_family`: `fail_safe`
- `typed_operation`: `fail_safe_timer_reboot_60`
- `timer_seconds`: `60`
- `expected_reboot`: `true`
- `opens_at` / `expires_at`
- `gates.D.status`: `closed`
- `gates.B.status`: `certification_trial_authorized` with `certification`: `CertificationTrialAuthorized` and `capability_family`: `fail_safe`
- `gates.C.status`: `open` with time-bounded `opens_at` / `expires_at` (3600s) aligned to authorization window

Historical/incomplete authorization JSON is **non-executable**. `--execute` requires digest-bound `status_source_digest`, `verification_receipt_sha256`, and `verification_receipt_path` matching a receipt JSON with `p1_complete`, `p2_complete`, and `p3_complete` all true — plus fresh exact T4 Human Gate. Local same-user filesystem trust for STATUS/auth/receipt files is assumed; an empty marker file is **not** a bypass.

Dry-run and `--validate` validate schema/bindings only — **no** trial consumption, **no** network.

---

## 3. Fixed runner sequence (execute path)

1. Load aligned Gate A (`ReadOnlyCertified` open)
2. Validate authorization vs tuple/evidence/window; atomically consume `trial_id`
3. Open pinned SSH; **live** pre-command identity via read probe over runner-owned RCI transport (not preloaded evidence file)
4. Create **new** encrypted startup backup (`backup_startup_config`) — **no** startup save
5. Execute sole typed op; validate bounded acknowledgement (boolean/hash only in evidence)
6. Verified close-all (exec → RCI → forwarder → transport) — abort without poll if not verified
7. TCP outage then recovery poll (injectable probe; no management sessions during wait)
8. Fresh pinned path; Gate A re-probe; exact tuple compare
9. Emit sanitized evidence JSON; failures set `window_closed: true`, never `WriteCertified`

---

## 4. CLI surface

```powershell
py.exe -3.11 scripts/certify-gate-b-fail-safe.py `
  --authorization path/to/auth.json `
  --gate-a-config docs/gate-a-certification.json `
  --gate-a-evidence data/artifacts/gate-a-probe-192.168.1.1.json `
  --status-path docs/STATUS.yaml `
  --evidence-out data/artifacts/fail-safe-discovery-dry-run.json `
  --validate
```

Execute mode (Main only, win32 DPAPI vault) — requires STATUS+receipt digests and fresh T4:

```powershell
# Requires authorization.status_source_digest + verification_receipt_* bound to STATUS.yaml bytes
py.exe -3.11 scripts/certify-gate-b-fail-safe.py `
  --execute `
  --host 192.168.1.1 `
  --username lab-user `
  --credential-ref <dpapi-ref> `
  --host-key-sha256 SHA256:... `
  --source-address 192.168.1.144 `
  --authorization path/to/auth.json `
  --evidence-out data/artifacts/fail-safe-discovery-result.json
```

Passwords: DPAPI credential ref only. Password env vars and extra mutation-like tokens are rejected.

---

## 5. Evidence

Sanitized JSON includes hashes, timestamps, status transitions, `ack_matched`, `sessions_closed_verified`, outage/recovery flags, reprobe tuple match — **never** passwords, command output, sessions, startup content, or raw physical IDs.

Failure evidence (2026-07-23+) adds allowlisted fields only:

| Field | Values |
|---|---|
| `error_code` | `cli_ack_unverified`, `cli_non_zero_exit`, `fail_safe_hardware_error` |
| `failure_stage` | `authorization`, `trial_consume`, `pre_command_probe`, `startup_backup`, `sealed_cli_dispatch`, … |
| `dispatch_attempted` | `true` iff sealed CLI dispatch path entered |
| `command_result` | Sealed meta only: `operation`, `timer_seconds`, `ack_matched`, `exit_status`, stdout/stderr SHA-256 + byte counts |

---

## 6. Historical trial closeouts (2026-07-23)

Both trials consumed once; **no replay**.

| Field | First trial (`fail-safe-20260723T094500Z`) | Second retry (`fail-safe-20260723T110000Z`) |
|---|---|---|
| outcome | `failed_after_dispatch_attempt_before_verified_ack` | `ssh_dispatch_failed_before_verified_ack` |
| executed_at | `2026-07-23T09:54:30Z` (approx) | `2026-07-23T11:41:34.896756Z` |
| source | `192.168.1.144` | `192.168.1.144` |
| result sha256 | `c39cc40fbf76d024296587c1865eae087e99fc74cb60222b9fd93e0cdbb12cf9` | `ecf9b0bbea6082586a06f8aacb4ef27e9914a3b58db983880f176c13b6e38355` |
| failure_stage | `sealed_cli_dispatch` | `sealed_cli_dispatch` |
| dispatch_attempted | true | true |
| ack_matched | false | false |
| error_code | `fail_safe_hardware_error` | `fail_safe_hardware_error` |
| VPN default route | operator-reported VPN temporarily on (unproven contributor) | **absent** (operator/diagnostic) |
| runner backup | `2026-07-23T09:54:20.717835Z`, digest `sha256:ee4a64cf3c1a928f9698efb161f2f9fcfe5f52ff1d1e55de7d50bb524e5ebb17`, 9733 bytes, DPAPI | same digest at execute time — no locator |
| post-trial Gate A health | `gate-a-post-fail-safe-20260723T095540Z.json` sha256 `db5e29b1…` — **not** SSOT | `gate-a-post-fail-safe-retry-20260723T114201Z.json` sha256 `4ce1ad59…` — **not** SSOT |
| Gate C window | `09:45:00Z`–`10:45:00Z` closed | `11:00:00Z`–`12:00:00Z` closed `2026-07-23T11:41:34Z` |

Gate A SSOT unchanged: `gate-a-return-home-20260723.json` sha256 `232bc5ca83c915fe29b037ed886859256fd5c27b29293db104b9b7bacef04c36`.

STATUS: Gate B/C **completed_failed**; Gate D closed; registries empty; **offline SSH CLI channel discovery harness delivered** (2026-07-23); **exact T4 required** for live `--live-probe` and before any third fail-safe mutation — see [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md).

Conservative wording: both trials attempted dispatch but effect is unproven; no verified ack or outage claim in-runner; **not WriteCertified**.

### Root cause (unproven)

Second retry with **VPN default route absent** reproduced the same fast `sealed_cli_dispatch` failure class as the first trial. VPN as primary cause is **unlikely but not impossible**. **Do not** claim an exact root cause. Run live read-only SSH CLI channel discovery per [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md) after exact T4 approval; review evidence before any third fail-safe mutation attempt.

### First-trial operator-reported transport context (unproven)

After the first trial closeout, the operator reported that a **client VPN was temporarily enabled** during the lab session and **could have caused local transport or routing disruptions**. Counterevidence on the first trial: explicit `--source-address 192.168.1.144`, pre-command probe passed, encrypted startup backup succeeded before dispatch. **Do not** infer VPN caused either trial failure.

---

## 7. Related docs

- [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md)
- [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)
- Official reference: [NC-1812 fail-safe configuration mode](https://support.netcraze.ru/ultra/nc-1812/en/26242-fail-safe-configuration-mode.html)
