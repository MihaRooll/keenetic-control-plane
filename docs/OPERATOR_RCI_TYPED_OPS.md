# Operator runbook — NC-1812 sealed typed RCI interface/save ops

## For agents

| Topic | Rule |
|---|---|
| When to read | Before constructing or executing a **live** interface up/down or system configuration save T4 packet |
| Scope | Typed sealed ops only: `interface up/down` via `interface_rci`; `system configuration save` via `system_rci.configuration_save` — **no** generic/raw RCI; **never** call `execute_rci_parse`; **never** expose `system_reboot` |
| Default | Offline validate (zero network, zero DPAPI, zero win32 guard); live only with `--execute` after exact T4 Human Gate Packet + human approval |
| Source bind | Live requires `--source-address 192.168.2.10` + pinned SSH host-key `SHA256:<pin>` matching Gate A SSOT — **after** operator source-bound Gate A reprobe on new network (`192.168.2.1`); current SSOT evidence still bound to `192.168.1.144` |
| Gates | A open ReadOnlyCertified (unchanged); B `completed_failed`; C/D **closed**; **not WriteCertified** |
| Next | Human approval of exact per-campaign T4 packet before any `--execute` on dedicated lab router |

---

## 1. Delivered operator CLIs

| Script | Typed op | Exact CLI string |
|---|---|---|
| `scripts/interface-rci-op.py` | `interface_up` / `interface_down` | `interface <id> up` or `interface <id> down` |
| `scripts/system-rci-save.py` | `configuration_save` | `system configuration save` |

Both scripts mirror `scripts/fail-safe-rci-cycle.py` surface args (`--host`, `--credential-ref`, `--username`, `--ssh-host-key-sha256`, `--source-address`, `--secrets-root`) and add validate-by-default with `--execute` for live dispatch via `execute_sealed_rci_write` inside the typed layer.

---

## 2. Validate mode (default — no network)

**No** `--execute`. **No** DPAPI. **No** win32 requirement. Builds sealed body via `sealed_request_for` / `command_for` + `allowlist.build_sealed_parse_body`; confirms `is_write_allowlisted("POST","/rci/", body)`; prints sanitized JSON plan and exits **0** when allowlisted, **nonzero** fail-closed otherwise.

### Interface up/down

```powershell
py.exe -3.11 scripts/interface-rci-op.py --operation up --interface-id GigabitEthernet1
py.exe -3.11 scripts/interface-rci-op.py --operation down --interface-id Bridge0
```

Example plan:

```json
{
  "mode": "validate",
  "operation": "up",
  "interface_id": "GigabitEthernet1",
  "cli": "interface GigabitEthernet1 up",
  "body_sha256": "sha256:…",
  "write_allowlisted": true,
  "bytes": 44
}
```

Invalid interface ids (spaces, slashes, out-of-bounds) fail **before** sealed build with stderr `invalid interface id: …` and nonzero exit.

### System configuration save

```powershell
py.exe -3.11 scripts/system-rci-save.py
```

Example plan (no `interface_id`):

```json
{
  "mode": "validate",
  "operation": "configuration_save",
  "cli": "system configuration save",
  "body_sha256": "sha256:…",
  "write_allowlisted": true,
  "bytes": 40
}
```

---

## 3. Live mode (`--execute` — T4 required)

Live dispatch requires **all** of:

1. **Exact per-campaign T4 Human Gate Packet** approved by a human (template §5 below) — program authorization is **not** standing write approval.
2. Windows host (`win32`) for DPAPI credential resolution.
3. `--host`, `--credential-ref`, `--username`, `--ssh-host-key-sha256` (use `SHA256:<pin>` placeholder; Gate A example pin `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM`).
4. `--source-address 192.168.2.10` (laptop Ethernet bind — mandatory despite non-overlapping subnets; dual NIC; **after Gate A reprobe на новой сети**).
5. Sealed allowlisted bodies only — dispatch via typed ops (`interface_up`/`interface_down`/`configuration_save`), never raw passthrough.

### Interface live example

```powershell
py.exe -3.11 scripts/interface-rci-op.py `
  --operation up `
  --interface-id GigabitEthernet1 `
  --host 192.168.2.1 `
  --credential-ref <dpapi-ref> `
  --username <username> `
  --ssh-host-key-sha256 SHA256:<pin> `
  --source-address 192.168.2.10 `
  --execute
```

### System save live example

```powershell
py.exe -3.11 scripts/system-rci-save.py `
  --host 192.168.2.1 `
  --credential-ref <dpapi-ref> `
  --username <username> `
  --ssh-host-key-sha256 SHA256:<pin> `
  --source-address 192.168.2.10 `
  --execute
```

**Historical (pre-migration):** host `192.168.1.1`, source `192.168.1.144`.

Prints only `result.sanitized_dict()` JSON; never prints secrets. Non-win32 → exit **2**; missing live args → exit **2**; dispatch failure → stderr `<script> failed: <ClassName>: <msg>`, exit **4**.

**Forbidden:** `system reboot`; generic RCI passthrough; opening Gates B/C/D; WriteCertified claims.

---

## 4. WAN / topology isolation note

Dedicated lab: test router **`192.168.2.1`** on `192.168.2.0/24` (host Ethernet **`192.168.2.10`**); home working router `192.168.1.1` via Wi‑Fi on `192.168.1.0/24` — subnet overlap **removed**, but dual NIC → always bind `--source-address 192.168.2.10` on live CLIs (**after Gate A reprobe на новой сети**). Working-router↔test-router uplink should remain physically disconnected per session handoff until an authorized campaign explicitly requires otherwise.

---

## 5. T4 Human Gate Packet template (per campaign)

Each live interface or save campaign requires a **separate**, **exact** T4 packet per [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §4. Copy and fill before human approval:

| Element | Requirement |
|---|---|
| **Scope** | Exact typed op(s) and interface id(s) if applicable; time-bounded window; e.g. `interface GigabitEthernet1 down` then `up`, or single `system configuration save` — **no** generic/raw RCI |
| **Identity** | Pre-flight Gate A reprobe on exact tuple (after network migration): `py.exe -3.11 scripts/probe-gate-a.py --host 192.168.2.1 --ssh-tunnel --ssh-host-key-sha256 SHA256:<pin> --source-address 192.168.2.10`; pending new source-bound artifact — current SSOT `gate-a-return-home-20260723.json` sha256 `232bc5ca83c915fe29b037ed886859256fd5c27b29293db104b9b7bacef04c36` still records `192.168.1.144` |
| **Backup** | Pre-change startup-config via `scripts/backup-router-startup.py`; record `content_sha256` + `size_bytes`; artifacts under `data/backups/` (`.dpapi` + `.meta.json`); **no** absolute paths in packet or docs |
| **Fail-safe / rollback** | Arm fail-safe timer via `scripts/fail-safe-rci-cycle.py` (sealed arm 60s) before disruptive steps; compensation: reverse interface up↔down as needed; run `scripts/system-rci-save.py` after intended stable state; disarm fail-safe when complete |
| **Gate C** | Time-bounded laboratory window when lab mutations apply (explicit opens_at / expires_at UTC) |
| **Gate D** | **Closed** — no production dispatch |
| **Post-test** | Gate A reprobe; sanitized evidence artifact; STATUS update only if a gate actually changes |
| **WriteCertified** | **Never** implied by this packet or operator CLI delivery |

---

## 6. Related docs

| Doc | Role |
|---|---|
| [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) | Active lab handoff; topology; Gate A SSOT |
| [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) | Gate A runbook; source bind |
| [`OPERATOR_GATE_FAIL_SAFE.md`](OPERATOR_GATE_FAIL_SAFE.md) | Fail-safe arm/disarm cycle |
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Program vs action; T4 elements |
| [`STATUS.yaml`](STATUS.yaml) | SSOT gates and next_task |
