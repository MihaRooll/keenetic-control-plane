# Gate B/C AWG — operator runbook (trial closed failed)

## For agents

| Rule | Action |
|---|---|
| Gate A coexistence | [`gate-a-certification.json`](gate-a-certification.json) keeps **B/C/D closed** so `GateACertification.is_open` stays valid |
| Trial closeout SSOT | [`gate-b-c-awg-authorization.json`](gate-b-c-awg-authorization.json) + [`gate-b-awg-certification-result.json`](gate-b-awg-certification-result.json) + [`STATUS.yaml`](STATUS.yaml) gates **B/C** record **completed_failed** — **not** `WriteCertified` |
| Gate C | **Closed** — lab window `2026-07-21T20:34:31Z` … `2026-07-21T21:34:31Z`; outcome `certification_failed_all_candidates_handshake` |
| Gate D | **Closed** — no production writes |
| Shapes | **write_shapes_registered false** — runner stops at `CommandShapeUnknown`; **never invent** NC-1812 Fail-safe/AWG/save/reboot commands |
| Re-open | Requires **new exact T4 Human Gate Packet** + sanitized shape discovery evidence; dedicated lab **program** ≠ standing write approval; do not infer WriteCertified from trial closeout |
| Gate B posture | **completed_failed** / **not WriteCertified** — unchanged by dedicated lab program authorization |
| Secrets | Local profiles only on operator disk; `PrivateKey` / `PresharedKey` → DPAPI refs; no endpoints/keys in repo/evidence |
| Lab policy | [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) — project-owned NC-1812; controlled lab churn under T4 only |
| CLI | `scripts/certify-gate-b-awg.py` — **`--dry-run` default**; rejects password env vars; **`--execute` requires `--source-address`** on overlapping-subnet labs |

---

## 1. Purpose

This runbook documents the **closed AmneziaWG Gate B/C certification trial** for the exact Gate A NC-1812 tuple. The trial **failed** (`certification_failed_all_candidates_handshake`). It does **not** claim `WriteCertified` — that requires a separate Main checklist per [`HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) §6.2–6.3 after shape registry evidence.

---

## 2. Final gate semantics (post-trial)

| Gate | Status | Meaning |
|---|---|---|
| **A** | `open` / `ReadOnlyCertified` | Read-only observe only ([`gate-a-certification.json`](gate-a-certification.json)) |
| **B** | `completed_failed` / `CertificationTrialAuthorized` (historical trial mode) | Trial write path ran; **not** family `WriteCertified`; `not_write_certified: true` |
| **C** | `closed` / `completed_failed` | Lab window ended; outcome `certification_failed_all_candidates_handshake` |
| **D** | `closed` | Production writes forbidden |

Tuple binding mirrors Gate A digests in authorization JSON — drift closes writes (`TupleDrift`).

---

## 3. Trial outcome summary

| Item | Value |
|---|---|
| Outcome | `certification_failed_all_candidates_handshake` |
| Candidates | `keenetic50-compat`, `fi-ip`, `de-ip` — all import accepted; handshake/reachability not proven |
| Rollback / recovery | Fail-safe rollback succeeded; reboot recovery succeeded for all candidates |
| Save/commit | **false** for all candidates (no disruptive tail on failure path) |
| Shapes | Discovery proved narrow frontend tokens; full advanced field parity **not** proven — registry remains fail-closed |
| Evidence | [`gate-b-awg-certification-result.json`](gate-b-awg-certification-result.json) (sanitized) |

---

## 4. Candidate order (historical)

Strict order used during trial (stop on first failure):

1. `keenetic50-compat`
2. `fi-ip`
3. `de-ip`

Local profile paths stay **off-repo**; parser accepts enumerated WireGuard + AmneziaWG ASC fields only.

---

## 5. Lifecycle (per candidate — historical)

1. Baseline observe (Gate A read-only tuple)
2. Fail-safe begin — **typed**; fails if shape unregistered
3. AWG import — secrets via DPAPI refs only
4. Field parity read-back
5. Handshake observe
6. Application reachability
7. **Only if all pass** → config save → router reboot → verify
8. On failure → baseline restore (**no** save/reboot on failure path)
9. Unknown fields / unknown shapes → **stop** (no continue)

---

## 6. Discovery boundary

Exact NC-1812 RCI write shapes are **not** registered in repo. The hardware boundary exposes **typed operation IDs** only:

- `fail_safe_begin`, `fail_safe_status`
- `awg_import`, `awg_field_parity_readback`
- `handshake_observe`, `application_reachability_observe`
- `config_save`, `router_reboot`, `baseline_restore`

Unregistered shapes → `CommandShapeUnknown` (fail-closed). Main must register shapes from **sanitized discovery artifacts** that bind to the exact tuple before any future lab re-open.

---

## 7. CLI (offline-safe default)

```powershell
# Dry-run (default) — single candidate, stops at CommandShapeUnknown
py.exe -3.11 scripts/certify-gate-b-awg.py `
  --profile-path C:\lab\profiles\keenetic50-compat.conf `
  --candidate keenetic50-compat
```

**Rejected:** password argv/env (`RC_ROUTER_PASSWORD`, etc.); mutation-like extra tokens.

Post-trial: live execute requires new human authorization — trial window is closed.

---

## 8. Next steps (not automatic)

1. Main supplies sanitized shape discovery evidence binding to exact Gate A tuple
2. New human packet for lab re-open or WriteCertified path
3. Separate SSOT update to `WriteCertified` only after full §6.3 checklist (out of failed trial scope)

---

## 9. Links

- Authorization SSOT: [`gate-b-c-awg-authorization.json`](gate-b-c-awg-authorization.json)
- Certification result: [`gate-b-awg-certification-result.json`](gate-b-awg-certification-result.json)
- Gate A runbook: [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md)
- Hardware gates: [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md)
- STATUS: [`STATUS.yaml`](STATUS.yaml)
