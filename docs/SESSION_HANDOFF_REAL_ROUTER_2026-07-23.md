# Session handoff — real router lab (2026-07-23)

> **SUPERSEDED (2026-07-31):** Active narrative handoff is [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Policy SSOT: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml). This doc is **historical** — P1–P3 substrates, network migration, fail-safe trials.

**Status: HISTORICAL HANDOFF (2026-07-23, session closeout).** P1–P3 offline substrates + topology safety closure delivered; **network migration 2026-07-23** to test router `192.168.2.1` / host source `192.168.2.10`; Gate A return-home recertification **historical** on **192.168.2.10** (`gate-a-return-home-192.168.2.1-20260723.json`) — **superseded** by 2026-07-31 rebind evidence `gate-a-probe-newrouter-192.168.2.1-20260731.json`. **Session deliverables (2026-07-23):** Russian language rule (`AGENTS.md` + `.cursor/rules/respond-in-russian.mdc`); sealed operator CLIs (`scripts/interface-rci-op.py`, `scripts/system-rci-save.py` + [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md)); integration facade (`RouterControlConfig`/`build_runtime` + [`INTEGRATION.md`](INTEGRATION.md)); UI vertical slice `#config` + `GET /api/router-control/v1/observed-interfaces` + [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md); offline VPN import (`scripts/import-vpn-profile.py`, 10/10 profiles); AWG parser 1.5 (S3/S4/I1–I5); test-router credential enrolled in DPAPI (`cred_db65665dd59f600bdd23544d85564c83`); live RO recon (HTTP:80, RCI x-ndw2-interactive, SSH:22; 32 interfaces; route direct-array shape captured — **parser v1.2 accepts offline**, DiscoveryRead/non-certifying only). **WriteCertified NOT claimed; Gates B/C/D unchanged.** **Historical next task (frozen 2026-07-23):** per-feature live read-only discovery → sealed typed op → Gate B + exact T4 — **superseded**; see [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + [`STATUS.yaml`](STATUS.yaml).

## For agents

> **HISTORICAL ONLY.** For current post-rebind lab narrative use [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md).

| Topic | Rule |
|---|---|
| When to read | **HISTORICAL ONLY** — P1–P3 substrates, network migration, fail-safe trials, topology discovery methods. **Not** the live guide for current unit |
| Delivered | P1–P3 offline substrates; network migration 2.1 + Gate A recert source-bound `192.168.2.10`; sealed operator CLIs (validate-default); integration facade; UI `#config` + observed-interfaces RO; VPN import (10/10) + AWG parser 1.5; Russian language rule; topology/default-route discovery (non-certifying); verify baseline ~1348 passed/2 skipped |
| Not delivered | Live interface/save `--execute`, per-feature RCI write-shape discovery, Gate B certification, captive-portal/KeenDNS models — all required **exact per-campaign T4** + human approval (historical 2026-07-23 posture) |
| Superseded | **This entire doc** for active narrative — use [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Live read-only SSH CLI channel discovery — superseded by RCI HTTP API (2026-07-23); offline harness only in [`OPERATOR_SSH_CLI_DISCOVERY.md`](OPERATOR_SSH_CLI_DISCOVERY.md) |
| SSOT | **Historical Gate A evidence only:** `data/artifacts/gate-a-return-home-192.168.2.1-20260723.json` — source-bound **`192.168.2.10`** (2026-07-23 migration). **Current Gate A SSOT superseded:** `data/artifacts/gate-a-probe-newrouter-192.168.2.1-20260731.json` — see [`STATUS.yaml`](STATUS.yaml) |
| Writes | **No standing T4.** Gate B fail_safe **completed_failed** (historical CertificationTrialAuthorized, not WriteCertified); Gates C/D closed. Program authorization ≠ per-campaign write approval |
| Topology | **Current (2026-07-23 migration):** laptop Ethernet source `192.168.2.10` → test NC-1812 `192.168.2.1` on `192.168.2.0/24`; home working router `192.168.1.1` via Wi‑Fi on `192.168.1.0/24` (subnets no longer overlap); dual NIC → `--source-address 192.168.2.10` still **mandatory**; see §Network migration. **Historical (pre-migration):** `192.168.1.144` → `192.168.1.1` overlapping `192.168.1.0/24` (§5) |
| Secrets | Never document passwords, keys, cookie values, raw startup-config, or absolute backup file paths |

---

## 1. Session summary

This handoff persists evidence from the **dedicated NC-1812 lab session** ending **2026-07-23**: offline execution substrates (P1–P3), non-certifying topology and default-route discovery, return-home Gate A recertification on the exact certified tuple, encrypted pre-change startup backup metadata, physical uplink disconnect as the pre-T4 isolation alternative, and **two consumed fail-safe trials** — first `fail-safe-20260723T094500Z` (`failed_after_dispatch_attempt_before_verified_ack`) and second retry `fail-safe-20260723T110000Z` (`ssh_dispatch_failed_before_verified_ack`; VPN default route absent; same dispatch-stage failure class; root cause unproven; not WriteCertified).

**RCI control plane (2026-07-23, delivered + live-verified):** after diagnosing the SSH-exec dead end, a typed sealed RCI layer was built and reconciled with a colliding in-tree parallel implementation:
- `router_control/adapters/netcraze/transport.py`: `execute_rci_parse` (generic lab primitive) + `SealedRciWriteRequest` + `execute_sealed_rci_write` (fail-closed write-allowlist) + `MAX_RCI_WRITE_BODY_BYTES`.
- `fail_safe_rci.py` (arm/disarm), `interface_rci.py` (up/down, id-validated), `system_rci.py` (save/reboot) — sealed typed ops, structural `parse.status[]` ack, no generic-CLI surface.
- `rci_live.py` (`open_pinned_rci_transport`); operator tools `scripts/rci-parse.py`, `scripts/fail-safe-rci-cycle.py`.
- Host: `router_control_host/rci_mutation_routes.py` wired in `app.py` (hub_admin auth + mutation gates + Idempotency-Key + fake-mode); OpenAPI regenerated.
- **Live:** `show version` read + fail-safe **arm→disarm** via the sealed path, verified acks, no reboot, config unchanged, under explicit user lab authorization on the dedicated test router.

**Session closeout achievements (2026-07-23):**

1. **Russian language rule:** `AGENTS.md` + `.cursor/rules/respond-in-russian.mdc`.
2. **Sealed operator CLIs:** `scripts/interface-rci-op.py` (up/down), `scripts/system-rci-save.py` (validate-default, `--execute` under T4) + [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) with T4 packet template.
3. **Integration facade:** `router_control/integration.py` (`RouterControlConfig` + `build_runtime`), additive exports in `router_control/__init__.py`, [`INTEGRATION.md`](INTEGRATION.md).
4. **Network migration:** test router `192.168.2.1` (source `192.168.2.10`); home working router `192.168.1.1` via Wi‑Fi in parallel (different subnets; source-bind required).
5. **Live RO recon:** HTTP:80=200, RCI x-ndw2-interactive, SSH:22; host-key SHA256 `lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM` **MATCHED** certified pin → same NC-1812.
6. **Enrolled credential:** DPAPI meta `data/secrets/meta/router-credential-meta-test-2.1.json`, `credential_ref` `cred_db65665dd59f600bdd23544d85564c83` (username admin; password **not** in repo).
7. **Gate A source-bound RECERT:** evidence `data/artifacts/gate-a-return-home-192.168.2.1-20260723.json` sha256 `24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3`, source `192.168.2.10`; same tuple; prior return-home (`232bc5ca`, source `1.144`) historical. A open ReadOnlyCertified; B completed_failed; C/D closed.
8. **Topology probe:** 32 interfaces (`data/artifacts/topology-192.168.2.1-20260723.json`), classification ambiguous (non-certifying), LAN `192.168.2.0/24`. Route shape (`data/artifacts/default-route-shape-192.168.2.1-20260723.json`): `/rci/show/ip/route` = direct array `{gateway,interface,+dynamic}`; route parser **`default-route-v1.2`** accepts bare top-level list offline (DiscoveryRead/non-certifying; v1.1 gap closed 2026-07-23).
9. **UI slice `#config`:** RO overview + VPN catalog + Wi‑Fi/DNS validate/preview + honest apply-gate banner; `GET /api/router-control/v1/observed-interfaces`; [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md).
10. **VPN import:** `scripts/import-vpn-profile.py` — offline AWG `.conf` → DPAPI vault (sanitized stdout); 10/10 profiles imported (`data/artifacts/vpn-import-catalog-20260723.json` — no secrets).
11. **AWG parser 1.5:** `awg_profile.py` extended S3/S4/I1–I5.
12. **Verify baseline:** pytest ~1348 passed/2 skipped; ruff/mypy/openapi/docs exit 0.

**Current next task:** per-feature live read-only discovery on `192.168.2.1` (`--source-address 192.168.2.10`) → sealed typed op + write-allowlist + operator CLI → offline tests/UI → Gate B certification + exact T4 Human Gate Packet → live apply under human approval. Priority: VPN AmneziaWG and Wi‑Fi; captive/KeenDNS greenfield. SSH-CLI-channel-discovery task is **superseded**.

Historical UI auth handoff: [`SESSION_HANDOFF_UI_AUTH_2026-07-22.md`](SESSION_HANDOFF_UI_AUTH_2026-07-22.md) (**historical — do not paste §10**).

---

## 2. Completed inventory (P1–P3 + session deliverables)

| Track | Deliverable | Scope | Live-ready |
|---|---|---|---|
| **P1-A** | Migration 4, schema fingerprint/history, migrate mutex, pre-migrate backup, execution fences, worker instances, effect SM, recovery CAS, artifact staging | Offline / not live-ready | **No** |
| **P1-B** | Poll continuation, effect SM, DPAPI artifacts, safety session wiring | Offline / fake; live MutationForbidden | **No** |
| **P2** | Immutable deployment model, offline/fake compiler path | Offline / fake | **No** |
| **P3** | Shared typed operation executor, Certified registry wiring (empty), Gate D default-deny, digest-bound execute prerequisite, explicit `source_address` bind | Offline / default-deny | **No** — registries empty until fresh T4 evidence |
| **Sealed CLIs** | `interface-rci-op.py`, `system-rci-save.py` (validate-default) + [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) | Offline / validate-default; live `--execute` T4 | **No** |
| **Integration** | `RouterControlConfig` + `build_runtime`, [`INTEGRATION.md`](INTEGRATION.md) | Offline tests | **No** |
| **UI #config** | Overview/VPN/Wi‑Fi-DNS validate-preview, observed-interfaces RO API, [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md) | Read-only / validate-preview | **No** — Apply blocked |
| **VPN import** | `import-vpn-profile.py`, AWG parser 1.5, 10/10 profiles in vault | Offline import | **No** — live deploy T4 |
| **Discovery** | Topology: 32 interfaces, parser v2.2 succeeded, classification **ambiguous** (non-certifying). Default-route: direct array accepted by parser **`default-route-v1.2`** offline (v1.1 gap closed; DiscoveryRead/non-certifying). Offline fixtures + CLI + tests | Non-certifying; not certification | N/A |
| **Russian rule** | `AGENTS.md` + `.cursor/rules/respond-in-russian.mdc` | Agent harness | N/A |

Gates **unchanged** by discovery delivery: A open ReadOnlyCertified; B fail_safe **completed_failed** (historical CertificationTrialAuthorized, not WriteCertified; current trial `fail-safe-20260723T110000Z`); C **closed** completed_failed; D closed.

---

## 3. Latest full verification (six-command suite)

**Fresh handoff verification ran** on **2026-07-23** (this session). All six commands exit **0**:

| Command | Result |
|---|---|
| `py.exe -3.11 -m pytest -q` | **1348 passed, 2 skipped** |
| `py.exe -3.11 -m ruff check router_control router_control_host tests scripts` | exit 0 |
| `py.exe -3.11 -m mypy router_control router_control_host` | exit 0 |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/export-openapi.ps1` | exit 0 |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/validate-project-docs.ps1` | exit 0 |
| `py.exe -3.11 scripts/project-docs.py audit --project-root .` | exit 0 |

Standard suite (for repro):

```text
py.exe -3.11 -m pytest -q
py.exe -3.11 -m ruff check router_control router_control_host tests scripts
py.exe -3.11 -m mypy router_control router_control_host
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/export-openapi.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/validate-project-docs.ps1
py.exe -3.11 scripts/project-docs.py audit --project-root .
```

---

## 4. Gate A — return-home SSOT (source-bound, 192.168.2.x)

| Field | Value |
|---|---|
| Evidence path | `data/artifacts/gate-a-return-home-192.168.2.1-20260723.json` |
| sha256 | `24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3` |
| source_address | `192.168.2.10` |
| recorded_at | `2026-07-23T18:18:49.005975+00:00` (per [`STATUS.yaml`](STATUS.yaml)) |
| Tuple | Same certified NC-1812 tuple — component_set_digest `sha256:de72a7af…`, device_fingerprint_digest `sha256:eb58946c…` (full digests in STATUS) |
| recertification_reason | `network_migration_192.168.2.x_source_bound_recertification_same_tuple` |

**Pre-T4 confirmation:** same tuple + host-key pin + `--source-address 192.168.2.10` → test router `192.168.2.1` — not a silent rebind.

**Previous evidence (historical, same tuple, superseded not revoked):** `gate-a-return-home-20260723.json` sha256 `232bc5ca…`, source `192.168.1.144`, recorded `2026-07-23T05:17:43.764839+00:00`.

Prior evidence `gate-a-probe-192.168.1.1.json` remains **historical** (same tuple, superseded not revoked) — see `previous_certifications` in [`gate-a-certification.json`](gate-a-certification.json).

---

## 5. Physical topology — before / after disconnect

### Before (dual-homed overlapping LAN)

| Path | Source | Gateway | Notes |
|---|---|---|---|
| Ethernet (`Ethernet 3` / Liga3) | `192.168.1.144` | `192.168.1.1` | Preferred for Gate A / discovery CLIs |
| Wi‑Fi | `192.168.1.119` | `192.168.1.1` | Overlapping `192.168.1.0/24`; SSH often timeout on Wi‑Fi path |
| LAN bridge | — | `192.168.1.0/24` | NC-1812 lab LAN |

Working-router ↔ test-router **uplink was connected** during early dual-router observation.

### After (user physical disconnect — historical, pre-migration)

| Change | Observation |
|---|---|
| Uplink | Working-router ↔ test-router **physically disconnected by operator** |
| Read-only delta | One **GigabitEthernet+Port** transitioned **up → down** |
| Logical classification | Remains **ambiguous / non-certifying** (topology discovery does not alone prove WAN isolation) |
| Pre-T4 isolation | **Physical disconnect satisfies** the P3 alternative to `proven_wan_isolated` **while cable stays disconnected** |

**Historical bind (pre-migration):** `--source-address 192.168.1.144` + pinned SSH on overlapping `192.168.1.0/24`. **Current mandatory bind:** `--source-address 192.168.2.10` → test router `192.168.2.1` — see **Network migration 2026-07-23** below and [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §7a.

---

## Network migration 2026-07-23: тестовый роутер → 192.168.2.1

Read-only recon on the **same physical NC-1812** after operator network migration (management IP and host Ethernet source changed). **Gate A SSOT recertified** source-bound to `192.168.2.10` — evidence `gate-a-return-home-192.168.2.1-20260723.json` (not a silent rebind).

| Check | Result |
|---|---|
| Reachability | Test router `192.168.2.1` reachable from host Ethernet `192.168.2.10` |
| HTTP :80 | **200** |
| RCI `/rci/show/version` (unauthenticated) | **401** with `WWW-Authenticate: x-ndw2-interactive endpoint="/auth"` |
| SSH :22 | Open |
| ed25519 host-key SHA256 | `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM` — **matches** Gate A pin in [`STATUS.yaml`](STATUS.yaml) `gates.A.tuple` (same physical device; only IP/network changed) |
| Host outbound bind | **`192.168.2.10`** (mandatory on all live observe CLIs despite non-overlapping subnets — dual NIC: home working router `192.168.1.1` still reachable via Wi‑Fi on `192.168.1.0/24`) |

**Notes:**

- **Identity confirmed** by SSH host-key pin match to certified Gate A tuple — not by port reachability alone.
- **Gate A freshness** satisfied by **source-bound reprobe** on `192.168.2.1` / `192.168.2.10` (2026-07-23); prior `192.168.1.144` return-home evidence historical.
- **Enroll credential:** operator step via getpass ([`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) §13); `--meta-out` to a separate metadata file — not part of this docs task.
- **Subnet overlap removed** (`192.168.2.0/24` ≠ `192.168.1.0/24`), but **`--source-address 192.168.2.10` remains mandatory** because the host retains dual paths (Ethernet to test router + Wi‑Fi to home router).

---

## 6. Discovery artifacts (non-certifying)

| Artifact kind | CLI / module | Gate impact |
|---|---|---|
| Topology | `scripts/probe-nc1812-topology.py` | Live: parser **v2.2 succeeded**, classification **ambiguous** (non-certifying). DiscoveryRead allowlist; `certification_eligible: false`; optional `--shape-out` on parse fail |
| Default route | `scripts/probe-nc1812-default-route.py` | Live response: structural **direct array** accepted by parser **`default-route-v1.2`** offline (v1.1 gap closed; DiscoveryRead/non-certifying — **no route-isolation claim**). Blocks T4 uplink claims on `multiple_default_routes` / `ambiguous` |

Delivered **2026-07-23** as offline fixtures + CLI + tests. **Does not** open Gates B/C/D or register write shapes.

---

## 7. Encrypted backup — sanitized metadata only (AC-4)

### Pre-T4 baseline (2026-07-23T09:03:45Z)

| Field | Value |
|---|---|
| recorded_at | `2026-07-23T09:03:45.211326Z` |
| sha256 | `ee4a64cf3c1a928f9698efb161f2f9fcfe5f52ff1d1e55de7d50bb524e5ebb17` |
| bytes | 9733 |
| storage | DPAPI encrypted (`.dpapi`) |
| tuple binding | Exact Gate A / STATUS certified tuple digests; source bind `192.168.1.144` |

### Runner backup before fail-safe dispatch (2026-07-23T09:54:20Z)

| Field | Value |
|---|---|
| recorded_at | `2026-07-23T09:54:20.717835Z` |
| sha256 | `ee4a64cf3c1a928f9698efb161f2f9fcfe5f52ff1d1e55de7d50bb524e5ebb17` |
| bytes | 9733 |
| storage | DPAPI encrypted — **no locator in docs** |

### Runner backup before second fail-safe dispatch (2026-07-23T11:41:34Z)

| Field | Value |
|---|---|
| recorded_at | `2026-07-23T11:41:34.896756Z` |
| sha256 | `ee4a64cf3c1a928f9698efb161f2f9fcfe5f52ff1d1e55de7d50bb524e5ebb17` |
| bytes | 9733 |
| storage | DPAPI encrypted — **no locator in docs** |

No raw startup-config content, no absolute filesystem path, no credentials.

---

## 8. Gates posture

| Gate | Status | Notes |
|---|---|---|
| **A** | Open ReadOnlyCertified | Return-home evidence SSOT recertified on 192.168.2.10 (§4); post-retry health reprobe `gate-a-post-fail-safe-retry-20260723T114201Z.json` sha256 `4ce1ad5909938b09c42c7ac13ec1791fd43c41f52707dded7b7144bf6ba9f55d` — health evidence only, **not** Gate A SSOT |
| **B** | completed_failed | Current trial `fail-safe-20260723T110000Z`; historical **CertificationTrialAuthorized** (not WriteCertified); outcome `ssh_dispatch_failed_before_verified_ack`; result sha256 `ecf9b0bbea6082586a06f8aacb4ef27e9914a3b58db983880f176c13b6e38355`. Prior trial `fail-safe-20260723T094500Z` under `previous_trial` (outcome `failed_after_dispatch_attempt_before_verified_ack`; result sha256 `c39cc40f…`) — see [`OPERATOR_GATE_FAIL_SAFE.md`](OPERATOR_GATE_FAIL_SAFE.md) §6 |
| **C** | closed completed_failed | Second window `2026-07-23T11:00:00Z`–`12:00:00Z`; closed `2026-07-23T11:41:34Z`; prior window preserved in `previous_trial` |
| **D** | closed | Production-only |
| **T4** | **No standing authorization** | Per-feature live RCI write-shape discovery first, then an exact per-campaign packet + explicit human approval before any live write |

---

## 9. Constraints

- **Preserve dirty working tree** — do not `git clean`, reset, or discard uncommitted work.
- **No router writes** without approved T4 packet for exact tuple/window.
- Cold-start: [`AGENTS.md`](../AGENTS.md) → [`STATUS.yaml`](STATUS.yaml) → this doc → [`contracts/AI_HANDOFF.md`](contracts/AI_HANDOFF.md).
- Dedicated lab program authorizes Gate A RO + offline prep — **not** standing writes ([`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)).

---

## 10. Next steps (per-feature discovery cycle)

1. **Per-feature cycle (priority VPN AmneziaWG, then Wi‑Fi):** live read-only discovery of RCI write-shape on `192.168.2.1` (`--source-address 192.168.2.10`, pinned SSH, `credential_ref`) → sealed typed op + write-allowlist + operator CLI (validate-default) → offline tests/UI → Gate B certification + exact per-campaign T4 Human Gate Packet → live apply under human approval.
2. **Gate A source-bound reprobe complete (2026-07-23):** SSOT `gate-a-return-home-192.168.2.1-20260723.json` / source `192.168.2.10` — not a silent rebind (§4).
3. **Routes direct-array parser (closed offline 2026-07-23):** `default-route-v1.2` accepts bare top-level list from `default-route-shape-192.168.2.1-20260723.json`; DiscoveryRead/non-certifying only — route-isolation/uplink claims still require correlation + gates; no WriteCertified claim.
4. **Greenfield:** captive-portal and KeenDNS — no RCI write-shape model yet.
5. **Stop for human approval** before any live write; offline code/tests/UI proceed autonomously.
6. Pursue **WriteCertified** only after full certification machinery + **principal-arbiter** approval. Registries remain empty until then.

---

## 11. Blockers

| ID | Scope | Status |
|---|---|---|
| SSH exec-channel diagnosis | fail-safe live campaign | **Closed / superseded** — NDMS SSH exec unsupported; RCI parse is the automation surface (§10) |
| Exact T4 for live interface/save | interface up/down + system configuration save | **Open** — sealed operator CLIs delivered ([`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md)); each live run needs an exact per-campaign T4 packet + explicit human approval |
| Write certification | AWG / per-family | Gate B completed_failed; parallel deferred lane |
| Firmware/capability matrix | future writes | Fail-closed until Gate B+ on exact tuple |

---

## 12. Copy-paste prompt for new AI chat (Russian)

> **DO NOT include passwords, keys, or cookie values in this prompt or replies.**

```
Ты продолжаешь Router Control (keenetic-control-plane) автономно и по-русски. Cold start СТРОГО по порядку:
AGENTS.md → README.md → docs/STATUS.yaml → docs/DEDICATED_ROUTER_LAB_POLICY.md → docs/CANONICAL.md → docs/contracts/README.md → docs/contracts/AI_HANDOFF.md → docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md → docs/project-state.md.
Сохрани большой dirty working tree: запрещены git clean/reset/checkout и commit/push без явной просьбы. Отвечай пользователю по-русски (правило .cursor/rules/respond-in-russian.mdc).

=== АРХИТЕКТУРА ДЕЛЕГИРОВАНИЯ (главное — не трать токены премиум-модели на рутину) ===
Ты — Main/dispatcher. Разведку, реализацию, проверки и ревью ВСЕГДА делегируй L2-субагентам; сам только классифицируй tier, координируй, принимай финальные решения и общайся с пользователем.
- В ОДНОМ сообщении запускай НЕСКОЛЬКО Task параллельно (2-4 explore под разные углы).
- Разведка/поиск/веб → explore или generalPurpose, model=cursor-grok-4.5-high-fast (веб только через субагентов).
- Многофайловая координация (T2/T3) → operational-orchestrator, model=cursor-grok-4.5-high-fast (он сам запускает explore/implementer/adversarial-reviewer/verifier).
- Запись в production-код → ТОЛЬКО implementer, model=composer-2.5-fast.
- Проверки (тесты/линт/типы/openapi/docs) → verifier, model=composer-2.5-fast.
- Независимое ревью диффа → adversarial-reviewer, model=cursor-grok-4.5-high-fast.
- principal-arbiter (T3 перед production-записью): model НЕ указывать. Если Main НЕ из Sol-семейства → Sol недоступна → НЕ вызывай principal-arbiter, удерживай работу в аддитивных T2-границах и фиксируй ограничение; для настоящих T3-архитектурных развилок — STOP+report.
- L2 не делегирует (Main → L1 → L2). Findings = path+строки+требование+воспроизводимое доказательство.
- Быстрый verify экономнее полного (полный pytest ~200s, 1350+ тестов). На Windows зависший тест роняет сессию — ВСЕГДА pytest --timeout=60 --timeout-method=thread.

=== ТЕКУЩЕЕ СОСТОЯНИЕ (2026-07-23) ===
- Тестовый NC-1812 на сети 192.168.2.1; хост Ethernet source 192.168.2.10; рабочий роутер 192.168.1.1 параллельно по Wi-Fi (разные подсети; source-bind обязателен из-за двух интерфейсов хоста).
- Gate A RECERT на новой сети: тот же tuple (host-key SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM совпал), evidence gate-a-return-home-192.168.2.1-20260723.json sha256 24c6df7e…, source 192.168.2.10. A open ReadOnlyCertified; B completed_failed (not WriteCertified); C/D closed.
- Credential тестового роутера: DPAPI, meta data/secrets/meta/router-credential-meta-test-2.1.json, credential_ref cred_db65665dd59f600bdd23544d85564c83 (username admin; пароль в репо НЕ хранить).
- Live read-only изучено: HTTP:80, RCI x-ndw2-interactive, SSH:22; 32 интерфейса (topology-192.168.2.1-20260723.json); route shape direct-array снят — парсер **`default-route-v1.2`** принимает offline (DiscoveryRead/non-certifying; v1.1 gap закрыт).
- Доставлено offline: sealed operator CLIs (interface-rci-op.py, system-rci-save.py), integration facade (RouterControlConfig/build_runtime + INTEGRATION.md), UI #config + observed-interfaces + import-vpn-profile.py, парсер AWG 1.5 (S3/S4/I1-I5), 10/10 VPN профилей в vault.
- Verify baseline: pytest ~1348 passed/2 skipped; ruff/mypy/openapi/docs exit 0.

=== ЦЕЛЬ ПРОДУКТА ===
Переносимый модуль управления роутером для интеграции в сторонний FastAPI + UI «потыкать настройки и применить». Минимум 4 фичи: (1) VPN AmneziaWG, (2) Wi-Fi guest/staff, (3) captive-portal/автостраница, (4) домен Keenetic (KeenDNS). Функционал расширяется.

=== СЛЕДУЮЩИЕ ЗАДАЧИ (автономно, по одной фиче) ===
Для КАЖДОЙ фичи цикл: live read-only discovery реального RCI write-shape на 192.168.2.1 (--source-address 192.168.2.10, pinned SSH, credential_ref) → sealed typed op + write-allowlist + operator CLI (validate-default) → offline тесты/UI → Gate B сертификация + exact per-campaign T4 Human Gate Packet → live apply под явным human approval.
Приоритет: VPN AmneziaWG и Wi-Fi ближе всего; captive и KeenDNS greenfield (модели нет).
Весь offline-код/тесты/UI/парсеры делай автономно. Live WRITE = T4: подготовь всё, STOP для human approval; live-команды запускает пользователь (у него credentials/DPAPI).

=== ЗАПРЕТЫ ===
Secrets/credentials/private keys в код/доки/логи/fixtures/artifacts; generic raw RCI passthrough на product-поверхности; router writes без exact T4; открытие Gates B/C/D без evidence; WriteCertified claims без сертификации; absolute backup paths в доках; silent rebind Gate A; commit/push/git clean/reset/checkout без явной просьбы.
```

---

## 13. Related docs

| Doc | Role |
|---|---|
| [`STATUS.yaml`](STATUS.yaml) | SSOT phase, gates, next_task |
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Program vs action; §7a topology |
| [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) | Gate A runbook; source bind |
| [`OPERATOR_GATE_FAIL_SAFE.md`](OPERATOR_GATE_FAIL_SAFE.md) | Fail-safe T4 prep |
| [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) | Sealed interface/save operator CLIs; validate-default; T4 live template |
| [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) | Gate definitions |
| [`OPERATOR_ROUTER_CONFIG_UI.md`](OPERATOR_ROUTER_CONFIG_UI.md) | UI #config vertical slice; VPN import; observed-interfaces RO |
| [`INTEGRATION.md`](INTEGRATION.md) | Third-party FastAPI integration facade |
| [`SESSION_HANDOFF_UI_AUTH_2026-07-22.md`](SESSION_HANDOFF_UI_AUTH_2026-07-22.md) | Historical UI closeout |

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | fail-safe-retry-closeout-20260723 |
| paths | docs/STATUS.yaml, docs/project-state.md, docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md, docs/OPERATOR_GATE_FAIL_SAFE.md, docs/DEDICATED_ROUTER_LAB_POLICY.md, docs/CANONICAL.md, docs/contracts/HARDWARE_GATES.md, docs/contracts/AI_HANDOFF.md, docs/contracts/README.md, docs/contracts/ROADMAP.md, docs/contracts/TEST_STRATEGY.md, docs/README.md, README.md, docs/docs-map.json |
| map_entries | all materially edited owned docs above |
| validator | orchestrator/verifier — not run by implementer |
| notes | Second trial fail-safe-20260723T110000Z closed completed_failed; both trial histories preserved; next_task offline SSH exec-channel diagnosis |

---

### Docs Impact Record — session closeout 2.1 (2026-07-23)

| Field | Value |
|---|---|
| contract_id | session-closeout-2dot1-20260723 |
| paths | docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md, docs/STATUS.yaml, docs/project-state.md, docs/docs-map.json |
| map_entries | all materially edited owned docs above |
| validator | verifier — not run by implementer |
| notes | Session closeout: network 2.1 migration, Gate A recert, sealed CLIs, integration facade, UI #config, VPN import+AWG1.5, Russian rule; §12 prompt replaced verbatim; next_task pivoted to per-feature discovery cycle |

### Docs Impact Record — RCI control plane delivery (2026-07-23, updated)

| Field | Value |
|---|---|
| contract_id | nc1812-fail-safe-rci-parse-20260723 |
| paths | docs/STATUS.yaml (next_task + reviews rci_control_plane_delivered), docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md (header, §1, §10, §12 prompt), docs/contracts/openapi-v0.json (regenerated), docs/netcraze-source-catalog.json (malformed JSON repaired), .cursor/plans/nc1812-fail-safe-rci-parse-20260723.plan.md |
| code | router_control/adapters/netcraze/{transport.py, fail_safe_rci.py, interface_rci.py, system_rci.py, rci_live.py, allowlist.py, ssh_tunnel.py, fail_safe_hardware.py}, router_control_host/rci_mutation_routes.py, scripts/{rci-parse.py, fail-safe-rci-cycle.py}, tests/{test_fail_safe_rci.py, test_rci_control_plane.py, test_rci_mutation_api.py} |
| verify | ruff/mypy/openapi/docs exit 0; pytest 1321 passed/1 skipped under VPN (1 env failure test_live_uvicorn_origin_null_login); VPN off → that test passes (quick subset 133/133) |
| notes | Architecture pivot to RCI; typed sealed control plane delivered + live-verified (fail-safe arm/disarm); WriteCertified not claimed; Gates B/C/D unchanged. Colliding parallel implementation reconciled. |
