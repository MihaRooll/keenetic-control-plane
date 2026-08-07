# Session handoff — real router lab (2026-07-24)

> **SUPERSEDED for active narrative (2026-07-31):** Current session handoff is [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) (post-rebind unit methods/traps/status). **Living policy SSOT** remains [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml). This 2026-07-24 doc is **historical** — prior-unit sealed ops, T4 campaigns, standing-auth 2026-07-24 context; host-key SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM and live WG/AWG evidence apply to **prior physical unit only** — **superseded** by rebind pin SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY.

**Status: HISTORICAL HANDOFF (2026-07-24 session closeout).** Superseded for active narrative by [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md).

## For agents

> **HISTORICAL ONLY.** This table describes the **prior-unit** 2026-07-24 session — **not** the live guide for the post-rebind unit. For current narrative use [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md).

| Topic | Rule |
|---|---|
| When to read | **HISTORICAL ONLY / methods archive** — prior physical unit 2026-07-24 sealed ops, T4 campaigns, standing-auth context. **Do not** use for current post-rebind lab work; read [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) instead |
| Delivered | Route parser `default-route-v1.2`; sanitize hardened (Wi-Fi/WG secret field names); sealed Wi-Fi ops (SSID/WPA/encryption/up/down); sealed AWG ops (create/asc/remove); operator CLIs `wifi-rci-op.py` / `wireguard-rci-op.py`; WifiIntent product model (`wpa_mode` + `band`); `wifi_apply_planner` + `wifi_apply_service`; POST `/wifi/preview\|apply\|teardown`; UI Wi-Fi Apply (test AP); live WPA2 + AWG core verified on **prior-unit** test AP; full web E2E; verify baseline **2075 passed / 0 failed / 2 skipped** (see §15.4) |
| Not delivered | Production AP apply (AccessPoint0/1/2); AWG secret tunnel end-to-end (private-key transport **partially device-verified**; **nested_rci peer WRITE device-verified ACCEPTED** 2026-07-24 — evidence only, NOT WriteCertified; path-style peer **REJECTED** live; preshared-key / tunnel connectivity **NOT** verified); Gate B / `write_shapes_registered` formalization; captive portal; KeenDNS; extended AWG asc I1–I5 encoding — remaining **carve-outs** require **explicit per-action** human confirmation. **Historical planning (frozen):** §14 + §14.6 — superseded for next-task by 2026-07-31 handoff + STATUS |
| Superseded | **This entire doc** for active narrative — use [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md). Historical prior session: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) |
| SSOT | **Historical (2026-07-24 session / prior unit):** evidence `data/artifacts/gate-a-return-home-192.168.2.1-20260723.json` — **superseded** by authorized rebind **2026-07-31**. **Current Gate A SSOT:** [`STATUS.yaml`](STATUS.yaml) + [`gate-a-certification.json`](gate-a-certification.json) → `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json` (rebind #2 post-WG; rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**) |
| Writes | **Standing bounded live-verification authorization (2026-07-24):** in-envelope Wi‑Fi/AWG apply+teardown on bounded test resources proceeds **autonomously** within envelope (identity preflight fail-closed; backup to `data/backups/`; no save; `credential_ref` only; evidence to `data/artifacts/`). Per-campaign T4 packets = **records/evidence**, not blocking gate. **Carve-outs** = **hard STOP** — explicit per-action confirmation. Gate B fail_safe **completed_failed**; Gates C/D closed |
| Topology | **Current:** laptop Ethernet source `192.168.2.10` → test NC-1812 `192.168.2.1` on `192.168.2.0/24`; home working router `192.168.1.1` via Wi‑Fi on `192.168.1.0/24`; dual NIC → `--source-address 192.168.2.10` **mandatory** |
| Secrets | Never document passwords, keys, cookie values, raw startup-config, or absolute backup file paths |

---

## 1. Session summary

This handoff persists evidence from the **dedicated NC-1812 lab session** ending **2026-07-24**: offline delivery of route parser, sanitize hardening, sealed Wi-Fi and AWG write operations, Wi-Fi product model and apply/verify stack, plus **live device-verified** bounded test-AP campaigns and **full E2E web** flow — all under human-approved T4 with full rollback and **no** `system configuration save`.

**Offline deliveries (L2 subagents; verifier passed):**

- **Route parser `default-route-v1.2`:** accepts real direct-array `/rci/show/ip/route` shape from lab fixtures.
- **`sanitize.py` hardened:** redacts Wi-Fi/WG secret field names (`psk`, `passphrase`, `preshared`, `private_key`, `privatekey`, `wpa_psk`, `obfs_key`); public-key/host-key/keepalive/ssid/encryption preserved.
- **Sealed write ops (bounded, security-reviewed):**
  - `wifi_rci.py`: `SET_SSID`, `CLEAR_SSID`, `UP`, `DOWN`, `SET_WPA_PSK` (secret via vault credential-ref), `ENCRYPTION_ENABLE`, `ENCRYPTION_DISABLE`, `ENCRYPTION_WPA2`, `ENCRYPTION_WPA2_CLEAR`. Allowlist `WifiMaster[01]/AccessPoint[3-9]` (`AccessPoint0/1/2` hard-blocked).
  - `wireguard_rci.py`: `CREATE_INTERFACE`, `REMOVE_INTERFACE`, `SET_ASC`. Allowlist `Wireguard[5-9]`; asc = exactly 9 or 16 integers.
  - Operator CLIs: `scripts/wifi-rci-op.py`, `scripts/wireguard-rci-op.py` (validate-default + `--execute` win32/DPAPI).
- **Wi-Fi product model:** `WifiIntent` `wpa_mode` (WPA2 default / WPA3 / WPA2_WPA3_MIXED) + `band` (`BAND_2_4GHZ`→`WifiMaster0` / `BAND_5GHZ`→`WifiMaster1`); parser/readiness/planner; `wifi_apply_planner.py` (APPLY: set_ssid→set_wpa_psk→encryption_enable→encryption_wpa2→up; TEARDOWN reverse incl `encryption_wpa2_clear`). WPA3 = `unsupported_pending_verification` at first closeout *(SUPERSEDED — see §14: WPA3/mixed device-verified 2026-07-24 on AccessPoint3; grammar `authentication wpa-psk` + `encryption wpa3`, NOT `authentication sae`)*.
- **Web:** `wifi_apply_service.py`; `wifi_apply_routes.py` POST `/api/router-control/v1/wifi/preview|apply|teardown`; `wifi_live_transport.py`; UI **Wi-Fi Apply (test AP)** in `router_control_host/web/{index.html,app.js,styles.css}`.
- **AWG apply (offline vertical, 2026-07-24):** `WireguardIntent` + `wireguard_apply_planner/service`; POST `/wireguard/preview|apply|teardown`; UI **AWG Apply (test interface)**; reuses `open_wifi_live_session`; see [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md).

**Live device-verified NC-1812** (Gate A tuple matched: model NC-1812, firmware 5.01.C.1.0-0, host-key SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM, source `192.168.2.10`; pre-change backups under `data/backups/`; **NO** system configuration save; full rollback; baseline restored):

- **Wi-Fi `WifiMaster0/AccessPoint3`:** ssid/up/down/no-ssid; WPA2 (auth wpa-psk[vault throwaway] + encryption enable + encryption wpa2); teardown to baseline.
- **AWG `Wireguard5`:** create; asc 9-arg accepted; asc 16-arg **REJECTED** (I1–I5 encoding unresolved); remove.
- **Web E2E (executed; artifact-backed):** auth → preview → apply(confirm) → backup + 5 sealed ops + readback verify → teardown → baseline. Evidence: `data/artifacts/wifi-web-e2e-verify-192.168.2.1-20260724.json`; pre-change backup `data/backups/startup-192.168.2.1-20260724T074507Z-946280a4`; sealed-op/WPA artifacts in §6. PSK never logged.

Prior discovery/T4 packet docs remain valid: [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md), [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md), [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md), [`T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_AWG_WRITESHAPE_VERIFY_2026-07-23.md), [`T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md`](T4_GATE_PACKET_WIFI_WRITESHAPE_VERIFY_2026-07-23.md).

Historical handoff: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) (**historical**). Active narrative: [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md).

---

## 2. Completed inventory

| Track | Deliverable | Scope | Live-ready |
|---|---|---|---|
| **Route parser** | `default-route-v1.2` accepts direct-array `/rci/show/ip/route` | Offline + fixture-backed | DiscoveryRead/non-certifying |
| **Sanitize** | Wi-Fi/WG secret field redaction hardened | Offline | N/A |
| **Sealed Wi-Fi ops** | `wifi_rci.py` + `scripts/wifi-rci-op.py` | Bounded test APs `AccessPoint[3-9]` | **Yes** — in-envelope **standing authorized** (2026-07-24; §14.6); carve-outs explicit per-action |
| **Sealed AWG ops** | `wireguard_rci.py` + `scripts/wireguard-rci-op.py` | Bounded `Wireguard[5-9]` | **Yes** — in-envelope **standing authorized** (2026-07-24; §14.6); secret WG ops deferred; carve-outs explicit per-action |
| **Wi-Fi product model** | `WifiIntent` `wpa_mode` + `band`; parser/readiness/planner | Offline; WPA2 verified path | WPA3 pending T4 *(SUPERSEDED — see §14: WPA3 + WPA2/WPA3-mixed device-verified 2026-07-24)* |
| **Wi-Fi apply stack** | `wifi_apply_planner.py`, `wifi_apply_service.py`, API routes, UI | Preview offline-safe; apply/teardown confirm-gated | **Yes** — bounded test AP + T4 |
| **Live Wi-Fi verify** | ssid/up/down + WPA2 on `WifiMaster0/AccessPoint3` | Human-approved T4 2026-07-24 | Executed; full rollback |
| **Live AWG verify** | create/asc-9/remove on `Wireguard5` | Human-approved T4 2026-07-24 | Executed; asc-16 rejected |
| **Web E2E** | auth → preview → apply → verify → teardown | Full stack on test AP | Executed 2026-07-24; evidence: `data/artifacts/wifi-web-e2e-verify-192.168.2.1-20260724.json` + apply backup `data/backups/startup-192.168.2.1-20260724T074507Z-946280a4` + §6 sealed-op/WPA artifacts |
| **Prior session (2026-07-23)** | P1–P3 substrates, Gate A recert, sealed interface/save CLIs, integration facade, UI `#config`, VPN import, AWG parser 1.5 | See prior handoff | See prior handoff |

Gates **unchanged:** A open ReadOnlyCertified; B fail_safe **completed_failed** (not WriteCertified); C **closed** completed_failed; D closed. **`write_shapes_registered` false.**

---

## 3. Latest full verification

**Fresh session verification** on **2026-07-24**. Key commands exit **0**:

| Command | Result |
|---|---|
| `py.exe -3.11 -m pytest -q` | **2075 passed, 0 failed, 2 skipped** |
| `py.exe -3.11 -m ruff check router_control router_control_host tests scripts` | exit 0 (clean) |
| `py.exe -3.11 -m mypy router_control router_control_host` | exit 0 (clean) |
| OpenAPI drift check | no drift |
| `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/validate-project-docs.ps1` | exit 0 |
| `py.exe -3.11 scripts/project-docs.py audit --project-root .` | exit 0 |

**Repository state:** NO commits since **2026-07-21**; dirty working tree preserved.

Standard suite (for repro):

```text
py.exe -3.11 -m pytest -q
py.exe -3.11 -m ruff check router_control router_control_host tests scripts
py.exe -3.11 -m mypy router_control router_control_host
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
| Host-key pin | SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM — **MATCHED** on all 2026-07-24 live campaigns |

**Pre-T4 confirmation:** same tuple + host-key pin + `--source-address 192.168.2.10` → test router `192.168.2.1` — not a silent rebind.

---

## 5. Physical topology — current (network migration 2026-07-23)

| Check | Result |
|---|---|
| Reachability | Test router `192.168.2.1` reachable from host Ethernet `192.168.2.10` |
| HTTP :80 | **200** |
| RCI `/rci/show/version` (unauthenticated) | **401** with `WWW-Authenticate: x-ndw2-interactive endpoint="/auth"` |
| SSH :22 | Open |
| ed25519 host-key SHA256 | `SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM` — **matches** Gate A pin |
| Host outbound bind | **`192.168.2.10`** mandatory (dual NIC: home `192.168.1.1` via Wi‑Fi on `192.168.1.0/24`) |

See [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) §7a and prior handoff §Network migration for historical pre-migration topology.

---

## 6. Discovery / evidence artifacts (non-certifying + live verify)

| Artifact basename | Kind |
|---|---|
| `awg-shape-192.168.2.1-20260723.json` | AWG RO write-shape discovery |
| `wifi-writeshape-verify-192.168.2.1-20260724.json` | Live Wi-Fi ssid/up/down verify |
| `awg-writeshape-verify-192.168.2.1-20260724.json` | Live AWG create/asc-9/remove verify |
| `wifi-wpa-writeshape-verify-192.168.2.1-20260724.json` | Live Wi-Fi WPA2 verify |
| `gate-a-probe-preflight-wifi-20260724.json` | Gate A preflight Wi-Fi campaign |
| `gate-a-probe-preflight-awg-20260724.json` | Gate A preflight AWG campaign |
| `wifi-web-e2e-verify-192.168.2.1-20260724.json` | Web E2E apply/teardown via HTTP API (auth → preview → apply → verify → teardown) |
| `awg-peer-nested-rci-live-verify-192.168.2.1-20260724.json` | Nested-RCI peer live probe REJECTED (op dispatch failed); private-key re-confirmed; baseline restored |
| `gate-a-preflight-live-192.168.2.1-20260724.json` | Gate A identity preflight PASS (2nd AWG nested-RCI+PSK campaign, standing auth) |
| `awg-peer-nested-rci-psk-live-192.168.2.1-20260724.json` | AWG nested-RCI peer+PSK E2E apply/teardown via web-host API (2nd campaign, standing auth) |

All under `data/artifacts/`. **Does not** open Gates B/C/D or register write shapes.

---

## 7. Encrypted backup — sanitized metadata only

Pre-change startup-config backups taken before 2026-07-24 live campaigns; storage DPAPI encrypted under `data/backups/` (basenames only — e.g. `startup-192.168.2.1-20260724T054149Z-59eb11d7`, `startup-192.168.2.1-20260724T060610Z-576347f8`, `startup-192.168.2.1-20260724T074507Z-946280a4` [web apply E2E]). **No** `system configuration save` executed. No raw startup-config content, no absolute filesystem paths, no credentials.

---

## 8. Gates posture

| Gate | Status | Notes |
|---|---|---|
| **A** | Open ReadOnlyCertified | Return-home evidence SSOT on `192.168.2.10` (§4); live T4 campaigns matched tuple |
| **B** | completed_failed | Trial `fail-safe-20260723T110000Z`; historical CertificationTrialAuthorized (**not WriteCertified**); registries empty |
| **C** | closed completed_failed | Second window closed 2026-07-23 |
| **D** | closed | Production-only |
| **T4 / standing auth** | **Standing bounded live-verification authorization (2026-07-24)** for in-envelope work; historical per-campaign T4 campaigns remain evidence. **Carve-outs** require explicit per-action confirmation |
| **write_shapes_registered** | **false** | Narrative only; not flipped |
| **WriteCertified** | **NOT claimed** | Wi-Fi apply = narrow bounded-test-AP exception, not broad WriteCertified |

---

## 9. Constraints / safe live-testing pattern

- **Preserve dirty working tree** — do not `git clean`, reset, or discard uncommitted work.
- **Safe live-testing pattern:** sealed op + security review → identity preflight (Gate A tuple + host-key pin + `--source-address 192.168.2.10`) → pre-change encrypted backup → minimal reversible write on **bounded test AP** (`WifiMaster0/AccessPoint3`–`AccessPoint9` or `Wireguard5`–`Wireguard9`) → readback verify → rollback → **NO** `system configuration save` → sanitized evidence under `data/artifacts/`. **In-envelope:** standing authorized (2026-07-24) — autonomous. **Carve-outs:** explicit per-action human confirmation required.
- **No router writes** outside standing bounded envelope or without carve-out explicit confirmation.
- Cold-start (**historical — do not use**): for current unit use [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md) → [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). Prior-unit paste archive: [`NEW_CHAT_COLD_START_2026-07-24b.md`](NEW_CHAT_COLD_START_2026-07-24b.md) / [`NEW_CHAT_COLD_START_2026-07-24.md`](NEW_CHAT_COLD_START_2026-07-24.md) (**superseded**).
- Dedicated lab program: Gate A RO + **standing bounded reversible verification** (2026-07-24) + offline prep — carve-outs still hard STOP ([`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md)).
- DPAPI credentials valid only under the **current OS user** who enrolled them.

---

## 10. Next steps (deferred, with tier tags)

*Pre-continued-session freeze — **HISTORICAL**; §14.5 was active planning at 2026-07-24 closeout — superseded for next-task by [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + STATUS.*

1. **Production-AP apply** — widen allowlist beyond test APs = **T3** architecture + **per-campaign T4**.
2. **WPA3 live-verify** — `unsupported_pending_verification` today = **T4**. *(Superseded §14.3: WPA3 + WPA2/WPA3-mixed **device-verified**.)*
3. **AWG secret tunnel ops** — private-key/peer/preshared-key = **T3** + **T4**. *(Superseded partially §14.3: private-key **ACCEPTED** (partially device-verified); nested_rci peer WRITE **device-verified ACCEPTED** 2026-07-24 (evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`); NEW re-verify **DONE** §14.5; preshared-key pending; **NOT** tunnel connectivity / **NOT** WriteCertified / `write_shapes_registered` remains false.)*
4. **Gate B / `write_shapes_registered` formalization** — deferred; registries remain empty.
5. **Captive portal** — Coova-Chilli install+reboot = escalated **T4**.
6. **KeenDNS/CrazeDNS** — cloud/external = **T4**.
7. **Extended AWG asc I1–I5 encoding** — 16-int asc rejected on device; probe unresolved.
8. **VPN AWG apply/verify UI vertical** — mirror Wi-Fi stack; offline first, live **T4**. *(Superseded §14.1: **delivered offline**.)*

Offline code/tests/docs for deferred items may proceed autonomously within T2 bounds. **In-envelope LIVE WRITE** = standing authorized (2026-07-24). **Carve-out LIVE WRITE** = explicit per-action human confirmation required.

---

## 11. Blockers

| ID | Scope | Status |
|---|---|---|
| Extended AWG asc I1–I5 encoding | 16-int asc on Wireguard5 | **Open** — device rejected; encoding unresolved |
| AWG secret WG ops | private-key/peer/preshared-key | **Open** — deferred T3+T4 *(§14.3 **PARTIAL**: private-key transport partially device-verified; peer path-style **REJECTED** live; OLD pubkey-keyed nested body **REJECTED** live 2026-07-24; nested_rci peer WRITE on corrected array/`key` shape **device-verified ACCEPTED** 2026-07-24 — evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`; NEW re-verify **DONE** §14.5; preshared-key pending; **NOT** tunnel connectivity / **NOT** WriteCertified / `write_shapes_registered` remains false; Gate B formalization **BLOCKED** §14.5)* |
| Production AP allowlist | AccessPoint0/1/2 | **Open** — needs T3+T4 decision |
| Write certification | per-family Gate B | Gate B completed_failed; formalization deferred |
| WPA3 | WifiIntent wpa_mode | **Open** at first closeout — unsupported_pending_verification *(SUPERSEDED — see §14: WPA3/mixed device-verified 2026-07-24 on AccessPoint3)* |

---

## 12. Cold-start prompt for new AI chat

> **HISTORICAL — do not paste.** Current cold-start: [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md) → [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md).

Prior-unit paste archive (**superseded**): [`NEW_CHAT_COLD_START_2026-07-24b.md`](NEW_CHAT_COLD_START_2026-07-24b.md), [`NEW_CHAT_COLD_START_2026-07-24.md`](NEW_CHAT_COLD_START_2026-07-24.md). **Do not** paste passwords, keys, or cookie values.

---

## 13. Related docs

| Doc | Role |
|---|---|
| [`STATUS.yaml`](STATUS.yaml) | SSOT phase, gates, next_task |
| [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md) | **Current** paste-ready cold-start (post-rebind 2026-07-31) |
| [`NEW_CHAT_COLD_START_2026-07-24b.md`](NEW_CHAT_COLD_START_2026-07-24b.md) | Historical cold-start prompt (superseded — prior unit §14) |
| [`NEW_CHAT_COLD_START_2026-07-24.md`](NEW_CHAT_COLD_START_2026-07-24.md) | Historical cold-start prompt (superseded) |
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Program vs action; §7a topology |
| [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md) | Wi-Fi apply/verify API + UI runbook |
| [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md) | AWG/WireGuard apply/verify API + UI runbook |
| [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) | Wi-Fi write-shape discovery |
| [`OPERATOR_AWG_DISCOVERY.md`](OPERATOR_AWG_DISCOVERY.md) | AWG write-shape discovery |
| [`OPERATOR_UI.md`](OPERATOR_UI.md) | Prototype host launch, auth, standalone profile |
| [`OPERATOR_RCI_TYPED_OPS.md`](OPERATOR_RCI_TYPED_OPS.md) | Sealed interface/save operator CLIs |
| [`contracts/HARDWARE_GATES.md`](contracts/HARDWARE_GATES.md) | Gate definitions |
| [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) | Historical prior session |

---

## 14. 2026-07-24 (continued session)

**Scope note:** Sections §1–§13 above record the **first closeout** of 2026-07-24 (WPA2 + AWG core + web E2E). **§14 appends** a second work block in the same calendar session on the **prior physical unit**. Where earlier sections still say WPA3 «not live-verified» / `unsupported_pending_verification` / AWG secret tunnel «deferred» / VPN AWG vertical «not delivered» — those claims reflect **pre-continued-session** state; **§14 records 2026-07-24 continued-session results as historical fact only** — **superseded for active next-task** by [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + STATUS.

**Repository:** last commit **2026-07-21**; dirty working tree preserved; **no commits** in continued session.

### 14.1 DELIVERED OFFLINE (code + tests + docs; verifier passed; gates unchanged)

| Track | Deliverable |
|---|---|
| **VPN AWG apply/verify vertical** | Mirrors Wi-Fi: `WireguardIntent` in `router_control/domain/network_intents.py`; `wireguard_apply_planner.py`; `wireguard_apply_service.py`; `wireguard_apply_routes.py` (POST `/api/router-control/v1/wireguard/preview\|apply\|teardown`); UI **AWG Apply (test interface)** in web `#config`; [`OPERATOR_AWG_APPLY.md`](OPERATOR_AWG_APPLY.md). Bounded `Wireguard[5-9]`; ops create/asc-9/up + teardown. |
| **WPA3/SAE + WPA2/WPA3-mixed Wi-Fi vertical** | Sealed ops in `wifi_rci.py` + allowlist arms (bounded `WifiMaster[01]/AccessPoint[3-9]`); planner/service/UI/tests/docs. |
| **AWG extended-ASC / I1–I5 probe harness** | `scripts/probe-nc1812-awg-asc-encoding.py` (**PLAN-ONLY**; `--execute` refused; no allowlist change). |
| **AWG secret tunnel ops** | Sealed ops in `wireguard_rci.py` + allowlist (`Wireguard5-9`): private-key/peer/preshared-key; planner/service/API/UI/tests/docs. Secrets **only** via `credential_ref` (vault kinds `awg_private_key` / `awg_preshared_key`), resolved at dispatch, never logged. |
| **Teardown best-effort hardening** | `wifi_apply_service.py` + `wireguard_apply_service.py`: continue-on-error; guaranteed `wifi_ap_clear_ssid` / `wireguard_remove_interface`; readback-exception aggregates dispatch errors. Apply-path unchanged (still aborts on first failure). |

### 14.2 Grammar corrections (offline)

| Area | Correction |
|---|---|
| **WPA3** | Uses `authentication wpa-psk` + `encryption wpa3` — **removed non-existent** `authentication sae`. |
| **AWG peer** | Path-style per-attribute lines + dotted-mask `allow-ips` — **REJECTED** live 2026-07-24. Nested body corrected offline to array/`key` shape (`endpoint.address`, `allow-ips[{address,mask}]`, `keepalive-interval.interval`); prior live probe used OLD pubkey-keyed flat body and **REJECTED**; corrected shape **device-verified write ACCEPTED** 2026-07-24 re-verify (evidence `awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`; NOT WriteCertified / NOT tunnel connectivity). Default `peer_rci_shape=nested_rci`. |

### 14.3 LIVE-VERIFIED (explicit per-campaign human T4; full rollback; **NO** system configuration save)

Tuple: NC-1812 / firmware **5.01.C.1.0-0** / SSH host-key **SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM** / host **192.168.2.1** / source **192.168.2.10** / `cred_ref` **cred_db65665dd59f600bdd23544d85564c83**. Evidence under `data/artifacts/` (sanitized, gitignored):

| Campaign | Result | Evidence basename |
|---|---|---|
| AWG `Wireguard5`: create + `wireguard asc 5 42 54 0 0 1 2 3 4` + up → teardown | **CONFIRMED** | `awg-wireguard5-live-verify-192.168.2.1-20260724.json` |
| Wi-Fi WPA2 on `WifiMaster0/AccessPoint3`: ssid + wpa-psk(WPA2) + up → teardown | **CONFIRMED** | `wifi-wpa2-live-verify-192.168.2.1-20260724.json` |
| Wi-Fi WPA3 on `AccessPoint3` — **first attempt** (`authentication sae`) | **REJECTED** (wrong grammar) | `wifi-wpa3-live-verify-192.168.2.1-20260724.json` |
| Wi-Fi WPA3 — **re-verify** after offline grammar fix (`authentication wpa-psk` + `encryption wpa3`; readback `encryption: wpa3`) | **CONFIRMED** | `wifi-wpa3-live-reverify-192.168.2.1-20260724.json` |
| Wi-Fi WPA2/WPA3-mixed on `AccessPoint3` (readback `encryption: wpa2,wpa3`) | **CONFIRMED** | `wifi-wpa2wpa3-mixed-live-verify-192.168.2.1-20260724.json` |
| AWG secret tunnel on `Wireguard5` | **PARTIAL** — `wireguard private-key` **ACCEPTED** (private-key grammar device-verified); `wireguard peer` (path-style single-line) **REJECTED** (peer needs **NESTED RCI**); `no wireguard private-key` **REJECTED** (undocumented); `no interface Wireguard5` cleanup **ACCEPTED** → baseline restored | `awg-secret-tunnel-wireguard5-live-probe-192.168.2.1-20260724.json` |
| AWG nested-RCI peer on `Wireguard5` (`peer_rci_shape=nested_rci`, web-E2E) | **REJECTED** — `wireguard_create_interface` ok; `wireguard_set_private_key` ok (private-key transport re-confirmed); `wireguard_upsert_peer_nested` **FAILED** (op dispatch failed); nested RCI body under `interface.WireguardN.wireguard.peer.<pubkey>` rejected same symptom as path-style peer; teardown: interface_down ok, remove_interface ok → baseline restored (readback `{}`); `clear_private_key`/`remove_peer` dispatch failed but interface removal guaranteed cleanup; `system_configuration_saved=false`; throwaway credentials deleted post-teardown — **OLD pubkey-keyed flat body; shape corrected offline afterward** | `awg-peer-nested-rci-live-verify-192.168.2.1-20260724.json` |
| AWG nested-RCI peer re-verify on `Wireguard5` (`peer_rci_shape=nested_rci`, corrected array/`key` shape, web-E2E) | **ACCEPTED (device-verified write)** — `wireguard_create_interface` ok; `wireguard_set_private_key` ok; `wireguard_upsert_peer_nested` **ACCEPTED** (ack matched + interface applied/up); corrected array/`key` nested body works where path-style peer + OLD pubkey-keyed nested body were **REJECTED**; teardown: interface_down ok, remove_interface ok → baseline restored; `clear_private_key` standalone **FAILED** (KNOWN quirk, non-blocking — cleanup guaranteed via `wireguard_remove_interface`); `system_configuration_saved=false`; throwaway credentials deleted post-teardown — **NOT** tunnel connectivity; **NOT** WriteCertified; **NOT** Gate B / `write_shapes_registered` | `awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json` |
| AWG nested-RCI peer + PSK on `Wireguard5` (2nd campaign, standing auth, web-host API E2E) | **PARTIAL** — identity preflight PASS (NC-1812 / 5.01.C.1.0-0 / host-key match / source `192.168.2.10`); apply HTTP 200, overall=applied; steps create → set private-key → upsert peer nested → interface up; private-key transport re-confirmed **ACCEPTED** (ack matched); nested_rci peer WRITE re-confirmed **ACCEPTED** (2nd campaign, ack matched); preshared-key enrolled via `credential_ref` and dispatched on nested upsert → **WRITE-ACKED** but effect NOT independently confirmed (artifact `verification_status=pending_live_verification`; PSK NOT device-verified / still PENDING); apply readback observed interface state only — nested peer field readback (endpoint/allow-ips/keepalive) NOT independently performed; after teardown interface removed, so independent peer-config field readback not obtained (future in-envelope item); teardown remove_peer + remove_interface OK → baseline restored; `clear_private_key` standalone **REJECTED** (KNOWN quirk, non-blocking — cleanup guaranteed via `remove_interface`); `system_configuration_saved=false`; throwaway `credential_ref` entries deleted post-teardown — **NOT** tunnel connectivity; **NOT** WriteCertified; **NOT** Gate B / `write_shapes_registered` | `data/artifacts/gate-a-preflight-live-192.168.2.1-20260724.json`; `data/artifacts/awg-peer-nested-rci-psk-live-192.168.2.1-20260724.json` |
| Wi-Fi sealed path (WPA2/WPA3/mixed + idempotent + compensating rollback) on `WifiMaster0/AccessPoint3` (expendable lab, post-rebind Gate A 2026-07-31) | **CONFIRMED (apply path)** — NC-1812 / fw 5.01.C.1.0-0 / host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY / source `192.168.2.10`; preview sealed ops; apply=applied; readback ssid/encryption/state up; observed-vs-desired match via `open_wifi_live_session` (HTTP observed-state **503** this run — **NOT** HTTP live-validated); idempotent re-apply skipped set_ssid/encryption_enable/encryption_wpa2/up, PSK op dispatched; compensating rollback via missing PSK ref overall=rolled_back (CLIENT-side VaultError — router-rejection taxonomy unverified); pre-change backup; no save; no reboot — **NOT** WriteCertified; `write_shapes_registered` remains false; gates A/B/C/D UNCHANGED | `wifi-sealed-path-live-gate-a-20260731.json` |

**Offline status flips (planner/readiness, not gates):** pure WPA3 and WPA2/WPA3-mixed → `verification_status="device_verified_wpa2"`; Wi-Fi readiness `unverified` warnings removed. AWG secret tunnel stays **`pending_live_verification`** overall; planner records **private-key transport as partially device-verified** (SET_PRIVATE_KEY op note + plan-level enrichment; re-confirmed 2026-07-24 nested-RCI probes); **nested_rci peer write device-verified ACCEPTED** on corrected array/`key` shape (2026-07-24 re-verify; **re-confirmed 2nd campaign 2026-07-24**); preshared-key WRITE-ACKED on nested upsert (2nd campaign) but effect NOT independently confirmed — PSK remains NOT device-verified; nested peer-config field readback (endpoint/allow-ips/keepalive) still pending; path-style peer transport **REJECTED** live; default `peer_rci_shape` flipped to **`nested_rci`** offline (2026-07-24). **Do not** claim AWG secret tunnel fully device-verified, PSK device-verified, tunnel connectivity, WriteCertified, or `write_shapes_registered=true`.

**Gates unchanged:** A open ReadOnlyCertified; B **completed_failed**; C/D **closed**. **WriteCertified NOT claimed.** **`write_shapes_registered` remains false.**

### 14.4 SAFE LIVE-TESTING PATTERN + WEB HOST LIVE E2E (summary)

**Safe live-testing pattern:** sealed op + security review → identity preflight (Gate A tuple + host-key pin + `--source-address 192.168.2.10`) → pre-change encrypted backup (`data/backups/`) → minimal reversible write on bounded test AP (`WifiMaster0/AccessPoint3`–`AccessPoint9` or `Wireguard5`–`Wireguard9`) → readback verify → rollback → **NO** `system configuration save` → sanitized evidence (`data/artifacts/`). **In-envelope:** standing authorized (2026-07-24) — autonomous; per-campaign T4 packets = evidence. **Carve-outs:** explicit per-action human confirmation.

**Web host live E2E recipe:**

```text
$env:RC_ADAPTER_MODE = "live"
$env:HUB_ADMIN_PASSWORD = "<your-operator-password>"
$env:RC_STANDALONE_LOOPBACK_AUTH = "1"
$env:RC_PUBLIC_BASE_URL = "http://127.0.0.1:8787"
uvicorn router_control_host.app:app --host 127.0.0.1 --port 8787
# Auth: POST /login → hub_admin cookie (or mint via router_control_host.auth.mint_hub_admin_cookie in tests)
# UI: /settings/router-control → #config → Wi-Fi Apply / AWG Apply (test interface)
# API: confirm_live_apply / confirm_live_teardown on POST /wifi/* and /wireguard/*
# Vault: DPAPI credentials under data/secrets/ (credential_ref only; never plaintext in requests/logs)
```

Alternative launcher: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/run-prototype-host.ps1` (sets loopback profile; add `RC_ADAPTER_MODE=live` for live adapter).

### 14.5 NEXT TASKS (priority + tier; **HISTORICAL** — frozen 2026-07-24 closeout)

> **Superseded for active planning** by [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) + [`STATUS.yaml`](STATUS.yaml) `next_task`. Retained as prior-unit archive only.

1. ~~**AWG peer RCI NEW-shape live re-verify** (T4).~~ **DONE (2026-07-24):** nested_rci peer WRITE **device-verified ACCEPTED** on corrected array/`key` shape (evidence `awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json`); prior OLD pubkey-keyed probe **REJECTED** (historical `awg-peer-nested-rci-live-verify-192.168.2.1-20260724.json`); path-style peer **REJECTED** live; private-key transport partially device-verified (re-confirmed); `clear_private_key` standalone teardown **FAILED** (KNOWN quirk, non-blocking); **NOT** tunnel connectivity / **NOT** WriteCertified / `write_shapes_registered` remains false.
2. ~~Optionally record AWG private-key as **partially device-verified** (offline status flip).~~ **DONE (2026-07-24 offline):** planner SET_PRIVATE_KEY op carries partial device-verified note; plan-level `verification_status` remains `pending_live_verification`.
3. Extended-ASC 16-arg / I1–I5 live-probe (needs bounded allowlist extension — **carve-out**, explicit per-action confirmation).
4. Production-AP apply widen allowlist — **T3 fork + carve-out confirmation** — **BLOCKED** pending human sign-off (removing AccessPoint0/1/2 hard-block).
5. Captive portal Coova-Chilli install+reboot — escalated **carve-out** — **BLOCKED**.
6. KeenDNS/CrazeDNS cloud/external — **carve-out** — **BLOCKED**.
7. Gate B / `write_shapes_registered` formalization — **BLOCKED** (no gate opens without evidence).

Offline code/tests/docs autonomous within T2/T3. **In-envelope LIVE WRITE** = standing authorized (2026-07-24). **Carve-out LIVE WRITE** = explicit per-action human confirmation.

**Cold-start (historical — do not paste):** use [`NEW_CHAT_COLD_START_2026-07-31.md`](NEW_CHAT_COLD_START_2026-07-31.md). Prior-unit archive: [`NEW_CHAT_COLD_START_2026-07-24b.md`](NEW_CHAT_COLD_START_2026-07-24b.md) (**superseded**).

---

### 14.6 Standing bounded live-verification authorization (2026-07-24)

Human operator granted **standing authorization** for bounded, reversible live verification on the dedicated NC-1812 lab, replacing the previous per-campaign **STOP** for in-envelope work.

| Envelope (autonomous) | Carve-outs (hard STOP — explicit per-action confirmation) |
|---|---|
| Exact tuple + host-key preflight fail-closed (NC-1812 / 5.01.C.1.0-0 / SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM / source `192.168.2.10`) | Production APs `AccessPoint0/1/2`; any resource outside bounded ranges; allowlist widening |
| Bounded resources: `Wireguard5`–`Wireguard9`; `WifiMaster0/AccessPoint3`–`AccessPoint9` | `system configuration save`; reboot; component install; factory reset; firmware changes |
| Pre-change backup to `data/backups/`; minimal reversible writes; readback; rollback/teardown | KeenDNS/CrazeDNS; opening Gate B/C/D; WriteCertified; `write_shapes_registered=true` |
| **NO** system configuration save | Irreversible or non-guaranteed-rollback operations |
| Throwaway secrets via `credential_ref` only; sanitized evidence to `data/artifacts/` | Operator «разрешаю всё» = envelope only, **not** carve-outs |

**Gates/cert unchanged:** A open ReadOnlyCertified; B **completed_failed**; C/D **closed**; **WriteCertified NOT claimed**; **`write_shapes_registered` remains false**.

SSOT: [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) standing authorization section; [`STATUS.yaml`](STATUS.yaml) `approvals.dedicated_development_router_lab`.

---

## 15 Session log 2026-07-24 (continued — orchestrator autonomy)

Autonomous orchestrator session closeout. **§14 / §14.6 are HISTORICAL** (prior-unit live matrix, standing authorization 2026-07-24, frozen next tasks); for current lab use [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md). This section records measured offline + live cycles and lessons only.

### 15.1 Offline cycles

| Cycle | Scope | Outcome |
|---|---|---|
| **(A) GREEN baseline** | Static-asset secret vocabulary test + lint | Fixed `test_static_assets_no_secret_vocabulary` (mask safe `*_credential_ref_id`); **5** ruff fixes; baseline green |
| **(B) AWG peer nested_rci** | Corrected RCI shape + ack parsing | `wireguard.peer[]` array with `key` + nested `endpoint.address` / `allow-ips[{address,mask}]` / `keepalive-interval.interval` (ivansible/ndm-wireguard); nested ack accepts `status[]` without parse prompt (additive); `path_style` default at time of first probe |
| **(C) Web UI P0** | SPA gaps + honest copy | `peer_rci_shape` select; Wi-Fi enabled; Logout; WPA3 copy sync; honest KeenDNS/draft/gate-banner; UI tests added |
| **(D) Docs drift reconcile** | SSOT alignment | WPA3 supersession notes; dual sealed-apply-vs-preset pipeline; deferred-verticals roadmap |

### 15.2 Live campaigns (human-approved; bounded envelope)

| Probe | Body / shape | Result |
|---|---|---|
| 1st nested_rci | OLD pubkey-keyed flat body | **REJECTED** — op dispatch failed (see §14.3 historical row) |
| 2nd nested_rci (re-verify) | Corrected array/`key` nested body | **ACCEPTED (device-verified write)** — ack matched, interface up; evidence `data/artifacts/awg-peer-nested-rci-live-reverify-192.168.2.1-20260724.json` |
| 3rd nested_rci + PSK (2nd campaign, standing auth) | nested_rci + `credential_ref` PSK on upsert; web-host API E2E | **PARTIAL** — identity preflight PASS; peer write re-confirmed ACCEPTED (2nd campaign); private-key re-confirmed ACCEPTED; PSK write-acked, effect NOT independently confirmed; peer-field readback not performed; baseline restored; evidence `data/artifacts/gate-a-preflight-live-192.168.2.1-20260724.json`, `data/artifacts/awg-peer-nested-rci-psk-live-192.168.2.1-20260724.json` |

**Post-live offline flips:** default `peer_rci_shape` → **`nested_rci`**; `path_style` kept as legacy option.

**Invariants preserved each campaign:** baseline restored; **NO** `system configuration save`; throwaway creds deleted post-teardown.

**Not claimed:** tunnel connectivity; WriteCertified; Gate B; **`write_shapes_registered` remains false**.

### 15.3 Policy recorded

Standing bounded-lab live authorization (**2026-07-24**) encoded in §14.6 + [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md): in-envelope bounded reversible verification = **autonomous**; carve-outs = **hard STOP** (explicit per-action confirmation).

### 15.4 Final verification state

| Check | Result |
|---|---|
| `py.exe -3.11 -m pytest -q` | **2075 passed, 0 failed, 2 skipped** |
| ruff / mypy / OpenAPI | exit **0** |
| `validate-project-docs.ps1` + `project-docs.py audit` | exit **0** |

Gates A/B/C/D **unchanged**; WriteCertified **NOT** claimed; `write_shapes_registered` **false**.

### 15.5 Lessons learned

- Shell env vars **do not persist** across separate Shell tool calls — set env in the **same command** as uvicorn/driver invocation.
- Correct Keenetic peer RCI = `wireguard.peer[]` array with `key` + nested objects (ivansible/ndm-wireguard); nested ack carries `status[]`, not a parse prompt.
- Standalone `wireguard_clear_private_key` teardown op **rejected** by device — use `remove_interface` for guaranteed cleanup (non-blocking quirk).
- Sanctioned live peer path = **web host API**, not `wireguard-rci-op.py` CLI alone.
- Static-asset security test masks safe `*_credential_ref_id` tokens (not secret vocabulary).
- Live host runs headless via DPAPI hub-admin credential blob (`HUB_ADMIN_PASSWORD` / vault ref in same shell as uvicorn).

**Next-chat orchestrator prompt:** [`NEW_CHAT_ORCHESTRATOR_HANDOFF_2026-07-24.md`](NEW_CHAT_ORCHESTRATOR_HANDOFF_2026-07-24.md).

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | session-log-orchestrator-autonomy-20260724 |
| paths | docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md, docs/docs-map.json |
| map_entries | SESSION_HANDOFF §15 session log; NEW_CHAT_ORCHESTRATOR_HANDOFF_2026-07-24 orchestrator handoff prompt |
| validator | implementer — full validate/audit per verify_commands |
| notes | §15 records autonomous orchestrator session (offline A–D + nested_rci live re-verify ACCEPTED); maps new orchestrator handoff prompt; §14/§14.6 unchanged authoritative; gates/cert/write_shapes_registered unchanged |
