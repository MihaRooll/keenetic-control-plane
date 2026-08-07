# Session handoff — real router lab (2026-08-02)

> **ACTIVE narrative handoff (2026-08-02).** Post-rebind expendable unit at `192.168.2.1`: methods, evidence, assumption traps, and honest capability status for the **current physical router** after the **2026-08-01/02** live session. **Living policy SSOT** remains [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml) (lab class, expendable envelope, Gate posture, `next_task`, blockers) — this doc does **not** override them.
>
> **Historical capability banner (2026-08-05):** claims in this doc that **interface Address NOT configured**, **handshake NOT achieved**, or **tunnel NOT traffic-ready** are **superseded** for the current lab unit by [`STATUS.yaml`](STATUS.yaml) `next_task` night_3/morning_4/day_5 and `.cursor/plans/main-decisions-local-hub.md` §M-24..§M-35 (first handshake; `SET_IP_ADDRESS`/`ip global` accepted; traffic via tunnel reversible). Kill-switch/named policy, WriteCertified, and guest reachability limits **remain open** — read STATUS for current honesty markers. Prior handoffs [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) (historical methods companion — post-rebind unit facts through 2026-07-31), [`SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-24.md), [`SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-23.md) retain prior-unit / earlier-session methods; host-key and digests from superseded probes are **historical only**.

**Document timestamp:** 2026-08-02 (session closeout: Gate A parser-false-drift recert + guest Wi‑Fi AP3 live campaign).

## For agents

| Topic | Rule |
|---|---|
| When to read | Before any NC-1812 live observe, bounded write, backup, or campaign prep on the **post-rebind** unit; new session after real-router work; when code behavior seems surprising after live findings |
| Methodology companion | [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) — transferable process rules (L-1..L-21); **L-21** covers parser-false-drift vs identity drift; **recommended** after this handoff when you need judgement/process, not device facts; does **not** override POLICY/STATUS |
| Historical methods | [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) — post-rebind unit through 2026-07-31 (station uplink persisted, WG `tunnel_healthy`, sealed AP3 path, assumption traps §2); **not** active narrative |
| Delivered **this session (live)** | Gate A **parser-false-drift recert** (afternoon) — defective pre-fix probe looked like tuple drift; post-parser-fix pinned probe matches recorded tuple in **all nine** compared fields (`drifted_fields=0`); **NOT a rebind**; evidence freshness recert to `gate-a-probe-post-parser-fix-20260801.json`; guest Wi‑Fi live campaign on `WifiMaster0/AccessPoint3` — WPA2 apply + on-air verify + teardown (`on_air_verified`); throwaway credential revoked/deleted; `system_configuration_save=false`. **Late evening (§1a):** live discovery/connection-health re-verified via real browser click-throughs; **second** Gate A freshness recert (same tuple) to `gate-a-probe-main-verify-20260802.json` — session-closeout pointer; **superseded for current freshness by** [`STATUS.yaml`](STATUS.yaml) `gates.A.evidence` |
| Delivered **this session (offline docs)** | [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md) (updated late evening — now documents the Wi-Fi picker; itself NOT device-verified, the underlying site-survey grammar it documents IS); [`OPERATOR_ROUTER_DISCOVERY_CONNECTION_HEALTH.md`](OPERATOR_ROUTER_DISCOVERY_CONNECTION_HEALTH.md) (the doc itself is offline text, but the discovery/connection-health FEATURE it documents was live-verified — see §1a); KeenDNS read/preview layer — cloud write absent by design, NOT device-verified (human packet linked below) |
| Not delivered / not confirmed | **Guest isolation** — still unsupported at preview/apply (HTTP **422** `wifi.guest_isolation_unsupported`); campaign requested `guest_isolation=false` — isolation path **NOT verified**; **AP0/AP1 untouched** — campaign evidence targets **AccessPoint3 only**; no AP0/AP1 mutation recorded in guest campaign artifact; WriteCertified; Gate B/C/D open; `write_shapes_registered`; KeenDNS cloud booking (human gate only) |
| Human gate packets (do not rewrite) | [`HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`](HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md) — parser false drift, no rebind; [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md) — cloud write booking |
| SSOT | **Policy:** [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) + [`STATUS.yaml`](STATUS.yaml). **Gate A evidence (current — follow STATUS):** `data/artifacts/gate-a-probe-main-verify-20260805-evening.json` (sha256 **ff6e9bb84eefba911d00045b2f295b4cbcefe8754757373a64940e93b0144d1c**; algorithm **`component-set-v2`**; source `192.168.2.10`; host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY; tuple UNCHANGED byte-for-byte, NOT a rebind — see [`STATUS.yaml`](STATUS.yaml) `gates.A`). **Previous evidence (same tuple, superseded on freshness only):** `gate-a-probe-main-verify-20260804-2242.json`, `gate-a-probe-main-verify-20260803.json`, `gate-a-probe-main-verify-20260802.json`, `gate-a-probe-post-parser-fix-20260801.json`, then further back `gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`. **Defective probe (old parse — do not substitute as current):** `gate-a-probe-campaign-20260801.json`. **Narrative companion (this doc):** session methods/traps/status only — if STATUS mid-cycle lags, follow STATUS for gates |
| Writes | Expendable envelope when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` and live tuple matches recorded identity — see POLICY §1a. Fail-closed if live device ≠ recorded tuple |
| Topology | Laptop Ethernet source `192.168.2.10` → test NC-1812 `192.168.2.1` on `192.168.2.0/24`; dual NIC → `--source-address 192.168.2.10` **mandatory** on all live CLIs |
| Secrets | Never document passwords, keys, PSK values, cookie values, raw startup-config, neighbour SSIDs, production SSID, MACs, or absolute backup paths |

---

## 1. Confirmed live this session (2026-08-01/02)

Status markers: **device-verified** = end-to-end on unit; **grammar-accepted** = device ack'd commands, capability not proven; **blocked** = cannot proceed; **unverified** = not tested; **not confirmed** = absent from artifact.

| Topic | Status | Evidence | Notes |
|---|---|---|---|
| Gate A tuple (post-parser-fix) | **device-verified** (identity probe) | `data/artifacts/gate-a-probe-post-parser-fix-20260801.json` | NC-1812, fw `5.01.C.1.0-0`, region EA, channel Main/stable. **`component_set_digest_algorithm`: `component-set-v2`**. Digests match recorded tuple: `component_set_digest` sha256:23bd35bc…, `device_fingerprint` sha256:c34adec…; **`drifted_fields=0`** (all nine comparable fields). Host-key **unchanged** SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY. Source `192.168.2.10`. Artifact sha256 **f3dd1c328edb6546925e6f19cb0e2f62bc213e66942975508feebe8304e187d2**. **NOT a rebind** — certified tuple byte-identical throughout |
| Gate A false drift (parser defect) | **root-caused + recertified** | `data/artifacts/gate-a-probe-campaign-20260801.json` (defective); `data/artifacts/component-install-marker-truth-20260801.json` | Pre-fix live reprobe showed digest drift under old parse. Side truth: **`entries_with_installed_key`=40**, **`entries_parser_counts_installed`=54**, **`overlap=[]`** — dual-population response; v1 hashed catalogue stubs. Recorded Gate A digest already matched correct installed-key set under v2. Human packet: [`HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`](HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md) |
| Component inventory baseline | **device-verified** (read-only) | `data/artifacts/component-inventory-baseline-192.168.2.1-20260801.json` | Non-certifying baseline enumeration supporting parser investigation |
| Guest Wi‑Fi AP3 campaign | **device-verified** (bounded) | `data/artifacts/guest-wifi-live-campaign-20260802.json` | Target **`WifiMaster0/AccessPoint3`** only. **`apply_overall=applied`**, **`teardown_overall=applied`**, **`apply_on_air=on_air_verified`**. Observed: ssid=`Guest-Lab-Test`, encryption=`wpa2`, link=`up`, connected=`yes`. **`system_configuration_save=false`**. **`guest_isolation_requested=false`** — isolation still **unsupported** (422) — **NOT verified**. **`throwaway_credential_revoked_and_deleted=true`**. Backup basename `startup-192.168.2.1-20260802T065555Z-c790ed29.dpapi` (basename only — no secrets). Campaign did **not** record AP0/AP1 mutation |
| Prior session capabilities (unchanged unless re-proven) | **see 2026-07-31 handoff** | [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) | Station uplink **PERSISTED**; WG **`tunnel_healthy` DEVICE-CONFIRMED**; sealed AP3 WPA2/WPA3/mixed path 2026-07-31 — still valid historical evidence unless tuple changes |

---

## 1a. Late-evening addendum (2026-08-02, continued session)

Four threads, each personally re-verified by Main, but via DIFFERENT methods — do not blur them: discovery diagnosis was verified via real browser click-throughs against the REAL live router 192.168.2.1; the Gate A recert was verified via a pinned SSH probe against the REAL live router (read-only); the new Wi-Fi picker and both follow-up fix rounds were verified via real browser click-throughs but in FAKE MODE ONLY — zero live router reads or writes for the picker work. Full technical detail lives in `STATUS.yaml` `reviews.discovery_diagnosis_wifi_picker_and_second_gate_a_recert_20260802` — this section is the narrative summary.

| Topic | Status | Evidence | Notes |
|---|---|---|---|
| "Автообнаружение как будто не работает" (prior handoff blocker) | **investigated, NOT reproduced as a functional failure** | Two live browser click-throughs by Main against 192.168.2.1, both returned correct candidates in ~3.5s | Root-caused a much more plausible cause instead: PowerShell BOM / `UnicodeDecodeError` in `host_route_table.py` could silently degrade to an empty candidate list with HTTP 200 and no visible error — fixed with `source_diagnostics`/`degraded_sources`, BOM-stripping, and an in-flight "Автообнаружение…" button label |
| Related dedup bug (found by adversarial review, not the original complaint) | **fixed** | `tests/test_router_discovery.py` red→green | A failed internal `default_gateway` fetch used for dedup could produce a false-positive `local_subnet_gateway` candidate with zero diagnostic |
| Second Gate A freshness recertification | **device-verified** (pointer refresh only) | `data/artifacts/gate-a-probe-main-verify-20260802.json`, `tests/test_gate_a_certification.py` (24 green) | Tuple UNCHANGED byte-for-byte, `drifted_fields=0`, **NOT a rebind** — same pattern as 2026-08-01. Corrected two stale doc cross-references (`DEDICATED_ROUTER_LAB_POLICY.md`, `README.md`) that still named 2026-07-31 as "current" |
| Wi-Fi network picker in simple Step 3 (new feature, user request) | **delivered, fake-mode/offline live-click-tested by Main — NOT device-verified live** | reuses live-device-verified (2026-07-31) `POST /wifi/site-survey` | Scan is primary interaction (not hidden under `<details>`, unlike router auto-discovery); Main's own click-through found it fully broken end-to-end after Step 1 (422 on every real attempt) because Step 1's host/username/credential never carried forward — fixed for host/username/router_credential_ref_id; `ssh_host_key_sha256` still needs manual entry via Step 2 Advanced (documented gap, not silently worked around) |
| Adversarial-review follow-ups on the picker | **fixed** | new DOM tests in `tests/test_ui_simple_mode.py` | Re-scan left stale SSID/band/credential-ref in the form (now cleared); a manual-field edit could silently lift the open-network safety block even with a no-op edit or the same open SSID (now requires the SSID to actually change) |

**Known, disclosed residual gaps (not fixed tonight):** WPA3-labelled scan results still submit `wpa2_psk` grammar (planner has no WPA3 support yet); Step 5 "Гостевая Wi-Fi" likely has the identical live-params carry-forward gap as Step 3 had (not investigated).

**Verify (Main, final count this session):** pytest **3529 passed / 2 skipped / 2 failed** (pytest exits 1 due to the 2 failures, both the same known pre-existing ones: `test_connection_health_host_api_yellow_without_probe`, `test_live_create_app_wires_soft_candidate_identity_probe` — unrelated, not chased); ruff/mypy/node --check/docs-validate/docs-audit all exit 0; OpenAPI/manifest exports byte-identical. Zero live router mutations this addendum — all Wi-Fi-picker and discovery-fix work was fake-mode/offline.

---

## 2. NOT confirmed / must not be claimed

| Claim | Honest status |
|---|---|
| Gate A identity drift requiring rebind (2026-08-01 campaign) | **FALSE** — parser defect under v1; post-fix probe matches tuple; **no rebind** |
| Guest Wi‑Fi isolation (`guest_isolation=true`) | **NOT supported** — preview/apply fail-closed **422**; not device-verified even when `false` requested |
| AP0 / AP1 untouched by 2026-08-02 campaign | **Not asserted in artifact** — campaign targeted **AccessPoint3 only**; no AP0/AP1 mutation **recorded in evidence**; do not claim broader non-mutation without separate observe |
| KeenDNS cloud hostname booking / cloud write | **NOT delivered** — read/preview only; cloud path requires human gate [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md) |
| Simple mode / router discovery UI on live unit | **Partially device-verified, do not overclaim which part:** router discovery + connection-health ARE live-verified (§1a, late evening, real browser against 192.168.2.1). The NEW Wi-Fi network picker in Step 3 (site-survey scan/select/enroll/apply) is **NOT** live-device-verified — only fake-mode/offline click-tested by Main; the underlying site-survey scan grammar itself IS live-verified (2026-07-31), but the picker's end-to-end wiring on the real device has not been exercised |
| WriteCertified / `write_shapes_registered=true` | **NOT claimed** |
| Gates B / C / D open | **NOT open** — unchanged |
| Substituting arbitrary Gate A probe file as current evidence | **BLOCKED** — host tooling validates artifact sha256 against STATUS/gate-a-certification constants |

---

## 3. Time-wasting traps (read before guessing)

These burned time during the 2026-08-01/02 session. Treat as **hard constraints** until re-proven.

### 3.1 RCI parse vs show output

| Trap | Reality |
|---|---|
| `rci-parse` / parse confirmation | Returns a **confirmation envelope**, **not** `show` output — do not treat parse ack as observed state or inventory |

### 3.2 Gate A evidence integrity

| Trap | Reality |
|---|---|
| Arbitrary probe JSON as SSOT | Gate A probe artifact is validated by **sha256** against recorded constants — substituting a different file (including the **defective** `gate-a-probe-campaign-20260801.json`) **fails** live tooling freshness/integrity checks |
| 24h evidence freshness | When Gate A evidence is **stale** (>24h), live observe/write tooling **blocks** until fresh pinned reprobe — not a device fault |
| Parser false drift | Dual-population `components/list`: **`entries_with_installed_key`=40**, **`parser_counts_installed`=54**, **`overlap=[]`**. Pre-v2 digest hashed **catalogue stubs** (entries without `installed` key) — looked like component-set drift on same unit while host-key/firmware unchanged. Fix: algorithm **`component-set-v2`** (MODE A/B). See **L-21** in [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) |

### 3.3 Wi‑Fi preview / apply payloads

| Trap | Reality |
|---|---|
| Preview plan key name | Wi‑Fi preview payload uses **`apply_ops`**, **not** `ops` — wrong key yields empty op list in harness/logs (guest campaign harness note; device behaviour unaffected when compiler used correctly) |
| `connected: true` on AP | **≠ on air** — still applies; guest campaign verified via `link=up` + on-air checks |
| Guest isolation | **`guest_isolation=true` rejected** at compile — do not assume device grammar |

### 3.4 Inherited traps (still valid — see 07-31 §2)

Component `{id, version}` shape (no `installed` field); site survey JSON vs tabular CLI; station `auth-type` not security signal; `show rc interface` PSK plaintext — see [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) §2.

---

## 4. Current gate posture (2026-08-02)

| Gate | Status | Notes |
|---|---|---|
| **A** | **ReadOnlyCertified** | **Current evidence (follow STATUS):** `data/artifacts/gate-a-probe-main-verify-20260805-evening.json` (sha256 ff6e9bb8…, recorded 2026-08-05T17:00:22Z). **NOT a rebind** — tuple byte-identical through all recerts back to the post-WG rebind (2026-07-31). Host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY |
| **B** | **completed_failed** | Not WriteCertified |
| **C / D** | **closed** | Unchanged |
| Write shapes | **`write_shapes_registered: false`** | Do not claim WriteCertified |

**SSOT:** [`STATUS.yaml`](STATUS.yaml) + [`gate-a-certification.json`](gate-a-certification.json) — this handoff mirrors current evidence pointer; if divergence, follow STATUS.

---

## 5. Guest Wi‑Fi live campaign (2026-08-02)

Bounded expendable envelope on **`WifiMaster0/AccessPoint3`**:

1. Pre-change backup (basename recorded in artifact).
2. Applied WPA2 guest test SSID with on-air verification (`apply_on_air=on_air_verified`).
3. Full teardown (`teardown_overall=applied`).
4. **`system_configuration_save=false`** — runtime-only campaign.
5. Throwaway credential revoked and deleted.

Evidence: `data/artifacts/guest-wifi-live-campaign-20260802.json`.

**Honest limits:** **`guest_isolation` unsupported** (422) — not verified. Campaign evidence does **not** assert AP0/AP1 state. Prior sealed-path evidence on same AP (`wifi-sealed-path-live-gate-a-20260731.json`) remains valid for WPA2/WPA3/mixed grammar.

---

## 6. Offline deliverables (docs — not live-verified this session)

| Doc | Scope |
|---|---|
| [`OPERATOR_SIMPLE_MODE.md`](OPERATOR_SIMPLE_MODE.md) | Simple-by-default UI mode specification |
| [`OPERATOR_ROUTER_DISCOVERY_CONNECTION_HEALTH.md`](OPERATOR_ROUTER_DISCOVERY_CONNECTION_HEALTH.md) | Router discovery + connection health surfaces |
| KeenDNS | Read/preview only; cloud write absent — [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md) |

---

## 7. What to do next (ordered by value)

Follow `docs/STATUS.yaml` `next_task` if this list and STATUS ever disagree — STATUS is SSOT.
**Superseded same night by the LOCAL HUB mockups (see below) — this list is preserved for
history, but item 0 is now the actual priority, not items 1-3 as separate tracks.**

0. **(Now the actual priority, not "ready-state")** The operator delivered the full UI mockup
   package for a new "LOCAL HUB" PWA redesign: `Привью интерфейса/1.png`…`8.png` + `ТЗ и
   промт.txt`. See `docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md` §0/§0a/§0b for the full
   delegation model (Opus-5-led `operational-orchestrator`, 18-stage plan, live-router
   authorization on 192.168.2.1) — read that file, this bullet is just a pointer.
1. **`app.js` module split (P5)** and **2. `ssh_host_key_sha256` auto-resolution gap** (both
   Рабочая-сеть AND Гостевой-Wi-Fi screens) and **3. WPA3 grammar honesty** — all fold INTO
   the LOCAL HUB redesign above as part of the relevant screens, they are NOT separate
   parallel tracks to do before or instead of it.
4. Optional residual hardening backlog (should-fix/nit, not blockers) — see `STATUS.yaml` `next_task` for the full list.
5. Residual from `operator-web-ui-full-coverage` (older, still open, fold into the relevant LOCAL HUB screens rather than fixing in the old UI): KeenDNS `#settings` stub, residual `str(exc)` echo on wifi/wireguard/vpn/bootstrap routes, manual-body `extra=forbid`. See [`OPERATOR_UI.md`](OPERATOR_UI.md), [`OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md`](OPERATOR_WEB_UI_FULL_COVERAGE_PLAN.md).
6. **Guest isolation grammar discovery** (if in scope) — currently **422 unsupported**; do not claim device support without live probe evidence.
7. **Live station HTTP apply verification** — naturally falls out of testing the Рабочая-сеть/Подключение screens in the redesign.
8. **VPN routing live apply** (parallel deferred) — offline preview only; kill-switch `permit global` **unresolved** — see 07-31 handoff §6.
9. **KeenDNS cloud booking** — only after explicit human approval per [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md) — stays Level-2 even inside the redesign.
10. **Gate B / `write_shapes_registered`** — BLOCKED, the redesign's live-router authorization does not change this.

Do **not** treat 2026-08-01 defective Gate A probe as drift requiring rebind. Do **not** silent-update Gate A tuple.

---

## 8. Ops for next agent

### Lab access

- Wired path: host `192.168.2.10` → router `192.168.2.1`.
- Always pin host-key SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY before live observe.
- Credentials: **`credential_ref` only** — see [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md), [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md).

### Environment

- PowerShell env vars **do not persist** — set env in the **same command** that launches the host process.
- Hub-admin DPAPI blob is **ASCII-hex** encoding.

### Safety

- Live device ≠ recorded tuple → **fail-closed** for writes.
- Gate A evidence must pass **sha256 + freshness** checks — refresh with pinned reprobe, not arbitrary artifact swap.
- Do **not** open Gates B/C/D or claim WriteCertified.

### Paste prompt for new chat

[`NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md`](NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md) — refresh baseline blocks before copy (Main may update separately).

---

## 9. Related docs

| Doc | Role |
|---|---|
| [`DEDICATED_ROUTER_LAB_POLICY.md`](DEDICATED_ROUTER_LAB_POLICY.md) | Living lab policy SSOT |
| [`STATUS.yaml`](STATUS.yaml) | Machine-readable phase, gates, blockers, `next_task` |
| [`gate-a-certification.json`](gate-a-certification.json) | Gate A certification constants |
| [`OPERATOR_GATE_A.md`](OPERATOR_GATE_A.md) | Gate A operator procedures |
| [`OPERATOR_WIFI_APPLY.md`](OPERATOR_WIFI_APPLY.md) | Wi-Fi apply operator guide |
| [`OPERATOR_WIFI_DISCOVERY.md`](OPERATOR_WIFI_DISCOVERY.md) | Wi-Fi discovery + inventory |
| [`SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md`](SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md) | **Historical** — post-rebind methods through 2026-07-31 |
| [`ENGINEERING_LESSONS.md`](ENGINEERING_LESSONS.md) | Methodology companion (L-21 parser-false-drift) |
| [`HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md`](HUMAN_GATE_GATE_A_IDENTITY_DRIFT_20260801.md) | Human gate — parser false drift |
| [`HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md`](HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md) | Human gate — KeenDNS cloud |

---

## Docs Impact Record

| Field | Value |
|---|---|
| contract_id | session-handoff-20260802 |
| paths | docs/SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md, README.md, AGENTS.md, docs/project-state.md, docs/docs-map.json, docs/OPERATOR_GATE_A.md, docs/OPERATOR_WIFI_DISCOVERY.md, docs/OPERATOR_WIFI_APPLY.md, docs/DEDICATED_ROUTER_LAB_POLICY.md, docs/STATUS.yaml, docs/gate-a-certification.json, docs/NEW_CHAT_ORCHESTRATOR_PROMPT_2026-08-02.md, tests/test_gate_a_certification.py |
| map_entries | SESSION_HANDOFF 2026-08-02 (active), SESSION_HANDOFF 2026-07-31 (deprecated), README, AGENTS, project-state, OPERATOR_GATE_A, OPERATOR_WIFI_DISCOVERY, OPERATOR_WIFI_APPLY, NEW_CHAT_ORCHESTRATOR_PROMPT 2026-08-02 (active) |
| notes | §1a addendum added late evening 2026-08-02 (continued session): discovery-bug diagnosis (not reproduced; root-caused BOM/UnicodeDecodeError degradation instead, fixed); second Gate A freshness recert (pointer only, NOT rebind, tuple unchanged); new Wi-Fi network picker in simple Step 3 (reuses live-verified site-survey, live-click-tested by Main in fake mode, found+fixed a live-connection-params carry-forward bug plus two adversarial-review follow-ups); `next_task` pivoted to app.js module split + ssh-pin gap + incoming UI mockup images. Prior notes (guest AP3 live campaign, first parser-fix recert) unchanged below |
