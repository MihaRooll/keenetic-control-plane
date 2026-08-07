# Test strategy and evidence contract

## For agents

| Check | Action |
|---|---|
| Phase | **P3 topology safety closure complete** (2026-07-23; offline/default-deny); both fail-safe trials **completed_failed**; **`tunnel_healthy` DEVICE-CONFIRMED** (first real handshake §M-24..§M-26); **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** (§M-24/M-27); traffic via tunnel **device-verified reversible** (§M-27); **next task:** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](../STATUS.yaml) `next_task` |
| Lanes | contract/static → fake/domain → recorded sanitized fixtures → Gate A read-only → Gate B per-family → Gate C lab → Gate D production |
| Dedicated lab | Project-owned NC-1812; program authorization ≠ action approval; controlled churn/reboots/restores under exact T4 Human Gate — [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) |
| Forbidden | Invent RCI JSON bodies; live writes outside applicable expendable envelope (bounded writes OK when `ROUTER_CONTROL_LAB_CLASS=expendable_development_router` and live device matches recorded tuple per [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md) §1a) or without Gate B/C/D + T4 packet; store secrets in fixtures/evidence |
| Fake adapter | Vendor-neutral step kinds and failure modes only — see §4 |
| Tuple | Certification evidence binds exact fields in §5 — old-device fixtures **never** certify NC-1812 |
| Trace | ADR-0001..0005, [`ROADMAP.md`](ROADMAP.md) M0–M8, [`HARDWARE_GATES.md`](HARDWARE_GATES.md) |

---

## 1. Purpose and scope

This document is the **normative test and evidence strategy** for Router Control between Phase 0b contracts and future implementation. It defines:

- verification **lanes** and what each lane may prove;
- pyramid/matrix coverage across domain, RCI adapter contract, API, persistence, security, and failure isolation;
- fake-router behavior and recorded-fixture rules;
- deterministic hardware evidence packages for gates A/B/C/D;
- AWG and route-benchmark protocols derived from [`HARDWARE_GATES.md`](HARDWARE_GATES.md) checklists;
- persistence fault-injection requirements aligned with [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §8.7;
- API/security negative tests;
- evidence acceptance, rejection, quarantine, and phase mapping.

**Phase 0b (historical):** executed lanes 1–2 only (contract/static and fake/domain documentation). Lanes 3–7 were **specified but not opened**. Gates A/B/C/D remained **closed**.

**Current posture (2026-07-23):** **P3 shared typed executor complete (offline/default-deny)** — `tests/test_netcraze_codec.py`, `tests/test_netcraze_typed_executor.py`, `tests/test_executor_digest_parity.py`, `tests/test_netcraze_shape_registry.py` (promotion pipeline, digest revoke, direct-mint negatives), `tests/test_netcraze_read_discovery.py`; **M5 offline/default-deny framework** — `tests/test_netcraze_capability_families.py`, `tests/test_netcraze_evidence_manifest.py`, `tests/test_netcraze_certification_framework.py`, `tests/test_plan_gate_b_family_cli.py`, `tests/test_netcraze_awg_certification.py`; AWG compat suites; planner/runner refuse dispatch unconditionally. **Fail-safe runner (offline only):** `tests/test_netcraze_fail_safe_*`, `tests/test_certify_gate_b_fail_safe_cli.py` — `--execute` refused until fresh exact T4 Human Gate; standing execute unauthorized. **Topology read discovery (offline):** `tests/test_netcraze_topology_probe.py`, `tests/test_probe_nc1812_topology_cli.py` — v1 list fixtures (`topology_interface_*.json`) + **observed keyed v2.3** fixtures (`topology_observed_keyed_*.json`, `topology_observed_mixed_root.json`, `parser_version: topology-interface-v2.3`, `certification_eligible: false`); success artifact + optional **`--shape-out` structural fingerprint on `TopologyProbeError`** (map/list/wrapped/secret/deep/oversize; no canary values). **Default-route read discovery (offline, 2026-07-23):** `tests/test_netcraze_route_topology_probe.py`, `tests/test_probe_nc1812_default_route_cli.py` — fixtures `default_route_single.json`, `default_route_multiple.json`, `default_route_ambiguous.json`, **`default_route_observed_empty_wrapper.json` (`[[]]`)**; parser **`default-route-v1.3`** accepts v1 dict `{"route":[…]}` plus observed outer list wrapper `[ [entries…] ]` (reject `[]`, `[[],[]]`, sole non-list item, deeper nesting, mixed outer types); non-default routes dropped; gateway private class only (never host); secret canaries absent; unknown shape + **`--shape-out`** list-root/dict structural fingerprint (`describe_list_structure` for array roots: `top_type: array`, `top_count`, `element_type_histogram`, ordinal path indices, container-only allowlisted field names+types; bounds entries≤32/depth≤3/output bytes≤8192; non-certifying); topology correlation match/mismatch (uplink hash requires explicit bool `link_up: true` — never `connected`; v2.2 artifacts readable but spoofed `connected`-only must not match); `multiple_default_routes`/`ambiguous`/`no_default_route` block T4 uplink claims; Gate A four-read unchanged (`tests/test_gate_a_security_invariants.py` — `DISCOVERY_ALLOWLIST` includes `SHOW_INTERFACE` + `SHOW_IP_ROUTE`, neither in Gate A `ALLOWLIST`). **Field-name discovery stage (2026-07-23):** shape fingerprint's audited field-NAME allowlist expanded to a closed AC-1 set (`type,link,connected,state,up,traits,address,addresses,ip,mask,prefix,prefix-length,network,gateway,defaultgw,security-level,role,bridge,segment,uplink,parent,via,interface,member,members,port,mtu`); allowlisted names emit **name + JSON type/shape/count only, never scalar value/length**; allowlist wins over secret-category heuristics (`address`/`ip`/`gateway` no longer secret); sensitive names (`password`/`secret`/`token`/`mac`/`id`/`uuid`/`guid`/`name`/`ssid`/`essid`/`description`/`dns`/`hostname`/`domain`) remain categorized, never named; map-keyed dynamic interface top keys always hashed; canary tests (`SYNTH_MAC`/`SYNTH_SSID`/`SYNTH_SECRET`/`SYNTH_ID`/`SYNTH_IP`) prove no values/IDs/IPs/MAC/SSID leak. **Keyed v2.3 parser (2026-07-23+):** offline-only; per-interface sorted `uncertainty` field names (no values); malformed optional consumed fields omit fact + record uncertainty; unknown link signal with another valid uses valid signal; overlap positives may still yield `lan_to_lan_or_overlap` under uncertainty; uncertainty blocks `proven_wan_isolated`; mixed-root live-shape fixture ignores non-candidates and strips drop keys; role/address/classification matrix tests; classification is safety evidence not certification; Gates A–D unchanged. **Two-step discovery:** Gate A identity → topology DiscoveryRead; parse fail emits bounded structure only. **Current next task (2026-08-05):** `local-hub-vpn-real-peer-autoconnect-continuation` per [`STATUS.yaml`](../STATUS.yaml) `next_task` (device-verified VPN handshake/traffic/MSS/catalog per `.cursor/plans/main-decisions-local-hub.md` §M-24..§M-35 — **honesty:** MSS apply/clear device-verified but MSS ≠ captive portal; captive efficacy unproven; deferred plan `operator-web-ui-full-coverage` is **not** current). Gate **A** open **ReadOnlyCertified**; Gate **B** **completed_failed**; Gates **C/D** **closed**; **Certified operation registry empty**; `write_shapes_registered` false.

**M1 commissioning tests (delivered):** `tests/test_commissioning_*.py` — domain transitions, migration 2, API auth/idempotency/ETag, fake assess, mocked Gate A live assess, cancel, no-secret scans; default no-network.

---

## 2. Verification lanes

| Lane | Name | Adapter / surface | Opens in Phase 0b | Authorizes |
|---|---|---|---|---|
| **1** | Contract / static | Markdown contracts, schema tables, cross-doc trace | **Yes** (docs only) | Contract consistency; no runtime proof |
| **2** | Fake / domain | In-memory `FakeRouterAdapter` behind `RouterControlPort`, deterministic clocks/seeds | **Yes** (spec only; no test code in 0b) | Domain invariants, planner, gate evaluation logic without vendor I/O |
| **3** | Recorded sanitized fixtures | Redacted transcripts bound to manifest + tuple | **No** | Adapter parsing, error normalization, characterization — **not** NC-1812 certification alone |
| **4** | Gate **A** — live read-only | Project-owned dedicated NC-1812, read-only transport | **No** | Live observe, enroll/preflight identity legs ([`API_CONTRACT.md`](API_CONTRACT.md) §10.1) |
| **5** | Gate **B** — per-family write | Same tuple; family-scoped mutation evidence | **No** | Automated write dispatch for certified family ([`RCI_POLICY.md`](RCI_POLICY.md) §2) |
| **6** | Gate **C** — lab mutation window | Time-boxed operator-approved lab changes | **No** | Execute certified sequences on lab router — **not** event production |
| **7** | Gate **D** — production enablement | Event tuple + operator acceptance | **No** | Production automated writes on enrolled router |

**Fail-closed:** Unknown firmware/capability/profile, identity mismatch, stale observation, missing evidence, uncertified family, or closed applicable gate → **no write dispatch** ([`HARDWARE_GATES.md`](HARDWARE_GATES.md) §5, [`RCI_POLICY.md`](RCI_POLICY.md) §2).

**Phase 0b (historical):** opened none of lanes 4–7 and none of gates A/B/C/D — see **Current posture** above (§1, lines 29–31).

---

## 3. Test pyramid and coverage matrix

### 3.1 Layer pyramid (implementation target)

| Layer | Primary lane | Focus |
|---|---|---|
| Unit / domain | Fake (2) | Entities, invariants, ownership, revision rules, gate predicates |
| Contract / static | Contract (1) | Cross-doc must/must-not, closed vocabularies, error codes |
| Adapter contract | Fake (2) + Recorded (3) | Step kinds, transport errors, async continuation — **no invented vendor bodies** |
| Integration (SQLite + API) | Fake (2) + Recorded (3) | HTTP auth order, idempotency, ETag/If-Match, job lifecycle |
| Persistence fault | Fake (2) + injected SQLite | §8 matrix below |
| Security negatives | Fake (2) + API harness | Path normalization, token bypass, redaction scans |
| Hardware evidence | Gates A–D (4–7) | Sanitized packages only; no secrets in shared storage |

### 3.2 Coverage matrix (must demonstrate before production)

| Area | Must cover | Primary contracts |
|---|---|---|
| Domain invariants | Desired/applied separation, managed merge, stale plan rejection, one mutation per `RouterId` | [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`RCI_POLICY.md`](RCI_POLICY.md) §6 |
| RCI adapter contract | Vendor-neutral intents, allowlist families, lifecycle step order, unknown capability fail-closed | [`RCI_POLICY.md`](RCI_POLICY.md) §1–6 |
| API auth / errors / idempotency / ETag | §2 auth order, §4 codes, §4.3 idempotency, §8 Confirm, §10 gates | [`API_CONTRACT.md`](API_CONTRACT.md) |
| Persistence | Migrations, WAL backup, two-worker claim, fencing, crash boundaries, audit append-only | [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) |
| Security / redaction / vault boundary | No plaintext in surfaces; DPAPI opaque refs; Confirm binding | [`SECURITY_OPS.md`](SECURITY_OPS.md) |
| Failure isolation | RC DB/worker failure must not block kiosk, board, printing, Hub startup | [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §8.7 item 10 |

---

## 4. Fake router: behavior and state machine

Fake adapter **must** implement vendor-neutral **step kinds** aligned with [`RCI_POLICY.md`](RCI_POLICY.md) §5 (e.g. `preflight`, `identity-check`, `observe`, `backup`, `apply`, `read-back`, `verify`, compensation kinds) — **not** literal RCI command names or JSON bodies.

### 4.1 Configurable failure modes (fake only)

| Mode | Expected system behavior |
|---|---|
| **Identity mismatch** | Write dispatch blocked; `IdentityMismatch` or gate failure before apply |
| **Unknown capability** | Fail closed for writes; observe may report unknown field |
| **Stale observation** | New mutation plan rejected; requires fresh observe |
| **Partial / async transport** | `"continued"`-style polling simulated; checkpoints after confirmed segments |
| **Unknown external outcome** | No blind retry; read-back or `RecoveryRequired` ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §5.2) |
| **Fail-safe timeout** | Simulated loss-of-management; reboot restores last saved config narrative |
| **Managed / unmanaged conflict** | Planner touches only owned resources; unmanaged resources unchanged |

### 4.2 Fake state machine rules

- Fake **must not** invent certified NC-1812 RCI payloads; use abstract resource locators and digests.
- Fake **may** replay recorded fixture **digests** when manifest declares `adapter_mode: recorded`.
- Transitions **must** respect gate predicates even in fake mode when test declares `live_gates_enforced: true`.

---

## 5. Recorded fixtures: manifest, provenance, classification

### 5.1 Fixture manifest (required fields)

Each recorded fixture set **must** ship a manifest (no secrets):

| Field | Requirement |
|---|---|
| `manifest_schema_version` | Semver of manifest format |
| `fixture_id` | Stable opaque id |
| `recorded_at` | UTC ISO-8601 |
| `source_classification` | See §5.2 |
| `certification_tuple` | Subset or full tuple — see §5.3 |
| `redaction_profile` | Placeholder vocabulary used ([`SECURITY_OPS.md`](SECURITY_OPS.md) §5) |
| `content_digest` | Hash of sanitized bundle |
| `adapter_version` | Adapter that recorded or validated fixture |
| `provenance` | Human-readable origin (lab session id, strangler export — no credentials) |
| `quarantine_status` | `accepted` \| `quarantined` \| `rejected` |

### 5.2 Legacy fixture classification ([`LEGACY_MAP.md`](../LEGACY_MAP.md))

| Class | Use in tests | NC-1812 certification |
|---|---|---|
| **Golden behavior** | Characterization oracle for strangler | **Never** alone |
| **Port** | Transport/auth parsing development | **Never** alone |
| **Prototype-only** | Old-device RCI shape research | **Never** |
| **Do-not-reuse** | Negative fixtures only; no secrets | **Forbidden** |

Old-device shapes (`Wireguard0`, historical KeeneticHttpHelper bodies) **must not** certify NC-1812. Certification requires Gate A/B evidence on **exact NC-1812 tuple** ([`COMPATIBILITY.md`](../COMPATIBILITY.md)).

### 5.3 Certification tuple binding (exact fields)

Evidence packages **must** record these fields ([`HARDWARE_GATES.md`](HARDWARE_GATES.md) §1):

| Field | Requirement |
|---|---|
| `model` | e.g. `Netcraze Ultra NC-1812` |
| `firmware_version` | As observed (raw `5.01` allowed unclassified) |
| `build` | When captured |
| `update_channel` | Main / Preview / … as observed |
| `component_set_digest` | Hash of installed component list |
| `device_fingerprint` | Model + serial/MAC/vendor evidence — **redacted in shared fixtures** |
| `evidence_recorded_at` | UTC timestamp |
| `evidence_locator` | Internal artifact reference (not in public docs) |

Different tuple → prior certifications **do not inherit**.

### 5.4 Sanitization and quarantine

- Fixtures containing password, private key, PSK, raw session, or full startup-config **must** be quarantined and **must not** enter shared storage.
- Automated secret scans ([§8](#8-api-and-security-negative-tests)) apply to fixture bundles before acceptance.
- Rejected fixtures remain documented in quarantine log with reason; **must not** be used as certification input.

---

## 6. Hardware evidence packages (Gates A/B/C/D)

Deterministic packages **must** include (no secrets):

| Artifact | Content |
|---|---|
| Gate id + tuple | All §5.3 fields |
| Timestamps | `evidence_recorded_at`, window bounds for C |
| Adapter version | Semver + commit/build id |
| Operator actor ref | Redacted operator/session label |
| Content hashes | Manifest, transcripts, checklist exports |
| Pass/fail checklist | Per gate section below |
| Pass/fail summary | Single boolean + failure codes |

### 6.1 Gate A — read-only checklist

From [`HARDWARE_GATES.md`](HARDWARE_GATES.md) §6.1:

- [ ] Authenticated encrypted transport: local HTTPS with certificate validation **or** host-key-pinned SSH tunnel to the same verified management host RCI HTTP
- [ ] Digest or interactive auth challenge and session establishment recorded (redacted)
- [ ] Identity read matches enrolled fingerprint
- [ ] Command-level error normalization captured
- [ ] 401 re-auth behavior (single retry) captured or marked unknown
- [ ] `"continued": true` polling captured or marked not observed
- [ ] Timeout behavior documented

**Management host policy (implementation):** Loopback and non-private management hosts are rejected **before** vault or network I/O. IPv6 literals use unbracketed form for `ipaddress` / TCP connect; bracketed `host:port` authority forms are rejected with a validation error (see `tests/test_netcraze_transport.py` IPv6 cases).

### 6.2 Gate B — Fail-safe Configuration prerequisite

From [`HARDWARE_GATES.md`](HARDWARE_GATES.md) §6.2; offline runner: [`OPERATOR_GATE_FAIL_SAFE.md`](../OPERATOR_GATE_FAIL_SAFE.md), `scripts/certify-gate-b-fail-safe.py` (dry-run/validate default; replay marker; session-close-before-poll):

- [ ] Typed `fail_safe_timer_reboot_60` sealed exec only — no raw command API
- [ ] Trial authorization + atomic `trial_id` consumption
- [ ] Startup backup before command; **no** startup save
- [ ] Verified session close before TCP outage poll
- [ ] Gate A reprobe tuple match after recovery
- [ ] Sanitized evidence — never `WriteCertified`
- [ ] Failure evidence: allowlisted `error_code`, `failure_stage`, `dispatch_attempted`; sealed `command_result` meta (exit/ack/sha256/byte counts only — no raw CLI text)
- [ ] `gate_c_window_open_at_execute` reflects authorization-time check (not hardcoded false when window open)

### 6.3 Gate B — AmneziaWG family protocol

From [`HARDWARE_GATES.md`](HARDWARE_GATES.md) §6.3 — **steps only; no invented commands**:

| Step | Verification |
|---|---|
| Profile field enumeration | Accepted field set listed; unknown fields rejected |
| Greenfield import | Import + switch between two **synthetic** profiles |
| Semantic loss / read-back | Read-back proves **no silent field drop** |
| Handshake / reachability | Tunnel handshake and application reachability through tunnel |
| Reboot / restore | Save, reboot, health re-check, compensation, baseline restore |

### 6.4 Gate B — route benchmark (100 / 1,000 / 5,000)

From [`HARDWARE_GATES.md`](HARDWARE_GATES.md) §6.4, [`COMPATIBILITY.md`](../COMPATIBILITY.md) §Route scale benchmark gate:

Trials at **100**, **1,000**, and **5,000** managed routes. Each trial:

- [ ] Plan/diff and apply/read-back timings recorded
- [ ] Save and reboot recovery
- [ ] Backup/restore rehearsal
- [ ] Baseline → backup → apply → verify → save → reboot → verify → restore → reboot → verify baseline

**Production ceiling** = largest trial size meeting **evidence-derived SLO** (timings, loss, truncation, timeout, recoverability) — **not a promise**. Ceiling **may be lower than 5,000** ([`COMPATIBILITY.md`](../COMPATIBILITY.md), ADR-0004).

### 6.5 Gate C — laboratory mutation window

Package **must** record:

- [ ] Operator-approved window start/end (UTC)
- [ ] Dedicated lab NC-1812 identity (redacted fingerprint)
- [ ] Families exercised under open Gate B certifications
- [ ] Post-window restore to baseline verified

Gate C open **does not** authorize production writes ([`HARDWARE_GATES.md`](HARDWARE_GATES.md) §3).

### 6.6 Gate D — production enablement

Package **must** record:

- [ ] Operator acceptance sign-off (audit event reference)
- [ ] Restore rehearsal success on event tuple
- [ ] Strangler cutover readiness checklist
- [ ] Gate B certifications still valid for required families
- [ ] Gate C history where applicable

---

## 7. Persistence fault-injection and concurrency matrix

Maps 1:1 to [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §8.7 (implementation phase). Phase 0b documents requirements only.

| # | §8.7 requirement | Test approach |
|---|---|---|
| 1 | Idempotent re-run of migrations on current DB | Apply migration chain twice; assert `user_version` stable |
| 2 | Fault injection per migration leaves prior version readable and backup verifiable | Kill process mid-migration; restore from pre-migrate backup |
| 3 | Two workers cannot claim two mutation jobs for same `RouterId` | Concurrent `BEGIN IMMEDIATE` claim; exactly one succeeds |
| 4 | Expired lease + stale worker cannot double-apply | Stale fence rejected; single applied marker |
| 5 | Crash before/after each step recovers via checkpoint/read-back or `RecoveryRequired` | Crash injection at each step kind boundary |
| 6 | Concurrent desired update with stale `If-Match` rejected | Parallel PUT; one conflict |
| 7 | Stale observation/plan cannot start mutation | TTL expired observation → plan/apply rejected |
| 8 | Unknown managed outcome not retried without read-back | Timeout after apply → read-back before retry |
| 9 | DB/jobs/audit/artifact search finds no plaintext secrets | Scan vectors from [`SECURITY_OPS.md`](SECURITY_OPS.md) §5 |
| 10 | `router_control.sqlite3` outage does not block other Hub services startup | RC degraded; Hub/kiosk/board/printing start |

Additional topics from persistence contract:

| Topic | Must demonstrate |
|---|---|
| WAL backup before migrate | Online backup API; integrity check before migrate ([§8.2](PERSISTENCE_CONTRACT.md)) |
| Audit append-only | UPDATE/DELETE on `audit_events` rejected |
| Idempotency replay/conflict | Same key+digest replay; same key+different digest conflict ([§6](PERSISTENCE_CONTRACT.md)) |
| Cancel safe boundaries | Queued → immediate cancel; running → safe boundary; post-mutation verify ([§5.3](PERSISTENCE_CONTRACT.md)) |
| Disk-full / corruption isolation | RC → degraded/disabled; Hub continues ([§8.4](PERSISTENCE_CONTRACT.md)) |

---

## 8. API and security negative tests

### 8.1 Path normalization (ADR-0003)

Middleware prefix match for `/api/router-control/v1` **must** cover descendants. Tests **must** prove slash and path-normalization variants (`//`, trailing slash, encoded segments, case variants where applicable) **cannot** bypass `hub_admin` gate or reach handlers without auth ([`adrs/0003-security-auth-secrets.md`](../adrs/0003-security-auth-secrets.md)).

### 8.2 Auth and feature negatives

| Case | Expected |
|---|---|
| Enabled + empty `HUB_ADMIN_PASSWORD` | **503** `SecurityBlocked`; handler not invoked ([`SECURITY_OPS.md`](SECURITY_OPS.md) §1) |
| Invalid/missing `hub_admin` | **401** |
| API key / guest / board / promo token | **Never** substitutes for `hub_admin` |
| `Degraded` | Mutations **503**; limited status only |

### 8.3 Gate bypass denial

| Attempt | Expected |
|---|---|
| Apply without Gate B family certification | **403** `gate.mutation_forbidden` |
| Live observe with Gate A closed | **403** `gate.a_closed` |
| Lab write with Gate C closed | **403** (lab path) |
| Production write with Gate D not satisfied | **403** (production path) |
| Hidden admin override parameter | **Forbidden** — no bypass in v0 ([`API_CONTRACT.md`](API_CONTRACT.md) §10) |

### 8.4 Confirm, replay, conflict, cancel

| Case | Expected |
|---|---|
| Confirm with wrong plan digest / expired plan | **412** / **409** |
| Confirm without matching plan ETag | **412** `plan.precondition_failed` |
| Idempotency replay (same key + digest) | Same operation response |
| Idempotency conflict (same key + different digest) | Conflict; no second operation |
| Cancel post external mutation | Verify/compensate; cancel does not erase mutation |

### 8.5 Redaction and secret scans

Apply vectors from [`SECURITY_OPS.md`](SECURITY_OPS.md) §5 to API responses, plan diffs, job payloads, SQLite exports, logs, audit summaries, and fixture bundles. **Must** find zero plaintext secrets after redaction.

**Offline cross-surface scanner:** `tests/test_rci_secret_leak_scanner.py` exercises Wi‑Fi AP apply (PSK), WireGuard nested apply (private-key + preshared-key), fail-safe ack parsing, fake-transport command accumulation, and `repr`/`traceback` surfaces with synthetic canary tokens. Fake transports store **redacted** sealed CLI (`redact_sealed_cli_command`) and nested peer bodies (`redact_sealed_nested_body`) — never raw secret tails.

### 8.6 Operator UI DOM runtime (offline, no browser)

Autonomous UI verification for prototype management shell uses **Node + executable `app.js`** with a **rich offline DOM harness** (`tests/support/ui_dom_harness.js`) — **not** Playwright/Puppeteer and **not** jsdom/happy-dom (no new npm dependency).

| Must prove | Harness |
|---|---|
| Panel renders expected controls | `buildWifiApplyFormSurface` mounts real `createElement` tree; tests assert control ids + DOM tree |
| **Advanced settings** hidden by default | Native `<details class="config-advanced-settings">`; closed visible-text excludes advanced labels |
| Advanced expands on toggle | Set `details.open` → advanced fields appear in visible-text |
| Form defaults match request models | `readWifiApplyPayloadFromDom` compared to `WifiApplyBody` / enum defaults (Python SSOT) |
| Form secret not echoed in **result** markup | `buildCredentialEnrollTestSurface` + result `pre` — marker in input OK; marker absent from result box |
| No misleading success without positive verdict | `domHasMisleadingApplySuccessText` + `wifiApplyHonestySummary` / toast prefix on unverified apply |

Legacy checks in `tests/test_config_ui.py` (static source substring scans) remain as **supplemental** contract smoke; **behavioral** guarantees come from DOM runtime tests above. Optional Cursor Browser MCP (`browser-verify` skill) remains human-gated for auth/origin — not required for CI.

---

## 9. Evidence operations policy

### 9.1 Acceptance criteria

Evidence package **accepted** when:

- all required §5.3 / §6 fields present;
- checksums verify;
- secret scan pass;
- checklist complete or explicitly marked `unknown` with fail-closed write impact documented;
- tuple matches enrolled router for the claimed gate.

### 9.2 Rejection

**Reject** when: secrets detected; tuple mismatch; incomplete mandatory checklist; adapter version incompatible; provenance missing; classification `Do-not-reuse` without quarantine wrapper.

### 9.3 Flaky and quarantine

- Flaky hardware evidence → **quarantine**; gate status unchanged until deterministic re-run passes.
- Flaky automated tests → fix or quarantine with ticket; **must not** weaken gate predicates.
- Quarantined fixtures **must not** feed certification pipelines.

### 9.4 Deterministic clocks and seeds

- Fake and integration tests **must** inject `ClockPort` and seeded RNG — no wall-clock dependence for assertions.
- Recorded fixture replay **must** declare fixed clock offsets when timing-sensitive.

### 9.5 Required artifacts (implementation)

| Artifact | When |
|---|---|
| Test report (machine-readable) | CI / local verify |
| Coverage map to this contract §3.2 | Release candidate |
| Gate evidence package | Each gate passage |
| Secret scan log | Each fixture import and release |
| Migration fault-injection log | Persistence milestone |

### 9.6 Phase mapping (which lanes execute when)

| Phase | Lanes executed | Gates |
|---|---|---|
| **0b** (historical) | 1–2 documentation/static only | **All closed** |
| **M5 complete / P3 complete** (current) | 1–2 + 3 recorded + 4 Gate A RO + fake recovery/SCN-JOB + M1–M5 offline suites + P3 topology safety + fail-safe failure diagnostics tests + VPN/tunnel health suites | **A** ReadOnlyCertified (post-WG rebind 2026-07-31); **B** fail_safe trials **completed_failed** (094500Z + 110000Z); **C closed** completed_failed; **D closed**; `write_shapes_registered` false; WriteCertified **NOT** claimed; **`tunnel_healthy` DEVICE-CONFIRMED** (first real handshake §M-24..§M-26); **`SET_IP_ADDRESS` + `wireguard_ip_global` DEVICE-VERIFIED** (§M-24/M-27); traffic via tunnel **device-verified reversible** (§M-27) — **next task:** `local-hub-vpn-real-peer-autoconnect-continuation`; **parallel deferred:** kill-switch/named policy **unresolved** (kill-switch `permit global` pattern rejected by firmware); **`CLEAR_IP_GLOBAL` on teardown** not device-proven; handoff [`SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md`](../SESSION_HANDOFF_REAL_ROUTER_2026-08-02.md) |
| **Dedicated lab program** | Parallel lane: offline harness/fixtures/cert prep + Gate A RO + expendable envelope bounded writes; VPN routing/policy-routing apply under [`OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`](../OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md) | Gates unchanged unless explicit Human Gate opens them; Gate B **completed_failed**; not WriteCertified |
| **Implementation** (future lab+) | 2 fake + 3 recorded + SQLite/API integration | Write paths per gate ladder when certified |
| **Lab certification** | 4–6 on project-owned dedicated NC-1812 | A → B → C (each campaign T4 when mutating) |
| **Event production** | 7 + ongoing regression of 2–3 | D + maintained B |

---

## 10. Links

- RCI policy and lifecycle: [`RCI_POLICY.md`](RCI_POLICY.md)
- Hardware gates and checklists: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- Security, Confirm, redaction: [`SECURITY_OPS.md`](SECURITY_OPS.md)
- Persistence evidence requirements: [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §8.7
- HTTP/API gates and negatives: [`API_CONTRACT.md`](API_CONTRACT.md) §10
- Operator scenarios: [`SCENARIOS.md`](SCENARIOS.md)
- Implementation roadmap: [`ROADMAP.md`](ROADMAP.md)
- Dedicated lab policy: [`DEDICATED_ROUTER_LAB_POLICY.md`](../DEDICATED_ROUTER_LAB_POLICY.md)
- Compatibility and route benchmark: [`COMPATIBILITY.md`](../COMPATIBILITY.md)
- Legacy fixture classification: [`LEGACY_MAP.md`](../LEGACY_MAP.md)
- Contracts index: [`README.md`](README.md)
- ADRs: [0001](../adrs/0001-python-package-fastapi-host.md), [0002](../adrs/0002-persistence-jobs-sqlite.md), [0003](../adrs/0003-security-auth-secrets.md), [0004](../adrs/0004-product-capability-scope.md)
