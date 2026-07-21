# Operator and event scenarios contract

## For agents

| Check | Action |
|---|---|
| Phase 0b | **Contract authored and closed** — normative scenario rows preserve Phase 0b expectations (gates closed, live paths **403**) |
| Phase 1 / SLICE-1 | **Complete** (2026-07-21) — **L2 fake** implementation exists (portable core + `FakeRouterAdapter`); hardware live lanes **closed**; **no** live adapter or router I/O; **SLICE-2 blocked** pending separate human approval |
| Gates A/B/C/D | **All closed** — live observe → **403** `gate.a_closed`; write dispatch → **403** `gate.mutation_forbidden` ([`HARDWARE_GATES.md`](HARDWARE_GATES.md) §3, [`API_CONTRACT.md`](API_CONTRACT.md) §10) |
| ID families | `SCN-EVT-*` event lifecycle; `SCN-ZONE-*` four zones; `SCN-OPS-*` operator happy path; `SCN-NEG-*` fail-closed negatives; `SCN-JOB-*` job failures/recovery; `SCN-LAB-*` future lab evidence; `SCN-CUT-*` strangler/cutover |
| No secrets | No passwords, private keys, serial/MAC, real hostnames, startup-config, or real device IDs in scenarios or evidence examples |
| Zone ≠ auth | Network zone **complements** `hub_admin`; zone never substitutes authentication ([`SECURITY_OPS.md`](SECURITY_OPS.md) §8) |
| Apply/verify | Happy path through **Confirm** is L1/L2-spec; **apply dispatch remains gated closed** (hardware gates A–D); **L2 fake** full lifecycle is the SLICE-1 implementation target; successful verify/`applied_revision` via fake and/or future **L5–L7** hardware evidence only — never **L4** (Gate A read-only observe) |
| Trace | [`API_CONTRACT.md`](API_CONTRACT.md) §6, [`TEST_STRATEGY.md`](TEST_STRATEGY.md), [`SECURITY_OPS.md`](SECURITY_OPS.md), [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md), [`HARDWARE_GATES.md`](HARDWARE_GATES.md), [`RCI_POLICY.md`](RCI_POLICY.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`VISION.md`](../VISION.md) |

---

## 1. Purpose and scope

This document is the **normative scenario catalog** for Router Control operator and event-booth workflows between Phase 0b contracts and future implementation. It defines:

- stable scenario IDs with actor, preconditions, gate posture, API interactions, expected states, audit events, and evidence format;
- four-zone (Guest/Promo/Staff/Admin-Server) allow/deny paths;
- operator happy paths grounded in [`API_CONTRACT.md`](API_CONTRACT.md);
- fail-closed negatives, job failure/recovery, future lab evidence, and strangler cutover rehearsal;
- trace matrix mapping each scenario to API operations, TEST_STRATEGY lane, and contract references.

**Phase 0b (historical):** scenarios authored as specification; gates closed; no real router steps or RCI commands.

**Current (Phase 1 / SLICE-1 complete):** normative rows unchanged; **L2 fake** implementation exists; hardware gates A–D remain closed; no live adapter. **SLICE-2 blocked** pending separate human approval. See [`STATUS.yaml`](../STATUS.yaml).

---

## 2. Scenario template and field glossary

| Field | Meaning |
|---|---|
| **id** | Stable `SCN-*` identifier |
| **title** | Short human-readable name |
| **actor** | Operator role or system component |
| **preconditions** | Feature state, auth, zone, enrollment, observation freshness, gate posture |
| **gates** | A/B/C/D status for this scenario (`Closed` in Phase 0b unless marked future) |
| **api** | Exact `/api/router-control/v1` operations from [`API_CONTRACT.md`](API_CONTRACT.md) §6 |
| **expected** | Feature, `confirmation_state`, `aggregate_status`, `Job.status`, `reconcile_status`, `lifecycle_status` |
| **audit** | Append-only events (action, outcome, correlation IDs — no secrets) |
| **evidence** | Lane + artifact shape per [`TEST_STRATEGY.md`](TEST_STRATEGY.md) |
| **trace** | Contract refs (SECURITY, PERSISTENCE, HARDWARE, RCI) |

**Closed vocabularies** (exact names): Feature `Disabled | Starting | Ready | Degraded | SecurityBlocked`; plan `confirmation_state` `Draft | Confirmed | Expired | Superseded`; operation `aggregate_status` `Pending | Planning | Applying | Verifying | Converged | Drifted | Failed | RecoveryRequired`; job `Queued | Leased | Running | Succeeded | Failed | Cancelled | Lost | RecoveryRequired`; router `reconcile_status` `Converged | Pending | Drifted | Unknown | Failed | RecoveryRequired`; `lifecycle_status` `PendingEnrollment | Enrolled | IdentityMismatch | Disabled`.

---

## 3. Scenario catalog

### 3.1 Event lifecycle (`SCN-EVT-*`)

| id | title | actor | preconditions | gates | api (prefix `/api/router-control/v1`) | expected | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|
| **SCN-EVT-001** | Pre-event setup | Operator (Admin/Server + `hub_admin`) | Hub up; `HUB_ADMIN_PASSWORD` configured; feature `Ready`; SQLite enrollment intent only; gates **closed** | A/B/C/D **Closed** | `GET /status`; `POST /routers`; `POST .../preflight`; `PUT .../credentials`; `POST /vpn-profiles/import`; `POST .../validate`; `PUT .../desired-revision`; `POST .../plans`; `POST .../confirm` | Feature `Ready`; router `lifecycle_status` **`PendingEnrollment`** in 0b (SQLite intent via L2 fake **202**); live observe path → **403** `gate.a_closed`; **`Enrolled`** is future Gate A only; plan `confirmation_state` `Confirmed`; no `applied_revision` advance in 0b | `enroll_requested`, `gate_a_denied` (live path) or `enroll_intent_persisted` (L2 fake), `credential_stored`, `profile_imported`, `desired_revision_created`, `plan_confirmed` | **L1** contract trace; **L2** fake domain spec (no live observe) | SECURITY §1–4; PERSISTENCE §3–4; HARDWARE §3 |
| **SCN-EVT-002** | Event operation + 1–3 day offline | Operator + event staff | Pre-event complete; Guest order page reachable; WAN/VPN may degrade; RC may be `Degraded` | All **Closed** for live dispatch | `GET /status`; `GET /routers/{router_id}`; `GET /operations/{id}`; `GET /jobs/{id}` (observe only) | Hub kiosk/board/printing continue; RC `Degraded` or `Ready` with observe-only; `reconcile_status` may be `Pending`/`Unknown`; no write dispatch | `status_polled`, `operation_observed` | **L1** offline-window narrative; **L2** fake isolation (Hub continues) | ARCHITECTURE failure isolation; PERSISTENCE §1 |
| **SCN-EVT-003** | Post-event recovery | Operator | Event ended; operator reviews drift/failed jobs; gates still **closed** in 0b | A/B/C/D **Closed** | `GET /status`; `GET /routers/{router_id}`; `GET /operations/{id}`; `GET /operations/{id}/jobs`; optional `POST /jobs/{id}/cancel` (queued only) | Operations in `Failed`/`RecoveryRequired` surfaced; cancel on `Queued` → `Cancelled`; leased/running cancel → `cancel_requested` boundary | `recovery_review_started`, `cancel_requested` | **L1** + **L2** fake recovery states | PERSISTENCE §4–5; RCI §5 |
| **SCN-EVT-004** | Replacement / re-enrollment | Operator | Hardware replaced; old identity revoked; new enrollment ceremony | B/C/D **Closed**; future **A** for live identity | `POST .../credentials/{id}/revoke`; `POST /routers` (new enrollment); `PUT .../credentials`; `POST .../preflight` → **403** `gate.a_closed` in 0b | Old refs revoked; new router `PendingEnrollment`; new VPN keys policy ([`SECURITY_OPS.md`](SECURITY_OPS.md) §7); no reuse of prior AWG material | `credential_revoked`, `replacement_enroll_requested` | **L1** lifecycle spec; **L2** fake re-enrollment | SECURITY §7; DOMAIN_MODEL Router lifecycle |

### 3.2 Network zones (`SCN-ZONE-*`)

| id | title | actor | preconditions | gates | api | expected | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|
| **SCN-ZONE-001** | Guest — order page only | Guest client | Guest Wi-Fi; HTTPS order URL published | N/A (network policy) | **No** RC prefix access; order page via Hub (out of RC API) | Guest cannot reach `/api/router-control/v1/*` or `/settings`; management denied | N/A at RC layer | **L1** zone matrix | SECURITY §8; ARCHITECTURE §4 |
| **SCN-ZONE-002** | Promo — deny Router Control | Promo kiosk device | Promo zone; valid kiosk Hub token (non-RC) | N/A | Attempt `GET /api/router-control/v1/status` → **denied at network/firewall** before or with RC | No RC API; no router management | N/A | **L1** | SECURITY §8 |
| **SCN-ZONE-003** | Staff — deny router management | Staff device | Staff zone; board/printing access | N/A | Attempt RC prefix → **denied** | Staff workflows continue; RC unreachable | N/A | **L1** | SECURITY §8; VISION |
| **SCN-ZONE-004** | Admin — `hub_admin` required | Operator in Admin/Server | Admin zone; password configured | Closed | Valid cookie: `GET /status` → **200**; missing cookie: same → **401** `auth.required` | Zone alone insufficient; auth order §2.1 | `auth_required`, `session_valid` | **L1** + **L2** fake auth order | SECURITY §1; API §2 |
| **SCN-ZONE-005** | Zone never substitutes auth | Attacker/simulator | Spoofed Admin source IP without `hub_admin` | Closed | `GET /status` → **401** even if zone classifier says Admin | **Zone ≠ authentication** | `auth_required` | **L1** explicit statement | SECURITY §8 |

### 3.3 Operator happy path (`SCN-OPS-*`)

| id | title | actor | preconditions | gates | api | expected | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|
| **SCN-OPS-001** | Status — SecurityBlocked vs Ready | Operator | Case A: empty `HUB_ADMIN_PASSWORD`; Case B: configured + valid session | Closed | `GET /status` | A: **503** `security.configuration_blocked`, feature `SecurityBlocked`; B: **200**, `feature_state` `Ready` | `security_blocked` or `status_ok` | **L1** matrix; **L2** fake | SECURITY §1–2; API §2 |
| **SCN-OPS-002** | Enroll and identity | Operator | Valid `hub_admin`; enroll payload with write-only password | **A Closed** → live observe blocked | `POST /routers`; `POST .../preflight` | **L2 fake:** **202** + SQLite intent, `PendingEnrollment`. **Live path (0b):** **403** `gate.a_closed` before live adapter — **must not** claim live observe succeeded | `enroll_intent_persisted` (L2) or `gate_a_denied` (live) | **L1** gate fail-closed; **L2** fake enroll without live I/O | API §10.1; HARDWARE §3 |
| **SCN-OPS-003** | Credentials write-only | Operator | Valid `hub_admin`; router SQLite intent (`PendingEnrollment`); Gate **A** closed — **`Enrolled` not required** for vault-only | Vault only | `PUT .../credentials`; `GET .../credentials`; `GET .../credentials/{id}` | **201** ref; GET returns metadata only (`kind`, timestamps) — **no** plaintext | `credential_stored` | **L1** + **L2** redaction | SECURITY §4; API §7.5 |
| **SCN-OPS-004** | Profile import and validate | Operator | AWG import shape | Parser only | `POST /vpn-profiles/import`; `GET /vpn-profiles/{id}`; `POST .../validate` | `validation_status` `Valid` or `UnsupportedFields`; secrets as refs only | `profile_imported`, `profile_validated` | **L1**; **L2** fake parser | API §7.3; COMPATIBILITY |
| **SCN-OPS-005** | Desired revision If-Match | Operator | Fresh observation id (fake/fixture in L2) | Closed | `GET .../desired-revision`; `PUT .../desired-revision` with `If-Match` | **200** new revision + ETag; stale → **412** `revision.precondition_failed` | `desired_revision_updated` | **L2** fake ETag txn | PERSISTENCE §3.1; API §7.4 |
| **SCN-OPS-006** | Plan create and read | Operator | Desired revision current | Closed | `POST .../plans`; `GET .../plans/{plan_id}` | `confirmation_state` `Draft`; redacted diff; no secrets | `plan_created` | **L1** + **L2** | API §7.6; DOMAIN_MODEL ChangePlan |
| **SCN-OPS-007** | Confirm binding | Operator | Draft plan; same `hub_admin` session | Closed | `POST .../plans/{plan_id}/confirm` with `If-Match` | `confirmation_state` `Confirmed`; binds digest + expiry + session | `plan_confirmed` | **L1** Confirm rules; **L2** | SECURITY §3; API §8 |
| **SCN-OPS-008** | Observe operations and jobs | Operator | Confirmed plan; **observe-only** posture — **apply remains future-gated** (see OPS-009) | Closed | `GET /operations/{id}`; `GET /operations/{id}/jobs`; `GET /jobs/{id}` | `aggregate_status` visible; job steps redacted | `operation_polled` | **L1** DTO shapes; **L2** fake lifecycle | API §9; PERSISTENCE §4 |
| **SCN-OPS-009** | Apply through verify (future-gated in 0b) | Operator | Confirmed unexpired plan | **B/C/D Closed** | `POST .../plans/{plan_id}/apply` | **Phase 0b:** **403** `gate.mutation_forbidden` before live dispatch. **Future (L5–L7):** operation `Applying`→`Verifying`→`Converged`; `applied_revision_id` only after read-back verify. **L2 fake** may simulate full apply/verify path (never **L4** — Gate A is read-only observe only) | `apply_denied_gate` or future `apply_succeeded`, `verify_complete` | **L1** 0b fail-closed note; **L2** fake full lifecycle; **L5–L7** future hardware write evidence | API §10.2; RCI §5; PERSISTENCE §3.2 |

### 3.4 Fail-closed negatives (`SCN-NEG-*`)

| id | title | actor | preconditions | gates | api | expected HTTP / domain | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|
| **SCN-NEG-001** | Empty `HUB_ADMIN_PASSWORD` | Any client | Feature enabled; password empty | N/A (config) | Any RC route e.g. `GET /status` | **503** `security.configuration_blocked`; handler not invoked | `security_blocked` | L1 + L2 | SECURITY §1–2 |
| **SCN-NEG-002** | Invalid session | Operator | Password configured; no/invalid cookie | Closed | `GET /routers` | **401** `auth.required` | `auth_required` | L1 + L2 | SECURITY §1 |
| **SCN-NEG-003** | Identity mismatch | Operator | Enrolled fingerprint ≠ live read; **L2 fake** or future Gate **A open** for observe leg | A **Closed** in 0b for live preflight | `POST .../preflight` (0b live); `POST .../apply` (gate path) | **0b live preflight:** **403** `gate.a_closed` — not sync **409**. **409** `router.identity_mismatch` on apply/gate path or **L2 fake** observe when A open (future) | `gate_a_denied` or `identity_mismatch` | L2 fake | DOMAIN_MODEL; API §4 |
| **SCN-NEG-004** | Unknown firmware/capability/profile | Operator | Tuple or profile field unsupported | Closed | `POST .../plans`; import/validate | **422** `capability.unsupported` or `profile.validation_failed` per API §4.2; profile validate may surface `UnsupportedFields`; RCI adapter may normalize to `capability.unknown` (no separate HTTP binding in §4.2) | `capability_denied` or `profile_validation_failed` | L1 + L2 | COMPATIBILITY; RCI §2 |
| **SCN-NEG-005** | Gate A closed — live observe/preflight | Operator | Valid auth; **live** adapter observe attempted | **A Closed** | `POST /routers` (live observe leg); `POST .../preflight` (live leg) | **403** `gate.a_closed` before live adapter dispatch — distinct from L2 fake **202** persist-intent path | `gate_a_denied` | L1 | HARDWARE §3; API §10.1 |
| **SCN-NEG-005a** | Gate B closed — apply without family cert | Operator | Valid auth; confirmed plan; Gate **B** not passed for family | **B Closed** | `POST .../plans/{plan_id}/apply` | **403** `gate.mutation_forbidden` (uncertified write family) | `apply_denied_gate` | L1 | HARDWARE §5–6; API §10 |
| **SCN-NEG-005b** | Gate C closed — lab write path | Operator | Valid auth; lab mutation path; Gate **C** window closed | **C Closed** | `POST .../plans/{plan_id}/apply` (lab dispatch) | **403** `gate.mutation_forbidden` (lab window closed) | `apply_denied_gate` | L1 | HARDWARE §5; API §10 |
| **SCN-NEG-005c** | Gate D closed — production write path | Operator | Valid auth; production dispatch; Gate **D** not satisfied | **D Closed** | `POST .../plans/{plan_id}/apply` (production dispatch) | **403** `gate.mutation_forbidden` (production enablement not satisfied) | `apply_denied_gate` | L1 | HARDWARE §5; API §10 |
| **SCN-NEG-006** | Stale observation/plan | Operator | Observation TTL expired or desired changed | Closed | `POST .../plans`; `POST .../apply` | **412** `plan.precondition_failed` or `revision.precondition_failed` | `plan_precondition_failed` | L2 fake stale | PERSISTENCE §3.3; RCI §6 |
| **SCN-NEG-007** | Expired Confirm | Operator | `plan.expires_at` passed | Closed | `POST .../apply` | **409** `plan.expired`; `confirmation_state` → `Expired` | `plan_expired` | L2 fake clock | SECURITY §3; API §4 |
| **SCN-NEG-008** | Unmanaged conflict | Operator | Planner touches non-owned resource | Closed | `POST .../plans` | **422** `domain.semantic_error` per API §4.2; plan-time stop; unmanaged unchanged | `semantic_error` | L2 fake merge | RCI §6; DOMAIN_MODEL |
| **SCN-NEG-009** | Idempotency replay vs conflict | Operator | Same/different body same key | Closed | Mutating POST/PUT with `Idempotency-Key` | Replay → same op **200/202**; conflict → **409** `idempotency.conflict` | `idempotency_replay` or `idempotency_conflict` | L2 fake | PERSISTENCE §6; API §4.3 |
| **SCN-NEG-010** | Cancel boundaries | Operator | Job in `Queued` vs `Leased`/`Running` vs terminal | Closed | `POST /jobs/{id}/cancel` | Queued→**200** `Cancelled`; leased/running→**202** `cancel_requested`; when target reaches `Cancelled`, **must** update stored idempotency response **202**→**200** exactly once; same-key+digest replay returns currently stored outcome (**202** while in-flight, **200** after update); terminal→**409** `job.already_terminal`; different digest→**409** | `cancel_requested`, `cancel_denied`, or `idempotency_replay` | L2 fake | PERSISTENCE §5.3/§6; API §4.3/§9.3 |

### 3.5 Job failures and recovery (`SCN-JOB-*`)

| id | title | actor | preconditions | gates | trigger | api observe | expected job/operation state | recovery policy | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **SCN-JOB-001** | Transport timeout before dispatch | Worker / adapter | Confirmed plan; pre-dispatch | Closed (L2 fake) | Adapter timeout pre-dispatch | `GET /jobs/{id}` | Job `Failed` or op `Failed`; no router mutation | Safe retry from plan boundary | `job_failed` | L2 fake | RCI §5; PERSISTENCE §5 |
| **SCN-JOB-002** | Transport timeout after dispatch | Worker / adapter | Apply dispatched (future/L2) | Closed (L2 fake) | Timeout mid-apply | `GET /jobs/{id}` | **Unknown external outcome** path; no blind retry | Identity + read-back before resume | `job_unknown_outcome` | L2 fake | PERSISTENCE §5.2 |
| **SCN-JOB-003** | Async continuation incomplete | Worker / adapter | Long-running vendor poll | Closed (L2 fake) | Partial `"continued"`-style poll | `GET /jobs/{id}` | Job `Running`; checkpoints persisted | Resume from last checkpoint | `job_checkpoint_saved` | L2 fake | RCI §5; TEST §4 |
| **SCN-JOB-004** | Crash / expired lease / stale worker | Worker | Active leased job | Closed (L2 fake) | Worker dies; lease expires | `GET /jobs/{id}` | Job → `Lost`; fencing prevents stale write | Re-claim or `RecoveryRequired` | `job_lost`, `fence_rejected` | L2 fake + future fault inject | PERSISTENCE §4.4–4.5 |
| **SCN-JOB-005** | Unknown external outcome read-back | Operator + worker | Post-dispatch uncertainty | Closed (L2 fake) | Outcome uncertain after dispatch | `GET /jobs/{id}`; read-back step | Op `RecoveryRequired` until read-back | No blind retry post-dispatch | `recovery_required` | L2 fake | PERSISTENCE §5.2 |
| **SCN-JOB-006** | Compensation | Worker | Partial apply before verify fail | Closed (L2 fake) | Verify fails after partial apply | `GET /operations/{id}` | Compensation steps; `Failed` or `RecoveryRequired` | Fail-safe narrative restore | `compensation_started` | L2 fake | RCI §5; CANONICAL |
| **SCN-JOB-007** | Fail-safe timeout | Worker | Disruptive family apply | Closed (L2 fake) | Simulated loss-of-management window | Observe job steps | Fail-safe Configuration timeout handling | Reboot restores last saved config (narrative) | `failsafe_timeout` | L2 fake | RCI §5; CANONICAL |
| **SCN-JOB-008** | RecoveryRequired aggregate | Operator | Unresolved external state | Closed | Unresolved external state | `GET /operations/{id}` | `aggregate_status` `RecoveryRequired`; `reconcile_status` `RecoveryRequired` | Operator-led recovery workflow | `recovery_review_started` | L1 + L2 | DOMAIN_MODEL; PERSISTENCE §5 |
| **SCN-JOB-009** | DB corrupt / disk-full | System / SQLite | RC persistence fault | N/A (infra) | SQLite fault | `GET /status` | RC `Degraded`/`Disabled`; `database_state` `Degraded`/`Unavailable`; **Hub kiosk/board/printing continue** | RC isolated failure | `database_degraded` | L1 + L2 fault matrix | PERSISTENCE §8.4; §8.7 item 10; ARCHITECTURE |

### 3.6 Lab evidence — future gated (`SCN-LAB-*`)

| id | title | actor | preconditions | gates (future) | api (future) | scope | Phase 0b | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|---|
| **SCN-LAB-001** | AWG synthetic lab | Lab operator | Dedicated NC-1812; sanitized tuple | **B** then **C** (future) | `POST .../apply` → verify (future L5–L6) | AWG apply/verify sequence — **no real router steps in 0b** | **Spec only**; gates **closed** | `lab_evidence_recorded` (future) | **L5–L6** future sanitized package | HARDWARE §6; TEST §6; RCI §2 |
| **SCN-LAB-002** | Route benchmark 100/1k/5k | Lab operator | Lab router; route_sets phase | **B/C** future | Benchmark apply/read-back (future L6–L7) | Benchmark protocol 100 → 1k → 5k routes — **future gated** | **Spec only**; no Phase 0b gate opening | `benchmark_evidence_recorded` (future) | **L6–L7** future evidence | ADR-004; TEST §6.4; COMPATIBILITY |

**Phase 0b rule:** SCN-LAB scenarios document **future** evidence requirements only. No live RCI commands, no gate opening, no certification claims.

### 3.7 Strangler / cutover (`SCN-CUT-*`)

| id | title | actor | preconditions | gates | api | expected | audit | evidence | trace |
|---|---|---|---|---|---|---|---|---|---|
| **SCN-CUT-001** | Strangler cutover rehearsal | Operator + maintainer | Legacy `ScanCursorIP` parallel; parity checklist | All **Closed** in 0b | `GET /status` (parity observe); no production cutover writes | Rehearsal plan; no production cutover in 0b | `cutover_rehearsal_planned` | **L1** procedure spec; **L3** recorded fixtures later | ARCHITECTURE §9; LEGACY_MAP |
| **SCN-CUT-002** | Rollback / fallback | Operator | Cutover flag reversible; Hub RC disabled path | All **Closed** | `GET /status` | Fallback to legacy strangler; RC `Disabled` — Hub continues | `cutover_rollback` | L1 + L2 | ARCHITECTURE §9; VISION |
| **SCN-CUT-003** | Old fixtures ≠ NC-1812 cert | Reviewer | Legacy recorded shapes from old device | N/A (classification) | (no RC mutation — fixture review) | Fixtures classify as **behavioral evidence only** — **not** NC-1812 certification | `fixture_classified` | L1 + L3 classification | LEGACY_MAP; TEST §5.2; COMPATIBILITY |

---

## 4. Trace matrix

| scenario_id | primary API operations | TEST lane | contract refs |
|---|---|---|---|
| SCN-EVT-001 | status, routers POST, credentials PUT, vpn-profiles import/validate, desired-revision PUT, plans POST, confirm POST | L1, L2 | SECURITY, PERSISTENCE, HARDWARE |
| SCN-EVT-002 | status GET, routers GET, operations/jobs GET | L1, L2 | ARCHITECTURE, PERSISTENCE |
| SCN-EVT-003 | status, routers, operations, jobs, cancel POST | L1, L2 | PERSISTENCE, RCI |
| SCN-EVT-004 | revoke POST, routers POST, preflight POST, credentials PUT | L1, L2 | SECURITY, HARDWARE |
| SCN-ZONE-001..003 | (network deny — no successful RC access) | L1 | SECURITY §8, ARCHITECTURE §4 |
| SCN-ZONE-004 | status GET | L1, L2 | SECURITY §1, API §2 |
| SCN-ZONE-005 | status GET | L1 | SECURITY §8 |
| SCN-OPS-001..008 | operator surface per §3.3 (through Confirm/observe) | L1, L2 | API, SECURITY, PERSISTENCE |
| SCN-OPS-009 | `POST .../plans/{plan_id}/apply` (0b **403**; future verify) | L1, L2 fake; future **L5–L7** only | API §10.2, RCI §5, PERSISTENCE §3.2, HARDWARE |
| SCN-NEG-001..010 | mutating/GET routes per §3.4 | L1, L2 | API §4, SECURITY, PERSISTENCE, RCI |
| SCN-NEG-005a..005c | gate B/C/D write denial on apply | L1 | HARDWARE §5–6, API §10 |
| SCN-JOB-001..009 | jobs/operations GET; cancel POST | L1, L2 | PERSISTENCE §4–5, RCI §5 |
| SCN-LAB-001 | AWG apply/verify (future) | L5–L6 future spec | HARDWARE §6, TEST §6, RCI §2 |
| SCN-LAB-002 | route benchmark (future) | L6–L7 future spec | TEST §6.4, COMPATIBILITY, HARDWARE |
| SCN-CUT-001..003 | (process — minimal API during rehearsal) | L1, L3 later | ARCHITECTURE §9, LEGACY_MAP, TEST §5 |

---

## 5. Phase 0b Definition of Done (scenarios contract — historical closeout snapshot)

**Historical closeout snapshot (2026-07-20):** Phase 0b closed (Wave 7). This contract satisfied Phase 0b when:

1. This document is AI-first; §1–§4 define zones, happy paths, negatives, and the evidence trace matrix.
2. [`STATUS.yaml`](../STATUS.yaml) lists deliverable `scenarios` (`SCENARIOS.md`) as completed.
3. Navigation synchronized with STATUS, READMEs, `project-state.md`, `docs-map.json`, contracts index, and cross-links in VISION/API/TEST/SECURITY/PERSISTENCE/ARCHITECTURE/DOMAIN.
4. No implementation artifacts, secrets, invented endpoints, or opened hardware gates.
5. Operator happy paths document **Confirm** as L1/L2-spec; **apply/verify** explicitly **future-gated** or Phase 0b **403** fail-closed.

**Wave 7 closeout:** All eight STATUS contract deliverable IDs complete; cross-document review done; `pending: []`.

**Current state:** Phase 1 / SLICE-1 **complete** per [`STATUS.yaml`](../STATUS.yaml) — **L2 fake** implementation exists; hardware live lanes closed; hardware gates A–D closed; no live adapter. SLICE-2 **blocked** pending separate human approval.

---

## 6. Links

- HTTP/API surface: [`API_CONTRACT.md`](API_CONTRACT.md)
- Test lanes and evidence: [`TEST_STRATEGY.md`](TEST_STRATEGY.md)
- Zones and auth: [`SECURITY_OPS.md`](SECURITY_OPS.md)
- Jobs, lease, recovery: [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md)
- Hardware gates: [`HARDWARE_GATES.md`](HARDWARE_GATES.md)
- RCI lifecycle: [`RCI_POLICY.md`](RCI_POLICY.md)
- Event vision: [`VISION.md`](../VISION.md)
- Contracts index: [`README.md`](README.md)
