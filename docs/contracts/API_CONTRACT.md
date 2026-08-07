# HTTP/API contract (v0)

## For agents

| Topic | Rule |
|---|---|
| Prefix | All routes under **`/api/router-control/v1`** on shared Hub listener (prototype dev-host uses same prefix) |
| Phase 0b | Contract complete; **implementation exists** for host/persistence (SLICE-2/3); mutations gated |
| Auth order | Enabled + empty `HUB_ADMIN_PASSWORD` → **503** before handler; invalid/missing `hub_admin` → **401**; no API/guest/board/promo bypass |
| Feature states | `Disabled` / `Starting` / `Ready` / `Degraded` / `SecurityBlocked` — see §2 |
| Mutations | **`Idempotency-Key` required** on all POST/PUT/PATCH/DELETE; `If-Match` on desired revision/plan preconditions; Gate **A** before live observe; §10 gates before write dispatch |
| Secrets | Write-only inputs; **never** echoed in response/DTO/job/audit; use `CredentialRef` metadata on reads |
| Gates | Gate **A** **ReadOnlyCertified** (authorized rebind **2026-07-31** rebind #2 post-WG; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**); **NOT** WriteCertified; `write_shapes_registered` **false**; live observe when tuple matches; writes require Gate B + (C or D) — **B completed_failed; C/D closed** |
| P1-B dispatch | **Complete (2026-07-22, offline/fake):** `ApplyResult` continuation token + optional `poll_apply_continuation` on fake adapter; live HTTP/worker still `MutationForbidden` |
| Milestones | M1–M3 offline/read-only only (2026-07-22 authorization); no signed pull; no Hub embed in M1–M3 |
| v0 exclusions | No static routes CRUD/capture/raw-RCI/arbitrary-command endpoints; TrafficDiscovery is proposals-only (no apply) |
| Trace | [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), [`RCI_POLICY.md`](RCI_POLICY.md), [`HARDWARE_GATES.md`](HARDWARE_GATES.md), [`SECURITY_OPS.md`](SECURITY_OPS.md), [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md), ADR-001/002/003/004, [`SCENARIOS.md`](SCENARIOS.md), [`ROADMAP.md`](ROADMAP.md) |

---

## 1. Scope, hosts, prefix, content-type, versioning

### 1.1 Scope

This document is the **normative HTTP contract** for Router Control v0. It covers:

- feature health/status;
- router inventory, enrollment, and preflight;
- credential write/rotate/revoke and metadata-only reads;
- AmneziaWG (`AWG`) profile import, validation, and catalog;
- desired assignment revision (GET/PUT with ETag);
- change plan create/read/confirm/apply;
- read-only commissioning runs (M1): create/list/assess/report/cancel;
- offline event presets (M2): create/list/revisions/publish/validate/plan-preview/readiness report;
- traffic discovery (proposals-only): record observations, create/get route proposals — auto-apply always blocked;
- operation and job status/cancel.

It does **not** define RCI JSON, SQLite DDL, executable migrations, or OpenAPI artifacts (deferred to implementation phase).

### 1.2 Hosts

| Host | Role |
|---|---|
| Production Hub | Shared LAN HTTPS listener (`module_3.0`); Router Control is one `APIRouter` mount |
| Prototype dev-host | Separate FastAPI process for lab; **same prefix and contract**; not a divergent API surface |

Both hosts call identical application use cases ([`ARCHITECTURE.md`](../ARCHITECTURE.md) §6–7, ADR-001).

### 1.3 URL prefix and versioning

- **Common prefix:** `/api/router-control/v1`
- **Versioning:** `v1` is a URL path segment; breaking HTTP changes require a new prefix (e.g. `v2`). Non-breaking additive fields may appear in `v1` responses when unknown-field policy allows.
- **Deprecation:** Deprecated routes respond with `Deprecation: true` and optional `Sunset` (RFC 8594) header; contract changes are recorded in this document before code ships.

### 1.4 Content type

- Request and response bodies: **`application/json; charset=utf-8`**
- Error bodies: same content type unless noted (503 security block may omit body details)
- No `multipart/form-data` in v0; profile import accepts JSON wrapper with base64 or structured fields per §7.3

### 1.5 Correlation identifiers

Every response **must** include:

| Header | Purpose |
|---|---|
| `X-Request-Id` | Unique id for this HTTP request (server-generated if absent) |
| `X-Correlation-Id` | Echo client `X-Correlation-Id` when supplied; else equals `X-Request-Id` |

Every **error** response (**4xx/5xx** with body) **must** include **`request_id` and/or `correlation_id`** in the `error` object (§4.1), mirroring these headers.

Clients **may** send `X-Correlation-Id` on mutations for operator support and audit correlation ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.16, §2.21).

---

## 2. Auth and feature-state matrix

### 2.1 HTTP auth decision order (`hub_admin`)

For **every** request under `/api/router-control/v1` (including GET), evaluated **before** route handler ([`SECURITY_OPS.md`](SECURITY_OPS.md) §1, [`ARCHITECTURE.md`](../ARCHITECTURE.md) §10):

| Step | Condition | HTTP | Handler |
|---|---|---|---|
| 1 | Feature **enabled** and `HUB_ADMIN_PASSWORD` empty/whitespace | **503** | **Not invoked** |
| 2 | Password configured; missing/invalid `hub_admin` session cookie | **401** | Not invoked |
| 3 | Valid `hub_admin` session | — | Proceed to §2.2 |
| 4 | API key, guest, board, promo, or source-IP zone | — | **Never** substitutes for step 2–3 |

Step 1 corresponds to feature state **`SecurityBlocked`**. Response body uses machine code `security.configuration_blocked` (§4); no route-specific leakage.

### 2.2 Feature runtime states

After auth, feature policy applies:

| State | Meaning | API surface |
|---|---|---|
| **Disabled** | Feature off; no worker/adapters | **`GET /status` only** — reports `disabled`; all other routes **404** or **503** per implementation policy (prefer **404** for undiscoverable surface) |
| **Starting** | Composition/recovery in progress | **`GET /status` only** — reports `starting`; mutations **503** `feature.not_ready` |
| **Ready** | Full v0 contract | All v0 routes per auth + gates |
| **Degraded** | Store/worker/router recoverable failure | **`GET /status` only** (+ optional redacted sub-resources linked from status); **all mutations 503** `feature.degraded` |
| **SecurityBlocked** | Empty admin password when enabled | **All routes 503** before handler (§2.1 step 1) |

**Mutations are forbidden** in `Disabled`, `Starting`, `Degraded`, and `SecurityBlocked`. **`SecurityBlocked`** exposes **no** health handler — all prefix routes return **503**. **`Degraded`** alone may expose limited redacted **`GET /status`** ([`SECURITY_OPS.md`](SECURITY_OPS.md) §2).

### 2.3 Auth matrix (summary)

| State | GET `/status` | GET reads (inventory, plans, …) | Mutations |
|---|---|---|---|
| SecurityBlocked | 503 | 503 | 503 |
| Disabled | 200 (disabled) | 404/503 | 404/503 |
| Starting | 200 (starting) | 503 not_ready | 503 |
| Degraded | 200 (degraded) | 503 or limited per status links | 503 |
| Ready + 401 | 401 | 401 | 401 |
| Ready + auth OK | 200 | 200 | Per gates + contract |

---

## 3. Common headers

### 3.1 Request headers

| Header | Required | Applies to | Semantics |
|---|---|---|---|
| `Authorization` | No | — | **Not used** in v0; auth is `hub_admin` cookie only |
| `Cookie: hub_admin=…` | Yes (except step-1 503) | All routes | Existing Hub session cookie |
| `Idempotency-Key` | **Yes** | All mutation requests (POST/PUT/PATCH/DELETE) | Opaque client key; max 128 chars; scope per [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §6 |
| `If-Match` | Conditional | Desired revision PUT; plan create; plan confirm; plan apply | Desired revision ETag (create/PUT) or plan ETag (confirm/apply) |
| `If-None-Match` | Optional | GET | Standard conditional GET for caching |
| `X-Correlation-Id` | Optional | All | Propagated to audit/operations |
| `Content-Type` | Yes | Bodies | `application/json` |

### 3.2 Response headers

| Header | When |
|---|---|
| `ETag` | GET returning revision-backed or plan-backed resource |
| `Location` | Async mutation accepted — URI of `operation` or `job` |
| `Retry-After` | **202** accepted async; **429** rate limit; **503** transient feature/router busy |
| `X-Request-Id`, `X-Correlation-Id` | All responses |

ETag format: quoted strong validator derived from `revision_id` + `canonical_digest` or `plan_digest` ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §3.1).

---

## 4. Error envelope, machine codes, HTTP mapping

### 4.1 Error envelope

Failed responses (**4xx/5xx** except empty **503** security block) return:

```json
{
  "error": {
    "code": "revision.precondition_failed",
    "message": "Human-readable summary safe for operator UI",
    "details": [
      {
        "field": "if_match",
        "reason": "stale_revision",
        "message": "Desired revision changed since client ETag was issued"
      }
    ],
    "request_id": "req_01HEXAMPLE",
    "correlation_id": "corr_01HEXAMPLE"
  }
}
```

Rules:

- **`code`** — stable machine identifier (snake_case dotted); clients branch on this, not HTTP status alone.
- **`message`** — redacted; **must not** contain router command text, passwords, keys, session tokens, startup-config excerpts, or raw user input echoed from validation failures.
- **`details`** — optional array of field-level issues; values redacted.
- **`request_id` / `correlation_id`** — mirror response headers.
- **`request.validation_failed` union summary (2026-08-01):** for Pydantic union clusters (multiple branch failures on one root field), top-level `message` **must** prefer a single nested constraint field when unambiguous (`Invalid value for ip_global.priority: greater_than_equal (expected >= 0)`); **must not** lead with `literal['…']` or internal model class names. When no single constraint winner exists, use `Invalid value for {root}: does not match any allowed form (allowed: 'auto', object with 'priority', …)`. Structured `details[].loc` may retain branch paths; safe `ctx` includes `expected` / bounds keys only (`ge`, `le`, `gt`, `lt`). Never include `input` or pydantic `msg`.
- **Operator message synthesis (2026-08-01):** event-preset validation (400), network-family preview failures (422), and Starlette `HTTPException` **must** use the standard `error` envelope via `operator_structured_error_response` / `starlette_http_error_response` — fixed status messages, never `exc.detail`. Unknown document fields **must not** list user key names in `message` or `details` (use `unrecognized field(s)` + structural `{field, reason}`). Test vectors: `tests/test_operator_error_no_echo_guard.py`.

### 4.2 HTTP status mapping

| HTTP | Typical `error.code` | When |
|---|---|---|
| **400** | `request.invalid_json`, `request.validation_failed` | Malformed JSON; missing required header/field (including `Idempotency-Key` on mutations); unknown fields on mutation (§5.6) |
| **401** | `auth.required` | Missing/invalid `hub_admin` |
| **403** | `auth.forbidden`, `gate.a_closed`, `gate.mutation_forbidden` | Authenticated but action forbidden (e.g. wrong actor, Gate A closed for live observe, write gates closed, feature policy) |
| **404** | `resource.not_found` | Unknown `router_id`, `plan_id`, `job_id`, … |
| **409** | `revision.conflict`, `idempotency.conflict`, `router.identity_mismatch`, `plan.stale`, `plan.expired` | Concurrent revision update; idempotency key reuse with different digest; identity drift; expired plan |
| **412** | `revision.precondition_failed`, `plan.precondition_failed` | `If-Match` mismatch; stale observation/revision at plan create — `plan.precondition_failed` = observation/revision binding failed; `plan.stale` = plan state changed since client last read (e.g. superseded) |
| **422** | `domain.semantic_error`, `profile.validation_failed`, `capability.unsupported` | Valid JSON but business rule failure (unsupported profile field, uncertified capability) |
| **428** | `precondition.required` | Mutation requires `If-Match` but header absent |
| **429** | `rate_limit.exceeded` | Optional Hub rate limit |
| **503** | `security.configuration_blocked`, `feature.degraded`, `feature.not_ready`, `router.mutation_busy`, `sealed_apply.trail_begin_failed` | SecurityBlocked; degraded/disabled mutation; starting; router lock held (optional); sealed apply trail row could not be created (device dispatch blocked) |
| **504** | `router.transport_timeout` | Adapter bounded timeout (read paths); mutation jobs surface timeout via job status, not necessarily synchronous 504 |

Router RCI command errors **must not** leak verbatim; map to normalized codes (`router.transport_auth_failed`, `capability.unknown`, `observation.stale`, …).

### 4.3 Idempotency outcomes

Applies to **all mutation intents** (async and sync): enroll, preflight, credential PUT/rotate/revoke, profile import/validate, desired-revision PUT, plan create/confirm/apply, job cancel.

| Condition | HTTP | Behavior |
|---|---|---|
| Missing `Idempotency-Key` on mutation | **400** | `request.validation_failed`; handler not invoked |
| New key + new digest (async) | **202** or **201** | Create `idempotency_record`, `operation`, and initial `job`; return accepted body + `Location` |
| New key + new digest (sync) | **200** or **201** | Create `idempotency_record`, `operation`, and initial `job` in the same transaction ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §6); complete domain work in-request; initial `job` **may** reach terminal status (`Succeeded`/`Failed`/`Cancelled`) before COMMIT; persist terminal HTTP response on `idempotency_record`; return resource body (not `OperationAccepted`) |
| Same key + same digest (in-flight async) | **202** | Replay stored accept response (status, body, `Location`) |
| Same key + same digest (terminal) | **200** or **201** | Replay stored terminal response (status, body, relevant headers such as `ETag`) |
| Same key + different digest | **409** | `idempotency.conflict`; **must not** create second operation or re-run side effects |

**Persistence alignment** ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §6, §7.2): every mutation intent that commits the §6 creation bundle **must** atomically INSERT linked `operation`, `idempotency_record`, and initial `job` keyed by (`scope`, `router_id`, `operation_kind`, `idempotency_key`) with canonical `request_digest`. **Async** mutations return **202** with non-terminal initial `job` status (`Queued`, or `Running` after claim). **Sync** mutations return **200/201** with resource body; initial `job` **must** still be INSERTed and **may** be immediately terminal in the same transaction when work completes in-request. Terminal HTTP response **must** be stored on `idempotency_record` for replay.

**Cancel:** `POST /jobs/{job_id}/cancel` commits the §6 bundle with `operation_kind: cancel_job` (cancel-control initial `job` immediately terminal when the cancel HTTP outcome is final) **and** conditionally updates the **target** `jobs` row per [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §5.3 — cancel does not enqueue background work on the cancel-control job. Cancel idempotency replay **must** return the stored cancel-operation HTTP outcome without re-notifying the worker:

| Cancel replay condition | HTTP | Body / semantics |
|---|---|---|
| First cancel; target `Queued` | **200** | Target job → `Cancelled` |
| First cancel; target `Leased`/`Running` | **202** | `cancel_requested: true` on target; target **not** yet `Cancelled` |
| Same `Idempotency-Key` + digest replay while target still `cancel_requested` or cancel in-flight | **202** | Same stored `cancel_requested` outcome |
| Same key + digest replay after target reached `Cancelled` (or other terminal cancel success) | **200** | `Cancelled` |
| Same key + different digest, or illegal target state | **409** | `idempotency.conflict` or `job.already_terminal` per §9.3 |

**Cancel idempotency single-update policy:** Cancel is the **only** mutation where the stored `idempotency_record` HTTP response **may** change after the first commit. First cancel on `Leased`/`Running` **must** store **202** `cancel_requested` (terminal for the cancel-control operation). When the target job later reaches `Cancelled`, implementation **must** UPDATE that same stored response **exactly once** to **200** `Cancelled`. Same `Idempotency-Key` + digest replay **must** return whatever is currently stored and **must not** re-notify the worker or create a second cancel operation. Queued first-cancel stays **200** immediately; terminal target → **409**; different digest → **409**.

**Note:** For cancel, "terminal HTTP response" on `idempotency_record` means the **cancel operation's** recorded outcome (**202** `cancel_requested` or **200** `Cancelled`) — not that the target job is always `Cancelled` when **202** was returned. The **202**-then-**200** progression is not contradictory: **202** is stored at first commit on `Leased`/`Running`; the required single update to **200** when the target reaches `Cancelled` aligns replay with the stored outcome without a new idempotency record.

---

## 5. Conventions

### 5.1 Identifiers

Opaque string IDs (UUID/ULID style in examples only):

| Field | Entity |
|---|---|
| `site_id`, `router_id` | Site, Router |
| `endpoint_id`, `capability_id`, `observation_id` | Inventory reads |
| `credential_ref_id` | CredentialRef |
| `profile_id`, `assignment_id` | VPN profile, tunnel assignment |
| `revision_id` | DesiredRevision |
| `plan_id` | ChangePlan |
| `operation_id`, `job_id`, `step_id` | Async execution |
| `artifact_id`, `audit_event_id` | Artifacts, audit (referenced, not always exposed) |

Placeholders in examples: `rtr_01EXAMPLE`, `rev_01EXAMPLE` — never real hardware identifiers.

### 5.2 Timestamps

- All timestamps: **UTC ISO-8601/RFC3339** with `Z` suffix, e.g. `"2026-07-20T14:30:00Z"`.
- Client clocks must not be trusted for authorization; server `ClockPort` is authoritative for TTL/expiry.

### 5.3 Pagination

List endpoints support:

| Query | Default | Max |
|---|---|---|
| `limit` | 50 | 200 |
| `cursor` | — | Opaque cursor from previous `next_cursor` |

Response wrapper:

```json
{
  "items": [],
  "next_cursor": "opaque_or_null",
  "limit": 50
}
```

### 5.4 Filter and order

- Filter: query params `filter[field]=value` for documented fields only (e.g. `filter[lifecycle_status]=Enrolled`).
- Order: `sort=created_at` or `sort=-created_at` (prefix `-` = descending).
- Unknown filter/sort keys on GET: **ignored** with optional `Warning` header (implementation choice); unknown keys on mutation: **400** (§5.6).

### 5.5 Boolean and enumeration

- JSON booleans: `true` / `false` (not `0`/`1` on wire).
- Enumerations use PascalCase strings matching domain ([`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md)), e.g. `Enrolled`, `Draft`, `Confirmed`.

### 5.6 Unknown fields policy

| Operation | Policy |
|---|---|
| **Mutations** (POST/PUT/PATCH) | **Reject** unknown JSON properties → **400** `request.validation_failed` |
| **GET** responses | Server omits unset optional fields; clients **must ignore** unknown response properties |

---

## 6. Endpoint inventory (v0)

Base path: `/api/router-control/v1`

| Method | Path | Summary | Sync/Async | Idempotency-Key | If-Match | Gate before dispatch |
|---|---|---|---|---|---|---|
| GET | `/status` | Feature health/status | Sync | — | — | — |
| GET | `/routers` | List enrolled routers | Sync | — | — | — |
| POST | `/routers` | Enroll router | Async | **Req** | — | **A** (live observe); no write dispatch |
| GET | `/routers/{router_id}` | Router detail | Sync | — | — | — |
| POST | `/routers/{router_id}/preflight` | Preflight checks | Async | **Req** | Opt | **A** (live observe only) |
| GET | `/routers/{router_id}/credentials` | List credential metadata | Sync | — | — | — |
| GET | `/routers/{router_id}/credentials/{credential_ref_id}` | Credential metadata | Sync | — | — | — |
| PUT | `/routers/{router_id}/credentials` | Create/store credential (write-only secret) | Sync | **Req** | — | Vault only; no router write |
| POST | `/routers/{router_id}/credentials/{credential_ref_id}/rotate` | Rotate credential | Async | **Req** | — | B if triggers router verify job |
| POST | `/routers/{router_id}/credentials/{credential_ref_id}/revoke` | Revoke credential | Async | **Req** | — | Blocks new jobs using ref |
| GET | `/vpn-profiles` | Profile catalog | Sync | — | — | — |
| POST | `/vpn-profiles/import` | Import AWG profile | Sync | **Req** | — | Parser only; no router dispatch |
| POST | `/vpn-profiles/parse-preview` | Parse `.conf` text → vault + sanitized preview | Sync | — | — | Vault only; never echoes profile text or key values |
| GET | `/vpn-profiles/{profile_id}` | Profile detail | Sync | — | — | — |
| POST | `/vpn-profiles/{profile_id}/validate` | Re-validate profile | Sync | **Req** | — | Parser only |
| GET | `/routers/{router_id}/desired-revision` | Current desired revision | Sync | — | — | — |
| PUT | `/routers/{router_id}/desired-revision` | New desired revision | Sync | **Req** | **Req** | SQLite only; no router dispatch |
| POST | `/routers/{router_id}/plans` | Create change plan | Sync | **Req** | **Req** | Preconditions only; no apply |
| GET | `/routers/{router_id}/plans/{plan_id}` | Get plan | Sync | — | — | — |
| POST | `/routers/{router_id}/plans/{plan_id}/confirm` | Confirm plan | Sync | **Req** | **Req** | Records Confirm; no live dispatch |
| POST | `/routers/{router_id}/plans/{plan_id}/apply` | Apply confirmed plan | Async | **Req** | **Req** | §10 write gates |
| GET | `/operations/{operation_id}` | Operation status | Sync | — | — | — |
| GET | `/operations/{operation_id}/jobs` | Jobs for operation | Sync | — | — | — |
| GET | `/jobs/{job_id}` | Job status/steps | Sync | — | — | — |
| POST | `/jobs/{job_id}/cancel` | Request cancel | Sync | **Req** | — | Safe-boundary cancel (§9) |
| POST | `/jobs/{job_id}/resume` | Queue recovery resume (fake-only) | Sync | **Req** | — | M4: identity+read-back resume; same `operation_id` |
| POST | `/jobs/{job_id}/compensate` | Queue compensation (fake-only) | Sync | **Req** | — | M4: compensate after read-back policy |
| GET | `/jobs/{job_id}/backup-artifact` | Redacted backup metadata | Sync | — | — | No content/locator secrets |
| POST | `/sites/{site_id}/commissioning-runs` | Create commissioning run (Draft) | Sync | **Req** | — | SQLite only; no router write |
| GET | `/sites/{site_id}/commissioning-runs` | List commissioning runs for site | Sync | — | — | — |
| GET | `/commissioning-runs/{run_id}` | Get commissioning run | Sync | — | — | ETag on response |
| POST | `/commissioning-runs/{run_id}/assess` | Assess read-only readiness | Sync | **Req** | Opt | **A** when `mode=live`; no router write |
| GET | `/commissioning-runs/{run_id}/readiness-checks` | List readiness checks | Sync | — | — | Append-only checks |
| GET | `/commissioning-runs/{run_id}/report` | RO vs write readiness report | Sync | — | — | Never `Commissioned`/`WriteCertified` |
| POST | `/commissioning-runs/{run_id}/cancel` | Cancel commissioning run | Sync | **Req** | Opt | SQLite only |
| GET | `/sites/{site_id}/event-presets` | List event presets for site | Sync | — | — | — |
| POST | `/sites/{site_id}/event-presets` | Create event preset + revision 1 | Sync | **Req** | — | SQLite only; safe default when `document` omitted |
| GET | `/event-presets/{preset_id}` | Get event preset | Sync | — | — | ETag on response |
| POST | `/event-presets/{preset_id}/revisions` | New immutable revision | Sync | **Req** | Opt | INSERT-only revision rows |
| GET | `/event-presets/{preset_id}/revisions/{revision_id}` | Get revision + canonical document | Sync | — | — | ETag on response |
| POST | `/event-presets/{preset_id}/publish` | Publish revision pointer | Sync | **Req** | Opt | Pointer only; no router apply |
| POST | `/event-presets/{preset_id}/validate` | Deterministic offline validate | Sync | — | — | No router I/O |
| POST | `/event-presets/{preset_id}/plan-preview` | Redacted plan preview | Sync | — | — | `write_ready=false` always |
| GET | `/event-presets/{preset_id}/readiness/report` | Preset readiness report | Sync | — | — | May include commissioning summary read-side |
| POST | `/wifi/preview` | Compile Wi-Fi apply plan (offline) | Sync | — | — | No dispatch; no PSK resolution; **`enabled`, `wpa_mode`, `band`, `guest_isolation` required** (no HTTP silent defaults) |
| POST | `/wifi/apply` | Apply Wi-Fi intent to bounded test AP | Sync | — | — | Requires `confirm_live_apply: true`; **`enabled`, `wpa_mode`, `band`, `guest_isolation` required**; optional `compensate_on_failure` (default true; rollback on dispatch failure or **configuration** mismatch — **not** `on_air_admin_only` / `on_air_unverified`); `idempotent` (default false); response **`on_air_verification_status`** (`on_air_verified` \| `on_air_admin_only` \| `on_air_unverified` \| `on_air_still_broadcasting`) from shared `resolve_on_air_signal` (`link` only; `broadcast`/`broadcasting` supplementary; link/broadcast conflict → unverified); test AP allowlist; any live connection field without complete set → **422** `wifi.live_connection_incomplete`; complete live params on non-win32 → **503** `wifi.live_platform_unsupported`; live path: Gate A closed → **503** `wifi.gate_a_required`; startup-config backup failure → **503** `wifi.live_backup_unavailable`; injected transport |
| POST | `/wifi/teardown` | Teardown bounded test AP to baseline | Sync | — | — | Requires `confirm_live_teardown` or `confirm_live_apply`; **`wpa_mode` required** (no HTTP silent default — matches domain `_parse_wifi`); any live connection field without complete set → **422** `wifi.live_connection_incomplete`; complete live params on non-win32 → **503** `wifi.live_platform_unsupported`; live path: Gate A closed → **503** `wifi.gate_a_required`; startup-config backup before first write; backup failure → **503** `wifi.live_backup_unavailable`; injected transport / per-request live session |
| POST | `/wifi/observed-state` | Read-only observed Wi-Fi AP state (+ optional desired compare) | Sync | — | — | Live: same connection fields as apply (`host`, `username`, `router_credential_ref_id`, `ssh_host_key_sha256`, optional `source_address`/`router_id`); `credential_ref_id` aliases router password ref; Gate A required; read-only session (no confirm/backup/write); never PSK; `certification_eligible: false` |
| POST | `/wifi/site-survey` | Read-only Wi-Fi site-survey (WifiMaster0/1) | Sync | — | — | Issues only `show site-survey WifiMaster0\|WifiMaster1`; live RCI JSON (`parse.ap_cell`) exposes per-row encryption; tabular fallback has no security column; neighbour SSID/BSSID returned to authenticated operator only (never logged); live path reuses `open_wifi_live_session` + Gate A; fake/offline synthetic fixtures |
| POST | `/wifi/station/preview` | Compile Wi-Fi station (WISP) join plan (offline) | Sync | — | — | `UplinkIntent` WifiWan only; `grammar_verification_status=device_accepted_grammar`; preview **`planned_uplink_verification_level=planned_uplink_verified_bounded`** (compile-time plan label — machine-distinct from runtime `uplink_verification_status`; **not** runtime uplink observe); readback rule in preview (`configured_ssid` vs `associated_ssid`); OPEN auth → 422; no dispatch |
| POST | `/wifi/station/apply` | Apply Wi-Fi station (WISP) uplink intent | Sync | — | — | Requires `confirm_live_apply: true`; optional `compensate_on_failure` (default true; rollback only on dispatch failure or `uplink_failed` — not on `uplink_associated_no_global` / unverified observe); response `rollback.uncovered_ops` when `wifi_station_ip_global` succeeded without sealed negation; `idempotent` (default false), `uplink_settle_seconds` (default 25; clamp 20–30 when `>0` on live observe); `credential_ref_id` only; station allowlist via band; any live connection field without complete set → **422** `wifi.station.live_connection_incomplete`; live path: Gate A closed → **503** `wifi.station.gate_a_required`; startup-config backup before first write; complete live params on non-win32 → **503** `wifi.station.live_platform_unsupported`; backup failure → **503** `wifi.station.live_backup_unavailable`; live transport faults use `wifi.station.*` prefix (host-key, credential, transport failed); offline/fake returns `uplink_verification_status=uplink_dispatched_unverified` and empty `notes` (compile-time planner notes remain preview-only); live runtime uplink verdict from observe only; **NOT device-verified live in this delivery** |
| POST | `/wifi/station/teardown` | Teardown Wi-Fi station (WISP) to baseline | Sync | — | — | Requires `confirm_live_teardown` or `confirm_live_apply`; same intent fields as preview; continue-on-error teardown ops; any live connection field without complete set → **422** `wifi.station.live_connection_incomplete`; live path: Gate A closed → **503** `wifi.station.gate_a_required`; startup-config backup before first write; complete live params on non-win32 → **503** `wifi.station.live_platform_unsupported`; backup failure → **503** `wifi.station.live_backup_unavailable`; apply/teardown response `notes` empty (preview-only); injected transport / per-request live session |
| POST | `/wireguard/preview` | Compile WireGuard apply plan (offline) | Sync | — | — | **`enabled` required** (no silent default); explicit `peer_rci_shape=path_style` → **422** `wireguard.peer_rci_shape_unsupported` (REJECTED live; use `nested_rci`); no dispatch; credential_ref_id + peer non-secret fields only |
| POST | `/wireguard/apply` | Apply WireGuard intent to bounded test interface | Sync | — | — | **`enabled` required**; explicit `peer_rci_shape=path_style` → **422** `wireguard.peer_rci_shape_unsupported`; requires `confirm_live_apply: true`; optional `compensate_on_failure` (default true; rollback on dispatch failure, readback failure after dispatch, or configuration verify mismatch — not on tunnel-unverified observe when config ok); optional `handshake_settle_seconds` (default `0`; clamp 20–30 when `>0`, one recheck); response `rollback` + optional `rollback.uncovered_ops` (`wireguard_set_asc` when no sealed negation); any live connection field without complete set → **422** `wireguard.live_connection_incomplete`; complete live params on non-win32 → **503** `wireguard.live_platform_unsupported`; live path: Gate A closed → **503** `wireguard.gate_a_required`; live transport faults use `wireguard.*` prefix; default `Wireguard5`–`9`; expendable lab class adds `Wireguard0`–`4`; vault resolve at dispatch; response adds `configuration_verification_status`, `interface_verification_status` (observed admin: `interface_present_up` \| `interface_present_down` \| …), `interface_address_verification_status` (`interface_address_not_configured` when apply dispatch ok — including readback-failed paths; no sealed Address op; planner source `wireguard_apply_planner.py`), `tunnel_verification_status` (`tunnel_no_peer` \| `tunnel_never_handshaked` \| `tunnel_healthy` \| `tunnel_unverified` from `show interface` **`wireguard.peer[]`** — dead-peer + healthy **DEVICE-CONFIRMED** 2026-07-31; interface `public-key` not a peer; **NOT** `show rc`); `verification.observed` from **final** settle-recheck observation; `overall=applied` = config accepted + readback intent match (`id_ok∧up_ok`) — **NOT** egress/routing; `never_handshaked` does not fail overall; IPv6 allow-ips refused at parse/compile |
| POST | `/wireguard/teardown` | Teardown bounded test WireGuard interface | Sync | — | — | **`enabled` required**; requires confirm flags; any live connection field without complete set → **422** `wireguard.live_connection_incomplete`; complete live params on non-win32 → **503** `wireguard.live_platform_unsupported`; live path: Gate A closed → **503** `wireguard.gate_a_required`; startup-config backup before first write; backup failure → **503** `wireguard.live_backup_unavailable`; down→remove peer→clear private-key best-effort→remove interface; **`overall=applied`** when `interface_absent` even if only `wireguard_clear_private_key` failed (quirk; step visible); genuine removal failure still `failed`; `tunnel_verification_status` from final readback when present |
| POST | `/vlan/preview` | Compile VLAN bridge apply plan (offline) | Sync | — | — | No dispatch; `bridge_id` allowlisted (`Bridge2`–`Bridge9`); `verification_status=offline_unverified` (grammar not device-certified); zone id validated via allowlist |
| POST | `/dhcp/preview` | Compile DHCP pool apply plan (offline) | Sync | — | — | No dispatch; `verification_status=offline_unverified`; `lease_seconds` strict int 60–604800; reservations MAC+IPv4 only; no plaintext secrets |
| POST | `/dns/preview` | Compile DNS static-host/upstream apply plan (offline) | Sync | — | — | No dispatch; `verification_status=offline_unverified`; upstream resolvers IPv4 only |
| POST | `/firewall/preview` | Compile firewall access-list apply plan (offline) | Sync | — | — | No dispatch; `verification_status=offline_unverified`; `action`/`destination_family` enums; `ordinal` strict int ≥0 |
| POST | `/keendns/status` | Classify KeenDNS/CrazeDNS feature state from injected raw | Sync | — | — | **No network I/O**; optional body fields `components_raw`, `ndns_show_raw`, `get_booked_raw`; empty → all `unknown`; `feature_availability` tri-state (`unavailable` \| `disabled` \| `unknown`); show/get-booked shapes **not device-observed** |
| POST | `/keendns/preview` | Compile sealed KeenDNS cloud-booking preview descriptors (offline) | Sync | — | — | `intent_kind` `book` \| `drop`; `name` DNS-label 1–63; `domain` accept-list; `mode` required for `book`; `verification_status=documentation_sourced_unconfirmed`; preview-only (apply is separate route); grammar docs-sourced ([`OPERATOR_KEENDNS_DISCOVERY.md`](../OPERATOR_KEENDNS_DISCOVERY.md)) |
| POST | `/keendns/apply` | Dispatch sealed `ndns book-name` / `drop-name` on expendable lab | Sync | — | — | **`confirm_live_apply: true` required** (else **400** `keendns.confirm_required`); wifi-style live connection fields; live path: Gate A open → expendable fail-closed → backup → allowlisted writes; errors `keendns.*` (`component_absent`, `expendable_required`, `apply_failed`, …); **not WriteCertified**; cloud registration not verified by host |
| POST | `/traffic/observations` | Record traffic observation (digest only) | Sync | — | — | SQLite only; `evidence_json` never stored; raw evidence not echoed |
| POST | `/traffic/proposals` | Create route proposal from observation | Sync | — | — | `auto_apply_blocked=true`; `status=Proposed`; no router apply |
| GET | `/traffic/proposals/{proposal_id}` | Get route proposal | Sync | — | — | 404 when missing; no `proposal_json` in response |
| POST | `/lab/bootstrap-discovery` | Non-certifying bootstrap RO discovery (Add-router wizard) | Sync | — | — | `credential_ref_id` only; `allow_insecure_http: true` for plain HTTP; expendable lab class; Gate A closed OK; never certifies |
| POST | `/lab/router-discovery` | Bounded local router-candidate discovery (simple-mode UI) | Sync | — | — | Default gateway(s) + local subnet first-host per interface without DGW + enrolled endpoints; ternary `identity_state`; never subnet-scan; `certification_eligible: false` |
| POST | `/lab/connection-health` | Fact-derived connection health summary (green/yellow/red) | Sync | — | — | Green only when all five facts true; read-only; `certification_eligible: false` |
| POST | `/lab/wizard-draft-router` | Draft enroll for Add-router wizard (vault + SQLite, no probe) | Sync | Idempotency-Key | — | `secret` only (no `management_password`); Gate A closed OK; `certification_eligible: false`; no device writes |
| POST | `/routers/{router_id}/ssh-host-key/learn` | Learn SSH host-key fingerprint (pre-auth, no password) | Sync | — | — | Returns fingerprint + algorithm + out-of-band warning; never authenticates |
| POST | `/routers/{router_id}/ssh-host-key/confirm` | Confirm and pin learned SSH host key | Sync | — | — | Requires exact fingerprint echo; `409 ssh_host_key.pin_conflict` when stored pin differs; optional `allow_overwrite` |
| GET | `/connection-context/restore-candidate` | Best restorable connection context (single read) | Sync | — | — | Cookie `hub_admin`; bounded SQL selection; same context fields as per-router read when `restore_candidate: true`; `{ "restore_candidate": false }` when none qualify; no username/reachability |
| GET | `/routers/{router_id}/connection-context` | Read server-held connection context for one router | Sync | — | — | Cookie `hub_admin`; path `router_id` only (no client host); `Cache-Control: no-store` |
| POST | `/routers/{router_id}/management-username` | Persist management username on pin-bound endpoint | Sync | — | — | Value never echoed; required with pin + credential for `live_ready` |

**Sealed apply audit (2026-08-01, M11 recovery evidence):** Synchronous sealed apply/teardown routes append `audit_events` on every dispatch attempt. `summary_redacted` JSON: `intent`; `outcome` (verdict + rollback SSOT); `trail` snapshot (pre-apply baseline + per-op `ops_evidence_redacted` SSOT); residual `result` (backup/overall/ap_id — omits duplicated steps/verdict/rollback when trail/outcome present); optional scrubbed `error_message` / `exception_type`. Audit always correlates trail by `correlation_id` + route + verb. See [`SECURITY_OPS.md`](SECURITY_OPS.md) §6. **Mid-flight durability:** same routes write `sealed_apply_runs` during dispatch (M11 columns `pre_apply_baseline_redacted`, `ops_evidence_redacted`, `outcome_snapshot_redacted`); trail begin failure → **503** `sealed_apply.trail_begin_failed`; HTTP success-path status/body unchanged.

**Note:** Plan create/confirm and desired revision PUT persist intent only (SQLite). **`POST .../apply`** is the sole v0 client-visible path to enqueue router mutation dispatch after Confirm; it returns **202** `OperationAccepted` (§9.1). Apply runs §10 gate evaluation before any live adapter call. **`Ready` + valid `hub_admin` alone does not authorize live RCI observe** — live enroll/preflight observe legs require Gate **A** open; non-live (L2 fake) adapter **may** persist intent via **202** without live observe (§10.1). **Commissioning assess** is read-only: fake mode uses linked router/site state; live mode uses existing Gate A pinned-SSH RO probe only — never opens write gates or claims WriteCertified. **Event preset** endpoints are offline catalog/readiness only: canonical intent JSON excludes secrets/timestamps; missing AWG/routes/LTE or Gates B/C/D block apply/write fragments only, not `ValidOffline` LAN validation when intent is sound. **Wi-Fi apply/preview/teardown** (2026-07-24, updated 2026-07-31): default bounded to `WifiMaster0/1` + `AccessPoint3`–`AccessPoint6` (observed hardware max; AP7–9 not present); expendable lab class (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`) additionally allows `AccessPoint0`–`AccessPoint2`; request bodies accept `credential_ref_id` only (never plaintext PSK); WPA2 device-verified; WPA3/mixed offline-ready with `verification_status=pending_live_verification` (SAE grammar unverified on 5.01.C.1.0-0); teardown accepts optional `wpa_mode`; does not open WriteCertified or flip `write_shapes_registered`; Gate A **ReadOnlyCertified** (2026-07-31 rebind #2 post-WG; evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**); see [`OPERATOR_WIFI_APPLY.md`](../OPERATOR_WIFI_APPLY.md). **WireGuard apply/preview/teardown** (2026-07-24, updated 2026-07-31): default bounded to `Wireguard5`–`Wireguard9`; expendable lab class (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`) additionally allows `Wireguard0`–`Wireguard4`; intent accepts `wg_id`, optional 9-int `asc_args`, `enabled`, `private_key_credential_ref_id`, optional `preshared_key_credential_ref_id`, non-secret peer fields (`peer_public_key`, `peer_endpoint`, `peer_allow_ips`, `peer_keepalive_interval`), optional `peer_rci_shape` (`nested_rci` default \| `path_style` legacy) — never plaintext secrets; default nested_rci compiles peer upsert to sealed nested JSON under `interface.WireguardN.wireguard.peer[]`; explicit path-style peer ops compile with one CLI line per RCI parse request; planner `verification_status` (ASC/secret axis) unchanged; apply/teardown **result** adds honesty split: `configuration_verification_status=device_accepted_configuration` when sealed ops dispatch without op failure before verify; `interface_verification_status` = **observed** admin state (`interface_present_up` \| `interface_present_down` \| `interface_not_up` \| `interface_id_mismatch`; distinct from intent-matched `verification.up_ok`); **`tunnel_verification_status`** from `show interface` peer fields only (**NOT** `show rc`): `tunnel_no_peer` \| `tunnel_never_handshaked` \| `tunnel_healthy` \| `tunnel_unverified` — config accepted + interface admin up **never** imply healthy tunnel; `wireguard.status:up` / rising `txbytes` alone **NOT** healthy evidence; **`tunnel_healthy` requires non-sentinel handshake + `peer.online` yes + `rxbytes > 0` — branch implemented offline, NOT yet live-device-confirmed (2026-07-31)**; `overall=applied` compat = sealed ops ok + readback intent match (`id_ok∧up_ok`, where `up_ok` matches requested `enabled` — not necessarily interface up); secret/peer ops planner `verification_status=pending_live_verification`; nested_rci peer write device-verified accepted 2026-07-24; 16-arg ASC returns `unsupported_pending_verification`; `enabled` maps to generic sealed `interface up|down`; live path reuses `open_wifi_live_session`; see [`OPERATOR_AWG_APPLY.md`](../OPERATOR_AWG_APPLY.md). **TrafficDiscovery** (2026-07-24): proposals-only offline surface; observations store digest + metadata only (`evidence_json` and `proposal_json` remain null); `create_proposal` always sets `auto_apply_blocked=true` and `status=Proposed`; no apply/auto-apply HTTP endpoint; service `try_auto_apply` remains internal and always blocked.

---

## 7. Resource DTOs (vendor-neutral)

### 7.1 Feature status — `GET /status`

**Response 200:**

| Field | Type | Notes |
|---|---|---|
| `feature_state` | enum | `Disabled \| Starting \| Ready \| Degraded` — **`SecurityBlocked` is not returned on 200**; when admin password is empty and feature enabled, §2.1 returns **503** before handler with `security.configuration_blocked` (observable via error body / `feature_state` in error `details` when present) |
| `hub_available` | boolean | Hub listener up (always true if response returned) |
| `database_state` | enum | `Ok \| Degraded \| Unavailable` |
| `worker_state` | enum | `Stopped \| Starting \| Running \| Stopping \| Degraded` |
| `worker_heartbeat_at` | string \| null | ISO8601 UTC last successful lease renew (redacted observability) |
| `worker_last_error` | string \| null | Redacted last worker error summary (no secrets) |
| `routers_summary` | object | `{ "total": 0, "enrolled": 0, "degraded": 0 }` — redacted counts |
| `default_site_id` | string | Prototype host: resolved site for commissioning/preset UI (host state → first router → bootstrap lab site) |
| `write_gates` | object | Fail-closed summary `{ blocked: boolean, write_certified: boolean, reason: string, gate_b: string }` — UI must treat missing/`blocked=true` as write-forbidden |
| `gate_a` | object \| absent | When Gate A certification loaded: `{ status, certification, … }` from sanitized cert payload |
| `gates` | object \| absent | When Gate A loaded: `{ A, B, C, D }` gate states (`B` closed until WriteCertified) |
| `links` | object | Optional HAL-style links when `Ready`/`Degraded` (e.g. `routers`) |

No secrets, internal paths, or raw exception strings.

### 7.2 Router inventory

**`RouterSummary` (list item):**

| Field | Type | Notes |
|---|---|---|
| `router_id` | string | |
| `display_name` | string | |
| `vendor`, `model` | string | |
| `lifecycle_status` | enum | `PendingEnrollment \| Enrolled \| IdentityMismatch \| Disabled` |
| `certification_status` | enum | Aggregate from latest capability |
| `updated_at` | timestamp | |

**`RouterDetail` extends summary:**

| Field | Type | Notes |
|---|---|---|
| `site_id` | string | |
| `hardware_revision` | string? | |
| `identity_fingerprint` | string | Redacted digest, not raw serial |
| `endpoints` | array | `{ endpoint_id, kind, host, port, is_enabled, priority }` — host is locator, not identity |
| `current_desired_revision_id` | string? | |
| `applied_revision_id` | string? | |
| `reconcile_status` | enum | `Converged \| Pending \| Drifted \| Unknown \| Failed \| RecoveryRequired` |

**`POST /routers` (enroll) request:**

| Field | Type | Required | Validation |
|---|---|---|---|
| `site_id` | string | yes | Existing site |
| `display_name` | string | yes | 1–128 chars |
| `vendor`, `model` | string | yes | |
| `hardware_revision` | string | no | |
| `endpoint` | object | yes | `{ kind, host, port, source_address? }` — placeholder host only in docs |
| `endpoint.source_address` | string | live/ssh_tunnel: yes; fake: optional | Private unicast literal for outbound TCP bind on dual-homed labs; validated and bound before vault/network |
| `management_password` | string | fake: yes; live: one of password or ref | **Write-only**; stored via vault; **never** returned |
| `credential_ref_id` | string | live optional | Existing DPAPI `CredentialRef` from operator CLI; mutually exclusive with `management_password`; **never** returned |

**Live enroll credential policy:** When `RC_ADAPTER_MODE=live`, request **must** supply exactly one of `management_password` (inline enroll) or `credential_ref_id` (pre-stored DPAPI ref from operator workflow). Fake adapter mode requires `management_password` only.

**Response 202 (non-live / L2 fake adapter):** `OperationAccepted` (§9.1) — SQLite enrollment intent persisted; **no** live observe dispatch. **Response 403 (live adapter, Gate A closed):** `gate.a_closed` **before** live adapter dispatch — **must not** claim live observe succeeded (§10.1).

**`POST .../preflight` request:** optional `{ "observation_ttl_seconds": 300, "source_address": "<private-unicast>" }` — `source_address` required when `RC_ADAPTER_MODE=live` or enrolled endpoint uses `ssh_tunnel`; must match stored endpoint when present.

**Response 202 (non-live / L2 fake adapter):** `OperationAccepted` — SQLite preflight intent persisted without live observe. **Response 403 (live adapter, Gate A closed):** `gate.a_closed` **before** live adapter dispatch (§10.1).

### 7.3 VPN profiles (AWG)

**`POST /vpn-profiles/import` request:**

| Field | Type | Required | Validation |
|---|---|---|---|
| `display_name` | string | yes | |
| `vpn_kind` | string | yes | Must be `AmneziaWG` in v1 |
| `profile_document` | object | yes | Vendor-neutral normalized import shape; **no** raw `.conf` echo in response |
| `private_key` | string | conditional | **Write-only**; stored as `CredentialRef`; never returned |
| `preshared_key` | string | no | Write-only |

**`POST /vpn-profiles/parse-preview` request:**

| Field | Type | Required | Validation |
|---|---|---|---|
| `profile_text` | string | yes | Raw AmneziaWG `.conf` text; **write-only** — never echoed in response |

**`POST /vpn-profiles/parse-preview` response:** same sanitized shape as CLI stdout per file (`interface_field_names`, `peer_field_names`, `credential_refs` with `role`/`credential_ref_id`/`kind`, `endpoint_configured`, `awg_param_names`, `profile_digest`, optional `peer_public_key`/`peer_endpoint`/`peer_allow_ips`/`peer_keepalive_interval`/`interface_address`). When dual-stack `AllowedIPs` includes IPv6 routes, response also includes **`unsupported_fields`** (field names only, e.g. `["AllowedIPs"]`) and **`operator_notes`** (human-readable, e.g. IPv6 routes not applied). Secrets stored in vault during parse; no key values, endpoint host, Address, or raw conf in body.

**Dual-stack `AllowedIPs` (soft drop):** Standard operator profiles with `AllowedIPs = 0.0.0.0/0, ::/0` parse successfully. **`peer_allow_ips`** carries IPv4 entries only (comma-separated, order preserved). Dropped IPv6 is reported via **`unsupported_fields=["AllowedIPs"]`** and **`operator_notes`**: `Маршруты IPv6 из профиля не применены. Туннель работает только по IPv4.` **`validation_status` remains `Valid`** on import (hub treats `UnsupportedFields` as hard failure). IPv6-only or no usable IPv4 → **422** `profile.validation_failed` with field **`AllowedIPs`**; never silently defaults to `0.0.0.0/0`.

**`VpnProfileDetail` response:**

| Field | Type | Notes |
|---|---|---|
| `profile_id` | string | |
| `display_name`, `vpn_kind` | string | |
| `parser_version` | string | |
| `content_digest` | string | |
| `validation_status` | enum | `Pending \| Valid \| Invalid \| UnsupportedFields` |
| `unsupported_fields` | string[] | Redacted field names only (e.g. `AllowedIPs` when IPv6 routes soft-dropped) |
| `operator_notes` | string[] | Optional human-readable notes synthesized when `unsupported_fields` includes `AllowedIPs` (IPv6 soft-drop) |
| `credential_refs` | array | `{ credential_ref_id, role, kind }` — metadata only |
| `wireguard_intent_fields` | object? | Non-secret apply fields from import metadata |
| `created_at`, `superseded_at` | timestamp? | |

**`POST .../validate`:** empty body or `{ "parser_version": "…" }`; returns updated `VpnProfileDetail`.

### 7.4 Desired revision

**`GET .../desired-revision` response 200:**

| Field | Type | Notes |
|---|---|---|
| `revision_id`, `router_id` | string | |
| `revision_number` | integer | Monotonic per router |
| `canonical_digest` | string | |
| `etag` | string | Same as `ETag` header |
| `based_on_observation_id` | string? | |
| `assignments` | array | `{ assignment_id, profile_id, logical_role, desired_active }` |
| `created_at` | timestamp | |
| `desired_document` | object | Redacted vendor-neutral desired blob |

**`PUT .../desired-revision` request:**

| Field | Type | Required | Validation |
|---|---|---|---|
| `based_on_observation_id` | string | yes | Must reference fresh observation |
| `assignments` | array | yes | AWG assignment intents; max one active per policy v1 |
| `reason` | string | no | Redacted operator reason |

**Headers:** `If-Match` **required** (current desired ETag). **Response 200:** new revision body + new `ETag`. **412** if stale.

Creates new immutable revision in SQLite only ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §3.1); **does not** dispatch router apply.

### 7.5 Credentials

**`CredentialMetadata` (GET):**

| Field | Type | Notes |
|---|---|---|
| `credential_ref_id` | string | |
| `kind` | enum | See [`SECURITY_OPS.md`](SECURITY_OPS.md) §4 |
| `provider` | string | e.g. `DPAPI.CurrentUser` |
| `created_at`, `rotated_at`, `revoked_at` | timestamp? | |

**Forbidden on GET:** password, private key, session token, provider locator plaintext.

**`PUT .../credentials` request:**

| Field | Type | Required |
|---|---|---|
| `kind` | enum | yes |
| `secret` | string | yes — **write-only** |

**Response 201:** `{ "credential_ref_id": "…", "kind": "…", "created_at": "…" }` — subject to §4.3 idempotency replay.

**`POST .../credentials/{credential_ref_id}/rotate` request:**

| Field | Type | Required | Validation |
|---|---|---|---|
| `secret` | string | yes | **Write-only** new secret material |

**Headers:** `Idempotency-Key` **required** (§4.3).

**Response 202:** `OperationAccepted` (§9.1) with `operation_kind: rotate_credential` — rotate job runs vault update and optional router verify per gates.

**`POST .../credentials/{credential_ref_id}/revoke` request:** empty body or optional `{ "reason": "…" }` (redacted operator reason).

**Headers:** `Idempotency-Key` **required** (§4.3).

**Response 202:** `OperationAccepted` (§9.1) with `operation_kind: revoke_credential` — marks ref revoked and blocks new jobs referencing it; in-flight jobs fail closed or complete verify per [`SECURITY_OPS.md`](SECURITY_OPS.md) §4.

### 7.6 Change plan

**`POST .../plans` request:**

| Field | Type | Required |
|---|---|---|
| `revision_id` | string | yes — must match current desired |
| `observation_id` | string | yes — fresh observation |

**Headers:** `If-Match` = desired revision ETag.

**Response 201:** `ChangePlanDetail`:

| Field | Type | Notes |
|---|---|---|
| `plan_id`, `router_id`, `revision_id`, `observation_id` | string | |
| `plan_digest` | string | Confirm binding |
| `confirmation_state` | enum | `Draft` initially |
| `expires_at` | timestamp | |
| `risk_class` | enum | e.g. `Low \| Medium \| High` |
| `requires_backup`, `requires_fail_safe` | boolean | |
| `changes` | array | Ordered `{ ordinal, change_kind, summary, target_resource_id? }` — **no** raw RCI; `summary` is redacted from `intent_kind` + `ownership_action` only (never `intent_json` payload) |
| `etag` | string | Plan ETag for Confirm |

**`POST .../plans/{plan_id}/confirm` request:**

| Field | Type | Required |
|---|---|---|
| `plan_digest` | string | yes — must match stored plan |
| `risk_acknowledged` | boolean | yes — must be `true` |

**Headers:** `If-Match` **must** equal plan ETag (quoted strong validator from `plan_digest` + plan row version).

Confirm binds actor session ([§8](#8-plan-confirm-binding-rules)); **does not** re-authenticate password.

**Response 200:** updated plan with `confirmation_state: Confirmed`, `confirmed_at`. Apply is **not** auto-enqueued — client **must** call **`POST .../plans/{plan_id}/apply`** (§6) to start dispatch.

**`POST .../plans/{plan_id}/apply` request:** empty body.

**Headers:** `Idempotency-Key` **required**; `If-Match` **must** equal plan ETag (same validator as Confirm).

**Preconditions:** plan `confirmation_state` **must** be `Confirmed`; plan unexpired; linked `revision_id`, `observation_id`, and observation ETag/digest still current (§8); desired pointer unchanged.

**Response 202:** `OperationAccepted` (§9.1) with `operation_kind: apply_plan`, `plan_id` set — enqueue apply job; §10 gate evaluation runs before live adapter dispatch. **403** `gate.mutation_forbidden` / **412** / **409** when preconditions or gates fail at accept time. Replay per §4.3 on duplicate `Idempotency-Key` + digest.

### 7.7 Operation and job

**`OperationDetail`:**

| Field | Type | Notes |
|---|---|---|
| `operation_id`, `router_id` | string | |
| `operation_kind` | string | e.g. `enroll`, `preflight`, `apply_plan`, `rotate_credential` |
| `aggregate_status` | enum | `Pending \| Planning \| Applying \| Verifying \| Converged \| Drifted \| Failed \| RecoveryRequired` |
| `plan_id` | string? | |
| `created_at`, `updated_at`, `terminal_at` | timestamp? | |
| `jobs` | link | URI to `/operations/{id}/jobs` |

**`JobDetail`:**

| Field | Type | Notes |
|---|---|---|
| `job_id`, `operation_id`, `router_id` | string | |
| `attempt` | integer | |
| `status` | enum | `Queued \| Leased \| Running \| Succeeded \| Failed \| Cancelled \| Lost \| RecoveryRequired` |
| `cancel_requested` | boolean | |
| `steps` | array | `{ step_id, ordinal, step_kind, status, error_redacted? }` |
| `started_at`, `finished_at` | timestamp? | |

Step kinds align with [`RCI_POLICY.md`](RCI_POLICY.md) §5; step payloads in API are **redacted** — no raw RCI.

### 7.8 Wi-Fi observed state — `POST /wifi/observed-state`

Read-only observed Wi-Fi AP reality for operators. **Non-certifying** (always `certification_eligible: false`; `offline_verified_only: true`). Never returns PSK or key material.

**Live path (win32 + complete connection params):** reuses the same per-request pinned SSH session as Wi-Fi apply (`open_wifi_live_session`); **requires open Gate A**; **no** `confirm_live_apply`, **no** startup-config backup, **no** writes. Incomplete params → **422** `wifi.live_connection_incomplete` naming missing fields; complete params on non-win32 → **503** `wifi.live_platform_unsupported`; `RC_ADAPTER_MODE=live` without params → **422** `wifi.live_connection_required`; Gate A closed → **503** `wifi.gate_a_required`. Live transport faults: **422** `wifi.ssh_host_key_mismatch` (fail-closed); **404** `wifi.credential_not_found` / **400** `wifi.credential_unusable` (message includes `router_credential_ref_id=<id>`; no secret/path); **503** `wifi.live_transport_failed` for timeout/unreachable/generic tunnel errors.

**Fake/offline path:** injected transport factory or default fake when `adapter_mode=fake` and no live connection params.

**Request body (`extra=forbid`):**

| Field | Type | Notes |
|---|---|---|
| `ap_ids` | string[]? | Allowlisted test AP ids; defaults to lab-class AP range when omitted |
| `desired` | object? | Optional `WifiIntent` subset: `ssid`, `enabled`, `wpa_mode`, `band` — for per-field compare |
| `desired_ap_id` | string? | Required when `desired` supplied (unless single `ap_ids` entry) |
| `host` | string? | Live management target (same contract as Wi-Fi apply) |
| `username` | string? | Router management username |
| `router_credential_ref_id` | string? | Vault ref for router password (resolved at session open only) |
| `credential_ref_id` | string? | Legacy alias for `router_credential_ref_id` when latter absent |
| `ssh_host_key_sha256` | string? | Pinned SSH host-key fingerprint (`SHA256:…`) |
| `source_address` | string? | Optional outbound bind address (dual-NIC lab) |
| `router_id` | string? | Optional store-backed host-key pin resolution |
| `allow_insecure_http` | boolean? | Reserved; not used on live SSH path |

**Response 200 — `ObservedWifiStateReport`:**

| Field | Type | Notes |
|---|---|---|
| `access_points` | array | Per AP: `ap_id`, `band` (`2.4GHz` \| `5GHz` \| `unknown`), `ssid`, `enabled_or_up`, `link_up` (bool \| null — from device `link` only via shared `resolve_link_up` → `parse_up_down_flag`: `up`/`down`, `enabled`/`disabled`, `true`/`false`, string `"1"`/`"0"`; bare int/other/empty → null; **never** `yes`/`no`/`on`/`off`; **never** from `broadcast`/`connected`/`state`), `device_connected` (bool \| null — opaque device flag via same up/down parser on `connected`; **not** on-air), `wpa_mode` (`WPA2` \| `WPA3` \| `WPA2_WPA3_MIXED` \| `not_configured` \| `unrecognized` \| `unknown`), `encryption_raw` (string \| object \| null — scrubbed raw device encryption; same scrubber shape as site-survey), `key_configured` (bool \| null — never secret value), `readable` |
| `comparisons` | object? | Per AP: per-field `match` \| `differs` \| `unknown` for `ssid`, `wpa_mode`, `enabled`, `band`; missing observed never false-matches |
| `certification_eligible` | boolean | **Always `false`** |
| `transport_security` | string | e.g. `fixture` (offline fake) or `ssh_tunnel_pinned` (live read-only session) |
| `https_check` | string | e.g. `not_certified` |
| `offline_verified_only` | boolean | **Always `true`** in v0 |

**Honesty:** unreadable AP → `readable: false` and comparison fields `unknown` (not fabricated defaults). Device `connected` is **not** broadcasting/on-air — use `link_up` for wire link from `link` only. Apply/teardown on-air verdicts use `resolve_on_air_signal`: same `link` rule (`parse_up_down_flag`) plus `parse_broadcast_flag` on `broadcast`/`broadcasting`; fail-closed when they contradict. **`overall=applied`** on apply means configuration verify passed (SSID/encryption/admin up) — link/broadcast conflict yields `on_air_unverified` without changing `overall` (distinct from `on_air_admin_only` → `verify_mismatch`). `not_configured` / `unrecognized` / `unknown` wpa_mode never false-match desired real modes. Sanitizer drops `psk`/`passphrase`/key material structurally.

**Live-found lesson (2026-07-31):** certified lab router validation surfaced torn-down APs reporting `connected: true` with `link: down` and misleading HTTP error classification — offline fixtures alone did not catch this class; keep RO live smoke in validation playbook.

### 7.8a Wi-Fi site-survey — `POST /wifi/site-survey`

Read-only neighbour scan for venue SSID selection. **Non-certifying** (always `certification_eligible: false`; `offline_verified_only: true`).

**Transport shapes:** live `execute_rci_parse` returns RCI JSON `[{"parse":{"ap_cell":[…],"prompt":"…"}}]` with per-row `encryption` / `encryption-mode` when present. Tabular CLI text (columns **SSID \| MAC \| Ch \| Mode \| Q**) remains supported as fallback when payload is not `parse`-shaped — tabular rows have **no security column** (`per_network_security_present: false` on that path).

**Key mapping (RCI `ap_cell` row):** `essid`→`ssid` (empty `essid` → `hidden: true`); `address`→`bssid`; `channel`→`channel`; `quality`→`signal_quality`; **`ieee`→`mode`** (PHY string — do **not** use device `mode` key, which is BSS role); optional `rssi`, `bandwidth`; `encryption` / `encryption-mode`→per-row `encryption_raw` + `wpa_mode`.

**Per-row `wpa_mode` (site-survey, authoritative):** `WPA2` \| `WPA3` \| `WPA2_WPA3_MIXED` \| **`open`** (clear disabled/none encryption — live shape `encryption: disabled` + `encryption-mode: none`) \| `unrecognized` (present but unmappable — never coerced to WPA or open) \| `unknown` (encryption fields absent on row). Observed-state AP config uses `not_configured` for empty AP encryption instead of `open`; site-survey neighbours emit `open` when RCI clearly indicates no encryption.

**`encryption_raw` shape (site-survey and observed-state):** `string` \| `object` \| `null`. Scrubbed via the same helper (`scrub_encryption_value`): scalar encryption strings, or object e.g. `{"encryption":"disabled","encryption-mode":"none"}` when both RCI keys present. Never contains secrets.

**Commands issued (only):** `show site-survey WifiMaster0`, `show site-survey WifiMaster1`.

**Live-found defects (2026-07-31):** (1) live open networks (`encryption: disabled`, `encryption-mode: none`) were misclassified as `unrecognized`; (2) `security_type_known: true` + always-null `security_type` removed — use `per_network_security_present`; (3) `encryption_raw` object shape documented.

**Live-found lesson (2026-07-31):** parser was built against tabular CLI text while live transport returns RCI JSON — a read-path blind spot; offline fixtures must include both shapes.

**Live path (win32 + complete connection params):** reuses `open_wifi_live_session`; **requires open Gate A**; read-only (no writes). Incomplete params → **422** `wifi.live_connection_incomplete`; complete params on non-win32 → **503** `wifi.live_platform_unsupported`; `RC_ADAPTER_MODE=live` without params → **503** `wifi.live_connection_required`; Gate A closed → **503** `wifi.gate_a_required`. Same live transport error matrix as §7.8 (host-key mismatch, credential, transport failed).

**Fake/offline path:** default fake transport with synthetic fixtures when `adapter_mode=fake` and no live connection params.

**Request body (`extra=forbid`):**

| Field | Type | Notes |
|---|---|---|
| `radio` | enum | **`WifiMaster0`** \| **`WifiMaster1`** only (never passthrough string) |
| `host` | string? | Live management target (same contract as Wi-Fi observed-state) |
| `username` | string? | Router management username |
| `router_credential_ref_id` | string? | Vault ref for router password (resolved at session open only) |
| `credential_ref_id` | string? | Legacy alias for `router_credential_ref_id` when latter absent |
| `ssh_host_key_sha256` | string? | Pinned SSH host-key fingerprint (`SHA256:…`) |
| `source_address` | string? | Optional outbound bind address |
| `router_id` | string? | Optional store-backed host-key pin resolution |
| `allow_insecure_http` | boolean? | Reserved; not used on live SSH path |

**Response 200 — `SiteSurveyReport`:**

| Field | Type | Notes |
|---|---|---|
| `radio` | string | `WifiMaster0` or `WifiMaster1` |
| `command` | string | Exact CLI issued |
| `networks` | array | Per row: `ssid`, `bssid`, `channel`, `mode`, `signal_quality`, `hidden`, `wpa_mode` (`open` \| WPA modes \| `unrecognized` \| `unknown`); optional `rssi`, `bandwidth`, `encryption_raw` (`string` \| `object` \| null — scrubbed) when RCI path |
| `network_count` | integer | Count only (for logging/telemetry without row payloads) |
| `skipped_row_count` | integer | Rows skipped due to per-row parse errors (good rows retained) |
| `per_network_security_present` | boolean | **`true`** when ≥1 successfully parsed RCI row had `encryption` and/or `encryption-mode` present (per-network data in payload — **not** a global security type); **`false`** for tabular fallback, empty/malformed `ap_cell`, or all rows lacking encryption fields |
| `findings` | string[] | e.g. `site_survey_empty`, `site_survey_malformed`, `site_survey_rows_skipped` |
| `certification_eligible` | boolean | **Always `false`** |
| `transport_security` | string | e.g. `fixture` or `ssh_tunnel_pinned` |
| `offline_verified_only` | boolean | **Always `true`** in v0 |

**Privacy:** API may return neighbour `ssid`/`bssid` to authenticated operator; do **not** log row payloads server-side (counts/findings only); repo fixtures must use synthetic names/MACs only.

### 7.9 Bootstrap discovery — `POST /lab/bootstrap-discovery`

Read-only, **non-certifying** bootstrap observe for Add-router wizard. Works while Gate **A** is closed/stale. Plain HTTP never certifies Gate A.

**Request body (`extra=forbid`):**

| Field | Type | Notes |
|---|---|---|
| `host` | string | Management target (`http://192.168.x.x` or `https://…`); private hosts only |
| `username` | string | Router management username |
| `credential_ref_id` | string | Vault ref only — **no** `password` / `management_password` fields |
| `allow_insecure_http` | boolean | Must be `true` for `http://` targets |

**Response 200 — `BootstrapDiscoveryReport`:**

| Field | Type | Notes |
|---|---|---|
| `certification_eligible` | boolean | **Always `false`** |
| `transport_security` | string | e.g. `insecure_http`, `https` |
| `https_check` | string | Always `not_certified` on plain HTTP |
| `model` | string? | Sanitized identity model (RCI `hw_id` when observed) |
| `firmware_version` | string? | Raw firmware string from components — not display title |
| `firmware_digest` | string? | Digest only |
| `fingerprint_digest` | string? | Digest only |
| `component_set_digest` | string? | Digest only |
| `ssh_component_installed` | boolean? | `null` when components shape unknown or inventory unavailable |
| `ssh_component_determination` | object | How `ssh_component_installed` was derived: `{ "lookup": "component.ssh", "matched": bool, "outcome": "matched_true" \| "matched_false" \| "key_absent" \| "shape_unusable" \| "inventory_unavailable", "determination_shape"?: "explicit_installed" \| "presence_in_map" }`. **`determination_shape`** present when outcome is `matched_true` or `matched_false`. **`presence_in_map`**: `ssh` key present in component map without `installed` field → installed. **`explicit_installed`**: `installed` boolean read directly. Empty/unavailable inventory → `inventory_unavailable` (not `key_absent`) |
| `components_inventory` | object | Sanitized capped component list from `components.component` map: `{ "entries": [{ "id", "installed"?, "version"?, "available"? }], "total_observed": int, "truncated": bool, "source_shape": "component_map" \| "empty" \| "unavailable" }`. Cap **64** entries (sorted keys); `truncated=true` iff pre-cap count > 64. When truncated and `ssh` is present in the full map, the **`ssh` entry is force-included** in `entries` (replacing the last sorted slot). **`version`** emitted only for tight version-token pattern (e.g. `2022.82-7`, `0-5617eb4`); free-text vendor fields never echoed. Unrecognized vendor meta keys never echoed |
| `ssh_access_enabled` | boolean? | Defensive parse of `/rci/ip/ssh`; `null` when unknown |
| `management_http` | object? | Sanitized summary from GET `/rci/ip/http`; absent when shape unknown or read 404. Supports flat (`port`, `security-level` string, `listen`) and nested (`security-level` object with `private`/`public`/`disabled`, e.g. firmware 4.03) shapes. Subfields (when present): `port` (integer), `security_level` (`private` \| `public` \| `disabled`), optional `listen` (boolean). **No** passwords, hostnames, or session material |
| `wifi_access_points` | array | Hashed interface ids; link/role flags; **no** MAC/SSID/PSK |
| `findings` | string[] | Fixed vocabulary: `ssh_component_missing`, `ssh_disabled`, `ssh_state_unknown`, `firmware_below_verified_baseline`, `wifi_inventory_unavailable`, `component_change_triggers_firmware_upgrade`, `update_channel_not_stable`, `firmware_major_version_jump`, `components_listing_timeout`, `components_inventory_unavailable`, `update_channel_unknown`. **`ssh_component_missing`** only when inventory is usable (non-empty `component_map`) and SSH not installed; **`components_inventory_unavailable`** when listing timeout or inventory shape empty/unavailable — distinct from SSH absent on a present inventory |
| `sandbox` | string? | Raw update sandbox from final `components/list` payload when present (e.g. `stable`, `preview`) |
| `update_channel` | string? | Sanitized operator channel label; `stable` → `Main` (consistent with identity); other known sandboxes pass through sanitized; absent when sandbox unknown |
| `channel_firmware_version` | string? | Target/offered firmware on the update channel from final listing `firmware.version` **only when present** — never fabricated |
| `component_change_would_upgrade_firmware` | boolean? | `true` when installed firmware (from `show/version` when observed, else report `firmware_version`) and channel target are both known and target is newer; `false` when equal/lower; `null` if either unknown |
| `component_change_crosses_major_version` | boolean? | `true` when both firmware strings known and first numeric major segments differ (e.g. 4 vs 5), independent of upgrade direction; `false` when majors match; `null` if either unknown |
| `update_channel_is_stable` | boolean? | `true` iff sandbox is exactly `stable` (case-normalized); `false` for `preview`/`draft`/`dev` and other non-stable sandboxes; `null` when sandbox unknown |
| `component_change_side_effects` | object | **Informational only** — not a write trigger: `{ "firmware_rebuild": true, "automatic_reboot": true, "management_downtime": true, "firmware_version_changes": bool \| null }`. Process effects (`firmware_rebuild`, `automatic_reboot`, `management_downtime`) are **always true** when discussing component install (vendor rebuild+reboot semantics). `firmware_version_changes` is derived separately from `component_change_would_upgrade_firmware`: when both installed and channel firmware keys are known, `true` iff channel key **≠** installed key (includes downgrade), `false` when equal, `null` when either unknown — **rebuild ≠ version change**; upgrade direction remains strict `>` on `component_change_would_upgrade_firmware` |

**Components list continued polling (bootstrap-only):** `POST /rci/components/list` with `{}` once; while response has `"continued": true`, poll **GET** `/rci/components/list` (bootstrap allowlist only — **not** Gate A frozen four-read). Bounded by `MAX_CONTINUATION_ROUNDS` (5) and transport `continuation_budget_seconds` (default 30s). Gate A path continues to use POST-only continuation — bootstrap does **not** re-POST for continued responses.

**Non-certifying:** response always has `certification_eligible: false`; bootstrap discovery does **not** open Gate A, certify plain HTTP, or authorize writes. **No** `components install`, `components commit`, or SSH enable APIs in v0.

**Per-read resilience:** allowlisted optional management reads (`GET /rci/ip/ssh`, `GET /rci/ip/http`) that indicate feature or component absence (HTTP **404**) degrade to structured findings and unknown/null fields; the report still returns **200**. **`components/list` continuation budget exceed** → finding `components_listing_timeout`; channel/sandbox/target fields `null`/absent; identity falls back to `show/version` when listing incomplete; report still **200** with other reads intact. Required identity reads (system, identification, version, interface) remain fail-closed on transport/auth failure when listing timeout fallback cannot parse identity. Authentication failures (**401** after retry) and transport/network failures on any read remain **422** `bootstrap.discovery_failed` — they are never masked as findings.

**Vault / adapter decoupling:** host resolves credentials via `CredentialVaultPort` independent of `RC_ADAPTER_MODE`. Injected `vault=` (tests) always wins; default host resolution uses `WindowsDpapiVault` on Windows (`data/secrets` or `secrets_root`) unless `RC_VAULT=memory` or pytest isolation applies. Fake adapter mode does **not** force `MemoryVault` when the host vault is DPAPI-backed. Credential resolution errors name `credential_ref_id` only (never secret material).

**Errors:** **422** `bootstrap.discovery_failed` on policy/transport/identity failures (no secret echo). Requires expendable lab class (`ROUTER_CONTROL_LAB_CLASS=expendable_development_router`) for plain HTTP bootstrap path.

**Live validation note (2026-07):** shapes and resilience policy validated read-only on expendable lab NC-1812 Ultra firmware `4.03.C.6.4-16`; does **not** certify device, open Gate A, or claim WriteCertified.

### 7.9.2 Router discovery — `POST /lab/router-discovery`

Bounded local enumeration for simple-mode UI. **Sibling** to bootstrap discovery — does **not** extend bootstrap allowlist or plain-HTTP bootstrap path.

**Request body (`extra=forbid`):**

| Field | Type | Default | Notes |
|---|---|---|---|
| `include_default_gateway` | boolean | `true` | Include IPv4 default gateway(s) from local host routing table as **candidates**; when `false`, default-gateway candidates are omitted but an internal default-route read still runs for local-subnet dedup — if that read **fails**, `source_diagnostics` / `degraded_sources` still report `default_gateway` and local-subnet gateway candidates that depend on dedup are suppressed (fail-closed) |
| `include_known_endpoints` | boolean | `true` | Include hosts from enrolled `router_endpoints` in SQLite |
| `preferred_source_address` | string \| null | null | Optional validated private literal bind hint |
| `probe` | boolean | `false` | When `true`, call injectable identity probe for bounded candidates only |

**Out of bounds (never probed):** free-form host lists, CIDR/subnet scans, ARP/ping sweeps, credential stuffing, any host not in the candidate set derived from the allowed sources (default gateway, local subnet first-host per interface without default route, enrolled endpoints).

**Response 200 — `RouterDiscoveryResponse`:**

| Field | Type | Notes |
|---|---|---|
| `candidates[]` | array | Per candidate: `host`, `port`, `source_address`, `source_address_class?`, `candidate_origin` (`default_gateway` \| `local_subnet_gateway` \| `known_endpoint`), optional `router_id`, `identity_state` (`known_match` \| `known_mismatch` \| `unknown`), `credentials_required`, `writes_allowed`, `reason_code`, optional `facts` when probed |
| `excluded_candidates[]` | array | Soft-excluded hosts: `host`, optional `port`, optional `candidate_origin`, `reason_code` (`non_private_management_address`, `loopback_not_management_candidate`, …) — never probed |
| `bounds` | object | Machine-readable bound description (`subnet_scan: false`, `free_form_hosts: false`, …) |
| `certification_eligible` | boolean | **Always `false`** |
| `probed_hosts` | array | Audit list of hosts actually contacted when `probe=true` |
| `source_diagnostics[]` | array | Per host-route source: `source` (`default_gateway` \| `local_subnet_gateway`), `status` (`ok` \| `empty` \| `failed`), optional structural `reason_code` (`timeout`, `os_error`, `unicode_decode`, `json_decode`, `nonzero_exit`) — never raw stdout or exception text |
| `degraded_sources[]` | array | Source names with `status: failed` in `source_diagnostics`; includes `default_gateway` when the internal default-route read failed even if `include_default_gateway` is `false` |

**Identity (`probe=false`):** classify from local enrolled facts + Gate A tuple/pin when present; local enrollment+pin match returns `unknown` / `enrollment_match_identity_unverified` — **`known_match` only after successful live probe** (`probe=true`, `probe_tuple_match`). Never invent probe success.

**Soft exclusion:** public default-gateway NextHop and loopback (`127.0.0.1` / `::1`) are listed in `excluded_candidates[]` (not `candidates[]`); remaining private candidates still return HTTP 200. Public/loopback addresses are never probed.

**Incomplete probe evidence:** partial probe tuple → `unknown` / `probe_evidence_incomplete` (not `known_mismatch`); complete mismatched tuple → `known_mismatch` / `probe_tuple_mismatch`.

**Host wiring:** On Windows the hub reads IPv4 default gateway(s) from the local routing table (`Get-NetRoute`) and active IPv4 interfaces from `Get-NetIPConfiguration` (Up adapters; skips APIPA/loopback). OS query failures return empty candidate sets but **HTTP 200** with `source_diagnostics` / `degraded_sources` reporting failed sources (fail-soft, honest diagnostics). Non-Windows hosts omit gateway and local-subnet candidates unless injected in tests.

**Probe eligibility (`probe=true`):** identity probe runs only when the candidate has resolvable credentials **and** a stored SSH host-key pin or Gate A pin; unenrolled `default_gateway` and `local_subnet_gateway` candidates are skipped (remain `identity_state: unknown`). **Live host:** soft identity probe wired when Gate A open (`build_soft_candidate_identity_probe` over health probe).

**Errors:** **422** `router_discovery.failed` on policy failure or `probe not configured` when `probe=true` without injected probe port.

### 7.9.3 Connection health — `POST /lab/connection-health`

Read-only aggregate health for a known router endpoint. **Green** only when **all** of `reachable`, `host_key_match`, `tuple_match`, `credentials_present`, `evidence_fresh` are **`true`** — null never counts as healthy.

**Request body (`extra=forbid`):**

| Field | Type | Default | Notes |
|---|---|---|---|
| `router_id` | string \| null | null | Preferred resolver; endpoint host taken from store when set |
| `host` | string \| null | null | Must match enrolled endpoint unless `router_id` provided |
| `source_address` | string \| null | null | Optional validated private literal bind |
| `credential_ref_id` | string \| null | null | Vault ref only — never echoes secret |
| `ssh_host_key_sha256` | string \| null | null | Optional override; store pin preferred when absent |
| `probe` | boolean | `true` | Injectable reachability + tuple probe |

**Response 200 — `ConnectionHealthResponse`:**

| Field | Type | Notes |
|---|---|---|
| `status` | enum | `green` \| `yellow` \| `red` |
| `reason_code` | string | Machine-readable aggregate reason |
| `facts` | object | `{ reachable, host_key_match, tuple_match, credentials_present, evidence_fresh }` each `bool` \| `null` |
| `writes_allowed` | boolean | **Always `false`** on this endpoint |
| `certification_eligible` | boolean | **Always `false`** |
| `host`, `port`, `router_id`, `source_address` | various | Resolved target context (no secrets) |

**Status rules:** **red** for unreachable, host-key mismatch, identity/tuple mismatch, or missing credentials; **yellow** for reachable but stale evidence or unknown/null required facts (including `reachability_unknown` when probe port unavailable in fake/offline mode); **green** only when all five facts are true.

**Host wiring:** Live mode with open Gate A wires a soft SSH health probe (`reachable` + sanitized `evidence`); fake/offline mode leaves probe absent — default `probe=true` returns **200** with yellow `reachability_unknown`, not **422**.

**Errors:** **422** `connection_health.failed` when target cannot be resolved or policy validation fails (e.g. invalid `source_address`); not when probe port is absent.

### 7.9.1 Wizard draft router — `POST /lab/wizard-draft-router`

Thin glue for Add-router wizard: creates vault credential + SQLite router row **without** live identity probe or Gate A. Works while Gate **A** is closed/stale. **No device writes.**

**Request body (`extra=forbid`):**

| Field | Type | Notes |
|---|---|---|
| `host` | string | Management target (hostname or URL) |
| `username` | string | Router management username (stored in response metadata only) |
| `secret` | string | One-shot management password → vault; **not** `management_password` |
| `display_name` | string? | Optional label; default `Router at {host}` |
| `port` | integer? | Optional endpoint port |
| `allow_insecure_http` | boolean | Default `false`; influences endpoint kind metadata |

**Headers:** `Idempotency-Key` required (same semantics as enroll).

**Response 201:**

| Field | Type | Notes |
|---|---|---|
| `router_id` | string | Draft router row |
| `credential_ref_id` | string | Vault ref for bootstrap discovery |
| `username` | string | Echo of request username |
| `certification_eligible` | boolean | **Always `false`** |
| `certification_status` | string | `NotCertified` |
| `gate_a_status` | string | `closed` |
| `lifecycle_status` | string | `PendingEnrollment` |
| `handoff_note` | string | Honest limits — not ready for Wi‑Fi management |
| `operation_id` | string | Durable operation record |
| `links` | object | Operation/job links |

**Errors:** **400** missing Idempotency-Key; **401** auth; **409** idempotency conflict; **422** validation (extra fields forbidden). Never echoes `secret`.

**Offline-verified only** — no live router enrollment or Gate A open.

### 7.10 SSH host-key learn/confirm — Add-router wizard (offline-verified)

Explicit trust-on-first-use: learn retrieves the public host key **without authentication**; confirm requires the operator to echo the exact fingerprint before persistence. **Blind `accept-new` / AutoAddPolicy is forbidden** — see [`LEGACY_MAP.md`](../LEGACY_MAP.md) and [`SECURITY_OPS.md`](SECURITY_OPS.md).

#### `POST /routers/{router_id}/ssh-host-key/learn`

**Request body (`extra=forbid`):**

| Field | Type | Notes |
|---|---|---|
| `host` | string | Private management/SSH host |
| `port` | integer? | Default `22` |
| `source_address` | string? | Optional outbound bind (dual-homed labs) |
| *(forbidden)* | — | **No** `password`, `management_password`, or credential fields |

**Response 200:**

| Field | Type | Notes |
|---|---|---|
| `fingerprint_sha256` | string | Normalized `SHA256:<digest>` (public, not secret) |
| `algorithm` | string | e.g. `ssh-ed25519` |
| `warning` | string | Operator must verify fingerprint out-of-band before confirm |

**Errors:** **404** `router.not_found`; **422** `ssh_host_key.learn_failed` on transport/policy failures. Successful learn records a **short-lived in-process pending candidate** for the router (replaced on subsequent learn).

#### `POST /routers/{router_id}/ssh-host-key/confirm`

**Requires prior learn:** confirm is rejected (**422** `ssh_host_key.invalid_pin`) when no pending learn exists for the router, or when `fingerprint_sha256` / `algorithm` do not exactly match the pending learn candidate. Successful confirm clears the pending entry.

**Request body (`extra=forbid`):**

| Field | Type | Notes |
|---|---|---|
| `fingerprint_sha256` | string | **Exact echo** of learned fingerprint |
| `algorithm` | string | Algorithm from learn step |
| `allow_overwrite` | boolean | Default `false`; when `true`, replaces differing stored pin |

**Response 200:**

| Field | Type | Notes |
|---|---|---|
| `fingerprint_sha256` | string | Pinned value |
| `algorithm` | string | |
| `pinned_at` | string | ISO8601 UTC |
| `provenance` | string | `learned_confirmed` for wizard path |

**Errors:** **404** `router.not_found`; **422** `ssh_host_key.invalid_pin`; **409** `ssh_host_key.pin_conflict` with existing vs candidate fingerprints in `details` (fingerprints are public).

**Resolution elsewhere:** live Wi-Fi/WireGuard connection params accept explicit `ssh_host_key_sha256` **or** optional `router_id` to resolve stored pin from primary endpoint — explicit param wins; both absent → fail-closed.

#### `GET /connection-context/restore-candidate`

**Auth:** cookie `hub_admin` (401 without).

**Headers (200):** `Cache-Control: no-store`, `Vary: Cookie`.

**Input:** no query/body parameters; no client-supplied host/port/URL (M-3).

**Selection (bounded SQL, one row):** among routers with a confirmed SSH pin on the binding endpoint (`get_connection_binding_endpoint` semantics), pick by tier (lower wins):

1. `live_ready` non-draft — confirmed pin, host, `management_username`, and `credential_ref_id` all present; not wizard draft (`model=PendingDiscovery` + `lifecycle_status=PendingEnrollment`).
2. `live_ready` draft.
3. confirmed pin non-draft (not `live_ready`).
4. confirmed pin draft.

**Tie-break (within tier):** `ssh_host_key_pinned_at DESC`, then `created_at ASC`, then `router_id ASC`.

**Response 200 when candidate found:** same fields as `GET /routers/{router_id}/connection-context` plus `restore_candidate: true`.

**Response 200 when no candidate:** `{ "restore_candidate": false }` only.

**Never returns:** username value, passwords, vault contents, reachability claims.

**Enumeration:** does not expose router ids beyond what an authenticated operator already receives from `GET /routers`; returns at most one selected context.

#### `GET /routers/{router_id}/connection-context`

**Auth:** cookie `hub_admin`. **404** when router missing.

**Response 200:** `router_id`, endpoint `host`/`port`/`source_address`, `credential_ref_id`, `ssh_host_key` metadata (`confirmed`, `fingerprint_sha256`, `algorithm`, `pinned_at`, `provenance`), `username_available`, `live_ready`, `missing`. Does **not** echo username or imply reachability.

#### `POST /routers/{router_id}/management-username`

**Body:** `{ "username": "<non-empty>" }`. **Response 200:** `{ "router_id", "username_available": true }` — username value **not** echoed.

**Offline-verified only (2026-07-31):** mocked transport tests; no live SSH hardware validation in this brick.

---

## 8. Plan Confirm binding rules

Confirm authorizes dispatch of an immutable `ChangePlan` ([`SECURITY_OPS.md`](SECURITY_OPS.md) §3):

| Binding | API enforcement |
|---|---|
| Plan identity | URL `plan_id` + body `plan_digest` must match stored row |
| Preconditions | `revision_id` and `observation_id` on plan still current; desired pointer unchanged |
| Observation binding | Stored observation for `observation_id` **must** still exist with matching ETag/digest; mismatch → **412** `plan.precondition_failed` (not observation_id alone) |
| Expiry | Reject if `now > expires_at` → **409** `plan.expired` |
| Actor session | Same `hub_admin` session that created plan or explicit adopt (session id tracked server-side) |
| Risk acknowledgment | `risk_acknowledged: true` required |

**If-Match / ETag:** Confirm **must** include `If-Match` matching **plan ETag only**; desired-revision ETag is **not** accepted as substitute → mismatch **412** `plan.precondition_failed`. Apply (§7.6) uses the same plan ETag validator.

Confirm is **not** password re-entry. Expired or stale plan after Confirm attempt → **409** / **412**; client must create new observation + plan.

Dispatch after Confirm still re-validates identity, observation TTL, certification, and §10 gates immediately before lease ([`RCI_POLICY.md`](RCI_POLICY.md) §6, [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §3.5).

---

## 9. Async operations, jobs, cancel

### 9.1 Accepted async response (`202`)

```json
{
  "operation_id": "op_01EXAMPLE",
  "job_id": "job_01EXAMPLE",
  "status": "Queued",
  "links": {
    "operation": "/api/router-control/v1/operations/op_01EXAMPLE",
    "job": "/api/router-control/v1/jobs/job_01EXAMPLE"
  }
}
```

Headers: `Location: …/operations/{operation_id}`, optional `Retry-After: 1`.

Poll `GET /jobs/{job_id}` until terminal status.

### 9.2 Synchronous mutations

Desired revision PUT, plan create/confirm, credential PUT, profile import/validate return **200/201** with resource body when work completes in the request thread (SQLite-only or parser-only). Each **must** commit the §6 creation bundle (`operation`, `idempotency_record`, initial `job`) per §4.3; the initial `job` **may** be immediately terminal (`Succeeded`/`Failed`) in the same transaction — sync completion is an HTTP semantic, not permission to skip durable `jobs`. Router-touching work (enroll, preflight, rotate verify leg, plan apply) returns **202** with non-terminal initial `job` and `OperationAccepted` (§9.1).

### 9.3 Cancel — `POST /jobs/{job_id}/cancel`

Sync cancel endpoint; **may** return **202** when cancel is accepted but target job cancellation is async (worker stops at safe boundary).

| Target job state | First cancel result |
|---|---|
| `Queued` | Immediate **200**, target job → `Cancelled` |
| `Leased` / `Running` | **202**, body indicates `cancel_requested: true` on target; target **not** yet `Cancelled` |
| Terminal | **409** `job.already_terminal` |

**Idempotency replay** (same `Idempotency-Key` + digest; see §4.3):

| Replay condition | HTTP |
|---|---|
| Target still `cancel_requested` or cancel in-flight | **202** — same stored outcome |
| Target reached `Cancelled` (terminal cancel success) | **200** — `Cancelled` |
| Different digest or illegal state | **409** |

Cancel **must** commit the §6 creation bundle for the cancel HTTP intent (`operation_kind: cancel_job`) including initial `job` row, **and** apply target-job transitions in the same SQLite transaction per [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §5.3. The cancel-control initial `job` is immediately terminal when the cancel HTTP outcome is final (**202** or **200**); cancel does **not** omit durable jobs. Cancel **must not** delete audit or idempotency records. Post external mutation, cancel cannot pretend mutation did not occur — worker runs verify/compensate.

**Idempotency-Key required** on cancel POST; replay semantics in §4.3 (duplicate key + digest returns the currently stored cancel HTTP outcome — **202** while target in-flight, **200** after the §5.3 required single update — without re-notifying worker or creating a second cancel operation).

### 9.4 Recovery — `POST /jobs/{job_id}/resume` / `compensate` (M4, fake-only)

When `RC_ADAPTER_MODE=fake` and `RC_ALLOW_FAKE_MUTATIONS=1`, authenticated operators may queue recovery for jobs in `RecoveryRequired` (or operations with `aggregate_status=RecoveryRequired`):

| Endpoint | Behavior |
|---|---|
| `POST .../resume` | Creates new **Queued** job attempt under **same** `operation_id` with `recovery_state=resume_after_readback`; worker runs fresh identity+read-back before continue |
| `POST .../compensate` | Same pattern with `recovery_state=compensate`; compensation after identity check |

Live adapter / closed gates → **403** `gate.mutation_forbidden`. Idempotency via dispatch payload fingerprint (same key+digest replays queued job). **Must not** mint new `operation_id`.

---

## 10. Mutation and observe gate evaluation (fail-closed)

### 10.1 Live observe (Gate A)

Before scheduling any **live RCI observe** leg (enroll identity/observe job, preflight observe, inventory refresh that touches router transport), application **must** evaluate:

1. **HTTP/feature** — not `SecurityBlocked`/`Degraded`; valid `hub_admin` (§2).
2. **Gate A** — router transport read-only certification open for exact identity/firmware/capability tuple ([`HARDWARE_GATES.md`](HARDWARE_GATES.md)).

If Gate **A** is closed **and** the request would dispatch a **live** adapter observe leg, API **must** return **403** `gate.a_closed` **before** live adapter dispatch. **`Ready` + authenticated session does not suffice.**

When implementation selects **non-live** adapter mode (L2 fake / recorded fixtures; no production router I/O), `POST /routers` and `POST .../preflight` **may** return **202** `OperationAccepted` and persist SQLite enrollment/preflight intent **without** live observe — this is **not** a successful live observe and **must not** be reported as Gate A satisfied.

### 10.2 Router write dispatch

Before any router **write** dispatch (apply step, rotate triggering live verify, etc.), application **must** evaluate in order:

1. **HTTP/feature** — not `SecurityBlocked`/`Degraded`; valid `hub_admin` (§2).
2. **Identity** — enrolled fingerprint matches live read ([`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) Router).
3. **Fresh observation** — `now <= valid_until`, `collection_status = Succeeded` ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §3.3).
4. **Gate B** — each affected capability family `WriteCertified` on exact tuple ([`HARDWARE_GATES.md`](HARDWARE_GATES.md)).
5. **Mutation window** — lab path: Gate **C** open; production path: Gate **D** satisfied ([`RCI_POLICY.md`](RCI_POLICY.md) §4).
6. **Plan/Confirm** — confirmed, unexpired, digests match; desired pointer unchanged (apply preconditions §7.6).
7. **Concurrency** — router mutation lock available ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §4.6).

Failure at any step → **403** `gate.mutation_forbidden` (or **412** / **409** when precondition-specific codes apply) **before** live adapter write.

**Gate A (2026-07-31):** typed certification from [`docs/gate-a-certification.json`](../gate-a-certification.json) + [`STATUS.yaml`](../STATUS.yaml) gates section; **ReadOnlyCertified** after authorized rebind #2 post-WG on expendable class (evidence `data/artifacts/gate-a-probe-post-wireguard-install-192.168.2.1-20260731.json`; rebind #1 `gate-a-probe-newrouter-…` **SUPERSEDED**); **NOT** WriteCertified; `write_shapes_registered` remains **false**; live `RC_ADAPTER_MODE=live` enroll/preflight run bounded RO probe when Gate A tuple matches. Gates **B/C/D** remain **closed** — live mutations return **403** `gate.mutation_forbidden`; `RC_ALLOW_FAKE_MUTATIONS` applies **only** when `RC_ADAPTER_MODE=fake`.

---

## 11. Explicit v0 exclusions

The following are **out of scope** for v0 HTTP surface (no routes, no side channels):

| Excluded | Reason |
|---|---|
| Static/manage routes CRUD | Routes phase + benchmark gate ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.25) |
| Wi-Fi / VLAN / firewall mutations | Capability families not in v0 inventory |
| Raw RCI / arbitrary command | [`RCI_POLICY.md`](RCI_POLICY.md) §1 |
| Firmware/component install | ARCHITECTURE non-goal |
| Startup-config download/upload | High-risk; separate future contract |
| Promo/guest/board API tokens | ADR-001/003 |
| Plaintext secret read-back | [`SECURITY_OPS.md`](SECURITY_OPS.md) §4 |

Evidence lanes and test strategy: [`TEST_STRATEGY.md`](TEST_STRATEGY.md). **No v0 endpoint names** for excluded surfaces.

---

## 12. Traceability

| Source | Relationship |
|---|---|
| [`ARCHITECTURE.md`](../ARCHITECTURE.md) | Prefix, middleware, feature states, bounded contexts, inbound ports |
| [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md) | Entities, revisions, plans, operation/job lifecycle |
| [`RCI_POLICY.md`](RCI_POLICY.md) | Vendor-neutral boundary, lifecycle steps, allowlist |
| [`HARDWARE_GATES.md`](HARDWARE_GATES.md) | Gates A/B/C/D, certification tuple |
| [`SECURITY_OPS.md`](SECURITY_OPS.md) | Auth order, Confirm, CredentialRef, redaction |
| [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) | ETag/If-Match, idempotency, jobs, cancel, schema alignment |
| [`SCENARIOS.md`](SCENARIOS.md) | Operator/event scenarios traced to §6 endpoints and error codes |
| [ADR-001](../adrs/0001-python-package-fastapi-host.md) | Package vs host, Hub integration |
| [ADR-002](../adrs/0002-persistence-jobs-sqlite.md) | Durable jobs, idempotency |
| [ADR-003](../adrs/0003-security-auth-secrets.md) | hub_admin, DPAPI, fail-closed |
| [ADR-004](../adrs/0004-product-capability-scope.md) | NC-1812, AWG scope |

Index: [`README.md`](README.md).

---

## 13. OpenAPI generation note

This markdown contract is the **authoritative source** for HTTP behavior. Generated OpenAPI 3.x artifact: [`openapi-v0.json`](openapi-v0.json) (export via `scripts/export-openapi.ps1` from `router_control_host` FastAPI `app.openapi()`). Regenerate when §6 inventory changes; generated spec must:

- reproduce path/method inventory from §6 verbatim;
- embed machine codes from §4;
- mark write-only secret fields with `writeOnly: true` and exclude from response schemas;
- document required headers (`Idempotency-Key`, conditional `If-Match`) per operation;
- set `additionalProperties: false` on P2 request bodies;
- include `GET /routers/{router_id}/managed-resources` and publication/deployment P2 paths;
- document apply/teardown/preview **response bodies** via Pydantic models in `router_control_host/apply_response_models.py` (exported as `components.schemas.*`); verdict fields **`tunnel_verification_status`** (WireGuard apply/teardown), **`configuration_verification_status`**, **`interface_verification_status`**, **`interface_address_verification_status`** (WireGuard apply optional), **`on_air_verification_status`** (Wi-Fi AP apply/teardown), **`uplink_verification_status`** (Wi-Fi station apply/teardown runtime), and **`planned_uplink_verification_level`** (Wi-Fi station preview compile-time — machine-distinct enum from runtime uplink) are **required** `enum` literals where applicable; compile-time **`verification_status`** / **`grammar_verification_status`** on preview/apply-plan surfaces and **`error_category`** on Wi-Fi AP step objects are **closed enums** where the value set is finite (§13.2.2) — contract tests in `tests/test_openapi_contract.py` and `tests/test_planner_properties.py` fail if they disappear from the schema; **`overall`** on apply/teardown responses is a **closed enum** (`ApplyOverallStatus`) with OpenAPI `description` warning that HTTP **200** does not imply business success (§13.2.1); apply/teardown responses for WireGuard, Wi-Fi AP, and Wi-Fi station also require **`verdict_explanation`** (`VerdictExplanationResponse`: `signals_read[]`, `signals_missing[]`, `signals_rejected[]` with enum-coded signals/reasons — no secrets/SSID literals; human text is UI-only);
- **`test_pinned_openapi_matches_live_app`** compares live `GET /openapi.json` to committed [`openapi-v0.json`](openapi-v0.json) via canonical JSON (`sort_keys` + compact separators) — formatting/key-order drift ignored; first structural diffs reported on failure; regenerate with `py -3.11 scripts/export-openapi.py`;
- **`test_response_model_routes_validate_live_body`** invokes all **18** `response_model` routes on fake/injected transport (or field-name sync where dispatch is impractical) and validates live JSON against the Pydantic model with required-field presence checks;
- routes return **`JSONResponse(dict)`** (not bare model instances) so `response_model` documents OpenAPI only and does **not** filter runtime fields.

### 13.2 Typed apply/teardown response models (2026-08-01)

| Route group | OpenAPI schema | Required verdict field(s) |
|---|---|---|
| POST `/wireguard/apply`, `/wireguard/teardown` | `WireguardApplyResponse` | `tunnel_verification_status` + required `verdict_explanation`; apply optional when dispatch ok: `configuration_verification_status` (`device_accepted_configuration`), `interface_verification_status` (`interface_present_up` \| …), `interface_address_verification_status` (`interface_address_not_configured`; apply-only; includes readback-failed when dispatch ok); `errors` (apply failures) + `rollback_errors` (rollback failures, separate); optional `rollback` (`uncovered_ops` when sealed negation missing, baseline blocked, foreign-interface field unknown, or private-key unknown — offline-tested only) |
| POST `/wireguard/preview` | `WireguardPreviewResponse` | `verification_status` compile-time closed enum (`device_verified_asc9` \| `pending_live_verification` \| `unsupported_pending_verification` \| `unsupported`; not tunnel observe); optional same enum on apply when plan label echoed |
| POST `/wifi/preview` | `WifiPreviewResponse` | `verification_status=device_verified_wpa2` (compile-time closed enum) |
| POST `/wifi/apply`, `/wifi/teardown` | `WifiApplyResponse` | `on_air_verification_status` + required `verdict_explanation`; nested `verification.*` optional; step/rollback-step `error_category` closed enum when present; `errors` + `rollback_errors` (separate); optional `rollback.uncovered_ops` (baseline-blocked compensation; includes `pre-apply PSK state unknown…` when WPA enabled but readback omits PSK) |
| POST `/wifi/station/apply`, `/teardown` | `WifiStationApplyResponse` | runtime `uplink_verification_status` + required `verdict_explanation` + `grammar_verification_status=device_accepted_grammar`; legacy duplicate `verification_status` same value (split deferred — §13.2.2); `errors` + `rollback_errors` (separate); optional `rollback.uncovered_ops` for `wifi_station_ip_global`, baseline-blocked ops, and PSK-unknown fail-closed |
| POST `/wifi/station/preview` | `WifiStationPreviewResponse` | `planned_uplink_verification_level=planned_uplink_verified_bounded` + `grammar_verification_status=device_accepted_grammar` (compile-time; machine-distinct from runtime uplink observe) |
| POST `/vlan/preview`, `/dhcp/preview`, `/dns/preview`, `/firewall/preview` | `VlanPreviewResponse`, `DhcpPreviewResponse`, `DnsPreviewResponse`, `FirewallPreviewResponse` | `verification_status=offline_unverified` (compile-time; grammar not device-certified; **no apply/teardown HTTP routes**; offline service scaffold with PreState/compensation exists — see `docs/OPERATOR_NETWORK_FAMILY_APPLY_SCAFFOLD.md`) |
| POST `/keendns/status` | `KeenDnsStatusResponse` | Injected raw classify only; **no network I/O**; tri-state `feature_availability` + `name_reservation` + `access_mode` |
| POST `/keendns/preview` | `KeenDnsPreviewResponse` | `verification_status=documentation_sourced_unconfirmed` (docs-sourced CLI candidates; preview-only) |
| POST `/keendns/apply` | `KeenDnsApplyResponse` | `confirm_live_apply` required; sealed book/drop dispatch; Human Gate KeenDNS **APPROVED standing 2026-08-08** on expendable; **not live-proven cloud registration** |
| POST `/vpn-policy-routing/preview` | `VpnPolicyPreviewResponse` | `verification_status=help_verified_grammar_unapplied` (compile-time closed enum; **no apply/teardown HTTP routes**; offline service scaffold exists) |
| POST `/wifi/observed-state` | `WifiObservedStateResponse` | non-certifying observe report |
| POST `/wifi/site-survey` | `WifiSiteSurveyResponse` | non-certifying survey report |
| POST `/lab/bootstrap-discovery` | `BootstrapDiscoveryResponse` | `certification_eligible: false` invariant |
| POST `/lab/router-discovery` | `RouterDiscoveryResponse` | `certification_eligible: false`; bounded candidate sources; `source_diagnostics` / `degraded_sources` on OS read failures |
| POST `/lab/connection-health` | `ConnectionHealthResponse` | `certification_eligible: false`; green requires all five facts true |
| POST `/routers/{id}/rci/*` | `RciMutationResponse` | operation envelope + sanitized `result` |

### 13.2.1 `overall` outcome vs HTTP status (2026-08-01)

Sealed apply/teardown routes (`POST /wifi/apply`, `/wifi/teardown`, `/wifi/station/apply`, `/wifi/station/teardown`, `/wireguard/apply`, `/wireguard/teardown`) return **HTTP 200** when the handler finished and produced a typed response body — **including** terminal business failures (`overall=failed`, `verify_mismatch`, `rolled_back`, `unsupported_pending_verification`, …). This is **intentional**: HTTP success means *the apply run completed and the outcome is in the body*; it does **not** mean configuration succeeded. Clients **must** branch on `overall` (and family verdict fields such as `tunnel_verification_status`, `on_air_verification_status`, `uplink_verification_status`) — **not** on HTTP status alone. **Operator UI toasts (2026-08-01):** prefix text uses terminal `overall` failure labels before family verdict strings; verdict detail remains in honesty summary / `verdict_explanation` (see [`OPERATOR_UI.md`](../OPERATOR_UI.md) honesty panels).

| `overall` | Meaning (bounded) | HTTP when body returned |
|---|---|---|
| `applied` | Sealed ops dispatched without op failure and readback/verify passed per family rules | **200** |
| `failed` | Dispatch failure, uncaught service fault after dispatch start, or verify/readback failure without successful compensating rollback | **200** |
| `verify_mismatch` | Dispatch ok but readback does not match intent (Wi-Fi AP / WireGuard) | **200** |
| `rolled_back` | Compensating rollback attempted and `rollback.outcome=succeeded` after dispatch/verify failure | **200** |
| `dispatched_offline` | Offline/fake transport completed without live router I/O (Wi-Fi station and network-family offline apply services) | **200** |
| `unsupported_pending_verification` | Compiler blocked dispatch (e.g. 16-arg ASC) — empty op plan | **200** |

OpenAPI: `overall` is a **closed enum** on `WifiApplyResponse`, `WireguardApplyResponse`, and `WifiStationApplyResponse`; the field `description` warns that HTTP 200 does not imply success. Contract tests in `tests/test_openapi_contract.py` fail if any enum member disappears.

### 13.2.2 Compile-time `verification_status` overload (2026-08-01)

The field name **`verification_status`** is reused across families for **different semantic axes** (compile-time grammar/plan label — not runtime observe). Typed as **per-schema closed enums** in `apply_response_models.py`:

| Schema field | Closed values | Open / deferred |
|---|---|---|
| `WifiPreviewResponse.verification_status` | `device_verified_wpa2` | — |
| `WireguardPreviewResponse.verification_status` | `device_verified_asc9`, `pending_live_verification`, `unsupported_pending_verification`, `unsupported` | — |
| `WireguardApplyResponse.verification_status` (optional) | same as WireGuard preview | echoes plan label when present |
| `WifiStation*.{verification_status, grammar_verification_status}` | `device_accepted_grammar` | **Finding:** station apply duplicates grammar on both fields; prefer `grammar_verification_status` + runtime `uplink_verification_status`; rename/split deferred |
| `VpnPolicyPreviewResponse.verification_status` | `help_verified_grammar_unapplied` | — |
| `*PreviewResponse.verification_status` (vlan/dhcp/dns/firewall) | `offline_unverified` | — |
| `WifiApplyStepResponse.error_category` | `unsupported_grammar`, `rejected_by_router`, `auth_or_permission`, `resource_not_found`, `transport_or_timeout`, `unknown` | mirrors `WifiApRciErrorCategory` |

**Not typed (open by design):** router free-text in `errors[]`, `rollback.uncovered_ops[].reason`, planner op `notes[]`, persistence artifact `verification_status` (historical rows).

## Docs Impact Record

| Field | Value |
|---|---|
| trigger | docs-ssot-sync-post-session-20260801 |
| paths | docs/STATUS.yaml, docs/SESSION_HANDOFF_REAL_ROUTER_2026-07-31.md, docs/project-state.md, docs/contracts/ROADMAP.md, docs/contracts/API_CONTRACT.md, docs/docs-map.json, AGENTS.md |
| validators | `scripts/validate-project-docs.ps1`, `scripts/project-docs.py audit`, `tests/test_project_docs.py` |
| notes | Post-session SSOT sync: next_task operator-web-ui-full-coverage; verify baseline pytest 3196/2/0, ruff exit 0, mypy 112 files, schema v12; breaking table §13.4–§13.7 complete; all reliability items NOT device-verified |

### 13.3 HTTP intent body ↔ domain parse alignment (2026-08-01)

| Field | Domain (`network_intents.py`) | HTTP model | Drift? |
|---|---|---|---|
| Wi-Fi `ssid`, `enabled`, `wpa_mode`, `band`, `guest_isolation` | all required in `_parse_wifi` | required in `WifiIntentFields` | `guest_isolation=true` → **422** `wifi.guest_isolation_unsupported`; `false` noop |
| Wi-Fi `captive_portal` | optional; default `Disabled` | optional; default `Disabled` | `Enabled` → **422** `wifi.captive_portal_unsupported`; `Disabled` noop |
| Wi-Fi teardown `wpa_mode` | required in `_parse_wifi` | **required** in `WifiTeardownBody` (was silent `WPA2` default) | **fixed** |
| Wi-Fi observed `desired.*` | subset only | `guest_isolation`/`captive_portal` hardcoded in route helper | intentional — compare-only subset |
| WireGuard `enabled` | required | required | no |
| WireGuard `peer_rci_shape` | default `nested_rci`; `path_style` → `IntentValidationError` code `peer_rci_shape_unsupported` | default `nested_rci`; route uses `parse_network_intent` | no — HTTP maps domain codes to `wireguard.*` namespace (except `invalid_wg_id` → `wireguard.wg_forbidden`) |
| WireGuard `IntentValidationError` HTTP mapping | domain `IntentValidationError.code` | WireGuard preview/apply/teardown routes | **fixed** — bare domain codes (`invalid_asc_args`, `peer_rci_shape_unsupported`, …) prefixed to `wireguard.*` at HTTP boundary |
| Station `mode`, `band`, `priority` | defaults in `_parse_uplink` | matching Pydantic defaults | `priority≠100` without live `include_ip_global` → **422** `wifi.station_priority_requires_ip_global`; default `100` noop offline |
| Station `credential_ref_id` | required for `WifiWan` | optional at schema; route validates | no — runtime gate |
| WireGuard preview `asc_args` | N/A (compiler string) | `WireguardSealedOpPreview.asc_args: str \| null` | **fixed** (was `list[int]`) |

### 13.4 Breaking change — family-prefixed mutation error codes (2026-08-01)

**Impact:** Clients branching on `error.code` for Wi-Fi AP, Wi-Fi station, and WireGuard preview/apply/teardown routes **must** update matchers. Domain `IntentValidationError.code` values returned on WireGuard HTTP routes are now consistently prefixed at the route boundary (`wireguard_apply_routes._wireguard_intent_error_code`). Live transport faults use per-family prefixes via `map_wifi_live_transport_error(..., code_prefix=…)` and `live_*_code(family_prefix)`.

**Not a URL/version bump:** still `/api/router-control/v1`; additive response fields (`verdict_explanation`, …) remain non-breaking per §1.3.

| Previous HTTP `error.code` (or bare domain code) | New HTTP `error.code` | Route family |
|---|---|---|
| `confirm_required` | `wifi.confirm_required` | POST `/wifi/apply`, `/wifi/teardown` |
| `confirm_required` | `wifi.station_confirm_required` | POST `/wifi/station/apply`, `/wifi/station/teardown` |
| `confirm_required` | `wireguard.confirm_required` | POST `/wireguard/apply`, `/wireguard/teardown` |
| `preview_failed` | `wifi.preview_failed` | POST `/wifi/preview` |
| `preview_failed` | `wifi.station_preview_failed` | POST `/wifi/station/preview` |
| `preview_failed` | `wireguard.preview_failed` | POST `/wireguard/preview` |
| `apply_failed` | `wifi.apply_failed` | POST `/wifi/apply`, `/wifi/teardown` |
| `apply_failed` | `wifi.station_apply_failed` | POST `/wifi/station/apply`, `/wifi/station/teardown` |
| `apply_failed` | `wireguard.apply_failed` | POST `/wireguard/apply`, `/wireguard/teardown` |
| `ap_forbidden` | `wifi.ap_forbidden` | Wi-Fi AP allowlist rejections |
| `invalid_wg_id` (domain) / `wg_forbidden` | `wireguard.wg_forbidden` | WireGuard interface allowlist |
| `live_connection_incomplete` | `wifi.live_connection_incomplete` | Wi-Fi AP apply/teardown + observed-state/site-survey live paths |
| `live_connection_incomplete` | `wifi.station.live_connection_incomplete` | Wi-Fi station apply/teardown |
| `live_connection_incomplete` | `wireguard.live_connection_incomplete` | WireGuard apply/teardown |
| `live_platform_unsupported` | `wifi.live_platform_unsupported` | Wi-Fi AP live paths |
| `live_platform_unsupported` | `wifi.station.live_platform_unsupported` | Wi-Fi station apply/teardown |
| `live_platform_unsupported` | `wireguard.live_platform_unsupported` | WireGuard apply/teardown |
| `live_backup_unavailable` | `wifi.live_backup_unavailable` | Wi-Fi AP apply/teardown |
| `live_backup_unavailable` | `wifi.station.live_backup_unavailable` | Wi-Fi station apply/teardown |
| `live_backup_unavailable` | `wireguard.live_backup_unavailable` | WireGuard apply/teardown |
| `ssh_host_key_mismatch` | `wifi.ssh_host_key_mismatch` | Wi-Fi live transport |
| `ssh_host_key_mismatch` | `wifi.station.ssh_host_key_mismatch` | Wi-Fi station live transport |
| `ssh_host_key_mismatch` | `wireguard.ssh_host_key_mismatch` | WireGuard live transport |
| `credential_not_found` | `wifi.credential_not_found` | Wi-Fi live transport |
| `credential_not_found` | `wifi.station.credential_not_found` | Wi-Fi station live transport |
| `credential_not_found` | `wireguard.credential_not_found` | WireGuard live transport |
| `credential_unusable` | `wifi.credential_unusable` | Wi-Fi live transport |
| `credential_unusable` | `wifi.station.credential_unusable` | Wi-Fi station live transport |
| `credential_unusable` | `wireguard.credential_unusable` | WireGuard live transport |
| `live_transport_failed` | `wifi.live_transport_failed` | Wi-Fi live transport |
| `live_transport_failed` | `wifi.station.live_transport_failed` | Wi-Fi station live transport |
| `live_transport_failed` | `wireguard.live_transport_failed` | WireGuard live transport |
| `invalid_asc_args` (domain) | `wireguard.invalid_asc_args` | WireGuard preview/apply intent validation |
| `peer_rci_shape_unsupported` (domain) | `wireguard.peer_rci_shape_unsupported` | WireGuard preview/apply intent validation |
| `invalid_peer_rci_shape` (domain) | `wireguard.invalid_peer_rci_shape` | WireGuard preview/apply intent validation |
| `invalid_peer_allow_ips` (domain) | `wireguard.invalid_peer_allow_ips` | WireGuard preview/apply intent validation |
| `invalid_field_type` (domain) | `wireguard.invalid_field_type` | WireGuard preview/apply intent validation |
| `invalid_keepalive` (domain) | `wireguard.invalid_keepalive` | WireGuard preview/apply intent validation |
| `private_key_ref_required` (domain) | `wireguard.private_key_ref_required` | WireGuard preview/apply intent validation |
| `peer_public_key_required` (domain) | `wireguard.peer_public_key_required` | WireGuard preview/apply intent validation |
| `invalid_enabled` (domain) | `wireguard.invalid_enabled` | WireGuard preview/apply intent validation |
| `enabled_missing` (domain) | `wireguard.enabled_missing` | WireGuard preview/apply intent validation |
| `secret_shaped_field` (domain) | `wireguard.secret_shaped_field` | WireGuard intent secret-key rejection |

**Unchanged within Wi-Fi observe family (already `wifi.*`):** `wifi.live_connection_required`, `wifi.gate_a_required`, `wifi.observed_state_failed`, `wifi.site_survey_radio_forbidden`, `wifi.site_survey_failed`.

**Evidence:** route mappers in `router_control_host/wifi_apply_routes.py`, `wifi_station_apply_routes.py`, `wireguard_apply_routes.py`, `router_control_host/wifi_live_transport.py`; contract tests in `tests/test_wifi_apply_api.py`, `tests/test_wifi_station_apply_api.py`, `tests/test_wireguard_apply_api.py`, `tests/test_wifi_live_wiring.py`, `tests/test_wireguard_live_wiring.py`.

### 13.8 Breaking change — Wi-Fi AP guest isolation / captive portal fail-closed (2026-08-01)

**Impact:** Clients that previously received **200** from `POST /wifi/preview` or `POST /wifi/apply` with `guest_isolation=true` or `captive_portal=Enabled` (planner silently emitted zero ops for those fields) **must** handle **422** with explicit codes below. No device-verified grammar exists for these intent values; partial silent intent loss is forbidden.

| Intent field | Value | Previous behavior | New HTTP | `error.code` |
|---|---|---|---|---|
| `guest_isolation` | `false` | 200 (noop) | 200 (noop) | — |
| `guest_isolation` | `true` | 200 (silent zero-op) | **422** | `wifi.guest_isolation_unsupported` |
| `captive_portal` | `Disabled` | 200 (noop) | 200 (noop) | — |
| `captive_portal` | `Enabled` | 200 (silent zero-op) | **422** | `wifi.captive_portal_unsupported` |

**Not a URL/version bump:** still `/api/router-control/v1`.

**Evidence:** planner gate `_reject_unsupported_intent_fields` in `router_control/application/wifi_apply_planner.py`; HTTP mapper `_wifi_planner_error_response` in `router_control_host/wifi_apply_routes.py`; tests `tests/test_wifi_apply_planner.py`, `tests/test_wifi_apply_api.py` (`guest_isolation`, `captive_portal`, `unsupported`).

### 13.9 Breaking change — station priority fail-closed on preview/offline (2026-08-01)

**Impact:** Clients that previously received **200** from `POST /wifi/station/preview` or offline `POST /wifi/station/apply` with non-default `priority` (planner silently omitted `IP_GLOBAL` when `include_ip_global=false`) **must** handle **422** with explicit code below. Default `priority=100` remains noop offline; live apply path still consumes priority via forced `include_ip_global=true`.

| Intent field | Value | Previous behavior | New HTTP | `error.code` |
|---|---|---|---|---|
| `priority` | `100` (default) | 200 (no `IP_GLOBAL` op) | 200 (noop) | — |
| `priority` | non-default | 200 (silent omit of `IP_GLOBAL`) | **422** | `wifi.station_priority_requires_ip_global` |
| `priority` | non-default + live path | 200 (`IP_GLOBAL` sealed) | 200 (unchanged) | — |

**Not a URL/version bump:** still `/api/router-control/v1`.

**Evidence:** `compile_uplink_intent_to_station_ops` gate in `router_control/application/wifi_station_apply_planner.py`; HTTP mappers in `router_control_host/wifi_station_apply_routes.py`, `wifi_station_preview_routes.py`; tests `tests/test_wifi_station_apply_planner.py`, `tests/test_wifi_station_preview_api.py`, `tests/test_wifi_station_apply_api.py`.

### 13.5 Breaking change — Gate A vs backup-unavailable split (2026-08-01)

**Impact:** Clients branching on live mutation `error.code` **must** distinguish Gate A closed from startup-config backup failure. Previously both conditions returned `{family}.live_backup_unavailable` on mutation routes; Gate A closed now returns `{family}.gate_a_required` (aligned with read-only Wi-Fi observe/site-survey).

**Not a URL/version bump:** still `/api/router-control/v1`.

| Route | Condition | Previous HTTP `error.code` | New HTTP `error.code` |
|---|---|---|---|
| POST `/wifi/apply` | Gate A closed (live path) | `wifi.live_backup_unavailable` | `wifi.gate_a_required` |
| POST `/wifi/apply` | Startup-config backup failure | `wifi.live_backup_unavailable` | `wifi.live_backup_unavailable` (unchanged) |
| POST `/wifi/teardown` | Gate A closed (live path) | `wifi.live_backup_unavailable` | `wifi.gate_a_required` |
| POST `/wifi/teardown` | Startup-config backup failure | `wifi.live_backup_unavailable` | `wifi.live_backup_unavailable` (unchanged) |
| POST `/wifi/station/apply` | Gate A closed (live path) | `wifi.station.live_backup_unavailable` | `wifi.station.gate_a_required` |
| POST `/wifi/station/apply` | Startup-config backup failure | `wifi.station.live_backup_unavailable` | `wifi.station.live_backup_unavailable` (unchanged) |
| POST `/wifi/station/teardown` | Gate A closed (live path) | `wifi.station.live_backup_unavailable` | `wifi.station.gate_a_required` |
| POST `/wifi/station/teardown` | Startup-config backup failure | `wifi.station.live_backup_unavailable` | `wifi.station.live_backup_unavailable` (unchanged) |
| POST `/wireguard/apply` | Gate A closed (live path) | `wireguard.live_backup_unavailable` | `wireguard.gate_a_required` |
| POST `/wireguard/teardown` | Gate A closed (live path) | `wireguard.live_backup_unavailable` | `wireguard.gate_a_required` |
| POST `/wireguard/teardown` | Startup-config backup failure | `wireguard.live_backup_unavailable` | `wireguard.live_backup_unavailable` (unchanged) |

**Client migration:** replace matchers that treated `*.live_backup_unavailable` as “certification missing” with `*.gate_a_required`; retain `*.live_backup_unavailable` only for backup vault/transport failures after Gate A is open.

**Evidence:** `gate_a_required_code()` in `router_control_host/wifi_live_transport.py`; route handlers `_gate_a_required_error` / `_live_backup_unavailable_error`; tests `test_live_apply_requires_gate_a`, `test_live_teardown_requires_gate_a`, `test_wifi_station_apply_gate_a_required_when_live_params`, `test_wifi_station_teardown_live_requires_gate_a`, `test_live_apply_requires_gate_a` (wireguard), `test_*_live_backup_error*` / teardown backup tests.

### 13.6 Additive — sealed apply trail fail-closed + lease stale (2026-08-01)

**Impact:** Sealed apply/teardown routes may return **503** `sealed_apply.trail_begin_failed` when the durable trail row cannot be created; **no device I/O** occurs. Clients **must not** treat this as success. Trail durability now uses M10 lease + `ops_pending_redacted` intent window (see [`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.28).

| Condition | HTTP | `error.code` |
|---|---|---|
| Trail begin failure (all sealed apply/teardown routes) | **503** | `sealed_apply.trail_begin_failed` |

**Not a URL/version bump:** still `/api/router-control/v1`; success-path response bodies unchanged.

**Evidence:** `tests/test_sealed_apply_crash_durability.py` (`test_trail_begin_failure_blocks_device_writes`, `test_crash_after_device_ack_leaves_unconfirmed_op_in_trail`, `test_parallel_runtime_does_not_interrupt_active_sealed_apply`, `test_migration_v9_to_v10_sealed_apply_lease_columns`).

### 13.7 Breaking change — station preview planned uplink label split (2026-08-01)

**Impact:** Clients parsing `POST /wifi/station/preview` for compile-time uplink plan scope **must** read **`planned_uplink_verification_level`** — **not** runtime **`uplink_verification_status`**. The compile-time value **`planned_uplink_verified_bounded`** is **machine-distinct** from runtime **`uplink_verified_bounded`** (disjoint closed enums).

| Surface | Previous client assumption (ambiguous) | New contract |
|---|---|---|
| Preview compile-time plan label | Treating preview output as runtime uplink observe / conflating with `uplink_verification_status=uplink_verified_bounded` | Required **`planned_uplink_verification_level=planned_uplink_verified_bounded`**; `verification_status` / `grammar_verification_status` = `device_accepted_grammar` only |
| Apply/teardown runtime observe | — | **`uplink_verification_status`** closed enum (`uplink_dispatched_unverified` \| `uplink_associated_no_global` \| `uplink_verified_bounded` \| `uplink_failed`) — disjoint from preview plan enum |

**Not a URL/version bump:** still `/api/router-control/v1`; additive field on preview response.

**Evidence:** `apply_response_models.PlannedUplinkVerificationLevel`; `tests/test_openapi_contract.py::test_openapi_station_planned_uplink_level_distinct_from_runtime`; `tests/test_wifi_station_preview_api.py`.

### 13.1 P2 additive endpoints (offline/fake, 2026-07-22)

| Method | Path | Notes |
|---|---|---|
| POST | `/event-presets/{id}/publications` | 201; `If-Match` + `Idempotency-Key` required |
| POST | `/routers/{rid}/deployment-revisions` | 201; topology/tuple blockers → 422 |
| POST | `/routers/{rid}/plans` | 201; session HMAC binding; unknown fields → 422 |
| POST | `/routers/{rid}/plans/{pid}/confirm` | CAS `If-Match`; cross-session → 403 |
| POST | `/routers/{rid}/plans/{pid}/apply` | 202 fake-only; stale observation/credential/cert → 409/422 |
| GET | `/routers/{rid}/managed-resources` | Managed ownership inventory |
| GET | `/routers/{rid}/plans/{pid}/verification` | Structured verify report |

Stale codes: `stale_observation`, `stale_credential`, `stale_certification`, `tuple_mismatch`, `digest_mismatch`, `session_binding_mismatch`. **P3 topology safety closure complete** (2026-07-23; offline/default-deny; shared executor + Gate D default-deny); live apply not standing-executable for Gate B families — **next major phase:** full operator web UI (`operator-web-ui-full-coverage` per [`STATUS.yaml`](../STATUS.yaml) `next_task`); **parallel deferred:** VPN routing live apply (offline preview only); Gate B **completed_failed**; not WriteCertified; `write_shapes_registered` false.
