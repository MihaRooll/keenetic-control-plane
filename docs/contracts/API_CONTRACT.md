# HTTP/API contract (v0)

## For agents

| Topic | Rule |
|---|---|
| Prefix | All routes under **`/api/router-control/v1`** on shared Hub listener (prototype dev-host uses same prefix) |
| Phase 0b | Contract only — **no** OpenAPI file, package, or host implementation |
| Auth order | Enabled + empty `HUB_ADMIN_PASSWORD` → **503** before handler; invalid/missing `hub_admin` → **401**; no API/guest/board/promo bypass |
| Feature states | `Disabled` / `Starting` / `Ready` / `Degraded` / `SecurityBlocked` — see §2 |
| Mutations | **`Idempotency-Key` required** on all POST/PUT/PATCH/DELETE; `If-Match` on desired revision/plan preconditions; Gate **A** before live observe; §10 gates before write dispatch |
| Secrets | Write-only inputs; **never** echoed in response/DTO/job/audit; use `CredentialRef` metadata on reads |
| Gates | Live observe requires Gate **A**; writes require identity + fresh observation + Gate B + (lab C **or** production D); **Phase 0b opens none** — live observe and write dispatch fail closed |
| v0 exclusions | No routes/capture/Wi-Fi/firewall/raw-RCI/arbitrary-command endpoints |
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
- **`message`** — redacted; **must not** contain router command text, passwords, keys, session tokens, or startup-config excerpts.
- **`details`** — optional array of field-level issues; values redacted.
- **`request_id` / `correlation_id`** — mirror response headers.

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
| **503** | `security.configuration_blocked`, `feature.degraded`, `feature.not_ready`, `router.mutation_busy` | SecurityBlocked; degraded/disabled mutation; starting; router lock held (optional) |
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

**Note:** Plan create/confirm and desired revision PUT persist intent only (SQLite). **`POST .../apply`** is the sole v0 client-visible path to enqueue router mutation dispatch after Confirm; it returns **202** `OperationAccepted` (§9.1). Apply runs §10 gate evaluation before any live adapter call. **`Ready` + valid `hub_admin` alone does not authorize live RCI observe** — live enroll/preflight observe legs require Gate **A** open; non-live (L2 fake) adapter **may** persist intent via **202** without live observe (§10.1).

---

## 7. Resource DTOs (vendor-neutral)

### 7.1 Feature status — `GET /status`

**Response 200:**

| Field | Type | Notes |
|---|---|---|
| `feature_state` | enum | `Disabled \| Starting \| Ready \| Degraded` — **`SecurityBlocked` is not returned on 200**; when admin password is empty and feature enabled, §2.1 returns **503** before handler with `security.configuration_blocked` (observable via error body / `feature_state` in error `details` when present) |
| `hub_available` | boolean | Hub listener up (always true if response returned) |
| `database_state` | enum | `Ok \| Degraded \| Unavailable` |
| `worker_state` | enum | `Stopped \| Starting \| Running \| Degraded` |
| `routers_summary` | object | `{ "total": 0, "enrolled": 0, "degraded": 0 }` — redacted counts |
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
| `endpoint` | object | yes | `{ kind, host, port }` — placeholder host only in docs |
| `management_password` | string | yes | **Write-only**; stored via vault; **never** returned |

**Response 202 (non-live / L2 fake adapter):** `OperationAccepted` (§9.1) — SQLite enrollment intent persisted; **no** live observe dispatch. **Response 403 (live adapter, Gate A closed):** `gate.a_closed` **before** live adapter dispatch — **must not** claim live observe succeeded (§10.1).

**`POST .../preflight` request:** optional `{ "observation_ttl_seconds": 300 }`

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

**`VpnProfileDetail` response:**

| Field | Type | Notes |
|---|---|---|
| `profile_id` | string | |
| `display_name`, `vpn_kind` | string | |
| `parser_version` | string | |
| `content_digest` | string | |
| `validation_status` | enum | `Pending \| Valid \| Invalid \| UnsupportedFields` |
| `unsupported_fields` | string[] | Redacted field names only |
| `credential_refs` | array | `{ credential_ref_id, role, kind }` — metadata only |
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
| `changes` | array | Ordered `{ ordinal, change_kind, summary, target_resource_id? }` — **no** raw RCI |
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

**Phase 0b:** gates A/B/C/D are **closed** for real hardware. API handlers may persist intent (enroll request accepted only when using non-live fixtures; revisions, plans, credentials in SQLite) but **live observe and router write dispatch must fail closed** — **403** `gate.a_closed` for observe legs; **403** `gate.mutation_forbidden` for write legs. No hidden parameters or admin overrides in v0.

---

## 11. Explicit v0 exclusions

The following are **out of scope** for v0 HTTP surface (no routes, no side channels):

| Excluded | Reason |
|---|---|
| Static/manage routes CRUD | Routes phase + benchmark gate ([`PERSISTENCE_CONTRACT.md`](PERSISTENCE_CONTRACT.md) §2.25) |
| Traffic capture / proposals | TrafficDiscovery bounded context |
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

This markdown contract is the **authoritative source** for HTTP behavior in Phase 0b. OpenAPI 3.x artifact generation is **deferred** until implementation phase; generated spec must:

- reproduce path/method inventory from §6 verbatim;
- embed machine codes from §4;
- mark write-only secret fields with `writeOnly: true` and exclude from response schemas;
- document required headers (`Idempotency-Key`, conditional `If-Match`) per operation.

No `openapi.yaml` / `openapi.json` in repository during Phase 0b.
