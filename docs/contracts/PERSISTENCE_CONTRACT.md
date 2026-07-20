# Persistence, revisions, and durable jobs contract

## For agents

| Rule | Requirement |
|---|---|
| Authoritative store | `data/router_control.sqlite3` only; **never** `studio.sqlite3` or JSON sidecars as SSOT |
| Isolation | RC DB failure/degradation **must not** block kiosk, board, printing, or Hub startup |
| Migrations | Independent `PRAGMA user_version` and contiguous migration chain; shipped migrations immutable |
| Revisions | `DesiredRevision` immutable; monotonic per-router numbering; ETag/`If-Match` in same txn as pointer update |
| Applied marker | `applied_revision_id` updates **only** in successful verify transaction after read-back |
| Jobs | One active mutation per `RouterId`; `BEGIN IMMEDIATE` claim; leases/fencing; **no** long router I/O inside SQLite txn |
| Recovery | Unknown external outcome → identity/read-back then resume/verify/compensate/`RecoveryRequired`; **never** blind retry |
| Idempotency | Same key+digest → existing op; same key+different digest → conflict; retention ≥ retry/recovery window |
| Secrets | `CredentialRef` opaque metadata only; no plaintext secrets, raw RCI, or startup-config in DB/jobs/audit |
| Deferred | `route_sets*`, `traffic_observations`, `route_proposals` — reserved keys only; **no** API v0 write path |
| Trace | [`CANONICAL.md`](../CANONICAL.md), [`ARCHITECTURE.md`](../ARCHITECTURE.md), [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md), ADR-0002, [`RCI_POLICY.md`](RCI_POLICY.md), [`SECURITY_OPS.md`](SECURITY_OPS.md), [`SCENARIOS.md`](SCENARIOS.md), [`README.md`](README.md) |

---

## 1. Authoritative store and isolation

Router Control **must** persist all domain state, ownership, desired/observed/applied markers, durable operations/jobs, idempotency records, and audit in a **single dedicated SQLite file**:

```text
data/router_control.sqlite3
```

**Forbidden as authoritative store:**

- tables or migration counter in `data/studio.sqlite3`;
- JSON files, sidecars, or in-memory queues as database/outbox/job log;
- arbitrary JSON columns replacing relational constraints, indexes, leases, revision pointers, or normalized join-table links.

JSON and CONF are permitted **only** as import/export interchange, versioned **redacted** snapshot blobs inside explicitly defined artifact fields, hashed backup/diagnostic artifacts, or API wire representation. JSON sidecar **must not** be SSOT.

**Failure isolation:** corruption, disk-full, permission errors, or incompatible schema version **must** transition Router Control to degraded/disabled with a redacted operational event. Other Hub bounded contexts **must** continue startup and operation. Router Control **must not** share failure domain with `studio.sqlite3`.

**Schema lifecycle:** Router Control owns an independent contiguous migration chain starting at `user_version = 1`. Migration order, backup policy, and startup behavior are defined in §8; this contract specifies requirements only — **no executable migrations** in Phase 0b.

**Multi-router-ready:** no singleton router row. All router-scoped tables include `router_id`; uniqueness and indexes account for it. `SiteId` and `RouterId` are stable opaque IDs; endpoint IP, hostname, gateway, and interface names are mutable locators, never primary keys.

---

## 2. Logical schema v0

Storage conventions unless noted per column:

| Convention | SQLite type | Notes |
|---|---|---|
| Opaque IDs | `TEXT NOT NULL` | UUID/ULID/opaque string; application-generated; never reused after delete |
| Booleans | `INTEGER NOT NULL` | `0` = false, `1` = true; enforce with `CHECK (col IN (0, 1))` where listed |
| Timestamps | `TEXT NOT NULL` | ISO-8601 UTC from single clock abstraction |
| Epoch seconds | `INTEGER` | Lease/expiry when numeric comparison preferred |
| Enumerations | `TEXT NOT NULL` | Closed vocabulary documented per column |
| Redacted JSON blob | `TEXT` | Versioned, redacted value document only; **not** SSOT for relationships, secrets, or relational link IDs |
| Digests | `TEXT NOT NULL` | Stable hash of canonical normalized content |

Foreign keys **must** be enabled on every connection (`PRAGMA foreign_keys = ON`). Unless stated, `ON DELETE RESTRICT` applies; parent delete while referenced **must** fail closed. Unless stated, foreign key checks are **immediate** at statement time; only the cyclic `operations` ↔ `idempotency_records` pair uses `DEFERRABLE INITIALLY DEFERRED` (enforced at **COMMIT**; see §2.16, §2.20, §6).

### 2.1 `sites`

| Column | Type | Null | Notes |
|---|---|---|---|
| `site_id` | TEXT | NO | PK |
| `display_name` | TEXT | NO | |
| `timezone` | TEXT | NO | IANA name |
| `created_at` | TEXT | NO | |
| `updated_at` | TEXT | NO | |

**PK:** `site_id`

**Indexes:** none beyond PK (low cardinality)

### 2.2 `routers`

| Column | Type | Null | Notes |
|---|---|---|---|
| `router_id` | TEXT | NO | PK |
| `site_id` | TEXT | NO | FK → `sites.site_id` |
| `display_name` | TEXT | NO | |
| `vendor` | TEXT | NO | |
| `model` | TEXT | NO | |
| `hardware_revision` | TEXT | YES | |
| `identity_fingerprint` | TEXT | NO | enrolled claims digest |
| `identity_claims_json` | TEXT | YES | redacted enrollment claims blob |
| `credential_ref_id` | TEXT | YES | FK → `credential_refs.credential_ref_id` |
| `lifecycle_status` | TEXT | NO | `PendingEnrollment \| Enrolled \| IdentityMismatch \| Disabled` |
| `created_at` | TEXT | NO | |
| `updated_at` | TEXT | NO | |

**PK:** `router_id`

**FK:** `site_id` → `sites`; `credential_ref_id` → `credential_refs` (nullable until enrolled)

**Indexes:**

- `idx_routers_site_id` ON (`site_id`)
- `idx_routers_lifecycle_status` ON (`lifecycle_status`)

### 2.3 `router_endpoints`

| Column | Type | Null | Notes |
|---|---|---|---|
| `endpoint_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `kind` | TEXT | NO | e.g. `management_https`, `management_http` |
| `host` | TEXT | NO | mutable locator |
| `port` | INTEGER | NO | |
| `priority` | INTEGER | NO | lower = preferred |
| `is_enabled` | INTEGER | NO | CHECK IN (0,1) |
| `last_success_at` | TEXT | YES | |
| `last_failure_at` | TEXT | YES | |
| `last_error_redacted` | TEXT | YES | |
| `created_at` | TEXT | NO | |
| `updated_at` | TEXT | NO | |

**PK:** `endpoint_id`

**UNIQUE:** `uq_router_endpoints_router_kind_host_port` ON (`router_id`, `kind`, `host`, `port`)

**Indexes:**

- `idx_router_endpoints_router_priority` ON (`router_id`, `priority`, `is_enabled`)

### 2.4 `router_capabilities`

| Column | Type | Null | Notes |
|---|---|---|---|
| `capability_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `firmware_version` | TEXT | NO | |
| `firmware_build` | TEXT | YES | |
| `firmware_channel` | TEXT | YES | |
| `component_set_digest` | TEXT | NO | |
| `capabilities_json` | TEXT | YES | redacted capability snapshot blob |
| `certification_status` | TEXT | NO | `Unknown \| ReadOnlyCertified \| WriteCertified \| Unsupported` |
| `observed_at` | TEXT | NO | |
| `valid_until` | TEXT | NO | |
| `source` | TEXT | NO | |
| `created_at` | TEXT | NO | immutable row |

**PK:** `capability_id`

**Indexes:**

- `idx_router_capabilities_router_observed` ON (`router_id`, `observed_at` DESC)
- `idx_router_capabilities_router_valid_until` ON (`router_id`, `valid_until`)

Capability rows are **immutable** after insert; new observation creates new row.

### 2.5 `credential_refs`

| Column | Type | Null | Notes |
|---|---|---|---|
| `credential_ref_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `kind` | TEXT | NO | see [`SECURITY_OPS.md`](SECURITY_OPS.md) vocabulary |
| `provider` | TEXT | NO | e.g. `DPAPI.CurrentUser` |
| `provider_locator` | TEXT | NO | opaque vault locator |
| `created_at` | TEXT | NO | |
| `rotated_at` | TEXT | YES | |
| `revoked_at` | TEXT | YES | |

**PK:** `credential_ref_id`

**Indexes:**

- `idx_credential_refs_router_kind` ON (`router_id`, `kind`)
- `idx_credential_refs_revoked_at` ON (`revoked_at`) WHERE `revoked_at IS NOT NULL`

**Forbidden columns:** password, private key, session token, DPAPI plaintext/ciphertext payload.

### 2.6 `vpn_profile_artifacts`

| Column | Type | Null | Notes |
|---|---|---|---|
| `profile_id` | TEXT | NO | PK |
| `display_name` | TEXT | NO | |
| `vpn_kind` | TEXT | NO | e.g. `AmneziaWG` |
| `parser_version` | TEXT | NO | |
| `content_digest` | TEXT | NO | normalized import digest |
| `metadata_json` | TEXT | YES | redacted metadata blob |
| `validation_status` | TEXT | NO | |
| `unsupported_fields_json` | TEXT | YES | redacted list blob |
| `created_at` | TEXT | NO | |
| `superseded_at` | TEXT | YES | |

**PK:** `profile_id`

**Indexes:**

- `idx_vpn_profile_artifacts_vpn_kind` ON (`vpn_kind`, `validation_status`)
- `idx_vpn_profile_artifacts_superseded_at` ON (`superseded_at`)

### 2.7 `vpn_profile_secret_refs`

Normalized credential links for VPN profile artifacts. Credential references **must not** be stored as JSON ID arrays on profile rows.

| Column | Type | Null | Notes |
|---|---|---|---|
| `profile_id` | TEXT | NO | FK → `vpn_profile_artifacts.profile_id` ON DELETE CASCADE |
| `credential_ref_id` | TEXT | NO | FK → `credential_refs.credential_ref_id` |
| `role` | TEXT | NO | closed vocabulary; non-empty |
| `created_at` | TEXT | NO | |

**PK:** (`profile_id`, `credential_ref_id`, `role`)

**FK:** `profile_id` → `vpn_profile_artifacts` (`ON DELETE CASCADE`); `credential_ref_id` → `credential_refs` (`ON DELETE RESTRICT`)

**Indexes:**

- `idx_vpn_profile_secret_refs_credential_ref_id` ON (`credential_ref_id`)
- `idx_vpn_profile_secret_refs_credential_role` ON (`credential_ref_id`, `role`)

### 2.8 `tunnel_assignments`

| Column | Type | Null | Notes |
|---|---|---|---|
| `assignment_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `profile_id` | TEXT | NO | FK → `vpn_profile_artifacts.profile_id` |
| `logical_role` | TEXT | NO | e.g. `primary-event-vpn` |
| `desired_active` | INTEGER | NO | CHECK IN (0,1) |
| `policy_metadata_json` | TEXT | YES | redacted |
| `observed_vendor_locator` | TEXT | YES | mutable |
| `created_at` | TEXT | NO | |
| `retired_at` | TEXT | YES | |

**PK:** `assignment_id`

**Indexes:**

- `idx_tunnel_assignments_router_role` ON (`router_id`, `logical_role`)
- `idx_tunnel_assignments_router_active` ON (`router_id`, `desired_active`, `retired_at`)

### 2.9 `desired_revisions`

| Column | Type | Null | Notes |
|---|---|---|---|
| `revision_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `revision_number` | INTEGER | NO | monotonic per router |
| `parent_revision_id` | TEXT | YES | FK → `desired_revisions.revision_id` |
| `canonical_digest` | TEXT | NO | ETag source |
| `desired_document_json` | TEXT | YES | redacted canonical desired blob |
| `based_on_observation_id` | TEXT | YES | FK → `router_observations.observation_id` |
| `actor_type` | TEXT | NO | |
| `actor_id` | TEXT | YES | |
| `reason` | TEXT | YES | redacted |
| `created_at` | TEXT | NO | |

**PK:** `revision_id`

**UNIQUE:** `uq_desired_revisions_router_number` ON (`router_id`, `revision_number`)

**CHECK:** `revision_number > 0`

**Indexes:**

- `idx_desired_revisions_router_created` ON (`router_id`, `created_at` DESC)

Rows are **immutable** after insert; edits create new revision.

### 2.10 `router_revision_state`

One row per router — current pointers only (not singleton for whole system).

| Column | Type | Null | Notes |
|---|---|---|---|
| `router_id` | TEXT | NO | PK, FK → `routers.router_id` |
| `current_desired_revision_id` | TEXT | NO | FK → `desired_revisions.revision_id` |
| `applied_revision_id` | TEXT | YES | FK → `desired_revisions.revision_id` |
| `last_observation_id` | TEXT | YES | FK → `router_observations.observation_id` |
| `updated_at` | TEXT | NO | |

**PK:** `router_id`

**Indexes:** none beyond PK

`applied_revision_id` **must** change only inside verify-success transaction (§3.4).

### 2.11 `router_observations`

| Column | Type | Null | Notes |
|---|---|---|---|
| `observation_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `capability_id` | TEXT | YES | FK → `router_capabilities.capability_id` |
| `identity_fingerprint` | TEXT | NO | |
| `resource_version` | TEXT | NO | vendor ETag/version |
| `state_digest` | TEXT | NO | normalized snapshot digest |
| `state_snapshot_json` | TEXT | YES | redacted snapshot blob |
| `collection_status` | TEXT | NO | `Succeeded \| Partial \| Failed` |
| `error_redacted` | TEXT | YES | |
| `source` | TEXT | NO | |
| `adapter_version` | TEXT | NO | |
| `observed_at` | TEXT | NO | |
| `valid_until` | TEXT | NO | TTL boundary |
| `created_at` | TEXT | NO | |

**PK:** `observation_id`

**Indexes:**

- `idx_router_observations_router_observed` ON (`router_id`, `observed_at` DESC)
- `idx_router_observations_router_valid_until` ON (`router_id`, `valid_until`)

Rows are **immutable** after insert.

### 2.12 `observation_resources`

| Column | Type | Null | Notes |
|---|---|---|---|
| `observation_resource_id` | TEXT | NO | PK |
| `observation_id` | TEXT | NO | FK → `router_observations.observation_id` ON DELETE CASCADE |
| `resource_kind` | TEXT | NO | |
| `logical_key` | TEXT | NO | stable within observation |
| `vendor_locator` | TEXT | YES | |
| `fingerprint` | TEXT | YES | |
| `snapshot_ref` | TEXT | YES | artifact id or inline redacted ref |
| `snapshot_digest` | TEXT | YES | |
| `ordinal` | INTEGER | NO | display/diff order |

**PK:** `observation_resource_id`

**UNIQUE:** `uq_observation_resources_obs_kind_key` ON (`observation_id`, `resource_kind`, `logical_key`)

**Indexes:**

- `idx_observation_resources_observation_ordinal` ON (`observation_id`, `ordinal`)

### 2.13 `managed_resources`

| Column | Type | Null | Notes |
|---|---|---|---|
| `resource_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `resource_kind` | TEXT | NO | |
| `logical_key` | TEXT | NO | |
| `owner` | TEXT | NO | e.g. `router-control` |
| `creating_revision_id` | TEXT | NO | FK → `desired_revisions.revision_id` |
| `vendor_locator` | TEXT | YES | |
| `locator_fingerprint` | TEXT | YES | |
| `lifecycle_status` | TEXT | NO | `Planned \| Present \| Missing \| Retired` |
| `last_observation_id` | TEXT | YES | FK → `router_observations.observation_id` |
| `created_at` | TEXT | NO | |
| `updated_at` | TEXT | NO | |

**PK:** `resource_id`

**UNIQUE:** `uq_managed_resources_router_kind_key` ON (`router_id`, `resource_kind`, `logical_key`)

**Indexes:**

- `idx_managed_resources_router_lifecycle` ON (`router_id`, `lifecycle_status`)

### 2.14 `change_plans`

| Column | Type | Null | Notes |
|---|---|---|---|
| `plan_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `revision_id` | TEXT | NO | FK → `desired_revisions.revision_id` |
| `observation_id` | TEXT | NO | FK → `router_observations.observation_id` |
| `expected_desired_digest` | TEXT | NO | |
| `observed_resource_version` | TEXT | NO | |
| `observed_state_digest` | TEXT | NO | |
| `plan_digest` | TEXT | NO | content hash for Confirm |
| `risk_class` | TEXT | NO | |
| `requires_backup` | INTEGER | NO | CHECK IN (0,1) |
| `requires_fail_safe` | INTEGER | NO | CHECK IN (0,1) |
| `expires_at` | TEXT | NO | |
| `confirmation_state` | TEXT | NO | `Draft \| Confirmed \| Expired \| Superseded` |
| `confirmed_at` | TEXT | YES | |
| `confirmed_by_actor` | TEXT | YES | session-bound |
| `actor_type` | TEXT | NO | |
| `actor_id` | TEXT | YES | |
| `metadata_json` | TEXT | YES | redacted confirmation/risk blob |
| `created_at` | TEXT | NO | |

**PK:** `plan_id`

**Indexes:**

- `idx_change_plans_router_created` ON (`router_id`, `created_at` DESC)
- `idx_change_plans_router_confirmation` ON (`router_id`, `confirmation_state`, `expires_at`)

Plans are **immutable** after insert except `confirmation_state` / confirm timestamp fields updated by Confirm flow in conditional txn.

### 2.15 `change_plan_items`

| Column | Type | Null | Notes |
|---|---|---|---|
| `plan_item_id` | TEXT | NO | PK |
| `plan_id` | TEXT | NO | FK → `change_plans.plan_id` ON DELETE CASCADE |
| `ordinal` | INTEGER | NO | ordered |
| `change_kind` | TEXT | NO | high-level intent label |
| `target_resource_id` | TEXT | YES | FK → `managed_resources.resource_id` |
| `precondition_json` | TEXT | YES | redacted |
| `postcondition_json` | TEXT | YES | redacted |
| `ownership_impact` | TEXT | YES | |

**PK:** `plan_item_id`

**UNIQUE:** `uq_change_plan_items_plan_ordinal` ON (`plan_id`, `ordinal`)

**CHECK:** `ordinal >= 0`

**Forbidden:** raw RCI commands, secrets.

### 2.16 `operations`

| Column | Type | Null | Notes |
|---|---|---|---|
| `operation_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `plan_id` | TEXT | YES | FK → `change_plans.plan_id` |
| `operation_kind` | TEXT | NO | |
| `aggregate_status` | TEXT | NO | reconcile lifecycle status |
| `actor_type` | TEXT | NO | |
| `actor_id` | TEXT | YES | |
| `idempotency_record_id` | TEXT | NO | FK → `idempotency_records.idempotency_record_id` (`DEFERRABLE INITIALLY DEFERRED`) |
| `correlation_id` | TEXT | YES | |
| `created_at` | TEXT | NO | |
| `updated_at` | TEXT | NO | |
| `terminal_at` | TEXT | YES | |

**PK:** `operation_id`

**FK:** `router_id` → `routers`; `plan_id` → `change_plans`; `idempotency_record_id` → `idempotency_records` (`DEFERRABLE INITIALLY DEFERRED`)

**UNIQUE:** `uq_operations_idempotency_record_id` ON (`idempotency_record_id`) — one-to-one with `idempotency_records`

**Indexes:**

- `idx_operations_router_created` ON (`router_id`, `created_at` DESC)
- `idx_operations_correlation_id` ON (`correlation_id`)

`Operation` is user intent; **must not** be reissued as a new user request on recovery — resume via new `Job` attempt (§5).

### 2.17 `jobs`

| Column | Type | Null | Notes |
|---|---|---|---|
| `job_id` | TEXT | NO | PK |
| `operation_id` | TEXT | NO | FK → `operations.operation_id` |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `attempt` | INTEGER | NO | monotonic per operation |
| `status` | TEXT | NO | see §4.2 |
| `lease_owner` | TEXT | YES | unique worker id |
| `lease_until_epoch` | INTEGER | YES | |
| `heartbeat_at` | TEXT | YES | |
| `fencing_token` | INTEGER | NO | monotonic; default 0 at create |
| `recovery_state` | TEXT | YES | |
| `cancel_requested` | INTEGER | NO | CHECK IN (0,1); default 0 |
| `terminal_outcome` | TEXT | YES | redacted summary |
| `created_at` | TEXT | NO | |
| `updated_at` | TEXT | NO | |
| `started_at` | TEXT | YES | |
| `finished_at` | TEXT | YES | |

**PK:** `job_id`

**UNIQUE:** `uq_jobs_operation_attempt` ON (`operation_id`, `attempt`)

**CHECK:** `attempt >= 1`

**CHECK:** `status IN ('Queued', 'Leased', 'Running', 'Succeeded', 'Failed', 'Cancelled', 'Lost', 'RecoveryRequired')`

**Indexes:**

- `idx_jobs_router_status` ON (`router_id`, `status`)
- `idx_jobs_status_lease_until` ON (`status`, `lease_until_epoch`) — claim scan
- `idx_jobs_lease_owner` ON (`lease_owner`) WHERE `lease_owner IS NOT NULL`

### 2.18 `job_steps`

| Column | Type | Null | Notes |
|---|---|---|---|
| `step_id` | TEXT | NO | PK |
| `job_id` | TEXT | NO | FK → `jobs.job_id` ON DELETE CASCADE |
| `ordinal` | INTEGER | NO | deterministic order |
| `step_kind` | TEXT | NO | e.g. `preflight`, `apply`, `verify` |
| `status` | TEXT | NO | `Pending \| Running \| Succeeded \| Failed \| CompensationRequired \| RecoveryRequired` |
| `attempt` | INTEGER | NO | per-step retry counter |
| `checkpoint_json` | TEXT | YES | redacted facts only |
| `result_artifact_id` | TEXT | YES | FK → `artifacts.artifact_id` |
| `observation_id` | TEXT | YES | FK → `router_observations.observation_id` |
| `external_correlation` | TEXT | YES | adapter/router correlation |
| `error_redacted` | TEXT | YES | |
| `started_at` | TEXT | YES | |
| `finished_at` | TEXT | YES | |

**PK:** `step_id`

**UNIQUE:** `uq_job_steps_job_ordinal` ON (`job_id`, `ordinal`)

**Indexes:**

- `idx_job_steps_job_status` ON (`job_id`, `status`)

Checkpoint **must** be written only after confirmed step result; **forbidden** before external I/O completes.

### 2.19 `router_mutation_locks`

| Column | Type | Null | Notes |
|---|---|---|---|
| `router_id` | TEXT | NO | PK, FK → `routers.router_id` |
| `active_job_id` | TEXT | YES | FK → `jobs.job_id` |
| `lock_owner` | TEXT | YES | |
| `lock_until_epoch` | INTEGER | YES | |
| `fencing_token` | INTEGER | NO | matches active job attempt fence |
| `updated_at` | TEXT | NO | |

**PK:** `router_id`

At most **one** active mutation job per `router_id` **must** be enforced via this row plus conditional transactions (§5).

### 2.20 `idempotency_records`

| Column | Type | Null | Notes |
|---|---|---|---|
| `idempotency_record_id` | TEXT | NO | PK |
| `scope` | TEXT | NO | e.g. actor/API scope |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `operation_kind` | TEXT | NO | |
| `idempotency_key` | TEXT | NO | client-supplied |
| `request_digest` | TEXT | NO | canonical request hash |
| `operation_id` | TEXT | NO | FK → `operations.operation_id` (`DEFERRABLE INITIALLY DEFERRED`) |
| `response_ref` | TEXT | YES | serialized terminal response locator |
| `status` | TEXT | NO | `InProgress \| Completed \| Conflict` |
| `created_at` | TEXT | NO | |
| `expires_at` | TEXT | NO | |

**PK:** `idempotency_record_id`

**FK:** `router_id` → `routers`; `operation_id` → `operations` (`DEFERRABLE INITIALLY DEFERRED`)

**UNIQUE:** `uq_idempotency_scope_router_kind_key` ON (`scope`, `router_id`, `operation_kind`, `idempotency_key`)
**UNIQUE:** `uq_idempotency_records_operation_id` ON (`operation_id`) — one-to-one with `operations`

**Indexes:**

- `idx_idempotency_expires_at` ON (`expires_at`)

### 2.21 `audit_events`

| Column | Type | Null | Notes |
|---|---|---|---|
| `audit_event_id` | TEXT | NO | PK |
| `occurred_at` | TEXT | NO | |
| `actor_type` | TEXT | NO | |
| `actor_id` | TEXT | YES | |
| `request_id` | TEXT | YES | |
| `correlation_id` | TEXT | YES | |
| `router_id` | TEXT | YES | FK → `routers.router_id` |
| `operation_id` | TEXT | YES | FK → `operations.operation_id` |
| `job_id` | TEXT | YES | FK → `jobs.job_id` |
| `plan_id` | TEXT | YES | FK → `change_plans.plan_id` |
| `action` | TEXT | NO | |
| `outcome` | TEXT | NO | |
| `risk_level` | TEXT | YES | |
| `summary_redacted` | TEXT | YES | |
| `request_digest` | TEXT | YES | |
| `hub_version` | TEXT | YES | |
| `adapter_version` | TEXT | YES | |

**PK:** `audit_event_id`

**Indexes:**

- `idx_audit_events_occurred_at` ON (`occurred_at` DESC)
- `idx_audit_events_router_occurred` ON (`router_id`, `occurred_at` DESC)
- `idx_audit_events_correlation_id` ON (`correlation_id`)

**Append-only:** UPDATE and DELETE **forbidden** except archival copy-forward outside hot path.

### 2.22 `backup_artifacts`

| Column | Type | Null | Notes |
|---|---|---|---|
| `artifact_id` | TEXT | NO | PK |
| `router_id` | TEXT | NO | FK → `routers.router_id` |
| `operation_id` | TEXT | YES | FK → `operations.operation_id` |
| `kind` | TEXT | NO | |
| `storage_locator` | TEXT | NO | path/key outside SQLite |
| `content_digest` | TEXT | NO | |
| `size_bytes` | INTEGER | NO | |
| `identity_fingerprint` | TEXT | NO | |
| `source_observation_id` | TEXT | YES | FK → `router_observations.observation_id` |
| `source_revision_id` | TEXT | YES | FK → `desired_revisions.revision_id` |
| `encryption_metadata_json` | TEXT | YES | redacted |
| `verification_status` | TEXT | NO | |
| `retention_until` | TEXT | YES | |
| `created_at` | TEXT | NO | |

**PK:** `artifact_id`

**Indexes:**

- `idx_backup_artifacts_router_created` ON (`router_id`, `created_at` DESC)

Bytes **must** be published before metadata row is visible (§8.5).

### 2.23 `artifacts`

General plan/job/diagnostic artifact metadata.

| Column | Type | Null | Notes |
|---|---|---|---|
| `artifact_id` | TEXT | NO | PK |
| `router_id` | TEXT | YES | FK → `routers.router_id` |
| `operation_id` | TEXT | YES | FK → `operations.operation_id` |
| `job_id` | TEXT | YES | FK → `jobs.job_id` |
| `plan_id` | TEXT | YES | FK → `change_plans.plan_id` |
| `kind` | TEXT | NO | |
| `storage_locator` | TEXT | NO | |
| `content_digest` | TEXT | NO | |
| `size_bytes` | INTEGER | NO | |
| `metadata_json` | TEXT | YES | redacted |
| `published_at` | TEXT | NO | set only after bytes verified |
| `retention_until` | TEXT | YES | |
| `created_at` | TEXT | NO | |

**PK:** `artifact_id`

**Indexes:**

- `idx_artifacts_router_kind` ON (`router_id`, `kind`)
- `idx_artifacts_operation_id` ON (`operation_id`)

### 2.24 `audit_event_artifacts`

Normalized artifact links for audit events. Logical schema follows `audit_events` (§2.21); migration DDL **must** create this table **after** `artifacts` (§2.23) so FK targets exist.

| Column | Type | Null | Notes |
|---|---|---|---|
| `audit_event_id` | TEXT | NO | FK → `audit_events.audit_event_id` |
| `artifact_id` | TEXT | NO | FK → `artifacts.artifact_id` |

**PK:** (`audit_event_id`, `artifact_id`)

**FK:** `audit_event_id` → `audit_events` (`ON DELETE RESTRICT`); `artifact_id` → `artifacts` (`ON DELETE RESTRICT`) — preserves append-only audit and retention invariants

**Indexes:**

- `idx_audit_event_artifacts_artifact_id` ON (`artifact_id`)

### 2.25 Deferred tables (no API v0 write path)

The following tables reserve multi-router keys for later phases. Migrations **may** create empty schema in a future phase; Phase 0b **must not** implement API handlers or write repositories for them:

| Table group | Purpose | Phase |
|---|---|---|
| `route_sets`, `route_set_entries`, `route_resource_bindings` | Versioned managed routing policy | routes phase |
| `traffic_observations`, `route_proposals` | Traffic evidence and proposals | TrafficDiscovery phase |

**Forbidden in v0:** hidden write path, background mutation, or plan items referencing these tables before their safety gates open.

---

## 3. Revisions, concurrency, ETag, observations

### 3.1 Immutable desired revisions

- New operator intent **must** insert a new `desired_revisions` row with `revision_number = MAX(revision_number)+1` for that `router_id` in the **same transaction** that conditionally updates `router_revision_state.current_desired_revision_id`.
- Existing revision rows **must not** be updated or deleted while referenced.
- API ETag **must** derive from stable `revision_id` and/or `canonical_digest`.

### 3.2 If-Match / lost-update prevention

- Mutation requests carrying `If-Match` **must** compare against current desired ETag **inside the same SQLite transaction** that would create plan or revision.
- Mismatch **must** fail closed with conflict/precondition failure; **must not** partially create plan or revision.

### 3.3 Observations and TTL

- `RouterObservation` rows are immutable; freshness requires `collection_status = Succeeded`, identity match, and `now <= valid_until`.
- Stale observations remain queryable history but **must not** back new mutation plans.
- `change_plans` **must** store exact `revision_id`, `observation_id`, `observed_resource_version`, and digests; stale plan **must not** be «refreshed» by field substitution — new observation + new plan required.

### 3.4 Applied revision rule

`router_revision_state.applied_revision_id` **must** update **only** inside the verify-success transaction that:

1. completes successful read-back step;
2. proves postconditions for managed resources;
3. still holds valid lease/fencing for the mutation job.

Command dispatch, HTTP 200, or completed apply step **must not** alone advance applied marker.

### 3.5 Pre-apply revalidation

Before first mutation step after lease, worker **must** transactionally re-check: plan confirmed and unexpired; current desired pointer matches plan; observation still fresh; identity/capability gates valid; mutation lock acquired. Any failure **must** abort without adapter write.

---

## 4. Operations, jobs, steps, and locks

### 4.1 Separation of concerns

| Layer | Responsibility |
|---|---|
| `Operation` | API-visible user intent; aggregate lifecycle |
| `Job` | Single durable execution attempt with lease/recovery |
| `Step` | Ordered checkpoint unit |

Recovery **must** create or resume a `Job` attempt per explicit rules; **must not** mint a new `Operation` for the same user intent.

### 4.2 Job status vocabulary

**Claim pool:** `Queued`

**In-flight:** `Leased`, `Running`

**Terminal:** `Succeeded`, `Failed`, `Cancelled`, `Lost`, `RecoveryRequired`

Terminal statuses **must not** return to running.

### 4.3 Step status transitions

Allowed transitions per step:

```text
Pending → Running → Succeeded
                 → Failed
                 → CompensationRequired
                 → RecoveryRequired
```

Updates **must** use expected-status guard (`WHERE status = ?`) and valid lease/fencing token.

### 4.4 BEGIN IMMEDIATE claim

Worker **must** claim in a short transaction:

```text
BEGIN IMMEDIATE;
-- select one claimable job (Queued, lease expired, or recovery-eligible)
UPDATE jobs SET status='Leased', lease_owner=?, lease_until_epoch=?, fencing_token=fencing_token+1, ...
  WHERE job_id=? AND status='Queued' AND ...;
-- acquire router_mutation_locks row for mutation jobs
COMMIT;
```

Exactly one contender **must** succeed; others **must** observe zero rows updated.

### 4.5 Leases, heartbeat, fencing

Each active `Job` **must** maintain:

- unique `lease_owner`;
- `lease_until_epoch` renewed via heartbeat;
- monotonic `fencing_token` incremented on claim;
- monotonic `attempt` per `operation_id`.

All post-claim writes **must** verify `lease_owner`, unexpired lease (or grace policy), and matching `fencing_token`. Late stale worker reports **must** be rejected.

### 4.6 One mutation per RouterId

For mutation `operation_kind`, at most one job in `{Leased, Running}` per `router_id` **must** be enforced using `router_mutation_locks` and conditional updates, not only in-process locks. Read-only jobs **may** run in parallel when no conflicting fail-safe session exists ([`RCI_POLICY.md`](RCI_POLICY.md)).

### 4.7 No long router I/O inside SQLite transactions

SQLite transactions **must** only record intent, checkpoints, and conditional state transitions. Adapter/router I/O **must** occur **after** commit. Result recording **must** use a separate conditional transaction with lease/fence checks.

### 4.8 Minimum mutation step chain

Ordered steps **must** align with [`RCI_POLICY.md`](RCI_POLICY.md): `preflight` → `identity-check` → `observe` → `backup` → `plan-preconditions` → Confirm gate → `begin-fail-safe-configuration` → `apply` → `read-back` → `verify` → save/compensate → audit.

Successful steps **must not** repeat if postcondition still provable from persisted checkpoint and fresh evidence.

---

## 5. Crash, startup recovery, and cancellation

### 5.1 Startup recovery worker

On Router Control startup, recovery **must**:

1. leave terminal jobs unchanged;
2. return safe `Queued` jobs to claimable pool;
3. find `Leased`/`Running` jobs with expired lease;
4. mark attempt `Lost` and classify last checkpoint;
5. if external mutation unlikely — create resume attempt with new `Job` row;
6. if mutation may have occurred — **must** run identity check and read-back **before** resume apply;
7. continue verify/commit, compensation, or set `RecoveryRequired`.

### 5.2 Unknown external outcome

Timeout or crash **after** command dispatch **must** be treated as unknown outcome, **not** automatic failure. **Forbidden:** blind retry of apply. **Required:** read-back, compare managed resources, then resume, compensate, or `RecoveryRequired`.

### 5.3 Cancellation boundaries

| Job state | Cancel behavior |
|---|---|
| `Queued` | immediate terminal `Cancelled` |
| `Leased`/`Running` | durable `cancel_requested=1`; worker stops at safe step boundary only |
| post external mutation | verify/compensate; cancel **must not** pretend mutation did not happen |

Cancel **must not** delete audit history or idempotency records.

**Cancel HTTP transaction:** `POST .../jobs/{job_id}/cancel` **must** commit the §6 creation bundle for `operation_kind: cancel_job` (including initial `jobs` row, immediately terminal when the cancel HTTP outcome is final — **202** `cancel_requested` or **200** `Cancelled`) **and** conditionally UPDATE the **target** `jobs` row per the table above in one SQLite transaction. Cancel **must not** skip step 6 initial `jobs` INSERT.

**Cancel idempotency terminal semantics:** The cancel-control operation's stored HTTP outcome (**202** or **200**) is the idempotency "terminal response" for replay. A **202** `cancel_requested` outcome is terminal for the **cancel operation** even when the **target** job remains `Leased`/`Running` with `cancel_requested=1` until the worker reaches a safe boundary.

**Cancel idempotency single-update policy:** Cancel is the **only** mutation where the `idempotency_records` stored HTTP response **may** change after the first cancel HTTP commit. When the first cancel on a `Leased`/`Running` target commits, the stored response **must** be **202** `cancel_requested`. When the **target** job later reaches `Cancelled`, implementation **must** UPDATE that same `idempotency_record` stored HTTP response **exactly once** to **200** `Cancelled`. Same `Idempotency-Key` + digest replay **must** return whatever is currently stored (**202** while the target is still `cancel_requested` or in-flight; **200** after that required single update) and **must not** re-notify the worker, create a second cancel operation, or INSERT a second `idempotency_record`. Queued first-cancel remains **200** immediately with no later update. Terminal target on first cancel → **409**; different digest → **409** conflict.

---

## 6. Idempotency

All mutation API requests **must** carry `Idempotency-Key`.

**Cyclic FK deferral:** `operations.idempotency_record_id` → `idempotency_records` and `idempotency_records.operation_id` → `operations` are `DEFERRABLE INITIALLY DEFERRED`. Integrity for this pair is enforced at **COMMIT** only. All other foreign keys remain **immediate** unless explicitly stated elsewhere.

Creation transaction **must** atomically (single SQLite transaction; `PRAGMA foreign_keys=ON`):

1. compute canonical `request_digest`;
2. lookup existing idempotency by (`scope`, `router_id`, `operation_kind`, `idempotency_key`) — return early on replay/conflict per table below;
3. pre-generate opaque `operation_id` and `idempotency_record_id` (application-generated; never reused);
4. INSERT `operations` with both IDs populated (`idempotency_record_id` **NOT NULL**);
5. INSERT `idempotency_records` referencing the same pre-generated IDs;
6. INSERT initial `jobs` row — **required for every §6 commit**; for sync HTTP mutations that complete in-request ([`API_CONTRACT.md`](API_CONTRACT.md) §4.3, §9.2), this row **may** be inserted with terminal `status` (`Succeeded`, `Failed`, or `Cancelled`) and `finished_at` populated in the same transaction after domain work; for async accepts, initial `status` **must** be non-terminal (`Queued`, or `Running` only after claim per §4.4);
7. append `audit_events` (and `audit_event_artifacts` rows when artifact links exist);
8. COMMIT (deferred cyclic FKs validated here; roll back all on any failure).

**Forbidden:** INSERT `operations` with NULL `idempotency_record_id`; UPDATE-through-NULL to link idempotency; COMMIT leaving an operation without a linked idempotency record (orphan operation).

| Replay condition | Result |
|---|---|
| same key + same digest (general) | return existing operation/terminal response |
| same key + same digest (cancel; target still `cancel_requested` or in-flight) | replay stored **202** `cancel_requested` response (no worker re-notify) |
| same key + same digest (cancel; target terminal `Cancelled`) | replay stored **200** `Cancelled` response after the §5.3 required single update (**must** persist **200** when target reaches `Cancelled`; no second cancel op) |
| same key + different digest | conflict; **must not** create second operation |
| expired record | fail closed per API policy; **must not** silently reuse |

HTTP idempotency **must not** be confused with adapter step idempotency — each apply step still requires read-before-write, deterministic logical resource key, and postcondition proof ([`RCI_POLICY.md`](RCI_POLICY.md) §6).

Retention **must not** delete idempotency rows before client retry window and job recovery window elapse. Expiry **must** cover the retry/recovery window and **must not** expire before linked operation recovery completes. Idempotency retention **must not** outrun audit/operation retention (ADR-002); longer audit retention **must not** require idempotency to outlive linked operations.

---

## 7. Audit and secrets boundary

### 7.1 Append-only audit

`audit_events` **must** be insert-only in normal operation. Audit **must not** substitute for mutable job state.

### 7.2 Atomic creation bundle

Operation creation **must** commit idempotency record, operation, initial job, and audit event together or roll back all, using the insert order in [§6](#6-idempotency) steps 4–7 (pre-generated IDs; `operations` and `idempotency_records` inserts before `jobs` and `audit_events`; cyclic FK checks at COMMIT).

### 7.3 Secrets and redaction

Aligned with [`SECURITY_OPS.md`](SECURITY_OPS.md):

- **Forbidden in SQLite domain/job/audit fields:** router passwords, AWG private/PSK material, raw RCI sessions, startup-config full content, DPAPI plaintext/ciphertext blobs.
- `credential_refs` stores opaque metadata and provider locator only; resolve occurs in-process via vault port for adapter use only. Profile and audit relational links **must** use `vpn_profile_secret_refs` and `audit_event_artifacts`, not JSON ID arrays.
- Plans, steps, checkpoints, and audit summaries **must** use redacted digests and stable placeholders.

### 7.4 CredentialRef lifecycle

Revoked or rotated refs **must** block new jobs referencing them; in-flight jobs **must** fail closed or complete verify before revocation takes effect per security contract.

---

## 8. Migrations, backup, restore, and retention

### 8.1 Migration chain (contractual requirements)

1. Shipped migration files **must never** be edited or renumbered; changes add new version only.
2. Startup **must** verify contiguous versions before write path opens.
3. If no pending migrations, startup **must** no-op idempotently without backup.
4. Before first pending migration on non-empty DB, **must** create consistent verified backup (§8.2).
5. Each migration and `user_version` bump **must** run in one transaction; failure rolls back that migration and blocks Router Control startup (not whole Hub).
6. Default migrations additive; destructive rebuild requires tested migration, disk-space check, restore drill.
7. Incompatible future schema → Router Control fail-closed; **forbidden** silent downgrade.

**Phase 0b delivers this contract only — no migration scripts in repository.**

### 8.2 Online backup before migrate

Backup **must not** copy open WAL file blindly. Use SQLite online backup API or checkpointed close to temp path; run integrity/quick check, size/digest verification, fsync; atomic rename to timestamped final backup. Migrations **must not** start until backup publication succeeds.

Backup metadata **must** record source schema version, timestamp, digest, size. Retention **must not** delete last verified pre-migration backup.

### 8.3 Restore

Restore **must** be offline/stopped Router Control: temp restore → integrity check → atomic replace. **Forbidden:** automatic silent schema rollback.

### 8.4 Connection policy

- `PRAGMA foreign_keys=ON` on every connection.
- Busy timeout bounded and measured; infinite retry **forbidden**.
- WAL permitted; checkpoint/backup **must** account for `-wal`/`-shm`; Windows behavior **must** be evidence-tested at implementation.
- Parameter binding required; string concatenation SQL **forbidden**.
- Write transitions **must** include expected state/version guard.
- Corruption/disk-full/permission errors → Router Control degraded/disabled + redacted ops event.

### 8.5 Artifact publication order

Large bytes **must** publish atomically:

1. write temp file;
2. flush/fsync;
3. verify digest/size;
4. atomic replace to final storage path;
5. insert/update metadata row (`published_at`, `storage_locator`, digest) in SQLite **only after** bytes verified.

Reverse order **forbidden**.

### 8.6 Retention invariants

| Data class | Rule |
|---|---|
| Desired revisions, ownership, applied markers | retained while router enrolled and audit/recovery requires |
| Observations | last fresh + any referenced by active plan/job **must not** be deleted early |
| Operations/jobs/steps/idempotency | **must not** delete before recovery/retry window ends |
| Audit | append-only; long retention/export policy separate |
| Artifact bytes | delete only after metadata dereferenced and retention policy satisfied; metadata first in txn, bytes via recoverable cleanup |

Retention compaction **must not** expire idempotency before retry/recovery window ([§6](#6-idempotency)).

### 8.7 Deterministic evidence requirements (implementation phase)

Without prescribing migration code, implementation **must** demonstrate:

1. idempotent re-run of migrations on current DB;
2. fault injection per migration leaves prior version readable and backup verifiable;
3. two workers cannot claim two mutation jobs for same `RouterId`;
4. expired lease + stale worker cannot double-apply;
5. crash before/after each step recovers via checkpoint/read-back or ends `RecoveryRequired`;
6. concurrent desired update with stale `If-Match` rejected;
7. stale observation/plan cannot start mutation;
8. unknown managed outcome not retried without read-back;
9. DB/jobs/audit/artifact search finds no plaintext secrets;
10. `router_control.sqlite3` outage does not block other Hub services startup.

Evidence test matrix: [`TEST_STRATEGY.md`](TEST_STRATEGY.md) §7.

---

## 9. Links

- Domain entities: [`DOMAIN_MODEL.md`](../DOMAIN_MODEL.md)
- HTTP/API surface: [`API_CONTRACT.md`](API_CONTRACT.md)
- RCI lifecycle and step order: [`RCI_POLICY.md`](RCI_POLICY.md)
- Secrets, Confirm, audit policy: [`SECURITY_OPS.md`](SECURITY_OPS.md)
- Architecture isolation: [`ARCHITECTURE.md`](../ARCHITECTURE.md)
- Canonical invariants: [`CANONICAL.md`](../CANONICAL.md)
- ADR decision record: [`adrs/0002-persistence-jobs-sqlite.md`](../adrs/0002-persistence-jobs-sqlite.md)
- Test strategy (persistence fault matrix): [`TEST_STRATEGY.md`](TEST_STRATEGY.md)
- Contracts index: [`README.md`](README.md)
