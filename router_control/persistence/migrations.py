"""Contiguous migration chain. Shipped migrations are immutable.

Cyclic FK note (operations ↔ idempotency_records; routers ↔ credential_refs):
SQLite cannot create mutual REFERENCES at CREATE TABLE time. Integrity is enforced by:
pre-generated IDs, atomic single-transaction insert order, and UNIQUE 1:1 constraints.
Never leave orphan operations or NULL idempotency_record_id.
"""

from __future__ import annotations

import sqlite3

CURRENT_USER_VERSION = 1

_MIGRATION_1 = """
CREATE TABLE sites (
  site_id TEXT NOT NULL PRIMARY KEY,
  display_name TEXT NOT NULL,
  timezone TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE routers (
  router_id TEXT NOT NULL PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE RESTRICT,
  display_name TEXT NOT NULL,
  vendor TEXT NOT NULL,
  model TEXT NOT NULL,
  hardware_revision TEXT,
  identity_fingerprint TEXT NOT NULL,
  identity_claims_json TEXT,
  credential_ref_id TEXT,
  lifecycle_status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX idx_routers_site_id ON routers(site_id);
CREATE INDEX idx_routers_lifecycle_status ON routers(lifecycle_status);

CREATE TABLE router_endpoints (
  endpoint_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  kind TEXT NOT NULL,
  host TEXT NOT NULL,
  port INTEGER NOT NULL,
  priority INTEGER NOT NULL,
  is_enabled INTEGER NOT NULL CHECK (is_enabled IN (0, 1)),
  last_success_at TEXT,
  last_failure_at TEXT,
  last_error_redacted TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (router_id, kind, host, port)
);
CREATE INDEX idx_router_endpoints_router_priority
  ON router_endpoints(router_id, priority, is_enabled);

CREATE TABLE router_capabilities (
  capability_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  firmware_version TEXT NOT NULL,
  firmware_build TEXT,
  firmware_channel TEXT,
  component_set_digest TEXT NOT NULL,
  capabilities_json TEXT,
  certification_status TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_router_capabilities_router_observed
  ON router_capabilities(router_id, observed_at DESC);
CREATE INDEX idx_router_capabilities_router_valid_until
  ON router_capabilities(router_id, valid_until);

CREATE TABLE credential_refs (
  credential_ref_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  kind TEXT NOT NULL,
  provider TEXT NOT NULL,
  provider_locator TEXT NOT NULL,
  created_at TEXT NOT NULL,
  rotated_at TEXT,
  revoked_at TEXT
);
CREATE INDEX idx_credential_refs_router_kind ON credential_refs(router_id, kind);
CREATE INDEX idx_credential_refs_revoked_at ON credential_refs(revoked_at)
  WHERE revoked_at IS NOT NULL;

CREATE TABLE vpn_profile_artifacts (
  profile_id TEXT NOT NULL PRIMARY KEY,
  display_name TEXT NOT NULL,
  vpn_kind TEXT NOT NULL,
  parser_version TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  metadata_json TEXT,
  validation_status TEXT NOT NULL,
  unsupported_fields_json TEXT,
  created_at TEXT NOT NULL,
  superseded_at TEXT
);
CREATE INDEX idx_vpn_profile_artifacts_vpn_kind
  ON vpn_profile_artifacts(vpn_kind, validation_status);
CREATE INDEX idx_vpn_profile_artifacts_superseded_at
  ON vpn_profile_artifacts(superseded_at);

CREATE TABLE vpn_profile_secret_refs (
  profile_id TEXT NOT NULL REFERENCES vpn_profile_artifacts(profile_id) ON DELETE CASCADE,
  credential_ref_id TEXT NOT NULL REFERENCES credential_refs(credential_ref_id) ON DELETE RESTRICT,
  role TEXT NOT NULL,
  created_at TEXT NOT NULL,
  PRIMARY KEY (profile_id, credential_ref_id, role)
);
CREATE INDEX idx_vpn_profile_secret_refs_credential_ref_id
  ON vpn_profile_secret_refs(credential_ref_id);
CREATE INDEX idx_vpn_profile_secret_refs_credential_role
  ON vpn_profile_secret_refs(credential_ref_id, role);

CREATE TABLE tunnel_assignments (
  assignment_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  profile_id TEXT NOT NULL REFERENCES vpn_profile_artifacts(profile_id) ON DELETE RESTRICT,
  logical_role TEXT NOT NULL,
  desired_active INTEGER NOT NULL CHECK (desired_active IN (0, 1)),
  policy_metadata_json TEXT,
  observed_vendor_locator TEXT,
  created_at TEXT NOT NULL,
  retired_at TEXT
);
CREATE INDEX idx_tunnel_assignments_router_role
  ON tunnel_assignments(router_id, logical_role);
CREATE INDEX idx_tunnel_assignments_router_active
  ON tunnel_assignments(router_id, desired_active, retired_at);

CREATE TABLE router_observations (
  observation_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  capability_id TEXT REFERENCES router_capabilities(capability_id) ON DELETE RESTRICT,
  identity_fingerprint TEXT NOT NULL,
  resource_version TEXT NOT NULL,
  state_digest TEXT NOT NULL,
  state_snapshot_json TEXT,
  collection_status TEXT NOT NULL,
  error_redacted TEXT,
  source TEXT NOT NULL,
  adapter_version TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_router_observations_router_observed
  ON router_observations(router_id, observed_at DESC);
CREATE INDEX idx_router_observations_router_valid_until
  ON router_observations(router_id, valid_until);

CREATE TABLE observation_resources (
  observation_resource_id TEXT NOT NULL PRIMARY KEY,
  observation_id TEXT NOT NULL REFERENCES router_observations(observation_id) ON DELETE CASCADE,
  resource_kind TEXT NOT NULL,
  logical_key TEXT NOT NULL,
  vendor_locator TEXT,
  fingerprint TEXT,
  snapshot_ref TEXT,
  snapshot_digest TEXT,
  ordinal INTEGER NOT NULL,
  UNIQUE (observation_id, resource_kind, logical_key)
);
CREATE INDEX idx_observation_resources_observation_ordinal
  ON observation_resources(observation_id, ordinal);

CREATE TABLE desired_revisions (
  revision_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  revision_number INTEGER NOT NULL CHECK (revision_number > 0),
  parent_revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  canonical_digest TEXT NOT NULL,
  desired_document_json TEXT,
  based_on_observation_id TEXT REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  reason TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (router_id, revision_number)
);
CREATE INDEX idx_desired_revisions_router_created
  ON desired_revisions(router_id, created_at DESC);

CREATE TABLE router_revision_state (
  router_id TEXT NOT NULL PRIMARY KEY REFERENCES routers(router_id) ON DELETE RESTRICT,
  current_desired_revision_id TEXT NOT NULL
    REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  applied_revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  last_observation_id TEXT REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  updated_at TEXT NOT NULL
);

CREATE TABLE managed_resources (
  resource_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  resource_kind TEXT NOT NULL,
  logical_key TEXT NOT NULL,
  owner TEXT NOT NULL,
  creating_revision_id TEXT NOT NULL REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  vendor_locator TEXT,
  locator_fingerprint TEXT,
  lifecycle_status TEXT NOT NULL,
  last_observation_id TEXT REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (router_id, resource_kind, logical_key)
);
CREATE INDEX idx_managed_resources_router_lifecycle
  ON managed_resources(router_id, lifecycle_status);

CREATE TABLE change_plans (
  plan_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  revision_id TEXT NOT NULL REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  observation_id TEXT NOT NULL REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  expected_desired_digest TEXT NOT NULL,
  observed_resource_version TEXT NOT NULL,
  observed_state_digest TEXT NOT NULL,
  plan_digest TEXT NOT NULL,
  risk_class TEXT NOT NULL,
  requires_backup INTEGER NOT NULL CHECK (requires_backup IN (0, 1)),
  requires_fail_safe INTEGER NOT NULL CHECK (requires_fail_safe IN (0, 1)),
  expires_at TEXT NOT NULL,
  confirmation_state TEXT NOT NULL,
  confirmed_at TEXT,
  confirmed_by_actor TEXT,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_change_plans_router_created ON change_plans(router_id, created_at DESC);
CREATE INDEX idx_change_plans_router_confirmation
  ON change_plans(router_id, confirmation_state, expires_at);

CREATE TABLE change_plan_items (
  plan_item_id TEXT NOT NULL PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES change_plans(plan_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  change_kind TEXT NOT NULL,
  target_resource_id TEXT REFERENCES managed_resources(resource_id) ON DELETE RESTRICT,
  precondition_json TEXT,
  postcondition_json TEXT,
  ownership_impact TEXT,
  UNIQUE (plan_id, ordinal)
);

CREATE TABLE operations (
  operation_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  plan_id TEXT REFERENCES change_plans(plan_id) ON DELETE RESTRICT,
  operation_kind TEXT NOT NULL,
  aggregate_status TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  idempotency_record_id TEXT NOT NULL,
  correlation_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  terminal_at TEXT,
  UNIQUE (idempotency_record_id)
);
CREATE INDEX idx_operations_router_created ON operations(router_id, created_at DESC);
CREATE INDEX idx_operations_correlation_id ON operations(correlation_id);

CREATE TABLE idempotency_records (
  idempotency_record_id TEXT NOT NULL PRIMARY KEY,
  scope TEXT NOT NULL,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  operation_kind TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  operation_id TEXT NOT NULL,
  response_ref TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  UNIQUE (scope, router_id, operation_kind, idempotency_key),
  UNIQUE (operation_id)
);
CREATE INDEX idx_idempotency_expires_at ON idempotency_records(expires_at);

CREATE TABLE jobs (
  job_id TEXT NOT NULL PRIMARY KEY,
  operation_id TEXT NOT NULL REFERENCES operations(operation_id) ON DELETE RESTRICT,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  attempt INTEGER NOT NULL CHECK (attempt >= 1),
  status TEXT NOT NULL CHECK (status IN (
    'Queued', 'Leased', 'Running', 'Succeeded', 'Failed',
    'Cancelled', 'Lost', 'RecoveryRequired'
  )),
  lease_owner TEXT,
  lease_until_epoch INTEGER,
  heartbeat_at TEXT,
  fencing_token INTEGER NOT NULL DEFAULT 0,
  recovery_state TEXT,
  cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
  terminal_outcome TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  UNIQUE (operation_id, attempt)
);
CREATE INDEX idx_jobs_router_status ON jobs(router_id, status);
CREATE INDEX idx_jobs_status_lease_until ON jobs(status, lease_until_epoch);
CREATE INDEX idx_jobs_lease_owner ON jobs(lease_owner) WHERE lease_owner IS NOT NULL;

CREATE TABLE router_mutation_locks (
  router_id TEXT NOT NULL PRIMARY KEY REFERENCES routers(router_id) ON DELETE RESTRICT,
  active_job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  lock_owner TEXT,
  lock_until_epoch INTEGER,
  fencing_token INTEGER NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL
);

CREATE TABLE artifacts (
  artifact_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT REFERENCES routers(router_id) ON DELETE RESTRICT,
  operation_id TEXT REFERENCES operations(operation_id) ON DELETE RESTRICT,
  job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  plan_id TEXT REFERENCES change_plans(plan_id) ON DELETE RESTRICT,
  kind TEXT NOT NULL,
  storage_locator TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  metadata_json TEXT,
  published_at TEXT NOT NULL,
  retention_until TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_artifacts_router_kind ON artifacts(router_id, kind);
CREATE INDEX idx_artifacts_operation_id ON artifacts(operation_id);

CREATE TABLE backup_artifacts (
  artifact_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  operation_id TEXT REFERENCES operations(operation_id) ON DELETE RESTRICT,
  kind TEXT NOT NULL,
  storage_locator TEXT NOT NULL,
  content_digest TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  identity_fingerprint TEXT NOT NULL,
  source_observation_id TEXT REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  source_revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  encryption_metadata_json TEXT,
  verification_status TEXT NOT NULL,
  retention_until TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_backup_artifacts_router_created
  ON backup_artifacts(router_id, created_at DESC);

CREATE TABLE job_steps (
  step_id TEXT NOT NULL PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  ordinal INTEGER NOT NULL,
  step_kind TEXT NOT NULL,
  status TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  checkpoint_json TEXT,
  result_artifact_id TEXT REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
  observation_id TEXT REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  external_correlation TEXT,
  error_redacted TEXT,
  started_at TEXT,
  finished_at TEXT,
  UNIQUE (job_id, ordinal)
);
CREATE INDEX idx_job_steps_job_status ON job_steps(job_id, status);

CREATE TABLE audit_events (
  audit_event_id TEXT NOT NULL PRIMARY KEY,
  occurred_at TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  request_id TEXT,
  correlation_id TEXT,
  router_id TEXT REFERENCES routers(router_id) ON DELETE RESTRICT,
  operation_id TEXT REFERENCES operations(operation_id) ON DELETE RESTRICT,
  job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  plan_id TEXT REFERENCES change_plans(plan_id) ON DELETE RESTRICT,
  action TEXT NOT NULL,
  outcome TEXT NOT NULL,
  risk_level TEXT,
  summary_redacted TEXT,
  request_digest TEXT,
  hub_version TEXT,
  adapter_version TEXT
);
CREATE INDEX idx_audit_events_occurred_at ON audit_events(occurred_at DESC);
CREATE INDEX idx_audit_events_router_occurred ON audit_events(router_id, occurred_at DESC);
CREATE INDEX idx_audit_events_correlation_id ON audit_events(correlation_id);

CREATE TABLE audit_event_artifacts (
  audit_event_id TEXT NOT NULL REFERENCES audit_events(audit_event_id) ON DELETE RESTRICT,
  artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
  PRIMARY KEY (audit_event_id, artifact_id)
);
CREATE INDEX idx_audit_event_artifacts_artifact_id ON audit_event_artifacts(artifact_id);

CREATE TABLE traffic_observations (
  traffic_observation_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  observed_at TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  evidence_json TEXT,
  source TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_traffic_observations_router_observed
  ON traffic_observations(router_id, observed_at DESC);

CREATE TABLE route_proposals (
  proposal_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  traffic_observation_id TEXT NOT NULL
    REFERENCES traffic_observations(traffic_observation_id) ON DELETE RESTRICT,
  proposal_digest TEXT NOT NULL,
  confidence REAL NOT NULL,
  expires_at TEXT NOT NULL,
  trusted_policy INTEGER NOT NULL DEFAULT 0 CHECK (trusted_policy IN (0, 1)),
  auto_apply_blocked INTEGER NOT NULL DEFAULT 1 CHECK (auto_apply_blocked IN (0, 1)),
  status TEXT NOT NULL,
  proposal_json TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_route_proposals_router_created ON route_proposals(router_id, created_at DESC);
CREATE INDEX idx_route_proposals_status ON route_proposals(status, expires_at);
"""


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations. Idempotent when already at CURRENT_USER_VERSION."""
    row = conn.execute("PRAGMA user_version").fetchone()
    current = int(row[0]) if row else 0
    if current > CURRENT_USER_VERSION:
        raise RuntimeError(
            f"Schema version {current} newer than supported {CURRENT_USER_VERSION}; fail-closed"
        )
    if current == CURRENT_USER_VERSION:
        return current
    if current == 0:
        # executescript runs as one script transaction; do not wrap with BEGIN/COMMIT
        conn.executescript(_MIGRATION_1)
        conn.execute(f"PRAGMA user_version = {CURRENT_USER_VERSION}")
        return CURRENT_USER_VERSION
    raise RuntimeError(f"Unsupported schema version {current}; contiguous chain broken")


def list_user_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [str(r[0]) for r in rows]
