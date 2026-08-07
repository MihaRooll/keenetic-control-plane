"""Contiguous migration chain. Shipped migrations are immutable.

Cyclic FK note (operations ↔ idempotency_records; routers ↔ credential_refs):
SQLite cannot create mutual REFERENCES at CREATE TABLE time. Integrity is enforced by:
pre-generated IDs, atomic single-transaction insert order, and UNIQUE 1:1 constraints.
Never leave orphan operations or NULL idempotency_record_id.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

CURRENT_USER_VERSION = 16
DEFAULT_DB_PATH = Path("data") / "router_control.sqlite3"

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

_MIGRATION_2 = """
CREATE TABLE commissioning_runs (
  run_id TEXT NOT NULL PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE RESTRICT,
  router_id TEXT REFERENCES routers(router_id) ON DELETE RESTRICT,
  state TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  idempotency_key TEXT,
  create_request_digest TEXT,
  correlation_id TEXT,
  mode TEXT NOT NULL CHECK (mode IN ('fake', 'live')),
  summary_redacted TEXT,
  report_digest TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  assessed_at TEXT,
  UNIQUE (site_id, idempotency_key)
);
CREATE INDEX idx_commissioning_runs_site_created
  ON commissioning_runs(site_id, created_at DESC);
CREATE INDEX idx_commissioning_runs_router_id ON commissioning_runs(router_id);

CREATE TABLE readiness_checks (
  check_id TEXT NOT NULL PRIMARY KEY,
  run_id TEXT NOT NULL REFERENCES commissioning_runs(run_id) ON DELETE CASCADE,
  check_kind TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
  attempt INTEGER NOT NULL CHECK (attempt >= 1),
  outcome TEXT NOT NULL CHECK (outcome IN ('Passed', 'Failed', 'Blocked', 'Skipped')),
  blocking INTEGER NOT NULL CHECK (blocking IN (0, 1)),
  write_related INTEGER NOT NULL CHECK (write_related IN (0, 1)),
  summary_redacted TEXT,
  evidence_digest TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_readiness_checks_run_ordinal
  ON readiness_checks(run_id, ordinal, attempt);

CREATE TABLE commissioning_idempotency (
  record_id TEXT NOT NULL PRIMARY KEY,
  scope_kind TEXT NOT NULL CHECK (scope_kind IN ('site', 'run')),
  scope_id TEXT NOT NULL,
  operation_kind TEXT NOT NULL CHECK (operation_kind IN ('create_run', 'assess', 'cancel')),
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  response_ref TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (scope_kind, scope_id, operation_kind, idempotency_key)
);
CREATE INDEX idx_commissioning_idempotency_scope
  ON commissioning_idempotency(scope_kind, scope_id, operation_kind);
"""

_MIGRATION_3 = """
CREATE TABLE event_presets (
  preset_id TEXT NOT NULL PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE RESTRICT,
  name TEXT NOT NULL,
  version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1),
  current_revision_id TEXT,
  published_revision_id TEXT,
  idempotency_key TEXT,
  create_request_digest TEXT,
  correlation_id TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (site_id, idempotency_key)
);
CREATE INDEX idx_event_presets_site ON event_presets(site_id, created_at DESC);

CREATE TABLE event_preset_revisions (
  revision_id TEXT NOT NULL PRIMARY KEY,
  preset_id TEXT NOT NULL REFERENCES event_presets(preset_id) ON DELETE CASCADE,
  revision_number INTEGER NOT NULL CHECK (revision_number >= 1),
  canonical_json TEXT NOT NULL,
  canonical_digest TEXT NOT NULL,
  validation_status TEXT NOT NULL,
  summary_redacted TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (preset_id, revision_number)
);
CREATE INDEX idx_event_preset_revisions_preset
  ON event_preset_revisions(preset_id, revision_number DESC);

CREATE TABLE event_preset_idempotency (
  record_id TEXT NOT NULL PRIMARY KEY,
  scope_kind TEXT NOT NULL CHECK (scope_kind IN ('site', 'preset')),
  scope_id TEXT NOT NULL,
  operation_kind TEXT NOT NULL CHECK (
    operation_kind IN ('create_preset', 'create_revision', 'publish')
  ),
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  response_ref TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (scope_kind, scope_id, operation_kind, idempotency_key)
);
CREATE INDEX idx_event_preset_idempotency_scope
  ON event_preset_idempotency(scope_kind, scope_id, operation_kind);
"""

_MIGRATION_4 = """
CREATE TABLE worker_instances (
  worker_instance_id TEXT NOT NULL PRIMARY KEY,
  process_id INTEGER NOT NULL,
  boot_id TEXT NOT NULL,
  hostname TEXT,
  lifecycle_status TEXT NOT NULL CHECK (lifecycle_status IN (
    'Starting', 'Running', 'Stopping', 'Stopped', 'Degraded'
  )),
  started_at_epoch INTEGER NOT NULL,
  stopped_at_epoch INTEGER,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (process_id, boot_id)
);

CREATE TABLE router_execution_fences (
  fence_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  fence_token INTEGER NOT NULL,
  lease_owner TEXT NOT NULL,
  mutex_holder_id TEXT NOT NULL,
  lease_until_epoch INTEGER NOT NULL,
  active_job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (router_id)
);
CREATE INDEX idx_router_execution_fences_lease_until
  ON router_execution_fences(lease_until_epoch);

CREATE TABLE external_effects (
  effect_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  operation_id TEXT REFERENCES operations(operation_id) ON DELETE RESTRICT,
  job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  effect_key TEXT NOT NULL,
  current_state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (router_id, effect_key)
);
CREATE INDEX idx_external_effects_router_state
  ON external_effects(router_id, current_state);

CREATE TABLE external_effect_events (
  event_id TEXT NOT NULL PRIMARY KEY,
  effect_id TEXT NOT NULL REFERENCES external_effects(effect_id) ON DELETE RESTRICT,
  from_state TEXT,
  to_state TEXT NOT NULL,
  actor_type TEXT NOT NULL,
  actor_id TEXT,
  summary_redacted TEXT,
  occurred_at TEXT NOT NULL
);
CREATE INDEX idx_external_effect_events_effect
  ON external_effect_events(effect_id, occurred_at);

CREATE TABLE effect_continuations (
  continuation_id TEXT NOT NULL PRIMARY KEY,
  effect_id TEXT NOT NULL REFERENCES external_effects(effect_id) ON DELETE RESTRICT,
  continuation_key TEXT NOT NULL,
  state TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (effect_id, continuation_key)
);

CREATE TABLE recovery_requests (
  request_id TEXT NOT NULL PRIMARY KEY,
  recovery_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  recovery_action TEXT NOT NULL,
  parent_request_id TEXT REFERENCES recovery_requests(request_id) ON DELETE RESTRICT,
  operation_id TEXT REFERENCES operations(operation_id) ON DELETE RESTRICT,
  job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  router_id TEXT REFERENCES routers(router_id) ON DELETE RESTRICT,
  status TEXT NOT NULL CHECK (status IN (
    'Pending', 'Active', 'Succeeded', 'Failed', 'Conflict'
  )),
  response_digest TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  terminal_at TEXT,
  UNIQUE (recovery_key, request_digest)
);
CREATE INDEX idx_recovery_requests_key ON recovery_requests(recovery_key);
CREATE INDEX idx_recovery_requests_active ON recovery_requests(recovery_action, status);

CREATE TABLE artifact_staging (
  staging_id TEXT NOT NULL PRIMARY KEY,
  artifact_id TEXT,
  router_id TEXT REFERENCES routers(router_id) ON DELETE RESTRICT,
  operation_id TEXT REFERENCES operations(operation_id) ON DELETE RESTRICT,
  job_id TEXT REFERENCES jobs(job_id) ON DELETE RESTRICT,
  temp_path TEXT NOT NULL,
  final_path TEXT,
  content_digest TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  staging_status TEXT NOT NULL CHECK (staging_status IN (
    'temp', 'written', 'fsynced', 'renamed', 'published', 'reconciled', 'abandoned'
  )),
  restorable INTEGER NOT NULL DEFAULT 0 CHECK (restorable IN (0, 1)),
  restorable_reason TEXT,
  created_at TEXT NOT NULL,
  published_at TEXT
);
CREATE INDEX idx_artifact_staging_artifact ON artifact_staging(artifact_id);

CREATE TABLE artifact_publication_links (
  link_id TEXT NOT NULL PRIMARY KEY,
  staging_id TEXT NOT NULL REFERENCES artifact_staging(staging_id) ON DELETE RESTRICT,
  artifact_id TEXT NOT NULL REFERENCES artifacts(artifact_id) ON DELETE RESTRICT,
  link_kind TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (staging_id, artifact_id, link_kind)
);

CREATE TABLE artifact_backup_metadata (
  backup_meta_id TEXT NOT NULL PRIMARY KEY,
  artifact_id TEXT NOT NULL REFERENCES backup_artifacts(artifact_id) ON DELETE RESTRICT,
  restorable INTEGER NOT NULL DEFAULT 0 CHECK (restorable IN (0, 1)),
  restorable_reason TEXT NOT NULL,
  verified_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE router_safety_sessions (
  session_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  fail_safe_active INTEGER NOT NULL DEFAULT 0 CHECK (fail_safe_active IN (0, 1)),
  reboot_marker TEXT,
  baseline_revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  safety_state TEXT NOT NULL,
  verified_runtime_revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  startup_saved_revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE (router_id)
);

CREATE TABLE router_boot_observations (
  boot_observation_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  boot_id TEXT NOT NULL,
  boot_marker TEXT,
  boot_known INTEGER NOT NULL CHECK (boot_known IN (0, 1)),
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (router_id, boot_id)
);
CREATE INDEX idx_router_boot_observations_router
  ON router_boot_observations(router_id, observed_at DESC);

CREATE TABLE router_evidence_revisions (
  evidence_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  evidence_kind TEXT NOT NULL CHECK (evidence_kind IN ('runtime_applied', 'startup_saved')),
  revision_id TEXT REFERENCES desired_revisions(revision_id) ON DELETE RESTRICT,
  digest TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_router_evidence_revisions_router
  ON router_evidence_revisions(router_id, evidence_kind, observed_at DESC);

CREATE TRIGGER trg_audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER trg_audit_events_no_delete BEFORE DELETE ON audit_events
BEGIN SELECT RAISE(ABORT, 'audit_events is append-only'); END;
CREATE TRIGGER trg_external_effect_events_no_update BEFORE UPDATE ON external_effect_events
BEGIN SELECT RAISE(ABORT, 'external_effect_events is append-only'); END;
CREATE TRIGGER trg_external_effect_events_no_delete BEFORE DELETE ON external_effect_events
BEGIN SELECT RAISE(ABORT, 'external_effect_events is append-only'); END;
"""

_MIGRATION_5 = """
CREATE TABLE published_presets (
  published_preset_id TEXT NOT NULL PRIMARY KEY,
  preset_id TEXT NOT NULL REFERENCES event_presets(preset_id) ON DELETE RESTRICT,
  source_revision_id TEXT NOT NULL
    REFERENCES event_preset_revisions(revision_id) ON DELETE RESTRICT,
  site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE RESTRICT,
  canonical_document_digest TEXT NOT NULL,
  schema_digest TEXT NOT NULL,
  validation_digest TEXT NOT NULL,
  source_lineage_json TEXT NOT NULL,
  published_at TEXT NOT NULL,
  publisher_session_binding_hmac TEXT NOT NULL,
  UNIQUE (preset_id, source_revision_id)
);
CREATE INDEX idx_published_presets_site ON published_presets(site_id, published_at DESC);

CREATE TABLE router_deployment_revisions (
  deployment_revision_id TEXT NOT NULL PRIMARY KEY,
  published_preset_id TEXT NOT NULL
    REFERENCES published_presets(published_preset_id) ON DELETE RESTRICT,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE RESTRICT,
  execution_target TEXT NOT NULL CHECK (execution_target IN ('Lab', 'Production')),
  identity_tuple_json TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  required_families_json TEXT NOT NULL,
  credential_ref_versions_json TEXT NOT NULL,
  topology_bindings_json TEXT NOT NULL,
  awg_ref_json TEXT,
  routes_ref_json TEXT,
  canonical_desired_json TEXT NOT NULL,
  canonical_desired_digest TEXT NOT NULL,
  created_at TEXT NOT NULL,
  actor_session_binding_hmac TEXT NOT NULL,
  UNIQUE (router_id, canonical_desired_digest, published_preset_id)
);
CREATE INDEX idx_router_deployment_revisions_router
  ON router_deployment_revisions(router_id, created_at DESC);

ALTER TABLE desired_revisions ADD COLUMN deployment_revision_id TEXT
  REFERENCES router_deployment_revisions(deployment_revision_id) ON DELETE RESTRICT;

ALTER TABLE change_plans ADD COLUMN deployment_revision_id TEXT
  REFERENCES router_deployment_revisions(deployment_revision_id) ON DELETE RESTRICT;
ALTER TABLE change_plans ADD COLUMN session_binding_hmac TEXT;
ALTER TABLE change_plans ADD COLUMN plan_version INTEGER NOT NULL DEFAULT 1
  CHECK (plan_version >= 1);
ALTER TABLE change_plans ADD COLUMN adopt_acknowledged INTEGER NOT NULL DEFAULT 0
  CHECK (adopt_acknowledged IN (0, 1));

ALTER TABLE change_plan_items ADD COLUMN intent_kind TEXT;
ALTER TABLE change_plan_items ADD COLUMN intent_json TEXT;
ALTER TABLE change_plan_items ADD COLUMN ownership_action TEXT
  CHECK (ownership_action IN ('Create', 'Adopt', 'Update', 'Retire') OR ownership_action IS NULL);
ALTER TABLE change_plan_items ADD COLUMN family_cert_snapshot_json TEXT;

CREATE TABLE router_family_certifications (
  certification_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  family TEXT NOT NULL,
  identity_tuple_digest TEXT NOT NULL,
  shape_digest TEXT NOT NULL,
  codec_digest TEXT NOT NULL,
  executor_digest TEXT NOT NULL,
  evidence_digest TEXT NOT NULL,
  certification_level TEXT NOT NULL
    CHECK (certification_level IN ('LabProven', 'WriteCertified', 'ReadOnlyCertified')),
  valid_from TEXT NOT NULL,
  valid_until TEXT NOT NULL,
  revoked_at TEXT,
  gate_c_campaign_id TEXT,
  created_at TEXT NOT NULL,
  UNIQUE (
    router_id, family, identity_tuple_digest, shape_digest,
    codec_digest, executor_digest, evidence_digest
  )
);
CREATE INDEX idx_router_family_certifications_router
  ON router_family_certifications(router_id, family, revoked_at, valid_until);

CREATE TABLE plan_verify_reports (
  report_id TEXT NOT NULL PRIMARY KEY,
  plan_id TEXT NOT NULL REFERENCES change_plans(plan_id) ON DELETE RESTRICT,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
  observation_id TEXT NOT NULL REFERENCES router_observations(observation_id) ON DELETE RESTRICT,
  checks_json TEXT NOT NULL,
  overall_status TEXT NOT NULL CHECK (overall_status IN ('pass', 'fail', 'drifted')),
  created_at TEXT NOT NULL,
  UNIQUE (plan_id, job_id)
);

CREATE TABLE managed_resource_ownership_events (
  event_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT NOT NULL REFERENCES routers(router_id) ON DELETE RESTRICT,
  resource_id TEXT NOT NULL REFERENCES managed_resources(resource_id) ON DELETE RESTRICT,
  plan_id TEXT NOT NULL REFERENCES change_plans(plan_id) ON DELETE RESTRICT,
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE RESTRICT,
  action TEXT NOT NULL CHECK (action IN ('Create', 'Adopt', 'Update', 'Retire')),
  before_owner TEXT,
  after_owner TEXT,
  created_at TEXT NOT NULL
);
CREATE INDEX idx_managed_resource_ownership_events_router
  ON managed_resource_ownership_events(router_id, created_at DESC);

CREATE TABLE deployment_idempotency (
  scope_kind TEXT NOT NULL,
  scope_id TEXT NOT NULL,
  operation_kind TEXT NOT NULL,
  idempotency_key TEXT NOT NULL,
  request_digest TEXT NOT NULL,
  response_digest TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  created_at TEXT NOT NULL,
  UNIQUE (scope_kind, scope_id, operation_kind, idempotency_key)
);
"""

_MIGRATION_6 = """
ALTER TABLE router_endpoints ADD COLUMN source_address TEXT;
"""

_MIGRATION_7 = """
ALTER TABLE router_endpoints ADD COLUMN ssh_host_key_sha256 TEXT;
ALTER TABLE router_endpoints ADD COLUMN ssh_host_key_algorithm TEXT;
ALTER TABLE router_endpoints ADD COLUMN ssh_host_key_pinned_at TEXT;
ALTER TABLE router_endpoints ADD COLUMN ssh_host_key_provenance TEXT;
"""

_MIGRATION_8 = """
CREATE INDEX idx_jobs_status_created_at ON jobs(status, created_at);
"""

_MIGRATION_9 = """
CREATE TABLE sealed_apply_runs (
  run_id TEXT NOT NULL PRIMARY KEY,
  router_id TEXT REFERENCES routers(router_id) ON DELETE RESTRICT,
  route TEXT NOT NULL,
  verb TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN (
    'Running', 'Succeeded', 'Failed', 'RolledBack', 'Interrupted'
  )),
  correlation_id TEXT,
  request_digest TEXT,
  intent_summary_redacted TEXT NOT NULL,
  checkpoint_json TEXT,
  ops_planned_redacted TEXT,
  ops_dispatched_redacted TEXT,
  overall TEXT,
  error_redacted TEXT,
  started_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  finished_at TEXT
);
CREATE INDEX idx_sealed_apply_runs_status ON sealed_apply_runs(status);
CREATE INDEX idx_sealed_apply_runs_router_started
  ON sealed_apply_runs(router_id, started_at);
CREATE INDEX idx_sealed_apply_runs_correlation_id ON sealed_apply_runs(correlation_id);
"""

_MIGRATION_10 = """
ALTER TABLE sealed_apply_runs ADD COLUMN lease_owner TEXT;
ALTER TABLE sealed_apply_runs ADD COLUMN lease_until_epoch INTEGER;
ALTER TABLE sealed_apply_runs ADD COLUMN ops_pending_redacted TEXT DEFAULT '[]';
UPDATE sealed_apply_runs SET ops_pending_redacted = '[]' WHERE ops_pending_redacted IS NULL;
UPDATE sealed_apply_runs
  SET lease_until_epoch = 0
  WHERE status = 'Running' AND lease_until_epoch IS NULL;
CREATE INDEX idx_sealed_apply_runs_lease_until
  ON sealed_apply_runs(status, lease_until_epoch);
"""

_MIGRATION_11 = """
ALTER TABLE sealed_apply_runs ADD COLUMN pre_apply_baseline_redacted TEXT;
ALTER TABLE sealed_apply_runs ADD COLUMN ops_evidence_redacted TEXT NOT NULL DEFAULT '{}';
ALTER TABLE sealed_apply_runs ADD COLUMN outcome_snapshot_redacted TEXT;
UPDATE sealed_apply_runs SET ops_evidence_redacted = '{}'
  WHERE ops_evidence_redacted IS NULL;
"""

_MIGRATION_12 = """
ALTER TABLE router_endpoints ADD COLUMN management_username TEXT;
"""

_MIGRATION_13 = """
CREATE TABLE entry_pages (
  page_id TEXT NOT NULL PRIMARY KEY,
  site_id TEXT NOT NULL REFERENCES sites(site_id) ON DELETE CASCADE,
  audience TEXT NOT NULL CHECK (audience IN ('guest', 'staff')),
  slug TEXT NOT NULL UNIQUE,
  current_revision_id TEXT,
  published_revision_id TEXT,
  created_at_epoch INTEGER NOT NULL,
  updated_at_epoch INTEGER NOT NULL
);
CREATE UNIQUE INDEX idx_entry_pages_site_audience ON entry_pages(site_id, audience);

CREATE TABLE entry_page_revisions (
  revision_id TEXT NOT NULL PRIMARY KEY,
  page_id TEXT NOT NULL REFERENCES entry_pages(page_id) ON DELETE CASCADE,
  revision_number INTEGER NOT NULL CHECK (revision_number >= 1),
  canonical_json TEXT NOT NULL,
  content_sha256 TEXT NOT NULL,
  created_at_epoch INTEGER NOT NULL,
  UNIQUE (page_id, revision_number)
);
CREATE INDEX idx_entry_page_revisions_page
  ON entry_page_revisions(page_id, revision_number DESC);
"""

_MIGRATION_14 = """
CREATE TABLE standing_network_preferences (
  preferences_id TEXT NOT NULL PRIMARY KEY CHECK (preferences_id = 'default'),
  staff_ssid TEXT NOT NULL DEFAULT '',
  staff_password_credential_ref_id TEXT
    REFERENCES credential_refs(credential_ref_id) ON DELETE SET NULL,
  guest_default_ssid TEXT NOT NULL DEFAULT '',
  guest_default_enabled INTEGER NOT NULL DEFAULT 0 CHECK (guest_default_enabled IN (0, 1)),
  updated_at TEXT NOT NULL
);

INSERT INTO standing_network_preferences (
  preferences_id,
  staff_ssid,
  staff_password_credential_ref_id,
  guest_default_ssid,
  guest_default_enabled,
  updated_at
) VALUES (
  'default',
  'Рабочая сеть',
  NULL,
  'Гостевая сеть',
  0,
  '1970-01-01T00:00:00+00:00'
);
"""

_MIGRATION_15 = """
CREATE TABLE remembered_uplink (
  preferences_id TEXT NOT NULL PRIMARY KEY CHECK (preferences_id = 'default'),
  router_id TEXT REFERENCES routers(router_id) ON DELETE SET NULL,
  mode TEXT NOT NULL DEFAULT 'wifi' CHECK (mode IN ('wifi')),
  ssid TEXT NOT NULL DEFAULT '',
  band TEXT NOT NULL DEFAULT 'BAND_2_4GHZ'
    CHECK (band IN ('BAND_2_4GHZ', 'BAND_5GHZ')),
  station_id TEXT,
  credential_ref_id TEXT
    REFERENCES credential_refs(credential_ref_id) ON DELETE SET NULL,
  desired_active INTEGER NOT NULL DEFAULT 0 CHECK (desired_active IN (0, 1)),
  updated_at TEXT NOT NULL
);

INSERT INTO remembered_uplink (
  preferences_id,
  router_id,
  mode,
  ssid,
  band,
  station_id,
  credential_ref_id,
  desired_active,
  updated_at
) VALUES (
  'default',
  NULL,
  'wifi',
  '',
  'BAND_2_4GHZ',
  NULL,
  NULL,
  0,
  '1970-01-01T00:00:00+00:00'
);
"""

_MIGRATION_16 = """
ALTER TABLE standing_network_preferences ADD COLUMN staff_ap_id TEXT;
ALTER TABLE standing_network_preferences ADD COLUMN guest_ap_id TEXT;
"""

_MIGRATIONS: dict[int, str] = {
    1: _MIGRATION_1,
    2: _MIGRATION_2,
    3: _MIGRATION_3,
    4: _MIGRATION_4,
    5: _MIGRATION_5,
    6: _MIGRATION_6,
    7: _MIGRATION_7,
    8: _MIGRATION_8,
    9: _MIGRATION_9,
    10: _MIGRATION_10,
    11: _MIGRATION_11,
    12: _MIGRATION_12,
    13: _MIGRATION_13,
    14: _MIGRATION_14,
    15: _MIGRATION_15,
    16: _MIGRATION_16,
}

MIGRATION_CHECKSUMS: dict[int, str] = {
    version: hashlib.sha256(sql.encode("utf-8")).hexdigest()
    for version, sql in _MIGRATIONS.items()
}

_SCHEMA_MIGRATIONS_DDL = """
CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER PRIMARY KEY,
  migration_sha256 TEXT NOT NULL UNIQUE,
  schema_fingerprint_sha256 TEXT NOT NULL,
  source TEXT NOT NULL CHECK(source IN ('apply','backfill_legacy')),
  applied_at_epoch INTEGER NOT NULL
);
"""

_PROCESS_MIGRATION_LOCKS: dict[str, threading.Lock] = {}

# Populated at import from canonical schema fingerprints for versions 1..CURRENT_USER_VERSION.
EXPECTED_SCHEMA_FINGERPRINTS: dict[int, str] = {}


def normalize_sql(sql: str | None) -> str:
    if not sql:
        return ""
    text = sql.replace("\r\n", "\n").replace("\r", "\n")
    return text.strip()


def compute_schema_fingerprint(conn: sqlite3.Connection) -> str:
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations' "
        "ORDER BY type, name"
    ).fetchall()
    parts: list[str] = []
    for row in rows:
        parts.append(
            f"{row[0]}|{row[1]}|{row[2]}|{normalize_sql(row[3])}"
        )
    payload = "\n".join(parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _path_mutex_fingerprint(db_path: Path) -> str:
    normalized = str(db_path.resolve()).lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]


@contextmanager
def _migration_owner_lock(db_path: Path) -> Iterator[None]:
    fp = _path_mutex_fingerprint(db_path)
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        mutex_name = f"Local\\router_control_sqlite_migrate_{fp}"
        handle = kernel32.CreateMutexW(None, False, mutex_name)
        if not handle:
            raise RuntimeError("CreateMutexW failed for migration owner lock")
        wait = kernel32.WaitForSingleObject(handle, wintypes.DWORD(60_000))
        if wait != 0:  # WAIT_OBJECT_0
            kernel32.CloseHandle(handle)
            raise RuntimeError("migration owner mutex wait timed out or failed")
        try:
            yield
        finally:
            kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
    else:
        lock = _PROCESS_MIGRATION_LOCKS.setdefault(fp, threading.Lock())
        lock.acquire()
        try:
            yield
        finally:
            lock.release()


def _split_sql_statements(script: str) -> list[str]:
    text = script.replace("\r\n", "\n").replace("\r", "\n")
    statements: list[str] = []
    current: list[str] = []
    in_trigger = False
    for line in text.split("\n"):
        current.append(line)
        stripped = line.strip()
        upper = stripped.upper()
        if not in_trigger and upper.startswith("CREATE TRIGGER"):
            in_trigger = True
            continue
        if in_trigger:
            if upper.endswith("END;") or upper == "END;":
                stmt = "\n".join(current).strip()
                if stmt.endswith(";"):
                    stmt = stmt[:-1]
                statements.append(stmt)
                current = []
                in_trigger = False
            continue
        if stripped.endswith(";"):
            stmt = "\n".join(current).strip()
            if stmt.endswith(";"):
                stmt = stmt[:-1]
            if stmt:
                statements.append(stmt)
            current = []
    remainder = "\n".join(current).strip()
    if remainder:
        if remainder.endswith(";"):
            remainder = remainder[:-1]
        if remainder:
            statements.append(remainder)
    return statements


def _execute_sql_statements(conn: sqlite3.Connection, script: str) -> None:
    for stmt in _split_sql_statements(script):
        conn.execute(stmt)


def _ensure_schema_migrations_table(conn: sqlite3.Connection) -> None:
    _execute_sql_statements(conn, _SCHEMA_MIGRATIONS_DDL)


def _migration_test_barrier(version: int, *, phase: str) -> None:
    """Cross-process test hook: spin until parent releases barrier file (no sleep)."""
    barrier_path = os.environ.get("ROUTER_CONTROL_MIGRATE_TEST_BARRIER")
    pause_at = os.environ.get("ROUTER_CONTROL_MIGRATE_PAUSE_AT")
    if not barrier_path or pause_at != str(version):
        return
    path = Path(barrier_path)
    path.write_text(f"{phase}:{version}", encoding="utf-8")
    while path.exists() and path.read_text(encoding="utf-8") == f"{phase}:{version}":
        pass


def _validate_schema_checks(conn: sqlite3.Connection) -> None:
    quick = conn.execute("PRAGMA quick_check").fetchone()
    if quick is None or str(quick[0]).lower() != "ok":
        raise RuntimeError(f"PRAGMA quick_check failed: {quick}")
    fk_rows = conn.execute("PRAGMA foreign_key_check").fetchall()
    if fk_rows:
        raise RuntimeError("PRAGMA foreign_key_check reported violations")


def _validate_fingerprint_for_version(conn: sqlite3.Connection, version: int) -> None:
    expected = EXPECTED_SCHEMA_FINGERPRINTS.get(version)
    if expected is None:
        raise RuntimeError(f"missing expected schema fingerprint for version {version}")
    actual = compute_schema_fingerprint(conn)
    if actual != expected:
        raise RuntimeError(
            f"schema fingerprint mismatch for user_version={version}: "
            f"expected {expected}, got {actual}"
        )


def _db_has_user_data(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='sites' LIMIT 1"
    ).fetchone()
    if row is None:
        return False
    count = conn.execute("SELECT COUNT(*) FROM sites").fetchone()
    return count is not None and int(count[0]) > 0


def _fsync_path(path: Path) -> None:
    fd = os.open(str(path), os.O_RDWR)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    parent = path.parent
    if parent != Path(path.anchor) and parent.exists():
        try:
            dir_fd = os.open(str(parent), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)


def _backup_before_pending_migrate(
    conn: sqlite3.Connection, db_path: Path, from_version: int
) -> Path:
    backup_dir = db_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    temp_path = backup_dir / f".pre-migrate-v{from_version}-{stamp}.tmp"
    final_path = backup_dir / f"pre-migrate-v{from_version}-{stamp}.sqlite3"
    dest = sqlite3.connect(str(temp_path))
    try:
        conn.backup(dest)
        quick = dest.execute("PRAGMA quick_check").fetchone()
        if quick is None or str(quick[0]).lower() != "ok":
            raise RuntimeError("backup quick_check failed")
    finally:
        dest.close()
    _fsync_path(temp_path)
    digest = hashlib.sha256(temp_path.read_bytes()).hexdigest()
    temp_path.replace(final_path)
    _fsync_path(final_path)
    sidecar = final_path.with_suffix(".sha256")
    sidecar.write_text(digest, encoding="utf-8")
    _fsync_path(sidecar)
    published_digest = hashlib.sha256(final_path.read_bytes()).hexdigest()
    if published_digest != digest:
        raise RuntimeError("pre-migrate backup digest verify failed after publication")
    return final_path


def _record_schema_migration(
    conn: sqlite3.Connection,
    *,
    version: int,
    migration_sha256: str,
    source: str,
    applied_at_epoch: int,
) -> None:
    fingerprint = compute_schema_fingerprint(conn)
    conn.execute(
        "INSERT INTO schema_migrations("
        "version, migration_sha256, schema_fingerprint_sha256, source, applied_at_epoch"
        ") VALUES (?, ?, ?, ?, ?)",
        (version, migration_sha256, fingerprint, source, applied_at_epoch),
    )


def _apply_single_migration(
    conn: sqlite3.Connection,
    *,
    version: int,
    source: str,
    applied_at_epoch: int,
) -> None:
    sql = _MIGRATIONS[version]
    expected_checksum = MIGRATION_CHECKSUMS.get(version) or hashlib.sha256(
        sql.encode("utf-8")
    ).hexdigest()
    conn.execute("BEGIN EXCLUSIVE")
    try:
        _migration_test_barrier(version, phase="before_sql")
        _execute_sql_statements(conn, sql)
        _migration_test_barrier(version, phase="after_sql")
        _record_schema_migration(
            conn,
            version=version,
            migration_sha256=expected_checksum,
            source=source,
            applied_at_epoch=applied_at_epoch,
        )
        conn.execute(f"PRAGMA user_version = {version}")
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def _schema_migrations_populated(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
    ).fetchone()
    if row is None:
        return False
    count = conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()
    return count is not None and int(count[0]) > 0


def _backfill_legacy_schema_migrations_unlocked(
    conn: sqlite3.Connection, current_version: int
) -> None:
    """Populate schema_migrations for legacy DBs; caller must hold BEGIN EXCLUSIVE."""
    _ensure_schema_migrations_table(conn)
    applied_at = int(time.time())
    for version in range(1, current_version + 1):
        conn.execute(
            "INSERT INTO schema_migrations("
            "version, migration_sha256, schema_fingerprint_sha256, source, applied_at_epoch"
            ") VALUES (?, ?, ?, 'backfill_legacy', ?)",
            (
                version,
                MIGRATION_CHECKSUMS[version],
                EXPECTED_SCHEMA_FINGERPRINTS[version],
                applied_at,
            ),
        )


def _backfill_legacy_schema_migrations(conn: sqlite3.Connection, current_version: int) -> None:
    _validate_schema_checks(conn)
    _validate_fingerprint_for_version(conn, current_version)
    for version in range(1, current_version + 1):
        checksum = MIGRATION_CHECKSUMS[version]
        if checksum != hashlib.sha256(_MIGRATIONS[version].encode("utf-8")).hexdigest():
            raise RuntimeError(f"legacy migration checksum mismatch for version {version}")
    conn.execute("BEGIN EXCLUSIVE")
    try:
        if not _schema_migrations_populated(conn):
            _backfill_legacy_schema_migrations_unlocked(conn, current_version)
        conn.execute("COMMIT")
    except Exception:
        if conn.in_transaction:
            conn.execute("ROLLBACK")
        raise


def _compute_expected_fingerprints() -> dict[int, str]:
    """Build canonical fingerprints for empty DB migrated to each version."""
    fingerprints: dict[int, str] = {}
    for version in range(1, CURRENT_USER_VERSION + 1):
        mem = sqlite3.connect(":memory:")
        mem.execute("PRAGMA foreign_keys = ON")
        for v in range(1, version + 1):
            _execute_sql_statements(mem, _MIGRATIONS[v])
            mem.execute(f"PRAGMA user_version = {v}")
        fingerprints[version] = compute_schema_fingerprint(mem)
        mem.close()
    return fingerprints


EXPECTED_SCHEMA_FINGERPRINTS.update(_compute_expected_fingerprints())


def migrate(conn: sqlite3.Connection, *, db_path: Path | str | None = None) -> int:
    """Apply pending migrations with fingerprint validation and exclusive transactions."""
    resolved_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    row = conn.execute("PRAGMA user_version").fetchone()
    current = int(row[0]) if row else 0
    if current > CURRENT_USER_VERSION:
        raise RuntimeError(
            f"Schema version {current} newer than supported {CURRENT_USER_VERSION}; fail-closed"
        )

    with _migration_owner_lock(resolved_path):
        row = conn.execute("PRAGMA user_version").fetchone()
        current = int(row[0]) if row else 0
        if current > CURRENT_USER_VERSION:
            raise RuntimeError(
                f"Schema version {current} newer than supported {CURRENT_USER_VERSION}; fail-closed"
            )
        if current == CURRENT_USER_VERSION:
            _ensure_schema_migrations_table(conn)
            if not _schema_migrations_populated(conn) and current > 0:
                _backfill_legacy_schema_migrations(conn, current)
            return current

        _ensure_schema_migrations_table(conn)
        if current > 0 and not _schema_migrations_populated(conn):
            _backfill_legacy_schema_migrations(conn, current)
        if current > 0:
            _validate_schema_checks(conn)
            _validate_fingerprint_for_version(conn, current)
        if current > 0 and _db_has_user_data(conn):
            _backup_before_pending_migrate(conn, resolved_path, current)

        applied_at = int(time.time())
        while current < CURRENT_USER_VERSION:
            next_version = current + 1
            if current > 0:
                _validate_fingerprint_for_version(conn, current)
            _apply_single_migration(
                conn,
                version=next_version,
                source="apply",
                applied_at_epoch=applied_at,
            )
            current = next_version
        return current


def list_user_tables(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    return [str(r[0]) for r in rows]
