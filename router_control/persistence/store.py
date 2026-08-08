"""Persistence store: sites/routers, revisions, plans, ops/jobs, audit, traffic.

Each ``PersistenceStore`` owns one SQLite connection and a re-entrant RLock.
Public methods acquire the lock for their full span (including ``transaction()``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import sqlite3
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, cast

from router_control.adapters.netcraze.ssh_tunnel import normalize_sha256_fingerprint
from router_control.domain.errors import EntryPageConflict
from router_control.domain.network_intents import digest_canonical
from router_control.persistence.connection import transaction
from router_control.persistence.errors import (
    ArtifactNotRestorableError,
    ConflictError,
    EffectTransitionError,
    FenceExpiredError,
    IdempotencyConflict,
    MutexHolderRequiredError,
    NotFoundError,
    PersistenceError,
    PreconditionFailed,
    RecoveryConflictError,
    StaleFenceError,
    UnknownBootError,
)
from router_control.persistence.ids import new_id


class ActiveProfileError(PersistenceError):
    """VPN profile has an active tunnel assignment."""


class AlreadyRetiredError(PersistenceError):
    """VPN profile is already soft-retired from the catalog."""


class ActivateInProgressError(PersistenceError):
    """VPN profile activate apply is running or awaiting assignment upsert."""

    def __init__(self, profile_id: str) -> None:
        super().__init__(f"profile {profile_id} activate in progress")
        self.profile_id = profile_id


_VPN_ACTIVATE_GAP_GRACE_SECONDS = 120

_LOGGER = logging.getLogger(__name__)

_UNSET = object()

_SEALED_APPLY_AUDIT_SUMMARY_MAX_LEN = 16384

# Tables included in offline secret-leak scans (columns derived live from schema).
_SECRET_SCAN_TABLES: tuple[str, ...] = (
    "credential_refs",
    "audit_events",
    "change_plans",
    "jobs",
    "operations",
    "idempotency_records",
    "desired_revisions",
    "commissioning_runs",
    "readiness_checks",
    "commissioning_idempotency",
    "sealed_apply_runs",
)


def secret_scan_table_columns(conn: sqlite3.Connection, table: str) -> tuple[str, ...]:
    """Return all columns for ``table`` in schema order via ``PRAGMA table_info``.

    Secret scans must never rely on a hand-maintained column list — new migration
    columns (e.g. ``change_plans.session_binding_hmac``) would otherwise be skipped.
    """
    if table not in _SECRET_SCAN_TABLES:
        msg = f"not a secret-scan table: {table}"
        raise ValueError(msg)
    rows = conn.execute(f'PRAGMA table_info("{table}")').fetchall()
    return tuple(str(row[1]) for row in rows)

_SEALED_APPLY_LEASE_SECONDS = 30


def redact_sealed_apply_audit_error_message(message: str | None) -> str | None:
    """Scrub service-layer error text before persisting to sealed apply audit."""
    if message is None:
        return None
    from router_control.application.wifi_observation_helpers import scrub_error_message

    scrubbed = scrub_error_message(message)
    if not scrubbed:
        return None
    return scrubbed[:500]


def _parse_sealed_apply_trail_lists(raw: str | None) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed]


def _parse_sealed_apply_ops_evidence(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except (json.JSONDecodeError, TypeError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key): value for key, value in parsed.items()}


def _merge_sealed_apply_op_evidence(
    existing: dict[str, Any],
    op_name: str,
    evidence: dict[str, Any] | None,
) -> dict[str, Any]:
    if evidence is None:
        return existing
    merged = dict(existing)
    merged[op_name] = evidence
    return merged


def build_sealed_apply_trail_snapshot_for_audit(row: sqlite3.Row) -> dict[str, Any]:
    """Build redacted mid-flight trail snapshot for audit correlation."""
    ops_planned = _parse_sealed_apply_trail_lists(row["ops_planned_redacted"])
    ops_pending = _parse_sealed_apply_trail_lists(
        row["ops_pending_redacted"] if "ops_pending_redacted" in row.keys() else None
    )
    ops_dispatched = _parse_sealed_apply_trail_lists(row["ops_dispatched_redacted"])
    # Facts-first: dispatched op list is authoritative for audit correlation.
    apply_dispatched = bool(ops_dispatched)
    checkpoint_apply_dispatched: bool | None = None
    checkpoint_raw = row["checkpoint_json"]
    if checkpoint_raw:
        try:
            checkpoint = json.loads(str(checkpoint_raw))
            if isinstance(checkpoint, dict) and "apply_dispatched" in checkpoint:
                checkpoint_apply_dispatched = bool(checkpoint.get("apply_dispatched"))
        except (json.JSONDecodeError, TypeError):
            pass
    snapshot: dict[str, Any] = {
        "run_id": row["run_id"],
        "status": row["status"],
        "ops_planned_redacted": ops_planned,
        "ops_pending_redacted": ops_pending,
        "ops_dispatched_redacted": ops_dispatched,
        "apply_dispatched": apply_dispatched,
    }
    if "ops_evidence_redacted" in row.keys():
        ops_evidence = _parse_sealed_apply_ops_evidence(row["ops_evidence_redacted"])
        if ops_evidence:
            snapshot["ops_evidence_redacted"] = ops_evidence
    if "pre_apply_baseline_redacted" in row.keys():
        baseline_raw = row["pre_apply_baseline_redacted"]
        if baseline_raw:
            try:
                baseline = json.loads(str(baseline_raw))
            except (json.JSONDecodeError, TypeError):
                baseline = None
            if isinstance(baseline, dict):
                snapshot["pre_apply_baseline_redacted"] = baseline
    if checkpoint_apply_dispatched is not None:
        snapshot["checkpoint_apply_dispatched"] = checkpoint_apply_dispatched
    if ops_pending:
        snapshot["ops_unconfirmed_redacted"] = ops_pending
    overall = row["overall"]
    if overall is not None:
        snapshot["overall"] = overall
    return snapshot


def build_sealed_apply_audit_summary(
    *,
    route: str,
    verb: str,
    intent_redacted: dict[str, Any],
    result_payload: dict[str, Any] | None = None,
    outcome_snapshot: dict[str, Any] | None = None,
    error_message: str | None = None,
    exception_type: str | None = None,
    trail_snapshot: dict[str, Any] | None = None,
) -> str:
    """Build redacted JSON summary for sealed apply/teardown audit events."""
    summary: dict[str, Any] = {
        "route": route,
        "verb": verb,
        "intent": intent_redacted,
    }
    if outcome_snapshot is not None:
        summary["outcome"] = outcome_snapshot
    if trail_snapshot is not None:
        summary["trail"] = trail_snapshot
    if result_payload is not None:
        result_body = dict(result_payload)
        if trail_snapshot is not None and "ops_evidence_redacted" in trail_snapshot:
            result_body.pop("steps", None)
            result_body.pop("verdict_explanation", None)
            result_body.pop("rollback", None)
            result_body.pop("rollback_errors", None)
            result_body.pop("on_air_verification_status", None)
            result_body.pop("uplink_verification_status", None)
        summary["result"] = result_body
    redacted_error = redact_sealed_apply_audit_error_message(error_message)
    if redacted_error is not None:
        summary["error_message"] = redacted_error
    if exception_type is not None:
        summary["exception_type"] = exception_type
    text = json.dumps(summary, sort_keys=True, separators=(",", ":"))
    if len(text) > _SEALED_APPLY_AUDIT_SUMMARY_MAX_LEN:
        return text[: _SEALED_APPLY_AUDIT_SUMMARY_MAX_LEN] + "...[truncated]"
    return text


def sealed_apply_request_digest(intent_redacted: dict[str, Any]) -> str:
    raw = json.dumps(intent_redacted, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()


def _utc_now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sqlite_now_epoch(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT CAST(strftime('%s','now') AS INTEGER)").fetchone()
    return int(row[0])


def _lease_validity_epoch(
    conn: sqlite3.Connection,
    *,
    now_epoch: int | None,
    now: datetime | None = None,
) -> int:
    """Lease validity instant: explicit epoch injection, else SQLite DB time."""
    if now_epoch is not None:
        return now_epoch
    return _sqlite_now_epoch(conn)


def _enforce_lease_expiry(
    conn: sqlite3.Connection,
    job: sqlite3.Row,
    *,
    now_epoch: int | None,
    now: datetime | None,
) -> bool:
    """Return True when lease/fence expiry must be enforced for this call."""
    if now_epoch is not None:
        return True
    lease_until = job["lease_until_epoch"]
    if lease_until is None:
        return False
    db_now = _sqlite_now_epoch(conn)
    # Suites that pin leases with small now_epoch values are not DB-time aligned.
    if int(lease_until) < 1_000_000_000 and db_now >= 1_000_000_000:
        return False
    return True


def _assert_job_lease_valid(
    conn: sqlite3.Connection,
    job: sqlite3.Row,
    *,
    now_epoch: int | None,
    now: datetime | None = None,
) -> None:
    if not _enforce_lease_expiry(conn, job, now_epoch=now_epoch, now=now):
        return
    lease_until = job["lease_until_epoch"]
    if lease_until is None:
        return
    validity = _lease_validity_epoch(conn, now_epoch=now_epoch, now=now)
    if int(lease_until) < validity:
        raise StaleFenceError("job lease expired")


def _assert_active_router_fence_for_job(
    conn: sqlite3.Connection,
    job: sqlite3.Row,
    *,
    lease_owner: str,
    now_epoch: int | None,
    now: datetime | None = None,
) -> None:
    """Reject when an active router fence is expired or mismatched for this job."""
    if not _enforce_lease_expiry(conn, job, now_epoch=now_epoch, now=now):
        return
    router_id = str(job["router_id"])
    row = conn.execute(
        "SELECT * FROM router_execution_fences WHERE router_id = ?",
        (router_id,),
    ).fetchone()
    if row is None:
        return
    validity = _lease_validity_epoch(conn, now_epoch=now_epoch, now=now)
    if int(row["lease_until_epoch"]) < validity:
        raise StaleFenceError("router execution fence expired")
    active_job_id = row["active_job_id"]
    if active_job_id is not None and str(active_job_id) != str(job["job_id"]):
        raise StaleFenceError("router execution fence active job mismatch")
    if row["lease_owner"] != lease_owner:
        raise StaleFenceError("router execution fence lease owner mismatch")


SAFETY_PAYLOAD_PREFIX = "rc:safety:v1:"


def encode_safety_payload(payload: dict[str, Any]) -> str:
    return SAFETY_PAYLOAD_PREFIX + json.dumps(payload, sort_keys=True, separators=(",", ":"))


def decode_safety_payload(reboot_marker: str | None) -> dict[str, Any]:
    if not reboot_marker or not str(reboot_marker).startswith(SAFETY_PAYLOAD_PREFIX):
        return {}
    try:
        parsed = json.loads(str(reboot_marker)[len(SAFETY_PAYLOAD_PREFIX) :])
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _merge_safety_payload(
    existing_marker: str | None,
    *,
    boot_marker: str | None,
    payload_updates: dict[str, Any] | None,
) -> str | None:
    if payload_updates:
        merged = decode_safety_payload(existing_marker)
        merged.update(payload_updates)
        if boot_marker and "baseline_observation" not in merged:
            merged.setdefault("baseline_observation", boot_marker)
        return encode_safety_payload(merged)
    if boot_marker and not (
        existing_marker and str(existing_marker).startswith(SAFETY_PAYLOAD_PREFIX)
    ):
        return boot_marker
    return existing_marker


def _assert_fenced_effect_write(
    conn: sqlite3.Connection,
    *,
    router_id: str,
    job_id: str,
    lease_owner: str,
    now_epoch: int | None = None,
    now: datetime | None = None,
) -> None:
    job = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
    if job is None:
        raise NotFoundError("job not found for fenced effect write")
    if str(job["router_id"]) != router_id:
        raise StaleFenceError("effect job router mismatch")
    fence = conn.execute(
        "SELECT fence_id FROM router_execution_fences WHERE router_id = ?",
        (router_id,),
    ).fetchone()
    if fence is None:
        raise StaleFenceError("router execution fence required for external effect write")
    _assert_active_router_fence_for_job(
        conn,
        job,
        lease_owner=lease_owner,
        now_epoch=now_epoch,
        now=now,
    )


def _digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def etag_for_revision(revision_id: str, canonical_digest: str) -> str:
    return f'"{revision_id}:{canonical_digest}"'


def etag_for_plan(plan_id: str, plan_digest: str) -> str:
    return f'"{plan_id}:{plan_digest}"'


_SSH_HOST_KEY_PROVENANCE = frozenset({"learned_confirmed", "operator_supplied"})


@dataclass(frozen=True, slots=True)
class EndpointSshHostKeyPin:
    fingerprint_sha256: str
    algorithm: str
    pinned_at: str
    provenance: str


def etag_for_plan_version(plan_id: str, plan_version: int) -> str:
    return f'W/"{plan_id}:{plan_version}"'


def etag_for_commissioning_run(run_id: str, version: int, report_digest: str | None) -> str:
    digest = report_digest or "none"
    return f'"{run_id}:{version}:{digest}"'


def etag_for_event_preset(preset_id: str, version: int, current_digest: str | None) -> str:
    digest = current_digest or "none"
    return f'"{preset_id}:{version}:{digest}"'


def etag_for_event_preset_revision(revision_id: str, canonical_digest: str) -> str:
    return f'"{revision_id}:{canonical_digest}"'


@dataclass(frozen=True, slots=True)
class ClaimResult:
    job_id: str
    fencing_token: int
    lease_owner: str
    lease_until_epoch: int


@dataclass(frozen=True, slots=True)
class IdempotencyOutcome:
    created: bool
    operation_id: str
    job_id: str
    idempotency_record_id: str
    status: str
    response_ref: str | None
    http_status: int | None = None


@dataclass(frozen=True, slots=True)
class CommissioningAssessReservation:
    run_id: str
    fence_version: int
    idempotency_record_id: str
    idempotency_key: str
    request_digest: str
    mode: str
    router_id: str | None
    site_id: str


@dataclass(frozen=True, slots=True)
class CommissioningAssessPrepareResult:
    """Either ``replay`` (run, checks, created) or ``reservation`` for compute."""

    replay: tuple[dict[str, Any], list[dict[str, Any]], bool] | None = None
    reservation: CommissioningAssessReservation | None = None


# Bounded batch for Queued job scan (§4.4 claim); preserves FIFO via OFFSET paging.
_CLAIM_JOB_CANDIDATE_BATCH_SIZE = 64


class PersistenceStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.RLock()

    @property
    def conn(self) -> sqlite3.Connection:
        """Legacy test escape hatch; not RLock-covered — prefer public store methods."""
        return self._conn

    # --- sites / routers ---

    def create_site(
        self,
        *,
        site_id: str | None = None,
        display_name: str,
        timezone: str = "UTC",
        now: datetime | None = None,
    ) -> str:
        sid = site_id or new_id("site")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO sites(site_id, display_name, timezone, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (sid, display_name, timezone, ts, ts),
        )
        return sid

    def enroll_router(
        self,
        *,
        site_id: str,
        display_name: str,
        vendor: str,
        model: str,
        identity_fingerprint: str,
        host: str,
        port: int = 443,
        kind: str = "management_https",
        hardware_revision: str | None = None,
        router_id: str | None = None,
        source_address: str | None = None,
        now: datetime | None = None,
    ) -> str:
        """Insert router with NULL credential_ref, then endpoint. Ref linked later."""
        rid = router_id or new_id("rtr")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO routers("
            "router_id, site_id, display_name, vendor, model, hardware_revision, "
            "identity_fingerprint, identity_claims_json, credential_ref_id, "
            "lifecycle_status, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, NULL, NULL, 'PendingEnrollment', ?, ?)",
            (
                rid,
                site_id,
                display_name,
                vendor,
                model,
                hardware_revision,
                identity_fingerprint,
                ts,
                ts,
            ),
        )
        self._conn.execute(
            "INSERT INTO router_endpoints("
            "endpoint_id, router_id, kind, host, port, priority, is_enabled, "
            "source_address, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?, ?)",
            (new_id("ep"), rid, kind, host, port, source_address, ts, ts),
        )
        self._conn.execute(
            "INSERT INTO router_mutation_locks("
            "router_id, active_job_id, lock_owner, lock_until_epoch, fencing_token, updated_at"
            ") VALUES (?, NULL, NULL, NULL, 0, ?)",
            (rid, ts),
        )
        return rid

    def get_router(self, router_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM routers WHERE router_id = ?", (router_id,)
            ).fetchone(),
        )

    def get_site(self, site_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM sites WHERE site_id = ?", (site_id,)
            ).fetchone(),
        )

    def list_routers_for_site(self, site_id: str, *, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM routers WHERE site_id = ? ORDER BY created_at DESC LIMIT ?",
                (site_id, limit),
            ).fetchall()
        )

    def get_latest_observation(self, router_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_observations WHERE router_id = ? "
                "ORDER BY observed_at DESC LIMIT 1",
                (router_id,),
            ).fetchone(),
        )

    def list_routers(self, *, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM routers ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
        )

    def find_restore_candidate_router_id(self) -> str | None:
        """Return router_id of the best restorable connection context (bounded SQL).

        Eligible routers: confirmed SSH pin on the binding endpoint **or** a
        genuine enrolled record (lifecycle Enrolled + non-placeholder model).

        Genuine records always outrank drafts. Among genuine records (lower
        sort keys win): confirmed pin first, then live_ready, then
        ssh_host_key_pinned_at DESC, created_at ASC, router_id ASC.

        Among drafts (always below genuine): live_ready draft, pin-only
        non-draft, pin-only draft; tie-break ssh_host_key_pinned_at DESC,
        created_at ASC, router_id ASC.

        Draft = lifecycle PendingEnrollment and model does not assert a real
        device (empty/whitespace-only or PendingDiscovery), aligned with
        router_discovery._is_enrollment_draft.
        """
        row = self._conn.execute(
            """
            WITH pinned_endpoints AS (
                SELECT
                    ep.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY ep.router_id
                        ORDER BY ep.priority ASC, ep.created_at ASC
                    ) AS rn
                FROM router_endpoints ep
                WHERE ep.ssh_host_key_sha256 IS NOT NULL
                  AND ep.ssh_host_key_algorithm IS NOT NULL
                  AND ep.ssh_host_key_pinned_at IS NOT NULL
                  AND ep.ssh_host_key_provenance IS NOT NULL
            ),
            binding AS (
                SELECT * FROM pinned_endpoints WHERE rn = 1
            ),
            primary_endpoints AS (
                SELECT
                    ep.*,
                    ROW_NUMBER() OVER (
                        PARTITION BY ep.router_id
                        ORDER BY ep.priority ASC, ep.created_at ASC
                    ) AS rn
                FROM router_endpoints ep
            ),
            primary_binding AS (
                SELECT * FROM primary_endpoints WHERE rn = 1
            ),
            candidates AS (
                SELECT
                    r.router_id,
                    r.created_at,
                    b.ssh_host_key_pinned_at,
                    CASE
                        WHEN r.lifecycle_status = 'PendingEnrollment'
                         AND (
                             TRIM(COALESCE(r.model, '')) = ''
                             OR r.model = 'PendingDiscovery'
                         )
                        THEN 1
                        ELSE 0
                    END AS is_draft,
                    CASE
                        WHEN r.lifecycle_status = 'Enrolled'
                         AND TRIM(COALESCE(r.model, '')) != ''
                         AND r.model != 'PendingDiscovery'
                        THEN 1
                        ELSE 0
                    END AS is_genuine,
                    CASE WHEN b.router_id IS NOT NULL THEN 1 ELSE 0 END AS has_pin,
                    CASE
                        WHEN TRIM(COALESCE(COALESCE(b.host, pb.host), '')) != ''
                         AND TRIM(COALESCE(
                             COALESCE(b.management_username, pb.management_username),
                             ''
                         )) != ''
                         AND TRIM(COALESCE(r.credential_ref_id, '')) != ''
                        THEN 1
                        ELSE 0
                    END AS live_ready
                FROM routers r
                LEFT JOIN binding b ON b.router_id = r.router_id
                LEFT JOIN primary_binding pb ON pb.router_id = r.router_id
                WHERE b.router_id IS NOT NULL
                   OR (
                       r.lifecycle_status = 'Enrolled'
                       AND TRIM(COALESCE(r.model, '')) != ''
                       AND r.model != 'PendingDiscovery'
                       AND pb.router_id IS NOT NULL
                   )
            ),
            ranked AS (
                SELECT
                    router_id,
                    created_at,
                    ssh_host_key_pinned_at,
                    is_genuine,
                    live_ready,
                    has_pin,
                    CASE
                        WHEN live_ready = 1 AND is_draft = 1 THEN 1
                        WHEN is_draft = 0 THEN 2
                        ELSE 3
                    END AS draft_subtier
                FROM candidates
            )
            SELECT router_id
            FROM ranked
            ORDER BY
                CASE WHEN is_genuine = 1 THEN 0 ELSE 1 END ASC,
                CASE
                    WHEN is_genuine = 1 THEN (1 - has_pin)
                    ELSE draft_subtier
                END ASC,
                CASE WHEN is_genuine = 1 THEN (1 - live_ready) ELSE 0 END ASC,
                ssh_host_key_pinned_at DESC,
                created_at ASC,
                router_id ASC
            LIMIT 1
            """
        ).fetchone()
        if row is None:
            return None
        return str(row["router_id"])

    def get_primary_endpoint(self, router_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_endpoints WHERE router_id = ? "
                "ORDER BY priority ASC, created_at ASC LIMIT 1",
                (router_id,),
            ).fetchone(),
        )

    def get_connection_binding_endpoint(self, router_id: str) -> sqlite3.Row | None:
        """Endpoint row holding SSH pin and management username (same row for both)."""
        pinned = cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_endpoints WHERE router_id = ? "
                "AND ssh_host_key_sha256 IS NOT NULL "
                "AND ssh_host_key_algorithm IS NOT NULL "
                "AND ssh_host_key_pinned_at IS NOT NULL "
                "AND ssh_host_key_provenance IS NOT NULL "
                "ORDER BY priority ASC, created_at ASC LIMIT 1",
                (router_id,),
            ).fetchone(),
        )
        if pinned is not None:
            return pinned
        return self.get_primary_endpoint(router_id)

    def get_endpoint_ssh_host_key(self, router_id: str) -> EndpointSshHostKeyPin | None:
        endpoint = self.get_connection_binding_endpoint(router_id)
        if endpoint is None:
            return None
        fingerprint = endpoint["ssh_host_key_sha256"]
        algorithm = endpoint["ssh_host_key_algorithm"]
        pinned_at = endpoint["ssh_host_key_pinned_at"]
        provenance = endpoint["ssh_host_key_provenance"]
        if not fingerprint or not algorithm or not pinned_at or not provenance:
            return None
        return EndpointSshHostKeyPin(
            fingerprint_sha256=str(fingerprint),
            algorithm=str(algorithm),
            pinned_at=str(pinned_at),
            provenance=str(provenance),
        )

    def get_endpoint_management_username(self, router_id: str) -> str | None:
        endpoint = self.get_connection_binding_endpoint(router_id)
        if endpoint is None:
            return None
        raw = endpoint["management_username"]
        if raw is None:
            return None
        text = str(raw).strip()
        return text if text else None

    def set_endpoint_management_username(
        self,
        router_id: str,
        username: str,
        *,
        now: datetime | None = None,
    ) -> None:
        text = username.strip()
        if not text:
            raise PreconditionFailed("management username is required")
        endpoint = self.get_connection_binding_endpoint(router_id)
        if endpoint is None:
            raise NotFoundError("primary router endpoint not found")
        updated_at = _utc_now_iso(now)
        self._conn.execute(
            "UPDATE router_endpoints SET management_username = ?, updated_at = ? "
            "WHERE endpoint_id = ?",
            (text, updated_at, endpoint["endpoint_id"]),
        )

    def set_endpoint_ssh_host_key(
        self,
        router_id: str,
        fingerprint_sha256: str,
        algorithm: str,
        provenance: str,
        *,
        allow_overwrite: bool = False,
        pinned_at: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if provenance not in _SSH_HOST_KEY_PROVENANCE:
            raise PreconditionFailed(
                f"ssh host key provenance must be one of {sorted(_SSH_HOST_KEY_PROVENANCE)}"
            )
        try:
            normalized = normalize_sha256_fingerprint(fingerprint_sha256)
        except Exception as exc:
            raise PreconditionFailed(f"invalid ssh host key fingerprint: {exc}") from exc
        algorithm_value = algorithm.strip()
        if not algorithm_value:
            raise PreconditionFailed("ssh host key algorithm is required")
        endpoint = self.get_connection_binding_endpoint(router_id)
        if endpoint is None:
            raise NotFoundError("primary router endpoint not found")
        existing = self.get_endpoint_ssh_host_key(router_id)
        if (
            existing is not None
            and existing.fingerprint_sha256 != normalized
            and not allow_overwrite
        ):
            raise ConflictError(
                "ssh host key pin already set with a different fingerprint; "
                "pass allow_overwrite=true to replace"
            )
        ts = pinned_at or _utc_now_iso(now)
        updated_at = _utc_now_iso(now)
        self._conn.execute(
            "UPDATE router_endpoints SET "
            "ssh_host_key_sha256 = ?, ssh_host_key_algorithm = ?, "
            "ssh_host_key_pinned_at = ?, ssh_host_key_provenance = ?, updated_at = ? "
            "WHERE endpoint_id = ?",
            (
                normalized,
                algorithm_value,
                ts,
                provenance,
                updated_at,
                endpoint["endpoint_id"],
            ),
        )

    def set_router_credential_ref(
        self, router_id: str, credential_ref_id: str, *, now: datetime | None = None
    ) -> None:
        ts = _utc_now_iso(now)
        self._conn.execute(
            "UPDATE routers SET credential_ref_id = ?, updated_at = ? WHERE router_id = ?",
            (credential_ref_id, ts, router_id),
        )

    # --- credential_refs metadata ---

    def insert_credential_ref(
        self,
        *,
        router_id: str,
        kind: str,
        provider: str,
        provider_locator: str,
        credential_ref_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        cid = credential_ref_id or new_id("cred")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO credential_refs("
            "credential_ref_id, router_id, kind, provider, provider_locator, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (cid, router_id, kind, provider, provider_locator, ts),
        )
        return cid

    def get_credential_ref(self, credential_ref_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM credential_refs WHERE credential_ref_id = ?",
                (credential_ref_id,),
            ).fetchone(),
        )

    def list_credential_refs(self, router_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM credential_refs WHERE router_id = ? ORDER BY created_at",
                (router_id,),
            ).fetchall()
        )

    def mark_credential_rotated(
        self, credential_ref_id: str, *, now: datetime | None = None
    ) -> None:
        self._conn.execute(
            "UPDATE credential_refs SET rotated_at = ? WHERE credential_ref_id = ?",
            (_utc_now_iso(now), credential_ref_id),
        )

    def mark_credential_revoked(
        self, credential_ref_id: str, *, now: datetime | None = None
    ) -> None:
        self._conn.execute(
            "UPDATE credential_refs SET revoked_at = ? WHERE credential_ref_id = ?",
            (_utc_now_iso(now), credential_ref_id),
        )

    # --- observations / revisions ---

    def insert_observation(
        self,
        *,
        router_id: str,
        identity_fingerprint: str,
        resource_version: str,
        state_digest: str,
        collection_status: str = "Succeeded",
        source: str = "fake",
        adapter_version: str = "0.1.0",
        ttl_seconds: int = 3600,
        capability_id: str | None = None,
        observation_id: str | None = None,
        now: datetime | None = None,
        state_snapshot_json: str | None = None,
    ) -> str:
        oid = observation_id or new_id("obs")
        moment = now or datetime.now(UTC)
        ts = _utc_now_iso(moment)
        valid_until = _utc_now_iso(moment + timedelta(seconds=ttl_seconds))
        self._conn.execute(
            "INSERT INTO router_observations("
            "observation_id, router_id, capability_id, identity_fingerprint, "
            "resource_version, state_digest, state_snapshot_json, collection_status, "
            "source, adapter_version, observed_at, valid_until, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                oid,
                router_id,
                capability_id,
                identity_fingerprint,
                resource_version,
                state_digest,
                state_snapshot_json,
                collection_status,
                source,
                adapter_version,
                ts,
                valid_until,
                ts,
            ),
        )
        return oid

    def get_observation(self, observation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_observations WHERE observation_id = ?",
                (observation_id,),
            ).fetchone(),
        )

    def put_desired_revision(
        self,
        *,
        router_id: str,
        canonical_digest: str,
        based_on_observation_id: str,
        if_match: str | None,
        desired_document_json: str | None = None,
        actor_type: str = "operator",
        actor_id: str | None = None,
        reason: str | None = None,
        revision_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[str, str, int]:
        """Create immutable revision + update pointer. Returns (revision_id, etag, number)."""
        with transaction(self._conn, immediate=True):
            state = self._conn.execute(
                "SELECT * FROM router_revision_state WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            if state is None:
                if if_match is not None and if_match not in ("*", '""', ""):
                    raise PreconditionFailed("No current revision; If-Match must be absent or *")
                next_number = 1
                parent_id = None
            else:
                current = self._conn.execute(
                    "SELECT revision_id, canonical_digest, revision_number "
                    "FROM desired_revisions WHERE revision_id = ?",
                    (state["current_desired_revision_id"],),
                ).fetchone()
                if current is None:
                    raise ConflictError("Current desired revision missing")
                expected = etag_for_revision(current["revision_id"], current["canonical_digest"])
                if if_match is None:
                    raise PreconditionFailed("If-Match required")
                if if_match.strip() != expected:
                    raise PreconditionFailed("If-Match does not match current desired ETag")
                next_number = int(current["revision_number"]) + 1
                parent_id = current["revision_id"]

            obs = self.get_observation(based_on_observation_id)
            if obs is None or obs["router_id"] != router_id:
                raise PreconditionFailed("based_on_observation_id invalid")
            if obs["collection_status"] != "Succeeded":
                raise PreconditionFailed("Observation not Succeeded")
            now_iso = _utc_now_iso(now)
            if obs["valid_until"] < now_iso:
                raise PreconditionFailed("Observation expired")

            rid = revision_id or new_id("rev")
            self._conn.execute(
                "INSERT INTO desired_revisions("
                "revision_id, router_id, revision_number, parent_revision_id, "
                "canonical_digest, desired_document_json, based_on_observation_id, "
                "actor_type, actor_id, reason, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rid,
                    router_id,
                    next_number,
                    parent_id,
                    canonical_digest,
                    desired_document_json,
                    based_on_observation_id,
                    actor_type,
                    actor_id,
                    reason,
                    now_iso,
                ),
            )
            if state is None:
                self._conn.execute(
                    "INSERT INTO router_revision_state("
                    "router_id, current_desired_revision_id, applied_revision_id, "
                    "last_observation_id, updated_at"
                    ") VALUES (?, ?, NULL, ?, ?)",
                    (router_id, rid, based_on_observation_id, now_iso),
                )
            else:
                self._conn.execute(
                    "UPDATE router_revision_state SET current_desired_revision_id = ?, "
                    "last_observation_id = ?, updated_at = ? WHERE router_id = ?",
                    (rid, based_on_observation_id, now_iso, router_id),
                )
            return rid, etag_for_revision(rid, canonical_digest), next_number

    def get_desired_revision(self, router_id: str) -> sqlite3.Row | None:
        state = self._conn.execute(
            "SELECT current_desired_revision_id FROM router_revision_state WHERE router_id = ?",
            (router_id,),
        ).fetchone()
        if state is None:
            return None
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM desired_revisions WHERE revision_id = ?",
                (state["current_desired_revision_id"],),
            ).fetchone(),
        )

    # --- plans ---

    def create_plan(
        self,
        *,
        router_id: str,
        revision_id: str,
        observation_id: str,
        if_match: str,
        risk_class: str = "Medium",
        expires_in_seconds: int = 3600,
        actor_type: str = "operator",
        actor_id: str | None = None,
        items: list[dict[str, Any]] | None = None,
        plan_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[str, str]:
        with transaction(self._conn, immediate=True):
            rev = self._conn.execute(
                "SELECT * FROM desired_revisions WHERE revision_id = ?", (revision_id,)
            ).fetchone()
            if rev is None or rev["router_id"] != router_id:
                raise NotFoundError("revision not found")
            expected_etag = etag_for_revision(rev["revision_id"], rev["canonical_digest"])
            if if_match.strip() != expected_etag:
                raise PreconditionFailed("If-Match desired ETag mismatch")
            state = self._conn.execute(
                "SELECT current_desired_revision_id FROM router_revision_state WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            if state is None or state["current_desired_revision_id"] != revision_id:
                raise ConflictError("revision is not current desired pointer")
            obs = self.get_observation(observation_id)
            if obs is None or obs["router_id"] != router_id:
                raise PreconditionFailed("observation invalid")
            now_iso = _utc_now_iso(now)
            if obs["collection_status"] != "Succeeded" or obs["valid_until"] < now_iso:
                raise PreconditionFailed("observation stale or failed")

            pid = plan_id or new_id("plan")
            plan_digest = _digest(f"{pid}:{revision_id}:{observation_id}:{rev['canonical_digest']}")
            expires_at = _utc_now_iso(
                (now or datetime.now(UTC)) + timedelta(seconds=expires_in_seconds)
            )
            self._conn.execute(
                "INSERT INTO change_plans("
                "plan_id, router_id, revision_id, observation_id, expected_desired_digest, "
                "observed_resource_version, observed_state_digest, plan_digest, risk_class, "
                "requires_backup, requires_fail_safe, expires_at, confirmation_state, "
                "actor_type, actor_id, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, 'Draft', ?, ?, ?)",
                (
                    pid,
                    router_id,
                    revision_id,
                    observation_id,
                    rev["canonical_digest"],
                    obs["resource_version"],
                    obs["state_digest"],
                    plan_digest,
                    risk_class,
                    expires_at,
                    actor_type,
                    actor_id,
                    now_iso,
                ),
            )
            for ordinal, item in enumerate(items or [{"change_kind": "ensure-assignment"}]):
                self._conn.execute(
                    "INSERT INTO change_plan_items("
                    "plan_item_id, plan_id, ordinal, change_kind, target_resource_id"
                    ") VALUES (?, ?, ?, ?, ?)",
                    (
                        new_id("pli"),
                        pid,
                        ordinal,
                        item.get("change_kind", "ensure-assignment"),
                        item.get("target_resource_id"),
                    ),
                )
            return pid, etag_for_plan(pid, plan_digest)

    def get_plan(self, plan_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM change_plans WHERE plan_id = ?", (plan_id,)
            ).fetchone(),
        )

    def confirm_plan(
        self,
        *,
        plan_id: str,
        plan_digest: str,
        if_match: str,
        actor_id: str,
        now: datetime | None = None,
    ) -> sqlite3.Row:
        with transaction(self._conn, immediate=True):
            plan = self.get_plan(plan_id)
            if plan is None:
                raise NotFoundError("plan not found")
            expected = etag_for_plan(plan_id, plan["plan_digest"])
            if if_match.strip() != expected:
                raise PreconditionFailed("If-Match plan ETag mismatch")
            if plan["plan_digest"] != plan_digest:
                raise ConflictError("plan_digest mismatch")
            now_iso = _utc_now_iso(now)
            if plan["expires_at"] < now_iso:
                self._conn.execute(
                    "UPDATE change_plans SET confirmation_state = 'Expired' WHERE plan_id = ?",
                    (plan_id,),
                )
                raise ConflictError("plan expired")
            if plan["confirmation_state"] != "Draft":
                raise ConflictError("plan not in Draft state")
            # Stale plan: desired pointer or observation must still match
            state = self._conn.execute(
                "SELECT current_desired_revision_id FROM router_revision_state WHERE router_id = ?",
                (plan["router_id"],),
            ).fetchone()
            if state is None or state["current_desired_revision_id"] != plan["revision_id"]:
                raise ConflictError("plan stale: desired revision changed")
            obs = self.get_observation(plan["observation_id"])
            if (
                obs is None
                or obs["valid_until"] < now_iso
                or obs["state_digest"] != plan["observed_state_digest"]
            ):
                raise PreconditionFailed("plan stale: observation binding failed")
            self._conn.execute(
                "UPDATE change_plans SET confirmation_state = 'Confirmed', "
                "confirmed_at = ?, confirmed_by_actor = ? WHERE plan_id = ?",
                (now_iso, actor_id, plan_id),
            )
            updated = self.get_plan(plan_id)
            assert updated is not None
            return updated

    # --- operations / idempotency / jobs ---

    _MUTATION_OPERATION_KINDS = frozenset(
        {"apply_plan", "enroll", "preflight", "rotate_credential"}
    )
    _DISPATCH_PAYLOAD_REQUIRED_KINDS = frozenset(
        {
            "commissioning_assess_readonly",
            "preset_validate",
            "preset_plan_readiness",
        }
    )

    def peek_idempotency(
        self,
        *,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
        router_id: str | None = None,
        scope: str = "hub_admin",
    ) -> IdempotencyOutcome | None:
        """Lookup idempotency without side effects. router_id=None → scope+kind+key only."""
        if router_id is None:
            existing = self._conn.execute(
                "SELECT * FROM idempotency_records WHERE scope = ? "
                "AND operation_kind = ? AND idempotency_key = ?",
                (scope, operation_kind, idempotency_key),
            ).fetchone()
        else:
            existing = self._conn.execute(
                "SELECT * FROM idempotency_records WHERE scope = ? AND router_id = ? "
                "AND operation_kind = ? AND idempotency_key = ?",
                (scope, router_id, operation_kind, idempotency_key),
            ).fetchone()
        if existing is None:
            return None
        if existing["request_digest"] != request_digest:
            raise IdempotencyConflict("same key different digest")
        return self._outcome_from_idempotency_row(existing)

    def _outcome_from_idempotency_row(self, existing: sqlite3.Row) -> IdempotencyOutcome:
        job = self._conn.execute(
            "SELECT job_id FROM jobs WHERE operation_id = ? ORDER BY attempt LIMIT 1",
            (existing["operation_id"],),
        ).fetchone()
        stored_http: int | None = None
        if existing["response_ref"]:
            try:
                payload = json.loads(existing["response_ref"])
                stored_http = int(payload.get("http_status", 0)) or None
            except (json.JSONDecodeError, TypeError, ValueError):
                stored_http = None
        return IdempotencyOutcome(
            created=False,
            operation_id=existing["operation_id"],
            job_id=job["job_id"] if job else "",
            idempotency_record_id=existing["idempotency_record_id"],
            status=existing["status"],
            response_ref=existing["response_ref"],
            http_status=stored_http,
        )

    def create_operation_bundle(
        self,
        *,
        router_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
        scope: str = "hub_admin",
        plan_id: str | None = None,
        actor_type: str = "operator",
        actor_id: str | None = None,
        correlation_id: str | None = None,
        initial_job_status: str = "Queued",
        response_ref: str | None = None,
        http_status: int | None = None,
        expires_in_seconds: int = 86400,
        dispatch_payload: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> IdempotencyOutcome:
        """Atomic §6 bundle: lookup → ops + idempotency + job + audit."""
        with transaction(self._conn, immediate=True):
            outcome = self._create_operation_bundle_unlocked(
                router_id=router_id,
                operation_kind=operation_kind,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                scope=scope,
                plan_id=plan_id,
                actor_type=actor_type,
                actor_id=actor_id,
                correlation_id=correlation_id,
                initial_job_status=initial_job_status,
                response_ref=response_ref,
                http_status=http_status,
                expires_in_seconds=expires_in_seconds,
                now=now,
            )
            if dispatch_payload is not None and outcome.created:
                self._insert_job_dispatch_payload_unlocked(
                    job_id=outcome.job_id,
                    payload=dispatch_payload,
                    now=now,
                )
            return outcome

    def _create_operation_bundle_unlocked(
        self,
        *,
        router_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
        scope: str = "hub_admin",
        plan_id: str | None = None,
        actor_type: str = "operator",
        actor_id: str | None = None,
        correlation_id: str | None = None,
        initial_job_status: str = "Queued",
        response_ref: str | None = None,
        http_status: int | None = None,
        expires_in_seconds: int = 86400,
        now: datetime | None = None,
        match_without_router_id: bool = False,
    ) -> IdempotencyOutcome:
        """§6 bundle body; caller must hold an open transaction."""
        if match_without_router_id:
            existing = self._conn.execute(
                "SELECT * FROM idempotency_records WHERE scope = ? "
                "AND operation_kind = ? AND idempotency_key = ?",
                (scope, operation_kind, idempotency_key),
            ).fetchone()
        else:
            existing = self._conn.execute(
                "SELECT * FROM idempotency_records WHERE scope = ? AND router_id = ? "
                "AND operation_kind = ? AND idempotency_key = ?",
                (scope, router_id, operation_kind, idempotency_key),
            ).fetchone()
        if existing is not None:
            if existing["request_digest"] != request_digest:
                raise IdempotencyConflict("same key different digest")
            return self._outcome_from_idempotency_row(existing)

        moment = now or datetime.now(UTC)
        ts = _utc_now_iso(moment)
        expires_at = _utc_now_iso(moment + timedelta(seconds=expires_in_seconds))
        operation_id = new_id("op")
        idempotency_record_id = new_id("idem")
        job_id = new_id("job")
        terminal = initial_job_status in (
            "Succeeded",
            "Failed",
            "Cancelled",
        )
        aggregate = "Converged" if initial_job_status == "Succeeded" else "Pending"
        if initial_job_status == "Failed":
            aggregate = "Failed"
        if initial_job_status == "Cancelled":
            aggregate = "Failed"

        # Insert order: operations then idempotency (UNIQUE 1:1; cyclic FK app-enforced)
        self._conn.execute(
            "INSERT INTO operations("
            "operation_id, router_id, plan_id, operation_kind, aggregate_status, "
            "actor_type, actor_id, idempotency_record_id, correlation_id, "
            "created_at, updated_at, terminal_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                operation_id,
                router_id,
                plan_id,
                operation_kind,
                aggregate,
                actor_type,
                actor_id,
                idempotency_record_id,
                correlation_id,
                ts,
                ts,
                ts if terminal else None,
            ),
        )
        stored_ref = response_ref
        if http_status is not None:
            stored_ref = json.dumps(
                {
                    "http_status": http_status,
                    "body": json.loads(response_ref) if response_ref else {},
                }
            )
        self._conn.execute(
            "INSERT INTO idempotency_records("
            "idempotency_record_id, scope, router_id, operation_kind, idempotency_key, "
            "request_digest, operation_id, response_ref, status, created_at, expires_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                idempotency_record_id,
                scope,
                router_id,
                operation_kind,
                idempotency_key,
                request_digest,
                operation_id,
                stored_ref,
                "Completed" if terminal else "InProgress",
                ts,
                expires_at,
            ),
        )
        self._conn.execute(
            "INSERT INTO jobs("
            "job_id, operation_id, router_id, attempt, status, fencing_token, "
            "cancel_requested, created_at, updated_at, started_at, finished_at"
            ") VALUES (?, ?, ?, 1, ?, 0, 0, ?, ?, ?, ?)",
            (
                job_id,
                operation_id,
                router_id,
                initial_job_status,
                ts,
                ts,
                ts if terminal else None,
                ts if terminal else None,
            ),
        )
        self._conn.execute(
            "INSERT INTO audit_events("
            "audit_event_id, occurred_at, actor_type, actor_id, correlation_id, "
            "router_id, operation_id, job_id, plan_id, action, outcome, summary_redacted, "
            "request_digest"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                new_id("aud"),
                ts,
                actor_type,
                actor_id,
                correlation_id,
                router_id,
                operation_id,
                job_id,
                plan_id,
                f"operation.{operation_kind}",
                "accepted" if not terminal else "completed",
                f"operation_kind={operation_kind}",
                request_digest,
            ),
        )
        return IdempotencyOutcome(
            created=True,
            operation_id=operation_id,
            job_id=job_id,
            idempotency_record_id=idempotency_record_id,
            status="Completed" if terminal else "InProgress",
            response_ref=stored_ref,
            http_status=http_status,
        )

    def enroll_router_with_operation(
        self,
        *,
        site_id: str,
        display_name: str,
        vendor: str,
        model: str,
        identity_fingerprint: str,
        host: str,
        port: int,
        kind: str,
        hardware_revision: str | None,
        credential_ref_id: str,
        credential_kind: str,
        credential_provider: str,
        credential_provider_locator: str,
        idempotency_key: str,
        request_digest: str,
        actor_id: str | None,
        correlation_id: str | None,
        now: datetime | None = None,
        defer_success_response: bool = False,
        source_address: str | None = None,
    ) -> tuple[str, IdempotencyOutcome]:
        """Enroll + credential link + §6 enroll bundle in one SQLite transaction."""
        with transaction(self._conn, immediate=True):
            existing = self.peek_idempotency(
                operation_kind="enroll",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                router_id=None,
            )
            if existing is not None:
                op = self.get_operation(existing.operation_id)
                rid = str(op["router_id"]) if op else ""
                return rid, existing

            moment = now or datetime.now(UTC)
            router_id = self.enroll_router(
                site_id=site_id,
                display_name=display_name,
                vendor=vendor,
                model=model,
                identity_fingerprint=identity_fingerprint,
                host=host,
                port=port,
                kind=kind,
                hardware_revision=hardware_revision,
                source_address=source_address,
                now=moment,
            )
            self._conn.execute(
                "UPDATE routers SET identity_fingerprint = ? WHERE router_id = ?",
                (
                    "digest:enroll:"
                    + hashlib.sha256(router_id.encode()).hexdigest()[:32],
                    router_id,
                ),
            )
            cred_id = self.insert_credential_ref(
                router_id=router_id,
                kind=credential_kind,
                provider=credential_provider,
                provider_locator=credential_provider_locator,
                credential_ref_id=credential_ref_id,
                now=moment,
            )
            self.set_router_credential_ref(router_id, cred_id, now=moment)
            # placeholder body; job/operation ids filled after insert
            outcome = self._create_operation_bundle_unlocked(
                router_id=router_id,
                operation_kind="enroll",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                actor_id=actor_id,
                correlation_id=correlation_id,
                initial_job_status="Running" if defer_success_response else "Queued",
                match_without_router_id=True,
                now=moment,
            )
            if defer_success_response:
                return router_id, outcome
            body = {
                "operation_id": outcome.operation_id,
                "job_id": outcome.job_id,
                "status": "Queued",
                "router_id": router_id,
                "links": {
                    "operation": f"/api/router-control/v1/operations/{outcome.operation_id}",
                    "job": f"/api/router-control/v1/jobs/{outcome.job_id}",
                },
            }
            stored = json.dumps({"http_status": 202, "body": body})
            self._conn.execute(
                "UPDATE idempotency_records SET response_ref = ? "
                "WHERE idempotency_record_id = ?",
                (stored, outcome.idempotency_record_id),
            )
            return router_id, IdempotencyOutcome(
                created=True,
                operation_id=outcome.operation_id,
                job_id=outcome.job_id,
                idempotency_record_id=outcome.idempotency_record_id,
                status=outcome.status,
                response_ref=stored,
                http_status=202,
            )

    def put_credential_with_operation(
        self,
        *,
        router_id: str,
        credential_ref_id: str,
        kind: str,
        provider: str,
        provider_locator: str,
        idempotency_key: str,
        request_digest: str,
        actor_id: str | None,
        response_body: dict[str, Any],
        now: datetime | None = None,
    ) -> IdempotencyOutcome:
        """Credential ref + router link + §6 put_credential bundle in one transaction."""
        with transaction(self._conn, immediate=True):
            existing = self.peek_idempotency(
                router_id=router_id,
                operation_kind="put_credential",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                return existing
            cred_id = self.insert_credential_ref(
                router_id=router_id,
                kind=kind,
                provider=provider,
                provider_locator=provider_locator,
                credential_ref_id=credential_ref_id,
                now=now,
            )
            from router_control.domain.credential_kinds import kind_rebinds_router_management

            if kind_rebinds_router_management(kind):
                self.set_router_credential_ref(router_id, cred_id, now=now)
            body = {**response_body, "credential_ref_id": cred_id}
            return self._create_operation_bundle_unlocked(
                router_id=router_id,
                operation_kind="put_credential",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                actor_id=actor_id,
                initial_job_status="Succeeded",
                response_ref=json.dumps(body),
                http_status=201,
                now=now,
            )

    def update_idempotency_response(
        self, idempotency_record_id: str, *, http_status: int, body: dict[str, Any]
    ) -> None:
        """Cancel single-update policy: may change stored HTTP response exactly once path."""
        self._conn.execute(
            "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
            "WHERE idempotency_record_id = ?",
            (json.dumps({"http_status": http_status, "body": body}), idempotency_record_id),
        )

    def remint_put_credential(
        self,
        *,
        idempotency_record_id: str,
        router_id: str,
        credential_ref_id: str,
        kind: str,
        provider: str,
        provider_locator: str,
        response_body: dict[str, Any],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Replace idempotent put_credential body when prior ref was revoked."""
        with transaction(self._conn, immediate=True):
            cred_id = self.insert_credential_ref(
                router_id=router_id,
                kind=kind,
                provider=provider,
                provider_locator=provider_locator,
                credential_ref_id=credential_ref_id,
                now=now,
            )
            body = {**response_body, "credential_ref_id": cred_id}
            self._conn.execute(
                "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
                "WHERE idempotency_record_id = ?",
                (
                    json.dumps({"http_status": 201, "body": body}),
                    idempotency_record_id,
                ),
            )
            return body

    def get_operation(self, operation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM operations WHERE operation_id = ?", (operation_id,)
            ).fetchone(),
        )

    def get_job(self, job_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone(),
        )

    def list_jobs_for_operation(self, operation_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM jobs WHERE operation_id = ? ORDER BY attempt",
                (operation_id,),
            ).fetchall()
        )

    def list_job_steps(self, job_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM job_steps WHERE job_id = ? ORDER BY ordinal",
                (job_id,),
            ).fetchall()
        )

    def claim_job(
        self,
        *,
        worker_id: str,
        lease_seconds: int = 30,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> ClaimResult | None:
        """BEGIN IMMEDIATE claim of one claimable Queued job (§4.4/§4.6; skip locked routers)."""
        epoch = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            cursor_created_at: str | None = None
            cursor_job_id: str | None = None
            rescanned_from_start = False
            while True:
                if cursor_created_at is None:
                    candidates = self._conn.execute(
                        "SELECT j.job_id, j.router_id, j.fencing_token, o.operation_kind, "
                        "j.created_at "
                        "FROM jobs j JOIN operations o ON o.operation_id = j.operation_id "
                        "WHERE j.status = 'Queued' "
                        "ORDER BY j.created_at, j.job_id "
                        "LIMIT ?",
                        (_CLAIM_JOB_CANDIDATE_BATCH_SIZE,),
                    ).fetchall()
                else:
                    candidates = self._conn.execute(
                        "SELECT j.job_id, j.router_id, j.fencing_token, o.operation_kind, "
                        "j.created_at "
                        "FROM jobs j JOIN operations o ON o.operation_id = j.operation_id "
                        "WHERE j.status = 'Queued' "
                        "AND (j.created_at > ? OR (j.created_at = ? AND j.job_id > ?)) "
                        "ORDER BY j.created_at, j.job_id "
                        "LIMIT ?",
                        (
                            cursor_created_at,
                            cursor_created_at,
                            cursor_job_id,
                            _CLAIM_JOB_CANDIDATE_BATCH_SIZE,
                        ),
                    ).fetchall()
                if not candidates:
                    return None
                batch_all_lock_blocked = True
                for row in candidates:
                    job_id = row["job_id"]
                    router_id = row["router_id"]
                    operation_kind = str(row["operation_kind"])
                    if operation_kind in self._DISPATCH_PAYLOAD_REQUIRED_KINDS:
                        if self.get_job_dispatch_payload(job_id) is None:
                            batch_all_lock_blocked = False
                            continue
                    if operation_kind in self._MUTATION_OPERATION_KINDS:
                        lock = self._conn.execute(
                            "SELECT * FROM router_mutation_locks WHERE router_id = ?",
                            (router_id,),
                        ).fetchone()
                        if lock and lock["active_job_id"] is not None:
                            active = self.get_job(lock["active_job_id"])
                            if active and active["status"] in ("Leased", "Running"):
                                continue
                    batch_all_lock_blocked = False
                    new_fence = int(row["fencing_token"]) + 1
                    lease_until = epoch + lease_seconds
                    updated = self._conn.execute(
                        "UPDATE jobs SET status = 'Leased', lease_owner = ?, "
                        "lease_until_epoch = ?, fencing_token = ?, heartbeat_at = ?, "
                        "updated_at = ?, started_at = COALESCE(started_at, ?) "
                        "WHERE job_id = ? AND status = 'Queued'",
                        (worker_id, lease_until, new_fence, ts, ts, ts, job_id),
                    )
                    if updated.rowcount != 1:
                        continue
                    if operation_kind in self._MUTATION_OPERATION_KINDS:
                        self._conn.execute(
                            "UPDATE router_mutation_locks SET active_job_id = ?, lock_owner = ?, "
                            "lock_until_epoch = ?, fencing_token = ?, updated_at = ? "
                            "WHERE router_id = ?",
                            (job_id, worker_id, lease_until, new_fence, ts, router_id),
                        )
                    return ClaimResult(
                        job_id=job_id,
                        fencing_token=new_fence,
                        lease_owner=worker_id,
                        lease_until_epoch=lease_until,
                    )
                if len(candidates) < _CLAIM_JOB_CANDIDATE_BATCH_SIZE:
                    return None
                if batch_all_lock_blocked and not rescanned_from_start:
                    rescanned_from_start = True
                    cursor_created_at = None
                    cursor_job_id = None
                    continue
                last = candidates[-1]
                cursor_created_at = str(last["created_at"])
                cursor_job_id = str(last["job_id"])

    def _insert_job_dispatch_payload_unlocked(
        self,
        *,
        job_id: str,
        payload: dict[str, Any],
        now: datetime | None = None,
    ) -> str:
        """Dispatch step insert; caller must hold an open transaction."""
        ts = _utc_now_iso(now)
        step_id = new_id("step")
        self._conn.execute(
            "INSERT INTO job_steps("
            "step_id, job_id, ordinal, step_kind, status, attempt, checkpoint_json, "
            "started_at, finished_at"
            ") VALUES (?, ?, 0, 'dispatch', 'Queued', 1, ?, ?, NULL)",
            (step_id, job_id, json.dumps(payload, sort_keys=True), ts),
        )
        return step_id

    def insert_job_dispatch_payload(
        self,
        *,
        job_id: str,
        payload: dict[str, Any],
        now: datetime | None = None,
    ) -> str:
        """Initial dispatch step holding handler context (no secrets)."""
        return self._insert_job_dispatch_payload_unlocked(
            job_id=job_id,
            payload=payload,
            now=now,
        )

    def get_job_dispatch_payload(self, job_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT checkpoint_json FROM job_steps "
            "WHERE job_id = ? AND step_kind = 'dispatch' ORDER BY ordinal LIMIT 1",
            (job_id,),
        ).fetchone()
        if row is None or not row["checkpoint_json"]:
            return None
        return cast(dict[str, Any], json.loads(str(row["checkpoint_json"])))

    def get_idempotency_for_operation(self, operation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM idempotency_records WHERE operation_id = ?",
                (operation_id,),
            ).fetchone(),
        )

    def renew_lease(
        self,
        *,
        job_id: str,
        lease_owner: str,
        fencing_token: int,
        lease_seconds: int,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        """Extend lease + heartbeat; fence-guarded; updates mutation lock if held."""
        epoch = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            job = self.get_job(job_id)
            if job is None:
                raise NotFoundError("job not found")
            if job["lease_owner"] != lease_owner or int(job["fencing_token"]) != fencing_token:
                raise StaleFenceError("stale fencing token or lease owner")
            if str(job["status"]) not in ("Leased", "Running"):
                raise StaleFenceError("job not actively leased")
            _assert_job_lease_valid(self._conn, job, now_epoch=now_epoch, now=now)
            _assert_active_router_fence_for_job(
                self._conn,
                job,
                lease_owner=lease_owner,
                now_epoch=now_epoch,
                now=now,
            )
            lease_until = epoch + lease_seconds
            updated = self._conn.execute(
                "UPDATE jobs SET lease_until_epoch = ?, heartbeat_at = ?, updated_at = ? "
                "WHERE job_id = ? AND lease_owner = ? AND fencing_token = ? "
                "AND status IN ('Leased', 'Running')",
                (lease_until, ts, ts, job_id, lease_owner, fencing_token),
            )
            if updated.rowcount != 1:
                raise StaleFenceError("lease renew rejected")
            op = self.get_operation(str(job["operation_id"]))
            if op is not None and op["operation_kind"] in self._MUTATION_OPERATION_KINDS:
                self._conn.execute(
                    "UPDATE router_mutation_locks SET lock_until_epoch = ?, "
                    "fencing_token = ?, updated_at = ? "
                    "WHERE active_job_id = ? AND lock_owner = ?",
                    (lease_until, fencing_token, ts, job_id, lease_owner),
                )

    _TERMINAL_JOB_STATUSES = frozenset(
        {"Succeeded", "Failed", "Cancelled", "RecoveryRequired"}
    )
    _AGGREGATE_FOR_JOB_STATUS = {
        "Succeeded": "Converged",
        "Failed": "Failed",
        "Cancelled": "Failed",
        "RecoveryRequired": "RecoveryRequired",
    }

    def complete_job(
        self,
        *,
        job_id: str,
        lease_owner: str,
        fencing_token: int,
        status: str,
        summary_redacted: str | None = None,
        http_status: int | None = None,
        response_body: dict[str, Any] | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
        aggregate_status: str | None = None,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        """Fence-guarded terminalization: job, operation, idempotency, lock, audit."""
        if status not in self._TERMINAL_JOB_STATUSES:
            raise ConflictError("complete_job requires terminal status")
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            job = self.get_job(job_id)
            if job is None:
                raise NotFoundError("job not found")
            if job["lease_owner"] != lease_owner or int(job["fencing_token"]) != fencing_token:
                raise StaleFenceError("stale fencing token or lease owner")
            if str(job["status"]) not in ("Leased", "Running"):
                raise StaleFenceError("job not active for completion")
            _assert_job_lease_valid(self._conn, job, now_epoch=now_epoch, now=now)
            _assert_active_router_fence_for_job(
                self._conn,
                job,
                lease_owner=lease_owner,
                now_epoch=now_epoch,
                now=now,
            )
            operation_id = str(job["operation_id"])
            router_id = str(job["router_id"])
            had_cancel_requested = int(job["cancel_requested"])
            clear_late_cancel = status == "Succeeded" and had_cancel_requested
            if clear_late_cancel:
                updated = self._conn.execute(
                    "UPDATE jobs SET status = ?, terminal_outcome = ?, finished_at = ?, "
                    "updated_at = ?, lease_owner = NULL, cancel_requested = 0 "
                    "WHERE job_id = ? AND lease_owner = ? AND fencing_token = ? "
                    "AND status IN ('Leased', 'Running')",
                    (status, status, ts, ts, job_id, lease_owner, fencing_token),
                )
            else:
                updated = self._conn.execute(
                    "UPDATE jobs SET status = ?, terminal_outcome = ?, finished_at = ?, "
                    "updated_at = ?, lease_owner = NULL "
                    "WHERE job_id = ? AND lease_owner = ? AND fencing_token = ? "
                    "AND status IN ('Leased', 'Running')",
                    (status, status, ts, ts, job_id, lease_owner, fencing_token),
                )
            if updated.rowcount != 1:
                raise StaleFenceError("job completion rejected")
            if clear_late_cancel:
                self._update_cancel_idempotency_to_409_terminal(job_id, router_id)
            aggregate = aggregate_status or self._AGGREGATE_FOR_JOB_STATUS[status]
            if status == "Succeeded" and aggregate_status:
                aggregate = aggregate_status
            self._conn.execute(
                "UPDATE operations SET aggregate_status = ?, terminal_at = ?, updated_at = ? "
                "WHERE operation_id = ?",
                (aggregate, ts, ts, operation_id),
            )
            idem = self.get_idempotency_for_operation(operation_id)
            if idem is not None and http_status is not None and response_body is not None:
                stored = json.dumps({"http_status": http_status, "body": response_body})
                skip_idempotency_overwrite = False
                existing_ref = idem["response_ref"]
                if existing_ref and http_status >= 400:
                    try:
                        parsed_existing = json.loads(existing_ref)
                        prior_status = int(parsed_existing.get("http_status", 0))
                        if 200 <= prior_status < 300:
                            skip_idempotency_overwrite = True
                    except (TypeError, ValueError, json.JSONDecodeError):
                        pass
                if not skip_idempotency_overwrite:
                    self._conn.execute(
                        "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
                        "WHERE idempotency_record_id = ?",
                        (stored, idem["idempotency_record_id"]),
                    )
            self._conn.execute(
                "UPDATE router_mutation_locks SET active_job_id = NULL, lock_owner = NULL, "
                "lock_until_epoch = NULL, updated_at = ? WHERE active_job_id = ?",
                (ts, job_id),
            )
            self.append_audit(
                action="worker.complete",
                outcome=status.lower(),
                router_id=router_id,
                operation_id=operation_id,
                job_id=job_id,
                summary_redacted=summary_redacted or f"status={status}",
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=now,
            )

    def record_job_progress(
        self,
        *,
        job_id: str,
        lease_owner: str,
        fencing_token: int,
        status: str | None = None,
        step_kind: str | None = None,
        step_status: str | None = None,
        checkpoint_json: str | None = None,
        error_redacted: str | None = None,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            job = self.get_job(job_id)
            if job is None:
                raise NotFoundError("job not found")
            if job["lease_owner"] != lease_owner or int(job["fencing_token"]) != fencing_token:
                raise StaleFenceError("stale fencing token or lease owner")
            if str(job["status"]) in ("Leased", "Running"):
                _assert_job_lease_valid(self._conn, job, now_epoch=now_epoch, now=now)
                _assert_active_router_fence_for_job(
                    self._conn,
                    job,
                    lease_owner=lease_owner,
                    now_epoch=now_epoch,
                    now=now,
                )
            if status is not None:
                updated = self._conn.execute(
                    "UPDATE jobs SET status = ?, updated_at = ? WHERE job_id = ? "
                    "AND lease_owner = ? AND fencing_token = ?",
                    (status, ts, job_id, lease_owner, fencing_token),
                )
                if updated.rowcount != 1:
                    raise StaleFenceError("job update rejected")
            if step_kind is not None and step_status is not None:
                ordinal_row = self._conn.execute(
                    "SELECT COALESCE(MAX(ordinal), -1) AS m FROM job_steps WHERE job_id = ?",
                    (job_id,),
                ).fetchone()
                ordinal = int(ordinal_row["m"]) + 1
                self._conn.execute(
                    "INSERT INTO job_steps("
                    "step_id, job_id, ordinal, step_kind, status, attempt, checkpoint_json, "
                    "error_redacted, started_at, finished_at"
                    ") VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
                    (
                        new_id("step"),
                        job_id,
                        ordinal,
                        step_kind,
                        step_status,
                        checkpoint_json,
                        error_redacted,
                        ts,
                        ts if step_status in ("Succeeded", "Failed", "RecoveryRequired") else None,
                    ),
                )

    def cancel_job(
        self,
        *,
        target_job_id: str,
        idempotency_key: str,
        request_digest: str,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[int, dict[str, Any], IdempotencyOutcome]:
        """Cancel target + §6 cancel_job bundle in one SQLite transaction (§5.3)."""
        with transaction(self._conn, immediate=True):
            target = self.get_job(target_job_id)
            if target is None:
                raise NotFoundError("job not found")
            router_id = str(target["router_id"])
            status = str(target["status"])

            # Replay before terminal guard so Queued→Cancelled can return stored 200.
            existing = self.peek_idempotency(
                router_id=router_id,
                operation_kind="cancel_job",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                stored = json.loads(existing.response_ref or "{}")
                return (
                    int(stored.get("http_status", 200)),
                    stored.get(
                        "body",
                        {
                            "job_id": target_job_id,
                            "status": status,
                            "cancel_requested": bool(target["cancel_requested"]),
                        },
                    ),
                    existing,
                )

            if status in ("Succeeded", "Failed", "Cancelled", "Lost", "RecoveryRequired"):
                raise ConflictError("job already terminal")

            if status == "Queued":
                http_status = 200
                body: dict[str, Any] = {
                    "job_id": target_job_id,
                    "status": "Cancelled",
                    "cancel_requested": False,
                }
            else:
                http_status = 202
                body = {
                    "job_id": target_job_id,
                    "status": status,
                    "cancel_requested": True,
                }

            outcome = self._create_operation_bundle_unlocked(
                router_id=router_id,
                operation_kind="cancel_job",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                actor_id=actor_id,
                initial_job_status="Succeeded",
                response_ref=json.dumps(body),
                http_status=http_status,
                now=now,
            )

            ts = _utc_now_iso(now)
            if status == "Queued":
                self._conn.execute(
                    "UPDATE jobs SET status = 'Cancelled', finished_at = ?, updated_at = ? "
                    "WHERE job_id = ? AND status = 'Queued'",
                    (ts, ts, target_job_id),
                )
            else:
                self._conn.execute(
                    "UPDATE jobs SET cancel_requested = 1, updated_at = ? "
                    "WHERE job_id = ? AND status IN ('Leased', 'Running')",
                    (ts, target_job_id),
                )
            return http_status, body, outcome

    def mark_target_job_cancelled(
        self, *, target_job_id: str, now: datetime | None = None
    ) -> None:
        """Transition cancel_requested target → Cancelled; update cancel idempotency 202→200."""
        with transaction(self._conn, immediate=True):
            target = self.get_job(target_job_id)
            if target is None:
                raise NotFoundError("job not found")
            if target["status"] == "Cancelled":
                self._update_cancel_idempotency_to_200(target_job_id, target["router_id"])
                return
            if not int(target["cancel_requested"]):
                raise ConflictError("cancel not requested")
            if target["status"] not in ("Leased", "Running"):
                raise ConflictError("job not cancellable at boundary")
            ts = _utc_now_iso(now)
            updated = self._conn.execute(
                "UPDATE jobs SET status = 'Cancelled', finished_at = ?, updated_at = ? "
                "WHERE job_id = ? AND cancel_requested = 1 "
                "AND status IN ('Leased', 'Running')",
                (ts, ts, target_job_id),
            )
            if updated.rowcount != 1:
                raise ConflictError("cancel finalize rejected")
            operation_id = str(target["operation_id"])
            self._conn.execute(
                "UPDATE operations SET aggregate_status = 'Failed', "
                "terminal_at = ?, updated_at = ? WHERE operation_id = ?",
                (ts, ts, operation_id),
            )
            self._conn.execute(
                "UPDATE router_mutation_locks SET active_job_id = NULL, lock_owner = NULL, "
                "lock_until_epoch = NULL, updated_at = ? WHERE active_job_id = ?",
                (ts, target_job_id),
            )
            self._update_cancel_idempotency_to_200(target_job_id, str(target["router_id"]))

    def _update_cancel_idempotency_to_200(self, target_job_id: str, router_id: str) -> None:
        rows = self._conn.execute(
            "SELECT * FROM idempotency_records WHERE router_id = ? "
            "AND operation_kind = 'cancel_job'",
            (router_id,),
        ).fetchall()
        for row in rows:
            if not row["response_ref"]:
                continue
            try:
                payload = json.loads(row["response_ref"])
            except (json.JSONDecodeError, TypeError) as exc:
                _LOGGER.warning(
                    "cancel idempotency response_ref JSON invalid record=%s: %s",
                    row["idempotency_record_id"],
                    type(exc).__name__,
                )
                continue
            body = payload.get("body") or {}
            if body.get("job_id") != target_job_id:
                continue
            if int(payload.get("http_status", 0)) != 202:
                return
            self.update_idempotency_response(
                row["idempotency_record_id"],
                http_status=200,
                body={
                    "job_id": target_job_id,
                    "status": "Cancelled",
                    "cancel_requested": False,
                },
            )
            return

    def _update_cancel_idempotency_to_409_terminal(
        self, target_job_id: str, router_id: str
    ) -> None:
        rows = self._conn.execute(
            "SELECT * FROM idempotency_records WHERE router_id = ? "
            "AND operation_kind = 'cancel_job'",
            (router_id,),
        ).fetchall()
        for row in rows:
            if not row["response_ref"]:
                continue
            try:
                payload = json.loads(row["response_ref"])
            except (json.JSONDecodeError, TypeError) as exc:
                _LOGGER.warning(
                    "cancel idempotency response_ref JSON invalid record=%s: %s",
                    row["idempotency_record_id"],
                    type(exc).__name__,
                )
                continue
            body = payload.get("body") or {}
            if body.get("job_id") != target_job_id:
                continue
            if int(payload.get("http_status", 0)) != 202:
                return
            self.update_idempotency_response(
                row["idempotency_record_id"],
                http_status=409,
                body={
                    "error": {
                        "code": "job.already_terminal",
                        "message": "job already terminal",
                        "details": [],
                    }
                },
            )
            return

    def _job_has_post_dispatch_progress(self, job_id: str, job_status: str) -> bool:
        """True after worker dispatch/handler progress or legacy apply step (INV-8)."""
        if job_status == "Running":
            return True
        row = self._conn.execute(
            "SELECT 1 FROM job_steps WHERE job_id = ? AND ("
            "(step_kind = 'apply' AND status IN ('Running', 'Succeeded')) OR "
            "(step_kind = 'dispatch' AND status IN ('Running', 'Succeeded')) OR "
            "(step_kind = 'handler' AND status IN ('Running', 'Succeeded'))"
            ") LIMIT 1",
            (job_id,),
        ).fetchone()
        return row is not None

    def recover_expired_leases(
        self, *, now_epoch: int | None = None, now: datetime | None = None
    ) -> list[str]:
        """Mark Leased/Running with expired lease as Lost or RecoveryRequired; return job_ids."""
        ts = _utc_now_iso(now)
        lost_ids: list[str] = []
        with transaction(self._conn, immediate=True):
            db_now = _lease_validity_epoch(
                self._conn, now_epoch=now_epoch, now=now
            )
            rows = self._conn.execute(
                "SELECT job_id, router_id, status FROM jobs "
                "WHERE status IN ('Leased', 'Running') AND lease_until_epoch IS NOT NULL "
                "AND lease_until_epoch < ?",
                (db_now,),
            ).fetchall()
            for row in rows:
                job_id = str(row["job_id"])
                job_status = str(row["status"])
                if self._job_has_post_dispatch_progress(job_id, job_status):
                    new_status = "RecoveryRequired"
                else:
                    new_status = "Lost"
                self._conn.execute(
                    "UPDATE jobs SET status = ?, lease_owner = NULL, updated_at = ?, "
                    "finished_at = ?, recovery_state = 'expired_lease' WHERE job_id = ?",
                    (new_status, ts, ts, job_id),
                )
                self._conn.execute(
                    "UPDATE router_mutation_locks SET active_job_id = NULL, lock_owner = NULL, "
                    "lock_until_epoch = NULL, updated_at = ? WHERE active_job_id = ?",
                    (ts, job_id),
                )
                if new_status == "RecoveryRequired":
                    op_row = self._conn.execute(
                        "SELECT operation_id FROM jobs WHERE job_id = ?",
                        (job_id,),
                    ).fetchone()
                    if op_row:
                        self._conn.execute(
                            "UPDATE operations SET aggregate_status = 'RecoveryRequired', "
                            "updated_at = ? WHERE operation_id = ?",
                            (ts, op_row["operation_id"]),
                        )
                lost_ids.append(job_id)
                if new_status == "Lost":
                    dispatch_payload = self.get_job_dispatch_payload(job_id)
                    op = self._conn.execute(
                        "SELECT operation_id FROM jobs WHERE job_id = ?",
                        (job_id,),
                    ).fetchone()
                    if op:
                        attempt_row = self._conn.execute(
                            "SELECT MAX(attempt) AS m FROM jobs WHERE operation_id = ?",
                            (op["operation_id"],),
                        ).fetchone()
                        next_attempt = int(attempt_row["m"]) + 1
                        new_job_id = new_id("job")
                        self._conn.execute(
                            "INSERT INTO jobs("
                            "job_id, operation_id, router_id, attempt, status, fencing_token, "
                            "cancel_requested, recovery_state, created_at, updated_at"
                            ") VALUES (?, ?, ?, ?, 'Queued', 0, 0, 'resume_after_lost', ?, ?)",
                            (
                                new_job_id,
                                op["operation_id"],
                                row["router_id"],
                                next_attempt,
                                ts,
                                ts,
                            ),
                        )
                        if dispatch_payload is not None:
                            self.insert_job_dispatch_payload(
                                job_id=new_job_id,
                                payload=dispatch_payload,
                                now=now,
                            )
        return lost_ids

    def list_plan_items(self, plan_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM change_plan_items WHERE plan_id = ? ORDER BY ordinal",
                (plan_id,),
            ).fetchall()
        )

    def insert_backup_artifact_metadata(
        self,
        *,
        artifact_id: str,
        router_id: str,
        operation_id: str,
        content_digest: str,
        size_bytes: int,
        identity_fingerprint: str,
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO backup_artifacts("
            "artifact_id, router_id, operation_id, kind, storage_locator, content_digest, "
            "size_bytes, identity_fingerprint, verification_status, created_at"
            ") VALUES (?, ?, ?, 'startup-config-backup', ?, ?, ?, ?, 'Verified', ?)",
            (
                artifact_id,
                router_id,
                operation_id,
                "digest:locator:redacted",
                content_digest,
                size_bytes,
                identity_fingerprint,
                ts,
            ),
        )

    def get_backup_artifact(self, artifact_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM backup_artifacts WHERE artifact_id = ?",
                (artifact_id,),
            ).fetchone(),
        )

    def get_backup_artifact_redacted(self, artifact_id: str) -> dict[str, Any] | None:
        row = self.get_backup_artifact(artifact_id)
        if row is None:
            return None
        from router_control.persistence.artifacts import redacted_backup_dto

        return redacted_backup_dto(row)

    def _create_recovery_resume_job_unlocked(
        self,
        *,
        source: sqlite3.Row,
        recovery_state: str,
        dispatch_payload: dict[str, Any],
        now: datetime | None = None,
    ) -> str:
        operation_id = str(source["operation_id"])
        router_id = str(source["router_id"])
        ts = _utc_now_iso(now)
        attempt_row = self._conn.execute(
            "SELECT MAX(attempt) AS m FROM jobs WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        next_attempt = int(attempt_row["m"]) + 1
        new_job_id = new_id("job")
        self._conn.execute(
            "INSERT INTO jobs("
            "job_id, operation_id, router_id, attempt, status, fencing_token, "
            "cancel_requested, recovery_state, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, 'Queued', 0, 0, ?, ?, ?)",
            (
                new_job_id,
                operation_id,
                router_id,
                next_attempt,
                recovery_state,
                ts,
                ts,
            ),
        )
        if dispatch_payload:
            self._insert_job_dispatch_payload_unlocked(
                job_id=new_job_id,
                payload=dispatch_payload,
                now=now,
            )
        return new_job_id

    def create_recovery_resume_job(
        self,
        *,
        source_job_id: str,
        recovery_state: str,
        dispatch_payload: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> str:
        """New Queued attempt under same operation (Lost/RecoveryRequired resume pattern)."""
        source = self.get_job(source_job_id)
        if source is None:
            raise NotFoundError("source job not found")
        if str(source["status"]) not in ("RecoveryRequired", "Lost", "Failed"):
            raise ConflictError("source job not eligible for recovery resume")
        payload = dispatch_payload if dispatch_payload is not None else (
            self.get_job_dispatch_payload(source_job_id) or {}
        )
        with transaction(self._conn, immediate=True):
            return self._create_recovery_resume_job_unlocked(
                source=source,
                recovery_state=recovery_state,
                dispatch_payload=payload,
                now=now,
            )

    def resume_recovery_job(
        self,
        *,
        target_job_id: str,
        action: str,
        idempotency_key: str,
        request_digest: str,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[int, dict[str, Any]]:
        """Idempotent fake-only resume/compensate — new Queued job, same operation_id."""
        if action not in ("resume", "compensate"):
            raise ConflictError("unsupported recovery action")
        expected_digest = request_digest
        with transaction(self._conn, immediate=True):
            target = self.get_job(target_job_id)
            if target is None:
                raise NotFoundError("job not found")
            router_id = str(target["router_id"])
            operation_id = str(target["operation_id"])

            for job in self.list_jobs_for_operation(operation_id):
                payload = self.get_job_dispatch_payload(str(job["job_id"])) or {}
                if (
                    payload.get("resume_idempotency_key") == idempotency_key
                    and payload.get("resume_request_digest") == expected_digest
                ):
                    return 202, {
                        "source_job_id": target_job_id,
                        "job_id": str(job["job_id"]),
                        "operation_id": operation_id,
                        "recovery_state": str(job["recovery_state"]),
                        "status": str(job["status"]),
                    }

            if str(target["status"]) != "RecoveryRequired":
                op = self.get_operation(operation_id)
                if op is None or str(op["aggregate_status"]) != "RecoveryRequired":
                    raise ConflictError("job not in RecoveryRequired state")

            recovery_state = (
                "resume_after_readback" if action == "resume" else "compensate"
            )
            payload = dict(self.get_job_dispatch_payload(target_job_id) or {})
            payload["recovery_action"] = action
            payload["resume_idempotency_key"] = idempotency_key
            payload["resume_request_digest"] = expected_digest

            new_job_id = self._create_recovery_resume_job_unlocked(
                source=target,
                recovery_state=recovery_state,
                dispatch_payload=payload,
                now=now,
            )
            body = {
                "source_job_id": target_job_id,
                "job_id": new_job_id,
                "operation_id": operation_id,
                "recovery_state": recovery_state,
                "status": "Queued",
            }
            self.append_audit(
                action=f"recovery.{action}",
                outcome="accepted",
                router_id=router_id,
                operation_id=operation_id,
                job_id=new_job_id,
                summary_redacted=f"recovery {action} queued",
                actor_id=actor_id,
                request_digest=expected_digest,
                now=now,
            )
            return 202, body

    def append_audit(
        self,
        *,
        action: str,
        outcome: str,
        router_id: str | None = None,
        operation_id: str | None = None,
        job_id: str | None = None,
        plan_id: str | None = None,
        summary_redacted: str | None = None,
        actor_type: str = "system",
        actor_id: str | None = None,
        correlation_id: str | None = None,
        request_digest: str | None = None,
        now: datetime | None = None,
    ) -> str:
        aid = new_id("aud")
        self._conn.execute(
            "INSERT INTO audit_events("
            "audit_event_id, occurred_at, actor_type, actor_id, correlation_id, router_id, "
            "operation_id, job_id, plan_id, action, outcome, summary_redacted, request_digest"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                aid,
                _utc_now_iso(now),
                actor_type,
                actor_id,
                correlation_id,
                router_id,
                operation_id,
                job_id,
                plan_id,
                action,
                outcome,
                summary_redacted,
                request_digest,
            ),
        )
        return aid

    def get_sealed_apply_trail_snapshot_for_audit(
        self,
        *,
        correlation_id: str | None,
        route: str,
        verb: str,
    ) -> dict[str, Any] | None:
        """Return latest redacted sealed_apply_runs snapshot for audit correlation."""
        if not correlation_id:
            return None
        row = self._conn.execute(
            "SELECT run_id, status, overall, ops_planned_redacted, "
            "ops_pending_redacted, ops_dispatched_redacted, checkpoint_json, "
            "pre_apply_baseline_redacted, ops_evidence_redacted "
            "FROM sealed_apply_runs WHERE correlation_id = ? AND route = ? AND verb = ? "
            "ORDER BY started_at DESC LIMIT 1",
            (correlation_id, route, verb),
        ).fetchone()
        if row is None:
            return None
        return build_sealed_apply_trail_snapshot_for_audit(row)

    def try_append_sealed_apply_audit(
        self,
        *,
        action: str,
        outcome: str,
        route: str,
        verb: str,
        intent_redacted: dict[str, Any],
        router_id: str | None = None,
        correlation_id: str | None = None,
        result_payload: dict[str, Any] | None = None,
        outcome_snapshot: dict[str, Any] | None = None,
        error_message: str | None = None,
        exception_type: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> str | None:
        """Append sealed apply/teardown audit; never raise (logs on persistence failure)."""
        try:
            trail_snapshot = self.get_sealed_apply_trail_snapshot_for_audit(
                correlation_id=correlation_id,
                route=route,
                verb=verb,
            )
            summary = build_sealed_apply_audit_summary(
                route=route,
                verb=verb,
                intent_redacted=intent_redacted,
                result_payload=result_payload,
                outcome_snapshot=outcome_snapshot,
                error_message=error_message,
                exception_type=exception_type,
                trail_snapshot=trail_snapshot,
            )
            return self.append_audit(
                action=action,
                outcome=outcome,
                router_id=router_id,
                correlation_id=correlation_id,
                summary_redacted=summary,
                request_digest=sealed_apply_request_digest(intent_redacted),
                actor_id=actor_id,
                now=now,
            )
        except Exception as exc:
            _LOGGER.warning(
                "sealed_apply audit append failed action=%s route=%s: %s",
                action,
                route,
                type(exc).__name__,
            )
            return None

    def begin_sealed_apply_run(
        self,
        *,
        route: str,
        verb: str,
        intent_summary_redacted: dict[str, Any],
        ops_planned_redacted: tuple[str, ...],
        router_id: str | None = None,
        correlation_id: str | None = None,
        lease_owner: str,
        lease_seconds: int = _SEALED_APPLY_LEASE_SECONDS,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> str:
        from router_control.application.recovery import checkpoint_redacted

        run_id = new_id("sar")
        ts = _utc_now_iso(now)
        intent_text = json.dumps(intent_summary_redacted, sort_keys=True, separators=(",", ":"))
        ops_planned_json = json.dumps(list(ops_planned_redacted), separators=(",", ":"))
        checkpoint = checkpoint_redacted(phase="dispatch", apply_dispatched=False)
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        lease_until = validity + lease_seconds

        effective_router_id = router_id
        if effective_router_id is not None and self.get_router(effective_router_id) is None:
            _LOGGER.warning(
                "sealed_apply run begin: router_id %s not enrolled; storing NULL",
                effective_router_id,
            )
            effective_router_id = None

        def _insert(rid: str | None) -> None:
            self._conn.execute(
                "INSERT INTO sealed_apply_runs("
                "run_id, router_id, route, verb, status, correlation_id, request_digest, "
                "intent_summary_redacted, checkpoint_json, ops_planned_redacted, "
                "ops_pending_redacted, ops_dispatched_redacted, pre_apply_baseline_redacted, "
                "ops_evidence_redacted, outcome_snapshot_redacted, overall, error_redacted, "
                "lease_owner, lease_until_epoch, started_at, updated_at, finished_at"
                ") VALUES (?, ?, ?, ?, 'Running', ?, ?, ?, ?, ?, '[]', '[]', NULL, '{}', NULL, "
                "NULL, NULL, ?, ?, ?, ?, NULL)",
                (
                    run_id,
                    rid,
                    route,
                    verb,
                    correlation_id,
                    sealed_apply_request_digest(intent_summary_redacted),
                    intent_text,
                    checkpoint,
                    ops_planned_json,
                    lease_owner,
                    lease_until,
                    ts,
                    ts,
                ),
            )

        try:
            _insert(effective_router_id)
        except sqlite3.IntegrityError:
            if effective_router_id is None:
                raise
            _LOGGER.warning(
                "sealed_apply run begin: FK rejected router_id %s; retrying with NULL",
                effective_router_id,
            )
            _insert(None)
        return run_id

    def renew_sealed_apply_lease(
        self,
        run_id: str,
        *,
        lease_owner: str,
        lease_seconds: int = _SEALED_APPLY_LEASE_SECONDS,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> None:
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        lease_until = validity + lease_seconds
        ts = _utc_now_iso(now)
        cur = self._conn.execute(
            "UPDATE sealed_apply_runs SET lease_until_epoch = ?, updated_at = ? "
            "WHERE run_id = ? AND status = 'Running' AND lease_owner = ?",
            (lease_until, ts, run_id, lease_owner),
        )
        if cur.rowcount == 0:
            raise NotFoundError(f"sealed_apply_run not found or lease lost: {run_id}")

    def _renew_sealed_apply_lease(
        self,
        run_id: str,
        *,
        lease_owner: str,
        lease_seconds: int = _SEALED_APPLY_LEASE_SECONDS,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> None:
        self.renew_sealed_apply_lease(
            run_id,
            lease_owner=lease_owner,
            lease_seconds=lease_seconds,
            now=now,
            now_epoch=now_epoch,
        )

    def _load_sealed_apply_op_lists(
        self, run_id: str
    ) -> tuple[list[str], list[str], dict[str, Any], sqlite3.Row]:
        row = self._conn.execute(
            "SELECT ops_pending_redacted, ops_dispatched_redacted, ops_evidence_redacted "
            "FROM sealed_apply_runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(f"sealed_apply_run not found: {run_id}")
        pending = _parse_sealed_apply_trail_lists(row["ops_pending_redacted"])
        dispatched = _parse_sealed_apply_trail_lists(row["ops_dispatched_redacted"])
        evidence = _parse_sealed_apply_ops_evidence(
            row["ops_evidence_redacted"] if "ops_evidence_redacted" in row.keys() else None
        )
        return pending, dispatched, evidence, row

    def record_sealed_apply_pre_apply_baseline(
        self,
        run_id: str,
        baseline_redacted: dict[str, Any],
        *,
        lease_owner: str,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> None:
        baseline_json = json.dumps(baseline_redacted, sort_keys=True, separators=(",", ":"))
        ts = _utc_now_iso(now)
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        lease_until = validity + _SEALED_APPLY_LEASE_SECONDS
        with transaction(self._conn, immediate=True):
            cur = self._conn.execute(
                "UPDATE sealed_apply_runs SET pre_apply_baseline_redacted = ?, "
                "updated_at = ?, lease_until_epoch = ? "
                "WHERE run_id = ? AND status = 'Running' AND lease_owner = ? "
                "AND pre_apply_baseline_redacted IS NULL",
                (baseline_json, ts, lease_until, run_id, lease_owner),
            )
            if cur.rowcount == 0:
                raise NotFoundError(
                    f"sealed_apply_run not found, lease lost, or baseline already set: {run_id}"
                )

    def record_sealed_apply_op_intent(
        self,
        run_id: str,
        op_name_redacted: str,
        *,
        lease_owner: str,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> None:
        from router_control.application.recovery import checkpoint_redacted

        pending, dispatched, evidence, _row = self._load_sealed_apply_op_lists(run_id)
        if op_name_redacted not in pending:
            pending.append(op_name_redacted)
        pending_json = json.dumps(pending, separators=(",", ":"))
        checkpoint = checkpoint_redacted(
            phase="dispatch",
            apply_dispatched=bool(dispatched),
            ops_dispatched_redacted=tuple(dispatched) if dispatched else None,
        )
        ts = _utc_now_iso(now)
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        lease_until = validity + _SEALED_APPLY_LEASE_SECONDS
        with transaction(self._conn, immediate=True):
            cur = self._conn.execute(
                "UPDATE sealed_apply_runs SET ops_pending_redacted = ?, checkpoint_json = ?, "
                "updated_at = ?, lease_until_epoch = ? "
                "WHERE run_id = ? AND status = 'Running' AND lease_owner = ?",
                (pending_json, checkpoint, ts, lease_until, run_id, lease_owner),
            )
            if cur.rowcount == 0:
                raise NotFoundError(
                    f"sealed_apply_run not found or lease lost: {run_id}"
                )

    def abandon_sealed_apply_op_intent(
        self,
        run_id: str,
        op_name_redacted: str,
        *,
        lease_owner: str,
        op_evidence_redacted: dict[str, Any] | None = None,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> None:
        from router_control.application.recovery import checkpoint_redacted

        pending, dispatched, evidence, _row = self._load_sealed_apply_op_lists(run_id)
        pending = [op for op in pending if op != op_name_redacted]
        evidence = _merge_sealed_apply_op_evidence(
            evidence, op_name_redacted, op_evidence_redacted
        )
        pending_json = json.dumps(pending, separators=(",", ":"))
        evidence_json = json.dumps(evidence, separators=(",", ":"))
        checkpoint = checkpoint_redacted(
            phase="dispatch",
            apply_dispatched=bool(dispatched),
            ops_dispatched_redacted=tuple(dispatched) if dispatched else None,
        )
        ts = _utc_now_iso(now)
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        lease_until = validity + _SEALED_APPLY_LEASE_SECONDS
        with transaction(self._conn, immediate=True):
            cur = self._conn.execute(
                "UPDATE sealed_apply_runs SET ops_pending_redacted = ?, ops_evidence_redacted = ?, "
                "checkpoint_json = ?, updated_at = ?, lease_until_epoch = ? "
                "WHERE run_id = ? AND status = 'Running' AND lease_owner = ?",
                (pending_json, evidence_json, checkpoint, ts, lease_until, run_id, lease_owner),
            )
            if cur.rowcount == 0:
                raise NotFoundError(
                    f"sealed_apply_run not found or lease lost: {run_id}"
                )

    def record_sealed_apply_op_progress(
        self,
        run_id: str,
        op_name_redacted: str,
        *,
        lease_owner: str,
        op_evidence_redacted: dict[str, Any] | None = None,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> None:
        # Public store methods are RLock-wrapped at class init (_lock_store_method).
        from router_control.application.recovery import checkpoint_redacted

        pending, dispatched, evidence, _row = self._load_sealed_apply_op_lists(run_id)
        pending = [op for op in pending if op != op_name_redacted]
        if op_name_redacted not in dispatched:
            dispatched.append(op_name_redacted)
        evidence = _merge_sealed_apply_op_evidence(
            evidence, op_name_redacted, op_evidence_redacted
        )
        pending_json = json.dumps(pending, separators=(",", ":"))
        ops_json = json.dumps(dispatched, separators=(",", ":"))
        evidence_json = json.dumps(evidence, separators=(",", ":"))
        checkpoint = checkpoint_redacted(
            phase="dispatch",
            apply_dispatched=True,
            ops_dispatched_redacted=tuple(dispatched),
        )
        ts = _utc_now_iso(now)
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        lease_until = validity + _SEALED_APPLY_LEASE_SECONDS
        with transaction(self._conn, immediate=True):
            cur = self._conn.execute(
                "UPDATE sealed_apply_runs SET ops_pending_redacted = ?, "
                "ops_dispatched_redacted = ?, ops_evidence_redacted = ?, checkpoint_json = ?, "
                "updated_at = ?, lease_until_epoch = ? "
                "WHERE run_id = ? AND status = 'Running' AND lease_owner = ?",
                (
                    pending_json,
                    ops_json,
                    evidence_json,
                    checkpoint,
                    ts,
                    lease_until,
                    run_id,
                    lease_owner,
                ),
            )
            if cur.rowcount == 0:
                raise NotFoundError(
                    f"sealed_apply_run not found or lease lost: {run_id}"
                )

    def finish_sealed_apply_run(
        self,
        run_id: str,
        *,
        lease_owner: str,
        status: str,
        overall: str | None = None,
        error_redacted: str | None = None,
        outcome_snapshot_redacted: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> bool:
        """Fence-guarded terminalization; returns False when lease was lost."""
        ts = _utc_now_iso(now)
        outcome_json = (
            json.dumps(outcome_snapshot_redacted, sort_keys=True, separators=(",", ":"))
            if outcome_snapshot_redacted is not None
            else None
        )
        with transaction(self._conn, immediate=True):
            cur = self._conn.execute(
                "UPDATE sealed_apply_runs SET status = ?, overall = ?, error_redacted = ?, "
                "outcome_snapshot_redacted = ?, updated_at = ?, finished_at = ?, "
                "lease_owner = NULL, lease_until_epoch = NULL "
                "WHERE run_id = ? AND status = 'Running' AND lease_owner = ?",
                (status, overall, error_redacted, outcome_json, ts, ts, run_id, lease_owner),
            )
            return cur.rowcount == 1

    def interrupt_stale_sealed_apply_runs(
        self,
        *,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> int:
        """Mark Running sealed applies with expired lease Interrupted (local DB only)."""
        ts = _utc_now_iso(now)
        db_now = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        if now is not None:
            stale_moment = now.astimezone(UTC) - timedelta(seconds=_SEALED_APPLY_LEASE_SECONDS)
        else:
            stale_moment = datetime.fromtimestamp(
                db_now - _SEALED_APPLY_LEASE_SECONDS,
                tz=UTC,
            )
        stale_started_before = _utc_now_iso(stale_moment)
        cur = self._conn.execute(
            "UPDATE sealed_apply_runs SET status = 'Interrupted', updated_at = ?, "
            "lease_owner = NULL, lease_until_epoch = NULL "
            "WHERE status = 'Running' AND ("
            "(lease_until_epoch IS NOT NULL AND lease_until_epoch < ?) OR "
            "(lease_until_epoch IS NULL AND started_at < ?)"
            ")",
            (ts, db_now, stale_started_before),
        )
        return int(cur.rowcount)

    def list_unfinished_sealed_applies(
        self,
        *,
        router_id: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if router_id is not None:
            rows = self._conn.execute(
                "SELECT * FROM sealed_apply_runs WHERE status IN ('Running', 'Interrupted') "
                "AND router_id = ? ORDER BY started_at DESC LIMIT ?",
                (router_id, limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM sealed_apply_runs WHERE status IN ('Running', 'Interrupted') "
                "ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_audit_events(
        self,
        *,
        action_prefix: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if action_prefix:
            rows = self._conn.execute(
                "SELECT * FROM audit_events WHERE action LIKE ? "
                "ORDER BY occurred_at DESC LIMIT ?",
                (f"{action_prefix}%", limit),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM audit_events ORDER BY occurred_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    # --- profiles ---

    def import_profile(
        self,
        *,
        display_name: str,
        vpn_kind: str,
        content_digest: str,
        parser_version: str = "1",
        validation_status: str = "Valid",
        metadata_json: str | None = None,
        unsupported_fields_json: str | None = None,
        profile_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        pid = profile_id or new_id("prof")
        self._conn.execute(
            "INSERT INTO vpn_profile_artifacts("
            "profile_id, display_name, vpn_kind, parser_version, content_digest, "
            "metadata_json, validation_status, unsupported_fields_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                pid,
                display_name,
                vpn_kind,
                parser_version,
                content_digest,
                metadata_json,
                validation_status,
                unsupported_fields_json,
                _utc_now_iso(now),
            ),
        )
        return pid

    def list_profiles(self, *, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM vpn_profile_artifacts WHERE superseded_at IS NULL "
                "ORDER BY created_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        )

    def get_profile(self, profile_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM vpn_profile_artifacts "
                "WHERE profile_id = ? AND superseded_at IS NULL",
                (profile_id,),
            ).fetchone(),
        )

    def get_profile_including_superseded(self, profile_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM vpn_profile_artifacts WHERE profile_id = ?",
                (profile_id,),
            ).fetchone(),
        )

    def _profile_has_active_tunnel_assignment(self, profile_id: str) -> bool:
        for assignment in self.list_active_tunnel_assignments():
            if str(assignment["profile_id"]) == profile_id:
                return True
        return False

    def _profile_vpn_activate_apply_in_progress(
        self,
        profile_id: str,
        *,
        now: datetime | None = None,
    ) -> bool:
        """True when activate apply is running or post-apply assignment upsert may be pending."""
        running = self._conn.execute(
            "SELECT 1 FROM sealed_apply_runs "
            "WHERE status = 'Running' AND route = 'vpn-profiles' AND verb = 'activate' "
            "AND json_extract(intent_summary_redacted, '$.profile_id') = ? "
            "LIMIT 1",
            (profile_id,),
        ).fetchone()
        if running is not None:
            return True
        if self._profile_has_active_tunnel_assignment(profile_id):
            return False
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        finished_after = _utc_now_iso(
            moment - timedelta(seconds=_VPN_ACTIVATE_GAP_GRACE_SECONDS)
        )
        recent_succeeded = self._conn.execute(
            "SELECT 1 FROM sealed_apply_runs "
            "WHERE status = 'Succeeded' AND route = 'vpn-profiles' AND verb = 'activate' "
            "AND json_extract(intent_summary_redacted, '$.profile_id') = ? "
            "AND finished_at IS NOT NULL AND finished_at >= ? "
            "LIMIT 1",
            (profile_id, finished_after),
        ).fetchone()
        return recent_succeeded is not None

    def update_profile_validation(
        self,
        *,
        profile_id: str,
        validation_status: str,
        parser_version: str,
    ) -> None:
        cur = self._conn.execute(
            "UPDATE vpn_profile_artifacts SET validation_status = ?, parser_version = ? "
            "WHERE profile_id = ?",
            (validation_status, parser_version, profile_id),
        )
        if cur.rowcount == 0:
            raise NotFoundError(f"profile {profile_id} not found")

    def merge_profile_metadata(
        self,
        *,
        profile_id: str,
        patch: dict[str, Any],
    ) -> None:
        """Merge ``patch`` keys into profile ``metadata_json`` (non-superseded row)."""
        row = self.get_profile(profile_id)
        if row is None:
            raise NotFoundError(f"profile {profile_id} not found")
        raw = row["metadata_json"]
        if raw:
            try:
                metadata = json.loads(raw)
            except json.JSONDecodeError:
                metadata = {}
        else:
            metadata = {}
        if not isinstance(metadata, dict):
            metadata = {}
        metadata.update(patch)
        cur = self._conn.execute(
            "UPDATE vpn_profile_artifacts SET metadata_json = ? "
            "WHERE profile_id = ? AND superseded_at IS NULL",
            (json.dumps(metadata, sort_keys=True), profile_id),
        )
        if cur.rowcount == 0:
            raise NotFoundError(f"profile {profile_id} not found")

    def insert_profile_secret_refs(
        self,
        *,
        profile_id: str,
        refs: list[tuple[str, str]],
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        for credential_ref_id, role in refs:
            self._conn.execute(
                "INSERT INTO vpn_profile_secret_refs("
                "profile_id, credential_ref_id, role, created_at"
                ") VALUES (?, ?, ?, ?)",
                (profile_id, credential_ref_id, role, ts),
            )

    def list_profile_secret_refs(self, profile_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT credential_ref_id, role, created_at FROM vpn_profile_secret_refs "
            "WHERE profile_id = ? ORDER BY role",
            (profile_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def delete_profile_secret_refs(self, profile_id: str) -> None:
        self._conn.execute(
            "DELETE FROM vpn_profile_secret_refs WHERE profile_id = ?",
            (profile_id,),
        )

    def count_credential_ref_profile_links(self, credential_ref_id: str) -> int:
        row = self._conn.execute(
            "SELECT COUNT(*) AS cnt FROM vpn_profile_secret_refs "
            "WHERE credential_ref_id = ?",
            (credential_ref_id,),
        ).fetchone()
        return int(row["cnt"]) if row is not None else 0

    def credential_ref_has_active_tunnel_assignment(self, credential_ref_id: str) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM vpn_profile_secret_refs psr "
            "JOIN tunnel_assignments ta ON ta.profile_id = psr.profile_id "
            "WHERE psr.credential_ref_id = ? "
            "AND ta.desired_active = 1 AND ta.retired_at IS NULL "
            "LIMIT 1",
            (credential_ref_id,),
        ).fetchone()
        return row is not None

    def credential_ref_has_non_vpn_live_links(self, credential_ref_id: str) -> bool:
        standing = self._conn.execute(
            "SELECT 1 FROM standing_network_preferences "
            "WHERE staff_password_credential_ref_id = ? LIMIT 1",
            (credential_ref_id,),
        ).fetchone()
        if standing is not None:
            return True
        remembered = self._conn.execute(
            "SELECT 1 FROM remembered_uplink "
            "WHERE credential_ref_id = ? LIMIT 1",
            (credential_ref_id,),
        ).fetchone()
        if remembered is not None:
            return True
        router = self._conn.execute(
            "SELECT 1 FROM routers WHERE credential_ref_id = ? LIMIT 1",
            (credential_ref_id,),
        ).fetchone()
        return router is not None

    def _validate_vpn_profile_catalog_remove_gates(
        self,
        profile_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        row = self.get_profile_including_superseded(profile_id)
        if row is None:
            raise NotFoundError(f"profile {profile_id} not found")
        if row["superseded_at"] is not None:
            raise AlreadyRetiredError(f"profile {profile_id} already retired")
        if self._profile_vpn_activate_apply_in_progress(profile_id, now=now):
            raise ActivateInProgressError(profile_id)
        if self._profile_has_active_tunnel_assignment(profile_id):
            raise ActiveProfileError(f"profile {profile_id} is active")

    def prepare_vpn_profile_catalog_remove(
        self,
        profile_id: str,
        *,
        now: datetime | None = None,
    ) -> list[str]:
        """Validate remove gates and return linked credential_ref_ids without mutating."""
        with transaction(self._conn, immediate=True):
            self._validate_vpn_profile_catalog_remove_gates(profile_id, now=now)
            refs = self.list_profile_secret_refs(profile_id)
            return [str(ref["credential_ref_id"]) for ref in refs]

    def _commit_vpn_profile_catalog_remove_unlocked(
        self,
        profile_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        cur = self._conn.execute(
            "UPDATE vpn_profile_artifacts SET superseded_at = ? "
            "WHERE profile_id = ? AND superseded_at IS NULL",
            (ts, profile_id),
        )
        if cur.rowcount == 0:
            raise AlreadyRetiredError(f"profile {profile_id} already retired")
        self.delete_profile_secret_refs(profile_id)

    def commit_vpn_profile_catalog_remove(
        self,
        profile_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        """Supersede profile and unlink secret refs after exclusive revokes succeeded."""
        with transaction(self._conn, immediate=True):
            self._validate_vpn_profile_catalog_remove_gates(profile_id, now=now)
            self._commit_vpn_profile_catalog_remove_unlocked(profile_id, now=now)

    def finalize_vpn_profile_catalog_remove(
        self,
        profile_id: str,
        *,
        exclusive_credential_ref_ids: Sequence[str],
        now: datetime | None = None,
    ) -> None:
        """Mark exclusive refs revoked and supersede/unlink profile in one transaction."""
        with transaction(self._conn, immediate=True):
            self._validate_vpn_profile_catalog_remove_gates(profile_id, now=now)
            for ref_id in exclusive_credential_ref_ids:
                self.mark_credential_revoked(ref_id, now=now)
            self._commit_vpn_profile_catalog_remove_unlocked(profile_id, now=now)

    def retire_vpn_profile_from_catalog(
        self,
        profile_id: str,
        *,
        now: datetime | None = None,
    ) -> list[str]:
        """Soft-retire profile; return unlinked credential_ref_ids (legacy atomic helper)."""
        ref_ids = self.prepare_vpn_profile_catalog_remove(profile_id, now=now)
        self.commit_vpn_profile_catalog_remove(profile_id, now=now)
        return ref_ids

    def upsert_tunnel_assignment(
        self,
        *,
        router_id: str,
        profile_id: str,
        logical_role: str = "primary",
        desired_active: bool = True,
        policy_metadata_json: str | None = None,
        observed_vendor_locator: str | None = None,
        assignment_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        profile_row = self.get_profile(profile_id)
        if profile_row is None:
            raise NotFoundError(f"profile {profile_id} not found")
        if profile_row["superseded_at"] is not None:
            raise ConflictError(f"profile {profile_id} is retired from catalog")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "UPDATE tunnel_assignments SET desired_active = 0, retired_at = ? "
            "WHERE router_id = ? AND logical_role = ? AND retired_at IS NULL",
            (ts, router_id, logical_role),
        )
        aid = assignment_id or new_id("tun")
        self._conn.execute(
            "INSERT INTO tunnel_assignments("
            "assignment_id, router_id, profile_id, logical_role, desired_active, "
            "policy_metadata_json, observed_vendor_locator, created_at, retired_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL)",
            (
                aid,
                router_id,
                profile_id,
                logical_role,
                1 if desired_active else 0,
                policy_metadata_json,
                observed_vendor_locator,
                ts,
            ),
        )
        return aid

    def list_active_tunnel_assignments(self) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM tunnel_assignments WHERE desired_active = 1 AND retired_at IS NULL "
            "ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_active_tunnel_assignment(
        self,
        router_id: str,
        *,
        logical_role: str = "primary",
    ) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM tunnel_assignments WHERE router_id = ? AND logical_role = ? "
            "AND desired_active = 1 AND retired_at IS NULL "
            "ORDER BY created_at DESC LIMIT 1",
            (router_id, logical_role),
        ).fetchone()
        return dict(row) if row is not None else None

    def list_tunnel_assignments(
        self,
        router_id: str,
        *,
        active_only: bool = False,
    ) -> list[dict[str, Any]]:
        if active_only:
            rows = self._conn.execute(
                "SELECT * FROM tunnel_assignments WHERE router_id = ? "
                "AND desired_active = 1 AND retired_at IS NULL "
                "ORDER BY created_at DESC",
                (router_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM tunnel_assignments WHERE router_id = ? "
                "ORDER BY created_at DESC",
                (router_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def deactivate_tunnel_assignments(
        self,
        router_id: str,
        *,
        logical_role: str | None = None,
        now: datetime | None = None,
    ) -> int:
        ts = _utc_now_iso(now)
        if logical_role is not None:
            cur = self._conn.execute(
                "UPDATE tunnel_assignments SET desired_active = 0, retired_at = ? "
                "WHERE router_id = ? AND logical_role = ? AND retired_at IS NULL",
                (ts, router_id, logical_role),
            )
        else:
            cur = self._conn.execute(
                "UPDATE tunnel_assignments SET desired_active = 0, retired_at = ? "
                "WHERE router_id = ? AND retired_at IS NULL",
                (ts, router_id),
            )
        return int(cur.rowcount)

    # --- traffic ---

    def insert_traffic_observation(
        self,
        *,
        router_id: str,
        evidence_digest: str,
        source: str = "offline",
        evidence_json: str | None = None,
        traffic_observation_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        tid = traffic_observation_id or new_id("tobs")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO traffic_observations("
            "traffic_observation_id, router_id, observed_at, evidence_digest, "
            "evidence_json, source, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (tid, router_id, ts, evidence_digest, evidence_json, source, ts),
        )
        return tid

    def insert_route_proposal(
        self,
        *,
        router_id: str,
        traffic_observation_id: str,
        proposal_digest: str,
        confidence: float,
        expires_at: str,
        trusted_policy: bool = False,
        proposal_json: str | None = None,
        proposal_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        pid = proposal_id or new_id("prop")
        self._conn.execute(
            "INSERT INTO route_proposals("
            "proposal_id, router_id, traffic_observation_id, proposal_digest, confidence, "
            "expires_at, trusted_policy, auto_apply_blocked, status, proposal_json, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'Proposed', ?, ?)",
            (
                pid,
                router_id,
                traffic_observation_id,
                proposal_digest,
                confidence,
                expires_at,
                1 if trusted_policy else 0,
                proposal_json,
                _utc_now_iso(now),
            ),
        )
        return pid

    def get_route_proposal(self, proposal_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM route_proposals WHERE proposal_id = ?", (proposal_id,)
            ).fetchone(),
        )

    def get_traffic_observation(self, traffic_observation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM traffic_observations WHERE traffic_observation_id = ?",
                (traffic_observation_id,),
            ).fetchone(),
        )

    def fail_live_enroll_probe(
        self,
        *,
        router_id: str,
        operation_id: str,
        job_id: str,
        idempotency_record_id: str,
        http_status: int,
        error_body: dict[str, Any],
        orphan_credential_ref_id: str | None = None,
        delete_orphan_credential_ref: bool = False,
        now: datetime | None = None,
    ) -> None:
        """Mark failed live enroll probe; retain router row for audit, terminalize bundle."""
        moment = now or datetime.now(UTC)
        ts = _utc_now_iso(moment)
        with transaction(self._conn, immediate=True):
            self._conn.execute(
                "UPDATE routers SET lifecycle_status = 'IdentityMismatch', "
                "credential_ref_id = NULL, updated_at = ? WHERE router_id = ?",
                (ts, router_id),
            )
            if delete_orphan_credential_ref and orphan_credential_ref_id:
                self._delete_orphan_enroll_credential_ref_unlocked(
                    router_id=router_id,
                    credential_ref_id=orphan_credential_ref_id,
                )
            self._conn.execute(
                "UPDATE jobs SET status = 'Failed', finished_at = ?, updated_at = ? "
                "WHERE job_id = ?",
                (ts, ts, job_id),
            )
            stored = json.dumps({"http_status": http_status, "body": error_body})
            self._conn.execute(
                "UPDATE operations SET aggregate_status = 'Failed', terminal_at = ?, "
                "updated_at = ? WHERE operation_id = ?",
                (ts, ts, operation_id),
            )
            self._conn.execute(
                "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
                "WHERE idempotency_record_id = ?",
                (stored, idempotency_record_id),
            )

    def _delete_orphan_enroll_credential_ref_unlocked(
        self,
        *,
        router_id: str,
        credential_ref_id: str,
    ) -> bool:
        """Delete enroll-created credential_refs after router FK cleared (caller in txn)."""
        router = self.get_router(router_id)
        if router is None:
            return False
        if router["credential_ref_id"] is not None:
            return False
        if router["lifecycle_status"] != "IdentityMismatch":
            return False
        row = self.get_credential_ref(credential_ref_id)
        if row is None or str(row["router_id"]) != router_id:
            return False
        self._conn.execute(
            "DELETE FROM credential_refs WHERE credential_ref_id = ? AND router_id = ?",
            (credential_ref_id, router_id),
        )
        return True

    def finalize_live_enroll(
        self,
        *,
        router_id: str,
        identity_fingerprint: str,
        operation_id: str,
        job_id: str,
        idempotency_record_id: str,
        body: dict[str, Any],
        now: datetime | None = None,
    ) -> None:
        moment = now or datetime.now(UTC)
        ts = _utc_now_iso(moment)
        stored = json.dumps({"http_status": 202, "body": body})
        with transaction(self._conn, immediate=True):
            self._conn.execute(
                "UPDATE routers SET identity_fingerprint = ?, lifecycle_status = 'Enrolled', "
                "updated_at = ? WHERE router_id = ?",
                (identity_fingerprint, ts, router_id),
            )
            self._conn.execute(
                "UPDATE jobs SET status = 'Succeeded', finished_at = ?, updated_at = ? "
                "WHERE job_id = ?",
                (ts, ts, job_id),
            )
            self._conn.execute(
                "UPDATE operations SET aggregate_status = 'Converged', terminal_at = ?, "
                "updated_at = ? WHERE operation_id = ?",
                (ts, ts, operation_id),
            )
            self._conn.execute(
                "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
                "WHERE idempotency_record_id = ?",
                (stored, idempotency_record_id),
            )

    def finalize_live_preflight(
        self,
        *,
        router_id: str,
        operation_id: str,
        job_id: str,
        idempotency_record_id: str,
        observation_id: str,
        body: dict[str, Any],
        now: datetime | None = None,
    ) -> None:
        moment = now or datetime.now(UTC)
        ts = _utc_now_iso(moment)
        stored = json.dumps({"http_status": 200, "body": body})
        with transaction(self._conn, immediate=True):
            self._conn.execute(
                "UPDATE jobs SET status = 'Succeeded', finished_at = ?, updated_at = ? "
                "WHERE job_id = ?",
                (ts, ts, job_id),
            )
            self._conn.execute(
                "UPDATE operations SET aggregate_status = 'Converged', terminal_at = ?, "
                "updated_at = ? WHERE operation_id = ?",
                (ts, ts, operation_id),
            )
            self._conn.execute(
                "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
                "WHERE idempotency_record_id = ?",
                (stored, idempotency_record_id),
            )

    def fail_accepted_operation_bundle(
        self,
        *,
        operation_id: str,
        job_id: str,
        idempotency_record_id: str,
        http_status: int,
        error_body: dict[str, Any],
        now: datetime | None = None,
    ) -> None:
        """Terminalize a claimed §6 bundle when vault mutate fails (no orphan Queued jobs)."""
        moment = now or datetime.now(UTC)
        ts = _utc_now_iso(moment)
        stored = json.dumps({"http_status": http_status, "body": error_body})
        with transaction(self._conn, immediate=True):
            self._conn.execute(
                "UPDATE jobs SET status = 'Failed', finished_at = ?, updated_at = ? "
                "WHERE job_id = ?",
                (ts, ts, job_id),
            )
            self._conn.execute(
                "UPDATE operations SET aggregate_status = 'Failed', terminal_at = ?, "
                "updated_at = ? WHERE operation_id = ?",
                (ts, ts, operation_id),
            )
            self._conn.execute(
                "UPDATE idempotency_records SET response_ref = ?, status = 'Completed' "
                "WHERE idempotency_record_id = ?",
                (stored, idempotency_record_id),
            )

    def dump_text_for_secret_scan(self) -> str:
        """Concatenate scanned columns for secret-scan tests (redacted domain fields only).

        Column set is read from ``PRAGMA table_info`` per table (always complete).
        Rows are streamed instead of ``fetchall`` to avoid loading entire tables
        into memory.
        """
        chunks: list[str] = []
        for table in _SECRET_SCAN_TABLES:
            columns = secret_scan_table_columns(self._conn, table)
            col_sql = ", ".join(columns)
            cursor = self._conn.execute(f"SELECT {col_sql} FROM {table}")  # noqa: S608
            while True:
                row = cursor.fetchone()
                if row is None:
                    break
                chunks.append("|".join(str(value) for value in row if value is not None))
        return "\n".join(chunks)

    # --- commissioning ---

    def _row_to_commissioning_run(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "run_id": row["run_id"],
            "site_id": row["site_id"],
            "router_id": row["router_id"],
            "state": row["state"],
            "version": int(row["version"]),
            "mode": row["mode"],
            "correlation_id": row["correlation_id"],
            "summary_redacted": row["summary_redacted"],
            "report_digest": row["report_digest"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "assessed_at": row["assessed_at"],
        }

    def get_commissioning_run(self, run_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM commissioning_runs WHERE run_id = ?", (run_id,)
            ).fetchone(),
        )

    def list_commissioning_runs_for_site(
        self, site_id: str, *, limit: int = 50
    ) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM commissioning_runs WHERE site_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (site_id, limit),
            ).fetchall()
        )

    def list_readiness_checks(self, run_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM readiness_checks WHERE run_id = ? "
                "ORDER BY ordinal ASC, attempt ASC",
                (run_id,),
            ).fetchall()
        )

    def _clear_readiness_checks_for_run(self, run_id: str) -> None:
        self._conn.execute("DELETE FROM readiness_checks WHERE run_id = ?", (run_id,))

    def _next_check_attempt(self, run_id: str, check_kind: str) -> int:
        """Caller must hold an open store transaction; not for compute/probe paths."""
        row = self._conn.execute(
            "SELECT COALESCE(MAX(attempt), 0) AS m FROM readiness_checks "
            "WHERE run_id = ? AND check_kind = ?",
            (run_id, check_kind),
        ).fetchone()
        return int(row["m"]) + 1

    def append_readiness_check(
        self,
        *,
        run_id: str,
        check_kind: str,
        ordinal: int,
        attempt: int,
        outcome: str,
        blocking: bool,
        write_related: bool,
        summary_redacted: str,
        evidence_digest: str | None = None,
        check_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        cid = check_id or new_id("rcheck")
        self._conn.execute(
            "INSERT INTO readiness_checks("
            "check_id, run_id, check_kind, ordinal, attempt, outcome, blocking, "
            "write_related, summary_redacted, evidence_digest, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                cid,
                run_id,
                check_kind,
                ordinal,
                attempt,
                outcome,
                1 if blocking else 0,
                1 if write_related else 0,
                summary_redacted,
                evidence_digest,
                _utc_now_iso(now),
            ),
        )
        return cid

    def _peek_commissioning_idempotency(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
    ) -> sqlite3.Row | None:
        row = self._conn.execute(
            "SELECT * FROM commissioning_idempotency WHERE scope_kind = ? "
            "AND scope_id = ? AND operation_kind = ? AND idempotency_key = ?",
            (scope_kind, scope_id, operation_kind, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise IdempotencyConflict("same key different digest")
        return cast(sqlite3.Row, row)

    def _store_commissioning_idempotency(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
        response_ref: str | None,
        now: datetime | None = None,
        record_id: str | None = None,
    ) -> str:
        rid = record_id or new_id("cidem")
        self._conn.execute(
            "INSERT INTO commissioning_idempotency("
            "record_id, scope_kind, scope_id, operation_kind, idempotency_key, "
            "request_digest, response_ref, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rid,
                scope_kind,
                scope_id,
                operation_kind,
                idempotency_key,
                request_digest,
                response_ref,
                _utc_now_iso(now),
            ),
        )
        return rid

    def _row_to_readiness_check_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "check_id": row["check_id"],
            "check_kind": row["check_kind"],
            "ordinal": int(row["ordinal"]),
            "attempt": int(row["attempt"]),
            "outcome": row["outcome"],
            "blocking": bool(row["blocking"]),
            "write_related": bool(row["write_related"]),
            "summary_redacted": row["summary_redacted"],
            "evidence_digest": row["evidence_digest"],
        }

    def _readiness_checks_as_dicts(self, run_id: str) -> list[dict[str, Any]]:
        return [
            self._row_to_readiness_check_dict(row)
            for row in self.list_readiness_checks(run_id)
        ]

    def _replay_commissioning_assess_idempotency(
        self, existing: sqlite3.Row
    ) -> CommissioningAssessPrepareResult:
        payload = json.loads(existing["response_ref"] or "{}")
        return CommissioningAssessPrepareResult(
            replay=(payload["run"], payload["checks"], False)
        )

    def _assess_idempotency_in_progress(self) -> None:
        raise ConflictError("assess in progress")

    def prepare_commissioning_assess(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None,
        now: datetime | None = None,
    ) -> CommissioningAssessPrepareResult:
        """Reserve assess idempotency and transition to Assessing; no probe/callback."""
        with transaction(self._conn, immediate=True):
            row = self.get_commissioning_run(run_id)
            if row is None:
                raise NotFoundError("commissioning run not found")

            existing = self._peek_commissioning_idempotency(
                scope_kind="run",
                scope_id=run_id,
                operation_kind="assess",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                if existing["response_ref"]:
                    return self._replay_commissioning_assess_idempotency(existing)
                self._assess_idempotency_in_progress()

            if expected_version is not None and int(row["version"]) != expected_version:
                raise PreconditionFailed("If-Match version mismatch")

            if str(row["state"]) == "Cancelled":
                raise ConflictError("run cancelled")

            state = str(row["state"])
            if state in ("Blocked", "Failed", "ReadyReadOnly"):
                run_dict = self._row_to_commissioning_run(row)
                checks = self._readiness_checks_as_dicts(run_id)
                self._store_commissioning_idempotency(
                    scope_kind="run",
                    scope_id=run_id,
                    operation_kind="assess",
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    response_ref=json.dumps({"run": run_dict, "checks": checks}),
                    now=now,
                )
                return CommissioningAssessPrepareResult(replay=(run_dict, checks, True))

            version = int(row["version"])
            if state == "Draft":
                self._update_commissioning_run_state_unlocked(
                    run_id=run_id,
                    expected_version=version,
                    new_state="Observing",
                    summary_redacted="observing linked router",
                    now=now,
                )
                fresh = self.get_commissioning_run(run_id)
                assert fresh is not None
                version = int(fresh["version"])
                state = str(fresh["state"])

            if state == "Assessing":
                self._clear_readiness_checks_for_run(run_id)
            elif state == "Observing":
                self._update_commissioning_run_state_unlocked(
                    run_id=run_id,
                    expected_version=version,
                    new_state="Assessing",
                    summary_redacted="assessment in progress",
                    now=now,
                )
            else:
                raise ConflictError(f"illegal assess state: {state}")

            fresh = self.get_commissioning_run(run_id)
            assert fresh is not None
            fence_version = int(fresh["version"])
            record_id = new_id("cidem")
            try:
                self._store_commissioning_idempotency(
                    scope_kind="run",
                    scope_id=run_id,
                    operation_kind="assess",
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    response_ref=None,
                    now=now,
                    record_id=record_id,
                )
            except sqlite3.IntegrityError:
                raced = self._peek_commissioning_idempotency(
                    scope_kind="run",
                    scope_id=run_id,
                    operation_kind="assess",
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                )
                if raced is not None and raced["response_ref"]:
                    return self._replay_commissioning_assess_idempotency(raced)
                self._assess_idempotency_in_progress()

            return CommissioningAssessPrepareResult(
                reservation=CommissioningAssessReservation(
                    run_id=run_id,
                    fence_version=fence_version,
                    idempotency_record_id=record_id,
                    idempotency_key=idempotency_key,
                    request_digest=request_digest,
                    mode=str(fresh["mode"]),
                    router_id=str(fresh["router_id"]) if fresh["router_id"] else None,
                    site_id=str(fresh["site_id"]),
                )
            )

    def _cas_commissioning_assess_reservation(
        self,
        reservation: CommissioningAssessReservation,
    ) -> sqlite3.Row | None:
        row = self.get_commissioning_run(reservation.run_id)
        if row is None:
            raise NotFoundError("commissioning run not found")
        if int(row["version"]) != reservation.fence_version:
            return None
        if str(row["state"]) != "Assessing":
            return None
        idem = self._conn.execute(
            "SELECT * FROM commissioning_idempotency WHERE record_id = ?",
            (reservation.idempotency_record_id,),
        ).fetchone()
        if idem is None:
            return None
        if idem["response_ref"] is not None:
            return None
        if (
            idem["idempotency_key"] != reservation.idempotency_key
            or idem["request_digest"] != reservation.request_digest
        ):
            return None
        return row

    def _try_replay_commissioning_assess(
        self,
        reservation: CommissioningAssessReservation,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool] | None:
        existing = self._peek_commissioning_idempotency(
            scope_kind="run",
            scope_id=reservation.run_id,
            operation_kind="assess",
            idempotency_key=reservation.idempotency_key,
            request_digest=reservation.request_digest,
        )
        if existing is not None and existing["response_ref"]:
            payload = json.loads(existing["response_ref"])
            return payload["run"], payload["checks"], False
        return None

    def _resolve_lost_assess_reservation(
        self,
        reservation: CommissioningAssessReservation,
        *,
        checks: list[dict[str, Any]],
        correlation_id: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
        audit_outcome: str = "reservation_lost",
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool] | None:
        """Complete or clear a null assess reservation after ownership CAS loss."""
        replay = self._try_replay_commissioning_assess(reservation)
        if replay is not None:
            return replay

        idem = self._conn.execute(
            "SELECT * FROM commissioning_idempotency WHERE record_id = ?",
            (reservation.idempotency_record_id,),
        ).fetchone()
        if idem is None:
            return None
        if idem["response_ref"] is not None:
            return self._try_replay_commissioning_assess(reservation)

        row = self.get_commissioning_run(reservation.run_id)
        if row is None:
            self._conn.execute(
                "DELETE FROM commissioning_idempotency WHERE record_id = ? "
                "AND response_ref IS NULL",
                (reservation.idempotency_record_id,),
            )
            return None

        run_dict = self._row_to_commissioning_run(row)
        response_ref = json.dumps({"run": run_dict, "checks": checks})
        updated = self._conn.execute(
            "UPDATE commissioning_idempotency SET response_ref = ? "
            "WHERE record_id = ? AND response_ref IS NULL",
            (response_ref, reservation.idempotency_record_id),
        )
        if updated.rowcount == 1:
            self.append_audit(
                action="commissioning.assess",
                outcome=audit_outcome,
                router_id=reservation.router_id,
                summary_redacted=(
                    f"run_id={reservation.run_id};state={run_dict['state']};"
                    "reservation_lost"
                ),
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=reservation.request_digest,
                now=now,
            )
            return run_dict, checks, False

        return self._try_replay_commissioning_assess(reservation)

    def finalize_commissioning_assess(
        self,
        reservation: CommissioningAssessReservation,
        *,
        terminal_state: str,
        summary_redacted: str,
        report_digest: str,
        assessed_at: str,
        checks: list[dict[str, Any]],
        correlation_id: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        with transaction(self._conn, immediate=True):
            if self._cas_commissioning_assess_reservation(reservation) is None:
                resolved = self._resolve_lost_assess_reservation(
                    reservation,
                    checks=checks,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    now=now,
                    audit_outcome="reservation_lost",
                )
                if resolved is not None:
                    return resolved
                raise ConflictError("assess reservation lost")

            self._clear_readiness_checks_for_run(reservation.run_id)
            persisted_checks: list[dict[str, Any]] = []
            for check in checks:
                check_id = self.append_readiness_check(
                    run_id=reservation.run_id,
                    check_kind=str(check["check_kind"]),
                    ordinal=int(check["ordinal"]),
                    attempt=int(check["attempt"]),
                    outcome=str(check["outcome"]),
                    blocking=bool(check["blocking"]),
                    write_related=bool(check["write_related"]),
                    summary_redacted=str(check["summary_redacted"]),
                    evidence_digest=check.get("evidence_digest"),
                    check_id=check.get("check_id"),
                    now=now,
                )
                persisted_checks.append({**check, "check_id": check_id})

            run_dict = self._update_commissioning_run_state_unlocked(
                run_id=reservation.run_id,
                expected_version=reservation.fence_version,
                new_state=terminal_state,
                summary_redacted=summary_redacted,
                report_digest=report_digest,
                assessed_at=assessed_at,
                now=now,
            )
            response_ref = json.dumps({"run": run_dict, "checks": persisted_checks})
            updated = self._conn.execute(
                "UPDATE commissioning_idempotency SET response_ref = ? "
                "WHERE record_id = ? AND response_ref IS NULL",
                (response_ref, reservation.idempotency_record_id),
            )
            if updated.rowcount != 1:
                replay = self._try_replay_commissioning_assess(reservation)
                if replay is not None:
                    return replay
                raise ConflictError("assess idempotency completion lost")

            self.append_audit(
                action="commissioning.assess",
                outcome="completed",
                router_id=reservation.router_id,
                summary_redacted=f"run_id={reservation.run_id};state={run_dict['state']}",
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=reservation.request_digest,
                now=now,
            )
            return run_dict, persisted_checks, True

    def fail_commissioning_assess(
        self,
        reservation: CommissioningAssessReservation,
        *,
        summary_redacted: str,
        report_digest: str,
        assessed_at: str,
        checks: list[dict[str, Any]],
        correlation_id: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        with transaction(self._conn, immediate=True):
            if self._cas_commissioning_assess_reservation(reservation) is None:
                resolved = self._resolve_lost_assess_reservation(
                    reservation,
                    checks=checks,
                    correlation_id=correlation_id,
                    actor_id=actor_id,
                    now=now,
                    audit_outcome="failed",
                )
                if resolved is not None:
                    return resolved
                raise ConflictError("assess reservation lost")

            self._clear_readiness_checks_for_run(reservation.run_id)
            persisted_checks: list[dict[str, Any]] = []
            for check in checks:
                check_id = self.append_readiness_check(
                    run_id=reservation.run_id,
                    check_kind=str(check["check_kind"]),
                    ordinal=int(check["ordinal"]),
                    attempt=int(check["attempt"]),
                    outcome=str(check["outcome"]),
                    blocking=bool(check["blocking"]),
                    write_related=bool(check["write_related"]),
                    summary_redacted=str(check["summary_redacted"]),
                    evidence_digest=check.get("evidence_digest"),
                    check_id=check.get("check_id"),
                    now=now,
                )
                persisted_checks.append({**check, "check_id": check_id})

            run_dict = self._update_commissioning_run_state_unlocked(
                run_id=reservation.run_id,
                expected_version=reservation.fence_version,
                new_state="Failed",
                summary_redacted=summary_redacted,
                report_digest=report_digest,
                assessed_at=assessed_at,
                now=now,
            )
            response_ref = json.dumps({"run": run_dict, "checks": persisted_checks})
            updated = self._conn.execute(
                "UPDATE commissioning_idempotency SET response_ref = ? "
                "WHERE record_id = ? AND response_ref IS NULL",
                (response_ref, reservation.idempotency_record_id),
            )
            if updated.rowcount != 1:
                replay = self._try_replay_commissioning_assess(reservation)
                if replay is not None:
                    return replay
                raise ConflictError("assess idempotency completion lost")

            self.append_audit(
                action="commissioning.assess",
                outcome="failed",
                router_id=reservation.router_id,
                summary_redacted=f"run_id={reservation.run_id};state=Failed",
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=reservation.request_digest,
                now=now,
            )
            return run_dict, persisted_checks, True

    def create_commissioning_run(
        self,
        *,
        site_id: str,
        router_id: str,
        mode: str,
        idempotency_key: str,
        request_digest: str,
        correlation_id: str | None = None,
        actor_id: str | None = None,
        run_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Create Draft run idempotently. Returns (run_dict, created)."""
        with transaction(self._conn, immediate=True):
            existing = self._peek_commissioning_idempotency(
                scope_kind="site",
                scope_id=site_id,
                operation_kind="create_run",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                payload = json.loads(existing["response_ref"] or "{}")
                run = self.get_commissioning_run(payload["run_id"])
                if run is None:
                    raise ConflictError("idempotency references missing run")
                return self._row_to_commissioning_run(run), False

            site = self.get_site(site_id)
            if site is None:
                raise NotFoundError("site not found")
            router = self.get_router(router_id)
            if router is None:
                raise NotFoundError("router not found")
            if str(router["site_id"]) != site_id:
                raise PreconditionFailed("router not linked to site")

            ts = _utc_now_iso(now)
            rid = run_id or new_id("crun")
            self._conn.execute(
                "INSERT INTO commissioning_runs("
                "run_id, site_id, router_id, state, version, idempotency_key, "
                "create_request_digest, correlation_id, mode, summary_redacted, "
                "report_digest, created_at, updated_at, assessed_at"
                ") VALUES (?, ?, ?, 'Draft', 1, ?, ?, ?, ?, NULL, NULL, ?, ?, NULL)",
                (
                    rid,
                    site_id,
                    router_id,
                    idempotency_key,
                    request_digest,
                    correlation_id,
                    mode,
                    ts,
                    ts,
                ),
            )
            run_row = self.get_commissioning_run(rid)
            assert run_row is not None
            body = self._row_to_commissioning_run(run_row)
            self._store_commissioning_idempotency(
                scope_kind="site",
                scope_id=site_id,
                operation_kind="create_run",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_ref=json.dumps({"run_id": rid, "body": body}),
                now=now,
            )
            self.append_audit(
                action="commissioning.create",
                outcome="accepted",
                router_id=router_id,
                summary_redacted=f"run_id={rid};mode={mode};state=Draft",
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=request_digest,
                now=now,
            )
            return body, True

    def update_commissioning_run_state(
        self,
        *,
        run_id: str,
        expected_version: int,
        new_state: str,
        summary_redacted: str | None = None,
        report_digest: str | None = None,
        assessed_at: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        with transaction(self._conn, immediate=True):
            return self._update_commissioning_run_state_unlocked(
                run_id=run_id,
                expected_version=expected_version,
                new_state=new_state,
                summary_redacted=summary_redacted,
                report_digest=report_digest,
                assessed_at=assessed_at,
                now=now,
            )

    def _update_commissioning_run_state_unlocked(
        self,
        *,
        run_id: str,
        expected_version: int,
        new_state: str,
        summary_redacted: str | None = None,
        report_digest: str | None = None,
        assessed_at: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = _utc_now_iso(now)
        row = self.get_commissioning_run(run_id)
        if row is None:
            raise NotFoundError("commissioning run not found")
        if int(row["version"]) != expected_version:
            raise PreconditionFailed("optimistic version mismatch")
        new_version = expected_version + 1
        self._conn.execute(
            "UPDATE commissioning_runs SET state = ?, version = ?, "
            "summary_redacted = COALESCE(?, summary_redacted), "
            "report_digest = COALESCE(?, report_digest), "
            "assessed_at = COALESCE(?, assessed_at), updated_at = ? "
            "WHERE run_id = ? AND version = ?",
            (
                new_state,
                new_version,
                summary_redacted,
                report_digest,
                assessed_at,
                ts,
                run_id,
                expected_version,
            ),
        )
        if self._conn.execute("SELECT changes()").fetchone()[0] != 1:
            raise PreconditionFailed("optimistic version mismatch")
        updated = self.get_commissioning_run(run_id)
        assert updated is not None
        return self._row_to_commissioning_run(updated)

    def cancel_commissioning_run_idempotent(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with transaction(self._conn, immediate=True):
            row = self.get_commissioning_run(run_id)
            if row is None:
                raise NotFoundError("commissioning run not found")
            existing = self._peek_commissioning_idempotency(
                scope_kind="run",
                scope_id=run_id,
                operation_kind="cancel",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                payload = json.loads(existing["response_ref"] or "{}")
                return payload["run"], False

            if expected_version is not None and int(row["version"]) != expected_version:
                raise PreconditionFailed("If-Match version mismatch")

            state = str(row["state"])
            if state == "Cancelled":
                run_dict = self._row_to_commissioning_run(row)
            elif state in ("Blocked", "Failed"):
                raise ConflictError("run already terminal")
            else:
                run_dict = self._update_commissioning_run_state_unlocked(
                    run_id=run_id,
                    expected_version=int(row["version"]),
                    new_state="Cancelled",
                    summary_redacted="cancelled by operator",
                    now=now,
                )
            self._store_commissioning_idempotency(
                scope_kind="run",
                scope_id=run_id,
                operation_kind="cancel",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_ref=json.dumps({"run": run_dict}),
                now=now,
            )
            return run_dict, True

    # --- event presets (M2) ---

    def revision_canonical_json(self, revision: sqlite3.Row) -> dict[str, Any]:
        return cast(dict[str, Any], json.loads(str(revision["canonical_json"])))

    def _row_to_event_preset(self, row: sqlite3.Row) -> dict[str, Any]:
        current_digest: str | None = None
        if row["current_revision_id"]:
            rev = self.get_event_preset_revision(str(row["current_revision_id"]))
            if rev is not None:
                current_digest = str(rev["canonical_digest"])
        return {
            "preset_id": row["preset_id"],
            "site_id": row["site_id"],
            "name": row["name"],
            "version": int(row["version"]),
            "current_revision_id": row["current_revision_id"],
            "published_revision_id": row["published_revision_id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "current_digest": current_digest,
            "etag": etag_for_event_preset(
                str(row["preset_id"]), int(row["version"]), current_digest
            ),
        }

    def _row_to_event_preset_revision(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "revision_id": row["revision_id"],
            "preset_id": row["preset_id"],
            "revision_number": int(row["revision_number"]),
            "canonical_digest": row["canonical_digest"],
            "validation_status": row["validation_status"],
            "summary_redacted": row["summary_redacted"],
            "created_at": row["created_at"],
            "etag": etag_for_event_preset_revision(
                str(row["revision_id"]), str(row["canonical_digest"])
            ),
        }

    def get_event_preset(self, preset_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM event_presets WHERE preset_id = ?", (preset_id,)
            ).fetchone(),
        )

    def get_event_preset_revision(self, revision_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM event_preset_revisions WHERE revision_id = ?",
                (revision_id,),
            ).fetchone(),
        )

    def list_event_presets_for_site(self, site_id: str, *, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM event_presets WHERE site_id = ? "
                "ORDER BY created_at DESC LIMIT ?",
                (site_id, limit),
            ).fetchall()
        )

    def _peek_event_preset_idempotency(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
    ) -> sqlite3.Row | None:
        row = self._conn.execute(
            "SELECT * FROM event_preset_idempotency WHERE scope_kind = ? "
            "AND scope_id = ? AND operation_kind = ? AND idempotency_key = ?",
            (scope_kind, scope_id, operation_kind, idempotency_key),
        ).fetchone()
        if row is None:
            return None
        if row["request_digest"] != request_digest:
            raise IdempotencyConflict("same key different digest")
        return cast(sqlite3.Row, row)

    def _store_event_preset_idempotency(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
        response_ref: str,
        now: datetime | None = None,
    ) -> str:
        rid = new_id("epidem")
        self._conn.execute(
            "INSERT INTO event_preset_idempotency("
            "record_id, scope_kind, scope_id, operation_kind, idempotency_key, "
            "request_digest, response_ref, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rid,
                scope_kind,
                scope_id,
                operation_kind,
                idempotency_key,
                request_digest,
                response_ref,
                _utc_now_iso(now),
            ),
        )
        return rid

    def _insert_event_preset_revision(
        self,
        *,
        preset_id: str,
        revision_number: int,
        canonical_json: str,
        canonical_digest: str,
        validation_status: str,
        summary_redacted: str | None,
        revision_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        rid = revision_id or new_id("eprev")
        self._conn.execute(
            "INSERT INTO event_preset_revisions("
            "revision_id, preset_id, revision_number, canonical_json, canonical_digest, "
            "validation_status, summary_redacted, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                rid,
                preset_id,
                revision_number,
                canonical_json,
                canonical_digest,
                validation_status,
                summary_redacted,
                _utc_now_iso(now),
            ),
        )
        return rid

    def create_event_preset(
        self,
        *,
        site_id: str,
        name: str,
        canonical_json: str,
        canonical_digest: str,
        validation_status: str,
        summary_redacted: str | None,
        idempotency_key: str,
        request_digest: str,
        correlation_id: str | None = None,
        actor_id: str | None = None,
        preset_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        with transaction(self._conn, immediate=True):
            existing = self._peek_event_preset_idempotency(
                scope_kind="site",
                scope_id=site_id,
                operation_kind="create_preset",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                payload = json.loads(existing["response_ref"] or "{}")
                preset = self.get_event_preset(payload["preset_id"])
                revision = self.get_event_preset_revision(payload["revision_id"])
                if preset is None or revision is None:
                    raise ConflictError("idempotency references missing preset")
                return (
                    self._row_to_event_preset(preset),
                    self._row_to_event_preset_revision(revision),
                    False,
                )

            if self.get_site(site_id) is None:
                raise NotFoundError("site not found")

            ts = _utc_now_iso(now)
            pid = preset_id or new_id("epreset")
            rev_id = new_id("eprev")
            self._conn.execute(
                "INSERT INTO event_presets("
                "preset_id, site_id, name, version, current_revision_id, "
                "published_revision_id, idempotency_key, create_request_digest, "
                "correlation_id, created_at, updated_at"
                ") VALUES (?, ?, ?, 1, ?, NULL, ?, ?, ?, ?, ?)",
                (
                    pid,
                    site_id,
                    name,
                    rev_id,
                    idempotency_key,
                    request_digest,
                    correlation_id,
                    ts,
                    ts,
                ),
            )
            self._insert_event_preset_revision(
                preset_id=pid,
                revision_id=rev_id,
                revision_number=1,
                canonical_json=canonical_json,
                canonical_digest=canonical_digest,
                validation_status=validation_status,
                summary_redacted=summary_redacted,
                now=now,
            )
            preset_row = self.get_event_preset(pid)
            revision_row = self.get_event_preset_revision(rev_id)
            assert preset_row is not None and revision_row is not None
            preset_body = self._row_to_event_preset(preset_row)
            revision_body = self._row_to_event_preset_revision(revision_row)
            self._store_event_preset_idempotency(
                scope_kind="site",
                scope_id=site_id,
                operation_kind="create_preset",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_ref=json.dumps({"preset_id": pid, "revision_id": rev_id}),
                now=now,
            )
            self.append_audit(
                action="event_preset.create",
                outcome="accepted",
                summary_redacted=f"preset_id={pid};revision=1",
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=request_digest,
                now=now,
            )
            return preset_body, revision_body, True

    def create_event_preset_revision_idempotent(
        self,
        *,
        preset_id: str,
        canonical_json: str,
        canonical_digest: str,
        validation_status: str,
        summary_redacted: str | None,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], dict[str, Any], bool]:
        with transaction(self._conn, immediate=True):
            preset = self.get_event_preset(preset_id)
            if preset is None:
                raise NotFoundError("event preset not found")
            existing = self._peek_event_preset_idempotency(
                scope_kind="preset",
                scope_id=preset_id,
                operation_kind="create_revision",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                payload = json.loads(existing["response_ref"] or "{}")
                preset_row = self.get_event_preset(preset_id)
                revision = self.get_event_preset_revision(payload["revision_id"])
                if preset_row is None or revision is None:
                    raise ConflictError("idempotency references missing revision")
                return (
                    self._row_to_event_preset(preset_row),
                    self._row_to_event_preset_revision(revision),
                    False,
                )

            if expected_version is not None and int(preset["version"]) != expected_version:
                raise PreconditionFailed("If-Match version mismatch")

            next_num_row = self._conn.execute(
                "SELECT COALESCE(MAX(revision_number), 0) AS m "
                "FROM event_preset_revisions WHERE preset_id = ?",
                (preset_id,),
            ).fetchone()
            next_num = int(next_num_row["m"]) + 1
            rev_id = new_id("eprev")
            self._insert_event_preset_revision(
                preset_id=preset_id,
                revision_id=rev_id,
                revision_number=next_num,
                canonical_json=canonical_json,
                canonical_digest=canonical_digest,
                validation_status=validation_status,
                summary_redacted=summary_redacted,
                now=now,
            )
            new_version = int(preset["version"]) + 1
            ts = _utc_now_iso(now)
            self._conn.execute(
                "UPDATE event_presets SET current_revision_id = ?, version = ?, updated_at = ? "
                "WHERE preset_id = ? AND version = ?",
                (rev_id, new_version, ts, preset_id, int(preset["version"])),
            )
            if self._conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise PreconditionFailed("optimistic version mismatch")
            preset_row = self.get_event_preset(preset_id)
            revision_row = self.get_event_preset_revision(rev_id)
            assert preset_row is not None and revision_row is not None
            preset_body = self._row_to_event_preset(preset_row)
            revision_body = self._row_to_event_preset_revision(revision_row)
            self._store_event_preset_idempotency(
                scope_kind="preset",
                scope_id=preset_id,
                operation_kind="create_revision",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_ref=json.dumps({"revision_id": rev_id}),
                now=now,
            )
            self.append_audit(
                action="event_preset.revision",
                outcome="accepted",
                summary_redacted=f"preset_id={preset_id};revision={next_num}",
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=request_digest,
                now=now,
            )
            return preset_body, revision_body, True

    def publish_event_preset_revision_idempotent(
        self,
        *,
        preset_id: str,
        revision_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        with transaction(self._conn, immediate=True):
            preset = self.get_event_preset(preset_id)
            if preset is None:
                raise NotFoundError("event preset not found")
            revision = self.get_event_preset_revision(revision_id)
            if revision is None or str(revision["preset_id"]) != preset_id:
                raise NotFoundError("revision not found for preset")
            existing = self._peek_event_preset_idempotency(
                scope_kind="preset",
                scope_id=preset_id,
                operation_kind="publish",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                payload = json.loads(existing["response_ref"] or "{}")
                preset_row = self.get_event_preset(payload["preset_id"])
                if preset_row is None:
                    raise ConflictError("idempotency references missing preset")
                return self._row_to_event_preset(preset_row), False

            if expected_version is not None and int(preset["version"]) != expected_version:
                raise PreconditionFailed("If-Match version mismatch")

            new_version = int(preset["version"]) + 1
            ts = _utc_now_iso(now)
            self._conn.execute(
                "UPDATE event_presets SET published_revision_id = ?, version = ?, updated_at = ? "
                "WHERE preset_id = ? AND version = ?",
                (revision_id, new_version, ts, preset_id, int(preset["version"])),
            )
            if self._conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise PreconditionFailed("optimistic version mismatch")
            preset_row = self.get_event_preset(preset_id)
            assert preset_row is not None
            preset_body = self._row_to_event_preset(preset_row)
            self._store_event_preset_idempotency(
                scope_kind="preset",
                scope_id=preset_id,
                operation_kind="publish",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_ref=json.dumps({"preset_id": preset_id}),
                now=now,
            )
            self.append_audit(
                action="event_preset.publish",
                outcome="accepted",
                summary_redacted=f"preset_id={preset_id};published={revision_id}",
                actor_id=actor_id,
                correlation_id=correlation_id,
                request_digest=request_digest,
                now=now,
            )
            return preset_body, True

    # --- P1-A live persistence substrate (offline; no adapter dispatch) ---

    def register_worker_instance(
        self,
        *,
        worker_instance_id: str,
        process_id: int,
        boot_id: str,
        hostname: str | None = None,
        lifecycle_status: str = "Starting",
        started_at_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        epoch = started_at_epoch if started_at_epoch is not None else int(
            (now or datetime.now(UTC)).timestamp()
        )
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO worker_instances("
            "worker_instance_id, process_id, boot_id, hostname, lifecycle_status, "
            "started_at_epoch, stopped_at_epoch, created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            (
                worker_instance_id,
                process_id,
                boot_id,
                hostname,
                lifecycle_status,
                epoch,
                ts,
                ts,
            ),
        )

    def update_worker_instance_lifecycle(
        self,
        worker_instance_id: str,
        *,
        lifecycle_status: str,
        stopped_at_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        self._conn.execute(
            "UPDATE worker_instances SET lifecycle_status = ?, "
            "stopped_at_epoch = COALESCE(?, stopped_at_epoch), updated_at = ? "
            "WHERE worker_instance_id = ?",
            (lifecycle_status, stopped_at_epoch, ts, worker_instance_id),
        )

    def get_worker_instance(self, worker_instance_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM worker_instances WHERE worker_instance_id = ?",
                (worker_instance_id,),
            ).fetchone(),
        )

    def acquire_router_execution_fence(
        self,
        *,
        router_id: str,
        lease_owner: str,
        mutex_holder_id: str,
        lease_seconds: int,
        active_job_id: str | None = None,
        os_mutex_held: bool = False,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> int:
        """Monotonic per-router execution fence; rejects stale/expired active fence."""
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        ts = _utc_now_iso(now)
        lease_until = validity + lease_seconds
        with transaction(self._conn, immediate=True):
            row = self._conn.execute(
                "SELECT * FROM router_execution_fences WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            if row is not None:
                if int(row["lease_until_epoch"]) >= validity:
                    if (
                        row["lease_owner"] != lease_owner
                        or row["mutex_holder_id"] != mutex_holder_id
                    ):
                        raise MutexHolderRequiredError(
                            "active router execution fence held by another owner"
                        )
                    if active_job_id is not None and str(row["active_job_id"]) != str(
                        active_job_id
                    ):
                        updated = self._conn.execute(
                            "UPDATE router_execution_fences SET active_job_id = ?, "
                            "lease_until_epoch = ?, updated_at = ? "
                            "WHERE router_id = ? AND fence_token = ? AND lease_owner = ? "
                            "AND mutex_holder_id = ?",
                            (
                                active_job_id,
                                lease_until,
                                ts,
                                router_id,
                                int(row["fence_token"]),
                                lease_owner,
                                mutex_holder_id,
                            ),
                        )
                        if updated.rowcount != 1:
                            raise StaleFenceError("router execution fence handoff rejected")
                    return int(row["fence_token"])
                if not os_mutex_held:
                    raise MutexHolderRequiredError(
                        "expired fence takeover requires os mutex held"
                    )
                fence_token = int(row["fence_token"]) + 1
                self._conn.execute(
                    "UPDATE router_execution_fences SET fence_token = ?, lease_owner = ?, "
                    "mutex_holder_id = ?, lease_until_epoch = ?, active_job_id = ?, updated_at = ? "
                    "WHERE router_id = ?",
                    (
                        fence_token,
                        lease_owner,
                        mutex_holder_id,
                        lease_until,
                        active_job_id,
                        ts,
                        router_id,
                    ),
                )
                return fence_token
            fence_id = new_id("fence")
            self._conn.execute(
                "INSERT INTO router_execution_fences("
                "fence_id, router_id, fence_token, lease_owner, mutex_holder_id, "
                "lease_until_epoch, active_job_id, created_at, updated_at"
                ") VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)",
                (
                    fence_id,
                    router_id,
                    lease_owner,
                    mutex_holder_id,
                    lease_until,
                    active_job_id,
                    ts,
                    ts,
                ),
            )
            return 1

    def renew_router_execution_fence(
        self,
        *,
        router_id: str,
        lease_owner: str,
        mutex_holder_id: str,
        fence_token: int,
        lease_seconds: int,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        validity = _lease_validity_epoch(self._conn, now_epoch=now_epoch, now=now)
        ts = _utc_now_iso(now)
        lease_until = validity + lease_seconds
        with transaction(self._conn, immediate=True):
            row = self._conn.execute(
                "SELECT * FROM router_execution_fences WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("router execution fence not found")
            if int(row["fence_token"]) != fence_token:
                raise StaleFenceError("stale router execution fence token")
            if int(row["lease_until_epoch"]) < validity:
                raise FenceExpiredError("router execution fence expired")
            if (
                row["lease_owner"] != lease_owner
                or row["mutex_holder_id"] != mutex_holder_id
            ):
                raise MutexHolderRequiredError("mutex holder mismatch")
            updated = self._conn.execute(
                "UPDATE router_execution_fences SET lease_until_epoch = ?, updated_at = ? "
                "WHERE router_id = ? AND fence_token = ? AND lease_owner = ? "
                "AND mutex_holder_id = ?",
                (lease_until, ts, router_id, fence_token, lease_owner, mutex_holder_id),
            )
            if updated.rowcount != 1:
                raise StaleFenceError("router execution fence renew rejected")

    def release_router_execution_fence(
        self,
        *,
        router_id: str,
        lease_owner: str,
        mutex_holder_id: str,
        fence_token: int,
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            updated = self._conn.execute(
                "DELETE FROM router_execution_fences "
                "WHERE router_id = ? AND fence_token = ? AND lease_owner = ? "
                "AND mutex_holder_id = ?",
                (router_id, fence_token, lease_owner, mutex_holder_id),
            )
            if updated.rowcount != 1:
                raise StaleFenceError("router execution fence release rejected")
            _ = ts

    def reap_expired_router_execution_fences(
        self,
        *,
        now_epoch: int | None = None,
        limit: int = 100,
    ) -> list[str]:
        with transaction(self._conn, immediate=True):
            db_now = _lease_validity_epoch(self._conn, now_epoch=now_epoch)
            rows = self._conn.execute(
                "SELECT router_id FROM router_execution_fences "
                "WHERE lease_until_epoch < ? LIMIT ?",
                (db_now, limit),
            ).fetchall()
            router_ids = [str(r["router_id"]) for r in rows]
            for router_id in router_ids:
                self._conn.execute(
                    "DELETE FROM router_execution_fences WHERE router_id = ? "
                    "AND lease_until_epoch < ?",
                    (router_id, db_now),
                )
            return router_ids

    def get_router_execution_fence(self, router_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_execution_fences WHERE router_id = ?",
                (router_id,),
            ).fetchone(),
        )

    def create_external_effect(
        self,
        *,
        router_id: str,
        effect_key: str,
        job_id: str,
        lease_owner: str,
        operation_id: str | None = None,
        effect_id: str | None = None,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> str:
        from router_control.domain.enums import EffectState

        eid = effect_id or new_id("fx")
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            _assert_fenced_effect_write(
                self._conn,
                router_id=router_id,
                job_id=job_id,
                lease_owner=lease_owner,
                now_epoch=now_epoch,
                now=now,
            )
            self._conn.execute(
                "INSERT INTO external_effects("
                "effect_id, router_id, operation_id, job_id, effect_key, current_state, "
                "created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    eid,
                    router_id,
                    operation_id,
                    job_id,
                    effect_key,
                    EffectState.PREPARED.value,
                    ts,
                    ts,
                ),
            )
            self._append_external_effect_event_unlocked(
                effect_id=eid,
                from_state=None,
                to_state=EffectState.PREPARED.value,
                actor_type="system",
                summary_redacted="effect prepared",
                now=now,
            )
        return eid

    def _append_external_effect_event_unlocked(
        self,
        *,
        effect_id: str,
        from_state: str | None,
        to_state: str,
        actor_type: str,
        actor_id: str | None = None,
        summary_redacted: str | None = None,
        now: datetime | None = None,
    ) -> str:
        event_id = new_id("fxev")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO external_effect_events("
            "event_id, effect_id, from_state, to_state, actor_type, actor_id, "
            "summary_redacted, occurred_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                effect_id,
                from_state,
                to_state,
                actor_type,
                actor_id,
                summary_redacted,
                ts,
            ),
        )
        return event_id

    def transition_external_effect(
        self,
        *,
        effect_id: str,
        to_state: str,
        job_id: str,
        lease_owner: str,
        actor_type: str = "worker",
        actor_id: str | None = None,
        summary_redacted: str | None = None,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> None:
        from router_control.domain.enums import EffectState, can_transition_effect

        target = EffectState(to_state)
        with transaction(self._conn, immediate=True):
            row = self._conn.execute(
                "SELECT * FROM external_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("external effect not found")
            if str(row["job_id"]) != job_id:
                raise StaleFenceError("effect job mismatch for transition")
            _assert_fenced_effect_write(
                self._conn,
                router_id=str(row["router_id"]),
                job_id=job_id,
                lease_owner=lease_owner,
                now_epoch=now_epoch,
                now=now,
            )
            current = EffectState(str(row["current_state"]))
            if not can_transition_effect(current, target):
                raise EffectTransitionError(
                    f"invalid effect transition {current.value} -> {target.value}"
                )
            ts = _utc_now_iso(now)
            updated = self._conn.execute(
                "UPDATE external_effects SET current_state = ?, updated_at = ? "
                "WHERE effect_id = ? AND current_state = ?",
                (target.value, ts, effect_id, current.value),
            )
            if updated.rowcount != 1:
                raise ConflictError("effect transition lost race")
            self._append_external_effect_event_unlocked(
                effect_id=effect_id,
                from_state=current.value,
                to_state=target.value,
                actor_type=actor_type,
                actor_id=actor_id,
                summary_redacted=summary_redacted,
                now=now,
            )

    def get_external_effect(self, effect_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM external_effects WHERE effect_id = ?",
                (effect_id,),
            ).fetchone(),
        )

    def get_external_effect_by_key(
        self, router_id: str, effect_key: str
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM external_effects WHERE router_id = ? AND effect_key = ?",
                (router_id, effect_key),
            ).fetchone(),
        )

    def list_external_effect_events(self, effect_id: str) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM external_effect_events WHERE effect_id = ? "
                "ORDER BY occurred_at",
                (effect_id,),
            ).fetchall()
        )

    def upsert_effect_continuation(
        self,
        *,
        effect_id: str,
        continuation_key: str,
        state: str,
        job_id: str,
        lease_owner: str,
        now_epoch: int | None = None,
        now: datetime | None = None,
    ) -> str:
        row = self._conn.execute(
            "SELECT router_id, job_id FROM external_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("external effect not found for continuation")
        if str(row["job_id"]) != job_id:
            raise StaleFenceError("effect job mismatch for continuation upsert")
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            _assert_fenced_effect_write(
                self._conn,
                router_id=str(row["router_id"]),
                job_id=job_id,
                lease_owner=lease_owner,
                now_epoch=now_epoch,
                now=now,
            )
            existing = self._conn.execute(
                "SELECT continuation_id FROM effect_continuations "
                "WHERE effect_id = ? AND continuation_key = ?",
                (effect_id, continuation_key),
            ).fetchone()
            if existing:
                self._conn.execute(
                    "UPDATE effect_continuations SET state = ?, updated_at = ? "
                    "WHERE continuation_id = ?",
                    (state, ts, existing["continuation_id"]),
                )
                return str(existing["continuation_id"])
            cid = new_id("fxc")
            self._conn.execute(
                "INSERT INTO effect_continuations("
                "continuation_id, effect_id, continuation_key, state, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (cid, effect_id, continuation_key, state, ts, ts),
            )
            return cid

    def submit_recovery_request(
        self,
        *,
        recovery_key: str,
        request_digest: str,
        recovery_action: str,
        operation_id: str | None = None,
        job_id: str | None = None,
        router_id: str | None = None,
        parent_request_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[int, sqlite3.Row]:
        """CAS recovery substrate: same key+digest replay; different digest -> 409."""
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            existing = self._conn.execute(
                "SELECT * FROM recovery_requests WHERE recovery_key = ? AND request_digest = ?",
                (recovery_key, request_digest),
            ).fetchone()
            if existing is not None:
                return 200, existing
            conflict = self._conn.execute(
                "SELECT * FROM recovery_requests WHERE recovery_key = ? AND request_digest != ?",
                (recovery_key, request_digest),
            ).fetchone()
            if conflict is not None:
                raise RecoveryConflictError(
                    "recovery key replay with different digest"
                )
            active = self._conn.execute(
                "SELECT * FROM recovery_requests WHERE recovery_key = ? "
                "AND status = 'Active' LIMIT 1",
                (recovery_key,),
            ).fetchone()
            if active is not None:
                raise ConflictError("recovery action already active for key")
            parent = None
            if parent_request_id:
                parent = self._conn.execute(
                    "SELECT * FROM recovery_requests WHERE request_id = ?",
                    (parent_request_id,),
                ).fetchone()
                if parent is None:
                    raise NotFoundError("parent recovery request not found")
                if str(parent["status"]) in ("Succeeded", "Failed", "Conflict"):
                    raise ConflictError("stale parent recovery attempt")
            request_id = new_id("rcvr")
            self._conn.execute(
                "INSERT INTO recovery_requests("
                "request_id, recovery_key, request_digest, recovery_action, parent_request_id, "
                "operation_id, job_id, router_id, status, response_digest, created_at, updated_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Active', NULL, ?, ?)",
                (
                    request_id,
                    recovery_key,
                    request_digest,
                    recovery_action,
                    parent_request_id,
                    operation_id,
                    job_id,
                    router_id,
                    ts,
                    ts,
                ),
            )
            row = self._conn.execute(
                "SELECT * FROM recovery_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            assert row is not None
            return 201, row

    def complete_recovery_request(
        self,
        *,
        request_id: str,
        status: str,
        response_digest: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if status not in ("Succeeded", "Failed", "Conflict"):
            raise ConflictError("terminal recovery status required")
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            row = self._conn.execute(
                "SELECT * FROM recovery_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None:
                raise NotFoundError("recovery request not found")
            if str(row["status"]) in ("Succeeded", "Failed", "Conflict"):
                return
            updated = self._conn.execute(
                "UPDATE recovery_requests SET status = ?, response_digest = ?, "
                "updated_at = ?, terminal_at = ? "
                "WHERE request_id = ? AND status NOT IN ('Succeeded', 'Failed', 'Conflict')",
                (status, response_digest, ts, ts, request_id),
            )
            if updated.rowcount != 1:
                raise ConflictError("recovery completion rejected")

    def get_recovery_request(self, request_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM recovery_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone(),
        )

    def create_artifact_staging(
        self,
        *,
        temp_path: str,
        content_digest: str,
        size_bytes: int,
        router_id: str | None = None,
        operation_id: str | None = None,
        job_id: str | None = None,
        restorable: bool = False,
        restorable_reason: str = "fake-non-live",
        now: datetime | None = None,
    ) -> str:
        staging_id = new_id("stg")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO artifact_staging("
            "staging_id, artifact_id, router_id, operation_id, job_id, temp_path, final_path, "
            "content_digest, size_bytes, staging_status, restorable, restorable_reason, "
            "created_at, published_at"
            ") VALUES (?, NULL, ?, ?, ?, ?, NULL, ?, ?, 'temp', ?, ?, ?, NULL)",
            (
                staging_id,
                router_id,
                operation_id,
                job_id,
                temp_path,
                content_digest,
                size_bytes,
                1 if restorable else 0,
                restorable_reason,
                ts,
            ),
        )
        return staging_id

    def get_artifact_staging(self, staging_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM artifact_staging WHERE staging_id = ?",
                (staging_id,),
            ).fetchone(),
        )

    def advance_artifact_staging(
        self,
        staging_id: str,
        *,
        staging_status: str,
        final_path: str | None = None,
        artifact_id: str | None = None,
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        published_at = ts if staging_status == "published" else None
        self._conn.execute(
            "UPDATE artifact_staging SET staging_status = ?, final_path = COALESCE(?, final_path), "
            "artifact_id = COALESCE(?, artifact_id), published_at = COALESCE(?, published_at) "
            "WHERE staging_id = ?",
            (staging_status, final_path, artifact_id, published_at, staging_id),
        )

    def link_artifact_publication(
        self,
        *,
        staging_id: str,
        artifact_id: str,
        link_kind: str = "published",
        now: datetime | None = None,
    ) -> str:
        link_id = new_id("lnk")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO artifact_publication_links("
            "link_id, staging_id, artifact_id, link_kind, created_at"
            ") VALUES (?, ?, ?, ?, ?)",
            (link_id, staging_id, artifact_id, link_kind, ts),
        )
        return link_id

    def mark_backup_metadata_restorable(
        self,
        *,
        artifact_id: str,
        restorable: bool,
        restorable_reason: str,
        now: datetime | None = None,
    ) -> str:
        ts = _utc_now_iso(now)
        meta_id = new_id("bkpm")
        self._conn.execute(
            "INSERT INTO artifact_backup_metadata("
            "backup_meta_id, artifact_id, restorable, restorable_reason, verified_at, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            (
                meta_id,
                artifact_id,
                1 if restorable else 0,
                restorable_reason,
                ts,
                ts,
            ),
        )
        return meta_id

    def assert_backup_restorable(self, artifact_id: str) -> None:
        row = self._conn.execute(
            "SELECT restorable, restorable_reason FROM artifact_backup_metadata "
            "WHERE artifact_id = ? ORDER BY created_at DESC LIMIT 1",
            (artifact_id,),
        ).fetchone()
        if row is None or int(row["restorable"]) != 1:
            reason = str(row["restorable_reason"]) if row else "missing metadata"
            raise ArtifactNotRestorableError(
                f"backup artifact not live-restorable: {reason}"
            )

    def upsert_router_safety_session(
        self,
        *,
        router_id: str,
        safety_state: str,
        fail_safe_active: bool = False,
        reboot_marker: str | None = None,
        baseline_revision_id: str | None = None,
        verified_runtime_revision_id: str | None = None,
        startup_saved_revision_id: str | None = None,
        safety_payload: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> str:
        ts = _utc_now_iso(now)
        existing = self._conn.execute(
            "SELECT session_id, reboot_marker FROM router_safety_sessions WHERE router_id = ?",
            (router_id,),
        ).fetchone()
        resolved_marker = _merge_safety_payload(
            str(existing["reboot_marker"]) if existing else None,
            boot_marker=reboot_marker,
            payload_updates=safety_payload,
        )
        if existing:
            self._conn.execute(
                "UPDATE router_safety_sessions SET safety_state = ?, fail_safe_active = ?, "
                "reboot_marker = ?, baseline_revision_id = ?, verified_runtime_revision_id = ?, "
                "startup_saved_revision_id = ?, updated_at = ? WHERE router_id = ?",
                (
                    safety_state,
                    1 if fail_safe_active else 0,
                    resolved_marker,
                    baseline_revision_id,
                    verified_runtime_revision_id,
                    startup_saved_revision_id,
                    ts,
                    router_id,
                ),
            )
            return str(existing["session_id"])
        session_id = new_id("safe")
        self._conn.execute(
            "INSERT INTO router_safety_sessions("
            "session_id, router_id, fail_safe_active, reboot_marker, baseline_revision_id, "
            "safety_state, verified_runtime_revision_id, startup_saved_revision_id, "
            "created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                session_id,
                router_id,
                1 if fail_safe_active else 0,
                resolved_marker,
                baseline_revision_id,
                safety_state,
                verified_runtime_revision_id,
                startup_saved_revision_id,
                ts,
                ts,
            ),
        )
        return session_id

    def get_router_safety_payload(self, router_id: str) -> dict[str, Any]:
        row = self.get_router_safety_session(router_id)
        if row is None:
            return {}
        return decode_safety_payload(
            str(row["reboot_marker"]) if row["reboot_marker"] else None
        )

    def get_router_safety_session(self, router_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_safety_sessions WHERE router_id = ?",
                (router_id,),
            ).fetchone(),
        )

    def list_pending_artifact_staging(
        self,
        *,
        limit: int = 100,
    ) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM artifact_staging "
                "WHERE staging_status NOT IN ('published', 'abandoned') "
                "ORDER BY created_at LIMIT ?",
                (limit,),
            ).fetchall()
        )

    def record_router_boot_observation(
        self,
        *,
        router_id: str,
        boot_id: str,
        boot_known: bool,
        boot_marker: str | None = None,
        now: datetime | None = None,
    ) -> str:
        ts = _utc_now_iso(now)
        obs_id = new_id("boot")
        self._conn.execute(
            "INSERT OR REPLACE INTO router_boot_observations("
            "boot_observation_id, router_id, boot_id, boot_marker, boot_known, "
            "observed_at, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                obs_id,
                router_id,
                boot_id,
                boot_marker,
                1 if boot_known else 0,
                ts,
                ts,
            ),
        )
        return obs_id

    def assert_router_boot_known(self, router_id: str) -> None:
        row = self._conn.execute(
            "SELECT boot_known FROM router_boot_observations "
            "WHERE router_id = ? ORDER BY observed_at DESC LIMIT 1",
            (router_id,),
        ).fetchone()
        if row is None or int(row["boot_known"]) != 1:
            raise UnknownBootError("unknown boot blocks readiness")

    def record_evidence_revision(
        self,
        *,
        router_id: str,
        evidence_kind: str,
        digest: str,
        revision_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        ts = _utc_now_iso(now)
        evidence_id = new_id("evd")
        self._conn.execute(
            "INSERT INTO router_evidence_revisions("
            "evidence_id, router_id, evidence_kind, revision_id, digest, observed_at, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (evidence_id, router_id, evidence_kind, revision_id, digest, ts, ts),
        )
        return evidence_id

    def get_latest_evidence_revision(
        self, router_id: str, evidence_kind: str
    ) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_evidence_revisions "
                "WHERE router_id = ? AND evidence_kind = ? "
                "ORDER BY observed_at DESC LIMIT 1",
                (router_id, evidence_kind),
            ).fetchone(),
        )

    # --- P2 immutable deployment model (offline/fake) ---

    def _peek_deployment_idempotency(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
    ) -> sqlite3.Row | None:
        existing = self._conn.execute(
            "SELECT * FROM deployment_idempotency WHERE scope_kind = ? AND scope_id = ? "
            "AND operation_kind = ? AND idempotency_key = ?",
            (scope_kind, scope_id, operation_kind, idempotency_key),
        ).fetchone()
        if existing is None:
            return None
        if existing["request_digest"] != request_digest:
            raise IdempotencyConflict("same key different digest")
        return cast(sqlite3.Row, existing)

    def _store_deployment_idempotency(
        self,
        *,
        scope_kind: str,
        scope_id: str,
        operation_kind: str,
        idempotency_key: str,
        request_digest: str,
        response_digest: str,
        resource_id: str,
        now: datetime | None = None,
    ) -> None:
        self._conn.execute(
            "INSERT INTO deployment_idempotency("
            "scope_kind, scope_id, operation_kind, idempotency_key, request_digest, "
            "response_digest, resource_id, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scope_kind,
                scope_id,
                operation_kind,
                idempotency_key,
                request_digest,
                response_digest,
                resource_id,
                _utc_now_iso(now),
            ),
        )

    def create_published_preset_idempotent(
        self,
        *,
        preset_id: str,
        source_revision_id: str,
        site_id: str,
        canonical_document_digest: str,
        schema_digest: str,
        validation_digest: str,
        source_lineage_json: str,
        publisher_session_binding_hmac: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[sqlite3.Row, bool]:
        with transaction(self._conn, immediate=True):
            preset = self.get_event_preset(preset_id)
            if preset is None:
                raise NotFoundError("event preset not found")
            revision = self.get_event_preset_revision(source_revision_id)
            if revision is None or str(revision["preset_id"]) != preset_id:
                raise NotFoundError("revision not found for preset")
            if str(revision["validation_status"]) != "ValidOffline":
                raise ConflictError("revision not ValidOffline")
            existing = self._peek_deployment_idempotency(
                scope_kind="preset",
                scope_id=preset_id,
                operation_kind="publish_preset",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                row = self.get_published_preset(str(existing["resource_id"]))
                if row is None:
                    raise ConflictError("idempotency references missing publication")
                return row, False
            dup = self._conn.execute(
                "SELECT published_preset_id FROM published_presets "
                "WHERE preset_id = ? AND source_revision_id = ?",
                (preset_id, source_revision_id),
            ).fetchone()
            if dup is not None:
                row = self.get_published_preset(str(dup["published_preset_id"]))
                assert row is not None
                return row, False
            if expected_version is not None and int(preset["version"]) != expected_version:
                raise PreconditionFailed("If-Match version mismatch")
            pub_id = new_id("pub")
            ts = _utc_now_iso(now)
            self._conn.execute(
                "INSERT INTO published_presets("
                "published_preset_id, preset_id, source_revision_id, site_id, "
                "canonical_document_digest, schema_digest, validation_digest, "
                "source_lineage_json, published_at, publisher_session_binding_hmac"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pub_id,
                    preset_id,
                    source_revision_id,
                    site_id,
                    canonical_document_digest,
                    schema_digest,
                    validation_digest,
                    source_lineage_json,
                    ts,
                    publisher_session_binding_hmac,
                ),
            )
            new_version = int(preset["version"]) + 1
            self._conn.execute(
                "UPDATE event_presets SET published_revision_id = ?, version = ?, updated_at = ? "
                "WHERE preset_id = ? AND version = ?",
                (source_revision_id, new_version, ts, preset_id, int(preset["version"])),
            )
            if self._conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise PreconditionFailed("optimistic version mismatch")
            row = self.get_published_preset(pub_id)
            assert row is not None
            self._store_deployment_idempotency(
                scope_kind="preset",
                scope_id=preset_id,
                operation_kind="publish_preset",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_digest=canonical_document_digest,
                resource_id=pub_id,
                now=now,
            )
            self.append_audit(
                action="published_preset.create",
                outcome="accepted",
                summary_redacted=f"preset_id={preset_id};pub={pub_id}",
                actor_id=actor_id,
                request_digest=request_digest,
                now=now,
            )
            return row, True

    def get_published_preset(self, published_preset_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM published_presets WHERE published_preset_id = ?",
                (published_preset_id,),
            ).fetchone(),
        )

    def create_deployment_revision_idempotent(
        self,
        *,
        published_preset_id: str,
        router_id: str,
        site_id: str,
        execution_target: str,
        identity_tuple_json: str,
        evidence_digest: str,
        required_families_json: str,
        credential_ref_versions_json: str,
        topology_bindings_json: str,
        canonical_desired_json: str,
        canonical_desired_digest: str,
        actor_session_binding_hmac: str,
        idempotency_key: str,
        request_digest: str,
        awg_ref_json: str | None = None,
        routes_ref_json: str | None = None,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[sqlite3.Row, bool]:
        with transaction(self._conn, immediate=True):
            if self.get_router(router_id) is None:
                raise NotFoundError("router not found")
            if self.get_published_preset(published_preset_id) is None:
                raise NotFoundError("published preset not found")
            existing = self._peek_deployment_idempotency(
                scope_kind="router",
                scope_id=router_id,
                operation_kind="create_deployment",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                row = self.get_deployment_revision(str(existing["resource_id"]))
                if row is None:
                    raise ConflictError("idempotency references missing deployment")
                return row, False
            dup = self._conn.execute(
                "SELECT deployment_revision_id FROM router_deployment_revisions "
                "WHERE router_id = ? AND canonical_desired_digest = ? AND published_preset_id = ?",
                (router_id, canonical_desired_digest, published_preset_id),
            ).fetchone()
            if dup is not None:
                row = self.get_deployment_revision(str(dup["deployment_revision_id"]))
                assert row is not None
                return row, False
            dep_id = new_id("dep")
            ts = _utc_now_iso(now)
            self._conn.execute(
                "INSERT INTO router_deployment_revisions("
                "deployment_revision_id, published_preset_id, router_id, site_id, "
                "execution_target, identity_tuple_json, evidence_digest, "
                "required_families_json, credential_ref_versions_json, topology_bindings_json, "
                "awg_ref_json, routes_ref_json, canonical_desired_json, canonical_desired_digest, "
                "created_at, actor_session_binding_hmac"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    dep_id,
                    published_preset_id,
                    router_id,
                    site_id,
                    execution_target,
                    identity_tuple_json,
                    evidence_digest,
                    required_families_json,
                    credential_ref_versions_json,
                    topology_bindings_json,
                    awg_ref_json,
                    routes_ref_json,
                    canonical_desired_json,
                    canonical_desired_digest,
                    ts,
                    actor_session_binding_hmac,
                ),
            )
            row = self.get_deployment_revision(dep_id)
            assert row is not None
            self._store_deployment_idempotency(
                scope_kind="router",
                scope_id=router_id,
                operation_kind="create_deployment",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_digest=canonical_desired_digest,
                resource_id=dep_id,
                now=now,
            )
            self.append_audit(
                action="deployment_revision.create",
                outcome="accepted",
                summary_redacted=f"router_id={router_id};dep={dep_id}",
                actor_id=actor_id,
                request_digest=request_digest,
                now=now,
            )
            return row, True

    def get_deployment_revision(self, deployment_revision_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM router_deployment_revisions WHERE deployment_revision_id = ?",
                (deployment_revision_id,),
            ).fetchone(),
        )

    def create_desired_from_deployment(
        self,
        *,
        router_id: str,
        deployment_revision_id: str,
        based_on_observation_id: str,
        idempotency_key: str,
        request_digest: str,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[str, str, bool]:
        with transaction(self._conn, immediate=True):
            deployment = self.get_deployment_revision(deployment_revision_id)
            if deployment is None or str(deployment["router_id"]) != router_id:
                raise NotFoundError("deployment revision not found")
            existing = self._peek_deployment_idempotency(
                scope_kind="router",
                scope_id=router_id,
                operation_kind="create_desired_from_deployment",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
            if existing is not None:
                rev = self._conn.execute(
                    "SELECT * FROM desired_revisions WHERE revision_id = ?",
                    (existing["resource_id"],),
                ).fetchone()
                if rev is None:
                    raise ConflictError("idempotency references missing desired revision")
                return str(rev["revision_id"]), etag_for_revision(
                    str(rev["revision_id"]), str(rev["canonical_digest"])
                ), False
            obs = self.get_observation(based_on_observation_id)
            if obs is None or obs["router_id"] != router_id:
                raise PreconditionFailed("observation invalid")
            now_iso = _utc_now_iso(now)
            if obs["collection_status"] != "Succeeded" or obs["valid_until"] < now_iso:
                raise PreconditionFailed("observation stale or failed")
            next_num_row = self._conn.execute(
                "SELECT COALESCE(MAX(revision_number), 0) AS m FROM desired_revisions "
                "WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            next_number = int(next_num_row["m"]) + 1
            rid = new_id("rev")
            canonical_digest = str(deployment["canonical_desired_digest"])
            self._conn.execute(
                "INSERT INTO desired_revisions("
                "revision_id, router_id, revision_number, parent_revision_id, "
                "canonical_digest, desired_document_json, based_on_observation_id, "
                "deployment_revision_id, actor_type, actor_id, created_at"
                ") VALUES (?, ?, ?, NULL, ?, ?, ?, ?, 'operator', ?, ?)",
                (
                    rid,
                    router_id,
                    next_number,
                    canonical_digest,
                    deployment["canonical_desired_json"],
                    based_on_observation_id,
                    deployment_revision_id,
                    actor_id,
                    now_iso,
                ),
            )
            state = self._conn.execute(
                "SELECT router_id FROM router_revision_state WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            if state is None:
                self._conn.execute(
                    "INSERT INTO router_revision_state("
                    "router_id, current_desired_revision_id, last_observation_id, updated_at"
                    ") VALUES (?, ?, ?, ?)",
                    (router_id, rid, based_on_observation_id, now_iso),
                )
            else:
                self._conn.execute(
                    "UPDATE router_revision_state SET current_desired_revision_id = ?, "
                    "last_observation_id = ?, updated_at = ? WHERE router_id = ?",
                    (rid, based_on_observation_id, now_iso, router_id),
                )
            self._store_deployment_idempotency(
                scope_kind="router",
                scope_id=router_id,
                operation_kind="create_desired_from_deployment",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                response_digest=canonical_digest,
                resource_id=rid,
                now=now,
            )
            return rid, etag_for_revision(rid, canonical_digest), True

    def upsert_family_certification(
        self,
        *,
        router_id: str,
        family: str,
        identity_tuple_digest: str,
        shape_digest: str,
        codec_digest: str,
        executor_digest: str,
        evidence_digest: str,
        certification_level: str,
        valid_from: str,
        valid_until: str,
        gate_c_campaign_id: str | None = None,
        now: datetime | None = None,
    ) -> str:
        ts = _utc_now_iso(now)
        cert_id = new_id("fcert")
        self._conn.execute(
            "INSERT INTO router_family_certifications("
            "certification_id, router_id, family, identity_tuple_digest, shape_digest, "
            "codec_digest, executor_digest, evidence_digest, certification_level, "
            "valid_from, valid_until, revoked_at, gate_c_campaign_id, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)",
            (
                cert_id,
                router_id,
                family,
                identity_tuple_digest,
                shape_digest,
                codec_digest,
                executor_digest,
                evidence_digest,
                certification_level,
                valid_from,
                valid_until,
                gate_c_campaign_id,
                ts,
            ),
        )
        return cert_id

    def list_active_family_certifications(self, router_id: str) -> list[sqlite3.Row]:
        now_iso = _utc_now_iso(None)
        rows = self._conn.execute(
            "SELECT * FROM router_family_certifications "
            "WHERE router_id = ? AND revoked_at IS NULL AND valid_until >= ? "
            "ORDER BY family, created_at DESC",
            (router_id, now_iso),
        ).fetchall()
        return list(rows)

    def revoke_family_certification(
        self, certification_id: str, *, now: datetime | None = None
    ) -> None:
        self._conn.execute(
            "UPDATE router_family_certifications SET revoked_at = ? WHERE certification_id = ?",
            (_utc_now_iso(now), certification_id),
        )

    def create_p2_plan(
        self,
        *,
        router_id: str,
        revision_id: str,
        observation_id: str,
        deployment_revision_id: str,
        session_binding_hmac: str,
        plan_digest: str,
        items: list[dict[str, Any]],
        risk_class: str = "Medium",
        expires_in_seconds: int = 3600,
        adopt_acknowledged: bool = False,
        if_match: str,
        actor_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[str, str]:
        with transaction(self._conn, immediate=True):
            rev = self._conn.execute(
                "SELECT * FROM desired_revisions WHERE revision_id = ?", (revision_id,)
            ).fetchone()
            if rev is None or rev["router_id"] != router_id:
                raise NotFoundError("revision not found")
            if rev["deployment_revision_id"] is None:
                raise ConflictError("desired revision missing deployment binding")
            expected_etag = etag_for_revision(rev["revision_id"], rev["canonical_digest"])
            if if_match.strip() != expected_etag:
                raise PreconditionFailed("If-Match desired ETag mismatch")
            state = self._conn.execute(
                "SELECT current_desired_revision_id FROM router_revision_state WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            if state is None or state["current_desired_revision_id"] != revision_id:
                raise ConflictError("revision is not current desired pointer")
            obs = self.get_observation(observation_id)
            if obs is None or obs["router_id"] != router_id:
                raise PreconditionFailed("observation invalid")
            now_iso = _utc_now_iso(now)
            if obs["collection_status"] != "Succeeded" or obs["valid_until"] < now_iso:
                raise PreconditionFailed("observation stale or failed")
            pid = new_id("plan")
            expires_at = _utc_now_iso(
                (now or datetime.now(UTC)) + timedelta(seconds=expires_in_seconds)
            )
            self._conn.execute(
                "INSERT INTO change_plans("
                "plan_id, router_id, revision_id, observation_id, expected_desired_digest, "
                "observed_resource_version, observed_state_digest, plan_digest, risk_class, "
                "requires_backup, requires_fail_safe, expires_at, confirmation_state, "
                "actor_type, actor_id, created_at, deployment_revision_id, session_binding_hmac, "
                "plan_version, adopt_acknowledged"
                ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, ?, 'Draft', 'operator', ?, ?, "
                "?, ?, 1, ?)",
                (
                    pid,
                    router_id,
                    revision_id,
                    observation_id,
                    rev["canonical_digest"],
                    obs["resource_version"],
                    obs["state_digest"],
                    plan_digest,
                    risk_class,
                    expires_at,
                    actor_id,
                    now_iso,
                    deployment_revision_id,
                    session_binding_hmac,
                    1 if adopt_acknowledged else 0,
                ),
            )
            for item in items:
                self._conn.execute(
                    "INSERT INTO change_plan_items("
                    "plan_item_id, plan_id, ordinal, change_kind, target_resource_id, "
                    "intent_kind, intent_json, ownership_action, family_cert_snapshot_json"
                    ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        new_id("pli"),
                        pid,
                        int(item["ordinal"]),
                        item.get("change_kind", item["intent_kind"]),
                        item.get("target_resource_id"),
                        item["intent_kind"],
                        json.dumps(item["intent_json"], sort_keys=True, separators=(",", ":")),
                        item.get("ownership_action"),
                        json.dumps(item["family_cert_snapshot_json"])
                        if item.get("family_cert_snapshot_json")
                        else None,
                    ),
                )
            return pid, etag_for_plan_version(pid, 1)

    def confirm_p2_plan(
        self,
        *,
        plan_id: str,
        plan_digest: str,
        if_match: str,
        session_binding_hmac: str,
        adopt_acknowledged: bool,
        actor_id: str,
        now: datetime | None = None,
    ) -> sqlite3.Row:
        with transaction(self._conn, immediate=True):
            plan = self.get_plan(plan_id)
            if plan is None:
                raise NotFoundError("plan not found")
            plan_version = int(plan["plan_version"] or 1)
            expected = etag_for_plan_version(plan_id, plan_version)
            if if_match.strip() != expected:
                raise PreconditionFailed("If-Match plan ETag mismatch")
            recomputed_digest, _payload = self.recompute_p2_plan_digest(plan_id)
            if plan_digest != recomputed_digest:
                raise ConflictError("digest_mismatch")
            stored_hmac = plan["session_binding_hmac"]
            if not stored_hmac or not hmac.compare_digest(str(stored_hmac), session_binding_hmac):
                raise ConflictError("session_binding_mismatch")
            now_iso = _utc_now_iso(now)
            if plan["expires_at"] < now_iso:
                self._conn.execute(
                    "UPDATE change_plans SET confirmation_state = 'Expired' WHERE plan_id = ?",
                    (plan_id,),
                )
                raise ConflictError("plan expired")
            if plan["confirmation_state"] != "Draft":
                raise ConflictError("plan not in Draft state")
            self.assert_p2_plan_fresh(
                plan_id, expected_digest=recomputed_digest, now=now
            )
            item_rows = self._conn.execute(
                "SELECT ownership_action FROM change_plan_items WHERE plan_id = ?",
                (plan_id,),
            ).fetchall()
            needs_adopt = any(
                str(row["ownership_action"]) == "Adopt"
                for row in item_rows
                if row["ownership_action"]
            )
            if needs_adopt and not adopt_acknowledged:
                raise ConflictError("adopt_acknowledgment_required")
            new_version = plan_version + 1
            self._conn.execute(
                "UPDATE change_plans SET confirmation_state = 'Confirmed', "
                "confirmed_at = ?, confirmed_by_actor = ?, plan_version = ?, "
                "adopt_acknowledged = ? WHERE plan_id = ? AND plan_version = ?",
                (
                    now_iso,
                    actor_id,
                    new_version,
                    1 if adopt_acknowledged else 0,
                    plan_id,
                    plan_version,
                ),
            )
            if self._conn.execute("SELECT changes()").fetchone()[0] != 1:
                raise PreconditionFailed("If-Match plan ETag mismatch")
            updated = self.get_plan(plan_id)
            assert updated is not None
            return updated

    def get_plan_items(self, plan_id: str) -> list[sqlite3.Row]:
        rows = self._conn.execute(
            "SELECT * FROM change_plan_items WHERE plan_id = ? ORDER BY ordinal",
            (plan_id,),
        ).fetchall()
        return list(rows)

    def list_jobs_for_plan(self, plan_id: str) -> list[sqlite3.Row]:
        op = self._conn.execute(
            "SELECT operation_id FROM operations WHERE plan_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (plan_id,),
        ).fetchone()
        if op is None:
            return []
        rows = self._conn.execute(
            "SELECT * FROM jobs WHERE operation_id = ? ORDER BY attempt DESC",
            (op["operation_id"],),
        ).fetchall()
        return list(rows)

    def insert_plan_verify_report(
        self,
        *,
        plan_id: str,
        job_id: str,
        observation_id: str,
        checks_json: str,
        overall_status: str,
        now: datetime | None = None,
    ) -> str:
        report_id = new_id("pvr")
        ts = _utc_now_iso(now)
        self._conn.execute(
            "INSERT INTO plan_verify_reports("
            "report_id, plan_id, job_id, observation_id, checks_json, overall_status, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?)",
            (report_id, plan_id, job_id, observation_id, checks_json, overall_status, ts),
        )
        return report_id

    def get_plan_verify_report(self, plan_id: str, job_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            self._conn.execute(
                "SELECT * FROM plan_verify_reports WHERE plan_id = ? AND job_id = ?",
                (plan_id, job_id),
            ).fetchone(),
        )

    def record_ownership_event(
        self,
        *,
        router_id: str,
        resource_id: str,
        plan_id: str,
        job_id: str,
        action: str,
        before_owner: str | None,
        after_owner: str | None,
        now: datetime | None = None,
    ) -> str:
        event_id = new_id("own")
        self._conn.execute(
            "INSERT INTO managed_resource_ownership_events("
            "event_id, router_id, resource_id, plan_id, job_id, action, "
            "before_owner, after_owner, created_at"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                event_id,
                router_id,
                resource_id,
                plan_id,
                job_id,
                action,
                before_owner,
                after_owner,
                _utc_now_iso(now),
            ),
        )
        return event_id

    def _family_cert_snapshot_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "family": str(row["family"]),
            "certification_id": str(row["certification_id"]),
            "identity_tuple_digest": str(row["identity_tuple_digest"]),
            "shape_digest": str(row["shape_digest"]),
            "codec_digest": str(row["codec_digest"]),
            "executor_digest": str(row["executor_digest"]),
            "evidence_digest": str(row["evidence_digest"]),
            "certification_level": str(row["certification_level"]),
            "valid_until": str(row["valid_until"]),
        }

    def build_family_cert_snapshots(
        self, router_id: str, required_families: list[str]
    ) -> list[dict[str, Any]]:
        active = self.list_active_family_certifications(router_id)
        by_family = {str(r["family"]): r for r in active}
        snapshots: list[dict[str, Any]] = []
        for family in sorted(required_families):
            row = by_family.get(family)
            if row is not None:
                snapshots.append(self._family_cert_snapshot_from_row(row))
        return snapshots

    def _p2_plan_item_digest_rows(self, plan_id: str) -> list[dict[str, Any]]:
        rows = self.get_plan_items(plan_id)
        items: list[dict[str, Any]] = []
        for row in rows:
            intent_json = json.loads(str(row["intent_json"])) if row["intent_json"] else {}
            intent_kind = str(row["intent_kind"] or row["change_kind"])
            intent_digest = digest_canonical(
                "change_plan",
                {"intent_kind": intent_kind, "intent": intent_json},
            )
            items.append(
                {
                    "ordinal": int(row["ordinal"]),
                    "intent_kind": intent_kind,
                    "intent_digest": intent_digest,
                    "ownership_action": row["ownership_action"],
                    "preconditions": [],
                    "postconditions": [],
                }
            )
        return sorted(items, key=lambda i: int(i["ordinal"]))

    def recompute_p2_plan_digest(self, plan_id: str) -> tuple[str, dict[str, Any]]:
        plan = self.get_plan(plan_id)
        if plan is None:
            raise NotFoundError("plan not found")
        dep_id = plan["deployment_revision_id"]
        if dep_id is None:
            raise ConflictError("digest_mismatch")
        deployment = self.get_deployment_revision(str(dep_id))
        if deployment is None:
            raise ConflictError("digest_mismatch")
        desired = self._conn.execute(
            "SELECT * FROM desired_revisions WHERE revision_id = ?",
            (plan["revision_id"],),
        ).fetchone()
        if desired is None:
            raise ConflictError("digest_mismatch")
        obs = self.get_observation(str(plan["observation_id"]))
        if obs is None:
            raise PreconditionFailed("stale_observation")
        families = json.loads(str(deployment["required_families_json"]))
        snapshots = self.build_family_cert_snapshots(str(plan["router_id"]), families)
        payload = {
            "router_id": str(plan["router_id"]),
            "deployment_revision_id": str(dep_id),
            "deployment_digest": str(deployment["canonical_desired_digest"]),
            "desired_revision_id": str(plan["revision_id"]),
            "desired_digest": str(desired["canonical_digest"]),
            "observation_id": str(plan["observation_id"]),
            "observation_state_digest": str(obs["state_digest"]),
            "observation_resource_version": str(obs["resource_version"]),
            "execution_target": str(deployment["execution_target"]),
            "family_cert_snapshots": snapshots,
            "items": self._p2_plan_item_digest_rows(plan_id),
            "risk_class": str(plan["risk_class"]),
            "requires_backup": bool(plan["requires_backup"]),
            "requires_fail_safe": bool(plan["requires_fail_safe"]),
            "expires_at": str(plan["expires_at"]),
            "adopt_acknowledged": bool(plan["adopt_acknowledged"]),
        }
        return digest_canonical("change_plan", payload), payload

    def assert_p2_plan_fresh(
        self,
        plan_id: str,
        *,
        expected_digest: str | None = None,
        require_current_desired: bool = True,
        now: datetime | None = None,
    ) -> None:
        """Recompute digest and assert observation/credential/cert/tuple freshness."""
        plan = self.get_plan(plan_id)
        if plan is None:
            raise NotFoundError("plan not found")
        if not plan["session_binding_hmac"]:
            raise PreconditionFailed("unbound_plan_requires_recompile")
        now_iso = _utc_now_iso(now)
        digest, _payload = self.recompute_p2_plan_digest(plan_id)
        if expected_digest is not None and digest != expected_digest:
            raise ConflictError("digest_mismatch")
        if plan["plan_digest"] != digest:
            raise ConflictError("digest_mismatch")
        obs = self.get_observation(str(plan["observation_id"]))
        if obs is None or obs["valid_until"] < now_iso:
            raise PreconditionFailed("stale_observation")
        if obs["state_digest"] != plan["observed_state_digest"]:
            raise PreconditionFailed("stale_observation")
        state = self._conn.execute(
            "SELECT current_desired_revision_id, last_observation_id "
            "FROM router_revision_state WHERE router_id = ?",
            (plan["router_id"],),
        ).fetchone()
        if state is not None:
            last_obs = state["last_observation_id"]
            if last_obs is not None and str(last_obs) != str(plan["observation_id"]):
                rev = self._conn.execute(
                    "SELECT based_on_observation_id FROM desired_revisions WHERE revision_id = ?",
                    (plan["revision_id"],),
                ).fetchone()
                based_on = rev["based_on_observation_id"] if rev else None
                if based_on is None or str(based_on) != str(plan["observation_id"]):
                    raise PreconditionFailed("stale_observation")
        desired = self._conn.execute(
            "SELECT canonical_digest FROM desired_revisions WHERE revision_id = ?",
            (plan["revision_id"],),
        ).fetchone()
        if desired is None or desired["canonical_digest"] != plan["expected_desired_digest"]:
            raise ConflictError("digest_mismatch")
        if (
            require_current_desired
            and state is not None
            and state["current_desired_revision_id"] != plan["revision_id"]
        ):
            raise ConflictError("digest_mismatch")
        dep = self.get_deployment_revision(str(plan["deployment_revision_id"]))
        if dep is None:
            raise ConflictError("digest_mismatch")
        router = self.get_router(str(plan["router_id"]))
        if router is None:
            raise NotFoundError("router not found")
        identity_tuple = json.loads(str(dep["identity_tuple_json"]))
        router_fp = str(router["identity_fingerprint"])
        tuple_fp = str(
            identity_tuple.get(
                "fingerprint", identity_tuple.get("identity_fingerprint", "")
            )
        )
        if tuple_fp and router_fp != tuple_fp:
            raise ConflictError("tuple_mismatch")
        cred_versions = json.loads(str(dep["credential_ref_versions_json"]))
        for entry in cred_versions:
            ref_id = str(entry.get("ref_id", entry.get("credential_ref_id", "")))
            version = str(entry.get("version", ""))
            cred = self.get_credential_ref(ref_id)
            if cred is None or cred["revoked_at"] is not None:
                raise ConflictError("stale_credential")
            if version and version != str(cred["created_at"]):
                raise ConflictError("stale_credential")
        families = json.loads(str(dep["required_families_json"]))
        snapshots = self.build_family_cert_snapshots(str(plan["router_id"]), families)
        if families and len(snapshots) != len(families):
            raise ConflictError("stale_certification")
        now_cmp = now_iso
        for snap in snapshots:
            if snap["valid_until"] < now_cmp:
                raise ConflictError("stale_certification")
            cert = self._conn.execute(
                "SELECT revoked_at, identity_tuple_digest FROM router_family_certifications "
                "WHERE certification_id = ?",
                (snap["certification_id"],),
            ).fetchone()
            if cert is None or cert["revoked_at"] is not None:
                raise ConflictError("stale_certification")
            if cert["identity_tuple_digest"] != snap["identity_tuple_digest"]:
                raise ConflictError("tuple_mismatch")

    def _transition_external_effect_unlocked(
        self,
        *,
        effect_id: str,
        to_state: str,
        job_id: str,
        actor_type: str = "worker",
        actor_id: str | None = None,
        summary_redacted: str | None = None,
        now: datetime | None = None,
    ) -> None:
        from router_control.domain.enums import EffectState, can_transition_effect

        row = self._conn.execute(
            "SELECT * FROM external_effects WHERE effect_id = ?",
            (effect_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError("external effect not found")
        if str(row["job_id"]) != job_id:
            raise StaleFenceError("effect job mismatch for transition")
        current = EffectState(str(row["current_state"]))
        target = EffectState(to_state)
        if current == target:
            return
        if not can_transition_effect(current, target):
            raise EffectTransitionError(
                f"invalid effect transition {current.value} -> {target.value}"
            )
        ts = _utc_now_iso(now)
        updated = self._conn.execute(
            "UPDATE external_effects SET current_state = ?, updated_at = ? "
            "WHERE effect_id = ? AND current_state = ?",
            (target.value, ts, effect_id, current.value),
        )
        if updated.rowcount != 1:
            raise ConflictError("effect transition lost race")
        self._append_external_effect_event_unlocked(
            effect_id=effect_id,
            from_state=current.value,
            to_state=target.value,
            actor_type=actor_type,
            actor_id=actor_id,
            summary_redacted=summary_redacted,
            now=now,
        )

    def finalize_verify_success(
        self,
        *,
        plan_id: str,
        job_id: str,
        lease_owner: str,
        effect_id: str | None,
        readback_identity_fingerprint: str,
        readback_resource_version: str,
        readback_state_digest: str,
        verify_digest: str,
        checks_json: str,
        revision_id: str,
        router_id: str,
        now: datetime | None = None,
        now_epoch: int | None = None,
    ) -> str:
        """Fenced atomic verify-success bundle: report + optional ownership/applied."""
        existing = self.get_plan_verify_report(plan_id, job_id)
        if existing is not None:
            return str(existing["overall_status"])

        ts = _utc_now_iso(now)
        overall = "pass"
        readback_obs_id: str | None = None

        with transaction(self._conn, immediate=True):
            _assert_fenced_effect_write(
                self._conn,
                router_id=router_id,
                job_id=job_id,
                lease_owner=lease_owner,
                now_epoch=now_epoch,
                now=now,
            )
            plan = self.get_plan(plan_id)
            if plan is None:
                raise NotFoundError("plan not found")
            if plan["confirmation_state"] != "Confirmed":
                raise ConflictError("plan not confirmed")
            self.assert_p2_plan_fresh(plan_id, require_current_desired=False, now=now)
            state = self._conn.execute(
                "SELECT current_desired_revision_id FROM router_revision_state WHERE router_id = ?",
                (router_id,),
            ).fetchone()
            drifted = state is None or str(state["current_desired_revision_id"]) != str(
                plan["revision_id"]
            )
            if drifted:
                overall = "drifted"
            else:
                from router_control.domain.enums import EffectState

                _verify_success_predecessors = frozenset({EffectState.ACKNOWLEDGED})
                if not effect_id:
                    raise ConflictError("effect required for verify-success finalization")
                fx = self._conn.execute(
                    "SELECT current_state FROM external_effects WHERE effect_id = ?",
                    (effect_id,),
                ).fetchone()
                if fx is None:
                    raise NotFoundError("external effect not found")
                current_effect = EffectState(str(fx["current_state"]))
                if current_effect not in _verify_success_predecessors:
                    raise ConflictError(
                        f"effect not ready for verify finalize: {current_effect.value}"
                    )
                readback_obs_id = new_id("obs")
                self._conn.execute(
                    "INSERT INTO router_observations("
                    "observation_id, router_id, capability_id, identity_fingerprint, "
                    "resource_version, state_digest, state_snapshot_json, collection_status, "
                    "source, adapter_version, observed_at, valid_until, created_at"
                    ") VALUES (?, ?, NULL, ?, ?, ?, NULL, 'Succeeded', 'readback', "
                    "'0.1.0', ?, ?, ?)",
                    (
                        readback_obs_id,
                        router_id,
                        readback_identity_fingerprint,
                        readback_resource_version,
                        readback_state_digest,
                        ts,
                        ts,
                        ts,
                    ),
                )
                items = self.get_plan_items(plan_id)
                for item in items:
                    action = item["ownership_action"]
                    if not action:
                        continue
                    action_str = str(action)
                    if action_str not in ("Create", "Adopt", "Update", "Retire"):
                        continue
                    intent = (
                        json.loads(str(item["intent_json"])) if item["intent_json"] else {}
                    )
                    kind = str(item["intent_kind"] or item["change_kind"])
                    logical_key = str(intent.get("zone_id", f"ordinal-{item['ordinal']}"))
                    resource_id = (
                        str(item["target_resource_id"])
                        if item["target_resource_id"]
                        else new_id("res")
                    )
                    before_owner: str | None = None
                    after_owner: str | None = "router-control"
                    if action_str == "Retire":
                        after_owner = None
                    existing_res = self._conn.execute(
                        "SELECT resource_id, owner FROM managed_resources "
                        "WHERE router_id = ? AND resource_kind = ? AND logical_key = ?",
                        (router_id, kind, logical_key),
                    ).fetchone()
                    if existing_res is not None:
                        before_owner = str(existing_res["owner"])
                        resource_id = str(existing_res["resource_id"])
                    lifecycle = "Present"
                    if action_str == "Retire":
                        lifecycle = "Retired"
                    self._conn.execute(
                        "INSERT INTO managed_resources("
                        "resource_id, router_id, resource_kind, logical_key, owner, "
                        "creating_revision_id, vendor_locator, locator_fingerprint, "
                        "lifecycle_status, last_observation_id, created_at, updated_at"
                        ") VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?) "
                        "ON CONFLICT(router_id, resource_kind, logical_key) DO UPDATE SET "
                        "owner = excluded.owner, lifecycle_status = excluded.lifecycle_status, "
                        "last_observation_id = excluded.last_observation_id, "
                        "updated_at = excluded.updated_at",
                        (
                            resource_id,
                            router_id,
                            kind,
                            logical_key,
                            after_owner or before_owner or "router-control",
                            revision_id,
                            lifecycle,
                            readback_obs_id,
                            ts,
                            ts,
                        ),
                    )
                    dup = self._conn.execute(
                        "SELECT event_id FROM managed_resource_ownership_events "
                        "WHERE plan_id = ? AND resource_id = ? AND action = ?",
                        (plan_id, resource_id, action_str),
                    ).fetchone()
                    if dup is None:
                        self._conn.execute(
                            "INSERT INTO managed_resource_ownership_events("
                            "event_id, router_id, resource_id, plan_id, job_id, action, "
                            "before_owner, after_owner, created_at"
                            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (
                                new_id("own"),
                                router_id,
                                resource_id,
                                plan_id,
                                job_id,
                                action_str,
                                before_owner,
                                after_owner,
                                ts,
                            ),
                        )
                evidence_id = new_id("evd")
                self._conn.execute(
                    "INSERT INTO router_evidence_revisions("
                    "evidence_id, router_id, evidence_kind, revision_id, digest, "
                    "observed_at, created_at"
                    ") VALUES (?, ?, 'runtime_applied', ?, ?, ?, ?)",
                    (evidence_id, router_id, revision_id, verify_digest, ts, ts),
                )
                self._transition_external_effect_unlocked(
                    effect_id=effect_id,
                    to_state=EffectState.OBSERVED_APPLIED.value,
                    job_id=job_id,
                    summary_redacted="verify observed applied",
                    now=now,
                )
                existing_safety = self._conn.execute(
                    "SELECT session_id, reboot_marker FROM router_safety_sessions "
                    "WHERE router_id = ?",
                    (router_id,),
                ).fetchone()
                if existing_safety:
                    self._conn.execute(
                        "UPDATE router_safety_sessions SET safety_state = 'Ready', "
                        "verified_runtime_revision_id = ?, updated_at = ? WHERE router_id = ?",
                        (revision_id, ts, router_id),
                    )
                else:
                    sid = new_id("safety")
                    self._conn.execute(
                        "INSERT INTO router_safety_sessions("
                        "session_id, router_id, safety_state, fail_safe_active, reboot_marker, "
                        "baseline_revision_id, verified_runtime_revision_id, "
                        "startup_saved_revision_id, created_at, updated_at"
                        ") VALUES (?, ?, 'Ready', 0, NULL, ?, ?, NULL, ?, ?)",
                        (sid, router_id, revision_id, revision_id, ts, ts),
                    )

            report_obs_id = readback_obs_id or str(plan["observation_id"])
            self._conn.execute(
                "INSERT INTO plan_verify_reports("
                "report_id, plan_id, job_id, observation_id, checks_json, "
                "overall_status, created_at"
                ") VALUES (?, ?, ?, ?, ?, ?, ?)",
                (new_id("pvr"), plan_id, job_id, report_obs_id, checks_json, overall, ts),
            )
        return overall

    def list_managed_resources(self, router_id: str) -> list[sqlite3.Row]:
        rows = self._conn.execute(
            "SELECT * FROM managed_resources WHERE router_id = ? "
            "ORDER BY resource_kind, logical_key",
            (router_id,),
        ).fetchall()
        return list(rows)

    def get_revision_state(self, router_id: str) -> dict[str, Any] | None:
        state = self._conn.execute(
            "SELECT * FROM router_revision_state WHERE router_id = ?", (router_id,)
        ).fetchone()
        if state is None:
            return None
        safety = self._conn.execute(
            "SELECT * FROM router_safety_sessions WHERE router_id = ?", (router_id,)
        ).fetchone()
        runtime = self.get_latest_evidence_revision(router_id, "runtime_applied")
        startup = self.get_latest_evidence_revision(router_id, "startup_saved")
        return {
            "router_id": router_id,
            "current_desired_revision_id": state["current_desired_revision_id"],
            "runtime_applied_revision_id": runtime["revision_id"] if runtime else None,
            "startup_saved_revision_id": startup["revision_id"] if startup else None,
            "verified_runtime_revision_id": (
                safety["verified_runtime_revision_id"] if safety else None
            ),
            "reconcile_status": "Pending",
        }

    # --- entry pages (migration 13) ---

    def _epoch_now(self, now: datetime | None = None) -> int:
        moment = now or datetime.now(UTC)
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=UTC)
        return int(moment.astimezone(UTC).timestamp())

    def _row_to_entry_page(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "page_id": str(row["page_id"]),
            "site_id": str(row["site_id"]),
            "audience": str(row["audience"]),
            "slug": str(row["slug"]),
            "current_revision_id": row["current_revision_id"],
            "published_revision_id": row["published_revision_id"],
            "created_at_epoch": int(row["created_at_epoch"]),
            "updated_at_epoch": int(row["updated_at_epoch"]),
        }

    def _row_to_entry_page_revision(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "revision_id": str(row["revision_id"]),
            "page_id": str(row["page_id"]),
            "revision_number": int(row["revision_number"]),
            "canonical_json": str(row["canonical_json"]),
            "content_sha256": str(row["content_sha256"]),
            "created_at_epoch": int(row["created_at_epoch"]),
        }

    def create_entry_page(
        self,
        *,
        site_id: str,
        audience: str,
        slug: str,
        now: datetime | None = None,
    ) -> str:
        epoch = self._epoch_now(now)
        page_id = new_id("epage")
        self._conn.execute(
            "INSERT INTO entry_pages("
            "page_id, site_id, audience, slug, current_revision_id, "
            "published_revision_id, created_at_epoch, updated_at_epoch"
            ") VALUES (?, ?, ?, ?, NULL, NULL, ?, ?)",
            (page_id, site_id, audience, slug, epoch, epoch),
        )
        return page_id

    def create_entry_page_resolving_conflict(
        self,
        *,
        site_id: str,
        audience: str,
        slug: str,
        now: datetime | None = None,
    ) -> str:
        try:
            return self.create_entry_page(
                site_id=site_id,
                audience=audience,
                slug=slug,
                now=now,
            )
        except sqlite3.IntegrityError as exc:
            raise EntryPageConflict(
                "entry page already exists for site and audience"
            ) from exc

    def get_entry_page(self, page_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM entry_pages WHERE page_id = ?", (page_id,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_entry_page(cast(sqlite3.Row, row))

    def get_entry_page_by_slug(self, slug: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM entry_pages WHERE slug = ?", (slug,)
        ).fetchone()
        if row is None:
            return None
        return self._row_to_entry_page(cast(sqlite3.Row, row))

    def find_entry_page_by_audience(
        self, site_id: str, audience: str
    ) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM entry_pages WHERE site_id = ? AND audience = ?",
            (site_id, audience),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_entry_page(cast(sqlite3.Row, row))

    def list_entry_pages(self, site_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM entry_pages WHERE site_id = ? ORDER BY audience ASC",
            (site_id,),
        ).fetchall()
        return [self._row_to_entry_page(cast(sqlite3.Row, row)) for row in rows]

    def append_entry_page_revision(
        self,
        *,
        page_id: str,
        canonical_json: str,
        content_sha256: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        with transaction(self._conn, immediate=True):
            page = self.get_entry_page(page_id)
            if page is None:
                raise NotFoundError("entry page not found")
            next_num_row = self._conn.execute(
                "SELECT COALESCE(MAX(revision_number), 0) AS m "
                "FROM entry_page_revisions WHERE page_id = ?",
                (page_id,),
            ).fetchone()
            next_num = int(next_num_row["m"]) + 1
            revision_id = new_id("epgrev")
            epoch = self._epoch_now(now)
            self._conn.execute(
                "INSERT INTO entry_page_revisions("
                "revision_id, page_id, revision_number, canonical_json, "
                "content_sha256, created_at_epoch"
                ") VALUES (?, ?, ?, ?, ?, ?)",
                (
                    revision_id,
                    page_id,
                    next_num,
                    canonical_json,
                    content_sha256,
                    epoch,
                ),
            )
            self._conn.execute(
                "UPDATE entry_pages SET current_revision_id = ?, updated_at_epoch = ? "
                "WHERE page_id = ?",
                (revision_id, epoch, page_id),
            )
            row = self._conn.execute(
                "SELECT * FROM entry_page_revisions WHERE revision_id = ?",
                (revision_id,),
            ).fetchone()
            assert row is not None
            return self._row_to_entry_page_revision(cast(sqlite3.Row, row))

    def get_entry_page_revision(
        self, page_id: str, revision_id: str
    ) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM entry_page_revisions WHERE revision_id = ?",
            (revision_id,),
        ).fetchone()
        if row is None:
            return None
        if str(row["page_id"]) != page_id:
            return None
        return self._row_to_entry_page_revision(cast(sqlite3.Row, row))

    def set_entry_page_published_revision(
        self,
        *,
        page_id: str,
        revision_id: str,
        now: datetime | None = None,
    ) -> None:
        with transaction(self._conn, immediate=True):
            page = self.get_entry_page(page_id)
            if page is None:
                raise NotFoundError("entry page not found")
            revision = self.get_entry_page_revision(page_id, revision_id)
            if revision is None:
                raise NotFoundError("revision not found for entry page")
            epoch = self._epoch_now(now)
            self._conn.execute(
                "UPDATE entry_pages SET published_revision_id = ?, updated_at_epoch = ? "
                "WHERE page_id = ?",
                (revision_id, epoch, page_id),
            )

    def clear_entry_page_published_revision(
        self,
        *,
        page_id: str,
        now: datetime | None = None,
    ) -> None:
        with transaction(self._conn, immediate=True):
            page = self.get_entry_page(page_id)
            if page is None:
                raise NotFoundError("entry page not found")
            epoch = self._epoch_now(now)
            self._conn.execute(
                "UPDATE entry_pages SET published_revision_id = NULL, updated_at_epoch = ? "
                "WHERE page_id = ?",
                (epoch, page_id),
            )

    # --- standing network preferences (migration 14) ---

    _STANDING_PREFS_ID = "default"

    def _row_to_standing_network_preferences(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "preferences_id": row["preferences_id"],
            "staff_ssid": row["staff_ssid"],
            "staff_password_credential_ref_id": row["staff_password_credential_ref_id"],
            "guest_default_ssid": row["guest_default_ssid"],
            "guest_default_enabled": bool(row["guest_default_enabled"]),
            "staff_ap_id": row["staff_ap_id"],
            "guest_ap_id": row["guest_ap_id"],
            "updated_at": row["updated_at"],
        }

    def get_standing_network_preferences(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT * FROM standing_network_preferences WHERE preferences_id = ?",
            (self._STANDING_PREFS_ID,),
        ).fetchone()
        if row is None:
            msg = "standing network preferences row missing"
            raise NotFoundError(msg)
        return self._row_to_standing_network_preferences(cast(sqlite3.Row, row))

    def seed_standing_network_preferences_defaults(self) -> None:
        """Idempotently (re)create the migration-14 default singleton row.

        Store-layer reads keep raising ``NotFoundError`` when the row is
        absent (pinned by test_get_standing_preferences_missing_row_raises);
        self-healing on absence is the application service's job, which calls
        this before retrying the read. ``INSERT OR IGNORE`` makes this a
        no-op if the row already exists (no read-then-write race).
        """
        self._conn.execute(
            "INSERT OR IGNORE INTO standing_network_preferences ("
            "preferences_id, staff_ssid, staff_password_credential_ref_id, "
            "guest_default_ssid, guest_default_enabled, updated_at"
            ") VALUES (?, ?, NULL, ?, 0, ?)",
            (
                self._STANDING_PREFS_ID,
                "Рабочая сеть",
                "Гостевая сеть",
                "1970-01-01T00:00:00+00:00",
            ),
        )

    def upsert_standing_network_preferences(
        self,
        *,
        staff_ssid: str | None = None,
        staff_password_credential_ref_id: str | None | object = _UNSET,
        guest_default_ssid: str | None = None,
        staff_ap_id: str | None | object = _UNSET,
        guest_ap_id: str | None | object = _UNSET,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = _utc_now_iso(now)
        current = self.get_standing_network_preferences()
        resolved_staff_ssid = (
            staff_ssid if staff_ssid is not None else str(current["staff_ssid"])
        )
        resolved_guest_ssid = (
            guest_default_ssid
            if guest_default_ssid is not None
            else str(current["guest_default_ssid"])
        )
        if staff_password_credential_ref_id is _UNSET:
            resolved_ref = current["staff_password_credential_ref_id"]
        else:
            resolved_ref = staff_password_credential_ref_id
        if staff_ap_id is _UNSET:
            resolved_staff_ap_id = current["staff_ap_id"]
        else:
            resolved_staff_ap_id = staff_ap_id
        if guest_ap_id is _UNSET:
            resolved_guest_ap_id = current["guest_ap_id"]
        else:
            resolved_guest_ap_id = guest_ap_id
        self._conn.execute(
            "UPDATE standing_network_preferences SET "
            "staff_ssid = ?, staff_password_credential_ref_id = ?, "
            "guest_default_ssid = ?, staff_ap_id = ?, guest_ap_id = ?, updated_at = ? "
            "WHERE preferences_id = ?",
            (
                resolved_staff_ssid,
                resolved_ref,
                resolved_guest_ssid,
                resolved_staff_ap_id,
                resolved_guest_ap_id,
                ts,
                self._STANDING_PREFS_ID,
            ),
        )
        return self.get_standing_network_preferences()

    # --- remembered uplink (migration 15) ---

    _REMEMBERED_UPLINK_ID = "default"

    def _row_to_remembered_uplink(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "preferences_id": row["preferences_id"],
            "router_id": row["router_id"],
            "mode": row["mode"],
            "ssid": row["ssid"],
            "band": row["band"],
            "station_id": row["station_id"],
            "credential_ref_id": row["credential_ref_id"],
            "desired_active": bool(row["desired_active"]),
            "updated_at": row["updated_at"],
        }

    def get_remembered_uplink(self) -> dict[str, Any]:
        row = self._conn.execute(
            "SELECT * FROM remembered_uplink WHERE preferences_id = ?",
            (self._REMEMBERED_UPLINK_ID,),
        ).fetchone()
        if row is None:
            msg = "remembered uplink row missing"
            raise NotFoundError(msg)
        return self._row_to_remembered_uplink(cast(sqlite3.Row, row))

    def upsert_remembered_uplink(
        self,
        *,
        router_id: str | None | object = _UNSET,
        mode: str | None = None,
        ssid: str | None = None,
        band: str | None = None,
        station_id: str | None | object = _UNSET,
        credential_ref_id: str | None | object = _UNSET,
        desired_active: bool | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        ts = _utc_now_iso(now)
        current = self.get_remembered_uplink()
        resolved_router_id = (
            router_id if router_id is not _UNSET else current["router_id"]
        )
        resolved_mode = mode if mode is not None else str(current["mode"])
        resolved_ssid = ssid if ssid is not None else str(current["ssid"])
        resolved_band = band if band is not None else str(current["band"])
        if station_id is _UNSET:
            resolved_station_id = current["station_id"]
        else:
            resolved_station_id = station_id
        if credential_ref_id is _UNSET:
            resolved_cred = current["credential_ref_id"]
        else:
            resolved_cred = credential_ref_id
        resolved_active = (
            desired_active
            if desired_active is not None
            else bool(current["desired_active"])
        )
        self._conn.execute(
            "UPDATE remembered_uplink SET "
            "router_id = ?, mode = ?, ssid = ?, band = ?, station_id = ?, "
            "credential_ref_id = ?, desired_active = ?, updated_at = ? "
            "WHERE preferences_id = ?",
            (
                resolved_router_id,
                resolved_mode,
                resolved_ssid,
                resolved_band,
                resolved_station_id,
                resolved_cred,
                1 if resolved_active else 0,
                ts,
                self._REMEMBERED_UPLINK_ID,
            ),
        )
        return self.get_remembered_uplink()

    def reset_remembered_uplink(self, *, now: datetime | None = None) -> dict[str, Any]:
        ts = _utc_now_iso(now)
        self._conn.execute(
            "UPDATE remembered_uplink SET "
            "router_id = NULL, mode = 'wifi', ssid = '', band = 'BAND_2_4GHZ', "
            "station_id = NULL, credential_ref_id = NULL, desired_active = 0, "
            "updated_at = ? WHERE preferences_id = ?",
            (ts, self._REMEMBERED_UPLINK_ID),
        )
        return self.get_remembered_uplink()


def _lock_store_method(fn: Any) -> Any:
    @wraps(fn)
    def wrapper(self: PersistenceStore, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            return fn(self, *args, **kwargs)

    return wrapper


_STORE_LOCK_SKIP = frozenset({"__init__", "conn"})

for _name, _attr in list(vars(PersistenceStore).items()):
    if _name.startswith("_") or _name in _STORE_LOCK_SKIP:
        continue
    if isinstance(_attr, property):
        continue
    if callable(_attr) and not isinstance(_attr, (staticmethod, classmethod)):
        setattr(PersistenceStore, _name, _lock_store_method(_attr))
