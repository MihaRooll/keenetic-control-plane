"""Persistence store: sites/routers, revisions, plans, ops/jobs, audit, traffic."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from router_control.persistence.connection import transaction
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PreconditionFailed,
    StaleFenceError,
)
from router_control.persistence.ids import new_id


def _utc_now_iso(now: datetime | None = None) -> str:
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _digest(payload: str) -> str:
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def etag_for_revision(revision_id: str, canonical_digest: str) -> str:
    return f'"{revision_id}:{canonical_digest}"'


def etag_for_plan(plan_id: str, plan_digest: str) -> str:
    return f'"{plan_id}:{plan_digest}"'


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


class PersistenceStore:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    @property
    def conn(self) -> sqlite3.Connection:
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
            "created_at, updated_at"
            ") VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)",
            (new_id("ep"), rid, kind, host, port, ts, ts),
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

    def list_routers(self, *, limit: int = 50) -> list[sqlite3.Row]:
        return list(
            self._conn.execute(
                "SELECT * FROM routers ORDER BY created_at DESC LIMIT ?", (limit,)
            ).fetchall()
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
        now: datetime | None = None,
    ) -> IdempotencyOutcome:
        """Atomic §6 bundle: lookup → ops + idempotency + job + audit."""
        with transaction(self._conn, immediate=True):
            return self._create_operation_bundle_unlocked(
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
                initial_job_status="Queued",
                match_without_router_id=True,
                now=moment,
            )
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
            # Keep InProgress (async accept); only persist replayable HTTP body.
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
        epoch = now_epoch if now_epoch is not None else int((now or datetime.now(UTC)).timestamp())
        ts = _utc_now_iso(now)
        with transaction(self._conn, immediate=True):
            candidates = self._conn.execute(
                "SELECT j.job_id, j.router_id, j.fencing_token, o.operation_kind "
                "FROM jobs j JOIN operations o ON o.operation_id = j.operation_id "
                "WHERE j.status = 'Queued' "
                "ORDER BY j.created_at"
            ).fetchall()
            for row in candidates:
                job_id = row["job_id"]
                router_id = row["router_id"]
                if row["operation_kind"] in self._MUTATION_OPERATION_KINDS:
                    lock = self._conn.execute(
                        "SELECT * FROM router_mutation_locks WHERE router_id = ?",
                        (router_id,),
                    ).fetchone()
                    if lock and lock["active_job_id"] is not None:
                        active = self.get_job(lock["active_job_id"])
                        if active and active["status"] in ("Leased", "Running"):
                            continue
                new_fence = int(row["fencing_token"]) + 1
                lease_until = epoch + lease_seconds
                updated = self._conn.execute(
                    "UPDATE jobs SET status = 'Leased', lease_owner = ?, lease_until_epoch = ?, "
                    "fencing_token = ?, heartbeat_at = ?, updated_at = ?, "
                    "started_at = COALESCE(started_at, ?) "
                    "WHERE job_id = ? AND status = 'Queued'",
                    (worker_id, lease_until, new_fence, ts, ts, ts, job_id),
                )
                if updated.rowcount != 1:
                    continue
                if row["operation_kind"] in self._MUTATION_OPERATION_KINDS:
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
            return None

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
        now: datetime | None = None,
    ) -> None:
        ts = _utc_now_iso(now)
        job = self.get_job(job_id)
        if job is None:
            raise NotFoundError("job not found")
        if job["lease_owner"] != lease_owner or int(job["fencing_token"]) != fencing_token:
            raise StaleFenceError("stale fencing token or lease owner")
        if status is not None:
            self._conn.execute(
                "UPDATE jobs SET status = ?, updated_at = ? WHERE job_id = ? "
                "AND lease_owner = ? AND fencing_token = ?",
                (status, ts, job_id, lease_owner, fencing_token),
            )
            if self._conn.execute("SELECT changes()").fetchone()[0] != 1:
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
                "started_at, finished_at"
                ") VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
                (
                    new_id("step"),
                    job_id,
                    ordinal,
                    step_kind,
                    step_status,
                    checkpoint_json,
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
            except (json.JSONDecodeError, TypeError):
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

    def recover_expired_leases(
        self, *, now_epoch: int | None = None, now: datetime | None = None
    ) -> list[str]:
        """Mark Leased/Running with expired lease as Lost; return job_ids. No blind retry."""
        epoch = now_epoch if now_epoch is not None else int((now or datetime.now(UTC)).timestamp())
        ts = _utc_now_iso(now)
        lost_ids: list[str] = []
        with transaction(self._conn, immediate=True):
            rows = self._conn.execute(
                "SELECT job_id, router_id FROM jobs "
                "WHERE status IN ('Leased', 'Running') AND lease_until_epoch IS NOT NULL "
                "AND lease_until_epoch < ?",
                (epoch,),
            ).fetchall()
            for row in rows:
                # Check if apply step may have run — if so RecoveryRequired, else Lost + resume hook
                apply_step = self._conn.execute(
                    "SELECT step_id, status FROM job_steps "
                    "WHERE job_id = ? AND step_kind = 'apply' LIMIT 1",
                    (row["job_id"],),
                ).fetchone()
                if apply_step is not None and apply_step["status"] in (
                    "Running",
                    "Succeeded",
                ):
                    new_status = "RecoveryRequired"
                else:
                    new_status = "Lost"
                self._conn.execute(
                    "UPDATE jobs SET status = ?, lease_owner = NULL, updated_at = ?, "
                    "finished_at = ?, recovery_state = 'expired_lease' WHERE job_id = ?",
                    (new_status, ts, ts, row["job_id"]),
                )
                self._conn.execute(
                    "UPDATE router_mutation_locks SET active_job_id = NULL, lock_owner = NULL, "
                    "lock_until_epoch = NULL, updated_at = ? WHERE active_job_id = ?",
                    (ts, row["job_id"]),
                )
                lost_ids.append(row["job_id"])
                if new_status == "Lost":
                    # Resume hook: new Queued attempt — never re-dispatch apply blindly
                    op = self._conn.execute(
                        "SELECT operation_id FROM jobs WHERE job_id = ?",
                        (row["job_id"],),
                    ).fetchone()
                    if op:
                        attempt_row = self._conn.execute(
                            "SELECT MAX(attempt) AS m FROM jobs WHERE operation_id = ?",
                            (op["operation_id"],),
                        ).fetchone()
                        next_attempt = int(attempt_row["m"]) + 1
                        self._conn.execute(
                            "INSERT INTO jobs("
                            "job_id, operation_id, router_id, attempt, status, fencing_token, "
                            "cancel_requested, recovery_state, created_at, updated_at"
                            ") VALUES (?, ?, ?, ?, 'Queued', 0, 0, 'resume_after_lost', ?, ?)",
                            (
                                new_id("job"),
                                op["operation_id"],
                                row["router_id"],
                                next_attempt,
                                ts,
                                ts,
                            ),
                        )
        return lost_ids

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
        now: datetime | None = None,
    ) -> str:
        aid = new_id("aud")
        self._conn.execute(
            "INSERT INTO audit_events("
            "audit_event_id, occurred_at, actor_type, actor_id, router_id, "
            "operation_id, job_id, plan_id, action, outcome, summary_redacted"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                aid,
                _utc_now_iso(now),
                actor_type,
                actor_id,
                router_id,
                operation_id,
                job_id,
                plan_id,
                action,
                outcome,
                summary_redacted,
            ),
        )
        return aid

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
                "SELECT * FROM vpn_profile_artifacts WHERE profile_id = ?",
                (profile_id,),
            ).fetchone(),
        )

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
        """Concatenate text columns for secret-scan tests (redacted domain fields only)."""
        chunks: list[str] = []
        for table in (
            "credential_refs",
            "audit_events",
            "change_plans",
            "jobs",
            "operations",
            "idempotency_records",
            "desired_revisions",
        ):
            rows = self._conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
            for row in rows:
                chunks.append("|".join(str(v) for v in tuple(row) if v is not None))
        return "\n".join(chunks)
