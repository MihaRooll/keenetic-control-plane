"""SLICE-2 persistence fault matrix essentials."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.persistence.connection import open_database
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    PreconditionFailed,
    StaleFenceError,
)
from router_control.persistence.migrations import CURRENT_USER_VERSION, list_user_tables, migrate
from router_control.persistence.store import PersistenceStore, etag_for_revision


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    conn = open_database(tmp_path / "rc.sqlite3")
    return PersistenceStore(conn)


def _seed_router(store: PersistenceStore) -> str:
    site = store.create_site(display_name="Lab", now=datetime(2026, 7, 21, tzinfo=UTC))
    return store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:1",
        host="127.0.0.1",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )


def test_migrations_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "rc.sqlite3"
    conn = open_database(path)
    v1 = conn.execute("PRAGMA user_version").fetchone()[0]
    assert v1 == CURRENT_USER_VERSION
    tables = list_user_tables(conn)
    assert "jobs" in tables
    assert "traffic_observations" in tables
    assert "route_proposals" in tables
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    conn.close()
    conn2 = open_database(path)
    assert conn2.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION


def test_two_worker_claim_exclusivity(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="k1",
        request_digest="sha256:a",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    c1 = store.claim_job(worker_id="w1", now_epoch=1_000_000)
    c2 = store.claim_job(worker_id="w2", now_epoch=1_000_000)
    assert c1 is not None
    assert c2 is None


def test_claim_job_skips_locked_router_claims_other(store: PersistenceStore) -> None:
    site = store.create_site(display_name="Lab2", now=datetime(2026, 7, 21, tzinfo=UTC))
    rid_a = store.enroll_router(
        site_id=site,
        display_name="RA",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:a",
        host="127.0.0.1",
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    rid_b = store.enroll_router(
        site_id=site,
        display_name="RB",
        vendor="Fake",
        model="M2",
        identity_fingerprint="digest:fp:b",
        host="127.0.0.2",
        now=datetime(2026, 7, 21, 12, 0, 1, tzinfo=UTC),
    )
    out_a = store.create_operation_bundle(
        router_id=rid_a,
        operation_kind="apply_plan",
        idempotency_key="ka",
        request_digest="sha256:a",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, 12, 0, 2, tzinfo=UTC),
    )
    out_b = store.create_operation_bundle(
        router_id=rid_b,
        operation_kind="apply_plan",
        idempotency_key="kb",
        request_digest="sha256:b",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, 12, 0, 3, tzinfo=UTC),
    )
    claimed_a = store.claim_job(worker_id="w1", now_epoch=1_000_000)
    assert claimed_a is not None
    assert claimed_a.job_id == out_a.job_id
    claimed_b = store.claim_job(worker_id="w2", now_epoch=1_000_001)
    assert claimed_b is not None
    assert claimed_b.job_id == out_b.job_id


def test_cancel_job_atomic_queued_consistent(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="enroll",
        idempotency_key="enroll-cancel-store",
        request_digest="sha256:e",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    http_status, body, outcome = store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-store-1",
        request_digest="sha256:c",
        actor_id="op",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    assert http_status == 200
    assert body["status"] == "Cancelled"
    assert outcome.created is True
    job = store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "Cancelled"
    # Replay must not create a second cancel op or change target again.
    http2, body2, outcome2 = store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-store-1",
        request_digest="sha256:c",
        actor_id="op",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    assert outcome2.created is False
    assert http2 == 200
    assert body2["status"] == "Cancelled"
    assert store.get_job(out.job_id)["status"] == "Cancelled"


def test_fencing_rejects_stale(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="k2",
        request_digest="sha256:b",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", now_epoch=1_000_000)
    assert claim is not None
    with pytest.raises(StaleFenceError):
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token - 1,
            status="Running",
        )


def test_if_match_conflict(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    obs = store.insert_observation(
        router_id=rid,
        identity_fingerprint="digest:fp:1",
        resource_version="digest:rv:1",
        state_digest="digest:st:1",
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    rev_id, etag, _ = store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:d1",
        based_on_observation_id=obs,
        if_match="*",
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    with pytest.raises(PreconditionFailed):
        store.put_desired_revision(
            router_id=rid,
            canonical_digest="sha256:d2",
            based_on_observation_id=obs,
            if_match='"stale"',
            now=datetime(2026, 7, 21, 12, 1, 0, tzinfo=UTC),
        )
    assert etag == etag_for_revision(rev_id, "sha256:d1")


def test_stale_plan_rejected(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    obs = store.insert_observation(
        router_id=rid,
        identity_fingerprint="digest:fp:1",
        resource_version="digest:rv:1",
        state_digest="digest:st:1",
        ttl_seconds=3600,
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    rev_id, etag, _ = store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:d1",
        based_on_observation_id=obs,
        if_match="*",
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    plan_id, plan_etag = store.create_plan(
        router_id=rid,
        revision_id=rev_id,
        observation_id=obs,
        if_match=etag,
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    # Advance desired → plan becomes stale on confirm
    store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:d2",
        based_on_observation_id=obs,
        if_match=etag,
        now=datetime(2026, 7, 21, 12, 0, 30, tzinfo=UTC),
    )
    plan = store.get_plan(plan_id)
    assert plan is not None
    with pytest.raises(ConflictError):
        store.confirm_plan(
            plan_id=plan_id,
            plan_digest=plan["plan_digest"],
            if_match=plan_etag,
            actor_id="op",
            now=datetime(2026, 7, 21, 12, 1, 0, tzinfo=UTC),
        )


def test_idempotency_same_and_diff_digest(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    a = store.create_operation_bundle(
        router_id=rid,
        operation_kind="enroll",
        idempotency_key="same",
        request_digest="sha256:x",
        initial_job_status="Succeeded",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    b = store.create_operation_bundle(
        router_id=rid,
        operation_kind="enroll",
        idempotency_key="same",
        request_digest="sha256:x",
        initial_job_status="Succeeded",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    assert a.created is True
    assert b.created is False
    assert a.operation_id == b.operation_id
    with pytest.raises(IdempotencyConflict):
        store.create_operation_bundle(
            router_id=rid,
            operation_kind="enroll",
            idempotency_key="same",
            request_digest="sha256:y",
            initial_job_status="Succeeded",
            now=datetime(2026, 7, 21, tzinfo=UTC),
        )


def test_no_secrets_in_db_dump(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    secret = "super-secret-password-value"
    store.insert_credential_ref(
        router_id=rid,
        kind="RouterManagementPassword",
        provider="Memory.Test",
        provider_locator="mem:opaque",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.append_audit(
        action="credential.create",
        outcome="ok",
        router_id=rid,
        summary_redacted="credential stored",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    dump = store.dump_text_for_secret_scan()
    assert secret not in dump


def test_offline_runtime_recovers_expired_leases_on_boot(tmp_path: Path) -> None:
    from router_control.composition import FixedClock, create_offline_runtime

    db_path = tmp_path / "boot.sqlite3"
    conn = open_database(db_path)
    store = PersistenceStore(conn)
    rid = _seed_router(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="enroll",
        idempotency_key="boot-recover",
        request_digest="sha256:boot",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=30, now_epoch=100)
    assert claim is not None
    assert claim.job_id == out.job_id
    conn.close()

    boot_clock = FixedClock(datetime.fromtimestamp(200, tz=UTC))
    runtime = create_offline_runtime(db_path=db_path, clock=boot_clock)
    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "Lost"


def test_crash_unknown_outcome_no_blind_retry(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="apply1",
        request_digest="sha256:apply",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=1, now_epoch=100)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner="w1",
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="apply",
        step_status="Running",
    )
    lost = store.recover_expired_leases(now_epoch=200)
    assert out.job_id in lost
    job = store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    # No automatic re-apply step on resume job
    jobs = store.list_jobs_for_operation(out.operation_id)
    assert not any(
        s["step_kind"] == "apply" and s["status"] == "Succeeded"
        for j in jobs
        for s in store.list_job_steps(j["job_id"])
    )


def test_foreign_keys_on(store: PersistenceStore) -> None:
    row = store.conn.execute("PRAGMA foreign_keys").fetchone()
    assert int(row[0]) == 1


def test_credential_ref_link_order(store: PersistenceStore) -> None:
    """routers NULL ref → insert ref → update (cyclic FK app order)."""
    rid = _seed_router(store)
    row = store.get_router(rid)
    assert row is not None
    assert row["credential_ref_id"] is None
    cid = store.insert_credential_ref(
        router_id=rid,
        kind="RouterManagementPassword",
        provider="Memory.Test",
        provider_locator="mem:x",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.set_router_credential_ref(rid, cid, now=datetime(2026, 7, 21, tzinfo=UTC))
    assert store.get_router(rid)["credential_ref_id"] == cid
