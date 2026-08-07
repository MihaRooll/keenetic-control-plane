"""SLICE-2 persistence fault matrix essentials."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.persistence.connection import open_database
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PreconditionFailed,
    StaleFenceError,
)
from router_control.persistence.migrations import CURRENT_USER_VERSION, list_user_tables, migrate
from router_control.persistence.store import (
    _SECRET_SCAN_TABLES,
    PersistenceStore,
    etag_for_revision,
    secret_scan_table_columns,
)

_CLAIM_JOB_CANDIDATE_BATCH_SIZE = 64


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


def test_enroll_router_source_address_round_trip(store: PersistenceStore) -> None:
    site = store.create_site(display_name="Lab", now=datetime(2026, 7, 21, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site,
        display_name="R-src",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:src",
        host="192.168.1.1",
        source_address="192.168.1.144",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    row = store._conn.execute(
        "SELECT source_address FROM router_endpoints WHERE router_id = ?",
        (router_id,),
    ).fetchone()
    assert row is not None
    assert row[0] == "192.168.1.144"


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


def test_claim_job_pages_past_skipped_locked_batch(store: PersistenceStore) -> None:
    """FIFO claim must page beyond _CLAIM_JOB_CANDIDATE_BATCH_SIZE skipped rows."""
    site = store.create_site(display_name="BatchLab", now=datetime(2026, 7, 21, tzinfo=UTC))
    rid_locked = store.enroll_router(
        site_id=site,
        display_name="Locked",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:locked",
        host="127.0.0.1",
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    rid_free = store.enroll_router(
        site_id=site,
        display_name="Free",
        vendor="Fake",
        model="M2",
        identity_fingerprint="digest:fp:free",
        host="127.0.0.2",
        now=datetime(2026, 7, 21, 12, 0, 1, tzinfo=UTC),
    )
    lock_out = store.create_operation_bundle(
        router_id=rid_locked,
        operation_kind="apply_plan",
        idempotency_key="lock-active",
        request_digest="sha256:lock",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, 12, 0, 2, tzinfo=UTC),
    )
    assert store.claim_job(worker_id="w-lock", now_epoch=1_000_000) is not None
    assert store.get_job(lock_out.job_id)["status"] == "Leased"

    base = datetime(2026, 7, 21, 12, 1, 0, tzinfo=UTC)
    for i in range(70):
        store.create_operation_bundle(
            router_id=rid_locked,
            operation_kind="apply_plan",
            idempotency_key=f"blocked-{i}",
            request_digest=f"sha256:blocked-{i}",
            initial_job_status="Queued",
            now=base.replace(second=min(59, i % 60), microsecond=i),
        )
    free_out = store.create_operation_bundle(
        router_id=rid_free,
        operation_kind="apply_plan",
        idempotency_key="free-job",
        request_digest="sha256:free",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, 12, 2, 0, tzinfo=UTC),
    )
    claimed = store.claim_job(worker_id="w-free", now_epoch=1_000_001)
    assert claimed is not None
    assert claimed.job_id == free_out.job_id


def test_claim_job_rescans_when_full_batch_locks_release(store: PersistenceStore) -> None:
    """After a full lock-blocked batch, rescan claims FIFO once the router lock clears."""
    site = store.create_site(display_name="RescanLab", now=datetime(2026, 7, 21, tzinfo=UTC))
    rid_locked = store.enroll_router(
        site_id=site,
        display_name="LockedRouter",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:rescan-locked",
        host="127.0.0.1",
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    lock_out = store.create_operation_bundle(
        router_id=rid_locked,
        operation_kind="apply_plan",
        idempotency_key="active-lock",
        request_digest="sha256:active-lock",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, 12, 0, 1, tzinfo=UTC),
    )
    active_claim = store.claim_job(worker_id="w-active", now_epoch=1_000_000)
    assert active_claim is not None
    assert store.get_job(lock_out.job_id)["status"] == "Leased"

    base = datetime(2026, 7, 21, 12, 1, 0, tzinfo=UTC)
    for i in range(_CLAIM_JOB_CANDIDATE_BATCH_SIZE):
        store.create_operation_bundle(
            router_id=rid_locked,
            operation_kind="apply_plan",
            idempotency_key=f"blocked-rescan-{i}",
            request_digest=f"sha256:blocked-rescan-{i}",
            initial_job_status="Queued",
            now=base + timedelta(seconds=i),
        )

    fifo_first = store._conn.execute(
        "SELECT job_id FROM jobs WHERE status = 'Queued' ORDER BY created_at, job_id LIMIT 1"
    ).fetchone()
    assert fifo_first is not None

    store.complete_job(
        job_id=lock_out.job_id,
        lease_owner=active_claim.lease_owner,
        fencing_token=active_claim.fencing_token,
        status="Succeeded",
        now_epoch=1_000_001,
    )

    claimed = store.claim_job(worker_id="w-rescan", now_epoch=1_000_002)
    assert claimed is not None
    assert claimed.job_id == fifo_first["job_id"]


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


def test_wifi_ap_psk_put_leaves_router_credential_ref_unchanged(
    store: PersistenceStore,
) -> None:
    rid = _seed_router(store)
    mgmt_id = store.insert_credential_ref(
        router_id=rid,
        kind="RouterManagementPassword",
        provider="Memory.Test",
        provider_locator="mem:mgmt",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.set_router_credential_ref(rid, mgmt_id, now=datetime(2026, 7, 21, tzinfo=UTC))
    outcome = store.put_credential_with_operation(
        router_id=rid,
        credential_ref_id="credref:wifi-ap-psk",
        kind="WifiApPsk",
        provider="Memory.Test",
        provider_locator="mem:wifi",
        idempotency_key="put-wifi-psk",
        request_digest="sha256:wifi-psk",
        actor_id="test",
        response_body={"kind": "WifiApPsk", "created_at": "2026-07-21T00:00:00Z"},
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    assert outcome.created
    row = store.get_router(rid)
    assert row is not None
    assert row["credential_ref_id"] == mgmt_id


def test_router_management_password_put_rebinds_router_credential_ref(
    store: PersistenceStore,
) -> None:
    rid = _seed_router(store)
    initial_mgmt_id = store.insert_credential_ref(
        router_id=rid,
        kind="RouterManagementPassword",
        provider="Memory.Test",
        provider_locator="mem:initial",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.set_router_credential_ref(rid, initial_mgmt_id, now=datetime(2026, 7, 21, tzinfo=UTC))
    outcome = store.put_credential_with_operation(
        router_id=rid,
        credential_ref_id="credref:new-mgmt",
        kind="RouterManagementPassword",
        provider="Memory.Test",
        provider_locator="mem:new-mgmt",
        idempotency_key="put-mgmt",
        request_digest="sha256:mgmt",
        actor_id="test",
        response_body={
            "kind": "RouterManagementPassword",
            "created_at": "2026-07-21T00:00:00Z",
        },
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    assert outcome.created
    row = store.get_router(rid)
    assert row is not None
    assert row["credential_ref_id"] != initial_mgmt_id
    assert row["credential_ref_id"] is not None


def _legacy_dump_text_for_secret_scan(store: PersistenceStore) -> str:
    """Pre-optimization reference: ``SELECT *`` + ``fetchall`` over scan tables."""
    chunks: list[str] = []
    for table in _SECRET_SCAN_TABLES:
        rows = store.conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
        for row in rows:
            chunks.append("|".join(str(v) for v in tuple(row) if v is not None))
    return "\n".join(chunks)


def test_secret_scan_columns_match_live_schema(store: PersistenceStore) -> None:
    """Guard: scan column set must equal ``PRAGMA table_info`` for every scan table."""
    for table in _SECRET_SCAN_TABLES:
        pragma_cols = tuple(
            str(row[1])
            for row in store.conn.execute(f'PRAGMA table_info("{table}")').fetchall()
        )
        scan_cols = secret_scan_table_columns(store.conn, table)
        assert scan_cols == pragma_cols, (
            f"{table}: secret scan columns {scan_cols!r} != schema {pragma_cols!r}"
        )


def test_secret_scan_finds_marker_in_session_binding_hmac(store: PersistenceStore) -> None:
    """Regression: migration-5 ``change_plans.session_binding_hmac`` must be scanned."""
    marker = "canary-secret-scan-session-binding-hmac-marker"
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
    plan_id, _ = store.create_plan(
        router_id=rid,
        revision_id=rev_id,
        observation_id=obs,
        if_match=etag,
        now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
    )
    store.conn.execute(
        "UPDATE change_plans SET session_binding_hmac = ? WHERE plan_id = ?",
        (marker, plan_id),
    )
    dump = store.dump_text_for_secret_scan()
    assert marker in dump


def test_secret_scan_dump_streaming_equivalent_to_legacy_select_star(
    store: PersistenceStore,
) -> None:
    rid = _seed_router(store)
    store.insert_credential_ref(
        router_id=rid,
        kind="RouterManagementPassword",
        provider="Memory.Test",
        provider_locator="mem:opaque",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="secret-scan-equiv",
        request_digest="sha256:equiv",
        initial_job_status="Queued",
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    store.append_audit(
        action="operation.create",
        outcome="ok",
        router_id=rid,
        summary_redacted='{"route":"/wifi/preview","intent":{"ssid":"Lab"}}',
        now=datetime(2026, 7, 21, tzinfo=UTC),
    )
    assert store.dump_text_for_secret_scan() == _legacy_dump_text_for_secret_scan(store)


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


def test_unknown_boot_blocks_readiness(store: PersistenceStore) -> None:
    from router_control.persistence.errors import UnknownBootError

    rid = _seed_router(store)
    with pytest.raises(UnknownBootError):
        store.assert_router_boot_known(rid)
    store.record_router_boot_observation(
        router_id=rid,
        boot_id="boot-1",
        boot_known=True,
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    store.assert_router_boot_known(rid)


def test_evidence_revisions_runtime_vs_startup(store: PersistenceStore) -> None:
    from router_control.domain.enums import EvidenceKind

    rid = _seed_router(store)
    store.record_evidence_revision(
        router_id=rid,
        evidence_kind=EvidenceKind.RUNTIME_APPLIED.value,
        digest="sha256:runtime:1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    store.record_evidence_revision(
        router_id=rid,
        evidence_kind=EvidenceKind.STARTUP_SAVED.value,
        digest="sha256:startup:1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    runtime = store.get_latest_evidence_revision(
        rid, EvidenceKind.RUNTIME_APPLIED.value
    )
    startup = store.get_latest_evidence_revision(
        rid, EvidenceKind.STARTUP_SAVED.value
    )
    assert runtime is not None and runtime["digest"] == "sha256:runtime:1"
    assert startup is not None and startup["digest"] == "sha256:startup:1"


_TEST_SEALED_APPLY_LEASE_OWNER = "persistence-test-lease-owner"


def test_sealed_apply_audit_summary_and_list(store: PersistenceStore) -> None:
    from router_control.persistence.store import (
        build_sealed_apply_audit_summary,
        sealed_apply_request_digest,
    )

    intent = {"ap_id": "WifiMaster0/AccessPoint3", "credential_ref_id": "credref:staff"}
    summary = build_sealed_apply_audit_summary(
        route="wifi",
        verb="apply",
        intent_redacted=intent,
        result_payload={"overall": "applied", "steps": []},
    )
    parsed = json.loads(summary)
    assert parsed["route"] == "wifi"
    assert parsed["result"]["overall"] == "applied"
    assert "ssid" not in parsed["intent"]
    digest = sealed_apply_request_digest(intent)
    assert digest.startswith("sha256:")

    store.try_append_sealed_apply_audit(
        action="sealed_apply.wifi.apply",
        outcome="applied",
        route="wifi",
        verb="apply",
        intent_redacted=intent,
        result_payload={"overall": "applied"},
    )
    events = store.list_audit_events(action_prefix="sealed_apply.wifi")
    assert len(events) == 1
    assert events[0]["request_digest"] == digest


def test_sealed_apply_audit_scrubs_service_error_message(store: PersistenceStore) -> None:
    from router_control.persistence.store import (
        build_sealed_apply_audit_summary,
        redact_sealed_apply_audit_error_message,
    )

    marker = "MARKER-EXCEPTION-SECRET-PSK-VALUE"
    raw = f"step failed password={marker}"
    scrubbed = redact_sealed_apply_audit_error_message(raw)
    assert scrubbed is not None
    assert marker not in scrubbed
    assert scrubbed == "[REDACTED:error_message]"
    summary = build_sealed_apply_audit_summary(
        route="wifi",
        verb="apply",
        intent_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        error_message=raw,
    )
    parsed = json.loads(summary)
    assert marker not in json.dumps(parsed)
    assert "error_message" in parsed


def test_sealed_apply_audit_untrusted_exception_omits_message(store: PersistenceStore) -> None:
    from router_control.persistence.store import build_sealed_apply_audit_summary

    marker = "MARKER-EXCEPTION-SECRET-PSK-VALUE"
    summary = build_sealed_apply_audit_summary(
        route="wifi",
        verb="apply",
        intent_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        exception_type="RuntimeError",
    )
    parsed = json.loads(summary)
    assert parsed["exception_type"] == "RuntimeError"
    assert "error_message" not in parsed
    assert marker not in summary


def test_sealed_apply_audit_includes_trail_on_error(store: PersistenceStore) -> None:
    from router_control.persistence.store import build_sealed_apply_audit_summary

    intent = {"ap_id": "WifiMaster0/AccessPoint3"}
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted=intent,
        ops_planned_redacted=("set_ssid", "set_wpa_psk"),
        correlation_id="corr-trail-test",
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
    )
    store.record_sealed_apply_op_progress(
        run_id, "set_ssid", lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER
    )
    trail = store.get_sealed_apply_trail_snapshot_for_audit(
        correlation_id="corr-trail-test",
        route="wifi",
        verb="apply",
    )
    assert trail is not None
    assert trail["apply_dispatched"] is True
    assert trail["ops_dispatched_redacted"] == ["set_ssid"]
    summary = build_sealed_apply_audit_summary(
        route="wifi",
        verb="apply",
        intent_redacted=intent,
        exception_type="RuntimeError",
        trail_snapshot=trail,
    )
    parsed = json.loads(summary)
    assert parsed["trail"]["ops_dispatched_redacted"] == ["set_ssid"]


def test_sealed_apply_trail_apply_dispatched_facts_not_checkpoint() -> None:
    """Empty dispatched list must not be overridden by checkpoint apply_dispatched=true."""
    import sqlite3

    from router_control.persistence.store import build_sealed_apply_trail_snapshot_for_audit

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE sealed_apply_runs (
            run_id TEXT,
            status TEXT,
            ops_planned_redacted TEXT,
            ops_pending_redacted TEXT,
            ops_dispatched_redacted TEXT,
            checkpoint_json TEXT,
            overall TEXT
        )
        """
    )
    conn.execute(
        "INSERT INTO sealed_apply_runs VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            "run-facts-first",
            "Running",
            json.dumps(["set_ssid"]),
            json.dumps(["set_ssid"]),
            json.dumps([]),
            json.dumps({"apply_dispatched": True, "phase": "dispatch"}),
            None,
        ),
    )
    row = conn.execute("SELECT * FROM sealed_apply_runs").fetchone()
    trail = build_sealed_apply_trail_snapshot_for_audit(row)
    assert trail["apply_dispatched"] is False
    assert trail["ops_dispatched_redacted"] == []
    assert trail["checkpoint_apply_dispatched"] is True


def test_sealed_apply_run_store_roundtrip(store: PersistenceStore) -> None:
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3", "ssid": "Lab"},
        ops_planned_redacted=("set_ssid", "set_wpa_psk"),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
    )
    store.record_sealed_apply_op_progress(
        run_id, "set_ssid", lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER
    )
    unfinished = store.list_unfinished_sealed_applies()
    assert len(unfinished) == 1
    assert unfinished[0]["run_id"] == run_id
    assert unfinished[0]["status"] == "Running"
    dispatched = json.loads(str(unfinished[0]["ops_dispatched_redacted"]))
    assert dispatched == ["set_ssid"]
    store.finish_sealed_apply_run(
        run_id,
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        status="Succeeded",
        overall="applied",
    )
    assert store.list_unfinished_sealed_applies() == []
    store.begin_sealed_apply_run(
        route="wifi",
        verb="teardown",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        ops_planned_redacted=("down",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
    )
    store.conn.execute(
        "UPDATE sealed_apply_runs SET lease_until_epoch = 0 WHERE status = 'Running'"
    )
    assert store.interrupt_stale_sealed_apply_runs(now_epoch=100) == 1
    interrupted = store.list_unfinished_sealed_applies()
    assert len(interrupted) == 1
    assert interrupted[0]["status"] == "Interrupted"


def test_sealed_apply_begin_unknown_router_id_stores_null(store: PersistenceStore) -> None:
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        ops_planned_redacted=("set_ssid",),
        router_id="rtr-does-not-exist",
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
    )
    row = store.conn.execute(
        "SELECT router_id FROM sealed_apply_runs WHERE run_id = ?", (run_id,)
    ).fetchone()
    assert row is not None
    assert row["router_id"] is None


def test_sealed_apply_op_intent_renews_lease_atomically_with_owner_guard(
    store: PersistenceStore,
) -> None:
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        ops_planned_redacted=("set_ssid",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now_epoch=1000,
        lease_seconds=30,
    )
    before = store.conn.execute(
        "SELECT ops_pending_redacted, lease_until_epoch FROM sealed_apply_runs "
        "WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert before is not None
    assert json.loads(str(before["ops_pending_redacted"])) == []

    store.record_sealed_apply_op_intent(
        run_id,
        "set_ssid",
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now_epoch=1025,
    )
    after = store.conn.execute(
        "SELECT ops_pending_redacted, lease_until_epoch FROM sealed_apply_runs "
        "WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert after is not None
    assert json.loads(str(after["ops_pending_redacted"])) == ["set_ssid"]
    assert int(after["lease_until_epoch"]) == 1055
    assert int(after["lease_until_epoch"]) > int(before["lease_until_epoch"])

    with pytest.raises(NotFoundError):
        store.record_sealed_apply_op_intent(
            run_id,
            "set_wpa_psk",
            lease_owner="wrong-owner",
            now_epoch=1030,
        )
    unchanged = store.conn.execute(
        "SELECT ops_pending_redacted FROM sealed_apply_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert unchanged is not None
    assert json.loads(str(unchanged["ops_pending_redacted"])) == ["set_ssid"]


def test_sealed_apply_lease_survives_settle_wait(store: PersistenceStore) -> None:
    from router_control.application.recovery import (
        SealedApplyTrailHandle,
        sleep_preserving_sealed_apply_lease,
    )

    run_id = store.begin_sealed_apply_run(
        route="wifi.station",
        verb="apply",
        intent_summary_redacted={"station_id": "WifiMaster0/WifiStation0"},
        ops_planned_redacted=("up",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now_epoch=1000,
        lease_seconds=30,
    )
    handle = SealedApplyTrailHandle(
        store=store,
        run_id=run_id,
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
    )
    clock = {"epoch": 1000}

    def _advance_sleep(seconds: float) -> None:
        clock["epoch"] += int(seconds)

    sleep_preserving_sealed_apply_lease(
        handle,
        25.0,
        _advance_sleep,
        renew_now_epoch=lambda: clock["epoch"],
    )
    assert store.interrupt_stale_sealed_apply_runs(now_epoch=1024) == 0
    assert store.interrupt_stale_sealed_apply_runs(now_epoch=1056) == 1


def test_f5_sleep_preserving_lease_fails_closed_on_renew_error(
    store: PersistenceStore,
) -> None:
    from router_control.application.recovery import (
        SealedApplyTrailHandle,
        sleep_preserving_sealed_apply_lease,
    )
    from router_control.persistence.errors import NotFoundError

    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        ops_planned_redacted=("set_ssid",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now_epoch=1000,
        lease_seconds=30,
    )
    handle = SealedApplyTrailHandle(
        store=store,
        run_id=run_id,
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
    )
    store.conn.execute(
        "UPDATE sealed_apply_runs SET lease_owner = NULL WHERE run_id = ?",
        (run_id,),
    )
    with pytest.raises(NotFoundError):
        sleep_preserving_sealed_apply_lease(
            handle,
            25.0,
            lambda seconds: None,
            renew_now_epoch=lambda: 1020,
        )


def test_f6_interrupt_stale_running_without_lease_until(store: PersistenceStore) -> None:
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        ops_planned_redacted=("set_ssid",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now_epoch=1000,
        lease_seconds=30,
    )
    store.conn.execute(
        "UPDATE sealed_apply_runs SET lease_until_epoch = NULL, started_at = ? WHERE run_id = ?",
        ("1970-01-01T00:00:00Z", run_id),
    )
    assert store.interrupt_stale_sealed_apply_runs(now_epoch=2000) == 1
    row = store.conn.execute(
        "SELECT status FROM sealed_apply_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert row is not None
    assert row["status"] == "Interrupted"


def test_finish_sealed_apply_run_skips_when_lease_lost(store: PersistenceStore) -> None:
    run_id = store.begin_sealed_apply_run(
        route="wifi",
        verb="apply",
        intent_summary_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        ops_planned_redacted=("set_ssid",),
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        now_epoch=1000,
        lease_seconds=30,
    )
    store.conn.execute(
        "UPDATE sealed_apply_runs SET status = 'Interrupted', lease_owner = NULL, "
        "lease_until_epoch = NULL WHERE run_id = ?",
        (run_id,),
    )
    finished = store.finish_sealed_apply_run(
        run_id,
        lease_owner=_TEST_SEALED_APPLY_LEASE_OWNER,
        status="Succeeded",
        overall="applied",
    )
    assert finished is False
    row = store.conn.execute(
        "SELECT status, overall FROM sealed_apply_runs WHERE run_id = ?",
        (run_id,),
    ).fetchone()
    assert row is not None
    assert row["status"] == "Interrupted"
    assert row["overall"] is None


def test_find_restore_candidate_prefers_genuine_enrolled_over_live_ready_drafts(
    store: PersistenceStore,
) -> None:
    """Adversarial live shape: seven drafts + one genuine Enrolled NC-1812 without pin."""
    import base64
    import hashlib

    from router_control.application.router_discovery import (
        ENROLLMENT_DRAFT_LIFECYCLE,
        ENROLLMENT_DRAFT_MODEL,
    )

    def _pin_for(key_bytes: bytes) -> str:
        digest = hashlib.sha256(key_bytes).digest()
        return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"

    base = datetime(2026, 8, 3, 10, 0, tzinfo=UTC)
    site = store.create_site(display_name="Lab", now=base)
    host = "192.168.2.1"

    def _seed_draft(
        suffix: str,
        *,
        with_pin: bool = False,
        with_username: bool = False,
        created_at: datetime,
    ) -> str:
        router_id = store.enroll_router(
            site_id=site,
            display_name=f"Draft {suffix}",
            vendor="Netcraze",
            model=ENROLLMENT_DRAFT_MODEL,
            identity_fingerprint=f"digest:enroll:{suffix}",
            host=host,
            port=443,
            kind="management_https",
            source_address=None,
            now=created_at,
        )
        store._conn.execute(
            "UPDATE routers SET lifecycle_status = ? WHERE router_id = ?",
            (ENROLLMENT_DRAFT_LIFECYCLE, router_id),
        )
        cred_id = store.insert_credential_ref(
            router_id=router_id,
            kind="RouterManagementPassword",
            provider="test",
            provider_locator=f"loc-{suffix}",
            now=created_at,
        )
        store.set_router_credential_ref(router_id, cred_id, now=created_at)
        if with_pin:
            store.set_endpoint_ssh_host_key(
                router_id,
                _pin_for(f"draft-pin-{suffix}".encode()),
                "ssh-ed25519",
                "learned_confirmed",
                pinned_at=created_at.isoformat().replace("+00:00", "Z"),
            )
        if with_username:
            store.set_endpoint_management_username(router_id, "draft-mgmt-user")
        return router_id

    pinned_ids: list[str] = []
    for index in range(7):
        created = base + timedelta(minutes=index)
        with_pin = index < 3
        with_username = index == 2
        pinned_ids.append(
            _seed_draft(
                str(index),
                with_pin=with_pin,
                with_username=with_username,
                created_at=created,
            )
        )

    genuine_id = store.enroll_router(
        site_id=site,
        display_name="Lab NC-1812",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lab:enrolled",
        host=host,
        port=22,
        kind="ssh_tunnel",
        source_address="192.168.2.10",
        now=base - timedelta(hours=1),
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (genuine_id,),
    )
    genuine_cred = store.insert_credential_ref(
        router_id=genuine_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-genuine",
        now=base,
    )
    store.set_router_credential_ref(genuine_id, genuine_cred, now=base)

    winner = store.find_restore_candidate_router_id()
    assert winner == genuine_id


def test_find_restore_candidate_genuine_prefers_pin_over_live_ready(
    store: PersistenceStore,
) -> None:
    """Within genuine tier, confirmed pin outranks mere live_ready convenience."""
    import base64
    import hashlib

    def _pin_for(key_bytes: bytes) -> str:
        digest = hashlib.sha256(key_bytes).digest()
        return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"

    base = datetime(2026, 8, 4, tzinfo=UTC)
    site = store.create_site(display_name="Lab", now=base)
    host = "192.168.2.1"

    live_ready_id = store.enroll_router(
        site_id=site,
        display_name="Live-ready no pin",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lab:live-ready",
        host=host,
        port=22,
        kind="ssh_tunnel",
        source_address="192.168.2.10",
        now=base,
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (live_ready_id,),
    )
    live_cred = store.insert_credential_ref(
        router_id=live_ready_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-live-ready",
        now=base,
    )
    store.set_router_credential_ref(live_ready_id, live_cred, now=base)
    store.set_endpoint_management_username(live_ready_id, "admin")

    pinned_id = store.enroll_router(
        site_id=site,
        display_name="Pinned no username",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lab:pinned-only",
        host=host,
        port=22,
        kind="ssh_tunnel",
        source_address="192.168.2.10",
        now=base - timedelta(hours=1),
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (pinned_id,),
    )
    pinned_cred = store.insert_credential_ref(
        router_id=pinned_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-pinned",
        now=base,
    )
    store.set_router_credential_ref(pinned_id, pinned_cred, now=base)
    store.set_endpoint_ssh_host_key(
        pinned_id,
        _pin_for(b"genuine-intra-tier-pin"),
        "ssh-ed25519",
        "learned_confirmed",
        pinned_at=(base - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    )

    winner = store.find_restore_candidate_router_id()
    assert winner == pinned_id


def test_find_restore_candidate_skips_genuine_record_without_endpoint(
    store: PersistenceStore,
) -> None:
    """Defence in depth: endpoint-less genuine record cannot win restore ranking."""
    import base64
    import hashlib

    from router_control.application.router_discovery import (
        ENROLLMENT_DRAFT_LIFECYCLE,
        ENROLLMENT_DRAFT_MODEL,
    )

    def _pin_for(key_bytes: bytes) -> str:
        digest = hashlib.sha256(key_bytes).digest()
        return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"

    base = datetime(2026, 8, 4, tzinfo=UTC)
    site = store.create_site(display_name="Lab", now=base)
    host = "192.168.2.1"

    draft_id = store.enroll_router(
        site_id=site,
        display_name="Pinned draft",
        vendor="Netcraze",
        model=ENROLLMENT_DRAFT_MODEL,
        identity_fingerprint="digest:enroll:draft-only",
        host=host,
        now=base,
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = ? WHERE router_id = ?",
        (ENROLLMENT_DRAFT_LIFECYCLE, draft_id),
    )
    store.set_endpoint_ssh_host_key(
        draft_id,
        _pin_for(b"draft-endpoint-pin"),
        "ssh-ed25519",
        "learned_confirmed",
        pinned_at=base.isoformat().replace("+00:00", "Z"),
    )

    store._conn.execute(
        "INSERT INTO routers("
        "router_id, site_id, display_name, vendor, model, hardware_revision, "
        "identity_fingerprint, identity_claims_json, credential_ref_id, "
        "lifecycle_status, created_at, updated_at"
        ") VALUES (?, ?, ?, ?, ?, NULL, ?, NULL, NULL, 'Enrolled', ?, ?)",
        (
            "rtr-endpointless-genuine",
            site,
            "Endpointless genuine",
            "Netcraze",
            "NC-1812",
            "digest:lab:no-endpoint",
            base.isoformat().replace("+00:00", "Z"),
            base.isoformat().replace("+00:00", "Z"),
        ),
    )

    winner = store.find_restore_candidate_router_id()
    assert winner == draft_id
    assert winner != "rtr-endpointless-genuine"
