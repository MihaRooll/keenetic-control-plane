"""M4 recovery substrate — durable checkpoints, fencing, backup publication."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.adapters.fake.adapter import FakeMode, FakeRouterConfig
from router_control.application.mutation_executor import MutationExecutorHooks
from router_control.application.recovery import classify_job_steps
from router_control.application.worker import WorkerConfig
from router_control.composition import FixedClock, build_durable_worker, create_offline_runtime
from router_control.domain.entities import RouterIdentity
from router_control.domain.ids import RouterId
from router_control.persistence.artifacts import (
    FakeBlobStore,
)
from router_control.persistence.connection import open_database
from router_control.persistence.errors import ConflictError, StaleFenceError
from router_control.persistence.store import PersistenceStore

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    conn = open_database(tmp_path / "recovery.sqlite3")
    return PersistenceStore(conn)


def _align_fake_adapter(runtime, router_id: str, fingerprint: str) -> None:
    row = runtime.store.get_router(router_id)
    assert row is not None
    runtime.adapter.state.identity = RouterIdentity(
        router_id=RouterId(router_id),
        vendor=str(row["vendor"]),
        model=str(row["model"]),
        fingerprint_digest=fingerprint,
    )


def _runtime(db_path: Path, **kwargs: object):
    return create_offline_runtime(
        db_path=db_path,
        clock=FixedClock(FIXED),
        **kwargs,
    )


def _seed_plan_bundle(runtime, *, fingerprint: str = "digest:recovery-lab") -> tuple[str, str]:
    site = runtime.store.create_site(display_name="Recovery Lab", now=FIXED)
    rid = runtime.store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="FakeVendor",
        model="Fake",
        identity_fingerprint=fingerprint,
        host="127.0.0.1",
        now=FIXED,
    )
    runtime.store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (rid,),
    )
    obs_id = runtime.store.insert_observation(
        router_id=rid,
        identity_fingerprint=fingerprint,
        resource_version="digest:rv:001",
        state_digest="digest:state:baseline",
        observation_id="observation-fake-001",
        ttl_seconds=7200,
        now=FIXED,
    )
    rev_id, rev_etag, _ = runtime.store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:desired:recovery",
        based_on_observation_id=obs_id,
        if_match="*",
        now=FIXED,
    )
    plan_id, plan_etag = runtime.store.create_plan(
        router_id=rid,
        revision_id=rev_id,
        observation_id=obs_id,
        if_match=rev_etag,
        now=FIXED,
    )
    plan = runtime.store.get_plan(plan_id)
    assert plan is not None
    runtime.store.confirm_plan(
        plan_id=plan_id,
        plan_digest=str(plan["plan_digest"]),
        if_match=plan_etag,
        actor_id="operator",
        now=FIXED,
    )
    _align_fake_adapter(runtime, rid, fingerprint)
    return rid, plan_id


def test_complete_job_accepts_recovery_required(store: PersistenceStore) -> None:
    site = store.create_site(display_name="S", now=FIXED)
    router_id = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:x",
        host="127.0.0.1",
        now=FIXED,
    )
    out = store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key="rec-complete",
        request_digest="sha256:rec-complete",
        initial_job_status="Queued",
        now=FIXED,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=30, now_epoch=100)
    assert claim is not None
    store.complete_job(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        status="RecoveryRequired",
        summary_redacted="unknown outcome",
        http_status=422,
        response_body={"status": "RecoveryRequired"},
        now=FIXED,
    )
    job = store.get_job(out.job_id)
    op = store.get_operation(out.operation_id)
    assert job is not None and job["status"] == "RecoveryRequired"
    assert op is not None and op["aggregate_status"] == "RecoveryRequired"


def test_backup_digest_before_metadata() -> None:
    blob = FakeBlobStore()
    content = b"fake-backup-bytes"
    with pytest.raises(ValueError, match="digest"):
        blob.put("bkp-x", content, expected_digest="sha256:wrong")


def test_backup_metadata_redacted_no_locator_secrets(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "backup-redact.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="backup-pub2",
        request_digest="sha256:backup-pub2",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True, worker_id="w-bkp")
    worker.config = WorkerConfig(worker_id="w-bkp", poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    rows = runtime.store._conn.execute("SELECT * FROM backup_artifacts").fetchall()
    assert rows, "backup artifact row expected"
    row = rows[0]
    assert row["storage_locator"] == "digest:locator:redacted"
    redacted = runtime.store.get_backup_artifact_redacted(row["artifact_id"])
    assert redacted is not None
    assert "storage_locator" not in redacted


def test_no_router_io_inside_immediate_txn(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "txn-inv.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    conn = runtime.store._conn
    adapter_called_inside = {"value": False}
    original_check = runtime.adapter.check_identity

    async def wrapped_check(*args: object, **kwargs: object) -> object:
        if conn.in_transaction:
            adapter_called_inside["value"] = True
        return await original_check(*args, **kwargs)

    runtime.adapter.check_identity = wrapped_check  # type: ignore[method-assign]
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="txn-inv",
        request_digest="sha256:txn-inv",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    assert adapter_called_inside["value"] is False


def test_stale_fence_rejects_recovery_writes(store: PersistenceStore) -> None:
    site = store.create_site(display_name="S", now=FIXED)
    router_id = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:stale",
        host="127.0.0.1",
        now=FIXED,
    )
    out = store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key="stale-rec",
        request_digest="sha256:stale-rec",
        initial_job_status="Queued",
        now=FIXED,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    store.recover_expired_leases(now_epoch=200)
    with pytest.raises(StaleFenceError):
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner=claim.lease_owner,
            fencing_token=claim.fencing_token,
            step_kind="apply",
            step_status="Running",
        )
    with pytest.raises(StaleFenceError):
        store.complete_job(
            job_id=out.job_id,
            lease_owner=claim.lease_owner,
            fencing_token=claim.fencing_token,
            status="RecoveryRequired",
        )


def test_resume_same_operation_id(tmp_path: Path) -> None:
    runtime = _runtime(
        tmp_path / "resume-op.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.UNKNOWN_EXTERNAL_OUTCOME),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="resume-op",
        request_digest="sha256:resume-op",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] == "RecoveryRequired":
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    assert runtime.adapter.call_trace.count("apply_plan") == 1

    http_status, body = runtime.store.resume_recovery_job(
        target_job_id=out.job_id,
        action="resume",
        idempotency_key="resume-k1",
        request_digest="sha256:resume-k1",
        now=FIXED,
    )
    assert http_status == 202
    assert body["operation_id"] == out.operation_id
    assert body["job_id"] != out.job_id
    jobs = runtime.store.list_jobs_for_operation(out.operation_id)
    assert len(jobs) == 2
    assert jobs[1]["recovery_state"] == "resume_after_readback"

    runtime.adapter.call_trace.clear()
    worker.start()
    _wait_resume_job(runtime.store, body["job_id"])
    worker.stop(timeout=3.0)
    resume_steps = runtime.store.list_job_steps(body["job_id"])
    resume_kinds = [s["step_kind"] for s in resume_steps]
    assert "identity-check" in resume_kinds
    assert "read-back" in resume_kinds
    assert resume_kinds.count("apply") == 0
    assert runtime.adapter.call_trace.count("apply_plan") == 0
    assert runtime.store.get_job(body["job_id"])["status"] == "RecoveryRequired"


def _wait_resume_job(store: PersistenceStore, job_id: str, *, timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = store.get_job(job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired", "Cancelled"):
            return
        time.sleep(0.05)
    pytest.fail(f"resume job {job_id} did not reach terminal state in time")


def test_classify_post_dispatch_recovery_required(store: PersistenceStore) -> None:
    site = store.create_site(display_name="S", now=FIXED)
    router_id = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:cls",
        host="127.0.0.1",
        now=FIXED,
    )
    out = store.create_operation_bundle(
        router_id=router_id,
        operation_kind="apply_plan",
        idempotency_key="cls",
        request_digest="sha256:cls",
        initial_job_status="Queued",
        now=FIXED,
    )
    claim = store.claim_job(worker_id="w1", now_epoch=100)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        step_kind="apply",
        step_status="Running",
    )
    cls = classify_job_steps(store, out.job_id, job_status="Running")
    assert cls.post_dispatch is True
    assert cls.requires_readback is True
    assert cls.pre_dispatch is False


def test_durable_apply_lifecycle_steps(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "lifecycle.sqlite3", config=FakeRouterConfig())
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="lifecycle",
        request_digest="sha256:lifecycle",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "Succeeded"
    kinds = [s["step_kind"] for s in runtime.store.list_job_steps(out.job_id)]
    for expected in (
        "preflight",
        "identity-check",
        "observe",
        "backup",
        "apply",
        "read-back",
        "verify",
        "save",
    ):
        assert expected in kinds


def test_unknown_outcome_recovery_required(tmp_path: Path) -> None:
    runtime = _runtime(
        tmp_path / "unknown.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.UNKNOWN_EXTERNAL_OUTCOME),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="unknown",
        request_digest="sha256:unknown",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    op = runtime.store.get_operation(out.operation_id)
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    assert op is not None
    assert op["aggregate_status"] == "RecoveryRequired"
    assert runtime.adapter.call_trace.count("compensate") == 0


def test_late_cancel_after_handler_succeeded_stays_succeeded(tmp_path: Path) -> None:
    """Late cancel after converged Succeeded must not upgrade to RecoveryRequired."""
    runtime = _runtime(tmp_path / "late-cancel-ok.sqlite3")
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(step_delay_seconds=0.05)
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="late-cancel-ok",
        request_digest="sha256:late-cancel-ok",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    cancel_key = "cancel-late-ok"
    cancel_digest = "sha256:cancel-late-ok"

    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()

    cancelled = False
    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        steps = runtime.store.list_job_steps(out.job_id)
        save_done = any(
            s["step_kind"] == "save" and s["status"] == "Succeeded" for s in steps
        )
        if save_done and not cancelled:
            http_status, body, _ = runtime.store.cancel_job(
                target_job_id=out.job_id,
                idempotency_key=cancel_key,
                request_digest=cancel_digest,
                now=FIXED,
            )
            assert http_status == 202
            assert body["cancel_requested"] is True
            cancelled = True
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] == "Succeeded":
            break
        time.sleep(0.05)
    else:
        worker.stop(timeout=3.0)
        pytest.fail("job did not reach Succeeded after late cancel")

    worker.stop(timeout=3.0)

    job = runtime.store.get_job(out.job_id)
    op = runtime.store.get_operation(out.operation_id)
    assert job is not None and job["status"] == "Succeeded"
    assert op is not None and op["aggregate_status"] == "Converged"
    assert not int(job["cancel_requested"])

    replay_status, replay_body, _ = runtime.store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key=cancel_key,
        request_digest=cancel_digest,
        now=FIXED,
    )
    assert replay_status == 409
    assert replay_body["error"]["code"] == "job.already_terminal"

    with pytest.raises(ConflictError, match="already terminal"):
        runtime.store.cancel_job(
            target_job_id=out.job_id,
            idempotency_key="cancel-late-new",
            request_digest="sha256:cancel-late-new",
            now=FIXED,
        )
