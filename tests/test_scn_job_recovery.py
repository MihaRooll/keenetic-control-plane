"""SCN-JOB-001..009 recovery fault matrix (offline/fake)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from router_control.adapters.fake.adapter import FakeMode, FakeRouterConfig
from router_control.application.mutation_executor import MutationExecutorHooks
from router_control.application.recovery import classify_job_steps
from router_control.application.worker import WorkerConfig
from router_control.composition import build_durable_worker
from router_control.domain.enums import StepKind
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore

from tests.test_recovery_substrate import FIXED, _runtime, _seed_plan_bundle


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "scn.sqlite3"))


def test_scn_job_001_pre_dispatch_failure_no_mutation(tmp_path: Path) -> None:
    """SCN-JOB-001: failure before dispatch — safe terminal Failed, no apply step."""
    runtime = _runtime(
        tmp_path / "j001.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.IDENTITY_MISMATCH),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j001",
        request_digest="sha256:j001",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None and job["status"] == "Failed"
    kinds = [s["step_kind"] for s in runtime.store.list_job_steps(out.job_id)]
    assert "apply" not in kinds


def test_scn_job_002_post_dispatch_unknown_outcome(tmp_path: Path) -> None:
    """SCN-JOB-002/005: post-dispatch unknown — RecoveryRequired, no blind retry."""
    runtime = _runtime(
        tmp_path / "j002.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.UNKNOWN_EXTERNAL_OUTCOME),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j002",
        request_digest="sha256:j002",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None and job["status"] == "RecoveryRequired"
    resume_jobs = [
        j
        for j in runtime.store.list_jobs_for_operation(out.operation_id)
        if j["status"] == "Queued"
    ]
    assert len(resume_jobs) == 0


def test_scn_job_003_async_continuation_checkpoints(tmp_path: Path) -> None:
    """SCN-JOB-003: partial async apply — converged with apply step recorded."""
    runtime = _runtime(
        tmp_path / "j003.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.PARTIAL_ASYNC),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j003",
        request_digest="sha256:j003",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    assert runtime.store.get_job(out.job_id)["status"] == "Succeeded"
    apply_steps = [
        s for s in runtime.store.list_job_steps(out.job_id) if s["step_kind"] == "apply"
    ]
    assert len(apply_steps) >= 1


def test_scn_job_004_expired_lease_lost_vs_recovery(store: PersistenceStore) -> None:
    """SCN-JOB-004: pre-dispatch Lost; post-dispatch RecoveryRequired."""
    site = store.create_site(display_name="S", now=FIXED)
    rid = store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:j004",
        host="127.0.0.1",
        now=FIXED,
    )
    pre = store.create_operation_bundle(
        router_id=rid,
        operation_kind="preset_validate",
        idempotency_key="j004-pre",
        request_digest="sha256:j004-pre",
        initial_job_status="Queued",
        now=FIXED,
    )
    store.insert_job_dispatch_payload(
        job_id=pre.job_id, payload={"preset_id": "p1"}, now=FIXED
    )
    c1 = store.claim_job(worker_id="w1", lease_seconds=1, now_epoch=100)
    assert c1 is not None
    store.recover_expired_leases(now_epoch=200)
    assert store.get_job(pre.job_id)["status"] == "Lost"

    post = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j004-post",
        request_digest="sha256:j004-post",
        initial_job_status="Queued",
        now=FIXED,
    )
    c2 = store.claim_job(worker_id="w1", lease_seconds=1, now_epoch=300)
    assert c2 is not None
    store.record_job_progress(
        job_id=post.job_id,
        lease_owner=c2.lease_owner,
        fencing_token=c2.fencing_token,
        step_kind="apply",
        step_status="Running",
    )
    store.recover_expired_leases(now_epoch=400)
    assert store.get_job(post.job_id)["status"] == "RecoveryRequired"


def test_scn_job_006_compensation_path(tmp_path: Path) -> None:
    """SCN-JOB-006: verify failure routes RecoveryRequired without blind compensate."""
    runtime = _runtime(
        tmp_path / "j006.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.VERIFY_FAILURE),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j006",
        request_digest="sha256:j006",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    op = runtime.store.get_operation(out.operation_id)
    assert job is not None and job["status"] == "RecoveryRequired"
    assert op is not None and op["aggregate_status"] == "RecoveryRequired"
    assert runtime.adapter.call_trace.count("compensate") == 0
    safety = runtime.store.get_router_safety_session(rid)
    assert safety is not None and str(safety["safety_state"]) == "Blocked"


def test_scn_job_008_recovery_required_aggregate(tmp_path: Path) -> None:
    """SCN-JOB-008: operation aggregate RecoveryRequired surfaced."""
    runtime = _runtime(
        tmp_path / "j008.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.UNKNOWN_EXTERNAL_OUTCOME),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j008",
        request_digest="sha256:j008",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    op = runtime.store.get_operation(out.operation_id)
    assert op is not None and op["aggregate_status"] == "RecoveryRequired"


def test_scn_job_002_no_blind_compensate_on_unknown(tmp_path: Path) -> None:
    """SCN-JOB-002/005: unknown read-back must not blind-compensate before RecoveryRequired."""
    runtime = _runtime(
        tmp_path / "j002b.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.UNKNOWN_EXTERNAL_OUTCOME),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j002b",
        request_digest="sha256:j002b",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    assert runtime.adapter.call_trace.count("compensate") == 0
    assert runtime.adapter.call_trace.count("apply_plan") == 1


def test_scn_job_007_fail_safe_timeout(tmp_path: Path) -> None:
    """SCN-JOB-007: fail-safe timeout pre-dispatch — Failed, no apply, no compensate."""
    runtime = _runtime(
        tmp_path / "j007.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.FAIL_SAFE_TIMEOUT),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j007",
        request_digest="sha256:j007",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None and job["status"] == "Failed"
    kinds = [s["step_kind"] for s in runtime.store.list_job_steps(out.job_id)]
    assert "apply" not in kinds
    assert runtime.adapter.call_trace.count("compensate") == 0


def test_scn_job_009_db_fault_degraded_isolation(tmp_path: Path) -> None:
    """SCN-JOB-009: persistence fault isolates worker — Degraded, job not falsely Succeeded."""
    import sqlite3
    from unittest.mock import patch

    runtime = _runtime(tmp_path / "j009.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j009",
        request_digest="sha256:j009",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)

    def _faulty_complete(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("disk I/O error")

    degraded_seen = False
    with patch.object(worker.store, "complete_job", side_effect=_faulty_complete):
        worker.start()
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline:
            job = runtime.store.get_job(out.job_id)
            if worker.lifecycle.value == "Degraded":
                degraded_seen = True
            if job and job["status"] in ("Running", "Leased") and degraded_seen:
                break
            time.sleep(0.05)
        worker.stop(timeout=3.0)

    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] != "Succeeded"
    assert degraded_seen


def test_scn_job_cancel_after_apply_recovery_required(tmp_path: Path) -> None:
    """Post-apply cancel must not terminalize as clean Cancelled or claim undo."""
    runtime = _runtime(tmp_path / "j-cancel.sqlite3")
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(step_delay_seconds=0.05)
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="j-cancel",
        request_digest="sha256:j-cancel",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 8.0
    cancelled = False
    while time.monotonic() < deadline:
        steps = runtime.store.list_job_steps(out.job_id)
        apply_done = any(
            s["step_kind"] == "apply" and s["status"] == "Succeeded" for s in steps
        )
        if apply_done and not cancelled:
            runtime.store.cancel_job(
                target_job_id=out.job_id,
                idempotency_key="cancel-k1",
                request_digest="sha256:cancel-k1",
                now=FIXED,
            )
            cancelled = True
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("RecoveryRequired", "Cancelled", "Succeeded", "Failed"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    assert job["status"] != "Cancelled"
    op = runtime.store.get_operation(out.operation_id)
    assert op is not None and op["aggregate_status"] == "RecoveryRequired"


@pytest.mark.parametrize(
    ("crash_step", "expected_status"),
    [
        (StepKind.PREFLIGHT, "Failed"),
        (StepKind.APPLY, "Failed"),
        (StepKind.READ_BACK, "RecoveryRequired"),
    ],
)
def test_executor_crash_matrix_post_dispatch_recovery(
    tmp_path: Path, crash_step: StepKind, expected_status: str
) -> None:
    """Crash hooks: pre-dispatch Failed; post-dispatch RecoveryRequired."""
    runtime = _runtime(tmp_path / f"crash-{crash_step.value}.sqlite3")
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(crash_after_step=crash_step)
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key=f"crash-{crash_step.value}",
        request_digest=f"sha256:crash-{crash_step.value}",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None and job["status"] == expected_status
    if expected_status == "RecoveryRequired":
        cls = classify_job_steps(runtime.store, out.job_id, job_status=str(job["status"]))
        assert cls.apply_dispatched or cls.post_dispatch


def test_executor_crash_after_apply_no_blind_retry(tmp_path: Path) -> None:
    """Post-dispatch crash leaves no Queued retry job — operator resume required."""
    runtime = _runtime(tmp_path / "crash-retry.sqlite3")
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(crash_after_step=StepKind.APPLY)
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="crash-retry",
        request_digest="sha256:crash-retry",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    _wait_job(runtime.store, out.job_id)
    worker.stop(timeout=3.0)
    resume_jobs = [
        j
        for j in runtime.store.list_jobs_for_operation(out.operation_id)
        if j["status"] == "Queued"
    ]
    assert len(resume_jobs) == 0


def test_scn_job_cancel_after_partial_no_undo(tmp_path: Path) -> None:
    """Legacy alias — see test_scn_job_cancel_after_apply_recovery_required."""
    test_scn_job_cancel_after_apply_recovery_required(tmp_path)


def _wait_job(
    store: PersistenceStore,
    job_id: str,
    *,
    terminal: set[str] | None = None,
    timeout: float = 8.0,
) -> None:
    allowed = terminal or {"Succeeded", "Failed", "RecoveryRequired", "Cancelled"}
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = store.get_job(job_id)
        if job and job["status"] in allowed:
            return
        time.sleep(0.05)
    pytest.fail(f"job {job_id} did not reach terminal state in time")
