"""P1-B restart/recovery matrix — process boundaries, poll continuation, no redispatch."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest
from router_control.adapters.fake.adapter import FakeMode, FakeRouterConfig
from router_control.application.mutation_executor import MutationExecutorHooks
from router_control.application.recovery import classify_job_steps
from router_control.application.worker import WorkerConfig
from router_control.composition import FixedClock, build_durable_worker, create_offline_runtime
from router_control.domain.enums import EffectState, EvidenceKind, ReconcileStatus, StepKind
from router_control.persistence.artifacts import (
    ArtifactStagingPublisher,
    DpapiDurableArtifactStore,
    compute_content_digest,
    reconcile_orphan_staging_records,
)
from router_control.persistence.connection import connect, open_database
from router_control.persistence.store import PersistenceStore

from tests.test_recovery_substrate import FIXED, _runtime, _seed_plan_bundle


def _wait_job(store: PersistenceStore, job_id: str, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = store.get_job(job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired", "Cancelled"):
            return
        time.sleep(0.05)
    pytest.fail(f"job {job_id} did not reach terminal state")


def _worker_child_script(
    *,
    db_path: str,
    barrier_path: str,
    pause_at: str,
    durable_artifacts: bool,
    idempotency_key: str,
) -> str:
    project_root = str(Path(__file__).resolve().parents[1])
    return textwrap.dedent(
        f"""
        import os
        import sys
        import time
        from datetime import UTC, datetime
        from pathlib import Path

        sys.path.insert(0, {project_root!r})
        os.environ["ROUTER_CONTROL_EXECUTOR_TEST_BARRIER"] = {barrier_path!r}
        os.environ["ROUTER_CONTROL_EXECUTOR_PAUSE_AT"] = {pause_at!r}
        os.environ["ROUTER_CONTROL_EXECUTOR_BARRIER_SPIN"] = "1"

        from router_control.application.worker import WorkerConfig
        from router_control.composition import (
            FixedClock,
            build_durable_worker,
            create_offline_runtime,
        )
        from tests.test_recovery_substrate import FIXED, _seed_plan_bundle

        runtime = create_offline_runtime(
            db_path={db_path!r},
            clock=FixedClock(FIXED),
            durable_backup_artifacts={durable_artifacts!r},
        )
        rid, plan_id = _seed_plan_bundle(runtime)
        runtime.store.create_operation_bundle(
            router_id=rid,
            operation_kind="apply_plan",
            idempotency_key={idempotency_key!r},
            request_digest="sha256:{idempotency_key}",
            plan_id=plan_id,
            initial_job_status="Queued",
            dispatch_payload={{"plan_id": plan_id}},
            now=FIXED,
        )
        worker = build_durable_worker(runtime, allow_fake_mutations=True)
        worker.config = WorkerConfig(
            poll_interval_seconds=0.05,
            worker_id="spawn-worker",
        )
        worker.start()
        while True:
            time.sleep(0.2)
        """
    )


def _spawn_kill_reopen(
    tmp_path: Path,
    pause_at: str,
    *,
    durable_artifacts: bool = False,
) -> tuple[PersistenceStore, str, str]:
    db_path = tmp_path / f"spawn-{pause_at}.sqlite3"
    barrier = tmp_path / f"barrier-{pause_at}.txt"
    idempotency_key = f"spawn-{pause_at}"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            _worker_child_script(
                db_path=str(db_path),
                barrier_path=str(barrier),
                pause_at=pause_at,
                durable_artifacts=durable_artifacts,
                idempotency_key=idempotency_key,
            ),
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            pytest.fail(f"spawn worker exited early: {stderr[:500]}")
        if barrier.exists() and barrier.read_text(encoding="utf-8") == f"at:{pause_at}":
            break
        time.sleep(0.05)
    else:
        proc.kill()
        proc.wait(timeout=10)
        stderr = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
        pytest.fail(f"spawn worker never reached barrier {pause_at}: {stderr[:500]}")
    proc.kill()
    proc.wait(timeout=10)
    reopen = PersistenceStore(connect(db_path))
    reopen.recover_expired_leases(now_epoch=9_999_999_999)
    row = reopen._conn.execute(
        "SELECT j.job_id, j.router_id FROM jobs j "
        "JOIN operations o ON j.operation_id = o.operation_id "
        "JOIN idempotency_records ir ON ir.operation_id = o.operation_id "
        "WHERE ir.idempotency_key = ?",
        (idempotency_key,),
    ).fetchone()
    assert row is not None
    return reopen, str(row["job_id"]), str(row["router_id"])


def _fresh_worker_apply_count(
    db_path: Path,
    *,
    durable_artifacts: bool = False,
    wait_seconds: float = 3.0,
) -> int:
    runtime = create_offline_runtime(
        db_path=db_path,
        clock=FixedClock(FIXED),
        durable_backup_artifacts=durable_artifacts,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05, worker_id="reopen-worker")
    worker.start()
    time.sleep(wait_seconds)
    worker.stop(timeout=3.0)
    return runtime.adapter.call_trace.count("apply_plan")


POST_DISPATCH_KILL_BARRIERS = frozenset(
    {"dispatching", "apply-response", "verify", "save"}
)
POST_DISPATCH_UNCERTAIN_EFFECT_STATES = frozenset(
    {
        EffectState.DISPATCHING.value,
        EffectState.ACKNOWLEDGED.value,
        EffectState.UNKNOWN.value,
        EffectState.OBSERVED_APPLIED.value,
        EffectState.OBSERVED_PARTIAL.value,
    }
)


@pytest.mark.parametrize(
    "pause_at",
    ["artifact", "effect", "fail-safe", "dispatching", "apply-response", "verify", "save"],
)
def test_process_kill_at_boundary_unknown_or_incomplete(
    tmp_path: Path, pause_at: str
) -> None:
    store, job_id, rid = _spawn_kill_reopen(tmp_path, pause_at)
    db_path = tmp_path / f"spawn-{pause_at}.sqlite3"
    job = store.get_job(job_id)
    assert job is not None
    effects = store._conn.execute(
        "SELECT * FROM external_effects WHERE router_id = ?", (rid,)
    ).fetchall()
    if pause_at in POST_DISPATCH_KILL_BARRIERS:
        assert job["status"] == "RecoveryRequired"
        assert len(effects) == 1
        effect_state = str(effects[0]["current_state"])
        assert effect_state in POST_DISPATCH_UNCERTAIN_EFFECT_STATES
        safety = store.get_router_safety_session(rid)
        if effect_state == EffectState.UNKNOWN.value:
            assert safety is not None
            assert str(safety["safety_state"]) == "Blocked"
        fresh_apply_count = _fresh_worker_apply_count(db_path)
        assert fresh_apply_count == 0
    elif pause_at in ("effect",):
        assert len(effects) == 1
        assert job["status"] in ("Lost", "RecoveryRequired", "Leased", "Running")
    else:
        assert job["status"] in ("Lost", "Leased", "Running", "RecoveryRequired", "Failed")
    if pause_at in ("effect", "dispatching", "apply-response", "verify", "save"):
        assert len(effects) == 1
    if pause_at == "dispatching":
        assert str(effects[0]["current_state"]) in (
            EffectState.DISPATCHING.value,
            EffectState.ACKNOWLEDGED.value,
            EffectState.UNKNOWN.value,
        )
    cls = classify_job_steps(store, job_id, job_status=str(job["status"]))
    if pause_at in POST_DISPATCH_KILL_BARRIERS:
        assert cls.apply_dispatched or cls.post_dispatch or cls.requires_readback


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI durable artifact spawn test")
def test_process_kill_artifact_boundary_durable_store(tmp_path: Path) -> None:
    store, job_id, _rid = _spawn_kill_reopen(
        tmp_path, "artifact", durable_artifacts=True
    )
    job = store.get_job(job_id)
    assert job is not None
    staging = store.list_pending_artifact_staging(limit=10)
    published = store._conn.execute(
        "SELECT artifact_id FROM backup_artifacts LIMIT 5"
    ).fetchall()
    assert job["status"] in ("Leased", "Running", "RecoveryRequired", "Failed")
    assert staging or published or job["status"] != "Succeeded"


def test_partial_async_poll_not_redispatch(tmp_path: Path) -> None:
    runtime = _runtime(
        tmp_path / "poll.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.PARTIAL_ASYNC),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="poll-once",
        request_digest="sha256:poll-once",
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
    assert runtime.adapter.call_trace.count("apply_plan") == 1
    assert runtime.adapter.call_trace.count("poll_apply_continuation") == 1
    effects = runtime.store._conn.execute(
        "SELECT * FROM external_effects WHERE router_id = ?", (rid,)
    ).fetchall()
    assert effects
    assert str(effects[0]["current_state"]) == EffectState.OBSERVED_APPLIED.value


def test_crash_before_apply_dispatch_failed_not_recovery(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "crash.sqlite3", config=FakeRouterConfig(mode=FakeMode.NORMAL))
    rid, plan_id = _seed_plan_bundle(runtime)
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(crash_after_step=StepKind.APPLY)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="crash-apply",
        request_digest="sha256:crash-apply",
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
    assert job is not None
    assert job["status"] == "Failed"
    assert runtime.adapter.call_trace.count("apply_plan") == 0
    effects = runtime.store._conn.execute(
        "SELECT current_state FROM external_effects WHERE router_id = ?", (rid,)
    ).fetchall()
    assert not effects


def test_crash_after_dispatching_recovery_required(tmp_path: Path) -> None:
    runtime = _runtime(
        tmp_path / "crash-disp.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.NORMAL),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(crash_after_dispatching=True)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="crash-disp",
        request_digest="sha256:crash-disp",
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
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    effects = runtime.store._conn.execute(
        "SELECT current_state FROM external_effects WHERE router_id = ?", (rid,)
    ).fetchall()
    assert len(effects) == 1
    assert str(effects[0]["current_state"]) in (
        EffectState.DISPATCHING.value,
        EffectState.UNKNOWN.value,
    )


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI durable artifact tests require Windows")
def test_dpapi_durable_store_roundtrip(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "dpapi.sqlite3")
    store = PersistenceStore(conn)
    rid = store.enroll_router(
        site_id=store.create_site(display_name="Lab", now=FIXED),
        display_name="R",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:1",
        host="127.0.0.1",
        now=FIXED,
    )
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="dpapi",
        request_digest="sha256:dpapi",
        initial_job_status="Queued",
        now=FIXED,
    )
    content = b"encrypted-backup-bytes"
    digest = compute_content_digest(content)
    durable = DpapiDurableArtifactStore(
        store=store,
        staging_root=tmp_path / "staging",
        encrypted_root=tmp_path / "encrypted",
    )
    aid = durable.publish_encrypted(
        artifact_id="bkp-dpapi-1",
        router_id=rid,
        operation_id=out.operation_id,
        content_bytes=content,
        content_digest=digest,
        identity_fingerprint="digest:fp:1",
        now=FIXED,
    )
    restored = durable.restore(aid)
    assert restored == content
    publisher = ArtifactStagingPublisher(store=store, staging_root=tmp_path / "staging2")
    reconcile_orphan_staging_records(publisher, store, now=FIXED)


def test_offline_runtime_durable_backup_hook(tmp_path: Path) -> None:
    runtime = create_offline_runtime(
        db_path=tmp_path / "durable-hook.sqlite3",
        durable_backup_artifacts=sys.platform == "win32",
    )
    assert runtime.mutation_executor is not None
    publisher = runtime.mutation_executor.backup_publisher
    assert hasattr(publisher, "publish")


def test_evidence_recorded_on_success(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "evidence.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="evidence",
        request_digest="sha256:evidence",
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
    runtime_evidence = runtime.store.get_latest_evidence_revision(
        rid, EvidenceKind.RUNTIME_APPLIED.value
    )
    saved_evidence = runtime.store.get_latest_evidence_revision(
        rid, EvidenceKind.STARTUP_SAVED.value
    )
    assert runtime_evidence is not None
    assert saved_evidence is not None


def test_blocked_safety_session_rejects_mutation(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "blocked.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    runtime.store.upsert_router_safety_session(
        router_id=rid,
        safety_state="Blocked",
        now=FIXED,
    )
    runtime.store.record_router_boot_observation(
        router_id=rid,
        boot_id="boot-blocked",
        boot_known=True,
        boot_marker="boot:blocked",
        now=FIXED,
    )
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="blocked",
        request_digest="sha256:blocked",
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
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    assert runtime.adapter.call_trace.count("apply_plan") == 0


def test_safety_session_payload_fields_persisted(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path / "safety-payload.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="safety-payload",
        request_digest="sha256:safety-payload",
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
    payload = runtime.store.get_router_safety_payload(rid)
    assert payload.get("backup_artifact_ref")
    assert payload.get("baseline_observation") or payload.get("baseline_revision_id")
    assert payload.get("fail_safe_status") in ("active", "inactive")
    assert payload.get("authorization_ref") == out.operation_id


def test_drifted_when_desired_advanced_mid_flight(tmp_path: Path) -> None:
    from router_control.persistence.store import etag_for_revision

    runtime = _runtime(tmp_path / "drifted.sqlite3")
    rid, plan_id = _seed_plan_bundle(runtime)
    plan_row = runtime.store.get_plan(plan_id)
    assert plan_row is not None
    obs_id = str(plan_row["observation_id"])
    assert runtime.mutation_executor is not None
    runtime.mutation_executor.hooks = MutationExecutorHooks(step_delay_seconds=2.0)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="drifted",
        request_digest="sha256:drifted",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 10.0
    while (
        time.monotonic() < deadline
        and runtime.adapter.call_trace.count("apply_plan") == 0
    ):
        time.sleep(0.05)
    rev = runtime.store.get_desired_revision(rid)
    assert rev is not None
    etag = etag_for_revision(str(rev["revision_id"]), str(rev["canonical_digest"]))
    runtime.store.put_desired_revision(
        router_id=rid,
        canonical_digest="sha256:desired:drifted-new",
        based_on_observation_id=obs_id,
        if_match=etag,
        now=FIXED,
    )
    _wait_job(runtime.store, out.job_id, timeout=60.0)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    op = runtime.store.get_operation(out.operation_id)
    assert job is not None and job["status"] == "Succeeded"
    assert op is not None
    assert op["aggregate_status"] == ReconcileStatus.DRIFTED.value
    applied = runtime.store.get_latest_evidence_revision(
        rid, EvidenceKind.RUNTIME_APPLIED.value
    )
    assert applied is not None
    assert str(applied["revision_id"]) == str(plan_row["revision_id"])
