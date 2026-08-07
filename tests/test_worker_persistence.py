"""Worker persistence: claim, renew, reclaim, stale fence."""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.application.worker import WorkerConfig
from router_control.composition import build_durable_worker, create_offline_runtime
from router_control.persistence.connection import NestedTransactionError, open_database, transaction
from router_control.persistence.errors import ConflictError, StaleFenceError
from router_control.persistence.store import IdempotencyOutcome, PersistenceStore


class ControllableClock:
    """Injectable clock whose epoch advances deterministically in tests."""

    def __init__(self, start_epoch: int = 1_000_000) -> None:
        self._epoch = float(start_epoch)
        self._lock = threading.Lock()

    def now(self) -> datetime:
        with self._lock:
            return datetime.fromtimestamp(self._epoch, tz=UTC)

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._epoch += seconds

    @property
    def epoch(self) -> int:
        with self._lock:
            return int(self._epoch)


class AdvancingSleeper:
    """Sleep that advances ControllableClock and yields for heartbeat threads."""

    def __init__(self, clock: ControllableClock, *, yield_seconds: float = 0.01) -> None:
        self._clock = clock
        self._yield = yield_seconds

    def sleep(self, seconds: float) -> None:
        step = 0.05
        remaining = seconds
        while remaining > 0:
            delta = min(step, remaining)
            self._clock.advance(delta)
            remaining -= delta
            time.sleep(self._yield)


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    conn = open_database(tmp_path / "worker-persist.sqlite3")
    return PersistenceStore(conn)


def _seed(store: PersistenceStore) -> str:
    site = store.create_site(display_name="Lab", now=datetime(2026, 7, 22, tzinfo=UTC))
    return store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:1",
        host="127.0.0.1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )


def _queue_preset_validate(
    store: PersistenceStore,
    router_id: str,
    *,
    idempotency_key: str,
    request_digest: str,
    preset_id: str = "preset_test",
    now: datetime | None = None,
    **kwargs: object,
) -> IdempotencyOutcome:
    out = store.create_operation_bundle(
        router_id=router_id,
        operation_kind="preset_validate",
        idempotency_key=idempotency_key,
        request_digest=request_digest,
        initial_job_status="Queued",
        now=now,
        **kwargs,
    )
    store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload={"preset_id": preset_id},
        now=now,
    )
    return out


def test_renew_lease_extends_ownership(store: PersistenceStore) -> None:
    rid = _seed(store)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="k-renew",
        request_digest="sha256:r",
        now=now,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=10, now_epoch=100)
    assert claim is not None
    job = store.get_job(out.job_id)
    assert job is not None
    initial_until = int(job["lease_until_epoch"])
    store.renew_lease(
        job_id=claim.job_id,
        lease_owner="w1",
        fencing_token=claim.fencing_token,
        lease_seconds=10,
        now_epoch=105,
    )
    job = store.get_job(out.job_id)
    assert job is not None
    assert int(job["lease_until_epoch"]) == 115
    assert int(job["lease_until_epoch"]) > initial_until


def test_expired_lease_without_renew_reclaims(store: PersistenceStore) -> None:
    """No renew past lease_seconds: recover reclaims; stale owner fence on complete."""
    rid = _seed(store)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="k-no-renew",
        request_digest="sha256:nr",
        now=now,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=2, now_epoch=100)
    assert claim is not None
    job = store.get_job(out.job_id)
    assert job is not None
    assert int(job["lease_until_epoch"]) == 102
    store.recover_expired_leases(now_epoch=103)
    lost = store.get_job(out.job_id)
    assert lost is not None
    assert lost["status"] == "Lost"
    with pytest.raises(StaleFenceError):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            summary_redacted="stale after expiry",
        )


def test_two_workers_different_routers(store: PersistenceStore) -> None:
    site = store.create_site(display_name="S", now=datetime(2026, 7, 22, tzinfo=UTC))
    rid_a = store.enroll_router(
        site_id=site,
        display_name="A",
        vendor="V",
        model="M",
        identity_fingerprint="digest:a",
        host="127.0.0.1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    rid_b = store.enroll_router(
        site_id=site,
        display_name="B",
        vendor="V",
        model="M",
        identity_fingerprint="digest:b",
        host="127.0.0.2",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out_a = _queue_preset_validate(
        store,
        rid_a,
        idempotency_key="ka",
        request_digest="sha256:a",
        preset_id="preset_a",
        now=now,
    )
    out_b = _queue_preset_validate(
        store,
        rid_b,
        idempotency_key="kb",
        request_digest="sha256:b",
        preset_id="preset_b",
        now=now,
    )
    c1 = store.claim_job(worker_id="w1", now_epoch=1000)
    c2 = store.claim_job(worker_id="w2", now_epoch=1000)
    assert c1 is not None and c2 is not None
    assert {c1.job_id, c2.job_id} == {out_a.job_id, out_b.job_id}


def test_stale_fence_on_complete_after_reclaim(store: PersistenceStore) -> None:
    rid = _seed(store)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="k-stale",
        request_digest="sha256:s",
        now=now,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    store.recover_expired_leases(now_epoch=200)
    with pytest.raises(StaleFenceError):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            summary_redacted="stale",
        )


def test_long_handler_with_heartbeat_prevents_reclaim(tmp_path: Path) -> None:
    """Heartbeat ON: DB-time lease renew prevents reclaim during long handler."""
    runtime = create_offline_runtime(db_path=tmp_path / "hb.sqlite3")
    site = runtime.store.create_site(display_name="S", now=runtime.clock.now())
    rid = runtime.store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:x",
        host="127.0.0.1",
        now=runtime.clock.now(),
    )
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="long",
        request_digest="sha256:long",
        initial_job_status="Queued",
        now=runtime.clock.now(),
    )
    runtime.store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload={"simulate_ms": 3500},
        now=runtime.clock.now(),
    )
    worker1 = build_durable_worker(runtime, allow_fake_mutations=True, worker_id="owner")
    worker1.config = WorkerConfig(worker_id="owner", lease_seconds=2, poll_interval_seconds=0.05)
    worker1.start()

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job is not None and job["status"] in ("Leased", "Running"):
            break
        time.sleep(0.05)
    else:
        pytest.fail("worker did not claim job in time")

    job = runtime.store.get_job(out.job_id)
    assert job is not None
    initial_until = int(job["lease_until_epoch"])

    time.sleep(3.0)
    runtime.store.recover_expired_leases()
    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] in ("Leased", "Running")
    assert int(job["lease_until_epoch"]) > initial_until
    claim2 = runtime.store.claim_job(worker_id="w2")
    assert claim2 is None

    finish_by = time.monotonic() + 10.0
    while time.monotonic() < finish_by:
        job = runtime.store.get_job(out.job_id)
        if job is not None and job["status"] in ("Succeeded", "Failed", "Cancelled"):
            break
        time.sleep(0.05)
    else:
        pytest.fail("worker did not finish long handler in time")
    worker1.stop(timeout=5.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "Succeeded"


def test_worker_cancel_finalize_updates_cancel_idempotency(tmp_path: Path) -> None:
    """Running cancel → 202; worker observes cancel → Cancelled + idempotency replay 200."""
    runtime = create_offline_runtime(db_path=tmp_path / "cancel-worker.sqlite3")
    site = runtime.store.create_site(display_name="S", now=runtime.clock.now())
    rid = runtime.store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:cancel",
        host="127.0.0.1",
        now=runtime.clock.now(),
    )
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="k-cancel-worker",
        request_digest="sha256:cancel-worker",
        initial_job_status="Queued",
        now=runtime.clock.now(),
    )
    runtime.store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload={"simulate_ms": 800},
        now=runtime.clock.now(),
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True, worker_id="w-cancel")
    worker.config = WorkerConfig(worker_id="w-cancel", poll_interval_seconds=0.05)
    worker.start()

    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job is not None and job["status"] == "Running":
            break
        time.sleep(0.05)
    else:
        worker.stop(timeout=2.0)
        pytest.fail("worker did not reach Running before cancel")

    http_status, body, _ = runtime.store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-worker-idem",
        request_digest="sha256:cancel-worker-req",
        now=runtime.clock.now(),
    )
    assert http_status == 202
    assert body["cancel_requested"] is True

    replay_202_status, replay_202_body, _ = runtime.store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-worker-idem",
        request_digest="sha256:cancel-worker-req",
        now=runtime.clock.now(),
    )
    assert replay_202_status == 202
    assert replay_202_body["cancel_requested"] is True

    finish_by = time.monotonic() + 5.0
    while time.monotonic() < finish_by:
        job = runtime.store.get_job(out.job_id)
        if job is not None and job["status"] == "Cancelled":
            break
        time.sleep(0.05)
    else:
        worker.stop(timeout=2.0)
        pytest.fail("worker did not finalize cancel")

    replay_status, replay_body, _ = runtime.store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-worker-idem",
        request_digest="sha256:cancel-worker-req",
        now=runtime.clock.now(),
    )
    assert replay_status == 200
    assert replay_body["status"] == "Cancelled"
    assert replay_body["cancel_requested"] is False

    worker.stop(timeout=3.0)


def test_no_heartbeat_allows_reclaim_and_stale_complete(store: PersistenceStore) -> None:
    """Pre-dispatch lease loss: resume Queued job; original owner fence is stale."""
    rid = _seed(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="preset_validate",
        idempotency_key="exp",
        request_digest="sha256:exp",
        correlation_id="preset_x",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    payload = {"preset_id": "preset_x", "source": "test"}
    store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload=payload,
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=1, now_epoch=100)
    assert claim is not None
    store.recover_expired_leases(now_epoch=200)
    lost = store.get_job(out.job_id)
    assert lost is not None
    assert lost["status"] == "Lost"
    resume_jobs = [
        j
        for j in store.list_jobs_for_operation(out.operation_id)
        if j["recovery_state"] == "resume_after_lost"
    ]
    assert len(resume_jobs) == 1
    assert store.get_job_dispatch_payload(resume_jobs[0]["job_id"]) == payload
    claim2 = store.claim_job(worker_id="w2", now_epoch=201)
    assert claim2 is not None
    assert claim2.job_id == resume_jobs[0]["job_id"]
    with pytest.raises(StaleFenceError):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
        )


def test_post_dispatch_expired_lease_recovery_required(store: PersistenceStore) -> None:
    """Post-dispatch progress: no blind requeue; stale owner cannot complete or progress."""
    rid = _seed(store)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="post-dispatch",
        request_digest="sha256:pd",
        now=now,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner="w1",
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="dispatch",
        step_status="Running",
    )
    store.recover_expired_leases(now_epoch=200)
    job = store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    assert not any(
        j["recovery_state"] == "resume_after_lost"
        for j in store.list_jobs_for_operation(out.operation_id)
    )
    with pytest.raises(StaleFenceError):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            summary_redacted="stale",
        )
    with pytest.raises(StaleFenceError):
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            step_kind="handler",
            step_status="Succeeded",
        )


def test_post_dispatch_handler_step_triggers_recovery_required(store: PersistenceStore) -> None:
    rid = _seed(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="handler-step",
        request_digest="sha256:hs",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner="w1",
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="handler",
        step_status="Running",
    )
    store.recover_expired_leases(now_epoch=200)
    job = store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "RecoveryRequired"


def test_record_job_progress_stale_fence_no_orphan_step(store: PersistenceStore) -> None:
    """Stale owner after reclaim cannot append job_steps; step count unchanged."""
    rid = _seed(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="progress-stale",
        request_digest="sha256:progress-stale",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner="w1",
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="apply",
        step_status="Running",
    )
    steps_before = len(store.list_job_steps(out.job_id))
    store.recover_expired_leases(now_epoch=200)
    with pytest.raises(StaleFenceError):
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            step_kind="verify",
            step_status="Running",
        )
    assert len(store.list_job_steps(out.job_id)) == steps_before


def test_complete_job_clears_late_cancel_and_updates_cancel_idempotency(
    store: PersistenceStore,
) -> None:
    """Late Succeeded completion clears cancel_requested and replays cancel as 409."""
    rid = _seed(store)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="late-cancel-store",
        request_digest="sha256:late-cancel-store",
        initial_job_status="Queued",
        now=now,
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=30, now=now)
    assert claim is not None
    store.record_job_progress(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="apply",
        step_status="Succeeded",
        now=now,
    )
    store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-late-store",
        request_digest="sha256:cancel-late-store",
        now=now,
    )
    job = store.get_job(out.job_id)
    assert job is not None and int(job["cancel_requested"]) == 1

    store.complete_job(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        status="Succeeded",
        summary_redacted="converged after late cancel",
        http_status=200,
        response_body={"status": "Succeeded", "job_id": out.job_id},
        now=now,
    )
    job = store.get_job(out.job_id)
    assert job is not None and job["status"] == "Succeeded"
    assert not int(job["cancel_requested"])

    replay_status, replay_body, _ = store.cancel_job(
        target_job_id=out.job_id,
        idempotency_key="cancel-late-store",
        request_digest="sha256:cancel-late-store",
        now=now,
    )
    assert replay_status == 409
    assert replay_body["error"]["code"] == "job.already_terminal"

    with pytest.raises(ConflictError, match="already terminal"):
        store.cancel_job(
            target_job_id=out.job_id,
            idempotency_key="cancel-late-store-new",
            request_digest="sha256:cancel-late-store-new",
            now=now,
        )


def test_stale_progress_race_after_reclaim_two_connections(tmp_path: Path) -> None:
    """Two SQLite connections: reclaim then stale progress must not append steps."""
    db_path = tmp_path / "stale-progress-race.sqlite3"
    store_a = PersistenceStore(open_database(db_path))
    store_b = PersistenceStore(open_database(db_path))
    rid = _seed(store_a)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = store_a.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="stale-race",
        request_digest="sha256:stale-race",
        initial_job_status="Queued",
        now=now,
    )
    claim = store_a.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    store_a.record_job_progress(
        job_id=out.job_id,
        lease_owner=claim.lease_owner,
        fencing_token=claim.fencing_token,
        status="Running",
        step_kind="apply",
        step_status="Running",
        now_epoch=100,
    )
    steps_before = len(store_a.list_job_steps(out.job_id))

    start_barrier = threading.Barrier(2, timeout=5)
    reclaim_barrier = threading.Barrier(2, timeout=5)
    reclaim_errors: list[BaseException] = []
    stale_outcome: list[str] = []

    def reclaim_thread() -> None:
        try:
            start_barrier.wait()
            store_b.recover_expired_leases(now_epoch=200)
            reclaim_barrier.wait()
        except BaseException as exc:
            reclaim_errors.append(exc)

    def stale_thread() -> None:
        try:
            start_barrier.wait()
            reclaim_barrier.wait()
            store_a.record_job_progress(
                job_id=out.job_id,
                lease_owner=claim.lease_owner,
                fencing_token=claim.fencing_token,
                step_kind="verify",
                step_status="Running",
            )
            stale_outcome.append("unexpected_ok")
        except StaleFenceError:
            stale_outcome.append("stale")
        except BaseException as exc:
            stale_outcome.append(f"error:{exc!r}")

    t_reclaim = threading.Thread(target=reclaim_thread, name="reclaim")
    t_stale = threading.Thread(target=stale_thread, name="stale")
    t_reclaim.start()
    t_stale.start()
    t_reclaim.join(timeout=10)
    t_stale.join(timeout=10)
    assert not reclaim_errors, reclaim_errors
    assert stale_outcome == ["stale"]
    assert len(store_a.list_job_steps(out.job_id)) == steps_before


def test_runtime_worker_store_separate_from_api_store(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "dual-conn.sqlite3")
    worker = build_durable_worker(runtime)
    assert worker.store is not runtime.store


def test_transaction_nest_guard_fail_closed(store: PersistenceStore) -> None:
    conn = store._conn
    with pytest.raises(NestedTransactionError, match="cannot start a transaction"):
        with transaction(conn, immediate=True):
            with transaction(conn, immediate=True):
                pass
    assert not conn.in_transaction


def test_transaction_exception_rollback_then_next_succeeds(store: PersistenceStore) -> None:
    rid = _seed(store)
    conn = store._conn
    with pytest.raises(ValueError, match="rollback probe"):
        with transaction(conn, immediate=True):
            raise ValueError("rollback probe")
    assert not conn.in_transaction
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="preset_validate",
        idempotency_key="post-rollback",
        request_digest="sha256:post-rollback",
        initial_job_status="Queued",
        dispatch_payload={"preset_id": "preset_post_rollback"},
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    assert out.created is True


def test_simultaneous_worker_and_api_store_transactions(tmp_path: Path) -> None:
    """Worker IMMEDIATE claim and API IMMEDIATE bundle on separate connections."""
    runtime = create_offline_runtime(db_path=tmp_path / "conc.sqlite3")
    api_store = runtime.store
    worker = build_durable_worker(runtime, worker_id="conc-worker")
    worker_store = worker.store
    site = api_store.create_site(display_name="Conc", now=datetime(2026, 7, 22, tzinfo=UTC))
    rid_worker = api_store.enroll_router(
        site_id=site,
        display_name="Worker Router",
        vendor="V",
        model="M",
        identity_fingerprint="digest:conc-worker",
        host="127.0.0.1",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    rid_api = api_store.enroll_router(
        site_id=site,
        display_name="API Router",
        vendor="V",
        model="M",
        identity_fingerprint="digest:conc-api",
        host="127.0.0.2",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    worker_out = api_store.create_operation_bundle(
        router_id=rid_worker,
        operation_kind="preset_validate",
        idempotency_key="worker-job",
        request_digest="sha256:worker-job",
        initial_job_status="Queued",
        dispatch_payload={"preset_id": "preset_worker"},
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    errors: list[tuple[str, BaseException]] = []
    barrier = threading.Barrier(2, timeout=5)

    def worker_claim() -> None:
        try:
            barrier.wait()
            claim = worker_store.claim_job(worker_id="conc-worker", now_epoch=5000)
            assert claim is not None
            assert claim.job_id == worker_out.job_id
        except BaseException as exc:
            errors.append(("worker", exc))

    def api_bundle() -> None:
        try:
            barrier.wait()
            out = api_store.create_operation_bundle(
                router_id=rid_api,
                operation_kind="preset_validate",
                idempotency_key="api-job",
                request_digest="sha256:api-job",
                initial_job_status="Queued",
                now=datetime(2026, 7, 22, tzinfo=UTC),
            )
            assert out.created is True
        except BaseException as exc:
            errors.append(("api", exc))

    t_worker = threading.Thread(target=worker_claim, name="worker-claim")
    t_api = threading.Thread(target=api_bundle, name="api-bundle")
    t_worker.start()
    t_api.start()
    t_worker.join(timeout=10)
    t_api.join(timeout=10)
    assert not errors, errors
    job = api_store.get_job(worker_out.job_id)
    assert job is not None
    assert job["status"] == "Leased"
    assert int(job["fencing_token"]) >= 1


def test_claim_skips_queued_job_until_dispatch_payload(tmp_path: Path) -> None:
    """Worker store must not claim payload-required Queued jobs before dispatch insert."""
    runtime = create_offline_runtime(db_path=tmp_path / "payload-race.sqlite3")
    api_store = runtime.store
    worker = build_durable_worker(runtime, worker_id="w1")
    worker_store = worker.store
    now = datetime(2026, 7, 22, tzinfo=UTC)
    site = api_store.create_site(display_name="PayloadRace", now=now)
    rid = api_store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:payload-race",
        host="127.0.0.1",
        now=now,
    )
    out = api_store.create_operation_bundle(
        router_id=rid,
        operation_kind="preset_validate",
        idempotency_key="payload-race",
        request_digest="sha256:payload-race",
        initial_job_status="Queued",
        now=now,
    )
    claim_before = worker_store.claim_job(worker_id="w1", now_epoch=1000)
    assert claim_before is None
    job_before = api_store.get_job(out.job_id)
    assert job_before is not None
    assert job_before["status"] == "Queued"

    api_store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload={"preset_id": "preset_race"},
        now=now,
    )
    claim_after = worker_store.claim_job(worker_id="w1", now_epoch=1001)
    assert claim_after is not None
    assert claim_after.job_id == out.job_id
    job_after = api_store.get_job(out.job_id)
    assert job_after is not None
    assert job_after["status"] == "Leased"


def test_atomic_preset_validate_enqueue_immediately_claimable(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "atomic-preset-svc.sqlite3")
    worker = build_durable_worker(runtime, worker_id="w1")
    now = datetime(2026, 7, 22, tzinfo=UTC)
    site = runtime.store.create_site(display_name="AtomicPresetSvc", now=now)
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site,
        name="Atomic",
        document=None,
        idempotency_key="atomic-preset-create",
        request_digest="sha256:atomic-preset-create",
    )
    body = runtime.event_presets.enqueue_validate_async(
        preset_id=preset["preset_id"],
        idempotency_key="atomic-preset-validate-svc",
        request_digest="sha256:atomic-preset-validate-svc",
    )
    job_id = body["job_id"]
    claim = worker.store.claim_job(worker_id="w1", now_epoch=2000)
    assert claim is not None
    assert claim.job_id == job_id
    assert runtime.store.get_job_dispatch_payload(job_id) == {
        "preset_id": preset["preset_id"],
    }


def test_atomic_preset_plan_readiness_enqueue_immediately_claimable(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "atomic-plan-svc.sqlite3")
    worker = build_durable_worker(runtime, worker_id="w1")
    now = datetime(2026, 7, 22, tzinfo=UTC)
    site = runtime.store.create_site(display_name="AtomicPlanSvc", now=now)
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site,
        name="AtomicPlan",
        document=None,
        idempotency_key="atomic-plan-create",
        request_digest="sha256:atomic-plan-create",
    )
    body = runtime.event_presets.enqueue_plan_readiness_async(
        preset_id=preset["preset_id"],
        idempotency_key="atomic-plan-readiness-svc",
        request_digest="sha256:atomic-plan-readiness-svc",
    )
    job_id = body["job_id"]
    claim = worker.store.claim_job(worker_id="w1", now_epoch=2500)
    assert claim is not None
    assert claim.job_id == job_id
    assert runtime.store.get_job_dispatch_payload(job_id) == {
        "preset_id": preset["preset_id"],
    }


def test_atomic_commissioning_assess_enqueue_immediately_claimable(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "atomic-comm-svc.sqlite3")
    worker = build_durable_worker(runtime, worker_id="w1")
    now = datetime(2026, 7, 22, tzinfo=UTC)
    site = runtime.store.create_site(display_name="AtomicCommSvc", now=now)
    router_id = runtime.store.enroll_router(
        site_id=site,
        display_name="R",
        vendor="V",
        model="M",
        identity_fingerprint="digest:atomic-comm-svc",
        host="127.0.0.1",
        now=now,
    )
    run, _ = runtime.store.create_commissioning_run(
        site_id=site,
        router_id=router_id,
        mode="fake",
        idempotency_key="atomic-comm-create",
        request_digest="sha256:atomic-comm-create",
        now=now,
    )
    expected_payload = {
        "run_id": run["run_id"],
        "idempotency_key": "atomic-comm-assess-svc",
        "request_digest": "sha256:atomic-comm-assess-svc",
        "expected_version": None,
    }
    body = runtime.commissioning.enqueue_assess_async(
        run_id=run["run_id"],
        router_id=router_id,
        idempotency_key="atomic-comm-assess-svc",
        request_digest="sha256:atomic-comm-assess-svc",
    )
    job_id = body["job_id"]
    claim = worker.store.claim_job(worker_id="w1", now_epoch=3000)
    assert claim is not None
    assert claim.job_id == job_id
    assert runtime.store.get_job_dispatch_payload(job_id) == expected_payload


def test_expired_lease_rejects_complete_without_reclaim(store: PersistenceStore) -> None:
    rid = _seed(store)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="lease-exp-complete",
        request_digest="sha256:lease-exp-complete",
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    with pytest.raises(StaleFenceError, match="lease expired"):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            now_epoch=200,
        )


def test_expired_lease_rejects_progress_without_reclaim(store: PersistenceStore) -> None:
    rid = _seed(store)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="lease-exp-progress",
        request_digest="sha256:lease-exp-progress",
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    with pytest.raises(StaleFenceError, match="lease expired"):
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            step_kind="handler",
            step_status="Running",
            now_epoch=200,
        )


def test_expired_lease_rejects_renew(store: PersistenceStore) -> None:
    rid = _seed(store)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="lease-exp-renew",
        request_digest="sha256:lease-exp-renew",
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=5, now_epoch=100)
    assert claim is not None
    with pytest.raises(StaleFenceError, match="lease expired"):
        store.renew_lease(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            lease_seconds=10,
            now_epoch=200,
        )


def test_expired_lease_rejects_complete_with_now_datetime(store: PersistenceStore) -> None:
    rid = _seed(store)
    claim_at = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)
    expired_at = datetime(2026, 7, 22, 12, 0, 30, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="lease-exp-complete-dt",
        request_digest="sha256:lease-exp-complete-dt",
    )
    claim = store.claim_job(
        worker_id="w1", lease_seconds=5, now_epoch=100, now=claim_at
    )
    assert claim is not None
    with pytest.raises(StaleFenceError, match="lease expired"):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            now=expired_at,
            now_epoch=200,
        )


def test_expired_lease_rejects_progress_with_now_datetime(store: PersistenceStore) -> None:
    rid = _seed(store)
    claim_at = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)
    expired_at = datetime(2026, 7, 22, 12, 0, 30, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="lease-exp-progress-dt",
        request_digest="sha256:lease-exp-progress-dt",
    )
    claim = store.claim_job(
        worker_id="w1", lease_seconds=5, now_epoch=100, now=claim_at
    )
    assert claim is not None
    with pytest.raises(StaleFenceError, match="lease expired"):
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            step_kind="handler",
            step_status="Running",
            now=expired_at,
            now_epoch=200,
        )


def test_stale_router_fence_rejects_complete_with_now_datetime(store: PersistenceStore) -> None:
    rid = _seed(store)
    claim_at = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)
    fence_expired_at = datetime(2026, 7, 22, 12, 0, 10, tzinfo=UTC)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="stale-fence-complete-dt",
        request_digest="sha256:stale-fence-complete-dt",
    )
    claim = store.claim_job(
        worker_id="w1", lease_seconds=300, now_epoch=100, now=claim_at
    )
    assert claim is not None
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=5,
        active_job_id=out.job_id,
        now=claim_at,
        now_epoch=100,
    )
    with pytest.raises(StaleFenceError, match="fence expired"):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            now=fence_expired_at,
            now_epoch=110,
        )


def test_stale_router_fence_rejects_complete(store: PersistenceStore) -> None:
    rid = _seed(store)
    out = _queue_preset_validate(
        store,
        rid,
        idempotency_key="stale-fence-complete",
        request_digest="sha256:stale-fence-complete",
    )
    claim = store.claim_job(worker_id="w1", lease_seconds=300, now_epoch=100)
    assert claim is not None
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=5,
        active_job_id=out.job_id,
        now_epoch=100,
    )
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w2",
        mutex_holder_id="inst-2",
        lease_seconds=30,
        active_job_id=None,
        now_epoch=200,
        os_mutex_held=True,
    )
    with pytest.raises(StaleFenceError, match="fence|lease owner"):
        store.complete_job(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            status="Succeeded",
            now_epoch=205,
        )


def test_complete_job_does_not_clobber_success_idempotency(
    store: PersistenceStore,
) -> None:
    """Defense-in-depth: worker Failed must not overwrite sync 2xx idempotency body."""
    rid = _seed(store)
    now = datetime(2026, 7, 22, tzinfo=UTC)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="import_profile",
        idempotency_key="sync-success-idem",
        request_digest="sha256:sync-success",
        initial_job_status="Queued",
        now=now,
    )
    success_body = {"profile_id": "prof-sync-1", "display_name": "Race"}
    store.update_idempotency_response(
        out.idempotency_record_id,
        http_status=201,
        body=success_body,
    )
    claim = store.claim_job(worker_id="w-race", now_epoch=1000)
    assert claim is not None
    store.complete_job(
        job_id=claim.job_id,
        lease_owner="w-race",
        fencing_token=claim.fencing_token,
        status="Failed",
        http_status=403,
        response_body={"error": {"code": "mutation.forbidden"}},
        now_epoch=1001,
    )
    idem = store.get_idempotency_for_operation(out.operation_id)
    assert idem is not None
    stored = json.loads(idem["response_ref"])
    assert stored["http_status"] == 201
    assert stored["body"]["profile_id"] == "prof-sync-1"
