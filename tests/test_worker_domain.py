"""Durable worker domain: lifecycle, stop, backoff, injected clock/sleeper."""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from router_control.application.worker import WorkerConfig, WorkerLifecycle
from router_control.composition import FixedClock, build_durable_worker, create_offline_runtime


class FakeSleeper:
    def __init__(self) -> None:
        self.calls: list[float] = []

    def sleep(self, seconds: float) -> None:
        self.calls.append(seconds)


def test_worker_lifecycle_start_stop(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "worker-domain.sqlite3")
    worker = build_durable_worker(runtime, worker_id="t1")
    worker.start()
    deadline = time.monotonic() + 2.0
    while worker.lifecycle != WorkerLifecycle.RUNNING and time.monotonic() < deadline:
        time.sleep(0.05)
    assert worker.lifecycle == WorkerLifecycle.RUNNING
    worker.stop(timeout=3.0)
    assert worker.lifecycle == WorkerLifecycle.STOPPED


def test_graceful_stop_waits_for_poll(tmp_path: Path) -> None:
    clock = FixedClock(datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC))
    runtime = create_offline_runtime(db_path=tmp_path / "worker-stop.sqlite3", clock=clock)
    sleeper = FakeSleeper()
    worker = build_durable_worker(runtime, worker_id="t2")
    worker.config = WorkerConfig(worker_id="t2", poll_interval_seconds=0.1)
    worker.sleeper = sleeper
    worker.start()
    time.sleep(0.3)
    worker.stop(timeout=2.0)
    assert worker.lifecycle == WorkerLifecycle.STOPPED


def test_one_claim_loop_no_unbounded_spawn(tmp_path: Path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "worker-loop.sqlite3")
    site = runtime.store.create_site(display_name="Lab", now=runtime.clock.now())
    rid = runtime.store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:1",
        host="127.0.0.1",
        now=runtime.clock.now(),
    )
    runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="commissioning_assess_readonly",
        idempotency_key="k1",
        request_digest="sha256:a",
        correlation_id="crun_test",
        initial_job_status="Queued",
        now=runtime.clock.now(),
    )
    worker = build_durable_worker(runtime, worker_id="t3")
    threads_before = threading.active_count()
    worker.start()
    time.sleep(0.5)
    worker.stop(timeout=2.0)
    assert threading.active_count() <= threads_before + 1
