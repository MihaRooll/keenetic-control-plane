"""P1-A router execution fence and process mutex."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.application.worker import router_process_mutex
from router_control.persistence.connection import open_database
from router_control.persistence.errors import (
    FenceExpiredError,
    MutexHolderRequiredError,
    StaleFenceError,
)
from router_control.persistence.store import PersistenceStore


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "fence.sqlite3"))


def _seed_router(store: PersistenceStore) -> str:
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


def test_fence_monotonic_and_renew(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    t1 = store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=30,
        now_epoch=100,
    )
    assert t1 == 1
    store.renew_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        fence_token=1,
        lease_seconds=30,
        now_epoch=110,
    )
    t2 = store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=30,
        now_epoch=200,
        os_mutex_held=True,
    )
    assert t2 == 2


def test_expired_fence_rejects_renew(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=5,
        now_epoch=100,
    )
    with pytest.raises(FenceExpiredError):
        store.renew_router_execution_fence(
            router_id=rid,
            lease_owner="w1",
            mutex_holder_id="inst-1",
            fence_token=1,
            lease_seconds=5,
            now_epoch=200,
        )


def test_mutex_holder_mismatch_rejected(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=30,
        now_epoch=100,
    )
    with pytest.raises(MutexHolderRequiredError):
        store.acquire_router_execution_fence(
            router_id=rid,
            lease_owner="w2",
            mutex_holder_id="inst-2",
            lease_seconds=30,
            now_epoch=105,
        )


def test_reap_expired_fences_bounded(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=1,
        now_epoch=100,
    )
    reaped = store.reap_expired_router_execution_fences(now_epoch=200, limit=10)
    assert rid in reaped
    assert store.get_router_execution_fence(rid) is None


def test_process_mutex_serializes_same_router() -> None:
    rid = "router-test-mutex"
    seen: list[int] = []

    def one() -> None:
        with router_process_mutex(rid):
            seen.append(1)

    def two() -> None:
        with router_process_mutex(rid):
            seen.append(2)

    import threading

    t1 = threading.Thread(target=one)
    t2 = threading.Thread(target=two)
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert len(seen) == 2


def test_process_mutex_serializes_subprocesses(tmp_path: Path) -> None:
    import os
    import subprocess
    import sys
    import textwrap

    counter = tmp_path / "counter.txt"
    counter.write_text("0", encoding="utf-8")
    start = tmp_path / "start.txt"
    router_id = "router-subprocess-mutex-test"
    child_script = textwrap.dedent(
        f"""
        import os
        import sys
        from pathlib import Path
        from router_control.application.worker import router_process_mutex

        counter = Path({str(counter)!r})
        start = Path({str(start)!r})
        while not start.exists():
            pass
        with router_process_mutex({router_id!r}):
            value = int(counter.read_text(encoding="utf-8"))
            counter.write_text(str(value + 1), encoding="utf-8")
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", child_script],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    start.write_text("go", encoding="utf-8")
    for proc in procs:
        proc.wait(timeout=30)
        assert proc.returncode == 0
    assert int(counter.read_text(encoding="utf-8")) == 2


def test_expired_fence_takeover_requires_os_mutex(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=5,
        now_epoch=100,
    )
    with pytest.raises(MutexHolderRequiredError, match="os mutex"):
        store.acquire_router_execution_fence(
            router_id=rid,
            lease_owner="w2",
            mutex_holder_id="inst-2",
            lease_seconds=30,
            now_epoch=200,
            os_mutex_held=False,
        )


def test_release_fence_requires_matching_token(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    token = store.acquire_router_execution_fence(
        router_id=rid,
        lease_owner="w1",
        mutex_holder_id="inst-1",
        lease_seconds=30,
        now_epoch=100,
    )
    with pytest.raises(StaleFenceError):
        store.release_router_execution_fence(
            router_id=rid,
            lease_owner="w1",
            mutex_holder_id="inst-1",
            fence_token=token + 1,
        )


def test_stale_fence_rejects_job_progress_when_mismatched(store: PersistenceStore) -> None:
    rid = _seed_router(store)
    out = store.create_operation_bundle(
        router_id=rid,
        operation_kind="preset_validate",
        idempotency_key="fence-progress",
        request_digest="sha256:fence-progress",
        initial_job_status="Queued",
        now=datetime(2026, 7, 22, tzinfo=UTC),
    )
    store.insert_job_dispatch_payload(
        job_id=out.job_id,
        payload={"preset_id": "p1"},
        now=datetime(2026, 7, 22, tzinfo=UTC),
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
        store.record_job_progress(
            job_id=out.job_id,
            lease_owner="w1",
            fencing_token=claim.fencing_token,
            step_kind="dispatch",
            step_status="Running",
            now_epoch=205,
        )
