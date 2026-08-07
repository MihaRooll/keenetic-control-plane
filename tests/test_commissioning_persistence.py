"""Commissioning persistence migration and CRUD."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.application.commissioning import CommissioningService
from router_control.composition import FixedClock
from router_control.persistence.connection import open_database
from router_control.persistence.errors import ConflictError, IdempotencyConflict, PreconditionFailed
from router_control.persistence.migrations import CURRENT_USER_VERSION, migrate
from router_control.persistence.store import PersistenceStore, _utc_now_iso

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    conn = open_database(tmp_path / "comm.sqlite3")
    return PersistenceStore(conn)


def _seed_router(store: PersistenceStore) -> tuple[str, str]:
    site_id = store.create_site(display_name="Lab", now=FIXED)
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="R1",
        vendor="FakeVendor",
        model="Fake",
        identity_fingerprint="digest:fp",
        host="127.0.0.1",
        now=FIXED,
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (router_id,),
    )
    store.insert_observation(
        router_id=router_id,
        identity_fingerprint="digest:fp",
        resource_version="v1",
        state_digest="sha256:state",
        now=FIXED,
    )
    return site_id, router_id


def test_migration_reaches_version_2(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "m.sqlite3")
    assert migrate(conn) == CURRENT_USER_VERSION
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "commissioning_runs" in tables
    assert "readiness_checks" in tables


def test_migration_1_to_2_adds_commissioning_tables(tmp_path: Path) -> None:
    import sqlite3

    from router_control.persistence import migrations

    path = tmp_path / "v1.sqlite3"
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(migrations._MIGRATION_1)
        conn.execute("PRAGMA user_version = 1")
        before = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "commissioning_runs" not in before
        assert migrate(conn) == CURRENT_USER_VERSION
        after = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "commissioning_runs" in after
        assert "readiness_checks" in after
        assert "commissioning_idempotency" in after
    finally:
        conn.close()


def test_create_run_idempotent(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run1, created1 = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="k1",
        request_digest="sha256:a",
        now=FIXED,
    )
    run2, created2 = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="k1",
        request_digest="sha256:a",
        now=FIXED,
    )
    assert created1 is True
    assert created2 is False
    assert run1["run_id"] == run2["run_id"]


def test_create_idempotency_conflict(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="k1",
        request_digest="sha256:a",
        now=FIXED,
    )
    with pytest.raises(IdempotencyConflict):
        store.create_commissioning_run(
            site_id=site_id,
            router_id=router_id,
            mode="fake",
            idempotency_key="k1",
            request_digest="sha256:b",
            now=FIXED,
        )


def test_append_check_and_optimistic_version(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="k2",
        request_digest="sha256:c",
        now=FIXED,
    )
    store.append_readiness_check(
        run_id=run["run_id"],
        check_kind="enroll_status",
        ordinal=0,
        attempt=1,
        outcome="Passed",
        blocking=True,
        write_related=False,
        summary_redacted="ok",
        now=FIXED,
    )
    updated = store.update_commissioning_run_state(
        run_id=run["run_id"],
        expected_version=1,
        new_state="Observing",
        now=FIXED,
    )
    assert updated["version"] == 2
    with pytest.raises(PreconditionFailed):
        store.update_commissioning_run_state(
            run_id=run["run_id"],
            expected_version=1,
            new_state="Failed",
            now=FIXED,
        )


def _assess_run(store: PersistenceStore, run_id: str, *, key: str = "assess-k1") -> None:
    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)
    svc.assess_run(
        run_id=run_id,
        idempotency_key=key,
        request_digest="sha256:assess",
    )


def test_assess_replay_same_key_digest(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k",
        request_digest="sha256:create",
        now=FIXED,
    )
    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)
    probe_calls = {"n": 0}

    def probe(**_kwargs: object) -> dict[str, object]:
        probe_calls["n"] += 1
        return {"matched": True}

    svc.probe_fn = probe  # type: ignore[method-assign]
    svc.gate_a_open = lambda: True  # type: ignore[method-assign]
    svc.matches_probe_evidence = lambda _e: True  # type: ignore[method-assign]
    run["mode"] = "live"
    store._conn.execute(
        "UPDATE commissioning_runs SET mode = 'live' WHERE run_id = ?",
        (run["run_id"],),
    )
    _, checks1, created1 = svc.assess_run(
        run_id=run["run_id"],
        idempotency_key="assess-replay",
        request_digest="sha256:replay",
    )
    _, checks2, created2 = svc.assess_run(
        run_id=run["run_id"],
        idempotency_key="assess-replay",
        request_digest="sha256:replay",
    )
    assert created1 is True
    assert created2 is False
    assert checks1 == checks2
    assert probe_calls["n"] == 1


def test_assess_digest_conflict(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k2",
        request_digest="sha256:create2",
        now=FIXED,
    )
    _assess_run(store, run["run_id"], key="assess-conflict")
    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)
    with pytest.raises(IdempotencyConflict):
        svc.store.prepare_commissioning_assess(
            run_id=run["run_id"],
            idempotency_key="assess-conflict",
            request_digest="sha256:other-digest",
            expected_version=None,
            now=FIXED,
        )


def test_compute_assess_does_not_query_unlocked_store_sql(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k3b",
        request_digest="sha256:create3b",
        now=FIXED,
    )
    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)

    def forbidden_next_attempt(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("_next_check_attempt must not run during compute/probe")

    store._next_check_attempt = forbidden_next_attempt  # type: ignore[method-assign]
    _, checks, created = svc.assess_run(
        run_id=run["run_id"],
        idempotency_key="assess-in-memory-attempt",
        request_digest="sha256:in-memory-attempt",
    )
    assert created is True
    assert checks
    assert all(int(c["attempt"]) == 1 for c in checks)


def test_assess_in_progress_conflict(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k3",
        request_digest="sha256:create3",
        now=FIXED,
    )
    prepared = store.prepare_commissioning_assess(
        run_id=run["run_id"],
        idempotency_key="assess-in-progress",
        request_digest="sha256:in-progress",
        expected_version=None,
        now=FIXED,
    )
    assert prepared.reservation is not None
    with pytest.raises(ConflictError, match="assess in progress"):
        store.prepare_commissioning_assess(
            run_id=run["run_id"],
            idempotency_key="assess-in-progress",
            request_digest="sha256:in-progress",
            expected_version=None,
            now=FIXED,
        )


def test_assess_compute_outside_txn_allows_other_store_txn(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k4",
        request_digest="sha256:create4",
        now=FIXED,
    )
    gate = threading.Event()
    probe_entered = threading.Event()
    parallel_done = threading.Event()
    blocker = threading.Event()
    parallel_ok: list[str] = []

    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)

    def probe(**_kwargs: object) -> dict[str, object]:
        gate.set()
        probe_entered.set()
        blocker.wait(timeout=5)
        return {"matched": True}

    svc.probe_fn = probe  # type: ignore[method-assign]
    svc.gate_a_open = lambda: True  # type: ignore[method-assign]
    svc.matches_probe_evidence = lambda _e: True  # type: ignore[method-assign]
    store._conn.execute(
        "UPDATE commissioning_runs SET mode = 'live' WHERE run_id = ?",
        (run["run_id"],),
    )

    def assess_thread() -> None:
        svc.assess_run(
            run_id=run["run_id"],
            idempotency_key="assess-txn-escape",
            request_digest="sha256:txn-escape",
        )

    def parallel_store_method() -> None:
        assert gate.wait(timeout=5)
        site_id = store.create_site(display_name="ParallelDuringAssess", now=FIXED)
        parallel_ok.append(site_id)
        parallel_done.set()

    t_assess = threading.Thread(target=assess_thread)
    t_parallel = threading.Thread(target=parallel_store_method)
    t_assess.start()
    assert probe_entered.wait(timeout=5)
    t_parallel.start()
    assert parallel_done.wait(timeout=5), "parallel store method must commit before probe unblocks"
    blocker.set()
    t_assess.join(timeout=10)
    t_parallel.join(timeout=10)
    assert len(parallel_ok) == 1


def test_assess_exception_cleanup_not_assessing_null(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k5",
        request_digest="sha256:create5",
        now=FIXED,
    )
    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)
    with patch.object(
        CommissioningService,
        "_compute_assess",
        side_effect=RuntimeError("boom"),
    ):
        run_out, _checks, _created = svc.assess_run(
            run_id=run["run_id"],
            idempotency_key="assess-fail",
            request_digest="sha256:fail",
        )
    assert run_out["state"] == "Failed"
    row = store.get_commissioning_run(run["run_id"])
    assert row is not None
    assert str(row["state"]) != "Assessing"
    idem = store._conn.execute(
        "SELECT response_ref FROM commissioning_idempotency WHERE idempotency_key = ?",
        ("assess-fail",),
    ).fetchone()
    assert idem is not None
    assert idem["response_ref"] is not None


def test_assess_finalize_rejects_stale_fence(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k6",
        request_digest="sha256:create6",
        now=FIXED,
    )
    prepared = store.prepare_commissioning_assess(
        run_id=run["run_id"],
        idempotency_key="assess-fence",
        request_digest="sha256:fence",
        expected_version=None,
        now=FIXED,
    )
    assert prepared.reservation is not None
    reservation = prepared.reservation
    store.cancel_commissioning_run_idempotent(
        run_id=run["run_id"],
        idempotency_key="cancel-fence",
        request_digest="sha256:cancel",
        expected_version=None,
        now=FIXED,
    )
    run_dict, _checks, created = store.finalize_commissioning_assess(
        reservation,
        terminal_state="ReadyReadOnly",
        summary_redacted="should not apply",
        report_digest="sha256:none",
        assessed_at=_utc_now_iso(FIXED),
        checks=[],
        now=FIXED,
    )
    assert created is False
    assert run_dict["state"] == "Cancelled"
    idem = store._conn.execute(
        "SELECT response_ref FROM commissioning_idempotency WHERE idempotency_key = ?",
        ("assess-fence",),
    ).fetchone()
    assert idem is not None
    assert idem["response_ref"] is not None
    replay = store.prepare_commissioning_assess(
        run_id=run["run_id"],
        idempotency_key="assess-fence",
        request_digest="sha256:fence",
        expected_version=None,
        now=FIXED,
    )
    assert replay.replay is not None


def test_assess_ownership_lost_fail_clears_stuck_in_progress(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k7",
        request_digest="sha256:create7",
        now=FIXED,
    )
    prepared = store.prepare_commissioning_assess(
        run_id=run["run_id"],
        idempotency_key="assess-ownership-lost",
        request_digest="sha256:ownership-lost",
        expected_version=None,
        now=FIXED,
    )
    assert prepared.reservation is not None
    reservation = prepared.reservation
    store.cancel_commissioning_run_idempotent(
        run_id=run["run_id"],
        idempotency_key="cancel-ownership",
        request_digest="sha256:cancel-ownership",
        expected_version=None,
        now=FIXED,
    )
    fail_checks = [
        {
            "check_kind": "gate_a_open",
            "ordinal": 0,
            "attempt": 1,
            "outcome": "Failed",
            "blocking": True,
            "write_related": False,
            "summary_redacted": "assess error: RuntimeError",
            "evidence_digest": None,
        }
    ]
    run_dict, _checks, created = store.fail_commissioning_assess(
        reservation,
        summary_redacted="read-only assessment failed",
        report_digest="sha256:fail",
        assessed_at=_utc_now_iso(FIXED),
        checks=fail_checks,
        now=FIXED,
    )
    assert created is False
    assert run_dict["state"] == "Cancelled"
    idem = store._conn.execute(
        "SELECT response_ref FROM commissioning_idempotency WHERE idempotency_key = ?",
        ("assess-ownership-lost",),
    ).fetchone()
    assert idem is not None
    assert idem["response_ref"] is not None
    replay = store.prepare_commissioning_assess(
        run_id=run["run_id"],
        idempotency_key="assess-ownership-lost",
        request_digest="sha256:ownership-lost",
        expected_version=None,
        now=FIXED,
    )
    assert replay.replay is not None


def test_assess_run_cancel_during_probe_not_stuck_in_progress(store: PersistenceStore) -> None:
    site_id, router_id = _seed_router(store)
    run, _ = store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="create-k8",
        request_digest="sha256:create8",
        now=FIXED,
    )
    gate = threading.Event()
    probe_entered = threading.Event()
    blocker = threading.Event()

    clock = FixedClock(FIXED)
    svc = CommissioningService(store=store, clock=clock)

    def probe(**_kwargs: object) -> dict[str, object]:
        gate.set()
        probe_entered.set()
        blocker.wait(timeout=5)
        return {"matched": True}

    svc.probe_fn = probe  # type: ignore[method-assign]
    svc.gate_a_open = lambda: True  # type: ignore[method-assign]
    svc.matches_probe_evidence = lambda _e: True  # type: ignore[method-assign]
    store._conn.execute(
        "UPDATE commissioning_runs SET mode = 'live' WHERE run_id = ?",
        (run["run_id"],),
    )

    def assess_thread() -> None:
        svc.assess_run(
            run_id=run["run_id"],
            idempotency_key="assess-cancel-during-probe",
            request_digest="sha256:cancel-during-probe",
        )

    t_assess = threading.Thread(target=assess_thread)
    t_assess.start()
    assert probe_entered.wait(timeout=5)
    store.cancel_commissioning_run_idempotent(
        run_id=run["run_id"],
        idempotency_key="cancel-during-probe",
        request_digest="sha256:cancel-during-probe",
        expected_version=None,
        now=FIXED,
    )
    blocker.set()
    t_assess.join(timeout=10)

    idem = store._conn.execute(
        "SELECT response_ref FROM commissioning_idempotency WHERE idempotency_key = ?",
        ("assess-cancel-during-probe",),
    ).fetchone()
    assert idem is not None
    assert idem["response_ref"] is not None
    replay = store.prepare_commissioning_assess(
        run_id=run["run_id"],
        idempotency_key="assess-cancel-during-probe",
        request_digest="sha256:cancel-during-probe",
        expected_version=None,
        now=FIXED,
    )
    assert replay.replay is not None
