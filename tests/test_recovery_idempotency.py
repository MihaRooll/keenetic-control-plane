"""P1-A recovery request CAS idempotency."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control.application.recovery import submit_recovery_request_cas
from router_control.persistence.connection import open_database
from router_control.persistence.errors import RecoveryConflictError
from router_control.persistence.store import PersistenceStore


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "rcvr.sqlite3"))


def test_same_key_digest_replay(store: PersistenceStore) -> None:
    status1, body1 = submit_recovery_request_cas(
        store,
        recovery_key="job:abc",
        request_digest="sha256:same",
        recovery_action="resume",
    )
    status2, body2 = submit_recovery_request_cas(
        store,
        recovery_key="job:abc",
        request_digest="sha256:same",
        recovery_action="resume",
    )
    assert status1 == 201
    assert status2 == 200
    assert body1["request_id"] == body2["request_id"]


def test_different_digest_conflict(store: PersistenceStore) -> None:
    submit_recovery_request_cas(
        store,
        recovery_key="job:abc",
        request_digest="sha256:a",
        recovery_action="resume",
    )
    status, body = submit_recovery_request_cas(
        store,
        recovery_key="job:abc",
        request_digest="sha256:b",
        recovery_action="resume",
    )
    assert status == 409
    assert body["error"] == "RecoveryConflict"


def test_one_active_recovery_action(store: PersistenceStore) -> None:
    store.submit_recovery_request(
        recovery_key="job:x",
        request_digest="sha256:1",
        recovery_action="resume",
    )
    with pytest.raises(RecoveryConflictError):
        store.submit_recovery_request(
            recovery_key="job:x",
            request_digest="sha256:2",
            recovery_action="compensate",
        )
    status, body = submit_recovery_request_cas(
        store,
        recovery_key="job:y",
        request_digest="sha256:other",
        recovery_action="compensate",
    )
    assert status == 201
    assert body["status"] == "Active"


def test_stale_cannot_overwrite_terminal(store: PersistenceStore) -> None:
    _, row = store.submit_recovery_request(
        recovery_key="job:t",
        request_digest="sha256:t",
        recovery_action="resume",
    )
    request_id = str(row["request_id"])
    store.complete_recovery_request(request_id=request_id, status="Succeeded")
    store.complete_recovery_request(request_id=request_id, status="Failed")
    final = store.get_recovery_request(request_id)
    assert final is not None
    assert final["status"] == "Succeeded"
