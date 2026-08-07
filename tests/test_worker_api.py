"""Async commissioning/preset API + worker completion."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "worker-api.sqlite3", enable_worker=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _enroll_and_run(client) -> tuple[str, str]:
    host = client.app.state.host
    site_id = host.ensure_default_site()
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Worker API Router",
            "vendor": "FakeVendor",
            "model": "FakeModel",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "secret-not-echoed",
        },
        headers={"Idempotency-Key": "enroll-worker-api"},
    )
    router_id = r.json()["router_id"]
    store = host.runtime.store
    now = host.runtime.clock.now()
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (router_id,),
    )
    store.insert_observation(
        router_id=router_id,
        identity_fingerprint="digest:enroll:seed",
        resource_version="v1",
        state_digest="sha256:obs",
        now=now,
    )
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-worker-api"},
    )
    run_id = create.json()["run_id"]
    return run_id, router_id


def _wait_for_job_terminal(store, job_id: str, *, timeout: float = 5.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = store.get_job(job_id)
        if job is not None and job["status"] in ("Succeeded", "Failed", "Cancelled"):
            return dict(job)
        time.sleep(0.05)
    job = store.get_job(job_id)
    assert job is not None, "job missing"
    pytest.fail(
        f"job {job_id} did not reach terminal status within {timeout}s "
        f"(status={job['status']})"
    )


def test_async_commissioning_assess_202(client) -> None:
    run_id, _router_id = _enroll_and_run(client)
    r = client.post(
        f"/api/router-control/v1/commissioning-runs/{run_id}/assess?execution=async",
        headers={"Idempotency-Key": "assess-async-1"},
    )
    assert r.status_code == 202, r.text
    body = r.json()
    assert "operation_id" in body
    assert "job_id" in body
    assert body["status"] == "Queued"
    host = client.app.state.host
    job = _wait_for_job_terminal(host.runtime.store, body["job_id"])
    assert job["status"] == "Succeeded"
    op = host.runtime.store.get_operation(body["operation_id"])
    assert op is not None
    assert op["aggregate_status"] == "Converged"


def test_async_commissioning_idempotency_replay(client) -> None:
    run_id, _ = _enroll_and_run(client)
    headers = {"Idempotency-Key": "assess-async-replay"}
    r1 = client.post(
        f"/api/router-control/v1/commissioning-runs/{run_id}/assess?execution=async",
        headers=headers,
    )
    r2 = client.post(
        f"/api/router-control/v1/commissioning-runs/{run_id}/assess?execution=async",
        headers=headers,
    )
    assert r1.status_code == 202
    assert r2.status_code == 202
    assert r1.json()["operation_id"] == r2.json()["operation_id"]


def test_sync_assess_unchanged(client) -> None:
    run_id, _ = _enroll_and_run(client)
    r = client.post(
        f"/api/router-control/v1/commissioning-runs/{run_id}/assess",
        headers={"Idempotency-Key": "assess-sync-1"},
    )
    assert r.status_code == 200
    assert "run" in r.json()
    assert "checks" in r.json()


def test_async_preset_validate_202(client) -> None:
    host = client.app.state.host
    site_id = host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Async Preset"},
        headers={"Idempotency-Key": "preset-create-async"},
    )
    preset_id = create.json()["preset"]["preset_id"]
    r = client.post(
        f"/api/router-control/v1/event-presets/{preset_id}/validate?execution=async",
        headers={"Idempotency-Key": "validate-async-1"},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "Queued"
    job = _wait_for_job_terminal(host.runtime.store, body["job_id"])
    assert job["status"] == "Succeeded"
    op = host.runtime.store.get_operation(body["operation_id"])
    assert op is not None
    assert op["aggregate_status"] == "Converged"
