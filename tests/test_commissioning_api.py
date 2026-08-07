"""Commissioning API auth, idempotency, ETag, fake assess."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "comm-api.sqlite3",
        allow_fake_mutations=False,
        enable_worker=True,
    )
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _enroll(client, *, key: str = "enroll-comm") -> tuple[str, str]:
    host = client.app.state.host
    site_id = host.ensure_default_site()
    r = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Comm Router",
            "vendor": "FakeVendor",
            "model": "FakeModel",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "secret-not-echoed",
        },
        headers={"Idempotency-Key": key},
    )
    assert r.status_code == 202, r.text
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
    return site_id, router_id


def test_commissioning_auth_required(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        r = c.post(
            "/api/router-control/v1/sites/site_x/commissioning-runs",
            json={"router_id": "rtr_x", "mode": "fake"},
            headers={"Idempotency-Key": "k"},
        )
    assert r.status_code == 401


def test_create_assess_report_fake(client) -> None:
    host = client.app.state.host
    assert host.worker_runtime is not None
    assert host.worker_runtime.worker is not None
    assert host.worker_runtime.worker.store is not host.runtime.store
    site_id, router_id = _enroll(client)
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-1"},
    )
    assert create.status_code == 201
    run = create.json()
    assert run["state"] == "Draft"
    assert run["never_write_certified"] is True
    assert "secret-not-echoed" not in create.text

    replay = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-1"},
    )
    assert replay.status_code == 200
    assert replay.json()["run_id"] == run["run_id"]

    assess = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
        headers={"Idempotency-Key": "assess-1", "If-Match": run["etag"]},
    )
    assert assess.status_code == 200
    body = assess.json()
    assert body["run"]["state"] == "ReadyReadOnly"
    assert body["run"]["read_only_ready"] is True
    assert body["run"]["write_ready"] is False
    kinds = {c["check_kind"] for c in body["checks"]}
    assert "gate_b_not_write_certified" in kinds

    report = client.get(f"/api/router-control/v1/commissioning-runs/{run['run_id']}/report")
    assert report.status_code == 200
    rep = report.json()
    assert rep["read_only_ready"] is True
    assert rep["never_commissioned"] is True
    assert rep["never_write_certified"] is True
    blocker_kinds = {b["check_kind"] for b in rep["write_blockers"]}
    assert "gate_b_not_write_certified" in blocker_kinds
    assert "gate_c_closed" in blocker_kinds
    assert "gate_d_closed" in blocker_kinds


def test_cancel_from_ready_readonly(client) -> None:
    site_id, router_id = _enroll(client, key="enroll-ro-cancel")
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-ro-cancel"},
    )
    run = create.json()
    assess = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
        headers={"Idempotency-Key": "assess-ro-cancel", "If-Match": run["etag"]},
    )
    assert assess.status_code == 200
    assessed = assess.json()["run"]
    assert assessed["state"] == "ReadyReadOnly"

    cancel = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/cancel",
        headers={"Idempotency-Key": "cancel-ro", "If-Match": assessed["etag"]},
    )
    assert cancel.status_code == 200
    assert cancel.json()["state"] == "Cancelled"


def test_assess_recovers_from_stuck_assessing(client) -> None:
    site_id, router_id = _enroll(client, key="enroll-stuck")
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-stuck"},
    )
    run = create.json()
    store = client.app.state.host.runtime.store
    store._conn.execute(
        "UPDATE commissioning_runs SET state = 'Assessing', version = 2, "
        "summary_redacted = 'assessment in progress' WHERE run_id = ?",
        (run["run_id"],),
    )
    assess = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
        headers={"Idempotency-Key": "assess-stuck-retry"},
    )
    assert assess.status_code == 200
    body = assess.json()
    assert body["run"]["state"] == "ReadyReadOnly"


def test_cancel_and_etag_precondition(client) -> None:
    site_id, router_id = _enroll(client, key="enroll-cancel")
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-cancel"},
    )
    run = create.json()
    cancel = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/cancel",
        headers={"Idempotency-Key": "cancel-1", "If-Match": run["etag"]},
    )
    assert cancel.status_code == 200
    assert cancel.json()["state"] == "Cancelled"

    assess = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
        headers={"Idempotency-Key": "assess-cancel"},
    )
    assert assess.status_code == 409
    assert assess.json()["error"]["code"] == "commissioning.cancelled"

    bad = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/cancel",
        headers={"Idempotency-Key": "cancel-bad", "If-Match": '"wrong:1:none"'},
    )
    assert bad.status_code == 412


def test_commissioning_report_includes_preset_readiness(client) -> None:
    site_id, router_id = _enroll(client, key="enroll-preset-ro")
    client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Report Booth"},
        headers={"Idempotency-Key": "preset-for-report"},
    )
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "create-preset-report"},
    )
    run = create.json()
    client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
        headers={"Idempotency-Key": "assess-preset-report", "If-Match": run["etag"]},
    )
    report = client.get(f"/api/router-control/v1/commissioning-runs/{run['run_id']}/report")
    assert report.status_code == 200
    body = report.json()
    assert "event_preset_readiness" in body
    assert body["event_preset_readiness"]["write_ready"] is False
