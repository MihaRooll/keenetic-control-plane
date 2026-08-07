"""Host worker lifespan and status isolation."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "worker-host.sqlite3", enable_worker=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_status_reports_worker_not_hardcoded_stopped(client) -> None:
    r = client.get("/api/router-control/v1/status")
    assert r.status_code == 200
    body = r.json()
    assert body["worker_state"] in ("Running", "Starting", "Stopped", "Degraded")
    assert "worker_heartbeat_at" in body
    assert "worker_last_error" in body


def test_app_constructs_when_worker_degraded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(
        db_path=tmp_path / "degraded.sqlite3",
        feature_state="Degraded",
        enable_worker=True,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        r = c.get("/api/router-control/v1/status")
    assert r.status_code == 200
    assert r.json()["feature_state"] == "Degraded"


def test_worker_disabled_stays_stopped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "no-worker.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        r = c.get("/api/router-control/v1/status")
    assert r.json()["worker_state"] == "Stopped"


def test_repeated_host_lifespan_start_stop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from fastapi.testclient import TestClient

    for cycle in range(3):
        app = create_app(
            db_path=tmp_path / f"lifespan-{cycle}.sqlite3",
            enable_worker=True,
        )
        with TestClient(app) as c:
            c.cookies.set("hub_admin", mint_hub_admin_cookie())
            r = c.get("/api/router-control/v1/status")
            assert r.status_code == 200
            assert r.json()["worker_state"] in ("Running", "Starting", "Stopped", "Degraded")
        assert app.state.host.worker_runtime is None
