"""Gate A closed semantics for RC_ADAPTER_MODE=live (fail-closed before transport)."""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def live_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "live")
    return create_app(
        db_path=tmp_path / "live.sqlite3",
        adapter_mode="live",
        skip_gate_a_load=True,
    )


@pytest.fixture
def live_client(live_app):
    from fastapi.testclient import TestClient

    with TestClient(live_app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


@pytest.fixture
def fake_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("RC_ADAPTER_MODE", raising=False)
    return create_app(db_path=tmp_path / "fake.sqlite3", adapter_mode="fake")


@pytest.fixture
def fake_client(fake_app):
    from fastapi.testclient import TestClient

    with TestClient(fake_app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _forbid_network_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbid(*args: object, **kwargs: object) -> None:
        raise AssertionError("network transport must not be used in live Gate A closed mode")

    monkeypatch.setattr(socket.socket, "connect", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)


def _enroll_body() -> dict[str, object]:
    return {
        "display_name": "Gate A Router",
        "vendor": "Netcraze",
        "model": "NC-1812",
        "endpoint": {"kind": "management_https", "host": "192.168.1.1", "port": 443},
        "management_password": "never-echo",
    }


def test_live_enroll_returns_gate_a_closed(
    live_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_network_transport(monkeypatch)
    r = live_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "live-enroll-gate"},
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "gate.a_closed"
    assert len(live_client.get("/api/router-control/v1/routers").json()["items"]) == 0


def test_live_preflight_returns_gate_a_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    db = tmp_path / "shared.sqlite3"
    from fastapi.testclient import TestClient

    fake_app = create_app(db_path=db, adapter_mode="fake")
    with TestClient(fake_app) as seed_client:
        seed_client.cookies.set("hub_admin", mint_hub_admin_cookie())
        enroll = seed_client.post(
            "/api/router-control/v1/routers",
            json=_enroll_body(),
            headers={"Idempotency-Key": "seed-for-preflight"},
        )
        assert enroll.status_code == 202
        router_id = enroll.json()["router_id"]

    live_app = create_app(db_path=db, adapter_mode="live", skip_gate_a_load=True)
    with TestClient(live_app) as live_client:
        live_client.cookies.set("hub_admin", mint_hub_admin_cookie())
        _forbid_network_transport(monkeypatch)
        r = live_client.post(
            f"/api/router-control/v1/routers/{router_id}/preflight",
            json={"observation_ttl_seconds": 300},
            headers={"Idempotency-Key": "live-preflight-gate"},
        )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "gate.a_closed"


def test_fake_enroll_and_preflight_accepted(fake_client) -> None:
    enroll = fake_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "fake-enroll-ok"},
    )
    assert enroll.status_code == 202
    router_id = enroll.json()["router_id"]

    preflight = fake_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        headers={"Idempotency-Key": "fake-preflight-ok"},
    )
    assert preflight.status_code == 202
    assert "operation_id" in preflight.json()


def test_default_adapter_mode_is_fake(fake_app) -> None:
    assert fake_app.state.host.adapter_mode == "fake"
