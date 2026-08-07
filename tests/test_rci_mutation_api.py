"""FastAPI tests for typed sealed RCI mutation routes."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def rci_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "rci.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        enroll = client.post(
            "/api/router-control/v1/routers",
            json={
                "display_name": "RCI Router",
                "vendor": "Netcraze",
                "model": "NC-1812",
                "endpoint": {"kind": "management_https", "host": "10.0.0.1", "port": 443},
                "management_password": "test-secret",
            },
            headers={"Idempotency-Key": "rci-enroll"},
        )
        assert enroll.status_code == 202
        client.test_router_id = enroll.json()["router_id"]
        yield client


def test_rci_arm_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "rci2.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post(
            "/api/router-control/v1/routers/r1/rci/fail-safe/arm",
            json={"operation": "arm_timer_reboot_60"},
            headers={"Idempotency-Key": "idem-arm"},
        )
    assert resp.status_code == 401


def test_rci_arm_fake_mode_succeeds(rci_client) -> None:
    router_id = rci_client.test_router_id
    resp = rci_client.post(
        f"/api/router-control/v1/routers/{router_id}/rci/fail-safe/arm",
        json={"operation": "arm_timer_reboot_60"},
        headers={"Idempotency-Key": "idem-arm-ok"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "Succeeded"
    assert body["result"]["ack_matched"] is True
    for entry in body["result"].get("status", []):
        assert "message" not in entry


def test_rci_arm_idempotent_replay(rci_client) -> None:
    router_id = rci_client.test_router_id
    headers = {"Idempotency-Key": "idem-arm-replay"}
    first = rci_client.post(
        f"/api/router-control/v1/routers/{router_id}/rci/fail-safe/arm",
        json={"operation": "arm_timer_reboot_60"},
        headers=headers,
    )
    second = rci_client.post(
        f"/api/router-control/v1/routers/{router_id}/rci/fail-safe/arm",
        json={"operation": "arm_timer_reboot_60"},
        headers=headers,
    )
    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["operation_id"] == second.json()["operation_id"]


def test_rci_mutations_forbidden_without_fake_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("RC_ALLOW_FAKE_MUTATIONS", raising=False)
    app = create_app(db_path=tmp_path / "rci3.sqlite3", allow_fake_mutations=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post(
            "/api/router-control/v1/routers/r1/rci/system/reboot",
            json={"operation": "reboot"},
            headers={"Idempotency-Key": "idem-reboot-deny"},
        )
    assert resp.status_code == 403
    assert resp.json()["error"]["code"] == "gate.mutation_forbidden"


def test_rci_interface_rejects_extra_fields(rci_client) -> None:
    router_id = rci_client.test_router_id
    resp = rci_client.post(
        f"/api/router-control/v1/routers/{router_id}/rci/interface",
        json={
            "operation": "interface_up",
            "interface_id": "Bridge0",
            "cli": "injected",
        },
        headers={"Idempotency-Key": "idem-iface-extra"},
    )
    assert resp.status_code == 422


def test_rci_system_save_and_reboot_are_separate(rci_client) -> None:
    router_id = rci_client.test_router_id
    save = rci_client.post(
        f"/api/router-control/v1/routers/{router_id}/rci/system/configuration-save",
        json={"operation": "configuration_save"},
        headers={"Idempotency-Key": "idem-save"},
    )
    reboot = rci_client.post(
        f"/api/router-control/v1/routers/{router_id}/rci/system/reboot",
        json={"operation": "reboot"},
        headers={"Idempotency-Key": "idem-reboot"},
    )
    assert save.status_code == 200
    assert reboot.status_code == 200
    assert save.json()["result"]["operation"] == "configuration_save"
    assert reboot.json()["result"]["operation"] == "reboot"
