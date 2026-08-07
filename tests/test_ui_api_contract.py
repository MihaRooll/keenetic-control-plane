"""UI client API contract references and mutation helpers."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "ui-api.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def _read_app_js() -> str:
    path = Path(__file__).resolve().parents[1] / "router_control_host" / "web" / "app.js"
    return path.read_text(encoding="utf-8")


def test_app_js_references_core_api_paths() -> None:
    source = _read_app_js()
    expected = [
        '"/status"',
        '"/routers"',
        "/commissioning-runs/",
        "/event-presets/",
        "/publications",
        "/deployment-revisions",
        "/desired-revisions",
        "/readiness",
        "/revision-state",
        "/backup-artifact",
        "/confirm",
        "/apply",
        "Deployment Confirm/Apply (FAKE)",
        "/operations/",
        "/jobs/",
        "/vpn-profiles",
        "Idempotency-Key",
        "If-Match",
        "credentials: \"same-origin\"",
    ]
    for fragment in expected:
        assert fragment in source, fragment


def test_app_js_theme_localstorage_key() -> None:
    source = _read_app_js()
    assert "rc.prototype.theme" in source
    assert "localStorage.setItem(THEME_KEY" in source


def test_app_js_json_content_type_on_mutations() -> None:
    source = _read_app_js()
    assert 'headers["Content-Type"] = "application/json"' in source


def test_app_js_write_gate_and_apply_safety() -> None:
    source = _read_app_js()
    assert "function writeGatesBlocked" in source
    assert "function gateADisplay" in source
    assert "!writeGatesBlocked(status)" in source
    assert "applyBtn.disabled = true" in source
    assert "Apply (заблокировано)" in source
    assert "credential_ref_id" in source
    assert "management_password" not in source
    assert "status.write_gates" in source
    assert "status.gate_a" in source
    assert "status.gates" in source
    assert "recovery-banner" in source or "RecoveryRequired" in source
    assert "/resume" in source
    assert "/compensate" in source
    wg_body = source.split("function writeGatesBlocked")[1].split("function gateBlockReason")[0]
    assert "return true;" in wg_body


def test_status_write_gates_fail_closed(authed_client) -> None:
    r = authed_client.get("/api/router-control/v1/status")
    assert r.status_code == 200
    body = r.json()
    assert "write_gates" in body
    wg = body["write_gates"]
    assert wg["blocked"] is True
    assert wg["write_certified"] is False
    assert isinstance(wg["reason"], str) and wg["reason"]
    assert wg["gate_b"] == "closed"
    assert body["feature_state"] == "Ready"
    assert "gate_b_status" not in body


def test_synthetic_api_smoke_with_ui_session(authed_client) -> None:
    html = authed_client.get("/settings/router-control")
    assert html.status_code == 200
    css = authed_client.get("/settings/router-control/assets/styles.css")
    assert css.status_code == 200
    js = authed_client.get("/settings/router-control/assets/app.js")
    assert js.status_code == 200

    status = authed_client.get("/api/router-control/v1/status")
    assert status.status_code == 200
    site_id = status.json()["default_site_id"]

    enroll = authed_client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "UI Smoke Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "ui-smoke-secret",
        },
        headers={"Idempotency-Key": "ui-smoke-enroll"},
    )
    assert enroll.status_code == 202
    router_id = enroll.json()["router_id"]
    assert "ui-smoke-secret" not in enroll.text

    preset = authed_client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "UI Smoke Preset"},
        headers={"Idempotency-Key": "ui-smoke-preset"},
    )
    assert preset.status_code == 201

    run = authed_client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "ui-smoke-run"},
    )
    assert run.status_code == 201

    profiles = authed_client.get("/api/router-control/v1/vpn-profiles")
    assert profiles.status_code == 200

    detail = authed_client.get(f"/api/router-control/v1/routers/{router_id}")
    assert detail.status_code == 200
    assert "ui-smoke-secret" not in detail.text
