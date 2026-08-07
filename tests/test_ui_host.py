"""UI host routing and auth smoke tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    return create_app(db_path=tmp_path / "ui-host.sqlite3", enable_worker=False)


@pytest.fixture
def authed_client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_ui_401_without_cookie(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        for path in (
            "/settings/router-control",
            "/settings/router-control/",
            "/settings/router-control/assets/styles.css",
            "/settings/router-control/assets/app.js",
        ):
            r = client.get(path)
            assert r.status_code == 401, path
            assert r.json()["error"]["code"] == "auth.required"


def test_ui_503_missing_password(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    from fastapi.testclient import TestClient

    app = create_app(db_path=tmp_path / "ui-503.sqlite3", enable_worker=False)
    with TestClient(app) as client:
        r = client.get("/settings/router-control")
    assert r.status_code == 503
    assert r.json()["error"]["code"] == "security.configuration_blocked"


def test_ui_html_served_with_auth(authed_client) -> None:
    r = authed_client.get("/settings/router-control")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "Router Control" in r.text
    assert 'href="/settings/router-control/assets/styles.css"' in r.text
    assert 'src="/settings/router-control/assets/app.js"' in r.text
    assert 'type="password"' not in r.text


def test_ui_slash_route(authed_client) -> None:
    r = authed_client.get("/settings/router-control/")
    assert r.status_code == 200
    assert "Router Control" in r.text


def test_ui_correlation_headers(authed_client) -> None:
    r = authed_client.get(
        "/settings/router-control",
        headers={"X-Request-Id": "req_ui_test", "X-Correlation-Id": "corr_ui_test"},
    )
    assert r.status_code == 200
    assert r.headers.get("X-Request-Id") == "req_ui_test"
    assert r.headers.get("X-Correlation-Id") == "corr_ui_test"


def test_ui_not_in_openapi_schema(app_env) -> None:
    paths = app_env.openapi().get("paths", {})
    assert "/settings/router-control" not in paths
    assert "/settings/router-control/assets/{asset_name}" not in paths


def test_api_auth_order_unchanged(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        r = client.get("/api/router-control/v1/status")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "auth.required"


def test_status_includes_default_site_id(authed_client) -> None:
    r = authed_client.get("/api/router-control/v1/status")
    assert r.status_code == 200
    body = r.json()
    assert "default_site_id" in body
    assert isinstance(body["default_site_id"], str)
    assert body["default_site_id"]
