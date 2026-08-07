"""LOCAL HUB routing, static assets, and auth smoke tests."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from urllib.parse import quote

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.hub_routes import (
    HUB_PREFIX,
    _path_has_traversal,
    _resolve_hub_relative_path,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
OLD_UI_APP_JS = (REPO_ROOT / "router_control_host" / "web" / "app.js").read_text(encoding="utf-8")


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    return create_app(db_path=tmp_path / "hub-routes.sqlite3", enable_worker=False)


@pytest.fixture
def authed_client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_hub_shell_200(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert "LOCAL HUB" in r.text


def test_hub_shell_slash_200(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub/")
    assert r.status_code == 200


def test_hub_security_headers(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub")
    assert r.status_code == 200
    assert "Content-Security-Policy" in r.headers
    assert r.headers.get("X-Frame-Options") == "DENY"
    assert r.headers.get("X-Content-Type-Options") == "nosniff"
    assert r.headers.get("Referrer-Policy") == "no-referrer"


def test_hub_app_js_served(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub/app.js")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/javascript")


def test_hub_cache_control_no_store(authed_client) -> None:
    index = authed_client.get("/settings/router-control/hub")
    assert index.headers.get("Cache-Control") == "no-store"
    runtime = authed_client.get("/settings/router-control/hub/runtime.json")
    assert runtime.headers.get("Cache-Control") == "no-store"


def test_hub_runtime_json(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub/runtime.json")
    assert r.status_code == 200
    body = r.json()
    assert set(body.keys()) == {"adapter_mode", "unsafe_auth_disabled", "hub_version"}
    assert body["adapter_mode"] == "fake"
    assert body["unsafe_auth_disabled"] is False
    assert body["hub_version"] == "0.1.0"


def test_hub_sw_js_headers(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub/sw.js")
    assert r.status_code == 200
    assert r.headers.get("Service-Worker-Allowed") == f"{HUB_PREFIX}/"
    assert r.headers.get("Cache-Control") == "no-store"


@pytest.mark.parametrize(
    "path",
    [
        "/settings/router-control/hub/../app.js",
        "/settings/router-control/hub/%2e%2e/app.js",
        "/settings/router-control/hub/..%2Fapp.js",
        "/settings/router-control/hub/styles/../../app.js",
    ],
)
def test_hub_traversal_rejected(authed_client, path: str) -> None:
    r = authed_client.get(path)
    assert r.status_code in (400, 404)
    assert "Router Control" not in r.text
    assert "renderConfig" not in r.text
    assert OLD_UI_APP_JS[:80] not in r.text


@pytest.mark.parametrize(
    "path,expected",
    [
        ("app.js", False),
        ("../app.js", True),
        ("%2e%2e/app.js", True),
        ("%252e%252e/app.js", True),
        ("styles/tokens.css", False),
        ("styles/../../app.js", True),
    ],
)
def test_path_has_traversal_unit(path: str, expected: bool) -> None:
    assert _path_has_traversal(path) is expected


@pytest.mark.parametrize(
    "path,expected",
    [
        ("app.js", "app.js"),
        ("%2e%2e/app.js", None),
        ("styles/tokens.css", "styles/tokens.css"),
        ("secret.pem", None),
    ],
)
def test_resolve_hub_relative_path_unit(path: str, expected: str | None) -> None:
    assert _resolve_hub_relative_path(path) == expected


def test_hub_forbidden_extension(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub/secret.pem")
    assert r.status_code == 404


def test_hub_missing_file_json_envelope(authed_client) -> None:
    r = authed_client.get("/settings/router-control/hub/no-such-file.css")
    assert r.status_code == 404
    assert r.json()["error"]["code"] == "resource.not_found"


def test_old_ui_unbroken(authed_client) -> None:
    shell = authed_client.get("/settings/router-control")
    assert shell.status_code == 200
    asset = authed_client.get("/settings/router-control/assets/app.js")
    assert asset.status_code == 200


def test_hub_401_without_cookie(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        for path in (
            "/settings/router-control/hub/app.js",
            "/settings/router-control/hub/runtime.json",
        ):
            r = client.get(path)
            assert r.status_code == 401, path
            assert r.json()["error"]["code"] == "auth.required"


@pytest.mark.parametrize(
    "path",
    [
        "/settings/router-control/hub",
        "/settings/router-control/hub/",
    ],
)
def test_hub_page_unauthenticated_redirects_to_login(app_env, path: str) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        r = client.get(path, follow_redirects=False)
        assert r.status_code == 302
        assert r.headers["location"] == f"/login?next={quote(path, safe='')}"


def test_hub_page_non_redirect_cases_stay_json(
    app_env, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        r = client.post("/settings/router-control/hub", follow_redirects=False)
        assert r.status_code != 302
        assert r.headers.get("location") is None

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    app = create_app(db_path=tmp_path / "hub-503.sqlite3", enable_worker=False)
    with TestClient(app) as client:
        r = client.get("/settings/router-control/hub", follow_redirects=False)
        assert r.status_code == 503
        assert r.json()["error"]["code"] == "security.configuration_blocked"


@pytest.mark.parametrize(
    "hub_path",
    [
        "/settings/router-control/hub",
        "/settings/router-control/hub/",
    ],
)
def test_hub_login_redirect_round_trip(app_env, hub_path: str) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        r = client.get(hub_path, follow_redirects=False)
        assert r.status_code == 302
        login_url = r.headers["location"]

        r = client.get(login_url)
        assert r.status_code == 200
        assert (
            f'<input type="hidden" name="next" value="{hub_path}">'
            in r.text
        )

        r = client.post(
            "/login",
            data={"password": "test-admin-password", "next": hub_path},
            headers={"Origin": "http://testserver"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == hub_path

        r = client.get(hub_path)
        assert r.status_code == 200
        assert "LOCAL HUB" in r.text


def _setuptools_glob_match(path: str, pattern: str) -> bool:
    """Approximate setuptools package-data glob matching (supports ``**``)."""
    parts: list[str] = ["^"]
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            parts.append("(?:.+/)*")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    parts.append("$")
    return re.match("".join(parts), path) is not None


def _path_covered_by_patterns(path: str, patterns: list[str]) -> bool:
    return any(_setuptools_glob_match(path, pattern) for pattern in patterns)


def test_pyproject_package_data_covers_nested_hub_assets() -> None:
    """Регрессия: ``web/*`` не включает ``web/hub/**`` в wheel — HUB 404 после pip install."""
    pyproject = REPO_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    patterns: list[str] = data["tool"]["setuptools"]["package-data"]["router_control_host"]

    nested_hub_paths = [
        "web/hub/index.html",
        "web/hub/core/shell.js",
        "web/hub/styles/tokens.css",
        "web/hub/icons/icon.svg",
    ]
    top_level_web_paths = [
        "web/app.js",
        "web/styles.css",
        "web/index.html",
        "web/login.html",
        "web/login.css",
        "web/login.js",
        "web/favicon.svg",
        "web/ui-field-manifest.json",
    ]

    for path in nested_hub_paths + top_level_web_paths:
        assert _path_covered_by_patterns(path, patterns), (
            f"package-data pattern(s) {patterns!r} do not cover {path!r}"
        )
