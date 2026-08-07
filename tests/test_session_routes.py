"""Session bootstrap routes — login, logout, root, favicon."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import (
    HUB_ADMIN_COOKIE_NAME,
    AuthFailureClass,
    classify_login_submit_failure,
    mint_hub_admin_cookie,
    session_ttl_seconds,
    set_auth_clock_for_tests,
)
from router_control_host.session_routes import same_origin_post

TEST_PASSWORD = "test-admin-password"
DEFAULT_TTL = session_ttl_seconds()


@pytest.fixture(autouse=True)
def _reset_auth_clock() -> None:
    set_auth_clock_for_tests(None)


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    monkeypatch.delenv("HUB_ADMIN_SESSION_SECRET", raising=False)
    return create_app(db_path=tmp_path / "session.sqlite3", enable_worker=False)


def _origin_for_base(base_url: str) -> str:
    return base_url.rstrip("/")


def _same_origin_headers(base_url: str) -> dict[str, str]:
    return {"Origin": _origin_for_base(base_url)}


def _fetch_metadata_headers(
    *,
    site: str = "same-origin",
    mode: str = "navigate",
    dest: str = "document",
) -> dict[str, str]:
    return {
        "Sec-Fetch-Site": site,
        "Sec-Fetch-Mode": mode,
        "Sec-Fetch-Dest": dest,
    }


def _referer_only_headers(base_url: str, path: str = "/login") -> dict[str, str]:
    return {"Referer": f"{base_url.rstrip('/')}{path}"}


def _cookie_max_age(set_cookie_header: str) -> int | None:
    for part in set_cookie_header.split(";"):
        stripped = part.strip().lower()
        if stripped.startswith("max-age="):
            return int(stripped.split("=", 1)[1])
    return None


def _assert_hub_admin_cookie_attrs(
    set_cookie_header: str,
    *,
    secure: bool,
    expected_max_age: int | None = None,
) -> None:
    lowered = set_cookie_header.lower()
    assert HUB_ADMIN_COOKIE_NAME in set_cookie_header
    assert "httponly" in lowered
    assert "path=/" in lowered
    assert "samesite=lax" in lowered
    if secure:
        assert "secure" in lowered
    else:
        assert "secure" not in lowered
    assert TEST_PASSWORD not in set_cookie_header
    if expected_max_age is not None:
        assert _cookie_max_age(set_cookie_header) == expected_max_age


def _client(app_env, base_url: str = "http://testserver"):
    from fastapi.testclient import TestClient

    return TestClient(app_env, base_url=base_url)


def _login(client, base_url: str = "http://testserver") -> None:
    r = client.post(
        "/login",
        data={"password": TEST_PASSWORD},
        headers=_same_origin_headers(base_url),
        follow_redirects=False,
    )
    assert r.status_code == 303


@pytest.mark.parametrize(
    ("base_url",),
    [
        ("http://127.0.0.1:8787",),
        ("http://localhost:8787",),
    ],
)
def test_browser_realistic_login_flow(app_env, base_url: str) -> None:
    with _client(app_env, base_url=base_url) as client:
        root = client.get("/", follow_redirects=False)
        assert root.status_code == 302
        assert root.headers.get("location") == "/login"

        login_page = client.get("/login")
        assert login_page.status_code == 200
        assert 'href="/login.css"' in login_page.text
        assert "<style" not in login_page.text.lower()

        post = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_same_origin_headers(base_url),
            follow_redirects=False,
        )
        assert post.status_code == 303
        set_cookie = post.headers.get("set-cookie")
        assert set_cookie is not None
        _assert_hub_admin_cookie_attrs(set_cookie, secure=False, expected_max_age=DEFAULT_TTL)

        ui = client.get("/settings/router-control")
        assert ui.status_code == 200
        assert TEST_PASSWORD not in ui.text


@pytest.mark.parametrize(
    ("host_base", "origin_base"),
    [
        ("http://127.0.0.1:8787", "http://localhost:8787"),
        ("http://localhost:8787", "http://127.0.0.1:8787"),
    ],
)
def test_login_rejects_cross_localhost_alias(app_env, host_base: str, origin_base: str) -> None:
    with _client(app_env, base_url=host_base) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": _origin_for_base(origin_base)},
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None


def test_login_page_served(app_env) -> None:
    with _client(app_env) as client:
        r = client.get("/login")
    assert r.status_code == 200
    assert "text/html" in r.headers.get("content-type", "")
    assert 'method="post"' in r.text
    assert 'name="password"' in r.text
    assert 'action="/login"' in r.text
    assert 'href="/login.css"' in r.text
    assert TEST_PASSWORD not in r.text
    assert "no-store" in r.headers.get("cache-control", "").lower()
    csp = r.headers.get("content-security-policy", "")
    assert "unsafe-inline" not in csp
    assert "style-src 'self'" in csp


def test_login_success_sets_cookie_and_grants_access(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
        assert r.status_code == 303
        set_cookie = r.headers.get("set-cookie")
        assert set_cookie is not None
        _assert_hub_admin_cookie_attrs(set_cookie, secure=False, expected_max_age=DEFAULT_TTL)
        ui = client.get("/settings/router-control")
        assert ui.status_code == 200
        assert TEST_PASSWORD not in ui.text


def test_login_password_outer_whitespace(app_env, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", f"  {TEST_PASSWORD}  ")
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": f"  {TEST_PASSWORD}  "},
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
    assert r.status_code == 303


def test_login_failure_no_secret_leak(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": "wrong-password-value"},
            headers=_same_origin_headers("http://testserver"),
        )
    assert r.status_code == 401
    assert TEST_PASSWORD not in r.text
    assert "wrong-password-value" not in r.text
    assert r.headers.get("set-cookie") is None
    with _client(app_env) as client:
        ui = client.get("/settings/router-control")
    assert ui.status_code == 401


def test_login_rejects_foreign_origin(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": "http://evil.example"},
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None


def test_login_rejects_missing_origin_and_referer(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None
    assert TEST_PASSWORD not in r.text


@pytest.mark.parametrize("base_url", ["http://127.0.0.1:8787", "http://localhost:8787"])
def test_login_accepts_fetch_metadata_without_origin_referer(
    app_env,
    base_url: str,
) -> None:
    with _client(app_env, base_url=base_url) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_fetch_metadata_headers(),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("set-cookie") is not None


@pytest.mark.parametrize("base_url", ["http://127.0.0.1:8787", "http://localhost:8787"])
def test_login_accepts_referer_without_origin(app_env, base_url: str) -> None:
    with _client(app_env, base_url=base_url) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_referer_only_headers(base_url),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("set-cookie") is not None


def test_login_rejects_empty_origin_despite_fetch_metadata(app_env) -> None:
    with _client(app_env, base_url="http://127.0.0.1:8787") as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={
                "Origin": "",
                **_fetch_metadata_headers(),
            },
            follow_redirects=False,
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None


def test_login_rejects_origin_mismatch_despite_perfect_fetch_metadata(app_env) -> None:
    with _client(app_env, base_url="http://127.0.0.1:8787") as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={
                "Origin": "http://evil.example",
                **_fetch_metadata_headers(),
            },
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None


@pytest.mark.parametrize(
    "fetch_site",
    ["cross-site", "same-site", "none"],
)
def test_login_rejects_bad_fetch_metadata_site(app_env, fetch_site: str) -> None:
    with _client(app_env, base_url="http://127.0.0.1:8787") as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_fetch_metadata_headers(site=fetch_site),
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None


def test_login_rejects_fetch_metadata_on_non_loopback_host(app_env) -> None:
    with _client(app_env, base_url="http://testserver") as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_fetch_metadata_headers(),
        )
    assert r.status_code == 401
    assert r.headers.get("set-cookie") is None


@pytest.mark.parametrize("base_url", ["http://127.0.0.1:8787", "http://localhost:8787"])
def test_logout_accepts_fetch_metadata_without_origin_referer(
    app_env,
    base_url: str,
) -> None:
    with _client(app_env, base_url=base_url) as client:
        _login(client, base_url=base_url)
        r = client.post(
            "/logout",
            headers=_fetch_metadata_headers(),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "max-age=0" in r.headers.get("set-cookie", "").lower()


@pytest.mark.parametrize("base_url", ["http://127.0.0.1:8787", "http://localhost:8787"])
def test_logout_accepts_referer_without_origin(app_env, base_url: str) -> None:
    with _client(app_env, base_url=base_url) as client:
        _login(client, base_url=base_url)
        r = client.post(
            "/logout",
            headers=_referer_only_headers(base_url, "/settings/router-control"),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert "max-age=0" in r.headers.get("set-cookie", "").lower()


def test_logout_rejects_empty_origin_despite_fetch_metadata(app_env) -> None:
    with _client(app_env, base_url="http://127.0.0.1:8787") as client:
        _login(client, base_url="http://127.0.0.1:8787")
        r = client.post(
            "/logout",
            headers={
                "Origin": "",
                **_fetch_metadata_headers(),
            },
            follow_redirects=False,
        )
    assert r.status_code == 401
    assert client.get("/settings/router-control").status_code == 200


def test_logout_rejects_fetch_metadata_on_non_loopback_host(app_env) -> None:
    with _client(app_env) as client:
        _login(client)
        r = client.post(
            "/logout",
            headers=_fetch_metadata_headers(),
            follow_redirects=False,
        )
    assert r.status_code == 401
    assert client.get("/settings/router-control").status_code == 200


def test_login_classify_origin_vs_credentials(app_env) -> None:
    assert (
        classify_login_submit_failure(
            password_configured=True,
            same_origin=False,
            password_valid=True,
        )
        == AuthFailureClass.ORIGIN_REJECTED
    )
    assert (
        classify_login_submit_failure(
            password_configured=True,
            same_origin=True,
            password_valid=False,
        )
        == AuthFailureClass.CREDENTIALS_REJECTED
    )


def test_login_https_sets_secure_cookie(app_env) -> None:
    with _client(app_env, base_url="https://testserver") as https_client:
        r = https_client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": "https://testserver"},
            follow_redirects=False,
        )
    assert r.status_code == 303
    set_cookie = r.headers.get("set-cookie")
    assert set_cookie is not None
    _assert_hub_admin_cookie_attrs(set_cookie, secure=True, expected_max_age=DEFAULT_TTL)


def test_login_empty_config_503(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    app = create_app(db_path=tmp_path / "session-503.sqlite3", enable_worker=False)
    with _client(app) as bare:
        get_r = bare.get("/login")
        assert get_r.status_code == 503
        post_r = bare.post(
            "/login",
            data={"password": "any"},
            headers=_same_origin_headers("http://testserver"),
        )
        assert post_r.status_code == 503
        assert TEST_PASSWORD not in post_r.text


def test_logout_post_clears_session(app_env) -> None:
    with _client(app_env) as client:
        _login(client)
        r = client.post(
            "/logout",
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
        assert r.status_code == 303
        set_cookie = r.headers.get("set-cookie", "")
        assert HUB_ADMIN_COOKIE_NAME in set_cookie
        assert "max-age=0" in set_cookie.lower()
        ui = client.get("/settings/router-control")
        assert ui.status_code == 401


def test_logout_post_rejects_foreign_origin(app_env) -> None:
    with _client(app_env) as client:
        _login(client)
        r = client.post(
            "/logout",
            headers={"Origin": "http://evil.example"},
            follow_redirects=False,
        )
        assert r.status_code == 401
        assert client.get("/settings/router-control").status_code == 200


def test_logout_get_non_mutating(app_env) -> None:
    with _client(app_env) as client:
        _login(client)
        r = client.get("/logout", follow_redirects=False)
        assert r.status_code == 405
        assert r.headers.get("allow") == "POST"
        assert client.get("/settings/router-control").status_code == 200


def test_root_redirect_unauthenticated(app_env) -> None:
    with _client(app_env) as client:
        r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get("location") == "/login"


def test_root_redirect_authenticated(app_env) -> None:
    with _client(app_env) as client:
        _login(client)
        r = client.get("/", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers.get("location") == "/settings/router-control/hub"


def test_favicon_local_200(app_env) -> None:
    with _client(app_env) as client:
        r = client.get("/favicon.ico")
    assert r.status_code == 200
    assert "image/svg+xml" in r.headers.get("content-type", "")
    assert "<svg" in r.text
    assert "cdn" not in r.text.lower()
    assert "npm" not in r.text.lower()


def test_login_js_public(app_env) -> None:
    with _client(app_env) as client:
        r = client.get("/login.js")
    assert r.status_code == 200
    assert "javascript" in r.headers.get("content-type", "")
    assert "localStorage" in r.text
    assert TEST_PASSWORD not in r.text


def test_login_css_public(app_env) -> None:
    with _client(app_env) as client:
        r = client.get("/login.css")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/css")
    assert ".login-card" in r.text
    assert TEST_PASSWORD not in r.text
    csp = r.headers.get("content-security-policy", "")
    assert "unsafe-inline" not in csp


def test_login_next_allowlist(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD, "next": "http://evil.example/phish"},
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("location") == "/settings/router-control/hub"


def test_login_no_next_defaults_to_hub(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("location") == "/settings/router-control/hub"


@pytest.mark.parametrize(
    "next_path",
    [
        "/settings/router-control/hub",
        "/settings/router-control/hub/",
    ],
)
def test_login_next_hub_paths_allowed(app_env, next_path: str) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={"password": TEST_PASSWORD, "next": next_path},
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("location") == next_path


def test_login_next_hub_external_url_rejected(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={
                "password": TEST_PASSWORD,
                "next": "https://evil.example/settings/router-control/hub/",
            },
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("location") == "/settings/router-control/hub"


def test_login_next_hub_path_traversal_rejected(app_env) -> None:
    with _client(app_env) as client:
        r = client.post(
            "/login",
            data={
                "password": TEST_PASSWORD,
                "next": "/settings/router-control/hub/../../etc",
            },
            headers=_same_origin_headers("http://testserver"),
            follow_redirects=False,
        )
    assert r.status_code == 303
    assert r.headers.get("location") == "/settings/router-control/hub"


def test_gated_api_order_after_login(app_env) -> None:
    with _client(app_env) as client:
        client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_same_origin_headers("http://testserver"),
        )
        r = client.get("/api/router-control/v1/status")
    assert r.status_code == 200


def test_gated_api_401_without_session(app_env) -> None:
    with _client(app_env) as bare:
        r = bare.get("/api/router-control/v1/status")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "auth.required"


def test_login_not_in_openapi(app_env) -> None:
    paths = app_env.openapi().get("paths", {})
    assert "/login" not in paths
    assert "/logout" not in paths


def test_expired_cookie_rejected(app_env) -> None:
    now = 1_700_000_000
    token = mint_hub_admin_cookie(now=now - DEFAULT_TTL - 1)
    set_auth_clock_for_tests(lambda: now)
    with _client(app_env) as client:
        client.cookies.set(HUB_ADMIN_COOKIE_NAME, token)
        r = client.get("/settings/router-control")
    assert r.status_code == 401


def test_same_origin_post_helper_exact_match() -> None:
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "POST",
        "path": "/login",
        "headers": [(b"origin", b"http://127.0.0.1:8787")],
        "query_string": b"",
        "server": ("127.0.0.1", 8787),
        "client": ("testclient", 50000),
        "scheme": "http",
    }
    request = Request(scope)
    assert same_origin_post(request) is True

    scope["headers"] = [(b"origin", b"http://localhost:8787")]
    request = Request(scope)
    assert same_origin_post(request) is False

    scope["headers"] = [
        (b"sec-fetch-site", b"same-origin"),
        (b"sec-fetch-mode", b"navigate"),
        (b"sec-fetch-dest", b"document"),
    ]
    request = Request(scope)
    assert same_origin_post(request) is True
