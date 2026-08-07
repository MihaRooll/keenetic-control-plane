"""Standalone loopback authority middleware and Origin:null tests."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest
from router_control_host.app import create_app
from router_control_host.auth import (
    LOGIN_THROTTLE_MAX_FAILURES,
    LoginThrottle,
    set_login_throttle_for_tests,
)

TEST_PASSWORD = "test-authority-password"
PUBLIC_BASE = "http://127.0.0.1:8787"
EXPECTED_HOST = "127.0.0.1:8787"


@pytest.fixture(autouse=True)
def _reset_login_throttle() -> None:
    set_login_throttle_for_tests(None)


@pytest.fixture
def standalone_app(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    monkeypatch.delenv("RC_STANDALONE_LOOPBACK_AUTH", raising=False)
    monkeypatch.delenv("RC_PUBLIC_BASE_URL", raising=False)
    return create_app(
        db_path=tmp_path / "authority.sqlite3",
        enable_worker=False,
        standalone_loopback_auth=True,
        public_base_url=PUBLIC_BASE,
        authority_test_server=("127.0.0.1", 8787),
    )


@pytest.fixture
def verify_password_counter(monkeypatch: pytest.MonkeyPatch):
    verify_calls = {"count": 0}
    original_verify = __import__(
        "router_control_host.session_routes", fromlist=["verify_hub_admin_password"]
    ).verify_hub_admin_password

    def counting_verify(submitted: str) -> bool:
        verify_calls["count"] += 1
        return original_verify(submitted)

    monkeypatch.setattr(
        "router_control_host.session_routes.verify_hub_admin_password",
        counting_verify,
    )
    return verify_calls


def _client(app, *, host: str = EXPECTED_HOST):
    from fastapi.testclient import TestClient

    return TestClient(app, base_url=PUBLIC_BASE, headers={"Host": host})


def _null_origin_headers() -> dict[str, str]:
    return {
        "Origin": "null",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Dest": "document",
    }


def test_standalone_login_accepts_origin_null(standalone_app) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_null_origin_headers(),
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers.get("set-cookie") is not None
    assert TEST_PASSWORD not in (response.headers.get("set-cookie") or "")


@pytest.mark.parametrize(
    "origin_value",
    ["NULL", "Null", " null", "null ", "foobar", ""],
)
def test_standalone_rejects_non_exact_null_origin(standalone_app, origin_value: str) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={**_null_origin_headers(), "Origin": origin_value},
        )
    assert response.status_code == 401
    assert response.headers.get("set-cookie") is None


def test_standalone_rejects_duplicate_origin(standalone_app) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=[
                ("Origin", "null"),
                ("Origin", "null"),
                ("Sec-Fetch-Site", "same-origin"),
                ("Sec-Fetch-Mode", "navigate"),
                ("Sec-Fetch-Dest", "document"),
            ],
        )
    assert response.status_code == 401


def test_standalone_rejects_wrong_host(standalone_app) -> None:
    with _client(standalone_app, host="localhost:8787") as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": PUBLIC_BASE},
        )
    assert response.status_code == 401


def test_standalone_rejects_trailing_dot_host(standalone_app) -> None:
    with _client(standalone_app, host="127.0.0.1:8787.") as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": PUBLIC_BASE},
        )
    assert response.status_code == 401


def test_standalone_rejects_x_forwarded_host(standalone_app) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={
                "Origin": PUBLIC_BASE,
                "X-Forwarded-Host": "evil.example",
            },
        )
    assert response.status_code == 401


def test_login_skips_password_verify_on_origin_reject(
    standalone_app,
    verify_password_counter: dict[str, int],
) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": "http://evil.example"},
        )
    assert response.status_code == 401
    assert verify_password_counter["count"] == 0


def test_login_skips_password_verify_on_authority_reject(
    standalone_app,
    verify_password_counter: dict[str, int],
) -> None:
    with _client(standalone_app, host="localhost:8787") as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": PUBLIC_BASE},
        )
    assert response.status_code == 401
    assert verify_password_counter["count"] == 0


def test_login_skips_password_verify_on_forwarded_header_reject(
    standalone_app,
    verify_password_counter: dict[str, int],
) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={
                "Origin": PUBLIC_BASE,
                "X-Forwarded-For": "203.0.113.1",
            },
        )
    assert response.status_code == 401
    assert verify_password_counter["count"] == 0


def test_standalone_rejects_origin_null_with_referer(standalone_app) -> None:
    with _client(standalone_app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={
                **_null_origin_headers(),
                "Referer": f"{PUBLIC_BASE}/login",
            },
        )
    assert response.status_code == 401


def test_standalone_logout_accepts_origin_null(standalone_app) -> None:
    with _client(standalone_app) as client:
        login = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": PUBLIC_BASE},
            follow_redirects=False,
        )
        assert login.status_code == 303
        logout = client.post(
            "/logout",
            headers=_null_origin_headers(),
            follow_redirects=False,
        )
    assert logout.status_code == 303
    assert "max-age=0" in logout.headers.get("set-cookie", "").lower()


def test_profile_off_disables_origin_null(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    app = create_app(
        db_path=tmp_path / "profile-off.sqlite3",
        enable_worker=False,
        standalone_loopback_auth=False,
    )
    with _client(app) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=_null_origin_headers(),
        )
    assert response.status_code == 401


def test_login_throttle_blocks_after_max_failures(
    standalone_app,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = {"now": 1000.0}

    def monotonic() -> float:
        return clock["now"]

    throttle = LoginThrottle(clock=monotonic)
    set_login_throttle_for_tests(throttle)
    verify_calls = {"count": 0}
    original_verify = __import__(
        "router_control_host.session_routes", fromlist=["verify_hub_admin_password"]
    ).verify_hub_admin_password

    def counting_verify(submitted: str) -> bool:
        verify_calls["count"] += 1
        return original_verify(submitted)

    monkeypatch.setattr(
        "router_control_host.session_routes.verify_hub_admin_password",
        counting_verify,
    )

    with _client(standalone_app) as client:
        headers = {"Origin": PUBLIC_BASE}
        for _ in range(LOGIN_THROTTLE_MAX_FAILURES):
            bad = client.post("/login", data={"password": "wrong-password"}, headers=headers)
            assert bad.status_code == 401

        blocked = client.post("/login", data={"password": "wrong-password"}, headers=headers)
        assert blocked.status_code == 401
        assert verify_calls["count"] == LOGIN_THROTTLE_MAX_FAILURES

        still_blocked = client.post("/login", data={"password": TEST_PASSWORD}, headers=headers)
        assert still_blocked.status_code == 401

        clock["now"] += 61.0
        after_window = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=headers,
            follow_redirects=False,
        )
        assert after_window.status_code == 303


def test_successful_login_resets_throttle(standalone_app) -> None:
    throttle = LoginThrottle()
    set_login_throttle_for_tests(throttle)
    with _client(standalone_app) as client:
        headers = {"Origin": PUBLIC_BASE}
        client.post("/login", data={"password": "wrong-password"}, headers=headers)
        assert throttle.failure_count() == 1
        ok = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers=headers,
            follow_redirects=False,
        )
        assert ok.status_code == 303
        assert throttle.failure_count() == 0


def test_standalone_ipv6_profile_accepts_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ipv6_base = "http://[::1]:8787"
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    app = create_app(
        db_path=tmp_path / "authority-ipv6.sqlite3",
        enable_worker=False,
        standalone_loopback_auth=True,
        public_base_url=ipv6_base,
        authority_test_server=("::1", 8787),
    )
    from fastapi.testclient import TestClient

    with TestClient(app, base_url="http://testserver", headers={"Host": "[::1]:8787"}) as client:
        response = client.post(
            "/login",
            data={"password": TEST_PASSWORD},
            headers={"Origin": ipv6_base},
            follow_redirects=False,
        )
    assert response.status_code == 303
    assert response.headers.get("set-cookie") is not None


def _port_available(host: str, port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _pick_ephemeral_port(host: str = "127.0.0.1") -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def test_live_uvicorn_origin_null_login(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    db_dir = tmp_path / "data"
    db_dir.mkdir(parents=True)
    from router_control.persistence.connection import open_database

    open_database(db_dir / "router_control.sqlite3")

    port = _pick_ephemeral_port()
    public_base = f"http://127.0.0.1:{port}"
    env = {
        **dict(__import__("os").environ),
        "HUB_ADMIN_PASSWORD": TEST_PASSWORD,
        "RC_STANDALONE_LOOPBACK_AUTH": "1",
        "RC_PUBLIC_BASE_URL": public_base,
        "PYTHONPATH": str(repo_root),
        "ROUTER_CONTROL_DB_PATH": str(db_dir / "router_control.sqlite3"),
    }
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "router_control_host.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(tmp_path),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 30.0
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                stderr_snippet = (proc.stderr.read() if proc.stderr else b"").decode(
                    "utf-8", errors="replace"
                )[:500]
                raise AssertionError(
                    f"uvicorn exited before readiness (code={proc.returncode}): {stderr_snippet}"
                )
            try:
                with httpx.Client(base_url=public_base, timeout=1.0) as client:
                    probe = client.get("/login")
                    if probe.status_code == 200:
                        break
            except Exception as exc:  # noqa: BLE001 - startup polling
                last_error = exc
            time.sleep(0.1)
        else:
            raise AssertionError(f"uvicorn did not become ready: {last_error}")

        with httpx.Client(base_url=public_base, timeout=5.0) as client:
            response = client.post(
                "/login",
                data={"password": TEST_PASSWORD},
                headers={
                    "Host": f"127.0.0.1:{port}",
                    **_null_origin_headers(),
                },
                follow_redirects=False,
            )
        assert response.status_code == 303
        assert "set-cookie" in response.headers
        assert TEST_PASSWORD not in response.text
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
