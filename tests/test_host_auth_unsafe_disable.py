"""Unsafe dev auth bypass (RC_UNSAFE_DISABLE_AUTH) — AC proofs."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from router_control_host.app import UNSAFE_AUTH_ARMED_MESSAGE, create_app

PUBLIC_BASE = "http://127.0.0.1:8787"
EXPECTED_HOST = "127.0.0.1:8787"
TEST_PASSWORD = "unsafe-disable-test-password"
STATUS_PATH = "/api/router-control/v1/status"
UI_PATH = "/settings/router-control"


def _client(app, *, host: str = EXPECTED_HOST) -> TestClient:
    return TestClient(app, base_url=PUBLIC_BASE, headers={"Host": host})


def _fake_standalone_app(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    unsafe_disable_auth: bool = False,
    password: str = TEST_PASSWORD,
    set_env_flag: bool = False,
) -> object:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", password)
    monkeypatch.delenv("RC_UNSAFE_DISABLE_AUTH", raising=False)
    monkeypatch.delenv("RC_STANDALONE_LOOPBACK_AUTH", raising=False)
    monkeypatch.delenv("RC_PUBLIC_BASE_URL", raising=False)
    if set_env_flag:
        monkeypatch.setenv("RC_UNSAFE_DISABLE_AUTH", "1")
    return create_app(
        db_path=tmp_path / "unsafe.sqlite3",
        enable_worker=False,
        adapter_mode="fake",
        standalone_loopback_auth=True,
        public_base_url=PUBLIC_BASE,
        authority_test_server=("127.0.0.1", 8787),
        unsafe_disable_auth=unsafe_disable_auth if not set_env_flag else None,
    )


def test_ac1_no_flag_requires_auth_with_standalone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1: flag unset + fake + standalone → protected paths still 401 without cookie."""
    app = _fake_standalone_app(tmp_path, monkeypatch, unsafe_disable_auth=False)
    with _client(app) as client:
        assert client.get(UI_PATH, follow_redirects=False).status_code == 401
        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401


def test_ac1_no_flag_requires_auth_without_standalone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-1: flag unset + fake without standalone → protected paths still 401."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    app = create_app(
        db_path=tmp_path / "no-standalone.sqlite3",
        enable_worker=False,
        adapter_mode="fake",
    )
    with TestClient(app) as client:
        assert client.get(UI_PATH, follow_redirects=False).status_code == 401
        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401


def test_ac2_flag_standalone_fake_bypasses_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-2: flag + standalone + fake → /, UI, API work without cookie (empty password OK)."""
    app = _fake_standalone_app(
        tmp_path,
        monkeypatch,
        unsafe_disable_auth=True,
        password="",
    )
    with _client(app) as client:
        root = client.get("/", follow_redirects=False)
        assert root.status_code == 302
        assert root.headers["location"] == "/settings/router-control"

        login = client.get("/login", follow_redirects=False)
        assert login.status_code == 302
        assert login.headers["location"] == "/settings/router-control"

        ui = client.get(UI_PATH, follow_redirects=False)
        assert ui.status_code == 200

        status = client.get(STATUS_PATH, follow_redirects=False)
        assert status.status_code == 200


def test_ac2_env_flag_via_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-2/AC-5: RC_UNSAFE_DISABLE_AUTH=1 env arms bypass and prints loud startup warning."""
    app = _fake_standalone_app(
        tmp_path,
        monkeypatch,
        set_env_flag=True,
        password="",
    )
    captured = capsys.readouterr()
    assert UNSAFE_AUTH_ARMED_MESSAGE in captured.err
    assert app.state.unsafe_dev_auth_disabled is True
    with _client(app) as client:
        assert client.get(STATUS_PATH).status_code == 200


def test_ac3_live_adapter_ignores_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-3: flag + standalone + live adapter → auth still required (live ignores flag)."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    monkeypatch.delenv("RC_UNSAFE_DISABLE_AUTH", raising=False)
    app = create_app(
        db_path=tmp_path / "live.sqlite3",
        enable_worker=False,
        adapter_mode="live",
        skip_gate_a_load=True,
        standalone_loopback_auth=True,
        public_base_url=PUBLIC_BASE,
        authority_test_server=("127.0.0.1", 8787),
        unsafe_disable_auth=True,
    )
    captured = capsys.readouterr()
    assert "IGNORED" in captured.err
    assert app.state.unsafe_dev_auth_disabled is False
    with _client(app) as client:
        assert client.get(UI_PATH, follow_redirects=False).status_code == 401
        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401


def test_ac4a_runtime_adapter_mode_flip_stops_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4a: after fake arm, mutate adapter_mode to live → bypass stops (401)."""
    app = _fake_standalone_app(tmp_path, monkeypatch, unsafe_disable_auth=True)
    assert app.state.unsafe_dev_auth_disabled is True
    app.state.host.adapter_mode = "live"
    with _client(app) as client:
        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401
        assert client.get(UI_PATH, follow_redirects=False).status_code == 401


def test_ac4b_live_create_with_forced_arm_bit_still_401(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4b: live + flag + standalone; forced arm bit → request-time live check → 401."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    app = create_app(
        db_path=tmp_path / "live-forced.sqlite3",
        enable_worker=False,
        adapter_mode="live",
        skip_gate_a_load=True,
        standalone_loopback_auth=True,
        public_base_url=PUBLIC_BASE,
        authority_test_server=("127.0.0.1", 8787),
        unsafe_disable_auth=True,
    )
    app.state.unsafe_dev_auth_disabled = True
    with _client(app) as client:
        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401


def test_ac4c_deleted_adapter_mode_denies_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4/INV-2: armed bypass + deleted adapter_mode attribute → fail-closed 401."""
    app = _fake_standalone_app(tmp_path, monkeypatch, unsafe_disable_auth=True)
    assert app.state.unsafe_dev_auth_disabled is True

    with _client(app) as client:
        class _MutableHost:
            wireguard_apply_transport_factory = None

        host = _MutableHost()
        host.adapter_mode = "fake"
        delattr(host, "adapter_mode")
        app.state.host = host

        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401
        assert client.get(UI_PATH, follow_redirects=False).status_code == 401


def test_ac4d_null_host_denies_bypass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AC-4/INV-2: armed bypass + app.state.host=None → fail-closed 401."""
    app = _fake_standalone_app(tmp_path, monkeypatch, unsafe_disable_auth=True)
    assert app.state.unsafe_dev_auth_disabled is True

    with _client(app) as client:
        app.state.host = None

        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401
        assert client.get(UI_PATH, follow_redirects=False).status_code == 401


def test_ac5_flag_requested_without_standalone_warns(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """AC-5: flag set but no standalone profile → ignored warning, auth required."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", TEST_PASSWORD)
    app = create_app(
        db_path=tmp_path / "no-standalone-flag.sqlite3",
        enable_worker=False,
        adapter_mode="fake",
        unsafe_disable_auth=True,
    )
    captured = capsys.readouterr()
    assert "IGNORED" in captured.err
    assert app.state.unsafe_dev_auth_disabled is False
    with TestClient(app) as client:
        assert client.get(STATUS_PATH, follow_redirects=False).status_code == 401
