"""Live sealed-write HTTP paths require non-empty router_id before apply lock."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from router_control.adapters.netcraze.allowlist import LAB_CLASS_EXPENDABLE
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_live_transport import normalize_live_apply_router_id

import router_control_host.keendns_apply_routes as keendns_routes
import router_control_host.routes as routes_mod
import router_control_host.wifi_apply_routes as wifi_routes
import router_control_host.wifi_station_apply_routes as station_routes
import router_control_host.wireguard_apply_routes as wg_routes

from tests.test_vpn_profile_catalog_live_v2 import SAMPLE_PROFILE, _open_gate_a

_API = "/api/router-control/v1"
_VALID_SSH = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
_TEST_AP = "WifiMaster0/AccessPoint3"
_TEST_WG = "Wireguard5"
_ROUTER_ID = "router-lab-1"
_ASC_9 = (5, 50, 1000, 80, 80, 1, 2, 3, 4)
_OFFLINE_PSK = "test-psk-placeholder"

_LIVE_CONN: dict[str, str] = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "credref:router-admin",
    "ssh_host_key_sha256": _VALID_SSH,
    "source_address": "192.168.2.10",
}


def _assert_router_id_required(resp: Any) -> None:
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert "live_connection_incomplete" in err["code"]
    details = err.get("details") or []
    if details:
        assert any(item.get("field") == "router_id" for item in details)
    else:
        assert "router_id" in err.get("message", "")


def _spy_lock_never_called(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> list[str | None]:
    lock_calls: list[str | None] = []

    def _spy(lock_key: str | None, fn: Any) -> Any:
        lock_calls.append(lock_key)
        raise AssertionError("run_with_router_apply_lock must not be called")

    monkeypatch.setattr(module, "run_with_router_apply_lock", _spy)
    return lock_calls


def _patch_live_ready(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    monkeypatch.setattr(f"{module}.is_win32_live_capable", lambda: True)
    monkeypatch.setattr(
        f"{module}.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    )


def _patch_vpn_live_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_live_ready(monkeypatch, "router_control_host.wireguard_apply_routes")
    monkeypatch.setattr(routes_mod, "is_win32_live_capable", lambda: True)


def _spy_lock_key_recorder(
    monkeypatch: pytest.MonkeyPatch,
    module: Any,
) -> list[str | None]:
    lock_keys: list[str | None] = []

    def _spy(lock_key: str | None, fn: Any) -> Any:
        lock_keys.append(lock_key)
        raise RuntimeError("lock-observed")

    monkeypatch.setattr(module, "run_with_router_apply_lock", _spy)
    return lock_keys


def _seed_live_router_with_pin(client: Any) -> str:
    store = client.test_app.state.host.runtime.store
    site_id = store.create_site(display_name="Live Apply Lock Key Lab")
    store.enroll_router(
        site_id=site_id,
        display_name="Lock Key Router",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lock-key-test",
        host=_LIVE_CONN["host"],
        port=22,
        kind="ssh_tunnel",
        source_address=_LIVE_CONN["source_address"],
        router_id=_ROUTER_ID,
    )
    store.set_endpoint_ssh_host_key(
        _ROUTER_ID,
        _LIVE_CONN["ssh_host_key_sha256"],
        "ssh-ed25519",
        "operator_supplied",
    )
    return _ROUTER_ID


@pytest.fixture
def live_wifi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "live-router-id-wifi.sqlite3", allow_fake_mutations=True)
    app.state.host.gate_a_certification = _open_gate_a()
    app.state.host.wifi_apply_transport_factory = lambda: (_ for _ in ()).throw(
        AssertionError("offline transport must not be used on live path")
    )
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _OFFLINE_PSK
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_app = app
        yield client


@pytest.fixture
def live_wg_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "live-router-id-wg.sqlite3", allow_fake_mutations=True)
    app.state.host.gate_a_certification = _open_gate_a()
    app.state.host.wireguard_apply_transport_factory = lambda: (_ for _ in ()).throw(
        AssertionError("offline transport must not be used on live path")
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_app = app
        yield client


@pytest.fixture
def live_station_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(
        db_path=tmp_path / "live-router-id-station.sqlite3",
        allow_fake_mutations=True,
    )
    app.state.host.gate_a_certification = _open_gate_a()
    app.state.host.wifi_station_apply_transport_factory = lambda: (_ for _ in ()).throw(
        AssertionError("offline transport must not be used on live path")
    )
    app.state.host.wifi_station_apply_credential_resolver = lambda _ref: _OFFLINE_PSK
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_app = app
        yield client


@pytest.fixture
def live_keendns_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", LAB_CLASS_EXPENDABLE)
    app = create_app(
        db_path=tmp_path / "live-router-id-keendns.sqlite3",
        allow_fake_mutations=True,
    )
    app.state.host.gate_a_certification = _open_gate_a()
    app.state.host.keendns_apply_transport_factory = lambda: (_ for _ in ()).throw(
        AssertionError("offline transport must not be used on live path")
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_app = app
        yield client


@pytest.fixture
def live_vpn_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "fake")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(
        db_path=tmp_path / "live-router-id-vpn.sqlite3",
        enable_worker=False,
    )
    app.state.host.gate_a_certification = _open_gate_a()
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_app = app
        yield client


def test_normalize_live_apply_router_id() -> None:
    assert normalize_live_apply_router_id(" router-lab-1 ") == "router-lab-1"
    assert normalize_live_apply_router_id(None) is None
    assert normalize_live_apply_router_id("") is None
    assert normalize_live_apply_router_id("   ") is None


def test_wifi_apply_live_omitted_router_id_rejects_before_lock(
    live_wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_calls = _spy_lock_never_called(monkeypatch, wifi_routes)
    _patch_live_ready(monkeypatch, "router_control_host.wifi_apply_routes")
    payload = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
        **_LIVE_CONN,
    }
    resp = live_wifi_client.post(f"{_API}/wifi/apply", json=payload)
    _assert_router_id_required(resp)
    assert lock_calls == []


def test_wireguard_apply_live_omitted_router_id_rejects_before_lock(
    live_wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_calls = _spy_lock_never_called(monkeypatch, wg_routes)
    _patch_live_ready(monkeypatch, "router_control_host.wireguard_apply_routes")
    payload = {
        "wg_id": _TEST_WG,
        "enabled": True,
        "asc_args": list(_ASC_9),
        "confirm_live_apply": True,
        **_LIVE_CONN,
    }
    resp = live_wg_client.post(f"{_API}/wireguard/apply", json=payload)
    _assert_router_id_required(resp)
    assert lock_calls == []


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        (
            f"{_API}/wifi/station/apply",
            {
                "mode": "WifiWan",
                "ssid": "Venue-Guest",
                "band": "BAND_2_4GHZ",
                "credential_ref_id": "credref:venue-wifi",
                "priority": 100,
                "confirm_live_apply": True,
                **_LIVE_CONN,
            },
        ),
        (
            f"{_API}/wifi/station/teardown",
            {
                "confirm_live_teardown": True,
                "ssid": "Venue-Guest",
                "credential_ref_id": "credref:venue-wifi",
                **_LIVE_CONN,
            },
        ),
        (
            f"{_API}/wifi/teardown",
            {
                "ap_id": _TEST_AP,
                "wpa_mode": "WPA2",
                "confirm_live_teardown": True,
                **_LIVE_CONN,
            },
        ),
        (
            f"{_API}/wireguard/teardown",
            {
                "wg_id": _TEST_WG,
                "enabled": False,
                "confirm_live_apply": True,
                **_LIVE_CONN,
            },
        ),
    ],
)
def test_live_teardown_paths_omitted_router_id_reject_before_lock(
    path: str,
    payload: dict[str, object],
    live_wifi_client,
    live_station_client,
    live_wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if "wifi/station" in path:
        client = live_station_client
        module = station_routes
        module_path = "router_control_host.wifi_station_apply_routes"
    elif path.endswith("/wifi/teardown"):
        client = live_wifi_client
        module = wifi_routes
        module_path = "router_control_host.wifi_apply_routes"
    else:
        client = live_wg_client
        module = wg_routes
        module_path = "router_control_host.wireguard_apply_routes"
    lock_calls = _spy_lock_never_called(monkeypatch, module)
    _patch_live_ready(monkeypatch, module_path)
    resp = client.post(path, json=payload)
    _assert_router_id_required(resp)
    assert lock_calls == []


def test_keendns_apply_live_omitted_router_id_rejects_before_lock(
    live_keendns_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_calls = _spy_lock_never_called(monkeypatch, keendns_routes)
    _patch_live_ready(monkeypatch, "router_control_host.keendns_apply_routes")
    payload = {
        "intent_kind": "book",
        "name": "sample-name",
        "domain": "netcraze.pro",
        "mode": "auto",
        "confirm_live_apply": True,
        **_LIVE_CONN,
    }
    resp = live_keendns_client.post(f"{_API}/keendns/apply", json=payload)
    _assert_router_id_required(resp)
    assert lock_calls == []


def test_vpn_activate_live_omitted_router_id_rejects_before_lock(
    live_vpn_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_calls = _spy_lock_never_called(monkeypatch, routes_mod)
    _patch_vpn_live_ready(monkeypatch)
    import_resp = live_vpn_client.post(
        f"{_API}/vpn-profiles/import",
        json={
            "display_name": "Router Id Required Activate",
            "profile_text": SAMPLE_PROFILE,
            "vpn_kind": "AmneziaWG",
        },
        headers={"Idempotency-Key": "import-router-id-required-activate"},
    )
    assert import_resp.status_code == 201
    profile_id = import_resp.json()["profile_id"]
    resp = live_vpn_client.post(
        f"{_API}/vpn-profiles/{profile_id}/activate",
        json={"confirm_live_apply": True, "wg_id": _TEST_WG, **_LIVE_CONN},
    )
    _assert_router_id_required(resp)
    assert lock_calls == []


def test_vpn_deactivate_live_omitted_router_id_rejects_before_lock(
    live_vpn_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_calls = _spy_lock_never_called(monkeypatch, routes_mod)
    _patch_vpn_live_ready(monkeypatch)
    resp = live_vpn_client.post(
        f"{_API}/vpn-profiles/deactivate",
        json={"confirm_live_apply": True, "wg_id": _TEST_WG, **_LIVE_CONN},
    )
    _assert_router_id_required(resp)
    assert lock_calls == []


def test_wifi_apply_live_blank_router_id_rejects_before_lock(
    live_wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_calls = _spy_lock_never_called(monkeypatch, wifi_routes)
    _patch_live_ready(monkeypatch, "router_control_host.wifi_apply_routes")
    payload = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
        "router_id": "   ",
        **_LIVE_CONN,
    }
    resp = live_wifi_client.post(f"{_API}/wifi/apply", json=payload)
    _assert_router_id_required(resp)
    assert lock_calls == []


def test_wifi_apply_live_router_id_used_as_lock_key(
    live_wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _seed_live_router_with_pin(live_wifi_client)
    lock_keys = _spy_lock_key_recorder(monkeypatch, wifi_routes)
    _patch_live_ready(monkeypatch, "router_control_host.wifi_apply_routes")
    payload = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
        "router_id": f" {_ROUTER_ID} ",
        **_LIVE_CONN,
    }
    resp = live_wifi_client.post(f"{_API}/wifi/apply", json=payload)
    assert lock_keys == [_ROUTER_ID]
    assert resp.status_code != 422
