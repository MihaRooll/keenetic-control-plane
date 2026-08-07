"""Wi-Fi observed-state host API tests."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from router_control.application.router_discovery import (
    ENROLLMENT_DRAFT_LIFECYCLE,
    ENROLLMENT_DRAFT_MODEL,
)
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_TEST_AP = "WifiMaster0/AccessPoint3"
_TEST_AP_TORN = "WifiMaster0/AccessPoint4"
_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


class ApiFakeObservedTransport:
    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        if _TEST_AP in cli_command:
            return {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "up",
                    "up": True,
                    "link": "up",
                    "connected": True,
                    "psk": "must-not-leak",
                }
            }
        if _TEST_AP_TORN in cli_command:
            return {
                "interface": {
                    "ssid": None,
                    "encryption": {},
                    "state": "down",
                    "up": False,
                    "link": "down",
                    "connected": True,
                }
            }
        return {
            "interface": {
                "ssid": "",
                "encryption": {},
                "state": "down",
                "up": False,
                "link": "down",
                "connected": True,
            }
        }


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(
        db_path=tmp_path / "wifi-observed.sqlite3",
        allow_fake_mutations=False,
        adapter_mode="fake",
    )
    application.state.host.wifi_observed_transport_factory = ApiFakeObservedTransport
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_wifi_observed_state_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        response = c.post(
            "/api/router-control/v1/wifi/observed-state",
            json={"ap_ids": [_TEST_AP]},
        )
    assert response.status_code == 401


def test_wifi_observed_state_rejects_extra_password(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], "password": "must-not-accept"},
    )
    assert response.status_code == 422


def test_wifi_observed_state_fake_deterministic(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["certification_eligible"] is False
    assert body["offline_verified_only"] is True
    assert body["access_points"][0]["ap_id"] == _TEST_AP
    assert body["access_points"][0]["wpa_mode"] == "WPA2"
    assert body["access_points"][0]["link_up"] is True
    assert body["access_points"][0]["device_connected"] is True


def test_wifi_observed_state_torn_down_ap_link_fields(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP_TORN]},
    )
    assert response.status_code == 200
    ap = response.json()["access_points"][0]
    assert ap["ap_id"] == _TEST_AP_TORN
    assert ap["link_up"] is False
    assert ap["device_connected"] is True
    assert ap["wpa_mode"] == "not_configured"


def test_wifi_observed_state_no_secret_leakage(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP]},
    )
    serialized = json.dumps(response.json())
    assert "must-not-leak" not in serialized
    assert "must-not-leak" not in serialized.lower()


def test_wifi_observed_state_with_desired_comparison(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={
            "ap_ids": [_TEST_AP],
            "desired_ap_id": _TEST_AP,
            "desired": {
                "ssid": "Staff-Private",
                "enabled": True,
                "wpa_mode": "WPA2",
                "band": "BAND_2_4GHZ",
            },
        },
    )
    assert response.status_code == 200
    comparisons = response.json()["comparisons"][_TEST_AP]
    assert comparisons["ssid"] == "match"
    assert comparisons["wpa_mode"] == "match"


def test_wifi_observed_state_default_fake_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    db_path = tmp_path / "wifi-observed-default.sqlite3"
    application = create_app(db_path=db_path, adapter_mode="fake")
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/observed-state",
            json={"ap_ids": [_TEST_AP]},
        )
    assert response.status_code == 200
    ap = response.json()["access_points"][0]
    assert ap["ssid"] == "Staff-Private"
    assert ap["link_up"] is True
    assert ap["device_connected"] is True


def _pin_for(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def _seed_live_shape_store(app_env) -> str:
    store = app_env.state.host.runtime.store
    base = datetime(2026, 8, 3, 10, 0, tzinfo=UTC)
    site = store.create_site(display_name="Lab", now=base)
    host = "192.168.2.1"

    for index in range(3):
        created = base + timedelta(minutes=index)
        draft_id = store.enroll_router(
            site_id=site,
            display_name=f"Draft {index}",
            vendor="Netcraze",
            model=ENROLLMENT_DRAFT_MODEL,
            identity_fingerprint=f"digest:draft:{index}",
            host=host,
            port=443,
            kind="management_https",
            source_address=None,
            now=created,
        )
        store._conn.execute(
            "UPDATE routers SET lifecycle_status = ? WHERE router_id = ?",
            (ENROLLMENT_DRAFT_LIFECYCLE, draft_id),
        )
        store.set_endpoint_ssh_host_key(
            draft_id,
            _pin_for(f"draft-pin-{index}".encode()),
            "ssh-ed25519",
            "learned_confirmed",
            pinned_at=created.isoformat().replace("+00:00", "Z"),
        )

    genuine_id = store.enroll_router(
        site_id=site,
        display_name="Lab NC-1812",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lab:enrolled",
        host=host,
        port=22,
        kind="ssh_tunnel",
        source_address="192.168.2.10",
        now=base - timedelta(hours=1),
    )
    store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (genuine_id,),
    )
    genuine_cred = store.insert_credential_ref(
        router_id=genuine_id,
        kind="RouterManagementPassword",
        provider="test",
        provider_locator="loc-genuine",
        now=base,
    )
    store.set_router_credential_ref(genuine_id, genuine_cred, now=base)
    return genuine_id


def test_wifi_observed_state_main_shape_without_router_id_refused(
    app_env,
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Main live verification tuple without router_id against live-shaped store."""
    _seed_live_shape_store(app_env)
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    response = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={
            "ap_ids": [_TEST_AP],
            "host": "192.168.2.1",
            "username": "admin",
            "router_credential_ref_id": "credref:router-admin",
            "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
            "source_address": "192.168.2.10",
        },
    )
    assert response.status_code == 422
    err = response.json()["error"]
    assert err["code"] == "wifi.live_connection_incomplete"
    assert "ssh_host_key_sha256" in err["message"]
    assert _VALID_SSH_HOST_KEY_SHA256 not in err["message"]
    details = err["details"]
    assert len(details) >= 1
    assert any(item.get("field") == "ssh_host_key_sha256" for item in details)
