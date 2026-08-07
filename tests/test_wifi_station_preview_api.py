"""Wi-Fi station preview host API tests (read-only offline compile)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from router_control.adapters.netcraze.wifi_station_rci import WifiStationRciOperation
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_PREVIEW_BODY = {
    "mode": "WifiWan",
    "ssid": "SYNTH-VENUE-NET",
    "band": "BAND_2_4GHZ",
    "credential_ref_id": "credref:venue-wifi",
}


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "station-preview.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        tc.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield tc


def test_wifi_station_preview_requires_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "station-preview-auth.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as tc:
        resp = tc.post("/api/router-control/v1/wifi/station/preview", json=_PREVIEW_BODY)
    assert resp.status_code == 401


def test_wifi_station_preview_compiles_offline(client) -> None:
    resp = client.post("/api/router-control/v1/wifi/station/preview", json=_PREVIEW_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["grammar_verification_status"] == "device_accepted_grammar"
    assert body["planned_uplink_verification_level"] == "planned_uplink_verified_bounded"
    assert "uplink_verification_status" not in body
    assert body["verification_status"] == "device_accepted_grammar"
    assert body["station_id"] == "WifiMaster0/WifiStation0"
    ops = [op["operation"] for op in body["apply_ops"]]
    assert WifiStationRciOperation.SET_SSID.value in ops
    assert WifiStationRciOperation.SET_WPA_PSK.value in ops


def test_wifi_station_preview_open_network_422(client) -> None:
    resp = client.post(
        "/api/router-control/v1/wifi/station/preview",
        json={
            "mode": "WifiWan",
            "ssid": "OPEN-NET",
            "band": "BAND_2_4GHZ",
            "auth_mode": "open",
        },
    )
    assert resp.status_code == 422
    assert "open-network authentication grammar" in resp.json()["error"]["message"]


def test_wifi_station_preview_missing_credential_422(client) -> None:
    resp = client.post(
        "/api/router-control/v1/wifi/station/preview",
        json={
            "mode": "WifiWan",
            "ssid": "SYNTH-VENUE-NET",
            "band": "BAND_2_4GHZ",
        },
    )
    assert resp.status_code == 422
    assert "credential_ref_id" in resp.json()["error"]["message"]


def test_wifi_station_preview_non_default_priority_422(client) -> None:
    payload = dict(_PREVIEW_BODY, priority=600)
    resp = client.post("/api/router-control/v1/wifi/station/preview", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.station_priority_requires_ip_global"


def test_wifi_station_preview_rejects_extra_fields(client) -> None:
    payload = dict(_PREVIEW_BODY)
    payload["password"] = "must-not-accept"
    resp = client.post("/api/router-control/v1/wifi/station/preview", json=payload)
    assert resp.status_code == 422


def test_wifi_station_preview_no_secret_in_response(client) -> None:
    resp = client.post("/api/router-control/v1/wifi/station/preview", json=_PREVIEW_BODY)
    assert resp.status_code == 200
    body = resp.json()
    forbidden_keys = {"password", "passphrase", "preshared", "secret", "private_key"}

    def _walk(obj: object) -> None:
        if isinstance(obj, dict):
            for key, value in obj.items():
                assert key.lower() not in forbidden_keys
                _walk(value)
        elif isinstance(obj, list):
            for item in obj:
                _walk(item)

    _walk(body)
    allowed_psk_ops = {
        WifiStationRciOperation.SET_WPA_PSK.value,
        WifiStationRciOperation.CLEAR_WPA_PSK.value,
    }
    for op in body["apply_ops"] + body.get("teardown_ops", []):
        if "psk" in op["operation"]:
            assert op["operation"] in allowed_psk_ops
    psk_ops = [
        op
        for op in body["apply_ops"]
        if op["operation"] == WifiStationRciOperation.SET_WPA_PSK.value
    ]
    assert len(psk_ops) == 1
    assert psk_ops[0]["credential_ref_id"] == _PREVIEW_BODY["credential_ref_id"]
    serialized = json.dumps(body).lower()
    assert "test-passphrase" not in serialized
    assert '"password"' not in serialized
