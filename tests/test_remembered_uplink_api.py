"""Remembered uplink API tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "remembered-api.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _seed_wifi_credential(client, *, kind: str = "WifiApPsk", revoke: bool = False) -> str:
    store = client.app.state.host.runtime.store
    site_id = client.app.state.host.resolve_site_id()
    now = datetime(2026, 8, 5, tzinfo=UTC)
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="Uplink API Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-remembered-api",
        host="127.0.0.1",
        now=now,
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind=kind,
        provider="memory",
        provider_locator="remembered-api-loc",
        now=now,
    )
    if revoke:
        store.mark_credential_revoked(cred_id, now=now)
    return cred_id


def test_get_remembered_uplink_never_contains_password_keys(client) -> None:
    response = client.get("/api/router-control/v1/remembered-uplink")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "password" not in payload
    assert "secret" not in payload
    assert payload["desired_active"] is False
    assert payload["credential_configured"] is False


def test_get_watchdog_status_exposes_uplink_watchdog_fields(client) -> None:
    response = client.get("/api/router-control/v1/remembered-uplink/watchdog-status")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "uplink_watchdog_enabled" in payload
    assert "uplink_watchdog_poll_seconds" in payload
    assert "uplink_watchdog_running" in payload
    assert isinstance(payload["uplink_watchdog_running"], bool)


def test_put_accepts_usable_wifi_ap_psk_ref(client) -> None:
    cred_id = _seed_wifi_credential(client)
    response = client.put(
        "/api/router-control/v1/remembered-uplink",
        json={
            "ssid": "UpstreamWiFi",
            "band": "BAND_2_4GHZ",
            "credential_ref_id": cred_id,
            "desired_active": True,
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["credential_configured"] is True
    assert payload["credential_ref_id"] == cred_id
    assert payload["desired_active"] is True
    assert payload["ssid"] == "UpstreamWiFi"


def test_put_rejects_secret_shaped_keys_without_echo(client) -> None:
    secret_value = "super-secret-not-in-repo-8"
    response = client.put(
        "/api/router-control/v1/remembered-uplink",
        json={"password": secret_value},
    )
    assert response.status_code == 422
    assert secret_value not in response.text


@pytest.mark.parametrize(
    "field",
    ["secret", "psk", "passphrase", "wpa_psk", "key", "wifi_password"],
)
def test_put_rejects_other_secret_shaped_keys(client, field: str) -> None:
    response = client.put(
        "/api/router-control/v1/remembered-uplink",
        json={field: "value-not-echoed-12345678"},
    )
    assert response.status_code == 422
    assert "value-not-echoed" not in response.text


def test_delete_clears_remembered_uplink(client) -> None:
    cred_id = _seed_wifi_credential(client)
    client.put(
        "/api/router-control/v1/remembered-uplink",
        json={
            "ssid": "ToForget",
            "credential_ref_id": cred_id,
            "desired_active": True,
        },
    )
    response = client.delete("/api/router-control/v1/remembered-uplink")
    assert response.status_code == 200
    payload = response.json()
    assert payload["desired_active"] is False
    assert payload["ssid"] == ""


def test_routes_require_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "remembered-auth.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as anon:
        assert anon.get("/api/router-control/v1/remembered-uplink").status_code == 401
        assert (
            anon.get("/api/router-control/v1/remembered-uplink/watchdog-status").status_code
            == 401
        )
        assert (
            anon.put(
                "/api/router-control/v1/remembered-uplink",
                json={"ssid": "X", "desired_active": True},
            ).status_code
            == 401
        )
        assert anon.delete("/api/router-control/v1/remembered-uplink").status_code == 401
