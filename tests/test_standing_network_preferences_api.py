"""Standing network preferences API tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "standing-api.sqlite3")
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
        display_name="API Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-standing-api",
        host="127.0.0.1",
        now=now,
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind=kind,
        provider="memory",
        provider_locator="api-loc",
        now=now,
    )
    if revoke:
        store.mark_credential_revoked(cred_id, now=now)
    return cred_id


def test_get_standing_preferences_never_contains_password_keys(client) -> None:
    response = client.get("/api/router-control/v1/standing-network-preferences")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert "password" not in payload
    assert "secret" not in payload
    assert payload["guest_default_enabled"] is False
    assert payload["staff_password_configured"] is False
    assert payload["staff_ssid"] == "Рабочая сеть"
    assert payload["guest_default_ssid"] == "Гостевая сеть"
    assert "staff_ap_id" in payload
    assert "guest_ap_id" in payload
    assert payload["staff_ap_id"] is None
    assert payload["guest_ap_id"] is None


def test_get_configured_false_for_revoked_ref(client) -> None:
    cred_id = _seed_wifi_credential(client, revoke=True)
    store = client.app.state.host.runtime.store
    store.upsert_standing_network_preferences(
        staff_password_credential_ref_id=cred_id,
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )
    response = client.get("/api/router-control/v1/standing-network-preferences")
    assert response.status_code == 200
    payload = response.json()
    assert payload["staff_password_configured"] is False
    assert payload["staff_password_credential_ref_id"] is None


def test_put_validates_credential_ref_kind(client) -> None:
    cred_id = _seed_wifi_credential(client, kind="RouterPassword")
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_password_credential_ref_id": cred_id},
    )
    assert response.status_code == 422
    assert "RouterPassword" not in response.text


def test_put_accepts_usable_wifi_ap_psk_ref(client) -> None:
    cred_id = _seed_wifi_credential(client)
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_password_credential_ref_id": cred_id},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["staff_password_configured"] is True
    assert payload["staff_password_credential_ref_id"] == cred_id


def test_put_rejects_secret_shaped_keys_without_echo(client) -> None:
    secret_value = "super-secret-not-in-repo-8"
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
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
        "/api/router-control/v1/standing-network-preferences",
        json={field: "value-not-echoed-12345678"},
    )
    assert response.status_code == 422
    assert "value-not-echoed" not in response.text


def test_put_rejects_guest_default_enabled_true(client) -> None:
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_default_enabled": True},
    )
    assert response.status_code == 422


def test_put_guest_default_enabled_false_is_noop(client) -> None:
    before = client.get("/api/router-control/v1/standing-network-preferences").json()
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_default_enabled": False},
    )
    assert response.status_code == 200
    after = response.json()
    assert after["guest_default_enabled"] is False
    assert after["staff_ssid"] == before["staff_ssid"]


def test_routes_require_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "standing-auth.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as anon:
        assert (
            anon.get("/api/router-control/v1/standing-network-preferences").status_code == 401
        )
        assert (
            anon.put(
                "/api/router-control/v1/standing-network-preferences",
                json={"staff_ssid": "X"},
            ).status_code
            == 401
        )


def test_put_updates_guest_default_ssid(client) -> None:
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_default_ssid": "Guest Event"},
    )
    assert response.status_code == 200
    assert response.json()["guest_default_ssid"] == "Guest Event"


def test_get_standing_preferences_self_heals_after_row_deleted(client) -> None:
    store = client.app.state.host.runtime.store
    store.conn.execute("DELETE FROM standing_network_preferences")
    store.conn.commit()
    response = client.get("/api/router-control/v1/standing-network-preferences")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["staff_ssid"] == "Рабочая сеть"
    assert payload["guest_default_ssid"] == "Гостевая сеть"
    assert payload["staff_password_configured"] is False


@pytest.mark.parametrize(
    "ap_id",
    ["WifiMaster0/AccessPoint0", "WifiMaster0/AccessPoint1", "WifiMaster1/AccessPoint2"],
)
def test_put_staff_ap_id_accepts_canonical_outside_auth_window(client, ap_id: str) -> None:
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": ap_id},
    )
    assert response.status_code == 200, response.text
    assert response.json()["staff_ap_id"] == ap_id


@pytest.mark.parametrize(
    "ap_id",
    ["AccessPoint7", "WifiMaster0/AccessPoint7", "wifimaster0/AccessPoint0"],
)
def test_put_staff_ap_id_rejects_invalid_shape(client, ap_id: str) -> None:
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": ap_id},
    )
    assert response.status_code == 422


def test_put_staff_ap_id_null_clears_assignment(client) -> None:
    ap_id = "WifiMaster0/AccessPoint0"
    assert client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": ap_id},
    ).status_code == 200
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": None},
    )
    assert response.status_code == 200
    assert response.json()["staff_ap_id"] is None


@pytest.mark.parametrize(
    "ap_id",
    ["WifiMaster0/AccessPoint0", "WifiMaster0/AccessPoint1", "WifiMaster1/AccessPoint2"],
)
def test_put_guest_ap_id_accepts_canonical_outside_auth_window(client, ap_id: str) -> None:
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_ap_id": ap_id},
    )
    assert response.status_code == 200, response.text
    assert response.json()["guest_ap_id"] == ap_id


@pytest.mark.parametrize(
    "ap_id",
    ["AccessPoint7", "WifiMaster0/AccessPoint7", "wifimaster0/AccessPoint0"],
)
def test_put_guest_ap_id_rejects_invalid_shape(client, ap_id: str) -> None:
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_ap_id": ap_id},
    )
    assert response.status_code == 422


def test_put_guest_ap_id_null_clears_assignment(client) -> None:
    ap_id = "WifiMaster0/AccessPoint0"
    assert client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_ap_id": ap_id},
    ).status_code == 200
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_ap_id": None},
    )
    assert response.status_code == 200
    assert response.json()["guest_ap_id"] is None


def test_put_rejects_overlapping_ap_roles(client) -> None:
    ap_id = "WifiMaster0/AccessPoint0"
    assert client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": ap_id},
    ).status_code == 200
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"guest_ap_id": ap_id},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "standing.ap_role_overlap"


def test_put_rejects_simultaneous_same_ap_roles(client) -> None:
    ap_id = "WifiMaster0/AccessPoint1"
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": ap_id, "guest_ap_id": ap_id},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "standing.ap_role_overlap"


def test_put_staff_ap_id_rejects_when_guest_already_assigned(client) -> None:
    staff_ap = "WifiMaster0/AccessPoint2"
    guest_ap = "WifiMaster0/AccessPoint3"
    assert client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": staff_ap, "guest_ap_id": guest_ap},
    ).status_code == 200
    response = client.put(
        "/api/router-control/v1/standing-network-preferences",
        json={"staff_ap_id": guest_ap},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "standing.ap_role_overlap"
