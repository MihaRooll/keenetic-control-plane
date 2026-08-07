"""Bootstrap discovery host API."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.bootstrap_discovery import BootstrapDiscoveryError
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"


def _sample_report() -> dict[str, object]:
    return {
        "certification_eligible": False,
        "transport_security": "insecure_http",
        "https_check": "not_certified",
        "model": "NC-1812",
        "firmware_version": "4.03.C.6.4-16",
        "firmware_digest": "sha256:abc",
        "fingerprint_digest": "sha256:def",
        "component_set_digest": "sha256:ghi",
        "ssh_component_installed": False,
        "ssh_access_enabled": False,
        "wifi_access_points": [{"interface_id_hash": "sha256:ap0", "link_up": True}],
        "findings": ["firmware_below_verified_baseline", "ssh_component_missing", "ssh_disabled"],
        "components_inventory": {
            "entries": [{"id": "ndm", "installed": True}],
            "total_observed": 3,
            "truncated": False,
            "source_shape": "component_map",
        },
        "ssh_component_determination": {
            "lookup": "component.ssh",
            "matched": False,
            "outcome": "key_absent",
        },
    }


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(db_path=tmp_path / "bootstrap.sqlite3", allow_fake_mutations=False)
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_bootstrap_discovery_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        response = c.post(
            "/api/router-control/v1/lab/bootstrap-discovery",
            json={
                "host": "http://192.168.2.1",
                "username": "admin",
                "credential_ref_id": "cred_test",
                "allow_insecure_http": True,
            },
        )
    assert response.status_code == 401


@patch("router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery")
def test_bootstrap_discovery_success(mock_run, client) -> None:
    mock_run.return_value = _sample_report()
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": "cred_test",
            "allow_insecure_http": True,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["certification_eligible"] is False
    assert body["transport_security"] == "insecure_http"
    assert body["components_inventory"]["source_shape"] == "component_map"
    assert body["ssh_component_determination"]["outcome"] == "key_absent"
    mock_run.assert_called_once()


@patch("router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery")
def test_bootstrap_discovery_works_with_gate_a_closed(mock_run, client, app_env) -> None:
    app_env.gate_a_certification = None
    mock_run.return_value = _sample_report()
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": "cred_test",
            "allow_insecure_http": True,
        },
    )
    assert response.status_code == 200


def test_bootstrap_discovery_rejects_extra_fields(client) -> None:
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": "cred_test",
            "allow_insecure_http": True,
            "password": "must-not-accept",
        },
    )
    assert response.status_code == 422


def test_bootstrap_discovery_rejects_management_password_field(client) -> None:
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": "cred_test",
            "allow_insecure_http": True,
            "management_password": "must-not-accept",
        },
    )
    assert response.status_code == 422


@patch("router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery")
def test_bootstrap_discovery_response_has_no_secrets(mock_run, client) -> None:
    mock_run.return_value = _sample_report()
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": "cred_test",
            "allow_insecure_http": True,
        },
    )
    serialized = json.dumps(response.json())
    assert "password" not in serialized.lower()
    assert "cred_test" not in serialized


@patch("router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery")
def test_bootstrap_discovery_uses_runtime_vault(mock_run, client, app_env) -> None:
    vault: MemoryVault = app_env.state.host.runtime.vault  # type: ignore[assignment]
    handle = vault.create(kind="RouterManagementPassword", secret="vault-secret")
    mock_run.return_value = _sample_report()
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": handle.credential_ref_id,
            "allow_insecure_http": True,
        },
    )
    assert response.status_code == 200
    _, kwargs = mock_run.call_args
    assert kwargs["vault"] is vault
    assert kwargs["credential_ref_id"] == handle.credential_ref_id


def test_bootstrap_discovery_resolves_vault_without_live_mode(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    injected = MemoryVault()
    handle = injected.create(kind="RouterManagementPassword", secret="dpapi-mock-secret")
    application = create_app(
        db_path=tmp_path / "bootstrap-vault.sqlite3",
        allow_fake_mutations=False,
        adapter_mode="fake",
        vault=injected,
    )
    from fastapi.testclient import TestClient

    with patch(
        "router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery"
    ) as mock_run:
        mock_run.return_value = _sample_report()
        with TestClient(application) as c:
            c.cookies.set("hub_admin", mint_hub_admin_cookie())
            response = c.post(
                "/api/router-control/v1/lab/bootstrap-discovery",
                json={
                    "host": "http://192.168.2.1",
                    "username": "admin",
                    "credential_ref_id": handle.credential_ref_id,
                    "allow_insecure_http": True,
                },
            )
    assert response.status_code == 200
    assert application.state.host.runtime.vault is injected
    _, kwargs = mock_run.call_args
    assert kwargs["vault"] is injected


@patch("router_control_host.bootstrap_discovery_routes.run_bootstrap_discovery")
def test_bootstrap_discovery_credential_error_surfaces_ref(mock_run, client) -> None:
    mock_run.side_effect = BootstrapDiscoveryError(
        "credential resolution failed for credential_ref_id=cred_unknown"
    )
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": "cred_unknown",
            "allow_insecure_http": True,
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert "cred_unknown" in body["error"]["message"]
    assert "password" not in body["error"]["message"].lower()


@patch("router_control.application.bootstrap_discovery.NetcrazeTransport.fetch_discovery_read")
def test_bootstrap_discovery_transport_timeout_returns_422(
    mock_fetch, client, app_env
) -> None:
    from router_control.adapters.netcraze.errors import TransportTimeout

    mock_fetch.side_effect = TransportTimeout("read timeout")
    vault: MemoryVault = app_env.state.host.runtime.vault  # type: ignore[assignment]
    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    response = client.post(
        "/api/router-control/v1/lab/bootstrap-discovery",
        json={
            "host": "http://192.168.2.1",
            "username": "admin",
            "credential_ref_id": handle.credential_ref_id,
            "allow_insecure_http": True,
        },
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "bootstrap.discovery_failed"
    assert "read timeout" in body["error"]["message"]
