"""Wi-Fi site-survey host API tests."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"

_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"

_LIVE_CONN: dict[str, str] = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "credref:router-admin",
    "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
    "source_address": "192.168.2.10",
}


def _open_gate_a() -> GateACertification:
    now = datetime.now(UTC)
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest="a" * 64,
        device_fingerprint_digest="b" * 64,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
        certification_eligible=True,
        evidence_recorded_at=now,
        evidence_path="data/artifacts/gate-a-probe.json",
        expires_at=now + timedelta(days=90),
        revocation_policy="human",
        gates_b_closed=True,
        gates_c_closed=True,
        gates_d_closed=True,
    )


class ApiFakeSiteSurveyTransport:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def execute_site_survey(self, command: str) -> str:
        self.commands.append(command)
        if "WifiMaster1" in command:
            return (_FIXTURES / "site_survey_wifi_master1.txt").read_text(encoding="utf-8")
        return (_FIXTURES / "site_survey_wifi_master0.txt").read_text(encoding="utf-8")


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(
        db_path=tmp_path / "wifi-site-survey.sqlite3",
        allow_fake_mutations=False,
        adapter_mode="fake",
    )
    application.state.host.wifi_site_survey_transport_factory = ApiFakeSiteSurveyTransport
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_wifi_site_survey_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={"radio": "WifiMaster0"},
        )
    assert response.status_code == 401


def test_wifi_site_survey_rejects_extra_password(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster0", "password": "must-not-accept"},
    )
    assert response.status_code == 422


def test_wifi_site_survey_fake_deterministic(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster0"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["certification_eligible"] is False
    assert body["offline_verified_only"] is True
    assert body["per_network_security_present"] is False
    assert "security_type" not in body
    assert "security_type_known" not in body
    assert body["command"] == "show site-survey WifiMaster0"
    assert body["network_count"] == 2
    assert body["networks"][0]["ssid"] == "SYNTH-SSID-Alpha"


def test_wifi_site_survey_radio_validation(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster2"},
    )
    assert response.status_code == 422


def test_wifi_site_survey_default_fake_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(db_path=tmp_path / "site-survey-default.sqlite3", adapter_mode="fake")
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={"radio": "WifiMaster1"},
        )
    assert response.status_code == 200
    assert response.json()["networks"][0]["ssid"] == "SYNTH-SSID-Gamma"


def test_wifi_site_survey_gate_a_required_when_live_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "site-survey-gate-a.sqlite3",
        adapter_mode="fake",
        gate_a_certification=None,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.is_win32_live_capable",
        lambda: True,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={
                "radio": "WifiMaster0",
                "host": "192.168.2.1",
                "username": "admin",
                "router_credential_ref_id": "credref:router-admin",
                    "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
                "source_address": "192.168.2.10",
            },
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "wifi.gate_a_required"


def test_wifi_site_survey_credential_ref_alias_on_incomplete_live_params(client) -> None:
    """Partial live fields with credential_ref_id alias still fail-closed (422)."""
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster0", "credential_ref_id": "credref:alias-only"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "wifi.live_connection_incomplete"


def test_wifi_site_survey_no_secret_leakage_in_response(client) -> None:
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster0"},
    )
    serialized = json.dumps(response.json())
    assert "must-not-accept" not in serialized.lower()
    assert "wpa-psk" not in serialized.lower()


def test_wifi_site_survey_non_win32_complete_params_platform_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "site-survey-platform.sqlite3",
        adapter_mode="live",
    )
    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.is_win32_live_capable",
        lambda: False,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={
                "radio": "WifiMaster0",
                "host": "192.168.2.1",
                "username": "admin",
                "router_credential_ref_id": "credref:router-admin",
                    "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
                "source_address": "192.168.2.10",
            },
        )
    assert response.status_code == 503
    err = response.json()["error"]
    assert err["code"] == "wifi.live_platform_unsupported"


def test_wifi_site_survey_live_transport_failed_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "site-survey-timeout.sqlite3",
        adapter_mode="fake",
    )
    application.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_timeout(**_kwargs: object):
        raise OSError("network unreachable")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.open_wifi_live_session",
        _raise_timeout,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.is_win32_live_capable",
        lambda: True,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={"radio": "WifiMaster0", **_LIVE_CONN},
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "wifi.live_transport_failed"


def test_wifi_site_survey_live_ssh_host_key_mismatch_422(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from router_control.adapters.netcraze.errors import SshHostKeyMismatch

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "site-survey-mismatch.sqlite3",
        adapter_mode="fake",
    )
    application.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_mismatch(**_kwargs: object):
        raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.open_wifi_live_session",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.is_win32_live_capable",
        lambda: True,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={"radio": "WifiMaster0", **_LIVE_CONN},
        )
    assert response.status_code == 422
    err = response.json()["error"]
    assert err["code"] == "wifi.ssh_host_key_mismatch"
    assert "refused" in err["message"].lower()


def test_wifi_site_survey_bare_router_id_after_draft_still_incomplete(client) -> None:
    """Backend honesty: bare router_id without full live params still 422."""
    draft = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json={
            "host": "192.168.2.1",
            "username": "admin",
            "secret": "lab-wizard-secret-value",
            "allow_insecure_http": True,
        },
        headers={"Idempotency-Key": "wiz-survey-honesty-1"},
    )
    assert draft.status_code == 201
    router_id = draft.json()["router_id"]
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster0", "router_id": router_id},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "wifi.live_connection_incomplete"


def test_wifi_site_survey_radio_only_after_draft_returns_networks(client) -> None:
    """Post-fix frontend path: no connection fields → fake fixture 200."""
    draft = client.post(
        "/api/router-control/v1/lab/wizard-draft-router",
        json={
            "host": "192.168.2.1",
            "username": "admin",
            "secret": "lab-wizard-secret-value",
            "allow_insecure_http": True,
        },
        headers={"Idempotency-Key": "wiz-survey-fake-1"},
    )
    assert draft.status_code == 201
    response = client.post(
        "/api/router-control/v1/wifi/site-survey",
        json={"radio": "WifiMaster0"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["network_count"] >= 1
    assert len(body["networks"]) >= 1


def test_wifi_site_survey_live_credential_not_found_404(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from router_control.adapters.secrets.memory import VaultError

    ref_id = "credref:missing-router"
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "site-survey-vault.sqlite3",
        adapter_mode="fake",
    )
    application.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_vault(**_kwargs: object):
        raise VaultError("credential not found")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.open_wifi_live_session",
        _raise_vault,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_site_survey_routes.is_win32_live_capable",
        lambda: True,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/wifi/site-survey",
            json={
                "radio": "WifiMaster0",
                **_LIVE_CONN,
                "router_credential_ref_id": ref_id,
            },
        )
    assert response.status_code == 404
    err = response.json()["error"]
    assert err["code"] == "wifi.credential_not_found"
    assert f"router_credential_ref_id={ref_id}" in err["message"]
