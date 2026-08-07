"""Internet-status observe host API tests."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.application.internet_status_observe import (
    parse_internet_status_payload,
    run_internet_status_observe,
)
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

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


class ApiFakeInternetStatusTransport:
    def __init__(
        self,
        *,
        payload: Any = None,
        raise_on_parse: bool = False,
        interface_responses: dict[str, Any] | None = None,
        raise_on_interface: bool = False,
    ) -> None:
        self.parse_commands: list[str] = []
        self.payload = payload if payload is not None else {
            "internet": "yes",
            "gateway": "yes",
            "dns": "yes",
            "reliable": "yes",
            "gateway-accessible": "yes",
            "dns-accessible": "yes",
            "captive-accessible": "no",
            "checked": "2026-08-01T12:00:00Z",
        }
        self.raise_on_parse = raise_on_parse
        self.interface_responses = interface_responses or {}
        self.raise_on_interface = raise_on_interface

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if self.raise_on_parse and cli_command == "show internet status":
            raise OSError("transport failed")
        if cli_command == "show internet status":
            return self.payload
        if cli_command.startswith("show interface "):
            if self.raise_on_interface:
                raise OSError("interface query failed")
            return self.interface_responses.get(cli_command, {})
        return {}


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    application = create_app(
        db_path=tmp_path / "internet-status.sqlite3",
        allow_fake_mutations=False,
        adapter_mode="fake",
    )
    application.state.host.internet_status_transport_factory = ApiFakeInternetStatusTransport
    return application


@pytest.fixture
def client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_internet_status_observe_requires_auth(app_env) -> None:
    from fastapi.testclient import TestClient

    with TestClient(app_env) as c:
        response = c.post("/api/router-control/v1/internet-status/observe", json={})
    assert response.status_code == 401


def test_internet_status_observe_rejects_extra_password(client) -> None:
    response = client.post(
        "/api/router-control/v1/internet-status/observe",
        json={"password": "must-not-accept"},
    )
    assert response.status_code == 422


def test_internet_status_observe_fake_success_internet_true(client) -> None:
    response = client.post("/api/router-control/v1/internet-status/observe", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["read_status"] == "ok"
    assert body["internet"] is True
    assert body["gateway_accessible"] is True
    assert body["dns_accessible"] is True
    assert body["checked_at"] == "2026-08-01T12:00:00Z"


def test_parse_internet_status_payload_rejects_nested_interface_dict() -> None:
    raw = {
        "internet": "yes",
        "interface": {"id": "Wireguard5", "state": "up"},
        "checked": "2026-08-01T12:00:00Z",
    }
    result = parse_internet_status_payload(raw)
    assert result.read_status == "ok"
    assert result.gateway_interface is None


def test_parse_internet_status_payload_rci_list_envelope_true() -> None:
    raw = [
        {
            "parse": {
                "internet": True,
                "reliable": True,
                "gateway-accessible": True,
                "dns-accessible": True,
                "captive-accessible": True,
                "gateway": {"interface": "WifiMaster1/WifiStation0"},
                "checked": "2026-08-01T12:00:00Z",
            },
        },
    ]
    result = parse_internet_status_payload(raw)
    assert result.read_status == "ok"
    assert result.internet is True
    assert result.gateway_interface == "WifiMaster1/WifiStation0"
    assert result.checked_at == "2026-08-01T12:00:00Z"


def test_parse_internet_status_payload_rci_list_envelope_false() -> None:
    raw = [
        {
            "parse": {
                "internet": False,
                "reliable": False,
                "gateway-accessible": False,
                "dns-accessible": False,
                "captive-accessible": False,
                "checked": "2026-08-01T12:00:00Z",
            },
        },
    ]
    result = parse_internet_status_payload(raw)
    assert result.read_status == "ok"
    assert result.internet is False


def test_internet_status_observe_rci_list_envelope_true(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "internet-envelope-true.sqlite3",
        adapter_mode="fake",
    )

    def _factory() -> ApiFakeInternetStatusTransport:
        return ApiFakeInternetStatusTransport(
            payload=[
                {
                    "parse": {
                        "internet": True,
                        "reliable": True,
                        "gateway-accessible": True,
                        "dns-accessible": True,
                        "captive-accessible": True,
                        "gateway": {"interface": "WifiMaster1/WifiStation0"},
                        "checked": "2026-08-01T12:00:00Z",
                    },
                },
            ],
        )

    application.state.host.internet_status_transport_factory = _factory
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post("/api/router-control/v1/internet-status/observe", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["read_status"] == "ok"
    assert body["internet"] is True
    assert body["gateway_interface"] == "WifiMaster1/WifiStation0"


def test_internet_status_observe_rci_list_envelope_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "internet-envelope-false.sqlite3",
        adapter_mode="fake",
    )

    def _factory() -> ApiFakeInternetStatusTransport:
        return ApiFakeInternetStatusTransport(
            payload=[
                {
                    "parse": {
                        "internet": False,
                        "reliable": False,
                        "gateway-accessible": False,
                        "dns-accessible": False,
                        "captive-accessible": False,
                        "checked": "2026-08-01T12:00:00Z",
                    },
                },
            ],
        )

    application.state.host.internet_status_transport_factory = _factory
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post("/api/router-control/v1/internet-status/observe", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["read_status"] == "ok"
    assert body["internet"] is False


def test_internet_status_observe_fake_success_internet_false(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "internet-false.sqlite3",
        adapter_mode="fake",
    )

    def _factory() -> ApiFakeInternetStatusTransport:
        return ApiFakeInternetStatusTransport(
            payload={
                "internet": "no",
                "gateway": "no",
                "dns": "no",
                "checked": "2026-08-01T12:00:00Z",
            },
        )

    application.state.host.internet_status_transport_factory = _factory
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post("/api/router-control/v1/internet-status/observe", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["read_status"] == "ok"
    assert body["internet"] is False


def test_internet_status_observe_transport_failure_honest_nulls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "internet-fail.sqlite3",
        adapter_mode="fake",
    )
    application.state.host.internet_status_transport_factory = (
        lambda: ApiFakeInternetStatusTransport(raise_on_parse=True)
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post("/api/router-control/v1/internet-status/observe", json={})
    assert response.status_code == 200
    body = response.json()
    assert body["read_status"] == "failed"
    assert body["internet"] is None


def test_internet_status_observe_gate_a_required_when_live_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "internet-gate-a.sqlite3",
        adapter_mode="fake",
        gate_a_certification=None,
    )
    monkeypatch.setattr(
        "router_control_host.internet_status_routes.is_win32_live_capable",
        lambda: True,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/internet-status/observe",
            json=_LIVE_CONN,
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "internet.gate_a_required"


def test_internet_status_observe_incomplete_connection_422(client) -> None:
    response = client.post(
        "/api/router-control/v1/internet-status/observe",
        json={"credential_ref_id": "credref:alias-only"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "internet.live_connection_incomplete"


def test_internet_status_observe_no_secret_leakage_in_response(client) -> None:
    response = client.post(
        "/api/router-control/v1/internet-status/observe",
        json={"password": "ignored"},
    )
    assert response.status_code == 422
    serialized = json.dumps(response.json())
    assert "must-not-accept" not in serialized.lower()


def test_internet_status_observe_live_transport_failed_on_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    application = create_app(
        db_path=tmp_path / "internet-timeout.sqlite3",
        adapter_mode="fake",
    )
    application.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_timeout(**_kwargs: object):
        raise OSError("network unreachable")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.internet_status_routes.open_wifi_live_session",
        _raise_timeout,
    )
    monkeypatch.setattr(
        "router_control_host.internet_status_routes.is_win32_live_capable",
        lambda: True,
    )
    from fastapi.testclient import TestClient

    with TestClient(application) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = c.post(
            "/api/router-control/v1/internet-status/observe",
            json=_LIVE_CONN,
        )
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "internet.live_transport_failed"


def test_run_internet_status_observe_enriches_wifi_gateway_ssid() -> None:
    station_id = "WifiMaster1/WifiStation0"
    transport = ApiFakeInternetStatusTransport(
        payload={
            "internet": "yes",
            "gateway": "yes",
            "dns": "yes",
            "interface": station_id,
            "checked": "2026-08-01T12:00:00Z",
        },
        interface_responses={
            f"show interface {station_id}": {
                "ssid": "Cafe-Upstream",
                "state": "up",
            },
        },
    )
    result = run_internet_status_observe(transport=transport)
    assert result.read_status == "ok"
    assert result.gateway_interface == station_id
    assert result.gateway_ssid == "Cafe-Upstream"
    assert transport.parse_commands == [
        "show internet status",
        f"show interface {station_id}",
    ]


@pytest.mark.parametrize(
    "gateway_interface",
    ["GigabitEthernet0", "Wireguard5"],
)
def test_run_internet_status_observe_skips_ssid_for_non_wifi_gateway(
    gateway_interface: str,
) -> None:
    transport = ApiFakeInternetStatusTransport(
        payload={
            "internet": "yes",
            "gateway": "yes",
            "dns": "yes",
            "interface": gateway_interface,
            "checked": "2026-08-01T12:00:00Z",
        },
        interface_responses={
            f"show interface {gateway_interface}": {"ssid": "Should-Not-Query"},
        },
    )
    result = run_internet_status_observe(transport=transport)
    assert result.read_status == "ok"
    assert result.gateway_interface == gateway_interface
    assert result.gateway_ssid is None
    assert transport.parse_commands == ["show internet status"]


def test_run_internet_status_observe_ssid_enrichment_failure_is_best_effort() -> None:
    station_id = "WifiMaster1/WifiStation0"
    transport = ApiFakeInternetStatusTransport(
        payload={
            "internet": "yes",
            "gateway": "yes",
            "dns": "yes",
            "interface": station_id,
            "checked": "2026-08-01T12:00:00Z",
        },
        raise_on_interface=True,
    )
    result = run_internet_status_observe(transport=transport)
    assert result.read_status == "ok"
    assert result.internet is True
    assert result.gateway_interface == station_id
    assert result.gateway_ssid is None
    assert transport.parse_commands == [
        "show internet status",
        f"show interface {station_id}",
    ]
