"""Offline tests for per-request WireGuard live transport wiring."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_live_transport import (
    WifiLiveSession,
    connection_params_from_fields,
    is_win32_live_capable,
    params_complete,
)

_ASC_9 = [5, 42, 54, 0, 0, 1, 2, 3, 4]
_TEST_WG = "Wireguard5"
_COMPONENT_DIGEST = "a" * 64
_FINGERPRINT_DIGEST = "b" * 64

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
        component_set_digest=_COMPONENT_DIGEST,
        device_fingerprint_digest=_FINGERPRINT_DIGEST,
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


def _intent_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "wg_id": _TEST_WG,
        "enabled": True,
        "asc_args": _ASC_9,
        "confirm_live_apply": True,
    }
    base.update(overrides)
    return base


def _ok_envelope(*, prompt: str = "(config)") -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": prompt,
                "status": [
                    {
                        "status": "message",
                        "code": "8979152",
                        "ident": "Core::Interface",
                        "message": "synthetic ack",
                    }
                ],
            }
        }
    ]


def _applied_readback() -> dict[str, Any]:
    return {
        "interface": {
            "id": _TEST_WG,
            "state": "up",
            "up": True,
        }
    }


class ApiFakeWireguardTransport:
    def __init__(self, *, readback: dict[str, Any] | None = None) -> None:
        self.readback = readback or _applied_readback()
        self.write_commands: list[str] = []
        self.parse_commands: list[str] = []
        self.sealed_write_calls = 0

    def execute_sealed_rci_write(self, request: Any) -> Any:
        self.sealed_write_calls += 1
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(command)
        if command == f"interface {_TEST_WG}":
            return _ok_envelope(prompt="(config-if)")
        return _ok_envelope()

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        return dict(self.readback)


@pytest.fixture
def wg_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wg_live.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeWireguardTransport()
    app.state.host.wireguard_apply_transport_factory = lambda: transport
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        client.test_app = app
        yield client


def test_fake_path_without_connection_params(wg_client, monkeypatch: pytest.MonkeyPatch) -> None:
    live_called: list[str] = []

    @contextmanager
    def _fail_live(**_kwargs: object):
        live_called.append("open")
        raise AssertionError("live session must not open without connection params")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _fail_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/apply",
        json=_intent_payload(),
    )
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"
    assert live_called == []


def test_live_path_selected_with_mocked_session(
    wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wg_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWireguardTransport()

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        return StartupBackupMetadata(
            artifact_type="startup_config_backup",
            endpoint="/ci/startup-config.txt",
            content_sha256="deadbeef" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-wg-test.enc",
            metadata_locator="data/backups/startup-wg-test.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _mock_backup,
    )
    payload = _intent_payload(**_LIVE_CONN)
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body.get("backup_basename") == "startup-wg-test.enc"
    assert len(session_transport.write_commands) == 3


def _baseline_readback() -> dict[str, Any]:
    return {"interface": {}}


def test_live_apply_requires_gate_a(wg_client, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _mock_live(**_kwargs: object):
        raise AssertionError("live session must not open without Gate A")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    wg_client.test_app.state.host.gate_a_certification = None

    resp = wg_client.post(
        "/api/router-control/v1/wireguard/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wireguard.gate_a_required"


def test_live_teardown_requires_gate_a(wg_client, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _mock_live(**_kwargs: object):
        raise AssertionError("live session must not open without Gate A")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    wg_client.test_app.state.host.gate_a_certification = None

    resp = wg_client.post(
        "/api/router-control/v1/wireguard/teardown",
        json={
            "wg_id": _TEST_WG,
            "enabled": True,
            "asc_args": _ASC_9,
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wireguard.gate_a_required"


def test_live_teardown_backup_before_write_and_response_fields(
    wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wg_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWireguardTransport(readback=_baseline_readback())
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        return StartupBackupMetadata(
            artifact_type="startup_config_backup",
            endpoint="/ci/startup-config.txt",
            content_sha256="cafebabe" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-wg-teardown.enc",
            metadata_locator="data/backups/startup-wg-teardown.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )

    original_write = session_transport.execute_sealed_rci_write

    def _tracked_write(request: Any) -> Any:
        backup_calls.append("write")
        return original_write(request)

    session_transport.execute_sealed_rci_write = _tracked_write  # type: ignore[method-assign]

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = wg_client.post(
        "/api/router-control/v1/wireguard/teardown",
        json={
            "wg_id": _TEST_WG,
            "enabled": True,
            "asc_args": _ASC_9,
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["backup_basename"] == "startup-wg-teardown.enc"
    assert body["backup_content_sha256"] == "cafebabe" * 8
    assert backup_calls.index("backup") < backup_calls.index("write")


def test_live_teardown_backup_error_maps_code_and_skips_write(
    wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.startup_backup import StartupBackupError

    wg_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWireguardTransport(readback=_baseline_readback())

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        raise StartupBackupError("backup vault unavailable")

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = wg_client.post(
        "/api/router-control/v1/wireguard/teardown",
        json={
            "wg_id": _TEST_WG,
            "enabled": True,
            "asc_args": _ASC_9,
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wireguard.live_backup_unavailable"
    assert session_transport.write_commands == []


def test_wireguard_apply_live_intent_platform_unsupported_apply(
    wg_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: False,
    )
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wireguard.live_platform_unsupported"


def test_wireguard_apply_live_intent_platform_unsupported_teardown(
    wg_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: False,
    )
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/teardown",
        json={
            "wg_id": _TEST_WG,
            "enabled": True,
            "asc_args": _ASC_9,
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wireguard.live_platform_unsupported"


def test_wireguard_state_has_transport_factory_hooks(wg_client) -> None:
    host = wg_client.test_app.state.host
    assert hasattr(host, "wireguard_apply_transport_factory")
    assert hasattr(host, "wireguard_apply_credential_resolver")


def test_params_complete_reused_from_wifi_live_transport() -> None:
    assert params_complete(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
    )
    params = connection_params_from_fields(**_LIVE_CONN)
    assert params is not None
    assert is_win32_live_capable() in (True, False)


_OBSERVE_PATH = "/api/router-control/v1/wireguard/observe"


def test_live_observe_requires_gate_a(wg_client, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _mock_live(**_kwargs: object):
        raise AssertionError("live session must not open without Gate A")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    wg_client.test_app.state.host.gate_a_certification = None

    resp = wg_client.post(
        _OBSERVE_PATH,
        json={"wg_id": _TEST_WG, **_LIVE_CONN},
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wireguard.gate_a_required"


def test_live_observe_uses_session_without_backup(
    wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wg_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWireguardTransport()
    backup_called: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _fail_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_called.append("backup")
        raise AssertionError("backup must not run for observe")

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _fail_backup,
    )

    resp = wg_client.post(
        _OBSERVE_PATH,
        json={"wg_id": _TEST_WG, **_LIVE_CONN},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["wg_id"] == _TEST_WG
    assert backup_called == []
    assert session_transport.parse_commands == [f"show interface {_TEST_WG}"]
    assert session_transport.write_commands == []
    assert session_transport.sealed_write_calls == 0


def test_live_observe_incomplete_connection_params(
    wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wg_client.post(
        _OBSERVE_PATH,
        json={"wg_id": _TEST_WG, "host": "192.168.2.1", "username": "admin"},
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wireguard.live_connection_incomplete"
    assert "router_credential_ref_id" in err["message"]
    assert "ssh_host_key_sha256" in err["message"]


def test_live_observe_ssh_host_key_mismatch_422(
    wg_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.errors import SshHostKeyMismatch

    wg_client.test_app.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_mismatch(**_kwargs: object):
        raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wg_client.post(
        _OBSERVE_PATH,
        json={"wg_id": _TEST_WG, **_LIVE_CONN},
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wireguard.ssh_host_key_mismatch"
    assert "refused" in err["message"].lower()
