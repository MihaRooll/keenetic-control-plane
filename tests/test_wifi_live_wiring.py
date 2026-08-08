"""Offline tests for per-request Wi-Fi live transport wiring."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_live_transport import (
    LiveIdentityTupleMismatchError,
    MissingLiveConnectionFieldError,
    WifiLiveConnectionParams,
    WifiLiveSession,
    connection_fields_present,
    connection_params_from_fields,
    ensure_live_gate_a_tuple_match,
    is_win32_live_capable,
    map_wifi_live_transport_error,
    missing_connection_fields,
    open_wifi_live_session,
    params_complete,
)

_OFFLINE_PSK_PLACEHOLDER = "test-psk-placeholder"
_TEST_AP = "WifiMaster0/AccessPoint3"
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

_OBSERVED_LIVE_CONN: dict[str, str] = {
    **_LIVE_CONN,
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


def _patch_tuple_match_ok(monkeypatch: pytest.MonkeyPatch, module: str) -> None:
    monkeypatch.setattr(
        f"{module}.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    )


def _matching_probe_evidence() -> dict[str, Any]:
    return {
        "model": "NC-1812",
        "firmware_version": "5.01.C.1.0-0",
        "build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": _COMPONENT_DIGEST,
        "device_fingerprint": _FINGERPRINT_DIGEST,
        "transport_security": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": _VALID_SSH_HOST_KEY_SHA256,
        "certification_eligible": True,
        "identity_complete": True,
    }


def _intent_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
    }
    base.update(overrides)
    return base


def _ok_envelope() -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
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
            "ssid": "Staff-Private",
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
            "up": True,
        }
    }


def _baseline_readback() -> dict[str, Any]:
    return {
        "interface": {
            "ssid": "",
            "encryption": {},
            "state": "down",
            "up": False,
        }
    }


class ApiFakeWifiTransport:
    def __init__(self, *, readback: dict[str, Any] | None = None) -> None:
        self.readback = readback or _applied_readback()
        self.write_commands: list[str] = []

    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        self.write_commands.append(str(body[0]["parse"]))
        return _ok_envelope()

    def execute_rci_parse(self, cli_command: str) -> Any:
        return dict(self.readback)


@pytest.fixture
def wifi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_live.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeWifiTransport()
    app.state.host.wifi_apply_transport_factory = lambda: transport
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _OFFLINE_PSK_PLACEHOLDER
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        client.test_app = app
        yield client


def test_params_complete_requires_core_fields() -> None:
    assert params_complete(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
    )
    assert not params_complete(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id=None,
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
    )
    assert not params_complete(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address=None,
    )


def test_connection_params_from_fields_require_source_address() -> None:
    params = connection_params_from_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
    )
    assert params is not None
    assert params.source_address == "192.168.2.10"
    assert (
        connection_params_from_fields(
            host="192.168.2.1",
            username="admin",
            router_credential_ref_id="credref:x",
            ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
            source_address=None,
        )
        is None
    )


def test_open_wifi_live_session_propagates_source_address() -> None:
    captured: dict[str, str] = {}
    fake_tunnel = MagicMock()
    fake_tunnel.local_host = "127.0.0.1"
    fake_tunnel.local_port = 54321
    fake_tunnel.host_key_algorithm = "ssh-ed25519"
    fake_tunnel.host_key_fingerprint_sha256 = _VALID_SSH_HOST_KEY_SHA256
    fake_tunnel.__enter__.return_value = fake_tunnel
    fake_tunnel.__exit__.return_value = None
    vault = MagicMock()
    vault.use.return_value = "lab-password"
    params = WifiLiveConnectionParams(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
    )

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
        return_value=fake_tunnel,
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.validate_source_address",
        side_effect=lambda value, **_: value,
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
        side_effect=lambda value, **_: value,
    ):
        with open_wifi_live_session(params=params, vault=vault) as session:
            captured["source_address"] = session.transport.source_address

    assert captured["source_address"] == "192.168.2.10"


def test_fake_path_without_connection_params(wifi_client, monkeypatch: pytest.MonkeyPatch) -> None:
    live_called: list[str] = []

    @contextmanager
    def _fail_live(**_kwargs: object):
        live_called.append("open")
        raise AssertionError("live session must not open without connection params")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _fail_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(),
    )
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"
    assert live_called == []


def test_live_path_selected_with_mocked_session(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport()

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
            encrypted_locator="data/backups/startup-192.168.2.1-test.enc",
            metadata_locator="data/backups/startup-192.168.2.1-test.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _mock_backup,
    )
    wifi_client.test_app.state.host.wifi_apply_transport_factory = lambda: (_ for _ in ()).throw(
        AssertionError("factory must not be used when live params complete")
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["backup_basename"] == "startup-192.168.2.1-test.enc"
    assert body["backup_content_sha256"] == "deadbeef" * 8
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)
    assert len(session_transport.write_commands) == 5


def test_live_apply_requires_gate_a(wifi_client, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _mock_live(**_kwargs: object):
        raise AssertionError("live session must not open without Gate A")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    wifi_client.test_app.state.host.gate_a_certification = None

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.gate_a_required"


def test_wifi_apply_live_intent_platform_unsupported_apply(
    wifi_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: False,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.live_platform_unsupported"


def test_wifi_apply_live_intent_platform_unsupported_teardown(
    wifi_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: False,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={
            "ap_id": _TEST_AP,
            "wpa_mode": "WPA2",
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.live_platform_unsupported"


def test_live_teardown_requires_gate_a(wifi_client, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _mock_live(**_kwargs: object):
        raise AssertionError("live session must not open without Gate A")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    wifi_client.test_app.state.host.gate_a_certification = None

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={
            "ap_id": _TEST_AP,
            "wpa_mode": "WPA2",
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.gate_a_required"


def test_live_teardown_backup_before_write_and_response_fields(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport(readback=_baseline_readback())
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
            content_sha256="deadbeef" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-192.168.2.1-teardown.enc",
            metadata_locator="data/backups/startup-192.168.2.1-teardown.meta.json",
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
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={
            "ap_id": _TEST_AP,
            "wpa_mode": "WPA2",
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["backup_basename"] == "startup-192.168.2.1-teardown.enc"
    assert body["backup_content_sha256"] == "deadbeef" * 8
    assert backup_calls.index("backup") < backup_calls.index("write")


def test_live_teardown_backup_error_maps_code_and_skips_write(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.startup_backup import StartupBackupError

    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport(readback=_baseline_readback())

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        raise StartupBackupError("backup vault unavailable")

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={
            "ap_id": _TEST_AP,
            "wpa_mode": "WPA2",
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.live_backup_unavailable"
    assert session_transport.write_commands == []


def test_live_apply_backup_error_maps_code_and_skips_write(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.startup_backup import StartupBackupError

    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport(readback=_baseline_readback())

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        raise StartupBackupError("backup vault unavailable")

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.live_backup_unavailable"
    assert session_transport.write_commands == []


def test_live_apply_identity_mismatch_returns_422_zero_writes(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport()
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _raise_mismatch(*_args: object, **_kwargs: object) -> None:
        raise LiveIdentityTupleMismatchError("tuple mismatch")

    def _track_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        raise AssertionError("backup must not run on identity mismatch")

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(**_LIVE_CONN),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.identity_mismatch"
    assert backup_calls == []
    assert session_transport.write_commands == []


def test_live_teardown_identity_mismatch_returns_422_zero_writes(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport(readback=_baseline_readback())
    backup_calls: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _raise_mismatch(*_args: object, **_kwargs: object) -> None:
        raise LiveIdentityTupleMismatchError("tuple mismatch")

    def _track_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_calls.append("backup")
        raise AssertionError("backup must not run on identity mismatch")

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={
            "ap_id": _TEST_AP,
            "wpa_mode": "WPA2",
            "confirm_live_teardown": True,
            **_LIVE_CONN,
        },
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.identity_mismatch"
    assert backup_calls == []
    assert session_transport.write_commands == []


def test_ensure_live_gate_a_tuple_match_accepts_matching_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert = _open_gate_a()
    session = WifiLiveSession(transport=MagicMock(), tunnel=MagicMock())

    class _FakeAdapter:
        def probe_gate_a_evidence(self) -> dict[str, object]:
            return _matching_probe_evidence()

    monkeypatch.setattr(
        "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
        lambda **_kwargs: _FakeAdapter(),
    )
    ensure_live_gate_a_tuple_match(session, cert)


def test_ensure_live_gate_a_tuple_match_rejects_incomplete_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cert = _open_gate_a()
    session = WifiLiveSession(transport=MagicMock(), tunnel=MagicMock())

    class _FakeAdapter:
        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {"model": "NC-1812"}

    monkeypatch.setattr(
        "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
        lambda **_kwargs: _FakeAdapter(),
    )
    with pytest.raises(LiveIdentityTupleMismatchError):
        ensure_live_gate_a_tuple_match(session, cert)


def test_incomplete_connection_params_rejected_422(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    @contextmanager
    def _fail_live(**_kwargs: object):
        raise AssertionError("live session must not open for incomplete params")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.open_wifi_live_session",
        _fail_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(host="192.168.2.1", username="admin"),
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wifi.live_connection_incomplete"
    assert "router_credential_ref_id" in err["message"]
    assert "ssh_host_key_sha256" in err["message"]


def test_is_win32_live_capable_matches_platform() -> None:
    assert is_win32_live_capable() == (__import__("sys").platform == "win32")


def test_connection_fields_present_detects_any_field() -> None:
    assert connection_fields_present(
        host="192.168.2.1",
        username=None,
        router_credential_ref_id=None,
        ssh_host_key_sha256=None,
    )
    assert not connection_fields_present(
        host=None,
        username=None,
        router_credential_ref_id=None,
        ssh_host_key_sha256=None,
    )


def test_missing_connection_fields_lists_core_gaps() -> None:
    missing = missing_connection_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id=None,
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
    )
    assert missing == ["router_credential_ref_id"]


def test_missing_connection_fields_requires_source_when_explicit() -> None:
    missing = missing_connection_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address=None,
    )
    assert missing == ["source_address"]


def test_observed_live_path_uses_session_without_backup(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeWifiTransport()
    backup_called: list[str] = []

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _fail_backup(**_kwargs: object) -> StartupBackupMetadata:
        backup_called.append("backup")
        raise AssertionError("backup must not run for observed-state")

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_apply_routes.backup_startup_config",
        _fail_backup,
    )

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], **_OBSERVED_LIVE_CONN},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["certification_eligible"] is False
    assert body["transport_security"] == "ssh_tunnel_pinned"
    assert backup_called == []
    assert "must-not-leak" not in json.dumps(body)


def test_observed_live_requires_gate_a(wifi_client, monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def _mock_live(**_kwargs: object):
        raise AssertionError("live session must not open without Gate A")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    wifi_client.test_app.state.host.gate_a_certification = None

    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], **_OBSERVED_LIVE_CONN},
    )
    assert resp.status_code == 503
    err = resp.json()["error"]
    assert err["code"] == "wifi.gate_a_required"
    assert "Gate A" in err["message"]


def test_observed_incomplete_connection_params_actionable(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], "host": "192.168.2.1", "username": "admin"},
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wifi.live_connection_incomplete"
    assert "router_credential_ref_id" in err["message"]
    assert "ssh_host_key_sha256" in err["message"]


def test_observed_live_mode_without_params_actionable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "wifi_observed_live.sqlite3", adapter_mode="live")
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post(
            "/api/router-control/v1/wifi/observed-state",
            json={"ap_ids": [_TEST_AP]},
        )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wifi.live_connection_required"
    assert "host" in err["message"]
    assert "router_credential_ref_id" in err["message"]


def test_observed_non_win32_complete_params_platform_unsupported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "wifi_observed_platform.sqlite3", adapter_mode="live")
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: False,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post(
            "/api/router-control/v1/wifi/observed-state",
            json={"ap_ids": [_TEST_AP], **_OBSERVED_LIVE_CONN},
        )
    assert resp.status_code == 503
    err = resp.json()["error"]
    assert err["code"] == "wifi.live_platform_unsupported"
    assert "win32" in err["message"].lower()


def test_observed_live_ssh_host_key_mismatch_422(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.errors import SshHostKeyMismatch

    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_mismatch(**_kwargs: object):
        raise SshHostKeyMismatch("SSH host key fingerprint mismatch")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], **_OBSERVED_LIVE_CONN},
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wifi.ssh_host_key_mismatch"
    assert "refused" in err["message"].lower()


def test_observed_live_credential_not_found_404(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.secrets.memory import VaultError

    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    ref_id = "credref:missing-router"

    @contextmanager
    def _raise_vault(**_kwargs: object):
        raise VaultError("credential not found")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _raise_vault,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={
            "ap_ids": [_TEST_AP],
            **_OBSERVED_LIVE_CONN,
            "router_credential_ref_id": ref_id,
        },
    )
    assert resp.status_code == 404
    err = resp.json()["error"]
    assert err["code"] == "wifi.credential_not_found"
    assert f"router_credential_ref_id={ref_id}" in err["message"]
    assert "secret" not in err["message"].lower()
    assert "C:\\" not in err["message"]
    assert "/home/" not in err["message"]


def test_observed_live_credential_unusable_400(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.secrets.memory import VaultError

    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()
    ref_id = "credref:revoked-router"

    @contextmanager
    def _raise_vault(**_kwargs: object):
        raise VaultError("credential revoked")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _raise_vault,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={
            "ap_ids": [_TEST_AP],
            **_OBSERVED_LIVE_CONN,
            "router_credential_ref_id": ref_id,
        },
    )
    assert resp.status_code == 400
    err = resp.json()["error"]
    assert err["code"] == "wifi.credential_unusable"
    assert f"router_credential_ref_id={ref_id}" in err["message"]


def test_observed_live_transport_timeout_503(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_timeout(**_kwargs: object):
        raise TimeoutError("connection timed out")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _raise_timeout,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], **_OBSERVED_LIVE_CONN},
    )
    assert resp.status_code == 503
    err = resp.json()["error"]
    assert err["code"] == "wifi.live_transport_failed"


def test_apply_steps_include_operation_field(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(confirm_live_apply=True),
    )
    assert resp.status_code == 200
    for step in resp.json()["steps"]:
        assert step["operation"] == step["op"]
        assert step["operation"] is not None


def test_wifi_apply_invalid_band_422(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(band="BAND_6GHZ"),
    )
    assert resp.status_code == 422
    body = resp.json()
    assert "detail" not in body
    err = body["error"]
    assert err["code"] == "request.validation_failed"
    detail_blob = json.dumps(err["details"])
    assert "band" in detail_blob.lower()


def test_wifi_apply_invalid_captive_portal_422(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(captive_portal="Maybe"),
    )
    assert resp.status_code == 422
    body = resp.json()
    assert "detail" not in body
    err = body["error"]
    assert err["code"] == "request.validation_failed"
    detail_blob = json.dumps(err["details"])
    assert "captive_portal" in detail_blob.lower()


def test_missing_connection_fields_body_source_not_reported_missing(
    tmp_path: Path,
) -> None:
    """Body source_address must satisfy completeness even when store endpoint is NULL."""
    from router_control.persistence.connection import open_database
    from router_control.persistence.store import PersistenceStore

    store = PersistenceStore(open_database(tmp_path / "src-body.sqlite3"))
    site = store.create_site(display_name="Lab", now=datetime(2026, 8, 4, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site,
        display_name="R1",
        vendor="Fake",
        model="M1",
        identity_fingerprint="digest:fp:src-body",
        host="192.168.2.1",
        source_address=None,
        now=datetime(2026, 8, 4, tzinfo=UTC),
    )
    missing = missing_connection_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:x",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
        router_id=router_id,
        store=store,
    )
    assert "source_address" not in missing


def test_map_wifi_live_transport_error_missing_field_is_422_not_503() -> None:
    mapped = map_wifi_live_transport_error(
        MissingLiveConnectionFieldError("source_address"),
        router_credential_ref_id="credref:x",
    )
    assert mapped.status_code == 422
    assert mapped.code == "wifi.live_connection_incomplete"
    assert "source_address" in mapped.message


def test_map_wifi_live_transport_error_identity_mismatch_is_422() -> None:
    mapped = map_wifi_live_transport_error(
        LiveIdentityTupleMismatchError("live device identity does not match recorded Gate A tuple"),
        router_credential_ref_id="credref:x",
        code_prefix="wifi",
    )
    assert mapped.status_code == 422
    assert mapped.code == "wifi.identity_mismatch"


def test_live_apply_sealed_dispatch_gate_a_closed_mid_flight_returns_503() -> None:
    """Sealed _dispatch_apply_live raises LiveGateARequiredError when Gate A closes mid-flight."""
    from unittest.mock import MagicMock

    from router_control.adapters.netcraze.allowlist import validate_wifi_ap_id
    from router_control.domain.network_intents import WifiBand, WifiWpaMode
    from router_control_host.wifi_apply_routes import WifiApplyBody, _dispatch_apply_live
    from router_control_host.wifi_live_transport import LiveGateARequiredError, WifiLiveConnectionParams

    host = MagicMock()
    host.gate_a_certification = None
    body = WifiApplyBody(
        ap_id=validate_wifi_ap_id(_TEST_AP),
        ssid="Staff-Private",
        enabled=True,
        credential_ref_id="credref:staff-wifi",
        captive_portal="Disabled",
        guest_isolation=False,
        wpa_mode=WifiWpaMode.WPA2,
        band=WifiBand.BAND_2_4GHZ,
        confirm_live_apply=True,
        router_id="router-mid-flight-gate-a",
    )
    params = WifiLiveConnectionParams(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="credref:router-admin",
        ssh_host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        source_address="192.168.2.10",
    )

    with pytest.raises(LiveGateARequiredError, match="Gate A certification required"):
        _dispatch_apply_live(host=host, body=body, params=params)


def test_observed_live_transport_missing_source_maps_incomplete(
    wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Defence in depth: missing source at session open → 422 incomplete, not 503."""
    wifi_client.test_app.state.host.gate_a_certification = _open_gate_a()

    @contextmanager
    def _raise_missing_source(**_kwargs: object):
        raise MissingLiveConnectionFieldError("source_address")
        yield  # pragma: no cover

    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.open_wifi_live_session",
        _raise_missing_source,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_observed_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP], **_OBSERVED_LIVE_CONN},
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wifi.live_connection_incomplete"
    assert "source_address" in err["message"]
