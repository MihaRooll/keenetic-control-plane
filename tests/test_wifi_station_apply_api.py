"""FastAPI tests for Wi-Fi station apply/teardown routes."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_station_rci import WifiStationRciOperation
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_live_transport import LiveIdentityTupleMismatchError, WifiLiveSession

_OFFLINE_PSK_PLACEHOLDER = "test-psk-placeholder-for-station"
_VALID_SSH_HOST_KEY_SHA256 = "SHA256:" + "a" * 43
_FINGERPRINT_DIGEST = "sha256:" + "b" * 64
_COMPONENT_DIGEST = "sha256:" + "d" * 64
_LIVE_CONN: dict[str, str] = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "credref:router-admin",
    "ssh_host_key_sha256": _VALID_SSH_HOST_KEY_SHA256,
    "source_address": "192.168.2.10",
}
_APPLY_BODY: dict[str, object] = {
    "mode": "WifiWan",
    "ssid": "Venue-Guest",
    "band": "BAND_2_4GHZ",
    "credential_ref_id": "credref:venue-wifi",
    "priority": 100,
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


def _ok_envelope() -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "8979152",
                        "ident": "Network::Interface",
                        "message": "synthetic ack",
                    }
                ],
            }
        }
    ]


def _associated_readback(*, ssid: str = "Venue-Guest") -> dict[str, Any]:
    return {
        "configured_ssid": ssid,
        "configured_encryption": "wpa2",
        "associated_ssid": ssid,
        "associated_ssid_field_present": True,
        "associated_encryption": "wpa2",
        "state": "up",
        "associated_network": "present",
    }


def _deceptive_link_only_readback() -> dict[str, Any]:
    return {
        "configured_ssid": "Venue-Guest",
        "associated_ssid": "Venue-Guest",
        "associated_ssid_field_present": True,
        "state": "up",
        "link": False,
        "connected": True,
    }


def _ip_global_ack_envelope(
    *,
    station: str = "WifiMaster0/WifiStation0",
    priority: int = 100,
) -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "72744991",
                        "ident": "Network::Interface::L3Base",
                        "message": f'"{station}": global priority is {priority}.',
                    }
                ],
            }
        }
    ]


def _station_ack_for_body(body: bytes) -> list[dict[str, Any]]:
    text = body.decode("utf-8", errors="replace").lower()
    if " ip global " in text:
        return _ip_global_ack_envelope()
    message = "synthetic ack"
    for fragment, ack_message in (
        (" no authentication wpa-psk", "WPA PSK removed."),
        (" no encryption wpa2", "WPA2 algorithms disabled."),
        (" no encryption enable", "wireless encryption disabled."),
        (" no ssid", "SSID reset."),
        (" ssid ", "SSID saved."),
        (" encryption enable", "wireless encryption enabled."),
        (" encryption wpa2", "WPA2 algorithms enabled."),
        (" authentication wpa-psk", "WPA PSK set."),
        (" ip global ", '"WifiMaster0/WifiStation0": global priority is 100.'),
        (" ip address dhcp", "Started DHCP client on station."),
        (" up", "interface is up."),
        (" down", "interface is down."),
    ):
        if fragment in text:
            message = ack_message
            break
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "8979152",
                        "ident": "Network::Interface",
                        "message": message,
                    }
                ],
            }
        }
    ]


class ApiFakeStationOfflineTransport:
    wifi_station_offline_only = True

    def __init__(self) -> None:
        self.write_commands: list[str] = []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        self.write_commands.append(redact_sealed_cli_command(str(body[0]["parse"])))
        return _station_ack_for_body(request.body)


class ApiFakeStationLiveTransport:
    wifi_station_live_dispatch = True
    wifi_station_offline_only = False  # type: ignore[misc, assignment]

    def __init__(
        self,
        *,
        readback: dict[str, Any] | None = None,
        internet_status: dict[str, Any] | None = None,
        sleep_calls: list[float] | None = None,
    ) -> None:
        self.readback = readback or _associated_readback()
        self.internet_status = internet_status or {
            "internet": "yes",
            "gateway": "yes",
            "dns": "yes",
        }
        self.write_commands: list[str] = []
        self.parse_commands: list[str] = []
        self.sleep_calls = sleep_calls if sleep_calls is not None else []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        self.write_commands.append(redact_sealed_cli_command(str(body[0]["parse"])))
        return _station_ack_for_body(request.body)

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if cli_command.startswith("show rc interface"):
            return {"ssid": self.readback.get("configured_ssid", ""), "encryption": "wpa2"}
        if cli_command.startswith("show interface"):
            return {
                "ssid": self.readback.get("associated_ssid", ""),
                "encryption": "wpa2",
                "state": self.readback.get("state", "up"),
                "link": self.readback.get("link"),
                "connected": self.readback.get("connected"),
            }
        if cli_command == "show internet status":
            return self.internet_status
        raise AssertionError(f"unexpected parse command: {cli_command}")


@pytest.fixture
def station_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_station_apply.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeStationOfflineTransport()
    app.state.host.wifi_station_apply_transport_factory = lambda: transport
    app.state.host.wifi_station_apply_credential_resolver = (
        lambda _ref: _OFFLINE_PSK_PLACEHOLDER
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        client.test_app = app
        yield client

def test_wifi_station_apply_requires_confirm(station_client) -> None:
    payload = dict(_APPLY_BODY)
    payload["confirm_live_apply"] = False
    resp = station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wifi.station_confirm_required"


def test_wifi_station_apply_offline_success(station_client) -> None:
    payload = dict(_APPLY_BODY)
    payload["confirm_live_apply"] = True
    resp = station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "dispatched_offline"
    assert body["station_id"] == "WifiMaster0/WifiStation0"
    assert body["uplink_verification_status"] == "uplink_dispatched_unverified"
    notes_text = " ".join(body.get("notes", []))
    assert "uplink_verified_bounded" not in notes_text
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_station_apply_incomplete_live_params_422(
    station_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(
            _APPLY_BODY,
            confirm_live_apply=True,
            host="192.168.2.1",
            username="admin",
        ),
    )
    assert resp.status_code == 422
    err = resp.json()["error"]
    assert err["code"] == "wifi.station.live_connection_incomplete"
    assert "router_credential_ref_id" in err["message"]
    assert "ssh_host_key_sha256" in err["message"]


def test_wifi_station_apply_incomplete_live_params_without_fake_mode_422(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.delenv("RC_ALLOW_FAKE_MUTATIONS", raising=False)
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    app = create_app(
        db_path=tmp_path / "wifi_station_incomplete.sqlite3",
        allow_fake_mutations=False,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post(
            "/api/router-control/v1/wifi/station/apply",
            json=dict(
                _APPLY_BODY,
                confirm_live_apply=True,
                host="192.168.2.1",
                username="admin",
            ),
        )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.station.live_connection_incomplete"


def test_wifi_station_teardown_incomplete_live_params_422(
    station_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    resp = station_client.post(
        "/api/router-control/v1/wifi/station/teardown",
        json=dict(
            _APPLY_BODY,
            confirm_live_teardown=True,
            host="192.168.2.1",
        ),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.station.live_connection_incomplete"


def test_wifi_station_apply_open_auth_422(station_client) -> None:
    payload = dict(_APPLY_BODY, auth_mode="open", confirm_live_apply=True)
    resp = station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 422
    assert "open-network authentication grammar" in resp.json()["error"]["message"]


def test_wifi_station_apply_plaintext_psk_forbidden(station_client) -> None:
    payload = dict(_APPLY_BODY, psk="plaintext-secret", confirm_live_apply=True)
    resp = station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 422


def test_wifi_station_apply_missing_credential_422(station_client) -> None:
    payload = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
    }
    resp = station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 422


def test_wifi_station_apply_non_default_priority_offline_422(station_client) -> None:
    payload = dict(_APPLY_BODY, priority=600, confirm_live_apply=True)
    resp = station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.station_priority_requires_ip_global"


def test_wifi_station_apply_gate_a_required_when_live_params(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    app = create_app(
        db_path=tmp_path / "wifi_station_gate_a.sqlite3",
        allow_fake_mutations=True,
    )
    app.state.host.gate_a_certification = None
    from fastapi.testclient import TestClient

    payload = dict(
        _APPLY_BODY,
        confirm_live_apply=True,
        **_LIVE_CONN,
    )
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.station.gate_a_required"


def test_wifi_station_apply_live_backup_before_write_and_response_fields(
    station_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeStationLiveTransport()
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
            encrypted_locator="data/backups/startup-192.168.2.1-station-test.enc",
            metadata_locator="data/backups/startup-192.168.2.1-station-test.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )

    original_write = session_transport.execute_sealed_rci_write

    def _tracked_write(request: SealedRciWriteRequest) -> Any:
        backup_calls.append("write")
        return original_write(request)

    session_transport.execute_sealed_rci_write = _tracked_write  # type: ignore[method-assign]

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_station_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _mock_backup,
    )
    station_client.test_app.state.host.wifi_station_apply_transport_factory = lambda: (
        _ for _ in ()
    ).throw(AssertionError("factory must not be used when live params complete"))

    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(_APPLY_BODY, confirm_live_apply=True, **_LIVE_CONN),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["backup_basename"] == "startup-192.168.2.1-station-test.enc"
    assert body["backup_content_sha256"] == "deadbeef" * 8
    assert backup_calls.index("backup") < backup_calls.index("write")
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_station_teardown_requires_confirm(station_client) -> None:
    resp = station_client.post(
        "/api/router-control/v1/wifi/station/teardown",
        json=dict(_APPLY_BODY, confirm_live_teardown=False),
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wifi.station_confirm_required"


def test_wifi_station_teardown_offline_success(station_client) -> None:
    resp = station_client.post(
        "/api/router-control/v1/wifi/station/teardown",
        json=dict(_APPLY_BODY, confirm_live_teardown=True),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "dispatched_offline"
    assert body["steps"][0]["op"] == WifiStationRciOperation.DOWN.value
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


_EXCEPTION_SECRET_MARKER = "MARKER-EXCEPTION-SECRET-PSK-VALUE"


def _station_apply_store(station_client):
    return station_client.test_app.state.host.runtime.store


def _latest_station_audit(station_client, *, verb: str) -> dict[str, object]:
    events = _station_apply_store(station_client).list_audit_events(
        action_prefix=f"sealed_apply.wifi.station.{verb}"
    )
    assert events, f"expected sealed_apply.wifi.station.{verb} audit event"
    return events[0]


def test_wifi_station_apply_audit_exception_excludes_secret_marker(
    station_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wifi_station_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"synthetic secret={_EXCEPTION_SECRET_MARKER}")

    monkeypatch.setattr(routes_mod, "apply_wifi_station_intent", _boom)
    payload = dict(_APPLY_BODY, confirm_live_apply=True)
    with pytest.raises(RuntimeError):
        station_client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    dump = _station_apply_store(station_client).dump_text_for_secret_scan()
    assert _EXCEPTION_SECRET_MARKER not in dump
    event = _latest_station_audit(station_client, verb="apply")
    summary = json.loads(str(event["summary_redacted"]))
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary
    assert "ssid" not in summary["intent"]


def test_wifi_station_teardown_audit_exception_excludes_secret_marker(
    station_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wifi_station_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"synthetic secret={_EXCEPTION_SECRET_MARKER}")

    monkeypatch.setattr(routes_mod, "teardown_wifi_station", _boom)
    payload = dict(_APPLY_BODY, confirm_live_teardown=True)
    with pytest.raises(RuntimeError):
        station_client.post("/api/router-control/v1/wifi/station/teardown", json=payload)
    dump = _station_apply_store(station_client).dump_text_for_secret_scan()
    assert _EXCEPTION_SECRET_MARKER not in dump
    summary = json.loads(
        str(_latest_station_audit(station_client, verb="teardown")["summary_redacted"])
    )
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary


def test_observe_deceptive_link_not_verified_uplink() -> None:
    from router_control.application.wifi_station_apply_service import observe_station_uplink

    observation = observe_station_uplink(
        _deceptive_link_only_readback(),
        internet_status={"internet": "yes", "gateway": "yes", "dns": "yes"},
        intended_ssid="Venue-Guest",
    )
    verdict = observation.verdict
    assert verdict == "uplink_associated_no_global"
    assert verdict != "uplink_verified_bounded"


def test_observe_station_uplink_verified_with_internet_status() -> None:
    from router_control.application.wifi_station_apply_service import observe_station_uplink

    observation = observe_station_uplink(
        _associated_readback(),
        internet_status={"internet": "yes", "gateway": "yes", "dns": "yes"},
        intended_ssid="Venue-Guest",
    )
    verdict = observation.verdict
    assert verdict == "uplink_verified_bounded"


def test_live_dispatch_service_settle_and_verdict() -> None:
    from router_control.application.wifi_station_apply_service import apply_wifi_station_intent
    from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand

    sleep_calls: list[float] = []
    transport = ApiFakeStationLiveTransport()

    result = apply_wifi_station_intent(
        intent=UplinkIntent(
            mode=UplinkMode.WIFI_WAN,
            ssid="Venue-Guest",
            band=WifiBand.BAND_2_4GHZ,
            credential_ref_id="credref:venue-wifi",
        ),
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        live_dispatch=True,
        uplink_settle_seconds=25,
        sleep_fn=lambda seconds: sleep_calls.append(seconds),
    )
    assert sleep_calls == [25.0]
    assert result.uplink_verification_status == "uplink_verified_bounded"
    assert result.overall == "applied"
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(result.to_dict())


def test_wifi_station_apply_live_intent_platform_unsupported(
    station_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: False,
    )
    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(_APPLY_BODY, confirm_live_apply=True, **_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.station.live_platform_unsupported"


def test_wifi_station_teardown_live_intent_platform_unsupported(
    station_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: False,
    )
    resp = station_client.post(
        "/api/router-control/v1/wifi/station/teardown",
        json=dict(_APPLY_BODY, confirm_live_teardown=True, **_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.station.live_platform_unsupported"


def test_wifi_station_teardown_live_requires_gate_a(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    app = create_app(
        db_path=tmp_path / "wifi_station_teardown_gate_a.sqlite3",
        allow_fake_mutations=True,
    )
    app.state.host.gate_a_certification = None
    from fastapi.testclient import TestClient

    payload = dict(_APPLY_BODY, confirm_live_teardown=True, **_LIVE_CONN)
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/station/teardown", json=payload)
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.station.gate_a_required"


def test_wifi_station_apply_live_backup_error_maps_code(
    station_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.startup_backup import StartupBackupError

    station_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeStationLiveTransport()

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    def _mock_backup(**_kwargs: object) -> StartupBackupMetadata:
        raise StartupBackupError("backup vault unavailable")

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_station_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _mock_backup,
    )

    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(_APPLY_BODY, confirm_live_apply=True, **_LIVE_CONN),
    )
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "wifi.station.live_backup_unavailable"
    assert len(session_transport.write_commands) == 0


def test_wifi_station_apply_live_dispatch_failure_not_verified_bounded(
    station_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeStationLiveTransport()

    def _fail_write(_request: SealedRciWriteRequest) -> Any:
        return [
            {
                "parse": {
                    "prompt": "(config)",
                    "status": [
                        {
                            "status": "error",
                            "code": "1",
                            "ident": "Network::Interface",
                            "message": "syntax error: rejected",
                        }
                    ],
                }
            }
        ]

    session_transport.execute_sealed_rci_write = _fail_write  # type: ignore[method-assign]

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_station_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        lambda **_kwargs: StartupBackupMetadata(
            artifact_type="startup_config_backup",
            endpoint="/ci/startup-config.txt",
            content_sha256="deadbeef" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-station-fail.enc",
            metadata_locator="data/backups/startup-station-fail.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        ),
    )

    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(_APPLY_BODY, confirm_live_apply=True, **_LIVE_CONN),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] in {"failed", "rolled_back"}
    assert body["uplink_verification_status"] == "uplink_dispatched_unverified"
    assert body["uplink_verification_status"] != "uplink_verified_bounded"


def test_wifi_station_apply_settle_zero_no_destructive_rollback(
    station_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeStationLiveTransport()

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=session_transport, tunnel=tunnel)

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    _patch_tuple_match_ok(monkeypatch, "router_control_host.wifi_station_apply_routes")
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        lambda **_kwargs: StartupBackupMetadata(
            artifact_type="startup_config_backup",
            endpoint="/ci/startup-config.txt",
            content_sha256="deadbeef" * 8,
            size_bytes=128,
            encrypted_locator="data/backups/startup-station-settle0.enc",
            metadata_locator="data/backups/startup-station-settle0.meta.json",
            recorded_at=datetime.now(UTC).isoformat(),
            transport_security="ssh_tunnel_pinned",
            host="192.168.2.1",
            device_fingerprint_digest=_FINGERPRINT_DIGEST,
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        ),
    )

    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(
            _APPLY_BODY,
            confirm_live_apply=True,
            uplink_settle_seconds=0,
            **_LIVE_CONN,
        ),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] != "applied"
    assert body["uplink_verification_status"] == "uplink_dispatched_unverified"
    rollback = body.get("rollback") or {}
    assert rollback.get("attempted") is False
    teardown_ops = (" down", " no authentication", " no encryption", " no ssid")
    assert not any(
        any(fragment in cmd for fragment in teardown_ops)
        for cmd in session_transport.write_commands
    )


@pytest.mark.parametrize(
    ("readback", "internet_status"),
    [
        (
            {
                **_associated_readback(),
                "connected": True,
                "link": False,
            },
            {"internet": "yes", "gateway": "yes", "dns": "yes"},
        ),
        (
            {
                **_associated_readback(),
                "txbytes": 100,
                "rxbytes": 0,
            },
            {"internet": "yes", "gateway": "yes", "dns": "yes"},
        ),
        (
            {
                **_associated_readback(),
                "state": "up",
                "link": False,
            },
            {"internet": "yes", "gateway": "yes", "dns": "yes"},
        ),
    ],
)
def test_observe_traps_never_verified_bounded(readback, internet_status) -> None:
    from router_control.application.wifi_station_apply_service import observe_station_uplink

    observation = observe_station_uplink(
        readback,
        internet_status=internet_status,
        intended_ssid="Venue-Guest",
    )
    verdict = observation.verdict
    assert verdict != "uplink_verified_bounded"


def test_wifi_station_apply_identity_mismatch_returns_422_zero_writes(
    station_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeStationLiveTransport()
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
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = station_client.post(
        "/api/router-control/v1/wifi/station/apply",
        json=dict(_APPLY_BODY, confirm_live_apply=True, **_LIVE_CONN),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.station.identity_mismatch"
    assert backup_calls == []
    assert len(session_transport.write_commands) == 0


def test_wifi_station_teardown_identity_mismatch_returns_422_zero_writes(
    station_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    station_client.test_app.state.host.gate_a_certification = _open_gate_a()
    session_transport = ApiFakeStationLiveTransport()
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
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.ensure_live_gate_a_tuple_match",
        _raise_mismatch,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.backup_startup_config",
        _track_backup,
    )

    resp = station_client.post(
        "/api/router-control/v1/wifi/station/teardown",
        json=dict(_APPLY_BODY, confirm_live_teardown=True, **_LIVE_CONN),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.station.identity_mismatch"
    assert backup_calls == []
    assert len(session_transport.write_commands) == 0
