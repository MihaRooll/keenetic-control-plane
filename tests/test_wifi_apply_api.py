"""FastAPI tests for Wi-Fi apply/preview/teardown routes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_OFFLINE_PSK_PLACEHOLDER = "test-psk-placeholder"
_TEST_AP = "WifiMaster0/AccessPoint3"
_PRODUCTION_AP = "WifiMaster0/AccessPoint0"
_PRODUCTION_AP_IDS = (
    "WifiMaster0/AccessPoint0",
    "WifiMaster0/AccessPoint1",
    "WifiMaster0/AccessPoint2",
)
_NON_WIFIMASTER_AP = "Bridge0"


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
            "link": "up",
            "broadcast": True,
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


def _teardown_on_air_verified_readback() -> dict[str, Any]:
    return {
        "interface": {
            "ssid": "",
            "encryption": {},
            "state": "down",
            "up": False,
            "link": False,
            "broadcast": False,
        }
    }


class ApiFakeWifiTransport:
    def __init__(
        self,
        *,
        readback_sequence: list[Any] | None = None,
        fail_on: str | None = None,
    ) -> None:
        self.readback_sequence = list(readback_sequence or [])
        self.fail_on = fail_on
        self.write_commands: list[str] = []
        self._pre_apply_read_done = False

    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(command)
        if self.fail_on is not None and command == self.fail_on:
            return [
                {
                    "parse": {
                        "prompt": "(config)",
                        "status": [
                            {
                                "status": "error",
                                "code": "1",
                                "ident": "Core::Interface",
                                "message": "fail",
                            }
                        ],
                    }
                }
            ]
        return _ok_envelope()

    def execute_rci_parse(self, cli_command: str) -> Any:
        if cli_command.startswith("show interface") and not self._pre_apply_read_done:
            self._pre_apply_read_done = True
            if len(self.readback_sequence) == 1:
                return _baseline_readback()
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return _baseline_readback()


@pytest.fixture
def vault_wifi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_vault_apply.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeWifiTransport()
    app.state.host.wifi_apply_transport_factory = lambda: transport
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        yield client


def _enroll_vault_test_router(client) -> str:
    resp = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Vault Apply Router",
            "vendor": "V",
            "model": "M",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "mgmt-lab-standin-not-secret",
        },
        headers={"Idempotency-Key": "enroll-vault-wifi-apply"},
    )
    assert resp.status_code == 202
    return str(resp.json()["router_id"])


def _put_wifi_ap_psk(client, router_id: str, *, secret: str, key: str) -> str:
    resp = client.put(
        f"/api/router-control/v1/routers/{router_id}/credentials",
        json={"kind": "WifiApPsk", "secret": secret},
        headers={"Idempotency-Key": key},
    )
    assert resp.status_code == 201
    return str(resp.json()["credential_ref_id"])


@pytest.fixture
def wifi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_apply.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeWifiTransport()
    app.state.host.wifi_apply_transport_factory = lambda: transport
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _OFFLINE_PSK_PLACEHOLDER
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        yield client


def test_wifi_preview_ok(wifi_client) -> None:
    resp = wifi_client.post("/api/router-control/v1/wifi/preview", json=_intent_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "device_verified_wpa2"
    assert len(body["apply_ops"]) == 5
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_apply_requires_confirm(wifi_client) -> None:
    payload = _intent_payload()
    payload["confirm_live_apply"] = False
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wifi.confirm_required"


def test_wifi_apply_missing_wpa_mode_422(wifi_client) -> None:
    payload = _intent_payload(confirm_live_apply=True)
    del payload["wpa_mode"]
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 422


def test_wifi_apply_admin_up_link_down_verify_mismatch(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [
        {
            "interface": {
                "ssid": "Staff-Private",
                "encryption": {"wpa2": True, "enabled": True},
                "state": "up",
                "up": True,
                "link": "down",
                "connected": True,
            }
        }
    ]
    payload = _intent_payload(confirm_live_apply=True, compensate_on_failure=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "verify_mismatch"
    assert body["on_air_verification_status"] == "on_air_admin_only"
    assert body["rollback"]["attempted"] is False


def test_wifi_apply_success(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["on_air_verification_status"] == "on_air_verified"
    assert len(body["steps"]) == 5
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_apply_verify_mismatch(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [
        {
            "interface": {
                "ssid": "Wrong",
                "encryption": {"wpa2": True},
                "state": "up",
                "up": True,
            }
        }
    ]
    payload = _intent_payload(confirm_live_apply=True, compensate_on_failure=False)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "verify_mismatch"


def test_wifi_apply_op_error(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.fail_on = "interface WifiMaster0/AccessPoint3 encryption enable"
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True, compensate_on_failure=False)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "failed"


def test_wifi_teardown_requires_confirm(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={"ap_id": _TEST_AP, "wpa_mode": "WPA2", "confirm_live_teardown": False},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wifi.confirm_required"


def test_wifi_teardown_success(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    verified = _teardown_on_air_verified_readback()
    transport.readback_sequence = [verified, verified]
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={"ap_id": _TEST_AP, "wpa_mode": "WPA2", "confirm_live_teardown": True},
    )
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"


def test_production_ap_rejected_via_api(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(ap_id=_PRODUCTION_AP),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.ap_forbidden"


@pytest.mark.parametrize("ap_id", _PRODUCTION_AP_IDS)
def test_production_ap_rejected_via_api_preview(wifi_client, ap_id: str) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(ap_id=ap_id),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.ap_forbidden"


@pytest.mark.parametrize("ap_id", _PRODUCTION_AP_IDS)
def test_production_ap_rejected_via_api_apply(wifi_client, ap_id: str) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(ap_id=ap_id, confirm_live_apply=True),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.ap_forbidden"


@pytest.mark.parametrize("ap_id", _PRODUCTION_AP_IDS)
def test_production_ap_rejected_via_api_teardown(wifi_client, ap_id: str) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/teardown",
        json={"ap_id": ap_id, "wpa_mode": "WPA2", "confirm_live_teardown": True},
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.ap_forbidden"


def test_production_ap_accepted_via_api_preview_in_expendable_mode(
    wifi_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(ap_id=_PRODUCTION_AP),
    )
    assert resp.status_code == 200
    assert resp.json()["verification_status"] == "device_verified_wpa2"


def test_non_wifimaster_ap_rejected_via_api(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(ap_id=_NON_WIFIMASTER_AP),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wifi.ap_forbidden"


def test_wifi_apply_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_auth.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post(
            "/api/router-control/v1/wifi/apply",
            json=_intent_payload(confirm_live_apply=True),
        )
    assert resp.status_code == 401


def test_wifi_preview_wpa3_device_verified_wpa2(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(wpa_mode="WPA3"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "device_verified_wpa2"
    assert len(body["apply_ops"]) == 5
    assert any(op["operation"] == "wifi_ap_set_wpa_psk" for op in body["apply_ops"])


def test_wifi_apply_wpa3_success(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [
        {
            "interface": {
                "ssid": "Staff-Private",
                "encryption": {"wpa3": True, "enabled": True},
                "state": "up",
                "up": True,
                "link": "up",
                "broadcast": True,
            }
        }
    ]
    payload = _intent_payload(wpa_mode="WPA3", confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert len(body["steps"]) == 5
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_preview_wpa2_wpa3_mixed_device_verified_wpa2(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(wpa_mode="WPA2_WPA3_MIXED"),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "device_verified_wpa2"
    assert len(body["apply_ops"]) == 6
    op_names = [op["operation"] for op in body["apply_ops"]]
    assert op_names == [
        "wifi_ap_set_ssid",
        "wifi_ap_set_wpa_psk",
        "wifi_ap_encryption_enable",
        "wifi_ap_encryption_wpa2",
        "wifi_ap_encryption_wpa3",
        "wifi_ap_up",
    ]
    assert any("5.01.C.1.0-0" in note for note in body["notes"])
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_apply_wpa2_wpa3_mixed_success(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [
        {
            "interface": {
                "ssid": "Staff-Private",
                "encryption": {"wpa2": True, "wpa3": True, "enabled": True},
                "state": "up",
                "up": True,
                "link": "up",
                "broadcast": True,
            }
        }
    ]
    payload = _intent_payload(wpa_mode="WPA2_WPA3_MIXED", confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert len(body["steps"]) == 6
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


def test_wifi_preview_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_preview_auth.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post("/api/router-control/v1/wifi/preview", json=_intent_payload())
    assert resp.status_code == 401


def test_wifi_teardown_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_teardown_auth.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post(
            "/api/router-control/v1/wifi/teardown",
            json={"ap_id": _TEST_AP, "wpa_mode": "WPA2", "confirm_live_teardown": True},
        )
    assert resp.status_code == 401


def test_wifi_preview_rejects_plaintext_psk_field(wifi_client) -> None:
    payload = _intent_payload()
    payload["psk"] = _OFFLINE_PSK_PLACEHOLDER
    resp = wifi_client.post("/api/router-control/v1/wifi/preview", json=payload)
    assert resp.status_code == 422


_AUDIT_SECRET_MARKER = "MARKER-SEALED-APPLY-AUDIT-SECRET-VALUE"
_EXCEPTION_SECRET_MARKER = "MARKER-EXCEPTION-SECRET-PSK-VALUE"


def _wifi_apply_store(wifi_client):
    return wifi_client.app.state.host.runtime.store


def _latest_wifi_apply_audit(wifi_client) -> dict[str, object]:
    events = _wifi_apply_store(wifi_client).list_audit_events(action_prefix="sealed_apply.wifi")
    assert events, "expected sealed_apply.wifi audit event"
    return events[0]


def test_wifi_apply_audit_on_success(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    event = _latest_wifi_apply_audit(wifi_client)
    assert event["action"] == "sealed_apply.wifi.apply"
    assert event["outcome"] == "applied"
    summary = json.loads(str(event["summary_redacted"]))
    assert summary["result"]["overall"] == "applied"
    assert summary["intent"]["ap_id"] == _TEST_AP


def test_wifi_apply_audit_on_failure(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.fail_on = "interface WifiMaster0/AccessPoint3 encryption enable"
    payload = _intent_payload(confirm_live_apply=True, compensate_on_failure=False)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "failed"
    event = _latest_wifi_apply_audit(wifi_client)
    assert event["action"] == "sealed_apply.wifi.apply"
    assert event["outcome"] == "failed"


def test_wifi_apply_audit_on_exception(wifi_client, monkeypatch: pytest.MonkeyPatch) -> None:
    import router_control_host.wifi_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic apply fault")

    monkeypatch.setattr(routes_mod, "apply_wifi_intent", _boom)
    payload = _intent_payload(confirm_live_apply=True)
    with pytest.raises(RuntimeError, match="synthetic apply fault"):
        wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    event = _latest_wifi_apply_audit(wifi_client)
    assert event["action"] == "sealed_apply.wifi.apply"
    assert event["outcome"] == "error"
    summary = json.loads(str(event["summary_redacted"]))
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary
    assert _EXCEPTION_SECRET_MARKER not in json.dumps(summary)


def test_wifi_apply_audit_intent_excludes_ssid(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    summary = json.loads(str(_latest_wifi_apply_audit(wifi_client)["summary_redacted"]))
    assert "ssid" not in summary["intent"]
    assert summary["intent"]["credential_ref_id"] == "credref:staff-wifi"


def test_wifi_apply_audit_exception_excludes_secret_marker(
    wifi_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wifi_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"synthetic secret={_EXCEPTION_SECRET_MARKER}")

    monkeypatch.setattr(routes_mod, "apply_wifi_intent", _boom)
    payload = _intent_payload(confirm_live_apply=True)
    with pytest.raises(RuntimeError):
        wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    dump = _wifi_apply_store(wifi_client).dump_text_for_secret_scan()
    assert _EXCEPTION_SECRET_MARKER not in dump
    summary = json.loads(str(_latest_wifi_apply_audit(wifi_client)["summary_redacted"]))
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary


def test_wifi_teardown_audit_exception_excludes_secret_marker(
    wifi_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wifi_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"synthetic secret={_EXCEPTION_SECRET_MARKER}")

    monkeypatch.setattr(routes_mod, "teardown_wifi_ap", _boom)
    payload = {
        "ap_id": _TEST_AP,
        "wpa_mode": "WPA2",
        "confirm_live_teardown": True,
    }
    with pytest.raises(RuntimeError):
        wifi_client.post("/api/router-control/v1/wifi/teardown", json=payload)
    events = _wifi_apply_store(wifi_client).list_audit_events(
        action_prefix="sealed_apply.wifi.teardown"
    )
    assert events
    dump = _wifi_apply_store(wifi_client).dump_text_for_secret_scan()
    assert _EXCEPTION_SECRET_MARKER not in dump
    summary = json.loads(str(events[0]["summary_redacted"]))
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary


def test_wifi_apply_audit_excludes_secret_marker(wifi_client) -> None:
    wifi_client.app.state.host.wifi_apply_credential_resolver = (
        lambda _ref: _AUDIT_SECRET_MARKER
    )
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    dump = _wifi_apply_store(wifi_client).dump_text_for_secret_scan()
    assert _AUDIT_SECRET_MARKER not in dump


def test_wifi_apply_audit_append_failure_does_not_break_apply(
    wifi_client, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    store = _wifi_apply_store(wifi_client)

    def _fail_append_audit(*_args: object, **_kwargs: object) -> str:
        raise OSError("audit store unavailable")

    monkeypatch.setattr(store, "append_audit", _fail_append_audit)
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    with caplog.at_level(logging.WARNING):
        resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"
    assert any("sealed_apply audit append failed" in rec.message for rec in caplog.records)


@pytest.mark.parametrize(
    "field_override,expected_code",
    [
        ({"guest_isolation": True}, "wifi.guest_isolation_unsupported"),
        ({"captive_portal": "Enabled"}, "wifi.captive_portal_unsupported"),
    ],
)
def test_wifi_preview_rejects_unsupported_intent_fields(
    wifi_client,
    field_override: dict[str, object],
    expected_code: str,
) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(**field_override),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == expected_code


@pytest.mark.parametrize(
    "field_override,expected_code",
    [
        ({"guest_isolation": True}, "wifi.guest_isolation_unsupported"),
        ({"captive_portal": "Enabled"}, "wifi.captive_portal_unsupported"),
    ],
)
def test_wifi_apply_rejects_unsupported_intent_fields(
    wifi_client,
    field_override: dict[str, object],
    expected_code: str,
) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(confirm_live_apply=True, **field_override),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == expected_code


def test_wifi_preview_accepts_noop_isolation_and_captive_defaults(wifi_client) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(guest_isolation=False, captive_portal="Disabled"),
    )
    assert resp.status_code == 200
    assert resp.json()["verification_status"] == "device_verified_wpa2"


def test_wifi_apply_accepts_noop_isolation_and_captive_defaults(wifi_client) -> None:
    transport: ApiFakeWifiTransport = wifi_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(
            confirm_live_apply=True,
            guest_isolation=False,
            captive_portal="Disabled",
        ),
    )
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"


@pytest.mark.parametrize(
    "field_override,expected_code",
    [
        (
            {"enabled": False, "guest_isolation": True, "credential_ref_id": None},
            "wifi.guest_isolation_unsupported",
        ),
        (
            {"enabled": False, "captive_portal": "Enabled", "credential_ref_id": None},
            "wifi.captive_portal_unsupported",
        ),
    ],
)
def test_wifi_preview_rejects_unsupported_when_disabled(
    wifi_client,
    field_override: dict[str, object],
    expected_code: str,
) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(**field_override),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == expected_code


@pytest.mark.parametrize(
    "field_override,expected_code",
    [
        (
            {"enabled": False, "guest_isolation": True, "credential_ref_id": None},
            "wifi.guest_isolation_unsupported",
        ),
        (
            {"enabled": False, "captive_portal": "Enabled", "credential_ref_id": None},
            "wifi.captive_portal_unsupported",
        ),
    ],
)
def test_wifi_apply_rejects_unsupported_when_disabled(
    wifi_client,
    field_override: dict[str, object],
    expected_code: str,
) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(confirm_live_apply=True, **field_override),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == expected_code


_SECRET_MARKER = "SYNTHETIC-PSK-MUST-NOT-APPEAR-IN-RESPONSE"


def test_wifi_preview_missing_credential_ref_structural(wifi_client) -> None:
    payload = _intent_payload(credential_ref_id=None)
    resp = wifi_client.post("/api/router-control/v1/wifi/preview", json=payload)
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "wifi.credential_ref_required"
    details = body["error"]["details"]
    assert len(details) >= 1
    assert details[0].get("field") == "credential_ref_id"
    assert "planner.credential_ref_required" not in body["error"]["message"]


def test_wifi_apply_missing_credential_ref_structural(wifi_client) -> None:
    payload = _intent_payload(credential_ref_id=None, confirm_live_apply=True)
    resp = wifi_client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "wifi.credential_ref_required"
    details = body["error"]["details"]
    assert len(details) >= 1
    assert details[0].get("field") == "credential_ref_id"
    assert "planner.credential_ref_required" not in body["error"]["message"]


def test_wifi_preview_rejects_revoked_credential_ref(vault_wifi_client) -> None:
    client = vault_wifi_client
    router_id = _enroll_vault_test_router(client)
    ref_id = _put_wifi_ap_psk(
        client, router_id, secret="edit-psk-aaaaaa", key="put-preview-revoked"
    )
    revoke = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{ref_id}/revoke",
        headers={"Idempotency-Key": "revoke-preview-revoked"},
    )
    assert revoke.status_code == 202
    resp = client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(credential_ref_id=ref_id),
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "wifi.credential_unusable"
    assert body["error"]["details"][0].get("field") == "credential_ref_id"
    assert body["error"]["details"][0].get("reason") == "revoked"


def test_wifi_apply_rejects_revoked_credential_ref_before_dispatch(
    vault_wifi_client,
) -> None:
    client = vault_wifi_client
    transport: ApiFakeWifiTransport = client.test_transport
    router_id = _enroll_vault_test_router(client)
    ref_id = _put_wifi_ap_psk(
        client, router_id, secret="edit-psk-bbbbbb", key="put-apply-revoked"
    )
    revoke = client.post(
        f"/api/router-control/v1/routers/{router_id}/credentials/{ref_id}/revoke",
        headers={"Idempotency-Key": "revoke-apply-revoked"},
    )
    assert revoke.status_code == 202
    resp = client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(credential_ref_id=ref_id, confirm_live_apply=True),
    )
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "wifi.credential_unusable"
    assert body["error"]["details"][0].get("field") == "credential_ref_id"
    assert transport.write_commands == []
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(body)


@pytest.fixture
def shared_fake_wifi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "shared_fake_wifi.sqlite3", allow_fake_mutations=True)
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _OFFLINE_PSK_PLACEHOLDER
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_fake_apply_then_observed_readback_roundtrip(shared_fake_wifi_client) -> None:
    client = shared_fake_wifi_client
    apply_payload = _intent_payload(confirm_live_apply=True, ssid="Roundtrip-SSID")
    apply_resp = client.post("/api/router-control/v1/wifi/apply", json=apply_payload)
    assert apply_resp.status_code == 200

    obs_resp = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP]},
    )
    assert obs_resp.status_code == 200
    items = obs_resp.json()["access_points"]
    ap_row = next(row for row in items if row["ap_id"] == _TEST_AP)
    assert ap_row["ssid"] == "Roundtrip-SSID"
    assert ap_row["wpa_mode"] == "WPA2"
    assert ap_row["enabled_or_up"] is True


def test_fake_teardown_then_observed_readback_disabled(shared_fake_wifi_client) -> None:
    client = shared_fake_wifi_client
    apply_resp = client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(confirm_live_apply=True, ssid="Teardown-SSID"),
    )
    assert apply_resp.status_code == 200

    teardown_resp = client.post(
        "/api/router-control/v1/wifi/teardown",
        json={
            "ap_id": _TEST_AP,
            "wpa_mode": "WPA2",
            "confirm_live_teardown": True,
        },
    )
    assert teardown_resp.status_code == 200

    obs_resp = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP]},
    )
    assert obs_resp.status_code == 200
    ap_row = next(
        row for row in obs_resp.json()["access_points"] if row["ap_id"] == _TEST_AP
    )
    assert ap_row["enabled_or_up"] is False


def test_fake_wifi_state_secret_marker_not_leaked(shared_fake_wifi_client) -> None:
    client = shared_fake_wifi_client
    host = client.app.state.host
    host.wifi_apply_credential_resolver = lambda _ref: _SECRET_MARKER
    apply_resp = client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(confirm_live_apply=True),
    )
    assert apply_resp.status_code == 200
    obs_resp = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={"ap_ids": [_TEST_AP]},
    )
    assert obs_resp.status_code == 200

    device = host.fake_wifi_device
    assert device is not None
    blob = json.dumps(
        {
            "device": repr(device),
            "apply": apply_resp.json(),
            "observed": obs_resp.json(),
        }
    )
    assert _OFFLINE_PSK_PLACEHOLDER not in blob
    assert _SECRET_MARKER not in blob

    store = host.runtime.store
    audit_dump = store.dump_text_for_secret_scan()
    assert _OFFLINE_PSK_PLACEHOLDER not in audit_dump


def test_observed_live_params_do_not_read_fake_device_state(
    shared_fake_wifi_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = shared_fake_wifi_client
    host = client.app.state.host
    apply_resp = client.post(
        "/api/router-control/v1/wifi/apply",
        json=_intent_payload(confirm_live_apply=True, ssid="Must-Not-Leak-To-Live"),
    )
    assert apply_resp.status_code == 200
    device = host.fake_wifi_device
    assert device is not None

    readback_called = False
    original_readback = device.readback_for

    def _tracked_readback(ap_id: str):
        nonlocal readback_called
        readback_called = True
        return original_readback(ap_id)

    monkeypatch.setattr(device, "readback_for", _tracked_readback)

    resp = client.post(
        "/api/router-control/v1/wifi/observed-state",
        json={
            "ap_ids": [_TEST_AP],
            "host": "192.168.2.1",
            "username": "admin",
            "router_credential_ref_id": "credref:missing",
            "ssh_host_key_sha256": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "source_address": "127.0.0.1",
        },
    )
    assert resp.status_code in (422, 503)
    assert readback_called is False
