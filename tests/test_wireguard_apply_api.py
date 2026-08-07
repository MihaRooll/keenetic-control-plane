"""FastAPI tests for WireGuard apply/preview/teardown routes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from router_control.adapters.netcraze.allowlist import is_wireguard_nested_peer_body
from router_control.adapters.netcraze.sanitize import (
    redact_sealed_cli_command,
    redact_sealed_nested_body,
)
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_ASC_9 = [5, 42, 54, 0, 0, 1, 2, 3, 4]
_ASC_16 = [5, 42, 54, 0, 0, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0]
_TEST_WG = "Wireguard5"
_FORBIDDEN_WG = "Wireguard0"
_PLACEHOLDER_PEER = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
_PRIVATE_KEY_REF = "credref:awg-private-test"
_PSK_REF = "credref:awg-psk-test"
_PLACEHOLDER_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def _intent_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "wg_id": _TEST_WG,
        "enabled": True,
        "asc_args": _ASC_9,
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
            "type": "Wireguard",
        }
    }


def _baseline_readback() -> dict[str, Any]:
    return {"interface": {}}


class ApiFakeWireguardTransport:
    def __init__(
        self,
        *,
        readback_sequence: list[Any] | None = None,
        fail_on: str | None = None,
    ) -> None:
        self.readback_sequence = list(readback_sequence or [])
        self.fail_on = fail_on
        self.write_commands: list[str] = []
        self.nested_write_bodies: list[dict[str, Any]] = []
        self.parse_commands: list[str] = []
        self.sealed_write_calls = 0
        self._pre_apply_read_done = False

    def execute_sealed_rci_write(self, request: Any) -> Any:
        self.sealed_write_calls += 1
        body_bytes = request.body
        if is_wireguard_nested_peer_body(body_bytes):
            nested = json.loads(body_bytes.decode("utf-8"))
            self.nested_write_bodies.append(redact_sealed_nested_body(nested))
            return _ok_envelope()
        body = json.loads(body_bytes.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(redact_sealed_cli_command(command))
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
        if command == f"interface {_TEST_WG}":
            return _ok_envelope(prompt="(config-if)")
        return _ok_envelope()

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if cli_command.startswith("show interface") and not self._pre_apply_read_done:
            self._pre_apply_read_done = True
            if len(self.readback_sequence) == 1:
                return _baseline_readback()
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return _baseline_readback()


@pytest.fixture
def wg_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wg_apply.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeWireguardTransport()

    def _fake_resolver(ref_id: str) -> str:
        if ref_id == _PRIVATE_KEY_REF:
            return _PLACEHOLDER_KEY
        if ref_id == _PSK_REF:
            return "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
        raise AssertionError(f"unexpected credential ref: {ref_id}")

    app.state.host.wireguard_apply_transport_factory = lambda: transport
    app.state.host.wireguard_apply_credential_resolver = _fake_resolver
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        yield client


def test_wireguard_preview_ok(wg_client) -> None:
    resp = wg_client.post("/api/router-control/v1/wireguard/preview", json=_intent_payload())
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "device_verified_asc9"
    assert len(body["apply_ops"]) == 3
    serialized = json.dumps(body)
    assert "private-key" not in serialized
    assert "peer_public_key" not in serialized


def test_wireguard_apply_requires_confirm(wg_client) -> None:
    payload = _intent_payload()
    payload["confirm_live_apply"] = False
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wireguard.confirm_required"


def test_wireguard_apply_success(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert len(body["steps"]) == 3
    assert body["verification_status"] == "device_verified_asc9"
    assert body["configuration_verification_status"] == "device_accepted_configuration"
    assert body["interface_verification_status"] == "interface_present_up"
    assert body["tunnel_verification_status"] == "tunnel_no_peer"


def test_wireguard_apply_tunnel_field_always_present_when_applied(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["tunnel_verification_status"] == "tunnel_no_peer"
    assert "tunnel_verified" not in json.dumps(body)


def test_wireguard_apply_verify_mismatch(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport.readback_sequence = [
        {"interface": {"id": "Wireguard6", "state": "up", "up": True}}
    ]
    payload = _intent_payload(confirm_live_apply=True)
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "verify_mismatch"


def test_wireguard_apply_handshake_settle_seconds_accepted(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(confirm_live_apply=True, handshake_settle_seconds=25)
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"


def test_wireguard_teardown_requires_confirm(wg_client) -> None:
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/teardown",
        json={"wg_id": _TEST_WG, "enabled": True, "confirm_live_teardown": False},
    )
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "wireguard.confirm_required"


def test_wireguard_teardown_success(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport.readback_sequence = [_baseline_readback()]
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/teardown",
        json={"wg_id": _TEST_WG, "enabled": True, "confirm_live_teardown": True},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "applied"
    assert body["verification_status"] == "device_verified_asc9"


_EXCEPTION_SECRET_MARKER = "MARKER-EXCEPTION-SECRET-PSK-VALUE"


def _wg_apply_store(wg_client):
    return wg_client.app.state.host.runtime.store


def _latest_wg_audit(wg_client, *, verb: str) -> dict[str, object]:
    events = _wg_apply_store(wg_client).list_audit_events(
        action_prefix=f"sealed_apply.wireguard.{verb}"
    )
    assert events, f"expected sealed_apply.wireguard.{verb} audit event"
    return events[0]


def test_wireguard_apply_audit_exception_excludes_secret_marker(
    wg_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wireguard_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"synthetic secret={_EXCEPTION_SECRET_MARKER}")

    monkeypatch.setattr(routes_mod, "apply_wireguard_intent", _boom)
    payload = _intent_payload(confirm_live_apply=True)
    with pytest.raises(RuntimeError):
        wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    dump = _wg_apply_store(wg_client).dump_text_for_secret_scan()
    assert _EXCEPTION_SECRET_MARKER not in dump
    summary = json.loads(str(_latest_wg_audit(wg_client, verb="apply")["summary_redacted"]))
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary
    assert "peer_public_key" not in summary["intent"]
    assert "asc_args" not in summary["intent"]


def test_wireguard_teardown_audit_exception_excludes_secret_marker(
    wg_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    import router_control_host.wireguard_apply_routes as routes_mod

    def _boom(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"synthetic secret={_EXCEPTION_SECRET_MARKER}")

    monkeypatch.setattr(routes_mod, "teardown_wireguard", _boom)
    payload = {"wg_id": _TEST_WG, "enabled": True, "confirm_live_teardown": True}
    with pytest.raises(RuntimeError):
        wg_client.post("/api/router-control/v1/wireguard/teardown", json=payload)
    dump = _wg_apply_store(wg_client).dump_text_for_secret_scan()
    assert _EXCEPTION_SECRET_MARKER not in dump
    summary = json.loads(str(_latest_wg_audit(wg_client, verb="teardown")["summary_redacted"]))
    assert summary["exception_type"] == "RuntimeError"
    assert "error_message" not in summary


def test_forbidden_wg_rejected_via_api(wg_client) -> None:
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/preview",
        json=_intent_payload(wg_id=_FORBIDDEN_WG),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.wg_forbidden"


def test_16_arg_preview_unsupported(wg_client) -> None:
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/preview",
        json=_intent_payload(asc_args=_ASC_16),
    )
    assert resp.status_code == 200
    assert resp.json()["verification_status"] == "unsupported_pending_verification"


def test_negative_asc_args_rejected_on_preview(wg_client) -> None:
    negative_asc = list(_ASC_9)
    negative_asc[0] = -1
    resp = wg_client.post(
        "/api/router-control/v1/wireguard/preview",
        json=_intent_payload(asc_args=negative_asc),
    )
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.invalid_asc_args"


def test_negative_asc_args_rejected_on_apply_without_dispatch(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    negative_asc = list(_ASC_9)
    negative_asc[3] = -1
    payload = _intent_payload(asc_args=negative_asc, confirm_live_apply=True)
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.invalid_asc_args"
    assert transport.write_commands == []


def test_default_fake_transport_reaches_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wg_default_fake.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        payload = _intent_payload(wg_id="Wireguard6", confirm_live_apply=True)
        resp = client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"
    assert resp.json()["wg_id"] == "Wireguard6"


def test_wireguard_preview_rejects_secret_field(wg_client) -> None:
    payload = _intent_payload()
    payload["private-key"] = "secret"
    resp = wg_client.post("/api/router-control/v1/wireguard/preview", json=payload)
    assert resp.status_code == 422


def test_wireguard_preview_accepts_credential_refs_and_peer_fields(wg_client) -> None:
    payload = _intent_payload(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
    )
    resp = wg_client.post("/api/router-control/v1/wireguard/preview", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["verification_status"] == "pending_live_verification"
    serialized = json.dumps(body)
    assert _PLACEHOLDER_KEY not in serialized
    assert _PRIVATE_KEY_REF in serialized


def test_wireguard_preview_includes_set_tcp_mss(wg_client) -> None:
    payload = _intent_payload(tcp_mss_pmtu=True)
    resp = wg_client.post("/api/router-control/v1/wireguard/preview", json=payload)
    assert resp.status_code == 200
    ops = [op["operation"] for op in resp.json()["apply_ops"]]
    assert "wireguard_set_tcp_mss" in ops


def test_wireguard_preview_rejects_path_style(wg_client) -> None:
    payload = _intent_payload(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_rci_shape="path_style",
    )
    resp = wg_client.post("/api/router-control/v1/wireguard/preview", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.peer_rci_shape_unsupported"
    details = resp.json()["error"].get("details", [])
    assert details and details[0].get("reason") == "invalid_value"
    assert "path_style" not in json.dumps(resp.json()).lower()


def test_wireguard_apply_rejects_path_style(wg_client) -> None:
    payload = _intent_payload(
        asc_args=None,
        confirm_live_apply=True,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_rci_shape="path_style",
    )
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "wireguard.peer_rci_shape_unsupported"


def test_wireguard_apply_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wg_auth.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post(
            "/api/router-control/v1/wireguard/apply",
            json=_intent_payload(confirm_live_apply=True),
        )
    assert resp.status_code == 401


def test_wireguard_preview_nested_rci_shape(wg_client) -> None:
    payload = _intent_payload(
        asc_args=None,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        peer_rci_shape="nested_rci",
    )
    resp = wg_client.post("/api/router-control/v1/wireguard/preview", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    peer_ops = [
        op
        for op in body["apply_ops"]
        if op["operation"] in ("wireguard_upsert_peer_nested", "wireguard_add_peer")
    ]
    assert len(peer_ops) == 1
    assert peer_ops[0]["operation"] == "wireguard_upsert_peer_nested"
    assert peer_ops[0]["peer_rci_shape"] == "nested_rci"
    body_json = json.dumps(body)
    assert _PLACEHOLDER_KEY not in body_json
    assert "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" not in body_json


def test_wireguard_apply_nested_rci_dispatches_nested_body(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport.readback_sequence = [_applied_readback()]
    payload = _intent_payload(
        asc_args=None,
        confirm_live_apply=True,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        preshared_key_credential_ref_id=_PSK_REF,
        peer_rci_shape="nested_rci",
    )
    resp = wg_client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    assert resp.json()["overall"] == "applied"
    assert len(transport.nested_write_bodies) == 1
    peer_obj = transport.nested_write_bodies[0]["interface"][_TEST_WG]["wireguard"]["peer"][0]
    assert peer_obj["key"] == _PLACEHOLDER_PEER
    assert peer_obj["endpoint"] == {"address": "vpn.example.com:51820"}
    assert peer_obj["preshared-key"] == "REDACTED"
    body_json = json.dumps(resp.json())
    assert _PLACEHOLDER_KEY not in body_json
    assert "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=" not in body_json


_OBSERVE_PATH = "/api/router-control/v1/wireguard/observe"


def _healthy_peer_readback(*, wg_id: str = _TEST_WG) -> dict[str, Any]:
    return {
        "interface": {
            "id": wg_id,
            "state": "up",
            "up": True,
            "wireguard": {
                "peer": [
                    {
                        "public-key": _PLACEHOLDER_PEER,
                        "last-handshake": 1_700_000_000,
                        "online": "yes",
                        "rxbytes": 1024,
                        "txbytes": 2048,
                    }
                ],
            },
        }
    }


def test_wireguard_observe_fake_transport_ok(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport._pre_apply_read_done = True
    transport.readback_sequence = [_applied_readback()]
    resp = wg_client.post(_OBSERVE_PATH, json={"wg_id": _TEST_WG})
    assert resp.status_code == 200
    body = resp.json()
    assert body["wg_id"] == _TEST_WG
    assert body["tunnel_verification_status"] in {
        "tunnel_no_peer",
        "tunnel_never_handshaked",
        "tunnel_healthy",
        "tunnel_unverified",
    }
    assert isinstance(body["verdict_explanation"], dict)
    assert "signals_read" in body["verdict_explanation"]


def test_wireguard_observe_no_mutation(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport._pre_apply_read_done = True
    transport.readback_sequence = [_applied_readback()]
    resp = wg_client.post(_OBSERVE_PATH, json={"wg_id": _TEST_WG})
    assert resp.status_code == 200
    assert transport.parse_commands == [f"show interface {_TEST_WG}"]
    assert transport.write_commands == []
    assert transport.nested_write_bodies == []
    assert transport.sealed_write_calls == 0


def test_wireguard_observe_requires_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "wg_observe_auth.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        resp = client.post(_OBSERVE_PATH, json={"wg_id": _TEST_WG})
    assert resp.status_code == 401


def test_wireguard_observe_forbidden_wg_id_no_echo(wg_client) -> None:
    resp = wg_client.post(_OBSERVE_PATH, json={"wg_id": _FORBIDDEN_WG})
    assert resp.status_code == 422
    body = resp.json()
    assert body["error"]["code"] == "wireguard.wg_forbidden"
    assert _FORBIDDEN_WG not in json.dumps(body)
    details = body["error"].get("details", [])
    assert details and details[0].get("reason") == "not_allowlisted"
    assert details[0].get("field") == "wg_id"


def test_wireguard_observe_tunnel_no_peer(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport._pre_apply_read_done = True
    transport.readback_sequence = [_applied_readback()]
    resp = wg_client.post(_OBSERVE_PATH, json={"wg_id": _TEST_WG})
    assert resp.status_code == 200
    assert resp.json()["tunnel_verification_status"] == "tunnel_no_peer"
    assert resp.json()["interface_readable"] is True


def test_wireguard_observe_tunnel_healthy(wg_client) -> None:
    transport: ApiFakeWireguardTransport = wg_client.test_transport
    transport._pre_apply_read_done = True
    transport.readback_sequence = [_healthy_peer_readback()]
    resp = wg_client.post(_OBSERVE_PATH, json={"wg_id": _TEST_WG})
    assert resp.status_code == 200
    assert resp.json()["tunnel_verification_status"] == "tunnel_healthy"


def test_wireguard_observe_without_fake_mutations_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "wg_observe_no_flag.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post(_OBSERVE_PATH, json={"wg_id": _TEST_WG})
    assert resp.status_code == 200
    assert resp.json()["wg_id"] == _TEST_WG
