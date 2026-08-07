"""KeenDNS apply host API tests (confirm-gated; fake transport)."""

from __future__ import annotations

import importlib
import json

import pytest
from router_control.adapters.netcraze.allowlist import build_sealed_parse_body, is_write_allowlisted
from router_control.application.keendns_apply_service import (
    ERROR_CODE_COMPONENT_ABSENT,
    ERROR_CODE_INVENTORY_UNREADABLE,
    KeenDnsApplyServiceError,
    apply_keendns_intent,
)
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_API = "/api/router-control/v1"

_APPLY_BODY = {
    "intent_kind": "book",
    "name": "sample-name",
    "domain": "netcraze.pro",
    "mode": "auto",
    "confirm_live_apply": True,
}


class ApiFakeKeenDnsTransport:
    keendns_offline_only = True

    def __init__(self) -> None:
        self.write_commands: list[str] = []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, object]]:
        body = json.loads(request.body.decode("utf-8"))
        self.write_commands.append(redact_sealed_cli_command(str(body[0]["parse"])))
        return [{"parse": {"status": [{"ident": "Cloud::KeenDNS", "message": "ok"}]}}]


@pytest.fixture
def keendns_client(tmp_path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "keendns-apply.sqlite3", allow_fake_mutations=True)
    transport = ApiFakeKeenDnsTransport()
    app.state.host.keendns_apply_transport_factory = lambda: transport
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_transport = transport
        yield client


def test_keendns_apply_requires_confirm(keendns_client) -> None:
    payload = dict(_APPLY_BODY)
    payload["confirm_live_apply"] = False
    resp = keendns_client.post(f"{_API}/keendns/apply", json=payload)
    assert resp.status_code == 400
    assert resp.json()["error"]["code"] == "keendns.confirm_required"


def test_keendns_apply_offline_success(keendns_client) -> None:
    resp = keendns_client.post(f"{_API}/keendns/apply", json=_APPLY_BODY)
    assert resp.status_code == 200
    body = resp.json()
    assert body["overall"] == "dispatched_offline"
    assert body["name"] == "sample-name"
    assert body["domain"] == "netcraze.pro"
    transport: ApiFakeKeenDnsTransport = keendns_client.test_transport
    assert transport.write_commands == ["ndns book-name sample-name netcraze.pro auto"]


def test_keendns_apply_rejects_invalid_name(keendns_client) -> None:
    payload = dict(_APPLY_BODY)
    payload["name"] = "bad_name"
    resp = keendns_client.post(f"{_API}/keendns/apply", json=payload)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "keendns.apply_failed"


def test_keendns_apply_book_requires_mode(keendns_client) -> None:
    payload = dict(_APPLY_BODY)
    payload.pop("mode")
    resp = keendns_client.post(f"{_API}/keendns/apply", json=payload)
    assert resp.status_code == 422


def test_no_apply_keendns_in_preview_service() -> None:
    module = importlib.import_module("router_control.application.keendns_preview_service")
    assert not hasattr(module, "apply_keendns")


def test_allowlist_accepts_apply_command_body() -> None:
    body = build_sealed_parse_body("ndns book-name sample-name netcraze.pro auto")
    assert is_write_allowlisted("POST", "/rci/", body) is True


_APPLY_INTENT = {
    "intent_kind": "book",
    "name": "sample-name",
    "domain": "netcraze.pro",
    "mode": "auto",
}


class _LiveTransportNoNdns:
    keendns_live_dispatch = True

    def __init__(self) -> None:
        self.dispatched = False

    def read_json(self, command: object, body: bytes | None = None) -> dict[str, object]:
        return {"component": {"wifi": {}}}

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, object]]:
        self.dispatched = True
        raise AssertionError("must not dispatch when ndns component absent")


class _LiveTransportInventoryUnreadable:
    keendns_live_dispatch = True

    def __init__(self) -> None:
        self.dispatched = False

    def read_json(self, command: object, body: bytes | None = None) -> dict[str, object]:
        raise RuntimeError("components inventory unreadable")

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, object]]:
        self.dispatched = True
        raise AssertionError("must not dispatch when inventory unreadable")


def test_live_apply_component_absent_fail_closed() -> None:
    transport = _LiveTransportNoNdns()
    with pytest.raises(KeenDnsApplyServiceError, match=ERROR_CODE_COMPONENT_ABSENT):
        apply_keendns_intent(
            intent=_APPLY_INTENT,
            transport=transport,
            live_dispatch=True,
            backup_callback=lambda: None,
        )
    assert transport.dispatched is False


def test_live_apply_inventory_unreadable_fail_closed() -> None:
    transport = _LiveTransportInventoryUnreadable()
    with pytest.raises(KeenDnsApplyServiceError, match=ERROR_CODE_INVENTORY_UNREADABLE):
        apply_keendns_intent(
            intent=_APPLY_INTENT,
            transport=transport,
            live_dispatch=True,
            backup_callback=lambda: None,
        )
    assert transport.dispatched is False


def test_live_apply_without_backup_callback_fail_closed() -> None:
    transport = _LiveTransportNoNdns()

    with pytest.raises(KeenDnsApplyServiceError, match="backup callback"):
        apply_keendns_intent(
            intent=_APPLY_INTENT,
            transport=transport,
            live_dispatch=True,
        )
    assert transport.dispatched is False


class _LiveTransportNdnsPresent:
    keendns_live_dispatch = True

    def __init__(self, ack: list[dict[str, object]]) -> None:
        self.ack = ack
        self.dispatched = False

    def read_json(self, command: object, body: bytes | None = None) -> dict[str, object]:
        return {"component": {"ndns": {}, "wifi": {}}}

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, object]]:
        self.dispatched = True
        return self.ack


def test_live_apply_ack_single_error_status_fails() -> None:
    ack = [{"parse": {"status": [{"status": "error", "message": "booking failed"}]}}]
    transport = _LiveTransportNdnsPresent(ack)
    result = apply_keendns_intent(
        intent=_APPLY_INTENT,
        transport=transport,
        live_dispatch=True,
        backup_callback=lambda: None,
    )
    assert result.overall == "failed"
    assert any(step.ok is False for step in result.steps)
    assert transport.dispatched is True


def test_live_apply_ack_mixed_message_then_error_fails() -> None:
    ack = [
        {
            "parse": {
                "status": [
                    {"ident": "Cloud::KeenDNS", "message": "ok"},
                    {"status": "error", "message": "booking failed after message"},
                ]
            }
        }
    ]
    transport = _LiveTransportNdnsPresent(ack)
    result = apply_keendns_intent(
        intent=_APPLY_INTENT,
        transport=transport,
        live_dispatch=True,
        backup_callback=lambda: None,
    )
    assert result.overall == "failed"
    assert any(step.ok is False for step in result.steps)
    assert transport.dispatched is True
