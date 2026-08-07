"""Tests for sealed RCI allowlist, interface/system modules, and transport bounds."""

from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.adapters.netcraze import transport as transport_mod
from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    is_wifi_ap_parse_body,
    is_wireguard_parse_body,
    is_write_allowlisted,
    validate_interface_id,
)
from router_control.adapters.netcraze.errors import AllowlistViolation, TransportError
from router_control.adapters.netcraze.interface_rci import (
    InterfaceRciOperation,
    interface_up,
    verify_interface_response,
)
from router_control.adapters.netcraze.system_rci import (
    SystemRciError,
    SystemRciOperation,
    configuration_save,
    system_reboot,
    verify_system_response,
)
from router_control.adapters.netcraze.transport import (
    MAX_RCI_WRITE_BODY_BYTES,
    SealedRciWriteRequest,
)


class _RecordingClient:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def request(
        self,
        *,
        host: str,
        port: int,
        method: str,
        path: str,
        headers: dict[str, str],
        body: bytes | None,
        connect_timeout: float,
        read_timeout: float,
        ssl_context: object | None,
    ) -> transport_mod.HttpExchange:
        self.calls.append({"method": method, "path": path, "body": body})
        return transport_mod.HttpExchange(
            status=200,
            headers={"content-type": "application/json"},
            body=json.dumps([{"parse": {"prompt": "(config)", "status": []}}]).encode(),
        )

    def request_limited(self, **kwargs: Any) -> transport_mod.HttpExchange:
        return self.request(**{k: v for k, v in kwargs.items() if k != "max_bytes"})


def _ok_envelope() -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "1",
                        "ident": "Core::Interface",
                        "message": "ok",
                    }
                ],
            }
        }
    ]


def test_fixed_write_bodies_are_allowlisted() -> None:
    for command in (
        "system configuration fail-safe timer reboot 60",
        "no system configuration fail-safe timer",
        "system configuration save",
        "system reboot",
    ):
        body = build_sealed_parse_body(command)
        assert is_write_allowlisted("POST", "/rci/", body)


def test_interface_body_allowlisted_only_for_sealed_template() -> None:
    good = build_sealed_parse_body("interface upstream-wan-001 up")
    bad = build_sealed_parse_body("show version")
    assert is_write_allowlisted("POST", "/rci/", good)
    assert not is_write_allowlisted("POST", "/rci/", bad)


def test_wifi_ap_body_allowlisted_only_for_sealed_template() -> None:
    good = build_sealed_parse_body("interface WifiMaster0/AccessPoint3 up")
    good_wpa2_clear = build_sealed_parse_body(
        "interface WifiMaster0/AccessPoint3 no encryption wpa2"
    )
    bad_ap0 = build_sealed_parse_body("interface WifiMaster0/AccessPoint0 up")
    bad_ap0_wpa2_clear = build_sealed_parse_body(
        "interface WifiMaster0/AccessPoint0 no encryption wpa2"
    )
    bad_verb = build_sealed_parse_body("interface WifiMaster0/AccessPoint3 delete")
    assert is_wifi_ap_parse_body(good)
    assert is_write_allowlisted("POST", "/rci/", good)
    assert is_wifi_ap_parse_body(good_wpa2_clear)
    assert is_write_allowlisted("POST", "/rci/", good_wpa2_clear)
    assert not is_wifi_ap_parse_body(bad_ap0)
    assert not is_write_allowlisted("POST", "/rci/", bad_ap0)
    assert not is_wifi_ap_parse_body(bad_ap0_wpa2_clear)
    assert not is_write_allowlisted("POST", "/rci/", bad_ap0_wpa2_clear)
    assert not is_wifi_ap_parse_body(bad_verb)
    assert not is_write_allowlisted("POST", "/rci/", bad_verb)


def test_wifi_ap_body_allowlists_ap0_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    ap0 = build_sealed_parse_body("interface WifiMaster0/AccessPoint0 up")
    assert is_wifi_ap_parse_body(ap0)
    assert is_write_allowlisted("POST", "/rci/", ap0)


def test_wireguard_body_allowlists_wg0_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    wg0 = build_sealed_parse_body("interface Wireguard0")
    assert is_wireguard_parse_body(wg0)
    assert is_write_allowlisted("POST", "/rci/", wg0)


def test_wireguard_body_allowlisted_only_for_sealed_template() -> None:
    good = build_sealed_parse_body("interface Wireguard5")
    bad_wg0 = build_sealed_parse_body("interface Wireguard0")
    bad_secret = build_sealed_parse_body("interface Wireguard5 wireguard private-key secret")
    assert is_wireguard_parse_body(good)
    assert is_write_allowlisted("POST", "/rci/", good)
    assert not is_wireguard_parse_body(bad_wg0)
    assert not is_write_allowlisted("POST", "/rci/", bad_wg0)
    assert not is_wireguard_parse_body(bad_secret)
    assert not is_write_allowlisted("POST", "/rci/", bad_secret)


def test_validate_interface_id_rejects_injection() -> None:
    with pytest.raises(ValueError):
        validate_interface_id("GigabitEthernet0; reboot")
    with pytest.raises(ValueError):
        validate_interface_id("")


def test_interface_up_verifies_prompt_and_drops_message() -> None:
    result = verify_interface_response(
        InterfaceRciOperation.UP,
        "upstream-wan-001",
        _ok_envelope(),
    )
    sanitized = result.sanitized_dict()
    assert sanitized["interface_id"] == "upstream-wan-001"
    for entry in sanitized.get("status", []):
        assert "message" not in entry


def test_system_save_and_reboot_are_separate_allowlisted_bodies() -> None:
    save_body = build_sealed_parse_body("system configuration save")
    reboot_body = build_sealed_parse_body("system reboot")
    assert is_write_allowlisted("POST", "/rci/", save_body)
    assert is_write_allowlisted("POST", "/rci/", reboot_body)
    assert save_body != reboot_body


def test_system_reboot_verify_requires_prompt() -> None:
    response = [
        {
            "parse": {
                "prompt": "",
                "status": [{"status": "message", "code": "1", "ident": "x"}],
            }
        }
    ]
    with pytest.raises(SystemRciError, match="prompt"):
        verify_system_response(SystemRciOperation.REBOOT, response)


def test_execute_sealed_rci_write_rejects_unlisted_body() -> None:
    transport = transport_mod.NetcrazeTransport(
        host="127.0.0.1",
        username="u",
        password="p",
        http_client=_RecordingClient(),
    )
    body = build_sealed_parse_body("show version")
    with pytest.raises(AllowlistViolation):
        transport.execute_sealed_rci_write(SealedRciWriteRequest(body=body))


def test_execute_sealed_rci_write_enforces_body_size() -> None:
    transport = transport_mod.NetcrazeTransport(
        host="127.0.0.1",
        username="u",
        password="p",
        http_client=_RecordingClient(),
    )
    oversized = b"x" * (MAX_RCI_WRITE_BODY_BYTES + 1)
    with pytest.raises(TransportError, match="size bound"):
        transport.execute_sealed_rci_write(SealedRciWriteRequest(body=oversized))


class _FakeTransport:
    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> list[dict[str, Any]]:
        return _ok_envelope()


def test_interface_and_system_modules_dispatch_via_sealed_write() -> None:
    up = interface_up(_FakeTransport(), "Bridge0")
    save = configuration_save(_FakeTransport())
    reboot = system_reboot(_FakeTransport())
    assert up.operation.value == "interface_up"
    assert save.operation.value == "configuration_save"
    assert reboot.operation.value == "reboot"
