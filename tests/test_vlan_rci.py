"""Offline tests for sealed VLAN bridge RCI module."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.rci_validation import RciValidationError
from router_control.adapters.netcraze.vlan_rci import (
    VlanRciError,
    VlanRciOperation,
    command_for,
    sealed_request_for,
    validate_ipv4_dotted_mask,
    validate_ipv4_gateway,
    validate_security_level,
    validate_vlan_bridge_id,
    verify_vlan_response,
)


def _ok_envelope() -> list[dict[str, object]]:
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


def _error_envelope() -> list[dict[str, object]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "error",
                        "code": "1",
                        "ident": "Core::Interface",
                        "message": "failed",
                    }
                ],
            }
        }
    ]


@pytest.mark.parametrize(
    ("operation", "bridge_id", "kwargs", "expected_cli"),
    [
        (
            VlanRciOperation.CREATE_BRIDGE,
            "Bridge3",
            {},
            "interface Bridge3",
        ),
        (
            VlanRciOperation.REMOVE_BRIDGE,
            "Bridge4",
            {},
            "no interface Bridge4",
        ),
        (
            VlanRciOperation.SET_IP_ADDRESS,
            "Bridge5",
            {"ipv4_address": "10.20.0.1", "ipv4_mask": "255.255.255.0"},
            "interface Bridge5 ip address 10.20.0.1 255.255.255.0",
        ),
        (
            VlanRciOperation.CLEAR_IP_ADDRESS,
            "Bridge6",
            {},
            "interface Bridge6 no ip address",
        ),
        (
            VlanRciOperation.SET_SECURITY_LEVEL,
            "Bridge7",
            {"security_level": "protected"},
            "interface Bridge7 security-level protected",
        ),
        (
            VlanRciOperation.CLEAR_SECURITY_LEVEL,
            "Bridge8",
            {},
            "interface Bridge8 no security-level",
        ),
        (
            VlanRciOperation.UP,
            "Bridge9",
            {},
            "interface Bridge9 up",
        ),
        (
            VlanRciOperation.DOWN,
            "Bridge2",
            {},
            "interface Bridge2 down",
        ),
    ],
)
def test_command_for_allowlisted_cli(
    operation: VlanRciOperation,
    bridge_id: str,
    kwargs: dict[str, str],
    expected_cli: str,
) -> None:
    assert command_for(operation, bridge_id, **kwargs) == expected_cli


@pytest.mark.parametrize(
    "bridge_id",
    ["Bridge0", "Bridge1", "Bridge10", "WifiMaster0/AccessPoint3"],
)
def test_validate_vlan_bridge_id_rejects_disallowed(bridge_id: str) -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_vlan_bridge_id(bridge_id)
    assert exc_info.value.code == "not_allowlisted"
    assert exc_info.value.field == "bridge_id"


@pytest.mark.parametrize("bridge_id", ["Bridge2", "Bridge9", "  Bridge5  "])
def test_validate_vlan_bridge_id_accepts_throwaway(bridge_id: str) -> None:
    assert validate_vlan_bridge_id(bridge_id).startswith("Bridge")


def test_validate_ipv4_gateway_rejects_invalid() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_ipv4_gateway("999.1.1.1")
    assert exc_info.value.field == "ipv4_gateway"


def test_validate_ipv4_dotted_mask_rejects_non_netmask() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_ipv4_dotted_mask("255.255.255.1")
    assert exc_info.value.field == "ipv4_mask"


@pytest.mark.parametrize("level", ["private", "protected", "public", "  PUBLIC  "])
def test_validate_security_level_accepts_allowlisted(level: str) -> None:
    assert validate_security_level(level) in {"private", "protected", "public"}


def test_validate_security_level_rejects_unknown() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_security_level("dmz")
    assert exc_info.value.field == "security_level"


def test_sealed_request_for_shape() -> None:
    request = sealed_request_for(
        VlanRciOperation.SET_IP_ADDRESS,
        "Bridge3",
        ipv4_address="10.20.0.1",
        ipv4_mask="255.255.255.0",
    )
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [{"parse": "interface Bridge3 ip address 10.20.0.1 255.255.255.0"}]
    assert request.body == build_sealed_parse_body(
        "interface Bridge3 ip address 10.20.0.1 255.255.255.0"
    )


@pytest.mark.parametrize(
    "operation",
    [
        VlanRciOperation.CREATE_BRIDGE,
        VlanRciOperation.UP,
        VlanRciOperation.SET_IP_ADDRESS,
        VlanRciOperation.SET_SECURITY_LEVEL,
    ],
)
def test_verify_vlan_response_accepts_good_ack(operation: VlanRciOperation) -> None:
    kwargs: dict[str, str] = {}
    if operation is VlanRciOperation.SET_IP_ADDRESS:
        kwargs = {"ipv4_address": "10.20.0.1", "ipv4_mask": "255.255.255.0"}
    if operation is VlanRciOperation.SET_SECURITY_LEVEL:
        kwargs = {"security_level": "protected"}
    result = verify_vlan_response(
        operation,
        "Bridge3",
        _ok_envelope(),
        **kwargs,
    )
    sanitized = result.sanitized_dict()
    assert sanitized["bridge_id"] == "Bridge3"
    assert sanitized["ack_matched"] is True


def test_verify_vlan_response_rejects_error_status() -> None:
    with pytest.raises(VlanRciError, match="error status"):
        verify_vlan_response(VlanRciOperation.DOWN, "Bridge3", _error_envelope())


def test_verify_vlan_response_rejects_missing_status() -> None:
    with pytest.raises(VlanRciError, match="no RCI parse status"):
        verify_vlan_response(VlanRciOperation.UP, "Bridge3", [{"parse": {"prompt": "(config)"}}])


def test_command_for_set_ip_requires_address_and_mask() -> None:
    with pytest.raises(VlanRciError, match="ipv4_address and ipv4_mask"):
        command_for(VlanRciOperation.SET_IP_ADDRESS, "Bridge3")
