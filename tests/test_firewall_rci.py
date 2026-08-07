"""Offline tests for sealed firewall RCI module."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.firewall_rci import (
    FirewallRciError,
    FirewallRciOperation,
    command_for,
    sealed_request_for,
    validate_action,
    validate_destination_family,
    validate_ordinal,
    validate_zone_id,
    verify_firewall_response,
)
from router_control.adapters.netcraze.rci_validation import RciValidationError


def _ok_envelope() -> list[dict[str, object]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "1",
                        "ident": "Core::Firewall",
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
                        "ident": "Core::Firewall",
                        "message": "failed",
                    }
                ],
            }
        }
    ]


@pytest.mark.parametrize(
    ("operation", "zone_id", "kwargs", "expected_cli"),
    [
        (
            FirewallRciOperation.ADD_RULE,
            "Guest",
            {"action": "Allow", "destination_family": "OrderPage", "ordinal": 10},
            "ip access-list Guest 10 Allow OrderPage",
        ),
        (
            FirewallRciOperation.REMOVE_RULE,
            "Guest",
            {"ordinal": 10},
            "no ip access-list Guest 10",
        ),
    ],
)
def test_command_for_allowlisted_cli(
    operation: FirewallRciOperation,
    zone_id: str,
    kwargs: dict[str, object],
    expected_cli: str,
) -> None:
    assert command_for(operation, zone_id, **kwargs) == expected_cli


def test_validate_zone_id_rejects_empty() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_zone_id("")
    assert exc_info.value.field == "zone_id"


@pytest.mark.parametrize("action", ["Allow", "Deny"])
def test_validate_action_accepts_domain_enum(action: str) -> None:
    assert validate_action(action) == action


def test_validate_action_rejects_unknown() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_action("Drop")
    assert exc_info.value.field == "action"


@pytest.mark.parametrize(
    "family",
    ["OrderPage", "Dns", "Dhcp", "Management", "Internet", "LocalZone"],
)
def test_validate_destination_family_accepts_domain_enum(family: str) -> None:
    assert validate_destination_family(family) == family


def test_validate_destination_family_rejects_unknown() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_destination_family("Unknown")
    assert exc_info.value.field == "destination_family"


@pytest.mark.parametrize("ordinal", [-1, "10"])
def test_validate_ordinal_rejects_invalid(ordinal: object) -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_ordinal(ordinal)  # type: ignore[arg-type]
    assert exc_info.value.field == "ordinal"


def test_sealed_request_for_shape() -> None:
    request = sealed_request_for(
        FirewallRciOperation.ADD_RULE,
        "Guest",
        action="Allow",
        destination_family="Dns",
        ordinal=5,
    )
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [{"parse": "ip access-list Guest 5 Allow Dns"}]
    assert request.body == build_sealed_parse_body("ip access-list Guest 5 Allow Dns")


def test_verify_firewall_response_accepts_good_ack() -> None:
    result = verify_firewall_response(
        FirewallRciOperation.ADD_RULE,
        "Guest",
        _ok_envelope(),
        action="Allow",
        destination_family="OrderPage",
        ordinal=10,
    )
    sanitized = result.sanitized_dict()
    assert sanitized["zone_id"] == "Guest"
    assert sanitized["ack_matched"] is True


def test_verify_firewall_response_rejects_error_status() -> None:
    with pytest.raises(FirewallRciError, match="error status"):
        verify_firewall_response(
            FirewallRciOperation.REMOVE_RULE,
            "Guest",
            _error_envelope(),
            ordinal=10,
        )


def test_verify_firewall_response_rejects_missing_status() -> None:
    with pytest.raises(FirewallRciError, match="no RCI parse status"):
        verify_firewall_response(
            FirewallRciOperation.REMOVE_RULE,
            "Guest",
            [{"parse": {"prompt": "(config)"}}],
            ordinal=10,
        )


def test_command_for_add_rule_requires_all_fields() -> None:
    with pytest.raises(FirewallRciError, match="action, destination_family, and ordinal"):
        command_for(FirewallRciOperation.ADD_RULE, "Guest")
