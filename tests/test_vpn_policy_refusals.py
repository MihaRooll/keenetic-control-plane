"""VPN policy-routing refusal tests (AC-D1)."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.allowlist import (
    SHOW_IP_NAME_SERVER,
    SHOW_IP_POLICY,
    is_vpn_policy_read_allowlisted,
    refuse_rejected_vpn_policy_show_command,
    validate_vpn_policy_read_command,
)
from router_control.adapters.netcraze.vpn_policy_rci import refuse_ip_policy_permit_global


@pytest.mark.parametrize(
    "command",
    [
        "show rc ip policy",
        "show ip name-servers",
        "show name-server",
        "show hotspot",
    ],
)
def test_rejected_show_commands_raise_with_command_name(command: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        refuse_rejected_vpn_policy_show_command(command)
    message = str(exc_info.value)
    assert command in message
    assert "rejected" in message
    assert "not allowlisted" in message
    assert ":230-233" in message


@pytest.mark.parametrize(
    "command",
    [
        "show rc ip policy",
        "show ip name-servers",
        "show name-server",
        "show hotspot",
    ],
)
def test_validate_read_command_refuses_rejected_shows(command: str) -> None:
    with pytest.raises(ValueError) as exc_info:
        validate_vpn_policy_read_command(command)
    assert command in str(exc_info.value)


def test_allowlisted_show_commands_map_to_read_commands() -> None:
    assert validate_vpn_policy_read_command("show ip policy") is SHOW_IP_POLICY
    assert validate_vpn_policy_read_command("show ip name-server") is SHOW_IP_NAME_SERVER
    assert is_vpn_policy_read_allowlisted("GET", "/rci/show/ip/policy") is True
    assert is_vpn_policy_read_allowlisted("GET", "/rci/show/ip/name-server") is True
    assert is_vpn_policy_read_allowlisted("GET", "/rci/show/rc/ip/policy") is False


def test_permit_global_refusal_message() -> None:
    with pytest.raises(ValueError) as exc_info:
        refuse_ip_policy_permit_global()
    message = str(exc_info.value)
    assert "no such command: global" in message
    assert "unresolved" in message
    assert "permit global" in message
