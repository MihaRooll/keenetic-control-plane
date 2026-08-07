"""Read-only parsers for VPN connection-policy show commands (help-verified samples only)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    SHOW_IP_NAME_SERVER,
    SHOW_IP_POLICY,
    ReadCommand,
    refuse_rejected_vpn_policy_show_command,
    validate_vpn_policy_read_command,
)
from router_control.adapters.netcraze.sanitize import strip_ssh_cli_ansi_artifacts

PARSER_VERSION_POLICY = "vpn-policy-v1"
PARSER_VERSION_NAME_SERVER = "vpn-name-server-v1"
_EMPTY_NAME_SERVER_TEXT = "Server list is empty."


class VpnPolicyParseStatus(StrEnum):
    ZERO_POLICIES = "zero_policies"
    EMPTY = "empty"
    UNKNOWN = "unknown"
    UNPARSED = "unparsed"


@dataclass(frozen=True, slots=True)
class VpnPolicyShowParseResult:
    parser_version: str
    parse_status: VpnPolicyParseStatus
    command: str
    policy_count: int | None = None
    name_servers: tuple[str, ...] = ()


def _normalize_raw(raw: str | bytes) -> str:
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
    return strip_ssh_cli_ansi_artifacts(text.strip())


def resolve_vpn_policy_read_command(command: str) -> ReadCommand:
    """Map CLI show command to allowlisted ReadCommand or refuse rejected forms."""
    refuse_rejected_vpn_policy_show_command(command)
    return validate_vpn_policy_read_command(command)


def parse_show_ip_policy(raw: str | bytes) -> dict[str, Any]:
    """Parse ``show ip policy`` output; empty sample → zero_policies; else unknown."""
    text = _normalize_raw(raw)
    if not text:
        return {
            "parser_version": PARSER_VERSION_POLICY,
            "parse_status": VpnPolicyParseStatus.ZERO_POLICIES.value,
            "command": SHOW_IP_POLICY.name,
            "policy_count": 0,
        }
    return {
        "parser_version": PARSER_VERSION_POLICY,
        "parse_status": VpnPolicyParseStatus.UNKNOWN.value,
        "command": SHOW_IP_POLICY.name,
        "policy_count": None,
        "notes": (
            "non-empty show ip policy output has no sealed sample beyond empty "
            "(OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md:85)",
        ),
    }


def parse_show_ip_name_server(raw: str | bytes) -> dict[str, Any]:
    """Parse ``show ip name-server``; documented empty string → empty list."""
    text = _normalize_raw(raw)
    if text == _EMPTY_NAME_SERVER_TEXT:
        return {
            "parser_version": PARSER_VERSION_NAME_SERVER,
            "parse_status": VpnPolicyParseStatus.EMPTY.value,
            "command": SHOW_IP_NAME_SERVER.name,
            "name_servers": [],
        }
    if not text:
        return {
            "parser_version": PARSER_VERSION_NAME_SERVER,
            "parse_status": VpnPolicyParseStatus.UNKNOWN.value,
            "command": SHOW_IP_NAME_SERVER.name,
            "name_servers": None,
        }
    return {
        "parser_version": PARSER_VERSION_NAME_SERVER,
        "parse_status": VpnPolicyParseStatus.UNPARSED.value,
        "command": SHOW_IP_NAME_SERVER.name,
        "name_servers": None,
        "notes": (
            "unrecognized show ip name-server shape; only empty sample sealed "
            "(OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md:115)",
        ),
    }


__all__ = [
    "PARSER_VERSION_NAME_SERVER",
    "PARSER_VERSION_POLICY",
    "VpnPolicyParseStatus",
    "VpnPolicyShowParseResult",
    "parse_show_ip_name_server",
    "parse_show_ip_policy",
    "resolve_vpn_policy_read_command",
]
