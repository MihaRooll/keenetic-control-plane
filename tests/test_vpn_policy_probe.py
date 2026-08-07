"""VPN policy-routing probe parser tests (AC-D2)."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.sanitize import strip_ssh_cli_ansi_artifacts
from router_control.adapters.netcraze.vpn_policy_probe import (
    PARSER_VERSION_NAME_SERVER,
    PARSER_VERSION_POLICY,
    parse_show_ip_name_server,
    parse_show_ip_policy,
)


def test_parse_empty_policy_returns_zero_policies() -> None:
    result = parse_show_ip_policy("")
    assert result["parser_version"] == PARSER_VERSION_POLICY
    assert result["parse_status"] == "zero_policies"
    assert result["policy_count"] == 0


def test_parse_whitespace_policy_returns_zero_policies() -> None:
    result = parse_show_ip_policy("   \n  ")
    assert result["parse_status"] == "zero_policies"
    assert result["policy_count"] == 0


def test_parse_non_empty_policy_unknown() -> None:
    result = parse_show_ip_policy("Policy vpn1: interface Wireguard0")
    assert result["parser_version"] == PARSER_VERSION_POLICY
    assert result["parse_status"] == "unknown"
    assert result["policy_count"] is None


def test_parse_name_server_empty_string() -> None:
    result = parse_show_ip_name_server("Server list is empty.")
    assert result["parser_version"] == PARSER_VERSION_NAME_SERVER
    assert result["parse_status"] == "empty"
    assert result["name_servers"] == []


def test_parse_name_server_unrecognized_shape() -> None:
    result = parse_show_ip_name_server("1.1.1.1 on GigabitEthernet1")
    assert result["parse_status"] == "unparsed"
    assert result["name_servers"] is None


def test_parse_name_server_blank_unknown() -> None:
    result = parse_show_ip_name_server("")
    assert result["parse_status"] == "unknown"


def test_parse_policy_ansi_erase_suffix_zero_policies() -> None:
    result = parse_show_ip_policy("\x1b[K")
    assert result["parse_status"] == "zero_policies"
    assert result["policy_count"] == 0


def test_parse_name_server_empty_with_ansi_erase_suffix() -> None:
    result = parse_show_ip_name_server("Server list is empty.\x1b[K")
    assert result["parse_status"] == "empty"
    assert result["name_servers"] == []


def test_parse_name_server_mid_string_ansi_forgery_unparsed() -> None:
    """Mid-string \\x1b[K must not assemble a forged empty-list phrase."""
    result = parse_show_ip_name_server("Server list is empt\x1b[Ky.")
    assert result["parse_status"] == "unparsed"
    assert result["name_servers"] is None


def test_parse_policy_ansi_non_empty_still_unknown() -> None:
    result = parse_show_ip_policy("Policy vpn1: interface Wireguard0\x1b[K")
    assert result["parse_status"] == "unknown"
    assert result["policy_count"] is None


@pytest.mark.parametrize(
    ("raw", "expected_status"),
    [
        ("Server list is empty.\x1b[K\x1b[K", "empty"),
        ("a\x1b[K\r\nb\x1b[K\r\n", "unparsed"),
        ("Server list is empty.\x1b[K\r", "empty"),
        ("Server list is empty.", "empty"),
        ("", "unknown"),
        ("   ", "unknown"),
        ("Server list is empty.\x1b[K\x1b[K\x1b[K", "empty"),
    ],
)
def test_parse_name_server_ansi_and_line_endings(raw: str, expected_status: str) -> None:
    result = parse_show_ip_name_server(raw)
    assert result["parse_status"] == expected_status
    if expected_status == "empty":
        assert result["name_servers"] == []


@pytest.mark.parametrize(
    ("raw", "expected_text"),
    [
        ("Server list is empty.\x1b[K\x1b[K", "Server list is empty."),
        ("a\x1b[K\r\nb\x1b[K\r\n", "a\nb\n"),
        ("line\x1b[K\r", "line"),
        ("trailing\x1b[K", "trailing"),
        ("", ""),
        ("   ", "   "),
        ("\x1b[Kprefix", "\x1b[Kprefix"),
        ("a\x1b[K\x1b[K\x1b[K", "a"),
    ],
)
def test_strip_ssh_cli_ansi_artifacts_line_suffixes(raw: str, expected_text: str) -> None:
    assert strip_ssh_cli_ansi_artifacts(raw) == expected_text


def test_strip_ssh_cli_ansi_mid_string_r_forgery_preserved() -> None:
    """Lone \\r without \\n must not split lines for ANSI stripping."""
    raw = "Server list is empt\x1b[K\ry."
    assert strip_ssh_cli_ansi_artifacts(raw) == raw
    result = parse_show_ip_name_server(raw)
    assert result["parse_status"] == "unparsed"
