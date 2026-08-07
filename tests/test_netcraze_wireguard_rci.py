"""Offline tests for sealed WireGuard RCI allowlist, wireguard_rci module, and operator CLI."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.allowlist import (
    body_sha256,
    build_sealed_parse_body,
    build_wireguard_nested_peer_body,
    is_wireguard_nested_peer_body,
    is_wireguard_parse_body,
    is_write_allowlisted,
    normalize_nested_peer_allow_ips,
    validate_asc_args,
    validate_wireguard_id,
)
from router_control.adapters.netcraze.wireguard_rci import (
    WireguardRciError,
    WireguardRciOperation,
    command_for,
    execute_wireguard_nested_peer_rci,
    nested_peer_body_for,
    sealed_nested_peer_request_for,
    sealed_request_for,
    verify_wireguard_nested_peer_response,
    verify_wireguard_response,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
WIREGUARD_CLI = REPO_ROOT / "scripts" / "wireguard-rci-op.py"

_ASC_9 = "5 42 54 0 0 1 2 3 4"
_ASC_16 = "5 42 54 0 0 1 2 3 4 0 0 0 0 0 0 0"
_REAL_ASC_9 = "4 10 50 130 69 149835824 1778159739 1704282148 748462068"
_ASC_SMALL_MAX = 99_999
_ASC_UINT32_MAX = 4_294_967_295
_PLACEHOLDER_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
_PLACEHOLDER_PEER = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
_PLACEHOLDER_PSK = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="


def _load_cli(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def wireguard_cli():
    return _load_cli(WIREGUARD_CLI, "wireguard_rci_op_cli")


def _ok_envelope(*, prompt: str = "(config)") -> list[dict[str, object]]:
    return [
        {
            "parse": {
                "prompt": prompt,
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


def _create_ok_envelope() -> list[dict[str, object]]:
    return [
        {
            "parse": {
                "prompt": "(config-if)",
                "status": [
                    {
                        "status": "message",
                        "code": "6553601",
                        "ident": "Network::Interface::Repository",
                        "message": '"Wireguard5" interface created.',
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
    "cli_command",
    [
        "interface Wireguard5",
        "interface Wireguard6",
        "interface Wireguard7",
        "interface Wireguard8",
        "interface Wireguard9",
        "no interface Wireguard5",
        "no interface Wireguard9",
        f"interface Wireguard5 wireguard asc {_ASC_9}",
        f"interface Wireguard9 wireguard asc {_ASC_16}",
    ],
)
def test_wireguard_allowlist_accepts_bounded_commands(cli_command: str) -> None:
    body = build_sealed_parse_body(cli_command)
    assert is_wireguard_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "cli_command",
    [
        f"interface Wireguard5 wireguard private-key {_PLACEHOLDER_KEY}",
        "interface Wireguard6 no wireguard private-key",
        f"interface Wireguard7 wireguard peer {_PLACEHOLDER_PEER}",
        (
            f"interface Wireguard7 wireguard peer {_PLACEHOLDER_PEER} "
            "endpoint vpn.example.com:51820"
        ),
        f"interface Wireguard8 wireguard peer {_PLACEHOLDER_PEER} allow-ips 10.0.0.0 24",
        (
            f"interface Wireguard8 wireguard peer {_PLACEHOLDER_PEER} "
            "allow-ips 10.99.99.2 255.255.255.255"
        ),
        f"interface Wireguard8 wireguard peer {_PLACEHOLDER_PEER} keepalive-interval 25",
        f"interface Wireguard5 no wireguard peer {_PLACEHOLDER_PEER}",
        f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER} preshared-key {_PLACEHOLDER_PSK}",
        f"interface Wireguard5 no wireguard peer {_PLACEHOLDER_PEER} preshared-key",
    ],
)
def test_wireguard_allowlist_accepts_secret_peer_commands(cli_command: str) -> None:
    body = build_sealed_parse_body(cli_command)
    assert is_wireguard_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "cli_command",
    [
        "interface Wireguard5 ip address 10.0.0.2 255.255.255.255",
        "interface Wireguard9 ip address 192.168.100.1 255.255.255.0",
        "interface Wireguard5 no ip address",
        "interface Wireguard5 ip global auto",
        "interface Wireguard5 ip global order 0",
        "interface Wireguard7 ip global order 65535",
        "interface Wireguard5 ip global 0",
        "interface Wireguard8 ip global 100",
        "interface Wireguard9 ip global 65535",
        "interface Wireguard5 no ip global",
        "interface Wireguard5 ip tcp adjust-mss pmtu",
        "interface Wireguard9 no ip tcp adjust-mss",
    ],
)
def test_wireguard_allowlist_accepts_ip_address_and_ip_global_commands(
    cli_command: str,
) -> None:
    body = build_sealed_parse_body(cli_command)
    assert is_wireguard_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "cli_command",
    [
        "interface Wireguard0 ip address 10.0.0.2 255.255.255.255",
        "interface Wireguard10 ip global 100",
        "interface Wireguard5 ip address 10.0.0.2",
        "interface Wireguard5 ip address 10.0.0.2 255.255.255.255 extra",
        "interface Wireguard5 ip address 999.999.999.999 255.255.255.0",
        "interface Wireguard5 ip address 10.0.0.2 255.255.255.1",
        "interface Wireguard5 ip address 10.0.0.2 24",
        "interface Wireguard5 ip address 10.0.0.2 255.255.255.255; reboot",
        "interface Wireguard5 ip global order 65536",
        "interface Wireguard5 ip global 99999",
        "interface Wireguard5 ip global order -1",
        "interface Wireguard5  ip address 10.0.0.2 255.255.255.255",
        "no interface Wireguard5 ip address 10.0.0.2 255.255.255.255",
        "interface Wireguard5 ip tcp adjust-mss 1280",
        "interface Wireguard5 ip tcp adjust-mss auto",
        "interface Wireguard5 ip tcp adjust-mss",
        "interface Wireguard5 ip tcp adjust-mss pmtu extra",
        "interface Wireguard10 ip tcp adjust-mss pmtu",
        "interface GigabitEthernet0 ip tcp adjust-mss pmtu",
        "no interface Wireguard5 ip tcp adjust-mss",
    ],
)
def test_wireguard_allowlist_rejects_invalid_ip_address_and_ip_global_commands(
    cli_command: str,
) -> None:
    body = build_sealed_parse_body(cli_command)
    assert not is_wireguard_parse_body(body)
    assert not is_write_allowlisted("POST", "/rci/", body)


def test_wireguard_allowlist_accepts_wg0_ip_global_auto_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    body = build_sealed_parse_body("interface Wireguard0 ip global auto")
    assert is_wireguard_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "cli_command",
    [
        "interface Wireguard0",
        "interface Wireguard1",
        "interface Wireguard2",
        "interface Wireguard3",
        "interface Wireguard4",
        "interface Wireguard10",
        "interface Wireguard99",
        "no interface Wireguard0",
        "no interface Wireguard4",
        "no interface Wireguard10",
        f"interface Wireguard0 wireguard asc {_ASC_9}",
        f"interface Wireguard4 wireguard asc {_ASC_9}",
        f"interface Wireguard10 wireguard asc {_ASC_9}",
        "interface GigabitEthernet0",
        "no interface Bridge0",
        "interface WifiMaster0/AccessPoint3",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4 5",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4 -1",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4 0x10",
        "interface Wireguard5 wireguard asc 5 42 54 0 0 1 2 3 4 abc",
        "interface Wireguard5 wireguard asc 123456 42 54 0 0 1 2 3 4",
        "interface Wireguard5 wireguard private-key secret",
        "interface Wireguard5 wireguard peer test",
        (
            f"interface Wireguard9 wireguard peer {_PLACEHOLDER_PEER} "
            f"endpoint 203.0.113.1:51820 allow-ips 192.168.1.0 24 keepalive-interval 60"
        ),
        "interface Wireguard5 wireguard preshared-key secret",
        "interface Wireguard5 wireguard endpoint 1.2.3.4:51820",
        "interface Wireguard5 wireguard allow-ips 0.0.0.0/0",
        "interface Wireguard5 wireguard keepalive 25",
        f"interface Wireguard5 wireguard asc {_ASC_9} extra",
        f"interface Wireguard5 wireguard asc {_ASC_9}; reboot",
        f"interface Wireguard5 wireguard asc {_ASC_9}\nreboot",
        f"interface Wireguard5 wireguard asc {_ASC_9}`inject",
        f'interface Wireguard5 wireguard asc {_ASC_9}"inject',
        "interface Wireguard5 extra",
        "show version",
    ],
)
def test_wireguard_allowlist_rejects_disallowed_commands_write_denied(
    cli_command: str,
) -> None:
    body = build_sealed_parse_body(cli_command)
    assert not is_wireguard_parse_body(body)
    assert not is_write_allowlisted("POST", "/rci/", body)


def test_wireguard_allowlist_rejects_empty_sealed_command() -> None:
    with pytest.raises(ValueError, match="empty sealed parse command"):
        build_sealed_parse_body("")


@pytest.mark.parametrize(
    "cli_command",
    [
        "interface Wireguard5 up",
        "interface Wireguard5 down",
        "interface Wireguard0 up",
    ],
)
def test_wireguard_allowlist_rejects_wg_template_only(cli_command: str) -> None:
    body = build_sealed_parse_body(cli_command)
    assert not is_wireguard_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    ("operation", "wg_id", "asc_args", "expected_cli"),
    [
        (
            WireguardRciOperation.CREATE_INTERFACE,
            "Wireguard5",
            None,
            "interface Wireguard5",
        ),
        (
            WireguardRciOperation.REMOVE_INTERFACE,
            "Wireguard6",
            None,
            "no interface Wireguard6",
        ),
        (
            WireguardRciOperation.SET_ASC,
            "Wireguard5",
            _ASC_9,
            f"interface Wireguard5 wireguard asc {_ASC_9}",
        ),
        (
            WireguardRciOperation.SET_ASC,
            "Wireguard9",
            _ASC_16,
            f"interface Wireguard9 wireguard asc {_ASC_16}",
        ),
        (
            WireguardRciOperation.SET_PRIVATE_KEY,
            "Wireguard5",
            None,
            f"interface Wireguard5 wireguard private-key {_PLACEHOLDER_KEY}",
        ),
        (
            WireguardRciOperation.CLEAR_PRIVATE_KEY,
            "Wireguard5",
            None,
            "interface Wireguard5 no wireguard private-key",
        ),
        (
            WireguardRciOperation.ADD_PEER,
            "Wireguard5",
            None,
            f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER}",
        ),
        (
            WireguardRciOperation.SET_PEER_ENDPOINT,
            "Wireguard5",
            None,
            (
                f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER} "
                "endpoint vpn.example.com:51820"
            ),
        ),
        (
            WireguardRciOperation.SET_PEER_ALLOW_IPS,
            "Wireguard5",
            None,
            f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER} allow-ips 10.0.0.0 24",
        ),
        (
            WireguardRciOperation.SET_PEER_KEEPALIVE,
            "Wireguard5",
            None,
            f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER} keepalive-interval 25",
        ),
        (
            WireguardRciOperation.REMOVE_PEER,
            "Wireguard5",
            None,
            f"interface Wireguard5 no wireguard peer {_PLACEHOLDER_PEER}",
        ),
        (
            WireguardRciOperation.SET_PRESHARED_KEY,
            "Wireguard5",
            None,
            (
                f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER} "
                f"preshared-key {_PLACEHOLDER_PSK}"
            ),
        ),
        (
            WireguardRciOperation.CLEAR_PRESHARED_KEY,
            "Wireguard5",
            None,
            f"interface Wireguard5 no wireguard peer {_PLACEHOLDER_PEER} preshared-key",
        ),
        (
            WireguardRciOperation.SET_TCP_MSS,
            "Wireguard5",
            None,
            "interface Wireguard5 ip tcp adjust-mss pmtu",
        ),
        (
            WireguardRciOperation.CLEAR_TCP_MSS,
            "Wireguard5",
            None,
            "interface Wireguard5 no ip tcp adjust-mss",
        ),
    ],
)
def test_command_for_all_operations(
    operation: WireguardRciOperation,
    wg_id: str,
    asc_args: str | None,
    expected_cli: str,
) -> None:
    kwargs: dict[str, object] = {}
    if operation is WireguardRciOperation.SET_PRIVATE_KEY:
        kwargs["secret"] = _PLACEHOLDER_KEY
    elif operation is WireguardRciOperation.ADD_PEER:
        kwargs["peer_public_key"] = _PLACEHOLDER_PEER
    elif operation is WireguardRciOperation.SET_PEER_ENDPOINT:
        kwargs["peer_public_key"] = _PLACEHOLDER_PEER
        kwargs["endpoint"] = "vpn.example.com:51820"
    elif operation is WireguardRciOperation.SET_PEER_ALLOW_IPS:
        kwargs["peer_public_key"] = _PLACEHOLDER_PEER
        kwargs["allow_ips"] = "10.0.0.0/24"
    elif operation is WireguardRciOperation.SET_PEER_KEEPALIVE:
        kwargs["peer_public_key"] = _PLACEHOLDER_PEER
        kwargs["keepalive_interval"] = 25
    elif operation in (
        WireguardRciOperation.REMOVE_PEER,
        WireguardRciOperation.SET_PRESHARED_KEY,
        WireguardRciOperation.CLEAR_PRESHARED_KEY,
    ):
        kwargs["peer_public_key"] = _PLACEHOLDER_PEER
        if operation is WireguardRciOperation.SET_PRESHARED_KEY:
            kwargs["secret"] = _PLACEHOLDER_PSK
    assert command_for(operation, wg_id, asc_args=asc_args, **kwargs) == expected_cli  # type: ignore[arg-type]


def test_builder_tcp_mss_commands_are_allowlisted() -> None:
    for operation in (WireguardRciOperation.SET_TCP_MSS, WireguardRciOperation.CLEAR_TCP_MSS):
        cli = command_for(operation, "Wireguard5")
        body = build_sealed_parse_body(cli)
        assert is_wireguard_parse_body(body)
        assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "wg_id",
    [
        "Wireguard0",
        "Wireguard1",
        "Wireguard2",
        "Wireguard3",
        "Wireguard4",
        "Wireguard10",
        "WireGuard5",
        "wireguard5",
        "GigabitEthernet0",
        "",
    ],
)
def test_validate_wireguard_id_rejects_disallowed(wg_id: str) -> None:
    with pytest.raises(ValueError):
        validate_wireguard_id(wg_id)


@pytest.mark.parametrize(
    "wg_id",
    [
        "Wireguard5",
        "Wireguard6",
        "Wireguard7",
        "Wireguard8",
        "Wireguard9",
        "  Wireguard5  ",
    ],
)
def test_validate_wireguard_id_accepts_test_interfaces(wg_id: str) -> None:
    normalized = validate_wireguard_id(wg_id)
    assert normalized.startswith("Wireguard")
    assert normalized[-1] in "56789"


@pytest.mark.parametrize(
    "wg_id",
    ["Wireguard0", "Wireguard1", "Wireguard2", "Wireguard3", "Wireguard4"],
)
def test_validate_wireguard_id_accepts_low_indices_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch, wg_id: str
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    assert validate_wireguard_id(wg_id) == wg_id


@pytest.mark.parametrize(
    "asc_args",
    [
        "",
        "5 42 54 0 0 1 2 3",
        "5 42 54 0 0 1 2 3 4 5",
        "5 42 54 0 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17",
        "5 42 54 0 0 1 2 3 4 -1",
        "5 42 54 0 0 1 2 3 4 0x10",
        "5 42 54 0 0 1 2 3 4 abc",
        "123456 42 54 0 0 1 2 3 4",
        f"{_ASC_SMALL_MAX + 1} 42 54 0 0 1 2 3 4",
        f"5 42 54 0 0 {_ASC_UINT32_MAX + 1} 2 3 4",
        "5 42 54 0 0 1 2 3 4 +10",
        "5  42 54 0 0 1 2 3 4",
        "5 42 54 0 0 1 2 3 ",
    ],
)
def test_validate_asc_args_rejects_disallowed(asc_args: str) -> None:
    with pytest.raises(ValueError):
        validate_asc_args(asc_args)


@pytest.mark.parametrize(
    "asc_args",
    [
        _ASC_9,
        _ASC_16,
        _REAL_ASC_9,
        f"  {_ASC_9}  ",
        "0 0 0 0 0 0 0 0 0",
        f"{_ASC_SMALL_MAX} 0 0 0 0 0 0 0 0",
        f"5 42 54 0 0 {_ASC_UINT32_MAX} {_ASC_UINT32_MAX} {_ASC_UINT32_MAX} {_ASC_UINT32_MAX}",
    ],
)
def test_validate_asc_args_accepts_bounded(asc_args: str) -> None:
    assert validate_asc_args(asc_args) == asc_args.strip()


def test_real_asc9_sealed_cli_allowlisted() -> None:
    request = sealed_request_for(
        WireguardRciOperation.SET_ASC,
        "Wireguard5",
        asc_args=_REAL_ASC_9,
    )
    assert is_write_allowlisted("POST", "/rci/", request.body)
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [
        {"parse": f"interface Wireguard5 wireguard asc {_REAL_ASC_9}"}
    ]


def test_sealed_request_for_body_matches_allowlist() -> None:
    request = sealed_request_for(
        WireguardRciOperation.SET_ASC,
        "Wireguard5",
        asc_args=_ASC_9,
    )
    assert is_write_allowlisted("POST", "/rci/", request.body)
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [{"parse": f"interface Wireguard5 wireguard asc {_ASC_9}"}]


def test_verify_wireguard_response_accepts_create_with_config_if_prompt() -> None:
    result = verify_wireguard_response(
        WireguardRciOperation.CREATE_INTERFACE,
        "Wireguard5",
        _create_ok_envelope(),
    )
    sanitized = result.sanitized_dict()
    assert sanitized["wg_id"] == "Wireguard5"
    assert sanitized["ack_matched"] is True
    assert sanitized["prompt"] == "(config-if)"
    for entry in sanitized.get("status", []):
        assert "message" not in entry


@pytest.mark.parametrize(
    ("operation", "asc_args"),
    [
        (WireguardRciOperation.REMOVE_INTERFACE, None),
        (WireguardRciOperation.SET_ASC, _ASC_9),
    ],
)
def test_verify_wireguard_response_accepts_config_prompt_for_asc_and_remove(
    operation: WireguardRciOperation,
    asc_args: str | None,
) -> None:
    result = verify_wireguard_response(
        operation,
        "Wireguard5",
        _ok_envelope(prompt="(config)"),
        asc_args=asc_args,
    )
    assert result.ack_matched is True
    assert result.prompt == "(config)"


def test_verify_wireguard_response_accepts_config_if_prompt_with_trailing_gt() -> None:
    result = verify_wireguard_response(
        WireguardRciOperation.CREATE_INTERFACE,
        "Wireguard5",
        _ok_envelope(prompt="(config-if)>"),
    )
    assert result.ack_matched is True
    assert result.prompt == "(config-if)"


def test_verify_wireguard_response_rejects_unrecognized_prompt_context() -> None:
    with pytest.raises(WireguardRciError, match="prompt missing or not allowlisted"):
        verify_wireguard_response(
            WireguardRciOperation.SET_ASC,
            "Wireguard5",
            _ok_envelope(prompt="(exec)"),
            asc_args=_ASC_9,
        )


def test_verify_wireguard_response_rejects_error_status() -> None:
    with pytest.raises(WireguardRciError, match="error status"):
        verify_wireguard_response(
            WireguardRciOperation.REMOVE_INTERFACE,
            "Wireguard5",
            _error_envelope(),
        )


def test_verify_wireguard_response_rejects_missing_prompt() -> None:
    response = [
        {
            "parse": {
                "status": [
                    {
                        "status": "message",
                        "code": "1",
                        "ident": "Core::Interface",
                        "message": "ok",
                    }
                ]
            }
        }
    ]
    with pytest.raises(WireguardRciError, match="prompt missing"):
        verify_wireguard_response(
            WireguardRciOperation.REMOVE_INTERFACE,
            "Wireguard5",
            response,
        )


def test_sanitized_dict_excludes_secret_material() -> None:
    result = verify_wireguard_response(
        WireguardRciOperation.SET_PRIVATE_KEY,
        "Wireguard5",
        _ok_envelope(),
    )
    sanitized = result.sanitized_dict()
    serialized = json.dumps(sanitized)
    assert _PLACEHOLDER_KEY not in serialized
    assert "private-key" not in serialized.lower()
    assert sanitized["operation"] == WireguardRciOperation.SET_PRIVATE_KEY.value


def test_add_peer_emits_bare_create_only() -> None:
    cli = command_for(
        WireguardRciOperation.ADD_PEER,
        "Wireguard5",
        peer_public_key=_PLACEHOLDER_PEER,
    )
    assert cli == f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER}"
    assert " endpoint " not in cli
    assert " allow-ips " not in cli
    assert " keepalive-interval " not in cli


def test_set_peer_allow_ips_accepts_dotted_mask() -> None:
    cli = command_for(
        WireguardRciOperation.SET_PEER_ALLOW_IPS,
        "Wireguard5",
        peer_public_key=_PLACEHOLDER_PEER,
        allow_ips="10.99.99.2 255.255.255.255",
    )
    assert cli == (
        f"interface Wireguard5 wireguard peer {_PLACEHOLDER_PEER} "
        "allow-ips 10.99.99.2 255.255.255.255"
    )
    body = build_sealed_parse_body(cli)
    assert is_wireguard_parse_body(body)


def test_sanitized_dict_includes_peer_non_secret_fields() -> None:
    result = verify_wireguard_response(
        WireguardRciOperation.SET_PEER_ENDPOINT,
        "Wireguard5",
        _ok_envelope(),
        peer_public_key=_PLACEHOLDER_PEER,
        endpoint="vpn.example.com:51820",
    )
    sanitized = result.sanitized_dict()
    assert sanitized["peer_public_key"] == _PLACEHOLDER_PEER
    assert sanitized["peer_endpoint"] == "vpn.example.com:51820"
    allow_ips_result = verify_wireguard_response(
        WireguardRciOperation.SET_PEER_ALLOW_IPS,
        "Wireguard5",
        _ok_envelope(),
        peer_public_key=_PLACEHOLDER_PEER,
        allow_ips="10.0.0.0/24",
    )
    allow_ips_sanitized = allow_ips_result.sanitized_dict()
    assert allow_ips_sanitized["peer_allow_ips"] == "10.0.0.0 24"
    keepalive_result = verify_wireguard_response(
        WireguardRciOperation.SET_PEER_KEEPALIVE,
        "Wireguard5",
        _ok_envelope(),
        peer_public_key=_PLACEHOLDER_PEER,
        keepalive_interval=25,
    )
    keepalive_sanitized = keepalive_result.sanitized_dict()
    assert keepalive_sanitized["peer_keepalive_interval"] == 25


def test_sanitized_dict_includes_asc_args_for_set_asc() -> None:
    result = verify_wireguard_response(
        WireguardRciOperation.SET_ASC,
        "Wireguard5",
        _ok_envelope(),
        asc_args=_ASC_9,
    )
    sanitized = result.sanitized_dict()
    assert sanitized["asc_args"] == _ASC_9
    for entry in sanitized.get("status", []):
        assert "message" not in entry


def _expected_digest(cli: str) -> str:
    return body_sha256(build_sealed_parse_body(cli))


def _transport_guard():
    return patch(
        "router_control.adapters.netcraze.rci_live.open_pinned_rci_transport",
        side_effect=AssertionError("open_pinned_rci_transport must not be called in validate mode"),
    )


@pytest.mark.parametrize(
    ("operation", "wg_id", "asc_args", "expected_cli"),
    [
        ("create-interface", "Wireguard5", None, "interface Wireguard5"),
        ("remove-interface", "Wireguard6", None, "no interface Wireguard6"),
        (
            "set-asc",
            "Wireguard5",
            _ASC_9,
            f"interface Wireguard5 wireguard asc {_ASC_9}",
        ),
    ],
)
def test_wireguard_cli_validate_mode_success(
    wireguard_cli,
    operation: str,
    wg_id: str,
    asc_args: str | None,
    expected_cli: str,
) -> None:
    argv = [
        "wireguard-rci-op.py",
        "--operation",
        operation,
        "--wg-id",
        wg_id,
    ]
    if operation == "set-asc":
        argv.extend(["--asc-args", asc_args or ""])
    stdout = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert wireguard_cli.main() == 0
    plan = json.loads(stdout.getvalue())
    expected_plan: dict[str, object] = {
        "mode": "validate",
        "operation": operation,
        "wg_id": wg_id.strip(),
        "cli": expected_cli,
        "body_sha256": _expected_digest(expected_cli),
        "write_allowlisted": True,
        "bytes": len(build_sealed_parse_body(expected_cli)),
    }
    if operation == "set-asc":
        expected_plan["asc_args"] = asc_args
    assert plan == expected_plan


@pytest.mark.parametrize(
    ("argv_suffix", "expected_fragment"),
    [
        (["--operation", "create-interface", "--wg-id", "Wireguard0"], "invalid wg id"),
        (["--operation", "set-asc", "--wg-id", "Wireguard5"], "invalid asc args"),
        (
            [
                "--operation",
                "set-asc",
                "--wg-id",
                "Wireguard5",
                "--asc-args",
                "bad args",
            ],
            "invalid asc args",
        ),
    ],
)
def test_wireguard_cli_validate_mode_invalid_inputs(
    wireguard_cli,
    argv_suffix: list[str],
    expected_fragment: str,
) -> None:
    argv = ["wireguard-rci-op.py", *argv_suffix]
    stderr = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert wireguard_cli.main() == 1
    assert expected_fragment in stderr.getvalue()


def test_wireguard_cli_has_execute_flag(wireguard_cli) -> None:
    parser = wireguard_cli._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    assert "execute" in actions
    assert "operation" in actions
    assert "wg_id" in actions


def test_wireguard_cli_execute_rejects_non_allowlisted_before_io(wireguard_cli) -> None:
    argv = [
        "wireguard-rci-op.py",
        "--execute",
        "--operation",
        "create-interface",
        "--wg-id",
        "Wireguard5",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_test",
        "--username",
        "lab-user",
        "--ssh-host-key-sha256",
        "SHA256:abc123",
    ]
    stderr = StringIO()
    fake_vault = MagicMock()
    with patch.object(sys, "platform", "win32"):
        with patch(
            "router_control.adapters.netcraze.allowlist.is_write_allowlisted",
            return_value=False,
        ):
            with patch(
                "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
                return_value=fake_vault,
            ):
                with _transport_guard():
                    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
                        assert wireguard_cli.main() == 3
    assert "sealed body is not write-allowlisted" in stderr.getvalue()
    fake_vault.use.assert_not_called()


def test_nested_peer_body_serialization_and_allowlist() -> None:
    body = nested_peer_body_for(
        "Wireguard5",
        _PLACEHOLDER_PEER,
        endpoint="vpn.example.com:51820",
        allow_ips="10.0.0.0/24",
        keepalive_interval=25,
        preshared_key=_PLACEHOLDER_PSK,
    )
    assert is_wireguard_nested_peer_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)
    payload = json.loads(body.decode("utf-8"))
    peer_obj = payload["interface"]["Wireguard5"]["wireguard"]["peer"][0]
    assert peer_obj["key"] == _PLACEHOLDER_PEER
    assert peer_obj["endpoint"] == {"address": "vpn.example.com:51820"}
    assert peer_obj["allow-ips"] == [{"address": "10.0.0.0", "mask": "255.255.255.0"}]
    assert peer_obj["keepalive-interval"] == {"interval": 25}
    assert peer_obj["preshared-key"] == _PLACEHOLDER_PSK
    assert "parse" not in payload


def test_nested_peer_body_supports_multiple_allow_ips() -> None:
    body = build_wireguard_nested_peer_body(
        "Wireguard5",
        _PLACEHOLDER_PEER,
        allow_ips="10.0.0.0/24,192.168.1.0/32",
    )
    assert is_wireguard_nested_peer_body(body)
    peer_obj = json.loads(body.decode("utf-8"))["interface"]["Wireguard5"]["wireguard"][
        "peer"
    ][0]
    assert peer_obj["allow-ips"] == [
        {"address": "10.0.0.0", "mask": "255.255.255.0"},
        {"address": "192.168.1.0", "mask": "255.255.255.255"},
    ]


def test_nested_peer_body_rejects_old_pubkey_keyed_shape() -> None:
    old_shape = {
        "interface": {
            "Wireguard5": {
                "wireguard": {
                    "peer": {
                        _PLACEHOLDER_PEER: {
                            "endpoint": "vpn.example.com:51820",
                            "allow-ips": "10.0.0.0 24",
                        }
                    }
                }
            }
        }
    }
    body = json.dumps(old_shape, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert not is_wireguard_nested_peer_body(body)
    assert not is_write_allowlisted("POST", "/rci/", body)


def test_nested_peer_body_rejects_unknown_top_level_keys() -> None:
    body = build_wireguard_nested_peer_body(
        "Wireguard5",
        _PLACEHOLDER_PEER,
        endpoint="vpn.example.com:51820",
    )
    payload = json.loads(body.decode("utf-8"))
    payload["extra"] = "inject"
    tampered = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert not is_wireguard_nested_peer_body(tampered)
    assert not is_write_allowlisted("POST", "/rci/", tampered)


@pytest.mark.parametrize(
    "tamper",
    [
        {"interface": {"Wireguard4": {"wireguard": {"peer": [{"key": _PLACEHOLDER_PEER}]}}}},
        {"interface": {"Wireguard5": {"wireguard": {"peer": [{"key": "bad"}]}}}},
        {
            "interface": {
                "Wireguard5": {
                    "wireguard": {
                        "peer": [
                            {
                                "key": _PLACEHOLDER_PEER,
                                "endpoint": {"address": "vpn.example.com:51820"},
                                "unknown": True,
                            }
                        ]
                    }
                }
            }
        },
        {
            "interface": {
                "Wireguard5": {
                    "wireguard": {
                        "peer": [
                            {
                                "key": _PLACEHOLDER_PEER,
                                "keepalive-interval": {"interval": "25"},
                            }
                        ]
                    }
                }
            }
        },
        {
            "interface": {
                "Wireguard5": {
                    "wireguard": {
                        "peer": [
                            {
                                "key": _PLACEHOLDER_PEER,
                                "allow-ips": [{"address": "10.0.0.0", "mask": "24"}],
                            }
                        ]
                    }
                }
            }
        },
    ],
)
def test_nested_peer_allowlist_rejects_invalid_shapes(tamper: dict[str, object]) -> None:
    body = json.dumps(tamper, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert not is_wireguard_nested_peer_body(body)
    assert not is_write_allowlisted("POST", "/rci/", body)


def test_sealed_nested_peer_request_matches_allowlist() -> None:
    request = sealed_nested_peer_request_for(
        "Wireguard6",
        _PLACEHOLDER_PEER,
        endpoint="vpn.example.com:51820",
    )
    assert is_write_allowlisted("POST", "/rci/", request.body)


def test_verify_wireguard_nested_peer_response_accepts_ok_envelope() -> None:
    result = verify_wireguard_nested_peer_response(
        "Wireguard5",
        _ok_envelope(),
        peer_public_key=_PLACEHOLDER_PEER,
        endpoint="vpn.example.com:51820",
    )
    sanitized = result.sanitized_dict()
    assert sanitized["operation"] == WireguardRciOperation.UPSERT_PEER_NESTED.value
    assert sanitized["peer_public_key"] == _PLACEHOLDER_PEER
    assert sanitized["peer_endpoint"] == "vpn.example.com:51820"
    assert sanitized["prompt"] == "(config)"
    assert _PLACEHOLDER_PSK not in json.dumps(sanitized)


def _nested_status_only_envelope() -> list[dict[str, object]]:
    return [
        {
            "interface": {
                "Wireguard5": {
                    "wireguard": {
                        "peer": [
                            {
                                "status": [
                                    {
                                        "status": "message",
                                        "code": "1",
                                        "ident": "Core::Interface",
                                        "message": "ok",
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
    ]


def test_verify_wireguard_nested_peer_response_accepts_status_without_prompt() -> None:
    result = verify_wireguard_nested_peer_response(
        "Wireguard5",
        _nested_status_only_envelope(),
        peer_public_key=_PLACEHOLDER_PEER,
    )
    sanitized = result.sanitized_dict()
    assert sanitized["ack_matched"] is True
    assert sanitized["prompt"] == ""
    assert sanitized["status"]


def test_verify_wireguard_nested_peer_response_rejects_error_status() -> None:
    response = [
        {
            "interface": {
                "Wireguard5": {
                    "wireguard": {
                        "peer": [
                            {
                                "status": [
                                    {
                                        "status": "error",
                                        "code": "1",
                                        "ident": "x",
                                        "message": "failed",
                                    }
                                ]
                            }
                        ]
                    }
                }
            }
        }
    ]
    with pytest.raises(WireguardRciError, match="error status"):
        verify_wireguard_nested_peer_response(
            "Wireguard5",
            response,
            peer_public_key=_PLACEHOLDER_PEER,
        )


def test_normalize_nested_peer_allow_ips_multi_entry() -> None:
    normalized = normalize_nested_peer_allow_ips("10.0.0.0/24,192.168.1.0/32")
    assert normalized == "10.0.0.0 255.255.255.0,192.168.1.0 255.255.255.255"


def test_verify_wireguard_nested_peer_response_accepts_multi_allow_ips() -> None:
    allow_ips = "10.0.0.0/24,192.168.1.0/32"
    result = verify_wireguard_nested_peer_response(
        "Wireguard5",
        _ok_envelope(),
        peer_public_key=_PLACEHOLDER_PEER,
        allow_ips=allow_ips,
    )
    sanitized = result.sanitized_dict()
    assert sanitized["peer_allow_ips"] == (
        "10.0.0.0 255.255.255.0,192.168.1.0 255.255.255.255"
    )
    assert sanitized["ack_matched"] is True


class _NestedPeerFakeTransport:
    def __init__(self) -> None:
        self.last_body: bytes | None = None

    def execute_sealed_rci_write(self, request: Any) -> list[dict[str, object]]:
        self.last_body = request.body
        return _ok_envelope()


def test_execute_wireguard_nested_peer_rci_multi_allow_ips() -> None:
    allow_ips = "10.0.0.0/24,192.168.1.0/32"
    transport = _NestedPeerFakeTransport()
    result = execute_wireguard_nested_peer_rci(
        transport,
        "Wireguard5",
        _PLACEHOLDER_PEER,
        allow_ips=allow_ips,
    )
    assert transport.last_body is not None
    peer_obj = json.loads(transport.last_body.decode("utf-8"))["interface"]["Wireguard5"][
        "wireguard"
    ]["peer"][0]
    assert len(peer_obj["allow-ips"]) == 2
    sanitized = result.sanitized_dict()
    assert sanitized["peer_allow_ips"] == (
        "10.0.0.0 255.255.255.0,192.168.1.0 255.255.255.255"
    )
    assert sanitized["operation"] == WireguardRciOperation.UPSERT_PEER_NESTED.value
