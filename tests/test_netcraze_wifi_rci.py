"""Offline tests for sealed Wi-Fi AP RCI allowlist, wifi_rci module, and operator CLI."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.adapters.netcraze.allowlist import (
    body_sha256,
    build_sealed_parse_body,
    is_wifi_ap_parse_body,
    is_write_allowlisted,
    validate_ssid,
    validate_wifi_ap_id,
    validate_wpa_psk,
)
from router_control.adapters.netcraze.wifi_rci import (
    WifiApRciError,
    WifiApRciOperation,
    command_for,
    sealed_request_for,
    verify_wifi_ap_response,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
WIFI_CLI = REPO_ROOT / "scripts" / "wifi-rci-op.py"
_OFFLINE_PSK_PLACEHOLDER = "Testpass123456"


def _load_cli(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def wifi_cli():
    return _load_cli(WIFI_CLI, "wifi_rci_op_cli")


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
    "cli_command",
    [
        "interface WifiMaster0/AccessPoint3 up",
        "interface WifiMaster0/AccessPoint3 down",
        "interface WifiMaster0/AccessPoint3 no ssid",
        "interface WifiMaster0/AccessPoint3 ssid RC-TEST-1",
        "interface WifiMaster1/AccessPoint4 up",
        "interface WifiMaster1/AccessPoint5 down",
        "interface WifiMaster1/AccessPoint6 no ssid",
        "interface WifiMaster1/AccessPoint3 ssid x.y-z_0",
        f"interface WifiMaster0/AccessPoint3 authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}",
        "interface WifiMaster0/AccessPoint3 no authentication wpa-psk",
        "interface WifiMaster0/AccessPoint3 encryption enable",
        "interface WifiMaster0/AccessPoint3 no encryption enable",
        "interface WifiMaster0/AccessPoint3 encryption wpa2",
        "interface WifiMaster0/AccessPoint3 no encryption wpa2",
        f"interface WifiMaster1/AccessPoint4 authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}",
        "interface WifiMaster1/AccessPoint5 no authentication wpa-psk",
        "interface WifiMaster1/AccessPoint6 encryption enable",
        "interface WifiMaster0/AccessPoint3 encryption wpa3",
        "interface WifiMaster0/AccessPoint3 no encryption wpa3",
        "interface WifiMaster1/AccessPoint6 encryption wpa3",
    ],
)
def test_wifi_ap_allowlist_accepts_bounded_commands(cli_command: str) -> None:
    body = build_sealed_parse_body(cli_command)
    assert is_wifi_ap_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "cli_command",
    [
        "interface WifiMaster0/AccessPoint0 up",
        "interface WifiMaster0/AccessPoint1 down",
        "interface WifiMaster0/AccessPoint2 no ssid",
        "interface WifiMaster1/AccessPoint2 ssid RC-TEST-1",
        "interface GigabitEthernet0 up",
        "interface Bridge0 down",
        "interface WifiMaster0/AccessPoint3 delete",
        "interface WifiMaster0/AccessPoint3 reboot",
        "interface WifiMaster0/AccessPoint3 security-level wpa2",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk",
        "interface WifiMaster0/AccessPoint3 encryption aes",
        "interface WifiMaster0/AccessPoint3 wpa-psk secret",
        "interface WifiMaster0/AccessPoint3 ssid has space",
        "interface WifiMaster0/AccessPoint3 ssid quote\"bad",
        "interface WifiMaster0/AccessPoint3 ssid semi;colon",
        "interface WifiMaster0/AccessPoint3 ssid newline\nbad",
        "interface WifiMaster0/AccessPoint3 ssid back`tick",
        "interface WifiMaster0/AccessPoint3 ssid dollar$bad",
        "interface WifiMaster0/AccessPoint3 ssid "
        + ("A" * 33),
        "interface WifiMaster0/AccessPoint3 up extra",
        "",
        "interface WifiMaster2/AccessPoint3 up",
        "interface WifiMaster0/AccessPoint3",
        "show version",
        f"interface WifiMaster0/AccessPoint0 authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}",
        f"interface WifiMaster0/AccessPoint1 authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}",
        f"interface WifiMaster0/AccessPoint2 authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}",
        "interface WifiMaster0/AccessPoint0 no authentication wpa-psk",
        "interface WifiMaster0/AccessPoint1 encryption enable",
        "interface WifiMaster0/AccessPoint2 encryption wpa2",
        "interface WifiMaster0/AccessPoint0 no encryption wpa2",
        "interface WifiMaster0/AccessPoint1 no encryption wpa2",
        "interface WifiMaster0/AccessPoint2 no encryption wpa2",
        "interface GigabitEthernet0 no encryption wpa2",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk short",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk "
        + ("A" * 64),
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk has space",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk quote\"bad",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk semi;colon",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk back`tick",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk dollar$bad",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk back\\slash",
        "interface WifiMaster0/AccessPoint3 authentication wpa-psk newline\nbad",
        "interface WifiMaster0/AccessPoint3 encryption enable extra",
        "interface WifiMaster0/AccessPoint3 no authentication wpa-psk extra",
        "interface WifiMaster0/AccessPoint3 no encryption wpa2 extra",
        "interface WifiMaster0/AccessPoint3 authentication sae",
        "interface WifiMaster0/AccessPoint3 authentication sae short",
        "interface WifiMaster0/AccessPoint3 authentication sae "
        + ("A" * 64),
        "interface WifiMaster0/AccessPoint3 authentication sae has space",
        f"interface WifiMaster0/AccessPoint0 authentication sae {_OFFLINE_PSK_PLACEHOLDER}",
        f"interface WifiMaster0/AccessPoint1 authentication sae {_OFFLINE_PSK_PLACEHOLDER}",
        f"interface WifiMaster0/AccessPoint2 authentication sae {_OFFLINE_PSK_PLACEHOLDER}",
        "interface WifiMaster0/AccessPoint0 no authentication sae",
        "interface WifiMaster0/AccessPoint1 encryption wpa3",
        "interface WifiMaster0/AccessPoint2 no encryption wpa3",
        "interface WifiMaster0/AccessPoint3 encryption wpa3 extra",
        "interface WifiMaster0/AccessPoint7 up",
        "interface WifiMaster0/AccessPoint8 ssid AP8-TEST",
        "interface WifiMaster1/AccessPoint9 down",
        "interface WifiMaster0/AccessPoint7 no encryption wpa2",
    ],
)
def test_wifi_ap_allowlist_rejects_disallowed_commands(cli_command: str) -> None:
    if not cli_command:
        with pytest.raises(ValueError, match="empty sealed parse command"):
            build_sealed_parse_body("")
        return
    body = build_sealed_parse_body(cli_command)
    assert not is_wifi_ap_parse_body(body)


@pytest.mark.parametrize(
    ("operation", "ap_id", "ssid", "psk", "expected_cli"),
    [
        (
            WifiApRciOperation.SET_SSID,
            "WifiMaster0/AccessPoint3",
            "RC-TEST-1",
            None,
            "interface WifiMaster0/AccessPoint3 ssid RC-TEST-1",
        ),
        (
            WifiApRciOperation.CLEAR_SSID,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 no ssid",
        ),
        (
            WifiApRciOperation.UP,
            "WifiMaster1/AccessPoint4",
            None,
            None,
            "interface WifiMaster1/AccessPoint4 up",
        ),
        (
            WifiApRciOperation.DOWN,
            "WifiMaster1/AccessPoint6",
            None,
            None,
            "interface WifiMaster1/AccessPoint6 down",
        ),
        (
            WifiApRciOperation.SET_WPA_PSK,
            "WifiMaster0/AccessPoint3",
            None,
            _OFFLINE_PSK_PLACEHOLDER,
            f"interface WifiMaster0/AccessPoint3 authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}",
        ),
        (
            WifiApRciOperation.CLEAR_WPA_PSK,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 no authentication wpa-psk",
        ),
        (
            WifiApRciOperation.ENCRYPTION_ENABLE,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 encryption enable",
        ),
        (
            WifiApRciOperation.ENCRYPTION_DISABLE,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 no encryption enable",
        ),
        (
            WifiApRciOperation.ENCRYPTION_WPA2,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 encryption wpa2",
        ),
        (
            WifiApRciOperation.ENCRYPTION_WPA2_CLEAR,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 no encryption wpa2",
        ),
        (
            WifiApRciOperation.ENCRYPTION_WPA3,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 encryption wpa3",
        ),
        (
            WifiApRciOperation.ENCRYPTION_WPA3_CLEAR,
            "WifiMaster0/AccessPoint3",
            None,
            None,
            "interface WifiMaster0/AccessPoint3 no encryption wpa3",
        ),
    ],
)
def test_command_for_all_operations(
    operation: WifiApRciOperation,
    ap_id: str,
    ssid: str | None,
    psk: str | None,
    expected_cli: str,
) -> None:
    assert command_for(operation, ap_id, ssid=ssid, psk=psk) == expected_cli


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint0",
        "WifiMaster0/AccessPoint1",
        "WifiMaster0/AccessPoint2",
        "WifiMaster0AccessPoint3",
        "WifiMaster0/AccessPoint3/extra",
        "WifiMaster2/AccessPoint3",
        "",
    ],
)
def test_validate_wifi_ap_id_rejects_disallowed(ap_id: str) -> None:
    with pytest.raises(ValueError):
        validate_wifi_ap_id(ap_id)


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint3",
        "WifiMaster0/AccessPoint6",
        "WifiMaster1/AccessPoint4",
        "  WifiMaster1/AccessPoint5  ",
    ],
)
def test_validate_wifi_ap_id_accepts_test_aps(ap_id: str) -> None:
    normalized = validate_wifi_ap_id(ap_id)
    assert normalized.startswith("WifiMaster")
    assert "/AccessPoint" in normalized


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint7",
        "WifiMaster0/AccessPoint8",
        "WifiMaster1/AccessPoint9",
    ],
)
def test_validate_wifi_ap_id_rejects_nonexistent_hardware_aps(ap_id: str) -> None:
    with pytest.raises(ValueError, match="not an allowlisted test access point"):
        validate_wifi_ap_id(ap_id)


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint0",
        "WifiMaster0/AccessPoint1",
        "WifiMaster0/AccessPoint2",
        "WifiMaster1/AccessPoint0",
    ],
)
def test_validate_wifi_ap_id_accepts_production_aps_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch, ap_id: str
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    normalized = validate_wifi_ap_id(ap_id)
    assert normalized == ap_id.strip()


def test_is_wifi_ap_parse_body_accepts_ap0_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    body = build_sealed_parse_body("interface WifiMaster0/AccessPoint0 up")
    assert is_wifi_ap_parse_body(body)
    assert is_write_allowlisted("POST", "/rci/", body)


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint7",
        "WifiMaster0/AccessPoint8",
        "WifiMaster1/AccessPoint9",
    ],
)
def test_validate_wifi_ap_id_rejects_ap7_9_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch, ap_id: str
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    with pytest.raises(ValueError, match="not an allowlisted test access point"):
        validate_wifi_ap_id(ap_id)


@pytest.mark.parametrize(
    ("cli_command", "ap_id"),
    [
        ("interface WifiMaster0/AccessPoint7 up", "WifiMaster0/AccessPoint7"),
        ("interface WifiMaster0/AccessPoint8 ssid AP8-TEST", "WifiMaster0/AccessPoint8"),
        ("interface WifiMaster1/AccessPoint9 down", "WifiMaster1/AccessPoint9"),
    ],
)
def test_is_wifi_ap_parse_body_rejects_ap7_9_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch, cli_command: str, ap_id: str
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    body = build_sealed_parse_body(cli_command)
    assert not is_wifi_ap_parse_body(body)
    with pytest.raises(ValueError, match="not an allowlisted test access point"):
        validate_wifi_ap_id(ap_id)


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint0",
        "WifiMaster0/AccessPoint6",
        "WifiMaster1/AccessPoint4",
    ],
)
def test_validate_wifi_ap_id_accepts_ap0_6_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch, ap_id: str
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    normalized = validate_wifi_ap_id(ap_id)
    assert normalized == ap_id.strip()


@pytest.mark.parametrize(
    "ssid",
    [
        "",
        "has space",
        "semi;colon",
        "quote\"bad",
        "A" * 33,
        "_starts-with-underscore",
    ],
)
def test_validate_ssid_rejects_disallowed(ssid: str) -> None:
    with pytest.raises(ValueError):
        validate_ssid(ssid)


@pytest.mark.parametrize("ssid", ["RC-TEST-1", "A", "x.y-z_0", "A" * 32])
def test_validate_ssid_accepts_bounded(ssid: str) -> None:
    assert validate_ssid(ssid) == ssid.strip()


@pytest.mark.parametrize(
    "psk",
    [
        "",
        "short",
        "A" * 64,
        "has space",
        "semi;colon",
        "quote\"bad",
        "back`tick",
        "dollar$bad",
        "back\\slash",
        "newline\nbad",
    ],
)
def test_validate_wpa_psk_rejects_disallowed(psk: str) -> None:
    with pytest.raises(ValueError):
        validate_wpa_psk(psk)


@pytest.mark.parametrize(
    "psk",
    [
        _OFFLINE_PSK_PLACEHOLDER,
        "A" * 8,
        "A" * 63,
        "x.y-z_0:+@%/=~^|!?&*()[]{}#,.<>-",
    ],
)
def test_validate_wpa_psk_accepts_bounded(psk: str) -> None:
    assert validate_wpa_psk(psk) == psk.strip()


def test_sealed_request_for_body_matches_allowlist() -> None:
    request = sealed_request_for(
        WifiApRciOperation.SET_SSID,
        "WifiMaster0/AccessPoint3",
        ssid="RC-TEST-1",
    )
    assert is_write_allowlisted("POST", "/rci/", request.body)
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [{"parse": "interface WifiMaster0/AccessPoint3 ssid RC-TEST-1"}]


def test_sealed_request_for_set_wpa_psk_matches_allowlist() -> None:
    request = sealed_request_for(
        WifiApRciOperation.SET_WPA_PSK,
        "WifiMaster0/AccessPoint3",
        psk=_OFFLINE_PSK_PLACEHOLDER,
    )
    assert is_write_allowlisted("POST", "/rci/", request.body)
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [
        {
            "parse": (
                f"interface WifiMaster0/AccessPoint3 authentication wpa-psk "
                f"{_OFFLINE_PSK_PLACEHOLDER}"
            )
        }
    ]


@pytest.mark.parametrize(
    "operation",
    [
        WifiApRciOperation.UP,
        WifiApRciOperation.DOWN,
        WifiApRciOperation.CLEAR_SSID,
        WifiApRciOperation.SET_WPA_PSK,
        WifiApRciOperation.CLEAR_WPA_PSK,
        WifiApRciOperation.ENCRYPTION_ENABLE,
        WifiApRciOperation.ENCRYPTION_DISABLE,
        WifiApRciOperation.ENCRYPTION_WPA2,
        WifiApRciOperation.ENCRYPTION_WPA2_CLEAR,
        WifiApRciOperation.ENCRYPTION_WPA3,
        WifiApRciOperation.ENCRYPTION_WPA3_CLEAR,
    ],
)
def test_verify_wifi_ap_response_accepts_good_ack(operation: WifiApRciOperation) -> None:
    ssid = "RC-TEST-1" if operation is WifiApRciOperation.SET_SSID else None
    result = verify_wifi_ap_response(
        operation,
        "WifiMaster0/AccessPoint3",
        _ok_envelope(),
        ssid=ssid,
    )
    sanitized = result.sanitized_dict()
    assert sanitized["ap_id"] == "WifiMaster0/AccessPoint3"
    assert sanitized["ack_matched"] is True
    for entry in sanitized.get("status", []):
        assert "message" not in entry


def test_verify_wifi_ap_response_rejects_error_status() -> None:
    with pytest.raises(WifiApRciError, match="error status"):
        verify_wifi_ap_response(
            WifiApRciOperation.DOWN,
            "WifiMaster0/AccessPoint3",
            _error_envelope(),
        )


def test_sanitized_dict_includes_ssid_for_set_ssid() -> None:
    result = verify_wifi_ap_response(
        WifiApRciOperation.SET_SSID,
        "WifiMaster0/AccessPoint3",
        _ok_envelope(),
        ssid="RC-TEST-1",
    )
    sanitized = result.sanitized_dict()
    assert sanitized["ssid"] == "RC-TEST-1"
    for entry in sanitized.get("status", []):
        assert "message" not in entry


def test_sanitized_dict_set_wpa_psk_never_contains_psk() -> None:
    result = verify_wifi_ap_response(
        WifiApRciOperation.SET_WPA_PSK,
        "WifiMaster0/AccessPoint3",
        _ok_envelope(),
    )
    sanitized = result.sanitized_dict()
    dumped = json.dumps(sanitized)
    assert _OFFLINE_PSK_PLACEHOLDER not in dumped
    assert "passphrase" not in dumped.lower()
    assert "authentication wpa-psk" not in dumped.lower()
    assert sanitized.keys() <= {"operation", "ap_id", "ack_matched", "prompt", "status", "ssid"}


def test_command_for_set_wpa_psk_requires_psk() -> None:
    with pytest.raises(WifiApRciError, match="psk is required"):
        command_for(WifiApRciOperation.SET_WPA_PSK, "WifiMaster0/AccessPoint3")


def _expected_digest(cli: str) -> str:
    return body_sha256(build_sealed_parse_body(cli))


def _transport_guard():
    return patch(
        "router_control.adapters.netcraze.rci_live.open_pinned_rci_transport",
        side_effect=AssertionError("open_pinned_rci_transport must not be called in validate mode"),
    )


@pytest.mark.parametrize(
    ("operation", "ap_id", "ssid", "expected_cli"),
    [
        ("up", "WifiMaster0/AccessPoint3", None, "interface WifiMaster0/AccessPoint3 up"),
        ("down", "WifiMaster1/AccessPoint4", None, "interface WifiMaster1/AccessPoint4 down"),
        (
            "clear-ssid",
            "WifiMaster0/AccessPoint5",
            None,
            "interface WifiMaster0/AccessPoint5 no ssid",
        ),
        (
            "set-ssid",
            "WifiMaster0/AccessPoint3",
            "RC-TEST-1",
            "interface WifiMaster0/AccessPoint3 ssid RC-TEST-1",
        ),
        (
            "clear-wpa-psk",
            "WifiMaster0/AccessPoint3",
            None,
            "interface WifiMaster0/AccessPoint3 no authentication wpa-psk",
        ),
        (
            "encryption-enable",
            "WifiMaster0/AccessPoint3",
            None,
            "interface WifiMaster0/AccessPoint3 encryption enable",
        ),
        (
            "encryption-disable",
            "WifiMaster0/AccessPoint3",
            None,
            "interface WifiMaster0/AccessPoint3 no encryption enable",
        ),
        (
            "encryption-wpa2",
            "WifiMaster0/AccessPoint3",
            None,
            "interface WifiMaster0/AccessPoint3 encryption wpa2",
        ),
        (
            "encryption-wpa2-clear",
            "WifiMaster0/AccessPoint3",
            None,
            "interface WifiMaster0/AccessPoint3 no encryption wpa2",
        ),
    ],
)
def test_wifi_cli_validate_mode_success(
    wifi_cli,
    operation: str,
    ap_id: str,
    ssid: str | None,
    expected_cli: str,
) -> None:
    argv = [
        "wifi-rci-op.py",
        "--operation",
        operation,
        "--ap-id",
        ap_id,
    ]
    if operation == "set-ssid":
        argv.extend(["--ssid", ssid or ""])
    stdout = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert wifi_cli.main() == 0
    plan = json.loads(stdout.getvalue())
    expected_plan: dict[str, object] = {
        "mode": "validate",
        "operation": operation,
        "ap_id": ap_id.strip(),
        "cli": expected_cli,
        "body_sha256": _expected_digest(expected_cli),
        "write_allowlisted": True,
        "bytes": len(build_sealed_parse_body(expected_cli)),
    }
    if operation == "set-ssid":
        expected_plan["ssid"] = ssid
    assert plan == expected_plan


def test_wifi_cli_validate_mode_set_wpa_psk_redacts_psk(wifi_cli) -> None:
    argv = [
        "wifi-rci-op.py",
        "--operation",
        "set-wpa-psk",
        "--ap-id",
        "WifiMaster0/AccessPoint3",
        "--psk-credential-ref",
        "test-psk-ref-id",
    ]
    stdout = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert wifi_cli.main() == 0
    output = stdout.getvalue()
    assert "<redacted>" in output
    assert _OFFLINE_PSK_PLACEHOLDER not in output
    assert "test-psk-ref-id" not in output
    plan = json.loads(output)
    assert plan["cli"] == "interface WifiMaster0/AccessPoint3 authentication wpa-psk <redacted>"
    assert plan["body_sha256"] == "omitted (secret-bearing)"
    assert plan["write_allowlisted"] is True


@pytest.mark.parametrize(
    ("argv_suffix", "expected_fragment"),
    [
        (["--operation", "up", "--ap-id", "WifiMaster0/AccessPoint0"], "invalid ap id"),
        (["--operation", "set-ssid", "--ap-id", "WifiMaster0/AccessPoint3"], "invalid ssid"),
        (
            [
                "--operation",
                "set-ssid",
                "--ap-id",
                "WifiMaster0/AccessPoint3",
                "--ssid",
                "bad space",
            ],
            "invalid ssid",
        ),
        (
            ["--operation", "set-wpa-psk", "--ap-id", "WifiMaster0/AccessPoint3"],
            "invalid psk credential ref",
        ),
    ],
)
def test_wifi_cli_validate_mode_invalid_inputs(
    wifi_cli,
    argv_suffix: list[str],
    expected_fragment: str,
) -> None:
    argv = ["wifi-rci-op.py", *argv_suffix]
    stderr = StringIO()
    with _transport_guard(), patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert wifi_cli.main() == 1
    assert expected_fragment in stderr.getvalue()


def test_wifi_cli_has_execute_flag(wifi_cli) -> None:
    parser = wifi_cli._build_parser()
    actions = {action.dest for action in parser._actions if action.dest != "help"}
    assert "execute" in actions
    assert "operation" in actions
    assert "ap_id" in actions
    assert "psk_credential_ref" in actions


def test_command_redacted_psk_never_leaks() -> None:
    from router_control.adapters.netcraze.wifi_rci import command_redacted_for

    redacted = command_redacted_for(
        WifiApRciOperation.SET_WPA_PSK,
        "WifiMaster0/AccessPoint3",
    )
    assert "<redacted>" in redacted
    assert _OFFLINE_PSK_PLACEHOLDER not in redacted


def test_classify_transport_timeout() -> None:
    from router_control.adapters.netcraze.wifi_rci import (
        WifiApRciErrorCategory,
        classify_wifi_ap_rci_failure,
    )

    details = classify_wifi_ap_rci_failure(
        operation=WifiApRciOperation.UP,
        ap_id="WifiMaster0/AccessPoint3",
        exc=TimeoutError("timed out"),
    )
    assert details.category == WifiApRciErrorCategory.TRANSPORT_OR_TIMEOUT


def test_verify_wifi_ap_response_accepts_trailing_prompt_suffix() -> None:
    envelope = [
        {
            "parse": {
                "prompt": "(config)>\x1b[K",
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
    result = verify_wifi_ap_response(
        WifiApRciOperation.UP,
        "WifiMaster0/AccessPoint3",
        envelope,
    )
    assert result.ack_matched is True
    assert result.prompt == "(config)"


def test_verify_wifi_ap_response_rejects_unrecognized_prompt_context() -> None:
    envelope = [
        {
            "parse": {
                "prompt": "(config-if)EXTRA",
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
    with pytest.raises(WifiApRciError, match="prompt missing or not allowlisted"):
        verify_wifi_ap_response(
            WifiApRciOperation.UP,
            "WifiMaster0/AccessPoint3",
            envelope,
        )


def test_classify_unknown_error_preserves_sanitized_message() -> None:
    from router_control.adapters.netcraze.fail_safe_rci import FailSafeStatusEntry
    from router_control.adapters.netcraze.wifi_rci import (
        WifiApRciErrorCategory,
        classify_wifi_ap_rci_failure,
    )

    entry = FailSafeStatusEntry(
        status="error",
        code="99",
        ident="Core::Custom",
        message="Router rejected custom policy XYZ",
    )
    details = classify_wifi_ap_rci_failure(
        operation=WifiApRciOperation.UP,
        ap_id="WifiMaster0/AccessPoint3",
        status_entries=(entry,),
        prompt="(config)",
    )
    assert details.category == WifiApRciErrorCategory.REJECTED_BY_ROUTER
    assert details.sanitized_message == "Router rejected custom policy XYZ"


def test_classify_unrecognized_error_tokens_preserves_ident_fallback() -> None:
    from router_control.adapters.netcraze.fail_safe_rci import FailSafeStatusEntry
    from router_control.adapters.netcraze.wifi_rci import (
        WifiApRciErrorCategory,
        classify_wifi_ap_rci_failure,
    )

    entry = FailSafeStatusEntry(
        status="error",
        code="1",
        ident="Core::Interface",
        message="",
    )
    details = classify_wifi_ap_rci_failure(
        operation=WifiApRciOperation.UP,
        ap_id="WifiMaster0/AccessPoint3",
        status_entries=(entry,),
        prompt="(config)",
    )
    assert details.category == WifiApRciErrorCategory.REJECTED_BY_ROUTER
    assert details.sanitized_message == "Core::Interface"
