"""Regression: show-rc station readback must never expose plaintext PSK."""

from __future__ import annotations

import json
import logging
import traceback
from typing import Any

import pytest
from router_control.application.wifi_observation_helpers import (
    parse_station_interface_readback,
    sanitize_show_rc_interface_raw,
    scrub_error_message,
)
from router_control.application.wifi_station_apply_service import (
    WifiStationApplyServiceError,
    readback_wifi_station_state,
)

_LEAK_TOKEN = "TEST-PLAINTEXT-PSK-LEAK-TOKEN"


def _realistic_show_rc_with_psk() -> dict[str, Any]:
    """Realistic Keenetic parse-shaped show-rc payload with plaintext PSK."""
    return {
        "parse": {
            "prompt": "(config-if)",
            "interface": {
                "ssid": "RC-LAB-UPSTREAM-d78c3d57",
                "encryption": f"wpa2 authentication wpa-psk {_LEAK_TOKEN}",
                "authentication": f"wpa-psk {_LEAK_TOKEN}",
                "psk": _LEAK_TOKEN,
                "wpa-psk": _LEAK_TOKEN,
            },
        }
    }


def _nested_keenetic_show_rc_with_psk() -> dict[str, Any]:
    """Nested authentication.wpa-psk.psk shape observed on Keenetic show-rc."""
    return {
        "parse": {
            "prompt": "(config-if)",
            "interface": {
                "ssid": "RC-LAB-NESTED-d78c3d57",
                "encryption": "wpa2",
                "authentication": {
                    "wpa-psk": {
                        "psk": _LEAK_TOKEN,
                    },
                },
            },
        }
    }


def _runtime_associated() -> dict[str, Any]:
    return {
        "ssid": "RC-LAB-UPSTREAM-d78c3d57",
        "encryption": "wpa2",
        "state": "up",
        "link": "up",
        "connected": True,
    }


class _LeakInjectingReadbackTransport:
    def __init__(self, configured: Any, runtime: Any, *, fail_on: str | None = None) -> None:
        self.configured = configured
        self.runtime = runtime
        self.fail_on = fail_on
        self.commands: list[str] = []

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.commands.append(cli_command)
        if self.fail_on and self.fail_on in cli_command:
            raise RuntimeError(f"device rejected authentication wpa-psk {_LEAK_TOKEN}")
        if cli_command.startswith("show rc interface"):
            return self.configured
        if cli_command.startswith("show interface"):
            return self.runtime
        raise AssertionError(f"unexpected command: {cli_command}")


def _assert_exception_chain_clean(exc: BaseException) -> None:
    assert _LEAK_TOKEN not in str(exc)
    cause = exc.__cause__
    assert cause is None or _LEAK_TOKEN not in str(cause)
    formatted = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, chain=True))
    assert _LEAK_TOKEN not in formatted


def test_sanitize_show_rc_interface_raw_strips_psk_token() -> None:
    sanitized = sanitize_show_rc_interface_raw(_realistic_show_rc_with_psk())
    serialized = json.dumps(sanitized)
    assert _LEAK_TOKEN not in serialized
    assert "REDACTED" in serialized


def test_sanitize_nested_authentication_wpa_psk_psk_shape() -> None:
    sanitized = sanitize_show_rc_interface_raw(_nested_keenetic_show_rc_with_psk())
    serialized = json.dumps(sanitized)
    assert _LEAK_TOKEN not in serialized
    assert "REDACTED" in serialized


def test_parse_station_readback_no_psk_in_dto() -> None:
    readback = parse_station_interface_readback(
        _realistic_show_rc_with_psk(),
        _runtime_associated(),
    )
    serialized = json.dumps(readback.to_dict())
    assert _LEAK_TOKEN not in serialized
    assert readback.configured_ssid == "RC-LAB-UPSTREAM-d78c3d57"
    enc = readback.configured_encryption or ""
    assert _LEAK_TOKEN not in enc


def test_parse_station_readback_nested_authentication_shape() -> None:
    readback = parse_station_interface_readback(
        _nested_keenetic_show_rc_with_psk(),
        _runtime_associated(),
    )
    serialized = json.dumps(readback.to_dict())
    assert _LEAK_TOKEN not in serialized
    assert readback.configured_ssid == "RC-LAB-NESTED-d78c3d57"


def test_readback_wifi_station_state_service_path_clean(
    caplog: pytest.LogCaptureFixture,
) -> None:
    transport = _LeakInjectingReadbackTransport(
        _realistic_show_rc_with_psk(),
        _runtime_associated(),
    )
    with caplog.at_level(logging.DEBUG):
        result = readback_wifi_station_state(transport, "WifiMaster1/WifiStation0")
    serialized = json.dumps(result)
    assert _LEAK_TOKEN not in serialized
    assert result["associated_network"] == "present"
    assert _LEAK_TOKEN not in caplog.text


def test_readback_wifi_station_state_nested_shape_clean() -> None:
    transport = _LeakInjectingReadbackTransport(
        _nested_keenetic_show_rc_with_psk(),
        _runtime_associated(),
    )
    result = readback_wifi_station_state(transport, "WifiMaster1/WifiStation0")
    serialized = json.dumps(result)
    assert _LEAK_TOKEN not in serialized


def test_readback_error_path_scrubs_psk_from_exception_chain() -> None:
    transport = _LeakInjectingReadbackTransport(
        _realistic_show_rc_with_psk(),
        _runtime_associated(),
        fail_on="show rc interface",
    )
    with pytest.raises(WifiStationApplyServiceError) as exc_info:
        readback_wifi_station_state(transport, "WifiMaster1/WifiStation0")
    _assert_exception_chain_clean(exc_info.value)
    assert "[REDACTED:error_message]" in str(exc_info.value)


def test_scrub_error_message_scalar_assignment() -> None:
    raw = f"authentication wpa-psk {_LEAK_TOKEN} failed"
    scrubbed = scrub_error_message(raw)
    assert _LEAK_TOKEN not in scrubbed
    assert scrubbed == "[REDACTED:error_message]"
