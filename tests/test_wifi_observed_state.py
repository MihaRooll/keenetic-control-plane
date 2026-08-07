"""Offline tests for Wi-Fi observed-state service."""

from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.application.wifi_observation_helpers import (
    parse_broadcast_flag,
    parse_up_down_flag,
    resolve_broadcast,
    resolve_device_connected,
    resolve_link_up,
    resolve_on_air_signal,
)
from router_control.application.wifi_observed_state import (
    compare_observed_to_desired,
    read_observed_ap_state,
    run_wifi_observed_state,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)

_TEST_AP = "WifiMaster0/AccessPoint3"
_TEST_AP_5G = "WifiMaster1/AccessPoint3"


def _wpa2_intent(**overrides: object) -> WifiIntent:
    base = {
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": None,
        "captive_portal": CaptivePortalMode.DISABLED,
        "guest_isolation": False,
        "wpa_mode": WifiWpaMode.WPA2,
        "band": WifiBand.BAND_2_4GHZ,
    }
    base.update(overrides)
    return WifiIntent(**base)  # type: ignore[arg-type]


class FakeObservedTransport:
    def __init__(self, readbacks: dict[str, Any] | None = None) -> None:
        self.readbacks = dict(readbacks or {})
        self.parse_commands: list[str] = []

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        for ap_id, payload in self.readbacks.items():
            if ap_id in cli_command:
                return payload
        return {"interface": {"ssid": "", "encryption": {}, "state": "down", "up": False}}


def test_parse_wpa2_observed_state() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "up",
                    "up": True,
                    "link": "up",
                    "connected": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.readable is True
    assert observed.ssid == "Staff-Private"
    assert observed.wpa_mode == "WPA2"
    assert observed.band == "2.4GHz"
    assert observed.enabled_or_up is True
    assert observed.link_up is True
    assert observed.device_connected is True


def test_parse_wpa3_observed_state() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP_5G: {
                "interface": {
                    "ssid": "Staff-5G",
                    "encryption": {"wpa3": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP_5G)
    assert observed.wpa_mode == "WPA3"
    assert observed.band == "5GHz"


def test_parse_mixed_observed_state() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Mixed",
                    "encryption": {"wpa2": True, "wpa3": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.wpa_mode == "WPA2_WPA3_MIXED"


def test_garbage_encryption_maps_to_unrecognized() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Open-ish",
                    "encryption": {"garbage_mode": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.wpa_mode == "unrecognized"


def test_key_material_redacted_in_serialized_report() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True},
                    "state": "up",
                    "up": True,
                    "psk": "super-secret-psk-value",
                    "passphrase": "also-secret",
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.key_configured is True
    serialized = json.dumps(observed.to_dict())
    assert "super-secret-psk-value" not in serialized
    assert "also-secret" not in serialized
    assert "REDACTED" in serialized or "psk" not in serialized.lower()


def test_unreadable_ap_not_fabricated() -> None:
    class FailingTransport:
        def execute_rci_parse(self, cli_command: str) -> Any:
            raise RuntimeError("read failed")

    observed = read_observed_ap_state(FailingTransport(), _TEST_AP)
    assert observed.readable is False
    assert observed.ssid is None
    assert observed.enabled_or_up is None
    assert observed.wpa_mode == "unknown"
    comparison = compare_observed_to_desired(observed, _wpa2_intent())
    assert all(value == "unknown" for value in comparison.values())


def test_comparison_match_all_fields() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    comparison = compare_observed_to_desired(observed, _wpa2_intent())
    assert comparison == {
        "ssid": "match",
        "wpa_mode": "match",
        "enabled": "match",
        "band": "match",
    }


def test_comparison_single_field_differs() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Other-SSID",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    comparison = compare_observed_to_desired(observed, _wpa2_intent())
    assert comparison["ssid"] == "differs"
    assert comparison["wpa_mode"] == "match"


def test_run_report_non_certifying() -> None:
    transport = FakeObservedTransport()
    report = run_wifi_observed_state(transport=transport, ap_ids=[_TEST_AP])
    payload = report.to_dict()
    assert payload["certification_eligible"] is False
    assert payload["offline_verified_only"] is True
    assert payload["transport_security"] == "fixture"


def test_mixed_observed_vs_wpa2_desired_differs() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Mixed",
                    "encryption": {"wpa2": True, "wpa3": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.wpa_mode == "WPA2_WPA3_MIXED"
    comparison = compare_observed_to_desired(observed, _wpa2_intent())
    assert comparison["wpa_mode"] == "differs"


def test_unrecognized_state_enabled_unknown_not_false_match() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "booting",
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.enabled_or_up is None
    comparison = compare_observed_to_desired(
        observed,
        _wpa2_intent(enabled=False),
    )
    assert comparison["enabled"] == "unknown"


def test_scalar_encryption_scrubs_psk_in_serialized() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": "wpa2 psk=super-secret-psk-value",
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    serialized = json.dumps(observed.to_dict())
    assert "super-secret-psk-value" not in serialized
    assert "REDACTED" in serialized


def test_key_configured_absent_is_null() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True, "enabled": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.key_configured is None


def _assert_no_secret_in_serialized(observed: object, secret: str) -> None:
    serialized = json.dumps(observed.to_dict())  # type: ignore[attr-defined]
    assert secret not in serialized
    assert "REDACTED" in serialized


def test_list_encryption_scrubs_psk_assignment() -> None:
    secret = "list-secret"
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": [f"wpa2 psk={secret}"],
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    _assert_no_secret_in_serialized(observed, secret)


def test_scalar_encryption_scrubs_password_assignment() -> None:
    secret = "secret123"
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": f"wpa2 password={secret}",
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    _assert_no_secret_in_serialized(observed, secret)


def test_scalar_encryption_scrubs_auth_wpa_psk_space_delimited() -> None:
    secret = "secret123"
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": f"authentication wpa-psk {secret}",
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    _assert_no_secret_in_serialized(observed, secret)


def test_scalar_encryption_scrubs_psk_space_delimited() -> None:
    secret = "secret123"
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": f"wpa2 psk {secret}",
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    _assert_no_secret_in_serialized(observed, secret)


def test_torn_down_ap_link_down_connected_true_not_on_air() -> None:
    """Live-found shape: device connected true while link down — not on-air."""
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": None,
                    "encryption": {},
                    "state": "down",
                    "up": False,
                    "link": "down",
                    "connected": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.readable is True
    assert observed.link_up is False
    assert observed.device_connected is True
    assert observed.wpa_mode == "not_configured"
    assert observed.enabled_or_up is False


def test_connected_only_without_link_does_not_imply_on_air() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"wpa2": True},
                    "state": "up",
                    "up": True,
                    "connected": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.link_up is None
    assert observed.device_connected is True


def test_empty_encryption_maps_to_not_configured() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "",
                    "encryption": {},
                    "state": "down",
                    "up": False,
                    "link": "down",
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    assert observed.wpa_mode == "not_configured"


def test_not_configured_and_unrecognized_differ() -> None:
    empty_transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "X",
                    "encryption": {},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    garbage_transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "X",
                    "encryption": {"garbage_mode": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    empty_mode = read_observed_ap_state(empty_transport, _TEST_AP).wpa_mode
    garbage_mode = read_observed_ap_state(garbage_transport, _TEST_AP).wpa_mode
    assert empty_mode == "not_configured"
    assert garbage_mode == "unrecognized"
    assert empty_mode != garbage_mode
    for mode in (empty_mode, garbage_mode):
        assert mode not in {"WPA2", "WPA3", "WPA2_WPA3_MIXED"}


def test_not_configured_never_false_match_desired_wpa2() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    comparison = compare_observed_to_desired(observed, _wpa2_intent())
    assert comparison["wpa_mode"] == "unknown"


def test_unrecognized_never_false_match_desired_wpa2() -> None:
    transport = FakeObservedTransport(
        {
            _TEST_AP: {
                "interface": {
                    "ssid": "Staff-Private",
                    "encryption": {"garbage_mode": True},
                    "state": "up",
                    "up": True,
                }
            }
        }
    )
    observed = read_observed_ap_state(transport, _TEST_AP)
    comparison = compare_observed_to_desired(observed, _wpa2_intent())
    assert comparison["wpa_mode"] == "unknown"


@pytest.mark.parametrize(
    ("fields", "expected_link_up", "expected_on_air", "expected_broadcast"),
    [
        ({"broadcast": True, "link": False}, False, None, True),
        ({"broadcast": False, "link": "up"}, True, None, False),
        ({"broadcast": True}, None, None, True),
        ({"link": "up"}, True, True, None),
        ({}, None, None, None),
        ({"broadcast": "yes", "link": "down"}, False, None, True),
        ({"broadcast": "garbage", "link": "up"}, True, True, None),
        ({"link": "garbage"}, None, None, None),
        ({"link": 1}, None, None, None),
        ({"link": ""}, None, None, None),
        ({"link": "up", "broadcast": True}, True, True, True),
        ({"link": False, "broadcast": False}, False, False, False),
        ({"broadcasting": "yes"}, None, None, True),
        ({"broadcasting": "no", "link": True}, True, None, False),
    ],
    ids=[
        "broadcast_true_link_false",
        "broadcast_false_link_up",
        "broadcast_only",
        "link_only_up",
        "neither",
        "broadcast_yes_link_down",
        "broadcast_garbage_link_up",
        "link_garbage",
        "link_numeric_int_unknown",
        "link_empty_string_unknown",
        "both_agree_up",
        "both_agree_down",
        "broadcasting_only_yes",
        "broadcasting_no_link_true_conflict",
    ],
)
def test_resolve_link_up_and_on_air_matrix(
    fields: dict[str, object],
    expected_link_up: bool | None,
    expected_on_air: bool | None,
    expected_broadcast: bool | None,
) -> None:
    assert resolve_link_up(fields) is expected_link_up
    assert resolve_on_air_signal(fields) is expected_on_air
    assert resolve_broadcast(fields) is expected_broadcast


def test_resolve_device_connected_string_false() -> None:
    assert resolve_device_connected({"connected": "false"}) is False


def test_resolve_device_connected_string_true() -> None:
    assert resolve_device_connected({"connected": "true"}) is True


_MATRIX_VALUES: list[tuple[object, str]] = [
    (True, "bool_true"),
    (False, "bool_false"),
    ("up", "str_up"),
    ("down", "str_down"),
    ("UP", "str_UP"),
    (" up ", "str_padded_up"),
    ("Up", "str_mixed_up"),
    ("true", "str_true"),
    ("false", "str_false"),
    ("yes", "str_yes"),
    ("no", "str_no"),
    ("on", "str_on"),
    ("off", "str_off"),
    ("enabled", "str_enabled"),
    ("disabled", "str_disabled"),
    (0, "int_0"),
    (1, "int_1"),
    (2, "int_2"),
    (-1, "int_neg1"),
    ("", "str_empty"),
    (None, "none"),
    ([], "list_empty"),
    ({}, "dict_empty"),
]


@pytest.mark.parametrize("value,label", _MATRIX_VALUES, ids=[label for _, label in _MATRIX_VALUES])
def test_parse_up_down_flag_full_matrix(value: object, label: str) -> None:
    expected = {
        "bool_true": True,
        "bool_false": False,
        "str_up": True,
        "str_down": False,
        "str_UP": True,
        "str_padded_up": True,
        "str_mixed_up": True,
        "str_true": True,
        "str_false": False,
        "str_yes": None,
        "str_no": None,
        "str_on": None,
        "str_off": None,
        "str_enabled": True,
        "str_disabled": False,
        "int_0": None,
        "int_1": None,
        "int_2": None,
        "int_neg1": None,
        "str_empty": None,
        "none": None,
        "list_empty": None,
        "dict_empty": None,
    }[label]
    assert parse_up_down_flag(value) is expected


@pytest.mark.parametrize("value,label", _MATRIX_VALUES, ids=[label for _, label in _MATRIX_VALUES])
def test_parse_broadcast_flag_full_matrix(value: object, label: str) -> None:
    expected = {
        "bool_true": True,
        "bool_false": False,
        "str_up": True,
        "str_down": False,
        "str_UP": True,
        "str_padded_up": True,
        "str_mixed_up": True,
        "str_true": True,
        "str_false": False,
        "str_yes": True,
        "str_no": False,
        "str_on": True,
        "str_off": False,
        "str_enabled": None,
        "str_disabled": None,
        "int_0": None,
        "int_1": None,
        "int_2": None,
        "int_neg1": None,
        "str_empty": None,
        "none": None,
        "list_empty": None,
        "dict_empty": None,
    }[label]
    assert parse_broadcast_flag(value) is expected
