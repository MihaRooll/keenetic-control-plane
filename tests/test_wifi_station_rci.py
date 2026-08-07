"""Offline tests for sealed Wi-Fi station RCI module."""



from __future__ import annotations

import pytest
from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.wifi_station_rci import (
    WifiStationRciError,
    WifiStationRciOperation,
    command_for,
    command_redacted_for,
    sealed_request_for,
    validate_wifi_station_id,
    verify_wifi_station_response,
)

_STATION_24 = "WifiMaster0/WifiStation0"

_STATION_5 = "WifiMaster1/WifiStation0"





def _ok_envelope(
    *,
    message: str = "interface is up.",
    prompt: str = "(config)",
    ident: str = "Network::Interface::Base",
    code: str = "1",
) -> list[dict[str, object]]:

    return [

        {

            "parse": {

                "prompt": prompt,

                "status": [

                    {

                        "status": "message",

                        "code": code,

                        "ident": ident,

                        "message": message,

                    }

                ],

            }

        }

    ]


def _ip_global_live_ack_envelope(
    *,
    station: str = "WifiMaster1/WifiStation0",
    priority: int = 600,
) -> list[dict[str, object]]:
    return _ok_envelope(
        message=f'"{station}": global priority is {priority}.',
        ident="Network::Interface::L3Base",
        code="72744991",
    )





def _error_envelope(
    *,
    message: str = "failed",
    ident: str = "Core::Interface",
    code: str = "1",
    prompt: str = "(config)",
) -> list[dict[str, object]]:

    return [

        {

            "parse": {

                "prompt": prompt,

                "status": [

                    {

                        "status": "error",

                        "code": code,

                        "ident": ident,

                        "message": message,

                    }

                ],

            }

        }

    ]





@pytest.mark.parametrize(

    ("operation", "station_id", "kwargs", "expected_cli"),

    [

        (

            WifiStationRciOperation.SET_SSID,

            _STATION_24,

            {"ssid": "Venue-Test"},

            f"interface {_STATION_24} ssid Venue-Test",

        ),

        (

            WifiStationRciOperation.SET_WPA_PSK,

            _STATION_24,

            {"psk": "test-passphrase-12345678"},

            f"interface {_STATION_24} authentication wpa-psk test-passphrase-12345678",

        ),

        (

            WifiStationRciOperation.ENCRYPTION_ENABLE,

            _STATION_24,

            {},

            f"interface {_STATION_24} encryption enable",

        ),

        (

            WifiStationRciOperation.ENCRYPTION_WPA2,

            _STATION_5,

            {},

            f"interface {_STATION_5} encryption wpa2",

        ),

        (

            WifiStationRciOperation.SET_BSSID,

            _STATION_24,

            {"bssid": "AA:BB:CC:DD:EE:FF"},

            f"interface {_STATION_24} mac bssid aa:bb:cc:dd:ee:ff",

        ),

        (

            WifiStationRciOperation.IP_GLOBAL,

            _STATION_24,

            {"priority": 40},

            f"interface {_STATION_24} ip global 40",

        ),

        (

            WifiStationRciOperation.IP_ADDRESS_DHCP,

            _STATION_24,

            {},

            f"interface {_STATION_24} ip address dhcp",

        ),

        (

            WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP,

            _STATION_24,

            {},

            f"interface {_STATION_24} no ip address dhcp",

        ),

        (

            WifiStationRciOperation.CLEAR_IP_ADDRESS,

            _STATION_24,

            {},

            f"interface {_STATION_24} no ip address",

        ),

        (

            WifiStationRciOperation.UP,

            _STATION_5,

            {},

            f"interface {_STATION_5} up",

        ),

        (

            WifiStationRciOperation.DOWN,

            _STATION_5,

            {},

            f"interface {_STATION_5} down",

        ),

    ],

)

def test_command_for_exact_strings(operation, station_id, kwargs, expected_cli) -> None:

    assert command_for(operation, station_id, **kwargs) == expected_cli





def test_validate_wifi_station_id_rejects_wifi_station1() -> None:

    with pytest.raises(ValueError, match="not allowlisted"):

        validate_wifi_station_id("WifiMaster1/WifiStation1")





def test_command_redacted_for_psk_never_includes_secret() -> None:

    redacted = command_redacted_for(

        WifiStationRciOperation.SET_WPA_PSK,

        _STATION_24,

    )

    assert redacted == f"interface {_STATION_24} authentication wpa-psk <redacted>"

    assert "test-passphrase" not in redacted





def test_sealed_request_for_roundtrip() -> None:

    request = sealed_request_for(

        WifiStationRciOperation.SET_SSID,

        _STATION_24,

        ssid="Venue-Test",

    )

    assert request.body == build_sealed_parse_body(

        f"interface {_STATION_24} ssid Venue-Test"

    )





@pytest.mark.parametrize(

    ("operation", "message"),

    [

        (WifiStationRciOperation.SET_SSID, "SSID saved."),

        (WifiStationRciOperation.CLEAR_SSID, "SSID reset."),

        (WifiStationRciOperation.SET_WPA_PSK, "WPA PSK set."),

        (WifiStationRciOperation.CLEAR_WPA_PSK, "WPA PSK removed."),

        (WifiStationRciOperation.ENCRYPTION_ENABLE, "wireless encryption enabled."),

        (WifiStationRciOperation.ENCRYPTION_DISABLE, "wireless encryption disabled."),

        (WifiStationRciOperation.ENCRYPTION_WPA2, "WPA2 algorithms enabled."),

        (WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR, "WPA2 algorithms disabled."),

        (WifiStationRciOperation.UP, "interface is up."),

        (WifiStationRciOperation.DOWN, "interface is down."),

        (WifiStationRciOperation.IP_ADDRESS_DHCP, "Started DHCP client on station."),

        (WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP, "Stopped DHCP client on station."),

        (WifiStationRciOperation.CLEAR_IP_ADDRESS, "IP address cleared."),

        (
            WifiStationRciOperation.IP_GLOBAL,
            f'"{_STATION_24}": global priority is 600.',
        ),

    ],

)

def test_verify_wifi_station_response_observed_acks(operation, message) -> None:

    result = verify_wifi_station_response(

        operation,

        _STATION_24,

        _ok_envelope(message=message),

        ssid="Venue-Test" if operation is WifiStationRciOperation.SET_SSID else None,

    )

    assert result.ack_matched is True

    assert result.prompt == "(config)"





def test_verify_wifi_station_response_ansi_prompt_tolerance() -> None:

    result = verify_wifi_station_response(

        WifiStationRciOperation.UP,

        _STATION_24,

        _ok_envelope(message="interface is up.", prompt="(config-if)>\x1b[K"),

    )

    assert result.ack_matched is True

    assert result.prompt == "(config)"





def test_verify_wifi_station_response_rejects_malformed_config_if_prompt() -> None:

    with pytest.raises(WifiStationRciError, match="prompt missing or not allowlisted"):

        verify_wifi_station_response(

            WifiStationRciOperation.UP,

            _STATION_24,

            _ok_envelope(message="interface is up.", prompt="(config-if)EXTRA"),

        )


def test_verify_wifi_station_response_accepts_config_prompt_with_trailing_gt() -> None:
    result = verify_wifi_station_response(
        WifiStationRciOperation.UP,
        _STATION_24,
        _ok_envelope(message="interface is up.", prompt="(config)>"),
    )
    assert result.ack_matched is True
    assert result.prompt == "(config)"





def test_verify_wifi_station_response_fail_closed_on_unexpected_ack() -> None:

    with pytest.raises(WifiStationRciError, match="device-confirmed pattern"):

        verify_wifi_station_response(

            WifiStationRciOperation.SET_SSID,

            _STATION_24,

            _ok_envelope(message="totally unexpected ack"),

            ssid="Venue-Test",

        )





def test_verify_wifi_station_response_ip_global_fail_closed_on_unexpected_ack() -> None:

    with pytest.raises(WifiStationRciError, match="device-confirmed pattern"):

        verify_wifi_station_response(

            WifiStationRciOperation.IP_GLOBAL,

            _STATION_24,

            _ok_envelope(message="totally unexpected ack"),

        )





def test_verify_wifi_station_response_ip_global_rejects_configurator_done() -> None:

    with pytest.raises(WifiStationRciError, match="device-confirmed pattern"):

        verify_wifi_station_response(

            WifiStationRciOperation.IP_GLOBAL,

            _STATION_24,

            _ok_envelope(message="Core::Configurator: Done."),

        )





def test_verify_wifi_station_response_ip_global_accepts_live_l3_ack() -> None:

    result = verify_wifi_station_response(

        WifiStationRciOperation.IP_GLOBAL,

        _STATION_5,

        _ip_global_live_ack_envelope(),

    )

    assert result.ack_matched is True

    assert result.prompt == "(config)"


def test_verify_wifi_station_response_ip_global_rejects_wrong_station_in_message() -> None:
    with pytest.raises(WifiStationRciError, match="device-confirmed pattern"):
        verify_wifi_station_response(
            WifiStationRciOperation.IP_GLOBAL,
            _STATION_24,
            _ip_global_live_ack_envelope(station=_STATION_5),
        )


def test_verify_wifi_station_response_ip_global_fail_closed_on_error() -> None:
    with pytest.raises(WifiStationRciError, match="error status"):
        verify_wifi_station_response(
            WifiStationRciOperation.IP_GLOBAL,
            _STATION_5,
            _error_envelope(
                message='"WifiMaster1/WifiStation0": global priority is 600.',
                ident="Network::Interface::L3Base",
                code="72744991",
            ),
        )





def test_verify_wifi_station_response_fail_closed_on_error() -> None:

    with pytest.raises(WifiStationRciError, match="error status"):

        verify_wifi_station_response(

            WifiStationRciOperation.UP,

            _STATION_24,

            _error_envelope(),

        )

