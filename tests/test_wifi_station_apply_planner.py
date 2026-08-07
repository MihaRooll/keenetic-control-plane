"""Offline tests for Wi-Fi station apply planner."""



from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.wifi_station_rci import WifiStationRciOperation
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlannerError,
    WifiStationAuthMode,
    WifiStationPlannerOptions,
    compile_uplink_intent_to_station_ops,
)
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand


def _wifi_wan_intent(**overrides: object) -> UplinkIntent:

    base = {

        "mode": UplinkMode.WIFI_WAN,

        "ssid": "Venue-Guest",

        "band": WifiBand.BAND_2_4GHZ,

        "credential_ref_id": "credref:venue-wifi",

        "priority": 100,

    }

    base.update(overrides)

    return UplinkIntent(**base)  # type: ignore[arg-type]





def test_compile_wpa2_apply_sequence_default_options() -> None:

    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent())

    apply_ops = [op.operation for op in plan.apply_ops]

    assert apply_ops == [

        WifiStationRciOperation.SET_SSID.value,

        WifiStationRciOperation.ENCRYPTION_ENABLE.value,

        WifiStationRciOperation.ENCRYPTION_WPA2.value,

        WifiStationRciOperation.SET_WPA_PSK.value,

        WifiStationRciOperation.UP.value,

    ]

    assert plan.grammar_verification_status == "device_accepted_grammar"

    assert plan.planned_uplink_verification_level == "planned_uplink_verified_bounded"

    assert plan.verification_status == "device_accepted_grammar"

    assert plan.station_id == "WifiMaster0/WifiStation0"

    encryption_notes = [
        note for op in plan.apply_ops for note in op.notes if "encryption" in op.operation
    ]

    assert any(
        "association to real WPA2 upstream requires both" in note for note in encryption_notes
    )





def test_compile_without_encryption() -> None:

    plan = compile_uplink_intent_to_station_ops(

        _wifi_wan_intent(),

        options=WifiStationPlannerOptions(include_encryption_wpa2=False),

    )

    apply_ops = [op.operation for op in plan.apply_ops]

    assert WifiStationRciOperation.ENCRYPTION_ENABLE.value not in apply_ops

    assert WifiStationRciOperation.ENCRYPTION_WPA2.value not in apply_ops

    assert WifiStationRciOperation.SET_WPA_PSK.value in apply_ops

    teardown_ops = [op.operation for op in plan.teardown_ops]

    assert WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value not in teardown_ops





def test_compile_wpa2_with_bssid_and_optional_ops() -> None:

    plan = compile_uplink_intent_to_station_ops(

        _wifi_wan_intent(bssid="aa:bb:cc:dd:ee:ff"),

        options=WifiStationPlannerOptions(

            include_dhcp_client=True,

            include_standby=True,

            standby_timeout_seconds=120,

        ),

    )

    apply_ops = [op.operation for op in plan.apply_ops]

    assert apply_ops[1] == WifiStationRciOperation.SET_BSSID.value

    bssid_op = plan.apply_ops[1]

    assert any("not device-confirmed" in note for note in bssid_op.notes)

    assert WifiStationRciOperation.IP_ADDRESS_DHCP.value in apply_ops

    assert WifiStationRciOperation.STANDBY_ENABLE.value in apply_ops

    assert WifiStationRciOperation.STANDBY_TIMEOUT.value in apply_ops





def test_compile_teardown_full_confirmed_negation_reverse_order() -> None:

    options = WifiStationPlannerOptions(

        include_dhcp_client=True,

        include_encryption_wpa2=True,

    )

    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent(), options=options)

    teardown_ops = [op.operation for op in plan.teardown_ops]

    assert teardown_ops == [

        WifiStationRciOperation.DOWN.value,

        WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP.value,

        WifiStationRciOperation.CLEAR_IP_ADDRESS.value,

        WifiStationRciOperation.CLEAR_WPA_PSK.value,

        WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value,

        WifiStationRciOperation.ENCRYPTION_DISABLE.value,

        WifiStationRciOperation.CLEAR_SSID.value,

    ]

    invented = {

        "wifi_station_no_standby",

        "wifi_station_ip_global_clear",

        "wifi_station_clear_security_level",

    }

    assert invented.isdisjoint(set(teardown_ops))

    assert any("ip global and standby negation remain unverified" in note for note in plan.notes)

    assert not any("partial teardown only" in note for note in plan.notes)





def test_ip_global_marked_unexercised_when_opted_in() -> None:

    plan = compile_uplink_intent_to_station_ops(

        _wifi_wan_intent(),

        options=WifiStationPlannerOptions(include_ip_global=True),

    )

    ip_global = next(
        op for op in plan.apply_ops if op.operation == WifiStationRciOperation.IP_GLOBAL.value
    )

    assert any("device-exercised on station" in note for note in ip_global.notes)

    assert any("settle" in note.lower() for note in plan.notes)





def test_default_plan_excludes_ip_global() -> None:

    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent())

    apply_ops = [op.operation for op in plan.apply_ops]

    assert WifiStationRciOperation.IP_GLOBAL.value not in apply_ops




def test_non_default_priority_without_ip_global_rejected() -> None:
    with pytest.raises(
        WifiStationApplyPlannerError,
        match=ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
    ):
        compile_uplink_intent_to_station_ops(_wifi_wan_intent(priority=600))


def test_default_priority_without_ip_global_compiles() -> None:
    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent(priority=100))
    assert WifiStationRciOperation.IP_GLOBAL.value not in [
        op.operation for op in plan.apply_ops
    ]


def test_non_default_priority_with_ip_global_includes_op() -> None:
    plan = compile_uplink_intent_to_station_ops(
        _wifi_wan_intent(priority=600),
        options=WifiStationPlannerOptions(include_ip_global=True),
    )
    ip_global = next(
        op for op in plan.apply_ops if op.operation == WifiStationRciOperation.IP_GLOBAL.value
    )
    assert ip_global.priority == 600





def test_open_network_rejected() -> None:

    with pytest.raises(WifiStationApplyPlannerError, match="open-network authentication"):

        compile_uplink_intent_to_station_ops(

            _wifi_wan_intent(),

            options=WifiStationPlannerOptions(auth_mode=WifiStationAuthMode.OPEN),

        )





def test_missing_credential_rejected() -> None:

    with pytest.raises(WifiStationApplyPlannerError, match="planner.credential_ref_required"):

        compile_uplink_intent_to_station_ops(

            _wifi_wan_intent(credential_ref_id=None),

        )





def test_captive_portal_client_rejected() -> None:

    with pytest.raises(WifiStationApplyPlannerError, match="captive_portal_client"):

        compile_uplink_intent_to_station_ops(

            _wifi_wan_intent(captive_portal_client=True),

        )





def test_non_wifi_wan_mode_rejected() -> None:

    with pytest.raises(WifiStationApplyPlannerError, match="WIFI_WAN"):

        compile_uplink_intent_to_station_ops(

            UplinkIntent(mode=UplinkMode.ETHERNET),

        )





def test_band_maps_to_station_iface() -> None:

    plan = compile_uplink_intent_to_station_ops(

        _wifi_wan_intent(band=WifiBand.BAND_5GHZ),

    )

    assert plan.station_id == "WifiMaster1/WifiStation0"





def test_no_psk_literals_in_plan_serialized() -> None:

    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent())

    serialized = json.dumps(

        {

            "apply_ops": [

                {

                    "operation": op.operation,

                    "credential_ref_id": op.credential_ref_id,

                    "ssid": op.ssid,

                    "bssid": op.bssid,

                    "notes": list(op.notes),

                }

                for op in plan.apply_ops

            ],

            "teardown_ops": [

                {

                    "operation": op.operation,

                    "credential_ref_id": op.credential_ref_id,

                    "notes": list(op.notes),

                }

                for op in plan.teardown_ops

            ],

            "notes": list(plan.notes),

        }

    ).lower()

    forbidden_secret_keys = ("passphrase", "password", "preshared", "private_key")

    for key in forbidden_secret_keys:

        assert f'"{key}"' not in serialized

    allowed_psk_ops = {

        WifiStationRciOperation.SET_WPA_PSK.value,

        WifiStationRciOperation.CLEAR_WPA_PSK.value,

    }

    for op in plan.apply_ops + plan.teardown_ops:

        if "psk" in op.operation:

            assert op.operation in allowed_psk_ops

    assert "test-passphrase" not in serialized

    assert "credref:venue-wifi" in serialized

    psk_op = next(

        op for op in plan.apply_ops if op.operation == WifiStationRciOperation.SET_WPA_PSK.value

    )

    assert psk_op.credential_ref_id == "credref:venue-wifi"


def test_compensate_ops_for_succeeded_station_apply_reverse_order() -> None:
    from router_control.application.wifi_station_apply_planner import (
        compensate_ops_for_succeeded_station_apply,
    )

    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent())
    succeeded = tuple(op.operation for op in plan.apply_ops[:3])
    compensate = compensate_ops_for_succeeded_station_apply(plan.apply_ops, succeeded)
    assert [op.operation for op in compensate] == [
        WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value,
        WifiStationRciOperation.ENCRYPTION_DISABLE.value,
        WifiStationRciOperation.CLEAR_SSID.value,
    ]


def test_derive_station_pre_state_psk_unknown_when_readback_omits_psk() -> None:
    from router_control.application.wifi_station_apply_planner import (
        compensate_ops_for_succeeded_station_apply,
        derive_wifi_station_pre_state,
        uncovered_compensate_ops_for_succeeded_station_apply,
    )

    raw = {
        "interface": {
            "ssid": "Venue-Upstream",
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
        }
    }
    readback = {
        "configured_ssid": "Venue-Upstream",
        "configured_encryption": {"wpa2": True, "enabled": True},
        "state": "up",
    }
    pre_state = derive_wifi_station_pre_state(readback, raw_configured=raw)
    assert pre_state.had_psk is None

    plan = compile_uplink_intent_to_station_ops(_wifi_wan_intent())
    succeeded = (WifiStationRciOperation.SET_WPA_PSK.value,)
    compensate = compensate_ops_for_succeeded_station_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert WifiStationRciOperation.CLEAR_WPA_PSK.value not in [
        op.operation for op in compensate
    ]
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_station_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "PSK state unknown" in uncovered[WifiStationRciOperation.SET_WPA_PSK.value]


def test_derive_station_pre_state_dhcp_from_show_rc_not_default_false() -> None:
    from router_control.application.wifi_station_apply_planner import (
        compensate_ops_for_succeeded_station_apply,
        derive_wifi_station_pre_state,
    )

    raw = {
        "interface": {
            "ip": {"address dhcp": "yes"},
            "ssid": "Upstream",
            "state": "up",
        }
    }
    readback = {
        "configured_ssid": "Upstream",
        "configured_dhcp_client": True,
        "state": "up",
    }
    pre_state = derive_wifi_station_pre_state(readback, raw_configured=raw)
    assert pre_state.had_dhcp_client is True

    plan = compile_uplink_intent_to_station_ops(
        _wifi_wan_intent(),
        options=WifiStationPlannerOptions(include_dhcp_client=True),
    )
    succeeded = (WifiStationRciOperation.IP_ADDRESS_DHCP.value,)
    compensate = compensate_ops_for_succeeded_station_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP.value not in [
        op.operation for op in compensate
    ]


def test_derive_station_pre_state_dhcp_unknown_blocks_compensation() -> None:
    from router_control.application.wifi_station_apply_planner import (
        compensate_ops_for_succeeded_station_apply,
        derive_wifi_station_pre_state,
        uncovered_compensate_ops_for_succeeded_station_apply,
    )

    readback = {"configured_ssid": "Upstream", "state": "up"}
    pre_state = derive_wifi_station_pre_state(readback)
    assert pre_state.had_dhcp_client is None

    plan = compile_uplink_intent_to_station_ops(
        _wifi_wan_intent(),
        options=WifiStationPlannerOptions(include_dhcp_client=True),
    )
    succeeded = (WifiStationRciOperation.IP_ADDRESS_DHCP.value,)
    compensate = compensate_ops_for_succeeded_station_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert compensate == ()
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_station_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert "DHCP client state unknown" in uncovered[WifiStationRciOperation.IP_ADDRESS_DHCP.value]

