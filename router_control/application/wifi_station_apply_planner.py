"""Offline Wi-Fi station (WISP) UplinkIntent → sealed RCI op descriptor compiler."""



from __future__ import annotations

from dataclasses import dataclass, fields
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.wifi_station_rci import (
    WifiStationRciOperation,
    validate_wifi_station_id,
)
from router_control.application.grammar_doc_refs import build_planner_op_notes
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_SSID_REQUIRED,
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
    derive_dhcp_client_configured,
    derive_key_configured,
    encryption_empty,
    encryption_indicates_open,
    encryption_indicates_wpa2,
    ssid_present,
    state_is_up,
)
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand

_GRAMMAR_STATUS = "device_accepted_grammar"

_UPLINK_PLAN_LEVEL = "planned_uplink_verified_bounded"

_UPLINK_LIMITS_NOTE = (
    "planned_uplink_verified_bounded limits: one upstream network; "
    "WifiMaster1/WifiStation0 5GHz WPA2 only; "
    "open/captive/standby/failover/multi-uplink unverified; "
    "preset planner wifi_wan_not_certified unchanged"
)

_OFFLINE_NOTE = (
    "Wi-Fi station apply compiled offline; device-confirmed grammar from bounded lab probe "
    f"(grammar_verification_status={_GRAMMAR_STATUS}; "
    f"planned_uplink_verification_level={_UPLINK_PLAN_LEVEL})"
)

_MSG_OPEN_UNSUPPORTED = (

    "not yet supported: no verified open-network authentication grammar"

)

def _uplink_intent_default_priority() -> int:
    for field in fields(UplinkIntent):
        if field.name == "priority":
            default = field.default
            if isinstance(default, int):
                return default
            break
    raise RuntimeError("UplinkIntent.priority default must be int")


_DEFAULT_UPLINK_PRIORITY = _uplink_intent_default_priority()

_UNVERIFIED_NEGATION_NOTE = (

    "ip global and standby negation remain unverified (probe did not exercise); "

    "no verified negation claimed for those knobs"

)

_IP_GLOBAL_STATION_EXERCISED_NOTE = (
    "ip global device-exercised on station only (2026-07-31 first association grammar); "
    "product L3-ack verified 2026-08-05 (message contains global priority is N; "
    "ident Network::Interface::L3Base); priority semantics observed; "
    "default-route settle ~20-30s — verify with bounded wait-and-recheck of show ip route "
    "(no live polling loop in offline compiler); write success ≠ internet; "
    "still unexercised on WireGuard interfaces"
)

_IP_GLOBAL_SETTLE_SECONDS_MIN = 20
_IP_GLOBAL_SETTLE_SECONDS_MAX = 30

_CONNECTIVITY_CHECK_NOTE = (
    "CLI has no general ping; sanctioned upstream check is show internet status "
    "(internet/gateway/dns/captive-accessible fields)"
)

_BSSID_UNEXERCISED_NOTE = (

    "bssid pin compiled from help-derived grammar only; "

    "not device-confirmed in bounded probe (2026-07-31)"

)

_IP_GLOBAL_PLAN_NOTE = (
    "ip global included: device-exercised on station (2026-07-31 first association); "
    "product L3-ack verified 2026-08-05 (global priority is …); settle delay "
    f"{_IP_GLOBAL_SETTLE_SECONDS_MIN}-{_IP_GLOBAL_SETTLE_SECONDS_MAX}s "
    "before default-route recheck; write success ≠ internet; "
    + _CONNECTIVITY_CHECK_NOTE
)

_ENCRYPTION_DEFAULT_NOTE = (
    "encryption enable + encryption wpa2 default-on: device accepts PSK without them but "
    "association to real WPA2 upstream requires both (2026-07-31 first association); "
    "distinct from command-acceptance-only probe"
)

_DHCP_OPTIONAL_NOTE = (

    "DHCP optional (default off): IPv4 acquisition via ip address dhcp when caller needs IPv4; "

    "not required for admin up (summary.ipv4 may stay pending/disabled)"

)

_STANDBY_UNVERIFIED_NOTE = "standby for WISP not exercised in bounded probe; optional op only"

_WIFI_STATION_RCI = "router_control/adapters/netcraze/wifi_station_rci.py"
_STATION_PROBE_EVIDENCE = "station-wisp-grammar-probe-20260731.json"
_WIFI_STATION_FAMILY = "wifi_station"


def _station_sealed(op: str, lines: str) -> str:
    return f"wifi_station_rci.command_for {op} ({_WIFI_STATION_RCI}:{lines})"


_STATION_SEALED_LINES: dict[WifiStationRciOperation, str] = {
    WifiStationRciOperation.SET_SSID: _station_sealed("SET_SSID", "176-180"),
    WifiStationRciOperation.CLEAR_SSID: _station_sealed("CLEAR_SSID", "181-182"),
    WifiStationRciOperation.UP: _station_sealed("UP", "183-184"),
    WifiStationRciOperation.DOWN: _station_sealed("DOWN", "185-186"),
    WifiStationRciOperation.SET_WPA_PSK: _station_sealed("SET_WPA_PSK", "187-191"),
    WifiStationRciOperation.CLEAR_WPA_PSK: _station_sealed("CLEAR_WPA_PSK", "192-193"),
    WifiStationRciOperation.ENCRYPTION_ENABLE: _station_sealed("ENCRYPTION_ENABLE", "194-195"),
    WifiStationRciOperation.ENCRYPTION_DISABLE: _station_sealed("ENCRYPTION_DISABLE", "196-197"),
    WifiStationRciOperation.ENCRYPTION_WPA2: _station_sealed("ENCRYPTION_WPA2", "198-199"),
    WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR: _station_sealed(
        "ENCRYPTION_WPA2_CLEAR", "200-201"
    ),
    WifiStationRciOperation.IP_ADDRESS_DHCP: _station_sealed("IP_ADDRESS_DHCP", "233-234"),
    WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP: _station_sealed(
        "CLEAR_IP_ADDRESS_DHCP", "235-236"
    ),
    WifiStationRciOperation.CLEAR_IP_ADDRESS: _station_sealed("CLEAR_IP_ADDRESS", "237-238"),
    WifiStationRciOperation.SET_BSSID: _station_sealed("SET_BSSID", "206-210"),
    WifiStationRciOperation.IP_GLOBAL: _station_sealed("IP_GLOBAL", "223-232"),
    WifiStationRciOperation.STANDBY_ENABLE: _station_sealed("STANDBY_ENABLE", "216-217"),
    WifiStationRciOperation.STANDBY_TIMEOUT: _station_sealed("STANDBY_TIMEOUT", "218-222"),
}

_STATION_NEGATION_OPS = frozenset(
    {
        WifiStationRciOperation.CLEAR_SSID,
        WifiStationRciOperation.CLEAR_WPA_PSK,
        WifiStationRciOperation.ENCRYPTION_DISABLE,
        WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR,
        WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP,
        WifiStationRciOperation.CLEAR_IP_ADDRESS,
        WifiStationRciOperation.DOWN,
    }
)


def _wifi_station_op_notes(operation: WifiStationRciOperation) -> tuple[str, ...]:
    """Per-op grammar citations — sealed wifi_station_rci templates + registry doc anchors."""
    sealed = _STATION_SEALED_LINES.get(operation)
    if sealed is None:
        return ()
    extra: tuple[str, ...] = ()
    verification_kind: str | None = None
    if operation in {
        WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP,
        WifiStationRciOperation.CLEAR_IP_ADDRESS,
    }:
        extra = ("command no ip address ack matched in grammar probe",)
    if operation is WifiStationRciOperation.SET_BSSID:
        extra = ("help-derived only — not device-confirmed",)
    if operation in {
        WifiStationRciOperation.STANDBY_ENABLE,
        WifiStationRciOperation.STANDBY_TIMEOUT,
    }:
        extra = ("help-derived — not exercised",)
    if operation is WifiStationRciOperation.IP_GLOBAL:
        verification_kind = "positive form device-exercised"
        extra = ("negation not device-confirmed — rollback.uncovered_ops when apply succeeds",)
    return build_planner_op_notes(
        _WIFI_STATION_FAMILY,
        operation.value,
        sealed_template=sealed,
        negation=operation in _STATION_NEGATION_OPS,
        verification_kind=verification_kind,
        extra=extra,
    )





class WifiStationAuthMode(StrEnum):

    WPA2_PSK = "wpa2_psk"

    OPEN = "open"





class WifiStationApplyPlannerError(ValueError):

    """Fail-closed compiler error for Wi-Fi station apply planning."""





@dataclass(frozen=True, slots=True)

class WifiStationPlannerOptions:

    auth_mode: WifiStationAuthMode = WifiStationAuthMode.WPA2_PSK

    include_encryption_wpa2: bool = True

    include_dhcp_client: bool = False

    include_ip_global: bool = False

    include_standby: bool = False

    standby_timeout_seconds: int | None = None





@dataclass(frozen=True, slots=True)

class WifiStationSealedOpDescriptor:

    operation: str

    station_id: str

    ssid: str | None = None

    credential_ref_id: str | None = None

    bssid: str | None = None

    priority: int | None = None

    standby_timeout_seconds: int | None = None

    notes: tuple[str, ...] = ()





@dataclass(frozen=True, slots=True)

class WifiStationApplyPlan:

    station_id: str

    apply_ops: tuple[WifiStationSealedOpDescriptor, ...]

    teardown_ops: tuple[WifiStationSealedOpDescriptor, ...]

    grammar_verification_status: str

    planned_uplink_verification_level: str

    verification_status: str

    notes: tuple[str, ...] = ()





def station_id_for_band(band: WifiBand) -> str:

    if band == WifiBand.BAND_2_4GHZ:

        return "WifiMaster0/WifiStation0"

    if band == WifiBand.BAND_5GHZ:

        return "WifiMaster1/WifiStation0"

    raise WifiStationApplyPlannerError(f"unsupported band: {band.value}")





def _require_wifi_wan(intent: UplinkIntent) -> None:

    if intent.mode != UplinkMode.WIFI_WAN:

        raise WifiStationApplyPlannerError(

            f"station compiler requires UplinkMode.WIFI_WAN, got {intent.mode.value}"

        )





def _require_credential(intent: UplinkIntent, options: WifiStationPlannerOptions) -> None:

    if options.auth_mode is WifiStationAuthMode.OPEN:

        raise WifiStationApplyPlannerError(_MSG_OPEN_UNSUPPORTED)

    if not intent.credential_ref_id:

        raise WifiStationApplyPlannerError(ERROR_CODE_CREDENTIAL_REF_REQUIRED)





def _reject_captive_portal(intent: UplinkIntent) -> None:

    if intent.captive_portal_client:

        raise WifiStationApplyPlannerError(

            "captive_portal_client is unsupported for station apply (no verified grammar)"

        )





def _wpa2_apply_ops(

    station_id: str,

    intent: UplinkIntent,

    options: WifiStationPlannerOptions,

) -> tuple[WifiStationSealedOpDescriptor, ...]:

    ops: list[WifiStationSealedOpDescriptor] = [

        WifiStationSealedOpDescriptor(

            operation=WifiStationRciOperation.SET_SSID.value,

            station_id=station_id,

            ssid=intent.ssid,

            notes=_wifi_station_op_notes(WifiStationRciOperation.SET_SSID),

        ),

    ]

    if intent.bssid:

        ops.append(

            WifiStationSealedOpDescriptor(

                operation=WifiStationRciOperation.SET_BSSID.value,

                station_id=station_id,

                bssid=intent.bssid,

                notes=_wifi_station_op_notes(WifiStationRciOperation.SET_BSSID),

            )

        )

    if options.include_encryption_wpa2:

        ops.extend(

            [

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.ENCRYPTION_ENABLE.value,

                    station_id=station_id,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.ENCRYPTION_ENABLE)
                    + (_ENCRYPTION_DEFAULT_NOTE,),

                ),

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.ENCRYPTION_WPA2.value,

                    station_id=station_id,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.ENCRYPTION_WPA2)
                    + (_ENCRYPTION_DEFAULT_NOTE,),

                ),

            ]

        )

    ops.append(

        WifiStationSealedOpDescriptor(

            operation=WifiStationRciOperation.SET_WPA_PSK.value,

            station_id=station_id,

            credential_ref_id=intent.credential_ref_id,

            notes=_wifi_station_op_notes(WifiStationRciOperation.SET_WPA_PSK),

        )

    )

    if options.include_ip_global:

        ops.append(

            WifiStationSealedOpDescriptor(

                operation=WifiStationRciOperation.IP_GLOBAL.value,

                station_id=station_id,

                priority=intent.priority,

                notes=(
                    _wifi_station_op_notes(WifiStationRciOperation.IP_GLOBAL)
                    + (_IP_GLOBAL_STATION_EXERCISED_NOTE,)
                ),

            )

        )

    if options.include_dhcp_client:

        ops.append(

            WifiStationSealedOpDescriptor(

                operation=WifiStationRciOperation.IP_ADDRESS_DHCP.value,

                station_id=station_id,

                notes=(
                    _wifi_station_op_notes(WifiStationRciOperation.IP_ADDRESS_DHCP)
                    + (_DHCP_OPTIONAL_NOTE,)
                ),

            )

        )

    if options.include_standby:

        ops.append(

            WifiStationSealedOpDescriptor(

                operation=WifiStationRciOperation.STANDBY_ENABLE.value,

                station_id=station_id,

                notes=_wifi_station_op_notes(WifiStationRciOperation.STANDBY_ENABLE)
                + (_STANDBY_UNVERIFIED_NOTE,),

            )

        )

        if options.standby_timeout_seconds is not None:

            ops.append(

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.STANDBY_TIMEOUT.value,

                    station_id=station_id,

                    standby_timeout_seconds=options.standby_timeout_seconds,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.STANDBY_TIMEOUT)
                    + (_STANDBY_UNVERIFIED_NOTE,),

                )

            )

    ops.append(

        WifiStationSealedOpDescriptor(

            operation=WifiStationRciOperation.UP.value,

            station_id=station_id,

            notes=_wifi_station_op_notes(WifiStationRciOperation.UP),

        )

    )

    return tuple(ops)





def _wpa2_teardown_ops(

    station_id: str,

    options: WifiStationPlannerOptions,

) -> tuple[WifiStationSealedOpDescriptor, ...]:

    """Device-confirmed negations in reverse apply order (probe 2026-07-31)."""

    ops: list[WifiStationSealedOpDescriptor] = [

        WifiStationSealedOpDescriptor(

            operation=WifiStationRciOperation.DOWN.value,

            station_id=station_id,

            notes=_wifi_station_op_notes(WifiStationRciOperation.DOWN),

        ),

    ]

    if options.include_dhcp_client:

        ops.extend(

            [

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP.value,

                    station_id=station_id,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP),

                ),

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.CLEAR_IP_ADDRESS.value,

                    station_id=station_id,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.CLEAR_IP_ADDRESS),

                ),

            ]

        )

    ops.append(

        WifiStationSealedOpDescriptor(

            operation=WifiStationRciOperation.CLEAR_WPA_PSK.value,

            station_id=station_id,

            notes=_wifi_station_op_notes(WifiStationRciOperation.CLEAR_WPA_PSK),

        )

    )

    if options.include_encryption_wpa2:

        ops.extend(

            [

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value,

                    station_id=station_id,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR),

                ),

                WifiStationSealedOpDescriptor(

                    operation=WifiStationRciOperation.ENCRYPTION_DISABLE.value,

                    station_id=station_id,

                    notes=_wifi_station_op_notes(WifiStationRciOperation.ENCRYPTION_DISABLE),

                ),

            ]

        )

    ops.append(

        WifiStationSealedOpDescriptor(

            operation=WifiStationRciOperation.CLEAR_SSID.value,

            station_id=station_id,

            notes=_wifi_station_op_notes(WifiStationRciOperation.CLEAR_SSID),

        )

    )

    return tuple(ops)





def _compile_notes(options: WifiStationPlannerOptions) -> tuple[str, ...]:
    notes: list[str] = [_OFFLINE_NOTE, _UPLINK_LIMITS_NOTE, _UNVERIFIED_NEGATION_NOTE]
    if options.include_ip_global:
        notes.append(_IP_GLOBAL_PLAN_NOTE)
    return tuple(notes)




def compile_uplink_intent_to_station_ops(

    intent: UplinkIntent,

    *,

    options: WifiStationPlannerOptions | None = None,

    station_id: str | None = None,

) -> WifiStationApplyPlan:

    """Compile WifiWan UplinkIntent to sealed station ops (offline; grammar device-accepted)."""

    resolved_options = options or WifiStationPlannerOptions()

    _require_wifi_wan(intent)

    _reject_captive_portal(intent)

    if resolved_options.auth_mode is WifiStationAuthMode.OPEN:

        raise WifiStationApplyPlannerError(_MSG_OPEN_UNSUPPORTED)

    _require_credential(intent, resolved_options)

    if not intent.ssid:

        raise WifiStationApplyPlannerError(ERROR_CODE_SSID_REQUIRED)

    if (
        not resolved_options.include_ip_global
        and intent.priority != _DEFAULT_UPLINK_PRIORITY
    ):
        raise WifiStationApplyPlannerError(ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL)

    band = intent.band or WifiBand.BAND_2_4GHZ

    resolved_station = station_id or station_id_for_band(band)

    validate_wifi_station_id(resolved_station)

    expected_station = station_id_for_band(band)

    if resolved_station != expected_station:

        raise WifiStationApplyPlannerError(

            f"station_id {resolved_station!r} does not match band {band.value} "

            f"(expected {expected_station})"

        )

    apply_ops = _wpa2_apply_ops(resolved_station, intent, resolved_options)

    teardown_ops = _wpa2_teardown_ops(resolved_station, resolved_options)

    return WifiStationApplyPlan(

        station_id=resolved_station,

        apply_ops=apply_ops,

        teardown_ops=teardown_ops,

        grammar_verification_status=_GRAMMAR_STATUS,

        planned_uplink_verification_level=_UPLINK_PLAN_LEVEL,

        verification_status=_GRAMMAR_STATUS,

        notes=_compile_notes(resolved_options),

    )





__all__ = [
    "WifiStationApplyPlan",
    "WifiStationApplyPlannerError",
    "WifiStationAuthMode",
    "WifiStationPlannerOptions",
    "WifiStationSealedOpDescriptor",
    "IP_GLOBAL_DEFAULT_ROUTE_SETTLE_SECONDS_MIN",
    "IP_GLOBAL_DEFAULT_ROUTE_SETTLE_SECONDS_MAX",
    "clamp_uplink_settle_seconds",
    "compensate_ops_for_succeeded_station_apply",
    "compile_uplink_intent_to_station_ops",
    "station_id_for_band",
]

IP_GLOBAL_DEFAULT_ROUTE_SETTLE_SECONDS_MIN = _IP_GLOBAL_SETTLE_SECONDS_MIN
IP_GLOBAL_DEFAULT_ROUTE_SETTLE_SECONDS_MAX = _IP_GLOBAL_SETTLE_SECONDS_MAX


def clamp_uplink_settle_seconds(value: float) -> float:
    """Return 0 (no wait) or clamp caller-supplied settle into [20, 30] seconds."""
    if value <= 0:
        return 0.0
    return float(
        max(_IP_GLOBAL_SETTLE_SECONDS_MIN, min(_IP_GLOBAL_SETTLE_SECONDS_MAX, value))
    )


_STATION_UNCOVERED_COMPENSATION_REASON = (
    "no sealed negation grammar (unverified; "
    "docs/OPERATOR_WIFI_DISCOVERY.md §2c: ip global negation not device-confirmed)"
)

_APPLY_TO_COMPENSATE: dict[str, str] = {
    WifiStationRciOperation.SET_SSID.value: WifiStationRciOperation.CLEAR_SSID.value,
    WifiStationRciOperation.SET_WPA_PSK.value: WifiStationRciOperation.CLEAR_WPA_PSK.value,
    WifiStationRciOperation.ENCRYPTION_ENABLE.value: (
        WifiStationRciOperation.ENCRYPTION_DISABLE.value
    ),
    WifiStationRciOperation.ENCRYPTION_WPA2.value: (
        WifiStationRciOperation.ENCRYPTION_WPA2_CLEAR.value
    ),
    WifiStationRciOperation.UP.value: WifiStationRciOperation.DOWN.value,
    WifiStationRciOperation.IP_ADDRESS_DHCP.value: (
        WifiStationRciOperation.CLEAR_IP_ADDRESS_DHCP.value
    ),
}

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_PSK_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply PSK state unknown; clear would destroy foreign state"
)
_DHCP_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply DHCP client state unknown; clear would destroy foreign state"
)


@dataclass(frozen=True, slots=True)
class WifiStationApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    had_ssid: bool = False
    had_psk: bool | None = None
    encryption_enabled: bool = False
    had_wpa2: bool = False
    was_admin_up: bool = False
    had_dhcp_client: bool | None = None


def derive_wifi_station_pre_state(
    readback: dict[str, Any],
    *,
    raw_configured: Any | None = None,
) -> WifiStationApplyPreState:
    """Derive compensation baseline from pre-apply station readback."""
    sanitized = {str(key): value for key, value in readback.items()}
    configured_ssid = readback.get("configured_ssid")
    had_ssid = ssid_present(configured_ssid)
    encryption_raw = readback.get("configured_encryption")
    encryption_enabled = (
        not encryption_empty(encryption_raw) and not encryption_indicates_open(encryption_raw)
    )
    had_wpa2 = encryption_indicates_wpa2(encryption_raw)
    was_admin_up = state_is_up(readback.get("state"))
    had_psk = (
        derive_key_configured(raw_configured, sanitized) if raw_configured is not None else None
    )
    if (
        had_psk is None
        and raw_configured is not None
        and encryption_indicates_open(encryption_raw)
    ):
        had_psk = False
    configured_dhcp = readback.get("configured_dhcp_client")
    if configured_dhcp is None and raw_configured is not None:
        configured_dhcp = derive_dhcp_client_configured(raw_configured)
    had_dhcp: bool | None
    if configured_dhcp is None:
        had_dhcp = None
    else:
        had_dhcp = bool(configured_dhcp)
    return WifiStationApplyPreState(
        known=True,
        had_ssid=had_ssid,
        had_psk=had_psk,
        encryption_enabled=encryption_enabled,
        had_wpa2=had_wpa2,
        was_admin_up=was_admin_up,
        had_dhcp_client=had_dhcp,
    )


def _station_compensation_blocked_reason(
    apply_op: str,
    pre_state: WifiStationApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == WifiStationRciOperation.SET_SSID.value and pre_state.had_ssid:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiStationRciOperation.SET_WPA_PSK.value:
        if pre_state.had_psk is None:
            return _PSK_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_psk:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiStationRciOperation.ENCRYPTION_ENABLE.value and pre_state.encryption_enabled:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiStationRciOperation.ENCRYPTION_WPA2.value and pre_state.had_wpa2:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiStationRciOperation.UP.value and pre_state.was_admin_up:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiStationRciOperation.IP_ADDRESS_DHCP.value:
        if pre_state.had_dhcp_client is None:
            return _DHCP_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_dhcp_client:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None


def compensate_ops_for_succeeded_station_apply(
    apply_ops: tuple[WifiStationSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: WifiStationApplyPreState | None = None,
) -> tuple[WifiStationSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    name_to_desc = {op.operation: op for op in apply_ops}
    compensate: list[WifiStationSealedOpDescriptor] = []
    for op_name in reversed(succeeded_op_names):
        compensate_op = _APPLY_TO_COMPENSATE.get(op_name)
        if compensate_op is None:
            continue
        if _station_compensation_blocked_reason(op_name, pre_state) is not None:
            continue
        orig = name_to_desc.get(op_name)
        if orig is None:
            continue
        compensate.append(
            WifiStationSealedOpDescriptor(
                operation=compensate_op,
                station_id=orig.station_id,
                priority=orig.priority,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_station_apply(
    apply_ops: tuple[WifiStationSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: WifiStationApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return apply op names that succeeded but have no sealed compensating operation."""
    name_to_desc = {op.operation: op for op in apply_ops}
    uncovered: list[tuple[str, str]] = []
    for op_name in succeeded_op_names:
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _station_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
        if op_name not in name_to_desc:
            continue
        uncovered.append((op_name, _STATION_UNCOVERED_COMPENSATION_REASON))
    return tuple(uncovered)
