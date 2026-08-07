"""Offline Wi-Fi intent → sealed RCI op descriptor compiler.

WPA2, WPA3-Personal, and WPA2_WPA3_MIXED apply/teardown sequences are
device-verified (NC-1812, 2026-07-24). WPA3 uses ``authentication wpa-psk`` +
``encryption wpa3`` (no ``authentication sae``). WPA2_WPA3_MIXED uses
``encryption wpa2`` + ``encryption wpa3`` with readback ``wpa2,wpa3``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.allowlist import validate_wifi_ap_id
from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation
from router_control.application.grammar_doc_refs import (
    build_planner_op_notes,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
    derive_key_configured,
    encryption_empty,
    encryption_indicates_open,
    encryption_indicates_wpa2,
    encryption_indicates_wpa3,
    ssid_present,
    state_is_up,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)

_WPA3_DEVICE_VERIFIED_NOTE = (
    "WPA3-Personal uses authentication wpa-psk + encryption wpa3 per Keenetic CLI Reference "
    "(KN-1812 / KeeneticOS 5.0); encryption wpa3 History 3.00; no authentication sae command; "
    "device-verified on NC-1812 firmware 5.01.C.1.0-0 (2026-07-24)"
)
_MIXED_DEVICE_VERIFIED_NOTE = (
    "WPA2+WPA3 mixed uses authentication wpa-psk + encryption wpa2 + encryption wpa3 per "
    "Keenetic CLI Reference (KN-1812 / KeeneticOS 5.0); readback wpa2,wpa3; "
    "no authentication sae command; "
    "device-verified on NC-1812 firmware 5.01.C.1.0-0 (2026-07-24)"
)

_WIFI_RCI = "router_control/adapters/netcraze/wifi_rci.py"
_WIFI_AP_FAMILY = "wifi_ap"


def _wifi_sealed(op: str, line: str) -> str:
    return f"wifi_rci.command_for {op} ({_WIFI_RCI}:{line})"


_WIFI_AP_SEALED_LINES: dict[WifiApRciOperation, str] = {
    WifiApRciOperation.SET_SSID: _wifi_sealed("SET_SSID", "131"),
    WifiApRciOperation.CLEAR_SSID: _wifi_sealed("CLEAR_SSID", "133"),
    WifiApRciOperation.UP: _wifi_sealed("UP", "135"),
    WifiApRciOperation.DOWN: _wifi_sealed("DOWN", "137"),
    WifiApRciOperation.SET_WPA_PSK: _wifi_sealed("SET_WPA_PSK", "142"),
    WifiApRciOperation.CLEAR_WPA_PSK: _wifi_sealed("CLEAR_WPA_PSK", "144"),
    WifiApRciOperation.ENCRYPTION_ENABLE: _wifi_sealed("ENCRYPTION_ENABLE", "146"),
    WifiApRciOperation.ENCRYPTION_DISABLE: _wifi_sealed("ENCRYPTION_DISABLE", "148"),
    WifiApRciOperation.ENCRYPTION_WPA2: _wifi_sealed("ENCRYPTION_WPA2", "150"),
    WifiApRciOperation.ENCRYPTION_WPA2_CLEAR: _wifi_sealed("ENCRYPTION_WPA2_CLEAR", "152"),
    WifiApRciOperation.ENCRYPTION_WPA3: _wifi_sealed("ENCRYPTION_WPA3", "154"),
    WifiApRciOperation.ENCRYPTION_WPA3_CLEAR: _wifi_sealed("ENCRYPTION_WPA3_CLEAR", "156"),
}


def _wifi_ap_op_notes(operation: WifiApRciOperation) -> tuple[str, ...]:
    """Per-op grammar citations — sealed wifi_rci templates + registry doc anchors."""
    sealed = _WIFI_AP_SEALED_LINES.get(operation)
    if sealed is None:
        return ()
    negation = operation in {
        WifiApRciOperation.CLEAR_SSID,
        WifiApRciOperation.CLEAR_WPA_PSK,
        WifiApRciOperation.ENCRYPTION_DISABLE,
        WifiApRciOperation.ENCRYPTION_WPA2_CLEAR,
        WifiApRciOperation.ENCRYPTION_WPA3_CLEAR,
        WifiApRciOperation.DOWN,
    }
    verification_kind = "device-verified rollback" if operation is WifiApRciOperation.DOWN else None
    extra: tuple[str, ...] = ()
    if operation is WifiApRciOperation.ENCRYPTION_WPA3:
        extra = (_WPA3_DEVICE_VERIFIED_NOTE,)
    if operation is WifiApRciOperation.ENCRYPTION_WPA3_CLEAR:
        extra = ("ack matched wifi_ap_encryption_wpa3_clear",)
    return build_planner_op_notes(
        _WIFI_AP_FAMILY,
        operation.value,
        sealed_template=sealed,
        negation=negation,
        verification_kind=verification_kind,
        extra=extra,
    )


class WifiApplyPlannerError(ValueError):
    """Fail-closed compiler error for Wi-Fi apply planning."""


@dataclass(frozen=True, slots=True)
class WifiSealedOpDescriptor:
    operation: str
    ap_id: str
    ssid: str | None = None
    credential_ref_id: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class WifiApplyPlan:
    ap_id: str
    apply_ops: tuple[WifiSealedOpDescriptor, ...]
    teardown_ops: tuple[WifiSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...] = ()


def wifi_master_for_band(band: WifiBand) -> str:
    if band == WifiBand.BAND_2_4GHZ:
        return "WifiMaster0"
    if band == WifiBand.BAND_5GHZ:
        return "WifiMaster1"
    raise WifiApplyPlannerError(f"unsupported band: {band.value}")


def _validate_band_matches_ap_id(ap_id: str, band: WifiBand) -> None:
    expected = wifi_master_for_band(band)
    if not ap_id.startswith(f"{expected}/"):
        raise WifiApplyPlannerError(
            f"ap_id {ap_id!r} does not match intent band {band.value} (expected {expected})"
        )


def _require_credential_ref(intent: WifiIntent, label: str) -> None:
    if not intent.credential_ref_id:
        raise WifiApplyPlannerError(ERROR_CODE_CREDENTIAL_REF_REQUIRED)


def _wpa2_apply_ops(ap_id: str, intent: WifiIntent) -> tuple[WifiSealedOpDescriptor, ...]:
    if not intent.enabled:
        return ()
    _require_credential_ref(intent, "WPA2")
    return (
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.SET_SSID.value,
            ap_id=ap_id,
            ssid=intent.ssid,
            notes=_wifi_ap_op_notes(WifiApRciOperation.SET_SSID),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.SET_WPA_PSK.value,
            ap_id=ap_id,
            credential_ref_id=intent.credential_ref_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.SET_WPA_PSK),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_ENABLE.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_ENABLE),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA2.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA2),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.UP.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.UP),
        ),
    )


def _wpa2_teardown_ops(ap_id: str) -> tuple[WifiSealedOpDescriptor, ...]:
    return (
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.DOWN.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.DOWN),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA2_CLEAR.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA2_CLEAR),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_DISABLE.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_DISABLE),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.CLEAR_WPA_PSK.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.CLEAR_WPA_PSK),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.CLEAR_SSID.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.CLEAR_SSID),
        ),
    )


def _wpa3_apply_ops(ap_id: str, intent: WifiIntent) -> tuple[WifiSealedOpDescriptor, ...]:
    if not intent.enabled:
        return ()
    _require_credential_ref(intent, "WPA3")
    return (
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.SET_SSID.value,
            ap_id=ap_id,
            ssid=intent.ssid,
            notes=_wifi_ap_op_notes(WifiApRciOperation.SET_SSID),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.SET_WPA_PSK.value,
            ap_id=ap_id,
            credential_ref_id=intent.credential_ref_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.SET_WPA_PSK),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_ENABLE.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_ENABLE),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA3.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA3),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.UP.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.UP),
        ),
    )


def _wpa3_teardown_ops(ap_id: str) -> tuple[WifiSealedOpDescriptor, ...]:
    return (
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.DOWN.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.DOWN),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA3_CLEAR.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA3_CLEAR),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_DISABLE.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_DISABLE),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.CLEAR_WPA_PSK.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.CLEAR_WPA_PSK),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.CLEAR_SSID.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.CLEAR_SSID),
        ),
    )


def _mixed_apply_ops(ap_id: str, intent: WifiIntent) -> tuple[WifiSealedOpDescriptor, ...]:
    if not intent.enabled:
        return ()
    _require_credential_ref(intent, "WPA2+WPA3 mixed")
    return (
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.SET_SSID.value,
            ap_id=ap_id,
            ssid=intent.ssid,
            notes=_wifi_ap_op_notes(WifiApRciOperation.SET_SSID),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.SET_WPA_PSK.value,
            ap_id=ap_id,
            credential_ref_id=intent.credential_ref_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.SET_WPA_PSK),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_ENABLE.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_ENABLE),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA2.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA2),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA3.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA3),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.UP.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.UP),
        ),
    )


def _mixed_teardown_ops(ap_id: str) -> tuple[WifiSealedOpDescriptor, ...]:
    return (
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.DOWN.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.DOWN),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA3_CLEAR.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA3_CLEAR),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_WPA2_CLEAR.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_WPA2_CLEAR),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.ENCRYPTION_DISABLE.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.ENCRYPTION_DISABLE),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.CLEAR_WPA_PSK.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.CLEAR_WPA_PSK),
        ),
        WifiSealedOpDescriptor(
            operation=WifiApRciOperation.CLEAR_SSID.value,
            ap_id=ap_id,
            notes=_wifi_ap_op_notes(WifiApRciOperation.CLEAR_SSID),
        ),
    )


def _reject_unsupported_intent_fields(intent: WifiIntent) -> None:
    if intent.guest_isolation:
        raise WifiApplyPlannerError(ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED)
    if intent.captive_portal == CaptivePortalMode.ENABLED:
        raise WifiApplyPlannerError(ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED)


def compile_wifi_intent_to_ops(intent: WifiIntent, ap_id: str) -> WifiApplyPlan:
    _reject_unsupported_intent_fields(intent)
    normalized_ap_id = validate_wifi_ap_id(ap_id)
    _validate_band_matches_ap_id(normalized_ap_id, intent.band)

    if intent.wpa_mode == WifiWpaMode.WPA2:
        return WifiApplyPlan(
            ap_id=normalized_ap_id,
            apply_ops=_wpa2_apply_ops(normalized_ap_id, intent),
            teardown_ops=_wpa2_teardown_ops(normalized_ap_id),
            verification_status="device_verified_wpa2",
        )

    if intent.wpa_mode == WifiWpaMode.WPA3:
        return WifiApplyPlan(
            ap_id=normalized_ap_id,
            apply_ops=_wpa3_apply_ops(normalized_ap_id, intent),
            teardown_ops=_wpa3_teardown_ops(normalized_ap_id),
            verification_status="device_verified_wpa2",
            notes=(_WPA3_DEVICE_VERIFIED_NOTE,),
        )

    if intent.wpa_mode == WifiWpaMode.WPA2_WPA3_MIXED:
        return WifiApplyPlan(
            ap_id=normalized_ap_id,
            apply_ops=_mixed_apply_ops(normalized_ap_id, intent),
            teardown_ops=_mixed_teardown_ops(normalized_ap_id),
            verification_status="device_verified_wpa2",
            notes=(_MIXED_DEVICE_VERIFIED_NOTE,),
        )

    raise WifiApplyPlannerError(f"unsupported wpa_mode: {intent.wpa_mode.value}")


_APPLY_TO_COMPENSATE: dict[str, str] = {
    WifiApRciOperation.SET_SSID.value: WifiApRciOperation.CLEAR_SSID.value,
    WifiApRciOperation.SET_WPA_PSK.value: WifiApRciOperation.CLEAR_WPA_PSK.value,
    WifiApRciOperation.ENCRYPTION_ENABLE.value: WifiApRciOperation.ENCRYPTION_DISABLE.value,
    WifiApRciOperation.ENCRYPTION_WPA2.value: WifiApRciOperation.ENCRYPTION_WPA2_CLEAR.value,
    WifiApRciOperation.ENCRYPTION_WPA3.value: WifiApRciOperation.ENCRYPTION_WPA3_CLEAR.value,
    WifiApRciOperation.UP.value: WifiApRciOperation.DOWN.value,
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


@dataclass(frozen=True, slots=True)
class WifiApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    had_ssid: bool = False
    had_psk: bool | None = None
    encryption_enabled: bool = False
    had_wpa2: bool = False
    had_wpa3: bool = False
    was_admin_up: bool = False


def derive_wifi_pre_state(
    observed: dict[str, Any],
    *,
    raw: Any | None = None,
) -> WifiApplyPreState:
    """Derive compensation baseline from a pre-apply ``show interface`` observation."""
    sanitized = {str(key): value for key, value in observed.items()}
    had_ssid = ssid_present(observed.get("ssid"))
    encryption = observed.get("encryption")
    encryption_enabled = (
        not encryption_empty(encryption) and not encryption_indicates_open(encryption)
    )
    had_wpa2 = encryption_indicates_wpa2(encryption)
    had_wpa3 = encryption_indicates_wpa3(encryption)
    was_admin_up = state_is_up(observed.get("state")) or state_is_up(observed.get("up"))
    had_psk = derive_key_configured(raw, sanitized) if raw is not None else None
    if had_psk is None and raw is not None and encryption_indicates_open(encryption):
        had_psk = False
    return WifiApplyPreState(
        known=True,
        had_ssid=had_ssid,
        had_psk=had_psk,
        encryption_enabled=encryption_enabled,
        had_wpa2=had_wpa2,
        had_wpa3=had_wpa3,
        was_admin_up=was_admin_up,
    )


def _wifi_compensation_blocked_reason(
    apply_op: str,
    pre_state: WifiApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == WifiApRciOperation.SET_SSID.value and pre_state.had_ssid:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiApRciOperation.SET_WPA_PSK.value:
        if pre_state.had_psk is None:
            return _PSK_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_psk:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiApRciOperation.ENCRYPTION_ENABLE.value and pre_state.encryption_enabled:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiApRciOperation.ENCRYPTION_WPA2.value and pre_state.had_wpa2:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiApRciOperation.ENCRYPTION_WPA3.value and pre_state.had_wpa3:
        return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == WifiApRciOperation.UP.value and pre_state.was_admin_up:
        return _PRE_EXISTING_COMPENSATION_REASON
    return None


def compensate_ops_for_succeeded_apply(
    apply_ops: tuple[WifiSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: WifiApplyPreState | None = None,
) -> tuple[WifiSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    name_to_desc = {op.operation: op for op in apply_ops}
    compensate: list[WifiSealedOpDescriptor] = []
    for op_name in reversed(succeeded_op_names):
        compensate_op = _APPLY_TO_COMPENSATE.get(op_name)
        if compensate_op is None:
            continue
        if _wifi_compensation_blocked_reason(op_name, pre_state) is not None:
            continue
        orig = name_to_desc.get(op_name)
        if orig is None:
            continue
        compensate.append(
            WifiSealedOpDescriptor(
                operation=compensate_op,
                ap_id=orig.ap_id,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_apply(
    apply_ops: tuple[WifiSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: WifiApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return succeeded apply ops whose compensation is blocked or unverified."""
    name_to_desc = {op.operation: op for op in apply_ops}
    uncovered: list[tuple[str, str]] = []
    for op_name in succeeded_op_names:
        blocked = _wifi_compensation_blocked_reason(op_name, pre_state)
        if blocked is not None:
            if op_name in _APPLY_TO_COMPENSATE or op_name in name_to_desc:
                uncovered.append((op_name, blocked))
            continue
        if op_name in _APPLY_TO_COMPENSATE:
            continue
        if op_name not in name_to_desc:
            continue
    return tuple(uncovered)
