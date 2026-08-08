"""Wi-Fi station (WISP) Configure → Apply service (injected transport; offline + live paths).

Preview/build is deterministic and safe offline. ``apply_wifi_station_intent`` requires an
explicit injected transport. Offline fake transports must set ``wifi_station_offline_only``;
live dispatch requires ``wifi_station_live_dispatch`` and explicit ``live_dispatch=True``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast

from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_station_rci import (
    WifiStationRciError,
    WifiStationRciOperation,
    WifiStationRciResult,
    execute_wifi_station_rci,
    validate_wifi_station_id,
)
from router_control.application.apply_pre_read import execute_pre_apply_read
from router_control.application.apply_types import ApplyOverallStatus, ApplyRollbackOutcome
from router_control.application.recovery import (
    SealedApplyTrailHandle,
    SealedApplyTrailParams,
    begin_sealed_apply_trail,
    build_sealed_apply_op_evidence,
    finish_sealed_apply_trail,
    guard_sealed_apply_trail,
    outcome_snapshot_from_apply_result,
    redact_sealed_apply_device_ack,
    serialize_pre_apply_baseline_for_trail,
    sleep_preserving_sealed_apply_lease,
)
from router_control.application.verdict_explanation import (
    VerdictExplanation,
    VerdictMissingSignalCode,
    VerdictObservation,
    VerdictRejectedSignal,
    VerdictSignalReading,
    _append_unique_missing,
    _append_unique_rejected,
    _state_is_up_token,
    assert_verdict_explanation_invariant,
    assert_verdict_observation,
    explanation_for_skipped_observe,
    normalize_counter,
    normalize_up_down,
    normalize_yes_no,
    validate_wifi_station_apply_payload,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    ERROR_CODE_OP_DISPATCH_FAILED,
    ERROR_CODE_READBACK_FAILED,
    ERROR_CODE_UNSUPPORTED_OPERATION,
    parse_station_interface_readback,
    resolve_device_connected,
    resolve_link_up,
    sanitize_show_rc_interface_raw,
    sanitize_station_readback_dict,
    scrub_error_message,
    ssid_present,
    walk_for_keys,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlan,
    WifiStationApplyPlannerError,
    WifiStationApplyPreState,
    WifiStationPlannerOptions,
    WifiStationSealedOpDescriptor,
    clamp_uplink_settle_seconds,
    compensate_ops_for_succeeded_station_apply,
    compile_uplink_intent_to_station_ops,
    derive_wifi_station_pre_state,
    uncovered_compensate_ops_for_succeeded_station_apply,
)
from router_control.domain.network_intents import UplinkIntent

# Upstream SSIDs from device readback are operator secrets at the API boundary.
_STATION_READBACK_API_SECRET_KEYS = frozenset(
    {"configured_ssid", "associated_ssid", "ssid", "bssid"}
)


def _sanitize_uplink_readback_for_api(readback: dict[str, object]) -> dict[str, object]:
    """Redact upstream SSID/BSSID values before HTTP serialization."""
    sanitized = sanitize_station_readback_dict(readback)
    result: dict[str, object] = {}
    for key, value in sanitized.items():
        norm = str(key).lower().replace("-", "_")
        if norm in _STATION_READBACK_API_SECRET_KEYS and value is not None:
            result[str(key)] = "REDACTED"
        else:
            result[str(key)] = value
    return result


CredentialResolver = Callable[[str], str]
BackupCallback = Callable[[], None]
SleepFn = Callable[[float], None]

_MSG_LIVE_DISPATCH_DISABLED = (
    "live Wi-Fi station apply dispatch is disabled; inject transport for offline tests only"
)
_MSG_OP_DISPATCH_FAILED = ERROR_CODE_OP_DISPATCH_FAILED
_MSG_CREDENTIAL_RESOLUTION_FAILED = ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED
_MSG_READBACK_FAILED = ERROR_CODE_READBACK_FAILED
_SECRET_DISPATCH_OPS = frozenset({WifiStationRciOperation.SET_WPA_PSK.value})


def _dispatch_failure_detail(op_name: str, exc: BaseException) -> str:
    if op_name in _SECRET_DISPATCH_OPS:
        return _MSG_OP_DISPATCH_FAILED
    return scrub_error_message(f"{type(exc).__name__}: {exc}")

_UPLINK_DISPATCHED_UNVERIFIED = "uplink_dispatched_unverified"
_UPLINK_ASSOCIATED_NO_GLOBAL = "uplink_associated_no_global"
_UPLINK_VERIFIED_BOUNDED = "uplink_verified_bounded"
_UPLINK_FAILED = "uplink_failed"

_INTERNET_STATUS_KEYS = frozenset({"internet", "gateway", "dns"})


def _unused_teardown_credential_resolver(_ref: str) -> str:
    return "unused-for-teardown"


class WifiStationApplyServiceError(ValueError):
    """Fail-closed Wi-Fi station apply service error."""


class WifiStationApplyTransport(Protocol):
    wifi_station_offline_only: Literal[True]

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...


class WifiStationLiveTransport(Protocol):
    wifi_station_live_dispatch: Literal[True]

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...

    def execute_rci_parse(self, cli_command: str) -> Any: ...


def require_wifi_station_offline_transport(transport: object) -> None:
    if getattr(transport, "wifi_station_offline_only", False) is not True:
        raise WifiStationApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)


def require_wifi_station_live_transport(transport: object) -> None:
    if getattr(transport, "wifi_station_live_dispatch", False) is not True:
        raise WifiStationApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    if getattr(transport, "wifi_station_offline_only", False) is True:
        raise WifiStationApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)


def _validate_transport_marker(transport: object, *, live_dispatch: bool) -> None:
    if live_dispatch:
        require_wifi_station_live_transport(transport)
    else:
        require_wifi_station_offline_transport(transport)


@dataclass(frozen=True, slots=True)
class WifiStationApplyStep:
    op: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"op": self.op, "ok": self.ok}
        if self.status_ident is not None:
            payload["status_ident"] = self.status_ident
        if self.error is not None:
            payload["error"] = self.error
        return payload


@dataclass(frozen=True, slots=True)
class WifiStationApplyUncoveredRollbackOp:
    op: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class WifiStationApplyRollback:
    attempted: bool
    ops: tuple[str, ...]
    outcome: ApplyRollbackOutcome
    steps: tuple[WifiStationApplyStep, ...] = ()
    uncovered_ops: tuple[WifiStationApplyUncoveredRollbackOp, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "attempted": self.attempted,
            "ops": list(self.ops),
            "outcome": self.outcome,
        }
        if self.steps:
            payload["steps"] = [step.to_dict() for step in self.steps]
        if self.uncovered_ops:
            payload["uncovered_ops"] = [item.to_dict() for item in self.uncovered_ops]
        return payload


@dataclass(frozen=True, slots=True)
class WifiStationApplyResult:
    overall: ApplyOverallStatus
    station_id: str
    verification_status: str
    grammar_verification_status: str
    uplink_verification_status: str
    steps: tuple[WifiStationApplyStep, ...]
    errors: tuple[str, ...]
    logs: tuple[str, ...]
    notes: tuple[str, ...] = ()
    backup_basename: str | None = None
    backup_content_sha256: str | None = None
    rollback: WifiStationApplyRollback | None = None
    uplink_readback: dict[str, object] | None = None
    uplink_settle_seconds: float | None = None
    verdict_explanation: VerdictExplanation | None = None
    rollback_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "overall": self.overall,
            "station_id": self.station_id,
            "verification_status": self.verification_status,
            "grammar_verification_status": self.grammar_verification_status,
            "uplink_verification_status": self.uplink_verification_status,
            "notes": list(self.notes),
            "steps": [step.to_dict() for step in self.steps],
            "errors": list(self.errors),
            "rollback_errors": list(self.rollback_errors),
            "logs": list(self.logs),
        }
        if self.verdict_explanation is not None:
            payload["verdict_explanation"] = self.verdict_explanation.to_dict()
        if self.backup_basename is not None:
            payload["backup_basename"] = self.backup_basename
        if self.backup_content_sha256 is not None:
            payload["backup_content_sha256"] = self.backup_content_sha256
        if self.rollback is not None:
            payload["rollback"] = self.rollback.to_dict()
        if self.uplink_readback is not None:
            payload["uplink_readback"] = _sanitize_uplink_readback_for_api(self.uplink_readback)
        if self.uplink_settle_seconds is not None:
            payload["uplink_settle_seconds"] = self.uplink_settle_seconds
        return validate_wifi_station_apply_payload(payload)


def _parse_yes_no(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"yes", "true", "1"}:
        return True
    if text in {"no", "false", "0"}:
        return False
    return None


def _parse_counter(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _readback_has_deceptive_uplink_signals(readback: dict[str, Any]) -> bool:
    """Reject link/connected/byte counters that must not imply healthy uplink."""
    link_up = resolve_link_up(readback)
    connected = resolve_device_connected(readback)
    if connected is True and link_up is False:
        return True
    txbytes = readback.get("txbytes", readback.get("tx_bytes"))
    rxbytes = readback.get("rxbytes", readback.get("rx_bytes"))
    if txbytes is not None and rxbytes is not None:
        tx = _parse_counter(txbytes)
        rx = _parse_counter(rxbytes)
        if tx is not None and rx is not None and tx > 0 and rx == 0:
            return True
    state = readback.get("state")
    if state is not None and str(state).strip().lower() in {"up", "enabled", "true", "1"}:
        if link_up is False:
            return True
    return False


def _internet_status_affirmative(internet_status: dict[str, Any] | None) -> bool | None:
    """Return True when internet/gateway/dns are all yes; False if any explicit no; else None."""
    if not internet_status:
        return None
    found = walk_for_keys(internet_status, _INTERNET_STATUS_KEYS)
    if not found:
        return None
    verdicts: list[bool | None] = []
    for key in ("internet", "gateway", "dns"):
        parsed = _parse_yes_no(found.get(key))
        verdicts.append(parsed)
    if any(item is False for item in verdicts):
        return False
    if all(item is True for item in verdicts):
        return True
    return None


def _collect_uplink_deceptive_rejections(
    readback: dict[str, Any],
    rejected: list[VerdictRejectedSignal],
) -> None:
    link_up = resolve_link_up(readback)
    connected = resolve_device_connected(readback)
    if connected is True and link_up is False:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("connected", "connected_with_link_down"),
        )
    txbytes = readback.get("txbytes", readback.get("tx_bytes"))
    rxbytes = readback.get("rxbytes", readback.get("rx_bytes"))
    if txbytes is not None and rxbytes is not None:
        tx = _parse_counter(txbytes)
        rx = _parse_counter(rxbytes)
        if tx is not None and rx is not None and tx > 0 and rx == 0:
            _append_unique_rejected(
                rejected,
                VerdictRejectedSignal("txbytes", "txbytes_without_rxbytes"),
            )
    state = readback.get("state")
    if state is not None and _state_is_up_token(state) and link_up is False:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("state", "state_up_with_link_down"),
        )
    if readback.get("auth-type") is not None or readback.get("auth_type") is not None:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("connected", "auth_type_not_evidence"),
        )


def _read_uplink_signals(
    readback: dict[str, Any],
    *,
    intended_ssid: str,
    internet_status: dict[str, Any] | None,
    readings: list[VerdictSignalReading],
) -> None:
    field_present = readback.get("associated_ssid_field_present")
    readings.append(
        VerdictSignalReading(
            "associated_ssid_field_present",
            field_present if isinstance(field_present, bool) else None,
        )
    )
    associated = readback.get("associated_ssid")
    if associated is not None:
        readings.append(
            VerdictSignalReading(
                "associated_ssid_matches_intent",
                ssid_present(associated)
                and str(associated).strip() == intended_ssid.strip(),
            )
        )
    link_up = resolve_link_up(readback)
    if link_up is not None:
        readings.append(VerdictSignalReading("link", link_up))
    connected = resolve_device_connected(readback)
    if connected is not None:
        readings.append(VerdictSignalReading("connected", connected))
    if "state" in readback:
        readings.append(
            VerdictSignalReading("state", normalize_up_down(readback["state"]))
        )
    tx_raw = readback.get("txbytes", readback.get("tx_bytes"))
    if tx_raw is not None:
        readings.append(VerdictSignalReading("txbytes", normalize_counter(tx_raw)))
    rx_raw = readback.get("rxbytes", readback.get("rx_bytes"))
    if rx_raw is not None:
        readings.append(VerdictSignalReading("rxbytes", normalize_counter(rx_raw)))
    if internet_status:
        found = walk_for_keys(internet_status, _INTERNET_STATUS_KEYS)
        if "internet" in found:
            readings.append(
                VerdictSignalReading("internet_status", normalize_yes_no(found["internet"]))
            )
        if "gateway" in found:
            readings.append(
                VerdictSignalReading("gateway_status", normalize_yes_no(found["gateway"]))
            )
        if "dns" in found:
            readings.append(
                VerdictSignalReading("dns_status", normalize_yes_no(found["dns"]))
            )


def observe_station_uplink(
    readback: dict[str, Any],
    *,
    internet_status: dict[str, Any] | None,
    intended_ssid: str,
) -> VerdictObservation:
    """Derive station uplink verdict and explanation from split readback + internet status."""

    def _finalize(observation: VerdictObservation) -> VerdictObservation:
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return assert_verdict_observation(observation)

    readings: list[VerdictSignalReading] = []
    missing: list[VerdictMissingSignalCode] = []
    rejected: list[VerdictRejectedSignal] = []

    if not readback:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=("readback",),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_DISPATCHED_UNVERIFIED,
            explanation=explanation,
        )
        return _finalize(observation)

    _read_uplink_signals(
        readback,
        intended_ssid=intended_ssid,
        internet_status=internet_status,
        readings=readings,
    )

    field_present = readback.get("associated_ssid_field_present")
    associated = readback.get("associated_ssid")
    if field_present is not True:
        _append_unique_missing(missing, "associated_ssid_field")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_DISPATCHED_UNVERIFIED,
            explanation=explanation,
        )
        return _finalize(observation)

    if not ssid_present(associated):
        _append_unique_missing(missing, "associated_ssid")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_UPLINK_FAILED, explanation=explanation)
        return _finalize(observation)

    if str(associated).strip() != intended_ssid.strip():
        _append_unique_missing(missing, "ssid_intent_match")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_UPLINK_FAILED, explanation=explanation)
        return _finalize(observation)

    internet_ok = _internet_status_affirmative(internet_status)
    if internet_status:
        found = walk_for_keys(internet_status, _INTERNET_STATUS_KEYS)
        for key, code in (
            ("internet", "internet_status"),
            ("gateway", "gateway_status"),
            ("dns", "dns_status"),
        ):
            if key not in found or _parse_yes_no(found.get(key)) is None:
                if code == "internet_status":
                    _append_unique_missing(missing, "internet_status")
                elif code == "gateway_status":
                    _append_unique_missing(missing, "gateway_status")
                else:
                    _append_unique_missing(missing, "dns_status")

    if internet_ok is True:
        if _readback_has_deceptive_uplink_signals(readback):
            _collect_uplink_deceptive_rejections(readback, rejected)
            explanation = VerdictExplanation(
                signals_read=tuple(readings),
                signals_missing=tuple(missing),
                signals_rejected=tuple(rejected),
            )
            observation = VerdictObservation(
                verdict=_UPLINK_ASSOCIATED_NO_GLOBAL,
                explanation=explanation,
            )
            return _finalize(observation)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_VERIFIED_BOUNDED,
            explanation=explanation,
        )
        return _finalize(observation)
    if internet_ok is False:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=("internet_affirmative",),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_UPLINK_FAILED, explanation=explanation)
        return _finalize(observation)

    if not internet_status:
        _append_unique_missing(missing, "internet_status")
    else:
        _append_unique_missing(missing, "internet_affirmative")
    _collect_uplink_deceptive_rejections(readback, rejected)
    explanation = VerdictExplanation(
        signals_read=tuple(readings),
        signals_missing=tuple(missing),
        signals_rejected=tuple(rejected),
    )
    observation = VerdictObservation(
        verdict=_UPLINK_ASSOCIATED_NO_GLOBAL,
        explanation=explanation,
    )
    return _finalize(observation)


def _read_teardown_signals(
    readback: dict[str, Any],
    *,
    readings: list[VerdictSignalReading],
) -> None:
    field_present = readback.get("associated_ssid_field_present")
    readings.append(
        VerdictSignalReading(
            "associated_ssid_field_present",
            field_present if isinstance(field_present, bool) else None,
        )
    )
    associated = readback.get("associated_ssid")
    if associated is not None:
        readings.append(
            VerdictSignalReading(
                "associated_ssid_matches_intent",
                not ssid_present(associated),
            )
        )
    if "state" in readback:
        readings.append(
            VerdictSignalReading("state", normalize_up_down(readback["state"]))
        )
    link_up = resolve_link_up(readback)
    if link_up is not None:
        readings.append(VerdictSignalReading("link", link_up))
    connected = resolve_device_connected(readback)
    if connected is not None:
        readings.append(VerdictSignalReading("connected", connected))


def observe_station_teardown(readback: dict[str, Any]) -> VerdictObservation:
    """Derive station teardown verdict from split readback (disconnected / cleared)."""

    def _finalize(observation: VerdictObservation) -> VerdictObservation:
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return assert_verdict_observation(observation)

    readings: list[VerdictSignalReading] = []
    missing: list[VerdictMissingSignalCode] = []
    rejected: list[VerdictRejectedSignal] = []

    if not readback:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=("readback",),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_DISPATCHED_UNVERIFIED,
            explanation=explanation,
        )
        return _finalize(observation)

    _read_teardown_signals(readback, readings=readings)

    field_present = readback.get("associated_ssid_field_present")
    associated = readback.get("associated_ssid")
    configured = readback.get("configured_ssid")

    if field_present is True and ssid_present(associated):
        _append_unique_missing(missing, "associated_ssid")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_UPLINK_FAILED, explanation=explanation)
        return _finalize(observation)

    if ssid_present(configured):
        _append_unique_missing(missing, "associated_ssid")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_UPLINK_FAILED, explanation=explanation)
        return _finalize(observation)

    if _readback_has_deceptive_uplink_signals(readback):
        _collect_uplink_deceptive_rejections(readback, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_ASSOCIATED_NO_GLOBAL,
            explanation=explanation,
        )
        return _finalize(observation)

    link_up = resolve_link_up(readback)
    connected = resolve_device_connected(readback)
    if connected is True or link_up is True:
        _append_unique_missing(missing, "link")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_UPLINK_FAILED, explanation=explanation)
        return _finalize(observation)

    if field_present is not True:
        _append_unique_missing(missing, "associated_ssid_field")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_DISPATCHED_UNVERIFIED,
            explanation=explanation,
        )
        return _finalize(observation)

    state = readback.get("state")
    if state is None:
        _append_unique_missing(missing, "link")
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_DISPATCHED_UNVERIFIED,
            explanation=explanation,
        )
        return _finalize(observation)

    if not _state_is_up_token(state) or not ssid_present(associated):
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_UPLINK_VERIFIED_BOUNDED,
            explanation=explanation,
        )
        return _finalize(observation)

    _append_unique_missing(missing, "link")
    explanation = VerdictExplanation(
        signals_read=tuple(readings),
        signals_missing=tuple(missing),
        signals_rejected=tuple(rejected),
    )
    observation = VerdictObservation(
        verdict=_UPLINK_DISPATCHED_UNVERIFIED,
        explanation=explanation,
    )
    return _finalize(observation)


def _op_to_preview_dict(op: WifiStationSealedOpDescriptor) -> dict[str, object]:
    payload: dict[str, object] = {
        "operation": op.operation,
        "station_id": op.station_id,
    }
    if op.ssid is not None:
        payload["ssid"] = op.ssid
    if op.credential_ref_id is not None:
        payload["credential_ref_id"] = op.credential_ref_id
    if op.bssid is not None:
        payload["bssid"] = op.bssid
    if op.priority is not None:
        payload["priority"] = op.priority
    if op.standby_timeout_seconds is not None:
        payload["standby_timeout_seconds"] = op.standby_timeout_seconds
    if op.notes:
        payload["notes"] = list(op.notes)
    return payload


def plan_to_preview_dict(plan: WifiStationApplyPlan) -> dict[str, object]:
    return {
        "station_id": plan.station_id,
        "verification_status": plan.verification_status,
        "grammar_verification_status": plan.grammar_verification_status,
        "planned_uplink_verification_level": plan.planned_uplink_verification_level,
        "readback_rule": (
            "configured_ssid from show rc interface; associated_ssid from show interface "
            "(empty ssid while up = no associated network, not configured-ssid-empty)"
        ),
        "notes": list(plan.notes),
        "apply_ops": [_op_to_preview_dict(op) for op in plan.apply_ops],
        "teardown_ops": [_op_to_preview_dict(op) for op in plan.teardown_ops],
    }


class WifiStationReadbackTransport(Protocol):
    def execute_rci_parse(self, cli_command: str) -> Any: ...


def readback_wifi_station_state(
    transport: WifiStationReadbackTransport,
    station_id: str,
) -> dict[str, object]:
    """Pure readback split: configured (show rc) vs associated (show interface)."""
    validate_wifi_station_id(station_id)
    try:
        configured_raw = sanitize_show_rc_interface_raw(
            transport.execute_rci_parse(f"show rc interface {station_id}")
        )
        runtime_raw = transport.execute_rci_parse(f"show interface {station_id}")
    except Exception as exc:
        raise WifiStationApplyServiceError(scrub_error_message(str(exc))) from None
    readback = parse_station_interface_readback(configured_raw, runtime_raw)
    return readback.to_dict()


def preview_wifi_station_apply(
    intent: UplinkIntent,
    *,
    options: WifiStationPlannerOptions | None = None,
) -> dict[str, object]:
    plan = _compile_plan(intent, options=options)
    return plan_to_preview_dict(plan)


def _compile_plan(
    intent: UplinkIntent,
    *,
    options: WifiStationPlannerOptions | None = None,
) -> WifiStationApplyPlan:
    try:
        return compile_uplink_intent_to_station_ops(intent, options=options)
    except (WifiStationApplyPlannerError, ValueError) as exc:
        raise WifiStationApplyServiceError(str(exc)) from exc


def _live_planner_options(
    options: WifiStationPlannerOptions | None,
) -> WifiStationPlannerOptions:
    base = options or WifiStationPlannerOptions()
    return WifiStationPlannerOptions(
        auth_mode=base.auth_mode,
        include_encryption_wpa2=True,
        include_dhcp_client=True,
        include_ip_global=True,
        include_standby=base.include_standby,
        standby_timeout_seconds=base.standby_timeout_seconds,
    )


def _teardown_planner_options(
    options: WifiStationPlannerOptions | None,
) -> WifiStationPlannerOptions:
    """Teardown compile only dispatches teardown_ops; allow non-default priority offline."""
    base = options or WifiStationPlannerOptions()
    if base.include_ip_global:
        return base
    return WifiStationPlannerOptions(
        auth_mode=base.auth_mode,
        include_encryption_wpa2=base.include_encryption_wpa2,
        include_dhcp_client=base.include_dhcp_client,
        include_ip_global=True,
        include_standby=base.include_standby,
        standby_timeout_seconds=base.standby_timeout_seconds,
    )


def _status_ident(result: WifiStationRciResult) -> str | None:
    if not result.status_entries:
        return None
    return result.status_entries[0].ident


def _step_from_result(op_name: str, result: WifiStationRciResult) -> WifiStationApplyStep:
    return WifiStationApplyStep(op=op_name, ok=True, status_ident=_status_ident(result))


def _step_from_error(op_name: str, message: str) -> WifiStationApplyStep:
    return WifiStationApplyStep(op=op_name, ok=False, error=message)


def _result_from_plan(
    *,
    plan: WifiStationApplyPlan,
    overall: ApplyOverallStatus,
    steps: tuple[WifiStationApplyStep, ...],
    errors: tuple[str, ...],
    logs: tuple[str, ...],
    uplink_verification_status: str | None = None,
    backup_basename: str | None = None,
    backup_content_sha256: str | None = None,
    rollback: WifiStationApplyRollback | None = None,
    rollback_errors: tuple[str, ...] = (),
    uplink_readback: dict[str, object] | None = None,
    uplink_settle_seconds: float | None = None,
    verdict_explanation: VerdictExplanation | None = None,
) -> WifiStationApplyResult:
    resolved_status = (
        uplink_verification_status
        if uplink_verification_status is not None
        else _UPLINK_DISPATCHED_UNVERIFIED
    )
    resolved_explanation = verdict_explanation
    if resolved_explanation is None:
        resolved_explanation = explanation_for_skipped_observe(resolved_status)
    return WifiStationApplyResult(
        overall=overall,
        station_id=plan.station_id,
        verification_status=plan.verification_status,
        grammar_verification_status=plan.grammar_verification_status,
        uplink_verification_status=resolved_status,
        steps=steps,
        errors=errors,
        logs=logs,
        notes=(),
        backup_basename=backup_basename,
        backup_content_sha256=backup_content_sha256,
        rollback=rollback,
        rollback_errors=rollback_errors,
        uplink_readback=uplink_readback,
        uplink_settle_seconds=uplink_settle_seconds,
        verdict_explanation=resolved_explanation,
    )


def _dispatch_ops(
    *,
    transport: object,
    ops: tuple[WifiStationSealedOpDescriptor, ...],
    credential_resolver: CredentialResolver,
    logs: list[str],
    continue_on_error: bool = False,
    live_dispatch: bool = False,
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[tuple[WifiStationApplyStep, ...], tuple[str, ...]]:
    _validate_transport_marker(transport, live_dispatch=live_dispatch)
    steps: list[WifiStationApplyStep] = []
    errors: list[str] = []
    for descriptor in ops:
        op_name = descriptor.operation
        try:
            operation = WifiStationRciOperation(op_name)
        except ValueError:
            message = ERROR_CODE_UNSUPPORTED_OPERATION
            steps.append(_step_from_error(op_name, message))
            errors.append(message)
            logs.append(f"dispatch failed for {op_name}: {message}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue

        psk: str | None = None
        if operation is WifiStationRciOperation.SET_WPA_PSK:
            if not descriptor.credential_ref_id:
                message = ERROR_CODE_CREDENTIAL_REF_REQUIRED
                steps.append(_step_from_error(op_name, message))
                errors.append(message)
                logs.append(f"dispatch failed for {op_name}: {message}")
                if not continue_on_error:
                    return tuple(steps), tuple(errors)
                continue
            try:
                psk = credential_resolver(descriptor.credential_ref_id)
            except Exception:
                steps.append(_step_from_error(op_name, _MSG_CREDENTIAL_RESOLUTION_FAILED))
                errors.append(_MSG_CREDENTIAL_RESOLUTION_FAILED)
                logs.append(
                    f"dispatch failed for {op_name}: {ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED}"
                )
                if not continue_on_error:
                    return tuple(steps), tuple(errors)
                continue
            logs.append(f"dispatched {op_name} with credential_ref (secret not logged)")

        intent_recorded = False
        if trail is not None:
            trail.record_op_intent(op_name)
            intent_recorded = True

        try:
            result = execute_wifi_station_rci(
                cast(Any, transport),
                operation,
                descriptor.station_id,
                ssid=descriptor.ssid,
                psk=psk,
                bssid=descriptor.bssid,
                priority=descriptor.priority,
                standby_timeout=descriptor.standby_timeout_seconds,
            )
        except WifiStationRciError as exc:
            failure_detail = _dispatch_failure_detail(op_name, exc)
            failure_step = _step_from_error(op_name, failure_detail)
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure_step),
                )
            steps.append(failure_step)
            errors.append(failure_detail)
            logs.append(f"dispatch failed for {op_name}: {failure_detail}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue
        except Exception as exc:
            failure_detail = _dispatch_failure_detail(op_name, exc)
            failure_step = _step_from_error(op_name, failure_detail)
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure_step),
                )
            steps.append(failure_step)
            errors.append(failure_detail)
            logs.append(f"dispatch failed for {op_name}: {failure_detail}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue

        if operation is not WifiStationRciOperation.SET_WPA_PSK:
            logs.append(f"ack matched for {op_name}")
        success_step = _step_from_result(op_name, result)
        steps.append(success_step)
        if trail is not None:
            trail.record_op(
                op_name,
                op_evidence_redacted=build_sealed_apply_op_evidence(
                    success_step,
                    device_ack=redact_sealed_apply_device_ack(result),
                ),
            )
    return tuple(steps), tuple(errors)


def _rollback_not_attempted() -> WifiStationApplyRollback:
    return WifiStationApplyRollback(attempted=False, ops=(), outcome="not_attempted")


def _rollback_noop() -> WifiStationApplyRollback:
    return WifiStationApplyRollback(attempted=True, ops=(), outcome="noop")


def _finalize_station_rollback_outcome(
    *,
    rollback_steps: tuple[WifiStationApplyStep, ...],
    rollback_errors: tuple[str, ...],
    uncovered_ops: tuple[WifiStationApplyUncoveredRollbackOp, ...],
) -> ApplyRollbackOutcome:
    if rollback_errors:
        if all(step.ok for step in rollback_steps):
            outcome: ApplyRollbackOutcome = "failed"
        elif any(step.ok for step in rollback_steps):
            outcome = "partial"
        else:
            outcome = "failed"
    elif all(step.ok for step in rollback_steps):
        outcome = "succeeded"
    elif any(step.ok for step in rollback_steps):
        outcome = "partial"
    elif rollback_steps:
        outcome = "failed"
    else:
        outcome = "noop"
    if uncovered_ops and outcome == "succeeded":
        return "partial"
    if uncovered_ops and outcome == "noop":
        return "partial"
    return outcome


def _attempt_compensating_rollback(
    *,
    transport: object,
    apply_ops: tuple[WifiStationSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    credential_resolver: CredentialResolver,
    logs: list[str],
    live_dispatch: bool,
    pre_state: WifiStationApplyPreState | None = None,
) -> tuple[WifiStationApplyRollback, tuple[str, ...]]:
    uncovered_pairs = uncovered_compensate_ops_for_succeeded_station_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    uncovered_ops = tuple(
        WifiStationApplyUncoveredRollbackOp(op=op_name, reason=reason)
        for op_name, reason in uncovered_pairs
    )
    for item in uncovered_ops:
        logs.append(f"compensate uncovered {item.op}: {item.reason}")
    compensate_ops = compensate_ops_for_succeeded_station_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    if not compensate_ops and not uncovered_ops:
        return _rollback_noop(), ()
    if not compensate_ops:
        return (
            WifiStationApplyRollback(
                attempted=True,
                ops=(),
                outcome="partial",
                uncovered_ops=uncovered_ops,
            ),
            (),
        )
    op_names = tuple(op.operation for op in compensate_ops)
    logs.append(f"compensating rollback for {len(compensate_ops)} ops")
    rollback_steps, rollback_errors = _dispatch_ops(
        transport=transport,
        ops=compensate_ops,
        credential_resolver=credential_resolver,
        logs=logs,
        continue_on_error=True,
        live_dispatch=live_dispatch,
    )
    if rollback_errors:
        for note in rollback_errors:
            logs.append(f"rollback note: {note}")
    outcome = _finalize_station_rollback_outcome(
        rollback_steps=rollback_steps,
        rollback_errors=rollback_errors,
        uncovered_ops=uncovered_ops,
    )
    return (
        WifiStationApplyRollback(
            attempted=True,
            ops=op_names,
            outcome=outcome,
            steps=rollback_steps,
            uncovered_ops=uncovered_ops,
        ),
        rollback_errors,
    )


def _finalize_overall_with_rollback(
    base_overall: ApplyOverallStatus,
    *,
    rollback: WifiStationApplyRollback | None,
) -> ApplyOverallStatus:
    if base_overall in {"failed", "verify_mismatch"} and rollback is not None:
        if rollback.outcome == "succeeded":
            return "rolled_back"
    return base_overall


def _should_skip_idempotent_op(
    descriptor: WifiStationSealedOpDescriptor,
    *,
    readback: dict[str, Any],
    intent: UplinkIntent,
) -> bool:
    operation = descriptor.operation
    if operation == WifiStationRciOperation.SET_WPA_PSK.value:
        return False
    if operation == WifiStationRciOperation.SET_SSID.value:
        configured = readback.get("configured_ssid")
        if configured is None or intent.ssid is None:
            return False
        return str(configured).strip() == intent.ssid.strip()
    if operation == WifiStationRciOperation.UP.value:
        state = readback.get("state")
        if state is None:
            return False
        return str(state).strip().lower() in {"up", "enabled", "true", "1"}
    return False


def _filter_idempotent_ops(
    apply_ops: tuple[WifiStationSealedOpDescriptor, ...],
    *,
    readback: dict[str, Any],
    intent: UplinkIntent,
    logs: list[str],
) -> tuple[tuple[WifiStationSealedOpDescriptor, ...], tuple[str, ...]]:
    to_dispatch: list[WifiStationSealedOpDescriptor] = []
    skipped: list[str] = []
    for descriptor in apply_ops:
        if _should_skip_idempotent_op(descriptor, readback=readback, intent=intent):
            skipped.append(descriptor.operation)
            logs.append(f"idempotent skip {descriptor.operation}: already_satisfied")
        else:
            to_dispatch.append(descriptor)
    return tuple(to_dispatch), tuple(skipped)


def _readback_internet_and_observe_station_uplink(
    transport: WifiStationLiveTransport,
    *,
    plan: WifiStationApplyPlan,
    intent: UplinkIntent,
    logs: list[str],
    readback_failure_log: Callable[[WifiStationApplyServiceError], str] | None = None,
) -> tuple[VerdictObservation, dict[str, Any]] | None:
    try:
        readback = readback_wifi_station_state(transport, plan.station_id)
    except WifiStationApplyServiceError as exc:
        if readback_failure_log is not None:
            logs.append(readback_failure_log(exc))
        else:
            logs.append(f"uplink readback failed: {exc}")
        return None

    internet_status: dict[str, Any] | None
    try:
        raw_internet = transport.execute_rci_parse("show internet status")
        internet_status = raw_internet if isinstance(raw_internet, dict) else None
    except Exception:
        logs.append("show internet status read failed")
        internet_status = None

    observation = observe_station_uplink(
        readback,
        internet_status=internet_status,
        intended_ssid=str(intent.ssid or ""),
    )
    return observation, readback


def _cap_uplink_verdict_without_settle(
    verdict: str,
    explanation: VerdictExplanation,
    *,
    settle_performed: bool,
    logs: list[str],
) -> tuple[str, VerdictExplanation]:
    if settle_performed or verdict != _UPLINK_VERIFIED_BOUNDED:
        return verdict, explanation
    logs.append(
        "uplink observe capped: verified_bounded requires performed settle wait "
        f"in [{clamp_uplink_settle_seconds(20)}-{clamp_uplink_settle_seconds(30)}]s"
    )
    capped = VerdictExplanation(
        signals_read=explanation.signals_read,
        signals_missing=(*explanation.signals_missing, "uplink_settle_performed"),
        signals_rejected=explanation.signals_rejected,
    )
    assert_verdict_explanation_invariant(_UPLINK_DISPATCHED_UNVERIFIED, capped)
    return _UPLINK_DISPATCHED_UNVERIFIED, capped


def _observe_uplink_after_settle(
    transport: WifiStationLiveTransport,
    *,
    plan: WifiStationApplyPlan,
    intent: UplinkIntent,
    uplink_settle_seconds: float | None,
    sleep_fn: SleepFn,
    logs: list[str],
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[str, dict[str, object] | None, float | None, VerdictExplanation]:
    settle = clamp_uplink_settle_seconds(
        uplink_settle_seconds if uplink_settle_seconds is not None else 25.0
    )
    settle_performed = False

    if settle > 0:
        logs.append(
            f"uplink settle wait {settle}s before readback "
            f"(recommended band {clamp_uplink_settle_seconds(20)}-"
            f"{clamp_uplink_settle_seconds(30)}s)"
        )
        sleep_preserving_sealed_apply_lease(trail, settle, sleep_fn)
        settle_performed = True
    else:
        logs.append("uplink settle skipped (0s); observe without wait")

    result = _readback_internet_and_observe_station_uplink(
        transport,
        plan=plan,
        intent=intent,
        logs=logs,
    )
    if result is None:
        verdict = _UPLINK_DISPATCHED_UNVERIFIED
        explanation = explanation_for_skipped_observe(_UPLINK_DISPATCHED_UNVERIFIED)
        readback = None
    else:
        observation, readback = result
        verdict = observation.verdict
        explanation = observation.explanation

    recheckable = {
        _UPLINK_FAILED,
        _UPLINK_ASSOCIATED_NO_GLOBAL,
        _UPLINK_DISPATCHED_UNVERIFIED,
    }
    if settle_performed and verdict in recheckable:
        logs.append(
            f"{verdict} after settle readback; one uplink recheck without additional wait"
        )
        recheck = _readback_internet_and_observe_station_uplink(
            transport,
            plan=plan,
            intent=intent,
            logs=logs,
            readback_failure_log=lambda _exc: (
                "uplink recheck readback failed; keeping post-settle verdict"
            ),
        )
        if recheck is not None:
            recheck_observation, recheck_readback = recheck
            recheck_verdict = recheck_observation.verdict
            if recheck_verdict != verdict:
                logs.append(f"uplink recheck verdict: {verdict} -> {recheck_verdict}")
            else:
                logs.append(f"uplink recheck unchanged: {verdict}")
            verdict = recheck_verdict
            explanation = recheck_observation.explanation
            readback = recheck_readback

    verdict, explanation = _cap_uplink_verdict_without_settle(
        verdict,
        explanation,
        settle_performed=settle_performed,
        logs=logs,
    )
    logs.append(f"uplink observe verdict: {verdict}")
    return verdict, readback, settle if settle_performed else None, explanation


def _readback_and_observe_station_teardown(
    transport: WifiStationLiveTransport,
    *,
    plan: WifiStationApplyPlan,
    logs: list[str],
) -> tuple[str, dict[str, object] | None, VerdictExplanation]:
    try:
        readback = readback_wifi_station_state(transport, plan.station_id)
    except WifiStationApplyServiceError as exc:
        logs.append(f"teardown readback failed: {exc}")
        verdict = _UPLINK_DISPATCHED_UNVERIFIED
        return verdict, None, explanation_for_skipped_observe(verdict)

    observation = observe_station_teardown(readback)
    logs.append(f"teardown observe verdict: {observation.verdict}")
    return observation.verdict, readback, observation.explanation


def apply_wifi_station_intent(
    *,
    intent: UplinkIntent,
    transport: WifiStationApplyTransport | WifiStationLiveTransport | None = None,
    credential_resolver: CredentialResolver | None = None,
    options: WifiStationPlannerOptions | None = None,
    live_dispatch: bool = False,
    backup_callback: BackupCallback | None = None,
    compensate_on_failure: bool = True,
    idempotent: bool = False,
    uplink_settle_seconds: float | None = None,
    sleep_fn: SleepFn | None = None,
    store: Any | None = None,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiStationApplyResult:
    if transport is None:
        raise WifiStationApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    _validate_transport_marker(transport, live_dispatch=live_dispatch)
    if credential_resolver is None:
        raise WifiStationApplyServiceError("credential_resolver is required for station apply")

    resolved_options = _live_planner_options(options) if live_dispatch else options
    plan = _compile_plan(intent, options=resolved_options)
    validate_wifi_station_id(plan.station_id)
    logs: list[str] = [f"compiled {len(plan.apply_ops)} apply ops for {plan.station_id}"]

    if backup_callback is not None:
        backup_callback()
        logs.append("backup_callback invoked")

    ops_to_dispatch = plan.apply_ops
    pre_state: WifiStationApplyPreState | None = None
    pre_readback: dict[str, Any] | None = None
    if compensate_on_failure or (idempotent and live_dispatch):
        try:
            readback_transport = cast(WifiStationReadbackTransport, transport)

            def _read_pre_state() -> dict[str, Any]:
                return readback_wifi_station_state(readback_transport, plan.station_id)

            pre_readback = execute_pre_apply_read(transport, _read_pre_state)
            pre_state = derive_wifi_station_pre_state(pre_readback)
            logs.append("pre_apply baseline read completed")
        except Exception:
            pre_state = WifiStationApplyPreState(known=False)
            logs.append("pre_apply baseline read failed; compensation fail-closed")
    if idempotent and live_dispatch and pre_readback is not None:
        try:
            ops_to_dispatch, skipped = _filter_idempotent_ops(
                plan.apply_ops,
                readback=pre_readback,
                intent=intent,
                logs=logs,
            )
            if skipped:
                logs.append(f"idempotent skipped ops: {', '.join(skipped)}")
        except WifiStationApplyServiceError:
            logs.append("idempotent_fallback_full_sequence")
            ops_to_dispatch = plan.apply_ops

    planned_op_names = tuple(op.operation for op in ops_to_dispatch)
    trail = begin_sealed_apply_trail(
        store,
        params=sealed_apply_params,
        ops_planned=planned_op_names,
    )
    if trail is not None and pre_state is not None:
        try:
            trail.record_pre_apply_baseline(
                serialize_pre_apply_baseline_for_trail(
                    pre_state,
                    observed=pre_readback,
                )
            )
        except Exception:
            logs.append("sealed_apply pre_apply baseline trail write failed")

    def _run() -> WifiStationApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=ops_to_dispatch,
            credential_resolver=credential_resolver,
            logs=logs,
            live_dispatch=live_dispatch,
            trail=trail,
        )
        succeeded_op_names = tuple(step.op for step in steps if step.ok)

        def _finish_and_return(result: WifiStationApplyResult) -> WifiStationApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        if dispatch_errors:

            def _failure_result(overall: ApplyOverallStatus) -> WifiStationApplyResult:
                rollback: WifiStationApplyRollback | None
                rollback_errors: tuple[str, ...] = ()
                if compensate_on_failure:
                    if succeeded_op_names:
                        rollback, rollback_errors = _attempt_compensating_rollback(
                            transport=transport,
                            apply_ops=plan.apply_ops,
                            succeeded_op_names=succeeded_op_names,
                            credential_resolver=credential_resolver,
                            logs=logs,
                            live_dispatch=live_dispatch,
                            pre_state=pre_state,
                        )
                    else:
                        rollback = _rollback_noop()
                else:
                    rollback = _rollback_not_attempted()
                final_overall = _finalize_overall_with_rollback(overall, rollback=rollback)
                return _result_from_plan(
                    plan=plan,
                    overall=final_overall,
                    steps=steps,
                    errors=dispatch_errors,
                    logs=tuple(logs),
                    rollback=rollback,
                    rollback_errors=rollback_errors,
                    uplink_verification_status=_UPLINK_DISPATCHED_UNVERIFIED,
                )

            return _finish_and_return(_failure_result("failed"))

        if not live_dispatch:
            logs.append("offline dispatch completed without uplink verification")
            return _finish_and_return(
                _result_from_plan(
                plan=plan,
                overall="dispatched_offline",
                steps=steps,
                errors=(),
                logs=tuple(logs),
                uplink_verification_status=_UPLINK_DISPATCHED_UNVERIFIED,
                )
            )

        actual_sleep = sleep_fn or time.sleep
        uplink_status, uplink_readback, settle_used, uplink_explanation = (
            _observe_uplink_after_settle(
            transport,  # type: ignore[arg-type]
            plan=plan,
            intent=intent,
            uplink_settle_seconds=uplink_settle_seconds,
            sleep_fn=actual_sleep,
            logs=logs,
            trail=trail,
            )
        )
        overall: ApplyOverallStatus = (
            "applied" if uplink_status == _UPLINK_VERIFIED_BOUNDED else "verify_mismatch"
        )
        rollback: WifiStationApplyRollback | None
        rollback_errors: tuple[str, ...] = ()
        if uplink_status == _UPLINK_FAILED and compensate_on_failure:
            if succeeded_op_names:
                rollback, rollback_errors = _attempt_compensating_rollback(
                    transport=transport,
                    apply_ops=plan.apply_ops,
                    succeeded_op_names=succeeded_op_names,
                    credential_resolver=credential_resolver,
                    logs=logs,
                    live_dispatch=live_dispatch,
                    pre_state=pre_state,
                )
            else:
                rollback = _rollback_noop()
        else:
            rollback = _rollback_not_attempted()
        final_overall = _finalize_overall_with_rollback(overall, rollback=rollback)
        return _finish_and_return(
            _result_from_plan(
            plan=plan,
            overall=final_overall,
            steps=steps,
            errors=(),
            logs=tuple(logs),
            uplink_verification_status=uplink_status,
            uplink_readback=uplink_readback,
            uplink_settle_seconds=settle_used,
            rollback=rollback,
            rollback_errors=rollback_errors,
            verdict_explanation=uplink_explanation,
            )
        )

    return guard_sealed_apply_trail(trail, _run)


def teardown_wifi_station(
    *,
    intent: UplinkIntent,
    transport: WifiStationApplyTransport | WifiStationLiveTransport | None = None,
    credential_resolver: CredentialResolver | None = None,
    options: WifiStationPlannerOptions | None = None,
    live_dispatch: bool = False,
    store: Any | None = None,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiStationApplyResult:
    if transport is None:
        raise WifiStationApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    _validate_transport_marker(transport, live_dispatch=live_dispatch)
    if credential_resolver is None:
        credential_resolver = _unused_teardown_credential_resolver

    resolved_options = (
        _live_planner_options(options) if live_dispatch else _teardown_planner_options(options)
    )
    plan = _compile_plan(intent, options=resolved_options)
    logs: list[str] = [f"compiled {len(plan.teardown_ops)} teardown ops for {plan.station_id}"]

    planned_op_names = tuple(op.operation for op in plan.teardown_ops)
    trail = begin_sealed_apply_trail(
        store,
        params=sealed_apply_params,
        ops_planned=planned_op_names,
    )

    def _run() -> WifiStationApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.teardown_ops,
            credential_resolver=credential_resolver,
            logs=logs,
            continue_on_error=True,
            live_dispatch=live_dispatch,
            trail=trail,
        )
        if not live_dispatch:
            overall: ApplyOverallStatus = (
                "failed" if dispatch_errors else "dispatched_offline"
            )
            result = _result_from_plan(
                plan=plan,
                overall=overall,
                steps=steps,
                errors=dispatch_errors,
                logs=tuple(logs),
            )
        elif dispatch_errors:
            result = _result_from_plan(
                plan=plan,
                overall="failed",
                steps=steps,
                errors=dispatch_errors,
                logs=tuple(logs),
                uplink_verification_status=_UPLINK_DISPATCHED_UNVERIFIED,
            )
        else:
            uplink_status, uplink_readback, uplink_explanation = (
                _readback_and_observe_station_teardown(
                    transport,  # type: ignore[arg-type]
                    plan=plan,
                    logs=logs,
                )
            )
            overall = (
                "applied"
                if uplink_status == _UPLINK_VERIFIED_BOUNDED
                else "verify_mismatch"
            )
            result = _result_from_plan(
                plan=plan,
                overall=overall,
                steps=steps,
                errors=dispatch_errors,
                logs=tuple(logs),
                uplink_verification_status=uplink_status,
                uplink_readback=uplink_readback,
                verdict_explanation=uplink_explanation,
            )
        finish_sealed_apply_trail(
            trail,
            overall=result.overall,
            outcome_snapshot=outcome_snapshot_from_apply_result(result),
        )
        return result

    return guard_sealed_apply_trail(trail, _run)


__all__ = [
    "WifiStationApplyResult",
    "WifiStationApplyRollback",
    "WifiStationApplyServiceError",
    "WifiStationApplyStep",
    "WifiStationApplyTransport",
    "WifiStationLiveTransport",
    "apply_wifi_station_intent",
    "observe_station_teardown",
    "observe_station_uplink",
    "plan_to_preview_dict",
    "preview_wifi_station_apply",
    "readback_wifi_station_state",
    "require_wifi_station_live_transport",
    "require_wifi_station_offline_transport",
    "teardown_wifi_station",
]
