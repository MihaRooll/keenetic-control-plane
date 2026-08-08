"""Wi-Fi Configure → Apply → Verify service (injected transport; offline-testable)."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from router_control.adapters.netcraze.allowlist import validate_wifi_ap_id
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wifi_rci import (
    WifiApRciError,
    WifiApRciErrorCategory,
    WifiApRciFailureDetails,
    WifiApRciOperation,
    WifiApRciResult,
    classify_wifi_ap_rci_failure,
    command_redacted_for,
    execute_wifi_ap_rci,
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
    explanation_for_skipped_observe,
    normalize_up_down,
    validate_wifi_apply_payload,
)
from router_control.application.wifi_apply_planner import (
    WifiApplyPlan,
    WifiApplyPlannerError,
    WifiApplyPreState,
    WifiSealedOpDescriptor,
    compensate_ops_for_succeeded_apply,
    compile_wifi_intent_to_ops,
    derive_wifi_pre_state,
    uncovered_compensate_ops_for_succeeded_apply,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    ERROR_CODE_NO_APPLY_OPS,
    ERROR_CODE_OP_DISPATCH_FAILED,
    ERROR_CODE_READBACK_FAILED,
    ERROR_CODE_UNSUPPORTED_OPERATION,
)
from router_control.application.wifi_observation_helpers import (
    encryption_empty as _encryption_empty,
)
from router_control.application.wifi_observation_helpers import (
    encryption_indicates_wpa2 as _encryption_indicates_wpa2,
)
from router_control.application.wifi_observation_helpers import (
    encryption_indicates_wpa3 as _encryption_indicates_wpa3,
)
from router_control.application.wifi_observation_helpers import (
    encryption_matches_mode as _encryption_matches_mode,
)
from router_control.application.wifi_observation_helpers import (
    extract_interface_fields as _extract_interface_fields,
)
from router_control.application.wifi_observation_helpers import (
    resolve_broadcast as _resolve_broadcast,
)
from router_control.application.wifi_observation_helpers import (
    resolve_device_connected as _resolve_device_connected,
)
from router_control.application.wifi_observation_helpers import (
    resolve_link_up as _resolve_link_up,
)
from router_control.application.wifi_observation_helpers import (
    resolve_on_air_signal as _resolve_on_air_signal,
)
from router_control.application.wifi_observation_helpers import (
    sanitize_observed_fields as _sanitize_observed,
)
from router_control.application.wifi_observation_helpers import (
    ssid_present as _ssid_present,
)
from router_control.application.wifi_observation_helpers import (
    state_is_up as _state_is_up,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)

CredentialResolver = Callable[[str], str]
BackupCallback = Callable[[], None]

_MSG_CREDENTIAL_RESOLUTION_FAILED = ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED
_MSG_OP_DISPATCH_FAILED = ERROR_CODE_OP_DISPATCH_FAILED
_MSG_READBACK_FAILED = ERROR_CODE_READBACK_FAILED

_ON_AIR_VERIFIED = "on_air_verified"
_ON_AIR_ADMIN_ONLY = "on_air_admin_only"
_ON_AIR_UNVERIFIED = "on_air_unverified"
_ON_AIR_STILL_BROADCASTING = "on_air_still_broadcasting"


class WifiApplyServiceError(ValueError):
    """Fail-closed Wi-Fi apply service error."""


class WifiApplyTransport(Protocol):
    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...

    def execute_rci_parse(self, cli_command: str) -> Any: ...


@dataclass(frozen=True, slots=True)
class WifiApplyStep:
    op: str
    ok: bool
    status_ident: str | None = None
    error: str | None = None
    error_category: str | None = None
    router_message: str | None = None
    command_redacted: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"op": self.op, "operation": self.op, "ok": self.ok}
        if self.status_ident is not None:
            payload["status_ident"] = self.status_ident
        if self.error is not None:
            payload["error"] = self.error
        if self.error_category is not None:
            payload["error_category"] = self.error_category
        if self.router_message is not None:
            payload["router_message"] = self.router_message
        if self.command_redacted is not None:
            payload["command_redacted"] = self.command_redacted
        return payload


@dataclass(frozen=True, slots=True)
class WifiApplySkippedOp:
    op: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class WifiApplyUncoveredRollbackOp:
    op: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class WifiApplyRollback:
    attempted: bool
    ops: tuple[str, ...]
    outcome: ApplyRollbackOutcome
    steps: tuple[WifiApplyStep, ...] = ()
    uncovered_ops: tuple[WifiApplyUncoveredRollbackOp, ...] = ()

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
class WifiApplyVerification:
    ssid_ok: bool
    encryption_ok: bool
    admin_up_ok: bool
    on_air_ok: bool | None
    observed: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        return {
            "ssid_ok": self.ssid_ok,
            "encryption_ok": self.encryption_ok,
            "admin_up_ok": self.admin_up_ok,
            "on_air_ok": self.on_air_ok,
            "observed": self.observed,
        }


@dataclass(frozen=True, slots=True)
class WifiApplyResult:
    overall: ApplyOverallStatus
    ap_id: str
    steps: tuple[WifiApplyStep, ...]
    verification: WifiApplyVerification | None
    errors: tuple[str, ...]
    logs: tuple[str, ...]
    backup_basename: str | None = None
    backup_content_sha256: str | None = None
    rollback: WifiApplyRollback | None = None
    skipped_ops: tuple[WifiApplySkippedOp, ...] = ()
    on_air_verification_status: str = _ON_AIR_UNVERIFIED
    verdict_explanation: VerdictExplanation | None = None
    rollback_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "overall": self.overall,
            "ap_id": self.ap_id,
            "on_air_verification_status": self.on_air_verification_status,
            "steps": [step.to_dict() for step in self.steps],
            "errors": list(self.errors),
            "rollback_errors": list(self.rollback_errors),
            "logs": list(self.logs),
        }
        if self.verdict_explanation is not None:
            payload["verdict_explanation"] = self.verdict_explanation.to_dict()
        if self.verification is not None:
            payload["verification"] = self.verification.to_dict()
        if self.backup_basename is not None:
            payload["backup_basename"] = self.backup_basename
        if self.backup_content_sha256 is not None:
            payload["backup_content_sha256"] = self.backup_content_sha256
        if self.rollback is not None:
            payload["rollback"] = self.rollback.to_dict()
        if self.skipped_ops:
            payload["skipped_ops"] = [item.to_dict() for item in self.skipped_ops]
        return validate_wifi_apply_payload(payload)


def _op_to_preview_dict(op: WifiSealedOpDescriptor) -> dict[str, object]:
    payload: dict[str, object] = {"operation": op.operation, "ap_id": op.ap_id}
    if op.ssid is not None:
        payload["ssid"] = op.ssid
    if op.credential_ref_id is not None:
        payload["credential_ref_id"] = op.credential_ref_id
    if op.notes:
        payload["notes"] = list(op.notes)
    return payload


def plan_to_preview_dict(plan: WifiApplyPlan) -> dict[str, object]:
    return {
        "ap_id": plan.ap_id,
        "verification_status": plan.verification_status,
        "notes": list(plan.notes),
        "apply_ops": [_op_to_preview_dict(op) for op in plan.apply_ops],
        "teardown_ops": [_op_to_preview_dict(op) for op in plan.teardown_ops],
    }


def preview_wifi_apply(intent: WifiIntent, ap_id: str) -> dict[str, object]:
    """Validate + compile only; no dispatch, no credential resolution."""
    plan = _compile_plan(intent, ap_id)
    return plan_to_preview_dict(plan)


def _status_ident(result: WifiApRciResult) -> str | None:
    if not result.status_entries:
        return None
    return result.status_entries[0].ident


def _step_from_result(op_name: str, result: WifiApRciResult) -> WifiApplyStep:
    return WifiApplyStep(op=op_name, ok=True, status_ident=_status_ident(result))


def _step_from_error(
    op_name: str,
    message: str,
    *,
    details: WifiApRciFailureDetails | None = None,
) -> WifiApplyStep:
    if details is None:
        return WifiApplyStep(op=op_name, ok=False, error=message)
    return WifiApplyStep(
        op=op_name,
        ok=False,
        error=message,
        error_category=details.category.value,
        router_message=details.sanitized_message,
        command_redacted=details.command_redacted,
    )


def _failure_details_from_exception(
    operation: WifiApRciOperation,
    ap_id: str,
    *,
    ssid: str | None = None,
    exc: BaseException,
    fallback_message: str,
) -> WifiApRciFailureDetails:
    if isinstance(exc, WifiApRciError) and exc.details is not None:
        return exc.details
    return classify_wifi_ap_rci_failure(
        operation=operation,
        ap_id=ap_id,
        ssid=ssid,
        exc=exc,
        fallback_message=fallback_message,
    )


def _compile_plan(intent: WifiIntent, ap_id: str) -> WifiApplyPlan:
    try:
        return compile_wifi_intent_to_ops(intent, ap_id)
    except (WifiApplyPlannerError, ValueError) as exc:
        raise WifiApplyServiceError(str(exc)) from exc


def _validate_ap(ap_id: str) -> str:
    try:
        return validate_wifi_ap_id(ap_id)
    except ValueError as exc:
        raise WifiApplyServiceError(str(exc)) from exc


def _readback_show_interface(transport: WifiApplyTransport, ap_id: str) -> dict[str, Any]:
    command = f"show interface {ap_id}"
    raw = transport.execute_rci_parse(command)
    return _extract_interface_fields(raw)


def _read_on_air_signals(
    observed: dict[str, Any],
    readings: list[VerdictSignalReading],
) -> tuple[bool | None, bool]:
    link = _resolve_link_up(observed)
    broadcast = _resolve_broadcast(observed)
    admin_up = _state_is_up(observed.get("state")) or _state_is_up(observed.get("up"))
    readings.append(VerdictSignalReading("admin_up", admin_up))
    if link is not None:
        readings.append(VerdictSignalReading("link", link))
    if broadcast is not None:
        readings.append(VerdictSignalReading("broadcast", broadcast))
    on_air = _resolve_on_air_signal(observed)
    if on_air is not None:
        readings.append(VerdictSignalReading("on_air_signal", on_air))
    connected = observed.get("connected")
    if connected is not None:
        readings.append(
            VerdictSignalReading("connected", normalize_up_down(connected))
        )
    if observed.get("state") is not None:
        readings.append(
            VerdictSignalReading("state", normalize_up_down(observed["state"]))
        )
    return on_air, admin_up


def _collect_on_air_deceptive_rejections(
    observed: dict[str, Any],
    rejected: list[VerdictRejectedSignal],
) -> None:
    link = _resolve_link_up(observed)
    broadcast = _resolve_broadcast(observed)
    if link is not None and broadcast is not None and link != broadcast:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("link", "link_broadcast_conflict"),
        )
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("broadcast", "link_broadcast_conflict"),
        )
    connected = observed.get("connected")
    if connected is not None:
        if _resolve_device_connected(observed) is True and link is False:
            _append_unique_rejected(
                rejected,
                VerdictRejectedSignal("connected", "connected_with_link_down"),
            )
        else:
            _append_unique_rejected(
                rejected,
                VerdictRejectedSignal("connected", "connected_not_evidence"),
            )
    if _state_is_up_token(observed.get("state")) and link is False:
        _append_unique_rejected(
            rejected,
            VerdictRejectedSignal("state", "state_up_with_link_down"),
        )


def observe_on_air_apply(observed: dict[str, Any]) -> VerdictObservation:
    readings: list[VerdictSignalReading] = []
    missing: list[VerdictMissingSignalCode] = []
    rejected: list[VerdictRejectedSignal] = []

    on_air, admin_up = _read_on_air_signals(observed, readings)
    link = _resolve_link_up(observed)
    broadcast = _resolve_broadcast(observed)

    if link is not None and broadcast is not None and link != broadcast:
        _append_unique_missing(missing, "on_air_signal")
        _collect_on_air_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_ON_AIR_UNVERIFIED, explanation=explanation)
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return observation

    if on_air is True:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_ON_AIR_VERIFIED, explanation=explanation)
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return observation
    if on_air is False:
        _append_unique_missing(missing, "on_air_signal")
        _collect_on_air_deceptive_rejections(observed, rejected)
        verdict = _ON_AIR_ADMIN_ONLY if admin_up else _ON_AIR_UNVERIFIED
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=verdict, explanation=explanation)
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return observation

    if link is None and broadcast is None:
        _append_unique_missing(missing, "link")
        _append_unique_missing(missing, "broadcast")
    _append_unique_missing(missing, "on_air_signal")
    _collect_on_air_deceptive_rejections(observed, rejected)
    explanation = VerdictExplanation(
        signals_read=tuple(readings),
        signals_missing=tuple(missing),
        signals_rejected=tuple(rejected),
    )
    observation = VerdictObservation(verdict=_ON_AIR_UNVERIFIED, explanation=explanation)
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
    return observation


def observe_on_air_teardown(observed: dict[str, Any]) -> VerdictObservation:
    readings: list[VerdictSignalReading] = []
    missing: list[VerdictMissingSignalCode] = []
    rejected: list[VerdictRejectedSignal] = []

    on_air, _admin_up = _read_on_air_signals(observed, readings)
    link = _resolve_link_up(observed)
    broadcast = _resolve_broadcast(observed)

    if link is not None and broadcast is not None and link != broadcast:
        _append_unique_missing(missing, "on_air_signal")
        _collect_on_air_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_ON_AIR_UNVERIFIED, explanation=explanation)
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return observation

    if on_air is False:
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(verdict=_ON_AIR_VERIFIED, explanation=explanation)
        assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
        return observation
    if on_air is True:
        _append_unique_missing(missing, "on_air_signal")
        _collect_on_air_deceptive_rejections(observed, rejected)
        explanation = VerdictExplanation(
            signals_read=tuple(readings),
            signals_missing=tuple(missing),
            signals_rejected=tuple(rejected),
        )
        observation = VerdictObservation(
            verdict=_ON_AIR_STILL_BROADCASTING,
            explanation=explanation,
        )
        return observation

    if link is None and broadcast is None:
        _append_unique_missing(missing, "link")
        _append_unique_missing(missing, "broadcast")
    _append_unique_missing(missing, "on_air_signal")
    _collect_on_air_deceptive_rejections(observed, rejected)
    explanation = VerdictExplanation(
        signals_read=tuple(readings),
        signals_missing=tuple(missing),
        signals_rejected=tuple(rejected),
    )
    observation = VerdictObservation(verdict=_ON_AIR_UNVERIFIED, explanation=explanation)
    assert_verdict_explanation_invariant(observation.verdict, observation.explanation)
    return observation


def _resolve_apply_on_air_verification_status(observed: dict[str, Any]) -> str:
    return observe_on_air_apply(observed).verdict


def _resolve_teardown_on_air_verification_status(observed: dict[str, Any]) -> str:
    return observe_on_air_teardown(observed).verdict


def _verify_applied(
    observed: dict[str, Any],
    expected_ssid: str,
    wpa_mode: WifiWpaMode,
) -> WifiApplyVerification:
    sanitized = _sanitize_observed(observed)
    ssid_value = observed.get("ssid")
    ssid_ok = _ssid_present(ssid_value) and str(ssid_value) == expected_ssid
    encryption_ok = _encryption_matches_mode(observed.get("encryption"), wpa_mode)
    admin_up_ok = _state_is_up(observed.get("state")) or _state_is_up(observed.get("up"))
    on_air_ok = _resolve_on_air_signal(observed)
    return WifiApplyVerification(
        ssid_ok=ssid_ok,
        encryption_ok=encryption_ok,
        admin_up_ok=admin_up_ok,
        on_air_ok=on_air_ok,
        observed=sanitized,
    )


def _verify_teardown(observed: dict[str, Any]) -> WifiApplyVerification:
    sanitized = _sanitize_observed(observed)
    ssid_ok = not _ssid_present(observed.get("ssid"))
    encryption_ok = _encryption_empty(observed.get("encryption"))
    admin_up_ok = _state_is_up(observed.get("state")) or _state_is_up(observed.get("up"))
    on_air_ok = _resolve_on_air_signal(observed)
    return WifiApplyVerification(
        ssid_ok=ssid_ok,
        encryption_ok=encryption_ok,
        admin_up_ok=admin_up_ok,
        on_air_ok=on_air_ok,
        observed=sanitized,
    )


def _should_skip_idempotent_op(
    descriptor: WifiSealedOpDescriptor,
    *,
    intent: WifiIntent,
    observed: dict[str, Any],
) -> bool:
    operation = descriptor.operation
    if operation == WifiApRciOperation.SET_WPA_PSK.value:
        return False
    if operation == WifiApRciOperation.SET_SSID.value:
        ssid_value = observed.get("ssid")
        if ssid_value is None:
            return False
        return str(ssid_value) == intent.ssid
    if operation == WifiApRciOperation.ENCRYPTION_ENABLE.value:
        encryption = observed.get("encryption")
        if encryption is None or _encryption_empty(encryption):
            return False
        return _encryption_matches_mode(encryption, intent.wpa_mode)
    if operation == WifiApRciOperation.ENCRYPTION_WPA2.value:
        encryption = observed.get("encryption")
        if encryption is None:
            return False
        return _encryption_indicates_wpa2(encryption)
    if operation == WifiApRciOperation.ENCRYPTION_WPA3.value:
        encryption = observed.get("encryption")
        if encryption is None:
            return False
        return _encryption_indicates_wpa3(encryption)
    if operation == WifiApRciOperation.UP.value:
        state = observed.get("state")
        up_flag = observed.get("up")
        if state is None and up_flag is None:
            return False
        return _state_is_up(state) or _state_is_up(up_flag)
    return False


def _idempotent_skip_decisions_missing_majority(
    apply_ops: tuple[WifiSealedOpDescriptor, ...],
    observed: dict[str, Any],
) -> bool:
    """True when most skip-relevant observed keys are absent (conservative full sequence)."""
    decisions = 0
    missing = 0
    for descriptor in apply_ops:
        operation = descriptor.operation
        if operation == WifiApRciOperation.SET_WPA_PSK.value:
            continue
        if operation == WifiApRciOperation.SET_SSID.value:
            decisions += 1
            if observed.get("ssid") is None:
                missing += 1
        elif operation == WifiApRciOperation.ENCRYPTION_ENABLE.value:
            decisions += 1
            if observed.get("encryption") is None:
                missing += 1
        elif operation in (
            WifiApRciOperation.ENCRYPTION_WPA2.value,
            WifiApRciOperation.ENCRYPTION_WPA3.value,
        ):
            decisions += 1
            if observed.get("encryption") is None:
                missing += 1
        elif operation == WifiApRciOperation.UP.value:
            decisions += 1
            if observed.get("state") is None and observed.get("up") is None:
                missing += 1
    if decisions == 0:
        return False
    return missing > decisions // 2


def _filter_idempotent_ops(
    apply_ops: tuple[WifiSealedOpDescriptor, ...],
    *,
    intent: WifiIntent,
    observed: dict[str, Any],
    logs: list[str],
) -> tuple[tuple[WifiSealedOpDescriptor, ...], tuple[WifiApplySkippedOp, ...]]:
    if not observed or _idempotent_skip_decisions_missing_majority(apply_ops, observed):
        logs.append("idempotent_fallback_full_sequence")
        return apply_ops, ()
    to_dispatch: list[WifiSealedOpDescriptor] = []
    skipped: list[WifiApplySkippedOp] = []
    for descriptor in apply_ops:
        if _should_skip_idempotent_op(descriptor, intent=intent, observed=observed):
            skipped.append(WifiApplySkippedOp(op=descriptor.operation, reason="already_satisfied"))
            logs.append(f"idempotent skip {descriptor.operation}: already_satisfied")
        else:
            to_dispatch.append(descriptor)
    return tuple(to_dispatch), tuple(skipped)


def _rollback_not_attempted() -> WifiApplyRollback:
    return WifiApplyRollback(attempted=False, ops=(), outcome="not_attempted")


def _rollback_noop() -> WifiApplyRollback:
    return WifiApplyRollback(attempted=True, ops=(), outcome="noop")


def _finalize_wifi_rollback_outcome(
    *,
    rollback_steps: tuple[WifiApplyStep, ...],
    rollback_errors: tuple[str, ...],
    uncovered_ops: tuple[WifiApplyUncoveredRollbackOp, ...],
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
    transport: WifiApplyTransport,
    apply_ops: tuple[WifiSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    credential_resolver: CredentialResolver,
    logs: list[str],
    pre_state: WifiApplyPreState | None = None,
) -> tuple[WifiApplyRollback, tuple[str, ...]]:
    uncovered_pairs = uncovered_compensate_ops_for_succeeded_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    uncovered_ops = tuple(
        WifiApplyUncoveredRollbackOp(op=op_name, reason=reason)
        for op_name, reason in uncovered_pairs
    )
    for item in uncovered_ops:
        logs.append(f"compensate uncovered {item.op}: {item.reason}")
    compensate_ops = compensate_ops_for_succeeded_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    if not compensate_ops and not uncovered_ops:
        return _rollback_noop(), ()
    if not compensate_ops:
        return (
            WifiApplyRollback(
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
    )
    if rollback_errors:
        for note in rollback_errors:
            logs.append(f"rollback note: {note}")
    outcome = _finalize_wifi_rollback_outcome(
        rollback_steps=rollback_steps,
        rollback_errors=rollback_errors,
        uncovered_ops=uncovered_ops,
    )
    return (
        WifiApplyRollback(
            attempted=True,
            ops=op_names,
            outcome=outcome,
            steps=rollback_steps,
            uncovered_ops=uncovered_ops,
        ),
        rollback_errors,
    )


def _normalize_wifi_pre_state_baseline(
    pre_state: WifiApplyPreState,
    pre_read: dict[str, Any],
) -> WifiApplyPreState:
    """Treat empty pre-apply encryption as confirmed absent PSK (compensation baseline)."""
    if not pre_state.known or pre_state.had_psk is not None:
        return pre_state
    from router_control.application.wifi_observation_helpers import encryption_empty

    if encryption_empty(pre_read.get("encryption")):
        return WifiApplyPreState(
            known=True,
            had_ssid=pre_state.had_ssid,
            had_psk=False,
            encryption_enabled=pre_state.encryption_enabled,
            had_wpa2=pre_state.had_wpa2,
            had_wpa3=pre_state.had_wpa3,
            was_admin_up=pre_state.was_admin_up,
        )
    return pre_state


def _finalize_overall_with_rollback(
    base_overall: ApplyOverallStatus,
    *,
    rollback: WifiApplyRollback | None,
) -> ApplyOverallStatus:
    if base_overall in {"failed", "verify_mismatch"} and rollback is not None:
        if rollback.outcome == "succeeded":
            return "rolled_back"
    return base_overall


def _dispatch_ops(
    *,
    transport: WifiApplyTransport,
    ops: tuple[WifiSealedOpDescriptor, ...],
    credential_resolver: CredentialResolver,
    logs: list[str],
    continue_on_error: bool = False,
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[tuple[WifiApplyStep, ...], tuple[str, ...]]:
    steps: list[WifiApplyStep] = []
    errors: list[str] = []
    for descriptor in ops:
        op_name = descriptor.operation
        try:
            operation = WifiApRciOperation(op_name)
        except ValueError:
            message = ERROR_CODE_UNSUPPORTED_OPERATION
            details = classify_wifi_ap_rci_failure(
                operation=WifiApRciOperation.SET_SSID,
                ap_id=descriptor.ap_id,
                fallback_message=message,
            )
            details = WifiApRciFailureDetails(
                category=WifiApRciErrorCategory.UNKNOWN,
                sanitized_message=message,
                operation=op_name,
                command_redacted=details.command_redacted,
            )
            steps.append(_step_from_error(op_name, message, details=details))
            errors.append(message)
            logs.append(f"dispatch failed for {op_name}: {message}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue

        psk: str | None = None
        if operation is WifiApRciOperation.SET_WPA_PSK:
            if not descriptor.credential_ref_id:
                message = ERROR_CODE_CREDENTIAL_REF_REQUIRED
                details = WifiApRciFailureDetails(
                    category=WifiApRciErrorCategory.UNKNOWN,
                    sanitized_message=message,
                    operation=op_name,
                    command_redacted=command_redacted_for(operation, descriptor.ap_id),
                )
                steps.append(_step_from_error(op_name, message, details=details))
                errors.append(message)
                logs.append(f"dispatch failed for {op_name}: {message}")
                if not continue_on_error:
                    return tuple(steps), tuple(errors)
                continue
            try:
                psk = credential_resolver(descriptor.credential_ref_id)
            except Exception as exc:
                details = classify_wifi_ap_rci_failure(
                    operation=operation,
                    ap_id=descriptor.ap_id,
                    exc=exc,
                    fallback_message=_MSG_CREDENTIAL_RESOLUTION_FAILED,
                )
                steps.append(
                    _step_from_error(
                        op_name,
                        _MSG_CREDENTIAL_RESOLUTION_FAILED,
                        details=details,
                    )
                )
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
            result = execute_wifi_ap_rci(
                transport,
                operation,
                descriptor.ap_id,
                ssid=descriptor.ssid,
                psk=psk,
            )
        except WifiApRciError as exc:
            details = _failure_details_from_exception(
                operation,
                descriptor.ap_id,
                ssid=descriptor.ssid,
                exc=exc,
                fallback_message=_MSG_OP_DISPATCH_FAILED,
            )
            failure_step = _step_from_error(
                op_name, _MSG_OP_DISPATCH_FAILED, details=details
            )
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure_step),
                )
            steps.append(failure_step)
            errors.append(_MSG_OP_DISPATCH_FAILED)
            logs.append(f"dispatch failed for {op_name}: op dispatch failed")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue
        except Exception as exc:
            details = _failure_details_from_exception(
                operation,
                descriptor.ap_id,
                ssid=descriptor.ssid,
                exc=exc,
                fallback_message=_MSG_OP_DISPATCH_FAILED,
            )
            failure_step = _step_from_error(
                op_name, _MSG_OP_DISPATCH_FAILED, details=details
            )
            if intent_recorded and trail is not None:
                trail.record_op_failure(
                    op_name,
                    op_evidence_redacted=build_sealed_apply_op_evidence(failure_step),
                )
            steps.append(failure_step)
            errors.append(_MSG_OP_DISPATCH_FAILED)
            logs.append(f"dispatch failed for {op_name}: unexpected error")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue

        if operation is WifiApRciOperation.SET_WPA_PSK:
            logs.append(f"ack matched for {op_name}")
        else:
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


def apply_wifi_intent(
    *,
    intent: WifiIntent,
    ap_id: str,
    transport: WifiApplyTransport,
    credential_resolver: CredentialResolver,
    backup_callback: BackupCallback | None = None,
    compensate_on_failure: bool = True,
    idempotent: bool = False,
    store: Any | None = None,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiApplyResult:
    normalized_ap = _validate_ap(ap_id)
    plan = _compile_plan(intent, normalized_ap)

    if not plan.apply_ops:
        message = ERROR_CODE_NO_APPLY_OPS
        return WifiApplyResult(
            overall="failed",
            ap_id=plan.ap_id,
            steps=(),
            verification=None,
            errors=(message,),
            logs=(message,),
            rollback=_rollback_not_attempted(),
        )

    logs: list[str] = [f"compiled {len(plan.apply_ops)} apply ops for {plan.ap_id}"]
    if backup_callback is not None:
        backup_callback()
        logs.append("backup_callback invoked")

    skipped_ops: tuple[WifiApplySkippedOp, ...] = ()
    ops_to_dispatch = plan.apply_ops
    pre_state: WifiApplyPreState | None = None
    pre_read_raw: Any | None = None
    if compensate_on_failure or idempotent:
        try:
            pre_read_raw = execute_pre_apply_read(
                transport,
                lambda: transport.execute_rci_parse(f"show interface {plan.ap_id}"),
            )
            pre_read = _extract_interface_fields(pre_read_raw)
            pre_state = _normalize_wifi_pre_state_baseline(
                derive_wifi_pre_state(pre_read, raw=pre_read_raw),
                pre_read,
            )
            logs.append("pre_apply baseline read completed")
        except Exception:
            pre_state = WifiApplyPreState(known=False)
            logs.append("pre_apply baseline read failed; compensation fail-closed")
    if idempotent and pre_state is not None and pre_state.known:
        try:
            pre_read = _extract_interface_fields(pre_read_raw)
            ops_to_dispatch, skipped_ops = _filter_idempotent_ops(
                plan.apply_ops,
                intent=intent,
                observed=pre_read,
                logs=logs,
            )
        except Exception:
            logs.append("idempotent_fallback_full_sequence")
            ops_to_dispatch = plan.apply_ops
            skipped_ops = ()
    elif idempotent:
        logs.append("idempotent_fallback_full_sequence")
        ops_to_dispatch = plan.apply_ops
        skipped_ops = ()

    planned_op_names = tuple(op.operation for op in ops_to_dispatch)
    trail = begin_sealed_apply_trail(
        store,
        params=sealed_apply_params,
        ops_planned=planned_op_names,
    )
    if trail is not None and pre_state is not None:
        try:
            pre_read_fields = (
                _extract_interface_fields(pre_read_raw) if pre_read_raw is not None else None
            )
            trail.record_pre_apply_baseline(
                serialize_pre_apply_baseline_for_trail(
                    pre_state,
                    observed=pre_read_fields,
                    raw=pre_read_raw,
                )
            )
        except Exception:
            logs.append("sealed_apply pre_apply baseline trail write failed")

    def _run() -> WifiApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=ops_to_dispatch,
            credential_resolver=credential_resolver,
            logs=logs,
            trail=trail,
        )
        succeeded_op_names = tuple(step.op for step in steps if step.ok)

        def _finish_and_return(result: WifiApplyResult) -> WifiApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        def _build_failure_result(
            overall: ApplyOverallStatus,
            *,
            verification: WifiApplyVerification | None = None,
            extra_errors: tuple[str, ...] = (),
            observed: dict[str, Any] | None = None,
        ) -> WifiApplyResult:
            rollback: WifiApplyRollback | None
            rollback_errors: tuple[str, ...] = ()
            if compensate_on_failure:
                if succeeded_op_names:
                    rollback, rollback_errors = _attempt_compensating_rollback(
                        transport=transport,
                        apply_ops=plan.apply_ops,
                        succeeded_op_names=succeeded_op_names,
                        credential_resolver=credential_resolver,
                        logs=logs,
                        pre_state=pre_state,
                    )
                else:
                    rollback = _rollback_noop()
            else:
                rollback = _rollback_not_attempted()
            final_overall = _finalize_overall_with_rollback(overall, rollback=rollback)
            if observed is not None:
                on_air_observation = observe_on_air_apply(observed)
                on_air_status = on_air_observation.verdict
                on_air_explanation = on_air_observation.explanation
            else:
                on_air_status = _ON_AIR_UNVERIFIED
                on_air_explanation = explanation_for_skipped_observe(on_air_status)
            return _finish_and_return(
                WifiApplyResult(
                overall=final_overall,
                ap_id=plan.ap_id,
                steps=steps,
                verification=verification,
                errors=dispatch_errors + extra_errors,
                logs=tuple(logs),
                rollback=rollback,
                rollback_errors=rollback_errors,
                skipped_ops=skipped_ops,
                on_air_verification_status=on_air_status,
                verdict_explanation=on_air_explanation,
                )
            )

        if dispatch_errors:
            return _build_failure_result("failed")

        try:
            observed = _readback_show_interface(transport, plan.ap_id)
        except Exception:
            logs.append(_MSG_READBACK_FAILED)
            return _build_failure_result(
                "failed",
                verification=None,
                extra_errors=(_MSG_READBACK_FAILED,),
            )

        verification = _verify_applied(observed, intent.ssid, intent.wpa_mode)
        on_air_observation = observe_on_air_apply(observed)
        on_air_status = on_air_observation.verdict
        logs.append("readback verification completed")
        config_ok = (
            verification.ssid_ok and verification.encryption_ok and verification.admin_up_ok
        )
        if not config_ok:
            return _build_failure_result(
                "verify_mismatch",
                verification=verification,
                observed=observed,
            )

        if on_air_status == _ON_AIR_ADMIN_ONLY:
            return _finish_and_return(
                WifiApplyResult(
                overall="verify_mismatch",
                ap_id=plan.ap_id,
                steps=steps,
                verification=verification,
                errors=(),
                logs=tuple(logs),
                rollback=_rollback_not_attempted(),
                skipped_ops=skipped_ops,
                on_air_verification_status=on_air_status,
                verdict_explanation=on_air_observation.explanation,
                )
            )

        return _finish_and_return(
            WifiApplyResult(
            overall="applied",
            ap_id=plan.ap_id,
            steps=steps,
            verification=verification,
            errors=(),
            logs=tuple(logs),
            rollback=_rollback_not_attempted(),
            skipped_ops=skipped_ops,
            on_air_verification_status=on_air_status,
            verdict_explanation=on_air_observation.explanation,
            )
        )

    return guard_sealed_apply_trail(trail, _run)


def _band_for_ap_id(ap_id: str) -> WifiBand:
    if ap_id.startswith("WifiMaster1/"):
        return WifiBand.BAND_5GHZ
    return WifiBand.BAND_2_4GHZ


def teardown_wifi_ap(
    *,
    ap_id: str,
    transport: WifiApplyTransport,
    wpa_mode: WifiWpaMode = WifiWpaMode.WPA2,
    store: Any | None = None,
    sealed_apply_params: SealedApplyTrailParams | None = None,
) -> WifiApplyResult:
    normalized_ap = _validate_ap(ap_id)
    dummy_intent = WifiIntent(
        ssid="teardown",
        enabled=False,
        credential_ref_id=None,
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=False,
        band=_band_for_ap_id(normalized_ap),
        wpa_mode=wpa_mode,
    )
    plan = _compile_plan(dummy_intent, normalized_ap)
    logs: list[str] = [f"compiled {len(plan.teardown_ops)} teardown ops for {plan.ap_id}"]

    planned_op_names = tuple(op.operation for op in plan.teardown_ops)
    trail = begin_sealed_apply_trail(
        store,
        params=sealed_apply_params,
        ops_planned=planned_op_names,
    )

    def _run() -> WifiApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.teardown_ops,
            credential_resolver=lambda _ref: "",
            logs=logs,
            continue_on_error=True,
            trail=trail,
        )

        def _finish_and_return(result: WifiApplyResult) -> WifiApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        try:
            observed = _readback_show_interface(transport, plan.ap_id)
        except Exception:
            return _finish_and_return(
                WifiApplyResult(
                overall="failed",
                ap_id=plan.ap_id,
                steps=steps,
                verification=None,
                errors=(*dispatch_errors, _MSG_READBACK_FAILED),
                logs=tuple(logs + [_MSG_READBACK_FAILED]),
                )
            )

        verification = _verify_teardown(observed)
        on_air_observation = observe_on_air_teardown(observed)
        on_air_status = on_air_observation.verdict
        logs.append("teardown readback verification completed")
        admin_down_ok = not verification.admin_up_ok
        config_ok = verification.ssid_ok and verification.encryption_ok and admin_down_ok
        overall: ApplyOverallStatus
        if dispatch_errors:
            overall = "failed"
        elif not config_ok:
            overall = "verify_mismatch"
        elif on_air_status in {_ON_AIR_STILL_BROADCASTING, _ON_AIR_UNVERIFIED}:
            overall = "verify_mismatch"
        else:
            overall = "applied"

        return _finish_and_return(
            WifiApplyResult(
            overall=overall,
            ap_id=plan.ap_id,
            steps=steps,
            verification=verification,
            errors=dispatch_errors,
            logs=tuple(logs),
            on_air_verification_status=on_air_status,
            verdict_explanation=on_air_observation.explanation,
            )
        )

    return guard_sealed_apply_trail(trail, _run)
