"""VLAN Configure → Apply service (offline sealed executor; not composition-wired).

Preview/build is deterministic and safe offline. ``apply_vlan_intent`` requires an
explicit injected transport (fake-transport unit tests only). There is no
``composition.py`` wiring, no HTTP routes, and no default live router dispatch
until Gate B VLAN certification / WriteCertified.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.vlan_rci import (
    VlanRciError,
    VlanRciOperation,
    VlanRciResult,
    execute_vlan_rci,
    validate_vlan_bridge_id,
)
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
)
from router_control.application.vlan_apply_planner import (
    VlanApplyPlan,
    VlanApplyPlannerError,
    VlanApplyPreState,
    VlanSealedOpDescriptor,
    compensate_ops_for_succeeded_vlan_apply,
    compile_vlan_intent_to_ops,
    derive_vlan_pre_state,
    uncovered_compensate_ops_for_succeeded_vlan_apply,
)
from router_control.application.wifi_observation_helpers import ERROR_CODE_OP_DISPATCH_FAILED

BackupCallback = Callable[[], None]

_MSG_LIVE_DISPATCH_DISABLED = (
    "live VLAN apply dispatch is disabled; inject transport for offline tests only"
)
_MSG_OP_DISPATCH_FAILED = ERROR_CODE_OP_DISPATCH_FAILED


class VlanApplyServiceError(ValueError):
    """Fail-closed VLAN apply service error."""


class VlanApplyTransport(Protocol):
    vlan_offline_only: Literal[True]

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...


def require_vlan_offline_transport(transport: object) -> None:
    """Fail-closed guard: block live NetcrazeHttpTransport unless explicitly marked offline-only."""
    if getattr(transport, "vlan_offline_only", False) is not True:
        raise VlanApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)


@dataclass(frozen=True, slots=True)
class VlanApplyStep:
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
class VlanApplyUncoveredRollbackOp:
    op: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class VlanApplyRollback:
    attempted: bool
    ops: tuple[str, ...]
    outcome: ApplyRollbackOutcome
    steps: tuple[VlanApplyStep, ...] = ()
    uncovered_ops: tuple[VlanApplyUncoveredRollbackOp, ...] = ()

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
class VlanApplyResult:
    overall: ApplyOverallStatus
    bridge_id: str
    verification_status: str
    steps: tuple[VlanApplyStep, ...]
    errors: tuple[str, ...]
    logs: tuple[str, ...]
    notes: tuple[str, ...] = ()
    rollback: VlanApplyRollback | None = None
    rollback_errors: tuple[str, ...] = ()

    @property
    def rollback_outcome(self) -> ApplyRollbackOutcome:
        if self.rollback is None:
            return "not_attempted"
        return self.rollback.outcome

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "overall": self.overall,
            "bridge_id": self.bridge_id,
            "verification_status": self.verification_status,
            "rollback_outcome": self.rollback_outcome,
            "notes": list(self.notes),
            "steps": [step.to_dict() for step in self.steps],
            "errors": list(self.errors),
            "logs": list(self.logs),
        }
        if self.rollback is not None:
            payload["rollback"] = self.rollback.to_dict()
        if self.rollback_errors:
            payload["rollback_errors"] = list(self.rollback_errors)
        return payload


def _op_to_preview_dict(op: VlanSealedOpDescriptor) -> dict[str, object]:
    payload: dict[str, object] = {"operation": op.operation, "bridge_id": op.bridge_id}
    if op.zone_id is not None:
        payload["zone_id"] = op.zone_id
    if op.vlan_id is not None:
        payload["vlan_id"] = op.vlan_id
    if op.ipv4_cidr is not None:
        payload["ipv4_cidr"] = op.ipv4_cidr
    if op.ipv4_gateway is not None:
        payload["ipv4_gateway"] = op.ipv4_gateway
    if op.ipv4_mask is not None:
        payload["ipv4_mask"] = op.ipv4_mask
    if op.security_level is not None:
        payload["security_level"] = op.security_level
    if op.notes:
        payload["notes"] = list(op.notes)
    return payload


def plan_to_preview_dict(plan: VlanApplyPlan) -> dict[str, object]:
    return {
        "bridge_id": plan.bridge_id,
        "zone_id": plan.zone_id,
        "vlan_id": plan.vlan_id,
        "ipv4_cidr": plan.ipv4_cidr,
        "ipv4_gateway": plan.ipv4_gateway,
        "verification_status": plan.verification_status,
        "notes": list(plan.notes),
        "apply_ops": [_op_to_preview_dict(op) for op in plan.apply_ops],
        "teardown_ops": [_op_to_preview_dict(op) for op in plan.teardown_ops],
    }


def preview_vlan_apply(intent: Mapping[str, Any], bridge_id: str) -> dict[str, object]:
    """Validate + compile only; no dispatch."""
    plan = _compile_plan(intent, bridge_id)
    return plan_to_preview_dict(plan)


def _compile_plan(intent: Mapping[str, Any], bridge_id: str) -> VlanApplyPlan:
    try:
        return compile_vlan_intent_to_ops(intent, bridge_id)
    except (VlanApplyPlannerError, ValueError) as exc:
        raise VlanApplyServiceError(str(exc)) from exc


def _validate_bridge(bridge_id: str) -> str:
    try:
        return validate_vlan_bridge_id(bridge_id)
    except ValueError as exc:
        raise VlanApplyServiceError(str(exc)) from exc


def _status_ident(result: VlanRciResult) -> str | None:
    if not result.status_entries:
        return None
    return result.status_entries[0].ident


def _step_from_result(op_name: str, result: VlanRciResult) -> VlanApplyStep:
    return VlanApplyStep(op=op_name, ok=True, status_ident=_status_ident(result))


def _step_from_error(op_name: str, message: str) -> VlanApplyStep:
    return VlanApplyStep(op=op_name, ok=False, error=message)


def _rollback_not_attempted() -> VlanApplyRollback:
    return VlanApplyRollback(attempted=False, ops=(), outcome="not_attempted")


def _rollback_noop() -> VlanApplyRollback:
    return VlanApplyRollback(attempted=True, ops=(), outcome="noop")


def _finalize_vlan_rollback_outcome(
    *,
    rollback_steps: tuple[VlanApplyStep, ...],
    rollback_errors: tuple[str, ...],
    uncovered_ops: tuple[VlanApplyUncoveredRollbackOp, ...],
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
    if uncovered_ops and outcome in {"succeeded", "noop"}:
        return "partial"
    return outcome


def _finalize_overall_with_rollback(
    base_overall: ApplyOverallStatus,
    *,
    rollback: VlanApplyRollback | None,
) -> ApplyOverallStatus:
    if base_overall == "failed" and rollback is not None and rollback.outcome == "succeeded":
        return "rolled_back"
    return base_overall


def _dispatch_ops(
    *,
    transport: VlanApplyTransport,
    ops: tuple[VlanSealedOpDescriptor, ...],
    logs: list[str],
    continue_on_error: bool = False,
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[tuple[VlanApplyStep, ...], tuple[str, ...]]:
    require_vlan_offline_transport(transport)
    steps: list[VlanApplyStep] = []
    errors: list[str] = []
    for descriptor in ops:
        op_name = descriptor.operation
        try:
            operation = VlanRciOperation(op_name)
        except ValueError:
            message = f"unsupported operation: {op_name}"
            steps.append(_step_from_error(op_name, message))
            errors.append(message)
            logs.append(f"dispatch failed for {op_name}: {message}")
            if not continue_on_error:
                return tuple(steps), tuple(errors)
            continue

        intent_recorded = False
        if trail is not None:
            trail.record_op_intent(op_name)
            intent_recorded = True

        try:
            result = execute_vlan_rci(
                transport,
                operation,
                descriptor.bridge_id,
                ipv4_address=descriptor.ipv4_gateway,
                ipv4_mask=descriptor.ipv4_mask,
                security_level=descriptor.security_level,
            )
        except VlanRciError:
            failure_step = _step_from_error(op_name, _MSG_OP_DISPATCH_FAILED)
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
        except Exception:
            failure_step = _step_from_error(op_name, _MSG_OP_DISPATCH_FAILED)
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


def _attempt_compensating_rollback(
    *,
    transport: VlanApplyTransport,
    apply_ops: tuple[VlanSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    logs: list[str],
    pre_state: VlanApplyPreState | None = None,
) -> tuple[VlanApplyRollback, tuple[str, ...]]:
    uncovered_pairs = uncovered_compensate_ops_for_succeeded_vlan_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    uncovered_ops = tuple(
        VlanApplyUncoveredRollbackOp(op=op_name, reason=reason)
        for op_name, reason in uncovered_pairs
    )
    for item in uncovered_ops:
        logs.append(f"compensate uncovered {item.op}: {item.reason}")
    compensate_ops = compensate_ops_for_succeeded_vlan_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    if not compensate_ops and not uncovered_ops:
        return _rollback_noop(), ()
    if not compensate_ops:
        return (
            VlanApplyRollback(
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
        logs=logs,
        continue_on_error=True,
    )
    outcome = _finalize_vlan_rollback_outcome(
        rollback_steps=rollback_steps,
        rollback_errors=rollback_errors,
        uncovered_ops=uncovered_ops,
    )
    return (
        VlanApplyRollback(
            attempted=True,
            ops=op_names,
            outcome=outcome,
            steps=rollback_steps,
            uncovered_ops=uncovered_ops,
        ),
        rollback_errors,
    )


def apply_vlan_intent(
    *,
    intent: Mapping[str, Any],
    bridge_id: str,
    transport: VlanApplyTransport | None = None,
    backup_callback: BackupCallback | None = None,
    compensate_on_failure: bool = False,
    store: Any | None = None,
    trail_params: SealedApplyTrailParams | None = None,
    pre_state: VlanApplyPreState | None = None,
) -> VlanApplyResult:
    if transport is None:
        raise VlanApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    require_vlan_offline_transport(transport)

    normalized_bridge = _validate_bridge(bridge_id)
    plan = _compile_plan(intent, normalized_bridge)
    baseline = pre_state if pre_state is not None else derive_vlan_pre_state(None)
    logs: list[str] = [f"compiled {len(plan.apply_ops)} apply ops for {plan.bridge_id}"]

    if backup_callback is not None:
        backup_callback()
        logs.append("backup_callback invoked")

    trail = begin_sealed_apply_trail(
        store,
        params=trail_params,
        ops_planned=tuple(op.operation for op in plan.apply_ops),
    )

    def _run() -> VlanApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.apply_ops,
            logs=logs,
            trail=trail,
        )
        succeeded_op_names = tuple(step.op for step in steps if step.ok)

        def _finish(result: VlanApplyResult) -> VlanApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        if dispatch_errors:
            rollback: VlanApplyRollback
            rollback_errors: tuple[str, ...] = ()
            if compensate_on_failure and succeeded_op_names:
                rollback, rollback_errors = _attempt_compensating_rollback(
                    transport=transport,
                    apply_ops=plan.apply_ops,
                    succeeded_op_names=succeeded_op_names,
                    logs=logs,
                    pre_state=baseline,
                )
            elif compensate_on_failure:
                rollback = _rollback_noop()
            else:
                rollback = _rollback_not_attempted()
            overall = _finalize_overall_with_rollback("failed", rollback=rollback)
            return _finish(
                VlanApplyResult(
                    overall=overall,
                    bridge_id=plan.bridge_id,
                    verification_status=plan.verification_status,
                    steps=steps,
                    errors=dispatch_errors,
                    logs=tuple(logs),
                    notes=plan.notes,
                    rollback=rollback,
                    rollback_errors=rollback_errors,
                )
            )

        logs.append("offline dispatch completed without device readback verification")
        return _finish(
            VlanApplyResult(
                overall="dispatched_offline",
                bridge_id=plan.bridge_id,
                verification_status=plan.verification_status,
                steps=steps,
                errors=(),
                logs=tuple(logs),
                notes=plan.notes,
                rollback=_rollback_not_attempted(),
            )
        )

    return guard_sealed_apply_trail(trail, _run)


def teardown_vlan_bridge(
    *,
    intent: Mapping[str, Any],
    bridge_id: str,
    transport: VlanApplyTransport | None = None,
    store: Any | None = None,
    trail_params: SealedApplyTrailParams | None = None,
) -> VlanApplyResult:
    if transport is None:
        raise VlanApplyServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    require_vlan_offline_transport(transport)

    normalized_bridge = _validate_bridge(bridge_id)
    plan = _compile_plan(intent, normalized_bridge)
    logs: list[str] = [f"compiled {len(plan.teardown_ops)} teardown ops for {plan.bridge_id}"]

    trail = begin_sealed_apply_trail(
        store,
        params=trail_params,
        ops_planned=tuple(op.operation for op in plan.teardown_ops),
    )

    def _run() -> VlanApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.teardown_ops,
            logs=logs,
            trail=trail,
        )
        overall: ApplyOverallStatus = "failed" if dispatch_errors else "dispatched_offline"
        result = VlanApplyResult(
            overall=overall,
            bridge_id=plan.bridge_id,
            verification_status=plan.verification_status,
            steps=steps,
            errors=dispatch_errors,
            logs=tuple(logs),
            notes=plan.notes,
            rollback=_rollback_not_attempted(),
        )
        finish_sealed_apply_trail(
            trail,
            overall=result.overall,
            outcome_snapshot=outcome_snapshot_from_apply_result(result),
        )
        return result

    return guard_sealed_apply_trail(trail, _run)
