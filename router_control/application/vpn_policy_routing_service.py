"""VPN policy-routing preview + offline apply scaffold (no HTTP routes; no live default)."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from router_control.adapters.netcraze.fail_safe_rci import collect_rci_status_and_prompt
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.vpn_policy_rci import (
    VpnPolicyRciError,
    VpnPolicyRciOperation,
    sealed_request_for,
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
)
from router_control.application.vpn_policy_routing_planner import (
    VpnPolicyApplyPreState,
    VpnPolicyRoutingPlan,
    VpnPolicyRoutingPlannerError,
    VpnPolicySealedOpDescriptor,
    compensate_ops_for_succeeded_vpn_policy_apply,
    compile_vpn_policy_routing_intent,
    derive_vpn_policy_pre_state,
    uncovered_compensate_ops_for_succeeded_vpn_policy_apply,
)
from router_control.application.wifi_observation_helpers import ERROR_CODE_OP_DISPATCH_FAILED

BackupCallback = Callable[[], None]

_ALLOWED_PROMPTS = frozenset({"(config)"})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"

_MSG_LIVE_DISPATCH_DISABLED = (
    "live VPN policy apply dispatch is disabled; inject transport for offline tests only"
)
_MSG_OP_DISPATCH_FAILED = ERROR_CODE_OP_DISPATCH_FAILED


class VpnPolicyRoutingServiceError(ValueError):
    """Fail-closed VPN policy-routing service error."""


class VpnPolicyApplyTransport(Protocol):
    vpn_policy_offline_only: Literal[True]

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...


def require_vpn_policy_offline_transport(transport: object) -> None:
    if getattr(transport, "vpn_policy_offline_only", False) is not True:
        raise VpnPolicyRoutingServiceError(_MSG_LIVE_DISPATCH_DISABLED)


@dataclass(frozen=True, slots=True)
class VpnPolicyApplyStep:
    op: str
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"op": self.op, "ok": self.ok}
        if self.error is not None:
            payload["error"] = self.error
        return payload


@dataclass(frozen=True, slots=True)
class VpnPolicyApplyUncoveredRollbackOp:
    op: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {"op": self.op, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class VpnPolicyApplyRollback:
    attempted: bool
    ops: tuple[str, ...]
    outcome: ApplyRollbackOutcome
    steps: tuple[VpnPolicyApplyStep, ...] = ()
    uncovered_ops: tuple[VpnPolicyApplyUncoveredRollbackOp, ...] = ()

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
class VpnPolicyApplyResult:
    overall: ApplyOverallStatus
    policy_name: str
    verification_status: str
    steps: tuple[VpnPolicyApplyStep, ...]
    errors: tuple[str, ...]
    logs: tuple[str, ...]
    notes: tuple[str, ...] = ()
    rollback: VpnPolicyApplyRollback | None = None
    rollback_errors: tuple[str, ...] = ()

    @property
    def rollback_outcome(self) -> ApplyRollbackOutcome:
        if self.rollback is None:
            return "not_attempted"
        return self.rollback.outcome

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "overall": self.overall,
            "policy_name": self.policy_name,
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


def _op_to_preview_dict(op: VpnPolicySealedOpDescriptor) -> dict[str, object]:
    payload: dict[str, object] = {"operation": op.operation}
    if op.policy_name is not None:
        payload["policy_name"] = op.policy_name
    if op.interface_id is not None:
        payload["interface_id"] = op.interface_id
    if op.name_server_address is not None:
        payload["name_server_address"] = op.name_server_address
    if op.name_server_domain is not None:
        payload["name_server_domain"] = op.name_server_domain
    if op.name_server_on_interface is not None:
        payload["name_server_on_interface"] = op.name_server_on_interface
    if op.global_auto:
        payload["global_auto"] = True
    if op.global_order is not None:
        payload["global_order"] = op.global_order
    if op.global_priority is not None:
        payload["global_priority"] = op.global_priority
    if op.notes:
        payload["notes"] = list(op.notes)
    return payload


def plan_to_preview_dict(plan: VpnPolicyRoutingPlan) -> dict[str, object]:
    return {
        "policy_name": plan.policy_name,
        "vpn_interface": plan.vpn_interface,
        "verification_status": plan.verification_status,
        "unknowns": list(plan.unknowns),
        "notes": list(plan.notes),
        "apply_ops": [_op_to_preview_dict(op) for op in plan.apply_ops],
        "teardown_ops": [_op_to_preview_dict(op) for op in plan.teardown_ops],
    }


def preview_vpn_policy_routing(intent: Mapping[str, Any]) -> dict[str, object]:
    """Validate + compile only; no dispatch."""
    plan = _compile_plan(intent)
    return plan_to_preview_dict(plan)


def _compile_plan(intent: Mapping[str, Any]) -> VpnPolicyRoutingPlan:
    try:
        return compile_vpn_policy_routing_intent(intent)
    except (VpnPolicyRoutingPlannerError, ValueError) as exc:
        raise VpnPolicyRoutingServiceError(str(exc)) from exc


def _step_from_error(op_name: str, message: str) -> VpnPolicyApplyStep:
    return VpnPolicyApplyStep(op=op_name, ok=False, error=message)


def _rollback_not_attempted() -> VpnPolicyApplyRollback:
    return VpnPolicyApplyRollback(attempted=False, ops=(), outcome="not_attempted")


def _rollback_noop() -> VpnPolicyApplyRollback:
    return VpnPolicyApplyRollback(attempted=True, ops=(), outcome="noop")


def _finalize_vpn_policy_rollback_outcome(
    *,
    rollback_steps: tuple[VpnPolicyApplyStep, ...],
    rollback_errors: tuple[str, ...],
    uncovered_ops: tuple[VpnPolicyApplyUncoveredRollbackOp, ...],
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
    rollback: VpnPolicyApplyRollback | None,
) -> ApplyOverallStatus:
    if base_overall == "failed" and rollback is not None and rollback.outcome == "succeeded":
        return "rolled_back"
    return base_overall


def _execute_vpn_policy_op(
    transport: VpnPolicyApplyTransport,
    descriptor: VpnPolicySealedOpDescriptor,
) -> None:
    operation = VpnPolicyRciOperation(descriptor.operation)
    request = sealed_request_for(
        operation,
        policy_name=descriptor.policy_name,
        interface_id=descriptor.interface_id,
        name_server_address=descriptor.name_server_address,
        name_server_domain=descriptor.name_server_domain,
        name_server_on_interface=descriptor.name_server_on_interface,
        global_auto=descriptor.global_auto,
        global_order=descriptor.global_order,
        global_priority=descriptor.global_priority,
    )
    response = transport.execute_sealed_rci_write(request)
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise VpnPolicyRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise VpnPolicyRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise VpnPolicyRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise VpnPolicyRciError("RCI parse returned an unexpected status kind")


def _dispatch_ops(
    *,
    transport: VpnPolicyApplyTransport,
    ops: tuple[VpnPolicySealedOpDescriptor, ...],
    logs: list[str],
    continue_on_error: bool = False,
    trail: SealedApplyTrailHandle | None = None,
) -> tuple[tuple[VpnPolicyApplyStep, ...], tuple[str, ...]]:
    require_vpn_policy_offline_transport(transport)
    steps: list[VpnPolicyApplyStep] = []
    errors: list[str] = []
    for descriptor in ops:
        op_name = descriptor.operation
        try:
            VpnPolicyRciOperation(op_name)
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
            _execute_vpn_policy_op(transport, descriptor)
        except VpnPolicyRciError:
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
        success_step = VpnPolicyApplyStep(op=op_name, ok=True)
        steps.append(success_step)
        if trail is not None:
            trail.record_op(
                op_name,
                op_evidence_redacted=build_sealed_apply_op_evidence(success_step),
            )
    return tuple(steps), tuple(errors)


def _attempt_compensating_rollback(
    *,
    transport: VpnPolicyApplyTransport,
    apply_ops: tuple[VpnPolicySealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    logs: list[str],
    pre_state: VpnPolicyApplyPreState | None = None,
) -> tuple[VpnPolicyApplyRollback, tuple[str, ...]]:
    uncovered_pairs = uncovered_compensate_ops_for_succeeded_vpn_policy_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    uncovered_ops = tuple(
        VpnPolicyApplyUncoveredRollbackOp(op=op_name, reason=reason)
        for op_name, reason in uncovered_pairs
    )
    for item in uncovered_ops:
        logs.append(f"compensate uncovered {item.op}: {item.reason}")
    compensate_ops = compensate_ops_for_succeeded_vpn_policy_apply(
        apply_ops, succeeded_op_names, pre_state=pre_state
    )
    if not compensate_ops and not uncovered_ops:
        return _rollback_noop(), ()
    if not compensate_ops:
        return (
            VpnPolicyApplyRollback(
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
    outcome = _finalize_vpn_policy_rollback_outcome(
        rollback_steps=rollback_steps,
        rollback_errors=rollback_errors,
        uncovered_ops=uncovered_ops,
    )
    return (
        VpnPolicyApplyRollback(
            attempted=True,
            ops=op_names,
            outcome=outcome,
            steps=rollback_steps,
            uncovered_ops=uncovered_ops,
        ),
        rollback_errors,
    )


def apply_vpn_policy_routing_intent(
    *,
    intent: Mapping[str, Any],
    transport: VpnPolicyApplyTransport | None = None,
    backup_callback: BackupCallback | None = None,
    compensate_on_failure: bool = False,
    store: Any | None = None,
    trail_params: SealedApplyTrailParams | None = None,
    pre_state: VpnPolicyApplyPreState | None = None,
) -> VpnPolicyApplyResult:
    if transport is None:
        raise VpnPolicyRoutingServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    require_vpn_policy_offline_transport(transport)

    plan = _compile_plan(intent)
    baseline = pre_state if pre_state is not None else derive_vpn_policy_pre_state()
    logs: list[str] = [f"compiled {len(plan.apply_ops)} apply ops for {plan.policy_name}"]

    if backup_callback is not None:
        backup_callback()
        logs.append("backup_callback invoked")

    trail = begin_sealed_apply_trail(
        store,
        params=trail_params,
        ops_planned=tuple(op.operation for op in plan.apply_ops),
    )

    def _run() -> VpnPolicyApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.apply_ops,
            logs=logs,
            trail=trail,
        )
        succeeded_op_names = tuple(step.op for step in steps if step.ok)

        def _finish(result: VpnPolicyApplyResult) -> VpnPolicyApplyResult:
            finish_sealed_apply_trail(
                trail,
                overall=result.overall,
                outcome_snapshot=outcome_snapshot_from_apply_result(result),
            )
            return result

        if dispatch_errors:
            rollback: VpnPolicyApplyRollback
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
                VpnPolicyApplyResult(
                    overall=overall,
                    policy_name=plan.policy_name,
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
            VpnPolicyApplyResult(
                overall="dispatched_offline",
                policy_name=plan.policy_name,
                verification_status=plan.verification_status,
                steps=steps,
                errors=(),
                logs=tuple(logs),
                notes=plan.notes,
                rollback=_rollback_not_attempted(),
            )
        )

    return guard_sealed_apply_trail(trail, _run)


def teardown_vpn_policy_routing_intent(
    *,
    intent: Mapping[str, Any],
    transport: VpnPolicyApplyTransport | None = None,
    store: Any | None = None,
    trail_params: SealedApplyTrailParams | None = None,
) -> VpnPolicyApplyResult:
    if transport is None:
        raise VpnPolicyRoutingServiceError(_MSG_LIVE_DISPATCH_DISABLED)
    require_vpn_policy_offline_transport(transport)

    plan = _compile_plan(intent)
    logs: list[str] = [f"compiled {len(plan.teardown_ops)} teardown ops for {plan.policy_name}"]

    trail = begin_sealed_apply_trail(
        store,
        params=trail_params,
        ops_planned=tuple(op.operation for op in plan.teardown_ops),
    )

    def _run() -> VpnPolicyApplyResult:
        steps, dispatch_errors = _dispatch_ops(
            transport=transport,
            ops=plan.teardown_ops,
            logs=logs,
            trail=trail,
        )
        overall: ApplyOverallStatus = "failed" if dispatch_errors else "dispatched_offline"
        result = VpnPolicyApplyResult(
            overall=overall,
            policy_name=plan.policy_name,
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


__all__ = [
    "VpnPolicyApplyResult",
    "VpnPolicyApplyTransport",
    "VpnPolicyRoutingServiceError",
    "apply_vpn_policy_routing_intent",
    "plan_to_preview_dict",
    "preview_vpn_policy_routing",
    "require_vpn_policy_offline_transport",
    "teardown_vpn_policy_routing_intent",
]
