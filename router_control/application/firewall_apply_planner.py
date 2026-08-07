"""Offline firewall deployment intent → sealed RCI op descriptor compiler."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.firewall_rci import (
    FirewallRciOperation,
    validate_action,
    validate_destination_family,
    validate_ordinal,
)
from router_control.application.grammar_doc_refs import build_planner_op_notes

_FW_RCI = "router_control/adapters/netcraze/firewall_rci.py"
_FW_FAMILY = "firewall"

_REQUIRED_INTENT_KEYS = frozenset({"zone_id", "rules"})
_RULE_KEYS = frozenset({"action", "destination_family", "ordinal"})
_OFFLINE_NOTE = (
    "Firewall apply compiled offline; grammar is offline_unverified / not device-certified; "
    "verification_status=offline_unverified"
)
_MAX_ZONE_ID_LEN = 64


class FirewallApplyPlannerError(ValueError):
    """Fail-closed compiler error for firewall apply planning."""


@dataclass(frozen=True, slots=True)
class FirewallSealedOpDescriptor:
    operation: str
    zone_id: str
    action: str | None = None
    destination_family: str | None = None
    ordinal: int | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class FirewallApplyPlan:
    zone_id: str
    rules: tuple[tuple[str, str, int], ...]
    apply_ops: tuple[FirewallSealedOpDescriptor, ...]
    teardown_ops: tuple[FirewallSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...] = ()


def _validate_zone_id(raw: Any) -> str:
    if not isinstance(raw, str):
        raise FirewallApplyPlannerError("zone_id must be a non-empty string")
    zone_id = raw.strip()
    if not zone_id or len(zone_id) > _MAX_ZONE_ID_LEN:
        raise FirewallApplyPlannerError("zone_id must be a non-empty bounded string")
    return zone_id


def _validate_rules(raw: Any) -> tuple[tuple[str, str, int], ...]:
    if raw is None or not isinstance(raw, list):
        raise FirewallApplyPlannerError("rules must be a list")
    rules: list[tuple[str, str, int]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise FirewallApplyPlannerError(f"rule {idx} must be a dict")
        keys = set(item.keys())
        unknown = keys - _RULE_KEYS
        if unknown:
            raise FirewallApplyPlannerError(f"rule {idx} unknown fields: {sorted(unknown)}")
        missing = _RULE_KEYS - keys
        if missing:
            raise FirewallApplyPlannerError(f"rule {idx} missing fields: {sorted(missing)}")
        raw_ordinal = item["ordinal"]
        if isinstance(raw_ordinal, bool) or not isinstance(raw_ordinal, int):
            raise FirewallApplyPlannerError(f"rule {idx} ordinal must be an integer")
        try:
            action = validate_action(str(item["action"]))
            family = validate_destination_family(str(item["destination_family"]))
            ordinal = validate_ordinal(raw_ordinal)
        except ValueError as exc:
            raise FirewallApplyPlannerError(str(exc)) from exc
        rules.append((action, family, ordinal))
    return tuple(sorted(rules, key=lambda r: r[2]))


def _validate_intent(intent: Mapping[str, Any]) -> tuple[str, tuple[tuple[str, str, int], ...]]:
    keys = set(intent.keys())
    unknown = keys - _REQUIRED_INTENT_KEYS
    if unknown:
        raise FirewallApplyPlannerError(f"unknown intent fields: {sorted(unknown)}")
    missing = _REQUIRED_INTENT_KEYS - keys
    if missing:
        raise FirewallApplyPlannerError(f"missing required intent fields: {sorted(missing)}")
    try:
        zone_id = _validate_zone_id(intent["zone_id"])
        rules = _validate_rules(intent["rules"])
    except ValueError as exc:
        raise FirewallApplyPlannerError(str(exc)) from exc
    return zone_id, rules


def _firewall_op_notes(operation: FirewallRciOperation) -> tuple[str, ...]:
    return build_planner_op_notes(
        _FW_FAMILY,
        operation.value,
        sealed_template=f"firewall_rci.command_for {operation.name} ({_FW_RCI})",
    )


def compile_firewall_intent_to_ops(intent: Mapping[str, Any]) -> FirewallApplyPlan:
    zone_id, rules = _validate_intent(intent)

    apply_ops = tuple(
        FirewallSealedOpDescriptor(
            operation=FirewallRciOperation.ADD_RULE.value,
            zone_id=zone_id,
            action=action,
            destination_family=family,
            ordinal=ordinal,
            notes=_firewall_op_notes(FirewallRciOperation.ADD_RULE),
        )
        for action, family, ordinal in rules
    )
    teardown_ops = tuple(
        FirewallSealedOpDescriptor(
            operation=FirewallRciOperation.REMOVE_RULE.value,
            zone_id=zone_id,
            ordinal=ordinal,
            notes=_firewall_op_notes(FirewallRciOperation.REMOVE_RULE),
        )
        for _, _, ordinal in reversed(rules)
    )

    return FirewallApplyPlan(
        zone_id=zone_id,
        rules=rules,
        apply_ops=apply_ops,
        teardown_ops=teardown_ops,
        verification_status="offline_unverified",
        notes=(_OFFLINE_NOTE,),
    )


_APPLY_TO_COMPENSATE: dict[str, str] = {
    FirewallRciOperation.ADD_RULE.value: FirewallRciOperation.REMOVE_RULE.value,
}

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_RULES_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply access-list state unknown; remove would destroy foreign state"
)


@dataclass(frozen=True, slots=True)
class FirewallApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    had_rules: bool | None = None


def derive_firewall_pre_state(
    observed: Mapping[str, Any] | None = None,
) -> FirewallApplyPreState:
    """Derive compensation baseline; no sealed access-list show parser — always fail-closed."""
    _ = observed
    return FirewallApplyPreState(known=False)


def _firewall_compensation_blocked_reason(
    apply_op: str,
    pre_state: FirewallApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == FirewallRciOperation.ADD_RULE.value:
        if pre_state.had_rules is None:
            return _RULES_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_rules:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None


def _matched_apply_descriptors_for_succeeded_prefix(
    apply_ops: tuple[FirewallSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
) -> list[FirewallSealedOpDescriptor]:
    """Match succeeded op names as a prefix of apply_ops in forward order."""
    matched: list[FirewallSealedOpDescriptor] = []
    succeeded_idx = 0
    for op in apply_ops:
        if succeeded_idx >= len(succeeded_op_names):
            break
        if op.operation == succeeded_op_names[succeeded_idx]:
            matched.append(op)
            succeeded_idx += 1
    return matched


def compensate_ops_for_succeeded_firewall_apply(
    apply_ops: tuple[FirewallSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: FirewallApplyPreState | None = None,
) -> tuple[FirewallSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    compensate: list[FirewallSealedOpDescriptor] = []
    for orig in reversed(matched):
        compensate_op = _APPLY_TO_COMPENSATE.get(orig.operation)
        if compensate_op is None:
            continue
        if _firewall_compensation_blocked_reason(orig.operation, pre_state) is not None:
            continue
        compensate.append(
            FirewallSealedOpDescriptor(
                operation=compensate_op,
                zone_id=orig.zone_id,
                action=orig.action,
                destination_family=orig.destination_family,
                ordinal=orig.ordinal,
                notes=orig.notes,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_firewall_apply(
    apply_ops: tuple[FirewallSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: FirewallApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return succeeded apply ops whose compensation is blocked or unverified."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    uncovered: list[tuple[str, str]] = []
    for orig in matched:
        op_name = orig.operation
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _firewall_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
    return tuple(uncovered)
