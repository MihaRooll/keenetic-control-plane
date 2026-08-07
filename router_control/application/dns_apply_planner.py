"""Offline DNS deployment intent → sealed RCI op descriptor compiler."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.dns_rci import (
    DnsRciOperation,
    validate_local_fqdn,
    validate_upstream_resolver,
)
from router_control.application.grammar_doc_refs import build_planner_op_notes

_DNS_RCI = "router_control/adapters/netcraze/dns_rci.py"
_DNS_FAMILY = "dns"

_REQUIRED_INTENT_KEYS = frozenset({"zone_id", "local_fqdn", "upstream_resolvers"})
_OFFLINE_NOTE = (
    "DNS apply compiled offline; grammar is offline_unverified / not device-certified; "
    "verification_status=offline_unverified"
)
_MAX_ZONE_ID_LEN = 64


class DnsApplyPlannerError(ValueError):
    """Fail-closed compiler error for DNS apply planning."""


@dataclass(frozen=True, slots=True)
class DnsSealedOpDescriptor:
    operation: str
    zone_id: str
    local_fqdn: str | None = None
    upstream_resolver: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DnsApplyPlan:
    zone_id: str
    local_fqdn: str
    upstream_resolvers: tuple[str, ...]
    apply_ops: tuple[DnsSealedOpDescriptor, ...]
    teardown_ops: tuple[DnsSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...] = ()


def _validate_zone_id(raw: Any) -> str:
    if not isinstance(raw, str):
        raise DnsApplyPlannerError("zone_id must be a non-empty string")
    zone_id = raw.strip()
    if not zone_id or len(zone_id) > _MAX_ZONE_ID_LEN:
        raise DnsApplyPlannerError("zone_id must be a non-empty bounded string")
    return zone_id


def _validate_upstream_resolvers(raw: Any) -> tuple[str, ...]:
    if raw is None or not isinstance(raw, list):
        raise DnsApplyPlannerError("upstream_resolvers must be a list")
    resolvers: list[str] = []
    for item in raw:
        try:
            resolvers.append(validate_upstream_resolver(str(item)))
        except ValueError as exc:
            raise DnsApplyPlannerError(str(exc)) from exc
    return tuple(resolvers)


def _validate_intent(intent: Mapping[str, Any]) -> tuple[str, str, tuple[str, ...]]:
    keys = set(intent.keys())
    unknown = keys - _REQUIRED_INTENT_KEYS
    if unknown:
        raise DnsApplyPlannerError(f"unknown intent fields: {sorted(unknown)}")
    missing = _REQUIRED_INTENT_KEYS - keys
    if missing:
        raise DnsApplyPlannerError(f"missing required intent fields: {sorted(missing)}")
    try:
        zone_id = _validate_zone_id(intent["zone_id"])
        local_fqdn = validate_local_fqdn(str(intent["local_fqdn"]))
        resolvers = _validate_upstream_resolvers(intent["upstream_resolvers"])
    except ValueError as exc:
        raise DnsApplyPlannerError(str(exc)) from exc
    return zone_id, local_fqdn, resolvers


def _dns_op_notes(operation: DnsRciOperation) -> tuple[str, ...]:
    return build_planner_op_notes(
        _DNS_FAMILY,
        operation.value,
        sealed_template=f"dns_rci.command_for {operation.name} ({_DNS_RCI})",
    )


def compile_dns_intent_to_ops(intent: Mapping[str, Any]) -> DnsApplyPlan:
    zone_id, local_fqdn, resolvers = _validate_intent(intent)

    apply_ops: list[DnsSealedOpDescriptor] = [
        DnsSealedOpDescriptor(
            operation=DnsRciOperation.SET_STATIC_HOST.value,
            zone_id=zone_id,
            local_fqdn=local_fqdn,
            notes=_dns_op_notes(DnsRciOperation.SET_STATIC_HOST),
        ),
    ]
    for resolver in resolvers:
        apply_ops.append(
            DnsSealedOpDescriptor(
                operation=DnsRciOperation.SET_UPSTREAM.value,
                zone_id=zone_id,
                upstream_resolver=resolver,
                notes=_dns_op_notes(DnsRciOperation.SET_UPSTREAM),
            )
        )

    teardown_ops: list[DnsSealedOpDescriptor] = []
    for resolver in reversed(resolvers):
        teardown_ops.append(
            DnsSealedOpDescriptor(
                operation=DnsRciOperation.CLEAR_UPSTREAM.value,
                zone_id=zone_id,
                upstream_resolver=resolver,
                notes=_dns_op_notes(DnsRciOperation.CLEAR_UPSTREAM),
            )
        )
    teardown_ops.append(
        DnsSealedOpDescriptor(
            operation=DnsRciOperation.CLEAR_STATIC_HOST.value,
            zone_id=zone_id,
            local_fqdn=local_fqdn,
            notes=_dns_op_notes(DnsRciOperation.CLEAR_STATIC_HOST),
        )
    )

    return DnsApplyPlan(
        zone_id=zone_id,
        local_fqdn=local_fqdn,
        upstream_resolvers=resolvers,
        apply_ops=tuple(apply_ops),
        teardown_ops=tuple(teardown_ops),
        verification_status="offline_unverified",
        notes=(_OFFLINE_NOTE,),
    )


_APPLY_TO_COMPENSATE: dict[str, str] = {
    DnsRciOperation.SET_STATIC_HOST.value: DnsRciOperation.CLEAR_STATIC_HOST.value,
    DnsRciOperation.SET_UPSTREAM.value: DnsRciOperation.CLEAR_UPSTREAM.value,
}

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_STATIC_HOST_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply static host state unknown; clear would destroy foreign state"
)
_UPSTREAM_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply upstream state unknown; clear would destroy foreign state"
)


@dataclass(frozen=True, slots=True)
class DnsApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    had_static_host: bool | None = None
    had_upstreams: bool | None = None


def derive_dns_pre_state(
    observed: Mapping[str, Any] | None = None,
) -> DnsApplyPreState:
    """Derive compensation baseline; no sealed DNS inventory parser — always fail-closed."""
    _ = observed
    return DnsApplyPreState(known=False)


def _dns_compensation_blocked_reason(
    apply_op: str,
    pre_state: DnsApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == DnsRciOperation.SET_STATIC_HOST.value:
        if pre_state.had_static_host is None:
            return _STATIC_HOST_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_static_host:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == DnsRciOperation.SET_UPSTREAM.value:
        if pre_state.had_upstreams is None:
            return _UPSTREAM_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_upstreams:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None


def _matched_apply_descriptors_for_succeeded_prefix(
    apply_ops: tuple[DnsSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
) -> list[DnsSealedOpDescriptor]:
    """Match succeeded op names as a prefix of apply_ops in forward order."""
    matched: list[DnsSealedOpDescriptor] = []
    succeeded_idx = 0
    for op in apply_ops:
        if succeeded_idx >= len(succeeded_op_names):
            break
        if op.operation == succeeded_op_names[succeeded_idx]:
            matched.append(op)
            succeeded_idx += 1
    return matched


def compensate_ops_for_succeeded_dns_apply(
    apply_ops: tuple[DnsSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: DnsApplyPreState | None = None,
) -> tuple[DnsSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    compensate: list[DnsSealedOpDescriptor] = []
    for orig in reversed(matched):
        compensate_op = _APPLY_TO_COMPENSATE.get(orig.operation)
        if compensate_op is None:
            continue
        if _dns_compensation_blocked_reason(orig.operation, pre_state) is not None:
            continue
        compensate.append(
            DnsSealedOpDescriptor(
                operation=compensate_op,
                zone_id=orig.zone_id,
                local_fqdn=orig.local_fqdn,
                upstream_resolver=orig.upstream_resolver,
                notes=orig.notes,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_dns_apply(
    apply_ops: tuple[DnsSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: DnsApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return succeeded apply ops whose compensation is blocked or unverified."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    uncovered: list[tuple[str, str]] = []
    for orig in matched:
        op_name = orig.operation
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _dns_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
    return tuple(uncovered)
