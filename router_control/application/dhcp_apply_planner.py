"""Offline DHCP deployment intent → sealed RCI op descriptor compiler."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.dhcp_rci import (
    DhcpRciOperation,
    validate_ipv4_address,
    validate_lease_seconds,
    validate_mac_address,
)
from router_control.application.grammar_doc_refs import build_planner_op_notes

_DHCP_RCI = "router_control/adapters/netcraze/dhcp_rci.py"
_DHCP_FAMILY = "dhcp"

_REQUIRED_INTENT_KEYS = frozenset(
    {"zone_id", "pool_start", "pool_end", "lease_seconds", "reservations"}
)
_RESERVATION_KEYS = frozenset({"mac_address", "ipv4_address"})
_OFFLINE_NOTE = (
    "DHCP pool apply compiled offline; grammar is offline_unverified / not device-certified; "
    "verification_status=offline_unverified"
)
_MAX_ZONE_ID_LEN = 64


class DhcpApplyPlannerError(ValueError):
    """Fail-closed compiler error for DHCP apply planning."""


@dataclass(frozen=True, slots=True)
class DhcpSealedOpDescriptor:
    operation: str
    zone_id: str
    pool_start: str | None = None
    pool_end: str | None = None
    lease_seconds: int | None = None
    mac_address: str | None = None
    ipv4_address: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DhcpApplyPlan:
    zone_id: str
    pool_start: str
    pool_end: str
    lease_seconds: int
    reservations: tuple[tuple[str, str], ...]
    apply_ops: tuple[DhcpSealedOpDescriptor, ...]
    teardown_ops: tuple[DhcpSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...] = ()


def _validate_zone_id(raw: Any) -> str:
    if not isinstance(raw, str):
        raise DhcpApplyPlannerError("zone_id must be a non-empty string")
    zone_id = raw.strip()
    if not zone_id or len(zone_id) > _MAX_ZONE_ID_LEN:
        raise DhcpApplyPlannerError("zone_id must be a non-empty bounded string")
    return zone_id


def _validate_reservations(raw: Any) -> tuple[tuple[str, str], ...]:
    if raw is None or not isinstance(raw, list):
        raise DhcpApplyPlannerError("reservations must be a list")
    reservations: list[tuple[str, str]] = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            raise DhcpApplyPlannerError(f"reservation {idx} must be a dict")
        keys = set(item.keys())
        unknown = keys - _RESERVATION_KEYS
        if unknown:
            raise DhcpApplyPlannerError(
                f"reservation {idx} unknown fields: {sorted(unknown)}"
            )
        missing = _RESERVATION_KEYS - keys
        if missing:
            raise DhcpApplyPlannerError(
                f"reservation {idx} missing fields: {sorted(missing)}"
            )
        try:
            mac = validate_mac_address(str(item["mac_address"]))
            addr = validate_ipv4_address(str(item["ipv4_address"]))
        except ValueError as exc:
            raise DhcpApplyPlannerError(str(exc)) from exc
        reservations.append((mac, addr))
    return tuple(reservations)


def _validate_intent(
    intent: Mapping[str, Any],
) -> tuple[str, str, str, int, tuple[tuple[str, str], ...]]:
    keys = set(intent.keys())
    unknown = keys - _REQUIRED_INTENT_KEYS
    if unknown:
        raise DhcpApplyPlannerError(f"unknown intent fields: {sorted(unknown)}")
    missing = _REQUIRED_INTENT_KEYS - keys
    if missing:
        raise DhcpApplyPlannerError(f"missing required intent fields: {sorted(missing)}")
    raw_lease = intent["lease_seconds"]
    if isinstance(raw_lease, bool) or not isinstance(raw_lease, int):
        raise DhcpApplyPlannerError("lease_seconds must be an integer")
    try:
        zone_id = _validate_zone_id(intent["zone_id"])
        pool_start = validate_ipv4_address(str(intent["pool_start"]))
        pool_end = validate_ipv4_address(str(intent["pool_end"]))
        lease_seconds = validate_lease_seconds(raw_lease)
        reservations = _validate_reservations(intent["reservations"])
    except ValueError as exc:
        raise DhcpApplyPlannerError(str(exc)) from exc
    return zone_id, pool_start, pool_end, lease_seconds, reservations


def _dhcp_op_notes(operation: DhcpRciOperation) -> tuple[str, ...]:
    return build_planner_op_notes(
        _DHCP_FAMILY,
        operation.value,
        sealed_template=f"dhcp_rci.command_for {operation.name} ({_DHCP_RCI})",
    )


def compile_dhcp_intent_to_ops(intent: Mapping[str, Any]) -> DhcpApplyPlan:
    zone_id, pool_start, pool_end, lease_seconds, reservations = _validate_intent(intent)

    apply_ops: list[DhcpSealedOpDescriptor] = [
        DhcpSealedOpDescriptor(
            operation=DhcpRciOperation.SET_POOL.value,
            zone_id=zone_id,
            pool_start=pool_start,
            pool_end=pool_end,
            notes=_dhcp_op_notes(DhcpRciOperation.SET_POOL),
        ),
        DhcpSealedOpDescriptor(
            operation=DhcpRciOperation.SET_LEASE.value,
            zone_id=zone_id,
            lease_seconds=lease_seconds,
            notes=_dhcp_op_notes(DhcpRciOperation.SET_LEASE),
        ),
    ]
    for mac, addr in reservations:
        apply_ops.append(
            DhcpSealedOpDescriptor(
                operation=DhcpRciOperation.BIND_HOST.value,
                zone_id=zone_id,
                mac_address=mac,
                ipv4_address=addr,
                notes=_dhcp_op_notes(DhcpRciOperation.BIND_HOST),
            )
        )

    teardown_ops: list[DhcpSealedOpDescriptor] = []
    for mac, addr in reversed(reservations):
        teardown_ops.append(
            DhcpSealedOpDescriptor(
                operation=DhcpRciOperation.UNBIND_HOST.value,
                zone_id=zone_id,
                mac_address=mac,
                ipv4_address=addr,
                notes=_dhcp_op_notes(DhcpRciOperation.UNBIND_HOST),
            )
        )
    teardown_ops.append(
        DhcpSealedOpDescriptor(
            operation=DhcpRciOperation.CLEAR_POOL.value,
            zone_id=zone_id,
            notes=_dhcp_op_notes(DhcpRciOperation.CLEAR_POOL),
        )
    )

    return DhcpApplyPlan(
        zone_id=zone_id,
        pool_start=pool_start,
        pool_end=pool_end,
        lease_seconds=lease_seconds,
        reservations=reservations,
        apply_ops=tuple(apply_ops),
        teardown_ops=tuple(teardown_ops),
        verification_status="offline_unverified",
        notes=(_OFFLINE_NOTE,),
    )


_APPLY_TO_COMPENSATE: dict[str, str] = {
    DhcpRciOperation.SET_POOL.value: DhcpRciOperation.CLEAR_POOL.value,
    DhcpRciOperation.BIND_HOST.value: DhcpRciOperation.UNBIND_HOST.value,
}

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_POOL_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply pool state unknown; clear would destroy foreign state"
)
_LEASE_UNCOVERED_COMPENSATION_REASON = "no sealed lease-clear op"
_RESERVATION_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply reservation state unknown; unbind would destroy foreign state"
)


@dataclass(frozen=True, slots=True)
class DhcpApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    pool_existed: bool | None = None
    had_lease: bool | None = None
    had_reservations: bool | None = None


def derive_dhcp_pre_state(
    observed: Mapping[str, Any] | None = None,
) -> DhcpApplyPreState:
    """Derive compensation baseline; no sealed DHCP show parser — always fail-closed."""
    _ = observed
    return DhcpApplyPreState(known=False)


def _dhcp_compensation_blocked_reason(
    apply_op: str,
    pre_state: DhcpApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == DhcpRciOperation.SET_POOL.value:
        if pre_state.pool_existed is None:
            return _POOL_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.pool_existed:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == DhcpRciOperation.BIND_HOST.value:
        if pre_state.had_reservations is None:
            return _RESERVATION_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_reservations:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None


def _matched_apply_descriptors_for_succeeded_prefix(
    apply_ops: tuple[DhcpSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
) -> list[DhcpSealedOpDescriptor]:
    """Match succeeded op names as a prefix of apply_ops in forward order."""
    matched: list[DhcpSealedOpDescriptor] = []
    succeeded_idx = 0
    for op in apply_ops:
        if succeeded_idx >= len(succeeded_op_names):
            break
        if op.operation == succeeded_op_names[succeeded_idx]:
            matched.append(op)
            succeeded_idx += 1
    return matched


def compensate_ops_for_succeeded_dhcp_apply(
    apply_ops: tuple[DhcpSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: DhcpApplyPreState | None = None,
) -> tuple[DhcpSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    compensate: list[DhcpSealedOpDescriptor] = []
    for orig in reversed(matched):
        compensate_op = _APPLY_TO_COMPENSATE.get(orig.operation)
        if compensate_op is None:
            continue
        if _dhcp_compensation_blocked_reason(orig.operation, pre_state) is not None:
            continue
        compensate.append(
            DhcpSealedOpDescriptor(
                operation=compensate_op,
                zone_id=orig.zone_id,
                pool_start=orig.pool_start,
                pool_end=orig.pool_end,
                lease_seconds=orig.lease_seconds,
                mac_address=orig.mac_address,
                ipv4_address=orig.ipv4_address,
                notes=orig.notes,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_dhcp_apply(
    apply_ops: tuple[DhcpSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: DhcpApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return succeeded apply ops whose compensation is blocked or unverified."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    uncovered: list[tuple[str, str]] = []
    for orig in matched:
        op_name = orig.operation
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _dhcp_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
        if op_name == DhcpRciOperation.SET_LEASE.value:
            uncovered.append((op_name, _LEASE_UNCOVERED_COMPENSATION_REASON))
    return tuple(uncovered)
