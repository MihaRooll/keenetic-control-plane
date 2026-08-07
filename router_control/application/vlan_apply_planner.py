"""Offline VLAN deployment intent → sealed RCI op descriptor compiler."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.vlan_rci import VlanRciOperation, validate_vlan_bridge_id
from router_control.application.grammar_doc_refs import build_planner_op_notes

_VLAN_RCI = "router_control/adapters/netcraze/vlan_rci.py"
_VLAN_FAMILY = "vlan"

_REQUIRED_INTENT_KEYS = frozenset({"zone_id", "vlan_id", "ipv4_cidr", "ipv4_gateway"})
_MAX_ZONE_ID_LEN = 64
_OFFLINE_NOTE = (
    "VLAN bridge apply compiled offline; port tagged/untagged grammar not in this slice; "
    "verification_status=offline_unverified"
)


class VlanApplyPlannerError(ValueError):
    """Fail-closed compiler error for VLAN apply planning."""


@dataclass(frozen=True, slots=True)
class VlanSealedOpDescriptor:
    operation: str
    bridge_id: str
    zone_id: str | None = None
    vlan_id: int | None = None
    ipv4_cidr: str | None = None
    ipv4_gateway: str | None = None
    ipv4_mask: str | None = None
    security_level: str | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VlanApplyPlan:
    bridge_id: str
    zone_id: str
    vlan_id: int
    ipv4_cidr: str
    ipv4_gateway: str
    apply_ops: tuple[VlanSealedOpDescriptor, ...]
    teardown_ops: tuple[VlanSealedOpDescriptor, ...]
    verification_status: str
    notes: tuple[str, ...] = ()


def _validate_zone_id(raw: Any) -> str:
    if not isinstance(raw, str):
        raise VlanApplyPlannerError("zone_id must be a non-empty string")
    zone_id = raw.strip()
    if not zone_id or len(zone_id) > _MAX_ZONE_ID_LEN:
        raise VlanApplyPlannerError("zone_id must be a non-empty bounded string")
    return zone_id


def _validate_vlan_id(raw: Any) -> int:
    if isinstance(raw, bool) or not isinstance(raw, int):
        raise VlanApplyPlannerError("vlan_id must be an integer")
    vlan_id = int(raw)
    if vlan_id < 1 or vlan_id > 4094:
        raise VlanApplyPlannerError("vlan_id must be in range 1..4094")
    return vlan_id


def _validate_ipv4_cidr(raw: Any) -> ipaddress.IPv4Network:
    if not isinstance(raw, str) or not raw.strip():
        raise VlanApplyPlannerError("ipv4_cidr must be a non-empty string")
    try:
        network = ipaddress.IPv4Network(raw.strip(), strict=False)
    except ValueError as exc:
        raise VlanApplyPlannerError(f"invalid ipv4_cidr: {raw!r}") from exc
    return network


def _validate_ipv4_gateway(raw: Any, network: ipaddress.IPv4Network) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise VlanApplyPlannerError("ipv4_gateway must be a non-empty string")
    try:
        gateway = ipaddress.IPv4Address(raw.strip())
    except ValueError as exc:
        raise VlanApplyPlannerError(f"invalid ipv4_gateway: {raw!r}") from exc
    if gateway not in network:
        raise VlanApplyPlannerError("ipv4_gateway must belong to ipv4_cidr network")
    if gateway in {network.network_address, network.broadcast_address}:
        raise VlanApplyPlannerError("ipv4_gateway must not be network or broadcast address")
    return str(gateway)


def _validate_intent(intent: Mapping[str, Any]) -> tuple[str, int, ipaddress.IPv4Network, str]:
    keys = set(intent.keys())
    unknown = keys - _REQUIRED_INTENT_KEYS
    if unknown:
        raise VlanApplyPlannerError(f"unknown intent fields: {sorted(unknown)}")
    missing = _REQUIRED_INTENT_KEYS - keys
    if missing:
        raise VlanApplyPlannerError(f"missing required intent fields: {sorted(missing)}")
    zone_id = _validate_zone_id(intent["zone_id"])
    vlan_id = _validate_vlan_id(intent["vlan_id"])
    network = _validate_ipv4_cidr(intent["ipv4_cidr"])
    gateway = _validate_ipv4_gateway(intent["ipv4_gateway"], network)
    return zone_id, vlan_id, network, gateway


def _vlan_op_notes(operation: VlanRciOperation, *, vlan_id: int) -> tuple[str, ...]:
    return build_planner_op_notes(
        _VLAN_FAMILY,
        operation.value,
        sealed_template=f"vlan_rci.command_for {operation.name} ({_VLAN_RCI})",
        extra=(f"vlan_id={vlan_id} carried for audit; port tag grammar not in this slice",),
    )


def compile_vlan_intent_to_ops(intent: Mapping[str, Any], bridge_id: str) -> VlanApplyPlan:
    normalized_bridge = validate_vlan_bridge_id(bridge_id)
    zone_id, vlan_id, network, gateway = _validate_intent(intent)
    ipv4_cidr = str(network)
    ipv4_mask = str(network.netmask)

    apply_ops = (
        VlanSealedOpDescriptor(
            operation=VlanRciOperation.CREATE_BRIDGE.value,
            bridge_id=normalized_bridge,
            zone_id=zone_id,
            vlan_id=vlan_id,
            ipv4_cidr=ipv4_cidr,
            ipv4_gateway=gateway,
            notes=_vlan_op_notes(VlanRciOperation.CREATE_BRIDGE, vlan_id=vlan_id),
        ),
        VlanSealedOpDescriptor(
            operation=VlanRciOperation.SET_IP_ADDRESS.value,
            bridge_id=normalized_bridge,
            zone_id=zone_id,
            vlan_id=vlan_id,
            ipv4_cidr=ipv4_cidr,
            ipv4_gateway=gateway,
            ipv4_mask=ipv4_mask,
            notes=_vlan_op_notes(VlanRciOperation.SET_IP_ADDRESS, vlan_id=vlan_id),
        ),
        VlanSealedOpDescriptor(
            operation=VlanRciOperation.UP.value,
            bridge_id=normalized_bridge,
            zone_id=zone_id,
            vlan_id=vlan_id,
            ipv4_cidr=ipv4_cidr,
            ipv4_gateway=gateway,
            notes=_vlan_op_notes(VlanRciOperation.UP, vlan_id=vlan_id),
        ),
    )
    teardown_ops = (
        VlanSealedOpDescriptor(
            operation=VlanRciOperation.DOWN.value,
            bridge_id=normalized_bridge,
            zone_id=zone_id,
            vlan_id=vlan_id,
            notes=_vlan_op_notes(VlanRciOperation.DOWN, vlan_id=vlan_id),
        ),
        VlanSealedOpDescriptor(
            operation=VlanRciOperation.CLEAR_IP_ADDRESS.value,
            bridge_id=normalized_bridge,
            zone_id=zone_id,
            vlan_id=vlan_id,
            notes=_vlan_op_notes(VlanRciOperation.CLEAR_IP_ADDRESS, vlan_id=vlan_id),
        ),
        VlanSealedOpDescriptor(
            operation=VlanRciOperation.REMOVE_BRIDGE.value,
            bridge_id=normalized_bridge,
            zone_id=zone_id,
            vlan_id=vlan_id,
            notes=_vlan_op_notes(VlanRciOperation.REMOVE_BRIDGE, vlan_id=vlan_id),
        ),
    )
    return VlanApplyPlan(
        bridge_id=normalized_bridge,
        zone_id=zone_id,
        vlan_id=vlan_id,
        ipv4_cidr=ipv4_cidr,
        ipv4_gateway=gateway,
        apply_ops=apply_ops,
        teardown_ops=teardown_ops,
        verification_status="offline_unverified",
        notes=(_OFFLINE_NOTE,),
    )


_APPLY_TO_COMPENSATE: dict[str, str] = {
    VlanRciOperation.CREATE_BRIDGE.value: VlanRciOperation.REMOVE_BRIDGE.value,
    VlanRciOperation.SET_IP_ADDRESS.value: VlanRciOperation.CLEAR_IP_ADDRESS.value,
    VlanRciOperation.UP.value: VlanRciOperation.DOWN.value,
}

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_BRIDGE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply bridge state unknown; remove would destroy foreign state"
)
_IP_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply IP state unknown; clear would destroy foreign state"
)
_ADMIN_UP_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply admin-up state unknown; down would destroy foreign state"
)


@dataclass(frozen=True, slots=True)
class VlanApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    bridge_existed: bool | None = None
    had_ip: bool | None = None
    was_admin_up: bool | None = None


def derive_vlan_pre_state(
    observed: Mapping[str, Any] | None = None,
) -> VlanApplyPreState:
    """Derive compensation baseline; no sealed VLAN show parser — always fail-closed."""
    _ = observed
    return VlanApplyPreState(known=False)


def _vlan_compensation_blocked_reason(
    apply_op: str,
    pre_state: VlanApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == VlanRciOperation.CREATE_BRIDGE.value:
        if pre_state.bridge_existed is None:
            return _BRIDGE_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.bridge_existed:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == VlanRciOperation.SET_IP_ADDRESS.value:
        if pre_state.had_ip is None:
            return _IP_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_ip:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == VlanRciOperation.UP.value:
        if pre_state.was_admin_up is None:
            return _ADMIN_UP_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.was_admin_up:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None


def _matched_apply_descriptors_for_succeeded_prefix(
    apply_ops: tuple[VlanSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
) -> list[VlanSealedOpDescriptor]:
    """Match succeeded op names as a prefix of apply_ops in forward order."""
    matched: list[VlanSealedOpDescriptor] = []
    succeeded_idx = 0
    for op in apply_ops:
        if succeeded_idx >= len(succeeded_op_names):
            break
        if op.operation == succeeded_op_names[succeeded_idx]:
            matched.append(op)
            succeeded_idx += 1
    return matched


def compensate_ops_for_succeeded_vlan_apply(
    apply_ops: tuple[VlanSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: VlanApplyPreState | None = None,
) -> tuple[VlanSealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    compensate: list[VlanSealedOpDescriptor] = []
    for orig in reversed(matched):
        compensate_op = _APPLY_TO_COMPENSATE.get(orig.operation)
        if compensate_op is None:
            continue
        if _vlan_compensation_blocked_reason(orig.operation, pre_state) is not None:
            continue
        compensate.append(
            VlanSealedOpDescriptor(
                operation=compensate_op,
                bridge_id=orig.bridge_id,
                zone_id=orig.zone_id,
                vlan_id=orig.vlan_id,
                ipv4_cidr=orig.ipv4_cidr,
                ipv4_gateway=orig.ipv4_gateway,
                ipv4_mask=orig.ipv4_mask,
                security_level=orig.security_level,
                notes=orig.notes,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_vlan_apply(
    apply_ops: tuple[VlanSealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: VlanApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return succeeded apply ops whose compensation is blocked or unverified."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    uncovered: list[tuple[str, str]] = []
    for orig in matched:
        op_name = orig.operation
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _vlan_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
    return tuple(uncovered)
