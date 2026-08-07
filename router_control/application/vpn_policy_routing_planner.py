"""Offline VPN policy-routing intent → sealed RCI op descriptor compiler."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    is_canonical_wireguard_interface_id,
    is_wireguard_like_interface_name,
    validate_interface_id,
)
from router_control.adapters.netcraze.vpn_policy_probe import VpnPolicyParseStatus
from router_control.adapters.netcraze.vpn_policy_rci import (
    VpnPolicyRciOperation,
    op_notes_for,
    validate_ip_global_bound,
    validate_name_server_address,
    validate_name_server_domain,
    validate_policy_name,
)

_DOC = "OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md"
_VERIFICATION_STATUS = "help_verified_grammar_unapplied"
_OFFLINE_NOTE = (
    "VPN policy-routing compiled offline; grammar help-verified only; "
    f"verification_status={_VERIFICATION_STATUS}; NOT device-applied"
)

_OPEN_UNKNOWNS: tuple[str, ...] = (
    f"policy restricted to single connection unknown ({_DOC}:200 §5.1)",
    f"policy populated without permit global unknown ({_DOC}:201 §5.2; "
    f"permit global rejected {_DOC}:93-96)",
    f"policy interior ipv6/route function unknown ({_DOC}:202 §5.3)",
    f"WireGuard interface ip global expression unconfirmed ({_DOC}:77,:203 §5.4)",
)

_REQUIRED_INTENT_KEYS = frozenset({"policy_name", "vpn_interface", "ip_global"})
_OPTIONAL_INTENT_KEYS = frozenset(
    {"interface_kind", "address_configured", "name_servers"}
)
_ALLOWED_INTENT_KEYS = _REQUIRED_INTENT_KEYS | _OPTIONAL_INTENT_KEYS


class VpnPolicyRoutingPlannerError(ValueError):
    """Fail-closed compiler error for VPN policy-routing planning."""


@dataclass(frozen=True, slots=True)
class VpnPolicySealedOpDescriptor:
    operation: str
    policy_name: str | None = None
    interface_id: str | None = None
    name_server_address: str | None = None
    name_server_domain: str | None = None
    name_server_on_interface: str | None = None
    global_auto: bool = False
    global_order: int | None = None
    global_priority: int | None = None
    notes: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class VpnPolicyRoutingPlan:
    policy_name: str
    vpn_interface: str
    apply_ops: tuple[VpnPolicySealedOpDescriptor, ...]
    teardown_ops: tuple[VpnPolicySealedOpDescriptor, ...]
    verification_status: str
    unknowns: tuple[str, ...]
    notes: tuple[str, ...] = ()


# Canonical device form: ``WireguardN`` — ``allowlist.validate_wireguard_id`` only.
_WIREGUARD_CANONICAL_REFUSAL = (
    "vpn_interface must be canonical WireguardN "
    "(router_control/adapters/netcraze/allowlist.validate_wireguard_id)"
)


def _validate_ip_global_numeric(value: int, *, field: str) -> int:
    try:
        return validate_ip_global_bound(value, field=field)
    except ValueError as exc:
        raise VpnPolicyRoutingPlannerError(str(exc)) from exc


def _parse_ip_global(raw: Any) -> tuple[bool, int | None, int | None]:
    if raw == "auto":
        return True, None, None
    if isinstance(raw, dict):
        keys = set(raw.keys())
        unknown = keys - {"order", "priority"}
        if unknown:
            raise VpnPolicyRoutingPlannerError(
                f"unknown ip_global fields: {sorted(unknown)}"
            )
        if "order" in raw and "priority" in raw:
            raise VpnPolicyRoutingPlannerError(
                "ip_global must specify either order or priority, not both"
            )
        if "order" in raw:
            order = _validate_ip_global_numeric(raw["order"], field="order")
            return False, order, None
        if "priority" in raw:
            priority = _validate_ip_global_numeric(raw["priority"], field="priority")
            return False, None, priority
        raise VpnPolicyRoutingPlannerError("ip_global dict requires order or priority")
    raise VpnPolicyRoutingPlannerError("ip_global must be 'auto' or {order|priority} dict")


def _parse_name_servers(raw: Any) -> tuple[tuple[dict[str, str | None], ...], tuple[str, ...]]:
    if raw is None:
        return (), ()
    if not isinstance(raw, list):
        raise VpnPolicyRoutingPlannerError("name_servers must be a list")
    entries: list[dict[str, str | None]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, dict):
            raise VpnPolicyRoutingPlannerError(f"name_servers[{index}] must be an object")
        keys = set(item.keys())
        unknown = keys - {"address", "domain", "on_interface"}
        if unknown:
            raise VpnPolicyRoutingPlannerError(
                f"name_servers[{index}] unknown fields: {sorted(unknown)}"
            )
        if "address" not in item:
            raise VpnPolicyRoutingPlannerError(f"name_servers[{index}] missing address")
        address = validate_name_server_address(str(item["address"]))
        domain = (
            validate_name_server_domain(str(item["domain"]))
            if item.get("domain") is not None
            else None
        )
        on_interface = (
            validate_interface_id(str(item["on_interface"]))
            if item.get("on_interface") is not None
            else None
        )
        if on_interface is not None and domain is None:
            raise VpnPolicyRoutingPlannerError(
                f"name_servers[{index}] on_interface requires domain"
            )
        entries.append(
            {
                "address": address,
                "domain": domain,
                "on_interface": on_interface,
            }
        )
    return tuple(entries), ()


_IntentParsed = tuple[str, str, bool, int | None, int | None, tuple[dict[str, str | None], ...]]


def _validate_intent(intent: Mapping[str, Any]) -> _IntentParsed:
    keys = set(intent.keys())
    unknown = keys - _ALLOWED_INTENT_KEYS
    if unknown:
        raise VpnPolicyRoutingPlannerError(f"unknown intent fields: {sorted(unknown)}")
    missing = _REQUIRED_INTENT_KEYS - keys
    if missing:
        raise VpnPolicyRoutingPlannerError(
            f"missing required intent fields: {sorted(missing)}"
        )

    policy_name = validate_policy_name(str(intent["policy_name"]))
    raw_vpn_interface = str(intent["vpn_interface"])
    interface_kind = intent.get("interface_kind")
    interface_kind_text = str(interface_kind) if interface_kind is not None else None

    if is_wireguard_like_interface_name(raw_vpn_interface):
        if not is_canonical_wireguard_interface_id(raw_vpn_interface):
            raise VpnPolicyRoutingPlannerError(
                f"{_WIREGUARD_CANONICAL_REFUSAL}; "
                f"refusing non-canonical wireguard name: {raw_vpn_interface!r}"
            )
        is_wg = True
    elif interface_kind_text == "wireguard":
        raise VpnPolicyRoutingPlannerError(
            "interface_kind=wireguard requires canonical WireguardN vpn_interface "
            f"(allowlist.validate_wireguard_id); got: {raw_vpn_interface!r}"
        )
    else:
        is_wg = False

    vpn_interface = validate_interface_id(raw_vpn_interface)
    global_auto, global_order, global_priority = _parse_ip_global(intent["ip_global"])
    name_servers, _ = _parse_name_servers(intent.get("name_servers"))

    address_configured = intent.get("address_configured")

    if interface_kind is not None and interface_kind not in {"wireguard", "other"}:
        raise VpnPolicyRoutingPlannerError(
            f"interface_kind not allowlisted: {interface_kind!r}"
        )
    if is_wg:
        if address_configured is not True:
            raise VpnPolicyRoutingPlannerError(
                "WireGuard interface Address is NOT configured — refuse policy-routing "
                "until address_configured=true; no sealed WG interface-address op "
                "(wireguard_apply_planner honesty)"
            )
        if interface_kind != "wireguard":
            raise VpnPolicyRoutingPlannerError(
                "WireGuard vpn_interface requires interface_kind=wireguard"
            )
    elif address_configured is not None and address_configured is not True:
        raise VpnPolicyRoutingPlannerError(
            "address_configured may be omitted or true for non-WireGuard interfaces"
        )

    return (
        policy_name,
        vpn_interface,
        global_auto,
        global_order,
        global_priority,
        name_servers,
    )


def compile_vpn_policy_routing_intent(intent: Mapping[str, Any]) -> VpnPolicyRoutingPlan:
    (
        policy_name,
        vpn_interface,
        global_auto,
        global_order,
        global_priority,
        name_servers,
    ) = _validate_intent(intent)

    apply_ops: list[VpnPolicySealedOpDescriptor] = []
    for entry in name_servers:
        apply_ops.append(
            VpnPolicySealedOpDescriptor(
                operation=VpnPolicyRciOperation.SET_NAME_SERVER.value,
                name_server_address=entry["address"],
                name_server_domain=entry["domain"],
                name_server_on_interface=entry["on_interface"],
                notes=op_notes_for(VpnPolicyRciOperation.SET_NAME_SERVER),
            )
        )
    apply_ops.append(
        VpnPolicySealedOpDescriptor(
            operation=VpnPolicyRciOperation.IP_GLOBAL.value,
            interface_id=vpn_interface,
            global_auto=global_auto,
            global_order=global_order,
            global_priority=global_priority,
            notes=op_notes_for(VpnPolicyRciOperation.IP_GLOBAL),
        )
    )
    apply_ops.append(
        VpnPolicySealedOpDescriptor(
            operation=VpnPolicyRciOperation.CREATE_POLICY.value,
            policy_name=policy_name,
            notes=op_notes_for(VpnPolicyRciOperation.CREATE_POLICY),
        )
    )

    teardown_ops: list[VpnPolicySealedOpDescriptor] = []
    teardown_ops.append(
        VpnPolicySealedOpDescriptor(
            operation=VpnPolicyRciOperation.REMOVE_POLICY.value,
            policy_name=policy_name,
            notes=op_notes_for(VpnPolicyRciOperation.REMOVE_POLICY),
        )
    )
    teardown_ops.append(
        VpnPolicySealedOpDescriptor(
            operation=VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED.value,
            interface_id=vpn_interface,
            notes=op_notes_for(VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED),
        )
    )
    for entry in reversed(name_servers):
        teardown_ops.append(
            VpnPolicySealedOpDescriptor(
                operation=VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
                name_server_address=entry["address"],
                notes=op_notes_for(VpnPolicyRciOperation.CLEAR_NAME_SERVER),
            )
        )

    unknowns = list(_OPEN_UNKNOWNS)
    if is_canonical_wireguard_interface_id(vpn_interface):
        unknowns.append(
            f"compiled ip global targets WireGuard interface {vpn_interface!r}; "
            f"WG ip global unconfirmed ({_DOC}:77,:203 §5.4)"
        )

    return VpnPolicyRoutingPlan(
        policy_name=policy_name,
        vpn_interface=vpn_interface,
        apply_ops=tuple(apply_ops),
        teardown_ops=tuple(teardown_ops),
        verification_status=_VERIFICATION_STATUS,
        unknowns=tuple(unknowns),
        notes=(_OFFLINE_NOTE,),
    )


_APPLY_TO_COMPENSATE: dict[str, str] = {
    VpnPolicyRciOperation.CREATE_POLICY.value: VpnPolicyRciOperation.REMOVE_POLICY.value,
    VpnPolicyRciOperation.SET_NAME_SERVER.value: VpnPolicyRciOperation.CLEAR_NAME_SERVER.value,
}

_PRE_EXISTING_COMPENSATION_REASON = (
    "pre-existing configuration; compensation would destroy foreign state"
)
_PRE_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply state unknown; compensation skipped (fail-closed)"
)
_POLICY_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply policy state unknown; remove would destroy foreign state"
)
_NAME_SERVER_STATE_UNKNOWN_COMPENSATION_REASON = (
    "pre-apply name-server state unknown; clear would destroy foreign state"
)
_IP_GLOBAL_UNCOVERED_COMPENSATION_REASON = "no sealed negation grammar (unverified)"


@dataclass(frozen=True, slots=True)
class VpnPolicyApplyPreState:
    """Observed device state immediately before apply dispatch (compensation baseline)."""

    known: bool
    policy_existed: bool | None = None
    had_name_servers: bool | None = None
    had_ip_global: bool | None = None


def derive_vpn_policy_pre_state(
    *,
    policy_parse_status: str | None = None,
    name_server_parse_status: str | None = None,
) -> VpnPolicyApplyPreState:
    """Derive baseline from documented empty-probe classifications only; else fail-closed."""
    if policy_parse_status is None and name_server_parse_status is None:
        return VpnPolicyApplyPreState(known=False)

    policy_existed: bool | None = None
    policy_classified = False
    if policy_parse_status == VpnPolicyParseStatus.ZERO_POLICIES.value:
        policy_existed = False
        policy_classified = True
    elif policy_parse_status is not None:
        policy_existed = None

    had_name_servers: bool | None = None
    name_server_classified = False
    if name_server_parse_status == VpnPolicyParseStatus.EMPTY.value:
        had_name_servers = False
        name_server_classified = True
    elif name_server_parse_status is not None:
        had_name_servers = None

    if not policy_classified and not name_server_classified:
        return VpnPolicyApplyPreState(known=False)

    return VpnPolicyApplyPreState(
        known=True,
        policy_existed=policy_existed,
        had_name_servers=had_name_servers,
        had_ip_global=None,
    )


def _vpn_policy_compensation_blocked_reason(
    apply_op: str,
    pre_state: VpnPolicyApplyPreState | None,
) -> str | None:
    if pre_state is None:
        return None
    if not pre_state.known:
        return _PRE_STATE_UNKNOWN_COMPENSATION_REASON
    if apply_op == VpnPolicyRciOperation.CREATE_POLICY.value:
        if pre_state.policy_existed is None:
            return _POLICY_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.policy_existed:
            return _PRE_EXISTING_COMPENSATION_REASON
    if apply_op == VpnPolicyRciOperation.SET_NAME_SERVER.value:
        if pre_state.had_name_servers is None:
            return _NAME_SERVER_STATE_UNKNOWN_COMPENSATION_REASON
        if pre_state.had_name_servers:
            return _PRE_EXISTING_COMPENSATION_REASON
    return None



def _matched_apply_descriptors_for_succeeded_prefix(
    apply_ops: tuple[VpnPolicySealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
) -> list[VpnPolicySealedOpDescriptor]:
    """Match succeeded op names as a prefix of apply_ops in forward order."""
    matched: list[VpnPolicySealedOpDescriptor] = []
    succeeded_idx = 0
    for op in apply_ops:
        if succeeded_idx >= len(succeeded_op_names):
            break
        if op.operation == succeeded_op_names[succeeded_idx]:
            matched.append(op)
            succeeded_idx += 1
    return matched


def compensate_ops_for_succeeded_vpn_policy_apply(
    apply_ops: tuple[VpnPolicySealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: VpnPolicyApplyPreState | None = None,
) -> tuple[VpnPolicySealedOpDescriptor, ...]:
    """Return reverse-order compensating descriptors for succeeded apply ops only."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    compensate: list[VpnPolicySealedOpDescriptor] = []
    for orig in reversed(matched):
        compensate_op = _APPLY_TO_COMPENSATE.get(orig.operation)
        if compensate_op is None:
            continue
        if _vpn_policy_compensation_blocked_reason(orig.operation, pre_state) is not None:
            continue
        compensate.append(
            VpnPolicySealedOpDescriptor(
                operation=compensate_op,
                policy_name=orig.policy_name,
                interface_id=orig.interface_id,
                name_server_address=orig.name_server_address,
                name_server_domain=orig.name_server_domain,
                name_server_on_interface=orig.name_server_on_interface,
                global_auto=orig.global_auto,
                global_order=orig.global_order,
                global_priority=orig.global_priority,
                notes=orig.notes,
            )
        )
    return tuple(compensate)


def uncovered_compensate_ops_for_succeeded_vpn_policy_apply(
    apply_ops: tuple[VpnPolicySealedOpDescriptor, ...],
    succeeded_op_names: tuple[str, ...],
    pre_state: VpnPolicyApplyPreState | None = None,
) -> tuple[tuple[str, str], ...]:
    """Return succeeded apply ops whose compensation is blocked or unverified."""
    matched = _matched_apply_descriptors_for_succeeded_prefix(apply_ops, succeeded_op_names)
    uncovered: list[tuple[str, str]] = []
    for orig in matched:
        op_name = orig.operation
        if op_name in _APPLY_TO_COMPENSATE:
            blocked = _vpn_policy_compensation_blocked_reason(op_name, pre_state)
            if blocked is not None:
                uncovered.append((op_name, blocked))
            continue
        if op_name == VpnPolicyRciOperation.IP_GLOBAL.value:
            uncovered.append((op_name, _IP_GLOBAL_UNCOVERED_COMPENSATION_REASON))
    return tuple(uncovered)


__all__ = [
    "VpnPolicyApplyPreState",
    "VpnPolicyRoutingPlan",
    "VpnPolicyRoutingPlannerError",
    "VpnPolicySealedOpDescriptor",
    "compensate_ops_for_succeeded_vpn_policy_apply",
    "compile_vpn_policy_routing_intent",
    "derive_vpn_policy_pre_state",
    "uncovered_compensate_ops_for_succeeded_vpn_policy_apply",
]
