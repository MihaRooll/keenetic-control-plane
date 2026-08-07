"""Sealed RCI builders for VPN connection-policy grammar (help-verified; not device-applied).

Grammar source: ``docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md`` §2b / §7 only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum

from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    validate_interface_id,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.application.grammar_doc_refs import build_planner_op_notes

_DOC = "docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md"
_VPN_RCI = "router_control/adapters/netcraze/vpn_policy_rci.py"
_VPN_FAMILY = "vpn_policy"
_IPV4_DOTTED_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_FQDN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_MAX_POLICY_NAME_LEN = 64
_RESERVED_POLICY_NAMES = frozenset({"permit", "deny", "global"})


class VpnPolicyRciError(Exception):
    """RCI VPN policy operation failed validation or is not allowlisted."""


class VpnPolicyRciOperation(StrEnum):
    CREATE_POLICY = "vpn_policy_create"
    REMOVE_POLICY = "vpn_policy_remove"
    IP_GLOBAL = "vpn_policy_ip_global"
    IP_GLOBAL_TEARDOWN_UNVERIFIED = "vpn_policy_ip_global_teardown_unverified"
    SET_NAME_SERVER = "vpn_policy_set_name_server"
    CLEAR_NAME_SERVER = "vpn_policy_clear_name_server"


@dataclass(frozen=True, slots=True)
class VpnPolicyRciResult:
    operation: VpnPolicyRciOperation
    policy_name: str | None
    interface_id: str | None
    name_server_address: str | None
    cli_command: str | None
    notes: tuple[str, ...] = ()


def refuse_ip_policy_permit_global() -> None:
    """Reject vendor kill-switch pattern rejected on Gate A firmware (:93-96)."""
    raise ValueError(
        "ip policy permit global rejected on this firmware: "
        "no such command: global; kill-switch unresolved "
        f"({_DOC}:93-96)"
    )


def validate_policy_name(policy_name: str) -> str:
    normalized = policy_name.strip()
    if not normalized or len(normalized) > _MAX_POLICY_NAME_LEN:
        raise ValueError(f"policy name not allowlisted: {policy_name!r}")
    if normalized.lower() in _RESERVED_POLICY_NAMES:
        raise ValueError(f"policy name reserved: {policy_name!r}")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", normalized):
        raise ValueError(f"policy name not allowlisted: {policy_name!r}")
    return normalized


def validate_name_server_address(address: str) -> str:
    candidate = address.strip()
    host = candidate
    if ":" in candidate and not candidate.startswith("["):
        host, _, port_text = candidate.rpartition(":")
        if not port_text.isdigit():
            raise ValueError(f"invalid name-server address: {address!r}")
        port = int(port_text)
        if port < 1 or port > 65535:
            raise ValueError(f"invalid name-server address: {address!r}")
    if not _IPV4_DOTTED_RE.fullmatch(host):
        raise ValueError(f"invalid name-server address: {address!r}")
    try:
        addr = ipaddress.IPv4Address(host)
    except ValueError as exc:
        raise ValueError(f"invalid name-server address: {address!r}") from exc
    return candidate if ":" in candidate else str(addr)


def validate_name_server_domain(domain: str) -> str:
    normalized = domain.strip().lower().rstrip(".")
    if not normalized or len(normalized) > 253 or not _FQDN_RE.match(normalized):
        raise ValueError(f"invalid name-server domain: {domain!r}")
    return normalized


# Same ``interface … ip global {priority}`` / ``order {N}`` bounds as wifi station uplink.
# Sealed 0..65535 from ``wifi_station_rci._validate_priority`` — upper bound not
# exhaustively probed on WireGuard or non-station interfaces.
IP_GLOBAL_BOUND_MIN = 0
IP_GLOBAL_BOUND_MAX = 65535
_IP_GLOBAL_BOUND_NOTE = (
    "(sealed wifi_station_rci template; upper bound not device-exhaustive)"
)


def validate_ip_global_bound(value: int, *, field: str) -> int:
    """Validate ``interface … ip global`` order/priority (shared planner + RCI)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"ip global {field} must be integer")
    if value < IP_GLOBAL_BOUND_MIN or value > IP_GLOBAL_BOUND_MAX:
        raise ValueError(
            f"ip global {field} must be in range "
            f"{IP_GLOBAL_BOUND_MIN}..{IP_GLOBAL_BOUND_MAX} "
            f"{_IP_GLOBAL_BOUND_NOTE}"
        )
    return value


def command_for(
    operation: VpnPolicyRciOperation,
    *,
    policy_name: str | None = None,
    interface_id: str | None = None,
    name_server_address: str | None = None,
    name_server_domain: str | None = None,
    name_server_on_interface: str | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> str:
    if operation is VpnPolicyRciOperation.CREATE_POLICY:
        if policy_name is None:
            raise VpnPolicyRciError("policy_name is required for CREATE_POLICY")
        name = validate_policy_name(policy_name)
        return f"ip policy {name}"
    if operation is VpnPolicyRciOperation.REMOVE_POLICY:
        if policy_name is None:
            raise VpnPolicyRciError("policy_name is required for REMOVE_POLICY")
        name = validate_policy_name(policy_name)
        return f"no ip policy {name}"
    if operation is VpnPolicyRciOperation.IP_GLOBAL:
        if interface_id is None:
            raise VpnPolicyRciError("interface_id is required for IP_GLOBAL")
        iface = validate_interface_id(interface_id)
        if global_auto:
            return f"interface {iface} ip global auto"
        if global_order is not None:
            order = validate_ip_global_bound(global_order, field="order")
            return f"interface {iface} ip global order {order}"
        if global_priority is None:
            raise VpnPolicyRciError("global_priority or global_auto required for IP_GLOBAL")
        priority = validate_ip_global_bound(global_priority, field="priority")
        return f"interface {iface} ip global {priority}"
    if operation is VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED:
        raise VpnPolicyRciError(
            "interface ip global teardown not in discovery doc "
            f"({_DOC}:74-76 apply only; :203 open unknown)"
        )
    if operation is VpnPolicyRciOperation.SET_NAME_SERVER:
        if name_server_address is None:
            raise VpnPolicyRciError("name_server_address is required for SET_NAME_SERVER")
        addr = validate_name_server_address(name_server_address)
        parts = [f"ip name-server {addr}"]
        if name_server_domain is not None:
            domain = validate_name_server_domain(name_server_domain)
            parts.append(domain)
            if name_server_on_interface is not None:
                on_iface = validate_interface_id(name_server_on_interface)
                parts.append(f"on {on_iface}")
        elif name_server_on_interface is not None:
            raise VpnPolicyRciError("name_server_domain required when on_interface is set")
        return " ".join(parts)
    if operation is VpnPolicyRciOperation.CLEAR_NAME_SERVER:
        if name_server_address is None:
            raise VpnPolicyRciError("name_server_address is required for CLEAR_NAME_SERVER")
        addr = validate_name_server_address(name_server_address)
        return f"no ip name-server {addr}"
    raise VpnPolicyRciError(f"operation not allowlisted: {operation}")


def op_notes_for(operation: VpnPolicyRciOperation) -> tuple[str, ...]:
    extra: tuple[str, ...] = ()
    verification_kind: str | None = "help-verified"
    if operation is VpnPolicyRciOperation.IP_GLOBAL:
        extra = (
            "WireGuard form unconfirmed "
            "(docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md §5.4)",
        )
    if operation is VpnPolicyRciOperation.IP_GLOBAL_TEARDOWN_UNVERIFIED:
        extra = ("teardown grammar not in discovery doc",)
        verification_kind = None
    if operation is VpnPolicyRciOperation.CLEAR_NAME_SERVER:
        extra = (
            "negation from sealed dns_rci template "
            "(router_control/adapters/netcraze/dns_rci.py); "
            "discovery documents positive ip name-server only",
        )
        verification_kind = None
    return build_planner_op_notes(
        _VPN_FAMILY,
        operation.value,
        sealed_template=f"vpn_policy_rci.command_for {operation.name} ({_VPN_RCI})",
        extra=extra,
        verification_kind=verification_kind,
    )


def sealed_request_for(
    operation: VpnPolicyRciOperation,
    *,
    policy_name: str | None = None,
    interface_id: str | None = None,
    name_server_address: str | None = None,
    name_server_domain: str | None = None,
    name_server_on_interface: str | None = None,
    global_auto: bool = False,
    global_order: int | None = None,
    global_priority: int | None = None,
) -> SealedRciWriteRequest:
    cli = command_for(
        operation,
        policy_name=policy_name,
        interface_id=interface_id,
        name_server_address=name_server_address,
        name_server_domain=name_server_domain,
        name_server_on_interface=name_server_on_interface,
        global_auto=global_auto,
        global_order=global_order,
        global_priority=global_priority,
    )
    return SealedRciWriteRequest(body=build_sealed_parse_body(cli))


__all__ = [
    "VpnPolicyRciError",
    "VpnPolicyRciOperation",
    "VpnPolicyRciResult",
    "command_for",
    "op_notes_for",
    "refuse_ip_policy_permit_global",
    "sealed_request_for",
    "IP_GLOBAL_BOUND_MAX",
    "IP_GLOBAL_BOUND_MIN",
    "validate_ip_global_bound",
    "validate_name_server_address",
    "validate_name_server_domain",
    "validate_policy_name",
]
