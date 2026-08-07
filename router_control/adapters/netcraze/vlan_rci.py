"""Typed, sealed RCI VLAN bridge create/remove/ip/security/up/down operations."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeStatusEntry,
    RciSealedWriteTransport,
    collect_rci_status_and_prompt,
)
from router_control.adapters.netcraze.rci_validation import RciValidationError
from router_control.adapters.netcraze.transport import SealedRciWriteRequest

_ALLOWED_PROMPTS = frozenset({"(config)"})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"
_ALLOWED_VLAN_BRIDGES = frozenset(f"Bridge{i}" for i in range(2, 10))
_ALLOWED_SECURITY_LEVELS = frozenset({"private", "protected", "public"})
_IPV4_DOTTED_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class VlanRciError(Exception):
    """RCI VLAN bridge operation failed or returned an unverifiable ack."""


class VlanRciOperation(StrEnum):
    CREATE_BRIDGE = "vlan_create_bridge"
    REMOVE_BRIDGE = "vlan_remove_bridge"
    SET_IP_ADDRESS = "vlan_set_ip_address"
    CLEAR_IP_ADDRESS = "vlan_clear_ip_address"
    SET_SECURITY_LEVEL = "vlan_set_security_level"
    CLEAR_SECURITY_LEVEL = "vlan_clear_security_level"
    UP = "vlan_up"
    DOWN = "vlan_down"


@dataclass(frozen=True, slots=True)
class VlanRciResult:
    operation: VlanRciOperation
    bridge_id: str
    ipv4_address: str | None
    ipv4_mask: str | None
    security_level: str | None
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation.value,
            "bridge_id": self.bridge_id,
            "ack_matched": self.ack_matched,
            "prompt": self.prompt,
            "status": [
                {
                    "status": entry.status,
                    "code": entry.code,
                    "ident": entry.ident,
                }
                for entry in self.status_entries
            ],
        }
        if self.ipv4_address is not None:
            payload["ipv4_address"] = self.ipv4_address
        if self.ipv4_mask is not None:
            payload["ipv4_mask"] = self.ipv4_mask
        if self.security_level is not None:
            payload["security_level"] = self.security_level
        return payload


def validate_vlan_bridge_id(bridge_id: str) -> str:
    normalized = bridge_id.strip()
    if normalized not in _ALLOWED_VLAN_BRIDGES:
        raise RciValidationError(code="not_allowlisted", field="bridge_id")
    return normalized


def validate_ipv4_gateway(gateway: str) -> str:
    candidate = gateway.strip()
    if not _IPV4_DOTTED_RE.fullmatch(candidate):
        raise RciValidationError(code="invalid_format", field="ipv4_gateway")
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ValueError as exc:
        raise RciValidationError(code="invalid_format", field="ipv4_gateway") from exc
    return str(addr)


def validate_ipv4_dotted_mask(mask: str) -> str:
    candidate = mask.strip()
    if not _IPV4_DOTTED_RE.fullmatch(candidate):
        raise RciValidationError(code="invalid_format", field="ipv4_mask")
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ValueError as exc:
        raise RciValidationError(code="invalid_format", field="ipv4_mask") from exc
    bits = int(addr)
    if bits == 0:
        raise RciValidationError(code="invalid_format", field="ipv4_mask")
    inverted = (~bits) & 0xFFFFFFFF
    if inverted & (inverted + 1):
        raise RciValidationError(code="invalid_format", field="ipv4_mask")
    return str(addr)


def validate_security_level(level: str) -> str:
    normalized = level.strip().lower()
    if normalized not in _ALLOWED_SECURITY_LEVELS:
        raise RciValidationError(code="not_allowlisted", field="security_level")
    return normalized


def command_for(
    operation: VlanRciOperation,
    bridge_id: str,
    *,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    security_level: str | None = None,
) -> str:
    bridge = validate_vlan_bridge_id(bridge_id)
    if operation is VlanRciOperation.CREATE_BRIDGE:
        return f"interface {bridge}"
    if operation is VlanRciOperation.REMOVE_BRIDGE:
        return f"no interface {bridge}"
    if operation is VlanRciOperation.SET_IP_ADDRESS:
        if ipv4_address is None or ipv4_mask is None:
            raise VlanRciError("ipv4_address and ipv4_mask are required for SET_IP_ADDRESS")
        addr = validate_ipv4_gateway(ipv4_address)
        mask = validate_ipv4_dotted_mask(ipv4_mask)
        return f"interface {bridge} ip address {addr} {mask}"
    if operation is VlanRciOperation.CLEAR_IP_ADDRESS:
        return f"interface {bridge} no ip address"
    if operation is VlanRciOperation.SET_SECURITY_LEVEL:
        if security_level is None:
            raise VlanRciError("security_level is required for SET_SECURITY_LEVEL")
        level = validate_security_level(security_level)
        return f"interface {bridge} security-level {level}"
    if operation is VlanRciOperation.CLEAR_SECURITY_LEVEL:
        return f"interface {bridge} no security-level"
    if operation is VlanRciOperation.UP:
        return f"interface {bridge} up"
    if operation is VlanRciOperation.DOWN:
        return f"interface {bridge} down"
    raise VlanRciError(f"operation not allowlisted: {operation}")


def sealed_request_for(
    operation: VlanRciOperation,
    bridge_id: str,
    *,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    security_level: str | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(
        command_for(
            operation,
            bridge_id,
            ipv4_address=ipv4_address,
            ipv4_mask=ipv4_mask,
            security_level=security_level,
        )
    )
    return SealedRciWriteRequest(body=body)


def verify_vlan_response(
    operation: VlanRciOperation,
    bridge_id: str,
    response: Any,
    *,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    security_level: str | None = None,
) -> VlanRciResult:
    bridge = validate_vlan_bridge_id(bridge_id)
    normalized_address: str | None = None
    normalized_mask: str | None = None
    normalized_level: str | None = None
    if operation is VlanRciOperation.SET_IP_ADDRESS:
        if ipv4_address is None or ipv4_mask is None:
            raise VlanRciError(
                "ipv4_address and ipv4_mask are required for SET_IP_ADDRESS verification"
            )
        normalized_address = validate_ipv4_gateway(ipv4_address)
        normalized_mask = validate_ipv4_dotted_mask(ipv4_mask)
    if operation is VlanRciOperation.SET_SECURITY_LEVEL:
        if security_level is None:
            raise VlanRciError("security_level is required for SET_SECURITY_LEVEL verification")
        normalized_level = validate_security_level(security_level)
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise VlanRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise VlanRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise VlanRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise VlanRciError("RCI parse returned an unexpected status kind")
    return VlanRciResult(
        operation=operation,
        bridge_id=bridge,
        ipv4_address=normalized_address,
        ipv4_mask=normalized_mask,
        security_level=normalized_level,
        ack_matched=True,
        prompt=prompt,
        status_entries=tuple(entries),
    )


def execute_vlan_rci(
    transport: RciSealedWriteTransport,
    operation: VlanRciOperation,
    bridge_id: str,
    *,
    ipv4_address: str | None = None,
    ipv4_mask: str | None = None,
    security_level: str | None = None,
) -> VlanRciResult:
    request = sealed_request_for(
        operation,
        bridge_id,
        ipv4_address=ipv4_address,
        ipv4_mask=ipv4_mask,
        security_level=security_level,
    )
    response = transport.execute_sealed_rci_write(request)
    return verify_vlan_response(
        operation,
        bridge_id,
        response,
        ipv4_address=ipv4_address,
        ipv4_mask=ipv4_mask,
        security_level=security_level,
    )


__all__ = [
    "VlanRciError",
    "VlanRciOperation",
    "VlanRciResult",
    "command_for",
    "execute_vlan_rci",
    "sealed_request_for",
    "validate_ipv4_dotted_mask",
    "validate_ipv4_gateway",
    "validate_security_level",
    "validate_vlan_bridge_id",
    "verify_vlan_response",
]
