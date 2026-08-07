"""Typed, sealed RCI DHCP pool/lease/host bind operations."""

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
_MAX_ZONE_ID_LEN = 64
_MIN_LEASE_SECONDS = 60
_MAX_LEASE_SECONDS = 604800
_IPV4_DOTTED_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_MAC_ADDRESS_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class DhcpRciError(Exception):
    """RCI DHCP operation failed or returned an unverifiable ack."""


class DhcpRciOperation(StrEnum):
    SET_POOL = "dhcp_set_pool"
    CLEAR_POOL = "dhcp_clear_pool"
    SET_LEASE = "dhcp_set_lease"
    BIND_HOST = "dhcp_bind_host"
    UNBIND_HOST = "dhcp_unbind_host"


@dataclass(frozen=True, slots=True)
class DhcpRciResult:
    operation: DhcpRciOperation
    zone_id: str
    pool_start: str | None
    pool_end: str | None
    lease_seconds: int | None
    mac_address: str | None
    ipv4_address: str | None
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "operation": self.operation.value,
            "zone_id": self.zone_id,
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
        if self.pool_start is not None:
            payload["pool_start"] = self.pool_start
        if self.pool_end is not None:
            payload["pool_end"] = self.pool_end
        if self.lease_seconds is not None:
            payload["lease_seconds"] = self.lease_seconds
        if self.mac_address is not None:
            payload["mac_address"] = self.mac_address
        if self.ipv4_address is not None:
            payload["ipv4_address"] = self.ipv4_address
        return payload


def validate_zone_id(zone_id: str) -> str:
    normalized = zone_id.strip()
    if not normalized or len(normalized) > _MAX_ZONE_ID_LEN:
        raise RciValidationError(code="not_allowlisted", field="zone_id")
    return normalized


def validate_ipv4_address(address: str) -> str:
    candidate = address.strip()
    if not _IPV4_DOTTED_RE.fullmatch(candidate):
        raise RciValidationError(code="invalid_format", field="ipv4_address")
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ValueError as exc:
        raise RciValidationError(code="invalid_format", field="ipv4_address") from exc
    return str(addr)


def validate_lease_seconds(lease_seconds: int) -> int:
    if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, int):
        raise RciValidationError(code="invalid_format", field="lease_seconds")
    if lease_seconds < _MIN_LEASE_SECONDS or lease_seconds > _MAX_LEASE_SECONDS:
        raise RciValidationError(code="out_of_range", field="lease_seconds")
    return lease_seconds


def validate_mac_address(mac_address: str) -> str:
    candidate = mac_address.strip().lower()
    if not _MAC_ADDRESS_RE.fullmatch(candidate):
        raise RciValidationError(code="invalid_format", field="mac_address")
    return candidate


def command_for(
    operation: DhcpRciOperation,
    zone_id: str,
    *,
    pool_start: str | None = None,
    pool_end: str | None = None,
    lease_seconds: int | None = None,
    mac_address: str | None = None,
    ipv4_address: str | None = None,
) -> str:
    zone = validate_zone_id(zone_id)
    if operation is DhcpRciOperation.SET_POOL:
        if pool_start is None or pool_end is None:
            raise DhcpRciError("pool_start and pool_end are required for SET_POOL")
        start = validate_ipv4_address(pool_start)
        end = validate_ipv4_address(pool_end)
        return f"ip dhcp pool {zone} {start} {end}"
    if operation is DhcpRciOperation.CLEAR_POOL:
        return f"no ip dhcp pool {zone}"
    if operation is DhcpRciOperation.SET_LEASE:
        if lease_seconds is None:
            raise DhcpRciError("lease_seconds is required for SET_LEASE")
        lease = validate_lease_seconds(lease_seconds)
        return f"ip dhcp pool {zone} lease {lease}"
    if operation is DhcpRciOperation.BIND_HOST:
        if mac_address is None or ipv4_address is None:
            raise DhcpRciError("mac_address and ipv4_address are required for BIND_HOST")
        mac = validate_mac_address(mac_address)
        addr = validate_ipv4_address(ipv4_address)
        return f"ip dhcp host {mac} {addr}"
    if operation is DhcpRciOperation.UNBIND_HOST:
        if mac_address is None:
            raise DhcpRciError("mac_address is required for UNBIND_HOST")
        mac = validate_mac_address(mac_address)
        return f"no ip dhcp host {mac}"
    raise DhcpRciError(f"operation not allowlisted: {operation}")


def sealed_request_for(
    operation: DhcpRciOperation,
    zone_id: str,
    *,
    pool_start: str | None = None,
    pool_end: str | None = None,
    lease_seconds: int | None = None,
    mac_address: str | None = None,
    ipv4_address: str | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(
        command_for(
            operation,
            zone_id,
            pool_start=pool_start,
            pool_end=pool_end,
            lease_seconds=lease_seconds,
            mac_address=mac_address,
            ipv4_address=ipv4_address,
        )
    )
    return SealedRciWriteRequest(body=body)


def verify_dhcp_response(
    operation: DhcpRciOperation,
    zone_id: str,
    response: Any,
    *,
    pool_start: str | None = None,
    pool_end: str | None = None,
    lease_seconds: int | None = None,
    mac_address: str | None = None,
    ipv4_address: str | None = None,
) -> DhcpRciResult:
    zone = validate_zone_id(zone_id)
    normalized_start: str | None = None
    normalized_end: str | None = None
    normalized_lease: int | None = None
    normalized_mac: str | None = None
    normalized_addr: str | None = None
    if operation is DhcpRciOperation.SET_POOL:
        if pool_start is None or pool_end is None:
            raise DhcpRciError("pool_start and pool_end are required for SET_POOL verification")
        normalized_start = validate_ipv4_address(pool_start)
        normalized_end = validate_ipv4_address(pool_end)
    if operation is DhcpRciOperation.SET_LEASE:
        if lease_seconds is None:
            raise DhcpRciError("lease_seconds is required for SET_LEASE verification")
        normalized_lease = validate_lease_seconds(lease_seconds)
    if operation in {DhcpRciOperation.BIND_HOST, DhcpRciOperation.UNBIND_HOST}:
        if mac_address is None:
            raise DhcpRciError("mac_address is required for host bind/unbind verification")
        normalized_mac = validate_mac_address(mac_address)
    if operation is DhcpRciOperation.BIND_HOST:
        if ipv4_address is None:
            raise DhcpRciError("ipv4_address is required for BIND_HOST verification")
        normalized_addr = validate_ipv4_address(ipv4_address)
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise DhcpRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise DhcpRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise DhcpRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise DhcpRciError("RCI parse returned an unexpected status kind")
    return DhcpRciResult(
        operation=operation,
        zone_id=zone,
        pool_start=normalized_start,
        pool_end=normalized_end,
        lease_seconds=normalized_lease,
        mac_address=normalized_mac,
        ipv4_address=normalized_addr,
        ack_matched=True,
        prompt=prompt,
        status_entries=tuple(entries),
    )


def execute_dhcp_rci(
    transport: RciSealedWriteTransport,
    operation: DhcpRciOperation,
    zone_id: str,
    *,
    pool_start: str | None = None,
    pool_end: str | None = None,
    lease_seconds: int | None = None,
    mac_address: str | None = None,
    ipv4_address: str | None = None,
) -> DhcpRciResult:
    request = sealed_request_for(
        operation,
        zone_id,
        pool_start=pool_start,
        pool_end=pool_end,
        lease_seconds=lease_seconds,
        mac_address=mac_address,
        ipv4_address=ipv4_address,
    )
    response = transport.execute_sealed_rci_write(request)
    return verify_dhcp_response(
        operation,
        zone_id,
        response,
        pool_start=pool_start,
        pool_end=pool_end,
        lease_seconds=lease_seconds,
        mac_address=mac_address,
        ipv4_address=ipv4_address,
    )


__all__ = [
    "DhcpRciError",
    "DhcpRciOperation",
    "DhcpRciResult",
    "command_for",
    "execute_dhcp_rci",
    "sealed_request_for",
    "validate_ipv4_address",
    "validate_lease_seconds",
    "validate_mac_address",
    "validate_zone_id",
    "verify_dhcp_response",
]
