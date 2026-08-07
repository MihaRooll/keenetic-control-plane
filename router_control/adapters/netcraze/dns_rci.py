"""Typed, sealed RCI DNS static host and upstream resolver operations."""

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
_MAX_FQDN_LEN = 253
_IPV4_DOTTED_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_FQDN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class DnsRciError(Exception):
    """RCI DNS operation failed or returned an unverifiable ack."""


class DnsRciOperation(StrEnum):
    SET_STATIC_HOST = "dns_set_static_host"
    CLEAR_STATIC_HOST = "dns_clear_static_host"
    SET_UPSTREAM = "dns_set_upstream"
    CLEAR_UPSTREAM = "dns_clear_upstream"


@dataclass(frozen=True, slots=True)
class DnsRciResult:
    operation: DnsRciOperation
    zone_id: str
    local_fqdn: str | None
    upstream_resolver: str | None
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
        if self.local_fqdn is not None:
            payload["local_fqdn"] = self.local_fqdn
        if self.upstream_resolver is not None:
            payload["upstream_resolver"] = self.upstream_resolver
        return payload


def validate_zone_id(zone_id: str) -> str:
    normalized = zone_id.strip()
    if not normalized or len(normalized) > _MAX_ZONE_ID_LEN:
        raise RciValidationError(code="not_allowlisted", field="zone_id")
    return normalized


def validate_local_fqdn(local_fqdn: str) -> str:
    normalized = local_fqdn.strip().lower().rstrip(".")
    if not normalized or len(normalized) > _MAX_FQDN_LEN or not _FQDN_RE.match(normalized):
        raise RciValidationError(code="invalid_fqdn", field="local_fqdn")
    return normalized


def validate_upstream_resolver(resolver: str) -> str:
    candidate = resolver.strip()
    if not _IPV4_DOTTED_RE.fullmatch(candidate):
        raise RciValidationError(code="invalid_format", field="upstream_resolver")
    try:
        addr = ipaddress.IPv4Address(candidate)
    except ValueError as exc:
        raise RciValidationError(code="invalid_format", field="upstream_resolver") from exc
    return str(addr)


def command_for(
    operation: DnsRciOperation,
    zone_id: str,
    *,
    local_fqdn: str | None = None,
    upstream_resolver: str | None = None,
) -> str:
    validate_zone_id(zone_id)
    if operation is DnsRciOperation.SET_STATIC_HOST:
        if local_fqdn is None:
            raise DnsRciError("local_fqdn is required for SET_STATIC_HOST")
        fqdn = validate_local_fqdn(local_fqdn)
        return f"ip host {fqdn}"
    if operation is DnsRciOperation.CLEAR_STATIC_HOST:
        if local_fqdn is None:
            raise DnsRciError("local_fqdn is required for CLEAR_STATIC_HOST")
        fqdn = validate_local_fqdn(local_fqdn)
        return f"no ip host {fqdn}"
    if operation is DnsRciOperation.SET_UPSTREAM:
        if upstream_resolver is None:
            raise DnsRciError("upstream_resolver is required for SET_UPSTREAM")
        resolver = validate_upstream_resolver(upstream_resolver)
        return f"ip name-server {resolver}"
    if operation is DnsRciOperation.CLEAR_UPSTREAM:
        if upstream_resolver is None:
            raise DnsRciError("upstream_resolver is required for CLEAR_UPSTREAM")
        resolver = validate_upstream_resolver(upstream_resolver)
        return f"no ip name-server {resolver}"
    raise DnsRciError(f"operation not allowlisted: {operation}")


def sealed_request_for(
    operation: DnsRciOperation,
    zone_id: str,
    *,
    local_fqdn: str | None = None,
    upstream_resolver: str | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(
        command_for(
            operation,
            zone_id,
            local_fqdn=local_fqdn,
            upstream_resolver=upstream_resolver,
        )
    )
    return SealedRciWriteRequest(body=body)


def verify_dns_response(
    operation: DnsRciOperation,
    zone_id: str,
    response: Any,
    *,
    local_fqdn: str | None = None,
    upstream_resolver: str | None = None,
) -> DnsRciResult:
    zone = validate_zone_id(zone_id)
    normalized_fqdn: str | None = None
    normalized_resolver: str | None = None
    if operation in {DnsRciOperation.SET_STATIC_HOST, DnsRciOperation.CLEAR_STATIC_HOST}:
        if local_fqdn is None:
            raise DnsRciError("local_fqdn is required for static host verification")
        normalized_fqdn = validate_local_fqdn(local_fqdn)
    if operation in {DnsRciOperation.SET_UPSTREAM, DnsRciOperation.CLEAR_UPSTREAM}:
        if upstream_resolver is None:
            raise DnsRciError("upstream_resolver is required for upstream verification")
        normalized_resolver = validate_upstream_resolver(upstream_resolver)
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise DnsRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise DnsRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise DnsRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise DnsRciError("RCI parse returned an unexpected status kind")
    return DnsRciResult(
        operation=operation,
        zone_id=zone,
        local_fqdn=normalized_fqdn,
        upstream_resolver=normalized_resolver,
        ack_matched=True,
        prompt=prompt,
        status_entries=tuple(entries),
    )


def execute_dns_rci(
    transport: RciSealedWriteTransport,
    operation: DnsRciOperation,
    zone_id: str,
    *,
    local_fqdn: str | None = None,
    upstream_resolver: str | None = None,
) -> DnsRciResult:
    request = sealed_request_for(
        operation,
        zone_id,
        local_fqdn=local_fqdn,
        upstream_resolver=upstream_resolver,
    )
    response = transport.execute_sealed_rci_write(request)
    return verify_dns_response(
        operation,
        zone_id,
        response,
        local_fqdn=local_fqdn,
        upstream_resolver=upstream_resolver,
    )


__all__ = [
    "DnsRciError",
    "DnsRciOperation",
    "DnsRciResult",
    "command_for",
    "execute_dns_rci",
    "sealed_request_for",
    "validate_local_fqdn",
    "validate_upstream_resolver",
    "validate_zone_id",
    "verify_dns_response",
]
