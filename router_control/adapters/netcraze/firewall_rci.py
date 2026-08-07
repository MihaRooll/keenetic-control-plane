"""Typed, sealed RCI firewall access-list rule add/remove operations."""

from __future__ import annotations

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
from router_control.domain.network_intents import (
    FirewallAction,
    FirewallDestinationFamily,
)

_ALLOWED_PROMPTS = frozenset({"(config)"})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"
_MAX_ZONE_ID_LEN = 64
_ALLOWED_ACTIONS = frozenset({a.value for a in FirewallAction})
_ALLOWED_DESTINATION_FAMILIES = frozenset({f.value for f in FirewallDestinationFamily})


class FirewallRciError(Exception):
    """RCI firewall operation failed or returned an unverifiable ack."""


class FirewallRciOperation(StrEnum):
    ADD_RULE = "firewall_add_rule"
    REMOVE_RULE = "firewall_remove_rule"


@dataclass(frozen=True, slots=True)
class FirewallRciResult:
    operation: FirewallRciOperation
    zone_id: str
    action: str | None
    destination_family: str | None
    ordinal: int | None
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
        if self.action is not None:
            payload["action"] = self.action
        if self.destination_family is not None:
            payload["destination_family"] = self.destination_family
        if self.ordinal is not None:
            payload["ordinal"] = self.ordinal
        return payload


def validate_zone_id(zone_id: str) -> str:
    normalized = zone_id.strip()
    if not normalized or len(normalized) > _MAX_ZONE_ID_LEN:
        raise RciValidationError(code="not_allowlisted", field="zone_id")
    return normalized


def validate_action(action: str) -> str:
    candidate = action.strip()
    if candidate not in _ALLOWED_ACTIONS:
        raise RciValidationError(code="not_allowlisted", field="action")
    return candidate


def validate_destination_family(destination_family: str) -> str:
    candidate = destination_family.strip()
    if candidate not in _ALLOWED_DESTINATION_FAMILIES:
        raise RciValidationError(code="not_allowlisted", field="destination_family")
    return candidate


def validate_ordinal(ordinal: int) -> int:
    if isinstance(ordinal, bool) or not isinstance(ordinal, int):
        raise RciValidationError(code="invalid_format", field="ordinal")
    if ordinal < 0:
        raise RciValidationError(code="out_of_range", field="ordinal")
    return ordinal


def command_for(
    operation: FirewallRciOperation,
    zone_id: str,
    *,
    action: str | None = None,
    destination_family: str | None = None,
    ordinal: int | None = None,
) -> str:
    zone = validate_zone_id(zone_id)
    if operation is FirewallRciOperation.ADD_RULE:
        if action is None or destination_family is None or ordinal is None:
            raise FirewallRciError(
                "action, destination_family, and ordinal are required for ADD_RULE"
            )
        act = validate_action(action)
        family = validate_destination_family(destination_family)
        ord_val = validate_ordinal(ordinal)
        return f"ip access-list {zone} {ord_val} {act} {family}"
    if operation is FirewallRciOperation.REMOVE_RULE:
        if ordinal is None:
            raise FirewallRciError("ordinal is required for REMOVE_RULE")
        ord_val = validate_ordinal(ordinal)
        return f"no ip access-list {zone} {ord_val}"
    raise FirewallRciError(f"operation not allowlisted: {operation}")


def sealed_request_for(
    operation: FirewallRciOperation,
    zone_id: str,
    *,
    action: str | None = None,
    destination_family: str | None = None,
    ordinal: int | None = None,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(
        command_for(
            operation,
            zone_id,
            action=action,
            destination_family=destination_family,
            ordinal=ordinal,
        )
    )
    return SealedRciWriteRequest(body=body)


def verify_firewall_response(
    operation: FirewallRciOperation,
    zone_id: str,
    response: Any,
    *,
    action: str | None = None,
    destination_family: str | None = None,
    ordinal: int | None = None,
) -> FirewallRciResult:
    zone = validate_zone_id(zone_id)
    normalized_action: str | None = None
    normalized_family: str | None = None
    normalized_ordinal: int | None = None
    if operation is FirewallRciOperation.ADD_RULE:
        if action is None or destination_family is None or ordinal is None:
            raise FirewallRciError(
                "action, destination_family, and ordinal are required for ADD_RULE verification"
            )
        normalized_action = validate_action(action)
        normalized_family = validate_destination_family(destination_family)
        normalized_ordinal = validate_ordinal(ordinal)
    if operation is FirewallRciOperation.REMOVE_RULE:
        if ordinal is None:
            raise FirewallRciError("ordinal is required for REMOVE_RULE verification")
        normalized_ordinal = validate_ordinal(ordinal)
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise FirewallRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise FirewallRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise FirewallRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise FirewallRciError("RCI parse returned an unexpected status kind")
    return FirewallRciResult(
        operation=operation,
        zone_id=zone,
        action=normalized_action,
        destination_family=normalized_family,
        ordinal=normalized_ordinal,
        ack_matched=True,
        prompt=prompt,
        status_entries=tuple(entries),
    )


def execute_firewall_rci(
    transport: RciSealedWriteTransport,
    operation: FirewallRciOperation,
    zone_id: str,
    *,
    action: str | None = None,
    destination_family: str | None = None,
    ordinal: int | None = None,
) -> FirewallRciResult:
    request = sealed_request_for(
        operation,
        zone_id,
        action=action,
        destination_family=destination_family,
        ordinal=ordinal,
    )
    response = transport.execute_sealed_rci_write(request)
    return verify_firewall_response(
        operation,
        zone_id,
        response,
        action=action,
        destination_family=destination_family,
        ordinal=ordinal,
    )


__all__ = [
    "FirewallRciError",
    "FirewallRciOperation",
    "FirewallRciResult",
    "command_for",
    "execute_firewall_rci",
    "sealed_request_for",
    "validate_action",
    "validate_destination_family",
    "validate_ordinal",
    "validate_zone_id",
    "verify_firewall_response",
]
