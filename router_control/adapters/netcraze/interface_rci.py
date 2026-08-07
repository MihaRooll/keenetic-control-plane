"""Typed, sealed RCI interface up/down operations."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    validate_interface_id,
)
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeStatusEntry,
    RciSealedWriteTransport,
    collect_rci_status_and_prompt,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest

_ALLOWED_PROMPTS = frozenset({"(config)"})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"


class InterfaceRciError(Exception):
    """RCI interface operation failed or returned an unverifiable ack."""


class InterfaceRciOperation(StrEnum):
    UP = "interface_up"
    DOWN = "interface_down"


@dataclass(frozen=True, slots=True)
class InterfaceRciResult:
    operation: InterfaceRciOperation
    interface_id: str
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation.value,
            "interface_id": self.interface_id,
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


def command_for(operation: InterfaceRciOperation, interface_id: str) -> str:
    iface = validate_interface_id(interface_id)
    if operation is InterfaceRciOperation.UP:
        return f"interface {iface} up"
    if operation is InterfaceRciOperation.DOWN:
        return f"interface {iface} down"
    raise InterfaceRciError(f"operation not allowlisted: {operation}")


def sealed_request_for(
    operation: InterfaceRciOperation,
    interface_id: str,
) -> SealedRciWriteRequest:
    body = build_sealed_parse_body(command_for(operation, interface_id))
    return SealedRciWriteRequest(body=body)


def verify_interface_response(
    operation: InterfaceRciOperation,
    interface_id: str,
    response: Any,
) -> InterfaceRciResult:
    iface = validate_interface_id(interface_id)
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise InterfaceRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise InterfaceRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise InterfaceRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise InterfaceRciError("RCI parse returned an unexpected status kind")
    return InterfaceRciResult(
        operation=operation,
        interface_id=iface,
        ack_matched=True,
        prompt=prompt,
        status_entries=tuple(entries),
    )


def execute_interface_rci(
    transport: RciSealedWriteTransport,
    operation: InterfaceRciOperation,
    interface_id: str,
) -> InterfaceRciResult:
    request = sealed_request_for(operation, interface_id)
    response = transport.execute_sealed_rci_write(request)
    return verify_interface_response(operation, interface_id, response)


def interface_up(transport: RciSealedWriteTransport, interface_id: str) -> InterfaceRciResult:
    return execute_interface_rci(transport, InterfaceRciOperation.UP, interface_id)


def interface_down(transport: RciSealedWriteTransport, interface_id: str) -> InterfaceRciResult:
    return execute_interface_rci(transport, InterfaceRciOperation.DOWN, interface_id)


__all__ = [
    "InterfaceRciError",
    "InterfaceRciOperation",
    "InterfaceRciResult",
    "command_for",
    "execute_interface_rci",
    "interface_down",
    "interface_up",
    "sealed_request_for",
    "verify_interface_response",
]
