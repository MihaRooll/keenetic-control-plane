"""Typed, sealed RCI system configuration save and reboot operations."""

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
from router_control.adapters.netcraze.transport import SealedRciWriteRequest

_ALLOWED_PROMPTS = frozenset({"(config)"})
_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"


class SystemRciError(Exception):
    """RCI system operation failed or returned an unverifiable ack."""


class SystemRciOperation(StrEnum):
    CONFIGURATION_SAVE = "configuration_save"
    REBOOT = "reboot"


_OPERATION_COMMANDS: dict[SystemRciOperation, str] = {
    SystemRciOperation.CONFIGURATION_SAVE: "system configuration save",
    SystemRciOperation.REBOOT: "system reboot",
}


@dataclass(frozen=True, slots=True)
class SystemRciResult:
    operation: SystemRciOperation
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation.value,
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


def command_for(operation: SystemRciOperation) -> str:
    try:
        return _OPERATION_COMMANDS[operation]
    except KeyError as exc:
        raise SystemRciError(f"operation not allowlisted: {operation}") from exc


def sealed_request_for(operation: SystemRciOperation) -> SealedRciWriteRequest:
    return SealedRciWriteRequest(body=build_sealed_parse_body(command_for(operation)))


def verify_system_response(operation: SystemRciOperation, response: Any) -> SystemRciResult:
    if operation not in _OPERATION_COMMANDS:
        raise SystemRciError(f"operation not allowlisted: {operation}")
    entries, prompt = collect_rci_status_and_prompt(response)
    if not entries:
        raise SystemRciError("no RCI parse status returned")
    if not prompt or prompt not in _ALLOWED_PROMPTS:
        raise SystemRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise SystemRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise SystemRciError("RCI parse returned an unexpected status kind")
    return SystemRciResult(
        operation=operation,
        ack_matched=True,
        prompt=prompt,
        status_entries=tuple(entries),
    )


def execute_system_rci(
    transport: RciSealedWriteTransport,
    operation: SystemRciOperation,
) -> SystemRciResult:
    request = sealed_request_for(operation)
    response = transport.execute_sealed_rci_write(request)
    return verify_system_response(operation, response)


def configuration_save(transport: RciSealedWriteTransport) -> SystemRciResult:
    return execute_system_rci(transport, SystemRciOperation.CONFIGURATION_SAVE)


def system_reboot(transport: RciSealedWriteTransport) -> SystemRciResult:
    return execute_system_rci(transport, SystemRciOperation.REBOOT)


__all__ = [
    "SystemRciError",
    "SystemRciOperation",
    "SystemRciResult",
    "command_for",
    "configuration_save",
    "execute_system_rci",
    "sealed_request_for",
    "system_reboot",
    "verify_system_response",
]
