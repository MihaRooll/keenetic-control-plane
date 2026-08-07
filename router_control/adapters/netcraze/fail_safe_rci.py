"""Typed, sealed RCI fail-safe operations over the certified pinned-SSH RCI transport.

Forward path that supersedes the raw SSH exec dispatch (exec_fail_safe_timer_reboot_60),
which is unsupported by the NDMS SSH server. Only two allowlisted operations are exposed
here (arm the 60-second reboot timer, disarm it) via pre-serialized, write-allowlisted
bodies — no generic CLI surface. Success is verified structurally from the RCI
`parse.status[]` envelope (validated live 2026-07-23 on the certified NC-1812 tuple).

This module also hosts the shared RCI ack primitives (FailSafeStatusEntry,
collect_rci_status_and_prompt, RciSealedWriteTransport) reused by interface_rci and
system_rci.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.rci_prompt import (
    RCI_PROMPT_CONFIG,
    is_allowlisted_rci_prompt,
    normalize_rci_prompt,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest

FAIL_SAFE_TIMER_SECONDS = 60

# Subsystem ident the router returns for fail-safe timer / config-storage acks.
# Exact match is intentional: this is a structured RCI ident, not free-form text.
# Localization or ident renames fail closed until evidence updates this constant.
FAIL_SAFE_ACK_IDENT = "Core::System::Mtd::ConfigStorage"

_SUCCESS_STATUS_KINDS = frozenset({"message", "warning"})
_ERROR_STATUS_KIND = "error"
_ALLOWED_PROMPTS = frozenset({RCI_PROMPT_CONFIG})


class FailSafeRciError(Exception):
    """RCI fail-safe operation failed or returned an unverifiable ack."""


class FailSafeRciOperation(StrEnum):
    ARM_TIMER_REBOOT_60 = "arm_timer_reboot_60"
    DISARM_TIMER = "disarm_timer"


# Fixed, sealed CLI strings — the only commands this layer will ever dispatch.
_OPERATION_COMMANDS: dict[FailSafeRciOperation, str] = {
    FailSafeRciOperation.ARM_TIMER_REBOOT_60: (
        f"system configuration fail-safe timer reboot {FAIL_SAFE_TIMER_SECONDS}"
    ),
    FailSafeRciOperation.DISARM_TIMER: "no system configuration fail-safe timer",
}


class RciSealedWriteTransport(Protocol):
    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any: ...


@dataclass(frozen=True, slots=True)
class FailSafeStatusEntry:
    status: str
    code: str
    ident: str
    message: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class FailSafeRciResult:
    operation: FailSafeRciOperation
    timer_seconds: int | None
    ack_matched: bool
    prompt: str
    status_entries: tuple[FailSafeStatusEntry, ...]

    def sanitized_dict(self) -> dict[str, object]:
        return {
            "operation": self.operation.value,
            "timer_seconds": self.timer_seconds,
            "ack_matched": self.ack_matched,
            "prompt": self.prompt,
            "status": [
                {"status": entry.status, "code": entry.code, "ident": entry.ident}
                for entry in self.status_entries
            ],
        }


def collect_rci_status_and_prompt(response: Any) -> tuple[list[FailSafeStatusEntry], str]:
    """Walk an RCI parse response, collecting all status entries and the first prompt."""
    entries: list[FailSafeStatusEntry] = []
    prompt = ""

    def _walk(current: Any) -> None:
        nonlocal prompt
        if isinstance(current, dict):
            raw_prompt = current.get("prompt")
            if isinstance(raw_prompt, str) and not prompt:
                prompt = raw_prompt
            raw_status = current.get("status")
            if isinstance(raw_status, list):
                for entry in raw_status:
                    if isinstance(entry, dict):
                        entries.append(
                            FailSafeStatusEntry(
                                status=str(entry.get("status", "")),
                                code=str(entry.get("code", "")),
                                ident=str(entry.get("ident", "")),
                                message=str(entry.get("message", "")),
                            )
                        )
            for value in current.values():
                _walk(value)
        elif isinstance(current, list):
            for item in current:
                _walk(item)

    _walk(response)
    return entries, prompt


def command_for(operation: FailSafeRciOperation) -> str:
    """Return the fixed sealed CLI string for an allowlisted operation."""
    try:
        return _OPERATION_COMMANDS[operation]
    except KeyError as exc:
        raise FailSafeRciError(f"operation not allowlisted: {operation}") from exc


def sealed_request_for(operation: FailSafeRciOperation) -> SealedRciWriteRequest:
    return SealedRciWriteRequest(body=build_sealed_parse_body(command_for(operation)))


def verify_fail_safe_response(
    operation: FailSafeRciOperation,
    response: Any,
) -> FailSafeRciResult:
    """Validate a raw RCI parse response for a fail-safe operation.

    Message wording varies (e.g. 'Enabled a 60-second ...' vs 'bumped up to 60
    seconds.'), so the ack is bound to the subsystem ident and non-error status,
    not to an exact message string.
    """
    if operation not in _OPERATION_COMMANDS:
        raise FailSafeRciError(f"operation not allowlisted: {operation}")
    entries, prompt = collect_rci_status_and_prompt(response)
    normalized_prompt = normalize_rci_prompt(prompt, collapse_config_if=True) if prompt else ""
    if not entries:
        raise FailSafeRciError("no RCI parse status returned")
    if not is_allowlisted_rci_prompt(
        prompt,
        allowed=_ALLOWED_PROMPTS,
        collapse_config_if=True,
    ):
        raise FailSafeRciError("RCI parse prompt missing or not allowlisted")
    if any(entry.status == _ERROR_STATUS_KIND for entry in entries):
        raise FailSafeRciError("RCI parse reported an error status")
    if not all(entry.status in _SUCCESS_STATUS_KINDS for entry in entries):
        raise FailSafeRciError("RCI parse returned an unexpected status kind")
    if not any(entry.ident == FAIL_SAFE_ACK_IDENT for entry in entries):
        raise FailSafeRciError("RCI parse ack ident does not match fail-safe subsystem")
    timer = (
        FAIL_SAFE_TIMER_SECONDS
        if operation is FailSafeRciOperation.ARM_TIMER_REBOOT_60
        else None
    )
    return FailSafeRciResult(
        operation=operation,
        timer_seconds=timer,
        ack_matched=True,
        prompt=normalized_prompt,
        status_entries=tuple(entries),
    )


def execute_fail_safe_rci(
    transport: RciSealedWriteTransport,
    operation: FailSafeRciOperation,
) -> FailSafeRciResult:
    """Dispatch a single allowlisted fail-safe operation and verify the ack."""
    request = sealed_request_for(operation)
    response = transport.execute_sealed_rci_write(request)
    return verify_fail_safe_response(operation, response)


def arm_fail_safe_timer_reboot_60(transport: RciSealedWriteTransport) -> FailSafeRciResult:
    return execute_fail_safe_rci(transport, FailSafeRciOperation.ARM_TIMER_REBOOT_60)


def disarm_fail_safe_timer(transport: RciSealedWriteTransport) -> FailSafeRciResult:
    return execute_fail_safe_rci(transport, FailSafeRciOperation.DISARM_TIMER)


__all__ = [
    "FAIL_SAFE_ACK_IDENT",
    "FAIL_SAFE_TIMER_SECONDS",
    "FailSafeRciError",
    "FailSafeRciOperation",
    "FailSafeRciResult",
    "FailSafeStatusEntry",
    "RciSealedWriteTransport",
    "arm_fail_safe_timer_reboot_60",
    "collect_rci_status_and_prompt",
    "command_for",
    "disarm_fail_safe_timer",
    "execute_fail_safe_rci",
    "sealed_request_for",
    "verify_fail_safe_response",
]
