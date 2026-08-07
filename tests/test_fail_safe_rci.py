"""Offline tests for the typed sealed RCI fail-safe layer (ack parsing, sealed commands)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.adapters.netcraze.fail_safe_rci import (
    FAIL_SAFE_ACK_IDENT,
    FailSafeRciError,
    FailSafeRciOperation,
    FailSafeStatusEntry,
    arm_fail_safe_timer_reboot_60,
    command_for,
    disarm_fail_safe_timer,
    verify_fail_safe_response,
)

ARM_COMMAND = "system configuration fail-safe timer reboot 60"
DISARM_COMMAND = "no system configuration fail-safe timer"


class FakeSealedTransport:
    def __init__(self, response: Any) -> None:
        self._response = response
        self.commands: list[str] = []

    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        self.commands.append(str(body[0]["parse"]))
        return self._response


def _ok(message: str, *, ident: str = FAIL_SAFE_ACK_IDENT, code: str = "8979152") -> dict[str, Any]:
    return {"status": "message", "code": code, "ident": ident, "message": message}


def _envelope(
    status_entries: list[dict[str, Any]], prompt: str = "(config)"
) -> list[dict[str, Any]]:
    return [{"parse": {"prompt": prompt, "status": status_entries}}]


def test_arm_success_dispatches_fixed_command_and_matches_ack() -> None:
    transport = FakeSealedTransport(_envelope([_ok("bumped up to 60 seconds.")]))
    result = arm_fail_safe_timer_reboot_60(transport)
    assert transport.commands == [ARM_COMMAND]
    assert result.ack_matched is True
    assert result.timer_seconds == 60
    assert result.operation is FailSafeRciOperation.ARM_TIMER_REBOOT_60
    assert result.prompt == "(config)"


def test_disarm_success_dispatches_fixed_command() -> None:
    transport = FakeSealedTransport(
        _envelope([_ok("turned off the fail-safe mode.", code="8979332")])
    )
    result = disarm_fail_safe_timer(transport)
    assert transport.commands == [DISARM_COMMAND]
    assert result.ack_matched is True
    assert result.timer_seconds is None


def test_object_form_response_is_accepted() -> None:
    response = {"parse": {"prompt": "(config)", "status": [_ok("bumped up to 60 seconds.")]}}
    result = verify_fail_safe_response(FailSafeRciOperation.ARM_TIMER_REBOOT_60, response)
    assert result.ack_matched is True


def test_error_status_raises() -> None:
    entry = {"status": "error", "code": "1", "ident": FAIL_SAFE_ACK_IDENT, "message": "no"}
    response = _envelope([entry])
    with pytest.raises(FailSafeRciError):
        verify_fail_safe_response(FailSafeRciOperation.ARM_TIMER_REBOOT_60, response)


def test_missing_status_raises() -> None:
    with pytest.raises(FailSafeRciError):
        verify_fail_safe_response(
            FailSafeRciOperation.DISARM_TIMER,
            [{"parse": {"prompt": "(config)"}}],
        )


def test_wrong_ident_raises() -> None:
    response = _envelope([_ok("something", ident="Core::Other::Thing")])
    with pytest.raises(FailSafeRciError):
        verify_fail_safe_response(FailSafeRciOperation.ARM_TIMER_REBOOT_60, response)


def test_unexpected_status_kind_raises() -> None:
    entry = {"status": "weird", "code": "1", "ident": FAIL_SAFE_ACK_IDENT, "message": "x"}
    response = _envelope([entry])
    with pytest.raises(FailSafeRciError):
        verify_fail_safe_response(FailSafeRciOperation.DISARM_TIMER, response)


def test_command_for_is_sealed() -> None:
    assert command_for(FailSafeRciOperation.ARM_TIMER_REBOOT_60) == ARM_COMMAND
    assert command_for(FailSafeRciOperation.DISARM_TIMER) == DISARM_COMMAND


def test_verify_fail_safe_accepts_prompt_with_trailing_gt_and_ansi() -> None:
    response = _envelope([_ok("bumped up to 60 seconds.")], prompt="(config)>\x1b[K")
    result = verify_fail_safe_response(FailSafeRciOperation.ARM_TIMER_REBOOT_60, response)
    assert result.ack_matched is True
    assert result.prompt == "(config)"


def test_verify_fail_safe_rejects_unrecognized_prompt_context() -> None:
    response = _envelope([_ok("bumped up to 60 seconds.")], prompt="(exec)")
    with pytest.raises(FailSafeRciError, match="prompt missing or not allowlisted"):
        verify_fail_safe_response(FailSafeRciOperation.ARM_TIMER_REBOOT_60, response)


def test_fail_safe_status_entry_repr_omits_message() -> None:
    entry = FailSafeStatusEntry(
        status="message",
        code="1",
        ident=FAIL_SAFE_ACK_IDENT,
        message="device secret echo must-not-appear-in-repr",
    )
    rendered = repr(entry)
    assert "must-not-appear-in-repr" not in rendered
    assert "device secret echo" not in rendered
