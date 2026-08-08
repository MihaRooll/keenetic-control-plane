"""Offline tests for Wi-Fi apply reliability: rollback, taxonomy, idempotency."""

from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.adapters.netcraze.wifi_rci import (
    WifiApRciErrorCategory,
    WifiApRciOperation,
    classify_wifi_ap_rci_failure,
    command_redacted_for,
)
from router_control.application.wifi_apply_planner import compensate_ops_for_succeeded_apply
from router_control.application.wifi_apply_service import apply_wifi_intent

from tests.test_wifi_apply_service import (
    _OFFLINE_PSK_PLACEHOLDER,
    _TEST_AP,
    FakeWifiApplyTransport,
    _on_air_verified_readback,
    _applied_readback,
    _wpa2_intent,
)

_AP = _TEST_AP


def _wpa2_apply_descriptors(ap_id: str = _AP):
    from router_control.application.wifi_apply_planner import compile_wifi_intent_to_ops

    plan = compile_wifi_intent_to_ops(_wpa2_intent(), ap_id)
    return plan.apply_ops


def test_compensate_ops_reverse_order_and_mapping() -> None:
    apply_ops = _wpa2_apply_descriptors()
    succeeded = (
        WifiApRciOperation.SET_SSID.value,
        WifiApRciOperation.SET_WPA_PSK.value,
        WifiApRciOperation.ENCRYPTION_ENABLE.value,
    )
    compensate = compensate_ops_for_succeeded_apply(apply_ops, succeeded)
    assert [op.operation for op in compensate] == [
        WifiApRciOperation.ENCRYPTION_DISABLE.value,
        WifiApRciOperation.CLEAR_WPA_PSK.value,
        WifiApRciOperation.CLEAR_SSID.value,
    ]


def test_compensate_zero_ops_is_empty() -> None:
    apply_ops = _wpa2_apply_descriptors()
    assert compensate_ops_for_succeeded_apply(apply_ops, ()) == ()


@pytest.mark.parametrize(
    ("ident", "message", "expected"),
    [
        ("Auth::Denied", "permission denied", WifiApRciErrorCategory.AUTH_OR_PERMISSION),
        ("Core", "interface not found", WifiApRciErrorCategory.RESOURCE_NOT_FOUND),
        ("Parse", "unknown command", WifiApRciErrorCategory.UNSUPPORTED_GRAMMAR),
        ("Parse", "unknown command authentication", WifiApRciErrorCategory.UNSUPPORTED_GRAMMAR),
        ("Core", "generic failure", WifiApRciErrorCategory.REJECTED_BY_ROUTER),
    ],
)
def test_taxonomy_from_status_entries(
    ident: str,
    message: str,
    expected: WifiApRciErrorCategory,
) -> None:
    from router_control.adapters.netcraze.fail_safe_rci import FailSafeStatusEntry

    entry = FailSafeStatusEntry(status="error", code="1", ident=ident, message=message)
    details = classify_wifi_ap_rci_failure(
        operation=WifiApRciOperation.ENCRYPTION_ENABLE,
        ap_id=_AP,
        status_entries=(entry,),
        prompt="(config)",
    )
    assert details.category == expected


def test_taxonomy_unknown_without_evidence() -> None:
    details = classify_wifi_ap_rci_failure(
        operation=WifiApRciOperation.UP,
        ap_id=_AP,
    )
    assert details.category == WifiApRciErrorCategory.UNKNOWN


def test_command_redacted_never_includes_psk() -> None:
    redacted = command_redacted_for(WifiApRciOperation.SET_WPA_PSK, _AP)
    assert "<redacted>" in redacted
    assert _OFFLINE_PSK_PLACEHOLDER not in redacted


def test_partial_dispatch_failure_triggers_rollback_and_rolled_back() -> None:
    transport = FakeWifiApplyTransport(
        fail_on_command=f"interface {_AP} encryption enable",
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "rolled_back"
    assert result.rollback is not None
    assert result.rollback.attempted is True
    assert result.rollback.outcome == "succeeded"
    assert WifiApRciOperation.CLEAR_WPA_PSK.value in result.rollback.ops
    assert WifiApRciOperation.CLEAR_SSID.value in result.rollback.ops
    assert result.errors == ("service.op_dispatch_failed",)
    serialized = json.dumps(result.to_dict())
    assert _OFFLINE_PSK_PLACEHOLDER not in serialized


def test_verify_mismatch_triggers_rollback() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback(ssid="Wrong-SSID")])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "rolled_back"
    assert result.rollback is not None
    assert result.rollback.outcome == "succeeded"
    assert result.verification is not None
    assert result.verification.ssid_ok is False


def test_compensate_opt_out_keeps_failed() -> None:
    transport = FakeWifiApplyTransport(
        fail_on_command=f"interface {_AP} encryption enable",
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=False,
    )
    assert result.overall == "failed"
    assert result.rollback is not None
    assert result.rollback.attempted is False
    assert result.rollback.outcome == "not_attempted"


def test_first_op_failure_zero_succeeded_rollback_noop() -> None:
    transport = FakeWifiApplyTransport(
        fail_on_command=f"interface {_AP} ssid Staff-Private",
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "failed"
    assert result.rollback is not None
    assert result.rollback.outcome == "noop"
    assert result.rollback.ops == ()


def test_dispatch_failure_includes_taxonomy_on_step() -> None:
    transport = FakeWifiApplyTransport(
        fail_on_command=f"interface {_AP} encryption enable",
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=False,
    )
    failed_step = next(step for step in result.steps if not step.ok)
    assert failed_step.error_category == WifiApRciErrorCategory.REJECTED_BY_ROUTER.value
    assert failed_step.command_redacted is not None
    assert _OFFLINE_PSK_PLACEHOLDER not in (failed_step.command_redacted or "")


def test_idempotent_skips_already_satisfied_ops() -> None:
    transport = FakeWifiApplyTransport(
        show_interface_readback_sequence=[_on_air_verified_readback(), _on_air_verified_readback()],
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        idempotent=True,
    )
    assert result.overall == "applied"
    skipped_names = {item.op for item in result.skipped_ops}
    assert WifiApRciOperation.SET_SSID.value in skipped_names
    assert WifiApRciOperation.ENCRYPTION_ENABLE.value in skipped_names
    assert WifiApRciOperation.UP.value in skipped_names
    assert WifiApRciOperation.SET_WPA_PSK.value not in skipped_names
    assert any("authentication wpa-psk" in cmd for cmd in transport.write_commands)


def test_idempotent_unreadable_pre_read_full_sequence() -> None:
    class FirstParseFailTransport(FakeWifiApplyTransport):
        def execute_rci_parse(self, cli_command: str) -> Any:
            self.parse_commands.append(cli_command)
            if len(self.parse_commands) == 1:
                raise RuntimeError("pre-read failed")
            if self.readback_sequence:
                return self.readback_sequence.pop(0)
            return _on_air_verified_readback()

    transport = FirstParseFailTransport(readback_sequence=[_on_air_verified_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        idempotent=True,
    )
    assert result.overall == "applied"
    assert result.skipped_ops == ()
    assert "idempotent_fallback_full_sequence" in result.logs
    assert len(result.steps) == 5


def test_idempotent_empty_pre_read_full_sequence() -> None:
    transport = FakeWifiApplyTransport(
        show_interface_readback_sequence=[{}, _on_air_verified_readback()],
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        idempotent=True,
    )
    assert result.skipped_ops == ()
    assert "idempotent_fallback_full_sequence" in result.logs
    assert len(result.steps) == 5


def test_readback_failure_after_dispatch_triggers_rollback() -> None:
    transport = FakeWifiApplyTransport(readback_raises=RuntimeError("readback failed"))
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "rolled_back"
    assert result.errors == ("service.readback_failed",)
    assert result.rollback is not None
    assert result.rollback.outcome == "succeeded"


def test_router_message_psk_echo_scrubbed_from_result() -> None:
    psk_cmd = f"interface {_AP} authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}"
    leak_message = f"rejected: authentication wpa-psk {_OFFLINE_PSK_PLACEHOLDER}"

    class PskEchoFailTransport(FakeWifiApplyTransport):
        def execute_sealed_rci_write(self, request: Any) -> Any:
            body = json.loads(request.body.decode("utf-8"))
            command = str(body[0]["parse"])
            self.write_commands.append(command)
            if command == psk_cmd:
                return [
                    {
                        "parse": {
                            "prompt": "(config)",
                            "status": [
                                {
                                    "status": "error",
                                    "code": "1",
                                    "ident": "Core::Interface",
                                    "message": leak_message,
                                }
                            ],
                        }
                    }
                ]
            return self.write_response

    transport = PskEchoFailTransport()
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=False,
    )
    assert result.overall == "failed"
    psk_step = next(
        step for step in result.steps if step.op == WifiApRciOperation.SET_WPA_PSK.value
    )
    assert psk_step.router_message is not None
    assert _OFFLINE_PSK_PLACEHOLDER not in psk_step.router_message
    assert "<redacted>" in psk_step.router_message
    serialized = json.dumps(result.to_dict())
    assert _OFFLINE_PSK_PLACEHOLDER not in serialized
    assert _OFFLINE_PSK_PLACEHOLDER not in " ".join(result.errors)
    assert _OFFLINE_PSK_PLACEHOLDER not in " ".join(result.logs)


def test_partial_compensation_keeps_failed_not_rolled_back() -> None:
    enable_fail = f"interface {_AP} encryption enable"
    rollback_psk_fail = f"interface {_AP} no authentication wpa-psk"

    class PartialRollbackTransport(FakeWifiApplyTransport):
        def execute_sealed_rci_write(self, request: Any) -> Any:
            body = json.loads(request.body.decode("utf-8"))
            command = str(body[0]["parse"])
            self.write_commands.append(command)
            if command in {enable_fail, rollback_psk_fail}:
                return [
                    {
                        "parse": {
                            "prompt": "(config)",
                            "status": [
                                {
                                    "status": "error",
                                    "code": "1",
                                    "ident": "Core::Interface",
                                    "message": "synthetic failure",
                                }
                            ],
                        }
                    }
                ]
            return self.write_response

    transport = PartialRollbackTransport()
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "failed"
    assert result.overall not in {"applied", "rolled_back"}
    assert result.errors == ("service.op_dispatch_failed",)
    assert result.rollback is not None
    assert result.rollback.outcome in {"partial", "failed"}
    assert rollback_psk_fail in transport.write_commands


def test_idempotent_sparse_observed_fallback_full_sequence() -> None:
    sparse = {"interface": {"mac": "aa:bb:cc:dd:ee:ff"}}
    transport = FakeWifiApplyTransport(
        show_interface_readback_sequence=[sparse, _on_air_verified_readback()],
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        idempotent=True,
    )
    assert result.skipped_ops == ()
    assert "idempotent_fallback_full_sequence" in result.logs
    assert len(result.steps) == 5


def test_compensate_skips_clear_psk_when_pre_readback_omits_psk() -> None:
    pre_readback = {
        "interface": {
            "ssid": "Existing-Net",
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
        }
    }
    transport = FakeWifiApplyTransport(
        show_interface_readback_sequence=[pre_readback, _on_air_verified_readback()],
        fail_on_command=f"interface {_AP} encryption enable",
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.rollback is not None
    assert WifiApRciOperation.CLEAR_WPA_PSK.value not in result.rollback.ops
    uncovered = {item.op: item.reason for item in result.rollback.uncovered_ops}
    assert WifiApRciOperation.SET_WPA_PSK.value in uncovered
    assert "PSK state unknown" in uncovered[WifiApRciOperation.SET_WPA_PSK.value]


def test_pre_apply_read_timeout_continues_with_unknown_baseline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import time

    from router_control.application import apply_pre_read

    monkeypatch.setattr(apply_pre_read, "_DEFAULT_PRE_APPLY_READ_TIMEOUT_SECONDS", 0.05)

    class HangingPreReadTransport(FakeWifiApplyTransport):
        def execute_rci_parse(self, cli_command: str) -> Any:
            self.parse_commands.append(cli_command)
            if cli_command.startswith("show interface ") and len(self.parse_commands) == 1:
                time.sleep(0.2)
            if self.readback_sequence:
                return self.readback_sequence.pop(0)
            return _on_air_verified_readback()

    started = time.monotonic()
    transport = HangingPreReadTransport(readback_sequence=[_on_air_verified_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    elapsed = time.monotonic() - started
    assert elapsed < 1.0
    assert result.overall == "applied"
    assert "pre_apply baseline read failed; compensation fail-closed" in result.logs
    assert len(result.steps) == 5
