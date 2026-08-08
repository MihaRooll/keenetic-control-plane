"""Offline tests for Wi-Fi apply service (injected fake transport)."""

from __future__ import annotations

import json
from typing import Any

import pytest
from router_control.adapters.netcraze.sanitize import redact_sealed_cli_command
from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation
from router_control.application import wifi_apply_service
from router_control.application.verdict_explanation import (
    VerdictLiteralError,
    validate_wifi_apply_payload,
)
from router_control.application.wifi_apply_service import (
    WifiApplyResult,
    WifiApplyServiceError,
    _encryption_indicates_wpa2,
    _encryption_indicates_wpa3,
    _encryption_matches_mode,
    apply_wifi_intent,
    preview_wifi_apply,
    teardown_wifi_ap,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)

_OFFLINE_PSK_PLACEHOLDER = "test-psk-placeholder"
_TEST_AP = "WifiMaster0/AccessPoint3"
_PRODUCTION_AP = "WifiMaster0/AccessPoint0"
_PRODUCTION_AP_IDS = (
    "WifiMaster0/AccessPoint0",
    "WifiMaster0/AccessPoint1",
    "WifiMaster0/AccessPoint2",
)
_NON_WIFIMASTER_AP = "Bridge0"


def _wpa2_intent(**overrides: object) -> WifiIntent:
    base = {
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": CaptivePortalMode.DISABLED,
        "guest_isolation": False,
        "wpa_mode": WifiWpaMode.WPA2,
        "band": WifiBand.BAND_2_4GHZ,
    }
    base.update(overrides)
    return WifiIntent(**base)  # type: ignore[arg-type]


def _ok_envelope(ident: str = "Core::Interface") -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "8979152",
                        "ident": ident,
                        "message": "synthetic ack",
                    }
                ],
            }
        }
    ]


def _applied_readback(ssid: str = "Staff-Private") -> dict[str, Any]:
    return {
        "interface": {
            "ssid": ssid,
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
            "up": True,
            "mac": "aa:bb:cc:dd:ee:ff",
        }
    }


def _baseline_readback() -> dict[str, Any]:
    return {
        "interface": {
            "ssid": "",
            "encryption": {},
            "state": "down",
            "up": False,
        }
    }


def _teardown_on_air_verified_readback() -> dict[str, Any]:
    return {
        "interface": {
            "ssid": "",
            "encryption": {},
            "state": "down",
            "up": False,
            "link": False,
            "broadcast": False,
        }
    }


def _wpa3_applied_readback(ssid: str = "Staff-Private") -> dict[str, Any]:
    return {
        "interface": {
            "ssid": ssid,
            "encryption": {"wpa3": True, "enabled": True},
            "state": "up",
            "up": True,
            "mac": "aa:bb:cc:dd:ee:ff",
        }
    }


def _mixed_applied_readback(ssid: str = "Staff-Private") -> dict[str, Any]:
    return {
        "interface": {
            "ssid": ssid,
            "encryption": {"wpa2": True, "wpa3": True, "enabled": True},
            "state": "up",
            "up": True,
            "mac": "aa:bb:cc:dd:ee:ff",
        }
    }


class FakeWifiApplyTransport:
    def __init__(
        self,
        *,
        write_response: Any | None = None,
        readback_sequence: list[Any] | None = None,
        fail_on_command: str | None = None,
        readback_raises: BaseException | None = None,
        show_interface_readback_sequence: list[Any] | None = None,
        pre_read_raises: BaseException | None = None,
    ) -> None:
        self.write_response = write_response if write_response is not None else _ok_envelope()
        self.readback_sequence = list(readback_sequence or [])
        self.show_interface_readback_sequence = list(show_interface_readback_sequence or [])
        self.fail_on_command = fail_on_command
        self.readback_raises = readback_raises
        self.pre_read_raises = pre_read_raises
        self.write_commands: list[str] = []
        self.parse_commands: list[str] = []
        self._show_interface_parse_count = 0

    def execute_sealed_rci_write(self, request: Any) -> Any:
        body = json.loads(request.body.decode("utf-8"))
        command = str(body[0]["parse"])
        self.write_commands.append(redact_sealed_cli_command(command))
        if self.fail_on_command is not None and command == self.fail_on_command:
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

    def execute_rci_parse(self, cli_command: str) -> Any:
        self.parse_commands.append(cli_command)
        if cli_command.startswith("show interface "):
            if (
                self.pre_read_raises is not None
                and self._show_interface_parse_count == 0
            ):
                self._show_interface_parse_count += 1
                raise self.pre_read_raises
            if (
                self.readback_raises is not None
                and self._show_interface_parse_count > 0
            ):
                raise self.readback_raises
            if self.show_interface_readback_sequence:
                idx = self._show_interface_parse_count
                self._show_interface_parse_count += 1
                if idx < len(self.show_interface_readback_sequence):
                    return self.show_interface_readback_sequence[idx]
            if self.readback_sequence and self._show_interface_parse_count > 0:
                self._show_interface_parse_count += 1
                return self.readback_sequence.pop(0)
            if self.readback_sequence and self._show_interface_parse_count == 0:
                self._show_interface_parse_count += 1
                return _baseline_readback()
            self._show_interface_parse_count += 1
            return _baseline_readback()
        if self.readback_raises is not None:
            raise self.readback_raises
        if self.readback_sequence:
            return self.readback_sequence.pop(0)
        return _baseline_readback()


def test_preview_returns_plan_without_dispatch() -> None:
    intent = _wpa2_intent()
    plan = preview_wifi_apply(intent, _TEST_AP)
    assert plan["verification_status"] == "device_verified_wpa2"
    assert len(plan["apply_ops"]) == 5
    psk_op = next(
        op for op in plan["apply_ops"] if op["operation"] == WifiApRciOperation.SET_WPA_PSK.value
    )
    assert psk_op["credential_ref_id"] == "credref:staff-wifi"
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(plan)


def test_preview_no_plaintext_psk_in_plan() -> None:
    plan = preview_wifi_apply(_wpa2_intent(), _TEST_AP)
    serialized = json.dumps(plan)
    assert _OFFLINE_PSK_PLACEHOLDER not in serialized
    assert "password" not in serialized.lower()


def test_apply_success_dispatches_ops_and_verifies() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "applied"
    assert len(result.steps) == 5
    assert all(step.ok for step in result.steps)
    step_dicts = [step.to_dict() for step in result.steps]
    assert all(step["operation"] == step["op"] for step in step_dicts)
    assert result.verification is not None
    assert result.verification.ssid_ok is True
    assert result.verification.encryption_ok is True
    assert result.verification.admin_up_ok is True
    assert result.verification.on_air_ok is None
    assert result.on_air_verification_status == "on_air_unverified"
    assert "mac" not in json.dumps(result.verification.observed).lower() or (
        "REDACTED" in json.dumps(result.verification.observed)
    )
    serialized = json.dumps(result.to_dict())
    assert _OFFLINE_PSK_PLACEHOLDER not in serialized


def test_apply_op_error_stops_with_failed() -> None:
    transport = FakeWifiApplyTransport(
        fail_on_command="interface WifiMaster0/AccessPoint3 encryption enable"
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=False,
    )
    assert result.overall == "failed"
    assert any(not step.ok for step in result.steps)
    assert result.verification is None
    assert len(transport.write_commands) == 3


def test_apply_verify_mismatch() -> None:
    transport = FakeWifiApplyTransport(
        readback_sequence=[_applied_readback(ssid="Wrong-SSID")]
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=False,
    )
    assert result.overall == "verify_mismatch"
    assert result.verification is not None
    assert result.verification.ssid_ok is False


def test_teardown_baseline_verify() -> None:
    transport = FakeWifiApplyTransport(
        show_interface_readback_sequence=[_teardown_on_air_verified_readback()],
    )
    result = teardown_wifi_ap(ap_id=_TEST_AP, transport=transport)
    assert result.overall == "applied"
    assert len(result.steps) == 5
    assert result.verification is not None
    assert result.verification.ssid_ok is True
    assert result.verification.encryption_ok is True
    assert result.verification.admin_up_ok is False
    assert result.verification.on_air_ok is False
    assert result.on_air_verification_status == "on_air_verified"


def test_teardown_on_air_unverified_is_verify_mismatch() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_baseline_readback()])
    result = teardown_wifi_ap(ap_id=_TEST_AP, transport=transport)
    assert result.on_air_verification_status == "on_air_unverified"
    assert result.overall == "verify_mismatch"


def _admin_up_link_down_readback(ssid: str = "Staff-Private") -> dict[str, Any]:
    return {
        "interface": {
            "ssid": ssid,
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
            "up": True,
            "link": "down",
            "connected": True,
        }
    }


def _admin_up_link_up_readback(ssid: str = "Staff-Private") -> dict[str, Any]:
    return {
        "interface": {
            "ssid": ssid,
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
            "up": True,
            "link": "up",
            "broadcast": True,
        }
    }


def test_apply_admin_up_link_down_verify_mismatch_no_rollback() -> None:
    """state=up alone must not count as on-air success (live torn-down AP shape)."""
    transport = FakeWifiApplyTransport(
        readback_sequence=[_admin_up_link_down_readback()]
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=True,
    )
    assert result.overall == "verify_mismatch"
    assert result.on_air_verification_status == "on_air_admin_only"
    assert result.verification is not None
    assert result.verification.admin_up_ok is True
    assert result.verification.on_air_ok is False
    assert result.rollback is not None
    assert result.rollback.attempted is False


def test_apply_missing_link_fields_applied_unverified_not_failed() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "applied"
    assert result.on_air_verification_status == "on_air_unverified"
    assert result.verification is not None
    assert result.verification.on_air_ok is None


def test_apply_on_air_verified_when_link_up() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_admin_up_link_up_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "applied"
    assert result.on_air_verification_status == "on_air_verified"
    assert result.verification is not None
    assert result.verification.on_air_ok is True
    with pytest.raises(WifiApplyServiceError, match="allowlisted"):
        preview_wifi_apply(_wpa2_intent(), _PRODUCTION_AP)


def _broadcast_true_link_false_readback() -> dict[str, Any]:
    return {
        "interface": {
            "ssid": "Staff-Private",
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
            "up": True,
            "link": False,
            "broadcast": True,
        }
    }


def test_apply_broadcast_true_link_false_not_on_air_verified() -> None:
    """broadcast=true must not override link=false for on-air success.

    Config verify passes → overall=applied (configuration delivered). On-air unknown
    due to link/broadcast conflict → on_air_unverified, not verify_mismatch (unlike
    admin_up+link_down which is a known deceptive on-air state).
    """
    transport = FakeWifiApplyTransport(
        readback_sequence=[_broadcast_true_link_false_readback()]
    )
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        compensate_on_failure=True,
    )
    assert result.on_air_verification_status == "on_air_unverified"
    assert result.verification is not None
    assert result.verification.on_air_ok is None
    assert result.verification.ssid_ok is True
    assert result.verification.encryption_ok is True
    assert result.verification.admin_up_ok is True
    assert result.overall == "applied"
    assert result.rollback is not None
    assert result.rollback.attempted is False


@pytest.mark.parametrize("ap_id", _PRODUCTION_AP_IDS)
def test_production_ap_rejected_on_apply(ap_id: str) -> None:
    transport = FakeWifiApplyTransport()
    with pytest.raises(WifiApplyServiceError, match="allowlisted"):
        apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=ap_id,
            transport=transport,
            credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        )
    assert transport.write_commands == []


@pytest.mark.parametrize("ap_id", _PRODUCTION_AP_IDS)
def test_production_ap_rejected_on_teardown(ap_id: str) -> None:
    transport = FakeWifiApplyTransport()
    with pytest.raises(WifiApplyServiceError, match="allowlisted"):
        teardown_wifi_ap(ap_id=ap_id, transport=transport)
    assert transport.write_commands == []


@pytest.mark.parametrize("ap_id", _PRODUCTION_AP_IDS)
def test_production_ap_rejected_at_service_preview(ap_id: str) -> None:
    with pytest.raises(WifiApplyServiceError, match="allowlisted"):
        preview_wifi_apply(_wpa2_intent(), ap_id)


def test_production_ap_accepted_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    plan = preview_wifi_apply(_wpa2_intent(), _PRODUCTION_AP)
    assert plan["verification_status"] == "device_verified_wpa2"


def test_non_wifimaster_ap_rejected_at_service() -> None:
    with pytest.raises(WifiApplyServiceError, match="allowlisted"):
        preview_wifi_apply(_wpa2_intent(), _NON_WIFIMASTER_AP)


def test_credential_resolver_exception_does_not_leak_psk() -> None:
    def _failing_resolver(_ref: str) -> str:
        raise RuntimeError(f"decode failed: {_OFFLINE_PSK_PLACEHOLDER}")

    transport = FakeWifiApplyTransport()
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=_failing_resolver,
    )
    assert result.overall == "rolled_back"
    serialized = json.dumps(result.to_dict())
    assert _OFFLINE_PSK_PLACEHOLDER not in serialized
    assert result.errors == (ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,)
    assert len(result.steps) == 2
    assert result.steps[0].ok is True
    assert result.steps[1].ok is False
    assert result.steps[1].error == ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED
    assert result.rollback is not None
    assert result.rollback.outcome == "succeeded"


def test_wpa3_apply_dispatches_and_verifies() -> None:
    intent = _wpa2_intent(wpa_mode=WifiWpaMode.WPA3)
    transport = FakeWifiApplyTransport(readback_sequence=[_wpa3_applied_readback()])
    result = apply_wifi_intent(
        intent=intent,
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "applied"
    assert len(result.steps) == 5
    assert all(step.ok for step in result.steps)
    assert result.verification is not None
    assert result.verification.encryption_ok is True
    assert _OFFLINE_PSK_PLACEHOLDER not in json.dumps(result.to_dict())
    assert any("authentication wpa-psk" in cmd for cmd in transport.write_commands)
    assert any("encryption wpa3" in cmd for cmd in transport.write_commands)


def test_wpa2_wpa3_mixed_apply_dispatches_and_verifies() -> None:
    intent = _wpa2_intent(wpa_mode=WifiWpaMode.WPA2_WPA3_MIXED)
    transport = FakeWifiApplyTransport(readback_sequence=[_mixed_applied_readback()])
    result = apply_wifi_intent(
        intent=intent,
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    assert result.overall == "applied"
    assert len(result.steps) == 6
    assert all(step.ok for step in result.steps)
    assert result.verification is not None
    assert result.verification.encryption_ok is True


def test_wpa3_preview_device_verified_wpa2() -> None:
    plan = preview_wifi_apply(_wpa2_intent(wpa_mode=WifiWpaMode.WPA3), _TEST_AP)
    assert plan["verification_status"] == "device_verified_wpa2"
    assert len(plan["apply_ops"]) == 5
    assert any("5.01.C.1.0-0" in note for note in plan["notes"])


def test_wpa2_wpa3_mixed_preview_device_verified_wpa2() -> None:
    plan = preview_wifi_apply(_wpa2_intent(wpa_mode=WifiWpaMode.WPA2_WPA3_MIXED), _TEST_AP)
    assert plan["verification_status"] == "device_verified_wpa2"
    assert len(plan["apply_ops"]) == 6
    assert any("5.01.C.1.0-0" in note for note in plan["notes"])


def test_compile_plan_preserves_guest_isolation_unsupported_code() -> None:
    intent = _wpa2_intent(guest_isolation=True)
    with pytest.raises(WifiApplyServiceError) as exc_info:
        wifi_apply_service._compile_plan(intent, _TEST_AP)
    assert str(exc_info.value) == ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED


def test_preview_wifi_apply_surfaces_planner_guest_isolation_code() -> None:
    intent = _wpa2_intent(enabled=False, guest_isolation=True, credential_ref_id=None)
    with pytest.raises(WifiApplyServiceError) as exc_info:
        preview_wifi_apply(intent, _TEST_AP)
    assert str(exc_info.value) == ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED


def test_wpa3_teardown_dispatches_wpa_psk_clear() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_baseline_readback()])
    result = teardown_wifi_ap(
        ap_id=_TEST_AP,
        transport=transport,
        wpa_mode=WifiWpaMode.WPA3,
    )
    assert result.overall == "applied"
    assert len(result.steps) == 5
    assert any("no authentication wpa-psk" in cmd for cmd in transport.write_commands)
    assert any("no encryption wpa3" in cmd for cmd in transport.write_commands)


def test_wpa3_teardown_continues_after_mid_op_failure() -> None:
    transport = FakeWifiApplyTransport(
        readback_sequence=[_baseline_readback()],
        fail_on_command=f"interface {_TEST_AP} no authentication wpa-psk",
    )
    result = teardown_wifi_ap(
        ap_id=_TEST_AP,
        transport=transport,
        wpa_mode=WifiWpaMode.WPA3,
    )
    assert result.overall == "failed"
    assert result.overall != "applied"
    assert any(f"interface {_TEST_AP} no ssid" in cmd for cmd in transport.write_commands)
    psk_step = next(
        step for step in result.steps if step.op == WifiApRciOperation.CLEAR_WPA_PSK.value
    )
    assert psk_step.ok is False
    assert result.verification is not None
    assert result.errors == ("service.op_dispatch_failed",)


def test_wpa3_teardown_aggregates_dispatch_and_readback_errors() -> None:
    class TeardownReadbackFailTransport(FakeWifiApplyTransport):
        def execute_rci_parse(self, cli_command: str) -> Any:
            if cli_command.startswith("show interface "):
                raise RuntimeError("synthetic readback failure")
            return super().execute_rci_parse(cli_command)

    transport = TeardownReadbackFailTransport(
        fail_on_command=f"interface {_TEST_AP} no authentication wpa-psk",
    )
    result = teardown_wifi_ap(
        ap_id=_TEST_AP,
        transport=transport,
        wpa_mode=WifiWpaMode.WPA3,
    )
    assert result.overall == "failed"
    assert result.verification is None
    assert result.errors == ("service.op_dispatch_failed", "service.readback_failed")
    assert len(result.steps) == 5
    assert any(f"interface {_TEST_AP} no ssid" in cmd for cmd in transport.write_commands)


def test_mixed_teardown_dispatches_full_clear_sequence() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_baseline_readback()])
    result = teardown_wifi_ap(
        ap_id=_TEST_AP,
        transport=transport,
        wpa_mode=WifiWpaMode.WPA2_WPA3_MIXED,
    )
    assert result.overall == "applied"
    assert len(result.steps) == 6
    assert any("no encryption wpa2" in cmd for cmd in transport.write_commands)
    assert any("no encryption wpa3" in cmd for cmd in transport.write_commands)


def test_apply_op_order_matches_planner() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    expected = [
        f"interface {_TEST_AP} ssid Staff-Private",
        f"interface {_TEST_AP} authentication wpa-psk <redacted>",
        f"interface {_TEST_AP} encryption enable",
        f"interface {_TEST_AP} encryption wpa2",
        f"interface {_TEST_AP} up",
    ]
    assert transport.write_commands == expected


def test_teardown_5ghz_ap_uses_correct_band() -> None:
    ap_id = "WifiMaster1/AccessPoint4"
    transport = FakeWifiApplyTransport(readback_sequence=[_baseline_readback()])
    result = teardown_wifi_ap(ap_id=ap_id, transport=transport)
    assert result.overall == "applied"
    assert transport.parse_commands == [f"show interface {ap_id}"]


def test_encryption_dict_false_keys_do_not_match() -> None:
    enc = {"wpa2": False, "wpa3": False}
    assert _encryption_indicates_wpa3(enc) is False
    assert _encryption_indicates_wpa2(enc) is False
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA3) is False
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA2) is False
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA2_WPA3_MIXED) is False


def test_encryption_partial_wpa3_without_wpa2_not_mixed() -> None:
    enc = {"wpa2": False, "wpa3": True}
    assert _encryption_indicates_wpa3(enc) is True
    assert _encryption_indicates_wpa2(enc) is False
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA3) is True
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA2_WPA3_MIXED) is False


def test_encryption_genuine_mixed_positive() -> None:
    enc = {"wpa2": True, "wpa3": True}
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA2_WPA3_MIXED) is True
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA2) is True
    assert _encryption_matches_mode(enc, WifiWpaMode.WPA3) is True


@pytest.mark.parametrize(
    ("encryption", "mode", "expected"),
    [
        ({"wpa2": "no", "wpa3": "no"}, WifiWpaMode.WPA3, False),
        ({"wpa2": "disabled", "wpa3": "disabled"}, WifiWpaMode.WPA2_WPA3_MIXED, False),
        ("wpa3-personal", WifiWpaMode.WPA3, True),
        ("wpa2", WifiWpaMode.WPA2, True),
        ("wpa2 wpa3", WifiWpaMode.WPA2_WPA3_MIXED, True),
    ],
)
def test_encryption_string_readbacks_still_match(
    encryption: object, mode: WifiWpaMode, expected: bool
) -> None:
    assert _encryption_matches_mode(encryption, mode) is expected


def _wifi_apply_payload_without_validation(result: WifiApplyResult) -> dict[str, object]:
    """Mirror ``WifiApplyResult.to_dict`` payload assembly without runtime validation."""
    payload: dict[str, object] = {
        "overall": result.overall,
        "ap_id": result.ap_id,
        "on_air_verification_status": result.on_air_verification_status,
        "steps": [step.to_dict() for step in result.steps],
        "errors": list(result.errors),
        "rollback_errors": list(result.rollback_errors),
        "logs": list(result.logs),
    }
    if result.verdict_explanation is not None:
        payload["verdict_explanation"] = result.verdict_explanation.to_dict()
    if result.verification is not None:
        payload["verification"] = result.verification.to_dict()
    if result.backup_basename is not None:
        payload["backup_basename"] = result.backup_basename
    if result.backup_content_sha256 is not None:
        payload["backup_content_sha256"] = result.backup_content_sha256
    if result.rollback is not None:
        payload["rollback"] = result.rollback.to_dict()
    if result.skipped_ops:
        payload["skipped_ops"] = [item.to_dict() for item in result.skipped_ops]
    return payload


def test_wifi_apply_to_dict_invokes_validate_wifi_apply_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []

    def _tracking_validate(payload: dict[str, object]) -> dict[str, object]:
        calls.append(payload)
        return validate_wifi_apply_payload(payload)

    monkeypatch.setattr(
        wifi_apply_service,
        "validate_wifi_apply_payload",
        _tracking_validate,
    )
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    serialized = result.to_dict()
    assert calls, "WifiApplyResult.to_dict must call validate_wifi_apply_payload"
    assert calls[-1] is serialized


def test_validate_wifi_apply_payload_is_identity_passthrough() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    raw = _wifi_apply_payload_without_validation(result)
    validated = validate_wifi_apply_payload(raw)
    assert validated is raw
    assert json.dumps(raw, sort_keys=True) == json.dumps(validated, sort_keys=True)


@pytest.mark.parametrize(
    ("scenario", "overall"),
    [
        ("applied", "applied"),
        ("failed", "failed"),
        ("verify_mismatch", "verify_mismatch"),
        ("rolled_back", "rolled_back"),
        ("teardown_applied", "applied"),
        ("teardown_mismatch", "verify_mismatch"),
        ("readback_failed", "failed"),
    ],
)
def test_wifi_apply_validation_preserves_payload_on_all_branches(
    scenario: str,
    overall: str,
) -> None:
    if scenario == "applied":
        transport = FakeWifiApplyTransport(readback_sequence=[_admin_up_link_up_readback()])
        result = apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
        )
    elif scenario == "failed":
        transport = FakeWifiApplyTransport(
            fail_on_command="interface WifiMaster0/AccessPoint3 encryption enable"
        )
        result = apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
            compensate_on_failure=False,
        )
    elif scenario == "verify_mismatch":
        transport = FakeWifiApplyTransport(
            readback_sequence=[_applied_readback(ssid="Wrong-SSID")]
        )
        result = apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
            compensate_on_failure=False,
        )
    elif scenario == "rolled_back":

        def _failing_resolver(_ref: str) -> str:
            raise RuntimeError("credential decode failed")

        transport = FakeWifiApplyTransport()
        result = apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=_failing_resolver,
        )
    elif scenario == "teardown_applied":
        transport = FakeWifiApplyTransport(
            show_interface_readback_sequence=[_teardown_on_air_verified_readback()],
        )
        result = teardown_wifi_ap(ap_id=_TEST_AP, transport=transport)
    elif scenario == "teardown_mismatch":
        transport = FakeWifiApplyTransport(
            show_interface_readback_sequence=[_applied_readback()],
        )
        result = teardown_wifi_ap(ap_id=_TEST_AP, transport=transport)
    else:

        class ReadbackFailTransport(FakeWifiApplyTransport):
            def execute_rci_parse(self, cli_command: str) -> Any:
                if cli_command.startswith("show interface "):
                    raise RuntimeError("offline readback")
                return super().execute_rci_parse(cli_command)

        transport = ReadbackFailTransport()
        result = apply_wifi_intent(
            intent=_wpa2_intent(),
            ap_id=_TEST_AP,
            transport=transport,
            credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
            compensate_on_failure=False,
        )

    assert result.overall == overall
    raw = _wifi_apply_payload_without_validation(result)
    validated = validate_wifi_apply_payload(raw)
    assert raw == validated
    assert set(raw.keys()) == set(result.to_dict().keys())
    assert json.dumps(raw, sort_keys=True) == json.dumps(result.to_dict(), sort_keys=True)


def test_wifi_apply_to_dict_rejects_invalid_on_air_verdict() -> None:
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _OFFLINE_PSK_PLACEHOLDER,
    )
    broken = _wifi_apply_payload_without_validation(result)
    broken["on_air_verification_status"] = "on_air_totally_unknown"
    with pytest.raises(VerdictLiteralError, match="on_air_verification_status"):
        validate_wifi_apply_payload(broken)
