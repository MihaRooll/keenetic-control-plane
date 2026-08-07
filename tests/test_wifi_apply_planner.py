"""Offline Wi-Fi intent → sealed op compiler tests."""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest
import router_control.application.wifi_apply_planner as wifi_apply_planner_module
from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation
from router_control.application.wifi_apply_planner import (
    WifiApplyPlannerError,
    compile_wifi_intent_to_ops,
    wifi_master_for_band,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)

WPA2_APPLY = (
    WifiApRciOperation.SET_SSID,
    WifiApRciOperation.SET_WPA_PSK,
    WifiApRciOperation.ENCRYPTION_ENABLE,
    WifiApRciOperation.ENCRYPTION_WPA2,
    WifiApRciOperation.UP,
)

WPA2_TEARDOWN = (
    WifiApRciOperation.DOWN,
    WifiApRciOperation.ENCRYPTION_WPA2_CLEAR,
    WifiApRciOperation.ENCRYPTION_DISABLE,
    WifiApRciOperation.CLEAR_WPA_PSK,
    WifiApRciOperation.CLEAR_SSID,
)

WPA3_APPLY = (
    WifiApRciOperation.SET_SSID,
    WifiApRciOperation.SET_WPA_PSK,
    WifiApRciOperation.ENCRYPTION_ENABLE,
    WifiApRciOperation.ENCRYPTION_WPA3,
    WifiApRciOperation.UP,
)

WPA3_TEARDOWN = (
    WifiApRciOperation.DOWN,
    WifiApRciOperation.ENCRYPTION_WPA3_CLEAR,
    WifiApRciOperation.ENCRYPTION_DISABLE,
    WifiApRciOperation.CLEAR_WPA_PSK,
    WifiApRciOperation.CLEAR_SSID,
)

MIXED_APPLY = (
    WifiApRciOperation.SET_SSID,
    WifiApRciOperation.SET_WPA_PSK,
    WifiApRciOperation.ENCRYPTION_ENABLE,
    WifiApRciOperation.ENCRYPTION_WPA2,
    WifiApRciOperation.ENCRYPTION_WPA3,
    WifiApRciOperation.UP,
)

MIXED_TEARDOWN = (
    WifiApRciOperation.DOWN,
    WifiApRciOperation.ENCRYPTION_WPA3_CLEAR,
    WifiApRciOperation.ENCRYPTION_WPA2_CLEAR,
    WifiApRciOperation.ENCRYPTION_DISABLE,
    WifiApRciOperation.CLEAR_WPA_PSK,
    WifiApRciOperation.CLEAR_SSID,
)


def _wpa2_intent(**overrides: object) -> WifiIntent:
    base = {
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": CaptivePortalMode.DISABLED,
        "guest_isolation": False,
    }
    base.update(overrides)
    return WifiIntent(**base)  # type: ignore[arg-type]


def test_wifi_master_for_band_mapping() -> None:
    assert wifi_master_for_band(WifiBand.BAND_2_4GHZ) == "WifiMaster0"
    assert wifi_master_for_band(WifiBand.BAND_5GHZ) == "WifiMaster1"


def test_wpa2_full_apply_and_teardown_sequence() -> None:
    intent = _wpa2_intent()
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")

    assert plan.verification_status == "device_verified_wpa2"
    assert [op.operation for op in plan.apply_ops] == [op.value for op in WPA2_APPLY]
    assert [op.operation for op in plan.teardown_ops] == [op.value for op in WPA2_TEARDOWN]
    assert plan.apply_ops[0].ssid == "Staff-Private"
    assert plan.apply_ops[1].credential_ref_id == "credref:staff-wifi"
    assert all(op.ap_id == "WifiMaster0/AccessPoint3" for op in plan.apply_ops)
    assert all(op.ap_id == "WifiMaster0/AccessPoint3" for op in plan.teardown_ops)


def test_wpa2_defaults_when_fields_omitted() -> None:
    intent = WifiIntent(
        ssid="Promo",
        enabled=False,
        credential_ref_id=None,
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=False,
    )
    assert intent.wpa_mode == WifiWpaMode.WPA2
    assert intent.band == WifiBand.BAND_2_4GHZ

    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint4")
    assert plan.verification_status == "device_verified_wpa2"
    assert plan.apply_ops == ()
    assert len(plan.teardown_ops) == len(WPA2_TEARDOWN)


def test_disabled_wpa2_apply_ops_empty_teardown_present() -> None:
    intent = _wpa2_intent(enabled=False)
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")
    assert plan.apply_ops == ()
    assert len(plan.teardown_ops) == len(WPA2_TEARDOWN)


def test_enabled_wpa2_requires_credential_ref() -> None:
    intent = _wpa2_intent(credential_ref_id=None)
    with pytest.raises(WifiApplyPlannerError, match="planner.credential_ref_required"):
        compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")


def test_credential_ref_only_no_plaintext_in_ops() -> None:
    intent = _wpa2_intent(credential_ref_id="credref:promo-wifi")
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint5")
    psk_op = next(
        op for op in plan.apply_ops if op.operation == WifiApRciOperation.SET_WPA_PSK.value
    )
    assert psk_op.credential_ref_id == "credref:promo-wifi"
    assert not hasattr(psk_op, "psk")
    assert psk_op.ssid is None


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint0",
        "WifiMaster0/AccessPoint1",
        "WifiMaster0/AccessPoint2",
        "WifiMaster1/AccessPoint0",
    ],
)
def test_rejects_production_access_points(ap_id: str) -> None:
    intent = _wpa2_intent()
    with pytest.raises(ValueError, match="allowlisted"):
        compile_wifi_intent_to_ops(intent, ap_id)


@pytest.mark.parametrize(
    "ap_id",
    [
        "WifiMaster0/AccessPoint0",
        "WifiMaster0/AccessPoint1",
        "WifiMaster0/AccessPoint2",
    ],
)
def test_accepts_production_access_points_in_expendable_mode(
    monkeypatch: pytest.MonkeyPatch, ap_id: str
) -> None:
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    intent = _wpa2_intent()
    plan = compile_wifi_intent_to_ops(intent, ap_id)
    assert plan.verification_status == "device_verified_wpa2"


@pytest.mark.parametrize(
    "ap_id",
    [
        "Bridge0",
        "WifiMaster2/AccessPoint3",
    ],
)
def test_rejects_non_wifi_master_ap_id(ap_id: str) -> None:
    intent = _wpa2_intent()
    with pytest.raises(ValueError, match="allowlisted"):
        compile_wifi_intent_to_ops(intent, ap_id)


def test_band_mismatch_fails_closed() -> None:
    intent = _wpa2_intent(band=WifiBand.BAND_5GHZ)
    with pytest.raises(WifiApplyPlannerError, match="does not match intent band"):
        compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")


def test_band_match_master1() -> None:
    intent = _wpa2_intent(band=WifiBand.BAND_5GHZ)
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster1/AccessPoint3")
    assert plan.verification_status == "device_verified_wpa2"
    assert len(plan.apply_ops) == len(WPA2_APPLY)


@pytest.mark.parametrize(
    "wpa_mode,apply_seq,teardown_seq",
    [
        (WifiWpaMode.WPA3, WPA3_APPLY, WPA3_TEARDOWN),
    ],
)
def test_wpa3_device_verified_wpa2(
    wpa_mode: WifiWpaMode,
    apply_seq: tuple[WifiApRciOperation, ...],
    teardown_seq: tuple[WifiApRciOperation, ...],
) -> None:
    intent = _wpa2_intent(wpa_mode=wpa_mode)
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")
    assert plan.verification_status == "device_verified_wpa2"
    assert [op.operation for op in plan.apply_ops] == [op.value for op in apply_seq]
    assert [op.operation for op in plan.teardown_ops] == [op.value for op in teardown_seq]
    assert any("5.01.C.1.0-0" in note for note in plan.notes)
    psk_op = next(
        (op for op in plan.apply_ops if op.operation == WifiApRciOperation.SET_WPA_PSK.value),
        None,
    )
    assert psk_op is not None
    assert psk_op.credential_ref_id == "credref:staff-wifi"
    assert not hasattr(psk_op, "psk")


@pytest.mark.parametrize(
    "wpa_mode,apply_seq,teardown_seq",
    [
        (WifiWpaMode.WPA2_WPA3_MIXED, MIXED_APPLY, MIXED_TEARDOWN),
    ],
)
def test_wpa2_wpa3_mixed_device_verified_wpa2(
    wpa_mode: WifiWpaMode,
    apply_seq: tuple[WifiApRciOperation, ...],
    teardown_seq: tuple[WifiApRciOperation, ...],
) -> None:
    intent = _wpa2_intent(wpa_mode=wpa_mode)
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")
    assert plan.verification_status == "device_verified_wpa2"
    assert [op.operation for op in plan.apply_ops] == [op.value for op in apply_seq]
    assert [op.operation for op in plan.teardown_ops] == [op.value for op in teardown_seq]
    assert any("5.01.C.1.0-0" in note for note in plan.notes)
    psk_op = next(
        (op for op in plan.apply_ops if op.operation == WifiApRciOperation.SET_WPA_PSK.value),
        None,
    )
    assert psk_op is not None
    assert psk_op.credential_ref_id == "credref:staff-wifi"
    assert not hasattr(psk_op, "psk")


def test_wpa3_requires_credential_ref() -> None:
    intent = _wpa2_intent(wpa_mode=WifiWpaMode.WPA3, credential_ref_id=None)
    with pytest.raises(WifiApplyPlannerError, match="planner.credential_ref_required"):
        compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")


def test_compensate_ops_for_succeeded_apply_wpa2() -> None:
    from router_control.application.wifi_apply_planner import compensate_ops_for_succeeded_apply

    plan = compile_wifi_intent_to_ops(_wpa2_intent(), "WifiMaster0/AccessPoint3")
    succeeded = tuple(op.value for op in WPA2_APPLY[:3])
    compensate = compensate_ops_for_succeeded_apply(plan.apply_ops, succeeded)
    assert [op.operation for op in compensate] == [
        WifiApRciOperation.ENCRYPTION_DISABLE.value,
        WifiApRciOperation.CLEAR_WPA_PSK.value,
        WifiApRciOperation.CLEAR_SSID.value,
    ]


def test_derive_pre_state_psk_unknown_when_readback_omits_psk() -> None:
    from router_control.application.wifi_apply_planner import (
        compensate_ops_for_succeeded_apply,
        derive_wifi_pre_state,
        uncovered_compensate_ops_for_succeeded_apply,
    )

    raw = {
        "interface": {
            "ssid": "Existing-Net",
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
        }
    }
    observed = {
        "ssid": "Existing-Net",
        "encryption": {"wpa2": True, "enabled": True},
        "state": "up",
    }
    pre_state = derive_wifi_pre_state(observed, raw=raw)
    assert pre_state.had_psk is None

    plan = compile_wifi_intent_to_ops(_wpa2_intent(), "WifiMaster0/AccessPoint3")
    succeeded = (WifiApRciOperation.SET_WPA_PSK.value,)
    compensate = compensate_ops_for_succeeded_apply(plan.apply_ops, succeeded, pre_state=pre_state)
    assert WifiApRciOperation.CLEAR_WPA_PSK.value not in [op.operation for op in compensate]
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_apply(plan.apply_ops, succeeded, pre_state=pre_state)
    )
    assert "PSK state unknown" in uncovered[WifiApRciOperation.SET_WPA_PSK.value]


def test_derive_pre_state_psk_known_when_raw_contains_secret_marker() -> None:
    from router_control.application.wifi_apply_planner import derive_wifi_pre_state

    raw = {
        "interface": {
            "authentication": {"wpa-psk": "REDACTED"},
            "encryption": {"wpa2": True, "enabled": True},
        }
    }
    observed = {"encryption": {"wpa2": True, "enabled": True}}
    pre_state = derive_wifi_pre_state(observed, raw=raw)
    assert pre_state.had_psk is True


def _wpa2_compensation_count(pre_state) -> int:
    from router_control.application.wifi_apply_planner import compensate_ops_for_succeeded_apply

    plan = compile_wifi_intent_to_ops(_wpa2_intent(), "WifiMaster0/AccessPoint3")
    succeeded = tuple(op.value for op in WPA2_APPLY)
    compensate = compensate_ops_for_succeeded_apply(plan.apply_ops, succeeded, pre_state=pre_state)
    return len(compensate)


def test_derive_pre_state_open_dict_encryption_uses_open_predicate() -> None:
    """Keenetic readback shape from site_survey fixture: disabled/none dict keys."""
    from router_control.application.wifi_apply_planner import derive_wifi_pre_state

    open_encryption = {"encryption": "disabled", "encryption-mode": "none"}
    raw = {
        "interface": {
            "ssid": "Open-Net",
            "encryption": open_encryption,
            "state": "up",
        }
    }
    observed = {
        "ssid": "Open-Net",
        "encryption": open_encryption,
        "state": "up",
    }
    pre_state = derive_wifi_pre_state(observed, raw=raw)
    assert pre_state.had_psk is False
    assert pre_state.encryption_enabled is False
    assert pre_state.had_wpa2 is False


def test_open_network_wpa2_rollback_compensation_count_before_after_predicate() -> None:
    """Open AP with dict encryption: rollback must cover PSK+encryption ops, not just one."""
    from router_control.application.wifi_apply_planner import derive_wifi_pre_state

    open_encryption = {"encryption": "disabled", "encryption-mode": "none"}
    raw = {
        "interface": {
            "ssid": "Open-Net",
            "encryption": open_encryption,
            "state": "up",
        }
    }
    observed = {
        "ssid": "Open-Net",
        "encryption": open_encryption,
        "state": "up",
    }
    pre_state = derive_wifi_pre_state(observed, raw=raw)
    count = _wpa2_compensation_count(pre_state)
    # SET_SSID blocked (pre-existing); UP blocked (was_admin_up); 3 encryption/psk ops allowed
    assert count == 3


def test_wpa2_with_unknown_psk_still_fail_closed() -> None:
    from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation
    from router_control.application.wifi_apply_planner import (
        compensate_ops_for_succeeded_apply,
        derive_wifi_pre_state,
        uncovered_compensate_ops_for_succeeded_apply,
    )

    raw = {
        "interface": {
            "ssid": "Existing-Net",
            "encryption": {"wpa2": True, "enabled": True},
            "state": "up",
        }
    }
    observed = {
        "ssid": "Existing-Net",
        "encryption": {"wpa2": True, "enabled": True},
        "state": "up",
    }
    pre_state = derive_wifi_pre_state(observed, raw=raw)
    assert pre_state.had_psk is None

    plan = compile_wifi_intent_to_ops(_wpa2_intent(), "WifiMaster0/AccessPoint3")
    succeeded = tuple(op.value for op in WPA2_APPLY)
    compensate = compensate_ops_for_succeeded_apply(plan.apply_ops, succeeded, pre_state=pre_state)
    assert WifiApRciOperation.CLEAR_WPA_PSK.value not in [op.operation for op in compensate]
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_apply(plan.apply_ops, succeeded, pre_state=pre_state)
    )
    assert "PSK state unknown" in uncovered[WifiApRciOperation.SET_WPA_PSK.value]


def test_guest_isolation_true_rejected_with_stable_code() -> None:
    intent = _wpa2_intent(guest_isolation=True)
    with pytest.raises(WifiApplyPlannerError, match=ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED):
        compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")


def test_guest_isolation_false_compiles() -> None:
    intent = _wpa2_intent(guest_isolation=False)
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")
    assert len(plan.apply_ops) == len(WPA2_APPLY)


def test_captive_portal_enabled_rejected_with_stable_code() -> None:
    intent = _wpa2_intent(captive_portal=CaptivePortalMode.ENABLED)
    with pytest.raises(WifiApplyPlannerError, match=ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED):
        compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")


def test_captive_portal_disabled_compiles() -> None:
    intent = _wpa2_intent(captive_portal=CaptivePortalMode.DISABLED)
    plan = compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")
    assert len(plan.apply_ops) == len(WPA2_APPLY)


def _assert_compile_rejects_unsupported_intent(
    intent: WifiIntent,
    ap_id: str,
    *,
    expected_code: str,
) -> None:
    try:
        compile_wifi_intent_to_ops(intent, ap_id)
    except WifiApplyPlannerError as exc:
        assert str(exc) == expected_code, (
            f"expected {expected_code!r}, got {str(exc)!r}"
        )
    else:
        raise AssertionError(
            f"expected WifiApplyPlannerError {expected_code!r}, compile succeeded"
        )


def test_wifi_apply_planner_unsupported_intent_source_guard() -> None:
    source = Path(inspect.getfile(wifi_apply_planner_module)).read_text(encoding="utf-8")
    assert "def _reject_unsupported_intent_fields" in source
    reject_start = source.index("def _reject_unsupported_intent_fields")
    reject_end = source.index("\ndef compile_wifi_intent_to_ops")
    reject_body = source[reject_start:reject_end]
    assert "guest_isolation" in reject_body
    assert "CaptivePortalMode.ENABLED" in reject_body
    assert "ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED" in reject_body
    assert "ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED" in reject_body
    compile_start = source.index("def compile_wifi_intent_to_ops")
    compile_body = source[compile_start : compile_start + 600]
    assert "_reject_unsupported_intent_fields(intent)" in compile_body


def test_wifi_apply_planner_unsupported_intent_rejection_is_not_tautological() -> None:
    """Breaking the gate or substituting an unrelated planner code must fail."""
    ap_id = "WifiMaster0/AccessPoint3"
    guest_intent = _wpa2_intent(
        enabled=False,
        guest_isolation=True,
        credential_ref_id=None,
    )
    captive_intent = _wpa2_intent(
        enabled=False,
        captive_portal=CaptivePortalMode.ENABLED,
        credential_ref_id=None,
    )
    _assert_compile_rejects_unsupported_intent(
        guest_intent,
        ap_id,
        expected_code=ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
    )
    _assert_compile_rejects_unsupported_intent(
        captive_intent,
        ap_id,
        expected_code=ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
    )
    safe_intent = _wpa2_intent(guest_isolation=False)
    with pytest.raises(AssertionError, match="compile succeeded"):
        _assert_compile_rejects_unsupported_intent(
            safe_intent,
            ap_id,
            expected_code=ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
        )
    with pytest.raises(AssertionError, match=ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED):
        _assert_compile_rejects_unsupported_intent(
            guest_intent,
            ap_id,
            expected_code=ERROR_CODE_CREDENTIAL_REF_REQUIRED,
        )


@pytest.mark.parametrize(
    "field_override,expected_code",
    [
        (
            {"enabled": False, "guest_isolation": True, "credential_ref_id": None},
            ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
        ),
        (
            {
                "enabled": False,
                "captive_portal": CaptivePortalMode.ENABLED,
                "credential_ref_id": None,
            },
            ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
        ),
    ],
)
def test_disabled_intent_still_rejects_unsupported_fields(
    field_override: dict[str, object],
    expected_code: str,
) -> None:
    intent = _wpa2_intent(**field_override)
    with pytest.raises(WifiApplyPlannerError, match=expected_code):
        compile_wifi_intent_to_ops(intent, "WifiMaster0/AccessPoint3")
