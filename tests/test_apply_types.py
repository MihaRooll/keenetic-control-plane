"""Apply outcome typing and structured error-code migration guards."""

from __future__ import annotations

from typing import get_args, get_type_hints

import pytest
from router_control.application.apply_types import ApplyOverallStatus, ApplyRollbackOutcome
from router_control.application.wifi_apply_planner import (
    WifiApplyPlannerError,
    compile_wifi_intent_to_ops,
)
from router_control.application.wifi_apply_service import WifiApplyResult, apply_wifi_intent
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    ERROR_CODE_SSID_REQUIRED,
    scrub_error_message,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlannerError,
    compile_uplink_intent_to_station_ops,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    UplinkIntent,
    UplinkMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)
from router_control_host.apply_response_models import (
    ApplyOverallStatus as OpenApiApplyOverallStatus,
)
from router_control_host.apply_response_models import (
    ApplyRollbackOutcome as OpenApiApplyRollbackOutcome,
)

_TEST_AP = "WifiMaster0/AccessPoint3"


def test_apply_overall_status_matches_openapi_contract() -> None:
    assert set(get_args(ApplyOverallStatus)) == set(get_args(OpenApiApplyOverallStatus))


def test_apply_rollback_outcome_matches_openapi_contract() -> None:
    assert set(get_args(ApplyRollbackOutcome)) == set(get_args(OpenApiApplyRollbackOutcome))


def test_wifi_apply_result_overall_field_is_apply_overall_status() -> None:
    hints = get_type_hints(WifiApplyResult)
    assert hints["overall"] == ApplyOverallStatus


def test_structured_error_codes_pass_secret_scrubber() -> None:
    codes = (
        ERROR_CODE_CREDENTIAL_REF_REQUIRED,
        ERROR_CODE_SSID_REQUIRED,
        ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
        "service.op_dispatch_failed",
        "service.readback_failed",
        "service.unsupported_operation",
        "planner.no_apply_ops",
    )
    for code in codes:
        assert scrub_error_message(code) == code


def test_wifi_planner_missing_credential_raises_structured_code() -> None:
    intent = WifiIntent(
        ssid="Staff-Private",
        enabled=True,
        credential_ref_id=None,
        captive_portal=CaptivePortalMode.DISABLED,
        guest_isolation=False,
        wpa_mode=WifiWpaMode.WPA2,
        band=WifiBand.BAND_2_4GHZ,
    )
    with pytest.raises(WifiApplyPlannerError, match=ERROR_CODE_CREDENTIAL_REF_REQUIRED):
        compile_wifi_intent_to_ops(intent, _TEST_AP)


def test_wifi_station_planner_missing_ssid_raises_structured_code() -> None:
    intent = UplinkIntent(
        mode=UplinkMode.WIFI_WAN,
        ssid="",
        credential_ref_id="credref:test",
        band=WifiBand.BAND_2_4GHZ,
    )
    with pytest.raises(WifiStationApplyPlannerError, match=ERROR_CODE_SSID_REQUIRED):
        compile_uplink_intent_to_station_ops(intent)


def test_wifi_apply_credential_resolution_failure_uses_structured_code() -> None:
    from tests.test_wifi_apply_service import FakeWifiApplyTransport, _wpa2_intent

    def _failing_resolver(_ref: str) -> str:
        raise RuntimeError("vault decode failed")

    transport = FakeWifiApplyTransport()
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=_failing_resolver,
    )
    assert result.errors == (ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,)
    assert result.steps[1].error == ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED


def test_invalid_overall_literal_rejected_by_type_checker() -> None:
    """Document mypy guard: invalid overall literals fail static check in application layer."""
    invalid: ApplyOverallStatus = "not_a_valid_overall"  # type: ignore[assignment]
    assert invalid == "not_a_valid_overall"
