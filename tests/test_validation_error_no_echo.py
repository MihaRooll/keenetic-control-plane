"""HTTP 422 validation errors must not echo user-supplied values (Option E)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.errors import build_validation_error_details, validation_error_response
from router_control_host.vpn_policy_preview_routes import VpnPolicyPreviewBody

_CANARY = "SuperSecretPSK-should-not-echo"
_TEST_AP = "WifiMaster0/AccessPoint3"


def _intent_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
    }
    base.update(overrides)
    return base


def _assert_canary_absent(payload: object, *, canary: str = _CANARY) -> None:
    blob = json.dumps(payload)
    assert canary not in blob
    assert "input" not in blob


def _assert_structural_diagnostics(body: dict[str, object], *, field: str) -> None:
    error = body["error"]
    assert error["code"] == "request.validation_failed"
    details = error["details"]
    assert isinstance(details, list) and details
    detail_blob = json.dumps(details)
    assert field in detail_blob.lower()
    first = details[0]
    assert isinstance(first, dict)
    assert "type" in first or "ctx" in first


@pytest.fixture
def wifi_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "validation_no_echo.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_wifi_preview_422_extra_key_canary_absent_with_diagnostics(wifi_client) -> None:
    """Extra JSON key (extra=forbid) must not echo user-supplied key name in loc/message."""
    payload = _intent_payload()
    payload[_CANARY] = "anything"
    resp = wifi_client.post("/api/router-control/v1/wifi/preview", json=payload)
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    assert "detail" not in body
    error = body["error"]
    assert error["code"] == "request.validation_failed"
    assert _CANARY not in error["message"]
    assert "extra_forbidden" in error["message"]
    details = error["details"]
    assert isinstance(details, list) and details
    assert details[0]["type"] == "extra_forbidden"
    assert details[0]["loc"] == ["body", "[unrecognized_field]"]
    assert _CANARY not in json.dumps(details)


def test_build_validation_error_details_redacts_extra_forbidden_loc() -> None:
    errors = [
        {
            "type": "extra_forbidden",
            "loc": ("body", _CANARY),
            "msg": "Extra inputs are not permitted",
            "input": "anything",
        }
    ]
    message, details = build_validation_error_details(errors)
    blob = json.dumps({"message": message, "details": details})
    assert _CANARY not in blob
    assert "input" not in blob
    assert details[0]["type"] == "extra_forbidden"
    assert details[0]["loc"] == ["body", "[unrecognized_field]"]
    assert "Unrecognized field" in message
    assert "extra_forbidden" in message
    assert _CANARY not in message


@pytest.mark.parametrize(
    ("field_override", "field_name"),
    [
        ({"captive_portal": _CANARY}, "captive_portal"),
        ({"band": _CANARY}, "band"),
    ],
)
def test_wifi_preview_422_canary_absent_with_diagnostics(
    wifi_client,
    field_override: dict[str, object],
    field_name: str,
) -> None:
    resp = wifi_client.post(
        "/api/router-control/v1/wifi/preview",
        json=_intent_payload(**field_override),
    )
    assert resp.status_code == 422
    body = resp.json()
    _assert_canary_absent(body)
    assert "detail" not in body
    _assert_structural_diagnostics(body, field=field_name)


def test_build_validation_error_details_omits_input_and_raw_msg() -> None:
    errors = [
        {
            "type": "value_error",
            "loc": ("body", "captive_portal"),
            "msg": (
                f"Value error, captive_portal must be one of: Disabled, Enabled "
                f"(got {_CANARY!r})"
            ),
            "input": _CANARY,
        }
    ]
    message, details = build_validation_error_details(errors)
    blob = json.dumps({"message": message, "details": details})
    assert _CANARY not in blob
    assert "input" not in blob
    assert "got" not in message.lower()
    assert details[0]["loc"] == ["body", "captive_portal"]
    assert details[0]["type"] == "value_error"


def test_validation_error_response_not_fastapi_default_shape() -> None:
    errors = [
        {
            "type": "enum",
            "loc": ("body", "captive_portal"),
            "msg": f"Input should be 'Disabled' or 'Enabled' (got {_CANARY!r})",
            "input": _CANARY,
            "ctx": {"expected": "'Disabled' or 'Enabled'"},
        }
    ]
    exc = RequestValidationError(errors)
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/api/router-control/v1/wifi/preview",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8787),
        "scheme": "http",
        "root_path": "",
    }
    from starlette.requests import Request

    request = Request(scope)
    request.state.request_id = "req_validation_no_echo"
    request.state.correlation_id = "corr_validation_no_echo"

    custom = validation_error_response(request, exc)
    default = asyncio.run(request_validation_exception_handler(request, exc))
    custom_body = json.loads(custom.body)
    default_body = json.loads(default.body)

    assert "detail" in default_body
    assert any(item.get("input") == _CANARY for item in default_body["detail"])
    assert _CANARY in json.dumps(default_body)

    assert "error" in custom_body
    assert "detail" not in custom_body
    _assert_canary_absent(custom_body)
    _assert_structural_diagnostics(custom_body, field="captive_portal")
    assert custom_body["error"]["details"][0].get("ctx", {}).get("expected")


def test_red_green_default_handler_would_echo_canary() -> None:
    """Guard: FastAPI default 422 handler echoes input — our contract forbids that."""
    errors = [
        {
            "type": "value_error",
            "loc": ("body", "band"),
            "msg": f"band must be one of: BAND_2_4GHZ (got {_CANARY!r})",
            "input": _CANARY,
        }
    ]
    exc = RequestValidationError(errors)
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "path": "/",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 1),
        "server": ("127.0.0.1", 8787),
        "scheme": "http",
        "root_path": "",
    }
    from starlette.requests import Request

    request = Request(scope)
    default = asyncio.run(request_validation_exception_handler(request, exc))
    default_body = json.loads(default.body)
    assert _CANARY in json.dumps(default_body)


def test_host_app_registers_custom_validation_handler(tmp_path: Path) -> None:
    app = create_app(db_path=tmp_path / "handler_check.sqlite3", enable_worker=False)
    handler = app.exception_handlers.get(RequestValidationError)
    assert handler is not None
    assert handler.__name__ == "handle_request_validation_error"


def _ip_global_validation_errors(ip_global: object) -> list[dict[str, object]]:
    with pytest.raises(ValidationError) as exc_info:
        VpnPolicyPreviewBody.model_validate(
            {
                "policy_name": "test-policy",
                "vpn_interface": "Wireguard0",
                "ip_global": ip_global,
            }
        )
    return list(exc_info.value.errors())


def test_union_case_b_prefers_nested_constraint_field() -> None:
    errors = [
        {
            "type": "literal_error",
            "loc": ("body", "ip_global", "literal['auto']"),
            "msg": "Input should be 'auto'",
            "input": {"priority": -1},
            "ctx": {"expected": "'auto'"},
        },
        {
            "type": "greater_than_equal",
            "loc": ("body", "ip_global", "VpnPolicyIpGlobalPriorityBody", "priority"),
            "msg": "Input should be greater than or equal to 0",
            "input": -1,
            "ctx": {"ge": 0},
        },
        {
            "type": "missing",
            "loc": ("body", "ip_global", "VpnPolicyIpGlobalOrderBody", "order"),
            "msg": "Field required",
            "input": {"priority": -1},
        },
    ]
    message, details = build_validation_error_details(errors)
    assert "ip_global.priority" in message
    assert "greater_than_equal" in message
    assert "(expected >= 0)" in message
    assert "literal['auto']" not in message
    assert "-1" not in message
    assert "input" not in json.dumps({"message": message, "details": details})
    assert details[1]["ctx"] == {"ge": 0}


@pytest.mark.parametrize(
    "ip_global",
    [
        "not-auto",
        {"priority": 1, "order": 2},
        {"priority": 700, "extra": 1},
    ],
    ids=["scalar-not-auto", "both-keys", "hand-crafted-missing-extra"],
)
def test_union_case_c_forms_allowed_list(ip_global: object) -> None:
    errors = _ip_global_validation_errors(ip_global)
    message, details = build_validation_error_details(errors)
    assert "does not match any allowed form" in message
    assert "'auto'" in message
    assert "object with 'priority'" in message
    assert "object with 'order'" in message
    assert "extra" not in message
    assert "700" not in message
    assert "not-auto" not in message
    assert "foo" not in message
    assert details[0]["loc"][-1] == "literal['auto']"
    if ip_global == {"priority": 700, "extra": 1}:
        assert details[1]["loc"][-1] == "[unrecognized_field]"


def test_union_case_c_unknown_key_uses_model_introspection_not_user_key() -> None:
    errors = _ip_global_validation_errors({"foo": 1})
    message, details = build_validation_error_details(errors)
    assert "does not match any allowed form" in message
    assert "object with 'priority'" in message
    assert "object with 'order'" in message
    assert "foo" not in message
    assert all(
        detail.get("loc", [])[-1] != "foo"
        for detail in details
        if detail.get("type") == "extra_forbidden"
    )


def test_union_case_c_classname_key_does_not_pollute_allowed_forms() -> None:
    """User key matching a loaded BaseModel name must not expand parent body fields."""
    canary_key = "VpnPolicyPreviewBody"
    errors = _ip_global_validation_errors({canary_key: 1})
    message, details = build_validation_error_details(errors)
    assert "does not match any allowed form" in message
    assert "'auto'" in message
    assert "object with 'priority'" in message
    assert "object with 'order'" in message
    assert "policy_name" not in message
    assert "vpn_interface" not in message
    assert "name_servers" not in message
    assert canary_key not in message
    assert all(
        detail.get("loc", [])[-1] != canary_key
        for detail in details
        if detail.get("type") == "extra_forbidden"
    )
