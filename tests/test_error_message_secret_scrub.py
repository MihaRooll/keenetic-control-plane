"""Fail-closed secret indicator detection for error/audit messages."""

from __future__ import annotations

import json
from urllib.parse import quote

import pytest
from router_control.application.wifi_observation_helpers import (
    _ERROR_MESSAGE_REDACTED,
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    ERROR_CODE_SSID_REQUIRED,
    error_message_contains_secret_indicator,
    scrub_error_message,
)
from router_control.persistence.store import (
    build_sealed_apply_audit_summary,
    redact_sealed_apply_audit_error_message,
)
from router_control_host.errors import (
    build_validation_error_details,
    error_body,
    error_response,
    sealed_apply_trail_begin_error_response,
)
from starlette.requests import Request

_MARKER = "MARKER-SECRET-SCRUB-CANARY"
_EXCEPTION_ECHO_MARKER = "MARKER-EXCEPTION-ECHO-MUST-NOT-LEAK-98765"
_LONG_ENTROPY = "MARKER-STRUCTURAL-BYPASS-AAAAbbbbCCCCddddEEEEffff"


def _assert_fully_redacted(raw: str, *, marker: str = _MARKER) -> None:
    scrubbed = scrub_error_message(raw)
    assert marker not in scrubbed
    assert scrubbed == _ERROR_MESSAGE_REDACTED
    assert error_message_contains_secret_indicator(raw)


@pytest.mark.parametrize(
    ("raw", "id"),
    [
        (f"Authorization: Bearer {_MARKER}-AUTH-TOKEN-VALUE", "authorization_bearer"),
        (f"passwd={_MARKER}", "passwd_field"),
        (f"pass\nword={_MARKER}", "pass_newline_word"),
        (f"пароль={_MARKER}", "cyrillic_password_field"),
        (
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n{_MARKER}\n-----END OPENSSH PRIVATE KEY-----",
            "pem_private_key_block",
        ),
        (f"psk%253D{quote(_MARKER, safe='')}", "double_url_encoded_psk"),
        (f"orphan-field-name {_LONG_ENTROPY}", "structural_high_entropy_no_lexicon"),
        (f"unexpected failure {_LONG_ENTROPY} trailing", "structural_high_entropy_embedded"),
    ],
)
def test_f1_review_bypass_forms_fully_redacted(raw: str, id: str) -> None:
    marker = _LONG_ENTROPY if id.startswith("structural_high_entropy") else _MARKER
    _assert_fully_redacted(raw, marker=marker)


@pytest.mark.parametrize(
    ("raw",),
    [
        (f"private_key={_MARKER}-WG-PRIVKEY-aaaa",),
        (json.dumps({"psk": f"{_MARKER}-PSK-abc123XYZ"}),),
        (f"SSH password is {_MARKER}-SSH-PASSWORD-cccc",),
        (f"password\t{_MARKER}-SSH-PASSWORD-cccc",),
        (f"key={_MARKER}-PSK-abc123XYZ",),
        (f"passphrase'{_MARKER}-PSK-abc123XYZ'",),
        (f"ssid={_MARKER}-UPSTREAM-SSID-dddd",),
        (json.dumps({"nested": {"psk": f"{_MARKER}-NESTED"}}),),
        (f"wireguard private-key {_MARKER}-WG-KEY-B64",),
        (f"preshared-key {_MARKER}-WG-PSK",),
        (f"authentication wpa-psk {_MARKER}-WPA-PSK",),
        (f"psk {_MARKER}-SPACE-DELIMITED",),
        (f"secret={_MARKER}-GENERIC",),
        (f"credential={_MARKER}-CRED",),
        (f"password%3D{_MARKER}-URL-ENCODED",),
        (f"%22psk%22%3A%22{_MARKER}-JSON-URL%22",),
        (
            f"private_key={_MARKER}-B64\n"
            "AAAAbbbbCCCCddddEEEEffffGGGGhhhhIIIIjjjjKKKKllll==",
        ),
        (f"duplicate psk={_MARKER}-ONE psk={_MARKER}-TWO",),
    ],
    ids=[
        "private_key_equals",
        "json_psk",
        "password_prose_is",
        "password_tab_delimited",
        "key_equals",
        "passphrase_quote",
        "ssid_equals",
        "nested_json_psk",
        "wireguard_private_key_space",
        "preshared_key_space",
        "auth_wpa_psk_space",
        "psk_space_delimited",
        "secret_equals",
        "credential_equals",
        "url_encoded_assignment",
        "url_encoded_json_key",
        "multiline_private_key_b64",
        "duplicate_psk_assignments",
    ],
)
def test_secret_forms_fully_redacted(raw: str) -> None:
    _assert_fully_redacted(raw)


def test_sealed_apply_audit_json_psk_fail_closed() -> None:
    raw = json.dumps({"psk": _MARKER})
    scrubbed = redact_sealed_apply_audit_error_message(raw)
    assert scrubbed == _ERROR_MESSAGE_REDACTED
    summary = build_sealed_apply_audit_summary(
        route="wifi",
        verb="apply",
        intent_redacted={"ap_id": "WifiMaster0/AccessPoint3"},
        error_message=raw,
    )
    assert _MARKER not in summary
    parsed = json.loads(summary)
    assert parsed["error_message"] == _ERROR_MESSAGE_REDACTED


@pytest.mark.parametrize(
    "message",
    [
        "RCI command failed: timeout waiting for response",
        "Device rejected configuration at step 3",
        "Interface WifiMaster0/AccessPoint3 not found",
        "Rollback checkpoint missing for run abc123",
        "Host key mismatch during SSH preflight",
        "invalid credential_ref_id: missing ref",
        "sealed_apply.trail_begin_failed",
        ERROR_CODE_CREDENTIAL_REF_REQUIRED,
        ERROR_CODE_SSID_REQUIRED,
        "enabled WPA2 Wi-Fi requires credential_ref_id",
        "credential resolution failed for credential_ref_id=cred_abc123",
        ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
        "Device rejected password length",
        "secret is required for SET_PRIVATE_KEY",
        "failed to resolve credential reference",
        "Host key SHA256:abcdEFGH1234+/= fingerprint mismatch",
        "correlation_id=req_a1b2c3d4e5f67890",
        "Plan digest sha256:deadbeefcafebabe repeated for audit only",
    ],
)
def test_non_secret_errors_pass_through_unchanged(message: str) -> None:
    assert scrub_error_message(message) == message
    assert not error_message_contains_secret_indicator(message)


def test_existing_scalar_assignment_still_redacted() -> None:
    token = "TEST-PLAINTEXT-PSK-LEAK-TOKEN"
    raw = f"authentication wpa-psk {token} failed"
    scrubbed = scrub_error_message(raw)
    assert token not in scrubbed
    assert scrubbed == _ERROR_MESSAGE_REDACTED


def test_url_encoded_psk_assignment_detected() -> None:
    encoded = f"psk%3D{quote(_MARKER, safe='')}"
    _assert_fully_redacted(encoded)


def _make_request() -> Request:
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "path": "/api/router-control/v1/wifi/apply",
        "headers": [],
        "query_string": b"",
        "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8787),
        "scheme": "http",
        "root_path": "",
    }
    request = Request(scope)
    request.state.request_id = "req_test_http_scrub"
    request.state.correlation_id = "corr_test_http_scrub"
    return request


def test_error_body_scrubs_secret_message() -> None:
    body = error_body(
        code="service.apply_failed",
        message=f"device rejected psk={_MARKER}",
        request_id="req_1",
        correlation_id="corr_1",
    )
    assert body["error"]["message"] == _ERROR_MESSAGE_REDACTED
    assert _MARKER not in json.dumps(body)


def test_error_body_scrubs_secret_details() -> None:
    body = error_body(
        code="service.apply_failed",
        message="apply failed",
        request_id="req_1",
        correlation_id="corr_1",
        details=[{"field": "note", "message": f"password is {_MARKER}"}],
    )
    assert body["error"]["details"][0]["message"] == _ERROR_MESSAGE_REDACTED


def test_error_body_scrubs_nested_secret_details() -> None:
    body = error_body(
        code="service.apply_failed",
        message="apply failed",
        request_id="req_1",
        correlation_id="corr_1",
        details=[{"nested": {"note": f"password is {_MARKER}"}}],
    )
    payload = json.dumps(body)
    assert _MARKER not in payload
    assert body["error"]["details"][0]["nested"]["note"] == _ERROR_MESSAGE_REDACTED


def test_f1_sha256_prefix_mask_does_not_hide_appended_secret() -> None:
    secret_tail = "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVv"
    raw = f"SHA256:{secret_tail}"
    scrubbed = scrub_error_message(raw)
    assert secret_tail not in scrubbed
    assert scrubbed == _ERROR_MESSAGE_REDACTED


def test_f1_module_path_mask_does_not_hide_appended_secret() -> None:
    secret_tail = "MARKER-MODULE-PATH-SUFFIX-SECRET-TOKEN-AAAAbbbb"
    raw = f"router_control/adapters/{secret_tail}"
    scrubbed = scrub_error_message(raw)
    assert secret_tail not in scrubbed
    assert scrubbed == _ERROR_MESSAGE_REDACTED


def test_f3_correlation_id_assignment_not_fully_redacted() -> None:
    message = "correlation_id=corr_" + ("a" * 40)
    assert scrub_error_message(message) == message
    assert not error_message_contains_secret_indicator(message)


def test_f3_request_digest_assignment_not_fully_redacted() -> None:
    message = "request_digest=" + ("deadbeef" * 8)
    assert scrub_error_message(message) == message
    assert not error_message_contains_secret_indicator(message)


def test_error_response_scrubs_exception_text() -> None:
    request = _make_request()
    response = error_response(
        request,
        status_code=500,
        code="service.internal_error",
        message=f"Authorization: Bearer {_MARKER}",
    )
    payload = json.loads(response.body)
    assert payload["error"]["message"] == _ERROR_MESSAGE_REDACTED


def test_sealed_apply_trail_begin_error_response_scrubs() -> None:
    """Synthesized template message: no scrub path; exception echo impossible by construction."""
    request = _make_request()
    exc = RuntimeError(f"passwd={_MARKER} diagnostic={_EXCEPTION_ECHO_MARKER}")
    response = sealed_apply_trail_begin_error_response(request, exc)
    assert response.status_code == 503
    payload = json.loads(response.body)
    assert payload["error"]["code"] == "sealed_apply.trail_begin_failed"
    blob = json.dumps(payload)
    assert _MARKER not in blob
    assert _EXCEPTION_ECHO_MARKER not in blob
    assert str(exc) not in blob


def test_build_validation_error_details_preserves_expected_ctx() -> None:
    errors = [
        {
            "type": "enum",
            "loc": ("body", "captive_portal"),
            "msg": "Input should be 'Disabled' or 'Enabled'",
            "input": "SuperSecretPSK-should-not-echo",
            "ctx": {"expected": "'Disabled' or 'Enabled'"},
        }
    ]
    message, details = build_validation_error_details(errors)
    assert "SuperSecretPSK-should-not-echo" not in message
    assert details[0]["ctx"]["expected"] == "'Disabled' or 'Enabled'"
    assert "input" not in json.dumps(details)


def test_build_validation_error_details_preserves_bounds_ctx() -> None:
    errors = [
        {
            "type": "greater_than_equal",
            "loc": ("body", "ip_global", "VpnPolicyIpGlobalPriorityBody", "priority"),
            "msg": "Input should be greater than or equal to 0",
            "input": -1,
            "ctx": {"ge": 0},
        }
    ]
    message, details = build_validation_error_details(errors)
    assert details[0]["ctx"] == {"ge": 0}
    assert "(expected >= 0)" in message
    assert "-1" not in message
    assert "input" not in json.dumps(details)


_REAL_DIAGNOSTIC_MESSAGES: tuple[str, ...] = (
    "RCI command failed: timeout waiting for response",
    "Device rejected configuration at step 3",
    "Interface WifiMaster0/AccessPoint3 not found",
    "Rollback checkpoint missing for run abc123",
    "Host key mismatch during SSH preflight",
    "invalid credential_ref_id: missing ref",
    "sealed_apply.trail_begin_failed",
    ERROR_CODE_CREDENTIAL_REF_REQUIRED,
    ERROR_CODE_SSID_REQUIRED,
    ERROR_CODE_CREDENTIAL_RESOLUTION_FAILED,
    "service.op_dispatch_failed",
    "service.readback_failed",
    "service.unsupported_operation",
    "planner.no_apply_ops",
    "enabled WPA2 Wi-Fi requires credential_ref_id",
    "credential resolution failed for credential_ref_id=cred_abc123",
    "Device rejected password length",
    "secret is required for SET_PRIVATE_KEY",
    "failed to resolve credential reference",
    "job not found",
    "plan expired",
    "plan stale: desired revision changed",
    "resource.not_found",
    "asc_args must contain exactly 9 integers for apply",
    "unsupported band: band_6ghz",
    "Interface WifiMaster0/AccessPoint3 not found on device",
    "Host key SHA256:abcdEFGH1234+/= fingerprint mismatch",
    f"private_key={_MARKER}",
    f"password is {_MARKER}",
    f"Authorization: Bearer {_MARKER}",
)


def test_quantitative_scrub_balance() -> None:
    scrubbed = [msg for msg in _REAL_DIAGNOSTIC_MESSAGES if scrub_error_message(msg) != msg]
    justified = {
        f"private_key={_MARKER}",
        f"password is {_MARKER}",
        f"Authorization: Bearer {_MARKER}",
    }
    assert set(scrubbed) == justified
    assert len(_REAL_DIAGNOSTIC_MESSAGES) - len(scrubbed) == len(_REAL_DIAGNOSTIC_MESSAGES) - 3
    assert len(scrubbed) == 3
    assert len(justified) == len(scrubbed)
