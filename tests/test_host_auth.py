"""Unit tests for hub_admin auth helpers."""

from __future__ import annotations

import hashlib
import hmac

import pytest
from router_control_host.auth import (
    HUB_ADMIN_COOKIE_NAME,
    LOGIN_THROTTLE_MAX_FAILURES,
    AuthFailureClass,
    LoginThrottle,
    auth_gate,
    auth_now_unix,
    classify_hub_admin_cookie,
    classify_login_submit_failure,
    classify_request_provenance,
    hub_admin_password,
    mint_hub_admin_cookie,
    parse_public_base_url,
    session_signing_key,
    session_ttl_seconds,
    set_auth_clock_for_tests,
    set_login_throttle_for_tests,
    validate_host_authority,
    validate_hub_admin_cookie,
    validate_standalone_authority,
    verify_hub_admin_password,
)


@pytest.fixture(autouse=True)
def _reset_auth_clock() -> None:
    set_auth_clock_for_tests(None)
    set_login_throttle_for_tests(None)


def test_verify_hub_admin_password_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "secret-operator-password")
    assert verify_hub_admin_password("secret-operator-password") is True


def test_verify_hub_admin_password_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "secret-operator-password")
    assert verify_hub_admin_password("wrong-password") is False


def test_verify_hub_admin_password_empty_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    assert verify_hub_admin_password("anything") is False


def test_verify_strips_outer_whitespace_on_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "  padded-password  ")
    assert verify_hub_admin_password("  padded-password  ") is True
    assert verify_hub_admin_password("padded-password") is True


def test_verify_preserves_internal_spaces(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "  hello world  ")
    assert verify_hub_admin_password("  hello world  ") is True
    assert verify_hub_admin_password("hello world") is True


def test_auth_gate_order(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    decision = auth_gate(None)
    assert decision.status_code == 503
    assert decision.code == "security.configuration_blocked"

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "gate-order-password")
    decision = auth_gate(None)
    assert decision.status_code == 401
    assert decision.code == "auth.required"

    token = mint_hub_admin_cookie()
    decision = auth_gate(token)
    assert decision.status_code is None


def test_auth_gate_bypass_allowed_kwarg_skips_empty_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "")
    decision = auth_gate(None, bypass_allowed=True)
    assert decision.status_code is None


def test_cookie_name_constant() -> None:
    assert HUB_ADMIN_COOKIE_NAME == "hub_admin"


def test_token_v2_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "shape-test-password")
    fixed_now = 1_700_000_000
    set_auth_clock_for_tests(lambda: fixed_now)
    token = mint_hub_admin_cookie()
    payload, sig = token.rsplit(".", 1)
    assert payload.startswith("hub_admin:v2|")
    assert sig
    parts = payload.split("|")
    assert len(parts) == 4
    assert int(parts[1]) == fixed_now
    assert int(parts[2]) == fixed_now + session_ttl_seconds()
    assert len(parts[3]) == 32


def test_plan_session_binding_from_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    from router_control_host.auth import plan_session_binding_hmac, session_binding_from_cookie

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "binding-test-password")
    token = mint_hub_admin_cookie()
    sid = token.split("|")[3].split(".")[0]
    binding = session_binding_from_cookie(token)
    assert binding == plan_session_binding_hmac(sid)


def test_validate_rejects_tampered_cookie(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "tamper-test-password")
    token = mint_hub_admin_cookie()
    assert validate_hub_admin_cookie(token) is True
    assert validate_hub_admin_cookie(token + "x") is False
    assert classify_hub_admin_cookie(token + "x") == AuthFailureClass.INVALID_SIGNATURE


def test_hub_admin_password_strips_whitespace(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "  padded-password  ")
    assert hub_admin_password() == "padded-password"
    assert verify_hub_admin_password("padded-password") is True


def test_classify_missing_and_malformed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "classify-password")
    assert classify_hub_admin_cookie(None) == AuthFailureClass.MISSING_TOKEN
    assert classify_hub_admin_cookie("") == AuthFailureClass.MISSING_TOKEN
    assert classify_hub_admin_cookie("not-a-token") == AuthFailureClass.MALFORMED_TOKEN
    assert classify_hub_admin_cookie("hub_admin:v1|1|2.sig") == AuthFailureClass.MALFORMED_TOKEN


def test_classify_expired_and_future_iat(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "time-password")
    now = 1_700_000_000
    set_auth_clock_for_tests(lambda: now)
    ttl = session_ttl_seconds()
    token = mint_hub_admin_cookie(now=now - ttl - 1)
    assert classify_hub_admin_cookie(token) == AuthFailureClass.EXPIRED

    future_token = mint_hub_admin_cookie(now=now + 120)
    assert classify_hub_admin_cookie(future_token) == AuthFailureClass.NOT_YET_VALID


def test_classify_invalid_timestamps(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "ts-password")
    now = 1_700_000_000
    set_auth_clock_for_tests(lambda: now)
    bad = mint_hub_admin_cookie(now=now)
    payload = bad.rsplit(".", 1)[0]
    tampered = payload.replace(f"|{now + session_ttl_seconds()}", f"|{now}") + ".deadbeef"
    assert classify_hub_admin_cookie(tampered) == AuthFailureClass.INVALID_TIMESTAMPS


def test_session_secret_overrides_password_derivation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "pwd-for-secret-test")
    monkeypatch.setenv("HUB_ADMIN_SESSION_SECRET", "explicit-session-secret")
    assert session_signing_key() == "explicit-session-secret"
    token = mint_hub_admin_cookie()
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "other-password")
    assert validate_hub_admin_cookie(token) is True


def test_password_derived_signing_key_domain_separated(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("HUB_ADMIN_SESSION_SECRET", raising=False)
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "derive-key-password")
    pwd = hub_admin_password()
    expected = hmac.new(
        pwd.encode("utf-8"),
        b"rc-proto-session:v1",
        hashlib.sha256,
    ).hexdigest()
    assert session_signing_key() == expected


def test_classify_login_submit_failure_helper() -> None:
    assert (
        classify_login_submit_failure(
            password_configured=False,
            same_origin=True,
            password_valid=True,
        )
        == AuthFailureClass.CONFIGURATION_BLOCKED
    )
    assert (
        classify_login_submit_failure(
            password_configured=True,
            same_origin=False,
            password_valid=True,
        )
        == AuthFailureClass.ORIGIN_REJECTED
    )
    assert (
        classify_login_submit_failure(
            password_configured=True,
            same_origin=True,
            password_valid=False,
        )
        == AuthFailureClass.CREDENTIALS_REJECTED
    )
    assert (
        classify_login_submit_failure(
            password_configured=True,
            same_origin=True,
            password_valid=True,
        )
        is None
    )


def test_auth_now_unix_uses_injected_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    set_auth_clock_for_tests(lambda: 42)
    assert auth_now_unix() == 42


def _fm_kwargs(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "origin": None,
        "origin_count": 0,
        "referer": None,
        "referer_count": 0,
        "method": "POST",
        "expected_origin": "http://127.0.0.1:8787",
        "request_hostname": "127.0.0.1",
        "sec_fetch_site": "same-origin",
        "sec_fetch_site_count": 1,
        "sec_fetch_mode": "navigate",
        "sec_fetch_mode_count": 1,
        "sec_fetch_dest": "document",
        "sec_fetch_dest_count": 1,
    }
    base.update(overrides)
    if base.get("origin") is not None and "origin_count" not in overrides:
        base["origin_count"] = 1
    return base


def test_classify_request_provenance_origin_exact_match() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(origin="http://127.0.0.1:8787"),
        )
        is True
    )


def test_classify_request_provenance_origin_mismatch_overrides_fm() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(origin="http://evil.example"),
        )
        is False
    )


def test_classify_request_provenance_empty_origin_header_rejects() -> None:
    assert classify_request_provenance(**_fm_kwargs(origin="")) is False


def test_classify_request_provenance_referer_fallback() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(referer="http://127.0.0.1:8787/login"),
        )
        is True
    )


def test_classify_request_provenance_referer_mismatch_rejects_without_fm() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                referer="http://evil.example/login",
                sec_fetch_site="same-origin",
            ),
        )
        is False
    )


def test_classify_request_provenance_fm_loopback_success() -> None:
    assert classify_request_provenance(**_fm_kwargs()) is True


@pytest.mark.parametrize("hostname", ["127.0.0.1", "localhost", "::1", "LOCALHOST"])
def test_classify_request_provenance_fm_accepts_loopback_hostnames(hostname: str) -> None:
    expected = f"http://{hostname}:8787" if hostname != "::1" else "http://[::1]:8787"
    host = hostname.lower() if hostname != "::1" else "::1"
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                expected_origin=expected,
                request_hostname=host,
            ),
        )
        is True
    )


@pytest.mark.parametrize(
    "sec_fetch_site",
    ["cross-site", "same-site", "none", "", "SAME-ORIGIN", None],
)
def test_classify_request_provenance_fm_rejects_bad_fetch_site(sec_fetch_site: str | None) -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(sec_fetch_site=sec_fetch_site),
        )
        is False
    )


@pytest.mark.parametrize(
    ("sec_fetch_mode", "sec_fetch_dest"),
    [
        ("cors", "document"),
        ("navigate", "empty"),
        (None, "document"),
        ("navigate", None),
    ],
)
def test_classify_request_provenance_fm_rejects_bad_mode_or_dest(
    sec_fetch_mode: str | None,
    sec_fetch_dest: str | None,
) -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                sec_fetch_mode=sec_fetch_mode,
                sec_fetch_dest=sec_fetch_dest,
            ),
        )
        is False
    )


def test_classify_request_provenance_fm_rejects_non_post() -> None:
    assert classify_request_provenance(**_fm_kwargs(method="GET")) is False


def test_classify_request_provenance_fm_rejects_non_loopback_host() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                expected_origin="http://testserver",
                request_hostname="testserver",
            ),
        )
        is False
    )


def test_parse_public_base_url_accepts_loopback_with_port() -> None:
    cfg = parse_public_base_url("http://127.0.0.1:8787")
    assert cfg.expected_origin == "http://127.0.0.1:8787"
    assert cfg.expected_host == "127.0.0.1:8787"
    assert cfg.port == 8787


@pytest.mark.parametrize(
    "url",
    [
        "https://127.0.0.1:8787",
        "http://127.0.0.1:8787/path",
        "http://127.0.0.1:8787?x=1",
        "http://user:pass@127.0.0.1:8787",
        "http://127.0.0.1",
        "http://192.168.1.1:8787",
    ],
)
def test_parse_public_base_url_rejects_invalid(url: str) -> None:
    with pytest.raises(ValueError):
        parse_public_base_url(url)


def test_classify_request_provenance_origin_null_accepts_when_allowed() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                origin="null",
                origin_count=1,
                allow_null_origin=True,
            ),
        )
        is True
    )


@pytest.mark.parametrize("origin", ["Null", "NULL", " null"])
def test_classify_request_provenance_origin_null_case_sensitive(origin: str) -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                origin=origin,
                origin_count=1,
                allow_null_origin=True,
            ),
        )
        is False
    )


def test_classify_request_provenance_origin_null_rejects_with_referer() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                origin="null",
                origin_count=1,
                referer="http://127.0.0.1:8787/login",
                referer_count=1,
                allow_null_origin=True,
            ),
        )
        is False
    )


def test_classify_request_provenance_rejects_duplicate_origin() -> None:
    assert (
        classify_request_provenance(
            **_fm_kwargs(
                origin="http://127.0.0.1:8787",
                origin_count=2,
            ),
        )
        is False
    )


def test_validate_host_authority_exact_match() -> None:
    assert validate_host_authority(
        host_values=["127.0.0.1:8787"],
        expected_host="127.0.0.1:8787",
    )


def test_validate_host_authority_rejects_alias() -> None:
    assert not validate_host_authority(
        host_values=["localhost:8787"],
        expected_host="127.0.0.1:8787",
    )


def test_validate_host_authority_accepts_ipv6_bracketed_with_port() -> None:
    assert validate_host_authority(
        host_values=["[::1]:8787"],
        expected_host="[::1]:8787",
    )


@pytest.mark.parametrize(
    "host_value",
    ["[::1", "[::1]:", "[::1]:abc", "[::1]extra", "[[::1]:8787"],
)
def test_validate_host_authority_rejects_malformed_ipv6_bracket(host_value: str) -> None:
    assert not validate_host_authority(
        host_values=[host_value],
        expected_host=host_value,
    )


def test_validate_standalone_authority_accepts_ipv6_loopback() -> None:
    assert validate_standalone_authority(
        host_values=["[::1]:8787"],
        expected_host="[::1]:8787",
        server=("::1", 8787),
        expected_port=8787,
        headers={"host": "[::1]:8787"},
    )


def test_validate_standalone_authority_rejects_ipv6_host_mismatch() -> None:
    assert not validate_standalone_authority(
        host_values=["127.0.0.1:8787"],
        expected_host="[::1]:8787",
        server=("::1", 8787),
        expected_port=8787,
        headers={"host": "127.0.0.1:8787"},
    )


def test_validate_standalone_authority_rejects_forwarded_headers() -> None:
    assert not validate_standalone_authority(
        host_values=["127.0.0.1:8787"],
        expected_host="127.0.0.1:8787",
        server=("127.0.0.1", 8787),
        expected_port=8787,
        headers={"X-Forwarded-Host": "evil.example", "host": "127.0.0.1:8787"},
    )


def test_login_throttle_window() -> None:
    clock = {"now": 100.0}
    throttle = LoginThrottle(clock=lambda: clock["now"])
    for _ in range(LOGIN_THROTTLE_MAX_FAILURES):
        throttle.record_failure()
    assert throttle.is_blocked()
    clock["now"] += 61.0
    assert not throttle.is_blocked()
