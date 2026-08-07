"""Offline tests for sealed DNS RCI module."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.dns_rci import (
    DnsRciError,
    DnsRciOperation,
    command_for,
    sealed_request_for,
    validate_local_fqdn,
    validate_upstream_resolver,
    validate_zone_id,
    verify_dns_response,
)
from router_control.adapters.netcraze.rci_validation import RciValidationError


def _ok_envelope() -> list[dict[str, object]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "1",
                        "ident": "Core::Dns",
                        "message": "ok",
                    }
                ],
            }
        }
    ]


def _error_envelope() -> list[dict[str, object]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "error",
                        "code": "1",
                        "ident": "Core::Dns",
                        "message": "failed",
                    }
                ],
            }
        }
    ]


@pytest.mark.parametrize(
    ("operation", "zone_id", "kwargs", "expected_cli"),
    [
        (
            DnsRciOperation.SET_STATIC_HOST,
            "Guest",
            {"local_fqdn": "order.guest.example.com"},
            "ip host order.guest.example.com",
        ),
        (
            DnsRciOperation.CLEAR_STATIC_HOST,
            "Guest",
            {"local_fqdn": "order.guest.example.com"},
            "no ip host order.guest.example.com",
        ),
        (
            DnsRciOperation.SET_UPSTREAM,
            "Guest",
            {"upstream_resolver": "8.8.8.8"},
            "ip name-server 8.8.8.8",
        ),
        (
            DnsRciOperation.CLEAR_UPSTREAM,
            "Guest",
            {"upstream_resolver": "8.8.8.8"},
            "no ip name-server 8.8.8.8",
        ),
    ],
)
def test_command_for_allowlisted_cli(
    operation: DnsRciOperation,
    zone_id: str,
    kwargs: dict[str, object],
    expected_cli: str,
) -> None:
    assert command_for(operation, zone_id, **kwargs) == expected_cli


def test_validate_zone_id_rejects_empty() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_zone_id("")
    assert exc_info.value.field == "zone_id"


def test_validate_local_fqdn_normalizes() -> None:
    assert validate_local_fqdn("Order.Guest.Example.COM.") == "order.guest.example.com"


def test_validate_local_fqdn_rejects_invalid() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_local_fqdn("not-valid")
    assert exc_info.value.field == "local_fqdn"


def test_validate_upstream_resolver_rejects_invalid() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_upstream_resolver("999.1.1.1")
    assert exc_info.value.field == "upstream_resolver"


def test_sealed_request_for_shape() -> None:
    request = sealed_request_for(
        DnsRciOperation.SET_UPSTREAM,
        "Guest",
        upstream_resolver="8.8.8.8",
    )
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [{"parse": "ip name-server 8.8.8.8"}]
    assert request.body == build_sealed_parse_body("ip name-server 8.8.8.8")


@pytest.mark.parametrize(
    "operation",
    [
        DnsRciOperation.SET_STATIC_HOST,
        DnsRciOperation.SET_UPSTREAM,
    ],
)
def test_verify_dns_response_accepts_good_ack(operation: DnsRciOperation) -> None:
    kwargs: dict[str, object] = {}
    if operation is DnsRciOperation.SET_STATIC_HOST:
        kwargs = {"local_fqdn": "order.guest.example.com"}
    if operation is DnsRciOperation.SET_UPSTREAM:
        kwargs = {"upstream_resolver": "8.8.8.8"}
    result = verify_dns_response(operation, "Guest", _ok_envelope(), **kwargs)
    sanitized = result.sanitized_dict()
    assert sanitized["zone_id"] == "Guest"
    assert sanitized["ack_matched"] is True


def test_verify_dns_response_rejects_error_status() -> None:
    with pytest.raises(DnsRciError, match="error status"):
        verify_dns_response(
            DnsRciOperation.CLEAR_STATIC_HOST,
            "Guest",
            _error_envelope(),
            local_fqdn="order.guest.example.com",
        )


def test_verify_dns_response_rejects_missing_status() -> None:
    with pytest.raises(DnsRciError, match="no RCI parse status"):
        verify_dns_response(
            DnsRciOperation.CLEAR_UPSTREAM,
            "Guest",
            [{"parse": {"prompt": "(config)"}}],
            upstream_resolver="8.8.8.8",
        )


def test_command_for_set_static_host_requires_fqdn() -> None:
    with pytest.raises(DnsRciError, match="local_fqdn is required"):
        command_for(DnsRciOperation.SET_STATIC_HOST, "Guest")
