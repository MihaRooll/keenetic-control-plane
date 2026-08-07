"""Offline tests for sealed DHCP RCI module."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.allowlist import build_sealed_parse_body
from router_control.adapters.netcraze.dhcp_rci import (
    DhcpRciError,
    DhcpRciOperation,
    command_for,
    sealed_request_for,
    validate_ipv4_address,
    validate_lease_seconds,
    validate_mac_address,
    validate_zone_id,
    verify_dhcp_response,
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
                        "ident": "Core::Dhcp",
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
                        "ident": "Core::Dhcp",
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
            DhcpRciOperation.SET_POOL,
            "Guest",
            {"pool_start": "10.10.0.100", "pool_end": "10.10.0.200"},
            "ip dhcp pool Guest 10.10.0.100 10.10.0.200",
        ),
        (
            DhcpRciOperation.CLEAR_POOL,
            "Guest",
            {},
            "no ip dhcp pool Guest",
        ),
        (
            DhcpRciOperation.SET_LEASE,
            "Guest",
            {"lease_seconds": 86400},
            "ip dhcp pool Guest lease 86400",
        ),
        (
            DhcpRciOperation.BIND_HOST,
            "Guest",
            {"mac_address": "aa:bb:cc:00:00:01", "ipv4_address": "10.10.0.50"},
            "ip dhcp host aa:bb:cc:00:00:01 10.10.0.50",
        ),
        (
            DhcpRciOperation.UNBIND_HOST,
            "Guest",
            {"mac_address": "aa:bb:cc:00:00:01"},
            "no ip dhcp host aa:bb:cc:00:00:01",
        ),
    ],
)
def test_command_for_allowlisted_cli(
    operation: DhcpRciOperation,
    zone_id: str,
    kwargs: dict[str, object],
    expected_cli: str,
) -> None:
    assert command_for(operation, zone_id, **kwargs) == expected_cli


def test_validate_zone_id_rejects_empty() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_zone_id("")
    assert exc_info.value.field == "zone_id"


def test_validate_zone_id_accepts_bounded() -> None:
    assert validate_zone_id("  Guest  ") == "Guest"


def test_validate_ipv4_address_rejects_invalid() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_ipv4_address("999.1.1.1")
    assert exc_info.value.field == "ipv4_address"


@pytest.mark.parametrize("lease", [59, 604801, "86400"])
def test_validate_lease_seconds_rejects_out_of_range(lease: object) -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_lease_seconds(lease)  # type: ignore[arg-type]
    assert exc_info.value.field == "lease_seconds"


def test_validate_mac_address_accepts_fake() -> None:
    assert validate_mac_address("AA:BB:CC:00:00:01") == "aa:bb:cc:00:00:01"


def test_validate_mac_address_rejects_invalid() -> None:
    with pytest.raises(RciValidationError) as exc_info:
        validate_mac_address("not-a-mac")
    assert exc_info.value.field == "mac_address"


def test_sealed_request_for_shape() -> None:
    request = sealed_request_for(
        DhcpRciOperation.SET_POOL,
        "Guest",
        pool_start="10.10.0.100",
        pool_end="10.10.0.200",
    )
    payload = json.loads(request.body.decode("utf-8"))
    assert payload == [{"parse": "ip dhcp pool Guest 10.10.0.100 10.10.0.200"}]
    assert request.body == build_sealed_parse_body(
        "ip dhcp pool Guest 10.10.0.100 10.10.0.200"
    )


@pytest.mark.parametrize(
    "operation",
    [
        DhcpRciOperation.SET_POOL,
        DhcpRciOperation.SET_LEASE,
        DhcpRciOperation.BIND_HOST,
    ],
)
def test_verify_dhcp_response_accepts_good_ack(operation: DhcpRciOperation) -> None:
    kwargs: dict[str, object] = {}
    if operation is DhcpRciOperation.SET_POOL:
        kwargs = {"pool_start": "10.10.0.100", "pool_end": "10.10.0.200"}
    if operation is DhcpRciOperation.SET_LEASE:
        kwargs = {"lease_seconds": 86400}
    if operation is DhcpRciOperation.BIND_HOST:
        kwargs = {"mac_address": "aa:bb:cc:00:00:01", "ipv4_address": "10.10.0.50"}
    result = verify_dhcp_response(operation, "Guest", _ok_envelope(), **kwargs)
    sanitized = result.sanitized_dict()
    assert sanitized["zone_id"] == "Guest"
    assert sanitized["ack_matched"] is True


def test_verify_dhcp_response_rejects_error_status() -> None:
    with pytest.raises(DhcpRciError, match="error status"):
        verify_dhcp_response(DhcpRciOperation.CLEAR_POOL, "Guest", _error_envelope())


def test_verify_dhcp_response_rejects_missing_status() -> None:
    with pytest.raises(DhcpRciError, match="no RCI parse status"):
        verify_dhcp_response(
            DhcpRciOperation.CLEAR_POOL, "Guest", [{"parse": {"prompt": "(config)"}}]
        )


def test_command_for_set_pool_requires_start_and_end() -> None:
    with pytest.raises(DhcpRciError, match="pool_start and pool_end"):
        command_for(DhcpRciOperation.SET_POOL, "Guest")
