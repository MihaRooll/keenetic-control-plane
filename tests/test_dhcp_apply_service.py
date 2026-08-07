"""Offline tests for DHCP apply service (preview + fail-closed apply)."""

from __future__ import annotations

from typing import Any

import pytest
from router_control.adapters.netcraze.dhcp_rci import DhcpRciOperation
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.application.dhcp_apply_service import (
    DhcpApplyServiceError,
    apply_dhcp_intent,
    preview_dhcp_apply,
    teardown_dhcp_pool,
)


def _dhcp_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "Guest",
        "pool_start": "10.10.0.100",
        "pool_end": "10.10.0.200",
        "lease_seconds": 86400,
        "reservations": [
            {"mac_address": "aa:bb:cc:00:00:01", "ipv4_address": "10.10.0.50"},
        ],
    }
    base.update(overrides)
    return base


def _ok_envelope(ident: str = "Core::Dhcp") -> list[dict[str, Any]]:
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


class FakeDhcpApplyTransport:
    dhcp_offline_only = True

    def __init__(self, *, write_response: Any | None = None) -> None:
        self.write_response = _ok_envelope() if write_response is None else write_response
        self.write_calls: list[SealedRciWriteRequest] = []

    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        self.write_calls.append(request)
        return self.write_response


class UnmarkedTransport:
    def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
        raise AssertionError("execute_sealed_rci_write must not be called without offline marker")


class FalseMarkerTransport(UnmarkedTransport):
    dhcp_offline_only = False


def _error_envelope() -> list[dict[str, Any]]:
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


def test_preview_dhcp_apply_is_deterministic() -> None:
    intent = _dhcp_intent()
    preview_a = preview_dhcp_apply(intent)
    preview_b = preview_dhcp_apply(intent)
    assert preview_a == preview_b
    assert preview_a["zone_id"] == "Guest"
    assert preview_a["verification_status"] == "offline_unverified"
    assert [op["operation"] for op in preview_a["apply_ops"]] == [
        DhcpRciOperation.SET_POOL.value,
        DhcpRciOperation.SET_LEASE.value,
        DhcpRciOperation.BIND_HOST.value,
    ]


def test_apply_without_transport_is_fail_closed() -> None:
    with pytest.raises(DhcpApplyServiceError, match="live DHCP apply dispatch is disabled"):
        apply_dhcp_intent(intent=_dhcp_intent(), transport=None)


def test_teardown_without_transport_is_fail_closed() -> None:
    with pytest.raises(DhcpApplyServiceError, match="live DHCP apply dispatch is disabled"):
        teardown_dhcp_pool(intent=_dhcp_intent(), transport=None)


def test_apply_with_fake_transport_dispatches_sealed_ops() -> None:
    transport = FakeDhcpApplyTransport()
    result = apply_dhcp_intent(intent=_dhcp_intent(), transport=transport)
    assert result.overall == "dispatched_offline"
    assert result.verification_status == "offline_unverified"
    assert len(result.steps) == 3
    assert all(step.ok for step in result.steps)
    assert len(transport.write_calls) == 3


def test_teardown_with_fake_transport_dispatches_teardown_ops() -> None:
    transport = FakeDhcpApplyTransport()
    result = teardown_dhcp_pool(intent=_dhcp_intent(), transport=transport)
    assert result.overall == "dispatched_offline"
    assert len(result.steps) == 2
    assert len(transport.write_calls) == 2


@pytest.mark.parametrize(
    "transport",
    [UnmarkedTransport(), FalseMarkerTransport()],
)
def test_apply_rejects_transport_without_offline_marker(transport: object) -> None:
    with pytest.raises(DhcpApplyServiceError, match="live DHCP apply dispatch is disabled"):
        apply_dhcp_intent(intent=_dhcp_intent(), transport=transport)


def test_teardown_rejects_transport_without_offline_marker() -> None:
    with pytest.raises(DhcpApplyServiceError, match="live DHCP apply dispatch is disabled"):
        teardown_dhcp_pool(
            intent=_dhcp_intent(),
            transport=UnmarkedTransport(),
        )


def test_apply_fail_closed_on_error_ack() -> None:
    transport = FakeDhcpApplyTransport(write_response=_error_envelope())
    result = apply_dhcp_intent(intent=_dhcp_intent(), transport=transport)
    assert result.overall == "failed"
    assert len(result.steps) == 1
    assert result.steps[0].ok is False
    assert result.errors == ("service.op_dispatch_failed",)
