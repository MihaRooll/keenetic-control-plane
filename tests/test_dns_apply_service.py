"""Offline tests for DNS apply service (preview + fail-closed apply)."""

from __future__ import annotations

from typing import Any

import pytest
from router_control.adapters.netcraze.dns_rci import DnsRciOperation
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.application.dns_apply_service import (
    DnsApplyServiceError,
    apply_dns_intent,
    preview_dns_apply,
    teardown_dns_config,
)


def _dns_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "Guest",
        "local_fqdn": "order.guest.example.com",
        "upstream_resolvers": ["8.8.8.8"],
    }
    base.update(overrides)
    return base


def _ok_envelope(ident: str = "Core::Dns") -> list[dict[str, Any]]:
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


class FakeDnsApplyTransport:
    dns_offline_only = True

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
    dns_offline_only = False


def _error_envelope() -> list[dict[str, Any]]:
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


def test_preview_dns_apply_is_deterministic() -> None:
    intent = _dns_intent()
    preview_a = preview_dns_apply(intent)
    preview_b = preview_dns_apply(intent)
    assert preview_a == preview_b
    assert preview_a["zone_id"] == "Guest"
    assert preview_a["verification_status"] == "offline_unverified"
    assert [op["operation"] for op in preview_a["apply_ops"]] == [
        DnsRciOperation.SET_STATIC_HOST.value,
        DnsRciOperation.SET_UPSTREAM.value,
    ]


def test_apply_without_transport_is_fail_closed() -> None:
    with pytest.raises(DnsApplyServiceError, match="live DNS apply dispatch is disabled"):
        apply_dns_intent(intent=_dns_intent(), transport=None)


def test_teardown_without_transport_is_fail_closed() -> None:
    with pytest.raises(DnsApplyServiceError, match="live DNS apply dispatch is disabled"):
        teardown_dns_config(intent=_dns_intent(), transport=None)


def test_apply_with_fake_transport_dispatches_sealed_ops() -> None:
    transport = FakeDnsApplyTransport()
    result = apply_dns_intent(intent=_dns_intent(), transport=transport)
    assert result.overall == "dispatched_offline"
    assert result.verification_status == "offline_unverified"
    assert len(result.steps) == 2
    assert all(step.ok for step in result.steps)
    assert len(transport.write_calls) == 2


def test_teardown_with_fake_transport_dispatches_teardown_ops() -> None:
    transport = FakeDnsApplyTransport()
    result = teardown_dns_config(intent=_dns_intent(), transport=transport)
    assert result.overall == "dispatched_offline"
    assert len(result.steps) == 2
    assert len(transport.write_calls) == 2


@pytest.mark.parametrize(
    "transport",
    [UnmarkedTransport(), FalseMarkerTransport()],
)
def test_apply_rejects_transport_without_offline_marker(transport: object) -> None:
    with pytest.raises(DnsApplyServiceError, match="live DNS apply dispatch is disabled"):
        apply_dns_intent(intent=_dns_intent(), transport=transport)


def test_teardown_rejects_transport_without_offline_marker() -> None:
    with pytest.raises(DnsApplyServiceError, match="live DNS apply dispatch is disabled"):
        teardown_dns_config(
            intent=_dns_intent(),
            transport=UnmarkedTransport(),
        )


def test_apply_fail_closed_on_error_ack() -> None:
    transport = FakeDnsApplyTransport(write_response=_error_envelope())
    result = apply_dns_intent(intent=_dns_intent(), transport=transport)
    assert result.overall == "failed"
    assert len(result.steps) == 1
    assert result.steps[0].ok is False
    assert result.errors == ("service.op_dispatch_failed",)
