"""Offline tests for VLAN apply service (preview + fail-closed apply)."""

from __future__ import annotations

from typing import Any

import pytest
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.vlan_rci import VlanRciOperation
from router_control.application.vlan_apply_service import (
    VlanApplyServiceError,
    apply_vlan_intent,
    preview_vlan_apply,
    teardown_vlan_bridge,
)

_TEST_BRIDGE = "Bridge3"
_PRODUCTION_BRIDGE = "Bridge0"


def _vlan_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "staff",
        "vlan_id": 20,
        "ipv4_cidr": "10.20.0.0/24",
        "ipv4_gateway": "10.20.0.1",
    }
    base.update(overrides)
    return base


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


class FakeVlanApplyTransport:
    vlan_offline_only = True

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
    vlan_offline_only = False


def _error_envelope() -> list[dict[str, Any]]:
    return [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "error",
                        "code": "1",
                        "ident": "Core::Interface",
                        "message": "failed",
                    }
                ],
            }
        }
    ]


def _missing_status_envelope() -> list[dict[str, Any]]:
    return [{"parse": {"prompt": "(config)"}}]


def test_preview_vlan_apply_is_deterministic() -> None:
    intent = _vlan_intent()
    preview_a = preview_vlan_apply(intent, _TEST_BRIDGE)
    preview_b = preview_vlan_apply(intent, _TEST_BRIDGE)
    assert preview_a == preview_b
    assert preview_a["bridge_id"] == _TEST_BRIDGE
    assert preview_a["verification_status"] == "offline_unverified"
    assert [op["operation"] for op in preview_a["apply_ops"]] == [
        VlanRciOperation.CREATE_BRIDGE.value,
        VlanRciOperation.SET_IP_ADDRESS.value,
        VlanRciOperation.UP.value,
    ]
    assert preview_a["apply_ops"][1]["ipv4_gateway"] == "10.20.0.1"
    assert preview_a["apply_ops"][1]["ipv4_mask"] == "255.255.255.0"


def test_preview_rejects_production_bridge() -> None:
    with pytest.raises(VlanApplyServiceError, match="allowlisted"):
        preview_vlan_apply(_vlan_intent(), _PRODUCTION_BRIDGE)


def test_apply_without_transport_is_fail_closed() -> None:
    with pytest.raises(VlanApplyServiceError, match="live VLAN apply dispatch is disabled"):
        apply_vlan_intent(intent=_vlan_intent(), bridge_id=_TEST_BRIDGE, transport=None)


def test_teardown_without_transport_is_fail_closed() -> None:
    with pytest.raises(VlanApplyServiceError, match="live VLAN apply dispatch is disabled"):
        teardown_vlan_bridge(intent=_vlan_intent(), bridge_id=_TEST_BRIDGE, transport=None)


def test_apply_with_fake_transport_dispatches_sealed_ops() -> None:
    transport = FakeVlanApplyTransport()
    result = apply_vlan_intent(
        intent=_vlan_intent(),
        bridge_id=_TEST_BRIDGE,
        transport=transport,
    )
    assert result.overall == "dispatched_offline"
    assert result.verification_status == "offline_unverified"
    assert len(result.steps) == 3
    assert all(step.ok for step in result.steps)
    assert len(transport.write_calls) == 3


def test_teardown_with_fake_transport_dispatches_teardown_ops() -> None:
    transport = FakeVlanApplyTransport()
    result = teardown_vlan_bridge(
        intent=_vlan_intent(),
        bridge_id=_TEST_BRIDGE,
        transport=transport,
    )
    assert result.overall == "dispatched_offline"
    assert len(result.steps) == 3
    assert len(transport.write_calls) == 3


@pytest.mark.parametrize(
    "transport",
    [UnmarkedTransport(), FalseMarkerTransport()],
)
def test_apply_rejects_transport_without_offline_marker(transport: object) -> None:
    with pytest.raises(VlanApplyServiceError, match="live VLAN apply dispatch is disabled"):
        apply_vlan_intent(
            intent=_vlan_intent(),
            bridge_id=_TEST_BRIDGE,
            transport=transport,
        )


def test_teardown_rejects_transport_without_offline_marker() -> None:
    with pytest.raises(VlanApplyServiceError, match="live VLAN apply dispatch is disabled"):
        teardown_vlan_bridge(
            intent=_vlan_intent(),
            bridge_id=_TEST_BRIDGE,
            transport=UnmarkedTransport(),
        )


def test_apply_fail_closed_on_error_ack() -> None:
    transport = FakeVlanApplyTransport(write_response=_error_envelope())
    result = apply_vlan_intent(
        intent=_vlan_intent(),
        bridge_id=_TEST_BRIDGE,
        transport=transport,
    )
    assert result.overall == "failed"
    assert len(result.steps) == 1
    assert result.steps[0].ok is False
    assert result.steps[0].error == "service.op_dispatch_failed"
    assert result.errors == ("service.op_dispatch_failed",)
    assert len(transport.write_calls) == 1


def test_apply_fail_closed_on_missing_status_ack() -> None:
    transport = FakeVlanApplyTransport(write_response=_missing_status_envelope())
    result = apply_vlan_intent(
        intent=_vlan_intent(),
        bridge_id=_TEST_BRIDGE,
        transport=transport,
    )
    assert result.overall == "failed"
    assert len(result.steps) == 1
    assert result.steps[0].ok is False
    assert result.errors == ("service.op_dispatch_failed",)


def test_teardown_fail_closed_on_error_ack() -> None:
    transport = FakeVlanApplyTransport(write_response=_error_envelope())
    result = teardown_vlan_bridge(
        intent=_vlan_intent(),
        bridge_id=_TEST_BRIDGE,
        transport=transport,
    )
    assert result.overall == "failed"
    assert len(result.steps) == 1
    assert result.steps[0].ok is False
    assert result.steps[0].error == "service.op_dispatch_failed"
    assert result.errors == ("service.op_dispatch_failed",)
    assert len(transport.write_calls) == 1


def test_apply_unknown_pre_state_blocks_compensation_on_failure() -> None:
    from router_control.application.vlan_apply_planner import VlanApplyPreState

    class FailSecondTransport(FakeVlanApplyTransport):
        def __init__(self) -> None:
            super().__init__()
            self._call = 0

        def execute_sealed_rci_write(self, request: SealedRciWriteRequest) -> Any:
            self._call += 1
            if self._call >= 2:
                return _error_envelope()
            return super().execute_sealed_rci_write(request)

    transport = FailSecondTransport()
    result = apply_vlan_intent(
        intent=_vlan_intent(),
        bridge_id=_TEST_BRIDGE,
        transport=transport,
        compensate_on_failure=True,
        pre_state=VlanApplyPreState(known=False),
    )
    assert result.overall == "failed"
    assert result.rollback is not None
    assert result.rollback.attempted is True
    assert result.rollback.ops == ()
    assert result.rollback.uncovered_ops
