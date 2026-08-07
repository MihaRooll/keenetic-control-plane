"""Offline VLAN deployment intent → sealed op compiler tests."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.vlan_rci import VlanRciOperation
from router_control.application.vlan_apply_planner import (
    VlanApplyPlannerError,
    compile_vlan_intent_to_ops,
)

APPLY_OPS = (
    VlanRciOperation.CREATE_BRIDGE,
    VlanRciOperation.SET_IP_ADDRESS,
    VlanRciOperation.UP,
)

TEARDOWN_OPS = (
    VlanRciOperation.DOWN,
    VlanRciOperation.CLEAR_IP_ADDRESS,
    VlanRciOperation.REMOVE_BRIDGE,
)


def _vlan_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "staff",
        "vlan_id": 20,
        "ipv4_cidr": "10.20.0.0/24",
        "ipv4_gateway": "10.20.0.1",
    }
    base.update(overrides)
    return base


def test_compile_emits_ordered_apply_and_teardown_ops() -> None:
    plan = compile_vlan_intent_to_ops(_vlan_intent(), "Bridge3")

    assert plan.verification_status == "offline_unverified"
    assert plan.bridge_id == "Bridge3"
    assert plan.zone_id == "staff"
    assert plan.vlan_id == 20
    assert plan.ipv4_cidr == "10.20.0.0/24"
    assert plan.ipv4_gateway == "10.20.0.1"
    assert [op.operation for op in plan.apply_ops] == [op.value for op in APPLY_OPS]
    assert [op.operation for op in plan.teardown_ops] == [op.value for op in TEARDOWN_OPS]
    assert plan.apply_ops[1].ipv4_gateway == "10.20.0.1"
    assert plan.apply_ops[1].ipv4_mask == "255.255.255.0"
    assert all(op.bridge_id == "Bridge3" for op in plan.apply_ops)
    assert any("vlan_id=20" in note for op in plan.apply_ops for note in op.notes)


def test_unknown_intent_field_raises() -> None:
    intent = _vlan_intent(extra="bad")
    with pytest.raises(VlanApplyPlannerError, match="unknown intent fields"):
        compile_vlan_intent_to_ops(intent, "Bridge4")


def test_missing_required_field_raises() -> None:
    intent = {"zone_id": "staff", "vlan_id": 20, "ipv4_cidr": "10.20.0.0/24"}
    with pytest.raises(VlanApplyPlannerError, match="missing required intent fields"):
        compile_vlan_intent_to_ops(intent, "Bridge4")


@pytest.mark.parametrize("vlan_id", [0, 4095, -1, "20"])
def test_invalid_vlan_id_rejected(vlan_id: object) -> None:
    with pytest.raises(VlanApplyPlannerError, match="vlan_id"):
        compile_vlan_intent_to_ops(_vlan_intent(vlan_id=vlan_id), "Bridge5")


def test_gateway_outside_network_rejected() -> None:
    with pytest.raises(VlanApplyPlannerError, match="ipv4_gateway"):
        compile_vlan_intent_to_ops(_vlan_intent(ipv4_gateway="10.99.0.1"), "Bridge5")


def test_gateway_network_address_rejected() -> None:
    with pytest.raises(VlanApplyPlannerError, match="network or broadcast"):
        compile_vlan_intent_to_ops(_vlan_intent(ipv4_gateway="10.20.0.0"), "Bridge5")


@pytest.mark.parametrize("bridge_id", ["Bridge0", "Bridge1", "Bridge10", "GigabitEthernet0"])
def test_rejects_non_allowlisted_bridge(bridge_id: str) -> None:
    with pytest.raises(ValueError, match="allowlisted"):
        compile_vlan_intent_to_ops(_vlan_intent(), bridge_id)


def test_accepts_throwaway_bridges() -> None:
    plan = compile_vlan_intent_to_ops(_vlan_intent(), "  Bridge9  ")
    assert plan.bridge_id == "Bridge9"


def test_derive_pre_state_without_parser_is_unknown() -> None:
    from router_control.application.vlan_apply_planner import (
        VlanApplyPreState,
        compensate_ops_for_succeeded_vlan_apply,
        derive_vlan_pre_state,
        uncovered_compensate_ops_for_succeeded_vlan_apply,
    )

    pre_state = derive_vlan_pre_state({"bridge": "Bridge3"})
    assert pre_state == VlanApplyPreState(known=False)
    plan = compile_vlan_intent_to_ops(_vlan_intent(), "Bridge3")
    succeeded = tuple(op.operation for op in plan.apply_ops)
    assert (
        compensate_ops_for_succeeded_vlan_apply(plan.apply_ops, succeeded, pre_state=pre_state)
        == ()
    )
    uncovered = uncovered_compensate_ops_for_succeeded_vlan_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert len(uncovered) == len(succeeded)


def test_pre_existing_blocks_compensation() -> None:
    from router_control.application.vlan_apply_planner import (
        VlanApplyPreState,
        compensate_ops_for_succeeded_vlan_apply,
        uncovered_compensate_ops_for_succeeded_vlan_apply,
    )

    plan = compile_vlan_intent_to_ops(_vlan_intent(), "Bridge3")
    succeeded = (plan.apply_ops[0].operation,)
    pre_state = VlanApplyPreState(known=True, bridge_existed=True)
    assert (
        compensate_ops_for_succeeded_vlan_apply(plan.apply_ops, succeeded, pre_state=pre_state)
        == ()
    )
    uncovered = uncovered_compensate_ops_for_succeeded_vlan_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert uncovered[0][0] == plan.apply_ops[0].operation
