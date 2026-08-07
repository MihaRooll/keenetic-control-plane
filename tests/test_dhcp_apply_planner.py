"""Offline DHCP deployment intent → sealed op compiler tests."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.dhcp_rci import DhcpRciOperation
from router_control.application.dhcp_apply_planner import (
    DhcpApplyPlannerError,
    compile_dhcp_intent_to_ops,
)


def _dhcp_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "Guest",
        "pool_start": "10.10.0.100",
        "pool_end": "10.10.0.200",
        "lease_seconds": 86400,
        "reservations": [
            {"mac_address": "aa:bb:cc:00:00:01", "ipv4_address": "10.10.0.50"},
            {"mac_address": "aa:bb:cc:00:00:02", "ipv4_address": "10.10.0.51"},
        ],
    }
    base.update(overrides)
    return base


def test_compile_emits_ordered_apply_and_teardown_ops() -> None:
    plan = compile_dhcp_intent_to_ops(_dhcp_intent())

    assert plan.verification_status == "offline_unverified"
    assert plan.zone_id == "Guest"
    assert plan.pool_start == "10.10.0.100"
    assert plan.pool_end == "10.10.0.200"
    assert plan.lease_seconds == 86400
    assert [op.operation for op in plan.apply_ops] == [
        DhcpRciOperation.SET_POOL.value,
        DhcpRciOperation.SET_LEASE.value,
        DhcpRciOperation.BIND_HOST.value,
        DhcpRciOperation.BIND_HOST.value,
    ]
    assert [op.operation for op in plan.teardown_ops] == [
        DhcpRciOperation.UNBIND_HOST.value,
        DhcpRciOperation.UNBIND_HOST.value,
        DhcpRciOperation.CLEAR_POOL.value,
    ]
    assert plan.teardown_ops[0].mac_address == "aa:bb:cc:00:00:02"
    assert plan.teardown_ops[1].mac_address == "aa:bb:cc:00:00:01"
    assert any("offline_unverified" in note for note in plan.notes)


def test_unknown_intent_field_raises() -> None:
    intent = _dhcp_intent(extra="bad")
    with pytest.raises(DhcpApplyPlannerError, match="unknown intent fields"):
        compile_dhcp_intent_to_ops(intent)


def test_missing_required_field_raises() -> None:
    intent = {"zone_id": "Guest", "pool_start": "10.10.0.100", "pool_end": "10.10.0.200"}
    with pytest.raises(DhcpApplyPlannerError, match="missing required intent fields"):
        compile_dhcp_intent_to_ops(intent)


def test_reservation_unknown_field_raises() -> None:
    intent = _dhcp_intent(
        reservations=[{"mac_address": "aa:bb:cc:00:00:01", "ipv4": "10.10.0.50"}]
    )
    with pytest.raises(DhcpApplyPlannerError, match="unknown fields"):
        compile_dhcp_intent_to_ops(intent)


@pytest.mark.parametrize("lease_seconds", [59, 604801, "86400"])
def test_invalid_lease_seconds_rejected(lease_seconds: object) -> None:
    with pytest.raises(DhcpApplyPlannerError):
        compile_dhcp_intent_to_ops(_dhcp_intent(lease_seconds=lease_seconds))


def test_invalid_mac_rejected() -> None:
    intent = _dhcp_intent(
        reservations=[{"mac_address": "bad", "ipv4_address": "10.10.0.50"}]
    )
    with pytest.raises(DhcpApplyPlannerError):
        compile_dhcp_intent_to_ops(intent)


@pytest.mark.parametrize("zone_id", [True, 123])
def test_non_string_zone_id_rejected(zone_id: object) -> None:
    with pytest.raises(DhcpApplyPlannerError, match="zone_id must be a non-empty string"):
        compile_dhcp_intent_to_ops(_dhcp_intent(zone_id=zone_id))


@pytest.mark.parametrize("reservations", [None, "not-a-list"])
def test_reservations_none_or_non_list_rejected(reservations: object) -> None:
    with pytest.raises(DhcpApplyPlannerError, match="reservations must be a list"):
        compile_dhcp_intent_to_ops(_dhcp_intent(reservations=reservations))


def test_set_lease_is_uncovered_for_compensation() -> None:
    from router_control.application.dhcp_apply_planner import (
        compensate_ops_for_succeeded_dhcp_apply,
        derive_dhcp_pre_state,
        uncovered_compensate_ops_for_succeeded_dhcp_apply,
    )

    plan = compile_dhcp_intent_to_ops(_dhcp_intent(reservations=[]))
    succeeded = (DhcpRciOperation.SET_LEASE.value,)
    pre_state = derive_dhcp_pre_state(None)
    assert (
        compensate_ops_for_succeeded_dhcp_apply(plan.apply_ops, succeeded, pre_state=pre_state)
        == ()
    )
    uncovered = dict(
        uncovered_compensate_ops_for_succeeded_dhcp_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
    )
    assert uncovered[DhcpRciOperation.SET_LEASE.value] == "no sealed lease-clear op"


def test_compensate_duplicate_bind_host_preserves_macs() -> None:
    from router_control.application.dhcp_apply_planner import (
        DhcpApplyPreState,
        compensate_ops_for_succeeded_dhcp_apply,
    )

    plan = compile_dhcp_intent_to_ops(_dhcp_intent())
    bind_ops = [op for op in plan.apply_ops if op.operation == DhcpRciOperation.BIND_HOST.value]
    succeeded = tuple(op.operation for op in bind_ops)
    pre_state = DhcpApplyPreState(known=True, pool_existed=False, had_reservations=False)
    compensate = compensate_ops_for_succeeded_dhcp_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert [op.operation for op in compensate] == [
        DhcpRciOperation.UNBIND_HOST.value,
        DhcpRciOperation.UNBIND_HOST.value,
    ]
    assert [op.mac_address for op in compensate] == ["aa:bb:cc:00:00:02", "aa:bb:cc:00:00:01"]


def test_compensate_first_bind_only_on_fail_stop() -> None:
    from router_control.application.dhcp_apply_planner import (
        DhcpApplyPreState,
        compensate_ops_for_succeeded_dhcp_apply,
    )

    plan = compile_dhcp_intent_to_ops(_dhcp_intent())
    bind_ops = tuple(
        op for op in plan.apply_ops if op.operation == DhcpRciOperation.BIND_HOST.value
    )
    succeeded = (DhcpRciOperation.BIND_HOST.value,)
    pre_state = DhcpApplyPreState(known=True, pool_existed=False, had_reservations=False)
    compensate = compensate_ops_for_succeeded_dhcp_apply(
        bind_ops, succeeded, pre_state=pre_state
    )
    assert len(compensate) == 1
    assert compensate[0].operation == DhcpRciOperation.UNBIND_HOST.value
    assert compensate[0].mac_address == "aa:bb:cc:00:00:01"
