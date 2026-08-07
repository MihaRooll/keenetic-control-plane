"""Offline firewall deployment intent → sealed op compiler tests."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.firewall_rci import FirewallRciOperation
from router_control.application.firewall_apply_planner import (
    FirewallApplyPlannerError,
    compile_firewall_intent_to_ops,
)


def _firewall_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "Guest",
        "rules": [
            {"action": "Allow", "destination_family": "OrderPage", "ordinal": 20},
            {"action": "Allow", "destination_family": "Dns", "ordinal": 10},
            {"action": "Deny", "destination_family": "Internet", "ordinal": 30},
        ],
    }
    base.update(overrides)
    return base


def test_compile_emits_ordered_apply_and_teardown_ops() -> None:
    plan = compile_firewall_intent_to_ops(_firewall_intent())

    assert plan.verification_status == "offline_unverified"
    assert plan.zone_id == "Guest"
    assert [op.ordinal for op in plan.apply_ops] == [10, 20, 30]
    assert [op.operation for op in plan.apply_ops] == [
        FirewallRciOperation.ADD_RULE.value,
        FirewallRciOperation.ADD_RULE.value,
        FirewallRciOperation.ADD_RULE.value,
    ]
    assert [op.ordinal for op in plan.teardown_ops] == [30, 20, 10]
    assert [op.operation for op in plan.teardown_ops] == [
        FirewallRciOperation.REMOVE_RULE.value,
        FirewallRciOperation.REMOVE_RULE.value,
        FirewallRciOperation.REMOVE_RULE.value,
    ]
    assert any("offline_unverified" in note for note in plan.notes)


def test_unknown_intent_field_raises() -> None:
    intent = _firewall_intent(extra="bad")
    with pytest.raises(FirewallApplyPlannerError, match="unknown intent fields"):
        compile_firewall_intent_to_ops(intent)


def test_missing_required_field_raises() -> None:
    intent = {"zone_id": "Guest"}
    with pytest.raises(FirewallApplyPlannerError, match="missing required intent fields"):
        compile_firewall_intent_to_ops(intent)


def test_rule_unknown_field_raises() -> None:
    intent = _firewall_intent(
        rules=[{"action": "Allow", "destination_family": "Dns", "priority": 10}]
    )
    with pytest.raises(FirewallApplyPlannerError, match="unknown fields"):
        compile_firewall_intent_to_ops(intent)


def test_invalid_action_rejected() -> None:
    intent = _firewall_intent(
        rules=[{"action": "Drop", "destination_family": "Dns", "ordinal": 10}]
    )
    with pytest.raises(FirewallApplyPlannerError):
        compile_firewall_intent_to_ops(intent)


def test_invalid_destination_family_rejected() -> None:
    intent = _firewall_intent(
        rules=[{"action": "Allow", "destination_family": "Unknown", "ordinal": 10}]
    )
    with pytest.raises(FirewallApplyPlannerError):
        compile_firewall_intent_to_ops(intent)


@pytest.mark.parametrize("zone_id", [True, 123])
def test_non_string_zone_id_rejected(zone_id: object) -> None:
    with pytest.raises(FirewallApplyPlannerError, match="zone_id must be a non-empty string"):
        compile_firewall_intent_to_ops(_firewall_intent(zone_id=zone_id))


@pytest.mark.parametrize("rules", [None, "not-a-list"])
def test_rules_none_or_non_list_rejected(rules: object) -> None:
    with pytest.raises(FirewallApplyPlannerError, match="rules must be a list"):
        compile_firewall_intent_to_ops(_firewall_intent(rules=rules))


@pytest.mark.parametrize("ordinal", [True, 10.9])
def test_invalid_rule_ordinal_type_rejected(ordinal: object) -> None:
    intent = _firewall_intent(
        rules=[{"action": "Allow", "destination_family": "Dns", "ordinal": ordinal}]
    )
    with pytest.raises(FirewallApplyPlannerError, match="ordinal must be an integer"):
        compile_firewall_intent_to_ops(intent)


def test_derive_pre_state_without_parser_is_unknown() -> None:
    from router_control.application.firewall_apply_planner import (
        compensate_ops_for_succeeded_firewall_apply,
        derive_firewall_pre_state,
    )

    pre_state = derive_firewall_pre_state({"rules": []})
    assert pre_state.known is False
    plan = compile_firewall_intent_to_ops(_firewall_intent())
    succeeded = (plan.apply_ops[0].operation,)
    assert (
        compensate_ops_for_succeeded_firewall_apply(
            plan.apply_ops, succeeded, pre_state=pre_state
        )
        == ()
    )


def test_compensate_duplicate_add_rules_preserves_ordinals() -> None:
    from router_control.application.firewall_apply_planner import (
        FirewallApplyPreState,
        compensate_ops_for_succeeded_firewall_apply,
    )

    plan = compile_firewall_intent_to_ops(
        _firewall_intent(
            rules=[
                {"action": "Allow", "destination_family": "Dns", "ordinal": 10},
                {"action": "Allow", "destination_family": "OrderPage", "ordinal": 20},
            ]
        )
    )
    succeeded = tuple(op.operation for op in plan.apply_ops)
    pre_state = FirewallApplyPreState(known=True, had_rules=False)
    compensate = compensate_ops_for_succeeded_firewall_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert [op.operation for op in compensate] == [
        FirewallRciOperation.REMOVE_RULE.value,
        FirewallRciOperation.REMOVE_RULE.value,
    ]
    assert [op.ordinal for op in compensate] == [20, 10]


def test_compensate_first_add_rule_only_on_fail_stop() -> None:
    from router_control.application.firewall_apply_planner import (
        FirewallApplyPreState,
        compensate_ops_for_succeeded_firewall_apply,
    )

    plan = compile_firewall_intent_to_ops(
        _firewall_intent(
            rules=[
                {"action": "Allow", "destination_family": "Dns", "ordinal": 10},
                {"action": "Allow", "destination_family": "OrderPage", "ordinal": 20},
            ]
        )
    )
    succeeded = (FirewallRciOperation.ADD_RULE.value,)
    pre_state = FirewallApplyPreState(known=True, had_rules=False)
    compensate = compensate_ops_for_succeeded_firewall_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert len(compensate) == 1
    assert compensate[0].operation == FirewallRciOperation.REMOVE_RULE.value
    assert compensate[0].ordinal == 10
