"""Offline DNS deployment intent → sealed op compiler tests."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.dns_rci import DnsRciOperation
from router_control.application.dns_apply_planner import (
    DnsApplyPlannerError,
    compile_dns_intent_to_ops,
)


def _dns_intent(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "zone_id": "Guest",
        "local_fqdn": "order.guest.example.com",
        "upstream_resolvers": ["8.8.8.8", "1.1.1.1"],
    }
    base.update(overrides)
    return base


def test_compile_emits_ordered_apply_and_teardown_ops() -> None:
    plan = compile_dns_intent_to_ops(_dns_intent())

    assert plan.verification_status == "offline_unverified"
    assert plan.zone_id == "Guest"
    assert plan.local_fqdn == "order.guest.example.com"
    assert plan.upstream_resolvers == ("8.8.8.8", "1.1.1.1")
    assert [op.operation for op in plan.apply_ops] == [
        DnsRciOperation.SET_STATIC_HOST.value,
        DnsRciOperation.SET_UPSTREAM.value,
        DnsRciOperation.SET_UPSTREAM.value,
    ]
    assert [op.operation for op in plan.teardown_ops] == [
        DnsRciOperation.CLEAR_UPSTREAM.value,
        DnsRciOperation.CLEAR_UPSTREAM.value,
        DnsRciOperation.CLEAR_STATIC_HOST.value,
    ]
    assert plan.teardown_ops[0].upstream_resolver == "1.1.1.1"
    assert plan.teardown_ops[1].upstream_resolver == "8.8.8.8"
    assert any("offline_unverified" in note for note in plan.notes)


def test_unknown_intent_field_raises() -> None:
    intent = _dns_intent(extra="bad")
    with pytest.raises(DnsApplyPlannerError, match="unknown intent fields"):
        compile_dns_intent_to_ops(intent)


def test_missing_required_field_raises() -> None:
    intent = {"zone_id": "Guest", "local_fqdn": "order.guest.example.com"}
    with pytest.raises(DnsApplyPlannerError, match="missing required intent fields"):
        compile_dns_intent_to_ops(intent)


def test_invalid_fqdn_rejected() -> None:
    with pytest.raises(DnsApplyPlannerError):
        compile_dns_intent_to_ops(_dns_intent(local_fqdn="not-valid"))


def test_invalid_resolver_rejected() -> None:
    with pytest.raises(DnsApplyPlannerError):
        compile_dns_intent_to_ops(_dns_intent(upstream_resolvers=["999.1.1.1"]))


@pytest.mark.parametrize("zone_id", [True, 123])
def test_non_string_zone_id_rejected(zone_id: object) -> None:
    with pytest.raises(DnsApplyPlannerError, match="zone_id must be a non-empty string"):
        compile_dns_intent_to_ops(_dns_intent(zone_id=zone_id))


@pytest.mark.parametrize("upstream_resolvers", [None, "not-a-list"])
def test_upstream_resolvers_none_or_non_list_rejected(upstream_resolvers: object) -> None:
    with pytest.raises(DnsApplyPlannerError, match="upstream_resolvers must be a list"):
        compile_dns_intent_to_ops(_dns_intent(upstream_resolvers=upstream_resolvers))


def test_derive_pre_state_without_parser_is_unknown() -> None:
    from router_control.application.dns_apply_planner import derive_dns_pre_state

    assert derive_dns_pre_state({"hosts": []}).known is False


def test_compensate_duplicate_upstream_preserves_resolvers() -> None:
    from router_control.application.dns_apply_planner import (
        DnsApplyPreState,
        compensate_ops_for_succeeded_dns_apply,
    )

    plan = compile_dns_intent_to_ops(_dns_intent())
    upstream_ops = [
        op for op in plan.apply_ops if op.operation == DnsRciOperation.SET_UPSTREAM.value
    ]
    succeeded = tuple(op.operation for op in upstream_ops)
    pre_state = DnsApplyPreState(known=True, had_static_host=False, had_upstreams=False)
    compensate = compensate_ops_for_succeeded_dns_apply(
        plan.apply_ops, succeeded, pre_state=pre_state
    )
    assert [op.operation for op in compensate] == [
        DnsRciOperation.CLEAR_UPSTREAM.value,
        DnsRciOperation.CLEAR_UPSTREAM.value,
    ]
    assert [op.upstream_resolver for op in compensate] == ["1.1.1.1", "8.8.8.8"]


def test_compensate_first_upstream_only_on_fail_stop() -> None:
    from router_control.application.dns_apply_planner import (
        DnsApplyPreState,
        compensate_ops_for_succeeded_dns_apply,
    )

    plan = compile_dns_intent_to_ops(_dns_intent())
    upstream_ops = tuple(
        op for op in plan.apply_ops if op.operation == DnsRciOperation.SET_UPSTREAM.value
    )
    succeeded = (DnsRciOperation.SET_UPSTREAM.value,)
    pre_state = DnsApplyPreState(known=True, had_static_host=False, had_upstreams=False)
    compensate = compensate_ops_for_succeeded_dns_apply(
        upstream_ops, succeeded, pre_state=pre_state
    )
    assert len(compensate) == 1
    assert compensate[0].operation == DnsRciOperation.CLEAR_UPSTREAM.value
    assert compensate[0].upstream_resolver == "8.8.8.8"
