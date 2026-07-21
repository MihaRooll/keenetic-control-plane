"""Domain invariant unit tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone
from typing import cast

import pytest
from router_control.domain.entities import (
    ChangePlan,
    ChangePlanItem,
    DesiredRevision,
    ManagedResource,
    RouterCapability,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.enums import (
    CertificationStatus,
    ManagedResourceLifecycle,
    ObservationCollectionStatus,
    PlanConfirmationState,
)
from router_control.domain.errors import (
    CapabilityExpired,
    CapabilityUnknown,
    CapabilityUnsupported,
    IdentityMismatch,
    StaleObservation,
    UnmanagedConflict,
)
from router_control.domain.ids import (
    CapabilityId,
    ObservationId,
    PlanId,
    ResourceId,
    RevisionId,
    RouterId,
)
from router_control.domain.policies import (
    assert_capability_allows_write,
    assert_endpoint_not_identity,
    assert_identity_match,
    assert_no_unmanaged_conflict,
    assert_observation_fresh,
)


def test_endpoint_not_identity() -> None:
    identity = RouterIdentity(
        router_id=RouterId("router-fake-001"),
        vendor="FakeVendor",
        model="FakeModel",
        fingerprint_digest="digest:identity:001",
    )
    assert_endpoint_not_identity("192.168.1.1", identity)
    with pytest.raises(ValueError, match="endpoint must not equal"):
        assert_endpoint_not_identity("router-fake-001", identity)


def test_identity_mismatch_hard_abort() -> None:
    identity = RouterIdentity(
        router_id=RouterId("router-fake-001"),
        vendor="FakeVendor",
        model="FakeModel",
        fingerprint_digest="digest:identity:001",
    )
    with pytest.raises(IdentityMismatch):
        assert_identity_match(identity, "digest:identity:other")


def test_unknown_capability_fail_closed() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    capability = RouterCapability(
        capability_id=CapabilityId("capability-fake-001"),
        router_id=RouterId("router-fake-001"),
        firmware_digest="digest:firmware:001",
        certification_status=CertificationStatus.UNKNOWN,
        observed_at=now,
        valid_until=now + timedelta(hours=1),
        source="fake",
    )
    with pytest.raises(CapabilityUnknown):
        assert_capability_allows_write(capability, now)


def test_expired_capability_fail_closed() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    capability = RouterCapability(
        capability_id=CapabilityId("capability-fake-001"),
        router_id=RouterId("router-fake-001"),
        firmware_digest="digest:firmware:001",
        certification_status=CertificationStatus.WRITE_CERTIFIED,
        observed_at=now - timedelta(hours=2),
        valid_until=now - timedelta(seconds=1),
        source="fake",
    )
    with pytest.raises(CapabilityExpired):
        assert_capability_allows_write(capability, now)


def test_unsupported_capability_fail_closed() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    capability = RouterCapability(
        capability_id=CapabilityId("capability-fake-001"),
        router_id=RouterId("router-fake-001"),
        firmware_digest="digest:firmware:001",
        certification_status=CertificationStatus.UNSUPPORTED,
        observed_at=now,
        valid_until=now + timedelta(hours=1),
        source="fake",
    )
    with pytest.raises(CapabilityUnsupported):
        assert_capability_allows_write(capability, now)


def test_stale_observation_rejected() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    observation = RouterObservation(
        observation_id=ObservationId("observation-fake-001"),
        router_id=RouterId("router-fake-001"),
        identity_fingerprint_digest="digest:identity:001",
        capability_id=CapabilityId("capability-fake-001"),
        state_digest="digest:state:001",
        resource_version="digest:rv:001",
        observed_at=now - timedelta(minutes=10),
        valid_until=now - timedelta(seconds=1),
        collection_status=ObservationCollectionStatus.SUCCEEDED,
        source="fake",
    )
    with pytest.raises(StaleObservation):
        assert_observation_fresh(observation, now)


def test_failed_observation_rejected() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    observation = RouterObservation(
        observation_id=ObservationId("observation-fake-001"),
        router_id=RouterId("router-fake-001"),
        identity_fingerprint_digest="digest:identity:001",
        capability_id=CapabilityId("capability-fake-001"),
        state_digest="digest:state:001",
        resource_version="digest:rv:001",
        observed_at=now,
        valid_until=now + timedelta(minutes=5),
        collection_status=ObservationCollectionStatus.FAILED,
        source="fake",
    )
    with pytest.raises(StaleObservation):
        assert_observation_fresh(observation, now)


def test_id_validation_rejects_empty() -> None:
    with pytest.raises(ValueError):
        RouterId("")


def test_unmanaged_plan_item_rejected() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    router_id = RouterId("router-fake-001")
    revision_id = RevisionId("revision-fake-001")
    managed = ManagedResource(
        resource_id=ResourceId("resource-fake-001"),
        router_id=router_id,
        resource_kind="tunnel-assignment",
        logical_key="primary",
        owner="router-control",
        revision_id=revision_id,
        external_locator_digest="digest:locator:managed-001",
        lifecycle=ManagedResourceLifecycle.PRESENT,
        last_observation_id=ObservationId("observation-fake-001"),
    )
    plan = ChangePlan(
        plan_id=PlanId("plan-fake-001"),
        router_id=router_id,
        revision_id=revision_id,
        observation_id=ObservationId("observation-fake-001"),
        expected_desired_digest="digest:desired:001",
        observed_resource_version="digest:rv:001",
        items=(
            ChangePlanItem(
                resource_id=ResourceId("resource-unmanaged-999"),
                intent_kind="ensure-managed-assignment",
                intent_digest="digest:intent:unmanaged",
            ),
        ),
        confirmation_state=PlanConfirmationState.CONFIRMED,
        expires_at=now + timedelta(hours=1),
        created_at=now,
        actor="operator-fake",
    )
    with pytest.raises(UnmanagedConflict):
        assert_no_unmanaged_conflict((managed,), (), plan)


def test_change_plan_items_normalized_to_tuple() -> None:
    now = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    item = ChangePlanItem(
        resource_id=ResourceId("resource-fake-001"),
        intent_kind="ensure-managed-assignment",
        intent_digest="digest:intent:001",
    )
    mutable_items = [item]
    plan = ChangePlan(
        plan_id=PlanId("plan-fake-001"),
        router_id=RouterId("router-fake-001"),
        revision_id=RevisionId("revision-fake-001"),
        observation_id=ObservationId("observation-fake-001"),
        expected_desired_digest="digest:desired:001",
        observed_resource_version="digest:rv:001",
        items=cast(tuple[ChangePlanItem, ...], mutable_items),
        confirmation_state=PlanConfirmationState.CONFIRMED,
        expires_at=now + timedelta(hours=1),
        created_at=now,
        actor="operator-fake",
    )
    assert isinstance(plan.items, tuple)
    assert plan.items == (item,)
    mutable_items.append(
        ChangePlanItem(
            resource_id=ResourceId("resource-fake-002"),
            intent_kind="ensure-managed-assignment",
            intent_digest="digest:intent:002",
        )
    )
    assert len(plan.items) == 1


def test_naive_datetime_rejected() -> None:
    naive = datetime(2026, 7, 21, 12, 0, 0)
    with pytest.raises(ValueError, match="timezone-aware UTC"):
        DesiredRevision(
            revision_id=RevisionId("revision-fake-001"),
            router_id=RouterId("router-fake-001"),
            revision_number=1,
            desired_digest="digest:desired:001",
            based_on_observation_id=ObservationId("observation-fake-001"),
            created_at=naive,
        )


def test_nonzero_utc_offset_rejected() -> None:
    offset = datetime(2026, 7, 21, 15, 0, 0, tzinfo=timezone(timedelta(hours=3)))
    with pytest.raises(ValueError, match="must use UTC timezone"):
        DesiredRevision(
            revision_id=RevisionId("revision-fake-001"),
            router_id=RouterId("router-fake-001"),
            revision_number=1,
            desired_digest="digest:desired:001",
            based_on_observation_id=ObservationId("observation-fake-001"),
            created_at=offset,
        )


def test_zero_offset_timezone_normalized_to_utc() -> None:
    zero_offset = datetime(2026, 7, 21, 12, 0, 0, tzinfo=timezone(timedelta(0)))
    revision = DesiredRevision(
        revision_id=RevisionId("revision-fake-001"),
        router_id=RouterId("router-fake-001"),
        revision_number=1,
        desired_digest="digest:desired:001",
        based_on_observation_id=ObservationId("observation-fake-001"),
        created_at=zero_offset,
    )
    assert revision.created_at.tzinfo is UTC
    assert revision.created_at == datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
