"""Shared pytest fixtures for fake-only tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from router_control.adapters.fake.adapter import FakeRouterConfig
from router_control.application.provisioning import ProvisioningRequest
from router_control.composition import FakeRuntime, create_fake_runtime, default_plan_expiry
from router_control.domain.entities import (
    ChangePlan,
    ChangePlanItem,
    DesiredRevision,
    ManagedResource,
)
from router_control.domain.enums import (
    ManagedResourceLifecycle,
    PlanConfirmationState,
)
from router_control.domain.ids import (
    ObservationId,
    OperationId,
    PlanId,
    ResourceId,
    RevisionId,
    RouterId,
)


@pytest.fixture
def base_moment() -> datetime:
    return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def runtime(base_moment: datetime) -> FakeRuntime:
    from router_control.composition import FixedClock

    return create_fake_runtime(clock=FixedClock(base_moment))


def build_plan(
    *,
    router_id: RouterId,
    revision_id: RevisionId,
    desired_digest: str,
    observation_id: ObservationId,
    resource_version: str,
    expires_at: datetime,
    confirmed: bool = True,
) -> ChangePlan:
    return ChangePlan(
        plan_id=PlanId("plan-fake-001"),
        router_id=router_id,
        revision_id=revision_id,
        observation_id=observation_id,
        expected_desired_digest=desired_digest,
        observed_resource_version=resource_version,
        items=(
            ChangePlanItem(
                resource_id=ResourceId("resource-fake-001"),
                intent_kind="ensure-managed-assignment",
                intent_digest="digest:intent:001",
            ),
        ),
        confirmation_state=(
            PlanConfirmationState.CONFIRMED if confirmed else PlanConfirmationState.PENDING
        ),
        expires_at=expires_at,
        created_at=expires_at - timedelta(hours=1),
        actor="operator-fake",
    )


def build_desired(revision_id: RevisionId, router_id: RouterId, digest: str) -> DesiredRevision:
    return DesiredRevision(
        revision_id=revision_id,
        router_id=router_id,
        revision_number=1,
        desired_digest=digest,
        based_on_observation_id=ObservationId("observation-fake-001"),
        created_at=datetime(2026, 7, 21, 11, 0, 0, tzinfo=UTC),
    )


def build_managed(router_id: RouterId, revision_id: RevisionId) -> ManagedResource:
    return ManagedResource(
        resource_id=ResourceId("resource-fake-001"),
        router_id=router_id,
        resource_kind="tunnel-assignment",
        logical_key="primary-event-vpn",
        owner="router-control",
        revision_id=revision_id,
        external_locator_digest="digest:locator:managed-001",
        lifecycle=ManagedResourceLifecycle.PRESENT,
        last_observation_id=ObservationId("observation-fake-001"),
    )


def build_request(
    *,
    confirmed: bool = True,
    config: FakeRouterConfig | None = None,
) -> tuple[FakeRuntime, ProvisioningRequest]:
    from router_control.composition import FixedClock

    runtime = create_fake_runtime(
        clock=FixedClock(datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)),
        config=config or FakeRouterConfig(),
    )

    router_id = runtime.adapter.state.identity.router_id
    revision_id = RevisionId("revision-fake-001")
    desired_digest = "digest:desired:001"
    observation_id = ObservationId("observation-fake-001")
    resource_version = "digest:rv:001"
    expires_at = default_plan_expiry(runtime.clock)

    plan = build_plan(
        router_id=router_id,
        revision_id=revision_id,
        desired_digest=desired_digest,
        observation_id=observation_id,
        resource_version=resource_version,
        expires_at=expires_at,
        confirmed=confirmed,
    )
    desired = build_desired(revision_id, router_id, desired_digest)
    managed = build_managed(router_id, revision_id)

    return runtime, ProvisioningRequest(
        router_id=router_id,
        expected_identity=runtime.adapter.state.identity,
        desired_revision=desired,
        plan=plan,
        managed_resources=(managed,),
        operation_id=OperationId("operation-fake-001"),
        confirmed=confirmed,
    )


@pytest.fixture
def happy_request() -> tuple[FakeRuntime, ProvisioningRequest]:
    return build_request()
