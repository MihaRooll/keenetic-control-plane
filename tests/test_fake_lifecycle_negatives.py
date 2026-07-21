"""Negative fake lifecycle scenarios."""

from __future__ import annotations

from datetime import timedelta

import pytest
from router_control.adapters.fake.adapter import FakeMode, FakeRouterConfig
from router_control.application.provisioning import ProvisioningRequest
from router_control.composition import FakeRuntime
from router_control.domain.entities import ChangePlan, ChangePlanItem
from router_control.domain.enums import CertificationStatus, ReconcileStatus
from router_control.domain.errors import (
    CapabilityExpired,
    FailSafeTimeout,
    IdentityMismatch,
    PlanExpired,
    PlanUnconfirmed,
    RecoveryRequired,
    StaleObservation,
    UnknownExternalOutcome,
    UnmanagedConflict,
)
from router_control.domain.ids import ResourceId, RouterId
from router_control.ports.router_control import IdentityCheckResult

from tests.conftest import build_plan, build_request


@pytest.mark.asyncio
async def test_request_router_id_mismatch_before_apply(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    mismatched_request = type(request)(
        router_id=RouterId("router-fake-mismatch"),
        expected_identity=request.expected_identity,
        desired_revision=request.desired_revision,
        plan=request.plan,
        managed_resources=request.managed_resources,
        operation_id=request.operation_id,
        confirmed=True,
    )
    outcome = await runtime.service.execute(mismatched_request)
    assert isinstance(outcome.error, IdentityMismatch)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls
    assert outcome.applied_revision_id is None


@pytest.mark.asyncio
async def test_identity_mismatch_before_apply() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.IDENTITY_MISMATCH))
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, IdentityMismatch)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_identity_matched_false_aborts_before_apply(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request

    async def check_matched_false(expected: object) -> IdentityCheckResult:
        identity = request.expected_identity
        return IdentityCheckResult(
            matched=False,
            observed_fingerprint_digest=identity.fingerprint_digest,
        )

    runtime.adapter.check_identity = check_matched_false  # type: ignore[method-assign]
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, IdentityMismatch)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_unknown_capability_blocks_writes() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.UNKNOWN_CAPABILITY))
    outcome = await runtime.service.execute(request)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_stale_observation_rejected() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.STALE_OBSERVATION))
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, StaleObservation)
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_unconfirmed_plan_rejected() -> None:
    runtime, request = build_request(confirmed=False)
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, PlanUnconfirmed)
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_expired_plan_rejected(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    expired_plan = build_plan(
        router_id=request.router_id,
        revision_id=request.desired_revision.revision_id,
        desired_digest=request.desired_revision.desired_digest,
        observation_id=request.plan.observation_id,
        resource_version=request.plan.observed_resource_version,
        expires_at=runtime.clock.now() - timedelta(seconds=1),
        confirmed=True,
    )
    expired_request = type(request)(
        router_id=request.router_id,
        expected_identity=request.expected_identity,
        desired_revision=request.desired_revision,
        plan=expired_plan,
        managed_resources=request.managed_resources,
        operation_id=request.operation_id,
        confirmed=True,
    )
    outcome = await runtime.service.execute(expired_request)
    assert isinstance(outcome.error, PlanExpired)


@pytest.mark.asyncio
async def test_unmanaged_conflict_preserved(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    conflict_request = type(request)(
        router_id=request.router_id,
        expected_identity=request.expected_identity,
        desired_revision=request.desired_revision,
        plan=request.plan,
        managed_resources=request.managed_resources,
        operation_id=request.operation_id,
        confirmed=True,
        conflicting_unmanaged_locators=(runtime.adapter.unmanaged_conflict_locator(),),
    )
    outcome = await runtime.service.execute(conflict_request)
    assert isinstance(outcome.error, UnmanagedConflict)
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_unmanaged_plan_item_rejected_before_apply(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    unmanaged_item = ChangePlanItem(
        resource_id=ResourceId("resource-unmanaged-999"),
        intent_kind="ensure-managed-assignment",
        intent_digest="digest:intent:unmanaged",
    )
    bad_plan = ChangePlan(
        plan_id=request.plan.plan_id,
        router_id=request.plan.router_id,
        revision_id=request.plan.revision_id,
        observation_id=request.plan.observation_id,
        expected_desired_digest=request.plan.expected_desired_digest,
        observed_resource_version=request.plan.observed_resource_version,
        items=(unmanaged_item,),
        confirmation_state=request.plan.confirmation_state,
        expires_at=request.plan.expires_at,
        created_at=request.plan.created_at,
        actor=request.plan.actor,
    )
    bad_request = type(request)(
        router_id=request.router_id,
        expected_identity=request.expected_identity,
        desired_revision=request.desired_revision,
        plan=bad_plan,
        managed_resources=request.managed_resources,
        operation_id=request.operation_id,
        confirmed=True,
        conflicting_unmanaged_locators=(),
    )
    outcome = await runtime.service.execute(bad_request)
    assert isinstance(outcome.error, UnmanagedConflict)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls
    assert outcome.applied_revision_id is None


@pytest.mark.asyncio
async def test_fake_mode_unmanaged_conflict_before_apply() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.UNMANAGED_CONFLICT))
    conflict_request = type(request)(
        router_id=request.router_id,
        expected_identity=request.expected_identity,
        desired_revision=request.desired_revision,
        plan=request.plan,
        managed_resources=request.managed_resources,
        operation_id=request.operation_id,
        confirmed=True,
        conflicting_unmanaged_locators=(),
    )
    pre_digest = runtime.adapter.state.state_digest
    pre_rv = runtime.adapter.state.resource_version
    outcome = await runtime.service.execute(conflict_request)
    assert isinstance(outcome.error, UnmanagedConflict)
    assert outcome.status is ReconcileStatus.FAILED
    assert outcome.trace.adapter_calls.count("apply_plan") == 1
    assert outcome.trace.adapter_calls.count("compensate") == 1
    assert outcome.applied_revision_id is None
    assert outcome.observation is not None
    assert outcome.backup is not None
    assert runtime.adapter.state.state_digest == pre_digest
    assert runtime.adapter.state.resource_version == pre_rv
    assert runtime.adapter.state.fail_safe_active is False


@pytest.mark.asyncio
async def test_unknown_outcome_triggers_recovery(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    pre_digest = runtime.adapter.state.state_digest
    pre_rv = runtime.adapter.state.resource_version
    pre_applied = runtime.adapter.state.applied_plan_digest
    runtime.adapter.config.mode = FakeMode.UNKNOWN_EXTERNAL_OUTCOME
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, UnknownExternalOutcome)
    assert outcome.status is ReconcileStatus.RECOVERY_REQUIRED
    assert outcome.trace.adapter_calls.count("compensate") == 1
    assert outcome.applied_revision_id is None
    assert outcome.trace.adapter_calls.count("apply_plan") == 1
    assert outcome.observation is not None
    assert outcome.backup is not None
    assert outcome.read_back is not None
    assert not outcome.read_back.outcome_known
    assert runtime.adapter.state.state_digest == pre_digest
    assert runtime.adapter.state.resource_version == pre_rv
    assert runtime.adapter.state.applied_plan_digest == pre_applied
    assert runtime.adapter.state.fail_safe_active is False


@pytest.mark.asyncio
async def test_fail_safe_timeout_leaves_state_unchanged() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.FAIL_SAFE_TIMEOUT))
    pre_digest = runtime.adapter.state.state_digest
    pre_rv = runtime.adapter.state.resource_version
    pre_applied = runtime.adapter.state.applied_plan_digest
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, FailSafeTimeout)
    assert "compensate" not in outcome.trace.adapter_calls
    assert runtime.adapter.state.state_digest == pre_digest
    assert runtime.adapter.state.resource_version == pre_rv
    assert runtime.adapter.state.applied_plan_digest == pre_applied
    assert runtime.adapter.state.fail_safe_active is False


@pytest.mark.asyncio
async def test_verification_failure_requires_recovery() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.VERIFY_FAILURE))
    pre_digest = runtime.adapter.state.state_digest
    pre_rv = runtime.adapter.state.resource_version
    pre_applied = runtime.adapter.state.applied_plan_digest
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, RecoveryRequired)
    assert outcome.status is ReconcileStatus.RECOVERY_REQUIRED
    assert outcome.trace.adapter_calls.count("compensate") == 1
    assert outcome.applied_revision_id is None
    assert outcome.observation is not None
    assert outcome.backup is not None
    assert outcome.read_back is not None
    assert runtime.adapter.state.state_digest == pre_digest
    assert runtime.adapter.state.resource_version == pre_rv
    assert runtime.adapter.state.applied_plan_digest == pre_applied
    assert runtime.adapter.state.fail_safe_active is False


@pytest.mark.asyncio
async def test_read_only_capability_blocks_writes(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    runtime.adapter.state.capability_status = CertificationStatus.READ_ONLY_CERTIFIED
    outcome = await runtime.service.execute(request)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls


@pytest.mark.asyncio
async def test_expired_capability_blocks_writes() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.EXPIRED_CAPABILITY))
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, CapabilityExpired)
    assert outcome.status is ReconcileStatus.FAILED
    assert "apply_plan" not in outcome.trace.adapter_calls
