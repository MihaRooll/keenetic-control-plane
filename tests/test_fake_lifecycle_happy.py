"""Happy-path fake lifecycle."""

from __future__ import annotations

import pytest
from router_control.application.provisioning import ProvisioningRequest
from router_control.composition import FakeRuntime
from router_control.domain.enums import ReconcileStatus, StepKind
from router_control.domain.errors import RecoveryRequired


@pytest.mark.asyncio
async def test_happy_lifecycle_converges(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    outcome = await runtime.service.execute(request)

    assert outcome.status is ReconcileStatus.CONVERGED
    assert outcome.error is None
    assert outcome.applied_revision_id == request.desired_revision.revision_id
    assert outcome.read_back is not None
    assert outcome.read_back.outcome_known is True

    expected_steps = (
        StepKind.PREFLIGHT,
        StepKind.IDENTITY_CHECK,
        StepKind.OBSERVE,
        StepKind.BACKUP,
        StepKind.PLAN_PRECONDITIONS,
        StepKind.CONFIRM,
        StepKind.BEGIN_FAIL_SAFE,
        StepKind.APPLY,
        StepKind.READ_BACK,
        StepKind.VERIFY,
        StepKind.SAVE,
    )
    assert outcome.trace.steps == expected_steps


@pytest.mark.asyncio
async def test_fake_evidence_cannot_certify_nc1812(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, _ = happy_request
    evidence = runtime.adapter.evidence
    assert evidence.adapter_mode == "fake"
    assert evidence.certifies_nc1812 is False


@pytest.mark.asyncio
async def test_applied_marker_only_after_verify(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    outcome = await runtime.service.execute(request)
    assert outcome.applied_revision_id is not None
    assert "verify_postconditions" in outcome.trace.adapter_calls
    verify_index = outcome.trace.adapter_calls.index("verify_postconditions")
    save_index = outcome.trace.adapter_calls.index("save_configuration")
    assert verify_index < save_index


@pytest.mark.asyncio
async def test_compensate_after_converged_cannot_revert_saved_state(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    outcome = await runtime.service.execute(request)
    assert outcome.status is ReconcileStatus.CONVERGED
    assert outcome.backup is not None

    saved_digest = runtime.adapter.state.state_digest
    saved_rv = runtime.adapter.state.resource_version
    saved_applied = runtime.adapter.state.applied_plan_digest

    with pytest.raises(RecoveryRequired):
        await runtime.adapter.compensate(request.router_id, outcome.backup)

    assert runtime.adapter.state.state_digest == saved_digest
    assert runtime.adapter.state.resource_version == saved_rv
    assert runtime.adapter.state.applied_plan_digest == saved_applied
