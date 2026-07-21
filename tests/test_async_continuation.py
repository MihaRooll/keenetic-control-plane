"""Async continuation and deterministic call order."""

from __future__ import annotations

import pytest
from router_control.adapters.fake.adapter import FakeMode, FakeRouterConfig
from router_control.application.provisioning import (
    MAX_APPLY_CONTINUATIONS,
    ProvisioningRequest,
)
from router_control.composition import FakeRuntime
from router_control.domain.enums import ReconcileStatus
from router_control.domain.errors import RecoveryRequired

from tests.conftest import build_request


@pytest.mark.asyncio
async def test_partial_async_continuation() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.PARTIAL_ASYNC))
    outcome = await runtime.service.execute(request)
    assert outcome.status is ReconcileStatus.CONVERGED
    apply_calls = [call for call in outcome.trace.adapter_calls if call == "apply_plan"]
    assert len(apply_calls) == 2


@pytest.mark.asyncio
async def test_always_continued_exceeds_bound() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.ALWAYS_CONTINUED))
    outcome = await runtime.service.execute(request)
    assert isinstance(outcome.error, RecoveryRequired)
    assert outcome.status is ReconcileStatus.RECOVERY_REQUIRED
    assert outcome.trace.adapter_calls.count("apply_plan") == MAX_APPLY_CONTINUATIONS
    assert "read_back" not in outcome.trace.adapter_calls
    assert outcome.trace.adapter_calls.count("compensate") == 1
    assert outcome.observation is not None
    assert outcome.backup is not None
    assert outcome.read_back is None


@pytest.mark.asyncio
async def test_deterministic_call_order(
    happy_request: tuple[FakeRuntime, ProvisioningRequest],
) -> None:
    runtime, request = happy_request
    outcome = await runtime.service.execute(request)
    expected_prefix = (
        "check_identity",
        "observe",
        "get_capabilities",
        "create_backup",
        "begin_fail_safe",
        "apply_plan",
        "read_back",
        "verify_postconditions",
        "save_configuration",
    )
    assert outcome.trace.adapter_calls[: len(expected_prefix)] == expected_prefix
