"""Async continuation and deterministic call order."""

from __future__ import annotations

import time

import pytest
from router_control.adapters.fake.adapter import FakeMode, FakeRouterConfig
from router_control.application.provisioning import (
    MAX_APPLY_CONTINUATIONS,
    ProvisioningRequest,
)
from router_control.application.worker import WorkerConfig
from router_control.composition import FakeRuntime, build_durable_worker
from router_control.domain.enums import EffectState, SafetyState

from tests.conftest import build_request
from tests.test_recovery_substrate import FIXED, _runtime, _seed_plan_bundle


def _wait_job_terminal(store, job_id: str, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job = store.get_job(job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired", "Cancelled"):
            return
        time.sleep(0.05)
    pytest.fail(f"job {job_id} did not reach terminal state")


@pytest.mark.asyncio
async def test_partial_async_continuation() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.PARTIAL_ASYNC))
    first = await runtime.adapter.apply_plan(request.plan)
    assert first.continuation_token
    assert first.continued is True
    second = await runtime.adapter.poll_apply_continuation(
        request.router_id,
        request.plan.plan_id,
        first.continuation_token,
    )
    assert second.continued is False
    apply_calls = [call for call in runtime.adapter.call_trace if call == "apply_plan"]
    poll_calls = [
        call for call in runtime.adapter.call_trace if call == "poll_apply_continuation"
    ]
    assert len(apply_calls) == 1
    assert len(poll_calls) == 1


@pytest.mark.asyncio
async def test_always_continued_exceeds_bound() -> None:
    runtime, request = build_request(config=FakeRouterConfig(mode=FakeMode.ALWAYS_CONTINUED))
    apply_result = await runtime.adapter.apply_plan(request.plan)
    count = 0
    while apply_result.continued or apply_result.continuation_token:
        count += 1
        if count >= MAX_APPLY_CONTINUATIONS:
            break
        token = apply_result.continuation_token
        assert token
        apply_result = await runtime.adapter.poll_apply_continuation(
            request.router_id,
            request.plan.plan_id,
            token,
        )
    assert count == MAX_APPLY_CONTINUATIONS
    assert runtime.adapter.call_trace.count("apply_plan") == 1


def test_durable_partial_async_poll_not_redispatch(tmp_path) -> None:
    runtime = _runtime(
        tmp_path / "durable-poll.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.PARTIAL_ASYNC),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="durable-poll",
        request_digest="sha256:durable-poll",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    import time

    deadline = time.monotonic() + 8.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("Succeeded", "Failed", "RecoveryRequired"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    assert runtime.adapter.call_trace.count("apply_plan") == 1
    assert runtime.adapter.call_trace.count("poll_apply_continuation") == 1


def test_continued_without_poll_blocks_recovery_required(tmp_path) -> None:
    """F-11: missing poll after continued apply must not leave Ready+Failed re-apply path."""
    runtime = _runtime(
        tmp_path / "no-poll.sqlite3",
        config=FakeRouterConfig(mode=FakeMode.ALWAYS_CONTINUED),
    )
    rid, plan_id = _seed_plan_bundle(runtime)
    runtime.adapter.poll_apply_continuation = None  # type: ignore[method-assign]
    out = runtime.store.create_operation_bundle(
        router_id=rid,
        operation_kind="apply_plan",
        idempotency_key="no-poll",
        request_digest="sha256:no-poll",
        plan_id=plan_id,
        initial_job_status="Queued",
        dispatch_payload={"plan_id": plan_id},
        now=FIXED,
    )
    worker = build_durable_worker(runtime, allow_fake_mutations=True)
    worker.config = WorkerConfig(poll_interval_seconds=0.05)
    worker.start()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        job = runtime.store.get_job(out.job_id)
        if job and job["status"] in ("RecoveryRequired", "Failed", "Succeeded"):
            break
        time.sleep(0.05)
    worker.stop(timeout=3.0)
    job = runtime.store.get_job(out.job_id)
    assert job is not None
    assert job["status"] == "RecoveryRequired"
    assert runtime.adapter.call_trace.count("apply_plan") == 1
    safety = runtime.store.get_router_safety_session(rid)
    assert safety is not None
    assert str(safety["safety_state"]) == SafetyState.BLOCKED.value
    effects = runtime.store._conn.execute(
        "SELECT current_state FROM external_effects WHERE router_id = ?", (rid,)
    ).fetchall()
    assert len(effects) == 1
    assert str(effects[0]["current_state"]) == EffectState.UNKNOWN.value


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
