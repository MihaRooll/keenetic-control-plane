"""Worker handler registry: reject unknown/live mutations; fake gating."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
from router_control.application.worker_handlers import (
    build_default_registry,
    resolve_handler_kind,
)
from router_control.composition import create_offline_runtime
from router_control.domain.errors import MutationForbidden, WorkerJobRejected

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@dataclass
class _HandlerCtx:
    job_id: str
    operation_id: str
    operation_kind: str
    router_id: str
    correlation_id: str | None
    _cancel: bool = False

    def ensure_lease(self) -> None:
        return

    def is_cancel_requested(self) -> bool:
        return self._cancel

    def sleeper_sleep(self, seconds: float) -> None:
        return


def test_unknown_kind_rejected() -> None:
    with pytest.raises(WorkerJobRejected):
        resolve_handler_kind("unknown_kind_xyz", adapter_mode="fake", allow_fake_mutations=False)


def test_live_apply_rejected_without_fake_gate() -> None:
    with pytest.raises(MutationForbidden):
        resolve_handler_kind("apply_plan", adapter_mode="live", allow_fake_mutations=False)
    with pytest.raises(MutationForbidden):
        resolve_handler_kind("apply_plan", adapter_mode="fake", allow_fake_mutations=False)


def test_fake_apply_resolves_when_gated() -> None:
    kind = resolve_handler_kind("apply_plan", adapter_mode="fake", allow_fake_mutations=True)
    assert kind == "fake_simulate_apply"


def test_enroll_mutation_rejected() -> None:
    with pytest.raises(MutationForbidden):
        resolve_handler_kind("enroll", adapter_mode="fake", allow_fake_mutations=True)


def test_registry_has_supported_handlers(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "handlers.sqlite3")
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=True,
    )
    for kind in (
        "commissioning_assess_readonly",
        "preset_validate",
        "preset_plan_readiness",
        "fake_simulate_apply",
    ):
        assert reg.get_or_reject(kind) is not None


def test_preset_validate_uses_dispatch_payload_not_correlation(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "preset-handler.sqlite3")
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="Handler Preset",
        document=None,
        idempotency_key="preset-handler-k1",
        request_digest="sha256:handler-preset",
    )
    preset_id = preset["preset_id"]
    router_id = runtime.event_presets._sentinel_router_id(site_id)
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="preset_validate",
        idempotency_key="validate-handler-k1",
        request_digest="sha256:validate-handler",
        correlation_id="corr-not-a-preset-id",
        initial_job_status="Queued",
        now=FIXED,
    )
    runtime.store.insert_job_dispatch_payload(
        job_id=outcome.job_id,
        payload={"preset_id": preset_id},
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("preset_validate")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="preset_validate",
        router_id=router_id,
        correlation_id="corr-not-a-preset-id",
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Succeeded"
    assert result.http_status == 200
    assert result.response_body is not None
    assert result.response_body["preset_id"] == preset_id


def test_preset_validate_missing_payload_preset_id_fails_before_service(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "preset-missing.sqlite3")
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    router_id = runtime.event_presets._sentinel_router_id(site_id)
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="preset_validate",
        idempotency_key="validate-missing-k1",
        request_digest="sha256:validate-missing",
        correlation_id="corr-should-not-select-preset",
        initial_job_status="Queued",
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("preset_validate")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="preset_validate",
        router_id=router_id,
        correlation_id="corr-should-not-select-preset",
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Failed"
    assert result.http_status == 422
    assert result.response_body == {"error": "missing preset_id"}


def test_preset_plan_readiness_uses_dispatch_payload_not_correlation(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "plan-handler.sqlite3")
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    target, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="Handler Target Preset",
        document=None,
        idempotency_key="plan-handler-target-k1",
        request_digest="sha256:plan-handler-target",
    )
    decoy, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="Handler Decoy Preset",
        document=None,
        idempotency_key="plan-handler-decoy-k1",
        request_digest="sha256:plan-handler-decoy",
    )
    preset_id = target["preset_id"]
    decoy_preset_id = decoy["preset_id"]
    router_id = runtime.event_presets._sentinel_router_id(site_id)
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="preset_plan_readiness",
        idempotency_key="plan-handler-k1",
        request_digest="sha256:plan-handler",
        correlation_id=decoy_preset_id,
        initial_job_status="Queued",
        now=FIXED,
    )
    runtime.store.insert_job_dispatch_payload(
        job_id=outcome.job_id,
        payload={"preset_id": preset_id},
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("preset_plan_readiness")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="preset_plan_readiness",
        router_id=router_id,
        correlation_id=decoy_preset_id,
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Succeeded"
    assert result.http_status == 200
    assert result.response_body is not None
    assert result.response_body["readiness_report"]["preset_id"] == preset_id
    assert result.response_body["readiness_report"]["preset_id"] != decoy_preset_id
    assert "plan_preview" in result.response_body


def test_preset_plan_readiness_missing_payload_preset_id_fails_before_service(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "plan-missing.sqlite3")
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="Handler Preset",
        document=None,
        idempotency_key="plan-missing-preset-k1",
        request_digest="sha256:plan-missing-preset",
    )
    router_id = runtime.event_presets._sentinel_router_id(site_id)
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="preset_plan_readiness",
        idempotency_key="plan-missing-k1",
        request_digest="sha256:plan-missing",
        correlation_id=preset["preset_id"],
        initial_job_status="Queued",
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("preset_plan_readiness")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="preset_plan_readiness",
        router_id=router_id,
        correlation_id=preset["preset_id"],
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Failed"
    assert result.http_status == 422
    assert result.response_body == {"error": "missing preset_id"}


def test_preset_plan_readiness_invalid_payload_preset_id_ignores_correlation(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "plan-invalid.sqlite3")
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    preset, _, _ = runtime.event_presets.create_preset(
        site_id=site_id,
        name="Handler Preset",
        document=None,
        idempotency_key="plan-invalid-preset-k1",
        request_digest="sha256:plan-invalid-preset",
    )
    router_id = runtime.event_presets._sentinel_router_id(site_id)
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="preset_plan_readiness",
        idempotency_key="plan-invalid-k1",
        request_digest="sha256:plan-invalid",
        correlation_id=preset["preset_id"],
        initial_job_status="Queued",
        now=FIXED,
    )
    runtime.store.insert_job_dispatch_payload(
        job_id=outcome.job_id,
        payload={"preset_id": "epreset-unknown-target"},
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("preset_plan_readiness")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="preset_plan_readiness",
        router_id=router_id,
        correlation_id=preset["preset_id"],
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Failed"
    assert result.http_status == 422
    assert result.response_body == {"error": "EventPresetNotFound"}


def _seed_commissioning_run(runtime) -> tuple[str, str]:
    site_id = runtime.store.create_site(display_name="Lab", now=FIXED)
    router_id = runtime.store.enroll_router(
        site_id=site_id,
        display_name="R1",
        vendor="FakeVendor",
        model="Fake",
        identity_fingerprint="digest:handler",
        host="127.0.0.1",
        now=FIXED,
    )
    runtime.store._conn.execute(
        "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
        (router_id,),
    )
    runtime.store.insert_observation(
        router_id=router_id,
        identity_fingerprint="digest:handler",
        resource_version="v1",
        state_digest="sha256:state",
        now=FIXED,
    )
    run, _ = runtime.store.create_commissioning_run(
        site_id=site_id,
        router_id=router_id,
        mode="fake",
        idempotency_key="handler-create",
        request_digest="sha256:handler-create",
        now=FIXED,
    )
    return run["run_id"], router_id


def test_commissioning_assess_uses_dispatch_payload_not_correlation(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "comm-handler.sqlite3")
    run_id, router_id = _seed_commissioning_run(runtime)
    decoy_run_id = "crun-decoy-not-real"
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="commissioning_assess_readonly",
        idempotency_key="comm-handler-k1",
        request_digest="sha256:comm-handler",
        correlation_id=decoy_run_id,
        initial_job_status="Queued",
        dispatch_payload={
            "run_id": run_id,
            "idempotency_key": "worker-assess-k1",
            "request_digest": "sha256:worker-assess",
        },
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("commissioning_assess_readonly")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="commissioning_assess_readonly",
        router_id=router_id,
        correlation_id=decoy_run_id,
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Succeeded"
    assert result.response_body is not None
    assert result.response_body["run"]["run_id"] == run_id


def test_commissioning_assess_missing_payload_run_id_fails_before_service(tmp_path) -> None:
    runtime = create_offline_runtime(db_path=tmp_path / "comm-missing.sqlite3")
    run_id, router_id = _seed_commissioning_run(runtime)
    outcome = runtime.store.create_operation_bundle(
        router_id=router_id,
        operation_kind="commissioning_assess_readonly",
        idempotency_key="comm-missing-k1",
        request_digest="sha256:comm-missing",
        correlation_id=run_id,
        initial_job_status="Queued",
        now=FIXED,
    )
    reg = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode="fake",
        allow_fake_mutations=False,
    )
    handler = reg.get_or_reject("commissioning_assess_readonly")
    ctx = _HandlerCtx(
        job_id=outcome.job_id,
        operation_id=outcome.operation_id,
        operation_kind="commissioning_assess_readonly",
        router_id=router_id,
        correlation_id=run_id,
    )
    result = handler(ctx, runtime.store)
    assert result.status == "Failed"
    assert result.http_status == 422
    assert result.response_body == {"error": "missing run_id"}
    row = runtime.store.get_commissioning_run(run_id)
    assert row is not None
    assert str(row["state"]) == "Draft"
