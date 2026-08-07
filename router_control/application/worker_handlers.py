"""Typed deny-by-default job handler registry for durable worker."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from router_control.application.commissioning import CommissioningService
from router_control.application.mutation_executor import MutationExecutor
from router_control.application.preset_readiness import EventPresetCatalogService
from router_control.application.recovery import classify_job_steps
from router_control.domain.errors import (
    LeaseLostError,
    MutationForbidden,
    WorkerJobRejected,
)
from router_control.domain.errors import (
    RecoveryRequired as RecoveryRequiredError,
)
from router_control.persistence.store import PersistenceStore

# Supported readonly / offline handler kinds.
HANDLER_COMMISSIONING_ASSESS = "commissioning_assess_readonly"
HANDLER_PRESET_VALIDATE = "preset_validate"
HANDLER_PRESET_PLAN_READINESS = "preset_plan_readiness"
HANDLER_FAKE_SIMULATE = "fake_simulate_apply"

SUPPORTED_HANDLER_KINDS = frozenset(
    {
        HANDLER_COMMISSIONING_ASSESS,
        HANDLER_PRESET_VALIDATE,
        HANDLER_PRESET_PLAN_READINESS,
        HANDLER_FAKE_SIMULATE,
    }
)

LIVE_MUTATION_KINDS = frozenset(
    {
        "apply_plan",
        "enroll",
        "preflight",
        "rotate_credential",
        "revoke_credential",
        "put_credential",
        "import_profile",
        "validate_profile",
    }
)


def resolve_handler_kind(
    operation_kind: str,
    *,
    adapter_mode: str,
    allow_fake_mutations: bool,
) -> str:
    """Map operation_kind to handler kind or raise before external I/O."""
    if operation_kind in SUPPORTED_HANDLER_KINDS:
        return operation_kind
    if operation_kind == "apply_plan":
        if adapter_mode == "fake" and allow_fake_mutations:
            return HANDLER_FAKE_SIMULATE
        raise MutationForbidden("live apply_plan forbidden; fake simulation not enabled")
    if operation_kind in LIVE_MUTATION_KINDS:
        raise MutationForbidden(f"operation_kind {operation_kind} is a live mutation; rejected")
    raise WorkerJobRejected(f"unknown or unsupported operation_kind: {operation_kind}")


@dataclass(frozen=True, slots=True)
class HandlerResult:
    status: str  # Succeeded | Failed | Cancelled | RecoveryRequired
    summary_redacted: str
    http_status: int | None = None
    response_body: dict[str, Any] | None = None
    aggregate_status: str | None = None


class HandlerContext(Protocol):
    job_id: str
    operation_id: str
    operation_kind: str
    router_id: str
    correlation_id: str | None
    lease_owner: str
    fencing_token: int

    def ensure_lease(self) -> None: ...

    def is_cancel_requested(self) -> bool: ...

    def sleeper_sleep(self, seconds: float) -> None: ...


HandlerFn = Callable[[HandlerContext, PersistenceStore], HandlerResult]


@dataclass
class HandlerRegistry:
    handlers: dict[str, HandlerFn] = field(default_factory=dict)
    adapter_mode: str = "fake"
    allow_fake_mutations: bool = False

    def register(self, kind: str, handler: HandlerFn) -> None:
        self.handlers[kind] = handler

    def get_or_reject(self, operation_kind: str) -> HandlerFn:
        kind = resolve_handler_kind(
            operation_kind,
            adapter_mode=self.adapter_mode,
            allow_fake_mutations=self.allow_fake_mutations,
        )
        handler = self.handlers.get(kind)
        if handler is None:
            raise WorkerJobRejected(f"no handler registered for kind: {kind}")
        return handler


def _redact_exc(exc: BaseException) -> str:
    return f"{type(exc).__name__}: handler error"


def build_default_registry(
    *,
    commissioning: CommissioningService,
    event_presets: EventPresetCatalogService,
    adapter_mode: str = "fake",
    allow_fake_mutations: bool = False,
    mutation_executor: MutationExecutor | None = None,
) -> HandlerRegistry:
    registry = HandlerRegistry(
        adapter_mode=adapter_mode,
        allow_fake_mutations=allow_fake_mutations,
    )

    def commissioning_assess(ctx: HandlerContext, store: PersistenceStore) -> HandlerResult:
        ctx.ensure_lease()
        payload = store.get_job_dispatch_payload(ctx.job_id) or {}
        raw_run_id = payload.get("run_id")
        run_id = str(raw_run_id).strip() if raw_run_id is not None else ""
        if not run_id:
            return HandlerResult(
                status="Failed",
                summary_redacted="missing run_id in dispatch payload",
                http_status=422,
                response_body={"error": "missing run_id"},
            )
        if ctx.is_cancel_requested():
            return HandlerResult(status="Cancelled", summary_redacted="cancelled before assess")
        try:
            run, checks, _created = commissioning.assess_run(
                run_id=run_id,
                idempotency_key=str(payload.get("idempotency_key", ctx.job_id)),
                request_digest=str(payload.get("request_digest", "sha256:async-assess")),
                expected_version=payload.get("expected_version"),
                correlation_id=ctx.correlation_id,
            )
        except Exception as exc:
            return HandlerResult(
                status="Failed",
                summary_redacted=_redact_exc(exc),
                http_status=422,
                response_body={"error": type(exc).__name__},
            )
        body = {"run": run, "checks": checks}
        return HandlerResult(
            status="Succeeded",
            summary_redacted=f"assess completed state={run.get('state')}",
            http_status=200,
            response_body=body,
        )

    def preset_validate(ctx: HandlerContext, store: PersistenceStore) -> HandlerResult:
        ctx.ensure_lease()
        payload = store.get_job_dispatch_payload(ctx.job_id) or {}
        preset_id = str(payload.get("preset_id") or "")
        if not preset_id:
            return HandlerResult(
                status="Failed",
                summary_redacted="missing preset_id in dispatch payload",
                http_status=422,
                response_body={"error": "missing preset_id"},
            )
        if ctx.is_cancel_requested():
            return HandlerResult(status="Cancelled", summary_redacted="cancelled before validate")
        try:
            result = event_presets.validate_preset(preset_id)
        except Exception as exc:
            return HandlerResult(
                status="Failed",
                summary_redacted=_redact_exc(exc),
                http_status=422,
                response_body={"error": type(exc).__name__},
            )
        return HandlerResult(
            status="Succeeded",
            summary_redacted=f"preset validated status={result.get('validation_status')}",
            http_status=200,
            response_body=result,
        )

    def preset_plan_readiness(ctx: HandlerContext, store: PersistenceStore) -> HandlerResult:
        ctx.ensure_lease()
        payload = store.get_job_dispatch_payload(ctx.job_id) or {}
        preset_id = str(payload.get("preset_id") or "")
        if not preset_id:
            return HandlerResult(
                status="Failed",
                summary_redacted="missing preset_id in dispatch payload",
                http_status=422,
                response_body={"error": "missing preset_id"},
            )
        if ctx.is_cancel_requested():
            return HandlerResult(
                status="Cancelled", summary_redacted="cancelled before plan-readiness"
            )
        try:
            preview = event_presets.plan_preview(preset_id)
            report = event_presets.readiness_report(preset_id)
        except Exception as exc:
            return HandlerResult(
                status="Failed",
                summary_redacted=_redact_exc(exc),
                http_status=422,
                response_body={"error": type(exc).__name__},
            )
        body = {"plan_preview": preview, "readiness_report": report}
        return HandlerResult(
            status="Succeeded",
            summary_redacted="plan preview and readiness report generated",
            http_status=200,
            response_body=body,
        )

    def fake_simulate(ctx: HandlerContext, store: PersistenceStore) -> HandlerResult:
        ctx.ensure_lease()
        if ctx.is_cancel_requested():
            return HandlerResult(status="Cancelled", summary_redacted="cancelled before simulate")
        payload = store.get_job_dispatch_payload(ctx.job_id) or {}
        job = store.get_job(ctx.job_id)
        recovery_state = str(job["recovery_state"]) if job and job["recovery_state"] else None

        if mutation_executor is not None:
            try:
                status, summary, body = mutation_executor.execute_apply(
                    ctx,
                    store,
                    dispatch_payload=payload,
                    recovery_state=recovery_state,
                )
            except LeaseLostError:
                return HandlerResult(
                    status="Failed",
                    summary_redacted="lease lost during handler",
                )
            except RecoveryRequiredError as exc:
                return HandlerResult(
                    status="RecoveryRequired",
                    summary_redacted=str(exc)[:200],
                    http_status=422,
                    response_body={
                        "status": "RecoveryRequired",
                        "error": type(exc).__name__,
                    },
                )
            except MutationForbidden as exc:
                return HandlerResult(
                    status="Failed",
                    summary_redacted=str(exc)[:200],
                    http_status=403,
                    response_body={"error": type(exc).__name__, "message": str(exc)[:120]},
                )
            except Exception as exc:
                cls = classify_job_steps(store, ctx.job_id, job_status="Running")
                if cls.apply_dispatched:
                    return HandlerResult(
                        status="RecoveryRequired",
                        summary_redacted=f"{type(exc).__name__}: post-dispatch handler error",
                        http_status=422,
                        response_body={
                            "status": "RecoveryRequired",
                            "error": type(exc).__name__,
                        },
                    )
                return HandlerResult(
                    status="Failed",
                    summary_redacted=_redact_exc(exc),
                    http_status=500,
                    response_body={"error": type(exc).__name__},
                )
            http_status: int | None = 200 if status == "Succeeded" else 422
            if status == "RecoveryRequired":
                http_status = 422
            if status == "Cancelled":
                http_status = None
            aggregate = None
            if body and isinstance(body, dict):
                aggregate = body.get("aggregate_status")
            return HandlerResult(
                status=status,
                summary_redacted=summary,
                http_status=http_status,
                response_body=body,
                aggregate_status=str(aggregate) if aggregate else None,
            )

        simulate_ms = float(payload.get("simulate_ms", 0))
        if simulate_ms > 0:
            ctx.sleeper_sleep(simulate_ms / 1000.0)
            ctx.ensure_lease()
        plan_id = payload.get("plan_id")
        body = {
            "operation_id": ctx.operation_id,
            "job_id": ctx.job_id,
            "status": "Succeeded",
            "simulated": True,
            "plan_id": plan_id,
        }
        return HandlerResult(
            status="Succeeded",
            summary_redacted="fake apply simulation completed",
            http_status=200,
            response_body=body,
        )

    registry.register(HANDLER_COMMISSIONING_ASSESS, commissioning_assess)
    registry.register(HANDLER_PRESET_VALIDATE, preset_validate)
    registry.register(HANDLER_PRESET_PLAN_READINESS, preset_plan_readiness)
    registry.register(HANDLER_FAKE_SIMULATE, fake_simulate)
    return registry


def safe_handler_call(
    handler: HandlerFn,
    ctx: HandlerContext,
    store: PersistenceStore,
) -> HandlerResult:
    try:
        return handler(ctx, store)
    except LeaseLostError:
        return HandlerResult(
            status="Failed",
            summary_redacted="lease lost during handler",
        )
    except RecoveryRequiredError as exc:
        return HandlerResult(
            status="RecoveryRequired",
            summary_redacted=str(exc)[:200],
            http_status=422,
            response_body={"status": "RecoveryRequired", "error": type(exc).__name__},
        )
    except Exception as exc:
        cls = classify_job_steps(store, ctx.job_id, job_status="Running")
        if cls.apply_dispatched:
            return HandlerResult(
                status="RecoveryRequired",
                summary_redacted=f"{type(exc).__name__}: post-dispatch handler error",
                http_status=422,
                response_body={"status": "RecoveryRequired", "error": type(exc).__name__},
            )
        return HandlerResult(
            status="Failed",
            summary_redacted=_redact_exc(exc),
            http_status=500,
            response_body={"error": type(exc).__name__},
        )
