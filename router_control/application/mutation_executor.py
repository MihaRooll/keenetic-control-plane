"""Durable checkpointed mutation executor — router I/O outside SQLite IMMEDIATE txns."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from router_control.application.provisioning import MAX_APPLY_CONTINUATIONS
from router_control.application.recovery import checkpoint_redacted
from router_control.domain.entities import (
    BackupArtifact,
    ChangePlan,
    ChangePlanItem,
    DesiredRevision,
    ManagedResource,
    RouterIdentity,
)
from router_control.domain.enums import (
    EffectState,
    EvidenceKind,
    ManagedResourceLifecycle,
    PlanConfirmationState,
    ReconcileStatus,
    SafetyState,
    StepKind,
)
from router_control.domain.errors import (
    DomainError,
    IdentityMismatch,
    LeaseLostError,
    MutationForbidden,
    PlanUnconfirmed,
    RecoveryRequired,
    UnknownExternalOutcome,
)
from router_control.domain.ids import (
    ArtifactId,
    ObservationId,
    OperationId,
    PlanId,
    ResourceId,
    RevisionId,
    RouterId,
)
from router_control.domain.policies import (
    assert_capability_allows_write,
    assert_desired_matches_plan,
    assert_identity_match,
    assert_no_unmanaged_conflict,
    assert_observation_fresh,
    assert_observation_matches_plan,
    assert_plan_valid,
)
from router_control.persistence.errors import StaleFenceError
from router_control.persistence.store import PersistenceStore
from router_control.ports.clock import ClockPort
from router_control.ports.router_control import (
    ApplyResult,
    ReadBackResult,
    RouterControlPort,
)


class ExecutorContext(Protocol):
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


class BackupPublisherPort(Protocol):
    def publish(
        self,
        *,
        artifact_id: str | None,
        router_id: str,
        operation_id: str,
        content_bytes: bytes,
        content_digest: str,
        identity_fingerprint: str,
        now: datetime | None = None,
    ) -> str: ...


@dataclass
class MutationExecutorHooks:
    crash_after_step: StepKind | None = None
    step_delay_seconds: float = 0.0
    crash_after_checkpoint: bool = False
    crash_after_dispatching: bool = False


@dataclass
class _StepContext:
    backup: BackupArtifact | None = None
    fail_safe_began: bool = False
    apply_dispatched: bool = False
    read_back: ReadBackResult | None = None
    effect_id: str | None = None
    aggregate_status: str | None = None
    boot_marker: str | None = None


@dataclass
class MutationExecutor:
    adapter: RouterControlPort
    clock: ClockPort
    backup_publisher: BackupPublisherPort
    hooks: MutationExecutorHooks = field(default_factory=MutationExecutorHooks)

    def execute_apply(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        *,
        dispatch_payload: dict[str, Any],
        recovery_state: str | None = None,
    ) -> tuple[str, str, dict[str, Any] | None]:
        simulate_ms = float(dispatch_payload.get("simulate_ms", 0))
        if simulate_ms > 0:
            ctx.sleeper_sleep(simulate_ms / 1000.0)
            ctx.ensure_lease()

        if ctx.is_cancel_requested():
            return "Cancelled", "cancelled before apply", None

        action = str(dispatch_payload.get("recovery_action", "") or "")
        if recovery_state == "resume_after_readback" or action == "resume":
            return self._execute_resume(ctx, store, dispatch_payload)
        if recovery_state == "compensate" or action == "compensate":
            return self._execute_compensate(ctx, store, dispatch_payload)

        plan_id = _resolve_plan_id(ctx, store, dispatch_payload)
        if not plan_id:
            body = {
                "operation_id": ctx.operation_id,
                "job_id": ctx.job_id,
                "simulated": True,
                "status": "Succeeded",
            }
            return "Succeeded", "fake apply simulation completed (no plan binding)", body

        request = self._build_request(ctx, store, plan_id)
        if request is None:
            return (
                "Failed",
                "plan binding failed",
                {"error": "PlanNotFound", "plan_id": plan_id},
            )
        self._initialize_safety_and_boot(ctx, store, request)
        self._assert_mutation_allowed(store, ctx.router_id)
        boot_marker = f"boot:simulated:{ctx.job_id}"
        return self._execute_steps(
            ctx, store, request, start_after=None, boot_marker=boot_marker
        )

    def _execute_resume(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        dispatch_payload: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any] | None]:
        plan_id = _resolve_plan_id(ctx, store, dispatch_payload)
        request = self._build_request(ctx, store, plan_id) if plan_id else None
        if request is None:
            return "Failed", "resume plan binding failed", {"error": "PlanNotFound"}

        step_ctx = _StepContext(apply_dispatched=True)
        status, summary, body = self._run_checkpointed_step(
            ctx, store, StepKind.IDENTITY_CHECK, request, step_ctx
        )
        if status != "Succeeded":
            return status, summary, body
        status, summary, body = self._run_checkpointed_step(
            ctx, store, StepKind.READ_BACK, request, step_ctx
        )
        if status != "Succeeded":
            return status, summary, body
        return self._execute_steps(ctx, store, request, start_after=StepKind.READ_BACK)

    def _execute_compensate(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        dispatch_payload: dict[str, Any],
    ) -> tuple[str, str, dict[str, Any] | None]:
        artifact_id = _resolve_backup_artifact_id(store, ctx.job_id, dispatch_payload)
        if not artifact_id:
            return "Failed", "no backup artifact for compensate", {"error": "NoBackupArtifact"}

        router = store.get_router(ctx.router_id)
        if router is None:
            return "Failed", "router not found", {"error": "NotFound"}
        identity = _adapter_identity(self.adapter, router, ctx.router_id)
        request = _ProvisioningBundle(
            router_id=RouterId(ctx.router_id),
            expected_identity=identity,
            desired_revision=_stub_desired(ctx.router_id),
            plan=_stub_plan(ctx.router_id),
            managed_resources=(),
            operation_id=OperationId(ctx.operation_id),
            confirmed=True,
            conflicting_unmanaged_locators=(),
        )

        step_ctx = _StepContext(apply_dispatched=True)
        status, summary, body = self._run_checkpointed_step(
            ctx, store, StepKind.IDENTITY_CHECK, request, step_ctx
        )
        if status != "Succeeded":
            return status, summary, body

        row = store.get_backup_artifact(artifact_id)
        if row is None:
            return "Failed", "backup artifact missing", {"error": "BackupNotFound"}

        step_ctx.backup = BackupArtifact(
            artifact_id=ArtifactId(artifact_id),
            router_id=RouterId(ctx.router_id),
            operation_id=OperationId(str(row["operation_id"] or ctx.operation_id)),
            content_digest=str(row["content_digest"]),
            storage_locator_digest="digest:locator:redacted",
            identity_fingerprint_digest=str(row["identity_fingerprint"]),
            created_at=_parse_ts(str(row["created_at"])),
        )
        status, summary, _body = self._run_checkpointed_step(
            ctx, store, StepKind.COMPENSATE, request, step_ctx
        )
        if status == "RecoveryRequired":
            return status, summary, _body
        return "Failed", "compensated after partial apply", {
            "status": "Failed",
            "compensated": True,
        }

    def _execute_steps(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        request: _ProvisioningBundle,
        *,
        start_after: StepKind | None,
        boot_marker: str | None = None,
    ) -> tuple[str, str, dict[str, Any] | None]:
        chain = (
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
        step_ctx = _StepContext(boot_marker=boot_marker)
        backup_artifact_id: str | None = None
        start_idx = 0
        if start_after is not None:
            order = [s.value for s in chain]
            start_idx = order.index(start_after.value) + 1
            step_ctx.apply_dispatched = True

        for kind in chain[start_idx:]:
            if ctx.is_cancel_requested():
                if step_ctx.apply_dispatched:
                    return (
                        "RecoveryRequired",
                        "cancel after partial apply requires verify/compensate",
                        {
                            "operation_id": ctx.operation_id,
                            "job_id": ctx.job_id,
                            "status": "RecoveryRequired",
                            "step": kind.value,
                        },
                    )
                return "Cancelled", "cancelled at safe boundary", None
            status, summary, body = self._run_checkpointed_step(
                ctx, store, kind, request, step_ctx
            )
            if status != "Succeeded":
                return status, summary, body
            if kind == StepKind.BACKUP and step_ctx.backup is not None:
                content_bytes = json.dumps(
                    {
                        "fake": True,
                        "artifact_id": step_ctx.backup.artifact_id.value,
                        "semantic_digest": step_ctx.backup.content_digest,
                    },
                    sort_keys=True,
                ).encode("utf-8")
                from router_control.persistence.artifacts import compute_content_digest

                published_digest = compute_content_digest(content_bytes)
                try:
                    backup_artifact_id = self.backup_publisher.publish(
                        artifact_id=step_ctx.backup.artifact_id.value,
                        router_id=request.router_id.value,
                        operation_id=request.operation_id.value,
                        content_bytes=content_bytes,
                        content_digest=published_digest,
                        identity_fingerprint=step_ctx.backup.identity_fingerprint_digest,
                        now=self.clock.now(),
                    )
                    store.upsert_router_safety_session(
                        router_id=ctx.router_id,
                        safety_state=SafetyState.READY.value,
                        fail_safe_active=step_ctx.fail_safe_began,
                        reboot_marker=step_ctx.boot_marker,
                        baseline_revision_id=request.desired_revision.revision_id.value,
                        safety_payload=_safety_payload_for_step(
                            step_ctx,
                            request,
                            ctx,
                            backup_artifact_ref=backup_artifact_id,
                        ),
                        now=self.clock.now(),
                    )
                except Exception as exc:
                    return "Failed", type(exc).__name__, {"error": type(exc).__name__}

        return (
            "Succeeded",
            "fake apply lifecycle converged",
            {
                "operation_id": ctx.operation_id,
                "job_id": ctx.job_id,
                "status": "Succeeded",
                "plan_id": request.plan.plan_id.value,
                "backup_artifact_id": backup_artifact_id,
                "aggregate_status": step_ctx.aggregate_status or ReconcileStatus.CONVERGED.value,
            },
        )

    def _run_checkpointed_step(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        kind: StepKind,
        request: _ProvisioningBundle,
        step_ctx: _StepContext,
    ) -> tuple[str, str, dict[str, Any] | None]:
        backup_id = step_ctx.backup.artifact_id.value if step_ctx.backup else None
        self._checkpoint(
            ctx,
            store,
            kind,
            "Running",
            apply_dispatched=step_ctx.apply_dispatched,
            backup_artifact_id=backup_id,
        )
        if self.hooks.step_delay_seconds > 0:
            ctx.sleeper_sleep(self.hooks.step_delay_seconds)
        ctx.ensure_lease()

        try:
            if self.hooks.crash_after_step == kind or self.hooks.crash_after_checkpoint:
                raise RuntimeError(f"injected crash after {kind.value}")
            self._adapter_step(kind, request, step_ctx, ctx, store)
        except RecoveryRequired as exc:
            self._checkpoint(
                ctx,
                store,
                kind,
                "RecoveryRequired",
                apply_dispatched=step_ctx.apply_dispatched,
                backup_artifact_id=backup_id,
                error=type(exc).__name__,
            )
            return (
                "RecoveryRequired",
                str(exc),
                {
                    "operation_id": ctx.operation_id,
                    "job_id": ctx.job_id,
                    "status": "RecoveryRequired",
                    "step": kind.value,
                },
            )
        except UnknownExternalOutcome as exc:
            if step_ctx.effect_id or step_ctx.apply_dispatched:
                self._mark_effect_unknown(
                    store, step_ctx.effect_id, exec_ctx=ctx
                )
            self._checkpoint(
                ctx,
                store,
                kind,
                "RecoveryRequired",
                apply_dispatched=step_ctx.apply_dispatched or bool(step_ctx.effect_id),
                backup_artifact_id=backup_id,
                error=type(exc).__name__,
            )
            return (
                "RecoveryRequired",
                str(exc),
                {
                    "operation_id": ctx.operation_id,
                    "job_id": ctx.job_id,
                    "status": "RecoveryRequired",
                    "step": kind.value,
                },
            )
        except DomainError as exc:
            post_dispatch = self._post_dispatch_uncertain(step_ctx, store)
            if post_dispatch:
                if step_ctx.effect_id:
                    self._mark_effect_unknown(
                        store, step_ctx.effect_id, exec_ctx=ctx
                    )
                self._checkpoint(
                    ctx,
                    store,
                    kind,
                    "RecoveryRequired",
                    apply_dispatched=True,
                    backup_artifact_id=backup_id,
                    error=type(exc).__name__,
                )
                return (
                    "RecoveryRequired",
                    str(exc),
                    {
                        "operation_id": ctx.operation_id,
                        "job_id": ctx.job_id,
                        "status": "RecoveryRequired",
                        "step": kind.value,
                        "error": type(exc).__name__,
                    },
                )
            self._checkpoint(
                ctx,
                store,
                kind,
                "Failed",
                apply_dispatched=step_ctx.apply_dispatched,
                backup_artifact_id=backup_id,
                error=type(exc).__name__,
            )
            return (
                "Failed",
                str(exc),
                {"error": type(exc).__name__, "step": kind.value},
            )
        except Exception as exc:
            post_dispatch = step_ctx.apply_dispatched or bool(step_ctx.effect_id)
            if post_dispatch and step_ctx.effect_id:
                self._mark_effect_unknown(
                    store, step_ctx.effect_id, exec_ctx=ctx
                )
            terminal = "RecoveryRequired" if post_dispatch else "Failed"
            self._checkpoint(
                ctx,
                store,
                kind,
                terminal,
                apply_dispatched=post_dispatch,
                backup_artifact_id=backup_id,
                error=type(exc).__name__,
            )
            if terminal == "RecoveryRequired":
                return (
                    "RecoveryRequired",
                    type(exc).__name__,
                    {
                        "operation_id": ctx.operation_id,
                        "job_id": ctx.job_id,
                        "status": "RecoveryRequired",
                        "step": kind.value,
                        "error": type(exc).__name__,
                    },
                )
            return "Failed", type(exc).__name__, {"error": type(exc).__name__}

        if kind == StepKind.APPLY:
            step_ctx.apply_dispatched = True
        self._checkpoint(
            ctx,
            store,
            kind,
            "Succeeded",
            apply_dispatched=step_ctx.apply_dispatched,
            backup_artifact_id=backup_id,
        )
        return "Succeeded", kind.value, None

    def _adapter_step(
        self,
        kind: StepKind,
        request: _ProvisioningBundle,
        step_ctx: _StepContext,
        exec_ctx: ExecutorContext,
        store: PersistenceStore,
    ) -> None:
        now = self.clock.now()
        if kind == StepKind.PREFLIGHT:
            if request.router_id != request.expected_identity.router_id:
                raise IdentityMismatch("router_id mismatch")
            assert_desired_matches_plan(request.desired_revision, request.plan)
            return
        if kind == StepKind.IDENTITY_CHECK:
            result = asyncio.run(self.adapter.check_identity(request.expected_identity))
            if not result.matched:
                raise IdentityMismatch("identity mismatch")
            assert_identity_match(
                request.expected_identity, result.observed_fingerprint_digest
            )
            return
        if kind == StepKind.OBSERVE:
            observation = asyncio.run(self.adapter.observe(request.router_id))
            assert_observation_fresh(observation, now)
            assert_observation_matches_plan(observation, request.plan)
            assert_identity_match(
                request.expected_identity, observation.identity_fingerprint_digest
            )
            capability = asyncio.run(self.adapter.get_capabilities(request.router_id))
            assert_capability_allows_write(capability, now)
            return
        if kind == StepKind.BACKUP:
            step_ctx.backup = asyncio.run(
                self.adapter.create_backup(request.router_id, request.operation_id)
            )
            _executor_test_barrier("artifact")
            store.upsert_router_safety_session(
                router_id=exec_ctx.router_id,
                safety_state=SafetyState.READY.value,
                fail_safe_active=step_ctx.fail_safe_began,
                reboot_marker=step_ctx.boot_marker,
                baseline_revision_id=request.desired_revision.revision_id.value,
                safety_payload=_safety_payload_for_step(
                    step_ctx, request, exec_ctx, fail_safe_status="inactive"
                ),
                now=now,
            )
            return
        if kind == StepKind.PLAN_PRECONDITIONS:
            assert_plan_valid(request.plan, now, self.clock)
            if not request.confirmed:
                raise PlanUnconfirmed("Confirm gate not satisfied")
            assert_no_unmanaged_conflict(
                request.managed_resources, request.conflicting_unmanaged_locators, request.plan
            )
            return
        if kind == StepKind.CONFIRM:
            return
        if kind == StepKind.BEGIN_FAIL_SAFE:
            asyncio.run(self.adapter.begin_fail_safe(request.router_id))
            step_ctx.fail_safe_began = True
            fail_safe_deadline = (
                now + timedelta(minutes=30)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            _executor_test_barrier("fail-safe")
            store.upsert_router_safety_session(
                router_id=exec_ctx.router_id,
                safety_state=SafetyState.READY.value,
                fail_safe_active=True,
                reboot_marker=step_ctx.boot_marker,
                baseline_revision_id=request.desired_revision.revision_id.value,
                safety_payload=_safety_payload_for_step(
                    step_ctx,
                    request,
                    exec_ctx,
                    fail_safe_status="active",
                    fail_safe_deadline=fail_safe_deadline,
                ),
                now=now,
            )
            return
        if kind == StepKind.APPLY:
            self._dispatch_apply_once(request, step_ctx, exec_ctx, store)
            return
        if kind == StepKind.READ_BACK:
            read_back = asyncio.run(
                self.adapter.read_back(request.router_id, request.plan.plan_id)
            )
            if not read_back.outcome_known:
                raise UnknownExternalOutcome("unknown external outcome")
            step_ctx.read_back = read_back
            if step_ctx.effect_id and read_back.outcome_known:
                store.transition_external_effect(
                    effect_id=step_ctx.effect_id,
                    to_state=EffectState.OBSERVED_APPLIED.value,
                    job_id=exec_ctx.job_id,
                    lease_owner=exec_ctx.lease_owner,
                    summary_redacted="read-back observed applied",
                    now=now,
                )
            return
        if kind == StepKind.VERIFY:
            _executor_test_barrier("verify")
            resolved_read_back = step_ctx.read_back
            if resolved_read_back is None:
                resolved_read_back = asyncio.run(
                    self.adapter.read_back(request.router_id, request.plan.plan_id)
                )
            verify = asyncio.run(
                self.adapter.verify_postconditions(request.plan, resolved_read_back)
            )
            if not verify.postconditions_met:
                store.upsert_router_safety_session(
                    router_id=exec_ctx.router_id,
                    safety_state=SafetyState.BLOCKED.value,
                    fail_safe_active=step_ctx.fail_safe_began,
                    reboot_marker=step_ctx.boot_marker,
                    baseline_revision_id=request.desired_revision.revision_id.value,
                    safety_payload=_safety_payload_for_step(step_ctx, request, exec_ctx),
                    now=now,
                )
                raise RecoveryRequired(
                    "verification failed — recovery compensate path required"
                )
            assert_identity_match(
                request.expected_identity, resolved_read_back.identity_fingerprint_digest
            )
            plan_row = store.get_plan(request.plan.plan_id.value)
            current_desired = store.get_desired_revision(exec_ctx.router_id)
            drifted = (
                current_desired is not None
                and str(current_desired["revision_id"]) != request.plan.revision_id.value
            )
            checks = {
                "postconditions_met": verify.postconditions_met,
                "identity_match": True,
                "drifted": drifted,
            }
            checks_json = json.dumps(checks, sort_keys=True, separators=(",", ":"))
            if plan_row is not None and plan_row["session_binding_hmac"]:
                overall = store.finalize_verify_success(
                    plan_id=request.plan.plan_id.value,
                    job_id=exec_ctx.job_id,
                    lease_owner=exec_ctx.lease_owner,
                    effect_id=step_ctx.effect_id,
                    readback_identity_fingerprint=resolved_read_back.identity_fingerprint_digest,
                    readback_resource_version=resolved_read_back.resource_version,
                    readback_state_digest=resolved_read_back.state_digest,
                    verify_digest=verify.verify_digest,
                    checks_json=checks_json,
                    revision_id=request.plan.revision_id.value,
                    router_id=exec_ctx.router_id,
                    now=now,
                )
                if overall == "drifted":
                    step_ctx.aggregate_status = ReconcileStatus.DRIFTED.value
                return
            if drifted:
                step_ctx.aggregate_status = ReconcileStatus.DRIFTED.value
            store.record_evidence_revision(
                router_id=exec_ctx.router_id,
                evidence_kind=EvidenceKind.RUNTIME_APPLIED.value,
                digest=verify.verify_digest,
                revision_id=request.plan.revision_id.value,
                now=now,
            )
            store.upsert_router_safety_session(
                router_id=exec_ctx.router_id,
                safety_state=SafetyState.READY.value,
                fail_safe_active=step_ctx.fail_safe_began,
                reboot_marker=step_ctx.boot_marker,
                baseline_revision_id=request.desired_revision.revision_id.value,
                verified_runtime_revision_id=request.plan.revision_id.value,
                now=now,
            )
            if step_ctx.effect_id:
                row = store.get_external_effect(step_ctx.effect_id)
                observed = EffectState.OBSERVED_APPLIED.value
                if row is not None and str(row["current_state"]) != observed:
                    store.transition_external_effect(
                        effect_id=step_ctx.effect_id,
                        to_state=EffectState.OBSERVED_APPLIED.value,
                        job_id=exec_ctx.job_id,
                        lease_owner=exec_ctx.lease_owner,
                        summary_redacted="verify observed applied",
                        now=now,
                    )
            return
        if kind == StepKind.SAVE:
            _executor_test_barrier("save")
            save_result = asyncio.run(self.adapter.save_configuration(request.router_id))
            store.record_evidence_revision(
                router_id=exec_ctx.router_id,
                evidence_kind=EvidenceKind.STARTUP_SAVED.value,
                digest=save_result.saved_digest,
                revision_id=request.plan.revision_id.value,
                now=now,
            )
            store.upsert_router_safety_session(
                router_id=exec_ctx.router_id,
                safety_state=SafetyState.READY.value,
                fail_safe_active=False,
                reboot_marker=step_ctx.boot_marker,
                baseline_revision_id=request.desired_revision.revision_id.value,
                verified_runtime_revision_id=request.plan.revision_id.value,
                startup_saved_revision_id=request.plan.revision_id.value,
                now=now,
            )
            return
        if kind == StepKind.COMPENSATE:
            if step_ctx.backup is None:
                raise DomainError("no backup for compensate")
            store.assert_router_boot_known(exec_ctx.router_id)
            before = asyncio.run(
                self.adapter.read_back(request.router_id, request.plan.plan_id)
            )
            asyncio.run(self.adapter.compensate(request.router_id, step_ctx.backup))
            after = asyncio.run(
                self.adapter.read_back(request.router_id, request.plan.plan_id)
            )
            if not after.outcome_known:
                raise UnknownExternalOutcome("compensate outcome unknown")
            if before.state_digest == after.state_digest:
                raise RecoveryRequired("compensate did not restore baseline")
            return

    def _initialize_safety_and_boot(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        request: _ProvisioningBundle,
    ) -> None:
        existing = store.get_router_safety_session(ctx.router_id)
        if existing is not None and str(existing["safety_state"]) == SafetyState.BLOCKED.value:
            return
        boot_marker = f"boot:simulated:{ctx.job_id}"
        store.record_router_boot_observation(
            router_id=ctx.router_id,
            boot_id=f"boot-{ctx.job_id}",
            boot_known=True,
            boot_marker=boot_marker,
            now=self.clock.now(),
        )
        store.upsert_router_safety_session(
            router_id=ctx.router_id,
            safety_state=SafetyState.READY.value,
            reboot_marker=boot_marker,
            baseline_revision_id=request.desired_revision.revision_id.value,
            safety_payload={
                "baseline_observation": boot_marker,
                "fail_safe_status": "inactive",
                "expected_reboot_outage": False,
                "authorization_ref": ctx.operation_id,
            },
            now=self.clock.now(),
        )

    def _assert_mutation_allowed(self, store: PersistenceStore, router_id: str) -> None:
        row = store.get_router_safety_session(router_id)
        if row is not None and str(row["safety_state"]) == SafetyState.BLOCKED.value:
            raise RecoveryRequired("router safety session blocked")

    def _post_dispatch_uncertain(
        self,
        step_ctx: _StepContext,
        store: PersistenceStore,
    ) -> bool:
        if step_ctx.apply_dispatched:
            return True
        if not step_ctx.effect_id:
            return False
        row = store.get_external_effect(step_ctx.effect_id)
        if row is None:
            return False
        return str(row["current_state"]) in (
            EffectState.DISPATCHING.value,
            EffectState.ACKNOWLEDGED.value,
            EffectState.UNKNOWN.value,
            EffectState.OBSERVED_PARTIAL.value,
        )

    def _mark_effect_unknown(
        self,
        store: PersistenceStore,
        effect_id: str | None,
        *,
        exec_ctx: ExecutorContext,
    ) -> None:
        now = self.clock.now()
        if effect_id:
            row = store.get_external_effect(effect_id)
            if row is not None and str(row["current_state"]) in (
                EffectState.DISPATCHING.value,
                EffectState.ACKNOWLEDGED.value,
            ):
                store.transition_external_effect(
                    effect_id=effect_id,
                    to_state=EffectState.UNKNOWN.value,
                    job_id=exec_ctx.job_id,
                    lease_owner=exec_ctx.lease_owner,
                    summary_redacted="uncertain external outcome",
                    now=now,
                )
        store.upsert_router_safety_session(
            router_id=exec_ctx.router_id,
            safety_state=SafetyState.BLOCKED.value,
            safety_payload={
                "fail_safe_status": "blocked",
                "expected_reboot_outage": True,
            },
            now=now,
        )

    def _dispatch_apply_once(
        self,
        request: _ProvisioningBundle,
        step_ctx: _StepContext,
        exec_ctx: ExecutorContext,
        store: PersistenceStore,
    ) -> None:
        self._assert_mutation_allowed(store, exec_ctx.router_id)
        store.assert_router_boot_known(exec_ctx.router_id)
        effect_key = f"apply:{request.plan.plan_id.value}"
        effect_id = store.create_external_effect(
            router_id=exec_ctx.router_id,
            effect_key=effect_key,
            operation_id=exec_ctx.operation_id,
            job_id=exec_ctx.job_id,
            lease_owner=exec_ctx.lease_owner,
            now=self.clock.now(),
        )
        step_ctx.effect_id = effect_id
        _executor_test_barrier("effect")
        store.transition_external_effect(
            effect_id=effect_id,
            to_state=EffectState.DISPATCHING.value,
            job_id=exec_ctx.job_id,
            lease_owner=exec_ctx.lease_owner,
            summary_redacted="dispatching apply",
            now=self.clock.now(),
        )
        if self.hooks.crash_after_dispatching:
            raise RuntimeError("injected crash after dispatching")
        _executor_test_barrier("dispatching")
        try:
            apply_result = asyncio.run(self.adapter.apply_plan(request.plan))
        except Exception:
            self._mark_effect_unknown(store, effect_id, exec_ctx=exec_ctx)
            raise
        _executor_test_barrier("apply-response")
        store.transition_external_effect(
            effect_id=effect_id,
            to_state=EffectState.ACKNOWLEDGED.value,
            job_id=exec_ctx.job_id,
            lease_owner=exec_ctx.lease_owner,
            summary_redacted="apply acknowledged",
            now=self.clock.now(),
        )
        if apply_result.continuation_token:
            store.upsert_effect_continuation(
                effect_id=effect_id,
                continuation_key=apply_result.continuation_token,
                state="Pending",
                job_id=exec_ctx.job_id,
                lease_owner=exec_ctx.lease_owner,
                now=self.clock.now(),
            )
        apply_result = self._poll_apply_continuations(
            request, apply_result, effect_id, store, exec_ctx
        )
        if apply_result.continuation_token is None and not _apply_continued(apply_result):
            store.upsert_effect_continuation(
                effect_id=effect_id,
                continuation_key=f"final:{request.plan.plan_id.value}",
                state="Complete",
                job_id=exec_ctx.job_id,
                lease_owner=exec_ctx.lease_owner,
                now=self.clock.now(),
            )

    def _poll_apply_continuations(
        self,
        request: _ProvisioningBundle,
        apply_result: ApplyResult,
        effect_id: str,
        store: PersistenceStore,
        exec_ctx: ExecutorContext,
    ) -> ApplyResult:
        poll_count = 0
        while _apply_continued(apply_result):
            poll_count += 1
            if poll_count >= MAX_APPLY_CONTINUATIONS:
                raise RecoveryRequired(
                    f"apply continuation exceeded bound ({MAX_APPLY_CONTINUATIONS})"
                )
            token = apply_result.continuation_token
            if not token:
                raise UnknownExternalOutcome("continuation without token")
            poller = getattr(self.adapter, "poll_apply_continuation", None)
            if poller is None:
                raise MutationForbidden(
                    "continuation required but adapter lacks poll — live deny"
                )
            try:
                apply_result = asyncio.run(
                    poller(request.router_id, request.plan.plan_id, token)
                )
            except UnknownExternalOutcome:
                self._mark_effect_unknown(store, effect_id, exec_ctx=exec_ctx)
                raise
            if apply_result.continuation_token:
                store.upsert_effect_continuation(
                    effect_id=effect_id,
                    continuation_key=apply_result.continuation_token,
                    state="Pending",
                    job_id=exec_ctx.job_id,
                    lease_owner=exec_ctx.lease_owner,
                    now=self.clock.now(),
                )
        return apply_result

    def _checkpoint(
        self,
        ctx: ExecutorContext,
        store: PersistenceStore,
        kind: StepKind,
        status: str,
        *,
        apply_dispatched: bool = False,
        backup_artifact_id: str | None = None,
        error: str | None = None,
    ) -> None:
        cp = checkpoint_redacted(
            phase=kind.value,
            last_safe_step=kind.value if status == "Succeeded" else None,
            backup_artifact_id=backup_artifact_id,
            apply_dispatched=apply_dispatched,
        )
        try:
            store.record_job_progress(
                job_id=ctx.job_id,
                lease_owner=ctx.lease_owner,
                fencing_token=ctx.fencing_token,
                step_kind=kind.value,
                step_status=status,
                checkpoint_json=cp,
                error_redacted=error,
                now=self.clock.now(),
            )
        except StaleFenceError as exc:
            raise LeaseLostError("stale fence on checkpoint") from exc

    def _build_request(
        self, ctx: ExecutorContext, store: PersistenceStore, plan_id: str
    ) -> _ProvisioningBundle | None:
        plan_row = store.get_plan(plan_id)
        if plan_row is None:
            return None
        router = store.get_router(ctx.router_id)
        if router is None:
            return None
        rev = store.get_desired_revision(ctx.router_id)
        if rev is None:
            return None
        items_rows = store.list_plan_items(plan_id)
        if items_rows:
            items = tuple(
                ChangePlanItem(
                    resource_id=ResourceId(str(r["target_resource_id"] or r["plan_item_id"])),
                    intent_kind=str(r["change_kind"]),
                    intent_digest="digest:intent:001",
                )
                for r in items_rows
            )
        else:
            items = (
                ChangePlanItem(
                    resource_id=ResourceId("resource-fake-001"),
                    intent_kind="ensure-managed-assignment",
                    intent_digest="digest:intent:001",
                ),
            )
        plan = ChangePlan(
            plan_id=PlanId(plan_id),
            router_id=RouterId(ctx.router_id),
            revision_id=RevisionId(str(plan_row["revision_id"])),
            observation_id=ObservationId(str(plan_row["observation_id"])),
            expected_desired_digest=str(plan_row["expected_desired_digest"]),
            observed_resource_version=str(plan_row["observed_resource_version"]),
            items=items,
            confirmation_state=PlanConfirmationState(str(plan_row["confirmation_state"])),
            expires_at=_parse_ts(str(plan_row["expires_at"])),
            created_at=_parse_ts(str(plan_row["created_at"])),
            actor=str(plan_row["confirmed_by_actor"] or "operator"),
        )
        desired = DesiredRevision(
            revision_id=RevisionId(str(rev["revision_id"])),
            router_id=RouterId(ctx.router_id),
            revision_number=int(rev["revision_number"]),
            desired_digest=str(rev["canonical_digest"]),
            based_on_observation_id=ObservationId(str(rev["based_on_observation_id"])),
            created_at=_parse_ts(str(rev["created_at"])),
        )
        identity = _adapter_identity(self.adapter, router, ctx.router_id)
        managed = tuple(
            ManagedResource(
                resource_id=item.resource_id,
                router_id=RouterId(ctx.router_id),
                resource_kind="tunnel-assignment",
                logical_key="recovery-test",
                owner="router-control",
                revision_id=RevisionId(str(plan_row["revision_id"])),
                external_locator_digest="digest:locator:managed-001",
                lifecycle=ManagedResourceLifecycle.PRESENT,
                last_observation_id=ObservationId(str(plan_row["observation_id"])),
            )
            for item in items
        )
        return _ProvisioningBundle(
            router_id=RouterId(ctx.router_id),
            expected_identity=identity,
            desired_revision=desired,
            plan=plan,
            managed_resources=managed,
            operation_id=OperationId(ctx.operation_id),
            confirmed=str(plan_row["confirmation_state"]) == "Confirmed",
            conflicting_unmanaged_locators=(),
        )


@dataclass(frozen=True, slots=True)
class _ProvisioningBundle:
    router_id: RouterId
    expected_identity: RouterIdentity
    desired_revision: DesiredRevision
    plan: ChangePlan
    managed_resources: tuple[Any, ...]
    operation_id: OperationId
    confirmed: bool
    conflicting_unmanaged_locators: tuple[str, ...]


def _parse_ts(raw: str) -> datetime:
    return datetime.fromisoformat(raw.replace("Z", "+00:00"))


def _apply_continued(result: ApplyResult) -> bool:
    return result.continued or bool(result.continuation_token)


def _resolve_plan_id(
    ctx: ExecutorContext, store: PersistenceStore, dispatch_payload: dict[str, Any]
) -> str:
    plan_id = str(dispatch_payload.get("plan_id") or "")
    if plan_id:
        return plan_id
    op = store.get_operation(ctx.operation_id)
    if op is not None and op["plan_id"]:
        return str(op["plan_id"])
    return ""


def _resolve_backup_artifact_id(
    store: PersistenceStore, job_id: str, dispatch_payload: dict[str, Any]
) -> str:
    artifact_id = str(dispatch_payload.get("backup_artifact_id") or "")
    if artifact_id:
        return artifact_id
    for step in reversed(store.list_job_steps(job_id)):
        cp = step["checkpoint_json"]
        if not cp:
            continue
        try:
            data = json.loads(str(cp))
            found = str(data.get("backup_artifact_id") or "")
            if found:
                return found
        except json.JSONDecodeError as exc:
            # Skip corrupt checkpoints while scanning older steps for backup ref.
            logging.getLogger(__name__).debug(
                "job step checkpoint_json invalid job=%s: %s",
                job_id,
                type(exc).__name__,
            )
            continue
    return ""


def _adapter_identity(adapter: RouterControlPort, router: Any, router_id: str) -> RouterIdentity:
    if hasattr(adapter, "state"):
        state = adapter.state
        if hasattr(state, "identity"):
            identity = state.identity
            if isinstance(identity, RouterIdentity):
                return identity
    return RouterIdentity(
        router_id=RouterId(router_id),
        vendor=str(router["vendor"]),
        model=str(router["model"]),
        fingerprint_digest=str(router["identity_fingerprint"]),
    )


def _stub_desired(router_id: str) -> DesiredRevision:
    return DesiredRevision(
        revision_id=RevisionId("revision-stub"),
        router_id=RouterId(router_id),
        revision_number=1,
        desired_digest="digest:desired:stub",
        based_on_observation_id=ObservationId("observation-stub"),
        created_at=_parse_ts("2026-07-22T12:00:00Z"),
    )


def _stub_plan(router_id: str) -> ChangePlan:
    return ChangePlan(
        plan_id=PlanId("plan-stub"),
        router_id=RouterId(router_id),
        revision_id=RevisionId("revision-stub"),
        observation_id=ObservationId("observation-stub"),
        expected_desired_digest="digest:desired:stub",
        observed_resource_version="digest:rv:stub",
        items=(
            ChangePlanItem(
                resource_id=ResourceId("resource-stub"),
                intent_kind="ensure-managed-assignment",
                intent_digest="digest:intent:stub",
            ),
        ),
        confirmation_state=PlanConfirmationState.CONFIRMED,
        expires_at=_parse_ts("2026-07-23T12:00:00Z"),
        created_at=_parse_ts("2026-07-22T12:00:00Z"),
        actor="operator",
    )


def _executor_test_barrier(at: str) -> None:
    barrier_path = os.environ.get("ROUTER_CONTROL_EXECUTOR_TEST_BARRIER")
    pause_at = os.environ.get("ROUTER_CONTROL_EXECUTOR_PAUSE_AT")
    if not barrier_path or pause_at != at:
        return
    marker = Path(barrier_path)
    marker.write_text(f"at:{at}", encoding="utf-8")
    if os.environ.get("ROUTER_CONTROL_EXECUTOR_BARRIER_SPIN") == "1":
        while marker.read_text(encoding="utf-8") != "release":
            time.sleep(0.05)


def _safety_payload_for_step(
    step_ctx: _StepContext,
    request: _ProvisioningBundle,
    exec_ctx: ExecutorContext,
    *,
    backup_artifact_ref: str | None = None,
    fail_safe_status: str | None = None,
    fail_safe_deadline: str | None = None,
    authorization_ref: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "baseline_observation": step_ctx.boot_marker,
        "expected_reboot_outage": False,
    }
    if backup_artifact_ref:
        payload["backup_artifact_ref"] = backup_artifact_ref
    elif step_ctx.backup is not None:
        payload["backup_artifact_ref"] = step_ctx.backup.artifact_id.value
    if fail_safe_status is not None:
        payload["fail_safe_status"] = fail_safe_status
        if fail_safe_deadline:
            payload["fail_safe_deadline"] = fail_safe_deadline
    elif step_ctx.fail_safe_began:
        payload["fail_safe_status"] = "active"
    else:
        payload["fail_safe_status"] = "inactive"
    payload["authorization_ref"] = authorization_ref or exec_ctx.operation_id
    payload["baseline_revision_id"] = request.desired_revision.revision_id.value
    return payload
