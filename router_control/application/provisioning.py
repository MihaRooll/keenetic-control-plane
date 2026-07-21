"""Provisioning lifecycle service (in-memory, no persistence)."""

from __future__ import annotations

from dataclasses import dataclass, field

from router_control.domain.entities import (
    BackupArtifact,
    ChangePlan,
    DesiredRevision,
    ManagedResource,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.enums import PlanConfirmationState, ReconcileStatus, StepKind
from router_control.domain.errors import (
    DomainError,
    IdentityMismatch,
    RecoveryRequired,
    UnknownExternalOutcome,
)
from router_control.domain.ids import OperationId, RevisionId, RouterId
from router_control.domain.policies import (
    assert_capability_allows_write,
    assert_desired_matches_plan,
    assert_identity_match,
    assert_no_unmanaged_conflict,
    assert_observation_fresh,
    assert_observation_matches_plan,
    assert_plan_valid,
)
from router_control.ports.clock import ClockPort
from router_control.ports.router_control import ReadBackResult, RouterControlPort

MAX_APPLY_CONTINUATIONS = 8


@dataclass(frozen=True, slots=True)
class ProvisioningRequest:
    router_id: RouterId
    expected_identity: RouterIdentity
    desired_revision: DesiredRevision
    plan: ChangePlan
    managed_resources: tuple[ManagedResource, ...]
    operation_id: OperationId
    confirmed: bool
    conflicting_unmanaged_locators: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class LifecycleTrace:
    steps: tuple[StepKind, ...]
    adapter_calls: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LifecycleOutcome:
    status: ReconcileStatus
    trace: LifecycleTrace
    error: DomainError | None
    observation: RouterObservation | None
    backup: BackupArtifact | None
    applied_revision_id: RevisionId | None
    read_back: ReadBackResult | None


@dataclass
class _LifecycleContext:
    observation: RouterObservation | None = None
    backup: BackupArtifact | None = None
    read_back: ReadBackResult | None = None
    fail_safe_began: bool = False
    compensated: bool = False


@dataclass
class ProvisioningLifecycleService:
    adapter: RouterControlPort
    clock: ClockPort
    _steps: list[StepKind] = field(default_factory=list)

    def _step(self, kind: StepKind) -> None:
        self._steps.append(kind)

    async def execute(self, request: ProvisioningRequest) -> LifecycleOutcome:
        self._steps.clear()
        adapter_calls_start = len(getattr(self.adapter, "call_trace", []))
        ctx = _LifecycleContext()

        try:
            return await self._execute_inner(request, adapter_calls_start, ctx)
        except DomainError as exc:
            await self._compensate_after_fail_safe(request, ctx)
            calls = self._adapter_calls_since(adapter_calls_start)
            return LifecycleOutcome(
                status=self._status_for_error(exc),
                trace=LifecycleTrace(steps=tuple(self._steps), adapter_calls=calls),
                error=exc,
                observation=ctx.observation,
                backup=ctx.backup,
                applied_revision_id=None,
                read_back=ctx.read_back,
            )
        except ValueError as exc:
            calls = self._adapter_calls_since(adapter_calls_start)
            return LifecycleOutcome(
                status=ReconcileStatus.FAILED,
                trace=LifecycleTrace(steps=tuple(self._steps), adapter_calls=calls),
                error=DomainError(str(exc)),
                observation=ctx.observation,
                backup=ctx.backup,
                applied_revision_id=None,
                read_back=ctx.read_back,
            )

    async def _compensate_after_fail_safe(
        self, request: ProvisioningRequest, ctx: _LifecycleContext
    ) -> None:
        if ctx.fail_safe_began and not ctx.compensated and ctx.backup is not None:
            self._step(StepKind.COMPENSATE)
            await self.adapter.compensate(request.router_id, ctx.backup)
            ctx.compensated = True

    async def _execute_inner(
        self,
        request: ProvisioningRequest,
        adapter_calls_start: int,
        ctx: _LifecycleContext,
    ) -> LifecycleOutcome:
        now = self.clock.now()

        self._step(StepKind.PREFLIGHT)
        if request.router_id != request.expected_identity.router_id:
            raise IdentityMismatch(
                "request router_id does not match expected identity router_id — hard abort"
            )
        assert_desired_matches_plan(request.desired_revision, request.plan)

        self._step(StepKind.IDENTITY_CHECK)
        identity_result = await self.adapter.check_identity(request.expected_identity)
        if not identity_result.matched:
            raise IdentityMismatch("identity check reported mismatch — hard abort")
        assert_identity_match(
            request.expected_identity,
            identity_result.observed_fingerprint_digest,
        )

        self._step(StepKind.OBSERVE)
        ctx.observation = await self.adapter.observe(request.router_id)
        assert_observation_fresh(ctx.observation, now)
        assert_observation_matches_plan(ctx.observation, request.plan)
        assert_identity_match(
            request.expected_identity,
            ctx.observation.identity_fingerprint_digest,
        )

        capability = await self.adapter.get_capabilities(request.router_id)
        assert_capability_allows_write(capability, now)

        self._step(StepKind.BACKUP)
        ctx.backup = await self.adapter.create_backup(request.router_id, request.operation_id)

        self._step(StepKind.PLAN_PRECONDITIONS)
        plan = request.plan
        if not request.confirmed:
            plan = _with_confirmation(plan, PlanConfirmationState.PENDING)
        assert_plan_valid(plan, now, self.clock)
        if not request.confirmed:
            from router_control.domain.errors import PlanUnconfirmed

            raise PlanUnconfirmed("Confirm gate not satisfied")
        assert_no_unmanaged_conflict(
            request.managed_resources,
            request.conflicting_unmanaged_locators,
            plan,
        )

        self._step(StepKind.CONFIRM)

        self._step(StepKind.BEGIN_FAIL_SAFE)
        await self.adapter.begin_fail_safe(request.router_id)
        ctx.fail_safe_began = True

        self._step(StepKind.APPLY)
        apply_result = await self.adapter.apply_plan(request.plan)
        continuation_count = 0
        while apply_result.continued:
            continuation_count += 1
            if continuation_count >= MAX_APPLY_CONTINUATIONS:
                raise RecoveryRequired(
                    f"apply continuation exceeded bound ({MAX_APPLY_CONTINUATIONS})"
                )
            apply_result = await self.adapter.apply_plan(request.plan)

        self._step(StepKind.READ_BACK)
        ctx.read_back = await self.adapter.read_back(request.router_id, request.plan.plan_id)
        if not ctx.read_back.outcome_known:
            raise UnknownExternalOutcome("unknown external outcome — compensation attempted")

        self._step(StepKind.VERIFY)
        verify_result = await self.adapter.verify_postconditions(request.plan, ctx.read_back)
        if not verify_result.postconditions_met:
            raise RecoveryRequired("verification failed — recovery required")

        assert_identity_match(
            request.expected_identity,
            ctx.read_back.identity_fingerprint_digest,
        )

        self._step(StepKind.SAVE)
        await self.adapter.save_configuration(request.router_id)

        calls = self._adapter_calls_since(adapter_calls_start)
        return LifecycleOutcome(
            status=ReconcileStatus.CONVERGED,
            trace=LifecycleTrace(steps=tuple(self._steps), adapter_calls=calls),
            error=None,
            observation=ctx.observation,
            backup=ctx.backup,
            applied_revision_id=request.desired_revision.revision_id,
            read_back=ctx.read_back,
        )

    def _adapter_calls_since(self, start: int) -> tuple[str, ...]:
        trace = getattr(self.adapter, "call_trace", [])
        return tuple(trace[start:])

    @staticmethod
    def _status_for_error(exc: DomainError) -> ReconcileStatus:
        if isinstance(exc, RecoveryRequired):
            return ReconcileStatus.RECOVERY_REQUIRED
        if isinstance(exc, UnknownExternalOutcome):
            return ReconcileStatus.RECOVERY_REQUIRED
        return ReconcileStatus.FAILED


def _with_confirmation(plan: ChangePlan, state: PlanConfirmationState) -> ChangePlan:
    return ChangePlan(
        plan_id=plan.plan_id,
        router_id=plan.router_id,
        revision_id=plan.revision_id,
        observation_id=plan.observation_id,
        expected_desired_digest=plan.expected_desired_digest,
        observed_resource_version=plan.observed_resource_version,
        items=plan.items,
        confirmation_state=state,
        expires_at=plan.expires_at,
        created_at=plan.created_at,
        actor=plan.actor,
    )
