"""Deterministic in-memory FakeRouterAdapter (no network/file/process I/O)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import StrEnum

from router_control.adapters.fake.evidence import FakeAdapterEvidence
from router_control.domain.entities import (
    BackupArtifact,
    ChangePlan,
    RouterCapability,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.enums import (
    CertificationStatus,
    ObservationCollectionStatus,
)
from router_control.domain.errors import (
    FailSafeTimeout,
    IdentityMismatch,
    RecoveryRequired,
    UnknownExternalOutcome,
    UnmanagedConflict,
)
from router_control.domain.ids import (
    ArtifactId,
    CapabilityId,
    ObservationId,
    OperationId,
    PlanId,
    RouterId,
)
from router_control.ports.clock import ClockPort
from router_control.ports.router_control import (
    ApplyResult,
    CompensateResult,
    FailSafeSession,
    IdentityCheckResult,
    ReadBackResult,
    SaveResult,
    VerifyResult,
)


class FakeMode(StrEnum):
    NORMAL = "normal"
    IDENTITY_MISMATCH = "identity_mismatch"
    UNKNOWN_CAPABILITY = "unknown_capability"
    STALE_OBSERVATION = "stale_observation"
    PARTIAL_ASYNC = "partial_async"
    ALWAYS_CONTINUED = "always_continued"
    UNKNOWN_EXTERNAL_OUTCOME = "unknown_external_outcome"
    FAIL_SAFE_TIMEOUT = "fail_safe_timeout"
    UNMANAGED_CONFLICT = "unmanaged_conflict"
    VERIFY_FAILURE = "verify_failure"
    EXPIRED_CAPABILITY = "expired_capability"


@dataclass(frozen=True, slots=True)
class _MutableStateSnapshot:
    state_digest: str
    resource_version: str
    applied_plan_digest: str | None


@dataclass
class FakeRouterState:
    identity: RouterIdentity
    capability_status: CertificationStatus = CertificationStatus.WRITE_CERTIFIED
    state_digest: str = "digest:state:baseline"
    resource_version: str = "digest:rv:001"
    applied_plan_digest: str | None = None
    fail_safe_active: bool = False
    backup_digest: str = "digest:backup:baseline"
    unmanaged_locator_digest: str = "digest:locator:unmanaged-001"
    partial_apply_pending: bool = False


@dataclass
class FakeRouterConfig:
    mode: FakeMode = FakeMode.NORMAL
    observation_ttl: timedelta = timedelta(minutes=5)
    capability_ttl: timedelta = timedelta(hours=1)


@dataclass
class FakeRouterAdapter:
    clock: ClockPort
    state: FakeRouterState
    config: FakeRouterConfig = field(default_factory=FakeRouterConfig)
    call_trace: list[str] = field(default_factory=list)
    evidence: FakeAdapterEvidence = field(default_factory=FakeAdapterEvidence.fake_only)
    _apply_continuation_pending: bool = field(default=False, init=False)
    _mutable_snapshot: _MutableStateSnapshot | None = field(default=None, init=False)

    def _record(self, name: str) -> None:
        self.call_trace.append(name)

    def _now(self) -> datetime:
        return self.clock.now()

    def _capability(self) -> RouterCapability:
        now = self._now()
        status = self.state.capability_status
        if self.config.mode is FakeMode.UNKNOWN_CAPABILITY:
            status = CertificationStatus.UNKNOWN
        valid_until = (
            now - timedelta(seconds=1)
            if self.config.mode is FakeMode.EXPIRED_CAPABILITY
            else now + self.config.capability_ttl
        )
        return RouterCapability(
            capability_id=CapabilityId("capability-fake-001"),
            router_id=self.state.identity.router_id,
            firmware_digest="digest:firmware:fake-001",
            certification_status=status,
            observed_at=now,
            valid_until=valid_until,
            source="fake-adapter",
        )

    def _observation(self, *, stale: bool = False) -> RouterObservation:
        now = self._now()
        valid_until = now - timedelta(seconds=1) if stale else now + self.config.observation_ttl
        fingerprint = self.state.identity.fingerprint_digest
        if self.config.mode is FakeMode.IDENTITY_MISMATCH:
            fingerprint = "digest:identity:mismatch"
        return RouterObservation(
            observation_id=ObservationId("observation-fake-001"),
            router_id=self.state.identity.router_id,
            identity_fingerprint_digest=fingerprint,
            capability_id=CapabilityId("capability-fake-001"),
            state_digest=self.state.state_digest,
            resource_version=self.state.resource_version,
            observed_at=now,
            valid_until=valid_until,
            collection_status=ObservationCollectionStatus.SUCCEEDED,
            source="fake-adapter",
        )

    async def check_identity(self, expected: RouterIdentity) -> IdentityCheckResult:
        self._record("check_identity")
        observed = self.state.identity.fingerprint_digest
        if self.config.mode is FakeMode.IDENTITY_MISMATCH:
            observed = "digest:identity:mismatch"
        matched = expected.fingerprint_digest == observed
        if not matched:
            raise IdentityMismatch("fake adapter identity mismatch")
        return IdentityCheckResult(matched=True, observed_fingerprint_digest=observed)

    async def get_capabilities(self, router_id: RouterId) -> RouterCapability:
        self._record("get_capabilities")
        if router_id != self.state.identity.router_id:
            raise ValueError("unknown router")
        return self._capability()

    async def observe(self, router_id: RouterId) -> RouterObservation:
        self._record("observe")
        if router_id != self.state.identity.router_id:
            raise ValueError("unknown router")
        stale = self.config.mode is FakeMode.STALE_OBSERVATION
        return self._observation(stale=stale)

    async def create_backup(
        self, router_id: RouterId, operation_id: OperationId
    ) -> BackupArtifact:
        self._record("create_backup")
        self._mutable_snapshot = _MutableStateSnapshot(
            state_digest=self.state.state_digest,
            resource_version=self.state.resource_version,
            applied_plan_digest=self.state.applied_plan_digest,
        )
        now = self._now()
        return BackupArtifact(
            artifact_id=ArtifactId("artifact-fake-001"),
            router_id=router_id,
            operation_id=operation_id,
            content_digest=self.state.backup_digest,
            storage_locator_digest="digest:locator:backup-fake-001",
            identity_fingerprint_digest=self.state.identity.fingerprint_digest,
            created_at=now,
        )

    async def begin_fail_safe(self, router_id: RouterId) -> FailSafeSession:
        self._record("begin_fail_safe")
        if self.config.mode is FakeMode.FAIL_SAFE_TIMEOUT:
            raise FailSafeTimeout("simulated fail-safe session timeout")
        self.state.fail_safe_active = True
        return FailSafeSession(session_digest="digest:session:fail-safe-001", active=True)

    async def apply_plan(self, plan: ChangePlan) -> ApplyResult:
        self._record("apply_plan")
        if self.config.mode is FakeMode.UNMANAGED_CONFLICT:
            raise UnmanagedConflict("unmanaged resource conflict — apply blocked")
        if self.config.mode is FakeMode.ALWAYS_CONTINUED:
            return ApplyResult(
                plan_id=plan.plan_id,
                outcome_digest="digest:apply:continued",
                continued=True,
            )
        continued = False
        if self.config.mode is FakeMode.PARTIAL_ASYNC and not self._apply_continuation_pending:
            self._apply_continuation_pending = True
            continued = True
            return ApplyResult(
                plan_id=plan.plan_id,
                outcome_digest="digest:apply:partial",
                continued=True,
            )
        self._apply_continuation_pending = False
        self.state.applied_plan_digest = plan.expected_desired_digest
        self.state.state_digest = plan.expected_desired_digest
        self.state.resource_version = f"digest:rv:{plan.plan_id.value}"
        return ApplyResult(
            plan_id=plan.plan_id,
            outcome_digest="digest:apply:complete",
            continued=continued,
        )

    async def read_back(self, router_id: RouterId, plan_id: PlanId) -> ReadBackResult:
        self._record("read_back")
        if self.config.mode is FakeMode.UNKNOWN_EXTERNAL_OUTCOME:
            return ReadBackResult(
                plan_id=plan_id,
                state_digest="digest:state:unknown",
                resource_version="digest:rv:unknown",
                identity_fingerprint_digest=self.state.identity.fingerprint_digest,
                outcome_known=False,
            )
        if self.config.mode is FakeMode.VERIFY_FAILURE:
            return ReadBackResult(
                plan_id=plan_id,
                state_digest="digest:state:verify-mismatch",
                resource_version=self.state.resource_version,
                identity_fingerprint_digest=self.state.identity.fingerprint_digest,
                outcome_known=True,
            )
        return ReadBackResult(
            plan_id=plan_id,
            state_digest=self.state.state_digest,
            resource_version=self.state.resource_version,
            identity_fingerprint_digest=self.state.identity.fingerprint_digest,
            outcome_known=True,
        )

    async def verify_postconditions(
        self, plan: ChangePlan, read_back: ReadBackResult
    ) -> VerifyResult:
        self._record("verify_postconditions")
        if not read_back.outcome_known:
            raise UnknownExternalOutcome("external mutation outcome unknown")
        identity_ok = (
            read_back.identity_fingerprint_digest
            == self.state.identity.fingerprint_digest
        )
        postconditions_met = (
            read_back.state_digest == plan.expected_desired_digest and identity_ok
        )
        return VerifyResult(
            plan_id=plan.plan_id,
            postconditions_met=postconditions_met,
            verify_digest="digest:verify:001" if postconditions_met else "digest:verify:failed",
        )

    async def save_configuration(self, router_id: RouterId) -> SaveResult:
        self._record("save_configuration")
        self.state.fail_safe_active = False
        self._mutable_snapshot = None
        return SaveResult(router_id=router_id, saved_digest=self.state.state_digest)

    async def compensate(
        self, router_id: RouterId, backup: BackupArtifact
    ) -> CompensateResult:
        self._record("compensate")
        if self._mutable_snapshot is None:
            raise RecoveryRequired(
                "no active pre-apply snapshot — cannot compensate saved/converged state"
            )
        snap = self._mutable_snapshot
        self.state.state_digest = snap.state_digest
        self.state.resource_version = snap.resource_version
        self.state.applied_plan_digest = snap.applied_plan_digest
        self.state.fail_safe_active = False
        self._apply_continuation_pending = False
        return CompensateResult(
            router_id=router_id,
            restored_digest=snap.state_digest,
            success=True,
        )

    def unmanaged_conflict_locator(self) -> str:
        return self.state.unmanaged_locator_digest
