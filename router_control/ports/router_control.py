"""Vendor-neutral router control port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from router_control.domain.entities import (
    BackupArtifact,
    ChangePlan,
    RouterCapability,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.ids import OperationId, PlanId, RouterId


@dataclass(frozen=True, slots=True)
class IdentityCheckResult:
    matched: bool
    observed_fingerprint_digest: str


@dataclass(frozen=True, slots=True)
class FailSafeSession:
    session_digest: str
    active: bool


@dataclass(frozen=True, slots=True)
class ApplyResult:
    plan_id: PlanId
    outcome_digest: str
    continued: bool


@dataclass(frozen=True, slots=True)
class ReadBackResult:
    plan_id: PlanId
    state_digest: str
    resource_version: str
    identity_fingerprint_digest: str
    outcome_known: bool


@dataclass(frozen=True, slots=True)
class VerifyResult:
    plan_id: PlanId
    postconditions_met: bool
    verify_digest: str


@dataclass(frozen=True, slots=True)
class SaveResult:
    router_id: RouterId
    saved_digest: str


@dataclass(frozen=True, slots=True)
class CompensateResult:
    router_id: RouterId
    restored_digest: str
    success: bool


class RouterControlPort(Protocol):
    async def check_identity(self, expected: RouterIdentity) -> IdentityCheckResult: ...

    async def get_capabilities(self, router_id: RouterId) -> RouterCapability: ...

    async def observe(self, router_id: RouterId) -> RouterObservation: ...

    async def create_backup(
        self, router_id: RouterId, operation_id: OperationId
    ) -> BackupArtifact: ...

    async def begin_fail_safe(self, router_id: RouterId) -> FailSafeSession: ...

    async def apply_plan(self, plan: ChangePlan) -> ApplyResult: ...

    async def read_back(self, router_id: RouterId, plan_id: PlanId) -> ReadBackResult: ...

    async def verify_postconditions(
        self, plan: ChangePlan, read_back: ReadBackResult
    ) -> VerifyResult: ...

    async def save_configuration(self, router_id: RouterId) -> SaveResult: ...

    async def compensate(
        self, router_id: RouterId, backup: BackupArtifact
    ) -> CompensateResult: ...
