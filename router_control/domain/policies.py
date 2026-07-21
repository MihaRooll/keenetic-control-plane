"""Domain policy checks (fail-closed invariants)."""

from __future__ import annotations

from datetime import datetime

from router_control.domain.entities import (
    ChangePlan,
    DesiredRevision,
    ManagedResource,
    RouterCapability,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.enums import (
    CertificationStatus,
    ObservationCollectionStatus,
    PlanConfirmationState,
)
from router_control.domain.errors import (
    CapabilityExpired,
    CapabilityUnknown,
    CapabilityUnsupported,
    IdentityMismatch,
    PlanExpired,
    PlanUnconfirmed,
    StaleObservation,
    UnmanagedConflict,
)
from router_control.ports.clock import ClockPort


def assert_endpoint_not_identity(endpoint: str, identity: RouterIdentity) -> None:
    """IP/endpoint must not be treated as router identity."""
    if endpoint.strip() and endpoint.strip() == identity.router_id.value:
        raise ValueError("endpoint must not equal router identity")


def assert_identity_match(expected: RouterIdentity, observed_fingerprint: str) -> None:
    if expected.fingerprint_digest != observed_fingerprint:
        raise IdentityMismatch("identity fingerprint mismatch — hard abort")


def assert_capability_allows_write(capability: RouterCapability, now: datetime) -> None:
    if capability.certification_status is CertificationStatus.UNKNOWN:
        raise CapabilityUnknown("capability unknown — writes blocked")
    if capability.certification_status is CertificationStatus.UNSUPPORTED:
        raise CapabilityUnsupported("capability unsupported — writes blocked")
    if now > capability.valid_until:
        raise CapabilityExpired("capability expired — writes blocked")
    if capability.certification_status is not CertificationStatus.WRITE_CERTIFIED:
        raise CapabilityUnsupported("write certification required — writes blocked")


def assert_observation_fresh(observation: RouterObservation, now: datetime) -> None:
    if observation.collection_status is not ObservationCollectionStatus.SUCCEEDED:
        raise StaleObservation("observation collection failed — cannot plan or apply")
    if now > observation.valid_until:
        raise StaleObservation("observation stale — fresh observe required")


def assert_plan_valid(plan: ChangePlan, now: datetime, clock: ClockPort) -> None:
    _ = clock
    if plan.confirmation_state is PlanConfirmationState.EXPIRED:
        raise PlanExpired("plan expired")
    if now > plan.expires_at:
        raise PlanExpired("plan past expiry")
    if plan.confirmation_state is not PlanConfirmationState.CONFIRMED:
        raise PlanUnconfirmed("plan not confirmed")


def assert_no_unmanaged_conflict(
    managed_resources: tuple[ManagedResource, ...],
    conflicting_locator_digests: tuple[str, ...],
    plan: ChangePlan,
) -> None:
    managed_locators = {resource.external_locator_digest for resource in managed_resources}
    managed_resource_ids = {resource.resource_id for resource in managed_resources}
    for digest in conflicting_locator_digests:
        if digest not in managed_locators:
            raise UnmanagedConflict("unmanaged resource conflict — unmanaged resources preserved")
    for item in plan.items:
        if item.resource_id not in managed_resource_ids:
            raise UnmanagedConflict("plan item targets unmanaged resource — apply blocked")


def assert_desired_matches_plan(desired: DesiredRevision, plan: ChangePlan) -> None:
    if desired.revision_id != plan.revision_id:
        raise ValueError("plan revision mismatch")
    if desired.desired_digest != plan.expected_desired_digest:
        raise ValueError("plan desired digest mismatch")


def assert_observation_matches_plan(observation: RouterObservation, plan: ChangePlan) -> None:
    if observation.observation_id != plan.observation_id:
        raise StaleObservation("plan observation mismatch — replan required")
    if observation.resource_version != plan.observed_resource_version:
        raise StaleObservation("plan observed resource version mismatch — replan required")
