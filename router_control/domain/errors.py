"""Domain errors for Router Control."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DomainError(Exception):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True, slots=True)
class IdentityMismatch(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CapabilityUnknown(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CapabilityExpired(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CapabilityUnsupported(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class StaleObservation(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class UnmanagedConflict(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class PlanExpired(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class PlanUnconfirmed(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class UnknownExternalOutcome(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class RecoveryRequired(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class FailSafeTimeout(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class MutationForbidden(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CommissioningNotFound(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CommissioningConflict(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CommissioningPreconditionFailed(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class CommissioningCancelled(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EventPresetNotFound(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EventPresetConflict(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EventPresetIdempotencyConflict(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EventPresetPreconditionFailed(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EventPresetValidationFailed(DomainError):
    reason_code: str = "invalid_document"
    field: str | None = None


@dataclass(frozen=True, slots=True)
class WorkerJobRejected(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class LeaseLostError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class DispatchForbidden(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EvidenceManifestError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class ShapeRegistryError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class FenceExpiredError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class MutexHolderRequiredError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class RecoveryConflictError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EffectTransitionError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class UnknownBootError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class ArtifactNotRestorableError(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class SessionBindingMismatch(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class StaleCredential(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class StaleCertification(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class DigestMismatch(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class TupleMismatch(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class AdoptAcknowledgmentRequired(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class DeploymentPreconditionFailed(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class DeploymentNotFound(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class PublicationNotFound(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class PublicationPreconditionFailed(DomainError):
    pass


@dataclass(frozen=True, slots=True)
class EntryPageConflict(DomainError):
    pass
