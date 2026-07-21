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
