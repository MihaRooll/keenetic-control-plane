"""Core domain enumerations."""

from __future__ import annotations

from enum import StrEnum


class CertificationStatus(StrEnum):
    UNKNOWN = "Unknown"
    READ_ONLY_CERTIFIED = "ReadOnlyCertified"
    WRITE_CERTIFIED = "WriteCertified"
    UNSUPPORTED = "Unsupported"


class RouterLifecycleStatus(StrEnum):
    PENDING_ENROLLMENT = "PendingEnrollment"
    ENROLLED = "Enrolled"
    IDENTITY_MISMATCH = "IdentityMismatch"
    DISABLED = "Disabled"


class PlanConfirmationState(StrEnum):
    PENDING = "Pending"
    CONFIRMED = "Confirmed"
    EXPIRED = "Expired"


class ReconcileStatus(StrEnum):
    PENDING = "Pending"
    PLANNING = "Planning"
    APPLYING = "Applying"
    VERIFYING = "Verifying"
    CONVERGED = "Converged"
    DRIFTED = "Drifted"
    FAILED = "Failed"
    RECOVERY_REQUIRED = "RecoveryRequired"


class ManagedResourceLifecycle(StrEnum):
    PLANNED = "Planned"
    PRESENT = "Present"
    MISSING = "Missing"
    RETIRED = "Retired"


class ObservationCollectionStatus(StrEnum):
    PENDING = "Pending"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"


class StepKind(StrEnum):
    PREFLIGHT = "preflight"
    IDENTITY_CHECK = "identity-check"
    OBSERVE = "observe"
    BACKUP = "backup"
    PLAN_PRECONDITIONS = "plan-preconditions"
    CONFIRM = "Confirm"
    BEGIN_FAIL_SAFE = "begin-fail-safe-configuration"
    APPLY = "apply"
    READ_BACK = "read-back"
    VERIFY = "verify"
    SAVE = "save"
    COMPENSATE = "compensate"
