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


class RecoveryState(StrEnum):
    EXPIRED_LEASE = "expired_lease"
    RESUME_AFTER_LOST = "resume_after_lost"
    RESUME_AFTER_READBACK = "resume_after_readback"
    COMPENSATE = "compensate"


class EffectState(StrEnum):
    PREPARED = "Prepared"
    DISPATCHING = "Dispatching"
    ACKNOWLEDGED = "Acknowledged"
    OBSERVED_APPLIED = "ObservedApplied"
    OBSERVED_ABSENT = "ObservedAbsent"
    OBSERVED_PARTIAL = "ObservedPartial"
    UNKNOWN = "Unknown"


_EFFECT_TRANSITIONS: dict[EffectState, frozenset[EffectState]] = {
    EffectState.PREPARED: frozenset({EffectState.DISPATCHING}),
    EffectState.DISPATCHING: frozenset(
        {EffectState.ACKNOWLEDGED, EffectState.UNKNOWN}
    ),
    EffectState.ACKNOWLEDGED: frozenset(
        {
            EffectState.OBSERVED_APPLIED,
            EffectState.OBSERVED_ABSENT,
            EffectState.OBSERVED_PARTIAL,
            EffectState.UNKNOWN,
        }
    ),
    EffectState.OBSERVED_APPLIED: frozenset(),
    EffectState.OBSERVED_ABSENT: frozenset(),
    EffectState.OBSERVED_PARTIAL: frozenset({EffectState.UNKNOWN}),
    EffectState.UNKNOWN: frozenset(
        {
            EffectState.OBSERVED_APPLIED,
            EffectState.OBSERVED_ABSENT,
            EffectState.OBSERVED_PARTIAL,
        }
    ),
}


def can_transition_effect(from_state: EffectState, to_state: EffectState) -> bool:
    return to_state in _EFFECT_TRANSITIONS.get(from_state, frozenset())


class ArtifactStagingStatus(StrEnum):
    TEMP = "temp"
    WRITTEN = "written"
    FSYNCED = "fsynced"
    RENAMED = "renamed"
    PUBLISHED = "published"
    RECONCILED = "reconciled"
    ABANDONED = "abandoned"


class RecoveryRequestStatus(StrEnum):
    PENDING = "Pending"
    ACTIVE = "Active"
    SUCCEEDED = "Succeeded"
    FAILED = "Failed"
    CONFLICT = "Conflict"


class WorkerInstanceLifecycle(StrEnum):
    STARTING = "Starting"
    RUNNING = "Running"
    STOPPING = "Stopping"
    STOPPED = "Stopped"
    DEGRADED = "Degraded"


class SafetyState(StrEnum):
    UNKNOWN = "Unknown"
    READY = "Ready"
    BLOCKED = "Blocked"


class EvidenceKind(StrEnum):
    RUNTIME_APPLIED = "runtime_applied"
    STARTUP_SAVED = "startup_saved"


class ExecutionTarget(StrEnum):
    LAB = "Lab"
    PRODUCTION = "Production"


class OwnershipAction(StrEnum):
    CREATE = "Create"
    ADOPT = "Adopt"
    UPDATE = "Update"
    RETIRE = "Retire"


class FamilyCertificationLevel(StrEnum):
    LAB_PROVEN = "LabProven"
    WRITE_CERTIFIED = "WriteCertified"
    READ_ONLY_CERTIFIED = "ReadOnlyCertified"


class VerifyOverallStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    DRIFTED = "drifted"


class IntentKind(StrEnum):
    VLAN = "vlan"
    DHCP = "dhcp"
    DNS = "dns"
    WIFI = "wifi"
    WIREGUARD = "wireguard"
    FIREWALL = "firewall"
