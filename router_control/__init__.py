"""Router Control portable domain core (SLICE-1)."""

from router_control.adapters.fake.adapter import FakeRouterAdapter, FakeRouterConfig
from router_control.adapters.fake.evidence import FakeAdapterEvidence
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.provisioning import (
    LifecycleOutcome,
    LifecycleTrace,
    ProvisioningLifecycleService,
    ProvisioningRequest,
)
from router_control.composition import (
    LiveRuntime,
    OfflineRuntime,
    create_fake_runtime,
    create_live_runtime,
    create_offline_runtime,
)
from router_control.domain.entities import (
    BackupArtifact,
    ChangePlan,
    ChangePlanItem,
    DesiredRevision,
    ManagedResource,
    RouterCapability,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.enums import (
    CertificationStatus,
    ManagedResourceLifecycle,
    ObservationCollectionStatus,
    PlanConfirmationState,
    ReconcileStatus,
    RouterLifecycleStatus,
    StepKind,
)
from router_control.domain.errors import (
    CapabilityExpired,
    CapabilityUnknown,
    CapabilityUnsupported,
    DomainError,
    FailSafeTimeout,
    IdentityMismatch,
    PlanExpired,
    PlanUnconfirmed,
    RecoveryRequired,
    StaleObservation,
    UnknownExternalOutcome,
    UnmanagedConflict,
)
from router_control.domain.ids import (
    ArtifactId,
    CapabilityId,
    ObservationId,
    OperationId,
    PlanId,
    ResourceId,
    RevisionId,
    RouterId,
    StepId,
)
from router_control.integration import RouterControlConfig, build_runtime
from router_control.ports.clock import ClockPort, SystemClock
from router_control.ports.router_control import RouterControlPort

__version__ = "0.1.0"

__all__ = [
    "ArtifactId",
    "BackupArtifact",
    "CapabilityExpired",
    "CapabilityId",
    "CapabilityUnknown",
    "CapabilityUnsupported",
    "CertificationStatus",
    "ChangePlan",
    "ChangePlanItem",
    "ClockPort",
    "DesiredRevision",
    "DomainError",
    "FakeAdapterEvidence",
    "FakeRouterAdapter",
    "FakeRouterConfig",
    "FailSafeTimeout",
    "IdentityMismatch",
    "LifecycleOutcome",
    "LifecycleTrace",
    "LiveRuntime",
    "ManagedResource",
    "MemoryVault",
    "ManagedResourceLifecycle",
    "ObservationCollectionStatus",
    "ObservationId",
    "OfflineRuntime",
    "OperationId",
    "PlanConfirmationState",
    "PlanExpired",
    "PlanId",
    "PlanUnconfirmed",
    "ProvisioningLifecycleService",
    "ProvisioningRequest",
    "ReconcileStatus",
    "RecoveryRequired",
    "ResourceId",
    "RevisionId",
    "RouterCapability",
    "RouterControlConfig",
    "RouterControlPort",
    "RouterId",
    "build_runtime",
    "RouterIdentity",
    "RouterLifecycleStatus",
    "RouterObservation",
    "StaleObservation",
    "StepId",
    "StepKind",
    "SystemClock",
    "UnknownExternalOutcome",
    "UnmanagedConflict",
    "__version__",
    "create_fake_runtime",
    "create_live_runtime",
    "create_offline_runtime",
]
