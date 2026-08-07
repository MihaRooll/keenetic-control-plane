"""Domain entities for SLICE-1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from router_control.domain.enums import (
    CertificationStatus,
    ExecutionTarget,
    ManagedResourceLifecycle,
    ObservationCollectionStatus,
    OwnershipAction,
    PlanConfirmationState,
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
)


def _validate_digest(value: str, name: str) -> str:
    if not value or not value.strip():
        raise ValueError(f"{name} must be a non-empty digest")
    return value


def _ensure_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise ValueError(f"{name} must use UTC timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class RouterIdentity:
    router_id: RouterId
    vendor: str
    model: str
    fingerprint_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "fingerprint_digest",
            _validate_digest(self.fingerprint_digest, "fingerprint_digest"),
        )
        if not self.vendor.strip():
            raise ValueError("vendor must be non-empty")
        if not self.model.strip():
            raise ValueError("model must be non-empty")


@dataclass(frozen=True, slots=True)
class RouterCapability:
    capability_id: CapabilityId
    router_id: RouterId
    firmware_digest: str
    certification_status: CertificationStatus
    observed_at: datetime
    valid_until: datetime
    source: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "firmware_digest", _validate_digest(self.firmware_digest, "firmware_digest")
        )
        object.__setattr__(self, "observed_at", _ensure_utc(self.observed_at, "observed_at"))
        object.__setattr__(self, "valid_until", _ensure_utc(self.valid_until, "valid_until"))


@dataclass(frozen=True, slots=True)
class RouterObservation:
    observation_id: ObservationId
    router_id: RouterId
    identity_fingerprint_digest: str
    capability_id: CapabilityId
    state_digest: str
    resource_version: str
    observed_at: datetime
    valid_until: datetime
    collection_status: ObservationCollectionStatus
    source: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "identity_fingerprint_digest",
            _validate_digest(self.identity_fingerprint_digest, "identity_fingerprint_digest"),
        )
        object.__setattr__(
            self,
            "state_digest",
            _validate_digest(self.state_digest, "state_digest"),
        )
        object.__setattr__(
            self, "resource_version", _validate_digest(self.resource_version, "resource_version")
        )
        object.__setattr__(self, "observed_at", _ensure_utc(self.observed_at, "observed_at"))
        object.__setattr__(self, "valid_until", _ensure_utc(self.valid_until, "valid_until"))


@dataclass(frozen=True, slots=True)
class DesiredRevision:
    revision_id: RevisionId
    router_id: RouterId
    revision_number: int
    desired_digest: str
    based_on_observation_id: ObservationId
    created_at: datetime
    deployment_revision_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "desired_digest", _validate_digest(self.desired_digest, "desired_digest")
        )
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
        if self.revision_number < 1:
            raise ValueError("revision_number must be >= 1")


@dataclass(frozen=True, slots=True)
class PublishedPreset:
    published_preset_id: str
    preset_id: str
    source_revision_id: str
    site_id: str
    canonical_document_digest: str
    schema_digest: str
    validation_digest: str
    published_at: datetime
    publisher_session_binding_hmac: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "canonical_document_digest",
            _validate_digest(self.canonical_document_digest, "canonical_document_digest"),
        )
        object.__setattr__(
            self, "published_at", _ensure_utc(self.published_at, "published_at")
        )


@dataclass(frozen=True, slots=True)
class RouterDeploymentRevision:
    deployment_revision_id: str
    published_preset_id: str
    router_id: RouterId
    site_id: str
    execution_target: ExecutionTarget
    identity_tuple_digest: str
    evidence_digest: str
    canonical_desired_digest: str
    created_at: datetime
    actor_session_binding_hmac: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "identity_tuple_digest",
            _validate_digest(self.identity_tuple_digest, "identity_tuple_digest"),
        )
        object.__setattr__(
            self,
            "evidence_digest",
            _validate_digest(self.evidence_digest, "evidence_digest"),
        )
        object.__setattr__(
            self,
            "canonical_desired_digest",
            _validate_digest(self.canonical_desired_digest, "canonical_desired_digest"),
        )
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))


@dataclass(frozen=True, slots=True)
class ManagedResource:
    resource_id: ResourceId
    router_id: RouterId
    resource_kind: str
    logical_key: str
    owner: str
    revision_id: RevisionId
    external_locator_digest: str
    lifecycle: ManagedResourceLifecycle
    last_observation_id: ObservationId

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "external_locator_digest",
            _validate_digest(self.external_locator_digest, "external_locator_digest"),
        )


@dataclass(frozen=True, slots=True)
class ChangePlanItem:
    resource_id: ResourceId
    intent_kind: str
    intent_digest: str
    intent_json: dict[str, object] | None = None
    ownership_action: OwnershipAction | None = None
    family_cert_snapshot_json: dict[str, object] | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "intent_digest", _validate_digest(self.intent_digest, "intent_digest")
        )


@dataclass(frozen=True, slots=True)
class ChangePlan:
    plan_id: PlanId
    router_id: RouterId
    revision_id: RevisionId
    observation_id: ObservationId
    expected_desired_digest: str
    observed_resource_version: str
    items: tuple[ChangePlanItem, ...]
    confirmation_state: PlanConfirmationState
    expires_at: datetime
    created_at: datetime
    actor: str
    deployment_revision_id: str | None = None
    session_binding_hmac: str | None = None
    plan_version: int = 1
    adopt_acknowledged: bool = False
    execution_target: ExecutionTarget | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "items", tuple(self.items))
        object.__setattr__(
            self,
            "expected_desired_digest",
            _validate_digest(self.expected_desired_digest, "expected_desired_digest"),
        )
        object.__setattr__(
            self,
            "observed_resource_version",
            _validate_digest(self.observed_resource_version, "observed_resource_version"),
        )
        object.__setattr__(self, "expires_at", _ensure_utc(self.expires_at, "expires_at"))
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
        if self.plan_version < 1:
            raise ValueError("plan_version must be >= 1")


@dataclass(frozen=True, slots=True)
class BackupArtifact:
    artifact_id: ArtifactId
    router_id: RouterId
    operation_id: OperationId
    content_digest: str
    storage_locator_digest: str
    identity_fingerprint_digest: str
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "content_digest", _validate_digest(self.content_digest, "content_digest")
        )
        object.__setattr__(
            self,
            "storage_locator_digest",
            _validate_digest(self.storage_locator_digest, "storage_locator_digest"),
        )
        object.__setattr__(
            self,
            "identity_fingerprint_digest",
            _validate_digest(self.identity_fingerprint_digest, "identity_fingerprint_digest"),
        )
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
