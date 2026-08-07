"""Read-only Netcraze adapter implementing RouterControlPort (Gate A)."""



from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    SHOW_IDENTIFICATION,
    SHOW_SYSTEM,
    SHOW_VERSION,
)
from router_control.adapters.netcraze.errors import IdentityParseError, NetcrazeAdapterError
from router_control.adapters.netcraze.identity import (
    OperatorIdentityHints,
    ParsedIdentity,
    parse_identity,
)
from router_control.adapters.netcraze.sanitize import build_gate_a_evidence
from router_control.adapters.netcraze.shape_registry import CertifiedOperationRegistry
from router_control.adapters.netcraze.transport import NetcrazeTransport
from router_control.adapters.netcraze.typed_executor import (
    ExecutorError,
    LiveMutationPolicy,
    SharedTypedOperationExecutor,
)
from router_control.domain.entities import (
    BackupArtifact,
    ChangePlan,
    RouterCapability,
    RouterIdentity,
    RouterObservation,
)
from router_control.domain.enums import CertificationStatus, ObservationCollectionStatus
from router_control.domain.errors import IdentityMismatch, MutationForbidden
from router_control.domain.ids import (
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

_COMPONENTS_BODY = json.dumps({}).encode("utf-8")

_CAPABILITY_TTL = timedelta(hours=1)

_OBSERVATION_TTL = timedelta(minutes=5)

_MUTATION_MESSAGE = "Gate A read-only adapter forbids mutation without network"

_LIVE_MUTATION_POLICY_MESSAGE = "live mutation policy not injected"

_CERTIFIED_REGISTRY_EMPTY_MESSAGE = (
    "no certified operations registered — mutation forbidden before vault/network"
)





@dataclass

class NetcrazeReadOnlyAdapter:

    router_id: RouterId

    transport: NetcrazeTransport

    clock: ClockPort

    identity_hints: OperatorIdentityHints | None = None

    certified_registry: CertifiedOperationRegistry = field(
        default_factory=CertifiedOperationRegistry
    )

    typed_executor: SharedTypedOperationExecutor = field(
        default_factory=SharedTypedOperationExecutor
    )

    live_mutation_policy: LiveMutationPolicy | None = None

    active_p1_effect_context_id: str | None = None

    call_trace: list[str] = field(default_factory=list)

    _cached_identity: ParsedIdentity | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        adapter_registry = self.certified_registry
        executor_registry = self.typed_executor.registry
        if adapter_registry is executor_registry:
            return
        if adapter_registry.is_empty() and executor_registry.is_empty():
            self.typed_executor.registry = adapter_registry
            return
        if (
            not adapter_registry.is_empty()
            and not executor_registry.is_empty()
            and adapter_registry.content_digest() == executor_registry.content_digest()
        ):
            self.typed_executor.registry = adapter_registry
            return
        raise NetcrazeAdapterError(
            "certified_registry and typed_executor.registry must share the same "
            "CertifiedOperationRegistry object"
        )

    def _record(self, name: str) -> None:

        self.call_trace.append(name)



    def _now(self) -> datetime:

        return self.clock.now()



    def _resolved_hints(self) -> OperatorIdentityHints:

        return (self.identity_hints or OperatorIdentityHints()).normalized()

    def _deny_mutation_before_io(self, *, operation: str) -> None:
        if self.live_mutation_policy is None:
            raise MutationForbidden(_LIVE_MUTATION_POLICY_MESSAGE)
        runtime_context_id = self.active_p1_effect_context_id
        if not runtime_context_id:
            raise MutationForbidden("P1 effect context not bound")
        policy = self.live_mutation_policy
        try:
            policy.validate(
                operation=operation,
                registry_digest=self.certified_registry.content_digest(),
                p1_effect_context_id=runtime_context_id,
            )
        except ExecutorError as exc:
            raise MutationForbidden(str(exc)) from exc
        if self.certified_registry.is_empty():
            raise MutationForbidden(_CERTIFIED_REGISTRY_EMPTY_MESSAGE)

    def _load_identity(self) -> ParsedIdentity:

        if self._cached_identity is not None:

            return self._cached_identity

        system_payload = self.transport.read_json(SHOW_SYSTEM)
        components_payload = self.transport.read_json(COMPONENTS_LIST, _COMPONENTS_BODY)
        identification_payload = self.transport.read_json(SHOW_IDENTIFICATION)
        version_payload = self.transport.read_json(SHOW_VERSION)
        parsed = parse_identity(
            system_payload,
            components_payload,
            identification_payload=identification_payload,
            version_payload=version_payload,
            hints=self._resolved_hints(),
        )

        self._cached_identity = parsed

        return parsed



    def clear_identity_cache(self) -> None:

        self._cached_identity = None



    def probe_gate_a_evidence(self) -> dict[str, object]:

        """Collect sanitized Gate A evidence (no secrets or raw serial/MAC)."""

        identity = self._load_identity()

        return build_gate_a_evidence(
            model=identity.model,
            title=identity.title,
            firmware_version=identity.firmware_version,
            firmware_display_title=identity.firmware_display_title,
            build=identity.build,
            region=identity.region,
            update_channel=identity.update_channel,
            component_set_digest=identity.component_set_digest,
            device_fingerprint_digest=identity.fingerprint_digest,
            evidence_recorded_at=self._now().isoformat(),
            transport_security=self.transport.transport_security_label,
            https_check=self.transport.https_check_label,
            gate_a_certification_eligible=self.transport.gate_a_certification_eligible,
            certification_eligible=(
                identity.identity_complete and self.transport.gate_a_certification_eligible
            ),
            ssh_host_key_algorithm=getattr(self.transport, "ssh_host_key_algorithm", None),
            ssh_host_key_fingerprint_sha256=getattr(
                self.transport, "ssh_host_key_fingerprint_sha256", None
            ),
            fingerprint_status=identity.fingerprint_status,
            identity_shape=identity.identity_shape,
            identity_complete=identity.identity_complete,
            model_source=identity.model_source,
            update_channel_source=identity.update_channel_source,
            build_source=identity.build_source,
            region_source=identity.region_source,
            physical_identifier_source=identity.physical_identifier_source,
            firmware_sources_agreement=identity.firmware_sources_agreement,
            model_disagreement=identity.model_disagreement,
            model_display=identity.model_display,
            model_display_source=identity.model_display_source,
            sandbox=identity.sandbox,
            sandbox_source=identity.sandbox_source,
            bsp_build=identity.bsp_build,
            bsp_build_source=identity.bsp_build_source,
        )



    async def check_identity(self, expected: RouterIdentity) -> IdentityCheckResult:

        self._record("check_identity")

        identity = self._load_identity()

        if not identity.identity_complete:

            raise IdentityParseError("identity incomplete for exact fingerprint match")

        observed = identity.fingerprint_digest

        if expected.fingerprint_digest != observed:

            raise IdentityMismatch("netcraze identity fingerprint mismatch")

        return IdentityCheckResult(matched=True, observed_fingerprint_digest=observed)



    async def get_capabilities(self, router_id: RouterId) -> RouterCapability:

        self._record("get_capabilities")

        if router_id != self.router_id:

            raise ValueError("unknown router")

        identity = self._load_identity()

        now = self._now()

        return RouterCapability(

            capability_id=CapabilityId(f"capability-netcraze-{identity.fingerprint_digest[-8:]}"),

            router_id=self.router_id,

            firmware_digest=identity.firmware_digest,

            # Observed RO transport only; Gate A certification requires

            # human evidence + STATUS open.

            certification_status=CertificationStatus.UNKNOWN,

            observed_at=now,

            valid_until=now + _CAPABILITY_TTL,

            source="netcraze-readonly-adapter",

        )



    async def observe(self, router_id: RouterId) -> RouterObservation:

        self._record("observe")

        if router_id != self.router_id:

            raise ValueError("unknown router")

        identity = self._load_identity()

        now = self._now()

        capability_id = CapabilityId(f"capability-netcraze-{identity.fingerprint_digest[-8:]}")

        state_digest = identity.component_set_digest

        return RouterObservation(

            observation_id=ObservationId(f"observation-netcraze-{now.timestamp():.0f}"),

            router_id=self.router_id,

            identity_fingerprint_digest=identity.fingerprint_digest,

            capability_id=capability_id,

            state_digest=state_digest,

            resource_version=identity.fingerprint_digest,

            observed_at=now,

            valid_until=now + _OBSERVATION_TTL,

            collection_status=ObservationCollectionStatus.SUCCEEDED,

            source="netcraze-readonly-adapter",

        )



    async def create_backup(self, router_id: RouterId, operation_id: OperationId) -> BackupArtifact:

        self._record("create_backup")

        self._deny_mutation_before_io(operation="create_backup")

        raise MutationForbidden(_MUTATION_MESSAGE)



    async def begin_fail_safe(self, router_id: RouterId) -> FailSafeSession:

        self._deny_mutation_before_io(operation="begin_fail_safe")

        raise MutationForbidden(_MUTATION_MESSAGE)



    async def apply_plan(self, plan: ChangePlan) -> ApplyResult:

        self._deny_mutation_before_io(operation="apply_plan")

        raise MutationForbidden(_MUTATION_MESSAGE)



    async def read_back(self, router_id: RouterId, plan_id: PlanId) -> ReadBackResult:

        self._deny_mutation_before_io(operation="read_back")

        raise MutationForbidden(_MUTATION_MESSAGE)



    async def verify_postconditions(

        self, plan: ChangePlan, read_back: ReadBackResult

    ) -> VerifyResult:

        self._deny_mutation_before_io(operation="verify_postconditions")

        raise MutationForbidden(_MUTATION_MESSAGE)



    async def save_configuration(self, router_id: RouterId) -> SaveResult:

        self._deny_mutation_before_io(operation="save_configuration")

        raise MutationForbidden(_MUTATION_MESSAGE)



    async def compensate(self, router_id: RouterId, backup: BackupArtifact) -> CompensateResult:

        self._deny_mutation_before_io(operation="compensate")

        raise MutationForbidden(_MUTATION_MESSAGE)





def build_router_identity(parsed: ParsedIdentity, router_id: RouterId) -> RouterIdentity:

    return RouterIdentity(

        router_id=router_id,

        vendor=parsed.vendor,

        model=parsed.model,

        fingerprint_digest=parsed.fingerprint_digest,

    )





__all__ = [

    "NetcrazeReadOnlyAdapter",

    "build_router_identity",

    "IdentityParseError",

    "NetcrazeAdapterError",

]

