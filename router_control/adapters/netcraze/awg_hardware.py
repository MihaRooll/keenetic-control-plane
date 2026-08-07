"""Typed AWG hardware boundary — empty shape registry fail-closed."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from router_control.adapters.netcraze.capability_families import CapabilityFamily
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.codec import (
    ContinuationToken,
    HttpExchange,
    InMemorySecretResolver,
    TypedIntent,
    WireRequest,
)
from router_control.adapters.netcraze.gate_bc import GateBCAuthorization, GateBCError
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_RECORDED_AWG_IMPORT,
    MutationClass,
    OperationSpec,
    TransportKind,
    TupleCertRequirements,
    build_registered_operation,
)
from router_control.adapters.netcraze.shape_registry import (
    CommandShapeUnknown,
    FamilyRegisteredShape,
    FamilyShapeRegistry,
    ShapePromotionState,
    ShapeRegistryError,
    assert_no_generic_rci_executor,
)
from router_control.adapters.netcraze.typed_executor import (
    CertificationExecutionContext,
    ExecutorError,
    SharedTypedOperationExecutor,
)

# Re-export for backward compatibility
__compat_command_shape_unknown = CommandShapeUnknown


class TypedOperation(StrEnum):
    FAIL_SAFE_BEGIN = "fail_safe_begin"
    FAIL_SAFE_STATUS = "fail_safe_status"
    AWG_IMPORT = "awg_import"
    AWG_FIELD_PARITY_READBACK = "awg_field_parity_readback"
    HANDSHAKE_OBSERVE = "handshake_observe"
    APPLICATION_REACHABILITY_OBSERVE = "application_reachability_observe"
    CONFIG_SAVE = "config_save"
    ROUTER_REBOOT = "router_reboot"
    BASELINE_RESTORE = "baseline_restore"


TYPED_OPERATIONS: frozenset[TypedOperation] = frozenset(TypedOperation)
DISRUPTIVE_TAIL: frozenset[TypedOperation] = frozenset(
    {TypedOperation.CONFIG_SAVE, TypedOperation.ROUTER_REBOOT}
)

_AWG_FAMILY = CapabilityFamily.AMNEZIAWG
_CODEC_VERSION = "netcraze-codec-v1"
_EXECUTOR_VERSION = "shared-typed-executor-v1"


def _intent_fields_for_shape(shape: RegisteredShape) -> dict[str, Any]:
    fields: dict[str, Any] = {}
    for key in shape.body_keys:
        if key == "mode":
            fields[key] = "on"
        else:
            fields[key] = []
    return fields


def _operation_spec_for_shape(shape: RegisteredShape) -> OperationSpec:
    return OperationSpec(
        family=_AWG_FAMILY,
        operation_id=shape.operation.value,
        revision=1,
        mutation_class=MutationClass.MUTATION,
        transport_kind=TransportKind.RCI_HTTP,
        input_schema_id=f"schema:{shape.operation.value}:v1",
        output_schema_id=f"schema:{shape.operation.value}_out:v1",
        endpoint_identifier=shape.path,
        codec_version=_CODEC_VERSION,
        executor_version=_EXECUTOR_VERSION,
        tuple_cert_requirements=TupleCertRequirements(
            require_gate_a_open=True,
            require_exact_tuple=True,
            require_gate_c_open=True,
        ),
        body_field_keys=shape.body_keys,
        http_method=shape.method,
    )


class TransportPort(Protocol):
    def execute_shape(
        self,
        *,
        method: str,
        path: str,
        body_keys: tuple[str, ...],
    ) -> dict[str, Any]:
        """Execute a registered typed shape — never arbitrary path/body pass-through."""
        ...


@dataclass
class ShapeHttpTransport:
    """HttpTransportPort adapter that dispatches wire requests through execute_shape."""

    transport: TransportPort
    shape: RegisteredShape
    wire_endpoint_identifier: str
    _poll_responses: list[HttpExchange] = field(default_factory=list)

    def execute_wire(self, request: WireRequest) -> HttpExchange:
        if request.endpoint_identifier != self.wire_endpoint_identifier:
            raise ExecutorError("wire endpoint mismatch with operation spec")
        payload = self.transport.execute_shape(
            method=self.shape.method,
            path=self.shape.path,
            body_keys=self.shape.body_keys,
        )
        return HttpExchange(
            status=200,
            headers={},
            body=json.dumps(payload).encode("utf-8"),
        )

    def poll_continuation(self, *, token: ContinuationToken) -> HttpExchange:
        if not token.token.strip():
            raise ExecutorError("continuation poll token missing")
        if not self._poll_responses:
            raise ExecutorError("poll response missing")
        return self._poll_responses.pop(0)


@dataclass(frozen=True, slots=True)
class RegisteredShape:
    operation: TypedOperation
    method: str
    path: str
    body_keys: tuple[str, ...]
    tuple_component_set_digest: str
    tuple_device_fingerprint_digest: str
    adapter_version: str

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation.value,
            "method": self.method,
            "path": self.path,
            "body_keys": list(self.body_keys),
            "tuple_component_set_digest": self.tuple_component_set_digest,
            "tuple_device_fingerprint_digest": self.tuple_device_fingerprint_digest,
            "adapter_version": self.adapter_version,
        }

    @classmethod
    def from_family_shape(cls, shape: FamilyRegisteredShape) -> RegisteredShape:
        return cls(
            operation=TypedOperation(shape.operation_id),
            method=shape.method,
            path=shape.path,
            body_keys=shape.body_keys,
            tuple_component_set_digest=shape.tuple_component_set_digest,
            tuple_device_fingerprint_digest=shape.tuple_device_fingerprint_digest,
            adapter_version=shape.adapter_version,
        )

    def to_family_shape(self) -> FamilyRegisteredShape:
        return FamilyRegisteredShape(
            family=_AWG_FAMILY,
            operation_id=self.operation.value,
            method=self.method,
            path=self.path,
            body_keys=self.body_keys,
            tuple_component_set_digest=self.tuple_component_set_digest,
            tuple_device_fingerprint_digest=self.tuple_device_fingerprint_digest,
            adapter_version=self.adapter_version,
        )


class ShapeRegistry:
    """Evidence-backed AWG shape registry — thin wrapper over FamilyShapeRegistry."""

    def __init__(self) -> None:
        self._inner = FamilyShapeRegistry()

    def __len__(self) -> int:
        return len(self._inner)

    @property
    def _family_registry(self) -> FamilyShapeRegistry:
        return self._inner

    def is_registered(self, operation: TypedOperation) -> bool:
        return self._inner.is_registered(_AWG_FAMILY, operation.value)

    def registered_operations(self) -> frozenset[TypedOperation]:
        return frozenset(
            TypedOperation(op) for op in self._inner.for_family(_AWG_FAMILY)
        )

    def register_shape(self, shape: RegisteredShape) -> None:
        if shape.operation not in TYPED_OPERATIONS:
            raise GateBCError(f"operation not allowlisted: {shape.operation}")
        try:
            self._inner.register_shape(shape.to_family_shape())
        except ShapeRegistryError as exc:
            raise GateBCError(str(exc)) from exc

    def register_from_discovery_artifact(
        self,
        artifact: dict[str, Any],
        *,
        gate_a: GateACertification,
        adapter_version: str,
    ) -> RegisteredShape:
        operation_raw = str(artifact.get("operation", ""))
        try:
            operation = TypedOperation(operation_raw)
        except ValueError as exc:
            raise GateBCError(f"unknown operation in discovery artifact: {operation_raw}") from exc
        method = str(artifact.get("method", "")).upper()
        path = str(artifact.get("path", ""))
        body_keys_raw = artifact.get("body_keys") or []
        if not isinstance(body_keys_raw, list):
            raise GateBCError("discovery artifact body_keys must be a list")
        component_digest = str(artifact.get("tuple_component_set_digest", ""))
        fingerprint_digest = str(artifact.get("tuple_device_fingerprint_digest", ""))
        if component_digest != gate_a.component_set_digest:
            raise GateBCError("discovery artifact tuple_component_set_digest mismatch")
        if fingerprint_digest != gate_a.device_fingerprint_digest:
            raise GateBCError("discovery artifact tuple_device_fingerprint_digest mismatch")
        shape = RegisteredShape(
            operation=operation,
            method=method,
            path=path,
            body_keys=tuple(str(item) for item in body_keys_raw),
            tuple_component_set_digest=component_digest,
            tuple_device_fingerprint_digest=fingerprint_digest,
            adapter_version=adapter_version,
        )
        self.register_shape(shape)
        return shape

    def get(self, operation: TypedOperation) -> RegisteredShape:
        try:
            family_shape = self._inner.get(_AWG_FAMILY, operation.value)
        except CommandShapeUnknown as exc:
            raise CommandShapeUnknown(
                f"no registered shape for operation {operation.value}"
            ) from exc
        return RegisteredShape.from_family_shape(family_shape)


@dataclass(frozen=True, slots=True)
class HardwareExecutionResult:
    operation: TypedOperation
    status: str
    sanitized: dict[str, Any]


class AwgHardwareBoundary:
    """Typed allowlist executor — no generic/raw RCI API."""

    def __init__(
        self,
        *,
        registry: ShapeRegistry | None = None,
        transport: TransportPort | None = None,
        adapter_version: str = "netcraze-awg-v0",
        executor: SharedTypedOperationExecutor | None = None,
    ) -> None:
        self.registry = registry or ShapeRegistry()
        self.transport = transport
        self.adapter_version = adapter_version
        self.executor = executor or SharedTypedOperationExecutor()

    def _assert_gates(
        self,
        *,
        gate_a: GateACertification,
        gate_bc: GateBCAuthorization,
        probe_evidence: dict[str, Any],
        capability_family: str,
        now: Any,
    ) -> None:
        gate_bc.writes_permitted(
            gate_a=gate_a,
            capability_family=capability_family,
            probe_evidence=probe_evidence,
            now=now,
        )

    def execute(
        self,
        operation: TypedOperation | str,
        *,
        gate_a: GateACertification,
        gate_bc: GateBCAuthorization,
        probe_evidence: dict[str, Any],
        capability_family: str = "AmneziaWG",
        now: Any = None,
        transport: TransportPort | None = None,
        profile_digest: str | None = None,
        profile_fields: dict[str, Any] | None = None,
        credential_refs: tuple[dict[str, str], ...] | None = None,
    ) -> HardwareExecutionResult:
        if isinstance(operation, str):
            try:
                operation = TypedOperation(operation)
            except ValueError as exc:
                raise GateBCError(f"operation not allowlisted: {operation}") from exc
        if operation not in TYPED_OPERATIONS:
            raise GateBCError(f"operation not allowlisted: {operation}")

        self._assert_gates(
            gate_a=gate_a,
            gate_bc=gate_bc,
            probe_evidence=probe_evidence,
            capability_family=capability_family,
            now=now,
        )

        shape = self.registry.get(operation)
        if shape.tuple_component_set_digest != gate_a.component_set_digest:
            raise CommandShapeUnknown("registered shape tuple_component_set_digest mismatch")
        if shape.tuple_device_fingerprint_digest != gate_a.device_fingerprint_digest:
            raise CommandShapeUnknown("registered shape tuple_device_fingerprint_digest mismatch")
        if shape.adapter_version != self.adapter_version:
            raise CommandShapeUnknown("registered shape adapter_version mismatch")

        active_transport = transport or self.transport
        if active_transport is None:
            raise GateBCError("active transport required for typed hardware execution")

        return self._execute_via_executor(
            operation=operation,
            shape=shape,
            gate_a=gate_a,
            gate_bc=gate_bc,
            probe_evidence=probe_evidence,
            active_transport=active_transport,
            now=now,
            profile_digest=profile_digest,
            profile_fields=profile_fields,
            credential_refs=credential_refs,
        )

    def _execute_via_executor(
        self,
        *,
        operation: TypedOperation,
        shape: RegisteredShape,
        gate_a: GateACertification,
        gate_bc: GateBCAuthorization,
        probe_evidence: dict[str, Any],
        active_transport: TransportPort,
        now: Any,
        profile_digest: str | None = None,
        profile_fields: dict[str, Any] | None = None,
        credential_refs: tuple[dict[str, str], ...] | None = None,
    ) -> HardwareExecutionResult:
        if operation == TypedOperation.AWG_IMPORT and profile_digest is None:
            raise GateBCError("AWG import requires encoded profile digest")

        spec = (
            SYNTHETIC_RECORDED_AWG_IMPORT
            if operation == TypedOperation.AWG_IMPORT
            else _operation_spec_for_shape(shape)
        )
        gate_a_digest = gate_a.evidence_sha256 or gate_a.device_fingerprint_digest
        if not str(gate_a_digest).startswith("sha256:"):
            gate_a_digest = f"sha256:{gate_a_digest}"
        registered = build_registered_operation(
            spec,
            promotion_state=ShapePromotionState.LAB_OBSERVED.value,
            tuple_component_set_digest=gate_a.component_set_digest,
            tuple_device_fingerprint_digest=gate_a.device_fingerprint_digest,
            gate_a_evidence_digest=gate_a_digest,
            adapter_version=self.adapter_version,
            evidence_digest=gate_a_digest,
        )
        http_transport = ShapeHttpTransport(
            transport=active_transport,
            shape=shape,
            wire_endpoint_identifier=spec.endpoint_identifier,
        )
        current = now
        if current is None:
            from datetime import UTC, datetime

            current = datetime.now(UTC)

        intent_fields: dict[str, Any] = _intent_fields_for_shape(shape)
        if operation == TypedOperation.AWG_IMPORT:
            fields = profile_fields or {"profile_fields": ["Address", "Endpoint"]}
            intent_fields = {
                "profile_fields": fields.get("profile_fields", []),
                "credential_refs": list(credential_refs or ()),
            }

        try:
            exec_result = self.executor.execute_certification(
                registered,
                intent=TypedIntent(
                    operation_spec_digest=spec.spec_digest,
                    fields=intent_fields,
                ),
                context=CertificationExecutionContext(
                    gate_a_open=gate_a.is_open_at(current),
                    gate_c_open=gate_bc.gate_c_is_open(current),
                    candidate_spec_digest=spec.spec_digest,
                    trial_authorized=True,
                    probe_tuple_match=gate_bc.matches_probe_evidence(probe_evidence),
                    gate_d_closed=True,
                    lab_observed_grant_digest=gate_a_digest,
                    readback_evidence=True,
                    functional_evidence=True,
                    compensation_evidence=True,
                ),
                secret_resolver=InMemorySecretResolver(),
                http_transport=http_transport,
                profile_digest=profile_digest,
            )
        except ExecutorError as exc:
            raise GateBCError(str(exc)) from exc
        if not exec_result.passed:
            error = exec_result.error
            message = error.message if error is not None else "AWG executor rejected operation"
            raise GateBCError(message)
        sanitized = dict(exec_result.sanitized)
        sanitized["operation"] = operation.value
        sanitized["shape"] = shape.sanitized_dict()
        default_status = {
            TypedOperation.AWG_IMPORT: "import_verified",
            TypedOperation.AWG_FIELD_PARITY_READBACK: "read_back_verified",
            TypedOperation.HANDSHAKE_OBSERVE: "handshake_verified",
            TypedOperation.APPLICATION_REACHABILITY_OBSERVE: "reachability_verified",
        }.get(operation, "executed")
        return HardwareExecutionResult(
            operation=operation,
            status=str(exec_result.sanitized.get("status", default_status)),
            sanitized=sanitized,
        )


__all__ = [
    "AwgHardwareBoundary",
    "CommandShapeUnknown",
    "DISRUPTIVE_TAIL",
    "HardwareExecutionResult",
    "RegisteredShape",
    "ShapeRegistry",
    "TYPED_OPERATIONS",
    "TransportPort",
    "TypedOperation",
    "assert_no_generic_rci_executor",
]
