"""Immutable typed operation specifications — deterministic digests, no raw RCI surface."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from router_control.adapters.netcraze.capability_families import CapabilityFamily
from router_control.adapters.netcraze.gate_bc import GateBCError

_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_CODEC_VERSION = "netcraze-codec-v1"
_EXECUTOR_VERSION = "shared-typed-executor-v1"


class OperationSpecError(GateBCError):
    """Operation specification validation failure."""


class TransportKind(StrEnum):
    RCI_HTTP = "rci_http"
    SEALED_SSH_CLI = "sealed_ssh_cli"


class MutationClass(StrEnum):
    READ = "read"
    MUTATION = "mutation"


class UnknownFieldPolicy(StrEnum):
    REJECT = "reject"
    FAIL_CLOSED = "fail_closed"


class RetryPolicy(StrEnum):
    NONE = "none"
    CONTINUATION_POLL = "continuation_poll"


@dataclass(frozen=True, slots=True)
class TupleCertRequirements:
    require_gate_a_open: bool = True
    require_exact_tuple: bool = True
    require_host_pin: bool = False
    require_write_certified: bool = False
    require_gate_c_open: bool = False

    def sanitized_dict(self) -> dict[str, bool]:
        return {
            "require_gate_a_open": self.require_gate_a_open,
            "require_exact_tuple": self.require_exact_tuple,
            "require_host_pin": self.require_host_pin,
            "require_write_certified": self.require_write_certified,
            "require_gate_c_open": self.require_gate_c_open,
        }


@dataclass(frozen=True, slots=True)
class OperationSpec:
    family: CapabilityFamily
    operation_id: str
    revision: int
    mutation_class: MutationClass
    transport_kind: TransportKind
    input_schema_id: str
    output_schema_id: str
    endpoint_identifier: str
    codec_version: str
    executor_version: str
    tuple_cert_requirements: TupleCertRequirements
    unknown_field_policy: UnknownFieldPolicy = UnknownFieldPolicy.REJECT
    retry_policy: RetryPolicy = RetryPolicy.NONE
    continuation_poll_spec_id: str | None = None
    body_field_keys: tuple[str, ...] = ()
    http_method: str = "POST"

    @property
    def spec_digest(self) -> str:
        payload = {
            "family": self.family.value,
            "operation_id": self.operation_id,
            "revision": self.revision,
            "mutation_class": self.mutation_class.value,
            "transport_kind": self.transport_kind.value,
            "input_schema_id": self.input_schema_id,
            "output_schema_id": self.output_schema_id,
            "endpoint_identifier": self.endpoint_identifier,
            "codec_version": self.codec_version,
            "executor_version": self.executor_version,
            "tuple_cert_requirements": self.tuple_cert_requirements.sanitized_dict(),
            "unknown_field_policy": self.unknown_field_policy.value,
            "retry_policy": self.retry_policy.value,
            "continuation_poll_spec_id": self.continuation_poll_spec_id,
            "body_field_keys": list(self.body_field_keys),
            "http_method": self.http_method.upper(),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    @property
    def codec_digest(self) -> str:
        payload = {
            "codec_version": self.codec_version,
            "input_schema_id": self.input_schema_id,
            "output_schema_id": self.output_schema_id,
            "transport_kind": self.transport_kind.value,
            "endpoint_identifier": self.endpoint_identifier,
            "body_field_keys": list(self.body_field_keys),
            "unknown_field_policy": self.unknown_field_policy.value,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    @property
    def executor_digest(self) -> str:
        payload = {
            "executor_version": self.executor_version,
            "spec_digest": self.spec_digest,
            "codec_digest": self.codec_digest,
            "retry_policy": self.retry_policy.value,
            "continuation_poll_spec_id": self.continuation_poll_spec_id,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "family": self.family.value,
            "operation_id": self.operation_id,
            "revision": self.revision,
            "mutation_class": self.mutation_class.value,
            "transport_kind": self.transport_kind.value,
            "input_schema_id": self.input_schema_id,
            "output_schema_id": self.output_schema_id,
            "endpoint_identifier": self.endpoint_identifier,
            "spec_digest": self.spec_digest,
            "codec_version": self.codec_version,
            "codec_digest": self.codec_digest,
            "executor_version": self.executor_version,
            "executor_digest": self.executor_digest,
            "tuple_cert_requirements": self.tuple_cert_requirements.sanitized_dict(),
            "unknown_field_policy": self.unknown_field_policy.value,
            "retry_policy": self.retry_policy.value,
            "continuation_poll_spec_id": self.continuation_poll_spec_id,
            "body_field_keys": list(self.body_field_keys),
            "http_method": self.http_method.upper(),
        }


@dataclass(frozen=True, slots=True)
class RegisteredOperation:
    spec: OperationSpec
    promotion_state: str
    read_back_spec_ids: tuple[str, ...]
    state_projection_id: str
    postcondition_id: str
    compensation_spec_id: str
    compensation_baseline_requirements: tuple[str, ...]
    functional_verifier_ids: tuple[str, ...]
    tuple_component_set_digest: str
    tuple_device_fingerprint_digest: str
    gate_a_evidence_digest: str
    host_pin_digest: str | None
    adapter_version: str
    evidence_digest: str

    @property
    def shape_digest(self) -> str:
        return self.spec.spec_digest

    @property
    def codec_digest(self) -> str:
        return self.spec.codec_digest

    @property
    def executor_digest(self) -> str:
        return self.spec.executor_digest

    def bundle_digests(self) -> dict[str, str]:
        return {
            "shape_digest": self.shape_digest,
            "codec_digest": self.codec_digest,
            "executor_digest": self.executor_digest,
            "spec_digest": self.spec.spec_digest,
            "evidence_digest": self.evidence_digest,
            "postcondition_id": self.postcondition_id,
        }

    def sanitized_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "spec": self.spec.sanitized_dict(),
            "promotion_state": self.promotion_state,
            "read_back_spec_ids": list(self.read_back_spec_ids),
            "state_projection_id": self.state_projection_id,
            "postcondition_id": self.postcondition_id,
            "compensation_spec_id": self.compensation_spec_id,
            "compensation_baseline_requirements": list(self.compensation_baseline_requirements),
            "functional_verifier_ids": list(self.functional_verifier_ids),
            "tuple_component_set_digest": self.tuple_component_set_digest,
            "tuple_device_fingerprint_digest": self.tuple_device_fingerprint_digest,
            "gate_a_evidence_digest": self.gate_a_evidence_digest,
            "adapter_version": self.adapter_version,
            "evidence_digest": self.evidence_digest,
            "bundle_digests": self.bundle_digests(),
        }
        if self.host_pin_digest is not None:
            payload["host_pin_digest"] = self.host_pin_digest
        return payload


def _validate_digest(value: str, *, field: str) -> None:
    if not _SHA256_PREFIX_RE.match(value.strip().lower()):
        raise OperationSpecError(f"{field} must be sha256:<64-hex>")


def build_registered_operation(
    spec: OperationSpec,
    *,
    promotion_state: str,
    tuple_component_set_digest: str,
    tuple_device_fingerprint_digest: str,
    gate_a_evidence_digest: str,
    adapter_version: str,
    evidence_digest: str,
    read_back_spec_ids: tuple[str, ...] = (),
    state_projection_id: str = "",
    postcondition_id: str = "",
    compensation_spec_id: str = "",
    compensation_baseline_requirements: tuple[str, ...] = (),
    functional_verifier_ids: tuple[str, ...] = (),
    host_pin_digest: str | None = None,
) -> RegisteredOperation:
    _validate_digest(tuple_component_set_digest, field="tuple_component_set_digest")
    _validate_digest(tuple_device_fingerprint_digest, field="tuple_device_fingerprint_digest")
    _validate_digest(gate_a_evidence_digest, field="gate_a_evidence_digest")
    _validate_digest(evidence_digest, field="evidence_digest")
    if host_pin_digest is not None:
        _validate_digest(host_pin_digest, field="host_pin_digest")
    return RegisteredOperation(
        spec=spec,
        promotion_state=promotion_state,
        read_back_spec_ids=read_back_spec_ids,
        state_projection_id=state_projection_id or f"state:{spec.operation_id}:v{spec.revision}",
        postcondition_id=postcondition_id or f"post:{spec.operation_id}:v{spec.revision}",
        compensation_spec_id=compensation_spec_id or f"comp:{spec.operation_id}:v{spec.revision}",
        compensation_baseline_requirements=compensation_baseline_requirements,
        functional_verifier_ids=functional_verifier_ids,
        tuple_component_set_digest=tuple_component_set_digest,
        tuple_device_fingerprint_digest=tuple_device_fingerprint_digest,
        gate_a_evidence_digest=gate_a_evidence_digest,
        host_pin_digest=host_pin_digest,
        adapter_version=adapter_version,
        evidence_digest=evidence_digest,
    )


# Synthetic recorded operations for offline golden/parity tests.
# Not registered in production defaults.
_SYNTHETIC_COMPONENT_DIGEST = (
    "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
)
_SYNTHETIC_FINGERPRINT_DIGEST = (
    "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
)
_SYNTHETIC_EVIDENCE_DIGEST = "sha256:" + "c" * 64
_SYNTHETIC_GATE_A_DIGEST = "sha256:" + "d" * 64

SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN = OperationSpec(
    family=CapabilityFamily.FAIL_SAFE,
    operation_id="fail_safe_begin",
    revision=1,
    mutation_class=MutationClass.MUTATION,
    transport_kind=TransportKind.RCI_HTTP,
    input_schema_id="schema:fail_safe_begin:v1",
    output_schema_id="schema:fail_safe_begin_out:v1",
    endpoint_identifier="/rci/fail-safe/begin",
    codec_version=_CODEC_VERSION,
    executor_version=_EXECUTOR_VERSION,
    tuple_cert_requirements=TupleCertRequirements(
        require_gate_a_open=True,
        require_exact_tuple=True,
        require_gate_c_open=True,
    ),
    retry_policy=RetryPolicy.CONTINUATION_POLL,
    continuation_poll_spec_id="continuation:rci_http:v1",
    body_field_keys=("mode",),
    http_method="POST",
)

SYNTHETIC_RECORDED_AWG_IMPORT = OperationSpec(
    family=CapabilityFamily.AMNEZIAWG,
    operation_id="awg_import",
    revision=1,
    mutation_class=MutationClass.MUTATION,
    transport_kind=TransportKind.RCI_HTTP,
    input_schema_id="schema:awg_import:v1",
    output_schema_id="schema:awg_import_out:v1",
    endpoint_identifier="/rci/wireguard/import",
    codec_version=_CODEC_VERSION,
    executor_version=_EXECUTOR_VERSION,
    tuple_cert_requirements=TupleCertRequirements(
        require_gate_a_open=True,
        require_exact_tuple=True,
        require_gate_c_open=True,
    ),
    body_field_keys=("profile_fields", "credential_refs"),
    http_method="POST",
)

SYNTHETIC_RECORDED_FAIL_SAFE_TIMER = OperationSpec(
    family=CapabilityFamily.FAIL_SAFE,
    operation_id="fail_safe_timer_reboot_60",
    revision=1,
    mutation_class=MutationClass.MUTATION,
    transport_kind=TransportKind.SEALED_SSH_CLI,
    input_schema_id="schema:fail_safe_timer:v1",
    output_schema_id="schema:fail_safe_timer_out:v1",
    endpoint_identifier="sealed:fail_safe_timer_reboot_60",
    codec_version=_CODEC_VERSION,
    executor_version=_EXECUTOR_VERSION,
    tuple_cert_requirements=TupleCertRequirements(
        require_gate_a_open=True,
        require_exact_tuple=True,
        require_host_pin=True,
        require_gate_c_open=True,
    ),
    body_field_keys=(),
    http_method="POST",
)

SYNTHETIC_REGISTERED_OPERATIONS: tuple[RegisteredOperation, ...] = (
    build_registered_operation(
        SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN,
        promotion_state="lab_observed",
        tuple_component_set_digest=_SYNTHETIC_COMPONENT_DIGEST,
        tuple_device_fingerprint_digest=_SYNTHETIC_FINGERPRINT_DIGEST,
        gate_a_evidence_digest=_SYNTHETIC_GATE_A_DIGEST,
        adapter_version="netcraze-p3-v0",
        evidence_digest=_SYNTHETIC_EVIDENCE_DIGEST,
        read_back_spec_ids=("read_back:fail_safe_status:v1",),
        functional_verifier_ids=("verifier:fail_safe_active:v1",),
        compensation_baseline_requirements=("baseline:startup_config:v1",),
    ),
    build_registered_operation(
        SYNTHETIC_RECORDED_AWG_IMPORT,
        promotion_state="lab_observed",
        tuple_component_set_digest=_SYNTHETIC_COMPONENT_DIGEST,
        tuple_device_fingerprint_digest=_SYNTHETIC_FINGERPRINT_DIGEST,
        gate_a_evidence_digest=_SYNTHETIC_GATE_A_DIGEST,
        adapter_version="netcraze-p3-v0",
        evidence_digest=_SYNTHETIC_EVIDENCE_DIGEST,
        read_back_spec_ids=("read_back:awg_field_parity:v1",),
        functional_verifier_ids=(
            "verifier:handshake:v1",
            "verifier:application_reachability:v1",
        ),
        compensation_baseline_requirements=("baseline:awg_profile:v1",),
    ),
)


__all__ = [
    "MutationClass",
    "OperationSpec",
    "OperationSpecError",
    "RegisteredOperation",
    "RetryPolicy",
    "SYNTHETIC_RECORDED_AWG_IMPORT",
    "SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN",
    "SYNTHETIC_RECORDED_FAIL_SAFE_TIMER",
    "SYNTHETIC_REGISTERED_OPERATIONS",
    "TransportKind",
    "TupleCertRequirements",
    "UnknownFieldPolicy",
    "build_registered_operation",
]
