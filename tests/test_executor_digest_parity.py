"""Certification/runtime executor digest parity."""

from __future__ import annotations

import json

from router_control.adapters.netcraze.codec import HttpExchange, InMemorySecretResolver, TypedIntent
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_REGISTERED_OPERATIONS,
    build_registered_operation,
)
from router_control.adapters.netcraze.shape_registry import (
    LabObservedEvidence,
    OperationPromotionRegistry,
    ShapePromotionState,
)
from router_control.adapters.netcraze.typed_executor import (
    CertificationExecutionContext,
    RuntimeExecutionContext,
    SharedTypedOperationExecutor,
    assert_identical_executor_digests,
)


class _StubHttpTransport:
    def execute_wire(self, request):  # type: ignore[no-untyped-def]
        return HttpExchange(
            status=200,
            headers={},
            body=json.dumps({"status": "executed"}).encode("utf-8"),
        )

    def poll_continuation(self, *, token):  # type: ignore[no-untyped-def]
        raise AssertionError("no continuation expected for parity stub")


def _lab_evidence(operation) -> LabObservedEvidence:
    return LabObservedEvidence(
        tuple_component_set_digest=operation.tuple_component_set_digest,
        tuple_device_fingerprint_digest=operation.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=operation.gate_a_evidence_digest,
        evidence_digest=operation.evidence_digest,
        trial_authorized=True,
        artifact_digest_verified=True,
    )


def _certification_context(operation, **overrides: object) -> CertificationExecutionContext:
    base: dict[str, object] = {
        "gate_a_open": True,
        "gate_c_open": True,
        "candidate_spec_digest": operation.spec.spec_digest,
        "trial_authorized": True,
        "probe_tuple_match": True,
        "lab_observed_grant_digest": operation.evidence_digest,
        "readback_evidence": True,
        "functional_evidence": True,
        "compensation_evidence": True,
    }
    base.update(overrides)
    return CertificationExecutionContext(**base)  # type: ignore[arg-type]


def test_certification_runtime_instrumentation_parity() -> None:
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    candidate = build_registered_operation(
        lab.spec,
        promotion_state=ShapePromotionState.CANDIDATE.value,
        tuple_component_set_digest=lab.tuple_component_set_digest,
        tuple_device_fingerprint_digest=lab.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=lab.gate_a_evidence_digest,
        adapter_version=lab.adapter_version,
        evidence_digest=lab.evidence_digest,
    )
    executor = SharedTypedOperationExecutor()
    staging = OperationPromotionRegistry()
    staging.register_candidate(candidate)
    observed = staging.mark_lab_observed(candidate, evidence=_lab_evidence(candidate))
    certified = executor.registry.promote_lab_observed_to_certified(
        observed,
        lab_evidence_verified=True,
        independent_promotion=True,
        persistent_family_certification=True,
    )
    intent = TypedIntent(
        operation_spec_digest=certified.spec.spec_digest,
        fields={"mode": "on"},
    )
    resolver = InMemorySecretResolver()
    transport = _StubHttpTransport()
    cert = executor.execute_certification(
        observed,
        intent=intent,
        context=_certification_context(observed),
        secret_resolver=resolver,
        http_transport=transport,
    )
    runtime = executor.execute_runtime(
        family=certified.spec.family.value,
        operation_id=certified.spec.operation_id,
        intent=intent,
        context=RuntimeExecutionContext(
            write_certified=True,
            gate_c_applicable=False,
            gate_c_open=False,
            gate_d_closed=True,
            probe_tuple_match=True,
        ),
        secret_resolver=resolver,
        http_transport=transport,
    )
    assert_identical_executor_digests(
        cert.instrumentation,
        runtime.instrumentation,
    )
    assert cert.instrumentation.spec_digest == runtime.instrumentation.spec_digest
