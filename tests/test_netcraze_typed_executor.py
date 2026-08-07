"""SharedTypedOperationExecutor policy tests."""

from __future__ import annotations

import json

import pytest
from router_control.adapters.netcraze.codec import HttpExchange, InMemorySecretResolver, TypedIntent
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_REGISTERED_OPERATIONS,
    build_registered_operation,
)
from router_control.adapters.netcraze.shape_registry import (
    CertifiedOperationUnknown,
    LabObservedEvidence,
    OperationPromotionRegistry,
    ShapePromotionState,
    promote_through_pipeline,
)
from router_control.adapters.netcraze.typed_executor import (
    CertificationExecutionContext,
    ExecutorError,
    RuntimeExecutionContext,
    SharedTypedOperationExecutor,
)


class _StubHttpTransport:
    def __init__(self) -> None:
        self.wire_calls = 0
        self.poll_calls = 0

    def execute_wire(self, request):  # type: ignore[no-untyped-def]
        self.wire_calls += 1
        return HttpExchange(
            status=200,
            headers={},
            body=json.dumps({"status": "executed"}).encode("utf-8"),
        )

    def poll_continuation(self, *, token):  # type: ignore[no-untyped-def]
        self.poll_calls += 1
        return HttpExchange(
            status=200,
            headers={},
            body=json.dumps({"status": "executed"}).encode("utf-8"),
        )


class _ContinuationTransport:
    def __init__(self) -> None:
        self.wire_calls = 0
        self.poll_calls = 0

    def execute_wire(self, request):  # type: ignore[no-untyped-def]
        self.wire_calls += 1
        return HttpExchange(
            status=200,
            headers={},
            body=json.dumps(
                {"continued": True, "continuation_token": "poll-token-1"}
            ).encode("utf-8"),
        )

    def poll_continuation(self, *, token):  # type: ignore[no-untyped-def]
        self.poll_calls += 1
        return HttpExchange(
            status=200,
            headers={},
            body=json.dumps({"status": "executed"}).encode("utf-8"),
        )


def _lab_evidence(operation) -> LabObservedEvidence:
    return LabObservedEvidence(
        tuple_component_set_digest=operation.tuple_component_set_digest,
        tuple_device_fingerprint_digest=operation.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=operation.gate_a_evidence_digest,
        evidence_digest=operation.evidence_digest,
        trial_authorized=True,
        artifact_digest_verified=True,
    )


def _lab_observed_operation():
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
    staging = OperationPromotionRegistry()
    staging.register_candidate(candidate)
    return staging.mark_lab_observed(candidate, evidence=_lab_evidence(candidate))


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


def _lab_observed_executor() -> tuple[SharedTypedOperationExecutor, object]:
    observed = _lab_observed_operation()
    executor = SharedTypedOperationExecutor()
    return executor, observed


def _certified_executor() -> tuple[SharedTypedOperationExecutor, object]:
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
    certified = promote_through_pipeline(
        staging=OperationPromotionRegistry(),
        runtime=executor.registry,
        candidate=candidate,
        evidence=_lab_evidence(candidate),
    )
    return executor, certified


def test_dry_run_cannot_emit_pass() -> None:
    executor, observed = _lab_observed_executor()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    context = _certification_context(observed, dry_run=True)
    with pytest.raises(ExecutorError, match="dry-run"):
        executor.execute_certification(
            observed,
            intent=intent,
            context=context,
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_mock_transport_cannot_emit_pass() -> None:
    executor, observed = _lab_observed_executor()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    context = _certification_context(observed, mock_transport=True)
    with pytest.raises(ExecutorError, match="mock"):
        executor.execute_certification(
            observed,
            intent=intent,
            context=context,
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_no_transport_cannot_emit_pass() -> None:
    executor, observed = _lab_observed_executor()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    context = _certification_context(observed, no_transport=True)
    with pytest.raises(ExecutorError, match="no-transport"):
        executor.execute_certification(
            observed,
            intent=intent,
            context=context,
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_execute_certification_rejects_candidate_promotion_state() -> None:
    executor, certified = _certified_executor()
    intent = TypedIntent(
        operation_spec_digest=certified.spec.spec_digest,
        fields={"mode": "on"},
    )
    with pytest.raises(ExecutorError, match="lab_observed"):
        executor.execute_certification(
            certified,
            intent=intent,
            context=_certification_context(certified),
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_execute_certification_rejects_missing_evidence_flags() -> None:
    executor, observed = _lab_observed_executor()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    with pytest.raises(ExecutorError, match="readback evidence required"):
        executor.execute_certification(
            observed,
            intent=intent,
            context=_certification_context(
                observed,
                readback_evidence=False,
                functional_evidence=True,
                compensation_evidence=True,
            ),
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_execute_certification_rejects_grant_digest_mismatch() -> None:
    executor, observed = _lab_observed_executor()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    with pytest.raises(ExecutorError, match="grant digest mismatch"):
        executor.execute_certification(
            observed,
            intent=intent,
            context=_certification_context(
                observed,
                lab_observed_grant_digest="sha256:" + "f" * 64,
            ),
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_runtime_requires_write_certified() -> None:
    executor, certified = _certified_executor()
    intent = TypedIntent(
        operation_spec_digest=certified.spec.spec_digest,
        fields={"mode": "on"},
    )
    context = RuntimeExecutionContext(
        write_certified=False,
        gate_c_applicable=False,
        gate_c_open=False,
        gate_d_closed=True,
        probe_tuple_match=True,
    )
    with pytest.raises(ExecutorError, match="WriteCertified"):
        executor.execute_runtime(
            family=certified.spec.family.value,
            operation_id=certified.spec.operation_id,
            intent=intent,
            context=context,
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_runtime_requires_gate_d_state() -> None:
    executor, certified = _certified_executor()
    intent = TypedIntent(
        operation_spec_digest=certified.spec.spec_digest,
        fields={"mode": "on"},
    )
    context = RuntimeExecutionContext(
        write_certified=True,
        gate_c_applicable=False,
        gate_c_open=False,
        gate_d_closed=None,
        probe_tuple_match=True,
    )
    with pytest.raises(ExecutorError, match="Gate D state is required"):
        executor.execute_runtime(
            family=certified.spec.family.value,
            operation_id=certified.spec.operation_id,
            intent=intent,
            context=context,
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_runtime_rejects_non_certified_registry() -> None:
    executor = SharedTypedOperationExecutor()
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    intent = TypedIntent(
        operation_spec_digest=lab.spec.spec_digest,
        fields={"mode": "on"},
    )
    context = RuntimeExecutionContext(
        write_certified=True,
        gate_c_applicable=False,
        gate_c_open=False,
        gate_d_closed=True,
        probe_tuple_match=True,
    )
    with pytest.raises(CertifiedOperationUnknown):
        executor.execute_runtime(
            family=lab.spec.family.value,
            operation_id=lab.spec.operation_id,
            intent=intent,
            context=context,
            secret_resolver=InMemorySecretResolver(),
            http_transport=_StubHttpTransport(),
        )


def test_continuation_poll_no_initial_replay() -> None:
    executor, observed = _lab_observed_executor()
    transport = _ContinuationTransport()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    result = executor.execute_certification(
        observed,
        intent=intent,
        context=_certification_context(observed),
        secret_resolver=InMemorySecretResolver(),
        http_transport=transport,
    )
    assert result.passed
    assert transport.wire_calls == 1
    assert transport.poll_calls == 1
    assert result.instrumentation.continuation_rounds == 1
    assert result.sanitized["initial_mutation_replayed"] is False


def test_continuation_session_loss() -> None:
    executor, observed = _lab_observed_executor()

    class _SessionLossTransport(_ContinuationTransport):
        def poll_continuation(self, *, token):  # type: ignore[no-untyped-def]
            self.poll_calls += 1
            return HttpExchange(status=401, headers={}, body=b"")

    transport = _SessionLossTransport()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    result = executor.execute_certification(
        observed,
        intent=intent,
        context=_certification_context(observed),
        secret_resolver=InMemorySecretResolver(),
        http_transport=transport,
    )
    assert not result.passed
    assert result.error is not None
    assert result.error.error_code == "session_loss"


def test_continuation_timeout() -> None:
    executor, observed = _lab_observed_executor()

    class _TimeoutTransport(_ContinuationTransport):
        def poll_continuation(self, *, token):  # type: ignore[no-untyped-def]
            self.poll_calls += 1
            return HttpExchange(status=408, headers={}, body=b"")

    transport = _TimeoutTransport()
    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    result = executor.execute_certification(
        observed,
        intent=intent,
        context=_certification_context(observed),
        secret_resolver=InMemorySecretResolver(),
        http_transport=transport,
    )
    assert not result.passed
    assert result.error is not None
    assert result.error.error_code == "timeout"


def test_http200_command_error_fail_closed() -> None:
    executor, observed = _lab_observed_executor()

    class _CommandErrorTransport:
        def execute_wire(self, request):  # type: ignore[no-untyped-def]
            return HttpExchange(
                status=200,
                headers={},
                body=json.dumps({"error": "rejected"}).encode("utf-8"),
            )

        def poll_continuation(self, *, token):  # type: ignore[no-untyped-def]
            raise AssertionError("poll not expected")

    intent = TypedIntent(
        operation_spec_digest=observed.spec.spec_digest,
        fields={"mode": "on"},
    )
    result = executor.execute_certification(
        observed,
        intent=intent,
        context=_certification_context(observed),
        secret_resolver=InMemorySecretResolver(),
        http_transport=_CommandErrorTransport(),
    )
    assert not result.passed
    assert result.error is not None
    assert result.error.error_code == "command_level_error"


def test_certification_and_runtime_share_executor_digest() -> None:
    executor = SharedTypedOperationExecutor()
    assert executor.executor_digest.startswith("sha256:")
