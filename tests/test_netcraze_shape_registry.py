"""Tests for generalized family shape registry."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.capability_families import CapabilityFamily
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_REGISTERED_OPERATIONS,
    build_registered_operation,
)
from router_control.adapters.netcraze.shape_registry import (
    CertifiedOperationRegistry,
    CertifiedOperationUnknown,
    CommandShapeUnknown,
    FamilyRegisteredShape,
    FamilyShapeRegistry,
    LabObservedEvidence,
    OperationPromotionRegistry,
    PromotionError,
    ShapePromotionState,
    ShapeRegistryError,
    promote_through_pipeline,
)

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"


def _lab_evidence(operation) -> LabObservedEvidence:
    return LabObservedEvidence(
        tuple_component_set_digest=operation.tuple_component_set_digest,
        tuple_device_fingerprint_digest=operation.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=operation.gate_a_evidence_digest,
        evidence_digest=operation.evidence_digest,
        trial_authorized=True,
        artifact_digest_verified=True,
    )


def _candidate_from_lab(lab) -> object:
    return build_registered_operation(
        lab.spec,
        promotion_state=ShapePromotionState.CANDIDATE.value,
        tuple_component_set_digest=lab.tuple_component_set_digest,
        tuple_device_fingerprint_digest=lab.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=lab.gate_a_evidence_digest,
        adapter_version=lab.adapter_version,
        evidence_digest=lab.evidence_digest,
    )


def _sample_shape(**overrides: object) -> FamilyRegisteredShape:
    base = dict(
        family=CapabilityFamily.FAIL_SAFE,
        operation_id="fail_safe_begin",
        method="POST",
        path="/rci/fail-safe/begin",
        body_keys=("mode",),
        tuple_component_set_digest=COMPONENT_DIGEST,
        tuple_device_fingerprint_digest=FINGERPRINT_DIGEST,
        adapter_version="netcraze-m5-v0",
    )
    base.update(overrides)
    return FamilyRegisteredShape(**base)  # type: ignore[arg-type]


def test_empty_registry_denies_all() -> None:
    registry = FamilyShapeRegistry()
    assert len(registry) == 0
    with pytest.raises(CommandShapeUnknown):
        registry.get(CapabilityFamily.FAIL_SAFE, "fail_safe_begin")


def test_register_and_get_shape() -> None:
    registry = FamilyShapeRegistry()
    shape = _sample_shape()
    registry.register_shape(shape)
    assert registry.is_registered(CapabilityFamily.FAIL_SAFE, "fail_safe_begin")
    assert registry.get(CapabilityFamily.FAIL_SAFE, "fail_safe_begin") == shape


def test_reject_secret_body_keys() -> None:
    registry = FamilyShapeRegistry()
    with pytest.raises(ShapeRegistryError, match="secret-like"):
        registry.register_shape(_sample_shape(body_keys=("password",)))


def test_reject_duplicate_ambiguous() -> None:
    registry = FamilyShapeRegistry()
    registry.register_shape(_sample_shape())
    with pytest.raises(ShapeRegistryError, match="ambiguous duplicate"):
        registry.register_shape(_sample_shape(path="/rci/other"))


def test_hash_pending_manifest_entry_rejected() -> None:
    registry = FamilyShapeRegistry()
    with pytest.raises(ShapeRegistryError, match="hash_pending"):
        registry.register_from_manifest_entry(
            {
                "operation_id": "fail_safe_begin",
                "method": "POST",
                "path": "/rci/fail-safe/begin",
                "body_keys": ["mode"],
                "evidence_hash": "hash_pending",
            },
            family=CapabilityFamily.FAIL_SAFE,
            component_set_digest=COMPONENT_DIGEST,
            device_fingerprint_digest=FINGERPRINT_DIGEST,
            adapter_version="netcraze-m5-v0",
        )


def test_missing_evidence_hash_rejected() -> None:
    registry = FamilyShapeRegistry()
    with pytest.raises(ShapeRegistryError, match="missing evidence_hash"):
        registry.register_from_manifest_entry(
            {
                "operation_id": "fail_safe_begin",
                "method": "POST",
                "path": "/rci/fail-safe/begin",
                "body_keys": ["mode"],
            },
            family=CapabilityFamily.FAIL_SAFE,
            component_set_digest=COMPONENT_DIGEST,
            device_fingerprint_digest=FINGERPRINT_DIGEST,
            adapter_version="netcraze-m5-v0",
        )


def test_valid_evidence_hash_registers() -> None:
    registry = FamilyShapeRegistry()
    evidence_hash = "sha256:" + "a" * 64
    shape = registry.register_from_manifest_entry(
        {
            "operation_id": "fail_safe_begin",
            "method": "POST",
            "path": "/rci/fail-safe/begin",
            "body_keys": ["mode"],
            "evidence_hash": evidence_hash,
        },
        family=CapabilityFamily.FAIL_SAFE,
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        adapter_version="netcraze-m5-v0",
    )
    assert shape.evidence_hash == evidence_hash
    assert registry.is_registered(CapabilityFamily.FAIL_SAFE, "fail_safe_begin")


def test_tuple_mismatch_rejected() -> None:
    registry = FamilyShapeRegistry()
    with pytest.raises(ShapeRegistryError, match="tuple"):
        registry.register_from_manifest_entry(
            {
                "operation_id": "fail_safe_begin",
                "method": "POST",
                "path": "/rci/fail-safe/begin",
                "body_keys": ["mode"],
                "tuple_binding": {"component_set_digest": "sha256:" + "a" * 64},
            },
            family=CapabilityFamily.FAIL_SAFE,
            component_set_digest=COMPONENT_DIGEST,
            device_fingerprint_digest=FINGERPRINT_DIGEST,
            adapter_version="netcraze-m5-v0",
        )


def test_certified_registry_empty_by_default() -> None:
    registry = CertifiedOperationRegistry()
    assert registry.is_empty()
    assert registry.content_digest().startswith("sha256:")
    with pytest.raises(PromotionError, match="certified"):
        registry.register_operation(SYNTHETIC_REGISTERED_OPERATIONS[0])


def test_direct_certified_mint_forbidden() -> None:
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    runtime = CertifiedOperationRegistry()
    minted = build_registered_operation(
        lab.spec,
        promotion_state=ShapePromotionState.CERTIFIED.value,
        tuple_component_set_digest=lab.tuple_component_set_digest,
        tuple_device_fingerprint_digest=lab.tuple_device_fingerprint_digest,
        gate_a_evidence_digest=lab.gate_a_evidence_digest,
        adapter_version=lab.adapter_version,
        evidence_digest=lab.evidence_digest,
    )
    with pytest.raises(PromotionError, match="direct certified mint"):
        runtime.register_operation(minted)


def test_mark_lab_observed_requires_evidence() -> None:
    staging = OperationPromotionRegistry()
    candidate = _candidate_from_lab(SYNTHETIC_REGISTERED_OPERATIONS[0])
    staging.register_candidate(candidate)
    with pytest.raises(PromotionError, match="trial authorization"):
        staging.mark_lab_observed(
            candidate,
            evidence=LabObservedEvidence(
                tuple_component_set_digest=candidate.tuple_component_set_digest,
                tuple_device_fingerprint_digest=candidate.tuple_device_fingerprint_digest,
                gate_a_evidence_digest=candidate.gate_a_evidence_digest,
                evidence_digest=candidate.evidence_digest,
                trial_authorized=False,
                artifact_digest_verified=True,
            ),
        )


def test_revoke_on_digest_change_removes_certified() -> None:
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    staging = OperationPromotionRegistry()
    runtime = CertifiedOperationRegistry()
    candidate = _candidate_from_lab(lab)
    promote_through_pipeline(
        staging=staging,
        runtime=runtime,
        candidate=candidate,
        evidence=_lab_evidence(candidate),
    )
    assert not runtime.is_empty()
    runtime.revoke_on_digest_change(
        lab.spec.family,
        lab.spec.operation_id,
        next_spec_digest="sha256:" + "f" * 64,
    )
    with pytest.raises(CertifiedOperationUnknown):
        runtime.get_registered(lab.spec.family, lab.spec.operation_id)


def test_promotion_lab_observed_to_certified() -> None:
    staging = OperationPromotionRegistry()
    lab = SYNTHETIC_REGISTERED_OPERATIONS[0]
    candidate = _candidate_from_lab(lab)
    staging.register_candidate(candidate)
    observed = staging.mark_lab_observed(candidate, evidence=_lab_evidence(candidate))
    runtime = CertifiedOperationRegistry()
    promoted = runtime.promote_lab_observed_to_certified(
        observed,
        lab_evidence_verified=True,
        independent_promotion=True,
        persistent_family_certification=True,
    )
    assert promoted.promotion_state == ShapePromotionState.CERTIFIED.value
    assert not runtime.is_empty()
