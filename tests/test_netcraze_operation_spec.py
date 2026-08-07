"""OperationSpec immutable revision and digest tests."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_RECORDED_AWG_IMPORT,
    SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN,
    SYNTHETIC_REGISTERED_OPERATIONS,
    OperationSpecError,
    TransportKind,
    build_registered_operation,
)


def test_spec_digest_is_deterministic() -> None:
    first = SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.spec_digest
    second = SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.spec_digest
    assert first == second
    assert first.startswith("sha256:")


def test_codec_and_executor_digests_present() -> None:
    spec = SYNTHETIC_RECORDED_AWG_IMPORT
    assert spec.codec_digest.startswith("sha256:")
    assert spec.executor_digest.startswith("sha256:")
    assert spec.transport_kind == TransportKind.RCI_HTTP


def test_registered_operation_bundle_digests() -> None:
    registered = SYNTHETIC_REGISTERED_OPERATIONS[0]
    bundle = registered.bundle_digests()
    assert bundle["shape_digest"] == registered.shape_digest
    assert bundle["codec_digest"] == registered.codec_digest
    assert bundle["executor_digest"] == registered.executor_digest


def test_build_registered_operation_rejects_bad_digest() -> None:
    with pytest.raises(OperationSpecError, match="sha256"):
        build_registered_operation(
            SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN,
            promotion_state="lab_observed",
            tuple_component_set_digest="bad",
            tuple_device_fingerprint_digest="sha256:" + "a" * 64,
            gate_a_evidence_digest="sha256:" + "b" * 64,
            adapter_version="v0",
            evidence_digest="sha256:" + "c" * 64,
        )
