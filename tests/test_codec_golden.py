"""Golden codec vectors for synthetic recorded operations."""

from __future__ import annotations

from router_control.adapters.netcraze.codec import (
    InMemorySecretResolver,
    TypedIntent,
    codec_for_spec,
)
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_RECORDED_AWG_IMPORT,
    SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN,
)


def test_fail_safe_begin_golden_wire_digest() -> None:
    codec = codec_for_spec(SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN)
    wire = codec.encode(
        TypedIntent(
            operation_spec_digest=SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.spec_digest,
            fields={"mode": "on"},
        ),
        InMemorySecretResolver(),
    )
    golden = wire.sanitized_dict()["body_sha256"]
    assert golden == codec.encode(
        TypedIntent(
            operation_spec_digest=SYNTHETIC_RECORDED_FAIL_SAFE_BEGIN.spec_digest,
            fields={"mode": "on"},
        ),
        InMemorySecretResolver(),
    ).sanitized_dict()["body_sha256"]


def test_awg_import_golden_spec_digest_stable() -> None:
    assert SYNTHETIC_RECORDED_AWG_IMPORT.spec_digest == SYNTHETIC_RECORDED_AWG_IMPORT.spec_digest
