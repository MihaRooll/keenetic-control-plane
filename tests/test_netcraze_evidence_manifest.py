"""Tests for evidence manifest loader."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.adapters.netcraze.capability_families import TupleBinding
from router_control.adapters.netcraze.evidence_manifest import (
    EvidenceManifestError,
    load_shapes_from_manifest,
    validate_manifest_mapping,
    verify_manifest_artifact_bytes,
)
from router_control.adapters.netcraze.shape_registry import FamilyShapeRegistry

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
NOW = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)
ARTIFACT_BYTES = b"lab-observed-evidence-bytes"
CONTENT_HASH = "sha256:" + hashlib.sha256(ARTIFACT_BYTES).hexdigest()


def _tuple_binding_dict() -> dict[str, str]:
    return {
        "model": "NC-1812",
        "firmware_version": "5.01.C.1.0-0",
        "ndm_build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
    }


def _valid_manifest(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "manifest_id": "test-manifest",
        "capability_family": "fail_safe",
        "source_url": "https://support.netcraze.ru/example",
        "content_hash": CONTENT_HASH,
        "retrieved_at": NOW.isoformat(),
        "provenance_tier": "lab_observed",
        "tuple_binding": _tuple_binding_dict(),
        "adapter_version": "netcraze-m5-v0",
        "operations": [
            {
                "operation_id": "fail_safe_begin",
                "semantics": "activate fail-safe mode",
                "method": "POST",
                "path": "/rci/fail-safe/begin",
                "body_keys": ["mode"],
                "read_back": ["status"],
                "postconditions": ["fail_safe_active"],
                "rollback": ["timeout_restore"],
            }
        ],
    }
    base.update(overrides)
    return base


def test_validate_success() -> None:
    manifest = validate_manifest_mapping(_valid_manifest(), now=NOW)
    assert manifest.capability_family.value == "fail_safe"
    assert manifest.registration_eligible
    assert manifest.provenance_tier.value == "lab_observed"


def test_official_vendor_is_candidate_only() -> None:
    manifest = validate_manifest_mapping(
        _valid_manifest(provenance_tier="official_vendor"),
        now=NOW,
    )
    assert manifest.candidate_only
    assert not manifest.registration_eligible
    registry = FamilyShapeRegistry()
    artifact = Path("unused")
    with pytest.raises(EvidenceManifestError, match="official_vendor"):
        load_shapes_from_manifest(manifest, registry, artifact_path=artifact)


def test_reject_community_for_registration() -> None:
    manifest = validate_manifest_mapping(
        _valid_manifest(provenance_tier="community_candidate"),
        now=NOW,
    )
    registry = FamilyShapeRegistry()
    with pytest.raises(EvidenceManifestError, match="community_candidate"):
        load_shapes_from_manifest(manifest, registry, artifact_path=Path("unused"))


def test_reject_hash_pending_for_registration() -> None:
    manifest = validate_manifest_mapping(
        _valid_manifest(content_hash="hash_pending"),
        now=NOW,
    )
    assert manifest.hash_is_pending
    registry = FamilyShapeRegistry()
    with pytest.raises(EvidenceManifestError, match="hash_pending"):
        load_shapes_from_manifest(manifest, registry, artifact_path=Path("unused"))


def test_reject_unknown_manifest_fields() -> None:
    payload = _valid_manifest()
    payload["unexpected_field"] = True
    with pytest.raises(EvidenceManifestError, match="unknown fields"):
        validate_manifest_mapping(payload, now=NOW)


def test_reject_stale_manifest() -> None:
    stale_retrieved = (NOW - timedelta(days=120)).isoformat()
    with pytest.raises(EvidenceManifestError, match="stale"):
        validate_manifest_mapping(
            _valid_manifest(retrieved_at=stale_retrieved),
            now=NOW,
        )


def test_reject_duplicate_operation_id() -> None:
    ops = _valid_manifest()["operations"]
    assert isinstance(ops, list)
    duplicate_ops = list(ops) + list(ops)
    with pytest.raises(EvidenceManifestError, match="duplicate"):
        validate_manifest_mapping(_valid_manifest(operations=duplicate_ops), now=NOW)


def test_tuple_mismatch() -> None:
    expected = TupleBinding(**_tuple_binding_dict())  # type: ignore[arg-type]
    bad_binding = dict(_tuple_binding_dict())
    bad_binding["model"] = "OTHER"
    with pytest.raises(EvidenceManifestError, match="tuple_binding mismatch"):
        validate_manifest_mapping(
            _valid_manifest(tuple_binding=bad_binding),
            now=NOW,
            expected_tuple=expected,
        )


def test_load_shapes_requires_verified_artifact_bytes(tmp_path: Path) -> None:
    manifest = validate_manifest_mapping(_valid_manifest(), now=NOW)
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(ARTIFACT_BYTES)
    verify_manifest_artifact_bytes(artifact_path=artifact, content_hash=manifest.content_hash)
    registry = FamilyShapeRegistry()
    _, count = load_shapes_from_manifest(
        manifest,
        registry,
        artifact_path=artifact,
        expected_tuple=TupleBinding(**_tuple_binding_dict()),  # type: ignore[arg-type]
    )
    assert count == 1
    assert registry.is_registered(manifest.capability_family, "fail_safe_begin")


def test_reject_artifact_hash_mismatch(tmp_path: Path) -> None:
    manifest = validate_manifest_mapping(_valid_manifest(), now=NOW)
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"different-bytes")
    registry = FamilyShapeRegistry()
    with pytest.raises(EvidenceManifestError, match="SHA256 mismatch"):
        load_shapes_from_manifest(manifest, registry, artifact_path=artifact)
