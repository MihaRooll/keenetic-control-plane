"""Source catalog provenance negative tests."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from router_control.adapters.netcraze.capability_families import CapabilityFamily
from router_control.adapters.netcraze.evidence_manifest import ProvenanceTier
from router_control.adapters.netcraze.read_discovery import (
    ProposalState,
    SourceCandidate,
    UseDisposition,
    load_read_discovery_catalog,
    validate_source_artifact_bytes,
)
from router_control.adapters.netcraze.shape_registry import ShapeRegistryError

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_catalog_loads_committed_file() -> None:
    catalog = load_read_discovery_catalog()
    assert catalog.catalog_id.startswith("netcraze-source-catalog")


def test_keen_pbr_is_reference_only_non_portable() -> None:
    catalog = load_read_discovery_catalog()
    keen = next(c for c in catalog.candidates if c.candidate_id == "keen-pbr-upstream")
    assert keen.use_disposition == UseDisposition.REFERENCE_ONLY
    assert keen.portable is False
    assert keen.license_status == "GPL-3.0"


def test_rci_tools_unknown_license_non_portable() -> None:
    catalog = load_read_discovery_catalog()
    rci = next(c for c in catalog.candidates if c.candidate_id == "rci-tools-upstream")
    assert rci.license_status == "unknown"
    assert rci.portable is False


def test_validate_bytes_rejects_forged_hash(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"official-bytes")
    forged = "sha256:" + ("f" * 64)
    with pytest.raises(ShapeRegistryError, match="mismatch"):
        validate_source_artifact_bytes(artifact_path=artifact, content_hash=forged)


def test_validate_bytes_accepts_matching_hash(tmp_path: Path) -> None:
    payload = b"retained-bytes"
    digest = "sha256:" + hashlib.sha256(payload).hexdigest()
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(payload)
    validate_source_artifact_bytes(artifact_path=artifact, content_hash=digest)


def test_branch_only_hash_pending_not_registerable() -> None:
    candidate = SourceCandidate(
        candidate_id="branch-only",
        capability_family=CapabilityFamily.FAIL_SAFE,
        title="branch ref",
        source_url="https://github.com/example/repo/tree/main",
        canonical_repo="https://github.com/example/repo",
        immutable_commit="hash_pending",
        content_hash="hash_pending",
        retrieved_at="2026-07-22T00:00:00+00:00",
        provenance_tier=ProvenanceTier.OFFICIAL_VENDOR,
        proposal_state=ProposalState.PENDING,
        use_disposition=UseDisposition.REFERENCE_ONLY,
        license_status="unknown",
        portable=False,
        notes="branch-only",
    )
    assert candidate.immutable_commit == "hash_pending"
