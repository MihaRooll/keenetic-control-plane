"""Tests for read discovery catalog."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import ALLOWLIST
from router_control.adapters.netcraze.capability_families import CapabilityFamily
from router_control.adapters.netcraze.read_discovery import (
    HASH_PENDING,
    ProposalState,
    UseDisposition,
    gate_a_allowlist_unchanged,
    load_read_discovery_catalog,
    propose_allowlist_candidate,
)
from router_control.adapters.netcraze.shape_registry import ShapeRegistryError

REPO_ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = REPO_ROOT / "docs" / "netcraze-source-catalog.json"


def _candidate_by_id(catalog, candidate_id: str):
    return next(c for c in catalog.candidates if c.candidate_id == candidate_id)


def test_load_source_catalog() -> None:
    catalog = load_read_discovery_catalog(CATALOG_PATH)
    assert catalog.catalog_id.startswith("netcraze-source-catalog")
    assert len(catalog.candidates) >= 10
    fail_safe = catalog.for_family(CapabilityFamily.FAIL_SAFE)
    assert any(c.candidate_id == "fail-safe-mode" for c in fail_safe)

    keen_pbr = _candidate_by_id(catalog, "keen-pbr-upstream")
    assert keen_pbr.use_disposition == UseDisposition.REFERENCE_ONLY
    assert keen_pbr.content_hash == HASH_PENDING
    assert keen_pbr.portable is False
    assert keen_pbr.license_status == "GPL-3.0"
    assert keen_pbr.proposal_state == ProposalState.REJECTED

    rci_tools = _candidate_by_id(catalog, "rci-tools-upstream")
    assert rci_tools.use_disposition == UseDisposition.REFERENCE_ONLY
    assert rci_tools.content_hash == HASH_PENDING
    assert rci_tools.portable is False
    assert rci_tools.license_status == "unknown"
    assert rci_tools.proposal_state == ProposalState.REJECTED


def test_community_candidate_rejected_state() -> None:
    catalog = load_read_discovery_catalog(CATALOG_PATH)
    amnezia = _candidate_by_id(catalog, "amnezia-community-docs")
    assert amnezia.proposal_state == ProposalState.REJECTED
    assert amnezia.use_disposition == UseDisposition.UNSPECIFIED
    assert amnezia.portable is False

    rci_tools = _candidate_by_id(catalog, "rci-tools-upstream")
    assert rci_tools.use_disposition == UseDisposition.REFERENCE_ONLY
    assert rci_tools.content_hash == HASH_PENDING
    assert rci_tools.portable is False
    assert rci_tools.proposal_state == ProposalState.REJECTED


def test_reference_only_candidate_cannot_be_promoted() -> None:
    catalog = load_read_discovery_catalog(CATALOG_PATH)
    with pytest.raises(ShapeRegistryError, match="not registerable for observation"):
        propose_allowlist_candidate(
            catalog,
            "rci-tools-upstream",
            new_state=ProposalState.APPROVED_FOR_OBSERVATION,
        )


def test_proposal_does_not_change_gate_a_allowlist() -> None:
    before = gate_a_allowlist_unchanged()
    assert before == frozenset(cmd.name for cmd in ALLOWLIST)
    assert len(before) == 4

    catalog = load_read_discovery_catalog(CATALOG_PATH)
    candidate = catalog.pending_proposals()[0]
    pending_before = len(catalog.pending_proposals())
    with pytest.raises(ShapeRegistryError, match="not registerable for observation"):
        propose_allowlist_candidate(
            catalog,
            candidate.candidate_id,
            new_state=ProposalState.APPROVED_FOR_OBSERVATION,
        )
    updated_catalog = propose_allowlist_candidate(
        catalog,
        candidate.candidate_id,
        new_state=ProposalState.REJECTED,
    )
    updated = next(
        c for c in updated_catalog.candidates if c.candidate_id == candidate.candidate_id
    )
    assert updated.proposal_state == ProposalState.REJECTED
    assert len(updated_catalog.pending_proposals()) == pending_before - 1
    assert len(catalog.pending_proposals()) == pending_before
    after = gate_a_allowlist_unchanged()
    assert after == before
