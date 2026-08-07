"""Read discovery catalog — official source candidates, proposal state only.

Gate A ``ALLOWLIST`` (four frozen reads) is never mutated by catalog proposals.
Non-certifying discovery reads use separate ``DISCOVERY_ALLOWLIST`` with
GET ``/rci/show/interface`` and GET ``/rci/show/ip/route`` — see
``router_control.adapters.netcraze.topology_probe`` and
``router_control.adapters.netcraze.route_topology_probe`` (still never mutates Gate A).
Station configured/runtime readback uses ``STATION_READ_ALLOWLIST`` (includes
GET ``/rci/show/rc/interface``) — separate from topology discovery.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from enum import StrEnum
from pathlib import Path
from typing import Any

from router_control.adapters.netcraze.capability_families import (
    CapabilityFamily,
    parse_capability_family,
)
from router_control.adapters.netcraze.evidence_manifest import ProvenanceTier
from router_control.adapters.netcraze.shape_registry import ShapeRegistryError

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_CATALOG_PATH = REPO_ROOT / "docs" / "netcraze-source-catalog.json"
HASH_PENDING = "hash_pending"
_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")


class ProposalState(StrEnum):
    PENDING = "pending"
    APPROVED_FOR_OBSERVATION = "approved_for_observation"
    REJECTED = "rejected"


class UseDisposition(StrEnum):
    UNSPECIFIED = "unspecified"
    REFERENCE_ONLY = "reference_only"


@dataclass(frozen=True, slots=True)
class SourceCandidate:
    candidate_id: str
    capability_family: CapabilityFamily
    title: str
    source_url: str
    content_hash: str
    retrieved_at: str
    provenance_tier: ProvenanceTier
    proposal_state: ProposalState
    use_disposition: UseDisposition
    license_status: str
    portable: bool
    notes: str
    canonical_repo: str = ""
    immutable_commit: str = "hash_pending"

    def sanitized_dict(self) -> dict[str, Any]:
        payload = {
            "candidate_id": self.candidate_id,
            "capability_family": self.capability_family.value,
            "title": self.title,
            "source_url": self.source_url,
            "content_hash": self.content_hash,
            "retrieved_at": self.retrieved_at,
            "provenance_tier": self.provenance_tier.value,
            "proposal_state": self.proposal_state.value,
            "use_disposition": self.use_disposition.value,
            "license_status": self.license_status,
            "portable": self.portable,
            "notes": self.notes,
        }
        if self.canonical_repo:
            payload["canonical_repo"] = self.canonical_repo
        if self.immutable_commit:
            payload["immutable_commit"] = self.immutable_commit
        return payload


def _candidate_registerable_for_observation(candidate: SourceCandidate) -> bool:
    if candidate.use_disposition == UseDisposition.REFERENCE_ONLY:
        return False
    if not candidate.portable:
        return False
    if candidate.content_hash == HASH_PENDING:
        return False
    return True


@dataclass(frozen=True, slots=True)
class ReadDiscoveryCatalog:
    catalog_id: str
    retrieved_at: str
    candidates: tuple[SourceCandidate, ...]

    def for_family(self, family: CapabilityFamily | str) -> tuple[SourceCandidate, ...]:
        resolved = parse_capability_family(family) if isinstance(family, str) else family
        return tuple(c for c in self.candidates if c.capability_family == resolved)

    def pending_proposals(self) -> tuple[SourceCandidate, ...]:
        return tuple(c for c in self.candidates if c.proposal_state == ProposalState.PENDING)

    def approved_for_observation(self) -> tuple[SourceCandidate, ...]:
        return tuple(
            c for c in self.candidates if c.proposal_state == ProposalState.APPROVED_FOR_OBSERVATION
        )

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "catalog_id": self.catalog_id,
            "retrieved_at": self.retrieved_at,
            "candidates": [c.sanitized_dict() for c in self.candidates],
        }


def _parse_candidate(data: dict[str, Any]) -> SourceCandidate:
    candidate_id = str(data.get("candidate_id", "")).strip()
    if not candidate_id:
        raise ShapeRegistryError("candidate missing candidate_id")
    try:
        family = parse_capability_family(str(data.get("capability_family", "")))
    except ValueError as exc:
        raise ShapeRegistryError(str(exc)) from exc
    try:
        provenance = ProvenanceTier(str(data.get("provenance_tier", "")))
    except ValueError as exc:
        raise ShapeRegistryError(f"unknown provenance_tier: {data.get('provenance_tier')}") from exc
    try:
        proposal = ProposalState(str(data.get("proposal_state", "pending")))
    except ValueError as exc:
        raise ShapeRegistryError(f"unknown proposal_state: {data.get('proposal_state')}") from exc
    try:
        use_disposition = UseDisposition(str(data.get("use_disposition", "unspecified")))
    except ValueError as exc:
        raise ShapeRegistryError(f"unknown use_disposition: {data.get('use_disposition')}") from exc
    portable_raw = data.get("portable", False)
    if not isinstance(portable_raw, bool):
        raise ShapeRegistryError("portable must be a boolean when present")
    source_url = str(data.get("source_url", "")).strip()
    license_status = str(data.get("license_status", "")).strip()
    if provenance in {ProvenanceTier.OFFICIAL_VENDOR, ProvenanceTier.COMMUNITY_CANDIDATE}:
        if not license_status:
            raise ShapeRegistryError(
                f"{candidate_id}: {provenance.value} entry requires license_status"
            )
        if "use_disposition" not in data:
            raise ShapeRegistryError(
                f"{candidate_id}: {provenance.value} entry requires use_disposition"
            )
    if "github.com" in source_url.lower() or data.get("canonical_repo"):
        canonical_repo = str(data.get("canonical_repo", "")).strip()
        if not canonical_repo:
            raise ShapeRegistryError(f"{candidate_id}: upstream entry requires canonical_repo")
        if "immutable_commit" not in data:
            raise ShapeRegistryError(f"{candidate_id}: upstream entry requires immutable_commit")
    return SourceCandidate(
        candidate_id=candidate_id,
        capability_family=family,
        title=str(data.get("title", "")),
        source_url=str(data.get("source_url", "")),
        content_hash=str(data.get("content_hash", HASH_PENDING)),
        retrieved_at=str(data.get("retrieved_at", "")),
        provenance_tier=provenance,
        proposal_state=proposal,
        use_disposition=use_disposition,
        license_status=license_status,
        portable=portable_raw,
        notes=str(data.get("notes", "")),
        canonical_repo=str(data.get("canonical_repo", "")),
        immutable_commit=str(data.get("immutable_commit", HASH_PENDING)),
    )


def validate_source_artifact_bytes(*, artifact_path: Path, content_hash: str) -> None:
    """Require retained local artifact bytes whose SHA256 matches catalog content_hash."""
    if content_hash == HASH_PENDING:
        raise ShapeRegistryError("hash_pending catalog entries cannot verify artifact bytes")
    if not _SHA256_PREFIX_RE.match(content_hash.strip().lower()):
        raise ShapeRegistryError("content_hash must be sha256:<64-hex> or hash_pending")
    if not artifact_path.is_file():
        raise ShapeRegistryError(f"artifact not found: {artifact_path}")
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    expected = content_hash.split(":", 1)[1] if content_hash.startswith("sha256:") else content_hash
    if digest.lower() != expected.lower():
        raise ShapeRegistryError("artifact byte SHA256 mismatch with content_hash")


def load_read_discovery_catalog(path: Path | str | None = None) -> ReadDiscoveryCatalog:
    resolved = Path(path) if path is not None else DEFAULT_CATALOG_PATH
    if not resolved.is_file():
        raise ShapeRegistryError(f"source catalog not found: {resolved}")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ShapeRegistryError(f"malformed source catalog JSON: {resolved}") from exc
    if not isinstance(payload, dict):
        raise ShapeRegistryError("source catalog must be an object")

    candidates_raw = payload.get("candidates") or []
    if not isinstance(candidates_raw, list):
        raise ShapeRegistryError("candidates must be a list")

    seen: set[str] = set()
    candidates: list[SourceCandidate] = []
    for item in candidates_raw:
        if not isinstance(item, dict):
            raise ShapeRegistryError("each candidate must be an object")
        candidate = _parse_candidate(item)
        if candidate.candidate_id in seen:
            raise ShapeRegistryError(f"duplicate candidate_id: {candidate.candidate_id}")
        seen.add(candidate.candidate_id)
        candidates.append(candidate)

    return ReadDiscoveryCatalog(
        catalog_id=str(payload.get("catalog_id", "netcraze-source-catalog")),
        retrieved_at=str(payload.get("retrieved_at", "")),
        candidates=tuple(candidates),
    )


def propose_allowlist_candidate(
    catalog: ReadDiscoveryCatalog,
    candidate_id: str,
    *,
    new_state: ProposalState,
) -> ReadDiscoveryCatalog:
    """Update proposal state in-memory only — never mutates Gate A allowlist."""
    updated: list[SourceCandidate] = []
    found = False
    for candidate in catalog.candidates:
        if candidate.candidate_id == candidate_id:
            found = True
            if (
                new_state == ProposalState.APPROVED_FOR_OBSERVATION
                and not _candidate_registerable_for_observation(candidate)
            ):
                raise ShapeRegistryError(
                    f"candidate not registerable for observation: {candidate_id}"
                )
            updated.append(replace(candidate, proposal_state=new_state))
        else:
            updated.append(candidate)
    if not found:
        raise ShapeRegistryError(f"candidate not found: {candidate_id}")
    return replace(catalog, candidates=tuple(updated))


def gate_a_allowlist_unchanged() -> frozenset[str]:
    """Return frozen Gate A command names — catalog proposals do not expand this set."""
    from router_control.adapters.netcraze.allowlist import ALLOWLIST

    return frozenset(cmd.name for cmd in ALLOWLIST)


__all__ = [
    "DEFAULT_CATALOG_PATH",
    "HASH_PENDING",
    "ProposalState",
    "ReadDiscoveryCatalog",
    "SourceCandidate",
    "UseDisposition",
    "gate_a_allowlist_unchanged",
    "load_read_discovery_catalog",
    "propose_allowlist_candidate",
    "validate_source_artifact_bytes",
]
