"""Canonical tuple field extraction from probe evidence — fail-closed on conflicts."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# Canonical binding keys (gate-a-certification.json, TupleBinding, persistence manifests)
# accept probe/evidence aliases listed as the second member of each pair.
TUPLE_EVIDENCE_ALIAS_PAIRS: tuple[tuple[str, str], ...] = (
    ("ndm_build", "build"),
    ("transport", "transport_security"),
    ("device_fingerprint_digest", "device_fingerprint"),
)


class TupleEvidenceConflictError(Exception):
    """Conflicting alias keys in probe/tuple evidence."""


@dataclass(frozen=True, slots=True)
class TupleEvidenceMatchFields:
    ndm_build: str
    transport: str
    device_fingerprint_digest: str


def _coerce_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def resolve_alias_pair(
    evidence: Mapping[str, Any],
    *,
    canonical: str,
    alias: str,
) -> str:
    """Resolve a canonical key and its probe alias; raise when both disagree."""
    canonical_value = _coerce_str(evidence.get(canonical))
    alias_value = _coerce_str(evidence.get(alias))
    if canonical_value and alias_value and canonical_value != alias_value:
        raise TupleEvidenceConflictError(
            f"conflicting tuple evidence keys {canonical!r} ({canonical_value!r}) "
            f"and {alias!r} ({alias_value!r})"
        )
    return canonical_value or alias_value


def extract_tuple_evidence_match_fields(
    evidence: Mapping[str, Any],
) -> TupleEvidenceMatchFields:
    """Extract normalized tuple match fields from probe evidence."""
    return TupleEvidenceMatchFields(
        ndm_build=resolve_alias_pair(evidence, canonical="ndm_build", alias="build"),
        transport=resolve_alias_pair(
            evidence, canonical="transport", alias="transport_security"
        ),
        device_fingerprint_digest=resolve_alias_pair(
            evidence,
            canonical="device_fingerprint_digest",
            alias="device_fingerprint",
        ),
    )


def tuple_evidence_fields_or_none(
    evidence: Mapping[str, Any],
) -> TupleEvidenceMatchFields | None:
    """Return match fields, or None when alias keys conflict (fail-closed deny)."""
    try:
        return extract_tuple_evidence_match_fields(evidence)
    except TupleEvidenceConflictError:
        return None


__all__ = [
    "TUPLE_EVIDENCE_ALIAS_PAIRS",
    "TupleEvidenceConflictError",
    "TupleEvidenceMatchFields",
    "extract_tuple_evidence_match_fields",
    "resolve_alias_pair",
    "tuple_evidence_fields_or_none",
]
