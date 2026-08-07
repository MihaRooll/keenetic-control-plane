"""Evidence manifest loader and validator — sanitized, provenance-gated."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

from router_control.adapters.netcraze.capability_families import (
    CapabilityFamily,
    TupleBinding,
    parse_capability_family,
)
from router_control.adapters.netcraze.shape_registry import FamilyShapeRegistry, ShapeRegistryError

_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_HASH_PENDING = "hash_pending"
DEFAULT_MAX_AGE_DAYS = 90

_MANIFEST_ALLOWED_KEYS = frozenset(
    {
        "manifest_id",
        "capability_family",
        "source_url",
        "content_hash",
        "retrieved_at",
        "provenance_tier",
        "tuple_binding",
        "operations",
        "adapter_version",
    }
)
_OPERATION_ALLOWED_KEYS = frozenset(
    {
        "operation_id",
        "semantics",
        "method",
        "path",
        "body_keys",
        "read_back",
        "postconditions",
        "rollback",
    }
)
_TUPLE_BINDING_ALLOWED_KEYS = frozenset(
    {
        "model",
        "firmware_version",
        "ndm_build",
        "bsp_build",
        "update_channel",
        "region",
        "component_set_digest",
        "device_fingerprint_digest",
        "transport",
        "ssh_host_key_algorithm",
    }
)


class EvidenceManifestError(ShapeRegistryError):
    """Manifest validation failure."""


class ProvenanceTier(StrEnum):
    OFFICIAL_VENDOR = "official_vendor"
    LAB_OBSERVED = "lab_observed"
    COMMUNITY_CANDIDATE = "community_candidate"


REGISTRATION_ALLOWED_PROVENANCE: frozenset[ProvenanceTier] = frozenset(
    {ProvenanceTier.LAB_OBSERVED}
)
CANDIDATE_ONLY_PROVENANCE: frozenset[ProvenanceTier] = frozenset(
    {
        ProvenanceTier.OFFICIAL_VENDOR,
        ProvenanceTier.COMMUNITY_CANDIDATE,
    }
)


@dataclass(frozen=True, slots=True)
class ManifestOperationEntry:
    operation_id: str
    semantics: str
    method: str
    path: str
    body_keys: tuple[str, ...]
    read_back: tuple[str, ...]
    postconditions: tuple[str, ...]
    rollback: tuple[str, ...]

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "semantics": self.semantics,
            "method": self.method,
            "path": self.path,
            "body_keys": list(self.body_keys),
            "read_back": list(self.read_back),
            "postconditions": list(self.postconditions),
            "rollback": list(self.rollback),
        }


@dataclass(frozen=True, slots=True)
class EvidenceManifest:
    manifest_id: str
    capability_family: CapabilityFamily
    source_url: str
    content_hash: str
    retrieved_at: datetime
    provenance_tier: ProvenanceTier
    tuple_binding: TupleBinding
    operations: tuple[ManifestOperationEntry, ...]
    adapter_version: str

    @property
    def hash_is_pending(self) -> bool:
        return self.content_hash == _HASH_PENDING

    @property
    def registration_eligible(self) -> bool:
        return (
            not self.hash_is_pending
            and self.provenance_tier == ProvenanceTier.LAB_OBSERVED
            and bool(_SHA256_PREFIX_RE.match(self.content_hash.strip().lower()))
        )

    @property
    def candidate_only(self) -> bool:
        return self.hash_is_pending or self.provenance_tier in CANDIDATE_ONLY_PROVENANCE

    def sanitized_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "capability_family": self.capability_family.value,
            "source_url": self.source_url,
            "content_hash": self.content_hash,
            "retrieved_at": self.retrieved_at.isoformat(),
            "provenance_tier": self.provenance_tier.value,
            "tuple_binding": self.tuple_binding.sanitized_dict(),
            "operations": [op.sanitized_dict() for op in self.operations],
            "adapter_version": self.adapter_version,
            "registration_eligible": self.registration_eligible,
        }


def _parse_iso_datetime(value: str, *, field: str) -> datetime:
    text = value.strip()
    if not text:
        raise EvidenceManifestError(f"missing {field}")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise EvidenceManifestError(f"missing or invalid {key}")
    return value.strip()


def _parse_tuple_binding(data: dict[str, Any]) -> TupleBinding:
    return TupleBinding(
        model=_require_str(data, "model"),
        firmware_version=_require_str(data, "firmware_version"),
        ndm_build=_require_str(data, "ndm_build"),
        bsp_build=_require_str(data, "bsp_build"),
        update_channel=_require_str(data, "update_channel"),
        region=_require_str(data, "region"),
        component_set_digest=_require_str(data, "component_set_digest"),
        device_fingerprint_digest=_require_str(data, "device_fingerprint_digest"),
        transport=_require_str(data, "transport"),
        ssh_host_key_algorithm=_require_str(data, "ssh_host_key_algorithm"),
    )


def _parse_operation_entry(data: dict[str, Any]) -> ManifestOperationEntry:
    _reject_unknown_keys(data, allowed=_OPERATION_ALLOWED_KEYS, label="operation")
    operation_id = _require_str(data, "operation_id")
    body_keys_raw = data.get("body_keys") or []
    if not isinstance(body_keys_raw, list):
        raise EvidenceManifestError("operation body_keys must be a list")

    def _str_tuple(key: str) -> tuple[str, ...]:
        raw = data.get(key) or []
        if not isinstance(raw, list):
            raise EvidenceManifestError(f"operation {key} must be a list")
        return tuple(str(item) for item in raw)

    return ManifestOperationEntry(
        operation_id=operation_id,
        semantics=_require_str(data, "semantics"),
        method=_require_str(data, "method").upper(),
        path=_require_str(data, "path"),
        body_keys=tuple(str(item) for item in body_keys_raw),
        read_back=_str_tuple("read_back"),
        postconditions=_str_tuple("postconditions"),
        rollback=_str_tuple("rollback"),
    )


def _reject_unknown_keys(data: dict[str, Any], *, allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(data.keys()) - allowed)
    if unknown:
        raise EvidenceManifestError(f"{label} has unknown fields: {unknown}")


def _normalize_content_hash(value: str) -> str:
    digest = value.strip().lower()
    if digest == _HASH_PENDING:
        return digest
    if not _SHA256_PREFIX_RE.match(digest):
        raise EvidenceManifestError("content_hash must be sha256:<64-hex> or hash_pending")
    return digest


def verify_manifest_artifact_bytes(*, artifact_path: Path, content_hash: str) -> None:
    """Require retained local artifact bytes whose SHA256 matches manifest content_hash."""
    if content_hash == _HASH_PENDING:
        raise EvidenceManifestError("hash_pending manifests cannot verify artifact bytes")
    if not artifact_path.is_file():
        raise EvidenceManifestError(f"artifact not found: {artifact_path}")
    digest = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    expected = content_hash.split(":", 1)[1] if content_hash.startswith("sha256:") else content_hash
    if digest.lower() != expected.lower():
        raise EvidenceManifestError("artifact byte SHA256 mismatch with content_hash")


def validate_manifest_mapping(
    data: dict[str, Any],
    *,
    now: datetime | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    expected_tuple: TupleBinding | None = None,
) -> EvidenceManifest:
    if not isinstance(data, dict):
        raise EvidenceManifestError("manifest must be an object")
    _reject_unknown_keys(data, allowed=_MANIFEST_ALLOWED_KEYS, label="manifest")

    manifest_id = _require_str(data, "manifest_id")
    family_raw = _require_str(data, "capability_family")
    try:
        family = parse_capability_family(family_raw)
    except ValueError as exc:
        raise EvidenceManifestError(str(exc)) from exc

    source_url = _require_str(data, "source_url")
    content_hash = _normalize_content_hash(_require_str(data, "content_hash"))

    retrieved_at = _parse_iso_datetime(_require_str(data, "retrieved_at"), field="retrieved_at")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if retrieved_at > current + timedelta(minutes=5):
        raise EvidenceManifestError("retrieved_at must not be in the future")
    if current - retrieved_at > timedelta(days=max_age_days):
        raise EvidenceManifestError("manifest evidence is stale")

    provenance_raw = _require_str(data, "provenance_tier")
    try:
        provenance = ProvenanceTier(provenance_raw)
    except ValueError as exc:
        raise EvidenceManifestError(f"unknown provenance_tier: {provenance_raw}") from exc

    tuple_data = data.get("tuple_binding")
    if not isinstance(tuple_data, dict):
        raise EvidenceManifestError("tuple_binding must be an object")
    _reject_unknown_keys(tuple_data, allowed=_TUPLE_BINDING_ALLOWED_KEYS, label="tuple_binding")
    tuple_binding = _parse_tuple_binding(tuple_data)
    if expected_tuple is not None:
        if tuple_binding.sanitized_dict() != expected_tuple.sanitized_dict():
            raise EvidenceManifestError("tuple_binding mismatch with expected binding")

    operations_raw = data.get("operations") or []
    if not isinstance(operations_raw, list) or not operations_raw:
        raise EvidenceManifestError("operations must be a non-empty list")

    seen_ops: set[str] = set()
    operations: list[ManifestOperationEntry] = []
    for item in operations_raw:
        if not isinstance(item, dict):
            raise EvidenceManifestError("each operation must be an object")
        entry = _parse_operation_entry(item)
        if entry.operation_id in seen_ops:
            raise EvidenceManifestError(f"duplicate operation_id: {entry.operation_id}")
        seen_ops.add(entry.operation_id)
        operations.append(entry)

    adapter_version = _require_str(data, "adapter_version")

    return EvidenceManifest(
        manifest_id=manifest_id,
        capability_family=family,
        source_url=source_url,
        content_hash=content_hash,
        retrieved_at=retrieved_at,
        provenance_tier=provenance,
        tuple_binding=tuple_binding,
        operations=tuple(operations),
        adapter_version=adapter_version,
    )


def load_evidence_manifest(
    path: Path | str,
    *,
    now: datetime | None = None,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    expected_tuple: TupleBinding | None = None,
) -> EvidenceManifest:
    resolved = Path(path)
    if not resolved.is_file():
        raise EvidenceManifestError(f"manifest not found: {resolved}")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvidenceManifestError(f"malformed manifest JSON: {resolved}") from exc
    if not isinstance(payload, dict):
        raise EvidenceManifestError("manifest must be an object")
    return validate_manifest_mapping(
        payload,
        now=now,
        max_age_days=max_age_days,
        expected_tuple=expected_tuple,
    )


def load_shapes_from_manifest(
    manifest: EvidenceManifest,
    registry: FamilyShapeRegistry,
    *,
    artifact_path: Path | str,
    expected_tuple: TupleBinding | None = None,
) -> tuple[FamilyShapeRegistry, int]:
    if manifest.provenance_tier == ProvenanceTier.COMMUNITY_CANDIDATE:
        raise EvidenceManifestError(
            "community_candidate manifests cannot register certified shapes"
        )
    if manifest.provenance_tier == ProvenanceTier.OFFICIAL_VENDOR:
        raise EvidenceManifestError(
            "official_vendor manifests are candidate-only — lab_observed required for registration"
        )
    if manifest.hash_is_pending:
        raise EvidenceManifestError("hash_pending manifests are candidate-planning only")
    if not manifest.registration_eligible:
        raise EvidenceManifestError("manifest is not eligible for shape registration")
    if expected_tuple is not None:
        if manifest.tuple_binding.sanitized_dict() != expected_tuple.sanitized_dict():
            raise EvidenceManifestError("manifest tuple_binding mismatch with expected binding")

    resolved_artifact = Path(artifact_path)
    verify_manifest_artifact_bytes(
        artifact_path=resolved_artifact,
        content_hash=manifest.content_hash,
    )

    registered = 0
    for op in manifest.operations:
        registry.register_from_manifest_entry(
            {
                "operation_id": op.operation_id,
                "method": op.method,
                "path": op.path,
                "body_keys": list(op.body_keys),
                "tuple_binding": manifest.tuple_binding.sanitized_dict(),
                "evidence_hash": manifest.content_hash,
            },
            family=manifest.capability_family,
            component_set_digest=manifest.tuple_binding.component_set_digest,
            device_fingerprint_digest=manifest.tuple_binding.device_fingerprint_digest,
            adapter_version=manifest.adapter_version,
        )
        registered += 1
    return registry, registered


def manifest_eligible_for_lab_observed(manifest: EvidenceManifest) -> bool:
    """Lab observed registration requires verified bytes and exact tuple — not Certified runtime."""
    return manifest.registration_eligible and manifest.provenance_tier.value == "lab_observed"


def manifest_revoked_on_digest_change(
    *,
    prior_evidence_digest: str,
    next_evidence_digest: str,
) -> bool:
    return prior_evidence_digest.strip().lower() != next_evidence_digest.strip().lower()


__all__ = [
    "CANDIDATE_ONLY_PROVENANCE",
    "DEFAULT_MAX_AGE_DAYS",
    "EvidenceManifest",
    "EvidenceManifestError",
    "ManifestOperationEntry",
    "ProvenanceTier",
    "REGISTRATION_ALLOWED_PROVENANCE",
    "load_evidence_manifest",
    "load_shapes_from_manifest",
    "manifest_eligible_for_lab_observed",
    "manifest_revoked_on_digest_change",
    "validate_manifest_mapping",
    "verify_manifest_artifact_bytes",
]
