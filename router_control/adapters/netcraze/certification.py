"""Typed Gate A certification boundary — fail-closed, not a loose boolean."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from router_control.adapters.netcraze.tuple_evidence import (
    TUPLE_EVIDENCE_ALIAS_PAIRS,
    TupleEvidenceConflictError,
    extract_tuple_evidence_match_fields,
    tuple_evidence_fields_or_none,
)

GateStatus = Literal["open", "closed", "stale_pending_recertification"]
CertificationLevel = Literal["ReadOnlyCertified", "StalePendingRecertification"]

DEFAULT_OPENING_FRESHNESS_HOURS = 24
DEFAULT_OBSERVATION_TTL_SECONDS = 300

_OPENNESS_CLOCK: Callable[[], datetime] | None = None

_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")

_EVIDENCE_REQUIRED_KEYS = frozenset(
    {
        "model",
        "firmware_version",
        "update_channel",
        "region",
        "component_set_digest",
        "certification_eligible",
        "identity_complete",
        "evidence_recorded_at",
    }
)


class GateACertificationError(Exception):
    """Gate A config missing, malformed, stale, or mismatched."""


def _openness_moment(now: datetime | None = None) -> datetime:
    if now is not None:
        moment = now
    elif _OPENNESS_CLOCK is not None:
        moment = _OPENNESS_CLOCK()
    else:
        moment = datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class GateACertification:
    """Sanitized Gate A open tuple; never holds passwords or raw physical IDs."""

    status: GateStatus
    certification: CertificationLevel | None
    approved_scope: str
    model: str
    model_display: str
    firmware_version: str
    firmware_display: str
    ndm_build: str
    bsp_build: str
    update_channel: str
    region: str
    component_set_digest: str
    device_fingerprint_digest: str
    physical_id_source: str
    transport: str
    ssh_host_key_algorithm: str
    ssh_host_key_fingerprint_sha256: str
    certification_eligible: bool
    evidence_recorded_at: datetime
    evidence_path: str
    expires_at: datetime
    revocation_policy: str
    opening_freshness_hours: int = DEFAULT_OPENING_FRESHNESS_HOURS
    evidence_sha256: str | None = None
    gates_b_closed: bool = True
    gates_c_closed: bool = True
    gates_d_closed: bool = True
    checklist: frozenset[str] = frozenset()

    def is_stale_pending_recertification(self) -> bool:
        """Historical tuple retained; observe/load OK, writes fail-closed."""
        return (
            self.status == "stale_pending_recertification"
            or self.certification == "StalePendingRecertification"
        )

    def is_open_at(self, now: datetime | None = None) -> bool:
        """Runtime openness check; defaults to wall clock (fail-closed freshness)."""
        if self.is_stale_pending_recertification():
            return False
        moment = _openness_moment(now)
        opening_deadline = self.evidence_recorded_at + timedelta(hours=self.opening_freshness_hours)
        return (
            self.status == "open"
            and self.certification == "ReadOnlyCertified"
            and self.approved_scope == "SLICE-4-readonly"
            and self.certification_eligible
            and self.gates_b_closed
            and self.gates_c_closed
            and self.gates_d_closed
            and moment <= self.expires_at
            and moment <= opening_deadline
        )

    @property
    def is_open(self) -> bool:
        return self.is_open_at()

    def sanitized_status_payload(self, *, now: datetime | None = None) -> dict[str, Any]:
        open_now = self.is_open_at(now)
        return {
            "gate_a": {
                "status": "open" if open_now else "closed",
                "certification": self.certification if open_now else None,
                "approved_scope": self.approved_scope if open_now else None,
                "model": self.model,
                "firmware_display": self.firmware_display,
                "component_set_digest": self.component_set_digest,
                "device_fingerprint_digest": self.device_fingerprint_digest,
                "transport": self.transport,
                "ssh_host_key_algorithm": self.ssh_host_key_algorithm,
                "evidence_recorded_at": self.evidence_recorded_at.date().isoformat(),
                "expires_at": self.expires_at.date().isoformat(),
            },
            "gates": {
                "A": "open" if open_now else "closed",
                "B": "closed",
                "C": "closed",
                "D": "closed",
            },
        }

    def matches_probe_evidence(self, evidence: dict[str, Any]) -> bool:
        fields = tuple_evidence_fields_or_none(evidence)
        if fields is None:
            return False
        return (
            str(evidence.get("model", "")) == self.model
            and str(evidence.get("firmware_version", "")) == self.firmware_version
            and fields.ndm_build == self.ndm_build
            and str(evidence.get("bsp_build", "")) == self.bsp_build
            and str(evidence.get("update_channel", "")) == self.update_channel
            and str(evidence.get("region", "")) == self.region
            and str(evidence.get("component_set_digest", "")) == self.component_set_digest
            and fields.device_fingerprint_digest == self.device_fingerprint_digest
            and fields.transport == self.transport
            and str(evidence.get("ssh_host_key_algorithm", "")) == self.ssh_host_key_algorithm
            and _normalize_pin(str(evidence.get("ssh_host_key_fingerprint_sha256", "")))
            == _normalize_pin(self.ssh_host_key_fingerprint_sha256)
            and bool(evidence.get("certification_eligible")) is True
            and bool(evidence.get("identity_complete")) is True
        )

    def matches_enroll_request(self, *, model: str, vendor: str) -> bool:
        if vendor.strip().lower() not in ("netcraze", "keenetic"):
            return False
        return model.strip() == self.model


def _normalize_pin(value: str) -> str:
    stripped = value.strip()
    if stripped.upper().startswith("SHA256:"):
        return f"SHA256:{stripped.split(':', 1)[1].strip()}"
    return f"SHA256:{stripped}" if stripped else ""


def _normalize_sha256(value: str) -> str:
    stripped = value.strip().lower()
    if stripped.startswith("sha256:"):
        return stripped.split(":", 1)[1]
    return stripped


def _require_evidence_sha256(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateACertificationError("evidence_sha256 is required when Gate A open")
    normalized = _normalize_sha256(value)
    if not _SHA256_HEX_RE.match(normalized):
        raise GateACertificationError("evidence_sha256 must be a 64-character hex digest")
    return normalized


def _parse_iso_datetime(value: str) -> datetime:
    text = value.strip()
    if not text:
        raise GateACertificationError("evidence_recorded_at is required")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GateACertificationError(f"missing or invalid {key}")
    return value.strip()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise GateACertificationError(f"Gate A config not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateACertificationError(f"malformed Gate A config JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise GateACertificationError(f"Gate A config must be an object: {path}")
    return payload


def _validate_evidence_schema(evidence: dict[str, Any]) -> None:
    missing = sorted(key for key in _EVIDENCE_REQUIRED_KEYS if key not in evidence)
    if missing:
        raise GateACertificationError(f"evidence artifact missing required keys: {missing}")
    for canonical, alias in TUPLE_EVIDENCE_ALIAS_PAIRS:
        if canonical not in evidence and alias not in evidence:
            raise GateACertificationError(
                f"evidence artifact missing required keys: ['{canonical}/{alias}']"
            )
    try:
        fields = extract_tuple_evidence_match_fields(evidence)
    except TupleEvidenceConflictError as exc:
        raise GateACertificationError(str(exc)) from exc
    if not fields.ndm_build:
        raise GateACertificationError("evidence artifact missing build/ndm_build")
    if not fields.device_fingerprint_digest:
        raise GateACertificationError("evidence artifact missing device fingerprint digest")
    if not fields.transport:
        raise GateACertificationError(
            "evidence artifact missing transport/transport_security"
        )
    if fields.transport == "ssh_tunnel":
        for key in ("ssh_host_key_algorithm", "ssh_host_key_fingerprint_sha256"):
            if not str(evidence.get(key, "")).strip():
                raise GateACertificationError(f"evidence artifact missing {key}")


def _validate_evidence_freshness(
    *,
    config: GateACertification,
    evidence_at: datetime,
    now: datetime,
) -> None:
    if evidence_at > config.expires_at:
        raise GateACertificationError("evidence recorded_at beyond Gate A expiry")
    opening_deadline = config.evidence_recorded_at + timedelta(
        hours=config.opening_freshness_hours
    )
    if evidence_at > opening_deadline:
        raise GateACertificationError("evidence recorded_at beyond opening freshness window")
    if now > config.expires_at:
        raise GateACertificationError("Gate A certification expired")
    if now > opening_deadline:
        raise GateACertificationError("Gate A opening freshness expired")


def _validate_evidence_file_hash(
    *,
    evidence_file: Path,
    expected_sha256: str,
) -> None:
    digest = hashlib.sha256(evidence_file.read_bytes()).hexdigest()
    if _normalize_sha256(digest) != _normalize_sha256(expected_sha256):
        raise GateACertificationError("evidence artifact SHA256 mismatch")


def _build_from_mapping(data: dict[str, Any]) -> GateACertification:
    status_raw = _require_str(data, "status").lower()
    if status_raw not in ("open", "closed", "stale_pending_recertification"):
        raise GateACertificationError(
            "status must be open, closed, or stale_pending_recertification"
        )
    certification_raw = data.get("certification")
    certification: CertificationLevel | None = None
    if certification_raw is not None:
        cert_str = str(certification_raw)
        if cert_str == "ReadOnlyCertified":
            certification = "ReadOnlyCertified"
        elif cert_str == "StalePendingRecertification":
            certification = "StalePendingRecertification"
        else:
            raise GateACertificationError(
                "certification must be ReadOnlyCertified or StalePendingRecertification when set"
            )

    recorded_at = _parse_iso_datetime(_require_str(data, "evidence_recorded_at"))
    expiry_days = int(data.get("expires_after_days", 90))
    if expiry_days <= 0:
        raise GateACertificationError("expires_after_days must be positive")
    opening_freshness_hours = int(
        data.get("opening_freshness_hours", DEFAULT_OPENING_FRESHNESS_HOURS)
    )
    if opening_freshness_hours <= 0:
        raise GateACertificationError("opening_freshness_hours must be positive")

    checklist_raw = data.get("checklist") or []
    checklist: frozenset[str] = frozenset()
    if isinstance(checklist_raw, list):
        checklist = frozenset(str(item) for item in checklist_raw)

    eligible = bool(data.get("certification_eligible"))
    if (
        status_raw == "open"
        and certification == "ReadOnlyCertified"
        and not eligible
    ):
        raise GateACertificationError("certification_eligible must be true when Gate A open")

    gates = data.get("gates") or {}
    if not isinstance(gates, dict):
        raise GateACertificationError("gates must be an object")

    def _gate_closed(letter: str) -> bool:
        gate = gates.get(letter) or {}
        if isinstance(gate, dict):
            return str(gate.get("status", "closed")).lower() == "closed"
        return str(gate).lower() == "closed"

    gate_a_active = status_raw in ("open", "stale_pending_recertification")
    if gate_a_active and not (_gate_closed("B") and _gate_closed("C") and _gate_closed("D")):
        raise GateACertificationError("Gate A active requires gates B/C/D closed")

    evidence_sha256: str | None = None
    if status_raw == "open" and certification == "ReadOnlyCertified":
        evidence_sha256 = _require_evidence_sha256(data.get("evidence_sha256"))
    elif data.get("evidence_sha256") is not None:
        evidence_sha256 = _require_evidence_sha256(data.get("evidence_sha256"))

    return GateACertification(
        status=status_raw,  # type: ignore[arg-type]
        certification=certification,
        approved_scope=_require_str(data, "approved_scope"),
        model=_require_str(data, "model"),
        model_display=str(data.get("model_display") or ""),
        firmware_version=_require_str(data, "firmware_version"),
        firmware_display=str(
            data.get("firmware_display") or data.get("firmware_display_title") or ""
        ),
        ndm_build=(
            _require_str(data, "ndm_build")
            if "ndm_build" in data
            else _require_str(data, "build")
        ),
        bsp_build=_require_str(data, "bsp_build"),
        update_channel=_require_str(data, "update_channel"),
        region=_require_str(data, "region"),
        component_set_digest=_require_str(data, "component_set_digest"),
        device_fingerprint_digest=_require_str(
            data,
            "device_fingerprint_digest"
            if "device_fingerprint_digest" in data
            else "device_fingerprint",
        ),
        physical_id_source=_require_str(data, "physical_id_source"),
        transport=_require_str(data, "transport"),
        ssh_host_key_algorithm=_require_str(data, "ssh_host_key_algorithm"),
        ssh_host_key_fingerprint_sha256=_normalize_pin(
            _require_str(data, "ssh_host_key_fingerprint_sha256")
        ),
        certification_eligible=eligible,
        evidence_recorded_at=recorded_at,
        evidence_path=str(data.get("evidence_path") or ""),
        expires_at=recorded_at + timedelta(days=expiry_days),
        revocation_policy=str(data.get("revocation_policy") or "human operator message required"),
        opening_freshness_hours=opening_freshness_hours,
        evidence_sha256=evidence_sha256,
        gates_b_closed=_gate_closed("B"),
        gates_c_closed=_gate_closed("C"),
        gates_d_closed=_gate_closed("D"),
        checklist=checklist,
    )


def _parse_status_yaml_gate_a(status_text: str) -> dict[str, str | None]:
    """Parse gates.A block from STATUS.yaml using bounded indentation rules."""
    lines = status_text.splitlines()
    in_gates = False
    gates_indent = -1
    in_gate_a = False
    gate_a_indent = -1
    parsed: dict[str, str | None] = {"status": None, "certification": None}

    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)

        if stripped == "gates:" or stripped.startswith("gates:"):
            in_gates = True
            gates_indent = indent
            in_gate_a = False
            continue

        if not in_gates:
            continue

        if indent <= gates_indent and not in_gate_a:
            in_gates = False
            continue

        if stripped.startswith("A:") and indent > gates_indent:
            in_gate_a = True
            gate_a_indent = indent
            continue

        if in_gate_a:
            if indent <= gate_a_indent:
                in_gate_a = False
                if stripped.startswith("A:") and indent > gates_indent:
                    in_gate_a = True
                    gate_a_indent = indent
                continue
            if stripped.startswith("status:"):
                parsed["status"] = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            elif stripped.startswith("certification:"):
                parsed["certification"] = (
                    stripped.split(":", 1)[1].strip().strip('"').strip("'")
                )

    return parsed


def _status_declares_gate_a_open(status_text: str) -> bool:
    gate_a = _parse_status_yaml_gate_a(status_text)
    return (
        str(gate_a.get("status") or "").lower() == "open"
        and gate_a.get("certification") == "ReadOnlyCertified"
    )


def _status_declares_gate_a_stale(status_text: str) -> bool:
    gate_a = _parse_status_yaml_gate_a(status_text)
    return gate_a.get("certification") == "StalePendingRecertification"


def load_gate_a_certification(
    *,
    config_path: Path | str | None = None,
    evidence_path: Path | str | None = None,
    status_path: Path | str | None = None,
    require_status_alignment: bool = True,
    require_evidence: bool | None = None,
    now: datetime | None = None,
) -> GateACertification:
    """Load typed Gate A config; open certification always validates STATUS and evidence."""
    repo_root = Path(__file__).resolve().parents[3]
    resolved_config = Path(
        config_path
        or os.environ.get("RC_GATE_A_CONFIG")
        or repo_root / "docs" / "gate-a-certification.json"
    )
    config = _build_from_mapping(_load_json(resolved_config))
    current = now or datetime.now(UTC)

    resolved_status = Path(
        status_path or os.environ.get("RC_STATUS_PATH") or repo_root / "docs" / "STATUS.yaml"
    )
    open_certification = (
        config.status == "open" and config.certification == "ReadOnlyCertified"
    )
    stale_certification = config.is_stale_pending_recertification()
    must_align_status = (
        open_certification or stale_certification or require_status_alignment
    )
    if must_align_status:
        if not resolved_status.is_file():
            raise GateACertificationError(f"STATUS.yaml not found: {resolved_status}")
        status_text = resolved_status.read_text(encoding="utf-8")
        if open_certification and not _status_declares_gate_a_open(status_text):
            raise GateACertificationError("STATUS.yaml does not declare Gate A open")
        if stale_certification and not _status_declares_gate_a_stale(status_text):
            raise GateACertificationError(
                "STATUS.yaml does not declare Gate A stale pending recertification"
            )

    must_have_evidence = open_certification or require_evidence is not False
    evidence_candidate = (
        evidence_path or os.environ.get("RC_GATE_A_EVIDENCE") or config.evidence_path
    )
    if evidence_candidate:
        evidence_file = Path(evidence_candidate)
        if not evidence_file.is_absolute():
            evidence_file = repo_root / evidence_file
        if evidence_file.is_file():
            if config.status == "open" and config.evidence_sha256 is None:
                raise GateACertificationError("evidence_sha256 is required when Gate A open")
            if config.evidence_sha256 is not None:
                _validate_evidence_file_hash(
                    evidence_file=evidence_file,
                    expected_sha256=config.evidence_sha256,
                )
            evidence = _load_json(evidence_file)
            _validate_evidence_schema(evidence)
            if not config.matches_probe_evidence(evidence):
                raise GateACertificationError("evidence artifact tuple mismatch")
            if not stale_certification:
                evidence_at = _parse_iso_datetime(
                    str(evidence.get("evidence_recorded_at", ""))
                )
                _validate_evidence_freshness(
                    config=config,
                    evidence_at=evidence_at,
                    now=current,
                )
        elif must_have_evidence:
            raise GateACertificationError(f"evidence artifact missing: {evidence_file}")
    elif must_have_evidence:
        raise GateACertificationError("evidence artifact path is required")

    if config.status == "open":
        _validate_evidence_freshness(
            config=config,
            evidence_at=config.evidence_recorded_at,
            now=current,
        )

    return config


def try_load_gate_a_certification(**kwargs: Any) -> GateACertification | None:
    try:
        return load_gate_a_certification(**kwargs)
    except GateACertificationError:
        return None


__all__ = [
    "DEFAULT_OBSERVATION_TTL_SECONDS",
    "DEFAULT_OPENING_FRESHNESS_HOURS",
    "GateACertification",
    "GateACertificationError",
    "load_gate_a_certification",
    "try_load_gate_a_certification",
]
