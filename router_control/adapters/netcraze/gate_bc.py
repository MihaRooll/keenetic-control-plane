"""Gate B/C AWG trial authorization loader — fail-closed write boundary."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from router_control.adapters.netcraze.capability_families import normalize_family_for_gate_bc
from router_control.adapters.netcraze.certification import (
    GateACertification,
    GateACertificationError,
    load_gate_a_certification,
)
from router_control.adapters.netcraze.tuple_evidence import tuple_evidence_fields_or_none

GateBStatus = Literal["certification_trial_authorized"]
GateCStatus = Literal["open", "closed"]
GateDStatus = Literal["closed"]
CapabilityFamily = Literal["AmneziaWG"]
TrialCertification = Literal["CertificationTrialAuthorized"]

_GATE_C_DURATION_SECONDS = 3600
_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")


class GateBCError(Exception):
    """Authorization missing, malformed, expired, or misaligned."""


class GateCExpired(GateBCError):
    """Gate C lab window is not open at the requested instant."""


class TupleDrift(GateBCError):
    """Live tuple does not match authorization binding — writes closed."""


@dataclass(frozen=True, slots=True)
class GateBCTupleBinding:
    model: str
    firmware_version: str
    ndm_build: str
    bsp_build: str
    update_channel: str
    region: str
    component_set_digest: str
    device_fingerprint_digest: str
    transport: str
    ssh_host_key_algorithm: str


@dataclass(frozen=True, slots=True)
class GateBCAuthorization:
    contract_id: str
    human_decision: str
    authorization_recorded_at: datetime
    gate_b_status: GateBStatus
    gate_b_certification: TrialCertification
    capability_family: CapabilityFamily
    approved_scope: str
    gate_c_status: GateCStatus
    gate_c_opens_at: datetime
    gate_c_expires_at: datetime
    gate_d_status: GateDStatus
    tuple_binding: GateBCTupleBinding
    candidate_order: tuple[str, ...]
    write_shapes_registered: bool

    @property
    def gate_c_duration_seconds(self) -> int:
        delta = int((self.gate_c_expires_at - self.gate_c_opens_at).total_seconds())
        return delta

    def gate_c_is_open(self, now: datetime) -> bool:
        if self.gate_c_status != "open":
            return False
        current = now.astimezone(UTC)
        return self.gate_c_opens_at <= current <= self.gate_c_expires_at

    def matches_probe_evidence(self, evidence: dict[str, Any]) -> bool:
        binding = self.tuple_binding
        fields = tuple_evidence_fields_or_none(evidence)
        if fields is None:
            return False
        return (
            str(evidence.get("model", "")) == binding.model
            and str(evidence.get("firmware_version", "")) == binding.firmware_version
            and fields.ndm_build == binding.ndm_build
            and str(evidence.get("bsp_build", "")) == binding.bsp_build
            and str(evidence.get("update_channel", "")) == binding.update_channel
            and str(evidence.get("region", "")) == binding.region
            and str(evidence.get("component_set_digest", "")) == binding.component_set_digest
            and fields.device_fingerprint_digest == binding.device_fingerprint_digest
            and fields.transport == binding.transport
            and str(evidence.get("ssh_host_key_algorithm", "")) == binding.ssh_host_key_algorithm
        )

    def writes_permitted(
        self,
        *,
        gate_a: GateACertification,
        capability_family: str,
        probe_evidence: dict[str, Any] | None,
        now: datetime | None = None,
    ) -> None:
        """Raise on any failed predicate; return None when writes may proceed."""
        current = (now or datetime.now(UTC)).astimezone(UTC)

        if not gate_a.is_open_at(current):
            raise GateBCError("Gate A ReadOnlyCertified is not open")
        if self.gate_b_status != "certification_trial_authorized":
            raise GateBCError("Gate B trial authorization is not active")
        if self.gate_b_certification != "CertificationTrialAuthorized":
            raise GateBCError("Gate B is not CertificationTrialAuthorized")
        try:
            requested = normalize_family_for_gate_bc(capability_family)
            authorized = normalize_family_for_gate_bc(self.capability_family)
        except ValueError as exc:
            raise GateBCError("capability family mismatch") from exc
        if requested != authorized:
            raise GateBCError("capability family mismatch")
        if self.gate_d_status != "closed":
            raise GateBCError("Gate D must remain closed")
        if not self.gate_c_is_open(current):
            raise GateCExpired("Gate C lab window is closed or expired")
        if self.gate_c_duration_seconds != _GATE_C_DURATION_SECONDS:
            raise GateBCError("Gate C window duration must be exactly 3600 seconds")

        if probe_evidence is None:
            raise GateBCError("probe evidence is required for write authorization")
        if not self.matches_probe_evidence(probe_evidence):
            raise TupleDrift("live tuple drift — require Gate A recertification")


def _parse_iso_datetime(value: str, *, field: str) -> datetime:
    text = value.strip()
    if not text:
        raise GateBCError(f"missing {field}")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise GateBCError(f"missing or invalid {key}")
    return value.strip()


def _require_digest(value: str, *, field: str) -> str:
    if not _SHA256_PREFIX_RE.match(value.strip().lower()):
        raise GateBCError(f"{field} must be sha256:<64-hex>")
    return value.strip()


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise GateBCError(f"authorization config not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise GateBCError(f"malformed authorization JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise GateBCError("authorization config must be an object")
    return payload


def _build_tuple_binding(data: dict[str, Any]) -> GateBCTupleBinding:
    binding = data.get("gate_a_tuple_binding") or data.get("tuple_binding") or data
    if not isinstance(binding, dict):
        raise GateBCError("gate_a_tuple_binding must be an object")
    return GateBCTupleBinding(
        model=_require_str(binding, "model"),
        firmware_version=_require_str(binding, "firmware_version"),
        ndm_build=_require_str(binding, "ndm_build"),
        bsp_build=_require_str(binding, "bsp_build"),
        update_channel=_require_str(binding, "update_channel"),
        region=_require_str(binding, "region"),
        component_set_digest=_require_digest(
            _require_str(binding, "component_set_digest"),
            field="component_set_digest",
        ),
        device_fingerprint_digest=_require_digest(
            _require_str(binding, "device_fingerprint_digest"),
            field="device_fingerprint_digest",
        ),
        transport=_require_str(binding, "transport"),
        ssh_host_key_algorithm=_require_str(binding, "ssh_host_key_algorithm"),
    )


def _build_from_mapping(data: dict[str, Any]) -> GateBCAuthorization:
    contract_id = _require_str(data, "contract_id")
    human_decision = _require_str(data, "human_decision").lower()
    if human_decision != "approve":
        raise GateBCError("human_decision must be approve")

    gates = data.get("gates") or {}
    if not isinstance(gates, dict):
        raise GateBCError("gates must be an object")

    gate_b = gates.get("B") or {}
    gate_c = gates.get("C") or {}
    gate_d = gates.get("D") or {}
    if not isinstance(gate_b, dict) or not isinstance(gate_c, dict) or not isinstance(gate_d, dict):
        raise GateBCError("gates B/C/D must be objects")

    gate_b_status = _require_str(gate_b, "status").lower()
    if gate_b_status != "certification_trial_authorized":
        raise GateBCError("Gate B status must be certification_trial_authorized")

    gate_b_cert = str(gate_b.get("certification") or "CertificationTrialAuthorized")
    if gate_b_cert == "WriteCertified":
        raise GateBCError("WriteCertified is forbidden in trial authorization")
    if gate_b_cert != "CertificationTrialAuthorized":
        raise GateBCError("Gate B certification must be CertificationTrialAuthorized")

    capability_family = _require_str(gate_b, "capability_family")
    if capability_family != "AmneziaWG":
        raise GateBCError("Gate B capability_family must be AmneziaWG")

    gate_c_status = _require_str(gate_c, "status").lower()
    if gate_c_status != "open":
        raise GateBCError("Gate C status must be open for trial window")

    opens_at = _parse_iso_datetime(_require_str(gate_c, "opens_at"), field="opens_at")
    expires_at = _parse_iso_datetime(_require_str(gate_c, "expires_at"), field="expires_at")
    duration = int((expires_at - opens_at).total_seconds())
    if duration != _GATE_C_DURATION_SECONDS:
        raise GateBCError("Gate C window must be exactly 3600 seconds")

    gate_d_status = _require_str(gate_d, "status").lower()
    if gate_d_status != "closed":
        raise GateBCError("Gate D must be closed")

    candidate_raw = data.get("candidate_order") or []
    if not isinstance(candidate_raw, list) or not candidate_raw:
        raise GateBCError("candidate_order must be a non-empty list")
    candidate_order = tuple(str(item) for item in candidate_raw)
    expected = ("keenetic50-compat", "fi-ip", "de-ip")
    if candidate_order != expected:
        raise GateBCError(f"candidate_order must be {list(expected)}")

    write_shapes_registered = bool(data.get("write_shapes_registered"))
    if write_shapes_registered and not data.get("registered_shape_ops"):
        raise GateBCError("write_shapes_registered requires registered_shape_ops evidence")

    recorded_at_raw = data.get("authorization_recorded_at") or opens_at.isoformat()
    recorded_at = _parse_iso_datetime(str(recorded_at_raw), field="authorization_recorded_at")

    return GateBCAuthorization(
        contract_id=contract_id,
        human_decision=human_decision,
        authorization_recorded_at=recorded_at,
        gate_b_status="certification_trial_authorized",
        gate_b_certification="CertificationTrialAuthorized",
        capability_family="AmneziaWG",
        approved_scope=_require_str(gate_b, "approved_scope"),
        gate_c_status="open",
        gate_c_opens_at=opens_at,
        gate_c_expires_at=expires_at,
        gate_d_status="closed",
        tuple_binding=_build_tuple_binding(data),
        candidate_order=candidate_order,
        write_shapes_registered=write_shapes_registered,
    )


def _parse_status_yaml_gate_bc(status_text: str) -> dict[str, str | None]:
    lines = status_text.splitlines()
    in_gates = False
    gates_indent = -1
    current_gate: str | None = None
    gate_indent = -1
    parsed: dict[str, str | None] = {
        "B_status": None,
        "B_certification": None,
        "C_status": None,
        "D_status": None,
    }

    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)

        if stripped == "gates:" or stripped.startswith("gates:"):
            in_gates = True
            gates_indent = indent
            current_gate = None
            continue
        if not in_gates:
            continue
        if indent <= gates_indent and current_gate is None:
            in_gates = False
            continue

        for letter in ("B", "C", "D"):
            if stripped.startswith(f"{letter}:") and indent == gates_indent + 2:
                current_gate = letter
                gate_indent = indent
                break
        else:
            if current_gate and indent > gate_indent:
                if stripped.startswith("status:"):
                    value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    parsed[f"{current_gate}_status"] = value
                elif stripped.startswith("certification:"):
                    value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    if current_gate == "B":
                        parsed["B_certification"] = value
            elif current_gate and indent <= gate_indent:
                current_gate = None

    return parsed


def _status_declares_trial_alignment(status_text: str, auth: GateBCAuthorization) -> bool:
    gate_bc = _parse_status_yaml_gate_bc(status_text)
    return (
        str(gate_bc.get("B_status") or "").lower() == auth.gate_b_status
        and gate_bc.get("B_certification") == auth.gate_b_certification
        and str(gate_bc.get("C_status") or "").lower() == auth.gate_c_status
        and str(gate_bc.get("D_status") or "").lower() == auth.gate_d_status
    )


def load_gate_bc_authorization(
    *,
    config_path: Path | str | None = None,
    status_path: Path | str | None = None,
    require_status_alignment: bool = True,
    now: datetime | None = None,
) -> GateBCAuthorization:
    repo_root = Path(__file__).resolve().parents[3]
    resolved_config = Path(
        config_path
        or os.environ.get("RC_GATE_BC_AWG_CONFIG")
        or repo_root / "docs" / "gate-b-c-awg-authorization.json"
    )
    auth = _build_from_mapping(_load_json(resolved_config))

    resolved_status = Path(
        status_path or os.environ.get("RC_STATUS_PATH") or repo_root / "docs" / "STATUS.yaml"
    )
    if require_status_alignment:
        if not resolved_status.is_file():
            raise GateBCError(f"STATUS.yaml not found: {resolved_status}")
        status_text = resolved_status.read_text(encoding="utf-8")
        if not _status_declares_trial_alignment(status_text, auth):
            raise GateBCError("STATUS.yaml does not declare Gate B/C trial authorization")

    current = (now or datetime.now(UTC)).astimezone(UTC)
    if not auth.gate_c_is_open(current):
        raise GateCExpired("Gate C lab window is closed or expired at load time")

    return auth


def try_load_gate_bc_authorization(**kwargs: Any) -> GateBCAuthorization | None:
    try:
        return load_gate_bc_authorization(**kwargs)
    except GateBCError:
        return None


def load_gate_a_for_bc_writes(
    *,
    gate_a_config_path: Path | str | None = None,
    gate_a_evidence_path: Path | str | None = None,
    status_path: Path | str | None = None,
    now: datetime | None = None,
) -> GateACertification:
    try:
        return load_gate_a_certification(
            config_path=gate_a_config_path,
            evidence_path=gate_a_evidence_path,
            status_path=status_path,
            now=now,
        )
    except GateACertificationError as exc:
        raise GateBCError(str(exc)) from exc


def _normalize_sha256_digest(value: str, *, field: str) -> str:
    text = value.strip().lower()
    if _SHA256_PREFIX_RE.match(text):
        return text
    if _SHA256_HEX_RE.match(text):
        return f"sha256:{text}"
    raise GateBCError(f"{field} must be sha256:<64-hex> or 64-hex")


def _parse_yaml_scalar_block(text: str, block_key: str) -> dict[str, str | bool]:
    lines = text.splitlines()
    in_block = False
    block_indent = -1
    parsed: dict[str, str | bool] = {}
    for line in lines:
        if not line.strip() or line.strip().startswith("#"):
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if stripped.startswith(f"{block_key}:"):
            in_block = True
            block_indent = indent
            continue
        if not in_block:
            continue
        if indent <= block_indent:
            in_block = False
            continue
        if ":" not in stripped:
            continue
        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        value_text = raw_value.strip().strip('"').strip("'")
        if value_text.lower() in {"true", "false"}:
            parsed[key] = value_text.lower() == "true"
        else:
            parsed[key] = value_text
    return parsed


def _status_lineage_complete(status_text: str) -> bool:
    lineage = _parse_yaml_scalar_block(status_text, "lineage")
    if lineage:
        for key in ("p1_complete", "p2_complete", "p3_complete"):
            if lineage.get(key) is not True:
                return False
        return True
    reviews = _parse_yaml_scalar_block(status_text, "reviews")
    rebaseline = str(reviews.get("real_router_execution_rebaseline") or "")
    p1a = str(reviews.get("p1a_live_persistence_foundation") or "").strip()
    p1b_marker = any(
        str(reviews.get(key) or "").strip()
        for key in reviews
        if key.startswith("p1b_")
    )
    if not p1a:
        return False
    if not p1b_marker and "P1-B complete" not in rebaseline:
        return False
    if "P2 immutable deployment complete" not in rebaseline:
        return False
    return True


def _status_phase_p3_complete(status_text: str) -> bool:
    phase = _parse_yaml_scalar_block(status_text, "current_phase")
    phase_id = str(phase.get("id") or "")
    complete = phase.get("complete")
    if phase_id != "p3-shared-netcraze-executor" or complete is not True:
        return False
    return _status_lineage_complete(status_text)


def require_live_execute_prerequisite(
    *,
    status_path: Path | str,
    authorization: Mapping[str, Any],
) -> None:
    """Bind --execute to digest-faithful STATUS + verification receipt (not touch-marker)."""
    resolved_status = Path(status_path)
    if not resolved_status.is_file():
        raise GateBCError(f"STATUS.yaml not found: {resolved_status}")
    status_bytes = resolved_status.read_bytes()
    status_text = status_bytes.decode("utf-8")
    status_digest = f"sha256:{hashlib.sha256(status_bytes).hexdigest()}"
    if not _status_phase_p3_complete(status_text):
        raise GateBCError("STATUS.yaml does not declare P1/P2/P3 complete lineage")
    auth_status_digest = authorization.get("status_source_digest")
    if not isinstance(auth_status_digest, str) or not auth_status_digest.strip():
        raise GateBCError("authorization missing status_source_digest")
    if _normalize_sha256_digest(auth_status_digest, field="status_source_digest") != status_digest:
        raise GateBCError("status_source_digest mismatch with STATUS.yaml bytes")
    receipt_sha_raw = authorization.get("verification_receipt_sha256")
    receipt_path_raw = authorization.get("verification_receipt_path")
    if not isinstance(receipt_sha_raw, str) or not receipt_sha_raw.strip():
        raise GateBCError("authorization missing verification_receipt_sha256")
    if not isinstance(receipt_path_raw, str) or not receipt_path_raw.strip():
        raise GateBCError("authorization missing verification_receipt_path")
    receipt_digest = _normalize_sha256_digest(
        receipt_sha_raw,
        field="verification_receipt_sha256",
    )
    repo_root = Path(__file__).resolve().parents[3]
    receipt_path = Path(receipt_path_raw.strip())
    if not receipt_path.is_absolute():
        receipt_path = resolved_status.parent / receipt_path
        if not receipt_path.is_file():
            receipt_path = repo_root / receipt_path_raw.strip()
    if not receipt_path.is_file():
        raise GateBCError(f"verification receipt not found: {receipt_path_raw}")
    receipt_bytes = receipt_path.read_bytes()
    if f"sha256:{hashlib.sha256(receipt_bytes).hexdigest()}" != receipt_digest:
        raise GateBCError("verification_receipt_sha256 mismatch with receipt file bytes")
    try:
        receipt_payload = json.loads(receipt_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise GateBCError("verification receipt must be JSON") from exc
    if not isinstance(receipt_payload, dict):
        raise GateBCError("verification receipt must be an object")
    for key in ("p1_complete", "p2_complete", "p3_complete"):
        if receipt_payload.get(key) is not True:
            raise GateBCError(f"verification receipt missing {key}=true")
    contract_id = str(receipt_payload.get("contract_id") or "").strip()
    if not contract_id:
        raise GateBCError("verification receipt missing contract_id")
    auth_contract = str(authorization.get("contract_id") or "").strip()
    if not auth_contract:
        raise GateBCError("authorization missing contract_id")
    if contract_id != auth_contract:
        raise GateBCError("verification receipt contract_id mismatch")


__all__ = [
    "GateBCAuthorization",
    "GateBCError",
    "GateBCTupleBinding",
    "GateCExpired",
    "TupleDrift",
    "load_gate_a_for_bc_writes",
    "load_gate_bc_authorization",
    "require_live_execute_prerequisite",
    "try_load_gate_bc_authorization",
]
