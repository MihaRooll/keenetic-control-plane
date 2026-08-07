"""Read-only SSH CLI channel discovery — typed ops, auth replay guard, non-certifying evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from router_control.adapters.netcraze.certification import (
    GateACertification,
    GateACertificationError,
    load_gate_a_certification,
)
from router_control.adapters.netcraze.sanitize import sanitize_mapping
from router_control.adapters.netcraze.ssh_tunnel import (
    PinnedSshTransport,
    ShowInterfaceHomeExecResult,
    ShowInterfaceHomeShellResult,
    SshTunnelConfig,
    exec_show_interface_home,
    normalize_sha256_fingerprint,
    shell_show_interface_home,
    source_address_class,
    validate_source_address,
)
from router_control.adapters.netcraze.topology_probe import (
    digest_evidence_record,
    digest_gate_a_tuple,
)
from router_control.adapters.netcraze.tuple_evidence import tuple_evidence_fields_or_none
from router_control.ports.vault import CredentialVaultPort

CONTRACT_ID = "nc1812-ssh-cli-channel-discovery-20260723"
TYPED_OPERATION_EXEC = "ssh_exec_show_interface_home"
TYPED_OPERATION_SHELL = "ssh_shell_show_interface_home"
TYPED_OPERATIONS = (TYPED_OPERATION_EXEC, TYPED_OPERATION_SHELL)
AUTHORIZED_SOURCE_ADDRESS = "192.168.2.10"
GATE_A_EVIDENCE_SHA256 = "24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3"
_PROBE_WINDOW_MAX_SECONDS = 3600

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACTS_ROOT = REPO_ROOT / "data" / "artifacts"
DEFAULT_PROBES_DIR = DEFAULT_ARTIFACTS_ROOT / "ssh-cli-discovery-probes"

_AUTHORIZATION_ALLOWED_KEYS = frozenset(
    {
        "contract_id",
        "human_decision",
        "probe_id",
        "authorization_recorded_at",
        "typed_operations",
        "mutation_allowed",
        "source_address",
        "evidence_sha256",
        "opens_at",
        "expires_at",
        "gates",
        "gate_a_tuple_binding",
        "status_source_digest",
        "verification_receipt_sha256",
        "verification_receipt_path",
    }
)
_GATE_B_AUTH_KEYS = frozenset({"status", "not_write_certified"})
_GATE_CD_AUTH_KEYS = frozenset({"status"})
_ALLOWED_GATE_B_STATUS = frozenset({"closed", "completed_failed"})
_VERIFICATION_RECEIPTS_PREFIX = "data/artifacts/verification-receipts"
_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_SHA256_HEX_RE = re.compile(r"^[a-f0-9]{64}$")
_PROBE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_ARTIFACT_ALLOWED_KEYS = frozenset(
    {
        "artifact_type",
        "contract_id",
        "probe_id",
        "result",
        "recorded_at",
        "certification_eligible",
        "mutation_performed",
        "source_address",
        "source_address_class",
        "gate_a_tuple_digest",
        "gate_a_evidence_digest",
        "evidence_sha256",
        "ssh_host_key_algorithm",
        "ssh_host_key_fingerprint_sha256",
        "transport_security",
        "exec_candidate",
        "shell_candidate",
        "timing_bounds",
    }
)
_CANDIDATE_ALLOWED_KEYS = frozenset(
    {
        "typed_operation",
        "classification",
        "channel_opened",
        "exec_dispatched",
        "exit_status_observed",
        "exit_status",
        "stdout_byte_count",
        "stderr_byte_count",
        "stdout_sha256",
        "stderr_sha256",
        "response_body_byte_count",
        "response_body_sha256",
        "response_body_nonempty",
        "truncated",
        "timed_out",
        "channel_closed_verified",
        "error_code",
        "pty_allocated",
        "shell_invoked",
        "initial_prompt_observed",
        "command_sent",
        "prompt_return_observed",
        "echo_stripped",
        "prompt_ambiguous",
    }
)
_TIMING_ALLOWED_KEYS = frozenset(
    {
        "exec_timeout_seconds",
        "shell_stage_timeout_seconds",
        "connect_timeout_seconds",
    }
)


class SshCliDiscoveryError(Exception):
    """Authorization missing, malformed, expired, or misaligned."""


class SshCliDiscoveryReplayError(SshCliDiscoveryError):
    """probe_id was already consumed."""


class SshCliDiscoveryWindowClosed(SshCliDiscoveryError):
    """Discovery window is not open at the requested instant."""


class SshCliDiscoveryTupleDrift(SshCliDiscoveryError):
    """Live tuple does not match authorization binding."""


class RunnerPhase(StrEnum):
    GATE_A_LOADED = "gate_a_loaded"
    AUTHORIZATION_VALIDATED = "authorization_validated"
    PROBE_CONSUMED = "probe_consumed"
    EXEC_CANDIDATE = "exec_candidate"
    SHELL_CANDIDATE = "shell_candidate"
    TRANSPORT_CLOSED = "transport_closed"
    COMPLETE = "complete"


@dataclass(frozen=True, slots=True)
class SshCliTupleBinding:
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
        )


@dataclass(frozen=True, slots=True)
class SshCliDiscoveryAuthorization:
    contract_id: str
    probe_id: str
    human_decision: str
    authorization_recorded_at: datetime
    typed_operations: tuple[str, ...]
    mutation_allowed: bool
    source_address: str
    evidence_sha256: str
    opens_at: datetime
    expires_at: datetime
    gate_b_status: str
    gate_c_status: str
    gate_d_status: str
    tuple_binding: SshCliTupleBinding

    @property
    def window_seconds(self) -> int:
        return int((self.expires_at - self.opens_at).total_seconds())

    def window_is_open(self, now: datetime) -> bool:
        current = now.astimezone(UTC)
        return self.opens_at <= current < self.expires_at

    def validate_for_probe(
        self,
        *,
        now: datetime,
        source_address: str | None,
        host_key_pin: str | None = None,
        gate_a: GateACertification | None = None,
        probe_evidence: dict[str, Any] | None = None,
    ) -> None:
        if self.human_decision != "approve":
            raise SshCliDiscoveryError("human_decision must be approve")
        if self.mutation_allowed:
            raise SshCliDiscoveryError("mutation_allowed must be false")
        if self.typed_operations != TYPED_OPERATIONS:
            raise SshCliDiscoveryError("typed_operations must match fixed read-only discovery ops")
        if not self.window_is_open(now):
            raise SshCliDiscoveryWindowClosed("discovery window is closed or expired")
        if self.window_seconds > _PROBE_WINDOW_MAX_SECONDS:
            raise SshCliDiscoveryError("discovery window must be at most 3600 seconds")
        if self.gate_b_status not in _ALLOWED_GATE_B_STATUS:
            raise SshCliDiscoveryError("Gate B must be closed or completed_failed")
        if self.gate_c_status != "closed":
            raise SshCliDiscoveryError("Gate C must be closed")
        if self.gate_d_status != "closed":
            raise SshCliDiscoveryError("Gate D must be closed")
        bound_source = validate_source_address(self.source_address)
        if bound_source != AUTHORIZED_SOURCE_ADDRESS:
            raise SshCliDiscoveryError("authorization source_address must be 192.168.2.10")
        if source_address is not None:
            if validate_source_address(source_address) != bound_source:
                raise SshCliDiscoveryError("source_address mismatch")
        evidence_norm = _normalize_evidence_sha256(self.evidence_sha256)
        if evidence_norm != GATE_A_EVIDENCE_SHA256:
            raise SshCliDiscoveryError("evidence_sha256 must match Gate A SSOT")
        if gate_a is not None and host_key_pin:
            cli_pin = normalize_sha256_fingerprint(host_key_pin)
            gate_pin = normalize_sha256_fingerprint(gate_a.ssh_host_key_fingerprint_sha256)
            if cli_pin != gate_pin:
                raise SshCliDiscoveryError("host-key pin mismatches Gate A certification")
        if probe_evidence is not None and not self.tuple_binding.matches_probe_evidence(
            probe_evidence
        ):
            raise SshCliDiscoveryTupleDrift("authorization Gate A binding mismatch")


class TransportFactory(Protocol):
    def __call__(self, config: SshTunnelConfig) -> Any: ...


def _normalize_evidence_sha256(value: str) -> str:
    stripped = value.strip().lower()
    if stripped.startswith("sha256:"):
        return stripped.split(":", 1)[1]
    return stripped


def _normalize_sha256_digest(value: str, *, field: str) -> str:
    text = value.strip().lower()
    if _SHA256_PREFIX_RE.match(text):
        return text
    if _SHA256_HEX_RE.match(text):
        return f"sha256:{text}"
    raise SshCliDiscoveryError(f"{field} must be sha256:<64-hex> or 64-hex")


def _validate_verification_receipt_path(raw_path: str) -> Path:
    candidate = raw_path.strip()
    if not candidate:
        raise SshCliDiscoveryError("verification_receipt_path is required")
    if "\\" in candidate:
        raise SshCliDiscoveryError("verification_receipt_path must use forward slashes")
    if candidate.startswith("/"):
        raise SshCliDiscoveryError("verification_receipt_path must be relative")
    path_obj = Path(candidate)
    if path_obj.is_absolute():
        raise SshCliDiscoveryError("verification_receipt_path must be relative")
    if ".." in path_obj.parts:
        raise SshCliDiscoveryError("verification_receipt_path must not traverse")
    normalized = candidate.replace("\\", "/")
    prefix = f"{_VERIFICATION_RECEIPTS_PREFIX}/"
    if not normalized.startswith(prefix):
        raise SshCliDiscoveryError(
            "verification_receipt_path must be under data/artifacts/verification-receipts"
        )
    resolved = (REPO_ROOT / normalized).resolve()
    confinement_root = (REPO_ROOT / _VERIFICATION_RECEIPTS_PREFIX).resolve()
    try:
        resolved.relative_to(confinement_root)
    except ValueError as exc:
        raise SshCliDiscoveryError(
            "verification_receipt_path escapes verification-receipts directory"
        ) from exc
    return resolved


def _parse_status_yaml_gates_bcd(status_text: str) -> dict[str, str | bool | None]:
    lines = status_text.splitlines()
    in_gates = False
    gates_indent = -1
    current_gate: str | None = None
    gate_indent = -1
    seen_gates: set[str] = set()
    parsed: dict[str, str | bool | None] = {
        "B_status": None,
        "B_certification": None,
        "B_not_write_certified": None,
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

        matched_gate = False
        for letter in ("B", "C", "D"):
            if stripped.startswith(f"{letter}:") and indent == gates_indent + 2:
                if letter in seen_gates:
                    raise SshCliDiscoveryError(f"duplicate Gate {letter} in STATUS.yaml")
                seen_gates.add(letter)
                current_gate = letter
                gate_indent = indent
                matched_gate = True
                break
        if matched_gate:
            continue

        if current_gate and indent > gate_indent:
            if stripped.startswith("status:"):
                value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                parsed[f"{current_gate}_status"] = value
            elif stripped.startswith("certification:") and current_gate == "B":
                value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                parsed["B_certification"] = value
            elif stripped.startswith("not_write_certified:") and current_gate == "B":
                value = stripped.split(":", 1)[1].strip().strip('"').strip("'").lower()
                parsed["B_not_write_certified"] = value == "true"
        elif current_gate and indent <= gate_indent:
            current_gate = None

    return parsed


def _validate_status_gates_non_write(gate_state: dict[str, str | bool | None]) -> dict[str, str]:
    for letter in ("B", "C", "D"):
        if gate_state.get(f"{letter}_status") is None:
            raise SshCliDiscoveryError(f"STATUS.yaml missing Gate {letter}")

    b_status = str(gate_state.get("B_status") or "").lower()
    c_status = str(gate_state.get("C_status") or "").lower()
    d_status = str(gate_state.get("D_status") or "").lower()
    b_cert = str(gate_state.get("B_certification") or "")

    if b_status == "open":
        raise SshCliDiscoveryError("Gate B must not be open")
    if b_status == "certification_trial_authorized":
        raise SshCliDiscoveryError("Gate B must not be certification_trial_authorized")
    if b_cert.lower() == "writecertified":
        raise SshCliDiscoveryError("Gate B must not be WriteCertified")
    if b_status not in _ALLOWED_GATE_B_STATUS:
        raise SshCliDiscoveryError(
            f"Gate B status {b_status!r} is not allowed for read-only discovery"
        )
    if b_status == "completed_failed" and gate_state.get("B_not_write_certified") is not True:
        raise SshCliDiscoveryError("Gate B completed_failed requires not_write_certified true")
    if c_status != "closed":
        raise SshCliDiscoveryError("Gate C must be closed")
    if d_status != "closed":
        raise SshCliDiscoveryError("Gate D must be closed")

    return {"B": b_status, "C": c_status, "D": d_status}


def _validate_auth_gates_match_status(
    data: dict[str, Any],
    *,
    status_gates: dict[str, str],
) -> None:
    gates = data.get("gates") or {}
    if not isinstance(gates, dict):
        raise SshCliDiscoveryError("gates must be an object")
    for letter in ("B", "C", "D"):
        gate = gates.get(letter) or {}
        if not isinstance(gate, dict):
            raise SshCliDiscoveryError(f"gates.{letter} must be an object")
        auth_status = str(gate.get("status") or "").lower()
        if auth_status != status_gates[letter]:
            raise SshCliDiscoveryError(
                f"authorization gates.{letter}.status must match STATUS.yaml"
            )


def _validate_status_source_digest(data: dict[str, Any], *, status_bytes: bytes) -> None:
    raw = data.get("status_source_digest")
    if not isinstance(raw, str) or not raw.strip():
        raise SshCliDiscoveryError("status_source_digest is required")
    expected = f"sha256:{hashlib.sha256(status_bytes).hexdigest()}"
    if _normalize_sha256_digest(raw, field="status_source_digest") != expected:
        raise SshCliDiscoveryError("status_source_digest mismatch with STATUS.yaml bytes")


def _validate_verification_receipt(data: dict[str, Any]) -> None:
    receipt_sha_raw = data.get("verification_receipt_sha256")
    receipt_path_raw = data.get("verification_receipt_path")
    if not isinstance(receipt_sha_raw, str) or not receipt_sha_raw.strip():
        raise SshCliDiscoveryError("verification_receipt_sha256 is required")
    if not isinstance(receipt_path_raw, str) or not receipt_path_raw.strip():
        raise SshCliDiscoveryError("verification_receipt_path is required")
    receipt_digest = _normalize_sha256_digest(
        receipt_sha_raw,
        field="verification_receipt_sha256",
    )
    receipt_path = _validate_verification_receipt_path(receipt_path_raw)
    if not receipt_path.is_file():
        raise SshCliDiscoveryError(f"verification receipt not found: {receipt_path_raw.strip()}")
    receipt_bytes = receipt_path.read_bytes()
    if f"sha256:{hashlib.sha256(receipt_bytes).hexdigest()}" != receipt_digest:
        raise SshCliDiscoveryError("verification_receipt_sha256 mismatch with receipt file bytes")
    try:
        receipt_payload = json.loads(receipt_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise SshCliDiscoveryError("verification receipt must be JSON") from exc
    if not isinstance(receipt_payload, dict):
        raise SshCliDiscoveryError("verification receipt must be an object")
    for key in ("p1_complete", "p2_complete", "p3_complete"):
        if receipt_payload.get(key) is not True:
            raise SshCliDiscoveryError(f"verification receipt missing {key}=true")
    contract_id = str(receipt_payload.get("contract_id") or "").strip()
    auth_contract = str(data.get("contract_id") or "").strip()
    if not contract_id:
        raise SshCliDiscoveryError("verification receipt missing contract_id")
    if contract_id != auth_contract:
        raise SshCliDiscoveryError("verification receipt contract_id mismatch")


def _require_str(mapping: dict[str, Any], key: str) -> str:
    raw = mapping.get(key)
    if not isinstance(raw, str) or not raw.strip():
        raise SshCliDiscoveryError(f"{key} is required")
    return raw.strip()


def _reject_unknown_keys(mapping: dict[str, Any], *, allowed: frozenset[str], label: str) -> None:
    unknown = set(mapping.keys()) - allowed
    if unknown:
        raise SshCliDiscoveryError(f"unknown {label} keys: {', '.join(sorted(unknown))}")


def _parse_iso_datetime(value: str, *, field: str) -> datetime:
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise SshCliDiscoveryError(f"invalid {field} datetime") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _validate_probe_id(value: str) -> str:
    if not _PROBE_ID_RE.fullmatch(value):
        raise SshCliDiscoveryError("probe_id format invalid")
    return value


def _build_tuple_binding(data: dict[str, Any]) -> SshCliTupleBinding:
    binding = data.get("gate_a_tuple_binding") or {}
    if not isinstance(binding, dict):
        raise SshCliDiscoveryError("gate_a_tuple_binding must be an object")
    return SshCliTupleBinding(
        model=_require_str(binding, "model"),
        firmware_version=_require_str(binding, "firmware_version"),
        ndm_build=_require_str(binding, "ndm_build"),
        bsp_build=_require_str(binding, "bsp_build"),
        update_channel=_require_str(binding, "update_channel"),
        region=_require_str(binding, "region"),
        component_set_digest=_require_str(binding, "component_set_digest"),
        device_fingerprint_digest=_require_str(binding, "device_fingerprint_digest"),
        transport=_require_str(binding, "transport"),
        ssh_host_key_algorithm=_require_str(binding, "ssh_host_key_algorithm"),
    )


def _build_from_mapping(data: dict[str, Any]) -> SshCliDiscoveryAuthorization:
    _reject_unknown_keys(data, allowed=_AUTHORIZATION_ALLOWED_KEYS, label="authorization")

    contract_id = _require_str(data, "contract_id")
    if contract_id != CONTRACT_ID:
        raise SshCliDiscoveryError(f"contract_id must be {CONTRACT_ID}")

    probe_id = _validate_probe_id(_require_str(data, "probe_id"))
    human_decision = _require_str(data, "human_decision").lower()
    if human_decision != "approve":
        raise SshCliDiscoveryError("human_decision must be approve")

    typed_raw = data.get("typed_operations")
    if not isinstance(typed_raw, list) or [str(item) for item in typed_raw] != list(
        TYPED_OPERATIONS
    ):
        raise SshCliDiscoveryError("typed_operations must be fixed read-only discovery ops")

    mutation_allowed = data.get("mutation_allowed")
    if mutation_allowed is not False:
        raise SshCliDiscoveryError("mutation_allowed must be false")

    source_address = validate_source_address(_require_str(data, "source_address"))
    if source_address != AUTHORIZED_SOURCE_ADDRESS:
        raise SshCliDiscoveryError("source_address must be 192.168.2.10")

    evidence_sha256 = _normalize_evidence_sha256(_require_str(data, "evidence_sha256"))
    if evidence_sha256 != GATE_A_EVIDENCE_SHA256:
        raise SshCliDiscoveryError("evidence_sha256 must match Gate A SSOT")

    opens_at = _parse_iso_datetime(_require_str(data, "opens_at"), field="opens_at")
    expires_at = _parse_iso_datetime(_require_str(data, "expires_at"), field="expires_at")
    if expires_at <= opens_at:
        raise SshCliDiscoveryError("expires_at must be after opens_at")
    if int((expires_at - opens_at).total_seconds()) > _PROBE_WINDOW_MAX_SECONDS:
        raise SshCliDiscoveryError("discovery window must be at most 3600 seconds")

    _normalize_sha256_digest(
        _require_str(data, "status_source_digest"), field="status_source_digest"
    )
    _normalize_sha256_digest(
        _require_str(data, "verification_receipt_sha256"),
        field="verification_receipt_sha256",
    )
    _validate_verification_receipt_path(_require_str(data, "verification_receipt_path"))

    gates = data.get("gates") or {}
    if not isinstance(gates, dict):
        raise SshCliDiscoveryError("gates must be an object")
    _reject_unknown_keys(gates, allowed=frozenset({"B", "C", "D"}), label="gates")
    if not {"B", "C", "D"}.issubset(gates.keys()):
        raise SshCliDiscoveryError("gates must include B, C, and D")

    gate_b = gates.get("B") or {}
    gate_c = gates.get("C") or {}
    gate_d = gates.get("D") or {}
    if not isinstance(gate_b, dict) or not isinstance(gate_c, dict) or not isinstance(gate_d, dict):
        raise SshCliDiscoveryError("gates B/C/D must be objects")
    _reject_unknown_keys(gate_b, allowed=_GATE_B_AUTH_KEYS, label="gates.B")
    _reject_unknown_keys(gate_c, allowed=_GATE_CD_AUTH_KEYS, label="gates.C")
    _reject_unknown_keys(gate_d, allowed=_GATE_CD_AUTH_KEYS, label="gates.D")

    gate_b_status = _require_str(gate_b, "status").lower()
    if gate_b_status not in _ALLOWED_GATE_B_STATUS:
        raise SshCliDiscoveryError("Gate B status must be closed or completed_failed")
    if gate_b_status == "completed_failed" and gate_b.get("not_write_certified") is not True:
        raise SshCliDiscoveryError(
            "gates.B.not_write_certified must be true when status is completed_failed"
        )
    gate_c_status = _require_str(gate_c, "status").lower()
    gate_d_status = _require_str(gate_d, "status").lower()
    if gate_c_status != "closed":
        raise SshCliDiscoveryError("Gate C must be closed")
    if gate_d_status != "closed":
        raise SshCliDiscoveryError("Gate D must be closed")

    recorded_raw = data.get("authorization_recorded_at") or opens_at.isoformat()
    recorded_at = _parse_iso_datetime(str(recorded_raw), field="authorization_recorded_at")

    return SshCliDiscoveryAuthorization(
        contract_id=contract_id,
        probe_id=probe_id,
        human_decision=human_decision,
        authorization_recorded_at=recorded_at,
        typed_operations=tuple(TYPED_OPERATIONS),
        mutation_allowed=False,
        source_address=source_address,
        evidence_sha256=evidence_sha256,
        opens_at=opens_at,
        expires_at=expires_at,
        gate_b_status=gate_b_status,
        gate_c_status=gate_c_status,
        gate_d_status=gate_d_status,
        tuple_binding=_build_tuple_binding(data),
    )


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise SshCliDiscoveryError(f"authorization config not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SshCliDiscoveryError(f"malformed authorization JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise SshCliDiscoveryError("authorization config must be an object")
    return payload


def load_ssh_cli_discovery_authorization(
    *,
    config_path: Path | str,
    status_path: Path | str | None = None,
    require_status_alignment: bool = True,
    now: datetime | None = None,
) -> SshCliDiscoveryAuthorization:
    config_file = Path(config_path)
    raw_payload = _load_json(config_file)
    auth = _build_from_mapping(raw_payload)
    current = (now or datetime.now(UTC)).astimezone(UTC)

    resolved_status = Path(
        status_path or os.environ.get("RC_STATUS_PATH") or REPO_ROOT / "docs" / "STATUS.yaml"
    )
    if require_status_alignment:
        if not resolved_status.is_file():
            raise SshCliDiscoveryError(f"STATUS.yaml not found: {resolved_status}")
        status_bytes = resolved_status.read_bytes()
        status_text = status_bytes.decode("utf-8")
        gate_state = _parse_status_yaml_gates_bcd(status_text)
        status_gates = _validate_status_gates_non_write(gate_state)
        _validate_auth_gates_match_status(raw_payload, status_gates=status_gates)
        _validate_status_source_digest(raw_payload, status_bytes=status_bytes)
        _validate_verification_receipt(raw_payload)

    if not auth.window_is_open(current):
        raise SshCliDiscoveryWindowClosed("discovery window is closed or expired at load time")
    return auth


def probe_marker_path(probes_root: Path, probe_id: str) -> Path:
    safe_id = _validate_probe_id(probe_id)
    return probes_root / f"{safe_id}.consumed"


def consume_probe_id(
    *,
    authorization: SshCliDiscoveryAuthorization,
    probes_root: Path | None = None,
    now: datetime | None = None,
) -> Path:
    root = probes_root or DEFAULT_PROBES_DIR
    root.mkdir(parents=True, exist_ok=True)
    marker = probe_marker_path(root, authorization.probe_id)
    if marker.exists() and marker.stat().st_size == 0:
        raise SshCliDiscoveryReplayError(
            f"probe_id already consumed (empty marker): {authorization.probe_id}"
        )
    if marker.exists():
        raise SshCliDiscoveryReplayError(f"probe_id already consumed: {authorization.probe_id}")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    metadata = sanitize_mapping(
        {
            "artifact_type": "ssh_cli_discovery_probe_consumed",
            "contract_id": authorization.contract_id,
            "probe_id": authorization.probe_id,
            "typed_operations": list(authorization.typed_operations),
            "consumed_at": current.isoformat(),
            "evidence_sha256": authorization.evidence_sha256,
            "component_set_digest": authorization.tuple_binding.component_set_digest,
            "device_fingerprint_digest": authorization.tuple_binding.device_fingerprint_digest,
        }
    )
    payload = (json.dumps(metadata, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    try:
        fd = os.open(str(marker), flags, 0o600)
    except FileExistsError as exc:
        raise SshCliDiscoveryReplayError(
            f"probe_id already consumed: {authorization.probe_id}"
        ) from exc
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    return marker


def load_gate_a_for_ssh_cli_discovery(
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
        raise SshCliDiscoveryError(str(exc)) from exc


def _candidate_from_exec(result: ShowInterfaceHomeExecResult) -> dict[str, object]:
    payload = {
        "typed_operation": TYPED_OPERATION_EXEC,
        "classification": result.classification,
        "channel_opened": result.channel_opened,
        "exec_dispatched": result.exec_dispatched,
        "exit_status_observed": result.exit_status_observed,
        "exit_status": result.exit_status,
        "stdout_byte_count": result.stdout_byte_count,
        "stderr_byte_count": result.stderr_byte_count,
        "stdout_sha256": result.stdout_sha256,
        "stderr_sha256": result.stderr_sha256,
        "response_body_byte_count": result.response_body_byte_count,
        "response_body_sha256": result.response_body_sha256,
        "response_body_nonempty": result.response_body_nonempty,
        "truncated": result.truncated,
        "timed_out": result.timed_out,
        "channel_closed_verified": result.channel_closed_verified,
        "error_code": result.error_code,
    }
    _reject_unknown_keys(payload, allowed=_CANDIDATE_ALLOWED_KEYS, label="exec_candidate")
    return sanitize_mapping(payload)


def _candidate_from_shell(result: ShowInterfaceHomeShellResult) -> dict[str, object]:
    payload = {
        "typed_operation": TYPED_OPERATION_SHELL,
        "classification": result.classification,
        "channel_opened": result.shell_invoked or result.pty_allocated,
        "pty_allocated": result.pty_allocated,
        "shell_invoked": result.shell_invoked,
        "initial_prompt_observed": result.initial_prompt_observed,
        "command_sent": result.command_sent,
        "prompt_return_observed": result.prompt_return_observed,
        "response_body_byte_count": result.response_body_byte_count,
        "response_body_sha256": result.response_body_sha256,
        "response_body_nonempty": result.response_body_nonempty,
        "echo_stripped": result.echo_stripped,
        "truncated": result.truncated,
        "timed_out": result.timed_out,
        "prompt_ambiguous": result.prompt_ambiguous,
        "channel_closed_verified": result.channel_closed_verified,
        "error_code": result.error_code,
    }
    _reject_unknown_keys(payload, allowed=_CANDIDATE_ALLOWED_KEYS, label="shell_candidate")
    return sanitize_mapping(payload)


def build_ssh_cli_discovery_artifact(
    *,
    authorization: SshCliDiscoveryAuthorization | None,
    result: str,
    recorded_at: datetime,
    source_address: str,
    gate_a_tuple_digest: str,
    gate_a_evidence_digest: str,
    ssh_host_key_algorithm: str,
    ssh_host_key_fingerprint_sha256: str,
    exec_candidate: dict[str, object] | None = None,
    shell_candidate: dict[str, object] | None = None,
) -> dict[str, object]:
    validated_source = validate_source_address(source_address)
    timing_bounds = sanitize_mapping(
        {
            "exec_timeout_seconds": 20,
            "shell_stage_timeout_seconds": 15,
            "connect_timeout_seconds": 10,
        }
    )
    _reject_unknown_keys(timing_bounds, allowed=_TIMING_ALLOWED_KEYS, label="timing_bounds")

    artifact: dict[str, object] = {
        "artifact_type": "ssh_cli_discovery_evidence",
        "contract_id": CONTRACT_ID,
        "probe_id": authorization.probe_id if authorization else "offline-validate",
        "result": result,
        "recorded_at": recorded_at.astimezone(UTC).isoformat(),
        "certification_eligible": False,
        "mutation_performed": False,
        "source_address": validated_source,
        "source_address_class": source_address_class(validated_source),
        "gate_a_tuple_digest": gate_a_tuple_digest,
        "gate_a_evidence_digest": gate_a_evidence_digest,
        "evidence_sha256": GATE_A_EVIDENCE_SHA256,
        "ssh_host_key_algorithm": ssh_host_key_algorithm,
        "ssh_host_key_fingerprint_sha256": ssh_host_key_fingerprint_sha256,
        "transport_security": "ssh_tunnel",
        "timing_bounds": timing_bounds,
    }
    if exec_candidate is not None:
        artifact["exec_candidate"] = exec_candidate
    if shell_candidate is not None:
        artifact["shell_candidate"] = shell_candidate
    _reject_unknown_keys(artifact, allowed=_ARTIFACT_ALLOWED_KEYS, label="artifact")
    return sanitize_mapping(artifact)


@dataclass
class SshCliDiscoveryRunner:
    authorization: SshCliDiscoveryAuthorization | None = None
    gate_a: GateACertification | None = None
    host: str = ""
    username: str = ""
    credential_ref: str = ""
    host_key_pin: str = ""
    vault: CredentialVaultPort | None = None
    probe_evidence: dict[str, Any] | None = None
    validate_only: bool = True
    live_probe: bool = False
    probes_root: Path | None = None
    transport_factory: TransportFactory | None = None
    exec_runner: Callable[..., ShowInterfaceHomeExecResult] | None = None
    shell_runner: Callable[..., ShowInterfaceHomeShellResult] | None = None
    now: datetime | None = None
    source_address: str | None = None

    def _current_now(self) -> datetime:
        return (self.now or datetime.now(UTC)).astimezone(UTC)

    def _tuple_digest(self) -> str:
        if self.gate_a is None:
            return f"sha256:{hashlib.sha256(b'offline').hexdigest()}"
        return digest_gate_a_tuple(
            model=self.gate_a.model,
            firmware_version=self.gate_a.firmware_version,
            ndm_build=self.gate_a.ndm_build,
            component_set_digest=self.gate_a.component_set_digest,
            device_fingerprint_digest=self.gate_a.device_fingerprint_digest,
        )

    def _evidence_digest(self) -> str:
        if self.probe_evidence is None:
            return f"sha256:{hashlib.sha256(b'offline').hexdigest()}"
        return digest_evidence_record(self.probe_evidence)

    def _host_key_fields(self) -> tuple[str, str]:
        if self.gate_a is not None:
            return (
                self.gate_a.ssh_host_key_algorithm,
                normalize_sha256_fingerprint(self.gate_a.ssh_host_key_fingerprint_sha256),
            )
        if self.host_key_pin.strip():
            return ("ssh-ed25519", normalize_sha256_fingerprint(self.host_key_pin.strip()))
        return ("offline", "SHA256:offline")

    def run(self) -> dict[str, object]:
        current = self._current_now()
        source = validate_source_address(self.source_address or AUTHORIZED_SOURCE_ADDRESS)
        algorithm, fingerprint = self._host_key_fields()

        if self.validate_only and not self.live_probe:
            if self.authorization is not None:
                self.authorization.validate_for_probe(
                    now=current,
                    source_address=source,
                    host_key_pin=None,
                    gate_a=None,
                    probe_evidence=None,
                )
            return build_ssh_cli_discovery_artifact(
                authorization=self.authorization,
                result="validated",
                recorded_at=current,
                source_address=source,
                gate_a_tuple_digest=self._tuple_digest(),
                gate_a_evidence_digest=self._evidence_digest(),
                ssh_host_key_algorithm=algorithm,
                ssh_host_key_fingerprint_sha256=fingerprint,
            )

        if self.authorization is None:
            raise SshCliDiscoveryError("authorization is required for live probe")
        if self.gate_a is None or self.probe_evidence is None:
            raise SshCliDiscoveryError("Gate A alignment is required for live probe")
        if not self.host.strip() or not self.username.strip() or not self.credential_ref.strip():
            raise SshCliDiscoveryError(
                "host, username, and credential_ref are required for live probe"
            )
        if not self.host_key_pin.strip():
            raise SshCliDiscoveryError("host-key pin is required for live probe")
        if self.vault is None:
            raise SshCliDiscoveryError("credential vault is required for live probe")

        self.authorization.validate_for_probe(
            now=current,
            source_address=source,
            host_key_pin=self.host_key_pin,
            gate_a=self.gate_a,
            probe_evidence=self.probe_evidence,
        )
        consume_probe_id(
            authorization=self.authorization,
            probes_root=self.probes_root,
            now=current,
        )

        password = self.vault.use(self.credential_ref)
        exec_fn = self.exec_runner or exec_show_interface_home
        shell_fn = self.shell_runner or shell_show_interface_home

        exec_result: ShowInterfaceHomeExecResult
        shell_result: ShowInterfaceHomeShellResult
        exec_closed = False
        shell_closed = False

        exec_config = SshTunnelConfig(
            ssh_host=self.host.strip(),
            username=self.username.strip(),
            password=password,
            host_key_sha256=self.host_key_pin.strip(),
            source_address=source,
        )
        with PinnedSshTransport(
            exec_config, _transport_factory=self.transport_factory
        ) as exec_transport:
            exec_result = exec_fn(
                exec_transport.transport,
                password=password,
            )
            exec_closed = exec_transport.close()

        shell_config = SshTunnelConfig(
            ssh_host=self.host.strip(),
            username=self.username.strip(),
            password=password,
            host_key_sha256=self.host_key_pin.strip(),
            source_address=source,
        )
        with PinnedSshTransport(
            shell_config, _transport_factory=self.transport_factory
        ) as shell_transport:
            shell_result = shell_fn(
                shell_transport.transport,
                password=password,
            )
            shell_closed = shell_transport.close()

        if not exec_closed or not shell_closed:
            raise SshCliDiscoveryError("transport close verification failed")

        return build_ssh_cli_discovery_artifact(
            authorization=self.authorization,
            result="probed",
            recorded_at=current,
            source_address=source,
            gate_a_tuple_digest=self._tuple_digest(),
            gate_a_evidence_digest=self._evidence_digest(),
            ssh_host_key_algorithm=algorithm,
            ssh_host_key_fingerprint_sha256=fingerprint,
            exec_candidate=_candidate_from_exec(exec_result),
            shell_candidate=_candidate_from_shell(shell_result),
        )


__all__ = [
    "AUTHORIZED_SOURCE_ADDRESS",
    "CONTRACT_ID",
    "GATE_A_EVIDENCE_SHA256",
    "SshCliDiscoveryAuthorization",
    "SshCliDiscoveryError",
    "SshCliDiscoveryReplayError",
    "SshCliDiscoveryRunner",
    "SshCliDiscoveryTupleDrift",
    "SshCliDiscoveryWindowClosed",
    "TYPED_OPERATION_EXEC",
    "TYPED_OPERATION_SHELL",
    "TYPED_OPERATIONS",
    "build_ssh_cli_discovery_artifact",
    "consume_probe_id",
    "load_gate_a_for_ssh_cli_discovery",
    "load_ssh_cli_discovery_authorization",
    "probe_marker_path",
]
