"""Fail-safe timer discovery certification — authorization, replay guard, runner."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from router_control.adapters.netcraze.capability_families import CapabilityFamily
from router_control.adapters.netcraze.certification import (
    GateACertification,
    GateACertificationError,
    load_gate_a_certification,
)
from router_control.adapters.netcraze.fail_safe_hardware import (
    FAIL_SAFE_TIMER_SECONDS,
    FailSafeHardwareBoundary,
    FailSafeHardwareError,
    FailSafeTypedOperation,
)
from router_control.adapters.netcraze.live_probe import LiveProbeTarget, ReadOnlyProbeFn
from router_control.adapters.netcraze.sanitize import sanitize_mapping
from router_control.adapters.netcraze.ssh_tunnel import (
    SSH_PORT,
    FailSafeExecSession,
    PinnedSshTunnel,
    SshTunnelConfig,
    SshTunnelError,
    close_rci_transport_verified,
    normalize_sha256_fingerprint,
)
from router_control.adapters.netcraze.startup_backup import (
    StartupBackupError,
    StartupBackupMetadata,
    _backup_startup_config_with_fetcher,
    fetch_startup_config_bytes,
)
from router_control.adapters.netcraze.transport import (
    SshTunnelNetcrazeTransport,
    derive_management_host_header,
)
from router_control.adapters.netcraze.tuple_evidence import tuple_evidence_fields_or_none
from router_control.domain.ids import RouterId
from router_control.ports.vault import CredentialVaultPort

CONTRACT_FAMILY = CapabilityFamily.FAIL_SAFE.value
CONTRACT_ID = "fail-safe-discovery-nc1812-20260722"
TYPED_OPERATION = FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60.value
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_ARTIFACTS_ROOT = REPO_ROOT / "data" / "artifacts"
DEFAULT_TRIALS_DIR = DEFAULT_ARTIFACTS_ROOT / "fail-safe-trials"
_GATE_C_DURATION_SECONDS = 3600

_AUTHORIZATION_ALLOWED_KEYS = frozenset(
    {
        "contract_id",
        "human_decision",
        "trial_id",
        "authorization_recorded_at",
        "capability_family",
        "typed_operation",
        "timer_seconds",
        "expected_reboot",
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
_GATE_B_ALLOWED_KEYS = frozenset({"status", "certification", "capability_family"})
_GATE_C_ALLOWED_KEYS = frozenset({"status", "opens_at", "expires_at"})
_GATE_D_ALLOWED_KEYS = frozenset({"status"})

_SHA256_PREFIX_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_TRIAL_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

_DEFAULT_OUTAGE_TIMEOUT = 120.0
_DEFAULT_RECOVERY_TIMEOUT = 300.0
_DEFAULT_POLL_INTERVAL = 1.0


class FailSafeError(Exception):
    """Authorization missing, malformed, expired, or misaligned."""


class FailSafeReplayError(FailSafeError):
    """Trial id was already consumed."""


class FailSafeWindowClosed(FailSafeError):
    """Trial window is not open at the requested instant."""


class FailSafeTupleDrift(FailSafeError):
    """Live tuple does not match authorization binding."""


class FailSafeSessionCloseError(FailSafeError):
    """Runner could not verify all management sessions closed."""


class RunnerPhase(StrEnum):
    GATE_A_LOADED = "gate_a_loaded"
    AUTHORIZATION_VALIDATED = "authorization_validated"
    TRIAL_CONSUMED = "trial_consumed"
    PRE_COMMAND_PROBE = "pre_command_probe"
    STARTUP_BACKUP = "startup_backup"
    COMMAND_EXECUTED = "command_executed"
    SESSIONS_CLOSED = "sessions_closed"
    OUTAGE_OBSERVED = "outage_observed"
    RECOVERY_OBSERVED = "recovery_observed"
    REPROBE = "reprobe"
    COMPLETE = "complete"


_PHASE_TO_FAILURE_STAGE: dict[str, str] = {
    RunnerPhase.GATE_A_LOADED.value: "authorization",
    RunnerPhase.AUTHORIZATION_VALIDATED.value: "authorization",
    RunnerPhase.TRIAL_CONSUMED.value: "trial_consume",
    RunnerPhase.PRE_COMMAND_PROBE.value: "pre_command_probe",
    RunnerPhase.STARTUP_BACKUP.value: "startup_backup",
    RunnerPhase.COMMAND_EXECUTED.value: "sealed_cli_dispatch",
    RunnerPhase.SESSIONS_CLOSED.value: "sessions_closed",
    RunnerPhase.OUTAGE_OBSERVED.value: "outage_observe",
    RunnerPhase.RECOVERY_OBSERVED.value: "recovery_observe",
    RunnerPhase.REPROBE.value: "reprobe",
}


@dataclass(frozen=True, slots=True)
class FailSafeTupleBinding:
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
class FailSafeTrialAuthorization:
    contract_id: str
    trial_id: str
    human_decision: str
    authorization_recorded_at: datetime
    capability_family: str
    typed_operation: str
    timer_seconds: int
    expected_reboot: bool
    evidence_sha256: str
    opens_at: datetime
    expires_at: datetime
    gate_b_status: str
    gate_b_certification: str
    gate_c_status: str
    gate_c_opens_at: datetime
    gate_c_expires_at: datetime
    gate_d_status: str
    tuple_binding: FailSafeTupleBinding

    @property
    def gate_c_duration_seconds(self) -> int:
        return int((self.gate_c_expires_at - self.gate_c_opens_at).total_seconds())

    def gate_c_is_open(self, now: datetime) -> bool:
        if self.gate_c_status != "open":
            return False
        current = now.astimezone(UTC)
        return self.gate_c_opens_at <= current <= self.gate_c_expires_at

    def window_is_open(self, now: datetime) -> bool:
        current = now.astimezone(UTC)
        return self.opens_at <= current <= self.expires_at

    def matches_gate_a(self, gate_a: GateACertification) -> bool:
        if gate_a.evidence_sha256 is None:
            return False
        if gate_a.evidence_sha256.lower() != self.evidence_sha256.lower():
            return False
        binding = self.tuple_binding
        return (
            gate_a.model == binding.model
            and gate_a.firmware_version == binding.firmware_version
            and gate_a.ndm_build == binding.ndm_build
            and gate_a.bsp_build == binding.bsp_build
            and gate_a.update_channel == binding.update_channel
            and gate_a.region == binding.region
            and gate_a.component_set_digest == binding.component_set_digest
            and gate_a.device_fingerprint_digest == binding.device_fingerprint_digest
            and gate_a.transport == binding.transport
            and gate_a.ssh_host_key_algorithm == binding.ssh_host_key_algorithm
        )

    def validate_for_execute(
        self,
        *,
        gate_a: GateACertification,
        probe_evidence: dict[str, Any] | None,
        now: datetime,
    ) -> None:
        if not gate_a.is_open_at(now):
            raise FailSafeError("Gate A ReadOnlyCertified is not open")
        if self.human_decision != "approve":
            raise FailSafeError("human_decision must be approve")
        if self.capability_family != CONTRACT_FAMILY:
            raise FailSafeError("capability_family must be fail_safe")
        if self.typed_operation != TYPED_OPERATION:
            raise FailSafeError("typed_operation must be fail_safe_timer_reboot_60")
        if self.timer_seconds != FAIL_SAFE_TIMER_SECONDS:
            raise FailSafeError("timer_seconds must be 60")
        if not self.expected_reboot:
            raise FailSafeError("expected_reboot must be true")
        if self.gate_b_status != "certification_trial_authorized":
            raise FailSafeError("Gate B trial authorization is not active")
        if self.gate_b_certification != "CertificationTrialAuthorized":
            raise FailSafeError("Gate B is not CertificationTrialAuthorized")
        if self.gate_c_status != "open":
            raise FailSafeError("Gate C status must be open")
        if self.gate_c_duration_seconds != _GATE_C_DURATION_SECONDS:
            raise FailSafeError("Gate C window must be exactly 3600 seconds")
        if self.gate_c_opens_at != self.opens_at or self.gate_c_expires_at != self.expires_at:
            raise FailSafeError("Gate C window must match authorization opens_at/expires_at")
        if not self.gate_c_is_open(now):
            raise FailSafeWindowClosed("Gate C lab window is closed or expired")
        if self.gate_d_status != "closed":
            raise FailSafeError("Gate D must remain closed")
        if not self.window_is_open(now):
            raise FailSafeWindowClosed("fail-safe trial window is closed or expired")
        if not self.matches_gate_a(gate_a):
            raise FailSafeTupleDrift("authorization Gate A binding mismatch")
        if probe_evidence is None:
            raise FailSafeError("probe evidence is required")
        if not self.tuple_binding.matches_probe_evidence(probe_evidence):
            raise FailSafeTupleDrift("live tuple drift — require Gate A recertification")


class ConnectivityProbe(Protocol):
    def tcp_reachable(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
    ) -> bool: ...

    def wait_for_outage(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> bool: ...

    def wait_for_recovery(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> bool: ...


@dataclass
class TcpConnectivityProbe:
    """TCP reachability only — no SSH/RCI/tunnel during outage/recovery wait."""

    source_address: str | None = None
    allow_loopback_test_seam: bool = False

    def tcp_reachable(self, host: str, port: int, *, timeout: float) -> bool:
        from router_control.adapters.netcraze.ssh_tunnel import create_bound_tcp_connection

        try:
            if self.source_address is not None:
                sock = create_bound_tcp_connection(
                    host,
                    port,
                    timeout=timeout,
                    source_address=self.source_address,
                    allow_loopback_test_seam=self.allow_loopback_test_seam,
                )
                sock.close()
                return True
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            return False

    def wait_for_outage(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.tcp_reachable(host, port, timeout=min(poll_interval, 2.0)):
                return True
            time.sleep(poll_interval)
        return False

    def wait_for_recovery(
        self,
        host: str,
        port: int,
        *,
        timeout: float,
        poll_interval: float = _DEFAULT_POLL_INTERVAL,
    ) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.tcp_reachable(host, port, timeout=min(poll_interval, 2.0)):
                return True
            time.sleep(poll_interval)
        return False


@dataclass
class _RunnerSessions:
    exec_session: FailSafeExecSession | None = None
    rci_transport: SshTunnelNetcrazeTransport | None = None
    tunnel: PinnedSshTunnel | None = None

    def close_all_verified(self) -> bool:
        exec_closed = True
        if self.exec_session is not None:
            exec_closed = self.exec_session.close()
            self.exec_session = None

        rci_closed = True
        if self.rci_transport is not None:
            rci_closed = close_rci_transport_verified(self.rci_transport)
            self.rci_transport = None

        forward_closed = True
        transport_closed = True
        tunnel_closed = True
        if self.tunnel is not None:
            tunnel = self.tunnel
            had_forward = tunnel._forward_server is not None
            had_transport = tunnel._transport is not None
            tunnel.close()
            forward_closed = (not had_forward) or tunnel._forward_server is None
            transport_closed = (not had_transport) or tunnel._transport is None
            tunnel_closed = bool(getattr(tunnel, "_closed", False))
            self.tunnel = None

        return (
            exec_closed
            and rci_closed
            and forward_closed
            and transport_closed
            and tunnel_closed
        )


def _runner_startup_backup(
    *,
    tunnel: PinnedSshTunnel,
    certification: GateACertification,
    rci_transport: SshTunnelNetcrazeTransport,
    recorded_at: datetime | None = None,
) -> StartupBackupMetadata:
    """Startup backup via runner-owned RCI transport (shared with pre-command probe)."""

    def _fetcher(_unused_transport: SshTunnelNetcrazeTransport) -> bytes:
        return fetch_startup_config_bytes(rci_transport)

    return _backup_startup_config_with_fetcher(
        tunnel=tunnel,
        certification=certification,
        fetcher=_fetcher,
        recorded_at=recorded_at,
    )


def _normalize_runner_failure(exc: Exception) -> FailSafeError:
    if isinstance(exc, FailSafeError):
        return exc
    if isinstance(exc, (FailSafeHardwareError, SshTunnelError, StartupBackupError)):
        return FailSafeError(str(exc))
    return FailSafeError(str(exc))


def _parse_iso_datetime(value: str, *, field: str) -> datetime:
    text = value.strip()
    if not text:
        raise FailSafeError(f"missing {field}")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _require_str(data: dict[str, Any], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value.strip():
        raise FailSafeError(f"missing or invalid {key}")
    return value.strip()


def _require_digest(value: str, *, field: str) -> str:
    if not _SHA256_PREFIX_RE.match(value.strip().lower()):
        raise FailSafeError(f"{field} must be sha256:<64-hex>")
    return value.strip()


def _require_evidence_sha256(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FailSafeError("evidence_sha256 is required")
    digest = value.strip().lower()
    if len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest):
        return digest
    if digest.startswith("sha256:"):
        digest = digest.split(":", 1)[1]
    if len(digest) != 64 or not all(ch in "0123456789abcdef" for ch in digest):
        raise FailSafeError("evidence_sha256 must be a 64-character hex digest")
    return digest


def _validate_trial_id(trial_id: str) -> str:
    candidate = trial_id.strip()
    if not _TRIAL_ID_RE.fullmatch(candidate):
        raise FailSafeError("trial_id must be a safe unique token")
    return candidate


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FailSafeError(f"authorization config not found: {path}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise FailSafeError(f"malformed authorization JSON: {path}") from exc
    if not isinstance(payload, dict):
        raise FailSafeError("authorization config must be an object")
    return payload


def _build_tuple_binding(data: dict[str, Any]) -> FailSafeTupleBinding:
    binding = data.get("gate_a_tuple_binding") or data.get("tuple_binding") or data
    if not isinstance(binding, dict):
        raise FailSafeError("gate_a_tuple_binding must be an object")
    return FailSafeTupleBinding(
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


def _reject_unknown_keys(data: dict[str, Any], *, allowed: frozenset[str], label: str) -> None:
    unknown = sorted(set(data.keys()) - allowed)
    if unknown:
        raise FailSafeError(f"{label} has unknown fields: {unknown}")


def _parse_status_yaml_gates(status_text: str) -> dict[str, str | None]:
    lines = status_text.splitlines()
    in_gates = False
    gates_indent = -1
    current_gate: str | None = None
    gate_indent = -1
    parsed: dict[str, str | None] = {
        "B_status": None,
        "B_certification": None,
        "B_capability_family": None,
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
                elif stripped.startswith("capability_family:"):
                    value = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    if current_gate == "B":
                        parsed["B_capability_family"] = value
            elif current_gate and indent <= gate_indent:
                current_gate = None

    return parsed


def _status_declares_trial_alignment(status_text: str, auth: FailSafeTrialAuthorization) -> bool:
    gate_state = _parse_status_yaml_gates(status_text)
    status_family = str(gate_state.get("B_capability_family") or "").lower()
    if not status_family or status_family != auth.capability_family:
        return False
    return (
        str(gate_state.get("B_status") or "").lower() == auth.gate_b_status
        and gate_state.get("B_certification") == auth.gate_b_certification
        and str(gate_state.get("C_status") or "").lower() == auth.gate_c_status
        and str(gate_state.get("D_status") or "").lower() == auth.gate_d_status
    )


def _build_from_mapping(data: dict[str, Any]) -> FailSafeTrialAuthorization:
    _reject_unknown_keys(data, allowed=_AUTHORIZATION_ALLOWED_KEYS, label="authorization")

    contract_id = _require_str(data, "contract_id")
    if contract_id != CONTRACT_ID:
        raise FailSafeError(f"contract_id must be {CONTRACT_ID}")
    trial_id = _validate_trial_id(_require_str(data, "trial_id"))
    human_decision = _require_str(data, "human_decision").lower()
    if human_decision != "approve":
        raise FailSafeError("human_decision must be approve")

    capability_family = _require_str(data, "capability_family").lower()
    if capability_family != CONTRACT_FAMILY:
        raise FailSafeError("capability_family must be fail_safe")

    typed_operation = _require_str(data, "typed_operation")
    if typed_operation != TYPED_OPERATION:
        raise FailSafeError("typed_operation must be fail_safe_timer_reboot_60")

    timer_seconds_raw = data.get("timer_seconds")
    if not isinstance(timer_seconds_raw, int) or timer_seconds_raw != FAIL_SAFE_TIMER_SECONDS:
        raise FailSafeError("timer_seconds must be 60")

    expected_reboot = data.get("expected_reboot")
    if expected_reboot is not True:
        raise FailSafeError("expected_reboot must be true")

    evidence_sha256 = _require_evidence_sha256(data.get("evidence_sha256"))

    opens_at = _parse_iso_datetime(_require_str(data, "opens_at"), field="opens_at")
    expires_at = _parse_iso_datetime(_require_str(data, "expires_at"), field="expires_at")
    if expires_at <= opens_at:
        raise FailSafeError("expires_at must be after opens_at")

    gates = data.get("gates") or {}
    if not isinstance(gates, dict):
        raise FailSafeError("gates must be an object")
    _reject_unknown_keys(gates, allowed=frozenset({"B", "C", "D"}), label="gates")
    if not {"B", "C", "D"}.issubset(gates.keys()):
        raise FailSafeError("gates must include B, C, and D")

    gate_b = gates.get("B") or {}
    gate_c = gates.get("C") or {}
    gate_d = gates.get("D") or {}
    if not isinstance(gate_b, dict) or not isinstance(gate_c, dict) or not isinstance(gate_d, dict):
        raise FailSafeError("gates B/C/D must be objects")
    _reject_unknown_keys(gate_b, allowed=_GATE_B_ALLOWED_KEYS, label="gates.B")
    _reject_unknown_keys(gate_c, allowed=_GATE_C_ALLOWED_KEYS, label="gates.C")
    _reject_unknown_keys(gate_d, allowed=_GATE_D_ALLOWED_KEYS, label="gates.D")

    gate_b_status = _require_str(gate_b, "status").lower()
    if gate_b_status != "certification_trial_authorized":
        raise FailSafeError("Gate B status must be certification_trial_authorized")
    gate_b_cert = str(gate_b.get("certification") or "")
    if gate_b_cert == "WriteCertified":
        raise FailSafeError("WriteCertified is forbidden in trial authorization")
    if gate_b_cert != "CertificationTrialAuthorized":
        raise FailSafeError("Gate B certification must be CertificationTrialAuthorized")
    gate_b_family = _require_str(gate_b, "capability_family").lower()
    if gate_b_family != CONTRACT_FAMILY:
        raise FailSafeError("Gate B capability_family must be fail_safe")

    gate_c_status = _require_str(gate_c, "status").lower()
    if gate_c_status != "open":
        raise FailSafeError("Gate C status must be open for trial window")
    gate_c_opens_at = _parse_iso_datetime(_require_str(gate_c, "opens_at"), field="opens_at")
    gate_c_expires_at = _parse_iso_datetime(_require_str(gate_c, "expires_at"), field="expires_at")
    if gate_c_opens_at != opens_at or gate_c_expires_at != expires_at:
        raise FailSafeError("Gate C window must match authorization opens_at/expires_at")
    gate_c_duration = int((gate_c_expires_at - gate_c_opens_at).total_seconds())
    if gate_c_duration != _GATE_C_DURATION_SECONDS:
        raise FailSafeError("Gate C window must be exactly 3600 seconds")

    gate_d_status = _require_str(gate_d, "status").lower()
    if gate_d_status != "closed":
        raise FailSafeError("Gate D must be closed")

    recorded_at_raw = data.get("authorization_recorded_at") or opens_at.isoformat()
    recorded_at = _parse_iso_datetime(str(recorded_at_raw), field="authorization_recorded_at")

    return FailSafeTrialAuthorization(
        contract_id=contract_id,
        trial_id=trial_id,
        human_decision=human_decision,
        authorization_recorded_at=recorded_at,
        capability_family=CONTRACT_FAMILY,
        typed_operation=TYPED_OPERATION,
        timer_seconds=FAIL_SAFE_TIMER_SECONDS,
        expected_reboot=True,
        evidence_sha256=evidence_sha256,
        opens_at=opens_at,
        expires_at=expires_at,
        gate_b_status="certification_trial_authorized",
        gate_b_certification="CertificationTrialAuthorized",
        gate_c_status="open",
        gate_c_opens_at=gate_c_opens_at,
        gate_c_expires_at=gate_c_expires_at,
        gate_d_status="closed",
        tuple_binding=_build_tuple_binding(data),
    )


def load_fail_safe_authorization(
    *,
    config_path: Path | str,
    status_path: Path | str | None = None,
    require_status_alignment: bool = True,
    now: datetime | None = None,
) -> FailSafeTrialAuthorization:
    auth = _build_from_mapping(_load_json(Path(config_path)))
    current = (now or datetime.now(UTC)).astimezone(UTC)

    resolved_status = Path(
        status_path or os.environ.get("RC_STATUS_PATH") or REPO_ROOT / "docs" / "STATUS.yaml"
    )
    if require_status_alignment:
        if not resolved_status.is_file():
            raise FailSafeError(f"STATUS.yaml not found: {resolved_status}")
        status_text = resolved_status.read_text(encoding="utf-8")
        if not _status_declares_trial_alignment(status_text, auth):
            raise FailSafeError("STATUS.yaml does not declare Gate B/C trial authorization")

    if not auth.window_is_open(current):
        raise FailSafeWindowClosed("fail-safe trial window is closed or expired at load time")
    if not auth.gate_c_is_open(current):
        raise FailSafeWindowClosed("Gate C lab window is closed or expired at load time")
    return auth


def trial_marker_path(trials_root: Path, trial_id: str) -> Path:
    safe_id = _validate_trial_id(trial_id)
    return trials_root / f"{safe_id}.consumed"


def consume_trial_id(
    *,
    authorization: FailSafeTrialAuthorization,
    trials_root: Path | None = None,
    now: datetime | None = None,
) -> Path:
    root = trials_root or DEFAULT_TRIALS_DIR
    root.mkdir(parents=True, exist_ok=True)
    marker = trial_marker_path(root, authorization.trial_id)
    if marker.exists():
        raise FailSafeReplayError(f"trial_id already consumed: {authorization.trial_id}")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    metadata = sanitize_mapping(
        {
            "artifact_type": "fail_safe_trial_consumed",
            "contract_id": authorization.contract_id,
            "trial_id": authorization.trial_id,
            "typed_operation": authorization.typed_operation,
            "timer_seconds": authorization.timer_seconds,
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
        raise FailSafeReplayError(
            f"trial_id already consumed: {authorization.trial_id}"
        ) from exc
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)
    return marker


def load_gate_a_for_fail_safe(
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
        raise FailSafeError(str(exc)) from exc


@dataclass
class FailSafeDiscoveryRunner:
    authorization: FailSafeTrialAuthorization
    gate_a: GateACertification
    host: str
    username: str
    credential_ref: str
    host_key_pin: str
    vault: CredentialVaultPort
    probe_evidence: dict[str, Any]
    source_address: str | None = None
    hardware: FailSafeHardwareBoundary = field(default_factory=FailSafeHardwareBoundary)
    connectivity_probe: ConnectivityProbe = field(default_factory=TcpConnectivityProbe)
    trials_root: Path = field(default_factory=lambda: DEFAULT_TRIALS_DIR)
    dry_run: bool = True
    validate_only: bool = False
    now: datetime | None = None
    outage_timeout: float = _DEFAULT_OUTAGE_TIMEOUT
    recovery_timeout: float = _DEFAULT_RECOVERY_TIMEOUT
    probe_fn_factory: Callable[..., ReadOnlyProbeFn] | None = None
    pre_command_probe_fn: Callable[[SshTunnelNetcrazeTransport], dict[str, Any]] | None = None
    backup_fn: Callable[..., StartupBackupMetadata] | None = None
    _transitions: list[dict[str, str]] = field(default_factory=list)

    def _source_bind_evidence(self) -> dict[str, str]:
        if self.source_address is None:
            return {}
        from router_control.adapters.netcraze.ssh_tunnel import (
            source_address_class,
            validate_source_address,
        )

        validated = validate_source_address(self.source_address)
        return {
            "source_address": validated,
            "source_address_class": source_address_class(validated),
        }

    def _validated_source_address(self) -> str | None:
        if self.source_address is None:
            return None
        from router_control.adapters.netcraze.ssh_tunnel import validate_source_address

        return validate_source_address(self.source_address)

    def _assert_host_key_pin_matches_gate_a(self, *, required: bool = False) -> None:
        pin_text = self.host_key_pin.strip()
        if not pin_text:
            if required:
                raise FailSafeError("host-key pin is required for execute")
            return
        try:
            pin = normalize_sha256_fingerprint(pin_text)
            certified = normalize_sha256_fingerprint(self.gate_a.ssh_host_key_fingerprint_sha256)
        except SshTunnelError as exc:
            raise FailSafeError(str(exc)) from exc
        if pin != certified:
            raise FailSafeError("host-key pin mismatches Gate A certification fingerprint")

    def _current_now(self) -> datetime:
        return (self.now or datetime.now(UTC)).astimezone(UTC)

    def _record(self, phase: RunnerPhase, status: str) -> None:
        self._transitions.append(
            {
                "phase": phase.value,
                "status": status,
                "recorded_at": self._current_now().isoformat(),
            }
        )

    def _infer_pre_dispatch_failure(self) -> tuple[str, bool]:
        non_complete = [
            transition
            for transition in self._transitions
            if transition.get("phase") != RunnerPhase.COMPLETE.value
        ]
        if not non_complete:
            return "authorization", False
        last_phase = str(non_complete[-1].get("phase", ""))
        failure_stage = _PHASE_TO_FAILURE_STAGE.get(last_phase, "authorization")
        dispatch_attempted = failure_stage == "sealed_cli_dispatch"
        return failure_stage, dispatch_attempted

    def validate_offline(self) -> dict[str, Any]:
        current = self._current_now()
        self._record(RunnerPhase.GATE_A_LOADED, "validated")
        try:
            self._assert_host_key_pin_matches_gate_a(required=False)
            self.authorization.validate_for_execute(
                gate_a=self.gate_a,
                probe_evidence=self.probe_evidence,
                now=current,
            )
        except FailSafeError as exc:
            return self._failed_evidence(exc, window_closed=True)
        self._record(RunnerPhase.AUTHORIZATION_VALIDATED, "validated")
        return self._success_evidence(
            result="validated",
            sessions_closed_verified=False,
            outage_observed=False,
            recovery_observed=False,
            reprobe_match=False,
            ack_matched=False,
        )

    def run(self) -> dict[str, Any]:
        current = self._current_now()
        if self.dry_run or self.validate_only:
            return self.validate_offline()

        self._record(RunnerPhase.GATE_A_LOADED, "started")
        try:
            self._assert_host_key_pin_matches_gate_a(required=True)
            self.authorization.validate_for_execute(
                gate_a=self.gate_a,
                probe_evidence=self.probe_evidence,
                now=current,
            )
        except FailSafeError as exc:
            return self._failed_evidence(exc, window_closed=True)

        self._record(RunnerPhase.AUTHORIZATION_VALIDATED, "passed")
        try:
            consume_trial_id(
                authorization=self.authorization,
                trials_root=self.trials_root,
                now=current,
            )
        except FailSafeError as exc:
            return self._failed_evidence(exc, window_closed=True)
        self._record(RunnerPhase.TRIAL_CONSUMED, "passed")

        sessions = _RunnerSessions()
        backup_meta: StartupBackupMetadata | None = None
        ack_matched = False
        exec_result_sanitized: dict[str, object] = {}
        gate_c_window_open_at_execute: bool | None = None

        try:
            validated_source = self._validated_source_address()
            if validated_source is not None:
                if not isinstance(self.connectivity_probe, TcpConnectivityProbe):
                    raise FailSafeError(
                        "source_address requires TcpConnectivityProbe "
                        "for bound outage/recovery polls"
                    )
                self.connectivity_probe.source_address = validated_source
                from router_control.adapters.netcraze.ssh_tunnel import (
                    preflight_source_address_bind,
                )

                preflight_source_address_bind(validated_source)
            password = self.vault.use(self.credential_ref)
            tunnel_config = SshTunnelConfig(
                ssh_host=self.host,
                username=self.username,
                password=password,
                host_key_sha256=self.host_key_pin,
                source_address=validated_source,
            )
            tunnel = PinnedSshTunnel(tunnel_config)
            tunnel.open()
            sessions.tunnel = tunnel

            management_header = derive_management_host_header(self.host)
            rci_transport = SshTunnelNetcrazeTransport(
                host=tunnel.local_host,
                port=tunnel.local_port,
                use_tls=False,
                username=self.username,
                password=password,
                management_host_header=management_header,
                ssh_host_key_algorithm=tunnel.host_key_algorithm,
                ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
                source_address=validated_source or "",
            )
            sessions.rci_transport = rci_transport

            live_probe_evidence = self._live_pre_command_probe(rci_transport=rci_transport)
            if not self.authorization.tuple_binding.matches_probe_evidence(live_probe_evidence):
                raise FailSafeTupleDrift("pre-command live probe evidence mismatch")
            self._record(RunnerPhase.PRE_COMMAND_PROBE, "passed")

            backup_callable = self.backup_fn or _runner_startup_backup
            backup_meta = backup_callable(
                tunnel=tunnel,
                certification=self.gate_a,
                rci_transport=rci_transport,
                recorded_at=current,
            )
            self._record(RunnerPhase.STARTUP_BACKUP, "passed")

            final_now = self._current_now()
            gate_c_window_open_at_execute = self.authorization.gate_c_is_open(final_now)
            try:
                self.authorization.validate_for_execute(
                    gate_a=self.gate_a,
                    probe_evidence=live_probe_evidence,
                    now=final_now,
                )
            except FailSafeError as exc:
                raise FailSafeWindowClosed(str(exc)) from exc

            ssh_transport = tunnel._transport
            if ssh_transport is None:
                raise FailSafeSessionCloseError("pinned SSH transport missing")
            result, exec_session = self.hardware.execute(
                FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
                transport=ssh_transport,
                password=password,
                gate_a=self.gate_a,
                now=final_now,
                gate_b_trial_authorized=True,
                gate_c_open=self.authorization.gate_c_is_open(final_now),
                gate_d_closed=self.authorization.gate_d_status == "closed",
                probe_tuple_match=self.authorization.tuple_binding.matches_probe_evidence(
                    live_probe_evidence
                ),
                trial_authorized=True,
            )
            sessions.exec_session = exec_session
            ack_matched = result.ack_matched
            exec_result_sanitized = result.sanitized_dict()
            if result.exit_status != 0:
                raise FailSafeError("fail-safe command exited with non-zero status")
            if not ack_matched:
                raise FailSafeError("fail-safe command acknowledgement did not match")
            self._record(RunnerPhase.COMMAND_EXECUTED, "passed")

            if not sessions.close_all_verified():
                raise FailSafeSessionCloseError("sessions not verified closed")
            self._record(RunnerPhase.SESSIONS_CLOSED, "passed")

            tcp_host = tunnel.tcp_connect_host
            if not self.connectivity_probe.wait_for_outage(
                tcp_host,
                SSH_PORT,
                timeout=self.outage_timeout,
            ):
                raise FailSafeError("expected TCP outage not observed")
            self._record(RunnerPhase.OUTAGE_OBSERVED, "passed")

            if not self.connectivity_probe.wait_for_recovery(
                tcp_host,
                SSH_PORT,
                timeout=self.recovery_timeout,
            ):
                raise FailSafeError("TCP recovery timed out")
            self._record(RunnerPhase.RECOVERY_OBSERVED, "passed")

            reprobe_evidence = self._reprobe_gate_a(password=password)
            reprobe_match = self.authorization.tuple_binding.matches_probe_evidence(
                reprobe_evidence
            )
            if not reprobe_match:
                raise FailSafeTupleDrift("post-reboot Gate A reprobe tuple mismatch")
            self._record(RunnerPhase.REPROBE, "passed")

            return self._success_evidence(
                result="passed",
                sessions_closed_verified=True,
                outage_observed=True,
                recovery_observed=True,
                reprobe_match=True,
                ack_matched=ack_matched,
                backup_meta=backup_meta,
                exec_result=exec_result_sanitized,
            )
        except Exception as exc:
            hw_error_code: str | None = None
            hw_failure_stage: str | None = None
            hw_dispatch_attempted: bool | None = None
            hw_sealed_meta: dict[str, object] | None = None
            if isinstance(exc, FailSafeHardwareError):
                hw_error_code = exc.error_code
                hw_failure_stage = exc.failure_stage
                hw_dispatch_attempted = exc.dispatch_attempted
                hw_sealed_meta = exc.sealed_meta
                if hw_sealed_meta is not None and not exec_result_sanitized:
                    exec_result_sanitized = dict(hw_sealed_meta)
                if hw_sealed_meta is not None:
                    ack_matched = bool(hw_sealed_meta.get("ack_matched"))
            normalized = _normalize_runner_failure(exc)
            return self._failed_evidence(
                normalized,
                window_closed=True,
                backup_meta=backup_meta,
                ack_matched=ack_matched,
                exec_result=exec_result_sanitized or None,
                gate_c_window_open_at_execute=gate_c_window_open_at_execute,
                hw_error_code=hw_error_code,
                hw_failure_stage=hw_failure_stage,
                hw_dispatch_attempted=hw_dispatch_attempted,
            )
        finally:
            sessions.close_all_verified()

    def _live_pre_command_probe(
        self,
        *,
        rci_transport: SshTunnelNetcrazeTransport,
    ) -> dict[str, Any]:
        if self.pre_command_probe_fn is not None:
            return self.pre_command_probe_fn(rci_transport)

        from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
        from router_control.adapters.netcraze.identity import OperatorIdentityHints
        from router_control.ports.clock import SystemClock

        adapter = NetcrazeReadOnlyAdapter(
            router_id=RouterId("fail-safe-discovery"),
            transport=rci_transport,
            clock=SystemClock(),
            identity_hints=OperatorIdentityHints(
                expected_model=self.gate_a.model,
                update_channel=self.gate_a.update_channel,
            ),
        )
        return dict(adapter.probe_gate_a_evidence())

    def _reprobe_gate_a(self, *, password: str) -> dict[str, Any]:
        if self.probe_fn_factory is not None:
            probe_fn = self.probe_fn_factory(
                certification=self.gate_a,
                vault=self.vault,
            )
        else:
            from router_control.adapters.netcraze.live_probe import build_pinned_ssh_probe_fn
            from router_control.ports.clock import SystemClock

            probe_fn = build_pinned_ssh_probe_fn(
                self.gate_a,
                vault=self.vault,
                clock=SystemClock(),
            )
        target = LiveProbeTarget(
            ssh_host=self.host,
            username=self.username,
            credential_ref_id=self.credential_ref,
            router_id=RouterId("fail-safe-discovery"),
            source_address=self.source_address,
        )
        evidence = probe_fn(target)
        return dict(evidence)

    def _success_evidence(
        self,
        *,
        result: str,
        sessions_closed_verified: bool,
        outage_observed: bool,
        recovery_observed: bool,
        reprobe_match: bool,
        ack_matched: bool,
        backup_meta: StartupBackupMetadata | None = None,
        exec_result: dict[str, object] | None = None,
    ) -> dict[str, Any]:
        self._record(RunnerPhase.COMPLETE, result)
        payload: dict[str, Any] = {
            "artifact_type": "fail_safe_discovery_evidence",
            "contract_id": self.authorization.contract_id,
            "trial_id": self.authorization.trial_id,
            "capability_family": CONTRACT_FAMILY,
            "typed_operation": TYPED_OPERATION,
            "timer_seconds": FAIL_SAFE_TIMER_SECONDS,
            "expected_reboot": True,
            "result": result,
            "write_certified": False,
            "not_write_certified": True,
            "window_closed": False,
            "gate_c_window_open_at_execute": self.authorization.gate_c_is_open(self._current_now()),
            "sessions_closed_verified": sessions_closed_verified,
            "outage_observed": outage_observed,
            "recovery_observed": recovery_observed,
            "reprobe_tuple_match": reprobe_match,
            "ack_matched": ack_matched,
            "component_set_digest": self.gate_a.component_set_digest,
            "device_fingerprint_digest": self.gate_a.device_fingerprint_digest,
            "evidence_sha256": self.authorization.evidence_sha256,
            "status_transitions": list(self._transitions),
        }
        payload.update(self._source_bind_evidence())
        if backup_meta is not None:
            payload["startup_backup_content_sha256"] = backup_meta.content_sha256
            payload["startup_backup_recorded_at"] = backup_meta.recorded_at
        if exec_result:
            payload["command_result"] = exec_result
        return sanitize_mapping(payload)

    def _failed_evidence(
        self,
        exc: Exception,
        *,
        window_closed: bool,
        backup_meta: StartupBackupMetadata | None = None,
        ack_matched: bool = False,
        exec_result: dict[str, object] | None = None,
        gate_c_window_open_at_execute: bool | None = None,
        hw_error_code: str | None = None,
        hw_failure_stage: str | None = None,
        hw_dispatch_attempted: bool | None = None,
    ) -> dict[str, Any]:
        self._record(RunnerPhase.COMPLETE, "failed")
        inferred_stage, inferred_dispatch = self._infer_pre_dispatch_failure()
        failure_stage = hw_failure_stage or inferred_stage
        dispatch_attempted = (
            hw_dispatch_attempted
            if hw_dispatch_attempted is not None
            else inferred_dispatch
        )
        error_code = hw_error_code or "fail_safe_hardware_error"
        gate_c_open = (
            gate_c_window_open_at_execute
            if gate_c_window_open_at_execute is not None
            else self.authorization.gate_c_is_open(self._current_now())
        )
        payload: dict[str, Any] = {
            "artifact_type": "fail_safe_discovery_evidence",
            "contract_id": self.authorization.contract_id,
            "trial_id": self.authorization.trial_id,
            "capability_family": CONTRACT_FAMILY,
            "typed_operation": TYPED_OPERATION,
            "timer_seconds": FAIL_SAFE_TIMER_SECONDS,
            "expected_reboot": True,
            "result": "failed",
            "write_certified": False,
            "not_write_certified": True,
            "window_closed": window_closed,
            "gate_c_window_open_at_execute": gate_c_open,
            "sessions_closed_verified": False,
            "outage_observed": False,
            "recovery_observed": False,
            "reprobe_tuple_match": False,
            "ack_matched": ack_matched,
            "error_type": exc.__class__.__name__,
            "error_code": error_code,
            "failure_stage": failure_stage,
            "dispatch_attempted": dispatch_attempted,
            "component_set_digest": self.gate_a.component_set_digest,
            "device_fingerprint_digest": self.gate_a.device_fingerprint_digest,
            "evidence_sha256": self.authorization.evidence_sha256,
            "status_transitions": list(self._transitions),
        }
        payload.update(self._source_bind_evidence())
        if backup_meta is not None:
            payload["startup_backup_content_sha256"] = backup_meta.content_sha256
        if exec_result:
            payload["command_result"] = exec_result
        return sanitize_mapping(payload)


def evidence_file_sha256(path: Path) -> str:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest


__all__ = [
    "CONTRACT_FAMILY",
    "CONTRACT_ID",
    "DEFAULT_TRIALS_DIR",
    "FailSafeDiscoveryRunner",
    "FailSafeError",
    "FailSafeReplayError",
    "FailSafeSessionCloseError",
    "FailSafeTrialAuthorization",
    "FailSafeTupleBinding",
    "FailSafeTupleDrift",
    "FailSafeWindowClosed",
    "ConnectivityProbe",
    "TcpConnectivityProbe",
    "consume_trial_id",
    "load_fail_safe_authorization",
    "load_gate_a_for_fail_safe",
    "trial_marker_path",
    "TYPED_OPERATION",
]
