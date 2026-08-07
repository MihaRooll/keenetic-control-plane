"""Fail-safe certification runner tests (mocked; no live network)."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze import fail_safe_certification as fsc_mod
from router_control.adapters.netcraze import fail_safe_hardware as fsh_mod
from router_control.adapters.netcraze import ssh_tunnel as ssh_tunnel_mod
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.errors import SshTunnelError
from router_control.adapters.netcraze.fail_safe_certification import (
    CONTRACT_ID,
    FailSafeDiscoveryRunner,
    FailSafeError,
    FailSafeReplayError,
    FailSafeSessionCloseError,
    FailSafeTupleDrift,
    FailSafeWindowClosed,
    TcpConnectivityProbe,
    consume_trial_id,
    load_fail_safe_authorization,
    trial_marker_path,
)
from router_control.adapters.netcraze.fail_safe_hardware import (
    FailSafeExecutionResult,
    FailSafeHardwareBoundary,
    FailSafeHardwareError,
    FailSafeTypedOperation,
)
from router_control.adapters.netcraze.ssh_tunnel import FailSafeExecAck, FailSafeExecSession
from router_control.adapters.netcraze.startup_backup import StartupBackupMetadata
from router_control.adapters.secrets.memory import MemoryVault

COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
EVIDENCE_SHA256 = "c1682b110a2e0555fd3cd71f392677a88e674e382b46106c8b0e632a655e11c0"
WINDOW_OPEN = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)
WINDOW_CLOSE = WINDOW_OPEN + timedelta(hours=1)
NOW = WINDOW_OPEN + timedelta(minutes=10)

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
FORBIDDEN_SENTINELS = (SYNTH_PASSWORD, "system configuration fail-safe timer reboot 60")

_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


def _memory_vault(ref: str = "lab-ref") -> MemoryVault:
    vault = MemoryVault()
    vault._secrets[ref] = SYNTH_PASSWORD
    return vault

PROBE_EVIDENCE = {
    "model": "NC-1812",
    "firmware_version": "5.01.C.1.0-0",
    "build": "0-b592e619a0",
    "bsp_build": "0-f371d30955",
    "update_channel": "Main",
    "region": "EA",
    "component_set_digest": COMPONENT_DIGEST,
    "device_fingerprint": FINGERPRINT_DIGEST,
    "transport_security": "ssh_tunnel",
    "ssh_host_key_algorithm": "ssh-ed25519",
}


def _gate_payload() -> dict[str, object]:
    return {
        "B": {
            "status": "certification_trial_authorized",
            "certification": "CertificationTrialAuthorized",
            "capability_family": "fail_safe",
        },
        "C": {
            "status": "open",
            "opens_at": WINDOW_OPEN.isoformat(),
            "expires_at": WINDOW_CLOSE.isoformat(),
        },
        "D": {"status": "closed"},
    }


def _auth_payload(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "contract_id": "fail-safe-discovery-nc1812-20260722",
        "human_decision": "approve",
        "trial_id": "trial-001",
        "authorization_recorded_at": WINDOW_OPEN.isoformat(),
        "capability_family": "fail_safe",
        "typed_operation": "fail_safe_timer_reboot_60",
        "timer_seconds": 60,
        "expected_reboot": True,
        "evidence_sha256": EVIDENCE_SHA256,
        "opens_at": WINDOW_OPEN.isoformat(),
        "expires_at": WINDOW_CLOSE.isoformat(),
        "gates": _gate_payload(),
        "gate_a_tuple_binding": {
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
        },
    }
    base.update(overrides)
    return base


def _gate_a(**overrides: object) -> GateACertification:
    now = datetime.now(UTC)
    base = {
        "status": "open",
        "certification": "ReadOnlyCertified",
        "approved_scope": "SLICE-4-readonly",
        "model": "NC-1812",
        "model_display": "Ultra (NC-1812)",
        "firmware_version": "5.01.C.1.0-0",
        "firmware_display": "5.1.1",
        "ndm_build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "physical_id_source": "show.identification_digest",
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": _VALID_SSH_HOST_KEY_SHA256,
        "certification_eligible": True,
        "evidence_recorded_at": now,
        "evidence_path": "data/artifacts/gate-a-probe.json",
        "expires_at": now + timedelta(days=90),
        "revocation_policy": "human",
        "evidence_sha256": EVIDENCE_SHA256,
        "gates_b_closed": True,
        "gates_c_closed": True,
        "gates_d_closed": True,
    }
    base.update(overrides)
    return GateACertification(**base)  # type: ignore[arg-type]


@pytest.fixture
def auth_path(tmp_path: Path) -> Path:
    path = tmp_path / "auth.json"
    path.write_text(json.dumps(_auth_payload()), encoding="utf-8")
    return path


def test_load_authorization_binds_timer_and_family(auth_path: Path) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path,
        require_status_alignment=False,
        now=NOW,
    )
    assert auth.contract_id == CONTRACT_ID
    assert auth.capability_family == "fail_safe"
    assert auth.typed_operation == "fail_safe_timer_reboot_60"
    assert auth.timer_seconds == 60
    assert auth.expected_reboot is True
    assert auth.gate_b_certification == "CertificationTrialAuthorized"
    assert auth.gate_c_status == "open"
    assert auth.gate_d_status == "closed"


def test_rejects_expired_window(auth_path: Path) -> None:
    with pytest.raises(FailSafeWindowClosed):
        load_fail_safe_authorization(
            config_path=auth_path,
            require_status_alignment=False,
            now=WINDOW_CLOSE + timedelta(seconds=1),
        )


def test_rejects_wrong_contract_id(auth_path: Path) -> None:
    payload = _auth_payload(contract_id="other-contract")
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FailSafeError, match="contract_id must be"):
        load_fail_safe_authorization(
            config_path=auth_path,
            require_status_alignment=False,
            now=NOW,
        )


def test_rejects_tuple_mismatch(auth_path: Path) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    gate_a = _gate_a(model="OTHER")
    with pytest.raises(FailSafeTupleDrift):
        auth.validate_for_execute(gate_a=gate_a, probe_evidence=PROBE_EVIDENCE, now=NOW)


def test_rejects_evidence_sha256_mismatch(auth_path: Path) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    gate_a = _gate_a(evidence_sha256="a" * 64)
    with pytest.raises(FailSafeTupleDrift):
        auth.validate_for_execute(gate_a=gate_a, probe_evidence=PROBE_EVIDENCE, now=NOW)


def test_consume_trial_marker_is_atomic(tmp_path: Path, auth_path: Path) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    trials_root = tmp_path / "trials"
    marker = consume_trial_id(authorization=auth, trials_root=trials_root, now=NOW)
    assert marker.is_file()
    payload = json.loads(marker.read_text(encoding="utf-8"))
    assert payload["trial_id"] == "trial-001"
    with pytest.raises(FailSafeReplayError):
        consume_trial_id(authorization=auth, trials_root=trials_root, now=NOW)


def test_dry_run_does_not_consume_marker(tmp_path: Path, auth_path: Path) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        dry_run=True,
        validate_only=True,
        trials_root=tmp_path / "trials",
        now=NOW,
    )
    evidence = runner.run()
    assert evidence["result"] == "validated"
    assert not any((tmp_path / "trials").glob("*.consumed"))


def _backup_meta() -> StartupBackupMetadata:
    return StartupBackupMetadata(
        artifact_type="startup_backup",
        endpoint="/ci/startup-config.txt",
        content_sha256="sha256:" + "c" * 64,
        size_bytes=128,
        encrypted_locator="data/backups/x.enc",
        metadata_locator="data/backups/x.meta.json",
        recorded_at=NOW.isoformat(),
        transport_security="ssh_tunnel",
        host="192.168.1.1",
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
        ssh_host_key_algorithm="ssh-ed25519",
    )


class ScriptedConnectivityProbe(TcpConnectivityProbe):
    def __init__(self, *, outage_ok: bool = True, recovery_ok: bool = True) -> None:
        self.outage_calls = 0
        self.recovery_calls = 0
        self._outage_ok = outage_ok
        self._recovery_ok = recovery_ok

    def wait_for_outage(
        self, host: str, port: int, *, timeout: float, poll_interval: float = 1.0
    ) -> bool:
        self.outage_calls += 1
        return self._outage_ok

    def wait_for_recovery(
        self, host: str, port: int, *, timeout: float, poll_interval: float = 1.0
    ) -> bool:
        self.recovery_calls += 1
        return self._recovery_ok


def _fake_tunnel_class():
    class FakeTunnel:
        def __init__(self, config: object) -> None:
            self.config = config
            self._transport = MagicMock(is_active=lambda: True)
            self._forward_server = MagicMock()
            self._forward_server.server_address = ("127.0.0.1", 54321)
            self._closed = False
            self.local_host = "127.0.0.1"
            self.local_port = 54321
            self.host_key_algorithm = "ssh-ed25519"
            self.host_key_fingerprint_sha256 = _VALID_SSH_HOST_KEY_SHA256
            self.tcp_connect_host = "192.168.1.1"

        def open(self) -> None:
            return None

        def close(self) -> None:
            self._closed = True
            self._transport = None
            self._forward_server = None

    return FakeTunnel


def _exec_fixtures() -> tuple[FailSafeExecutionResult, FailSafeExecSession]:
    exec_channel = MagicMock()
    exec_channel.closed = False

    def _close_exec_channel() -> None:
        exec_channel.closed = True

    exec_channel.close = _close_exec_channel
    exec_session = FailSafeExecSession(
        channel=exec_channel,
        ack=FailSafeExecAck(
            ack_matched=True,
            exit_status=0,
            stdout_byte_count=8,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "d" * 64,
            stderr_sha256="sha256:" + "e" * 64,
        ),
    )
    exec_result = FailSafeExecutionResult(
        operation=FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
        timer_seconds=60,
        ack_matched=True,
        exit_status=0,
        stdout_sha256="sha256:" + "d" * 64,
        stderr_sha256="sha256:" + "e" * 64,
        stdout_byte_count=8,
        stderr_byte_count=0,
    )
    return exec_result, exec_session


def _runner_execute_mocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        fsc_mod,
        "PinnedSshTunnel",
        _fake_tunnel_class(),
    )
    exec_result, exec_session = _exec_fixtures()
    monkeypatch.setattr(
        FailSafeHardwareBoundary,
        "execute",
        lambda self, *args, **kwargs: (exec_result, exec_session),
    )


def _live_probe_fn(_transport: object) -> dict[str, object]:
    return dict(PROBE_EVIDENCE)


def _capture_transport_source(transport: object) -> dict[str, object]:
    _capture_transport_source.captured = getattr(transport, "source_address", None)  # type: ignore[attr-defined]
    return dict(PROBE_EVIDENCE)


def test_runner_happy_path_with_mocks(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    probe = ScriptedConnectivityProbe()
    hardware = FailSafeHardwareBoundary()
    _runner_execute_mocks(monkeypatch)

    def fake_probe_factory(**kwargs: object):
        def _probe(_target: object) -> dict[str, object]:
            return dict(PROBE_EVIDENCE)

        return _probe

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=hardware,
        connectivity_probe=probe,
        dry_run=False,
        validate_only=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=_live_probe_fn,
        probe_fn_factory=fake_probe_factory,
    )
    evidence = runner.run()
    assert evidence["result"] == "passed"
    assert evidence["sessions_closed_verified"] is True
    assert evidence["write_certified"] is False
    serialized = json.dumps(evidence)
    for sentinel in FORBIDDEN_SENTINELS:
        assert sentinel not in serialized


def test_runner_fails_with_evidence_when_vault_use_raises_after_consume(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    vault.revoke("lab-ref")
    trials_root = tmp_path / "trials"
    close_calls: list[bool] = []

    class TrackingSessions:
        exec_session = None
        rci_transport = None
        tunnel = None

        def close_all_verified(self) -> bool:
            close_calls.append(True)
            return True

    monkeypatch.setattr(
        fsc_mod,
        "_RunnerSessions",
        lambda: TrackingSessions(),
    )

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        dry_run=False,
        trials_root=trials_root,
        now=NOW,
    )
    evidence = runner.run()
    assert evidence["result"] == "failed"
    assert evidence["window_closed"] is True
    assert evidence["write_certified"] is False
    assert evidence["not_write_certified"] is True
    assert evidence["error_type"] == FailSafeError.__name__
    assert trial_marker_path(trials_root, auth.trial_id).is_file()
    assert close_calls == [True]


def test_runner_fails_without_session_close_before_poll(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()

    class BadSessions:
        exec_session = None
        rci_transport = None
        tunnel = None

        def close_all_verified(self) -> bool:
            return False

    monkeypatch.setattr(
        fsc_mod,
        "_RunnerSessions",
        lambda: BadSessions(),
    )
    monkeypatch.setattr(
        fsc_mod,
        "PinnedSshTunnel",
        lambda config: MagicMock(
            open=lambda: None,
            close=lambda: None,
            _transport=MagicMock(is_active=lambda: True),
            _forward_server=MagicMock(server_address=("127.0.0.1", 1)),
            local_host="127.0.0.1",
            local_port=1,
            host_key_algorithm="ssh-ed25519",
            host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            tcp_connect_host="192.168.1.1",
            config=MagicMock(ssh_host="192.168.1.1", password=SYNTH_PASSWORD, username="lab"),
        ),
    )
    hardware = FailSafeHardwareBoundary()
    exec_session = FailSafeExecSession(
        channel=MagicMock(closed=False),
        ack=FailSafeExecAck(
            ack_matched=True,
            exit_status=0,
            stdout_byte_count=1,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "f" * 64,
            stderr_sha256="sha256:" + "0" * 64,
        ),
    )
    monkeypatch.setattr(
        FailSafeHardwareBoundary,
        "execute",
        lambda self, *args, **kwargs: (
            FailSafeExecutionResult(
                operation=FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
                timer_seconds=60,
                ack_matched=True,
                exit_status=0,
                stdout_sha256="sha256:" + "f" * 64,
                stderr_sha256="sha256:" + "0" * 64,
                stdout_byte_count=1,
                stderr_byte_count=0,
            ),
            exec_session,
        ),
    )

    class NeverCalledProbe(ScriptedConnectivityProbe):
        def wait_for_outage(self, *args: object, **kwargs: object) -> bool:
            raise AssertionError("outage poll must not start when sessions not closed")

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=hardware,
        connectivity_probe=NeverCalledProbe(),
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=_live_probe_fn,
    )
    evidence = runner.run()
    assert evidence["result"] == "failed"
    assert evidence["window_closed"] is True
    assert evidence["error_type"] == FailSafeSessionCloseError.__name__


def _execute_runner(
    tmp_path: Path,
    auth_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    probe: ScriptedConnectivityProbe,
    pre_command_probe_fn=_live_probe_fn,
    probe_fn_factory=None,
) -> dict[str, object]:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    hardware = FailSafeHardwareBoundary()
    _runner_execute_mocks(monkeypatch)

    if probe_fn_factory is None:

        def probe_fn_factory(**kwargs: object):
            def _probe(_target: object) -> dict[str, object]:
                return dict(PROBE_EVIDENCE)

            return _probe

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=hardware,
        connectivity_probe=probe,
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=pre_command_probe_fn,
        probe_fn_factory=probe_fn_factory,
    )
    return runner.run()


def test_runner_fails_on_outage_timeout(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = _execute_runner(
        tmp_path,
        auth_path,
        monkeypatch,
        probe=ScriptedConnectivityProbe(outage_ok=False),
    )
    assert evidence["result"] == "failed"
    assert evidence["window_closed"] is True
    assert evidence["write_certified"] is False
    assert evidence["not_write_certified"] is True
    assert evidence["outage_observed"] is False


def test_runner_fails_on_recovery_timeout(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = _execute_runner(
        tmp_path,
        auth_path,
        monkeypatch,
        probe=ScriptedConnectivityProbe(outage_ok=True, recovery_ok=False),
    )
    assert evidence["result"] == "failed"
    assert evidence["window_closed"] is True
    assert evidence["write_certified"] is False
    assert evidence["recovery_observed"] is False


def test_runner_fails_on_reprobe_tuple_drift(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    drifted = dict(PROBE_EVIDENCE)
    drifted["model"] = "OTHER"

    def drift_probe_factory(**kwargs: object):
        def _probe(_target: object) -> dict[str, object]:
            return drifted

        return _probe

    evidence = _execute_runner(
        tmp_path,
        auth_path,
        monkeypatch,
        probe=ScriptedConnectivityProbe(),
        probe_fn_factory=drift_probe_factory,
    )
    assert evidence["result"] == "failed"
    assert evidence["window_closed"] is True
    assert evidence["write_certified"] is False
    assert evidence["error_type"] == FailSafeTupleDrift.__name__
    assert evidence["reprobe_tuple_match"] is False


def test_runner_backup_before_command_ordering(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    call_order: list[str] = []
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    hardware = FailSafeHardwareBoundary()
    _runner_execute_mocks(monkeypatch)

    def pre_probe(_transport: object) -> dict[str, object]:
        call_order.append("pre_command_probe")
        return dict(PROBE_EVIDENCE)

    def backup(**kwargs: object) -> StartupBackupMetadata:
        call_order.append("startup_backup")
        return _backup_meta()

    exec_result, exec_session = _exec_fixtures()

    def execute_with_order(self, *args: object, **kwargs: object):
        call_order.append("command_executed")
        return exec_result, exec_session

    monkeypatch.setattr(FailSafeHardwareBoundary, "execute", execute_with_order)

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=hardware,
        connectivity_probe=ScriptedConnectivityProbe(),
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        backup_fn=backup,
        pre_command_probe_fn=pre_probe,
        probe_fn_factory=lambda **kwargs: (lambda _t: dict(PROBE_EVIDENCE)),
    )
    evidence = runner.run()
    assert evidence["result"] == "passed"
    assert call_order == ["pre_command_probe", "startup_backup", "command_executed"]


def test_rejects_missing_gate_b(auth_path: Path) -> None:
    payload = _auth_payload()
    gates = dict(payload["gates"])  # type: ignore[arg-type]
    gates.pop("B")
    payload["gates"] = gates
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FailSafeError, match="gates"):
        load_fail_safe_authorization(
            config_path=auth_path,
            require_status_alignment=False,
            now=NOW,
        )


def test_rejects_gate_b_write_certified(auth_path: Path) -> None:
    payload = _auth_payload()
    gates = dict(payload["gates"])  # type: ignore[arg-type]
    gate_b = dict(gates["B"])  # type: ignore[index]
    gate_b["certification"] = "WriteCertified"
    gates["B"] = gate_b
    payload["gates"] = gates
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(FailSafeError, match="WriteCertified"):
        load_fail_safe_authorization(
            config_path=auth_path,
            require_status_alignment=False,
            now=NOW,
        )


def test_status_alignment_required(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.json"
    status_path = tmp_path / "STATUS.yaml"
    auth_path.write_text(json.dumps(_auth_payload()), encoding="utf-8")
    status_path.write_text("gates:\n  B:\n    status: closed\n", encoding="utf-8")
    with pytest.raises(FailSafeError, match="STATUS.yaml does not declare"):
        load_fail_safe_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=NOW,
        )


def test_status_alignment_rejects_wrong_capability_family(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.json"
    status_path = tmp_path / "STATUS.yaml"
    auth_path.write_text(json.dumps(_auth_payload()), encoding="utf-8")
    status_path.write_text(
        "gates:\n"
        "  B:\n"
        "    status: certification_trial_authorized\n"
        "    certification: CertificationTrialAuthorized\n"
        "    capability_family: AmneziaWG\n"
        "  C:\n"
        "    status: open\n"
        "  D:\n"
        "    status: closed\n",
        encoding="utf-8",
    )
    with pytest.raises(FailSafeError, match="STATUS.yaml does not declare"):
        load_fail_safe_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=NOW,
        )


def test_status_alignment_rejects_missing_capability_family(tmp_path: Path) -> None:
    auth_path = tmp_path / "auth.json"
    status_path = tmp_path / "STATUS.yaml"
    auth_path.write_text(json.dumps(_auth_payload()), encoding="utf-8")
    status_path.write_text(
        "gates:\n"
        "  B:\n"
        "    status: certification_trial_authorized\n"
        "    certification: CertificationTrialAuthorized\n"
        "  C:\n"
        "    status: open\n"
        "  D:\n"
        "    status: closed\n",
        encoding="utf-8",
    )
    with pytest.raises(FailSafeError, match="STATUS.yaml does not declare"):
        load_fail_safe_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=NOW,
        )


def test_tcp_connectivity_probe_uses_bound_connection_with_source_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = TcpConnectivityProbe(source_address="192.168.1.144")
    fake_sock = MagicMock()

    def fake_create_bound(*args: object, **kwargs: object) -> MagicMock:
        assert kwargs.get("source_address") == "192.168.1.144"
        return fake_sock

    monkeypatch.setattr(ssh_tunnel_mod, "create_bound_tcp_connection", fake_create_bound)
    assert probe.tcp_reachable("192.168.1.1", 22, timeout=1.0) is True
    fake_sock.close.assert_called_once()


def test_tcp_connectivity_probe_remote_unreachable_returns_false(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = TcpConnectivityProbe(source_address="192.168.1.144")

    def fake_create_bound(*args: object, **kwargs: object) -> MagicMock:
        raise OSError("connection refused")

    monkeypatch.setattr(ssh_tunnel_mod, "create_bound_tcp_connection", fake_create_bound)
    assert probe.tcp_reachable("192.168.1.1", 22, timeout=1.0) is False


def test_tcp_connectivity_probe_bind_failure_raises_without_unbound_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control.adapters.netcraze.ssh_tunnel import SshSourceAddressBindError

    probe = TcpConnectivityProbe(source_address="192.168.1.144")

    def fake_create_bound(*args: object, **kwargs: object) -> MagicMock:
        raise SshSourceAddressBindError(
            "failed to bind outbound TCP to source_address 192.168.1.144"
        )

    unbound_called = False

    def fake_unbound(*args: object, **kwargs: object) -> None:
        nonlocal unbound_called
        unbound_called = True

    monkeypatch.setattr(ssh_tunnel_mod, "create_bound_tcp_connection", fake_create_bound)
    monkeypatch.setattr(fsc_mod.socket, "create_connection", fake_unbound)
    with pytest.raises(SshSourceAddressBindError):
        probe.tcp_reachable("192.168.1.1", 22, timeout=1.0)
    assert unbound_called is False


def test_tcp_connectivity_probe_wait_for_outage_survives_remote_refuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    probe = TcpConnectivityProbe(source_address="192.168.1.144")
    calls = {"count": 0}

    def fake_create_bound(*args: object, **kwargs: object) -> MagicMock:
        calls["count"] += 1
        if calls["count"] == 1:
            return MagicMock()
        raise OSError("connection refused")

    monkeypatch.setattr(ssh_tunnel_mod, "create_bound_tcp_connection", fake_create_bound)
    monkeypatch.setattr(fsc_mod.time, "sleep", lambda _: None)
    assert probe.wait_for_outage("192.168.1.1", 22, timeout=5.0, poll_interval=0.01) is True


def test_runner_threads_source_address_into_tunnel_polls_and_reprobe(
    tmp_path: Path,
    auth_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    captured: dict[str, object] = {}
    _runner_execute_mocks(monkeypatch)

    class TrackingTunnel:
        def __init__(self, config: object) -> None:
            captured["tunnel_source"] = getattr(config, "source_address", None)
            self.config = config
            self._transport = MagicMock(is_active=lambda: True)
            self._forward_server = MagicMock()
            self._forward_server.server_address = ("127.0.0.1", 54321)
            self._closed = False
            self.local_host = "127.0.0.1"
            self.local_port = 54321
            self.host_key_algorithm = "ssh-ed25519"
            self.host_key_fingerprint_sha256 = _VALID_SSH_HOST_KEY_SHA256
            self.tcp_connect_host = "192.168.1.1"

        def open(self) -> None:
            return None

        def close(self) -> None:
            self._closed = True
            self._transport = None
            self._forward_server = None

    monkeypatch.setattr(fsc_mod, "PinnedSshTunnel", TrackingTunnel)
    preflight_calls: list[str] = []

    def fake_preflight(source_address: str, **kwargs: object) -> str:
        preflight_calls.append(source_address)
        return source_address

    monkeypatch.setattr(ssh_tunnel_mod, "preflight_source_address_bind", fake_preflight)

    probe = ScriptedConnectivityProbe()
    reprobe_targets: list[object] = []

    def probe_factory(**kwargs: object):
        def _probe(target: object) -> dict[str, object]:
            reprobe_targets.append(target)
            return dict(PROBE_EVIDENCE)

        return _probe

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=FailSafeHardwareBoundary(),
        connectivity_probe=probe,
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        source_address="192.168.1.144",
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=_capture_transport_source,
        probe_fn_factory=probe_factory,
    )
    evidence = runner.run()
    assert evidence["result"] == "passed"
    assert captured["tunnel_source"] == "192.168.1.144"
    assert _capture_transport_source.captured == "192.168.1.144"  # type: ignore[attr-defined]
    assert preflight_calls == ["192.168.1.144"]
    assert isinstance(runner.connectivity_probe, TcpConnectivityProbe)
    assert runner.connectivity_probe.source_address == "192.168.1.144"
    assert len(reprobe_targets) == 1
    assert getattr(reprobe_targets[0], "source_address", None) == "192.168.1.144"
    assert evidence["source_address"] == "192.168.1.144"


def test_runner_rejects_custom_probe_when_source_address_set(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    _runner_execute_mocks(monkeypatch)

    class CustomProbe:
        def tcp_reachable(self, *args: object, **kwargs: object) -> bool:
            return True

        def wait_for_outage(self, *args: object, **kwargs: object) -> bool:
            return True

        def wait_for_recovery(self, *args: object, **kwargs: object) -> bool:
            return True

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        connectivity_probe=CustomProbe(),
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        source_address="192.168.1.144",
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=_live_probe_fn,
    )
    evidence = runner.run()
    assert evidence["result"] == "failed"
    assert evidence["error_type"] == FailSafeError.__name__


def _runner_with_hardware_failure(
    tmp_path: Path,
    auth_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    hardware_error: FailSafeHardwareError,
) -> dict[str, object]:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    _runner_execute_mocks(monkeypatch)

    def failing_execute(self, *args: object, **kwargs: object):
        raise hardware_error

    monkeypatch.setattr(FailSafeHardwareBoundary, "execute", failing_execute)

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=FailSafeHardwareBoundary(),
        connectivity_probe=ScriptedConnectivityProbe(),
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=_live_probe_fn,
    )
    return runner.run()


def test_runner_failed_evidence_includes_dispatch_diagnostics_and_open_gate_c(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sealed_meta = {
        "operation": "fail_safe_timer_reboot_60",
        "timer_seconds": 60,
        "ack_matched": False,
        "exit_status": 0,
        "stdout_sha256": "sha256:" + "a" * 64,
        "stderr_sha256": "sha256:" + "b" * 64,
        "stdout_byte_count": 0,
        "stderr_byte_count": 0,
    }
    evidence = _runner_with_hardware_failure(
        tmp_path,
        auth_path,
        monkeypatch,
        hardware_error=FailSafeHardwareError(
            "fail-safe sealed CLI ack not matched",
            error_code="cli_ack_unverified",
            failure_stage="sealed_cli_dispatch",
            dispatch_attempted=True,
            sealed_meta=sealed_meta,
        ),
    )
    assert evidence["result"] == "failed"
    assert evidence["dispatch_attempted"] is True
    assert evidence["error_code"] == "cli_ack_unverified"
    assert evidence["failure_stage"] == "sealed_cli_dispatch"
    assert evidence["gate_c_window_open_at_execute"] is True
    assert evidence["command_result"] == sealed_meta
    serialized = json.dumps(evidence)
    for sentinel in FORBIDDEN_SENTINELS:
        assert sentinel not in serialized


def test_runner_failed_evidence_maps_non_zero_exit_diagnostics(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sealed_meta = {
        "operation": "fail_safe_timer_reboot_60",
        "timer_seconds": 60,
        "ack_matched": True,
        "exit_status": 1,
        "stdout_sha256": "sha256:" + "c" * 64,
        "stderr_sha256": "sha256:" + "d" * 64,
        "stdout_byte_count": 4,
        "stderr_byte_count": 2,
    }
    evidence = _runner_with_hardware_failure(
        tmp_path,
        auth_path,
        monkeypatch,
        hardware_error=FailSafeHardwareError(
            "fail-safe command exited with non-zero status",
            error_code="cli_non_zero_exit",
            failure_stage="sealed_cli_dispatch",
            dispatch_attempted=True,
            sealed_meta=sealed_meta,
        ),
    )
    assert evidence["error_code"] == "cli_non_zero_exit"
    assert evidence["command_result"]["exit_status"] == 1
    assert evidence["gate_c_window_open_at_execute"] is True


def test_runner_failed_evidence_plumbs_executor_error_mid_dispatch(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    monkeypatch.setattr(
        fsc_mod,
        "PinnedSshTunnel",
        _fake_tunnel_class(),
    )

    def failing_exec(transport: object, **kwargs: object) -> FailSafeExecSession:
        raise SshTunnelError("raw transport failure during sealed dispatch")

    monkeypatch.setattr(fsh_mod, "exec_fail_safe_timer_reboot_60", failing_exec)

    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        hardware=FailSafeHardwareBoundary(),
        connectivity_probe=ScriptedConnectivityProbe(),
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
        backup_fn=lambda **kwargs: _backup_meta(),
        pre_command_probe_fn=_live_probe_fn,
    )
    evidence = runner.run()
    assert evidence["result"] == "failed"
    assert evidence["dispatch_attempted"] is True
    assert evidence["failure_stage"] == "sealed_cli_dispatch"
    assert evidence["error_code"] == "fail_safe_hardware_error"
    assert "command_result" not in evidence
    serialized = json.dumps(evidence)
    for sentinel in FORBIDDEN_SENTINELS:
        assert sentinel not in serialized
    assert "raw transport failure" not in serialized


def test_runner_pre_dispatch_failure_has_dispatch_attempted_false(
    tmp_path: Path, auth_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    auth = load_fail_safe_authorization(
        config_path=auth_path, require_status_alignment=False, now=NOW
    )
    vault = _memory_vault()
    vault.revoke("lab-ref")
    runner = FailSafeDiscoveryRunner(
        authorization=auth,
        gate_a=_gate_a(),
        host="192.168.1.1",
        username="lab",
        credential_ref="lab-ref",
        host_key_pin=_VALID_SSH_HOST_KEY_SHA256,
        vault=vault,
        probe_evidence=dict(PROBE_EVIDENCE),
        dry_run=False,
        trials_root=tmp_path / "trials",
        now=NOW,
    )
    evidence = runner.run()
    assert evidence["dispatch_attempted"] is False
    assert evidence["failure_stage"] == "trial_consume"
