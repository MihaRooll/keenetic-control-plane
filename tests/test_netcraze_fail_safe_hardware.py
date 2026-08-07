"""Fail-safe hardware boundary tests (synthetic; no live network)."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze import fail_safe_hardware as fsh_mod
from router_control.adapters.netcraze import ssh_tunnel as ssh_tunnel_module
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.errors import SshTunnelError
from router_control.adapters.netcraze.fail_safe_hardware import (
    ALLOWLISTED_FAIL_SAFE_OPERATIONS,
    FailSafeHardwareBoundary,
    FailSafeHardwareError,
    FailSafeTypedOperation,
)
from router_control.adapters.netcraze.ssh_tunnel import (
    FailSafeExecAck,
    FailSafeExecSession,
    sanitize_ssh_error_message,
)
from router_control.adapters.netcraze.typed_executor import ExecutorError

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
COMPONENT_DIGEST = "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
FINGERPRINT_DIGEST = "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"


def _authorized_gate_kwargs() -> dict[str, object]:
    return {
        "gate_b_trial_authorized": True,
        "gate_c_open": True,
        "gate_d_closed": True,
        "trial_authorized": True,
    }


def _open_gate_a(**overrides: object) -> GateACertification:
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
        "ssh_host_key_fingerprint_sha256": "SHA256:abc",
        "certification_eligible": True,
        "evidence_recorded_at": now,
        "evidence_path": "data/artifacts/gate-a-probe.json",
        "expires_at": now + timedelta(days=90),
        "revocation_policy": "human",
        "gates_b_closed": True,
        "gates_c_closed": True,
        "gates_d_closed": True,
    }
    base.update(overrides)
    return GateACertification(**base)  # type: ignore[arg-type]


def test_allowlist_exposes_single_operation() -> None:
    assert list(ALLOWLISTED_FAIL_SAFE_OPERATIONS) == [
        FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60
    ]


def test_module_has_no_general_exec_command_api() -> None:
    assert "exec_command" not in ssh_tunnel_module.__all__
    assert not hasattr(ssh_tunnel_module, "exec_command")


def test_sealed_command_constant_is_private() -> None:
    assert "FAIL_SAFE_TIMER_REBOOT_60" not in ssh_tunnel_module.__all__
    command = ssh_tunnel_module._FAIL_SAFE_TIMER_REBOOT_60_COMMAND
    assert command == "system configuration fail-safe timer reboot 60"


def test_execute_unauthorized_by_default() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = True
    with pytest.raises(FailSafeHardwareError, match="authorization"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
        )


def test_rejects_missing_gate_c_state() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = True
    with pytest.raises(FailSafeHardwareError, match="Gate C lab window state is required"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            gate_c_open=None,
            gate_b_trial_authorized=True,
            trial_authorized=True,
        )


def test_rejects_missing_gate_d_state_by_default() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = True
    with pytest.raises(FailSafeHardwareError, match="Gate D state is required"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            gate_c_open=True,
            gate_b_trial_authorized=True,
            trial_authorized=True,
        )


def test_rejects_open_gate_d() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = True
    kwargs = _authorized_gate_kwargs()
    kwargs["gate_d_closed"] = False
    with pytest.raises(FailSafeHardwareError, match="Gate D"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            **kwargs,
        )


def test_rejects_closed_gate_c() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = True
    with pytest.raises(FailSafeHardwareError, match="Gate C lab window is not open"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            gate_c_open=False,
            gate_b_trial_authorized=True,
            gate_d_closed=True,
            trial_authorized=True,
        )


def test_rejects_closed_gate_a() -> None:
    gate_a = _open_gate_a(status="closed", certification=None)
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = True
    with pytest.raises(FailSafeHardwareError, match="Gate A"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=gate_a,
        )


def test_rejects_inactive_transport() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock()
    transport.is_active.return_value = False
    with pytest.raises(FailSafeHardwareError, match="not active"):
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
        )


def test_execute_delegates_to_sealed_exec(monkeypatch: pytest.MonkeyPatch) -> None:
    channel = MagicMock()
    channel.closed = False
    session = FailSafeExecSession(
        channel=channel,
        ack=FailSafeExecAck(
            ack_matched=True,
            exit_status=0,
            stdout_byte_count=10,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "a" * 64,
            stderr_sha256="sha256:" + "b" * 64,
        ),
    )
    captured: dict[str, object] = {}

    def fake_exec(transport: object, **kwargs: object) -> FailSafeExecSession:
        captured["transport"] = transport
        captured.update(kwargs)
        return session

    monkeypatch.setattr(
        fsh_mod,
        "exec_fail_safe_timer_reboot_60",
        fake_exec,
    )
    transport = MagicMock()
    transport.is_active.return_value = True
    boundary = FailSafeHardwareBoundary()
    result, returned_session = boundary.execute(
        FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
        transport=transport,
        password=SYNTH_PASSWORD,
        gate_a=_open_gate_a(),
        stdout_cap=512,
        **_authorized_gate_kwargs(),
    )
    assert captured["transport"] is transport
    assert captured["password"] == SYNTH_PASSWORD
    assert captured["stdout_cap"] == 512
    assert result.ack_matched is True
    assert returned_session is session
    assert "password" not in repr(result)


def test_ack_pattern_requires_fail_safe_and_timer_tokens() -> None:
    assert ssh_tunnel_module._fail_safe_ack_matched(
        b"Fail-safe configuration timer enabled",
        b"reboot in 60 seconds",
    )
    assert not ssh_tunnel_module._fail_safe_ack_matched(b"ok", b"")


def test_exec_redacts_password_in_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = MagicMock()
    transport.is_active.return_value = True
    transport.open_session.side_effect = RuntimeError(f"failed for {SYNTH_PASSWORD}")

    with pytest.raises(SshTunnelError) as exc:
        ssh_tunnel_module.exec_fail_safe_timer_reboot_60(
            transport,
            password=SYNTH_PASSWORD,
        )
    assert SYNTH_PASSWORD not in str(exc.value)
    assert "[REDACTED]" in sanitize_ssh_error_message(str(exc.value), password=SYNTH_PASSWORD)


def test_bounded_read_respects_cap() -> None:
    channel = MagicMock()
    channel.recv.side_effect = [b"x" * 3000, b"y" * 3000, b""]
    data = ssh_tunnel_module._read_bounded_channel_stream(channel, cap=4096, is_stderr=False)
    assert len(data) == 4096


def test_result_sanitized_dict_has_no_raw_output(monkeypatch: pytest.MonkeyPatch) -> None:
    channel = MagicMock()
    channel.closed = False
    session = FailSafeExecSession(
        channel=channel,
        ack=FailSafeExecAck(
            ack_matched=True,
            exit_status=0,
            stdout_byte_count=10,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "a" * 64,
            stderr_sha256="sha256:" + "b" * 64,
        ),
    )
    monkeypatch.setattr(
        fsh_mod,
        "exec_fail_safe_timer_reboot_60",
        lambda transport, **kwargs: session,
    )
    boundary = FailSafeHardwareBoundary()
    result, _ = boundary.execute(
        FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
        transport=MagicMock(is_active=lambda: True),
        password=SYNTH_PASSWORD,
        gate_a=_open_gate_a(),
        **_authorized_gate_kwargs(),
    )
    payload = result.sanitized_dict()
    assert set(payload) == {
        "operation",
        "timer_seconds",
        "ack_matched",
        "dispatch_path",
        "exit_status",
        "stdout_sha256",
        "stderr_sha256",
        "stdout_byte_count",
        "stderr_byte_count",
    }
    assert payload["timer_seconds"] == 60
    assert re.fullmatch(r"sha256:[a-f0-9]{64}", str(payload["stdout_sha256"]))


def _boundary_execute_with_ack(
    monkeypatch: pytest.MonkeyPatch,
    ack: FailSafeExecAck,
) -> FailSafeHardwareError:
    session = FailSafeExecSession(channel=MagicMock(closed=False), ack=ack)
    monkeypatch.setattr(
        fsh_mod,
        "exec_fail_safe_timer_reboot_60",
        lambda transport, **kwargs: session,
    )
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock(is_active=lambda: True)
    with pytest.raises(FailSafeHardwareError) as exc_info:
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            **_authorized_gate_kwargs(),
        )
    return exc_info.value


def test_sealed_dispatch_failure_attaches_sanitized_diagnostics_for_empty_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exc = _boundary_execute_with_ack(
        monkeypatch,
        FailSafeExecAck(
            ack_matched=False,
            exit_status=0,
            stdout_byte_count=0,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "0" * 64,
            stderr_sha256="sha256:" + "1" * 64,
        ),
    )
    assert exc.dispatch_attempted is True
    assert exc.failure_stage == "sealed_cli_dispatch"
    assert exc.error_code == "cli_ack_unverified"
    assert exc.sealed_meta is not None
    assert exc.sealed_meta["ack_matched"] is False
    assert exc.sealed_meta["stdout_byte_count"] == 0
    assert SYNTH_PASSWORD not in json.dumps(exc.sealed_meta)


def test_sealed_dispatch_failure_attaches_sanitized_diagnostics_for_unmatched_ack(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exc = _boundary_execute_with_ack(
        monkeypatch,
        FailSafeExecAck(
            ack_matched=False,
            exit_status=0,
            stdout_byte_count=12,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "2" * 64,
            stderr_sha256="sha256:" + "3" * 64,
        ),
    )
    assert exc.error_code == "cli_ack_unverified"
    assert exc.sealed_meta is not None
    assert exc.sealed_meta["ack_matched"] is False


def test_sealed_dispatch_failure_attaches_sanitized_diagnostics_for_non_zero_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exc = _boundary_execute_with_ack(
        monkeypatch,
        FailSafeExecAck(
            ack_matched=True,
            exit_status=1,
            stdout_byte_count=8,
            stderr_byte_count=4,
            stdout_sha256="sha256:" + "4" * 64,
            stderr_sha256="sha256:" + "5" * 64,
        ),
    )
    assert exc.error_code == "cli_non_zero_exit"
    assert exc.sealed_meta is not None
    assert exc.sealed_meta["exit_status"] == 1


def test_executor_error_mid_dispatch_sets_dispatch_attempted_without_raw_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failing_exec(transport: object, **kwargs: object) -> FailSafeExecSession:
        raise SshTunnelError("raw transport failure during sealed dispatch")

    monkeypatch.setattr(fsh_mod, "exec_fail_safe_timer_reboot_60", failing_exec)
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock(is_active=lambda: True)
    with pytest.raises(FailSafeHardwareError) as exc_info:
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            **_authorized_gate_kwargs(),
        )
    exc = exc_info.value
    assert exc.dispatch_attempted is True
    assert exc.failure_stage == "sealed_cli_dispatch"
    assert exc.error_code == "fail_safe_hardware_error"
    assert exc.sealed_meta is None
    assert str(exc) == "fail-safe sealed CLI dispatch failed"
    assert "raw transport failure" not in str(exc)
    assert SYNTH_PASSWORD not in json.dumps(
        {
            "error_code": exc.error_code,
            "failure_stage": exc.failure_stage,
            "dispatch_attempted": exc.dispatch_attempted,
            "sealed_meta": exc.sealed_meta,
        }
    )


def test_executor_error_mid_dispatch_attaches_sealed_meta_when_session_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FailSafeExecSession(
        channel=MagicMock(closed=False),
        ack=FailSafeExecAck(
            ack_matched=False,
            exit_status=0,
            stdout_byte_count=0,
            stderr_byte_count=0,
            stdout_sha256="sha256:" + "6" * 64,
            stderr_sha256="sha256:" + "7" * 64,
        ),
    )

    def failing_execute_sealed(
        self: fsh_mod._SealedFailSafeCliTransport,
        request: object,
        *,
        password: str,
    ) -> object:
        self._sealed_dispatch_entered = True
        self._session = session
        raise ExecutorError("mid-dispatch executor failure")

    monkeypatch.setattr(
        fsh_mod._SealedFailSafeCliTransport,
        "execute_sealed",
        failing_execute_sealed,
    )
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock(is_active=lambda: True)
    with pytest.raises(FailSafeHardwareError) as exc_info:
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password=SYNTH_PASSWORD,
            gate_a=_open_gate_a(),
            **_authorized_gate_kwargs(),
        )
    exc = exc_info.value
    assert exc.dispatch_attempted is True
    assert exc.error_code == "cli_ack_unverified"
    assert exc.sealed_meta is not None
    assert exc.sealed_meta["ack_matched"] is False
    assert "mid-dispatch executor failure" not in json.dumps(exc.sealed_meta)


def test_executor_error_pre_transport_has_dispatch_attempted_false() -> None:
    boundary = FailSafeHardwareBoundary()
    transport = MagicMock(is_active=lambda: True)
    with pytest.raises(FailSafeHardwareError) as exc_info:
        boundary.execute(
            FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60,
            transport=transport,
            password="",
            gate_a=_open_gate_a(),
            **_authorized_gate_kwargs(),
        )
    exc = exc_info.value
    assert exc.dispatch_attempted is False
    assert exc.failure_stage is None
    assert exc.error_code == "fail_safe_hardware_error"
    assert exc.sealed_meta is None
    assert str(exc) == "fail-safe sealed CLI dispatch failed"
    assert "password" not in json.dumps(
        {
            "error_code": exc.error_code,
            "failure_stage": exc.failure_stage,
            "dispatch_attempted": exc.dispatch_attempted,
            "sealed_meta": exc.sealed_meta,
        }
    )
