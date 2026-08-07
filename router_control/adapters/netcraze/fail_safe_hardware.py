"""Typed fail-safe hardware boundary — single sealed NC-1812 timer operation."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.codec import (
    InMemorySecretResolver,
    NormalizedError,
    SealedCliExchange,
    TypedIntent,
    WireRequest,
)
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeRciError,
    RciSealedWriteTransport,
    arm_fail_safe_timer_reboot_60,
)
from router_control.adapters.netcraze.operation_spec import (
    SYNTHETIC_RECORDED_FAIL_SAFE_TIMER,
    build_registered_operation,
)
from router_control.adapters.netcraze.shape_registry import ShapePromotionState
from router_control.adapters.netcraze.ssh_tunnel import (
    FailSafeExecAck,
    FailSafeExecSession,
    SshTunnelError,
    exec_fail_safe_timer_reboot_60,
)
from router_control.adapters.netcraze.typed_executor import (
    CertificationExecutionContext,
    ExecutorError,
    SharedTypedOperationExecutor,
)


class FailSafeTypedOperation(StrEnum):
    FAIL_SAFE_TIMER_REBOOT_60 = "fail_safe_timer_reboot_60"


ALLOWLISTED_FAIL_SAFE_OPERATIONS: frozenset[FailSafeTypedOperation] = frozenset(
    FailSafeTypedOperation
)
FAIL_SAFE_TIMER_SECONDS = 60


_ALLOWLISTED_SEALED_ERROR_CODES = frozenset({"cli_ack_unverified", "cli_non_zero_exit"})


class FailSafeHardwareError(Exception):
    """Fail-safe hardware boundary rejected the request."""

    error_code: str | None
    failure_stage: str | None
    dispatch_attempted: bool
    sealed_meta: dict[str, object] | None

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        failure_stage: str | None = None,
        dispatch_attempted: bool = False,
        sealed_meta: dict[str, object] | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.failure_stage = failure_stage
        self.dispatch_attempted = dispatch_attempted
        self.sealed_meta = sealed_meta


class FailSafeOperationForbidden(FailSafeHardwareError):
    """Operation is not on the fail-safe allowlist."""


class FailSafeTransportRequired(FailSafeHardwareError):
    """Pinned authenticated SSH transport is required."""


class PinnedSshTransportPort(Protocol):
    def is_active(self) -> bool: ...


@dataclass
class _SealedFailSafeCliTransport:
    transport: Any
    channel_timeout: float
    exec_timeout: float
    stdout_cap: int
    stderr_cap: int
    _session: FailSafeExecSession | None = field(default=None, init=False, repr=False)
    _sealed_dispatch_entered: bool = field(default=False, init=False, repr=False)

    @property
    def sealed_dispatch_entered(self) -> bool:
        return self._sealed_dispatch_entered

    def is_active(self) -> bool:
        is_active = getattr(self.transport, "is_active", None)
        return bool(is_active()) if callable(is_active) else False

    def execute_sealed(self, request: WireRequest, *, password: str) -> SealedCliExchange:
        self._sealed_dispatch_entered = True
        if request.endpoint_identifier != SYNTHETIC_RECORDED_FAIL_SAFE_TIMER.endpoint_identifier:
            raise ExecutorError("sealed endpoint identifier mismatch")
        try:
            session = exec_fail_safe_timer_reboot_60(
                self.transport,
                password=password,
                channel_timeout=self.channel_timeout,
                exec_timeout=self.exec_timeout,
                stdout_cap=self.stdout_cap,
                stderr_cap=self.stderr_cap,
            )
        except SshTunnelError as exc:
            raise ExecutorError(str(exc)) from exc
        self._session = session
        ack = session.ack
        return SealedCliExchange(
            exit_status=ack.exit_status,
            stdout=b"",
            stderr=b"",
            stdout_sha256=ack.stdout_sha256,
            stderr_sha256=ack.stderr_sha256,
            ack_matched=ack.ack_matched,
            stdout_byte_count=ack.stdout_byte_count,
            stderr_byte_count=ack.stderr_byte_count,
        )

    def take_session(self) -> FailSafeExecSession | None:
        session = self._session
        self._session = None
        return session


def _sealed_meta_from_ack(
    operation: FailSafeTypedOperation,
    ack: FailSafeExecAck,
) -> dict[str, object]:
    return {
        "operation": operation.value,
        "timer_seconds": FAIL_SAFE_TIMER_SECONDS,
        "ack_matched": ack.ack_matched,
        "exit_status": ack.exit_status,
        "stdout_sha256": ack.stdout_sha256,
        "stderr_sha256": ack.stderr_sha256,
        "stdout_byte_count": ack.stdout_byte_count,
        "stderr_byte_count": ack.stderr_byte_count,
    }


def _codec_error_code(error: object | None) -> str:
    if error is not None:
        code = getattr(error, "error_code", None)
        if isinstance(code, str) and code in _ALLOWLISTED_SEALED_ERROR_CODES:
            return code
    return "fail_safe_hardware_error"


def _executor_dispatch_error_code(
    exc: ExecutorError,
    session: FailSafeExecSession | None,
) -> str:
    if session is not None:
        ack = session.ack
        if ack.exit_status != 0:
            return "cli_non_zero_exit"
        if not ack.ack_matched:
            return "cli_ack_unverified"
    cause: BaseException | None = exc
    while cause is not None:
        if isinstance(cause, NormalizedError):
            if cause.error_code in _ALLOWLISTED_SEALED_ERROR_CODES:
                return cause.error_code
        cause = cause.__cause__
    return "fail_safe_hardware_error"



@dataclass(frozen=True, slots=True)
class FailSafeExecutionResult:
    operation: FailSafeTypedOperation
    timer_seconds: int
    ack_matched: bool
    dispatch_path: str = "ssh_exec"
    prompt: str | None = None
    status: tuple[dict[str, str], ...] | None = None
    exit_status: int | None = None
    stdout_sha256: str | None = None
    stderr_sha256: str | None = None
    stdout_byte_count: int | None = None
    stderr_byte_count: int | None = None

    def sanitized_dict(self) -> dict[str, object]:
        if self.dispatch_path == "rci_parse":
            payload: dict[str, object] = {
                "operation": self.operation.value,
                "timer_seconds": self.timer_seconds,
                "ack_matched": self.ack_matched,
                "dispatch_path": self.dispatch_path,
                "prompt": self.prompt or "",
                "status": list(self.status or ()),
            }
            return payload
        return {
            "operation": self.operation.value,
            "timer_seconds": self.timer_seconds,
            "ack_matched": self.ack_matched,
            "dispatch_path": self.dispatch_path,
            "exit_status": self.exit_status,
            "stdout_sha256": self.stdout_sha256,
            "stderr_sha256": self.stderr_sha256,
            "stdout_byte_count": self.stdout_byte_count,
            "stderr_byte_count": self.stderr_byte_count,
        }


@dataclass
class FailSafeHardwareBoundary:
    """Expose only allowlisted fail-safe typed operations — no raw command surface."""

    executor: SharedTypedOperationExecutor = field(default_factory=SharedTypedOperationExecutor)

    def assert_operation_allowlisted(self, operation: FailSafeTypedOperation) -> None:
        if operation not in ALLOWLISTED_FAIL_SAFE_OPERATIONS:
            raise FailSafeOperationForbidden(f"operation not allowlisted: {operation}")

    def assert_pre_io_gates(
        self,
        *,
        gate_a: GateACertification,
        now: Any,
        gate_b_trial_authorized: bool,
        gate_c_open: bool | None,
        gate_d_closed: bool | None,
        probe_tuple_match: bool,
        trial_authorized: bool,
    ) -> None:
        if not gate_a.is_open_at(now):
            raise FailSafeHardwareError("Gate A ReadOnlyCertified is not open")
        if not gate_b_trial_authorized:
            raise FailSafeHardwareError("Gate B trial authorization is not active")
        if gate_c_open is None:
            raise FailSafeHardwareError("Gate C lab window state is required")
        if not gate_c_open:
            raise FailSafeHardwareError("Gate C lab window is not open")
        if gate_d_closed is None:
            raise FailSafeHardwareError("Gate D state is required")
        if not gate_d_closed:
            raise FailSafeHardwareError("Gate D must remain closed")
        if not probe_tuple_match:
            raise FailSafeHardwareError("probe tuple mismatch")
        if not trial_authorized:
            raise FailSafeHardwareError("fail-safe execute authorization required")

    def execute(
        self,
        operation: FailSafeTypedOperation,
        *,
        transport: PinnedSshTransportPort | None = None,
        rci_transport: RciSealedWriteTransport | None = None,
        password: str,
        gate_a: GateACertification,
        channel_timeout: float = 15.0,
        exec_timeout: float = 30.0,
        stdout_cap: int = 4096,
        stderr_cap: int = 1024,
        now: Any = None,
        gate_b_trial_authorized: bool = False,
        gate_c_open: bool | None = None,
        gate_d_closed: bool | None = None,
        probe_tuple_match: bool = True,
        trial_authorized: bool = False,
    ) -> tuple[FailSafeExecutionResult, FailSafeExecSession | None]:
        self.assert_operation_allowlisted(operation)
        if operation != FailSafeTypedOperation.FAIL_SAFE_TIMER_REBOOT_60:
            raise FailSafeOperationForbidden(f"unsupported operation: {operation}")
        if now is None:
            from datetime import UTC, datetime

            current = datetime.now(UTC)
        else:
            current = now
        self.assert_pre_io_gates(
            gate_a=gate_a,
            now=current,
            gate_b_trial_authorized=gate_b_trial_authorized,
            gate_c_open=gate_c_open,
            gate_d_closed=gate_d_closed,
            probe_tuple_match=probe_tuple_match,
            trial_authorized=trial_authorized,
        )
        if rci_transport is not None:
            return self._execute_via_rci(operation, rci_transport=rci_transport)
        if transport is None:
            raise FailSafeTransportRequired("rci_transport or pinned SSH transport is required")
        if not transport.is_active():
            raise FailSafeTransportRequired("pinned SSH transport is not active")
        return self._execute_via_ssh_exec(
            operation,
            transport=transport,
            password=password,
            gate_a=gate_a,
            current=current,
            channel_timeout=channel_timeout,
            exec_timeout=exec_timeout,
            stdout_cap=stdout_cap,
            stderr_cap=stderr_cap,
            gate_b_trial_authorized=gate_b_trial_authorized,
            gate_c_open=gate_c_open,
            gate_d_closed=gate_d_closed,
            probe_tuple_match=probe_tuple_match,
            trial_authorized=trial_authorized,
        )

    def _execute_via_rci(
        self,
        operation: FailSafeTypedOperation,
        *,
        rci_transport: RciSealedWriteTransport,
    ) -> tuple[FailSafeExecutionResult, None]:
        try:
            rci_result = arm_fail_safe_timer_reboot_60(rci_transport)
        except FailSafeRciError as exc:
            raise FailSafeHardwareError(
                "fail-safe sealed RCI dispatch failed",
                error_code="rci_ack_unverified",
                failure_stage="sealed_rci_dispatch",
                dispatch_attempted=True,
            ) from exc
        status = tuple(
            {"status": entry.status, "code": entry.code, "ident": entry.ident}
            for entry in rci_result.status_entries
        )
        result = FailSafeExecutionResult(
            operation=operation,
            timer_seconds=FAIL_SAFE_TIMER_SECONDS,
            ack_matched=rci_result.ack_matched,
            dispatch_path="rci_parse",
            prompt=rci_result.prompt,
            status=status,
        )
        return result, None

    def _execute_via_ssh_exec(
        self,
        operation: FailSafeTypedOperation,
        *,
        transport: PinnedSshTransportPort,
        password: str,
        gate_a: GateACertification,
        current: Any,
        channel_timeout: float,
        exec_timeout: float,
        stdout_cap: int,
        stderr_cap: int,
        gate_b_trial_authorized: bool,
        gate_c_open: bool | None,
        gate_d_closed: bool | None,
        probe_tuple_match: bool,
        trial_authorized: bool,
    ) -> tuple[FailSafeExecutionResult, FailSafeExecSession]:
        gate_a_digest = gate_a.evidence_sha256 or gate_a.device_fingerprint_digest
        if not str(gate_a_digest).startswith("sha256:"):
            gate_a_digest = f"sha256:{gate_a_digest}"
        registered = build_registered_operation(
            SYNTHETIC_RECORDED_FAIL_SAFE_TIMER,
            promotion_state=ShapePromotionState.LAB_OBSERVED.value,
            tuple_component_set_digest=gate_a.component_set_digest,
            tuple_device_fingerprint_digest=gate_a.device_fingerprint_digest,
            gate_a_evidence_digest=gate_a_digest,
            adapter_version="netcraze-p3-v0",
            evidence_digest=gate_a_digest,
        )
        cli_adapter = _SealedFailSafeCliTransport(
            transport=transport,
            channel_timeout=channel_timeout,
            exec_timeout=exec_timeout,
            stdout_cap=stdout_cap,
            stderr_cap=stderr_cap,
        )
        try:
            exec_result = self.executor.execute_certification(
                registered,
                intent=TypedIntent(
                    operation_spec_digest=SYNTHETIC_RECORDED_FAIL_SAFE_TIMER.spec_digest,
                    fields={},
                ),
                context=CertificationExecutionContext(
                    gate_a_open=gate_a.is_open_at(current),
                    gate_c_open=bool(gate_c_open),
                    candidate_spec_digest=SYNTHETIC_RECORDED_FAIL_SAFE_TIMER.spec_digest,
                    trial_authorized=trial_authorized and gate_b_trial_authorized,
                    probe_tuple_match=probe_tuple_match,
                    gate_d_closed=bool(gate_d_closed),
                    lab_observed_grant_digest=gate_a_digest,
                    readback_evidence=True,
                    functional_evidence=True,
                    compensation_evidence=True,
                ),
                secret_resolver=InMemorySecretResolver(),
                cli_transport=cli_adapter,
                password=password,
            )
        except ExecutorError as exc:
            dispatch_attempted = cli_adapter.sealed_dispatch_entered
            session = cli_adapter.take_session() if dispatch_attempted else None
            sealed_meta = (
                _sealed_meta_from_ack(operation, session.ack)
                if session is not None
                else None
            )
            raise FailSafeHardwareError(
                "fail-safe sealed CLI dispatch failed",
                error_code=_executor_dispatch_error_code(exc, session),
                failure_stage="sealed_cli_dispatch" if dispatch_attempted else None,
                dispatch_attempted=dispatch_attempted,
                sealed_meta=sealed_meta,
            ) from exc

        if not exec_result.passed:
            session = cli_adapter.take_session()
            sealed_meta = (
                _sealed_meta_from_ack(operation, session.ack)
                if session is not None
                else None
            )
            raise FailSafeHardwareError(
                "fail-safe executor rejected sealed CLI dispatch",
                error_code=_codec_error_code(exec_result.error),
                failure_stage="sealed_cli_dispatch",
                dispatch_attempted=True,
                sealed_meta=sealed_meta,
            )

        session = cli_adapter.take_session()
        if session is None:
            raise FailSafeHardwareError(
                "sealed CLI session missing after executor dispatch",
                error_code="fail_safe_hardware_error",
                failure_stage="sealed_cli_dispatch",
                dispatch_attempted=True,
            )
        ack: FailSafeExecAck = session.ack
        sealed_meta = _sealed_meta_from_ack(operation, ack)
        if ack.exit_status != 0:
            raise FailSafeHardwareError(
                "fail-safe command exited with non-zero status",
                error_code="cli_non_zero_exit",
                failure_stage="sealed_cli_dispatch",
                dispatch_attempted=True,
                sealed_meta=sealed_meta,
            )
        if not ack.ack_matched:
            raise FailSafeHardwareError(
                "fail-safe sealed CLI ack not matched",
                error_code="cli_ack_unverified",
                failure_stage="sealed_cli_dispatch",
                dispatch_attempted=True,
                sealed_meta=sealed_meta,
            )
        result = FailSafeExecutionResult(
            operation=operation,
            timer_seconds=FAIL_SAFE_TIMER_SECONDS,
            ack_matched=ack.ack_matched,
            dispatch_path="ssh_exec_diagnostic",
            exit_status=ack.exit_status,
            stdout_sha256=ack.stdout_sha256,
            stderr_sha256=ack.stderr_sha256,
            stdout_byte_count=ack.stdout_byte_count,
            stderr_byte_count=ack.stderr_byte_count,
        )
        return result, session


def assert_no_raw_fail_safe_command_api(module_globals: dict[str, Any]) -> None:
    forbidden = (
        "exec_command",
        "run_command",
        "execute_command",
        "send_cli",
        "rci_exec",
    )
    for name in forbidden:
        if name in module_globals and callable(module_globals[name]):
            raise FailSafeHardwareError(f"raw command API forbidden: {name}")


assert_no_raw_fail_safe_command_api(globals())


__all__ = [
    "ALLOWLISTED_FAIL_SAFE_OPERATIONS",
    "FAIL_SAFE_TIMER_SECONDS",
    "FailSafeExecutionResult",
    "FailSafeHardwareBoundary",
    "FailSafeHardwareError",
    "FailSafeOperationForbidden",
    "FailSafeTransportRequired",
    "FailSafeTypedOperation",
]
