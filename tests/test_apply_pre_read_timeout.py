"""Pre-apply baseline read timeout and transport safety."""

from __future__ import annotations

import threading
import time

import pytest
from router_control.application.apply_pre_read import (
    active_pre_apply_read_worker_count,
    execute_pre_apply_read,
    execute_transport_io,
    transport_io_inflight,
)


class _TimeoutProbeTransport:
    """Minimal transport token for timeout tests (supports setattr identity)."""


def test_pre_apply_read_timeout_releases_caller_within_budget() -> None:
    hang_seconds = 0.5
    timeout_seconds = 0.3

    def _hang() -> str:
        time.sleep(hang_seconds)
        return "late"

    started = time.monotonic()
    with pytest.raises(TimeoutError, match="timed out"):
        execute_pre_apply_read(
            _TimeoutProbeTransport(), _hang, timeout_seconds=timeout_seconds
        )
    elapsed = time.monotonic() - started
    assert elapsed < timeout_seconds + 0.5
    time.sleep(hang_seconds + 0.1)


def test_pre_apply_read_repeated_timeouts_do_not_accumulate_workers() -> None:
    hang_seconds = 0.3
    timeout_seconds = 0.05
    transport = _TimeoutProbeTransport()

    with pytest.raises(TimeoutError, match="timed out"):
        execute_pre_apply_read(
            transport, lambda: time.sleep(hang_seconds), timeout_seconds=timeout_seconds
        )
    assert active_pre_apply_read_worker_count() == 1

    with pytest.raises(TimeoutError, match="blocked"):
        execute_pre_apply_read(
            transport, lambda: time.sleep(hang_seconds), timeout_seconds=timeout_seconds
        )
    assert active_pre_apply_read_worker_count() == 1

    time.sleep(hang_seconds + 0.2)
    assert active_pre_apply_read_worker_count() == 0


def test_f4_abandoned_pre_read_serializes_subsequent_transport_io() -> None:
    hang_seconds = 0.4
    timeout_seconds = 0.05
    transport = _TimeoutProbeTransport()
    write_started = threading.Event()
    write_completed = threading.Event()
    timed_out_at = {"mono": 0.0}
    write_started_at = {"mono": 0.0}

    def _hang_read() -> None:
        time.sleep(hang_seconds)

    with pytest.raises(TimeoutError, match="timed out"):
        execute_pre_apply_read(
            transport, _hang_read, timeout_seconds=timeout_seconds
        )
    timed_out_at["mono"] = time.monotonic()
    assert transport_io_inflight(transport)

    def _write_probe() -> str:
        write_started_at["mono"] = time.monotonic()
        write_started.set()
        return "write-ok"

    def _run_write() -> None:
        execute_transport_io(transport, _write_probe)
        write_completed.set()

    writer = threading.Thread(
        target=_run_write,
        name="transport-write-probe",
        daemon=True,
    )
    writer.start()
    assert write_started.wait(timeout=hang_seconds - 0.15) is False
    assert write_started.wait(timeout=1.0) is True
    assert write_started_at["mono"] - timed_out_at["mono"] >= hang_seconds - 0.15
    assert write_completed.wait(timeout=2.0)
    assert active_pre_apply_read_worker_count() == 0
