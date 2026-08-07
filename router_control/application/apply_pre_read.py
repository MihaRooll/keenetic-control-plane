"""Bounded pre-apply baseline reads for apply services."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TypeVar

# Matches NetcrazeTransport.read_timeout default (router_control/adapters/netcraze/transport.py).
_DEFAULT_PRE_APPLY_READ_TIMEOUT_SECONDS = 15.0

T = TypeVar("T")

_PRE_APPLY_READ_KEY_ATTR = "_pre_apply_read_identity"
_identity_fallback: dict[int, object] = {}
_inflight_by_identity: dict[int, int] = {}
_state_guard = threading.Lock()
_transport_io_locks: dict[int, threading.RLock] = {}
_active_pre_read_workers = 0
_active_pre_read_workers_lock = threading.Lock()


def _transport_identity(transport: object) -> object:
    identity = getattr(transport, _PRE_APPLY_READ_KEY_ATTR, None)
    if identity is not None:
        return identity
    identity = object()
    try:
        setattr(transport, _PRE_APPLY_READ_KEY_ATTR, identity)
    except (AttributeError, TypeError):
        _identity_fallback[id(transport)] = identity
    return identity


def _transport_io_lock(transport: object) -> threading.RLock:
    key = id(_transport_identity(transport))
    with _state_guard:
        lock = _transport_io_locks.get(key)
        if lock is None:
            lock = threading.RLock()
            _transport_io_locks[key] = lock
        return lock


def _inflight_count(transport: object) -> int:
    key = id(_transport_identity(transport))
    with _state_guard:
        return _inflight_by_identity.get(key, 0)


def _adjust_inflight(transport: object, delta: int) -> None:
    key = id(_transport_identity(transport))
    with _state_guard:
        count = _inflight_by_identity.get(key, 0) + delta
        if count <= 0:
            _inflight_by_identity.pop(key, None)
        else:
            _inflight_by_identity[key] = count


def active_pre_apply_read_worker_count() -> int:
    """Test hook: in-flight pre-apply read worker threads."""
    with _active_pre_read_workers_lock:
        return _active_pre_read_workers


def pre_apply_read_timeout_seconds(transport: object) -> float:
    timeout = getattr(transport, "read_timeout", None)
    if timeout is None:
        return _DEFAULT_PRE_APPLY_READ_TIMEOUT_SECONDS
    try:
        value = float(timeout)
    except (TypeError, ValueError):
        return _DEFAULT_PRE_APPLY_READ_TIMEOUT_SECONDS
    return value if value > 0 else _DEFAULT_PRE_APPLY_READ_TIMEOUT_SECONDS


def transport_io_inflight(transport: object) -> bool:
    """True while a pre-apply read worker still holds the per-transport I/O lock."""
    return _inflight_count(transport) > 0


@contextmanager
def transport_io_guard(transport: object) -> Iterator[None]:
    """Serialize all transport I/O (reads and writes) on one session instance (F-4)."""
    lock = _transport_io_lock(transport)
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def execute_transport_io(transport: object, operation: Callable[[], T]) -> T:
    """Run transport I/O under the shared per-transport lock."""
    with transport_io_guard(transport):
        return operation()


def execute_pre_apply_read(
    transport: object,
    operation: Callable[[], T],
    *,
    timeout_seconds: float | None = None,
) -> T:
    """Run a baseline read with transport-aligned timeout; raise TimeoutError on expiry.

    On timeout the caller returns immediately (fail-closed for this read). The
    abandoned worker keeps the per-transport I/O lock until the underlying
    operation completes so a late response cannot race with subsequent writes on
    the same transport instance.
    """
    timeout = (
        timeout_seconds
        if timeout_seconds is not None
        else pre_apply_read_timeout_seconds(transport)
    )
    done = threading.Event()
    result_box: list[T] = []
    error_box: list[BaseException] = []
    io_lock = _transport_io_lock(transport)
    if _inflight_count(transport) > 0:
        raise TimeoutError(
            "pre-apply baseline read blocked: prior read still in flight on transport"
        )
    _adjust_inflight(transport, 1)

    def _worker() -> None:
        global _active_pre_read_workers
        with _active_pre_read_workers_lock:
            _active_pre_read_workers += 1
        io_lock.acquire()
        try:
            try:
                result_box.append(operation())
            except BaseException as exc:
                error_box.append(exc)
        finally:
            io_lock.release()
            done.set()
            with _active_pre_read_workers_lock:
                _active_pre_read_workers -= 1
            _adjust_inflight(transport, -1)

    thread = threading.Thread(target=_worker, name="pre-apply-read", daemon=True)
    thread.start()
    if done.wait(timeout=timeout):
        if error_box:
            raise error_box[0]
        return result_box[0]
    raise TimeoutError(
        f"pre-apply baseline read timed out after {timeout}s"
    )
