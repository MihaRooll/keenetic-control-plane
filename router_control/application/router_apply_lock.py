"""Per-router mutual exclusion for WireGuard apply/teardown/activate/watchdog paths."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import TypeVar

_T = TypeVar("_T")

_lock_guard = threading.Lock()
_router_locks: dict[str, threading.Lock] = {}


def resolve_router_apply_lock_key(
    router_id: str | None,
    *,
    live_host: str | None = None,
    ssh_host_key_sha256: str | None = None,
    source_address: str | None = None,
) -> str:
    """Stable lock key: enrolled router_id, else live connection identity, else offline default."""
    if router_id is not None and router_id.strip():
        return router_id.strip()
    identity_parts = [
        live_host.strip() if live_host and live_host.strip() else "",
        ssh_host_key_sha256.strip() if ssh_host_key_sha256 and ssh_host_key_sha256.strip() else "",
        source_address.strip() if source_address and source_address.strip() else "",
    ]
    if any(identity_parts):
        digest = hashlib.sha256("|".join(identity_parts).encode()).hexdigest()[:16]
        return f"live:{digest}"
    return "__default__"


def _lock_for_router(lock_key: str) -> threading.Lock:
    key = lock_key.strip() or "__default__"
    with _lock_guard:
        lock = _router_locks.get(key)
        if lock is None:
            lock = threading.Lock()
            _router_locks[key] = lock
        return lock


@contextmanager
def router_apply_lock(lock_key: str | None) -> Iterator[None]:
    """Serialize apply/teardown/activate/watchdog for one router."""
    lock = _lock_for_router(lock_key or "__default__")
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def run_with_router_apply_lock(
    lock_key: str | None,
    fn: Callable[[], _T],
) -> _T:
    with router_apply_lock(lock_key):
        return fn()


__all__ = [
    "resolve_router_apply_lock_key",
    "router_apply_lock",
    "run_with_router_apply_lock",
]
