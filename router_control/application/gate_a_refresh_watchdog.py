"""Background reload of Gate A certification from disk — keeps a long-running
host process's in-memory certification object in sync with an externally
refreshed evidence pointer (see scripts/recertify-gate-a-freshness.py), without
requiring a process restart. Read-only local file reload only — no network,
no device access, no mutation of anything. Never weakens the fail-closed
invariant: a transient reload failure or malformed file simply leaves the
last-known-good certification object in place; it never nulls it out or
fabricates a value.
"""

from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from router_control.adapters.netcraze.certification import (
    GateACertification,
    try_load_gate_a_certification,
)

GATE_A_REFRESH_WATCHDOG_ENABLED = os.environ.get(
    "GATE_A_REFRESH_WATCHDOG_ENABLED", "1"
).strip().lower() not in ("0", "false", "no")
GATE_A_REFRESH_POLL_SECONDS = max(
    30.0,
    float(os.environ.get("GATE_A_REFRESH_POLL_SECONDS", "120") or "120"),
)

GateACertLoader = Callable[[], GateACertification | None]


class WatchdogHost(Protocol):
    gate_a_certification: GateACertification | None


@dataclass
class GateARefreshWatchdogHandle:
    host: WatchdogHost
    loader: GateACertLoader = field(default=try_load_gate_a_certification)
    poll_seconds: float = GATE_A_REFRESH_POLL_SECONDS
    _task: asyncio.Task[None] | None = field(default=None, init=False)
    _stop: asyncio.Event = field(default_factory=asyncio.Event, init=False)

    def status_payload(self) -> dict[str, Any]:
        running = self._task is not None and not self._task.done()
        return {
            "gate_a_refresh_watchdog_enabled": GATE_A_REFRESH_WATCHDOG_ENABLED,
            "gate_a_refresh_watchdog_poll_seconds": self.poll_seconds,
            "gate_a_refresh_watchdog_running": running,
        }

    def start(self) -> None:
        if not GATE_A_REFRESH_WATCHDOG_ENABLED:
            return
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run_loop(), name="gate-a-refresh-watchdog")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                pass
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=self.poll_seconds)
                break
            except TimeoutError:
                continue

    async def _poll_once(self) -> None:
        try:
            new_cert = await asyncio.to_thread(self.loader)
        except Exception:
            return
        if new_cert is not None:
            self.host.gate_a_certification = new_cert


__all__ = [
    "GATE_A_REFRESH_WATCHDOG_ENABLED",
    "GATE_A_REFRESH_POLL_SECONDS",
    "GateARefreshWatchdogHandle",
]
