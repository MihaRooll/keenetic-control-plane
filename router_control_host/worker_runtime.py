"""Host lifespan worker runtime — starts/stops DurableWorker with FastAPI."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any

from router_control.application.worker import DurableWorker, WorkerConfig, WorkerLifecycle
from router_control.application.worker_handlers import build_default_registry
from router_control.composition import LiveRuntime, OfflineRuntime
from router_control.persistence.connection import connect
from router_control.persistence.store import PersistenceStore


@dataclass
class WorkerRuntimeHandle:
    worker: DurableWorker | None = None
    thread: threading.Thread | None = None
    lifecycle: WorkerLifecycle = WorkerLifecycle.STOPPED
    last_error_redacted: str | None = None
    last_heartbeat_at: str | None = None
    _started: bool = field(default=False, repr=False)

    def status_payload(self) -> dict[str, Any]:
        if self.worker is not None:
            lifecycle = self.worker.lifecycle
            last_err = self.worker.last_error_redacted or self.last_error_redacted
            heartbeat = self.worker.last_heartbeat_at or self.last_heartbeat_at
        else:
            lifecycle = self.lifecycle
            last_err = self.last_error_redacted
            heartbeat = self.last_heartbeat_at
        return {
            "worker_state": lifecycle.value,
            "worker_heartbeat_at": heartbeat,
            "worker_last_error": last_err,
        }


def build_worker_for_runtime(
    runtime: OfflineRuntime | LiveRuntime,
    *,
    adapter_mode: str,
    allow_fake_mutations: bool,
    worker_id: str = "host-worker",
) -> DurableWorker:
    registry = build_default_registry(
        commissioning=runtime.commissioning,
        event_presets=runtime.event_presets,
        adapter_mode=adapter_mode,
        allow_fake_mutations=allow_fake_mutations,
        mutation_executor=getattr(runtime, "mutation_executor", None)
        if allow_fake_mutations and adapter_mode == "fake"
        else None,
    )
    worker_store = PersistenceStore(connect(runtime.db_path))
    return DurableWorker(
        store=worker_store,
        clock=runtime.clock,
        handler_registry=registry,
        config=WorkerConfig(worker_id=worker_id),
    )


def start_worker_runtime(
    runtime: OfflineRuntime | LiveRuntime,
    *,
    adapter_mode: str,
    allow_fake_mutations: bool,
) -> WorkerRuntimeHandle:
    handle = WorkerRuntimeHandle()
    try:
        worker = build_worker_for_runtime(
            runtime,
            adapter_mode=adapter_mode,
            allow_fake_mutations=allow_fake_mutations,
        )
        worker.start()
        handle.worker = worker
        handle.lifecycle = worker.lifecycle
        handle._started = True
    except Exception as exc:
        handle.lifecycle = WorkerLifecycle.DEGRADED
        handle.last_error_redacted = f"{type(exc).__name__}: worker start failed"
    return handle


def stop_worker_runtime(handle: WorkerRuntimeHandle | None) -> None:
    if handle is None or handle.worker is None:
        return
    try:
        handle.worker.stop()
        handle.lifecycle = handle.worker.lifecycle
        handle.last_error_redacted = handle.worker.last_error_redacted
        handle.last_heartbeat_at = handle.worker.last_heartbeat_at
    except Exception as exc:
        handle.lifecycle = WorkerLifecycle.DEGRADED
        handle.last_error_redacted = f"{type(exc).__name__}: worker stop failed"
