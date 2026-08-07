"""Portable durable worker runtime — no FastAPI/vendor imports."""

from __future__ import annotations

import hashlib
import logging
import os
import sys
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol

from router_control.application.recovery import classify_job_steps
from router_control.application.worker_handlers import (
    HandlerRegistry,
    HandlerResult,
    safe_handler_call,
)
from router_control.domain.enums import WorkerInstanceLifecycle
from router_control.domain.errors import LeaseLostError, MutationForbidden, WorkerJobRejected
from router_control.persistence.errors import FenceExpiredError, StaleFenceError
from router_control.persistence.store import ClaimResult, PersistenceStore
from router_control.ports.clock import ClockPort

_LOGGER = logging.getLogger(__name__)


class WorkerLifecycle(StrEnum):
    STOPPED = "Stopped"
    STARTING = "Starting"
    RUNNING = "Running"
    STOPPING = "Stopping"
    DEGRADED = "Degraded"


class SleeperPort(Protocol):
    def sleep(self, seconds: float) -> None: ...


class ThreadSleeper:
    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


def _router_mutex_fingerprint(router_id: str) -> str:
    return hashlib.sha256(router_id.encode("utf-8")).hexdigest()[:16]


@contextmanager
def router_process_mutex(router_id: str) -> Iterator[None]:
    """Per-router process mutex — Windows named mutex; fallback threading lock."""
    fp = _router_mutex_fingerprint(router_id)
    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        name = f"Local\\router_control_router_mutex_{fp}"
        handle = kernel32.CreateMutexW(None, False, name)
        if not handle:
            raise RuntimeError("CreateMutexW failed for router process mutex")
        wait = kernel32.WaitForSingleObject(handle, wintypes.DWORD(30_000))
        if wait != 0:
            kernel32.CloseHandle(handle)
            raise RuntimeError("router process mutex wait failed")
        try:
            yield
        finally:
            kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
    else:
        lock = _ROUTER_PROCESS_LOCKS.setdefault(fp, threading.Lock())
        lock.acquire()
        try:
            yield
        finally:
            lock.release()


_ROUTER_PROCESS_LOCKS: dict[str, threading.Lock] = {}


def new_boot_id() -> str:
    return uuid.uuid4().hex


def worker_instance_id(process_id: int, boot_id: str) -> str:
    digest = hashlib.sha256(f"{process_id}:{boot_id}".encode()).hexdigest()[:24]
    return f"worker-{digest}"


def _is_sqlite_busy_error(exc: BaseException) -> bool:
    if type(exc).__module__ != "sqlite3" or type(exc).__name__ != "OperationalError":
        return False
    message = str(exc).lower()
    return "locked" in message or "busy" in message


@dataclass(slots=True)
class WorkerConfig:
    worker_id: str = "worker-default"
    boot_id: str = field(default_factory=new_boot_id)
    process_id: int = field(default_factory=os.getpid)
    lease_seconds: int = 30
    poll_interval_seconds: float = 0.25
    max_backoff_seconds: float = 2.0
    stop_timeout_seconds: float = 10.0

    @property
    def worker_instance_id(self) -> str:
        return worker_instance_id(self.process_id, self.boot_id)


@dataclass
class ActiveHandlerContext:
    job_id: str
    operation_id: str
    operation_kind: str
    router_id: str
    correlation_id: str | None
    lease_owner: str
    fencing_token: int
    store: PersistenceStore
    clock: ClockPort
    sleeper: SleeperPort
    _lease_lost: threading.Event = field(default_factory=threading.Event)
    _heartbeat_stop: threading.Event = field(default_factory=threading.Event)

    def ensure_lease(self) -> None:
        if self._lease_lost.is_set():
            raise LeaseLostError("lease lost; aborting handler progress")

    def is_cancel_requested(self) -> bool:
        job = self.store.get_job(self.job_id)
        return bool(job and int(job["cancel_requested"]))

    def sleeper_sleep(self, seconds: float) -> None:
        self.sleeper.sleep(seconds)


@dataclass
class DurableWorker:
    store: PersistenceStore
    clock: ClockPort
    handler_registry: HandlerRegistry
    config: WorkerConfig = field(default_factory=WorkerConfig)
    sleeper: SleeperPort = field(default_factory=ThreadSleeper)

    _lifecycle: WorkerLifecycle = field(default=WorkerLifecycle.STOPPED, init=False)
    _thread: threading.Thread | None = field(default=None, init=False)
    _stop_event: threading.Event = field(default_factory=threading.Event, init=False)
    _heartbeat_thread: threading.Thread | None = field(default=None, init=False)
    _last_error_redacted: str | None = field(default=None, init=False)
    _last_heartbeat_at: str | None = field(default=None, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    _active_handler: threading.Thread | None = field(default=None, init=False)
    _mutation_thread_active: threading.Event = field(
        default_factory=threading.Event, init=False
    )

    @property
    def lifecycle(self) -> WorkerLifecycle:
        return self._lifecycle

    @property
    def last_error_redacted(self) -> str | None:
        return self._last_error_redacted

    @property
    def last_heartbeat_at(self) -> str | None:
        return self._last_heartbeat_at

    def start(self) -> None:
        with self._lock:
            if self._lifecycle in (WorkerLifecycle.RUNNING, WorkerLifecycle.STARTING):
                return
            self._lifecycle = WorkerLifecycle.STARTING
            self._stop_event.clear()
            try:
                self.store.register_worker_instance(
                    worker_instance_id=self.config.worker_instance_id,
                    process_id=self.config.process_id,
                    boot_id=self.config.boot_id,
                    hostname=None,
                    lifecycle_status=WorkerInstanceLifecycle.STARTING.value,
                    started_at_epoch=int(self.clock.now().timestamp()),
                    now=self.clock.now(),
                )
            except Exception as exc:
                # Best-effort: worker may start before persistence is ready; do not block boot.
                _LOGGER.warning(
                    "worker lifecycle persistence failed (register_worker_instance): %s",
                    type(exc).__name__,
                )
            self._thread = threading.Thread(
                target=self._run_loop,
                name=f"durable-worker-{self.config.worker_id}",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float | None = None) -> None:
        timeout = timeout if timeout is not None else self.config.stop_timeout_seconds
        with self._lock:
            if self._lifecycle == WorkerLifecycle.STOPPED:
                return
            self._lifecycle = WorkerLifecycle.STOPPING
        self._stop_event.set()
        self._stop_heartbeat()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=timeout)
        handler = self._active_handler
        if handler is not None and handler.is_alive():
            handler.join(timeout=timeout)
        with self._lock:
            if self._mutation_thread_active.is_set():
                self._lifecycle = WorkerLifecycle.DEGRADED
            else:
                self._lifecycle = WorkerLifecycle.STOPPED
            self._thread = None
            self._active_handler = None
        try:
            self.store.update_worker_instance_lifecycle(
                self.config.worker_instance_id,
                lifecycle_status=self._lifecycle.value,
                stopped_at_epoch=int(self.clock.now().timestamp()),
                now=self.clock.now(),
            )
        except Exception as exc:
            # Best-effort shutdown persistence; worker thread already stopped.
            _LOGGER.warning(
                "worker lifecycle persistence failed (stop update): %s",
                type(exc).__name__,
            )

    def _run_loop(self) -> None:
        backoff = self.config.poll_interval_seconds
        try:
            self.store.recover_expired_leases()
            self.store.reap_expired_router_execution_fences()
            with self._lock:
                self._lifecycle = WorkerLifecycle.RUNNING
            try:
                self.store.update_worker_instance_lifecycle(
                    self.config.worker_instance_id,
                    lifecycle_status=WorkerInstanceLifecycle.RUNNING.value,
                    now=self.clock.now(),
                )
            except Exception as exc:
                # Best-effort RUNNING transition; loop continues with in-memory lifecycle.
                _LOGGER.warning(
                    "worker lifecycle persistence failed (run_loop running): %s",
                    type(exc).__name__,
                )
            while not self._stop_event.is_set():
                try:
                    processed = self._poll_once()
                    backoff = self.config.poll_interval_seconds if processed else min(
                        backoff * 1.5, self.config.max_backoff_seconds
                    )
                except Exception as exc:
                    self._last_error_redacted = f"{type(exc).__name__}: worker loop error"
                    with self._lock:
                        self._lifecycle = WorkerLifecycle.DEGRADED
                    backoff = self.config.max_backoff_seconds
                if self._stop_event.wait(backoff):
                    break
        except Exception as exc:
            self._last_error_redacted = f"{type(exc).__name__}: worker fatal"
            with self._lock:
                self._lifecycle = WorkerLifecycle.DEGRADED
        finally:
            self._stop_heartbeat()
            if not self._stop_event.is_set():
                with self._lock:
                    if self._lifecycle == WorkerLifecycle.RUNNING:
                        self._lifecycle = WorkerLifecycle.STOPPED

    def _poll_once(self) -> bool:
        claim = self.store.claim_job(
            worker_id=self.config.worker_id,
            lease_seconds=self.config.lease_seconds,
        )
        if claim is None:
            return False
        self._process_claim(claim)
        return True

    def _process_claim(self, claim: ClaimResult) -> None:
        job = self.store.get_job(claim.job_id)
        if job is None:
            return
        op = self.store.get_operation(str(job["operation_id"]))
        if op is None:
            return
        operation_kind = str(op["operation_kind"])
        correlation_id = str(op["correlation_id"]) if op["correlation_id"] else None
        router_id = str(job["router_id"])
        operation_id = str(job["operation_id"])

        def _run() -> None:
            self._mutation_thread_active.set()
            try:
                with router_process_mutex(router_id):
                    self.store.acquire_router_execution_fence(
                        router_id=router_id,
                        lease_owner=self.config.worker_id,
                        mutex_holder_id=self.config.worker_instance_id,
                        lease_seconds=self.config.lease_seconds,
                        active_job_id=claim.job_id,
                        os_mutex_held=True,
                    )
                    self._process_claim_locked(
                        claim,
                        job=job,
                        operation_kind=operation_kind,
                        correlation_id=correlation_id,
                        router_id=router_id,
                        operation_id=operation_id,
                    )
            except Exception as exc:
                self._last_error_redacted = f"{type(exc).__name__}: handler thread error"
                with self._lock:
                    self._lifecycle = WorkerLifecycle.DEGRADED
            finally:
                self._mutation_thread_active.clear()

        handler_thread = threading.Thread(
            target=_run,
            name=f"handler-{claim.job_id}",
            daemon=True,
        )
        with self._lock:
            self._active_handler = handler_thread
        handler_thread.start()
        handler_thread.join()
        with self._lock:
            self._active_handler = None

    def _process_claim_locked(
        self,
        claim: ClaimResult,
        *,
        job: Any,
        operation_kind: str,
        correlation_id: str | None,
        router_id: str,
        operation_id: str,
    ) -> None:
        self.store.append_audit(
            action="worker.claim",
            outcome="accepted",
            router_id=router_id,
            operation_id=operation_id,
            job_id=claim.job_id,
            summary_redacted=f"operation_kind={operation_kind}",
            correlation_id=correlation_id,
            now=self.clock.now(),
        )

        ctx = ActiveHandlerContext(
            job_id=claim.job_id,
            operation_id=operation_id,
            operation_kind=operation_kind,
            router_id=router_id,
            correlation_id=correlation_id,
            lease_owner=claim.lease_owner,
            fencing_token=claim.fencing_token,
            store=self.store,
            clock=self.clock,
            sleeper=self.sleeper,
        )

        try:
            handler = self.handler_registry.get_or_reject(operation_kind)
        except (WorkerJobRejected, MutationForbidden, Exception) as exc:
            self._fail_job(
                ctx,
                summary=f"rejected: {type(exc).__name__}",
                http_status=403,
                body={"error": type(exc).__name__, "message": str(exc)[:120]},
            )
            return

        try:
            self.store.record_job_progress(
                job_id=claim.job_id,
                lease_owner=claim.lease_owner,
                fencing_token=claim.fencing_token,
                status="Running",
                step_kind="dispatch",
                step_status="Running",
            )
        except StaleFenceError:
            return

        self.store.append_audit(
            action="worker.start",
            outcome="running",
            router_id=router_id,
            operation_id=operation_id,
            job_id=claim.job_id,
            summary_redacted=f"handler dispatch operation_kind={operation_kind}",
            correlation_id=correlation_id,
            now=self.clock.now(),
        )

        self._start_heartbeat(ctx, claim)
        try:
            result = safe_handler_call(handler, ctx, self.store)
        finally:
            self._stop_heartbeat(ctx)

        if ctx._lease_lost.is_set():
            return

        if ctx.is_cancel_requested() and result.status != "RecoveryRequired":
            if result.status == "Cancelled":
                self._finalize_cancel(ctx)
                return
            if result.status == "Succeeded":
                self._complete_from_result(ctx, result)
                return
            cls = classify_job_steps(self.store, ctx.job_id, job_status="Running")
            if cls.apply_dispatched:
                self._complete_from_result(
                    ctx,
                    HandlerResult(
                        status="RecoveryRequired",
                        summary_redacted=(
                            "cancel after partial apply requires verify/compensate"
                        ),
                        http_status=422,
                        response_body={
                            "operation_id": ctx.operation_id,
                            "job_id": ctx.job_id,
                            "status": "RecoveryRequired",
                        },
                    ),
                )
                return
            self._finalize_cancel(ctx)
            return

        self._complete_from_result(ctx, result)

    def _start_heartbeat(self, ctx: ActiveHandlerContext, claim: ClaimResult) -> None:
        ctx._heartbeat_stop.clear()
        interval = max(1, self.config.lease_seconds // 3)

        def _beat() -> None:
            while not ctx._heartbeat_stop.is_set():
                self.sleeper.sleep(interval)
                if ctx._heartbeat_stop.is_set():
                    break
                try:
                    fence = self.store.get_router_execution_fence(ctx.router_id)
                    if (
                        fence is not None
                        and fence["lease_owner"] == claim.lease_owner
                        and fence["mutex_holder_id"] == self.config.worker_instance_id
                    ):
                        self.store.renew_router_execution_fence(
                            router_id=ctx.router_id,
                            lease_owner=claim.lease_owner,
                            mutex_holder_id=self.config.worker_instance_id,
                            fence_token=int(fence["fence_token"]),
                            lease_seconds=self.config.lease_seconds,
                        )
                    self.store.renew_lease(
                        job_id=claim.job_id,
                        lease_owner=claim.lease_owner,
                        fencing_token=claim.fencing_token,
                        lease_seconds=self.config.lease_seconds,
                    )
                    self._last_heartbeat_at = self.clock.now().strftime("%Y-%m-%dT%H:%M:%SZ")
                except (StaleFenceError, FenceExpiredError):
                    ctx._lease_lost.set()
                    break
                except Exception as exc:
                    if not _is_sqlite_busy_error(exc):
                        raise

        self._heartbeat_thread = threading.Thread(
            target=_beat,
            name=f"heartbeat-{claim.job_id}",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def _stop_heartbeat(self, ctx: ActiveHandlerContext | None = None) -> None:
        if ctx is not None:
            ctx._heartbeat_stop.set()
            if self._heartbeat_thread is not None and self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=2.0)
            self._heartbeat_thread = None
        elif self._heartbeat_thread is not None:
            if self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=1.0)
            self._heartbeat_thread = None

    def _complete_from_result(self, ctx: ActiveHandlerContext, result: HandlerResult) -> None:
        try:
            self.store.record_job_progress(
                job_id=ctx.job_id,
                lease_owner=ctx.lease_owner,
                fencing_token=ctx.fencing_token,
                step_kind="handler",
                step_status=result.status,
                checkpoint_json=result.summary_redacted[:500],
            )
        except StaleFenceError:
            return

        http_status = result.http_status
        if result.status == "Succeeded" and http_status is None:
            http_status = 200
        if result.status in ("Failed", "RecoveryRequired") and http_status is None:
            http_status = 422

        try:
            self.store.complete_job(
                job_id=ctx.job_id,
                lease_owner=ctx.lease_owner,
                fencing_token=ctx.fencing_token,
                status=result.status,
                summary_redacted=result.summary_redacted,
                http_status=http_status,
                response_body=result.response_body,
                correlation_id=ctx.correlation_id,
                aggregate_status=getattr(result, "aggregate_status", None),
            )
        except StaleFenceError:
            return
        except Exception as exc:
            if _is_sqlite_busy_error(exc) or (
                type(exc).__module__ == "sqlite3"
                and type(exc).__name__ == "OperationalError"
            ):
                self._last_error_redacted = f"{type(exc).__name__}: complete_job persistence fault"
                with self._lock:
                    self._lifecycle = WorkerLifecycle.DEGRADED
                return
            raise

        audit_action = "worker.success"
        if result.status == "Failed":
            audit_action = "worker.failure"
        elif result.status == "RecoveryRequired":
            audit_action = "worker.recovery_required"

        self.store.append_audit(
            action=audit_action,
            outcome=result.status.lower(),
            router_id=ctx.router_id,
            operation_id=ctx.operation_id,
            job_id=ctx.job_id,
            summary_redacted=result.summary_redacted,
            correlation_id=ctx.correlation_id,
            now=self.clock.now(),
        )

    def _fail_job(
        self,
        ctx: ActiveHandlerContext,
        *,
        summary: str,
        http_status: int,
        body: dict[str, Any],
    ) -> None:
        try:
            self.store.complete_job(
                job_id=ctx.job_id,
                lease_owner=ctx.lease_owner,
                fencing_token=ctx.fencing_token,
                status="Failed",
                summary_redacted=summary,
                http_status=http_status,
                response_body=body,
                correlation_id=ctx.correlation_id,
            )
        except StaleFenceError:
            pass

    def _finalize_cancel(self, ctx: ActiveHandlerContext) -> None:
        try:
            self.store.mark_target_job_cancelled(target_job_id=ctx.job_id, now=self.clock.now())
        except Exception as exc:
            # Cancel audit must still append even when finalize persistence fails.
            _LOGGER.warning(
                "mark_target_job_cancelled failed job=%s: %s",
                ctx.job_id,
                type(exc).__name__,
            )
        self.store.append_audit(
            action="worker.cancel",
            outcome="cancelled",
            router_id=ctx.router_id,
            operation_id=ctx.operation_id,
            job_id=ctx.job_id,
            summary_redacted="cancelled at safe boundary",
            correlation_id=ctx.correlation_id,
            now=self.clock.now(),
        )
