"""CommissioningService — read-only readiness assessment; zero router writes."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from router_control.domain.commissioning import (
    CheckKind,
    CheckOutcome,
    CommissioningMode,
    CommissioningState,
    etag_token,
)
from router_control.domain.errors import (
    CommissioningCancelled,
    CommissioningConflict,
    CommissioningNotFound,
    CommissioningPreconditionFailed,
)
from router_control.persistence.errors import (
    ConflictError,
    IdempotencyConflict,
    NotFoundError,
    PreconditionFailed,
)
from router_control.persistence.store import (
    CommissioningAssessReservation,
    PersistenceStore,
    _utc_now_iso,
)
from router_control.ports.clock import ClockPort


class ReadOnlyProbeFn(Protocol):
    def __call__(self, *, router_id: str) -> dict[str, Any]: ...


@dataclass
class CommissioningService:
    store: PersistenceStore
    clock: ClockPort
    probe_fn: ReadOnlyProbeFn | None = None
    gate_a_open: Callable[[], bool] = field(default=lambda: False)
    matches_probe_evidence: Callable[[dict[str, Any]], bool] = field(
        default=lambda _evidence: False
    )
    gate_b_not_write_certified: Callable[[], bool] = field(default=lambda: True)
    gate_c_closed: Callable[[], bool] = field(default=lambda: True)
    gate_d_closed: Callable[[], bool] = field(default=lambda: True)

    def create_run(
        self,
        *,
        site_id: str,
        router_id: str,
        mode: str,
        idempotency_key: str,
        request_digest: str,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        if mode not in (CommissioningMode.FAKE.value, CommissioningMode.LIVE.value):
            raise CommissioningPreconditionFailed("mode must be fake or live")
        try:
            run_dict, created = self.store.create_commissioning_run(
                site_id=site_id,
                router_id=router_id,
                mode=mode,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=self.clock.now(),
            )
        except NotFoundError as exc:
            raise CommissioningNotFound(str(exc)) from exc
        except PreconditionFailed as exc:
            raise CommissioningPreconditionFailed(str(exc)) from exc
        except IdempotencyConflict as exc:
            raise CommissioningConflict(str(exc)) from exc
        return self._public_run(run_dict), created

    def get_run(self, run_id: str) -> dict[str, Any]:
        row = self.store.get_commissioning_run(run_id)
        if row is None:
            raise CommissioningNotFound("commissioning run not found")
        return self._public_run(self.store._row_to_commissioning_run(row))

    def list_runs_for_site(self, site_id: str) -> list[dict[str, Any]]:
        if self.store.get_site(site_id) is None:
            raise CommissioningNotFound("site not found")
        return [
            self._public_run(self.store._row_to_commissioning_run(row))
            for row in self.store.list_commissioning_runs_for_site(site_id)
        ]

    def list_checks(self, run_id: str) -> list[dict[str, Any]]:
        if self.store.get_commissioning_run(run_id) is None:
            raise CommissioningNotFound("commissioning run not found")
        return [self._public_check(row) for row in self.store.list_readiness_checks(run_id)]

    def build_report(self, run_id: str) -> dict[str, Any]:
        run = self.get_run(run_id)
        checks = self.list_checks(run_id)
        write_blockers = [
            {
                "check_kind": c["check_kind"],
                "outcome": c["outcome"],
                "summary_redacted": c["summary_redacted"],
            }
            for c in checks
            if c["write_related"] and c["outcome"] != CheckOutcome.PASSED.value
        ]
        ro_blocking = [
            c
            for c in checks
            if c["blocking"]
            and not c["write_related"]
            and c["outcome"] != CheckOutcome.PASSED.value
        ]
        return {
            "run_id": run["run_id"],
            "state": run["state"],
            "read_only_ready": run["state"] == CommissioningState.READY_READ_ONLY.value,
            "write_ready": False,
            "write_blockers": write_blockers,
            "read_only_blockers": [
                {
                    "check_kind": c["check_kind"],
                    "outcome": c["outcome"],
                    "summary_redacted": c["summary_redacted"],
                }
                for c in ro_blocking
            ],
            "summary_redacted": run.get("summary_redacted"),
            "report_digest": run.get("report_digest"),
            "never_commissioned": True,
            "never_write_certified": True,
        }

    def assess_run(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        try:
            prepared = self.store.prepare_commissioning_assess(
                run_id=run_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expected_version=expected_version,
                now=self.clock.now(),
            )
        except NotFoundError as exc:
            raise CommissioningNotFound(str(exc)) from exc
        except PreconditionFailed as exc:
            raise CommissioningPreconditionFailed(str(exc)) from exc
        except ConflictError as exc:
            if str(exc) == "run cancelled":
                raise CommissioningCancelled(str(exc)) from exc
            raise CommissioningConflict(str(exc)) from exc
        except IdempotencyConflict as exc:
            raise CommissioningConflict(str(exc)) from exc

        if prepared.replay is not None:
            run_dict, checks, created = prepared.replay
            return self._public_run(run_dict), [self._public_check_dict(c) for c in checks], created

        reservation = prepared.reservation
        assert reservation is not None
        now = self.clock.now()
        try:
            terminal, summary, report_digest, assessed_at, checks = self._compute_assess(
                reservation
            )
        except Exception as exc:
            return self._fail_assess_reservation(
                reservation,
                error=exc,
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=now,
            )

        try:
            run_dict, persisted, created = self.store.finalize_commissioning_assess(
                reservation,
                terminal_state=terminal.value,
                summary_redacted=summary,
                report_digest=report_digest,
                assessed_at=assessed_at,
                checks=checks,
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=now,
            )
        except (NotFoundError, PreconditionFailed, ConflictError, IdempotencyConflict) as exc:
            raise self._map_assess_store_error(exc) from exc
        except Exception as exc:
            return self._fail_assess_reservation(
                reservation,
                error=exc,
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=now,
            )
        return (
            self._public_run(run_dict),
            [self._public_check_dict(c) for c in persisted],
            created,
        )

    def _fail_assess_reservation(
        self,
        reservation: CommissioningAssessReservation,
        *,
        error: Exception,
        correlation_id: str | None,
        actor_id: str | None,
        now: Any,
    ) -> tuple[dict[str, Any], list[dict[str, Any]], bool]:
        fail_checks = [
            {
                "check_kind": CheckKind.GATE_A_OPEN.value,
                "ordinal": 0,
                "attempt": 1,
                "outcome": CheckOutcome.FAILED.value,
                "blocking": True,
                "write_related": False,
                "summary_redacted": f"assess error: {type(error).__name__}",
                "evidence_digest": None,
            }
        ]
        ts = _utc_now_iso(now)
        fail_digest = "sha256:" + hashlib.sha256(
            json.dumps(
                {"checks": fail_checks, "state": CommissioningState.FAILED.value},
                sort_keys=True,
            ).encode()
        ).hexdigest()
        try:
            run_dict, persisted, created = self.store.fail_commissioning_assess(
                reservation,
                summary_redacted="read-only assessment failed",
                report_digest=fail_digest,
                assessed_at=ts,
                checks=fail_checks,
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=now,
            )
        except (NotFoundError, PreconditionFailed, ConflictError, IdempotencyConflict) as exc:
            raise self._map_assess_store_error(exc) from exc
        return (
            self._public_run(run_dict),
            [self._public_check_dict(c) for c in persisted],
            created,
        )

    @staticmethod
    def _map_assess_store_error(exc: Exception) -> Exception:
        if isinstance(exc, NotFoundError):
            return CommissioningNotFound(str(exc))
        if isinstance(exc, PreconditionFailed):
            return CommissioningPreconditionFailed(str(exc))
        if isinstance(exc, ConflictError):
            if str(exc) == "run cancelled":
                return CommissioningCancelled(str(exc))
            return CommissioningConflict(str(exc))
        if isinstance(exc, IdempotencyConflict):
            return CommissioningConflict(str(exc))
        return exc

    def cancel_run(
        self,
        *,
        run_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> tuple[dict[str, Any], bool]:
        try:
            run_dict, created = self.store.cancel_commissioning_run_idempotent(
                run_id=run_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                expected_version=expected_version,
                correlation_id=correlation_id,
                actor_id=actor_id,
                now=self.clock.now(),
            )
        except NotFoundError as exc:
            raise CommissioningNotFound(str(exc)) from exc
        except PreconditionFailed as exc:
            raise CommissioningPreconditionFailed(str(exc)) from exc
        except ConflictError as exc:
            raise CommissioningConflict(str(exc)) from exc
        except IdempotencyConflict as exc:
            raise CommissioningConflict(str(exc)) from exc
        return self._public_run(run_dict), created

    def _compute_assess(
        self, reservation: CommissioningAssessReservation
    ) -> tuple[CommissioningState, str, str, str, list[dict[str, Any]]]:
        """Pure in-memory assess; probe/network only here, never under store txn."""
        mode = reservation.mode
        router_id = reservation.router_id
        site_id = reservation.site_id
        now = self.clock.now()
        ts = _utc_now_iso(now)

        checks: list[dict[str, Any]] = []
        ordinal = 0
        ro_failed = False
        ro_blocked = False
        # prepare clears prior checks; attempt numbers are assigned in memory only.
        attempt_by_kind: dict[str, int] = {}

        def record(
            kind: CheckKind,
            outcome: CheckOutcome,
            *,
            blocking: bool,
            write_related: bool,
            summary: str,
            evidence: dict[str, Any] | None = None,
        ) -> None:
            nonlocal ordinal, ro_failed, ro_blocked
            evidence_digest = None
            if evidence is not None:
                evidence_digest = "sha256:" + hashlib.sha256(
                    json.dumps(evidence, sort_keys=True).encode()
                ).hexdigest()
            kind_key = kind.value
            attempt = attempt_by_kind.get(kind_key, 0) + 1
            attempt_by_kind[kind_key] = attempt
            checks.append(
                {
                    "check_kind": kind.value,
                    "ordinal": ordinal,
                    "attempt": attempt,
                    "outcome": outcome.value,
                    "blocking": blocking,
                    "write_related": write_related,
                    "summary_redacted": summary,
                    "evidence_digest": evidence_digest,
                }
            )
            ordinal += 1
            if blocking and not write_related and outcome != CheckOutcome.PASSED:
                if outcome == CheckOutcome.BLOCKED:
                    ro_blocked = True
                else:
                    ro_failed = True

        if router_id is None:
            record(
                CheckKind.SITE_ROUTER_LINKAGE,
                CheckOutcome.FAILED,
                blocking=True,
                write_related=False,
                summary="router not linked",
            )
        else:
            router = self.store.get_router(router_id)
            if router is None:
                record(
                    CheckKind.SITE_ROUTER_LINKAGE,
                    CheckOutcome.FAILED,
                    blocking=True,
                    write_related=False,
                    summary="router missing",
                )
            elif str(router["site_id"]) != site_id:
                record(
                    CheckKind.SITE_ROUTER_LINKAGE,
                    CheckOutcome.FAILED,
                    blocking=True,
                    write_related=False,
                    summary="router site mismatch",
                )
            else:
                record(
                    CheckKind.SITE_ROUTER_LINKAGE,
                    CheckOutcome.PASSED,
                    blocking=True,
                    write_related=False,
                    summary="router linked to site",
                )

                if str(router["lifecycle_status"]) != "Enrolled":
                    record(
                        CheckKind.ENROLL_STATUS,
                        CheckOutcome.FAILED,
                        blocking=True,
                        write_related=False,
                        summary=f"lifecycle={router['lifecycle_status']}",
                    )
                else:
                    record(
                        CheckKind.ENROLL_STATUS,
                        CheckOutcome.PASSED,
                        blocking=True,
                        write_related=False,
                        summary="router enrolled",
                    )

                obs = self.store.get_latest_observation(router_id)
                if obs is None:
                    record(
                        CheckKind.OBSERVATION_FRESH,
                        CheckOutcome.FAILED,
                        blocking=True,
                        write_related=False,
                        summary="no observation",
                    )
                elif obs["collection_status"] != "Succeeded":
                    record(
                        CheckKind.OBSERVATION_FRESH,
                        CheckOutcome.FAILED,
                        blocking=True,
                        write_related=False,
                        summary="observation collection failed",
                    )
                elif obs["valid_until"] < ts:
                    record(
                        CheckKind.OBSERVATION_FRESH,
                        CheckOutcome.FAILED,
                        blocking=True,
                        write_related=False,
                        summary="observation stale",
                    )
                else:
                    record(
                        CheckKind.OBSERVATION_FRESH,
                        CheckOutcome.PASSED,
                        blocking=True,
                        write_related=False,
                        summary="observation fresh",
                    )

        if mode == CommissioningMode.LIVE.value:
            if not self.gate_a_open():
                record(
                    CheckKind.GATE_A_OPEN,
                    CheckOutcome.BLOCKED,
                    blocking=True,
                    write_related=False,
                    summary="gate A closed",
                )
            else:
                record(
                    CheckKind.GATE_A_OPEN,
                    CheckOutcome.PASSED,
                    blocking=True,
                    write_related=False,
                    summary="gate A open ReadOnlyCertified",
                )
                if router_id and not ro_failed and not ro_blocked:
                    try:
                        if self.probe_fn is None:
                            raise RuntimeError("probe not configured")
                        evidence = self.probe_fn(router_id=router_id)
                        if self.matches_probe_evidence(evidence):
                            record(
                                CheckKind.IDENTITY_TUPLE_MATCH,
                                CheckOutcome.PASSED,
                                blocking=True,
                                write_related=False,
                                summary="live probe matches Gate A tuple",
                                evidence={"matched": True},
                            )
                        else:
                            record(
                                CheckKind.IDENTITY_TUPLE_MATCH,
                                CheckOutcome.BLOCKED,
                                blocking=True,
                                write_related=False,
                                summary="probe evidence mismatch",
                                evidence={"matched": False},
                            )
                            ro_blocked = True
                    except Exception as exc:
                        record(
                            CheckKind.IDENTITY_TUPLE_MATCH,
                            CheckOutcome.FAILED,
                            blocking=True,
                            write_related=False,
                            summary=f"probe error: {type(exc).__name__}",
                        )
                        ro_failed = True
        else:
            record(
                CheckKind.GATE_A_OPEN,
                CheckOutcome.PASSED,
                blocking=True,
                write_related=False,
                summary="fake mode gate A not required",
            )

        if self.gate_b_not_write_certified():
            record(
                CheckKind.GATE_B_NOT_WRITE_CERTIFIED,
                CheckOutcome.BLOCKED,
                blocking=False,
                write_related=True,
                summary="Gate B not WriteCertified",
            )
        if self.gate_c_closed():
            record(
                CheckKind.GATE_C_CLOSED,
                CheckOutcome.BLOCKED,
                blocking=False,
                write_related=True,
                summary="Gate C closed",
            )
        if self.gate_d_closed():
            record(
                CheckKind.GATE_D_CLOSED,
                CheckOutcome.BLOCKED,
                blocking=False,
                write_related=True,
                summary="Gate D closed",
            )

        if ro_blocked:
            terminal = CommissioningState.BLOCKED
            summary = "read-only blocked"
        elif ro_failed:
            terminal = CommissioningState.FAILED
            summary = "read-only assessment failed"
        else:
            terminal = CommissioningState.READY_READ_ONLY
            summary = "read-only ready; write gates closed"

        report_digest = "sha256:" + hashlib.sha256(
            json.dumps({"checks": checks, "state": terminal.value}, sort_keys=True).encode()
        ).hexdigest()
        return terminal, summary, report_digest, ts, checks

    def _public_run(self, run_dict: dict[str, Any]) -> dict[str, Any]:
        etag = etag_token(
            run_dict["run_id"],
            int(run_dict["version"]),
            run_dict.get("report_digest"),
        )
        return {
            **run_dict,
            "etag": etag,
            "read_only_ready": run_dict["state"] == CommissioningState.READY_READ_ONLY.value,
            "write_ready": False,
            "never_commissioned": True,
            "never_write_certified": True,
        }

    @staticmethod
    def _public_check(row: Any) -> dict[str, Any]:
        return {
            "check_id": row["check_id"],
            "check_kind": row["check_kind"],
            "ordinal": int(row["ordinal"]),
            "attempt": int(row["attempt"]),
            "outcome": row["outcome"],
            "blocking": bool(row["blocking"]),
            "write_related": bool(row["write_related"]),
            "summary_redacted": row["summary_redacted"],
            "evidence_digest": row["evidence_digest"],
            "created_at": row["created_at"],
        }

    @staticmethod
    def _public_check_dict(check: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in check.items() if k != "created_at" or "created_at" in check}

    def enqueue_assess_async(
        self,
        *,
        run_id: str,
        router_id: str,
        idempotency_key: str,
        request_digest: str,
        expected_version: int | None = None,
        correlation_id: str | None = None,
        actor_id: str | None = None,
    ) -> dict[str, Any]:
        """Create §6 operation/job for async assess; worker persists terminal assess outcome."""
        row = self.store.get_commissioning_run(run_id)
        if row is None:
            raise CommissioningNotFound("commissioning run not found")
        try:
            existing = self.store.peek_idempotency(
                router_id=router_id,
                operation_kind="commissioning_assess_readonly",
                idempotency_key=idempotency_key,
                request_digest=request_digest,
            )
        except IdempotencyConflict as exc:
            raise CommissioningConflict(str(exc)) from exc
        if existing is not None:
            return self._async_assess_envelope(existing, router_id)

        payload = {
            "run_id": run_id,
            "idempotency_key": idempotency_key,
            "request_digest": request_digest,
            "expected_version": expected_version,
        }
        outcome = self.store.create_operation_bundle(
            router_id=router_id,
            operation_kind="commissioning_assess_readonly",
            idempotency_key=idempotency_key,
            request_digest=request_digest,
            actor_id=actor_id,
            correlation_id=correlation_id or run_id,
            initial_job_status="Queued",
            dispatch_payload=payload,
            now=self.clock.now(),
        )
        body = self._async_assess_body(outcome, router_id)
        self.store.update_idempotency_response(
            outcome.idempotency_record_id,
            http_status=202,
            body=body,
        )
        return body

    @staticmethod
    def _async_assess_body(outcome: Any, router_id: str) -> dict[str, Any]:
        return {
            "operation_id": outcome.operation_id,
            "job_id": outcome.job_id,
            "status": "Queued",
            "router_id": router_id,
            "links": {
                "operation": f"/api/router-control/v1/operations/{outcome.operation_id}",
                "job": f"/api/router-control/v1/jobs/{outcome.job_id}",
            },
        }

    def _async_assess_envelope(self, existing: Any, router_id: str) -> dict[str, Any]:
        if existing.response_ref:
            stored = json.loads(existing.response_ref)
            if isinstance(stored, dict):
                body = stored.get("body")
                if isinstance(body, dict):
                    typed_body: dict[str, Any] = body
                    return typed_body
        return self._async_assess_body(existing, router_id)
