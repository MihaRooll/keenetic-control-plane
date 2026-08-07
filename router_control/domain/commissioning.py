"""Commissioning domain — read-only readiness runs and checks (vendor-neutral)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum


def _ensure_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise ValueError(f"{name} must use UTC timezone")
    return value.astimezone(UTC)


class CommissioningState(StrEnum):
    DRAFT = "Draft"
    OBSERVING = "Observing"
    ASSESSING = "Assessing"
    READY_READ_ONLY = "ReadyReadOnly"
    BLOCKED = "Blocked"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


class CommissioningMode(StrEnum):
    FAKE = "fake"
    LIVE = "live"


class CheckOutcome(StrEnum):
    PASSED = "Passed"
    FAILED = "Failed"
    BLOCKED = "Blocked"
    SKIPPED = "Skipped"


class CheckKind(StrEnum):
    SITE_ROUTER_LINKAGE = "site_router_linkage"
    ENROLL_STATUS = "enroll_status"
    OBSERVATION_FRESH = "observation_fresh"
    GATE_A_OPEN = "gate_a_open"
    IDENTITY_TUPLE_MATCH = "identity_tuple_match"
    GATE_B_NOT_WRITE_CERTIFIED = "gate_b_not_write_certified"
    GATE_C_CLOSED = "gate_c_closed"
    GATE_D_CLOSED = "gate_d_closed"


TERMINAL_STATES = frozenset(
    {
        CommissioningState.BLOCKED,
        CommissioningState.FAILED,
        CommissioningState.CANCELLED,
        CommissioningState.READY_READ_ONLY,
    }
)

_LEGAL_TRANSITIONS: dict[CommissioningState, frozenset[CommissioningState]] = {
    CommissioningState.DRAFT: frozenset(
        {CommissioningState.OBSERVING, CommissioningState.CANCELLED}
    ),
    CommissioningState.OBSERVING: frozenset(
        {
            CommissioningState.ASSESSING,
            CommissioningState.BLOCKED,
            CommissioningState.FAILED,
            CommissioningState.CANCELLED,
        }
    ),
    CommissioningState.ASSESSING: frozenset(
        {
            CommissioningState.READY_READ_ONLY,
            CommissioningState.BLOCKED,
            CommissioningState.FAILED,
            CommissioningState.CANCELLED,
        }
    ),
    CommissioningState.READY_READ_ONLY: frozenset({CommissioningState.CANCELLED}),
}


def assert_legal_transition(
    current: CommissioningState, target: CommissioningState
) -> None:
    if current in TERMINAL_STATES and current != CommissioningState.READY_READ_ONLY:
        raise IllegalCommissioningTransition(
            f"terminal state {current.value} cannot transition to {target.value}"
        )
    allowed = _LEGAL_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise IllegalCommissioningTransition(
            f"illegal transition {current.value} -> {target.value}"
        )


@dataclass(frozen=True, slots=True)
class IllegalCommissioningTransition(ValueError):
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    check_id: str
    run_id: str
    check_kind: CheckKind
    ordinal: int
    attempt: int
    outcome: CheckOutcome
    blocking: bool
    write_related: bool
    summary_redacted: str
    evidence_digest: str | None
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
        if self.attempt < 1:
            raise ValueError("attempt must be >= 1")
        if self.ordinal < 0:
            raise ValueError("ordinal must be >= 0")


@dataclass(frozen=True, slots=True)
class CommissioningRun:
    run_id: str
    site_id: str
    router_id: str | None
    state: CommissioningState
    version: int
    mode: CommissioningMode
    correlation_id: str | None
    summary_redacted: str | None
    report_digest: str | None
    created_at: datetime
    updated_at: datetime
    assessed_at: datetime | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "created_at", _ensure_utc(self.created_at, "created_at"))
        object.__setattr__(self, "updated_at", _ensure_utc(self.updated_at, "updated_at"))
        if self.assessed_at is not None:
            object.__setattr__(
                self,
                "assessed_at",
                _ensure_utc(self.assessed_at, "assessed_at"),
            )
        if self.version < 1:
            raise ValueError("version must be >= 1")

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES

    @property
    def read_only_ready(self) -> bool:
        return self.state == CommissioningState.READY_READ_ONLY


def etag_token(run_id: str, version: int, report_digest: str | None) -> str:
    digest = report_digest or "none"
    return f'"{run_id}:{version}:{digest}"'
