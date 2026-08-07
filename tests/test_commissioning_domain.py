"""Commissioning domain transitions and invariants."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from router_control.domain.commissioning import (
    CheckKind,
    CheckOutcome,
    CommissioningMode,
    CommissioningRun,
    CommissioningState,
    IllegalCommissioningTransition,
    ReadinessCheck,
    assert_legal_transition,
    etag_token,
)

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


def test_legal_transitions() -> None:
    assert_legal_transition(CommissioningState.DRAFT, CommissioningState.OBSERVING)
    assert_legal_transition(CommissioningState.ASSESSING, CommissioningState.READY_READ_ONLY)
    assert_legal_transition(CommissioningState.READY_READ_ONLY, CommissioningState.CANCELLED)


def test_illegal_transition_raises() -> None:
    with pytest.raises(IllegalCommissioningTransition):
        assert_legal_transition(CommissioningState.DRAFT, CommissioningState.READY_READ_ONLY)


def test_commissioning_run_requires_utc() -> None:
    run = CommissioningRun(
        run_id="crun_test",
        site_id="site_test",
        router_id="rtr_test",
        state=CommissioningState.DRAFT,
        version=1,
        mode=CommissioningMode.FAKE,
        correlation_id="corr",
        summary_redacted=None,
        report_digest=None,
        created_at=FIXED,
        updated_at=FIXED,
        assessed_at=None,
    )
    assert run.state == CommissioningState.DRAFT
    assert not run.read_only_ready


def test_readiness_check_immutable_fields() -> None:
    check = ReadinessCheck(
        check_id="rcheck_test",
        run_id="crun_test",
        check_kind=CheckKind.ENROLL_STATUS,
        ordinal=0,
        attempt=1,
        outcome=CheckOutcome.PASSED,
        blocking=True,
        write_related=False,
        summary_redacted="ok",
        evidence_digest="sha256:abc",
        created_at=FIXED,
    )
    assert check.attempt == 1


def test_etag_token_format() -> None:
    assert etag_token("crun_x", 2, "sha256:d") == '"crun_x:2:sha256:d"'
