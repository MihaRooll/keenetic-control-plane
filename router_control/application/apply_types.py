"""Shared apply/teardown outcome types for application services and HTTP contract."""

from __future__ import annotations

from typing import Literal

ApplyOverallStatus = Literal[
    "applied",
    "failed",
    "verify_mismatch",
    "rolled_back",
    "dispatched_offline",
    "unsupported_pending_verification",
]

ApplyRollbackOutcome = Literal[
    "not_attempted",
    "noop",
    "succeeded",
    "partial",
    "failed",
]

__all__ = [
    "ApplyOverallStatus",
    "ApplyRollbackOutcome",
]
