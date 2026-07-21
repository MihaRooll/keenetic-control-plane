"""TrafficDiscovery entities — proposals only; never mutate routes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def _ensure_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None:
        raise ValueError(f"{name} must be timezone-aware UTC")
    offset = value.utcoffset()
    if offset is None or offset != timedelta(0):
        raise ValueError(f"{name} must use UTC timezone")
    return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class TrafficObservation:
    traffic_observation_id: str
    router_id: str
    evidence_digest: str
    observed_at: datetime
    source: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_at", _ensure_utc(self.observed_at, "observed_at"))


@dataclass(frozen=True, slots=True)
class RouteProposal:
    proposal_id: str
    router_id: str
    traffic_observation_id: str
    proposal_digest: str
    confidence: float
    expires_at: datetime
    trusted_policy: bool
    auto_apply_blocked: bool
    status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "expires_at", _ensure_utc(self.expires_at, "expires_at"))
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be in [0, 1]")
