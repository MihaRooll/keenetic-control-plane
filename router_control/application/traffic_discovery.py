"""TrafficDiscovery service — create proposals; never call router apply."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from router_control.domain.traffic import RouteProposal, TrafficObservation
from router_control.persistence.ids import new_id
from router_control.persistence.store import PersistenceStore


class RouterApplyPort(Protocol):
    def apply(self, *args: Any, **kwargs: Any) -> Any: ...


class AutoApplyBlocked(Exception):
    pass


@dataclass
class TrafficDiscoveryService:
    store: PersistenceStore
    apply_port: RouterApplyPort | None = None

    def record_observation(
        self,
        *,
        router_id: str,
        evidence: dict[str, Any],
        source: str = "offline",
        now: datetime | None = None,
    ) -> TrafficObservation:
        moment = now or datetime.now(UTC)
        digest = "sha256:" + hashlib.sha256(repr(sorted(evidence.items())).encode()).hexdigest()
        tid = self.store.insert_traffic_observation(
            router_id=router_id,
            evidence_digest=digest,
            source=source,
            evidence_json=None,  # redacted — do not store raw secrets
            now=moment,
        )
        return TrafficObservation(
            traffic_observation_id=tid,
            router_id=router_id,
            evidence_digest=digest,
            observed_at=moment,
            source=source,
        )

    def create_proposal(
        self,
        *,
        observation: TrafficObservation,
        route_intent: dict[str, Any],
        confidence: float,
        ttl_seconds: int = 3600,
        trusted_policy: bool = False,
        now: datetime | None = None,
    ) -> RouteProposal:
        moment = now or datetime.now(UTC)
        expires = moment + timedelta(seconds=ttl_seconds)
        proposal_digest = "sha256:" + hashlib.sha256(
            f"{observation.traffic_observation_id}:{sorted(route_intent.items())}".encode()
        ).hexdigest()
        pid = new_id("prop")
        # Always block auto-apply at persistence default; trusted still needs plan gates
        self.store.insert_route_proposal(
            router_id=observation.router_id,
            traffic_observation_id=observation.traffic_observation_id,
            proposal_digest=proposal_digest,
            confidence=confidence,
            expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
            trusted_policy=trusted_policy,
            proposal_json=None,
            proposal_id=pid,
            now=moment,
        )
        return RouteProposal(
            proposal_id=pid,
            router_id=observation.router_id,
            traffic_observation_id=observation.traffic_observation_id,
            proposal_digest=proposal_digest,
            confidence=confidence,
            expires_at=expires,
            trusted_policy=trusted_policy,
            auto_apply_blocked=True,
            status="Proposed",
        )

    def try_auto_apply(self, proposal: RouteProposal) -> None:
        """Fail-closed: untrusted (and default) auto-apply blocked; never mutates router."""
        if proposal.auto_apply_blocked or not proposal.trusted_policy:
            raise AutoApplyBlocked(
                "auto-apply blocked; proposals require plan/confirm/apply gates"
            )
        # Even trusted_policy requires plan gates — do not call adapter
        raise AutoApplyBlocked(
            "trusted_policy still requires plan/idempotency/ownership/verify gates"
        )
