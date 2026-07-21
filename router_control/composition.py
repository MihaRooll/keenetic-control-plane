"""Composition root for fake runtime (no FastAPI)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from router_control.adapters.fake.adapter import (
    FakeRouterAdapter,
    FakeRouterConfig,
    FakeRouterState,
)
from router_control.application.provisioning import ProvisioningLifecycleService
from router_control.domain.entities import RouterIdentity
from router_control.domain.ids import RouterId
from router_control.ports.clock import ClockPort


@dataclass(frozen=True, slots=True)
class FakeRuntime:
    adapter: FakeRouterAdapter
    service: ProvisioningLifecycleService
    clock: ClockPort


class FixedClock:
    def __init__(self, moment: datetime) -> None:
        self._moment = moment

    def now(self) -> datetime:
        return self._moment


def create_fake_runtime(
    *,
    router_id: str = "router-fake-001",
    fingerprint_digest: str = "digest:identity:fake-001",
    config: FakeRouterConfig | None = None,
    clock: ClockPort | None = None,
) -> FakeRuntime:
    moment = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    resolved_clock = clock or FixedClock(moment)
    identity = RouterIdentity(
        router_id=RouterId(router_id),
        vendor="FakeVendor",
        model="FakeModel-001",
        fingerprint_digest=fingerprint_digest,
    )
    adapter = FakeRouterAdapter(
        clock=resolved_clock,
        state=FakeRouterState(identity=identity),
        config=config or FakeRouterConfig(),
    )
    service = ProvisioningLifecycleService(adapter=adapter, clock=resolved_clock)
    return FakeRuntime(adapter=adapter, service=service, clock=resolved_clock)


def default_plan_expiry(clock: ClockPort) -> datetime:
    return clock.now() + timedelta(hours=1)
