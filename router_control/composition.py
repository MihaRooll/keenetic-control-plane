"""Composition root for offline runtime (SQLite + Fake + Vault). No FastAPI."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from router_control.adapters.fake.adapter import (
    FakeRouterAdapter,
    FakeRouterConfig,
    FakeRouterState,
)
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.provisioning import ProvisioningLifecycleService
from router_control.application.traffic_discovery import TrafficDiscoveryService
from router_control.domain.entities import RouterIdentity
from router_control.domain.ids import RouterId
from router_control.persistence.connection import DEFAULT_DB_PATH, open_database
from router_control.persistence.store import PersistenceStore
from router_control.ports.clock import ClockPort
from router_control.ports.vault import CredentialVaultPort


@dataclass(frozen=True, slots=True)
class FakeRuntime:
    adapter: FakeRouterAdapter
    service: ProvisioningLifecycleService
    clock: ClockPort


@dataclass(slots=True)
class OfflineRuntime:
    store: PersistenceStore
    adapter: FakeRouterAdapter
    vault: CredentialVaultPort
    traffic: TrafficDiscoveryService
    clock: ClockPort
    db_path: Path


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


def create_offline_runtime(
    *,
    db_path: Path | str | None = None,
    vault: CredentialVaultPort | None = None,
    clock: ClockPort | None = None,
    config: FakeRouterConfig | None = None,
) -> OfflineRuntime:
    """SQLite + FakeAdapter + MemoryVault composition for offline host/tests."""
    moment = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    resolved_clock = clock or FixedClock(moment)
    path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
    conn = open_database(path)
    store = PersistenceStore(conn)
    store.recover_expired_leases(now=resolved_clock.now())
    resolved_vault: CredentialVaultPort = vault or MemoryVault()
    fake = create_fake_runtime(clock=resolved_clock, config=config)
    traffic = TrafficDiscoveryService(store=store, apply_port=None)
    return OfflineRuntime(
        store=store,
        adapter=fake.adapter,
        vault=resolved_vault,
        traffic=traffic,
        clock=resolved_clock,
        db_path=path,
    )


def default_plan_expiry(clock: ClockPort) -> datetime:
    return clock.now() + timedelta(hours=1)
