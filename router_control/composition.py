"""Composition root for offline runtime (SQLite + Fake + Vault). No FastAPI."""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from router_control.adapters.fake.adapter import (
    FakeRouterAdapter,
    FakeRouterConfig,
    FakeRouterState,
)
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.commissioning import CommissioningService
from router_control.application.deployment_planner import DeploymentPlannerService
from router_control.application.entry_pages import EntryPageService
from router_control.application.mutation_executor import MutationExecutor
from router_control.application.preset_planner import PresetPlannerService
from router_control.application.preset_readiness import (
    EventPresetCatalogService,
    PresetReadinessService,
    wire_commissioning_lookup,
)
from router_control.application.provisioning import ProvisioningLifecycleService
from router_control.application.remembered_uplink import RememberedUplinkService
from router_control.application.standing_network_preferences import (
    StandingNetworkPreferencesService,
)
from router_control.application.traffic_discovery import TrafficDiscoveryService
from router_control.application.worker import DurableWorker, WorkerConfig
from router_control.application.worker_handlers import build_default_registry
from router_control.domain.entities import RouterIdentity
from router_control.domain.ids import RouterId
from router_control.persistence.artifacts import BackupArtifactPublisher, FakeBlobStore
from router_control.persistence.connection import connect, open_database, resolve_db_path
from router_control.persistence.store import PersistenceStore
from router_control.ports.clock import ClockPort, SystemClock
from router_control.ports.vault import CredentialVaultPort


def resolve_host_vault(
    *,
    vault: CredentialVaultPort | None = None,
    secrets_root: Path | str | None = None,
) -> CredentialVaultPort:
    """Resolve host credential vault; injected vault wins (tests). Decoupled from adapter mode."""
    if vault is not None:
        return vault
    if os.environ.get("RC_VAULT", "").strip().lower() == "memory":
        return MemoryVault()
    if "pytest" in sys.modules:
        return MemoryVault()
    root = Path(secrets_root) if secrets_root is not None else Path("data/secrets")
    try:
        from router_control.adapters.secrets.dpapi import WindowsDpapiVault

        return WindowsDpapiVault(root=root)
    except Exception:
        return MemoryVault()


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
    commissioning: CommissioningService
    event_presets: EventPresetCatalogService
    entry_pages: EntryPageService
    standing_network_preferences: StandingNetworkPreferencesService
    remembered_uplink: RememberedUplinkService
    preset_readiness: PresetReadinessService
    preset_planner: PresetPlannerService
    deployment_planner: DeploymentPlannerService
    clock: ClockPort
    db_path: Path
    blob_store: FakeBlobStore = field(default_factory=FakeBlobStore)
    mutation_executor: MutationExecutor | None = field(default=None, repr=False)


@dataclass(slots=True)
class LiveRuntime:
    store: PersistenceStore
    vault: CredentialVaultPort
    traffic: TrafficDiscoveryService
    commissioning: CommissioningService
    event_presets: EventPresetCatalogService
    entry_pages: EntryPageService
    standing_network_preferences: StandingNetworkPreferencesService
    remembered_uplink: RememberedUplinkService
    preset_readiness: PresetReadinessService
    preset_planner: PresetPlannerService
    deployment_planner: DeploymentPlannerService
    clock: ClockPort
    db_path: Path
    secrets_root: Path


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
    durable_backup_artifacts: bool = False,
) -> OfflineRuntime:
    """SQLite + FakeAdapter + MemoryVault composition for offline host/tests."""
    moment = datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)
    resolved_clock = clock or FixedClock(moment)
    path = resolve_db_path(db_path)
    conn = open_database(path)
    store = PersistenceStore(conn)
    store.recover_expired_leases(now=resolved_clock.now())
    store.interrupt_stale_sealed_apply_runs(now=resolved_clock.now())
    store.reap_expired_router_execution_fences()
    from router_control.persistence.artifacts import (
        ArtifactStagingPublisher,
        DpapiDurableArtifactStore,
        DurableBackupArtifactPublisher,
        reconcile_orphan_staging_records,
    )

    staging_publisher = ArtifactStagingPublisher(
        store=store,
        staging_root=path.parent / "artifact-staging",
    )
    reconcile_orphan_staging_records(staging_publisher, store, now=resolved_clock.now())
    resolved_vault: CredentialVaultPort = vault or MemoryVault()
    fake = create_fake_runtime(clock=resolved_clock, config=config)
    traffic = TrafficDiscoveryService(store=store, apply_port=None)
    commissioning = CommissioningService(store=store, clock=resolved_clock)
    planner = PresetPlannerService()
    deployment = DeploymentPlannerService(store=store, clock=resolved_clock)
    readiness = PresetReadinessService(
        store=store,
        planner=planner,
        commissioning_lookup=wire_commissioning_lookup(commissioning),
    )
    event_presets = EventPresetCatalogService(
        store=store,
        clock=resolved_clock,
        planner=planner,
        readiness=readiness,
    )
    entry_pages = EntryPageService(store=store, clock=resolved_clock)
    standing_network_preferences = StandingNetworkPreferencesService(
        store=store,
        clock=resolved_clock,
    )
    remembered_uplink = RememberedUplinkService(
        store=store,
        clock=resolved_clock,
    )
    blob_store = FakeBlobStore()
    if durable_backup_artifacts:
        durable = DpapiDurableArtifactStore(
            store=store,
            staging_root=path.parent / "artifact-staging-durable",
            encrypted_root=path.parent / "artifact-encrypted",
        )
        backup_publisher: BackupArtifactPublisher | DurableBackupArtifactPublisher = (
            DurableBackupArtifactPublisher(durable_store=durable)
        )
    else:
        backup_publisher = BackupArtifactPublisher(blob_store=blob_store, store=store)
    mutation_executor = MutationExecutor(
        adapter=fake.adapter,
        clock=resolved_clock,
        backup_publisher=backup_publisher,
    )
    return OfflineRuntime(
        store=store,
        adapter=fake.adapter,
        vault=resolved_vault,
        traffic=traffic,
        commissioning=commissioning,
        event_presets=event_presets,
        entry_pages=entry_pages,
        standing_network_preferences=standing_network_preferences,
        remembered_uplink=remembered_uplink,
        preset_readiness=readiness,
        preset_planner=planner,
        deployment_planner=deployment,
        clock=resolved_clock,
        db_path=path,
        blob_store=blob_store,
        mutation_executor=mutation_executor,
    )


def build_durable_worker(
    runtime: OfflineRuntime | LiveRuntime,
    *,
    adapter_mode: str = "fake",
    allow_fake_mutations: bool = False,
    worker_id: str = "offline-worker",
) -> DurableWorker:
    """Build DurableWorker with a dedicated DB connection (separate from runtime.store)."""
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


def create_live_runtime(
    *,
    db_path: Path | str | None = None,
    secrets_root: Path | str | None = None,
    clock: ClockPort | None = None,
    vault: CredentialVaultPort | None = None,
) -> LiveRuntime:
    """SQLite + WindowsDpapiVault composition for live Gate A host (lazy hardware I/O)."""
    resolved_clock = clock or SystemClock()
    path = resolve_db_path(db_path)
    conn = open_database(path)
    store = PersistenceStore(conn)
    store.recover_expired_leases(now=resolved_clock.now())
    store.interrupt_stale_sealed_apply_runs(now=resolved_clock.now())
    root = Path(secrets_root) if secrets_root is not None else Path("data/secrets")
    resolved_vault = resolve_host_vault(vault=vault, secrets_root=root)
    traffic = TrafficDiscoveryService(store=store, apply_port=None)
    commissioning = CommissioningService(store=store, clock=resolved_clock)
    planner = PresetPlannerService()
    deployment = DeploymentPlannerService(store=store, clock=resolved_clock)
    readiness = PresetReadinessService(
        store=store,
        planner=planner,
        commissioning_lookup=wire_commissioning_lookup(commissioning),
    )
    event_presets = EventPresetCatalogService(
        store=store,
        clock=resolved_clock,
        planner=planner,
        readiness=readiness,
    )
    entry_pages = EntryPageService(store=store, clock=resolved_clock)
    standing_network_preferences = StandingNetworkPreferencesService(
        store=store,
        clock=resolved_clock,
    )
    remembered_uplink = RememberedUplinkService(
        store=store,
        clock=resolved_clock,
    )
    return LiveRuntime(
        store=store,
        vault=resolved_vault,
        traffic=traffic,
        commissioning=commissioning,
        event_presets=event_presets,
        entry_pages=entry_pages,
        standing_network_preferences=standing_network_preferences,
        remembered_uplink=remembered_uplink,
        preset_readiness=readiness,
        preset_planner=planner,
        deployment_planner=deployment,
        clock=resolved_clock,
        db_path=path,
        secrets_root=root,
    )


def default_plan_expiry(clock: ClockPort) -> datetime:
    return clock.now() + timedelta(hours=1)
