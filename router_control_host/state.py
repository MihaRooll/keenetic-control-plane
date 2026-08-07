"""Host application state holder."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.live_probe import LiveProbeTarget, ReadOnlyProbeFn
from router_control.adapters.netcraze.ssh_tunnel import validate_source_address
from router_control.application.commissioning import CommissioningService
from router_control.application.connection_health import ConnectionHealthProbePort
from router_control.application.deployment_planner import DeploymentPlannerService
from router_control.application.entry_pages import EntryPageService
from router_control.application.preset_readiness import EventPresetCatalogService
from router_control.application.remembered_uplink import RememberedUplinkService
from router_control.application.router_discovery import CandidateIdentityProbePort
from router_control.application.ssh_host_key_pin import PendingLearnRegistry
from router_control.application.standing_network_preferences import (
    StandingNetworkPreferencesService,
)
from router_control.application.traffic_discovery import TrafficDiscoveryService
from router_control.composition import LiveRuntime, OfflineRuntime
from router_control.domain.ids import RouterId

from router_control_host.host_probes import HostProbeRunner
from router_control_host.worker_runtime import WorkerRuntimeHandle

if TYPE_CHECKING:
    from router_control.application.gate_a_refresh_watchdog import GateARefreshWatchdogHandle
    from router_control.application.uplink_watchdog_service import UplinkWatchdogHandle
    from router_control.application.vpn_watchdog_service import VpnWatchdogHandle


@dataclass
class HostState:
    runtime: OfflineRuntime | LiveRuntime
    feature_state: str = "Ready"
    adapter_mode: str = "fake"
    allow_fake_mutations: bool = False
    gate_a_certification: GateACertification | None = None
    read_only_probe_fn: ReadOnlyProbeFn | None = None
    connection_health_probe_port: ConnectionHealthProbePort | None = None
    router_discovery_identity_probe: CandidateIdentityProbePort | None = None
    # Injected factory for offline/tests only — not standing live wiring in create_app.
    keendns_apply_transport_factory: Callable[[], Any] | None = None
    wifi_apply_transport_factory: Callable[[], Any] | None = None
    wifi_apply_credential_resolver: Callable[[str], str] | None = None
    wifi_station_apply_transport_factory: Callable[[], Any] | None = None
    wifi_station_apply_credential_resolver: Callable[[str], str] | None = None
    wifi_observed_transport_factory: Callable[[], Any] | None = None
    internet_status_transport_factory: Callable[[], Any] | None = None
    fake_wifi_device: Any | None = None
    wireguard_apply_transport_factory: Callable[[], Any] | None = None
    wireguard_apply_credential_resolver: Callable[[str], str] | None = None
    host_probe_runner: HostProbeRunner | None = None
    ssh_host_key_pending_learn: PendingLearnRegistry = field(default_factory=PendingLearnRegistry)
    site_id: str | None = None
    worker_runtime: WorkerRuntimeHandle | None = None
    vpn_watchdog: VpnWatchdogHandle | None = None
    uplink_watchdog: UplinkWatchdogHandle | None = None
    gate_a_refresh_watchdog: GateARefreshWatchdogHandle | None = None
    _bootstrapped: bool = field(default=False, repr=False)

    def ensure_default_site(self) -> str:
        if self.site_id:
            return self.site_id
        self.site_id = self.runtime.store.create_site(
            display_name="Offline Lab",
            timezone="UTC",
            now=self.runtime.clock.now(),
        )
        return self.site_id

    def resolve_site_id(self) -> str:
        """Default site for UI/API: host state, first router, or bootstrap lab site."""
        if self.site_id:
            return self.site_id
        rows = self.runtime.store.list_routers(limit=1)
        if rows:
            self.site_id = str(rows[0]["site_id"])
            return self.site_id
        return self.ensure_default_site()

    def gate_a_open(self) -> bool:
        return self.gate_a_certification is not None and self.gate_a_certification.is_open

    def run_read_only_probe(self, target: LiveProbeTarget) -> dict[str, object]:
        if self.read_only_probe_fn is None:
            raise RuntimeError("read-only probe factory not configured")
        return self.read_only_probe_fn(target)

    def commissioning_service(self) -> CommissioningService:
        svc = self.runtime.commissioning
        svc.gate_a_open = self.gate_a_open
        cert = self.gate_a_certification
        if cert is not None:
            svc.matches_probe_evidence = cert.matches_probe_evidence
        svc.gate_b_not_write_certified = lambda: True
        svc.gate_c_closed = lambda: True
        svc.gate_d_closed = lambda: True
        if self.read_only_probe_fn is not None:

            def _probe(router_id: str) -> dict[str, Any]:
                import os

                row = self.runtime.store.get_router(router_id)
                if row is None:
                    raise RuntimeError("router not found for probe")
                endpoint = self.runtime.store.get_primary_endpoint(router_id)
                if endpoint is None:
                    raise RuntimeError("endpoint missing for probe")
                cred_id = str(row["credential_ref_id"] or "")
                if not cred_id:
                    raise RuntimeError("credential ref missing for probe")
                username = os.environ.get("RC_NETCRAZE_USERNAME", "admin")
                source_raw = endpoint["source_address"]
                if source_raw is None or (
                    isinstance(source_raw, str) and not str(source_raw).strip()
                ):
                    raise RuntimeError("source_address missing for probe")
                source_address = validate_source_address(str(source_raw).strip())
                target = LiveProbeTarget(
                    ssh_host=str(endpoint["host"]),
                    username=username,
                    credential_ref_id=cred_id,
                    router_id=RouterId(router_id),
                    source_address=source_address,
                )
                result = self.run_read_only_probe(target)
                return dict(result)

            svc.probe_fn = _probe
        return svc

    def event_preset_service(self) -> EventPresetCatalogService:
        return self.runtime.event_presets

    def entry_page_service(self) -> EntryPageService:
        return self.runtime.entry_pages

    def standing_network_preferences_service(self) -> StandingNetworkPreferencesService:
        return self.runtime.standing_network_preferences

    def remembered_uplink_service(self) -> RememberedUplinkService:
        return self.runtime.remembered_uplink

    def deployment_service(self) -> DeploymentPlannerService:
        return self.runtime.deployment_planner

    def traffic_service(self) -> TrafficDiscoveryService:
        return self.runtime.traffic

    def worker_status(self) -> dict[str, Any]:
        if self.worker_runtime is not None:
            return self.worker_runtime.status_payload()
        return {
            "worker_state": "Stopped",
            "worker_heartbeat_at": None,
            "worker_last_error": None,
        }

    def vpn_watchdog_status(self) -> dict[str, Any]:
        if self.vpn_watchdog is not None:
            return self.vpn_watchdog.status_payload()
        from router_control.application.vpn_watchdog_service import (
            VPN_WATCHDOG_ENABLED,
            VPN_WATCHDOG_POLL_SECONDS,
        )

        return {
            "vpn_watchdog_enabled": VPN_WATCHDOG_ENABLED,
            "vpn_watchdog_poll_seconds": VPN_WATCHDOG_POLL_SECONDS,
            "vpn_watchdog_running": False,
        }

    def uplink_watchdog_status(self) -> dict[str, Any]:
        if self.uplink_watchdog is not None:
            return self.uplink_watchdog.status_payload()
        from router_control.application.uplink_watchdog_service import (
            UPLINK_WATCHDOG_ENABLED,
            UPLINK_WATCHDOG_POLL_SECONDS,
        )

        return {
            "uplink_watchdog_enabled": UPLINK_WATCHDOG_ENABLED,
            "uplink_watchdog_poll_seconds": UPLINK_WATCHDOG_POLL_SECONDS,
            "uplink_watchdog_running": False,
        }
