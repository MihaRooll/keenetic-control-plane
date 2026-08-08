"""Env-gated Wi-Fi uplink watchdog — reapply when station gateway absent/mismatch."""

from __future__ import annotations

import asyncio
import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from router_control.adapters.netcraze.allowlist import is_wireguard_like_interface_name
from router_control.adapters.netcraze.startup_backup import StartupBackupError
from router_control.application.internet_status_observe import (
    InternetStatusTransport,
    run_internet_status_observe,
)
from router_control.application.recovery import SealedApplyTrailParams
from router_control.application.router_apply_lock import run_with_router_apply_lock
from router_control.application.wifi_station_apply_service import (
    WifiStationApplyTransport,
    apply_wifi_station_intent,
)
from router_control.domain.network_intents import UplinkIntent, UplinkMode, WifiBand
from router_control.persistence.errors import SealedApplyTrailBeginError

_LOGGER = logging.getLogger(__name__)

UPLINK_WATCHDOG_ENABLED = os.environ.get("UPLINK_WATCHDOG_ENABLED", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
UPLINK_WATCHDOG_POLL_SECONDS = max(
    5.0,
    float(os.environ.get("UPLINK_WATCHDOG_POLL_SECONDS", "45") or "45"),
)
_UNHEALTHY_STREAK_THRESHOLD = 2
_BACKOFF_BASE_SECONDS = UPLINK_WATCHDOG_POLL_SECONDS
_BACKOFF_MAX_SECONDS = 600.0

CredentialResolver = Callable[[str], str]
ObserveTransportFactory = Callable[[str], InternetStatusTransport | None]
ApplyTransportFactory = Callable[[str], WifiStationApplyTransport | None]
BackupCallback = Callable[[], None]
BackupCallbackFactory = Callable[[str], BackupCallback | None]
# True = internet reachable (skip router SSH this cycle), False = unreachable
# (escalate to router-side check), None = inconclusive (fall back to router-side
# check, same as if no probe were wired at all).
HostInternetProbeFn = Callable[[], bool | None]


class WatchdogHost(Protocol):
    runtime: Any


def _parse_updated_at_epoch(value: str | None) -> float | None:
    if not value:
        return None
    try:
        normalized = value.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return None


def is_ethernet_like_gateway(gateway_interface: str | None) -> bool:
    if not gateway_interface:
        return False
    gateway = gateway_interface.strip()
    if not gateway:
        return False
    if gateway.startswith("GigabitEthernet"):
        return True
    return bool(re.match(r"^Ethernet", gateway, re.IGNORECASE))


def is_wireguard_like_gateway(gateway_interface: str | None) -> bool:
    if not gateway_interface:
        return False
    gateway = gateway_interface.strip()
    if not gateway:
        return False
    return is_wireguard_like_interface_name(gateway)


def gateway_matches_remembered_station(
    gateway_interface: str | None,
    *,
    expected_station_id: str | None,
) -> bool:
    if not expected_station_id:
        return False
    if not gateway_interface:
        return False
    gateway = gateway_interface.strip()
    if gateway == expected_station_id:
        return True
    if gateway.startswith("WifiMaster") and expected_station_id.startswith("WifiMaster"):
        return gateway == expected_station_id
    return False


def should_skip_uplink_reapply(
    *,
    observation: Any,
    expected_station_id: str | None,
    suppress_until_epoch: float | None,
    now_epoch: float,
) -> bool:
    if suppress_until_epoch is not None and now_epoch < suppress_until_epoch:
        return True
    gateway = getattr(observation, "gateway_interface", None)
    if gateway_matches_remembered_station(gateway, expected_station_id=expected_station_id):
        return True
    return False


def should_reapply_uplink(
    *,
    observation: Any,
    expected_station_id: str | None,
) -> bool:
    gateway = getattr(observation, "gateway_interface", None)
    return not gateway_matches_remembered_station(gateway, expected_station_id=expected_station_id)


@dataclass
class _RouterWatchState:
    unhealthy_streak: int = 0
    backoff_seconds: float = _BACKOFF_BASE_SECONDS
    next_poll_at: float = 0.0


@dataclass
class UplinkWatchdogHandle:
    host: WatchdogHost
    observe_transport_factory: ObserveTransportFactory | None = None
    apply_transport_factory: ApplyTransportFactory | None = None
    credential_resolver: CredentialResolver | None = None
    backup_callback_factory: BackupCallbackFactory | None = None
    host_internet_probe: HostInternetProbeFn | None = None
    _task: asyncio.Task[None] | None = field(default=None, init=False)
    _stop: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _states: dict[str, _RouterWatchState] = field(default_factory=dict, init=False)

    def status_payload(self) -> dict[str, Any]:
        running = self._task is not None and not self._task.done()
        return {
            "uplink_watchdog_enabled": UPLINK_WATCHDOG_ENABLED,
            "uplink_watchdog_poll_seconds": UPLINK_WATCHDOG_POLL_SECONDS,
            "uplink_watchdog_running": running,
        }

    def start(self) -> None:
        if not UPLINK_WATCHDOG_ENABLED:
            return
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run_loop(), name="uplink-watchdog")

    async def stop(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                await self._poll_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                _LOGGER.exception("uplink watchdog poll loop failed")
                try:
                    self.host.runtime.store.try_append_sealed_apply_audit(
                        action="uplink_watchdog.poll",
                        outcome="failed",
                        route="remembered-uplink",
                        verb="watchdog_poll",
                        intent_redacted={},
                        router_id=None,
                        correlation_id=None,
                        result_payload=None,
                        outcome_snapshot=None,
                        error_message="uplink watchdog poll loop failed",
                        exception_type="Exception",
                    )
                except Exception:
                    _LOGGER.exception("uplink watchdog poll failure audit append failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=UPLINK_WATCHDOG_POLL_SECONDS)
                break
            except TimeoutError:
                continue

    async def _poll_once(self) -> None:
        if self.observe_transport_factory is None or self.apply_transport_factory is None:
            return
        remembered_svc = self.host.runtime.remembered_uplink
        remembered = remembered_svc.get_remembered()
        if not remembered.get("desired_active"):
            self._states.clear()
            return
        if not remembered.get("credential_configured"):
            return
        station_id = remembered.get("station_id")
        ssid = str(remembered.get("ssid") or "").strip()
        band_raw = remembered.get("band")
        cred_ref = remembered.get("credential_ref_id")
        if not ssid or not band_raw or not cred_ref:
            return
        try:
            band = WifiBand(str(band_raw))
        except ValueError:
            return
        router_id = remembered.get("router_id")
        if not router_id:
            return
        router_key = str(router_id)
        loop = asyncio.get_running_loop()
        now = loop.time()
        state = self._states.setdefault(router_key, _RouterWatchState())
        if now < state.next_poll_at:
            return
        if self.host_internet_probe is not None:
            try:
                host_reachable = await asyncio.to_thread(self.host_internet_probe)
            except Exception:
                host_reachable = None
            if host_reachable is True:
                # Cheap host-side check (no router SSH round-trip) says internet
                # is fine — skip the expensive router-side probe this cycle.
                # Only escalate to the router when the host-side signal is
                # False or inconclusive, to avoid loading the router with
                # routine SSH traffic just for monitoring.
                state.unhealthy_streak = 0
                state.backoff_seconds = _BACKOFF_BASE_SECONDS
                state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
                return
        observe_transport = self.observe_transport_factory(router_key)
        if observe_transport is None:
            return
        observation = await asyncio.to_thread(
            run_internet_status_observe,
            transport=observe_transport,
        )
        if getattr(observation, "read_status", None) == "failed":
            state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
            return
        updated_at = _parse_updated_at_epoch(str(remembered.get("updated_at") or ""))
        suppress_until = (
            updated_at + 2.0 * UPLINK_WATCHDOG_POLL_SECONDS
            if updated_at is not None
            else None
        )
        gateway = getattr(observation, "gateway_interface", None)
        if is_ethernet_like_gateway(
            str(gateway) if gateway is not None else None
        ):
            state.unhealthy_streak = 0
            state.backoff_seconds = _BACKOFF_BASE_SECONDS
            state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
            return
        if is_wireguard_like_gateway(
            str(gateway) if gateway is not None else None
        ):
            state.unhealthy_streak = 0
            state.backoff_seconds = _BACKOFF_BASE_SECONDS
            state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
            return
        if should_skip_uplink_reapply(
            observation=observation,
            expected_station_id=str(station_id) if station_id else None,
            suppress_until_epoch=suppress_until,
            now_epoch=datetime.now(tz=UTC).timestamp(),
        ):
            state.unhealthy_streak = 0
            state.backoff_seconds = _BACKOFF_BASE_SECONDS
            state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
            return
        if not should_reapply_uplink(
            observation=observation,
            expected_station_id=str(station_id) if station_id else None,
        ):
            state.unhealthy_streak = 0
            state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
            return
        state.unhealthy_streak += 1
        if state.unhealthy_streak >= _UNHEALTHY_STREAK_THRESHOLD:
            apply_transport = self.apply_transport_factory(router_key)
            reapply_outcome: str | None = None
            if apply_transport is not None:
                intent = UplinkIntent(
                    mode=UplinkMode.WIFI_WAN,
                    ssid=ssid,
                    band=band,
                    credential_ref_id=str(cred_ref),
                )
                reapply_outcome = await asyncio.to_thread(
                    self._reapply_locked,
                    router_key,
                    intent,
                    apply_transport,
                    remembered,
                )
            if reapply_outcome in ("applied", "skipped"):
                state.unhealthy_streak = 0
                state.backoff_seconds = _BACKOFF_BASE_SECONDS
                state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS
            else:
                state.backoff_seconds = min(
                    state.backoff_seconds * 2.0,
                    _BACKOFF_MAX_SECONDS,
                )
                state.next_poll_at = now + state.backoff_seconds
        else:
            state.next_poll_at = now + UPLINK_WATCHDOG_POLL_SECONDS

    def _resolve_credentials(self) -> CredentialResolver:
        if self.credential_resolver is not None:
            return self.credential_resolver
        vault = self.host.runtime.vault

        def resolve(ref_id: str) -> str:
            return str(vault.use(ref_id))

        return resolve

    def _reapply_locked(
        self,
        router_id: str,
        intent: UplinkIntent,
        transport: WifiStationApplyTransport,
        remembered: dict[str, Any],
    ) -> str | None:
        credential_resolver = self._resolve_credentials()
        intent_redacted = {
            "router_id": router_id,
            "ssid": remembered.get("ssid"),
            "band": remembered.get("band"),
            "credential_ref_id": remembered.get("credential_ref_id"),
        }
        outcome_holder: list[str | None] = [None]

        def _audit_failure(
            *,
            error_message: str,
            exception_type: str | None = None,
        ) -> None:
            self.host.runtime.store.try_append_sealed_apply_audit(
                action="uplink_watchdog.reapply",
                outcome="failed",
                route="remembered-uplink",
                verb="watchdog_reapply",
                intent_redacted=intent_redacted,
                router_id=router_id,
                correlation_id=None,
                result_payload=None,
                outcome_snapshot=None,
                error_message=error_message,
                exception_type=exception_type,
            )

        def _audit_skip(*, error_message: str) -> None:
            self.host.runtime.store.try_append_sealed_apply_audit(
                action="uplink_watchdog.reapply",
                outcome="skipped",
                route="remembered-uplink",
                verb="watchdog_reapply",
                intent_redacted=intent_redacted,
                router_id=router_id,
                correlation_id=None,
                result_payload=None,
                outcome_snapshot=None,
                error_message=error_message,
                exception_type=None,
            )

        def _run() -> None:
            expected_ssid = str(remembered.get("ssid") or "").strip()
            expected_band = str(remembered.get("band") or "")
            expected_cred_ref = remembered.get("credential_ref_id")
            fresh = self.host.runtime.remembered_uplink.get_remembered()
            if not fresh.get("desired_active"):
                _audit_failure(error_message="remembered uplink desired cleared under lock")
                outcome_holder[0] = "failed"
                return
            fresh_router_id = fresh.get("router_id")
            if not fresh_router_id or str(fresh_router_id) != router_id:
                _audit_failure(error_message="remembered uplink router mismatch under lock")
                outcome_holder[0] = "failed"
                return
            if not fresh.get("credential_configured"):
                _audit_failure(
                    error_message="remembered uplink credential not configured under lock"
                )
                outcome_holder[0] = "failed"
                return
            fresh_ssid = str(fresh.get("ssid") or "").strip()
            fresh_band_raw = fresh.get("band")
            fresh_cred_ref = fresh.get("credential_ref_id")
            if not fresh_ssid or not fresh_band_raw or not fresh_cred_ref:
                _audit_failure(error_message="remembered uplink incomplete under lock")
                outcome_holder[0] = "failed"
                return
            if (
                fresh_ssid != expected_ssid
                or str(fresh_band_raw) != expected_band
                or str(fresh_cred_ref) != str(expected_cred_ref)
            ):
                _audit_failure(error_message="remembered uplink identity changed under lock")
                outcome_holder[0] = "failed"
                return
            try:
                fresh_band = WifiBand(str(fresh_band_raw))
            except ValueError:
                _audit_failure(error_message="remembered uplink incomplete under lock")
                outcome_holder[0] = "failed"
                return
            apply_intent = UplinkIntent(
                mode=UplinkMode.WIFI_WAN,
                ssid=fresh_ssid,
                band=fresh_band,
                credential_ref_id=str(fresh_cred_ref),
            )
            intent_redacted["ssid"] = fresh.get("ssid")
            intent_redacted["band"] = fresh.get("band")
            intent_redacted["credential_ref_id"] = fresh.get("credential_ref_id")
            if self.observe_transport_factory is None:
                _audit_failure(error_message="observe transport unavailable under lock")
                outcome_holder[0] = "failed"
                return
            observe_transport = self.observe_transport_factory(router_id)
            if observe_transport is None:
                _audit_failure(error_message="observe transport unavailable under lock")
                outcome_holder[0] = "failed"
                return
            observation = run_internet_status_observe(transport=observe_transport)
            if getattr(observation, "read_status", None) == "failed":
                _audit_failure(error_message="gateway observe failed under lock")
                outcome_holder[0] = "failed"
                return
            gateway = getattr(observation, "gateway_interface", None)
            gateway_s = str(gateway) if gateway is not None else None
            if is_wireguard_like_gateway(gateway_s):
                _audit_skip(error_message="gateway is WireGuard under lock")
                outcome_holder[0] = "skipped"
                return
            if is_ethernet_like_gateway(gateway_s):
                _audit_skip(error_message="gateway is ethernet under lock")
                outcome_holder[0] = "skipped"
                return
            expected_station = fresh.get("station_id")
            if gateway_matches_remembered_station(
                gateway_s,
                expected_station_id=str(expected_station) if expected_station else None,
            ):
                _audit_skip(
                    error_message="gateway matches remembered station under lock"
                )
                outcome_holder[0] = "skipped"
                return
            backup_cb: BackupCallback | None = None
            if self.backup_callback_factory is not None:
                backup_cb = self.backup_callback_factory(router_id)
            if backup_cb is None:
                _audit_failure(error_message="startup-config backup unavailable")
                outcome_holder[0] = "failed"
                return
            sealed_apply_params = SealedApplyTrailParams(
                route="remembered-uplink",
                verb="watchdog_reapply",
                intent_redacted=intent_redacted,
                router_id=router_id,
            )
            try:
                result = apply_wifi_station_intent(
                    intent=apply_intent,
                    transport=transport,
                    credential_resolver=credential_resolver,
                    live_dispatch=True,
                    backup_callback=backup_cb,
                    compensate_on_failure=True,
                    idempotent=True,
                    uplink_settle_seconds=25.0,
                    store=self.host.runtime.store,
                    sealed_apply_params=sealed_apply_params,
                )
            except StartupBackupError as exc:
                _audit_failure(
                    error_message="startup-config backup unavailable",
                    exception_type=type(exc).__name__,
                )
                outcome_holder[0] = "failed"
                return
            except SealedApplyTrailBeginError as exc:
                _audit_failure(
                    error_message="Sealed apply trail begin failed",
                    exception_type=type(exc).__name__,
                )
                outcome_holder[0] = "failed"
                return
            outcome_holder[0] = result.overall
            self.host.runtime.store.try_append_sealed_apply_audit(
                action="uplink_watchdog.reapply",
                outcome=result.overall,
                route="remembered-uplink",
                verb="watchdog_reapply",
                intent_redacted=intent_redacted,
                router_id=router_id,
                correlation_id=None,
                result_payload=result.to_dict(),
                outcome_snapshot=None,
                error_message=None,
                exception_type=None,
            )

        run_with_router_apply_lock(router_id, _run)
        return outcome_holder[0]


__all__ = [
    "UPLINK_WATCHDOG_ENABLED",
    "UPLINK_WATCHDOG_POLL_SECONDS",
    "UplinkWatchdogHandle",
    "gateway_matches_remembered_station",
    "is_ethernet_like_gateway",
    "is_wireguard_like_gateway",
    "should_reapply_uplink",
    "should_skip_uplink_reapply",
]
