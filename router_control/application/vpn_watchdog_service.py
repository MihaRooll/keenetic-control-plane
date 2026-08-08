"""Env-gated VPN tunnel watchdog — bounded poll, unhealthy streak, shared apply lock."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from router_control.adapters.netcraze.startup_backup import StartupBackupError
from router_control.application.recovery import SealedApplyTrailParams
from router_control.application.router_apply_lock import run_with_router_apply_lock
from router_control.application.vpn_assignment_helpers import (
    coerce_peer_rci_shape,
    resolve_assignment_wg_id,
)
from router_control.application.vpn_credential_usability import vpn_secret_refs_usable
from router_control.application.wireguard_apply_planner import (
    WG_HANDSHAKE_SETTLE_SECONDS_MIN,
    clamp_handshake_settle_seconds,
)
from router_control.application.wireguard_apply_service import (
    WireguardApplyTransport,
    _extract_show_interface_observed,
    _observe_tunnel_with_optional_recheck,
    apply_wireguard_intent,
)
from router_control.domain.network_intents import WireguardIntent
from router_control.persistence.errors import SealedApplyTrailBeginError

_LOGGER = logging.getLogger(__name__)

VPN_WATCHDOG_ENABLED = os.environ.get("VPN_WATCHDOG_ENABLED", "").strip().lower() in (
    "1",
    "true",
    "yes",
)
VPN_WATCHDOG_POLL_SECONDS = max(
    5.0,
    float(os.environ.get("VPN_WATCHDOG_POLL_SECONDS", "45") or "45"),
)
_UNHEALTHY_STREAK_THRESHOLD = 2
_BACKOFF_BASE_SECONDS = VPN_WATCHDOG_POLL_SECONDS
_BACKOFF_MAX_SECONDS = 600.0

CredentialResolver = Callable[[str], str]
TransportFactory = Callable[[str], WireguardApplyTransport | None]
BackupCallback = Callable[[], None]
BackupCallbackFactory = Callable[[str], BackupCallback | None]


class WatchdogHost(Protocol):
    runtime: Any


@dataclass
class _RouterWatchState:
    unhealthy_streak: int = 0
    backoff_seconds: float = _BACKOFF_BASE_SECONDS
    next_poll_at: float = 0.0


@dataclass
class VpnWatchdogHandle:
    host: WatchdogHost
    transport_factory: TransportFactory | None = None
    credential_resolver: CredentialResolver | None = None
    backup_callback_factory: BackupCallbackFactory | None = None
    _task: asyncio.Task[None] | None = field(default=None, init=False)
    _stop: asyncio.Event = field(default_factory=asyncio.Event, init=False)
    _states: dict[str, _RouterWatchState] = field(default_factory=dict, init=False)

    def status_payload(self) -> dict[str, Any]:
        running = self._task is not None and not self._task.done()
        return {
            "vpn_watchdog_enabled": VPN_WATCHDOG_ENABLED,
            "vpn_watchdog_poll_seconds": VPN_WATCHDOG_POLL_SECONDS,
            "vpn_watchdog_running": running,
        }

    def start(self) -> None:
        if not VPN_WATCHDOG_ENABLED:
            return
        if self._task is not None and not self._task.done():
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run_loop(), name="vpn-watchdog")

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
                _LOGGER.exception("vpn watchdog poll loop failed")
                try:
                    self.host.runtime.store.try_append_sealed_apply_audit(
                        action="vpn_watchdog.poll",
                        outcome="failed",
                        route="vpn-watchdog",
                        verb="watchdog_poll",
                        intent_redacted={},
                        router_id=None,
                        correlation_id=None,
                        result_payload=None,
                        outcome_snapshot=None,
                        error_message="vpn watchdog poll loop failed",
                        exception_type="Exception",
                    )
                except Exception:
                    _LOGGER.exception("vpn watchdog poll failure audit append failed")
            try:
                await asyncio.wait_for(self._stop.wait(), timeout=VPN_WATCHDOG_POLL_SECONDS)
                break
            except TimeoutError:
                continue

    async def _poll_once(self) -> None:
        if self.transport_factory is None:
            return
        store = self.host.runtime.store
        loop = asyncio.get_running_loop()
        now = loop.time()
        for row in store.list_routers(limit=500):
            router_id = str(row["router_id"])
            assignment = store.get_active_tunnel_assignment(router_id)
            if assignment is None:
                self._states.pop(router_id, None)
                continue
            state = self._states.setdefault(router_id, _RouterWatchState())
            if now < state.next_poll_at:
                continue
            intent = self._intent_from_assignment(assignment, store)
            if intent is None:
                continue
            transport = self.transport_factory(router_id)
            if transport is None:
                continue
            healthy = await asyncio.to_thread(
                self._probe_tunnel_healthy,
                transport,
                intent,
            )
            if healthy:
                state.unhealthy_streak = 0
                state.backoff_seconds = _BACKOFF_BASE_SECONDS
                state.next_poll_at = now + VPN_WATCHDOG_POLL_SECONDS
                continue
            state.unhealthy_streak += 1
            if state.unhealthy_streak >= _UNHEALTHY_STREAK_THRESHOLD:
                overall, tvs = await asyncio.to_thread(
                    self._reapply_locked,
                    router_id,
                    intent,
                    transport,
                    assignment,
                )
                if overall == "applied" and tvs == "tunnel_healthy":
                    state.unhealthy_streak = 0
                    state.backoff_seconds = _BACKOFF_BASE_SECONDS
                    state.next_poll_at = now + VPN_WATCHDOG_POLL_SECONDS
                else:
                    state.backoff_seconds = min(
                        state.backoff_seconds * 2.0,
                        _BACKOFF_MAX_SECONDS,
                    )
                    state.next_poll_at = now + state.backoff_seconds
            else:
                state.next_poll_at = now + VPN_WATCHDOG_POLL_SECONDS

    def _resolve_credentials(self) -> CredentialResolver:
        if self.credential_resolver is not None:
            return self.credential_resolver
        vault = self.host.runtime.vault

        def resolve(ref_id: str) -> str:
            return str(vault.use(ref_id))

        return resolve

    def _probe_tunnel_healthy(
        self,
        transport: WireguardApplyTransport,
        intent: WireguardIntent,
    ) -> bool:
        raw = transport.execute_rci_parse(f"show interface {intent.wg_id}")
        observed = _extract_show_interface_observed(
            raw,
            match_peer_public_key=intent.peer_public_key,
        )
        tunnel_status, _final_observed, _explanation = _observe_tunnel_with_optional_recheck(
            transport,
            wg_id=intent.wg_id,
            observed=observed,
            handshake_settle_seconds=clamp_handshake_settle_seconds(
                WG_HANDSHAKE_SETTLE_SECONDS_MIN
            ),
            logs=[],
            match_peer_public_key=intent.peer_public_key,
            trail=None,
        )
        return tunnel_status == "tunnel_healthy"

    def _intent_from_assignment(
        self,
        assignment: dict[str, Any],
        store: Any,
    ) -> WireguardIntent | None:
        profile = store.get_profile(str(assignment["profile_id"]))
        if profile is None:
            return None
        metadata = json.loads(profile["metadata_json"] or "{}")
        refs = store.list_profile_secret_refs(str(assignment["profile_id"]))
        private_ref: str | None = None
        psk_ref: str | None = None
        for ref in refs:
            role = str(ref["role"])
            if role == "PrivateKey":
                private_ref = str(ref["credential_ref_id"])
            elif role == "PresharedKey":
                psk_ref = str(ref["credential_ref_id"])
        if not vpn_secret_refs_usable(store, private_ref, psk_ref):
            return None
        asc_raw = metadata.get("asc9_args")
        asc_args = tuple(asc_raw) if isinstance(asc_raw, list) else None
        wg_id = resolve_assignment_wg_id(assignment, profile_metadata=metadata)
        if not wg_id:
            return None
        ip_global_priority = metadata.get("ip_global_priority")
        metadata_keepalive = metadata.get("peer_keepalive_interval")
        return WireguardIntent(
            wg_id=wg_id,
            enabled=True,
            asc_args=asc_args,
            private_key_credential_ref_id=private_ref,
            preshared_key_credential_ref_id=psk_ref,
            peer_public_key=metadata.get("peer_public_key"),
            peer_endpoint=metadata.get("peer_endpoint"),
            peer_allow_ips=metadata.get("peer_allow_ips"),
            peer_keepalive_interval=(
                metadata_keepalive
                if isinstance(metadata_keepalive, int)
                and not isinstance(metadata_keepalive, bool)
                else None
            ),
            peer_rci_shape=coerce_peer_rci_shape(metadata.get("peer_rci_shape")),
            interface_address=metadata.get("interface_address"),
            ip_global_auto=bool(metadata.get("ip_global_auto", False)),
            ip_global_priority=int(ip_global_priority)
            if isinstance(ip_global_priority, int)
            else None,
            tcp_mss_pmtu=bool(metadata.get("tcp_mss_pmtu", False)),
        )

    def _reapply_locked(
        self,
        router_id: str,
        intent: WireguardIntent,
        transport: WireguardApplyTransport,
        assignment: dict[str, Any],
    ) -> tuple[str | None, str | None]:
        credential_resolver = self._resolve_credentials()
        intent_redacted = {
            "router_id": router_id,
            "profile_id": assignment.get("profile_id"),
            "wg_id": intent.wg_id,
        }
        outcome_holder: list[tuple[str | None, str | None]] = [(None, None)]

        def _audit_failure(
            *,
            error_message: str,
            exception_type: str | None = None,
        ) -> None:
            self.host.runtime.store.try_append_sealed_apply_audit(
                action="vpn_watchdog.reapply",
                outcome="failed",
                route="vpn-profiles",
                verb="watchdog_reapply",
                intent_redacted=intent_redacted,
                router_id=router_id,
                correlation_id=None,
                result_payload=None,
                outcome_snapshot=None,
                error_message=error_message,
                exception_type=exception_type,
            )

        def _run() -> None:
            expected_profile_id = assignment.get("profile_id")
            logical_role = str(assignment.get("logical_role") or "primary")
            fresh_assignment = self.host.runtime.store.get_active_tunnel_assignment(
                router_id, logical_role=logical_role
            )
            if fresh_assignment is None:
                _audit_failure(error_message="active tunnel assignment missing under lock")
                outcome_holder[0] = ("failed", None)
                return
            if str(fresh_assignment["profile_id"]) != str(expected_profile_id):
                _audit_failure(error_message="tunnel assignment profile changed under lock")
                outcome_holder[0] = ("failed", None)
                return
            apply_intent = self._intent_from_assignment(
                fresh_assignment, self.host.runtime.store
            )
            if apply_intent is None:
                _audit_failure(
                    error_message="cannot rebuild WireGuard intent from fresh assignment"
                )
                outcome_holder[0] = ("failed", None)
                return
            intent_redacted["wg_id"] = apply_intent.wg_id
            backup_cb: BackupCallback | None = None
            if self.backup_callback_factory is not None:
                backup_cb = self.backup_callback_factory(router_id)
            if backup_cb is None:
                _audit_failure(error_message="startup-config backup unavailable")
                outcome_holder[0] = ("failed", None)
                return
            sealed_apply_params = SealedApplyTrailParams(
                route="vpn-profiles",
                verb="watchdog_reapply",
                intent_redacted=intent_redacted,
                router_id=router_id,
            )
            try:
                result = apply_wireguard_intent(
                    intent=apply_intent,
                    transport=transport,
                    credential_resolver=credential_resolver,
                    backup_callback=backup_cb,
                    handshake_settle_seconds=clamp_handshake_settle_seconds(
                        WG_HANDSHAKE_SETTLE_SECONDS_MIN
                    ),
                    store=self.host.runtime.store,
                    sealed_apply_params=sealed_apply_params,
                )
            except StartupBackupError as exc:
                _audit_failure(
                    error_message="startup-config backup unavailable",
                    exception_type=type(exc).__name__,
                )
                outcome_holder[0] = ("failed", None)
                return
            except SealedApplyTrailBeginError as exc:
                _audit_failure(
                    error_message="Sealed apply trail begin failed",
                    exception_type=type(exc).__name__,
                )
                outcome_holder[0] = ("failed", None)
                return
            outcome_holder[0] = (result.overall, result.tunnel_verification_status)
            self.host.runtime.store.try_append_sealed_apply_audit(
                action="vpn_watchdog.reapply",
                outcome=result.overall,
                route="vpn-profiles",
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
    "VPN_WATCHDOG_ENABLED",
    "VPN_WATCHDOG_POLL_SECONDS",
    "VpnWatchdogHandle",
]
