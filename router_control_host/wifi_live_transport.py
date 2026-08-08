"""Per-request Wi-Fi live RCI transport (win32 + DPAPI + pinned SSH).

Opens a short-lived pinned SSH tunnel for apply/teardown when connection params
are supplied on the request body. Does not read secret stores except via the
injected vault at session open (router password only).
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

if TYPE_CHECKING:
    from router_control.adapters.netcraze.certification import GateACertification
    from router_control.adapters.netcraze.ssh_tunnel import PinnedSshTunnel
    from router_control.adapters.netcraze.transport import SshTunnelNetcrazeTransport
    from router_control.persistence.store import PersistenceStore
    from router_control.ports.clock import Clock


@dataclass(frozen=True, slots=True)
class WifiLiveTransportErrorMapping:
    status_code: int
    code: str
    message: str


class MissingLiveConnectionFieldError(ValueError):
    """Raised when a bound live dial lacks a required connection field."""

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(
            f"live Wi-Fi transport requires {field} for bound SSH dial"
        )


class LiveIdentityTupleMismatchError(RuntimeError):
    """Live Gate A probe evidence does not match the recorded certified tuple."""


class LiveGateARequiredError(RuntimeError):
    """Gate A certification is closed or missing for a live mutation."""


def _is_vault_error(exc: BaseException) -> bool:
    return exc.__class__.__name__ == "VaultError"


_LIVE_PLATFORM_UNSUPPORTED_MESSAGE = (
    "live router transport requires win32 with DPAPI-backed credential vault"
)


def live_connection_incomplete_code(family_prefix: str) -> str:
    return f"{family_prefix}.live_connection_incomplete"


def normalize_live_apply_router_id(router_id: str | None) -> str | None:
    """Return stripped router_id for live sealed-write paths, or None if blank."""
    if router_id is None:
        return None
    stripped = str(router_id).strip()
    return stripped if stripped else None


def live_platform_unsupported_code(family_prefix: str) -> str:
    return f"{family_prefix}.live_platform_unsupported"


def gate_a_required_code(family_prefix: str) -> str:
    return f"{family_prefix}.gate_a_required"


def live_backup_unavailable_code(family_prefix: str) -> str:
    return f"{family_prefix}.live_backup_unavailable"


def identity_mismatch_code(family_prefix: str) -> str:
    return f"{family_prefix}.identity_mismatch"


_IDENTITY_MISMATCH_MESSAGE = (
    "live device identity does not match recorded Gate A tuple"
)


def live_platform_unsupported_message() -> str:
    return _LIVE_PLATFORM_UNSUPPORTED_MESSAGE


def map_wifi_live_transport_error(
    exc: BaseException,
    *,
    router_credential_ref_id: str | None = None,
    code_prefix: str = "wifi",
) -> WifiLiveTransportErrorMapping:
    """Map live transport faults to HTTP status/code for a mutation/read family."""
    from router_control.adapters.netcraze.errors import SshHostKeyMismatch

    ref_id = (router_credential_ref_id or "").strip() or "unknown"
    prefix = code_prefix.strip(".") or "wifi"

    if isinstance(exc, SshHostKeyMismatch):
        return WifiLiveTransportErrorMapping(
            status_code=422,
            code=f"{prefix}.ssh_host_key_mismatch",
            message="SSH host key fingerprint mismatch; connection refused",
        )

    if _is_vault_error(exc):
        msg = str(exc).lower()
        if "not found" in msg:
            return WifiLiveTransportErrorMapping(
                status_code=404,
                code=f"{prefix}.credential_not_found",
                message=(
                    f"router credential reference not found: "
                    f"router_credential_ref_id={ref_id}"
                ),
            )
        return WifiLiveTransportErrorMapping(
            status_code=400,
            code=f"{prefix}.credential_unusable",
            message=(
                f"router credential unusable: router_credential_ref_id={ref_id}"
            ),
        )

    if isinstance(exc, MissingLiveConnectionFieldError):
        return WifiLiveTransportErrorMapping(
            status_code=422,
            code=f"{prefix}.live_connection_incomplete",
            message=(
                f"incomplete live connection params; missing: {exc.field}"
            ),
        )

    if isinstance(exc, LiveGateARequiredError):
        return WifiLiveTransportErrorMapping(
            status_code=503,
            code=gate_a_required_code(prefix),
            message=str(exc) or "Gate A certification required for live mutation",
        )

    return WifiLiveTransportErrorMapping(
        status_code=503,
        code=f"{prefix}.live_transport_failed",
        message=f"live transport failed: {exc.__class__.__name__}",
    )


class VaultUseFn(Protocol):
    def use(self, ref_id: str) -> str: ...


_SOURCE_ADDRESS_UNSPECIFIED = object()


@dataclass(frozen=True, slots=True)
class WifiLiveConnectionParams:
    host: str
    username: str
    router_credential_ref_id: str
    ssh_host_key_sha256: str
    source_address: str | None = None


@dataclass(frozen=True, slots=True)
class WifiLiveSession:
    transport: SshTunnelNetcrazeTransport
    tunnel: PinnedSshTunnel


def is_win32_live_capable() -> bool:
    return sys.platform == "win32"


def params_complete(
    *,
    host: str | None,
    username: str | None,
    router_credential_ref_id: str | None,
    ssh_host_key_sha256: str | None,
    source_address: str | None = None,
) -> bool:
    return bool(
        host
        and str(host).strip()
        and username
        and str(username).strip()
        and router_credential_ref_id
        and str(router_credential_ref_id).strip()
        and ssh_host_key_sha256
        and str(ssh_host_key_sha256).strip()
        and source_address
        and str(source_address).strip()
    )


def _resolve_management_username(
    *,
    username: str | None,
    router_id: str | None,
    store: PersistenceStore | None,
) -> str | None:
    if username and str(username).strip():
        return str(username).strip()
    if store is None or not router_id or not str(router_id).strip():
        return None
    stored = store.get_endpoint_management_username(str(router_id).strip())
    return stored if stored else None


def _resolve_connection_endpoint_fields(
    *,
    host: str | None,
    source_address: str | None,
    router_id: str | None,
    store: PersistenceStore | None,
) -> tuple[str | None, str | None]:
    """Resolve host/source from store when router_id is known (SSRF-safe binding)."""
    explicit_host = str(host).strip() if host and str(host).strip() else None
    explicit_source = (
        str(source_address).strip()
        if source_address and str(source_address).strip()
        else None
    )
    if store is not None and router_id and str(router_id).strip():
        endpoint = store.get_connection_binding_endpoint(str(router_id).strip())
        if endpoint is not None:
            ep_host = str(endpoint["host"]).strip() if endpoint["host"] else None
            ep_source = (
                str(endpoint["source_address"]).strip()
                if endpoint["source_address"]
                else None
            )
            return ep_host or explicit_host, ep_source or explicit_source
    return explicit_host, explicit_source


def connection_fields_present(
    *,
    host: str | None,
    username: str | None,
    router_credential_ref_id: str | None,
    ssh_host_key_sha256: str | None,
    source_address: str | None = None,
    router_id: str | None = None,
) -> bool:
    for value in (
        host,
        username,
        router_credential_ref_id,
        ssh_host_key_sha256,
        source_address,
        router_id,
    ):
        if value is not None and str(value).strip():
            return True
    return False


def missing_connection_fields(
    *,
    host: str | None,
    username: str | None,
    router_credential_ref_id: str | None,
    ssh_host_key_sha256: str | None,
    source_address: str | None | object = _SOURCE_ADDRESS_UNSPECIFIED,
    router_id: str | None = None,
    store: PersistenceStore | None = None,
) -> list[str]:
    explicit_source = (
        None
        if source_address is _SOURCE_ADDRESS_UNSPECIFIED
        else cast(str | None, source_address)
    )
    resolved_host, resolved_source = _resolve_connection_endpoint_fields(
        host=host,
        source_address=explicit_source,
        router_id=router_id,
        store=store,
    )
    resolved_pin = _resolve_ssh_host_key_pin(
        ssh_host_key_sha256=ssh_host_key_sha256,
        router_id=router_id,
        store=store,
        host=host,
    )
    resolved_username = _resolve_management_username(
        username=username,
        router_id=router_id,
        store=store,
    )
    missing: list[str] = []
    if not resolved_host:
        missing.append("host")
    if not resolved_username:
        missing.append("username")
    if not router_credential_ref_id or not str(router_credential_ref_id).strip():
        missing.append("router_credential_ref_id")
    if not resolved_pin or not str(resolved_pin).strip():
        missing.append("ssh_host_key_sha256")
    require_source = source_address is not _SOURCE_ADDRESS_UNSPECIFIED or (
        store is not None and router_id and str(router_id).strip()
    )
    if require_source and not resolved_source:
        missing.append("source_address")
    return missing


def _resolve_ssh_host_key_pin(
    *,
    ssh_host_key_sha256: str | None,
    router_id: str | None,
    store: PersistenceStore | None,
    host: str | None = None,
) -> str | None:
    from router_control.adapters.netcraze.errors import SshHostKeyMissing
    from router_control.application.ssh_host_key_pin import resolve_ssh_host_key_sha256

    if store is None:
        if ssh_host_key_sha256 and str(ssh_host_key_sha256).strip():
            return str(ssh_host_key_sha256).strip()
        return None
    try:
        return resolve_ssh_host_key_sha256(
            explicit=ssh_host_key_sha256,
            router_id=router_id,
            store=store,
            host=host,
        )
    except SshHostKeyMissing:
        return None


def incomplete_live_connection_fields(
    *,
    host: str | None,
    username: str | None,
    router_credential_ref_id: str | None,
    ssh_host_key_sha256: str | None,
    source_address: str | None = None,
    router_id: str | None = None,
    store: PersistenceStore | None = None,
) -> list[str]:
    """When any live connection field is present, return missing required fields."""
    if not connection_fields_present(
        host=host,
        username=username,
        router_credential_ref_id=router_credential_ref_id,
        ssh_host_key_sha256=ssh_host_key_sha256,
        source_address=source_address,
        router_id=router_id,
    ):
        return []
    return missing_connection_fields(
        host=host,
        username=username,
        router_credential_ref_id=router_credential_ref_id,
        ssh_host_key_sha256=ssh_host_key_sha256,
        source_address=source_address,
        router_id=router_id,
        store=store,
    )


def connection_params_from_fields(
    *,
    host: str | None,
    username: str | None,
    router_credential_ref_id: str | None,
    ssh_host_key_sha256: str | None,
    source_address: str | None = None,
    router_id: str | None = None,
    store: PersistenceStore | None = None,
) -> WifiLiveConnectionParams | None:
    resolved_host, resolved_source = _resolve_connection_endpoint_fields(
        host=host,
        source_address=source_address,
        router_id=router_id,
        store=store,
    )
    resolved_pin = _resolve_ssh_host_key_pin(
        ssh_host_key_sha256=ssh_host_key_sha256,
        router_id=router_id,
        store=store,
        host=host,
    )
    resolved_username = _resolve_management_username(
        username=username,
        router_id=router_id,
        store=store,
    )
    if not params_complete(
        host=resolved_host,
        username=resolved_username,
        router_credential_ref_id=router_credential_ref_id,
        ssh_host_key_sha256=resolved_pin,
        source_address=resolved_source,
    ):
        return None
    return WifiLiveConnectionParams(
        host=str(resolved_host).strip(),
        username=str(resolved_username).strip(),
        router_credential_ref_id=str(router_credential_ref_id).strip(),
        ssh_host_key_sha256=str(resolved_pin).strip(),
        source_address=resolved_source,
    )


@contextmanager
def open_wifi_live_session(
    *,
    params: WifiLiveConnectionParams,
    vault: VaultUseFn,
) -> Iterator[WifiLiveSession]:
    """Resolve router password via vault, open pinned tunnel, yield transport + tunnel."""
    from router_control.adapters.netcraze.ssh_tunnel import PinnedSshTunnel, SshTunnelConfig
    from router_control.adapters.netcraze.transport import (
        derive_management_host_header,
        parse_transport_target,
    )

    password = vault.use(params.router_credential_ref_id)
    target = parse_transport_target(params.host)
    management_header = derive_management_host_header(params.host)

    if not params.source_address or not str(params.source_address).strip():
        raise MissingLiveConnectionFieldError("source_address")

    from router_control.adapters.netcraze.ssh_tunnel import (
        preflight_source_address_bind,
        validate_source_address,
    )

    validated_source = validate_source_address(params.source_address)
    preflight_source_address_bind(validated_source)

    tunnel_config = SshTunnelConfig(
        ssh_host=target.hostname,
        username=params.username,
        password=password,
        host_key_sha256=params.ssh_host_key_sha256,
        source_address=validated_source,
        allow_non_private=False,
    )

    with PinnedSshTunnel(tunnel_config) as tunnel:
        from router_control.adapters.netcraze.transport import SshTunnelNetcrazeTransport

        transport = SshTunnelNetcrazeTransport(
            host=tunnel.local_host,
            port=tunnel.local_port,
            use_tls=False,
            username=params.username,
            password=password,
            management_host_header=management_header,
            ssh_host_key_algorithm=tunnel.host_key_algorithm,
            ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
            source_address=validated_source,
        )
        yield WifiLiveSession(transport=transport, tunnel=tunnel)


def ensure_live_gate_a_tuple_match(
    session: WifiLiveSession,
    certification: GateACertification,
    *,
    clock: Clock | None = None,
    router_id: str | None = None,
) -> None:
    """Probe live device tuple via open session; fail-closed before backup/mutation."""
    from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
    from router_control.adapters.netcraze.identity import OperatorIdentityHints
    from router_control.domain.ids import RouterId
    from router_control.ports.clock import SystemClock

    resolved_clock = clock or SystemClock()
    rid = RouterId(router_id.strip()) if router_id and str(router_id).strip() else RouterId(
        "live-apply-probe"
    )
    adapter = NetcrazeReadOnlyAdapter(
        router_id=rid,
        transport=session.transport,
        clock=resolved_clock,
        identity_hints=OperatorIdentityHints(
            expected_model=certification.model,
            update_channel=certification.update_channel,
        ),
    )
    evidence = dict(adapter.probe_gate_a_evidence())
    if not certification.matches_probe_evidence(evidence):
        raise LiveIdentityTupleMismatchError(_IDENTITY_MISMATCH_MESSAGE)


__all__ = [
    "LiveGateARequiredError",
    "LiveIdentityTupleMismatchError",
    "MissingLiveConnectionFieldError",
    "WifiLiveConnectionParams",
    "WifiLiveSession",
    "WifiLiveTransportErrorMapping",
    "connection_fields_present",
    "connection_params_from_fields",
    "ensure_live_gate_a_tuple_match",
    "identity_mismatch_code",
    "incomplete_live_connection_fields",
    "is_win32_live_capable",
    "gate_a_required_code",
    "live_backup_unavailable_code",
    "live_connection_incomplete_code",
    "live_platform_unsupported_code",
    "live_platform_unsupported_message",
    "map_wifi_live_transport_error",
    "missing_connection_fields",
    "normalize_live_apply_router_id",
    "open_wifi_live_session",
    "params_complete",
]
