"""Live pinned-SSH RCI transport helper shared by operator CLIs and the host service.

Builds a host-key-pinned SSH local-forward tunnel to the router's RCI HTTP surface and
yields a source-bound SshTunnelNetcrazeTransport. Password resolution (DPAPI vault or
other) is the caller's responsibility — this helper never reads secret stores.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from router_control.adapters.netcraze.transport import SshTunnelNetcrazeTransport


@contextmanager
def open_pinned_rci_transport(
    *,
    host: str,
    username: str,
    password: str,
    host_key_sha256: str,
    source_address: str | None = None,
    allow_non_private: bool = False,
) -> Iterator[SshTunnelNetcrazeTransport]:
    """Yield a source-bound, host-key-pinned RCI transport over an SSH local forward."""
    from router_control.adapters.netcraze.ssh_tunnel import (
        PinnedSshTunnel,
        SshTunnelConfig,
        preflight_source_address_bind,
        validate_source_address,
    )
    from router_control.adapters.netcraze.transport import (
        SshTunnelNetcrazeTransport,
        derive_management_host_header,
        parse_transport_target,
    )

    target = parse_transport_target(host)
    ssh_host = target.hostname
    management_header = derive_management_host_header(host)

    validated_source: str | None = None
    if source_address:
        validated_source = validate_source_address(source_address)
        preflight_source_address_bind(validated_source)

    tunnel_config = SshTunnelConfig(
        ssh_host=ssh_host,
        username=username,
        password=password,
        host_key_sha256=host_key_sha256,
        source_address=validated_source,
        allow_non_private=allow_non_private,
    )
    with PinnedSshTunnel(tunnel_config) as tunnel:
        transport = SshTunnelNetcrazeTransport(
            host=tunnel.local_host,
            port=tunnel.local_port,
            use_tls=False,
            username=username,
            password=password,
            management_host_header=management_header,
            ssh_host_key_algorithm=tunnel.host_key_algorithm,
            ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
            source_address=validated_source or "",
        )
        yield transport


__all__ = ["open_pinned_rci_transport"]
