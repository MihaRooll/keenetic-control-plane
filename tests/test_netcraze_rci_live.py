"""Synthetic tests for open_pinned_rci_transport (no live network)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
from router_control.adapters.netcraze.ssh_tunnel import SshSourceAddressInvalid
from router_control.adapters.netcraze.transport import SshTunnelNetcrazeTransport
from router_control_host.wifi_live_transport import connection_params_from_fields

_GATE_A_STYLE_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
_LAB_SOURCE = "192.168.1.144"


def _fake_tunnel() -> MagicMock:
    tunnel = MagicMock()
    tunnel.local_host = "127.0.0.1"
    tunnel.local_port = 54321
    tunnel.host_key_algorithm = "ssh-ed25519"
    tunnel.host_key_fingerprint_sha256 = _GATE_A_STYLE_PIN
    tunnel.__enter__.return_value = tunnel
    tunnel.__exit__.return_value = None
    return tunnel


def _open_with_mocked_tunnel(
    *,
    source_address: str | None = None,
) -> SshTunnelNetcrazeTransport:
    fake_tunnel = _fake_tunnel()
    patches = [
        patch(
            "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
            return_value=fake_tunnel,
        ),
    ]
    if source_address is not None:
        patches.extend(
            [
                patch(
                    "router_control.adapters.netcraze.ssh_tunnel.validate_source_address",
                    side_effect=lambda value, **_: value,
                ),
                patch(
                    "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
                    side_effect=lambda value, **_: value,
                ),
            ]
        )
    for item in patches:
        item.start()
    try:
        with open_pinned_rci_transport(
            host="192.168.1.1",
            username="lab-user",
            password="test-password",
            host_key_sha256=_GATE_A_STYLE_PIN,
            source_address=source_address,
        ) as transport:
            return transport
    finally:
        for item in reversed(patches):
            item.stop()


def test_open_pinned_rci_transport_propagates_source_address() -> None:
    transport = _open_with_mocked_tunnel(source_address=_LAB_SOURCE)
    assert transport.source_address == _LAB_SOURCE


def test_open_pinned_rci_transport_without_source_address_stays_empty() -> None:
    """CLI rci_live helper may omit source; hub Wi-Fi live path must not."""
    transport = _open_with_mocked_tunnel(source_address=None)
    assert transport.source_address == ""

    params = connection_params_from_fields(
        host="192.168.2.1",
        username="admin",
        router_credential_ref_id="cred-1",
        ssh_host_key_sha256=_GATE_A_STYLE_PIN,
        source_address=None,
    )
    assert params is None


def test_open_pinned_rci_transport_rejects_invalid_source_before_tunnel() -> None:
    fake_tunnel = _fake_tunnel()
    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
        return_value=fake_tunnel,
    ) as tunnel_cls:
        with pytest.raises(SshSourceAddressInvalid, match="private unicast"):
            with open_pinned_rci_transport(
                host="192.168.1.1",
                username="lab-user",
                password="test-password",
                host_key_sha256=_GATE_A_STYLE_PIN,
                source_address="8.8.8.8",
            ):
                pass
    tunnel_cls.assert_not_called()
