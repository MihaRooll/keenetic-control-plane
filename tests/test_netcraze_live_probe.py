"""Synthetic tests for build_pinned_ssh_probe_fn source_address propagation."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.live_probe import LiveProbeTarget, build_pinned_ssh_probe_fn
from router_control.domain.ids import RouterId

_GATE_A_STYLE_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
_LAB_SOURCE = "192.168.1.144"


def _open_gate_a() -> GateACertification:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="test",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-test",
        bsp_build="0-test",
        update_channel="Main",
        region="EA",
        component_set_digest="a" * 64,
        device_fingerprint_digest="b" * 64,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=_GATE_A_STYLE_PIN,
        certification_eligible=True,
        evidence_recorded_at=now,
        evidence_path="data/artifacts/gate-a-probe.json",
        expires_at=now + timedelta(days=90),
        revocation_policy="human",
        gates_b_closed=True,
        gates_c_closed=True,
        gates_d_closed=True,
    )


def _fake_tunnel() -> MagicMock:
    tunnel = MagicMock()
    tunnel.local_host = "127.0.0.1"
    tunnel.local_port = 54321
    tunnel.host_key_algorithm = "ssh-ed25519"
    tunnel.host_key_fingerprint_sha256 = _GATE_A_STYLE_PIN
    tunnel.__enter__.return_value = tunnel
    tunnel.__exit__.return_value = None
    return tunnel


def test_live_probe_propagates_source_address_to_transport() -> None:
    captured: dict[str, str] = {}
    fake_tunnel = _fake_tunnel()
    vault = MagicMock()
    vault.use.return_value = "lab-password"
    clock = MagicMock()

    class CapturingAdapter:
        def __init__(self, *, router_id, transport, clock, identity_hints=None) -> None:
            captured["source_address"] = transport.source_address

        def probe_gate_a_evidence(self) -> dict[str, object]:
            return {"model": "NC-1812"}

    with patch(
        "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
        return_value=fake_tunnel,
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.validate_source_address",
        side_effect=lambda value, **_: value,
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.preflight_source_address_bind",
        side_effect=lambda value, **_: value,
    ), patch(
        "router_control.adapters.netcraze.adapter.NetcrazeReadOnlyAdapter",
        CapturingAdapter,
    ), patch(
        "router_control.adapters.netcraze.live_probe.GateACertification.matches_probe_evidence",
        return_value=True,
    ):
        probe_fn = build_pinned_ssh_probe_fn(_open_gate_a(), vault=vault, clock=clock)
        probe_fn(
            LiveProbeTarget(
                ssh_host="192.168.1.1",
                username="lab-user",
                credential_ref_id="cred-test",
                router_id=RouterId("router-test"),
                source_address=_LAB_SOURCE,
            )
        )

    assert captured["source_address"] == _LAB_SOURCE
