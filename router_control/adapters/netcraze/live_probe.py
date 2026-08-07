"""Live read-only probe — lazy hardware imports, pinned SSH only."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from router_control.adapters.netcraze.certification import GateACertification
from router_control.domain.ids import RouterId
from router_control.ports.clock import ClockPort
from router_control.ports.vault import CredentialVaultPort

if TYPE_CHECKING:
    from router_control.application.router_discovery import CandidateProbeTarget


class ReadOnlyProbeFn(Protocol):
    def __call__(self, target: LiveProbeTarget) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class LiveProbeTarget:
    ssh_host: str
    username: str
    credential_ref_id: str
    router_id: RouterId
    source_address: str | None = None


def collect_pinned_ssh_probe_evidence(
    target: LiveProbeTarget,
    certification: GateACertification,
    *,
    vault: CredentialVaultPort,
    clock: ClockPort,
) -> dict[str, object]:
    """Run bounded RO probe; returns evidence without tuple match enforcement."""
    from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
    from router_control.adapters.netcraze.identity import OperatorIdentityHints
    from router_control.adapters.netcraze.ssh_tunnel import (
        PinnedSshTunnel,
        SshTunnelConfig,
        preflight_source_address_bind,
        validate_source_address,
    )
    from router_control.adapters.netcraze.transport import (
        NetcrazeTransport,
        SshTunnelNetcrazeTransport,
        derive_management_host_header,
    )

    validated_source: str | None = None
    if target.source_address is not None:
        validated_source = validate_source_address(target.source_address)
        preflight_source_address_bind(validated_source)
    password = vault.use(target.credential_ref_id)
    management_header = derive_management_host_header(target.ssh_host)
    tunnel_config = SshTunnelConfig(
        ssh_host=target.ssh_host,
        username=target.username,
        password=password,
        host_key_sha256=certification.ssh_host_key_fingerprint_sha256,
        source_address=validated_source,
    )
    with PinnedSshTunnel(tunnel_config) as tunnel:
        transport: NetcrazeTransport = SshTunnelNetcrazeTransport(
            host=tunnel.local_host,
            port=tunnel.local_port,
            use_tls=False,
            username=target.username,
            password=password,
            management_host_header=management_header,
            ssh_host_key_algorithm=tunnel.host_key_algorithm,
            ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
            source_address=validated_source or "",
        )
        adapter = NetcrazeReadOnlyAdapter(
            router_id=target.router_id,
            transport=transport,
            clock=clock,
            identity_hints=OperatorIdentityHints(
                expected_model=certification.model,
                update_channel=certification.update_channel,
            ),
        )
        evidence = adapter.probe_gate_a_evidence()
    return dict(evidence)


def build_pinned_ssh_probe_fn(
    certification: GateACertification,
    *,
    vault: CredentialVaultPort,
    clock: ClockPort,
) -> ReadOnlyProbeFn:
    """Return callable that runs bounded RO probe over pinned SSH tunnel."""

    def _probe(target: LiveProbeTarget) -> dict[str, object]:
        evidence = collect_pinned_ssh_probe_evidence(
            target,
            certification,
            vault=vault,
            clock=clock,
        )
        if not certification.matches_probe_evidence(dict(evidence)):
            raise ValueError("live probe identity tuple mismatch")
        return dict(evidence)

    return _probe


@dataclass(frozen=True, slots=True)
class SoftConnectionHealthProbe:
    """Non-raising health probe returning ``{reachable, evidence}``."""

    _certification: GateACertification
    _vault: CredentialVaultPort
    _clock: ClockPort

    def probe(
        self,
        *,
        host: str,
        port: int,
        source_address: str | None,
        router_id: str | None,
        credential_ref_id: str | None,
    ) -> dict[str, Any]:
        import os

        from router_control.adapters.netcraze.errors import (
            AuthFailed,
            NetcrazeAdapterError,
            SshHostKeyMismatch,
            SshHostKeyMissing,
            TransportError,
            TransportTimeout,
        )
        from router_control.adapters.netcraze.ssh_tunnel import (
            SshSourceAddressBindError,
            SshSourceAddressInvalid,
            SshTunnelError,
        )

        if credential_ref_id is None or source_address is None:
            return {"reachable": None, "evidence": None}

        try:
            username = os.environ.get("RC_NETCRAZE_USERNAME", "admin")
            target = LiveProbeTarget(
                ssh_host=host,
                username=username,
                credential_ref_id=credential_ref_id,
                router_id=RouterId(router_id or "health-probe-placeholder"),
                source_address=source_address,
            )
            evidence = collect_pinned_ssh_probe_evidence(
                target,
                self._certification,
                vault=self._vault,
                clock=self._clock,
            )
            return {"reachable": True, "evidence": dict(evidence)}
        except SshHostKeyMismatch:
            return {"reachable": False, "evidence": None}
        except (
            SshHostKeyMissing,
            SshSourceAddressBindError,
            SshSourceAddressInvalid,
            SshTunnelError,
            AuthFailed,
            TransportError,
            TransportTimeout,
            NetcrazeAdapterError,
            OSError,
            ConnectionError,
            TimeoutError,
            ValueError,
        ):
            return {"reachable": False, "evidence": None}


def build_soft_readonly_health_probe_fn(
    certification: GateACertification,
    *,
    vault: CredentialVaultPort,
    clock: ClockPort,
) -> SoftConnectionHealthProbe:
    """Return soft health probe that never raises on tuple mismatch."""
    return SoftConnectionHealthProbe(
        _certification=certification,
        _vault=vault,
        _clock=clock,
    )


@dataclass(frozen=True, slots=True)
class SoftCandidateIdentityProbe:
    """Discovery identity probe — flattens soft health probe for classification."""

    _health_probe: SoftConnectionHealthProbe

    def probe(self, target: CandidateProbeTarget) -> dict[str, Any]:
        result = self._health_probe.probe(
            host=target.host,
            port=target.port,
            source_address=target.source_address,
            router_id=target.router_id,
            credential_ref_id=target.credential_ref_id,
        )
        reachable = result.get("reachable")
        evidence_raw = result.get("evidence")
        if isinstance(evidence_raw, dict):
            flat = dict(evidence_raw)
            flat["reachable"] = reachable
            return flat
        return {"reachable": reachable}


def build_soft_candidate_identity_probe(
    health_probe: SoftConnectionHealthProbe,
) -> SoftCandidateIdentityProbe:
    """Wrap soft health probe as bounded discovery identity probe port."""
    return SoftCandidateIdentityProbe(_health_probe=health_probe)


def run_read_only_probe(
    target: LiveProbeTarget,
    probe_fn: Callable[[LiveProbeTarget], dict[str, object]],
) -> dict[str, object]:
    return probe_fn(target)


__all__ = [
    "LiveProbeTarget",
    "ReadOnlyProbeFn",
    "SoftCandidateIdentityProbe",
    "SoftConnectionHealthProbe",
    "build_pinned_ssh_probe_fn",
    "build_soft_candidate_identity_probe",
    "build_soft_readonly_health_probe_fn",
    "collect_pinned_ssh_probe_evidence",
    "run_read_only_probe",
]
