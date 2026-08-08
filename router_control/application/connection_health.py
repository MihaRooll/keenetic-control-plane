"""Fact-derived connection health summary — read-only, non-certifying."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

from router_control.adapters.netcraze.certification import (
    GateACertification,
    try_load_gate_a_certification,
)
from router_control.adapters.netcraze.ssh_tunnel import (
    host_is_private,
    normalize_sha256_fingerprint,
    validate_source_address,
)
from router_control.adapters.netcraze.transport import normalize_management_host as _normalize_host
from router_control.persistence.store import PersistenceStore
from router_control.ports.vault import CredentialVaultPort

HealthStatus = Literal["green", "yellow", "red"]


class ConnectionHealthError(Exception):
    """Policy failure during connection health assessment."""


@dataclass(frozen=True, slots=True)
class ConnectionHealthFacts:
    reachable: bool | None
    host_key_match: bool | None
    tuple_match: bool | None
    credentials_present: bool | None
    evidence_fresh: bool | None

    def to_dict(self) -> dict[str, bool | None]:
        return {
            "reachable": self.reachable,
            "host_key_match": self.host_key_match,
            "tuple_match": self.tuple_match,
            "credentials_present": self.credentials_present,
            "evidence_fresh": self.evidence_fresh,
        }


class ConnectionHealthProbePort(Protocol):
    def probe(
        self,
        *,
        host: str,
        port: int,
        source_address: str | None,
        router_id: str | None,
        credential_ref_id: str | None,
    ) -> dict[str, Any]: ...


class NotConfiguredConnectionHealthProbe:
    def probe(
        self,
        *,
        host: str,
        port: int,
        source_address: str | None,
        router_id: str | None,
        credential_ref_id: str | None,
    ) -> dict[str, Any]:
        raise RuntimeError("probe not configured")


def _resolve_target(
    store: PersistenceStore,
    *,
    router_id: str | None,
    host: str | None,
) -> tuple[str, int, str | None, str | None]:
    if router_id is not None:
        router = store.get_router(router_id)
        if router is None:
            raise ConnectionHealthError("router not found")
        endpoint = store.get_primary_endpoint(router_id)
        if endpoint is None:
            raise ConnectionHealthError("router endpoint not found")
        resolved_host = _normalize_host(str(endpoint["host"]))
        endpoint_source = str(endpoint["source_address"] or "") or None
        return resolved_host, int(endpoint["port"]), router_id, endpoint_source

    if host is None:
        raise ConnectionHealthError("host or router_id is required")

    resolved_host = _normalize_host(host)
    if not resolved_host:
        raise ConnectionHealthError("host must be non-empty")
    if not host_is_private(resolved_host):
        raise ConnectionHealthError("host must be a private management address")

    for router_row in store.list_routers(limit=200):
        rid = str(router_row["router_id"])
        endpoint = store.get_primary_endpoint(rid)
        if endpoint is None:
            continue
        if _normalize_host(str(endpoint["host"])) == resolved_host:
            endpoint_source = str(endpoint["source_address"] or "") or None
            return resolved_host, int(endpoint["port"]), rid, endpoint_source

    raise ConnectionHealthError("host is not a known enrolled endpoint; provide router_id")


def _credentials_present(
    store: PersistenceStore,
    vault: CredentialVaultPort,
    *,
    router_id: str | None,
    credential_ref_id: str | None,
) -> bool:
    ref_id = credential_ref_id
    if ref_id is None and router_id is not None:
        router = store.get_router(router_id)
        if router is not None and router["credential_ref_id"]:
            ref_id = str(router["credential_ref_id"])
        if ref_id is None:
            for row in store.list_credential_refs(router_id):
                if row["revoked_at"] is None:
                    ref_id = str(row["credential_ref_id"])
                    break
    if ref_id is None:
        return False
    cred_row = store.get_credential_ref(ref_id)
    if cred_row is None or cred_row["revoked_at"] is not None:
        return False
    try:
        vault.use(ref_id)
    except Exception:
        return False
    return True


def _expected_host_key_sha256(
    store: PersistenceStore,
    *,
    router_id: str | None,
    override: str | None,
    gate_a: GateACertification | None,
) -> str | None:
    if override is not None and override.strip():
        return normalize_sha256_fingerprint(override)
    if router_id is not None:
        pin = store.get_endpoint_ssh_host_key(router_id)
        if pin is not None:
            return normalize_sha256_fingerprint(pin.fingerprint_sha256)
    if gate_a is not None:
        return normalize_sha256_fingerprint(gate_a.ssh_host_key_fingerprint_sha256)
    return None


def _host_key_match_from_evidence(
    expected: str | None,
    evidence: dict[str, Any] | None,
) -> bool | None:
    if expected is None:
        return None
    if evidence is None:
        return None
    observed = evidence.get("ssh_host_key_fingerprint_sha256")
    if not isinstance(observed, str) or not observed.strip():
        return None
    return normalize_sha256_fingerprint(observed) == expected


def derive_health_status(facts: ConnectionHealthFacts) -> tuple[HealthStatus, str]:
    required = (
        facts.reachable,
        facts.host_key_match,
        facts.tuple_match,
        facts.credentials_present,
        facts.evidence_fresh,
    )
    if all(value is True for value in required):
        return "green", "all_facts_healthy"

    if facts.reachable is False:
        return "red", "unreachable"
    if facts.host_key_match is False:
        return "red", "host_key_mismatch"
    if facts.tuple_match is False:
        return "red", "identity_mismatch"
    if facts.credentials_present is False:
        return "red", "credentials_missing"

    if facts.evidence_fresh is False:
        return "yellow", "evidence_stale"
    if facts.reachable is None:
        return "yellow", "reachability_unknown"
    if facts.host_key_match is None:
        return "yellow", "host_key_unknown"
    if facts.tuple_match is None:
        return "yellow", "tuple_unknown"
    if facts.credentials_present is None:
        return "yellow", "credentials_unknown"
    if facts.evidence_fresh is None:
        return "yellow", "evidence_freshness_unknown"

    return "yellow", "health_incomplete"


def assess_connection_health(
    *,
    store: PersistenceStore,
    vault: CredentialVaultPort,
    router_id: str | None = None,
    host: str | None = None,
    source_address: str | None = None,
    credential_ref_id: str | None = None,
    ssh_host_key_sha256: str | None = None,
    probe: bool = True,
    gate_a: GateACertification | None = None,
    gate_a_loader: Callable[[], GateACertification | None] | None = None,
    probe_port: ConnectionHealthProbePort | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if source_address is not None:
        validate_source_address(source_address)

    resolved_host, port, resolved_router_id, endpoint_source = _resolve_target(
        store,
        router_id=router_id,
        host=host,
    )
    effective_router_id = router_id or resolved_router_id
    bind_source = source_address or endpoint_source

    cert = gate_a
    if cert is None and gate_a_loader is not None:
        cert = gate_a_loader()
    if cert is None and gate_a_loader is None:
        cert = try_load_gate_a_certification()

    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)

    creds_present = _credentials_present(
        store,
        vault,
        router_id=effective_router_id,
        credential_ref_id=credential_ref_id,
    )
    evidence_fresh = cert.is_open_at(moment) if cert is not None else None

    expected_pin = _expected_host_key_sha256(
        store,
        router_id=effective_router_id,
        override=ssh_host_key_sha256,
        gate_a=cert,
    )

    reachable: bool | None = None
    probe_evidence: dict[str, Any] | None = None
    host_key_match: bool | None = None
    tuple_match: bool | None = None

    if probe:
        if probe_port is None:
            reachable = None
        else:
            effective_cred_ref = credential_ref_id
            if effective_cred_ref is None and effective_router_id is not None:
                router = store.get_router(effective_router_id)
                if router is not None and router["credential_ref_id"]:
                    effective_cred_ref = str(router["credential_ref_id"])
            probe_result = probe_port.probe(
                host=resolved_host,
                port=port,
                source_address=bind_source,
                router_id=effective_router_id,
                credential_ref_id=effective_cred_ref,
            )
            reachable_raw = probe_result.get("reachable")
            reachable = reachable_raw if isinstance(reachable_raw, bool) else None
            evidence_raw = probe_result.get("evidence")
            probe_evidence = evidence_raw if isinstance(evidence_raw, dict) else None
            host_key_match = _host_key_match_from_evidence(expected_pin, probe_evidence)
            if cert is not None and probe_evidence is not None:
                tuple_match = cert.matches_probe_evidence(probe_evidence)
            elif cert is not None and probe_evidence is None:
                tuple_match = None
            else:
                tuple_match = None
    else:
        if expected_pin is not None and cert is not None:
            gate_pin = normalize_sha256_fingerprint(cert.ssh_host_key_fingerprint_sha256)
            host_key_match = expected_pin == gate_pin
        pin = (
            store.get_endpoint_ssh_host_key(effective_router_id)
            if effective_router_id is not None
            else None
        )
        if (
            host_key_match is None
            and pin is not None
            and cert is not None
        ):
            host_key_match = (
                normalize_sha256_fingerprint(pin.fingerprint_sha256)
                == normalize_sha256_fingerprint(cert.ssh_host_key_fingerprint_sha256)
            )

    facts = ConnectionHealthFacts(
        reachable=reachable,
        host_key_match=host_key_match,
        tuple_match=tuple_match,
        credentials_present=creds_present,
        evidence_fresh=evidence_fresh,
    )
    status, reason_code = derive_health_status(facts)

    return {
        "status": status,
        "reason_code": reason_code,
        "facts": facts.to_dict(),
        "writes_allowed": False,
        "certification_eligible": False,
        "host": resolved_host,
        "port": port,
        "router_id": effective_router_id,
        "source_address": bind_source,
    }


__all__ = [
    "ConnectionHealthError",
    "ConnectionHealthFacts",
    "ConnectionHealthProbePort",
    "HealthStatus",
    "NotConfiguredConnectionHealthProbe",
    "assess_connection_health",
    "derive_health_status",
]
