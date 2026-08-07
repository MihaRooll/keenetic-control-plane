"""Router discovery service and bounds tests."""

from __future__ import annotations

import socket
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.router_discovery import (
    ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT,
    ENROLLMENT_DRAFT_LIFECYCLE,
    ENROLLMENT_DRAFT_MODEL,
    CandidateProbeTarget,
    DefaultGatewayRoute,
    LocalHostIPv4Interface,
    RouterDiscoveryError,
    _is_enrollment_draft,
    run_router_discovery,
)
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore
from router_control_host.host_route_table import (
    parse_net_ip_interface_json,
    parse_net_route_json,
)

COMPONENT_DIGEST = "sha256:" + "a" * 64
FINGERPRINT_DIGEST = "sha256:" + "b" * 64
HOST_KEY_FINGERPRINT = "SHA256:" + "c" * 43
MISMATCH_HOST_KEY = "SHA256:" + "d" * 43


class FakeRouteTable:
    def __init__(
        self,
        routes: list[DefaultGatewayRoute] | None = None,
        interfaces: list[LocalHostIPv4Interface] | None = None,
    ) -> None:
        self._routes = list(routes or [])
        self._interfaces = list(interfaces or [])

    def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]:
        return list(self._routes)

    def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]:
        return list(self._interfaces)


class SpyIdentityProbe:
    def __init__(self, responses: dict[str, dict[str, Any]] | None = None) -> None:
        self.calls: list[CandidateProbeTarget] = []
        self._responses = responses or {}

    def probe(self, target: CandidateProbeTarget) -> dict[str, Any]:
        self.calls.append(target)
        if target.host not in self._responses:
            raise AssertionError(f"probe contacted out-of-bounds host: {target.host}")
        return self._responses[target.host]


@pytest.fixture
def store(tmp_path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "discovery.sqlite3"))


@pytest.fixture
def vault() -> MemoryVault:
    return MemoryVault()


def _gate_a(*, fresh: bool = True, host_key: str = HOST_KEY_FINGERPRINT) -> GateACertification:
    # Gate A openness is judged against the wall clock (24h freshness window), so a
    # hardcoded calendar date would make these tests decay into failures.
    recorded = datetime.now(UTC)
    expires = recorded + timedelta(days=90)
    if not fresh:
        recorded = recorded - timedelta(days=30)
        expires = recorded + timedelta(days=1)
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="NC-1812",
        firmware_version="4.03.C.6.4-16",
        firmware_display="4.03.C.6.4-16",
        ndm_build="canonical-build",
        bsp_build="bsp",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="synthetic",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=host_key,
        certification_eligible=True,
        evidence_recorded_at=recorded,
        evidence_path="synthetic-evidence.json",
        expires_at=expires,
        revocation_policy="test",
    )


def _probe_evidence(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": "NC-1812",
        "firmware_version": "4.03.C.6.4-16",
        "ndm_build": "canonical-build",
        "bsp_build": "bsp",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": HOST_KEY_FINGERPRINT,
        "certification_eligible": True,
        "identity_complete": True,
        "reachable": True,
    }
    payload.update(overrides)
    return payload


def _seed_router(
    store: PersistenceStore,
    *,
    host: str = "192.168.2.1",
    port: int = 443,
    kind: str = "management_https",
    source_address: str = "192.168.2.144",
    model: str = "NC-1812",
    identity_fingerprint: str = "digest:lab",
    lifecycle: str = "Enrolled",
    vault: MemoryVault | None = None,
    with_credentials: bool = False,
) -> str:
    site = store.create_site(display_name="Lab", now=datetime(2026, 8, 1, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site,
        display_name="Lab Router",
        vendor="Netcraze",
        model=model,
        identity_fingerprint=identity_fingerprint,
        host=host,
        port=port,
        kind=kind,
        source_address=source_address,
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    if lifecycle != "PendingEnrollment":
        store._conn.execute(
            "UPDATE routers SET lifecycle_status = ? WHERE router_id = ?",
            (lifecycle, router_id),
        )
    if with_credentials and vault is not None:
        handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
        store.insert_credential_ref(
            router_id=router_id,
            kind="RouterManagementPassword",
            provider="memory",
            provider_locator="inline",
            credential_ref_id=handle.credential_ref_id,
            now=datetime(2026, 8, 1, tzinfo=UTC),
        )
        store.set_router_credential_ref(
            router_id,
            handle.credential_ref_id,
            now=datetime(2026, 8, 1, tzinfo=UTC),
        )
    return router_id


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbid(*args: object, **kwargs: object) -> None:
        raise AssertionError("network transport must not be used during discovery tests")

    monkeypatch.setattr(socket.socket, "connect", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)


def test_discovery_classifies_gateway_unknown_and_endpoint_unverified_without_probe(
    store: PersistenceStore,
) -> None:
    """Local enrollment+pin match without live probe is unknown, not known_match."""
    router_id = _seed_router(store)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    report = run_router_discovery(
        store=store,
        route_table=FakeRouteTable(
            [DefaultGatewayRoute(gateway_host="192.168.1.1", source_address="192.168.1.144")]
        ),
        gate_a=_gate_a(),
    )
    by_host = {item["host"]: item for item in report["candidates"]}
    assert by_host["192.168.1.1"]["identity_state"] == "unknown"
    assert by_host["192.168.1.1"]["credentials_required"] is True
    assert by_host["192.168.1.1"]["writes_allowed"] is False
    endpoint = by_host["192.168.2.1"]
    assert endpoint["identity_state"] == "unknown"
    assert endpoint["reason_code"] == "enrollment_match_identity_unverified"
    assert endpoint["candidate_origin"] == "known_endpoint"
    assert report["certification_eligible"] is False
    assert report["bounds"]["subnet_scan"] is False
    assert report["probed_hosts"] == []
    assert report["excluded_candidates"] == []


def test_discovery_identity_mismatch_then_match_with_probe(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id = _seed_router(store, vault=vault, with_credentials=True)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    gate = _gate_a()
    mismatch_probe = SpyIdentityProbe(
        {"192.168.2.1": _probe_evidence(model="OTHER-MODEL")}
    )
    mismatch = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=True,
        identity_probe=mismatch_probe,
        gate_a=gate,
        vault=vault,
    )
    candidate = mismatch["candidates"][0]
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "probe_tuple_mismatch"
    assert candidate["writes_allowed"] is False

    match_probe = SpyIdentityProbe({"192.168.2.1": _probe_evidence()})
    matched = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=True,
        identity_probe=match_probe,
        gate_a=gate,
        vault=vault,
    )
    matched_candidate = matched["candidates"][0]
    assert matched_candidate["identity_state"] == "known_match"
    assert matched_candidate["reason_code"] == "probe_tuple_match"


def test_discovery_probe_never_contacts_out_of_bounds_hosts(
    store: PersistenceStore,
    vault: MemoryVault,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _forbid_network(monkeypatch)
    router_id = _seed_router(store, host="192.168.2.1", vault=vault, with_credentials=True)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    allowed_hosts = {"192.168.2.1"}
    spy = SpyIdentityProbe({host: {"reachable": True} for host in allowed_hosts})
    report = run_router_discovery(
        store=store,
        probe=True,
        identity_probe=spy,
        vault=vault,
        route_table=FakeRouteTable(
            [DefaultGatewayRoute(gateway_host="192.168.1.1", source_address="192.168.1.144")]
        ),
        gate_a=_gate_a(),
    )
    contacted = {call.host for call in spy.calls}
    assert contacted == allowed_hosts
    assert contacted.isdisjoint({"8.8.8.8", "192.168.99.1", "192.168.1.1"})
    assert {item["host"] for item in report["probed_hosts"]} == allowed_hosts
    gateway = next(item for item in report["candidates"] if item["host"] == "192.168.1.1")
    assert gateway["identity_state"] == "unknown"
    assert gateway["credentials_required"] is True


def test_discovery_probe_not_configured_raises(store: PersistenceStore) -> None:
    _seed_router(store)
    with pytest.raises(RouterDiscoveryError, match="probe not configured"):
        run_router_discovery(store=store, include_default_gateway=False, probe=True)


def test_discovery_local_mismatch_lifecycle(store: PersistenceStore) -> None:
    router_id = _seed_router(store, lifecycle="IdentityMismatch")
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "lifecycle_identity_mismatch"


def test_discovery_host_key_pin_mismatch_local(store: PersistenceStore) -> None:
    router_id = _seed_router(store)
    store.set_endpoint_ssh_host_key(
        router_id,
        MISMATCH_HOST_KEY,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "host_key_pin_mismatch"


def test_discovery_enrollment_draft_classified_unknown_not_mismatch(
    store: PersistenceStore,
) -> None:
    """Wizard placeholder draft must not report tuple_model_mismatch."""
    _seed_router(
        store,
        model=ENROLLMENT_DRAFT_MODEL,
        identity_fingerprint=ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT,
        lifecycle=ENROLLMENT_DRAFT_LIFECYCLE,
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "enrollment_draft_model_unknown"


def test_discovery_pending_discovery_model_with_enrolled_lifecycle_not_draft(
    store: PersistenceStore,
) -> None:
    """T-1: model PendingDiscovery alone is insufficient — lifecycle must match draft."""
    _seed_router(
        store,
        model=ENROLLMENT_DRAFT_MODEL,
        identity_fingerprint=ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT,
        lifecycle="Enrolled",
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["reason_code"] != "enrollment_draft_model_unknown"
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "tuple_model_mismatch"


def test_discovery_real_model_mismatch_still_known_mismatch(
    store: PersistenceStore,
) -> None:
    """A record that claims a real model and disagrees with Gate A stays mismatch."""
    _seed_router(store, model="OTHER-MODEL", lifecycle="Enrolled")
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "tuple_model_mismatch"


def test_discovery_pending_enrollment_real_model_mismatch_still_known_mismatch(
    store: PersistenceStore,
) -> None:
    """PendingEnrollment with a real but different model stays tuple mismatch, not draft."""
    _seed_router(store, model="OTHER-MODEL", lifecycle="PendingEnrollment")
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "tuple_model_mismatch"


def _infer_sql_is_enrollment_draft_via_restore_ranking(
    tmp_path,
    case_index: int,
    *,
    model: str,
    lifecycle: str,
    identity_fingerprint: str,
) -> bool:
    """Infer store is_draft CASE via find_restore_candidate_router_id (real SQL path)."""
    conn = open_database(tmp_path / f"draft-rank-{case_index}.sqlite3")
    ranking_store = PersistenceStore(conn)
    base = datetime(2026, 8, 4, tzinfo=UTC)
    competitor_id = _seed_router(
        ranking_store,
        model=ENROLLMENT_DRAFT_MODEL,
        identity_fingerprint="digest:enroll:" + "f" * 32,
        lifecycle=ENROLLMENT_DRAFT_LIFECYCLE,
        host="10.0.0.2",
    )
    ranking_store.set_endpoint_ssh_host_key(
        competitor_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        pinned_at=(base + timedelta(hours=2)).isoformat().replace("+00:00", "Z"),
    )
    subject_id = _seed_router(
        ranking_store,
        model=model,
        identity_fingerprint=identity_fingerprint,
        lifecycle=lifecycle,
        host="10.0.0.3",
    )
    ranking_store.set_endpoint_ssh_host_key(
        subject_id,
        "SHA256:" + "d" * 43,
        "ssh-ed25519",
        "learned_confirmed",
        pinned_at=(base + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
    )
    winner = ranking_store.find_restore_candidate_router_id()
    return winner == competitor_id


def test_discovery_enrollment_draft_predicates_agree_with_persistence_sql(
    tmp_path,
) -> None:
    """Application _is_enrollment_draft and store restore SQL is_draft agree on seeded rows."""
    cases: list[tuple[str, str, str, str]] = [
        (
            ENROLLMENT_DRAFT_MODEL,
            ENROLLMENT_DRAFT_LIFECYCLE,
            ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT,
            "wizard-draft",
        ),
        (
            ENROLLMENT_DRAFT_MODEL,
            ENROLLMENT_DRAFT_LIFECYCLE,
            "digest:enroll:" + "c" * 32,
            "failed-enroll",
        ),
        ("NC-1812", "Enrolled", "digest:lab", "enrolled-real-model"),
        (
            ENROLLMENT_DRAFT_MODEL,
            "Enrolled",
            ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT,
            "placeholder-model-enrolled-lifecycle",
        ),
        (
            "   ",
            ENROLLMENT_DRAFT_LIFECYCLE,
            "digest:enroll:" + "e" * 32,
            "whitespace-model-pending-enrollment",
        ),
    ]
    for index, (model, lifecycle, fingerprint, label) in enumerate(cases):
        conn = open_database(tmp_path / f"draft-row-{index}.sqlite3")
        row_store = PersistenceStore(conn)
        router_id = _seed_router(
            row_store,
            model=model,
            identity_fingerprint=fingerprint,
            lifecycle=lifecycle,
        )
        router_row = row_store.get_router(router_id)
        assert router_row is not None
        app_draft = _is_enrollment_draft(router_row)
        if lifecycle == "Enrolled" and model == "NC-1812":
            sql_draft = False
        else:
            sql_draft = _infer_sql_is_enrollment_draft_via_restore_ranking(
                tmp_path,
                index,
                model=model,
                lifecycle=lifecycle,
                identity_fingerprint=fingerprint,
            )
        assert app_draft == sql_draft, f"draft predicate drift for case {label}"


def test_discovery_failed_enroll_digest_shape_classified_draft_not_mismatch(
    store: PersistenceStore,
) -> None:
    """Live failed-enroll placeholder (digest:enroll:*) must not tuple_model_mismatch."""
    _seed_router(
        store,
        model=ENROLLMENT_DRAFT_MODEL,
        identity_fingerprint="digest:enroll:" + "a" * 32,
        lifecycle=ENROLLMENT_DRAFT_LIFECYCLE,
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "enrollment_draft_model_unknown"
    assert candidate["reason_code"] != "tuple_model_mismatch"


def test_discovery_two_record_address_no_known_mismatch_with_probe_false(
    store: PersistenceStore,
) -> None:
    """Mirrors live 192.168.2.1: enrolled :22 + failed-enroll placeholder :443."""
    enrolled_id = _seed_router(
        store,
        host="192.168.2.1",
        port=22,
        kind="ssh_tunnel",
        source_address="192.168.2.10",
        model="NC-1812",
        lifecycle="Enrolled",
    )
    store.set_endpoint_ssh_host_key(
        enrolled_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    _seed_router(
        store,
        host="192.168.2.1",
        port=443,
        model=ENROLLMENT_DRAFT_MODEL,
        identity_fingerprint="digest:enroll:" + "b" * 32,
        lifecycle=ENROLLMENT_DRAFT_LIFECYCLE,
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=False,
        gate_a=_gate_a(),
    )
    host_candidates = [item for item in report["candidates"] if item["host"] == "192.168.2.1"]
    assert len(host_candidates) == 2
    for candidate in host_candidates:
        assert candidate["identity_state"] != "known_mismatch"
        assert candidate["reason_code"] != "tuple_model_mismatch"


def test_discovery_empty_model_pending_enrollment_is_draft(
    store: PersistenceStore,
) -> None:
    """Whitespace-only model is a placeholder — unfinished enrollment stays unknown."""
    _seed_router(
        store,
        model="   ",
        identity_fingerprint="digest:enroll:" + "d" * 32,
        lifecycle=ENROLLMENT_DRAFT_LIFECYCLE,
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=False,
        gate_a=_gate_a(),
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "enrollment_draft_model_unknown"


def test_wizard_draft_literals_match_router_discovery_constants() -> None:
    """Drift guard: wizard_draft_routes placeholders must match discovery constants."""
    from pathlib import Path

    wizard_source = (
        Path(__file__).resolve().parents[1]
        / "router_control_host"
        / "wizard_draft_routes.py"
    ).read_text(encoding="utf-8")
    assert f'model="{ENROLLMENT_DRAFT_MODEL}"' in wizard_source
    assert f'identity_fingerprint="{ENROLLMENT_DRAFT_IDENTITY_FINGERPRINT}"' in wizard_source
    assert f'"lifecycle_status": "{ENROLLMENT_DRAFT_LIFECYCLE}"' in wizard_source


def test_parse_net_ip_interface_json_single_and_array() -> None:
    single_payload = (
        '{"IPAddress":"192.168.2.10","PrefixLength":24,'
        '"InterfaceIndex":7,"InterfaceAlias":"Ethernet 3"}'
    )
    single = parse_net_ip_interface_json(single_payload)
    assert len(single) == 1
    assert single[0].address == "192.168.2.10"
    assert single[0].prefix_length == 24
    assert single[0].if_index == 7
    assert single[0].if_label == "Ethernet 3"

    array = parse_net_ip_interface_json(
        '[{"IPAddress":"192.168.2.10","PrefixLength":24,"InterfaceIndex":7,'
        '"InterfaceAlias":"Ethernet 3"},'
        '{"IPAddress":"192.168.2.10","PrefixLength":24,"InterfaceIndex":7,'
        '"InterfaceAlias":"Ethernet 3"}]'
    )
    assert len(array) == 1

    assert parse_net_ip_interface_json("") == []
    assert parse_net_ip_interface_json("not-json") == []


def test_parse_net_ip_interface_json_skips_apipa_and_loopback() -> None:
    payload = (
        '[{"IPAddress":"169.254.12.34","PrefixLength":16,"InterfaceIndex":1},'
        '{"IPAddress":"127.0.0.1","PrefixLength":8,"InterfaceIndex":2},'
        '{"IPAddress":"192.168.2.10","PrefixLength":24,"InterfaceIndex":7}]'
    )
    interfaces = parse_net_ip_interface_json(payload)
    assert len(interfaces) == 1
    assert interfaces[0].address == "192.168.2.10"


def test_parse_net_route_json_strips_utf8_bom() -> None:
    payload = (
        "\ufeff"
        '{"NextHop":"192.168.1.1","InterfaceIndex":12,'
        '"InterfaceAlias":"Wi-Fi","SourceAddress":"192.168.1.144"}'
    )
    routes = parse_net_route_json(payload)
    assert len(routes) == 1
    assert routes[0].gateway_host == "192.168.1.1"

    bom_bytes = payload.encode("utf-8")
    routes_bytes = parse_net_route_json(bom_bytes)
    assert len(routes_bytes) == 1
    assert routes_bytes[0].gateway_host == "192.168.1.1"


def test_parse_net_ip_interface_json_strips_utf8_bom() -> None:
    payload = (
        "\ufeff"
        '{"IPAddress":"192.168.2.10","PrefixLength":24,'
        '"InterfaceIndex":7,"InterfaceAlias":"Ethernet 3"}'
    )
    interfaces = parse_net_ip_interface_json(payload)
    assert len(interfaces) == 1
    assert interfaces[0].address == "192.168.2.10"

    bom_bytes = payload.encode("utf-8")
    interfaces_bytes = parse_net_ip_interface_json(bom_bytes)
    assert len(interfaces_bytes) == 1
    assert interfaces_bytes[0].address == "192.168.2.10"


def test_parse_net_ip_interface_json_skips_missing_or_invalid_prefix_length() -> None:
    missing = parse_net_ip_interface_json(
        '{"IPAddress":"192.168.2.10","InterfaceIndex":7}'
    )
    assert missing == []

    invalid = parse_net_ip_interface_json(
        '{"IPAddress":"192.168.2.10","PrefixLength":"bad","InterfaceIndex":7}'
    )
    assert invalid == []

    zero_prefix = parse_net_ip_interface_json(
        '{"IPAddress":"192.168.2.10","PrefixLength":0,"InterfaceIndex":7}'
    )
    assert zero_prefix == []


def test_discovery_prefix_length_zero_does_not_emit_local_subnet_candidate(
    store: PersistenceStore,
) -> None:
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=False,
        route_table=FakeRouteTable(
            interfaces=[
                LocalHostIPv4Interface(
                    address="192.168.2.10",
                    prefix_length=0,
                    if_index=7,
                )
            ]
        ),
    )
    assert report["candidates"] == []


def test_windows_host_route_table_unicode_decode_error_returns_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control_host.host_route_table import WindowsHostRouteTable

    def _raise_unicode(*_args: object, **_kwargs: object) -> object:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    monkeypatch.setattr("router_control_host.host_route_table.subprocess.run", _raise_unicode)
    table = WindowsHostRouteTable()
    assert table.list_ipv4_default_gateways() == []
    assert table.list_ipv4_host_interfaces() == []
    diagnostics = {item["source"]: item for item in table.last_source_diagnostics}
    assert diagnostics["default_gateway"]["status"] == "failed"
    assert diagnostics["default_gateway"]["reason_code"] == "unicode_decode"
    assert diagnostics["local_subnet_gateway"]["status"] == "failed"
    assert diagnostics["local_subnet_gateway"]["reason_code"] == "unicode_decode"


def test_windows_host_route_table_json_decode_error_returns_failed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import subprocess

    from router_control_host.host_route_table import WindowsHostRouteTable

    def _malformed_json(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="not valid json",
            stderr="",
        )

    monkeypatch.setattr(
        "router_control_host.host_route_table.subprocess.run",
        _malformed_json,
    )
    table = WindowsHostRouteTable()
    assert table.list_ipv4_default_gateways() == []
    diagnostics = {item["source"]: item for item in table.last_source_diagnostics}
    assert diagnostics["default_gateway"]["status"] == "failed"
    assert diagnostics["default_gateway"]["reason_code"] == "json_decode"


class DiagnosticRouteTable:
    def __init__(self, diagnostics: list[dict[str, object]]) -> None:
        self.last_source_diagnostics = diagnostics

    def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]:
        return []

    def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]:
        return []


def test_run_router_discovery_reports_degraded_source_diagnostics(
    store: PersistenceStore,
) -> None:
    table = DiagnosticRouteTable(
        [
            {"source": "default_gateway", "status": "failed", "reason_code": "timeout"},
            {"source": "local_subnet_gateway", "status": "empty"},
        ]
    )
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        route_table=table,
    )
    assert report["degraded_sources"] == ["default_gateway"]
    assert len(report["source_diagnostics"]) == 2
    failed = next(
        item for item in report["source_diagnostics"] if item["source"] == "default_gateway"
    )
    assert failed["status"] == "failed"
    assert failed["reason_code"] == "timeout"


class DefaultGatewayFailLocalSubnetOkRouteTable:
    def __init__(self) -> None:
        self._source_diagnostics: dict[str, dict[str, object]] = {}

    @property
    def last_source_diagnostics(self) -> list[dict[str, object]]:
        return list(self._source_diagnostics.values())

    def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]:
        self._source_diagnostics["default_gateway"] = {
            "source": "default_gateway",
            "status": "failed",
            "reason_code": "timeout",
        }
        return []

    def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]:
        self._source_diagnostics["local_subnet_gateway"] = {
            "source": "local_subnet_gateway",
            "status": "ok",
        }
        return [
            LocalHostIPv4Interface(
                address="192.168.2.10",
                prefix_length=24,
                if_index=7,
            )
        ]


def test_run_router_discovery_omits_disabled_default_gateway_diagnostics(
    store: PersistenceStore,
) -> None:
    """include_default_gateway=false hides GW candidates, not a failed dedup fetch."""
    table = DefaultGatewayFailLocalSubnetOkRouteTable()
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=False,
        route_table=table,
    )
    assert "default_gateway" in report["degraded_sources"]
    failed = next(
        item for item in report["source_diagnostics"] if item["source"] == "default_gateway"
    )
    assert failed["status"] == "failed"
    assert failed["reason_code"] == "timeout"
    assert report["candidates"] == []
    assert all(item["candidate_origin"] != "default_gateway" for item in report["candidates"])


def test_run_router_discovery_fail_closed_local_subnet_when_default_gateway_fetch_failed(
    store: PersistenceStore,
) -> None:
    table = DefaultGatewayFailLocalSubnetOkRouteTable()
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=True,
        route_table=table,
    )
    assert "default_gateway" in report["degraded_sources"]
    assert report["candidates"] == []


def test_router_discovery_api_degraded_sources_http_200(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    class FailingHostRouteTable:
        last_source_diagnostics = [
            {
                "source": "default_gateway",
                "status": "failed",
                "reason_code": "os_error",
            },
            {"source": "local_subnet_gateway", "status": "empty"},
        ]

        def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]:
            return []

        def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]:
            return []

    monkeypatch.setattr(
        "router_control_host.router_discovery_routes.platform_host_route_table",
        lambda: FailingHostRouteTable(),
    )
    app = create_app(
        db_path=tmp_path / "discovery-degraded.sqlite3",
        enable_worker=False,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = client.post(
            "/api/router-control/v1/lab/router-discovery",
            json={"include_known_endpoints": False},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["degraded_sources"] == ["default_gateway"]
    assert any(item["status"] == "failed" for item in body["source_diagnostics"])


def test_parse_net_route_json_single_and_array() -> None:
    single = parse_net_route_json(
        '{"NextHop":"192.168.1.1","InterfaceIndex":12,"InterfaceAlias":"Wi-Fi","SourceAddress":"192.168.1.144"}'
    )
    assert len(single) == 1
    assert single[0].gateway_host == "192.168.1.1"
    assert single[0].route_if_index == 12
    assert single[0].route_label == "Wi-Fi"
    assert single[0].source_address == "192.168.1.144"

    array = parse_net_route_json(
        '[{"NextHop":"192.168.1.1","InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"},'
        '{"NextHop":"192.168.1.1","InterfaceIndex":12,"InterfaceAlias":"Wi-Fi"}]'
    )
    assert len(array) == 1

    assert parse_net_route_json("") == []
    assert parse_net_route_json("not-json") == []


def test_parse_net_route_json_cyrillic_interface_alias() -> None:
    cyrillic_alias = "Беспроводная сеть 3"
    payload = (
        '{"NextHop":"192.168.1.254","InterfaceIndex":12,'
        '"InterfaceAlias":"' + cyrillic_alias + '","SourceAddress":"192.168.1.10"}'
    )
    routes = parse_net_route_json(payload)
    assert len(routes) == 1
    assert routes[0].route_label == cyrillic_alias

    utf8_payload = payload.encode("utf-8")
    routes_bytes = parse_net_route_json(utf8_payload)
    assert len(routes_bytes) == 1
    assert routes_bytes[0].route_label == cyrillic_alias


def test_parse_net_ip_interface_json_cyrillic_interface_alias() -> None:
    cyrillic_alias = "Беспроводная сеть 3"
    payload = (
        '{"IPAddress":"192.168.1.10","PrefixLength":24,"InterfaceIndex":12,'
        '"InterfaceAlias":"' + cyrillic_alias + '"}'
    )
    interfaces = parse_net_ip_interface_json(payload)
    assert len(interfaces) == 1
    assert interfaces[0].if_label == cyrillic_alias

    utf8_payload = payload.encode("utf-8")
    interfaces_bytes = parse_net_ip_interface_json(utf8_payload)
    assert len(interfaces_bytes) == 1
    assert interfaces_bytes[0].if_label == cyrillic_alias


def test_discovery_skips_probe_without_credentials_and_pin(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    _seed_router(store, vault=vault, with_credentials=False)
    spy = SpyIdentityProbe({"192.168.2.1": _probe_evidence()})
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=True,
        identity_probe=spy,
        gate_a=_gate_a(),
        vault=vault,
    )
    assert spy.calls == []
    assert report["probed_hosts"] == []
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "missing_ssh_host_key_pin"


def test_discovery_digest_drift_known_mismatch_with_probe(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    """Digest-only drift with matching host key + firmware → known_mismatch when probed."""
    router_id = _seed_router(store, vault=vault, with_credentials=True)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    drift_digest = "sha256:" + "e" * 64
    probe = SpyIdentityProbe(
        {
            "192.168.2.1": _probe_evidence(device_fingerprint_digest=drift_digest),
        }
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=True,
        identity_probe=probe,
        gate_a=_gate_a(),
        vault=vault,
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "known_mismatch"
    assert candidate["reason_code"] == "probe_tuple_mismatch"
    assert candidate["facts"]["probe_tuple_match"] is False


def test_discovery_public_gateway_soft_excluded_private_endpoint_remains(
    store: PersistenceStore,
) -> None:
    router_id = _seed_router(store)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    report = run_router_discovery(
        store=store,
        route_table=FakeRouteTable(
            [DefaultGatewayRoute(gateway_host="8.8.8.8", source_address="192.168.1.144")]
        ),
        gate_a=_gate_a(),
    )
    assert {item["host"] for item in report["candidates"]} == {"192.168.2.1"}
    excluded = report["excluded_candidates"]
    assert len(excluded) == 1
    assert excluded[0]["host"] == "8.8.8.8"
    assert excluded[0]["reason_code"] == "non_private_management_address"
    assert excluded[0]["candidate_origin"] == "default_gateway"


def test_discovery_loopback_gateway_soft_excluded(
    store: PersistenceStore,
) -> None:
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        route_table=FakeRouteTable(
            [DefaultGatewayRoute(gateway_host="127.0.0.1", source_address="127.0.0.1")]
        ),
    )
    assert report["candidates"] == []
    excluded = report["excluded_candidates"]
    assert len(excluded) == 1
    assert excluded[0]["host"] == "127.0.0.1"
    assert excluded[0]["reason_code"] == "loopback_not_management_candidate"


def test_discovery_partial_probe_evidence_unknown(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id = _seed_router(store, vault=vault, with_credentials=True)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    incomplete = _probe_evidence(identity_complete=False)
    probe = SpyIdentityProbe({"192.168.2.1": incomplete})
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=True,
        identity_probe=probe,
        gate_a=_gate_a(),
        vault=vault,
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "probe_evidence_incomplete"
    assert candidate["facts"]["probe_tuple_match"] is None


def test_discovery_probe_false_enrolled_not_known_match(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id = _seed_router(store, vault=vault, with_credentials=True)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=False,
        gate_a=_gate_a(),
        vault=vault,
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "enrollment_match_identity_unverified"
    assert candidate["credentials_required"] is False


def test_discovery_enrollment_unverified_missing_credentials_required(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    """AC-1 complement: unverified enrollment without resolvable creds needs credentials."""
    router_id = _seed_router(store, vault=vault, with_credentials=False)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=False,
        gate_a=_gate_a(),
        vault=vault,
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "enrollment_match_identity_unverified"
    assert candidate["credentials_required"] is True


class _FakeUnreachableHealthProbe:
    def probe(
        self,
        *,
        host: str,
        port: int,
        source_address: str | None,
        router_id: str | None,
        credential_ref_id: str | None,
    ) -> dict[str, Any]:
        return {"reachable": False, "evidence": None}


def test_discovery_soft_identity_probe_unreachable_incomplete(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    """SoftCandidateIdentityProbe flatten of unreachable → probe_evidence_incomplete."""
    from router_control.adapters.netcraze.live_probe import SoftCandidateIdentityProbe

    router_id = _seed_router(store, vault=vault, with_credentials=True)
    store.set_endpoint_ssh_host_key(
        router_id,
        HOST_KEY_FINGERPRINT,
        "ssh-ed25519",
        "learned_confirmed",
        now=datetime(2026, 8, 1, tzinfo=UTC),
    )
    identity_probe = SoftCandidateIdentityProbe(_health_probe=_FakeUnreachableHealthProbe())
    report = run_router_discovery(
        store=store,
        include_default_gateway=False,
        probe=True,
        identity_probe=identity_probe,
        gate_a=_gate_a(),
        vault=vault,
    )
    candidate = report["candidates"][0]
    assert candidate["identity_state"] == "unknown"
    assert candidate["reason_code"] == "probe_evidence_incomplete"
    assert candidate["facts"]["probe_tuple_match"] is None
    assert candidate["facts"]["probe_reachable"] is False


def test_live_create_app_wires_soft_candidate_identity_probe(tmp_path) -> None:
    """AC-5: live + open Gate A wires SoftCandidateIdentityProbe on host state."""
    from router_control.adapters.netcraze.live_probe import SoftCandidateIdentityProbe
    from router_control_host.app import create_app

    vault = MemoryVault()
    app = create_app(
        db_path=tmp_path / "discovery-live-wiring.sqlite3",
        adapter_mode="live",
        gate_a_certification=_gate_a(),
        enable_worker=False,
        vault=vault,
        skip_gate_a_load=True,
    )
    probe = app.state.host.router_discovery_identity_probe
    assert probe is not None
    assert isinstance(probe, SoftCandidateIdentityProbe)


def test_router_discovery_host_api_probe_true_without_port_422(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AC-5: probe=true without injected identity probe port → 422."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    app = create_app(
        db_path=tmp_path / "discovery-no-probe.sqlite3",
        enable_worker=False,
    )
    assert app.state.host.router_discovery_identity_probe is None

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = client.post(
            "/api/router-control/v1/lab/router-discovery",
            json={"probe": True},
        )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "router_discovery.failed"
    assert "probe not configured" in body["error"]["message"]


def test_discovery_local_subnet_gateway_without_default_route(
    store: PersistenceStore,
) -> None:
    """AC-1: interface without DGW yields one .1 candidate with local_subnet_gateway."""
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=False,
        route_table=FakeRouteTable(
            interfaces=[
                LocalHostIPv4Interface(
                    address="192.168.2.10",
                    prefix_length=24,
                    if_index=7,
                    if_label="Ethernet 3",
                )
            ]
        ),
    )
    assert len(report["candidates"]) == 1
    candidate = report["candidates"][0]
    assert candidate["host"] == "192.168.2.1"
    assert candidate["candidate_origin"] == "local_subnet_gateway"
    assert candidate["source_address"] == "192.168.2.10"
    assert candidate["route_if_index"] == 7
    assert candidate["route_label"] == "Ethernet 3"
    assert "local_subnet_gateway" in report["bounds"]["sources"]
    assert report["bounds"]["subnet_scan"] is False


@pytest.mark.parametrize(
    ("route_if_index",),
    [
        pytest.param(7, id="if_index_match"),
        pytest.param(None, id="source_address_match"),
    ],
)
def test_discovery_local_subnet_gateway_not_duplicated_when_default_gateway_covers_if(
    store: PersistenceStore,
    route_if_index: int | None,
) -> None:
    """AC-2: DGW-covered interface is not duplicated as local_subnet_gateway."""
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        route_table=FakeRouteTable(
            routes=[
                DefaultGatewayRoute(
                    gateway_host="192.168.2.254",
                    source_address="192.168.2.10",
                    route_if_index=route_if_index,
                    route_label="Ethernet 3",
                )
            ],
            interfaces=[
                LocalHostIPv4Interface(
                    address="192.168.2.10",
                    prefix_length=24,
                    if_index=7,
                    if_label="Ethernet 3",
                )
            ],
        ),
    )
    by_origin = {item["candidate_origin"]: item for item in report["candidates"]}
    assert "local_subnet_gateway" not in by_origin
    assert by_origin["default_gateway"]["host"] == "192.168.2.254"


def test_discovery_local_subnet_gateway_not_duplicated_when_default_gateway_in_same_subnet(
    store: PersistenceStore,
) -> None:
    """F-1: DGW in iface subnet suppresses local_subnet_gateway without if_index/source match."""
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        route_table=FakeRouteTable(
            routes=[
                DefaultGatewayRoute(
                    gateway_host="192.168.1.254",
                    source_address=None,
                    route_if_index=None,
                    route_label="Ethernet",
                )
            ],
            interfaces=[
                LocalHostIPv4Interface(
                    address="192.168.1.10",
                    prefix_length=24,
                    if_index=7,
                    if_label="Ethernet",
                )
            ],
        ),
    )
    by_origin = {item["candidate_origin"]: item for item in report["candidates"]}
    assert "local_subnet_gateway" not in by_origin
    assert by_origin["default_gateway"]["host"] == "192.168.1.254"


def test_discovery_local_subnet_gateway_excludes_apipa_and_loopback(
    store: PersistenceStore,
) -> None:
    """AC-3: APIPA and loopback interfaces excluded from local_subnet_gateway."""
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=False,
        route_table=FakeRouteTable(
            interfaces=[
                LocalHostIPv4Interface(address="169.254.12.34", prefix_length=16, if_index=1),
                LocalHostIPv4Interface(address="127.0.0.1", prefix_length=8, if_index=2),
                LocalHostIPv4Interface(address="192.168.50.20", prefix_length=24, if_index=3),
            ]
        ),
    )
    assert len(report["candidates"]) == 1
    assert report["candidates"][0]["host"] == "192.168.50.1"
    assert report["candidates"][0]["candidate_origin"] == "local_subnet_gateway"


@pytest.mark.parametrize(
    ("host_address", "prefix_length", "expected_gateway"),
    [
        pytest.param("192.168.2.10", 16, "192.168.0.1", id="prefix_16"),
        pytest.param("192.168.3.10", 23, "192.168.2.1", id="prefix_23"),
        pytest.param("192.168.2.130", 25, "192.168.2.129", id="prefix_25"),
    ],
)
def test_discovery_local_subnet_gateway_respects_prefix_length(
    store: PersistenceStore,
    host_address: str,
    prefix_length: int,
    expected_gateway: str,
) -> None:
    """Адрес подсети вычисляется по маске интерфейса, а не как /24 по умолчанию."""
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=False,
        route_table=FakeRouteTable(
            interfaces=[
                LocalHostIPv4Interface(
                    address=host_address,
                    prefix_length=prefix_length,
                    if_index=7,
                )
            ]
        ),
    )
    assert len(report["candidates"]) == 1
    assert report["candidates"][0]["host"] == expected_gateway
    assert report["candidates"][0]["candidate_origin"] == "local_subnet_gateway"


def test_discovery_local_subnet_gateway_different_prefixes_stay_separate(
    store: PersistenceStore,
) -> None:
    """Кандидаты с разными адресами подсетей не склеиваются в одну запись."""
    report = run_router_discovery(
        store=store,
        include_known_endpoints=False,
        include_default_gateway=False,
        route_table=FakeRouteTable(
            interfaces=[
                LocalHostIPv4Interface(
                    address="192.168.2.10",
                    prefix_length=16,
                    if_index=7,
                ),
                LocalHostIPv4Interface(
                    address="10.0.5.10",
                    prefix_length=16,
                    if_index=8,
                ),
            ]
        ),
    )
    hosts = {item["host"] for item in report["candidates"]}
    assert hosts == {"192.168.0.1", "10.0.0.1"}
    assert len(report["candidates"]) == 2
