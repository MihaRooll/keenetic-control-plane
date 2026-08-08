"""Connection health worst-case red→green tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.secrets.memory import MemoryVault
from router_control.application.connection_health import (
    ConnectionHealthFacts,
    assess_connection_health,
    derive_health_status,
)
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore

COMPONENT_DIGEST = "sha256:" + "a" * 64
FINGERPRINT_DIGEST = "sha256:" + "b" * 64
HOST_KEY_FINGERPRINT = "SHA256:" + "c" * 43
MISMATCH_HOST_KEY = "SHA256:" + "d" * 43
# Gate A openness is judged against the wall clock (24h freshness window), so a
# hardcoded calendar date would make these tests decay into failures.
NOW = datetime.now(UTC)


class FakeHealthProbe:
    def __init__(self, *, reachable: bool, evidence: dict[str, Any] | None) -> None:
        self.reachable = reachable
        self.evidence = evidence
        self.calls: list[dict[str, Any]] = []

    def probe(
        self,
        *,
        host: str,
        port: int,
        source_address: str | None,
        router_id: str | None,
        credential_ref_id: str | None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "host": host,
                "port": port,
                "source_address": source_address,
                "router_id": router_id,
                "credential_ref_id": credential_ref_id,
            }
        )
        return {"reachable": self.reachable, "evidence": self.evidence}


@pytest.fixture
def store(tmp_path) -> PersistenceStore:
    return PersistenceStore(open_database(tmp_path / "health.sqlite3"))


@pytest.fixture
def vault() -> MemoryVault:
    return MemoryVault()


def _gate_a(*, fresh: bool = True) -> GateACertification:
    recorded = NOW if fresh else NOW - timedelta(days=30)
    expires = recorded + (timedelta(days=90) if fresh else timedelta(days=1))
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
        ssh_host_key_fingerprint_sha256=HOST_KEY_FINGERPRINT,
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
    }
    payload.update(overrides)
    return payload


def _seed_router(
    store: PersistenceStore,
    vault: MemoryVault,
    *,
    with_credentials: bool = True,
    host_key: str = HOST_KEY_FINGERPRINT,
) -> tuple[str, str | None]:
    site = store.create_site(display_name="Lab", now=NOW)
    router_id = store.enroll_router(
        site_id=site,
        display_name="Lab Router",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:lab",
        host="192.168.2.1",
        source_address="192.168.2.144",
        now=NOW,
    )
    store.set_endpoint_ssh_host_key(
        router_id,
        host_key,
        "ssh-ed25519",
        "learned_confirmed",
        now=NOW,
    )
    credential_ref_id = None
    if with_credentials:
        handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
        credential_ref_id = handle.credential_ref_id
        store.insert_credential_ref(
            router_id=router_id,
            kind="RouterManagementPassword",
            provider="memory",
            provider_locator="inline",
            credential_ref_id=credential_ref_id,
            now=NOW,
        )
        store.set_router_credential_ref(router_id, credential_ref_id, now=NOW)
    return router_id, credential_ref_id


def _assess(
    store: PersistenceStore,
    vault: MemoryVault,
    router_id: str,
    credential_ref_id: str | None,
    probe: FakeHealthProbe,
    *,
    gate_a: GateACertification | None = None,
) -> dict[str, Any]:
    return assess_connection_health(
        store=store,
        vault=vault,
        router_id=router_id,
        credential_ref_id=credential_ref_id,
        probe=True,
        gate_a=gate_a or _gate_a(),
        probe_port=probe,
        now=NOW,
    )



def test_connection_health_digest_drift_red_identity_mismatch(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    """Digest-only drift with matching host key + firmware → red identity_mismatch."""
    router_id, credential_ref_id = _seed_router(store, vault)
    gate = _gate_a()
    drift_digest = "sha256:" + "e" * 64
    report = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(
            reachable=True,
            evidence=_probe_evidence(device_fingerprint_digest=drift_digest),
        ),
        gate_a=gate,
    )
    assert report["status"] == "red"
    assert report["facts"]["tuple_match"] is False
    assert report["facts"]["host_key_match"] is True
    assert report["reason_code"] == "identity_mismatch"


def test_identity_mismatch_not_green_then_match_green(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)
    gate = _gate_a()
    bad = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence(model="OTHER")),
        gate_a=gate,
    )
    assert bad["status"] != "green"
    assert bad["facts"]["tuple_match"] is False
    assert bad["reason_code"] == "identity_mismatch"

    good = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=gate,
    )
    assert good["status"] == "green"
    assert good["facts"]["tuple_match"] is True
    assert good["reason_code"] == "all_facts_healthy"


def test_unreachable_red_then_all_facts_green(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)
    gate = _gate_a()
    bad = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=False, evidence=None),
        gate_a=gate,
    )
    assert bad["status"] == "red"
    assert bad["facts"]["reachable"] is False
    assert bad["reason_code"] == "unreachable"

    good = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=gate,
    )
    assert good["status"] == "green"
    assert all(good["facts"][key] is True for key in good["facts"])


def test_host_key_mismatch_red_then_match_green(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)
    gate = _gate_a()
    bad = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(
            reachable=True,
            evidence=_probe_evidence(ssh_host_key_fingerprint_sha256=MISMATCH_HOST_KEY),
        ),
        gate_a=gate,
    )
    assert bad["status"] == "red"
    assert bad["facts"]["host_key_match"] is False
    assert bad["reason_code"] == "host_key_mismatch"

    good = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=gate,
    )
    assert good["status"] == "green"
    assert good["facts"]["host_key_match"] is True


def test_stale_evidence_not_green_then_fresh_green(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)
    stale_gate = _gate_a(fresh=False)
    stale = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=stale_gate,
    )
    assert stale["status"] != "green"
    assert stale["facts"]["evidence_fresh"] is False
    assert stale["reason_code"] == "evidence_stale"

    fresh = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=_gate_a(fresh=True),
    )
    assert fresh["status"] == "green"
    assert fresh["facts"]["evidence_fresh"] is True


def test_missing_credentials_not_green_then_present_green(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, _ = _seed_router(store, vault, with_credentials=False)
    gate = _gate_a()
    missing = _assess(
        store,
        vault,
        router_id,
        None,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=gate,
    )
    assert missing["status"] != "green"
    assert missing["facts"]["credentials_present"] is False
    assert missing["reason_code"] == "credentials_missing"

    handle = vault.create(kind="RouterManagementPassword", secret="lab-password")
    store.insert_credential_ref(
        router_id=router_id,
        kind="RouterManagementPassword",
        provider="memory",
        provider_locator="inline",
        credential_ref_id=handle.credential_ref_id,
        now=NOW,
    )
    store.set_router_credential_ref(router_id, handle.credential_ref_id, now=NOW)
    present = _assess(
        store,
        vault,
        router_id,
        handle.credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
        gate_a=gate,
    )
    assert present["status"] == "green"
    assert present["facts"]["credentials_present"] is True


def test_null_facts_never_green() -> None:
    status, reason = derive_health_status(
        ConnectionHealthFacts(
            reachable=True,
            host_key_match=True,
            tuple_match=True,
            credentials_present=True,
            evidence_fresh=None,
        )
    )
    assert status != "green"
    assert reason == "evidence_freshness_unknown"


def test_health_response_is_read_only(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)
    report = _assess(
        store,
        vault,
        router_id,
        credential_ref_id,
        FakeHealthProbe(reachable=True, evidence=_probe_evidence()),
    )
    assert report["writes_allowed"] is False
    assert report["certification_eligible"] is False


def test_null_reachable_stays_unknown_not_red(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)

    class NullReachableProbe:
        def probe(
            self,
            *,
            host: str,
            port: int,
            source_address: str | None,
            router_id: str | None,
            credential_ref_id: str | None,
        ) -> dict[str, Any]:
            return {"reachable": None, "evidence": None}

    report = assess_connection_health(
        store=store,
        vault=vault,
        router_id=router_id,
        credential_ref_id=credential_ref_id,
        probe=True,
        gate_a=_gate_a(),
        probe_port=NullReachableProbe(),
        now=NOW,
    )
    assert report["facts"]["reachable"] is None
    assert report["status"] == "yellow"
    assert report["reason_code"] == "reachability_unknown"


def test_connection_health_without_probe_port_yellow(
    store: PersistenceStore,
    vault: MemoryVault,
) -> None:
    router_id, credential_ref_id = _seed_router(store, vault)
    report = assess_connection_health(
        store=store,
        vault=vault,
        router_id=router_id,
        credential_ref_id=credential_ref_id,
        probe=True,
        gate_a=_gate_a(),
        probe_port=None,
        now=NOW,
    )
    assert report["status"] == "yellow"
    assert report["reason_code"] == "reachability_unknown"
    assert report["facts"]["reachable"] is None


def test_connection_health_host_api_with_injected_probe(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    vault = MemoryVault()
    app = create_app(
        db_path=tmp_path / "health-host-api.sqlite3",
        enable_worker=False,
        vault=vault,
    )
    store = app.state.host.runtime.store
    router_id, credential_ref_id = _seed_router(store, vault)
    app.state.host.connection_health_probe_port = FakeHealthProbe(
        reachable=True,
        evidence=_probe_evidence(),
    )
    app.state.host.gate_a_certification = _gate_a()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = client.post(
            "/api/router-control/v1/lab/connection-health",
            json={"router_id": router_id, "credential_ref_id": credential_ref_id},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] in ("green", "yellow", "red")
    assert body["certification_eligible"] is False


def test_connection_health_host_api_yellow_without_probe(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    vault = MemoryVault()
    app = create_app(
        db_path=tmp_path / "health-host-no-probe.sqlite3",
        enable_worker=False,
        vault=vault,
    )
    store = app.state.host.runtime.store
    router_id, credential_ref_id = _seed_router(store, vault)
    app.state.host.connection_health_probe_port = None
    app.state.host.gate_a_certification = _gate_a()

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = client.post(
            "/api/router-control/v1/lab/connection-health",
            json={"router_id": router_id, "credential_ref_id": credential_ref_id},
        )
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "yellow"
    assert body["reason_code"] == "reachability_unknown"


def test_connection_health_host_api_rejects_non_private_host(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    app = create_app(
        db_path=tmp_path / "health-public-host.sqlite3",
        enable_worker=False,
        vault=MemoryVault(),
    )

    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        response = client.post(
            "/api/router-control/v1/lab/connection-health",
            json={"host": "8.8.8.8", "probe": False},
        )
    assert response.status_code == 422
    err = response.json()["error"]
    assert err["code"] == "endpoint.host_not_private"
    assert err["message"] == "endpoint.host must be a private management address"
