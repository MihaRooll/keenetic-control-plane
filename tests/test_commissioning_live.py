"""Live commissioning assess with mocked Gate A probe."""

from __future__ import annotations

import hashlib
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.adapters.netcraze.certification import load_gate_a_certification
from router_control.adapters.netcraze.live_probe import LiveProbeTarget
from router_control.adapters.secrets.memory import MemoryVault
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

from tests.test_gate_a_certification import CERTIFIED_EVIDENCE, _gate_config

FIXED = datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC)


def _freeze_gate_a_openness(monkeypatch: pytest.MonkeyPatch) -> None:
    from router_control.adapters.netcraze import certification as gate_mod

    monkeypatch.setattr(gate_mod, "_OPENNESS_CLOCK", lambda: FIXED)


def _passthrough_source_bind(source_address: str, **kwargs: object) -> str:
    return source_address


@pytest.fixture
def gate_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    config_path = tmp_path / "gate-a.json"
    evidence_path = tmp_path / "evidence.json"
    status_path = tmp_path / "STATUS.yaml"
    evidence_path.write_text(json.dumps(CERTIFIED_EVIDENCE), encoding="utf-8")
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    config_path.write_text(json.dumps(_gate_config(evidence_sha256=digest)), encoding="utf-8")
    status_path.write_text(
        "gates:\n  A:\n    status: open\n    certification: ReadOnlyCertified\n",
        encoding="utf-8",
    )
    return config_path, evidence_path, status_path


def _mock_probe_fn(target: LiveProbeTarget) -> dict[str, object]:
    assert target.source_address == "192.168.1.144"
    return dict(CERTIFIED_EVIDENCE)


@pytest.fixture
def live_client(tmp_path, gate_paths, monkeypatch):
    _freeze_gate_a_openness(monkeypatch)
    monkeypatch.setattr(
        "router_control_host.routes.preflight_source_address_bind",
        _passthrough_source_bind,
    )
    config_path, evidence_path, status_path = gate_paths
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "live")
    monkeypatch.setenv("RC_NETCRAZE_USERNAME", "lab-user")
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED,
    )
    app = create_app(
        db_path=tmp_path / "live-comm.sqlite3",
        adapter_mode="live",
        gate_a_certification=cert,
        read_only_probe_fn=_mock_probe_fn,
        skip_gate_a_load=True,
        vault=MemoryVault(),
        enable_worker=True,
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbid(*args: object, **kwargs: object) -> None:
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket.socket, "connect", _forbid)


def test_live_commissioning_assess_ready_readonly(live_client, monkeypatch) -> None:
    _forbid_network(monkeypatch)
    host = live_client.app.state.host
    assert host.worker_runtime is not None
    assert host.worker_runtime.worker.store is not host.runtime.store
    enroll = live_client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Gate A Router",
            "vendor": "Netcraze",
            "model": "NC-1812",
            "endpoint": {
                "kind": "management_https",
                "host": "192.168.1.1",
                "port": 443,
                "username": "lab-user",
                "source_address": "192.168.1.144",
            },
            "management_password": "never-echo",
        },
        headers={"Idempotency-Key": "live-comm-enroll"},
    )
    assert enroll.status_code == 202
    router_id = enroll.json()["router_id"]
    pf = live_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        headers={"Idempotency-Key": "live-comm-pf"},
    )
    assert pf.status_code == 200, pf.text
    site_id = live_client.app.state.host.ensure_default_site()
    create = live_client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "live"},
        headers={"Idempotency-Key": "live-comm-create"},
    )
    assert create.status_code == 201
    run_id = create.json()["run_id"]
    assess = live_client.post(
        f"/api/router-control/v1/commissioning-runs/{run_id}/assess",
        headers={"Idempotency-Key": "live-comm-assess"},
    )
    assert assess.status_code == 200
    body = assess.json()
    assert body["run"]["state"] == "ReadyReadOnly"
    assert "identity_tuple_match" in {c["check_kind"] for c in body["checks"]}
    assert "never-echo" not in assess.text


def test_live_gate_a_closed_blocks_assess(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(
        db_path=tmp_path / "closed.sqlite3",
        adapter_mode="live",
        gate_a_certification=None,
        skip_gate_a_load=True,
        vault=MemoryVault(),
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        r = c.post(
            "/api/router-control/v1/routers",
            json={
                "display_name": "R",
                "vendor": "FakeVendor",
                "model": "Fake",
                "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
                "management_password": "pw",
            },
            headers={"Idempotency-Key": "enroll-closed"},
        )
        assert r.status_code == 403

    offline = create_app(db_path=tmp_path / "offline-closed.sqlite3")
    with TestClient(offline) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        site_id = c.app.state.host.ensure_default_site()
        er = c.post(
            "/api/router-control/v1/routers",
            json={
                "display_name": "R",
                "vendor": "FakeVendor",
                "model": "Fake",
                "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
                "management_password": "pw",
            },
            headers={"Idempotency-Key": "enroll-off"},
        )
        router_id = er.json()["router_id"]
        store = c.app.state.host.runtime.store
        now = c.app.state.host.runtime.clock.now()
        store._conn.execute(
            "UPDATE routers SET lifecycle_status = 'Enrolled' WHERE router_id = ?",
            (router_id,),
        )
        store.insert_observation(
            router_id=router_id,
            identity_fingerprint="digest:seed",
            resource_version="v1",
            state_digest="sha256:obs",
            now=now,
        )
        run = c.post(
            f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
            json={"router_id": router_id, "mode": "live"},
            headers={"Idempotency-Key": "create-live-closed"},
        ).json()
        assess = c.post(
            f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
            headers={"Idempotency-Key": "assess-live-closed"},
        )
        assert assess.status_code == 200
        assert assess.json()["run"]["state"] == "Blocked"


def test_live_identity_mismatch_blocks_assess(live_client, monkeypatch) -> None:
    _forbid_network(monkeypatch)
    enroll = live_client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Mismatch Router",
            "vendor": "Netcraze",
            "model": "NC-1812",
            "endpoint": {
                "kind": "management_https",
                "host": "192.168.1.1",
                "port": 443,
                "username": "lab-user",
                "source_address": "192.168.1.144",
            },
            "management_password": "never-echo",
        },
        headers={"Idempotency-Key": "live-comm-mismatch-enroll"},
    )
    assert enroll.status_code == 202
    router_id = enroll.json()["router_id"]
    pf = live_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        headers={"Idempotency-Key": "live-comm-mismatch-pf"},
    )
    assert pf.status_code == 200, pf.text
    site_id = live_client.app.state.host.ensure_default_site()
    create = live_client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "live"},
        headers={"Idempotency-Key": "live-comm-mismatch-create"},
    )
    assert create.status_code == 201
    run_id = create.json()["run_id"]
    host = live_client.app.state.host
    original_commissioning_service = host.commissioning_service

    def commissioning_with_identity_mismatch():
        svc = original_commissioning_service()
        svc.matches_probe_evidence = lambda _evidence: False
        return svc

    monkeypatch.setattr(host, "commissioning_service", commissioning_with_identity_mismatch)
    assess = live_client.post(
        f"/api/router-control/v1/commissioning-runs/{run_id}/assess",
        headers={"Idempotency-Key": "live-comm-mismatch-assess"},
    )
    assert assess.status_code == 200
    body = assess.json()
    assert body["run"]["state"] == "Blocked"
    identity_checks = [
        c for c in body["checks"] if c["check_kind"] == "identity_tuple_match"
    ]
    assert len(identity_checks) == 1
    assert identity_checks[0]["outcome"] == "Blocked"
