"""FastAPI tests for TrafficDiscovery proposals-only routes."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

_API = "/api/router-control/v1"
_EVIDENCE = {"dst": "10.0.0.1", "proto": "tcp", "secret_token": "must-not-echo"}
_ROUTE_INTENT = {"prefix": "10.0.0.0/24"}


@pytest.fixture
def traffic_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "traffic_api.sqlite3", enable_worker=False)
    store = app.state.host.runtime.store
    site_id = store.create_site(display_name="Traffic Lab", now=datetime(2026, 7, 24, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="Traffic Router",
        vendor="FakeVendor",
        model="FakeModel",
        identity_fingerprint="digest:traffic",
        host="127.0.0.1",
        now=datetime(2026, 7, 24, tzinfo=UTC),
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.test_router_id = router_id
        yield client


def _record_observation(client, *, router_id: str | None = None) -> dict[str, object]:
    rid = router_id or client.test_router_id
    resp = client.post(
        f"{_API}/traffic/observations",
        json={"router_id": rid, "evidence": _EVIDENCE, "source": "offline"},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def test_record_observation(traffic_client) -> None:
    body = _record_observation(traffic_client)
    assert body["router_id"] == traffic_client.test_router_id
    assert body["source"] == "offline"
    assert body["evidence_digest"].startswith("sha256:")
    assert "traffic_observation_id" in body
    serialized = json.dumps(body)
    assert "must-not-echo" not in serialized
    assert "secret_token" not in serialized
    assert "evidence" not in body

    row = traffic_client.app.state.host.runtime.store.get_traffic_observation(
        str(body["traffic_observation_id"])
    )
    assert row is not None
    assert row["evidence_json"] is None


def test_create_proposal(traffic_client) -> None:
    obs = _record_observation(traffic_client)
    resp = traffic_client.post(
        f"{_API}/traffic/proposals",
        json={
            "traffic_observation_id": obs["traffic_observation_id"],
            "route_intent": _ROUTE_INTENT,
            "confidence": 0.8,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "Proposed"
    assert body["auto_apply_blocked"] is True
    assert body["confidence"] == 0.8
    assert body["traffic_observation_id"] == obs["traffic_observation_id"]
    assert "proposal_digest" in body
    assert "route_intent" not in body

    row = traffic_client.app.state.host.runtime.store.get_route_proposal(str(body["proposal_id"]))
    assert row is not None
    assert row["proposal_json"] is None
    assert int(row["auto_apply_blocked"]) == 1


def test_get_proposal(traffic_client) -> None:
    obs = _record_observation(traffic_client)
    create = traffic_client.post(
        f"{_API}/traffic/proposals",
        json={
            "traffic_observation_id": obs["traffic_observation_id"],
            "route_intent": _ROUTE_INTENT,
            "confidence": 0.75,
        },
    )
    proposal_id = create.json()["proposal_id"]
    resp = traffic_client.get(f"{_API}/traffic/proposals/{proposal_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["proposal_id"] == proposal_id
    assert body["auto_apply_blocked"] is True
    assert body["status"] == "Proposed"


def test_get_proposal_not_found(traffic_client) -> None:
    resp = traffic_client.get(f"{_API}/traffic/proposals/prop_missing")
    assert resp.status_code == 404
    assert resp.json()["error"]["code"] == "resource.not_found"


def test_traffic_auth_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "traffic_auth.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        obs = client.post(
            f"{_API}/traffic/observations",
            json={"router_id": "rtr_x", "evidence": {"x": 1}},
        )
        prop = client.post(
            f"{_API}/traffic/proposals",
            json={
                "traffic_observation_id": "tobs_x",
                "route_intent": {"prefix": "0.0.0.0/0"},
                "confidence": 0.5,
            },
        )
        get_prop = client.get(f"{_API}/traffic/proposals/prop_x")
    assert obs.status_code == 401
    assert prop.status_code == 401
    assert get_prop.status_code == 401


def test_extra_forbid_rejects_unknown_fields(traffic_client) -> None:
    resp = traffic_client.post(
        f"{_API}/traffic/observations",
        json={
            "router_id": traffic_client.test_router_id,
            "evidence": {"x": 1},
            "unknown_field": True,
        },
    )
    assert resp.status_code == 422

    obs = _record_observation(traffic_client)
    resp = traffic_client.post(
        f"{_API}/traffic/proposals",
        json={
            "traffic_observation_id": obs["traffic_observation_id"],
            "route_intent": _ROUTE_INTENT,
            "confidence": 0.5,
            "apply_now": True,
        },
    )
    assert resp.status_code == 422


def test_no_raw_evidence_echoed(traffic_client) -> None:
    secret_evidence = {"dst": "10.0.0.2", "psk": "super-secret-psk-value"}
    resp = traffic_client.post(
        f"{_API}/traffic/observations",
        json={"router_id": traffic_client.test_router_id, "evidence": secret_evidence},
    )
    assert resp.status_code == 201
    serialized = resp.text
    assert "super-secret-psk-value" not in serialized
    assert "psk" not in serialized


def test_record_observation_evidence_keys_collide_with_response_fields(traffic_client) -> None:
    evidence = {
        "source": "netflow-secret-source",
        "router_id": "rtr_wrong_from_evidence",
        "dst": "10.0.0.5",
    }
    resp = traffic_client.post(
        f"{_API}/traffic/observations",
        json={
            "router_id": traffic_client.test_router_id,
            "evidence": evidence,
            "source": "offline",
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["router_id"] == traffic_client.test_router_id
    assert body["source"] == "offline"
    assert "evidence" not in body
    assert "netflow-secret-source" not in resp.text
    assert "rtr_wrong_from_evidence" not in resp.text


def test_create_proposal_trusted_policy_still_blocks_auto_apply(traffic_client) -> None:
    obs = _record_observation(traffic_client)
    resp = traffic_client.post(
        f"{_API}/traffic/proposals",
        json={
            "traffic_observation_id": obs["traffic_observation_id"],
            "route_intent": _ROUTE_INTENT,
            "confidence": 0.9,
            "trusted_policy": True,
        },
    )
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["status"] == "Proposed"
    assert body["auto_apply_blocked"] is True
    assert body["trusted_policy"] is True
    assert "route_intent" not in body
