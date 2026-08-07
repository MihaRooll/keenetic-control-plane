"""GET /observed-interfaces — local artifact only, hub_admin auth."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def authed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    artifacts_dir = tmp_path / "artifacts"
    artifacts_dir.mkdir()
    monkeypatch.setenv("RC_ARTIFACTS_DIR", str(artifacts_dir))
    app = create_app(db_path=tmp_path / "observed.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        client.app.state.artifacts_dir = artifacts_dir
        yield client


@pytest.fixture
def unauthed_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ARTIFACTS_DIR", str(tmp_path / "artifacts"))
    app = create_app(db_path=tmp_path / "observed-noauth.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        yield client


def test_observed_interfaces_empty_without_artifact(authed_client) -> None:
    r = authed_client.get("/api/router-control/v1/observed-interfaces")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert "note" in body


def test_observed_interfaces_returns_sanitized_items(authed_client) -> None:
    artifacts_dir: Path = authed_client.app.state.artifacts_dir
    artifact = {
        "findings": {
            "sanitized_interfaces": [
                {
                    "interface_id_hash": "sha256:abc",
                    "role": "wan",
                    "interface_type": "ISP",
                    "link_up": True,
                    "connected": True,
                }
            ]
        }
    }
    path = artifacts_dir / "topology-test.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    r = authed_client.get("/api/router-control/v1/observed-interfaces")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["interface_id_hash"] == "sha256:abc"
    assert body["artifact_name"] == "topology-test.json"
    assert "203.0.113" not in r.text


def test_observed_interfaces_auth_required(unauthed_client) -> None:
    r = unauthed_client.get("/api/router-control/v1/observed-interfaces")
    assert r.status_code == 401


def test_observed_interfaces_strips_poisoned_keys(authed_client) -> None:
    artifacts_dir: Path = authed_client.app.state.artifacts_dir
    artifact = {
        "findings": {
            "sanitized_interfaces": [
                {
                    "interface_id_hash": "sha256:clean",
                    "role": "lan",
                    "secret": "must-not-leak",
                    "endpoint_host": "203.0.113.1",
                }
            ]
        }
    }
    path = artifacts_dir / "topology-poisoned.json"
    path.write_text(json.dumps(artifact), encoding="utf-8")
    r = authed_client.get("/api/router-control/v1/observed-interfaces")
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 1
    item = body["items"][0]
    assert item["interface_id_hash"] == "sha256:clean"
    assert item["role"] == "lan"
    assert "secret" not in item
    assert "endpoint_host" not in item
    assert "must-not-leak" not in r.text
    assert "203.0.113" not in r.text


def test_observed_interfaces_latest_mtime_wins(authed_client) -> None:
    artifacts_dir: Path = authed_client.app.state.artifacts_dir
    old_artifact = {
        "findings": {
            "sanitized_interfaces": [
                {"interface_id_hash": "sha256:old", "role": "wan", "interface_type": "ISP"}
            ]
        }
    }
    new_artifact = {
        "findings": {
            "sanitized_interfaces": [
                {"interface_id_hash": "sha256:new", "role": "lan", "interface_type": "Bridge"}
            ]
        }
    }
    old_path = artifacts_dir / "topology-older.json"
    new_path = artifacts_dir / "topology-newer.json"
    old_path.write_text(json.dumps(old_artifact), encoding="utf-8")
    time.sleep(0.02)
    new_path.write_text(json.dumps(new_artifact), encoding="utf-8")
    old_mtime = old_path.stat().st_mtime
    new_mtime = new_path.stat().st_mtime
    assert new_mtime > old_mtime
    r = authed_client.get("/api/router-control/v1/observed-interfaces")
    assert r.status_code == 200
    body = r.json()
    assert body["artifact_name"] == "topology-newer.json"
    assert len(body["items"]) == 1
    assert body["items"][0]["interface_id_hash"] == "sha256:new"
    assert body["items"][0]["role"] == "lan"
