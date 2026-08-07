"""Published preset lineage and idempotency."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "pub.sqlite3", enable_worker=False)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_publication_immutable_lineage(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Pub Booth"},
        headers={"Idempotency-Key": "pub-create"},
    )
    preset = create.json()["preset"]
    etag = create.headers["ETag"]
    pub = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/publications",
        json={"revision_id": preset["current_revision_id"]},
        headers={"Idempotency-Key": "pub-1", "If-Match": etag},
    )
    assert pub.status_code == 201, pub.text
    body = pub.json()
    published_id = body["published_preset_id"]
    replay = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/publications",
        json={"revision_id": preset["current_revision_id"]},
        headers={"Idempotency-Key": "pub-1", "If-Match": etag},
    )
    assert replay.status_code == 200
    get_r = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/publications/{published_id}"
    )
    assert get_r.status_code == 200
    lineage = get_r.json()["source_lineage"]
    assert lineage["preset_id"] == preset["preset_id"]
