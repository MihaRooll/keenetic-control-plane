"""Event preset artifacts must not contain secrets."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

FORBIDDEN = re.compile(
    r"(password|secret|session|192\.168\.|startup-config|BEGIN PRIVATE KEY|never-echo|dpapi-)",
    re.IGNORECASE,
)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "preset-nosecret.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_preset_db_scan_no_secrets(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Scan Booth"},
        headers={"Idempotency-Key": "scan-1"},
    )
    assert create.status_code == 201
    preset_id = create.json()["preset"]["preset_id"]
    client.post(f"/api/router-control/v1/event-presets/{preset_id}/validate")
    client.get(f"/api/router-control/v1/event-presets/{preset_id}/readiness/report")
    store = client.app.state.host.runtime.store
    chunks: list[str] = []
    for table in ("event_presets", "event_preset_revisions", "event_preset_idempotency"):
        rows = store.conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
        for row in rows:
            chunks.append("|".join(str(v) for v in tuple(row) if v is not None))
    dump = "\n".join(chunks)
    assert "credref:" in dump
    assert not FORBIDDEN.search(dump)
