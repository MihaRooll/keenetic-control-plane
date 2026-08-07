"""Commissioning artifacts must not contain secrets or raw probe payloads."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

FORBIDDEN = re.compile(
    r"(password|secret|session|192\.168\.|startup-config|BEGIN PRIVATE KEY|never-echo|dpapi-)",
    re.IGNORECASE,
)
FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "nosecret.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_commissioning_db_scan_no_secrets(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    er = client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "R",
            "vendor": "FakeVendor",
            "model": "Fake",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "never-echo",
        },
        headers={"Idempotency-Key": "sec-enroll"},
    )
    router_id = er.json()["router_id"]
    store = client.app.state.host.runtime.store
    now = client.app.state.host.runtime.clock.now()
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
    run = client.post(
        f"/api/router-control/v1/sites/{site_id}/commissioning-runs",
        json={"router_id": router_id, "mode": "fake"},
        headers={"Idempotency-Key": "sec-create"},
    ).json()
    assess = client.post(
        f"/api/router-control/v1/commissioning-runs/{run['run_id']}/assess",
        headers={"Idempotency-Key": "sec-assess"},
    )
    assert assess.status_code == 200
    assert "never-echo" not in assess.text
    store = client.app.state.host.runtime.store
    chunks: list[str] = []
    for table in ("commissioning_runs", "readiness_checks", "commissioning_idempotency"):
        rows = store.conn.execute(f"SELECT * FROM {table}").fetchall()  # noqa: S608
        for row in rows:
            chunks.append("|".join(str(v) for v in tuple(row) if v is not None))
    audit_rows = store.conn.execute(
        "SELECT summary_redacted FROM audit_events WHERE action LIKE 'commissioning.%'"
    ).fetchall()
    for row in audit_rows:
        if row[0]:
            chunks.append(str(row[0]))
    dump = "\n".join(chunks)
    assert not FORBIDDEN.search(dump)
