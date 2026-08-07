"""Event preset API auth, idempotency, ETag."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "preset-api.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def test_preset_auth_required(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "noauth.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        site_id = c.app.state.host.ensure_default_site()
        r = c.post(
            f"/api/router-control/v1/sites/{site_id}/event-presets",
            json={"name": "Booth"},
            headers={"Idempotency-Key": "k1"},
        )
    assert r.status_code == 401


def test_create_validate_plan_readiness(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Safe Booth"},
        headers={"Idempotency-Key": "preset-create-1"},
    )
    assert create.status_code == 201, create.text
    body = create.json()
    preset = body["preset"]
    revision = body["revision"]
    assert preset["write_ready"] is False
    assert revision["validation_status"] == "ValidOffline"

    replay = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Safe Booth"},
        headers={"Idempotency-Key": "preset-create-1"},
    )
    assert replay.status_code == 200

    get_r = client.get(f"/api/router-control/v1/event-presets/{preset['preset_id']}")
    assert get_r.status_code == 200
    assert "ETag" in get_r.headers

    validate = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/validate"
    )
    assert validate.status_code == 200
    assert validate.json()["validation_status"] == "ValidOffline"

    plan = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/plan-preview"
    )
    assert plan.status_code == 200
    preview = plan.json()
    assert preview["write_ready"] is False
    families = {f["family"] for f in preview["families"]}
    assert "lan_zones" in families
    assert "certification_apply" in families

    report = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/readiness/report"
    )
    assert report.status_code == 200
    rep = report.json()
    assert rep["write_ready"] is False
    assert rep["valid_offline"] is True


def test_create_revision_if_match(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Rev Booth"},
        headers={"Idempotency-Key": "rev-create"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]

    rev = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "rev-1", "If-Match": preset["etag"]},
    )
    assert rev.status_code == 201
    assert rev.json()["preset"]["version"] == 2


def test_list_presets(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Listed"},
        headers={"Idempotency-Key": "list-1"},
    )
    listed = client.get(f"/api/router-control/v1/sites/{site_id}/event-presets")
    assert listed.status_code == 200
    assert len(listed.json()["items"]) >= 1


def test_create_idempotency_conflict(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Conflict Booth"},
        headers={"Idempotency-Key": "preset-conflict-1"},
    )
    second = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Different Booth"},
        headers={"Idempotency-Key": "preset-conflict-1"},
    )
    assert second.status_code == 409
    assert second.json()["error"]["code"] == "idempotency.conflict"


def test_revision_invalid_admin_zone_returns_400_not_500(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Bad Zone Booth"},
        headers={"Idempotency-Key": "bad-zone-1"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    for zone in doc["zones"]:
        if zone["zone_id"] == "AdminServer":
            zone["zone_id"] = "Admin"
    rev = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "bad-zone-rev", "If-Match": preset["etag"]},
    )
    assert rev.status_code == 400, rev.text
    assert rev.json()["error"]["code"] == "request.validation_failed"


def test_revision_invalid_uplink_lte_returns_400_not_500(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Bad Uplink Booth"},
        headers={"Idempotency-Key": "bad-uplink-1"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc["uplink"]["mode"] = "LTE"
    rev = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "bad-uplink-rev", "If-Match": preset["etag"]},
    )
    assert rev.status_code == 400, rev.text
    assert rev.json()["error"]["code"] == "request.validation_failed"


def test_revision_missing_management_allowed_returns_400_not_500(client) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Missing Mgmt Booth"},
        headers={"Idempotency-Key": "bad-mgmt-1"},
    )
    preset = create.json()["preset"]
    doc = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc["zones"][0].pop("management_allowed")
    rev = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": "bad-mgmt-rev", "If-Match": preset["etag"]},
    )
    assert rev.status_code == 400, rev.text
    assert rev.json()["error"]["code"] == "request.validation_failed"


@pytest.mark.parametrize(
    ("field", "value", "idempotency_key"),
    [
        ("zones", ["Guest"], "bad-shape-zones"),
        ("uplink", "Ethernet", "bad-shape-uplink"),
        ("rack_assets", [1], "bad-shape-rack"),
    ],
)
def test_create_revision_malformed_nested_shape_returns_400_not_500(
    client, field: str, value: object, idempotency_key: str
) -> None:
    site_id = client.app.state.host.ensure_default_site()
    create = client.post(
        f"/api/router-control/v1/sites/{site_id}/event-presets",
        json={"name": "Malformed Shape Booth"},
        headers={"Idempotency-Key": f"create-{idempotency_key}"},
    )
    assert create.status_code == 201, create.text
    preset = create.json()["preset"]
    doc = client.get(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions/"
        f"{preset['current_revision_id']}"
    ).json()["canonical_document"]
    doc[field] = value
    rev = client.post(
        f"/api/router-control/v1/event-presets/{preset['preset_id']}/revisions",
        json={"document": doc},
        headers={"Idempotency-Key": idempotency_key, "If-Match": preset["etag"]},
    )
    assert rev.status_code == 400, rev.text
    assert rev.json()["error"]["code"] == "request.validation_failed"
