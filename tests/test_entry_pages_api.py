"""Operator entry page API tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.entry_page_routes import build_self_check_payload


@pytest.fixture
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "entry-api.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _guest_document(**overrides):
    doc = {
        "title": "Guest welcome",
        "intro": "Please register",
        "button_label": "Submit",
        "fields": [
            {
                "name": "full_name",
                "label": "Name",
                "kind": "text",
                "required": True,
            }
        ],
        "submissions_enabled": True,
    }
    doc.update(overrides)
    return doc


def _create_guest_page(client) -> dict:
    create = client.post("/api/router-control/v1/entry-pages", json={"audience": "guest"})
    assert create.status_code == 201, create.text
    return create.json()


def test_all_operator_routes_require_auth(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=tmp_path / "entry-auth.sqlite3")
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        site_id = c.app.state.host.ensure_default_site()
        c.app.state.host.site_id = site_id
        page = c.app.state.host.entry_page_service().ensure_page(site_id, "guest")
        page_id = page["page_id"]
        routes = [
            ("GET", "/api/router-control/v1/entry-pages"),
            ("POST", "/api/router-control/v1/entry-pages", {"audience": "guest"}),
            ("GET", f"/api/router-control/v1/entry-pages/{page_id}"),
            (
                "PUT",
                f"/api/router-control/v1/entry-pages/{page_id}/draft",
                {"document": _guest_document()},
            ),
            (
                "POST",
                f"/api/router-control/v1/entry-pages/{page_id}/publish",
                {"revision_id": "missing"},
            ),
            ("POST", f"/api/router-control/v1/entry-pages/{page_id}/unpublish", {}),
            ("POST", f"/api/router-control/v1/entry-pages/{page_id}/self-check", {}),
            ("GET", f"/api/router-control/v1/entry-pages/{page_id}/draft-preview"),
        ]
        for method, path, *body in routes:
            payload = body[0] if body else None
            response = c.request(method, path, json=payload)
            assert response.status_code == 401, (method, path, response.text)


def test_draft_save_rejects_html_without_echo(client) -> None:
    page = _create_guest_page(client)
    canary = "CANARY_HTML_REJECT_XYZ_998877"
    response = client.put(
        f"/api/router-control/v1/entry-pages/{page['page_id']}/draft",
        json={"document": _guest_document(title=f"Bad {canary} <tag>")},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "entry.html_not_allowed"
    assert canary not in response.text


def test_publish_unpublish_cycle(client) -> None:
    page = _create_guest_page(client)
    page_id = page["page_id"]
    draft = client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document(title="Published title")},
    )
    assert draft.status_code == 200, draft.text
    revision_id = draft.json()["revision"]["revision_id"]
    published = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/publish",
        json={"revision_id": revision_id},
    )
    assert published.status_code == 200
    detail = client.get(f"/api/router-control/v1/entry-pages/{page_id}")
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["published"] is True
    assert payload["published_document"]["title"] == "Published title"
    unpublish = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/unpublish",
        json={},
    )
    assert unpublish.status_code == 200
    after = client.get(f"/api/router-control/v1/entry-pages/{page_id}")
    assert after.json()["published"] is False
    assert after.json()["published_document"] is None


def test_self_check_guest_reachable_always_null(client) -> None:
    page = _create_guest_page(client)
    response = client.post(
        f"/api/router-control/v1/entry-pages/{page['page_id']}/self-check",
        json={},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["guest_reachable"] is None
    assert payload["guest_reachable_reason"] == "guest_device_check_required"


def test_self_check_guard_rejects_guest_reachable_true(client, monkeypatch) -> None:
    page = _create_guest_page(client)

    def _bad_payload(host_state, *, page_id: str) -> dict[str, object]:
        payload = build_self_check_payload(host_state, page_id=page_id)
        payload["guest_reachable"] = True
        return payload

    monkeypatch.setattr(
        "router_control_host.entry_page_routes.build_self_check_payload",
        _bad_payload,
    )
    response = client.post(
        f"/api/router-control/v1/entry-pages/{page['page_id']}/self-check",
        json={},
    )
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal.error"


def test_draft_preview_has_strict_csp_and_no_script(client) -> None:
    page = _create_guest_page(client)
    page_id = page["page_id"]
    draft = client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document()},
    )
    assert draft.status_code == 200
    preview = client.get(f"/api/router-control/v1/entry-pages/{page_id}/draft-preview")
    assert preview.status_code == 200
    csp = preview.headers.get("content-security-policy", "")
    assert "script-src" not in csp.lower()
    assert "default-src 'none'" in csp
    assert preview.headers.get("x-robots-tag") == "noindex"
    assert "<script" not in preview.text.lower()


def test_foreign_site_page_id_returns_404_on_all_by_id_routes(client) -> None:
    from datetime import UTC, datetime

    host = client.app.state.host
    store = host.runtime.store
    now = datetime(2026, 8, 4, tzinfo=UTC)
    default_site = host.ensure_default_site()
    foreign_site = store.create_site(display_name="Foreign Lab", now=now)
    foreign_page = host.entry_page_service().ensure_page(foreign_site, "guest")
    saved = host.entry_page_service().save_draft(
        foreign_page["page_id"],
        _guest_document(title="Foreign draft"),
    )
    foreign_page_id = foreign_page["page_id"]
    revision_id = str(saved["revision"]["revision_id"])

    routes = [
        ("GET", f"/api/router-control/v1/entry-pages/{foreign_page_id}", None),
        (
            "PUT",
            f"/api/router-control/v1/entry-pages/{foreign_page_id}/draft",
            {"document": _guest_document(title="Cross-site edit")},
        ),
        (
            "POST",
            f"/api/router-control/v1/entry-pages/{foreign_page_id}/publish",
            {"revision_id": revision_id},
        ),
        (
            "POST",
            f"/api/router-control/v1/entry-pages/{foreign_page_id}/unpublish",
            {},
        ),
        (
            "POST",
            f"/api/router-control/v1/entry-pages/{foreign_page_id}/self-check",
            {},
        ),
        (
            "GET",
            f"/api/router-control/v1/entry-pages/{foreign_page_id}/draft-preview",
            None,
        ),
    ]
    for method, path, payload in routes:
        response = client.request(method, path, json=payload)
        assert response.status_code == 404, (method, path, response.text)
        if method == "GET" and path.endswith("/draft-preview"):
            assert response.text == "Not found"
        else:
            assert response.json()["error"]["code"] == "entry.page_not_found"

    listed = client.get("/api/router-control/v1/entry-pages")
    assert listed.status_code == 200
    listed_ids = {item["page_id"] for item in listed.json()["items"]}
    assert foreign_page_id not in listed_ids
    assert default_site != foreign_site


def test_unknown_page_id_returns_404(client) -> None:
    response = client.get("/api/router-control/v1/entry-pages/missing-page-id")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "entry.page_not_found"


def test_create_draft_publish_self_check_http_chain(client, monkeypatch: pytest.MonkeyPatch) -> None:
    """POST create → PUT draft → POST publish → POST self-check with honesty fields."""
    monkeypatch.delenv("RC_PUBLIC_ENTRY_BIND", raising=False)
    create = client.post("/api/router-control/v1/entry-pages", json={"audience": "guest"})
    assert create.status_code == 201, create.text
    page_id = create.json()["page_id"]
    draft = client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document(title="Chain published title")},
    )
    assert draft.status_code == 200, draft.text
    revision_id = draft.json()["revision"]["revision_id"]
    published = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/publish",
        json={"revision_id": revision_id},
    )
    assert published.status_code == 200, published.text
    self_check = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/self-check",
        json={},
    )
    assert self_check.status_code == 200, self_check.text
    payload = self_check.json()
    assert payload["published"] is True
    assert payload["render_ok"] is True
    assert payload["guest_reachable"] is None
    assert payload["guest_reachable_reason"] == "guest_device_check_required"
    assert payload["reason_code"] == "entry.render_ok"


def test_self_check_unpublished_page(client) -> None:
    page = _create_guest_page(client)
    page_id = page["page_id"]
    draft = client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document(title="Draft only")},
    )
    assert draft.status_code == 200, draft.text
    response = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/self-check",
        json={},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["published"] is False
    assert payload["render_ok"] is None
    assert payload["reason_code"] == "entry.not_published"
    assert payload["guest_reachable"] is None
    assert payload["guest_reachable_reason"] == "guest_device_check_required"


@pytest.mark.parametrize(
    "bind_value",
    [
        pytest.param(None, id="unset"),
        pytest.param("   ", id="blank"),
    ],
)
def test_self_check_public_zone_enabled_null_without_bind(
    client,
    monkeypatch: pytest.MonkeyPatch,
    bind_value: str | None,
) -> None:
    page = _create_guest_page(client)
    page_id = page["page_id"]
    draft = client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document(title="Public zone probe")},
    )
    assert draft.status_code == 200, draft.text
    revision_id = draft.json()["revision"]["revision_id"]
    published = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/publish",
        json={"revision_id": revision_id},
    )
    assert published.status_code == 200, published.text
    if bind_value is None:
        monkeypatch.delenv("RC_PUBLIC_ENTRY_BIND", raising=False)
    else:
        monkeypatch.setenv("RC_PUBLIC_ENTRY_BIND", bind_value)
    response = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/self-check",
        json={},
    )
    assert response.status_code == 200, response.text
    assert response.json()["public_zone_enabled"] is None


def test_self_check_public_zone_enabled_true_when_bind_set(
    client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RC_PUBLIC_ENTRY_BIND", "192.168.1.10:8790")
    page = _create_guest_page(client)
    page_id = page["page_id"]
    draft = client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document(title="Bind configured")},
    )
    assert draft.status_code == 200, draft.text
    revision_id = draft.json()["revision"]["revision_id"]
    published = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/publish",
        json={"revision_id": revision_id},
    )
    assert published.status_code == 200, published.text
    response = client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/self-check",
        json={},
    )
    assert response.status_code == 200, response.text
    assert response.json()["public_zone_enabled"] is True


def test_create_entry_page_handles_concurrent_ensure_race(client, monkeypatch) -> None:
    import sqlite3

    host = client.app.state.host
    svc = host.entry_page_service()
    site_id = host.resolve_site_id()
    real_find = svc.store.find_entry_page_by_audience
    stale_read = {"pending": False}

    def patched_find(site_id: str, audience: str):
        if stale_read["pending"]:
            stale_read["pending"] = False
            return None
        return real_find(site_id, audience)

    def patched_create(**kwargs):
        raise sqlite3.IntegrityError("unique audience index")

    first = client.post("/api/router-control/v1/entry-pages", json={"audience": "staff"})
    assert first.status_code == 201, first.text
    page_id = first.json()["page_id"]

    stale_read["pending"] = True
    monkeypatch.setattr(svc.store, "find_entry_page_by_audience", patched_find)
    monkeypatch.setattr(svc.store, "create_entry_page", patched_create)

    second = client.post("/api/router-control/v1/entry-pages", json={"audience": "staff"})
    assert second.status_code == 201, second.text
    assert second.json()["page_id"] == page_id
    assert "internal.error" not in second.text
    assert real_find(site_id, "staff") is not None
