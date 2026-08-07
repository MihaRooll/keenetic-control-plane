"""Public guest entry zone isolation and behaviour tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi import APIRouter
from router_control.application.entry_pages import PublicHtmlBuilder
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.public_app import (
    assert_public_zone_route_isolation,
    create_public_app,
    is_allowed_public_zone_path,
    iter_public_route_paths,
)
from router_control_host.public_entry_routes import (
    EntrySubmitRateLimiter,
    set_entry_submit_rate_limiter_for_tests,
)
from starlette.routing import Mount, Route


@pytest.fixture
def shared_db(tmp_path: Path) -> Path:
    return tmp_path / "shared.sqlite3"


@pytest.fixture
def operator_client(shared_db: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    app = create_app(db_path=shared_db)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


@pytest.fixture
def public_client(shared_db: Path):
    app = create_public_app(db_path=shared_db)
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
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


def _publish_guest_page_via_operator_http(
    operator_client,
    *,
    title: str = "Guest welcome",
) -> dict:
    create = operator_client.post("/api/router-control/v1/entry-pages", json={"audience": "guest"})
    assert create.status_code == 201, create.text
    page_id = create.json()["page_id"]
    draft = operator_client.put(
        f"/api/router-control/v1/entry-pages/{page_id}/draft",
        json={"document": _guest_document(title=title)},
    )
    assert draft.status_code == 200, draft.text
    revision_id = draft.json()["revision"]["revision_id"]
    published = operator_client.post(
        f"/api/router-control/v1/entry-pages/{page_id}/publish",
        json={"revision_id": revision_id},
    )
    assert published.status_code == 200, published.text
    detail = operator_client.get(f"/api/router-control/v1/entry-pages/{page_id}")
    assert detail.status_code == 200, detail.text
    payload = detail.json()
    payload["page_id"] = page_id
    return payload


def _publish_guest_page(operator_client, *, title: str = "Guest welcome") -> dict:
    host = operator_client.app.state.host
    site_id = host.ensure_default_site()
    page = host.entry_page_service().ensure_page(site_id, "guest")
    saved = host.entry_page_service().save_draft(
        page["page_id"],
        _guest_document(title=title),
    )
    published = host.entry_page_service().publish(
        page["page_id"],
        str(saved["revision"]["revision_id"]),
    )
    return published


def _public_route_paths(app) -> set[str]:
    return set(iter_public_route_paths(app.routes))


def test_published_page_via_operator_http_chain(public_client, operator_client) -> None:
    """Operator HTTP create→draft→publish, then public GET returns published HTML."""
    published = _publish_guest_page_via_operator_http(
        operator_client,
        title="HTTP operator published title",
    )
    response = public_client.get(f"/p/{published['slug']}")
    assert response.status_code == 200
    assert "HTTP operator published title" in response.text


def test_operator_app_does_not_mount_public_routes(operator_client, public_client) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]
    response = operator_client.get(f"/p/{slug}")
    assert response.status_code == 404


def test_public_app_route_set_is_exactly_three(public_client) -> None:
    expected = {
        "/p/{slug}",
        "/p/_assets/entry-page.css",
        "/p/{slug}/submit",
    }
    assert _public_route_paths(public_client.app) == expected


def test_public_zone_route_guard_rejects_non_p_paths() -> None:
    contaminated = [
        Route("/secret-op", endpoint=lambda request: None),
    ]
    with pytest.raises(RuntimeError, match="forbidden path: '/secret-op'"):
        assert_public_zone_route_isolation(contaminated)


@pytest.mark.parametrize(
    "path",
    [
        "/ptrap",
        "/private",
        "/px",
        "/p-trap",
        "/P/x",
    ],
)
def test_public_zone_route_guard_rejects_p_prefix_false_positives(path: str) -> None:
    assert not is_allowed_public_zone_path(path)
    contaminated = [Route(path, endpoint=lambda request: None)]
    with pytest.raises(RuntimeError, match="forbidden path"):
        assert_public_zone_route_isolation(contaminated)


def test_public_zone_route_guard_rejects_mount_p_traversal_escape() -> None:
    contaminated = [
        Mount("/p", routes=[Route("/../secret-op", endpoint=lambda request: None)]),
    ]
    with pytest.raises(RuntimeError, match="forbidden path"):
        assert_public_zone_route_isolation(contaminated)


def test_public_zone_route_guard_allows_p_slash_paths() -> None:
    allowed = [
        Route("/p/{slug}", endpoint=lambda request: None),
        Route("/p/_assets/entry-page.css", endpoint=lambda request: None),
    ]
    assert_public_zone_route_isolation(allowed)


def test_public_zone_route_guard_rejects_nested_mount() -> None:
    contaminated = [
        Mount("/secret-op", routes=[Route("/login", endpoint=lambda request: None)]),
    ]
    with pytest.raises(RuntimeError, match="forbidden path: '/secret-op/login'"):
        assert_public_zone_route_isolation(contaminated)


def test_create_public_app_refuses_contaminated_mount(shared_db: Path) -> None:
    app = create_public_app(db_path=shared_db)
    secret = APIRouter()

    @secret.get("/secret-op")
    def _secret() -> dict[str, str]:
        return {"leak": "yes"}

    app.include_router(secret)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.get("/secret-op")
        assert response.status_code == 404
        assert response.text == "Страница не найдена."
        assert "leak" not in response.text


def test_public_app_rejects_operator_surfaces(public_client) -> None:
    probes = [
        ("GET", "/api/router-control/v1/entry-pages"),
        ("GET", "/settings/router-control/hub/"),
        ("GET", "/login"),
        ("GET", "/openapi.json"),
        ("GET", "/docs"),
    ]
    for method, path in probes:
        response = public_client.request(method, path)
        assert response.status_code == 404, (method, path, response.text)


def test_published_page_without_cookie(public_client, operator_client) -> None:
    published = _publish_guest_page(operator_client)
    response = public_client.get(f"/p/{published['slug']}")
    assert response.status_code == 200
    text = response.text
    lowered = text.lower()
    assert "/api" not in lowered
    assert "/settings" not in lowered
    assert "<script" not in lowered
    assert "correlation" not in lowered
    assert "router" not in lowered


def test_unknown_and_unpublished_slug_identical_404(public_client, operator_client) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]
    host = operator_client.app.state.host
    host.entry_page_service().unpublish(published["page_id"])
    unknown_get = public_client.get("/p/unknown-slug-abc123")
    unpublished_get = public_client.get(f"/p/{slug}")
    assert unknown_get.status_code == 404
    assert unpublished_get.status_code == 404
    assert unknown_get.content == unpublished_get.content
    for response in (unknown_get, unpublished_get):
        _assert_public_security_headers(response)
    unknown_post = public_client.post(
        "/p/unknown-slug-abc123/submit",
        data={"full_name": ""},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    unpublished_post = public_client.post(
        f"/p/{slug}/submit",
        data={"full_name": ""},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert unknown_post.status_code == 404
    assert unpublished_post.status_code == 404
    assert unknown_post.content == unpublished_post.content
    for response in (unknown_post, unpublished_post):
        _assert_public_security_headers(response)


def test_html_escaping(public_client, operator_client) -> None:
    title = 'Кафе "У Иваныча" & Ко «тест» 😀'
    published = _publish_guest_page(
        operator_client,
        title=title,
    )
    response = public_client.get(f"/p/{published['slug']}")
    assert response.status_code == 200
    escaped = 'Кафе &quot;У Иваныча&quot; &amp; Ко «тест» 😀'
    assert f"<title>\n{escaped}\n</title>" in response.text
    assert f"<h1>\n{escaped}\n</h1>" in response.text
    assert title not in response.text
    assert "&amp;amp;" not in response.text


def _assert_public_security_headers(response) -> None:
    csp = response.headers.get("content-security-policy", "")
    assert "default-src 'none'" in csp
    assert "script-src" not in csp.lower()
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("referrer-policy") == "no-referrer"
    assert response.headers.get("cache-control") == "no-store"
    assert response.headers.get("x-robots-tag") == "noindex"


def test_security_headers_on_all_public_responses(
    public_client,
    operator_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]

    ok_html = public_client.get(f"/p/{slug}")
    assert ok_html.status_code == 200
    css = public_client.get("/p/_assets/entry-page.css")
    missing = public_client.get("/p/no-such-slug")
    not_found_path = public_client.get("/login")
    wrong_method = public_client.delete(f"/p/{slug}")
    wrong_type = public_client.post(
        f"/p/{slug}/submit",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    for response in (ok_html, css, missing, not_found_path, wrong_method, wrong_type):
        _assert_public_security_headers(response)

    host = operator_client.app.state.host
    host.entry_page_service().unpublish(published["page_id"])
    unpublished = public_client.get(f"/p/{slug}")
    assert unpublished.status_code == 404
    _assert_public_security_headers(unpublished)

    limiter = EntrySubmitRateLimiter(global_max=0, per_slug_max=0)
    set_entry_submit_rate_limiter_for_tests(limiter)
    try:
        saved = host.entry_page_service().save_draft(
            published["page_id"],
            _guest_document(),
        )
        host.entry_page_service().publish(
            published["page_id"],
            str(saved["revision"]["revision_id"]),
        )
        blocked = public_client.post(
            f"/p/{slug}/submit",
            data={"full_name": "A"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert blocked.status_code == 404
        _assert_public_security_headers(blocked)
    finally:
        set_entry_submit_rate_limiter_for_tests(None)

    svc = public_client.app.state.host.entry_page_service()

    def _forced_failure(_slug: str):
        raise RuntimeError("forced public zone failure")

    monkeypatch.setattr(svc, "get_page_by_slug", _forced_failure)
    from fastapi.testclient import TestClient

    with TestClient(public_client.app, raise_server_exceptions=False) as crash_client:
        server_error = crash_client.get(f"/p/{slug}")
        assert server_error.status_code == 500
        _assert_public_security_headers(server_error)


def _all_table_counts(conn) -> dict[str, int]:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return {
        str(row[0]): conn.execute(f"SELECT COUNT(*) FROM [{row[0]}]").fetchone()[0]
        for row in rows
    }


def test_submit_accepts_declared_field_and_persists_nothing(
    public_client,
    operator_client,
    tmp_path: Path,
) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]
    store = public_client.app.state.host.runtime.store
    before = _all_table_counts(store.conn)
    canary = "CANARY_SUBMIT_NO_PERSIST_445566"
    response = public_client.post(
        f"/p/{slug}/submit",
        data={"full_name": canary},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 200
    assert response.json() == {"accepted": True}
    after = _all_table_counts(store.conn)
    assert before == after
    assert canary not in response.text
    data_dir = tmp_path
    for path in data_dir.rglob("*"):
        if path.is_file():
            assert canary not in path.read_text(encoding="utf-8", errors="ignore")


def test_submit_rejects_when_submissions_disabled(public_client, operator_client) -> None:
    host = operator_client.app.state.host
    site_id = host.ensure_default_site()
    page = host.entry_page_service().ensure_page(site_id, "guest")
    saved = host.entry_page_service().save_draft(
        page["page_id"],
        _guest_document(submissions_enabled=False),
    )
    published = host.entry_page_service().publish(
        page["page_id"],
        str(saved["revision"]["revision_id"]),
    )
    response = public_client.post(
        f"/p/{published['slug']}/submit",
        data={"full_name": "Test"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "entry.submissions_disabled"


def test_submit_rate_limited_returns_identical_not_found(
    public_client,
    operator_client,
) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]
    clock = {"now": 1000.0}

    def _clock() -> float:
        return clock["now"]

    limiter = EntrySubmitRateLimiter(global_max=2, per_slug_max=2, clock=_clock)
    set_entry_submit_rate_limiter_for_tests(limiter)
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    try:
        for _ in range(2):
            ok = public_client.post(
                f"/p/{slug}/submit",
                data={"full_name": "A"},
                headers=headers,
            )
            assert ok.status_code == 200
        published_blocked = public_client.post(
            f"/p/{slug}/submit",
            data={"full_name": "B"},
            headers=headers,
        )
        host = operator_client.app.state.host
        host.entry_page_service().unpublish(published["page_id"])
        unpublished_blocked = public_client.post(
            f"/p/{slug}/submit",
            data={"full_name": "B"},
            headers=headers,
        )
        unknown_blocked = public_client.post(
            "/p/unknown-slug-abc123/submit",
            data={"full_name": "B"},
            headers=headers,
        )
        for response in (published_blocked, unpublished_blocked, unknown_blocked):
            assert response.status_code == 404
            _assert_public_security_headers(response)
        assert published_blocked.content == unpublished_blocked.content == unknown_blocked.content
    finally:
        set_entry_submit_rate_limiter_for_tests(None)


def test_public_error_messages_avoid_operator_jargon(public_client, operator_client) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]
    operator_terms = (
        "preview",
        "compilation",
        "revision",
        "slug",
        "preset",
        "probe",
        "router",
        "resource not found",
        "method not allowed",
    )
    english_operator_phrases = (
        "Resource not found",
        "Method not allowed",
    )
    responses = []

    not_found_path = public_client.get("/login")
    assert not_found_path.status_code == 404
    responses.append(not_found_path)

    wrong_method = public_client.delete(f"/p/{slug}")
    assert wrong_method.status_code == 405
    responses.append(wrong_method)

    wrong_type = public_client.post(
        f"/p/{slug}/submit",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert wrong_type.status_code == 422
    responses.append(wrong_type)

    host = operator_client.app.state.host
    site_id = host.ensure_default_site()
    page = host.entry_page_service().ensure_page(site_id, "guest")
    saved = host.entry_page_service().save_draft(
        page["page_id"],
        _guest_document(submissions_enabled=False),
    )
    published_disabled = host.entry_page_service().publish(
        page["page_id"],
        str(saved["revision"]["revision_id"]),
    )
    disabled = public_client.post(
        f"/p/{published_disabled['slug']}/submit",
        data={"full_name": "Test"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert disabled.status_code == 422
    responses.append(disabled)

    for response in responses:
        lowered = response.text.lower()
        for term in operator_terms:
            assert term not in lowered
        for phrase in english_operator_phrases:
            assert phrase not in response.text
        assert "correlation_id" not in lowered
        if response.headers.get("content-type", "").startswith("application/json"):
            body = response.json()
            assert "correlation_id" not in body.get("error", {})


def test_public_html_builder_escapes_dynamic_text() -> None:
    builder = PublicHtmlBuilder()
    builder._static("<p>")
    builder.text("<script>alert(1)</script>")
    builder._static("</p>")
    assert builder.build() == "<p>\n&lt;script&gt;alert(1)&lt;/script&gt;\n</p>"


def test_public_html_builder_rejects_dynamic_markup() -> None:
    builder = PublicHtmlBuilder()
    with pytest.raises(ValueError, match="module-level constants only"):
        builder._static("<script>")


def test_submit_rejects_missing_required_field(public_client, operator_client) -> None:
    published = _publish_guest_page(operator_client)
    response = public_client.post(
        f"/p/{published['slug']}/submit",
        data={},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "entry.validation_failed"
    assert "correlation_id" not in body["error"]


def test_submit_rejects_invalid_select_value(public_client, operator_client) -> None:
    host = operator_client.app.state.host
    site_id = host.ensure_default_site()
    page = host.entry_page_service().ensure_page(site_id, "guest")
    saved = host.entry_page_service().save_draft(
        page["page_id"],
        _guest_document(
            fields=[
                {
                    "name": "visit_type",
                    "label": "Type",
                    "kind": "select",
                    "required": True,
                    "options": ["Day", "Night"],
                }
            ],
        ),
    )
    published = host.entry_page_service().publish(
        page["page_id"],
        str(saved["revision"]["revision_id"]),
    )
    response = public_client.post(
        f"/p/{published['slug']}/submit",
        data={"visit_type": "INVALID"},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "entry.validation_failed"
    assert "INVALID" not in response.text


def test_submit_rejects_overlong_field_value(public_client, operator_client) -> None:
    published = _publish_guest_page(operator_client)
    canary = "CANARY_OVERLONG_FIELD_778899"
    response = public_client.post(
        f"/p/{published['slug']}/submit",
        data={"full_name": ("x" * 600) + canary},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == 422
    assert canary not in response.text


def test_submit_rate_limiter_stays_bounded_and_cannot_evade() -> None:
    clock = {"now": 1000.0}

    def _clock() -> float:
        return clock["now"]

    limiter = EntrySubmitRateLimiter(
        global_max=100,
        per_slug_max=2,
        max_tracked_slugs=4,
        clock=_clock,
    )
    for index in range(4):
        limiter.record(f"tracked-{index}")
    assert limiter.tracked_slug_count == 4
    assert limiter.is_blocked("brand-new-slug")
    limiter.record("tracked-0")
    limiter.record("tracked-0")
    assert limiter.is_blocked("tracked-0")
    for flood_index in range(20):
        assert limiter.is_blocked(f"flood-{flood_index}")
    assert limiter.is_blocked("tracked-0")
    assert limiter.tracked_slug_count <= 4
    clock["now"] += 120.0
    assert not limiter.is_blocked("tracked-0")
    assert limiter.tracked_slug_count < 4


def test_oversized_submit_rejected_without_echo(public_client, operator_client) -> None:
    published = _publish_guest_page(operator_client)
    slug = published["slug"]
    canary = "CANARY_OVERSIZED_BODY_112233"
    oversized = ("full_name=" + ("x" * 9000) + canary).encode("utf-8")
    response = public_client.post(
        f"/p/{slug}/submit",
        content=oversized,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code in (413, 422)
    assert canary not in response.text
