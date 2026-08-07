"""Application service tests for entry pages."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest
from router_control.application.entry_pages import (
    EntryPageNotFound,
    EntryPageService,
    EntryPageValidationError,
    render_public_html,
    validate_and_canonicalize_entry_document,
)
from router_control.composition import FixedClock
from router_control.persistence.connection import open_database
from router_control.persistence.store import PersistenceStore


@pytest.fixture
def runtime(tmp_path):
    conn = open_database(tmp_path / "entry-service.sqlite3")
    store = PersistenceStore(conn)
    clock = FixedClock(datetime(2026, 8, 4, 12, 0, 0, tzinfo=UTC))
    site_id = store.create_site(display_name="Service Lab", now=clock.now())
    service = EntryPageService(store=store, clock=clock)
    return service, site_id


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


def _staff_document(**overrides):
    doc = _guest_document()
    doc["roles"] = ["Host", "Security"]
    doc.update(overrides)
    return doc


def test_html_rejection_in_title(runtime) -> None:
    service, site_id = runtime
    page = service.ensure_page(site_id, "guest")
    with pytest.raises(EntryPageValidationError) as exc_info:
        service.save_draft(page["page_id"], _guest_document(title="<script>"))
    assert exc_info.value.code == "entry.html_not_allowed"
    assert exc_info.value.field == "title"


def test_render_public_html_escapes_quotes_and_ampersands(runtime) -> None:
    document = _guest_document(
        title='Кафе "У Иваныча" & Ко',
        fields=[
            {
                "name": "note",
                "label": 'Комментарий & "особый"',
                "kind": "text",
                "required": False,
            }
        ],
    )
    html_body = render_public_html(
        document,
        audience="guest",
        slug="demo-slug",
        submit_path="/p/demo-slug/submit",
    )
    assert "Кафе &quot;У Иваныча&quot; &amp; Ко" in html_body
    assert "Комментарий &amp; &quot;особый&quot;" in html_body
    assert 'value="Комментарий &amp; &quot;особый&quot;"' not in html_body
    assert 'id="note"' in html_body
    assert "<script" not in html_body.lower()
    assert 'style="' not in html_body


def test_render_public_html_has_no_operator_leaks(runtime) -> None:
    html_body = render_public_html(
        _guest_document(),
        audience="guest",
        slug="safe-slug",
        submit_path="/p/safe-slug/submit",
    )
    lowered = html_body.lower()
    for forbidden in ("/api", "/settings", "hub", "router"):
        assert forbidden not in lowered


def test_same_document_produces_identical_content_sha256(runtime) -> None:
    service, site_id = runtime
    page = service.ensure_page(site_id, "guest")
    doc = _guest_document()
    first = service.save_draft(page["page_id"], doc)
    second = service.save_draft(page["page_id"], doc)
    assert (
        first["revision"]["content_sha256"]
        == second["revision"]["content_sha256"]
    )


def test_validation_rejects_unknown_keys_and_role_rules(runtime) -> None:
    service, site_id = runtime
    guest_page = service.ensure_page(site_id, "guest")
    with pytest.raises(EntryPageValidationError) as exc_info:
        service.save_draft(guest_page["page_id"], _guest_document(extra="nope"))
    assert exc_info.value.code == "entry.validation_failed"

    with pytest.raises(EntryPageValidationError) as exc_info:
        service.save_draft(
            guest_page["page_id"],
            _guest_document(roles=["Host"]),
        )
    assert exc_info.value.code == "entry.validation_failed"
    assert exc_info.value.field == "roles"

    staff_page = service.ensure_page(site_id, "staff")
    with pytest.raises(EntryPageValidationError) as exc_info:
        service.save_draft(staff_page["page_id"], _guest_document())
    assert exc_info.value.code == "entry.validation_failed"
    assert exc_info.value.field == "roles"


def test_validation_rejects_field_limits_and_select_options(runtime) -> None:
    service, site_id = runtime
    page = service.ensure_page(site_id, "guest")
    too_many_fields = [
        {
            "name": f"field_{index}",
            "label": f"Field {index}",
            "kind": "text",
            "required": False,
        }
        for index in range(9)
    ]
    with pytest.raises(EntryPageValidationError) as exc_info:
        service.save_draft(page["page_id"], _guest_document(fields=too_many_fields))
    assert exc_info.value.code == "entry.validation_failed"
    assert exc_info.value.field == "fields"

    with pytest.raises(EntryPageValidationError) as exc_info:
        service.save_draft(
            page["page_id"],
            _guest_document(
                fields=[
                    {
                        "name": "choice",
                        "label": "Choice",
                        "kind": "text",
                        "required": False,
                        "options": ["A"],
                    }
                ]
            ),
        )
    assert exc_info.value.code == "entry.validation_failed"
    assert exc_info.value.field == "fields[0].options"


def test_publish_unpublish_and_render_published_only(runtime) -> None:
    service, site_id = runtime
    page = service.ensure_page(site_id, "guest")
    saved = service.save_draft(page["page_id"], _guest_document())
    revision_id = saved["revision"]["revision_id"]

    html_before, reason_before = service.render_document_for_page(
        page["page_id"], published_only=True
    )
    assert html_before is None
    assert reason_before == "entry.not_published"

    service.publish(page["page_id"], revision_id)
    html_after, reason_after = service.render_document_for_page(
        page["page_id"], published_only=True
    )
    assert html_after is not None
    assert reason_after == "entry.render_ok"

    service.unpublish(page["page_id"])
    html_unpub, reason_unpub = service.render_document_for_page(
        page["page_id"], published_only=True
    )
    assert html_unpub is None
    assert reason_unpub == "entry.not_published"


def test_publish_foreign_revision_raises(runtime) -> None:
    service, site_id = runtime
    guest = service.ensure_page(site_id, "guest")
    staff = service.ensure_page(site_id, "staff")
    staff_rev = service.save_draft(staff["page_id"], _staff_document())
    with pytest.raises(EntryPageNotFound) as exc_info:
        service.publish(guest["page_id"], staff_rev["revision"]["revision_id"])
    assert exc_info.value.code == "entry.revision_not_found"


def test_get_page_and_slug_not_found(runtime) -> None:
    service, _site_id = runtime
    with pytest.raises(EntryPageNotFound):
        service.get_page("epage_missing")
    with pytest.raises(EntryPageNotFound):
        service.get_page_by_slug("missing-slug")


def test_staff_render_includes_role_select(runtime) -> None:
    html_body = render_public_html(
        _staff_document(),
        audience="staff",
        slug="staff-slug",
        submit_path="/p/staff-slug/submit",
    )
    assert '<select name="role"' in html_body
    assert "Host" in html_body


def test_submissions_disabled_skips_form(runtime) -> None:
    html_body = render_public_html(
        _guest_document(submissions_enabled=False),
        audience="guest",
        slug="no-form",
        submit_path="/p/no-form/submit",
    )
    assert "<form" not in html_body
    assert "<button" not in html_body


def test_canonicalize_duplicate_field_name(runtime) -> None:
    with pytest.raises(EntryPageValidationError) as exc_info:
        validate_and_canonicalize_entry_document(
            _guest_document(
                fields=[
                    {
                        "name": "dup",
                        "label": "One",
                        "kind": "text",
                        "required": True,
                    },
                    {
                        "name": "dup",
                        "label": "Two",
                        "kind": "text",
                        "required": False,
                    },
                ]
            ),
            audience="guest",
        )
    assert exc_info.value.code == "entry.validation_failed"
    assert exc_info.value.field == "fields[1].name"


def test_staff_roles_limit(runtime) -> None:
    with pytest.raises(EntryPageValidationError) as exc_info:
        validate_and_canonicalize_entry_document(
            _staff_document(roles=[f"role_{index}" for index in range(13)]),
            audience="staff",
        )
    assert exc_info.value.code == "entry.validation_failed"
    assert exc_info.value.field == "roles"


def test_content_sha256_matches_canonical_bytes(runtime) -> None:
    canonical, canonical_json, content_sha256 = validate_and_canonicalize_entry_document(
        _guest_document(),
        audience="guest",
    )
    expected = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    assert content_sha256 == expected
    assert canonical["title"] == "Guest welcome"
