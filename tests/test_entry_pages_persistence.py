"""Persistence tests for entry pages (migration 13)."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

import pytest
from router_control.persistence.connection import open_database
from router_control.persistence.errors import NotFoundError
from router_control.persistence.migrations import (
    _MIGRATIONS,
    CURRENT_USER_VERSION,
    _execute_sql_statements,
    migrate,
)
from router_control.persistence.store import PersistenceStore


@pytest.fixture
def store(tmp_path) -> PersistenceStore:
    conn = open_database(tmp_path / "entry-pages.sqlite3")
    return PersistenceStore(conn)


def _seed_site(store: PersistenceStore) -> str:
    return store.create_site(display_name="Entry Lab", now=datetime(2026, 8, 4, tzinfo=UTC))


def _canonical_json(title: str = "Welcome") -> str:
    return (
        '{"button_label":"Go","fields":[],"intro":"","submissions_enabled":true,'
        f'"title":"{title}"}}'
    )


def _content_sha256(canonical_json: str) -> str:
    import hashlib

    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def test_migration_13_fresh_db_reaches_current_version(tmp_path) -> None:
    conn = open_database(tmp_path / "fresh.sqlite3")
    migrate(conn)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    tables = {
        row[0]
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert "entry_pages" in tables
    assert "entry_page_revisions" in tables


def _build_v12_db(path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 13):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_migration_13_from_v12_is_idempotent(tmp_path) -> None:
    path = tmp_path / "v12.sqlite3"
    _build_v12_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 12
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        migrate(conn, db_path=path)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    finally:
        conn.close()


def test_one_page_per_audience_enforced_by_schema(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    now = datetime(2026, 8, 4, tzinfo=UTC)
    store.create_entry_page(site_id=site_id, audience="guest", slug="guest-a", now=now)
    with pytest.raises(sqlite3.IntegrityError):
        store.create_entry_page(site_id=site_id, audience="guest", slug="guest-b", now=now)


def test_entry_page_revision_immutable_numbering(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    now = datetime(2026, 8, 4, tzinfo=UTC)
    page_id = store.create_entry_page(
        site_id=site_id, audience="staff", slug="staff-one", now=now
    )
    canonical = _canonical_json("Staff")
    rev1 = store.append_entry_page_revision(
        page_id=page_id,
        canonical_json=canonical,
        content_sha256=_content_sha256(canonical),
        now=now,
    )
    rev2 = store.append_entry_page_revision(
        page_id=page_id,
        canonical_json=canonical,
        content_sha256=_content_sha256(canonical),
        now=now,
    )
    assert rev1["revision_number"] == 1
    assert rev2["revision_number"] == 2
    page = store.get_entry_page(page_id)
    assert page is not None
    assert page["current_revision_id"] == rev2["revision_id"]


def test_publish_accepts_own_revision_rejects_foreign(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    now = datetime(2026, 8, 4, tzinfo=UTC)
    guest_id = store.create_entry_page(
        site_id=site_id, audience="guest", slug="guest-pub", now=now
    )
    staff_id = store.create_entry_page(
        site_id=site_id, audience="staff", slug="staff-pub", now=now
    )
    canonical = _canonical_json()
    guest_rev = store.append_entry_page_revision(
        page_id=guest_id,
        canonical_json=canonical,
        content_sha256=_content_sha256(canonical),
        now=now,
    )
    staff_rev = store.append_entry_page_revision(
        page_id=staff_id,
        canonical_json=canonical,
        content_sha256=_content_sha256(canonical),
        now=now,
    )
    store.set_entry_page_published_revision(
        page_id=guest_id,
        revision_id=guest_rev["revision_id"],
        now=now,
    )
    with pytest.raises(NotFoundError, match="revision not found"):
        store.set_entry_page_published_revision(
            page_id=guest_id,
            revision_id=staff_rev["revision_id"],
            now=now,
        )


def test_unpublish_clears_pointer(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    now = datetime(2026, 8, 4, tzinfo=UTC)
    page_id = store.create_entry_page(
        site_id=site_id, audience="guest", slug="guest-unpub", now=now
    )
    canonical = _canonical_json()
    rev = store.append_entry_page_revision(
        page_id=page_id,
        canonical_json=canonical,
        content_sha256=_content_sha256(canonical),
        now=now,
    )
    store.set_entry_page_published_revision(
        page_id=page_id, revision_id=rev["revision_id"], now=now
    )
    store.clear_entry_page_published_revision(page_id=page_id, now=now)
    page = store.get_entry_page(page_id)
    assert page is not None
    assert page["published_revision_id"] is None


def test_find_and_list_entry_pages(store: PersistenceStore) -> None:
    site_id = _seed_site(store)
    now = datetime(2026, 8, 4, tzinfo=UTC)
    guest_id = store.create_entry_page(
        site_id=site_id, audience="guest", slug="guest-list", now=now
    )
    staff_id = store.create_entry_page(
        site_id=site_id, audience="staff", slug="staff-list", now=now
    )
    assert store.find_entry_page_by_audience(site_id, "guest")["page_id"] == guest_id
    assert store.get_entry_page_by_slug("staff-list")["page_id"] == staff_id
    listed = store.list_entry_pages(site_id)
    assert {row["page_id"] for row in listed} == {guest_id, staff_id}
