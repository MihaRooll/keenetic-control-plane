"""Event preset persistence migration and CRUD."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.domain.event_preset import (
    build_safe_default_document,
    document_to_revision_fields,
)
from router_control.persistence.connection import open_database
from router_control.persistence.errors import IdempotencyConflict, PreconditionFailed
from router_control.persistence.migrations import CURRENT_USER_VERSION, migrate
from router_control.persistence.store import PersistenceStore

FIXED = datetime(2026, 7, 22, 12, 0, 0, tzinfo=UTC)


@pytest.fixture
def store(tmp_path: Path) -> PersistenceStore:
    conn = open_database(tmp_path / "preset.sqlite3")
    return PersistenceStore(conn)


def _canonical_pair() -> tuple[str, str]:
    doc = build_safe_default_document()
    canonical, digest = document_to_revision_fields(doc)
    import json

    return json.dumps(canonical, sort_keys=True, separators=(",", ":")), digest


def test_migration_reaches_version_current(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "m.sqlite3")
    assert migrate(conn) == CURRENT_USER_VERSION
    tables = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
    }
    assert "event_presets" in tables
    assert "event_preset_revisions" in tables
    assert "worker_instances" in tables


def test_migration_1_to_current(tmp_path: Path) -> None:
    import sqlite3

    from router_control.persistence import migrations

    conn = sqlite3.connect(tmp_path / "v1.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(migrations._MIGRATION_1)
        conn.execute("PRAGMA user_version = 1")
        assert migrate(conn) == CURRENT_USER_VERSION
    finally:
        conn.close()


def test_migration_2_to_current(tmp_path: Path) -> None:
    import sqlite3

    from router_control.persistence import migrations

    conn = sqlite3.connect(tmp_path / "v2.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.executescript(migrations._MIGRATION_1)
        conn.executescript(migrations._MIGRATION_2)
        conn.execute("PRAGMA user_version = 2")
        assert migrate(conn) == CURRENT_USER_VERSION
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "event_presets" in tables
    finally:
        conn.close()


def test_legacy_v3_to_current(tmp_path: Path) -> None:
    import sqlite3

    from router_control.persistence import migrations

    conn = sqlite3.connect(tmp_path / "v3.sqlite3")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        for version in range(1, 4):
            conn.executescript(migrations._MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
        assert migrate(conn, db_path=tmp_path / "v3.sqlite3") == CURRENT_USER_VERSION
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        assert "event_presets" in tables
        assert "router_execution_fences" in tables
    finally:
        conn.close()


def test_create_preset_idempotent(store: PersistenceStore) -> None:
    site_id = store.create_site(display_name="Lab", now=FIXED)
    canonical_json, digest = _canonical_pair()
    p1, r1, created1 = store.create_event_preset(
        site_id=site_id,
        name="Booth",
        canonical_json=canonical_json,
        canonical_digest=digest,
        validation_status="ValidOffline",
        summary_redacted=None,
        idempotency_key="create-1",
        request_digest="sha256:req1",
        now=FIXED,
    )
    assert created1 is True
    p2, r2, created2 = store.create_event_preset(
        site_id=site_id,
        name="Booth",
        canonical_json=canonical_json,
        canonical_digest=digest,
        validation_status="ValidOffline",
        summary_redacted=None,
        idempotency_key="create-1",
        request_digest="sha256:req1",
        now=FIXED,
    )
    assert created2 is False
    assert p1["preset_id"] == p2["preset_id"]
    assert r1["revision_id"] == r2["revision_id"]


def test_revision_immutable_and_etag(store: PersistenceStore) -> None:
    site_id = store.create_site(display_name="Lab", now=FIXED)
    canonical_json, digest = _canonical_pair()
    preset, rev, _ = store.create_event_preset(
        site_id=site_id,
        name="Booth",
        canonical_json=canonical_json,
        canonical_digest=digest,
        validation_status="ValidOffline",
        summary_redacted=None,
        idempotency_key="k1",
        request_digest="sha256:req",
        now=FIXED,
    )
    preset2, rev2, created = store.create_event_preset_revision_idempotent(
        preset_id=preset["preset_id"],
        canonical_json=canonical_json,
        canonical_digest=digest,
        validation_status="ValidOffline",
        summary_redacted=None,
        idempotency_key="rev-1",
        request_digest="sha256:rev",
        expected_version=1,
        now=FIXED,
    )
    assert created is True
    assert rev2["revision_number"] == 2
    assert preset2["version"] == 2
    assert preset2["etag"] != preset["etag"]


def test_publish_precondition(store: PersistenceStore) -> None:
    site_id = store.create_site(display_name="Lab", now=FIXED)
    canonical_json, digest = _canonical_pair()
    preset, rev, _ = store.create_event_preset(
        site_id=site_id,
        name="Booth",
        canonical_json=canonical_json,
        canonical_digest=digest,
        validation_status="ValidOffline",
        summary_redacted=None,
        idempotency_key="k1",
        request_digest="sha256:req",
        now=FIXED,
    )
    with pytest.raises(PreconditionFailed):
        store.publish_event_preset_revision_idempotent(
            preset_id=preset["preset_id"],
            revision_id=rev["revision_id"],
            idempotency_key="pub-1",
            request_digest="sha256:pub",
            expected_version=99,
            now=FIXED,
        )


def test_idempotency_digest_conflict(store: PersistenceStore) -> None:
    site_id = store.create_site(display_name="Lab", now=FIXED)
    canonical_json, digest = _canonical_pair()
    store.create_event_preset(
        site_id=site_id,
        name="Booth",
        canonical_json=canonical_json,
        canonical_digest=digest,
        validation_status="ValidOffline",
        summary_redacted=None,
        idempotency_key="k1",
        request_digest="sha256:req",
        now=FIXED,
    )
    with pytest.raises(IdempotencyConflict):
        store.create_event_preset(
            site_id=site_id,
            name="Booth",
            canonical_json=canonical_json,
            canonical_digest=digest,
            validation_status="ValidOffline",
            summary_redacted=None,
            idempotency_key="k1",
            request_digest="sha256:other",
            now=FIXED,
        )
