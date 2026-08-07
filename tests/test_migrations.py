"""P1-A migration runner: fingerprint, checksums, idempotent migrate."""

from __future__ import annotations

import hashlib
from pathlib import Path

from router_control.persistence.connection import open_database
from router_control.persistence.migrations import (
    _MIGRATIONS,
    CURRENT_USER_VERSION,
    EXPECTED_SCHEMA_FINGERPRINTS,
    MIGRATION_CHECKSUMS,
    _execute_sql_statements,
    compute_schema_fingerprint,
    migrate,
)


def test_migration_checksums_immutable() -> None:
    for version in range(1, CURRENT_USER_VERSION + 1):
        source = _MIGRATIONS[version]
        assert MIGRATION_CHECKSUMS[version] == hashlib.sha256(source.encode()).hexdigest()


def test_expected_fingerprints_match_live_schema(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "fp.sqlite3")
    fp = compute_schema_fingerprint(conn)
    assert fp == EXPECTED_SCHEMA_FINGERPRINTS[CURRENT_USER_VERSION]
    for version in range(1, CURRENT_USER_VERSION + 1):
        row = conn.execute(
            "SELECT schema_fingerprint_sha256 FROM schema_migrations WHERE version = ?",
            (version,),
        ).fetchone()
        assert row is not None
        if version == CURRENT_USER_VERSION:
            assert row[0] == fp


def test_migrate_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "idem.sqlite3"
    conn = open_database(path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    migrate(conn, db_path=path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
    history = conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
    assert history == CURRENT_USER_VERSION


def test_schema_migrations_source_apply_on_fresh_db(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "fresh.sqlite3")
    rows = conn.execute(
        "SELECT source FROM schema_migrations ORDER BY version"
    ).fetchall()
    assert all(str(r[0]) == "apply" for r in rows)


def test_v4_live_tables_present(tmp_path: Path) -> None:
    conn = open_database(tmp_path / "v4.sqlite3")
    tables = {
        str(r[0])
        for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    for name in (
        "worker_instances",
        "router_execution_fences",
        "external_effects",
        "external_effect_events",
        "recovery_requests",
        "artifact_staging",
        "router_safety_sessions",
        "router_boot_observations",
        "router_evidence_revisions",
    ):
        assert name in tables


def _build_legacy_v3_db(path: Path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 4):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
    finally:
        conn.close()


def test_legacy_v3_backfill_migrates_atomically(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v3.sqlite3"
    _build_legacy_v3_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone()
            is None
        )
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        history = conn.execute(
            "SELECT version, source FROM schema_migrations ORDER BY version"
        ).fetchall()
        assert len(history) == CURRENT_USER_VERSION
        assert all(str(r[1]) in ("apply", "backfill_legacy") for r in history)
        backfill_rows = [r for r in history if str(r[1]) == "backfill_legacy"]
        assert len(backfill_rows) == 3
        assert conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='worker_instances'"
        ).fetchone() is not None
    finally:
        conn.close()


def test_pre_migrate_backup_durable_order(tmp_path: Path) -> None:
    from router_control.persistence.connection import connect
    from router_control.persistence.migrations import _backup_before_pending_migrate

    db_path = tmp_path / "backup-order.sqlite3"
    _build_legacy_v3_db(db_path)
    conn = connect(db_path, wal=False)
    try:
        conn.execute(
            "INSERT INTO sites(site_id, display_name, timezone, created_at, updated_at) "
            "VALUES ('site-1', 'Lab', 'UTC', '2026-07-22T00:00:00Z', '2026-07-22T00:00:00Z')"
        )
        conn.commit()
        backup_path = _backup_before_pending_migrate(conn, db_path, 3)
    finally:
        conn.close()
    assert backup_path.is_file()
    sidecar = backup_path.with_suffix(".sha256")
    assert sidecar.is_file()
    expected = sidecar.read_text(encoding="utf-8").strip()
    actual = hashlib.sha256(backup_path.read_bytes()).hexdigest()
    assert actual == expected
    temp_glob = list(backup_path.parent.glob(".pre-migrate-v3-*.tmp"))
    assert temp_glob == []


def _build_legacy_v5_db(path: Path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 6):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_legacy_v5_upgrades_to_v6_with_source_address(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v5.sqlite3"
    _build_legacy_v5_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 5
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        cols = [
            str(row[1])
            for row in conn.execute("PRAGMA table_info(router_endpoints)").fetchall()
        ]
        assert "source_address" in cols
        fp = compute_schema_fingerprint(conn)
        assert fp == EXPECTED_SCHEMA_FINGERPRINTS[CURRENT_USER_VERSION]
    finally:
        conn.close()


def _build_legacy_v6_db(path: Path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 7):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_legacy_v6_upgrades_to_v7_with_ssh_host_key_columns(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v6.sqlite3"
    _build_legacy_v6_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 6
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        cols = [
            str(row[1])
            for row in conn.execute("PRAGMA table_info(router_endpoints)").fetchall()
        ]
        assert "ssh_host_key_sha256" in cols
        assert "ssh_host_key_algorithm" in cols
        assert "ssh_host_key_pinned_at" in cols
        assert "ssh_host_key_provenance" in cols
        fp = compute_schema_fingerprint(conn)
        assert fp == EXPECTED_SCHEMA_FINGERPRINTS[CURRENT_USER_VERSION]
    finally:
        conn.close()


def _build_legacy_v7_db(path: Path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 8):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_legacy_v7_upgrades_to_v8_with_jobs_status_created_at_index(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v7.sqlite3"
    _build_legacy_v7_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 7
        before = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='jobs'"
            ).fetchall()
        }
        assert "idx_jobs_status_created_at" not in before
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        indexes = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='jobs'"
            ).fetchall()
        }
        assert "idx_jobs_status_created_at" in indexes
        fp = compute_schema_fingerprint(conn)
        assert fp == EXPECTED_SCHEMA_FINGERPRINTS[CURRENT_USER_VERSION]
    finally:
        conn.close()


def _build_legacy_v8_db(path: Path) -> None:
    from router_control.persistence.connection import connect

    conn = connect(path, wal=False)
    try:
        for version in range(1, 9):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
        conn.commit()
    finally:
        conn.close()


def test_legacy_v8_upgrades_to_v9_with_sealed_apply_runs(tmp_path: Path) -> None:
    path = tmp_path / "legacy-v8.sqlite3"
    _build_legacy_v8_db(path)
    from router_control.persistence.connection import connect as raw_connect

    conn = raw_connect(path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 8
        before = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "sealed_apply_runs" not in before
    finally:
        conn.close()

    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        tables = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        assert "sealed_apply_runs" in tables
        indexes = {
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index' "
                "AND tbl_name='sealed_apply_runs'"
            ).fetchall()
        }
        assert "idx_sealed_apply_runs_status" in indexes
        fp = compute_schema_fingerprint(conn)
        assert fp == EXPECTED_SCHEMA_FINGERPRINTS[CURRENT_USER_VERSION]
    finally:
        conn.close()


def test_v4_drop_schema_migrations_backfill_or_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "v4-rebackfill.sqlite3"
    conn = open_database(path)
    conn.execute("DROP TABLE schema_migrations")
    conn.close()
    conn = open_database(path)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        count = conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
        assert count == CURRENT_USER_VERSION
        row = conn.execute(
            "SELECT source FROM schema_migrations WHERE version = 4"
        ).fetchone()
        assert row is not None
        assert str(row[0]) == "backfill_legacy"
    finally:
        conn.close()
