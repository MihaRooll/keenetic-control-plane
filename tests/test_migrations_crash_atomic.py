"""P1-A migration atomicity and concurrent owner tests."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest
from router_control.persistence.connection import connect
from router_control.persistence.migrations import (
    _MIGRATIONS,
    CURRENT_USER_VERSION,
    _execute_sql_statements,
    _migration_owner_lock,
    migrate,
)


def _build_legacy_v3_db(path: Path) -> None:
    conn = connect(path, wal=False)
    try:
        for version in range(1, 4):
            _execute_sql_statements(conn, _MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
    finally:
        conn.close()


def test_concurrent_migrate_single_owner(tmp_path: Path) -> None:
    db_path = tmp_path / "conc.sqlite3"
    connect(db_path, wal=False).close()
    results: list[int] = []
    start = threading.Barrier(2)

    def worker() -> None:
        conn = connect(db_path, wal=False)
        start.wait()
        try:
            migrate(conn, db_path=db_path)
            results.append(int(conn.execute("PRAGMA user_version").fetchone()[0]))
        finally:
            conn.close()

    t1 = threading.Thread(target=worker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join(timeout=30)
    t2.join(timeout=30)
    assert results == [CURRENT_USER_VERSION, CURRENT_USER_VERSION]
    conn = connect(db_path, wal=False)
    try:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        assert (
            conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
            == CURRENT_USER_VERSION
        )
    finally:
        conn.close()


def test_migration_lock_serializes_threads(tmp_path: Path) -> None:
    db_path = tmp_path / "lock.sqlite3"
    order: list[int] = []
    lock = threading.Barrier(2)

    def worker(tag: int) -> None:
        lock.wait()
        with _migration_owner_lock(db_path):
            order.append(tag)

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join(timeout=5)
    t2.join(timeout=5)
    assert len(order) == 2
    assert order != [1, 1]


def test_partial_migration_rolls_back_user_version(tmp_path: Path) -> None:
    path = tmp_path / "rollback.sqlite3"
    conn = connect(path, wal=False)
    conn.execute("PRAGMA user_version = 3")
    conn.executescript(
        "CREATE TABLE sites (site_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, "
        "timezone TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);"
    )
    conn.commit()
    conn.close()
    conn = connect(path, wal=False)
    with pytest.raises(RuntimeError, match="fingerprint mismatch"):
        migrate(conn, db_path=path)
    assert conn.execute("PRAGMA user_version").fetchone()[0] == 3


def test_crash_mid_migration_recovers(tmp_path: Path) -> None:
    db_path = tmp_path / "crash.sqlite3"
    barrier = tmp_path / "migrate.barrier"
    _build_legacy_v3_db(db_path)
    child_script = textwrap.dedent(
        f"""
        import os
        from pathlib import Path
        from router_control.persistence.connection import connect
        from router_control.persistence.migrations import migrate

        os.environ["ROUTER_CONTROL_MIGRATE_TEST_BARRIER"] = {str(barrier)!r}
        os.environ["ROUTER_CONTROL_MIGRATE_PAUSE_AT"] = "4"
        conn = connect({str(db_path)!r}, wal=False)
        try:
            migrate(conn, db_path={str(db_path)!r})
        finally:
            conn.close()
        """
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
    proc = subprocess.Popen(
        [sys.executable, "-c", child_script],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    saw_before = False
    while True:
        if proc.poll() is not None:
            break
        if barrier.exists():
            marker = barrier.read_text(encoding="utf-8")
            if marker == "before_sql:4":
                saw_before = True
                barrier.write_text("release", encoding="utf-8")
            elif marker == "after_sql:4":
                break
        elif saw_before and proc.poll() is None:
            time.sleep(0.01)
    if proc.poll() is None:
        proc.kill()
        proc.wait(timeout=10)
    conn = connect(db_path, wal=False)
    try:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        assert version in (3, CURRENT_USER_VERSION)
        quick = conn.execute("PRAGMA quick_check").fetchone()
        assert quick is not None and str(quick[0]).lower() == "ok"
        migrate(conn, db_path=db_path)
        assert conn.execute("PRAGMA user_version").fetchone()[0] == CURRENT_USER_VERSION
        assert (
            conn.execute("SELECT COUNT(*) FROM schema_migrations").fetchone()[0]
            == CURRENT_USER_VERSION
        )
    finally:
        conn.close()
        barrier.unlink(missing_ok=True)
