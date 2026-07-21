"""SQLite connection policy: foreign_keys, busy_timeout, parameter binding only."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from router_control.persistence.migrations import migrate

DEFAULT_DB_PATH = Path("data") / "router_control.sqlite3"
_BUSY_TIMEOUT_MS = 5_000


def connect(path: Path | str, *, wal: bool = True) -> sqlite3.Connection:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    if wal:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def open_database(path: Path | str, *, wal: bool = True) -> sqlite3.Connection:
    """Open (or create) DB and run migrations to current schema."""
    conn = connect(path, wal=wal)
    migrate(conn)
    return conn


@contextmanager
def transaction(
    conn: sqlite3.Connection, *, immediate: bool = False
) -> Iterator[sqlite3.Connection]:
    begin = "BEGIN IMMEDIATE" if immediate else "BEGIN"
    conn.execute(begin)
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
