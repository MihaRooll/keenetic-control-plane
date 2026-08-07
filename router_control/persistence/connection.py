"""SQLite connection policy: foreign_keys, busy_timeout, parameter binding only.

Invariants (per connection):
- Never issue BEGIN / BEGIN IMMEDIATE while ``conn.in_transaction`` is true.
- Serialize all use of a connection via ``PersistenceStore``'s per-store RLock.
- Do not hold the store/connection lock across network or handler I/O outside
  store methods (long I/O inside an open transaction blocks other store callers).
"""

from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from router_control.persistence.migrations import DEFAULT_DB_PATH, migrate

__all__ = [
    "DEFAULT_DB_PATH",
    "NestedTransactionError",
    "connect",
    "open_database",
    "resolve_db_path",
    "transaction",
]

_BUSY_TIMEOUT_MS = 5_000


class NestedTransactionError(RuntimeError):
    """Raised when ``transaction()`` is called while a transaction is already active."""


def resolve_db_path(db_path: Path | str | None = None) -> Path:
    """Resolve the sqlite path callers should open.

    Priority: explicit db_path argument > ROUTER_CONTROL_DB_PATH env
    override > production DEFAULT_DB_PATH. Refuses the production default
    while a test session is active with neither an explicit path nor an env
    override, so a harness that forgets isolation fails loudly at startup
    instead of silently opening/migrating the operator's live database.

    Two layers detect an active test session (either is sufficient):

    - ``PYTEST_CURRENT_TEST`` — per-test signal set by pytest during each
      test item's setup/call/teardown window; fast and obvious when code
      runs inside a test.
    - ``ROUTER_CONTROL_TEST_SESSION`` — set once at ``tests/conftest.py``
      import time (pytest collection start), timing-independent; covers
      collection-time code, module-level code, session/module-scoped
      fixtures, and subprocesses built via ``os.environ.copy()``.

    Both propagate into subprocesses whose env is built from
    ``os.environ.copy()``, which is the only pattern this repo's test
    harnesses use.
    """
    if db_path is not None:
        return Path(db_path)
    override = os.environ.get("ROUTER_CONTROL_DB_PATH", "").strip()
    if override:
        return Path(override)
    if (
        os.environ.get("PYTEST_CURRENT_TEST") is not None
        or os.environ.get("ROUTER_CONTROL_TEST_SESSION") is not None
    ):
        raise RuntimeError(
            "Refusing to open production database "
            f"{DEFAULT_DB_PATH} while PYTEST_CURRENT_TEST or "
            "ROUTER_CONTROL_TEST_SESSION is set; pass an explicit db_path or "
            "set ROUTER_CONTROL_DB_PATH."
        )
    return DEFAULT_DB_PATH


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
    db_path = Path(path)
    conn = connect(path, wal=wal)
    migrate(conn, db_path=db_path)
    return conn


@contextmanager
def transaction(
    conn: sqlite3.Connection, *, immediate: bool = False
) -> Iterator[sqlite3.Connection]:
    """Begin a single SQLite transaction; fail closed on nested BEGIN.

    Callers already inside an open transaction must use ``*_unlocked`` helpers
    or direct SQL on ``conn`` — do not call ``transaction()`` again on the same
    connection until COMMIT or ROLLBACK completes.
    """
    if conn.in_transaction:
        raise NestedTransactionError(
            "cannot start a transaction within a transaction; "
            "use *_unlocked helpers inside an open transaction"
        )
    begin = "BEGIN IMMEDIATE" if immediate else "BEGIN"
    conn.execute(begin)
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
