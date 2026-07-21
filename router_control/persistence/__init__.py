"""SQLite persistence (SLICE-2). No FastAPI."""

from __future__ import annotations

from router_control.persistence.connection import DEFAULT_DB_PATH, connect, open_database
from router_control.persistence.migrations import CURRENT_USER_VERSION, migrate
from router_control.persistence.store import PersistenceStore

__all__ = [
    "CURRENT_USER_VERSION",
    "DEFAULT_DB_PATH",
    "PersistenceStore",
    "connect",
    "migrate",
    "open_database",
]
