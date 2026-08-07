"""Main-only diagnostic: read audit_events / sealed_apply_runs without a browser."""

from __future__ import annotations

import sqlite3

DB = "data/router_control.sqlite3"


def _cols(con: sqlite3.Connection, table: str) -> list[str]:
    return [r[1] for r in con.execute(f"PRAGMA table_info({table})")]


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row

    print("audit_events columns:", _cols(con, "audit_events"))
    print("sealed_apply_runs columns:", _cols(con, "sealed_apply_runs"))

    print()
    print("=== audit_events (last 10) ===")
    for r in con.execute("select * from audit_events order by rowid desc limit 10"):
        print(dict(r))

    print()
    print("=== sealed_apply_runs (last 5) ===")
    for r in con.execute("select * from sealed_apply_runs order by rowid desc limit 5"):
        print(dict(r))


if __name__ == "__main__":
    main()
