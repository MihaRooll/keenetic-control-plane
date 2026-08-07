"""Main-only diagnostic: recent wifi station apply/preview audit history."""

from __future__ import annotations

import sqlite3

DB = "data/router_control.sqlite3"


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "select occurred_at, action, outcome, summary_redacted from audit_events "
        "where action like '%station%' order by occurred_at desc limit 6"
    ).fetchall()
    for r in rows:
        print(r["occurred_at"], r["action"], r["outcome"])
        print((r["summary_redacted"] or "")[:1000])
        print("---")


if __name__ == "__main__":
    main()
