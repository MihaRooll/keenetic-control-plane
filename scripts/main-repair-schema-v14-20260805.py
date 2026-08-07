"""Main-only repair: reconcile the live lab database with the canonical schema.

Why this exists: the live database was migrated to user_version 14 by an earlier revision
of migration 14, and that migration was then rewritten by a later package cycle. The
fingerprint check compares the *text* of every schema object, so the host now refuses to
start with "schema fingerprint mismatch for user_version=14".

This script replays the current migrations in memory to obtain the canonical schema for the
database's current version, diffs it object by object against the live database, and — only
with --apply — drops and recreates the objects that differ. It refuses to touch any object
that holds rows, so no operator data can be destroyed silently.

Dry run by default:
  py -3.11 scripts/main-repair-schema-v14-20260805.py
Apply:
  py -3.11 scripts/main-repair-schema-v14-20260805.py --apply
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

DB = REPO_ROOT / "data" / "router_control.sqlite3"


def _objects(conn: sqlite3.Connection) -> dict[tuple[str, str], tuple[str, str]]:
    rows = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations' "
        "ORDER BY type, name"
    ).fetchall()
    return {(row[0], row[1]): (row[2], row[3] or "") for row in rows}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true", help="actually repair the live database")
    parser.add_argument(
        "--allow-drop",
        action="append",
        default=[],
        metavar="TABLE",
        help="table that may be recreated even though it holds rows; use only after "
        "inspecting the rows and confirming they are regenerable defaults",
    )
    args = parser.parse_args()

    from router_control.persistence.migrations import (  # noqa: E402
        _MIGRATIONS,
        _execute_sql_statements,
        compute_schema_fingerprint,
        normalize_sql,
    )

    live = sqlite3.connect(str(DB))
    version = int(live.execute("PRAGMA user_version").fetchone()[0])
    print(f"live user_version = {version}")

    canonical = sqlite3.connect(":memory:")
    canonical.execute("PRAGMA foreign_keys = ON")
    for step in range(1, version + 1):
        _execute_sql_statements(canonical, _MIGRATIONS[step])
        canonical.execute(f"PRAGMA user_version = {step}")

    expected = compute_schema_fingerprint(canonical)
    actual = compute_schema_fingerprint(live)
    print(f"expected fingerprint: {expected}")
    print(f"actual fingerprint:   {actual}")
    if expected == actual:
        print("\nschema already matches; nothing to repair")
        return 0

    live_objects = _objects(live)
    canonical_objects = _objects(canonical)

    only_live = sorted(set(live_objects) - set(canonical_objects))
    only_canonical = sorted(set(canonical_objects) - set(live_objects))
    differing = sorted(
        key
        for key in set(live_objects) & set(canonical_objects)
        if normalize_sql(live_objects[key][1]) != normalize_sql(canonical_objects[key][1])
    )

    print(f"\nobjects only in live db:      {only_live}")
    print(f"objects only in canonical:    {only_canonical}")
    print(f"objects with differing DDL:   {differing}")

    affected_tables: set[str] = set()
    for kind, name in only_live + differing:
        affected_tables.add(name if kind == "table" else live_objects[(kind, name)][0])
    for kind, name in only_canonical:
        affected_tables.add(name if kind == "table" else canonical_objects[(kind, name)][0])

    print(f"\naffected tables: {sorted(affected_tables)}")
    blocked: list[str] = []
    for table in sorted(affected_tables):
        try:
            count = live.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.Error:
            count = 0
        print(f"  {table}: {count} row(s)")
        if count > 0:
            for row in live.execute(f"SELECT * FROM {table} LIMIT 5"):
                print(f"      row: {row}")
        if count > 0 and table not in args.allow_drop:
            blocked.append(f"{table} ({count} rows)")

    if blocked:
        print(
            "\nREFUSING to repair automatically — these affected tables hold rows: "
            + ", ".join(blocked)
            + "\nInspect them manually; this script never drops tables containing data."
        )
        return 2

    for key in differing:
        print(f"\n--- DDL diff for {key[0]} {key[1]} ---")
        print("live:      " + normalize_sql(live_objects[key][1])[:400])
        print("canonical: " + normalize_sql(canonical_objects[key][1])[:400])

    if not args.apply:
        print("\ndry run only; re-run with --apply to repair")
        return 1

    backup = DB.with_name(f"router_control.pre-repair-{int(time.time())}.sqlite3")
    shutil.copy2(DB, backup)
    print(f"\nbackup written: {backup}")

    live.execute("PRAGMA foreign_keys = OFF")
    live.execute("BEGIN EXCLUSIVE")
    try:
        for kind, name in sorted(only_live + differing, key=lambda item: item[0] != "index"):
            live.execute(f"DROP {kind.upper()} IF EXISTS {name}")
            print(f"dropped {kind} {name}")
        for kind, name in sorted(set(only_canonical) | set(differing), key=lambda i: i[0] != "table"):
            ddl = canonical_objects[(kind, name)][1]
            if ddl:
                live.execute(ddl)
                print(f"recreated {kind} {name}")
        live.execute("COMMIT")
    except Exception:
        live.execute("ROLLBACK")
        raise
    finally:
        live.execute("PRAGMA foreign_keys = ON")

    repaired = compute_schema_fingerprint(live)
    print(f"\nfingerprint after repair: {repaired}")
    print("MATCHES canonical" if repaired == expected else "STILL DIFFERS — investigate")
    return 0 if repaired == expected else 3


if __name__ == "__main__":
    raise SystemExit(main())
