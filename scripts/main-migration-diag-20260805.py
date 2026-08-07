"""Main-only diagnostic: why does the live database fail the schema fingerprint check?"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DB = REPO_ROOT / "data" / "router_control.sqlite3"
MIGRATIONS = REPO_ROOT / "router_control" / "persistence" / "migrations.py"


def main() -> int:
    source = MIGRATIONS.read_text(encoding="utf-8")

    current = re.search(r"CURRENT_USER_VERSION\s*=\s*(\d+)", source)
    print("CURRENT_USER_VERSION in code:", current.group(1) if current else "not found")

    names = sorted(set(re.findall(r"_MIGRATION_(\d+)\b", source)), key=int)
    print("migration constants present:", names)

    fingerprints = re.findall(r"(\d+)\s*:\s*[\"']([0-9a-f]{64})[\"']", source)
    if fingerprints:
        print("fingerprint table entries (version -> digest prefix):")
        for version, digest in fingerprints:
            print(f"  {version} -> {digest[:16]}…")

    conn = sqlite3.connect(str(DB))
    print("\nlive db user_version:", conn.execute("PRAGMA user_version").fetchone()[0])

    tables = [
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    ]
    interesting = [t for t in tables if "pref" in t or "uplink" in t or "standing" in t]
    print("live tables matching pref/uplink/standing:", interesting)
    print("live table count:", len(tables))

    for table in interesting:
        cols = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
        print(f"  {table}: {cols}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
