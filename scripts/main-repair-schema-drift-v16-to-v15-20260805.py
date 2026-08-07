"""Main-only: undo an out-of-band schema drift of the shared operator database.

Situation this repairs
----------------------
`data/router_control.sqlite3` is the database the operator's host on port 8787
opens. A test run (the loopback test in `tests/test_hub_staff_wifi.py`) opened
that SHARED file while migration 16 still existed in the code, so the file was
upgraded to `user_version = 16` and gained the columns `staff_ap_id` and
`guest_ap_id`. Migration 16 was then reverted in code after a T3 rejection, so
the code is back at 15 while the file is at 16. The running host is unaffected
because it loaded the old code, but the next start would fail closed with
"Schema version 16 newer than supported 15".

Approach, in order of preference
-------------------------------
1. Work on a COPY: drop the two added columns and set `user_version` back to 15.
2. Compare the resulting schema fingerprint against the canonical v15
   fingerprint that the product itself computes from its migration SQL
   (`EXPECTED_SCHEMA_FINGERPRINTS[15]`). SQLite rewrites table DDL on DROP
   COLUMN, so this comparison is the whole point — a byte-identical schema is
   the only acceptable outcome.
3. Only on an exact match, swap the repaired copy in, after taking a fresh
   backup of the current file.

If the fingerprints disagree the script changes nothing and says so. The
fallback is then the product's own automatic pre-migration backup, which is
reported but never restored automatically — that is the operator's data.

Nothing here touches the router. Requires the host to be stopped so the file is
not open.
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from router_control.persistence.migrations import (  # noqa: E402
    EXPECTED_SCHEMA_FINGERPRINTS,
    compute_schema_fingerprint,
)

TARGET_VERSION = 15
DRIFTED_COLUMNS = ("staff_ap_id", "guest_ap_id")
TABLE = "standing_network_preferences"


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def describe(path: Path, label: str) -> tuple[int, list[str]]:
    uri = f"file:{path.as_posix()}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    try:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        columns = [row[1] for row in conn.execute(f"PRAGMA table_info({TABLE})")]
        print(f"{label}: user_version={version} columns={columns}")
        return version, columns
    finally:
        conn.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/router_control.sqlite3")
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Actually swap the repaired copy in. Without this the script only reports.",
    )
    args = parser.parse_args()

    db = Path(args.db)
    if not db.is_file():
        print(f"database not found: {db}", file=sys.stderr)
        return 2

    expected = EXPECTED_SCHEMA_FINGERPRINTS.get(TARGET_VERSION)
    if not expected:
        print(f"no canonical fingerprint for v{TARGET_VERSION} in code", file=sys.stderr)
        return 2
    print(f"canonical v{TARGET_VERSION} fingerprint: {expected}")

    version, columns = describe(db, "live file (before)")
    if version == TARGET_VERSION:
        print("already at target version; nothing to repair")
        return 0
    if version != TARGET_VERSION + 1:
        print(
            f"unexpected drift: file at v{version}, this script only undoes "
            f"v{TARGET_VERSION + 1} -> v{TARGET_VERSION}",
            file=sys.stderr,
        )
        return 2

    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    work = db.with_name(f"{db.stem}.repair-{stamp}.sqlite3")
    shutil.copy2(db, work)
    print(f"working copy: {work.name}")

    conn = sqlite3.connect(work)
    try:
        present = [row[1] for row in conn.execute(f"PRAGMA table_info({TABLE})")]
        for column in DRIFTED_COLUMNS:
            if column in present:
                conn.execute(f"ALTER TABLE {TABLE} DROP COLUMN {column}")
                print(f"dropped column {column}")
        conn.execute(f"PRAGMA user_version = {TARGET_VERSION}")
        conn.execute(
            "DELETE FROM schema_migrations WHERE version > ?", (TARGET_VERSION,)
        )
        conn.commit()
        actual = compute_schema_fingerprint(conn)
        rows = conn.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0]
    finally:
        conn.close()

    print(f"repaired copy fingerprint: {actual}")
    print(f"singleton rows preserved: {rows}")
    describe(work, "repaired copy")

    if actual != expected:
        print(
            "\nFINGERPRINT MISMATCH — refusing to swap. SQLite's DROP COLUMN did not "
            "reproduce the canonical v15 DDL byte-for-byte.",
            file=sys.stderr,
        )
        backups = sorted(Path("data/backups").glob("pre-migrate-v15-*.sqlite3"))
        if backups:
            newest = backups[-1]
            print(f"fallback candidate (NOT restored automatically): {newest}")
            digest_file = newest.with_suffix(".sha256")
            if digest_file.is_file():
                recorded = digest_file.read_text(encoding="utf-8").strip().split()[0]
                actual_digest = sha256_of(newest)
                match = "MATCHES" if recorded == actual_digest else "DOES NOT MATCH"
                print(f"backup sha256 {match} its recorded digest")
        print(f"working copy kept for inspection: {work}")
        return 1

    print("\nFINGERPRINT MATCHES canonical v15.")
    if not args.apply:
        print("dry run — re-run with --apply to swap the repaired copy in")
        return 0

    safety = db.with_name(f"{db.stem}.pre-repair-{stamp}.sqlite3")
    shutil.copy2(db, safety)
    print(f"safety copy of drifted file: {safety.name} (sha256 {sha256_of(safety)[:16]}…)")

    for suffix in ("-wal", "-shm"):
        sidecar = db.with_name(db.name + suffix)
        if sidecar.exists():
            print(f"removing stale sidecar {sidecar.name}")
            sidecar.unlink()

    shutil.copy2(work, db)
    work.unlink()
    describe(db, "live file (after)")
    print("\nREPAIR_APPLIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
