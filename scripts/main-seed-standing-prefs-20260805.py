"""Main-only: restore the standing_network_preferences singleton row.

The row is normally created by migration 14. It went missing on this host after
`scripts/main-repair-schema-v14-20260805.py` recreated the table without
re-seeding it, which made `GET /standing-network-preferences` fail with 500 and
left the staff/guest blocks on the main menu empty. Values here are copied from
`_MIGRATION_14` so the restored row is identical to a fresh install.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys

SEED = (
    "default",
    "Рабочая сеть",
    None,
    "Гостевая сеть",
    0,
    "1970-01-01T00:00:00+00:00",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/router_control.sqlite3")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute("SELECT * FROM standing_network_preferences").fetchall()
        print(f"rows_before={len(rows)}")
        for row in rows:
            print("existing:", dict(row))
        if rows:
            print("nothing to do")
            return 0
        conn.execute(
            "INSERT INTO standing_network_preferences ("
            "preferences_id, staff_ssid, staff_password_credential_ref_id, "
            "guest_default_ssid, guest_default_enabled, updated_at"
            ") VALUES (?, ?, ?, ?, ?, ?)",
            SEED,
        )
        conn.commit()
        for row in conn.execute("SELECT * FROM standing_network_preferences"):
            print("seeded:", dict(row))
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
