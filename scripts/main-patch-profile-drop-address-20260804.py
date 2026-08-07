"""Main-only diagnostic patch: drop interface_address from a catalog profile's metadata
so the next activate skips SET_IP_ADDRESS (isolates whether peer handshake works
independent of the already-documented interface-address dispatch failure).
Never touches secret tables; only rewrites the non-secret metadata_json blob.
"""

from __future__ import annotations

import json
import sqlite3
import sys

DB = "data/router_control.sqlite3"


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: main-patch-profile-drop-address-20260804.py <profile_id>", file=sys.stderr)
        return 2
    profile_id = sys.argv[1]
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "select metadata_json from vpn_profile_artifacts where profile_id = ?", (profile_id,)
    ).fetchone()
    if row is None:
        print("profile not found", file=sys.stderr)
        return 1
    metadata = json.loads(row["metadata_json"] or "{}")
    had = "interface_address" in metadata
    metadata.pop("interface_address", None)
    con.execute(
        "update vpn_profile_artifacts set metadata_json = ? where profile_id = ?",
        (json.dumps(metadata, sort_keys=True), profile_id),
    )
    con.commit()
    print(json.dumps({"profile_id": profile_id, "had_interface_address": had, "patched": True}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
