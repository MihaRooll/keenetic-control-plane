"""Main-only diagnostic: read the pre-apply baseline for the latest wifi.station run."""

from __future__ import annotations

import json
import sqlite3

DB = "data/router_control.sqlite3"


def main() -> None:
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    row = con.execute(
        "select * from sealed_apply_runs where route='wifi.station' order by rowid desc limit 1"
    ).fetchone()
    if row is None:
        print("no run found")
        return
    d = dict(row)
    for key in ("pre_apply_baseline_redacted", "checkpoint_json", "ops_evidence_redacted"):
        if d.get(key):
            print(f"--- {key} ---")
            try:
                print(json.dumps(json.loads(d[key]), indent=2)[:3000])
            except Exception:
                print(d[key][:2000])


if __name__ == "__main__":
    main()
