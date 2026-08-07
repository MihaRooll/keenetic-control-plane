"""Main-only: find sealed apply runs whose planned ops mention ip_global or keepalive."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / "data" / "router_control.sqlite3"


def main() -> int:
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT started_at, run_id, route, verb, status, overall, ops_planned_redacted, "
        "outcome_snapshot_redacted FROM sealed_apply_runs "
        "WHERE route LIKE '%vpn%' OR route LIKE '%wireguard%' ORDER BY started_at DESC LIMIT 200"
    ).fetchall()

    print(f"scanned {len(rows)} vpn/wireguard runs")
    for row in rows:
        planned = row["ops_planned_redacted"] or ""
        if "global" not in planned and "keepalive" not in planned:
            continue
        try:
            names = list(json.loads(planned).keys()) if planned.strip().startswith("{") else json.loads(planned)
        except json.JSONDecodeError:
            names = planned[:200]
        snapshot = row["outcome_snapshot_redacted"] or ""
        signals = ""
        if snapshot:
            try:
                data = json.loads(snapshot)
                read = data.get("verdict_explanation", {}).get("signals_read", [])
                signals = ", ".join(f"{s.get('signal')}={s.get('value')}" for s in read)
            except json.JSONDecodeError:
                signals = "<unparsable>"
        print(f"\n{row['started_at']} | {row['route']}/{row['verb']} | {row['status']}/{row['overall']} | {row['run_id']}")
        print(f"  planned: {names}")
        if signals:
            print(f"  signals: {signals}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
