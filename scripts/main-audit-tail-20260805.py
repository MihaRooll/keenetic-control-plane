"""Main-only audit/apply-run tail for the 2026-08-05 session (read-only, redacted columns).

Usage:
  py -3.11 scripts/main-audit-tail-20260805.py [limit] [--filter substring]
"""

from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

DB = Path(__file__).resolve().parents[1] / "data" / "router_control.sqlite3"


def _clip(value: object, width: int) -> str:
    text = "" if value is None else str(value)
    return text[:width] + ("…" if len(text) > width else "")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("limit", nargs="?", type=int, default=20)
    parser.add_argument("--filter", default="", help="substring filter on action/route/evidence")
    parser.add_argument("--width", type=int, default=260)
    args = parser.parse_args()

    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    needle = args.filter.lower()

    print("--- audit_events (newest first) ---")
    query = (
        "SELECT occurred_at, action, outcome, risk_level, summary_redacted "
        "FROM audit_events ORDER BY occurred_at DESC LIMIT ?"
    )
    shown = 0
    for row in conn.execute(query, (args.limit * 12 if needle else args.limit,)):
        blob = f"{row['action']} {row['summary_redacted'] or ''}".lower()
        if needle and needle not in blob:
            continue
        print(
            f"{row['occurred_at']} | {row['action']} | {row['outcome']} | "
            f"{_clip(row['summary_redacted'], args.width)}"
        )
        shown += 1
        if shown >= args.limit:
            break

    print("\n--- sealed_apply_runs (newest first) ---")
    query = (
        "SELECT started_at, finished_at, run_id, route, verb, status, overall, "
        "error_redacted, ops_evidence_redacted, outcome_snapshot_redacted "
        "FROM sealed_apply_runs ORDER BY started_at DESC LIMIT ?"
    )
    shown = 0
    for row in conn.execute(query, (args.limit * 12 if needle else args.limit,)):
        blob = f"{row['route']} {row['verb']} {row['ops_evidence_redacted'] or ''}".lower()
        if needle and needle not in blob:
            continue
        print(
            f"{row['started_at']} -> {row['finished_at']} | {row['route']}/{row['verb']} | "
            f"status={row['status']} overall={row['overall']} | run={row['run_id']}"
        )
        if row["error_redacted"]:
            print(f"    error: {_clip(row['error_redacted'], args.width)}")
        if row["ops_evidence_redacted"]:
            print(f"    ops:   {_clip(row['ops_evidence_redacted'], args.width)}")
        if row["outcome_snapshot_redacted"]:
            print(f"    out:   {_clip(row['outcome_snapshot_redacted'], args.width)}")
        shown += 1
        if shown >= args.limit:
            break

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
