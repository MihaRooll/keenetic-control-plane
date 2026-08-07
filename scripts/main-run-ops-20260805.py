"""Main-only: print the planned/dispatched op names of a sealed apply run (no secrets).

Usage:
  py -3.11 scripts/main-run-ops-20260805.py <run_id>
  py -3.11 scripts/main-run-ops-20260805.py --latest vpn-profiles activate
"""

from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

DB = Path(__file__).resolve().parents[1] / "data" / "router_control.sqlite3"


def _op_names(blob: str | None) -> Any:
    if not blob:
        return None
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return "<unparsable>"
    if isinstance(data, dict):
        return list(data.keys())
    if isinstance(data, list):
        names = []
        for item in data:
            if isinstance(item, dict):
                names.append(item.get("op") or item.get("operation") or sorted(item.keys())[:2])
            else:
                names.append(str(item))
        return names
    return data


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("run_id", nargs="?")
    parser.add_argument("--latest", nargs=2, metavar=("ROUTE", "VERB"))
    args = parser.parse_args()

    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row

    if args.latest:
        row = conn.execute(
            "SELECT * FROM sealed_apply_runs WHERE route=? AND verb=? "
            "ORDER BY started_at DESC LIMIT 1",
            (args.latest[0], args.latest[1]),
        ).fetchone()
    else:
        row = conn.execute("SELECT * FROM sealed_apply_runs WHERE run_id=?", (args.run_id,)).fetchone()

    if row is None:
        print("run not found")
        return 1

    print(f"run_id={row['run_id']} route={row['route']}/{row['verb']} status={row['status']} overall={row['overall']}")
    print(f"started={row['started_at']} finished={row['finished_at']}")
    for column in ("ops_planned_redacted", "ops_dispatched_redacted", "ops_pending_redacted"):
        print(f"\n{column}: {json.dumps(_op_names(row[column]), ensure_ascii=False)}")

    evidence = row["ops_evidence_redacted"]
    if evidence:
        try:
            data = json.loads(evidence)
        except json.JSONDecodeError:
            data = {}
        print("\nops_evidence per op:")
        for name, payload in (data.items() if isinstance(data, dict) else []):
            ok = payload.get("ok") if isinstance(payload, dict) else None
            ident = payload.get("status_ident") if isinstance(payload, dict) else None
            err = payload.get("error") if isinstance(payload, dict) else None
            print(f"  {name}: ok={ok} ident={ident}{' error=' + str(err) if err else ''}")

    snapshot = row["outcome_snapshot_redacted"]
    if snapshot:
        print("\noutcome_snapshot:")
        print(json.dumps(json.loads(snapshot), indent=2, ensure_ascii=False)[:4000])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
