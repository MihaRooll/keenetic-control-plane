"""Main-only measurement: how long does the Wi-Fi station need, after `up`, to regain the
global flag and the default route?

The product's settle band is 20-30 seconds, documented from an earlier device observation.
After a full uplink apply the readback still reports `uplink_associated_no_global`, while a
later manual read shows `global: true`. This measures the real time so any change to the band
rests on device evidence rather than guesswork.

Read-only polling; performs no writes of its own.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE = REPO_ROOT / "scripts" / "main-wg-live-probe-20260805.py"
STATION = "WifiMaster1/WifiStation0"


def _read_state() -> dict[str, str]:
    result = subprocess.run(
        [
            sys.executable,
            str(PROBE),
            "--command",
            f"show interface {STATION}",
        ],
        capture_output=True,
        text=True,
        timeout=90,
    )
    state: dict[str, str] = {}
    for line in result.stdout.splitlines():
        for field in ("link", "global", "defaultgw", "address", "uptime"):
            # Exact top-level key only: the response also carries summary.layer.link,
            # which is a different thing and must not be mistaken for interface link state.
            marker = f'"[0].parse.{field}": '
            if marker in line:
                state[field] = line.split(marker, 1)[1].strip().rstrip(",")
    return state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--limit", type=float, default=120.0)
    args = parser.parse_args()

    started = time.monotonic()
    global_seen_at: float | None = None
    while True:
        elapsed = time.monotonic() - started
        if elapsed > args.limit:
            break
        state = _read_state()
        print(
            f"t+{elapsed:5.1f}s  link={state.get('link')} global={state.get('global')} "
            f"defaultgw={state.get('defaultgw')} uptime={state.get('uptime')}"
        )
        if state.get("global") == "true" and global_seen_at is None:
            global_seen_at = elapsed
            print(f"  -> global flag present at t+{elapsed:.1f}s")
            break
        time.sleep(args.interval)

    if global_seen_at is None:
        print(f"\nglobal flag NOT observed within {args.limit:.0f}s")
        return 1
    print(f"\nglobal flag observed {global_seen_at:.1f}s after polling started")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
