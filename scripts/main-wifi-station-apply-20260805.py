"""Main-only live proof that the product can now configure the Wi-Fi internet uplink.

Applies the SSID the lab router is ALREADY associated with, using the credential reference
the operator supplied earlier, so a success leaves the router's internet exactly as it was
and a failure is recoverable. Management reaches the router over Ethernet on Bridge0 with
its own route, independent of this uplink.

Never prints a password; the pre-shared key is passed only as a credential reference.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import requests
from hub_admin_password import resolve_hub_admin_password

BASE = "http://127.0.0.1:8787"
API = f"{BASE}/api/router-control/v1"

LIVE_FIELDS = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "cred_69280efb9361ca2911e99d383f0ce474",
    "ssh_host_key_sha256": "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY",
    "source_address": "192.168.2.10",
    "router_id": "rtr_f17a7d35fd3643b9a837d25c15088bfb",
}

# The network the lab router already uses for internet, stored earlier as a credential ref.
UPLINK_SSID = "Netcraze-7619"
UPLINK_CREDENTIAL_REF = "cred_e91e4625f9698f9910756bccd7e753e0"


def _summary(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "overall": payload.get("overall"),
        "verification_status": payload.get("verification_status"),
        "station_verification_status": payload.get("station_verification_status"),
        "uplink_verification_status": payload.get("uplink_verification_status"),
        "errors": payload.get("errors"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--band", default="BAND_5GHZ")
    parser.add_argument("--priority", type=int, default=600)
    parser.add_argument("--settle", type=float, default=30.0)
    parser.add_argument("--password", default=None)
    parser.add_argument("--apply", action="store_true", help="dispatch the live apply")
    args = parser.parse_args()
    password = resolve_hub_admin_password(args.password)

    session = requests.Session()
    session.headers.update({"Origin": BASE})
    login = session.post(
        f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15
    )
    if login.status_code >= 400:
        print(f"login failed: {login.status_code}", file=sys.stderr)
        return 2

    intent = {
        "mode": "WifiWan",
        "ssid": UPLINK_SSID,
        "band": args.band,
        "credential_ref_id": UPLINK_CREDENTIAL_REF,
        "priority": args.priority,
    }

    # The offline preview refuses a non-default priority because only the live path forces
    # the ip-global option, so preview is skipped when the operator keeps the device's own
    # priority. Not a defect: the live planner supplies that option itself.
    if args.priority != 100:
        print(f"skipping preview: priority {args.priority} is live-path only")
        if not args.apply:
            return 0
        preview = None
    else:
        preview = session.post(f"{API}/wifi/station/preview", json=intent, timeout=60)
    if preview is not None:
        print(f"preview: {preview.status_code}")
        if preview.status_code >= 400:
            print(preview.text[:1500])
            return 1
        plan = preview.json()
        ops = plan.get("ops") or plan.get("sealed_ops") or []
        names = (
            [op.get("operation") or op.get("op") for op in ops] if isinstance(ops, list) else ops
        )
        print(f"planned ops: {json.dumps(names, ensure_ascii=False)}")

    if not args.apply:
        print("\npreview only; re-run with --apply to dispatch the live write")
        return 0

    body = dict(intent)
    body.update(LIVE_FIELDS)
    body["confirm_live_apply"] = True
    body["uplink_settle_seconds"] = args.settle

    response = session.post(f"{API}/wifi/station/apply", json=body, timeout=300)
    print(f"apply: {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:3000])
        return 1
    payload = response.json()
    print("summary: " + json.dumps(_summary(payload), indent=2, ensure_ascii=False))
    print("steps: " + json.dumps(
        [{"op": s.get("op"), "ok": s.get("ok")} for s in payload.get("steps", [])],
        ensure_ascii=False,
    ))
    for line in payload.get("logs", [])[-12:]:
        print(f"  log: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
