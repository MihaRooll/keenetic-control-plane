"""Main-only live experiment (2026-08-05): does an explicit `ip global <priority>` on the
WireGuard interface take the default route away from the Wi-Fi station uplink?

The repository does not record NDMS priority-comparison semantics for two simultaneous
global interfaces (see docs/OPERATOR_VPN_CONNECTION_POLICY_DISCOVERY.md §5 open questions),
so this is a live determination, not a documented fact.

Observed baseline used to form the hypothesis: GigabitEthernet1 (wired ISP) priority 700
global true but link down; WifiMaster1/WifiStation0 priority 600 holds defaultgw; a
WireGuard interface brought up with `ip global auto` received priority 300 and did NOT win.
That ordering suggests a higher number means a stronger preference.

Safe on this bench: management reaches 192.168.2.1 over Bridge0 via a kernel route for
192.168.2.0/24, independent of the default route, and the host's own internet comes from a
different router over Wi-Fi. Losing the lab router's internet is acceptable and reversible.
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


def _signals(payload: dict[str, Any]) -> dict[str, Any]:
    observed = (payload.get("verification") or {}).get("observed") or {}
    return {
        "tunnel_verification_status": payload.get("tunnel_verification_status"),
        "link": observed.get("link"),
        "peer_rxbytes": observed.get("peer_rxbytes"),
        "peer_txbytes": observed.get("peer_txbytes"),
        "peer_last_handshake": observed.get("peer_last_handshake"),
        "address": observed.get("address"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile_id")
    parser.add_argument("wg_id")
    parser.add_argument(
        "--priority",
        type=int,
        required=True,
        help="explicit ip global priority (0..65535); station uplink currently holds 600",
    )
    parser.add_argument("--settle", type=float, default=25.0)
    parser.add_argument("--password", default=None)
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

    body = dict(LIVE_FIELDS)
    body.update(
        {
            "wg_id": args.wg_id,
            "logical_role": "primary",
            "confirm_live_apply": True,
            "handshake_settle_seconds": args.settle,
            "ip_global_priority": args.priority,
        }
    )
    response = session.post(
        f"{API}/vpn-profiles/{args.profile_id}/activate", json=body, timeout=300
    )
    print(f"activate (ip_global_priority={args.priority}): {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:3000])
        return 1
    payload = response.json()
    print(f"overall = {payload.get('overall')}")
    print("steps: " + json.dumps(
        [{"op": s.get("op"), "ok": s.get("ok")} for s in payload.get("steps", [])],
        ensure_ascii=False,
    ))
    print("signals: " + json.dumps(_signals(payload), indent=2, ensure_ascii=False))
    for line in payload.get("errors", []):
        print(f"  err: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
