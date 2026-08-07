"""Main-only: read the VPN catalog live status and show the routing evidence.

Confirms on the real device that `POST /vpn-profiles/catalog-status` now returns
`routed_through_tunnel` / `routing_probe_status` per profile, and cross-checks
the claim against `internet-status/observe`, which reports the interface that
currently owns the default route.
"""

from __future__ import annotations

import argparse
import json
import sys

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


def main() -> int:
    parser = argparse.ArgumentParser()
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

    observed = session.post(
        f"{API}/internet-status/observe", json=dict(LIVE_FIELDS), timeout=120
    )
    gateway = None
    if observed.status_code == 200:
        payload = observed.json()
        gateway = payload.get("gateway_interface")
        print(f"default-route interface (device): {gateway!r}")
    else:
        print(f"internet-status/observe -> {observed.status_code}", file=sys.stderr)

    status = session.post(f"{API}/vpn-profiles/catalog-status", json=dict(LIVE_FIELDS), timeout=180)
    print(f"catalog-status -> {status.status_code}")
    if status.status_code != 200:
        print(status.text[:600], file=sys.stderr)
        return 1

    body = status.json()
    items = body.get("items", body if isinstance(body, list) else [])
    if not items:
        print("no profiles returned")
        print(json.dumps(body, ensure_ascii=False, indent=1)[:600])
        return 1

    for item in items:
        name = item.get("display_name") or item.get("profile_id")
        wg = item.get("assigned_wg_id")
        print(f"\n{name}")
        print(f"  assigned_wg_id            = {wg!r}")
        print(f"  is_active                 = {item.get('is_active')!r}")
        print(f"  live_probed               = {item.get('live_probed')!r}")
        print(f"  live_tunnel_verification  = {item.get('live_tunnel_verification_status')!r}")
        print(f"  routed_through_tunnel     = {item.get('routed_through_tunnel')!r}")
        print(f"  routing_probe_status      = {item.get('routing_probe_status')!r}")
        if "routed_through_tunnel" not in item:
            print("  !! routing evidence field ABSENT from the response")
        elif wg and gateway is not None:
            expected = gateway == wg
            actual = item.get("routed_through_tunnel")
            verdict = "consistent" if bool(actual) == expected else "INCONSISTENT"
            print(f"  cross-check vs device gateway: {verdict}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
