"""Main-only: read the live VPN catalog status the tile grid consumes.

Verifies that the honest per-profile status surface behaves against the real router:
the active profile gets a live probe, inactive profiles are reported as unchecked.
Prints no secrets.
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

INTERESTING = (
    "profile_id",
    "display_name",
    "is_active",
    "assigned_wg_id",
    "live_probed",
    "live_tunnel_verification_status",
    "probe_error",
    "tunnel_verification_status",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--password", default=None)
    parser.add_argument("--raw", action="store_true")
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

    response = session.post(
        f"{API}/vpn-profiles/catalog-status", json=dict(LIVE_FIELDS), timeout=180
    )
    print(f"catalog-status: {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:2000])
        return 1
    payload = response.json()
    if args.raw:
        print(json.dumps(payload, indent=2, ensure_ascii=False)[:6000])
        return 0

    items = payload.get("items") or payload.get("profiles") or []
    if not isinstance(items, list):
        print(json.dumps(payload, indent=2, ensure_ascii=False)[:3000])
        return 0
    print(f"profiles: {len(items)}")
    for item in items:
        summary = {key: item.get(key) for key in INTERESTING if key in item}
        print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
