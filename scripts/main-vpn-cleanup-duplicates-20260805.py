"""Main-only: remove Main's own debugging VPN profiles through the product route.

Refuses to touch the active profile, and only removes profiles whose display name matches
exactly, so real operator profiles are never affected. Dry run by default.
"""

from __future__ import annotations

import argparse
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
    parser.add_argument("display_name", help="exact display name to remove")
    parser.add_argument("--apply", action="store_true")
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

    status = session.post(f"{API}/vpn-profiles/catalog-status", json=dict(LIVE_FIELDS), timeout=120)
    if status.status_code >= 400:
        print(f"catalog-status failed: {status.status_code}", file=sys.stderr)
        print(status.text[:1000])
        return 1
    items = status.json().get("items") or []

    targets = [
        item
        for item in items
        if item.get("display_name") == args.display_name and not item.get("is_active")
    ]
    active = [item for item in items if item.get("is_active")]
    print(f"catalog: {len(items)} profiles; active: {[i.get('profile_id') for i in active]}")
    print(f"matching and inactive: {len(targets)}")
    for item in targets:
        print(f"  would remove {item['profile_id']}")

    if not args.apply:
        print("\ndry run; re-run with --apply")
        return 0

    removed = 0
    for item in targets:
        profile_id = item["profile_id"]
        response = session.post(
            f"{API}/vpn-profiles/{profile_id}/remove",
            json={"confirm_catalog_remove": True},
            timeout=60,
        )
        print(f"remove {profile_id}: {response.status_code}")
        if response.status_code >= 400:
            print(f"    {response.text[:400]}")
            continue
        removed += 1
    print(f"\nremoved {removed} of {len(targets)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
