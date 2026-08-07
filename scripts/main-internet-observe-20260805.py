"""Main-only: read the router's own internet status through the product route."""

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

    response = session.post(f"{API}/internet-status/observe", json=dict(LIVE_FIELDS), timeout=120)
    print(f"internet-status/observe: {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:2000])
        return 1
    print(json.dumps(response.json(), indent=2, ensure_ascii=False)[:3000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
