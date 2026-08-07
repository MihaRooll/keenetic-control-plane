"""Main-only: activate an already-imported VPN profile (diagnostic re-try)."""

from __future__ import annotations

import json
import sys

import requests
from hub_admin_password import require_hub_admin_password

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
    profile_id = sys.argv[1]
    wg_id = sys.argv[2] if len(sys.argv) > 2 else "Wireguard5"
    password = require_hub_admin_password()
    sess = requests.Session()
    sess.headers.update({"Origin": BASE})
    login = sess.post(f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15)
    print(json.dumps({"step": "login", "status": login.status_code}))

    body = dict(LIVE_FIELDS)
    body.update({
        "wg_id": wg_id,
        "logical_role": "primary",
        "confirm_live_apply": True,
        "handshake_settle_seconds": 25,
        "ip_global_auto": False,
    })
    resp = sess.post(f"{API}/vpn-profiles/{profile_id}/activate", json=body, timeout=60)
    print(json.dumps({"step": "activate", "status": resp.status_code}))
    print(resp.text[:6000])
    return 0 if resp.status_code < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
