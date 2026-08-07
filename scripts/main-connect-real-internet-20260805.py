"""Main-only live script: store the operator's real Wi-Fi PSK as a credential_ref
(never raw in docs) and connect the router (WifiWan station) to it for real
internet, then honestly parse the verdict. Never prints the secret."""

from __future__ import annotations

import json
import sys

import requests
from hub_admin_password import require_hub_admin_password

BASE = "http://127.0.0.1:8787"
API = f"{BASE}/api/router-control/v1"
ROUTER_ID = "rtr_f17a7d35fd3643b9a837d25c15088bfb"

LIVE_FIELDS = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "cred_69280efb9361ca2911e99d383f0ce474",
    "ssh_host_key_sha256": "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY",
    "source_address": "192.168.2.10",
    "router_id": ROUTER_ID,
}


def main() -> int:
    ssid = sys.argv[1]
    band = sys.argv[2]  # BAND_2_4GHZ or BAND_5GHZ
    secret = sys.argv[3]
    password = require_hub_admin_password()

    sess = requests.Session()
    sess.headers.update({"Origin": BASE})
    login = sess.post(f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15)
    print(json.dumps({"step": "login", "status": login.status_code}))

    cred_resp = sess.put(
        f"{API}/routers/{ROUTER_ID}/credentials",
        json={"kind": "WifiApPsk", "secret": secret},
        headers={"Idempotency-Key": "main-uplink-psk-20260805"},
        timeout=15,
    )
    secret = None
    print(json.dumps({"step": "store_credential", "status": cred_resp.status_code}))
    if cred_resp.status_code >= 400:
        print(cred_resp.text[:1000])
        return 1
    credential_ref_id = cred_resp.json().get("credential_ref_id")
    print(json.dumps({"step": "credential_ref", "credential_ref_id": credential_ref_id}))

    preview_body = {
        "mode": "WifiWan",
        "ssid": ssid.strip(),
        "band": band,
        "credential_ref_id": credential_ref_id,
        "priority": 100,
        "auth_mode": "wpa2_psk",
    }
    preview = sess.post(f"{API}/wifi/station/preview", preview_body, timeout=20) if False else sess.post(
        f"{API}/wifi/station/preview", json=preview_body, timeout=20
    )
    print(json.dumps({"step": "preview", "status": preview.status_code}))
    if preview.status_code >= 400:
        print(preview.text[:2000])
        return 1

    apply_body = dict(preview_body)
    apply_body.update({
        "confirm_live_apply": True,
        "compensate_on_failure": True,
        "idempotent": True,
        "uplink_settle_seconds": 25,
    })
    apply_body.update(LIVE_FIELDS)
    apply_resp = sess.post(f"{API}/wifi/station/apply", json=apply_body, timeout=60)
    print(json.dumps({"step": "apply", "status": apply_resp.status_code}))
    print(apply_resp.text[:6000])
    return 0 if apply_resp.status_code < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())
