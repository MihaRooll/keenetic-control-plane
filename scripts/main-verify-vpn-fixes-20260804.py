"""Main-only live verification of the delegated VPN fixes (watchdog status,
catalog badges, idempotency race fix) against the real host on 127.0.0.1:8787."""

from __future__ import annotations

import json
import time

import requests
from hub_admin_password import require_hub_admin_password

BASE = "http://127.0.0.1:8787"
API = f"{BASE}/api/router-control/v1"


def main() -> int:
    password = require_hub_admin_password()
    sess = requests.Session()
    sess.headers.update({"Origin": BASE})
    login = sess.post(f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15)
    print(json.dumps({"step": "login", "status": login.status_code}))

    profiles = sess.get(f"{API}/vpn-profiles", timeout=15)
    print(json.dumps({"step": "list_profiles", "status": profiles.status_code}))
    if profiles.status_code < 400:
        payload = profiles.json()
        items = payload.get("items", [])
        for item in items:
            print(json.dumps({
                "profile_id": item.get("profile_id"),
                "display_name": item.get("display_name"),
                "keys_present": sorted(item.keys()),
            }))
        if "watchdog" in payload or "vpn_watchdog" in payload:
            print(json.dumps({"top_level_watchdog_field": True, "keys": sorted(payload.keys())}))
        else:
            print(json.dumps({"top_level_keys": sorted(payload.keys())}))

    for candidate in (
        "vpn-watchdog/status",
        "vpn-profiles/watchdog/status",
        "vpn/watchdog/status",
    ):
        resp = sess.get(f"{API}/{candidate}", timeout=10)
        print(json.dumps({"step": "watchdog_status_probe", "path": candidate, "status": resp.status_code}))
        if resp.status_code < 400:
            print(resp.text[:2000])

    key = f"main-verify-idem-{int(time.time())}"
    profile_text_path = "C:\\Users\\katko\\Downloads\\rockblack-awg2-fi-keenetic50-compat.conf"
    with open(profile_text_path, encoding="utf-8") as fh:
        profile_text = fh.read()
    import re
    profile_text = re.sub(
        r"(?im)^(AllowedIPs\s*=\s*)(.+)$",
        lambda m: m.group(1) + ", ".join(p.strip() for p in m.group(2).split(",") if ":" not in p),
        profile_text,
    )

    body = {
        "display_name": "Idempotency retry test",
        "profile_text": profile_text,
        "vpn_kind": "AmneziaWG",
        "wg_id": "Wireguard6",
        "ip_global_auto": False,
    }
    profile_text = None

    first = sess.post(f"{API}/vpn-profiles/import", json=body, headers={"Idempotency-Key": key}, timeout=20)
    print(json.dumps({"step": "import_first", "status": first.status_code}))
    time.sleep(3)  # give any background worker a chance to race
    second = sess.post(f"{API}/vpn-profiles/import", json=body, headers={"Idempotency-Key": key}, timeout=20)
    print(json.dumps({"step": "import_replay_same_key", "status": second.status_code}))
    if second.status_code >= 400:
        print(second.text[:2000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
