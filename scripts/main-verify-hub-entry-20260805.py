"""Main-only live verification of the hub-entry and robustness package.

Checks three things against the running host on 8787:
  1. an unauthenticated browser GET of a hub PAGE redirects to /login?next=...
  2. an unauthenticated GET of an /api/... route still returns JSON 401
  3. deleting the standing_network_preferences singleton no longer breaks the
     read path (the application service is expected to self-heal it)

The row is deleted deliberately as part of check 3 and is expected to be
recreated by the product itself; the script fails loudly if it is not.
"""

from __future__ import annotations

import argparse
import sqlite3
import sys

import requests
from hub_admin_password import require_hub_admin_password

BASE = "http://127.0.0.1:8787"
API = f"{BASE}/api/router-control/v1"
HUB_PAGE = "/settings/router-control/hub"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/router_control.sqlite3")
    args = parser.parse_args()
    password = require_hub_admin_password()
    failures: list[str] = []

    anon = requests.Session()
    anon.headers.update({"Origin": BASE})

    page = anon.get(f"{BASE}{HUB_PAGE}", allow_redirects=False, timeout=15)
    location = page.headers.get("Location", "")
    print(f"1. anon hub page  -> {page.status_code} Location={location!r}")
    if page.status_code not in (302, 303, 307) or "/login" not in location:
        failures.append("hub page did not redirect to /login")
    if "next=" not in location:
        failures.append("redirect carried no next= target")

    api = anon.get(f"{API}/status", allow_redirects=False, timeout=15)
    print(f"2. anon api       -> {api.status_code} ct={api.headers.get('Content-Type')}")
    if api.status_code != 401:
        failures.append(f"api status changed: expected 401, got {api.status_code}")
    else:
        body = api.json()
        code = body.get("error", {}).get("code")
        print(f"   api error code -> {code}")
        if code != "auth.required":
            failures.append(f"api error code changed: {code}")

    session = requests.Session()
    session.headers.update({"Origin": BASE})
    login = session.post(
        f"{BASE}/login",
        data={"password": password, "next": HUB_PAGE},
        allow_redirects=False,
        timeout=15,
    )
    dest = login.headers.get("Location", "")
    print(f"3. login          -> {login.status_code} Location={dest!r}")
    if login.status_code != 303:
        failures.append(f"login status: {login.status_code}")
    if dest != HUB_PAGE:
        failures.append(f"login did not return to requested page: {dest!r}")

    before = session.get(f"{API}/standing-network-preferences", timeout=30)
    print(f"4. prefs (before) -> {before.status_code}")
    if before.status_code != 200:
        failures.append(f"prefs broken before test: {before.status_code}")

    conn = sqlite3.connect(args.db)
    try:
        conn.execute("DELETE FROM standing_network_preferences")
        conn.commit()
        remaining = conn.execute(
            "SELECT COUNT(*) FROM standing_network_preferences"
        ).fetchone()[0]
        print(f"5. row deleted    -> rows={remaining}")
    finally:
        conn.close()

    healed = session.get(f"{API}/standing-network-preferences", timeout=30)
    print(f"6. prefs (after)  -> {healed.status_code}")
    if healed.status_code != 200:
        failures.append(f"self-heal failed: {healed.status_code} {healed.text[:200]}")
    else:
        payload = healed.json()
        print(f"   staff={payload.get('staff_ssid')!r} guest={payload.get('guest_default_ssid')!r}")
        if not payload.get("staff_ssid") or not payload.get("guest_default_ssid"):
            failures.append("self-healed row has empty SSIDs")

    conn = sqlite3.connect(args.db)
    try:
        rows = conn.execute("SELECT COUNT(*) FROM standing_network_preferences").fetchone()[0]
        print(f"7. row restored   -> rows={rows}")
        if rows != 1:
            failures.append(f"expected exactly 1 restored row, found {rows}")
    finally:
        conn.close()

    if failures:
        print("\nFAILURES:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("\nALL_CHECKS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
