"""Main-only: confirm the host serves the freshly edited hub assets.

When a browser keeps showing old wording it is usually the service-worker or
HTTP cache, not the server. This checks the server side directly so the two
causes can be told apart.
"""

from __future__ import annotations

import re
import sys

import requests
from hub_admin_password import resolve_hub_admin_password

BASE = "http://127.0.0.1:8787"
HUB = f"{BASE}/settings/router-control/hub"

MARKERS = {
    "features/vpn-model.js": (
        "идёт через этот туннель",
        "connected_routed",
        "connected_not_routed",
    ),
    "screens/overview.js": ("routed_through_tunnel",),
    "screens/vpn.js": ("routed_through_tunnel",),
}


def main() -> int:
    password = resolve_hub_admin_password(None)
    session = requests.Session()
    session.headers.update({"Origin": BASE})
    login = session.post(
        f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15
    )
    if login.status_code >= 400:
        print(f"login failed: {login.status_code}", file=sys.stderr)
        return 2

    sw = session.get(f"{HUB}/sw.js", timeout=15)
    match = re.search(r"CACHE_VERSION = '([^']+)'", sw.text)
    print(f"sw.js -> {sw.status_code}, served CACHE_VERSION = {match.group(1) if match else '?'}")

    failures = 0
    for path, markers in MARKERS.items():
        response = session.get(f"{HUB}/{path}", timeout=15)
        print(f"\n{path} -> {response.status_code}, {len(response.text)} bytes")
        for marker in markers:
            present = marker in response.text
            print(f"  {'OK  ' if present else 'MISS'} {marker!r}")
            if not present:
                failures += 1

    print("\nSERVER_SERVES_NEW_ASSETS" if failures == 0 else f"\nMISSING_MARKERS={failures}")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
