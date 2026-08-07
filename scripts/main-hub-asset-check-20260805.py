"""Main-only: verify the live host actually serves the updated LOCAL HUB assets.

Checks marker strings that must be present after the 2026-08-05 responsiveness work.
Does not touch the router; read-only HTTP against 127.0.0.1:8787.
"""

from __future__ import annotations

import argparse

import requests
from hub_admin_password import resolve_hub_admin_password

BASE = "http://127.0.0.1:8787"
HUB = "/settings/router-control/hub"

CHECKS: list[tuple[str, str, bool]] = [
    # (path, marker, must_be_present)
    (f"{HUB}/sw.js", "CACHE_VERSION = '30'", True),
    (f"{HUB}/features/overview-internet-simple.js", "export", True),
    (f"{HUB}/features/overview-simple-networks.js", "export", True),
    (f"{HUB}/features/domain-simple-publish.js", "mountDomainSimplePublishAffordance", True),
    (f"{HUB}/features/vpn-model.js", "createVpnProfileStatusTileGrid", True),
    (f"{HUB}/screens/overview.js", "domainWrap", True),
    (f"{HUB}/screens/staff-wifi.js", "mountLayoutOnce", True),
    (f"{HUB}/screens/entry-pages.js", "mountLayoutOnce", True),
    (f"{HUB}/screens/domain.js", "mountLayoutOnce", True),
    (f"{HUB}/features/diagnostics-model.js", "emitProgress", True),
    (f"{HUB}/sw.js", "core/form-submit-sync.js", True),
    (f"{HUB}/sw.js", "core/motion.js", True),
    (f"{HUB}/app.js", "HUB_SKIP_WAITING", True),
    (f"{HUB}/core/motion.js", "export", True),
    (f"{HUB}/core/api.js", "subscribeInFlight", True),
    (f"{HUB}/core/states.js", "createProgressPanel", True),
    (f"{HUB}/screens/vpn.js", "clearElement(contentWrap)", False),
    (f"{HUB}/features/vpn-model.js", "VPN_OBSERVE", True),
    (f"{HUB}/styles/base.css", "hub-screen-enter", True),
]


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
    print(f"login: {login.status_code}")

    failures = 0
    cache: dict[str, str] = {}
    for path, marker, must_be_present in CHECKS:
        if path not in cache:
            response = session.get(f"{BASE}{path}", timeout=20)
            if response.status_code != 200:
                print(f"FAIL {path} -> HTTP {response.status_code}")
                failures += 1
                cache[path] = ""
                continue
            cache[path] = response.text
        body = cache[path]
        if not body:
            continue
        present = marker in body
        ok = present is must_be_present
        state = "ok  " if ok else "FAIL"
        expectation = "present" if must_be_present else "absent"
        print(f"{state} {path}: {marker!r} expected {expectation}, got {'present' if present else 'absent'}")
        if not ok:
            failures += 1

    print(f"\nfailures: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
