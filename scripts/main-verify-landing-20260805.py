"""Main-only live verification of the post-login landing decision.

Operator decision (2026-08-05): after login go straight to LOCAL HUB; keep the
legacy prototype wizard reachable, but only by link. This checks all five rules
that were handed to the implementing package.
"""

from __future__ import annotations

import sys

import requests
from hub_admin_password import require_hub_admin_password

BASE = "http://127.0.0.1:8787"
HUB = "/settings/router-control/hub"
LEGACY = "/settings/router-control"


def fresh() -> requests.Session:
    session = requests.Session()
    session.headers.update({"Origin": BASE})
    return session


def main() -> int:
    password = require_hub_admin_password()
    failures: list[str] = []

    plain = fresh()
    r1 = plain.post(f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15)
    dest1 = r1.headers.get("Location", "")
    print(f"1. login without next      -> {r1.status_code} {dest1!r}")
    if dest1 != HUB:
        failures.append(f"rule 1: plain login went to {dest1!r}, expected {HUB!r}")

    r2 = plain.get(f"{BASE}/", allow_redirects=False, timeout=15)
    dest2 = r2.headers.get("Location", "")
    print(f"2. GET / authenticated     -> {r2.status_code} {dest2!r}")
    if dest2 != HUB:
        failures.append(f"rule 3: root landing went to {dest2!r}, expected {HUB!r}")
    if dest1 != dest2:
        failures.append("rule 3: form login and root landing disagree")

    r3 = plain.get(f"{BASE}{LEGACY}", allow_redirects=False, timeout=15)
    print(f"3. legacy wizard by URL    -> {r3.status_code}")
    if r3.status_code != 200:
        failures.append(f"rule 2: legacy wizard not reachable ({r3.status_code})")

    explicit = fresh()
    r4 = explicit.post(
        f"{BASE}/login",
        data={"password": password, "next": LEGACY},
        allow_redirects=False,
        timeout=15,
    )
    dest4 = r4.headers.get("Location", "")
    print(f"4. explicit next=legacy    -> {r4.status_code} {dest4!r}")
    if dest4 != LEGACY:
        failures.append(f"rule 4: explicit next ignored, got {dest4!r}")

    hostile = fresh()
    r5 = hostile.post(
        f"{BASE}/login",
        data={"password": password, "next": "https://example.com/evil"},
        allow_redirects=False,
        timeout=15,
    )
    dest5 = r5.headers.get("Location", "")
    print(f"5. hostile next rejected   -> {r5.status_code} {dest5!r}")
    if dest5.startswith("http") or "example.com" in dest5:
        failures.append(f"rule 5: open redirect! landed on {dest5!r}")
    if dest5 != HUB:
        failures.append(f"rule 5: hostile next should fall back to {HUB!r}, got {dest5!r}")

    anon = fresh()
    r6 = anon.get(f"{BASE}/", allow_redirects=False, timeout=15)
    print(f"6. GET / anonymous         -> {r6.status_code} {r6.headers.get('Location')!r}")
    if "/login" not in r6.headers.get("Location", ""):
        failures.append("anonymous root should go to /login")

    if failures:
        print("\nFAILURES:")
        for item in failures:
            print(f"  - {item}")
        return 1
    print("\nALL_LANDING_CHECKS_PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
