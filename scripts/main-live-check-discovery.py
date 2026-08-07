"""Main-orchestrator live check of discovery candidate identity classification (defect L-1).

Read-only. Calls POST /lab/router-discovery through an authenticated browser
session (the login check requires same-origin headers, so a bare curl gets 401),
first the way the hub calls it (probe=false) and then with probe=true, and prints
the identity fields of every candidate so the classification can be judged on
real data instead of on fixtures.

probe=true performs a bounded read-only identity probe against the lab router and
requires fresh Gate A evidence.

Usage:
  py -3.11 scripts/main-live-check-discovery.py <base_url> <hub_password> [source_address]
"""

from __future__ import annotations

import json
import sys

from playwright.sync_api import sync_playwright

API = "/api/router-control/v1/lab/router-discovery"
FIELDS = (
    "host",
    "port",
    "source",
    "router_id",
    "identity_state",
    "reason_code",
    "lifecycle",
    "model",
    "probe_reachable",
    "probe_tuple_match",
)


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2]
    source = sys.argv[3] if len(sys.argv) > 3 else "192.168.2.10"

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(service_workers="block")
        page = context.new_page()
        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        for probe in (False, True):
            print(f"\n=== POST /lab/router-discovery probe={probe} ===", flush=True)
            result = page.evaluate(
                """async ([url, body]) => {
                    const res = await fetch(url, {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(body),
                    });
                    let parsed = null;
                    try {
                        parsed = await res.json();
                    } catch (err) {
                        parsed = { parse_error: String(err) };
                    }
                    return { status: res.status, body: parsed };
                }""",
                [
                    API,
                    {
                        "include_default_gateway": True,
                        "include_known_endpoints": True,
                        "preferred_source_address": source,
                        "probe": probe,
                    },
                ],
            )
            print("status:", result.get("status"))
            body = result.get("body") or {}
            candidates = body.get("candidates") if isinstance(body, dict) else None
            if not isinstance(candidates, list):
                print(json.dumps(body, ensure_ascii=False, indent=2)[:2000])
                continue
            print(f"candidates: {len(candidates)}")
            for candidate in candidates:
                if not isinstance(candidate, dict):
                    continue
                row = {key: candidate.get(key) for key in FIELDS if key in candidate}
                print(json.dumps(row, ensure_ascii=False))

        context.close()
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
