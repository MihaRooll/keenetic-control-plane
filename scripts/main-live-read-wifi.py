"""Main-orchestrator live read of real Wi-Fi state, bypassing the broken UI restore.

Read-only. Calls POST /wifi/observed-state with an explicit connection tuple so
that the live device path can be judged independently of the connection-context
restore defects. No router_id is sent on purpose: with a router_id the server
resolves host/source from the store, which currently points at a junk draft
record with source_address NULL.

Requires fresh Gate A evidence and the wired lab path (source 192.168.2.10).

Usage:
  py -3.11 scripts/main-live-read-wifi.py <base_url> <hub_password> <credential_ref_id> [ap_id]
"""

from __future__ import annotations

import json
import sys

from playwright.sync_api import sync_playwright

API = "/api/router-control/v1/wifi/observed-state"


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2]
    credential_ref = sys.argv[3]
    ap_id = sys.argv[4] if len(sys.argv) > 4 else "WifiMaster0/AccessPoint3"

    body = {
        "host": "192.168.2.1",
        "username": "admin",
        "router_credential_ref_id": credential_ref,
        "ssh_host_key_sha256": "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY",
        "source_address": "192.168.2.10",
        "ap_ids": [ap_id],
    }

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(service_workers="block")
        page = context.new_page()
        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        print(f"=== POST /wifi/observed-state ap={ap_id} ===", flush=True)
        result = page.evaluate(
            """async ([url, payload]) => {
                const res = await fetch(url, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                let parsed = null;
                try {
                    parsed = await res.json();
                } catch (err) {
                    parsed = { parse_error: String(err) };
                }
                return { status: res.status, body: parsed };
            }""",
            [API, body],
        )
        print("status:", result.get("status"))
        print(json.dumps(result.get("body"), ensure_ascii=False, indent=2)[:6000])
        context.close()
        browser.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
