"""Main-orchestrator peek at the staff Wi-Fi screen state and the device state.

Read-only. Dumps what the screen renders, whether its controls are locked, any
failing API call, and the observed state of the access point as reported by the
device through the store-backed pin.

Usage:
  py -3.11 scripts/main-live-peek-staff-wifi.py <base_url> <hub_password> [ap_id]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
API = "/api/router-control/v1/"
OUT = Path("data/artifacts/main-live-peek")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2]
    ap_id = sys.argv[3] if len(sys.argv) > 3 else "WifiMaster0/AccessPoint3"
    OUT.mkdir(parents=True, exist_ok=True)
    hub = f"{base}/settings/router-control/hub/"

    failures: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()

        def on_response(response: object) -> None:
            url = getattr(response, "url", "")
            status = getattr(response, "status", 0)
            if API not in url or status < 400:
                return
            try:
                body = response.text()  # type: ignore[attr-defined]
            except Exception as err:
                body = f"<unreadable: {err}>"
            failures.append(f"{status} {url.split(API, 1)[1]} -> {body[:500]}")

        page.on("response", on_response)
        page.on("pageerror", lambda exc: failures.append(f"pageerror: {exc}"))

        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        print("=== restore candidate ===")
        ctx = page.evaluate(
            """async (url) => {
                const res = await fetch(url, { credentials: 'same-origin' });
                return { status: res.status, body: await res.json().catch(() => null) };
            }""",
            API + "connection-context/restore-candidate",
        )
        print(json.dumps(ctx, ensure_ascii=False, indent=2)[:900])
        router_id = None
        body = (ctx or {}).get("body") or {}
        if isinstance(body, dict):
            router_id = body.get("router_id")

        print("\n=== device observed state (store-backed pin) ===")
        observed = page.evaluate(
            """async ([url, payload]) => {
                const res = await fetch(url, {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                return { status: res.status, body: await res.json().catch(() => null) };
            }""",
            [
                API + "wifi/observed-state",
                {
                    "router_id": router_id,
                    "router_credential_ref_id": body.get("credential_ref_id"),
                    "ap_ids": [ap_id],
                },
            ],
        )
        print(json.dumps(observed, ensure_ascii=False, indent=2)[:1500])

        print("\n=== staff wifi screen ===")
        page.goto(hub + "#/staff-wifi", wait_until="load")
        page.wait_for_timeout(30000)
        select = page.locator("#hub-staff-wifi-ap-select")
        print("ap select present:", select.count())
        if select.count():
            print("ap select disabled:", select.first.is_disabled())
            print("ap select value:", select.first.input_value())
        save = page.get_by_role("button", name="Сохранить изменения")
        save_enabled = save.first.is_enabled() if save.count() else None
        print("save present:", save.count(), "enabled:", save_enabled)
        text = page.inner_text("main")
        (OUT / "screen.txt").write_text(text, encoding="utf-8")
        page.screenshot(path=str(OUT / "screen.png"), full_page=True)
        print(text[:2500])

        context.close()
        browser.close()

    print("\n=== api failures ===")
    for entry in dict.fromkeys(failures):
        print(entry)
    print("artifacts:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
