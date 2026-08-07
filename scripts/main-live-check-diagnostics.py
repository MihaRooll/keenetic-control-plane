"""Main-orchestrator live verification of the «Диагностика» screen.

Runs the readiness check against the real router and records what each row says,
so three things can be judged: whether the Wi-Fi rows read real access-point
state, whether the router verdict agrees with the «Обзор» banner, and whether a
host-side internet success wrongly colours the router-side internet row.

Usage:
  py -3.11 scripts/main-live-check-diagnostics.py <base_url> <hub_password>
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
OUT = Path("data/artifacts/main-live-diagnostics")
CHECK_LABELS = ("Проверить ещё раз", "Проверить систему", "Проверка...", "Проверить")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2]
    OUT.mkdir(parents=True, exist_ok=True)
    hub = f"{base}/settings/router-control/hub/"

    console: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()
        page.on(
            "console",
            lambda m: console.append(f"{m.type}: {m.text}") if m.type == "error" else None,
        )
        page.on("pageerror", lambda exc: console.append(f"pageerror: {exc}"))

        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        page.goto(hub + "#/diagnostics", wait_until="load")
        page.wait_for_timeout(5000)
        for label in CHECK_LABELS:
            button = page.get_by_role("button", name=label)
            if button.count() and button.first.is_enabled():
                button.first.click()
                print("clicked:", label)
                break
        else:
            print("no check button was clickable; the check may already be running")

        for step in range(18):
            page.wait_for_timeout(10000)
            text = page.inner_text("body")
            if "Проверка..." not in text and "Проверяем" not in text:
                print(f"check settled after ~{(step + 1) * 10}s")
                break
        text = page.inner_text("body")
        page.screenshot(path=str(OUT / "diagnostics.png"), full_page=True)
        (OUT / "diagnostics.txt").write_text(text, encoding="utf-8")
        print("\n=== diagnostics screen ===")
        print(text[:4000])

        page.goto(hub + "#/overview", wait_until="load")
        page.wait_for_timeout(20000)
        overview = page.inner_text("body")
        page.screenshot(path=str(OUT / "overview.png"), full_page=True)
        (OUT / "overview.txt").write_text(overview, encoding="utf-8")
        print("\n=== overview screen ===")
        print(overview[:1800])

        context.close()
        browser.close()

    print("\n=== console errors ===")
    for entry in dict.fromkeys(console):
        print(entry)
    print("artifacts:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
