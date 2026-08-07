"""Main-orchestrator live check of the discovery verdict on screen (defect L-1).

Resets the current binding through the UI (the confirmation dialog warns that the
steps must be redone; the server-side stored access is not revoked), runs the
router search, and reads the identity verdict the operator actually sees for the
real router. Re-run scripts/main-live-ceremony-and-wifi.py afterwards to restore
the confirmed binding.

Usage:
  py -3.11 scripts/main-live-check-l1-ui.py <base_url> <hub_password>
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
OUT = Path("data/artifacts/main-live-l1-ui")
FORBIDDEN = ("Не совпадает с сохранённой записью", "Модель устройства не совпадает")


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

    problems: list[str] = []
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

        page.goto(hub + "#/connection", wait_until="load")
        page.wait_for_timeout(6000)

        switch = page.get_by_role("button", name="Сменить роутер")
        if switch.count():
            switch.first.click()
            page.wait_for_timeout(1500)
            page.screenshot(path=str(OUT / "switch-dialog.png"), full_page=True)
            confirm = page.get_by_role("button", name="Сменить роутер")
            print("switch buttons on screen:", confirm.count())
            confirm.last.click()
            page.wait_for_timeout(4000)
        else:
            print("no active binding to reset; already on the search step")

        find = page.get_by_role("button", name="Найти роутер")
        if not find.count():
            problems.append("«Найти роутер» not reachable after resetting the binding")
        else:
            find.first.click()
            page.wait_for_timeout(20000)

        text = page.inner_text("main")
        page.screenshot(path=str(OUT / "discovery.png"), full_page=True)
        print(text[:3000])
        (OUT / "discovery.txt").write_text(text, encoding="utf-8")

        for forbidden in FORBIDDEN:
            if forbidden in text:
                problems.append(f"L-1 OPEN: «{forbidden}» shown for the live router")
        if "Совпадение ещё не проверено" in text:
            print("\nverdict on screen: «Совпадение ещё не проверено» (honest, as required)")

        context.close()
        browser.close()

    for entry in dict.fromkeys(console):
        print("console:", entry)
        problems.append(f"console: {entry}")

    print("\n=== verdict ===")
    for problem in dict.fromkeys(problems):
        print("PROBLEM:", problem)
    if not problems:
        print("no problems detected")
    print("artifacts:", OUT)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
