"""Main-orchestrator personal browser verification for the LOCAL HUB screens.

Not part of the product test suite: this is the Main orchestrator's own
click-through harness, used because the IDE browser tool is unavailable.
Renders each screen at iPad-landscape size, reports console errors,
flags visibly stretched narrow elements, and saves screenshots.

Usage: py -3.11 scripts/main-verify-hub-screens.py [base_url] [out_dir]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}

SCREENS = (
    ("overview", "#/overview", None),
    ("connection", "#/connection", None),
    ("staff-wifi", "#/staff-wifi", "WifiMaster0/AccessPoint3"),
    ("guest-wifi", "#/guest-wifi", "WifiMaster0/AccessPoint3"),
    ("vpn", "#/vpn", None),
    ("domain", "#/domain", None),
    ("entry-pages", "#/entry-pages", None),
    ("diagnostics", "#/diagnostics", None),
)

STRETCH_PROBE = """
() => {
  const narrow = ['.hub-badge', '.hub-state-inline', '.hub-btn', '.hub-mode-chip'];
  const bad = [];
  for (const selector of narrow) {
    for (const el of document.querySelectorAll(selector)) {
      const box = el.getBoundingClientRect();
      if (box.width === 0) continue;
      const parent = el.parentElement;
      if (!parent) continue;
      const parentBox = parent.getBoundingClientRect();
      if (parentBox.width > 320 && box.width >= parentBox.width - 1) {
        bad.push({
          selector,
          width: Math.round(box.width),
          parentWidth: Math.round(parentBox.width),
          text: (el.textContent || '').trim().slice(0, 60),
        });
      }
    }
  }
  return bad;
}
"""


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    base = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8788"
    out_dir = Path(sys.argv[2] if len(sys.argv) > 2 else "data/artifacts/main-verify-screens")
    out_dir.mkdir(parents=True, exist_ok=True)
    hub = f"{base}/settings/router-control/hub/"

    failures = 0
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()
        console: list[str] = []
        page.on(
            "console",
            lambda msg: console.append(f"{msg.type}: {msg.text}") if msg.type == "error" else None,
        )
        page.on("pageerror", lambda exc: console.append(f"pageerror: {exc}"))

        # The live host requires an operator session; the fake host usually runs
        # with auth disabled, so the password is optional.
        hub_password = os.environ.get("RC_HUB_PASSWORD")
        if hub_password:
            page.goto(f"{base}/login", wait_until="load")
            page.fill("input[type=password]", hub_password)
            page.click("button[type=submit], input[type=submit]")
            page.wait_for_timeout(2000)

        for name, route, access_point in SCREENS:
            console.clear()
            page.goto(hub + route, wait_until="load")
            page.wait_for_timeout(1500)
            if access_point:
                selects = page.locator("select")
                for index in range(selects.count()):
                    options = selects.nth(index).locator(f'option[value="{access_point}"]')
                    if options.count():
                        selects.nth(index).select_option(access_point)
                        page.wait_for_timeout(1500)
                        break
            page.wait_for_timeout(500)
            stretched = page.evaluate(STRETCH_PROBE)
            heading = page.locator("h1").first
            title = heading.inner_text() if heading.count() else "<no h1>"
            interactive = page.locator(
                "button:not([disabled]), a[href], select, input"
            ).count()
            page.screenshot(path=str(out_dir / f"{name}.png"), full_page=True)

            status = "OK"
            if console or stretched:
                status = "PROBLEM"
                failures += 1
            print(f"[{status}] {name}: h1={title!r} interactive={interactive}")
            for entry in console:
                print(f"    console -> {entry}")
            for entry in stretched:
                print(f"    stretched -> {entry}")

        context.close()
        browser.close()

    print(f"\nscreenshots: {out_dir}")
    print("verdict:", "problems found" if failures else "all screens clean")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
