"""Main-orchestrator live click-through of LOCAL HUB against the real lab router.

Read-only by default: it logs in, opens the screens, runs the system check and
router discovery, and reads back what the UI actually renders while the host
runs with RC_ADAPTER_MODE=live. No write/apply/teardown action is triggered.

Scope warning: this is a smoke run, not an acceptance test. Exit 0 means the
screens rendered, the two known live defects (L-1, L-2) did not reproduce in
their exact wording, and no invented mockup value was displayed. It does NOT
prove that applying Wi-Fi settings or bringing up a VPN tunnel works — those
need a deliberate campaign on the device.

Usage:
  py -3.11 scripts/main-live-hub-campaign.py <base_url> <hub_password> [out_dir]
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
FORBIDDEN_MOCKUP_VALUES = (
    "8 устройств",
    "23 устройства",
    "142 Мбит",
    "Нидерланды",
    "sber-event.keenetic.pro",
)


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2]
    out_dir = Path(sys.argv[3] if len(sys.argv) > 3 else "data/artifacts/main-live-hub")
    out_dir.mkdir(parents=True, exist_ok=True)
    hub = f"{base}/settings/router-control/hub/"

    problems: list[str] = []
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()
        console: list[str] = []
        page.on(
            "console",
            lambda m: console.append(f"{m.type}: {m.text}") if m.type == "error" else None,
        )
        page.on("pageerror", lambda exc: console.append(f"pageerror: {exc}"))

        section("login")
        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)
        print("url after login:", page.url)

        section("overview (live adapter)")
        page.goto(hub + "#/overview", wait_until="load")
        page.wait_for_timeout(6000)
        overview_text = page.inner_text(".hub-overview")
        print(overview_text[:900])
        page.screenshot(path=str(out_dir / "live-overview.png"), full_page=True)

        section("system check button")
        check = page.get_by_role("button", name="Проверить систему")
        if check.count():
            check.first.click()
            page.wait_for_timeout(20000)
            print(page.inner_text(".hub-overview")[:700])
            page.screenshot(path=str(out_dir / "live-overview-after-check.png"), full_page=True)
        else:
            problems.append("overview: system check button not found")

        section("connection discovery")
        page.goto(hub + "#/connection", wait_until="load")
        page.wait_for_timeout(3000)
        find = page.get_by_role("button", name="Найти роутер")
        if find.count():
            find.first.click()
            page.wait_for_timeout(15000)
        body = page.inner_text("main")
        print(body[:900])
        page.screenshot(path=str(out_dir / "live-connection.png"), full_page=True)
        # Defect L-1: the real router is matched by the probe, so the screen must
        # not tell the operator it is a different device.
        if "Не совпадает с сохранённой записью" in body:
            problems.append(
                "L-1 OPEN: discovery still shows «Не совпадает с сохранённой записью» "
                "for the live router"
            )
        if "Модель устройства не совпадает" in body:
            problems.append("L-1 OPEN: discovery still reports a model mismatch")

        section("staff wifi observed state")
        page.goto(hub + "#/staff-wifi", wait_until="load")
        page.wait_for_timeout(2500)
        selects = page.locator("select")
        picked = False
        for index in range(selects.count()):
            option = selects.nth(index).locator('option[value="WifiMaster0/AccessPoint3"]')
            if option.count():
                selects.nth(index).select_option("WifiMaster0/AccessPoint3")
                picked = True
                break
        if not picked:
            problems.append("staff-wifi: access point selector not found")
        page.wait_for_timeout(20000)
        staff_text = page.inner_text("main")
        print(staff_text[:900])
        page.screenshot(path=str(out_dir / "live-staff-wifi.png"), full_page=True)
        # Defect L-2: the confirmed host key already lives on the server, so a
        # freshly loaded page must be able to read live state without redoing
        # the confirmation ceremony.
        if "Нужно активное подключение к роутеру" in staff_text:
            problems.append(
                "L-2 OPEN: staff-wifi cannot read live state on a fresh page load "
                "even though the pin is stored server-side"
            )
        if "Проблема с роутером" in staff_text:
            problems.append("L-2 OPEN: staff-wifi reports «Проблема с роутером» on live host")

        section("honesty scan")
        whole = staff_text
        for route in (
            "#/overview",
            "#/connection",
            "#/guest-wifi",
            "#/vpn",
            "#/domain",
            "#/entry-pages",
            "#/diagnostics",
        ):
            page.goto(hub + route, wait_until="load")
            page.wait_for_timeout(4000)
            whole += " " + page.inner_text("main")
        for forbidden in FORBIDDEN_MOCKUP_VALUES:
            if forbidden in whole:
                problems.append(f"invented mockup value rendered: {forbidden}")
        print("forbidden mockup values found:", [f for f in FORBIDDEN_MOCKUP_VALUES if f in whole])

        if console:
            problems.extend(f"console: {entry}" for entry in console)

        context.close()
        browser.close()

    section("verdict")
    if problems:
        for problem in problems:
            print("PROBLEM:", problem)
    else:
        print("no problems detected")
    print("artifacts:", out_dir)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
