"""Main-orchestrator live acceptance run for defects L-1 and L-2.

Runs against a host started with RC_ADAPTER_MODE=live, i.e. against the real
lab router. Read-only: it reads discovery and observed Wi-Fi state through the
UI and stores the management username, but triggers no apply/teardown.

L-2 is checked in a way that is stricter than a page reload: after the one-time
username step the whole flow is repeated in a brand-new tab, so anything kept
only in tab memory is gone. If live capability survives that, it really does
come from the server.

Usage:
  py -3.11 scripts/main-verify-live-l1-l2.py <base_url> <hub_password> [username] [out_dir]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
API = "/api/router-control/v1/"
RESTORE_PENDING_TEXT = "Проверяем сохранённое подключение"
L1_FORBIDDEN = ("Не совпадает с сохранённой записью", "Модель устройства не совпадает")
L2_FORBIDDEN = ("Проблема с роутером", "Нужно активное подключение к роутеру")


def section(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def api_get(page: Page, path: str) -> Any:
    return page.evaluate(
        """async (url) => {
            const res = await fetch(url, { credentials: 'same-origin' });
            let body = null;
            try { body = await res.json(); } catch (err) { body = { parse_error: String(err) }; }
            return { status: res.status, body };
        }""",
        API + path,
    )


def settle_restore(page: Page, timeout_ms: int = 40000) -> str:
    """Wait until the server-side connection restore stops being pending."""
    deadline = timeout_ms
    text = ""
    while deadline > 0:
        text = page.inner_text("main")
        if RESTORE_PENDING_TEXT not in text:
            return text
        page.wait_for_timeout(1000)
        deadline -= 1000
    return text


def read_staff_wifi(page: Page, hub: str, problems: list[str], out: Path, tag: str) -> str:
    page.goto(hub + "#/staff-wifi", wait_until="load")
    settle_restore(page)
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
        problems.append(f"{tag}: access point selector WifiMaster0/AccessPoint3 not found")
    page.wait_for_timeout(25000)
    text = page.inner_text("main")
    page.screenshot(path=str(out / f"{tag}-staff-wifi.png"), full_page=True)
    print(text[:1600])
    for forbidden in L2_FORBIDDEN:
        if forbidden in text:
            problems.append(f"L-2 OPEN ({tag}): staff-wifi shows «{forbidden}»")
    return text


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    password = sys.argv[2]
    username = sys.argv[3] if len(sys.argv) > 3 else "admin"
    out = Path(sys.argv[4] if len(sys.argv) > 4 else "data/artifacts/main-live-l1-l2")
    out.mkdir(parents=True, exist_ok=True)
    hub = f"{base}/settings/router-control/hub/"

    problems: list[str] = []
    console: list[str] = []
    http_errors: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")

        def watch(page: Page) -> None:
            page.on(
                "console",
                lambda m: console.append(f"{m.type}: {m.text}") if m.type == "error" else None,
            )
            page.on("pageerror", lambda exc: console.append(f"pageerror: {exc}"))
            page.on(
                "response",
                lambda r: http_errors.append(f"{r.status} {r.url}")
                if r.status >= 400 and API in r.url
                else None,
            )

        page = context.new_page()
        watch(page)

        section("login")
        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)
        print("url after login:", page.url)

        section("server-side restore candidate (before any UI ceremony)")
        candidate = api_get(page, "connection-context/restore-candidate")
        print(json.dumps(candidate, ensure_ascii=False, indent=2)[:1500])
        router_id = None
        body = candidate.get("body") or {}
        if isinstance(body, dict):
            router_id = body.get("router_id")

        section("connection screen, first load")
        page.goto(hub + "#/connection", wait_until="load")
        text = settle_restore(page)
        page.screenshot(path=str(out / "first-connection.png"), full_page=True)
        print(text[:1600])
        if RESTORE_PENDING_TEXT in text:
            problems.append("restore never settled on the connection screen (stuck pending)")

        section("one-time management username step")
        field = page.locator("#hub-connection-management-username")
        if field.count():
            field.first.click()
            field.first.type(username, delay=60)
            save = page.get_by_role("button", name="Сохранить имя пользователя").first
            if save.is_enabled():
                save.click()
            else:
                problems.append(
                    "L-3 OPEN: «Сохранить имя пользователя» stays disabled after typing "
                    "(input does not re-render the button); submitted via Enter instead"
                )
                field.first.press("Enter")
            page.wait_for_timeout(8000)
            print(page.inner_text("main")[:900])
            page.screenshot(path=str(out / "after-username.png"), full_page=True)
        else:
            print("username panel not shown (username already stored server-side)")

        if router_id:
            section("connection context after username step")
            print(json.dumps(api_get(page, f"routers/{router_id}/connection-context"),
                             ensure_ascii=False, indent=2)[:1200])

        section("L-2 acceptance: brand-new tab, empty tab memory")
        fresh = context.new_page()
        watch(fresh)
        fresh.goto(hub + "#/overview", wait_until="load")
        settle_restore(fresh)
        fresh.wait_for_timeout(3000)
        fresh.screenshot(path=str(out / "fresh-overview.png"), full_page=True)
        read_staff_wifi(fresh, hub, problems, out, "fresh")

        section("L-1 acceptance: discovery in the fresh tab")
        fresh.goto(hub + "#/connection", wait_until="load")
        settle_restore(fresh)
        find = fresh.get_by_role("button", name="Найти роутер")
        if not find.count():
            switch = fresh.get_by_role("button", name="Сменить роутер")
            if switch.count():
                switch.first.click()
                fresh.wait_for_timeout(3000)
                find = fresh.get_by_role("button", name="Найти роутер")
        if find.count():
            find.first.click()
            fresh.wait_for_timeout(20000)
        else:
            problems.append("L-1: «Найти роутер» button not found")
        disco = fresh.inner_text("main")
        fresh.screenshot(path=str(out / "fresh-connection-discovery.png"), full_page=True)
        print(disco[:2500])
        for forbidden in L1_FORBIDDEN:
            if forbidden in disco:
                problems.append(f"L-1 OPEN: discovery shows «{forbidden}» for the live router")

        (out / "discovery-text.txt").write_text(disco, encoding="utf-8")

        context.close()
        browser.close()

    section("http errors on api calls")
    for entry in dict.fromkeys(http_errors):
        print(entry)
        if " 422 " in f" {entry} ":
            problems.append(f"L-2 OPEN: live call rejected with 422 -> {entry}")

    section("console errors")
    for entry in dict.fromkeys(console):
        print(entry)
        problems.append(f"console: {entry}")

    section("verdict")
    if problems:
        for problem in dict.fromkeys(problems):
            print("PROBLEM:", problem)
    else:
        print("no problems detected")
    print("artifacts:", out)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
