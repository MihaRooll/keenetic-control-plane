"""Main-orchestrator live acceptance: host-key ceremony on the enrolled record, then Wi-Fi read.

Runs the learn -> confirm ceremony through the LOCAL HUB UI against the real lab
router, stores the management username if the UI asks for it, and then reads the
observed Wi-Fi state of a test access point through the UI (not through the API).

Writes performed: the confirmed SSH host-key pin and the management username are
stored on the management server (not on the router). Nothing is written to the
router itself.

Usage:
  py -3.11 scripts/main-live-ceremony-and-wifi.py <base_url> <hub_password> [username]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
API = "/api/router-control/v1/"
OUT = Path("data/artifacts/main-live-ceremony")


def section(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


def api_get(page: Page, path: str) -> object:
    return page.evaluate(
        """async (url) => {
            const res = await fetch(url, { credentials: 'same-origin' });
            let parsed = null;
            try {
                parsed = await res.json();
            } catch (err) {
                parsed = { parse_error: String(err) };
            }
            return { status: res.status, body: parsed };
        }""",
        API + path,
    )


def click_if_present(page: Page, label: str, wait_ms: int) -> bool:
    button = page.get_by_role("button", name=label)
    if not button.count():
        print(f"button not present: {label}")
        return False
    target = button.first
    if not target.is_enabled():
        print(f"button disabled: {label}")
        return False
    target.click()
    page.wait_for_timeout(wait_ms)
    print(f"clicked: {label}")
    return True


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
    OUT.mkdir(parents=True, exist_ok=True)
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
        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        section("context before ceremony")
        print(json.dumps(api_get(page, "connection-context/restore-candidate"),
                         ensure_ascii=False, indent=2)[:1200])

        section("host key ceremony through the UI")
        page.goto(hub + "#/connection", wait_until="load")
        page.wait_for_timeout(6000)
        click_if_present(page, "Получить отпечаток", 25000)
        page.screenshot(path=str(OUT / "after-learn.png"), full_page=True)
        print(page.inner_text("main")[:1400])
        click_if_present(page, "Подтвердить отпечаток", 8000)
        page.screenshot(path=str(OUT / "after-confirm.png"), full_page=True)
        print(page.inner_text("main")[:1400])

        section("management username")
        field = page.locator("#hub-connection-management-username")
        if field.count():
            field.first.click()
            field.first.type(username, delay=60)
            if not click_if_present(page, "Сохранить имя пользователя", 8000):
                problems.append("username save button not clickable")
        else:
            print("recovery panel not shown; storing username through the documented endpoint")
            candidate = api_get(page, "connection-context/restore-candidate")
            router_id = None
            if isinstance(candidate, dict):
                body = candidate.get("body")
                if isinstance(body, dict):
                    router_id = body.get("router_id")
            if router_id:
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
                    [f"{API}routers/{router_id}/management-username", {"username": username}],
                )
                print(json.dumps(result, ensure_ascii=False)[:600])
            else:
                problems.append("no restore candidate to attach the username to")

        section("context after ceremony")
        after = api_get(page, "connection-context/restore-candidate")
        print(json.dumps(after, ensure_ascii=False, indent=2)[:1200])

        section("Wi-Fi read through the UI, fresh tab")
        fresh = context.new_page()
        watch(fresh)
        fresh.goto(hub + "#/staff-wifi", wait_until="load")
        fresh.wait_for_timeout(4000)
        selects = fresh.locator("select")
        picked = False
        for index in range(selects.count()):
            option = selects.nth(index).locator('option[value="WifiMaster0/AccessPoint3"]')
            if option.count():
                selects.nth(index).select_option("WifiMaster0/AccessPoint3")
                picked = True
                break
        if not picked:
            problems.append("staff-wifi: AccessPoint3 option not found")
        fresh.wait_for_timeout(30000)
        staff = fresh.inner_text("main")
        fresh.screenshot(path=str(OUT / "staff-wifi-live.png"), full_page=True)
        print(staff[:2000])
        for forbidden in ("Проблема с роутером", "Нужно активное подключение к роутеру"):
            if forbidden in staff:
                problems.append(f"staff-wifi still shows «{forbidden}» after the ceremony")

        context.close()
        browser.close()

    section("http errors")
    for entry in dict.fromkeys(http_errors):
        print(entry)
    section("console errors")
    for entry in dict.fromkeys(console):
        print(entry)
        problems.append(f"console: {entry}")

    section("verdict")
    for problem in dict.fromkeys(problems):
        print("PROBLEM:", problem)
    if not problems:
        print("no problems detected")
    print("artifacts:", OUT)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
