"""Main-orchestrator diagnostic: saving staff Wi-Fi with an empty password.

Expected behaviour is an immediate honest refusal. Observed on the live host is a
screen whose controls stay locked for more than 90 seconds, so this run records
the exact API sequence, the responses, and how long the controls stay disabled.

Usage:
  py -3.11 scripts/main-live-diagnose-no-password.py <base_url> <hub_password>
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
API = "/api/router-control/v1/"
OUT = Path("data/artifacts/main-live-no-password")
AP = "WifiMaster0/AccessPoint3"


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

    log: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()

        def on_request(request: object) -> None:
            url = getattr(request, "url", "")
            if API not in url:
                return
            method = getattr(request, "method", "?")
            try:
                body = request.post_data or ""  # type: ignore[attr-defined]
            except Exception:
                body = ""
            log.append(f"--> {method} {url.split(API, 1)[1]} {body[:300]}")

        def on_response(response: object) -> None:
            url = getattr(response, "url", "")
            if API not in url:
                return
            status = getattr(response, "status", 0)
            snippet = ""
            if status >= 400:
                try:
                    snippet = response.text()[:300]  # type: ignore[attr-defined]
                except Exception:
                    snippet = "<unreadable>"
            log.append(f"<-- {status} {url.split(API, 1)[1]} {snippet}")

        page.on("request", on_request)
        page.on("response", on_response)
        page.on("pageerror", lambda exc: log.append(f"pageerror: {exc}"))

        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        page.goto(hub + "#/staff-wifi", wait_until="load")
        page.wait_for_timeout(4000)
        select = page.locator("#hub-staff-wifi-ap-select")
        for _ in range(60):
            if select.count() and not select.first.is_disabled():
                break
            page.wait_for_timeout(1000)
        select.first.select_option(AP)
        page.wait_for_timeout(25000)

        page.fill("#hub-staff-wifi-ssid", "RC-Lab-AP3-NoPass")
        page.select_option("#hub-staff-wifi-wpa", "WPA2")
        page.wait_for_timeout(500)

        log.append("=== clicking save with an empty password field ===")
        save = page.get_by_role("button", name="Сохранить изменения")
        print("save enabled before click:", save.first.is_enabled())
        save.first.click()

        for step in range(12):
            page.wait_for_timeout(10000)
            disabled = select.first.is_disabled() if select.count() else None
            text = page.inner_text("main")
            marker = ""
            for needle in (
                "Действие не выполнено",
                "Проблема с роутером",
                "Подключение не готово",
                "Применяем",
                "Сохранено и проверено",
            ):
                if needle in text:
                    marker += f" [{needle}]"
            print(f"t+{(step + 1) * 10}s select_disabled={disabled}{marker}")
            if marker and disabled is False:
                break

        page.screenshot(path=str(OUT / "final.png"), full_page=True)
        text = page.inner_text("main")
        (OUT / "screen.txt").write_text(text, encoding="utf-8")
        idx = max(text.find("Действие не выполнено"), text.find("Проблема с роутером"))
        print("\n=== screen excerpt ===")
        print(text[max(0, idx - 200): idx + 900] if idx >= 0 else text[:1200])

        context.close()
        browser.close()

    print("\n=== api sequence ===")
    for entry in log:
        print(entry)
    (OUT / "api-sequence.txt").write_text("\n".join(log), encoding="utf-8")
    print("artifacts:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
