"""Main-orchestrator diagnostic for the failing staff Wi-Fi apply (422 on /wifi/preview).

Captures the full request and response bodies of the failing call and the state
of the network toggle, so the defect can be handed over with evidence instead of
a guess. Applies nothing new beyond the single attempt the UI makes.

Usage:
  py -3.11 scripts/main-live-diagnose-apply.py <base_url> <hub_password>
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
API = "/api/router-control/v1/"
OUT = Path("data/artifacts/main-live-diagnose-apply")
AP = "WifiMaster0/AccessPoint3"
SSID = "RC-Lab-AP3-Test"


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
    psk = secrets.token_urlsafe(16)

    captured: list[str] = []

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()

        def on_response(response: object) -> None:
            try:
                status = response.status  # type: ignore[attr-defined]
                url = response.url  # type: ignore[attr-defined]
            except Exception:
                return
            if API not in url or status < 400:
                return
            request = response.request  # type: ignore[attr-defined]
            try:
                body = response.text()  # type: ignore[attr-defined]
            except Exception as err:
                body = f"<unreadable: {err}>"
            try:
                sent = request.post_data or ""
            except Exception:
                sent = ""
            # The PSK must never be written to an artifact or the console.
            sent = sent.replace(psk, "<redacted-psk>")
            captured.append(f"{status} {url}\nREQUEST: {sent}\nRESPONSE: {body}\n")

        page.on("response", on_response)

        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        page.goto(hub + "#/staff-wifi", wait_until="load")
        page.wait_for_timeout(4000)
        page.select_option("#hub-staff-wifi-ap-select", AP)
        page.wait_for_timeout(25000)

        box = page.locator("#hub-staff-wifi-network-toggle")
        print("toggle present:", box.count())
        if box.count():
            print("toggle checked before:", box.first.is_checked())
            print("toggle disabled:", box.first.is_disabled())
            label = page.locator("label:has(#hub-staff-wifi-network-toggle)")
            print("label count:", label.count())
            if label.count():
                label.first.click()
                page.wait_for_timeout(1500)
                print("toggle checked after label click:", box.first.is_checked())

        page.fill("#hub-staff-wifi-ssid", SSID)
        page.fill("#hub-staff-wifi-password", psk)
        page.wait_for_timeout(500)

        save = page.get_by_role("button", name="Сохранить изменения")
        print("save enabled:", save.first.is_enabled() if save.count() else None)
        if save.count() and save.first.is_enabled():
            save.first.click()
            page.wait_for_timeout(45000)

        details = page.get_by_text("Технические подробности")
        if details.count():
            details.first.click()
            page.wait_for_timeout(1000)
        page.screenshot(path=str(OUT / "apply-failure.png"), full_page=True)
        text = page.inner_text("main")
        (OUT / "screen.txt").write_text(text, encoding="utf-8")
        print("\n=== screen excerpt around the failure ===")
        marker = text.find("Проблема с роутером")
        print(text[max(0, marker - 400): marker + 1200] if marker >= 0 else text[:1200])

        context.close()
        browser.close()

    print("\n=== captured api failures ===")
    for entry in captured:
        print(entry)
    (OUT / "api-failures.txt").write_text("\n".join(captured), encoding="utf-8")
    print("artifacts:", OUT)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
