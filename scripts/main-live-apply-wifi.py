"""Main-orchestrator live acceptance of the Wi-Fi apply flow (staff or guest screen).

For each WPA mode: fills SSID and PSK, drives the network switch, confirms the
risk dialog, verifies the device readback in a fresh tab, and asks the device
directly for its SSID and WPA mode (screen text alone is weak proof because every
mode is also listed as an option). Finally tears the test network down.

Only AccessPoint3-6 are in scope. AccessPoint0/1 serve current clients and the
station uplink carries the router's internet — never touched here.

Lessons baked in: the confirmation dialog renders outside <main>, so text is read
from <body>; navigating to the same URL with a fragment does not reload the
document, so reload() is explicit; the dialog's primary button is named for the
action («Включить сеть» / «Выключить сеть» / «Сохранить изменения»).

The PSK is generated per run, never printed and never written to an artifact.
Take a startup-config backup before the first write of a session.

Usage:
  py -3.11 scripts/main-live-apply-wifi.py <base_url> <hub_password>
      [ssid] [modes] [staff|guest] [ap_id]
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

from playwright.sync_api import Page, sync_playwright

IPAD_LANDSCAPE = {"width": 1180, "height": 820}
API = "/api/router-control/v1/"
OUT = Path("data/artifacts/main-live-apply-wifi")
ALL_MODES = ("WPA2", "WPA3", "WPA2_WPA3_MIXED")
MODE_LABEL = {"WPA2": "WPA2", "WPA3": "WPA3", "WPA2_WPA3_MIXED": "WPA2 и WPA3"}
APPLIED_OK = "Сохранено и проверено"
CONFIRM_LABELS = ("Включить сеть", "Выключить сеть", "Сохранить изменения")


class Screen:
    def __init__(self, kind: str, ap_id: str) -> None:
        self.kind = kind
        self.ap = ap_id
        self.route = f"#/{kind}-wifi"

    def sel(self, part: str) -> str:
        return f"#hub-{self.kind}-wifi-{part}"


def section(title: str) -> None:
    print(f"\n=== {title} ===", flush=True)


class Recorder:
    def __init__(self, psk: str) -> None:
        self.psk = psk
        self.calls: list[str] = []
        self.failures: list[str] = []
        self.leaks: list[str] = []

    def attach(self, page: Page) -> None:
        page.on("request", self._on_request)
        page.on("response", self._on_response)
        page.on("pageerror", lambda exc: self.failures.append(f"pageerror: {exc}"))
        page.on(
            "console",
            lambda m: self.failures.append(f"console: {m.text}") if m.type == "error" else None,
        )

    def _on_request(self, request: object) -> None:
        url = getattr(request, "url", "")
        if API not in url:
            return
        method = getattr(request, "method", "?")
        path = url.split(API, 1)[1]
        self.calls.append(f"{method} {path}")
        try:
            body = request.post_data or ""  # type: ignore[attr-defined]
        except Exception:
            body = ""
        if self.psk and self.psk in body and "credentials" not in path:
            self.leaks.append(f"plaintext PSK sent to {method} {path}")

    def _on_response(self, response: object) -> None:
        url = getattr(response, "url", "")
        status = getattr(response, "status", 0)
        if API not in url or status < 400:
            return
        try:
            body = response.text()[:300]  # type: ignore[attr-defined]
        except Exception:
            body = "<unreadable>"
        self.failures.append(f"{status} {url.split(API, 1)[1]} -> {body}")

    def reset(self) -> None:
        self.calls = []


def open_ap(page: Page, hub: str, screen: Screen, settle_ms: int = 25000) -> str:
    page.goto(hub + screen.route, wait_until="load")
    page.reload(wait_until="load")
    page.wait_for_timeout(4000)
    select = page.locator(screen.sel("ap-select"))
    for _ in range(60):
        if select.count() and not select.first.is_disabled():
            break
        page.wait_for_timeout(1000)
    else:
        raise RuntimeError("access point selector stayed disabled for 60s after a reload")
    select.first.select_option(screen.ap)
    page.wait_for_timeout(settle_ms)
    return page.inner_text("body")


def confirm_risk_dialog(page: Page, *labels: str) -> str | None:
    for label in labels or CONFIRM_LABELS:
        buttons = page.get_by_role("button", name=label)
        if buttons.count():
            buttons.last.click()
            page.wait_for_timeout(2500)
            return label
    return None


def wait_for_settled(page: Page, screen: Screen, timeout_s: int = 180) -> str:
    select = page.locator(screen.sel("ap-select"))
    for _ in range(timeout_s):
        text = page.inner_text("body")
        if select.count() and not select.first.is_disabled():
            return text
        page.wait_for_timeout(1000)
    return page.inner_text("body")


def ask_device(page: Page, ap_id: str) -> dict[str, object]:
    result = page.evaluate(
        """async ([base, apId]) => {
            const ctx = await (await fetch(base + 'connection-context/restore-candidate',
                { credentials: 'same-origin' })).json();
            const res = await fetch(base + 'wifi/observed-state', {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    router_id: ctx.router_id,
                    router_credential_ref_id: ctx.credential_ref_id,
                    ap_ids: [apId],
                }),
            });
            return { status: res.status, body: await res.json().catch(() => null) };
        }""",
        [API, ap_id],
    )
    aps = ((result or {}).get("body") or {}).get("access_points") or []
    return aps[0] if aps else {}


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/")
    hub_password = sys.argv[2]
    ssid_base = sys.argv[3] if len(sys.argv) > 3 else "RC-Lab-AP3"
    modes = tuple(sys.argv[4].split(",")) if len(sys.argv) > 4 else ALL_MODES
    kind = sys.argv[5] if len(sys.argv) > 5 else "staff"
    ap_id = sys.argv[6] if len(sys.argv) > 6 else "WifiMaster0/AccessPoint3"
    screen = Screen(kind, ap_id)
    psk = secrets.token_urlsafe(16)
    OUT.mkdir(parents=True, exist_ok=True)
    hub = f"{base}/settings/router-control/hub/"

    problems: list[str] = []
    rec = Recorder(psk)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        context = browser.new_context(viewport=IPAD_LANDSCAPE, service_workers="block")
        page = context.new_page()
        rec.attach(page)

        page.goto(f"{base}/login", wait_until="load")
        page.fill("input[type=password]", hub_password)
        page.click("button[type=submit], input[type=submit]")
        page.wait_for_timeout(2000)

        for mode in modes:
            target = f"{ssid_base}-{mode.split('_')[-1]}"
            section(f"[{kind}] apply {mode} as «{target}» on {ap_id}")
            rec.reset()
            open_ap(page, hub, screen)
            page.fill(screen.sel("ssid"), target)
            page.fill(screen.sel("password"), psk)
            page.select_option(screen.sel("wpa"), mode)
            page.wait_for_timeout(500)

            box = page.locator(screen.sel("network-toggle"))
            button = page.get_by_role("button", name="Сохранить изменения")
            if box.count() and not box.first.is_checked():
                # Parameters reach the device through the «Сеть» switch; the UI
                # states outright that «Сохранить» alone leaves the network off.
                page.locator(f"label:has({screen.sel('network-toggle')})").first.click()
            elif button.count() and button.first.is_enabled():
                button.first.click()
            else:
                problems.append(f"{mode}: no way to submit (switch and save both unavailable)")
                continue
            page.wait_for_timeout(3000)
            page.screenshot(path=str(OUT / f"{kind}-{mode}-1-dialog.png"), full_page=True)
            confirmed = confirm_risk_dialog(page)
            print("confirmed via:", confirmed)
            if confirmed is None:
                problems.append(f"{mode}: risk dialog did not appear")
            applied = wait_for_settled(page, screen)
            page.screenshot(path=str(OUT / f"{kind}-{mode}-2-applied.png"), full_page=True)
            print("api calls:", rec.calls)
            cred = next((i for i, c in enumerate(rec.calls) if "credentials" in c), None)
            prev = next((i for i, c in enumerate(rec.calls) if c.endswith("wifi/preview")), None)
            if cred is None:
                problems.append(f"{mode}: no credential mint call")
            elif prev is not None and cred > prev:
                problems.append(f"{mode}: credential minted after preview")
            if APPLIED_OK in applied:
                print(f"verdict on screen: «{APPLIED_OK}»")
            else:
                problems.append(f"{mode}: no «{APPLIED_OK}» verdict on the applying tab")

            section(f"[{kind}] device readback {mode} in a fresh tab")
            fresh = context.new_page()
            rec.attach(fresh)
            readback = open_ap(fresh, hub, screen, settle_ms=30000)
            fresh.screenshot(path=str(OUT / f"{kind}-{mode}-3-readback.png"), full_page=True)
            if target in readback:
                print(f"readback shows «{target}»")
            else:
                problems.append(f"{mode}: readback does not report «{target}»")
            state = ask_device(fresh, ap_id)
            print("device says:", {k: state.get(k) for k in ("ssid", "enabled_or_up", "wpa_mode")})
            if state.get("ssid") != target:
                problems.append(f"{mode}: device reports ssid {state.get('ssid')!r}")
            if state.get("wpa_mode") != mode:
                problems.append(
                    f"{mode}: device reports wpa_mode {state.get('wpa_mode')!r} — silent downgrade"
                )
            fresh.close()

        section(f"[{kind}] teardown on {ap_id}")
        open_ap(page, hub, screen)
        box = page.locator(screen.sel("network-toggle"))
        label = page.locator(f"label:has({screen.sel('network-toggle')})")
        if label.count() and box.count() and box.first.is_checked():
            label.first.click()
            page.wait_for_timeout(2500)
            page.screenshot(path=str(OUT / f"{kind}-teardown-dialog.png"), full_page=True)
            confirm_risk_dialog(page, "Выключить сеть")
            wait_for_settled(page, screen)
            page.screenshot(path=str(OUT / f"{kind}-teardown-result.png"), full_page=True)
        final = ask_device(page, ap_id)
        summary = {k: final.get(k) for k in ("ssid", "enabled_or_up", "wpa_mode")}
        print("device after teardown:", summary)
        if final.get("enabled_or_up") is not False:
            problems.append("teardown: device still reports the network as up")

        context.close()
        browser.close()

    section("api failures")
    for entry in dict.fromkeys(rec.failures):
        print(entry)
    section("secret leaks")
    for entry in dict.fromkeys(rec.leaks):
        print(entry)
        problems.append(entry)

    section("verdict")
    for problem in dict.fromkeys(problems):
        print("PROBLEM:", problem)
    if not problems:
        print("no problems detected")
    print("artifacts:", OUT)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
