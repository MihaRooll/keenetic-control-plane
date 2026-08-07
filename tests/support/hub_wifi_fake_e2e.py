"""Drive fake-mode Wi-Fi API roundtrip over HTTP (no hub UI, no curl.exe).

Coverage: 8 access points (WifiMaster0/1 × AccessPoint3–6) × 3 WPA modes —
preview → apply → observed readback → teardown. Does not exercise staff/guest
hub screens or role-specific UI flows.
"""

from __future__ import annotations

import json
import sys
import time
import urllib.error
import urllib.request
import uuid
from typing import Any

TEST_PSK = "test-psk-not-real-8chars"
TEST_AP_IDS = (
    "WifiMaster0/AccessPoint3",
    "WifiMaster0/AccessPoint4",
    "WifiMaster0/AccessPoint5",
    "WifiMaster0/AccessPoint6",
    "WifiMaster1/AccessPoint3",
    "WifiMaster1/AccessPoint4",
    "WifiMaster1/AccessPoint5",
    "WifiMaster1/AccessPoint6",
)
WPA_MODES = ("WPA2", "WPA3", "WPA2_WPA3_MIXED")
ENROLL_ROUTER_ID = "router-lab-e2e"
ENROLL_IDEMPOTENCY_KEY = f"e2e-enroll-router-lab-{uuid.uuid4().hex[:12]}"
EXPECTED_READBACK_WPA = {
    "WPA2": "WPA2",
    "WPA3": "WPA3",
    "WPA2_WPA3_MIXED": "WPA2_WPA3_MIXED",
}


def _request(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    cookie: str | None = None,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    url = f"{base_url.rstrip('/')}{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8")
        payload = json.loads(raw) if raw else {}
        return exc.code, payload


def ensure_enrolled_router(base_url: str, hub_cookie: str) -> str:
    """Enroll fake router if missing; return router_id after worker persistence."""
    status, body = _request(
        base_url,
        "POST",
        "/api/router-control/v1/routers",
        {
            "display_name": "E2E Fake Router",
            "vendor": "Keenetic",
            "model": "Lab",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "e2e-mgmt-password-not-real",
        },
        cookie=hub_cookie,
        extra_headers={"Idempotency-Key": ENROLL_IDEMPOTENCY_KEY},
    )
    if status not in (200, 201, 202):
        raise RuntimeError(f"router enroll failed: {status} {body}")
    router_id = body.get("router_id")
    if not isinstance(router_id, str) or not router_id:
        raise RuntimeError(f"router enroll missing router_id: {body}")
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        get_status, _ = _request(
            base_url,
            "GET",
            f"/api/router-control/v1/routers/{router_id}",
            cookie=hub_cookie,
        )
        if get_status == 200:
            return router_id
        time.sleep(0.1)
    raise RuntimeError(f"router {router_id} not ready after enroll")


def run_roundtrip(base_url: str, hub_cookie: str) -> dict[str, Any]:
    """Register PSK, preview, apply, read back observed SSID; then teardown."""
    router_id = ensure_enrolled_router(base_url, hub_cookie)
    results: dict[str, Any] = {"router_id": router_id, "modes": {}, "secret_leaks": []}

    for ap_id in TEST_AP_IDS:
        for wpa_mode in WPA_MODES:
            label = f"{ap_id}|{wpa_mode}"
            ssid = f"E2E-{ap_id.split('/')[-1]}-{wpa_mode.replace('_', '')}"[:32]
            idem_key = f"e2e-{ap_id}-{wpa_mode}-psk"

            cred_status, cred_body = _request(
                base_url,
                "PUT",
                f"/api/router-control/v1/routers/{router_id}/credentials",
                {"kind": "WifiApPsk", "secret": TEST_PSK},
                cookie=hub_cookie,
                extra_headers={"Idempotency-Key": idem_key},
            )
            if cred_status not in (200, 201):
                raise RuntimeError(f"credentials PUT failed for {label}: {cred_status} {cred_body}")
            ref_id = cred_body.get("credential_ref_id")
            if not isinstance(ref_id, str) or not ref_id:
                raise RuntimeError(f"missing credential_ref_id for {label}")

            preview_body = {
                "ap_id": ap_id,
                "ssid": ssid,
                "enabled": True,
                "captive_portal": "Disabled",
                "guest_isolation": False,
                "wpa_mode": wpa_mode,
                "band": "BAND_2_4GHZ" if ap_id.startswith("WifiMaster0") else "BAND_5GHZ",
                "credential_ref_id": ref_id,
            }
            preview_status, preview_resp = _request(
                base_url,
                "POST",
                "/api/router-control/v1/wifi/preview",
                preview_body,
                cookie=hub_cookie,
            )
            if preview_status != 200:
                raise RuntimeError(f"preview failed for {label}: {preview_status} {preview_resp}")
            if preview_resp.get("verification_status") != "device_verified_wpa2":
                raise RuntimeError(
                    f"preview verification_status drift for {label}: "
                    f"{preview_resp.get('verification_status')}"
                )

            apply_body = {
                **preview_body,
                "confirm_live_apply": True,
                "compensate_on_failure": True,
                "idempotent": True,
            }
            apply_status, apply_resp = _request(
                base_url,
                "POST",
                "/api/router-control/v1/wifi/apply",
                apply_body,
                cookie=hub_cookie,
            )
            if apply_status != 200:
                raise RuntimeError(f"apply failed for {label}: {apply_status} {apply_resp}")
            if apply_resp.get("overall") not in {"applied", "verify_mismatch"}:
                raise RuntimeError(f"unexpected overall for {label}: {apply_resp.get('overall')}")

            obs_status, obs_resp = _request(
                base_url,
                "POST",
                "/api/router-control/v1/wifi/observed-state",
                {"ap_ids": [ap_id]},
                cookie=hub_cookie,
            )
            if obs_status != 200:
                raise RuntimeError(f"observed-state failed for {label}: {obs_status} {obs_resp}")
            rows = obs_resp.get("access_points") or []
            row = next((item for item in rows if item.get("ap_id") == ap_id), None)
            expected_wpa = EXPECTED_READBACK_WPA[wpa_mode]
            if not row or row.get("ssid") != ssid:
                raise RuntimeError(f"readback ssid mismatch for {label}: {row}")
            if row.get("wpa_mode") != expected_wpa:
                raise RuntimeError(
                    f"readback wpa_mode mismatch for {label}: "
                    f"expected {expected_wpa}, got {row.get('wpa_mode')}"
                )

            blob = json.dumps({"apply": apply_resp, "observed": obs_resp, "cred": cred_body})
            if TEST_PSK in blob:
                results["secret_leaks"].append(label)

            teardown_status, teardown_resp = _request(
                base_url,
                "POST",
                "/api/router-control/v1/wifi/teardown",
                {
                    "ap_id": ap_id,
                    "wpa_mode": wpa_mode,
                    "confirm_live_teardown": True,
                },
                cookie=hub_cookie,
            )
            if teardown_status != 200:
                raise RuntimeError(
                    f"teardown failed for {label}: {teardown_status} {teardown_resp}"
                )

            obs_after_status, obs_after = _request(
                base_url,
                "POST",
                "/api/router-control/v1/wifi/observed-state",
                {"ap_ids": [ap_id]},
                cookie=hub_cookie,
            )
            if obs_after_status != 200:
                raise RuntimeError(f"post-teardown observed failed for {label}")
            after_row = next(
                (
                    item
                    for item in (obs_after.get("access_points") or [])
                    if item.get("ap_id") == ap_id
                ),
                None,
            )
            disabled = after_row is not None and after_row.get("enabled_or_up") is False
            results["modes"][label] = {
                "ssid": ssid,
                "overall": apply_resp.get("overall"),
                "teardown_ok": teardown_resp.get("overall") == "applied",
                "disabled_after_teardown": disabled,
            }

    if results["secret_leaks"]:
        raise RuntimeError(f"PSK leaked in responses: {results['secret_leaks']}")
    return results


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: hub_wifi_fake_e2e.py <base_url> <hub_admin_cookie>", file=sys.stderr)
        return 2
    base_url, cookie = sys.argv[1], sys.argv[2]
    result = run_roundtrip(base_url, cookie)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
