"""Subprocess HTTP driver for staff-wifi fake host apply→readback test.

Runs outside the pytest process so suite-wide stdlib ``http.client`` patches
(for example ``test_host_probes.py`` lines 273–903 patching
``router_control_host.host_probes.http.client.HTTPConnection``, which aliases
the stdlib module) cannot break real urllib traffic.
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
AP_ID = "WifiMaster0/AccessPoint4"
TARGET_SSID = "Staff-FakeHost-E2E"
HUB_COOKIE = "hub_admin=hub_admin"


def _wait_health(base_url: str, timeout_s: float = 25.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{base_url.rstrip('/')}/login", timeout=2) as resp:
                if resp.status == 200:
                    return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError(f"fake host not healthy at {base_url}")


def _request(
    base_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
    *,
    extra_headers: dict[str, str] | None = None,
) -> tuple[int, dict[str, Any]]:
    url = f"{base_url.rstrip('/')}{path}"
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Cookie": HUB_COOKIE,
    }
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


def _enroll_router(base_url: str) -> str:
    status, body = _request(
        base_url,
        "POST",
        "/api/router-control/v1/routers",
        {
            "display_name": "Staff Wi-Fi UI E2E",
            "vendor": "Keenetic",
            "model": "Lab",
            "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
            "management_password": "e2e-mgmt-password-not-real",
        },
        extra_headers={"Idempotency-Key": f"staff-wifi-ui-e2e-{uuid.uuid4().hex[:12]}"},
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
        )
        if get_status == 200:
            return router_id
        time.sleep(0.1)
    raise RuntimeError(f"router {router_id} not ready after enroll")


def run_readback_roundtrip(base_url: str) -> dict[str, Any]:
    _wait_health(base_url)
    router_id = _enroll_router(base_url)

    cred_status, cred_body = _request(
        base_url,
        "PUT",
        f"/api/router-control/v1/routers/{router_id}/credentials",
        {"kind": "WifiApPsk", "secret": TEST_PSK},
        extra_headers={"Idempotency-Key": f"staff-wifi-fake-api-{uuid.uuid4().hex[:12]}"},
    )
    if cred_status not in (200, 201):
        raise RuntimeError(f"credentials PUT failed: {cred_status} {cred_body}")
    ref_id = cred_body.get("credential_ref_id")
    if not isinstance(ref_id, str) or not ref_id:
        raise RuntimeError(f"missing credential_ref_id: {cred_body}")

    apply_body = {
        "ap_id": AP_ID,
        "ssid": TARGET_SSID,
        "enabled": True,
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "credential_ref_id": ref_id,
        "confirm_live_apply": True,
        "compensate_on_failure": True,
        "idempotent": True,
    }
    apply_status, apply_payload = _request(
        base_url,
        "POST",
        "/api/router-control/v1/wifi/apply",
        apply_body,
    )
    if apply_status != 200:
        raise RuntimeError(f"apply failed: {apply_status} {apply_payload}")

    obs_status, obs_payload = _request(
        base_url,
        "POST",
        "/api/router-control/v1/wifi/observed-state",
        {"ap_ids": [AP_ID]},
    )
    if obs_status != 200:
        raise RuntimeError(f"observed-state failed: {obs_status} {obs_payload}")

    row = next(
        (item for item in (obs_payload.get("access_points") or []) if item.get("ap_id") == AP_ID),
        None,
    )
    if row is None:
        raise RuntimeError(f"missing observed row for {AP_ID}: {obs_payload}")

    blob = json.dumps({"apply": apply_payload, "observed": obs_payload, "cred": cred_body})
    if TEST_PSK in blob:
        raise RuntimeError("PSK leaked in API responses")

    return {
        "router_id": router_id,
        "apply_overall": apply_payload.get("overall"),
        "on_air_verification_status": apply_payload.get("on_air_verification_status"),
        "observed_ssid": row.get("ssid"),
        "observed_wpa_mode": row.get("wpa_mode"),
        "observed_enabled_or_up": row.get("enabled_or_up"),
    }


def main() -> int:
    if len(sys.argv) != 2:
        print(
            "usage: staff_wifi_fake_host_readback_driver.py <base_url>",
            file=sys.stderr,
        )
        return 2
    try:
        result = run_readback_roundtrip(sys.argv[1])
    except Exception as exc:  # noqa: BLE001 — subprocess driver reports failure to pytest
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
