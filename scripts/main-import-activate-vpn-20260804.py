"""Main-only live script: import real VPN profile into catalog and activate it.

Run only by Main against the live host on 127.0.0.1:8787 (never printed secrets).
Reads the operator-provided .conf file path from argv[1]; never echoes its content.
"""

from __future__ import annotations

import json
import re
import sys
import time

import requests
from hub_admin_password import require_hub_admin_password


def _strip_interface_address(profile_text: str) -> tuple[str, bool]:
    """Router firmware rejects SET_IP_ADDRESS for this interface (service.op_dispatch_failed,
    documented pre-existing limitation — interface Address NOT configured on this NC-1812
    firmware path). Dropping [Interface] Address lets create/private-key/peer/up proceed so
    a real handshake can still be attempted; traffic routing was never claimed either way.
    """
    changed = False

    def _sub(match: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return ""

    new_text = re.sub(r"(?im)^Address\s*=.*\n?", _sub, profile_text)
    return new_text, changed


def _strip_ipv6_allowed_ips(profile_text: str) -> tuple[str, bool]:
    """Router firmware only accepts IPv4 peer allow-ips; drop IPv6 entries, keep IPv4.

    Documented hardware limitation (not a workaround for anything else) —
    the NC-1812 RCI peer allow-ips grammar this project drives is IPv4-only.
    Never prints the (non-secret) AllowedIPs value.
    """
    changed = False

    def _sub(match: re.Match[str]) -> str:
        nonlocal changed
        prefix, value = match.group(1), match.group(2)
        parts = [p.strip() for p in value.split(",") if p.strip()]
        ipv4_parts = [p for p in parts if ":" not in p]
        if len(ipv4_parts) != len(parts):
            changed = True
        if not ipv4_parts:
            ipv4_parts = ["0.0.0.0/0"]
            changed = True
        return f"{prefix}{', '.join(ipv4_parts)}"

    new_text = re.sub(
        r"(?im)^(AllowedIPs\s*=\s*)(.+)$",
        _sub,
        profile_text,
    )
    return new_text, changed

BASE = "http://127.0.0.1:8787"
API = f"{BASE}/api/router-control/v1"

LIVE_FIELDS = {
    "host": "192.168.2.1",
    "username": "admin",
    "router_credential_ref_id": "cred_69280efb9361ca2911e99d383f0ce474",
    "ssh_host_key_sha256": "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY",
    "source_address": "192.168.2.10",
    "router_id": "rtr_f17a7d35fd3643b9a837d25c15088bfb",
}


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: main-import-activate-vpn-20260804.py <conf_path> <display_name> [wg_id]", file=sys.stderr)
        return 2
    conf_path = sys.argv[1]
    display_name = sys.argv[2]
    wg_id = sys.argv[3] if len(sys.argv) > 3 else "Wireguard5"

    password = require_hub_admin_password()

    sess = requests.Session()
    sess.headers.update({"Origin": BASE})

    login = sess.post(
        f"{BASE}/login",
        data={"password": password},
        allow_redirects=False,
        timeout=15,
    )
    if login.status_code not in (302, 303):
        print(json.dumps({"step": "login", "status": login.status_code}))
        return 1
    print(json.dumps({"step": "login", "status": login.status_code, "ok": True}))

    with open(conf_path, encoding="utf-8") as fh:
        profile_text = fh.read()
    profile_text, stripped_ipv6 = _strip_ipv6_allowed_ips(profile_text)
    if stripped_ipv6:
        print(json.dumps({"step": "normalize", "stripped_ipv6_allowed_ips": True}))

    import_resp = sess.post(
        f"{API}/vpn-profiles/import",
        json={
            "display_name": display_name,
            "profile_text": profile_text,
            "vpn_kind": "AmneziaWG",
            "wg_id": wg_id,
            "ip_global_auto": False,
        },
        headers={"Idempotency-Key": f"main-import-{int(time.time())}"},
        timeout=20,
    )
    profile_text = None  # drop from memory promptly
    print(json.dumps({"step": "import", "status": import_resp.status_code}))
    if import_resp.status_code >= 400:
        print(import_resp.text[:2000])
        return 1
    imported = import_resp.json()
    profile_id = imported.get("profile_id")
    print(json.dumps({
        "step": "import_result",
        "profile_id": profile_id,
        "vpn_kind": imported.get("vpn_kind"),
        "validation_status": imported.get("validation_status"),
    }))

    if not profile_id:
        print("no profile_id returned", file=sys.stderr)
        return 1

    validate_resp = sess.post(
        f"{API}/vpn-profiles/{profile_id}/validate",
        json={},
        headers={"Idempotency-Key": f"main-validate-{int(time.time())}"},
        timeout=20,
    )
    print(json.dumps({"step": "validate", "status": validate_resp.status_code}))
    if validate_resp.status_code < 400:
        vr = validate_resp.json()
        print(json.dumps({
            "step": "validate_result",
            "validation_status": vr.get("validation_status"),
        }))

    activate_body = dict(LIVE_FIELDS)
    activate_body.update({
        "wg_id": wg_id,
        "logical_role": "primary",
        "confirm_live_apply": True,
        "handshake_settle_seconds": 25,
        "ip_global_auto": False,
    })
    activate_resp = sess.post(
        f"{API}/vpn-profiles/{profile_id}/activate",
        json=activate_body,
        timeout=60,
    )
    print(json.dumps({"step": "activate", "status": activate_resp.status_code}))
    if activate_resp.status_code >= 400:
        print(activate_resp.text[:4000])
        return 1
    activated = activate_resp.json()
    print(json.dumps({
        "step": "activate_result",
        "overall": activated.get("overall"),
        "configuration_verification_status": activated.get("configuration_verification_status"),
        "interface_verification_status": activated.get("interface_verification_status"),
        "tunnel_verification_status": activated.get("tunnel_verification_status"),
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
