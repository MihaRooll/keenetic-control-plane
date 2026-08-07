"""Main-only live E2E (2026-08-05): does the PROFILE path (the one the operator's UI
uses) now produce a real WireGuard handshake after the keepalive carry-through fix?

Imports a real operator .conf, asserts that peer_keepalive_interval survived into the
stored profile metadata, activates the profile on a lab WireGuard interface, and prints
the device signals. Never prints profile contents or secret material.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any
from uuid import uuid4

import requests
from hub_admin_password import resolve_hub_admin_password

REPO_ROOT = Path(__file__).resolve().parents[1]
DB = REPO_ROOT / "data" / "router_control.sqlite3"
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


def _signals(payload: dict[str, Any]) -> dict[str, Any]:
    observed = (payload.get("verification") or {}).get("observed") or {}
    return {
        "tunnel_verification_status": payload.get("tunnel_verification_status"),
        "interface_verification_status": payload.get("interface_verification_status"),
        "link": observed.get("link"),
        "peer_txbytes": observed.get("peer_txbytes"),
        "peer_rxbytes": observed.get("peer_rxbytes"),
        "peer_last_handshake": observed.get("peer_last_handshake"),
        "peer_online": observed.get("peer_online"),
        "address": observed.get("address"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("conf_name", help="file name inside the user's Downloads folder")
    parser.add_argument("--wg-id", default="Wireguard7")
    parser.add_argument("--display-name", default="Keepalive E2E 20260805")
    parser.add_argument("--settle", type=float, default=30.0)
    parser.add_argument("--ip-global-auto", action="store_true", default=False)
    parser.add_argument(
        "--tcp-mss-pmtu",
        action="store_true",
        default=False,
        help="request MSS clamping at import time; activate deliberately omits it so the "
        "stored-metadata path is what gets exercised",
    )
    parser.add_argument("--password", default=None)
    args = parser.parse_args()
    password = resolve_hub_admin_password(args.password)

    conf_path = Path.home() / "Downloads" / args.conf_name
    if not conf_path.is_file():
        print(f"conf not found: {conf_path}", file=sys.stderr)
        return 2
    # The file is imported verbatim: the importer accepts dual-stack AllowedIPs and reports
    # the IPv6 entry as unsupported instead of rejecting the whole profile.
    profile_text = conf_path.read_text(encoding="utf-8")

    declared_keepalive: int | None = None
    for line in profile_text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("persistentkeepalive"):
            _, _, value = stripped.partition("=")
            try:
                declared_keepalive = int(value.strip())
            except ValueError:
                declared_keepalive = None
    print(f"conf {conf_path.name}: declared PersistentKeepalive = {declared_keepalive}")

    session = requests.Session()
    session.headers.update({"Origin": BASE})
    login = session.post(
        f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15
    )
    if login.status_code >= 400:
        print(f"login failed: {login.status_code}", file=sys.stderr)
        return 2

    import_body = {
        "display_name": args.display_name,
        "profile_text": profile_text,
        "vpn_kind": "AmneziaWG",
        "wg_id": args.wg_id,
        "ip_global_auto": bool(args.ip_global_auto),
    }
    if args.tcp_mss_pmtu:
        import_body["tcp_mss_pmtu"] = True
    response = session.post(
        f"{API}/vpn-profiles/import",
        json=import_body,
        headers={"Idempotency-Key": f"main-e2e-{uuid4()}"},
        timeout=60,
    )
    print(f"import: {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:2000])
        return 1
    imported = response.json()
    profile_id = imported.get("profile_id") or imported.get("id")
    print(f"profile_id = {profile_id}")
    print(f"unsupported_fields = {imported.get('unsupported_fields')}")
    print(f"operator_notes = {imported.get('operator_notes')}")

    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT metadata_json FROM vpn_profile_artifacts WHERE profile_id=?", (profile_id,)
    ).fetchone()
    metadata = json.loads(row["metadata_json"] or "{}") if row else {}
    stored_keepalive = metadata.get("peer_keepalive_interval")
    print(f"stored metadata.peer_keepalive_interval = {stored_keepalive}")
    print(f"stored metadata.tcp_mss_pmtu = {metadata.get('tcp_mss_pmtu')}")
    if declared_keepalive is not None and stored_keepalive != declared_keepalive:
        print(
            "FAIL: keepalive did not survive import "
            f"(declared {declared_keepalive}, stored {stored_keepalive})",
            file=sys.stderr,
        )
        return 1
    print("OK: keepalive survived parse -> metadata")

    activate_body = dict(LIVE_FIELDS)
    activate_body.update(
        {
            "wg_id": args.wg_id,
            "logical_role": "primary",
            "confirm_live_apply": True,
            "handshake_settle_seconds": args.settle,
            "ip_global_auto": bool(args.ip_global_auto),
        }
    )
    response = session.post(
        f"{API}/vpn-profiles/{profile_id}/activate", json=activate_body, timeout=240
    )
    print(f"activate: {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:3000])
        return 1
    payload = response.json()
    print(f"overall = {payload.get('overall')}")
    print("steps: " + json.dumps(
        [{"op": s.get("op"), "ok": s.get("ok")} for s in payload.get("steps", [])],
        ensure_ascii=False,
    ))
    print("signals: " + json.dumps(_signals(payload), indent=2, ensure_ascii=False))
    for line in payload.get("errors", []):
        print(f"  err: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
