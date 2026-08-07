"""Main-only live experiment (2026-08-05): does peer keepalive-interval make the
router actually emit WireGuard handshake packets (txbytes > 0)?

Background: every real operator .conf carries PersistentKeepalive, the domain
intent / planner / RCI builder / allowlist all support keepalive-interval, but the
vpn-profiles activate path never carries it (routes.py::_profile_metadata_from_parsed
and ::_wireguard_intent_from_profile_row omit peer_keepalive_interval). All live
activations so far therefore configured a peer with NO keepalive, and the device
reported peer_txbytes = 0 forever - it had no reason to send anything.

This script drives the raw /wireguard/apply endpoint (which DOES accept
peer_keepalive_interval) with the stored profile's own fields, changing exactly one
variable versus the last activation: keepalive.

Reads secrets only as credential_ref ids; never prints or stores secret material.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

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


def _profile_intent(profile_id: str) -> dict[str, Any]:
    conn = sqlite3.connect(str(DB))
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT profile_id, display_name, metadata_json FROM vpn_profile_artifacts WHERE profile_id=?",
        (profile_id,),
    ).fetchone()
    if row is None:
        raise SystemExit(f"profile not found: {profile_id}")
    metadata = json.loads(row["metadata_json"] or "{}")
    refs = conn.execute(
        "SELECT role, credential_ref_id FROM vpn_profile_secret_refs WHERE profile_id=?",
        (profile_id,),
    ).fetchall()
    private_ref = next((r["credential_ref_id"] for r in refs if r["role"] == "PrivateKey"), None)
    psk_ref = next((r["credential_ref_id"] for r in refs if r["role"] == "PresharedKey"), None)
    if not private_ref:
        raise SystemExit("profile has no PrivateKey credential ref")
    intent: dict[str, Any] = {
        "enabled": True,
        "private_key_credential_ref_id": private_ref,
        "peer_public_key": metadata.get("peer_public_key"),
        "peer_endpoint": metadata.get("peer_endpoint"),
        "peer_allow_ips": metadata.get("peer_allow_ips"),
        "peer_rci_shape": "nested_rci",
    }
    if psk_ref:
        intent["preshared_key_credential_ref_id"] = psk_ref
    if metadata.get("interface_address"):
        intent["interface_address"] = metadata["interface_address"]
    if isinstance(metadata.get("asc9_args"), list):
        intent["asc_args"] = metadata["asc9_args"]
    print(f"profile {profile_id} ({row['display_name']}) endpoint={intent['peer_endpoint']}")
    return intent


def _signals(payload: dict[str, Any]) -> dict[str, Any]:
    verification = payload.get("verification") or {}
    observed = verification.get("observed") or {}
    return {
        "tunnel_verification_status": payload.get("tunnel_verification_status"),
        "interface_verification_status": payload.get("interface_verification_status"),
        "interface_address_verification_status": payload.get("interface_address_verification_status"),
        "link": observed.get("link"),
        "peer_txbytes": observed.get("peer_txbytes"),
        "peer_rxbytes": observed.get("peer_rxbytes"),
        "peer_last_handshake": observed.get("peer_last_handshake"),
        "peer_online": observed.get("peer_online"),
        "peer_via": observed.get("peer_via"),
        "peer_remote_endpoint": observed.get("peer_remote_endpoint"),
        "address": observed.get("address"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile_id")
    parser.add_argument("--wg-id", default="Wireguard8")
    parser.add_argument("--keepalive", type=int, default=25)
    parser.add_argument("--no-keepalive", action="store_true", help="control run without keepalive")
    parser.add_argument(
        "--no-ip-global",
        dest="ip_global_auto",
        action="store_false",
        default=True,
        help="control run without ip global auto",
    )
    parser.add_argument("--settle", type=float, default=30.0)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()
    password = resolve_hub_admin_password(args.password)

    intent = _profile_intent(args.profile_id)
    intent["wg_id"] = args.wg_id
    intent["ip_global_auto"] = bool(args.ip_global_auto)
    if not args.no_keepalive:
        intent["peer_keepalive_interval"] = args.keepalive

    session = requests.Session()
    session.headers.update({"Origin": BASE})
    login = session.post(
        f"{BASE}/login", data={"password": password}, allow_redirects=False, timeout=15
    )
    if login.status_code >= 400:
        print(f"login failed: {login.status_code}", file=sys.stderr)
        return 2

    preview = session.post(f"{API}/wireguard/preview", json=intent, timeout=30)
    print(f"preview: {preview.status_code}")
    if preview.status_code >= 400:
        print(preview.text[:2000])
        return 1
    plan = preview.json()
    ops = plan.get("ops") or plan.get("sealed_ops") or []
    op_names = [op.get("operation") or op.get("op") for op in ops] if isinstance(ops, list) else ops
    print(f"planned ops: {json.dumps(op_names, ensure_ascii=False)}")

    apply_body = dict(intent)
    apply_body.update(LIVE_FIELDS)
    apply_body["confirm_live_apply"] = True
    apply_body["handshake_settle_seconds"] = args.settle

    response = session.post(f"{API}/wireguard/apply", json=apply_body, timeout=240)
    print(f"apply: {response.status_code}")
    if response.status_code >= 400:
        print(response.text[:3000])
        return 1
    payload = response.json()
    print(f"overall={payload.get('overall')}")
    print("steps: " + json.dumps(
        [{"op": s.get("op"), "ok": s.get("ok")} for s in payload.get("steps", [])],
        ensure_ascii=False,
    ))
    print("signals: " + json.dumps(_signals(payload), indent=2, ensure_ascii=False))
    for line in payload.get("logs", []):
        print(f"  log: {line}")
    for line in payload.get("errors", []):
        print(f"  err: {line}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
