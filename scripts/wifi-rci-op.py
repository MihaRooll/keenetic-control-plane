"""Sealed typed RCI Wi-Fi AP operator CLI — validate by default, live with --execute."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"

_CLI_OPERATIONS = (
    "set-ssid",
    "clear-ssid",
    "up",
    "down",
    "set-wpa-psk",
    "clear-wpa-psk",
    "encryption-enable",
    "encryption-disable",
    "encryption-wpa2",
    "encryption-wpa2-clear",
)
_OFFLINE_PSK_PLACEHOLDER = "Testpass123456"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Sealed typed RCI Wi-Fi AP up/down/ssid/WPA (validate default; live with --execute)."
        )
    )
    p.add_argument(
        "--operation",
        required=True,
        choices=_CLI_OPERATIONS,
        help=(
            "Wi-Fi AP operation: set-ssid, clear-ssid, up, down, set-wpa-psk, "
            "clear-wpa-psk, encryption-enable, encryption-disable, encryption-wpa2, "
            "encryption-wpa2-clear"
        ),
    )
    p.add_argument(
        "--ap-id",
        required=True,
        help="Allowlisted test AP id, e.g. WifiMaster0/AccessPoint3",
    )
    p.add_argument(
        "--ssid",
        default="",
        help="Bounded SSID (required for set-ssid)",
    )
    p.add_argument("--host", default="", help="Router management host, e.g. 192.168.1.1")
    p.add_argument("--credential-ref", default="", help="DPAPI credential ref id (router login)")
    p.add_argument(
        "--psk-credential-ref",
        default="",
        help="DPAPI credential ref id for WPA PSK (required for set-wpa-psk)",
    )
    p.add_argument("--username", default="", help="RCI auth username (not password)")
    p.add_argument("--ssh-host-key-sha256", default="", help="Pinned SSH host key SHA256")
    p.add_argument("--source-address", default="", help="Source IP bind, e.g. 192.168.1.144")
    p.add_argument("--secrets-root", default=str(DEFAULT_SECRETS_ROOT))
    p.add_argument(
        "--execute",
        action="store_true",
        help="Live dispatch via sealed typed op (requires win32 + pinned transport args)",
    )
    return p


def _resolve_operation(cli_operation: str):
    from router_control.adapters.netcraze.wifi_rci import WifiApRciOperation

    mapping = {
        "set-ssid": WifiApRciOperation.SET_SSID,
        "clear-ssid": WifiApRciOperation.CLEAR_SSID,
        "up": WifiApRciOperation.UP,
        "down": WifiApRciOperation.DOWN,
        "set-wpa-psk": WifiApRciOperation.SET_WPA_PSK,
        "clear-wpa-psk": WifiApRciOperation.CLEAR_WPA_PSK,
        "encryption-enable": WifiApRciOperation.ENCRYPTION_ENABLE,
        "encryption-disable": WifiApRciOperation.ENCRYPTION_DISABLE,
        "encryption-wpa2": WifiApRciOperation.ENCRYPTION_WPA2,
        "encryption-wpa2-clear": WifiApRciOperation.ENCRYPTION_WPA2_CLEAR,
    }
    return mapping[cli_operation]


def _validate_inputs(args: argparse.Namespace) -> tuple[str, str | None, int | None]:
    from router_control.adapters.netcraze.allowlist import validate_ssid, validate_wifi_ap_id

    try:
        ap_id = validate_wifi_ap_id(args.ap_id)
    except ValueError as exc:
        print(f"invalid ap id: {exc}", file=sys.stderr)
        return "", None, 1

    ssid: str | None = None
    if args.operation == "set-ssid":
        if not args.ssid:
            print("invalid ssid: ssid is required for set-ssid", file=sys.stderr)
            return "", None, 1
        try:
            ssid = validate_ssid(args.ssid)
        except ValueError as exc:
            print(f"invalid ssid: {exc}", file=sys.stderr)
            return "", None, 1

    if args.operation == "set-wpa-psk":
        if not args.psk_credential_ref.strip():
            print(
                "invalid psk credential ref: --psk-credential-ref is required for set-wpa-psk",
                file=sys.stderr,
            )
            return "", None, 1

    return ap_id, ssid, None


def _validate_plan(args: argparse.Namespace) -> int:
    from router_control.adapters.netcraze.allowlist import (
        RCI_WRITE_PATH,
        body_sha256,
        is_write_allowlisted,
    )
    from router_control.adapters.netcraze.wifi_rci import command_for, sealed_request_for

    ap_id, ssid, error_code = _validate_inputs(args)
    if error_code is not None:
        return error_code

    operation = _resolve_operation(args.operation)
    secret_bearing = args.operation == "set-wpa-psk"
    psk = _OFFLINE_PSK_PLACEHOLDER if secret_bearing else None
    request = sealed_request_for(operation, ap_id, ssid=ssid, psk=psk)
    body = request.body
    allowlisted = is_write_allowlisted("POST", RCI_WRITE_PATH, body)
    if secret_bearing:
        cli = f"interface {ap_id} authentication wpa-psk <redacted>"
    else:
        cli = command_for(operation, ap_id, ssid=ssid)
    plan: dict[str, object] = {
        "mode": "validate",
        "operation": args.operation,
        "ap_id": ap_id,
        "cli": cli,
        "write_allowlisted": allowlisted,
        "bytes": len(body),
    }
    if secret_bearing:
        plan["body_sha256"] = "omitted (secret-bearing)"
    else:
        plan["body_sha256"] = body_sha256(body)
    if args.operation == "set-ssid":
        plan["ssid"] = ssid
    print(json.dumps(plan, indent=2))
    return 0 if allowlisted else 3


def _execute_live(args: argparse.Namespace) -> int:
    if sys.platform != "win32":
        print("DPAPI credential resolution requires win32", file=sys.stderr)
        return 2

    missing = [
        name
        for name, value in (
            ("--host", args.host),
            ("--credential-ref", args.credential_ref),
            ("--username", args.username),
            ("--ssh-host-key-sha256", args.ssh_host_key_sha256),
        )
        if not value
    ]
    if args.operation == "set-wpa-psk" and not args.psk_credential_ref.strip():
        missing.append("--psk-credential-ref")
    if missing:
        print(f"Missing required arguments for --execute: {', '.join(missing)}", file=sys.stderr)
        return 2

    from router_control.adapters.netcraze.allowlist import (
        RCI_WRITE_PATH,
        is_write_allowlisted,
    )
    from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
    from router_control.adapters.netcraze.wifi_rci import (
        WifiApRciOperation,
        execute_wifi_ap_rci,
        sealed_request_for,
        wifi_ap_clear_ssid,
        wifi_ap_clear_wpa_psk,
        wifi_ap_down,
        wifi_ap_encryption_disable,
        wifi_ap_encryption_enable,
        wifi_ap_encryption_wpa2,
        wifi_ap_encryption_wpa2_clear,
        wifi_ap_set_ssid,
        wifi_ap_set_wpa_psk,
        wifi_ap_up,
    )
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    ap_id, ssid, error_code = _validate_inputs(args)
    if error_code is not None:
        return error_code

    operation = _resolve_operation(args.operation)
    psk: str | None = None
    vault = WindowsDpapiVault(root=Path(args.secrets_root))
    if operation is WifiApRciOperation.SET_WPA_PSK:
        psk = vault.use(args.psk_credential_ref)
    request = sealed_request_for(operation, ap_id, ssid=ssid, psk=psk)
    if not is_write_allowlisted("POST", RCI_WRITE_PATH, request.body):
        print("sealed body is not write-allowlisted", file=sys.stderr)
        return 3

    password = vault.use(args.credential_ref)

    try:
        with open_pinned_rci_transport(
            host=args.host,
            username=args.username,
            password=password,
            host_key_sha256=args.ssh_host_key_sha256,
            source_address=args.source_address or None,
        ) as transport:
            if operation is WifiApRciOperation.SET_SSID:
                result = wifi_ap_set_ssid(transport, ap_id, ssid or "")
            elif operation is WifiApRciOperation.CLEAR_SSID:
                result = wifi_ap_clear_ssid(transport, ap_id)
            elif operation is WifiApRciOperation.UP:
                result = wifi_ap_up(transport, ap_id)
            elif operation is WifiApRciOperation.DOWN:
                result = wifi_ap_down(transport, ap_id)
            elif operation is WifiApRciOperation.SET_WPA_PSK:
                result = wifi_ap_set_wpa_psk(transport, ap_id, psk or "")
            elif operation is WifiApRciOperation.CLEAR_WPA_PSK:
                result = wifi_ap_clear_wpa_psk(transport, ap_id)
            elif operation is WifiApRciOperation.ENCRYPTION_ENABLE:
                result = wifi_ap_encryption_enable(transport, ap_id)
            elif operation is WifiApRciOperation.ENCRYPTION_DISABLE:
                result = wifi_ap_encryption_disable(transport, ap_id)
            elif operation is WifiApRciOperation.ENCRYPTION_WPA2:
                result = wifi_ap_encryption_wpa2(transport, ap_id)
            elif operation is WifiApRciOperation.ENCRYPTION_WPA2_CLEAR:
                result = wifi_ap_encryption_wpa2_clear(transport, ap_id)
            else:
                result = execute_wifi_ap_rci(transport, operation, ap_id, ssid=ssid, psk=psk)
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(
            f"wifi-rci-op failed: {exc.__class__.__name__}: {exc}",
            file=sys.stderr,
        )
        return 4

    print(json.dumps(result.sanitized_dict(), indent=2))
    return 0


def main() -> int:
    args = _build_parser().parse_args()
    if args.execute:
        return _execute_live(args)
    return _validate_plan(args)


if __name__ == "__main__":
    raise SystemExit(main())
