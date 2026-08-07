"""Sealed typed RCI WireGuard operator CLI — validate by default, live with --execute."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"

_CLI_OPERATIONS = ("create-interface", "remove-interface", "set-asc")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Sealed typed RCI WireGuard create/remove/asc (validate default; live with --execute)."
        )
    )
    p.add_argument(
        "--operation",
        required=True,
        choices=_CLI_OPERATIONS,
        help="WireGuard operation: create-interface, remove-interface, or set-asc",
    )
    p.add_argument(
        "--wg-id",
        required=True,
        help="Allowlisted test interface id, e.g. Wireguard5",
    )
    p.add_argument(
        "--asc-args",
        default="",
        help="Space-separated asc integers (required for set-asc)",
    )
    p.add_argument("--host", default="", help="Router management host, e.g. 192.168.1.1")
    p.add_argument("--credential-ref", default="", help="DPAPI credential ref id")
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
    from router_control.adapters.netcraze.wireguard_rci import WireguardRciOperation

    mapping = {
        "create-interface": WireguardRciOperation.CREATE_INTERFACE,
        "remove-interface": WireguardRciOperation.REMOVE_INTERFACE,
        "set-asc": WireguardRciOperation.SET_ASC,
    }
    return mapping[cli_operation]


def _validate_inputs(args: argparse.Namespace) -> tuple[str, str | None, int | None]:
    from router_control.adapters.netcraze.allowlist import validate_asc_args, validate_wireguard_id

    try:
        wg_id = validate_wireguard_id(args.wg_id)
    except ValueError as exc:
        print(f"invalid wg id: {exc}", file=sys.stderr)
        return "", None, 1

    asc_args: str | None = None
    if args.operation == "set-asc":
        if not args.asc_args:
            print("invalid asc args: asc args is required for set-asc", file=sys.stderr)
            return "", None, 1
        try:
            asc_args = validate_asc_args(args.asc_args)
        except ValueError as exc:
            print(f"invalid asc args: {exc}", file=sys.stderr)
            return "", None, 1

    return wg_id, asc_args, None


def _validate_plan(args: argparse.Namespace) -> int:
    from router_control.adapters.netcraze.allowlist import (
        RCI_WRITE_PATH,
        body_sha256,
        is_write_allowlisted,
    )
    from router_control.adapters.netcraze.wireguard_rci import command_for, sealed_request_for

    wg_id, asc_args, error_code = _validate_inputs(args)
    if error_code is not None:
        return error_code

    operation = _resolve_operation(args.operation)
    request = sealed_request_for(operation, wg_id, asc_args=asc_args)
    body = request.body
    digest = body_sha256(body)
    allowlisted = is_write_allowlisted("POST", RCI_WRITE_PATH, body)
    cli = command_for(operation, wg_id, asc_args=asc_args)
    plan: dict[str, object] = {
        "mode": "validate",
        "operation": args.operation,
        "wg_id": wg_id,
        "cli": cli,
        "body_sha256": digest,
        "write_allowlisted": allowlisted,
        "bytes": len(body),
    }
    if args.operation == "set-asc":
        plan["asc_args"] = asc_args
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
    if missing:
        print(f"Missing required arguments for --execute: {', '.join(missing)}", file=sys.stderr)
        return 2

    from router_control.adapters.netcraze.allowlist import (
        RCI_WRITE_PATH,
        is_write_allowlisted,
    )
    from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
    from router_control.adapters.netcraze.wireguard_rci import (
        WireguardRciOperation,
        execute_wireguard_rci,
        sealed_request_for,
        wireguard_create_interface,
        wireguard_remove_interface,
        wireguard_set_asc,
    )
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    wg_id, asc_args, error_code = _validate_inputs(args)
    if error_code is not None:
        return error_code

    operation = _resolve_operation(args.operation)
    request = sealed_request_for(operation, wg_id, asc_args=asc_args)
    if not is_write_allowlisted("POST", RCI_WRITE_PATH, request.body):
        print("sealed body is not write-allowlisted", file=sys.stderr)
        return 3

    vault = WindowsDpapiVault(root=Path(args.secrets_root))
    password = vault.use(args.credential_ref)

    try:
        with open_pinned_rci_transport(
            host=args.host,
            username=args.username,
            password=password,
            host_key_sha256=args.ssh_host_key_sha256,
            source_address=args.source_address or None,
        ) as transport:
            if operation is WireguardRciOperation.CREATE_INTERFACE:
                result = wireguard_create_interface(transport, wg_id)
            elif operation is WireguardRciOperation.REMOVE_INTERFACE:
                result = wireguard_remove_interface(transport, wg_id)
            elif operation is WireguardRciOperation.SET_ASC:
                result = wireguard_set_asc(transport, wg_id, asc_args or "")
            else:
                result = execute_wireguard_rci(transport, operation, wg_id, asc_args=asc_args)
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(
            f"wireguard-rci-op failed: {exc.__class__.__name__}: {exc}",
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
