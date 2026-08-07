"""Sealed typed RCI interface up/down operator CLI — validate by default, live with --execute."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Sealed typed RCI interface up/down (validate default; live with --execute)."
    )
    p.add_argument(
        "--operation",
        required=True,
        choices=("up", "down"),
        help="Interface operation: up or down",
    )
    p.add_argument(
        "--interface-id",
        required=True,
        help="Bounded interface id, e.g. GigabitEthernet1",
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


def _validate_plan(args: argparse.Namespace) -> int:
    from router_control.adapters.netcraze.allowlist import (
        RCI_WRITE_PATH,
        body_sha256,
        is_write_allowlisted,
        validate_interface_id,
    )
    from router_control.adapters.netcraze.interface_rci import (
        InterfaceRciOperation,
        command_for,
        sealed_request_for,
    )

    try:
        interface_id = validate_interface_id(args.interface_id)
    except ValueError as exc:
        print(f"invalid interface id: {exc}", file=sys.stderr)
        return 1

    operation = (
        InterfaceRciOperation.UP if args.operation == "up" else InterfaceRciOperation.DOWN
    )
    request = sealed_request_for(operation, interface_id)
    body = request.body
    digest = body_sha256(body)
    allowlisted = is_write_allowlisted("POST", RCI_WRITE_PATH, body)
    cli = command_for(operation, interface_id)
    plan = {
        "mode": "validate",
        "operation": args.operation,
        "interface_id": interface_id,
        "cli": cli,
        "body_sha256": digest,
        "write_allowlisted": allowlisted,
        "bytes": len(body),
    }
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

    from router_control.adapters.netcraze.allowlist import validate_interface_id
    from router_control.adapters.netcraze.interface_rci import (
        interface_down,
        interface_up,
    )
    from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    try:
        interface_id = validate_interface_id(args.interface_id)
    except ValueError as exc:
        print(f"invalid interface id: {exc}", file=sys.stderr)
        return 1

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
            if args.operation == "up":
                result = interface_up(transport, interface_id)
            else:
                result = interface_down(transport, interface_id)
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(
            f"interface-rci-op failed: {exc.__class__.__name__}: {exc}",
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
