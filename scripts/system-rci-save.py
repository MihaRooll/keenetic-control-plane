"""Sealed typed RCI system configuration save — validate default, live with --execute."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Sealed typed RCI system configuration save (validate default; live with --execute)."
        )
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


def _validate_plan() -> int:
    from router_control.adapters.netcraze.allowlist import (
        RCI_WRITE_PATH,
        body_sha256,
        is_write_allowlisted,
    )
    from router_control.adapters.netcraze.system_rci import (
        SystemRciOperation,
        command_for,
        sealed_request_for,
    )

    operation = SystemRciOperation.CONFIGURATION_SAVE
    request = sealed_request_for(operation)
    body = request.body
    digest = body_sha256(body)
    allowlisted = is_write_allowlisted("POST", RCI_WRITE_PATH, body)
    cli = command_for(operation)
    plan = {
        "mode": "validate",
        "operation": operation.value,
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

    from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
    from router_control.adapters.netcraze.system_rci import configuration_save
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

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
            result = configuration_save(transport)
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(
            f"system-rci-save failed: {exc.__class__.__name__}: {exc}",
            file=sys.stderr,
        )
        return 4

    print(json.dumps(result.sanitized_dict(), indent=2))
    return 0


def main() -> int:
    args = _build_parser().parse_args()
    if args.execute:
        return _execute_live(args)
    return _validate_plan()


if __name__ == "__main__":
    raise SystemExit(main())
