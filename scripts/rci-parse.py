"""Live RCI parse dispatcher over the pinned SSH tunnel (operator lab tool).

Sends a single NDMS CLI command via RCI `parse` (POST /rci/ [{"parse": cmd}]) and
prints the sanitized parse.status envelope. Reads are safe; writes are gated by
an explicit --allow-write flag. Never prints or stores secrets.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"

# Read-only CLI verbs. Anything not starting with one of these is treated as a
# write and requires --allow-write (fail-closed default).
_READ_PREFIXES = frozenset({"show", "help", "trace", "ping"})


def _looks_like_write(command: str) -> bool:
    tokens = command.strip().lower().split()
    if not tokens:
        return False
    return tokens[0] not in _READ_PREFIXES


def _summarize(result: Any) -> list[dict[str, Any]]:
    """Collect all parse.status entries (status/code/ident/message) from the response."""
    summary: list[dict[str, Any]] = []

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            status = node.get("status")
            if isinstance(status, list):
                for entry in status:
                    if isinstance(entry, dict):
                        summary.append(
                            {
                                "status": entry.get("status"),
                                "code": entry.get("code"),
                                "ident": entry.get("ident"),
                                "message": entry.get("message"),
                            }
                        )
            for value in node.values():
                _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(result)
    return summary


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Live RCI parse over pinned SSH tunnel.")
    p.add_argument("--host", required=True, help="Router management host, e.g. 192.168.1.1")
    p.add_argument("--credential-ref", required=True, help="DPAPI credential ref id")
    p.add_argument("--username", required=True, help="RCI auth username (not password)")
    p.add_argument("--ssh-host-key-sha256", required=True, help="Pinned SSH host key SHA256")
    p.add_argument("--source-address", default="", help="Source IP bind, e.g. 192.168.1.144")
    p.add_argument("--command", required=True, help="NDMS CLI command to parse")
    p.add_argument("--allow-write", action="store_true", help="Permit config-mutating commands")
    p.add_argument("--raw", action="store_true", help="Also print raw JSON response")
    p.add_argument("--secrets-root", default=str(DEFAULT_SECRETS_ROOT))
    return p


def main() -> int:
    args = _build_parser().parse_args()

    if _looks_like_write(args.command) and not args.allow_write:
        print(
            f"Refusing write-like command without --allow-write: {args.command!r}",
            file=sys.stderr,
        )
        return 2

    if sys.platform != "win32":
        print("DPAPI credential resolution requires win32", file=sys.stderr)
        return 2

    from router_control.adapters.netcraze.ssh_tunnel import (
        PinnedSshTunnel,
        SshTunnelConfig,
        preflight_source_address_bind,
        validate_source_address,
    )
    from router_control.adapters.netcraze.transport import (
        SshTunnelNetcrazeTransport,
        derive_management_host_header,
        parse_transport_target,
    )
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    target = parse_transport_target(args.host)
    ssh_host = target.hostname
    management_header = derive_management_host_header(args.host)

    source = None
    if args.source_address.strip():
        source = validate_source_address(args.source_address.strip())
        preflight_source_address_bind(source)

    vault = WindowsDpapiVault(root=Path(args.secrets_root))
    password = vault.use(args.credential_ref)

    tunnel_config = SshTunnelConfig(
        ssh_host=ssh_host,
        username=args.username,
        password=password,
        host_key_sha256=args.ssh_host_key_sha256,
        source_address=source,
    )

    try:
        with PinnedSshTunnel(tunnel_config) as tunnel:
            transport = SshTunnelNetcrazeTransport(
                host=tunnel.local_host,
                port=tunnel.local_port,
                use_tls=False,
                username=args.username,
                password=password,
                management_host_header=management_header,
                ssh_host_key_algorithm=tunnel.host_key_algorithm,
                ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
                source_address=source or "",
            )
            result = transport.execute_rci_parse(args.command)
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(f"RCI parse failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 4

    status_entries = _summarize(result)
    has_error = any(e.get("status") == "error" for e in status_entries)
    out: dict[str, Any] = {"ack_ok": not has_error, "status": status_entries}
    if args.raw:
        out["raw"] = result
    print(json.dumps(out, indent=2))
    return 1 if has_error else 0


if __name__ == "__main__":
    raise SystemExit(main())
