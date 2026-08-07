"""Main-only live read-only WireGuard diagnostics probe (2026-08-05 session).

Runs `show interface WireguardN` (and optional extra read commands) over the
pinned SSH tunnel and prints a REDACTED summary: link/connection state,
security level, global/ip settings, peer handshake counters. Never prints
private keys, preshared keys or passwords; public keys are truncated.

Usage (Main only, lab router 192.168.2.1):
  py -3.11 scripts/main-wg-live-probe-20260805.py --wg 5 --wg 8
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

HOST = "192.168.2.1"
USERNAME = "admin"
CREDENTIAL_REF = "cred_69280efb9361ca2911e99d383f0ce474"
HOST_KEY = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
SOURCE_ADDRESS = "192.168.2.10"

SECRET_HINTS = ("private", "preshared", "password", "secret")
INTERESTING = (
    "id",
    "index",
    "interface-name",
    "type",
    "description",
    "link",
    "connected",
    "state",
    "mtu",
    "address",
    "mask",
    "security-level",
    "global",
    "defaultgw",
    "priority",
    "uptime",
    "last-handshake",
    "rxbytes",
    "txbytes",
    "endpoint",
    "allowed-ips",
    "keepalive-interval",
    "public-key",
    "listen-port",
    "asc",
)


def _redact(key: str, value: Any) -> Any:
    lowered = key.lower()
    if any(hint in lowered for hint in SECRET_HINTS):
        return "<redacted>"
    if lowered.endswith("public-key") and isinstance(value, str):
        return f"{value[:6]}...len={len(value)}"
    return value


def _summarize(node: Any, path: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(node, dict):
        for key, value in node.items():
            child = f"{path}.{key}" if path else key
            if isinstance(value, (dict, list)):
                nested = _summarize(value, child)
                if nested:
                    out.update(nested)
            elif key in INTERESTING or key.lower() in INTERESTING:
                out[child] = _redact(key, value)
    elif isinstance(node, list):
        for position, item in enumerate(node):
            nested = _summarize(item, f"{path}[{position}]")
            if nested:
                out.update(nested)
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wg", action="append", default=[], help="WireGuard index, repeatable")
    parser.add_argument("--command", action="append", default=[], help="Extra read-only command")
    parser.add_argument("--full", action="store_true", help="Print full redacted JSON tree")
    args = parser.parse_args()

    commands = [f"show interface Wireguard{index}" for index in args.wg]
    commands.extend(args.command)
    if not commands:
        parser.error("at least one --wg or --command is required")

    for command in commands:
        tokens = command.strip().lower().split()
        if not tokens or tokens[0] not in {"show", "help", "trace", "ping"}:
            print(f"refusing non-read command: {command!r}", file=sys.stderr)
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

    target = parse_transport_target(HOST)
    source = validate_source_address(SOURCE_ADDRESS)
    preflight_source_address_bind(source)
    password = WindowsDpapiVault(root=REPO_ROOT / "data" / "secrets").use(CREDENTIAL_REF)

    config = SshTunnelConfig(
        ssh_host=target.hostname,
        username=USERNAME,
        password=password,
        host_key_sha256=HOST_KEY,
        source_address=source,
    )

    results: dict[str, Any] = {}
    with PinnedSshTunnel(config) as tunnel:
        transport = SshTunnelNetcrazeTransport(
            host=tunnel.local_host,
            port=tunnel.local_port,
            use_tls=False,
            username=USERNAME,
            password=password,
            management_host_header=derive_management_host_header(HOST),
            ssh_host_key_algorithm=tunnel.host_key_algorithm,
            ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
            source_address=source,
        )
        for command in commands:
            try:
                raw = transport.execute_rci_parse(command)
            except Exception as exc:  # noqa: BLE001 - operator diagnostics surface
                results[command] = {"error": f"{exc.__class__.__name__}: {exc}"}
                continue
            results[command] = _summarize(raw) if not args.full else _redact_tree(raw)

    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0


def _redact_tree(node: Any) -> Any:
    if isinstance(node, dict):
        return {key: ("<redacted>" if any(h in key.lower() for h in SECRET_HINTS) else _redact_tree(value)) for key, value in node.items()}
    if isinstance(node, list):
        return [_redact_tree(item) for item in node]
    return node


if __name__ == "__main__":
    raise SystemExit(main())
