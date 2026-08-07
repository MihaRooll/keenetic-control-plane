"""Main-only READ-ONLY NDMS CLI grammar discovery (2026-08-05, PACKAGE H step S-0).

Opens an interactive SSH CLI session with a pinned host key and asks the device for
completions using `?` only. It enters the context of an EXISTING, UNUSED interface
(`GigabitEthernet1`, the wired ISP port, link down) so that no configuration is created
or changed, and it never touches `Bridge0` — that is the management path.

Safety rules enforced here:
  * every probe line must end with `?` (a completion request, not a command);
  * only a fixed allowlist of context-enter lines is permitted;
  * the session is left with `exit`;
  * nothing is saved.

Never prints secrets. Usage:
  py -3.11 scripts/main-cli-help-discovery-20260805.py
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

HOST = "192.168.2.1"
USERNAME = "admin"
CREDENTIAL_REF = "cred_69280efb9361ca2911e99d383f0ce474"
HOST_KEY_SHA256 = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
SOURCE_ADDRESS = "192.168.2.10"

# Existing, unused, link-down wired WAN port. NOT Bridge0 (management), NOT a tunnel.
SAFE_CONTEXT = "interface GigabitEthernet1"

PROBES = (
    "ip ?",
    "ip tcp ?",
    "ip mtu ?",
    "ip tcp adjust-mss ?",
)


def _fingerprint(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout", type=float, default=6.0, help="seconds to read per probe")
    parser.add_argument(
        "--context",
        default=SAFE_CONTEXT,
        help="context-enter line; must be an existing non-management interface, or 'none'",
    )
    parser.add_argument(
        "--probe",
        action="append",
        default=[],
        help="probe line; must end with '?' or start with a read-only diagnostic verb",
    )
    args = parser.parse_args()

    probes = tuple(args.probe) if args.probe else PROBES
    read_only_verbs = ("show ", "ping ", "trace ", "help ")
    for probe in probes:
        stripped = probe.strip()
        if not (stripped.endswith("?") or stripped.startswith(read_only_verbs)):
            print(f"refusing probe that is neither a completion nor a read: {probe!r}", file=sys.stderr)
            return 2
    if args.context.strip().lower() != "none" and args.context.strip() != SAFE_CONTEXT:
        print(
            f"refusing unexpected context {args.context!r}; only {SAFE_CONTEXT!r} or 'none'",
            file=sys.stderr,
        )
        return 2

    import paramiko

    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    password = WindowsDpapiVault(root=REPO_ROOT / "data" / "secrets").use(CREDENTIAL_REF)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.RejectPolicy())

    transport_socket = None
    try:
        import socket

        transport_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        transport_socket.bind((SOURCE_ADDRESS, 0))
        transport_socket.settimeout(15)
        transport_socket.connect((HOST, 22))

        transport = paramiko.Transport(transport_socket)
        transport.start_client(timeout=15)
        server_key = transport.get_remote_server_key()
        observed = _fingerprint(server_key.asbytes())
        if observed != HOST_KEY_SHA256:
            print(
                f"HOST KEY MISMATCH: expected {HOST_KEY_SHA256}, observed {observed} — refusing",
                file=sys.stderr,
            )
            transport.close()
            return 3
        print(f"host key pinned ok ({server_key.get_name()})")
        transport.auth_password(USERNAME, password)

        channel = transport.open_session()
        channel.get_pty()
        channel.invoke_shell()
        channel.settimeout(args.timeout)

        def _drain(seconds: float) -> str:
            collected: list[str] = []
            deadline = time.time() + seconds
            while time.time() < deadline:
                if channel.recv_ready():
                    collected.append(channel.recv(65535).decode("utf-8", errors="replace"))
                else:
                    time.sleep(0.15)
            return "".join(collected)

        banner = _drain(2.0)
        print(f"--- banner/prompt ---\n{banner.strip()[-400:]}")

        if args.context.strip().lower() != "none":
            channel.send(args.context + "\n")
            context_output = _drain(2.0)
            print(f"\n--- after `{args.context}` ---\n{context_output.strip()[-600:]}")

        for probe in probes:
            channel.send(probe + "\n")
            output = _drain(args.timeout)
            print(f"\n=== probe `{probe}` ===\n{output.strip()[:2500]}")

        channel.send("exit\n")
        _drain(1.5)
        channel.close()
        transport.close()
    except Exception as exc:  # noqa: BLE001 - operator diagnostics surface
        print(f"discovery failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 4
    finally:
        if transport_socket is not None:
            try:
                transport_socket.close()
            except OSError:
                pass

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
