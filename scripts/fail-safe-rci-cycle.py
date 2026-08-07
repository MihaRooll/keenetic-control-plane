"""Live typed fail-safe RCI cycle: arm 60s then disarm via the sealed fail_safe_rci layer.

Exercises the productized typed path end-to-end (execute_sealed_rci_write + write
allowlist + structured ack verification) against the certified NC-1812 over the pinned
SSH tunnel. Arms the 60-second reboot timer then immediately disarms it, so the router
does not reboot. Prints only sanitized status envelopes; never prints secrets.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Live typed fail-safe RCI arm+disarm cycle.")
    p.add_argument("--host", required=True, help="Router management host, e.g. 192.168.1.1")
    p.add_argument("--credential-ref", required=True, help="DPAPI credential ref id")
    p.add_argument("--username", required=True, help="RCI auth username (not password)")
    p.add_argument("--ssh-host-key-sha256", required=True, help="Pinned SSH host key SHA256")
    p.add_argument("--source-address", default="", help="Source IP bind, e.g. 192.168.1.144")
    p.add_argument("--secrets-root", default=str(DEFAULT_SECRETS_ROOT))
    return p


def main() -> int:
    args = _build_parser().parse_args()

    if sys.platform != "win32":
        print("DPAPI credential resolution requires win32", file=sys.stderr)
        return 2

    from router_control.adapters.netcraze.fail_safe_rci import (
        arm_fail_safe_timer_reboot_60,
        disarm_fail_safe_timer,
    )
    from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
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
            arm = arm_fail_safe_timer_reboot_60(transport)
            disarm = disarm_fail_safe_timer(transport)
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(f"fail-safe cycle failed: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        return 4

    print(
        json.dumps(
            {"arm": arm.sanitized_dict(), "disarm": disarm.sanitized_dict()},
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
