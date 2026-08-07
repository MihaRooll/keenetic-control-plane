"""Store router RCI credentials in Windows DPAPI vault (interactive getpass)."""

from __future__ import annotations

import argparse
import json
import sys
from getpass import getpass
from pathlib import Path
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"
DEFAULT_META_DIR = DEFAULT_SECRETS_ROOT / "meta"


def host_has_embedded_credentials(host: str) -> bool:
    if "://" in host:
        parsed = urlparse(host)
        return parsed.username is not None or parsed.password is not None
    return "@" in host


def main() -> int:
    parser = argparse.ArgumentParser(description="Store router RCI password in DPAPI vault.")
    parser.add_argument("--host", required=True, help="Router management host or IP")
    parser.add_argument("--username", required=True, help="Digest auth username")
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root (default: data/secrets)",
    )
    parser.add_argument(
        "--meta-out",
        default="",
        help="Optional metadata JSON path (default: data/secrets/meta/router-credential-meta.json)",
    )
    args = parser.parse_args()

    if host_has_embedded_credentials(args.host):
        print("Host must not contain embedded credentials", file=sys.stderr)
        return 2

    if sys.platform != "win32":
        print("WindowsDpapiVault requires win32", file=sys.stderr)
        return 2

    password = getpass("Router password: ")
    if not password:
        print("Password must not be empty", file=sys.stderr)
        return 2

    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    secrets_root = Path(args.secrets_root)
    vault = WindowsDpapiVault(root=secrets_root)
    handle = vault.create(kind="router_rci", secret=password)

    meta_path = (
        Path(args.meta_out) if args.meta_out else DEFAULT_META_DIR / "router-credential-meta.json"
    )
    meta_path.parent.mkdir(parents=True, exist_ok=True)
    metadata = {
        "host": args.host,
        "username": args.username,
        "credential_ref": handle.credential_ref_id,
    }
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    print(handle.credential_ref_id)
    insecure_flag = ""
    if args.host.lower().startswith("http://"):
        insecure_flag = " --allow-insecure-http"
    print(
        "Next: probe Gate A evidence with "
        f"py.exe -3.11 scripts\\probe-gate-a.py --host {args.host} "
        f"--credential-ref {handle.credential_ref_id} --username {args.username}{insecure_flag}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
