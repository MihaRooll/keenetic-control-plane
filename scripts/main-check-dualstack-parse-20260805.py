"""Main-only: verify the profile parser accepts the operator's real UNMODIFIED configs.

Runs the in-process parser over every .conf in the user's Downloads folder and prints a
per-file verdict. Never prints file contents, keys, endpoints or the AllowedIPs value.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from router_control.adapters.netcraze.awg_profile import (  # noqa: E402
    AwgProfileError,
    parse_awg_profile_text,
)
from router_control.adapters.secrets.dpapi import WindowsDpapiVault  # noqa: E402


def main() -> int:
    # Throwaway vault root so parsing does not add credential refs to the real store.
    vault_root = Path(tempfile.mkdtemp(prefix="main-parse-check-"))
    vault = WindowsDpapiVault(root=vault_root)
    files = sorted((Path.home() / "Downloads").glob("*.conf"))
    if not files:
        print("no .conf files found")
        return 2

    accepted = 0
    rejected = 0
    for path in files:
        try:
            parsed = parse_awg_profile_text(path.read_text(encoding="utf-8"), vault=vault)
        except AwgProfileError as exc:
            print(f"REJECT {path.name}: {exc.__class__.__name__}: {exc}")
            rejected += 1
            continue
        except Exception as exc:  # noqa: BLE001 - diagnostics surface
            print(f"ERROR  {path.name}: {exc.__class__.__name__}: {exc}")
            rejected += 1
            continue
        accepted += 1
        print(
            f"ok     {path.name}: allow_ips_ipv4={parsed.peer_allow_ips!r} "
            f"keepalive={parsed.peer_keepalive_interval} "
            f"asc9={'yes' if parsed.asc9_args else 'no'} "
            f"unsupported={list(parsed.unsupported_fields)} "
            f"notes={len(parsed.operator_notes)}"
        )

    print(f"\naccepted={accepted} rejected={rejected} total={len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
