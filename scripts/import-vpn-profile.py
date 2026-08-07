"""Offline AWG .conf import CLI — vault storage, sanitized stdout only."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Import AmneziaWG .conf profiles into vault; print sanitized metadata only.",
    )
    parser.add_argument(
        "--conf",
        action="append",
        default=[],
        metavar="PATH",
        help="Profile .conf path (repeatable)",
    )
    parser.add_argument(
        "--conf-dir",
        default="",
        help="Directory to scan for .conf files",
    )
    parser.add_argument(
        "--glob",
        default="*.conf",
        help="Glob under --conf-dir (default: *.conf)",
    )
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="Vault root (default: data/secrets)",
    )
    parser.add_argument(
        "--catalog-out",
        default="",
        help="Optional JSON path for sanitized import report",
    )
    parser.add_argument(
        "--allow-memory-vault",
        action="store_true",
        help="Use in-memory vault (tests/offline only; not for production secrets)",
    )
    return parser


def _resolve_conf_paths(args: argparse.Namespace) -> list[Path]:
    paths: list[Path] = [Path(p) for p in args.conf]
    if args.conf_dir:
        conf_dir = Path(args.conf_dir)
        if not conf_dir.is_dir():
            raise ValueError(f"conf-dir not found: {conf_dir}")
        paths.extend(sorted(conf_dir.glob(args.glob)))
    seen: set[Path] = set()
    unique: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def _build_vault(args: argparse.Namespace):
    if args.allow_memory_vault:
        from router_control.adapters.secrets.memory import MemoryVault

        return MemoryVault()
    if sys.platform != "win32":
        print(
            "WindowsDpapiVault requires win32; use --allow-memory-vault for offline tests",
            file=sys.stderr,
        )
        raise SystemExit(2)
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    return WindowsDpapiVault(root=Path(args.secrets_root))


def main() -> int:
    args = _build_parser().parse_args()
    if not args.conf and not args.conf_dir:
        print("Provide --conf and/or --conf-dir", file=sys.stderr)
        return 2

    try:
        conf_paths = _resolve_conf_paths(args)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if not conf_paths:
        print("No profile paths matched", file=sys.stderr)
        return 2

    vault = _build_vault(args)
    from router_control.adapters.netcraze.awg_profile import AwgProfileError, parse_awg_profile_path

    report: list[dict[str, object]] = []
    ok_count = 0
    for path in conf_paths:
        entry: dict[str, object] = {"path": str(path), "ok": False}
        try:
            parsed = parse_awg_profile_path(path, vault=vault)
            sanitized = parsed.sanitized_dict()
            entry["ok"] = True
            entry["sanitized"] = sanitized
            ok_count += 1
        except AwgProfileError as exc:
            entry["error"] = str(exc)
        except OSError as exc:
            entry["error"] = str(exc)
        report.append(entry)

    output = {"imports": report, "ok_count": ok_count, "total": len(report)}
    print(json.dumps(output, indent=2, ensure_ascii=False))

    if args.catalog_out:
        catalog_path = Path(args.catalog_out)
        catalog_path.parent.mkdir(parents=True, exist_ok=True)
        catalog_path.write_text(
            json.dumps(output, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    return 0 if ok_count >= 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
