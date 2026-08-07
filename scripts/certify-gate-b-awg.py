"""Gate B AWG certification CLI — dry-run default, no password argv/env."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_DIR = REPO_ROOT / "data" / "artifacts"
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"

MUTATION_COMMANDS = frozenset(
    {
        "apply",
        "backup",
        "save",
        "mutate",
        "write",
        "compensate",
        "fail-safe",
        "fail_safe",
        "reboot",
    }
)

PASSWORD_ENV_VARS = frozenset(
    {
        "RC_ROUTER_PASSWORD",
        "ROUTER_PASSWORD",
        "AWG_PASSWORD",
        "HUB_ADMIN_PASSWORD",
    }
)


def _reject_password_env() -> int:
    for name in PASSWORD_ENV_VARS:
        if os.environ.get(name):
            print(f"Refusing password environment variable: {name}", file=sys.stderr)
            return 2
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gate B/C AWG certification runner (dry-run default)."
    )
    parser.add_argument(
        "--profile",
        action="append",
        default=[],
        metavar="CANDIDATE=PATH",
        help="Candidate profile mapping (repeat for each candidate)",
    )
    parser.add_argument(
        "--candidate",
        default="",
        help="Single candidate id when using --profile-path",
    )
    parser.add_argument(
        "--profile-path",
        default="",
        help="Local profile path for single-candidate dry-run",
    )
    parser.add_argument(
        "--authorization-config",
        default=str(REPO_ROOT / "docs" / "gate-b-c-awg-authorization.json"),
        help="Gate B/C AWG authorization JSON path",
    )
    parser.add_argument(
        "--gate-a-config",
        default=str(REPO_ROOT / "docs" / "gate-a-certification.json"),
        help="Gate A certification JSON path",
    )
    parser.add_argument(
        "--gate-a-evidence",
        default=str(REPO_ROOT / "data" / "artifacts" / "gate-a-probe-192.168.1.1.json"),
        help="Gate A probe evidence JSON path",
    )
    parser.add_argument(
        "--status-path",
        default=str(REPO_ROOT / "docs" / "STATUS.yaml"),
        help="STATUS.yaml path for alignment checks",
    )
    parser.add_argument(
        "--artifact-out",
        default="",
        help="Sanitized evidence JSON output path",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Allow non-dry-run path (Main only; still fail-closed without shapes)",
    )
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root for --execute on win32 (default: data/secrets)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Offline-safe dry-run (default)",
    )
    parser.add_argument(
        "--source-address",
        default="",
        help="Literal private local IPv4/IPv6 bind for outbound TCP (required with --execute)",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    return parser


def _parse_profile_mappings(raw_items: list[str]) -> dict[str, Path]:
    profiles: dict[str, Path] = {}
    for item in raw_items:
        if "=" not in item:
            raise ValueError(f"invalid --profile value (expected CANDIDATE=PATH): {item}")
        candidate, path_text = item.split("=", 1)
        candidate = candidate.strip()
        path = Path(path_text.strip())
        if not candidate:
            raise ValueError("candidate id must be non-empty")
        profiles[candidate] = path
    return profiles


def _load_probe_evidence(path: Path) -> dict[str, object]:
    if not path.is_file():
        raise FileNotFoundError(f"Gate A evidence not found: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Gate A evidence must be an object")
    return payload


def _current_utc() -> datetime:
    return datetime.now(UTC)


def _resolve_vault(*, execute: bool, secrets_root: Path):
    if execute:
        if sys.platform != "win32":
            print(
                "Execute mode requires win32 with WindowsDpapiVault; refusing MemoryVault",
                file=sys.stderr,
            )
            return None, 2
        from router_control.adapters.secrets.dpapi import WindowsDpapiVault

        return WindowsDpapiVault(root=secrets_root), 0

    from router_control.adapters.secrets.memory import MemoryVault

    return MemoryVault(), 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    for token in args.extra:
        if token.lower() in MUTATION_COMMANDS:
            print(f"Refusing mutation-like command: {token}", file=sys.stderr)
            return 2

    guard = _reject_password_env()
    if guard != 0:
        return guard

    dry_run = not args.execute

    if args.execute:
        from router_control.adapters.netcraze.gate_bc import (
            GateBCError,
            require_live_execute_prerequisite,
        )

        auth_path = Path(args.authorization_config)
        try:
            auth_mapping = json.loads(auth_path.read_text(encoding="utf-8"))
            if not isinstance(auth_mapping, dict):
                raise ValueError("authorization config must be an object")
            require_live_execute_prerequisite(
                status_path=Path(args.status_path),
                authorization=auth_mapping,
            )
        except (GateBCError, ValueError, json.JSONDecodeError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if args.execute and not args.source_address.strip():
        print("--source-address is required with --execute", file=sys.stderr)
        return 2

    if args.source_address.strip():
        from router_control.adapters.netcraze.ssh_tunnel import (
            SshSourceAddressInvalid,
            validate_source_address,
        )

        try:
            validate_source_address(args.source_address.strip())
        except SshSourceAddressInvalid as exc:
            print(str(exc), file=sys.stderr)
            return 2

    try:
        profiles = _parse_profile_mappings(list(args.profile))
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if args.profile_path:
        candidate = args.candidate.strip() or "keenetic50-compat"
        profiles[candidate] = Path(args.profile_path)

    if not profiles:
        print(
            "At least one --profile CANDIDATE=PATH or --profile-path is required",
            file=sys.stderr,
        )
        return 2

    from router_control.adapters.netcraze.awg_certification import (
        CANDIDATE_ORDER,
        CertificationRunner,
        CertificationStop,
    )
    from router_control.adapters.netcraze.awg_hardware import AwgHardwareBoundary
    from router_control.adapters.netcraze.gate_bc import (
        GateBCError,
        GateCExpired,
        load_gate_a_for_bc_writes,
        load_gate_bc_authorization,
    )
    vault, vault_code = _resolve_vault(
        execute=not dry_run,
        secrets_root=Path(args.secrets_root),
    )
    if vault_code != 0:
        return vault_code

    try:
        gate_bc = load_gate_bc_authorization(
            config_path=Path(args.authorization_config),
            status_path=Path(args.status_path),
            now=_current_utc(),
        )
        gate_a = load_gate_a_for_bc_writes(
            gate_a_config_path=Path(args.gate_a_config),
            gate_a_evidence_path=Path(args.gate_a_evidence),
            status_path=Path(args.status_path),
            now=_current_utc(),
        )
        probe_evidence = _load_probe_evidence(Path(args.gate_a_evidence))
    except (GateBCError, GateCExpired, FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 3

    require_all = len(profiles) >= len(CANDIDATE_ORDER)

    hardware = AwgHardwareBoundary()
    runner = CertificationRunner(
        gate_a=gate_a,
        gate_bc=gate_bc,
        hardware=hardware,
        vault=vault,
        probe_evidence=dict(probe_evidence),
        dry_run=dry_run,
        now=_current_utc(),
        source_address=args.source_address.strip() or None,
    )

    try:
        evidence = runner.run_profiles(profiles, require_all_candidates=require_all)
    except CertificationStop as exc:
        print(str(exc), file=sys.stderr)
        return 4

    artifact_path = (
        Path(args.artifact_out)
        if args.artifact_out
        else DEFAULT_ARTIFACT_DIR / "gate-bc-awg-certification-dry-run.json"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(str(artifact_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
