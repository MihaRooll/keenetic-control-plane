"""Gate B fail-safe timer discovery CLI — dry-run default, no password argv/env."""

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
        "reboot",
        "exec",
        "run",
    }
)

PASSWORD_ENV_VARS = frozenset(
    {
        "RC_ROUTER_PASSWORD",
        "ROUTER_PASSWORD",
        "AWG_PASSWORD",
        "HUB_ADMIN_PASSWORD",
        "RC_PASSWORD",
        "NETCRAZE_PASSWORD",
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
        description="Gate B fail-safe timer discovery runner (dry-run default)."
    )
    parser.add_argument("--host", default="", help="Router management SSH host")
    parser.add_argument("--username", default="", help="Router SSH username")
    parser.add_argument("--credential-ref", default="", help="DPAPI credential ref id")
    parser.add_argument(
        "--host-key-sha256",
        "--pin",
        dest="host_key_sha256",
        default="",
        help="Pinned SSH host key SHA256 fingerprint",
    )
    parser.add_argument(
        "--authorization",
        required=True,
        help="Fail-safe trial authorization JSON path",
    )
    parser.add_argument(
        "--evidence-out",
        default="",
        help="Sanitized evidence JSON output path",
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
        "--trials-root",
        default=str(DEFAULT_ARTIFACT_DIR / "fail-safe-trials"),
        help="Directory for consumed trial markers",
    )
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root for --execute on win32",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Refused until P1-P3 live substrate verified and fresh exact T4 Human Gate",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Offline-safe dry-run (default)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Authorization/schema validation only (zero network)",
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


def _load_authorization_mapping(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("authorization must be an object")
    return payload


def _require_execute_fields(args: argparse.Namespace) -> int:
    missing = []
    if not args.host.strip():
        missing.append("--host")
    if not args.username.strip():
        missing.append("--username")
    if not args.credential_ref.strip():
        missing.append("--credential-ref")
    if not args.host_key_sha256.strip():
        missing.append("--host-key-sha256")
    if not args.source_address.strip():
        missing.append("--source-address")
    if missing:
        print(
            "Execute mode requires: " + ", ".join(missing),
            file=sys.stderr,
        )
        return 2
    return 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.extra:
        print(
            "Refusing unexpected arguments: " + " ".join(args.extra),
            file=sys.stderr,
        )
        return 2

    guard = _reject_password_env()
    if guard != 0:
        return guard

    execute = bool(args.execute)
    validate_only = bool(args.validate) or not execute

    if execute:
        field_guard = _require_execute_fields(args)
        if field_guard != 0:
            return field_guard
        from router_control.adapters.netcraze.gate_bc import (
            GateBCError,
            require_live_execute_prerequisite,
        )
        from router_control.adapters.netcraze.ssh_tunnel import (
            SshSourceAddressInvalid,
            validate_source_address,
        )

        try:
            require_live_execute_prerequisite(
                status_path=Path(args.status_path),
                authorization=_load_authorization_mapping(Path(args.authorization)),
            )
            validate_source_address(args.source_address.strip())
        except (GateBCError, SshSourceAddressInvalid, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

    from router_control.adapters.netcraze.fail_safe_certification import (
        CONTRACT_ID,
        FailSafeDiscoveryRunner,
        FailSafeError,
        FailSafeWindowClosed,
        load_fail_safe_authorization,
        load_gate_a_for_fail_safe,
    )
    from router_control.adapters.netcraze.ssh_tunnel import normalize_sha256_fingerprint

    vault, vault_code = _resolve_vault(execute=execute, secrets_root=Path(args.secrets_root))
    if vault_code != 0:
        return vault_code

    try:
        authorization = load_fail_safe_authorization(
            config_path=Path(args.authorization),
            status_path=Path(args.status_path),
            now=_current_utc(),
        )
        gate_a = load_gate_a_for_fail_safe(
            gate_a_config_path=Path(args.gate_a_config),
            gate_a_evidence_path=Path(args.gate_a_evidence),
            status_path=Path(args.status_path),
            now=_current_utc(),
        )
        probe_evidence = _load_probe_evidence(Path(args.gate_a_evidence))
    except (FailSafeError, FailSafeWindowClosed, FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 3

    if authorization.contract_id != CONTRACT_ID:
        print(f"authorization contract_id must be {CONTRACT_ID}", file=sys.stderr)
        return 3

    if execute and args.host_key_sha256.strip():
        try:
            cli_pin = normalize_sha256_fingerprint(args.host_key_sha256.strip())
            gate_pin = normalize_sha256_fingerprint(gate_a.ssh_host_key_fingerprint_sha256)
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 3
        if cli_pin != gate_pin:
            print("host-key pin mismatches Gate A certification fingerprint", file=sys.stderr)
            return 3

    runner = FailSafeDiscoveryRunner(
        authorization=authorization,
        gate_a=gate_a,
        host=args.host.strip(),
        username=args.username.strip(),
        credential_ref=args.credential_ref.strip(),
        host_key_pin=args.host_key_sha256.strip(),
        vault=vault,
        probe_evidence=dict(probe_evidence),
        dry_run=not execute,
        validate_only=validate_only,
        trials_root=Path(args.trials_root),
        now=_current_utc(),
        source_address=args.source_address.strip() or None,
    )

    evidence = runner.run()

    artifact_path = (
        Path(args.evidence_out)
        if args.evidence_out
        else DEFAULT_ARTIFACT_DIR / "fail-safe-discovery-dry-run.json"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(str(artifact_path))
    return 0 if evidence.get("result") in {"passed", "validated"} else 4


if __name__ == "__main__":
    raise SystemExit(main())
