"""NC-1812 read-only SSH CLI channel discovery — validate default, live-probe gated."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

from router_control.adapters.netcraze.ssh_tunnel import host_is_private
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"
DEFAULT_ARTIFACT_DIR = REPO_ROOT / "data" / "artifacts"

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
        "exec",
        "run",
        "execute",
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


def _host_is_private(host: str) -> bool:
    candidate = host
    if "://" in host:
        from urllib.parse import urlparse

        parsed = urlparse(host)
        candidate = parsed.hostname or host
    return host_is_private(candidate)


def _validate_ssh_tunnel_preflight(
    host: str,
    *,
    allow_non_private: bool,
) -> tuple[int, str]:
    from router_control.adapters.netcraze.transport import (
        is_loopback_management_host,
        parse_transport_target,
    )

    try:
        target = parse_transport_target(host)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2, ""

    ssh_host = target.hostname
    if not allow_non_private and not _host_is_private(ssh_host):
        print(
            "Refusing non-private SSH host without --allow-non-private",
            file=sys.stderr,
        )
        return 2, ""

    try:
        from router_control.adapters.netcraze.transport import derive_management_host_header

        management_header = derive_management_host_header(host)
        if is_loopback_management_host(management_header):
            raise ValueError("management host must not be loopback")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2, ""

    return 0, ssh_host


def _resolve_source_address(raw: str, *, required: bool) -> tuple[int, str | None]:
    if not raw.strip():
        if required:
            print("--source-address is required for live SSH CLI discovery", file=sys.stderr)
            return 2, None
        return 0, None
    from router_control.adapters.netcraze.ssh_tunnel import (
        SshSourceAddressInvalid,
        validate_source_address,
    )

    try:
        bound = validate_source_address(raw.strip())
    except SshSourceAddressInvalid as exc:
        print(str(exc), file=sys.stderr)
        return 2, None
    if bound != "192.168.2.10":
        print("source_address must be 192.168.2.10 for NC-1812 lab discovery", file=sys.stderr)
        return 2, None
    return 0, bound


def _reject_password_env() -> int:
    for name in PASSWORD_ENV_VARS:
        if os.environ.get(name):
            print(f"Refusing password environment variable: {name}", file=sys.stderr)
            return 2
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NC-1812 read-only SSH CLI channel discovery (validate default)."
    )
    parser.add_argument("--host", default="", help="Router management SSH host")
    parser.add_argument("--credential-ref", default="", help="DPAPI credential ref id")
    parser.add_argument("--username", default="", help="SSH username (not password)")
    parser.add_argument(
        "--ssh-host-key-sha256",
        "--pin",
        dest="ssh_host_key_sha256",
        default="",
        help="Pinned SSH host key SHA256 fingerprint (required for live-probe)",
    )
    parser.add_argument(
        "--source-address",
        required=False,
        default="192.168.2.10",
        help="Literal private local IPv4/IPv6 bind (192.168.2.10 for lab)",
    )
    parser.add_argument(
        "--authorization",
        default="",
        help="SSH CLI discovery authorization JSON path",
    )
    parser.add_argument(
        "--artifact-out",
        default="",
        help="Sanitized discovery artifact JSON path",
    )
    parser.add_argument(
        "--gate-a-config",
        default=str(REPO_ROOT / "docs" / "gate-a-certification.json"),
        help="Gate A certification JSON path",
    )
    parser.add_argument(
        "--gate-a-evidence",
        default=str(
            REPO_ROOT / "data" / "artifacts" / "gate-a-return-home-192.168.2.1-20260723.json"
        ),
        help="Gate A probe evidence JSON path",
    )
    parser.add_argument(
        "--status-path",
        default=str(REPO_ROOT / "docs" / "STATUS.yaml"),
        help="STATUS.yaml path for alignment checks",
    )
    parser.add_argument(
        "--probes-root",
        default=str(DEFAULT_ARTIFACT_DIR / "ssh-cli-discovery-probes"),
        help="Directory for consumed probe_id markers",
    )
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root (live-probe only)",
    )
    parser.add_argument(
        "--allow-non-private",
        action="store_true",
        help="Allow non-private SSH host (lab edge cases only)",
    )
    parser.add_argument(
        "--live-probe",
        action="store_true",
        help="Live read-only discovery (requires authorization, DPAPI, pin, source)",
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


def _resolve_vault(*, live_probe: bool, secrets_root: Path):
    if live_probe:
        if sys.platform != "win32":
            print(
                "Live-probe mode requires win32 with WindowsDpapiVault; refusing MemoryVault",
                file=sys.stderr,
            )
            return None, 2
        from router_control.adapters.secrets.dpapi import WindowsDpapiVault

        return WindowsDpapiVault(root=secrets_root), 0

    from router_control.adapters.secrets.memory import MemoryVault

    return MemoryVault(), 0


def _require_live_probe_fields(args: argparse.Namespace) -> int:
    missing = []
    if not args.host.strip():
        missing.append("--host")
    if not args.username.strip():
        missing.append("--username")
    if not args.credential_ref.strip():
        missing.append("--credential-ref")
    if not args.ssh_host_key_sha256.strip():
        missing.append("--ssh-host-key-sha256")
    if not args.source_address.strip():
        missing.append("--source-address")
    if not args.authorization.strip():
        missing.append("--authorization")
    if missing:
        print("Live-probe requires: " + ", ".join(missing), file=sys.stderr)
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

    live_probe = bool(args.live_probe)
    validate_only = not live_probe

    if live_probe:
        field_guard = _require_live_probe_fields(args)
        if field_guard != 0:
            return field_guard
        preflight_code, _ssh_host = _validate_ssh_tunnel_preflight(
            args.host,
            allow_non_private=args.allow_non_private,
        )
        if preflight_code != 0:
            return preflight_code
        source_guard, validated_source = _resolve_source_address(args.source_address, required=True)
        if source_guard != 0 or validated_source is None:
            return source_guard or 2
        from router_control.adapters.netcraze.ssh_tunnel import (
            SshSourceAddressBindError,
            preflight_source_address_bind,
        )

        try:
            preflight_source_address_bind(validated_source)
        except SshSourceAddressBindError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    else:
        source_guard, validated_source = _resolve_source_address(
            args.source_address,
            required=False,
        )
        if source_guard != 0:
            return source_guard

    from router_control.adapters.netcraze.ssh_cli_discovery import (
        CONTRACT_ID,
        SshCliDiscoveryError,
        SshCliDiscoveryRunner,
        SshCliDiscoveryWindowClosed,
        load_gate_a_for_ssh_cli_discovery,
        load_ssh_cli_discovery_authorization,
    )

    vault, vault_code = _resolve_vault(live_probe=live_probe, secrets_root=Path(args.secrets_root))
    if vault_code != 0:
        return vault_code

    authorization = None
    gate_a = None
    probe_evidence: dict[str, object] | None = None
    now = datetime.now(UTC)

    if args.authorization.strip():
        try:
            authorization = load_ssh_cli_discovery_authorization(
                config_path=Path(args.authorization),
                status_path=Path(args.status_path),
                now=now,
            )
        except (SshCliDiscoveryError, SshCliDiscoveryWindowClosed) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        if authorization.contract_id != CONTRACT_ID:
            print(f"authorization contract_id must be {CONTRACT_ID}", file=sys.stderr)
            return 3

    try:
        gate_a = load_gate_a_for_ssh_cli_discovery(
            gate_a_config_path=Path(args.gate_a_config),
            gate_a_evidence_path=Path(args.gate_a_evidence),
            status_path=Path(args.status_path),
            now=now,
        )
        if args.gate_a_evidence.strip():
            probe_evidence = _load_probe_evidence(Path(args.gate_a_evidence))
    except (SshCliDiscoveryError, FileNotFoundError, ValueError) as exc:
        if live_probe:
            print(str(exc), file=sys.stderr)
            return 3

    if validate_only and not args.authorization.strip():
        print("--authorization is required for --validate", file=sys.stderr)
        return 2

    runner = SshCliDiscoveryRunner(
        authorization=authorization,
        gate_a=gate_a,
        host=args.host.strip(),
        username=args.username.strip(),
        credential_ref=args.credential_ref.strip(),
        host_key_pin=args.ssh_host_key_sha256.strip(),
        vault=vault,
        probe_evidence=probe_evidence,
        validate_only=validate_only,
        live_probe=live_probe,
        probes_root=Path(args.probes_root),
        now=now,
        source_address=(validated_source or "192.168.2.10"),
    )

    try:
        evidence = runner.run()
    except SshCliDiscoveryError as exc:
        print(str(exc), file=sys.stderr)
        return 4

    artifact_path = (
        Path(args.artifact_out)
        if args.artifact_out
        else DEFAULT_ARTIFACT_DIR / "ssh-cli-discovery-validate.json"
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    print(str(artifact_path))
    return 0 if evidence.get("result") in {"validated", "probed"} else 4


if __name__ == "__main__":
    raise SystemExit(main())
