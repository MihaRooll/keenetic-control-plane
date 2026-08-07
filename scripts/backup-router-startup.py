"""Encrypted startup-config backup CLI — pinned SSH tunnel, DPAPI vault, no secrets in output."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"
DEFAULT_BACKUPS_ROOT = REPO_ROOT / "data" / "backups"

MUTATION_COMMANDS = frozenset(
    {
        "apply",
        "backup",
        "save",
        "mutate",
        "write",
        "compensate",
        "install",
        "reboot",
    }
)

PASSWORD_ENV_VARS = (
    "ROUTER_PASSWORD",
    "RCI_PASSWORD",
    "NETCRAZE_PASSWORD",
    "PROBE_PASSWORD",
    "RC_PASSWORD",
    "HUB_ADMIN_PASSWORD",
)


def _host_is_private(host: str) -> bool:
    candidate = host
    if "://" in host:
        from urllib.parse import urlparse

        parsed = urlparse(host)
        candidate = parsed.hostname or host
    if candidate.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return addr.is_private or addr.is_link_local or addr.is_loopback


def _validate_ssh_tunnel_preflight(
    host: str,
    *,
    allow_non_private: bool,
) -> tuple[int, str, str]:
    from router_control.adapters.netcraze.transport import (
        derive_management_host_header,
        is_loopback_management_host,
        parse_transport_target,
    )

    try:
        target = parse_transport_target(host)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2, "", ""

    ssh_host = target.hostname
    if not allow_non_private and not _host_is_private(ssh_host):
        print(
            "Refusing non-private SSH host without --allow-non-private",
            file=sys.stderr,
        )
        return 2, "", ""

    try:
        management_header = derive_management_host_header(host)
        if is_loopback_management_host(management_header):
            raise ValueError("management host must not be loopback")
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2, "", ""

    return 0, ssh_host, management_header


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Fetch fixed /ci/startup-config.txt over pinned SSH tunnel and "
            "store DPAPI-encrypted backup under data/backups."
        )
    )
    parser.add_argument("--host", required=True, help="Router management host (private by default)")
    parser.add_argument("--credential-ref", required=True, help="DPAPI credential ref id")
    parser.add_argument("--username", required=True, help="RCI auth username (not password)")
    parser.add_argument(
        "--ssh-host-key-sha256",
        required=True,
        help="Pinned SSH host key SHA256 fingerprint (SHA256:...)",
    )
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root (default: data/secrets)",
    )
    parser.add_argument(
        "--allow-non-private",
        action="store_true",
        help="Allow non-private SSH hosts (lab edge cases only)",
    )
    parser.add_argument(
        "--source-address",
        default="",
        help="Optional literal private local IPv4/IPv6 bind for outbound TCP",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    for token in args.extra:
        if token.lower() in MUTATION_COMMANDS:
            print(f"Refusing mutation-like command: {token}", file=sys.stderr)
            return 2

    for env_name in PASSWORD_ENV_VARS:
        if env_name in __import__("os").environ:
            print(f"Refusing password env var: {env_name}", file=sys.stderr)
            return 2

    from router_control.adapters.netcraze.certification import (
        GateACertificationError,
        load_gate_a_certification,
    )
    from router_control.adapters.netcraze.ssh_tunnel import normalize_sha256_fingerprint

    try:
        certification = load_gate_a_certification(
            require_status_alignment=True,
            require_evidence=True,
        )
        if not certification.is_open:
            raise GateACertificationError("Gate A ReadOnlyCertified certification is not open")
        if (
            normalize_sha256_fingerprint(args.ssh_host_key_sha256)
            != normalize_sha256_fingerprint(
                certification.ssh_host_key_fingerprint_sha256
            )
        ):
            raise GateACertificationError(
                "requested SSH host-key fingerprint mismatches certification"
            )
    except GateACertificationError as exc:
        print(f"Certification check failed: {exc}", file=sys.stderr)
        return 3

    preflight_code, ssh_host, management_host_header = _validate_ssh_tunnel_preflight(
        args.host,
        allow_non_private=args.allow_non_private,
    )
    if preflight_code != 0:
        return preflight_code

    if args.source_address.strip():
        from router_control.adapters.netcraze.ssh_tunnel import (
            SshSourceAddressInvalid,
            validate_source_address,
        )

        try:
            validated_source = validate_source_address(args.source_address.strip())
        except SshSourceAddressInvalid as exc:
            print(str(exc), file=sys.stderr)
            return 2
    else:
        validated_source = None

    if validated_source is not None:
        from router_control.adapters.netcraze.ssh_tunnel import (
            SshSourceAddressBindError,
            preflight_source_address_bind,
        )

        try:
            preflight_source_address_bind(validated_source)
        except SshSourceAddressBindError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    if sys.platform != "win32":
        print("DPAPI credential resolution requires win32", file=sys.stderr)
        return 2

    from router_control.adapters.netcraze.ssh_tunnel import PinnedSshTunnel, SshTunnelConfig
    from router_control.adapters.netcraze.startup_backup import (
        StartupBackupError,
        backup_startup_config,
    )
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    vault = WindowsDpapiVault(root=Path(args.secrets_root))
    password = vault.use(args.credential_ref)

    tunnel_config = SshTunnelConfig(
        ssh_host=ssh_host,
        username=args.username,
        password=password,
        host_key_sha256=args.ssh_host_key_sha256,
        allow_non_private=args.allow_non_private,
        source_address=validated_source,
    )

    try:
        with PinnedSshTunnel(tunnel_config) as tunnel:
            metadata = backup_startup_config(
                tunnel=tunnel,
                certification=certification,
            )
    except StartupBackupError as exc:
        print(f"Startup backup failed: {exc}", file=sys.stderr)
        return 4
    except Exception as exc:
        print(f"Startup backup failed: {exc.__class__.__name__}", file=sys.stderr)
        return 4

    output = {
        "encrypted_locator": metadata.encrypted_locator,
        "metadata_locator": metadata.metadata_locator,
        "content_sha256": metadata.content_sha256,
        "size_bytes": metadata.size_bytes,
        "endpoint": metadata.endpoint,
        "recorded_at": metadata.recorded_at,
        "transport_security": metadata.transport_security,
        "device_fingerprint_digest": metadata.device_fingerprint_digest,
        "ssh_host_key_fingerprint_sha256": metadata.ssh_host_key_fingerprint_sha256,
        "ssh_host_key_algorithm": metadata.ssh_host_key_algorithm,
    }
    if getattr(metadata, "source_address", None) is not None:
        output["source_address"] = metadata.source_address
    if getattr(metadata, "source_address_class", None) is not None:
        output["source_address_class"] = metadata.source_address_class
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
