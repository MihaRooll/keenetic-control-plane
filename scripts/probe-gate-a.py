"""Gate A read-only probe CLI — sanitized evidence artifact, no secrets."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

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
    }
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


def _validate_target(host: str, *, allow_non_private: bool, allow_insecure_http: bool) -> int:

    from router_control.adapters.netcraze.transport import parse_transport_target

    try:
        target = parse_transport_target(host)

    except ValueError as exc:
        print(str(exc), file=sys.stderr)

        return 2

    if not allow_non_private and not _host_is_private(target.hostname):
        print(
            "Refusing non-private host without --allow-non-private",
            file=sys.stderr,
        )

        return 2

    if target.scheme == "http":
        if not allow_insecure_http:
            print(
                "Refusing plain HTTP without --allow-insecure-http",
                file=sys.stderr,
            )

            return 2

        if not _host_is_private(target.hostname):
            print(
                "Refusing plain HTTP to non-private host",
                file=sys.stderr,
            )

            return 2

    return 0


def _resolve_ssh_host(host: str) -> str:

    from router_control.adapters.netcraze.transport import parse_transport_target

    target = parse_transport_target(host)

    return target.hostname


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


def _resolve_source_address(raw: str) -> tuple[int, str | None]:
    if not raw.strip():
        return 0, None
    from router_control.adapters.netcraze.ssh_tunnel import (
        SshSourceAddressInvalid,
        validate_source_address,
    )

    try:
        return 0, validate_source_address(raw.strip())
    except SshSourceAddressInvalid as exc:
        print(str(exc), file=sys.stderr)
        return 2, None


def _source_bind_evidence(source_address: str | None) -> dict[str, str]:
    if source_address is None:
        return {}
    from router_control.adapters.netcraze.ssh_tunnel import source_address_class

    return {
        "source_address": source_address,
        "source_address_class": source_address_class(source_address),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Gate A read-only Netcraze identity probe.")
    parser.add_argument("--host", required=True, help="Router management host (private by default)")
    parser.add_argument("--credential-ref", required=True, help="DPAPI credential ref id")
    parser.add_argument("--username", required=True, help="RCI auth username (not password)")
    parser.add_argument(
        "--ssh-tunnel",
        action="store_true",
        help=(
            "Use host-key-pinned SSH local forward to verified router "
            "management RCI HTTP (port 80)"
        ),
    )
    parser.add_argument(
        "--ssh-host-key-sha256",
        default="",
        help="Pinned SSH host key SHA256 fingerprint (required with --ssh-tunnel)",
    )
    parser.add_argument(
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root (default: data/secrets)",
    )
    parser.add_argument(
        "--artifact-out",
        default="",
        help="Sanitized evidence JSON path (default: data/artifacts/gate-a-probe-<host>.json)",
    )
    parser.add_argument(
        "--allow-non-private",
        action="store_true",
        help="Allow probing non-private hosts (lab edge cases only)",
    )
    parser.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="Allow plain HTTP to private lab hosts only (never certifying)",
    )
    parser.add_argument(
        "--expected-model",
        default="",
        help="Optional operator UI model hint (never RCI-proven)",
    )
    parser.add_argument(
        "--update-channel",
        default="",
        help="Optional operator UI update-channel hint (never RCI-proven)",
    )
    parser.add_argument(
        "--source-address",
        default="",
        help=(
            "Literal private local IPv4/IPv6 bind for SSH tunnel outbound TCP "
            "(overlapping-subnet labs; requires --ssh-tunnel)"
        ),
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

    if args.ssh_tunnel and not args.ssh_host_key_sha256.strip():
        print("--ssh-host-key-sha256 is required with --ssh-tunnel", file=sys.stderr)

        return 2

    ssh_host: str | None = None
    management_host_header: str | None = None

    if args.ssh_tunnel:
        preflight_code, ssh_host, management_host_header = _validate_ssh_tunnel_preflight(
            args.host,
            allow_non_private=args.allow_non_private,
        )
        if preflight_code != 0:
            return preflight_code
    else:
        guard = _validate_target(
            args.host,
            allow_non_private=args.allow_non_private,
            allow_insecure_http=args.allow_insecure_http,
        )

        if guard != 0:
            return guard

    source_guard, validated_source = _resolve_source_address(args.source_address)
    if source_guard != 0:
        return source_guard

    if validated_source is not None and not args.ssh_tunnel:
        print(
            "--source-address requires --ssh-tunnel with --ssh-host-key-sha256 "
            "(plain HTTP cannot bind outbound source address)",
            file=sys.stderr,
        )
        return 2

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

    from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
    from router_control.adapters.netcraze.identity import (
        COMPONENT_SET_DIGEST_ALGORITHM,
        OperatorIdentityHints,
    )
    from router_control.adapters.netcraze.ssh_tunnel import PinnedSshTunnel, SshTunnelConfig
    from router_control.adapters.netcraze.transport import (
        NetcrazeTransport,
        SshTunnelNetcrazeTransport,
        parse_transport_target,
    )
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault
    from router_control.domain.errors import IdentityMismatch
    from router_control.domain.ids import RouterId
    from router_control.ports.clock import SystemClock

    target = parse_transport_target(args.host)

    vault = WindowsDpapiVault(root=Path(args.secrets_root))

    password = vault.use(args.credential_ref)

    probe_host = target.hostname

    if args.ssh_tunnel:
        assert ssh_host is not None
        assert management_host_header is not None
        probe_host = ssh_host
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
                transport: NetcrazeTransport = SshTunnelNetcrazeTransport(
                    host=tunnel.local_host,
                    port=tunnel.local_port,
                    use_tls=False,
                    username=args.username,
                    password=password,
                    management_host_header=management_host_header,
                    ssh_host_key_algorithm=tunnel.host_key_algorithm,
                    ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
                    source_address=validated_source or "",
                )
                adapter = NetcrazeReadOnlyAdapter(
                    router_id=RouterId(f"router-{probe_host}"),
                    transport=transport,
                    clock=SystemClock(),
                    identity_hints=OperatorIdentityHints(
                        expected_model=args.expected_model or None,
                        update_channel=args.update_channel or None,
                    ),
                )
                evidence = adapter.probe_gate_a_evidence()
        except IdentityMismatch as exc:
            print(str(exc), file=sys.stderr)

            return 3

        except Exception as exc:
            print(f"Probe failed: {exc.__class__.__name__}", file=sys.stderr)

            return 4

        evidence.update(_source_bind_evidence(validated_source))
    else:
        transport = NetcrazeTransport(
            host=target.hostname,
            port=target.port,
            use_tls=target.use_tls,
            username=args.username,
            password=password,
        )

        adapter = NetcrazeReadOnlyAdapter(
            router_id=RouterId(f"router-{probe_host}"),
            transport=transport,
            clock=SystemClock(),
            identity_hints=OperatorIdentityHints(
                expected_model=args.expected_model or None,
                update_channel=args.update_channel or None,
            ),
        )

        try:
            evidence = adapter.probe_gate_a_evidence()

        except IdentityMismatch as exc:
            print(str(exc), file=sys.stderr)

            return 3

        except Exception as exc:
            print(f"Probe failed: {exc.__class__.__name__}", file=sys.stderr)

            return 4

    evidence["component_set_digest_algorithm"] = COMPONENT_SET_DIGEST_ALGORITHM

    artifact_path = (
        Path(args.artifact_out)
        if args.artifact_out
        else DEFAULT_ARTIFACT_DIR / f"gate-a-probe-{probe_host.replace(':', '_')}.json"
    )

    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    artifact_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")

    print(str(artifact_path))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
