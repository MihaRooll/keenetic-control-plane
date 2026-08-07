"""NC-1812 topology discovery probe — non-certifying GET /rci/show/interface."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"
DEFAULT_ARTIFACT_DIR = REPO_ROOT / "data" / "artifacts"
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures" / "netcraze"

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


def _resolve_source_address(raw: str, *, required: bool) -> tuple[int, str | None]:
    if not raw.strip():
        if required:
            print("--source-address is required for live topology probe", file=sys.stderr)
            return 2, None
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NC-1812 topology discovery probe (non-certifying, source-bound)."
    )
    parser.add_argument("--host", default="", help="Router management SSH host")
    parser.add_argument("--credential-ref", default="", help="DPAPI credential ref id")
    parser.add_argument("--username", default="", help="RCI auth username (not password)")
    parser.add_argument(
        "--ssh-host-key-sha256",
        "--pin",
        dest="ssh_host_key_sha256",
        default="",
        help="Pinned SSH host key SHA256 fingerprint (required for live)",
    )
    parser.add_argument(
        "--source-address",
        required=False,
        default="",
        help="Literal private local IPv4/IPv6 bind (required for live)",
    )
    parser.add_argument(
        "--artifact-out",
        default="",
        help="Sanitized topology artifact JSON path",
    )
    parser.add_argument(
        "--shape-out",
        default="",
        help="Optional structural fingerprint JSON path on TopologyProbeError",
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
        "--secrets-root",
        default=str(DEFAULT_SECRETS_ROOT),
        help="DPAPI vault root (live only)",
    )
    parser.add_argument(
        "--allow-non-private",
        action="store_true",
        help="Allow non-private SSH host (lab edge cases only)",
    )
    parser.add_argument(
        "--fixture",
        default="",
        help="Offline fixture basename under tests/fixtures/netcraze/ (network-free)",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    return parser


def _load_gate_a_aligned(
    *,
    gate_a_config: Path,
    gate_a_evidence: Path,
    status_path: Path,
    ssh_pin: str,
) -> tuple[object, dict[str, object]]:
    from router_control.adapters.netcraze.certification import (
        GateACertificationError,
        load_gate_a_certification,
    )
    from router_control.adapters.netcraze.ssh_tunnel import normalize_sha256_fingerprint

    gate_a = load_gate_a_certification(
        config_path=gate_a_config,
        evidence_path=gate_a_evidence,
        status_path=status_path,
        now=datetime.now(UTC),
    )
    if not gate_a.is_open:
        raise GateACertificationError("Gate A is not open for aligned topology probe")
    evidence = json.loads(gate_a_evidence.read_text(encoding="utf-8"))
    if not isinstance(evidence, dict):
        raise GateACertificationError("Gate A evidence must be an object")
    if not gate_a.matches_probe_evidence(evidence):
        raise GateACertificationError("Gate A evidence tuple mismatch")
    if ssh_pin.strip():
        cli_pin = normalize_sha256_fingerprint(ssh_pin.strip())
        gate_pin = normalize_sha256_fingerprint(gate_a.ssh_host_key_fingerprint_sha256)
        if cli_pin != gate_pin:
            raise GateACertificationError("SSH host-key pin mismatches Gate A certification")
    return gate_a, evidence


def _write_shape_artifact(path: Path, artifact: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")


def _fixture_shape_artifact(
    *,
    fixture_name: str,
    parser_error: object,
    source_address: str,
) -> dict[str, object]:
    from router_control.adapters.netcraze.ssh_tunnel import (
        source_address_class,
        validate_source_address,
    )
    from router_control.adapters.netcraze.topology_probe import (
        build_topology_shape_artifact,
        digest_evidence_record,
        digest_gate_a_tuple,
    )

    fixture_path = FIXTURES_DIR / fixture_name
    raw_bytes = fixture_path.read_bytes()
    payload = json.loads(raw_bytes.decode("utf-8"))
    validated_source = validate_source_address(source_address or "192.168.2.10")
    return build_topology_shape_artifact(
        payload=payload,
        raw_bytes=raw_bytes,
        parser_error=parser_error,  # type: ignore[arg-type]
        source_address=validated_source,
        source_address_class=source_address_class(validated_source),
        gate_a_tuple_digest=digest_gate_a_tuple(
            model="NC-1812",
            firmware_version="fixture",
            ndm_build="fixture",
            component_set_digest="sha256:" + "0" * 64,
            device_fingerprint_digest="sha256:" + "1" * 64,
        ),
        gate_a_evidence_digest=digest_evidence_record({"fixture": fixture_name}),
        transport_security="fixture",
        https_check="fixture",
        ssh_host_key_algorithm="fixture",
        ssh_host_key_fingerprint_sha256="SHA256:fixture",
    )


def _run_fixture(
    *,
    fixture_name: str,
    artifact_out: Path,
    source_address: str,
) -> dict[str, object]:
    from router_control.adapters.netcraze.ssh_tunnel import (
        source_address_class,
        validate_source_address,
    )
    from router_control.adapters.netcraze.topology_probe import (
        build_topology_artifact,
        digest_evidence_record,
        digest_gate_a_tuple,
    )

    fixture_path = FIXTURES_DIR / fixture_name
    if not fixture_path.is_file():
        raise FileNotFoundError(f"fixture not found: {fixture_path}")
    raw_bytes = fixture_path.read_bytes()
    payload = json.loads(raw_bytes.decode("utf-8"))
    validated_source = validate_source_address(source_address or "192.168.2.10")
    artifact = build_topology_artifact(
        payload=payload,
        raw_bytes=raw_bytes,
        source_address=validated_source,
        source_address_class=source_address_class(validated_source),
        gate_a_tuple_digest=digest_gate_a_tuple(
            model="NC-1812",
            firmware_version="fixture",
            ndm_build="fixture",
            component_set_digest="sha256:" + "0" * 64,
            device_fingerprint_digest="sha256:" + "1" * 64,
        ),
        gate_a_evidence_digest=digest_evidence_record({"fixture": fixture_name}),
        transport_security="fixture",
        https_check="fixture",
        ssh_host_key_algorithm="fixture",
        ssh_host_key_fingerprint_sha256="SHA256:fixture",
    )
    artifact_out.parent.mkdir(parents=True, exist_ok=True)
    artifact_out.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    return artifact


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    for token in args.extra:
        if token.lower() in MUTATION_COMMANDS:
            print(f"Refusing mutation-like command: {token}", file=sys.stderr)
            return 2

    fixture_mode = bool(args.fixture.strip())
    if fixture_mode:
        if not args.artifact_out.strip():
            print("--artifact-out is required with --fixture", file=sys.stderr)
            return 2
        fixture_name = args.fixture.strip()
        if not fixture_name.endswith(".json"):
            fixture_name = f"{fixture_name}.json"
        from router_control.adapters.netcraze.topology_probe import TopologyProbeError

        try:
            _run_fixture(
                fixture_name=fixture_name,
                artifact_out=Path(args.artifact_out),
                source_address=args.source_address.strip() or "192.168.2.10",
            )
        except TopologyProbeError as exc:
            shape_path = args.shape_out.strip()
            if shape_path:
                shape_artifact = _fixture_shape_artifact(
                    fixture_name=fixture_name,
                    parser_error=exc,
                    source_address=args.source_address.strip() or "192.168.2.10",
                )
                _write_shape_artifact(Path(shape_path), shape_artifact)
            print(str(exc), file=sys.stderr)
            return 4
        except (FileNotFoundError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"Fixture probe failed: {exc.__class__.__name__}", file=sys.stderr)
            return 4
        print(args.artifact_out)
        return 0

    missing = []
    if not args.host.strip():
        missing.append("--host")
    if not args.credential_ref.strip():
        missing.append("--credential-ref")
    if not args.username.strip():
        missing.append("--username")
    if not args.ssh_host_key_sha256.strip():
        missing.append("--ssh-host-key-sha256")
    if not args.source_address.strip():
        missing.append("--source-address")
    if not args.artifact_out.strip():
        missing.append("--artifact-out")
    if missing:
        print("Live topology probe requires: " + ", ".join(missing), file=sys.stderr)
        return 2

    preflight_code, ssh_host, management_header = _validate_ssh_tunnel_preflight(
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
        source_address_class,
    )

    try:
        preflight_source_address_bind(validated_source)
    except SshSourceAddressBindError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    if sys.platform != "win32":
        print("DPAPI credential resolution requires win32", file=sys.stderr)
        return 2

    from router_control.adapters.netcraze.allowlist import SHOW_INTERFACE
    from router_control.adapters.netcraze.certification import GateACertificationError
    from router_control.adapters.netcraze.ssh_tunnel import PinnedSshTunnel, SshTunnelConfig
    from router_control.adapters.netcraze.topology_probe import (
        TopologyProbeError,
        build_topology_artifact,
        build_topology_shape_artifact,
        digest_evidence_record,
        digest_gate_a_tuple,
    )
    from router_control.adapters.netcraze.transport import SshTunnelNetcrazeTransport
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    try:
        gate_a, probe_evidence = _load_gate_a_aligned(
            gate_a_config=Path(args.gate_a_config),
            gate_a_evidence=Path(args.gate_a_evidence),
            status_path=Path(args.status_path),
            ssh_pin=args.ssh_host_key_sha256,
        )
    except GateACertificationError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    vault = WindowsDpapiVault(root=Path(args.secrets_root))
    password = vault.use(args.credential_ref)

    tuple_digest = digest_gate_a_tuple(
        model=gate_a.model,
        firmware_version=gate_a.firmware_version,
        ndm_build=gate_a.ndm_build,
        component_set_digest=gate_a.component_set_digest,
        device_fingerprint_digest=gate_a.device_fingerprint_digest,
    )
    evidence_digest = digest_evidence_record(probe_evidence)

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
            transport = SshTunnelNetcrazeTransport(
                host=tunnel.local_host,
                port=tunnel.local_port,
                use_tls=False,
                username=args.username,
                password=password,
                management_host_header=management_header,
                ssh_host_key_algorithm=tunnel.host_key_algorithm,
                ssh_host_key_fingerprint_sha256=tunnel.host_key_fingerprint_sha256,
                source_address=validated_source,
            )
            payload = transport.fetch_discovery_read(SHOW_INTERFACE)
            raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
            artifact = build_topology_artifact(
                payload=payload,
                raw_bytes=raw_bytes,
                source_address=validated_source,
                source_address_class=source_address_class(validated_source),
                gate_a_tuple_digest=tuple_digest,
                gate_a_evidence_digest=evidence_digest,
                transport_security=transport.transport_security_label,
                https_check=transport.https_check_label,
                ssh_host_key_algorithm=transport.ssh_host_key_algorithm,
                ssh_host_key_fingerprint_sha256=transport.ssh_host_key_fingerprint_sha256,
            )
    except TopologyProbeError as exc:
        shape_path = args.shape_out.strip()
        if shape_path:
            shape_artifact = build_topology_shape_artifact(
                payload=payload,
                raw_bytes=raw_bytes,
                parser_error=exc,
                source_address=validated_source,
                source_address_class=source_address_class(validated_source),
                gate_a_tuple_digest=tuple_digest,
                gate_a_evidence_digest=evidence_digest,
                transport_security=transport.transport_security_label,
                https_check=transport.https_check_label,
                ssh_host_key_algorithm=transport.ssh_host_key_algorithm,
                ssh_host_key_fingerprint_sha256=transport.ssh_host_key_fingerprint_sha256,
            )
            _write_shape_artifact(Path(shape_path), shape_artifact)
        print(str(exc), file=sys.stderr)
        return 4
    except Exception as exc:
        print(f"Topology probe failed: {exc.__class__.__name__}", file=sys.stderr)
        return 4

    artifact_path = Path(args.artifact_out)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(str(artifact_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
