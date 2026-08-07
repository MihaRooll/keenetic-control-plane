"""NC-1812 read-only AmneziaWG/WireGuard RCI write-shape discovery — validate default."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SECRETS_ROOT = REPO_ROOT / "data" / "secrets"
DEFAULT_ARTIFACT_DIR = REPO_ROOT / "data" / "artifacts"

CONTRACT_ID = "nc1812-awg-ro-discovery-probe-20260723"

GATE_A_MODEL = "NC-1812"
GATE_A_FIRMWARE = "5.01.C.1.0-0"
GATE_A_TRANSPORT = "ssh_tunnel"
GATE_A_SSH_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
LAB_SOURCE_ADDRESS = "192.168.2.10"

RO_PARSE_PREFIXES = frozenset({"show", "help"})

RO_PARSE_COMMANDS: tuple[str, ...] = (
    "help interface",
    "help wireguard",
    "help AmneziaWG",
    "show interface",
)

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

_AWG_SECRET_KEY_FRAGMENTS = frozenset(
    {
        "privatekey",
        "private_key",
        "presharedkey",
        "preshared_key",
    }
)


def is_ro_parse_command(command: str) -> bool:
    """Return True when the first CLI token is an allowed read-only parse verb."""
    tokens = command.strip().split()
    if not tokens:
        return False
    return tokens[0].lower() in RO_PARSE_PREFIXES


def _assert_ro_command_set() -> None:
    for command in RO_PARSE_COMMANDS:
        if not is_ro_parse_command(command):
            raise ValueError(f"planned command is not read-only: {command}")


def build_planned_commands() -> list[dict[str, str]]:
    """Fixed RO discovery command list shared by validate plan and live probe."""
    from router_control.adapters.netcraze.allowlist import SHOW_INTERFACE

    _assert_ro_command_set()
    planned: list[dict[str, str]] = [
        {"kind": "parse", "command": command} for command in RO_PARSE_COMMANDS
    ]
    planned.append(
        {
            "kind": "discovery_read",
            "name": SHOW_INTERFACE.name,
            "method": SHOW_INTERFACE.method.value,
            "path": SHOW_INTERFACE.path,
        }
    )
    return planned


def gate_a_tuple_binding(*, ssh_pin: str = GATE_A_SSH_PIN) -> dict[str, str]:
    return {
        "model": GATE_A_MODEL,
        "firmware_version": GATE_A_FIRMWARE,
        "transport": GATE_A_TRANSPORT,
        "ssh_host_key_fingerprint_sha256": ssh_pin,
    }


def build_validate_plan(
    *, host: str = "", source_address: str = LAB_SOURCE_ADDRESS
) -> dict[str, Any]:
    return {
        "mode": "validate",
        "contract_id": CONTRACT_ID,
        "host": host.strip() or None,
        "source_address": source_address,
        "mutation_allowed": False,
        "mutation_performed": False,
        "write_shapes_registered": False,
        "certification_eligible": False,
        "gate_a_tuple": gate_a_tuple_binding(),
        "commands_planned": build_planned_commands(),
    }


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


def _validate_ssh_tunnel_preflight(host: str, *, allow_non_private: bool) -> tuple[int, str]:
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
            print("--source-address is required for live AWG discovery", file=sys.stderr)
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
    if bound != LAB_SOURCE_ADDRESS:
        print(
            f"source_address must be {LAB_SOURCE_ADDRESS} for NC-1812 lab discovery",
            file=sys.stderr,
        )
        return 2, None
    return 0, bound


def _reject_password_env() -> int:
    for name in PASSWORD_ENV_VARS:
        if os.environ.get(name):
            print(f"Refusing password environment variable: {name}", file=sys.stderr)
            return 2
    return 0


def _normalize_ssh_pin(raw: str) -> str:
    from router_control.adapters.netcraze.ssh_tunnel import normalize_sha256_fingerprint

    return normalize_sha256_fingerprint(raw.strip())


def _validate_gate_a_pin(raw_pin: str) -> int:
    if not raw_pin.strip():
        return 0
    try:
        cli_pin = _normalize_ssh_pin(raw_pin)
        gate_pin = _normalize_ssh_pin(GATE_A_SSH_PIN)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if cli_pin != gate_pin:
        print("SSH host-key pin mismatches Gate A certification", file=sys.stderr)
        return 3
    return 0


def _artifact_host_slug(host: str) -> str:
    candidate = host.strip()
    if "://" in candidate:
        from urllib.parse import urlparse

        parsed = urlparse(candidate)
        candidate = parsed.hostname or candidate
    return candidate.replace(":", "-")


def default_artifact_path(host: str) -> Path:
    date_stamp = datetime.now(UTC).strftime("%Y%m%d")
    return DEFAULT_ARTIFACT_DIR / f"awg-shape-{_artifact_host_slug(host)}-{date_stamp}.json"


def _redact_awg_secrets(value: Any) -> Any:
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for key, item in value.items():
            normalized = key.strip().lower().replace("-", "_")
            if normalized in _AWG_SECRET_KEY_FRAGMENTS:
                sanitized[key] = "REDACTED"
            else:
                sanitized[key] = _redact_awg_secrets(item)
        return sanitized
    if isinstance(value, list):
        return [_redact_awg_secrets(item) for item in value]
    return value


def _sanitize_discovery_item(item: object) -> Any:
    from router_control.adapters.netcraze.sanitize import sanitize_mapping, sanitize_value

    redacted = _redact_awg_secrets(item)
    if isinstance(redacted, dict):
        return sanitize_mapping(redacted)
    if isinstance(redacted, list):
        return sanitize_value(redacted)
    return redacted


def sanitize_discovery_response(payload: object) -> dict[str, Any]:
    """Sanitize a live discovery payload; never persist raw secrets."""
    from router_control.adapters.netcraze.sanitize import (
        describe_list_structure,
        describe_structure,
        sanitize_mapping,
    )

    if isinstance(payload, dict):
        cleaned = sanitize_mapping(_redact_awg_secrets(payload))
        try:
            structure = describe_structure(cleaned)
        except ValueError:
            structure = {"top_type": "object", "note": "structure_unavailable"}
        return {"sanitized": cleaned, "structure": structure}
    if isinstance(payload, list):
        cleaned_list = [_sanitize_discovery_item(item) for item in payload]
        try:
            structure = describe_list_structure(cleaned_list)
        except ValueError:
            structure = {"top_type": "array", "note": "structure_unavailable"}
        return {"sanitized": cleaned_list, "structure": structure}
    return {"top_type": type(payload).__name__}


def build_live_artifact(
    *,
    host: str,
    source_address: str,
    credential_ref: str,
    ssh_pin: str,
    commands_issued: list[dict[str, str]],
    responses: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "contract_id": CONTRACT_ID,
        "host": _artifact_host_slug(host),
        "captured_at": datetime.now(UTC).date().isoformat(),
        "gate_a_tuple": gate_a_tuple_binding(ssh_pin=ssh_pin),
        "source_address": source_address,
        "credential_ref": credential_ref,
        "mutation_performed": False,
        "mutation_allowed": False,
        "write_shapes_registered": False,
        "certification_eligible": False,
        "commands_issued": commands_issued,
        "responses": responses,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="NC-1812 read-only AWG/WireGuard RCI write-shape discovery (validate default)."
    )
    parser.add_argument("--host", default="", help="Router management SSH host")
    parser.add_argument("--credential-ref", default="", help="DPAPI credential ref id")
    parser.add_argument("--username", default="", help="RCI auth username (not password)")
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
        default=LAB_SOURCE_ADDRESS,
        help=f"Literal private local IPv4/IPv6 bind ({LAB_SOURCE_ADDRESS} for lab)",
    )
    parser.add_argument(
        "--artifact-out",
        default="",
        help="Sanitized AWG discovery artifact JSON path",
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
        help="Live read-only discovery (requires DPAPI, pin, source bind)",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    return parser


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
    if missing:
        print("Live-probe requires: " + ", ".join(missing), file=sys.stderr)
        return 2
    return 0


def _run_live_probe(args: argparse.Namespace) -> int:
    if sys.platform != "win32":
        print("Live-probe mode requires win32 with WindowsDpapiVault", file=sys.stderr)
        return 2

    field_guard = _require_live_probe_fields(args)
    if field_guard != 0:
        return field_guard

    pin_guard = _validate_gate_a_pin(args.ssh_host_key_sha256)
    if pin_guard != 0:
        return pin_guard

    preflight_code, _ssh_host = _validate_ssh_tunnel_preflight(
        args.host,
        allow_non_private=args.allow_non_private,
    )
    if preflight_code != 0:
        return preflight_code

    source_guard, validated_source = _resolve_source_address(args.source_address, required=True)
    if source_guard != 0 or validated_source is None:
        return source_guard or 2

    from router_control.adapters.netcraze.allowlist import SHOW_INTERFACE
    from router_control.adapters.netcraze.rci_live import open_pinned_rci_transport
    from router_control.adapters.netcraze.ssh_tunnel import (
        SshSourceAddressBindError,
        preflight_source_address_bind,
    )
    from router_control.adapters.secrets.dpapi import WindowsDpapiVault

    try:
        preflight_source_address_bind(validated_source)
    except SshSourceAddressBindError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    vault = WindowsDpapiVault(root=Path(args.secrets_root))
    password = vault.use(args.credential_ref)

    planned = build_planned_commands()
    responses: list[dict[str, Any]] = []

    try:
        with open_pinned_rci_transport(
            host=args.host,
            username=args.username,
            password=password,
            host_key_sha256=args.ssh_host_key_sha256,
            source_address=validated_source,
            allow_non_private=args.allow_non_private,
        ) as transport:
            for entry in planned:
                if entry["kind"] == "parse":
                    command = entry["command"]
                    if not is_ro_parse_command(command):
                        print(f"Refusing non-read-only parse command: {command}", file=sys.stderr)
                        return 2
                    raw = transport.execute_rci_parse(command)
                    responses.append(
                        {
                            "kind": "parse",
                            "command": command,
                            "response": sanitize_discovery_response(raw),
                        }
                    )
                elif entry["kind"] == "discovery_read":
                    raw = transport.fetch_discovery_read(SHOW_INTERFACE)
                    responses.append(
                        {
                            "kind": "discovery_read",
                            "path": SHOW_INTERFACE.path,
                            "method": SHOW_INTERFACE.method.value,
                            "response": sanitize_discovery_response(raw),
                        }
                    )
    except Exception as exc:  # noqa: BLE001 - operator tool surface
        print(f"AWG discovery probe failed: {exc.__class__.__name__}", file=sys.stderr)
        return 4

    artifact = build_live_artifact(
        host=args.host,
        source_address=validated_source,
        credential_ref=args.credential_ref.strip(),
        ssh_pin=_normalize_ssh_pin(args.ssh_host_key_sha256),
        commands_issued=planned,
        responses=responses,
    )
    artifact_path = (
        Path(args.artifact_out) if args.artifact_out.strip() else default_artifact_path(args.host)
    )
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_path.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(str(artifact_path))
    return 0


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

    live_probe = bool(args.live_probe)

    if live_probe:
        return _run_live_probe(args)

    source_guard, validated_source = _resolve_source_address(
        args.source_address,
        required=False,
    )
    if source_guard != 0:
        return source_guard

    try:
        build_planned_commands()
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    plan = build_validate_plan(
        host=args.host,
        source_address=validated_source or LAB_SOURCE_ADDRESS,
    )
    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
