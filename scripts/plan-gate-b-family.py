"""Offline Gate B per-family certification planner CLI — plan/validate/export only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

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
        "dispatch",
        "execute",
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

RAW_COMMAND_FLAGS = frozenset({"--raw-rci", "--command", "--password"})
SECRET_ATTACH_PREFIXES = ("--password=", "--secret=", "--token=")
RAW_COMMAND_ATTACH_PREFIXES = ("--raw-rci=", "--command=")


def _reject_password_env() -> int:
    for name in PASSWORD_ENV_VARS:
        if os.environ.get(name):
            print(f"Refusing password environment variable: {name}", file=sys.stderr)
            return 2
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline Gate B per-family certification planner (no dispatch)."
    )
    parser.add_argument(
        "--family",
        required=True,
        help="Capability family (fail_safe,vlan,dhcp,dns,wifi,firewall,amneziawg,routes)",
    )
    parser.add_argument(
        "--manifest",
        default="",
        help="Optional evidence manifest JSON path to validate",
    )
    parser.add_argument(
        "--catalog",
        default=str(REPO_ROOT / "docs" / "netcraze-source-catalog.json"),
        help="Read discovery source catalog path",
    )
    parser.add_argument(
        "--fixture-id",
        default="",
        help="Optional fixture id for replay planning",
    )
    parser.add_argument(
        "--export",
        default="",
        help="Write sanitized campaign packet JSON to path",
    )
    parser.add_argument(
        "extra",
        nargs="*",
        help=argparse.SUPPRESS,
    )
    return parser


def _current_utc() -> datetime:
    return datetime.now(UTC)


def main() -> int:
    for arg in sys.argv[1:]:
        lowered = arg.lower()
        for prefix in SECRET_ATTACH_PREFIXES + RAW_COMMAND_ATTACH_PREFIXES:
            if lowered.startswith(prefix):
                print(f"Refusing raw command flag: {arg}", file=sys.stderr)
                return 2

    for flag in RAW_COMMAND_FLAGS:
        if flag in sys.argv:
            print(f"Refusing raw command flag: {flag}", file=sys.stderr)
            return 2

    parser = _build_parser()
    args = parser.parse_args()

    for token in args.extra:
        lowered = token.lower()
        if lowered in MUTATION_COMMANDS:
            print(f"Refusing mutation-like command: {token}", file=sys.stderr)
            return 2
        if token.startswith("/rci/"):
            print(f"Refusing raw RCI path argument: {token}", file=sys.stderr)
            return 2

    guard = _reject_password_env()
    if guard != 0:
        return guard

    from router_control.adapters.netcraze.capability_families import (
        parse_capability_family,
    )
    from router_control.adapters.netcraze.certification_framework import (
        CertificationPlanner,
        CertificationRunner,
    )
    from router_control.adapters.netcraze.evidence_manifest import (
        EvidenceManifestError,
        load_evidence_manifest,
    )
    from router_control.adapters.netcraze.read_discovery import (
        ShapeRegistryError,
        load_read_discovery_catalog,
    )
    from router_control.adapters.netcraze.sanitize import sanitize_mapping

    try:
        family = parse_capability_family(args.family)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    manifest = None
    if args.manifest:
        try:
            manifest = load_evidence_manifest(Path(args.manifest), now=_current_utc())
            if manifest.capability_family != family:
                print("manifest capability_family mismatch", file=sys.stderr)
                return 3
        except EvidenceManifestError as exc:
            print(str(exc), file=sys.stderr)
            return 3

    try:
        catalog = load_read_discovery_catalog(Path(args.catalog))
    except ShapeRegistryError as exc:
        print(str(exc), file=sys.stderr)
        return 3

    planner = CertificationPlanner()
    tuple_binding = None

    if args.fixture_id:
        runner = CertificationRunner(
            planner=planner,
            fixtures={
                "lab-default": {
                    "tuple_binding": {
                        "model": "NC-1812",
                        "firmware_version": "5.01.C.1.0-0",
                        "ndm_build": "0-b592e619a0",
                        "bsp_build": "0-f371d30955",
                        "update_channel": "Main",
                        "region": "EA",
                        "component_set_digest": (
                            "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
                        ),
                        "device_fingerprint_digest": (
                            "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
                        ),
                        "transport": "ssh_tunnel",
                        "ssh_host_key_algorithm": "ssh-ed25519",
                    },
                    "probe_evidence": {
                        "model": "NC-1812",
                        "firmware_version": "5.01.C.1.0-0",
                        "build": "0-b592e619a0",
                        "bsp_build": "0-f371d30955",
                        "update_channel": "Main",
                        "region": "EA",
                        "component_set_digest": (
                            "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
                        ),
                        "device_fingerprint": (
                            "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
                        ),
                        "transport_security": "ssh_tunnel",
                        "ssh_host_key_algorithm": "ssh-ed25519",
                    },
                }
            },
        )
        packet = runner.plan_from_fixtures(family, fixture_id=args.fixture_id, now=_current_utc())
    else:
        if manifest is not None:
            tuple_binding = manifest.tuple_binding
        packet = planner.plan(
            family,
            tuple_binding=tuple_binding,
            manifest=manifest,
            now=_current_utc(),
        )

    packet["source_catalog"] = {
        "catalog_id": catalog.catalog_id,
        "family_candidates": len(catalog.for_family(family)),
    }
    packet["dispatch_permitted"] = False

    sanitized = sanitize_mapping(packet)
    output = json.dumps(sanitized, indent=2) + "\n"

    if args.export:
        export_path = Path(args.export)
        export_path.parent.mkdir(parents=True, exist_ok=True)
        export_path.write_text(output, encoding="utf-8")
        print(str(export_path))
    else:
        print(output, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
