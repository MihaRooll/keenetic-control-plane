"""NC-1812 extended AmneziaWG `wireguard asc` encoding probe — plan/validate only."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

REPO_ROOT = __import__("pathlib").Path(__file__).resolve().parents[1]

CONTRACT_ID = "nc1812-awg-asc-encoding-probe-offline-20260724"

GATE_A_MODEL = "NC-1812"
GATE_A_FIRMWARE = "5.01.C.1.0-0"
GATE_A_TRANSPORT = "ssh_tunnel"
GATE_A_SSH_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
LAB_SOURCE_ADDRESS = "192.168.2.10"
LAB_CREDENTIAL_REF_ID = "cred_db65665dd59f600bdd23544d85564c83"

DEFAULT_BASE_ASC_9 = "5 42 54 0 0 1 2 3 4"
DEFAULT_TRAILING = "0 0 10 11 12 13 14"

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

_EXECUTE_REFUSAL = (
    "live extended-ASC probing requires a bounded allowlist extension + "
    "explicit per-campaign T4 (deferred); this harness is plan-only"
)


def _reject_password_env() -> int:
    for name in PASSWORD_ENV_VARS:
        if os.environ.get(name):
            print(f"Refusing password environment variable: {name}", file=sys.stderr)
            return 2
    return 0


def _parse_int_tokens(
    label: str,
    text: str,
    *,
    expected: int,
    max_value: int = 4_294_967_295,
) -> list[int]:
    tokens = text.strip().split()
    if len(tokens) != expected:
        raise ValueError(f"{label} must contain exactly {expected} space-separated integers")
    values: list[int] = []
    for token in tokens:
        if not token.isdigit():
            raise ValueError(f"{label} token {token!r} is not a bounded non-negative integer")
        value = int(token)
        if value > max_value:
            raise ValueError(f"{label} token {token!r} is not a bounded non-negative integer")
        values.append(value)
    return values


def is_allowlisted_asc_args(asc_args: str) -> bool:
    from router_control.adapters.netcraze.allowlist import validate_asc_args

    try:
        validate_asc_args(asc_args)
    except ValueError:
        return False
    return True


def build_cli(wg_id: str, asc_args: str) -> str:
    return f"interface {wg_id} wireguard asc {asc_args}"


def _candidate(
    *,
    encoding: str,
    wg_id: str,
    asc_args: str,
    device_verified: bool | None = None,
    verification_status: str | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "encoding": encoding,
        "cli": build_cli(wg_id, asc_args),
        "allowlisted": is_allowlisted_asc_args(asc_args),
    }
    if device_verified is not None:
        entry["device_verified"] = device_verified
    if verification_status is not None:
        entry["verification_status"] = verification_status
    return entry


def _hex_token(value: int) -> str:
    if value == 0:
        return "0"
    return format(value, "x")


def enumerate_candidates(
    *,
    wg_id: str,
    base_asc_9: str,
    trailing: str,
) -> list[dict[str, Any]]:
    from router_control.adapters.netcraze.allowlist import validate_asc_args, validate_wireguard_id

    normalized_wg = validate_wireguard_id(wg_id)
    base = validate_asc_args(base_asc_9)
    trailing_values = _parse_int_tokens("trailing", trailing, expected=7)
    trailing_text = " ".join(str(value) for value in trailing_values)

    candidates: list[dict[str, Any]] = []

    candidates.append(
        _candidate(
            encoding="plain_int_9",
            wg_id=normalized_wg,
            asc_args=base,
            device_verified=True,
            verification_status="device_verified_asc9",
        )
    )

    plain_16 = f"{base} {trailing_text}"
    candidates.append(
        _candidate(
            encoding="plain_int_16",
            wg_id=normalized_wg,
            asc_args=plain_16,
            device_verified=False,
            verification_status="unsupported_pending_verification",
        )
    )

    s3, s4, i1, i2, i3, i4, i5 = trailing_values
    i_values = [i1, i2, i3, i4, i5]
    _unsupported = "unsupported_pending_verification"

    hex_i_bare = " ".join(_hex_token(value) for value in i_values)
    candidates.append(
        _candidate(
            encoding="hex_i_bare",
            wg_id=normalized_wg,
            asc_args=f"{base} {s3} {s4} {hex_i_bare}",
            verification_status=_unsupported,
        )
    )

    hex_i_0x = " ".join(f"0x{_hex_token(value)}" for value in i_values)
    candidates.append(
        _candidate(
            encoding="hex_i_0x",
            wg_id=normalized_wg,
            asc_args=f"{base} {s3} {s4} {hex_i_0x}",
            verification_status=_unsupported,
        )
    )

    hex_trailing_bare = " ".join(_hex_token(value) for value in trailing_values)
    candidates.append(
        _candidate(
            encoding="hex_trailing_bare",
            wg_id=normalized_wg,
            asc_args=f"{base} {hex_trailing_bare}",
            verification_status=_unsupported,
        )
    )

    hex_trailing_0x = " ".join(f"0x{_hex_token(value)}" for value in trailing_values)
    candidates.append(
        _candidate(
            encoding="hex_trailing_0x",
            wg_id=normalized_wg,
            asc_args=f"{base} {hex_trailing_0x}",
            verification_status=_unsupported,
        )
    )

    candidates.append(
        _candidate(
            encoding="cps_i_comma",
            wg_id=normalized_wg,
            asc_args=f"{base} {s3} {s4} {','.join(str(value) for value in i_values)}",
            verification_status=_unsupported,
        )
    )

    candidates.append(
        _candidate(
            encoding="cps_i_colon",
            wg_id=normalized_wg,
            asc_args=f"{base} {s3} {s4} {':'.join(str(value) for value in i_values)}",
            verification_status=_unsupported,
        )
    )

    candidates.append(
        _candidate(
            encoding="cps_trailing_comma",
            wg_id=normalized_wg,
            asc_args=f"{base} {','.join(str(value) for value in trailing_values)}",
            verification_status=_unsupported,
        )
    )

    candidates.append(
        _candidate(
            encoding="cps_trailing_colon",
            wg_id=normalized_wg,
            asc_args=f"{base} {':'.join(str(value) for value in trailing_values)}",
            verification_status=_unsupported,
        )
    )

    return candidates


def build_plan_payload(
    *,
    wg_id: str,
    base_asc_9: str,
    trailing: str,
) -> dict[str, Any]:
    return {
        "contract_id": CONTRACT_ID,
        "mode": "plan-only",
        "mutation_allowed": False,
        "write_shapes_registered": False,
        "certification_eligible": False,
        "gate_a_tuple": {
            "model": GATE_A_MODEL,
            "firmware_version": GATE_A_FIRMWARE,
            "transport": GATE_A_TRANSPORT,
            "ssh_host_key_fingerprint_sha256": GATE_A_SSH_PIN,
        },
        "source_address": LAB_SOURCE_ADDRESS,
        "credential_ref": LAB_CREDENTIAL_REF_ID,
        "wg_id": wg_id,
        "base_asc_9": base_asc_9.strip(),
        "trailing": trailing.strip(),
        "candidates": enumerate_candidates(
            wg_id=wg_id,
            base_asc_9=base_asc_9,
            trailing=trailing,
        ),
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Enumerate extended AmneziaWG wireguard asc encoding candidates "
            "(plan-only; no live execution)."
        )
    )
    parser.add_argument(
        "--wg-id",
        default="Wireguard5",
        help="Allowlisted throwaway interface id (Wireguard5–9)",
    )
    parser.add_argument(
        "--base-asc",
        default=DEFAULT_BASE_ASC_9,
        help="Nine space-separated asc integers (jc jmin jmax s1 s2 h1 h2 h3 h4)",
    )
    parser.add_argument(
        "--trailing",
        default=DEFAULT_TRAILING,
        help="Seven space-separated trailing integers (s3 s4 i1 i2 i3 i4 i5)",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Refused — live extended-ASC probing is deferred pending T4 + allowlist extension",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    if args.execute:
        print(_EXECUTE_REFUSAL, file=sys.stderr)
        return 2

    guard = _reject_password_env()
    if guard != 0:
        return guard

    try:
        plan = build_plan_payload(
            wg_id=args.wg_id,
            base_asc_9=args.base_asc,
            trailing=args.trailing,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(json.dumps(plan, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
