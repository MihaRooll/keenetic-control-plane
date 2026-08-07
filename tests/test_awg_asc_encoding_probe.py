"""Offline tests for probe-nc1812-awg-asc-encoding candidate generator."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest
from router_control.adapters.netcraze.allowlist import validate_wireguard_id

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-awg-asc-encoding.py"

_ASC_9 = "5 42 54 0 0 1 2 3 4"
_ASC_16 = "5 42 54 0 0 1 2 3 4 0 0 0 0 0 0 0"
GATE_A_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
LAB_CREDENTIAL_REF = "cred_db65665dd59f600bdd23544d85564c83"


def _load_module():
    spec = importlib.util.spec_from_file_location("probe_nc1812_awg_asc_encoding_cli", CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli_module():
    return _load_module()


def test_plain_int_9_is_allowlisted(cli_module) -> None:
    candidates = cli_module.enumerate_candidates(
        wg_id="Wireguard5",
        base_asc_9=_ASC_9,
        trailing="0 0 0 0 0 0 0",
    )
    plain_9 = next(entry for entry in candidates if entry["encoding"] == "plain_int_9")
    assert plain_9["allowlisted"] is True
    assert plain_9["device_verified"] is True
    assert plain_9["verification_status"] == "device_verified_asc9"
    assert plain_9["cli"] == f"interface Wireguard5 wireguard asc {_ASC_9}"


def test_plain_int_16_generated_and_not_device_verified(cli_module) -> None:
    candidates = cli_module.enumerate_candidates(
        wg_id="Wireguard5",
        base_asc_9=_ASC_9,
        trailing="0 0 0 0 0 0 0",
    )
    plain_16 = next(entry for entry in candidates if entry["encoding"] == "plain_int_16")
    assert plain_16["allowlisted"] is True
    assert plain_16["device_verified"] is False
    assert plain_16["verification_status"] == "unsupported_pending_verification"
    assert plain_16["cli"] == f"interface Wireguard5 wireguard asc {_ASC_16}"


@pytest.mark.parametrize(
    "encoding",
    [
        "hex_i_bare",
        "hex_i_0x",
        "hex_trailing_bare",
        "hex_trailing_0x",
        "cps_i_comma",
        "cps_i_colon",
        "cps_trailing_comma",
        "cps_trailing_colon",
    ],
)
def test_hex_and_cps_candidates_not_allowlisted(cli_module, encoding: str) -> None:
    candidates = cli_module.enumerate_candidates(
        wg_id="Wireguard5",
        base_asc_9=_ASC_9,
        trailing="0 0 10 11 12 13 14",
    )
    entry = next(item for item in candidates if item["encoding"] == encoding)
    assert entry["allowlisted"] is False
    assert entry["verification_status"] == "unsupported_pending_verification"


@pytest.mark.parametrize(
    "encoding",
    [
        "hex_i_bare",
        "hex_trailing_bare",
    ],
)
def test_default_trailing_hex_bare_not_allowlisted_and_distinct_from_plain16(
    cli_module, encoding: str
) -> None:
    plan = cli_module.build_plan_payload(
        wg_id="Wireguard5",
        base_asc_9=_ASC_9,
        trailing=cli_module.DEFAULT_TRAILING,
    )
    assert plan["trailing"] == cli_module.DEFAULT_TRAILING
    plain_16 = next(
        entry for entry in plan["candidates"] if entry["encoding"] == "plain_int_16"
    )
    entry = next(item for item in plan["candidates"] if item["encoding"] == encoding)
    assert entry["allowlisted"] is False
    assert entry["verification_status"] == "unsupported_pending_verification"
    assert entry["cli"] != plain_16["cli"]


@pytest.mark.parametrize(
    "wg_id",
    ["Wireguard0", "Wireguard1", "Wireguard2", "Wireguard3", "Wireguard4"],
)
def test_rejects_wireguard0_through_4(cli_module, wg_id: str) -> None:
    with pytest.raises(ValueError, match="allowlisted test interface"):
        cli_module.enumerate_candidates(
            wg_id=wg_id,
            base_asc_9=_ASC_9,
            trailing="0 0 0 0 0 0 0",
        )


def test_validate_wireguard_id_accepts_throwaway_range() -> None:
    for index in range(5, 10):
        assert validate_wireguard_id(f"Wireguard{index}") == f"Wireguard{index}"


def test_execute_flag_refuses(cli_module) -> None:
    argv = ["probe-nc1812-awg-asc-encoding.py", "--execute"]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "plan-only" in stderr.getvalue()
    assert "T4" in stderr.getvalue()


def test_plan_only_default_exits_zero_and_includes_gate_a_tuple(cli_module) -> None:
    stdout = StringIO()
    argv = ["probe-nc1812-awg-asc-encoding.py"]
    with patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout):
        assert cli_module.main() == 0
    plan = json.loads(stdout.getvalue())
    assert plan["mode"] == "plan-only"
    assert plan["mutation_allowed"] is False
    assert plan["write_shapes_registered"] is False
    assert plan["certification_eligible"] is False
    assert plan["gate_a_tuple"]["model"] == "NC-1812"
    assert plan["gate_a_tuple"]["firmware_version"] == "5.01.C.1.0-0"
    assert plan["gate_a_tuple"]["ssh_host_key_fingerprint_sha256"] == GATE_A_PIN
    assert plan["source_address"] == "192.168.2.10"
    assert plan["credential_ref"] == LAB_CREDENTIAL_REF
    assert len(plan["candidates"]) >= 10


def test_plan_payload_is_deterministic(cli_module) -> None:
    kwargs = {
        "wg_id": "Wireguard6",
        "base_asc_9": _ASC_9,
        "trailing": "0 0 1 2 3 4 5",
    }
    first = cli_module.build_plan_payload(**kwargs)
    second = cli_module.build_plan_payload(**kwargs)
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
    assert first["certification_eligible"] is False


def test_plan_payload_contains_no_secret_material(cli_module) -> None:
    plan = cli_module.build_plan_payload(
        wg_id="Wireguard5",
        base_asc_9=_ASC_9,
        trailing="0 0 0 0 0 0 0",
    )
    serialized = json.dumps(plan)
    forbidden_substrings = (
        "private-key",
        "preshared",
        "password",
        "BEGIN ",
        "-----",
    )
    lowered = serialized.lower()
    for fragment in forbidden_substrings:
        assert fragment.lower() not in lowered
    assert plan["credential_ref"] == LAB_CREDENTIAL_REF
    assert "cred_" in plan["credential_ref"]
    assert plan["certification_eligible"] is False
