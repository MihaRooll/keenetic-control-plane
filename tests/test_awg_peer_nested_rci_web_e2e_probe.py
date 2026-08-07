"""Offline tests for probe-nc1812-awg-peer-nested-rci-web-e2e plan-only path."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from dataclasses import replace
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-awg-peer-nested-rci-web-e2e.py"

LAB_CREDENTIAL_REF = "cred_db65665dd59f600bdd23544d85564c83"
GATE_A_PIN = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"
DEFAULT_PEER_PUBLIC_KEY = "Oq6wuNSfv44nSkw3d3zfIqzda3ZZQlogDvY3nCLq/vM="


def _load_module():
    module_name = "probe_nc1812_awg_peer_nested_rci_web_e2e_cli"
    spec = importlib.util.spec_from_file_location(module_name, CLI_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def cli_module():
    return _load_module()


def _sample_config(cli_module):
    return cli_module.ProbeConfig(
        host="192.168.2.1",
        source_address="192.168.2.10",
        username="admin",
        router_credential_ref_id=LAB_CREDENTIAL_REF,
        ssh_host_key_sha256=GATE_A_PIN,
        wg_id="Wireguard5",
        base_url="http://127.0.0.1:8787",
        secrets_root="data/secrets",
        peer_public_key=DEFAULT_PEER_PUBLIC_KEY,
        peer_endpoint="203.0.113.1:51820",
        peer_allow_ips="10.99.99.0 255.255.255.0",
        peer_keepalive=25,
        with_psk=False,
        artifact_out="data/artifacts/example.json",
        confirm_live=False,
    )


def test_build_plan_is_pure_and_has_expected_intent(cli_module) -> None:
    plan = cli_module.build_plan(_sample_config(cli_module))
    assert plan["confirm_live"] is False
    assert plan["mode"] == "plan-only"
    assert plan["bounded_test_interface"] == "Wireguard5"
    assert plan["peer_rci_shape"] == "nested_rci"
    assert plan["preview_intent"]["enabled"] is True
    assert plan["preview_intent"]["peer_public_key"] == DEFAULT_PEER_PUBLIC_KEY
    assert plan["preview_intent"]["private_key_credential_ref_id"] == "<throwaway-enrolled-at-live>"
    assert plan["apply_body_shape"]["confirm_live_apply"] is True
    assert plan["teardown_body_shape"]["confirm_live_teardown"] is True
    assert plan["connection"]["router_credential_ref_id"] == LAB_CREDENTIAL_REF
    assert plan["system_configuration_saved"] is False


@pytest.mark.parametrize(
    "wg_id",
    ["Wireguard0", "Wireguard4", "Wireguard10", "WireguardX", "wireguard5"],
)
def test_wg_id_outside_bounds_exits_two(cli_module, wg_id: str) -> None:
    argv = ["probe-nc1812-awg-peer-nested-rci-web-e2e.py", "--wg-id", wg_id]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert cli_module.main() == 2
    assert "Wireguard[5-9]" in stderr.getvalue()


def test_plan_only_default_exits_zero_without_vault_or_network() -> None:
    result = subprocess.run(
        [sys.executable, str(CLI_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["confirm_live"] is False
    assert plan["peer_rci_shape"] == "nested_rci"
    assert plan["preview_intent"]["peer_endpoint"] == "203.0.113.1:51820"


def test_plan_output_has_no_raw_secret_field_names(cli_module) -> None:
    plan = cli_module.build_plan(_sample_config(cli_module))

    def walk(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                lowered = str(key).lower()
                assert lowered not in {"private_key", "preshared_key"}
                if lowered.endswith("_key") and lowered not in {
                    "peer_public_key",
                    "private_key_credential_ref_id",
                    "preshared_key_credential_ref_id",
                }:
                    assert isinstance(nested, str) and nested.startswith("<")
                walk(nested)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    walk(plan)


def test_validate_wg_id_accepts_throwaway_range(cli_module) -> None:
    for index in range(5, 10):
        assert cli_module.validate_wg_id(f"Wireguard{index}") == f"Wireguard{index}"


def test_build_plan_with_psk_flag(cli_module) -> None:
    config = replace(_sample_config(cli_module), with_psk=True)
    plan = cli_module.build_plan(config)
    assert plan["with_psk"] is True
    assert "preshared_key_credential_ref_id" in plan["preview_intent"]


def _representative_live_evidence(*, with_psk: bool = True) -> dict[str, object]:
    deleted: dict[str, bool] = {"awg_private_key_ref_deleted": True}
    if with_psk:
        deleted["awg_preshared_key_ref_deleted"] = True
    return {
        "contract_id": "nc1812-awg-peer-nested-rci-web-e2e-probe-20260724",
        "campaign": "awg-peer-nested-rci-web-e2e-live-verify",
        "mode": "live",
        "confirm_live": True,
        "preview_http_status": 200,
        "apply_http_status": 200,
        "teardown_http_status": 200,
        "preview": {"overall": "previewed"},
        "apply": {"overall": "applied"},
        "teardown": {"overall": "applied"},
        "throwaway_credentials_deleted": deleted,
        "findings": [],
        "summary": "nested_rci peer web-E2E live verify completed",
    }


def test_evidence_leak_scan_passes_for_deletion_status_keys(cli_module) -> None:
    evidence = _representative_live_evidence(with_psk=True)
    fake_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    fake_psk = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    cli_module._assert_evidence_has_no_in_memory_secrets(
        evidence,
        forbidden_substrings=frozenset({fake_pk, fake_psk}),
    )


def test_evidence_leak_scan_raises_on_embedded_plaintext_secret(cli_module) -> None:
    evidence = _representative_live_evidence(with_psk=False)
    leaked_secret = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
    evidence["findings"] = [f"debug fragment contains {leaked_secret}"]
    with pytest.raises(RuntimeError, match="evidence would leak"):
        cli_module._assert_evidence_has_no_in_memory_secrets(
            evidence,
            forbidden_substrings=frozenset({leaked_secret}),
        )


def test_default_artifact_out_is_relative(cli_module) -> None:
    path = cli_module.default_artifact_out("192.168.2.1")
    assert not Path(path).is_absolute()
    assert path.startswith("data/artifacts/awg-peer-nested-rci-live-verify-192.168.2.1-")


def test_plan_only_artifact_out_is_relative() -> None:
    result = subprocess.run(
        [sys.executable, str(CLI_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    artifact_out = plan["artifact_out"]
    assert not Path(artifact_out).is_absolute()
    assert artifact_out.startswith("data/artifacts/awg-peer-nested-rci-live-verify-")
