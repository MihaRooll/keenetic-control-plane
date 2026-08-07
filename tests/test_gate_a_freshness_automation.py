"""Offline tests for Gate A freshness automation library."""

from __future__ import annotations

import importlib.util
import json
import sys
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.adapters.netcraze.certification import load_gate_a_certification

REPO_ROOT = Path(__file__).resolve().parents[1]
LIB_SCRIPT = REPO_ROOT / "scripts" / "gate_a_freshness_lib.py"

BASE_RECORDED_AT = datetime(2026, 8, 5, 12, 0, 0, tzinfo=UTC)
NEW_RECORDED_AT = datetime(2026, 8, 6, 10, 0, 0, tzinfo=UTC)


def _load_lib():
    spec = importlib.util.spec_from_file_location("gate_a_freshness_lib", LIB_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def lib():
    return _load_lib()


def _minimal_raw_config() -> dict:
    return {
        "status": "open",
        "certification": "ReadOnlyCertified",
        "approved_scope": "SLICE-4-readonly",
        "opened_on": "2026-07-21",
        "recertified_on": "2026-08-05",
        "recertification_reason": "evidence_freshness_recertification_same_tuple_20260805",
        "recertification_note": "Prior manual recert.",
        "expires_after_days": 90,
        "revocation_policy": "human operator message required",
        "model": "NC-1812",
        "model_display": "Ultra (NC-1812)",
        "firmware_version": "5.01.C.1.0-0",
        "firmware_display": "5.1.1",
        "ndm_build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": (
            "sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80"
        ),
        "device_fingerprint_digest": (
            "sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd"
        ),
        "physical_id_source": "show.identification_digest",
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": (
            "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
        ),
        "certification_eligible": True,
        "evidence_recorded_at": BASE_RECORDED_AT.isoformat(),
        "opening_freshness_hours": 24,
        "evidence_sha256": "ff6e9bb84eefba911d00045b2f295b4cbcefe8754757373a64940e93b0144d1c",
        "evidence_path": "data/artifacts/gate-a-probe-fixture-old.json",
        "component_set_digest_algorithm": "component-set-v2",
        "source_address": "192.168.2.10",
        "checklist": ["exact_identity_pass"],
        "gates": {
            "A": {"status": "open", "certification": "ReadOnlyCertified"},
            "B": {"status": "closed"},
            "C": {"status": "closed"},
            "D": {"status": "closed"},
        },
        "previous_certifications": [],
    }


def _matching_evidence(*, recorded_at: datetime | None = None) -> dict:
    when = recorded_at or NEW_RECORDED_AT
    return {
        "model": "NC-1812",
        "firmware_version": "5.01.C.1.0-0",
        "build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": (
            "sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80"
        ),
        "device_fingerprint": (
            "sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd"
        ),
        "transport_security": "ssh_tunnel",
        "ssh_host_key_algorithm": "ssh-ed25519",
        "ssh_host_key_fingerprint_sha256": (
            "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
        ),
        "certification_eligible": True,
        "identity_complete": True,
        "evidence_recorded_at": when.isoformat(),
    }


def test_compute_deadline_z_and_offset_suffixes(lib) -> None:
    config_z = {
        "evidence_recorded_at": "2026-08-05T12:00:00Z",
        "opening_freshness_hours": 24,
    }
    config_offset = {
        "evidence_recorded_at": "2026-08-05T12:00:00+00:00",
        "opening_freshness_hours": 24,
    }
    expected = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)
    assert lib.compute_deadline(config_z) == expected
    assert lib.compute_deadline(config_offset) == expected


def test_is_due_margin_and_expiry(lib) -> None:
    raw_config = {
        "evidence_recorded_at": BASE_RECORDED_AT.isoformat(),
        "opening_freshness_hours": 24,
    }
    assert lib.is_due(
        raw_config,
        now=BASE_RECORDED_AT + timedelta(hours=23, minutes=59),
        margin_hours=12,
    )
    assert not lib.is_due(
        raw_config,
        now=BASE_RECORDED_AT + timedelta(hours=1),
        margin_hours=12,
    )
    assert lib.is_due(
        raw_config,
        now=BASE_RECORDED_AT + timedelta(hours=25),
        margin_hours=12,
    )


def test_diff_tuple_fields_firmware_and_ssh_pin(lib) -> None:
    raw_config = _minimal_raw_config()
    evidence = _matching_evidence()

    fw_evidence = deepcopy(evidence)
    fw_evidence["firmware_version"] = "9.99.Z.9.9-9"
    assert "firmware_version" in lib.diff_tuple_fields(raw_config, fw_evidence)

    pin_evidence = deepcopy(evidence)
    pin_evidence["ssh_host_key_fingerprint_sha256"] = (
        "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    )
    diffs = lib.diff_tuple_fields(raw_config, pin_evidence)
    assert "ssh_host_key_fingerprint_sha256" in diffs


def test_evaluate_and_apply_matching_tuple(lib) -> None:
    raw_config = _minimal_raw_config()
    evidence = _matching_evidence()
    now = NEW_RECORDED_AT
    evidence_path_rel = "data/artifacts/gate-a-probe-auto-fixture.json"
    evidence_sha256 = "abc123def456" + "0" * 52

    outcome, new_config = lib.evaluate_and_apply(
        raw_config,
        evidence=evidence,
        evidence_path_rel=evidence_path_rel,
        evidence_sha256=evidence_sha256,
        now=now,
    )

    assert outcome.status == "recertified"
    assert new_config["evidence_recorded_at"] == evidence["evidence_recorded_at"]
    assert new_config["evidence_path"] == evidence_path_rel
    prev = new_config["previous_certifications"]
    assert len(prev) == len(raw_config["previous_certifications"]) + 1

    superseded = new_config["previous_certifications"][-1]
    assert superseded["status"] == "superseded_evidence"
    assert superseded["evidence_path"] == raw_config["evidence_path"]
    assert superseded["evidence_sha256"] == raw_config["evidence_sha256"]
    assert superseded["evidence_recorded_at"] == raw_config["evidence_recorded_at"]

    unchanged_keys = [
        "model",
        "component_set_digest",
        "ssh_host_key_fingerprint_sha256",
        "source_address",
        "checklist",
        "ndm_build",
        "device_fingerprint_digest",
    ]
    for key in unchanged_keys:
        assert new_config[key] == raw_config[key]


def test_evaluate_and_apply_drift_unchanged(lib) -> None:
    raw_config = _minimal_raw_config()
    evidence = _matching_evidence()
    evidence["component_set_digest"] = "sha256:deadbeef" + "0" * 56

    outcome, new_config = lib.evaluate_and_apply(
        raw_config,
        evidence=evidence,
        evidence_path_rel="data/artifacts/gate-a-probe-drift.json",
        evidence_sha256="0" * 64,
        now=NEW_RECORDED_AT,
    )

    assert outcome.status == "drift_detected"
    assert "component_set_digest" in outcome.diffs
    assert new_config == raw_config


def test_evaluate_and_apply_ineligible_unchanged(lib) -> None:
    raw_config = _minimal_raw_config()
    evidence = _matching_evidence()
    evidence["identity_complete"] = False

    outcome, new_config = lib.evaluate_and_apply(
        raw_config,
        evidence=evidence,
        evidence_path_rel="data/artifacts/gate-a-probe-ineligible.json",
        evidence_sha256="0" * 64,
        now=NEW_RECORDED_AT,
    )

    assert outcome.status == "ineligible"
    assert new_config == raw_config


def test_round_trip_reopens_gate_via_load_gate_a_certification(lib, tmp_path: Path) -> None:
    raw_config = _minimal_raw_config()
    evidence = _matching_evidence()
    evidence_path_rel = "data/artifacts/gate-a-probe-auto-roundtrip.json"
    now = NEW_RECORDED_AT

    outcome, new_config = lib.evaluate_and_apply(
        raw_config,
        evidence=evidence,
        evidence_path_rel=evidence_path_rel,
        evidence_sha256="placeholder",
        now=now,
    )
    assert outcome.status == "recertified"

    config_path = tmp_path / "gate-a-certification.json"
    evidence_path = tmp_path / "evidence.json"
    status_path = tmp_path / "STATUS.yaml"

    evidence_path.write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
    actual_sha256 = lib.sha256_of_file(evidence_path)
    new_config["evidence_sha256"] = actual_sha256

    lib.write_config(config_path, new_config)
    status_path.write_text(
        "gates:\n  A:\n    status: open\n    certification: ReadOnlyCertified\n",
        encoding="utf-8",
    )

    check_now = NEW_RECORDED_AT + timedelta(hours=1)
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=check_now,
    )
    assert cert.is_open_at(check_now) is True
