"""Typed Gate A certification loader tests (offline, no network)."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from router_control.adapters.netcraze.certification import (
    GateACertification,
    GateACertificationError,
    load_gate_a_certification,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMITTED_CONFIG_PATH = REPO_ROOT / "docs" / "gate-a-certification.json"
COMMITTED_STATUS_PATH = REPO_ROOT / "docs" / "STATUS.yaml"
# Synthetic fixture timestamp only — not tied to committed evidence pointer refreshes.
FIXTURE_EVIDENCE_RECORDED_AT = "2026-08-05T17:00:22.399087+00:00"
CURRENT_EVIDENCE_SOURCE_ADDRESS = "192.168.2.10"
FIXED_OPEN = datetime(2026, 8, 5, 18, 0, 0, tzinfo=UTC)
STALE_OPEN = datetime(2026, 8, 6, 20, 0, 0, tzinfo=UTC)
COMPONENT_DIGEST = (
    "sha256:23bd35bc1bcbf8523495ff7fb37ef2ded597ce9d07b9c1c968ae1f9e4aa4de80"
)
FINGERPRINT_DIGEST = (
    "sha256:c34adec44383c0dc1f31833bb6d7885a8e9af454722af0c6bfba3761ac71e6fd"
)
PRE_WG_COMPONENT_DIGEST = (
    "sha256:91145a8284d142729b93bb0fd549312134dd669ef7b07f4d2207d2b6a22dd83b"
)
PRE_WG_FINGERPRINT_DIGEST = (
    "sha256:13885245280ae4301f27d7ef03ab7cdaf1b51367943216b62f5c81590973e021"
)
PRIOR_COMPONENT_DIGEST = (
    "sha256:de72a7af2255a1993c382ffd41143b8061525137b0d8e192811a32babf852f2f"
)
PRIOR_FINGERPRINT_DIGEST = (
    "sha256:eb58946c0d18b3cb259c2687e474d10907dfdbbcf39c88992202917c37855169"
)
PRIOR_EVIDENCE_SHA256 = (
    "24c6df7eeb2648af25a1ed6d795ad634f32c4fa664555a67f9ff00d57ee9d4f3"
)
PRIOR_EVIDENCE_RECORDED_AT = "2026-07-23T18:18:49.005975+00:00"
SSH_HOST_KEY_ALGORITHM = "ssh-ed25519"
SSH_HOST_KEY_FINGERPRINT_SHA256 = (
    "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
)
REVOKED_COMPONENT_DIGEST = (
    "sha256:db8af50bfd4280f36eb874c881e652c3be1221db0c63215d268741f871cbb0d7"
)
REVOKED_FINGERPRINT_DIGEST = (
    "sha256:9d24556612fd2d1644c44e55bbfd781db06a3aee83dd6eb99329b2ce4216da6f"
)
CERTIFIED_EVIDENCE = {
    "model": "NC-1812",
    "firmware_version": "5.01.C.1.0-0",
    "build": "0-b592e619a0",
    "bsp_build": "0-f371d30955",
    "update_channel": "Main",
    "region": "EA",
    "component_set_digest": COMPONENT_DIGEST,
    "device_fingerprint": FINGERPRINT_DIGEST,
    "transport_security": "ssh_tunnel",
    "ssh_host_key_algorithm": SSH_HOST_KEY_ALGORITHM,
    "ssh_host_key_fingerprint_sha256": SSH_HOST_KEY_FINGERPRINT_SHA256,
    "certification_eligible": True,
    "identity_complete": True,
    "evidence_recorded_at": FIXTURE_EVIDENCE_RECORDED_AT,
    "source_address": "192.168.2.10",
}


def _evidence_sha256(evidence_path: Path) -> str:
    return hashlib.sha256(evidence_path.read_bytes()).hexdigest()


def _normalize_sha256(value: str) -> str:
    normalized = str(value).strip().lower()
    if normalized.startswith("sha256:"):
        normalized = normalized[7:]
    return normalized


def _parse_evidence_recorded_at(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    return parsed


def _resolved_committed_evidence_path(config: dict[str, object]) -> Path:
    return REPO_ROOT / str(config["evidence_path"]).replace("\\", "/")


def _assert_evidence_sha256_matches_file(
    *,
    config_sha256: str,
    evidence_file: Path,
) -> None:
    if not evidence_file.is_file():
        return
    actual = _normalize_sha256(_evidence_sha256(evidence_file))
    expected = _normalize_sha256(config_sha256)
    assert actual == expected


def _walk_status_previous_evidence_chain(status: str) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    path_prefix: tuple[str, ...] = ("gates", "A", "previous_evidence")
    while True:
        try:
            chain.append(
                {
                    "path": _yaml_value(status, (*path_prefix, "path")),
                    "sha256": _yaml_value(status, (*path_prefix, "sha256")),
                    "recorded_at": _yaml_value(status, (*path_prefix, "recorded_at")),
                }
            )
        except AssertionError:
            break
        path_prefix = (*path_prefix, "prior_evidence")
    return chain


def _yaml_value(text: str, path: tuple[str, ...]) -> str:
    """Read one scalar through exact two-space-indented mapping blocks."""
    lines = text.splitlines()
    start = 0
    end = len(lines)
    parent_indent = -2

    for depth, key in enumerate(path):
        target_indent = parent_indent + 2
        matches: list[int] = []
        for index in range(start, end):
            line = lines[index]
            stripped = line.lstrip(" ")
            indent = len(line) - len(stripped)
            if indent == target_indent and stripped.startswith(f"{key}:"):
                matches.append(index)
        assert len(matches) == 1, f"expected one YAML path segment {path[: depth + 1]}"

        index = matches[0]
        value = lines[index].lstrip(" ").split(":", 1)[1].strip()
        if depth == len(path) - 1:
            return value.strip("\"'")
        assert value == "", f"expected YAML mapping at {path[: depth + 1]}"

        start = index + 1
        end = len(lines)
        for child_index in range(start, len(lines)):
            child = lines[child_index]
            if not child.strip() or child.lstrip(" ").startswith("#"):
                continue
            child_indent = len(child) - len(child.lstrip(" "))
            if child_indent <= target_indent:
                end = child_index
                break
        parent_indent = target_indent

    raise AssertionError(f"empty YAML path: {path}")


def _gate_config(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "status": "open",
        "certification": "ReadOnlyCertified",
        "approved_scope": "SLICE-4-readonly",
        "model": "NC-1812",
        "model_display": "Ultra (NC-1812)",
        "firmware_version": "5.01.C.1.0-0",
        "firmware_display": "5.1.1",
        "ndm_build": "0-b592e619a0",
        "bsp_build": "0-f371d30955",
        "update_channel": "Main",
        "region": "EA",
        "component_set_digest": COMPONENT_DIGEST,
        "device_fingerprint_digest": FINGERPRINT_DIGEST,
        "physical_id_source": "show.identification_digest",
        "transport": "ssh_tunnel",
        "ssh_host_key_algorithm": SSH_HOST_KEY_ALGORITHM,
        "ssh_host_key_fingerprint_sha256": SSH_HOST_KEY_FINGERPRINT_SHA256,
        "certification_eligible": True,
        "evidence_recorded_at": FIXTURE_EVIDENCE_RECORDED_AT,
        "opening_freshness_hours": 24,
        "evidence_path": "ignored-evidence.json",
        "expires_after_days": 90,
        "gates": {
            "A": {"status": "open", "certification": "ReadOnlyCertified"},
            "B": {"status": "closed"},
            "C": {"status": "closed"},
            "D": {"status": "closed"},
        },
    }
    base.update(overrides)
    return base


@pytest.fixture
def gate_paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    config_path = tmp_path / "gate-a.json"
    evidence_path = tmp_path / "evidence.json"
    status_path = tmp_path / "STATUS.yaml"
    evidence_path.write_text(json.dumps(CERTIFIED_EVIDENCE), encoding="utf-8")
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    config_path.write_text(
        json.dumps(_gate_config(evidence_sha256=digest)),
        encoding="utf-8",
    )
    status_path.write_text(
        "gates:\n  A:\n    status: open\n    certification: ReadOnlyCertified\n",
        encoding="utf-8",
    )
    return config_path, evidence_path, status_path


def test_committed_gate_a_config_has_exact_current_tuple() -> None:
    config = json.loads(COMMITTED_CONFIG_PATH.read_text(encoding="utf-8"))
    status = COMMITTED_STATUS_PATH.read_text(encoding="utf-8")

    assert config["status"] == "open"
    assert config["certification"] == "ReadOnlyCertified"
    assert config["certification_eligible"] is True
    assert config["model"] == "NC-1812"
    assert config["component_set_digest"] == COMPONENT_DIGEST
    assert config["device_fingerprint_digest"] == FINGERPRINT_DIGEST
    assert config["source_address"] == CURRENT_EVIDENCE_SOURCE_ADDRESS
    assert config["ssh_host_key_algorithm"] == SSH_HOST_KEY_ALGORITHM
    assert (
        config["ssh_host_key_fingerprint_sha256"]
        == SSH_HOST_KEY_FINGERPRINT_SHA256
    )

    recorded_at = _parse_evidence_recorded_at(str(config["evidence_recorded_at"]))
    assert recorded_at.tzinfo is not None
    assert recorded_at.utcoffset() == timedelta(0)

    evidence_file = _resolved_committed_evidence_path(config)
    _assert_evidence_sha256_matches_file(
        config_sha256=str(config["evidence_sha256"]),
        evidence_file=evidence_file,
    )

    recertification_reason = str(config["recertification_reason"])
    assert recertification_reason
    assert recertification_reason.startswith(
        "evidence_freshness_recertification_same_tuple"
    )

    previous_certifications = config["previous_certifications"]
    assert len(previous_certifications) >= 1
    last_superseded = previous_certifications[-1]
    assert last_superseded["status"] == "superseded_evidence"
    assert last_superseded["component_set_digest"] == COMPONENT_DIGEST
    assert last_superseded["device_fingerprint_digest"] == FINGERPRINT_DIGEST
    assert (
        last_superseded["ssh_host_key_fingerprint_sha256"]
        == SSH_HOST_KEY_FINGERPRINT_SHA256
    )

    assert config["gates"] == {
        "A": {
            "status": "open",
            "certification": "ReadOnlyCertified",
        },
        "B": {"status": "closed"},
        "C": {"status": "closed"},
        "D": {"status": "closed"},
    }
    assert "observed_components" not in config
    assert _yaml_value(status, ("gates", "A", "status")) == "open"
    assert (
        _yaml_value(status, ("gates", "A", "certification"))
        == "ReadOnlyCertified"
    )
    assert (
        _yaml_value(status, ("gates", "A", "tuple", "component_set_digest"))
        == COMPONENT_DIGEST
    )
    assert (
        _yaml_value(status, ("gates", "A", "tuple", "device_fingerprint_digest"))
        == FINGERPRINT_DIGEST
    )
    assert (
        _yaml_value(status, ("gates", "A", "tuple", "ssh_host_key_algorithm"))
        == SSH_HOST_KEY_ALGORITHM
    )
    assert (
        _yaml_value(
            status,
            ("gates", "A", "tuple", "ssh_host_key_fingerprint_sha256"),
        )
        == SSH_HOST_KEY_FINGERPRINT_SHA256
    )
    assert (
        _yaml_value(status, ("gates", "A", "previous_evidence", "tuple_status"))
        == "superseded_evidence_same_tuple"
    )
    assert len(previous_certifications) >= 11
    revoked_entries = [
        entry
        for entry in previous_certifications
        if entry.get("status") == "revoked"
    ]
    superseded_entries = [
        entry
        for entry in previous_certifications
        if entry.get("status") == "superseded_evidence"
    ]
    stale_entries = [
        entry
        for entry in previous_certifications
        if entry.get("status") == "stale_pending_recertification"
    ]
    assert len(revoked_entries) == 1
    assert len(superseded_entries) >= 9
    assert len(stale_entries) == 1
    assert (
        revoked_entries[0]["component_set_digest"] == REVOKED_COMPONENT_DIGEST
    )
    assert (
        revoked_entries[0]["device_fingerprint_digest"]
        == REVOKED_FINGERPRINT_DIGEST
    )
    probe_superseded = [
        entry
        for entry in superseded_entries
        if entry.get("evidence_path")
        == "data/artifacts/gate-a-probe-192.168.1.1.json"
    ]
    return_home_superseded = [
        entry
        for entry in superseded_entries
        if entry.get("evidence_path") == "data/artifacts/gate-a-return-home-20260723.json"
    ]
    assert len(probe_superseded) == 1
    assert len(return_home_superseded) == 1
    assert (
        probe_superseded[0]["component_set_digest"] == PRIOR_COMPONENT_DIGEST
    )
    assert (
        probe_superseded[0]["device_fingerprint_digest"]
        == PRIOR_FINGERPRINT_DIGEST
    )
    assert (
        return_home_superseded[0]["component_set_digest"] == PRIOR_COMPONENT_DIGEST
    )
    assert (
        return_home_superseded[0]["device_fingerprint_digest"]
        == PRIOR_FINGERPRINT_DIGEST
    )
    assert (
        return_home_superseded[0]["evidence_sha256"]
        == "232bc5ca83c915fe29b037ed886859256fd5c27b29293db104b9b7bacef04c36"
    )
    assert return_home_superseded[0]["source_address"] == "192.168.1.144"
    assert stale_entries[0]["component_set_digest"] == PRIOR_COMPONENT_DIGEST
    assert stale_entries[0]["device_fingerprint_digest"] == PRIOR_FINGERPRINT_DIGEST
    assert stale_entries[0]["prior_certification"] == "ReadOnlyCertified"
    assert (
        stale_entries[0]["evidence_sha256"]
        == PRIOR_EVIDENCE_SHA256
    )
    rebind_superseded = [
        entry
        for entry in superseded_entries
        if entry.get("superseded_on") == "2026-07-31"
    ]
    assert len(rebind_superseded) == 2
    rebind_reasons = {entry["supersession_reason"] for entry in rebind_superseded}
    assert rebind_reasons == {
        "physical_device_replaced_authorized_rebind_expendable",
        "component_set_changed_after_wireguard_install_authorized_rebind_expendable",
    }
    identity_drift_superseded = [
        entry
        for entry in rebind_superseded
        if entry.get("supersession_reason")
        == "component_set_changed_after_wireguard_install_authorized_rebind_expendable"
    ]
    assert len(identity_drift_superseded) == 1
    assert (
        identity_drift_superseded[0]["component_set_digest"] == PRE_WG_COMPONENT_DIGEST
    )
    assert (
        identity_drift_superseded[0]["device_fingerprint_digest"]
        == PRE_WG_FINGERPRINT_DIGEST
    )
    assert (
        identity_drift_superseded[0]["evidence_path"]
        == "data/artifacts/gate-a-probe-newrouter-192.168.2.1-20260731.json"
    )
    physical_rebind_superseded = [
        entry
        for entry in rebind_superseded
        if entry.get("supersession_reason")
        == "physical_device_replaced_authorized_rebind_expendable"
    ]
    assert len(physical_rebind_superseded) == 1
    assert physical_rebind_superseded[0]["component_set_digest"] == PRIOR_COMPONENT_DIGEST
    assert (
        physical_rebind_superseded[0]["evidence_sha256"]
        == PRIOR_EVIDENCE_SHA256
    )
    status_previous_chain = _walk_status_previous_evidence_chain(status)
    assert len(status_previous_chain) >= 8
    for entry in status_previous_chain:
        _parse_evidence_recorded_at(entry["recorded_at"])
        _assert_evidence_sha256_matches_file(
            config_sha256=entry["sha256"],
            evidence_file=REPO_ROOT / entry["path"].replace("\\", "/"),
        )

    status_recorded_at = _yaml_value(status, ("gates", "A", "evidence", "recorded_at"))
    _parse_evidence_recorded_at(status_recorded_at)
    status_evidence_path = _yaml_value(status, ("gates", "A", "evidence", "path"))
    status_evidence_sha256 = _yaml_value(status, ("gates", "A", "evidence", "sha256"))
    _assert_evidence_sha256_matches_file(
        config_sha256=status_evidence_sha256,
        evidence_file=REPO_ROOT / status_evidence_path.replace("\\", "/"),
    )
    assert (
        _yaml_value(status, ("gates", "A", "evidence", "source_address"))
        == CURRENT_EVIDENCE_SOURCE_ADDRESS
    )
    status_recertification_reason = _yaml_value(
        status, ("gates", "A", "recertification_reason")
    )
    assert status_recertification_reason.startswith(
        "evidence_freshness_recertification_same_tuple"
    )
    assert (
        _yaml_value(status, ("gates", "A", "component_set_digest_algorithm"))
        == "component-set-v2"
    )
    assert (
        _yaml_value(status, ("gates", "B", "status"))
        == "completed_failed"
    )
    assert _yaml_value(status, ("gates", "B", "not_write_certified")) == "true"
    assert _yaml_value(status, ("gates", "C", "status")) == "closed"
    assert _yaml_value(status, ("gates", "C", "outcome")) == "completed_failed"
    assert (
        _yaml_value(status, ("gates", "C", "opens_at"))
        == "2026-07-23T11:00:00Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "expires_at"))
        == "2026-07-23T12:00:00Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "completed_at"))
        == "2026-07-23T11:41:34Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "capability_family"))
        == "fail_safe"
    )
    assert (
        _yaml_value(status, ("gates", "C", "trial_id"))
        == "fail-safe-20260723T110000Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "previous_trial", "trial_id"))
        == "fail-safe-20260723T094500Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "previous_trial", "opens_at"))
        == "2026-07-23T09:45:00Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "previous_trial", "expires_at"))
        == "2026-07-23T10:45:00Z"
    )
    assert (
        _yaml_value(status, ("gates", "C", "previous_trial", "completed_at"))
        == "2026-07-23T09:54:30Z"
    )
    assert (
        _yaml_value(status, ("gates", "B", "previous_trial", "trial_id"))
        == "fail-safe-20260723T094500Z"
    )
    assert (
        _yaml_value(
            status,
            ("gates", "B", "previous_trial", "result_evidence_sha256"),
        )
        == "c39cc40fbf76d024296587c1865eae087e99fc74cb60222b9fd93e0cdbb12cf9"
    )
    assert _yaml_value(status, ("gates", "D", "status")) == "closed"


def test_committed_gate_a_config_matches_optional_local_artifact() -> None:
    config = json.loads(COMMITTED_CONFIG_PATH.read_text(encoding="utf-8"))
    evidence_file = _resolved_committed_evidence_path(config)
    if not evidence_file.is_file():
        pytest.skip(f"committed Gate A evidence artifact not present: {evidence_file}")

    now = datetime.now(UTC)
    cert = load_gate_a_certification(
        config_path=COMMITTED_CONFIG_PATH,
        evidence_path=evidence_file,
        status_path=COMMITTED_STATUS_PATH,
        now=now,
    )

    _assert_evidence_sha256_matches_file(
        config_sha256=str(config["evidence_sha256"]),
        evidence_file=evidence_file,
    )
    assert cert.status == "open"
    assert cert.certification == "ReadOnlyCertified"
    assert not cert.is_stale_pending_recertification()
    assert cert.is_open_at(now)


def test_gate_a_loader_exact_match(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED_OPEN,
    )
    assert cert.is_open_at(FIXED_OPEN)
    assert cert.model == "NC-1812"
    assert cert.device_fingerprint_digest.startswith("sha256:")


def test_gate_a_loader_missing_config(tmp_path: Path) -> None:
    with pytest.raises(GateACertificationError, match="not found"):
        load_gate_a_certification(
            config_path=tmp_path / "missing.json",
            require_status_alignment=False,
            require_evidence=False,
        )


def test_gate_a_loader_malformed_json(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(GateACertificationError, match="malformed"):
        load_gate_a_certification(
            config_path=bad,
            require_status_alignment=False,
            require_evidence=False,
        )


def test_gate_a_loader_stale_expired(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    stale_evidence = dict(CERTIFIED_EVIDENCE)
    stale_evidence["evidence_recorded_at"] = "2020-01-01T00:00:00+00:00"
    evidence_path.write_text(json.dumps(stale_evidence), encoding="utf-8")
    stale = _gate_config(
        evidence_recorded_at="2020-01-01T00:00:00+00:00",
        expires_after_days=1,
        evidence_sha256=_evidence_sha256(evidence_path),
    )
    config_path.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(GateACertificationError, match="expired|freshness"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
        )


def test_gate_a_loader_opening_freshness_window(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    recorded = "2026-07-19T12:00:00+00:00"
    stale_evidence = dict(CERTIFIED_EVIDENCE)
    stale_evidence["evidence_recorded_at"] = recorded
    evidence_path.write_text(json.dumps(stale_evidence), encoding="utf-8")
    stale = _gate_config(
        evidence_recorded_at=recorded,
        evidence_sha256=_evidence_sha256(evidence_path),
    )
    config_path.write_text(json.dumps(stale), encoding="utf-8")
    with pytest.raises(GateACertificationError, match="freshness"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
        )


def test_gate_a_loader_evidence_mismatch(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    wrong = dict(CERTIFIED_EVIDENCE)
    wrong["model"] = "WRONG"
    evidence_path.write_text(json.dumps(wrong), encoding="utf-8")
    config_path.write_text(
        json.dumps(_gate_config(evidence_sha256=_evidence_sha256(evidence_path))),
        encoding="utf-8",
    )
    with pytest.raises(GateACertificationError, match="mismatch"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_revoked_tuple_digests_do_not_inherit_current_certification(
    tmp_path: Path,
) -> None:
    current_config = json.loads(COMMITTED_CONFIG_PATH.read_text(encoding="utf-8"))
    revoked_evidence = dict(CERTIFIED_EVIDENCE)
    revoked_evidence["component_set_digest"] = REVOKED_COMPONENT_DIGEST
    revoked_evidence["device_fingerprint"] = REVOKED_FINGERPRINT_DIGEST

    evidence_path = tmp_path / "revoked-evidence.json"
    config_path = tmp_path / "current-config.json"
    evidence_path.write_text(json.dumps(revoked_evidence), encoding="utf-8")
    current_config["evidence_path"] = str(evidence_path)
    current_config["evidence_sha256"] = _evidence_sha256(evidence_path)
    config_path.write_text(json.dumps(current_config), encoding="utf-8")

    with pytest.raises(GateACertificationError, match="evidence artifact tuple mismatch"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=COMMITTED_STATUS_PATH,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_pre_wg_tuple_digests_do_not_match_current_certification(
    tmp_path: Path,
) -> None:
    current_config = json.loads(COMMITTED_CONFIG_PATH.read_text(encoding="utf-8"))
    pre_wg_evidence = dict(CERTIFIED_EVIDENCE)
    pre_wg_evidence["component_set_digest"] = PRE_WG_COMPONENT_DIGEST
    pre_wg_evidence["device_fingerprint"] = PRE_WG_FINGERPRINT_DIGEST
    pre_wg_evidence["evidence_recorded_at"] = "2026-07-31T12:26:34.442533+00:00"

    evidence_path = tmp_path / "pre-wg-evidence.json"
    config_path = tmp_path / "current-config.json"
    evidence_path.write_text(json.dumps(pre_wg_evidence), encoding="utf-8")
    current_config["evidence_path"] = str(evidence_path)
    current_config["evidence_sha256"] = _evidence_sha256(evidence_path)
    config_path.write_text(json.dumps(current_config), encoding="utf-8")

    with pytest.raises(GateACertificationError, match="evidence artifact tuple mismatch"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=COMMITTED_STATUS_PATH,
            now=FIXED_OPEN,
        )


def test_gate_a_loader_evidence_hash_mismatch(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    config = _gate_config(
        evidence_sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(GateACertificationError, match="SHA256"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_open_requires_evidence_sha256(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    config = _gate_config()
    config.pop("evidence_sha256", None)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(GateACertificationError, match="evidence_sha256"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            require_evidence=False,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_open_missing_evidence_cannot_be_bypassed(
    gate_paths: tuple[Path, Path, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, _evidence_path, status_path = gate_paths
    missing_evidence = tmp_path / "missing-evidence.json"
    monkeypatch.setenv("RC_GATE_A_SKIP_EVIDENCE", "1")

    with pytest.raises(GateACertificationError, match="evidence artifact missing"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=missing_evidence,
            status_path=status_path,
            require_evidence=False,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_open_rejects_malformed_evidence_sha256(
    gate_paths: tuple[Path, Path, Path],
) -> None:
    config_path, evidence_path, status_path = gate_paths
    config = _gate_config(evidence_sha256="deadbeef")
    config_path.write_text(json.dumps(config), encoding="utf-8")
    with pytest.raises(GateACertificationError, match="64-character hex"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_status_alignment_gate_a_closed_fails(
    gate_paths: tuple[Path, Path, Path],
) -> None:
    config_path, evidence_path, status_path = gate_paths
    status_path.write_text(
        "gates:\n"
        "  A:\n"
        "    status: closed\n"
        "  B:\n"
        "    status: open\n"
        "notes: stray ReadOnlyCertified mention must not open Gate A\n",
        encoding="utf-8",
    )
    with pytest.raises(GateACertificationError, match="STATUS.yaml does not declare Gate A open"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_open_status_alignment_cannot_be_bypassed(
    gate_paths: tuple[Path, Path, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config_path, evidence_path, status_path = gate_paths
    status_path.write_text(
        "gates:\n"
        "  A:\n"
        "    status: closed\n"
        "  B:\n"
        "    status: open\n"
        "notes: ReadOnlyCertified\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RC_GATE_A_SKIP_STATUS", "1")

    with pytest.raises(
        GateACertificationError,
        match="STATUS.yaml does not declare Gate A open",
    ):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            require_status_alignment=False,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_status_alignment_requires_gate_a_open_block(
    gate_paths: tuple[Path, Path, Path],
) -> None:
    config_path, evidence_path, status_path = gate_paths
    status_path.write_text(
        "notes: ReadOnlyCertified\n"
        "gates:\n"
        "  B:\n"
        "    status: open\n",
        encoding="utf-8",
    )
    with pytest.raises(GateACertificationError, match="STATUS.yaml does not declare Gate A open"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_loader_evidence_hash_match(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    digest = hashlib.sha256(evidence_path.read_bytes()).hexdigest()
    config = _gate_config(evidence_sha256=digest)
    config_path.write_text(json.dumps(config), encoding="utf-8")
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED_OPEN,
    )
    assert cert.is_open_at(FIXED_OPEN)


def test_gate_a_loader_missing_evidence_schema(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    incomplete = {k: v for k, v in CERTIFIED_EVIDENCE.items() if k != "identity_complete"}
    evidence_path.write_text(json.dumps(incomplete), encoding="utf-8")
    config_path.write_text(
        json.dumps(_gate_config(evidence_sha256=_evidence_sha256(evidence_path))),
        encoding="utf-8",
    )
    with pytest.raises(GateACertificationError, match="required keys"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
        )


def test_gate_a_loader_accepts_canonical_transport_key(
    gate_paths: tuple[Path, Path, Path],
) -> None:
    config_path, evidence_path, status_path = gate_paths
    canonical_transport = dict(CERTIFIED_EVIDENCE)
    del canonical_transport["transport_security"]
    canonical_transport["transport"] = "ssh_tunnel"
    evidence_path.write_text(json.dumps(canonical_transport), encoding="utf-8")
    config_path.write_text(
        json.dumps(_gate_config(evidence_sha256=_evidence_sha256(evidence_path))),
        encoding="utf-8",
    )
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED_OPEN,
    )
    assert cert.is_open_at(FIXED_OPEN)
    assert cert.matches_probe_evidence(canonical_transport)


def test_gate_a_loader_rejects_missing_transport_alias_pair(
    gate_paths: tuple[Path, Path, Path],
) -> None:
    config_path, evidence_path, status_path = gate_paths
    missing_transport = {
        k: v
        for k, v in CERTIFIED_EVIDENCE.items()
        if k not in ("transport", "transport_security")
    }
    evidence_path.write_text(json.dumps(missing_transport), encoding="utf-8")
    config_path.write_text(
        json.dumps(_gate_config(evidence_sha256=_evidence_sha256(evidence_path))),
        encoding="utf-8",
    )
    with pytest.raises(GateACertificationError, match="transport"):
        load_gate_a_certification(
            config_path=config_path,
            evidence_path=evidence_path,
            status_path=status_path,
            now=FIXED_OPEN,
        )


def test_gate_a_wrong_approved_scope_not_open(gate_paths: tuple[Path, Path, Path]) -> None:
    config_path, evidence_path, status_path = gate_paths
    bad = _gate_config(
        approved_scope="WRONG-SCOPE",
        evidence_sha256=_evidence_sha256(evidence_path),
    )
    config_path.write_text(json.dumps(bad), encoding="utf-8")
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=datetime(2026, 7, 21, 18, 0, 0, tzinfo=UTC),
    )
    assert not cert.is_open_at(FIXED_OPEN)


def test_gate_a_certification_from_config_helper() -> None:
    recorded = datetime(2026, 7, 21, 17, 15, 29, 318950, tzinfo=UTC)
    cert = GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra (NC-1812)",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="0-b592e619a0",
        bsp_build="0-f371d30955",
        update_channel="Main",
        region="EA",
        component_set_digest=COMPONENT_DIGEST,
        device_fingerprint_digest=FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm=SSH_HOST_KEY_ALGORITHM,
        ssh_host_key_fingerprint_sha256=SSH_HOST_KEY_FINGERPRINT_SHA256,
        certification_eligible=True,
        evidence_recorded_at=recorded,
        evidence_path="ignored-evidence.json",
        expires_at=recorded + timedelta(days=90),
        revocation_policy="test",
        opening_freshness_hours=24,
    )
    assert cert.matches_probe_evidence(dict(CERTIFIED_EVIDENCE))


def test_gate_a_opening_freshness_closes_at_stale_wall_clock(
    gate_paths: tuple[Path, Path, Path],
) -> None:
    config_path, evidence_path, status_path = gate_paths
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED_OPEN,
    )
    assert cert.is_open_at(FIXED_OPEN)
    assert not cert.is_open_at(STALE_OPEN)
