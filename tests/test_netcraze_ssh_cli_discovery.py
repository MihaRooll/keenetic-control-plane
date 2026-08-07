"""Offline tests for read-only SSH CLI channel discovery library."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.ssh_cli_discovery import (
    AUTHORIZED_SOURCE_ADDRESS,
    CONTRACT_ID,
    GATE_A_EVIDENCE_SHA256,
    TYPED_OPERATIONS,
    SshCliDiscoveryError,
    SshCliDiscoveryReplayError,
    SshCliDiscoveryRunner,
    build_ssh_cli_discovery_artifact,
    consume_probe_id,
    load_ssh_cli_discovery_authorization,
    probe_marker_path,
)
from router_control.adapters.netcraze.ssh_tunnel import (
    ShowInterfaceHomeExecResult,
    ShowInterfaceHomeShellResult,
    exec_show_interface_home,
    shell_show_interface_home,
)

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
FORBIDDEN_RAW = b"show interface Home"
REPO_ROOT = Path(__file__).resolve().parents[1]
STATUS_PATH = REPO_ROOT / "docs" / "STATUS.yaml"
VERIFICATION_RECEIPTS_DIR = REPO_ROOT / "data" / "artifacts" / "verification-receipts"


def _status_yaml(
    *,
    b_status: str = "completed_failed",
    b_certification: str = "CertificationTrialAuthorized",
    b_not_write_certified: bool = True,
    c_status: str = "closed",
    d_status: str = "closed",
) -> str:
    return (
        "gates:\n"
        "  A:\n"
        "    status: open\n"
        "    certification: ReadOnlyCertified\n"
        "  B:\n"
        f"    status: {b_status}\n"
        f"    certification: {b_certification}\n"
        f"    not_write_certified: {'true' if b_not_write_certified else 'false'}\n"
        "  C:\n"
        f"    status: {c_status}\n"
        "  D:\n"
        f"    status: {d_status}\n"
    )


def _write_verification_receipt(*, contract_id: str = CONTRACT_ID) -> tuple[str, str]:
    VERIFICATION_RECEIPTS_DIR.mkdir(parents=True, exist_ok=True)
    name = f"test-ssh-cli-{uuid.uuid4().hex}.json"
    rel_path = f"data/artifacts/verification-receipts/{name}"
    abs_path = REPO_ROOT / rel_path
    payload = {
        "contract_id": contract_id,
        "p1_complete": True,
        "p2_complete": True,
        "p3_complete": True,
    }
    abs_path.write_text(json.dumps(payload), encoding="utf-8")
    digest = f"sha256:{hashlib.sha256(abs_path.read_bytes()).hexdigest()}"
    return rel_path, digest


def _attach_status_and_receipt(
    payload: dict[str, object],
    *,
    status_path: Path,
    receipt_rel_path: str,
    receipt_digest: str,
) -> None:
    payload["status_source_digest"] = (
        f"sha256:{hashlib.sha256(status_path.read_bytes()).hexdigest()}"
    )
    payload["verification_receipt_sha256"] = receipt_digest
    payload["verification_receipt_path"] = receipt_rel_path


def _sample_authorization(
    *,
    probe_id: str = "ssh-cli-discovery-test-001",
    b_status: str = "completed_failed",
    include_not_write_certified: bool = True,
) -> dict[str, object]:
    opens = datetime.now(UTC) - timedelta(minutes=5)
    expires = opens + timedelta(hours=1)
    gate_b: dict[str, object] = {"status": b_status}
    if include_not_write_certified and b_status == "completed_failed":
        gate_b["not_write_certified"] = True
    return {
        "contract_id": CONTRACT_ID,
        "human_decision": "approve",
        "probe_id": probe_id,
        "authorization_recorded_at": opens.isoformat(),
        "typed_operations": list(TYPED_OPERATIONS),
        "mutation_allowed": False,
        "source_address": AUTHORIZED_SOURCE_ADDRESS,
        "evidence_sha256": GATE_A_EVIDENCE_SHA256,
        "opens_at": opens.isoformat(),
        "expires_at": expires.isoformat(),
        "status_source_digest": "sha256:" + "a" * 64,
        "verification_receipt_sha256": "sha256:" + "b" * 64,
        "verification_receipt_path": "data/artifacts/verification-receipts/placeholder.json",
        "gates": {
            "B": gate_b,
            "C": {"status": "closed"},
            "D": {"status": "closed"},
        },
        "gate_a_tuple_binding": {
            "model": "NC-1812",
            "firmware_version": "5.01.C.1.0-0",
            "ndm_build": "0",
            "bsp_build": "0",
            "update_channel": "Main",
            "region": "EA",
            "component_set_digest": "sha256:" + "c" * 64,
            "device_fingerprint_digest": "sha256:" + "d" * 64,
            "transport": "ssh_tunnel",
            "ssh_host_key_algorithm": "ssh-ed25519",
        },
    }


@pytest.fixture
def aligned_auth_bundle(tmp_path: Path):
    created_receipts: list[Path] = []
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(), encoding="utf-8")
    rel_path, receipt_digest = _write_verification_receipt()
    created_receipts.append(REPO_ROOT / rel_path)

    def _build(**overrides: object) -> tuple[Path, dict[str, object]]:
        payload = _sample_authorization(**overrides)  # type: ignore[arg-type]
        _attach_status_and_receipt(
            payload,
            status_path=status_path,
            receipt_rel_path=rel_path,
            receipt_digest=receipt_digest,
        )
        auth_path = tmp_path / f"auth-{uuid.uuid4().hex}.json"
        auth_path.write_text(json.dumps(payload), encoding="utf-8")
        return auth_path, payload

    yield _build, status_path

    for receipt in created_receipts:
        receipt.unlink(missing_ok=True)


def _load_aligned(
    aligned_auth_bundle,
    *,
    status_path: Path | None = None,
    **overrides: object,
):
    build, default_status = aligned_auth_bundle
    auth_path, _payload = build(**overrides)
    return load_ssh_cli_discovery_authorization(
        config_path=auth_path,
        status_path=status_path or default_status,
        now=datetime.now(UTC),
    )


def test_authorization_rejects_mutation_allowed(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    payload["mutation_allowed"] = True
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="mutation_allowed"):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_authorization_rejects_wrong_source(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, _payload = build()
    payload = json.loads(auth_path.read_text(encoding="utf-8"))
    payload["source_address"] = "192.168.1.1"
    path = status_path.parent / "auth-source.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="source_address"):
        load_ssh_cli_discovery_authorization(
            config_path=path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_validate_runner_builds_non_certifying_artifact(aligned_auth_bundle) -> None:
    authorization = _load_aligned(aligned_auth_bundle)
    runner = SshCliDiscoveryRunner(
        authorization=authorization,
        validate_only=True,
        live_probe=False,
        now=datetime.now(UTC),
        source_address=AUTHORIZED_SOURCE_ADDRESS,
    )
    artifact = runner.run()
    assert artifact["certification_eligible"] is False
    assert artifact["mutation_performed"] is False
    assert artifact["result"] == "validated"
    assert artifact["contract_id"] == CONTRACT_ID
    serialized = json.dumps(artifact)
    assert SYNTH_PASSWORD not in serialized
    assert "show interface Home" not in serialized


def test_consume_probe_id_rejects_empty_marker(aligned_auth_bundle) -> None:
    authorization = _load_aligned(aligned_auth_bundle, probe_id="probe-empty-marker")
    marker = probe_marker_path(
        aligned_auth_bundle[1].parent / "probes",
        authorization.probe_id,
    )
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_bytes(b"")
    with pytest.raises(SshCliDiscoveryReplayError, match="empty marker"):
        consume_probe_id(
            authorization=authorization,
            probes_root=aligned_auth_bundle[1].parent / "probes",
        )


def test_exec_inactive_transport_is_inconclusive() -> None:
    transport = MagicMock()
    transport.is_active.return_value = False
    result = exec_show_interface_home(transport, password=SYNTH_PASSWORD)
    assert result.classification == "exec_inconclusive"
    assert result.error_code == "transport_inactive"


def test_shell_strips_echo_before_nonempty_claim() -> None:
    channel = MagicMock()
    channel.recv_ready.return_value = True
    prompt = b"(config)> "
    body = b"Interface Home state up\r\n"
    command_echo = b"show interface Home\r\n"
    channel.recv.side_effect = [
        prompt,
        command_echo + body + prompt,
        b"",
    ] + [b""] * 20
    transport = MagicMock()
    transport.is_active.return_value = True
    transport.open_session.return_value = channel
    channel.get_pty.return_value = None
    channel.invoke_shell.return_value = None
    channel.closed = True

    result = shell_show_interface_home(transport, password=SYNTH_PASSWORD, stage_timeout=0.2)
    assert result.echo_stripped is True
    assert result.response_body_nonempty is True
    assert result.classification == "shell_framing_observed"
    assert FORBIDDEN_RAW.decode("ascii") not in json.dumps(
        {
            "response_body_sha256": result.response_body_sha256,
            "response_body_byte_count": result.response_body_byte_count,
        }
    )


def test_live_runner_uses_mock_transport_without_network(aligned_auth_bundle) -> None:
    authorization = _load_aligned(aligned_auth_bundle, probe_id="probe-live-mock")
    key_bytes = b"pinned-discovery-key"

    class _FakeDiscoveryKey:
        def get_name(self) -> str:
            return "ssh-ed25519"

        def asbytes(self) -> bytes:
            return key_bytes

    fake_key = _FakeDiscoveryKey()
    digest = __import__("hashlib").sha256(key_bytes).digest()
    import base64

    fingerprint = f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"
    fake_transport = MagicMock()
    fake_transport.is_active.return_value = True
    fake_transport.get_remote_server_key.return_value = fake_key
    fake_transport.close.return_value = None

    class _Vault:
        def use(self, _ref: str) -> str:
            return SYNTH_PASSWORD

    runner = SshCliDiscoveryRunner(
        authorization=authorization,
        gate_a=MagicMock(
            model="NC-1812",
            firmware_version="5.01.C.1.0-0",
            ndm_build="0",
            component_set_digest="sha256:" + "c" * 64,
            device_fingerprint_digest="sha256:" + "d" * 64,
            ssh_host_key_algorithm="ssh-ed25519",
            ssh_host_key_fingerprint_sha256=fingerprint,
        ),
        host="192.168.1.1",
        username="lab-user",
        credential_ref="cred-ref",
        host_key_pin=fingerprint,
        vault=_Vault(),
        probe_evidence={
            "model": "NC-1812",
            "firmware_version": "5.01.C.1.0-0",
            "build": "0",
            "bsp_build": "0",
            "update_channel": "Main",
            "region": "EA",
            "component_set_digest": "sha256:" + "c" * 64,
            "device_fingerprint_digest": "sha256:" + "d" * 64,
            "transport_security": "ssh_tunnel",
            "ssh_host_key_algorithm": "ssh-ed25519",
        },
        validate_only=False,
        live_probe=True,
        probes_root=aligned_auth_bundle[1].parent / "probes",
        transport_factory=lambda _cfg: fake_transport,
        exec_runner=lambda _transport, password: _exec_supported(),
        shell_runner=lambda _transport, password: _shell_observed(),
        now=datetime.now(UTC),
        source_address=AUTHORIZED_SOURCE_ADDRESS,
    )
    artifact = runner.run()
    assert artifact["result"] == "probed"
    assert artifact["exec_candidate"]["classification"] == "exec_supported"
    assert artifact["shell_candidate"]["classification"] == "shell_framing_observed"
    assert (aligned_auth_bundle[1].parent / "probes" / "probe-live-mock.consumed").is_file()


def test_artifact_allowlist_only() -> None:
    artifact = build_ssh_cli_discovery_artifact(
        authorization=None,
        result="validated",
        recorded_at=datetime(2099, 1, 1, tzinfo=UTC),
        source_address=AUTHORIZED_SOURCE_ADDRESS,
        gate_a_tuple_digest="sha256:" + "0" * 64,
        gate_a_evidence_digest="sha256:" + "1" * 64,
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:fixture",
    )
    assert set(artifact.keys()) <= {
        "artifact_type",
        "contract_id",
        "probe_id",
        "result",
        "recorded_at",
        "certification_eligible",
        "mutation_performed",
        "source_address",
        "source_address_class",
        "gate_a_tuple_digest",
        "gate_a_evidence_digest",
        "evidence_sha256",
        "ssh_host_key_algorithm",
        "ssh_host_key_fingerprint_sha256",
        "transport_security",
        "timing_bounds",
    }


def _exec_supported() -> ShowInterfaceHomeExecResult:
    return ShowInterfaceHomeExecResult(
        classification="exec_supported",
        channel_opened=True,
        exec_dispatched=True,
        exit_status_observed=True,
        exit_status=0,
        stdout_byte_count=128,
        stderr_byte_count=0,
        stdout_sha256="sha256:" + "1" * 64,
        stderr_sha256="sha256:" + "0" * 64,
        response_body_byte_count=128,
        response_body_sha256="sha256:" + "1" * 64,
        response_body_nonempty=True,
        truncated=False,
        timed_out=False,
        channel_closed_verified=True,
        error_code=None,
    )


def _shell_observed() -> ShowInterfaceHomeShellResult:
    return ShowInterfaceHomeShellResult(
        classification="shell_framing_observed",
        pty_allocated=True,
        shell_invoked=True,
        initial_prompt_observed=True,
        command_sent=True,
        prompt_return_observed=True,
        response_body_byte_count=96,
        response_body_sha256="sha256:" + "2" * 64,
        response_body_nonempty=True,
        echo_stripped=True,
        truncated=False,
        timed_out=False,
        prompt_ambiguous=False,
        channel_closed_verified=True,
        error_code=None,
    )


@pytest.mark.parametrize(
    ("status_kwargs", "match"),
    [
        ({"b_status": "open"}, "Gate B must not be open"),
        ({"b_status": "certification_trial_authorized"}, "certification_trial_authorized"),
        ({"b_certification": "WriteCertified"}, "WriteCertified"),
        ({"b_not_write_certified": False}, "not_write_certified true"),
        ({"c_status": "open"}, "Gate C must be closed"),
        ({"d_status": "open"}, "Gate D must be closed"),
    ],
)
def test_status_gate_negatives(tmp_path: Path, status_kwargs: dict, match: str) -> None:
    status_path = tmp_path / "STATUS.yaml"
    status_path.write_text(_status_yaml(**status_kwargs), encoding="utf-8")
    rel_path, receipt_digest = _write_verification_receipt()
    try:
        payload = _sample_authorization()
        _attach_status_and_receipt(
            payload,
            status_path=status_path,
            receipt_rel_path=rel_path,
            receipt_digest=receipt_digest,
        )
        auth_path = tmp_path / "auth.json"
        auth_path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(SshCliDiscoveryError, match=match):
            load_ssh_cli_discovery_authorization(
                config_path=auth_path,
                status_path=status_path,
                now=datetime.now(UTC),
            )
    finally:
        (REPO_ROOT / rel_path).unlink(missing_ok=True)


def test_auth_gate_b_closed_mismatch_with_status_completed_failed(
    aligned_auth_bundle,
) -> None:
    build, status_path = aligned_auth_bundle
    with pytest.raises(SshCliDiscoveryError, match="gates.B.status must match"):
        _load_aligned(aligned_auth_bundle, b_status="closed")


def test_status_source_digest_mismatch(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    payload["status_source_digest"] = "sha256:" + "f" * 64
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="status_source_digest mismatch"):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_verification_receipt_missing_file(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    payload["verification_receipt_path"] = (
        "data/artifacts/verification-receipts/missing-test-receipt.json"
    )
    payload["verification_receipt_sha256"] = "sha256:" + "0" * 64
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="verification receipt not found"):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_verification_receipt_digest_mismatch(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    payload["verification_receipt_sha256"] = "sha256:" + "0" * 64
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="verification_receipt_sha256 mismatch"):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_verification_receipt_missing_p3(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    receipt_path = REPO_ROOT / str(payload["verification_receipt_path"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_payload["p3_complete"] = False
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")
    payload["verification_receipt_sha256"] = (
        f"sha256:{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}"
    )
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="p3_complete"):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_verification_receipt_contract_id_mismatch(aligned_auth_bundle) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    receipt_path = REPO_ROOT / str(payload["verification_receipt_path"])
    receipt_payload = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt_payload["contract_id"] = "other-contract"
    receipt_path.write_text(json.dumps(receipt_payload), encoding="utf-8")
    payload["verification_receipt_sha256"] = (
        f"sha256:{hashlib.sha256(receipt_path.read_bytes()).hexdigest()}"
    )
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match="contract_id mismatch"):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


@pytest.mark.parametrize(
    ("receipt_path", "match"),
    [
        ("/etc/passwd", "must be relative"),
        ("data/artifacts/verification-receipts/../gate-a-certification.json", "must not traverse"),
        ("docs/verification-receipt.json", "verification-receipts"),
        ("C:\\data\\artifacts\\verification-receipts\\x.json", "forward slashes"),
    ],
)
def test_verification_receipt_path_rejected(
    aligned_auth_bundle,
    receipt_path: str,
    match: str,
) -> None:
    build, status_path = aligned_auth_bundle
    auth_path, payload = build()
    payload["verification_receipt_path"] = receipt_path
    auth_path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(SshCliDiscoveryError, match=match):
        load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=status_path,
            now=datetime.now(UTC),
        )


def test_load_with_real_status_yaml(aligned_auth_bundle) -> None:
    rel_path, receipt_digest = _write_verification_receipt()
    try:
        payload = _sample_authorization()
        _attach_status_and_receipt(
            payload,
            status_path=STATUS_PATH,
            receipt_rel_path=rel_path,
            receipt_digest=receipt_digest,
        )
        auth_path = aligned_auth_bundle[1].parent / "real-status-auth.json"
        auth_path.write_text(json.dumps(payload), encoding="utf-8")
        authorization = load_ssh_cli_discovery_authorization(
            config_path=auth_path,
            status_path=STATUS_PATH,
            now=datetime.now(UTC),
        )
        assert authorization.gate_b_status == "completed_failed"
    finally:
        (REPO_ROOT / rel_path).unlink(missing_ok=True)
