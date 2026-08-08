"""Live Gate A host integration tests with mocked probe (no network)."""

from __future__ import annotations

import hashlib
import json
import socket
from datetime import UTC, datetime
from pathlib import Path

import pytest
from router_control.adapters.netcraze.certification import load_gate_a_certification
from router_control.adapters.netcraze.live_probe import LiveProbeTarget
from router_control.adapters.secrets.memory import MemoryVault
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

from tests.test_gate_a_certification import CERTIFIED_EVIDENCE, _gate_config

FIXED_NOW = datetime(2026, 7, 23, 6, 0, 0, tzinfo=UTC)


def _freeze_gate_a_openness(monkeypatch: pytest.MonkeyPatch) -> None:
    from router_control.adapters.netcraze import certification as gate_mod

    monkeypatch.setattr(gate_mod, "_OPENNESS_CLOCK", lambda: FIXED_NOW)


def _passthrough_source_bind(source_address: str, **kwargs: object) -> str:
    return source_address


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


def _mock_probe_fn(target: LiveProbeTarget) -> dict[str, object]:
    assert target.ssh_host == "192.168.1.1"
    assert target.source_address == "192.168.2.10"
    return dict(CERTIFIED_EVIDENCE)


def _enroll_body(**overrides: object) -> dict[str, object]:
    body: dict[str, object] = {
        "display_name": "Gate A Router",
        "vendor": "Netcraze",
        "model": "NC-1812",
        "endpoint": {
            "kind": "management_https",
            "host": "192.168.1.1",
            "port": 443,
            "username": "lab-user",
            "source_address": "192.168.2.10",
        },
        "management_password": "never-echo",
    }
    body.update(overrides)
    return body


@pytest.fixture
def live_open_app(
    tmp_path,
    gate_paths,
    monkeypatch: pytest.MonkeyPatch,
):
    _freeze_gate_a_openness(monkeypatch)
    monkeypatch.setattr(
        "router_control_host.routes.preflight_source_address_bind",
        _passthrough_source_bind,
    )
    config_path, evidence_path, status_path = gate_paths
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ADAPTER_MODE", "live")
    monkeypatch.setenv("RC_NETCRAZE_USERNAME", "lab-user")
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED_NOW,
    )
    return create_app(
        db_path=tmp_path / "live-open.sqlite3",
        adapter_mode="live",
        gate_a_certification=cert,
        read_only_probe_fn=_mock_probe_fn,
        skip_gate_a_load=True,
        vault=MemoryVault(),
    )


@pytest.fixture
def live_open_client(live_open_app):
    from fastapi.testclient import TestClient

    with TestClient(live_open_app) as c:
        c.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield c


def _forbid_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def _forbid(*args: object, **kwargs: object) -> None:
        raise AssertionError("network transport must not be used in mocked live tests")

    monkeypatch.setattr(socket.socket, "connect", _forbid)
    monkeypatch.setattr(socket, "create_connection", _forbid)


def test_live_preflight_source_address_mismatch_rejects_before_probe(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = live_open_client.app.state.host.runtime.vault
    probe_calls: list[str] = []

    def counting_probe(target: LiveProbeTarget) -> dict[str, object]:
        probe_calls.append("probe")
        return dict(CERTIFIED_EVIDENCE)

    _forbid_network(monkeypatch)
    enroll = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "preflight-mismatch-seed"},
    )
    assert enroll.status_code == 202
    router_id = enroll.json()["router_id"]
    secrets_after_enroll = len(vault._secrets)

    live_open_client.app.state.host.read_only_probe_fn = counting_probe
    r = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"source_address": "192.168.1.145", "observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-source-mismatch"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "request.validation_failed"
    assert r.json()["error"]["message"] == "source_address mismatch with enrolled endpoint"
    assert len(vault._secrets) == secrets_after_enroll
    assert len(probe_calls) == 0


def test_live_enroll_missing_source_address_rejects_before_vault(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = live_open_client.app.state.host.runtime.vault
    probe_calls: list[str] = []

    def counting_probe(target: LiveProbeTarget) -> dict[str, object]:
        probe_calls.append("probe")
        return dict(CERTIFIED_EVIDENCE)

    live_open_client.app.state.host.read_only_probe_fn = counting_probe
    _forbid_network(monkeypatch)
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json={
            "display_name": "Gate A Router",
            "vendor": "Netcraze",
            "model": "NC-1812",
            "endpoint": {
                "kind": "management_https",
                "host": "192.168.1.1",
                "port": 443,
                "username": "lab-user",
            },
            "management_password": "never-echo",
        },
        headers={"Idempotency-Key": "live-enroll-missing-source"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "request.validation_failed"
    assert "source_address" in r.json()["error"]["message"]
    assert len(vault._secrets) == 0
    assert len(probe_calls) == 0


def test_live_enroll_with_mock_probe(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_network(monkeypatch)
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "live-enroll-open"},
    )
    assert r.status_code == 202
    body = r.json()
    assert body["status"] == "Succeeded"
    assert body["certification_status"] == "ReadOnlyCertified"
    assert body["lifecycle_status"] == "Enrolled"
    assert "never-echo" not in r.text


def test_live_enroll_with_existing_credential_ref(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = live_open_client.app.state.host.runtime.vault
    handle = vault.create(kind="RouterManagementPassword", secret="dpapi-prestored")
    _forbid_network(monkeypatch)
    body = _enroll_body()
    body.pop("management_password")
    body["credential_ref_id"] = handle.credential_ref_id
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "live-enroll-cred-ref"},
    )
    assert r.status_code == 202
    assert r.json()["certification_status"] == "ReadOnlyCertified"
    assert len(vault._secrets) == 1


def test_live_enroll_idempotency_before_probe(
    live_open_app, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def counting_probe(target: LiveProbeTarget) -> dict[str, object]:
        calls.append("probe")
        return dict(CERTIFIED_EVIDENCE)

    live_open_app.state.host.read_only_probe_fn = counting_probe
    from fastapi.testclient import TestClient

    with TestClient(live_open_app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        _forbid_network(monkeypatch)
        body = _enroll_body()
        first = client.post(
            "/api/router-control/v1/routers",
            json=body,
            headers={"Idempotency-Key": "enroll-idem-probe"},
        )
        assert first.status_code == 202
        second = client.post(
            "/api/router-control/v1/routers",
            json=body,
            headers={"Idempotency-Key": "enroll-idem-probe"},
        )
        assert second.status_code == 202
    assert len(calls) == 1


def test_live_enroll_probe_mismatch_rolls_back(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = live_open_client.app.state.host.runtime.vault
    assert len(vault._secrets) == 0

    def bad_probe(target: LiveProbeTarget) -> dict[str, object]:
        evidence = dict(CERTIFIED_EVIDENCE)
        evidence["model"] = "WRONG"
        return evidence

    live_open_client.app.state.host.read_only_probe_fn = bad_probe
    _forbid_network(monkeypatch)
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "live-enroll-mismatch"},
    )
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "router.identity_mismatch"
    routers = live_open_client.get("/api/router-control/v1/routers").json()["items"]
    assert len(routers) == 1
    assert routers[0]["lifecycle_status"] == "IdentityMismatch"
    assert len(vault._secrets) == 0


def test_live_enroll_probe_exception_sanitized_idempotency_replay(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_marker = "leaked-enroll-credential-marker"

    def failing_probe(target: LiveProbeTarget) -> dict[str, object]:
        raise RuntimeError(f"ssh auth failed password={secret_marker}")

    live_open_client.app.state.host.read_only_probe_fn = failing_probe
    _forbid_network(monkeypatch)
    body = _enroll_body()
    first = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "live-enroll-probe-exc"},
    )
    assert first.status_code == 422
    assert first.json()["error"]["message"] == "live enroll identity probe failed"
    assert secret_marker not in first.text

    second = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "live-enroll-probe-exc"},
    )
    assert second.status_code == 422
    assert secret_marker not in second.text
    assert second.json()["error"]["message"] == "live enroll identity probe failed"


def test_live_preflight_sync_success(live_open_client, monkeypatch: pytest.MonkeyPatch) -> None:
    _forbid_network(monkeypatch)
    enroll = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "preflight-seed"},
    )
    router_id = enroll.json()["router_id"]
    pf = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-open"},
    )
    assert pf.status_code == 200
    assert pf.json()["status"] == "Succeeded"
    assert "observation_id" in pf.json()


def test_live_preflight_missing_username_no_replayable_queued(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_network(monkeypatch)
    enroll = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "preflight-seed-no-user"},
    )
    router_id = enroll.json()["router_id"]
    monkeypatch.delenv("RC_NETCRAZE_USERNAME", raising=False)
    first = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-missing-user"},
    )
    assert first.status_code == 400
    assert first.json()["error"]["code"] == "request.validation_failed"
    second = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-missing-user"},
    )
    assert second.status_code == 400
    assert second.json()["error"]["code"] == "request.validation_failed"
    assert "status" not in second.json()


def test_live_preflight_probe_fail_terminal_replay(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret_marker = "leaked-preflight-credential-marker"

    def failing_probe(target: LiveProbeTarget) -> dict[str, object]:
        raise RuntimeError(f"probe failed password={secret_marker}")

    _forbid_network(monkeypatch)
    enroll = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "preflight-seed-probe-fail"},
    )
    router_id = enroll.json()["router_id"]
    live_open_client.app.state.host.read_only_probe_fn = failing_probe
    first = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-probe-fail"},
    )
    assert first.status_code == 422
    assert secret_marker not in first.text
    second = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-probe-fail"},
    )
    assert second.status_code == 422
    assert secret_marker not in second.text
    assert second.json()["error"]["message"] == "live preflight identity probe failed"


def test_live_apply_forbidden_even_with_fake_mutations_env(
    tmp_path, monkeypatch: pytest.MonkeyPatch, gate_paths
) -> None:
    config_path, evidence_path, status_path = gate_paths
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    cert = load_gate_a_certification(
        config_path=config_path,
        evidence_path=evidence_path,
        status_path=status_path,
        now=FIXED_NOW,
    )
    app = create_app(
        db_path=tmp_path / "live-mut.sqlite3",
        adapter_mode="live",
        gate_a_certification=cert,
        read_only_probe_fn=_mock_probe_fn,
        skip_gate_a_load=True,
        allow_fake_mutations=True,
        vault=MemoryVault(),
    )
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        r = client.post(
            "/api/router-control/v1/routers/rtr_x/plans/plan_x/apply",
            json={},
            headers={"Idempotency-Key": "live-apply", "If-Match": "x"},
        )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "gate.mutation_forbidden"


def test_status_reports_sanitized_gate_a(live_open_client) -> None:
    r = live_open_client.get("/api/router-control/v1/status")
    assert r.status_code == 200
    body = r.json()
    assert body["gate_a"]["status"] == "open"
    assert body["gates"]["B"] == "closed"
    assert "password" not in r.text.lower()


def test_live_app_env_status_bypass_does_not_construct_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import router_control_host.app as host_app_module

    config_path = tmp_path / "gate-a.json"
    evidence_path = tmp_path / "evidence.json"
    status_path = tmp_path / "STATUS.yaml"
    evidence_path.write_text(json.dumps(CERTIFIED_EVIDENCE), encoding="utf-8")
    config_path.write_text(
        json.dumps(
            _gate_config(
                evidence_path=str(evidence_path),
                evidence_sha256=hashlib.sha256(evidence_path.read_bytes()).hexdigest(),
            )
        ),
        encoding="utf-8",
    )
    status_path.write_text(
        "gates:\n  A:\n    status: closed\n  B:\n    status: open\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RC_GATE_A_CONFIG", str(config_path))
    monkeypatch.setenv("RC_GATE_A_EVIDENCE", str(evidence_path))
    monkeypatch.setenv("RC_STATUS_PATH", str(status_path))
    monkeypatch.setenv("RC_GATE_A_SKIP_STATUS", "1")
    _forbid_network(monkeypatch)

    probe_constructions: list[str] = []

    def fail_if_probe_constructed(*args: object, **kwargs: object) -> None:
        probe_constructions.append("constructed")
        raise AssertionError("live probe must not be constructed while STATUS Gate A is closed")

    monkeypatch.setattr(
        host_app_module,
        "build_pinned_ssh_probe_fn",
        fail_if_probe_constructed,
    )
    vault = MemoryVault()
    app = create_app(
        db_path=tmp_path / "status-bypass.sqlite3",
        adapter_mode="live",
        vault=vault,
    )

    assert app.state.host.gate_a_certification is None
    assert app.state.host.read_only_probe_fn is None
    assert probe_constructions == []
    assert vault._secrets == {}


def test_live_app_env_evidence_bypass_does_not_construct_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import router_control_host.app as host_app_module

    config_path = tmp_path / "gate-a.json"
    missing_evidence = tmp_path / "missing-evidence.json"
    status_path = tmp_path / "STATUS.yaml"
    config_path.write_text(
        json.dumps(
            _gate_config(
                evidence_path=str(missing_evidence),
                evidence_sha256="a" * 64,
            )
        ),
        encoding="utf-8",
    )
    status_path.write_text(
        "gates:\n  A:\n    status: open\n    certification: ReadOnlyCertified\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("RC_GATE_A_CONFIG", str(config_path))
    monkeypatch.setenv("RC_GATE_A_EVIDENCE", str(missing_evidence))
    monkeypatch.setenv("RC_STATUS_PATH", str(status_path))
    monkeypatch.setenv("RC_GATE_A_SKIP_EVIDENCE", "1")
    _forbid_network(monkeypatch)

    probe_constructions: list[str] = []

    def fail_if_probe_constructed(*args: object, **kwargs: object) -> None:
        probe_constructions.append("constructed")
        raise AssertionError("live probe must not be constructed without evidence")

    monkeypatch.setattr(
        host_app_module,
        "build_pinned_ssh_probe_fn",
        fail_if_probe_constructed,
    )
    vault = MemoryVault()
    app = create_app(
        db_path=tmp_path / "evidence-bypass.sqlite3",
        adapter_mode="live",
        vault=vault,
    )

    assert app.state.host.gate_a_certification is None
    assert app.state.host.read_only_probe_fn is None
    assert probe_constructions == []
    assert vault._secrets == {}


def test_live_enroll_create_conflict_loser_returns_in_progress(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent enroll loser (peek miss, null response_ref) must not return 202 empty."""
    from router_control.persistence.store import IdempotencyOutcome

    store = live_open_client.app.state.host.runtime.store
    loser = IdempotencyOutcome(
        created=False,
        operation_id="op_enroll_race",
        job_id="job_enroll_race",
        idempotency_record_id="idem_enroll_race",
        status="InProgress",
        response_ref=None,
    )
    monkeypatch.setattr(store, "peek_idempotency", lambda **_kwargs: None)
    monkeypatch.setattr(
        store,
        "enroll_router_with_operation",
        lambda **_kwargs: ("rtr_race", loser),
    )
    _forbid_network(monkeypatch)
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "live-enroll-create-race"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency.in_progress"
    assert r.json() != {}


def test_live_preflight_create_conflict_loser_returns_in_progress_no_probe(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Concurrent preflight loser must 409 in_progress and must not run a second probe."""
    from router_control.persistence.store import IdempotencyOutcome

    _forbid_network(monkeypatch)
    enroll = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "preflight-race-seed"},
    )
    assert enroll.status_code == 202
    router_id = enroll.json()["router_id"]

    probe_calls: list[str] = []

    def counting_probe(target: LiveProbeTarget) -> dict[str, object]:
        probe_calls.append("probe")
        return dict(CERTIFIED_EVIDENCE)

    live_open_client.app.state.host.read_only_probe_fn = counting_probe

    store = live_open_client.app.state.host.runtime.store
    loser = IdempotencyOutcome(
        created=False,
        operation_id="op_pf_race",
        job_id="job_pf_race",
        idempotency_record_id="idem_pf_race",
        status="InProgress",
        response_ref=None,
    )
    real_create = store.create_operation_bundle

    def create_with_preflight_race(**kwargs: object) -> IdempotencyOutcome:
        if kwargs.get("operation_kind") == "preflight":
            return loser
        return real_create(**kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store, "peek_idempotency", lambda **_kwargs: None)
    monkeypatch.setattr(store, "create_operation_bundle", create_with_preflight_race)

    r = live_open_client.post(
        f"/api/router-control/v1/routers/{router_id}/preflight",
        json={"observation_ttl_seconds": 300},
        headers={"Idempotency-Key": "live-pf-create-race"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "idempotency.in_progress"
    assert len(probe_calls) == 0


@pytest.mark.parametrize(
    "bad_host",
    [
        "127.0.0.1",
        "::1",
        "[::1]",
        "localhost",
        "127.1",
        "0177.0.0.1",
        "127.000.000.001",
    ],
)
def test_live_enroll_rejects_malformed_hosts_before_side_effects(
    live_open_client,
    monkeypatch: pytest.MonkeyPatch,
    bad_host: str,
) -> None:
    vault = live_open_client.app.state.host.runtime.vault
    store = live_open_client.app.state.host.runtime.store
    probe_calls: list[str] = []

    def counting_probe(target: LiveProbeTarget) -> dict[str, object]:
        probe_calls.append("probe")
        return dict(CERTIFIED_EVIDENCE)

    live_open_client.app.state.host.read_only_probe_fn = counting_probe
    _forbid_network(monkeypatch)
    body = _enroll_body()
    body["endpoint"] = {
        "kind": "management_https",
        "host": bad_host,
        "port": 443,
        "username": "lab-user",
    }
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": f"live-enroll-bad-host-{bad_host}"},
    )
    assert r.status_code == 400
    assert r.json()["error"]["code"] == "request.validation_failed"
    assert len(vault._secrets) == 0
    assert len(store.list_routers()) == 0
    assert len(probe_calls) == 0


def test_live_enroll_accepts_valid_private_host(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    _forbid_network(monkeypatch)
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "live-enroll-valid-private"},
    )
    assert r.status_code == 202
    assert r.json()["certification_status"] == "ReadOnlyCertified"


def test_live_enroll_rejects_non_private_literal_host(
    live_open_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public literal management host → 422 endpoint.host_not_private, no side effects."""
    vault = live_open_client.app.state.host.runtime.vault
    store = live_open_client.app.state.host.runtime.store
    probe_calls: list[str] = []

    def counting_probe(target: LiveProbeTarget) -> dict[str, object]:
        probe_calls.append("probe")
        return dict(CERTIFIED_EVIDENCE)

    live_open_client.app.state.host.read_only_probe_fn = counting_probe
    _forbid_network(monkeypatch)
    body = _enroll_body()
    body["endpoint"] = {
        "kind": "management_https",
        "host": "8.8.8.8",
        "port": 443,
        "username": "lab-user",
        "source_address": "192.168.2.10",
    }
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "live-enroll-public-literal"},
    )
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "endpoint.host_not_private"
    assert err["message"] == "endpoint.host must be a private management address"
    assert len(vault._secrets) == 0
    assert len(store.list_routers()) == 0
    assert len(probe_calls) == 0


def test_live_enroll_rejects_public_hostname_resolve_fail_closed(
    live_open_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hostname resolving to public addresses → 422 endpoint.host_not_private."""
    vault = live_open_client.app.state.host.runtime.vault
    store = live_open_client.app.state.host.runtime.store
    _forbid_network(monkeypatch)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 0)),
        ],
    )
    body = _enroll_body()
    body["endpoint"] = {
        "kind": "management_https",
        "host": "example.com",
        "port": 443,
        "username": "lab-user",
        "source_address": "192.168.2.10",
    }
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "live-enroll-public-hostname"},
    )
    assert r.status_code == 422
    err = r.json()["error"]
    assert err["code"] == "endpoint.host_not_private"
    assert len(vault._secrets) == 0
    assert len(store.list_routers()) == 0


def test_live_enroll_probe_failure_removes_orphan_credential_ref(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = live_open_client.app.state.host.runtime.vault

    def bad_probe(target: LiveProbeTarget) -> dict[str, object]:
        evidence = dict(CERTIFIED_EVIDENCE)
        evidence["model"] = "WRONG"
        return evidence

    live_open_client.app.state.host.read_only_probe_fn = bad_probe
    _forbid_network(monkeypatch)
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=_enroll_body(),
        headers={"Idempotency-Key": "live-enroll-orphan-cleanup"},
    )
    assert r.status_code == 422
    routers = live_open_client.get("/api/router-control/v1/routers").json()["items"]
    assert len(routers) == 1
    router_id = routers[0]["router_id"]
    creds = live_open_client.get(
        f"/api/router-control/v1/routers/{router_id}/credentials"
    ).json()["items"]
    assert creds == []
    assert len(vault._secrets) == 0


def test_live_enroll_probe_failure_preserves_supplied_credential_ref(
    live_open_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    vault = live_open_client.app.state.host.runtime.vault
    handle = vault.create(kind="RouterManagementPassword", secret="preexisting-secret")

    def bad_probe(target: LiveProbeTarget) -> dict[str, object]:
        evidence = dict(CERTIFIED_EVIDENCE)
        evidence["model"] = "WRONG"
        return evidence

    live_open_client.app.state.host.read_only_probe_fn = bad_probe
    _forbid_network(monkeypatch)
    body = _enroll_body()
    body.pop("management_password")
    body["credential_ref_id"] = handle.credential_ref_id
    r = live_open_client.post(
        "/api/router-control/v1/routers",
        json=body,
        headers={"Idempotency-Key": "live-enroll-preserve-supplied-ref"},
    )
    assert r.status_code == 422
    assert handle.credential_ref_id in vault._secrets
    vault.use(handle.credential_ref_id)


def test_live_runtime_uses_system_clock_by_default(tmp_path: Path) -> None:
    from router_control.composition import create_live_runtime
    from router_control.ports.clock import SystemClock

    runtime = create_live_runtime(
        db_path=tmp_path / "system-clock.sqlite3",
        vault=MemoryVault(),
    )
    assert isinstance(runtime.clock, SystemClock)


def test_observation_ttl_expires_with_wall_time(tmp_path: Path) -> None:
    import time

    from router_control.composition import create_live_runtime
    from router_control.ports.clock import SystemClock

    runtime = create_live_runtime(
        db_path=tmp_path / "ttl.sqlite3",
        vault=MemoryVault(),
    )
    assert isinstance(runtime.clock, SystemClock)
    now = runtime.clock.now()
    site_id = runtime.store.create_site(display_name="ttl-site", now=now)
    router_id = runtime.store.enroll_router(
        site_id=site_id,
        display_name="ttl-router",
        vendor="Netcraze",
        model="NC-1812",
        identity_fingerprint="digest:ttl",
        host="192.168.1.1",
        now=now,
    )
    observation_id = runtime.store.insert_observation(
        router_id=router_id,
        identity_fingerprint="digest:ttl",
        resource_version="v1",
        state_digest="sha256:abc",
        ttl_seconds=1,
        now=now,
    )
    obs = runtime.store.get_observation(observation_id)
    assert obs is not None
    time.sleep(1.2)
    expired = runtime.store.get_observation(observation_id)
    assert expired is not None
    valid_until = datetime.fromisoformat(str(expired["valid_until"]).replace("Z", "+00:00"))
    assert valid_until <= runtime.clock.now()
