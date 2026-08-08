"""VPN watchdog reapply startup-config backup parity tests."""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest
from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.startup_backup import StartupBackupError
from router_control.application import vpn_watchdog_service
from router_control.application.vpn_watchdog_service import VpnWatchdogHandle
from router_control.composition import create_offline_runtime
from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape
from router_control.persistence.errors import SealedApplyTrailBeginError
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import WifiLiveSession
from router_control_host.wireguard_apply_routes import (
    build_vpn_watchdog_backup_callback_factory,
)

_COMPONENT_DIGEST = "a" * 64
_FINGERPRINT_DIGEST = "b" * 64
_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


def _setup_watchdog(
    tmp_path: Any,
) -> tuple[VpnWatchdogHandle, str, WireguardIntent, dict[str, Any], Any]:
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-wd-backup.sqlite3")
    store = runtime.store
    site_id = store.create_site(display_name="VPN WD", now=datetime(2026, 8, 8, tzinfo=UTC))
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="VPN WD Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-vpn-wd",
        host="127.0.0.1",
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )
    profile_id = store.import_profile(
        display_name="WD profile",
        vpn_kind="AmneziaWG",
        content_digest="sha256:vpn-wd",
        metadata_json=json.dumps(
            {
                "wg_id": "Wireguard5",
                "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                "peer_endpoint": "example.com:51820",
                "peer_allow_ips": "0.0.0.0/0",
            }
        ),
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="awg_private_key",
        provider="MemoryVault",
        provider_locator="loc-vpn-wd-backup",
    )
    store.insert_profile_secret_refs(
        profile_id=profile_id,
        refs=[(cred_id, "PrivateKey")],
    )
    store.upsert_tunnel_assignment(
        router_id=router_id,
        profile_id=profile_id,
        desired_active=True,
        observed_vendor_locator="Wireguard5",
        policy_metadata_json='{"wg_id":"Wireguard5"}',
    )
    assignment = store.get_active_tunnel_assignment(router_id)
    assert assignment is not None
    host = type("Host", (), {"runtime": runtime})()
    handle = VpnWatchdogHandle(host=host)
    intent = WireguardIntent(
        wg_id="Wireguard5",
        enabled=True,
        peer_public_key="BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        peer_endpoint="example.com:51820",
        peer_allow_ips="0.0.0.0/0",
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )
    return handle, router_id, intent, assignment, store


class _Transport:
    def execute_rci_parse(self, _cmd: str) -> dict[str, Any]:
        return {}


def test_reapply_passes_backup_callback_and_invokes_before_apply(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, assignment, store = _setup_watchdog(tmp_path)
    order: list[str] = []
    captured: dict[str, Any] = {}

    def backup_cb() -> None:
        order.append("backup")

    handle.backup_callback_factory = lambda _rid: backup_cb

    def _fake_apply(**kwargs: Any) -> Any:
        captured.update(kwargs)
        if captured.get("backup_callback") is not None:
            captured["backup_callback"]()
        order.append("apply")
        from router_control.application.wireguard_apply_service import WireguardApplyResult

        return WireguardApplyResult(
            overall="applied",
            wg_id=intent.wg_id,
            steps=(),
            verification=None,
            errors=(),
            logs=(),
            verification_status="pending_live_verification",
            verification_notes=(),
            rollback=None,
        )

    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), assignment)  # noqa: SLF001
    assert captured["backup_callback"] is backup_cb
    assert order == ["backup", "apply"]
    assert captured.get("store") is store
    sealed = captured.get("sealed_apply_params")
    assert sealed is not None
    assert sealed.route == "vpn-profiles"
    assert sealed.verb == "watchdog_reapply"
    assert sealed.router_id == router_id


def test_reapply_fail_closed_when_backup_factory_returns_none(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, assignment, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run without backup")

    handle.backup_callback_factory = lambda _rid: None
    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), assignment)  # noqa: SLF001
    assert apply_called is False
    audit = store.conn.execute(
        "SELECT action, outcome FROM audit_events ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "vpn_watchdog.reapply"
    assert audit[1] == "failed"


def test_reapply_fail_closed_when_backup_factory_missing(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, assignment, store = _setup_watchdog(tmp_path)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run without backup factory")

    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), assignment)  # noqa: SLF001
    assert apply_called is False
    audit = store.conn.execute(
        "SELECT action, outcome FROM audit_events ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[1] == "failed"


def test_reapply_startup_backup_error_audited_without_success(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, assignment, store = _setup_watchdog(tmp_path)

    def backup_cb() -> None:
        raise StartupBackupError("backup vault unavailable")

    handle.backup_callback_factory = lambda _rid: backup_cb

    def _fake_apply(**kwargs: Any) -> Any:
        callback = kwargs.get("backup_callback")
        assert callback is not None
        callback()
        raise AssertionError("apply must abort when backup raises")

    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), assignment)  # noqa: SLF001
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "vpn_watchdog.reapply"
    assert audit[1] == "failed"
    assert "password" not in (audit[2] or "").lower()


def test_reapply_fail_closed_on_sealed_apply_trail_begin_error(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handle, router_id, intent, assignment, store = _setup_watchdog(tmp_path)

    handle.backup_callback_factory = lambda _rid: lambda: None

    def _fake_apply(**_kwargs: Any) -> Any:
        raise SealedApplyTrailBeginError("trail begin blocked")

    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    outcome, _verification = handle._reapply_locked(  # noqa: SLF001
        router_id, intent, _Transport(), assignment
    )
    assert outcome == "failed"
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "vpn_watchdog.reapply"
    assert audit[1] == "failed"
    assert "sealed apply trail begin failed" in (audit[2] or "").lower()


def _open_gate_a(*, evidence_path: str = "data/artifacts/gate-a-probe.json") -> GateACertification:
    now = datetime.now(UTC)
    return GateACertification(
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
        component_set_digest=_COMPONENT_DIGEST,
        device_fingerprint_digest=_FINGERPRINT_DIGEST,
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
        certification_eligible=True,
        evidence_recorded_at=now,
        evidence_path=evidence_path,
        expires_at=now + timedelta(days=90),
        revocation_policy="human",
        gates_b_closed=True,
        gates_c_closed=True,
        gates_d_closed=True,
    )


def _live_host(tmp_path: Any) -> tuple[HostState, str]:
    runtime = create_offline_runtime(db_path=tmp_path / "vpn-wd-factory.sqlite3")
    store = runtime.store
    now = datetime(2026, 8, 8, tzinfo=UTC)
    site_id = store.create_site(display_name="VPN WD Factory", now=now)
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="VPN WD Factory Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-vpn-wd-factory",
        host="192.168.2.1",
        source_address="192.168.2.10",
        now=now,
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="RouterAdmin",
        provider="memory",
        provider_locator="vpn-wd-factory-loc",
        now=now,
    )
    store.set_router_credential_ref(router_id, cred_id, now=now)
    store.set_endpoint_ssh_host_key(
        router_id,
        _VALID_SSH_HOST_KEY_SHA256,
        "ssh-ed25519",
        "operator_supplied",
        pinned_at=now.isoformat(),
    )
    host = HostState(
        runtime=runtime,
        adapter_mode="live",
        gate_a_certification=_open_gate_a(),
    )
    return host, router_id


def _patch_live_backup_mocks(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    @contextmanager
    def _mock_live(**_kwargs: object):
        tunnel = MagicMock()
        yield WifiLiveSession(transport=MagicMock(), tunnel=tunnel)

    def _mock_backup(**kwargs: Any) -> None:
        captured["certification"] = kwargs.get("certification")

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _mock_backup,
    )
    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    return captured


def test_backup_callback_factory_rereads_gate_a_on_invoke(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    captured = _patch_live_backup_mocks(monkeypatch)
    host.gate_a_certification = None
    factory = build_vpn_watchdog_backup_callback_factory(host)
    assert factory is not None
    assert factory(router_id) is None
    host.gate_a_certification = _open_gate_a()
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert captured["certification"] is host.gate_a_certification


def test_backup_callback_factory_live_uses_current_gate_a_cert(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    captured = _patch_live_backup_mocks(monkeypatch)
    factory = build_vpn_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert captured["certification"] is host.gate_a_certification


def test_backup_callback_factory_live_rereads_cert_after_refresh(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    captured = _patch_live_backup_mocks(monkeypatch)
    factory = build_vpn_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    original_cert = host.gate_a_certification
    refreshed_cert = _open_gate_a(evidence_path="data/artifacts/gate-a-refreshed.json")
    host.gate_a_certification = refreshed_cert
    callback()
    assert captured["certification"] is refreshed_cert
    assert captured["certification"] is not original_cert


def test_backup_callback_factory_live_raises_when_gate_a_closed(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    _patch_live_backup_mocks(monkeypatch)
    factory = build_vpn_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    host.gate_a_certification = None
    with pytest.raises(StartupBackupError, match="Gate A certification required"):
        callback()


def test_backup_callback_factory_injected_returns_noop(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    host.wireguard_apply_transport_factory = lambda: _Transport()
    backup_called = False

    def _fail_backup(**_kwargs: Any) -> None:
        nonlocal backup_called
        backup_called = True

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _fail_backup,
    )
    factory = build_vpn_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert backup_called is False


def test_backup_callback_factory_fake_returns_noop(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    host.adapter_mode = "fake"
    host.allow_fake_mutations = True
    backup_called = False

    def _fail_backup(**_kwargs: Any) -> None:
        nonlocal backup_called
        backup_called = True

    monkeypatch.setattr(
        "router_control_host.wireguard_apply_routes.backup_startup_config",
        _fail_backup,
    )
    factory = build_vpn_watchdog_backup_callback_factory(host)
    assert factory is not None
    callback = factory(router_id)
    assert callback is not None
    callback()
    assert backup_called is False


def test_reapply_aborts_when_assignment_cleared_before_lock(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Watchdog reapply must not apply when active assignment disappeared under lock."""
    handle, router_id, intent, assignment, store = _setup_watchdog(tmp_path)
    store.deactivate_tunnel_assignments(router_id)
    apply_called = False

    def _fake_apply(**_kwargs: Any) -> Any:
        nonlocal apply_called
        apply_called = True
        raise AssertionError("apply must not run when assignment is missing")

    handle.backup_callback_factory = lambda _rid: lambda: None
    monkeypatch.setattr(vpn_watchdog_service, "apply_wireguard_intent", _fake_apply)
    handle._reapply_locked(router_id, intent, _Transport(), assignment)  # noqa: SLF001
    assert apply_called is False
    audit = store.conn.execute(
        "SELECT action, outcome, summary_redacted FROM audit_events "
        "ORDER BY occurred_at DESC LIMIT 1"
    ).fetchone()
    assert audit is not None
    assert audit[0] == "vpn_watchdog.reapply"
    assert audit[1] == "failed"
    assert "missing under lock" in (audit[2] or "")
