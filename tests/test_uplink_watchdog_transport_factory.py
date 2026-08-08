"""Uplink watchdog observe/apply transport factory parity tests."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock

import pytest

from router_control.adapters.netcraze.certification import GateACertification
from router_control.composition import create_offline_runtime
from router_control_host.state import HostState
from router_control_host.wifi_live_transport import WifiLiveSession
from router_control_host.wifi_station_apply_routes import (
    _EphemeralLiveInternetStatusTransport,
    _EphemeralLiveStationApplyTransport,
    build_uplink_watchdog_apply_transport_factory,
    build_uplink_watchdog_observe_transport_factory,
)

_COMPONENT_DIGEST = "a" * 64
_FINGERPRINT_DIGEST = "b" * 64
_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"


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
    runtime = create_offline_runtime(db_path=tmp_path / "uplink-wd-transport.sqlite3")
    store = runtime.store
    now = datetime(2026, 8, 8, tzinfo=UTC)
    site_id = store.create_site(display_name="Uplink WD Transport", now=now)
    router_id = store.enroll_router(
        site_id=site_id,
        display_name="Uplink WD Transport Router",
        vendor="Keenetic",
        model="NC-1812",
        identity_fingerprint="fp-uplink-wd-transport",
        host="192.168.2.1",
        source_address="192.168.2.10",
        now=now,
    )
    cred_id = store.insert_credential_ref(
        router_id=router_id,
        kind="WifiApPsk",
        provider="memory",
        provider_locator="uplink-wd-transport-loc",
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


def _patch_live_session_mocks(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    inner = MagicMock()
    inner.execute_rci_parse.return_value = {"internet": "yes", "interface": "WifiMaster1/WifiStation0"}
    inner.execute_sealed_rci_write.return_value = [{"parse": {"status": []}}]

    @contextmanager
    def _mock_live(**_kwargs: object):
        yield WifiLiveSession(transport=inner, tunnel=MagicMock())

    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.open_wifi_live_session",
        _mock_live,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "router_control_host.wifi_station_apply_routes.is_win32_live_capable",
        lambda: True,
    )
    return inner


def test_observe_transport_factory_live_returns_ephemeral_transport(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    inner = _patch_live_session_mocks(monkeypatch)
    factory = build_uplink_watchdog_observe_transport_factory(host)
    assert factory is not None
    transport = factory(router_id)
    assert isinstance(transport, _EphemeralLiveInternetStatusTransport)
    payload = transport.execute_rci_parse("show internet status")
    assert payload["internet"] == "yes"
    inner.execute_rci_parse.assert_called_once_with("show internet status")


def test_apply_transport_factory_live_returns_ephemeral_transport(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    inner = _patch_live_session_mocks(monkeypatch)
    factory = build_uplink_watchdog_apply_transport_factory(host)
    assert factory is not None
    transport = factory(router_id)
    assert isinstance(transport, _EphemeralLiveStationApplyTransport)
    assert transport.wifi_station_live_dispatch is True
    transport.execute_rci_parse("show interface")
    inner.execute_rci_parse.assert_called_with("show interface")


def test_transport_factories_none_when_gate_a_closed(tmp_path: Any) -> None:
    host, router_id = _live_host(tmp_path)
    host.gate_a_certification = None
    observe_factory = build_uplink_watchdog_observe_transport_factory(host)
    apply_factory = build_uplink_watchdog_apply_transport_factory(host)
    assert observe_factory is not None
    assert apply_factory is not None
    assert observe_factory(router_id) is None
    assert apply_factory(router_id) is None


def test_observe_transport_factory_rereads_gate_a_on_invoke(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    _patch_live_session_mocks(monkeypatch)
    host.gate_a_certification = None
    factory = build_uplink_watchdog_observe_transport_factory(host)
    assert factory is not None
    assert factory(router_id) is None
    host.gate_a_certification = _open_gate_a()
    transport = factory(router_id)
    assert isinstance(transport, _EphemeralLiveInternetStatusTransport)


def test_apply_transport_factory_rereads_gate_a_on_invoke(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    host, router_id = _live_host(tmp_path)
    _patch_live_session_mocks(monkeypatch)
    host.gate_a_certification = None
    factory = build_uplink_watchdog_apply_transport_factory(host)
    assert factory is not None
    assert factory(router_id) is None
    host.gate_a_certification = _open_gate_a()
    transport = factory(router_id)
    assert isinstance(transport, _EphemeralLiveStationApplyTransport)


def test_observe_transport_fail_closed_when_gate_a_closes_before_session(
    tmp_path: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from router_control_host.wifi_live_transport import LiveGateARequiredError

    host, router_id = _live_host(tmp_path)
    _patch_live_session_mocks(monkeypatch)
    factory = build_uplink_watchdog_observe_transport_factory(host)
    assert factory is not None
    transport = factory(router_id)
    assert transport is not None
    host.gate_a_certification = None
    with pytest.raises(LiveGateARequiredError, match="Gate A certification required"):
        transport.execute_rci_parse("show internet status")


def test_observe_transport_factory_uses_injected_factory(tmp_path: Any) -> None:
    host, router_id = _live_host(tmp_path)

    class _InjectedObserve:
        marker = "injected-observe"

    host.internet_status_transport_factory = lambda: _InjectedObserve()
    factory = build_uplink_watchdog_observe_transport_factory(host)
    assert factory is not None
    transport = factory(router_id)
    assert transport.marker == "injected-observe"  # type: ignore[attr-defined]


def test_apply_transport_factory_uses_injected_factory(tmp_path: Any) -> None:
    host, router_id = _live_host(tmp_path)

    class _InjectedApply:
        wifi_station_live_dispatch = True
        marker = "injected-apply"

    host.wifi_station_apply_transport_factory = lambda: _InjectedApply()
    factory = build_uplink_watchdog_apply_transport_factory(host)
    assert factory is not None
    transport = factory(router_id)
    assert transport.marker == "injected-apply"  # type: ignore[attr-defined]


def test_transport_factories_fake_mode_returns_offline_transports(tmp_path: Any) -> None:
    host, router_id = _live_host(tmp_path)
    host.adapter_mode = "fake"
    host.allow_fake_mutations = True
    observe_factory = build_uplink_watchdog_observe_transport_factory(host)
    apply_factory = build_uplink_watchdog_apply_transport_factory(host)
    assert observe_factory is not None
    assert apply_factory is not None
    observe = observe_factory(router_id)
    apply = apply_factory(router_id)
    assert observe is not None
    assert apply is not None
    assert observe.execute_rci_parse("show internet status")["internet"] == "yes"
    assert hasattr(apply, "wifi_station_offline_only")
