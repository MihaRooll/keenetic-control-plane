"""Cross-surface secret leak scanner for sealed RCI apply paths (offline only).

Scanner scope (honest boundary):
- Inspects transport *instances* after sealed writes (host fakes, HTTP-injected
  fakes, and any class passed to the assertion helpers) — not only classes
  declared inside ``router_control_host``.
- Walks ``repr(instance)``, instance ``__dict__``, and recursively collects
  string/bytes values plus contents of list/tuple/set/deque/dict containers.
- Does **not** intercept live SSH/RCI wire traffic, process memory, logs on
  disk, or secrets stored only in closure/local variables without touching
  instance attributes or ``repr``.
"""

from __future__ import annotations

import importlib
import importlib.util
import inspect
import json
import pkgutil
import sys
import traceback
from collections import deque
from collections.abc import Iterable, Mapping
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.fail_safe_rci import (
    FailSafeRciOperation,
    FailSafeStatusEntry,
    arm_fail_safe_timer_reboot_60,
    verify_fail_safe_response,
)
from router_control.adapters.netcraze.sanitize import (
    redact_sealed_cli_command,
    redact_sealed_nested_body,
)
from router_control.adapters.netcraze.transport import SealedRciWriteRequest
from router_control.adapters.netcraze.wireguard_rci import (
    WireguardRciOperation,
    command_redacted_for,
)
from router_control.application.wifi_apply_service import apply_wifi_intent
from router_control.application.wireguard_apply_service import apply_wireguard_intent
from router_control.domain.network_intents import WireguardIntent, WireguardPeerRciShape
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie
from router_control_host.wifi_apply_routes import _DefaultFakeWifiTransport
from router_control_host.wifi_live_transport import WifiLiveConnectionParams, WifiLiveSession
from router_control_host.wifi_station_apply_routes import _DefaultFakeStationTransport
from router_control_host.wireguard_apply_routes import _DefaultFakeWireguardTransport

from tests.test_wifi_apply_service import (
    _TEST_AP,
    FakeWifiApplyTransport,
    _applied_readback,
    _wpa2_intent,
)
from tests.test_wifi_station_show_rc_scrub import _LEAK_TOKEN as _STATION_PSK_CANARY
from tests.test_wireguard_apply_service import (
    _PLACEHOLDER_PEER,
    _PRIVATE_KEY_REF,
    _PSK_REF,
    _TEST_WG,
)

_PSK_CANARY = "PSK-CANARY-DO-NOT-LEAK-0001"
_HOST_FAKE_PSK_CANARY = "PSK-CANARY-HOST-FAKE-LEAK-9999"
_WG_PRIVATE_CANARY = "PRIVATE-KEY-CANARY-DO-NOT-LEAK-0001="
_WG_PSK_CANARY = "PRESHARED-KEY-CANARY-DO-NOT-LEAK-0001="
_WG_NESTED_PSK_CANARY = "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
_ASC_9 = (5, 42, 54, 0, 0, 1, 2, 3, 4)
_REDACTION_MARKERS = ("<redacted>", "REDACTED")
_EPHEMERAL_LIVE_WG_QUALIFIED = (
    "router_control_host.wireguard_apply_routes._EphemeralLiveWireguardTransport"
)
_SCANNER_INERT_LIVE_PARAMS = WifiLiveConnectionParams(
    host="scanner.example.invalid",
    username="scanner-fake-user",
    router_credential_ref_id="credref:scanner-fake-inert",
    ssh_host_key_sha256=(
        "SHA256:0000000000000000000000000000000000000000000000000000000000000000"
    ),
    source_address="203.0.113.1",
)


class _InertScannerVault:
    """Obvious fake vault stand-in for scanner instantiation; no I/O."""


class _ScannerEphemeralLiveInner:
    """Inert inner transport reached via open_wifi_live_session during scanner runs."""

    def __init__(self) -> None:
        self.sealed_write_calls = 0
        self.parse_calls = 0

    def execute_sealed_rci_write(self, request: Any) -> list[dict[str, Any]]:
        self.sealed_write_calls += 1
        return []

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        self.parse_calls += 1
        return {}


@contextmanager
def _ephemeral_live_wireguard_scan_patch():
    inner = _ScannerEphemeralLiveInner()

    @contextmanager
    def _mock_open_wifi_live_session(*, params: Any, vault: Any):
        tunnel = MagicMock(name="scanner_fake_tunnel")
        yield WifiLiveSession(transport=inner, tunnel=tunnel)

    with patch(
        "router_control_host.wireguard_apply_routes.open_wifi_live_session",
        _mock_open_wifi_live_session,
    ), patch(
        "router_control_host.wireguard_apply_routes.ensure_live_gate_a_tuple_match",
        lambda *_args, **_kwargs: None,
    ):
        yield inner


def _assert_no_canaries_in_blob(blob: str, *canaries: str) -> None:
    for canary in canaries:
        assert canary not in blob, f"canary {canary!r} leaked in blob"


def _collect_surfaces(*parts: object, canaries: tuple[str, ...]) -> None:
    blobs: list[str] = []
    for part in parts:
        if part is None:
            continue
        if isinstance(part, BaseException):
            blobs.append(str(part))
            blobs.append(repr(part))
            blobs.append("".join(traceback.format_exception(type(part), part, part.__traceback__)))
            if part.__cause__ is not None:
                blobs.append(str(part.__cause__))
                blobs.append(repr(part.__cause__))
            continue
        if hasattr(part, "to_dict"):
            blobs.append(json.dumps(part.to_dict()))  # type: ignore[union-attr]
        blobs.append(json.dumps(part, default=str))
        blobs.append(repr(part))
    joined = "\n".join(blobs)
    _assert_no_canaries_in_blob(joined, *canaries)


class _OkEnvelopeTransport:
    def execute_sealed_rci_write(self, request: Any) -> Any:
        return [
            {
                "parse": {
                    "prompt": "(config)",
                    "status": [
                        {
                            "status": "message",
                            "code": "1",
                            "ident": "Core::System::Mtd::ConfigStorage",
                            "message": "ok",
                        }
                    ],
                }
            }
        ]


def _sealed_cli_request(command: str) -> SealedRciWriteRequest:
    body = json.dumps([{"parse": command}]).encode("utf-8")
    return SealedRciWriteRequest(body=body)


def _nested_wg_peer_request(canary_psk: str) -> SealedRciWriteRequest:
    from router_control.adapters.netcraze.allowlist import build_wireguard_nested_peer_body

    body = build_wireguard_nested_peer_body(
        _TEST_WG,
        _PLACEHOLDER_PEER,
        preshared_key=canary_psk,
    )
    return SealedRciWriteRequest(body=body)


def _iter_router_control_host_modules() -> list[ModuleType]:
    import router_control_host

    pkg_path = Path(router_control_host.__file__).parent
    modules: list[ModuleType] = []
    for info in sorted(pkgutil.iter_modules([str(pkg_path)])):
        modules.append(importlib.import_module(f"router_control_host.{info.name}"))
    return modules


def _classes_defined_in_module(module: ModuleType) -> list[tuple[str, type[Any]]]:
    found: list[tuple[str, type[Any]]] = []
    for name, obj in inspect.getmembers(module, inspect.isclass):
        if obj.__module__ != module.__name__:
            continue
        found.append((f"{module.__name__}.{name}", obj))
    return found


def _implements_method(cls: type[Any], method_name: str) -> bool:
    for klass in cls.__mro__:
        if method_name in klass.__dict__:
            return True
    return False


def _discover_sealed_write_transport_classes() -> list[tuple[str, type[Any]]]:
    discovered: list[tuple[str, type[Any]]] = []
    seen: set[str] = set()
    for module in _iter_router_control_host_modules():
        for qualified_name, cls in _classes_defined_in_module(module):
            if not _implements_method(cls, "execute_sealed_rci_write"):
                continue
            if qualified_name in seen:
                continue
            seen.add(qualified_name)
            discovered.append((qualified_name, cls))
    return discovered


def _discover_readonly_output_transport_classes() -> list[tuple[str, type[Any]]]:
    discovered: list[tuple[str, type[Any]]] = []
    seen: set[str] = set()
    for module in _iter_router_control_host_modules():
        for qualified_name, cls in _classes_defined_in_module(module):
            has_parse = _implements_method(cls, "execute_rci_parse")
            has_survey = _implements_method(cls, "execute_site_survey")
            has_sealed = _implements_method(cls, "execute_sealed_rci_write")
            if not has_parse and not has_survey:
                continue
            if has_sealed and not has_survey:
                # Sealed-write fakes are covered by the write scanner; parse-only
                # accumulation on dual-mode transports is checked separately below.
                if not has_parse:
                    continue
            if qualified_name in seen:
                continue
            seen.add(qualified_name)
            discovered.append((qualified_name, cls))
    return discovered


class _MinimalDelegatingInner:
    def execute_sealed_rci_write(self, request: Any) -> list[dict[str, Any]]:
        return []

    def execute_rci_parse(self, cli_command: str) -> dict[str, Any]:
        return {}

    def execute_site_survey(self, command: str) -> str:
        return ""


def _instantiate_transport_or_fail(qualified_name: str, cls: type[Any]) -> Any:
    try:
        return cls()
    except TypeError as type_exc:
        sig = inspect.signature(cls.__init__)
        required = [
            name
            for name, param in sig.parameters.items()
            if name != "self"
            and param.default is inspect.Parameter.empty
            and param.kind
            not in (
                inspect.Parameter.VAR_POSITIONAL,
                inspect.Parameter.VAR_KEYWORD,
            )
        ]
        if required == ["inner"]:
            return cls(_MinimalDelegatingInner())
        if required == ["params", "vault"]:
            kwargs: dict[str, Any] = {
                "params": _SCANNER_INERT_LIVE_PARAMS,
                "vault": _InertScannerVault(),
            }
            if qualified_name == _EPHEMERAL_LIVE_WG_QUALIFIED:
                kwargs["certification"] = MagicMock(name="scanner_fake_gate_a_cert")
            return cls(**kwargs)
        pytest.fail(
            f"secret leak scanner cannot instantiate {qualified_name}: {type_exc!r}"
        )
    except Exception as exc:
        pytest.fail(
            f"secret leak scanner cannot instantiate {qualified_name}: {exc!r}"
        )


def _blob_from_surfaces(*surfaces: object) -> str:
    parts: list[str] = []
    for surface in surfaces:
        if surface is None:
            continue
        parts.append(json.dumps(surface, default=str))
        parts.append(repr(surface))
    return "\n".join(parts)


def _assert_no_canaries_and_redacted(
    blob: str,
    *,
    qualified_name: str,
    canaries: tuple[str, ...],
    require_redaction_marker: bool,
) -> None:
    for canary in canaries:
        assert canary not in blob, f"{qualified_name} leaked canary {canary!r}"
    if require_redaction_marker:
        assert any(marker in blob for marker in _REDACTION_MARKERS), (
            f"{qualified_name} must redact secrets "
            f"(expected one of {_REDACTION_MARKERS})"
        )


def _collect_value_surfaces(value: object, *, _seen: set[int]) -> list[object]:
    oid = id(value)
    if oid in _seen:
        return []
    _seen.add(oid)

    surfaces: list[object] = []
    if value is None or isinstance(value, (bool, int, float)):
        return surfaces
    if isinstance(value, (str, bytes)):
        surfaces.append(value)
        return surfaces
    if isinstance(value, Mapping):
        surfaces.append(value)
        for key, item in value.items():
            surfaces.extend(_collect_value_surfaces(key, _seen=_seen))
            surfaces.extend(_collect_value_surfaces(item, _seen=_seen))
        return surfaces
    if isinstance(value, (list, tuple, set, frozenset, deque)):
        surfaces.append(value)
        for item in value:
            surfaces.extend(_collect_value_surfaces(item, _seen=_seen))
        return surfaces
    if isinstance(value, Iterable) and not isinstance(value, (Mapping, str, bytes)):
        try:
            iterator = iter(value)
        except TypeError:
            pass
        else:
            surfaces.append(value)
            for item in iterator:
                surfaces.extend(_collect_value_surfaces(item, _seen=_seen))
            return surfaces
    if hasattr(value, "__dict__"):
        surfaces.extend(_collect_instance_surfaces(value, _seen=_seen))
    return surfaces


def _collect_instance_surfaces(transport: object, *, _seen: set[int] | None = None) -> list[object]:
    if _seen is None:
        _seen = set()
    oid = id(transport)
    if oid in _seen:
        return []
    _seen.add(oid)

    surfaces: list[object] = []
    try:
        surfaces.append(repr(transport))
    except Exception:
        pass

    instance_dict = getattr(transport, "__dict__", None)
    if isinstance(instance_dict, dict):
        for name, value in instance_dict.items():
            if name.startswith("__"):
                continue
            surfaces.extend(_collect_value_surfaces(value, _seen=_seen))
    return surfaces


def _transport_accumulates_writes(transport: object) -> bool:
    for surface in _collect_instance_surfaces(transport):
        if isinstance(surface, list) and surface:
            return True
        if isinstance(surface, deque) and surface:
            return True
    return False


def _assert_transport_instance_redacts(
    qualified_name: str,
    transport: object,
    *,
    canaries: tuple[str, ...] | None = None,
) -> None:
    ap_cmd = f"interface {_TEST_AP} authentication wpa-psk {_HOST_FAKE_PSK_CANARY}"
    station_cmd = (
        f"interface WifiMaster0/Station0 authentication wpa-psk {_HOST_FAKE_PSK_CANARY}"
    )
    wg_private_cmd = f"interface {_TEST_WG} wireguard private-key {_WG_PRIVATE_CANARY}"

    transport.execute_sealed_rci_write(_sealed_cli_request(ap_cmd))  # type: ignore[attr-defined]
    transport.execute_sealed_rci_write(_sealed_cli_request(station_cmd))  # type: ignore[attr-defined]
    transport.execute_sealed_rci_write(_sealed_cli_request(wg_private_cmd))  # type: ignore[attr-defined]
    nested_bodies = getattr(transport, "nested_write_bodies", None)
    if isinstance(nested_bodies, list):
        transport.execute_sealed_rci_write(_nested_wg_peer_request(_WG_NESTED_PSK_CANARY))  # type: ignore[attr-defined]

    resolved_canaries = canaries or (
        _HOST_FAKE_PSK_CANARY,
        _WG_PRIVATE_CANARY,
        _WG_PSK_CANARY,
        _WG_NESTED_PSK_CANARY,
    )
    surfaces = _collect_instance_surfaces(transport)
    blob = _blob_from_surfaces(*surfaces)
    _assert_no_canaries_and_redacted(
        blob,
        qualified_name=qualified_name,
        canaries=resolved_canaries,
        require_redaction_marker=_transport_accumulates_writes(transport),
    )


def _assert_sealed_write_transport_redacts(qualified_name: str, transport_cls: type[Any]) -> None:
    if qualified_name == _EPHEMERAL_LIVE_WG_QUALIFIED:
        with _ephemeral_live_wireguard_scan_patch() as inner:
            transport = _instantiate_transport_or_fail(qualified_name, transport_cls)
            _assert_transport_instance_redacts(qualified_name, transport)
            assert inner.sealed_write_calls >= 3, (
                f"{qualified_name} must delegate sealed writes during scanner run"
            )
        return
    transport = _instantiate_transport_or_fail(qualified_name, transport_cls)
    _assert_transport_instance_redacts(qualified_name, transport)


def _assert_readonly_transport_scrubs_output(
    qualified_name: str,
    transport_cls: type[Any],
) -> None:
    if qualified_name == _EPHEMERAL_LIVE_WG_QUALIFIED:
        with _ephemeral_live_wireguard_scan_patch() as inner:
            transport = _instantiate_transport_or_fail(qualified_name, transport_cls)
            canaries = (_HOST_FAKE_PSK_CANARY, _WG_PRIVATE_CANARY, _WG_PSK_CANARY)
            if _implements_method(transport_cls, "execute_rci_parse"):
                readback = transport.execute_rci_parse(f"show interface {_TEST_AP}")
                blob = _blob_from_surfaces(readback, *_collect_instance_surfaces(transport))
                _assert_no_canaries_and_redacted(
                    blob,
                    qualified_name=qualified_name,
                    canaries=canaries,
                    require_redaction_marker=False,
                )
                assert inner.parse_calls >= 1, (
                    f"{qualified_name} must delegate parse during scanner run"
                )
            if _implements_method(transport_cls, "execute_site_survey"):
                survey = transport.execute_site_survey(
                    "show interface WifiMaster0 site-survey"
                )
                blob = _blob_from_surfaces(survey, *_collect_instance_surfaces(transport))
                _assert_no_canaries_and_redacted(
                    blob,
                    qualified_name=qualified_name,
                    canaries=canaries,
                    require_redaction_marker=False,
                )
        return
    transport = _instantiate_transport_or_fail(qualified_name, transport_cls)
    canaries = (_HOST_FAKE_PSK_CANARY, _WG_PRIVATE_CANARY, _WG_PSK_CANARY)
    if _implements_method(transport_cls, "execute_rci_parse"):
        readback = transport.execute_rci_parse(f"show interface {_TEST_AP}")
        blob = _blob_from_surfaces(readback, *_collect_instance_surfaces(transport))
        _assert_no_canaries_and_redacted(
            blob,
            qualified_name=qualified_name,
            canaries=canaries,
            require_redaction_marker=False,
        )
    if _implements_method(transport_cls, "execute_site_survey"):
        survey = transport.execute_site_survey("show interface WifiMaster0 site-survey")
        blob = _blob_from_surfaces(survey, *_collect_instance_surfaces(transport))
        _assert_no_canaries_and_redacted(
            blob,
            qualified_name=qualified_name,
            canaries=canaries,
            require_redaction_marker=False,
        )


def _scan_all_host_transports_for_secret_leaks() -> None:
    sealed = _discover_sealed_write_transport_classes()
    assert sealed, "expected at least one sealed-write transport in router_control_host"
    readonly = _discover_readonly_output_transport_classes()

    for qualified_name, transport_cls in sealed:
        _assert_sealed_write_transport_redacts(qualified_name, transport_cls)

    for qualified_name, transport_cls in readonly:
        _assert_readonly_transport_scrubs_output(qualified_name, transport_cls)


def test_all_host_transports_redact_sealed_commands_by_capability() -> None:
    """Existence-based guard: every host transport that accepts sealed writes redacts."""
    _scan_all_host_transports_for_secret_leaks()


def test_scanner_catches_violator_class_in_separate_module(tmp_path: Path) -> None:
    """Proof: a non-conforming transport module must fail the scanner (red→green)."""
    violator_path = tmp_path / "router_control_host_violator.py"
    violator_path.write_text(
        "\n".join(
            [
                "from router_control.adapters.netcraze.transport import SealedRciWriteRequest",
                "",
                "class FakeWifiTransport:",
                "    def __init__(self) -> None:",
                "        self.write_commands: list[str] = []",
                "",
                "    def execute_sealed_rci_write(self, request: SealedRciWriteRequest):",
                "        body = request.body.decode('utf-8')",
                "        self.write_commands.append(body)",
                "        return []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "router_control_host_violator_proof",
        violator_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    violator_cls = module.FakeWifiTransport
    with pytest.raises(AssertionError, match="leaked canary"):
        _assert_transport_instance_redacts(
            f"{module.__name__}.FakeWifiTransport",
            violator_cls(),
        )
    sys.modules.pop(spec.name, None)


def test_scanner_catches_violator_deque_accumulator() -> None:
    """Proof: deque-backed accumulation must fail the instance scanner (red→green)."""

    class DequeViolator:
        def __init__(self) -> None:
            self._cmd_ring: deque[str] = deque()

        def execute_sealed_rci_write(self, request: Any) -> list[object]:
            self._cmd_ring.append(request.body.decode("utf-8"))
            return []

    with pytest.raises(AssertionError, match="leaked canary"):
        _assert_transport_instance_redacts("tests.DequeViolator", DequeViolator())


def test_scanner_catches_violator_private_attr_accumulator() -> None:
    """Proof: nonstandard private attr names must fail the instance scanner (red→green)."""

    class PrivateAttrViolator:
        def __init__(self) -> None:
            self._x_secret_log: list[str] = []

        def execute_sealed_rci_write(self, request: Any) -> list[object]:
            self._x_secret_log.append(request.body.decode("utf-8"))
            return []

    with pytest.raises(AssertionError, match="leaked canary"):
        _assert_transport_instance_redacts("tests.PrivateAttrViolator", PrivateAttrViolator())


def test_scanner_catches_external_transport_via_http_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proof: HTTP-injected transport outside router_control_host is scanned by instance."""
    violator_path = tmp_path / "external_http_violator.py"
    violator_path.write_text(
        "\n".join(
            [
                "from router_control.adapters.netcraze.transport import SealedRciWriteRequest",
                "",
                "class ExternalHttpViolator:",
                "    def __init__(self) -> None:",
                "        self._x_secret_log: list[str] = []",
                "",
                "    def execute_sealed_rci_write(self, request: SealedRciWriteRequest):",
                "        self._x_secret_log.append(request.body.decode('utf-8'))",
                "        return []",
                "",
            ]
        ),
        encoding="utf-8",
    )
    spec = importlib.util.spec_from_file_location(
        "external_http_violator_proof",
        violator_path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "external_violator.sqlite3", allow_fake_mutations=True)
    transport = module.ExternalHttpViolator()
    app.state.host.wifi_apply_transport_factory = lambda: transport
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _HOST_FAKE_PSK_CANARY
    from fastapi.testclient import TestClient

    payload = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
    }
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    with pytest.raises(AssertionError, match="leaked canary"):
        _assert_transport_instance_redacts(
            f"{module.__name__}.ExternalHttpViolator",
            transport,
        )
    sys.modules.pop(spec.name, None)


def test_wifi_ap_host_fake_transport_no_secret_leak_via_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canaries = (_HOST_FAKE_PSK_CANARY,)
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "ap_host_fake.sqlite3", allow_fake_mutations=True)
    transport = _DefaultFakeWifiTransport()
    app.state.host.wifi_apply_transport_factory = lambda: transport
    app.state.host.wifi_apply_credential_resolver = lambda _ref: _HOST_FAKE_PSK_CANARY
    from fastapi.testclient import TestClient

    payload = {
        "ap_id": _TEST_AP,
        "ssid": "Staff-Private",
        "enabled": True,
        "credential_ref_id": "credref:staff-wifi",
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA2",
        "band": "BAND_2_4GHZ",
        "confirm_live_apply": True,
    }
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/apply", json=payload)
    assert resp.status_code == 200
    _collect_surfaces(
        resp.json(),
        *_collect_instance_surfaces(transport),
        canaries=canaries,
    )


def test_wifi_station_host_fake_transport_no_secret_leak_via_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canaries = (_HOST_FAKE_PSK_CANARY,)
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(
        db_path=tmp_path / "station_host_fake.sqlite3", allow_fake_mutations=True
    )
    transport = _DefaultFakeStationTransport()
    app.state.host.wifi_station_apply_transport_factory = lambda: transport
    app.state.host.wifi_station_apply_credential_resolver = lambda _ref: _HOST_FAKE_PSK_CANARY
    from fastapi.testclient import TestClient

    payload = {
        "mode": "WifiWan",
        "ssid": "Venue-Guest",
        "band": "BAND_2_4GHZ",
        "credential_ref_id": "credref:venue-wifi",
        "confirm_live_apply": True,
    }
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/station/apply", json=payload)
    assert resp.status_code == 200
    _collect_surfaces(
        resp.json(),
        *_collect_instance_surfaces(transport),
        canaries=canaries,
    )


def test_wifi_ap_apply_full_path_no_psk_leak() -> None:
    canaries = (_PSK_CANARY,)
    transport = FakeWifiApplyTransport(readback_sequence=[_applied_readback()])
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _PSK_CANARY,
    )
    _collect_surfaces(
        result,
        result.errors,
        result.logs,
        transport.write_commands,
        canaries=canaries,
    )


def test_wifi_ap_failure_router_echo_scrubbed() -> None:
    canaries = (_PSK_CANARY,)
    leak_message = f"rejected: authentication wpa-psk {_PSK_CANARY}"
    psk_cmd = f"interface {_TEST_AP} authentication wpa-psk {_PSK_CANARY}"

    class EchoFailTransport(FakeWifiApplyTransport):
        def execute_sealed_rci_write(self, request: Any) -> Any:
            body = json.loads(request.body.decode("utf-8"))
            command = str(body[0]["parse"])
            self.write_commands.append(redact_sealed_cli_command(command))
            if command == psk_cmd:
                return [
                    {
                        "parse": {
                            "prompt": "(config)",
                            "status": [
                                {
                                    "status": "error",
                                    "code": "1",
                                    "ident": "Core::Interface",
                                    "message": leak_message,
                                }
                            ],
                        }
                    }
                ]
            return self.write_response

    transport = EchoFailTransport()
    result = apply_wifi_intent(
        intent=_wpa2_intent(),
        ap_id=_TEST_AP,
        transport=transport,
        credential_resolver=lambda _ref: _PSK_CANARY,
        compensate_on_failure=False,
    )
    _collect_surfaces(
        result,
        result.errors,
        result.logs,
        transport.write_commands,
        canaries=canaries,
    )


def test_wireguard_nested_apply_host_fake_transport_no_secret_leak(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canaries = (_WG_PRIVATE_CANARY, _WG_PSK_CANARY)
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wg_scanner.sqlite3", allow_fake_mutations=True)
    transport = _DefaultFakeWireguardTransport()

    def _resolver(ref_id: str) -> str:
        if ref_id == _PRIVATE_KEY_REF:
            return _WG_PRIVATE_CANARY
        if ref_id == _PSK_REF:
            return _WG_PSK_CANARY
        raise AssertionError(ref_id)

    app.state.host.wireguard_apply_transport_factory = lambda: transport
    app.state.host.wireguard_apply_credential_resolver = _resolver
    from fastapi.testclient import TestClient

    payload = {
        "wg_id": _TEST_WG,
        "enabled": True,
        "asc_args": list(_ASC_9),
        "confirm_live_apply": True,
        "private_key_credential_ref_id": _PRIVATE_KEY_REF,
        "peer_public_key": _PLACEHOLDER_PEER,
        "peer_endpoint": "vpn.example.com:51820",
        "preshared_key_credential_ref_id": _PSK_REF,
        "peer_rci_shape": "nested_rci",
    }
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wireguard/apply", json=payload)
    assert resp.status_code == 200
    _collect_surfaces(
        resp.json(),
        *_collect_instance_surfaces(transport),
        canaries=canaries,
    )


def test_wireguard_service_apply_no_secret_leak() -> None:
    canaries = (_WG_PRIVATE_CANARY, _WG_PSK_CANARY)
    transport = _DefaultFakeWireguardTransport()
    intent = WireguardIntent(
        wg_id=_TEST_WG,
        enabled=True,
        asc_args=_ASC_9,
        private_key_credential_ref_id=_PRIVATE_KEY_REF,
        peer_public_key=_PLACEHOLDER_PEER,
        peer_endpoint="vpn.example.com:51820",
        preshared_key_credential_ref_id=_PSK_REF,
        peer_rci_shape=WireguardPeerRciShape.NESTED_RCI,
    )

    def _resolver(ref_id: str) -> str:
        if ref_id == _PRIVATE_KEY_REF:
            return _WG_PRIVATE_CANARY
        if ref_id == _PSK_REF:
            return _WG_PSK_CANARY
        raise AssertionError(ref_id)

    result = apply_wireguard_intent(
        intent=intent,
        transport=transport,
        credential_resolver=_resolver,
    )
    _collect_surfaces(
        result,
        result.errors,
        result.logs,
        transport.write_commands,
        transport.nested_write_bodies,
        canaries=canaries,
    )


def test_fail_safe_cycle_repr_and_response_no_device_secret_echo() -> None:
    canaries = (_STATION_PSK_CANARY,)
    echo_message = f"device echoed authentication wpa-psk {_STATION_PSK_CANARY}"
    response = [
        {
            "parse": {
                "prompt": "(config)",
                "status": [
                    {
                        "status": "message",
                        "code": "1",
                        "ident": "Core::System::Mtd::ConfigStorage",
                        "message": echo_message,
                    }
                ],
            }
        }
    ]
    result = verify_fail_safe_response(FailSafeRciOperation.ARM_TIMER_REBOOT_60, response)
    entry = FailSafeStatusEntry(
        status="error",
        code="1",
        ident="Core",
        message=echo_message,
    )
    _collect_surfaces(
        result,
        result.sanitized_dict(),
        entry,
        canaries=canaries,
    )
    assert _STATION_PSK_CANARY not in repr(entry)
    arm_fail_safe_timer_reboot_60(_OkEnvelopeTransport())


def test_wireguard_command_redacted_for_never_includes_secrets() -> None:
    redacted_private = command_redacted_for(
        WireguardRciOperation.SET_PRIVATE_KEY,
        _TEST_WG,
    )
    redacted_psk = command_redacted_for(
        WireguardRciOperation.SET_PRESHARED_KEY,
        _TEST_WG,
        peer_public_key=_PLACEHOLDER_PEER,
    )
    assert "<redacted>" in redacted_private
    assert "<redacted>" in redacted_psk
    assert _WG_PRIVATE_CANARY not in redacted_private
    assert _WG_PSK_CANARY not in redacted_psk


def test_redact_sealed_cli_command_strips_canaries() -> None:
    raw_wifi = f"interface {_TEST_AP} authentication wpa-psk {_PSK_CANARY}"
    raw_wg_private = f"interface {_TEST_WG} wireguard private-key {_WG_PRIVATE_CANARY}"
    raw_wg_psk = (
        f"interface {_TEST_WG} wireguard peer {_PLACEHOLDER_PEER} "
        f"preshared-key {_WG_PSK_CANARY}"
    )
    for raw in (raw_wifi, raw_wg_private, raw_wg_psk):
        redacted = redact_sealed_cli_command(raw)
        assert _PSK_CANARY not in redacted
        assert _WG_PRIVATE_CANARY not in redacted
        assert _WG_PSK_CANARY not in redacted
        assert "<redacted>" in redacted


def test_redact_sealed_nested_body_strips_psk_canary() -> None:
    nested = {
        "interface": {
            _TEST_WG: {
                "wireguard": {
                    "peer": [
                        {
                            "key": _PLACEHOLDER_PEER,
                            "preshared-key": _WG_PSK_CANARY,
                        }
                    ]
                }
            }
        }
    }
    redacted = redact_sealed_nested_body(nested)
    blob = json.dumps(redacted)
    assert _WG_PSK_CANARY not in blob
    assert "REDACTED" in blob


def test_redact_sealed_cli_command_red_green_guard() -> None:
    """Guard: removing redaction must fail this assertion (red→green)."""
    raw = f"interface {_TEST_AP} authentication wpa-psk {_PSK_CANARY}"
    redacted = redact_sealed_cli_command(raw)
    assert _PSK_CANARY not in redacted


_CANARY_422 = "SuperSecretPSK-should-not-echo"
_WIFI_PREVIEW_PAYLOAD: dict[str, object] = {
    "ap_id": _TEST_AP,
    "ssid": "Staff-Private",
    "enabled": True,
    "credential_ref_id": "credref:staff-wifi",
    "captive_portal": "Disabled",
    "guest_isolation": False,
    "wpa_mode": "WPA2",
    "band": "BAND_2_4GHZ",
}


def test_http_422_validation_surface_no_canary_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scanner contract: POST wifi/preview invalid enum must not echo user input."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "422_scanner.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    payload = {**_WIFI_PREVIEW_PAYLOAD, "captive_portal": _CANARY_422}
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/preview", json=payload)
    assert resp.status_code == 422
    blob = json.dumps(resp.json())
    assert _CANARY_422 not in blob
    assert "detail" not in resp.json()
    assert resp.json()["error"]["code"] == "request.validation_failed"


def test_http_422_extra_key_no_canary_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scanner contract: extra JSON key (extra=forbid) must not echo user key in body."""
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "422_extra_key_scanner.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    payload = {**_WIFI_PREVIEW_PAYLOAD, _CANARY_422: "anything"}
    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        resp = client.post("/api/router-control/v1/wifi/preview", json=payload)
    assert resp.status_code == 422
    body = resp.json()
    blob = json.dumps(body)
    assert _CANARY_422 not in blob
    assert "detail" not in body
    assert body["error"]["code"] == "request.validation_failed"
    assert body["error"]["details"][0]["type"] == "extra_forbidden"
    assert body["error"]["details"][0]["loc"] == ["body", "[unrecognized_field]"]
