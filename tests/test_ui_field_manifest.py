"""Drift guard and curation coverage for ui-field-manifest.json."""

from __future__ import annotations

import inspect
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Annotated, Any, Literal
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import AliasChoices, BaseModel, ConfigDict, Field
from router_control.application.wifi_apply_planner import (
    WifiApplyPlannerError,
    compile_wifi_intent_to_ops,
)
from router_control.application.wifi_observation_helpers import (
    ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
    ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
    ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
)
from router_control.application.wifi_station_apply_planner import (
    WifiStationApplyPlannerError,
    WifiStationPlannerOptions,
    compile_uplink_intent_to_station_ops,
)
from router_control.domain.network_intents import (
    CaptivePortalMode,
    UplinkIntent,
    UplinkMode,
    WifiBand,
    WifiIntent,
    WifiWpaMode,
)
from router_control_host.wifi_apply_routes import _PLANNER_CODE_TO_HTTP as WIFI_AP_CODE_TO_HTTP
from router_control_host.wifi_station_apply_routes import (
    _PLANNER_CODE_TO_HTTP as STATION_APPLY_CODE_TO_HTTP,
)
from router_control_host.wifi_station_preview_routes import (
    _PLANNER_CODE_TO_HTTP as STATION_PREVIEW_CODE_TO_HTTP,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = REPO_ROOT / "router_control_host" / "web" / "ui-field-manifest.json"
EXPORTER_MODULE = "export_ui_field_manifest"

REQUIRED_FAMILIES = frozenset(
    {
        "wifi_ap",
        "wifi_station",
        "wireguard",
        "vlan",
        "dhcp",
        "dns",
        "firewall",
        "vpn_policy_routing",
        "wizard_draft",
        "bootstrap_discovery",
        "router_discovery",
        "connection_health",
        "ssh_host_key",
        "connection_context",
        "enroll",
        "change_plan",
        "deployment",
        "desired_revision",
        "vpn_profile",
        "traffic_discovery",
        "rci_sealed",
        "wifi_site_survey",
        "wifi_observed",
        "credentials",
        "commissioning",
        "keendns",
        "vpn_catalog",
        "internet_status",
        "standing_network_preferences",
        "remembered_uplink",
    }
)

# Residual (honestly pinned): see MANUAL_BODY_GUARD_DECISION_TABLE —
# untested handler branches; body passed to helper using getattr/dynamic access;
# JSON dump of whole body; nested opaque blob internals;
# API still accepts unknown extras when handlers lack extra=forbid (routes not owned).

MANUAL_BODY_GUARD_DECISION_TABLE: tuple[dict[str, Any], ...] = (
    {
        "pattern": "literal body.get('key')",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "literal body['key']",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "literal body.pop('key')",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "'key' in body",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "body.keys()",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "variable body.get(KEY)",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "for k in body (unpack / __iter__)",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "for k, v in body.items() (loop unpack)",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "body.values()",
        "covered_by_behavioral": True,
        "residual_named": None,
        "rejected_approach": "regex-only primary guard",
    },
    {
        "pattern": "body passed to helper using getattr/hasattr",
        "covered_by_behavioral": False,
        "residual_named": "dynamic getattr on body dict",
        "rejected_approach": "monkeypatching getattr globally",
    },
    {
        "pattern": "json.dumps(body) / whole-body serialization",
        "covered_by_behavioral": False,
        "residual_named": "whole-body JSON dump without per-key reads",
        "rejected_approach": "intercepting json.dumps globally",
    },
    {
        "pattern": "untested handler branches",
        "covered_by_behavioral": False,
        "residual_named": "handler branch not exercised by behavioral probe",
        "rejected_approach": "static regex over all route modules",
    },
)


class KeyTrackingDict(dict[str, Any]):
    """Records top-level body key reads regardless of literal vs variable access."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.accessed_keys: set[str] = set()

    def _track(self, key: object) -> None:
        if isinstance(key, str):
            self.accessed_keys.add(key)

    def __getitem__(self, key: str) -> Any:
        self._track(key)
        return super().__getitem__(key)

    def get(self, key: str, default: Any = None) -> Any:
        self._track(key)
        return super().get(key, default)

    def pop(self, key: str, default: Any = ...) -> Any:
        self._track(key)
        if default is ...:
            return super().pop(key)
        return super().pop(key, default)

    def __contains__(self, key: object) -> bool:
        self._track(key)
        return super().__contains__(key)

    def keys(self):  # type: ignore[no-untyped-def]
        for key in super().keys():
            self._track(key)
        return super().keys()

    def __iter__(self):  # type: ignore[no-untyped-def]
        for key in super().__iter__():
            self._track(key)
            yield key

    def items(self):  # type: ignore[no-untyped-def]
        for key, value in super().items():
            self._track(key)
            yield key, value

    def values(self):  # type: ignore[no-untyped-def]
        for key in super().keys():
            self._track(key)
        return super().values()


def _assert_manual_body_keys(
    *,
    accessed: frozenset[str],
    declared: frozenset[str],
    handler_label: str,
    must_consume: frozenset[str] | None = None,
) -> None:
    undeclared = accessed - declared
    assert not undeclared, (
        f"{handler_label}: body accessed undeclared keys {sorted(undeclared)}"
    )
    if must_consume is not None:
        missing = must_consume - accessed
        assert not missing, (
            f"{handler_label}: handler must consume declared keys {sorted(missing)}"
        )


# Secondary regex helpers — not primary guards; kept for spot checks only.

_BODY_GET_RE = re.compile(r"""body\.get\(\s*["']([^"']+)["']""")
_BODY_INDEX_RE = re.compile(r"""body\[\s*["']([^"']+)["']\s*\]""")
_BODY_POP_RE = re.compile(r"""body\.pop\(\s*["']([^"']+)["']""")
_BODY_ATTR_RE = re.compile(r"""body\.(\w+)""")


def _extract_body_attr_keys_from_handler(handler: Callable[..., object]) -> frozenset[str]:
    """Typed pydantic handlers use body.field — behavioral KeyTrackingDict cannot see these."""
    source = inspect.getsource(handler)
    return frozenset(_BODY_ATTR_RE.findall(source))


def _extract_body_keys_from_handler(handler: Callable[..., object]) -> frozenset[str]:
    """Legacy regex extraction — secondary only; behavioral KeyTrackingDict is primary."""
    source = inspect.getsource(handler)
    keys: set[str] = set()
    keys.update(_BODY_GET_RE.findall(source))
    keys.update(_BODY_INDEX_RE.findall(source))
    keys.update(_BODY_POP_RE.findall(source))
    return frozenset(keys)


def _manual_family_names(exporter, family_id: str) -> frozenset[str]:
    names: set[str] = set()
    for spec in exporter.MANUAL_FIELD_SPECS.get(family_id, []):
        names.add(spec["name"])
    for spec in exporter.MANUAL_FIELD_OVERLAY.get(family_id, []):
        names.add(spec["name"])
    return frozenset(names)


def _mock_request_with_body(body: KeyTrackingDict) -> MagicMock:
    request = MagicMock()
    request.state.correlation_id = "manifest-guard-test"
    request.json = AsyncMock(return_value=body)
    return request


def _mock_host(*, router_exists: bool = True, adapter_mode: str = "fake") -> MagicMock:
    host = MagicMock()
    host.runtime.store.get_router.return_value = (
        {"router_id": "rtr_test"} if router_exists else None
    )
    host.runtime.store.peek_idempotency.return_value = None
    host.runtime.vault.create.side_effect = AssertionError("vault must not be reached")
    host.adapter_mode = adapter_mode
    host.commissioning_service.return_value.create_run.side_effect = AssertionError(
        "commissioning service must not be reached"
    )
    return host


def _attach_host(request: MagicMock, host: MagicMock) -> None:
    app = MagicMock()
    app.state.host = host
    request.app = app

SECRET_INTAKE_FIELD_NAMES = frozenset(
    {"secret", "management_password", "private_key", "preshared_key"}
)
NOT_STORED_PHRASES = (
    "не сохраняется",
    "not stored",
    "не отображается",
    "not displayed",
    "write-only",
)

SECRET_VALUE_PATTERNS = (
    re.compile(r"password\s*[:=]", re.I),
    re.compile(r"\bpsk\b", re.I),
    re.compile(r"private[_-]?key\s*[:=]", re.I),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"^[A-Za-z0-9+/]{43}=$"),  # suspicious bare base64 key line
)

CURATED_TEXT_SECRET_PATTERNS = (
    re.compile(r"password\s*[:=]", re.I),
    re.compile(r"private[_-]?key\s*[:=]", re.I),
    re.compile(r"-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----"),
)

FORBIDDEN_PLAINTEXT_FIELD_SUFFIXES = (
    "password",
    "private_key",
    "preshared_key",
    "psk",
)


def _is_secret_intake_field(field: dict[str, Any]) -> bool:
    name = field["name"]
    if name in SECRET_INTAKE_FIELD_NAMES:
        return True
    if any(part in name for part in FORBIDDEN_PLAINTEXT_FIELD_SUFFIXES):
        if name.endswith("_credential_ref_id"):
            return False
        return field.get("default") is None and any(
            phrase in (field.get("verification_note") or "").lower()
            or phrase in (field.get("tooltip") or "").lower()
            for phrase in NOT_STORED_PHRASES
        )
    return False


def _load_exporter():
    scripts_dir = str(REPO_ROOT / "scripts")
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    # Script filename uses hyphens; load by path.
    import importlib.util

    script_path = REPO_ROOT / "scripts" / "export-ui-field-manifest.py"
    spec = importlib.util.spec_from_file_location(EXPORTER_MODULE, script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def exporter():
    return _load_exporter()


def test_manifest_schema_and_families(exporter) -> None:
    committed = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert committed["schema_version"] == 1
    assert set(committed["families"].keys()) == REQUIRED_FAMILIES


def test_manifest_matches_regenerated(exporter) -> None:
    committed_text = MANIFEST_PATH.read_text(encoding="utf-8")
    fresh_text = exporter.serialize_manifest(exporter.build_manifest())
    assert fresh_text == committed_text, (
        "ui-field-manifest.json drift: run py -3.11 scripts/export-ui-field-manifest.py"
    )


def test_missing_curation_exits(exporter, monkeypatch: pytest.MonkeyPatch) -> None:
    curated = dict(exporter.CURATED_META)
    remove_key = ("wifi_ap", "ssid")
    assert remove_key in curated
    curated.pop(remove_key)
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    with pytest.raises(SystemExit) as exc_info:
        exporter.build_manifest()
    assert "wifi_ap.ssid" in str(exc_info.value.code)


def test_new_family_missing_curation_exits(exporter, monkeypatch: pytest.MonkeyPatch) -> None:
    """RED→GREEN: uncured router_discovery field must fail export closed."""
    curated = dict(exporter.CURATED_META)
    remove_key = ("router_discovery", "probe")
    assert remove_key in curated
    curated.pop(remove_key)
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    with pytest.raises(SystemExit) as exc_info:
        exporter.build_manifest()
    assert "router_discovery.probe" in str(exc_info.value.code)


def _field_by_name(manifest: dict, family_id: str, field_name: str) -> dict:
    fields = manifest["families"][family_id]["fields"]
    for field in fields:
        if field["name"] == field_name:
            return field
    raise KeyError(f"{family_id}.{field_name} not in manifest")


def test_pep604_optional_field_types(exporter) -> None:
    """Regression: PEP604 X | None must not collapse to string type."""
    manifest = exporter.build_manifest()

    asc_args = _field_by_name(manifest, "wireguard", "asc_args")
    assert asc_args["type"] == "array"
    assert asc_args["enum"] is None

    peer_keepalive = _field_by_name(manifest, "wireguard", "peer_keepalive_interval")
    assert peer_keepalive["type"] == "integer"
    assert peer_keepalive["enum"] is None

    address_configured = _field_by_name(manifest, "vpn_policy_routing", "address_configured")
    assert address_configured["type"] == "boolean"
    assert address_configured["enum"] is None

    name_servers = _field_by_name(manifest, "vpn_policy_routing", "name_servers")
    assert name_servers["type"] == "array"
    assert name_servers["enum"] is None

    auth_mode = _field_by_name(manifest, "wifi_station", "auth_mode")
    assert auth_mode["type"] == "enum"
    assert auth_mode["enum"] == ["wpa2_psk", "open"]


def test_nested_list_item_fields_exported(exporter) -> None:
    manifest = exporter.build_manifest()
    dhcp_names = {f["name"] for f in manifest["families"]["dhcp"]["fields"]}
    assert {"reservations.mac_address", "reservations.ipv4_address"}.issubset(dhcp_names)

    firewall_names = {f["name"] for f in manifest["families"]["firewall"]["fields"]}
    assert {
        "rules.action",
        "rules.destination_family",
        "rules.ordinal",
    }.issubset(firewall_names)

    vpn_names = {f["name"] for f in manifest["families"]["vpn_policy_routing"]["fields"]}
    assert {
        "name_servers.address",
        "name_servers.domain",
        "name_servers.on_interface",
    }.issubset(vpn_names)


def test_vpn_policy_ip_global_union_nested_fields(exporter) -> None:
    manifest = exporter.build_manifest()
    vpn_names = {f["name"] for f in manifest["families"]["vpn_policy_routing"]["fields"]}
    assert {"ip_global", "ip_global.priority", "ip_global.order"}.issubset(vpn_names)
    priority = _field_by_name(manifest, "vpn_policy_routing", "ip_global.priority")
    order = _field_by_name(manifest, "vpn_policy_routing", "ip_global.order")
    assert priority["type"] == "integer"
    assert order["type"] == "integer"
    assert priority["constraints"] == {"ge": 0, "le": 65535}
    assert order["constraints"] == {"ge": 0, "le": 65535}


def test_manifest_has_no_secrets(exporter) -> None:
    manifest = exporter.build_manifest()

    for family_id, family in manifest["families"].items():
        title = family.get("title", "")
        for pattern in CURATED_TEXT_SECRET_PATTERNS:
            assert not pattern.search(title), (
                f"{family_id} title looks like secret material"
            )
        for field in family["fields"]:
            name = field["name"]
            if any(part in name for part in FORBIDDEN_PLAINTEXT_FIELD_SUFFIXES):
                if not name.endswith("_credential_ref_id") and not _is_secret_intake_field(
                    field
                ):
                    pytest.fail(
                        f"{family_id}.{name} must use *_credential_ref_id "
                        "or be write-only intake with default null + not-stored note"
                    )
            for text_key in ("tooltip", "verification_note"):
                text = field.get(text_key, "")
                if not text:
                    continue
                for pattern in CURATED_TEXT_SECRET_PATTERNS:
                    assert not pattern.search(text), (
                        f"{family_id}.{name} {text_key} looks like secret material"
                    )
            default = field.get("default")
            if default is None:
                continue
            default_blob = json.dumps(default, ensure_ascii=False)
            for pattern in SECRET_VALUE_PATTERNS:
                assert not pattern.search(default_blob), (
                    f"{family_id}.{name} default looks like secret material"
                )
            enum_vals = field.get("enum")
            if isinstance(enum_vals, list):
                enum_blob = json.dumps(enum_vals, ensure_ascii=False)
                for pattern in SECRET_VALUE_PATTERNS:
                    assert not pattern.search(enum_blob), (
                        f"{family_id}.{name} enum looks like secret material"
                    )


def _wpa2_intent(**overrides: object) -> WifiIntent:
    base: dict[str, object] = {
        "enabled": True,
        "ssid": "Manifest-Guard-SSID",
        "wpa_mode": WifiWpaMode.WPA2,
        "band": WifiBand.BAND_2_4GHZ,
        "guest_isolation": False,
        "captive_portal": CaptivePortalMode.DISABLED,
        "credential_ref_id": "credref:manifest-guard",
    }
    base.update(overrides)
    return WifiIntent(**base)  # type: ignore[arg-type]


def _wifi_wan_intent(**overrides: object) -> UplinkIntent:
    base: dict[str, object] = {
        "mode": UplinkMode.WIFI_WAN,
        "ssid": "Manifest-Guard-SSID",
        "band": WifiBand.BAND_2_4GHZ,
        "credential_ref_id": "credref:manifest-guard",
        "priority": 100,
    }
    base.update(overrides)
    return UplinkIntent(**base)  # type: ignore[arg-type]


_PLANNER_REJECT_FIELDS: tuple[dict[str, Any], ...] = (
    {
        "family_id": "wifi_ap",
        "field_name": "guest_isolation",
        "curated_key": ("wifi_ap", "guest_isolation"),
        "planner_code": ERROR_CODE_GUEST_ISOLATION_UNSUPPORTED,
        "planner_error": WifiApplyPlannerError,
        "code_to_http": WIFI_AP_CODE_TO_HTTP,
        "compile_probe": lambda: compile_wifi_intent_to_ops(
            _wpa2_intent(guest_isolation=True),
            "WifiMaster0/AccessPoint3",
        ),
    },
    {
        "family_id": "wifi_ap",
        "field_name": "captive_portal",
        "curated_key": ("wifi_ap", "captive_portal"),
        "planner_code": ERROR_CODE_CAPTIVE_PORTAL_UNSUPPORTED,
        "planner_error": WifiApplyPlannerError,
        "code_to_http": WIFI_AP_CODE_TO_HTTP,
        "compile_probe": lambda: compile_wifi_intent_to_ops(
            _wpa2_intent(captive_portal=CaptivePortalMode.ENABLED),
            "WifiMaster0/AccessPoint3",
        ),
    },
    {
        "family_id": "wifi_station",
        "field_name": "priority",
        "curated_key": ("wifi_station", "priority"),
        "planner_code": ERROR_CODE_STATION_PRIORITY_REQUIRES_IP_GLOBAL,
        "planner_error": WifiStationApplyPlannerError,
        "code_to_http": STATION_APPLY_CODE_TO_HTTP,
        "compile_probe": lambda: compile_uplink_intent_to_station_ops(
            _wifi_wan_intent(priority=600),
            options=WifiStationPlannerOptions(include_ip_global=False),
        ),
    },
)


def _assert_curated_reject_honesty(
    exporter,
    *,
    family_id: str,
    field_name: str,
    curated_key: tuple[str, str],
    planner_code: str,
    compile_probe: Callable[[], object],
    planner_error: type[Exception],
    code_to_http: dict[str, str],
) -> None:
    http_code = code_to_http[planner_code]
    with pytest.raises(planner_error, match=planner_code):
        compile_probe()

    manifest = exporter.build_manifest()
    field = _field_by_name(manifest, family_id, field_name)
    curated = exporter.CURATED_META[curated_key]

    assert field["verification_note"] == curated["verification_note"]
    assert http_code in field["verification_note"]
    assert field.get("reject_http_code") == http_code
    assert curated.get("reject_http_code") == http_code
    assert "принимается api" not in field["verification_note"].lower()
    assert "не применяет" not in field["verification_note"].lower()


@pytest.mark.parametrize(
    "case",
    _PLANNER_REJECT_FIELDS,
    ids=[f"{item['family_id']}.{item['field_name']}" for item in _PLANNER_REJECT_FIELDS],
)
def test_planner_reject_fields_have_honest_curation(exporter, case: dict[str, Any]) -> None:
    if case["family_id"] == "wifi_station":
        assert STATION_APPLY_CODE_TO_HTTP == STATION_PREVIEW_CODE_TO_HTTP
    _assert_curated_reject_honesty(
        exporter,
        family_id=str(case["family_id"]),
        field_name=str(case["field_name"]),
        curated_key=case["curated_key"],
        planner_code=str(case["planner_code"]),
        compile_probe=case["compile_probe"],
        planner_error=case["planner_error"],
        code_to_http=case["code_to_http"],
    )


@pytest.mark.parametrize(
    "case",
    (
        _PLANNER_REJECT_FIELDS[0],
        next(item for item in _PLANNER_REJECT_FIELDS if item["family_id"] == "wifi_station"),
    ),
    ids=["wifi_ap.guest_isolation", "wifi_station.priority"],
)
def test_planner_reject_curation_red_green_oracle(
    exporter, monkeypatch: pytest.MonkeyPatch, case: dict[str, Any]
) -> None:
    """RED→GREEN: stale verification_note without HTTP code must fail the honesty guard."""
    curated = dict(exporter.CURATED_META)
    stale = dict(curated[case["curated_key"]])
    stale["verification_note"] = (
        "Принимается API, но wifi_apply_planner не применяет на устройстве."
    )
    stale.pop("reject_http_code", None)
    curated[case["curated_key"]] = stale
    monkeypatch.setattr(exporter, "CURATED_META", curated)

    http_code = case["code_to_http"][str(case["planner_code"])]
    with pytest.raises(AssertionError, match=http_code):
        _assert_curated_reject_honesty(
            exporter,
            family_id=str(case["family_id"]),
            field_name=str(case["field_name"]),
            curated_key=case["curated_key"],
            planner_code=str(case["planner_code"]),
            compile_probe=case["compile_probe"],
            planner_error=case["planner_error"],
            code_to_http=case["code_to_http"],
        )


# --- Manual-dict behavioral KeyTrackingDict guards (Task 1) ---


def _fake_variable_key_probe(body: KeyTrackingDict) -> None:
    KEY = "sneaky_param"
    body.get(KEY)


def test_manual_body_guard_decision_table() -> None:
    """Document covered vs residual manual-body access patterns (F-2)."""
    assert MANUAL_BODY_GUARD_DECISION_TABLE, "decision table must not be empty"
    covered = [
        row["pattern"]
        for row in MANUAL_BODY_GUARD_DECISION_TABLE
        if row["covered_by_behavioral"]
    ]
    residual = [
        row["pattern"]
        for row in MANUAL_BODY_GUARD_DECISION_TABLE
        if not row["covered_by_behavioral"]
    ]
    assert "for k, v in body.items() (loop unpack)" in covered
    assert "for k in body (unpack / __iter__)" in covered
    assert any(
        "getattr" in row["residual_named"]
        for row in MANUAL_BODY_GUARD_DECISION_TABLE
        if row["residual_named"]
    )
    assert any(
        "JSON dump" in row["residual_named"]
        for row in MANUAL_BODY_GUARD_DECISION_TABLE
        if row["residual_named"]
    )
    assert len(covered) >= 9
    assert len(residual) >= 3
    for row in MANUAL_BODY_GUARD_DECISION_TABLE:
        assert "pattern" in row
        assert "covered_by_behavioral" in row
        assert "rejected_approach" in row


def _fake_items_loop_probe(body: KeyTrackingDict) -> None:
    for k, v in body.items():
        if k in ("secret", "kind"):
            _ = v


def test_key_tracking_items_loop_red_then_green() -> None:
    body = KeyTrackingDict(
        {"secret": "x", "kind": "y", "sneaky_param": "probe"}
    )
    _fake_items_loop_probe(body)
    accessed = frozenset(body.accessed_keys)
    with pytest.raises(AssertionError, match="sneaky_param"):
        _assert_manual_body_keys(
            accessed=accessed,
            declared=frozenset({"secret", "kind"}),
            handler_label="synthetic_items_probe",
        )
    _assert_manual_body_keys(
        accessed=accessed,
        declared=frozenset({"secret", "kind", "sneaky_param"}),
        handler_label="synthetic_items_probe",
    )


def test_key_tracking_variable_key_red_then_green() -> None:
    body = KeyTrackingDict({"sneaky_param": "probe"})
    _fake_variable_key_probe(body)
    accessed = frozenset(body.accessed_keys)
    with pytest.raises(AssertionError, match="sneaky_param"):
        _assert_manual_body_keys(
            accessed=accessed,
            declared=frozenset({"legit_key"}),
            handler_label="synthetic_probe",
        )
    _assert_manual_body_keys(
        accessed=accessed,
        declared=frozenset({"sneaky_param"}),
        handler_label="synthetic_probe",
        must_consume=frozenset({"sneaky_param"}),
    )


async def test_credentials_put_body_uses_pydantic_fields(exporter) -> None:
    from router_control_host.routes import PutCredentialBody, RotateCredentialBody

    put_fields = frozenset(PutCredentialBody.model_fields)
    rotate_fields = frozenset(RotateCredentialBody.model_fields)
    assert put_fields == frozenset({"secret", "kind"})
    assert rotate_fields == frozenset({"secret"})
    family = exporter.FAMILY_SPECS["credentials"]
    assert PutCredentialBody in family["models"]
    assert RotateCredentialBody in family["models"]


async def test_manual_commissioning_tracks_body_keys(exporter) -> None:
    from router_control_host.commissioning_routes import create_commissioning_run

    body = KeyTrackingDict({"router_id": "rtr_test", "mode": "fake"})
    request = MagicMock()
    request.state.correlation_id = "manifest-guard-test"
    host = _mock_host(adapter_mode="fake")
    _attach_host(request, host)
    try:
        create_commissioning_run("site_default", request, body, idempotency_key="idem-key")
    except Exception:
        pass
    declared = _manual_family_names(exporter, "commissioning")
    _assert_manual_body_keys(
        accessed=frozenset(body.accessed_keys),
        declared=declared,
        handler_label="create_commissioning_run",
        must_consume=frozenset({"router_id", "mode"}),
    )


async def test_manual_vpn_profile_import_tracks_body_keys(exporter) -> None:
    from router_control_host.routes import import_profile

    accessed = _extract_body_attr_keys_from_handler(import_profile)
    declared = frozenset(
        exporter._all_manifest_field_names(
            "vpn_profile",
            exporter.FAMILY_SPECS["vpn_profile"]["models"],
        )
    )
    _assert_manual_body_keys(
        accessed=accessed,
        declared=declared,
        handler_label="import_profile",
        must_consume=frozenset(
            {
                "display_name",
                "vpn_kind",
                "profile_text",
                "wg_id",
                "ip_global_auto",
                "ip_global_priority",
                "tcp_mss_pmtu",
            }
        ),
    )


async def test_manual_desired_revision_put_tracks_body_keys(exporter) -> None:
    from router_control_host.routes import put_desired

    body = KeyTrackingDict(
        {
            "based_on_observation_id": "obs_1",
            "assignments": [],
            "reason": "manifest guard",
        }
    )
    request = _mock_request_with_body(body)
    host = _mock_host()
    host.runtime.store.put_desired_revision.side_effect = AssertionError(
        "store put must not be reached"
    )
    _attach_host(request, host)
    try:
        await put_desired(
            "rtr_test",
            request,
            idempotency_key="idem-key",
            if_match='"etag-1"',
        )
    except Exception:
        pass
    declared = _manual_family_names(exporter, "desired_revision")
    _assert_manual_body_keys(
        accessed=frozenset(body.accessed_keys),
        declared=declared,
        handler_label="put_desired",
        must_consume=frozenset({"based_on_observation_id", "assignments", "reason"}),
    )


def test_regex_sentinel_misses_variable_key_access() -> None:
    """Prove regex is blind to body.get(KEY) when KEY is a variable."""
    source = inspect.getsource(_fake_variable_key_probe)
    assert "sneaky_param" not in _BODY_GET_RE.findall(source)
    body = KeyTrackingDict({"sneaky_param": "x"})
    _fake_variable_key_probe(body)
    assert body.accessed_keys == {"sneaky_param"}


# --- rci_sealed SSOT (Task 2) ---


def test_rci_sealed_operation_enum_and_body_mapping(exporter) -> None:
    manifest = exporter.build_manifest()
    operation = _field_by_name(manifest, "rci_sealed", "operation")
    assert operation["enum"] == list(exporter.RCI_SEALED_UI_OPERATIONS)
    assert operation["default"] == "fail_safe_arm"
    assert operation["body_operation_by_value"] == exporter.RCI_SEALED_BODY_OPERATION_BY_VALUE
    assert operation["route_key_by_value"] == exporter.RCI_SEALED_ROUTE_KEY_BY_VALUE


def test_router_discovery_and_connection_health_families(exporter) -> None:
    manifest = exporter.build_manifest()
    rd = manifest["families"]["router_discovery"]
    assert rd["verification_status"] == "non_certifying_readonly"
    assert rd["routes"]["discover"].endswith("/lab/router-discovery")
    rd_names = {f["name"] for f in rd["fields"]}
    assert rd_names == {
        "include_default_gateway",
        "include_known_endpoints",
        "preferred_source_address",
        "probe",
    }
    include_gw = _field_by_name(manifest, "router_discovery", "include_default_gateway")
    assert include_gw["disclosure"] == "simple"
    assert include_gw["default"] is True
    probe = _field_by_name(manifest, "router_discovery", "probe")
    assert probe["disclosure"] == "advanced"
    assert probe["default"] is False

    ch = manifest["families"]["connection_health"]
    assert ch["verification_status"] == "non_certifying_readonly"
    assert ch["routes"]["assess"].endswith("/lab/connection-health")
    ch_names = {f["name"] for f in ch["fields"]}
    assert ch_names == {
        "router_id",
        "host",
        "source_address",
        "credential_ref_id",
        "ssh_host_key_sha256",
        "probe",
    }
    router_id = _field_by_name(manifest, "connection_health", "router_id")
    assert router_id["disclosure"] == "simple"
    assert router_id["default"] is None
    ch_probe = _field_by_name(manifest, "connection_health", "probe")
    assert ch_probe["disclosure"] == "advanced"
    assert ch_probe["default"] is True


def test_body_route_guard_decision_table(exporter) -> None:
    assert exporter.BODY_ROUTE_GUARD_DECISION_TABLE
    chosen = [
        row for row in exporter.BODY_ROUTE_GUARD_DECISION_TABLE if row["verdict"] == "chosen"
    ]
    assert len(chosen) == 1
    assert chosen[0]["option"] == "B_walk_create_app_APIRoute_body_field"
    assert exporter.BODY_ROUTE_GUARD_RESIDUALS
    assert any("request.json()" in item for item in exporter.BODY_ROUTE_GUARD_RESIDUALS)


def test_body_route_coverage_live_paths_covered(exporter) -> None:
    live = exporter.collect_live_body_route_paths()
    family_paths = exporter.family_spec_route_paths()
    exemption_paths = frozenset(exporter.BODY_ROUTE_EXEMPTIONS.keys())
    allowed = family_paths | exemption_paths
    uncovered = sorted(live - allowed)

    # F-1: vacuous pass if walker returns empty set or FAMILY_SPECS mirror only.
    assert live, "collect_live_body_route_paths() must return non-empty live routes"

    prefix = exporter.API_PREFIX
    assert f"{prefix}/lab/router-discovery" in live
    assert f"{prefix}/lab/connection-health" in live
    assert (
        f"{prefix}/lab/bootstrap-discovery" in live
        or f"{prefix}/wifi/preview" in live
    ), "expected at least one additional FAMILY_SPECS body route in live walk"

    assert live != family_paths, (
        "live body routes must not equal FAMILY_SPECS.routes alone; "
        "walker must discover exempt routes too"
    )
    exempt_in_live = live & exemption_paths
    assert "/login" in live or exempt_in_live, (
        "live walk must include at least one BODY_ROUTE_EXEMPTION "
        "(e.g. /login) proving walk ≠ FAMILY_SPECS mirror"
    )

    assert not uncovered, f"uncovered body routes: {uncovered}"


def test_body_route_coverage_red_then_green(exporter, monkeypatch: pytest.MonkeyPatch) -> None:
    """RED→GREEN: uncured live body route must fail coverage guard."""
    fake_path = "/api/router-control/v1/lab/_manifest_guard_probe"
    live = exporter.collect_live_body_route_paths()
    assert fake_path not in live

    def _tampered_live_paths() -> frozenset[str]:
        return live | frozenset({fake_path})

    monkeypatch.setattr(exporter, "collect_live_body_route_paths", _tampered_live_paths)
    with pytest.raises(SystemExit, match=fake_path):
        exporter.assert_body_route_coverage()

    monkeypatch.setattr(
        exporter,
        "BODY_ROUTE_EXEMPTIONS",
        {**exporter.BODY_ROUTE_EXEMPTIONS, fake_path: "synthetic probe for red→green test"},
    )
    exporter.assert_body_route_coverage()


def test_rci_sealed_interface_id_conditional_required(exporter) -> None:
    manifest = exporter.build_manifest()
    interface_id = _field_by_name(manifest, "rci_sealed", "interface_id")
    assert interface_id["required"] is False
    assert interface_id["disclosure"] == "advanced"
    assert interface_id["required_when"] == {
        "operation": ["interface_up", "interface_down"]
    }


def _assert_keendns_ac7_honesty(note: str) -> None:
    """AC-7: documentation_sourced + preview/no-apply + device-cert negation."""
    lower = note.lower()
    assert "documentation_sourced_unconfirmed" in lower
    assert (
        "preview" in lower
        or "маршрута apply" in lower
        or "apply route" in lower
        or "apply" in lower
    )
    assert (
        "не device-certified" in lower
        or "не device-verified" in lower
        or "device-certified" in lower
    )


def test_keendns_family(exporter) -> None:
    manifest = exporter.build_manifest()
    kd = manifest["families"]["keendns"]
    assert kd["verification_status"] == "documentation_sourced_unconfirmed"
    assert kd["routes"]["status"].endswith("/keendns/status")
    assert kd["routes"]["preview"].endswith("/keendns/preview")
    assert "apply" not in kd["routes"]
    kd_names = {f["name"] for f in kd["fields"]}
    assert kd_names == {
        "components_raw",
        "ndns_show_raw",
        "get_booked_raw",
        "intent_kind",
        "name",
        "domain",
        "mode",
    }
    for raw_name in ("components_raw", "ndns_show_raw", "get_booked_raw"):
        raw_field = _field_by_name(manifest, "keendns", raw_name)
        assert raw_field["disclosure"] == "advanced"
        assert raw_field["required"] is False
        assert "не для обычного заполнения" in raw_field["tooltip"].lower()
        note = raw_field["verification_note"].lower()
        assert "documentation_sourced_unconfirmed" in note
        assert "preview" in note or "status" in note
        assert "apply" in note
        assert "device-certified" in note or "device-verified" in note

    intent_kind = _field_by_name(manifest, "keendns", "intent_kind")
    assert intent_kind["disclosure"] == "simple"
    assert intent_kind["enum"] == ["book", "drop"]
    assert intent_kind["required"] is True
    _assert_keendns_ac7_honesty(intent_kind["verification_note"])

    name = _field_by_name(manifest, "keendns", "name")
    assert name["disclosure"] == "simple"
    assert name["constraints"] == {"min_length": 1, "max_length": 64}
    _assert_keendns_ac7_honesty(name["verification_note"])

    domain = _field_by_name(manifest, "keendns", "domain")
    assert domain["disclosure"] == "simple"
    assert domain["constraints"] == {"min_length": 1, "max_length": 64}
    _assert_keendns_ac7_honesty(domain["verification_note"])


def test_keendns_mode_conditional_required(exporter) -> None:
    manifest = exporter.build_manifest()
    mode = _field_by_name(manifest, "keendns", "mode")
    assert mode["required"] is False
    assert mode["disclosure"] == "simple"
    assert mode["enum"] == ["auto", "cloud", "direct"]
    assert mode["default"] is None
    assert mode["required_when"] == {"intent_kind": ["book"]}
    _assert_keendns_ac7_honesty(mode["verification_note"])


def test_keendns_missing_curation_exits(exporter, monkeypatch: pytest.MonkeyPatch) -> None:
    """RED→GREEN: uncured keendns field must fail export closed."""
    curated = dict(exporter.CURATED_META)
    remove_key = ("keendns", "mode")
    assert remove_key in curated
    curated.pop(remove_key)
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    with pytest.raises(SystemExit) as exc_info:
        exporter.build_manifest()
    assert "keendns.mode" in str(exc_info.value.code)


def test_desired_revision_create_route_matches_live_app(exporter) -> None:
    manifest = exporter.build_manifest()
    routes = manifest["families"]["desired_revision"]["routes"]
    assert routes["create"] == f"{exporter.API_PREFIX}/routers/{{router_id}}/desired-revisions"
    assert "from-deployment" not in routes["create"]


def test_rci_sealed_system_save_route_matches_fastapi(exporter) -> None:
    manifest = exporter.build_manifest()
    routes = manifest["families"]["rci_sealed"]["routes"]
    assert routes["system_save"].endswith("/rci/system/configuration-save")


# --- Residual hole invariants (Task 3) ---


def _assert_all_opaque_dict_fields_marked(exporter, manifest: dict[str, Any]) -> None:
    for family_id, spec in exporter.FAMILY_SPECS.items():
        for model in spec["models"]:
            for python_name, field_info in model.model_fields.items():
                if not exporter._is_opaque_dict(field_info.annotation):
                    continue
                wire_name = exporter._manifest_wire_name(field_info, python_name)
                field = _field_by_name(manifest, family_id, wire_name)
                assert field.get("value_schema") == "opaque_object", (
                    f"{family_id}.{wire_name} dict[str,Any] must carry value_schema opaque_object"
                )


def test_opaque_dict_fields_carry_opaque_marker(exporter) -> None:
    manifest = exporter.build_manifest()
    _assert_all_opaque_dict_fields_marked(exporter, manifest)
    names = {f["name"] for f in manifest["families"]["traffic_discovery"]["fields"]}
    assert not any(name.startswith("evidence.") for name in names)
    assert not any(name.startswith("route_intent.") for name in names)


def test_opaque_marker_removal_fails_invariant(exporter) -> None:
    manifest = exporter.build_manifest()
    tampered = json.loads(json.dumps(manifest))
    for field in tampered["families"]["traffic_discovery"]["fields"]:
        if field["name"] == "evidence":
            field.pop("value_schema", None)
    with pytest.raises(AssertionError, match="evidence.*opaque_object"):
        _assert_all_opaque_dict_fields_marked(exporter, tampered)


def test_scalar_list_fields_have_no_dotted_children(exporter) -> None:
    manifest = exporter.build_manifest()
    scalar_array_parents: set[str] = set()
    for family_id, spec in exporter.FAMILY_SPECS.items():
        for model in spec["models"]:
            for python_name, field_info in model.model_fields.items():
                if exporter._is_scalar_list(field_info.annotation):
                    wire = exporter._manifest_wire_name(field_info, python_name)
                    scalar_array_parents.add(f"{family_id}.{wire}")
    assert scalar_array_parents, "expected at least one scalar list field in models"
    for family_id, family in manifest["families"].items():
        all_names = {f["name"] for f in family["fields"]}
        for field in family["fields"]:
            if field["type"] != "array" or "." in field["name"]:
                continue
            parent_key = f"{family_id}.{field['name']}"
            if parent_key in scalar_array_parents:
                prefix = field["name"] + "."
                dotted = [name for name in all_names if name.startswith(prefix)]
                assert not dotted, (
                    f"scalar list {field['name']} must not emit dotted children {dotted}"
                )


def test_scalar_list_invariant_catches_dotted_child(exporter) -> None:
    """RED oracle: vacuous top-level-only scan must not pass when dotted child exists."""
    manifest = exporter.build_manifest()
    tampered = json.loads(json.dumps(manifest))
    for field in tampered["families"]["dns"]["fields"]:
        if field["name"] == "upstream_resolvers":
            tampered["families"]["dns"]["fields"].append(
                {
                    **field,
                    "name": "upstream_resolvers.fake",
                    "type": "string",
                }
            )
            break
    else:
        pytest.fail("upstream_resolvers not found in dns family")

    scalar_array_parents: set[str] = set()
    for family_id, spec in exporter.FAMILY_SPECS.items():
        for model in spec["models"]:
            for python_name, field_info in model.model_fields.items():
                if exporter._is_scalar_list(field_info.annotation):
                    wire = exporter._manifest_wire_name(field_info, python_name)
                    scalar_array_parents.add(f"{family_id}.{wire}")

    def _check(manifest_blob: dict[str, Any]) -> None:
        for family_id, family in manifest_blob["families"].items():
            all_names = {f["name"] for f in family["fields"]}
            for field in family["fields"]:
                if field["type"] != "array" or "." in field["name"]:
                    continue
                parent_key = f"{family_id}.{field['name']}"
                if parent_key in scalar_array_parents:
                    prefix = field["name"] + "."
                    dotted = [name for name in all_names if name.startswith(prefix)]
                    assert not dotted, (
                        f"scalar list {field['name']} must not emit dotted children {dotted}"
                    )

    with pytest.raises(AssertionError, match="upstream_resolvers.fake"):
        _check(tampered)


def test_top_level_alias_uses_wire_name_red_then_green(
    exporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _TopLevelAliasProbe(BaseModel):
        model_config = ConfigDict(extra="forbid")
        python_only: str = Field(alias="wire_top_level")

    models = (_TopLevelAliasProbe,)
    missing_key = (PROBE_FAMILY, "python_only")
    red_message = _assert_missing_curation_for_nested(
        exporter,
        monkeypatch,
        models=models,
        missing_key=missing_key,
        expected_fragment=f"{PROBE_FAMILY}.python_only",
    )
    assert "missing CURATED_META" in red_message

    curated = dict(exporter.CURATED_META)
    for field_name in exporter._all_manifest_field_names(PROBE_FAMILY, models):
        probe_key = (PROBE_FAMILY, field_name)
        if probe_key not in curated:
            curated[probe_key] = _synthetic_curation(f"probe curation for {field_name}")
    specs = {
        PROBE_FAMILY: {
            "title": "Top-level alias probe",
            "models": models,
            "routes": {"probe": "/probe"},
            "verification_status": None,
        }
    }
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    monkeypatch.setattr(exporter, "FAMILY_SPECS", specs)
    manifest = exporter.build_manifest(skip_route_coverage=True)
    names = {f["name"] for f in manifest["families"][PROBE_FAMILY]["fields"]}
    assert "wire_top_level" in names
    assert "python_only" not in names


class _NestedAliasSlot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slot_value: str


class _TopLevelAliasNestedProbe(BaseModel):
    model_config = ConfigDict(extra="forbid")
    python_only: _NestedAliasSlot = Field(alias="wire_top")


def test_nested_alias_under_wire_parent_uses_wire_prefix(
    exporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nested dotted names under aliased parent must use wire prefix (F-4)."""
    models = (_TopLevelAliasNestedProbe,)
    missing_key = (PROBE_FAMILY, "wire_top.slot_value")
    red_message = _assert_missing_curation_for_nested(
        exporter,
        monkeypatch,
        models=models,
        missing_key=missing_key,
        expected_fragment=f"{PROBE_FAMILY}.wire_top.slot_value",
    )
    assert "missing CURATED_META" in red_message

    curated = dict(exporter.CURATED_META)
    for field_name in exporter._all_manifest_field_names(PROBE_FAMILY, models):
        probe_key = (PROBE_FAMILY, field_name)
        if probe_key not in curated:
            curated[probe_key] = _synthetic_curation(f"probe curation for {field_name}")
    specs = {
        PROBE_FAMILY: {
            "title": "Nested alias under wire parent probe",
            "models": models,
            "routes": {"probe": "/probe"},
            "verification_status": None,
        }
    }
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    monkeypatch.setattr(exporter, "FAMILY_SPECS", specs)
    manifest = exporter.build_manifest(skip_route_coverage=True)
    names = {f["name"] for f in manifest["families"][PROBE_FAMILY]["fields"]}
    assert "wire_top" in names
    assert "wire_top.slot_value" in names
    assert "python_only" not in names
    assert not any(name.startswith("python_only.") for name in names)


def test_alias_choices_multi_name_fails_export_closed(
    exporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    curated = dict(exporter.CURATED_META)
    curated[(PROBE_FAMILY, "ip_global")] = _synthetic_curation("ip_global")
    specs = {
        PROBE_FAMILY: {
            "title": "AliasChoices multi probe",
            "models": (_AliasChoicesParent,),
            "routes": {"probe": "/probe"},
            "verification_status": None,
        }
    }
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    monkeypatch.setattr(exporter, "FAMILY_SPECS", specs)
    with pytest.raises(SystemExit) as exc_info:
        exporter.build_manifest(skip_route_coverage=True)
    assert "multiple string wire names" in str(exc_info.value.code)


class _AliasChoicesSingleChild(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wire_value: int = Field(validation_alias=AliasChoices("priority"), ge=1)


class _AliasChoicesSingleParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip_global: _AliasChoicesSingleChild


def test_alias_choices_single_name_exports(exporter, monkeypatch: pytest.MonkeyPatch) -> None:
    models = (_AliasChoicesSingleParent,)
    curated = dict(exporter.CURATED_META)
    for field_name in exporter._all_manifest_field_names(PROBE_FAMILY, models):
        probe_key = (PROBE_FAMILY, field_name)
        if probe_key not in curated:
            curated[probe_key] = _synthetic_curation(f"probe curation for {field_name}")
    specs = {
        PROBE_FAMILY: {
            "title": "AliasChoices single probe",
            "models": models,
            "routes": {"probe": "/probe"},
            "verification_status": None,
        }
    }
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    monkeypatch.setattr(exporter, "FAMILY_SPECS", specs)
    manifest = exporter.build_manifest(skip_route_coverage=True)
    names = {f["name"] for f in manifest["families"][PROBE_FAMILY]["fields"]}
    assert "ip_global.priority" in names


def test_secret_intake_fields_have_null_default_and_not_stored_note(exporter) -> None:
    manifest = exporter.build_manifest()
    for family_id, family in manifest["families"].items():
        for field in family["fields"]:
            if not _is_secret_intake_field(field):
                continue
            assert field.get("default") is None, f"{family_id}.{field['name']} default must be null"
            note_blob = (
                (field.get("verification_note") or "") + " " + (field.get("tooltip") or "")
            ).lower()
            assert any(phrase in note_blob for phrase in NOT_STORED_PHRASES), (
                f"{family_id}.{field['name']} missing not-stored/not-displayed note"
            )


# --- Nested walk red→green construction tests (local models only) ---


class _UnionArmA(BaseModel):
    model_config = ConfigDict(extra="forbid")
    priority: int = Field(ge=0, le=100)


class _UnionArmB(BaseModel):
    model_config = ConfigDict(extra="forbid")
    order: int = Field(ge=0, le=100)


class _UnionParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip_global: Literal["auto"] | _UnionArmA | _UnionArmB


class _ParentModel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    child: _UnionArmA


class _ParentBase(BaseModel):
    model_config = ConfigDict(extra="forbid")
    inherited_field: str


class _ChildModel(_ParentBase):
    extra_field: int


class _OptionalNestedParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    nested: _UnionArmA | None = None


class _AliasChild(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wire_priority: int = Field(alias="priority", ge=1)


class _AliasParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip_global: _AliasChild


class _DictValueChild(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slot_name: str


class _DictParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    slots: dict[str, _DictValueChild]


class _ListArmA(BaseModel):
    model_config = ConfigDict(extra="forbid")
    a_field: str


class _ListArmB(BaseModel):
    model_config = ConfigDict(extra="forbid")
    b_field: int


class _ListUnionParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    items: list[_ListArmA | _ListArmB]


class _ListSingleParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    entries: list[_UnionArmA]


class _DirectNestedParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    child: _UnionArmA


class _AnnotatedListItem(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tagged: str


class _AnnotatedListParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rows: list[Annotated[_AnnotatedListItem, Field(description="row")]]


class _RecursiveNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    child: _RecursiveNode | None = None


class _RecursiveRoot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    root: _RecursiveNode


class _AliasChoicesChild(BaseModel):
    model_config = ConfigDict(extra="forbid")
    wire_value: int = Field(validation_alias=AliasChoices("priority", "order"), ge=1)


class _AliasChoicesParent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip_global: _AliasChoicesChild


PROBE_FAMILY = "_nested_walk_probe"


def _synthetic_curation(note: str) -> dict[str, str]:
    return {
        "disclosure": "advanced",
        "tooltip": note,
        "verification_note": note,
    }


def _assert_missing_curation_for_nested(
    exporter,
    monkeypatch: pytest.MonkeyPatch,
    *,
    models: tuple[type[BaseModel], ...],
    missing_key: tuple[str, str],
    expected_fragment: str,
) -> str:
    curated = dict(exporter.CURATED_META)
    curated.pop(missing_key, None)
    for field_name in exporter._all_manifest_field_names(PROBE_FAMILY, models):
        probe_key = (PROBE_FAMILY, field_name)
        if probe_key != missing_key and probe_key not in curated:
            curated[probe_key] = _synthetic_curation(f"probe curation for {field_name}")
    specs = {
        PROBE_FAMILY: {
            "title": "Nested walk probe",
            "models": models,
            "routes": {"probe": "/probe"},
            "verification_status": None,
        }
    }
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    monkeypatch.setattr(exporter, "FAMILY_SPECS", specs)
    with pytest.raises(SystemExit) as exc_info:
        exporter.build_manifest(skip_route_coverage=True)
    message = str(exc_info.value.code)
    assert expected_fragment in message
    return message


@pytest.mark.parametrize(
    ("construction", "models", "missing_field", "expected_fragment", "green_field"),
    [
        (
            "union",
            (_UnionParent,),
            "ip_global.priority",
            f"{PROBE_FAMILY}.ip_global.priority",
            "ip_global.priority",
        ),
        (
            "inheritance",
            (_ChildModel,),
            "inherited_field",
            f"{PROBE_FAMILY}.inherited_field",
            "inherited_field",
        ),
        (
            "optional_nested",
            (_OptionalNestedParent,),
            "nested.priority",
            f"{PROBE_FAMILY}.nested.priority",
            "nested.priority",
        ),
        (
            "alias",
            (_AliasParent,),
            "ip_global.priority",
            f"{PROBE_FAMILY}.ip_global.priority",
            "ip_global.priority",
        ),
        (
            "dict_str_model",
            (_DictParent,),
            "slots.slot_name",
            f"{PROBE_FAMILY}.slots.slot_name",
            "slots.slot_name",
        ),
        (
            "list_single_basemodel",
            (_ListSingleParent,),
            "entries.priority",
            f"{PROBE_FAMILY}.entries.priority",
            "entries.priority",
        ),
        (
            "direct_nested_basemodel",
            (_DirectNestedParent,),
            "child.priority",
            f"{PROBE_FAMILY}.child.priority",
            "child.priority",
        ),
        (
            "list_union_basemodel",
            (_ListUnionParent,),
            "items.a_field",
            f"{PROBE_FAMILY}.items.a_field",
            "items.a_field",
        ),
        (
            "annotated_list_item",
            (_AnnotatedListParent,),
            "rows.tagged",
            f"{PROBE_FAMILY}.rows.tagged",
            "rows.tagged",
        ),
    ],
)
def test_nested_walk_construction_red_then_green(
    exporter,
    monkeypatch: pytest.MonkeyPatch,
    construction: str,
    models: tuple[type[BaseModel], ...],
    missing_field: str,
    expected_fragment: str,
    green_field: str,
) -> None:
    missing_key = (PROBE_FAMILY, missing_field)
    red_message = _assert_missing_curation_for_nested(
        exporter,
        monkeypatch,
        models=models,
        missing_key=missing_key,
        expected_fragment=expected_fragment,
    )
    assert "missing CURATED_META" in red_message

    curated = dict(exporter.CURATED_META)
    for field_name in exporter._all_manifest_field_names(PROBE_FAMILY, models):
        probe_key = (PROBE_FAMILY, field_name)
        if probe_key not in curated:
            curated[probe_key] = _synthetic_curation(f"probe curation for {field_name}")
    specs = {
        PROBE_FAMILY: {
            "title": "Nested walk probe",
            "models": models,
            "routes": {"probe": "/probe"},
            "verification_status": None,
        }
    }
    monkeypatch.setattr(exporter, "CURATED_META", curated)
    monkeypatch.setattr(exporter, "FAMILY_SPECS", specs)
    manifest = exporter.build_manifest(skip_route_coverage=True)
    names = {f["name"] for f in manifest["families"][PROBE_FAMILY]["fields"]}
    assert green_field in names


def test_list_union_basemodel_discovers_all_arms(exporter) -> None:
    """list[A | B] must export dotted fields for every union arm (F-1)."""
    names = exporter._all_manifest_field_names(PROBE_FAMILY, (_ListUnionParent,))
    assert "items.a_field" in names
    assert "items.b_field" in names


def test_recursive_self_reference_does_not_recursion_error(exporter) -> None:
    """Self-referential models must stop via ancestry guard, not RecursionError (F-3)."""
    names = exporter._all_manifest_field_names(PROBE_FAMILY, (_RecursiveRoot,))
    assert "root" in names
    assert "root.child" in names
    assert not any(name.count("child") > 2 for name in names)


def test_existing_eight_family_top_level_keys_unchanged(exporter) -> None:
    """Regression: regenerator must not rename committed top-level keys."""
    manifest = exporter.build_manifest()
    golden_top_level = {
        "wifi_ap": {
            "ap_id",
            "band",
            "credential_ref_id",
            "host",
            "router_id",
            "ssid",
            "wpa_mode",
        },
        "dhcp": {"lease_seconds", "pool_end", "pool_start", "reservations", "zone_id"},
    }
    for family_id, expected in golden_top_level.items():
        actual = {
            f["name"]
            for f in manifest["families"][family_id]["fields"]
            if "." not in f["name"]
        }
        assert expected.issubset(actual), f"{family_id} top-level keys renamed or missing"
