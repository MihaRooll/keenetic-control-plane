"""Deterministic Gate A security invariant oracles (offline, no live network)."""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze.adapter import NetcrazeReadOnlyAdapter
from router_control.adapters.netcraze.allowlist import (
    ALLOWLIST,
    COMPONENTS_LIST,
    DISCOVERY_ALLOWLIST,
    SHOW_IDENTIFICATION,
    SHOW_INTERFACE,
    SHOW_IP_ROUTE,
    SHOW_RC_INTERFACE,
    SHOW_SYSTEM,
    SHOW_VERSION,
    STATION_READ_ALLOWLIST,
    HttpMethod,
    ReadCommand,
    is_allowlisted,
    is_discovery_allowlisted,
    is_station_read_allowlisted,
)
from router_control.adapters.netcraze.errors import AllowlistViolation, AuthFailed
from router_control.adapters.netcraze.gate_a_certification import GateACertification
from router_control.adapters.netcraze.sanitize import build_gate_a_evidence, sanitize_mapping
from router_control.adapters.netcraze.ssh_tunnel import (
    SshTunnelConfig,
    sanitize_ssh_error_message,
)
from router_control.adapters.netcraze.transport import NetcrazeTransport
from router_control.domain.entities import ChangePlan, ChangePlanItem
from router_control.domain.enums import PlanConfirmationState
from router_control.domain.errors import MutationForbidden
from router_control.domain.ids import (
    ObservationId,
    OperationId,
    PlanId,
    ResourceId,
    RevisionId,
    RouterId,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
PROBE_SCRIPT = REPO_ROOT / "scripts" / "probe-gate-a.py"
TOPOLOGY_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-topology.py"
DEFAULT_ROUTE_SCRIPT = REPO_ROOT / "scripts" / "probe-nc1812-default-route.py"
STORE_SCRIPT = REPO_ROOT / "scripts" / "store-router-credential.py"
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "netcraze"

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
SYNTH_USERNAME = "SENTINEL-USERNAME-ORACLE"
SYNTH_SESSION = "SENTINEL-SESSION-ORACLE"
SYNTH_TOKEN = "SENTINEL-TOKEN-ORACLE"
SYNTH_SERIAL = "SENTINEL-SERIAL-ORACLE-999"
SYNTH_SERVICETAG = "SENTINEL-SERVICETAG-ORACLE"
SYNTH_MAC = "DE:AD:BE:EF:00:99"
SYNTH_CREDENTIAL_REF = "SENTINEL-CREDREF-ORACLE"
SYNTH_PROVIDER_LOCATOR = "SENTINEL-PROVIDER-LOCATOR-ORACLE"
SYNTH_STARTUP_CONFIG = "SENTINEL-STARTUP-CONFIG-ORACLE"
SYNTH_RUNNING_CONFIG = "SENTINEL-RUNNING-CONFIG-ORACLE"
SYNTH_LOG = "SENTINEL-LOG-ORACLE"
SYNTH_SELF_TEST = "SENTINEL-SELF-TEST-ORACLE"

FORBIDDEN_SENTINELS = (
    SYNTH_PASSWORD,
    SYNTH_USERNAME,
    SYNTH_SESSION,
    SYNTH_TOKEN,
    SYNTH_SERIAL,
    SYNTH_SERVICETAG,
    SYNTH_MAC.replace(":", ""),
    SYNTH_MAC,
    SYNTH_CREDENTIAL_REF,
    SYNTH_PROVIDER_LOCATOR,
    SYNTH_STARTUP_CONFIG,
    SYNTH_RUNNING_CONFIG,
    SYNTH_LOG,
    SYNTH_SELF_TEST,
)

GATE_A_FROZEN_COMMANDS = frozenset(
    {
        (HttpMethod.GET, "/rci/show/system"),
        (HttpMethod.POST, "/rci/components/list"),
        (HttpMethod.GET, "/rci/show/identification"),
        (HttpMethod.GET, "/rci/show/version"),
    }
)

REJECTED_RCI_PATHS = (
    ("GET", "/rci/show/running-config"),
    ("GET", "/rci/show/startup-config"),
    ("GET", "/rci/log"),
    ("POST", "/rci/self-test"),
    ("POST", "/rci/raw/show/system"),
    ("GET", "/rci/raw/components/list"),
    ("POST", "/rci/mutate/system"),
    ("PUT", "/rci/show/system"),
    ("DELETE", "/rci/components/list"),
    ("GET", "/rci/arbitrary"),
)

PASSWORD_ENV_VARS = (
    "ROUTER_PASSWORD",
    "RCI_PASSWORD",
    "NETCRAZE_PASSWORD",
    "PROBE_PASSWORD",
    "RC_PASSWORD",
    "HUB_ADMIN_PASSWORD",
)


def _load_script_module(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _assert_no_sentinels(blob: str, *, allow: frozenset[str] = frozenset()) -> None:
    lowered = blob.lower()
    for sentinel in FORBIDDEN_SENTINELS:
        if sentinel in allow:
            continue
        assert sentinel not in blob, f"forbidden sentinel leaked: {sentinel!r}"
        assert sentinel.lower() not in lowered, (
            f"forbidden sentinel leaked (case-insensitive): {sentinel!r}"
        )


def _assert_excludes_sensitive_repr_and_errors(blob: str) -> None:
    for sentinel in (SYNTH_PASSWORD, SYNTH_SESSION, SYNTH_TOKEN, SYNTH_SERIAL, SYNTH_SERVICETAG):
        assert sentinel not in blob, f"sensitive sentinel leaked: {sentinel!r}"


def _scan_script_password_surface(script_path: Path) -> tuple[set[str], set[str]]:
    source = script_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    argv_password_flags: set[str] = set()
    env_password_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "add_argument":
                for arg in node.args:
                    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                        if "password" in arg.value.lower() and "credential-ref" not in arg.value:
                            argv_password_flags.add(arg.value)
                for keyword in node.keywords:
                    if keyword.arg == "dest" and isinstance(keyword.value, ast.Constant):
                        if "password" in str(keyword.value.value).lower():
                            argv_password_flags.add(str(keyword.value.value))
            if isinstance(func, ast.Attribute) and func.attr in ("getenv", "get"):
                env_key: str | None = None
                if node.args and isinstance(node.args[0], ast.Constant):
                    env_key = str(node.args[0].value)
                if env_key and "password" in env_key.lower():
                    env_password_names.add(env_key)
    return argv_password_flags, env_password_names


@pytest.fixture(scope="module")
def probe_module():
    return _load_script_module(PROBE_SCRIPT, "probe_gate_a_security")


@pytest.fixture(scope="module")
def store_module():
    return _load_script_module(STORE_SCRIPT, "store_router_credential_security")


class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC)


@dataclass
class BanHttpClient:
    calls: list[tuple[str, str]] = field(default_factory=list)

    def request(self, **_kwargs: object) -> object:
        raise AssertionError("HTTP client must not be called for rejected allowlist paths")


def test_allowlist_exactly_four_frozen_commands() -> None:
    assert len(ALLOWLIST) == 4
    assert ALLOWLIST == frozenset(
        {SHOW_SYSTEM, COMPONENTS_LIST, SHOW_IDENTIFICATION, SHOW_VERSION}
    )
    observed = frozenset((command.method, command.path) for command in ALLOWLIST)
    assert observed == GATE_A_FROZEN_COMMANDS


@pytest.mark.parametrize("method,path", sorted(GATE_A_FROZEN_COMMANDS))
def test_allowlist_accepts_only_frozen_commands(method: str, path: str) -> None:
    assert is_allowlisted(method, path)


@pytest.mark.parametrize("method,path", REJECTED_RCI_PATHS)
def test_allowlist_rejects_forbidden_paths_before_http(method: str, path: str) -> None:
    assert not is_allowlisted(method, path)
    client = BanHttpClient()
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="lab-user",
        password=SYNTH_PASSWORD,
        http_client=client,  # type: ignore[arg-type]
    )
    with pytest.raises(AllowlistViolation):
        transport._request(method, path, None)
    assert client.calls == []


def test_fetch_allowlisted_rejects_arbitrary_command_before_http() -> None:
    client = BanHttpClient()
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="lab-user",
        password=SYNTH_PASSWORD,
        http_client=client,  # type: ignore[arg-type]
    )
    rogue = ReadCommand("rogue", HttpMethod.GET, "/rci/show/running-config")
    with pytest.raises(AllowlistViolation):
        transport.fetch_allowlisted(rogue)
    assert client.calls == []


def test_gate_a_allowlist_excludes_discovery_reads() -> None:
    assert SHOW_INTERFACE not in ALLOWLIST
    assert SHOW_IP_ROUTE not in ALLOWLIST
    assert len(DISCOVERY_ALLOWLIST) == 2
    assert is_discovery_allowlisted(HttpMethod.GET, "/rci/show/interface")
    assert is_discovery_allowlisted(HttpMethod.GET, "/rci/show/ip/route")
    assert not is_allowlisted(HttpMethod.GET, "/rci/show/interface")
    assert not is_allowlisted(HttpMethod.GET, "/rci/show/ip/route")


def test_station_read_allowlist_includes_show_rc_interface() -> None:
    assert len(STATION_READ_ALLOWLIST) == 2
    assert SHOW_RC_INTERFACE in STATION_READ_ALLOWLIST
    assert SHOW_INTERFACE in STATION_READ_ALLOWLIST
    assert SHOW_RC_INTERFACE not in DISCOVERY_ALLOWLIST
    assert is_station_read_allowlisted(HttpMethod.GET, "/rci/show/rc/interface")
    assert is_station_read_allowlisted(HttpMethod.GET, "/rci/show/interface")
    assert not is_discovery_allowlisted(HttpMethod.GET, "/rci/show/rc/interface")


def test_fetch_allowlisted_rejects_discovery_commands_before_http() -> None:
    client = BanHttpClient()
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="lab-user",
        password=SYNTH_PASSWORD,
        http_client=client,  # type: ignore[arg-type]
    )
    for command in (SHOW_INTERFACE, SHOW_IP_ROUTE):
        with pytest.raises(AllowlistViolation):
            transport.fetch_allowlisted(command)
    assert client.calls == []


def test_plain_transport_refuses_discovery_fetch() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="lab-user",
        password=SYNTH_PASSWORD,
        http_client=BanHttpClient(),  # type: ignore[arg-type]
    )
    from router_control.adapters.netcraze.errors import TransportError

    for command in (SHOW_INTERFACE, SHOW_IP_ROUTE):
        with pytest.raises(TransportError, match="pinned SSH"):
            transport.fetch_discovery_read(command)


@pytest.mark.parametrize(
    "script_path",
    [PROBE_SCRIPT, TOPOLOGY_SCRIPT, DEFAULT_ROUTE_SCRIPT, STORE_SCRIPT],
)
def test_live_cli_scripts_have_no_password_argv_or_env_surface(script_path: Path) -> None:
    argv_flags, env_names = _scan_script_password_surface(script_path)
    assert argv_flags == set(), f"{script_path.name} exposes password argv: {argv_flags}"
    assert env_names == set(), f"{script_path.name} reads password env: {env_names}"


def test_probe_cli_rejects_password_flag_via_argparser(probe_module) -> None:
    argv = [
        "--host",
        "192.168.1.1",
        "--credential-ref",
        "cred_oracle",
        "--username",
        "lab-user",
        "--password",
        SYNTH_PASSWORD,
    ]
    with pytest.raises(SystemExit):
        probe_module._build_parser().parse_args(argv)


def test_store_cli_rejects_password_flag_via_argparser() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--username", required=True)
    parser.add_argument("--secrets-root", default="data/secrets")
    parser.add_argument("--meta-out", default="")
    argv = [
        "--host",
        "192.168.1.1",
        "--username",
        "lab-user",
        "--password",
        SYNTH_PASSWORD,
    ]
    with pytest.raises(SystemExit):
        parser.parse_args(argv)


def test_probe_cli_password_env_not_used(probe_module, monkeypatch: pytest.MonkeyPatch) -> None:
    for env_name in PASSWORD_ENV_VARS:
        monkeypatch.setenv(env_name, SYNTH_PASSWORD)
    argv = [
        "probe-gate-a.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        SYNTH_CREDENTIAL_REF,
        "--username",
        SYNTH_USERNAME,
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch(
        "sys.stderr", stderr
    ), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        MagicMock(use=MagicMock(side_effect=AssertionError("vault.use must be called"))),
    ):
        assert probe_module.main() != 0
    assert SYNTH_PASSWORD not in stderr.getvalue()


def test_store_cli_password_only_via_getpass(store_module, tmp_path: Path) -> None:
    meta_path = tmp_path / "meta.json"
    argv = [
        "store-router-credential.py",
        "--host",
        "192.168.1.1",
        "--username",
        SYNTH_USERNAME,
        "--secrets-root",
        str(tmp_path / "secrets"),
        "--meta-out",
        str(meta_path),
    ]

    class FakeHandle:
        credential_ref_id = SYNTH_CREDENTIAL_REF

    captured_secret: dict[str, str] = {}

    class FakeVault:
        def __init__(self, *, root: Path) -> None:
            self.root = root

        def create(self, *, kind: str, secret: str):
            captured_secret["secret"] = secret
            return FakeHandle()

    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch.object(
        store_module, "getpass", return_value=SYNTH_PASSWORD
    ), patch("router_control.adapters.secrets.dpapi.WindowsDpapiVault", FakeVault), patch(
        "sys.stdout", StringIO()
    ):
        assert store_module.main() == 0
    assert captured_secret["secret"] == SYNTH_PASSWORD
    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    blob = json.dumps(metadata)
    assert SYNTH_PASSWORD not in blob
    assert "password" not in metadata
    assert set(metadata.keys()) == {"host", "username", "credential_ref"}


def test_sanitize_mapping_redacts_core_forbidden_keys_recursively() -> None:
    nested = sanitize_mapping(
        {
            "password": SYNTH_PASSWORD,
            "username": SYNTH_USERNAME,
            "session": SYNTH_SESSION,
            "cookie": SYNTH_TOKEN,
            "token": SYNTH_TOKEN,
            "serial": SYNTH_SERIAL,
            "servicetag": SYNTH_SERVICETAG,
            "mac": SYNTH_MAC,
            "nested": {
                "session_cookie": SYNTH_SESSION,
                "child": {"password": SYNTH_PASSWORD},
            },
        }
    )
    blob = json.dumps(nested)
    _assert_no_sentinels(
        blob,
        allow=frozenset({SYNTH_USERNAME}),
    )
    assert nested["password"] == "REDACTED"
    assert nested["username"] == "REDACTED"
    assert nested["serial"] == "REDACTED"
    assert nested["nested"]["session_cookie"] == "REDACTED"



def test_build_gate_a_evidence_and_status_projection_exclude_sentinels() -> None:
    evidence = build_gate_a_evidence(
        model="NC-1812",
        title=None,
        firmware_version="5.01.C.1.0-0",
        build="SYNTH-BUILD-ORACLE",
        update_channel="Main",
        component_set_digest="sha256:component-oracle",
        device_fingerprint_digest="sha256:fingerprint-oracle",
        evidence_recorded_at="2026-07-21T12:00:00+00:00",
        transport_security="https",
        fingerprint_status="stable",
        identity_shape="observed",
        identity_complete=True,
        model_source="rci_version",
        update_channel_source="rci_version_sandbox_ui_map",
        build_source="rci_version_ndm_exact",
        physical_identifier_source="show.identification_digest",
    )
    evidence_blob = json.dumps(evidence)
    _assert_no_sentinels(evidence_blob)

    certification = GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="gate-a-read-only",
        model="NC-1812",
        model_display="Netcraze Ultra NC-1812",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="SYNTH-BUILD-ORACLE",
        bsp_build="SYNTH-BSP-ORACLE",
        update_channel="Main",
        region="SYNTH-REGION-ORACLE",
        component_set_digest="sha256:component-oracle",
        device_fingerprint_digest="sha256:fingerprint-oracle",
        physical_id_source="show.identification_digest",
        transport="https",
        ssh_host_key_algorithm="ssh-ed25519",
        ssh_host_key_fingerprint_sha256="SHA256:oraclepin",
        certification_eligible=True,
        evidence_recorded_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
        evidence_path="data/artifacts/gate-a-probe-oracle.json",
        expires_at=datetime(2026, 10, 21, 12, 0, 0, tzinfo=UTC),
        revocation_policy="human operator message required",
    )
    status_blob = json.dumps(certification.sanitized_status_payload())
    _assert_no_sentinels(status_blob)
    assert SYNTH_CREDENTIAL_REF not in status_blob
    assert SYNTH_PROVIDER_LOCATOR not in status_blob
    assert "credential_ref" not in status_blob
    assert "provider_locator" not in status_blob


class RecordingTransport:
    def __init__(self, *, payloads: dict[str, object]) -> None:
        self._payloads = payloads
        self.fetch_calls: list[str] = []

    def read_json(self, command, body=None):  # type: ignore[no-untyped-def]
        self.fetch_calls.append(command.name)
        return self._payloads[command.name]

    @property
    def transport_security_label(self) -> str:
        return "https"

    @property
    def https_check_label(self) -> str:
        return "not_certified"

    @property
    def gate_a_certification_eligible(self) -> bool:
        return False


def test_probe_evidence_artifact_excludes_raw_physical_and_credential_sentinels() -> None:
    system = json.loads((FIXTURES / "system_telemetry_only.json").read_text(encoding="utf-8"))
    components = json.loads((FIXTURES / "components_observed.json").read_text(encoding="utf-8"))
    identification = json.loads(
        (FIXTURES / "identification_both_ids.json").read_text(encoding="utf-8")
    )
    version = json.loads((FIXTURES / "version_match.json").read_text(encoding="utf-8"))
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-oracle-001"),
        transport=NetcrazeTransport(
            host="192.168.1.1",
            username=SYNTH_USERNAME,
            password=SYNTH_PASSWORD,
        ),
        clock=FixedClock(),
    )
    adapter.transport = RecordingTransport(  # type: ignore[assignment]
        payloads={
            "show_system": system,
            "components_list": components,
            "show_identification": identification,
            "show_version": version,
        }
    )
    evidence = adapter.probe_gate_a_evidence()
    blob = json.dumps(evidence)
    _assert_no_sentinels(blob)
    assert identification["serial"] not in blob
    assert identification["servicetag"] not in blob
    assert SYNTH_PASSWORD not in blob
    assert SYNTH_USERNAME not in blob


def test_transport_and_tunnel_repr_hide_password_and_session_sentinels() -> None:
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username=SYNTH_USERNAME,
        password=SYNTH_PASSWORD,
        http_client=BanHttpClient(),  # type: ignore[arg-type]
    )
    transport_repr = repr(transport)
    _assert_excludes_sensitive_repr_and_errors(transport_repr)
    assert SYNTH_USERNAME in transport_repr

    tunnel_config = SshTunnelConfig(
        ssh_host="192.168.1.1",
        username=SYNTH_USERNAME,
        password=SYNTH_PASSWORD,
        host_key_sha256="SHA256:oraclepin",
    )
    tunnel_repr = repr(tunnel_config)
    _assert_excludes_sensitive_repr_and_errors(tunnel_repr)


def test_normalized_exceptions_exclude_password_and_session_sentinels() -> None:
    allowlist_exc = AllowlistViolation("command not allowlisted: GET /rci/show/running-config")
    auth_exc = AuthFailed("interactive auth failed")
    ssh_message = sanitize_ssh_error_message(
        f"tunnel auth failed: {SYNTH_PASSWORD}",
        password=SYNTH_PASSWORD,
    )
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username=SYNTH_USERNAME,
        password=SYNTH_PASSWORD,
        http_client=BanHttpClient(),  # type: ignore[arg-type]
    )
    transport._session_cookie_name = "synth_cookie"
    transport._session_cookie_value = SYNTH_SESSION
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-oracle-001"),
        transport=transport,
        clock=FixedClock(),
    )
    surfaces = (
        repr(adapter.transport),
        str(allowlist_exc),
        repr(allowlist_exc),
        str(auth_exc),
        repr(auth_exc),
        ssh_message,
    )
    for surface in surfaces:
        _assert_excludes_sensitive_repr_and_errors(surface)
    assert "[REDACTED]" in ssh_message


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "method_name",
    [
        "create_backup",
        "begin_fail_safe",
        "apply_plan",
        "read_back",
        "verify_postconditions",
        "save_configuration",
        "compensate",
    ],
)
async def test_mutation_methods_forbidden_with_zero_http_calls(method_name: str) -> None:
    client = BanHttpClient()
    transport = NetcrazeTransport(
        host="192.168.1.1",
        username="lab-user",
        password=SYNTH_PASSWORD,
        http_client=client,  # type: ignore[arg-type]
    )
    adapter = NetcrazeReadOnlyAdapter(
        router_id=RouterId("router-oracle-001"),
        transport=transport,
        clock=FixedClock(),
    )
    method = getattr(adapter, method_name)
    plan = ChangePlan(
        plan_id=PlanId("plan-oracle-001"),
        router_id=RouterId("router-oracle-001"),
        revision_id=RevisionId("rev-oracle-001"),
        observation_id=ObservationId("obs-oracle-001"),
        expected_desired_digest="digest:desired:oracle",
        observed_resource_version="digest:rv:oracle",
        items=(ChangePlanItem(ResourceId("res-oracle-001"), "intent", "digest:intent:oracle"),),
        confirmation_state=PlanConfirmationState.CONFIRMED,
        expires_at=datetime(2026, 7, 21, 13, 0, 0, tzinfo=UTC),
        created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
        actor="oracle-test",
    )
    with pytest.raises(MutationForbidden):
        if method_name == "create_backup":
            await method(RouterId("router-oracle-001"), OperationId("op-oracle-001"))
        elif method_name == "begin_fail_safe":
            await method(RouterId("router-oracle-001"))
        elif method_name == "apply_plan":
            await method(plan)
        elif method_name == "read_back":
            await method(RouterId("router-oracle-001"), PlanId("plan-oracle-001"))
        elif method_name == "verify_postconditions":
            from router_control.ports.router_control import ReadBackResult

            read_back = ReadBackResult(
                plan_id=PlanId("plan-oracle-001"),
                state_digest="digest:state:oracle",
                resource_version="digest:rv:oracle",
                identity_fingerprint_digest="sha256:oracle",
                outcome_known=True,
            )
            await method(plan, read_back)
        elif method_name == "save_configuration":
            await method(RouterId("router-oracle-001"))
        elif method_name == "compensate":
            from router_control.domain.entities import BackupArtifact
            from router_control.domain.ids import ArtifactId

            backup = BackupArtifact(
                artifact_id=ArtifactId("artifact-oracle-001"),
                router_id=RouterId("router-oracle-001"),
                operation_id=OperationId("op-oracle-001"),
                content_digest="digest:backup:oracle",
                storage_locator_digest="digest:loc:oracle",
                identity_fingerprint_digest="sha256:oracle",
                created_at=datetime(2026, 7, 21, 12, 0, 0, tzinfo=UTC),
            )
            await method(RouterId("router-oracle-001"), backup)
    assert client.calls == []
