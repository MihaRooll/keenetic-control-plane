"""Startup-config backup tests (synthetic/mock; no live network)."""

from __future__ import annotations

import http.client
import importlib.util
import json
import stat
import sys
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from router_control.adapters.netcraze import startup_backup as startup_backup_module
from router_control.adapters.netcraze.certification import (
    GateACertification,
    GateACertificationError,
)
from router_control.adapters.netcraze.ssh_tunnel import (
    PinnedSshTunnel,
    SshTunnelConfig,
    compute_host_key_fingerprint,
)
from router_control.adapters.netcraze.startup_backup import (
    MAX_STARTUP_CONFIG_BYTES,
    STARTUP_CONFIG_PATH,
    BackupPathError,
    StartupConfigEmpty,
    StartupConfigFetchFailed,
    StartupConfigOversize,
    assert_fixed_startup_endpoint,
    backup_startup_config,
    decrypt_startup_backup_blob,
    fetch_startup_config_bytes,
    resolve_confined_path,
    sha256_digest,
)
from router_control.adapters.netcraze.transport import (
    HttpExchange,
    SshTunnelNetcrazeTransport,
    StdlibHttpClient,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BACKUP_SCRIPT = REPO_ROOT / "scripts" / "backup-router-startup.py"

SYNTH_PASSWORD = "SENTINEL-PASSWORD-ORACLE"
SYNTH_USERNAME = "SENTINEL-USERNAME-ORACLE"
SYNTH_CREDENTIAL_REF = "SENTINEL-CREDREF-ORACLE"
SYNTH_STARTUP_CONFIG = "SENTINEL-STARTUP-CONFIG-ORACLE\ninterface GigabitEthernet0/Vlan1\n"

FORBIDDEN_SENTINELS = (
    SYNTH_PASSWORD,
    SYNTH_USERNAME,
    SYNTH_CREDENTIAL_REF,
    SYNTH_STARTUP_CONFIG,
)

_VALID_SSH_HOST_KEY_SHA256 = "SHA256:lU1D6ChVB8XLfHxoIFZeA8RPpPf67zA+qwYX0ARyCmM"

PASSWORD_ENV_VARS = (
    "ROUTER_PASSWORD",
    "RCI_PASSWORD",
    "NETCRAZE_PASSWORD",
    "PROBE_PASSWORD",
    "RC_PASSWORD",
    "HUB_ADMIN_PASSWORD",
)


class LimitedHttpClient:
    def __init__(self, *, status: int = 200, body: bytes = b"") -> None:
        self.status = status
        self.body = body
        self.sent_paths: list[str] = []

    def request(self, **kwargs: object) -> HttpExchange:
        raise AssertionError("unbounded request forbidden")

    def request_limited(self, **kwargs: object) -> HttpExchange:
        path = str(kwargs["path"])
        max_bytes = int(kwargs["max_bytes"])  # type: ignore[arg-type]
        self.sent_paths.append(path)
        return HttpExchange(
            status=self.status,
            headers={},
            body=self.body[: max_bytes + 1],
        )


def _ssh_transport(
    *,
    status: int = 200,
    body: bytes = b"",
    pin: str = _VALID_SSH_HOST_KEY_SHA256,
    algorithm: str = "ssh-ed25519",
) -> SshTunnelNetcrazeTransport:
    return SshTunnelNetcrazeTransport(
        host="127.0.0.1",
        port=12345,
        use_tls=False,
        username="lab-user",
        password=SYNTH_PASSWORD,
        management_host_header="192.168.1.1",
        ssh_host_key_algorithm=algorithm,
        ssh_host_key_fingerprint_sha256=pin,
        http_client=LimitedHttpClient(status=status, body=body),
    )


def _certification(
    *,
    pin: str = _VALID_SSH_HOST_KEY_SHA256,
    algorithm: str = "ssh-ed25519",
) -> GateACertification:
    now = datetime.now(UTC)
    return GateACertification(
        status="open",
        certification="ReadOnlyCertified",
        approved_scope="SLICE-4-readonly",
        model="NC-1812",
        model_display="Ultra",
        firmware_version="5.01.C.1.0-0",
        firmware_display="5.1.1",
        ndm_build="build",
        bsp_build="bsp",
        update_channel="Main",
        region="EA",
        component_set_digest=f"sha256:{'1' * 64}",
        device_fingerprint_digest=f"sha256:{'2' * 64}",
        physical_id_source="show.identification_digest",
        transport="ssh_tunnel",
        ssh_host_key_algorithm=algorithm,
        ssh_host_key_fingerprint_sha256=pin,
        certification_eligible=True,
        evidence_recorded_at=now,
        evidence_path="synthetic",
        expires_at=now + timedelta(days=1),
        revocation_policy="synthetic",
    )


def _load_backup_module():
    spec = importlib.util.spec_from_file_location("backup_router_startup_cli", BACKUP_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def backup_cli():
    return _load_backup_module()


def _assert_no_sentinels(blob: str) -> None:
    for sentinel in FORBIDDEN_SENTINELS:
        assert sentinel not in blob


def test_fixed_endpoint_constant() -> None:
    assert STARTUP_CONFIG_PATH == "/ci/startup-config.txt"


@pytest.mark.parametrize(
    "path",
    [
        "/rci/show/startup-config",
        "/rci/show/running-config",
        "/rci/log",
        "/rci/self-test",
        "/ci/other.txt",
    ],
)
def test_assert_fixed_startup_endpoint_rejects_non_fixed(path: str) -> None:
    with pytest.raises(Exception, match="startup backup allows only"):
        assert_fixed_startup_endpoint(path)


def test_fetch_startup_config_uses_fixed_endpoint_only() -> None:
    transport = _ssh_transport(body=SYNTH_STARTUP_CONFIG.encode("utf-8"))
    payload = fetch_startup_config_bytes(transport)
    assert payload == SYNTH_STARTUP_CONFIG.encode("utf-8")
    assert transport.http_client.sent_paths == [STARTUP_CONFIG_PATH]


@pytest.mark.parametrize("status", [401, 403, 404, 500])
def test_non200_raises_without_artifact(status: int, tmp_path: Path) -> None:
    transport = _ssh_transport(status=status, body=b"ignored")
    with pytest.raises(StartupConfigFetchFailed):
        fetch_startup_config_bytes(transport)
    assert list(tmp_path.glob("*")) == []


def test_empty_response_raises_without_artifact(tmp_path: Path) -> None:
    transport = _ssh_transport(status=200, body=b"")
    with pytest.raises(StartupConfigEmpty):
        fetch_startup_config_bytes(transport)
    assert list(tmp_path.glob("*")) == []


def test_oversize_response_raises_without_artifact(tmp_path: Path) -> None:
    transport = _ssh_transport(
        status=200, body=b"x" * (MAX_STARTUP_CONFIG_BYTES + 1024)
    )
    with pytest.raises(StartupConfigOversize):
        fetch_startup_config_bytes(transport)
    assert len(transport.http_client.body[: MAX_STARTUP_CONFIG_BYTES + 1]) == (
        MAX_STARTUP_CONFIG_BYTES + 1
    )
    assert list(tmp_path.glob("*")) == []


def test_stdlib_limited_client_reads_only_max_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, int] = {}

    class FakeResponse:
        status = 200

        def getheaders(self) -> list[tuple[str, str]]:
            return []

        def read(self, amount: int) -> bytes:
            observed["amount"] = amount
            return b"x" * amount

    class FakeConnection:
        def __init__(self, *args: object, **kwargs: object) -> None:
            pass

        def request(self, *args: object, **kwargs: object) -> None:
            pass

        def getresponse(self) -> FakeResponse:
            return FakeResponse()

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        http.client,
        "HTTPConnection",
        FakeConnection,
    )
    exchange = StdlibHttpClient().request_limited(
        host="127.0.0.1",
        port=80,
        method="GET",
        path=STARTUP_CONFIG_PATH,
        headers={},
        body=None,
        connect_timeout=1,
        read_timeout=1,
        ssl_context=None,
        max_bytes=16,
    )
    assert observed["amount"] == 17
    assert len(exchange.body) == 17


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_write_encrypted_backup_roundtrip(tmp_path: Path) -> None:
    plaintext = SYNTH_STARTUP_CONFIG.encode("utf-8")
    metadata = startup_backup_module._write_encrypted_startup_backup(
        backups_root=tmp_path,
        host="192.168.1.1",
        plaintext=plaintext,
        transport_security="ssh_tunnel",
        device_fingerprint_digest=f"sha256:{'2' * 64}",
        ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
        ssh_host_key_algorithm="ssh-ed25519",
        recorded_at=datetime(2026, 7, 21, 12, 0, tzinfo=UTC),
    )
    encrypted_path = Path(metadata.encrypted_locator)
    metadata_path = Path(metadata.metadata_locator)
    assert encrypted_path.exists()
    assert metadata_path.exists()
    assert encrypted_path.suffix == ".dpapi"
    restored = decrypt_startup_backup_blob(encrypted_path)
    assert restored == plaintext
    assert metadata.content_sha256 == sha256_digest(plaintext)
    meta_blob = metadata_path.read_text(encoding="utf-8")
    _assert_no_sentinels(meta_blob)
    assert SYNTH_STARTUP_CONFIG not in meta_blob
    assert "password" not in json.loads(meta_blob)
    assert metadata.device_fingerprint_digest == f"sha256:{'2' * 64}"
    assert metadata.ssh_host_key_fingerprint_sha256 == _VALID_SSH_HOST_KEY_SHA256
    assert metadata.ssh_host_key_algorithm == "ssh-ed25519"


def test_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(BackupPathError):
        resolve_confined_path(tmp_path, "../escape.dpapi")
    with pytest.raises(BackupPathError):
        resolve_confined_path(tmp_path, "nested/artifact.dpapi")


def test_default_backup_root_rejects_data_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    try:
        (repo / "data").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks unavailable on this platform")

    monkeypatch.setattr(startup_backup_module, "REPO_ROOT", repo)
    monkeypatch.setattr(
        startup_backup_module,
        "DEFAULT_BACKUPS_ROOT",
        repo / "data" / "backups",
    )
    with pytest.raises(BackupPathError, match="symlink or reparse-point"):
        startup_backup_module._prepare_default_backups_root()
    assert list(outside.iterdir()) == []


def test_windows_reparse_attribute_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_stat = SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
    monkeypatch.setattr(startup_backup_module.os, "lstat", lambda _path: fake_stat)
    assert startup_backup_module._is_symlink_or_reparse(Path("data")) is True


def test_windows_directory_lock_verify_failure_closes_without_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(startup_backup_module, "REPO_ROOT", repo)
    monkeypatch.setattr(
        startup_backup_module,
        "DEFAULT_BACKUPS_ROOT",
        repo / "data" / "backups",
    )
    events: list[str] = []

    class FailingDirectoryApi:
        def open(self, path: Path) -> int:
            events.append("open")
            return 7

        def verify(self, handle: int, expected_path: Path) -> None:
            events.append("verify")
            raise BackupPathError("locked path mismatch")

        def close(self, handle: int) -> None:
            events.append("close")

    monkeypatch.setattr(
        startup_backup_module,
        "_windows_directory_api",
        lambda: FailingDirectoryApi(),
    )
    with pytest.raises(BackupPathError, match="locked path mismatch"):
        with startup_backup_module._locked_default_backups_root():
            raise AssertionError("lock body must not run")
    assert events == ["open", "verify", "close"]
    assert list((repo / "data" / "backups").iterdir()) == []


def test_windows_directory_lock_unavailable_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(startup_backup_module, "REPO_ROOT", repo)
    monkeypatch.setattr(
        startup_backup_module,
        "DEFAULT_BACKUPS_ROOT",
        repo / "data" / "backups",
    )

    class UnavailableDirectoryApi:
        def open(self, path: Path) -> int:
            raise BackupPathError("cannot lock backup directory")

        def verify(self, handle: int, expected_path: Path) -> None:
            raise AssertionError("verify must not run")

        def close(self, handle: int) -> None:
            raise AssertionError("close must not run without a handle")

    monkeypatch.setattr(
        startup_backup_module,
        "_windows_directory_api",
        lambda: UnavailableDirectoryApi(),
    )
    with pytest.raises(BackupPathError, match="cannot lock"):
        with startup_backup_module._locked_default_backups_root():
            raise AssertionError("lock body must not run")
    assert list((repo / "data" / "backups").iterdir()) == []


def test_locked_directory_final_path_mismatch_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    expected = repo / "data" / "backups"
    expected.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    monkeypatch.setattr(startup_backup_module, "REPO_ROOT", repo)
    with pytest.raises(BackupPathError, match="path mismatch"):
        startup_backup_module._verify_locked_directory_path(str(outside), expected)
    assert list(outside.iterdir()) == []
    assert list(expected.iterdir()) == []


def test_write_failure_cleans_temp_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def flaky_replace(src: Path, dst: Path) -> None:
        calls["count"] += 1
        if calls["count"] == 1:
            raise OSError("replace failed")
        __import__("os").replace(src, dst)

    monkeypatch.setattr(startup_backup_module.os, "replace", flaky_replace)
    monkeypatch.setattr(startup_backup_module, "protect_bytes", lambda data: data)
    with pytest.raises(OSError, match="replace failed"):
        startup_backup_module._write_encrypted_startup_backup(
            backups_root=tmp_path,
            host="192.168.1.1",
            plaintext=b"config",
            transport_security="ssh_tunnel",
            device_fingerprint_digest=f"sha256:{'2' * 64}",
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )
    leftovers = list(tmp_path.glob(".tmp-*"))
    assert leftovers == []


def test_metadata_publish_failure_removes_encrypted_final_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_replace = startup_backup_module.os.replace
    calls = {"count": 0}

    def fail_second_replace(src: Path, dst: Path) -> None:
        calls["count"] += 1
        if calls["count"] == 2:
            raise OSError("metadata replace failed")
        real_replace(src, dst)

    monkeypatch.setattr(startup_backup_module.os, "replace", fail_second_replace)
    monkeypatch.setattr(startup_backup_module, "protect_bytes", lambda data: b"encrypted")
    with pytest.raises(OSError, match="metadata replace failed"):
        startup_backup_module._write_encrypted_startup_backup(
            backups_root=tmp_path,
            host="192.168.1.1",
            plaintext=b"config",
            transport_security="ssh_tunnel",
            device_fingerprint_digest=f"sha256:{'2' * 64}",
            ssh_host_key_fingerprint_sha256=_VALID_SSH_HOST_KEY_SHA256,
            ssh_host_key_algorithm="ssh-ed25519",
        )
    assert list(tmp_path.iterdir()) == []


def test_backup_rejects_direct_transport_argument() -> None:
    direct_transport = _ssh_transport(body=b"config")
    with pytest.raises(TypeError, match="unexpected keyword argument 'transport'"):
        backup_startup_config(  # type: ignore[call-arg]
            transport=direct_transport,
            certification=_certification(),
        )
    assert direct_transport.http_client.sent_paths == []


def test_backup_rejects_unopened_pinned_tunnel_before_fetch() -> None:
    tunnel = PinnedSshTunnel(
        SshTunnelConfig(
            ssh_host="192.168.1.1",
            username="lab-user",
            password=SYNTH_PASSWORD,
            host_key_sha256=_VALID_SSH_HOST_KEY_SHA256,
        )
    )
    with pytest.raises(Exception, match="not open"):
        backup_startup_config(
            tunnel=tunnel,
            certification=_certification(),
        )


def test_validated_tunnel_uses_internal_transport_and_injected_fetch_seam(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeKey:
        def get_name(self) -> str:
            return "ssh-ed25519"

        def asbytes(self) -> bytes:
            return b"synthetic-public-key"

    key = FakeKey()
    algorithm, pin = compute_host_key_fingerprint(key)

    class AuthenticatedTransport:
        def is_authenticated(self) -> bool:
            return True

        def get_remote_server_key(self) -> FakeKey:
            return key

    tunnel = PinnedSshTunnel(
        SshTunnelConfig(
            ssh_host="192.168.1.1",
            username="lab-user",
            password=SYNTH_PASSWORD,
            host_key_sha256=pin,
        )
    )
    tunnel._transport = AuthenticatedTransport()
    tunnel._forward_server = SimpleNamespace(server_address=("127.0.0.1", 12345))
    tunnel._local_port = 12345
    tunnel._host_key_algorithm = algorithm
    tunnel._host_key_fingerprint_sha256 = pin

    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(startup_backup_module, "REPO_ROOT", repo)
    monkeypatch.setattr(
        startup_backup_module,
        "DEFAULT_BACKUPS_ROOT",
        repo / "data" / "backups",
    )
    monkeypatch.setattr(
        startup_backup_module,
        "protect_bytes",
        lambda plaintext: b"DPAPI:" + plaintext,
    )
    events: list[str] = []

    class FakeDirectoryApi:
        def open(self, path: Path) -> int:
            events.append("open")
            assert path == repo / "data" / "backups"
            return 42

        def verify(self, handle: int, expected_path: Path) -> None:
            events.append("verify")
            assert handle == 42
            assert expected_path == repo / "data" / "backups"

        def close(self, handle: int) -> None:
            events.append("close")
            assert handle == 42

    monkeypatch.setattr(
        startup_backup_module,
        "_windows_directory_api",
        lambda: FakeDirectoryApi(),
    )
    real_atomic_write = startup_backup_module._atomic_write_bytes

    def observed_atomic_write(path: Path, data: bytes) -> None:
        events.append("write")
        real_atomic_write(path, data)

    monkeypatch.setattr(
        startup_backup_module,
        "_atomic_write_bytes",
        observed_atomic_write,
    )
    observed: dict[str, object] = {}

    def fetcher(transport: SshTunnelNetcrazeTransport) -> bytes:
        events.append("fetch")
        observed["host"] = transport.host
        observed["port"] = transport.port
        observed["pin"] = transport.ssh_host_key_fingerprint_sha256
        observed["algorithm"] = transport.ssh_host_key_algorithm
        observed["source_address"] = transport.source_address
        return SYNTH_STARTUP_CONFIG.encode()

    metadata = startup_backup_module._backup_startup_config_with_fetcher(
        tunnel=tunnel,
        certification=_certification(pin=pin, algorithm=algorithm),
        fetcher=fetcher,
    )
    assert observed == {
        "host": "127.0.0.1",
        "port": 12345,
        "pin": pin,
        "algorithm": algorithm,
        "source_address": "",
    }
    assert Path(metadata.encrypted_locator).is_relative_to(repo / "data" / "backups")
    assert metadata.ssh_host_key_fingerprint_sha256 == pin
    assert events == ["open", "verify", "fetch", "write", "write", "close"]


def test_validated_tunnel_propagates_source_address_to_internal_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeKey:
        def get_name(self) -> str:
            return "ssh-ed25519"

        def asbytes(self) -> bytes:
            return b"synthetic-public-key"

    key = FakeKey()
    algorithm, pin = compute_host_key_fingerprint(key)

    class AuthenticatedTransport:
        def is_authenticated(self) -> bool:
            return True

        def get_remote_server_key(self) -> FakeKey:
            return key

    tunnel = PinnedSshTunnel(
        SshTunnelConfig(
            ssh_host="192.168.1.1",
            username="lab-user",
            password=SYNTH_PASSWORD,
            host_key_sha256=pin,
            source_address="192.168.1.144",
        )
    )
    tunnel._transport = AuthenticatedTransport()
    tunnel._forward_server = SimpleNamespace(server_address=("127.0.0.1", 12345))
    tunnel._local_port = 12345
    tunnel._host_key_algorithm = algorithm
    tunnel._host_key_fingerprint_sha256 = pin

    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setattr(startup_backup_module, "REPO_ROOT", repo)
    monkeypatch.setattr(
        startup_backup_module,
        "DEFAULT_BACKUPS_ROOT",
        repo / "data" / "backups",
    )
    monkeypatch.setattr(
        startup_backup_module,
        "protect_bytes",
        lambda plaintext: b"DPAPI:" + plaintext,
    )

    class FakeDirectoryApi:
        def open(self, path: Path) -> int:
            return 42

        def verify(self, handle: int, expected_path: Path) -> None:
            return None

        def close(self, handle: int) -> None:
            return None

    monkeypatch.setattr(
        startup_backup_module,
        "_windows_directory_api",
        lambda: FakeDirectoryApi(),
    )
    observed: dict[str, str] = {}

    def fetcher(transport: SshTunnelNetcrazeTransport) -> bytes:
        observed["source_address"] = transport.source_address
        return SYNTH_STARTUP_CONFIG.encode()

    metadata = startup_backup_module._backup_startup_config_with_fetcher(
        tunnel=tunnel,
        certification=_certification(pin=pin, algorithm=algorithm),
        fetcher=fetcher,
    )
    assert observed["source_address"] == "192.168.1.144"
    assert metadata.source_address == "192.168.1.144"


def test_cli_rejects_password_flag_via_argparser(backup_cli) -> None:
    with pytest.raises(SystemExit):
        backup_cli._build_parser().parse_args(
            [
                "--host",
                "192.168.1.1",
                "--credential-ref",
                SYNTH_CREDENTIAL_REF,
                "--username",
                SYNTH_USERNAME,
                "--ssh-host-key-sha256",
                _VALID_SSH_HOST_KEY_SHA256,
                "--password",
                SYNTH_PASSWORD,
            ]
        )


def test_cli_password_env_not_used(backup_cli, monkeypatch: pytest.MonkeyPatch) -> None:
    for env_name in PASSWORD_ENV_VARS:
        monkeypatch.setenv(env_name, SYNTH_PASSWORD)
    argv = [
        "backup-router-startup.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        SYNTH_CREDENTIAL_REF,
        "--username",
        SYNTH_USERNAME,
        "--ssh-host-key-sha256",
        _VALID_SSH_HOST_KEY_SHA256,
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "stderr", stderr):
        assert backup_cli.main() == 2
    assert SYNTH_PASSWORD not in stderr.getvalue()


def test_cli_certification_failure_precedes_vault_and_network(backup_cli) -> None:
    argv = [
        "backup-router-startup.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        SYNTH_CREDENTIAL_REF,
        "--username",
        SYNTH_USERNAME,
        "--ssh-host-key-sha256",
        _VALID_SSH_HOST_KEY_SHA256,
    ]
    vault = MagicMock(side_effect=AssertionError("vault must not be opened"))
    network = MagicMock(side_effect=AssertionError("network must not be opened"))
    with patch.object(sys, "argv", argv), patch(
        "router_control.adapters.netcraze.certification.load_gate_a_certification",
        MagicMock(side_effect=GateACertificationError("evidence missing")),
    ), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        vault,
    ), patch(
        "socket.create_connection",
        network,
    ):
        assert backup_cli.main() == 3
    vault.assert_not_called()
    network.assert_not_called()


def test_cli_requires_ssh_host_key_pin(backup_cli) -> None:
    with pytest.raises(SystemExit):
        backup_cli._build_parser().parse_args(
            [
                "--host",
                "192.168.1.1",
                "--credential-ref",
                SYNTH_CREDENTIAL_REF,
                "--username",
                SYNTH_USERNAME,
            ]
        )


def test_cli_rejects_backups_root_override(backup_cli) -> None:
    with pytest.raises(SystemExit):
        backup_cli._build_parser().parse_args(
            [
                "--host",
                "192.168.1.1",
                "--credential-ref",
                SYNTH_CREDENTIAL_REF,
                "--username",
                SYNTH_USERNAME,
                "--ssh-host-key-sha256",
                _VALID_SSH_HOST_KEY_SHA256,
                "--backups-root",
                "C:/escape",
            ]
        )


def test_cli_refuses_mutation_like_extra_tokens(backup_cli) -> None:
    argv = [
        "backup-router-startup.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        SYNTH_CREDENTIAL_REF,
        "--username",
        SYNTH_USERNAME,
        "--ssh-host-key-sha256",
        _VALID_SSH_HOST_KEY_SHA256,
        "install",
    ]
    with patch.object(sys, "argv", argv):
        assert backup_cli.main() == 2


def test_cli_success_output_paths_and_hash_only(
    backup_cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    argv = [
        "backup-router-startup.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        SYNTH_CREDENTIAL_REF,
        "--username",
        SYNTH_USERNAME,
        "--ssh-host-key-sha256",
        _VALID_SSH_HOST_KEY_SHA256,
    ]

    class FakeMetadata:
        encrypted_locator = "/tmp/backups-test/artifact.dpapi"
        metadata_locator = "/tmp/backups-test/artifact.meta.json"
        content_sha256 = "sha256:deadbeef"
        size_bytes = 42
        endpoint = STARTUP_CONFIG_PATH
        recorded_at = "2026-07-21T12:00:00+00:00"
        transport_security = "ssh_tunnel"
        device_fingerprint_digest = f"sha256:{'2' * 64}"
        ssh_host_key_fingerprint_sha256 = _VALID_SSH_HOST_KEY_SHA256
        ssh_host_key_algorithm = "ssh-ed25519"

    class FakeTunnel:
        local_host = "127.0.0.1"
        local_port = 12345
        host_key_algorithm = "ssh-ed25519"
        host_key_fingerprint_sha256 = _VALID_SSH_HOST_KEY_SHA256

        def __init__(self, *_args, **_kwargs) -> None:
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return None

    stdout = StringIO()
    certification = _certification()
    backup_call = MagicMock(return_value=FakeMetadata())
    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch(
        "router_control.adapters.netcraze.certification.load_gate_a_certification",
        MagicMock(return_value=certification),
    ), patch(
        "router_control.adapters.netcraze.ssh_tunnel.PinnedSshTunnel",
        FakeTunnel,
    ), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        MagicMock(use=MagicMock(return_value=SYNTH_PASSWORD)),
    ), patch(
        "router_control.adapters.netcraze.startup_backup.backup_startup_config",
        backup_call,
    ), patch("sys.stdout", stdout):
        assert backup_cli.main() == 0
    assert backup_call.call_args.kwargs["tunnel"].__class__ is FakeTunnel
    assert "transport" not in backup_call.call_args.kwargs

    payload = json.loads(stdout.getvalue())
    _assert_no_sentinels(json.dumps(payload))
    assert set(payload.keys()) == {
        "encrypted_locator",
        "metadata_locator",
        "content_sha256",
        "size_bytes",
        "endpoint",
        "recorded_at",
        "transport_security",
        "device_fingerprint_digest",
        "ssh_host_key_fingerprint_sha256",
        "ssh_host_key_algorithm",
    }
    assert payload["endpoint"] == STARTUP_CONFIG_PATH


def test_cli_network_ban_no_live_socket(backup_cli, monkeypatch: pytest.MonkeyPatch) -> None:
    argv = [
        "backup-router-startup.py",
        "--host",
        "192.168.1.1",
        "--credential-ref",
        SYNTH_CREDENTIAL_REF,
        "--username",
        SYNTH_USERNAME,
        "--ssh-host-key-sha256",
        _VALID_SSH_HOST_KEY_SHA256,
    ]

    def forbidden_socket(*args, **kwargs):
        raise AssertionError("live socket use forbidden in unit tests")

    monkeypatch.setattr("socket.create_connection", forbidden_socket)
    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        MagicMock(use=MagicMock(return_value=SYNTH_PASSWORD)),
    ):
        assert backup_cli.main() != 0
