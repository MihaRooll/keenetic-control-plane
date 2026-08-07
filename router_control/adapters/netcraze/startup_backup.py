"""Encrypted startup-config backup over pinned SSH tunnel (fixed CI endpoint only)."""

from __future__ import annotations

import ctypes
import hashlib
import json
import os
import re
import secrets
import stat
import sys
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from router_control.adapters.netcraze.certification import GateACertification
from router_control.adapters.netcraze.errors import AuthFailed
from router_control.adapters.netcraze.ssh_tunnel import (
    PinnedSshTunnel,
    compute_host_key_fingerprint,
    normalize_sha256_fingerprint,
    validate_ssh_tunnel_host,
)
from router_control.adapters.netcraze.transport import (
    SshTunnelNetcrazeTransport,
    derive_management_host_header,
)
from router_control.adapters.secrets.dpapi import protect_bytes, unprotect_bytes

STARTUP_CONFIG_PATH = "/ci/startup-config.txt"
MAX_STARTUP_CONFIG_BYTES = 4 * 1024 * 1024
REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_BACKUPS_ROOT = REPO_ROOT / "data" / "backups"

_FORBIDDEN_ENDPOINTS = frozenset(
    {
        "/rci/show/startup-config",
        "/rci/show/running-config",
        "/rci/log",
        "/rci/self-test",
    }
)

_SAFE_BASENAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002
_OPEN_EXISTING = 3
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400


class StartupBackupError(Exception):
    """Startup backup operation failed before artifact publication."""


class StartupConfigFetchFailed(StartupBackupError):
    """Fixed endpoint returned a non-success HTTP status."""


class StartupConfigEmpty(StartupBackupError):
    """Fixed endpoint returned an empty body."""


class StartupConfigOversize(StartupBackupError):
    """Fixed endpoint body exceeded the bounded size limit."""


class BackupPathError(StartupBackupError):
    """Resolved artifact path escapes the configured backups root."""


class _WindowsDirectoryApi:
    def __init__(self) -> None:
        if sys.platform != "win32":
            raise BackupPathError("Windows backup-directory locking unavailable")

        self._ctypes = ctypes
        self._wintypes = wintypes
        self._kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    def open(self, path: Path) -> int:
        create_file = self._kernel32.CreateFileW
        create_file.argtypes = (
            self._wintypes.LPCWSTR,
            self._wintypes.DWORD,
            self._wintypes.DWORD,
            self._wintypes.LPVOID,
            self._wintypes.DWORD,
            self._wintypes.DWORD,
            self._wintypes.HANDLE,
        )
        create_file.restype = self._wintypes.HANDLE
        handle = create_file(
            str(path),
            0,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
        invalid = self._ctypes.c_void_p(-1).value
        value = self._ctypes.cast(handle, self._ctypes.c_void_p).value
        if value is None or value == invalid:
            error = self._ctypes.get_last_error()
            raise BackupPathError(f"cannot lock backup directory (winerror={error})")
        return int(value)

    def verify(self, handle: int, expected_path: Path) -> None:
        class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("dwFileAttributes", wintypes.DWORD),
                ("ftCreationTime", wintypes.FILETIME),
                ("ftLastAccessTime", wintypes.FILETIME),
                ("ftLastWriteTime", wintypes.FILETIME),
                ("dwVolumeSerialNumber", wintypes.DWORD),
                ("nFileSizeHigh", wintypes.DWORD),
                ("nFileSizeLow", wintypes.DWORD),
                ("nNumberOfLinks", wintypes.DWORD),
                ("nFileIndexHigh", wintypes.DWORD),
                ("nFileIndexLow", wintypes.DWORD),
            ]

        raw_handle = wintypes.HANDLE(handle)
        information = BY_HANDLE_FILE_INFORMATION()
        get_info = self._kernel32.GetFileInformationByHandle
        get_info.argtypes = (
            wintypes.HANDLE,
            ctypes.POINTER(BY_HANDLE_FILE_INFORMATION),
        )
        get_info.restype = wintypes.BOOL
        if not get_info(raw_handle, ctypes.byref(information)):
            error = ctypes.get_last_error()
            raise BackupPathError(
                f"cannot verify backup directory attributes (winerror={error})"
            )
        if information.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise BackupPathError("backup directory handle is a reparse point")

        get_final_path = self._kernel32.GetFinalPathNameByHandleW
        get_final_path.argtypes = (
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        )
        get_final_path.restype = wintypes.DWORD
        required = get_final_path(raw_handle, None, 0, 0)
        if required == 0:
            error = ctypes.get_last_error()
            raise BackupPathError(
                f"cannot resolve backup directory handle (winerror={error})"
            )
        buffer = ctypes.create_unicode_buffer(required + 1)
        written = get_final_path(raw_handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            error = ctypes.get_last_error()
            raise BackupPathError(
                f"cannot resolve backup directory handle (winerror={error})"
            )
        _verify_locked_directory_path(buffer.value, expected_path)

    def close(self, handle: int) -> None:
        close_handle = self._kernel32.CloseHandle
        close_handle.argtypes = (self._wintypes.HANDLE,)
        close_handle.restype = self._wintypes.BOOL
        close_handle(self._wintypes.HANDLE(handle))


@dataclass(frozen=True, slots=True)
class _VerifiedTunnelBinding:
    local_host: str
    local_port: int
    management_host: str
    remote_host: str
    username: str
    password: str
    host_key_algorithm: str
    host_key_fingerprint_sha256: str
    source_address: str = ""


@dataclass(frozen=True, slots=True)
class StartupBackupMetadata:
    artifact_type: str
    endpoint: str
    content_sha256: str
    size_bytes: int
    encrypted_locator: str
    metadata_locator: str
    recorded_at: str
    transport_security: str
    host: str
    device_fingerprint_digest: str
    ssh_host_key_fingerprint_sha256: str
    ssh_host_key_algorithm: str
    source_address: str | None = None
    source_address_class: str | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "artifact_type": self.artifact_type,
            "endpoint": self.endpoint,
            "content_sha256": self.content_sha256,
            "size_bytes": self.size_bytes,
            "encrypted_locator": self.encrypted_locator,
            "metadata_locator": self.metadata_locator,
            "recorded_at": self.recorded_at,
            "transport_security": self.transport_security,
            "host": self.host,
            "device_fingerprint_digest": self.device_fingerprint_digest,
            "ssh_host_key_fingerprint_sha256": self.ssh_host_key_fingerprint_sha256,
            "ssh_host_key_algorithm": self.ssh_host_key_algorithm,
        }
        if self.source_address is not None:
            payload["source_address"] = self.source_address
        if self.source_address_class is not None:
            payload["source_address_class"] = self.source_address_class
        return payload


def assert_fixed_startup_endpoint(path: str) -> None:
    normalized = path if path.startswith("/") else f"/{path}"
    if normalized != STARTUP_CONFIG_PATH:
        raise StartupBackupError(f"startup backup allows only {STARTUP_CONFIG_PATH}")
    if normalized in _FORBIDDEN_ENDPOINTS:
        raise StartupBackupError("forbidden startup backup endpoint")


def _validate_ssh_transport(transport: object) -> SshTunnelNetcrazeTransport:
    if not isinstance(transport, SshTunnelNetcrazeTransport):
        raise StartupBackupError("startup backup requires SshTunnelNetcrazeTransport")
    if transport.transport_security_label != "ssh_tunnel":
        raise StartupBackupError("startup backup requires ssh_tunnel transport security")
    if not transport.ssh_host_key_algorithm.strip():
        raise StartupBackupError("startup backup requires pinned SSH host-key algorithm")
    if not transport.ssh_host_key_fingerprint_sha256.strip():
        raise StartupBackupError("startup backup requires pinned SSH host-key fingerprint")
    return transport


def _bind_open_tunnel(tunnel: object) -> _VerifiedTunnelBinding:
    if not isinstance(tunnel, PinnedSshTunnel):
        raise StartupBackupError("startup backup requires an open PinnedSshTunnel")
    ssh_transport = tunnel._transport
    forward_server = tunnel._forward_server
    if tunnel._closed or ssh_transport is None or forward_server is None:
        raise StartupBackupError("PinnedSshTunnel is not open")
    is_authenticated = getattr(ssh_transport, "is_authenticated", None)
    if not callable(is_authenticated) or not bool(is_authenticated()):
        raise StartupBackupError("PinnedSshTunnel transport is not authenticated")

    algorithm, fingerprint = compute_host_key_fingerprint(
        ssh_transport.get_remote_server_key()
    )
    if algorithm != tunnel.host_key_algorithm:
        raise StartupBackupError("open tunnel host-key algorithm binding mismatch")
    if normalize_sha256_fingerprint(fingerprint) != normalize_sha256_fingerprint(
        tunnel.host_key_fingerprint_sha256
    ):
        raise StartupBackupError("open tunnel host-key fingerprint binding mismatch")

    server_host, server_port = forward_server.server_address[:2]
    if str(server_host) != tunnel.local_host or int(server_port) != tunnel.local_port:
        raise StartupBackupError("open tunnel local-forward binding mismatch")

    management_host = derive_management_host_header(tunnel.config.ssh_host)
    canonical_host = validate_ssh_tunnel_host(tunnel.config.ssh_host)
    return _VerifiedTunnelBinding(
        local_host=tunnel.local_host,
        local_port=tunnel.local_port,
        management_host=management_host,
        remote_host=canonical_host,
        username=tunnel.config.username,
        password=tunnel.config.password,
        host_key_algorithm=algorithm,
        host_key_fingerprint_sha256=fingerprint,
        source_address=tunnel.config.source_address or "",
    )


def _transport_from_binding(
    binding: _VerifiedTunnelBinding,
) -> SshTunnelNetcrazeTransport:
    return SshTunnelNetcrazeTransport(
        host=binding.local_host,
        port=binding.local_port,
        use_tls=False,
        username=binding.username,
        password=binding.password,
        management_host_header=binding.management_host,
        ssh_host_key_algorithm=binding.host_key_algorithm,
        ssh_host_key_fingerprint_sha256=binding.host_key_fingerprint_sha256,
        source_address=binding.source_address,
    )


def _validate_certification(
    certification: GateACertification,
    binding: _VerifiedTunnelBinding,
) -> None:
    if not certification.is_open:
        raise StartupBackupError("Gate A ReadOnlyCertified certification is not open")
    if certification.transport != "ssh_tunnel":
        raise StartupBackupError("certification transport is not ssh_tunnel")
    actual_pin = normalize_sha256_fingerprint(binding.host_key_fingerprint_sha256)
    certified_pin = normalize_sha256_fingerprint(
        certification.ssh_host_key_fingerprint_sha256
    )
    if actual_pin != certified_pin:
        raise StartupBackupError("actual SSH host-key fingerprint mismatches certification")
    if binding.host_key_algorithm != certification.ssh_host_key_algorithm:
        raise StartupBackupError("actual SSH host-key algorithm mismatches certification")
    fingerprint = certification.device_fingerprint_digest
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", fingerprint):
        raise StartupBackupError("certified device fingerprint digest is invalid")


def fetch_startup_config_bytes(transport: SshTunnelNetcrazeTransport) -> bytes:
    """Fetch startup-config from the fixed CI endpoint over an authenticated session."""
    secured_transport = _validate_ssh_transport(transport)
    assert_fixed_startup_endpoint(STARTUP_CONFIG_PATH)
    try:
        exchange = secured_transport.fetch_startup_config_bounded(
            max_bytes=MAX_STARTUP_CONFIG_BYTES
        )
    except AuthFailed as exc:
        raise StartupConfigFetchFailed("startup config authentication failed") from exc
    if exchange.status != 200:
        raise StartupConfigFetchFailed(f"HTTP {exchange.status}")
    payload = exchange.body
    if not payload:
        raise StartupConfigEmpty("startup config response empty")
    if len(payload) > MAX_STARTUP_CONFIG_BYTES:
        raise StartupConfigOversize(
            f"startup config exceeds {MAX_STARTUP_CONFIG_BYTES} bytes"
        )
    return payload


def sha256_digest(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"


def resolve_confined_path(backups_root: Path, relative_name: str) -> Path:
    if not relative_name or relative_name in {".", ".."}:
        raise BackupPathError("invalid backup artifact name")
    if "/" in relative_name or "\\" in relative_name:
        raise BackupPathError("backup artifact name must not contain path separators")
    if not _SAFE_BASENAME_RE.match(relative_name):
        raise BackupPathError("backup artifact name contains unsafe characters")
    root = backups_root.resolve()
    candidate = (root / relative_name).resolve()
    if not candidate.is_relative_to(root):
        raise BackupPathError("backup artifact path escapes backups root")
    return candidate


def _is_symlink_or_reparse(path: Path) -> bool:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(info.st_mode):
        return True
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    attributes = int(getattr(info, "st_file_attributes", 0))
    return bool(attributes & reparse_flag)


def _assert_safe_default_backups_root() -> None:
    expected = REPO_ROOT / "data" / "backups"
    if os.path.normcase(os.path.abspath(DEFAULT_BACKUPS_ROOT)) != os.path.normcase(
        os.path.abspath(expected)
    ):
        raise BackupPathError("backup root must be repository data/backups")

    for component in (REPO_ROOT, REPO_ROOT / "data", expected):
        if component.exists() and _is_symlink_or_reparse(component):
            raise BackupPathError(f"unsafe symlink or reparse-point backup path: {component}")

    resolved_repo = REPO_ROOT.resolve(strict=True)
    resolved_root = DEFAULT_BACKUPS_ROOT.resolve(strict=False)
    if not resolved_root.is_relative_to(resolved_repo):
        raise BackupPathError("backup root resolves outside repository")


def _prepare_default_backups_root() -> Path:
    _assert_safe_default_backups_root()
    DEFAULT_BACKUPS_ROOT.mkdir(parents=True, exist_ok=True)
    _assert_safe_default_backups_root()
    return DEFAULT_BACKUPS_ROOT


def _normalize_windows_final_path(value: str) -> str:
    normalized = value
    if normalized.startswith("\\\\?\\UNC\\"):
        normalized = "\\\\" + normalized[8:]
    elif normalized.startswith("\\\\?\\"):
        normalized = normalized[4:]
    return os.path.normcase(os.path.abspath(normalized))


def _verify_locked_directory_path(final_path: str, expected_path: Path) -> None:
    lexical = os.path.normcase(os.path.abspath(expected_path))
    resolved = os.path.normcase(os.path.abspath(expected_path.resolve(strict=True)))
    actual = _normalize_windows_final_path(final_path)
    resolved_repo = os.path.normcase(os.path.abspath(REPO_ROOT.resolve(strict=True)))
    if actual != lexical or actual != resolved:
        raise BackupPathError("locked backup directory path mismatch")
    try:
        common = os.path.commonpath((actual, resolved_repo))
    except ValueError as exc:
        raise BackupPathError("locked backup directory is outside repository") from exc
    if common != resolved_repo:
        raise BackupPathError("locked backup directory is outside repository")


def _windows_directory_api() -> _WindowsDirectoryApi:
    return _WindowsDirectoryApi()


@contextmanager
def _locked_default_backups_root() -> Iterator[Path]:
    root = _prepare_default_backups_root()
    api = _windows_directory_api()
    handle = api.open(root)
    try:
        api.verify(handle, root)
        _assert_safe_default_backups_root()
        yield root
    finally:
        api.close(handle)


def _best_effort_mode0600(path: Path) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".tmp-", suffix=path.suffix, dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        _best_effort_mode0600(path)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def _write_encrypted_startup_backup(
    *,
    backups_root: Path,
    host: str,
    plaintext: bytes,
    transport_security: str,
    device_fingerprint_digest: str,
    ssh_host_key_fingerprint_sha256: str,
    ssh_host_key_algorithm: str,
    recorded_at: datetime | None = None,
    source_address: str | None = None,
    source_address_class: str | None = None,
) -> StartupBackupMetadata:
    if not plaintext:
        raise StartupConfigEmpty("startup config plaintext empty")
    if len(plaintext) > MAX_STARTUP_CONFIG_BYTES:
        raise StartupConfigOversize(
            f"startup config exceeds {MAX_STARTUP_CONFIG_BYTES} bytes"
        )

    timestamp = (recorded_at or datetime.now(tz=UTC)).strftime("%Y%m%dT%H%M%SZ")
    host_slug = host.replace(":", "_").replace("/", "_")
    token = secrets.token_hex(4)
    base_name = f"startup-{host_slug}-{timestamp}-{token}"
    encrypted_name = f"{base_name}.dpapi"
    metadata_name = f"{base_name}.meta.json"

    encrypted_path = resolve_confined_path(backups_root, encrypted_name)
    metadata_path = resolve_confined_path(backups_root, metadata_name)

    protected = protect_bytes(plaintext)
    _atomic_write_bytes(encrypted_path, protected)

    metadata = StartupBackupMetadata(
        artifact_type="startup_config_backup",
        endpoint=STARTUP_CONFIG_PATH,
        content_sha256=sha256_digest(plaintext),
        size_bytes=len(plaintext),
        encrypted_locator=str(encrypted_path),
        metadata_locator=str(metadata_path),
        recorded_at=(recorded_at or datetime.now(tz=UTC)).isoformat(),
        transport_security=transport_security,
        host=host,
        device_fingerprint_digest=device_fingerprint_digest,
        ssh_host_key_fingerprint_sha256=ssh_host_key_fingerprint_sha256,
        ssh_host_key_algorithm=ssh_host_key_algorithm,
        source_address=source_address,
        source_address_class=source_address_class,
    )
    metadata_blob = json.dumps(metadata.to_dict(), indent=2) + "\n"
    try:
        _atomic_write_bytes(metadata_path, metadata_blob.encode("utf-8"))
    except Exception:
        encrypted_path.unlink(missing_ok=True)
        metadata_path.unlink(missing_ok=True)
        raise
    return metadata


def _backup_startup_config_with_fetcher(
    *,
    tunnel: PinnedSshTunnel,
    certification: GateACertification,
    fetcher: Callable[[SshTunnelNetcrazeTransport], bytes],
    recorded_at: datetime | None = None,
) -> StartupBackupMetadata:
    """Test seam: inject fetching only after tunnel/certification validation."""
    binding = _bind_open_tunnel(tunnel)
    _validate_certification(certification, binding)
    source_address: str | None = None
    source_address_class: str | None = None
    if tunnel.config.source_address is not None:
        from router_control.adapters.netcraze.ssh_tunnel import (
            source_address_class as classify_source_address,
        )
        from router_control.adapters.netcraze.ssh_tunnel import (
            validate_source_address,
        )

        source_address = validate_source_address(tunnel.config.source_address)
        source_address_class = classify_source_address(source_address)
    with _locked_default_backups_root() as backups_root:
        transport = _transport_from_binding(binding)
        plaintext = fetcher(transport)
        _assert_safe_default_backups_root()
        return _write_encrypted_startup_backup(
            backups_root=backups_root,
            host=binding.remote_host,
            plaintext=plaintext,
            transport_security="ssh_tunnel",
            device_fingerprint_digest=certification.device_fingerprint_digest,
            ssh_host_key_fingerprint_sha256=binding.host_key_fingerprint_sha256,
            ssh_host_key_algorithm=binding.host_key_algorithm,
            recorded_at=recorded_at,
            source_address=source_address,
            source_address_class=source_address_class,
        )


def backup_startup_config(
    *,
    tunnel: PinnedSshTunnel,
    certification: GateACertification,
    recorded_at: datetime | None = None,
) -> StartupBackupMetadata:
    """Use one actually open pinned tunnel and fixed repository backup root."""
    return _backup_startup_config_with_fetcher(
        tunnel=tunnel,
        certification=certification,
        fetcher=fetch_startup_config_bytes,
        recorded_at=recorded_at,
    )


def decrypt_startup_backup_blob(encrypted_path: Path) -> bytes:
    return unprotect_bytes(encrypted_path.read_bytes())


__all__ = [
    "MAX_STARTUP_CONFIG_BYTES",
    "STARTUP_CONFIG_PATH",
    "DEFAULT_BACKUPS_ROOT",
    "BackupPathError",
    "StartupBackupError",
    "StartupBackupMetadata",
    "StartupConfigEmpty",
    "StartupConfigFetchFailed",
    "StartupConfigOversize",
    "assert_fixed_startup_endpoint",
    "backup_startup_config",
    "decrypt_startup_backup_blob",
    "fetch_startup_config_bytes",
    "resolve_confined_path",
    "sha256_digest",
]
