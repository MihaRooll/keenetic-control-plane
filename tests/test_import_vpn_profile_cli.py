"""CLI tests for scripts/import-vpn-profile.py — sanitized output only."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "import-vpn-profile.py"

SAMPLE_PROFILE = """
[Interface]
PrivateKey = SENTINEL_PRIVATE_KEY_ORACLE_AAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.2/32
DNS = 1.1.1.1
Jc = 5

[Peer]
PublicKey = SENTINEL_PUBLIC_KEY_ORACLE_BBBBBBBBBBBBBBBBBBBBBBBBBBBB
PresharedKey = SENTINEL_PSK_ORACLE_CCCCCCCCCCCCCCCCCCCCCCCCCCCC
Endpoint = SENTINEL_ENDPOINT_HOST:51820
AllowedIPs = 0.0.0.0/0
"""

BAD_PROFILE = """
[Interface]
PrivateKey = also-sentinel-bad-key-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Address = 10.0.0.3/32

[Peer]
PublicKey = bad-only
AllowedIPs = 0.0.0.0/0
"""

SECRET_SENTINELS = (
    "SENTINEL_PRIVATE_KEY_ORACLE",
    "SENTINEL_PSK_ORACLE",
    "also-sentinel-bad-key",
    "10.0.0.2/32",
    "10.0.0.3/32",
    "1.1.1.1",
)

CONF_BODY_FRAGMENTS = (
    "PrivateKey = SENTINEL",
    "PresharedKey = SENTINEL",
    "Endpoint = SENTINEL",
    "Address = 10.0.0.",
)


def _run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, str(SCRIPT), *args]
    return subprocess.run(cmd, capture_output=True, text=True, check=False, cwd=str(REPO_ROOT))


@pytest.fixture
def good_conf(tmp_path: Path) -> Path:
    path = tmp_path / "sample.conf"
    path.write_text(SAMPLE_PROFILE, encoding="utf-8")
    return path


@pytest.fixture
def bad_conf(tmp_path: Path) -> Path:
    path = tmp_path / "bad.conf"
    path.write_text(BAD_PROFILE, encoding="utf-8")
    return path


def test_import_vpn_sanitized_stdout(good_conf: Path, tmp_path: Path) -> None:
    secrets_root = tmp_path / "secrets"
    catalog = tmp_path / "catalog.json"
    result = _run_cli(
        "--conf",
        str(good_conf),
        "--secrets-root",
        str(secrets_root),
        "--allow-memory-vault",
        "--catalog-out",
        str(catalog),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok_count"] == 1
    sanitized = payload["imports"][0]["sanitized"]
    assert "PrivateKey" in sanitized["interface_field_names"]
    assert sanitized["endpoint_configured"] is True
    assert "profile_digest" in sanitized
    blob = result.stdout + catalog.read_text(encoding="utf-8")
    for sentinel in SECRET_SENTINELS:
        assert sentinel not in blob


def test_import_vpn_bad_file_resilience(good_conf: Path, bad_conf: Path, tmp_path: Path) -> None:
    secrets_root = tmp_path / "secrets"
    result = _run_cli(
        "--conf",
        str(good_conf),
        "--conf",
        str(bad_conf),
        "--secrets-root",
        str(secrets_root),
        "--allow-memory-vault",
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok_count"] == 1
    assert payload["total"] == 2
    assert payload["imports"][0]["ok"] is True
    assert payload["imports"][1]["ok"] is False
    assert "error" in payload["imports"][1]
    combined = result.stdout + result.stderr
    for sentinel in SECRET_SENTINELS:
        assert sentinel not in combined
    for fragment in CONF_BODY_FRAGMENTS:
        assert fragment not in combined


def test_import_vpn_all_fail_exit_nonzero(bad_conf: Path, tmp_path: Path) -> None:
    result = _run_cli(
        "--conf",
        str(bad_conf),
        "--secrets-root",
        str(tmp_path / "secrets"),
        "--allow-memory-vault",
    )
    assert result.returncode != 0
    payload = json.loads(result.stdout)
    assert payload["ok_count"] == 0


def test_import_vpn_non_win32_without_memory_vault(monkeypatch: pytest.MonkeyPatch) -> None:
    if sys.platform == "win32":
        pytest.skip("win32 uses DPAPI by default")
    monkeypatch.setattr(sys, "platform", "linux")
    result = _run_cli("--conf", "missing.conf")
    assert result.returncode == 2
    assert "win32" in result.stderr.lower() or "memory-vault" in result.stderr.lower()
