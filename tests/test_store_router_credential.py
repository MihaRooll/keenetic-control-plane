"""Store-router-credential CLI guard tests (no DPAPI secrets in artifacts)."""

from __future__ import annotations

import importlib.util
import json
import sys
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
STORE_SCRIPT = REPO_ROOT / "scripts" / "store-router-credential.py"


def _load_store_module():
    spec = importlib.util.spec_from_file_location("store_router_credential_cli", STORE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def store_module():
    return _load_store_module()


@pytest.mark.parametrize(
    "host",
    [
        "http://synthuser:synthpass@192.168.1.1",
        "https://synthuser:synthpass@192.168.1.1:8443",
        "synthuser@192.168.1.1",
    ],
)
def test_rejects_host_with_embedded_credentials(store_module, host: str, tmp_path: Path) -> None:
    meta_path = tmp_path / "router-credential-meta.json"
    argv = [
        "store-router-credential.py",
        "--host",
        host,
        "--username",
        "lab-user",
        "--secrets-root",
        str(tmp_path / "secrets"),
        "--meta-out",
        str(meta_path),
    ]
    stderr = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch(
        "sys.stderr", stderr
    ):
        assert store_module.main() == 2
    err_text = stderr.getvalue()
    assert "embedded credentials" in err_text.lower()
    assert "synthpass" not in err_text
    assert "synthuser" not in err_text
    assert not meta_path.exists()


def test_metadata_contains_no_secret_fields(store_module, tmp_path: Path) -> None:
    meta_path = tmp_path / "router-credential-meta.json"
    argv = [
        "store-router-credential.py",
        "--host",
        "192.168.1.1",
        "--username",
        "lab-user",
        "--secrets-root",
        str(tmp_path / "secrets"),
        "--meta-out",
        str(meta_path),
    ]

    class FakeHandle:
        credential_ref_id = "cred_synth_test"

    class FakeVault:
        def __init__(self, *, root: Path) -> None:
            self.root = root

        def create(self, *, kind: str, secret: str):
            assert secret == "synth-password-input"
            return FakeHandle()

    stdout = StringIO()
    with patch.object(sys, "argv", argv), patch.object(sys, "platform", "win32"), patch.object(
        store_module, "getpass", return_value="synth-password-input"
    ), patch(
        "router_control.adapters.secrets.dpapi.WindowsDpapiVault",
        FakeVault,
    ), patch("sys.stdout", stdout):
        assert store_module.main() == 0

    metadata = json.loads(meta_path.read_text(encoding="utf-8"))
    assert set(metadata.keys()) == {"host", "username", "credential_ref"}
    assert metadata["host"] == "192.168.1.1"
    assert metadata["username"] == "lab-user"
    assert metadata["credential_ref"] == "cred_synth_test"
    out_text = stdout.getvalue()
    assert "synth-password-input" not in out_text
    assert "cred_synth_test" in out_text
