"""Static checks for run-prototype-host.ps1 (no real DPAPI decrypt)."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "run-prototype-host.ps1"


def test_script_exists() -> None:
    assert SCRIPT.is_file()


def test_script_declares_actions_and_dpapi_path() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert 'ValidateSet("start", "init", "rotate", "clear")' in text
    assert "RouterControlDev" in text
    assert "hub-admin.dpapi" in text
    assert "RC_STANDALONE_LOOPBACK_AUTH" in text
    assert "RC_PUBLIC_BASE_URL" in text
    assert "127.0.0.1" in text


def test_script_never_echoes_password_to_disk() -> None:
    text = SCRIPT.read_text(encoding="utf-8").lower()
    assert "write-host $plain" not in text
    assert "write-host $env:hub_admin_password" not in text


def test_script_clears_env_in_finally() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Remove-Item Env:HUB_ADMIN_PASSWORD" in text
    assert "ZeroFreeBSTR" in text
    assert "$plain = $null" in text


def test_read_matching_password_disposes_first_on_mismatch() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert "Clear-SensitiveVariable -SecureString $first" in text
    assert "Password confirmation mismatch." in text


def test_clear_action_requires_explicit_switch() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert '"clear"' in text
    assert "Remove-DpapiBlob" in text


def _get_decrypted_secure_password_block() -> str:
    text = SCRIPT.read_text(encoding="utf-8")
    start = text.index("function Get-DecryptedSecurePassword")
    end = text.index("$ScriptRoot = $PSScriptRoot")
    return text[start:end]


def test_get_decrypted_secure_password_reads_raw_and_trims_ciphertext() -> None:
    func = _get_decrypted_secure_password_block()
    assert "Get-Content -LiteralPath $paths.File -Raw" in func
    assert "$cipher = $cipher.Trim()" in func
    trim_idx = func.index(".Trim()")
    convert_idx = func.index("ConvertTo-SecureString -String $cipher")
    assert trim_idx < convert_idx


def test_get_decrypted_secure_password_rejects_empty_ciphertext() -> None:
    func = _get_decrypted_secure_password_block()
    assert "[string]::IsNullOrEmpty($cipher)" in func
    assert "DPAPI store is empty or invalid. Run with -Action init first." in func


def test_save_dpapi_blob_preserves_no_newline_on_write() -> None:
    text = SCRIPT.read_text(encoding="utf-8")
    assert (
        "Set-Content -LiteralPath $paths.File -Value $cipher -Encoding UTF8 -NoNewline"
        in text
    )


def test_ciphertext_trim_shape_is_newline_compatible() -> None:
    """Trailing CR/LF on stored blob is stripped before conversion (no DPAPI)."""
    sample = "01000000D08C9DDF0115D1118C7A00C04FC9DEB"
    for suffix in ("\n", "\r\n", " \n", "\r\n "):
        assert (sample + suffix).strip() == sample
    for empty_blob in ("", "   ", "\n", "\r\n", " \t\n "):
        assert not empty_blob.strip()
