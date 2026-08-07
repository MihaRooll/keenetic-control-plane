"""Tests for plan-gate-b-family offline CLI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CLI = REPO_ROOT / "scripts" / "plan-gate-b-family.py"


def _run_cli(*args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return subprocess.run(
        [sys.executable, str(CLI), *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=merged,
        check=False,
    )


def test_cli_offline_plan_fail_safe() -> None:
    result = _run_cli("--family", "fail_safe")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["capability_family"] == "fail_safe"
    assert payload["dispatch_permitted"] is False
    assert payload["write_certified_claim"] is False


def test_cli_refuses_password_env() -> None:
    result = _run_cli("--family", "fail_safe", env={"RC_ROUTER_PASSWORD": "secret"})
    assert result.returncode == 2
    assert "Refusing password" in result.stderr


def test_cli_refuses_attached_password_flag() -> None:
    result = _run_cli("--family", "fail_safe", "--password=secret")
    assert result.returncode == 2
    assert "Refusing raw command flag" in result.stderr


def test_cli_refuses_raw_rci_path() -> None:
    result = _run_cli("--family", "fail_safe", "/rci/show/system")
    assert result.returncode == 2
    assert "raw RCI" in result.stderr


def test_cli_fixture_replay() -> None:
    result = _run_cli("--family", "fail_safe", "--fixture-id", "lab-default")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["fixture_replay"] is True
