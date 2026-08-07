"""Guard: router_control_host must stay under strict mypy (no silent ignore_errors)."""

from __future__ import annotations

import fnmatch
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_HOST_MODULE_SAMPLES = (
    "router_control_host/host_probes.py",
    "router_control_host/app.py",
    "router_control_host/host_probe_routes.py",
)


def _override_targets_host_module(module: str) -> bool:
    normalized = module.strip()
    if not normalized:
        return False
    if normalized == "router_control_host":
        return True
    if normalized.startswith("router_control_host."):
        return True
    return False


def _exclude_hides_host_module(pattern: str) -> bool:
    normalized = pattern.replace("\\", "/")
    for sample in _HOST_MODULE_SAMPLES:
        if fnmatch.fnmatch(sample, normalized):
            return True
        if fnmatch.fnmatch(sample, f"**/{normalized}"):
            return True
    return False


def test_pyproject_mypy_includes_router_control_host() -> None:
    """Regression: host package must not be excluded from config-driven mypy."""
    pyproject = REPO_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    mypy = data["tool"]["mypy"]
    files = mypy["files"]
    assert "router_control_host" in files, (
        f"[tool.mypy].files must include router_control_host; got {files!r}"
    )
    overrides = mypy.get("overrides", [])
    for override in overrides:
        module = override.get("module", "")
        if _override_targets_host_module(module) and override.get("ignore_errors"):
            raise AssertionError(
                f"mypy override for {module!r} must not set ignore_errors "
                f"(got {override.get('ignore_errors')!r})",
            )
    exclude = mypy.get("exclude", [])
    for entry in exclude:
        if _exclude_hides_host_module(str(entry)):
            raise AssertionError(
                f"mypy exclude pattern {entry!r} matches router_control_host modules",
            )


def test_mypy_ignore_errors_truthy_string_would_be_blocked() -> None:
    """Regression: truthy ignore_errors values must fail the host-module guard."""
    pyproject = REPO_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    overrides = data["tool"]["mypy"].get("overrides", [])
    for override in overrides:
        module = override.get("module", "")
        if not _override_targets_host_module(module):
            continue
        value = override.get("ignore_errors")
        assert not value, f"ignore_errors must be falsy for {module!r}, got {value!r}"

    assert _override_targets_host_module("router_control_host.host_probes")
    assert bool("True")
    assert bool(1)
