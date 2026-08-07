"""Offline tests for the public integration facade."""

from __future__ import annotations

from pathlib import Path

import pytest
from router_control import (
    LiveRuntime,
    MemoryVault,
    OfflineRuntime,
    RouterControlConfig,
    build_runtime,
    create_fake_runtime,
    create_live_runtime,
    create_offline_runtime,
)
from router_control.composition import FakeRuntime
from router_control.domain.ids import RouterId


def test_public_exports_importable() -> None:
    assert RouterControlConfig is not None
    assert build_runtime is not None
    assert create_offline_runtime is not None
    assert create_live_runtime is not None
    assert OfflineRuntime is not None
    assert LiveRuntime is not None
    assert MemoryVault is not None
    assert create_fake_runtime is not None


@pytest.mark.asyncio
async def test_fake_mode_observe_without_db() -> None:
    runtime = build_runtime(RouterControlConfig(adapter_mode="fake"))
    assert isinstance(runtime, FakeRuntime)
    obs = await runtime.adapter.observe(RouterId("router-fake-001"))
    assert obs.identity_fingerprint_digest
    assert obs.state_digest


def test_offline_mode_creates_db_at_configured_path(tmp_path: Path) -> None:
    db_path = tmp_path / "integration-offline.sqlite3"
    runtime = build_runtime(
        RouterControlConfig(adapter_mode="offline", db_path=db_path),
    )
    assert isinstance(runtime, OfflineRuntime)
    assert runtime.db_path == db_path
    assert db_path.is_file()


def test_live_mode_without_network(tmp_path: Path) -> None:
    db_path = tmp_path / "integration-live.sqlite3"
    secrets_root = tmp_path / "secrets"
    runtime = build_runtime(
        RouterControlConfig(
            adapter_mode="live",
            db_path=db_path,
            secrets_root=secrets_root,
        ),
    )
    assert isinstance(runtime, LiveRuntime)
    assert runtime.db_path == db_path
    assert runtime.secrets_root == secrets_root
    assert db_path.is_file()
    assert not hasattr(runtime, "adapter")


def test_create_fake_runtime_still_exported_from_package() -> None:
    runtime = create_fake_runtime(router_id="router-export-check")
    assert isinstance(runtime, FakeRuntime)
    assert runtime.adapter.state.identity.router_id == RouterId("router-export-check")


def test_unknown_adapter_mode_raises() -> None:
    with pytest.raises(ValueError, match="unknown adapter_mode"):
        build_runtime(RouterControlConfig(adapter_mode="invalid"))  # type: ignore[arg-type]
