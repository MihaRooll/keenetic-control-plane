"""Public integration facade for third-party services (stdlib-only)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from router_control.composition import (
    FakeRuntime,
    LiveRuntime,
    OfflineRuntime,
    create_fake_runtime,
    create_live_runtime,
    create_offline_runtime,
)


@dataclass(frozen=True, slots=True)
class RouterControlConfig:
    db_path: Path | None = None
    secrets_root: Path | None = None
    adapter_mode: Literal["fake", "offline", "live"] = "offline"
    router_id: str | None = None
    fingerprint_digest: str | None = None


def build_runtime(
    config: RouterControlConfig,
) -> FakeRuntime | OfflineRuntime | LiveRuntime:
    """Dispatch to composition factories; no extra wiring beyond passthrough."""
    mode = config.adapter_mode
    if mode == "fake":
        router_id = config.router_id
        fingerprint_digest = config.fingerprint_digest
        if router_id is not None and fingerprint_digest is not None:
            return create_fake_runtime(
                router_id=router_id,
                fingerprint_digest=fingerprint_digest,
            )
        if router_id is not None:
            return create_fake_runtime(router_id=router_id)
        if fingerprint_digest is not None:
            return create_fake_runtime(fingerprint_digest=fingerprint_digest)
        return create_fake_runtime()
    if mode == "offline":
        return create_offline_runtime(db_path=config.db_path)
    if mode == "live":
        return create_live_runtime(
            db_path=config.db_path,
            secrets_root=config.secrets_root,
        )
    raise ValueError(f"unknown adapter_mode: {mode!r}")
