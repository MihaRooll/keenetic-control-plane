"""Secret vault adapters (blobs outside SQLite)."""

from __future__ import annotations

from router_control.adapters.secrets.dpapi import WindowsDpapiVault
from router_control.adapters.secrets.memory import MemoryVault

__all__ = ["MemoryVault", "WindowsDpapiVault"]
