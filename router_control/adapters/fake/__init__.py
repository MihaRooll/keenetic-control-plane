"""Fake adapter package."""

from router_control.adapters.fake.adapter import FakeRouterAdapter, FakeRouterConfig
from router_control.adapters.fake.evidence import FakeAdapterEvidence

__all__ = ["FakeAdapterEvidence", "FakeRouterAdapter", "FakeRouterConfig"]
