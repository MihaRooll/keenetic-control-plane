"""Explicit fake-only evidence markers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FakeAdapterEvidence:
    adapter_mode: str
    certifies_nc1812: bool
    note: str

    @classmethod
    def fake_only(cls) -> FakeAdapterEvidence:
        return cls(
            adapter_mode="fake",
            certifies_nc1812=False,
            note=(
                "In-memory FakeRouterAdapter — simulates L2 apply/verify only; "
                "cannot certify NC-1812 or open hardware gates A–D."
            ),
        )
