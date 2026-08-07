"""Shared validation errors for network-family RCI adapters (no user-value echo)."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RciValidationError(ValueError):
    """Structural validation failure for operator-facing preview/compile paths."""

    code: str
    field: str | None = None

    def __str__(self) -> str:
        if self.field:
            return f"validation failed: {self.code} ({self.field})"
        return f"validation failed: {self.code}"
