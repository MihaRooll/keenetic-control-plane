"""KeenDNS/CrazeDNS preview-only service — no apply or RCI dispatch."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from router_control.application.keendns_planner import (
    KeenDnsPlannerError,
    compile_keendns_preview_intent,
    plan_to_preview_dict,
)


class KeenDnsPreviewServiceError(ValueError):
    """Fail-closed KeenDNS preview service error."""


def preview_keendns(intent: Mapping[str, Any]) -> dict[str, object]:
    """Validate + compile sealed preview descriptors only; never dispatches."""
    try:
        plan = compile_keendns_preview_intent(intent)
    except (KeenDnsPlannerError, ValueError) as exc:
        raise KeenDnsPreviewServiceError(str(exc)) from exc
    return plan_to_preview_dict(plan)


__all__ = ["KeenDnsPreviewServiceError", "preview_keendns"]
