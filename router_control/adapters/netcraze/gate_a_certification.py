"""Backward-compatible re-export of typed Gate A certification boundary."""

from router_control.adapters.netcraze.certification import (
    DEFAULT_OBSERVATION_TTL_SECONDS,
    DEFAULT_OPENING_FRESHNESS_HOURS,
    GateACertification,
    GateACertificationError,
    load_gate_a_certification,
    try_load_gate_a_certification,
)

__all__ = [
    "DEFAULT_OBSERVATION_TTL_SECONDS",
    "DEFAULT_OPENING_FRESHNESS_HOURS",
    "GateACertification",
    "GateACertificationError",
    "load_gate_a_certification",
    "try_load_gate_a_certification",
]
