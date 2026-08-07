"""Thin validation for WireGuard TCP MSS clamping (PMTU mode only).

NDMS also accepts ``interface Wireguard{N} ip tcp adjust-mss {numeric}`` on
5.01.C.1.0-0, but numeric MSS is intentionally unsupported in this product
path — only ``pmtu`` is emitted and allowlisted.
"""

from __future__ import annotations

TCP_MSS_MODE_PMTU = "pmtu"


def validate_tcp_mss_bound(value: str) -> str:
    """Accept only the device-verified PMTU mode token."""
    normalized = str(value).strip().lower()
    if normalized != TCP_MSS_MODE_PMTU:
        raise ValueError(
            f"tcp_mss mode must be {TCP_MSS_MODE_PMTU!r} (numeric MSS intentionally unsupported)"
        )
    return normalized
