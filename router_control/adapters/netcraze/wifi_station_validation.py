"""Thin validation for sealed Wi-Fi station (WISP client) write allowlist arms."""

from __future__ import annotations

ALLOWED_WIFI_STATION_IDS = frozenset(
    {"WifiMaster0/WifiStation0", "WifiMaster1/WifiStation0"}
)


def validate_wifi_station_id(station_id: str) -> str:
    """Return normalized allowlisted station id or raise ValueError."""
    normalized = station_id.strip()
    if normalized not in ALLOWED_WIFI_STATION_IDS:
        raise ValueError(f"wifi station id not allowlisted: {station_id!r}")
    return normalized
