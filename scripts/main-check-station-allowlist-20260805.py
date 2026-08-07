"""Main-only: is a Wi-Fi station sealed write body actually accepted by the client allowlist?

The uplink package reported that station writes are not allowlisted, which would mean the
remembered-uplink auto-reconnect cannot work live. This checks the claim directly by building
real sealed bodies with the project's own builder and asking the allowlist.
"""

from __future__ import annotations

import inspect
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))


def main() -> int:
    from router_control.adapters.netcraze import allowlist, wifi_station_rci

    builders = [
        name
        for name, obj in inspect.getmembers(wifi_station_rci, inspect.isfunction)
        if not name.startswith("_")
    ]
    print("wifi_station_rci public functions:", builders)

    operations = getattr(wifi_station_rci, "WifiStationRciOperation", None)
    if operations is None:
        print("no WifiStationRciOperation enum found")
        return 1
    print("\noperations:", [member.value for member in operations])

    command_for = getattr(wifi_station_rci, "command_for", None)
    if command_for is None:
        print("no command_for builder found")
        return 1

    sig = inspect.signature(command_for)
    print("\ncommand_for signature:", sig)

    station_id = "WifiMaster1/WifiStation0"
    sample_kwargs = {
        "ssid": "LabUplinkSsid",
        "psk": "placeholder-not-a-real-secret",
        "bssid": "00:11:22:33:44:55",
        "security_level": "public",
        "priority": 600,
        "standby_timeout": 60,
    }

    print("\nper-operation allowlist verdict:")
    for member in operations:
        kwargs = {
            key: value for key, value in sample_kwargs.items() if key in sig.parameters
        }
        try:
            command = command_for(member, station_id, **kwargs)
        except Exception as exc:  # noqa: BLE001 - diagnostics
            print(f"  {member.value}: builder refused ({exc.__class__.__name__}: {exc})")
            continue
        try:
            body = allowlist.build_sealed_parse_body(command)
        except Exception as exc:  # noqa: BLE001 - diagnostics
            print(f"  {member.value}: sealed body refused ({exc.__class__.__name__}: {exc})")
            continue
        verdict = allowlist.is_write_allowlisted("POST", "/rci/", body)
        redacted = command if "key" not in command.lower() else "<redacted command>"
        print(f"  {member.value}: is_write_allowlisted={verdict} | {redacted}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
