"""Per-app fake Wi-Fi device state shared by apply and observed transports."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_INTERFACE_PREFIX = re.compile(r"^interface\s+(\S+)\s+(.+)$", re.IGNORECASE)
_WPA_PSK_CMD = re.compile(r"^authentication\s+wpa-psk\s+\S+", re.IGNORECASE)

_DEFAULT_LAB_AP_ID = "WifiMaster0/AccessPoint3"


def _seed_default_lab_ap(device: FakeWifiDeviceState) -> None:
    device.apply_command(f"interface {_DEFAULT_LAB_AP_ID} ssid Staff-Private")
    device.apply_command(f"interface {_DEFAULT_LAB_AP_ID} encryption enable")
    device.apply_command(f"interface {_DEFAULT_LAB_AP_ID} encryption wpa2")
    device.apply_command(
        f"interface {_DEFAULT_LAB_AP_ID} authentication wpa-psk synthetic-lab-standin"
    )
    device.apply_command(f"interface {_DEFAULT_LAB_AP_ID} up")


_UNCONFIGURED_READBACK: dict[str, Any] = {
    "interface": {
        "ssid": "",
        "encryption": {},
        "state": "down",
        "up": False,
        "link": "down",
        "connected": True,
    }
}


@dataclass
class _ApState:
    ever_configured: bool = False
    ssid: str = ""
    up: bool = False
    encryption_enabled: bool = False
    wpa2: bool = False
    wpa3: bool = False
    psk_set: bool = False


@dataclass
class FakeWifiDeviceState:
    _aps: dict[str, _ApState] = field(default_factory=dict)

    def _ap(self, ap_id: str) -> _ApState:
        if ap_id not in self._aps:
            self._aps[ap_id] = _ApState()
        return self._aps[ap_id]

    def apply_command(self, command: str) -> None:
        cmd = command.strip()
        match = _INTERFACE_PREFIX.match(cmd)
        if not match:
            return
        ap_id, rest = match.group(1), match.group(2).strip()
        ap = self._ap(ap_id)
        lowered = rest.lower()

        if lowered == "up":
            ap.up = True
            ap.ever_configured = True
            return
        if lowered == "down":
            ap.up = False
            return
        if lowered.startswith("ssid "):
            ap.ssid = rest[5:].strip()
            ap.ever_configured = True
            return
        if lowered == "no ssid":
            ap.ssid = ""
            return
        if _WPA_PSK_CMD.match(rest):
            ap.psk_set = True
            ap.ever_configured = True
            return
        if lowered == "no authentication wpa-psk":
            ap.psk_set = False
            return
        if lowered == "encryption enable":
            ap.encryption_enabled = True
            ap.ever_configured = True
            return
        if lowered == "no encryption enable":
            ap.encryption_enabled = False
            return
        if lowered == "encryption wpa2":
            ap.wpa2 = True
            ap.ever_configured = True
            return
        if lowered == "no encryption wpa2":
            ap.wpa2 = False
            return
        if lowered == "encryption wpa3":
            ap.wpa3 = True
            ap.ever_configured = True
            return
        if lowered == "no encryption wpa3":
            ap.wpa3 = False

    def readback_for(self, ap_id: str) -> dict[str, Any]:
        if ap_id not in self._aps or not self._aps[ap_id].ever_configured:
            return dict(_UNCONFIGURED_READBACK)

        ap = self._aps[ap_id]
        if (
            not ap.up
            and not ap.ssid
            and not ap.encryption_enabled
            and not ap.psk_set
        ):
            return {
                "interface": {
                    "ssid": None,
                    "encryption": {},
                    "state": "down",
                    "up": False,
                    "link": "down",
                    "connected": True,
                }
            }

        encryption: dict[str, Any] = {}
        if ap.encryption_enabled:
            encryption["enabled"] = True
            if ap.wpa2:
                encryption["wpa2"] = True
            if ap.wpa3:
                encryption["wpa3"] = True

        up = ap.up
        return {
            "interface": {
                "ssid": ap.ssid,
                "encryption": encryption,
                "state": "up" if up else "down",
                "up": up,
                "link": "up" if up else "down",
                "connected": True,
            }
        }


def ensure_fake_wifi_device(host: Any) -> FakeWifiDeviceState:
    device = getattr(host, "fake_wifi_device", None)
    if device is None:
        device = FakeWifiDeviceState()
        _seed_default_lab_ap(device)
        host.fake_wifi_device = device
    return device
