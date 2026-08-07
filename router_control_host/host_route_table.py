"""Hub-local IPv4 default gateway reader (Windows Get-NetRoute)."""

from __future__ import annotations

import json
import platform
import subprocess
from collections.abc import Callable
from typing import Any, Literal, TypeVar

from router_control.application.router_discovery import (
    DefaultGatewayRoute,
    EmptyHostRouteTablePort,
    HostRouteTablePort,
    LocalHostIPv4Interface,
)

_UTF8_CONSOLE_PREFIX = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false); "

_POWERSHELL_COMMAND = (
    _UTF8_CONSOLE_PREFIX
    + "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 | ForEach-Object {"
    " $src = (Get-NetIPAddress -InterfaceIndex $_.InterfaceIndex -AddressFamily IPv4 "
    "-ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike '169.254.*' } "
    "| Select-Object -First 1).IPAddress;"
    " [PSCustomObject]@{ NextHop = $_.NextHop; InterfaceIndex = $_.InterfaceIndex;"
    " InterfaceAlias = $_.InterfaceAlias; SourceAddress = $src }"
    "} | ConvertTo-Json -Compress"
)

_IPV4_INTERFACES_COMMAND = (
    _UTF8_CONSOLE_PREFIX
    + "Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' } | ForEach-Object {"
    " $v4 = ($_.IPv4Address | Where-Object { $_ -and $_.IPAddress -notlike '169.254.*' "
    "-and $_.IPAddress -notlike '127.*' } | Select-Object -First 1);"
    " if ($v4) {"
    " [PSCustomObject]@{ IPAddress = $v4.IPAddress; PrefixLength = $v4.PrefixLength;"
    " InterfaceIndex = $_.NetAdapter.InterfaceIndex; InterfaceAlias = $_.NetAdapter.Name }"
    " }"
    "} | ConvertTo-Json -Compress"
)

RouteTableSourceName = Literal["default_gateway", "local_subnet_gateway"]
RouteTableSourceStatus = Literal["ok", "empty", "failed"]
RouteTableSourceReasonCode = Literal[
    "timeout", "os_error", "unicode_decode", "json_decode", "nonzero_exit"
]

_T = TypeVar("_T")


def _strip_utf8_bom(text: str) -> str:
    if text.startswith("\ufeff"):
        return text[1:]
    return text


def parse_net_route_records(raw: Any) -> list[dict[str, Any]]:
    """Normalize PowerShell ConvertTo-Json output to a list of route dicts."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def parse_net_route_json(payload: str | bytes) -> list[DefaultGatewayRoute]:
    """Parse Get-NetRoute JSON into DefaultGatewayRoute entries."""
    text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    stripped = _strip_utf8_bom(text.strip())
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return []
    records = parse_net_route_records(parsed)
    routes: list[DefaultGatewayRoute] = []
    seen: set[tuple[str, int | None]] = set()
    for record in records:
        next_hop = record.get("NextHop")
        if not isinstance(next_hop, str) or not next_hop.strip():
            continue
        gateway = next_hop.strip()
        if gateway in ("0.0.0.0", "::"):
            continue
        if_index_raw = record.get("InterfaceIndex")
        if_index: int | None
        if isinstance(if_index_raw, int):
            if_index = if_index_raw
        elif isinstance(if_index_raw, str) and if_index_raw.isdigit():
            if_index = int(if_index_raw)
        else:
            if_index = None
        alias = record.get("InterfaceAlias")
        route_label = alias.strip() if isinstance(alias, str) and alias.strip() else None
        source_raw = record.get("SourceAddress")
        source_address = (
            source_raw.strip()
            if isinstance(source_raw, str) and source_raw.strip()
            else None
        )
        dedupe_key = (gateway, if_index)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        routes.append(
            DefaultGatewayRoute(
                gateway_host=gateway,
                source_address=source_address,
                route_if_index=if_index,
                route_label=route_label,
            )
        )
    return routes


def parse_net_ip_interface_records(raw: Any) -> list[dict[str, Any]]:
    """Normalize PowerShell ConvertTo-Json output to a list of interface dicts."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, dict)]
    if isinstance(raw, dict):
        return [raw]
    return []


def _parse_prefix_length(raw: Any) -> int | None:
    if isinstance(raw, int) and raw > 0:
        return raw
    if isinstance(raw, str) and raw.isdigit():
        value = int(raw)
        return value if value > 0 else None
    return None


def _parse_if_index(raw: Any) -> int | None:
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str) and raw.isdigit():
        return int(raw)
    return None


def parse_net_ip_interface_json(payload: str | bytes) -> list[LocalHostIPv4Interface]:
    """Parse Get-NetIPConfiguration JSON into LocalHostIPv4Interface entries."""
    text = payload.decode("utf-8") if isinstance(payload, bytes) else payload
    stripped = _strip_utf8_bom(text.strip())
    if not stripped:
        return []
    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError:
        return []
    records = parse_net_ip_interface_records(parsed)
    interfaces: list[LocalHostIPv4Interface] = []
    seen: set[tuple[str, int | None]] = set()
    for record in records:
        address_raw = record.get("IPAddress")
        if not isinstance(address_raw, str) or not address_raw.strip():
            continue
        address = address_raw.strip()
        if address.startswith("169.254.") or address.startswith("127."):
            continue
        prefix_length = _parse_prefix_length(record.get("PrefixLength"))
        if prefix_length is None:
            continue
        if_index = _parse_if_index(record.get("InterfaceIndex"))
        alias = record.get("InterfaceAlias")
        if_label = alias.strip() if isinstance(alias, str) and alias.strip() else None
        dedupe_key = (address, if_index)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        interfaces.append(
            LocalHostIPv4Interface(
                address=address,
                prefix_length=prefix_length,
                if_index=if_index,
                if_label=if_label,
            )
        )
    return interfaces


class WindowsHostRouteTable:
    """Read IPv4 default gateways from the local Windows routing table."""

    def __init__(self) -> None:
        self._source_diagnostics: dict[str, dict[str, Any]] = {}

    @property
    def last_source_diagnostics(self) -> list[dict[str, Any]]:
        return list(self._source_diagnostics.values())

    def _record_source_diagnostic(
        self,
        source: RouteTableSourceName,
        *,
        status: RouteTableSourceStatus,
        reason_code: RouteTableSourceReasonCode | None = None,
    ) -> None:
        entry: dict[str, Any] = {"source": source, "status": status}
        if reason_code is not None:
            entry["reason_code"] = reason_code
        self._source_diagnostics[source] = entry

    def _run_powershell_source(
        self,
        *,
        source: RouteTableSourceName,
        command: str,
        parse_fn: Callable[[str], list[_T]],
    ) -> list[_T]:
        try:
            completed = subprocess.run(
                ["powershell", "-NoProfile", "-Command", command],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            self._record_source_diagnostic(source, status="failed", reason_code="timeout")
            return []
        except OSError:
            self._record_source_diagnostic(source, status="failed", reason_code="os_error")
            return []
        except UnicodeDecodeError:
            self._record_source_diagnostic(
                source, status="failed", reason_code="unicode_decode"
            )
            return []
        if completed.returncode != 0:
            self._record_source_diagnostic(
                source, status="failed", reason_code="nonzero_exit"
            )
            return []
        stdout = completed.stdout or ""
        stripped = _strip_utf8_bom(stdout.strip())
        if not stripped:
            self._record_source_diagnostic(source, status="empty")
            return []
        try:
            json.loads(stripped)
        except json.JSONDecodeError:
            self._record_source_diagnostic(
                source, status="failed", reason_code="json_decode"
            )
            return []
        rows = parse_fn(stdout)
        if rows:
            self._record_source_diagnostic(source, status="ok")
        else:
            self._record_source_diagnostic(source, status="empty")
        return rows

    def list_ipv4_default_gateways(self) -> list[DefaultGatewayRoute]:
        return self._run_powershell_source(
            source="default_gateway",
            command=_POWERSHELL_COMMAND,
            parse_fn=parse_net_route_json,
        )

    def list_ipv4_host_interfaces(self) -> list[LocalHostIPv4Interface]:
        return self._run_powershell_source(
            source="local_subnet_gateway",
            command=_IPV4_INTERFACES_COMMAND,
            parse_fn=parse_net_ip_interface_json,
        )


def platform_host_route_table() -> HostRouteTablePort:
    if platform.system() == "Windows":
        return WindowsHostRouteTable()
    return EmptyHostRouteTablePort()


__all__ = [
    "WindowsHostRouteTable",
    "parse_net_ip_interface_json",
    "parse_net_ip_interface_records",
    "parse_net_route_json",
    "parse_net_route_records",
    "platform_host_route_table",
]
