"""Non-certifying read-only bootstrap discovery for Add-router wizard (plain HTTP opt-in)."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.allowlist import (
    COMPONENTS_LIST,
    SHOW_IDENTIFICATION,
    SHOW_INTERFACE,
    SHOW_IP_HTTP,
    SHOW_IP_SSH,
    SHOW_SYSTEM,
    SHOW_VERSION,
    is_expendable_lab_class,
)
from router_control.adapters.netcraze.errors import (
    ContinuationUnsupported,
    FeatureAbsent,
    IdentityParseError,
    NetcrazeAdapterError,
)
from router_control.adapters.netcraze.identity import parse_identity
from router_control.adapters.netcraze.sanitize import (
    _SERIAL_MAC_PATTERN,
    hash_interface_id,
    redact_key,
    sanitize_mapping,
    sanitize_value,
)
from router_control.adapters.netcraze.transport import NetcrazeTransport, parse_transport_target
from router_control.application.wifi_observation_helpers import (
    resolve_device_connected,
    resolve_link_up,
)
from router_control.ports.vault import CredentialVaultPort

VERIFIED_FIRMWARE_BASELINE = "5.01.C.1.0-0"

FINDING_SSH_COMPONENT_MISSING = "ssh_component_missing"
FINDING_SSH_DISABLED = "ssh_disabled"
FINDING_SSH_STATE_UNKNOWN = "ssh_state_unknown"
FINDING_FIRMWARE_BELOW_BASELINE = "firmware_below_verified_baseline"
FINDING_WIFI_INVENTORY_UNAVAILABLE = "wifi_inventory_unavailable"
FINDING_COMPONENT_CHANGE_TRIGGERS_FIRMWARE_UPGRADE = (
    "component_change_triggers_firmware_upgrade"
)
FINDING_UPDATE_CHANNEL_NOT_STABLE = "update_channel_not_stable"
FINDING_FIRMWARE_MAJOR_VERSION_JUMP = "firmware_major_version_jump"
FINDING_COMPONENTS_LISTING_TIMEOUT = "components_listing_timeout"
FINDING_COMPONENTS_INVENTORY_UNAVAILABLE = "components_inventory_unavailable"
FINDING_UPDATE_CHANNEL_UNKNOWN = "update_channel_unknown"

_COMPONENTS_INVENTORY_CAP = 64
_SSH_COMPONENT_LOOKUP = "component.ssh"
_COMPONENT_VERSION_TOKEN_RE = re.compile(
    r"^[0-9]+(?:\.[0-9A-Za-z]+)*(?:-[0-9A-Za-z]+(?:\.[0-9A-Za-z]+)*)?$"
)

def _component_change_side_effects(
    firmware_version_changes: bool | None,
) -> dict[str, bool | None]:
    """Process effects always true; version change derived from channel vs installed."""
    return {
        "firmware_rebuild": True,
        "automatic_reboot": True,
        "management_downtime": True,
        "firmware_version_changes": firmware_version_changes,
    }

_KNOWN_NON_STABLE_SANDBOXES = frozenset({"preview", "draft", "dev"})
_SANDBOX_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")

_BOOTSTRAP_COMMANDS = (
    SHOW_SYSTEM,
    COMPONENTS_LIST,
    SHOW_IDENTIFICATION,
    SHOW_VERSION,
    SHOW_INTERFACE,
    SHOW_IP_SSH,
    SHOW_IP_HTTP,
)

_OPTIONAL_BOOTSTRAP_COMMANDS = frozenset({SHOW_IP_SSH, SHOW_IP_HTTP})

_WIFI_AP_ID_RE = re.compile(r"^WifiMaster[01]/AccessPoint[0-9]+$")

_COMPONENTS_BODY = json.dumps({}).encode("utf-8")


class BootstrapDiscoveryError(Exception):
    """Policy or transport failure during bootstrap discovery."""


@dataclass(frozen=True, slots=True)
class BootstrapDiscoveryReport:
    certification_eligible: bool
    transport_security: str
    https_check: str
    model: str | None
    firmware_version: str | None
    firmware_digest: str | None
    fingerprint_digest: str | None
    component_set_digest: str | None
    ssh_component_installed: bool | None
    ssh_access_enabled: bool | None
    management_http: dict[str, Any] | None
    wifi_access_points: tuple[dict[str, Any], ...]
    findings: tuple[str, ...]
    sandbox: str | None = None
    update_channel: str | None = None
    channel_firmware_version: str | None = None
    component_change_would_upgrade_firmware: bool | None = None
    component_change_crosses_major_version: bool | None = None
    component_change_firmware_version_changes: bool | None = None
    update_channel_is_stable: bool | None = None
    components_inventory: dict[str, Any] | None = None
    ssh_component_determination: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "certification_eligible": self.certification_eligible,
            "transport_security": self.transport_security,
            "https_check": self.https_check,
            "ssh_component_installed": self.ssh_component_installed,
            "ssh_access_enabled": self.ssh_access_enabled,
            "wifi_access_points": list(self.wifi_access_points),
            "findings": list(self.findings),
            "component_change_side_effects": _component_change_side_effects(
                self.component_change_firmware_version_changes
            ),
        }
        if self.management_http is not None:
            payload["management_http"] = self.management_http
        if self.model is not None:
            payload["model"] = self.model
        if self.firmware_version is not None:
            payload["firmware_version"] = self.firmware_version
        if self.firmware_digest is not None:
            payload["firmware_digest"] = self.firmware_digest
        if self.fingerprint_digest is not None:
            payload["fingerprint_digest"] = self.fingerprint_digest
        if self.component_set_digest is not None:
            payload["component_set_digest"] = self.component_set_digest
        if self.sandbox is not None:
            payload["sandbox"] = self.sandbox
        if self.update_channel is not None:
            payload["update_channel"] = self.update_channel
        if self.channel_firmware_version is not None:
            payload["channel_firmware_version"] = self.channel_firmware_version
        if self.component_change_would_upgrade_firmware is not None:
            payload["component_change_would_upgrade_firmware"] = (
                self.component_change_would_upgrade_firmware
            )
        if self.component_change_crosses_major_version is not None:
            payload["component_change_crosses_major_version"] = (
                self.component_change_crosses_major_version
            )
        if self.update_channel_is_stable is not None:
            payload["update_channel_is_stable"] = self.update_channel_is_stable
        if self.components_inventory is not None:
            payload["components_inventory"] = self.components_inventory
        if self.ssh_component_determination is not None:
            payload["ssh_component_determination"] = self.ssh_component_determination
        return sanitize_mapping(payload)


def _host_is_private(host: str) -> bool:
    try:
        candidate = parse_transport_target(host).hostname
    except ValueError:
        candidate = host
    if candidate.endswith(".local"):
        return True
    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return bool(addr.is_private or addr.is_link_local or addr.is_loopback)


def _firmware_sort_key(raw: str) -> tuple[Any, ...]:
    main, _, tail = raw.partition("-")
    segments: list[Any] = []
    for segment in main.split("."):
        if segment.isdigit():
            segments.append(int(segment))
        else:
            segments.append(segment)
    if tail.isdigit():
        segments.append(int(tail))
    elif tail:
        segments.append(tail)
    return tuple(segments)


def _firmware_below_verified_baseline(observed: str) -> bool:
    return _firmware_sort_key(observed) < _firmware_sort_key(VERIFIED_FIRMWARE_BASELINE)


def _firmware_major_segment(raw: str) -> int | None:
    main, _, _ = raw.partition("-")
    first = main.split(".")[0] if main else ""
    return int(first) if first.isdigit() else None


def _normalize_sandbox(raw: Any) -> str | None:
    if not isinstance(raw, str):
        return None
    normalized = raw.strip().lower()
    if not normalized or not _SANDBOX_TOKEN_RE.fullmatch(normalized):
        return None
    return normalized


def _extract_components_sandbox(components_payload: Any) -> str | None:
    if not isinstance(components_payload, dict):
        return None
    return _normalize_sandbox(components_payload.get("sandbox"))


def _extract_channel_firmware_version(components_payload: Any) -> str | None:
    if not isinstance(components_payload, dict):
        return None
    firmware = components_payload.get("firmware")
    if not isinstance(firmware, dict):
        return None
    version = firmware.get("version")
    if isinstance(version, str) and version.strip():
        return version.strip()
    return None


def _resolve_update_channel(sandbox: str | None) -> tuple[str | None, bool | None]:
    if sandbox is None:
        return None, None
    if sandbox == "stable":
        return "Main", True
    if sandbox in _KNOWN_NON_STABLE_SANDBOXES:
        return sandbox, False
    return sandbox, False


def _installed_firmware_for_channel_assessment(
    identity_firmware: str | None,
    version_payload: Any,
) -> str | None:
    if isinstance(version_payload, dict):
        for key in ("version", "release"):
            raw = version_payload.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
    return identity_firmware


def _assess_component_change_firmware(
    *,
    installed_firmware: str | None,
    channel_firmware_version: str | None,
) -> tuple[bool | None, bool | None, bool | None]:
    if not installed_firmware or not channel_firmware_version:
        return None, None, None
    installed_key = _firmware_sort_key(installed_firmware)
    channel_key = _firmware_sort_key(channel_firmware_version)
    installed_major = _firmware_major_segment(installed_firmware)
    channel_major = _firmware_major_segment(channel_firmware_version)
    crosses_major = (
        installed_major is not None
        and channel_major is not None
        and installed_major != channel_major
    )
    would_upgrade = channel_key > installed_key
    firmware_version_changes = channel_key != installed_key
    return would_upgrade, crosses_major, firmware_version_changes


def _synthetic_components_for_identity_timeout(version_payload: Any) -> dict[str, Any] | None:
    if not isinstance(version_payload, dict):
        return None
    version = version_payload.get("version")
    if not isinstance(version, str) or not version.strip():
        version = version_payload.get("release")
    if not isinstance(version, str) or not version.strip():
        return None
    return {
        "firmware": {"version": version.strip()},
        "component": {"ndm": {"installed": True}},
    }


def _version_token_is_allowed(raw: str) -> bool:
    normalized = raw.strip()
    if not normalized or len(normalized) > 64:
        return False
    return _COMPONENT_VERSION_TOKEN_RE.fullmatch(normalized) is not None


def _resolve_ssh_component_state(
    raw_components: Any,
    *,
    components_listing_timeout: bool,
    inventory: dict[str, Any],
) -> tuple[bool | None, dict[str, Any]]:
    """Derive ssh_component_installed and diagnostic determination together."""
    base: dict[str, Any] = {"lookup": _SSH_COMPONENT_LOOKUP}
    if components_listing_timeout or raw_components is None:
        return None, {**base, "matched": False, "outcome": "inventory_unavailable"}
    if inventory.get("source_shape") in {"unavailable", "empty"}:
        return None, {**base, "matched": False, "outcome": "inventory_unavailable"}
    if not isinstance(raw_components, dict):
        return None, {**base, "matched": False, "outcome": "shape_unusable"}
    component_map = raw_components.get("component")
    if not isinstance(component_map, dict):
        return None, {**base, "matched": False, "outcome": "shape_unusable"}
    ssh_meta = component_map.get("ssh")
    if ssh_meta is None:
        return False, {**base, "matched": False, "outcome": "key_absent"}
    if not isinstance(ssh_meta, dict):
        return None, {**base, "matched": False, "outcome": "shape_unusable"}
    if "installed" in ssh_meta:
        installed = ssh_meta.get("installed")
        if installed is True:
            return True, {
                **base,
                "matched": True,
                "outcome": "matched_true",
                "determination_shape": "explicit_installed",
            }
        if installed is False:
            return False, {
                **base,
                "matched": True,
                "outcome": "matched_false",
                "determination_shape": "explicit_installed",
            }
        return None, {**base, "matched": False, "outcome": "shape_unusable"}
    return True, {
        **base,
        "matched": True,
        "outcome": "matched_true",
        "determination_shape": "presence_in_map",
    }


def _ssh_component_installed(
    components_payload: Any,
    *,
    inventory: dict[str, Any] | None = None,
    components_listing_timeout: bool = False,
) -> bool | None:
    if inventory is None:
        inventory = _build_components_inventory(
            components_payload,
            components_listing_timeout=components_listing_timeout,
        )
    installed, _ = _resolve_ssh_component_state(
        components_payload,
        components_listing_timeout=components_listing_timeout,
        inventory=inventory,
    )
    return installed


def _component_id_is_redacted(comp_id: str) -> bool:
    normalized = comp_id.strip()
    if not normalized:
        return True
    if redact_key(normalized):
        return True
    return bool(_SERIAL_MAC_PATTERN.search(normalized))


def _sanitize_component_inventory_entry(
    comp_id: str,
    meta: Any,
) -> dict[str, Any] | None:
    if not isinstance(comp_id, str) or not comp_id.strip():
        return None
    if _component_id_is_redacted(comp_id):
        return None
    if not isinstance(meta, dict):
        return None
    entry: dict[str, Any] = {"id": sanitize_value(comp_id.strip())}
    for key in ("installed", "version", "available"):
        if key not in meta:
            continue
        raw = meta[key]
        if key == "version":
            if isinstance(raw, str) and raw.strip() and _version_token_is_allowed(raw):
                entry["version"] = raw.strip()
        elif isinstance(raw, bool):
            entry[key] = raw
    return entry


def _build_components_inventory(
    raw_components: Any,
    *,
    components_listing_timeout: bool,
) -> dict[str, Any]:
    unavailable = {
        "entries": [],
        "total_observed": 0,
        "truncated": False,
        "source_shape": "unavailable",
    }
    if components_listing_timeout or raw_components is None:
        return unavailable
    if not isinstance(raw_components, dict):
        return unavailable
    component_map = raw_components.get("component")
    if not isinstance(component_map, dict):
        return unavailable

    observed: list[dict[str, Any]] = []
    for key in sorted(component_map.keys()):
        if not isinstance(key, str):
            continue
        entry = _sanitize_component_inventory_entry(key, component_map[key])
        if entry is not None:
            observed.append(entry)

    total_observed = len(observed)
    if total_observed == 0:
        return {
            "entries": [],
            "total_observed": 0,
            "truncated": False,
            "source_shape": "empty",
        }

    truncated = total_observed > _COMPONENTS_INVENTORY_CAP
    capped = observed[:_COMPONENTS_INVENTORY_CAP]
    if truncated:
        ssh_entry = next((entry for entry in observed if entry.get("id") == "ssh"), None)
        if ssh_entry is not None:
            capped_ids = {entry["id"] for entry in capped}
            if "ssh" not in capped_ids:
                replace_idx = len(capped) - 1
                capped = capped[:replace_idx] + [ssh_entry]
    return {
        "entries": capped,
        "total_observed": total_observed,
        "truncated": truncated,
        "source_shape": "component_map",
    }


def _inventory_is_usable(inventory: dict[str, Any]) -> bool:
    return (
        inventory.get("source_shape") == "component_map"
        and inventory.get("total_observed", 0) > 0
    )


def _inventory_is_unavailable(inventory: dict[str, Any]) -> bool:
    return inventory.get("source_shape") in {"unavailable", "empty"}


def _derive_ssh_component_determination(
    raw_components: Any,
    *,
    components_listing_timeout: bool,
    inventory: dict[str, Any],
) -> dict[str, Any]:
    _, determination = _resolve_ssh_component_state(
        raw_components,
        components_listing_timeout=components_listing_timeout,
        inventory=inventory,
    )
    return determination


def _parse_ssh_access_enabled(payload: Any) -> bool | None:
    if payload is None:
        return None
    if not isinstance(payload, dict):
        return None
    if "enabled" in payload:
        enabled = payload.get("enabled")
        if isinstance(enabled, bool):
            return enabled
        return None
    security = payload.get("security-level")
    if isinstance(security, str):
        normalized = security.strip().lower()
        if normalized in {"private", "public"}:
            return True
        if normalized == "disabled":
            return False
    listen = payload.get("listen")
    if listen is False:
        return False
    if listen is True:
        return True
    if payload == {}:
        return False
    return None


def _extract_security_level(raw: Any) -> str | None:
    if isinstance(raw, str) and raw.strip():
        return raw.strip().lower()
    if isinstance(raw, dict):
        for level in ("private", "public", "disabled"):
            if raw.get(level) is True:
                return level
    return None


def _parse_management_http_summary(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    summary: dict[str, Any] = {}
    port = payload.get("port")
    if isinstance(port, int):
        summary["port"] = port
    security_level = _extract_security_level(payload.get("security-level"))
    if security_level is not None:
        summary["security_level"] = security_level
    listen = payload.get("listen")
    if isinstance(listen, bool):
        summary["listen"] = listen
    if not summary:
        return None
    return sanitize_mapping(summary)


def _resolve_link_connected(entry: dict[str, Any]) -> tuple[bool | None, bool | None] | None:
    link_up = resolve_link_up(entry)
    connected = resolve_device_connected(entry)
    if link_up is None and connected is None:
        return None
    return link_up, connected


def _sanitize_wifi_ap_entry(raw_id: str, entry: dict[str, Any]) -> dict[str, Any] | None:
    resolved = _resolve_link_connected(entry)
    link_up: bool | None
    connected: bool | None
    if resolved is None:
        link_up = None
        connected = None
    else:
        link_up, connected = resolved
    role_raw = entry.get("role")
    role = role_raw.strip() if isinstance(role_raw, str) else ""
    interface_type_raw = entry.get("type")
    interface_type = interface_type_raw.strip() if isinstance(interface_type_raw, str) else ""
    payload: dict[str, Any] = {
        "interface_id_hash": hash_interface_id(raw_id),
    }
    if role:
        payload["role"] = role
    if interface_type:
        payload["interface_type"] = interface_type
    if link_up is not None:
        payload["link_up"] = link_up
    if connected is not None:
        payload["connected"] = connected
    return sanitize_mapping(payload)


def _extract_wifi_access_points(interface_payload: Any) -> list[dict[str, Any]]:
    if isinstance(interface_payload, dict) and isinstance(interface_payload.get("interface"), list):
        interface_payload = interface_payload["interface"]
    access_points: list[dict[str, Any]] = []
    if isinstance(interface_payload, list):
        for entry in interface_payload:
            if not isinstance(entry, dict):
                continue
            raw_id = entry.get("id")
            if not isinstance(raw_id, str) or not _WIFI_AP_ID_RE.fullmatch(raw_id.strip()):
                continue
            sanitized = _sanitize_wifi_ap_entry(raw_id.strip(), entry)
            if sanitized is not None:
                access_points.append(sanitized)
        return access_points
    if isinstance(interface_payload, dict):
        for key, entry in interface_payload.items():
            if key in {"version", "continued", "status", "message"}:
                continue
            if not isinstance(key, str) or not _WIFI_AP_ID_RE.fullmatch(key.strip()):
                continue
            if not isinstance(entry, dict):
                continue
            sanitized = _sanitize_wifi_ap_entry(key.strip(), entry)
            if sanitized is not None:
                access_points.append(sanitized)
    return access_points


def _derive_findings(
    *,
    firmware_version: str | None,
    ssh_component_installed: bool | None,
    ssh_access_enabled: bool | None,
    wifi_access_points: list[dict[str, Any]],
    interface_fetch_failed: bool,
    components_listing_timeout: bool,
    components_inventory_usable: bool,
    components_inventory_unavailable: bool,
    sandbox: str | None,
    update_channel: str | None,
    component_change_would_upgrade_firmware: bool | None,
    component_change_crosses_major_version: bool | None,
) -> list[str]:
    findings: list[str] = []
    if components_listing_timeout:
        findings.append(FINDING_COMPONENTS_LISTING_TIMEOUT)
    if components_inventory_unavailable:
        findings.append(FINDING_COMPONENTS_INVENTORY_UNAVAILABLE)
    if firmware_version and _firmware_below_verified_baseline(firmware_version):
        findings.append(FINDING_FIRMWARE_BELOW_BASELINE)
    if components_inventory_usable and ssh_component_installed is False:
        findings.append(FINDING_SSH_COMPONENT_MISSING)
    elif ssh_component_installed is True:
        if ssh_access_enabled is False:
            findings.append(FINDING_SSH_DISABLED)
        elif ssh_access_enabled is None:
            findings.append(FINDING_SSH_STATE_UNKNOWN)
    elif ssh_component_installed is None:
        findings.append(FINDING_SSH_STATE_UNKNOWN)
    if interface_fetch_failed or not wifi_access_points:
        findings.append(FINDING_WIFI_INVENTORY_UNAVAILABLE)
    if not components_listing_timeout:
        if sandbox is None:
            findings.append(FINDING_UPDATE_CHANNEL_UNKNOWN)
        elif sandbox != "stable":
            findings.append(FINDING_UPDATE_CHANNEL_NOT_STABLE)
    if component_change_would_upgrade_firmware is True:
        findings.append(FINDING_COMPONENT_CHANGE_TRIGGERS_FIRMWARE_UPGRADE)
    if component_change_crosses_major_version is True:
        findings.append(FINDING_FIRMWARE_MAJOR_VERSION_JUMP)
    return findings


def _validate_bootstrap_policy(
    host: str,
    *,
    allow_insecure_http: bool,
) -> None:
    if not allow_insecure_http:
        raise BootstrapDiscoveryError("allow_insecure_http must be true for bootstrap discovery")
    if not is_expendable_lab_class():
        raise BootstrapDiscoveryError("bootstrap discovery requires expendable lab class")
    try:
        target = parse_transport_target(host)
    except ValueError as exc:
        raise BootstrapDiscoveryError(str(exc)) from exc
    if not _host_is_private(target.hostname):
        raise BootstrapDiscoveryError("bootstrap discovery requires private management host")
    if target.scheme == "http" and not allow_insecure_http:
        raise BootstrapDiscoveryError("plain HTTP requires allow_insecure_http")


def _build_transport(
    *,
    host: str,
    username: str,
    password: str,
    allow_insecure_http: bool,
    http_client: Any | None = None,
) -> NetcrazeTransport:
    target = parse_transport_target(host)
    kwargs: dict[str, Any] = {
        "host": target.hostname,
        "port": target.port,
        "username": username,
        "password": password,
        "use_tls": target.use_tls,
        "allow_insecure_http": allow_insecure_http,
    }
    if http_client is not None:
        kwargs["http_client"] = http_client
    return NetcrazeTransport(**kwargs)


def _fetch_bootstrap_payloads(
    transport: NetcrazeTransport,
) -> tuple[dict[str, Any], set[str], bool]:
    payloads: dict[str, Any] = {}
    absent_reads: set[str] = set()
    components_listing_timeout = False
    for command in _BOOTSTRAP_COMMANDS:
        key = "components" if command is COMPONENTS_LIST else command.name
        try:
            payloads[key] = transport.fetch_discovery_read(command)
        except ContinuationUnsupported:
            if command is COMPONENTS_LIST:
                payloads[key] = None
                components_listing_timeout = True
                continue
            raise BootstrapDiscoveryError(
                f"required bootstrap read continuation failed: {command.name}"
            ) from None
        except FeatureAbsent:
            if command not in _OPTIONAL_BOOTSTRAP_COMMANDS:
                raise BootstrapDiscoveryError(
                    f"required bootstrap read absent: {command.name}"
                ) from None
            payloads[key] = None
            absent_reads.add(key)
        except NetcrazeAdapterError as exc:
            raise BootstrapDiscoveryError(str(exc)) from exc
    return payloads, absent_reads, components_listing_timeout


def run_bootstrap_discovery(
    *,
    host: str,
    username: str,
    credential_ref_id: str,
    vault: CredentialVaultPort,
    allow_insecure_http: bool,
    transport: NetcrazeTransport | None = None,
    http_client: Any | None = None,
) -> dict[str, Any]:
    """Collect sanitized bootstrap discovery report; never logs or returns secrets."""
    _validate_bootstrap_policy(host, allow_insecure_http=allow_insecure_http)
    try:
        password = vault.use(credential_ref_id)
    except Exception as exc:
        raise BootstrapDiscoveryError(
            f"credential resolution failed for credential_ref_id={credential_ref_id}"
        ) from exc

    active_transport = transport
    if active_transport is None:
        active_transport = _build_transport(
            host=host,
            username=username,
            password=password,
            allow_insecure_http=allow_insecure_http,
            http_client=http_client,
        )

    interface_fetch_failed = False
    try:
        raw_payloads, _, components_listing_timeout = _fetch_bootstrap_payloads(
            active_transport
        )
    except BootstrapDiscoveryError:
        raise
    except NetcrazeAdapterError as exc:
        raise BootstrapDiscoveryError(str(exc)) from exc

    system_payload = raw_payloads.get("show_system")
    components_payload = raw_payloads.get("components")
    identification_payload = raw_payloads.get("show_identification")
    version_payload = raw_payloads.get("show_version")
    interface_payload = raw_payloads.get("show_interface")
    ssh_payload = raw_payloads.get("show_ip_ssh")
    http_payload = raw_payloads.get("show_ip_http")

    if components_payload is None and components_listing_timeout:
        components_payload = _synthetic_components_for_identity_timeout(version_payload)

    try:
        identity = parse_identity(
            system_payload,
            components_payload,
            identification_payload=identification_payload,
            version_payload=version_payload,
        )
    except IdentityParseError as exc:
        raise BootstrapDiscoveryError(str(exc)) from exc

    raw_components = raw_payloads.get("components")
    sandbox = _extract_components_sandbox(raw_components)
    update_channel, update_channel_is_stable = _resolve_update_channel(sandbox)
    channel_firmware_version = (
        _extract_channel_firmware_version(raw_components)
        if sandbox is not None
        else None
    )
    installed_for_channel = _installed_firmware_for_channel_assessment(
        identity.firmware_version,
        version_payload,
    )
    would_upgrade, crosses_major, firmware_version_changes = _assess_component_change_firmware(
        installed_firmware=installed_for_channel,
        channel_firmware_version=channel_firmware_version,
    )

    components_inventory = _build_components_inventory(
        raw_components,
        components_listing_timeout=components_listing_timeout,
    )
    ssh_installed, ssh_determination = _resolve_ssh_component_state(
        raw_components,
        components_listing_timeout=components_listing_timeout,
        inventory=components_inventory,
    )
    inventory_usable = _inventory_is_usable(components_inventory)
    inventory_unavailable = _inventory_is_unavailable(components_inventory)
    ssh_enabled = _parse_ssh_access_enabled(ssh_payload)
    management_http = _parse_management_http_summary(http_payload)
    try:
        wifi_aps = _extract_wifi_access_points(interface_payload)
    except Exception:
        interface_fetch_failed = True
        wifi_aps = []

    if interface_payload is None:
        interface_fetch_failed = True

    findings = _derive_findings(
        firmware_version=identity.firmware_version,
        ssh_component_installed=ssh_installed,
        ssh_access_enabled=ssh_enabled,
        wifi_access_points=wifi_aps,
        interface_fetch_failed=interface_fetch_failed,
        components_listing_timeout=components_listing_timeout,
        components_inventory_usable=inventory_usable,
        components_inventory_unavailable=inventory_unavailable,
        sandbox=sandbox,
        update_channel=update_channel,
        component_change_would_upgrade_firmware=would_upgrade,
        component_change_crosses_major_version=crosses_major,
    )

    report = BootstrapDiscoveryReport(
        certification_eligible=False,
        transport_security=active_transport.transport_security_label,
        https_check=active_transport.https_check_label,
        model=identity.model,
        firmware_version=identity.firmware_version,
        firmware_digest=identity.firmware_digest,
        fingerprint_digest=identity.fingerprint_digest,
        component_set_digest=identity.component_set_digest,
        ssh_component_installed=ssh_installed,
        ssh_access_enabled=ssh_enabled,
        management_http=management_http,
        wifi_access_points=tuple(wifi_aps),
        findings=tuple(findings),
        sandbox=sandbox,
        update_channel=update_channel,
        channel_firmware_version=channel_firmware_version,
        component_change_would_upgrade_firmware=would_upgrade,
        component_change_crosses_major_version=crosses_major,
        component_change_firmware_version_changes=firmware_version_changes,
        update_channel_is_stable=update_channel_is_stable,
        components_inventory=components_inventory,
        ssh_component_determination=ssh_determination,
    )
    return report.to_dict()
