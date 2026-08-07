"""Defensive parse of allowlisted Netcraze identity reads."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from router_control.adapters.netcraze.errors import IdentityParseError
from router_control.adapters.netcraze.sanitize import sanitize_mapping

VENDOR_NETCRAZE = "Netcraze"

MODEL_UNKNOWN = "unknown"

SOURCE_OPERATOR_UI_HINT = "operator_ui_hint"
SOURCE_UNKNOWN = "unknown"
SOURCE_RCI_SYSTEM = "rci_system"
SOURCE_RCI_VERSION = "rci_version"
SOURCE_RCI_VERSION_NDM_EXACT = "rci_version_ndm_exact"
SOURCE_RCI_VERSION_BSP_EXACT = "rci_version_bsp_exact"
SOURCE_RCI_VERSION_SANDBOX_UI_MAP = "rci_version_sandbox_ui_map"
SOURCE_RCI_VERSION_DISPLAY = "rci_version_display"
SOURCE_MISSING = "missing"
SOURCE_SHOW_IDENTIFICATION_DIGEST = "show.identification_digest"

SHAPE_LEGACY = "legacy"
SHAPE_OBSERVED = "observed"

COMPONENT_SET_DIGEST_ALGORITHM = "component-set-v2"
COMPONENT_SET_DIGEST_ALGORITHM_LEGACY = "component-set-legacy-list-v1"

FINGERPRINT_STABLE = "stable"
FINGERPRINT_PROVISIONAL = "provisional"

UPDATE_CHANNEL_MAIN = "Main"
SANDBOX_STABLE = "stable"

# Hardware-ID-like token: >=2 ASCII letters, hyphen, digits; non-alphanumeric boundaries.
_HW_ID_TOKEN_PATTERN = re.compile(
    r"(?<![A-Za-z])([A-Za-z]{2,}-[0-9]+)(?![A-Za-z0-9])"
)


def extract_hw_id_tokens(text: str) -> frozenset[str]:
    """Extract bounded hardware-ID-like tokens from display text."""
    return frozenset(_HW_ID_TOKEN_PATTERN.findall(text))


def _digest_canonical(mapping: dict[str, str]) -> str:
    canonical = json.dumps(mapping, sort_keys=True, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _digest_sorted_ids(ids: list[str]) -> str:
    canonical = json.dumps(ids, separators=(",", ":"))
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _digest_physical(value: str, label: str) -> str:
    material = f"{label}:{value}"
    return f"sha256:{hashlib.sha256(material.encode('utf-8')).hexdigest()}"


def _as_mapping(value: Any, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IdentityParseError(f"{label} must be a JSON object")
    return value


def _optional_mapping(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        return None
    return value


def _pick_str(mapping: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = mapping.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _extract_ndm(system: dict[str, Any]) -> dict[str, Any]:
    ndm = system.get("ndm")
    if isinstance(ndm, dict):
        return ndm
    return {}


def _optional_hint(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped if stripped else None


def _nested_exact(payload: dict[str, Any], section: str) -> str | None:
    nested = payload.get(section)
    if not isinstance(nested, dict):
        return None
    return _pick_str(nested, "exact")


def _operator_hint_disagreement(canonical_hw_id: str | None, hint: str | None) -> bool:
    """Operator hint: absent/blank => no disagreement; supplied => exact token set match."""
    if canonical_hw_id is None or not hint:
        return False
    expected = frozenset({canonical_hw_id})
    tokens = extract_hw_id_tokens(hint)
    return tokens != expected


def _display_token_disagreement(canonical_hw_id: str | None, *texts: str | None) -> bool:
    """RCI display metadata may omit tokens; present tokens must exactly match canonical."""
    if canonical_hw_id is None:
        return False
    expected = frozenset({canonical_hw_id})
    for text in texts:
        if not text:
            continue
        tokens = extract_hw_id_tokens(text)
        if tokens and tokens != expected:
            return True
    return False


@dataclass(frozen=True, slots=True)
class _IdentificationFields:
    serial_digest: str | None
    servicetag_digest: str | None
    hwid: str | None


@dataclass(frozen=True, slots=True)
class _VersionFields:
    hw_id: str | None
    version_field: str | None
    release_field: str | None
    ndm_build: str | None
    flat_build: str | None
    bsp_build: str | None
    region: str | None
    sandbox: str | None
    model_display: str | None
    display_texts: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class OperatorIdentityHints:
    """Optional operator-supplied identity hints; never treated as RCI-proven."""

    expected_model: str | None = None
    update_channel: str | None = None

    def normalized(self) -> OperatorIdentityHints:
        return OperatorIdentityHints(
            expected_model=_optional_hint(self.expected_model),
            update_channel=_optional_hint(self.update_channel),
        )

    @property
    def model_source(self) -> str:
        return SOURCE_OPERATOR_UI_HINT if self.expected_model else SOURCE_UNKNOWN

    @property
    def update_channel_source(self) -> str:
        return SOURCE_OPERATOR_UI_HINT if self.update_channel else SOURCE_UNKNOWN


@dataclass(frozen=True, slots=True)
class ParsedIdentity:
    vendor: str
    model: str
    title: str | None
    firmware_version: str
    build: str | None
    update_channel: str | None
    region: str | None
    fingerprint_digest: str
    component_set_digest: str
    firmware_digest: str
    system_raw: dict[str, Any]
    components_raw: Any
    identity_shape: str
    identity_complete: bool
    fingerprint_status: str
    model_source: str
    update_channel_source: str
    build_source: str
    region_source: str
    physical_identifier_source: str
    firmware_sources_agreement: bool | None
    model_disagreement: bool
    firmware_display_title: str | None = None
    model_display: str | None = None
    model_display_source: str = SOURCE_UNKNOWN
    sandbox: str | None = None
    sandbox_source: str = SOURCE_UNKNOWN
    bsp_build: str | None = None
    bsp_build_source: str = SOURCE_UNKNOWN
    component_set_digest_algorithm: str = COMPONENT_SET_DIGEST_ALGORITHM

    @property
    def public_system(self) -> dict[str, Any]:
        if self.identity_shape == SHAPE_OBSERVED:
            return {}
        return sanitize_mapping(dict(self.system_raw))


def parse_identity(
    system_payload: Any,
    components_payload: Any,
    *,
    identification_payload: Any | None = None,
    version_payload: Any | None = None,
    hints: OperatorIdentityHints | None = None,
) -> ParsedIdentity:
    normalized_hints = (hints or OperatorIdentityHints()).normalized()
    observed = _try_parse_observed(
        components_payload,
        identification_payload=identification_payload,
        version_payload=version_payload,
        hints=normalized_hints,
    )
    if observed is not None:
        return observed
    return _parse_legacy(system_payload, components_payload)


def _parse_identification_fields(payload: Any) -> _IdentificationFields:
    mapping = _optional_mapping(payload)
    if mapping is None:
        return _IdentificationFields(None, None, None)
    serial_raw = _pick_str(mapping, "serial")
    servicetag_raw = _pick_str(mapping, "servicetag")
    hwid = _pick_str(mapping, "hwid")
    serial_digest = _digest_physical(serial_raw, "serial") if serial_raw else None
    servicetag_digest = (
        _digest_physical(servicetag_raw, "servicetag") if servicetag_raw else None
    )
    return _IdentificationFields(serial_digest, servicetag_digest, hwid)


def _firmware_sources_agreement(
    components_firmware: str,
    version_field: str | None,
    release_field: str | None,
) -> bool | None:
    if version_field is None and release_field is None:
        return None
    if version_field is not None and release_field is not None:
        if version_field != release_field:
            return False
        return version_field == components_firmware
    sole = version_field if version_field is not None else release_field
    assert sole is not None
    return sole == components_firmware


def _parse_version_fields(payload: Any) -> _VersionFields:
    mapping = _optional_mapping(payload)
    if mapping is None:
        return _VersionFields(None, None, None, None, None, None, None, None, None, ())
    version_field = _pick_str(mapping, "version")
    release_field = _pick_str(mapping, "release")
    hw_id = _pick_str(mapping, "hw_id")
    ndm_build = _nested_exact(mapping, "ndm")
    flat_build = _pick_str(mapping, "build")
    bsp_build = _nested_exact(mapping, "bsp")
    region = _pick_str(mapping, "region")
    sandbox = _pick_str(mapping, "sandbox")
    display_candidates = [
        value
        for value in (
            _pick_str(mapping, "model"),
            _pick_str(mapping, "device"),
            _pick_str(mapping, "description"),
        )
        if value
    ]
    model_display = display_candidates[0] if display_candidates else None
    return _VersionFields(
        hw_id=hw_id,
        version_field=version_field,
        release_field=release_field,
        ndm_build=ndm_build,
        flat_build=flat_build,
        bsp_build=bsp_build,
        region=region,
        sandbox=sandbox,
        model_display=model_display,
        display_texts=tuple(display_candidates),
    )


def _resolve_observed_build(version: _VersionFields) -> tuple[str | None, str]:
    if version.ndm_build:
        return version.ndm_build, SOURCE_RCI_VERSION_NDM_EXACT
    if version.flat_build:
        return version.flat_build, SOURCE_RCI_VERSION
    return None, SOURCE_UNKNOWN


def _resolve_observed_channel(
    version: _VersionFields,
    hints: OperatorIdentityHints,
) -> tuple[str | None, str, str | None, str]:
    sandbox = version.sandbox
    sandbox_source = SOURCE_RCI_VERSION if sandbox else SOURCE_UNKNOWN
    if isinstance(sandbox, str) and sandbox.strip().lower() == SANDBOX_STABLE:
        return UPDATE_CHANNEL_MAIN, SOURCE_RCI_VERSION_SANDBOX_UI_MAP, sandbox, sandbox_source
    if hints.update_channel:
        return hints.update_channel, SOURCE_OPERATOR_UI_HINT, sandbox, sandbox_source
    return None, SOURCE_UNKNOWN, sandbox, sandbox_source


def _try_parse_observed(
    components_payload: Any,
    *,
    identification_payload: Any | None,
    version_payload: Any | None,
    hints: OperatorIdentityHints,
) -> ParsedIdentity | None:
    if not isinstance(components_payload, dict):
        return None
    firmware = components_payload.get("firmware")
    if not isinstance(firmware, dict):
        return None
    raw_version = firmware.get("version")
    if not isinstance(raw_version, str) or raw_version == "":
        return None
    component_map = components_payload.get("component")
    if not isinstance(component_map, dict):
        return None

    display_title = firmware.get("title") if isinstance(firmware.get("title"), str) else None
    installed_ids = _observed_installed_component_ids(component_map)
    if not installed_ids:
        raise IdentityParseError("observed components response has no installed component IDs")
    component_set_digest = _digest_sorted_ids(installed_ids)

    identification = _parse_identification_fields(identification_payload)
    version = _parse_version_fields(version_payload)

    canonical_hw_id = version.hw_id
    if canonical_hw_id:
        model = canonical_hw_id
        model_source = SOURCE_RCI_VERSION
    else:
        model = MODEL_UNKNOWN
        model_source = SOURCE_UNKNOWN

    hwid_disagreement = (
        identification.hwid is not None
        and canonical_hw_id is not None
        and identification.hwid != canonical_hw_id
    )
    hint_disagreement = _operator_hint_disagreement(canonical_hw_id, hints.expected_model)
    display_disagreement = _display_token_disagreement(
        canonical_hw_id,
        *version.display_texts,
    )
    model_disagreement = hwid_disagreement or hint_disagreement or display_disagreement

    update_channel, update_channel_source, sandbox, sandbox_source = _resolve_observed_channel(
        version, hints
    )

    build, build_source = _resolve_observed_build(version)
    region = version.region
    region_source = SOURCE_RCI_VERSION if region else SOURCE_UNKNOWN

    bsp_build = version.bsp_build
    bsp_build_source = SOURCE_RCI_VERSION_BSP_EXACT if bsp_build else SOURCE_UNKNOWN

    model_display = version.model_display
    model_display_source = SOURCE_RCI_VERSION_DISPLAY if model_display else SOURCE_UNKNOWN

    has_both_physical_digests = (
        identification.serial_digest is not None and identification.servicetag_digest is not None
    )
    physical_identifier_source = (
        SOURCE_SHOW_IDENTIFICATION_DIGEST if has_both_physical_digests else SOURCE_MISSING
    )

    firmware_sources_agreement = _firmware_sources_agreement(
        raw_version,
        version.version_field,
        version.release_field,
    )

    claims: dict[str, str] = {
        "vendor": VENDOR_NETCRAZE,
        "release": raw_version,
        "component_set_digest": component_set_digest,
    }
    if canonical_hw_id:
        claims["model"] = canonical_hw_id
    if build:
        claims["build"] = build
    if identification.serial_digest:
        claims["serial_digest"] = identification.serial_digest
    if identification.servicetag_digest:
        claims["servicetag_digest"] = identification.servicetag_digest

    fingerprint_digest = _digest_canonical(claims)
    firmware_digest = _digest_canonical({"release": raw_version})

    identity_complete = (
        has_both_physical_digests
        and canonical_hw_id is not None
        and (identification.hwid is None or identification.hwid == canonical_hw_id)
        and build is not None
        and build_source == SOURCE_RCI_VERSION_NDM_EXACT
        and firmware_sources_agreement is True
        and not model_disagreement
    )
    fingerprint_status = FINGERPRINT_STABLE if identity_complete else FINGERPRINT_PROVISIONAL

    return ParsedIdentity(
        vendor=VENDOR_NETCRAZE,
        model=model,
        title=None,
        firmware_version=raw_version,
        build=build,
        update_channel=update_channel,
        region=region,
        fingerprint_digest=fingerprint_digest,
        component_set_digest=component_set_digest,
        firmware_digest=firmware_digest,
        system_raw={},
        components_raw=components_payload,
        identity_shape=SHAPE_OBSERVED,
        identity_complete=identity_complete,
        fingerprint_status=fingerprint_status,
        model_source=model_source,
        update_channel_source=update_channel_source,
        build_source=build_source,
        region_source=region_source,
        physical_identifier_source=physical_identifier_source,
        firmware_sources_agreement=firmware_sources_agreement,
        model_disagreement=model_disagreement,
        firmware_display_title=display_title,
        model_display=model_display,
        model_display_source=model_display_source,
        sandbox=sandbox,
        sandbox_source=sandbox_source,
        bsp_build=bsp_build,
        bsp_build_source=bsp_build_source,
        component_set_digest_algorithm=COMPONENT_SET_DIGEST_ALGORITHM,
    )


def _parse_legacy(system_payload: Any, components_payload: Any) -> ParsedIdentity:
    system = _as_mapping(system_payload, label="system")
    ndm = _extract_ndm(system)

    model = _pick_str(system, "model", "device") or _pick_str(ndm, "model")
    title = _pick_str(system, "title") or _pick_str(ndm, "title")
    if not model and title:
        model = title
    firmware = _pick_str(system, "release", "firmware", "version") or _pick_str(
        ndm, "release", "firmware", "version"
    )
    if not model or not firmware:
        raise IdentityParseError("system response missing required model or firmware fields")

    build = _pick_str(system, "build") or _pick_str(ndm, "build")
    update_channel = _pick_str(system, "channel", "update_channel") or _pick_str(
        ndm, "channel", "update_channel"
    )

    serial = _pick_str(system, "serial")
    mac = _pick_str(system, "mac", "macaddr", "mac_address")

    claims: dict[str, str] = {
        "vendor": VENDOR_NETCRAZE,
        "model": model,
        "release": firmware,
    }
    if build:
        claims["build"] = build
    if serial:
        claims["serial"] = serial
    if mac:
        claims["mac"] = mac

    component_set_digest = _legacy_component_set_digest(components_payload)
    fingerprint_digest = _digest_canonical(claims)
    firmware_digest = _digest_canonical({"release": firmware})

    return ParsedIdentity(
        vendor=VENDOR_NETCRAZE,
        model=model,
        title=title,
        firmware_version=firmware,
        build=build,
        update_channel=update_channel,
        region=None,
        fingerprint_digest=fingerprint_digest,
        component_set_digest=component_set_digest,
        firmware_digest=firmware_digest,
        system_raw=system,
        components_raw=components_payload,
        identity_shape=SHAPE_LEGACY,
        identity_complete=True,
        fingerprint_status=FINGERPRINT_STABLE,
        model_source=SOURCE_RCI_SYSTEM,
        update_channel_source=SOURCE_RCI_SYSTEM if update_channel else SOURCE_UNKNOWN,
        build_source=SOURCE_RCI_SYSTEM if build else SOURCE_UNKNOWN,
        region_source=SOURCE_UNKNOWN,
        physical_identifier_source=SOURCE_RCI_SYSTEM if serial else SOURCE_MISSING,
        firmware_sources_agreement=None,
        model_disagreement=False,
        firmware_display_title=None,
        component_set_digest_algorithm=COMPONENT_SET_DIGEST_ALGORITHM_LEGACY,
    )


def _parse_installed_flag(value: Any) -> bool | None:
    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        if value == 0:
            return False
        if value == 1:
            return True
        return None
    if isinstance(value, float):
        if value == 0.0:
            return False
        if value == 1.0:
            return True
        return None
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"no", "false", "0", ""}:
            return False
        if text in {"yes", "true", "1", "installed"}:
            return True
        return True
    return None


def _component_map_uses_installed_key_mode(component_map: dict[str, Any]) -> bool:
    for metadata in component_map.values():
        if isinstance(metadata, dict) and "installed" in metadata:
            return True
    return False


def _component_installation_status(metadata: dict[str, Any], *, mode_a: bool) -> bool | None:
    """Return True/False when install status is known; None when metadata shape is unrecognized."""
    if mode_a:
        if "installed" in metadata:
            return _parse_installed_flag(metadata.get("installed"))
        return False
    version = metadata.get("version")
    has_version = isinstance(version, str) and version.strip() != ""
    if metadata.get("available") is True:
        return False
    if has_version:
        return True
    if not metadata:
        return None
    return None


def _observed_installed_component_ids(component_map: dict[str, Any]) -> list[str]:
    mode_a = _component_map_uses_installed_key_mode(component_map)
    installed: list[str] = []
    for comp_id, metadata in component_map.items():
        if not isinstance(comp_id, str):
            continue
        if not isinstance(metadata, dict):
            continue
        status = _component_installation_status(metadata, mode_a=mode_a)
        if status is True:
            installed.append(comp_id)
    if not installed:
        raise IdentityParseError("observed components response has no installed component IDs")
    return sorted(installed)


def _legacy_component_set_digest(components_payload: Any) -> str:
    if components_payload is None:
        raise IdentityParseError("components response missing")
    names = _legacy_component_names(components_payload)
    if not names:
        raise IdentityParseError("components response has no recognizable component names")
    return _digest_sorted_ids(sorted(names))


def _legacy_component_names(payload: Any) -> list[str]:
    names: list[str] = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                name = _pick_str(item, "name", "id", "component")
                if name:
                    names.append(name)
            elif isinstance(item, str) and item.strip():
                names.append(item.strip())
        return names
    if isinstance(payload, dict):
        if isinstance(payload.get("components"), list):
            return _legacy_component_names(payload["components"])
        for key, value in payload.items():
            if key in {"continued", "status", "message"}:
                continue
            if isinstance(value, str) and value.strip():
                names.append(value.strip())
            elif isinstance(value, dict):
                name = _pick_str(value, "name", "id", "component") or key
                names.append(name)
        return names
    raise IdentityParseError("components response has unsupported shape")
