"""UI event-preset editor → domain parse roundtrip guard (AC-E3)."""

from __future__ import annotations

import copy

import pytest
from router_control.domain.network_intents import IntentValidationError, parse_event_preset_document

from tests.test_config_ui import _run_ui_dom_runtime


def _build_doc_from_ui() -> dict:
    script = r"""
const bootstrap = uiExports.buildPresetBootstrapDocument();
const ui = uiExports.buildPresetEditorFormSurface(bootstrap);
document.body.appendChild(ui.form);
const doc = uiExports.buildPresetDocumentFromForm(ui.form, bootstrap);
console.log(JSON.stringify({ ok: true, zone_ids: doc.zones.map((z) => z.zone_id).sort() }));
"""
    result = _run_ui_dom_runtime(script)
    assert result["ok"] is True
    assert result["zone_ids"] == ["AdminServer", "Guest", "Promo", "Staff"]
    script2 = r"""
const bootstrap = uiExports.buildPresetBootstrapDocument();
const ui = uiExports.buildPresetEditorFormSurface(bootstrap);
document.body.appendChild(ui.form);
const doc = uiExports.buildPresetDocumentFromForm(ui.form, bootstrap);
console.log(JSON.stringify(doc));
"""
    return _run_ui_dom_runtime(script2)


def test_ui_preset_document_parses_in_domain() -> None:
    doc = _build_doc_from_ui()
    parsed = parse_event_preset_document(doc)
    assert parsed.name
    assert len(parsed.zones) == 4
    admin = next(z for z in parsed.zones if z.zone_id.value == "AdminServer")
    assert admin.management_allowed is True


def test_ui_preset_guard_red_admin_zone_id_fails_parse() -> None:
    """Red: breaking AdminServer → Admin must fail domain parse."""
    doc = _build_doc_from_ui()
    broken = copy.deepcopy(doc)
    for zone in broken["zones"]:
        if zone["zone_id"] == "AdminServer":
            zone["zone_id"] = "Admin"
    with pytest.raises(IntentValidationError):
        parse_event_preset_document(broken)


def test_ui_preset_guard_red_missing_ipv6_fails_parse() -> None:
    doc = _build_doc_from_ui()
    broken = copy.deepcopy(doc)
    broken["zones"][0].pop("ipv6_posture")
    with pytest.raises(IntentValidationError, match="ipv6"):
        parse_event_preset_document(broken)
