"""Event preset domain tests."""

from __future__ import annotations

from router_control.domain.event_preset import (
    ValidationStatus,
    build_safe_default_document,
    derive_readiness_status,
    document_to_revision_fields,
    validate_document,
)
from router_control.domain.network_intents import BlockingFor, FindingSeverity, ReadinessFinding


def test_safe_default_factory() -> None:
    doc = build_safe_default_document()
    assert doc.uplink.mode.value == "Ethernet"
    assert doc.router_owns_l3 is True
    guest = next(z for z in doc.zones if z.zone_id.value == "Guest")
    assert guest.wifi is not None
    assert guest.wifi.enabled is False
    assert len(doc.zones) == 4


def test_document_to_revision_fields() -> None:
    doc = build_safe_default_document()
    canonical, digest = document_to_revision_fields(doc)
    assert digest.startswith("sha256:")
    assert "created_at" not in canonical


def test_derive_readiness_status_ready() -> None:
    status, _ = validate_document(build_safe_default_document())
    assert status == ValidationStatus.VALID_OFFLINE
    derived = derive_readiness_status(status, [])
    assert derived == ValidationStatus.READY_FOR_READ_ONLY_ASSESSMENT


def test_derive_readiness_invalid_on_blockers() -> None:
    findings = [
        ReadinessFinding(
            code="x",
            severity=FindingSeverity.ERROR,
            blocking_for=BlockingFor.VALIDATION,
            summary_redacted="blocked",
        )
    ]
    derived = derive_readiness_status(ValidationStatus.VALID_OFFLINE, findings)
    assert derived == ValidationStatus.INVALID
