"""KeenDNS/CrazeDNS preview planner tests."""

from __future__ import annotations

import pytest
from router_control.application.keendns_planner import (
    KeenDnsPlannerError,
    compile_keendns_book_preview,
    compile_keendns_drop_preview,
    compile_keendns_preview_intent,
)

_DOC_CITATION = "OPERATOR_KEENDNS_DISCOVERY.md"


def test_book_preview_verification_status() -> None:
    plan = compile_keendns_book_preview("sample-name", "keenetic.link", "auto")
    assert plan.verification_status == "documentation_sourced_unconfirmed"
    assert len(plan.preview_ops) == 1
    op = plan.preview_ops[0]
    assert op.command_text == "ndns book-name sample-name keenetic.link auto"
    assert plan.name == "sample-name"
    assert any(_DOC_CITATION in note for note in op.notes)


def test_drop_preview_command_text() -> None:
    plan = compile_keendns_drop_preview("sample-name", "keenetic.link")
    assert plan.intent_kind == "drop"
    assert plan.preview_ops[0].command_text == "ndns drop-name sample-name keenetic.link"


def test_preview_rejects_underscore_name() -> None:
    with pytest.raises(KeenDnsPlannerError, match="DNS label"):
        compile_keendns_book_preview("sample_name", "keenetic.link", "auto")


def test_preview_rejects_unknown_domain() -> None:
    with pytest.raises(KeenDnsPlannerError, match="accept-list"):
        compile_keendns_book_preview("name", "example.com", "auto")


def test_preview_intent_book_requires_mode() -> None:
    with pytest.raises(KeenDnsPlannerError):
        compile_keendns_preview_intent(
            {"intent_kind": "book", "name": "n", "domain": "keenetic.link"}
        )
