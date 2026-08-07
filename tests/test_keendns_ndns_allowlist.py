"""Offline tests for KeenDNS sealed ndns book/drop write allowlist arm."""

from __future__ import annotations

import pytest
from router_control.adapters.netcraze.allowlist import (
    build_sealed_parse_body,
    is_ndns_parse_body,
    is_write_allowlisted,
)

_VALID_BOOK = "ndns book-name sample-name netcraze.pro auto"
_VALID_DROP = "ndns drop-name sample-name keenetic.link"


@pytest.mark.parametrize(
    "command",
    [
        _VALID_BOOK,
        _VALID_DROP,
        "ndns book-name a keenetic.pro cloud",
        "ndns book-name ab netcraze.club direct",
    ],
)
def test_ndns_book_drop_bodies_allowlisted(command: str) -> None:
    body = build_sealed_parse_body(command)
    assert is_ndns_parse_body(body) is True
    assert is_write_allowlisted("POST", "/rci/", body) is True


@pytest.mark.parametrize(
    "command",
    [
        "ndns get-update sample-name netcraze.pro",
        "ndns book-name sample-name netcraze.pro auto extra",
        "ndns book-name sample_name netcraze.pro auto",
        "ndns book-name sample-name example.com auto",
        "ndns drop-name sample-name netcraze.pro trailing",
        "ndns install",
    ],
)
def test_ndns_negative_commands_rejected(command: str) -> None:
    body = build_sealed_parse_body(command)
    assert is_ndns_parse_body(body) is False
    assert is_write_allowlisted("POST", "/rci/", body) is False
