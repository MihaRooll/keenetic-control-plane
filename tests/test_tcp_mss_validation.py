"""Unit tests for TCP MSS PMTU validation (thin module, no allowlist/wireguard_rci deps)."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from router_control.adapters.netcraze.tcp_mss_validation import (
    TCP_MSS_MODE_PMTU,
    validate_tcp_mss_bound,
)

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_validate_tcp_mss_bound_accepts_pmtu_only() -> None:
    assert validate_tcp_mss_bound("pmtu") == TCP_MSS_MODE_PMTU
    assert validate_tcp_mss_bound(" PMTU ") == TCP_MSS_MODE_PMTU


@pytest.mark.parametrize(
    "value",
    ["1280", "auto", "", "pmtu-extra", "numeric"],
)
def test_validate_tcp_mss_bound_rejects_non_pmtu(value: str) -> None:
    with pytest.raises(ValueError, match="pmtu"):
        validate_tcp_mss_bound(value)


def test_tcp_mss_validation_has_no_allowlist_or_wireguard_rci_imports() -> None:
    source = (REPO_ROOT / "router_control/adapters/netcraze/tcp_mss_validation.py").read_text(
        encoding="utf-8"
    )
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert "allowlist" not in alias.name
                assert "wireguard_rci" not in alias.name
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            assert "allowlist" not in module
            assert "wireguard_rci" not in module
