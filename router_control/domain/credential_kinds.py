"""Credential kind allowlists for vault PUT and router management binding."""

from __future__ import annotations

CREDENTIAL_PUT_KIND_ALLOWLIST: frozenset[str] = frozenset(
    {
        "RouterManagementPassword",
        "management_password",
        "WifiApPsk",
        "awg_private_key",
        "awg_preshared_key",
        "router_rci",
        "VpnPrivateKey",
    }
)

ROUTER_MANAGEMENT_CREDENTIAL_KINDS: frozenset[str] = frozenset(
    {
        "RouterManagementPassword",
        "management_password",
    }
)


def kind_rebinds_router_management(kind: str) -> bool:
    return kind in ROUTER_MANAGEMENT_CREDENTIAL_KINDS
