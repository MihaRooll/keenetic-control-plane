"""Simple signed hub_admin cookie (not Hub-parity; prototype only)."""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AuthDecision:
    status_code: int | None  # None = proceed
    code: str | None = None
    message: str | None = None


def hub_admin_password() -> str:
    return os.environ.get("HUB_ADMIN_PASSWORD", "").strip()


def session_secret() -> str:
    # Derive from password when set; prototype-only (document: not Hub-parity)
    pwd = hub_admin_password()
    if not pwd:
        return ""
    return hashlib.sha256(f"rc-proto:{pwd}".encode()).hexdigest()


def mint_hub_admin_cookie(password: str | None = None) -> str:
    pwd = (password if password is not None else hub_admin_password()).strip()
    if not pwd:
        raise ValueError("HUB_ADMIN_PASSWORD empty")
    secret = hashlib.sha256(f"rc-proto:{pwd}".encode()).hexdigest()
    payload = "hub_admin:v1"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def validate_hub_admin_cookie(cookie_value: str | None) -> bool:
    if not cookie_value:
        return False
    secret = session_secret()
    if not secret:
        return False
    try:
        payload, sig = cookie_value.rsplit(".", 1)
    except ValueError:
        return False
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig) and payload == "hub_admin:v1"


def auth_gate(cookie_value: str | None) -> AuthDecision:
    """Auth order: empty password → 503; invalid cookie → 401; else proceed."""
    if not hub_admin_password():
        return AuthDecision(
            status_code=503,
            code="security.configuration_blocked",
            message="HUB_ADMIN_PASSWORD is not configured",
        )
    if not validate_hub_admin_cookie(cookie_value):
        return AuthDecision(
            status_code=401,
            code="auth.required",
            message="Valid hub_admin session required",
        )
    return AuthDecision(status_code=None)
