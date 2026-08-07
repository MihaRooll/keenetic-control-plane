"""Adapter-local transport and parse errors for Netcraze read-only transport."""

from __future__ import annotations


class NetcrazeAdapterError(Exception):
    """Base adapter error."""


class AllowlistViolation(NetcrazeAdapterError):
    """Attempt to call a non-allowlisted RCI path."""


class TransportTimeout(NetcrazeAdapterError):
    """Connect or read timeout exceeded."""


class AuthFailed(NetcrazeAdapterError):
    """Digest authentication failed after retry."""


class TransportError(NetcrazeAdapterError):
    """Non-auth HTTP or protocol failure."""


class FeatureAbsent(NetcrazeAdapterError):
    """Optional bootstrap read indicates feature or component is not present (e.g. HTTP 404)."""


class ContinuationUnsupported(NetcrazeAdapterError):
    """Response continued beyond bounded poll policy."""


class IdentityParseError(NetcrazeAdapterError):
    """System/components payload missing required identity fields."""


class SshTunnelError(NetcrazeAdapterError):
    """Pinned SSH tunnel setup or teardown failure."""


class SshParamikoMissing(SshTunnelError):
    """Paramiko optional dependency not installed."""


class SshHostKeyMissing(SshTunnelError):
    """Required SSH host key fingerprint pin is missing."""


class SshHostKeyMismatch(SshTunnelError):
    """SSH host key fingerprint does not match pinned value."""


class SshHostKeyUnsupported(SshTunnelError):
    """SSH host key type is not supported for pin comparison."""


class SshHostNotPrivate(SshTunnelError):
    """SSH endpoint hostname is outside private address ranges."""


class SshTransientConnectionError(SshTunnelError):
    """Transient connect/handshake failure (e.g. reset banner, slow first negotiation) —
    safe to retry automatically; never raised for identity/auth/bind failures."""
