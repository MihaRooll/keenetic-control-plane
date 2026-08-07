"""Shared RCI CLI prompt normalization for write-ack verification."""

from __future__ import annotations

from router_control.adapters.netcraze.sanitize import strip_ssh_cli_ansi_artifacts

RCI_PROMPT_CONFIG = "(config)"
RCI_PROMPT_CONFIG_IF = "(config-if)"

_KNOWN_PROMPT_FORMS = frozenset(
    {
        "(config-if)",
        "(config-if)>",
        "(config)",
        "(config)>",
    }
)


def normalize_rci_prompt(prompt: str, *, collapse_config_if: bool = False) -> str:
    """Normalize device RCI prompt to canonical form for allowlist checks.

    Strips ANSI erase-to-EOL suffixes and trailing ``>``. When
    ``collapse_config_if`` is True, ``(config-if)`` variants map to ``(config)``
    (operations that return to global config context). WireGuard interface create
    keeps ``(config-if)`` when ``collapse_config_if`` is False.
    """
    text = strip_ssh_cli_ansi_artifacts(prompt.strip())
    if text not in _KNOWN_PROMPT_FORMS:
        return text
    if text.startswith(RCI_PROMPT_CONFIG_IF):
        return RCI_PROMPT_CONFIG if collapse_config_if else RCI_PROMPT_CONFIG_IF
    if text.endswith(">"):
        return text[:-1]
    return text


def is_allowlisted_rci_prompt(
    prompt: str | None,
    *,
    allowed: frozenset[str],
    collapse_config_if: bool = False,
) -> bool:
    """Return True when ``prompt`` normalizes to an entry in ``allowed``."""
    if not prompt:
        return False
    normalized = normalize_rci_prompt(prompt, collapse_config_if=collapse_config_if)
    return normalized in allowed


__all__ = [
    "RCI_PROMPT_CONFIG",
    "RCI_PROMPT_CONFIG_IF",
    "is_allowlisted_rci_prompt",
    "normalize_rci_prompt",
]
