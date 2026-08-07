"""Hub admin password from environment — repo forbids credential literals in code."""

from __future__ import annotations

import os
import sys

_ENV_VAR = "HUB_ADMIN_PASSWORD"
_MISSING_MSG = f"Set {_ENV_VAR} in the shell before running this script."


def require_hub_admin_password() -> str:
    """Return HUB_ADMIN_PASSWORD or exit non-zero with an actionable message."""
    value = os.environ.get(_ENV_VAR)
    if not value:
        print(_MISSING_MSG, file=sys.stderr)
        raise SystemExit(1)
    return value


def resolve_hub_admin_password(cli_password: str | None = None) -> str:
    """CLI override wins; otherwise require HUB_ADMIN_PASSWORD from the environment."""
    if cli_password:
        return cli_password
    return require_hub_admin_password()
