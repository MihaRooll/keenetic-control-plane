"""Ban network/socket/subprocess imports in domain package; allow sqlite3 in persistence/secrets."""

from __future__ import annotations

import ast
from pathlib import Path

NETWORK_FORBIDDEN = {
    "socket",
    "subprocess",
    "urllib",
    "urllib.request",
    "urllib.error",
    "http.client",
    "httpx",
    "requests",
    "aiohttp",
    "ftplib",
    "telnetlib",
}

# FastAPI must never appear inside router_control (host package only)
ALWAYS_FORBIDDEN = NETWORK_FORBIDDEN | {"fastapi"}

# sqlite3 allowed only under persistence and secrets adapters
SQLITE_ALLOWED_PREFIXES = (
    Path("router_control") / "persistence",
    Path("router_control") / "adapters" / "secrets",
)


def _imports_in_file(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            found.add(node.module.split(".")[0])
            found.add(node.module)
    return found


def _sqlite_allowed(path: Path) -> bool:
    try:
        path.relative_to(SQLITE_ALLOWED_PREFIXES[0])
        return True
    except ValueError:
        pass
    try:
        path.relative_to(SQLITE_ALLOWED_PREFIXES[1])
        return True
    except ValueError:
        return False


def test_router_control_has_no_forbidden_imports() -> None:
    root = Path("router_control")
    violations: list[str] = []
    for path in root.rglob("*.py"):
        imports = _imports_in_file(path)
        blocked = imports & ALWAYS_FORBIDDEN
        if "sqlite3" in imports and not _sqlite_allowed(path):
            blocked = set(blocked) | {"sqlite3"}
        if blocked:
            violations.append(f"{path}: {sorted(blocked)}")
    assert not violations, "\n".join(violations)
