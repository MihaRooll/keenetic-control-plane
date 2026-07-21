"""Ban network/socket/subprocess imports in package."""

from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_MODULES = {
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
    "fastapi",
    "sqlite3",
}


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


def test_router_control_has_no_forbidden_imports() -> None:
    root = Path("router_control")
    violations: list[str] = []
    for path in root.rglob("*.py"):
        imports = _imports_in_file(path)
        blocked = imports & FORBIDDEN_MODULES
        if blocked:
            violations.append(f"{path}: {sorted(blocked)}")
    assert not violations, "\n".join(violations)
