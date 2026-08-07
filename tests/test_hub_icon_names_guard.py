"""Static guard: every icon name used in the hub actually exists.

``createIcon(name, …)`` in ``components/icon.js`` silently falls back to an empty
grey circle for any unknown ``name`` — there is no console error, no thrown
exception, nothing an operator or a DOM-less test would ever see. The only
way to catch a typo'd icon name is a static string scan against the real
registry, which is what this file does.

``core/states.js`` intentionally owns a SEPARATE icon namespace (14 large
illustrative state icons with their own ``ICON_BUILDERS``, unrelated to
``components/icon.js``'s small navigational ``ICON_NAMES``) — checked against
its own registry, not ``ICON_NAMES``.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
ICON_JS = HUB / "components" / "icon.js"
STATES_JS = HUB / "core" / "states.js"

# core/states.js has its own separate icon system (ICON_BUILDERS) — excluded
# from the ICON_NAMES scan below and checked separately.
EXCLUDE_FROM_ICON_NAMES_SCAN = frozenset({STATES_JS})

CREATE_ICON_LITERAL_RE = re.compile(r"createIcon\(\s*['\"]([\w-]+)['\"]")
ICON_NAME_FIELD_RE = re.compile(r"iconName:\s*['\"]([\w-]+)['\"]")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_icon_names() -> frozenset[str]:
    source = _read(ICON_JS)
    match = re.search(r"export const ICON_NAMES = Object\.freeze\(\[([\s\S]*?)\]\)", source)
    assert match, "ICON_NAMES array not found in icon.js"
    names = re.findall(r"['\"]([\w-]+)['\"]", match.group(1))
    assert names, "ICON_NAMES parsed empty — regex likely stale"
    return frozenset(names)


def _extract_icon_defs_keys() -> frozenset[str]:
    source = _read(ICON_JS)
    match = re.search(r"const ICON_DEFS = \{([\s\S]*?)\n\};", source)
    assert match, "ICON_DEFS object not found in icon.js"
    body = match.group(1)
    # Top-level keys only: bare identifier or quoted string, immediately followed by ": {"
    keys = re.findall(r"(?:^|\n)\s*(?:['\"]([\w-]+)['\"]|([\w-]+)):\s*\{", body)
    resolved = frozenset(quoted or bare for quoted, bare in keys)
    assert resolved, "ICON_DEFS keys parsed empty — regex likely stale"
    return resolved


def _extract_state_icon_names() -> frozenset[str]:
    source = _read(STATES_JS)
    match = re.search(r"const ICON_BUILDERS = Object\.freeze\(\{([\s\S]*?)\n\}\);", source)
    assert match, "ICON_BUILDERS object not found in states.js"
    keys = re.findall(r"(?:^|\n)\s*(?:['\"]([\w-]+)['\"]|([\w-]+)):\s*\(\)", match.group(1))
    resolved = frozenset(quoted or bare for quoted, bare in keys)
    assert resolved, "ICON_BUILDERS keys parsed empty — regex likely stale"
    return resolved


def _extract_state_descriptor_icon_names() -> frozenset[str]:
    source = _read(STATES_JS)
    match = re.search(
        r"export const STATE_DESCRIPTORS = Object\.freeze\(\{([\s\S]*?)\n\}\);", source
    )
    assert match, "STATE_DESCRIPTORS object not found in states.js"
    return frozenset(ICON_NAME_FIELD_RE.findall(match.group(1)))


def _iter_hub_js_files() -> list[Path]:
    return sorted(p for p in HUB.rglob("*.js"))


def test_icon_names_and_defs_are_in_sync() -> None:
    """ICON_NAMES and ICON_DEFS must be exactly the same set — no gaps either way."""
    names = _extract_icon_names()
    defs = _extract_icon_defs_keys()
    missing_defs = names - defs
    orphan_defs = defs - names
    assert not missing_defs, (
        "ICON_NAMES lists names with no ICON_DEFS entry (silent circle fallback): "
        f"{sorted(missing_defs)}"
    )
    assert not orphan_defs, f"ICON_DEFS has entries not listed in ICON_NAMES: {sorted(orphan_defs)}"


def test_no_hub_file_references_an_unknown_icon_name() -> None:
    """Scan every literal ``createIcon('x', …)`` and ``iconName: 'x'`` across the hub.

    A name outside ``ICON_NAMES`` renders as an empty grey circle with zero
    console error — this is the only static oracle for that failure class.
    """
    icon_names = _extract_icon_names()
    violations: list[str] = []
    for path in _iter_hub_js_files():
        if path in EXCLUDE_FROM_ICON_NAMES_SCAN:
            continue
        source = _read(path)
        rel = path.relative_to(REPO_ROOT)
        for match in CREATE_ICON_LITERAL_RE.finditer(source):
            name = match.group(1)
            if name not in icon_names:
                line_no = source.count("\n", 0, match.start()) + 1
                violations.append(f"{rel}:{line_no}: createIcon('{name}', …) — unknown icon name")
        for match in ICON_NAME_FIELD_RE.finditer(source):
            name = match.group(1)
            if name not in icon_names:
                line_no = source.count("\n", 0, match.start()) + 1
                violations.append(f"{rel}:{line_no}: iconName: '{name}' — unknown icon name")
    assert violations == [], "\n".join(violations)


def test_no_hub_file_references_an_unknown_icon_name_catches_planted_typo() -> None:
    """Sensitivity check: the scan above must actually catch a typo, not just pass vacuously."""
    icon_names = _extract_icon_names()
    broken_source = "createIcon('rotuer', { size: 16 });"
    violations = [
        name
        for match in CREATE_ICON_LITERAL_RE.finditer(broken_source)
        if (name := match.group(1)) not in icon_names
    ]
    assert violations == ["rotuer"], "planted typo was not detected — scan is not sensitive"


def test_state_descriptors_icon_names_match_icon_builders() -> None:
    """core/states.js owns its own separate icon namespace — check it against itself."""
    descriptor_names = _extract_state_descriptor_icon_names()
    builder_names = _extract_state_icon_names()
    assert descriptor_names, "no iconName fields found in STATE_DESCRIPTORS — parser likely stale"
    missing_builders = descriptor_names - builder_names
    assert not missing_builders, (
        "STATE_DESCRIPTORS reference iconName(s) with no ICON_BUILDERS entry: "
        f"{sorted(missing_builders)}"
    )
