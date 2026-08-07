"""Guard: SVG nodes from createElementNS must not use .className assignment."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"

CREATE_ELEMENT_NS_BIND = re.compile(
    r"\b(?:const|let|var)\s+(\w+)\s*=\s*document\.createElementNS\s*\(",
    re.MULTILINE,
)
CREATE_ELEMENT_BIND = re.compile(
    r"\b(\w+)\s*=\s*document\.createElement\s*\(",
    re.MULTILINE,
)
DECLARATION_PREFIX = re.compile(r"\b(?:const|let|var)\s*$")
CLASSNAME_ASSIGN = re.compile(
    r"\b(\w+)(?:\.className\s*=|\[\s*['\"]className['\"]\s*\]\s*=)"
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _strip_js_comments(text: str) -> str:
    """Remove // and /* */ comments; preserve newlines for line numbers."""
    result: list[str] = []
    i = 0
    n = len(text)
    in_line_comment = False
    in_block_comment = False
    in_string: str | None = None

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                result.append(ch)
            i += 1
            continue

        if in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                i += 2
            else:
                if ch == "\n":
                    result.append(ch)
                i += 1
            continue

        if in_string:
            result.append(ch)
            if ch == "\\" and i + 1 < n:
                result.append(text[i + 1])
                i += 2
                continue
            if ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in ("'", '"', "`"):
            in_string = ch
            result.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            in_line_comment = True
            i += 2
            continue

        if ch == "/" and nxt == "*":
            in_block_comment = True
            i += 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def _svg_bound_names(source: str) -> set[str]:
    """Names bound via createElementNS that were not later rebound."""
    stripped = _strip_js_comments(source)
    bound: set[str] = set()

    for line in stripped.splitlines():
        for match in CREATE_ELEMENT_NS_BIND.finditer(line):
            bound.add(match.group(1))

        for match in CREATE_ELEMENT_BIND.finditer(line):
            bound.discard(match.group(1))

        for match in re.finditer(r"\b(\w+)\s*=\s*", line):
            name = match.group(1)
            if name not in bound:
                continue
            prefix = line[: match.start()]
            if DECLARATION_PREFIX.search(prefix):
                continue
            if "document.createElementNS" in line[match.end() :]:
                continue
            bound.discard(name)

    return bound


def _find_svg_classname_violations(source: str, *, rel_path: str) -> list[str]:
    stripped = _strip_js_comments(source)
    bound_names = _svg_bound_names(source)
    violations: list[str] = []

    for line_no, line in enumerate(stripped.splitlines(), start=1):
        for match in CLASSNAME_ASSIGN.finditer(line):
            var_name = match.group(1)
            if var_name in bound_names:
                violations.append(
                    f"{rel_path}:{line_no}: {var_name}.className = on createElementNS SVG node"
                )

    return violations


def _collect_hub_svg_classname_violations() -> list[str]:
    violations: list[str] = []
    for path in sorted(HUB.rglob("*.js")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        violations.extend(_find_svg_classname_violations(_read(path), rel_path=rel))
    return violations


def test_hub_svg_nodes_never_assign_class_name_property() -> None:
    """createElementNS bindings + later NAME.className = are forbidden hub-wide."""
    violations = _collect_hub_svg_classname_violations()
    assert violations == [], "SVG .className assignments:\n" + "\n".join(violations)


def test_detector_catches_svg_classname_violation_in_planted_snippet() -> None:
    planted = """
const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
svg.className = 'hub-bad-svg';
"""
    hits = _find_svg_classname_violations(planted, rel_path="planted.js")
    assert hits == ["planted.js:3: svg.className = on createElementNS SVG node"]


def test_detector_allows_html_create_element_classname() -> None:
    html_ok = """
const row = document.createElement('div');
row.className = 'hub-row';
"""
    assert _find_svg_classname_violations(html_ok, rel_path="html.js") == []


def test_detector_allows_svg_set_attribute_and_class_list() -> None:
    svg_ok = """
const circle = document.createElementNS(SVG_NS, 'circle');
circle.setAttribute('class', 'hub-ring__track');
circle.classList.add('hub-ring__track');
"""
    assert _find_svg_classname_violations(svg_ok, rel_path="svg-ok.js") == []


def test_detector_ignores_commented_classname_assignment() -> None:
    commented = """
const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
// svg.className = 'hub-bad-svg';
"""
    assert _find_svg_classname_violations(commented, rel_path="commented.js") == []


def test_detector_allows_rebind_to_html_before_classname_assignment() -> None:
    rebound = """
let svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
svg = document.createElement('div');
svg.className = 'hub-row';
"""
    assert _find_svg_classname_violations(rebound, rel_path="rebound.js") == []


def test_detector_catches_classname_without_rebind() -> None:
    no_rebind = """
const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
svg.className = 'hub-bad-svg';
"""
    hits = _find_svg_classname_violations(no_rebind, rel_path="no-rebind.js")
    assert hits == ["no-rebind.js:3: svg.className = on createElementNS SVG node"]


def test_detector_catches_bracket_classname_assignment() -> None:
    bracket = """
const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
svg['className'] = 'hub-bad-svg';
"""
    hits = _find_svg_classname_violations(bracket, rel_path="bracket.js")
    assert hits == ["bracket.js:3: svg.className = on createElementNS SVG node"]
