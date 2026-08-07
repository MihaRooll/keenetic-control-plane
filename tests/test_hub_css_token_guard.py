"""Guard: все --hub-* CSS custom properties ссылаются на SSOT tokens.css."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
TOKENS_CSS = HUB / "styles" / "tokens.css"
STYLES_DIR = HUB / "styles"

HUB_VAR_DECL = re.compile(r"(--hub-[a-zA-Z0-9-]+)\s*:")
HUB_VAR_TOKEN = re.compile(r"--hub-[a-zA-Z0-9-]+")
FORBIDDEN_PREFIXES = ("--hub-status-", "--hub-accent-")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_hub_token_declarations(tokens_css: str) -> set[str]:
    return set(HUB_VAR_DECL.findall(tokens_css))


def _is_forbidden_hub_token(name: str) -> bool:
    return name.startswith(FORBIDDEN_PREFIXES)


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


def _strip_css_comments(text: str) -> str:
    """Remove /* */ comments; preserve newlines for line numbers."""
    result: list[str] = []
    i = 0
    n = len(text)
    in_comment = False

    while i < n:
        ch = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if in_comment:
            if ch == "*" and nxt == "/":
                in_comment = False
                i += 2
            else:
                if ch == "\n":
                    result.append(ch)
                i += 1
            continue

        if ch == "/" and nxt == "*":
            in_comment = True
            i += 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def _strip_comments(text: str, *, is_css: bool) -> str:
    if is_css:
        return _strip_css_comments(text)
    return _strip_js_comments(text)


def _scan_text_for_hub_var_violations(
    text: str,
    *,
    global_tokens: set[str],
    rel_path: str,
    is_css: bool = True,
) -> list[str]:
    """Return file:line:token messages for unknown or forbidden --hub-* usages."""
    stripped = _strip_comments(text, is_css=is_css)
    local_tokens = set(HUB_VAR_DECL.findall(stripped)) if is_css else set()
    allowed = global_tokens | local_tokens
    violations: list[str] = []

    for line_no, line in enumerate(stripped.splitlines(), start=1):
        for match in HUB_VAR_TOKEN.finditer(line):
            token = match.group(0)
            rest = line[match.end() :].lstrip()
            is_declaration = is_css and rest.startswith(":")

            if _is_forbidden_hub_token(token):
                violations.append(f"{rel_path}:{line_no}: forbidden token {token}")
                continue

            if is_declaration:
                continue

            if token not in allowed:
                violations.append(f"{rel_path}:{line_no}: unknown token {token}")

    return violations


def _collect_hub_var_violations(global_tokens: set[str]) -> list[str]:
    violations: list[str] = []

    for path in sorted(STYLES_DIR.glob("*.css")):
        if path.name == "tokens.css":
            continue
        rel = path.relative_to(REPO_ROOT).as_posix()
        violations.extend(
            _scan_text_for_hub_var_violations(
                _read(path),
                global_tokens=global_tokens,
                rel_path=rel,
                is_css=True,
            )
        )

    for path in sorted(HUB.rglob("*.js")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        violations.extend(
            _scan_text_for_hub_var_violations(
                _read(path),
                global_tokens=global_tokens,
                rel_path=rel,
                is_css=False,
            )
        )

    return violations


def test_hub_css_tokens_reference_ssot_only() -> None:
    """Все --hub-* в styles/*.css и hub/**/*.js должны быть объявлены в tokens.css или локально."""
    global_tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    violations = _collect_hub_var_violations(global_tokens)
    assert violations == [], "Unknown or forbidden --hub-* tokens:\n" + "\n".join(violations)


def test_detector_unknown_css_variable_catches_violation() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    bad_css = ".x { border-radius: var(--hub-radius-md); }"
    hits = _scan_text_for_hub_var_violations(
        bad_css, global_tokens=tokens, rel_path="bad.css", is_css=True
    )
    assert hits == ["bad.css:1: unknown token --hub-radius-md"]


def test_detector_var_with_fallback_catches_unknown_token() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    bad_css = ".x { color: var(--hub-font-title-sm, var(--hub-text-primary)); }"
    hits = _scan_text_for_hub_var_violations(
        bad_css, global_tokens=tokens, rel_path="bad.css", is_css=True
    )
    assert any("--hub-font-title-sm" in hit for hit in hits)


def test_detector_nested_var_with_fallback_is_allowed_when_tokens_exist() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    good_css = ".x { color: var(--hub-state-tone-fill, var(--hub-state-tone)); }"
    local = (
        ":root { --hub-state-tone: var(--hub-color-primary); "
        "--hub-state-tone-fill: var(--hub-color-primary); }"
    )
    hits = _scan_text_for_hub_var_violations(
        local + good_css,
        global_tokens=tokens,
        rel_path="states-like.css",
        is_css=True,
    )
    assert hits == []


def test_detector_forbidden_prefix_catches_status_and_accent() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    for token in ("--hub-status-ok", "--hub-accent-primary"):
        css = f".x {{ color: var({token}); }}"
        hits = _scan_text_for_hub_var_violations(
            css, global_tokens=tokens, rel_path="bad.css", is_css=True
        )
        assert any("forbidden token" in hit and token in hit for hit in hits)


def test_detector_bem_class_names_do_not_trigger_forbidden_prefix() -> None:
    """`.hub-status-card` — BEM-класс, не custom property."""
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    css = ".hub-status-card { color: var(--hub-text-primary); }"
    hits = _scan_text_for_hub_var_violations(
        css, global_tokens=tokens, rel_path="ok.css", is_css=True
    )
    assert hits == []


def test_detector_known_token_passes() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    good_css = ".x { border-radius: var(--hub-radius-card); font-size: var(--hub-font-h2); }"
    hits = _scan_text_for_hub_var_violations(
        good_css, global_tokens=tokens, rel_path="ok.css", is_css=True
    )
    assert hits == []


def test_detector_ignores_commented_tokens_but_catches_live_ones() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    commented_css = """
/* var(--hub-totally-fake) */
.x { color: red; }
"""
    live = ".x { border-radius: var(--hub-totally-fake); }"
    assert (
        _scan_text_for_hub_var_violations(
            commented_css, global_tokens=tokens, rel_path="bad.css", is_css=True
        )
        == []
    )
    hits = _scan_text_for_hub_var_violations(
        live, global_tokens=tokens, rel_path="bad.css", is_css=True
    )
    assert hits == ["bad.css:1: unknown token --hub-totally-fake"]


def test_detector_ignores_js_line_comments() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    commented_js = """
// var(--hub-totally-fake)
el.style.color = 'red';
"""
    assert (
        _scan_text_for_hub_var_violations(
            commented_js, global_tokens=tokens, rel_path="bad.js", is_css=False
        )
        == []
    )


def test_detector_js_csstext_usage_is_not_treated_as_local_declaration() -> None:
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    js = "el.style.cssText = '--hub-totally-fake: 1px';"
    hits = _scan_text_for_hub_var_violations(
        js, global_tokens=tokens, rel_path="bad.js", is_css=False
    )
    assert hits == ["bad.js:1: unknown token --hub-totally-fake"]
