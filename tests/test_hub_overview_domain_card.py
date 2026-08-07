"""Static contract guards for Overview step-4 domain card (offline, no DOM)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
OVERVIEW_JS = HUB / "screens" / "overview.js"
SCREENS_CSS = HUB / "styles" / "screens.css"

DOMAIN_OWNED_START = "/* ==== OVERVIEW STEP CARD: DOMAIN (owned area) ==== */"
DOMAIN_OWNED_END = "/* ==== /OVERVIEW STEP CARD: DOMAIN ==== */"

INTERACTIVE_CLOSEST_FILTER = (
    "event.target.closest('a, button, input, select, textarea, label, [role=\"button\"]')"
)

FORBIDDEN_DOMAIN_CARD_NEEDLES = (
    "Доступ проверен",
    "Сертификат",
    "probeLocalApplicationHttp",
    "probeLocalApplicationTls",
    "fetch(",
    "--hub-status-",
    "Date.now(",
    "hub-domain-card__body",
    "variant: 'primary'",
)

_DOMAIN_WRAP_GUARD_CLASS_PATTERNS = (
    re.compile(r"\.hub-overview__domain-card-slot(?![\w-])"),
    re.compile(r"\.hub-overview__domain-mount-slot(?![\w-])"),
    re.compile(r"\.hub-overview__domain(?![\w-])"),
)

_FULL_SPAN_GRID_COLUMN = re.compile(r"^1\s*/\s*-1$", re.IGNORECASE)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function_body(source: str, signature: str) -> str | None:
    idx = source.find(signature)
    if idx == -1:
        return None
    brace = source.find("{", idx)
    if brace == -1:
        return None
    depth = 0
    for pos in range(brace, len(source)):
        char = source[pos]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : pos]
    return None


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _parse_css_declarations(block: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for decl in block.split(";"):
        if ":" not in decl:
            continue
        key, value = decl.split(":", 1)
        props[key.strip()] = value.strip()
    return props


def _iter_css_rules(css: str) -> list[tuple[str, dict[str, str]]]:
    """Extract (selector, props) from CSS, including rules inside @media."""
    css = _strip_css_comments(css)
    rules: list[tuple[str, dict[str, str]]] = []

    def walk(text: str, media_prefix: str = "") -> None:
        i = 0
        while i < len(text):
            while i < len(text) and text[i].isspace():
                i += 1
            if i >= len(text):
                break
            if text.startswith("@media", i):
                brace = text.find("{", i)
                if brace == -1:
                    break
                depth = 1
                j = brace + 1
                while j < len(text) and depth > 0:
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                    j += 1
                media_query = text[i:brace].strip()
                inner = text[brace + 1 : j - 1]
                walk(inner, media_prefix=f"{media_prefix}{media_query} ")
                i = j
                continue
            if text[i] == "@":
                brace = text.find("{", i)
                if brace == -1:
                    break
                depth = 1
                j = brace + 1
                while j < len(text) and depth > 0:
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                    j += 1
                i = j
                continue
            brace = text.find("{", i)
            if brace == -1:
                break
            selector = text[i:brace].strip()
            depth = 1
            j = brace + 1
            while j < len(text) and depth > 0:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            block = text[brace + 1 : j - 1]
            if "{" not in selector and selector:
                full_selector = f"{media_prefix}{selector}".strip()
                rules.append((full_selector, _parse_css_declarations(block)))
            i = j

    walk(css)
    return rules


def _selector_part_targets_domain_wrap(part: str) -> bool:
    return any(pattern.search(part) for pattern in _DOMAIN_WRAP_GUARD_CLASS_PATTERNS)


def _rule_selector_targets_domain_wrap(selector: str) -> bool:
    return any(_selector_part_targets_domain_wrap(part.strip()) for part in selector.split(","))


def _declares_full_span_grid_column(props: dict[str, str]) -> bool:
    value = props.get("grid-column")
    if value is None:
        return False
    return bool(_FULL_SPAN_GRID_COLUMN.match(value.strip()))


@pytest.fixture(scope="module")
def grid_source() -> str:
    return _read(OVERVIEW_CARD_GRID_JS)


@pytest.fixture(scope="module")
def overview_source() -> str:
    return _read(OVERVIEW_JS)


@pytest.fixture(scope="module")
def domain_card_block(grid_source: str) -> str:
    start = grid_source.find("export function buildDomainStatusCard")
    fn_match = re.search(
        r"export function buildDomainStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert start != -1, "buildDomainStatusCard missing"
    assert fn_match, "buildDomainStatusCard must exist"
    return grid_source[start:fn_match.end()]


@pytest.fixture(scope="module")
def wire_navigate_block(grid_source: str) -> str:
    fn_match = re.search(
        r"export function wireOverviewCardNavigate\([\s\S]*?\n\}",
        grid_source,
    )
    assert fn_match, "wireOverviewCardNavigate must exist"
    return fn_match.group(0)


@pytest.fixture(scope="module")
def render_domain_body(overview_source: str) -> str:
    body = _extract_function_body(overview_source, "function renderDomainCardSlot(")
    assert body is not None, "renderDomainCardSlot body missing"
    return body


@pytest.fixture(scope="module")
def domain_mount_setup_region(overview_source: str) -> str:
    start = overview_source.find("const domainWrap = document.createElement('div')")
    assert start != -1, "domainWrap setup missing"
    end_marker = "domainWrap.appendChild(domainMountSlot)"
    end = overview_source.find(end_marker, start)
    assert end != -1, "domainMountSlot append missing"
    end = overview_source.find(";", end) + 1
    return overview_source[start:end]


@pytest.fixture(scope="module")
def domain_owned_css() -> str:
    css = _read(SCREENS_CSS)
    start = css.find(DOMAIN_OWNED_START)
    end = css.find(DOMAIN_OWNED_END)
    assert start != -1, "domain owned CSS start marker missing"
    assert end != -1, "domain owned CSS end marker missing"
    assert end > start, "domain owned CSS markers out of order"
    return css[start:end]


@pytest.fixture(scope="module")
def screens_css() -> str:
    return _read(SCREENS_CSS)


def test_domain_card_function_exists(grid_source: str) -> None:
    assert "export function buildDomainStatusCard" in grid_source


def test_domain_card_uses_shared_marketplace_chrome(domain_card_block: str) -> None:
    assert "createOverviewStepCardMain()" in domain_card_block
    assert "createOverviewStepCardActions()" in domain_card_block
    assert "createOverviewStepCardMeta()" in domain_card_block
    assert "hub-overview__quiet-link" in domain_card_block
    assert "Все настройки домена" in domain_card_block
    assert "#/domain" in domain_card_block


def test_domain_card_uses_required_apis(domain_card_block: str) -> None:
    assert "createStepNumberBadge(4)" in domain_card_block
    assert domain_card_block.count("domainCreateCheckTile(") == 2
    assert "wireOverviewCardNavigate" in domain_card_block
    assert "hub-overview__domain-status-card" in domain_card_block
    assert "createIcon('domain'" in domain_card_block or 'createIcon("domain"' in domain_card_block
    assert "createIcon('info'" in domain_card_block or 'createIcon("info"' in domain_card_block
    assert "Не проверено" in domain_card_block
    # Подписи плиток обязаны меняться вместе с состоянием: иконка не должна быть
    # единственным признаком того, что пункт ещё не готов.
    assert "Имя подготовлено" in domain_card_block
    assert "Имя не готово" in domain_card_block
    assert "Событие выбрано" in domain_card_block
    assert "Событие не выбрано" in domain_card_block
    assert "Проверить домен" in domain_card_block
    assert "domainDraftSuffix" in domain_card_block
    assert "validateDomainName" in domain_card_block
    assert "buildDraftUrl" in domain_card_block
    assert "DOMAIN_DRAFT_LINK_NOTE" in domain_card_block


def test_domain_verify_cta_is_secondary(domain_card_block: str) -> None:
    verify_match = re.search(
        r"label:\s*'Проверить домен'[\s\S]*?hub-domain-card__verify",
        domain_card_block,
    )
    assert verify_match, "Verify CTA createButton block missing"
    verify_block = verify_match.group(0)
    assert "variant: 'secondary'" in verify_block


def test_domain_card_forbids_antipatterns(domain_card_block: str) -> None:
    for needle in FORBIDDEN_DOMAIN_CARD_NEEDLES:
        assert needle not in domain_card_block, f"forbidden needle in domain card: {needle!r}"


def test_render_domain_slot_no_sibling_quiet_link(render_domain_body: str) -> None:
    assert "hub-overview__quiet-link" not in render_domain_body
    assert "domainLink" not in render_domain_body
    assert "buildDomainStatusCard" in render_domain_body


def test_domain_owned_css_markers_and_classes(domain_owned_css: str) -> None:
    required_classes = (
        "hub-domain-card__icon-frame",
        "hub-domain-card__checks",
        "hub-domain-card__check-tile",
    )
    for cls in required_classes:
        assert cls in domain_owned_css, f"missing owned CSS class {cls!r}"


def test_domain_owned_css_no_body_island(domain_owned_css: str) -> None:
    assert "max-width: 28rem" not in domain_owned_css
    assert "hub-domain-card__body" not in domain_owned_css


def test_domain_owned_css_forbids_invalid_tokens(domain_owned_css: str) -> None:
    assert "--hub-status-" not in domain_owned_css
    assert "--hub-accent-primary" not in domain_owned_css


def test_domain_wrap_mount_slot_order(domain_mount_setup_region: str) -> None:
    card_idx = domain_mount_setup_region.index("domainWrap.appendChild(domainCardSlot)")
    mount_idx = domain_mount_setup_region.index("domainWrap.appendChild(domainMountSlot)")
    assert card_idx < mount_idx, "domainCardSlot must be appended before domainMountSlot"
    class_card_idx = domain_mount_setup_region.index("hub-overview__domain-card-slot")
    class_mount_idx = domain_mount_setup_region.index("hub-overview__domain-mount-slot")
    assert class_card_idx < class_mount_idx, (
        "hub-overview__domain-card-slot must appear before hub-overview__domain-mount-slot"
    )


def test_domain_wrap_no_full_span_grid_column(screens_css: str) -> None:
    rules = _iter_css_rules(screens_css)
    guarded = [selector for selector, _ in rules if _rule_selector_targets_domain_wrap(selector)]
    assert guarded, "expected CSS rules referencing domain wrap selectors"

    offenders = [
        selector
        for selector, props in rules
        if _rule_selector_targets_domain_wrap(selector) and _declares_full_span_grid_column(props)
    ]
    assert not offenders, (
        "domain wrap selectors must not re-expand overview grid with grid-column: 1 / -1; "
        f"offending rules: {offenders!r}"
    )


def test_domain_grid_item_not_full_span(screens_css: str) -> None:
    match = re.search(
        r"\.hub-overview__grid-item--domain\s*\{[^}]+\}",
        screens_css,
        re.DOTALL,
    )
    assert match is None, "domain grid item must not full-span the overview grid"
    domain_rule = re.search(
        r"\.hub-overview__domain\s*\{[^}]+\}",
        screens_css,
        re.DOTALL,
    )
    assert domain_rule is not None, ".hub-overview__domain rule must exist"
    domain_block = domain_rule.group(0)
    assert "grid-column: 1 / -1" not in domain_block
    assert "grid-column:1/-1" not in domain_block


def test_wire_overview_card_navigate_keydown_interactive_filter(wire_navigate_block: str) -> None:
    assert INTERACTIVE_CLOSEST_FILTER in wire_navigate_block
    click_idx = wire_navigate_block.index("element.addEventListener('click'")
    keydown_idx = wire_navigate_block.index("element.addEventListener('keydown'")
    click_block = wire_navigate_block[click_idx:keydown_idx]
    keydown_block = wire_navigate_block[keydown_idx:]
    assert INTERACTIVE_CLOSEST_FILTER in click_block
    assert INTERACTIVE_CLOSEST_FILTER in keydown_block
    assert "event.target instanceof Element" in click_block
    assert "event.target instanceof Element" in keydown_block
    assert "event.target instanceof HTMLElement" not in wire_navigate_block
    prevent_idx = keydown_block.index("event.preventDefault()")
    closest_idx = keydown_block.index(INTERACTIVE_CLOSEST_FILTER)
    assert closest_idx < prevent_idx, "keydown must filter interactive targets before preventDefault"


def test_domain_card_footer_note_inside_main(domain_card_block: str) -> None:
    assert "main.appendChild(note)" in domain_card_block
    assert "card.appendChild(note)" not in domain_card_block
    main_append_idx = domain_card_block.index("main.appendChild(note)")
    card_append_main_idx = domain_card_block.index("card.appendChild(main)")
    assert main_append_idx < card_append_main_idx, (
        "section.note footer must be appended to __main before card.appendChild(main)"
    )
