"""Static contract guards for Overview step-4 compact domain card (offline, no DOM)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
OVERVIEW_JS = HUB / "screens" / "overview.js"
DOMAIN_SIMPLE_PUBLISH_JS = HUB / "features" / "domain-simple-publish.js"
SCREENS_CSS = HUB / "styles" / "screens.css"

DOMAIN_OWNED_START = "/* ==== OVERVIEW STEP CARD: DOMAIN (owned area) ==== */"
DOMAIN_OWNED_END = "/* ==== /OVERVIEW STEP CARD: DOMAIN ==== */"

INTERACTIVE_CLOSEST_FILTER = (
    "event.target.closest('a, button, input, select, textarea, label, [role=\"button\"]')"
)

FORBIDDEN_OVERVIEW_DOMAIN_NEEDLES = (
    "buildDomainStatusCard",
    "domainCardSlot",
    "domainMountSlot",
    "hub-overview__domain-card-slot",
    "hub-overview__domain-mount-slot",
    "renderDomainCardSlot",
)

_DOMAIN_WRAP_GUARD_CLASS_PATTERNS = (
    re.compile(r"\.hub-overview__domain-slot(?![\w-])"),
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
def overview_source() -> str:
    return _read(OVERVIEW_JS)


@pytest.fixture(scope="module")
def simple_publish_source() -> str:
    return _read(DOMAIN_SIMPLE_PUBLISH_JS)


@pytest.fixture(scope="module")
def mount_overview_domain_body(overview_source: str) -> str:
    start = overview_source.find("domainMount = mountDomainSimplePublishAffordance(")
    assert start != -1, "overview domain mount missing"
    end = overview_source.find("entryPagesSlot.appendChild", start)
    assert end != -1, "overview domain mount region end missing"
    return overview_source[start:end]


@pytest.fixture(scope="module")
def domain_slot_setup_region(overview_source: str) -> str:
    start = overview_source.find("const domainWrap = document.createElement('div')")
    assert start != -1, "domainWrap setup missing"
    end_marker = "domainWrap.appendChild(domainSlot)"
    end = overview_source.find(end_marker, start)
    assert end != -1, "domainSlot append missing"
    end = overview_source.find(";", end) + 1
    return overview_source[start:end]


@pytest.fixture(scope="module")
def overview_compact_block(simple_publish_source: str) -> str:
    fn_match = re.search(
        r"export function mountDomainSimplePublishAffordance\([\s\S]*?\n\}",
        simple_publish_source,
    )
    assert fn_match, "mountDomainSimplePublishAffordance must exist"
    return fn_match.group(0)


@pytest.fixture(scope="module")
def wire_navigate_block() -> str:
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    fn_match = re.search(
        r"export function wireOverviewCardNavigate\([\s\S]*?\n\}",
        grid_source,
    )
    assert fn_match, "wireOverviewCardNavigate must exist"
    return fn_match.group(0)


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


def test_overview_uses_single_domain_slot(domain_slot_setup_region: str) -> None:
    assert "domainSlot" in domain_slot_setup_region
    assert "hub-overview__domain-slot" in domain_slot_setup_region
    assert "domainWrap.appendChild(domainSlot)" in domain_slot_setup_region


def test_overview_no_dual_domain_slots(overview_source: str) -> None:
    for needle in FORBIDDEN_OVERVIEW_DOMAIN_NEEDLES:
        assert needle not in overview_source, f"forbidden overview domain needle: {needle!r}"


def test_overview_mounts_compact_variant(
    mount_overview_domain_body: str,
    overview_source: str,
) -> None:
    assert "variant: 'overview'" in mount_overview_domain_body
    assert "navigate: (routeId) => ctx.navigate(routeId)" in mount_overview_domain_body
    assert "openDomainPublishApplyConfirm" in mount_overview_domain_body
    assert "applyKeendnsBooking" in mount_overview_domain_body
    assert "KEENDNS_DEFAULT_ACCESS_MODE" in mount_overview_domain_body
    assert "getRouterBookedFqdn" in mount_overview_domain_body
    assert "resolveKeendnsBookedFqdn" in mount_overview_domain_body
    assert "maybePrefillDomainDraftFromObserve" in overview_source


def test_overview_compact_publish_surface(overview_compact_block: str) -> None:
    assert "variant === 'overview'" in overview_compact_block or "isOverview" in overview_compact_block
    assert "createStepNumberBadge(4)" in overview_compact_block
    assert "label: 'Опубликовать'" in overview_compact_block
    assert "hub-overview__domain-compact-card" in overview_compact_block
    assert "hub-domain__compact-fqdn" in overview_compact_block
    assert "hub-domain__router-default" in overview_compact_block
    assert "getRouterDefaultFqdn" in overview_compact_block
    assert "getRouterBookedFqdn" in overview_compact_block
    assert "DOMAIN_ROUTER_BOOKED_FQDN_LABEL" in overview_compact_block
    assert "hub-domain__router-booked" in overview_compact_block
    assert "KEENDNS_APPLY_DISPATCH_HONESTY" not in overview_compact_block
    assert "hub-overview__quiet-link" in overview_compact_block
    assert "#/domain" in overview_compact_block
    assert "wireOverviewCardNavigate" in overview_compact_block


def test_overview_compact_no_hardcoded_lab_fqdn(
    overview_compact_block: str,
    simple_publish_source: str,
    overview_source: str,
) -> None:
    forbidden = "1880927356f927ebc1b7fa92.netcraze.io"
    for source in (overview_compact_block, simple_publish_source, overview_source):
        assert forbidden not in source, "lab FQDN must not be hardcoded in hub product JS"


def test_overview_compact_hides_legacy_chrome(overview_compact_block: str) -> None:
    # Overview must not mount starter/draft chrome (CSS display:flex overrides HTML hidden).
    assert "if (!isOverview)" in overview_compact_block
    assert "Подставить стартовое имя" in overview_compact_block  # full variant only
    assert overview_compact_block.count("if (!isOverview)") >= 2
    assert "Проверить домен" not in overview_compact_block
    assert "Открыть черновик" not in overview_compact_block
    assert "Облако не проверяется" not in overview_compact_block
    assert "domainCreateCheckTile" not in overview_compact_block


def test_overview_compact_keeps_publish_honesty(
    overview_compact_block: str,
    simple_publish_source: str,
) -> None:
    assert "KEENDNS_APPLY_DISPATCH_HONESTY" not in overview_compact_block
    assert "describeKeendnsApplyOutcome" in simple_publish_source
    assert "openDomainPublishApplyConfirm" in simple_publish_source


def test_domain_owned_css_markers_and_compact_classes(domain_owned_css: str) -> None:
    required_classes = (
        "hub-overview__domain-compact-card",
        "hub-domain__compact-fqdn",
        "hub-domain__compact-honesty",
        "hub-domain__compact-meta",
    )
    for cls in required_classes:
        assert cls in domain_owned_css, f"missing owned CSS class {cls!r}"


def test_domain_owned_css_no_body_island(domain_owned_css: str) -> None:
    assert "max-width: 28rem" not in domain_owned_css
    assert "hub-domain-card__body" not in domain_owned_css


def test_domain_owned_css_forbids_invalid_tokens(domain_owned_css: str) -> None:
    assert "--hub-status-" not in domain_owned_css
    assert "--hub-accent-primary" not in domain_owned_css


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
