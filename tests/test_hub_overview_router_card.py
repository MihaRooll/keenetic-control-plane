"""Static contract guards for Overview step-1 router card (offline, no DOM)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
SCREENS_CSS = HUB / "styles" / "screens.css"

ROUTER_OWNED_START = "/* ==== OVERVIEW STEP CARD: ROUTER (owned area) ==== */"
ROUTER_OWNED_END = "/* ==== /OVERVIEW STEP CARD: ROUTER ==== */"

FORBIDDEN_ROUTER_CARD_NEEDLES = (
    "dBm",
    "Date.now(",
    "<select",
    "createElement('select'",
)


@pytest.fixture(scope="module")
def grid_source() -> str:
    return OVERVIEW_CARD_GRID_JS.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def router_card_block(grid_source: str) -> str:
    start = grid_source.find("const ROUTER_CHECK_TILE_LABELS")
    fn_match = re.search(
        r"export function buildRouterConnectionStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert start != -1, "router card helpers block missing"
    assert fn_match, "buildRouterConnectionStatusCard must exist"
    return grid_source[start:fn_match.end()]


@pytest.fixture(scope="module")
def router_owned_css() -> str:
    css = SCREENS_CSS.read_text(encoding="utf-8")
    start = css.find(ROUTER_OWNED_START)
    end = css.find(ROUTER_OWNED_END)
    assert start != -1, "router owned CSS start marker missing"
    assert end != -1, "router owned CSS end marker missing"
    assert end > start, "router owned CSS markers out of order"
    return css[start:end]


def test_router_card_function_exists(grid_source: str) -> None:
    assert "export function buildRouterConnectionStatusCard" in grid_source


def test_router_card_uses_required_apis(router_card_block: str) -> None:
    assert "mapHealthFactsToRouterPills" in router_card_block
    assert "checkedAt" in router_card_block
    assert "createIcon('router'" in router_card_block or "createIcon(\"router\"" in router_card_block
    assert "createIcon('info'" in router_card_block or "createIcon(\"info\"" in router_card_block
    assert "wireOverviewCardNavigate" in router_card_block
    assert "hub-overview__router-status-card" in router_card_block
    assert "Сменить роутер" in router_card_block


def test_router_card_time_format_ru_locale(router_card_block: str) -> None:
    assert "toLocaleTimeString('ru-RU'" in router_card_block or 'toLocaleTimeString("ru-RU"' in router_card_block


def test_router_card_operator_tile_labels(router_card_block: str) -> None:
    assert "Роутер отвечает" in router_card_block
    assert "Доступ сохранён" in router_card_block
    assert "Устройство совпадает" in router_card_block


def test_router_card_forbids_antipatterns(router_card_block: str) -> None:
    for needle in FORBIDDEN_ROUTER_CARD_NEEDLES:
        assert needle not in router_card_block, f"forbidden needle in router card: {needle!r}"


def test_router_owned_css_markers_and_classes(router_owned_css: str) -> None:
    required_classes = (
        "hub-router-card__icon-frame",
        "hub-router-card__checks",
        "hub-router-card__check-tile",
        "hub-router-card__change",
    )
    for cls in required_classes:
        assert cls in router_owned_css, f"missing owned CSS class {cls!r}"


def test_router_owned_css_forbids_invalid_tokens(router_owned_css: str) -> None:
    assert "--hub-status-" not in router_owned_css
    assert "--hub-accent-primary" not in router_owned_css


@pytest.fixture(scope="module")
def router_create_check_tile_block(router_card_block: str) -> str:
    match = re.search(
        r"function routerCreateCheckTile\([\s\S]*?\n\}",
        router_card_block,
    )
    assert match, "routerCreateCheckTile must exist"
    return match.group(0)


@pytest.fixture(scope="module")
def router_create_checked_at_tile_block(router_card_block: str) -> str:
    match = re.search(
        r"function routerCreateCheckedAtTile\([\s\S]*?\n\}",
        router_card_block,
    )
    assert match, "routerCreateCheckedAtTile must exist"
    return match.group(0)


def test_router_check_tile_null_value_is_honest_unknown(
    router_create_check_tile_block: str,
) -> None:
    assert "неизвестно" in router_create_check_tile_block
    assert "pill.value === true" in router_create_check_tile_block or "pill.value === false" in router_create_check_tile_block
    assert "hub-router-card__check-tile--unknown" in router_create_check_tile_block
    assert "hub-router-card__check-label--muted" in router_create_check_tile_block
    assert "isUnknown" in router_create_check_tile_block or "pill.value !== true" in router_create_check_tile_block
    assert "createIcon(" in router_create_check_tile_block
    assert "createIcon('alert'" in router_create_check_tile_block or 'createIcon("alert"' in router_create_check_tile_block or "iconName = 'alert'" in router_create_check_tile_block


def test_router_checked_at_tile_unknown_uses_info_not_check(
    router_create_checked_at_tile_block: str,
) -> None:
    assert "Время проверки неизвестно" in router_create_checked_at_tile_block
    assert "createIcon('info'" in router_create_checked_at_tile_block or 'createIcon("info"' in router_create_checked_at_tile_block
    assert "createIcon('check'" not in router_create_checked_at_tile_block
    assert "createIcon(\"check\"" not in router_create_checked_at_tile_block


def test_router_card_shared_frame_dom(router_card_block: str) -> None:
    """AC2: router card uses unified __main/__actions/__meta frame."""
    assert "createOverviewStepCardMain" in router_card_block
    assert "createOverviewStepCardActions" in router_card_block
    assert "createOverviewStepCardMeta" in router_card_block


SKELETON_CSS_START = "/* ==== OVERVIEW CARD SKELETON ==== */"
SKELETON_CSS_END = "/* ==== /OVERVIEW CARD SKELETON ==== */"


@pytest.fixture(scope="module")
def skeleton_css() -> str:
    css = SCREENS_CSS.read_text(encoding="utf-8")
    start = css.find(SKELETON_CSS_START)
    end = css.find(SKELETON_CSS_END)
    assert start != -1, "skeleton CSS start marker missing"
    assert end != -1, "skeleton CSS end marker missing"
    assert end > start, "skeleton CSS markers out of order"
    return css[start:end]


@pytest.fixture(scope="module")
def skeleton_builder_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildOverviewStepCardSkeleton\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildOverviewStepCardSkeleton must exist"
    return match.group(0)


def test_router_skeleton_builder_export_and_sizes(
    grid_source: str,
    skeleton_builder_block: str,
    skeleton_css: str,
) -> None:
    assert "export function buildOverviewStepCardSkeleton" in grid_source
    assert "variant === 'router'" in skeleton_builder_block
    assert "setAttribute('aria-label'" in skeleton_builder_block
    assert "Загрузка:" in skeleton_builder_block
    assert "setAttribute('role', 'status')" in skeleton_builder_block
    assert "setAttribute('aria-busy', 'true')" in skeleton_builder_block
    assert "hub-overview-card-skeleton__info-block-bone" in skeleton_builder_block
    assert "createOverviewSkeletonCheckGrid(4)" in skeleton_builder_block
    assert "min-height: 4.25rem" in skeleton_css
    assert "min-height: 3.75rem" in skeleton_css
    assert "width: 4.5rem" in skeleton_css
    assert "height: 4.5rem" in skeleton_css


def test_router_skeleton_a11y_on_article(grid_source: str, skeleton_builder_block: str) -> None:
    assert "OVERVIEW_SKELETON_VARIANT_LABELS" in grid_source
    assert "router: 'Роутер'" in grid_source
    assert "setAttribute('aria-hidden', 'true')" in skeleton_builder_block
    assert "wireOverviewCardNavigate" not in skeleton_builder_block
    assert "createButton" not in skeleton_builder_block


def test_router_skeleton_css_prm_slice(skeleton_css: str) -> None:
    assert "hub-state-shimmer" in skeleton_css
    assert "--hub-duration-slow" in skeleton_css
    prm = re.search(
        r"@media\s*\(\s*prefers-reduced-motion:\s*reduce\s*\)\s*\{[^}]+\}",
        skeleton_css,
        re.DOTALL,
    )
    assert prm, "PRM block missing inside skeleton CSS slice"
    block = prm.group(0)
    assert "animation: none" in block or "animation:none" in block
    assert "background-image: none" in block or "background-image:none" in block
