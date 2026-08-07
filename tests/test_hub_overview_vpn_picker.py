"""Static contract guards for Overview VPN profile picker (offline, no DOM)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OVERVIEW_JS = HUB / "screens" / "overview.js"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
SCREENS_CSS = HUB / "styles" / "screens.css"

VPN_OWNED_START = "/* ==== OVERVIEW STEP CARD: VPN (owned area) ==== */"
VPN_OWNED_END = "/* ==== /OVERVIEW STEP CARD: VPN ==== */"

FORBIDDEN_PICKER_ACTIONS = (
    "onActivate",
    "onDeactivate",
    "onValidate",
    "onRemove",
    "createButton",
    "Подключить",
    "Отключить",
    "Проверить",
    "Удалить",
)


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


@pytest.fixture(scope="module")
def overview_source() -> str:
    return _read(OVERVIEW_JS)


@pytest.fixture(scope="module")
def render_vpn_body(overview_source: str) -> str:
    body = _extract_function_body(overview_source, "function renderVpnSlot(")
    assert body is not None, "renderVpnSlot body missing"
    return body


@pytest.fixture(scope="module")
def grid_source() -> str:
    return _read(OVERVIEW_CARD_GRID_JS)


@pytest.fixture(scope="module")
def picker_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildOverviewVpnProfilePicker\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildOverviewVpnProfilePicker must exist"
    return match.group(0)


@pytest.fixture(scope="module")
def reconcile_block(overview_source: str) -> str:
    body = _extract_function_body(overview_source, "function reconcileVpnSelectedProfileId(")
    assert body is not None, "reconcileVpnSelectedProfileId body missing"
    return body


@pytest.fixture(scope="module")
def vpn_helper_block(grid_source: str) -> str:
    start = grid_source.find("function vpnIsSetMember")
    fn_match = re.search(
        r"export function buildVpnStatusCardShell\([\s\S]*?\n\}",
        grid_source,
    )
    assert start != -1, "vpn helper block missing"
    assert fn_match, "buildVpnStatusCardShell must exist"
    return grid_source[start : fn_match.end()]


@pytest.fixture(scope="module")
def entry_pages_card_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildEntryPagesStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildEntryPagesStatusCard must exist"
    return match.group(0)


@pytest.fixture(scope="module")
def vpn_owned_css() -> str:
    css = _read(SCREENS_CSS)
    start = css.find(VPN_OWNED_START)
    end = css.find(VPN_OWNED_END)
    assert start != -1, "VPN owned CSS start marker missing"
    assert end != -1, "VPN owned CSS end marker missing"
    assert end > start, "VPN owned CSS markers out of order"
    return css[start:end]


def test_picker_export_and_imports(
    picker_block: str,
    render_vpn_body: str,
    overview_source: str,
) -> None:
    assert "export function buildOverviewVpnProfilePicker" in picker_block
    assert "buildOverviewVpnProfilePicker" in overview_source
    assert "buildOverviewVpnProfilePicker" in render_vpn_body
    assert "createVpnProfileStatusTileGrid" not in render_vpn_body


def test_picker_no_per_tile_action_buttons(picker_block: str) -> None:
    for needle in FORBIDDEN_PICKER_ACTIONS:
        assert needle not in picker_block, f"forbidden picker action needle: {needle!r}"


def test_picker_accessibility_and_data_attributes(picker_block: str) -> None:
    assert (
        "setAttribute('role', 'group')" in picker_block
        or 'setAttribute("role", "group")' in picker_block
    )
    assert "aria-pressed" in picker_block
    assert "type = 'button'" in picker_block or 'type = "button"' in picker_block
    assert "data-hub-vpn-profile-id" in picker_block
    assert "hub-vpn-card__tile--picked" in picker_block
    assert "createIcon('vpn'" in picker_block or 'createIcon("vpn"' in picker_block
    assert re.search(
        r"vpnIsConnectedRouted\(item\)"
        r"|describeVpnProfileTileStatus\(item\)\.kind\s*===\s*['\"]connected_routed['\"]",
        picker_block,
    ), "picker must gate --active on connected_routed only"
    assert "hub-vpn-card__tile--selected" in picker_block
    assert "vpnDeriveProfileQuality" in picker_block
    assert "hub-vpn-card__tile-status--" in picker_block
    assert "Активен" not in picker_block


def test_render_vpn_slot_selection_state_and_cta(render_vpn_body: str) -> None:
    assert "let vpnSelectedProfileId" in _read(OVERVIEW_JS)
    assert "vpnSelectedProfileId" in render_vpn_body
    assert "reconcileVpnSelectedProfileId" in render_vpn_body
    assert "selectedProfileId: vpnSelectedProfileId" in render_vpn_body
    assert "onSelect:" in render_vpn_body
    assert "runOverviewVpnActivate(selectedProfileId)" in render_vpn_body
    assert "busyProfileIds: vpnActivatingProfileIds" in render_vpn_body
    assert "deactivatingProfileIds: vpnDeactivatingProfileIds" in render_vpn_body
    assert "checkingProfileIds: vpnCheckingProfileIds" in render_vpn_body


def test_picker_tile_quality_labels_and_derive_kinds(
    grid_source: str,
    picker_block: str,
) -> None:
    assert "describeVpnProfileTileStatus" in grid_source
    assert "export function vpnDeriveProfileQuality" in grid_source

    derive_body = _extract_function_body(grid_source, "export function vpnDeriveProfileQuality(")
    assert derive_body is not None, "vpnDeriveProfileQuality body missing"

    assert re.search(
        r"item\?\.checking\s*===\s*true|item\.checking\s*===\s*true",
        derive_body,
    ), "derive must short-circuit on item.checking before describeVpnProfileTileStatus"
    assert "describeVpnProfileTileStatus" in derive_body
    checking_idx = derive_body.find("checking")
    describe_idx = derive_body.find("describeVpnProfileTileStatus")
    assert checking_idx != -1 and describe_idx != -1
    assert checking_idx < describe_idx, "checking guard must precede describeVpnProfileTileStatus"

    kind_label_pairs = (
        ("connected_routed", "Хороший"),
        ("connected_not_routed", "Слабый"),
        ("not_working", "Плохой"),
        ("check_failed", "Сбой"),
    )
    for kind, label in kind_label_pairs:
        assert f"case '{kind}':" in derive_body or f'case "{kind}":' in derive_body, (
            f"missing switch case for {kind!r}"
        )
        assert f"'{label}'" in derive_body or f'"{label}"' in derive_body, (
            f"missing label {label!r} in derive body"
        )
    assert "'Уточняется'" in derive_body or '"Уточняется"' in derive_body
    assert "'Не подключён'" in derive_body or '"Не подключён"' in derive_body
    assert "'Проверяем…'" in derive_body or '"Проверяем…"' in derive_body

    assert re.search(
        r"vpnDeriveProfileQuality\(\{\s*\.\.\.item,\s*checking:\s*tileChecking",
        picker_block,
    ), "picker must merge tileChecking into vpnDeriveProfileQuality call"
    assert "vpnDeriveProfileQuality(item)" not in picker_block


def test_vpn_owned_css_picker_scroll(vpn_owned_css: str) -> None:
    picker_block = re.search(
        r"\.hub-vpn-card__picker\s*\{[^}]+\}",
        vpn_owned_css,
        re.DOTALL,
    )
    assert picker_block, ".hub-vpn-card__picker rule missing"
    block = picker_block.group(0)
    assert "max-height: 9.25rem" in block or "max-height:9.25rem" in block
    assert "overflow-y: auto" in block or "overflow-y:auto" in block
    assert "overscroll-behavior: contain" in block or "overscroll-behavior:contain" in block
    assert "touch-action: pan-y" in block or "touch-action:pan-y" in block
    assert "scrollbar-gutter: stable" in block or "scrollbar-gutter:stable" in block
    assert "scrollbar-width: thin" in block or "scrollbar-width:thin" in block
    assert "scrollbar-color:" in block
    assert ".hub-vpn-card__picker::-webkit-scrollbar" in vpn_owned_css
    assert ".hub-vpn-card__picker::-webkit-scrollbar-thumb" in vpn_owned_css
    assert "::-webkit-scrollbar-button" in vpn_owned_css


def test_vpn_owned_css_tile_status_tones(vpn_owned_css: str) -> None:
    assert ".hub-vpn-card__tile-status--success" in vpn_owned_css
    assert ".hub-vpn-card__tile-status--warning" in vpn_owned_css
    assert ".hub-vpn-card__tile-status--danger" in vpn_owned_css
    assert ".hub-vpn-card__tile-status--neutral" in vpn_owned_css
    status_block = re.search(
        r"\.hub-vpn-card__tile-status\s*\{[^}]+\}",
        vpn_owned_css,
        re.DOTALL,
    )
    assert status_block, "tile-status rule missing"
    block = status_block.group(0)
    assert "white-space: nowrap" in block or "white-space:nowrap" in block
    assert "text-overflow: ellipsis" in block or "text-overflow:ellipsis" in block


def test_render_vpn_slot_no_cta_hint(render_vpn_body: str) -> None:
    assert "hub-vpn-card__cta-hint" not in render_vpn_body
    assert "кликом по плитке" not in render_vpn_body
    assert "Будет подключён профиль" not in render_vpn_body


def test_reconcile_orphan_and_default_logic(reconcile_block: str) -> None:
    assert "!ids.includes(vpnSelectedProfileId)" in reconcile_block
    assert "activeId ?? firstId" in reconcile_block
    assert "vpnSelectedProfileId === null" in reconcile_block
    assert "lastVpnActiveProfileId" in reconcile_block


def test_vpn_badge_honesty_unchanged(
    vpn_helper_block: str,
    picker_block: str,
    render_vpn_body: str,
) -> None:
    assert re.search(
        r"vpnIsConnectedRouted\(item\)"
        r"|describeVpnProfileTileStatus\(item\)\.kind\s*===\s*['\"]connected_routed['\"]",
        vpn_helper_block,
    ), "vpnDeriveCardStatus must gate «Подключён» on connected_routed only"
    assert re.search(
        r"vpnIsConnectedRouted\(item\)"
        r"|describeVpnProfileTileStatus\(item\)\.kind\s*===\s*['\"]connected_routed['\"]",
        picker_block,
    ), "picker must gate --active on connected_routed only"
    assert "vpnDeriveCardStatus" in render_vpn_body


def test_entry_pages_badge_honesty_invariant(entry_pages_card_block: str) -> None:
    assert "createBadge({ label: 'Не проверено', tone: 'warning' })" in entry_pages_card_block
    assert "hub-entry-pages-card__icon-frame" in entry_pages_card_block
    assert "createIcon('entry-pages'" in entry_pages_card_block
    assert "Проверка на этом экране не выполняется" in entry_pages_card_block


def test_vpn_owned_css_picker_and_legacy_selectors(vpn_owned_css: str) -> None:
    assert ".hub-vpn-card__picker-grid" in vpn_owned_css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in vpn_owned_css
    assert ".hub-vpn-card__tile--picked" in vpn_owned_css
    assert ".hub-vpn-card__tile--active.hub-vpn-card__tile--picked" in vpn_owned_css
    # Старая сетка .hub-vpn__tile-grid/.hub-vpn__tile-detail (полноценный экран #/vpn)
    # больше не рендерится внутри .hub-vpn-card__profiles на «Обзоре» — держать её CSS
    # здесь ради старого теста было бы мёртвым нечестным кодом, поэтому она удалена.
    assert ".hub-vpn-card__profiles .hub-vpn__tile-grid" not in vpn_owned_css
    assert ".hub-vpn-card__profiles .hub-vpn__tile-detail" not in vpn_owned_css
    assert "--hub-status-" not in vpn_owned_css
    assert "--hub-accent-primary" not in vpn_owned_css


def test_vpn_picker_skeleton_height_matches_live_picker(vpn_owned_css: str) -> None:
    css = _read(SCREENS_CSS)
    sk_start = css.index("/* ==== OVERVIEW CARD SKELETON ==== */")
    sk_end = css.index("/* ==== /OVERVIEW CARD SKELETON ==== */")
    skeleton_css = css[sk_start:sk_end]
    assert "height: 9.25rem" in skeleton_css
    assert "max-height: 9.25rem" in vpn_owned_css
