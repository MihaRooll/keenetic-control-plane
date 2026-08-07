"""Static contract guards for Overview step-3 VPN card (offline, no DOM).

``buildVpnStatusCardShell`` and ``vpn*`` helpers in ``overview-card-grid.js`` are the
SSOT honesty functions; compact profile quality lives in ``vpnDeriveProfileQuality``.
"""

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

FORBIDDEN_VPN_CARD_NEEDLES = (
    "kill-switch",
    "describeCatalogConnectionBadge",
    "createTechnicalDetails",
    "dBm",
    "Мбит",
    "мбит",
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
def vpn_shell_block(grid_source: str) -> str:
    start = grid_source.find("function vpnIsSetMember")
    fn_match = re.search(
        r"export function buildVpnStatusCardShell\([\s\S]*?\n\}",
        grid_source,
    )
    assert start != -1, "vpn helper block missing"
    assert fn_match, "buildVpnStatusCardShell must exist"
    return grid_source[start : fn_match.end()]


@pytest.fixture(scope="module")
def vpn_owned_css() -> str:
    css = _read(SCREENS_CSS)
    start = css.find(VPN_OWNED_START)
    end = css.find(VPN_OWNED_END)
    assert start != -1, "VPN owned CSS start marker missing"
    assert end != -1, "VPN owned CSS end marker missing"
    assert end > start, "VPN owned CSS markers out of order"
    return css[start:end]


def test_render_vpn_slot_uses_required_apis(render_vpn_body: str, vpn_shell_block: str) -> None:
    # Компактный выбираемый picker (не полноценная сетка с кнопками управления
    # с экрана #/vpn) — carte «Обзора» больше не тянет за собой validate/activate/
    # deactivate/remove на каждой плитке, только выбор + одна общая CTA-кнопка.
    assert "buildOverviewVpnProfilePicker" in render_vpn_body
    assert "createVpnProfileStatusTileGrid" not in render_vpn_body
    assert "runOverviewVpnActivate" in render_vpn_body
    assert "runOverviewVpnDeactivate" in render_vpn_body
    assert "hub-overview__vpn-note" not in render_vpn_body
    assert "OVERVIEW_VPN_STATUS_NOTE" not in render_vpn_body
    assert "hub-vpn-card__cta-hint" not in render_vpn_body
    assert "vpnBuildFactTiles" not in render_vpn_body
    assert "hub-vpn-card__" in render_vpn_body
    assert "createIcon('vpn'" in render_vpn_body or 'createIcon("vpn"' in render_vpn_body
    # Корпус карточки (номер шага, заголовок, info-иконка) собирает единственная
    # реализация — buildVpnStatusCardShell. Раньше эта же разметка дублировалась
    # инлайном в renderVpnSlot, и живой была только инлайновая копия.
    assert "buildVpnStatusCardShell" in render_vpn_body
    assert "hub-overview__vpn-heading" in vpn_shell_block
    assert "createIcon('info'" in vpn_shell_block or 'createIcon("info"' in vpn_shell_block


def test_render_vpn_slot_badge_honesty(render_vpn_body: str, vpn_shell_block: str) -> None:
    combined = render_vpn_body + vpn_shell_block
    assert "routed_through_tunnel" in combined
    assert "describeCatalogConnectionBadge" not in render_vpn_body
    assert "Подключён" in combined
    assert "vpnIsConnectedRouted" in render_vpn_body, (
        "renderVpnSlot must gate active tile chrome on vpnIsConnectedRouted"
    )
    assert re.search(
        r"vpnIsConnectedRouted\(item\)[\s\S]*hub-vpn-card__tile--active",
        render_vpn_body,
    ), "renderVpnSlot must gate active tile chrome on vpnIsConnectedRouted(item)"


def test_vpn_helpers_honesty_strings(vpn_shell_block: str) -> None:
    assert "Подключён" in vpn_shell_block
    assert "routed_through_tunnel" in vpn_shell_block
    assert "Туннель активен" in vpn_shell_block
    assert "Туннель не активен" in vpn_shell_block
    assert "Туннель не проверен" in vpn_shell_block
    assert "Трафик идёт через VPN" in vpn_shell_block
    assert "Трафик не через VPN" in vpn_shell_block
    assert "Трафик не проверен" in vpn_shell_block
    assert "tunnel_no_peer" in vpn_shell_block
    assert "tunnel_never_handshaked" in vpn_shell_block


def test_render_vpn_slot_tunnel_unhealthy_honesty(
    render_vpn_body: str,
    vpn_shell_block: str,
    grid_source: str,
) -> None:
    """Tunnel-unhealthy strings live in helpers; picker uses vpnDeriveProfileQuality."""
    assert "tunnel_no_peer" in vpn_shell_block or "tunnel_never_handshaked" in vpn_shell_block
    assert "Туннель не активен" in vpn_shell_block
    assert "Туннель не проверен" in vpn_shell_block
    assert "vpnBuildFactTiles" in vpn_shell_block
    assert "vpnBuildFactTiles" not in render_vpn_body
    assert "vpnDeriveProfileQuality" in grid_source
    assert "'Плохой'" in grid_source


def test_overview_js_no_create_technical_details(overview_source: str) -> None:
    assert "createTechnicalDetails" not in overview_source


def test_build_vpn_status_card_shell_exports_heading(vpn_shell_block: str) -> None:
    assert "export function buildVpnStatusCardShell" in vpn_shell_block
    assert "hub-overview__vpn-heading" in vpn_shell_block
    assert "hub-vpn-card" in vpn_shell_block
    assert "vpnDeriveCardStatus" in vpn_shell_block
    assert "routed_through_tunnel" in vpn_shell_block


def test_vpn_owned_css_markers_and_classes(vpn_owned_css: str) -> None:
    assert "hub-vpn-card__" in vpn_owned_css
    assert "grid-template-columns: repeat(2, minmax(0, 1fr))" in vpn_owned_css
    # picker — единственная сетка профилей на «Обзоре»; старая .hub-vpn__tile-grid
    # (сетка с кнопками управления с экрана #/vpn) больше не рендерится в этой
    # карточке, поэтому её CSS здесь не должно быть — мёртвый селектор был бы
    # нечестной подпоркой ради старого теста, а не реальным стилем.
    assert ".hub-vpn-card__picker-grid" in vpn_owned_css
    assert ".hub-vpn-card__profiles .hub-vpn__tile-grid" not in vpn_owned_css
    assert "--hub-status-" not in vpn_owned_css
    assert "--hub-accent-primary" not in vpn_owned_css


def test_vpn_owned_css_content_spacing(vpn_owned_css: str) -> None:
    assert ".hub-vpn-card__content" in vpn_owned_css
    content_block = re.search(
        r"\.hub-vpn-card__content\s*\{[^}]+\}",
        vpn_owned_css,
        re.DOTALL,
    )
    assert content_block, ".hub-vpn-card__content rule missing"
    block = content_block.group(0)
    assert "display: flex" in block or "display:flex" in block
    assert "gap:" in block


def test_vpn_owned_css_tile_status_not_hidden(vpn_owned_css: str) -> None:
    """Compact quality status on every picker tile must stay visible."""
    status_block = re.search(
        r"\.hub-vpn-card__tile-status\s*\{[^}]+\}",
        vpn_owned_css,
        re.DOTALL,
    )
    assert status_block, "tile-status rule missing in VPN owned CSS"
    assert "display: none" not in status_block.group(0)
    assert "display:none" not in status_block.group(0)
    assert ".hub-vpn-card__tile-status--success" in vpn_owned_css


def test_vpn_card_forbids_antipatterns(render_vpn_body: str, vpn_shell_block: str) -> None:
    combined = render_vpn_body + vpn_shell_block
    for needle in FORBIDDEN_VPN_CARD_NEEDLES:
        assert needle not in combined, f"forbidden needle in VPN card sources: {needle!r}"


def test_render_vpn_slot_preserves_wiring(render_vpn_body: str) -> None:
    assert "signature === lastVpnSignature" in render_vpn_body
    assert "busyProfileIds: vpnActivatingProfileIds" in render_vpn_body
    assert "deactivatingProfileIds: vpnDeactivatingProfileIds" in render_vpn_body
    assert "checkingProfileIds: vpnCheckingProfileIds" in render_vpn_body
    # Выбор профиля кликом по плитке — единственный способ сменить CTA-цель
    # (кнопок validate/activate/deactivate/remove на самой плитке больше нет).
    assert "selectedProfileId: vpnSelectedProfileId" in render_vpn_body
    assert "onSelect: (profileId) =>" in render_vpn_body
    assert "showMeta: false" not in render_vpn_body
    assert "ctx.navigate('vpn')" in render_vpn_body
    assert "wireOverviewCardNavigate(card, 'vpn'" in render_vpn_body
    assert render_vpn_body.count("preventScroll: true") >= 2, (
        "renderVpnSlot must restore focus with preventScroll for both focusedId and VPN tile paths"
    )
    assert render_vpn_body.count("scrollIntoView({ block: 'nearest', inline: 'nearest' })") >= 2, (
        "renderVpnSlot must scrollIntoView for both focusedId and VPN tile paths"
    )
    assert "hub-vpn-card__tile--active" in render_vpn_body
    assert "hub-vpn-card__tile--selected" in render_vpn_body
    assert "Отключить VPN" in render_vpn_body
    assert "Подключить VPN" in render_vpn_body


def test_render_vpn_slot_wires_after_real_shell_not_skeleton(
    render_vpn_body: str,
    vpn_shell_block: str,
) -> None:
    skeleton_return = render_vpn_body.find("buildOverviewStepCardSkeleton({ stepNumber: 3, variant: 'vpn' })")
    assert skeleton_return != -1, "skeleton early-return path must exist"
    wire_idx = render_vpn_body.find("wireOverviewCardNavigate(card, 'vpn'")
    assert wire_idx != -1, "renderVpnSlot must wire VPN card navigation"
    assert wire_idx > skeleton_return, "wire must be after skeleton builder, on real shell path"
    assert "wireOverviewCardNavigate" not in vpn_shell_block


def test_render_vpn_slot_cta_always_secondary(render_vpn_body: str) -> None:
    """AC4: Overview VPN CTA is always secondary — no primary branch."""
    cta_match = re.search(
        r"ctaBtn\s*=\s*createButton\(\{[\s\S]*?hub-vpn-card__cta",
        render_vpn_body,
    )
    assert cta_match, "VPN CTA createButton block missing in renderVpnSlot"
    cta_block = cta_match.group(0)
    assert "variant: 'secondary'" in cta_block
    assert "variant: 'primary'" not in cta_block
    assert "hub-overview-step-card__actions" in render_vpn_body
    assert "hub-overview-step-card__meta" in render_vpn_body


def test_render_vpn_slot_quiet_link_in_meta(render_vpn_body: str) -> None:
    assert "hub-overview__quiet-link" in render_vpn_body
    assert "Все настройки VPN" in render_vpn_body
    assert re.search(r"createElement\(['\"]a['\"]\)", render_vpn_body), (
        "quiet-link must be built as createElement('a')"
    )
    assert "#/vpn" in render_vpn_body
    assert re.search(r"meta\.appendChild\(vpnLink\)", render_vpn_body), (
        "quiet-link must be appended into __meta"
    )
    assert "hub-overview-step-card__meta" in render_vpn_body


def test_build_vpn_status_card_shell_uses_main_not_body(vpn_shell_block: str) -> None:
    """AC2: VPN shell puts content in __main; no __body wrapper."""
    assert "createOverviewStepCardMain" in vpn_shell_block
    assert "hub-overview-step-card__body" not in vpn_shell_block


def test_vpn_skeleton_builder_picker_height(grid_source: str) -> None:
    match = re.search(
        r"export function buildOverviewStepCardSkeleton\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildOverviewStepCardSkeleton must exist"
    block = match.group(0)
    assert "variant === 'vpn'" in block
    assert "hub-overview-card-skeleton__picker-bone" in block
    css = _read(SCREENS_CSS)
    sk_start = css.index("/* ==== OVERVIEW CARD SKELETON ==== */")
    sk_end = css.index("/* ==== /OVERVIEW CARD SKELETON ==== */")
    skeleton_css = css[sk_start:sk_end]
    assert "height: 9.25rem" in skeleton_css


def test_render_vpn_slot_catalog_settle_gate(render_vpn_body: str, overview_source: str) -> None:
    assert "vpnCatalogSettled" in overview_source
    assert "shouldShowVpnCardSkeleton" in overview_source
    assert (
        "vpnCatalogSettled && vpnCatalogItems.length === 0 && !vpnEnrichmentBusy"
        in render_vpn_body
    ), "EMPTY only when settled + empty + !busy"
    assert "buildOverviewStepCardSkeleton({ stepNumber: 3, variant: 'vpn' })" in render_vpn_body
    assert "Загружаем профили VPN" not in render_vpn_body


def test_refresh_vpn_catalog_settles_only_after_successful_list(overview_source: str) -> None:
    fn_body = _extract_function_body(overview_source, "async function refreshVpnCatalogAndLiveStatus(")
    assert fn_body is not None
    assert "let catalogListed = false" in fn_body or "catalogListed = false" in fn_body
    assert "catalogListed = true" in fn_body
    finally_block = fn_body.split("} finally {", 1)[1]
    assert re.search(
        r"if\s*\(\s*catalogListed\s*&&",
        finally_block,
    ), "settle must be gated by catalogListed success flag, not unconditional finally"
    assert "vpnCatalogSettled = true" in finally_block
    assert "renderVpnSlot()" in finally_block
    # Old bug: bare finally settle without catalogListed guard
    assert not re.search(
        r"\}\s*finally\s*\{\s*vpnCatalogSettled\s*=\s*true",
        fn_body,
    ), "must not unconditionally settle at start of finally"


def test_refresh_vpn_catalog_finally_generation_guard(overview_source: str) -> None:
    fn_body = _extract_function_body(overview_source, "async function refreshVpnCatalogAndLiveStatus(")
    assert fn_body is not None
    finally_block = fn_body.split("} finally {", 1)[1]
    assert "expectedGeneration" in fn_body
    assert "generationOk" in finally_block
    assert "expectedGeneration === generation" in finally_block
    assert re.search(
        r"if\s*\(\s*catalogListed\s*&&\s*generationOk\s*&&\s*!disposed\s*\)",
        finally_block,
    ), "finally settle/render must guard generation and disposed like enrichment paths"
    enrichment_fn = overview_source.split("async function runOverviewEnrichment")[1].split(
        "function buildSummaryPanelOptions",
        1,
    )[0]
    assert "refreshVpnCatalogAndLiveStatus(signal, gen)" in enrichment_fn


def test_refresh_vpn_catalog_live_status_failure_does_not_block_settle(overview_source: str) -> None:
    fn_body = _extract_function_body(overview_source, "async function refreshVpnCatalogAndLiveStatus(")
    assert fn_body is not None
    assert "catalogListed = true" in fn_body
    assert "optional live-status failure must not block catalog settle" in fn_body
    list_assign = fn_body.split("catalogListed = true", 1)[0]
    assert "listVpnProfiles" in list_assign


def test_empty_list_success_allows_empty_panel_after_settle(
    render_vpn_body: str,
    overview_source: str,
) -> None:
    fn_body = _extract_function_body(overview_source, "async function refreshVpnCatalogAndLiveStatus(")
    assert fn_body is not None
    assert "catalogListed = true" in fn_body
    assert "vpnLiveStatusById = {}" in fn_body
    assert (
        "vpnCatalogSettled && vpnCatalogItems.length === 0 && !vpnEnrichmentBusy"
        in render_vpn_body
    ), "EMPTY only after successful settle + empty catalog + !busy"
    assert "Профиль VPN не добавлен" in render_vpn_body


def test_soft_refresh_nonempty_catalog_skips_vpn_skeleton(overview_source: str) -> None:
    fn_body = _extract_function_body(overview_source, "function shouldShowVpnCardSkeleton(")
    assert fn_body is not None
    assert "vpnCatalogItems.length > 0" in fn_body
    assert "return false" in fn_body
