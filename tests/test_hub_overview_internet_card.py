"""Статические проверки polish карточки «Интернет» на Overview step-2."""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
SCREENS_CSS = HUB / "styles" / "screens.css"

INTERNET_FN_PATTERN = re.compile(
    r"export function buildInternetStatusCard\(options\) \{(.*?)^\}",
    re.MULTILINE | re.DOTALL,
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _internet_card_body() -> str:
    source = _read(OVERVIEW_CARD_GRID_JS)
    match = INTERNET_FN_PATTERN.search(source)
    assert match is not None, "buildInternetStatusCard body not found"
    return match.group(1)


def test_build_internet_status_card_export_exists() -> None:
    source = _read(OVERVIEW_CARD_GRID_JS)
    assert "export function buildInternetStatusCard" in source


def test_internet_card_uses_hub_internet_card_classes() -> None:
    body = _internet_card_body()
    assert "hub-internet-card" in body
    assert "hub-internet-card__hero" in body
    assert "hub-internet-card__segments" in body
    assert "hub-internet-card__segment" in body
    assert "hub-internet-card__checks" in body
    assert "hub-internet-card__change" in body


def test_internet_card_wired_segment_label_kabel() -> None:
    body = _internet_card_body()
    assert "{ id: 'wired', label: 'Кабель' }" in body
    assert "hub-overview-source-segments" not in body


def test_internet_card_segments_are_non_interactive_spans() -> None:
    body = _internet_card_body()
    assert "document.createElement('span')" in body
    assert "hub-internet-card__segment" in body
    assert "role='button'" not in body.replace('"', "'")
    assert 'role="button"' not in body


def test_internet_card_css_owned_section_pointer_events_and_prefix() -> None:
    source = _read(SCREENS_CSS)
    start = source.index("/* ==== OVERVIEW STEP CARD: INTERNET (owned area) ==== */")
    end = source.index("/* ==== /OVERVIEW STEP CARD: INTERNET ==== */")
    block = source[start:end]
    assert "hub-internet-card__" in block
    assert "pointer-events: none" in block
    assert ".hub-overview-source-segments" not in block


def test_internet_card_modem_note_preserved() -> None:
    body = _internet_card_body()
    assert "INTERNET_SOURCE_MODEM_NOTE" in body
    assert "Модем пока не поддерживается" not in body  # imported constant, not inlined


def test_internet_card_uses_describe_helpers() -> None:
    body = _internet_card_body()
    assert "describeInternetSource" in body
    assert "describeRememberedUplink" in body
    assert "mapInternetSourceKindToSegment" in body


def test_internet_card_no_dbm_or_fake_metrics() -> None:
    body = _internet_card_body()
    assert "dBm" not in body
    assert "Мбит" not in body
    assert "мбит" not in body
    assert "signal" not in body.lower()


def test_internet_card_root_class_and_navigate_wire() -> None:
    body = _internet_card_body()
    assert "hub-overview__internet-status-card" in body
    assert "wireOverviewCardNavigate(card, 'internet-uplink', navigate)" in body


def test_internet_card_change_network_button_label() -> None:
    body = _internet_card_body()
    assert "label: 'Сменить сеть'" in body


def test_internet_card_status_labels_and_check_tiles() -> None:
    source = _read(OVERVIEW_CARD_GRID_JS)
    body = _internet_card_body()
    assert "internetStatusBadgeTone" in body
    assert "'Работает'" in source
    assert "'Нет связи'" in source
    assert "'Проверяем…'" in source
    assert "'Неизвестно'" in source
    # Подписи плиток зависят от состояния: одна иконка не должна быть единственным
    # признаком того, что интернета нет или состояние неизвестно.
    assert "yes: 'Интернет доступен'" in body
    assert "no: 'Интернета нет'" in body
    assert "unknown: 'Интернет: неизвестно'" in body
    assert "yes: 'Автоподключение включено'" in body
    assert "no: 'Автоподключение выключено'" in body
    assert "unknown: 'Автоподключение: неизвестно'" in body


def test_internet_card_header_title_class_and_info_icon() -> None:
    body = _internet_card_body()
    assert "hub-overview-step-card__title" in body
    assert "createIcon('info'" in body
    assert "createIcon('connection'" in body


def test_map_internet_source_kind_to_segment_static_mapping() -> None:
    source = _read(OVERVIEW_CARD_GRID_JS)
    assert "export function mapInternetSourceKindToSegment" in source
    assert "if (kind === 'wifi')" in source
    assert "if (kind === 'wired')" in source


def test_internet_card_remembered_ssid_honesty_label() -> None:
    body = _internet_card_body()
    assert "Сохранённая сеть (не подтверждена как шлюз)" in body
    assert "hub-internet-card__network-saved-label" in body


def test_internet_card_busy_gate_describe_internet_source() -> None:
    body = _internet_card_body()
    assert "busy ? null : describeInternetSource(observation)" in body


def test_internet_card_gateway_ssid_requires_trustworthy_observation() -> None:
    body = _internet_card_body()
    assert "gatewayOk" in body
    assert "read_status === 'ok'" in body
    assert "gatewayOk && typeof observation?.gateway_ssid" in body


def test_internet_card_css_no_status_or_accent_tokens() -> None:
    source = _read(SCREENS_CSS)
    start = source.index("/* ==== OVERVIEW STEP CARD: INTERNET (owned area) ==== */")
    end = source.index("/* ==== /OVERVIEW STEP CARD: INTERNET ==== */")
    block = source[start:end]
    assert "--hub-status-" not in block
    assert "--hub-accent-primary" not in block


def test_internet_card_css_no_font_family_size_token_misuse() -> None:
    source = _read(SCREENS_CSS)
    start = source.index("/* ==== OVERVIEW STEP CARD: INTERNET (owned area) ==== */")
    end = source.index("/* ==== /OVERVIEW STEP CARD: INTERNET ==== */")
    block = source[start:end]
    assert "font-family: var(--hub-font-display)" not in block
    assert "font-family: var(--hub-font-h2)" not in block
    assert "font-family: var(--hub-font-body)" not in block


def test_internet_card_css_active_segment_uses_primary_soft_pattern() -> None:
    source = _read(SCREENS_CSS)
    start = source.index("/* ==== OVERVIEW STEP CARD: INTERNET (owned area) ==== */")
    end = source.index("/* ==== /OVERVIEW STEP CARD: INTERNET ==== */")
    block = source[start:end]
    active_match = re.search(
        r"\.hub-internet-card__segment--active\s*\{([^}]+)\}",
        block,
    )
    assert active_match is not None, ".hub-internet-card__segment--active rule not found"
    active_block = active_match.group(1)
    assert "background-color: var(--hub-color-primary-soft)" in active_block
    assert "border-color: var(--hub-color-primary)" in active_block
    assert "color: var(--hub-text-primary)" in active_block
    assert "var(--hub-color-primary-on)" not in active_block
    assert "background-color: var(--hub-color-primary)" not in active_block


def test_internet_card_no_modem_note_dom_or_css() -> None:
    """AC5: modem note is title-only; no hub-internet-card__modem-note DOM/CSS."""
    body = _internet_card_body()
    assert "hub-internet-card__modem-note" not in body
    assert "segment.title = INTERNET_SOURCE_MODEM_NOTE" in body
    source = _read(SCREENS_CSS)
    start = source.index("/* ==== OVERVIEW STEP CARD: INTERNET (owned area) ==== */")
    end = source.index("/* ==== /OVERVIEW STEP CARD: INTERNET ==== */")
    block = source[start:end]
    assert "hub-internet-card__modem-note" not in block


def test_internet_card_shared_frame_dom() -> None:
    """AC2: internet card uses unified __main/__actions/__meta frame."""
    body = _internet_card_body()
    assert "createOverviewStepCardMain" in body
    assert "createOverviewStepCardActions" in body
    assert "createOverviewStepCardMeta" in body
    assert "hub-internet-card__remembered" in body


def test_internet_card_hero_icon_size_and_css() -> None:
    """AC7: internet hero 4.5rem frame + connection icon size 32."""
    body = _internet_card_body()
    assert "createIcon('connection', { size: 32 })" in body
    source = _read(SCREENS_CSS)
    start = source.index("/* ==== OVERVIEW STEP CARD: INTERNET (owned area) ==== */")
    end = source.index("/* ==== /OVERVIEW STEP CARD: INTERNET ==== */")
    block = source[start:end]
    hero_match = re.search(
        r"\.hub-internet-card__hero\s*\{([^}]+)\}",
        block,
    )
    assert hero_match is not None, ".hub-internet-card__hero rule not found"
    hero_block = hero_match.group(1)
    assert "4.5rem" in hero_block
    assert "5rem" not in hero_block.replace("4.5rem", "")


def test_internet_band_pill_gated_on_ssid_match() -> None:
    """Band pill must not attribute remembered band to a mismatched live SSID."""
    body = _internet_card_body()
    assert "internetBandLabel(rememberedUplink?.band)" in body
    assert "rememberedSsid === gatewaySsid" in body
    assert "!gatewaySsid || rememberedSsid === gatewaySsid" in body


def test_internet_skeleton_builder_variant_and_sizes() -> None:
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    match = re.search(
        r"export function buildOverviewStepCardSkeleton\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildOverviewStepCardSkeleton must exist"
    block = match.group(0)
    assert "variant === 'internet'" in block
    assert "hub-overview-card-skeleton__segments-bone" in block
    assert "hub-overview-card-skeleton__network-block-bone" in block
    assert "createOverviewSkeletonCheckGrid(2)" in block
    css = _read(SCREENS_CSS)
    sk_start = css.index("/* ==== OVERVIEW CARD SKELETON ==== */")
    sk_end = css.index("/* ==== /OVERVIEW CARD SKELETON ==== */")
    skeleton_css = css[sk_start:sk_end]
    assert "min-height: 6.5rem" in skeleton_css
    assert "min-height: 3.75rem" in skeleton_css
