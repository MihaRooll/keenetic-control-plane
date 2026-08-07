"""Offline label-honesty guards for overview-card-grid.js (no DOM, no live host)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
NODE_SKIP_ENV = "ROUTER_CONTROL_SKIP_NODE_TESTS"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for label-honesty node harness; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _run_node_harness(script: str, tmp_path: Path, label: str) -> object:
    node = _require_node()
    tmp_path.mkdir(parents=True, exist_ok=True)
    harness_path = tmp_path / f"{label}.mjs"
    harness_path.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        [node, str(harness_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            f"node harness {label} failed:\nstdout={proc.stdout}\nstderr={proc.stderr}",
        )
    return json.loads(proc.stdout.strip())


@pytest.fixture(scope="module")
def grid_source() -> str:
    return _read(OVERVIEW_CARD_GRID_JS)


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
def router_create_check_tile_block(router_card_block: str) -> str:
    match = re.search(
        r"function routerCreateCheckTile\([\s\S]*?\n\}",
        router_card_block,
    )
    assert match, "routerCreateCheckTile must exist"
    return match.group(0)


@pytest.fixture(scope="module")
def entry_pages_card_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildEntryPagesStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildEntryPagesStatusCard must exist"
    return match.group(0)


@pytest.fixture(scope="module")
def internet_card_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildInternetStatusCard\(options\) \{(.*?)^\}",
        grid_source,
        re.MULTILINE | re.DOTALL,
    )
    assert match, "buildInternetStatusCard body not found"
    return match.group(1)


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
def domain_card_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildDomainStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildDomainStatusCard must exist"
    return match.group(0)


def test_router_tile_labels_ternary_yes_strings_preserved(router_card_block: str) -> None:
    assert "yes: 'Роутер отвечает'" in router_card_block
    assert "yes: 'Доступ сохранён'" in router_card_block
    assert "yes: 'Устройство совпадает'" in router_card_block


def test_router_tile_labels_negative_strings(router_card_block: str) -> None:
    assert "no: 'Роутер не отвечает'" in router_card_block
    assert "no: 'Доступ не сохранён'" in router_card_block
    assert "no: 'Устройство не совпадает'" in router_card_block


def test_router_tile_labels_unknown_strings(router_card_block: str) -> None:
    assert "unknown: 'Роутер: неизвестно'" in router_card_block
    assert "unknown: 'Доступ: неизвестно'" in router_card_block
    assert "unknown: 'Устройство: неизвестно'" in router_card_block


def test_router_create_check_tile_selects_label_by_value(
    router_create_check_tile_block: str,
    router_card_block: str,
) -> None:
    assert "resolveRouterCheckTileLabel(pill.id, pill.value)" in router_create_check_tile_block
    assert "resolveRouterCheckTileLabel(pill.id)" not in router_create_check_tile_block
    assert "${pill.id}: неизвестно" in router_create_check_tile_block
    tile_label_fn = router_card_block.split("function routerCreateCheckTile")[0]
    assert "export function resolveRouterCheckTileLabel" in tile_label_fn
    assert "value === true" in tile_label_fn
    assert "value === false" in tile_label_fn
    assert "labels.unknown" in tile_label_fn


def test_router_create_check_tile_false_not_affirmative_only(
    router_create_check_tile_block: str,
    router_card_block: str,
) -> None:
    assert "Роутер не отвечает" in router_card_block
    assert "Доступ не сохранён" in router_card_block
    assert "Устройство не совпадает" in router_card_block
    assert "iconName = 'alert'" in router_create_check_tile_block
    assert "pill.value === false" in router_create_check_tile_block


def test_router_create_check_tile_unknown_uses_explicit_label(
    router_create_check_tile_block: str,
    router_card_block: str,
) -> None:
    assert "hub-router-card__check-tile--unknown" in router_create_check_tile_block
    assert "hub-router-card__check-label--muted" in router_create_check_tile_block
    assert "iconName = 'info'" in router_create_check_tile_block
    assert "Роутер: неизвестно" in router_card_block
    assert "Доступ: неизвестно" in router_card_block
    assert "Устройство: неизвестно" in router_card_block


def test_entry_pages_card_shows_not_checked_badge(entry_pages_card_block: str) -> None:
    assert "createBadge({ label: 'Не проверено', tone: 'warning' })" in entry_pages_card_block
    assert entry_pages_card_block.count("Не проверено") >= 1


def test_entry_pages_card_marketplace_chrome(entry_pages_card_block: str) -> None:
    assert "createStepNumberBadge(7)" in entry_pages_card_block
    assert "label: 'Открыть'" in entry_pages_card_block
    assert "hub-overview__quiet-link" in entry_pages_card_block
    assert "wireOverviewCardNavigate(card, 'entry-pages', navigate)" in entry_pages_card_block


@pytest.fixture(scope="module")
def diagnostics_card_block(grid_source: str) -> str:
    match = re.search(
        r"export function buildDiagnosticsStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert match, "buildDiagnosticsStatusCard must exist"
    return match.group(0)


def test_diagnostics_card_shows_not_checked_badge(diagnostics_card_block: str) -> None:
    assert "createBadge({ label: 'Не проверено', tone: 'warning' })" in diagnostics_card_block
    assert diagnostics_card_block.count("Не проверено") >= 1
    assert "hub-diagnostics-card__icon-frame" in diagnostics_card_block
    assert "createIcon('diagnostics'" in diagnostics_card_block
    assert "Проверка на этом экране не выполняется" in diagnostics_card_block


def test_diagnostics_card_marketplace_chrome(diagnostics_card_block: str) -> None:
    assert "createStepNumberBadge(8)" in diagnostics_card_block
    assert "label: 'Открыть'" in diagnostics_card_block
    assert "hub-overview__quiet-link" in diagnostics_card_block
    assert "wireOverviewCardNavigate(card, 'diagnostics', navigate)" in diagnostics_card_block


def test_internet_tile_labels_negative_and_unknown(
    grid_source: str,
    internet_card_block: str,
) -> None:
    assert "no: 'Интернета нет'" in internet_card_block
    assert "unknown: 'Интернет: неизвестно'" in internet_card_block
    assert "no: 'Автоподключение выключено'" in internet_card_block
    assert "unknown: 'Автоподключение: неизвестно'" in internet_card_block
    tile_fn_body = grid_source.split("function internetCreateCheckTile")[1].split(
        "function buildInternetStatusCard"
    )[0]
    assert "value === false" in tile_fn_body


def test_vpn_helpers_negative_and_unknown_labels(vpn_helper_block: str) -> None:
    assert "Не подключён" in vpn_helper_block
    assert "Туннель не активен" in vpn_helper_block
    assert "Туннель не проверен" in vpn_helper_block
    assert "Трафик не через VPN" in vpn_helper_block
    assert "Трафик не проверен" in vpn_helper_block
    assert re.search(
        r"item\.is_active\s*===\s*true\s*&&\s*item\.routed_through_tunnel\s*===\s*true",
        vpn_helper_block,
    ), "vpnDeriveCardStatus must gate «Подключён» on active AND routed"


def test_domain_card_negative_and_unknown_labels(domain_card_block: str) -> None:
    assert "Имя не готово" in domain_card_block
    assert "Событие не выбрано" in domain_card_block
    assert "createBadge({ label: 'Не проверено', tone: 'warning' })" in domain_card_block


def test_resolve_router_check_tile_label_runtime(tmp_path: Path) -> None:
    """Runtime harness: false/null must not resolve to affirmative yes strings."""
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    script = f"""
const gridMod = await import({card_grid_uri});
const resolve = gridMod.resolveRouterCheckTileLabel;
console.log(JSON.stringify({{
  reachableFalse: resolve('reachable', false),
  reachableNull: resolve('reachable', null),
  reachableUndef: resolve('reachable', undefined),
  credsFalse: resolve('credentials_present', false),
  credsNull: resolve('credentials_present', null),
  tupleFalse: resolve('tuple_match', false),
  tupleNull: resolve('tuple_match', null),
  reachableTrue: resolve('reachable', true),
  credsTrue: resolve('credentials_present', true),
  tupleTrue: resolve('tuple_match', true),
}}));
"""
    payload = _run_node_harness(script, tmp_path, "label-honesty-router-tile-label")
    assert payload["reachableFalse"] == "Роутер не отвечает"
    assert payload["reachableNull"] == "Роутер: неизвестно"
    assert payload["reachableUndef"] == "Роутер: неизвестно"
    assert payload["credsFalse"] == "Доступ не сохранён"
    assert payload["credsNull"] == "Доступ: неизвестно"
    assert payload["tupleFalse"] == "Устройство не совпадает"
    assert payload["tupleNull"] == "Устройство: неизвестно"
    assert payload["reachableTrue"] == "Роутер отвечает"
    assert payload["credsTrue"] == "Доступ сохранён"
    assert payload["tupleTrue"] == "Устройство совпадает"


def test_map_health_facts_router_pills_false_keeps_affirmative_pill_labels(
    tmp_path: Path,
) -> None:
    """UI tiles are honest; pill.label for false stays affirmative (harness contract)."""
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    script = f"""
const gridMod = await import({card_grid_uri});
const pills = gridMod.mapHealthFactsToRouterPills([
  {{ id: 'reachable', value: true, tone: 'success' }},
  {{ id: 'credentials_present', value: false, tone: 'danger' }},
  {{ id: 'tuple_match', value: null, tone: 'neutral' }},
]);
console.log(JSON.stringify({{ labels: pills.map((pill) => pill.label) }}));
"""
    payload = _run_node_harness(script, tmp_path, "label-honesty-router-pills")
    assert payload["labels"] == ["Отвечает", "Доступ сохранён", "Совпадает: неизвестно"]


def test_vpn_derive_card_status_connected_only_when_active_and_routed(
    tmp_path: Path,
) -> None:
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    script = f"""
const gridMod = await import({card_grid_uri});
const activeNotRouted = gridMod.vpnDeriveCardStatus([
  {{ is_active: true, routed_through_tunnel: false }},
]);
const connected = gridMod.vpnDeriveCardStatus([
  {{ is_active: true, routed_through_tunnel: true }},
]);
const idle = gridMod.vpnDeriveCardStatus([]);
console.log(JSON.stringify({{
  activeNotRouted: activeNotRouted.label,
  connected: connected.label,
  idle: idle.label,
}}));
"""
    payload = _run_node_harness(script, tmp_path, "label-honesty-vpn-status")
    assert payload["activeNotRouted"] == "Не подключён"
    assert payload["connected"] == "Подключён"
    assert payload["idle"] == "Не подключён"
