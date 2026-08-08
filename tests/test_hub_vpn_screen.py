"""Структурные и поведенческие контракты экрана «VPN» LOCAL HUB."""

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
VPN_SCREEN_JS = HUB / "screens" / "vpn.js"
VPN_MODEL_JS = HUB / "features" / "vpn-model.js"
WIFI_SCREEN_PARTS_JS = HUB / "features" / "wifi-screen-parts.js"
SW_JS = HUB / "sw.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

FORBIDDEN_VPN_LITERALS = (
    "Нидерланды",
    "Активен",
    "46 мс",
    "185.22.64.18",
    "02:14:38",
    "Подключено",
    "HubState.SUCCESS",
    "renderStubScreen",
    "localStorage",
    "sessionStorage",
    "innerHTML",
    "console.log",
    "console.error",
    "http://",
    "https://",
)

REQUIRED_API_PATHS = (
    "vpn-profiles",
    "vpn-profiles/catalog-status",
    "vpn-profiles/",
    "/remove",
    "wireguard/preview",
    "wireguard/apply",
    "wireguard/teardown",
    "wireguard/observe",
)

STATUS_LINE_LABELS = (
    "Настройка на роутере",
    "Связь с сервером VPN",
    "Трафик через VPN",
)

RISK_MODAL_ACTIONS = ("connect", "reconnect", "disconnect")

SENTENCE_GLUE_RE = re.compile(
    r"(?:['\"][^'\"]*[а-яА-ЯёЁ][^'\"]*['\"])\s*\+\s*(?:['\"][^'\"]*[А-ЯA-Zа-я])",
)

ALLOWED_SENTENCE_GLUE_PATTERNS = (
    "${described.message} ${described.action}",
    "${punctuated} ${stateHint}",
    "connectionHintPrefix",
)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function_body(source: str, signature: str) -> str | None:
    """Извлекает тело function по сигнатуре (пропускает `{` в параметрах)."""
    start = source.find(signature)
    if start == -1:
        return None
    paren = source.find("(", start)
    if paren == -1:
        return None
    depth = 0
    i = paren
    while i < len(source):
        char = source[i]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                brace = source.find("{", i + 1)
                if brace == -1:
                    return None
                body_depth = 0
                j = brace
                while j < len(source):
                    c = source[j]
                    if c == "{":
                        body_depth += 1
                    elif c == "}":
                        body_depth -= 1
                        if body_depth == 0:
                            return source[brace + 1 : j]
                    j += 1
                return None
        i += 1
    return None


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            f"node is required for hub vpn screen tests; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _run_node_export(tmp_path: Path, script_body: str, label: str) -> object:
    node = _require_node()
    model_uri = VPN_MODEL_JS.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    harness_path = tmp_path / f"{label}.mjs"
    harness_path.parent.mkdir(parents=True, exist_ok=True)
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


def test_vpn_screen_no_decorative_toggle() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "createToggle" not in source
    assert "Что происходит с VPN" in source


def test_vpn_model_honesty_status_lines_behavioral(tmp_path: Path) -> None:
    """Три строки статуса: traffic WARNING (configured≠healthy); tunnel_healthy не SUCCESS."""
    result = _run_node_export(
        tmp_path,
        label="honesty-status",
        script_body="""
const applied = mod.parseTunnelVerdict({
  overall: 'applied',
  tunnel_verification_status: 'tunnel_healthy',
  configuration_verification_status: 'configuration_mismatch',
  interface_verification_status: 'interface_missing',
  verdict_explanation: {
    signals_rejected: [{ signal: 'interface_up', reason: 'interface_up_not_evidence' }],
    signals_missing: ['peer_rxbytes'],
  },
});
const empty = mod.parseTunnelVerdict(null);
console.log(JSON.stringify({
  configMessage: applied.configuration.message,
  tunnelMessage: applied.tunnel.message,
  trafficMessage: applied.trafficRouting.message,
  trafficTechnicalDetail: applied.trafficRouting.technicalDetail,
  trafficState: applied.trafficRouting.hubState,
  emptyTrafficState: empty.trafficRouting.hubState,
  configHub: applied.configuration.hubState,
  tunnelHub: applied.tunnel.hubState,
  technical: applied.technicalLines.join('\\n'),
  deceptiveInConfig: applied.configuration.message.includes('configuration_verification'),
  deceptiveInTunnel: applied.tunnel.message.includes('tunnel_verification'),
  tunnelHealthyQualifier: applied.tunnel.message.includes('не означает'),
}));
""",
    )
    assert result["trafficState"] == "WARNING"
    assert result["emptyTrafficState"] == "WARNING"
    assert "обход него" in result["trafficMessage"]
    assert "Переподключить" in result["trafficMessage"]
    assert "ip global" not in result["trafficMessage"]
    assert "ip global" in result["trafficTechnicalDetail"]
    assert "адрес туннеля" not in result["trafficMessage"]
    assert result["configHub"] != "SUCCESS"
    assert result["tunnelHub"] != "SUCCESS"
    assert result["deceptiveInConfig"] is False
    assert result["deceptiveInTunnel"] is False
    assert result["trafficMessage"]
    assert "configuration_verification_status" in result["technical"]
    assert "interface_up_not_evidence" not in result["configMessage"]
    assert "приняты роутером" not in result["configMessage"]
    assert "не подтвердила" in result["configMessage"]
    assert result["tunnelHealthyQualifier"] is True


def test_vpn_screen_exports_meta_and_render() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "export const meta" in source
    assert "id: 'vpn'" in source
    assert "export function render(container, ctx)" in source
    assert "return () => {" in source
    assert "renderStubScreen" not in source


def test_vpn_screen_honesty_forbidden_literals() -> None:
    source = _read(VPN_SCREEN_JS)
    for literal in FORBIDDEN_VPN_LITERALS:
        assert literal not in source, f"forbidden literal: {literal}"
    assert "Безопасное подключение" not in source


def test_vpn_screen_required_api_paths() -> None:
    source = _read(VPN_SCREEN_JS) + "\n" + _read(VPN_MODEL_JS)
    for path in REQUIRED_API_PATHS:
        assert path in source, f"missing API path: {path}"


def test_vpn_screen_three_status_line_labels() -> None:
    source = _read(VPN_SCREEN_JS) + "\n" + _read(VPN_MODEL_JS)
    for label in STATUS_LINE_LABELS:
        assert label in source, f"missing status label: {label}"


def test_vpn_screen_unsupported_blocks_without_controls() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "createUnsupportedCard" in source
    assert "VPN_TRAFFIC_DIRECTION_OPTIONS" not in source
    assert "renderDirectionUnsupportedCard" not in source
    assert "buildVpnProtectionOptions" in source
    assert "VPN_KILL_SWITCH_UNSUPPORTED_NOTE" in source
    assert "apiGet('status'" in source or 'apiGet("status"' in source
    assert "let watchdogEnabled = null" in source
    assert "watchdogEnabled = null" in source
    assert '<input type="radio"' not in source
    assert "type: 'radio'" not in source


def test_vpn_screen_risk_modal_for_mutations() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "openVpnRiskModal" in source
    assert "buildRiskModalBody" in source
    for action in RISK_MODAL_ACTIONS:
        assert f"'{action}'" in source


def test_vpn_screen_clears_textarea_after_parse() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "textareaEl.value = ''" in source
    assert "parseVpnProfileText" in source


def test_vpn_screen_handshake_wait_message() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "VPN_HANDSHAKE_WAIT_MESSAGE" in source
    assert "HubState.CONNECTING" in source
    assert "clearOutcomesForWgId" in source
    assert "clearOutcomesForSelectionChange" not in source


def _assert_vpn_screen_intent_confirm_pattern(source: str) -> None:
    assert re.search(
        r"function assertConfirmedIntentStillValid\(\s*confirmedSnapshot\s*,",
        source,
    )
    intent_body = re.search(
        r"function assertConfirmedIntentStillValid\([^)]+\)\s*\{([\s\S]*?\n  \})",
        source,
        re.DOTALL,
    )
    assert intent_body is not None
    assert "confirmedIntentSnapshot" not in intent_body.group(1)
    confirm_handler = re.search(
        r"const confirmBtn = createButton\(\{[\s\S]*?onActivate: \(\) => \{([\s\S]*?\n      \},)",
        source,
    )
    assert confirm_handler is not None
    assert "const confirmedSnapshot = confirmedIntentSnapshot" in confirm_handler.group(1)
    assert "modalRef?.close()" in confirm_handler.group(1)
    close_idx = confirm_handler.group(1).index("modalRef?.close()")
    snapshot_idx = confirm_handler.group(1).index(
        "const confirmedSnapshot = confirmedIntentSnapshot",
    )
    assert snapshot_idx < close_idx
    assert "assertConfirmedIntentStillValid(confirmedSnapshot," in confirm_handler.group(1)
    after_assert = confirm_handler.group(1).split("assertConfirmedIntentStillValid", 1)[-1]
    assert "confirmedIntentSnapshot)" not in after_assert


def test_vpn_screen_risk_modal_confirms_with_local_snapshot() -> None:
    """Подтверждение риска захватывает snapshot до close модалки."""
    _assert_vpn_screen_intent_confirm_pattern(_read(VPN_SCREEN_JS))


def test_vpn_screen_stale_intent_guard_mutation_self_check() -> None:
    """Чтение confirmedIntentSnapshot после close ломает контракт подтверждения."""
    source = _read(VPN_SCREEN_JS)
    mutated = source.replace(
        (
            "if (!confirmedSnapshot || !assertConfirmedIntentStillValid"
            "(confirmedSnapshot, action)) {"
        ),
        (
            "if (!confirmedIntentSnapshot || !assertConfirmedIntentStillValid"
            "(confirmedIntentSnapshot, action)) {"
        ),
        1,
    )
    with pytest.raises(AssertionError):
        _assert_vpn_screen_intent_confirm_pattern(mutated)


def test_vpn_screen_wg_select_preserves_outcomes_on_round_trip() -> None:
    """Переключение интерфейса не очищает сохранённые outcomes по wgId."""
    source = _read(VPN_SCREEN_JS)
    wg_select = re.search(
        r"id: 'hub-vpn-wg-select'[\s\S]*?"
        r"onChange: \(event\) => \{([\s\S]*?\n      \}\s*,)",
        source,
    )
    assert wg_select is not None
    assert "clearOutcomesForWgId" not in wg_select.group(1)
    assert "clearOutcomesForSelectionChange" not in wg_select.group(1)


def test_vpn_screen_wg_select_syncs_to_single_active_profile_when_untouched() -> None:
    """AC-2: selectedWgId syncs to the one active+assigned profile only when untouched and unlocked."""
    source = _read(VPN_SCREEN_JS)
    assert "wgIdUserTouched" in source
    load_flow = re.search(
        r"async function loadCatalogFlow\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert load_flow is not None
    body = load_flow.group(1)
    assert "activeWithWg.length === 1" in body
    assert "!wgIdUserTouched" in body
    assert "!controlsLocked()" in body
    assert "is_active !== true" in body
    assert "assigned_wg_id" in body
    assert re.search(
        r"if \(\s*activeWithWg\.length === 1\s*&&\s*!wgIdUserTouched\s*&&\s*!controlsLocked\(\)\s*\)",
        body,
    )
    onchange = re.search(
        r"id: 'hub-vpn-wg-select'[\s\S]*?onChange: \(event\) => \{([\s\S]*?\n      \}\s*,)",
        source,
    )
    assert onchange is not None
    assert "wgIdUserTouched = true" in onchange.group(1)


def test_vpn_screen_syntax_via_mjs_copy(tmp_path: Path) -> None:
    node = _require_node()
    mjs_copy = tmp_path / "vpn-screen.mjs"
    mjs_copy.write_text(_read(VPN_SCREEN_JS), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_vpn_sw_precache_and_cache_version() -> None:
    source = _read(SW_JS)
    assert "features/vpn-model.js" in source
    assert "features/domain-model.js" in source
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None
    assert int(version_match.group(1)) >= 10


def test_wifi_demo_banner_link_inside_sentence() -> None:
    source = _read(WIFI_SCREEN_PARTS_JS)
    assert "createDemoBanner" in source
    assert "connectionHintPrefix" in source
    assert "hint.appendChild(document.createTextNode(connectionHintPrefix))" in source
    assert "hub-wifi__demo-link-row" not in source


def test_guest_wifi_single_qr_button_construction() -> None:
    """Один литерал «Показать QR-код» в guest-wifi; VPN и quote-style не покрывает."""
    source = _read(HUB / "screens" / "guest-wifi.js")
    assert len(re.findall(r"label:\s*['\"]Показать QR-код['\"]", source)) == 1


@pytest.mark.parametrize(
    "js_path",
    sorted(HUB.rglob("*.js")),
    ids=lambda p: p.relative_to(HUB).as_posix(),
)
def test_hub_js_no_literal_sentence_glue(js_path: Path) -> None:
    """Регрессия: два кириллических литерала подряд через + без разделителя.

    Не ловит склейку через переменные и не проверяет семантику UI-текста.
    """
    source = _read(js_path)
    for pattern in ALLOWED_SENTENCE_GLUE_PATTERNS:
        source = source.replace(pattern, "")
    matches = SENTENCE_GLUE_RE.findall(source)
    assert not matches, f"{js_path.relative_to(HUB)}: suspicious glue {matches[:3]}"


def test_vpn_screen_catalog_refresh_keeps_list_when_items_exist() -> None:
    """AC-1: skeleton только при первой загрузке; refetch показывает «Обновляем»."""
    source = _read(VPN_SCREEN_JS)
    catalog_body = re.search(
        r"function renderCatalogCardBody\(body\) \{([\s\S]*?\n  \})",
        source,
    )
    assert catalog_body is not None
    body_src = catalog_body.group(1)
    assert "catalogItems.length === 0 && !catalogLoaded" in body_src
    assert "VPN_CATALOG_REFRESH_MESSAGE" in body_src
    assert "VPN_CATALOG_INITIAL_LOAD_MESSAGE" in body_src
    skeleton_branch = re.search(
        r"if \(catalogLoading && catalogItems\.length === 0 && !catalogLoaded\)",
        body_src,
    )
    refresh_branch = re.search(
        r"if \(catalogLoading \|\| catalogRefreshing\)",
        body_src,
    )
    assert skeleton_branch is not None
    assert refresh_branch is not None
    assert skeleton_branch.start() < refresh_branch.start()


def test_vpn_screen_load_catalog_flow_sets_refreshing() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "catalogRefreshing = isRefresh" in source
    assert "const isRefresh = catalogItems.length > 0 || catalogLoaded" in source


def test_vpn_screen_activate_deactivate_set_mutating_and_long_op_kind() -> None:
    source = _read(VPN_SCREEN_JS)
    activate = re.search(
        r"async function runActivateProfile\(profileId\) \{([\s\S]*?\n  \})",
        source,
    )
    deactivate = re.search(
        r"async function runDeactivateProfile\(profileId\) \{([\s\S]*?\n  \})",
        source,
    )
    assert activate is not None
    assert deactivate is not None
    assert "mutating = true" in activate.group(1)
    assert "longOpKind = 'activate'" in activate.group(1)
    assert "mutating = true" in deactivate.group(1)
    assert "longOpKind = 'deactivate'" in deactivate.group(1)
    assert "busyProfileIds: activatingProfileIds" in source
    assert "deactivatingProfileIds" in source


def test_vpn_screen_activate_toast_gated_on_activated_flag() -> None:
    """AC-1/AC-4/AC-5: activate toast honesty — success only when healthy or no status."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runActivateProfile(")
    assert body is not None
    assert "const response = await activateVpnProfile(" in body
    assert "response?.activated === true" in body
    activated_branch = body.split("response?.activated === true", 1)[1].split(
        "title: 'Не активирован'", 1,
    )[0]
    assert "tunnel_verification_status" in activated_branch
    assert "tunnel_healthy" in activated_branch
    unhealthy_idx = activated_branch.find("!tunnelHealthy")
    success_idx = activated_branch.find("tone: 'success'")
    assert unhealthy_idx != -1 and success_idx != -1
    assert unhealthy_idx < success_idx
    unhealthy_branch = activated_branch.split("!tunnelHealthy", 1)[1].split("} else {", 1)[0]
    assert "tone: 'warning'" in unhealthy_branch
    assert "Профиль активирован, ответ сервера не подтверждён" in unhealthy_branch
    assert "tone: 'success'" not in unhealthy_branch
    healthy_branch = activated_branch.split("} else {", 1)[1]
    assert "tone: 'success'" in healthy_branch
    assert "title: 'Профиль активирован'" in healthy_branch
    assert "title: 'Не активирован'" in body
    assert "describeConfigurationOutcome" not in body


def test_vpn_screen_deactivate_resolves_wg_id_from_profile() -> None:
    """Catalog deactivate must use resolveVpnProfileWgId without selectedWgId fallback."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runDeactivateProfile(")
    assert body is not None
    assert "const wgId = resolveVpnProfileWgId(catalogItems, profileId)" in body
    assert "VPN_PROFILE_WG_ID_MISSING_MESSAGE" in body
    deactivate_section = body.split(
        "const wgId = resolveVpnProfileWgId(catalogItems, profileId)", 1
    )[1]
    deactivate_call = deactivate_section.split("deactivateVpnProfile(", 1)[1].split("});", 1)[0]
    assert "wgId" in deactivate_call
    assert "wgId: selectedWgId" not in deactivate_call
    assert "selectedWgId" not in deactivate_call


def test_vpn_screen_activate_resolves_wg_id_from_profile() -> None:
    """Catalog activate must use resolveVpnProfileWgId without selectedWgId fallback."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runActivateProfile(")
    assert body is not None
    assert "const wgId = resolveVpnProfileWgId(catalogItems, profileId)" in body
    assert "VPN_PROFILE_WG_ID_MISSING_MESSAGE" in body
    activate_section = body.split(
        "const wgId = resolveVpnProfileWgId(catalogItems, profileId)", 1
    )[1]
    activate_call = activate_section.split("activateVpnProfile(", 1)[1].split("});", 1)[0]
    assert "wgId" in activate_call
    assert "wgId: selectedWgId" not in activate_call
    assert "selectedWgId" not in activate_call


def test_vpn_screen_deactivate_toast_gated_on_deactivated_flag() -> None:
    """AC-2/AC-4/AC-5: runDeactivateProfile success toast only when deactivated === true."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runDeactivateProfile(")
    assert body is not None
    assert "const response = await deactivateVpnProfile(" in body
    assert "response?.deactivated === true" in body
    success_branch = body.split("response?.deactivated === true", 1)[1].split("} else {", 1)[0]
    assert "tone: 'success'" in success_branch
    assert "title: 'Не отключён'" in body
    assert "tone: 'warning'" in body
    assert "describeConfigurationOutcome" not in body


def test_vpn_screen_validate_toast_gated_on_validation_status() -> None:
    """AC1/AC2/AC4: validateCatalogProfile success toast only when validation_status === 'Valid'."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function validateCatalogProfile(")
    assert body is not None
    assert "const response = await validateVpnProfile(" in body
    assert "validation_status" in body
    assert "=== 'Valid'" in body
    success_branch = body.split("=== 'Valid'", 1)[1].split("} else {", 1)[0]
    assert "tone: 'success'" in success_branch
    assert "title: 'Проверка завершена'" in success_branch
    non_valid_branch = body.split("} else {", 1)[1].split("await loadCatalogFlow()", 1)[0]
    assert "tone: 'success'" not in non_valid_branch
    assert "tone: 'warning'" in non_valid_branch
    assert "title: 'Проверка не пройдена'" in non_valid_branch
    assert "describeVpnProfileItem" in non_valid_branch


def test_vpn_screen_mutation_phase_only_discrete_awaits() -> None:
    """mutationPhase — только reconnect_teardown|preview|apply|teardown."""
    source = _read(VPN_SCREEN_JS)
    assignments = re.findall(
        r"mutationPhase\s*=\s*['\"]([^'\"]+)['\"]",
        source,
    )
    allowed = {"reconnect_teardown", "preview", "apply", "teardown", "null"}
    for value in assignments:
        assert value in allowed, f"unexpected mutationPhase assignment: {value}"
    forbidden = re.findall(
        r"mutationPhase\s*=\s*['\"](?:settle|readback|done)[^'\"]*['\"]",
        source,
        re.IGNORECASE,
    )
    assert not forbidden


def test_vpn_screen_scroll_restore_uses_hub_content() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "getElementById('hub-content')" in source
    assert "captureHubContentScroll" in source
    assert "restoreHubContentScroll" in source
    assert "contentWrap.scrollTop" not in source


def test_vpn_screen_observe_progress_not_handshake() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "VPN_OBSERVE_PROGRESS_MESSAGE" in source
    observe_block = re.search(
        r"if \(observing && !connecting\) \{([\s\S]*?\n    \})",
        source,
    )
    assert observe_block is not None
    assert "VPN_OBSERVE_PROGRESS_MESSAGE" in observe_block.group(1)
    assert "VPN_HANDSHAKE_WAIT_MESSAGE" not in observe_block.group(1)
    assert "HubState.CONNECTING" not in observe_block.group(1)
    run_observe = re.search(
        r"async function runObserveRecheck\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert run_observe is not None
    assert "longOpKind = 'observe'" in run_observe.group(1)
    assert "VPN_HANDSHAKE_WAIT_MESSAGE" not in run_observe.group(1)


def test_vpn_screen_no_clear_element_content_wrap_on_render() -> None:
    source = _read(VPN_SCREEN_JS)
    render_content = re.search(
        r"function renderContent\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert render_content is not None
    assert "clearElement(contentWrap)" not in render_content.group(1)
    assert "renderCatalogSlot" in render_content.group(1)
    assert "renderStatusSlot" in render_content.group(1)


def test_vpn_screen_wg_select_does_not_render_catalog() -> None:
    source = _read(VPN_SCREEN_JS)
    wg_select = re.search(
        r"id: 'hub-vpn-wg-select'[\s\S]*?"
        r"onChange: \(event\) => \{([\s\S]*?\n      \}\s*,)",
        source,
    )
    assert wg_select is not None
    assert "renderCatalogSlot" not in wg_select.group(1)
    assert "renderAll()" not in wg_select.group(1)


def test_vpn_screen_catalog_buttons_have_stable_focus_ids() -> None:
    """Catalog action buttons get hub-vpn-* id prefixes for focus restore."""
    model_src = _read(VPN_MODEL_JS)
    screen_src = _read(VPN_SCREEN_JS)
    assert "hub-vpn-validate-${profileId}" in model_src
    assert "hub-vpn-activate-${profileId}" in model_src
    assert "hub-vpn-deactivate-${profileId}" in model_src
    assert "hub-vpn-activate-${profileId}" in screen_src
    rebuild_slot = re.search(
        r"function rebuildSlot\(slot, rebuild\) \{([\s\S]*?\n  \})",
        screen_src,
    )
    assert rebuild_slot is not None
    assert "pendingFocus = { kind: 'element-id', id: active.id }" in rebuild_slot.group(1)


def test_vpn_screen_uses_tile_grid_export() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "createVpnProfileStatusTileGrid" in source
    assert "fetchVpnCatalogLiveStatus" in source
    assert "describeVpnProfileTileStatus" in source
    assert "hub-vpn__tile-grid" in _read(VPN_MODEL_JS)
    assert "runActivateProfile" in source
    assert "activateVpnProfile" in source


def test_vpn_model_exports_tile_grid_helpers() -> None:
    source = _read(VPN_MODEL_JS)
    assert "export function createVpnProfileStatusTileGrid" in source
    assert "export function describeVpnProfileTileStatus" in source
    assert "export function fetchVpnCatalogLiveStatus" in source
    assert "hub-vpn__tile-grid" in source
    assert "hub-vpn-activate-${profileId}" in source


def test_vpn_screen_disconnect_toast_overall_first() -> None:
    """Disconnect toast branches on response.overall; applied shows success without health gate."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runTunnelMutation(")
    assert body is not None
    disconnect_idx = body.find("if (action === 'disconnect') {")
    assert disconnect_idx != -1
    disconnect_region = body[disconnect_idx:]
    reconnect_else_idx = disconnect_region.find("} else {\n        if (action === 'reconnect')")
    assert reconnect_else_idx != -1
    disconnect_only = disconnect_region[:reconnect_else_idx]
    assert "const response = await teardownVpnTunnel(" in disconnect_only
    post_teardown = disconnect_only.split(
        "const response = await teardownVpnTunnel(", 1,
    )[1]
    post_teardown = post_teardown.split("storeMutationOutcome(wgId, response);", 1)[1]
    assert re.search(r"response\?\.overall|typeof response\?\.overall", post_teardown)
    assert "overall !== 'applied'" in post_teardown
    assert "describeConfigurationOutcome(response)" in post_teardown
    assert "getStateDescriptor(outcome.hubState).tone" in post_teardown
    assert "tunnel_healthy" not in disconnect_only
    non_applied_branch = post_teardown.split("overall !== 'applied'", 1)[1].split("} else", 1)[0]
    assert "describeConfigurationOutcome" in non_applied_branch
    assert "Туннель отключён, ответ сервера не подтверждён" not in non_applied_branch
    assert "tone: 'success'" not in non_applied_branch
    assert "tone: 'primary'" not in non_applied_branch
    applied_region = post_teardown.split("} else", 1)[1]
    assert "Туннель отключён, ответ сервера не подтверждён" not in applied_region
    assert "Отключено" in applied_region
    assert "tone: 'success'" in applied_region


def test_vpn_screen_connect_toast_overall_first() -> None:
    """AC1–AC5: connect/reconnect toast branches on response.overall before tunnel health."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runTunnelMutation(")
    assert body is not None
    assert "const response = await applyVpnTunnel(" in body
    assert "getStateDescriptor" in source
    post_apply = body.split("const response = await applyVpnTunnel(", 1)[1]
    post_apply = post_apply.split("storeMutationOutcome(wgId, response);", 1)[1]
    assert re.search(r"response\?\.overall|typeof response\?\.overall", post_apply)
    assert "overall !== 'applied'" in post_apply
    assert "describeConfigurationOutcome(response)" in post_apply
    assert "getStateDescriptor(outcome.hubState).tone" in post_apply
    overall_idx = post_apply.find("overall !== 'applied'")
    healthy_idx = post_apply.find("tunnel_healthy")
    assert overall_idx != -1 and healthy_idx != -1
    assert overall_idx < healthy_idx
    non_applied_branch = post_apply.split("overall !== 'applied'", 1)[1].split("} else", 1)[0]
    assert "describeConfigurationOutcome" in non_applied_branch
    assert "Туннель применён, ответ сервера не подтверждён" not in non_applied_branch
    assert "tone: 'success'" not in non_applied_branch
    assert "tone: 'primary'" not in non_applied_branch
    applied_region = post_apply.split("} else", 1)[1]
    assert "Туннель применён, ответ сервера не подтверждён" in applied_region
    assert "tunnel_healthy" in applied_region


def test_vpn_screen_reconnect_teardown_failure_does_not_continue() -> None:
    """Reconnect teardown errors abort before preview/apply; no empty catch."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runTunnelMutation(")
    assert body is not None
    assert "optional teardown before reconnect" not in body
    first_teardown = body.find("mutationPhase = 'reconnect_teardown'")
    reconnect_teardown_idx = body.find("mutationPhase = 'reconnect_teardown'", first_teardown + 1)
    assert reconnect_teardown_idx != -1
    preview_idx = body.find("mutationPhase = 'preview'", reconnect_teardown_idx)
    assert preview_idx != -1
    reconnect_region = body[reconnect_teardown_idx:preview_idx]
    assert "await teardownVpnTunnel({" in reconnect_region
    assert "} catch (error) {" in reconnect_region
    assert "isAborted(error)" in reconnect_region
    assert "operationError = error" in reconnect_region
    assert "ctx.showToast(" in reconnect_region
    assert re.search(r"tone:\s*'danger'", reconnect_region)
    catch_start = reconnect_region.find("} catch (error) {")
    catch_block = reconnect_region[catch_start:]
    assert "return;" in catch_block
    assert "mutationPhase = 'preview'" not in catch_block


def test_vpn_screen_reconnect_teardown_overall_gates_preview_apply() -> None:
    """Non-applied reconnect teardown overall aborts before preview/apply."""
    source = _read(VPN_SCREEN_JS)
    body = _extract_function_body(source, "async function runTunnelMutation(")
    assert body is not None
    first_teardown = body.find("mutationPhase = 'reconnect_teardown'")
    reconnect_teardown_idx = body.find("mutationPhase = 'reconnect_teardown'", first_teardown + 1)
    assert reconnect_teardown_idx != -1
    preview_idx = body.find("mutationPhase = 'preview'", reconnect_teardown_idx)
    assert preview_idx != -1
    reconnect_region = body[reconnect_teardown_idx:preview_idx]
    assert "await teardownVpnTunnel({" in reconnect_region
    assert re.search(r"teardownResponse\?\.overall|typeof teardownResponse\?\.overall", reconnect_region)
    assert "teardownOverall !== 'applied'" in reconnect_region
    assert "storeMutationOutcome(wgId, teardownResponse)" in reconnect_region
    assert "describeConfigurationOutcome(teardownResponse)" in reconnect_region
    overall_idx = reconnect_region.find("teardownOverall !== 'applied'")
    return_idx = reconnect_region.find("return;", overall_idx)
    assert overall_idx != -1 and return_idx != -1
    assert overall_idx < return_idx
    assert "previewVpnTunnel(" not in reconnect_region
    assert "applyVpnTunnel(" not in reconnect_region


def test_vpn_screen_connect_handshake_only_on_apply_phase() -> None:
    """AC-2: handshake message only when mutationPhase === 'apply', not bare connecting."""
    source = _read(VPN_SCREEN_JS)
    progress_fn = re.search(
        r"function mutationProgressMessage\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert progress_fn is not None
    body = progress_fn.group(1)
    assert re.search(
        r"if \(mutationPhase === 'apply'\) \{\s*\n\s*return VPN_HANDSHAKE_WAIT_MESSAGE;",
        body,
    )
    assert "mutationPhase === 'apply' || connecting" not in body
    run_mutation = re.search(
        r"async function runTunnelMutation\(action\) \{([\s\S]*?\n  \})",
        source,
    )
    assert run_mutation is not None
    assert "mutationPhase = 'preview'" in run_mutation.group(1)
    assert "mutationPhase = 'reconnect_teardown'" in run_mutation.group(1)


def test_vpn_screen_footer_signature_skips_full_rebuild() -> None:
    """AC-3: footer uses buildFooterSignature / lastFooterSignature."""
    source = _read(VPN_SCREEN_JS)
    assert "buildFooterSignature" in source
    assert "lastFooterSignature" in source
    render_footer = re.search(
        r"function renderFooter\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert render_footer is not None
    footer_body = render_footer.group(1)
    assert "signature === lastFooterSignature" in footer_body
    assert "syncFooterButtonsInPlace" in footer_body
    assert "syncActionButtonById" in source


def test_vpn_screen_footer_structure_signature_includes_offline() -> None:
    """AC-3: offline flip forces full footer rebuild (reason text), not in-place sync."""
    source = _read(VPN_SCREEN_JS)
    footer_struct = re.search(
        r"function footerStructureSignature\(signature\) \{([\s\S]*?\n  \})",
        source,
    )
    assert footer_struct is not None
    body = footer_struct.group(1)
    assert "parts.slice(7)" in body
    assert "parts.slice(8)" not in body
    assert re.search(r"7\s+offline", source)


def test_vpn_screen_catalog_error_keeps_list_when_items_exist() -> None:
    """catalogError with populated items keeps tile grid render, not error-only early return."""
    source = _read(VPN_SCREEN_JS)
    catalog_body = re.search(
        r"function renderCatalogCardBody\(body\) \{([\s\S]*?\n  \})",
        source,
    )
    assert catalog_body is not None
    body_src = catalog_body.group(1)
    error_branch = re.search(
        r"if \(catalogError && !isAborted\(catalogError\)\) \{([\s\S]*?\n    \})",
        body_src,
    )
    assert error_branch is not None
    error_src = error_branch.group(1)
    assert "catalogItems.length === 0" in error_src
    grid_render = re.search(r"createVpnProfileStatusTileGrid\(", body_src)
    assert grid_render is not None
    assert error_branch.start() < grid_render.start()
    assert re.search(
        r"if \(catalogItems\.length === 0\) \{\s*\n\s*return;\s*\n\s*\}",
        error_src,
    )


def test_vpn_screen_catalog_detail_enrichment_contract() -> None:
    """Каталог обогащается GET detail; отдельный abort; digest включает enrich."""
    source = _read(VPN_SCREEN_JS)
    assert "getVpnProfile" in source
    assert "startEnrichCatalogDetails" in source
    assert "startEnrichCatalogLiveStatus" in source
    assert "fetchVpnCatalogLiveStatus" in source
    assert "catalogLiveStatusById" in source
    assert "catalogLiveStatusAbort" in source
    assert "catalogDetailsById" in source
    assert "catalogEnrichAbort" in source
    assert "Promise.allSettled" in source
    assert "projectVpnProfileDetailForCatalog" in source
    load_flow = re.search(
        r"async function loadCatalogFlow\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert load_flow is not None
    assert "catalogEnrichAbort?.abort()" in load_flow.group(1)
    assert "startEnrichCatalogDetails(gen)" in load_flow.group(1)
    assert "startEnrichCatalogLiveStatus(gen)" in load_flow.group(1)
    digest = re.search(
        r"function catalogItemsDigest\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert digest is not None
    assert "enrich:ready" in digest.group(1)
    assert "describeVpnProfileKeepalive" in digest.group(1)
    assert "describeVpnProfileTileStatus" in digest.group(1)
    assert "extractVpnProfileOperatorNotes" in digest.group(1)


def test_vpn_screen_catalog_live_status_projection_active_only() -> None:
    """Live cache и checking применяются только к активному профилю."""
    source = _read(VPN_SCREEN_JS)
    project_fn = re.search(
        r"function projectCatalogTileItem\(item\) \{([\s\S]*?\n  \})",
        source,
    )
    assert project_fn is not None
    body = project_fn.group(1)
    assert "isActive" in body
    assert "isActive && profileId" in body
    assert "checking: isActive && catalogLiveChecking" in body
    live_fn = re.search(
        r"async function startEnrichCatalogLiveStatus\(gen\) \{([\s\S]*?\n  \})",
        source,
    )
    assert live_fn is not None
    live_body = live_fn.group(1)
    assert re.search(
        r"catalogLiveStatusById\s*=\s*\{\};",
        live_body,
    )
    assert "activeProfileIds" in live_body


def test_vpn_screen_catalog_keepalive_note_when_ready() -> None:
    """hub-vpn__note для keepalive только при enrich status ready."""
    source = _read(VPN_SCREEN_JS)
    catalog_body = re.search(
        r"function renderCatalogCardBody\(body\) \{([\s\S]*?\n  \})",
        source,
    )
    assert catalog_body is not None
    body_src = catalog_body.group(1)
    assert "enrichEntry?.status === 'ready'" in body_src
    assert "hub-vpn__note" in body_src
    assert "describeVpnProfileKeepalive" in body_src
    assert "extractVpnProfileOperatorNotes" in body_src
    assert "HubState.SUCCESS" not in body_src


def test_vpn_screen_catalog_enrich_no_pending_wipe_before_settle() -> None:
    """startEnrichCatalogDetails сохраняет prior ready до commit после settle."""
    source = _read(VPN_SCREEN_JS)
    enrich_fn = re.search(
        r"async function startEnrichCatalogDetails\(gen\) \{([\s\S]*?\n  \})",
        source,
    )
    assert enrich_fn is not None
    body = enrich_fn.group(1)
    allsettled = re.search(r"Promise\.allSettled\(tasks\)", body)
    assert allsettled is not None
    before_settle = body[: allsettled.start()]
    assert "catalogDetailsById = nextDetails" not in before_settle
    assert re.search(
        r"nextDetails\[[^\]]+\]\s*=\s*\{\s*status:\s*'pending'\s*\}",
        before_settle,
    ) is None
    after_settle = body[allsettled.end() :]
    assert "catalogDetailsById = nextDetails" in after_settle
    assert re.search(
        r"if \(disposed \|\| gen !== catalogGeneration \|\| signal\.aborted\) \{\s*\n\s*return;\s*\n\s*\}",
        after_settle,
    )
    assert after_settle.index("catalogDetailsById = nextDetails") < after_settle.index(
        "renderCatalogSlot()"
    )


def test_vpn_screen_catalog_enrich_no_absent_on_failed() -> None:
    """failed/pending enrich не показывает «не указана» для keepalive."""
    source = _read(VPN_SCREEN_JS)
    catalog_body = re.search(
        r"function renderCatalogCardBody\(body\) \{([\s\S]*?\n  \})",
        source,
    )
    assert catalog_body is not None
    body_src = catalog_body.group(1)
    enrich_block = re.search(
        r"for \(const item of catalogItems\) \{([\s\S]*?\n    \})",
        body_src,
    )
    assert enrich_block is not None
    block = enrich_block.group(1)
    assert "status === 'ready'" in block
    assert "status === 'failed'" not in block
    assert "status === 'pending'" not in block


def test_vpn_screen_catalog_remove_modal_before_api() -> None:
    """Catalog remove opens modal before removeVpnProfileFromCatalog."""
    source = _read(VPN_SCREEN_JS)
    assert "openCatalogRemoveModal" in source
    assert "removeVpnProfileFromCatalog" in source
    assert "VPN_CATALOG_REMOVE_CONFIRM_TITLE" in source
    assert "VPN_CATALOG_REMOVE_CONFIRM_LEAD" in source
    modal_block = re.search(
        r"function openCatalogRemoveModal\(profileId\) \{([\s\S]*?\n  \})",
        source,
    )
    assert modal_block is not None
    block = modal_block.group(1)
    assert "openModal" in block
    assert "removeVpnProfileFromCatalog" not in block
    remove_fn = re.search(
        r"async function runRemoveCatalogProfile\(profileId\) \{([\s\S]*?\n  \})",
        source,
    )
    assert remove_fn is not None
    assert "removeVpnProfileFromCatalog" in remove_fn.group(1)
    assert "loadCatalogFlow" in remove_fn.group(1)
    assert "deactivateVpnProfile" not in remove_fn.group(1)


def test_vpn_screen_catalog_remove_active_guard() -> None:
    """Active profile path shows refuse text without calling remove API from modal open."""
    source = _read(VPN_SCREEN_JS)
    modal_block = re.search(
        r"function openCatalogRemoveModal\(profileId\) \{([\s\S]*?\n  \})",
        source,
    )
    assert modal_block is not None
    assert "is_active === true" in modal_block.group(1)
    assert "VPN_CATALOG_REMOVE_ACTIVE_REFUSE" in modal_block.group(1)


def test_vpn_screen_catalog_remove_button_focus_id() -> None:
    source = _read(VPN_SCREEN_JS)
    assert "hub-vpn-remove-" in source
    assert "onRemove:" in source


def test_vpn_screen_build_catalog_signature_includes_offline() -> None:
    """AC3: buildCatalogSignature includes offline so catalog tiles rebuild on flip."""
    source = _read(VPN_SCREEN_JS)
    sig_fn = re.search(
        r"function buildCatalogSignature\(\) \{([\s\S]*?\n  \})",
        source,
    )
    assert sig_fn is not None
    body = sig_fn.group(1)
    assert "offline ? 'offline' : 'online'" in body
    assert "controlsLocked()" in body


def test_vpn_screen_controls_locked_does_not_include_offline() -> None:
    """AC1: offline stays separate from controlsLocked (footer copy vs busy copy)."""
    source = _read(VPN_SCREEN_JS)
    locked_body = _extract_function_body(source, "function controlsLocked(")
    assert locked_body is not None
    assert "offline" not in locked_body


def test_vpn_screen_catalog_tile_grid_disabled_includes_offline() -> None:
    """AC1: catalog tile grid disabled uses controlsLocked() || offline."""
    source = _read(VPN_SCREEN_JS)
    catalog_body = re.search(
        r"function renderCatalogCardBody\(body\) \{([\s\S]*?\n  \})",
        source,
    )
    assert catalog_body is not None
    assert "disabled: controlsLocked() || offline" in catalog_body.group(1)


def test_vpn_screen_catalog_runners_gate_offline() -> None:
    """AC2/AC6: catalog mutation runners early-return on offline before API."""
    source = _read(VPN_SCREEN_JS)
    activate = _extract_function_body(source, "async function runActivateProfile(")
    deactivate = _extract_function_body(source, "async function runDeactivateProfile(")
    validate = _extract_function_body(source, "async function validateCatalogProfile(")
    remove = _extract_function_body(source, "async function runRemoveCatalogProfile(")
    assert activate is not None
    assert deactivate is not None
    assert validate is not None
    assert remove is not None
    assert re.search(r"if \([^)]*\|\|\s*offline\s*\)", activate)
    assert re.search(r"if \([^)]*\|\|\s*offline\s*\)", deactivate)
    assert re.search(r"if \([^)]*\|\|\s*offline\s*\)", validate)
    assert re.search(r"if \([^)]*\|\|\s*offline\s*\)", remove)
    assert activate.find("offline") < activate.find("activateVpnProfile(")
    assert deactivate.find("offline") < deactivate.find("deactivateVpnProfile(")
    assert validate.find("offline") < validate.find("validateVpnProfile(")
    assert remove.find("offline") < remove.find("removeVpnProfileFromCatalog(")


def test_vpn_screen_recheck_disabled_includes_offline() -> None:
    """Recheck runner and button disabled state include offline before observe API."""
    source = _read(VPN_SCREEN_JS)
    run_observe = _extract_function_body(source, "async function runObserveRecheck(")
    assert run_observe is not None
    assert "offline" in run_observe.split("observing = true", maxsplit=1)[0]
    status_row = re.search(
        r"const recheckDisabled =([\s\S]*?);\s*\n\s*const recheckBtn",
        source,
    )
    assert status_row is not None
    assert "offline" in status_row.group(1)


def test_vpn_screen_import_load_config_gates_offline_and_can_prepare() -> None:
    """Import/load config paths gate offline and canPrepareProfile before parse/import."""
    source = _read(VPN_SCREEN_JS)
    open_import = _extract_function_body(source, "function openImportModal(")
    assert open_import is not None
    open_guard = open_import.split("importModalOpen = true", maxsplit=1)[0]
    assert "offline" in open_guard
    assert "canPrepareProfile" in open_guard

    active_cfg = _extract_function_body(source, "function renderActiveConfigurationCard(")
    assert active_cfg is not None
    assert "canPrepareProfile" in active_cfg
    assert "Загрузить конфигурацию" in active_cfg

    run_parse = re.search(
        r"async function runParseProfile\(\) \{([\s\S]*?\n    \})",
        source,
    )
    assert run_parse is not None
    parse_body = run_parse.group(1)
    parse_guard = parse_body.split("parseVpnProfileText(", maxsplit=1)[0]
    assert "offline" in parse_guard
    assert "canPrepareProfile" in parse_guard

    run_import = re.search(
        r"async function runCatalogImport\(\) \{([\s\S]*?\n    \})",
        source,
    )
    assert run_import is not None
    import_body = run_import.group(1)
    import_guard = import_body.split("importVpnProfileToCatalog(", maxsplit=1)[0]
    assert "offline" in import_guard
    assert "canPrepareProfile" in import_guard


def test_vpn_screen_parse_clears_textarea_only_after_success() -> None:
    """Textarea clear happens only on successful parse path, after parseVpnProfileText."""
    source = _read(VPN_SCREEN_JS)
    run_parse = re.search(
        r"async function runParseProfile\(\) \{([\s\S]*?\n    \})",
        source,
    )
    assert run_parse is not None
    body = run_parse.group(1)
    parse_call = body.find("parseVpnProfileText(")
    clear_idx = body.find("textareaEl.value = ''")
    assert parse_call != -1
    assert clear_idx != -1
    assert clear_idx > parse_call
    assert "textareaEl.value = ''" not in body[:parse_call]


def _extract_subscribe_connectivity_callback(source: str) -> str:
    """Извлекает тело subscribeConnectivity((online) => { ... })."""
    marker = "subscribeConnectivity((online) => {"
    start = source.find(marker)
    assert start != -1, "subscribeConnectivity callback missing"
    brace = source.find("{", start + len(marker) - 1)
    depth = 0
    j = brace
    while j < len(source):
        char = source[j]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : j]
        j += 1
    raise AssertionError("subscribeConnectivity callback body not closed")


def test_vpn_connectivity_offline_invalidates_all_operations() -> None:
    """hub-password-honesty: offline connectivity invalidates in-flight VPN operations."""
    source = _read(VPN_SCREEN_JS)
    callback = _extract_subscribe_connectivity_callback(source)
    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "invalidateAllOperations()" in offline_block
    invalidate_idx = offline_block.find("invalidateAllOperations()")
    render_idx = offline_block.find("renderAll()")
    assert invalidate_idx != -1 and render_idx != -1 and invalidate_idx < render_idx


def test_vpn_invalidate_all_operations_clears_catalog_busy_maps() -> None:
    """vpn-entry-overview-offline-settle: invalidateAllOperations clears catalog busy id maps."""
    source = _read(VPN_SCREEN_JS)
    invalidate_body = _extract_function_body(source, "function invalidateAllOperations(")
    assert invalidate_body is not None
    for map_name in (
        "validatingProfileIds = {}",
        "activatingProfileIds = {}",
        "deactivatingProfileIds = {}",
        "removingProfileIds = {}",
    ):
        assert map_name in invalidate_body


def test_vpn_catalog_mutations_pass_mutate_abort_signal() -> None:
    """vpn-entry-overview-offline-settle: catalog runners pass mutateAbort signal to API."""
    source = _read(VPN_SCREEN_JS)
    for fn_sig in (
        "async function runActivateProfile(",
        "async function runDeactivateProfile(",
        "async function runRemoveCatalogProfile(",
        "async function validateCatalogProfile(",
    ):
        body = _extract_function_body(source, fn_sig)
        assert body is not None
        assert "mutateAbort = new AbortController()" in body
        assert "signal: mutationSignal" in body


def test_vpn_catalog_mutations_skip_toast_when_offline_or_aborted() -> None:
    """vpn-entry-overview-offline-settle: catalog runners skip success toast when offline/aborted."""
    source = _read(VPN_SCREEN_JS)
    for fn_sig in (
        "async function runActivateProfile(",
        "async function runDeactivateProfile(",
        "async function runRemoveCatalogProfile(",
        "async function validateCatalogProfile(",
    ):
        body = _extract_function_body(source, fn_sig)
        assert body is not None
        after_await = body.split("await ", 1)[1]
        toast_idx = after_await.find("ctx.showToast(")
        assert toast_idx != -1
        guard = after_await[:toast_idx]
        assert "offline || mutationSignal.aborted" in guard
        assert "return" in guard
