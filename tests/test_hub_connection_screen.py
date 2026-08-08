"""Структурные контракты экрана «Подключение» LOCAL HUB (без сети и без живого роутера)."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from router_control_host.app import create_app
from router_control_host.auth import mint_hub_admin_cookie

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
OPENAPI = REPO_ROOT / "docs" / "contracts" / "openapi-v0.json"
CONNECTION_JS = HUB / "screens" / "connection.js"
CONNECTION_FLOW_JS = HUB / "features" / "connection-flow.js"
APP_JS = HUB / "app.js"
SESSION_JS = HUB / "core" / "session.js"
UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"
ICON_JS = HUB / "components" / "icon.js"
SCREENS_CSS = HUB / "styles" / "screens.css"
SW_JS = HUB / "sw.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
REAL_ROUTER_ID = "rtr_f17a7d35"
DRAFT_ROUTER_ID = "rtr_draft_new"
REAL_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"

API_PREFIX = "/api/router-control/v1/"
API_CALL_RE = re.compile(
    r"api(?:Get|Post)\(\s*(?:'([^']+)'|`([^`]+)`|\"([^\"]+)\")",
)
POST_WITH_HEADERS_RE = re.compile(
    r"postWithHeaders\(\s*(?:'([^']+)'|`([^`]+)`|\"([^\"]+)\")",
)
OPENAPI_TEMPLATE_SEGMENT_RE = re.compile(r"^\{[^}]+\}$")
FRONTEND_PARAM_SEGMENT_RE = re.compile(r"^\{param\}$")

MOCK_DATA_NEEDLES = (
    "SBER EVENT",
    "Keenetic Hopper",
    "192.168.1.1",
    "8 устройств",
    "23 устройства",
    "142",
    "Нидерланды",
    "Опубликован",
    "Уровень сигнала: отличный",
)

FORBIDDEN_IPAD_STORAGE_PHRASES = (
    "только на этом iPad",
    "только на этом ipad",
    "Данные доступа сохранены только",
)

FORBIDDEN_JARGON_IN_USER_STRINGS = (
    "Gate A",
    "WireGuard",
    "VLAN",
    "DHCP",
    "firewall",
    "SSH",
    " PIN",
    "fingerprint",
    "SHA256",
    "host key",
    "API",
    "HTTP",
    "AccessPoint",
    "Uplink",
    "RCI",
    "Station",
)

DOM_STORAGE_PATTERNS = (
    r"\blocalStorage\b",
    r"\bsessionStorage\b",
    r"\bdocument\.cookie\b",
    r"\binnerHTML\b",
    r"\bconsole\.log\b",
    r"\bconsole\.error\b",
)

HUB_STATE_KEYS = (
    "LOADING",
    "SEARCHING",
    "EMPTY",
    "CONNECTING",
    "SUCCESS",
    "WARNING",
    "ERROR",
    "NO_INTERNET",
    "CONNECTION_LOST",
    "RECOVERING",
    "FORBIDDEN",
    "UNSUPPORTED",
    "MOCK_MODE",
    "LIVE_DEVICE",
)

HTTP_CONNECTION_ASSETS = (
    "/settings/router-control/hub/features/connection-flow.js",
    "/settings/router-control/hub/screens/connection.js",
)

CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_function_body(source: str, signature: str) -> str | None:
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


def _normalize_api_path(raw: str) -> str:
    normalized = re.sub(r"\$\{[^}]+\}", "{param}", raw.strip())
    normalized = re.sub(r"\{[^}]+\}", "{param}", normalized)
    return normalized.strip("/")


def _path_segments(path: str) -> list[str]:
    return [segment for segment in path.strip("/").split("/") if segment]


def _segment_is_openapi_template(segment: str) -> bool:
    return OPENAPI_TEMPLATE_SEGMENT_RE.match(segment) is not None


def _segment_is_frontend_param(segment: str) -> bool:
    return FRONTEND_PARAM_SEGMENT_RE.match(segment) is not None


def _segments_match(frontend_segments: list[str], openapi_segments: list[str]) -> bool:
    if len(frontend_segments) != len(openapi_segments):
        return False
    for front, api in zip(frontend_segments, openapi_segments, strict=True):
        api_template = _segment_is_openapi_template(api)
        front_param = _segment_is_frontend_param(front)
        if api_template and not front_param:
            return False
        if front_param and not api_template:
            return False
        if not api_template and not front_param and front != api:
            return False
    return True


def _openapi_paths() -> list[str]:
    spec = json.loads(_read(OPENAPI))
    return [
        path.removeprefix(API_PREFIX)
        for path in spec.get("paths", {})
        if path.startswith(API_PREFIX)
    ]


def _extract_api_paths_from_sources(*sources: Path) -> set[str]:
    paths: set[str] = set()
    for path in sources:
        text = _read(path)
        for pattern in (API_CALL_RE, POST_WITH_HEADERS_RE):
            for match in pattern.finditer(text):
                raw = next(group for group in match.groups() if group is not None)
                paths.add(_normalize_api_path(raw))
    return paths


def _assert_render_abort_guard(body: str) -> None:
    assert "AbortController" in body, "render() must create AbortController"
    assert ".abort()" in body, "render() must abort in-flight requests"
    assert "generation" in body, "render() must track generation"
    assert re.search(r"gen\s*!==\s*generation", body), "generation guard missing"
    assert "disposed" in body, "render() must track disposed"


def _mutate_remove_evaluate_finish_gate(source: str) -> tuple[str, bool]:
    if "evaluateFinishGate" not in source:
        return source, False
    mutated = source.replace("evaluateFinishGate", "__finishGateRemoved__")
    return mutated, mutated != source


def _assert_finish_gate_not_bypassed(source: str) -> None:
    """Экран завершения подключения обязан опираться на evaluateFinishGate, не на status green."""
    assert "evaluateFinishGate" in source
    assert re.search(r"status\s*===\s*['\"]green['\"]", source) is None, (
        "finish must not unlock on raw health status"
    )
    assert "gate.allowed" in source


def _mutate_allow_overwrite_on_normal_confirm(source: str) -> tuple[str, bool]:
    """Ослабляет контракт: обычная кнопка подтверждения отправляет allowOverwrite=true."""
    marker = "function openHostKeyConflictModal("
    split = source.find(marker)
    if split == -1:
        return source, False
    before = source[:split]
    after = source[split:]
    old = "void confirmHostKeyFlow(false);"
    if old not in before:
        return source, False
    mutated_before = before.replace(old, "void confirmHostKeyFlow(true);", 1)
    return mutated_before + after, True


def _assert_host_key_overwrite_only_from_danger_modal(source: str) -> None:
    """allowOverwrite=true допустим только в обработчике опасной модалки конфликта."""
    conflict_body = _extract_function_body(source, "function openHostKeyConflictModal(")
    assert conflict_body is not None
    assert "confirmHostKeyFlow(true)" in conflict_body.replace(" ", "")

    true_calls = [
        match.start()
        for match in re.finditer(r"confirmHostKeyFlow\s*\(\s*true\s*\)", source)
    ]
    assert len(true_calls) == 1, "allowOverwrite=true must appear exactly once"

    false_outside_modal = 0
    for _match in re.finditer(r"confirmHostKeyFlow\s*\(\s*false\s*\)", source):
        false_outside_modal += 1
    assert false_outside_modal >= 2, "normal confirm/retry must send allowOverwrite=false"


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    return create_app(db_path=tmp_path / "hub-connection.sqlite3", enable_worker=False)


@pytest.fixture
def authed_client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_connection_screen_not_stub() -> None:
    """Регрессия: экран подключения — полноценный render, не заглушка."""
    source = _read(CONNECTION_JS)
    assert "renderStubScreen" not in source
    assert "export function render(" in source
    assert "export const meta" in source


def test_connection_render_has_abort_and_dispose() -> None:
    """Регрессия: экран отменяет запросы, игнорирует устаревшие ответы и возвращает cleanup."""
    source = _read(CONNECTION_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    _assert_render_abort_guard(body)
    assert re.search(r"return\s*\(\)\s*=>", source[source.find("export function render(") :])


def test_connection_password_not_in_session() -> None:
    """Регрессия: пароль не попадает в updateSession; поле secret; очистка после сохранения."""
    source = _read(CONNECTION_JS)
    for match in re.finditer(r"updateSession\(\{([^}]+)\}\)", source, re.DOTALL):
        block = match.group(1).lower()
        assert "password" not in block, "password must not appear in updateSession"
        assert "secret" not in block, "secret must not appear in updateSession"

    password_field = re.search(
        r"id:\s*['\"]hub-connection-access-password['\"][\s\S]*?secret:\s*true",
        source,
    )
    assert password_field is not None, "password field must use secret: true"

    save_body = _extract_function_body(source, "async function saveAccessFlow(")
    assert save_body is not None
    assert "accessPassword = ''" in save_body
    assert re.search(r"pwdEl\.value\s*=\s*['\"]['\"]", save_body), (
        "password input must be cleared after successful save"
    )

    ensure_body = _extract_function_body(source, "function ensureAccessIdempotencyKey(")
    assert ensure_body is not None
    assert "accessPassword" not in ensure_body
    assert "password" not in ensure_body.lower()


def test_connection_username_field_has_admin_placeholder() -> None:
    """Регрессия: поле имени пользователя подсказывает vendor default admin."""
    source = _read(CONNECTION_JS)
    username_block = re.search(
        r"id:\s*['\"]hub-connection-access-username['\"][\s\S]*?onInput:",
        source,
    )
    assert username_block is not None
    assert "placeholder: 'admin'" in username_block.group(0)


def test_connection_address_edit_preserves_password_and_shows_reentry_note() -> None:
    """Регрессия: смена адреса синхронизирует пароль из DOM и предупреждает о повторном вводе."""
    source = _read(CONNECTION_JS)
    assert "syncAccessPasswordFromDom" in source
    host_body = _extract_function_body(source, "function renderAccessStep(")
    assert host_body is not None
    assert "syncAccessPasswordFromDom()" in host_body
    assert "accessPasswordReentryNote = true" in host_body
    assert "Пароль нужно ввести заново для нового адреса" in source
    host_on_input = re.search(
        r"id:\s*['\"]hub-connection-access-host['\"][\s\S]*?"
        r"onInput:\s*\(event\)\s*=>\s*\{([\s\S]*?)\n\s*\},\n",
        host_body,
    )
    assert host_on_input is not None, "host field onInput handler must exist"
    host_input_body = host_on_input.group(1)
    assert "syncAccessPasswordFromDom()" in host_input_body
    assert "accessPasswordReentryNote = true" in host_input_body
    assert "onAccessTargetChanged()" in host_input_body
    assert "renderAll()" in host_input_body, (
        "host onInput must call renderAll after address-target change "
        "so reentry note paints when subscribeSession early-returns"
    )
    assert "pendingFocus" in host_input_body
    assert "hub-connection-access-host" in host_input_body
    target_change_idx = host_input_body.index("onAccessTargetChanged()")
    pending_focus_idx = host_input_body.index("pendingFocus")
    render_all_idx = host_input_body.index("renderAll()")
    assert pending_focus_idx > target_change_idx
    assert render_all_idx > pending_focus_idx, (
        "host onInput must set pendingFocus before renderAll "
        "so the host field keeps focus across re-render"
    )
    save_body = _extract_function_body(source, "async function saveAccessFlow(")
    assert save_body is not None
    assert "accessPasswordReentryNote = false" in save_body


def test_connection_access_step_done_requires_host_key_confirmed() -> None:
    """Регрессия: VERIFY без hostKeyConfirmed недоступен; ACCESS «пройден» только с pin."""
    source = _read(CONNECTION_JS)
    render_init = _extract_function_body(source, "export function render(")
    assert render_init is not None
    assert "sessionSnapshot.hostKeyConfirmed" in render_init
    assert re.search(
        r"let maxReachableStep = sessionSnapshot\.hostKeyConfirmed",
        render_init,
    ), "maxReachableStep must gate VERIFY on hostKeyConfirmed"
    stepper_body = _extract_function_body(source, "function renderStepper(")
    assert stepper_body is not None
    assert "item.value === ConnectionStep.ACCESS" in stepper_body
    assert "session.hostKeyConfirmed === true" in stepper_body
    on_target_body = _extract_function_body(source, "function onAccessTargetChanged(")
    assert on_target_body is not None
    normalized_target = re.sub(r"\s+", "", on_target_body)
    assert "maxReachableStep=ConnectionStep.ACCESS" in normalized_target


def test_connection_reset_binding_clears_state_and_returns_search() -> None:
    """Регрессия: resetRouterBinding отменяет запросы и сбрасывает привязку на шаг поиска."""
    source = _read(CONNECTION_JS)
    reset_body = _extract_function_body(source, "function resetRouterBinding(")
    assert reset_body is not None
    normalized = re.sub(r"\s+", " ", reset_body)
    assert "invalidateAllOperations" in normalized
    assert "hostKeyConfirmed: false" in normalized
    assert "healthSnapshot = null" in normalized
    assert "discoveryView = null" in normalized
    assert "currentStep = ConnectionStep.SEARCH" in normalized
    assert "wifiLive" in normalized and "sshHostKeySha256: null" in normalized


def test_connection_save_access_resets_host_key_confirmed() -> None:
    """Регрессия: каждое успешное сохранение доступа сбрасывает hostKeyConfirmed."""
    source = _read(CONNECTION_JS)
    save_body = _extract_function_body(source, "async function saveAccessFlow(")
    assert save_body is not None
    success_slice = save_body.split("activeRouterId = routerId", 1)[-1]
    assert "updateSession({" in success_slice
    normalized_success = success_slice.replace(" ", "")
    assert "hostKeyConfirmed:false" in normalized_success
    assert "sshHostKeySha256:null" in normalized_success


def test_connection_forbidden_literals_absent() -> None:
    """Регрессия: нет макетных заглушек и запрещённых фраз про хранение на iPad."""
    source = _read(CONNECTION_JS)
    lower = source.lower()
    for phrase in FORBIDDEN_IPAD_STORAGE_PHRASES:
        assert phrase.lower() not in lower, f"forbidden phrase: {phrase!r}"
    for needle in MOCK_DATA_NEEDLES:
        assert needle not in source, f"mock needle: {needle!r}"
    for pattern in DOM_STORAGE_PATTERNS:
        assert re.search(pattern, source) is None, f"forbidden pattern: {pattern}"


def test_connection_finish_gate_not_bypassed() -> None:
    """Регрессия: завершение управляется evaluateFinishGate, без status === 'green'."""
    _assert_finish_gate_not_bypassed(_read(CONNECTION_JS))


def test_connection_host_key_overwrite_only_from_danger_modal() -> None:
    """Регрессия: allowOverwrite=true только из модалки конфликта; обычная кнопка — false."""
    _assert_host_key_overwrite_only_from_danger_modal(_read(CONNECTION_JS))


def test_connection_checklist_tone_from_model() -> None:
    """Регрессия: тон строки чеклиста берётся из item.tone модели, не назначается success."""
    source = _read(CONNECTION_JS)
    checklist_body = _extract_function_body(source, "function renderChecklistItem(")
    assert checklist_body is not None
    assert "item.tone" in checklist_body
    assert re.search(r"tone:\s*['\"]success['\"]", checklist_body) is None, (
        "checklist row must not hardcode success tone"
    )


def test_connection_uses_all_hub_states() -> None:
    """Регрессия: экран использует все требуемые ключи HubState."""
    source = _read(CONNECTION_JS)
    missing = [key for key in HUB_STATE_KEYS if f"HubState.{key}" not in source]
    assert missing == [], f"missing HubState keys: {missing}"


def test_connection_host_key_conflict_modal() -> None:
    """Регрессия: конфликт отпечатка — модалка, отказ по умолчанию, перезапись только из неё."""
    source = _read(CONNECTION_JS)
    assert "ssh_host_key.pin_conflict" in _read(CONNECTION_FLOW_JS) or (
        "describeHostKeyConflict" in source
    )
    assert "describeHostKeyConflict" in source
    assert "openModal" in source
    assert "openHostKeyConflictModal" in source
    assert "allowOverwrite" in source
    assert "confirmHostKeyFlow(true)" in source or "confirmHostKeyFlow(true)" in source.replace(
        " ", ""
    )
    conflict_body = _extract_function_body(source, "function openHostKeyConflictModal(")
    assert conflict_body is not None
    assert "'Отмена'" in conflict_body or '"Отмена"' in conflict_body
    assert "variant: 'danger'" in conflict_body or 'variant: "danger"' in conflict_body
    assert re.search(r"actions:\s*\[\s*cancelBtn", conflict_body.replace("\n", " "))


def test_connection_api_paths_exist_in_openapi() -> None:
    """Регрессия: пути API экрана и модели существуют в openapi-v0.json."""
    frontend_paths = _extract_api_paths_from_sources(CONNECTION_JS, CONNECTION_FLOW_JS)
    openapi_paths = _openapi_paths()
    missing: list[str] = []
    for front_path in sorted(frontend_paths):
        front_segments = _path_segments(front_path)
        if not any(
            _segments_match(front_segments, _path_segments(api_path))
            for api_path in openapi_paths
        ):
            missing.append(front_path)
    assert missing == [], f"API paths not in OpenAPI: {missing}"


def test_connection_pwa_shell_urls_updated() -> None:
    """Регрессия: SW precache включает connection-flow.js и CACHE_VERSION > 3."""
    source = _read(SW_JS)
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None
    assert int(version_match.group(1)) > 3
    assert "features/connection-flow.js" in source


def test_connection_new_assets_served_over_http(authed_client) -> None:
    """Регрессия: новые статические ресурсы подключения отдаются с 200 и непустым телом."""
    for url in HTTP_CONNECTION_ASSETS:
        response = authed_client.get(url)
        assert response.status_code == 200, url
        assert len(response.content) > 0, url


def test_connection_user_strings_no_jargon() -> None:
    """Регрессия: пользовательские строки экрана без запрещённого жаргона."""
    source = _read(CONNECTION_JS)
    literals = re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", source)
    literals += re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', source)
    for literal in literals:
        if not CYRILLIC.search(literal):
            continue
        for jargon in FORBIDDEN_JARGON_IN_USER_STRINGS:
            assert jargon not in literal, f"jargon {jargon!r} in: {literal!r}"


def test_detector_finish_gate_required_in_screen() -> None:
    """Самопроверка: удаление evaluateFinishGate ловится контрактом завершения."""
    source = _read(CONNECTION_JS)
    _assert_finish_gate_not_bypassed(source)
    broken, applied = _mutate_remove_evaluate_finish_gate(source)
    assert applied
    with pytest.raises(AssertionError):
        _assert_finish_gate_not_bypassed(broken)


def test_detector_normal_confirm_must_not_allow_overwrite() -> None:
    """Самопроверка: замена false→true на обычной кнопке ломает контракт перезаписи."""
    source = _read(CONNECTION_JS)
    _assert_host_key_overwrite_only_from_danger_modal(source)
    broken, applied = _mutate_allow_overwrite_on_normal_confirm(source)
    assert applied
    with pytest.raises(AssertionError):
        _assert_host_key_overwrite_only_from_danger_modal(broken)


def _extract_connection_screen_classes(source: str) -> set[str]:
    """Классы hub-connection__* из JS-разметки экрана."""
    static = set(re.findall(r"hub-connection__[\w-]+", source))
    static = {name for name in static if not name.endswith("--")}
    dynamic = {
        "hub-connection__checklist-item--success",
        "hub-connection__checklist-item--danger",
        "hub-connection__checklist-item--neutral",
    }
    return static | dynamic


def _extract_connection_css_classes(css: str) -> set[str]:
    """Классы hub-connection__* из screens.css (только блок экрана подключения)."""
    connection_block = css.split("/* ── Экран «Подключение к роутеру» ── */", 1)[-1]
    classes: set[str] = set()
    for match in re.finditer(r"\.(hub-connection__[\w-]+)", connection_block):
        classes.add(match.group(1))
    return classes


def _assert_step_marker_not_empty(source: str) -> None:
    """Маркер шага содержит номер или иконку галочки."""
    stepper_body = _extract_function_body(source, "function renderStepper(")
    assert stepper_body is not None
    assert "hub-connection__step-marker" in stepper_body
    has_number = "marker.textContent" in stepper_body or "marker.textContent =" in stepper_body
    has_check = re.search(r"createIcon\s*\(\s*['\"]check['\"]", stepper_body) is not None
    assert has_number and has_check, "step marker must show step number or check icon"


def _mutate_empty_step_marker(source: str) -> tuple[str, bool]:
    """Убирает наполнение маркера шага для детектора."""
    old = """      if (dataState === 'done') {
        marker.appendChild(createIcon('check', { size: 18 }));
      } else {
        marker.textContent = String(i + 1);
      }"""
    if old not in source:
        return source, False
    return source.replace(old, "      /* marker left empty */"), True


def _assert_icon_names_valid(source: str, allowed: set[str]) -> None:
    """Все iconName/createIcon на экране — из ICON_NAMES."""
    names: set[str] = set()
    for match in re.finditer(r"createIcon\s*\(\s*['\"]([^'\"]+)['\"]", source):
        names.add(match.group(1))
    for match in re.finditer(r"iconName:\s*['\"]([^'\"]+)['\"]", source):
        names.add(match.group(1))
    meta_match = re.search(r"iconName:\s*['\"]([^'\"]+)['\"]", source)
    if meta_match:
        names.add(meta_match.group(1))
    unknown = sorted(name for name in names if name not in allowed)
    assert unknown == [], f"unknown icon names: {unknown}"


def _assert_learn_host_key_resets_confirmation(source: str) -> None:
    """Повторное получение отпечатка сбрасывает hostKeyConfirmed в сессии."""
    learn_body = _extract_function_body(source, "async function learnHostKeyFlow(")
    assert learn_body is not None
    before_try = learn_body.split("try {", 1)[0]
    normalized = re.sub(r"\s+", "", before_try)
    assert "hostKeyConfirmed:false" in normalized
    assert "sshHostKeySha256:null" in normalized


def _mutate_skip_learn_confirmation_reset(source: str) -> tuple[str, bool]:
    """Убирает сброс подтверждения при learnHostKeyFlow."""
    old = """    updateSession({
      hostKeyConfirmed: false,
      wifiLive: { sshHostKeySha256: null },
    });
    renderAll();

    try {
      const response = /** @type {{ fingerprint_sha256?: string, algorithm?: string }} */ (
        await learnHostKey({"""
    if old not in source:
        return source, False
    new = """    renderAll();

    try {
      const response = /** @type {{ fingerprint_sha256?: string, algorithm?: string }} */ (
        await learnHostKey({"""
    return source.replace(old, new), True


def _assert_recovering_cleared_in_all_flows(source: str) -> None:
    """Флаг recovering сбрасывается в finally каждого из пяти потоков."""
    flow_names = (
        "async function runDiscoveryFlow(",
        "async function saveAccessFlow(",
        "async function learnHostKeyFlow(",
        "async function confirmHostKeyFlow(",
        "async function runHealthCheckFlow(",
    )
    for signature in flow_names:
        body = _extract_function_body(source, signature)
        assert body is not None, f"missing flow: {signature}"
        finally_part = body.rsplit("finally {", 1)[-1]
        assert "clearRecovering()" in finally_part, (
            f"{signature} must call clearRecovering() in finally"
        )


def _mutate_remove_clear_recovering_from_flow(source: str, signature: str) -> tuple[str, bool]:
    """Убирает один вызов clearRecovering из указанного потока."""
    body = _extract_function_body(source, signature)
    if body is None or "clearRecovering();" not in body:
        return source, False
    start = source.find(signature)
    if start == -1:
        return source, False
    brace = source.find("{", source.find(")", start))
    if brace == -1:
        return source, False
    depth = 0
    end = brace
    for idx in range(brace, len(source)):
        if source[idx] == "{":
            depth += 1
        elif source[idx] == "}":
            depth -= 1
            if depth == 0:
                end = idx
                break
    function_text = source[start : end + 1]
    if "clearRecovering();" not in function_text:
        return source, False
    mutated_function = function_text.replace("clearRecovering();", "", 1)
    return source[:start] + mutated_function + source[end + 1 :], True


# Исключения синхронизации: tone-модификаторы задаются динамически через item.tone.
CONNECTION_CLASS_SYNC_EXCEPTIONS = frozenset(
    {
        # tone-модификаторы задаются динамически через item.tone
        "hub-connection__checklist-item--success",
        "hub-connection__checklist-item--danger",
        "hub-connection__checklist-item--neutral",
    }
)


def _assert_connection_class_sync(source: str, css: str) -> None:
    """Множества hub-connection__ классов в разметке и CSS совпадают (с исключениями)."""
    markup = _extract_connection_screen_classes(source) - CONNECTION_CLASS_SYNC_EXCEPTIONS
    styles = _extract_connection_css_classes(css) - CONNECTION_CLASS_SYNC_EXCEPTIONS
    missing_in_css = sorted(markup - styles)
    missing_in_markup = sorted(styles - markup)
    assert missing_in_css == [], f"classes in markup but not CSS: {missing_in_css}"
    assert missing_in_markup == [], f"classes in CSS but not markup: {missing_in_markup}"


def test_connection_step_marker_not_empty() -> None:
    """Регрессия: маркер шага показывает номер или иконку check, не остаётся пустым."""
    source = _read(CONNECTION_JS)
    _assert_step_marker_not_empty(source)


def test_detector_empty_step_marker_fails() -> None:
    """Самопроверка: пустой маркер шага ловится контрактом renderStepper."""
    source = _read(CONNECTION_JS)
    _assert_step_marker_not_empty(source)
    broken, applied = _mutate_empty_step_marker(source)
    assert applied
    with pytest.raises(AssertionError):
        _assert_step_marker_not_empty(broken)


def test_connection_icon_names_in_catalog() -> None:
    """Регрессия: все iconName/createIcon экрана входят в ICON_NAMES из icon.js."""
    source = _read(CONNECTION_JS)
    icon_source = _read(ICON_JS)
    names_match = re.search(r"ICON_NAMES = Object\.freeze\(\[([\s\S]*?)\]\)", icon_source)
    assert names_match is not None
    allowed = set(re.findall(r"['\"]([^'\"]+)['\"]", names_match.group(1)))
    _assert_icon_names_valid(source, allowed)


def test_connection_learn_host_key_resets_confirmation() -> None:
    """Регрессия: старт learnHostKeyFlow сбрасывает hostKeyConfirmed и сохранённый отпечаток."""
    source = _read(CONNECTION_JS)
    _assert_learn_host_key_resets_confirmation(source)


def test_detector_learn_without_confirmation_reset_fails() -> None:
    """Самопроверка: отсутствие сброса подтверждения при learn ловится контрактом."""
    source = _read(CONNECTION_JS)
    _assert_learn_host_key_resets_confirmation(source)
    broken, applied = _mutate_skip_learn_confirmation_reset(source)
    assert applied
    with pytest.raises(AssertionError):
        _assert_learn_host_key_resets_confirmation(broken)


def test_connection_markup_css_class_sync() -> None:
    """Регрессия: классы hub-connection__ в разметке и screens.css синхронизированы."""
    _assert_connection_class_sync(_read(CONNECTION_JS), _read(SCREENS_CSS))


def test_detector_connection_class_sync() -> None:
    """Самопроверка: мёртвый CSS-класс ловится синхронизацией разметки и стилей."""
    source = _read(CONNECTION_JS)
    css = _read(SCREENS_CSS)
    _assert_connection_class_sync(source, css)
    broken_css = css + "\n.hub-connection__phantom-dead-class { display: none; }\n"
    with pytest.raises(AssertionError):
        _assert_connection_class_sync(source, broken_css)


def test_connection_recovering_cleared_in_all_flows() -> None:
    """Регрессия: clearRecovering() вызывается в finally всех пяти потоков экрана."""
    source = _read(CONNECTION_JS)
    _assert_recovering_cleared_in_all_flows(source)


def test_detector_missing_clear_recovering_fails() -> None:
    """Самопроверка: пропуск clearRecovering в потоке ловится контрактом recovering."""
    source = _read(CONNECTION_JS)
    _assert_recovering_cleared_in_all_flows(source)
    broken, applied = _mutate_remove_clear_recovering_from_flow(
        source, "async function learnHostKeyFlow("
    )
    assert applied
    with pytest.raises(AssertionError):
        _assert_recovering_cleared_in_all_flows(broken)


def test_connection_closes_modals_on_step_change() -> None:
    """Регрессия: переход между шагами закрывает открытые модальные окна."""
    source = _read(CONNECTION_JS)
    go_body = _extract_function_body(source, "function goToStep(")
    assert go_body is not None
    assert "closeAllModals()" in go_body.replace(" ", "")


def _assert_candidates_avoid_nested_labels(source: str) -> None:
    """Кандидаты: внешний контейнер div, порты — fieldset, без label внутри label."""
    search_body = _extract_function_body(source, "function renderSearchStep(")
    assert search_body is not None
    assert re.search(
        r"createElement\(['\"]div['\"]\);\s*\n\s*row\.className = 'hub-connection__candidate'",
        search_body,
    ), "candidate row must be a div"
    assert "createElement('fieldset')" in search_body or 'createElement("fieldset")' in search_body
    assert re.search(
        r"createElement\(['\"]label['\"]\);\s*\n\s*row\.className = 'hub-connection__candidate'",
        search_body,
    ) is None, "candidate must not be a label wrapping nested labels"


def _assert_step_labels_without_number_prefix(source: str) -> None:
    """Степпер: подписи без дублирующей нумерации (цифра только в маркере)."""
    assert "'1. Поиск'" not in source
    assert "'2. Доступ'" not in source
    assert "'3. Проверка'" not in source
    assert re.search(r"label:\s*['\"]Поиск['\"]", source) is not None
    stepper_body = _extract_function_body(source, "function renderStepper(")
    assert stepper_body is not None
    assert "String(i + 1)" in stepper_body


def test_connection_candidates_avoid_nested_labels() -> None:
    """Д-2: выбор порта не вложен во внешнюю подпись кандидата."""
    source = _read(CONNECTION_JS)
    _assert_candidates_avoid_nested_labels(source)
    broken = source.replace(
        (
            "const row = document.createElement('div');\n"
            "          row.className = 'hub-connection__candidate';"
        ),
        (
            "const row = document.createElement('label');\n"
            "          row.className = 'hub-connection__candidate';"
        ),
        1,
    )
    with pytest.raises(AssertionError):
        _assert_candidates_avoid_nested_labels(broken)


def test_connection_step_labels_without_duplicate_numbers() -> None:
    """Доп.: номер шага только в круглом маркере, не в подписи и заголовке."""
    source = _read(CONNECTION_JS)
    _assert_step_labels_without_number_prefix(source)
    broken = source.replace("label: 'Поиск'", "label: '1. Поиск'", 1)
    with pytest.raises(AssertionError):
        _assert_step_labels_without_number_prefix(broken)


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            f"node is required for hub connection screen tests; install Node.js or set "
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


def _run_connection_restore_mount_scenario(
    *,
    restore_mode: str,
    tmp_path: Path,
) -> dict[str, object]:
    session_uri = json.dumps(SESSION_JS.as_uri())
    app_uri = json.dumps(APP_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))

    if restore_mode == "candidate":
        restore_return = json.dumps(
            {
                "restore_candidate": True,
                "router_id": REAL_ROUTER_ID,
                "host": "192.168.2.1",
                "port": 22,
                "source_address": "192.168.2.10",
                "credential_ref_id": "cred-real",
                "ssh_host_key": {
                    "confirmed": False,
                    "fingerprint_sha256": REAL_FINGERPRINT,
                    "pinned_at": "2026-08-03T12:00:00Z",
                },
                "username_available": False,
                "live_ready": False,
            },
            ensure_ascii=False,
        )
        restore_body = f"return {restore_return};"
    elif restore_mode == "no_candidate":
        restore_body = "return { restore_candidate: false };"
    elif restore_mode == "failed":
        restore_body = "throw new Error('restore_failed');"
    else:
        raise ValueError(f"unknown restore_mode: {restore_mode}")

    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{
          el.children.unshift(node);
          node.parentNode = el;
        }} else {{
          el.appendChild(node);
        }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

import {{ restoreConnectionContextFromServer }} from {app_uri};

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);



globalThis.fetch = async (url, init = {{}}) => {{

  const method = init.method ?? 'GET';

  if (method === 'POST' && String(url).includes('lab/router-discovery')) {{

    return {{

      ok: true,

      status: 200,

      headers: {{ get: () => 'application/json' }},

      json: async () => ({{ candidates: [] }}),

    }};

  }}

  throw new Error(`unexpected fetch: ${{method}} ${{url}}`);

}};



import {{ resetSession, updateSession, getSession }} from {session_uri};

import {{ render }} from {connection_uri};



resetSession();

updateSession({{ connectionRestoreState: 'pending' }});



const container = document.createElement('div');

document.body.appendChild(container);



const dispose = render(container, {{ runtime: {{ adapterMode: 'fake' }} }});



const pendingText = dom.collectVisibleText(container);

const pendingHasFindBtn = !!document.getElementById('hub-connection-find-btn');



async function fakeApiGet(path) {{

  if (path === 'connection-context/restore-candidate') {{

    {restore_body}

  }}

  throw new Error(`unexpected apiGet path: ${{path}}`);

}}



await restoreConnectionContextFromServer(undefined, fakeApiGet);

await new Promise((resolve) => setTimeout(resolve, 200));



const settledText = dom.collectVisibleText(container);

const settledHasFindBtn = !!document.getElementById('hub-connection-find-btn');

const settledHasAccessHost = !!document.getElementById('hub-connection-access-host');

const settledSession = getSession();



dispose();



console.log(JSON.stringify({{

  pendingText,

  pendingHasFindBtn,

  settledText,

  settledHasFindBtn,

  settledHasAccessHost,

  restoreState: settledSession.connectionRestoreState,

  routerId: settledSession.routerId,

}}));

"""

    return _run_node_harness(script, tmp_path, f"connection-restore-{restore_mode}")  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("restore_mode", "expected_restore_state", "usable_check"),
    [
        ("candidate", "done", "access_host"),
        ("no_candidate", "done", "find_btn"),
        ("failed", "failed", "failure_panel"),
    ],
)
def test_connection_screen_reaches_usable_state_after_restore_settles(
    restore_mode: str,
    expected_restore_state: str,
    usable_check: str,
    tmp_path: Path,
) -> None:
    """Экран «Подключение» при монтировании во время pending доходит до рабочего состояния."""

    payload = _run_connection_restore_mount_scenario(restore_mode=restore_mode, tmp_path=tmp_path)

    assert payload["restoreState"] == expected_restore_state
    assert "Проверяем сохранённое подключение" in payload["pendingText"]
    assert payload["pendingHasFindBtn"] is False
    assert "Подготавливаем экран подключения" not in payload["settledText"]

    if usable_check == "access_host":
        assert payload["routerId"] == REAL_ROUTER_ID
        assert payload["settledHasAccessHost"] is True
        assert "Адрес роутера" in payload["settledText"]
    elif usable_check == "find_btn":
        assert payload["routerId"] is None
        assert payload["settledHasFindBtn"] is True
        assert "Найти роутер" in payload["settledText"]
    elif usable_check == "failure_panel":
        assert "Не удалось проверить сохранённое подключение" in payload["settledText"]
        assert payload["settledHasFindBtn"] is False


MANAGEMENT_USERNAME = "lab-admin"


def _management_username_recovery_harness_script(
    *,
    action: str,
    typed_username: str = MANAGEMENT_USERNAME,
) -> str:
    session_uri = json.dumps(SESSION_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))

    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{
          el.children.unshift(node);
          node.parentNode = el;
        }} else {{
          el.appendChild(node);
        }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

globalThis.HTMLInputElement = document.createElement('input').constructor;

globalThis.HTMLButtonElement = document.createElement('button').constructor;

globalThis.HTMLFormElement = document.createElement('form').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

const apiCalls = [];

globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const body = init.body ? JSON.parse(String(init.body)) : null;
  apiCalls.push({{ method, url: String(url), body }});
  if (method === 'POST' && String(url).includes('/management-username')) {{
    return {{
      ok: true,
      status: 204,
      headers: {{ get: () => '' }},
      text: async () => '',
      json: async () => null,
    }};
  }}
  if (method === 'GET' && String(url).includes('/connection-context')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        router_id: {json.dumps(REAL_ROUTER_ID)},
        host: '192.168.2.1',
        port: 22,
        source_address: '192.168.2.10',
        credential_ref_id: 'cred-real',
        ssh_host_key: {{
          confirmed: true,
          fingerprint_sha256: {json.dumps(REAL_FINGERPRINT)},
          pinned_at: '2026-08-03T12:00:00Z',
        }},
        username_available: true,
        live_ready: true,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{url}}`);
}};

import {{ resetSession, updateSession, getSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

updateSession({{
  routerId: {json.dumps(REAL_ROUTER_ID)},
  routerHost: '192.168.2.1',
  hostKeyConfirmed: true,
  usernameAvailable: false,
  liveReady: false,
  connectionRestoreState: 'done',
  pinnedEndpointPort: 22,
  wifiLive: {{
    host: '192.168.2.1',
    credentialRefId: 'cred-real',
    sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},
  }},
}});

const container = document.createElement('div');

document.body.appendChild(container);

const renderCtx = {{
  runtime: {{ adapterMode: 'fake' }},
  navigate: () => {{}},
  showToast: () => {{}},
}};
const dispose = render(container, renderCtx);

await new Promise((resolve) => setTimeout(resolve, 0));

const usernameInput = document.getElementById('hub-connection-management-username');
const saveBtn = document.getElementById('hub-connection-management-username-save');
const recoveryForm = usernameInput?.closest('form') ?? null;

const action = {json.dumps(action)};
const typedUsername = {json.dumps(typed_username)};

let saveDisabledAfterTyping = null;
let focusInputIdAfterTyping = null;
let caretAfterTyping = null;
let postCalls = [];
let sessionAfter = null;
let recoveryPanelVisible = null;

const typingActions = new Set(['type_only', 'click_save', 'enter_submit', 'caret_focus']);

if (typingActions.has(action)) {{
  if (!(usernameInput instanceof HTMLInputElement)) {{
    throw new Error('management username input missing');
  }}
  if (action === 'caret_focus') {{
    usernameInput.focus();
    dom.simulateInput(usernameInput, 'a');
    const afterFirst = {{
      focusId: document.activeElement?.id ?? null,
      caret: usernameInput.selectionStart,
    }};
    dom.simulateInput(usernameInput, 'ab');
    console.log(JSON.stringify({{
      action,
      afterFirst,
      afterSecond: {{
        focusId: document.activeElement?.id ?? null,
        caret: usernameInput.selectionStart,
        value: usernameInput.value,
      }},
      saveDisabledAfterTyping: saveBtn instanceof HTMLButtonElement ? saveBtn.disabled : null,
    }}));
    dispose();
    process.exit(0);
  }}
  dom.simulateInput(usernameInput, typedUsername);
  saveDisabledAfterTyping = saveBtn instanceof HTMLButtonElement ? saveBtn.disabled : null;
  focusInputIdAfterTyping = document.activeElement?.id ?? null;
  caretAfterTyping = usernameInput.selectionStart;
}}

if (action === 'click_save') {{
  if (!(saveBtn instanceof HTMLButtonElement)) {{
    throw new Error('management username save button missing');
  }}
  saveBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 200));
}}

if (action === 'enter_submit') {{
  if (!(recoveryForm instanceof HTMLFormElement)) {{
    throw new Error('management username form missing');
  }}
  dom.dispatchFormSubmit(recoveryForm);
  await new Promise((resolve) => setTimeout(resolve, 200));
}}

postCalls = apiCalls.filter(
  (call) => call.method === 'POST' && call.url.includes('/management-username'),
);
sessionAfter = getSession();
const recoveryTitle = 'Имя пользователя для управления';
recoveryPanelVisible = dom.collectVisibleText(container).includes(recoveryTitle);

console.log(JSON.stringify({{
  action,
  saveDisabledAfterTyping,
  focusInputIdAfterTyping,
  caretAfterTyping,
  postCalls,
  sessionAfter: {{
    usernameAvailable: sessionAfter.usernameAvailable,
    liveReady: sessionAfter.liveReady,
    connectionRestoreState: sessionAfter.connectionRestoreState,
  }},
  recoveryPanelVisible,
  visibleText: dom.collectVisibleText(container),
}}));

dispose();
"""


def _run_management_username_recovery_scenario(
    *,
    action: str,
    typed_username: str = MANAGEMENT_USERNAME,
    tmp_path: Path,
    label: str,
) -> dict[str, object]:
    script = _management_username_recovery_harness_script(
        action=action,
        typed_username=typed_username,
    )
    return _run_node_harness(script, tmp_path, label)  # type: ignore[return-value]


def test_management_username_typing_enables_save_button(tmp_path: Path) -> None:
    """Ввод имени пользователя включает кнопку «Сохранить имя пользователя»."""
    payload = _run_management_username_recovery_scenario(
        action="type_only",
        tmp_path=tmp_path,
        label="mgmt-username-type-enables",
    )
    assert payload["saveDisabledAfterTyping"] is False


def test_management_username_whitespace_keeps_button_disabled(tmp_path: Path) -> None:
    """Пробелы не включают кнопку сохранения имени пользователя."""
    payload = _run_management_username_recovery_scenario(
        action="type_only",
        typed_username="   ",
        tmp_path=tmp_path,
        label="mgmt-username-whitespace-disabled",
    )
    assert payload["saveDisabledAfterTyping"] is True


def test_management_username_click_posts_management_username(tmp_path: Path) -> None:
    """Клик по включённой кнопке отправляет POST management-username."""
    payload = _run_management_username_recovery_scenario(
        action="click_save",
        tmp_path=tmp_path,
        label="mgmt-username-click-post",
    )
    assert payload["saveDisabledAfterTyping"] is False
    post_calls = payload["postCalls"]
    assert len(post_calls) == 1
    assert post_calls[0]["body"] == {"username": MANAGEMENT_USERNAME}


def test_management_username_enter_submits_management_username(tmp_path: Path) -> None:
    """Enter в поле имени отправляет POST management-username."""
    payload = _run_management_username_recovery_scenario(
        action="enter_submit",
        tmp_path=tmp_path,
        label="mgmt-username-enter-post",
    )
    assert payload["saveDisabledAfterTyping"] is False
    post_calls = payload["postCalls"]
    assert len(post_calls) == 1
    assert post_calls[0]["body"] == {"username": MANAGEMENT_USERNAME}


def test_management_username_success_hides_panel_and_updates_session(tmp_path: Path) -> None:
    """После успешного сохранения панель исчезает, сессия отражает live_ready."""
    payload = _run_management_username_recovery_scenario(
        action="click_save",
        tmp_path=tmp_path,
        label="mgmt-username-success-session",
    )
    assert payload["recoveryPanelVisible"] is False
    session = payload["sessionAfter"]
    assert session["usernameAvailable"] is True
    assert session["liveReady"] is True
    assert "Имя пользователя для управления" not in payload["visibleText"]


def test_management_username_typing_preserves_focus_and_caret(tmp_path: Path) -> None:
    """Синхронизация кнопки не сбивает фокус и каретку при наборе текста."""
    payload = _run_management_username_recovery_scenario(
        action="caret_focus",
        tmp_path=tmp_path,
        label="mgmt-username-caret-focus",
    )
    assert payload["afterFirst"]["focusId"] == "hub-connection-management-username"
    second = payload["afterSecond"]
    assert second["focusId"] == "hub-connection-management-username"
    assert second["value"] == "ab"
    assert second["caret"] == 2


def _verify_host_key_badge_harness_script(*, host_key_match: object) -> str:
    session_uri = json.dumps(SESSION_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))
    health_facts = json.dumps(
        {
            "reachable": True,
            "credentials_present": True,
            "host_key_match": host_key_match,
            "tuple_match": None,
            "evidence_fresh": True,
        },
        ensure_ascii=False,
    )

    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{
          el.children.unshift(node);
          node.parentNode = el;
        }} else {{
          el.appendChild(node);
        }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

globalThis.HTMLButtonElement = document.createElement('button').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  if (method === 'POST' && String(url).includes('connection-health')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        status: 'yellow',
        reason_code: 'host_key_unknown',
        facts: {health_facts},
        writes_allowed: false,
      }}),
    }};
  }}
  if (method === 'GET') {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ adapter_mode: 'fake' }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{url}}`);
}};

import {{ resetSession, updateSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

updateSession({{
  routerId: {json.dumps(REAL_ROUTER_ID)},
  routerHost: '192.168.2.1',
  sourceAddress: '192.168.2.10',
  hostKeyConfirmed: true,
  liveReady: true,
  usernameAvailable: true,
  connectionRestoreState: 'done',
  pinnedEndpointPort: 443,
  wifiLive: {{
    host: '192.168.2.1',
    credentialRefId: 'cred-real',
    sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},
  }},
}});

const container = document.createElement('div');

document.body.appendChild(container);

const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate: () => {{}},
  showToast: () => {{}},
}});

await new Promise((resolve) => setTimeout(resolve, 0));

let badgeLabel = container.querySelector('.hub-badge__label');
for (let attempt = 0; attempt < 30; attempt += 1) {{
  await new Promise((resolve) => setTimeout(resolve, 50));
  badgeLabel = container.querySelector('.hub-badge__label');
  if (badgeLabel?.textContent) {{
    break;
  }}
}}

const visibleText = dom.collectVisibleText(container);

console.log(JSON.stringify({{
  badgeText: badgeLabel?.textContent ?? null,
  visibleText,
}}));

dispose();
"""


def _run_verify_host_key_badge_scenario(
    *,
    host_key_match: object,
    tmp_path: Path,
    label: str,
) -> dict[str, object]:
    script = _verify_host_key_badge_harness_script(host_key_match=host_key_match)
    return _run_node_harness(script, tmp_path, label)  # type: ignore[return-value]


@pytest.mark.parametrize(
    ("host_key_match", "expected_badge", "must_not_contain"),
    [
        (None, "Совпадение отпечатка ещё не проверено", "Отпечаток не совпадает"),
        (False, "Отпечаток не совпадает", None),
        (True, "Привязан", "Отпечаток не совпадает"),
    ],
)
def test_verify_host_key_badge_tri_state_after_health_check(
    host_key_match: object,
    expected_badge: str,
    must_not_contain: str | None,
    tmp_path: Path,
) -> None:
    """Бейдж отпечатка на VERIFY: три состояния после health-check."""
    payload = _run_verify_host_key_badge_scenario(
        host_key_match=host_key_match,
        tmp_path=tmp_path,
        label=f"verify-badge-{host_key_match}",
    )
    visible = str(payload["visibleText"])
    badge_text = payload.get("badgeText")
    if badge_text:
        assert badge_text == expected_badge
    assert expected_badge in visible
    if must_not_contain is not None:
        assert must_not_contain not in visible


def _endpoint_wording_harness_script() -> str:
    session_uri = json.dumps(SESSION_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))

    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

import {{ resetSession, updateSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

updateSession({{
  routerId: {json.dumps(REAL_ROUTER_ID)},
  routerHost: '192.168.2.1',
  hostKeyConfirmed: true,
  liveReady: false,
  connectionRestoreState: 'done',
  pinnedEndpointPort: 443,
  pinnedAt: '2026-08-03T12:00:00Z',
  wifiLive: {{
    host: '192.168.2.1',
    credentialRefId: 'cred-real',
    sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},
  }},
}});

const container = document.createElement('div');

document.body.appendChild(container);

const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate: () => {{}},
  showToast: () => {{}},
}});

await new Promise((resolve) => setTimeout(resolve, 0));

const visibleText = dom.collectVisibleText(container);

console.log(JSON.stringify({{ visibleText }}));

dispose();
"""


def test_server_pin_endpoint_wording_omits_stored_port(tmp_path: Path) -> None:
    """M-12.5: подтверждение не привязывается к сохранённому endpoint.port."""
    payload = _run_node_harness(
        _endpoint_wording_harness_script(),
        tmp_path,
        "endpoint-wording",
    )
    visible = str(payload["visibleText"])
    assert ":443" not in visible
    assert "служебное подключение к роутеру" in visible
    assert "порт 22" in visible


def _health_zone_g_harness_script(*, scenario: str) -> str:
    session_uri = json.dumps(SESSION_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))
    router_a = REAL_ROUTER_ID
    router_b = DRAFT_ROUTER_ID

    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{
          el.children.unshift(node);
          node.parentNode = el;
        }} else {{
          el.appendChild(node);
        }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

globalThis.HTMLButtonElement = document.createElement('button').constructor;

globalThis.HTMLInputElement = document.createElement('input').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

let healthResolve = null;
let healthDelayMs = 0;
let healthCallCount = 0;

const HEALTH_OK = {{
  status: 'green',
  writes_allowed: true,
  facts: {{
    reachable: true,
    credentials_present: true,
    host_key_match: true,
    tuple_match: true,
    evidence_fresh: true,
  }},
}};

let healthFailOnce = false;

const HEALTH_FAIL_BODY = {{
  error: {{
    code: 'connection_health.failed',
    message: 'synthetic health failure for j6 test',
    details: [],
  }},
}};

globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const target = String(url);
  if (method === 'POST' && target.includes('connection-health')) {{
    healthCallCount += 1;
    if (healthFailOnce) {{
      healthFailOnce = false;
      const failBody = JSON.stringify(HEALTH_FAIL_BODY);
      return {{
        ok: false,
        status: 503,
        headers: {{ get: () => 'application/json' }},
        text: async () => failBody,
        json: async () => HEALTH_FAIL_BODY,
      }};
    }}
    if (healthDelayMs > 0) {{
      await new Promise((resolve) => {{
        healthResolve = resolve;
      }});
    }}
    const okBody = JSON.stringify(HEALTH_OK);
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      text: async () => okBody,
      json: async () => HEALTH_OK,
    }};
  }}
  if (method === 'POST' && target.includes('wizard-draft-router')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        router_id: {json.dumps(router_b)},
        credential_ref_id: 'cred-draft-b',
        username: 'admin',
      }}),
    }};
  }}
  if (method === 'POST' && target.includes('/ssh-host-key/learn')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        fingerprint_sha256: {json.dumps(REAL_FINGERPRINT)},
        algorithm: 'ssh-ed25519',
      }}),
    }};
  }}
  if (method === 'POST' && target.includes('/ssh-host-key/confirm')) {{
    return {{
      ok: true,
      status: 204,
      headers: {{ get: () => '' }},
      text: async () => '',
      json: async () => null,
    }};
  }}
  if (method === 'GET') {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ adapter_mode: 'fake' }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{target}}`);
}};

import {{ resetSession, updateSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

updateSession({{
  routerId: {json.dumps(router_a)},
  routerHost: '192.168.1.1',
  sourceAddress: '192.168.1.144',
  hostKeyConfirmed: true,
  liveReady: true,
  usernameAvailable: true,
  connectionRestoreState: 'done',
  wifiLive: {{
    host: '192.168.1.1',
    username: 'admin',
    credentialRefId: 'cred-a',
    sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},
  }},
}});

const scenario = {json.dumps(scenario)};

const container = document.createElement('div');

document.body.appendChild(container);

const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate: () => {{}},
  showToast: () => {{}},
}});

async function waitForText(substr, attempts = 40) {{
  for (let i = 0; i < attempts; i += 1) {{
    await new Promise((resolve) => setTimeout(resolve, 50));
    const text = dom.collectVisibleText(container);
    if (text.includes(substr)) {{
      return text;
    }}
  }}
  throw new Error(`timeout waiting for text: ${{substr}}`);
}}

async function clickStepByLabel(label) {{
  const buttons = document.querySelectorAll('button');
  const btn = [...buttons].find((node) => {{
    const aria = node.getAttribute?.('aria-label') ?? '';
    return dom.collectVisibleText(node).includes(label) || aria.includes(label);
  }});
  if (!btn) {{
    throw new Error(`step button not found: ${{label}}`);
  }}
  btn.click();
  await new Promise((resolve) => setTimeout(resolve, 0));
}}

function findButtonByLabel(text) {{
  const buttons = document.querySelectorAll('button');
  return [...buttons].find((btn) => dom.collectVisibleText(btn).includes(text)) ?? null;
}}

/** @type {{ visibleText: string, healthCallCount: number }} */
let result = {{ visibleText: '', healthCallCount: 0 }};

if (scenario === 'stale_after_binding_change') {{
  await waitForText('Управление доступно');
  await waitForText('Совпадает с сохранённым роутером');
  await waitForText('Назад к доступу');
  const backBtn = findButtonByLabel('Назад к доступу');
  if (!backBtn) throw new Error('back to access button missing');
  backBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 50));
  const hostInput = document.getElementById('hub-connection-access-host');
  const userInput = document.getElementById('hub-connection-access-username');
  const passInput = document.getElementById('hub-connection-access-password');
  if (!(hostInput instanceof HTMLInputElement)) throw new Error('host input missing');
  if (!(userInput instanceof HTMLInputElement)) throw new Error('username input missing');
  if (!(passInput instanceof HTMLInputElement)) throw new Error('password input missing');
  dom.simulateInput(hostInput, '192.168.1.2');
  dom.simulateInput(userInput, 'admin2');
  dom.simulateInput(passInput, 'secret-b');
  const saveBtn = findButtonByLabel('Сохранить доступ');
  if (!saveBtn) throw new Error('save access button missing');
  saveBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 400));
  await waitForText('Да, это мой роутер', 80);
  const confirmBtn = findButtonByLabel('Да, это мой роутер');
  if (!confirmBtn) throw new Error('confirm host key button missing');
  confirmBtn.click();
  await waitForText('Роутер управления', 80);
  await new Promise((resolve) => setTimeout(resolve, 200));
  result = {{
    visibleText: dom.collectVisibleText(container),
    healthCallCount,
  }};
}} else if (scenario === 'in_flight_unknown_facts') {{
  await waitForText('Совпадает с сохранённым роутером');
  await waitForText('Проверить снова');
  await new Promise((resolve) => setTimeout(resolve, 100));
  healthDelayMs = 5000;
  const recheckBtn = findButtonByLabel('Проверить снова');
  if (!recheckBtn) throw new Error('recheck button missing');
  recheckBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 50));
  result = {{
    visibleText: dom.collectVisibleText(container),
    healthCallCount,
  }};
  if (healthResolve) healthResolve();
}} else if (scenario === 'stale_error_after_binding_change') {{
  await waitForText('Совпадает с сохранённым роутером');
  healthFailOnce = true;
  const recheckBtn = findButtonByLabel('Проверить снова');
  if (!recheckBtn) throw new Error('recheck button missing');
  recheckBtn.click();
  await waitForText('Проблема с роутером', 80);
  await waitForText('Назад к доступу');
  const backBtn = findButtonByLabel('Назад к доступу');
  if (!backBtn) throw new Error('back to access button missing');
  backBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 50));
  const hostInput = document.getElementById('hub-connection-access-host');
  const userInput = document.getElementById('hub-connection-access-username');
  const passInput = document.getElementById('hub-connection-access-password');
  if (!(hostInput instanceof HTMLInputElement)) throw new Error('host input missing');
  if (!(userInput instanceof HTMLInputElement)) throw new Error('username input missing');
  if (!(passInput instanceof HTMLInputElement)) throw new Error('password input missing');
  dom.simulateInput(hostInput, '192.168.1.2');
  dom.simulateInput(userInput, 'admin2');
  dom.simulateInput(passInput, 'secret-b');
  const saveBtn = findButtonByLabel('Сохранить доступ');
  if (!saveBtn) throw new Error('save access button missing');
  saveBtn.click();
  await new Promise((resolve) => setTimeout(resolve, 400));
  await waitForText('Да, это мой роутер', 80);
  const confirmBtn = findButtonByLabel('Да, это мой роутер');
  if (!confirmBtn) throw new Error('confirm host key button missing');
  confirmBtn.click();
  await waitForText('Роутер управления', 80);
  await new Promise((resolve) => setTimeout(resolve, 200));
  result = {{
    visibleText: dom.collectVisibleText(container),
    healthCallCount,
  }};
}} else if (scenario === 'management_not_checked_without_health') {{
  dispose();
  resetSession();
  updateSession({{
    routerId: {json.dumps(router_a)},
    routerHost: '192.168.1.1',
    hostKeyConfirmed: true,
    liveReady: false,
    usernameAvailable: true,
    connectionRestoreState: 'done',
    wifiLive: {{
      host: '192.168.1.1',
      credentialRefId: 'cred-a',
      sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},
    }},
  }});
  document.body.appendChild(container);
  render(container, {{
    runtime: {{ adapterMode: 'fake' }},
    navigate: () => {{}},
    showToast: () => {{}},
  }});
  await new Promise((resolve) => setTimeout(resolve, 100));
  result = {{
    visibleText: dom.collectVisibleText(container),
    healthCallCount,
  }};
}} else {{
  throw new Error(`unknown scenario: ${{scenario}}`);
}}

console.log(JSON.stringify(result));

dispose();
"""


def test_stale_health_not_shown_after_binding_change(tmp_path: Path) -> None:
    """G-1: после смены привязки экран VERIFY отражает router B и свежий health."""
    payload = _run_node_harness(
        _health_zone_g_harness_script(scenario="stale_after_binding_change"),
        tmp_path,
        "g1-stale-health",
    )
    visible = str(payload["visibleText"])
    assert "192.168.1.2" in visible
    assert "Роутер управления" in visible
    assert payload["healthCallCount"] >= 2
    assert "192.168.1.1" not in visible


def test_health_check_in_flight_shows_unknown_facts(tmp_path: Path) -> None:
    """G-2/J-7: во время проверки нет чеклиста с вердиктами «Неизвестно»."""
    payload = _run_node_harness(
        _health_zone_g_harness_script(scenario="in_flight_unknown_facts"),
        tmp_path,
        "g2-in-flight",
    )
    visible = str(payload["visibleText"])
    assert "Совпадает с сохранённым роутером" not in visible
    assert "Проверяем связь с роутером" in visible
    assert "Неизвестно" not in visible


def test_management_availability_honest_without_health(tmp_path: Path) -> None:
    """G-3/J-7: без health-результата — «Управление не проверено», без чеклиста."""
    payload = _run_node_harness(
        _health_zone_g_harness_script(scenario="management_not_checked_without_health"),
        tmp_path,
        "g3-management-copy",
    )
    visible = str(payload["visibleText"])
    assert "Управление не проверено" in visible
    assert "Управление пока недоступно" not in visible
    assert "Управление доступно" not in visible
    assert "Неизвестно" not in visible


def test_stale_health_error_not_shown_after_binding_change(tmp_path: Path) -> None:
    """J-6: ошибка health роутера A не показывается для роутера B."""
    payload = _run_node_harness(
        _health_zone_g_harness_script(scenario="stale_error_after_binding_change"),
        tmp_path,
        "j6-stale-health-error",
    )
    visible = str(payload["visibleText"])
    assert "Не удалось проверить связь с роутером" not in visible
    assert "Проблема с роутером" not in visible


def _assert_single_candidate_auto_advances(source: str) -> None:
    """Один кандидат поиска автоматически открывает шаг «Доступ»."""
    discovery_body = _extract_function_body(source, "async function runDiscoveryFlow(")
    assert discovery_body is not None
    assert "discoveryView.candidates.length === 1" in discovery_body
    assert "setMaxReachableStep(ConnectionStep.ACCESS)" in discovery_body
    assert "goToStep(ConnectionStep.ACCESS)" in discovery_body
    assert "!manualMode" in discovery_body.replace(" ", "")
    assert "!selectedTarget" not in discovery_body.split("discoveryView.candidates.length === 1", 1)[1].split("} catch", 1)[0]


def _assert_single_candidate_rebinds_stale_target(source: str) -> None:
    """Повторный поиск с одним кандидатом перепривязывает selectedTarget/accessHost."""
    discovery_body = _extract_function_body(source, "async function runDiscoveryFlow(")
    assert discovery_body is not None
    single_block = discovery_body.split("discoveryView.candidates.length === 1", 1)[1].split("} catch", 1)[0]
    assert "selectedTarget =" in single_block
    assert "accessHost=only.host" in single_block.replace(" ", "")
    assert "!selectedTarget" not in single_block


def _assert_save_access_chains_learn_host_key(source: str) -> None:
    """После сохранения доступа отпечаток запрашивается автоматически."""
    save_body = _extract_function_body(source, "async function saveAccessFlow(")
    assert save_body is not None
    assert "chainLearnHostKey = true" in save_body
    assert re.search(r"if\s*\(\s*chainLearnHostKey\s*&&", save_body) is not None
    assert re.search(r"void\s+learnHostKeyFlow\s*\(\s*\)", save_body) is not None
    try_block = save_body.split("try {", 1)[1].split("} catch", 1)[0]
    assert re.search(r"void\s+learnHostKeyFlow\s*\(\s*\)", try_block) is None


def _assert_confirm_chains_verify_and_health(source: str) -> None:
    """Успешное подтверждение отпечатка автоматически запускает проверку."""
    confirm_body = _extract_function_body(source, "async function confirmHostKeyFlow(")
    assert confirm_body is not None
    success_slice = confirm_body.split("hostKeyConfirmed: true", 1)[-1]
    normalized = success_slice.replace(" ", "")
    assert "goToStep(ConnectionStep.VERIFY)" in normalized
    assert "voidrunHealthCheckFlow()" in normalized


def _assert_confirm_requires_explicit_click(source: str) -> None:
    """hostKeyConfirmed=true только в confirmHostKeyFlow после API; learn/save не подтверждают."""
    learn_body = _extract_function_body(source, "async function learnHostKeyFlow(")
    save_body = _extract_function_body(source, "async function saveAccessFlow(")
    confirm_body = _extract_function_body(source, "async function confirmHostKeyFlow(")
    assert learn_body is not None
    assert save_body is not None
    assert confirm_body is not None
    assert "confirmHostKeyFlow" not in learn_body
    assert "confirmHostKey(" not in learn_body
    save_success = save_body.split("activeRouterId = routerId", 1)[-1]
    assert "hostKeyConfirmed: true" not in save_success.replace(" ", "")
    assert re.search(r"hostKeyConfirmed\s*:\s*true", confirm_body) is not None
    assert "Да, это мой роутер" in source
    assert "Перейти к проверке" not in source


def _mutate_skip_auto_advance_single_candidate(source: str) -> tuple[str, bool]:
    old = """        if (!manualMode) {
          setMaxReachableStep(ConnectionStep.ACCESS);
          goToStep(ConnectionStep.ACCESS);
        }"""
    if old not in source:
        return source, False
    return source.replace(old, "        /* auto-advance removed */"), True


def _mutate_skip_learn_after_save(source: str) -> tuple[str, bool]:
    old = """    if (chainLearnHostKey && !disposed && gen === generation && !offline) {
      void learnHostKeyFlow();
    }"""
    if old not in source:
        return source, False
    return source.replace(old, "    /* learn chain removed */"), True


def _shortened_flow_harness_script() -> str:
    session_uri = json.dumps(SESSION_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))

    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{
          el.children.unshift(node);
          node.parentNode = el;
        }} else {{
          el.appendChild(node);
        }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

globalThis.HTMLInputElement = document.createElement('input').constructor;

globalThis.HTMLButtonElement = document.createElement('button').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

const apiCalls = [];

function findButtonByLabel(label) {{
  const buttons = document.querySelectorAll('button');
  return [...buttons].find((btn) => dom.collectVisibleText(btn).includes(label)) ?? null;
}}

globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  const body = init.body ? JSON.parse(String(init.body)) : null;
  apiCalls.push({{ method, url: String(url), body }});
  if (method === 'POST' && String(url).includes('lab/router-discovery')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        candidates: [{{
          host: '192.168.1.50',
          port: 22,
          candidate_origin: 'default_gateway',
          identity_state: 'unknown',
          reason_code: 'unenrolled_host',
        }}],
      }}),
    }};
  }}
  if (method === 'POST' && String(url).includes('lab/wizard-draft-router')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        router_id: {json.dumps(DRAFT_ROUTER_ID)},
        credential_ref_id: 'cred-draft',
        username: 'admin',
      }}),
    }};
  }}
  if (method === 'POST' && String(url).includes('/ssh-host-key/learn')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        fingerprint_sha256: {json.dumps(REAL_FINGERPRINT)},
        algorithm: 'ssh-ed25519',
      }}),
    }};
  }}
  if (method === 'POST' && String(url).includes('/ssh-host-key/confirm')) {{
    return {{
      ok: true,
      status: 204,
      headers: {{ get: () => '' }},
      text: async () => '',
      json: async () => null,
    }};
  }}
  if (method === 'POST' && String(url).includes('lab/connection-health')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        status: 'green',
        writes_allowed: true,
        facts: {{
          reachable: true,
          credentials_present: true,
          host_key_match: true,
          tuple_match: true,
          evidence_fresh: true,
        }},
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{url}}`);
}};

import {{ resetSession, getSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

const container = document.createElement('div');

document.body.appendChild(container);

const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate: () => {{}},
  showToast: () => {{}},
}});

await new Promise((resolve) => setTimeout(resolve, 250));

const afterDiscoveryText = dom.collectVisibleText(container);
const afterDiscoveryHasAccessHost = !!document.getElementById('hub-connection-access-host');
const sessionAfterDiscovery = getSession();

const hostInput = document.getElementById('hub-connection-access-host');
const userInput = document.getElementById('hub-connection-access-username');
const passInput = document.getElementById('hub-connection-access-password');
if (!(hostInput instanceof HTMLInputElement)) throw new Error('host input missing after discovery');
if (!(userInput instanceof HTMLInputElement)) throw new Error('username input missing');
if (!(passInput instanceof HTMLInputElement)) throw new Error('password input missing');

dom.simulateInput(userInput, 'admin');
dom.simulateInput(passInput, 'secret123');
const saveBtn = findButtonByLabel('Сохранить доступ');
if (!saveBtn) throw new Error('save access button missing');
saveBtn.click();

await new Promise((resolve) => setTimeout(resolve, 250));

const sessionAfterSave = getSession();
const afterSaveText = dom.collectVisibleText(container);
const confirmBtnBeforeClick = findButtonByLabel('Да, это мой роутер');

if (!confirmBtnBeforeClick) throw new Error('confirm button missing before click');

confirmBtnBeforeClick.click();

await new Promise((resolve) => setTimeout(resolve, 250));

const sessionAfterConfirm = getSession();
const afterConfirmText = dom.collectVisibleText(container);

const confirmCalls = apiCalls.filter(
  (call) => call.method === 'POST' && call.url.includes('/ssh-host-key/confirm'),
);
const learnCalls = apiCalls.filter(
  (call) => call.method === 'POST' && call.url.includes('/ssh-host-key/learn'),
);
const healthCalls = apiCalls.filter(
  (call) => call.method === 'POST' && call.url.includes('lab/connection-health'),
);

console.log(JSON.stringify({{
  afterDiscoveryHasAccessHost,
  afterDiscoveryTextIncludesAccess: afterDiscoveryText.includes('Доступ'),
  hostAfterDiscovery: hostInput.value,
  sessionHostKeyAfterSave: sessionAfterSave.hostKeyConfirmed,
  sessionHostKeyAfterConfirm: sessionAfterConfirm.hostKeyConfirmed,
  afterSaveHasFingerprint: afterSaveText.includes({json.dumps(REAL_FINGERPRINT)}),
  afterConfirmOnVerify: afterConfirmText.includes('Проверка соединения'),
  learnCallCount: learnCalls.length,
  confirmCallCount: confirmCalls.length,
  healthCallCount: healthCalls.length,
  routerIdAfterSave: sessionAfterSave.routerId,
}}));

dispose();
"""


def _rediscovery_single_candidate_harness_script() -> str:
    session_uri = json.dumps(SESSION_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))
    host_a = "192.168.1.10"
    host_b = "192.168.1.20"

    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

function patchElement(el) {{
  if (!el.prepend) {{
    el.prepend = (...nodes) => {{
      for (let i = nodes.length - 1; i >= 0; i -= 1) {{
        const node = nodes[i];
        if (el.children && el.children.length > 0) {{
          el.children.unshift(node);
          node.parentNode = el;
        }} else {{
          el.appendChild(node);
        }}
      }}
    }};
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  return el;
}}

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

globalThis.HTMLInputElement = document.createElement('input').constructor;

globalThis.HTMLButtonElement = document.createElement('button').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

function findButtonByLabel(label) {{
  const buttons = document.querySelectorAll('button');
  return [...buttons].find((btn) => dom.collectVisibleText(btn).includes(label)) ?? null;
}}

let discoveryCallCount = 0;

globalThis.fetch = async (url, init = {{}}) => {{
  const method = init.method ?? 'GET';
  if (method === 'POST' && String(url).includes('lab/router-discovery')) {{
    discoveryCallCount += 1;
    if (discoveryCallCount === 1) {{
      return {{
        ok: true,
        status: 200,
        headers: {{ get: () => 'application/json' }},
        json: async () => ({{
          candidates: [
            {{
              host: {json.dumps(host_a)},
              port: 22,
              candidate_origin: 'default_gateway',
              identity_state: 'unknown',
              reason_code: 'unenrolled_host',
            }},
            {{
              host: {json.dumps(host_b)},
              port: 22,
              candidate_origin: 'mdns',
              identity_state: 'unknown',
              reason_code: 'unenrolled_host',
            }},
          ],
        }}),
      }};
    }}
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        candidates: [{{
          host: {json.dumps(host_b)},
          port: 22,
          candidate_origin: 'default_gateway',
          identity_state: 'unknown',
          reason_code: 'unenrolled_host',
        }}],
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{url}}`);
}};

import {{ resetSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

const container = document.createElement('div');

document.body.appendChild(container);

const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate: () => {{}},
  showToast: () => {{}},
}});

await new Promise((resolve) => setTimeout(resolve, 250));

const hostAInput = document.getElementById('hub-connection-candidate-0');
if (!(hostAInput instanceof HTMLInputElement)) throw new Error('candidate A radio missing');
hostAInput.click();
await new Promise((resolve) => setTimeout(resolve, 50));

const findBtn = findButtonByLabel('Найти роутер');
if (!findBtn) throw new Error('find router button missing');
findBtn.click();

await new Promise((resolve) => setTimeout(resolve, 250));

const accessHostInput = document.getElementById('hub-connection-access-host');
const visibleText = dom.collectVisibleText(container);

console.log(JSON.stringify({{
  discoveryCallCount,
  accessHostValue: accessHostInput instanceof HTMLInputElement ? accessHostInput.value : null,
  onAccessStep: visibleText.includes('Доступ'),
  hasAccessHostField: !!accessHostInput,
}}));

dispose();
"""


def test_connection_single_candidate_auto_advances_to_access() -> None:
    """Упрощённый поток: один кандидат автоматически открывает шаг «Доступ»."""
    _assert_single_candidate_auto_advances(_read(CONNECTION_JS))


def test_connection_single_candidate_rebinds_stale_target() -> None:
    """Повторный поиск с одним кандидатом перепривязывает host, даже если раньше был выбран другой."""
    _assert_single_candidate_rebinds_stale_target(_read(CONNECTION_JS))


def test_connection_rediscovery_single_candidate_uses_new_host(tmp_path: Path) -> None:
    """Поведение: multi→select A→rediscover single B → ACCESS показывает B."""
    payload = _run_node_harness(
        _rediscovery_single_candidate_harness_script(),
        tmp_path,
        "connection-rediscovery-single-candidate",
    )
    assert payload["discoveryCallCount"] == 2
    assert payload["accessHostValue"] == "192.168.1.20"
    assert payload["onAccessStep"] is True
    assert payload["hasAccessHostField"] is True


def test_connection_save_access_chains_learn_host_key() -> None:
    """Упрощённый поток: после сохранения доступа отпечаток запрашивается сам."""
    _assert_save_access_chains_learn_host_key(_read(CONNECTION_JS))


def test_connection_confirm_chains_verify_and_health() -> None:
    """Упрощённый поток: после подтверждения отпечатка идёт проверка связи."""
    _assert_confirm_chains_verify_and_health(_read(CONNECTION_JS))


def test_connection_confirm_requires_explicit_click() -> None:
    """Безопасность: подтверждение отпечатка только по явному клику оператора."""
    _assert_confirm_requires_explicit_click(_read(CONNECTION_JS))


def test_detector_skip_auto_advance_single_candidate_fails() -> None:
    """Самопроверка: удаление auto-advance ловится контрактом одного кандидата."""
    source = _read(CONNECTION_JS)
    _assert_single_candidate_auto_advances(source)
    broken, applied = _mutate_skip_auto_advance_single_candidate(source)
    assert applied
    with pytest.raises(AssertionError):
        _assert_single_candidate_auto_advances(broken)


def test_detector_skip_learn_after_save_fails() -> None:
    """Самопроверка: удаление цепочки learn после save ловится контрактом."""
    source = _read(CONNECTION_JS)
    _assert_save_access_chains_learn_host_key(source)
    broken, applied = _mutate_skip_learn_after_save(source)
    assert applied
    with pytest.raises(AssertionError):
        _assert_save_access_chains_learn_host_key(broken)


def test_connection_shortened_happy_path_behavior(tmp_path: Path) -> None:
    """Поведение: auto ACCESS → auto learn → confirm click → auto VERIFY+health."""
    payload = _run_node_harness(
        _shortened_flow_harness_script(),
        tmp_path,
        "connection-shortened-flow",
    )
    assert payload["afterDiscoveryHasAccessHost"] is True
    assert payload["afterDiscoveryTextIncludesAccess"] is True
    assert payload["hostAfterDiscovery"] == "192.168.1.50"
    assert payload["sessionHostKeyAfterSave"] is False
    assert payload["learnCallCount"] >= 1
    assert payload["afterSaveHasFingerprint"] is True
    assert payload["confirmCallCount"] == 1
    assert payload["sessionHostKeyAfterConfirm"] is True
    assert payload["afterConfirmOnVerify"] is True
    assert payload["healthCallCount"] >= 1
    assert payload["routerIdAfterSave"] == DRAFT_ROUTER_ID


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


def test_connection_connectivity_offline_invalidates_all_operations() -> None:
    """domain-connection-offline-invalidate: offline connectivity invalidates in-flight connection ops."""
    source = _read(CONNECTION_JS)
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
