"""Структурные и поведенческие контракты экрана «Домен» LOCAL HUB."""

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
DOMAIN_SCREEN_JS = HUB / "screens" / "domain.js"
DOMAIN_MODEL_JS = HUB / "features" / "domain-model.js"
DOMAIN_SIMPLE_PUBLISH_JS = HUB / "features" / "domain-simple-publish.js"
SESSION_JS = HUB / "core" / "session.js"
WIFI_QR_JS = HUB / "features" / "wifi-qr.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

FORBIDDEN_DOMAIN_LITERALS = (
    "Приложение опубликовано",
    "Сертификат действителен",
    "Переадресация работает",
    "После изменения адреса старая ссылка перестанет работать",
)

FORBIDDEN_DOMAIN_BADGE_RE = re.compile(
    r"""(?:label|title):\s*['"]Доступно['"]""",
)

FORBIDDEN_KEENDNS_DISPATCH_PATHS = (
    "keendns/book",
    "keendns/drop",
    "keendns/update",
)

ALLOWED_KEENDNS_PATHS = (
    "keendns/status",
    "keendns/preview",
    "keendns/apply",
)

HTTP_DOMAIN_ASSETS = (
    "/settings/router-control/hub/screens/domain.js",
    "/settings/router-control/hub/features/domain-model.js",
    "/settings/router-control/hub/features/domain-simple-publish.js",
)

IMPORT_FROM_RE = re.compile(
    r"""from\s+['"](\.[^'"]+)['"]""",
)

CONSOLE_EMIT_RE = re.compile(
    r"console\.(log|info|debug|warn|error)\s*\(",
    re.IGNORECASE,
)


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
                    if source[j] == "{":
                        body_depth += 1
                    elif source[j] == "}":
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
            f"node is required for hub domain screen tests; install Node.js or set "
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


def _run_domain_model_export(tmp_path: Path, *, label: str, script_body: str) -> object:
    model_uri = DOMAIN_MODEL_JS.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def test_domain_screen_exports_meta_and_render() -> None:
    source = _read(DOMAIN_SCREEN_JS)
    assert "export const meta" in source
    assert "export function render(container, ctx)" in source
    assert "id: 'domain'" in source or 'id: "domain"' in source


def test_domain_screen_subscribes_to_session_and_unsubscribes_on_cleanup() -> None:
    """Экран подписывается на session и отписывается в cleanup."""
    source = _read(DOMAIN_SCREEN_JS)
    render_body = _extract_function_body(source, "export function render(")
    assert render_body is not None
    assert "subscribeSession" in source
    assert "unsubSession" in source
    assert "unsubSession()" in source
    assert "trackedEventPresetId" in render_body
    assert "nextPresetId === trackedEventPresetId" in render_body
    assert "resetPresetDerivedState" in render_body
    assert "void loadPresetFlow()" in render_body
    assert "updateSession" not in render_body, "domain screen must not write session (reload loop)"


def test_domain_screen_session_subscription_behavioral(tmp_path: Path) -> None:
    """subscribeSession: handler вызывается при смене eventPresetId и отписывается."""
    session_uri = SESSION_JS.as_uri()
    result = _run_node_harness(
        f"""
import {{ subscribeSession, updateSession, resetSession }} from {json.dumps(session_uri)};

resetSession();
let callCount = 0;
let lastPresetId = null;
const unsub = subscribeSession((snapshot) => {{
  callCount += 1;
  lastPresetId = snapshot.eventPresetId;
}});

updateSession({{ routerHost: '10.0.0.1' }});
updateSession({{ eventPresetId: 'preset-a', eventPresetName: 'A' }});
updateSession({{ eventPresetId: 'preset-b', eventPresetName: 'B' }});
updateSession({{ eventPresetId: 'preset-b' }});
unsub();
updateSession({{ eventPresetId: 'preset-c' }});

console.log(JSON.stringify({{
  callCount,
  lastPresetId,
}}));
""",
        tmp_path,
        "session-subscription",
    )
    assert result["callCount"] == 4
    assert result["lastPresetId"] == "preset-b"


def test_domain_empty_state_wordings(tmp_path: Path) -> None:
    """Два честных текста пустого состояния и нейтральный fallback."""
    result = _run_domain_model_export(
        tmp_path,
        label="empty-state",
        script_body="""
console.log(JSON.stringify({
  choose: mod.describeDomainEventEmptyState({ hasEventPresets: true }),
  none: mod.describeDomainEventEmptyState({ hasEventPresets: false }),
  unknown: mod.describeDomainEventEmptyState({ hasEventPresets: null }),
}));
""",
    )
    assert result["choose"]["title"] == "Мероприятие не выбрано"
    assert (
        result["choose"]["description"]
        == "Выберите мероприятие в селекторе верхней панели, "
        + "чтобы задать локальный адрес приложения."
    )
    assert result["none"]["title"] == "Мероприятие ещё не создано"
    assert "Мероприятие пока не создано" in result["none"]["description"]
    assert result["unknown"]["title"] == "Мероприятие не выбрано"
    assert result["unknown"]["description"] == result["choose"]["description"]


def test_domain_probe_dns_failed_copy(tmp_path: Path) -> None:
    """Проба HTTP/TLS: «адрес», не «имя приложения»."""
    result = _run_domain_model_export(
        tmp_path,
        label="probe-copy",
        script_body="""
console.log(JSON.stringify({
  http: mod.describeHostHttpProbe({
    reason_code: 'host_http.dns_failed',
    reachable: false,
  }).message,
  tls: mod.describeHostTlsProbe({
    reason_code: 'host_tls.dns_failed',
    aggregate_status: 'failed',
  }).message,
}));
""",
    )
    assert "Адрес приложения не найден в сети" in result["http"]
    assert "Имя приложения" not in result["http"]
    assert result["tls"] == (
        "Адрес приложения не найден в сети — проверка сертификата не выполнялась."
    )
    assert "Имя приложения" not in result["tls"]


def test_domain_host_http_probe_pending_renders_neutral_not_warning(tmp_path: Path) -> None:
    """Не выполненная HTTP-проба — EMPTY/neutral, не WARNING «Внимание»."""
    result = _run_domain_model_export(
        tmp_path,
        label="http-pending-neutral",
        script_body="""
console.log(JSON.stringify(mod.describeHostHttpProbe({ reason_code: 'host_http.pending' })));
""",
    )
    assert result["factState"] == "unknown"
    assert result["hubState"] == "EMPTY"
    assert result["hubState"] != "WARNING"
    assert "ещё не выполнялась" in result["message"]


def test_domain_model_source_honesty_guards() -> None:
    source = _read(DOMAIN_MODEL_JS)
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "innerHTML" not in source
    assert not CONSOLE_EMIT_RE.search(source)
    assert "Имя приложения не удалось найти" not in source


def test_domain_screen_syntax_via_mjs_copy(tmp_path: Path) -> None:
    node = _require_node()
    mjs_copy = tmp_path / "domain-screen.mjs"
    mjs_copy.write_text(_read(DOMAIN_SCREEN_JS), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    return create_app(db_path=tmp_path / "hub-domain.sqlite3", enable_worker=False)


@pytest.fixture
def authed_client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def _resolve_relative_import(base_file: Path, specifier: str) -> Path:
    target = (base_file.parent / specifier).resolve()
    if target.is_file():
        return target
    with_suffix = target.with_suffix(".js")
    if with_suffix.is_file():
        return with_suffix
    index_candidate = target / "index.js"
    if index_candidate.is_file():
        return index_candidate
    raise AssertionError(f"unresolved import {specifier!r} from {base_file}")


def test_domain_screen_honesty_forbidden_literals() -> None:
    """D-DOM-1/D-DOM-12: экран не воспроизводит обманчивые формулировки макета."""
    source = _read(DOMAIN_SCREEN_JS)
    for literal in FORBIDDEN_DOMAIN_LITERALS:
        assert literal not in source, f"forbidden literal: {literal}"
    assert FORBIDDEN_DOMAIN_BADGE_RE.search(source) is None


def test_domain_screen_local_application_only_orders_option() -> None:
    """D-DOM-4: единственный пункт локального приложения — «Система заказов»."""
    source = _read(DOMAIN_SCREEN_JS)
    assert (
        "options: [{ value: 'orders', label: 'Система заказов' }]"
        in source
        or 'options: [{ value: "orders", label: "Система заказов" }]' in source
    )
    assert "value: 'fake'" not in source and 'value: "fake"' not in source


def test_domain_screen_keendns_paths_allowed_no_dispatch() -> None:
    """D-DOM-7: экран и модель ссылаются на keendns/status, preview и apply."""
    combined = _read(DOMAIN_SCREEN_JS) + "\n" + _read(DOMAIN_MODEL_JS)
    for path in ALLOWED_KEENDNS_PATHS:
        assert path in combined, f"missing allowed path: {path}"
    for forbidden in FORBIDDEN_KEENDNS_DISPATCH_PATHS:
        assert forbidden not in combined, f"forbidden dispatch path: {forbidden}"


def test_domain_screen_imports_wifi_qr_helper() -> None:
    """D-DOM-11: QR через features/wifi-qr.js, без blob:/createObjectURL."""
    source = _read(DOMAIN_SCREEN_JS)
    assert "from '../features/wifi-qr.js'" in source or 'from "../features/wifi-qr.js"' in source
    assert "drawWifiQrCanvas" in source
    assert "blob:" not in source
    assert "createObjectURL" not in source


def test_domain_screen_draft_link_note_honest() -> None:
    """D-DOM-12: честная замена подписи про «старую ссылку» — черновик без облачной записи."""
    source = _read(DOMAIN_SCREEN_JS) + "\n" + _read(DOMAIN_MODEL_JS)
    assert "После изменения адреса старая ссылка перестанет работать" not in source
    assert "Ссылка существует только как черновик" in source


def test_domain_screen_import_specifiers_resolve() -> None:
    """Регрессия: все static import specifiers экрана разрешаются в файлы."""
    source = _read(DOMAIN_SCREEN_JS)
    specifiers = IMPORT_FROM_RE.findall(source)
    assert specifiers, "expected static imports in domain screen"
    for specifier in specifiers:
        resolved = _resolve_relative_import(DOMAIN_SCREEN_JS, specifier)
        assert resolved.is_file(), specifier


def test_domain_screen_mount_once_no_clear_content_wrap() -> None:
    """F-DOM-01: renderContent не очищает contentWrap; mountLayoutOnce + signatures."""
    source = _read(DOMAIN_SCREEN_JS)
    render_content = _extract_function_body(source, "function renderContent()")
    assert render_content is not None
    assert "mountLayoutOnce" in render_content
    assert "clearElement(contentWrap)" not in render_content
    assert "buildSideSignature" in source
    assert "describeActiveProbeRow" in source


def test_domain_probe_card_always_three_rows_during_probing() -> None:
    """F-DOM-01: во время probing три строки проб, без mono CONNECTING wipe."""
    source = _read(DOMAIN_SCREEN_JS)
    probe_body = _extract_function_body(source, "function renderProbeCard()")
    assert probe_body is not None
    assert "describeActiveProbeRow(httpProbeResponse" in probe_body
    assert "internetProbeResponse" in probe_body
    assert "describeActiveProbeRow" in probe_body
    assert "Выполняем проверки" not in probe_body


def test_domain_assets_served_over_http(authed_client) -> None:
    """Регрессия: domain.js и domain-model.js отдаются с HTTP 200."""
    for url in HTTP_DOMAIN_ASSETS:
        response = authed_client.get(url)
        assert response.status_code == 200, url
        assert len(response.content) > 0, url


def test_domain_wifi_qr_module_exists_for_screen_import() -> None:
    """D-DOM-11: импортируемый wifi-qr.js существует на диске."""
    assert WIFI_QR_JS.is_file()
    assert "drawWifiQrCanvas" in _read(WIFI_QR_JS)


def test_domain_preset_soft_reload_skips_cold_skeleton() -> None:
    """F-3: preset reload при смонтированных настройках использует presetRefreshing, не skeleton-only."""
    source = _read(DOMAIN_SCREEN_JS)
    assert "presetRefreshing" in source
    assert "settingsMounted()" in source
    settings_body = _extract_function_body(source, "function renderSettingsCard()")
    assert settings_body is not None
    normalized = settings_body.replace(" ", "")
    assert "(presetLoading&&!settingsMounted())" in normalized
    assert "(statusLoading&&!settingsMounted())" in normalized
    assert "Обновляем данные" in settings_body
    load_body = _extract_function_body(source, "async function loadPresetFlow()")
    assert load_body is not None
    assert "presetRefreshing" in load_body
    assert "settingsMounted()" in load_body or "hasLoadedPresetOnce" in load_body


def test_domain_screen_imports_shared_gate_from_simple_publish() -> None:
    """R-8 F-7: book apply confirm + drop human gate из features/."""
    source = _read(DOMAIN_SCREEN_JS)
    assert "from '../features/domain-simple-publish.js'" in source or (
        'from "../features/domain-simple-publish.js"' in source
    )
    assert "openDomainPublishApplyConfirm" in source
    assert "openDomainPublishHumanGate" in source
    assert "mountDomainSimplePublishAffordance" in source
    apply_body = _extract_function_body(source, "function openPublishApplyModal(")
    assert apply_body is not None
    assert "openDomainPublishApplyConfirm" in apply_body
    assert "applyKeendnsBooking" in apply_body
    drop_body = _extract_function_body(source, "function openPublishGateModal(")
    assert drop_body is not None
    assert "openDomainPublishHumanGate" in drop_body


def test_domain_screen_has_opublikovat_primary_cta() -> None:
    """R-8 F-4: primary CTA «Опубликовать» на экране и в simple-модуле."""
    combined = _read(DOMAIN_SCREEN_JS) + _read(DOMAIN_SIMPLE_PUBLISH_JS)
    assert re.search(r"label:\s*['\"]Опубликовать", combined) is not None
    assert "openDomainPublishApplyConfirm" in combined


def test_domain_screen_main_signature_excludes_name_keystrokes() -> None:
    """R-8 F-2: buildMainSignature не включает domainName/domainSuffix."""
    source = _read(DOMAIN_SCREEN_JS)
    sig_body = _extract_function_body(source, "function buildMainSignature()")
    assert sig_body is not None
    assert "domainName" not in sig_body
    assert "domainSuffix" not in sig_body
    assert "onDomainNameOrSuffixSoftChange" in source


def test_domain_screen_syncs_advanced_name_suffix_on_soft_change() -> None:
    """R-8 F-2: simple→advanced soft sync без renderAll на keystroke."""
    source = _read(DOMAIN_SCREEN_JS)
    assert "syncAdvancedNameSuffixFieldsFromState" in source
    update_body = _extract_function_body(source, "function updateDraftDependentUi()")
    assert update_body is not None
    assert "syncAdvancedNameSuffixFieldsFromState" in update_body
    sync_body = _extract_function_body(source, "function syncAdvancedNameSuffixFieldsFromState(")
    assert sync_body is not None
    assert "hub-domain-name" in sync_body
    assert "hub-domain-suffix" in sync_body
    assert "activeElement" in sync_body


def test_domain_simple_publish_module_honesty_guards() -> None:
    """R-8: composition layer без storage/innerHTML/console/createObjectURL."""
    source = _read(DOMAIN_SIMPLE_PUBLISH_JS)
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "innerHTML" not in source
    assert not CONSOLE_EMIT_RE.search(source)
    assert "createObjectURL" not in source
    assert "blob:" not in source
