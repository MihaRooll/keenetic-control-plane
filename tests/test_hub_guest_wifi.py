"""Поведенческие контракты модели и экрана «Гостевой Wi‑Fi» LOCAL HUB."""

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
GUEST_WIFI_MODEL_JS = HUB / "features" / "guest-wifi-model.js"
GUEST_WIFI_SCREEN_JS = HUB / "screens" / "guest-wifi.js"
WIFI_AP_MODEL_JS = HUB / "features" / "wifi-ap-model.js"
WIFI_SCREEN_PARTS_JS = HUB / "features" / "wifi-screen-parts.js"
SW_JS = HUB / "sw.js"
SESSION_JS = HUB / "core" / "session.js"
UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
TEST_PSK = "test-psk-not-real-8chars"
REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"

DEVICE_COUNTER_RE = re.compile(
    r"\d+\s+устройств|\bустройств\b.*\d+|\d+\s+.*устройств",
    re.IGNORECASE,
)
GUEST_COUNTER_RE = re.compile(
    r"\d+\s+гост|\d+\s+.*гост|гост.*\d+|\$\{[^}]+\}\s*гост",
    re.IGNORECASE,
)
GUEST_COUNTER_CONCAT_RE = re.compile(
    r"(?:\+\s*['\"][^'\"]*гост|['\"][^'\"]*гост[^'\"]*['\"]\s*\+|`[^`]*\$\{[^}]+\}[^`]*гост)",
    re.IGNORECASE,
)
CONSOLE_EMIT_RE = re.compile(
    r"console\.(log|info|debug|warn|error)\s*\(",
    re.IGNORECASE,
)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub guest wifi tests; install Node.js or set "
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


def _run_wifi_ap_model_export(
    tmp_path: Path,
    *,
    label: str,
    script_body: str,
    model_source: str | None = None,
) -> object:
    if model_source is None:
        model_uri = WIFI_AP_MODEL_JS.as_uri()
    else:
        model_copy = tmp_path / f"{label}-wifi-ap-model.mjs"
        model_copy.parent.mkdir(parents=True, exist_ok=True)
        model_copy.write_text(model_source, encoding="utf-8")
        model_uri = model_copy.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def _assert_wifi_ap_model_applied_fallback_not_success(source: str) -> None:
    block = re.search(
        r"if \(overall === 'applied'\) \{\s*return \{\s*"
        r"hubState: HubState\.WARNING,\s*success: (true|false)",
        source,
        re.DOTALL,
    )
    assert block is not None, "applied fallback block must exist"
    assert block.group(1) == "false", "applied fallback must not return success:true"


def _assert_wifi_apply_verdict_not_success(
    tmp_path: Path,
    response: dict[str, object],
    *,
    model_source: str | None = None,
    expect_title_fragment: str | None = None,
    expect_message_fragment: str | None = None,
) -> None:
    result = _run_wifi_ap_model_export(
        tmp_path,
        label="apply-verdict-assert",
        script_body=f"""
console.log(JSON.stringify(mod.parseWifiApplyVerdict({json.dumps(response, ensure_ascii=False)})));
""",
        model_source=model_source,
    )
    assert result["success"] is False
    if expect_title_fragment is not None:
        assert expect_title_fragment.lower() in result["title"].lower()
    if expect_message_fragment is not None:
        assert expect_message_fragment.lower() in result["message"].lower()


def _assert_wifi_screen_no_apply_disable(source: str, *, teardown_fn: str) -> None:
    assert teardown_fn in source
    stripped = re.sub(
        r"runMutation\(\s*'teardown'[\s\S]*?'teardown',\s*\);",
        "",
        source,
    )
    assert "enabled: false" not in stripped
    assert "enabled:false" not in stripped.replace(" ", "")
    assert re.search(r"enabled\s*:\s*isOff", stripped) is None
    assert re.search(r"enabled\s*:\s*[^t\n\r]*false", stripped) is None
    assert re.search(r"wifi/apply.*enabled", stripped, re.IGNORECASE) is None


def _assert_wifi_screen_intent_confirm_pattern(source: str, *, ap_select_id: str) -> None:
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
    assert re.search(r"await onConfirm\(confirmedSnapshot\)", source)
    assert "assertConfirmedIntentStillValid(confirmedSnapshot," in source
    assert "assertConfirmedIntentStillValid(intent)" not in source
    assert "wifiMutationIntentMatchesCurrent(\n            confirmedIntentSnapshot," not in source
    ap_select_body = re.search(
        rf"id: '{ap_select_id}'[\s\S]*?"
        r"onChange: \(event\) => \{([\s\S]*?\n        \}\s*,)",
        source,
    )
    assert ap_select_body is not None
    assert "clearPreparedMutation" in ap_select_body.group(1)
    assert "sessionPskMemory = ''" in ap_select_body.group(1)


def _assert_guest_wifi_user_literals_have_no_guest_counter(source: str) -> None:
    user_literals = [
        text
        for _, text in re.findall(r"(['\"])(.*?)\1", source, re.DOTALL)
        if CYRILLIC.search(text)
    ]
    joined = "\n".join(user_literals)
    assert not GUEST_COUNTER_RE.search(joined)
    assert not GUEST_COUNTER_CONCAT_RE.search(source)


def _assert_guest_wifi_password_registration_error_safe(source: str) -> None:
    panel_body = re.search(
        r"function describePanelError\(err\) \{([\s\S]*?\n\})",
        source,
        re.DOTALL,
    )
    assert panel_body is not None
    block = panel_body.group(1)
    assert "client.credential_registration_failed" in block
    assert "serverMessage" not in block
    assert "technical: ''" in block or 'technical: ""' in block
    run_mutation_body = re.search(
        r"async function runMutation\(.+?\n  \}",
        source,
        re.DOTALL,
    )
    assert run_mutation_body is not None
    assert "describePanelError(error)" in run_mutation_body.group(0)


def _run_export(
    tmp_path: Path,
    *,
    label: str,
    script_body: str,
) -> object:
    script = f"""const mod = await import({json.dumps(GUEST_WIFI_MODEL_JS.as_uri())});
{script_body}
"""
    return _run_node_harness(script, tmp_path, label)


def _full_session() -> dict[str, object]:
    return {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "wifiLive": {
            "host": "10.0.0.1",
            "username": "admin",
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": REALISTIC_FINGERPRINT,
        },
        "wifiRoles": {"staffApId": "WifiMaster0/AccessPoint4", "guestApId": None},
        "sourceAddress": "192.168.2.144",
    }


def test_guest_wifi_preview_apply_always_guest_fields(tmp_path: Path) -> None:
    """preview/apply: guest_isolation=false, captive_portal=Disabled; never enabled:false."""
    result = _run_export(
        tmp_path,
        label="request-bodies",
        script_body=f"""
const preview = mod.buildGuestWifiPreviewBody({{
  apId: 'WifiMaster0/AccessPoint3',
  ssid: 'Guest-Lab',
  wpaMode: 'WPA2',
  enabled: true,
  credentialRefId: 'cred-wifi-1',
}});
const apply = mod.buildWifiApplyBody({{
  previewBody: preview,
  liveParams: {{
    host: '10.0.0.1',
    username: 'admin',
    router_credential_ref_id: 'cred-ref-1',
    ssh_host_key_sha256: {json.dumps(REALISTIC_FINGERPRINT)},
    source_address: null,
    router_id: 'router-lab-1',
  }},
}});
console.log(JSON.stringify({{ preview, apply }}));
""",
    )
    preview = result["preview"]
    apply = result["apply"]
    assert preview["guest_isolation"] is False
    assert preview["captive_portal"] == "Disabled"
    assert preview["enabled"] is True
    assert apply["guest_isolation"] is False
    assert apply["captive_portal"] == "Disabled"
    assert apply["enabled"] is True
    assert "enabled" not in apply or apply["enabled"] is True
    assert TEST_PSK not in json.dumps(apply)


def test_guest_wifi_teardown_not_apply_for_disable(tmp_path: Path) -> None:
    """Выключение — только teardown; apply с enabled:false не используется."""
    result = _run_export(
        tmp_path,
        label="teardown-body",
        script_body=f"""
const teardown = mod.buildWifiTeardownBody({{
  apId: 'WifiMaster1/AccessPoint3',
  wpaMode: 'WPA2',
  liveParams: {{
    host: '10.0.0.1',
    username: 'admin',
    router_credential_ref_id: 'cred-ref-1',
    ssh_host_key_sha256: {json.dumps(REALISTIC_FINGERPRINT)},
    source_address: null,
    router_id: 'router-lab-1',
  }},
}});
console.log(JSON.stringify(teardown));
""",
    )
    assert result["confirm_live_teardown"] is True
    assert "enabled" not in result


def test_guest_wifi_screen_teardown_only_no_apply_disable() -> None:
    """Экран: выключение через teardownGuestWifiNetwork, не apply с enabled:false."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    _assert_wifi_screen_no_apply_disable(source, teardown_fn="teardownGuestWifiNetwork")
    assert "applyGuestWifiChanges" not in source or "teardownFlow" in source


def test_guest_wifi_no_fake_device_or_guest_counters() -> None:
    """Нет литералов «23 устройства», счётчика гостей и выдуманной «Активна»."""
    model_source = GUEST_WIFI_MODEL_JS.read_text(encoding="utf-8")
    screen_source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    combined = f"{model_source}\n{screen_source}"
    assert "23 устройства" not in combined
    assert "устройств подключено" not in combined
    user_literals = [
        text
        for _, text in re.findall(r"(['\"])(.*?)\1", screen_source, re.DOTALL)
        if CYRILLIC.search(text)
    ]
    joined = "\n".join(user_literals)
    assert not DEVICE_COUNTER_RE.search(joined)
    assert not GUEST_COUNTER_RE.search(joined)
    assert not GUEST_COUNTER_CONCAT_RE.search(screen_source)
    assert not re.search(r"\$\{[^}]+\}\s*гост", joined, re.IGNORECASE)
    assert not re.search(r"\$\{[^}]+\}\s*гост", screen_source, re.IGNORECASE)
    assert "Активна" not in screen_source
    assert "GUEST_WIFI_GUEST_COUNTER_NOTE" in screen_source


def test_guest_wifi_no_isolation_or_limit_toggles() -> None:
    """Нет рабочего переключателя изоляции/лимита; есть честные строки с подписями."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "GUEST_WIFI_ISOLATION_LABEL" in source
    assert "GUEST_WIFI_ISOLATION_NOTE" in source
    assert "GUEST_WIFI_DEVICE_LIMIT_LABEL" in source
    assert "GUEST_WIFI_DEVICE_LIMIT_NOTE" in source
    assert "GUEST_WIFI_NO_OPEN_NETWORK_LABEL" in source
    assert "GUEST_WIFI_NO_OPEN_NETWORK_NOTE" in source
    settings_body = re.search(
        r"function renderSettingsCard\(\) \{(.+?\n  \}\n\n  function renderCaptivePortalCard)",
        source,
        re.DOTALL,
    )
    assert settings_body is not None
    block = settings_body.group(1)
    assert "createToggle" not in block
    assert "hub-wifi__unsupported-group" in block
    assert "hub-wifi__unsupported-row" in block
    assert "hub-wifi__unsupported-label" in block
    assert "GUEST_WIFI_ISOLATION_LABEL" in block
    assert "GUEST_WIFI_DEVICE_LIMIT_LABEL" in block
    assert "GUEST_WIFI_NO_OPEN_NETWORK_LABEL" in block


def test_guest_wifi_no_blob_or_object_url() -> None:
    """QR и экран не используют blob: / createObjectURL."""
    screen_source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    parts_source = WIFI_SCREEN_PARTS_JS.read_text(encoding="utf-8")
    combined = f"{screen_source}\n{parts_source}"
    assert "blob:" not in combined
    assert "createObjectURL" not in combined


def test_guest_wifi_password_not_logged() -> None:
    """Пароль не логируется и не попадает в технические строки экрана."""
    model_source = GUEST_WIFI_MODEL_JS.read_text(encoding="utf-8")
    screen_source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    combined = f"{model_source}\n{screen_source}"
    assert not CONSOLE_EMIT_RE.search(combined)
    technical_block = re.search(
        r"technicalNotes\s*=\s*\[([\s\S]*?)\]",
        screen_source,
    )
    assert technical_block is not None
    assert "password" not in technical_block.group(1).lower()
    assert "secret" not in technical_block.group(1).lower()
    assert "sessionPskMemory" not in technical_block.group(1)


@pytest.mark.parametrize(
    ("response", "expect_success", "expect_state", "title_fragment", "message_fragment"),
    [
        (
            {"overall": "applied", "on_air_verification_status": "on_air_verified", "errors": []},
            True,
            "SUCCESS",
            None,
            None,
        ),
        (
            {"overall": "applied", "on_air_verification_status": "on_air_admin_only", "errors": []},
            False,
            "WARNING",
            "оговорк",
            "телефона",
        ),
        (
            {"overall": "applied", "on_air_verification_status": "on_air_unverified", "errors": []},
            False,
            "WARNING",
            "оговорк",
            "телефона",
        ),
        (
            {
                "overall": "applied",
                "on_air_verification_status": "on_air_still_broadcasting",
                "errors": [],
            },
            False,
            "WARNING",
            "оговорк",
            "телефона",
        ),
        (
            {
                "overall": "dispatched_offline",
                "on_air_verification_status": "on_air_unverified",
                "errors": [],
            },
            False,
            "WARNING",
            "не отправлены",
            "без связи",
        ),
        (
            {
                "overall": "unsupported_pending_verification",
                "on_air_verification_status": "on_air_unverified",
                "errors": [],
            },
            False,
            "UNSUPPORTED",
            "недоступно",
            "не прошли проверку",
        ),
    ],
)
def test_guest_wifi_apply_verdict_on_air_admin_only_not_green(
    tmp_path: Path,
    response: dict[str, object],
    expect_success: bool,
    expect_state: str,
    title_fragment: str | None,
    message_fragment: str | None,
) -> None:
    """on_air_admin_only и родственные статусы не дают зелёного успеха."""
    result = _run_wifi_ap_model_export(
        tmp_path,
        label="apply-verdict",
        script_body=f"""
console.log(JSON.stringify(mod.parseWifiApplyVerdict({json.dumps(response, ensure_ascii=False)})));
""",
    )
    assert result["success"] is expect_success
    assert result["hubState"] == expect_state
    if title_fragment is not None:
        assert title_fragment.lower() in result["title"].lower()
    if message_fragment is not None:
        assert message_fragment.lower() in result["message"].lower()


def test_guest_wifi_model_imports_in_node(tmp_path: Path) -> None:
    """Модель экспортирует контрактные константы и хелперы намерения."""
    result = _run_export(
        tmp_path,
        label="import-check",
        script_body="""
console.log(JSON.stringify({
  hasList: typeof mod.listGuestWifiAccessPoints === 'function',
  hasPreview: typeof mod.buildGuestWifiPreviewBody === 'function',
  hasIntentSnapshot: typeof mod.buildWifiMutationIntentSnapshot === 'function',
  hasIntentMatch: typeof mod.wifiMutationIntentMatchesCurrent === 'function',
  counterNote: mod.GUEST_WIFI_GUEST_COUNTER_NOTE,
  isolationNote: mod.GUEST_WIFI_ISOLATION_NOTE,
  unreadableTitle: mod.WIFI_OBSERVED_UNREADABLE_TITLE,
  snapshot: mod.buildWifiMutationIntentSnapshot({
    apId: 'WifiMaster0/AccessPoint3',
    ssid: ' Guest ',
    wpaMode: 'WPA2',
    hasNewPassword: true,
  }),
  matches: mod.wifiMutationIntentMatchesCurrent(
    mod.buildWifiMutationIntentSnapshot({
      apId: 'WifiMaster0/AccessPoint3',
      ssid: 'Guest',
      wpaMode: 'WPA2',
      hasNewPassword: true,
    }),
    mod.buildWifiMutationIntentSnapshot({
      apId: 'WifiMaster0/AccessPoint3',
      ssid: 'Guest',
      wpaMode: 'WPA2',
      hasNewPassword: true,
    }),
  ),
  stale: mod.wifiMutationIntentMatchesCurrent(
    mod.buildWifiMutationIntentSnapshot({
      apId: 'WifiMaster0/AccessPoint3',
      ssid: 'Guest-A',
      wpaMode: 'WPA2',
      hasNewPassword: false,
    }),
    mod.buildWifiMutationIntentSnapshot({
      apId: 'WifiMaster0/AccessPoint3',
      ssid: 'Guest-B',
      wpaMode: 'WPA2',
      hasNewPassword: false,
    }),
  ),
}));
""",
    )
    assert result["hasList"] is True
    assert result["hasPreview"] is True
    assert result["hasIntentSnapshot"] is True
    assert result["hasIntentMatch"] is True
    assert "показать счётчик не получится" in result["counterNote"]
    assert "спрятать от гостей рабочие устройства" in result["isolationNote"]
    assert result["unreadableTitle"] == "Состояние сети не прочитано"
    assert result["snapshot"]["ssid"] == "Guest"
    assert result["matches"] is True
    assert result["stale"] is False


def test_guest_wifi_model_syntax_via_mjs_copy(tmp_path: Path) -> None:
    """Синтаксис guest-wifi-model.js проверяется копией .mjs."""
    node = _require_node()
    mjs_copy = tmp_path / "guest-wifi-model.mjs"
    mjs_copy.write_text(GUEST_WIFI_MODEL_JS.read_text(encoding="utf-8"), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_guest_wifi_screen_syntax_via_mjs_copy(tmp_path: Path) -> None:
    """Синтаксис guest-wifi.js проверяется копией .mjs."""
    node = _require_node()
    mjs_copy = tmp_path / "guest-wifi.mjs"
    mjs_copy.write_text(GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8"), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_guest_wifi_precache_includes_model() -> None:
    """guest-wifi-model.js в SHELL_URLS."""
    source = SW_JS.read_text(encoding="utf-8")
    assert "guest-wifi-model.js" in source


def test_guest_wifi_staff_ap_overlap_warning(tmp_path: Path) -> None:
    """Совпадение guestApId и staffApId → честное предупреждение."""
    session = _full_session()
    session["wifiRoles"] = {"staffApId": "WifiMaster0/AccessPoint3", "guestApId": None}
    session_json = json.dumps(session, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="overlap",
        script_body=f"""
console.log(JSON.stringify({{
  same: mod.getGuestStaffApOverlapWarning({session_json}, 'WifiMaster0/AccessPoint3'),
  different: mod.getGuestStaffApOverlapWarning({session_json}, 'WifiMaster1/AccessPoint5'),
}}));
""",
    )
    assert "перетирать" in result["same"]
    assert result["different"] is None


def test_guest_wifi_operator_text_has_required_honest_strings(tmp_path: Path) -> None:
    """serializeGuestWifiOperatorText содержит обязательные формулировки §4."""
    result = _run_export(
        tmp_path,
        label="operator-text",
        script_body="""
const observed = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint3',
  readable: true,
  ssid: 'Guest',
  wpa_mode: 'WPA2',
});
const screen = mod.buildGuestWifiScreenState({
  observed,
  draft: mod.createGuestWifiFormDraft(observed),
  selectedApId: observed.apId,
});
console.log(JSON.stringify({
  text: mod.serializeGuestWifiOperatorText({ observed, screen }),
}));
""",
    )
    text = result["text"]
    assert "показать счётчик не получится" in text
    assert "Изоляция от рабочей сети" in text
    assert "спрятать от гостей рабочие устройства" in text
    assert "Максимум устройств" in text
    assert "просто выключите гостевую сеть" in text
    assert "Режим без пароля" in text
    assert "Недоступен — пароль нужен даже гостям" in text
    assert "Роутер не умеет её включить" in text
    assert "Панель не узнает, подключился ли гость" in text
    assert "device_connected" not in text


def test_guest_wifi_screen_uses_model_endpoints() -> None:
    """Экран вызывает observed/apply через модель."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "fetchGuestWifiObservedState" in source
    assert "applyGuestWifiChanges" in source
    assert "wifi/observed-state" not in source
    assert "wifi/apply" not in source


def test_guest_wifi_screen_risk_modal_audience_guest() -> None:
    """Модалка риска использует audience: guest."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "audience: 'guest'" in source


def test_guest_wifi_no_share_network_button() -> None:
    """Кнопка «Поделиться сетью» не рисуется."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "Поделиться сетью" not in source


def test_guest_wifi_preview_never_guest_isolation_true(tmp_path: Path) -> None:
    """Тело preview никогда не содержит guest_isolation:true или captive_portal:Enabled."""
    result = _run_export(
        tmp_path,
        label="never-true-fields",
        script_body="""
const preview = mod.buildGuestWifiPreviewBody({
  apId: 'WifiMaster0/AccessPoint3',
  ssid: 'Guest',
  wpaMode: 'WPA3',
  enabled: true,
});
console.log(JSON.stringify(preview));
""",
    )
    assert result["guest_isolation"] is False
    assert result["captive_portal"] == "Disabled"
    assert result.get("guest_isolation") is not True


def test_guest_wifi_screen_shows_unreadable_state_panel() -> None:
    """Т-1: при readable:false показывается панель состояния с кнопкой «Повторить»."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "WIFI_OBSERVED_UNREADABLE_TITLE" in source
    assert "WIFI_OBSERVED_UNREADABLE_DESCRIPTION" in source
    assert "function isObservedUnreadable()" in source
    assert re.search(
        r"if \(isObservedUnreadable\(\)\) \{[\s\S]*?createStatePanel\([\s\S]*?"
        r"label:\s*['\"]Повторить['\"]",
        source,
    )


def test_guest_wifi_screen_stale_intent_guard() -> None:
    """Т-2: снимок передаётся аргументом и переживает onClose модалки."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "confirmedIntentSnapshot" in source
    assert "riskModalOpen" in source
    assert "wifiMutationIntentMatchesCurrent" in source
    assert "WIFI_MUTATION_INTENT_STALE_MESSAGE" in source
    assert re.search(r"controlsLocked\(\)[\s\S]*riskModalOpen", source)
    _assert_wifi_screen_intent_confirm_pattern(
        source,
        ap_select_id="hub-guest-wifi-ap-select",
    )


def test_guest_wifi_mutation_intent_explicit_snapshot_survives_clear(tmp_path: Path) -> None:
    """Поведенческий контракт: явный снимок валиден после обнуления переменной экрана."""
    result = _run_export(
        tmp_path,
        label="intent-survives-clear",
        script_body="""
const snapshot = mod.buildWifiMutationIntentSnapshot({
  apId: 'WifiMaster0/AccessPoint3',
  ssid: 'Guest',
  wpaMode: 'WPA2',
  hasNewPassword: false,
});
const current = mod.buildWifiMutationIntentSnapshot({
  apId: 'WifiMaster0/AccessPoint3',
  ssid: 'Guest',
  wpaMode: 'WPA2',
  hasNewPassword: false,
});
let screenSnapshot = snapshot;
screenSnapshot = null;
console.log(JSON.stringify({
  explicitValid: mod.wifiMutationIntentMatchesCurrent(snapshot, current),
  clearedInvalid: mod.wifiMutationIntentMatchesCurrent(screenSnapshot, current),
  staleReject: mod.wifiMutationIntentMatchesCurrent(snapshot, mod.buildWifiMutationIntentSnapshot({
    apId: 'WifiMaster0/AccessPoint3',
    ssid: 'Guest-Changed',
    wpaMode: 'WPA2',
    hasNewPassword: false,
  })),
}));
""",
    )
    assert result["explicitValid"] is True
    assert result["clearedInvalid"] is False
    assert result["staleReject"] is False


def test_guest_wifi_screen_stale_intent_guard_mutation_self_check() -> None:
    """Возврат к confirmedIntentSnapshot в assertConfirmedIntentStillValid ломает контракт."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    mutated = source.replace(
        "if (!wifiMutationIntentMatchesCurrent(confirmedSnapshot, current)) {",
        "if (!wifiMutationIntentMatchesCurrent(confirmedIntentSnapshot, current)) {",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_wifi_screen_intent_confirm_pattern(
            mutated,
            ap_select_id="hub-guest-wifi-ap-select",
        )


def test_guest_wifi_password_registration_error_not_exposed_to_user() -> None:
    """Ошибка регистрации пароля не показывает serverMessage и технические подробности."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    _assert_guest_wifi_password_registration_error_safe(source)


def test_guest_wifi_password_registration_error_mutation_self_check() -> None:
    """Мутация describePanelError → describeError в runMutation должна ломать контракт."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    mutated = source.replace(
        "const described = describePanelError(error);",
        "const described = describeError(error);",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_guest_wifi_password_registration_error_safe(mutated)


def test_guest_wifi_counter_mutation_self_check() -> None:
    """Мутация `${n} гостей` и конкатенации `n + ' гостей'` должны ломать детектор."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    mutated_literal = source.replace(
        "Сеть для гостей и оформления заказов",
        "${3} гостей на связи",
        1,
    )
    mutated_concat = source.replace(
        "markFormDirty();",
        "markFormDirty();\n            const guestLine = n + ' гостей';",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_guest_wifi_user_literals_have_no_guest_counter(mutated_literal)
    with pytest.raises(AssertionError):
        _assert_guest_wifi_user_literals_have_no_guest_counter(mutated_concat)


def _assert_guest_wifi_sources_have_no_console_emit(combined: str) -> None:
    assert not CONSOLE_EMIT_RE.search(combined)


def test_guest_wifi_console_mutation_self_check() -> None:
    """Мутация console.info(password) должна ломать запрет логирования."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    mutated = source.replace(
        "markFormDirty();",
        "markFormDirty();\n            console.info(password);",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_guest_wifi_sources_have_no_console_emit(mutated)


def test_guest_wifi_verdict_mutation_self_check() -> None:
    """Мутация applied+on_air_unverified→success должна падать на parseWifiApplyVerdict."""
    source = WIFI_AP_MODEL_JS.read_text(encoding="utf-8")
    _assert_wifi_ap_model_applied_fallback_not_success(source)
    applied_fallback = (
        "if (overall === 'applied') {\n    return {\n"
        "      hubState: HubState.WARNING,\n      success: false,"
    )
    applied_fallback_mutated = applied_fallback.replace("success: false,", "success: true,", 1)
    mutated = source.replace(applied_fallback, applied_fallback_mutated, 1)
    with pytest.raises(AssertionError):
        _assert_wifi_ap_model_applied_fallback_not_success(mutated)


def _assert_guest_wifi_teardown_block_clean(source: str) -> None:
    _assert_wifi_screen_no_apply_disable(source, teardown_fn="teardownGuestWifiNetwork")


def test_guest_wifi_teardown_mutation_self_check() -> None:
    """Мутация enabled: isOff в любом месте экрана должна ломать контракт."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    mutated = source.replace(
        "action: 'teardown',",
        "action: 'teardown',\n      enabled: isOff,",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_guest_wifi_teardown_block_clean(mutated)


def test_guest_wifi_meta_title_matches_screen_heading() -> None:
    """О-5: meta.title и H1 используют одно написание Wi‑Fi (типографский дефис)."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert re.search(r"title:\s*'Гостевой Wi‑Fi'", source)
    assert re.search(r"title\.textContent\s*=\s*'Гостевой Wi‑Fi'", source)
    assert "title: 'Гостевой Wi-Fi'" not in source


def test_guest_wifi_demo_mode_save_reason_only_once() -> None:
    """О-2: в fake-режиме причина блокировки показывается только у «Сохранить»."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    footer_body = re.search(
        r"function renderFooter\(\) \{([\s\S]*?\n  \}\n\n  function renderAll)",
        source,
    )
    assert footer_body is not None
    block = footer_body.group(1)
    assert re.search(
        r"else if \(!readiness\.allowed\) \{\s+if \(adapterMode !== 'fake'\) \{\s+"
        r"teardownReason = readiness\.reasonText;",
        block,
    )
    assert re.search(
        r"else if \(!readiness\.allowed\) \{\s+saveReason = readiness\.reasonText;",
        block,
    )


def test_guest_wifi_risk_modal_disables_form_fields() -> None:
    """О-9: пока модалка риска открыта, поля формы получают disabled через компоненты."""
    field_source = (HUB / "components" / "field.js").read_text(encoding="utf-8")
    assert "input.disabled = disabled" in field_source
    assert "select.disabled = disabled" in field_source
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    for field_id in (
        "hub-guest-wifi-ap-select",
        "hub-guest-wifi-ssid",
        "hub-guest-wifi-password",
        "hub-guest-wifi-wpa",
    ):
        pattern = rf"id: '{field_id}'[\s\S]*?disabled:[\s\S]*?controlsLocked\(\)"
        assert re.search(pattern, source), field_id


def test_wifi_demo_banner_has_connection_link() -> None:
    """О-6: баннер демо-режима содержит ссылку «Подключение» внутри предложения."""
    source = WIFI_SCREEN_PARTS_JS.read_text(encoding="utf-8")
    assert (
        "link.textContent = connectionLinkLabel" in source
        or "link.textContent = 'Подключение'" in source
    )
    assert "onNavigateToConnection()" in source
    assert "hub-wifi__inline-link" in source
    assert "connectionHintPrefix" in source
    assert "hint.appendChild(link)" in source
    assert "hub-wifi__demo-link-row" not in source


def _build_guest_wifi_footer_sync_harness_script(*, screen_uri: str) -> str:
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    session_uri = json.dumps(SESSION_JS.as_uri())
    screen_import = json.dumps(screen_uri)
    fingerprint = json.dumps(REALISTIC_FINGERPRINT)
    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();

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
  if (!el.hasChildNodes) {{
    el.hasChildNodes = () => (el.children?.length ?? 0) > 0;
  }}
  return el;
}}

globalThis.document = dom.document;
const origCreateElement = dom.document.createElement.bind(dom.document);
dom.document.createElement = (tag) => patchElement(origCreateElement(tag));
dom.document.createElementNS = (_ns, tag) => patchElement(origCreateElement(tag));
dom.document.createTextNode = (text) => {{
  const node = patchElement(origCreateElement('span'));
  node.textContent = String(text ?? '');
  return node;
}};
dom.document.addEventListener = () => {{}};
dom.document.removeEventListener = () => {{}};

const sampleBtn = dom.document.createElement('button');
const sampleInput = dom.document.createElement('input');
globalThis.HTMLElement = sampleBtn.constructor;
globalThis.HTMLButtonElement = sampleBtn.constructor;
globalThis.HTMLInputElement = sampleInput.constructor;
globalThis.HTMLSelectElement = dom.document.createElement('select').constructor;
globalThis.HTMLTextAreaElement = dom.document.createElement('textarea').constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});
globalThis.localStorage = dom.localStorage;
globalThis.window = {{
  ...dom.window,
  localStorage: dom.localStorage,
  addEventListener() {{}},
  removeEventListener() {{}},
  dispatchEvent() {{ return true; }},
  matchMedia() {{
    return {{ matches: false, addEventListener() {{}}, removeEventListener() {{}} }};
  }},
}};
globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
if (typeof globalThis.crypto?.randomUUID !== 'function') {{
  Object.defineProperty(globalThis, 'crypto', {{
    value: {{ randomUUID: () => '22222222-2222-4222-8222-222222222222' }},
    configurable: true,
  }});
}}

globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  let body = {{ ok: true }};
  if (urlStr.includes('wifi/observed-state')) {{
    body = {{
      access_points: [{{
        ap_id: 'WifiMaster0/AccessPoint3',
        readable: true,
        ssid: 'Guest-Lab',
        enabled_or_up: true,
        link_up: true,
        wpa_mode: 'WPA2',
        key_configured: true,
      }}],
    }};
  }}
  return {{
    ok: true,
    status: 200,
    headers: {{
      get: (name) => (
        String(name).toLowerCase() === 'content-type' ? 'application/json' : null
      ),
    }},
    json: async () => body,
    text: async () => JSON.stringify(body),
  }};
}};

import {{ resetSession, updateSession }} from {session_uri};
import {{ render }} from {screen_import};

resetSession();
updateSession({{
  routerId: 'router-lab-1',
  routerHost: '10.0.0.1',
  liveReady: true,
  hostKeyConfirmed: true,
  usernameAvailable: true,
  wifiLive: {{
    host: '10.0.0.1',
    username: 'admin',
    credentialRefId: 'cred-ref-1',
    sshHostKeySha256: {fingerprint},
  }},
  wifiRoles: {{ staffApId: 'WifiMaster0/AccessPoint4', guestApId: 'WifiMaster0/AccessPoint3' }},
  sourceAddress: '192.168.2.144',
}});

const container = dom.document.createElement('div');
dom.document.body.appendChild(container);
const dispose = render(container, {{
  runtime: {{ adapterMode: 'live' }},
  navigate() {{}},
  showToast() {{}},
}});
await new Promise((resolve) => setTimeout(resolve, 300));

const saveBtn = document.getElementById('hub-guest-wifi-save-btn');
const ssidInput = document.getElementById('hub-guest-wifi-ssid');
const contentWrap = container.querySelector('.hub-wifi__content');
const ssidNodeBefore = ssidInput;
const contentChildCountBefore = contentWrap ? contentWrap.children.length : 0;
const disabledBefore = saveBtn ? saveBtn.disabled : null;

dom.simulateInput(ssidInput, '');

const ssidNodeAfter = document.getElementById('hub-guest-wifi-ssid');
const contentChildCountAfter = contentWrap ? contentWrap.children.length : 0;
const disabledAfter = saveBtn ? saveBtn.disabled : null;

dispose();

console.log(JSON.stringify({{
  hadSaveBtn: !!saveBtn,
  hadSsidInput: !!ssidInput,
  disabledBefore,
  disabledAfter,
  sameSsidNode: ssidNodeBefore === ssidNodeAfter,
  sameContentChildCount: contentChildCountBefore === contentChildCountAfter,
}}));
"""


def _assert_guest_wifi_footer_sync_result(result: dict[str, object]) -> None:
    assert result["hadSaveBtn"] is True, result
    assert result["hadSsidInput"] is True, result
    assert result["disabledBefore"] is False, result
    assert result["disabledAfter"] is True, result
    assert result["sameSsidNode"] is True, result
    assert result["sameContentChildCount"] is True, result


def _run_guest_wifi_footer_sync_scenario(tmp_path: Path, *, screen_path: Path) -> dict[str, object]:
    script = _build_guest_wifi_footer_sync_harness_script(screen_uri=screen_path.as_uri())
    return _run_node_harness(script, tmp_path, "guest-footer-sync")  # type: ignore[return-value]


def test_guest_wifi_footer_sync_updates_save_button_without_rerender(tmp_path: Path) -> None:
    """markFormDirty → syncWifiFormFooterUi меняет disabled у «Сохранить» без re-render формы."""
    result = _run_guest_wifi_footer_sync_scenario(tmp_path, screen_path=GUEST_WIFI_SCREEN_JS)
    _assert_guest_wifi_footer_sync_result(result)


def test_guest_wifi_footer_sync_red_proof_without_sync_call(tmp_path: Path) -> None:
    """Без syncWifiFormFooterUi кнопка остаётся enabled после очистки SSID."""
    broken_hub = tmp_path / "hub-broken"
    shutil.copytree(
        HUB,
        broken_hub,
        ignore=shutil.ignore_patterns("_adv_mut_work"),
    )
    broken_screen = broken_hub / "screens" / "guest-wifi.js"
    broken_screen.write_text(
        broken_screen.read_text(encoding="utf-8").replace(
            "    syncWifiFormFooterUi();",
            "    // syncWifiFormFooterUi();",
            1,
        ),
        encoding="utf-8",
    )
    result = _run_guest_wifi_footer_sync_scenario(
        tmp_path / "broken-run",
        screen_path=broken_screen,
    )
    with pytest.raises(AssertionError):
        _assert_guest_wifi_footer_sync_result(result)


def _build_guest_wifi_mutation_harness_script(
    *,
    observed_ap_json: str,
    readback_readable: bool = True,
    readback_matches_apply: bool = True,
    readback_match_after_polls: int = 0,
) -> str:
    from tests.test_hub_staff_wifi import _build_staff_wifi_mutation_harness_script

    script = _build_staff_wifi_mutation_harness_script(
        screen_uri=GUEST_WIFI_SCREEN_JS.as_uri(),
        observed_ap_json=observed_ap_json,
        readback_readable=readback_readable,
        readback_matches_apply=readback_matches_apply,
        readback_match_after_polls=readback_match_after_polls,
    )
    return (
        script.replace("hub-staff-wifi", "hub-guest-wifi")
        .replace("guestApId: null", "guestApId: 'WifiMaster0/AccessPoint3'")
    )


def test_guest_wifi_apply_readback_verified_full_roundtrip(tmp_path: Path) -> None:
    """Guest parity: save → apply → readback → verified title."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint3",
        "readable": True,
        "ssid": "Guest-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "guest-mutation-harness.mjs"
    harness_path.write_text(
        _build_guest_wifi_mutation_harness_script(
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_matches_apply=True,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-guest-apply-readback.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('save')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["modalConfirmed"] is True, result
    assert result["hasApply"] is True, result["requestLog"]
    assert result["observedFetchCount"] >= 2, result
    apply_idx = next(
        i for i, e in enumerate(result["requestLog"]) if "wifi/apply" in e["url"]
    )
    obs_idx = next(
        i for i, e in enumerate(result["requestLog"]) if "wifi/observed-state" in e["url"]
    )
    assert apply_idx < obs_idx, result["requestLog"]
    assert "Изменение отправлено, проверить не удалось" not in result.get("toastTitles", [])


def test_guest_wifi_apply_triggers_observed_readback(tmp_path: Path) -> None:
    """Guest parity alias for verified apply→readback roundtrip."""
    test_guest_wifi_apply_readback_verified_full_roundtrip(tmp_path)


def test_guest_wifi_form_stable_during_readback_poll(tmp_path: Path) -> None:
    """Guest parity: форма не remount при soft poll во время readback."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint3",
        "readable": True,
        "ssid": "Guest-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "guest-stable-ui-harness.mjs"
    harness_path.write_text(
        _build_guest_wifi_mutation_harness_script(
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_match_after_polls=2,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-guest-stable-ui.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('save')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    checks = result.get("stableUiPollChecks") or []
    assert len(checks) >= 2, result
    assert all(item.get("sameSsidNode") for item in checks), checks
    assert all(item.get("formMounted") for item in checks), checks
    assert all(item.get("noLoadingReadWhileForm") for item in checks), checks


def test_guest_wifi_form_stable_when_readback_observed_soft_fails(tmp_path: Path) -> None:
    """F-6 guest parity: mid-readback observed 503 — форма и SSID node сохраняются."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint3",
        "readable": True,
        "ssid": "Guest-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "guest-soft-fail-harness.mjs"
    harness_path.write_text(
        _build_guest_wifi_mutation_harness_script(
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_readable=False,
            readback_matches_apply=False,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-guest-soft-fail.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('save')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    checks = result.get("stableUiPollChecks") or []
    assert len(checks) >= 1, result
    assert all(item.get("sameSsidNode") for item in checks), checks
    assert all(item.get("formMounted") for item in checks), checks
    assert all(item.get("noLoadingReadWhileForm") for item in checks), checks


def test_guest_wifi_teardown_readback_outcome(tmp_path: Path) -> None:
    """Guest parity: teardown verdict triggers observed refresh wiring."""
    result = _run_export(
        tmp_path,
        label="guest-teardown-readback-outcome",
        script_body="""
const applied = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_unverified',
  errors: [],
}, { intent: 'teardown' });
const verdict = mod.applyWifiReadbackOutcome(applied, true, { intent: 'teardown' });
console.log(JSON.stringify({
  success: verdict.success,
  refreshObserved: verdict.refreshObserved,
  title: verdict.title,
}));
""",
    )
    assert result["refreshObserved"] is True
    assert result["success"] is True
    assert result["title"] == "Сеть выключена"


def test_guest_wifi_credential_ref_g3_ensure_supersedes_with_revoke(tmp_path: Path) -> None:
    """Guest parity: shared ensureWifiCredentialRef revokes superseded refs."""
    wifi_ap_uri = json.dumps(WIFI_AP_MODEL_JS.as_uri())
    script = f"""const mod = await import({wifi_ap_uri});
let putCount = 0;
let revokeCount = 0;
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  const method = String(init.method || 'GET').toUpperCase();
  if (method === 'PUT' && urlStr.includes('/credentials')) {{
    putCount += 1;
    return {{
      ok: true,
      status: 201,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ credential_ref_id: `cred-${{putCount}}` }}),
      text: async () => '{{}}',
    }};
  }}
  if (method === 'POST' && urlStr.includes('/revoke')) {{
    revokeCount += 1;
    return {{
      ok: true,
      status: 202,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ status: 'Queued' }}),
      text: async () => '{{}}',
    }};
  }}
  throw new Error('unexpected fetch');
}};
let cache = null;
const base = {{ routerId: 'router-lab-1', apId: 'WifiMaster1/AccessPoint3', ssid: 'Guest-Lab' }};
for (const secret of ['guest-psk-aaaaaa', 'guest-psk-bbbbbb']) {{
  const result = await mod.ensureWifiCredentialRef({{ ...base, secret, cached: cache }});
  cache = result.cache;
}}
console.log(JSON.stringify({{ putCount, revokeCount }}));
"""
    result = _run_node_harness(script, tmp_path, "guest-g3-supersede")
    assert result["putCount"] == 2
    assert result["revokeCount"] == 1


def test_guest_standing_ssid_prefill_only_when_unreadable(tmp_path: Path) -> None:
    result = _run_node_harness(
        f"""const mod = await import({json.dumps((HUB / "features" / "guest-wifi-model.js").as_uri())});
const unreadable = mod.parseObservedAccessPoint({{ ap_id: 'WifiMaster1/AccessPoint3', readable: false }});
const standing = {{
  staff_ssid: 'Staff',
  guest_default_ssid: 'Event Guest',
  staff_password_credential_ref_id: null,
  staff_password_configured: false,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
}};
console.log(JSON.stringify({{
  ssid: mod.createGuestWifiFormDraft(unreadable, standing).ssid,
  seed: mod.GUEST_WIFI_STANDING_SSID_SEED,
}}));""",
        tmp_path,
        "guest-standing-prefill",
    )
    assert result["ssid"] == "Event Guest"


def test_guest_never_reuses_staff_standing_credential() -> None:
    screen = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "resolveStaffWifiCredentialIntent" not in screen
    assert "staff_password_configured" not in screen
    model = (HUB / "features" / "guest-wifi-model.js").read_text(encoding="utf-8")
    assert "resolveStaffWifiCredentialIntent" not in model


def test_guest_remember_default_offer(tmp_path: Path) -> None:
    result = _run_node_harness(
        f"""const mod = await import({json.dumps((HUB / "features" / "guest-wifi-model.js").as_uri())});
const standing = {{
  staff_ssid: 'Staff',
  guest_default_ssid: 'Guest Default',
  staff_password_credential_ref_id: null,
  staff_password_configured: false,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
}};
console.log(JSON.stringify({{
  offer: mod.shouldOfferGuestRememberDefault({{ draftSsid: 'Project Alpha', standing }}),
  same: mod.shouldOfferGuestRememberDefault({{ draftSsid: 'Guest Default', standing }}),
}}));""",
        tmp_path,
        "guest-remember-default",
    )
    assert result["offer"] is True
    assert result["same"] is False


def test_guest_standing_merge_when_observed_unreadable_arrives_first(tmp_path: Path) -> None:
    """F-2/R-6: loadStandingFlow merge — observed unreadable + standing uses standing SSID."""
    result = _run_node_harness(
        f"""const mod = await import({json.dumps((HUB / "features" / "guest-wifi-model.js").as_uri())});
const unreadableObserved = mod.parseObservedAccessPoint({{
  ap_id: 'WifiMaster1/AccessPoint3',
  readable: false,
}});
const standing = {{
  staff_ssid: 'Staff',
  guest_default_ssid: 'Event Guest',
  staff_password_credential_ref_id: null,
  staff_password_configured: false,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
}};
console.log(JSON.stringify({{
  mergeDraft: mod.createGuestWifiFormDraft(unreadableObserved, standing).ssid,
  seedOnly: mod.createGuestWifiFormDraft(unreadableObserved, null).ssid,
}}));""",
        tmp_path,
        "guest-standing-merge-race",
    )
    assert result["mergeDraft"] == "Event Guest"
    assert result["seedOnly"] == "Гостевая сеть"


def test_guest_load_standing_flow_merges_observed_when_not_dirty() -> None:
    """F-2: loadStandingFlow re-merges draft from observed+standing when !formDirty."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "if (!formDirty) {" in source
    assert "createGuestWifiFormDraft(observed, standing)" in source
    assert "!formDirty && !observed" not in source


def test_guest_wifi_standing_load_error_renders_inline_warning() -> None:
    """Standing GET failure shows inline warning — empty defaults not silent."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    load_start = source.find("async function loadStandingFlow(")
    assert load_start != -1
    load_region = source[load_start : load_start + 600]
    assert "standingError = error" in load_region
    extra_sig_start = source.find("function buildGuestExtraSignature(")
    assert extra_sig_start != -1
    extra_sig_region = source[extra_sig_start : extra_sig_start + 500]
    assert "standingError && !isAborted(standingError)" in extra_sig_region
    assert "standing-load-fail" in extra_sig_region
    extra_render_start = source.find("function renderExtraSlot(")
    assert extra_render_start != -1
    extra_render_region = source[extra_render_start : extra_render_start + 2000]
    assert "Не удалось загрузить обычные настройки" in extra_render_region
    assert "standingError && !isAborted(standingError)" in extra_render_region
    assert "Значения по умолчанию могут быть пустыми." in extra_render_region


def test_should_clear_guest_wifi_form_password_after_readback_success_despite_apply_false(
    tmp_path: Path,
) -> None:
    """AC-R3/F-3: guest password clear gates on final readback verdict, not pre-readback apply success."""
    result = _run_export(
        tmp_path,
        label="guest-password-clear-gate",
        script_body="""
const applyVerdict = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_admin_only: true,
});
const readbackVerdict = { success: true, title: 'OK', message: 'readback ok' };
console.log(JSON.stringify({
  applySuccess: applyVerdict.success,
  shouldClearAfterReadback: mod.shouldClearGuestWifiFormPasswordAfterMutation({
    lastVerdict: readbackVerdict,
  }),
  shouldNotClearOnFailure: mod.shouldClearGuestWifiFormPasswordAfterMutation({
    lastVerdict: { success: false, title: 'Fail', message: 'fail' },
  }),
  shouldNotClearOnNull: mod.shouldClearGuestWifiFormPasswordAfterMutation({
    lastVerdict: null,
  }),
}));
""",
    )
    assert result["applySuccess"] is False
    assert result["shouldClearAfterReadback"] is True
    assert result["shouldNotClearOnFailure"] is False
    assert result["shouldNotClearOnNull"] is False


def test_guest_run_mutation_password_clear_uses_final_verdict_gate() -> None:
    """F-3: runMutation password clear uses shouldClearGuestWifiFormPasswordAfterMutation."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "shouldClearGuestWifiFormPasswordAfterMutation" in source
    assert "succeeded && shouldResetGuestWifiFormAfterMutation" not in source


def test_guest_wifi_run_mutation_toast_tone_from_hub_state() -> None:
    """Apply toast tone uses getStateDescriptor(hubState) when !success."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "getStateDescriptor" in source
    run_mutation_start = source.find("async function runMutation(")
    assert run_mutation_start != -1
    run_mutation_region = source[run_mutation_start : run_mutation_start + 4000]
    assert "getStateDescriptor(lastVerdict.hubState).tone" in run_mutation_region
    assert "Object.values(HubState).includes(lastVerdict.hubState)" in run_mutation_region
    assert "tone: lastVerdict.success ? 'success' : 'warning'" not in run_mutation_region


def _extract_subscribe_connectivity_callback(source: str) -> str:
    marker = "subscribeConnectivity((online) => {"
    start = source.find(marker)
    assert start != -1, "subscribeConnectivity callback missing"
    brace = source.find("{", start + len(marker) - 1)
    depth = 0
    j = brace
    while j < len(source):
        if source[j] == "{":
            depth += 1
        elif source[j] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : j]
        j += 1
    raise AssertionError("subscribeConnectivity callback body not closed")


def test_guest_wifi_connectivity_offline_invalidates_all_operations() -> None:
    """hub-offline-abort-followups: offline connectivity invalidates in-flight guest Wi-Fi ops."""
    source = GUEST_WIFI_SCREEN_JS.read_text(encoding="utf-8")
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
