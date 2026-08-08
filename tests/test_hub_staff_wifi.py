"""Поведенческие контракты модели экрана «Рабочая сеть» LOCAL HUB."""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tests.test_hub_guest_wifi import (
    _assert_guest_wifi_password_registration_error_safe,
    _assert_wifi_screen_intent_confirm_pattern,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
STAFF_WIFI_MODEL_JS = HUB / "features" / "staff-wifi-model.js"
STAFF_WIFI_SCREEN_JS = HUB / "screens" / "staff-wifi.js"
WIFI_SCREEN_PARTS_JS = HUB / "features" / "wifi-screen-parts.js"
SESSION_JS = HUB / "core" / "session.js"
UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
TEST_PSK = "test-psk-not-real-8chars"
REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"

DEVICE_COUNTER_RE = re.compile(
    r"\d+\s+устройств|\bустройств\b.*\d+|\d+\s+.*устройств",
    re.IGNORECASE,
)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub staff wifi tests; install Node.js or set "
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


def _run_export(
    tmp_path: Path,
    *,
    label: str,
    script_body: str,
) -> object:
    script = f"""const mod = await import({json.dumps(STAFF_WIFI_MODEL_JS.as_uri())});
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


def test_staff_wifi_access_point_list_excludes_primary_and_covers_bands(tmp_path: Path) -> None:
    """Список точек: AP0/AP1 нет, AP3–6 на обоих диапазонах, band вычисляется верно."""
    result = _run_export(
        tmp_path,
        label="ap-list",
        script_body="""
const options = mod.listStaffWifiAccessPoints();
console.log(JSON.stringify({
  apIds: options.map((item) => item.apId),
  bands: options.map((item) => item.band),
  labels: options.map((item) => item.label),
}));
""",
    )
    ap_ids = result["apIds"]
    assert "WifiMaster0/AccessPoint0" not in ap_ids
    assert "WifiMaster0/AccessPoint1" not in ap_ids
    assert "WifiMaster1/AccessPoint0" not in ap_ids
    assert "WifiMaster1/AccessPoint1" not in ap_ids

    for point in (3, 4, 5, 6):
        assert f"WifiMaster0/AccessPoint{point}" in ap_ids
        assert f"WifiMaster1/AccessPoint{point}" in ap_ids

    assert ap_ids.count("BAND_2_4GHZ") == 0
    assert result["bands"].count("BAND_2_4GHZ") == 4
    assert result["bands"].count("BAND_5GHZ") == 4

    band_check = _run_export(
        tmp_path / "bands",
        label="band-from-ap",
        script_body="""
console.log(JSON.stringify({
  ap4: mod.bandFromApId('WifiMaster0/AccessPoint4'),
  ap5: mod.bandFromApId('WifiMaster1/AccessPoint5'),
}));
""",
    )
    assert band_check["ap4"] == "BAND_2_4GHZ"
    assert band_check["ap5"] == "BAND_5GHZ"


def test_staff_wifi_parse_observed_normal_readable(tmp_path: Path) -> None:
    """Разбор observed: нормальное чтение имени, активности и режима защиты."""
    result = _run_export(
        tmp_path,
        label="parse-normal",
        script_body="""
const parsed = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  band: '2.4GHz',
  ssid: 'Staff-Lab',
  enabled_or_up: true,
  link_up: true,
  device_connected: true,
  wpa_mode: 'WPA2',
  key_configured: true,
  readable: true,
});
console.log(JSON.stringify(parsed));
""",
    )
    assert result["ssidLabel"] == "Staff-Lab"
    assert result["activeLabel"] == "Включена"
    assert result["wpaModeLabel"] == "WPA2"
    assert result["readable"] is True


def test_staff_wifi_parse_observed_not_readable(tmp_path: Path) -> None:
    """readable:false → честное «Состояние не прочитано»."""
    result = _run_export(
        tmp_path,
        label="parse-unreadable",
        script_body="""
console.log(JSON.stringify(mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  band: '2.4GHz',
  ssid: 'Hidden',
  readable: false,
  wpa_mode: 'WPA2',
})));
""",
    )
    assert result["ssidLabel"] == "Состояние не прочитано"


def test_staff_wifi_parse_observed_missing_ssid(tmp_path: Path) -> None:
    """readable:true без ssid → «Название сети не прочитано»."""
    result = _run_export(
        tmp_path,
        label="parse-no-ssid",
        script_body="""
console.log(JSON.stringify(mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster1/AccessPoint3',
  band: '5GHz',
  ssid: '',
  readable: true,
  wpa_mode: 'WPA3',
  enabled_or_up: false,
  link_up: false,
})));
""",
    )
    assert result["ssidLabel"] == "Название сети не прочитано"


def test_staff_wifi_parse_observed_unknown_wpa_mode(tmp_path: Path) -> None:
    """wpa_mode unknown → понятная подпись защиты."""
    result = _run_export(
        tmp_path,
        label="parse-unknown-wpa",
        script_body="""
console.log(JSON.stringify(mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint3',
  readable: true,
  wpa_mode: 'unknown',
})));
""",
    )
    assert result["wpaModeLabel"] == "Защита неизвестна"


def test_staff_wifi_no_device_counter_in_operator_text(tmp_path: Path) -> None:
    """device_connected только в technicalLines; в тексте оператора нет счётчика."""
    result = _run_export(
        tmp_path,
        label="no-device-counter",
        script_body="""
const observed = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  band: '2.4GHz',
  ssid: 'Staff-Lab',
  enabled_or_up: true,
  link_up: true,
  device_connected: true,
  wpa_mode: 'WPA2',
  readable: true,
});
const screen = mod.buildStaffWifiScreenState({
  observed,
  draft: mod.createStaffWifiFormDraft(observed),
  selectedApId: observed.apId,
  mutationReadiness: { allowed: true, reasonText: null, missing: [], mock: false },
});
const operatorText = mod.serializeStaffWifiOperatorText({ observed, screen });
const technicalText = mod.serializeStaffWifiTechnicalText({ observed });
const fakeDynamicCounter = `${3} устройств подключено`;
console.log(JSON.stringify({
  operatorText,
  technicalText,
  activeLabel: observed.activeLabel,
  fakeDynamicCounter,
}));
""",
    )
    assert "device_connected" in result["technicalText"]
    assert "device_connected" not in result["operatorText"]
    assert "устройств" not in result["activeLabel"]
    assert not DEVICE_COUNTER_RE.search(result["operatorText"])
    assert DEVICE_COUNTER_RE.search(result["fakeDynamicCounter"]), (
        "detector must catch dynamic counter"
    )


def test_staff_wifi_screen_no_device_counter_in_user_strings() -> None:
    """Экран: нет подстановки счётчика устройств в строки UI."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "Роутер не сообщает число подключённых устройств" in source
    user_literals = [
        text
        for _, text in re.findall(r"(['\"])(.*?)\1", source, re.DOTALL)
        if CYRILLIC.search(text) and "WifiMaster" not in text
    ]
    joined = "\n".join(user_literals)
    assert not DEVICE_COUNTER_RE.search(joined)
    assert not re.search(r"\$\{[^}]+\}\s*устройств", source, re.IGNORECASE)
    assert "device_connected" not in source


def test_staff_wifi_preview_apply_bodies_match_contract(tmp_path: Path) -> None:
    """preview/apply: полное совпадение тела запроса с контрактом."""
    result = _run_export(
        tmp_path,
        label="request-bodies",
        script_body=f"""
const preview = mod.buildWifiPreviewBody({{
  apId: 'WifiMaster0/AccessPoint4',
  ssid: 'Staff-Lab',
  wpaMode: 'WPA3',
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
    expected_preview = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "ssid": "Staff-Lab",
        "enabled": True,
        "captive_portal": "Disabled",
        "guest_isolation": False,
        "wpa_mode": "WPA3",
        "band": "BAND_2_4GHZ",
        "credential_ref_id": "cred-wifi-1",
    }
    expected_apply = {
        **expected_preview,
        "confirm_live_apply": True,
        "compensate_on_failure": True,
        "idempotent": True,
        "host": "10.0.0.1",
        "username": "admin",
        "router_credential_ref_id": "cred-ref-1",
        "ssh_host_key_sha256": REALISTIC_FINGERPRINT,
        "router_id": "router-lab-1",
    }
    assert result["preview"] == expected_preview
    assert result["apply"] == expected_apply
    assert TEST_PSK not in json.dumps(result["apply"])


def test_staff_wifi_teardown_not_apply_for_disable(tmp_path: Path) -> None:
    """Выключение формирует teardown, а не apply с enabled:false."""
    result = _run_export(
        tmp_path,
        label="teardown-body",
        script_body=f"""
const teardown = mod.buildWifiTeardownBody({{
  apId: 'WifiMaster1/AccessPoint4',
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
    assert result["wpa_mode"] == "WPA2"


@pytest.mark.parametrize(
    ("response", "expect_success", "expect_state"),
    [
        (
            {"overall": "applied", "on_air_verification_status": "on_air_verified", "errors": []},
            True,
            "SUCCESS",
        ),
        (
            {"overall": "applied", "on_air_verification_status": "on_air_admin_only", "errors": []},
            False,
            "WARNING",
        ),
        (
            {
                "overall": "verify_mismatch",
                "on_air_verification_status": "on_air_unverified",
                "errors": [],
            },
            False,
            "WARNING",
        ),
        (
            {
                "overall": "failed",
                "on_air_verification_status": "on_air_unverified",
                "errors": ["planner.no_apply_ops"],
            },
            False,
            "ERROR",
        ),
        (
            {"overall": "applied", "on_air_verification_status": "on_air_unverified", "errors": []},
            False,
            "WARNING",
        ),
        (
            {
                "overall": "dispatched_offline",
                "on_air_verification_status": "on_air_unverified",
                "errors": [],
            },
            False,
            "WARNING",
        ),
        (
            {
                "overall": "unsupported_pending_verification",
                "on_air_verification_status": "on_air_unverified",
                "errors": [],
            },
            False,
            "UNSUPPORTED",
        ),
    ],
)
def test_staff_wifi_apply_verdict_cases(
    tmp_path: Path,
    response: dict[str, object],
    expect_success: bool,
    expect_state: str,
) -> None:
    """Вердикт apply: успех только при on_air_verified; иначе предупреждение/ошибка."""
    result = _run_export(
        tmp_path / expect_state,
        label="apply-verdict",
        script_body=f"""
console.log(JSON.stringify(mod.parseWifiApplyVerdict({json.dumps(response, ensure_ascii=False)})));
""",
    )
    assert result["success"] is expect_success
    assert result["hubState"] == expect_state
    if response.get("errors") == ["planner.no_apply_ops"]:
        assert "выключ" in result["message"].lower() or "отключ" in result["message"].lower()


@pytest.mark.parametrize(
    ("case_id", "ssid", "password", "expected_fragment"),
    [
        ("empty-name", "", TEST_PSK, "Укажите название сети"),
        ("long-name", "x" * 33, TEST_PSK, "32 символов"),
        ("short-password", "Staff-Lab", "short", "8 символов"),
    ],
)
def test_staff_wifi_form_validation_messages(
    tmp_path: Path,
    case_id: str,
    ssid: str,
    password: str,
    expected_fragment: str,
) -> None:
    """Валидация формы: человеческие сообщения для имени и пароля."""
    result = _run_export(
        tmp_path / case_id,
        label=f"validate-{case_id}",
        script_body=f"""
console.log(JSON.stringify(mod.validateStaffWifiForm({{
  ssid: {json.dumps(ssid)},
  password: {json.dumps(password)},
  requirePassword: true,
}})));
""",
    )
    assert result["valid"] is False
    assert any(expected_fragment in err for err in result["errors"]), result["errors"]


def test_staff_wifi_mutation_readiness_incomplete_live_params(tmp_path: Path) -> None:
    """Неполный набор live params → применять нельзя, перечислено недостающее."""
    session = _full_session()
    session["wifiLive"] = dict(session["wifiLive"])  # type: ignore[arg-type]
    session["wifiLive"]["sshHostKeySha256"] = None  # type: ignore[index]

    result = _run_export(
        tmp_path,
        label="mutation-readiness",
        script_body=f"""
console.log(JSON.stringify(mod.evaluateStaffWifiMutationReadiness(
  {json.dumps(session, ensure_ascii=False)},
  'live',
)));
""",
    )
    assert result["allowed"] is False
    assert "подключ" in result["reasonText"].lower()


def test_staff_wifi_credential_body_uses_wifi_ap_psk_kind(tmp_path: Path) -> None:
    """Регистрация пароля: kind WifiApPsk, secret без echo в apply."""
    result = _run_export(
        tmp_path,
        label="credential-body",
        script_body=f"""
console.log(JSON.stringify(mod.buildWifiCredentialBody({{ secret: {json.dumps(TEST_PSK)} }})));
""",
    )
    assert result == {"kind": "WifiApPsk", "secret": TEST_PSK}


def test_staff_wifi_primary_networks_note_constant(tmp_path: Path) -> None:
    """Константа про AP0/AP1 — честное пояснение без жаргона."""
    result = _run_export(
        tmp_path,
        label="primary-note",
        script_body="""
console.log(JSON.stringify({
  note: mod.STAFF_WIFI_PRIMARY_NETWORKS_NOTE,
  clients: mod.STAFF_WIFI_CLIENT_LIST_UNSUPPORTED,
}));
""",
    )
    assert "AccessPoint" not in result["note"]
    assert "основные сети" in result["note"].lower()
    assert "счётчик" in result["clients"].lower() or "счетчик" in result["clients"].lower()


def test_staff_wifi_operator_text_excludes_technical_lines(tmp_path: Path) -> None:
    """serializeStaffWifiOperatorText не включает technicalLines."""
    result = _run_export(
        tmp_path,
        label="operator-vs-technical",
        script_body="""
const observed = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  device_connected: true,
  wpa_mode: 'WPA2',
});
const screen = mod.buildStaffWifiScreenState({
  observed,
  draft: mod.createStaffWifiFormDraft(observed),
  selectedApId: observed.apId,
});
console.log(JSON.stringify({
  operatorText: mod.serializeStaffWifiOperatorText({ observed, screen }),
  technicalText: mod.serializeStaffWifiTechnicalText({ observed }),
}));
""",
    )
    assert "device_connected" in result["technicalText"]
    assert "device_connected" not in result["operatorText"]
    assert "Идентификатор точки" not in result["operatorText"]


def test_staff_wifi_no_device_counter_via_model_behavior(tmp_path: Path) -> None:
    """Поведенческая проверка: device_connected не порождает счётчик в тексте оператора."""
    result = _run_export(
        tmp_path / "behavior",
        label="device-counter-behavior",
        script_body="""
const observed = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  ssid: 'Staff-Lab',
  readable: true,
  enabled_or_up: true,
  link_up: true,
  device_connected: true,
  wpa_mode: 'WPA2',
});
const screen = mod.buildStaffWifiScreenState({
  observed,
  draft: mod.createStaffWifiFormDraft(observed),
  selectedApId: observed.apId,
  mutationReadiness: { allowed: true, reasonText: null, missing: [], mock: false },
});
const lines = mod.serializeStaffWifiOperatorText({ observed, screen }).split('\\n');
const counterLines = lines.filter((line) => /\\d+\\s+устройств|устройств.*\\d+/i.test(line));
console.log(JSON.stringify({ counterLines, lineCount: lines.length }));
""",
    )
    assert result["counterLines"] == []


def test_staff_wifi_access_point_labels_use_network_number_format(tmp_path: Path) -> None:
    """Подписи выбора AP — «Сеть №N — диапазон», не «Точка»."""
    result = _run_export(
        tmp_path,
        label="ap-labels",
        script_body="""
const options = mod.listStaffWifiAccessPoints();
console.log(JSON.stringify({ labels: options.map((item) => item.label) }));
""",
    )
    for label in result["labels"]:
        assert label.startswith("Сеть №"), label
        assert "Точка" not in label
        assert "2,4 ГГц" in label or "5 ГГц" in label


AP_ID_USER_STRING_RE = re.compile(
    r"WifiMaster\d+/AccessPoint\d+",
)


def test_staff_wifi_screen_no_staff_page_configured_badge() -> None:
    """Страница персонала — UNSUPPORTED, без зелёного «Настроена»."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "Настроена" not in source


def test_staff_wifi_screen_uses_model_wifi_endpoints() -> None:
    """Экран вызывает observed/apply через модель, а не напрямую."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "fetchStaffWifiObservedState" in source
    assert "applyStaffWifiChanges" in source
    assert "wifi/observed-state" not in source
    assert "wifi/apply" not in source


def test_staff_wifi_screen_no_blob_or_object_url() -> None:
    """QR и экран не используют blob: / createObjectURL."""
    screen_source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    parts_source = WIFI_SCREEN_PARTS_JS.read_text(encoding="utf-8")
    combined = f"{screen_source}\n{parts_source}"
    assert "blob:" not in combined
    assert "createObjectURL" not in combined


def test_staff_wifi_screen_no_ap_ids_in_user_strings() -> None:
    """Технические идентификаторы AP — только в technicalLines модели, не в UI-строках экрана."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    string_literals = re.findall(r"(['\"])(.*?)\1", source, re.DOTALL)
    user_facing = [
        text
        for _, text in string_literals
        if CYRILLIC.search(text) or "AccessPoint" in text or "WifiMaster" in text
    ]
    violations = [text for text in user_facing if AP_ID_USER_STRING_RE.search(text)]
    assert violations == [], violations


@pytest.mark.parametrize(
    ("case_id", "observed_payload", "expected_description", "expected_checked", "expected_unknown"),
    [
        (
            "unread-null",
            "null",
            "Состояние не прочитано",
            False,
            True,
        ),
        (
            "unread-false",
            "{ ap_id: 'WifiMaster0/AccessPoint4', readable: false }",
            "Состояние не прочитано",
            False,
            True,
        ),
        (
            "partial-active",
            """{
              ap_id: 'WifiMaster0/AccessPoint4',
              readable: true,
              enabled_or_up: true,
              link_up: false,
              wpa_mode: 'WPA2',
            }""",
            "Работает не полностью",
            False,
            True,
        ),
        (
            "confirmed-off",
            """{
              ap_id: 'WifiMaster0/AccessPoint4',
              readable: true,
              enabled_or_up: false,
              link_up: false,
              wpa_mode: 'WPA2',
            }""",
            "Выключена",
            False,
            False,
        ),
        (
            "confirmed-on",
            """{
              ap_id: 'WifiMaster0/AccessPoint4',
              readable: true,
              enabled_or_up: true,
              link_up: true,
              wpa_mode: 'WPA2',
            }""",
            "Включена",
            True,
            False,
        ),
    ],
)
def test_staff_wifi_network_toggle_honest_descriptions(
    tmp_path: Path,
    case_id: str,
    observed_payload: str,
    expected_description: str,
    expected_checked: bool,
    expected_unknown: bool,
) -> None:
    """Ч-1: подпись переключателя не утверждает «Выключена» без подтверждения."""
    result = _run_export(
        tmp_path / case_id,
        label=f"toggle-{case_id}",
        script_body=f"""
const observed = {observed_payload} === 'null'
  ? null
  : mod.parseObservedAccessPoint({observed_payload});
console.log(JSON.stringify(mod.describeStaffWifiNetworkToggle(observed)));
""",
    )
    assert result["description"] == expected_description
    assert result["checked"] is expected_checked
    assert result["unknown"] is expected_unknown


@pytest.mark.parametrize(
    "wpa_mode",
    ["unknown", "not_configured", "unrecognized"],
)
def test_staff_wifi_unknown_wpa_mode_shows_default_hint(
    tmp_path: Path,
    wpa_mode: str,
) -> None:
    """Ч-2: неизвестный wpa_mode → подсказка о значении по умолчанию, не прочитанном режиме."""
    result = _run_export(
        tmp_path / wpa_mode,
        label=f"wpa-{wpa_mode}",
        script_body=f"""
const observed = mod.parseObservedAccessPoint({{
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  wpa_mode: {json.dumps(wpa_mode)},
}});
const draft = mod.createStaffWifiFormDraft(observed);
console.log(JSON.stringify({{
  known: mod.isObservedWpaModeKnown(observed),
  hint: mod.staffWifiWpaFieldHint(observed),
  draftWpaMode: draft.wpaMode,
  wpaModeLabel: observed.wpaModeLabel,
}}));
""",
    )
    assert result["known"] is False
    assert result["draftWpaMode"] == ""
    assert "не прочитан" in result["hint"].lower()
    assert "режим" not in result["hint"].lower()
    assert result["wpaModeLabel"] != "WPA2"


def test_staff_wifi_form_reset_only_after_success_verdict(tmp_path: Path) -> None:
    """С-1: сброс формы и пароля только при success=true."""
    result = _run_export(
        tmp_path,
        label="form-reset",
        script_body="""
const successVerdict = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_verified',
  errors: [],
});
const failedVerdict = mod.parseWifiApplyVerdict({
  overall: 'rolled_back',
  on_air_verification_status: 'on_air_unverified',
  errors: [],
});
console.log(JSON.stringify({
  resetOnSuccess: mod.shouldResetStaffWifiFormAfterMutation(successVerdict),
  resetOnFailure: mod.shouldResetStaffWifiFormAfterMutation(failedVerdict),
  resetOnNull: mod.shouldResetStaffWifiFormAfterMutation(null),
}));
""",
    )
    assert result["resetOnSuccess"] is True
    assert result["resetOnFailure"] is False
    assert result["resetOnNull"] is False


def test_staff_wifi_restart_stops_after_failed_teardown(tmp_path: Path) -> None:
    """С-2: при неуспешном выключении второй шаг перезапуска не выполняется."""
    result = _run_export(
        tmp_path,
        label="restart-teardown-gate",
        script_body="""
const failedTeardown = mod.parseWifiApplyVerdict({
  overall: 'failed',
  on_air_verification_status: 'on_air_unverified',
  errors: ['planner.no_apply_ops'],
}, { intent: 'teardown' });
const okTeardown = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_verified',
  errors: [],
}, { intent: 'teardown' });
console.log(JSON.stringify({
  proceedAfterFailed: failedTeardown.success === true,
  proceedAfterOk: okTeardown.success === true,
  teardownMessage: okTeardown.message,
}));
""",
    )
    assert result["proceedAfterFailed"] is False
    assert result["proceedAfterOk"] is True
    assert "готов" not in result["teardownMessage"].lower()
    assert "выключ" in result["teardownMessage"].lower()


def test_staff_wifi_can_teardown_requires_observed_readable(tmp_path: Path) -> None:
    """Перезапуск недоступен, пока состояние сети не прочитано."""
    result = _run_export(
        tmp_path,
        label="can-teardown-readable",
        script_body="""
const unreadable = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: false,
});
const readable = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  enabled_or_up: true,
  link_up: true,
  wpa_mode: 'WPA2',
});
const readiness = { allowed: true, reasonText: null, missing: [], mock: false };
const unreadableState = mod.buildStaffWifiScreenState({
  observed: unreadable,
  draft: mod.createStaffWifiFormDraft(unreadable),
  selectedApId: unreadable.apId,
  mutationReadiness: readiness,
});
const readableState = mod.buildStaffWifiScreenState({
  observed: readable,
  draft: mod.createStaffWifiFormDraft(readable),
  selectedApId: readable.apId,
  mutationReadiness: readiness,
});
console.log(JSON.stringify({
  unreadable: unreadableState.canTeardown,
  readable: readableState.canTeardown,
}));
""",
    )
    assert result["unreadable"] is True
    assert result["readable"] is True


def test_staff_wifi_screen_toggle_exposes_honest_state_once() -> None:
    """Ч-1: состояние в бейдже; переключатель — aria-label без visible description."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    header_body = _extract_function_body_from_staff_screen(source, "function renderNetworkHeader(")
    assert header_body is not None
    assert "describeStaffWifiNetworkToggle(observed)" in header_body
    assert "createBadge" in header_body
    assert "aria-label" in header_body
    assert "toggleState.description" in header_body
    assert re.search(r"createToggle\(\{[^}]*description:", header_body) is None


def test_staff_wifi_observed_generation_rejects_stale_ap_response(tmp_path: Path) -> None:
    """Г-1: ответ по прежней точке не принимается после смены выбора."""
    result = _run_export(
        tmp_path,
        label="observed-generation",
        script_body="""
let observedGeneration = 0;
let observedSsid = null;

function beginLoad() {
  return ++observedGeneration;
}

function applyResult(gen, ssid) {
  if (!mod.shouldAcceptStaffWifiObservedResult(gen, observedGeneration)) {
    return observedSsid;
  }
  observedSsid = ssid;
  return observedSsid;
}

const firstGen = beginLoad();
const secondGen = beginLoad();
const afterStale = applyResult(firstGen, 'Stale-Network');
const afterFresh = applyResult(secondGen, 'Fresh-Network');
console.log(JSON.stringify({ afterStale, afterFresh, observedGeneration }));
""",
    )
    assert result["afterStale"] is None
    assert result["afterFresh"] == "Fresh-Network"
    assert result["observedGeneration"] == 2


def test_staff_wifi_apply_verdict_rolled_back(tmp_path: Path) -> None:
    """Вердикт rolled_back: success=false, человеческое сообщение без server summary."""
    result = _run_export(
        tmp_path,
        label="verdict-rolled-back",
        script_body="""
console.log(JSON.stringify(mod.parseWifiApplyVerdict({
  overall: 'rolled_back',
  on_air_verification_status: 'on_air_unverified',
  errors: [],
  verdict_explanation: { summary: 'server-side rollback detail' },
})));
""",
    )
    assert result["success"] is False
    assert result["hubState"] == "WARNING"
    assert "измен" in result["title"].lower() or "настрой" in result["title"].lower()
    assert "откат" not in result["title"].lower()
    assert "server-side rollback detail" not in result["message"]
    assert any("verdict_explanation" in line for line in result["technicalLines"])


def test_staff_wifi_screen_observed_load_uses_separate_generation() -> None:
    """Г-1/Г-3: чтение состояния не блокируется флагом loading и использует helper generation."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    load_body = re.search(
        r"async function loadObservedFlow\(\) \{(.+?\n  \}\n)",
        source,
        re.DOTALL,
    )
    assert load_body is not None, "loadObservedFlow body must be present"
    body = load_body.group(1)
    assert "loadingObserved ||" not in body
    assert "++observedGeneration" in body
    assert "shouldAcceptStaffWifiObservedResult" in body


def _build_staff_wifi_mutation_harness_script(
    *,
    screen_uri: str,
    observed_ap_json: str,
    preview_status: int = 200,
    apply_overall: str = "applied",
    readback_readable: bool = True,
    readback_matches_apply: bool = True,
    readback_match_after_polls: int = 0,
    credential_put_status: int = 200,
) -> str:
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    session_uri = json.dumps(SESSION_JS.as_uri())
    screen_import = json.dumps(screen_uri)
    fingerprint = json.dumps(REALISTIC_FINGERPRINT)
    psk = json.dumps(TEST_PSK)
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

globalThis.__WIFI_READBACK_POLL_TEST_CONFIG__ = {{ intervalMs: 50, timeoutMs: 500 }};

const observedAp = {observed_ap_json};
const requestLog = [];
let observedFetchCount = 0;
let postApplyObservedCount = 0;
let appliedSsid = null;
let appliedWpaMode = null;
let appliedEnabled = null;
const readbackMatchAfterPolls = {readback_match_after_polls};
const stableUiPollChecks = [];
/** @type {{globalThis.HTMLElement|null}} */
let initialSsidNode = null;

globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  const method = init.method ? String(init.method).toUpperCase() : 'GET';
  let body = {{ ok: true }};
  let parsedBody = null;
  if (init.body) {{
    try {{
      parsedBody = JSON.parse(String(init.body));
    }} catch {{
      parsedBody = null;
    }}
  }}
  requestLog.push({{ method, url: urlStr, body: parsedBody }});
  if (urlStr.includes('/credentials') && method === 'POST' && urlStr.includes('/revoke')) {{
    return {{
      ok: true,
      status: 202,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ status: 'Queued' }}),
      text: async () => JSON.stringify({{ status: 'Queued' }}),
    }};
  }}
  if (urlStr.includes('/credentials') && method === 'PUT') {{
    if ({credential_put_status} >= 400) {{
      return {{
        ok: false,
        status: {credential_put_status},
        headers: {{ get: () => 'application/json' }},
        json: async () => ({{ error: {{ code: 'internal.error', message: 'vault down' }} }}),
        text: async () => JSON.stringify({{ error: {{ code: 'internal.error' }} }}),
      }};
    }}
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ credential_ref_id: 'cred-wifi-test-ref' }}),
      text: async () => JSON.stringify({{ credential_ref_id: 'cred-wifi-test-ref' }}),
    }};
  }}
  if (urlStr.includes('wifi/preview')) {{
    if ({preview_status} >= 400) {{
      return {{
        ok: false,
        status: {preview_status},
        headers: {{ get: () => 'application/json' }},
        json: async () => ({{
          error: {{ code: 'request.validation_failed', message: 'bad preview' }},
        }}),
        text: async () => JSON.stringify({{ error: {{ code: 'request.validation_failed' }} }}),
      }};
    }}
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ ok: true }}),
      text: async () => JSON.stringify({{ ok: true }}),
    }};
  }}
  if (urlStr.includes('wifi/apply')) {{
    if (parsedBody) {{
      if (typeof parsedBody.ssid === 'string') {{
        appliedSsid = parsedBody.ssid;
      }}
      if (typeof parsedBody.wpa_mode === 'string') {{
        appliedWpaMode = parsedBody.wpa_mode;
      }}
      if (typeof parsedBody.enabled === 'boolean') {{
        appliedEnabled = parsedBody.enabled;
      }}
    }}
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        overall: {json.dumps(apply_overall)},
        on_air_verification_status: 'on_air_verified',
        errors: [],
      }}),
      text: async () => JSON.stringify({{
        overall: {json.dumps(apply_overall)},
        on_air_verification_status: 'on_air_verified',
        errors: [],
      }}),
    }};
  }}
  if (urlStr.includes('wifi/teardown')) {{
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        overall: 'applied',
        on_air_verification_status: 'on_air_verified',
        errors: [],
      }}),
      text: async () => JSON.stringify({{
        overall: 'applied',
        on_air_verification_status: 'on_air_verified',
        errors: [],
      }}),
    }};
  }}
  if (urlStr.includes('wifi/observed-state')) {{
    observedFetchCount += 1;
    const applySeen = requestLog.some((entry) => entry.url.includes('wifi/apply'));
    if (applySeen) {{
      postApplyObservedCount += 1;
      if (postApplyObservedCount === 1) {{
        initialSsidNode = document.getElementById('hub-staff-wifi-ssid');
      }}
      if (initialSsidNode) {{
        const currentSsid = document.getElementById('hub-staff-wifi-ssid');
        const loadingReadVisible = Array.from(
          document.querySelectorAll('.hub-state-inline__text'),
        ).some((el) => String(el.textContent ?? '').includes('Читаем состояние сети с роутера'));
        stableUiPollChecks.push({{
          sameSsidNode: currentSsid === initialSsidNode,
          formMounted: currentSsid instanceof globalThis.HTMLElement,
          noLoadingReadWhileForm: !(loadingReadVisible && currentSsid instanceof globalThis.HTMLElement),
        }});
      }}
    }}
    if (observedFetchCount > 1 && !{json.dumps(readback_readable)}) {{
      return {{
        ok: false,
        status: 503,
        headers: {{ get: () => 'application/json' }},
        json: async () => ({{ error: {{ code: 'wifi.observed_state_failed', message: 'fail' }} }}),
        text: async () => JSON.stringify({{ error: {{ code: 'wifi.observed_state_failed' }} }}),
      }};
    }}
    const readbackAp = {{ ...observedAp }};
    const shouldMatchReadback =
      appliedSsid
      && {json.dumps(readback_matches_apply)}
      && (!applySeen || postApplyObservedCount > readbackMatchAfterPolls);
    if (shouldMatchReadback) {{
      readbackAp.ssid = appliedSsid;
      if (appliedWpaMode) {{
        readbackAp.wpa_mode = appliedWpaMode;
      }}
      if (appliedEnabled === true) {{
        readbackAp.enabled_or_up = true;
        readbackAp.link_up = true;
      }}
    }}
    body = {{ access_points: [readbackAp] }};
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
  wifiRoles: {{ staffApId: 'WifiMaster0/AccessPoint4', guestApId: null }},
  sourceAddress: '192.168.2.144',
}});

const container = dom.document.createElement('div');
dom.document.body.appendChild(container);
const toasts = [];
const dispose = render(container, {{
  runtime: {{ adapterMode: 'live' }},
  navigate() {{}},
  showToast(payload) {{ toasts.push(payload); }},
}});
await new Promise((resolve) => setTimeout(resolve, 300));
initialSsidNode = document.getElementById('hub-staff-wifi-ssid');

export async function runScenario(mode) {{
  const initialObservedFetches = observedFetchCount;
  requestLog.length = 0;
  observedFetchCount = 0;
  toasts.length = 0;
  stableUiPollChecks.length = 0;
  initialSsidNode = null;

  function buttonLabel(btn) {{
    if (!btn) return '';
    const parts = [];
    const walk = (node) => {{
      if (!node || typeof node !== 'object') return;
      if (typeof node.textContent === 'string' && node.textContent) {{
        parts.push(node.textContent);
      }}
      for (const child of node.children || []) {{
        walk(child);
      }}
    }};
    walk(btn);
    return parts.join('');
  }}

  function findButtonByLabel(label) {{
    return Array.from(document.querySelectorAll('button')).find((btn) =>
      buttonLabel(btn).includes(label));
  }}

  function findModalRoot() {{
    return (
      document.querySelector('.hub-modal')
      || document.querySelector('.hub-modal-backdrop')
    );
  }}

  function findModalButtonByLabel(label) {{
    const modal = findModalRoot();
    if (!modal) return null;
    return Array.from(modal.querySelectorAll('button')).find((btn) =>
      buttonLabel(btn).includes(label));
  }}

  async function waitForModal(timeoutMs = 3000) {{
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {{
      if (findModalRoot()) {{
        return true;
      }}
      await new Promise((resolve) => setTimeout(resolve, 50));
    }}
    return false;
  }}

  async function confirmModal(label) {{
    const seen = await waitForModal();
    if (!seen) return false;
    await new Promise((resolve) => setTimeout(resolve, 100));
    let btn = findModalButtonByLabel(label);
    if (!btn) {{
      const modal = findModalRoot();
      btn = modal
        ? (modal.querySelector('.hub-btn--primary')
          || modal.querySelector('.hub-btn--danger')
          || modal.querySelectorAll('button')[modal.querySelectorAll('button').length - 1])
        : null;
    }}
    if (!btn) return false;
    const clickEvent = {{ type: 'click', target: btn, preventDefault() {{}} }};
    const handlers = btn._listeners && btn._listeners.click;
    if (handlers && handlers.length > 0) {{
      handlers.slice().forEach((fn) => fn(clickEvent));
    }} else {{
      btn.click();
    }}
    const toastStarted = Date.now();
    while (Date.now() - toastStarted < 8000) {{
      if (toasts.length > 0) {{
        break;
      }}
      await new Promise((resolve) => setTimeout(resolve, 50));
    }}
    await new Promise((resolve) => setTimeout(resolve, 300));
    return true;
  }}

  const ssidInput = document.getElementById('hub-staff-wifi-ssid');
  const passwordInput = document.getElementById('hub-staff-wifi-password');
  if (ssidInput) dom.simulateInput(ssidInput, 'Staff-Lab-2');
  if (passwordInput) dom.simulateInput(passwordInput, {psk});
  await new Promise((resolve) => setTimeout(resolve, 100));
  initialSsidNode = document.getElementById('hub-staff-wifi-ssid');
  async function waitForRequest(predicate, timeoutMs = 5000) {{
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {{
      if (requestLog.some(predicate)) {{
        return true;
      }}
      await new Promise((resolve) => setTimeout(resolve, 100));
    }}
    return false;
  }}

  let modalConfirmed = false;
  if (mode === 'save') {{
    const saveBtn = document.getElementById('hub-staff-wifi-save-btn');
    if (!saveBtn) throw new Error('save button missing');
    saveBtn.click();
    await waitForRequest((entry) => entry.url.includes('wifi/preview'));
    modalConfirmed = await confirmModal('Сохранить изменения');
    if (modalConfirmed) {{
      await waitForRequest((entry) => entry.url.includes('wifi/apply'), 8000);
    }}
  }} else if (mode === 'cancel-after-prepare') {{
    const saveBtn = document.getElementById('hub-staff-wifi-save-btn');
    if (!saveBtn) throw new Error('save button missing');
    saveBtn.click();
    await waitForRequest((entry) => entry.url.includes('wifi/preview'));
    const seen = await waitForModal();
    if (!seen) throw new Error('modal missing after prepare');
    await new Promise((resolve) => setTimeout(resolve, 100));
    const cancelBtn = findModalButtonByLabel('Отмена');
    if (!cancelBtn) throw new Error('cancel button missing');
    const cancelClick = {{ type: 'click', target: cancelBtn, preventDefault() {{}} }};
    const cancelHandlers = cancelBtn._listeners && cancelBtn._listeners.click;
    if (cancelHandlers && cancelHandlers.length > 0) {{
      cancelHandlers.slice().forEach((fn) => fn(cancelClick));
    }} else {{
      cancelBtn.click();
    }}
    await waitForRequest((entry) => entry.url.includes('/revoke'), 3000);
  }} else if (mode === 'enable') {{
    const ssidInput = document.getElementById('hub-staff-wifi-ssid');
    const passwordInput = document.getElementById('hub-staff-wifi-password');
    if (ssidInput) dom.simulateInput(ssidInput, 'Staff-Lab-2');
    if (passwordInput) dom.simulateInput(passwordInput, {psk});
    await new Promise((resolve) => setTimeout(resolve, 100));
    const input = document.getElementById('hub-staff-wifi-network-toggle');
    if (!input) throw new Error('toggle input missing');
    input.checked = true;
    const handlers = input._listeners && input._listeners.change;
    if (handlers && handlers.length > 0) {{
      handlers.slice().forEach((fn) =>
        fn({{ type: 'change', target: input, preventDefault() {{}} }}));
    }} else {{
      input.dispatchEvent({{ type: 'change', bubbles: true }});
    }}
    await waitForRequest((entry) => entry.url.includes('wifi/preview'));
    modalConfirmed = await confirmModal('Включить сеть');
    if (modalConfirmed) {{
      await waitForRequest((entry) => entry.url.includes('wifi/apply'), 8000);
    }}
  }} else if (mode === 'teardown-unknown' || mode === 'teardown') {{
    const offBtn = findButtonByLabel('Выключить сеть');
    if (!offBtn) throw new Error('teardown button missing');
    offBtn.click();
    modalConfirmed = await confirmModal('Выключить сеть');
    if (modalConfirmed) {{
      await waitForRequest((entry) => entry.url.includes('wifi/teardown'));
    }}
  }}
  await waitForRequest((entry) => entry.url.includes('wifi/observed-state'), 3000);
  let sawVerifying = false;
  const verdictDeadline = Date.now() + 15000;
  while (Date.now() < verdictDeadline) {{
    const inline = document.querySelector('.hub-wifi__verdict .hub-state-inline__text');
    const text = inline ? String(inline.textContent ?? '').trim() : '';
    if (text.includes('Проверяем изменения')) {{
      sawVerifying = true;
    }}
    if (
      text.includes('Сохранено и проверено')
      || text.includes('Изменение отправлено, проверить не удалось')
      || text.includes('Сеть выключена')
    ) {{
      break;
    }}
    if (toasts.length > 0) {{
      const lastTitle = String(toasts[toasts.length - 1]?.title ?? '').trim();
      if (
        lastTitle.includes('Сохранено и проверено')
        || lastTitle.includes('Изменение отправлено, проверить не удалось')
      ) {{
        await new Promise((resolve) => setTimeout(resolve, 200));
        break;
      }}
    }}
    await new Promise((resolve) => setTimeout(resolve, 50));
  }}
  await new Promise((resolve) => setTimeout(resolve, 300));
  const verdictRoot = document.querySelector('.hub-wifi__verdict');
  const verdictInline = verdictRoot?.querySelector('.hub-state-inline__text');
  const verdictInlineTitle = verdictInline ? String(verdictInline.textContent ?? '') : '';
  const verdictCombined = verdictRoot
    ? Array.from(verdictRoot.querySelectorAll('.hub-state-inline__text, .hub-wifi__note'))
        .map((el) => String(el.textContent ?? '').trim())
        .filter(Boolean)
        .join(' ')
    : '';
  const verdictText = verdictInlineTitle || verdictCombined;
  const verdictTitle = verdictText.includes('Сохранено и проверено')
    ? 'confirmed'
    : verdictText.includes('Изменение отправлено, проверить не удалось')
      ? 'unconfirmed'
      : verdictText.includes('Сохранено')
        ? 'saved-only'
        : verdictText.includes('Сеть выключена')
          ? 'teardown-confirmed'
          : 'none';
  return {{
    requestLog,
    observedFetchCount: initialObservedFetches + observedFetchCount,
    toasts,
    hasForm: !!document.getElementById('hub-staff-wifi-ssid'),
    hasApply: requestLog.some((entry) => entry.url.includes('wifi/apply')),
    hasTeardown: requestLog.some((entry) => entry.url.includes('wifi/teardown')),
    hasRevoke: requestLog.some((entry) => entry.url.includes('/revoke')),
    modalConfirmed,
    verdictTitle,
    verdictText,
    sawVerifying,
    postApplyObservedCount,
    toastTitles: toasts.map((item) => item.title),
    stableUiPollChecks,
  }};
}}
"""


def test_staff_wifi_save_registers_credential_before_preview(tmp_path: Path) -> None:
    """F-C3: PUT credentials precedes preview POST; preview carries credential_ref_id."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "mutation-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-save.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "const result = await runScenario('save');\n"
        "console.log(JSON.stringify(result));\n",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [node, str(runner)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    cred_idx = next(
        i for i, entry in enumerate(result["requestLog"]) if "/credentials" in entry["url"]
    )
    preview_idx = next(
        i for i, entry in enumerate(result["requestLog"]) if "wifi/preview" in entry["url"]
    )
    assert cred_idx < preview_idx, result["requestLog"]
    preview_body = result["requestLog"][preview_idx]["body"]
    assert preview_body is not None
    assert preview_body.get("credential_ref_id") == "cred-wifi-test-ref"
    assert "secret" not in preview_body
    assert TEST_PSK not in json.dumps(preview_body)
    cred_body = result["requestLog"][cred_idx]["body"]
    assert cred_body is not None
    assert cred_body.get("kind") == "WifiApPsk"


def test_staff_wifi_screen_derives_preview_enabled_not_literal() -> None:
    """F-C6: enabled в preview берётся из deriveWifiPreviewEnabled, не из literal true."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    body = _extract_function_body_from_staff_screen(source, "async function buildMutationIntent(")
    assert body is not None
    assert "deriveWifiPreviewEnabled" in body
    assert re.search(r"enabled:\s*true", body) is None


def test_apply_wifi_readback_outcome_distinguishes_confirmed(tmp_path: Path) -> None:
    """F-S3/F-C4: applied+readback vs applied без readback — разные исходы."""
    result = _run_export(
        tmp_path,
        label="readback-outcome",
        script_body="""
const applied = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_verified',
  errors: [],
});
const confirmed = mod.applyWifiReadbackOutcome(applied, true);
const unconfirmed = mod.applyWifiReadbackOutcome(applied, false);
const mismatch = mod.parseWifiApplyVerdict({
  overall: 'verify_mismatch',
  on_air_verification_status: 'on_air_unverified',
  errors: [],
});
const mismatchConfirmed = mod.applyWifiReadbackOutcome(mismatch, true);
console.log(JSON.stringify({
  confirmed,
  unconfirmed,
  mismatchApplied: mod.isWifiConfigurationApplied(mismatch),
  mismatchConfirmed,
}));
""",
    )
    assert result["confirmed"]["success"] is True
    assert result["confirmed"]["title"] == "Сохранено и проверено"
    assert result["unconfirmed"]["success"] is False
    assert result["unconfirmed"]["title"] == "Изменение отправлено, проверить не удалось"
    assert result["mismatchApplied"] is False
    assert result["mismatchConfirmed"]["success"] is False
    assert result["mismatchConfirmed"]["title"] == "Проверка не совпала"


def test_apply_wifi_readback_outcome_blocks_on_air_unverified_upgrade(tmp_path: Path) -> None:
    """applied+on_air_unverified must not upgrade to «Сохранено и проверено» via poll."""
    result = _run_export(
        tmp_path,
        label="readback-on-air-unverified",
        script_body="""
const applied = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_unverified',
  errors: [],
});
const confirmed = mod.applyWifiReadbackOutcome(applied, true);
console.log(JSON.stringify({ applied, confirmed }));
""",
    )
    assert result["applied"]["success"] is False
    assert result["applied"]["title"] == "Сохранено с оговоркой"
    assert result["confirmed"]["success"] is False
    assert result["confirmed"]["title"] == "Сохранено с оговоркой"
    assert result["confirmed"]["title"] != "Сохранено и проверено"


def test_staff_wifi_apply_readback_verified_full_roundtrip(tmp_path: Path) -> None:
    """F-D8: save → apply → observed refetch → «Сохранено и проверено» при совпадении."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "mutation-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_matches_apply=True,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-apply-readback.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "const result = await runScenario('save');\n"
        "console.log(JSON.stringify(result));\n",
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
    assert result["verdictTitle"] == "confirmed", result
    assert "Изменение отправлено, проверить не удалось" not in result.get("toastTitles", [])


def test_staff_wifi_enable_switch_apply_shows_confirmed_verdict_in_tab(tmp_path: Path) -> None:
    """F-D8 enable: переключатель «Сеть» → apply → «Сохранено и проверено» на вкладке."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": False,
        "link_up": False,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "enable-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_matches_apply=True,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-enable.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('enable')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["modalConfirmed"] is True, result
    assert result["hasApply"] is True, result["requestLog"]
    assert result["verdictTitle"] == "confirmed", result
    assert result["toastTitles"][-1] == "Сохранено и проверено", result


def test_staff_wifi_enable_switch_apply_shows_unconfirmed_when_readback_stale(
    tmp_path: Path,
) -> None:
    """F-D8 negative: enable + stale readback → честный unconfirmed на вкладке."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": False,
        "link_up": False,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "enable-stale-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_matches_apply=False,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-enable-stale.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('enable')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["hasApply"] is True
    assert result["verdictTitle"] == "unconfirmed", result
    assert result["toastTitles"][-1] == "Изменение отправлено, проверить не удалось", result


def test_evaluate_wifi_apply_readback_confirmed_when_observed_matches(tmp_path: Path) -> None:
    """F-G2: verified требует совпадения SSID/WPA/enabled с intent."""
    result = _run_export(
        tmp_path,
        label="readback-match-eval",
        script_body="""
const observed = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  ssid: 'Staff-Lab-2',
  enabled_or_up: true,
  link_up: true,
  wpa_mode: 'WPA2',
});
const applied = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_verified',
  errors: [],
});
const readbackOk = mod.evaluateWifiApplyReadback({
  observed,
  observedError: false,
  expected: { ssid: 'Staff-Lab-2', wpaMode: 'WPA2', enabled: true },
});
const verdict = mod.applyWifiReadbackOutcome(applied, readbackOk);
console.log(JSON.stringify({ readbackOk, title: verdict.title, success: verdict.success }));
""",
    )
    assert result["readbackOk"] is True
    assert result["title"] == "Сохранено и проверено"
    assert result["success"] is True


def test_staff_wifi_apply_readback_unverified_when_stale(tmp_path: Path) -> None:
    """F-G2/F-D8: stale readback не даёт «Сохранено и проверено»."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "mutation-harness-stale.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_matches_apply=False,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-stale-readback.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('save')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["hasApply"] is True
    assert result["verdictTitle"] == "unconfirmed", result
    assert result["toastTitles"][-1] == "Изменение отправлено, проверить не удалось", result


def test_staff_wifi_apply_readback_red_proof_skips_match_check(tmp_path: Path) -> None:
    """F-D8 red→green: без сравнения SSID/WPA «verified» при stale readback."""
    fixed_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    script = f"""const fixed = await import({fixed_uri});
const observed = fixed.parseObservedAccessPoint({{
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  ssid: 'Staff-Lab',
  enabled_or_up: true,
  link_up: true,
  wpa_mode: 'WPA2',
}});
const expected = {{ ssid: 'Staff-Lab-2', wpaMode: 'WPA2', enabled: true }};
const brokenEvaluate = ({{ observedError, observed }}) => (
  !observedError && observed?.readable === true
);
console.log(JSON.stringify({{
  broken: brokenEvaluate({{ observed, observedError: false, expected }}),
  fixed: fixed.evaluateWifiApplyReadback({{ observed, observedError: false, expected }}),
}}));
"""
    result = _run_node_harness(script, tmp_path, "readback-red-proof")
    assert result["broken"] is True
    assert result["fixed"] is False


def test_staff_wifi_apply_triggers_observed_readback(tmp_path: Path) -> None:
    """F-C4 alias: полный apply→readback wiring (delegates to verified roundtrip)."""
    test_staff_wifi_apply_readback_verified_full_roundtrip(tmp_path)


def test_staff_wifi_form_stable_during_readback_poll(tmp_path: Path) -> None:
    """F-WIFI-01/02: форма и SSID input не remount при soft poll во время readback."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "stable-ui-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_match_after_polls=2,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-stable-ui.mjs"
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


def test_staff_wifi_form_stable_when_readback_observed_soft_fails(tmp_path: Path) -> None:
    """F-6/F-3b: mid-readback observed 503 — форма остаётся, skeleton «Читаем…» не мигает."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "soft-fail-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_readable=False,
            readback_matches_apply=False,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-soft-fail.mjs"
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


def test_staff_wifi_cancel_after_prepare_revokes_credential_ref(tmp_path: Path) -> None:
    """F-D8: экранный revokePendingDraftCredentialRef на «Отмена» шлёт POST /revoke."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": True,
        "link_up": True,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "cancel-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-cancel.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('cancel-after-prepare')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["hasRevoke"] is True, result["requestLog"]
    cred_puts = [
        e
        for e in result["requestLog"]
        if "/credentials" in e["url"] and e["method"] == "PUT"
    ]
    assert len(cred_puts) >= 1


def test_wifi_credential_ref_supersede_put_failure_keeps_cache_live(tmp_path: Path) -> None:
    """F-E2: PUT после смены пароля падает — кеш не отдаёт revoked ref при повторе."""
    wifi_ap_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    script = f"""const mod = await import({wifi_ap_uri});
let putCount = 0;
globalThis.fetch = async (url, init = {{}}) => {{
  const method = String(init.method || 'GET').toUpperCase();
  if (method === 'PUT' && String(url).includes('/credentials')) {{
    putCount += 1;
    if (putCount === 2) {{
      return {{
        ok: false,
        status: 503,
        headers: {{ get: () => 'application/json' }},
        json: async () => ({{ error: {{ code: 'internal.error', message: 'vault down' }} }}),
        text: async () => '{{}}',
      }};
    }}
    return {{
      ok: true,
      status: 201,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ credential_ref_id: `cred-ref-${{putCount}}` }}),
      text: async () => JSON.stringify({{ credential_ref_id: `cred-ref-${{putCount}}` }}),
    }};
  }}
  if (method === 'POST' && String(url).includes('/revoke')) {{
    return {{
      ok: true,
      status: 202,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ status: 'Queued' }}),
      text: async () => '{{}}',
    }};
  }}
  throw new Error(`unexpected fetch ${{method}} ${{url}}`);
}};
const base = {{
  routerId: 'router-lab-1',
  apId: 'WifiMaster0/AccessPoint4',
  ssid: 'Staff-Lab',
}};
let cache = null;
let threw = false;
let staleReturned = false;
let reusedRef = null;
try {{
  const first = await mod.ensureWifiCredentialRef({{
    ...base,
    secret: 'edit-psk-aaaaaa',
    cached: cache,
  }});
  cache = first.cache;
  await mod.ensureWifiCredentialRef({{ ...base, secret: 'edit-psk-bbbbbb', cached: cache }});
}} catch {{
  threw = true;
}}
try {{
  const retry = await mod.ensureWifiCredentialRef({{
    ...base,
    secret: 'edit-psk-bbbbbb',
    cached: cache,
  }});
  reusedRef = retry.credentialRefId;
  staleReturned = reusedRef === 'cred-ref-1';
}} catch {{
  threw = true;
}}
console.log(JSON.stringify({{ threw, staleReturned, reusedRef, putCount }}));
"""
    result = _run_node_harness(script, tmp_path, "supersede-put-fail")
    assert result["threw"] is True
    assert result["staleReturned"] is False
    assert result["reusedRef"] == "cred-ref-3"
    assert result["putCount"] == 3


def test_poll_wifi_apply_readback_converges_after_delayed_match(tmp_path: Path) -> None:
    """Defect A: первый observed — старый, позже — новый → confirmed, не failure."""
    result = _run_export(
        tmp_path,
        label="poll-converges",
        script_body="""
const stale = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  ssid: 'Old-SSID',
  enabled_or_up: false,
  link_up: false,
  wpa_mode: 'WPA2',
});
const fresh = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  ssid: 'New-SSID',
  enabled_or_up: true,
  link_up: true,
  wpa_mode: 'WPA2',
});
let calls = 0;
const poll = await mod.pollWifiApplyReadback({
  fetchObserved: async () => {
    calls += 1;
    return calls === 1
      ? { observed: stale, observedError: false }
      : { observed: fresh, observedError: false };
  },
  expected: { ssid: 'New-SSID', wpaMode: 'WPA2', enabled: true },
  intervalMs: 10,
  timeoutMs: 200,
});
const applied = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_verified',
  errors: [],
});
const verdict = mod.applyWifiReadbackOutcome(applied, poll.readbackOk, {
  observed: poll.observed,
  observedError: poll.observedError,
  expected: { ssid: 'New-SSID', wpaMode: 'WPA2', enabled: true },
});
console.log(JSON.stringify({
  calls,
  readbackOk: poll.readbackOk,
  timedOut: poll.timedOut,
  title: verdict.title,
  success: verdict.success,
}));
""",
    )
    assert result["calls"] >= 2
    assert result["readbackOk"] is True
    assert result["timedOut"] is False
    assert result["title"] == "Сохранено и проверено"
    assert result["success"] is True


def test_poll_wifi_apply_readback_timeout_honest_wording(tmp_path: Path) -> None:
    """Defect A negative: observed не сходится → честный unconfirmed после timeout."""
    result = _run_export(
        tmp_path,
        label="poll-timeout",
        script_body="""
const stale = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  ssid: 'Old-SSID',
  enabled_or_up: false,
  link_up: false,
  wpa_mode: 'WPA2',
});
const poll = await mod.pollWifiApplyReadback({
  fetchObserved: async () => ({ observed: stale, observedError: false }),
  expected: { ssid: 'New-SSID', wpaMode: 'WPA2', enabled: true },
  intervalMs: 20,
  timeoutMs: 60,
});
const mismatch = mod.parseWifiApplyVerdict({
  overall: 'verify_mismatch',
  on_air_verification_status: 'on_air_verified',
  errors: [],
});
const verdict = mod.applyWifiReadbackOutcome(mismatch, poll.readbackOk, {
  observed: poll.observed,
  observedError: poll.observedError,
  expected: { ssid: 'New-SSID', wpaMode: 'WPA2', enabled: true },
});
console.log(JSON.stringify({
  readbackOk: poll.readbackOk,
  timedOut: poll.timedOut,
  title: verdict.title,
  message: verdict.message,
  success: verdict.success,
}));
""",
    )
    assert result["readbackOk"] is False
    assert result["timedOut"] is True
    assert result["title"] == "Проверка не совпала"
    assert result["success"] is False
    assert "Сравнение:" not in result["message"]


def test_staff_wifi_delayed_readback_shows_verifying_then_confirmed(tmp_path: Path) -> None:
    """Defect A integration: stale→fresh observed → interim verifying → confirmed."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": False,
        "link_up": False,
        "wpa_mode": "WPA2",
        "key_configured": True,
    }
    harness_path = tmp_path / "delayed-readback-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            readback_matches_apply=True,
            readback_match_after_polls=1,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-delayed-readback.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('enable')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["hasApply"] is True
    assert result["postApplyObservedCount"] >= 2, result
    assert result["verdictTitle"] == "confirmed", result
    assert result["toastTitles"][-1] == "Сохранено и проверено", result


def test_staff_wifi_verify_mismatch_does_not_upgrade_on_readback(tmp_path: Path) -> None:
    """verify_mismatch stays warning even when delayed client readback matches."""
    observed_ap = {
        "ap_id": "WifiMaster0/AccessPoint4",
        "readable": True,
        "ssid": "Staff-Lab",
        "enabled_or_up": False,
        "link_up": False,
        "wpa_mode": "WPA2",
        "key_configured": None,
    }
    harness_path = tmp_path / "verify-mismatch-harness.mjs"
    harness_path.write_text(
        _build_staff_wifi_mutation_harness_script(
            screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
            observed_ap_json=json.dumps(observed_ap, ensure_ascii=False),
            apply_overall="verify_mismatch",
            readback_matches_apply=True,
            readback_match_after_polls=1,
        ),
        encoding="utf-8",
    )
    node = _require_node()
    runner = tmp_path / "run-verify-mismatch.mjs"
    runner.write_text(
        f"import {{ runScenario }} from {json.dumps(harness_path.as_uri())};\n"
        "console.log(JSON.stringify(await runScenario('enable')));\n",
        encoding="utf-8",
    )
    proc = subprocess.run([node, str(runner)], capture_output=True, text=True, encoding="utf-8")
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout.strip())
    assert result["verdictTitle"] != "confirmed", result
    assert "Сохранено и проверено" not in result.get("toastTitles", [])


def test_staff_wifi_apply_readback_failure_distinct_outcome(tmp_path: Path) -> None:
    """F-S3: apply без readback — отдельный warning через applyWifiReadbackOutcome."""
    result = _run_export(
        tmp_path,
        label="readback-fail-outcome",
        script_body="""
const applied = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_verified',
  errors: [],
});
const verdict = mod.applyWifiReadbackOutcome(applied, false, {
  observed: mod.parseObservedAccessPoint({
    ap_id: 'WifiMaster0/AccessPoint4',
    readable: true,
    ssid: 'Staff-Lab',
    enabled_or_up: false,
    wpa_mode: 'WPA2',
  }),
  observedError: false,
  expected: { ssid: 'Staff-Lab-2', wpaMode: 'WPA2', enabled: true },
});
console.log(JSON.stringify(verdict));
""",
    )
    assert result["success"] is False
    assert result["title"] == "Изменение отправлено, проверить не удалось"
    assert "Сравнение:" in result["message"]
    assert "Пароль Wi‑Fi с роутера прочитать нельзя" in result["message"]



def test_staff_wifi_live_connection_errors_use_setup_kind(tmp_path: Path) -> None:
    """F-B1: hub session gap codes map to SETUP, not DEVICE."""
    errors_uri = json.dumps((HUB / "core" / "errors.js").as_uri())
    script = f"""import {{ resolveErrorEntry, ERROR_KIND }} from {errors_uri};
const codes = [
  'wifi.live_connection_required',
  'wifi.live_connection_incomplete',
  'wifi.credential_not_found',
  'wifi.credential_unusable',
];
console.log(JSON.stringify(codes.map((code) => {{
  const entry = resolveErrorEntry(code);
  return {{ code, kind: entry.kind }};
}})));
"""
    result = _run_node_harness(script, tmp_path, "wifi-setup-kinds")
    for row in result:
        assert row["kind"] == "SETUP", row


def test_staff_wifi_credential_registration_error_kind(tmp_path: Path) -> None:
    """F-S2: vault registration failure is SERVER with details."""
    wifi_ap_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    script = f"""import {{ toWifiCredentialRegistrationError }} from {wifi_ap_uri};
import {{ HubApiError, ERROR_KIND }} from {json.dumps((HUB / "core" / "errors.js").as_uri())};
const err = toWifiCredentialRegistrationError(new HubApiError({{
  code: 'internal.error',
  httpStatus: 503,
  userMessage: 'x',
  userAction: 'y',
  serverMessage: 'secret',
  details: ['step: vault'],
  requestId: null,
  correlationId: null,
  kind: ERROR_KIND.SERVER,
}}));
console.log(JSON.stringify({{ kind: err.kind, details: err.details, code: err.code }}));
"""
    result = _run_node_harness(script, tmp_path, "cred-reg-kind")
    assert result["kind"] == "SERVER"
    assert result["code"] == "client.credential_registration_failed"
    assert len(result["details"]) > 0

def test_staff_wifi_screen_connectivity_skips_reload_during_mutation() -> None:
    """Г-3: при восстановлении связи во время apply не запускается loadObservedFlow."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "!mutating && !preparingMutation" in source


def _assert_staff_wifi_layout_css_safe(css: str) -> None:
    """Сетка без неявных многострочных span, создающих сотни пустых строк."""
    wifi_block = css.split("/* ── Общие блоки экранов Wi‑Fi ── */", 1)[-1]
    for match in re.finditer(r"grid-(?:row|column):\s*[^;]*span\s+(\d+)", wifi_block):
        span_val = int(match.group(1))
        assert span_val <= 3, f"grid span {span_val} exceeds reasonable limit (max 3)"
    assert ".hub-wifi__layout-banner" in wifi_block
    assert ".hub-wifi__layout-network-header" in wifi_block


def _assert_staff_wifi_content_grid_children(source: str) -> None:
    """mountLayoutOnce: прямые потомки contentWrap — banner, network-header, main, side."""
    mount_body = _extract_function_body_from_staff_screen(source, "function mountLayoutOnce(")
    assert mount_body is not None
    child_vars = re.findall(r"contentWrap\.appendChild\((\w+)\)", mount_body)
    unique_children = set(child_vars)
    assert unique_children == {"bannerSlot", "networkHeaderSlot", "mainCol", "sideCol"}, (
        f"expected bannerSlot, networkHeaderSlot, mainCol, sideCol as direct children, "
        f"got {sorted(unique_children)}"
    )
    render_body = _extract_function_body_from_staff_screen(source, "function renderContent(")
    assert render_body is not None
    assert "mountLayoutOnce()" in render_body
    assert "clearElement(contentWrap)" not in render_body
    assert "hub-wifi__content--single-column" in source
    assert "markLayoutSpan" not in source


def test_staff_wifi_layout_three_child_grid_without_implicit_rows() -> None:
    """В-3: четыре прямых потомка сетки, без span 99 и без лишних grid-строк."""
    css = (HUB / "styles" / "screens.css").read_text(encoding="utf-8")
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    _assert_staff_wifi_layout_css_safe(css)
    _assert_staff_wifi_content_grid_children(source)
    broken_css = css.replace(
        ".hub-wifi__layout-side {\n    grid-column: 2;\n  }",
        ".hub-wifi__layout-side {\n    grid-column: 2;\n    grid-row: 1 / span 99;\n  }",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_staff_wifi_layout_css_safe(broken_css)


def test_staff_wifi_advanced_settings_use_settings_section() -> None:
    """В-6: расширенные настройки оформлены отдельным раскрывающимся разделом."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "createSettingsSection" in source
    assert "hub-wifi-settings-section" in source
    assert re.search(
        r"createTechnicalDetails\(\{\s*summary:\s*['\"]Расширенные настройки['\"]",
        source,
    ) is None


def test_staff_wifi_risk_modal_restores_focus_after_confirm() -> None:
    """Д-3: после подтверждения риск-модалки фокус возвращается на устойчивый элемент."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    risk_body = _extract_function_body_from_staff_screen(source, "function openRiskModal(")
    assert risk_body is not None
    assert "returnFocusTo: null" not in risk_body
    assert "returnFocusTo" in risk_body
    assert "pendingFocus" in risk_body
    assert "focusTargetIdAfterRiskConfirm" in source
    assert "document.activeElement instanceof HTMLElement" in source


def _extract_function_body_from_staff_screen(source: str, signature: str) -> str | None:
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


def test_staff_wifi_unsupported_cards_use_compact_inline_state() -> None:
    """В-4: блоки «не поддерживается» без полноразмерной панели состояния."""
    source = WIFI_SCREEN_PARTS_JS.read_text(encoding="utf-8")
    unsupported_body = _extract_function_body_from_staff_screen(
        source,
        "export function createUnsupportedCard(",
    )
    assert unsupported_body is not None
    assert "createInlineState" in unsupported_body
    assert "createStatePanel" not in unsupported_body


def test_staff_wifi_screen_shows_unreadable_warning_with_form() -> None:
    """Т-1: при readable:false предупреждение не блокирует форму."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "WIFI_OBSERVED_UNREADABLE_TITLE" in source
    assert "function isObservedUnreadable()" in source
    progress_body = _extract_function_body_from_staff_screen(source, "function renderProgressSlot(")
    assert progress_body is not None
    assert "createInlineState" in progress_body
    assert "WIFI_OBSERVED_UNREADABLE_DESCRIPTION" in progress_body
    settings_body = _extract_function_body_from_staff_screen(source, "function renderSettingsSlot(")
    assert settings_body is not None
    assert "canRenderObservedForm()" in settings_body
    can_render_body = _extract_function_body_from_staff_screen(
        source,
        "function canRenderObservedForm(",
    )
    assert can_render_body is not None
    assert "observed?.readable === true" not in can_render_body
    assert "!loadingObserved" not in can_render_body
    assert "observedError" not in can_render_body


def test_staff_wifi_screen_stale_intent_guard() -> None:
    """Т-2: снимок передаётся аргументом и переживает onClose модалки."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "confirmedIntentSnapshot" in source
    assert "riskModalOpen" in source
    assert "assertConfirmedIntentStillValid" in source
    assert re.search(r"controlsLocked\(\)[\s\S]*riskModalOpen", source)
    _assert_wifi_screen_intent_confirm_pattern(
        source,
        ap_select_id="hub-staff-wifi-ap-select",
    )


def test_staff_wifi_screen_stale_intent_guard_mutation_self_check() -> None:
    """Возврат к confirmedIntentSnapshot в assertConfirmedIntentStillValid ломает контракт."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    mutated = source.replace(
        "if (!wifiMutationIntentMatchesCurrent(confirmedSnapshot, current)) {",
        "if (!wifiMutationIntentMatchesCurrent(confirmedIntentSnapshot, current)) {",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_wifi_screen_intent_confirm_pattern(
            mutated,
            ap_select_id="hub-staff-wifi-ap-select",
        )


def test_staff_wifi_password_registration_error_not_exposed_to_user() -> None:
    """Ошибка регистрации пароля не показывает serverMessage и технические подробности."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    _assert_guest_wifi_password_registration_error_safe(source)


def _build_staff_wifi_footer_sync_harness_script(*, screen_uri: str) -> str:
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
    value: {{ randomUUID: () => '11111111-1111-4111-8111-111111111111' }},
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
        ap_id: 'WifiMaster0/AccessPoint4',
        readable: true,
        ssid: 'Staff-Lab',
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
  wifiRoles: {{ staffApId: 'WifiMaster0/AccessPoint4', guestApId: null }},
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

const saveBtn = document.getElementById('hub-staff-wifi-save-btn');
const ssidInput = document.getElementById('hub-staff-wifi-ssid');
const contentWrap = container.querySelector('.hub-wifi__content');
const ssidNodeBefore = ssidInput;
const contentChildCountBefore = contentWrap ? contentWrap.children.length : 0;
const disabledBefore = saveBtn ? saveBtn.disabled : null;

dom.simulateInput(ssidInput, '');

const ssidNodeAfter = document.getElementById('hub-staff-wifi-ssid');
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


def _assert_staff_wifi_footer_sync_result(result: dict[str, object]) -> None:
    assert result["hadSaveBtn"] is True, result
    assert result["hadSsidInput"] is True, result
    assert result["disabledBefore"] is False, result
    assert result["disabledAfter"] is True, result
    assert result["sameSsidNode"] is True, result
    assert result["sameContentChildCount"] is True, result


def _run_staff_wifi_footer_sync_scenario(tmp_path: Path, *, screen_path: Path) -> dict[str, object]:
    script = _build_staff_wifi_footer_sync_harness_script(screen_uri=screen_path.as_uri())
    return _run_node_harness(script, tmp_path, "staff-footer-sync")  # type: ignore[return-value]


def test_staff_wifi_footer_sync_updates_save_button_without_rerender(tmp_path: Path) -> None:
    """markFormDirty → syncWifiFormFooterUi меняет disabled у «Сохранить» без re-render формы."""
    result = _run_staff_wifi_footer_sync_scenario(tmp_path, screen_path=STAFF_WIFI_SCREEN_JS)
    _assert_staff_wifi_footer_sync_result(result)


def test_staff_wifi_footer_sync_red_proof_without_sync_call(tmp_path: Path) -> None:
    """Без syncWifiFormFooterUi кнопка остаётся enabled после очистки SSID."""
    broken_hub = tmp_path / "hub-broken"
    shutil.copytree(
        HUB,
        broken_hub,
        ignore=shutil.ignore_patterns("_adv_mut_work"),
    )
    broken_screen = broken_hub / "screens" / "staff-wifi.js"
    broken_screen.write_text(
        broken_screen.read_text(encoding="utf-8").replace(
            "    syncWifiFormFooterUi();",
            "    // syncWifiFormFooterUi();",
            1,
        ),
        encoding="utf-8",
    )
    result = _run_staff_wifi_footer_sync_scenario(
        tmp_path / "broken-run",
        screen_path=broken_screen,
    )
    with pytest.raises(AssertionError):
        _assert_staff_wifi_footer_sync_result(result)


def _build_staff_wifi_toggle_dom_harness_script(
    *,
    screen_uri: str,
    observed_ap_json: str,
) -> str:
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
    value: {{ randomUUID: () => '33333333-3333-4333-8333-333333333333' }},
    configurable: true,
  }});
}}

const observedAp = {observed_ap_json};

globalThis.fetch = async (url) => {{
  const urlStr = String(url);
  if (urlStr.includes('192.168.2.1')) {{
    throw new Error('forbidden fetch target');
  }}
  let body = {{ ok: true }};
  if (urlStr.includes('wifi/observed-state')) {{
    body = {{ access_points: [observedAp] }};
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
  wifiRoles: {{ staffApId: 'WifiMaster0/AccessPoint4', guestApId: null }},
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

const toggleInput = document.getElementById('hub-staff-wifi-network-toggle');
const toggleLabel = toggleInput ? toggleInput.parentNode : null;
const track = toggleLabel && toggleLabel.children ? toggleLabel.children[1] : null;
const thumb = track && track.children ? track.children[0] : null;

dispose();

console.log(JSON.stringify({{
  found: !!toggleInput,
  ariaChecked: toggleInput ? toggleInput.getAttribute('aria-checked') : null,
  ariaLabel: toggleInput ? toggleInput.getAttribute('aria-label') : null,
  role: toggleInput ? toggleInput.getAttribute('role') : null,
  checked: toggleInput ? toggleInput.checked : null,
  indeterminate: toggleInput ? toggleInput.indeterminate === true : false,
  disabled: toggleInput ? toggleInput.disabled : null,
  hasUnknownClass: toggleLabel ? toggleLabel.classList.contains('hub-toggle--unknown') : false,
}}));
"""


def _run_staff_wifi_toggle_dom_scenario(
    tmp_path: Path,
    *,
    observed_ap: dict[str, object] | None,
) -> dict[str, object]:
    ap_json = "null" if observed_ap is None else json.dumps(observed_ap, ensure_ascii=False)
    script = _build_staff_wifi_toggle_dom_harness_script(
        screen_uri=STAFF_WIFI_SCREEN_JS.as_uri(),
        observed_ap_json=ap_json,
    )
    return _run_node_harness(script, tmp_path, "staff-toggle-dom")  # type: ignore[return-value]


@pytest.mark.parametrize(
    (
        "case_id",
        "observed_ap",
        "expected_aria_checked",
        "expected_role",
        "expected_unknown_class",
        "expected_disabled",
        "expected_indeterminate",
    ),
    [
        (
            "partial-active",
            {
                "ap_id": "WifiMaster0/AccessPoint4",
                "readable": True,
                "enabled_or_up": True,
                "link_up": False,
                "wpa_mode": "WPA2",
            },
            "mixed",
            "checkbox",
            True,
            False,
            True,
        ),
        (
            "known-off",
            {
                "ap_id": "WifiMaster0/AccessPoint4",
                "readable": True,
                "enabled_or_up": False,
                "link_up": False,
                "wpa_mode": "WPA2",
            },
            "false",
            "switch",
            False,
            False,
            False,
        ),
        (
            "known-on",
            {
                "ap_id": "WifiMaster0/AccessPoint4",
                "readable": True,
                "enabled_or_up": True,
                "link_up": True,
                "wpa_mode": "WPA2",
            },
            "true",
            "switch",
            False,
            False,
            False,
        ),
    ],
)
def test_staff_wifi_network_toggle_dom_unknown_distinct_from_off(
    tmp_path: Path,
    case_id: str,
    observed_ap: dict[str, object],
    expected_aria_checked: str,
    expected_role: str,
    expected_unknown_class: bool,
    expected_disabled: bool,
    expected_indeterminate: bool,
) -> None:
    """H-1: неизвестное/частичное состояние сети в DOM отличимо от подтверждённого «выкл»."""
    result = _run_staff_wifi_toggle_dom_scenario(tmp_path / case_id, observed_ap=observed_ap)
    assert result["found"] is True, result
    assert result["ariaChecked"] == expected_aria_checked, result
    assert result["role"] == expected_role, result
    assert result["hasUnknownClass"] is expected_unknown_class, result
    assert result["disabled"] is expected_disabled, result
    assert bool(result["indeterminate"]) is expected_indeterminate, result
    if expected_unknown_class:
        assert result["checked"] is False, result
        assert result["indeterminate"] is True, result
    if case_id == "known-off":
        assert result["ariaChecked"] != "mixed", result
        assert result["hasUnknownClass"] is False, result
        assert result["indeterminate"] is not True, result
        assert "Выключена" in str(result["ariaLabel"]), result
        assert result["checked"] is False, result


def test_staff_wifi_network_toggle_dom_unread_via_create_toggle(tmp_path: Path) -> None:
    """H-1: непрочитанное состояние (модель) — indeterminate toggle, не «выкл»."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    wifi_ap_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    toggle_uri = json.dumps((HUB / "components" / "toggle.js").as_uri())
    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();
globalThis.document = dom.document;

import {{ describeWifiNetworkToggle }} from {wifi_ap_uri};
import {{ createToggle }} from {toggle_uri};

const toggleState = describeWifiNetworkToggle(null);
const toggle = createToggle({{
  id: 'hub-test-wifi-network-toggle',
  label: 'Сеть',
  checked: toggleState.checked,
  indeterminate: toggleState.unknown,
  disabled: false,
  tone: 'success',
}});
const toggleInput = toggle.querySelector('input');
if (toggleInput) {{
  toggleInput.setAttribute('aria-label', `Сеть: ${{toggleState.description}}`);
}}
dom.document.body.appendChild(toggle);

console.log(JSON.stringify({{
  unknown: toggleState.unknown,
  ariaChecked: toggleInput ? toggleInput.getAttribute('aria-checked') : null,
  ariaLabel: toggleInput ? toggleInput.getAttribute('aria-label') : null,
  role: toggleInput ? toggleInput.getAttribute('role') : null,
  indeterminate: toggleInput ? toggleInput.indeterminate === true : false,
  hasUnknownClass: toggle.classList.contains('hub-toggle--unknown'),
  disabled: toggleInput ? toggleInput.disabled : null,
  checked: toggleInput ? toggleInput.checked : null,
}}));
"""
    result = _run_node_harness(script, tmp_path, "staff-toggle-unread-direct")
    assert result["unknown"] is True
    assert result["ariaChecked"] == "mixed"
    assert result["role"] == "checkbox"
    assert result["indeterminate"] is True
    assert result["hasUnknownClass"] is True
    assert result["disabled"] is False
    assert result["checked"] is False
    assert "Состояние не прочитано" in str(result["ariaLabel"])
    assert result["ariaChecked"] != "false"


def test_staff_wifi_credential_ref_required_error_copy(tmp_path: Path) -> None:
    """G-5/G-6: точный код wifi.credential_ref_required → CONFLICT, не DEVICE."""
    errors_uri = json.dumps((HUB / "core" / "errors.js").as_uri())
    script = f"""import {{ resolveErrorEntry, ERROR_KIND }} from {errors_uri};
const entry = resolveErrorEntry('wifi.credential_ref_required');
console.log(JSON.stringify({{
  kind: entry.kind,
  userMessage: entry.userMessage,
  userAction: entry.userAction,
}}));
"""
    result = _run_node_harness(script, tmp_path, "cred-ref-error-copy")
    assert result["kind"] == "CONFLICT"
    assert "парол" in result["userMessage"].lower()
    assert "поле" in result["userAction"].lower() or "парол" in result["userAction"].lower()


def test_staff_wifi_preview_enabled_false_yields_empty_apply_plan(tmp_path: Path) -> None:
    """F-2 trap: enabled:false передаётся в preview body (выключение — через teardown)."""
    result = _run_export(
        tmp_path,
        label="enabled-false-preview",
        script_body="""
const preview = mod.buildWifiPreviewBody({
  apId: 'WifiMaster0/AccessPoint4',
  ssid: 'Off-Trap',
  wpaMode: 'WPA2',
  enabled: false,
});
console.log(JSON.stringify({ enabled: preview.enabled }));
""",
    )
    assert result["enabled"] is False


def test_staff_wifi_credential_ref_cache_reuses_same_ref(tmp_path: Path) -> None:
    """G-3: повторный ensureWifiCredentialRef с тем же черновиком не меняет ref."""
    wifi_ap_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    script = f"""const mod = await import({wifi_ap_uri});
let putCount = 0;
globalThis.fetch = async (url) => {{
  if (String(url).includes('/credentials')) {{
    putCount += 1;
    return {{
      ok: true,
      status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ credential_ref_id: `cred-ref-${{putCount}}` }}),
      text: async () => JSON.stringify({{ credential_ref_id: `cred-ref-${{putCount}}` }}),
    }};
  }}
  throw new Error('unexpected fetch');
}};
const secret = {json.dumps(TEST_PSK)};
const first = await mod.ensureWifiCredentialRef({{
  routerId: 'router-lab-1',
  apId: 'WifiMaster0/AccessPoint4',
  ssid: 'Staff-Lab',
  secret,
  cached: null,
}});
const second = await mod.ensureWifiCredentialRef({{
  routerId: 'router-lab-1',
  apId: 'WifiMaster0/AccessPoint4',
  ssid: 'Staff-Lab',
  secret,
  cached: first.cache,
}});
console.log(JSON.stringify({{
  putCount,
  firstRef: first.credentialRefId,
  secondRef: second.credentialRefId,
}}));
"""
    result = _run_node_harness(script, tmp_path, "cred-ref-cache")
    assert result["putCount"] == 1
    assert result["firstRef"] == result["secondRef"]


def test_staff_wifi_toggle_label_click_operable_when_unknown(tmp_path: Path) -> None:
    """F-C1: клик по track при unknown активирует через wrap-handler, не через change."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    toggle_uri = json.dumps((HUB / "components" / "toggle.js").as_uri())
    script = f"""import {{ createRequire }} from 'node:module';
const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();
globalThis.document = dom.document;
import {{ createToggle }} from {toggle_uri};
let activated = false;
let changeEvents = 0;
const toggle = createToggle({{
  id: 'hub-test-toggle',
  label: 'Сеть',
  checked: false,
  indeterminate: true,
  disabled: false,
  onChange: (checked) => {{ activated = checked; }},
}});
const input = toggle.querySelector('input');
if (input) {{
  input.addEventListener('change', () => {{ changeEvents += 1; }});
}}
dom.document.body.appendChild(toggle);
const track = toggle.children[1];
if (track) track.click();
console.log(JSON.stringify({{
  activated,
  checked: input ? input.checked : null,
  indeterminate: input ? input.indeterminate === true : null,
  changeEvents,
}}));
"""
    result = _run_node_harness(script, tmp_path, "toggle-label-click")
    assert result["activated"] is True
    assert result["checked"] is True
    assert result["indeterminate"] is False
    assert result["changeEvents"] == 1


def test_staff_wifi_toggle_label_click_red_proof_variants(tmp_path: Path) -> None:
    """F-C1 red→green: broken toggle variants fail the behavioural contract."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    toggle_src = (HUB / "components" / "toggle.js").read_text(encoding="utf-8")

    def _run_toggle_variant(label: str, source: str) -> dict[str, object]:
        broken = tmp_path / f"toggle-{label}.js"
        broken.write_text(source, encoding="utf-8")
        toggle_uri = json.dumps(broken.as_uri())
        script = f"""import {{ createRequire }} from 'node:module';
const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();
globalThis.document = dom.document;
import {{ createToggle }} from {toggle_uri};
let activated = false;
let changeEvents = 0;
const toggle = createToggle({{
  id: 'hub-test-toggle',
  label: 'Сеть',
  checked: false,
  indeterminate: true,
  disabled: false,
  onChange: (checked) => {{ activated = checked; }},
}});
const input = toggle.querySelector('input');
if (input) input.addEventListener('change', () => {{ changeEvents += 1; }});
dom.document.body.appendChild(toggle);
const track = toggle.children[1];
if (track) track.click();
console.log(JSON.stringify({{ activated, changeEvents }}));
"""
        return _run_node_harness(script, tmp_path / label, f"toggle-{label}")  # type: ignore[return-value]

    ok = _run_toggle_variant("ok", toggle_src)
    assert ok["activated"] is True
    assert ok["changeEvents"] == 1

    disabled_script = f"""import {{ createRequire }} from 'node:module';
const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();
globalThis.document = dom.document;
import {{ createToggle }} from {json.dumps((HUB / "components" / "toggle.js").as_uri())};
let activated = false;
const toggle = createToggle({{
  id: 'hub-test-toggle',
  label: 'Сеть',
  checked: false,
  indeterminate: true,
  disabled: true,
  onChange: (checked) => {{ activated = checked; }},
}});
dom.document.body.appendChild(toggle);
const track = toggle.children[1];
if (track) track.click();
console.log(JSON.stringify({{ activated }}));
"""
    disabled_result = _run_node_harness(disabled_script, tmp_path / "disabled", "toggle-disabled")
    assert disabled_result["activated"] is False

    no_wrap_toggle = tmp_path / "toggle-no-wrap.js"
    no_wrap_toggle.write_text(
        re.sub(
            r'\r?\n  wrap\.addEventListener\("click"[\s\S]*?\r?\n  \}\);\r?\n',
            "\n",
            toggle_src,
            count=1,
        ),
        encoding="utf-8",
    )
    old_harness = tmp_path / "harness-old.js"
    old_harness.write_text(
        UI_DOM_HARNESS.read_text(encoding="utf-8").replace(
            "        runClickActivation(this);",
            (
                "        if (String(this.tagName || '').toUpperCase() === 'LABEL') {\n"
                "          const input = this.querySelector('input');\n"
                "          if (input && !input.disabled) {\n"
                "            input.indeterminate = false;\n"
                "            input.checked = true;\n"
                "            dispatchEvent(input, 'change', {"
                " type: 'change', target: input, preventDefault() {} });\n"
                "            return;\n"
                "          }\n"
                "        }\n"
                "        runClickActivation(this);"
            ),
            1,
        ),
        encoding="utf-8",
    )
    decorative_script = f"""import {{ createRequire }} from 'node:module';
const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({json.dumps(str(old_harness))});
const dom = createUiDomHarness();
globalThis.document = dom.document;
import {{ createToggle }} from {json.dumps(no_wrap_toggle.as_uri())};
let activated = false;
let changeEvents = 0;
const toggle = createToggle({{
  id: 'hub-test-toggle',
  label: 'Net',
  checked: false,
  indeterminate: true,
  disabled: false,
  onChange: (checked) => {{ activated = checked; }},
}});
const input = toggle.querySelector('input');
if (input) input.addEventListener('change', () => {{ changeEvents += 1; }});
dom.document.body.appendChild(toggle);
toggle.click();
console.log(JSON.stringify({{ activated, changeEvents }}));
"""
    decorative = _run_node_harness(
        decorative_script,
        tmp_path / "decorative",
        "toggle-decorative",
    )
    assert decorative["activated"] is True
    with pytest.raises(AssertionError):
        assert decorative["changeEvents"] == 0


def test_staff_wifi_apply_refresh_observed_on_config_applied(tmp_path: Path) -> None:
    """F-3: refreshObserved=true при overall=applied даже без on_air_verified."""
    result = _run_export(
        tmp_path,
        label="refresh-observed",
        script_body="""
const verdict = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_verification_status: 'on_air_unverified',
  errors: [],
});
console.log(JSON.stringify({
  success: verdict.success,
  refreshObserved: verdict.refreshObserved,
}));
""",
    )
    assert result["success"] is False
    assert result["refreshObserved"] is True


def test_staff_wifi_fake_e2e_subset_via_test_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """E2E fake transport: preview → apply → readback (Python driver, fake cred ref)."""
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "wifi_fake_e2e.sqlite3", allow_fake_mutations=True)
    app.state.host.wifi_apply_credential_resolver = lambda _ref: TEST_PSK
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        ref_id = "credref:staff-wifi-e2e"
        preview_payload = {
            "ap_id": "WifiMaster0/AccessPoint4",
            "ssid": "E2E-Staff-SSID",
            "enabled": True,
            "captive_portal": "Disabled",
            "guest_isolation": False,
            "wpa_mode": "WPA2",
            "band": "BAND_2_4GHZ",
            "credential_ref_id": ref_id,
        }
        preview = client.post(
            "/api/router-control/v1/wifi/preview",
            json=preview_payload,
        )
        assert preview.status_code == 200, preview.text
        apply = client.post(
            "/api/router-control/v1/wifi/apply",
            json={
                **preview_payload,
                "confirm_live_apply": True,
                "compensate_on_failure": True,
                "idempotent": True,
            },
        )
        assert apply.status_code == 200, apply.text
        assert apply.json()["overall"] == "applied"
        observed = client.post(
            "/api/router-control/v1/wifi/observed-state",
            json={"ap_ids": ["WifiMaster0/AccessPoint4"]},
        )
        assert observed.status_code == 200
        row = observed.json()["access_points"][0]
        assert row["ssid"] == "E2E-Staff-SSID"
        assert TEST_PSK not in apply.text
        assert TEST_PSK not in observed.text


def _pick_loopback_port(min_port: int = 8790) -> int:
    for port in range(min_port, min_port + 32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    pytest.fail(f"no free loopback port from {min_port}")


def _assert_fake_host_readback_result(result: dict[str, object]) -> None:
    assert result["apply_overall"] == "applied"
    assert result["on_air_verification_status"] == "on_air_verified"
    assert result["observed_ssid"] == "Staff-FakeHost-E2E"
    assert result["observed_wpa_mode"] == "WPA2"
    assert result["observed_enabled_or_up"] is True


def test_staff_wifi_fake_host_apply_readback_on_loopback_port(tmp_path: Path) -> None:
    """Fake-mode host on 8790+: API apply → observed readback (HTTP driver in subprocess)."""
    port = _pick_loopback_port(8790)
    db_path = tmp_path / f"fake-host-api-{port}.sqlite3"
    base_url = f"http://127.0.0.1:{port}"
    env = os.environ.copy()
    env.update(
        {
            "RC_UNSAFE_DISABLE_AUTH": "1",
            "RC_STANDALONE_LOOPBACK_AUTH": "1",
            "RC_ADAPTER_MODE": "fake",
            "RC_ALLOW_FAKE_MUTATIONS": "1",
            "ROUTER_CONTROL_DB_PATH": str(db_path),
            "HUB_ADMIN_PASSWORD": "e2e-fake-hub-password",
            "RC_PUBLIC_BASE_URL": base_url,
        }
    )
    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "uvicorn",
            "router_control_host.app:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        cwd=str(REPO_ROOT),
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    driver = REPO_ROOT / "tests" / "support" / "staff_wifi_fake_host_readback_driver.py"
    try:
        run = subprocess.run(
            [sys.executable, str(driver), base_url],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=90,
        )
        assert run.returncode == 0, run.stderr or run.stdout
        result = json.loads(run.stdout.strip())
        _assert_fake_host_readback_result(result)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


def test_staff_wifi_fake_host_readback_result_red_proof() -> None:
    """Guard: rolled_back apply overall must fail parent assertions."""
    with pytest.raises(AssertionError):
        _assert_fake_host_readback_result(
            {
                "apply_overall": "rolled_back",
                "on_air_verification_status": "on_air_verified",
                "observed_ssid": "Staff-FakeHost-E2E",
                "observed_wpa_mode": "WPA2",
                "observed_enabled_or_up": True,
            }
        )


def test_staff_wifi_toggle_unknown_css_rule() -> None:
    """H-1 supplement: CSS-правило для unknown с forced-colors существует в components.css."""
    css_path = HUB / "styles" / "components.css"
    css = css_path.read_text(encoding="utf-8")
    assert ".hub-toggle--unknown .hub-toggle__track" in css
    assert ".hub-toggle--unknown .hub-toggle__thumb" in css
    unknown_block_start = css.index(".hub-toggle--unknown .hub-toggle__track")
    unknown_section = css[unknown_block_start : unknown_block_start + 1200]
    assert "@media (forced-colors: active)" in unknown_section
    assert "CanvasText" in unknown_section


def test_staff_wifi_network_toggle_dom_red_proof_without_indeterminate(tmp_path: Path) -> None:
    """H-1 red→green: без input.indeterminate непрочитанное снова неотличимо от «выкл»."""
    broken_hub = tmp_path / "hub-broken-toggle"
    shutil.copytree(
        HUB / "components",
        broken_hub,
    )
    broken_toggle = broken_hub / "toggle.js"
    broken_toggle.write_text(
        broken_toggle.read_text(encoding="utf-8").replace(
            "    input.indeterminate = true;\n",
            "",
        ),
        encoding="utf-8",
    )
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    wifi_ap_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    toggle_uri = json.dumps(broken_toggle.as_uri())
    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();
globalThis.document = dom.document;

import {{ describeWifiNetworkToggle }} from {wifi_ap_uri};
import {{ createToggle }} from {toggle_uri};

const toggleState = describeWifiNetworkToggle(null);
const toggle = createToggle({{
  checked: toggleState.checked,
  indeterminate: toggleState.unknown,
  disabled: false,
  label: 'Сеть',
}});
const toggleInput = toggle.querySelector('input');

console.log(JSON.stringify({{
  ariaChecked: toggleInput ? toggleInput.getAttribute('aria-checked') : null,
  indeterminate: toggleInput ? toggleInput.indeterminate === true : false,
  checked: toggleInput ? toggleInput.checked : null,
  hasUnknownClass: toggle.classList.contains('hub-toggle--unknown'),
}}));
"""
    result = _run_node_harness(script, tmp_path / "red-proof", "staff-toggle-red")
    with pytest.raises(AssertionError):
        assert result["indeterminate"] is True
        assert result["hasUnknownClass"] is True


def _count_active_wifi_psk_refs(store: object, router_id: str) -> int:
    rows = store.list_credential_refs(router_id)  # type: ignore[attr-defined]
    return sum(
        1 for row in rows if row["kind"] == "WifiApPsk" and row["revoked_at"] is None
    )


def _wait_for_router(client: object, router_id: str) -> None:
    import time

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        response = client.get(f"/api/router-control/v1/routers/{router_id}")  # type: ignore[attr-defined]
        if response.status_code == 200:
            return
        time.sleep(0.05)
    pytest.fail(f"router {router_id} not ready")


def test_wifi_credential_ref_g3_lifecycle_vault_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """G-3/F-A1: supersede revokes; at most one active WifiApPsk per draft."""
    from router_control_host.app import create_app
    from router_control_host.auth import mint_hub_admin_cookie

    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    monkeypatch.setenv("RC_ALLOW_FAKE_MUTATIONS", "1")
    app = create_app(db_path=tmp_path / "g3_vault.sqlite3", allow_fake_mutations=True)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        enroll = client.post(
            "/api/router-control/v1/routers",
            json={
                "display_name": "G3 Vault Router",
                "vendor": "V",
                "model": "M",
                "endpoint": {"kind": "management_https", "host": "127.0.0.1", "port": 443},
                "management_password": "mgmt-psk-not-real-secret",
            },
            headers={"Idempotency-Key": "enroll-g3-vault"},
        )
        assert enroll.status_code == 202
        router_id = enroll.json()["router_id"]
        _wait_for_router(client, router_id)
        store = app.state.host.runtime.store

        def put_psk(secret: str, key: str) -> str:
            resp = client.put(
                f"/api/router-control/v1/routers/{router_id}/credentials",
                json={"kind": "WifiApPsk", "secret": secret},
                headers={"Idempotency-Key": key},
            )
            assert resp.status_code == 201
            ref = resp.json()["credential_ref_id"]
            assert isinstance(ref, str)
            return ref

        def revoke_ref(ref_id: str, key: str) -> None:
            resp = client.post(
                f"/api/router-control/v1/routers/{router_id}/credentials/{ref_id}/revoke",
                headers={"Idempotency-Key": key},
            )
            assert resp.status_code == 202

        cache: str | None = None
        for idx, secret in enumerate(
            ("edit-psk-aaaaaa", "edit-psk-bbbbbb", "edit-psk-cccccc"),
            start=1,
        ):
            new_ref = put_psk(secret, f"put-edit-{idx}")
            if cache is not None:
                revoke_ref(cache, f"revoke-after-put-{idx}")
            cache = new_ref
        assert _count_active_wifi_psk_refs(store, router_id) == 1

        replay = client.put(
            f"/api/router-control/v1/routers/{router_id}/credentials",
            json={"kind": "WifiApPsk", "secret": "edit-psk-cccccc"},
            headers={"Idempotency-Key": "put-edit-3"},
        )
        assert replay.status_code == 201
        assert replay.json()["credential_ref_id"] == cache
        assert _count_active_wifi_psk_refs(store, router_id) == 1

        previous = cache
        cache = put_psk("ap-switch-psk-8ch", "put-ap-switch")
        revoke_ref(previous, "revoke-ap-switch")
        assert _count_active_wifi_psk_refs(store, router_id) == 1

        revoke_ref(cache, "revoke-cancel-modal")
        assert _count_active_wifi_psk_refs(store, router_id) == 0


def test_wifi_credential_ref_g3_ensure_supersedes_with_revoke(tmp_path: Path) -> None:
    """G-3/F-A1: ensureWifiCredentialRef revokes superseded ref before minting."""
    wifi_ap_uri = json.dumps((HUB / "features" / "wifi-ap-model.js").as_uri())
    script = f"""const mod = await import({wifi_ap_uri});
let putCount = 0;
let revokeCount = 0;
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  const method = String(init.method || 'GET').toUpperCase();
  if (method === 'PUT' && urlStr.includes('/credentials') && !urlStr.includes('/revoke')) {{
    putCount += 1;
    return {{
      ok: true,
      status: 201,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ credential_ref_id: `cred-ref-${{putCount}}` }}),
      text: async () => JSON.stringify({{ credential_ref_id: `cred-ref-${{putCount}}` }}),
    }};
  }}
  if (method === 'POST' && urlStr.includes('/revoke')) {{
    revokeCount += 1;
    return {{
      ok: true,
      status: 202,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ status: 'Queued' }}),
      text: async () => JSON.stringify({{ status: 'Queued' }}),
    }};
  }}
  throw new Error(`unexpected fetch ${{method}} ${{urlStr}}`);
}};
const base = {{
  routerId: 'router-lab-1',
  apId: 'WifiMaster0/AccessPoint4',
  ssid: 'Staff-Lab',
}};
let cache = null;
for (const secret of ['edit-psk-aaaaaa', 'edit-psk-bbbbbb', 'edit-psk-cccccc']) {{
  const result = await mod.ensureWifiCredentialRef({{ ...base, secret, cached: cache }});
  cache = result.cache;
}}
const reuse = await mod.ensureWifiCredentialRef({{
  ...base,
  secret: 'edit-psk-cccccc',
  cached: cache,
}});
console.log(JSON.stringify({{ putCount, revokeCount, reuseRef: reuse.credentialRefId }}));
"""
    result = _run_node_harness(script, tmp_path, "g3-ensure-supersede")
    assert result["putCount"] == 3
    assert result["revokeCount"] == 2
    assert result["reuseRef"] == "cred-ref-3"


def test_staff_standing_ssid_prefill_only_when_unreadable(tmp_path: Path) -> None:
    """R-3/F-7: standing SSID prefill only when !observed.readable."""
    result = _run_export(
        tmp_path,
        label="standing-prefill",
        script_body="""
const unreadable = mod.parseObservedAccessPoint({ ap_id: 'WifiMaster0/AccessPoint4', readable: false });
const readableUnknown = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  ssid: null,
});
const standing = {
  staff_ssid: 'Corp WiFi',
  guest_default_ssid: 'Guest',
  staff_password_credential_ref_id: null,
  staff_password_configured: false,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
};
console.log(JSON.stringify({
  unreadable: mod.createStaffWifiFormDraft(unreadable, standing).ssid,
  readableUnknown: mod.createStaffWifiFormDraft(readableUnknown, standing).ssid,
  noStanding: mod.createStaffWifiFormDraft(unreadable, null).ssid,
  seed: mod.STAFF_WIFI_STANDING_SSID_SEED,
}));
""",
    )
    assert result["unreadable"] == "Corp WiFi"
    assert result["readableUnknown"] == ""
    assert result["noStanding"] == result["seed"]


def test_staff_standing_credential_reuse_staff_only(tmp_path: Path) -> None:
    """F-2: staff path reuses standing ref; never register when configured."""
    result = _run_export(
        tmp_path,
        label="standing-cred-reuse",
        script_body="""
const standing = {
  staff_ssid: 'Corp',
  guest_default_ssid: 'Guest',
  staff_password_credential_ref_id: 'cred-standing-1',
  staff_password_configured: true,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
};
const intent = mod.resolveStaffWifiCredentialIntent({
  password: '',
  standing,
  draftCredentialRef: null,
  selectedApId: 'WifiMaster0/AccessPoint4',
  draftSsid: 'Corp',
});
console.log(JSON.stringify(intent));
""",
    )
    assert result["kind"] == "ref"
    assert result["credentialRefId"] == "cred-standing-1"


def test_staff_disabled_remediation_flag(tmp_path: Path) -> None:
    result = _run_export(
        tmp_path,
        label="staff-remediation",
        script_body="""
const off = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  enabled_or_up: false,
  link_up: false,
});
const on = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: true,
  enabled_or_up: true,
  link_up: true,
  ssid: 'Live',
});
console.log(JSON.stringify({
  off: mod.shouldShowStaffDisabledRemediation(off),
  on: mod.shouldShowStaffDisabledRemediation(on),
}));
""",
    )
    assert result["off"] is True
    assert result["on"] is False


def test_staff_apply_standing_defaults_feasibility(tmp_path: Path) -> None:
    result = _run_export(
        tmp_path,
        label="apply-defaults",
        script_body="""
const standing = {
  staff_ssid: 'Corp',
  guest_default_ssid: 'Guest',
  staff_password_credential_ref_id: 'cred-1',
  staff_password_configured: true,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
};
console.log(JSON.stringify({
  ok: mod.canApplyStaffStandingDefaults({
    selectedApId: 'WifiMaster0/AccessPoint4',
    standing,
    mutationReadiness: { allowed: true, reasonText: null, missing: [], mock: false },
  }),
  missingPassword: mod.resolveStaffWifiCredentialIntent({
    password: '',
    standing: { ...standing, staff_password_configured: false, staff_password_credential_ref_id: null },
    draftCredentialRef: null,
    selectedApId: 'WifiMaster0/AccessPoint4',
    draftSsid: 'Corp',
  }).kind,
}));
""",
    )
    assert result["ok"] is True
    assert result["missingPassword"] == "missing"


def test_should_persist_standing_after_readback_success_despite_apply_false(tmp_path: Path) -> None:
    """AC-R3/F-1: standing persist gates on final readback verdict, not pre-readback apply success."""
    result = _run_export(
        tmp_path,
        label="standing-persist-gate",
        script_body="""
const applyVerdict = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_admin_only: true,
});
const readbackVerdict = { success: true, title: 'OK', message: 'readback ok' };
console.log(JSON.stringify({
  applySuccess: applyVerdict.success,
  shouldPersistAfterReadback: mod.shouldPersistStandingPreferencesAfterMutation({
    lastVerdict: readbackVerdict,
    action: 'save',
  }),
  shouldNotPersistOnTeardown: mod.shouldPersistStandingPreferencesAfterMutation({
    lastVerdict: readbackVerdict,
    action: 'teardown',
  }),
  shouldNotPersistOnFailure: mod.shouldPersistStandingPreferencesAfterMutation({
    lastVerdict: { success: false, title: 'Fail', message: 'fail' },
    action: 'save',
  }),
}));
""",
    )
    assert result["applySuccess"] is False
    assert result["shouldPersistAfterReadback"] is True
    assert result["shouldNotPersistOnTeardown"] is False
    assert result["shouldNotPersistOnFailure"] is False


def test_staff_standing_merge_when_observed_unreadable_arrives_first(tmp_path: Path) -> None:
    """F-2/R-6: loadStandingFlow merge — observed unreadable + standing uses standing SSID."""
    result = _run_export(
        tmp_path,
        label="standing-merge-race",
        script_body="""
const unreadableObserved = mod.parseObservedAccessPoint({
  ap_id: 'WifiMaster0/AccessPoint4',
  readable: false,
});
const standing = {
  staff_ssid: 'Corp WiFi',
  guest_default_ssid: 'Guest',
  staff_password_credential_ref_id: null,
  staff_password_configured: false,
  guest_default_enabled: false,
  updated_at: '2026-08-05T00:00:00Z',
};
console.log(JSON.stringify({
  mergeDraft: mod.createStaffWifiFormDraft(unreadableObserved, standing).ssid,
  seedOnly: mod.createStaffWifiFormDraft(unreadableObserved, null).ssid,
}));
""",
    )
    assert result["mergeDraft"] == "Corp WiFi"
    assert result["seedOnly"] == "Рабочая сеть"


def test_staff_load_standing_flow_merges_observed_when_not_dirty() -> None:
    """F-2: loadStandingFlow re-merges draft from observed+standing when !formDirty."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "if (!formDirty) {" in source
    assert "createStaffWifiFormDraft(observed, standing)" in source
    assert "!formDirty && !observed" not in source


def test_staff_run_mutation_persist_uses_final_verdict_gate() -> None:
    """F-1: runMutation persist uses shouldPersistStandingPreferencesAfterMutation."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "shouldPersistStandingPreferencesAfterMutation" in source
    assert "succeeded && lastVerdict?.success" not in source


def test_should_clear_wifi_form_password_after_readback_success_despite_apply_false(
    tmp_path: Path,
) -> None:
    """AC-R3/F-3: password clear gates on final readback verdict, not pre-readback apply success."""
    result = _run_export(
        tmp_path,
        label="password-clear-gate",
        script_body="""
const applyVerdict = mod.parseWifiApplyVerdict({
  overall: 'applied',
  on_air_admin_only: true,
});
const readbackVerdict = { success: true, title: 'OK', message: 'readback ok' };
console.log(JSON.stringify({
  applySuccess: applyVerdict.success,
  shouldClearAfterReadback: mod.shouldClearStaffWifiFormPasswordAfterMutation({
    lastVerdict: readbackVerdict,
  }),
  shouldNotClearOnFailure: mod.shouldClearStaffWifiFormPasswordAfterMutation({
    lastVerdict: { success: false, title: 'Fail', message: 'fail' },
  }),
  shouldNotClearOnNull: mod.shouldClearStaffWifiFormPasswordAfterMutation({
    lastVerdict: null,
  }),
}));
""",
    )
    assert result["applySuccess"] is False
    assert result["shouldClearAfterReadback"] is True
    assert result["shouldNotClearOnFailure"] is False
    assert result["shouldNotClearOnNull"] is False


def test_staff_run_mutation_password_clear_uses_final_verdict_gate() -> None:
    """F-3: runMutation password clear uses shouldClearStaffWifiFormPasswordAfterMutation."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "shouldClearStaffWifiFormPasswordAfterMutation" in source
    assert "succeeded && shouldResetStaffWifiFormAfterMutation" not in source


def test_staff_wifi_run_mutation_toast_tone_from_hub_state() -> None:
    """Apply toast tone uses getStateDescriptor(hubState) when !success."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    assert "getStateDescriptor" in source
    body = _extract_function_body_from_staff_screen(source, "async function runMutation(")
    assert body is not None
    assert "getStateDescriptor(lastVerdict.hubState).tone" in body
    assert "Object.values(HubState).includes(lastVerdict.hubState)" in body
    assert "tone: lastVerdict.success ? 'success' : 'warning'" not in body


def test_staff_wifi_standing_persist_failure_shows_warning_with_retry() -> None:
    """After apply success, standing PUT failure warns + operationRetry, not silent swallow."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    persist_start = source.find("async function persistStandingPreferencesAfterSuccess(")
    assert persist_start != -1
    persist_region = source[persist_start : persist_start + 2200]
    assert "updateStaffStandingNetworkPreferences" in persist_region
    assert "updateStaffStandingNetworkPreferences(body, { signal })" in persist_region
    assert "signal?.aborted" in persist_region
    assert "{ signal: mutateAbort.signal }" in source
    assert "operationError = error" in persist_region
    assert "operationRetry = async () =>" in persist_region
    assert "tone: 'warning'" in persist_region
    assert "Не удалось сохранить обычные настройки" in persist_region
    assert "Нажмите «Повторить»" in persist_region
    assert "// Non-blocking" not in persist_region
    assert "catch {" not in persist_region


def test_staff_wifi_standing_load_error_renders_inline_warning() -> None:
    """Standing GET failure shows inline warning — empty defaults not silent."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
    load_body = _extract_function_body_from_staff_screen(source, "async function loadStandingFlow(")
    assert load_body is not None
    assert "standingError = error" in load_body
    extra_sig = _extract_function_body_from_staff_screen(source, "function buildStaffExtraSignature(")
    assert extra_sig is not None
    assert "standingError && !isAborted(standingError)" in extra_sig
    assert "standing-load-fail" in extra_sig
    extra_render = _extract_function_body_from_staff_screen(source, "function renderExtraSlot(")
    assert extra_render is not None
    assert "Не удалось загрузить обычные настройки" in extra_render
    assert "standingError && !isAborted(standingError)" in extra_render
    assert "Значения по умолчанию могут быть пустыми." in extra_render


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


def test_staff_wifi_connectivity_offline_invalidates_all_operations() -> None:
    """hub-offline-abort-followups: offline connectivity invalidates in-flight staff Wi-Fi ops."""
    source = STAFF_WIFI_SCREEN_JS.read_text(encoding="utf-8")
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
