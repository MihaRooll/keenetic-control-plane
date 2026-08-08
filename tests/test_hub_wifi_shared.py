"""Контракты общих Wi‑Fi модулей LOCAL HUB (live params + QR)."""

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
LIVE_PARAMS_JS = HUB / "features" / "live-connection-params.js"
WIFI_AP_MODEL_JS = HUB / "features" / "wifi-ap-model.js"
WIFI_QR_JS = HUB / "features" / "wifi-qr.js"
SESSION_JS = HUB / "core" / "session.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
QRCODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_QRCODE"
TEST_PSK = "test-psk-not-real"
REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"

QR_REFERENCE_PAYLOADS: tuple[dict[str, object], ...] = (
    {
        "label": "ascii-staff",
        "security": "WPA2",
        "ssid": "Staff-Private",
        "password": "not-a-real-psk-8793",
        "hidden": False,
    },
    {
        "label": "ascii-lab-short",
        "security": "WPA2",
        "ssid": "Lab",
        "password": TEST_PSK,
        "hidden": False,
    },
    {
        "label": "ascii-short-password",
        "security": "WPA2",
        "ssid": "Short",
        "password": "x",
        "hidden": False,
    },
    {
        "label": "ascii-multiblock",
        "security": "WPA2",
        "ssid": "LongNetworkName-ABCDEFGHIJ",
        "password": "very-long-password-for-multi-block-test-1234567890",
        "hidden": False,
    },
    {
        "label": "numeric-password-long",
        "security": "WPA2",
        "ssid": "DigitsOnlyNet",
        "password": "1" * 40,
        "hidden": False,
    },
    {
        "label": "ascii-long-password",
        "security": "WPA2",
        "ssid": "A",
        "password": "p" * 100,
        "hidden": False,
    },
    {
        "label": "ascii-numeric-password-run",
        "security": "WPA2",
        "ssid": "DigitPassNet",
        "password": "wifi-pass-12345678901234567890",
        "hidden": False,
    },
)

QR_ACCEPTANCE_PAYLOADS: tuple[dict[str, object], ...] = (
    {
        "label": "cyrillic-ssid-latin-password-v7",
        "security": "WPA2",
        # 40 кириллических символов → 121 байт UTF-8; .length=81 ломает версию (v6), байты → v7.
        "ssid": "\u0426" * 40,
        "password": "unicode-pass-42",
        "hidden": False,
    },
    {
        "label": "cyrillic-ssid-and-password-v10",
        "security": "WPA2",
        "ssid": (
            "\u0413\u043e\u0441\u0442\u0435\u0432\u0430\u044f-\u0441\u0435\u0442\u044c-"
            + ("\u0446" * 24)
        ),
        "password": "\u043f\u0430\u0440\u043e\u043b\u044c-" + ("\u0430" * 34),
        "hidden": False,
    },
    {
        "label": "emoji-four-byte-ssid",
        "security": "WPA2",
        "ssid": "WiFi\U0001f4f6-" + ("\u0426" * 3),
        "password": TEST_PSK,
        "hidden": False,
    },
    {
        "label": "ascii-version-11",
        "security": "WPA2",
        "ssid": "LongV10",
        "password": "x" * 200,
        "hidden": False,
    },
    {
        "label": "cyrillic-event-ssid-and-password-v7",
        "security": "WPA2",
        "ssid": (
            "\u041c\u0435\u0440\u043e\u043f\u0440\u0438\u044f\u0442\u0438\u0435-" + ("\u0426" * 22)
        ),
        "password": "\u043f\u0430\u0440\u043e\u043b\u044c-42",
        "hidden": False,
    },
)

QR_ESCAPING_PAYLOAD: dict[str, object] = {
    "label": "escaping-semicolon-backslash",
    "security": "WPA2",
    "ssid": r"Lab;net\quote",
    "password": TEST_PSK,
    "hidden": False,
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub wifi shared tests; install Node.js or set "
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


def _run_live_params(snapshot: dict[str, object], tmp_path: Path) -> dict[str, object]:
    script = f"""const mod = await import({json.dumps(LIVE_PARAMS_JS.as_uri())});
const snapshot = {json.dumps(snapshot, ensure_ascii=False)};
console.log(JSON.stringify(mod.buildLiveConnectionParams(snapshot)));
"""
    return _run_node_harness(script, tmp_path, "live-params")  # type: ignore[return-value]


def _run_needs_live(adapter_mode: str | None, tmp_path: Path) -> bool:
    script = f"""const mod = await import({json.dumps(LIVE_PARAMS_JS.as_uri())});
console.log(JSON.stringify(mod.needsLiveConnectionParamsForState({json.dumps(adapter_mode)})));
"""
    return _run_node_harness(script, tmp_path, "needs-live")  # type: ignore[return-value]


def _run_wifi_qr_string(payload: dict[str, object], tmp_path: Path) -> str:
    script = f"""const mod = await import({json.dumps(WIFI_QR_JS.as_uri())});
console.log(JSON.stringify(mod.buildWifiQrString({json.dumps(payload, ensure_ascii=False)})));
"""
    return _run_node_harness(script, tmp_path, "wifi-qr-string")  # type: ignore[return-value]


def _run_wifi_qr_matrix(data: str, tmp_path: Path) -> dict[str, object]:
    script = f"""const mod = await import({json.dumps(WIFI_QR_JS.as_uri())});
console.log(JSON.stringify(mod.buildWifiQrMatrix({json.dumps(data)})));
"""
    return _run_node_harness(script, tmp_path, "wifi-qr-matrix")  # type: ignore[return-value]


def _run_wifi_qr_matrix_expect_error(data: str, tmp_path: Path) -> str:
    script = f"""const mod = await import({json.dumps(WIFI_QR_JS.as_uri())});
try {{
  mod.buildWifiQrMatrix({json.dumps(data)});
  console.log(JSON.stringify({{ ok: true }}));
}} catch (error) {{
  console.log(JSON.stringify({{ ok: false, message: error.message }}));
}}
"""
    payload = _run_node_harness(script, tmp_path, "wifi-qr-matrix-error")
    assert payload["ok"] is False
    return str(payload["message"])


def _full_session() -> dict[str, object]:
    return {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "siteId": "site-1",
        "hostKeyConfirmed": True,
        "liveReady": True,
        "usernameAvailable": True,
        "connectionRestoreState": "done",
        "eventPresetId": None,
        "eventPresetName": None,
        "wifiLive": {
            "host": "10.0.0.1",
            "username": "admin",
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": REALISTIC_FINGERPRINT,
        },
        "wifiRoles": {
            "staffApId": "WifiMaster0/AccessPoint0",
            "guestApId": "WifiMaster0/AccessPoint3",
        },
        "sourceAddress": "192.168.2.144",
    }


def test_live_params_complete_from_filled_session(tmp_path: Path) -> None:
    """Полный набор полей из заполненной сессии."""
    result = _run_live_params(_full_session(), tmp_path)
    assert result["complete"] is True
    params = result["params"]
    assert params == {
        "host": "10.0.0.1",
        "username": "admin",
        "router_credential_ref_id": "cred-ref-1",
        "ssh_host_key_sha256": REALISTIC_FINGERPRINT,
        "source_address": "192.168.2.144",
        "router_id": "router-lab-1",
    }


def test_live_params_incomplete_when_fingerprint_missing(tmp_path: Path) -> None:
    """Отсутствие отпечатка при неподтверждённом пине → incomplete."""
    session = _full_session()
    session["hostKeyConfirmed"] = False  # type: ignore[index]
    session["liveReady"] = False  # type: ignore[index]
    session["wifiLive"] = dict(session["wifiLive"])  # type: ignore[arg-type]
    session["wifiLive"]["sshHostKeySha256"] = None  # type: ignore[index]
    result = _run_live_params(session, tmp_path)
    assert result["complete"] is False
    assert "ssh_host_key_sha256" in result["missing"]
    assert result["params"] == {}


def test_live_params_empty_strings_treated_as_missing(tmp_path: Path) -> None:
    """Пустые строки считаются отсутствующим значением."""
    session = _full_session()
    session["routerHost"] = "   "
    session["wifiLive"] = {
        "host": "   ",
        "username": "admin",
        "credentialRefId": "cred-ref-1",
        "sshHostKeySha256": REALISTIC_FINGERPRINT,
    }
    result = _run_live_params(session, tmp_path)
    assert result["complete"] is False
    assert "host" in result["missing"]
    assert result["params"] == {}


def test_needs_live_connection_params_by_adapter_mode(tmp_path: Path) -> None:
    """fake — без live params; live — нужны."""
    assert _run_needs_live("fake", tmp_path) is False
    assert _run_needs_live("live", tmp_path) is True
    assert _run_needs_live(None, tmp_path) is True


def test_wifi_qr_string_format_and_escaping(tmp_path: Path) -> None:
    """Строка WIFI:… с экранированием ; и \\ в имени сети."""
    result = _run_wifi_qr_string(
        {
            "security": "WPA2",
            "ssid": r"Lab;net\quote",
            "password": TEST_PSK,
            "hidden": False,
        },
        tmp_path,
    )
    assert result.startswith("WIFI:T:WPA;")
    assert r"S:Lab\;net\\quote;" in result
    assert f"P:{TEST_PSK};" in result
    assert result.endswith("H:false;;")


def test_wifi_qr_string_rejects_empty_password(tmp_path: Path) -> None:
    """Пустой пароль не допускается."""
    script = f"""const mod = await import({json.dumps(WIFI_QR_JS.as_uri())});
try {{
  mod.buildWifiQrString({{ security: 'WPA2', ssid: 'Lab', password: '' }});
  console.log(JSON.stringify({{ ok: true }}));
}} catch (error) {{
  console.log(JSON.stringify({{ ok: false, message: error.message }}));
}}
"""
    payload = _run_node_harness(script, tmp_path, "wifi-qr-no-pass")
    assert payload["ok"] is False


def _matrix_size(version: int) -> int:
    return version * 4 + 17


def _require_qrcode():
    try:
        import qrcode as qrcode_mod
        from qrcode.constants import ERROR_CORRECT_M
    except ImportError:
        if os.environ.get(QRCODE_SKIP_ENV) == "1":
            pytest.skip(f"qrcode library not installed ({QRCODE_SKIP_ENV}=1)")
        pytest.fail(
            f"qrcode library required for QR matrix reference tests; "
            f"set {QRCODE_SKIP_ENV}=1 to allow skip"
        )
    return qrcode_mod, ERROR_CORRECT_M


def _payload_for_qr(payload_dict: dict[str, object]) -> dict[str, object]:
    return {k: v for k, v in payload_dict.items() if k != "label"}


def _qrcode_min_version(data: str):
    qrcode_mod, error_correct_m = _require_qrcode()
    qr_auto = qrcode_mod.QRCode(
        version=None,
        error_correction=error_correct_m,
        box_size=1,
        border=0,
    )
    # optimize=0: наш wifi-qr.js кодирует только byte mode; без этого qrcode
    # выберет numeric-сегмент для длинных цифровых паролей и матрица не совпадёт.
    qr_auto.add_data(data, optimize=0)
    qr_auto.make(fit=True)
    return qr_auto.version


def _assert_wifi_qr_reference_contract(data: str, tmp_path: Path) -> dict[str, int]:
    """Сверка: наша версия = auto-fit эталона; матрица = эталон при нашей версии и маске."""
    qrcode_mod, error_correct_m = _require_qrcode()
    matrix_result = _run_wifi_qr_matrix(data, tmp_path)
    our_version = int(matrix_result["version"])
    our_mask = int(matrix_result["mask"])
    our_modules = matrix_result["modules"]

    min_version = _qrcode_min_version(data)
    assert our_version == min_version, (
        f"version mismatch: ours={our_version} required={min_version} "
        f"bytes={len(data.encode('utf-8'))} chars={len(data)}"
    )

    qr_fixed = qrcode_mod.QRCode(
        version=our_version,
        error_correction=error_correct_m,
        box_size=1,
        border=0,
        mask_pattern=our_mask,
    )
    qr_fixed.add_data(data, optimize=0)
    qr_fixed.make(fit=False)
    ref_modules = qr_fixed.get_matrix()
    assert len(ref_modules) == len(our_modules)
    for row in range(len(ref_modules)):
        assert ref_modules[row] == our_modules[row], (
            f"matrix row {row} differs for version={our_version} mask={our_mask}"
        )
    return {
        "our_version": our_version,
        "min_version": min_version,
        "bytes": len(data.encode("utf-8")),
        "chars": len(data),
    }


def test_wifi_qr_matrix_structure_and_roundtrip(tmp_path: Path) -> None:
    """Размер матрицы и эталонное совпадение с qrcode (не тавтологичный roundtrip)."""
    payload = _run_wifi_qr_string(
        {"security": "WPA3", "ssid": "LabNet", "password": TEST_PSK},
        tmp_path,
    )
    matrix_result = _run_wifi_qr_matrix(payload, tmp_path / "matrix")
    version = matrix_result["version"]
    modules = matrix_result["modules"]
    size = len(modules)
    assert size == _matrix_size(int(version))
    _assert_wifi_qr_reference_contract(payload, tmp_path / "ref")


@pytest.mark.parametrize("payload_dict", QR_REFERENCE_PAYLOADS)
def test_wifi_qr_matrix_matches_qrcode_library(
    payload_dict: dict[str, object], tmp_path: Path
) -> None:
    """ASCII: версия = auto-fit эталона; матрица совпадает при той же маске."""
    qr_string = _run_wifi_qr_string(_payload_for_qr(payload_dict), tmp_path / "string")
    _assert_wifi_qr_reference_contract(qr_string, tmp_path / "matrix")


@pytest.mark.parametrize("payload_dict", QR_ACCEPTANCE_PAYLOADS)
def test_wifi_qr_matrix_acceptance_cases(
    payload_dict: dict[str, object], tmp_path: Path
) -> None:
    """Приёмочные Unicode/UTF-8 кейсы: версия и матрица сверяются с qrcode."""
    qr_string = _run_wifi_qr_string(_payload_for_qr(payload_dict), tmp_path / "string")
    _assert_wifi_qr_reference_contract(qr_string, tmp_path / "matrix")


def test_wifi_qr_matrix_escaping_matches_qrcode_library(tmp_path: Path) -> None:
    """Экранирование ; и \\ в SSID: версия и матрица сверяются с qrcode."""
    qr_string = _run_wifi_qr_string(_payload_for_qr(QR_ESCAPING_PAYLOAD), tmp_path / "string")
    _assert_wifi_qr_reference_contract(qr_string, tmp_path / "matrix")


def test_wifi_qr_matrix_rejects_oversized_payload(tmp_path: Path) -> None:
    """Слишком длинные данные → ошибка, а не испорченный QR."""
    oversized = "WIFI:T:WPA;S:overflow;" + ("A" * 800) + ";P:pass;H:false;;"
    message = _run_wifi_qr_matrix_expect_error(oversized, tmp_path)
    assert "слишком длинные" in message.lower() or "too long" in message.lower()


def test_wifi_qr_no_secret_leaks_in_source() -> None:
    """Запрет утечек: нет createObjectURL, blob: и console.* в wifi-qr.js."""
    source = _read(WIFI_QR_JS)
    assert "createObjectURL" not in source
    assert "blob:" not in source
    assert "console.log" not in source
    assert "console.error" not in source
    assert "console.warn" not in source
    assert "console.debug" not in source


def test_session_wifi_roles_defaults_and_merge(tmp_path: Path) -> None:
    """wifiRoles в session: дефолт, merge и reset."""
    script = f"""const mod = await import({json.dumps(SESSION_JS.as_uri())});
mod.resetSession();
const initial = mod.getSession();
mod.updateSession({{ wifiRoles: {{ staffApId: 'WifiMaster0/AccessPoint0' }} }});
const merged = mod.getSession();
mod.updateSession({{ wifiRoles: {{ guestApId: 'WifiMaster0/AccessPoint3' }} }});
const both = mod.getSession();
mod.resetSession();
const cleared = mod.getSession();
console.log(JSON.stringify({{ initial, merged, both, cleared }}));
"""
    payload = _run_node_harness(script, tmp_path, "session-wifi-roles")
    assert payload["initial"]["wifiRoles"] == {"staffApId": None, "guestApId": None}
    assert payload["merged"]["wifiRoles"] == {
        "staffApId": "WifiMaster0/AccessPoint0",
        "guestApId": None,
    }
    assert payload["both"]["wifiRoles"] == {
        "staffApId": "WifiMaster0/AccessPoint0",
        "guestApId": "WifiMaster0/AccessPoint3",
    }
    assert payload["cleared"]["wifiRoles"] == {"staffApId": None, "guestApId": None}


def _restored_session_without_client_secrets() -> dict[str, object]:
    """Сессия после server-side restore: пин и username на сервере, не в вкладке."""
    return {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "siteId": "site-1",
        "hostKeyConfirmed": True,
        "liveReady": True,
        "usernameAvailable": True,
        "connectionRestoreState": "done",
        "eventPresetId": None,
        "eventPresetName": None,
        "wifiLive": {
            "host": "10.0.0.1",
            "username": None,
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": None,
        },
        "wifiRoles": {"staffApId": None, "guestApId": None},
        "sourceAddress": "192.168.2.144",
    }


def test_live_params_complete_with_server_resolvable_fields_only(tmp_path: Path) -> None:
    """router_id + client fields достаточны; username/pin резолвит сервер."""
    result = _run_live_params(_restored_session_without_client_secrets(), tmp_path)
    assert result["complete"] is True
    params = result["params"]
    assert params["host"] == "10.0.0.1"
    assert params["router_credential_ref_id"] == "cred-ref-1"
    assert params["router_id"] == "router-lab-1"
    assert params["source_address"] == "192.168.2.144"
    assert "username" not in params or params.get("username") is None
    assert "ssh_host_key_sha256" not in params or params.get("ssh_host_key_sha256") is None


def test_live_params_fail_closed_without_confirmed_pin_in_session(tmp_path: Path) -> None:
    """Без liveReady и без pin в сессии live params неполны (fail-closed)."""
    session = _restored_session_without_client_secrets()
    session["liveReady"] = False  # type: ignore[index]
    session["hostKeyConfirmed"] = False  # type: ignore[index]
    result = _run_live_params(session, tmp_path)
    assert result["complete"] is False
    assert "ssh_host_key_sha256" in result["missing"]
    assert result["params"] == {}


def test_live_params_incomplete_when_pin_confirmed_but_not_live_ready(tmp_path: Path) -> None:
    """F-4: подтверждённый пин без live_ready не даёт complete."""
    session = _restored_session_without_client_secrets()
    session["liveReady"] = False  # type: ignore[index]
    session["hostKeyConfirmed"] = True  # type: ignore[index]
    result = _run_live_params(session, tmp_path)
    assert result["complete"] is False
    assert "username" in result["missing"]
    assert result["params"] == {}


def test_live_params_incomplete_while_restore_pending(tmp_path: Path) -> None:
    """T-2: при liveReady=true pending всё равно блокирует live calls."""
    session = _full_session()
    session["connectionRestoreState"] = "pending"  # type: ignore[index]
    session["liveReady"] = True  # type: ignore[index]
    session["hostKeyConfirmed"] = True  # type: ignore[index]
    result = _run_live_params(session, tmp_path)
    assert result["complete"] is False
    assert "connection_restore_pending" in result["missing"]
    assert result["params"] == {}


def test_wifi_mutation_readiness_names_missing_source_address(tmp_path: Path) -> None:
    """H-2: пробел source_address показывается с русской меткой, не сырым ключом."""
    session = _full_session()
    session["liveReady"] = False  # type: ignore[index]
    session["hostKeyConfirmed"] = True  # type: ignore[index]
    session["sourceAddress"] = None  # type: ignore[index]
    script = f"""const mod = await import({json.dumps(WIFI_AP_MODEL_JS.as_uri())});
const sessionMod = await import({json.dumps(SESSION_JS.as_uri())});
sessionMod.resetSession();
sessionMod.updateSession({json.dumps(session, ensure_ascii=False)});
console.log(JSON.stringify(mod.evaluateWifiMutationReadiness(sessionMod.getSession(), 'live')));
"""
    result = _run_node_harness(script, tmp_path, "wifi-missing-source-label")
    assert result["allowed"] is False
    assert "локальный адрес этого компьютера" in result["missing"]
    assert "source_address" not in result["missing"]


def test_derive_wifi_preview_enabled_network_toggle_pending_false_returns_false(
    tmp_path: Path,
) -> None:
    """§4: networkTogglePending:false forces enabled:false (overview bug mode)."""
    script = f"""const mod = await import({json.dumps(WIFI_AP_MODEL_JS.as_uri())});
const result = mod.deriveWifiPreviewEnabled({{
  action: 'enable',
  observed: {{ readable: true, activeLabel: 'Выключена' }},
  networkTogglePending: false,
}});
console.log(JSON.stringify(result));
"""
    result = _run_node_harness(script, tmp_path, "derive-preview-toggle-false")
    assert result is False


STAFF_WIFI_SCREEN_JS = REPO_ROOT / "router_control_host" / "web" / "hub" / "screens" / "staff-wifi.js"
GUEST_WIFI_SCREEN_JS = REPO_ROOT / "router_control_host" / "web" / "hub" / "screens" / "guest-wifi.js"
WIFI_SCREEN_PARTS_JS = HUB / "features" / "wifi-screen-parts.js"


def _extract_function_body(source: str, signature: str) -> str | None:
    start = source.find(signature)
    if start < 0:
        return None
    brace = source.find("{", start)
    if brace < 0:
        return None
    depth = 0
    for index in range(brace, len(source)):
        char = source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace : index + 1]
    return None


@pytest.mark.parametrize(
    ("screen_path", "screen_label"),
    [
        (STAFF_WIFI_SCREEN_JS, "staff"),
        (GUEST_WIFI_SCREEN_JS, "guest"),
    ],
)
def test_wifi_screen_stable_ui_slot_pattern(screen_path: Path, screen_label: str) -> None:
    """F-WIFI-02: mountLayoutOnce + no contentWrap wipe; skeleton only on first load."""
    source = screen_path.read_text(encoding="utf-8")
    render_content = _extract_function_body(source, "function renderContent(")
    assert render_content is not None, f"{screen_label} renderContent missing"
    assert "mountLayoutOnce()" in render_content
    assert "clearElement(contentWrap)" not in render_content
    assert "function mountLayoutOnce(" in source
    assert "function rebuildSlot(" in source
    progress_body = _extract_function_body(source, "function renderProgressSlot(")
    assert progress_body is not None
    assert "loadingObserved && !observed" in progress_body
    assert "if (loadingObserved)" not in progress_body.replace("loadingObserved && !observed", "")
    load_body = _extract_function_body(source, "async function loadObservedFlow(")
    assert load_body is not None
    assert "observed = null" not in load_body.split("catch")[1].split("finally")[0]


def test_wifi_screen_parts_exports_signature_helpers() -> None:
    """Shared pure signature helpers exported for staff/guest slot gating."""
    source = WIFI_SCREEN_PARTS_JS.read_text(encoding="utf-8")
    for name in (
        "buildWifiSettingsFormSignature",
        "buildWifiNetworkHeaderSignature",
        "buildWifiApSelectSignature",
        "wifiFooterStructureSignature",
    ):
        assert f"export function {name}" in source


@pytest.mark.parametrize(
    ("screen_path", "screen_label"),
    [
        (STAFF_WIFI_SCREEN_JS, "staff"),
        (GUEST_WIFI_SCREEN_JS, "guest"),
    ],
)
def test_wifi_can_render_observed_form_ignores_soft_observed_error(
    screen_path: Path,
    screen_label: str,
) -> None:
    """F-3/F-3b: canRenderObservedForm не зависит от observedError при наличии observed."""
    source = screen_path.read_text(encoding="utf-8")
    can_render_body = _extract_function_body(source, "function canRenderObservedForm(")
    assert can_render_body is not None, f"{screen_label} canRenderObservedForm missing"
    assert "observedError" not in can_render_body
    progress_body = _extract_function_body(source, "function buildStaffProgressSignature(")
    if progress_body is None:
        progress_body = _extract_function_body(source, "function buildGuestProgressSignature(")
    assert progress_body is not None
    assert "observedError && !isAborted(observedError) && !observed" in progress_body
    extra_body = _extract_function_body(source, "function buildStaffExtraSignature(")
    if extra_body is None:
        extra_body = _extract_function_body(source, "function buildGuestExtraSignature(")
    assert extra_body is not None
    assert "observed-soft-fail" in extra_body


@pytest.mark.parametrize(
    ("screen_path", "screen_label"),
    [
        (STAFF_WIFI_SCREEN_JS, "staff"),
        (GUEST_WIFI_SCREEN_JS, "guest"),
    ],
)
def test_wifi_render_mutation_verdict_signature_gated(screen_path: Path, screen_label: str) -> None:
    """F-2: renderMutationVerdict пропускает remount при неизменной signature."""
    source = screen_path.read_text(encoding="utf-8")
    assert "lastVerdictSignature" in source
    assert "buildMutationVerdictSignature" in source
    verdict_body = _extract_function_body(source, "function renderMutationVerdict(")
    assert verdict_body is not None, f"{screen_label} renderMutationVerdict missing"
    assert "lastVerdictSignature" in verdict_body
    assert "signature === lastVerdictSignature" in verdict_body


@pytest.mark.parametrize(
    ("screen_path", "screen_label"),
    [
        (STAFF_WIFI_SCREEN_JS, "staff"),
        (GUEST_WIFI_SCREEN_JS, "guest"),
    ],
)
def test_wifi_network_header_signature_stabilized_during_mutation(
    screen_path: Path,
    screen_label: str,
) -> None:
    """F-9: network-header signature игнорирует label flips во время mutate/prepare."""
    source = screen_path.read_text(encoding="utf-8")
    header_sig_body = _extract_function_body(source, "function buildStaffNetworkHeaderSignature(")
    if header_sig_body is None:
        header_sig_body = _extract_function_body(source, "function buildGuestNetworkHeaderSignature(")
    assert header_sig_body is not None, f"{screen_label} network header signature missing"
    assert "stabilizeObservedLabels: preparingMutation || mutating" in header_sig_body
    parts_source = WIFI_SCREEN_PARTS_JS.read_text(encoding="utf-8")
    assert "stabilizeObservedLabels" in parts_source


def test_wifi_apply_teardown_timeout_keendns_parity() -> None:
    """apply/teardown client fetch timeoutMs >= 60000 (KeenDNS parity)."""
    source = WIFI_AP_MODEL_JS.read_text(encoding="utf-8")
    assert "WIFI_APPLY_TEARDOWN_TIMEOUT_MS" in source
    match = re.search(r"WIFI_APPLY_TEARDOWN_TIMEOUT_MS\s*=\s*(\d+)", source)
    assert match is not None
    assert int(match.group(1)) >= 60000
    apply_block = re.search(
        r"export async function applyWifiChanges\([\s\S]*?\n\}",
        source,
    )
    teardown_block = re.search(
        r"export async function teardownWifiNetwork\([\s\S]*?\n\}",
        source,
    )
    assert apply_block is not None
    assert teardown_block is not None
    assert "WIFI_APPLY_TEARDOWN_TIMEOUT_MS" in apply_block.group(0)
    assert "WIFI_APPLY_TEARDOWN_TIMEOUT_MS" in teardown_block.group(0)
    assert "wifi/apply" in apply_block.group(0)
    assert "wifi/teardown" in teardown_block.group(0)
