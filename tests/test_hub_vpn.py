"""Поведенческие контракты модели экрана «VPN» LOCAL HUB."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from router_control.adapters.netcraze.allowlist import validate_wireguard_id

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
VPN_MODEL_JS = HUB / "features" / "vpn-model.js"
WIREGUARD_SERVICE_PY = (
    REPO_ROOT / "router_control" / "application" / "wireguard_apply_service.py"
)

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"
SYNTHETIC_PRIVATE_KEY = "aGVsbG8tdGhpcy1pcy1ub3QtYS1yZWFsLWF3Zy1rZXktbWF0ZXJpYWw="
SYNTHETIC_PSK = "cHJlc2hhcmVkLWtleS1ub3QtcmVhbC1tYXRlcmlhbC1iNjQ="

CONSOLE_EMIT_RE = re.compile(
    r"console\.(log|info|debug|warn|error)\s*\(",
    re.IGNORECASE,
)
KEY_MATERIAL_RE = re.compile(
    r"(?:PrivateKey|PresharedKey|private[_-]?key|preshared[_-]?key)\s*[:=]",
    re.IGNORECASE,
)
TUNNEL_LITERAL_RE = re.compile(
    r'_TUNNEL_[A-Z_]+:\s*Literal\["(tunnel_[a-z_]+)"\]\s*=\s*"\1"',
)


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub vpn tests; install Node.js or set "
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
    model_source: str | None = None,
) -> object:
    if model_source is None:
        model_uri = VPN_MODEL_JS.as_uri()
    else:
        model_copy = tmp_path / f"{label}-vpn-model.mjs"
        model_copy.parent.mkdir(parents=True, exist_ok=True)
        model_copy.write_text(model_source, encoding="utf-8")
        model_uri = model_copy.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def _full_session() -> dict[str, object]:
    return {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "hostKeyConfirmed": True,
        "liveReady": True,
        "usernameAvailable": True,
        "connectionRestoreState": "done",
        "wifiLive": {
            "host": "10.0.0.1",
            "username": "admin",
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": REALISTIC_FINGERPRINT,
        },
        "sourceAddress": "192.168.2.144",
    }


def _expected_wireguard_ids_from_allowlist() -> list[str]:
    ids: list[str] = []
    for index in range(10):
        wg_id = f"Wireguard{index}"
        try:
            validate_wireguard_id(wg_id)
        except ValueError:
            continue
        ids.append(wg_id)
    return ids


def _python_tunnel_literals() -> list[str]:
    source = WIREGUARD_SERVICE_PY.read_text(encoding="utf-8")
    literals = TUNNEL_LITERAL_RE.findall(source)
    assert len(literals) == 4, f"expected 4 tunnel literals, got {literals}"
    return sorted(set(literals))


@pytest.mark.parametrize(
    ("status", "expected_message_fragment", "expected_hub_state"),
    [
        ("tunnel_unverified", "не сообщил нужных данных", "WARNING"),
        ("tunnel_no_peer", "не настроен сервер VPN", "WARNING"),
        ("tunnel_never_handshaked", "Ответа от сервера VPN нет", "WARNING"),
        ("tunnel_healthy", "рукопожатие есть", "WARNING"),
        (None, "не проверялась", "EMPTY"),
        ("unknown_status", "не проверялась", "EMPTY"),
    ],
)
def test_vpn_describe_tunnel_status_never_success(
    tmp_path: Path,
    status: str | None,
    expected_message_fragment: str,
    expected_hub_state: str,
) -> None:
    """Все вердикты туннеля — без HubState.SUCCESS."""
    status_json = "null" if status is None else json.dumps(status)
    result = _run_export(
        tmp_path,
        label="tunnel-status",
        script_body=f"""
console.log(JSON.stringify(mod.describeTunnelStatus({status_json})));
""",
    )
    assert result["hubState"] == expected_hub_state
    assert result["hubState"] != "SUCCESS"
    assert expected_message_fragment.lower() in result["message"].lower()


def test_vpn_parse_tunnel_verdict_applied_but_never_handshaked(tmp_path: Path) -> None:
    """applied + never_handshaked: конфигурация принята, туннель без ответа."""
    response = {
        "overall": "applied",
        "configuration_verification_status": "device_accepted_configuration",
        "interface_verification_status": "interface_present_up",
        "tunnel_verification_status": "tunnel_never_handshaked",
        "verdict_explanation": {"signals_missing": [], "signals_rejected": []},
    }
    result = _run_export(
        tmp_path,
        label="parse-verdict",
        script_body=f"""
console.log(JSON.stringify(mod.parseTunnelVerdict({json.dumps(response, ensure_ascii=False)})));
""",
    )
    assert "приняты роутером" in result["configuration"]["message"]
    assert "Ответа от сервера VPN нет" in result["tunnel"]["message"]
    assert result["trafficRouting"]["hubState"] == "WARNING"
    assert result["healthy"] is False
    assert result["configuration"]["hubState"] != "SUCCESS"
    assert result["tunnel"]["hubState"] != "SUCCESS"


def test_vpn_describe_rejected_signals_all_six_reasons(tmp_path: Path) -> None:
    """describeRejectedSignals покрывает все шесть обманчивых причин."""
    verdict = {
        "signals_rejected": [
            {"signal": "interface_state", "reason": "interface_state_not_evidence"},
            {"signal": "interface_up", "reason": "interface_up_not_evidence"},
            {"signal": "link", "reason": "link_not_evidence"},
            {"signal": "connected", "reason": "connected_not_evidence"},
            {"signal": "peer_enabled", "reason": "peer_enabled_not_evidence"},
            {"signal": "peer_txbytes", "reason": "peer_txbytes_alone_not_evidence"},
        ],
    }
    result = _run_export(
        tmp_path,
        label="rejected-signals",
        script_body=f"""
console.log(JSON.stringify(mod.describeRejectedSignals({json.dumps(verdict, ensure_ascii=False)})));
""",
    )
    assert isinstance(result, list)
    assert len(result) == 6
    expected_lines = [
        "Поле состояния интерфейса (state) проигнорировано — оно не доказывает работу туннеля",
        "Признак «интерфейс включён» (up) проигнорирован — он не доказывает работу туннеля",
        "Признак связи канала (link) проигнорирован — он не доказывает работу туннеля",
        "Признак connected проигнорирован — он не доказывает работу туннеля",
        "Признак peer_enabled проигнорирован — он не доказывает работу туннеля",
        (
            "Исходящий трафик без входящего (txbytes) проигнорирован — "
            "сам по себе он не доказывает работу туннеля"
        ),
    ]
    assert result == expected_lines
    for line in result:
        lowered = line.lower()
        assert "работает" not in lowered


def test_vpn_build_wireguard_apply_body_fields(tmp_path: Path) -> None:
    """apply body: confirm_live_apply, handshake_settle_seconds, router_credential_ref_id."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="apply-body",
        script_body=f"""
const intent = mod.buildWireguardIntentBody({{
  wgId: 'Wireguard5',
  enabled: true,
  ascArgs: '1 2 3 4 5 6 7 8 9',
  privateKeyCredentialRefId: 'priv-ref-1',
}});
const apply = mod.buildWireguardApplyBody({{
  intentBody: intent,
  session: {json.dumps(session, ensure_ascii=False)},
}});
console.log(JSON.stringify(apply));
""",
    )
    assert result["confirm_live_apply"] is True
    assert result["handshake_settle_seconds"] == 25
    assert result["router_credential_ref_id"] == "cred-ref-1"
    assert "credential_ref_id" not in result or result.get("credential_ref_id") is None
    assert "port" not in result
    assert result["wg_id"] == "Wireguard5"


def test_vpn_build_wireguard_observe_body_minimal(tmp_path: Path) -> None:
    """observe: без confirm_*, enabled, handshake_settle_seconds."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="observe-body",
        script_body=f"""
const observe = mod.buildWireguardObserveBody({{
  wgId: 'Wireguard5',
  session: {json.dumps(session, ensure_ascii=False)},
}});
console.log(JSON.stringify(observe));
""",
    )
    observe_keys = set(result.keys())
    assert "confirm_live_apply" not in observe_keys
    assert "confirm_live_teardown" not in observe_keys
    assert "enabled" not in observe_keys
    assert "handshake_settle_seconds" not in observe_keys
    assert result["wg_id"] == "Wireguard5"
    assert result["router_credential_ref_id"] == "cred-ref-1"


@pytest.mark.parametrize(
    ("status", "expected_checked"),
    [
        ("tunnel_healthy", True),
        ("tunnel_never_handshaked", False),
        ("tunnel_no_peer", False),
        ("tunnel_unverified", False),
        (None, False),
    ],
)
def test_vpn_screen_state_tunnel_indicator_only_when_healthy(
    tmp_path: Path,
    status: str | None,
    expected_checked: bool,
) -> None:
    """tunnelStatusIndicatorOn true только при tunnel_healthy."""
    status_json = "null" if status is None else json.dumps(status)
    result = _run_export(
        tmp_path,
        label="screen-state",
        script_body=f"""
console.log(JSON.stringify(mod.buildVpnScreenState({{
  lastTunnelVerificationStatus: {status_json},
  mutationReadiness: {{ allowed: true, reasonText: null, missing: [], mock: false }},
  hasPreparedIntent: true,
}})));
""",
    )
    assert result["tunnelStatusIndicatorOn"] is expected_checked


def test_vpn_summarize_parsed_profile_no_key_material(tmp_path: Path) -> None:
    """summarizeParsedProfile: реальные role, без ключевого материала в operatorLines."""
    parse_response = {
        "interface_field_names": ["PrivateKey", "Address"],
        "peer_field_names": ["PublicKey", "Endpoint"],
        "credential_refs": [
            {
                "role": "PrivateKey",
                "credential_ref_id": "vault-ref-abc",
                "kind": "awg_private_key",
            },
            {
                "role": "PresharedKey",
                "credential_ref_id": "vault-ref-psk",
                "kind": "awg_preshared_key",
            },
        ],
        "endpoint_configured": True,
        "interface_address_present": False,
        "awg_param_names": ["Jc", "Jmin"],
        "profile_digest": "sha256:abc123",
    }
    parse_json = json.dumps(parse_response, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="summarize-profile",
        script_body=f"""
console.log(JSON.stringify(mod.summarizeParsedProfile({parse_json})));
""",
    )
    operator_joined = "\n".join(result["operatorLines"])
    technical_joined = "\n".join(result["technicalLines"])
    assert SYNTHETIC_PRIVATE_KEY not in operator_joined
    assert SYNTHETIC_PSK not in operator_joined
    assert not KEY_MATERIAL_RE.search(operator_joined)
    assert "vault-ref-abc" in technical_joined
    assert "PrivateKey" in technical_joined
    assert "Приватный ключ" in operator_joined


def test_vpn_evaluate_mutation_readiness_blocks_fake_mode(tmp_path: Path) -> None:
    """В fake-режиме мутации VPN заблокированы."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="mutation-readiness",
        script_body=f"""
console.log(JSON.stringify(mod.evaluateVpnMutationReadiness(
  {json.dumps(session, ensure_ascii=False)},
  'fake',
)));
""",
    )
    assert result["allowed"] is False
    assert result["mock"] is True
    assert "демонстрацион" in result["reasonText"].lower()


def test_vpn_model_syntax_via_mjs_copy(tmp_path: Path) -> None:
    """Синтаксис vpn-model.js проверяется копией .mjs."""
    node = _require_node()
    mjs_copy = tmp_path / "vpn-model.mjs"
    mjs_copy.write_text(VPN_MODEL_JS.read_text(encoding="utf-8"), encoding="utf-8")
    proc = subprocess.run(
        [node, "--check", str(mjs_copy)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout


def test_vpn_model_source_honesty_guards() -> None:
    """Источник модели: без SUCCESS, storage, innerHTML, console."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    assert "HubState.SUCCESS" not in source
    assert "localStorage" not in source
    assert "sessionStorage" not in source
    assert "indexedDB" not in source
    assert "document.cookie" not in source
    assert "innerHTML" not in source
    assert not CONSOLE_EMIT_RE.search(source)


def test_vpn_tunnel_interface_options_match_allowlist(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """UI list mirrors Wireguard5–9; narrower than expendable allowlist Wireguard0–9."""
    monkeypatch.setenv("ROUTER_CONTROL_LAB_CLASS", "expendable_development_router")
    result = _run_export(
        tmp_path,
        label="tunnel-options",
        script_body="""
console.log(JSON.stringify(mod.listVpnTunnelInterfaceOptions().map((item) => item.wgId)));
""",
    )
    js_set = set(result)
    assert {"Wireguard5", "Wireguard6", "Wireguard7", "Wireguard8", "Wireguard9"} == js_set
    assert len(result) == 5


def test_vpn_tunnel_literals_match_python_service() -> None:
    """Четыре tunnel_verification_status совпадают с wireguard_apply_service.py (обе стороны)."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    js_literals = set(re.findall(r"['\"](tunnel_[a-z_]+)['\"]", source))
    js_tunnel_literals = {literal for literal in js_literals if literal.startswith("tunnel_")}
    python_literals = set(_python_tunnel_literals())
    assert js_tunnel_literals == python_literals
    assert len(python_literals) == 4


def test_vpn_apply_teardown_timeout_covers_settle_plus_margin(tmp_path: Path) -> None:
    """apply/teardown timeoutMs >= (settleSeconds + 45) * 1000."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    assert "VPN_APPLY_TEARDOWN_TIMEOUT_MS" in source
    assert "VPN_HANDSHAKE_SETTLE_SECONDS" in source
    result = _run_export(
        tmp_path,
        label="timeout-invariant",
        script_body="""
const timeoutMs = mod.VPN_APPLY_TEARDOWN_TIMEOUT_MS;
const settleSeconds = mod.VPN_HANDSHAKE_SETTLE_SECONDS;
console.log(JSON.stringify({
  ok: timeoutMs >= (settleSeconds + 45) * 1000,
  timeoutMs,
  settleSeconds,
}));
""",
    )
    assert result["ok"] is True
    apply_block = re.search(
        r"export function applyVpnTunnel\([\s\S]*?\n\}",
        source,
    )
    teardown_block = re.search(
        r"export function teardownVpnTunnel\([\s\S]*?\n\}",
        source,
    )
    assert apply_block is not None
    assert teardown_block is not None
    assert "VPN_APPLY_TEARDOWN_TIMEOUT_MS" in apply_block.group(0)
    assert "VPN_APPLY_TEARDOWN_TIMEOUT_MS" in teardown_block.group(0)
    assert "wireguard/apply" in apply_block.group(0)
    assert "wireguard/teardown" in teardown_block.group(0)


def test_vpn_three_status_line_constants_exact_wording(tmp_path: Path) -> None:
    """Три строки статуса и ожидание рукопожатия — точные формулировки плана §3/§4."""
    result = _run_export(
        tmp_path,
        label="status-line-messages",
        script_body="""
console.log(JSON.stringify({
  tunnelHealthy: mod.describeTunnelStatus('tunnel_healthy').message,
  trafficRouting: mod.describeTrafficRouting().message,
  handshakeWait: mod.VPN_HANDSHAKE_WAIT_MESSAGE,
}));
""",
    )
    assert (
        result["tunnelHealthy"]
        == "Сервер VPN отвечает: рукопожатие есть, данные от сервера приходят. "
        + "Это не означает, что трафик устройств идёт через VPN"
    )
    assert (
        result["trafficRouting"]
        == "Если VPN отключится, трафик может пойти в обход него — без предупреждения "
        + "и без автоматической защиты. Если заметили обрыв, нажмите «Переподключить»."
    )
    assert (
        result["handshakeWait"]
        == "Договариваемся с сервером VPN. Это занимает 20–30 секунд — не закрывайте экран"
    )


def test_vpn_one_tap_activate_body_includes_default_priority() -> None:
    """One-tap activate helper defaults ipGlobalPriority to sealed hub constant."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    assert "export const VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT = 900" in source
    activate_block = re.search(
        r"export function activateVpnProfile\([\s\S]*?\n\}",
        source,
    )
    assert activate_block is not None
    assert "ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT" in activate_block.group(0)
    assert "if (ipGlobalPriority != null) body.ip_global_priority = ipGlobalPriority;" in source


def test_vpn_import_body_includes_default_priority() -> None:
    """Catalog import helper defaults ipGlobalPriority to sealed hub constant."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    import_block = re.search(
        r"export function importVpnProfileToCatalog\([\s\S]*?\n\}",
        source,
    )
    assert import_block is not None
    assert "ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT" in import_block.group(0)


def test_vpn_activate_omits_priority_when_explicit_null() -> None:
    """Explicit ipGlobalPriority: null omits field from activate body (AC-8 hub opt-out)."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    assert "if (ipGlobalPriority != null) body.ip_global_priority = ipGlobalPriority;" in source


def test_vpn_build_intent_body_defaults_priority_in_source() -> None:
    """buildWireguardIntentBody defaults ipGlobalPriority to sealed hub constant."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    intent_block = re.search(
        r"export function buildWireguardIntentBody\([\s\S]*?\n\}",
        source,
    )
    assert intent_block is not None
    assert "ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT" in intent_block.group(0)


def test_vpn_build_intent_body_includes_default_priority(tmp_path: Path) -> None:
    """buildWireguardIntentBody defaults ip_global_priority for apply/reconnect/teardown paths."""
    result = _run_export(
        tmp_path,
        label="intent-priority",
        script_body="""
const enabled = mod.buildWireguardIntentBody({ wgId: 'Wireguard5', enabled: true });
const disabled = mod.buildWireguardIntentBody({ wgId: 'Wireguard5', enabled: false });
const optOut = mod.buildWireguardIntentBody({
  wgId: 'Wireguard5',
  enabled: true,
  ipGlobalPriority: null,
});
console.log(JSON.stringify({
  enabledPriority: enabled.ip_global_priority,
  disabledPriority: disabled.ip_global_priority,
  optOutHasPriority: Object.prototype.hasOwnProperty.call(optOut, 'ip_global_priority'),
}));
""",
    )
    assert result["enabledPriority"] == 900
    assert result["disabledPriority"] == 900
    assert result["optOutHasPriority"] is False


def test_vpn_build_intent_from_parse_preview_includes_default_priority(tmp_path: Path) -> None:
    """buildWireguardIntentFromParsePreview inherits sealed priority for activate and teardown."""
    parse_response = {
        "credential_refs": [
            {
                "role": "PrivateKey",
                "credential_ref_id": "priv-vault-ref-1",
                "kind": "awg_private_key",
            },
        ],
        "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    }
    result = _run_export(
        tmp_path,
        label="intent-parse-priority",
        script_body=f"""
const parseResponse = {json.dumps(parse_response, ensure_ascii=False)};
const activate = mod.buildWireguardIntentFromParsePreview(parseResponse, 'Wireguard5', true);
const teardown = mod.buildWireguardIntentFromParsePreview(parseResponse, 'Wireguard5', false);
console.log(JSON.stringify({{
  activatePriority: activate.ip_global_priority,
  teardownPriority: teardown.ip_global_priority,
}}));
""",
    )
    assert result["activatePriority"] == 900
    assert result["teardownPriority"] == 900


def test_vpn_apply_body_no_handshake_when_disabled(tmp_path: Path) -> None:
    """handshake_settle_seconds только при enabled=true."""
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="apply-disabled",
        script_body=f"""
const intent = mod.buildWireguardIntentBody({{ wgId: 'Wireguard5', enabled: false }});
const apply = mod.buildWireguardApplyBody({{
  intentBody: intent,
  session: {json.dumps(session, ensure_ascii=False)},
}});
console.log(JSON.stringify(apply));
""",
    )
    assert "handshake_settle_seconds" not in result


def test_vpn_build_intent_from_parse_preview_real_roles(tmp_path: Path) -> None:
    """parse-preview с PrivateKey/PresharedKey → credential_ref_id в intent/apply body."""
    parse_response = {
        "credential_refs": [
            {
                "role": "PrivateKey",
                "credential_ref_id": "priv-vault-ref-1",
                "kind": "awg_private_key",
            },
            {
                "role": "PresharedKey",
                "credential_ref_id": "psk-vault-ref-2",
                "kind": "awg_preshared_key",
            },
        ],
        "asc9_args": [1, 2, 3],
    }
    session = _full_session()
    result = _run_export(
        tmp_path,
        label="intent-from-parse",
        script_body=f"""
const parseResponse = {json.dumps(parse_response, ensure_ascii=False)};
const intent = mod.buildWireguardIntentFromParsePreview(parseResponse, 'Wireguard5', true);
const apply = mod.buildWireguardApplyBody({{
  intentBody: intent,
  session: {json.dumps(session, ensure_ascii=False)},
}});
console.log(JSON.stringify({{
  private_key_credential_ref_id: intent.private_key_credential_ref_id,
  preshared_key_credential_ref_id: intent.preshared_key_credential_ref_id,
  applyPrivate: apply.private_key_credential_ref_id,
  applyPsk: apply.preshared_key_credential_ref_id,
}}));
""",
    )
    assert result["private_key_credential_ref_id"] == "priv-vault-ref-1"
    assert result["preshared_key_credential_ref_id"] == "psk-vault-ref-2"
    assert result["applyPrivate"] == "priv-vault-ref-1"
    assert result["applyPsk"] == "psk-vault-ref-2"


def test_vpn_configuration_outcome_no_english_in_operator_message(tmp_path: Path) -> None:
    """describeConfigurationOutcome: snake_case только в technicalLines."""
    response = {
        "overall": "applied",
        "configuration_verification_status": "configuration_mismatch",
        "interface_verification_status": "interface_missing",
    }
    result = _run_export(
        tmp_path,
        label="config-outcome",
        script_body=f"""
const response = {json.dumps(response, ensure_ascii=False)};
console.log(JSON.stringify({{
  message: mod.describeConfigurationOutcome(response).message,
  technical: mod.describeConfigurationTechnicalLines(response),
}}));
""",
    )
    assert "configuration_verification_status" not in result["message"]
    assert "interface_verification_status" not in result["message"]
    assert "приняты роутером" not in result["message"]
    assert "не подтвердила" in result["message"]
    assert any("configuration_verification_status" in line for line in result["technical"])


def test_vpn_configuration_outcome_applied_clean_when_verified(tmp_path: Path) -> None:
    """applied + backend verification statuses → чистое принятие."""
    response = {
        "overall": "applied",
        "configuration_verification_status": "device_accepted_configuration",
        "interface_verification_status": "interface_present_up",
    }
    response_json = json.dumps(response, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="config-outcome-verified",
        script_body=f"""
console.log(JSON.stringify(mod.describeConfigurationOutcome({response_json}).message));
""",
    )
    assert result == "Настройки туннеля приняты роутером"


def test_vpn_configuration_outcome_applied_clean_when_present_down(tmp_path: Path) -> None:
    """applied + interface_present_down (disable) → чистое принятие."""
    response = {
        "overall": "applied",
        "configuration_verification_status": "device_accepted_configuration",
        "interface_verification_status": "interface_present_down",
    }
    response_json = json.dumps(response, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="config-outcome-present-down",
        script_body=f"""
console.log(JSON.stringify(mod.describeConfigurationOutcome({response_json}).message));
""",
    )
    assert result == "Настройки туннеля приняты роутером"


def test_vpn_configuration_outcome_applied_clean_when_interface_absent(tmp_path: Path) -> None:
    """applied + interface_absent (teardown) → чистое принятие."""
    response = {
        "overall": "applied",
        "configuration_verification_status": "device_accepted_configuration",
        "interface_verification_status": "interface_absent",
    }
    response_json = json.dumps(response, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label="config-outcome-interface-absent",
        script_body=f"""
console.log(JSON.stringify(mod.describeConfigurationOutcome({response_json}).message));
""",
    )
    assert result == "Настройки туннеля приняты роутером"


def test_vpn_configuration_outcome_applied_warns_when_verification_missing(tmp_path: Path) -> None:
    """applied без verification statuses → fail-closed warning, не «приняты»."""
    for label, response in [
        (
            "both_missing",
            {"overall": "applied"},
        ),
        (
            "configuration_missing",
            {
                "overall": "applied",
                "interface_verification_status": "interface_present_up",
            },
        ),
        (
            "interface_missing",
            {
                "overall": "applied",
                "configuration_verification_status": "device_accepted_configuration",
            },
        ),
    ]:
        response_json = json.dumps(response, ensure_ascii=False)
        result = _run_export(
            tmp_path,
            label=f"config-outcome-missing-{label}",
            script_body=f"""
console.log(JSON.stringify(mod.describeConfigurationOutcome({response_json}).message));
""",
        )
        assert "не подтвердила" in result
        assert "приняты роутером" not in result


def test_vpn_build_intent_from_parse_preview_includes_peer_fields(tmp_path: Path) -> None:
    """parse-preview peer_public_key/endpoint/allow_ips попадают в intent body."""
    parse_response = {
        "credential_refs": [
            {
                "role": "PrivateKey",
                "credential_ref_id": "priv-vault-ref-1",
                "kind": "awg_private_key",
            },
        ],
        "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        "peer_endpoint": "vpn.example.com:51820",
        "peer_allow_ips": "0.0.0.0/0",
    }
    result = _run_export(
        tmp_path,
        label="intent-peer-fields",
        script_body=f"""
const parseResponse = {json.dumps(parse_response, ensure_ascii=False)};
const intent = mod.buildWireguardIntentFromParsePreview(parseResponse, 'Wireguard5', true);
console.log(JSON.stringify({{
  peer_public_key: intent.peer_public_key,
  peer_endpoint: intent.peer_endpoint,
  peer_allow_ips: intent.peer_allow_ips,
}}));
""",
    )
    assert result["peer_public_key"] == "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
    assert result["peer_endpoint"] == "vpn.example.com:51820"
    assert result["peer_allow_ips"] == "0.0.0.0/0"


def test_vpn_prepared_parse_connect_readiness_missing_peer(tmp_path: Path) -> None:
    """Без peer_public_key connectReady=false с явной причиной."""
    parse_response = {
        "credential_refs": [
            {
                "role": "PrivateKey",
                "credential_ref_id": "priv-vault-ref-1",
                "kind": "awg_private_key",
            },
        ],
    }
    result = _run_export(
        tmp_path,
        label="parse-readiness-missing-peer",
        script_body=f"""
const parseResponse = {json.dumps(parse_response, ensure_ascii=False)};
console.log(JSON.stringify(mod.evaluatePreparedParseConnectReadiness(parseResponse)));
""",
    )
    assert result["connectReady"] is False
    assert result["reasonText"] == "В конфигурации нет данных сервера VPN — подключение недоступно"


def test_vpn_prepared_parse_connect_readiness_unrecognized_role(tmp_path: Path) -> None:
    """Нераспознанная роль credential ref блокирует connect."""
    parse_response = {
        "credential_refs": [
            {
                "role": "MysteryKey",
                "credential_ref_id": "mystery-ref-1",
                "kind": "awg_private_key",
            },
            {
                "role": "PrivateKey",
                "credential_ref_id": "priv-vault-ref-1",
                "kind": "awg_private_key",
            },
        ],
        "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
    }
    result = _run_export(
        tmp_path,
        label="parse-readiness-unknown-role",
        script_body=f"""
const parseResponse = {json.dumps(parse_response, ensure_ascii=False)};
console.log(JSON.stringify(mod.evaluatePreparedParseConnectReadiness(parseResponse)));
""",
    )
    assert result["connectReady"] is False
    assert (
        result["reasonText"]
        == "Профиль содержит ключ с нераспознанной ролью — подключение недоступно"
    )


def test_vpn_mutation_readiness_names_missing_source_address(tmp_path: Path) -> None:
    """H-2: пробел source_address в VPN readiness — именованная русская метка."""
    session = {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "hostKeyConfirmed": True,
        "liveReady": False,
        "usernameAvailable": True,
        "wifiLive": {
            "host": "10.0.0.1",
            "username": "admin",
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": REALISTIC_FINGERPRINT,
        },
        "sourceAddress": None,
    }
    result = _run_export(
        tmp_path,
        label="vpn-missing-source-label",
        script_body=f"""
const sessionMod = await import({json.dumps((HUB / "core" / "session.js").as_uri())});
sessionMod.resetSession();
sessionMod.updateSession({json.dumps(session, ensure_ascii=False)});
console.log(JSON.stringify(mod.evaluateVpnMutationReadiness(sessionMod.getSession(), 'live')));
""",
    )
    assert result["allowed"] is False
    assert "локальный адрес этого компьютера" in result["missing"]
    assert "source_address" not in result["missing"]


@pytest.mark.parametrize(
    ("watchdog_enabled", "expected_fragment"),
    [
        (True, "включено в сервере управления"),
        (False, "выключено"),
        ("null", "неизвестно"),
    ],
)
def test_vpn_describe_auto_reconnect_note_watchdog(
    tmp_path: Path,
    watchdog_enabled: bool | str,
    expected_fragment: str,
) -> None:
    enabled_expr = "null" if watchdog_enabled == "null" else json.dumps(watchdog_enabled)
    assignment_expr = "true" if watchdog_enabled is True else "undefined"
    result = _run_export(
        tmp_path,
        label=f"auto-reconnect-{watchdog_enabled}",
        script_body=f"""
console.log(JSON.stringify(mod.describeVpnAutoReconnectNote({{
  watchdogEnabled: {enabled_expr},
  hasActiveAssignment: {assignment_expr},
}})));
""",
    )
    assert expected_fragment in result
    assert "проверено" not in result.lower()


def test_vpn_describe_auto_reconnect_note_enabled_unknown_assignment(
    tmp_path: Path,
) -> None:
    """Enabled watchdog with unloaded catalog must not claim reconnect or no assignment."""
    result = _run_export(
        tmp_path,
        label="vpn-auto-reconnect-unknown-assignment",
        script_body="""
console.log(JSON.stringify(mod.describeVpnAutoReconnectNote({
  watchdogEnabled: true,
  hasActiveAssignment: null,
})));
""",
    )
    assert "ещё не загружено" in result
    assert "неизвестно" in result
    assert "активного назначения профиля нет" not in result
    assert "повтор при сбое без ручного подтверждения" not in result


def test_vpn_describe_auto_reconnect_note_enabled_without_active_assignment(
    tmp_path: Path,
) -> None:
    """Enabled watchdog without active profile assignment must not claim auto-reconnect."""
    result = _run_export(
        tmp_path,
        label="vpn-auto-reconnect-no-assignment",
        script_body="""
console.log(JSON.stringify(mod.describeVpnAutoReconnectNote({
  watchdogEnabled: true,
  hasActiveAssignment: false,
})));
""",
    )
    assert "активного назначения профиля нет" in result
    assert "пока профиль не подключён или не назначен" in result.lower()
    assert "повтор при сбое без ручного подтверждения" not in result


def test_vpn_describe_auto_reconnect_note_enabled_with_active_assignment(
    tmp_path: Path,
) -> None:
    """Enabled watchdog with active assignment keeps reconnect-enabled copy."""
    result = _run_export(
        tmp_path,
        label="vpn-auto-reconnect-active-assignment",
        script_body="""
console.log(JSON.stringify(mod.describeVpnAutoReconnectNote({
  watchdogEnabled: true,
  hasActiveAssignment: true,
})));
""",
    )
    assert "повтор при сбое без ручного подтверждения" in result
    assert "работа на роутере не подтверждена" in result


@pytest.mark.parametrize(
    ("item", "expected_label"),
    [
        ({"is_active": False}, "Не подключён"),
        (
            {
                "is_active": True,
                "assigned_wg_id": "Wireguard5",
                "tunnel_verification_status": "tunnel_healthy",
            },
            "Подключён",
        ),
        (
            {
                "is_active": True,
                "assigned_wg_id": "Wireguard6",
                "tunnel_verification_status": "tunnel_never_handshaked",
            },
            "Подключён",
        ),
    ],
)
def test_vpn_catalog_connection_badge(
    tmp_path: Path,
    item: dict[str, object],
    expected_label: str,
) -> None:
    result = _run_export(
        tmp_path,
        label="catalog-badge",
        script_body=f"""
console.log(JSON.stringify(mod.describeCatalogConnectionBadge({json.dumps(item, ensure_ascii=False)})));
""",
    )
    assert result["label"] == expected_label
    assert "Ответа от сервера VPN" not in result["label"]
    assert "рукопожатие" not in result["label"]


def test_vpn_tile_status_never_works_from_stored_snapshot(tmp_path: Path) -> None:
    """describeVpnProfileTileStatus: stored tunnel_verification_status alone → not works."""
    result = _run_export(
        tmp_path,
        label="tile-stored-only",
        script_body="""
console.log(JSON.stringify(mod.describeVpnProfileTileStatus({
  is_active: true,
  tunnel_verification_status: 'tunnel_healthy',
})));
""",
    )
    assert result["kind"] != "works"
    assert result["kind"] != "connected_routed"
    assert result["kind"] == "not_checked"


def test_vpn_tile_status_works_only_with_live_tunnel_healthy(tmp_path: Path) -> None:
    result = _run_export(
        tmp_path,
        label="tile-live-healthy",
        script_body="""
console.log(JSON.stringify({
  evidenceMissing: mod.describeVpnProfileTileStatus({
    is_active: true,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_healthy',
  }),
  routed: mod.describeVpnProfileTileStatus({
    is_active: true,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_healthy',
    routed_through_tunnel: true,
    routing_probe_status: 'ok',
  }),
  storedOnly: mod.describeVpnProfileTileStatus({
    is_active: true,
    tunnel_verification_status: 'tunnel_healthy',
  }),
  neverHandshaked: mod.describeVpnProfileTileStatus({
    is_active: true,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_never_handshaked',
  }),
  probeError: mod.describeVpnProfileTileStatus({
    is_active: true,
    live_probed: false,
    probe_error: 'нет интерфейса туннеля',
  }),
  checking: mod.describeVpnProfileTileStatus({ is_active: true, checking: true }),
}));
""",
    )
    assert result["evidenceMissing"]["kind"] == "connected_not_routed"
    assert result["evidenceMissing"]["tone"] == "warning"
    assert result["routed"]["kind"] == "connected_routed"
    assert result["routed"]["tone"] == "success"
    assert result["storedOnly"]["kind"] == "not_checked"
    assert result["neverHandshaked"]["kind"] == "not_working"
    assert result["probeError"]["kind"] == "check_failed"
    assert result["checking"]["kind"] == "checking"


def test_vpn_tile_status_routing_alone_cannot_promote_to_green(tmp_path: Path) -> None:
    """AC-3: routed_through_tunnel alone without tunnel_healthy must never be green."""
    result = _run_export(
        tmp_path,
        label="tile-and-gate",
        script_body="""
console.log(JSON.stringify(mod.describeVpnProfileTileStatus({
  is_active: true,
  live_probed: true,
  live_tunnel_verification_status: 'tunnel_never_handshaked',
  routed_through_tunnel: true,
  routing_probe_status: 'ok',
})));
""",
    )
    assert result["tone"] != "success"
    assert result["kind"] == "not_working"


def test_vpn_tile_status_never_hub_state_success(tmp_path: Path) -> None:
    result = _run_export(
        tmp_path,
        label="tile-no-success",
        script_body="""
const status = mod.describeVpnProfileTileStatus({
  is_active: true,
  live_probed: true,
  live_tunnel_verification_status: 'tunnel_healthy',
});
console.log(JSON.stringify({ tone: status.tone, label: status.label }));
""",
    )
    assert result["tone"] != "success"
    assert result["label"] == "Отвечает, не весь трафик"


def test_vpn_tile_status_routing_amber_submessages(tmp_path: Path) -> None:
    result = _run_export(
        tmp_path,
        label="tile-routing-amber",
        script_body="""
console.log(JSON.stringify({
  notRouted: mod.describeVpnProfileTileStatus({
    is_active: true,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_healthy',
    routed_through_tunnel: false,
    routing_probe_status: 'ok',
  }),
  checkFailed: mod.describeVpnProfileTileStatus({
    is_active: true,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_healthy',
    routed_through_tunnel: null,
    routing_probe_status: 'failed',
  }),
  notRoutedMsg: mod.VPN_TUNNEL_NOT_ROUTED_TILE_MESSAGE,
  checkFailedMsg: mod.VPN_TUNNEL_ROUTING_CHECK_FAILED_TILE_MESSAGE,
}));
""",
    )
    assert result["notRouted"]["tone"] == "warning"
    assert result["notRouted"]["detailMessage"] == result["notRoutedMsg"]
    assert result["checkFailed"]["tone"] == "warning"
    assert result["checkFailed"]["detailMessage"] == result["checkFailedMsg"]
    assert "другим путём" in result["notRouted"]["detailMessage"]
    assert "не удалось" in result["checkFailed"]["detailMessage"]


def test_vpn_tile_status_inactive_ignores_live_and_checking(tmp_path: Path) -> None:
    """Inactive profiles never show works/checking even with stale live cache."""
    result = _run_export(
        tmp_path,
        label="tile-inactive-live",
        script_body="""
console.log(JSON.stringify({
  healthy: mod.describeVpnProfileTileStatus({
    is_active: false,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_healthy',
  }),
  checking: mod.describeVpnProfileTileStatus({
    is_active: false,
    checking: true,
  }),
  neverHandshaked: mod.describeVpnProfileTileStatus({
    is_active: false,
    live_probed: true,
    live_tunnel_verification_status: 'tunnel_never_handshaked',
  }),
}));
""",
    )
    assert result["healthy"]["kind"] != "works"
    assert result["healthy"]["kind"] != "connected_routed"
    assert result["healthy"]["kind"] == "not_checked"
    assert result["checking"]["kind"] != "checking"
    assert result["checking"]["kind"] == "not_checked"
    assert result["neverHandshaked"]["kind"] == "not_checked"


def test_vpn_model_exports_progress_message_constants() -> None:
    """Прогресс-сообщения long ops экспортируются из vpn-model.js."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    for name in (
        "VPN_OBSERVE_PROGRESS_MESSAGE",
        "VPN_VALIDATE_PROGRESS_MESSAGE",
        "VPN_ACTIVATE_PROGRESS_MESSAGE",
        "VPN_DEACTIVATE_PROGRESS_MESSAGE",
        "VPN_TEARDOWN_PROGRESS_MESSAGE",
        "VPN_PREVIEW_PROGRESS_MESSAGE",
        "VPN_CATALOG_REFRESH_MESSAGE",
        "VPN_CATALOG_INITIAL_LOAD_MESSAGE",
    ):
        assert f"export const {name}" in source


def test_vpn_observe_progress_message_short_without_settle(tmp_path: Path) -> None:
    """Validate progress copy не переиспользует settle-секунды handshake."""
    result = _run_export(
        tmp_path,
        label="observe-progress-constant",
        script_body="""
console.log(JSON.stringify({
  observe: mod.VPN_OBSERVE_PROGRESS_MESSAGE,
  validate: mod.VPN_VALIDATE_PROGRESS_MESSAGE,
  handshake: mod.VPN_HANDSHAKE_WAIT_MESSAGE,
  settleSeconds: mod.VPN_HANDSHAKE_SETTLE_SECONDS,
}));
""",
    )
    assert result["observe"]
    assert result["validate"]
    assert str(result["settleSeconds"]) not in result["validate"]
    assert result["observe"] != result["handshake"]


DUALSTACK_IPV6_OPERATOR_NOTE = (
    "Маршруты IPv6 из профиля не применены. Туннель работает только по IPv4."
)


def test_vpn_summarize_parsed_profile_operator_notes_as_is(tmp_path: Path) -> None:
    """summarizeParsedProfile: backend operator_notes попадают в operatorLines без изменений."""
    parse_response = {
        "endpoint_configured": True,
        "interface_address_present": True,
        "operator_notes": [DUALSTACK_IPV6_OPERATOR_NOTE],
        "unsupported_fields": ["AllowedIPs"],
    }
    result = _run_export(
        tmp_path,
        label="summarize-operator-notes",
        script_body=f"""
console.log(JSON.stringify(mod.summarizeParsedProfile({json.dumps(parse_response, ensure_ascii=False)})));
""",
    )
    assert DUALSTACK_IPV6_OPERATOR_NOTE in result["operatorLines"]
    assert "unsupported_fields: AllowedIPs" in result["technicalLines"]
    assert not any("Параметры профиля без поддержки" in line for line in result["operatorLines"])


def test_vpn_summarize_parsed_profile_empty_notes_fields_add_nothing_extra(
    tmp_path: Path,
) -> None:
    """summarizeParsedProfile: пустые operator_notes/unsupported_fields не добавляют строк."""
    parse_response = {
        "endpoint_configured": True,
        "interface_address_present": True,
        "operator_notes": [],
        "unsupported_fields": [],
    }
    baseline = _run_export(
        tmp_path,
        label="summarize-baseline",
        script_body=f"""
console.log(JSON.stringify(mod.summarizeParsedProfile({json.dumps(parse_response, ensure_ascii=False)})));
""",
    )
    assert not any("unsupported_fields:" in line for line in baseline["technicalLines"])
    assert not any("без поддержки" in line for line in baseline["operatorLines"])

    absent = _run_export(
        tmp_path,
        label="summarize-absent",
        script_body="""
console.log(JSON.stringify(mod.summarizeParsedProfile({
  endpoint_configured: true,
  interface_address_present: true,
})));
""",
    )
    assert absent["technicalLines"] == baseline["technicalLines"]
    assert absent["operatorLines"] == baseline["operatorLines"]


def test_vpn_summarize_parsed_profile_unsupported_fields_only_calm_operator_line(
    tmp_path: Path,
) -> None:
    """summarizeParsedProfile: unsupported_fields без notes → calm operator + technical."""
    parse_response = {
        "endpoint_configured": True,
        "interface_address_present": True,
        "unsupported_fields": ["AllowedIPs", "DNS"],
    }
    result = _run_export(
        tmp_path,
        label="summarize-unsupported-only",
        script_body=f"""
console.log(JSON.stringify(mod.summarizeParsedProfile({json.dumps(parse_response, ensure_ascii=False)})));
""",
    )
    assert "unsupported_fields: AllowedIPs, DNS" in result["technicalLines"]
    assert any("AllowedIPs" in line and "DNS" in line for line in result["operatorLines"])
    assert not any("ошиб" in line.lower() for line in result["operatorLines"])


def test_vpn_describe_profile_keepalive_present_absent_unknown(tmp_path: Path) -> None:
    """describeVpnProfileKeepalive: present / absent / unknown без overclaim."""
    result = _run_export(
        tmp_path,
        label="keepalive-states",
        script_body="""
const presentIntent = mod.describeVpnProfileKeepalive({
  wireguard_intent_fields: { peer_keepalive_interval: 25 },
});
const presentMetadata = mod.describeVpnProfileKeepalive({
  metadata: { peer_keepalive_interval: 30 },
});
const absentNull = mod.describeVpnProfileKeepalive({
  metadata: { peer_keepalive_interval: null },
});
const absentMissing = mod.describeVpnProfileKeepalive({
  metadata: {},
  wireguard_intent_fields: {},
});
const unknown = mod.describeVpnProfileKeepalive(null);
console.log(JSON.stringify({
  presentIntent,
  presentMetadata,
  absentNull,
  absentMissing,
  unknown,
}));
""",
    )
    assert result["presentIntent"]["state"] == "present"
    assert result["presentIntent"]["seconds"] == 25
    assert "25" in result["presentIntent"]["label"]
    assert result["presentMetadata"]["state"] == "present"
    assert result["presentMetadata"]["seconds"] == 30
    assert result["absentNull"]["state"] == "absent"
    assert result["absentNull"]["label"] == "Автоподдержка соединения: не указана"
    assert result["absentMissing"]["state"] == "absent"
    assert result["unknown"]["state"] == "unknown"
    assert result["unknown"]["label"] is None


def test_vpn_extract_profile_operator_notes(tmp_path: Path) -> None:
    """extractVpnProfileOperatorNotes: только непустые строки из operator_notes."""
    result = _run_export(
        tmp_path,
        label="extract-operator-notes",
        script_body=f"""
console.log(JSON.stringify(mod.extractVpnProfileOperatorNotes({{
  operator_notes: [{json.dumps(DUALSTACK_IPV6_OPERATOR_NOTE, ensure_ascii=False)}, '', 42, null],
}})));
""",
    )
    assert result == [DUALSTACK_IPV6_OPERATOR_NOTE]


def test_vpn_model_remove_api_sends_confirm() -> None:
    """removeVpnProfileFromCatalog always sends confirm_catalog_remove: true."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    assert "export function removeVpnProfileFromCatalog" in source
    assert "confirm_catalog_remove: true" in source
    assert "vpn-profiles/${profileId}/remove" in source


def test_vpn_model_catalog_remove_constants(tmp_path: Path) -> None:
    """Operator copy constants for catalog remove are exported."""
    result = _run_export(
        tmp_path,
        label="catalog-remove-constants",
        script_body="""
console.log(JSON.stringify({
  button: mod.VPN_CATALOG_REMOVE_BUTTON_LABEL,
  title: mod.VPN_CATALOG_REMOVE_CONFIRM_TITLE,
  lead: mod.VPN_CATALOG_REMOVE_CONFIRM_LEAD,
  action: mod.VPN_CATALOG_REMOVE_CONFIRM_ACTION,
  cancel: mod.VPN_CATALOG_REMOVE_CANCEL,
  activeRefuse: mod.VPN_CATALOG_REMOVE_ACTIVE_REFUSE,
}));
""",
    )
    assert result["button"] == "Убрать"
    assert result["title"] == "Убрать профиль из списка?"
    assert "роутере ничего дополнительно не меняется" in result["lead"]
    assert result["action"] == "Убрать из списка"
    assert result["cancel"] == "Отмена"
    assert "Отключить" in result["activeRefuse"]


def test_vpn_tile_grid_remove_disabled_when_active() -> None:
    """Remove button disabled when is_active on tile item."""
    source = VPN_MODEL_JS.read_text(encoding="utf-8")
    assert "item.is_active === true" in source
    assert "tileActive" in source or "item.is_active === true" in source
    assert "VPN_CATALOG_REMOVE_BUTTON_LABEL" in source
    assert "variant: 'danger'" in source


@pytest.mark.parametrize(
    ("catalog_items", "profile_id", "expected"),
    [
        (
            [{"profile_id": "p1", "assigned_wg_id": "Wireguard6"}],
            "p1",
            "Wireguard6",
        ),
        (
            [{"profile_id": "p1", "wg_id": "Wireguard7"}],
            "p1",
            "Wireguard7",
        ),
        (
            [{"profile_id": "p1"}],
            "p1",
            None,
        ),
    ],
)
def test_resolve_vpn_profile_wg_id_priority(
    tmp_path: Path,
    catalog_items: list[dict[str, str]],
    profile_id: str,
    expected: str | None,
) -> None:
    """resolveVpnProfileWgId: assigned_wg_id → metadata wg_id; null when both absent."""
    items_json = json.dumps(catalog_items, ensure_ascii=False)
    result = _run_export(
        tmp_path,
        label=f"resolve-wg-{profile_id}-{expected}",
        script_body=f"""
const items = {items_json};
console.log(JSON.stringify(mod.resolveVpnProfileWgId(items, {json.dumps(profile_id)})));
""",
    )
    assert result == expected
