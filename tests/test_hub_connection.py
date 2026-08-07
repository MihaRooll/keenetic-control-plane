"""Структурные и поведенческие контракты модели экрана «Подключение» LOCAL HUB."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from _pytest.outcomes import Failed

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
CONNECTION_FLOW_JS = HUB / "features" / "connection-flow.js"
SESSION_JS = HUB / "core" / "session.js"
LIVE_PARAMS_JS = HUB / "features" / "live-connection-params.js"
SYSTEM_CHECK_JS = HUB / "features" / "system-check.js"
OPENAPI = REPO_ROOT / "docs" / "contracts" / "openapi-v0.json"

REAL_ROUTER_ID = "rtr_f17a7d35"
REAL_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

API_PREFIX = "/api/router-control/v1/"
API_CALL_RE = re.compile(
    r"api(?:Get|Post)\(\s*(?:'([^']+)'|`([^`]+)`|\"([^\"]+)\")",
)
POST_WITH_HEADERS_RE = re.compile(
    r"postWithHeaders\(\s*(?:'([^']+)'|`([^`]+)`|\"([^\"]+)\")",
)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")

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
)

DOM_STORAGE_PATTERNS = (
    r"\bdocument\b",
    r"\bwindow\b",
    r"\blocalStorage\b",
    r"\bsessionStorage\b",
    r"\bdocument\.cookie\b",
    r"\binnerHTML\b",
    r"\bconsole\.log\b",
    r"\bconsole\.error\b",
)

CONNECTION_USER_MESSAGES = (
    "Пароль на планшете не хранится",
    "только на сервере управления",
    "Полный обход всех устройств сети не выполняется",
    "Отпечаток устройства",
    "Подтвердите отпечаток устройства на шаге «Доступ»",
    "Демонстрационный режим",
    "Укажите адрес роутера",
    "Укажите имя пользователя",
    "Укажите пароль",
    "Система не проверяет качество локальной сети",
    "Система не проверяет наличие интернета",
    "Система не проверяет уровень сигнала",
    "Требуется дополнительная проверка",
)

GREEN_HEALTH_FACTS = {
    "reachable": True,
    "host_key_match": True,
    "tuple_match": True,
    "credentials_present": True,
    "evidence_fresh": True,
}

OPENAPI_TEMPLATE_SEGMENT_RE = re.compile(r"^\{[^}]+\}$")
FRONTEND_PARAM_SEGMENT_RE = re.compile(r"^\{param\}$")


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _require_node() -> str:
    """Node обязателен для поведенческих тестов, кроме явного opt-out через env."""
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub connection behavioral tests; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


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


def _extract_api_paths_from_connection_flow() -> set[str]:
    text = _read(CONNECTION_FLOW_JS)
    paths: set[str] = set()
    for pattern in (API_CALL_RE, POST_WITH_HEADERS_RE):
        for match in pattern.finditer(text):
            raw = next(group for group in match.groups() if group is not None)
            paths.add(_normalize_api_path(raw))
    return paths


def _green_health(**fact_overrides: object) -> dict[str, object]:
    facts = dict(GREEN_HEALTH_FACTS)
    facts.update(fact_overrides)
    return {
        "status": "green",
        "reason_code": "all_facts_healthy",
        "facts": facts,
    }


def _finish_gate_inputs_table() -> list[dict[str, object]]:
    return [
        {
            "id": "all_green_confirmed_live",
            "health": _green_health(),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "reachable_false",
            "health": _green_health(reachable=False),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "reachable_null",
            "health": _green_health(reachable=None),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "credentials_false",
            "health": _green_health(credentials_present=False),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "credentials_null",
            "health": _green_health(credentials_present=None),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "host_key_match_false",
            "health": _green_health(host_key_match=False),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "host_key_match_null",
            "health": _green_health(host_key_match=None),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "tuple_match_false",
            "health": _green_health(tuple_match=False),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "tuple_match_null",
            "health": _green_health(tuple_match=None),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "evidence_fresh_false",
            "health": _green_health(evidence_fresh=False),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "evidence_fresh_null",
            "health": _green_health(evidence_fresh=None),
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "host_key_not_confirmed",
            "health": _green_health(),
            "hostKeyConfirmed": False,
            "adapterMode": "live",
        },
        {
            "id": "red_status_live",
            "health": {
                "status": "red",
                "reason_code": "unreachable",
                "facts": {"reachable": False},
            },
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "health_null_live",
            "health": None,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "id": "fake_yellow_unconfirmed",
            "health": {"status": "yellow", "reason_code": "reachability_unknown", "facts": {}},
            "hostKeyConfirmed": False,
            "adapterMode": "fake",
        },
        {
            "id": "fake_red_unconfirmed",
            "health": {
                "status": "red",
                "reason_code": "unreachable",
                "facts": {"reachable": False},
            },
            "hostKeyConfirmed": False,
            "adapterMode": "fake",
        },
        {
            "id": "fake_health_null",
            "health": None,
            "hostKeyConfirmed": False,
            "adapterMode": "fake",
        },
        {
            "id": "red_status_only_blocker",
            "health": {
                "status": "red",
                "reason_code": "unreachable",
                "facts": dict(GREEN_HEALTH_FACTS),
            },
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
    ]


def _finish_gate_run_inputs(inputs: list[dict[str, object]]) -> list[dict[str, object]]:
    """Убирает поле id перед передачей в evaluateFinishGate."""
    return [{k: v for k, v in item.items() if k != "id"} for item in inputs]


def _index_finish_gate_results(
    inputs: list[dict[str, object]],
    results: list[dict[str, object | None]],
) -> dict[str, dict[str, object | None]]:
    return {
        str(item["id"]): result
        for item, result in zip(inputs, results, strict=True)
    }


def _write_connection_module_tree(root: Path, source: str) -> Path:
    features_dir = root / "features"
    core_dir = root / "core"
    features_dir.mkdir(parents=True, exist_ok=True)
    core_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("api.js", "errors.js", "states.js", "session.js"):
        shutil.copy(HUB / "core" / filename, core_dir / filename)
    shutil.copy(SYSTEM_CHECK_JS, features_dir / "system-check.js")
    module_path = features_dir / "connection-flow.js"
    module_path.write_text(source, encoding="utf-8")
    return module_path


def _mutate_finish_gate_only_false(source: str) -> tuple[str, bool]:
    """Ослабляет finish gate: null-факты больше не блокируют завершение."""
    marker = "    if (value !== true) {"
    if marker not in source:
        return source, False
    mutated = source.replace(marker, "    if (value === false) {", 1)
    return mutated, mutated != source


def _mutate_finish_gate_allow_unconfirmed(source: str) -> tuple[str, bool]:
    """Ослабляет finish gate: снимает требование подтверждения отпечатка."""
    old = "  if (hostKeyConfirmed !== true) {"
    if old not in source:
        return source, False
    mutated = source.replace(old, "  if (false && hostKeyConfirmed !== true) {", 1)
    return mutated, mutated != source


def _mutate_finish_gate_allow_red(source: str) -> tuple[str, bool]:
    """Ослабляет finish gate: красный status больше не блокирует завершение."""
    old = """  if (health.status === 'red') {
    return {
      allowed: false,"""
    new = """  if (health.status === 'red') {
    return {
      allowed: true,"""
    if old not in source:
        return source, False
    return source.replace(old, new, 1), True


def _mutate_finish_gate_allow_null_health(source: str) -> tuple[str, bool]:
    """Ослабляет finish gate: отсутствие health больше не блокирует завершение."""
    old = """  if (health == null) {
    return {
      allowed: false,"""
    new = """  if (health == null) {
    return {
      allowed: true,"""
    if old not in source:
        return source, False
    return source.replace(old, new, 1), True


def _mutate_finish_gate_fake_before_null(source: str) -> tuple[str, bool]:
    """Ослабляет finish gate: isFake проверяется до health==null."""
    fake_block = """  if (isFake) {
    return {
      allowed: true,
      reasonText: FAKE_FINISH_NOTE,
      mock: true,
    };
  }

"""
    null_marker = "  if (health == null) {"
    fake_pos = source.find("  if (isFake) {")
    null_pos = source.find(null_marker)
    if fake_pos == -1 or null_pos == -1 or fake_pos < null_pos:
        return source, False
    fake_end = source.find("\n\n  const facts", fake_pos)
    if fake_end == -1:
        fake_end = source.find("\n  const facts", fake_pos)
    if fake_end == -1:
        return source, False
    without_fake = source[:fake_pos] + source[fake_end + 1 :]
    insert_at = without_fake.find(null_marker)
    if insert_at == -1:
        return source, False
    mutated = without_fake[:insert_at] + fake_block + without_fake[insert_at:]
    return mutated, mutated != source


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


def _run_evaluate_finish_gate(
    inputs: list[dict[str, object]],
    module_path: Path,
    tmp_path: Path,
) -> list[dict[str, object | None]]:
    run_inputs = _finish_gate_run_inputs(inputs)
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const inputs = {json.dumps(run_inputs, ensure_ascii=False)};
const results = inputs.map((input) => mod.evaluateFinishGate(input));
console.log(JSON.stringify(results));
"""
    return _run_node_harness(script, tmp_path, "evaluate-finish-gate")


def _run_build_connection_checklist(
    health: dict[str, object] | None,
    module_path: Path,
    tmp_path: Path,
) -> list[dict[str, object]]:
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const checklist = mod.buildConnectionChecklist({json.dumps(health, ensure_ascii=False)});
console.log(JSON.stringify(checklist));
"""
    return _run_node_harness(script, tmp_path, "build-checklist")


def _run_describe_discovery(
    response: dict[str, object] | None,
    options: dict[str, object],
    module_path: Path,
    tmp_path: Path,
) -> dict[str, object]:
    response_json = json.dumps(response, ensure_ascii=False)
    options_json = json.dumps(options, ensure_ascii=False)
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const result = mod.describeDiscovery({response_json}, {options_json});
console.log(JSON.stringify(result));
"""
    return _run_node_harness(script, tmp_path, "describe-discovery")


def _run_group_discovery_candidates(
    raw_candidates: list[dict[str, object]],
    module_path: Path,
    tmp_path: Path,
) -> list[dict[str, object]]:
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const groups = mod.groupDiscoveryCandidates({json.dumps(raw_candidates, ensure_ascii=False)});
console.log(JSON.stringify(groups));
"""
    return _run_node_harness(script, tmp_path, "group-discovery")  # type: ignore[return-value]


def _run_resolve_group_endpoint(
    group: dict[str, object],
    selected_port: object,
    module_path: Path,
    tmp_path: Path,
) -> dict[str, object | None]:
    port_json = json.dumps(selected_port)
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const endpoint = mod.resolveGroupEndpoint({json.dumps(group, ensure_ascii=False)}, {port_json});
console.log(JSON.stringify(endpoint));
"""
    return _run_node_harness(script, tmp_path, "resolve-group-endpoint")  # type: ignore[return-value]


def _run_describe_candidate(
    candidate: dict[str, object],
    module_path: Path,
    tmp_path: Path,
) -> dict[str, object]:
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const result = mod.describeCandidate({json.dumps(candidate, ensure_ascii=False)});
console.log(JSON.stringify(result));
"""
    return _run_node_harness(script, tmp_path, "describe-candidate")


def _run_idempotency_header_test(module_path: Path, tmp_path: Path) -> dict[str, object]:
    script = f"""import {{ pathToFileURL }} from 'url';

const captured = [];
globalThis.fetch = async (_url, init) => {{
  captured.push({{
    headers: Object.fromEntries(new Headers(init.headers).entries()),
  }});
  return new Response(JSON.stringify({{ router_id: 'r1' }}), {{
    status: 201,
    headers: {{ 'Content-Type': 'application/json' }},
  }});
}};

const mod = await import({json.dumps(module_path.as_uri())});
await mod.createDraftRouter({{
  body: {{ host: '10.0.0.1', username: 'admin', secret: 'secret', allow_insecure_http: false }},
}});
await mod.createDraftRouter({{
  body: {{ host: '10.0.0.2', username: 'admin', secret: 'secret', allow_insecure_http: false }},
}});
console.log(JSON.stringify({{
  count: captured.length,
  keys: captured.map(
    (item) => item.headers['idempotency-key'] ?? item.headers['Idempotency-Key'],
  ),
  hasHeader: captured.every(
    (item) => Boolean(item.headers['idempotency-key'] ?? item.headers['Idempotency-Key']),
  ),
}}));
"""
    return _run_node_harness(script, tmp_path, "idempotency-key")


def test_connection_evaluate_finish_gate_behavior(tmp_path: Path) -> None:
    """Регрессия: evaluateFinishGate fail-closed по именованной таблице случаев в Node."""
    inputs = _finish_gate_inputs_table()
    results = _index_finish_gate_results(
        inputs,
        _run_evaluate_finish_gate(inputs, CONNECTION_FLOW_JS, tmp_path),
    )

    allowed = results["all_green_confirmed_live"]
    assert allowed["allowed"] is True, allowed
    assert allowed["mock"] is False, allowed

    denied_fact_cases = (
        "reachable_false",
        "reachable_null",
        "credentials_false",
        "credentials_null",
        "host_key_match_false",
        "host_key_match_null",
        "tuple_match_false",
        "tuple_match_null",
        "evidence_fresh_false",
        "evidence_fresh_null",
    )
    for case_id in denied_fact_cases:
        verdict = results[case_id]
        assert verdict["allowed"] is False, verdict
        assert verdict["reasonText"], f"{case_id} must explain denial"

    assert results["host_key_not_confirmed"]["allowed"] is False
    assert results["red_status_live"]["allowed"] is False
    assert results["health_null_live"]["allowed"] is False

    fake_allowed = results["fake_yellow_unconfirmed"]
    assert fake_allowed["allowed"] is True, fake_allowed
    assert fake_allowed["mock"] is True, fake_allowed

    assert results["fake_red_unconfirmed"]["allowed"] is False
    assert results["fake_health_null"]["allowed"] is False
    assert results["red_status_only_blocker"]["allowed"] is False


def _assert_finish_gate_null_fact_denied(
    module_path: Path,
    tmp_path: Path,
    *,
    label: str,
) -> None:
    inputs = _finish_gate_inputs_table()
    results = _index_finish_gate_results(
        inputs,
        _run_evaluate_finish_gate(inputs, module_path, tmp_path / label),
    )
    assert results["reachable_null"]["allowed"] is False, (
        f"{label}: reachable_null must stay denied"
    )


def test_detector_evaluate_finish_gate_catches_broken_logic(tmp_path: Path) -> None:
    """Самопроверка: ослабленное условие null-фактов ловится таблицей finish gate."""
    source = _read(CONNECTION_FLOW_JS)
    broken_source, applied = _mutate_finish_gate_only_false(source)
    assert applied, "mutation must apply to evaluateFinishGate fact check"
    broken_module = _write_connection_module_tree(tmp_path / "broken", broken_source)

    _assert_finish_gate_null_fact_denied(CONNECTION_FLOW_JS, tmp_path, label="good")
    broken_results = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(
            _finish_gate_inputs_table(),
            broken_module,
            tmp_path / "broken-run",
        ),
    )
    assert broken_results["reachable_null"]["allowed"] is True, (
        "broken logic must incorrectly allow reachable_null"
    )


def test_detector_finish_gate_catches_unconfirmed_host_key(tmp_path: Path) -> None:
    """Самопроверка: снятие требования hostKeyConfirmed ловится таблицей finish gate."""
    source = _read(CONNECTION_FLOW_JS)
    broken_source, applied = _mutate_finish_gate_allow_unconfirmed(source)
    assert applied
    broken_module = _write_connection_module_tree(tmp_path / "broken-unconfirmed", broken_source)

    good = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(_finish_gate_inputs_table(), CONNECTION_FLOW_JS, tmp_path),
    )
    broken = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(
            _finish_gate_inputs_table(),
            broken_module,
            tmp_path / "run",
        ),
    )
    assert good["host_key_not_confirmed"]["allowed"] is False
    assert broken["host_key_not_confirmed"]["allowed"] is True


def test_detector_finish_gate_catches_ignored_red(tmp_path: Path) -> None:
    """Самопроверка: снятие запрета при red status ловится на red_status_only_blocker."""
    source = _read(CONNECTION_FLOW_JS)
    broken_source, applied = _mutate_finish_gate_allow_red(source)
    assert applied
    broken_module = _write_connection_module_tree(tmp_path / "broken-red", broken_source)

    inputs = _finish_gate_inputs_table()
    good = _index_finish_gate_results(
        inputs,
        _run_evaluate_finish_gate(inputs, CONNECTION_FLOW_JS, tmp_path),
    )
    broken = _index_finish_gate_results(
        inputs,
        _run_evaluate_finish_gate(inputs, broken_module, tmp_path / "run"),
    )
    assert good["red_status_only_blocker"]["allowed"] is False
    assert broken["red_status_only_blocker"]["allowed"] is True


def test_detector_finish_gate_catches_ignored_null_health(tmp_path: Path) -> None:
    """Самопроверка: снятие запрета при health==null ловится на health_null_live."""
    source = _read(CONNECTION_FLOW_JS)
    broken_source, applied = _mutate_finish_gate_allow_null_health(source)
    assert applied
    broken_module = _write_connection_module_tree(tmp_path / "broken-null", broken_source)

    good = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(_finish_gate_inputs_table(), CONNECTION_FLOW_JS, tmp_path),
    )
    broken = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(
            _finish_gate_inputs_table(),
            broken_module,
            tmp_path / "run",
        ),
    )
    assert good["health_null_live"]["allowed"] is False
    assert broken["health_null_live"]["allowed"] is True


def test_detector_finish_gate_catches_fake_before_null(tmp_path: Path) -> None:
    """Самопроверка: fake-режим до health==null ловится на fake_health_null."""
    source = _read(CONNECTION_FLOW_JS)
    broken_source, applied = _mutate_finish_gate_fake_before_null(source)
    assert applied
    broken_module = _write_connection_module_tree(tmp_path / "broken-fake", broken_source)

    good = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(_finish_gate_inputs_table(), CONNECTION_FLOW_JS, tmp_path),
    )
    broken = _index_finish_gate_results(
        _finish_gate_inputs_table(),
        _run_evaluate_finish_gate(
            _finish_gate_inputs_table(),
            broken_module,
            tmp_path / "run",
        ),
    )
    assert good["fake_health_null"]["allowed"] is False
    assert broken["fake_health_null"]["allowed"] is True


def test_connection_build_checklist_behavior(tmp_path: Path) -> None:
    """Регрессия: чеклист содержит 5 фактов и 3 неподдерживаемых строки без success."""
    checklist = _run_build_connection_checklist(_green_health(), CONNECTION_FLOW_JS, tmp_path)

    supported = [item for item in checklist if item["supported"]]
    unsupported = [item for item in checklist if not item["supported"]]

    assert len(supported) == 5
    assert len(unsupported) == 3
    by_id = {item["id"]: item for item in checklist}
    assert set(by_id) >= {
        "reachable",
        "credentials_present",
        "host_key_match",
        "tuple_match",
        "evidence_fresh",
        "local_network",
        "internet",
        "signal_level",
    }
    assert all(by_id[item_id]["tone"] != "success" for item_id in (
        "local_network",
        "internet",
        "signal_level",
    ))

    null_checklist = _run_build_connection_checklist(
        {"status": "yellow", "facts": {"reachable": None}},
        CONNECTION_FLOW_JS,
        tmp_path / "null-fact",
    )
    reachable_item = next(item for item in null_checklist if item["id"] == "reachable")
    assert reachable_item["tone"] == "neutral", reachable_item
    assert reachable_item["tone"] != "success"


def test_connection_describe_discovery_behavior(tmp_path: Path) -> None:
    """Регрессия: describeDiscovery честно отражает пустой, деградированный и нормальный ответ."""
    cases = {
        "empty_no_candidates": (
            {"candidates": [], "excluded_candidates": [], "source_diagnostics": []},
            {},
            {"state": "EMPTY"},
        ),
        "empty_with_degraded_sources": (
            {
                "candidates": [],
                "excluded_candidates": [],
                "degraded_sources": ["default_gateway"],
            },
            {},
            {"state": "EMPTY"},
        ),
        "degraded_with_diagnostics": (
            {
                "candidates": [{"host": "10.0.0.1", "port": 22, "identity_state": "unknown"}],
                "degraded_sources": ["default_gateway"],
                "source_diagnostics": [
                    {"source": "default_gateway", "status": "failed", "reason_code": "timeout"},
                ],
            },
            {},
            {"state": "WARNING", "hasDiagnostics": True},
        ),
        "degraded_without_diagnostics": (
            {
                "candidates": [{"host": "10.0.0.1", "port": 22, "identity_state": "unknown"}],
                "degraded_sources": ["default_gateway"],
            },
            {},
            {"state": "WARNING", "hasDiagnostics": True},
        ),
        "success_known_match": (
            {
                "candidates": [{"host": "10.0.0.2", "port": 22, "identity_state": "known_match"}],
                "degraded_sources": [],
            },
            {},
            {"state": "SUCCESS"},
        ),
    }

    for case_id, (response, options, expected) in cases.items():
        result = _run_describe_discovery(response, options, CONNECTION_FLOW_JS, tmp_path / case_id)
        assert result["state"] == expected["state"], (case_id, result)
        if expected.get("hasDiagnostics"):
            assert result["diagnosticsNotes"], (case_id, result)

    mismatch = _run_describe_candidate(
        {
            "host": "10.0.0.3",
            "port": 22,
            "identity_state": "known_mismatch",
            "reason_code": "lifecycle_identity_mismatch",
        },
        CONNECTION_FLOW_JS,
        tmp_path / "mismatch",
    )
    assert mismatch["identityTone"] == "danger", mismatch
    assert mismatch["warning"], mismatch


def test_connection_string_contracts() -> None:
    """Регрессия: нет ложных строк, макетных заглушек, DOM и запрещённого жаргона."""
    source = _read(CONNECTION_FLOW_JS)
    lower = source.lower()

    for phrase in FORBIDDEN_IPAD_STORAGE_PHRASES:
        assert phrase.lower() not in lower, f"forbidden storage phrase: {phrase!r}"

    for needle in MOCK_DATA_NEEDLES:
        assert needle not in source, f"mock layout needle: {needle!r}"

    for pattern in DOM_STORAGE_PATTERNS:
        assert re.search(pattern, source) is None, f"forbidden pattern in source: {pattern}"

    for msg in CONNECTION_USER_MESSAGES:
        assert msg in source, f"expected user message missing: {msg!r}"

    user_string_literals = re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", source)
    user_string_literals += re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', source)
    for literal in user_string_literals:
        if not CYRILLIC.search(literal):
            continue
        for jargon in FORBIDDEN_JARGON_IN_USER_STRINGS:
            assert jargon not in literal, f"jargon {jargon!r} in user string: {literal!r}"


def test_connection_api_paths_exist_in_openapi() -> None:
    """Регрессия: все пути сетевых вызовов connection-flow существуют в openapi-v0.json."""
    frontend_paths = _extract_api_paths_from_connection_flow()
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


def test_connection_create_draft_sends_idempotency_key(tmp_path: Path) -> None:
    """Регрессия: createDraftRouter отправляет Idempotency-Key и ключ не константа."""
    result = _run_idempotency_header_test(CONNECTION_FLOW_JS, tmp_path)
    assert result["count"] == 2
    assert result["hasHeader"] is True
    keys = result["keys"]
    assert len(keys) == 2
    assert keys[0] and keys[1]
    assert keys[0] != keys[1], "Idempotency-Key must not be a constant"


def test_connection_module_imports_in_node(tmp_path: Path) -> None:
    """Регрессия: модуль импортируется в Node без DOM."""
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(CONNECTION_FLOW_JS.as_uri())});
if (!mod.ConnectionStep || !mod.evaluateFinishGate) {{
  throw new Error('missing exports');
}}
console.log(JSON.stringify({{ ok: true }}));
"""
    result = _run_node_harness(script, tmp_path, "import-check")
    assert result == {"ok": True}


REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"


def _run_format_fingerprint(value: str, module_path: Path, tmp_path: Path) -> str:
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const result = mod.formatFingerprint({json.dumps(value)});
console.log(JSON.stringify(result));
"""
    return _run_node_harness(script, tmp_path, "format-fingerprint")


def _run_describe_host_key_conflict(module_path: Path, tmp_path: Path) -> dict[str, object | None]:
    script = f"""import {{ pathToFileURL }} from 'url';
import {{ HubApiError, ERROR_KIND }} from {json.dumps((HUB / "core" / "errors.js").as_uri())};

const mod = await import({json.dumps(module_path.as_uri())});
const error = new HubApiError({{
  code: 'ssh_host_key.pin_conflict',
  httpStatus: 409,
  userMessage: 'conflict',
  userAction: null,
  serverMessage: null,
  details: [{{
    existing_fingerprint_sha256: {json.dumps(REALISTIC_FINGERPRINT)},
    candidate_fingerprint_sha256: 'SHA256:abc+/def0123456789012345678901234567890abcd',
  }}],
  requestId: null,
  correlationId: null,
  kind: ERROR_KIND.CONFLICT,
}});
const result = mod.describeHostKeyConflict(error);
console.log(JSON.stringify(result));
"""
    return _run_node_harness(script, tmp_path, "describe-conflict")


def test_connection_format_fingerprint_preserves_base64(tmp_path: Path) -> None:
    """Регрессия: formatFingerprint не искажает SHA256:+base64 (/ и + сохраняются)."""
    result = _run_format_fingerprint(REALISTIC_FINGERPRINT, CONNECTION_FLOW_JS, tmp_path)
    assert result == REALISTIC_FINGERPRINT, (
        "formatFingerprint must return fingerprint verbatim (trim only)"
    )


def test_connection_describe_candidate_no_fabricated_port(tmp_path: Path) -> None:
    """Регрессия: describeCandidate не подставляет порт 22, если сервер его не прислал."""
    result = _run_describe_candidate({"host": "10.0.0.1"}, CONNECTION_FLOW_JS, tmp_path)
    assert result["port"] is None, result
    assert result["host"] == "10.0.0.1"


def test_connection_describe_host_key_conflict_returns_both_fingerprints(
    tmp_path: Path,
) -> None:
    """Регрессия: describeHostKeyConflict возвращает оба отпечатка дословно."""
    result = _run_describe_host_key_conflict(CONNECTION_FLOW_JS, tmp_path)
    assert result is not None
    assert result["existingFingerprint"] == REALISTIC_FINGERPRINT
    assert result["candidateFingerprint"] == "SHA256:abc+/def0123456789012345678901234567890abcd"
    assert result["text"]
    assert isinstance(result["text"], str)


def test_node_required_for_behavioral_tests_unless_opt_out(monkeypatch: pytest.MonkeyPatch) -> None:
    """Регрессия: без Node набор не должен молча проходить (только явный opt-out)."""
    monkeypatch.delenv(NODE_SKIP_ENV, raising=False)

    def fake_which(name: str) -> str | None:
        if name == "node":
            return None
        return shutil.which(name)

    monkeypatch.setattr(shutil, "which", fake_which)
    with pytest.raises(Failed, match="node is required"):
        _require_node()

    monkeypatch.setenv(NODE_SKIP_ENV, "1")
    with pytest.raises(pytest.skip.Exception):  # type: ignore[attr-defined]
        _require_node()


def _run_node_export_call(
    module_path: Path,
    tmp_path: Path,
    *,
    label: str,
    script_body: str,
) -> object:
    script = f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
{script_body}
"""
    return _run_node_harness(script, tmp_path, label)


def test_connection_build_draft_body_maps_password_to_secret(tmp_path: Path) -> None:
    """Регрессия: buildDraftBody кладёт пароль в secret и не добавляет лишних полей."""
    result = _run_node_export_call(
        CONNECTION_FLOW_JS,
        tmp_path,
        label="build-draft-body",
        script_body="""
const body = mod.buildDraftBody({
  host: ' 10.0.0.5 ',
  username: ' admin ',
  password: 's3cret!',
  displayName: ' Lab ',
});
console.log(JSON.stringify(body));
""",
    )
    assert result == {
        "host": "10.0.0.5",
        "username": "admin",
        "secret": "s3cret!",
        "display_name": "Lab",
        "allow_insecure_http": False,
    }


def test_connection_validate_forms_table(tmp_path: Path) -> None:
    """Регрессия: validateManualHost/validateAccessForm fail-closed; значения не в тексте ошибок."""
    cases = {
        "host_empty": {
            "fn": "validateManualHost",
            "args": ['""'],
            "valid": False,
            "secret_in_errors": False,
        },
        "host_spaces": {
            "fn": "validateManualHost",
            "args": ['"10.0.0.1 bad"'],
            "valid": False,
            "secret_in_errors": False,
        },
        "host_with_credentials": {
            "fn": "validateManualHost",
            "args": ['"admin@10.0.0.1"'],
            "valid": False,
            "secret_in_errors": False,
        },
        "access_missing_password": {
            "fn": "validateAccessForm",
            "args": [
                '{ host: "10.0.0.1", username: "admin", password: "" }',
            ],
            "valid": False,
            "secret_in_errors": False,
            "probe_value": "s3cret!",
        },
        "access_whitespace_username": {
            "fn": "validateAccessForm",
            "args": [
                '{ host: "10.0.0.1", username: "   ", password: "s3cret!" }',
            ],
            "valid": False,
            "secret_in_errors": True,
            "probe_value": "s3cret!",
        },
    }

    for case_id, spec in cases.items():
        script_body = f"""
const result = mod.{spec["fn"]}({spec["args"][0]});
console.log(JSON.stringify(result));
"""
        result = _run_node_export_call(
            CONNECTION_FLOW_JS,
            tmp_path / case_id,
            label=case_id,
            script_body=script_body,
        )
        assert result["valid"] is spec["valid"], (case_id, result)
        errors_text = " ".join(result.get("errors", []))
        if spec.get("secret_in_errors"):
            assert spec["probe_value"] not in errors_text, (case_id, errors_text)
        else:
            assert "s3cret!" not in errors_text, (case_id, errors_text)
            assert "admin@10.0.0.1" not in errors_text, (case_id, errors_text)


def test_connection_create_idempotency_keys_differ(tmp_path: Path) -> None:
    """Регрессия: createIdempotencyKey возвращает разные значения при каждом вызове."""
    result = _run_node_export_call(
        CONNECTION_FLOW_JS,
        tmp_path,
        label="idempotency-keys",
        script_body="""
const a = mod.createIdempotencyKey();
const b = mod.createIdempotencyKey();
console.log(JSON.stringify({ a, b, distinct: a !== b && Boolean(a) && Boolean(b) }));
""",
    )
    assert result["distinct"] is True


def _run_api_capture_harness(module_path: Path, tmp_path: Path, label: str) -> dict[str, object]:
    script = f"""import {{ pathToFileURL }} from 'url';

const captured = [];
globalThis.fetch = async (url, init) => {{
  let body = null;
  if (init?.body) {{
    body = JSON.parse(String(init.body));
  }}
  captured.push({{
    url: String(url),
    method: init?.method ?? 'GET',
    headers: Object.fromEntries(new Headers(init?.headers ?? {{}}).entries()),
    body,
  }});
  return new Response(JSON.stringify({{ router_id: 'r1', credential_ref_id: 'c1' }}), {{
    status: 201,
    headers: {{ 'Content-Type': 'application/json' }},
  }});
}};

const mod = await import({json.dumps(module_path.as_uri())});

await mod.runDiscovery(new AbortController().signal);
await mod.createDraftRouter({{
  body: mod.buildDraftBody({{ host: '10.0.0.1', username: 'admin', password: 'secret' }}),
}});
await mod.confirmHostKey({{
  routerId: 'r1',
  fingerprintSha256: 'SHA256:abc',
  algorithm: 'ssh-ed25519',
}});
await mod.checkConnectionHealth({{ routerId: 'r1', host: '10.0.0.1' }});

console.log(JSON.stringify({{ calls: captured }}));
"""
    return _run_node_harness(script, tmp_path, label)  # type: ignore[return-value]


def test_connection_api_request_bodies_match_routes(tmp_path: Path) -> None:
    """Регрессия: тела и заголовки API-вызовов совпадают с backend-маршрутами."""
    payload = _run_api_capture_harness(CONNECTION_FLOW_JS, tmp_path, "api-capture")
    calls = payload["calls"]
    assert len(calls) == 4

    discovery = calls[0]
    assert discovery["body"] == {
        "include_default_gateway": True,
        "include_known_endpoints": True,
        "probe": False,
    }

    draft = calls[1]
    assert draft["body"] == {
        "host": "10.0.0.1",
        "username": "admin",
        "secret": "secret",
        "allow_insecure_http": False,
    }
    draft_headers = {k.lower(): v for k, v in draft["headers"].items()}
    assert draft_headers.get("idempotency-key")

    confirm = calls[2]
    assert confirm["body"] == {
        "fingerprint_sha256": "SHA256:abc",
        "algorithm": "ssh-ed25519",
        "allow_overwrite": False,
    }

    health = calls[3]
    assert health["body"]["probe"] is True
    assert health["body"]["router_id"] == "r1"
    assert health["body"]["host"] == "10.0.0.1"


def test_connection_run_discovery_sends_no_probe(tmp_path: Path) -> None:
    """Регрессия: runDiscovery всегда отправляет probe:false (без пробы на поиске)."""
    payload = _run_node_export_call(
        CONNECTION_FLOW_JS,
        tmp_path,
        label="discovery-probe",
        script_body="""
const captured = [];
globalThis.fetch = async (_url, init) => {
  captured.push(JSON.parse(String(init.body)));
  return new Response(JSON.stringify({ candidates: [] }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
};
await mod.runDiscovery(undefined);
console.log(JSON.stringify(captured[0]));
""",
    )
    assert payload["probe"] is False


def test_connection_group_discovery_merges_same_host_sources(tmp_path: Path) -> None:
    """Три источника одного адреса сливаются в одну группу с приоритетным портом 22."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "local_subnet_gateway",
            "identity_state": "unknown",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    assert len(groups) == 1
    group = groups[0]
    assert group["host"] == "192.168.2.1"
    assert group["port"] == 22
    assert len(group["sources"]) == 3
    assert group["hasMultiplePorts"] is True
    assert {item["port"] for item in group["ports"]} == {22, 443}


def test_connection_group_discovery_keeps_different_hosts_separate(tmp_path: Path) -> None:
    """Разные адреса не сливаются в одну группу."""
    raw = [
        {"host": "192.168.2.1", "port": 22, "candidate_origin": "known_endpoint"},
        {"host": "192.168.1.1", "port": 22, "candidate_origin": "default_gateway"},
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    assert len(groups) == 2
    assert {group["host"] for group in groups} == {"192.168.1.1", "192.168.2.1"}


def test_connection_group_discovery_worst_identity_state_wins(tmp_path: Path) -> None:
    """RECORD/UNPROVEN худшее состояние побеждает, когда нет PROVEN-доказательств."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "tuple_model_mismatch",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "local_subnet_gateway",
            "identity_state": "unknown",
            "reason_code": "unenrolled_host",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    assert len(groups) == 1
    group = groups[0]
    assert group["identityState"] == "known_mismatch"
    assert group["identityTone"] == "danger"
    assert group["warnings"], group


def test_connection_group_probe_match_not_downgraded_by_stale_duplicate(
    tmp_path: Path,
) -> None:
    """PROVEN known_match не понижается неподтверждённым дублем того же хоста."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_match",
            "reason_code": "probe_tuple_match",
            "router_id": "router-proven",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "router-draft",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "local_subnet_gateway",
            "identity_state": "unknown",
            "reason_code": "unenrolled_host",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_match"
    assert group["identityTone"] == "success"
    assert group["routerId"] == "router-proven"
    assert group["port"] == 22
    assert len(group["reasonTexts"]) >= 2
    assert not any(
        "Выберите этот адрес и продолжите настройку" in text
        for text in group["reasonTexts"]
    ), group["reasonTexts"]
    assert any(
        "незавершённый черновик" in text.lower()
        for text in group["reasonTexts"]
    ), group["reasonTexts"]


def test_connection_group_enrolled_endpoint_omits_draft_imperative(
    tmp_path: Path,
) -> None:
    """G-7: для enrolled endpoint черновик на том же хосте — факт без императива."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "missing_ssh_host_key_pin",
            "router_id": "router-enrolled",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "router-draft",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["routerId"] == "router-enrolled", group
    assert not any(
        "Выберите этот адрес и продолжите настройку" in text
        for text in group["reasonTexts"]
    ), group["reasonTexts"]
    assert any(
        "незавершённый черновик" in text.lower()
        for text in group["reasonTexts"]
    ), group["reasonTexts"]


def test_connection_group_probe_mismatch_not_masked_by_benign_duplicate(
    tmp_path: Path,
) -> None:
    """PROVEN known_mismatch не маскируется дублем с положительным identity_state."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "probe_tuple_mismatch",
            "router_id": "router-mismatch",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_match",
            "reason_code": "enrollment_match_identity_unverified",
            "router_id": "router-unverified",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_mismatch"
    assert group["identityTone"] == "danger"
    assert group["routerId"] == "router-mismatch"
    assert group["port"] == 22
    assert group["warnings"], group


def test_connection_group_unknown_reason_code_fails_closed(tmp_path: Path) -> None:
    """Нераспознанный reason_code на единственном кандидате понижает группу до unknown."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_match",
            "reason_code": "totally_made_up_reason",
            "router_id": "router-only",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "unknown"
    assert group["identityTone"] == "neutral"


def test_connection_group_precedence_proven_negative_beats_proven_positive(
    tmp_path: Path,
) -> None:
    """probe_tuple_mismatch на одном хосте всегда побеждает probe_tuple_match + known_match."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "probe_tuple_mismatch",
            "router_id": "router-mismatch",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_match",
            "reason_code": "probe_tuple_match",
            "router_id": "router-proven",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_mismatch"
    assert group["identityTone"] == "danger"
    assert group["routerId"] == "router-mismatch"
    assert group["port"] == 22


def test_connection_group_same_router_id_mismatch_not_subordinate(
    tmp_path: Path,
) -> None:
    """F-A2: mismatch на том же routerId не маскируется и не переформулируется."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_match",
            "reason_code": "probe_tuple_match",
            "router_id": "router-same",
        },
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "host_key_pin_mismatch",
            "router_id": "router-same",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_match"
    assert group["warnings"], group
    assert not any(
        "Другая сохранённая запись" in text for text in group["reasonTexts"]
    ), group["reasonTexts"]
    assert any(
        "Отпечаток устройства не совпадает" in text for text in group["reasonTexts"]
    ), group["reasonTexts"]


def test_connection_group_collapsed_draft_resolve_each_advertised_port(
    tmp_path: Path,
) -> None:
    """F-A1: каждый рекламируемый порт схлопнутых черновиков резолвится в свой routerId."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-1",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-2",
        },
        {
            "host": "192.168.2.1",
            "port": 8443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-3",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert {item["port"] for item in group["ports"]} == {22, 443, 8443}

    for port, router_id in ((22, "draft-1"), (443, "draft-2"), (8443, "draft-3")):
        endpoint = _run_resolve_group_endpoint(
            group,
            port,
            CONNECTION_FLOW_JS,
            tmp_path / f"draft-port-{port}",
        )
        assert endpoint["port"] == port, endpoint
        assert endpoint["routerId"] == router_id, endpoint


def test_connection_group_collapses_enrollment_draft_duplicates(tmp_path: Path) -> None:
    """Несколько placeholder-черновиков одного хоста сливаются в одну строку деталей."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-1",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-2",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-3",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert len(group["sources"]) == 1
    assert group["sources"][0]["duplicateCount"] == 3


def test_connection_group_router_id_from_proven_source_on_non_primary_port(
    tmp_path: Path,
) -> None:
    """routerId группы берётся из PROVEN-источника, даже если он не primary по origin/port."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "unenrolled_host",
            "router_id": "router-ssh",
            "source_address": "192.168.2.144",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "local_subnet_gateway",
            "identity_state": "known_match",
            "reason_code": "probe_tuple_match",
            "router_id": "router-proven-443",
            "source_address": "192.168.2.10",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_match"
    assert group["routerId"] == "router-proven-443"
    assert group["port"] == 443
    assert group["sourceAddress"] == "192.168.2.10"


def test_connection_group_port_selection_flows_to_access_endpoint(tmp_path: Path) -> None:
    """Выбор порта внутри группы сохраняется и попадает в endpoint шага «Доступ»."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "source_address": "192.168.2.144",
            "router_id": "router-ssh",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "source_address": "192.168.2.144",
            "router_id": "router-https",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    default_endpoint = _run_resolve_group_endpoint(
        group, None, CONNECTION_FLOW_JS, tmp_path / "default",
    )
    assert default_endpoint["port"] == 22
    assert default_endpoint["routerId"] == "router-ssh"

    selected_endpoint = _run_resolve_group_endpoint(
        group, 443, CONNECTION_FLOW_JS, tmp_path / "selected",
    )
    assert selected_endpoint["port"] == 443
    assert selected_endpoint["routerId"] == "router-https"


def test_connection_group_f1_no_contradictory_match_and_mismatch_badge(
    tmp_path: Path,
) -> None:
    """F-1: PROVEN match не сосуществует с device-level mismatch warning на том же адресе."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_match",
            "reason_code": "probe_tuple_match",
            "router_id": "router-proven",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "tuple_model_mismatch",
            "router_id": "router-stale",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_match", group
    assert group["identityTone"] == "success", group
    assert group["identityText"] == "Совпадает с сохранённой записью", group
    assert group["warnings"] == [], group
    assert any(
        "Другая сохранённая запись" in text for text in group["reasonTexts"]
    ), group["reasonTexts"]
    assert not any(
        text == "Модель устройства не совпадает с сохранённой записью"
        for text in group["reasonTexts"]
    ), group["reasonTexts"]


def test_connection_group_f2_draft_collapse_preserves_router_id(
    tmp_path: Path,
) -> None:
    """F-2: схлопывание черновиков не делает unenrolled_host primary и не теряет routerId."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-1",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-2",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "local_subnet_gateway",
            "identity_state": "unknown",
            "reason_code": "unenrolled_host",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["routerId"] == "draft-1", group
    assert group["port"] == 22, group
    assert group["sources"][0]["routerId"] == "draft-1", group["sources"]


def test_connection_group_f3_draft_collapse_preserves_all_ports(
    tmp_path: Path,
) -> None:
    """F-3: схлопывание черновиков сохраняет объединение портов 22 и 443."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-1",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-2",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-3",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["hasMultiplePorts"] is True, group
    assert {item["port"] for item in group["ports"]} == {22, 443}, group["ports"]


def test_connection_group_f4_duplicate_count_visible_in_reason_texts(
    tmp_path: Path,
) -> None:
    """F-4: duplicateCount=3 попадает в reasonTexts с корректным русским множественным числом."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-1",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-2",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
            "router_id": "draft-3",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert "3 незавершённых черновика на этом адресе" in group["reasonTexts"], group[
        "reasonTexts"
    ]


def test_connection_group_f5_enrollment_draft_copy_is_actionable(
    tmp_path: Path,
) -> None:
    """F-5: enrollment_draft_model_unknown — текст про незавершённый черновик и шаг."""
    result = _run_describe_candidate(
        {
            "host": "192.168.2.1",
            "port": 22,
            "identity_state": "unknown",
            "reason_code": "enrollment_draft_model_unknown",
        },
        CONNECTION_FLOW_JS,
        tmp_path,
    )
    assert (
        result["reasonText"]
        == "Незавершённый черновик: модель устройства ещё не записана. "
        "Выберите этот адрес и продолжите настройку."
    ), result


def test_connection_group_f6_inconsistent_probe_match_fails_closed(
    tmp_path: Path,
) -> None:
    """F-6/F-A4: known_mismatch + probe_tuple_match не поднимает группу и не успокаивает текст."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "probe_tuple_match",
            "router_id": "router-inconsistent",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_mismatch", group
    assert group["identityTone"] == "danger", group
    assert group["warnings"], group
    assert "Требуется дополнительная проверка" in group["reasonTexts"], group["reasonTexts"]
    assert not any(
        "Совпадает с записью по результатам проверки" in text
        for text in group["reasonTexts"]
    ), group["reasonTexts"]


def test_connection_group_f7_record_mismatch_prefers_good_connect_target(
    tmp_path: Path,
) -> None:
    """F-A3: RECORD mismatch сохраняет вердикт, но connect target — лучшая known_endpoint запись."""
    raw = [
        {
            "host": "192.168.2.1",
            "port": 22,
            "candidate_origin": "known_endpoint",
            "identity_state": "unknown",
            "reason_code": "enrollment_match_identity_unverified",
            "router_id": "rtr-good",
        },
        {
            "host": "192.168.2.1",
            "port": 443,
            "candidate_origin": "known_endpoint",
            "identity_state": "known_mismatch",
            "reason_code": "tuple_model_mismatch",
            "router_id": "rtr-stale",
        },
    ]
    groups = _run_group_discovery_candidates(raw, CONNECTION_FLOW_JS, tmp_path)
    group = groups[0]
    assert group["identityState"] == "known_mismatch", group
    assert group["routerId"] == "rtr-good", group
    assert group["port"] == 22, group
    assert any(
        "Модель устройства не совпадает" in text for text in group["reasonTexts"]
    ), group["reasonTexts"]


def test_derive_verify_host_key_badge_tri_state(tmp_path: Path) -> None:
    """deriveVerifyHostKeyBadge: true/false/null/undefined/absent."""
    health_base = {
        "status": "yellow",
        "facts": {
            "reachable": True,
            "credentials_present": True,
            "evidence_fresh": True,
        },
    }
    cases = [
        ("true", True, "Привязан", "success"),
        ("false", False, "Отпечаток не совпадает", "warning"),
        ("null", None, "Совпадение отпечатка ещё не проверено", "neutral"),
    ]
    for label, match_value, expected_label, expected_tone in cases:
        health = {**health_base, "facts": {**health_base["facts"], "host_key_match": match_value}}
        result = _run_node_export_call(
            CONNECTION_FLOW_JS,
            tmp_path / f"badge-{label}",
            label=f"derive-badge-{label}",
            script_body=f"""
const badge = mod.deriveVerifyHostKeyBadge({{
  hostKeyConfirmed: true,
  health: {json.dumps(health, ensure_ascii=False)},
}});
console.log(JSON.stringify(badge));
""",
        )
        assert result == {"label": expected_label, "tone": expected_tone}, label

    for absent_label, facts in [
        ("undefined", {"reachable": True, "credentials_present": True, "evidence_fresh": True}),
        ("absent_field", {"reachable": True, "credentials_present": True, "evidence_fresh": True}),
    ]:
        health = {"status": "yellow", "facts": facts}
        result = _run_node_export_call(
            CONNECTION_FLOW_JS,
            tmp_path / f"badge-{absent_label}",
            label=f"derive-badge-{absent_label}",
            script_body=f"""
const badge = mod.deriveVerifyHostKeyBadge({{
  hostKeyConfirmed: true,
  health: {json.dumps(health, ensure_ascii=False)},
}});
console.log(JSON.stringify(badge));
""",
        )
        assert result == {
            "label": "Совпадение отпечатка ещё не проверено",
            "tone": "neutral",
        }, absent_label


def test_host_key_reset_clears_sticky_live_credentials(tmp_path: Path) -> None:
    """J-1: hostKey reset clears sticky username/fingerprint; params incomplete."""
    session_uri = json.dumps(SESSION_JS.as_uri())
    live_uri = json.dumps(LIVE_PARAMS_JS.as_uri())
    script = f"""import {{ resetSession, updateSession, getSession }} from {session_uri};
import {{ buildLiveConnectionParams }} from {live_uri};

resetSession();
updateSession({{
  routerId: {json.dumps(REAL_ROUTER_ID)},
  routerHost: '192.168.2.1',
  sourceAddress: '192.168.2.10',
  hostKeyConfirmed: true,
  liveReady: true,
  usernameAvailable: true,
  connectionRestoreState: 'done',
  wifiLive: {{
    host: '192.168.2.1',
    username: 'admin',
    credentialRefId: 'cred-real',
    sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},
  }},
}});

updateSession({{
  hostKeyConfirmed: false,
  liveReady: false,
}});

const session = getSession();
const live = buildLiveConnectionParams(session);
console.log(JSON.stringify({{
  username: session.wifiLive.username,
  fingerprint: session.wifiLive.sshHostKeySha256,
  complete: live.complete,
  missing: live.missing,
}}));
"""
    payload = _run_node_harness(script, tmp_path, "host-key-reset-sticky")  # type: ignore[assignment]

    assert payload["username"] is None
    assert payload["fingerprint"] is None
    assert payload["complete"] is False
    assert "ssh_host_key_sha256" in payload["missing"]


def test_live_capability_subscription_key_includes_dial_fields(tmp_path: Path) -> None:
    """J-4: ключ подписки меняется при смене host/sourceAddress/credentialRefId."""
    live_uri = json.dumps(LIVE_PARAMS_JS.as_uri())
    script = f"""import {{ liveCapabilitySubscriptionKey }} from {live_uri};

const base = {{
  routerId: {json.dumps(REAL_ROUTER_ID)},
  routerHost: '10.0.0.2',
  sourceAddress: '192.168.2.10',
  liveReady: true,
  hostKeyConfirmed: true,
  usernameAvailable: true,
  connectionRestoreState: 'done',
  wifiLive: {{ host: '10.0.0.2', credentialRefId: 'cred-a' }},
}};

const hostChanged = {{
  ...base,
  routerHost: '10.0.0.99',
  wifiLive: {{ ...base.wifiLive, host: '10.0.0.99' }},
}};
const sourceChanged = {{ ...base, sourceAddress: '192.168.2.99' }};
const credChanged = {{ ...base, wifiLive: {{ ...base.wifiLive, credentialRefId: 'cred-b' }} }};

console.log(JSON.stringify({{
  base: liveCapabilitySubscriptionKey(base),
  hostChanged: liveCapabilitySubscriptionKey(hostChanged),
  sourceChanged: liveCapabilitySubscriptionKey(sourceChanged),
  credChanged: liveCapabilitySubscriptionKey(credChanged),
}}));
"""
    payload = _run_node_harness(script, tmp_path, "subscription-key-dial")  # type: ignore[assignment]
    assert payload["base"] != payload["hostChanged"]
    assert payload["base"] != payload["sourceChanged"]
    assert payload["base"] != payload["credChanged"]


def test_normalize_tri_state_fact(tmp_path: Path) -> None:
    """normalizeTriStateFact сворачивает не-boolean в null."""
    result = _run_node_export_call(
        CONNECTION_FLOW_JS,
        tmp_path,
        label="normalize-tri-state",
        script_body="""
console.log(JSON.stringify({
  t: mod.normalizeTriStateFact(true),
  f: mod.normalizeTriStateFact(false),
  n: mod.normalizeTriStateFact(null),
  u: mod.normalizeTriStateFact(undefined),
  s: mod.normalizeTriStateFact('yes'),
}));
""",
    )
    assert result == {"t": True, "f": False, "n": None, "u": None, "s": None}
