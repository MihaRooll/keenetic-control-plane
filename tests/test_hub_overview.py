"""Структурные контракты экрана «Обзор» LOCAL HUB (M-6, M-7; без сети и без живого роутера)."""

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
CONNECTION_HEALTH_PY = (
    REPO_ROOT / "router_control" / "application" / "connection_health.py"
)
APPLY_RESPONSE_MODELS = REPO_ROOT / "router_control_host" / "apply_response_models.py"

OVERVIEW_JS = HUB / "screens" / "overview.js"
OVERVIEW_CARD_GRID_JS = HUB / "features" / "overview-card-grid.js"
PROGRESS_RING_JS = HUB / "components" / "progress-ring.js"
OVERVIEW_MODEL_JS = HUB / "features" / "overview-model.js"
OVERVIEW_INTERNET_SIMPLE_JS = HUB / "features" / "overview-internet-simple.js"
OVERVIEW_SIMPLE_NETWORKS_JS = HUB / "features" / "overview-simple-networks.js"
SYSTEM_CHECK_JS = HUB / "features" / "system-check.js"
SESSION_JS = HUB / "core" / "session.js"
SHELL_JS = HUB / "core" / "shell.js"
SCREENS_CSS = HUB / "styles" / "screens.css"
SW_JS = HUB / "sw.js"
INDEX_HTML = HUB / "index.html"
UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

OVERVIEW_SOURCE_FILES = (
    OVERVIEW_JS,
    OVERVIEW_MODEL_JS,
    OVERVIEW_INTERNET_SIMPLE_JS,
    OVERVIEW_SIMPLE_NETWORKS_JS,
    SYSTEM_CHECK_JS,
    SESSION_JS,
    SHELL_JS,
    SCREENS_CSS,
)

MOCK_DATA_NEEDLES = (
    "SBER EVENT",
    "Keenetic Hopper",
    "CUSTOM STAFF",
    "CUSTOM EVENT",
    "8 устройств",
    "23 устройства",
    "142",
    "Нидерланды",
    "sber-event",
    "192.168.1.1",
    "Опубликован",
)

MOCK_EVENT_TEXTS = (
    "Проверка системы завершена",
    "Гостевое устройство подключено",
)

KNOWN_REASON_CODES = (
    "all_facts_healthy",
    "unreachable",
    "host_key_mismatch",
    "identity_mismatch",
    "credentials_missing",
    "evidence_stale",
    "reachability_unknown",
    "host_key_unknown",
    "tuple_unknown",
    "credentials_unknown",
    "evidence_freshness_unknown",
    "health_incomplete",
)

API_PREFIX = "/api/router-control/v1/"
API_CALL_RE = re.compile(
    r"api(?:Get|Post)\(\s*(?:'([^']+)'|`([^`]+)`|\"([^\"]+)\")",
)
HEALTH_FACT_ORDER_RE = re.compile(
    r"HEALTH_FACT_ORDER\s*=\s*Object\.freeze\(\[\s*(.*?)\s*\]\)",
    re.DOTALL,
)
CLASS_FIELDS_RE = re.compile(r"^\s+(\w+)\s*:", re.MULTILINE)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")
OPENAPI_TEMPLATE_SEGMENT_RE = re.compile(r"^\{[^}]+\}$")
FRONTEND_PARAM_SEGMENT_RE = re.compile(r"^\{param\}$")

OVERVIEW_USER_MESSAGES = (
    "Сеть и роутер",
    "Обновить",
    "Подключить роутер",
    "Проверить систему",
    "Готовность не определена",
    "Не удалось получить состояние системы",
    "Роутер не подключён",
    "Рабочая сеть",
    "Гостевая сеть",
    "Роутер не сообщает, какая сеть рабочая",
    "Состояние домена неизвестно",
    "Модель не указана",
    "Повторить",
    "Нужно подтвердить, что это ваш роутер",
    "Роутер отвечает",
    "Отпечаток устройства",
    "Это тот же роутер, что сохранён",
    "Сохранённый доступ",
    "Свежесть проверки",
    "Отпечаток совпадает",
    "Совпадает с сохранённым роутером",
    "Сохранённый доступ есть в системе",
    "Проверка свежая",
    "Роутер не отвечает. Проверьте питание и сеть, затем нажмите «Проверить систему»",
    "Данные проверки устарели. Нажмите «Проверить систему»",
    "Отпечаток устройства не совпал. Откройте раздел «Подключение» и подтвердите устройство заново",
    "Роутер не совпадает с сохранённой записью. Откройте раздел «Подключение»",
    "Сохранённого доступа нет. Откройте раздел «Подключение» и сохраните доступ заново",
    "Если Wi‑Fi пропадёт, подключитесь к сети заново вручную",
    "Подробнее про интернет",
    "Профиль VPN не добавлен",
    "Опубликовать",
    "Подключение",
    "Страницы входа",
    "Все настройки рабочей сети",
    "Все настройки гостевой сети",
    "Все настройки VPN",
    "Все настройки домена",
    "Состояние системы",
    "Проверить всё",
    "Сменить",
    "Отвечает",
    "Доступ сохранён",
    "Совпадает",
    "Модем пока не поддерживается",
)

READY_CONDITION_BLOCK_START = "    } else if (\n      facts.reachable === true &&"
READY_CONDITION_BLOCK_END = "      hostKeyConfirmed === true\n    ) {"
READY_HOST_KEY_CONFIRMED_TAIL = (
    "      facts.evidence_fresh === true &&\n      hostKeyConfirmed === true"
)
HOST_KEY_NOT_CONFIRMED_GUARD = (
    """    if (hostKeyConfirmed !== true) {
      core = {
        level: SystemCheckLevel.LIMITED,
        hubState: HubState.WARNING,
        title: 'Нужно подтвердить, что это ваш роутер',
        description:
          'Перед использованием подтвердите устройство в разделе «Подключение». """
    """Подтверждение нужно один раз — при первом знакомстве с этим роутером.',
        reasonCode,
        host,
        routerId,
      };
    } else if (
      facts.reachable === true &&"""
)
READY_FACTS_CONDITION_START = """    if (
      facts.reachable === true &&"""

PWA_NEW_SHELL_RESOURCES = (
    "styles/screens.css",
    "core/session.js",
    "features/system-check.js",
    "features/overview-model.js",
)

HTTP_OVERVIEW_ASSETS = (
    "/settings/router-control/hub/features/system-check.js",
    "/settings/router-control/hub/features/overview-model.js",
    "/settings/router-control/hub/core/session.js",
    "/settings/router-control/hub/styles/screens.css",
)

GREEN_HEALTH_FACTS = {
    "reachable": True,
    "host_key_match": True,
    "tuple_match": True,
    "credentials_present": True,
    "evidence_fresh": True,
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub overview behavioral tests; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text)


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


def _extract_api_paths(*sources: Path) -> set[str]:
    paths: set[str] = set()
    for path in sources:
        text = _read(path)
        for match in API_CALL_RE.finditer(text):
            raw = next(group for group in match.groups() if group is not None)
            paths.add(_normalize_api_path(raw))
    return paths


def _extract_api_call_literals(*sources: Path) -> list[str]:
    literals: list[str] = []
    for path in sources:
        text = _read(path)
        for match in API_CALL_RE.finditer(text):
            raw = next(group for group in match.groups() if group is not None)
            literals.append(raw.strip())
    return literals


def _extract_python_function_block(source: str, signature: str) -> str:
    start = source.find(signature)
    assert start != -1, f"{signature} not found"
    next_def = source.find("\ndef ", start + len(signature))
    if next_def == -1:
        return source[start:]
    return source[start:next_def]


def _parse_reason_codes_from_backend() -> set[str]:
    source = _read(CONNECTION_HEALTH_PY)
    block = _extract_python_function_block(source, "def derive_health_status(")
    codes = set(re.findall(r'return\s+"[^"]+",\s*"([^"]+)"', block))
    assert len(codes) >= len(KNOWN_REASON_CODES), (
        f"expected at least {len(KNOWN_REASON_CODES)} reason codes from backend, "
        f"got {len(codes)}: {sorted(codes)}"
    )
    return codes


def _parse_connection_health_fact_fields() -> set[str]:
    source = _read(APPLY_RESPONSE_MODELS)
    marker = "class ConnectionHealthFactsResponse"
    start = source.find(marker)
    assert start != -1, "ConnectionHealthFactsResponse not found"
    class_block = source[start : source.find("\n\n", start)]
    return set(CLASS_FIELDS_RE.findall(class_block))


def _parse_health_fact_order() -> set[str]:
    source = _read(SYSTEM_CHECK_JS)
    match = HEALTH_FACT_ORDER_RE.search(source)
    assert match is not None, "HEALTH_FACT_ORDER not found"
    return set(re.findall(r"'([^']+)'", match.group(1)))


def _extract_reason_code_keys() -> set[str]:
    source = _read(SYSTEM_CHECK_JS)
    return _extract_top_level_keys(source, "export const REASON_CODE_TEXT = Object.freeze({")


def _extract_top_level_keys(source: str, marker: str) -> set[str]:
    start = source.index(marker)
    brace = source.find("{", start)
    if brace == -1:
        return set()
    depth = 0
    keys: set[str] = set()
    i = brace
    while i < len(source):
        char = source[i]
        if char == "{":
            depth += 1
            if depth == 1:
                i += 1
                continue
        elif char == "}":
            depth -= 1
            if depth == 0:
                break
            i += 1
            continue
        if depth == 1:
            key_match = re.match(r"\s*(\w+)\s*:", source[i:])
            if key_match:
                keys.add(key_match.group(1))
                i += key_match.end()
                continue
        i += 1
    return keys


def _is_comment_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(("//", "/*", "*"))


def _hub_available_violations() -> list[str]:
    violations: list[str] = []
    for path in sorted(HUB.rglob("*.js")):
        for line_no, line in enumerate(_read(path).splitlines(), start=1):
            if "hub_available" not in line and "hubAvailable" not in line:
                continue
            if "M-7" in line and _is_comment_line(line):
                continue
            rel = path.relative_to(REPO_ROOT)
            violations.append(f"{rel}:{line_no}: {line.strip()}")
    return violations


def _assert_render_abort_guard(body: str) -> None:
    assert "AbortController" in body, "render() must create AbortController"
    assert ".abort()" in body, "render() must abort in-flight requests"
    assert "generation" in body, "render() must track generation"
    assert re.search(r"gen\s*!==\s*generation", body), "generation guard missing"
    assert "clearInterval" in body, "render() must clear refresh interval on dispose"
    assert "removeEventListener('visibilitychange'" in body, (
        "render() must remove visibility listener on dispose"
    )


def _extract_unknown_reason_text() -> str:
    source = _read(SYSTEM_CHECK_JS)
    match = re.search(r"const UNKNOWN_REASON_TEXT = '([^']+)'", source)
    assert match is not None, "UNKNOWN_REASON_TEXT constant not found in system-check.js"
    return match.group(1)


def _green_health(
    *,
    status: str = "green",
    reason_code: str = "all_facts_healthy",
    **fact_overrides: object,
) -> dict[str, object]:
    facts = dict(GREEN_HEALTH_FACTS)
    facts.update(fact_overrides)
    return {
        "status": status,
        "reason_code": reason_code,
        "facts": facts,
    }


def _system_check_inputs_table() -> list[dict[str, object]]:
    return [
        {
            "health": None,
            "routerPresent": False,
            "hostKeyConfirmed": False,
            "adapterMode": "live",
        },
        {
            "health": None,
            "routerPresent": True,
            "hostKeyConfirmed": False,
            "adapterMode": "live",
        },
        {
            "health": _green_health(),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(),
            "routerPresent": True,
            "hostKeyConfirmed": False,
            "adapterMode": "live",
        },
        {
            "health": _green_health(tuple_match=None),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(reachable=None),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(credentials_present=False),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(evidence_fresh=None),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(host_key_match=False),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(host_key_match=None),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "fake",
        },
        {
            "health": {
                "status": "red",
                "reason_code": "unreachable",
                "facts": {"reachable": False},
            },
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": {
                "status": "red",
                "reason_code": "host_key_mismatch",
                "facts": {
                    **GREEN_HEALTH_FACTS,
                    "reachable": True,
                    "host_key_match": False,
                },
            },
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": {
                "status": "yellow",
                "reason_code": "reachability_unknown",
                "facts": {},
            },
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": {
                "status": "yellow",
                "reason_code": "unknown_reason_code_xyz",
                "facts": dict(GREEN_HEALTH_FACTS),
            },
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": _green_health(reason_code="unknown_reason_code_xyz"),
            "routerPresent": True,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
        {
            "health": None,
            "routerPresent": None,
            "hostKeyConfirmed": False,
            "adapterMode": "live",
        },
        {
            "health": _green_health(),
            "routerPresent": None,
            "hostKeyConfirmed": True,
            "adapterMode": "live",
        },
    ]


def _write_system_check_module_tree(root: Path, source: str) -> Path:
    features_dir = root / "features"
    core_dir = root / "core"
    features_dir.mkdir(parents=True, exist_ok=True)
    core_dir.mkdir(parents=True, exist_ok=True)
    for filename in ("api.js", "errors.js", "states.js"):
        shutil.copy(HUB / "core" / filename, core_dir / filename)
    module_path = features_dir / "system-check.js"
    module_path.write_text(source, encoding="utf-8")
    return module_path


def _mutate_ready_and_to_or(source: str) -> tuple[str, bool]:
    """Ослабляет READY: все «и» в условии готовности заменяются на «или»."""
    start = source.find(READY_CONDITION_BLOCK_START)
    if start == -1:
        return source, False
    end = source.find(READY_CONDITION_BLOCK_END, start)
    if end == -1:
        return source, False
    block_end = end + len(READY_CONDITION_BLOCK_END)
    block = source[start:block_end]
    mutated = block.replace(" &&", " ||")
    if mutated == block:
        return source, False
    return source[:start] + mutated + source[block_end:], True


def _mutate_remove_host_key_confirmed_requirement(source: str) -> tuple[str, bool]:
    """Ослабляет READY: убирает ранний guard и проверку hostKeyConfirmed в условии."""
    if HOST_KEY_NOT_CONFIRMED_GUARD not in source:
        return source, False
    mutated = source.replace(HOST_KEY_NOT_CONFIRMED_GUARD, READY_FACTS_CONDITION_START, 1)
    if READY_HOST_KEY_CONFIRMED_TAIL not in mutated:
        return source, False
    mutated = mutated.replace(
        READY_HOST_KEY_CONFIRMED_TAIL,
        "      facts.evidence_fresh === true",
        1,
    )
    return mutated, mutated != source


def _run_evaluate_system_check(
    inputs: list[dict[str, object]],
    module_path: Path,
    tmp_path: Path,
) -> list[dict[str, object | None]]:
    node = _require_node()
    tmp_path.mkdir(parents=True, exist_ok=True)
    harness_path = tmp_path / "run-evaluate-system-check.mjs"
    harness_path.write_text(
        f"""import {{ pathToFileURL }} from 'url';

const mod = await import({json.dumps(module_path.as_uri())});
const inputs = {json.dumps(inputs, ensure_ascii=False)};
const results = inputs.map((input) => {{
  const verdict = mod.evaluateSystemCheck(input);
  return {{
    level: verdict.level,
    hubState: verdict.hubState,
    description: verdict.description,
    title: verdict.title,
  }};
}});
console.log(JSON.stringify(results));
""",
        encoding="utf-8",
    )
    proc = subprocess.run(
        [node, str(harness_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    if proc.returncode != 0:
        pytest.fail(
            "evaluateSystemCheck node harness failed:\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}",
        )
    return json.loads(proc.stdout.strip())


@pytest.fixture
def app_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("HUB_ADMIN_PASSWORD", "test-admin-password")
    return create_app(db_path=tmp_path / "hub-overview.sqlite3", enable_worker=False)


@pytest.fixture
def authed_client(app_env):
    from fastapi.testclient import TestClient

    with TestClient(app_env) as client:
        client.cookies.set("hub_admin", mint_hub_admin_cookie())
        yield client


def test_overview_no_mock_layout_strings() -> None:
    """Регрессия M-6: в коде обзора нет захардкоженных данных из макета."""
    violations: list[str] = []
    for path in OVERVIEW_SOURCE_FILES:
        text = _read(path)
        for needle in MOCK_DATA_NEEDLES:
            if needle in text:
                violations.append(f"{path.relative_to(REPO_ROOT)}: {needle!r}")
    assert violations == []


def test_overview_hub_available_not_used() -> None:
    """Регрессия M-7: hub_available/hubAvailable не в UI (комментарий с M-7 допустим)."""
    assert _hub_available_violations() == []


def test_overview_evaluate_system_check_behavior(tmp_path: Path) -> None:
    """Регрессия M-7/D-1: evaluateSystemCheck исполняется в Node по таблице случаев."""
    unknown_reason_text = _extract_unknown_reason_text()
    inputs = _system_check_inputs_table()
    results = _run_evaluate_system_check(inputs, SYSTEM_CHECK_JS, tmp_path)

    assert results[0]["level"] == "NO_ROUTER", results[0]
    assert "не подключ" in str(results[0]["title"]).lower(), results[0]
    assert results[1]["level"] == "FAILED", results[1]
    assert results[2]["level"] == "READY", results[2]
    assert results[3]["level"] != "READY", results[3]
    assert results[4]["level"] != "READY", results[4]
    assert results[5]["level"] != "READY", results[5]
    assert results[6]["level"] != "READY", results[6]
    assert results[7]["level"] != "READY", results[7]
    assert results[8]["level"] != "READY", results[8]
    assert results[9]["level"] != "READY", results[9]
    assert results[10]["level"] == "LIMITED", results[10]
    assert results[11]["level"] == "NOT_READY", results[11]
    assert results[11]["hubState"] == "CONNECTION_LOST", results[11]
    assert results[12]["level"] == "NOT_READY", results[12]
    assert results[12]["hubState"] == "ERROR", results[12]
    assert results[12]["hubState"] != "CONNECTION_LOST", results[12]
    assert results[13]["level"] == "LIMITED", results[13]
    assert results[13]["description"], "yellow verdict must expose a reason description"
    assert CYRILLIC.search(str(results[13]["description"])), results[13]
    assert results[14]["level"] == "LIMITED", results[14]
    assert results[14]["description"] == unknown_reason_text, results[14]
    assert results[15]["description"], "unknown reason_code must not yield empty description"
    assert results[15]["level"] == "READY", results[15]
    assert results[16]["level"] == "FAILED", results[16]
    assert "не подключ" not in str(results[16]["title"]).lower(), results[16]
    assert results[16]["description"], "routerPresent=null must expose non-empty description"
    assert CYRILLIC.search(str(results[16]["title"])), results[16]
    assert results[17]["level"] == "FAILED", results[17]
    assert "не подключ" not in str(results[17]["title"]).lower(), results[17]
    assert results[17]["description"], (
        "routerPresent=null with health must not crash and must stay honest"
    )


def test_detector_evaluate_system_check_catches_broken_ready_and_or(tmp_path: Path) -> None:
    """Самопроверка: OR вместо AND в условии READY ловится на случае №5 (tuple_match=null)."""
    source = _read(SYSTEM_CHECK_JS)
    broken_source, applied = _mutate_ready_and_to_or(source)
    assert applied, (
        "mutation AND→OR must apply to production system-check.js "
        f"(looked for block starting with {READY_CONDITION_BLOCK_START!r})"
    )
    assert broken_source != source, "broken copy must differ from production module"
    broken_module = _write_system_check_module_tree(tmp_path / "broken-and-or", broken_source)

    inputs = _system_check_inputs_table()
    good_results = _run_evaluate_system_check(inputs, SYSTEM_CHECK_JS, tmp_path / "good")
    broken_results = _run_evaluate_system_check(inputs, broken_module, tmp_path / "run")

    assert good_results[4]["level"] != "READY", "case #5 must stay non-READY in production"
    assert broken_results[4]["level"] == "READY", (
        "broken OR logic must incorrectly mark case #5 (tuple_match=null) as READY"
    )


def test_detector_evaluate_system_check_catches_broken_ready_no_confirm(
    tmp_path: Path,
) -> None:
    """Самопроверка: без hostKeyConfirmed READY ловится на случае №4 (не подтверждён)."""
    source = _read(SYSTEM_CHECK_JS)
    broken_source, applied = _mutate_remove_host_key_confirmed_requirement(source)
    assert applied, (
        "mutation remove hostKeyConfirmed must apply to production system-check.js "
        f"(looked for guard block and {READY_HOST_KEY_CONFIRMED_TAIL!r})"
    )
    assert broken_source != source, "broken copy must differ from production module"
    broken_module = _write_system_check_module_tree(
        tmp_path / "broken-no-confirm",
        broken_source,
    )

    inputs = _system_check_inputs_table()
    good_results = _run_evaluate_system_check(inputs, SYSTEM_CHECK_JS, tmp_path / "good")
    broken_results = _run_evaluate_system_check(inputs, broken_module, tmp_path / "run")

    assert good_results[3]["level"] != "READY", "case #4 must stay non-READY in production"
    assert broken_results[3]["level"] == "READY", (
        "broken READY logic must incorrectly mark case #4 (hostKeyConfirmed=false) as READY"
    )


def test_overview_reason_codes_synced_with_backend() -> None:
    """Регрессия: reason_code backend покрыты REASON_CODE_TEXT (без «Причина не распознана»)."""
    backend_codes = _parse_reason_codes_from_backend()
    frontend_keys = _extract_reason_code_keys()
    backend_source = _read(CONNECTION_HEALTH_PY)
    for code in backend_codes:
        assert code in backend_source, f"{code} must exist in connection_health.py"
    missing = sorted(backend_codes - frontend_keys)
    assert missing == [], f"REASON_CODE_TEXT missing keys: {missing}"


def test_overview_health_fact_order_matches_model() -> None:
    """Регрессия: HEALTH_FACT_ORDER совпадает с полями ConnectionHealthFactsResponse."""
    model_fields = _parse_connection_health_fact_fields()
    order_fields = _parse_health_fact_order()
    assert order_fields == model_fields


def test_overview_api_paths_exist_in_openapi() -> None:
    """Регрессия M-6: все apiGet/apiPost обзора существуют в openapi-v0.json."""
    frontend_paths = _extract_api_paths(OVERVIEW_MODEL_JS, SYSTEM_CHECK_JS, SHELL_JS)
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


def test_detector_api_paths_catches_fabricated_endpoint() -> None:
    """Самопроверка: выдуманный routers/list не сопоставляется с OpenAPI."""
    openapi_paths = _openapi_paths()
    fake_segments = _path_segments("routers/list")
    assert not any(
        _segments_match(fake_segments, _path_segments(api_path))
        for api_path in openapi_paths
    ), "routers/list must not match any OpenAPI route"


def test_overview_vpn_domain_no_success_state() -> None:
    """Регрессия F-6/D-10: VPN и домен не показывают HubState.SUCCESS без API-подтверждения."""
    source = _read(OVERVIEW_MODEL_JS)
    vpn_body = _extract_function_body(source, "function buildVpnSection(")
    domain_body = _extract_function_body(source, "function buildDomainSection(")
    assert vpn_body is not None and domain_body is not None
    assert "HubState.SUCCESS" not in vpn_body, "buildVpnSection must not use HubState.SUCCESS"
    assert "HubState.SUCCESS" not in domain_body, "buildDomainSection must not use HubState.SUCCESS"


def test_overview_events_section_unsupported_no_fabricated_entries() -> None:
    """R-9: события не на главном пути — ни mountEventsBlock, ни «Последние события»."""
    screen_source = _read(OVERVIEW_JS)
    for needle in MOCK_EVENT_TEXTS:
        assert needle not in screen_source, f"overview.js contains mock event: {needle!r}"
    assert "mountEventsBlock" not in screen_source
    assert "eventsWrap" not in screen_source
    assert "Последние события" not in screen_source
    assert "model.events" not in screen_source and "model?.events" not in screen_source

    model_source = _read(OVERVIEW_MODEL_JS)
    assert "buildEventsSection" not in model_source
    load_body = _extract_function_body(model_source, "export async function loadOverview(")
    assert load_body is not None
    assert "events:" not in load_body


def test_overview_router_present_unknown_when_routers_fetch_fails() -> None:
    """При ошибке GET /routers в system-check передаётся routerPresent=null, не false."""
    source = _read(OVERVIEW_MODEL_JS)
    load_body = _extract_function_body(source, "export async function loadOverview(")
    assert load_body is not None
    normalized = _normalize_whitespace(load_body)
    assert re.search(r"if \(routersError\) \{ routerPresent = null", normalized)
    assert re.search(
        r"else if \(routerItems\.length === 0\) \{ routerPresent = false",
        normalized,
    )
    assert re.search(r"else \{ routerPresent = true", normalized)
    assert "routerPresent," in normalized or "routerPresent\n" in load_body


DEVICE_COUNTER_RE = re.compile(
    r"\d+\s+устройств|\bустройств\b.*\d+|\d+\s+.*устройств",
    re.IGNORECASE,
)
REALISTIC_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"


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


def _overview_session_with_staff_role() -> dict[str, object]:
    return {
        "routerId": "router-lab-1",
        "routerHost": "10.0.0.1",
        "hostKeyConfirmed": True,
        "wifiLive": {
            "host": "10.0.0.1",
            "username": "admin",
            "credentialRefId": "cred-ref-1",
            "sshHostKeySha256": REALISTIC_FINGERPRINT,
        },
        "wifiRoles": {"staffApId": "WifiMaster0/AccessPoint4", "guestApId": None},
    }


def _overview_fetch_mock_script(
    *,
    wifi_observed_response: dict[str, object] | None,
    wifi_observed_status: int = 200,
    wifi_observed_error: dict[str, object] | None = None,
) -> str:
    wifi_payload = json.dumps(wifi_observed_response, ensure_ascii=False)
    wifi_status = wifi_observed_status
    wifi_error_body = json.dumps(wifi_observed_error, ensure_ascii=False)
    return f"""
const captured = [];
globalThis.fetch = async (url, init) => {{
  const path = String(url).replace(/^.*\\/api\\/router-control\\/v1\\//, '');
  let body = null;
  if (init?.body) {{
    body = JSON.parse(String(init.body));
  }}
  captured.push({{ path, method: init?.method ?? 'GET', body }});

  if (path === 'routers') {{
    return new Response(JSON.stringify({{
      items: [{{
        router_id: 'router-lab-1',
        display_name: 'Lab Router',
        vendor: 'Keenetic',
        model: 'Hopper',
      }}],
    }}), {{ status: 200, headers: {{ 'Content-Type': 'application/json' }} }});
  }}

  if (path === 'lab/connection-health') {{
    return new Response(JSON.stringify({{
      status: 'green',
      reason_code: 'all_facts_healthy',
      facts: {{
        reachable: true,
        host_key_match: true,
        tuple_match: true,
        credentials_present: true,
        evidence_fresh: true,
      }},
    }}), {{ status: 200, headers: {{ 'Content-Type': 'application/json' }} }});
  }}

  if (path === 'vpn-profiles') {{
    return new Response(JSON.stringify({{ items: [] }}), {{
      status: 200,
      headers: {{ 'Content-Type': 'application/json' }},
    }});
  }}

  if (path === 'keendns/status') {{
    return new Response(JSON.stringify({{
      feature_availability: 'unknown',
      name_reservation: 'unknown',
      access_mode: 'unknown',
    }}), {{ status: 200, headers: {{ 'Content-Type': 'application/json' }} }});
  }}

  if (path === 'entry-pages') {{
    return new Response(JSON.stringify({{ items: [] }}), {{
      status: 200,
      headers: {{ 'Content-Type': 'application/json' }},
    }});
  }}

  if (path === 'wifi/observed-state') {{
    if ({wifi_status} !== 200) {{
      return new Response({wifi_error_body}, {{
        status: {wifi_status},
        headers: {{ 'Content-Type': 'application/json' }},
      }});
    }}
    return new Response(JSON.stringify({wifi_payload}), {{
      status: 200,
      headers: {{ 'Content-Type': 'application/json' }},
    }});
  }}

  return new Response(JSON.stringify({{ error: {{ code: 'http.404', message: 'not found' }} }}), {{
    status: 404,
    headers: {{ 'Content-Type': 'application/json' }},
  }});
}};
"""


def _run_overview_load(
    tmp_path: Path,
    *,
    label: str,
    session: dict[str, object],
    fetch_mock: str,
) -> dict[str, object]:
    script = f"""{fetch_mock}
const mod = await import({json.dumps(OVERVIEW_MODEL_JS.as_uri())});
const model = await mod.loadOverview({{
  session: {json.dumps(session, ensure_ascii=False)},
  runtime: {{ adapterMode: 'live' }},
}});
console.log(JSON.stringify({{ model, captured }}));
"""
    return _run_node_harness(script, tmp_path, label)  # type: ignore[return-value]


def test_overview_wifi_sections_static_no_network() -> None:
    """Wi‑Fi observed — в overview-simple-networks (enrichment), не в loadOverview."""
    model_source = _read(OVERVIEW_MODEL_JS)
    load_body = _extract_function_body(model_source, "export async function loadOverview(")
    assert load_body is not None
    assert "wifi/observed-state" not in load_body, (
        "loadOverview must not fetch wifi/observed-state — enrichment owns it"
    )

    networks_source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "fetchStaffWifiObservedState" in networks_source
    assert "fetchGuestWifiObservedState" in networks_source
    assert "loadAndUpdate" in networks_source

    unassigned_body = _extract_function_body(
        model_source,
        "function buildUnassignedWifiRoleSection(",
    )
    assert unassigned_body is not None
    assert "HubState.UNSUPPORTED" in unassigned_body
    assert "routeId: 'staff-wifi'" in networks_source
    assert "routeId: 'guest-wifi'" in networks_source
    assert "wireOverviewCardNavigate(card, routeId, navigate)" in networks_source


def test_overview_wifi_role_unassigned_no_observed_state_call(tmp_path: Path) -> None:
    """loadOverview не тянет wifi/observed-state; enrichment откладывается на экран."""
    session = _overview_session_with_staff_role()
    session["wifiRoles"] = {"staffApId": None, "guestApId": None}
    mock = _overview_fetch_mock_script(wifi_observed_response={"access_points": []})
    payload = _run_overview_load(
        tmp_path, label="wifi-unassigned", session=session, fetch_mock=mock,
    )
    captured = payload["captured"]
    wifi_calls = [call for call in captured if call["path"] == "wifi/observed-state"]
    assert wifi_calls == []
    assert "staffWifi" not in payload["model"]
    assert "guestWifi" not in payload["model"]


def test_overview_wifi_unassigned_mock_in_fake_adapter_mode(tmp_path: Path) -> None:
    """Без ролей в fake-adapter карточки показывают честный UNSUPPORTED + select назначения."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    networks_uri = json.dumps(OVERVIEW_SIMPLE_NETWORKS_JS.as_uri())
    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();

function patchElement(el) {{
  if (!el.getAttributeNames) {{
    el.getAttributeNames = () => Object.keys(el.attributes || {{}});
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
  open() {{ return null; }},
  addEventListener() {{}},
  removeEventListener() {{}},
  dispatchEvent() {{ return true; }},
  matchMedia() {{
    return {{ matches: false, addEventListener() {{}}, removeEventListener() {{}} }};
  }},
}};
globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

globalThis.fetch = async (url) => {{
  const path = String(url).replace(/^.*\\/api\\/router-control\\/v1\\//, '');
  if (path === 'standing-network-preferences') {{
    return new Response(JSON.stringify({{}}), {{
      status: 200,
      headers: {{ 'Content-Type': 'application/json' }},
    }});
  }}
  return new Response(JSON.stringify({{ error: {{ code: 'http.404', message: 'not found' }} }}), {{
    status: 404,
    headers: {{ 'Content-Type': 'application/json' }},
  }});
}};

const {{ mountOverviewSimpleNetworks }} = await import({networks_uri});

const session = {{
  routerId: 'router-lab-1',
  hostKeyConfirmed: true,
  wifiRoles: {{ staffApId: null, guestApId: null }},
}};

const container = dom.document.createElement('div');
dom.document.body.appendChild(container);

const staffSlot = dom.document.createElement('div');
staffSlot.className = 'hub-overview__staff-slot';
const guestSlot = dom.document.createElement('div');
guestSlot.className = 'hub-overview__guest-slot';
container.appendChild(staffSlot);
container.appendChild(guestSlot);

const mount = mountOverviewSimpleNetworks({{
  staffSlot,
  guestSlot,
  getSession: () => session,
  adapterMode: 'fake',
  navigate: () => {{}},
  isRestorePending: () => false,
  idPrefix: 'hub-overview-networks',
}});

await mount.loadAndUpdate();

function inspectCard(className) {{
  const card = document.querySelector(className);
  const panel = card?.querySelector('.hub-state-panel');
  return {{
    hasPanel: Boolean(panel),
    panelTitle: panel?.querySelector('.hub-state-panel__title')?.textContent ?? '',
    panelDescription: panel?.querySelector('.hub-state-panel__description')?.textContent ?? '',
    badgeCount: card?.querySelectorAll('.hub-badge').length ?? 0,
    ssidCount: card?.querySelectorAll('.hub-overview-networks__ssid').length ?? 0,
    toggleCount: card?.querySelectorAll('.hub-toggle').length ?? 0,
    selectCount: card?.querySelectorAll('.hub-field__select').length ?? 0,
    staffEnableButton: Boolean(card?.querySelector('#hub-overview-networks-staff-enable')),
    guestEnableToggle: Boolean(card?.querySelector('#hub-overview-networks-guest-enabled')),
  }};
}}

console.log(JSON.stringify({{
  staff: inspectCard('.hub-overview-networks__staff'),
  guest: inspectCard('.hub-overview-networks__guest'),
}}));

mount.destroy();
"""
    payload = _run_node_harness(script, tmp_path, "wifi-unassigned-fake-dom")  # type: ignore[assignment]
    staff = payload["staff"]
    guest = payload["guest"]

    assert staff["hasPanel"] is True
    assert staff["panelTitle"] == "Роутер не сообщает, какая сеть рабочая"
    assert staff["panelDescription"] == "Настройка и состояние — в самом разделе."
    assert staff["badgeCount"] == 0
    assert staff["ssidCount"] == 0
    assert staff["toggleCount"] == 0
    assert staff["selectCount"] == 1
    assert staff["staffEnableButton"] is False

    assert guest["hasPanel"] is True
    assert guest["panelTitle"] == "Роутер не сообщает, какая сеть гостевая"
    assert guest["panelDescription"] == "Настройка и состояние — в самом разделе."
    assert guest["badgeCount"] == 0
    assert guest["ssidCount"] == 0
    assert guest["toggleCount"] == 0
    assert guest["selectCount"] == 1
    assert guest["guestEnableToggle"] is False


def test_overview_wifi_role_observed_ssid_in_section(tmp_path: Path) -> None:
    """overview-simple-networks показывает SSID из observed (не loadOverview)."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "staffObserved.ssid" in source or "staffObserved?.ssid" in source
    assert "createStaffWifiFormDraft" in source


def test_overview_wifi_role_missing_ssid_honest_label(tmp_path: Path) -> None:
    """Networks module: честный fallback SSID."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "STAFF_WIFI_STANDING_SSID_SEED" in source
    assert "Состояние рабочей сети не прочитано" in source


def test_overview_wifi_role_fetch_error_other_sections_filled(tmp_path: Path) -> None:
    """loadOverview без wifi-секций: router/systemCheck/domain остаются."""
    session = _overview_session_with_staff_role()
    mock = _overview_fetch_mock_script(
        wifi_observed_response=None,
        wifi_observed_status=503,
        wifi_observed_error={
            "error": {
                "code": "server.unavailable",
                "message": "backend down",
            },
        },
    )
    payload = _run_overview_load(
        tmp_path, label="wifi-fetch-error", session=session, fetch_mock=mock,
    )
    model = payload["model"]

    assert model["router"]["title"] == "Lab Router"
    assert model["systemCheck"]["title"]
    assert model["domain"]["title"] == "Домен"
    assert "staffWifi" not in model
    assert "vpn" not in model


def test_overview_wifi_role_section_no_device_counter(tmp_path: Path) -> None:
    """Networks module не показывает счётчик устройств."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    normalized = _normalize_whitespace(source).lower()
    assert "устройств" not in normalized
    assert "device_connected" not in source


def test_overview_wifi_role_section_mock_in_fake_adapter_mode(tmp_path: Path) -> None:
    """loadOverview в fake: systemCheck mock, без wifi tile sections."""
    session = _overview_session_with_staff_role()
    mock = _overview_fetch_mock_script(
        wifi_observed_response={
            "access_points": [{
                "ap_id": "WifiMaster0/AccessPoint4",
                "band": "2.4GHz",
                "ssid": "Demo-Staff-Net",
                "enabled_or_up": True,
                "link_up": True,
                "wpa_mode": "WPA2",
                "readable": True,
            }],
        },
    )
    script = f"""{mock}
const mod = await import({json.dumps(OVERVIEW_MODEL_JS.as_uri())});
const model = await mod.loadOverview({{
  session: {json.dumps(session, ensure_ascii=False)},
  runtime: {{ adapterMode: 'fake' }},
}});
console.log(JSON.stringify({{
  systemCheckMock: model.systemCheck.mock,
  hasStaffWifi: Object.prototype.hasOwnProperty.call(model, 'staffWifi'),
}}));
"""
    payload = _run_node_harness(script, tmp_path, "wifi-fake-mock")  # type: ignore[assignment]
    assert payload["systemCheckMock"] is True
    assert payload["hasStaffWifi"] is False


def test_overview_domain_technical_translated_no_raw_notes() -> None:
    """Домен: notes из API не попадают в UI, technical только через перевод значений."""
    source = _read(OVERVIEW_MODEL_JS)
    domain_body = _extract_function_body(source, "function buildDomainSection(")
    assert domain_body is not None
    assert "translateDomainValue" in domain_body
    notes_pattern = re.compile(
        r"payload\s*\?\.\s*notes|payload\s*\.\s*notes|\bnotes\b",
    )
    assert notes_pattern.search(domain_body) is None, (
        "buildDomainSection must not expose backend notes to users"
    )
    assert "feature_availability" in domain_body
    assert "DOMAIN_VALUE_LABELS" in source


def test_overview_entry_pages_not_fetched_on_load(tmp_path: Path) -> None:
    """R-9: loadOverview не вызывает GET entry-pages; quiet link на экране."""
    session = _overview_session_with_staff_role()
    mock = _overview_fetch_mock_script(
        wifi_observed_response={"access_points": []},
    )
    payload = _run_overview_load(
        tmp_path,
        label="entry-pages-not-in-load",
        session=session,
        fetch_mock=mock,
    )
    entry_calls = [call for call in payload["captured"] if call["path"] == "entry-pages"]
    assert entry_calls == [], "loadOverview must not call GET entry-pages"
    assert "entryPages" not in payload["model"]
    screen_source = _read(OVERVIEW_JS)
    assert "Страницы входа" in screen_source
    assert "#/entry-pages" in screen_source


def test_overview_render_has_abort_and_generation_guard() -> None:
    """Регрессия: экран отменяет запросы и игнорирует устаревшие ответы."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None, "render() body must be parseable"
    _assert_render_abort_guard(body)
    assert re.search(r"return\s*\(\)\s*=>", source[source.find("export function render(") :])


def test_detector_overview_render_catches_missing_abort() -> None:
    """Самопроверка: render без AbortController должен ломать контракт."""
    bad_body = "let generation = 0; void reloadOverview();"
    with pytest.raises(AssertionError):
        _assert_render_abort_guard(bad_body)
    good_body = _extract_function_body(_read(OVERVIEW_JS), "export function render(")
    assert good_body is not None
    _assert_render_abort_guard(good_body)


def test_overview_r9_action_slots_no_technical_expander() -> None:
    """R-9: нет TILE_CONFIG/technical expander; actionable slots + signature gating."""
    source = _read(OVERVIEW_JS)
    render_body = _extract_function_body(source, "export function render(")
    assert render_body is not None

    assert "TILE_CONFIG" not in source
    assert "renderTechnicalBlock" not in source
    assert "createTechnicalDetails" not in source
    assert "mountOverviewSimpleNetworks" in source
    assert "buildInternetStatusCard" in source
    assert "renderInternetCardSlot" in source
    assert "mountDomainSimplePublishAffordance" in source
    # Компактный выбираемый picker на «Обзоре» больше не тянет за собой
    # полноценную сетку профилей с кнопками управления с экрана #/vpn.
    assert "buildOverviewVpnProfilePicker" in source
    assert "createVpnProfileStatusTileGrid" not in source
    assert "runOverviewEnrichment" in render_body
    assert "isConnectionRestorePending" in render_body


def test_overview_internet_simple_honesty_no_autoconnect_promise() -> None:
    """R-2/R-15: overview internet card без mountInternetSourceAffordance; честные pills."""
    screen = _read(OVERVIEW_JS)
    assert "mountInternetSourceAffordance" not in screen
    assert "buildInternetStatusCard" in screen
    assert "renderInternetCardSlot" in screen
    grid = _read(OVERVIEW_CARD_GRID_JS)
    assert "describeInternetSource" in grid
    assert "INTERNET_SOURCE_MODEM_NOTE" in grid
    # Подпись плитки обязана сама нести состояние: иконка без текста читается как
    # утверждение («Интернет доступен») даже при false/неизвестном значении.
    assert "unknown: 'Автоподключение: неизвестно'" in grid
    assert "no: 'Автоподключение выключено'" in grid
    assert "unknown: 'Интернет: неизвестно'" in grid
    assert "no: 'Интернета нет'" in grid
    internet = _read(OVERVIEW_INTERNET_SIMPLE_JS)
    assert "Если Wi‑Fi пропадёт, подключитесь к сети заново вручную — автоматическое восстановление связи на роутере не подтверждено." in internet


def test_overview_networks_no_auto_apply_on_mount() -> None:
    """R-3…R-6: networks module не вызывает apply* на mount/update до enrichment."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    load_body = _extract_function_body(source, "async function loadAndUpdate(")
    assert load_body is not None
    assert "applyStaffWifiChanges" not in load_body
    assert "applyGuestWifiChanges" not in load_body
    update_body = _extract_function_body(source, "function update()")
    assert update_body is not None
    assert "applyStaffWifiChanges" not in update_body
    assert "applyGuestWifiChanges" not in update_body
    assert "runMutation" not in update_body


def test_overview_handles_total_load_failure() -> None:
    """Полный отказ loadOverview рисует панель с повтором; есть disposed и generation."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    assert "renderLoadErrorPanel" in body
    assert "Повторить" in body
    assert "disposed" in body
    assert "generation" in body
    assert "catch (error)" in body


def test_overview_heading_levels_use_h2() -> None:
    """Карточки главного экрана используют h2."""
    source = _read(OVERVIEW_JS)
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    # Заголовок VPN-карточки собирает buildVpnStatusCardShell в card-grid;
    # в overview.js остаётся только вызов этой единственной реализации.
    assert "buildVpnStatusCardShell" in source
    assert "hub-overview__vpn-heading" in grid_source
    assert "hub-overview-step-card__title" in grid_source
    networks_source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "hub-overview-step-card__title" in networks_source
    assert "createElement('h2')" in networks_source


def test_overview_pwa_shell_urls_updated() -> None:
    """Регрессия: SW precache включает новые ресурсы обзора и CACHE_VERSION > 2."""
    source = _read(SW_JS)
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None
    assert int(version_match.group(1)) > 2
    for resource in PWA_NEW_SHELL_RESOURCES:
        assert resource in source, f"SHELL_URLS must include {resource}"


def test_overview_new_assets_served_over_http(authed_client) -> None:
    """Регрессия: новые статические ресурсы обзора отдаются с 200 и непустым телом."""
    for url in HTTP_OVERVIEW_ASSETS:
        response = authed_client.get(url)
        assert response.status_code == 200, url
        assert len(response.content) > 0, url
    index = authed_client.get("/settings/router-control/hub/index.html")
    assert index.status_code == 200
    assert 'href="/settings/router-control/hub/styles/screens.css"' in index.text


def test_overview_user_strings_russian() -> None:
    """Регрессия: заметные пользовательские строки обзора на русском."""
    domain_simple = _read(HUB / "features" / "domain-simple-publish.js")
    combined = (
        _read(OVERVIEW_JS)
        + _read(OVERVIEW_MODEL_JS)
        + _read(OVERVIEW_CARD_GRID_JS)
        + _read(HUB / "features" / "internet-source-block.js")
        + _read(OVERVIEW_INTERNET_SIMPLE_JS)
        + _read(OVERVIEW_SIMPLE_NETWORKS_JS)
        + _read(SYSTEM_CHECK_JS)
        + domain_simple
    )
    normalized = _normalize_whitespace(combined)
    missing = [
        msg for msg in OVERVIEW_USER_MESSAGES
        if _normalize_whitespace(msg) not in normalized
    ]
    assert missing == [], f"expected user messages missing from overview sources: {missing}"
    non_cyrillic = [msg for msg in OVERVIEW_USER_MESSAGES if not CYRILLIC.search(msg)]
    assert non_cyrillic == []


def test_overview_offline_no_model_shows_retry_panel() -> None:
    """Без связи и без модели рисуется панель «нет интернета», а не скелетон."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    normalized = _normalize_whitespace(body)
    assert "renderOfflineNoModelPanel" in normalized
    assert "HubState.NO_INTERNET" in normalized
    assert _normalize_whitespace("Повторить") in normalized
    offline_panel_body = _extract_function_body(source, "function renderOfflineNoModelPanel(")
    assert offline_panel_body is not None
    render_summary_body = _extract_function_body(source, "function renderSummary(")
    assert render_summary_body is not None
    normalized_summary = _normalize_whitespace(render_summary_body)
    assert "if (offline)" in normalized_summary
    assert "renderOfflineNoModelPanel()" in normalized_summary
    assert re.search(r"if\s*\(\s*!model\s*\)", normalized_summary)


def test_overview_busy_flags_reset_by_generation_in_finally() -> None:
    """Флаги занятости сбрасываются в finally с привязкой к поколению."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    normalized = _normalize_whitespace(body)
    for name in (
        "refreshBusyGeneration",
        "loadingGeneration",
        "systemCheckRunningGeneration",
    ):
        assert name in normalized, f"{name} must be tracked by generation"
    reload_body = _extract_function_body(source, "async function reloadOverviewInternal(")
    assert reload_body is not None
    normalized_reload = _normalize_whitespace(reload_body)
    assert "finally" in normalized_reload
    assert "loadingGeneration === gen" in normalized_reload
    assert "refreshBusyGeneration === gen" in normalized_reload
    system_check_body = _extract_function_body(source, "async function runSystemCheckOnly(")
    assert system_check_body is not None
    normalized_check = _normalize_whitespace(system_check_body)
    assert "finally" in normalized_check
    assert "systemCheckRunningGeneration === gen" in normalized_check
    reload_finally = normalized_reload.split("finally", 1)[1]
    assert "renderSummary()" in reload_finally, (
        "reloadOverviewInternal must re-paint summary after clearing systemCheckRunning"
    )
    sc_false_idx = reload_finally.find("systemCheckRunning = false")
    render_idx = reload_finally.find("renderSummary()")
    assert sc_false_idx != -1 and render_idx != -1
    assert sc_false_idx < render_idx, (
        "renderSummary must run after systemCheckRunning is cleared in finally"
    )
    check_finally = normalized_check.split("finally", 1)[1]
    assert "renderSummary()" in check_finally


def test_overview_content_signature_skips_redundant_rerender() -> None:
    """Пропуск перерисовки по подписи содержимого summary и VPN-слота."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    normalized = _normalize_whitespace(body)
    assert "lastSummarySignature" in normalized
    assert "lastVpnSignature" in normalized
    assert "buildSummaryContentSignature" in normalized
    assert "buildVpnSlotSignature" in normalized
    render_summary_body = _extract_function_body(source, "function renderSummary(")
    assert render_summary_body is not None
    normalized_summary = _normalize_whitespace(render_summary_body)
    assert "signature === lastSummarySignature" in normalized_summary
    render_vpn_body = _extract_function_body(source, "function renderVpnSlot(")
    assert render_vpn_body is not None
    normalized_vpn = _normalize_whitespace(render_vpn_body)
    assert "signature === lastVpnSignature" in normalized_vpn


def test_overview_router_section_always_links_connection() -> None:
    """Секция роутера всегда ведёт в #/connection."""
    source = _read(OVERVIEW_MODEL_JS)
    router_body = _extract_function_body(source, "function buildRouterSection(")
    assert router_body is not None
    normalized = _normalize_whitespace(router_body)
    assert normalized.count("#/connection") >= 3, (
        "buildRouterSection must set route #/connection for error, empty, and connected states"
    )
    assert "route: null" not in normalized.replace("defaults.route ?? null", "")


def test_overview_vpn_section_no_profile_kind_subtitle() -> None:
    """VPN не показывает технический тип профиля как подпись пользователю."""
    source = _read(OVERVIEW_MODEL_JS)
    vpn_body = _extract_function_body(source, "function buildVpnSection(")
    assert vpn_body is not None
    profile_tail = vpn_body.split("const profile = items[0]")[-1]
    assert "vpn_kind" not in profile_tail
    assert re.search(r"subtitle:\s*null", _normalize_whitespace(profile_tail)), (
        "buildVpnSection must not derive user subtitle from profile kind"
    )


def test_overview_internet_banner_shows_only_when_no_internet_ok() -> None:
    """Баннер «Нет интернета — подключить» только при read_status ok и internet false."""
    source = _read(OVERVIEW_JS)
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    normalized = _normalize_whitespace(banner_body)
    assert "read_status === 'ok'" in normalized
    assert "internet === false" in normalized
    assert "Нет интернета — подключить" in banner_body
    assert "internet-uplink" in banner_body


def test_overview_internet_banner_silent_when_read_failed() -> None:
    """При read_status failed баннер интернета не показывается."""
    source = _read(OVERVIEW_JS)
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    assert "read_status === 'failed'" not in _normalize_whitespace(banner_body)
    assert "fetchRouterInternetObserve" in source


def test_overview_internet_banner_not_shown_for_internet_true() -> None:
    """При internet true отдельный connect-баннер не создаётся."""
    source = _read(OVERVIEW_JS)
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    assert "internet === true" not in _normalize_whitespace(banner_body)
    assert "signature: 'no-internet'" in banner_body


def test_overview_auto_connect_waits_restore_settle() -> None:
    """Все пути reloadOverview ждут settle restore; нет гонки с pending."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    normalized = _normalize_whitespace(body)
    assert "waitForConnectionRestoreSettle" in normalized
    assert "ensureOverviewLoadedAfterRestore" in normalized
    assert "requestReloadOverview" in normalized
    assert "isConnectionRestorePending" in normalized
    for entry in (
        "refreshInterval = setInterval",
        "onVisibilityChange",
        "subscribeConnectivity",
        "void ensureOverviewLoadedAfterRestore()",
    ):
        assert entry.replace(" ", "") in normalized.replace(" ", ""), entry
    reload_body = _extract_function_body(source, "async function reloadOverviewInternal(")
    assert reload_body is not None
    assert "isConnectionRestorePending" in _normalize_whitespace(reload_body)


def test_overview_auto_connect_single_flight_restore_load() -> None:
    """Single-flight: один waiter владеет post-settle load."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    normalized = _normalize_whitespace(body)
    assert "restoreSettleLoadPromise" in normalized
    ensure_body = _extract_function_body(source, "async function ensureOverviewLoadedAfterRestore(")
    assert ensure_body is not None
    assert "restoreSettleLoadPromise" in _normalize_whitespace(ensure_body)
    assert "reloadOverviewInternal" in ensure_body
    assert "restoreJustSettled" not in source


def test_overview_ensure_finally_does_not_clear_reload_progress() -> None:
    """ensure finally не сбрасывает progress reloadOverviewInternal."""
    source = _read(OVERVIEW_JS)
    ensure_body = _extract_function_body(source, "async function ensureOverviewLoadedAfterRestore(")
    assert ensure_body is not None
    normalized = _normalize_whitespace(ensure_body)
    finally_part = normalized.split("finally", 1)[1]
    assert "clearRestoreOrProbeProgress" not in finally_part
    catch_part = normalized.split("catch", 1)[1].split("finally", 1)[0]
    assert "clearRestoreOrProbeProgress" in catch_part


def test_overview_reload_single_flight_join() -> None:
    """requestReloadOverview/reloadOverviewInternal join in-flight reload."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    normalized = _normalize_whitespace(body)
    assert "inFlightReloadPromise" in normalized
    reload_body = _extract_function_body(source, "async function reloadOverviewInternal(")
    assert reload_body is not None
    normalized_reload = _normalize_whitespace(reload_body)
    assert "if(inFlightReloadPromise)" in normalized_reload.replace(" ", "")
    assert "inFlightReloadPromise=null" in normalized_reload.replace(" ", "")
    request_body = _extract_function_body(source, "async function requestReloadOverview(")
    assert request_body is not None
    assert "reloadOverviewInternal" in request_body


def test_overview_health_transient_retry_constants() -> None:
    """Bounded retry только NETWORK|TIMEOUT|SERVER; константы max attempts."""
    source = _read(SYSTEM_CHECK_JS)
    assert "SYSTEM_CHECK_TRANSIENT_MAX_ATTEMPTS = 3" in source
    assert "runSystemCheckWithTransientRetry" in source
    assert "ERROR_KIND.NETWORK" in source
    assert "ERROR_KIND.TIMEOUT" in source
    assert "ERROR_KIND.SERVER" in source
    retry_kinds_start = source.find("SYSTEM_CHECK_TRANSIENT_RETRY_KINDS")
    assert retry_kinds_start != -1
    retry_kinds_block = source[retry_kinds_start : source.find("]);", retry_kinds_start) + 3]
    for non_retry_kind in (
        "VALIDATION",
        "UNAUTHORIZED",
        "FORBIDDEN",
        "DEVICE",
        "ABORTED",
    ):
        assert non_retry_kind not in retry_kinds_block, (
            f"{non_retry_kind} must not be retried by transient health retry"
        )
    retry_body = _extract_function_body(
        source, "export async function runSystemCheckWithTransientRetry("
    )
    assert retry_body is not None
    normalized_retry = _normalize_whitespace(retry_body)
    assert "isTransientHealthRetryError" in normalized_retry
    assert "signal?.aborted" in normalized_retry
    assert "ERROR_KIND.ABORTED" in normalized_retry
    assert "sleepWithAbort" in normalized_retry
    abort_before_sleep = normalized_retry.find("signal?.aborted")
    sleep_idx = normalized_retry.find("sleepWithAbort")
    assert abort_before_sleep != -1 and sleep_idx != -1
    assert abort_before_sleep < sleep_idx, "abort must be checked before backoff sleep"
    model_source = _read(OVERVIEW_MODEL_JS)
    assert "runSystemCheckWithTransientRetry" in model_source
    assert "runSystemCheck(" not in model_source.replace("runSystemCheckWithTransientRetry", "")


def test_overview_restore_failed_primary_retry() -> None:
    """restore-failed: primary «Повторить», не «Открыть Подключение»."""
    source = _read(OVERVIEW_JS)
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    assert "retryRestoreConnection" in banner_body
    assert "label: 'Повторить'" in banner_body
    assert "retryConnectionContextRestore" in source
    failed_idx = banner_body.find("signature: 'failed'")
    assert failed_idx != -1
    failed_block = banner_body[failed_idx : failed_idx + 800]
    retry_idx = failed_block.find("label: 'Повторить'")
    connection_idx = failed_block.find("Открыть «Подключение»")
    assert retry_idx != -1 and connection_idx != -1
    assert retry_idx < connection_idx


def test_overview_username_recovery_inline_form() -> None:
    """Username recovery: inline form на overview, не navigate как primary."""
    source = _read(OVERVIEW_JS)
    assert "submitManagementUsername" in source
    assert "hub-overview-management-username" in source
    assert "buildUsernameRecoveryBannerPanel" in source
    assert "Сохранить имя пользователя" in source
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    assert "needsManagementUsernameRecovery" in banner_body
    assert "label: 'Открыть «Подключение»'" in banner_body
    assert "secondaryAction" in banner_body


def test_overview_connection_banner_rebuild_pending_focus() -> None:
    """F-c2-3: rebuildConnectionBannerSlot сохраняет focus/caret как diagnostics."""
    source = _read(OVERVIEW_JS)
    rebuild_body = _extract_function_body(source, "function rebuildConnectionBannerSlot(rebuild)")
    assert rebuild_body is not None
    assert "pendingFocus" in rebuild_body
    assert "connectionBannerWrap.contains(active)" in rebuild_body
    assert "restorePendingFocus()" in rebuild_body
    assert "selectionStart" in rebuild_body
    assert "selectionEnd" in rebuild_body
    assert "hub-overview-management-username" in source
    pending_idx = rebuild_body.find("pendingFocus")
    clear_idx = rebuild_body.find("clearContainer(connectionBannerWrap)")
    assert pending_idx != -1 and clear_idx != -1
    assert pending_idx < clear_idx, "pendingFocus must be captured before clearContainer"


def test_overview_restore_pending_focus_selection_range() -> None:
    """F-c2-3: restorePendingFocus восстанавливает каретку через setSelectionRange."""
    source = _read(OVERVIEW_JS)
    restore_body = _extract_function_body(source, "function restorePendingFocus()")
    assert restore_body is not None
    assert "setSelectionRange" in restore_body
    assert "selectionStart" in restore_body
    assert "selectionEnd" in restore_body
    focus_idx = restore_body.find(".focus()")
    selection_idx = restore_body.find("setSelectionRange")
    assert focus_idx != -1 and selection_idx != -1
    assert focus_idx < selection_idx, "focus must precede setSelectionRange"


def test_overview_username_recovery_signature_excludes_draft_and_saving() -> None:
    """F-c2-3: signature username-recovery не включает draft и saving — in-place без remount."""
    source = _read(OVERVIEW_JS)
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    sig_idx = banner_body.find("const signature = `username-recovery|")
    assert sig_idx != -1
    sig_end = banner_body.find("`", sig_idx + len("const signature = "))
    sig_expr = banner_body[sig_idx:sig_end]
    assert "managementUsernameDraft" not in sig_expr
    assert "savingManagementUsername" not in sig_expr
    assert "syncOverviewManagementUsernameInPlace" in banner_body


def test_overview_username_recovery_saving_uses_readonly_not_disable() -> None:
    """F-fc2-3-1: при сохранении username input остаётся readOnly, не disabled."""
    source = _read(OVERVIEW_JS)
    sync_body = _extract_function_body(source, "function syncOverviewManagementUsernameFormUi()")
    assert sync_body is not None
    assert "readOnly = savingManagementUsername" in sync_body
    assert "input.disabled = savingManagementUsername" not in sync_body
    banner_body = _extract_function_body(source, "function buildUsernameRecoveryBannerPanel(")
    assert banner_body is not None
    assert "readOnly: savingManagementUsername" in banner_body
    assert "disabled: savingManagementUsername" not in banner_body


def test_overview_submit_captures_pending_focus_before_save() -> None:
    """F-fc2-3-1: submit захватывает pendingFocus до saving/render."""
    source = _read(OVERVIEW_JS)
    submit_body = _extract_function_body(
        source,
        "async function submitOverviewManagementUsername()",
    )
    assert submit_body is not None
    pending_idx = submit_body.find("pendingFocus")
    saving_idx = submit_body.find("savingManagementUsername = true")
    assert pending_idx != -1 and saving_idx != -1
    assert pending_idx < saving_idx, "pendingFocus must be captured before saving flag"
    assert "document.activeElement === usernameInput" in submit_body
    assert "selectionStart" in submit_body
    assert "selectionEnd" in submit_body


def test_overview_progress_captures_summary_focus_before_clear() -> None:
    """F-fc2-3-3: showRestoreOrProbeProgress сохраняет focus summary до clear."""
    source = _read(OVERVIEW_JS)
    progress_body = _extract_function_body(source, "function showRestoreOrProbeProgress(")
    assert progress_body is not None
    assert "captureSummaryPendingFocus()" in progress_body
    capture_idx = progress_body.find("captureSummaryPendingFocus()")
    clear_idx = progress_body.find("clearContainer(summaryWrap)")
    assert capture_idx != -1 and clear_idx != -1
    assert capture_idx < clear_idx


def test_overview_username_recovery_saving_inplace_without_signature_reset() -> None:
    """F-c2-3: submit не сбрасывает signature — busy обновляется in-place."""
    source = _read(OVERVIEW_JS)
    assert "syncOverviewManagementUsernameFormUi" in source
    submit_body = _extract_function_body(
        source,
        "async function submitOverviewManagementUsername()",
    )
    assert submit_body is not None
    assert "lastConnectionBannerSignature = null" not in submit_body


def test_overview_connection_banner_remount_uses_rebuild_helper() -> None:
    """F-c2-3: все remount connection banner идут через rebuildConnectionBannerSlot."""
    source = _read(OVERVIEW_JS)
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    assert "clearContainer(connectionBannerWrap)" not in banner_body
    assert banner_body.count("rebuildConnectionBannerSlot") >= 3
    assert "hub-overview-restore-retry-btn" in banner_body


def test_overview_summary_probe_fail_preserves_retry_focus() -> None:
    """Summary probe-fail «Повторить» сохраняет focus через hadFocusInside (без изменений)."""
    source = _read(OVERVIEW_JS)
    summary_body = _extract_function_body(source, "function renderSummary()")
    assert summary_body is not None
    assert "hadFocusInside" in summary_body
    assert summary_body.count("hadFocusInside") >= 2
    assert "hub-state-action" in summary_body


def test_overview_render_summary_only_restores_summary_action_retry() -> None:
    """F-c2-3-4: renderSummary не восстанавливает banner element-id pendingFocus."""
    source = _read(OVERVIEW_JS)
    summary_body = _extract_function_body(source, "function renderSummary()")
    assert summary_body is not None
    assert "pendingFocus?.kind === 'summary-action-retry'" in summary_body
    assert "else if (pendingFocus?.kind === 'summary-action-retry')" in summary_body
    assert summary_body.count("restorePendingFocus()") == 1


def test_overview_render_summary_skips_summary_action_retry_when_banner_focused() -> None:
    """F-c2-3-5: renderSummary не крадёт focus у banner username при summary-action-retry."""
    source = _read(OVERVIEW_JS)
    summary_body = _extract_function_body(source, "function renderSummary()")
    assert summary_body is not None
    assert "connectionBannerWrap.contains(active)" in summary_body


def test_overview_submit_clears_pending_focus_when_input_still_focused() -> None:
    """F-c2-3-4: submit clears pendingFocus when input stays focused after in-place render."""
    source = _read(OVERVIEW_JS)
    submit_body = _extract_function_body(
        source,
        "async function submitOverviewManagementUsername()",
    )
    assert submit_body is not None
    render_idx = submit_body.find("renderConnectionBanner()")
    clear_idx = submit_body.find("pendingFocus = null")
    assert render_idx != -1 and clear_idx != -1
    assert render_idx < clear_idx, "pendingFocus must clear after in-place renderConnectionBanner"
    assert "document.activeElement === usernameInputAfterRender" in submit_body


def test_overview_probe_failed_primary_retry() -> None:
    """После probe-fail primary «Повторить» в summary."""
    source = _read(OVERVIEW_JS)
    summary_body = _extract_function_body(source, "function buildSummaryPanelOptions(")
    assert summary_body is not None
    assert "if (hasError)" in summary_body
    assert "label: 'Повторить'" in summary_body
    assert "requestReloadOverview" in summary_body


def test_overview_never_auto_confirms_host_key() -> None:
    """Overview не вызывает ssh-host-key learn/confirm."""
    combined = _read(OVERVIEW_JS) + _read(OVERVIEW_MODEL_JS)
    assert "ssh-host-key" not in combined
    assert "learnHostKey" not in combined
    assert "confirmHostKey" not in combined


def test_overview_progress_panel_single_surface() -> None:
    """Один progress surface через createProgressPanel в summary."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "export function render(")
    assert body is not None
    assert "createProgressPanel" in body
    assert "showRestoreOrProbeProgress" in body
    banner_body = _extract_function_body(source, "function renderConnectionBanner(")
    assert banner_body is not None
    assert "Проверяем сохранённое подключение на сервере" not in banner_body


def test_overview_host_key_unconfirmed_honest_wording() -> None:
    """LIMITED без overstatement «Связь есть»; READY только при confirmed."""
    source = _read(SYSTEM_CHECK_JS)
    assert "Связь есть, но устройство ещё не подтверждено" not in source
    assert "Нужно подтвердить, что это ваш роутер" in source
    assert HOST_KEY_NOT_CONFIRMED_GUARD in source


def test_overview_vpn_on_activate_wires_activate_profile_not_navigate() -> None:
    """F-c2-1: VPN «Подключить» вызывает activateVpnProfile, не только navigate.

    Раньше активация висела на ``onActivate`` каждой плитки полноценной сетки
    управления (экран #/vpn). После перехода на компактный picker плитка только
    выбирает профиль (``onSelect``); подключение/отключение делает единственная
    CTA-кнопка карточки — проверяем именно её обработчик.
    """
    source = _read(OVERVIEW_JS)
    render_vpn_body = _extract_function_body(source, "function renderVpnSlot(")
    assert render_vpn_body is not None
    assert "activateVpnProfile" in source
    assert "deactivateVpnProfile" in source
    assert "runOverviewVpnActivate" in source
    assert "runOverviewVpnDeactivate" in source
    assert "onSelect: (profileId) =>" in render_vpn_body
    assert "onActivate: () =>" in render_vpn_body
    cta_block = render_vpn_body.split("onActivate: () =>", 1)[1].split(
        "ctaBtn.className", 1
    )[0]
    assert "runOverviewVpnActivate" in cta_block
    assert "runOverviewVpnDeactivate" in cta_block
    assert "ctx.navigate('vpn')" not in cta_block
    assert "busyProfileIds: vpnActivatingProfileIds" in render_vpn_body
    assert "deactivatingProfileIds: vpnDeactivatingProfileIds" in render_vpn_body
    assert "checkingProfileIds: vpnCheckingProfileIds" in render_vpn_body
    assert "isConnectionRestorePending(getSession())" in source
    activate_body = _extract_function_body(source, "async function runOverviewVpnActivate(")
    assert activate_body is not None
    assert "ipGlobalPriority: null" not in activate_body
    assert "activateVpnProfile({" in activate_body
    vpn_model = _read(HUB / "features" / "vpn-model.js")
    activate_fn = re.search(
        r"export function activateVpnProfile\([\s\S]*?\n\}",
        vpn_model,
    )
    assert activate_fn is not None
    assert "ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT" in activate_fn.group(0)
    assert "refreshVpnCatalogAndLiveStatus" in activate_body
    assert "«Работает» только при подтверждённой связи туннеля" in activate_body


def test_overview_vpn_activate_toast_gated_on_activated_flag() -> None:
    """AC-3/AC-4/AC-5: runOverviewVpnActivate success toast only when activated === true."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "async function runOverviewVpnActivate(")
    assert body is not None
    assert "const response = await activateVpnProfile(" in body
    assert "response?.activated === true" in body
    success_branch = body.split("response?.activated === true", 1)[1].split("} else {", 1)[0]
    assert "tone: 'success'" in success_branch
    assert "title: 'Не активирован'" in body
    assert "tone: 'warning'" in body
    assert "describeConfigurationOutcome" not in body


def test_overview_vpn_deactivate_toast_gated_on_deactivated_flag() -> None:
    """AC-3b/AC-4/AC-5: runOverviewVpnDeactivate success toast only when deactivated === true."""
    source = _read(OVERVIEW_JS)
    body = _extract_function_body(source, "async function runOverviewVpnDeactivate(")
    assert body is not None
    assert "const response = await deactivateVpnProfile(" in body
    assert "response?.deactivated === true" in body
    success_branch = body.split("response?.deactivated === true", 1)[1].split("} else {", 1)[0]
    assert "tone: 'success'" in success_branch
    assert "title: 'Не отключён'" in body
    assert "tone: 'warning'" in body
    assert "describeConfigurationOutcome" not in body


def test_overview_vpn_slot_no_status_note_prose() -> None:
    """Overview VPN card no longer renders the long status note paragraph."""
    source = _read(OVERVIEW_JS)
    assert "OVERVIEW_VPN_STATUS_NOTE" not in source
    assert "hub-overview__vpn-note" not in source
    assert "hub-vpn-card__cta-hint" not in source
    render_vpn_body = _extract_function_body(source, "function renderVpnSlot(")
    assert render_vpn_body is not None
    assert "vpnBuildFactTiles" not in render_vpn_body
    assert "Все настройки VPN" in source


def test_overview_networks_no_unassigned_before_load_when_roles_exist() -> None:
    """F-c2-2: при ролях в standing select виден; loading до завершения load."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "loadCompleted" in source
    load_body = _extract_function_body(source, "async function loadAndUpdate(")
    assert load_body is not None
    assert "standing?.staff_ap_id" in load_body
    assert "standing?.guest_ap_id" in load_body
    staff_body = _extract_function_body(source, "function renderStaffSlot(")
    assert staff_body is not None
    staff_mount_guard = staff_body.split("} else if")[0]
    assert "if (!loadCompleted)" in staff_mount_guard
    assert "loading && !loadCompleted" not in staff_mount_guard
    guest_body = _extract_function_body(source, "function renderGuestSlot(")
    assert guest_body is not None
    guest_mount_guard = guest_body.split("} else if")[0]
    assert "if (!loadCompleted)" in guest_mount_guard
    assert "loading && !loadCompleted" not in guest_mount_guard


def _extract_if_branch(body: str, condition_prefix: str) -> str | None:
    """Extract body of first if-block whose condition starts with condition_prefix."""
    idx = body.find(condition_prefix)
    if idx == -1:
        return None
    brace = body.find("{", idx)
    if brace == -1:
        return None
    depth = 0
    j = brace
    while j < len(body):
        char = body[j]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return body[brace + 1 : j]
        j += 1
    return None


def test_overview_networks_staff_enable_network_toggle_pending_true() -> None:
    """§1: runStaffEnable passes networkTogglePending:true into deriveWifiPreviewEnabled."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    staff_enable_body = _extract_function_body(source, "async function runStaffEnable(")
    assert staff_enable_body is not None
    assert "networkTogglePending: true" in staff_enable_body
    assert "networkTogglePending: false" not in staff_enable_body


def test_overview_networks_guest_on_network_toggle_pending_true() -> None:
    """§1: guest ON path passes networkTogglePending:true and action:'enable'."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None
    assert "networkTogglePending: true" in guest_apply_body
    assert "action: 'enable'" in guest_apply_body
    assert "networkTogglePending: false" not in guest_apply_body


def test_overview_networks_guest_off_early_teardown_branch() -> None:
    """§2: guest OFF uses teardownGuestWifiNetwork early branch without apply/preview."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "teardownGuestWifiNetwork" in source
    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None

    off_branch = _extract_if_branch(guest_apply_body, "if (!enabled")
    if off_branch is None:
        off_branch = _extract_if_branch(guest_apply_body, "if (enabled === false")
    assert off_branch is not None

    assert "teardownGuestWifiNetwork(" in off_branch
    assert "apId:" in off_branch
    assert "wpaMode:" in off_branch
    assert "session" in off_branch
    assert "signal" in off_branch
    assert "return" in off_branch
    assert "applyGuestWifiChanges" not in off_branch
    assert "buildGuestWifiPreviewBody" not in off_branch
    assert "deriveWifiPreviewEnabled" not in off_branch


def test_overview_networks_wifi_apply_verdict_import() -> None:
    """AC-1: overview-simple-networks imports parseWifiApplyVerdict helpers from wifi-ap-model."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    wifi_import = source.split("from './wifi-ap-model.js';", 1)[0]
    assert "parseWifiApplyVerdict" in wifi_import
    assert "shouldRefreshWifiObservedAfterMutation" in wifi_import
    assert "from './wifi-ap-model.js'" in source


def test_overview_networks_helpers_return_verdict_or_null() -> None:
    """AC-2: Wi-Fi mutation helpers parse apply response and return verdict|null."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    for fn_name in ("runStaffEnable", "runStaffApplyDefaults", "runGuestApply"):
        body = _extract_function_body(source, f"async function {fn_name}(")
        assert body is not None
        assert "parseWifiApplyVerdict" in body
        assert "return verdict" in body
    defaults_body = _extract_function_body(source, "async function runStaffApplyDefaults(")
    assert defaults_body is not None
    assert "return null" in defaults_body


def test_overview_networks_guest_off_teardown_verdict_intent() -> None:
    """AC-3: guest OFF branch parses teardown response with { intent: 'teardown' }."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None
    off_branch = _extract_if_branch(guest_apply_body, "if (!enabled")
    assert off_branch is not None
    assert "parseWifiApplyVerdict(response, { intent: 'teardown' })" in off_branch


def test_overview_networks_guest_mutation_readiness_gated() -> None:
    """Guest apply/toggle gated by evaluateGuestWifiMutationReadiness; incomplete session must not reach apply API."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    guest_import = source.split("from './guest-wifi-model.js';", 1)[0]
    assert "evaluateGuestWifiMutationReadiness" in guest_import

    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None
    assert "evaluateGuestWifiMutationReadiness(session, adapterMode)" in guest_apply_body
    assert "!readiness.allowed" in guest_apply_body
    assert "HubApiError" in guest_apply_body

    readiness_idx = guest_apply_body.find("evaluateGuestWifiMutationReadiness")
    teardown_idx = guest_apply_body.find("teardownGuestWifiNetwork")
    apply_idx = guest_apply_body.find("applyGuestWifiChanges")
    assert readiness_idx != -1
    assert readiness_idx < teardown_idx
    assert apply_idx == -1 or readiness_idx < apply_idx

    guest_render_body = _extract_function_body(source, "function renderGuestSlot(")
    assert guest_render_body is not None
    assert "evaluateGuestWifiMutationReadiness" in guest_render_body
    assert "guestMutationBlocked" in guest_render_body
    toggle_block = guest_render_body.split("guest-enabled", 1)[1].split("onChange:", 1)[0]
    assert "guestMutationBlocked" in toggle_block


def test_overview_networks_run_mutation_toast_from_verdict() -> None:
    """AC-4: runMutation shows toast only when verdict exists; tone from verdict hubState."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    run_mutation_body = _extract_function_body(source, "async function runMutation(")
    assert run_mutation_body is not None
    assert "verdict = await runStaffEnable(signal)" in run_mutation_body
    assert "verdict = await runStaffApplyDefaults(signal)" in run_mutation_body
    assert "verdict = await runGuestApply(targetEnabled, signal)" in run_mutation_body
    toast_region = run_mutation_body.split("options.showToast({", 1)[0]
    assert "verdict" in toast_region
    assert "typeof options.showToast === 'function'" in toast_region
    assert "!signal?.aborted" in toast_region
    assert "resolveOffline()" in toast_region
    assert "getStateDescriptor" in source
    assert "getStateDescriptor(verdict.hubState).tone" in run_mutation_body
    assert "Object.values(HubState).includes(verdict.hubState)" in run_mutation_body
    assert "tone: verdict.success ? 'success' : 'warning'" not in run_mutation_body
    assert "title: verdict.title" in run_mutation_body
    assert "message: verdict.message" in run_mutation_body
    assert "title: 'Готово'" not in run_mutation_body
    assert "Настройки отправлены на роутер" not in run_mutation_body


def test_overview_networks_password_registered_apply_failed_message_honesty() -> None:
    """hub-password-honesty: registered password + failed apply rewrites toast message."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    wifi_import = source.split("from './wifi-ap-model.js';", 1)[0]
    assert "WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE" in wifi_import
    assert "isWifiConfigurationApplied" in wifi_import

    run_mutation_body = _extract_function_body(source, "async function runMutation(")
    assert run_mutation_body is not None
    assert "mutationPasswordRegistered = false" in run_mutation_body
    honesty_start = run_mutation_body.find(
        "mutationPasswordRegistered\n        && verdict",
    )
    assert honesty_start != -1
    honesty_region = run_mutation_body[honesty_start : honesty_start + 400]
    assert "!verdict.success" in honesty_region
    assert "!isWifiConfigurationApplied(verdict)" in honesty_region
    assert "message: WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE" in honesty_region

    staff_enable_body = _extract_function_body(source, "async function runStaffEnable(")
    assert staff_enable_body is not None
    assert "mutationPasswordRegistered = true" in staff_enable_body
    register_idx = staff_enable_body.find("ensureWifiCredentialRef(")
    set_flag_idx = staff_enable_body.find("mutationPasswordRegistered = true")
    assert register_idx != -1 and set_flag_idx != -1 and register_idx < set_flag_idx

    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None
    assert "mutationPasswordRegistered = true" in guest_apply_body
    register_idx = guest_apply_body.find("ensureWifiCredentialRef(")
    set_flag_idx = guest_apply_body.find("mutationPasswordRegistered = true")
    assert register_idx != -1 and set_flag_idx != -1 and register_idx < set_flag_idx


def test_overview_networks_form_dirty_and_standing_gated_on_verdict_success() -> None:
    """AC-5: formDirty clear and standing PUT require verdict.success."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    run_mutation_body = _extract_function_body(source, "async function runMutation(")
    assert run_mutation_body is not None
    assert "if (verdict?.success)" in run_mutation_body
    assert "staffFormDirty = false" in run_mutation_body
    assert "guestFormDirty = false" in run_mutation_body

    staff_enable_body = _extract_function_body(source, "async function runStaffEnable(")
    assert staff_enable_body is not None
    assert "if (standing && session.routerId && verdict.success)" in staff_enable_body

    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None
    assert "if (guestRememberDefault && enabled && verdict.success)" in guest_apply_body


def test_overview_networks_standing_persist_failure_shows_warning_after_apply_success() -> None:
    """Staff/guest apply success + standing PUT failure → warning toast after apply verdict."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    staff_enable_body = _extract_function_body(source, "async function runStaffEnable(")
    assert staff_enable_body is not None
    assert "standingPersistWarningKind = 'staff'" in staff_enable_body
    assert "// non-blocking" not in staff_enable_body

    guest_apply_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_apply_body is not None
    assert "standingPersistWarningKind = 'guest'" in guest_apply_body

    run_mutation_body = _extract_function_body(source, "async function runMutation(")
    assert run_mutation_body is not None
    assert "showStandingPersistWarningToast" in run_mutation_body
    assert "verdict?.success" in run_mutation_body
    assert "standingPersistWarningKind" in run_mutation_body
    assert "Не удалось сохранить обычные настройки" in source
    assert "Не удалось запомнить обычное имя" in source


def test_overview_networks_observed_refresh_gated_on_should_refresh() -> None:
    """AC-6: observed refresh runs only when shouldRefreshWifiObservedAfterMutation(verdict)."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    for fn_name in ("runStaffEnable", "runStaffApplyDefaults", "runGuestApply"):
        body = _extract_function_body(source, f"async function {fn_name}(")
        assert body is not None
        assert "shouldRefreshWifiObservedAfterMutation(verdict)" in body
        refresh_branch = _extract_if_branch(body, "if (shouldRefreshWifiObservedAfterMutation(verdict)")
        assert refresh_branch is not None
        assert "fetchStaffWifiObservedState" in refresh_branch or "fetchGuestWifiObservedState" in refresh_branch
    guest_body = _extract_function_body(source, "async function runGuestApply(")
    assert guest_body is not None
    # Guest OFF (teardown) and guest ON (apply) each gate refresh — not only the first match.
    assert guest_body.count("shouldRefreshWifiObservedAfterMutation(verdict)") >= 2
    assert "parseWifiApplyVerdict(response, { intent: 'teardown' })" in guest_body
    assert "parseWifiApplyVerdict(response)" in guest_body


def test_overview_guest_overlap_uses_persisted_staff_ap_id() -> None:
    """Overview overlap warning reads standing staff_ap_id, not session.wifiRoles."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    guest_body = _extract_function_body(source, "function renderGuestSlot(")
    assert guest_body is not None
    overlap_idx = guest_body.find("getGuestStaffApOverlapWarning(")
    assert overlap_idx != -1
    overlap_call = guest_body[overlap_idx : overlap_idx + 220]
    assert "wifiRoles: { staffApId: selectedStaffApId }" in overlap_call
    assert "options.getSession()" not in overlap_call


def test_overview_internet_observe_refresh_guards_restore_pending() -> None:
    """F-c2-3: refreshRouterInternetObserve и session subscribe не обходят restore gate."""
    source = _read(OVERVIEW_JS)
    refresh_body = _extract_function_body(source, "async function refreshRouterInternetObserve(")
    assert refresh_body is not None
    assert "isConnectionRestorePending" in refresh_body
    subscribe_idx = source.find("subscribeSession((snapshot) =>")
    assert subscribe_idx != -1
    subscribe_block = source[subscribe_idx : subscribe_idx + 1200]
    assert "isConnectionRestorePending(snapshot)" in subscribe_block
    assert "internetObserveAbort" in subscribe_block
    assert subscribe_block.index("isConnectionRestorePending") < subscribe_block.index(
        "refreshRouterInternetObserve"
    )


def test_overview_networks_guest_ssid_input_preserves_scroll() -> None:
    """F-c2-5: ввод SSID гостевой сети не вызывает полный rebuild; scroll сохраняется."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "captureScrollPosition" in source
    assert "restoreScrollPosition" in source
    assert "hub-content" in source
    update_body = _extract_function_body(source, "function update(")
    assert update_body is not None
    assert "captureScrollPosition()" in update_body
    assert "restoreScrollPosition(scrollPosition)" in update_body
    guest_body = _extract_function_body(source, "function renderGuestSlot(")
    assert guest_body is not None
    ssid_input_block = guest_body.split("guest-ssid", 1)[1].split("onInput:", 1)[1]
    assert "update()" not in ssid_input_block.split("},", 1)[0]
    assert "buildContentSignature()" in ssid_input_block


def _overview_networks_dual_slot_setup_js() -> str:
    """DOM: staffSlot + guestSlot для mountOverviewSimpleNetworks."""
    return """
const staffSlot = dom.document.createElement('div');
staffSlot.className = 'hub-overview__staff-slot';
const guestSlot = dom.document.createElement('div');
guestSlot.className = 'hub-overview__guest-slot';
const container = dom.document.createElement('div');
container.appendChild(staffSlot);
container.appendChild(guestSlot);
dom.document.body.appendChild(container);
"""


def _overview_networks_dom_harness_script(*, fetch_handler: str, body: str) -> str:
    """Общий Node DOM harness для behavioral-тестов overview-simple-networks."""
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    networks_uri = json.dumps(OVERVIEW_SIMPLE_NETWORKS_JS.as_uri())
    return f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();

function patchElement(el) {{
  if (!el.getAttributeNames) {{
    el.getAttributeNames = () => Object.keys(el.attributes || {{}});
  }}
  if (!Object.getOwnPropertyDescriptor(el, 'id')) {{
    Object.defineProperty(el, 'id', {{
      get() {{ return this.attributes.id || ''; }},
      set(v) {{ this.setAttribute('id', String(v)); }},
      configurable: true,
    }});
  }}
  if (!el.insertBefore) {{
    el.insertBefore = function(newNode, refNode) {{
      if (refNode && refNode.parentNode === this) {{
        const idx = this.children.indexOf(refNode);
        if (idx >= 0) {{
          if (newNode.parentNode && newNode.parentNode.children) {{
            const oldIdx = newNode.parentNode.children.indexOf(newNode);
            if (oldIdx >= 0) newNode.parentNode.children.splice(oldIdx, 1);
          }}
          this.children.splice(idx, 0, newNode);
          newNode.parentNode = this;
          return newNode;
        }}
      }}
      return this.appendChild(newNode);
    }};
  }}
  if (!el.contains) {{
    el.contains = function(node) {{
      if (!node) return false;
      let walk = node;
      while (walk) {{
        if (walk === this) return true;
        walk = walk.parentNode;
      }}
      return false;
    }};
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
  open() {{ return null; }},
  addEventListener() {{}},
  removeEventListener() {{}},
  dispatchEvent() {{ return true; }},
  matchMedia() {{
    return {{ matches: false, addEventListener() {{}}, removeEventListener() {{}} }};
  }},
}};
globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

{fetch_handler}

const {{ mountOverviewSimpleNetworks }} = await import({networks_uri});

const session = {{
  routerId: 'router-lab-1',
  hostKeyConfirmed: true,
  wifiRoles: {{ staffApId: 'WifiMaster0/AccessPoint4', guestApId: 'WifiMaster0/AccessPoint5' }},
}};

{body}
"""


def _overview_networks_guest_fetch_handler(*, guest_ap_payload_builder: str) -> str:
    """Fetch mock: standing prefs + wifi/observed-state (staff/guest по ap_ids[0])."""
    return f"""
globalThis.fetch = async (url, init) => {{
  const path = String(url).replace(/^.*\\/api\\/router-control\\/v1\\//, '');
  if (path === 'standing-network-preferences') {{
    return new Response(JSON.stringify({{
      staff_ap_id: 'WifiMaster0/AccessPoint4',
      guest_ap_id: 'WifiMaster0/AccessPoint5',
    }}), {{
      status: 200,
      headers: {{ 'Content-Type': 'application/json' }},
    }});
  }}
  if (path === 'wifi/observed-state') {{
    let apId = 'WifiMaster0/AccessPoint5';
    try {{
      const reqBody = init?.body ? JSON.parse(String(init.body)) : {{}};
      if (Array.isArray(reqBody.ap_ids) && reqBody.ap_ids[0]) {{
        apId = reqBody.ap_ids[0];
      }}
    }} catch (_err) {{
      /* test harness */
    }}
    if (apId === 'WifiMaster0/AccessPoint4') {{
      return new Response(JSON.stringify({{
        access_points: [{{
          ap_id: apId,
          band: '2.4GHz',
          ssid: 'Demo-Staff-Net',
          enabled_or_up: true,
          link_up: true,
          wpa_mode: 'WPA2',
          readable: true,
        }}],
      }}), {{
        status: 200,
        headers: {{ 'Content-Type': 'application/json' }},
      }});
    }}
    const guestAp = {guest_ap_payload_builder};
    return new Response(JSON.stringify({{ access_points: [guestAp] }}), {{
      status: 200,
      headers: {{ 'Content-Type': 'application/json' }},
    }});
  }}
  return new Response(JSON.stringify({{ error: {{ code: 'http.404', message: 'not found' }} }}), {{
    status: 404,
    headers: {{ 'Content-Type': 'application/json' }},
  }});
}};
"""


def test_overview_networks_guest_wpa_select_when_mode_unknown(tmp_path: Path) -> None:
    """R-6: селектор «Защита» только когда wpaMode роутера неизвестен."""
    id_prefix = "hub-overview-networks"
    guest_ap_unknown = """{
      ap_id: 'WifiMaster0/AccessPoint5',
      band: '2.4GHz',
      ssid: 'Fresh-Guest',
      enabled_or_up: false,
      link_up: false,
      readable: true,
    }"""
    fetch_unknown = _overview_networks_guest_fetch_handler(
        guest_ap_payload_builder=guest_ap_unknown,
    )
    script_unknown = _overview_networks_dom_harness_script(
        fetch_handler=fetch_unknown,
        body=f"""
{_overview_networks_dual_slot_setup_js()}
const mount = mountOverviewSimpleNetworks({{
  staffSlot,
  guestSlot,
  getSession: () => session,
  adapterMode: 'fake',
  navigate: () => {{}},
  isRestorePending: () => false,
  idPrefix: {json.dumps(id_prefix)},
}});
await mount.loadAndUpdate();
const guestCard = guestSlot.querySelector('.hub-overview-networks__guest');
const wpaSelect = guestCard?.querySelector('#{id_prefix}-guest-wpa');
console.log(JSON.stringify({{
  hasWpaSelect: Boolean(wpaSelect),
  selectCount: guestCard?.querySelectorAll('.hub-field__select').length ?? 0,
}}));
mount.destroy();
""",
    )
    payload_unknown = _run_node_harness(script_unknown, tmp_path, "guest-wpa-unknown")
    assert payload_unknown["hasWpaSelect"] is True
    assert payload_unknown["selectCount"] >= 1

    guest_ap_known = """{
      ap_id: 'WifiMaster0/AccessPoint5',
      band: '2.4GHz',
      ssid: 'Configured-Guest',
      enabled_or_up: false,
      link_up: false,
      wpa_mode: 'WPA2',
      readable: true,
    }"""
    fetch_known = _overview_networks_guest_fetch_handler(
        guest_ap_payload_builder=guest_ap_known,
    )
    script_known = _overview_networks_dom_harness_script(
        fetch_handler=fetch_known,
        body=f"""
{_overview_networks_dual_slot_setup_js()}
const mount = mountOverviewSimpleNetworks({{
  staffSlot,
  guestSlot,
  getSession: () => session,
  adapterMode: 'fake',
  navigate: () => {{}},
  isRestorePending: () => false,
  idPrefix: {json.dumps(id_prefix)},
}});
await mount.loadAndUpdate();
const guestCard = guestSlot.querySelector('.hub-overview-networks__guest');
const wpaSelect = guestCard?.querySelector('#{id_prefix}-guest-wpa');
console.log(JSON.stringify({{
  hasWpaSelect: Boolean(wpaSelect),
  wpaSelectCount: guestCard?.querySelectorAll('#{id_prefix}-guest-wpa').length ?? 0,
}}));
mount.destroy();
""",
    )
    payload_known = _run_node_harness(script_known, tmp_path, "guest-wpa-known")
    assert payload_known["hasWpaSelect"] is False
    assert payload_known["wpaSelectCount"] == 0


def test_overview_networks_guest_ssid_dirty_and_clean_on_poll(tmp_path: Path) -> None:
    """guestFormDirty: пользовательский SSID сохраняется при опросе; чистая форма обновляется."""
    id_prefix = "hub-overview-networks"
    fetch_handler = """
let guestObservedSsid = 'Initial-Guest-SSID';

globalThis.fetch = async (url, init) => {
  const path = String(url).replace(/^.*\\/api\\/router-control\\/v1\\//, '');
  if (path === 'standing-network-preferences') {
    return new Response(JSON.stringify({
      staff_ap_id: 'WifiMaster0/AccessPoint4',
      guest_ap_id: 'WifiMaster0/AccessPoint5',
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  if (path === 'wifi/observed-state') {
    let apId = 'WifiMaster0/AccessPoint5';
    try {
      const reqBody = init?.body ? JSON.parse(String(init.body)) : {};
      if (Array.isArray(reqBody.ap_ids) && reqBody.ap_ids[0]) {
        apId = reqBody.ap_ids[0];
      }
    } catch (_err) {
      /* test harness */
    }
    if (apId === 'WifiMaster0/AccessPoint4') {
      return new Response(JSON.stringify({
        access_points: [{
          ap_id: apId,
          band: '2.4GHz',
          ssid: 'Demo-Staff-Net',
          enabled_or_up: true,
          link_up: true,
          wpa_mode: 'WPA2',
          readable: true,
        }],
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return new Response(JSON.stringify({
      access_points: [{
        ap_id: 'WifiMaster0/AccessPoint5',
        band: '2.4GHz',
        ssid: guestObservedSsid,
        enabled_or_up: false,
        link_up: false,
        wpa_mode: 'WPA2',
        readable: true,
      }],
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  }
  return new Response(JSON.stringify({ error: { code: 'http.404', message: 'not found' } }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' },
  });
};
"""
    dirty_script = _overview_networks_dom_harness_script(
        fetch_handler=fetch_handler,
        body=f"""
{_overview_networks_dual_slot_setup_js()}
const mount = mountOverviewSimpleNetworks({{
  staffSlot,
  guestSlot,
  getSession: () => session,
  adapterMode: 'fake',
  navigate: () => {{}},
  isRestorePending: () => false,
  idPrefix: {json.dumps(id_prefix)},
}});

await mount.loadAndUpdate();
const ssidInput = container.querySelector('#{id_prefix}-guest-ssid');
const typedSsid = 'User-Typed-Guest-SSID';
dom.simulateInput(ssidInput, typedSsid);
guestObservedSsid = 'Observed-Changed-SSID';
await mount.loadAndUpdate();
const ssidAfterDirtyPoll = container.querySelector('#{id_prefix}-guest-ssid')?.value ?? '';

mount.destroy();
console.log(JSON.stringify({{ ssidAfterDirtyPoll: ssidAfterDirtyPoll, typedSsid }}));
""",
    )
    dirty_payload = _run_node_harness(dirty_script, tmp_path, "guest-ssid-dirty")
    assert dirty_payload["ssidAfterDirtyPoll"] == dirty_payload["typedSsid"]
    assert dirty_payload["ssidAfterDirtyPoll"] != "Observed-Changed-SSID"

    clean_script = _overview_networks_dom_harness_script(
        fetch_handler=fetch_handler,
        body=f"""
guestObservedSsid = 'First-Observed-SSID';
{_overview_networks_dual_slot_setup_js()}
const mount = mountOverviewSimpleNetworks({{
  staffSlot,
  guestSlot,
  getSession: () => session,
  adapterMode: 'fake',
  navigate: () => {{}},
  isRestorePending: () => false,
  idPrefix: {json.dumps(id_prefix)},
}});

await mount.loadAndUpdate();
const ssidAfterFirst = container.querySelector('#{id_prefix}-guest-ssid')?.value ?? '';
guestObservedSsid = 'Second-Observed-SSID';
await mount.loadAndUpdate();
const ssidAfterSecond = container.querySelector('#{id_prefix}-guest-ssid')?.value ?? '';
mount.destroy();
console.log(JSON.stringify({{ ssidAfterFirst, ssidAfterSecond }}));
""",
    )
    clean_payload = _run_node_harness(clean_script, tmp_path, "guest-ssid-clean")
    assert clean_payload["ssidAfterFirst"] == "First-Observed-SSID"
    assert clean_payload["ssidAfterSecond"] == "Second-Observed-SSID"


def test_overview_networks_guest_form_dirty_load_and_update_guards() -> None:
    """loadAndUpdate не перезаписывает draft при guestFormDirty/staffFormDirty."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    load_body = _extract_function_body(source, "async function loadAndUpdate(")
    assert load_body is not None
    assert "if (!staffFormDirty)" in load_body
    assert "createStaffWifiFormDraft(staffObserved, standing)" in load_body
    assert "if (!guestFormDirty)" in load_body
    assert "createGuestWifiFormDraft(guestObserved, standing)" in load_body
    guest_body = _extract_function_body(source, "function renderGuestSlot(")
    assert guest_body is not None
    ssid_input_block = guest_body.split("guest-ssid", 1)[1].split("onInput:", 1)[1]
    assert "guestFormDirty = true" in ssid_input_block.split("},", 1)[0]


def test_overview_refresh_interval_constants() -> None:
    """Full router refresh every 5 min; host heartbeat every 1 min."""
    source = _read(OVERVIEW_JS)
    assert "const REFRESH_INTERVAL_MS = 300000;" in source
    assert "const HOST_INTERNET_HEARTBEAT_INTERVAL_MS = 60000;" in source


def test_overview_host_heartbeat_wiring() -> None:
    """Overview wires host-only heartbeat parallel to full refresh interval."""
    source = _read(OVERVIEW_JS)
    render_body = _extract_function_body(source, "export function render(")
    assert render_body is not None
    normalized = _normalize_whitespace(render_body)
    assert "probeOperatorHostInternet" in normalized
    assert "startHeartbeatInterval()" in normalized
    assert "runHeartbeatCheck" in normalized
    assert "lastHeartbeatReachable" in normalized
    heartbeat_body = _extract_function_body(source, "async function runHeartbeatCheck(")
    assert heartbeat_body is not None
    assert "shouldRequestOverviewReloadOnHostHeartbeat" in heartbeat_body
    assert "void requestReloadOverview()" in heartbeat_body
    visibility_body = _extract_function_body(source, "function onVisibilityChange(")
    assert visibility_body is not None
    assert "heartbeatInterval" in visibility_body


def test_should_request_overview_reload_on_host_heartbeat(tmp_path: Path) -> None:
    """Heartbeat reload only on true→false; not on null→false or false→false."""
    script = f"""
const mod = await import({json.dumps(OVERVIEW_JS.as_uri())});
console.log(JSON.stringify({{
  trueToFalse: mod.shouldRequestOverviewReloadOnHostHeartbeat(true, false),
  falseToFalse: mod.shouldRequestOverviewReloadOnHostHeartbeat(false, false),
  nullToFalse: mod.shouldRequestOverviewReloadOnHostHeartbeat(null, false),
  trueToTrue: mod.shouldRequestOverviewReloadOnHostHeartbeat(true, true),
  falseToTrue: mod.shouldRequestOverviewReloadOnHostHeartbeat(false, true),
}}));
"""
    result = _run_node_harness(script, tmp_path, "host-heartbeat-transition")
    assert result["trueToFalse"] is True
    assert result["falseToFalse"] is False
    assert result["nullToFalse"] is False
    assert result["trueToTrue"] is False
    assert result["falseToTrue"] is False


def test_overview_card_grid_structure() -> None:
    """AC-1: обзор использует readiness header, status strip и сетку карточек."""
    screen_source = _read(OVERVIEW_JS)
    css_source = _read(SCREENS_CSS)
    grid_helper_source = _read(OVERVIEW_CARD_GRID_JS)

    assert "createOverviewGrid" in screen_source
    assert "hub-overview__grid" in css_source
    assert "hub-overview__readiness-header" in css_source
    assert "hub-overview__status-strip" in css_source
    assert "buildOverviewReadinessHeader" in screen_source
    assert "buildOverviewStatusStrip" in screen_source
    assert "renderReadinessHeader" in screen_source
    assert "renderStatusStrip" in screen_source
    assert "createOverviewGridItem('staff')" in screen_source
    assert "createOverviewGridItem('guest')" in screen_source
    assert "createOverviewGridItem('networks')" not in screen_source
    assert "createOverviewGridItem('internet')" in screen_source
    for suffix, literal in (
        ("staff", "createOverviewGridItem('staff')"),
        ("guest", "createOverviewGridItem('guest')"),
        ("router", "createOverviewGridItem('router')"),
        ("vpn", "createOverviewGridItem('vpn')"),
        ("domain", "createOverviewGridItem('domain')"),
        ("entry-pages", "createOverviewGridItem('entry-pages')"),
        ("diagnostics", "createOverviewGridItem('diagnostics')"),
    ):
        assert literal in screen_source, suffix
    entry_idx = screen_source.index("createOverviewGridItem('entry-pages')")
    diag_idx = screen_source.index("createOverviewGridItem('diagnostics')")
    assert entry_idx < diag_idx, "entry-pages grid item must precede diagnostics"
    assert "hub-overview__grid-item--" in grid_helper_source
    assert "buildRouterConnectionStatusCard" in grid_helper_source
    assert "buildInternetStatusCard" in grid_helper_source
    assert "mountOverviewSimpleNetworks" in screen_source
    assert "buildVpnStatusCardShell" in screen_source
    assert "hub-overview__vpn-heading" in grid_helper_source
    assert "mountDomainSimplePublishAffordance" in screen_source
    assert "createProgressRing" in grid_helper_source or "createProgressRing" in _read(PROGRESS_RING_JS)


def test_overview_vpn_slot_chrome_less_like_router_internet_slots() -> None:
    """AC1: .hub-overview__vpn shares chrome-less slot rule with router/internet."""
    css = _read(SCREENS_CSS)
    slot_match = re.search(
        r"(\.hub-overview__router-card-slot,\s*"
        r"\.hub-overview__internet-card-slot,\s*"
        r"\.hub-overview__vpn,[^\{]+)\{([^}]+)\}",
        css,
        re.DOTALL,
    )
    assert slot_match, "shared chrome-less slot rule for router/internet/vpn missing"
    block = slot_match.group(2)
    assert "display: flex" in block or "display:flex" in block
    assert "padding" not in block
    assert "border" not in block
    assert "background" not in block
    standalone_vpn_chrome = re.search(
        r"\.hub-overview__vpn\s*\{[^}]*padding:",
        css,
    )
    assert standalone_vpn_chrome is None, ".hub-overview__vpn must not have standalone padding chrome"


def test_overview_step_card_shared_frame_css_rules() -> None:
    """AC2/AC3: __main/__actions/__meta CSS with mt:auto and meta ellipsis."""
    css = _read(SCREENS_CSS)
    main_match = re.search(
        r"\.hub-overview-step-card__main\s*\{([^}]+)\}",
        css,
        re.DOTALL,
    )
    assert main_match, ".hub-overview-step-card__main rule missing"
    main_block = main_match.group(1)
    assert "flex-direction:" in main_block and "column" in main_block
    assert "gap:" in main_block

    actions_match = re.search(
        r"\.hub-overview-step-card__actions\s*\{([^}]+)\}",
        css,
        re.DOTALL,
    )
    assert actions_match, ".hub-overview-step-card__actions rule missing"
    actions_block = actions_match.group(1)
    assert "margin-top: auto" in actions_block or "margin-top:auto" in actions_block

    meta_match = re.search(
        r"\.hub-overview-step-card__meta\s*\{([^}]+)\}",
        css,
        re.DOTALL,
    )
    assert meta_match, ".hub-overview-step-card__meta rule missing"
    meta_block = meta_match.group(1)
    assert "var(--hub-touch-min)" in meta_block

    meta_child_match = re.search(
        r"\.hub-overview-step-card__meta\s*>\s*\*\s*\{([^}]+)\}",
        css,
        re.DOTALL,
    )
    assert meta_child_match, ".hub-overview-step-card__meta > * rule missing"
    child_block = meta_child_match.group(1)
    assert "text-overflow: ellipsis" in child_block or "text-overflow:ellipsis" in child_block


def test_overview_top_three_cards_use_shared_frame_helpers() -> None:
    """AC2: router/internet grid builders and renderVpnSlot use shared frame classes."""
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    overview_source = _read(OVERVIEW_JS)
    render_vpn_body = _extract_function_body(overview_source, "function renderVpnSlot(")
    assert render_vpn_body is not None

    router_fn = re.search(
        r"export function buildRouterConnectionStatusCard\([\s\S]*?\n\}",
        grid_source,
    )
    assert router_fn, "buildRouterConnectionStatusCard missing"
    assert "createOverviewStepCardMain" in router_fn.group(0)

    internet_fn = re.search(
        r"export function buildInternetStatusCard\(options\) \{(.*?)^\}",
        grid_source,
        re.MULTILINE | re.DOTALL,
    )
    assert internet_fn, "buildInternetStatusCard missing"
    assert "createOverviewStepCardActions" in internet_fn.group(0)

    vpn_shell_fn = re.search(
        r"export function buildVpnStatusCardShell\([\s\S]*?\n\}",
        grid_source,
    )
    assert vpn_shell_fn, "buildVpnStatusCardShell missing"
    assert "createOverviewStepCardMain" in vpn_shell_fn.group(0)

    assert "hub-overview-step-card__actions" in render_vpn_body
    assert "hub-overview-step-card__meta" in render_vpn_body


def test_overview_card_grid_navigate_targets() -> None:
    """AC-3: карточки сетки ведут в connection/internet-uplink/staff/guest/vpn/domain/entry-pages/diagnostics."""
    overview_source = _read(OVERVIEW_JS)
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    combined = overview_source + grid_source + _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "navigate('connection')" in combined or "navigate(\"connection\")" in combined
    assert "navigate('internet-uplink')" in combined or "ctx.navigate('internet-uplink')" in overview_source
    assert "'connection'" in combined
    assert "staff-wifi" in combined
    assert "guest-wifi" in combined
    assert "navigate('vpn')" in combined or "ctx.navigate('vpn')" in overview_source
    assert "'domain'" in combined
    assert "#/entry-pages" in overview_source
    assert "#/diagnostics" in overview_source
    assert (
        "wireOverviewCardNavigate(card, 'entry-pages', navigate)" in grid_source
        or "navigate('entry-pages')" in grid_source
    )
    assert (
        "wireOverviewCardNavigate(card, 'diagnostics', navigate)" in grid_source
        or "navigate('diagnostics')" in grid_source
    )
    assert "wireOverviewCardNavigate" in grid_source


def test_overview_builders_do_not_call_run_diagnostics_checks() -> None:
    """R-9: Overview builders/mount must not reference runDiagnosticsChecks."""
    overview_source = _read(OVERVIEW_JS)
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    assert "runDiagnosticsChecks" not in overview_source
    assert "runDiagnosticsChecks" not in grid_source


def test_overview_card_grid_no_dbm_or_access_cert_probes() -> None:
    """Overview не показывает dBm и не вызывает access/cert probes."""
    combined = _read(OVERVIEW_JS) + _read(OVERVIEW_CARD_GRID_JS)
    assert "dBm" not in combined
    assert "probeLocalApplicationHttp" not in combined
    assert "probeLocalApplicationTls" not in combined
    assert "Доступ проверен" not in combined
    assert "Сертификат проверен" not in combined
    assert "chevron-down" not in combined
    assert "INTERNET_SOURCE_MODEM_NOTE" in combined


def test_overview_card_grid_node_harness_readiness_and_pills(tmp_path: Path) -> None:
    """Node harness: readiness numerator, pills, source segments, loading≠0/4."""
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    states_uri = json.dumps((HUB / "core" / "states.js").as_uri())
    script = f"""
const gridMod = await import({card_grid_uri});
const {{ HubState }} = await import({states_uri});

const loadingRing = gridMod.computeOverviewReadiness(null, {{}});
const allReadyExceptDomain = gridMod.computeOverviewReadiness(
  {{ router: {{ state: HubState.SUCCESS }} }},
  {{
    routerInternetObserve: {{ internet: true }},
    vpnItems: [{{
      is_active: true,
      live_probed: true,
      live_tunnel_verification_status: 'tunnel_healthy',
      routed_through_tunnel: true,
    }}],
    domainDraftName: 'lab-event',
    eventPresetId: 'preset-1',
  }},
);
const allReady = gridMod.computeOverviewReadiness(
  {{ router: {{ state: HubState.SUCCESS }} }},
  {{
    routerInternetObserve: {{ internet: true }},
    vpnItems: [{{
      is_active: true,
      live_probed: true,
      live_tunnel_verification_status: 'tunnel_healthy',
      routed_through_tunnel: true,
    }}],
    domainPublished: true,
  }},
);
const noneReady = gridMod.computeOverviewReadiness(
  {{ router: {{ state: HubState.WARNING }} }},
  {{
    routerInternetObserve: {{ internet: false }},
    vpnItems: [{{
      is_active: true,
      live_probed: true,
      live_tunnel_verification_status: 'tunnel_no_peer',
      routed_through_tunnel: true,
    }}],
    domainDraftName: '',
    eventPresetId: null,
  }},
);

const pills = gridMod.mapHealthFactsToRouterPills([
  {{ id: 'reachable', value: true, tone: 'success' }},
  {{ id: 'credentials_present', value: false, tone: 'danger' }},
  {{ id: 'tuple_match', value: null, tone: 'neutral' }},
]);

console.log(JSON.stringify({{
  loadingReady: loadingRing.ready,
  loadingLoaded: loadingRing.loaded,
  allReadyExceptDomainCount: allReadyExceptDomain.ready,
  allReadyCount: allReady.ready,
  noneReadyCount: noneReady.ready,
  pillLabels: pills.map((pill) => pill.label),
  pillTones: pills.map((pill) => pill.tone),
  wifiSegment: gridMod.mapInternetSourceKindToSegment('wifi'),
  wiredSegment: gridMod.mapInternetSourceKindToSegment('wired'),
  vpnSegment: gridMod.mapInternetSourceKindToSegment('vpn'),
  unknownSegment: gridMod.mapInternetSourceKindToSegment('unknown'),
  modemSegment: gridMod.mapInternetSourceKindToSegment('modem'),
}}));
"""
    payload = _run_node_harness(script, tmp_path, "overview-card-grid-readiness")
    assert payload["loadingReady"] is None
    assert payload["loadingLoaded"] is False
    assert payload["allReadyExceptDomainCount"] == 3
    assert payload["allReadyCount"] == 3  # domainPublished dispatch ≠ cloud registration
    assert payload["noneReadyCount"] == 0
    assert payload["pillLabels"] == ["Отвечает", "Доступ сохранён", "Совпадает: неизвестно"]
    assert payload["pillTones"] == ["success", "danger", "neutral"]
    assert payload["wifiSegment"] == "wifi"
    assert payload["wiredSegment"] == "wired"
    assert payload["vpnSegment"] is None
    assert payload["unknownSegment"] is None
    assert payload["modemSegment"] is None


def test_overview_cycle2_finally_repaints_readiness_and_strip() -> None:
    """F-1: finally после load/check снимает skeleton и перерисовывает ring/strip."""
    source = _read(OVERVIEW_JS)
    finally_blocks = re.findall(r"finally\s*\{", source)
    assert len(finally_blocks) >= 2
    assert "renderReadinessHeader()" in source
    assert "renderStatusStrip()" in source
    reload_finally = source.split("async function reloadOverviewInternal")[1].split("async function runSystemCheckOnly")[0]
    check_finally = source.split("async function runSystemCheckOnly")[1].split("function startRefreshInterval")[0]
    for block in (reload_finally, check_finally):
        assert "renderSummary()" in block
        assert "renderReadinessHeader()" in block
        assert "renderStatusStrip()" in block


def test_overview_cycle2_load_path_assigns_system_check_facts() -> None:
    """F-2: initial loadOverview сохраняет DescribedFact для pills."""
    overview_source = _read(OVERVIEW_JS)
    model_source = _read(OVERVIEW_MODEL_JS)
    assert "systemCheckFacts" in model_source
    assert "lastSystemCheckFacts = Array.isArray(nextModel.systemCheckFacts)" in overview_source


def test_overview_cycle2_failed_recheck_clears_stale_facts() -> None:
    """F-3: ошибка ручной проверки сбрасывает pills в unknown/neutral."""
    source = _read(OVERVIEW_JS)
    catch_block = source.split("async function runSystemCheckOnly")[1].split("} finally {")[0]
    assert "lastSystemCheckFacts = null" in catch_block
    assert "renderRouterCardSlot()" in catch_block


def test_overview_cycle2_enrichment_refreshes_readiness() -> None:
    """F-4: enrichment busy держит ring в loading и обновляет N/4 после settle."""
    overview_source = _read(OVERVIEW_JS)
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    assert "internetEnrichmentBusy" in overview_source
    assert "vpnEnrichmentBusy" in overview_source
    assert "internetEnrichmentBusy" in grid_source
    assert "vpnEnrichmentBusy" in grid_source
    assert "systemCheckRunning" in grid_source
    enrichment_fn = overview_source.split("async function runOverviewEnrichment")[1].split("function buildSummaryPanelOptions")[0]
    assert enrichment_fn.count("renderReadinessHeader()") >= 2
    assert enrichment_fn.count("renderStatusStrip()") >= 2


def test_overview_cycle3_enrichment_busy_cleared_unconditionally() -> None:
    """F-1/F-7: enrichment finally always clears busy; abortAllOperations re-paints."""
    source = _read(OVERVIEW_JS)
    enrichment_fn = source.split("async function runOverviewEnrichment")[1].split("function buildSummaryPanelOptions")[0]
    internet_finally = enrichment_fn.split("} finally {", 1)[1]
    vpn_finally = enrichment_fn.split("} finally {", 2)[2]
    for flag, block in (
        ("internetEnrichmentBusy = false", internet_finally),
        ("vpnEnrichmentBusy = false", vpn_finally),
    ):
        assert flag in block, f"{flag} must appear in enrichment finally"
        before_render_guard = block.split("if (gen === generation", 1)[0]
        assert flag in before_render_guard, (
            f"{flag} must be cleared before generation-gated re-render guard"
        )
    abort_body = _extract_function_body(source, "function abortAllOperations(")
    assert abort_body is not None
    normalized_abort = _normalize_whitespace(abort_body)
    assert "internetEnrichmentBusy = false" in normalized_abort
    assert "vpnEnrichmentBusy = false" in normalized_abort
    assert "renderReadinessHeader()" in normalized_abort
    assert "renderStatusStrip()" in normalized_abort


def test_overview_cycle3_load_failure_clears_system_check_facts() -> None:
    """F-8: reload catch on load failure clears stale lastSystemCheckFacts."""
    source = _read(OVERVIEW_JS)
    reload_body = _extract_function_body(source, "async function reloadOverviewInternal(")
    assert reload_body is not None
    catch_block = reload_body.split("} catch (error) {", 1)[1].split("} finally {", 1)[0]
    assert "model = null" in catch_block
    assert "lastSystemCheckFacts = null" in catch_block
    assert "lastRouterCardSignature = null" in catch_block


def test_overview_cycle3_system_check_paints_busy_immediately() -> None:
    """F-9: runSystemCheckOnly start paints readiness header and status strip."""
    source = _read(OVERVIEW_JS)
    sc_body = _extract_function_body(source, "async function runSystemCheckOnly(")
    assert sc_body is not None
    idx_running = sc_body.find("systemCheckRunning = true")
    assert idx_running != -1
    idx_summary = sc_body.find("renderSummary()", idx_running)
    assert idx_summary != -1
    idx_readiness = sc_body.find("renderReadinessHeader()", idx_summary)
    idx_strip = sc_body.find("renderStatusStrip()", idx_summary)
    assert idx_readiness != -1 and idx_readiness > idx_summary
    assert idx_strip != -1 and idx_strip > idx_summary


def test_progress_ring_svg_elements_never_assign_class_name_property() -> None:
    """F-10 (live-caught regression): SVGElement.className is a read-only
    SVGAnimatedString getter in real browsers — assigning `.className = "..."`
    on an svg/circle node created via createElementNS throws a TypeError at
    runtime (Cannot set property className of #<SVGElement> which has only a
    getter), silently breaking createProgressRing/buildOverviewReadinessHeader
    every render without any exception surfaced to the operator. Only
    setAttribute('class', ...) or classList is safe on namespaced SVG nodes.
    This slipped past every prior static/node-harness test because none of
    them actually executed createProgressRing() against a real DOM — caught
    only by live browser verification on the real host.
    """
    source = _read(PROGRESS_RING_JS)
    assert "createElementNS" in source, "expected SVG elements to be created via createElementNS"
    for var_name in ("svg", "track", "progress"):
        assert f"{var_name}.className = " not in source, (
            f"{var_name} is created via createElementNS (real SVGElement) — "
            "must use setAttribute('class', ...), not .className assignment "
            "(throws TypeError: Cannot set property className of "
            "#<SVGElement> which has only a getter)"
        )
    assert source.count("setAttribute('class'") >= 3, (
        "expected class attribute set via setAttribute for svg + both circle elements"
    )


def test_overview_cycle2_null_facts_unknown_pill_labels(tmp_path: Path) -> None:
    """F-5: null DescribedFact → «…: неизвестно», не голое утвердительное."""
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    script = f"""
const gridMod = await import({card_grid_uri});
const pills = gridMod.mapHealthFactsToRouterPills(null);
console.log(JSON.stringify({{ labels: pills.map((pill) => pill.label) }}));
"""
    payload = _run_node_harness(script, tmp_path, "overview-null-fact-pills")
    assert payload["labels"] == [
        "Отвечает: неизвестно",
        "Доступ сохранён: неизвестно",
        "Совпадает: неизвестно",
    ]


def test_overview_cycle2_enrichment_busy_readiness_loading(tmp_path: Path) -> None:
    """F-4: пока enrichment busy — loaded=false, ready=null (не ложный 0/4)."""
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    states_uri = json.dumps((HUB / "core" / "states.js").as_uri())
    script = f"""
const gridMod = await import({card_grid_uri});
const {{ HubState }} = await import({states_uri});
const busy = gridMod.computeOverviewReadiness(
  {{ router: {{ state: HubState.SUCCESS }} }},
  {{ internetEnrichmentBusy: true }},
);
console.log(JSON.stringify({{ ready: busy.ready, loaded: busy.loaded }}));
"""
    payload = _run_node_harness(script, tmp_path, "overview-enrichment-busy-readiness")
    assert payload["ready"] is None
    assert payload["loaded"] is False


def test_overview_wired_segment_label_matches_operator_reference() -> None:
    """Сегмент проводного источника подписан «Кабель» — по референсу оператора.

    Раньше здесь требовалось «Провод» (как возвращает describeInternetSource),
    чтобы подпись не расходилась с текстом «Сейчас: …» на той же карточке.
    Конфликта больше нет: строка «Сейчас: …» рендерится только для kind === 'vpn',
    поэтому для проводного шлюза «Кабель» — единственная формулировка на экране.
    """
    source = _read(OVERVIEW_CARD_GRID_JS)
    assert "{ id: 'wired', label: 'Кабель' }" in source
    current_source_line = "`Сейчас: ${described.label}`"
    assert current_source_line in source
    vpn_only_guard = "described?.kind === 'vpn'"
    assert vpn_only_guard in source, (
        "строка «Сейчас: …» должна оставаться только для VPN — иначе на карточке "
        "одновременно появятся «Кабель» и «Провод» про один и тот же источник"
    )


def test_overview_card_skeleton_cold_gate_strings() -> None:
    source = _read(OVERVIEW_JS)
    gate_body = _extract_function_body(source, "function shouldShowOverviewCardSkeletons(")
    assert gate_body is not None
    assert "!model" in gate_body
    assert "!loadError" in gate_body
    assert "!offline" in gate_body


def test_overview_show_card_skeletons_wiring() -> None:
    source = _read(OVERVIEW_JS)
    show_body = _extract_function_body(source, "function showOverviewCardSkeletons(")
    assert show_body is not None
    assert "lastRouterCardSignature = null" in show_body
    assert "lastInternetCardSignature = null" in show_body
    assert "lastVpnSignature = null" in show_body
    assert "renderRouterCardSlot()" in show_body
    assert "renderInternetCardSlot()" in show_body
    assert "renderVpnSlot()" in show_body


def test_overview_boot_skeletons_after_mount() -> None:
    source = _read(OVERVIEW_JS)
    boot_tail = source.split("renderSummarySkeleton();", 1)[1].split("void ensureOverviewLoadedAfterRestore();", 1)[0]
    assert "mountOverviewActionSlots();" in boot_tail
    assert "shouldShowOverviewCardSkeletons()" in boot_tail
    assert "showOverviewCardSkeletons();" in boot_tail
    assert boot_tail.index("mountOverviewActionSlots();") < boot_tail.index("showOverviewCardSkeletons();")


def test_overview_reload_null_model_shows_skeletons() -> None:
    source = _read(OVERVIEW_JS)
    reload_body = _extract_function_body(source, "async function reloadOverviewInternal(")
    assert reload_body is not None
    assert "loadError = null" in reload_body
    assert "if (model === null)" in reload_body
    assert "showOverviewCardSkeletons();" in reload_body


def test_overview_first_model_assign_unsettles_vpn_catalog() -> None:
    source = _read(OVERVIEW_JS)
    reload_body = _extract_function_body(source, "async function reloadOverviewInternal(")
    assert reload_body is not None
    success_block = reload_body.split("model = nextModel", 1)[0]
    assert "wasNullModel = model === null" in success_block or "const wasNullModel = model === null" in reload_body
    after_model = reload_body.split("model = nextModel", 1)[1].split("renderAll();", 1)[0]
    assert "if (wasNullModel)" in after_model
    assert "vpnCatalogSettled = false" in after_model


def test_overview_skeleton_builder_dom_a11y(tmp_path: Path) -> None:
    card_grid_uri = json.dumps(OVERVIEW_CARD_GRID_JS.as_uri())
    harness_uri = json.dumps(str(UI_DOM_HARNESS))
    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);
const {{ createUiDomHarness }} = require({harness_uri});
const dom = createUiDomHarness();
globalThis.document = dom.document;
globalThis.window = dom.window;
Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

const gridMod = await import({card_grid_uri});
for (const [variant, label] of [
  ['router', 'Роутер'],
  ['internet', 'Интернет'],
  ['vpn', 'VPN'],
]) {{
  const step = variant === 'router' ? 1 : variant === 'internet' ? 2 : 3;
  const card = gridMod.buildOverviewStepCardSkeleton({{ stepNumber: step, variant }});
  dom.document.body.appendChild(card);
  if (card.getAttribute('aria-label') !== `Загрузка: ${{label}}`) {{
    throw new Error(`aria-label mismatch for ${{variant}}`);
  }}
  if (card.getAttribute('role') !== 'status') throw new Error('role status missing');
  if (card.getAttribute('aria-busy') !== 'true') throw new Error('aria-busy missing');
  if (card.querySelector('[aria-hidden=\"true\"]') === null) throw new Error('bones aria-hidden missing');
  if (card.querySelector('button, a[href]')) throw new Error('interactive element in skeleton');
  dom.document.body.removeChild(card);
}}
console.log(JSON.stringify({{ ok: true }}));
"""
    payload = _run_node_harness(script, tmp_path, "overview-skeleton-a11y")
    assert payload["ok"] is True


def _extract_subscribe_connectivity_callback(source: str) -> str:
    """Извлекает тело subscribeConnectivity((online) => { ... }) в render()."""
    render_body = _extract_function_body(source, "export function render(")
    assert render_body is not None
    marker = "subscribeConnectivity((online) => {"
    start = render_body.find(marker)
    assert start != -1, "subscribeConnectivity callback missing"
    brace = render_body.find("{", start + len(marker) - 1)
    depth = 0
    j = brace
    while j < len(render_body):
        c = render_body[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return render_body[brace + 1 : j]
        j += 1
    raise AssertionError("subscribeConnectivity callback body not closed")


def test_overview_domain_publish_connectivity_syncs_domain_mount() -> None:
    """Overview domain CTA: both connectivity arms call domainMount?.update(); mount uses getDisabled."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)
    normalized = _normalize_whitespace(callback)

    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "offline = true" in _normalize_whitespace(offline_block)
    assert "domainMount?.update()" in offline_block
    update_idx = offline_block.find("domainMount?.update()")
    return_idx = offline_block.find("return")
    assert update_idx != -1 and return_idx != -1 and update_idx < return_idx

    online_offline_false = callback.split("if (!online)", 1)[1].split("}", 1)[1]
    reload_idx = online_offline_false.find("void requestReloadOverview()")
    assert reload_idx != -1
    before_reload = online_offline_false[:reload_idx]
    assert "offline = false" in before_reload
    assert "domainMount?.update()" in before_reload
    assert ".then" not in before_reload.split("domainMount?.update()")[-1]

    slots_body = _extract_function_body(source, "function mountOverviewActionSlots(")
    assert slots_body is not None
    mount_start = slots_body.find("mountDomainSimplePublishAffordance(")
    assert mount_start != -1
    mount_end = slots_body.find("});", mount_start)
    assert mount_end != -1
    mount_block = slots_body[mount_start : mount_end + 3]
    assert _normalize_whitespace("getDisabled: () => offline") in _normalize_whitespace(mount_block)
    assert "disabled: offline" not in mount_block


def test_overview_connectivity_both_arms_call_render_vpn_slot() -> None:
    """AC-2: subscribeConnectivity offline/online arms call renderVpnSlot() after domainMount update."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)

    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "domainMount?.update()" in offline_block
    assert "renderVpnSlot()" in offline_block
    update_idx = offline_block.find("domainMount?.update()")
    render_idx = offline_block.find("renderVpnSlot()")
    return_idx = offline_block.find("return")
    assert update_idx != -1 and render_idx != -1 and return_idx != -1
    assert update_idx < render_idx < return_idx

    online_offline_false = callback.split("if (!online)", 1)[1].split("}", 1)[1]
    reload_idx = online_offline_false.find("void requestReloadOverview()")
    assert reload_idx != -1
    before_reload = online_offline_false[:reload_idx]
    assert "domainMount?.update()" in before_reload
    assert "renderVpnSlot()" in before_reload
    online_update_idx = before_reload.find("domainMount?.update()")
    online_render_idx = before_reload.find("renderVpnSlot()")
    assert online_update_idx != -1 and online_render_idx != -1
    assert online_update_idx < online_render_idx


def test_overview_networks_connectivity_syncs_networks_mount() -> None:
    """Overview networks: both connectivity arms call networksMount?.update(); mount uses getDisabled."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)

    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "networksMount?.update()" in offline_block
    update_idx = offline_block.find("networksMount?.update()")
    return_idx = offline_block.find("return")
    assert update_idx != -1 and return_idx != -1 and update_idx < return_idx

    online_offline_false = callback.split("if (!online)", 1)[1].split("}", 1)[1]
    reload_idx = online_offline_false.find("void requestReloadOverview()")
    assert reload_idx != -1
    before_reload = online_offline_false[:reload_idx]
    assert "networksMount?.update()" in before_reload
    assert ".then" not in before_reload.split("networksMount?.update()")[-1]

    slots_body = _extract_function_body(source, "function mountOverviewActionSlots(")
    assert slots_body is not None
    mount_start = slots_body.find("mountOverviewSimpleNetworks(")
    assert mount_start != -1
    mount_end = slots_body.find("});", mount_start)
    assert mount_end != -1
    mount_block = slots_body[mount_start : mount_end + 3]
    assert _normalize_whitespace("getDisabled: () => offline") in _normalize_whitespace(mount_block)


def test_overview_connectivity_both_arms_refresh_networks_after_domain() -> None:
    """AC-3: subscribeConnectivity offline/online arms call networksMount?.update() after domainMount."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)

    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "domainMount?.update()" in offline_block
    assert "networksMount?.update()" in offline_block
    domain_idx = offline_block.find("domainMount?.update()")
    networks_idx = offline_block.find("networksMount?.update()")
    render_idx = offline_block.find("renderVpnSlot()")
    return_idx = offline_block.find("return")
    assert domain_idx != -1 and networks_idx != -1 and render_idx != -1 and return_idx != -1
    assert domain_idx < networks_idx < render_idx < return_idx

    online_offline_false = callback.split("if (!online)", 1)[1].split("}", 1)[1]
    reload_idx = online_offline_false.find("void requestReloadOverview()")
    assert reload_idx != -1
    before_reload = online_offline_false[:reload_idx]
    assert "domainMount?.update()" in before_reload
    assert "networksMount?.update()" in before_reload
    assert "renderVpnSlot()" in before_reload
    online_domain_idx = before_reload.find("domainMount?.update()")
    online_networks_idx = before_reload.find("networksMount?.update()")
    online_render_idx = before_reload.find("renderVpnSlot()")
    assert online_domain_idx != -1 and online_networks_idx != -1 and online_render_idx != -1
    assert online_domain_idx < online_networks_idx < online_render_idx


def test_overview_status_strip_system_check_disabled_when_offline() -> None:
    """AC-1: «Проверить всё» createButton disabled when offline."""
    grid_source = _read(OVERVIEW_CARD_GRID_JS)
    strip_body = _extract_function_body(grid_source, "export function buildOverviewStatusStrip(")
    assert strip_body is not None
    normalized = _normalize_whitespace(strip_body)
    assert "offline" in normalized
    assert "disabled" in normalized
    create_btn = strip_body.split("createButton(")[1].split("});", 1)[0]
    assert "disabled:" in create_btn
    assert "offline" in create_btn or "disabled" in create_btn
    assert "busy: checkBusy" in _normalize_whitespace(create_btn) or "busy:checkBusy" in _normalize_whitespace(create_btn)

    screen_source = _read(OVERVIEW_JS)
    render_body = _extract_function_body(screen_source, "function renderStatusStrip(")
    assert render_body is not None
    assert "offline" in render_body
    build_call = render_body.split("buildOverviewStatusStrip(")[1].split("}),", 1)[0]
    assert "offline" in build_call


def test_overview_connectivity_both_arms_call_render_status_strip() -> None:
    """AC-2: subscribeConnectivity offline/online arms call renderStatusStrip()."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)

    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "renderStatusStrip()" in offline_block
    render_idx = offline_block.find("renderStatusStrip()")
    return_idx = offline_block.find("return")
    assert render_idx != -1 and return_idx != -1 and render_idx < return_idx

    online_offline_false = callback.split("if (!online)", 1)[1].split("}", 1)[1]
    reload_idx = online_offline_false.find("void requestReloadOverview()")
    assert reload_idx != -1
    before_reload = online_offline_false[:reload_idx]
    assert "renderStatusStrip()" in before_reload
    online_render_idx = before_reload.find("renderStatusStrip()")
    assert online_render_idx != -1


def test_overview_connectivity_offline_clears_stale_evidence() -> None:
    """overview-offline-stale-evidence: offline arm clears routerInternetObserve and vpnLiveStatusById."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)

    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    normalized = _normalize_whitespace(offline_block)
    assert "routerInternetObserve = null" in normalized
    assert "vpnLiveStatusById = {}" in normalized
    observe_idx = normalized.find("routerInternetObserve = null")
    vpn_idx = normalized.find("vpnLiveStatusById = {}")
    render_readiness_idx = normalized.find("renderReadinessHeader()")
    render_internet_idx = normalized.find("renderInternetCardSlot()")
    render_vpn_idx = normalized.find("renderVpnSlot()")
    return_idx = normalized.find("return")
    assert observe_idx != -1 and vpn_idx != -1
    assert observe_idx < render_readiness_idx < render_internet_idx < render_vpn_idx < return_idx


def test_overview_vpn_live_status_catch_clears_stale_cache() -> None:
    """overview-offline-stale-evidence: live-status probe failure clears vpnLiveStatusById fail-closed."""
    source = _read(OVERVIEW_JS)
    fn_body = _extract_function_body(source, "async function refreshVpnCatalogAndLiveStatus(")
    assert fn_body is not None
    catch_start = fn_body.find("} catch (liveError) {")
    assert catch_start != -1
    catch_block = fn_body[catch_start:]
    assert "isAborted(liveError)" in catch_block
    assert re.search(
        r"vpnLiveStatusById\s*=\s*\{\};",
        catch_block,
    ), "live-status catch must clear stale vpnLiveStatusById fail-closed"
    assert "optional live-status failure must not block catalog settle" in catch_block


def test_overview_vpn_live_status_abort_guard_before_assign() -> None:
    """overview-offline-abort-races: guard after fetchVpnCatalogLiveStatus before vpnLiveStatusById assign."""
    source = _read(OVERVIEW_JS)
    fn_body = _extract_function_body(source, "async function refreshVpnCatalogAndLiveStatus(")
    assert fn_body is not None
    fetch_idx = fn_body.find("await fetchVpnCatalogLiveStatus({ session, signal })")
    assert fetch_idx != -1
    assign_idx = fn_body.find("vpnLiveStatusById = nextLive")
    assert assign_idx != -1
    between = fn_body[fetch_idx:assign_idx]
    guard_idx = between.find("if (disposed || signal?.aborted)")
    assert guard_idx != -1, "abort/disposed guard must follow fetchVpnCatalogLiveStatus"
    guard_block = between[guard_idx : guard_idx + 80]
    assert "return" in guard_block


def test_overview_refresh_router_internet_observe_abort_guard() -> None:
    """overview-offline-abort-races: guard after fetch before routerInternetObserve assign."""
    source = _read(OVERVIEW_JS)
    fn_body = _extract_function_body(source, "async function refreshRouterInternetObserve(")
    assert fn_body is not None
    fetch_idx = fn_body.find("await fetchRouterInternetObserve({ session, signal })")
    assert fetch_idx != -1
    assign_idx = fn_body.find("routerInternetObserve = observeResult")
    assert assign_idx != -1
    between = fn_body[fetch_idx:assign_idx]
    assert "if (disposed || signal?.aborted)" in between
    assert "return" in between


def test_overview_connectivity_offline_aborts_load_and_system_check() -> None:
    """overview-offline-abort-races: offline arm aborts loadAbort and systemCheckAbort."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)
    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    normalized = _normalize_whitespace(offline_block)
    assert "loadAbort?.abort()" in normalized
    assert "systemCheckAbort?.abort()" in normalized
    load_idx = normalized.find("loadAbort?.abort()")
    system_idx = normalized.find("systemCheckAbort?.abort()")
    internet_idx = normalized.find("internetObserveAbort?.abort()")
    assert load_idx != -1 and system_idx != -1 and internet_idx != -1
    assert load_idx < system_idx < internet_idx


def test_overview_connectivity_offline_invalidates_overview_mutations() -> None:
    """domain-connection-offline-invalidate: offline arm aborts mutateAbort and clears VPN mutation UI."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)
    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "invalidateOverviewMutations()" in offline_block
    invalidate_idx = offline_block.find("invalidateOverviewMutations()")
    return_idx = offline_block.find("return")
    assert invalidate_idx != -1 and return_idx != -1 and invalidate_idx < return_idx


def test_overview_mutations_use_dedicated_mutate_abort() -> None:
    """domain-connection-offline-invalidate: VPN/network mutations use mutateAbort, skip toasts when offline."""
    source = _read(OVERVIEW_JS)
    assert "let mutateAbort = null" in source
    assert "let publishAbort = null" in source
    assert "function ensureMutateAbort()" in source
    assert "function invalidateOverviewMutations()" in source

    slots_body = _extract_function_body(source, "function mountOverviewActionSlots(")
    assert slots_body is not None
    assert "getSignal: () => ensureMutateAbort()" in slots_body
    publish_start = slots_body.find("onPublishApply:")
    assert publish_start != -1
    publish_body = slots_body[publish_start:]
    assert "publishAbort = new AbortController()" in publish_body
    assert "ensureMutateAbort()" not in publish_body

    abort_body = _extract_function_body(source, "function abortAllOperations(")
    assert abort_body is not None
    assert "invalidateOverviewMutations()" in abort_body

    for fn_sig in (
        "async function runOverviewVpnActivate(",
        "async function runOverviewVpnDeactivate(",
    ):
        body = _extract_function_body(source, fn_sig)
        assert body is not None
        assert "mutateAbort = new AbortController()" in body
        assert "signal: mutationSignal" in body
        response_guard = body.split("await ", 1)[1]
        toast_idx = response_guard.find("ctx.showToast(")
        assert toast_idx != -1
        before_toast = response_guard[:toast_idx]
        assert "if (disposed || offline)" in before_toast
        assert "return" in before_toast


def test_overview_vpn_activate_deactivate_finally_repaints_readiness() -> None:
    """overview-offline-abort-races: VPN activate/deactivate finally repaint readiness + status strip."""
    source = _read(OVERVIEW_JS)
    for fn_sig in (
        "async function runOverviewVpnActivate(",
        "async function runOverviewVpnDeactivate(",
    ):
        body = _extract_function_body(source, fn_sig)
        assert body is not None
        finally_start = body.rfind("} finally {")
        assert finally_start != -1
        finally_block = body[finally_start:]
        assert "renderVpnSlot()" in finally_block
        assert "renderReadinessHeader()" in finally_block
        assert "renderStatusStrip()" in finally_block
        vpn_idx = finally_block.find("renderVpnSlot()")
        readiness_idx = finally_block.find("renderReadinessHeader()")
        strip_idx = finally_block.find("renderStatusStrip()")
        assert vpn_idx != -1 and readiness_idx != -1 and strip_idx != -1
        assert vpn_idx < readiness_idx < strip_idx


def test_overview_networks_staff_enable_mutation_readiness_gated() -> None:
    """Staff enable CTA gated by evaluateStaffWifiMutationReadiness (parity with guest toggle)."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    staff_render_body = _extract_function_body(source, "function renderStaffSlot(")
    assert staff_render_body is not None
    assert "evaluateStaffWifiMutationReadiness" in staff_render_body
    assert "staffMutationBlocked" in staff_render_body
    staff_enable_region = staff_render_body.split("Включить рабочую сеть", 1)[1].split("staff-defaults", 1)[0]
    assert "staffMutationBlocked" in staff_enable_region


def test_overview_networks_run_mutation_resolve_disabled_guard() -> None:
    """AC-2: runMutation early-returns when resolveDisabled() is true."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "function resolveDisabled()" in source
    assert "typeof getDisabled === 'function'" in source
    run_mutation_body = _extract_function_body(source, "async function runMutation(")
    assert run_mutation_body is not None
    disabled_check = run_mutation_body.find("if (resolveDisabled())")
    restore_check = run_mutation_body.find("if (isRestorePending())")
    show_progress = run_mutation_body.find("showSlotProgress(")
    assert restore_check != -1 and disabled_check != -1 and show_progress != -1
    assert restore_check < disabled_check < show_progress
    assert "resolveDisabled() ? '1' : '0'" in source
    assert "disabled: staffBusy || loading || resolveDisabled() || staffMutationBlocked" in source
    assert "disabled: guestBusy || loading || resolveDisabled()" in source
    assert "disabled: busy || resolveDisabled()" in source


def test_overview_vpn_mutation_readiness_gated() -> None:
    """Overview VPN activate/deactivate gated by evaluateVpnMutationReadiness for fake/incomplete."""
    source = _read(OVERVIEW_JS)
    assert "evaluateVpnMutationReadiness" in source
    assert "function vpnMutationReadiness()" in source
    assert "vpnMutationBlocked" in source

    activate_body = _extract_function_body(source, "async function runOverviewVpnActivate(")
    deactivate_body = _extract_function_body(source, "async function runOverviewVpnDeactivate(")
    render_vpn_body = _extract_function_body(source, "function renderVpnSlot(")
    assert activate_body is not None
    assert deactivate_body is not None
    assert render_vpn_body is not None
    assert "!vpnMutationReadiness().allowed" in activate_body
    assert "!vpnMutationReadiness().allowed" in deactivate_body
    assert "vpnMutationBlocked" in render_vpn_body
    cta_block = render_vpn_body.split("actionDisabled", 1)[1].split("ctaBtn = createButton", 1)[0]
    assert "vpnMutationBlocked" in cta_block
    picker_block = render_vpn_body.split("buildOverviewVpnProfilePicker", 1)[1].split("});", 1)[0]
    assert "vpnMutationBlocked" in picker_block
    signature_body = _extract_function_body(source, "function buildVpnSlotSignature(")
    assert signature_body is not None
    assert "vpnMutationReadiness().allowed" in signature_body


def test_overview_vpn_refresh_uses_mutate_abort_not_enrichment() -> None:
    """keendns-signal-overview-toast-guards: VPN refresh uses mutationSignal, not enrichmentAbort."""
    source = _read(OVERVIEW_JS)
    for fn_sig in (
        "async function runOverviewVpnActivate(",
        "async function runOverviewVpnDeactivate(",
    ):
        body = _extract_function_body(source, fn_sig)
        assert body is not None
        assert "enrichmentAbort?.signal" not in body
        assert "refreshVpnCatalogAndLiveStatus(mutationSignal)" in body
        refresh_region = body.split("refreshVpnCatalogAndLiveStatus(mutationSignal)", 1)[0]
        assert "!offline" in refresh_region
        assert "!mutationSignal.aborted" in refresh_region


def test_overview_invalidate_mutations_does_not_abort_publish_abort() -> None:
    """overview-entry-abort-residuals: VPN invalidate must not abort in-flight KeenDNS publish."""
    source = _read(OVERVIEW_JS)
    invalidate_body = _extract_function_body(source, "function invalidateOverviewMutations(")
    assert invalidate_body is not None
    assert "publishAbort" not in invalidate_body


def test_overview_connectivity_offline_aborts_publish_abort() -> None:
    """overview-entry-abort-residuals: offline arm aborts dedicated publishAbort."""
    source = _read(OVERVIEW_JS)
    callback = _extract_subscribe_connectivity_callback(source)
    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    offline_return = offline_arm.find("return")
    offline_block = offline_arm[: offline_return + len("return")]
    assert "publishAbort?.abort()" in offline_block


def test_overview_networks_mount_passes_get_offline() -> None:
    """keendns-signal-overview-toast-guards: overview passes getOffline to simple-networks mount."""
    source = _read(OVERVIEW_JS)
    slots_body = _extract_function_body(source, "function mountOverviewActionSlots(")
    assert slots_body is not None
    assert "getOffline: () => offline" in slots_body


def test_overview_networks_run_mutation_skips_toast_when_aborted_or_offline() -> None:
    """keendns-signal-overview-toast-guards: runMutation skips success toast on abort/offline."""
    source = _read(OVERVIEW_SIMPLE_NETWORKS_JS)
    assert "function resolveOffline()" in source
    run_mutation_body = _extract_function_body(source, "async function runMutation(")
    assert run_mutation_body is not None
    toast_region = run_mutation_body.split("options.showToast({", 1)[0]
    assert "!signal?.aborted" in toast_region
    assert "resolveOffline()" in toast_region
