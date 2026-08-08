"""Структурные контракты buildless-фронтенда LOCAL HUB (без сети и без Node-тестов)."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
STATES_JS = HUB / "core" / "states.js"
ERRORS_JS = HUB / "core" / "errors.js"
API_JS = HUB / "core" / "api.js"
ROUTER_JS = HUB / "core" / "router.js"
STUB_JS = HUB / "screens" / "stub.js"
TOKENS_CSS = HUB / "styles" / "tokens.css"
BASE_CSS = HUB / "styles" / "base.css"
SHELL_CSS = HUB / "styles" / "shell.css"
STATES_CSS = HUB / "styles" / "states.css"
SCREENS_CSS = HUB / "styles" / "screens.css"
COMPONENTS_CSS = HUB / "styles" / "components.css"
MODAL_JS = HUB / "components" / "modal.js"
HUB_STYLES_DIR = HUB / "styles"
PILL_BORDER_RADIUS = "var(--hub-radius-pill)"

NARROW_COMPONENT_REGISTRY = (
    ".hub-badge",
    ".hub-state-inline",
    ".hub-shell__mode",
    ".hub-shell__menu-bar",
    ".hub-btn",
)

NARROW_COMPONENT_STRETCH_ALLOWLIST = frozenset(
    {
        ".hub-state-inline--full",
        ".hub-btn--block",
        # Mobile full-width opt-in (screens.css) — полная ширина осознанна
        "@media (max-width: 700px) .hub-wifi-network__actions .hub-btn",
        "@media (max-width: 700px) .hub-wifi__footer-left .hub-btn",
        "@media (max-width: 700px) .hub-wifi__footer-right .hub-btn",
        "@media (max-width: 700px) .hub-vpn__footer.hub-wifi__footer .hub-btn",
        "@media (max-width: 700px) .hub-vpn__footer.hub-wifi__footer "
        ".hub-wifi__footer-left .hub-btn",
        "@media (max-width: 700px) .hub-vpn__footer.hub-wifi__footer "
        ".hub-wifi__footer-right .hub-btn",
        "@media (max-width: 700px) .hub-domain__footer.hub-wifi__footer .hub-btn",
        "@media (max-width: 700px) .hub-domain__footer.hub-wifi__footer "
        ".hub-wifi__footer-left .hub-btn",
        "@media (max-width: 700px) .hub-domain__footer.hub-wifi__footer "
        ".hub-wifi__footer-right .hub-btn",
    }
)

STRETCH_VIOLATION_HINT = (
    "узкий по смыслу элемент растянется в flex-колонке; "
    "если полная ширина нужна, объявите её явно и внесите в allowlist"
)

EXPECTED_HUB_STATES = frozenset(
    {
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
    }
)

FORBIDDEN_STORAGE = ("localStorage", "sessionStorage", "indexedDB", "document.cookie")
FORBIDDEN_EXTERNAL_SCHEME = ("http://", "https://")
FORBIDDEN_EXTERNAL_OTHER = ("@import", "//cdn")
FORBIDDEN_EXTERNAL_SCHEME_CI = re.compile(r"https?://", re.I)
FORBIDDEN_PROTOCOL_RELATIVE = re.compile(r"(?<![:/])//[A-Za-z0-9]")

DOMAIN_MODEL_JS = HUB / "features" / "domain-model.js"
ICON_JS = HUB / "components" / "icon.js"
DOMAIN_MODEL_ALLOWED_SCHEME_COUNTS = {
    "http://": 1,
    "https://": 1,
}
# Фиксированный XML namespace URI для createElementNS(...) — не сетевой ресурс,
# браузер никогда его не запрашивает по сети. Вычитается из текста до сканирования
# схем, чтобы не путать namespace identifier с реальным внешним URL.
SVG_NAMESPACE_URI = "http://www.w3.org/2000/svg"
STYLE_TOKEN_FILES = (
    HUB / "styles" / "components.css",
    HUB / "styles" / "states.css",
    HUB / "styles" / "shell.css",
    HUB / "styles" / "screens.css",
)

HEX_COLOR = re.compile(r"#[0-9a-fA-F]{3,8}\b")
RGB_FUNCS = re.compile(r"\b(?:rgb|rgba|hsl|hsla)\(")
STUB_SCREEN_FILES = (
)

FORBIDDEN_USER_JARGON = ("Gate A", "WireGuard", "VLAN", "DHCP", "firewall")
DUPLICATE_STUB_PATTERN = re.compile(
    r"join\s*\(\s*['\"][;,]['\"]\s*\).*features",
    re.IGNORECASE,
)
CYRILLIC = re.compile(r"[А-Яа-яЁё]")

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub JS syntax checks; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _iter_hub_files(*suffixes: str) -> list[Path]:
    ext = {s if s.startswith(".") else f".{s}" for s in suffixes}
    return sorted(
        path
        for path in HUB.rglob("*")
        if path.is_file() and path.suffix in ext
    )


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
            match = re.match(r"\s*(\w+)\s*:", source[i:])
            if match:
                keys.add(match.group(1))
                i += match.end()
                continue
        i += 1
    return keys


def _find_forbidden_substrings(text: str, needles: tuple[str, ...]) -> list[str]:
    return [needle for needle in needles if needle in text]


def _is_inside_hover_media(css: str, pos: int) -> bool:
    depth = 0
    hover_depths: list[int] = []
    i = 0
    while i < pos:
        if css.startswith("@media", i):
            brace = css.find("{", i)
            if brace == -1 or brace >= pos:
                break
            query = css[i:brace]
            normalized = re.sub(r"\s+", "", query)
            is_hover = "(hover:hover)" in normalized
            i = brace
            depth += 1
            if is_hover:
                hover_depths.append(depth)
            i += 1
            continue
        char = css[i]
        if char == "{":
            depth += 1
        elif char == "}":
            hover_depths = [level for level in hover_depths if level != depth]
            depth -= 1
        i += 1
    return bool(hover_depths)


def _find_hover_violations(css: str) -> list[int]:
    lines: list[int] = []
    for match in re.finditer(r":hover", css):
        if not _is_inside_hover_media(css, match.start()):
            lines.append(css[: match.start()].count("\n") + 1)
    return lines


def _find_raw_color_literals(css: str) -> list[str]:
    hits: list[str] = []
    hits.extend(match.group(0) for match in HEX_COLOR.finditer(css))
    hits.extend(match.group(0) for match in RGB_FUNCS.finditer(css))
    return hits


def _descriptor_title_has_cyrillic(source: str, state: str) -> bool:
    pattern = rf"{state}:\s*\{{[^}}]*?title:\s*['\"]([^'\"]+)['\"]"
    match = re.search(pattern, source, re.DOTALL)
    return bool(match and CYRILLIC.search(match.group(1)))


HUB_WIFI_SHARED_MODULES = (
    "features/live-connection-params.js",
    "features/wifi-qr.js",
    "features/wifi-ap-model.js",
    "features/wifi-screen-parts.js",
    "features/staff-wifi-model.js",
    "features/guest-wifi-model.js",
)


def test_hub_sw_includes_wifi_shared_modules() -> None:
    """Регрессия: SW precache включает общие Wi‑Fi модули и CACHE_VERSION >= 8."""
    source = _read(REPO_ROOT / "router_control_host" / "web" / "hub" / "sw.js")
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None
    assert int(version_match.group(1)) >= 8
    for rel in HUB_WIFI_SHARED_MODULES:
        assert rel.replace("/", ".") in source or rel in source
        assert f"features/{rel.split('/', 1)[-1]}" in source or rel in source


def test_hub_wifi_shared_modules_exist() -> None:
    """Регрессия: общие Wi‑Fi модули присутствуют на диске."""
    hub = REPO_ROOT / "router_control_host" / "web" / "hub"
    for rel in HUB_WIFI_SHARED_MODULES:
        path = hub / rel
        assert path.is_file(), f"missing hub module: {rel}"


def test_hub_state_matrix_complete() -> None:
    """Регрессия: удаление ключа HubState или STATE_DESCRIPTORS ломает матрицу из 14 состояний."""
    source = _read(STATES_JS)
    hub_keys = _extract_top_level_keys(source, "export const HubState = Object.freeze({")
    descriptor_keys = _extract_top_level_keys(
        source, "export const STATE_DESCRIPTORS = Object.freeze({"
    )
    assert hub_keys == EXPECTED_HUB_STATES
    assert descriptor_keys == EXPECTED_HUB_STATES


def test_hub_js_no_browser_storage() -> None:
    """Регрессия: использование localStorage/sessionStorage/indexedDB/cookie на клиенте."""
    violations: list[str] = []
    for path in _iter_hub_files(".js"):
        text = _read(path)
        for needle in FORBIDDEN_STORAGE:
            if needle in text:
                violations.append(f"{path.relative_to(REPO_ROOT)}: {needle}")
    assert violations == []


def test_hub_js_no_inner_html() -> None:
    """Регрессия: innerHTML открывает XSS при рендере данных API."""
    violations = [
        str(path.relative_to(REPO_ROOT))
        for path in _iter_hub_files(".js")
        if "innerHTML" in _read(path)
    ]
    assert violations == []


def _find_inner_html_violations(paths: list[Path]) -> list[str]:
    return [str(path) for path in paths if "innerHTML" in path.read_text(encoding="utf-8")]


def test_detector_inner_html_catches_violation(tmp_path: Path) -> None:
    """Самопроверка: детектор innerHTML не всегда зелёный."""
    bad = tmp_path / "bad.js"
    bad.write_text("root.innerHTML = payload;", encoding="utf-8")
    good = tmp_path / "good.js"
    good.write_text("root.textContent = payload;", encoding="utf-8")
    assert _find_inner_html_violations([bad]) == [str(bad)]
    assert _find_inner_html_violations([good]) == []


def _find_external_resource_violations(text: str, *, rel_path: Path | None = None) -> list[str]:
    violations: list[str] = []
    scan_text = text.replace(SVG_NAMESPACE_URI, "")
    for scheme in FORBIDDEN_EXTERNAL_SCHEME:
        count = scan_text.count(scheme)
        if count == 0:
            continue
        if rel_path is not None and rel_path == DOMAIN_MODEL_JS:
            allowed = DOMAIN_MODEL_ALLOWED_SCHEME_COUNTS.get(scheme, 0)
            if count <= allowed:
                continue
            violations.append(f"{scheme} x{count} (allowed {allowed})")
            continue
        violations.append(scheme)
    for match in FORBIDDEN_EXTERNAL_SCHEME_CI.finditer(scan_text):
        token = match.group(0)
        if token not in FORBIDDEN_EXTERNAL_SCHEME:
            violations.append(token)
    for match in FORBIDDEN_PROTOCOL_RELATIVE.finditer(text):
        if rel_path == ICON_JS and "//www.w3.org/2000/svg" in text:
            continue
        violations.append(match.group(0))
    for needle in FORBIDDEN_EXTERNAL_OTHER:
        if needle in text:
            violations.append(needle)
    return violations


def _scan_hub_external_resource_violations() -> list[str]:
    violations: list[str] = []
    for path in _iter_hub_files(".js", ".css", ".html"):
        text = _read(path)
        rel = path.relative_to(REPO_ROOT)
        for hit in _find_external_resource_violations(text, rel_path=path):
            violations.append(f"{rel}: {hit}")
    return violations


def test_hub_no_external_resources() -> None:
    """Регрессия: внешние URL или CDN в статике hub (offline-first).

    Литералы ``'https://'`` и ``'http://'`` допустимы только в ``domain-model.js``
    (сборка URL из ввода оператора) и только в точном количестве, заданном allowlist.
    """
    assert _scan_hub_external_resource_violations() == []


def test_hub_no_external_resources_guard_self_test(tmp_path: Path) -> None:
    """Самопроверка: guard ловит внешние URL и пропускает голую схему в domain-model."""
    bad = tmp_path / "bad.js"
    bad.write_text('const u = "https://cdn.example.com/x.js";', encoding="utf-8")
    good = tmp_path / "good.js"
    good.write_text("const s = 'https://' + host;", encoding="utf-8")
    assert _find_external_resource_violations(bad.read_text(encoding="utf-8")) != []
    assert (
        _find_external_resource_violations(
            good.read_text(encoding="utf-8"),
            rel_path=DOMAIN_MODEL_JS,
        )
        == []
    )


def test_hub_no_external_resources_guard_uppercase_scheme(tmp_path: Path) -> None:
    """Самопроверка: верхний регистр схемы не обходит guard."""
    bad = tmp_path / "bad.js"
    bad.write_text('const u = "HTTPS://evil.com";', encoding="utf-8")
    assert _find_external_resource_violations(bad.read_text(encoding="utf-8")) != []


def test_hub_no_external_resources_guard_protocol_relative(tmp_path: Path) -> None:
    """Самопроверка: protocol-relative ``//evil.com`` ловится guard."""
    bad = tmp_path / "bad.js"
    bad.write_text('const u = "//evil.com/x.js";', encoding="utf-8")
    assert _find_external_resource_violations(bad.read_text(encoding="utf-8")) != []


def test_hub_no_external_resources_guard_domain_model_count() -> None:
    """Самопроверка: превышение allowlist схем в domain-model.js ловится."""
    over_limit = (
        "const HTTPS_SCHEME = 'https://';\n"
        "const HTTP_SCHEME = 'http://';\n"
        "const X = 'https://';\n"
    )
    hits = _find_external_resource_violations(
        over_limit,
        rel_path=DOMAIN_MODEL_JS,
    )
    assert any("https://" in hit for hit in hits)
    within_limit = (
        "const HTTPS_SCHEME = 'https://';\n"
        "const HTTP_SCHEME = 'http://';\n"
    )
    assert (
        _find_external_resource_violations(
            within_limit,
            rel_path=DOMAIN_MODEL_JS,
        )
        == []
    )


def test_domain_save_if_match_uses_preset_etag_not_revision() -> None:
    """Регрессия B-1: POST /revisions получает ETag пресета, а не ревизии."""
    domain_js = _read(HUB / "screens" / "domain.js")
    assert "typeof metaPayload.etag === 'string'" in domain_js
    assert "applyPresetRevisionData(revision" in domain_js
    assert (
        "applyPresetRevisionData(revision, typeof etag === 'string' ? etag : null)"
        not in domain_js
    )
    model_js = _read(DOMAIN_MODEL_JS)
    assert "headers['If-Match'] = etag.trim()" in model_js
    assert "presetEtag" in domain_js


def test_hub_style_files_use_design_tokens_only() -> None:
    """Регрессия: hex/rgb/hsl литералы вне tokens.css — обход единого источника цвета."""
    violations: list[str] = []
    for path in STYLE_TOKEN_FILES:
        if not path.is_file():
            continue
        literals = _find_raw_color_literals(_read(path))
        if literals:
            rel = path.relative_to(REPO_ROOT)
            violations.append(f"{rel}: {', '.join(sorted(set(literals)))}")
    assert violations == []


def test_hub_touch_min_token_and_usage() -> None:
    """Регрессия: тач-таргеты меньше 44px или без ссылки на --hub-touch-min."""
    tokens = _read(TOKENS_CSS)
    match = re.search(r"--hub-touch-min:\s*([0-9.]+)px", tokens)
    assert match is not None, "tokens.css должен определять --hub-touch-min"
    assert float(match.group(1)) >= 44
    assert "--hub-touch-min" in _read(BASE_CSS)


def test_hub_safe_area_insets() -> None:
    """Регрессия: iPad notch/home-indicator без env(safe-area-inset-*)."""
    combined = _read(TOKENS_CSS) + _read(BASE_CSS)
    assert "env(safe-area-inset-" in combined


def test_hub_hover_inside_media_query() -> None:
    """Регрессия: :hover вне @media (hover: hover) ломает тач-only UX."""
    violations: list[str] = []
    for path in _iter_hub_files(".css"):
        for line in _find_hover_violations(_read(path)):
            violations.append(f"{path.relative_to(REPO_ROOT)}:{line}")
    assert violations == []


def test_hub_prefers_reduced_motion() -> None:
    """Регрессия: отсутствие prefers-reduced-motion игнорирует accessibility."""
    css_files = _iter_hub_files(".css")
    assert css_files, "ожидались CSS-файлы hub"
    assert any(
        "@media (prefers-reduced-motion: reduce)" in _read(path) for path in css_files
    )


def test_hub_state_descriptors_russian_titles() -> None:
    """Регрессия: английские или пустые заголовки состояний в UI."""
    source = _read(STATES_JS)
    missing = [
        state
        for state in sorted(EXPECTED_HUB_STATES)
        if not _descriptor_title_has_cyrillic(source, state)
    ]
    assert missing == []


def test_hub_errors_module_exports() -> None:
    """Регрессия: no-echo слой теряет публичный API ошибок."""
    source = _read(ERRORS_JS)
    assert "export class HubApiError" in source
    assert "export const ERROR_KIND" in source
    assert "export const ERROR_MESSAGES" in source
    assert "export function describeError" in source
    assert "export function toTechnicalText" in source
    assert "ERROR_MESSAGES = Object.freeze({" in source


def test_hub_api_no_console_log() -> None:
    """Регрессия: console.log в api.js — утечка технических деталей в консоль."""
    assert "console.log" not in _read(API_JS)


def test_hub_api_merge_signals_abort_listener_cleanup() -> None:
    """Регрессия API-Q-W3-01 / TESTS-W4-01: abort-listeners не утекают после settle."""
    source = _read(API_JS)
    merge_body = _extract_function_body(source, "function mergeSignals") or ""
    exec_tail = source[source.find("async function executeRequest") :]

    has_any_branch = re.search(
        r"typeof\s+AbortSignal\.any\s*===\s*['\"]function['\"]",
        merge_body,
    )
    if has_any_branch:
        assert re.search(
            r"AbortSignal\.any\s*\(\s*\[\s*userSignal\s*,\s*timeoutSignal\s*\]\s*\)",
            merge_body,
        ), "AbortSignal.any fast-path must merge userSignal and timeoutSignal"

    fallback_cleanup = (
        "removeEventListener" in merge_body
        and re.search(r"\bcleanup\s*=\s*\(\)\s*=>", merge_body)
        and re.search(r"return\s*\{\s*signal:\s*merged\.signal\s*,\s*cleanup\s*\}", merge_body)
    )
    exec_cleanup = re.search(
        r"finally\s*\{[^}]*releaseMergedSignal\s*\(",
        exec_tail,
        re.DOTALL,
    )
    assert exec_cleanup, "executeRequest finally must invoke releaseMergedSignal()"
    assert fallback_cleanup, (
        "mergeSignals fallback must define cleanup with removeEventListener "
        "(comment-only AbortSignal.any must not satisfy this contract)"
    )


def test_hub_api_get_only_retries() -> None:
    """Регрессия: повтор POST может продублировать мутацию на сервере.

    Гарантирует, что maxAttempts зависит от метода GET (retry>0 только для GET),
    а apiPost явно передаёт retry: 0.
    """
    source = _read(API_JS)
    assert re.search(
        r"maxAttempts\s*=\s*normalizedMethod\s*===\s*['\"]GET['\"]\s*\?",
        source,
    ), "apiRequest должен вычислять maxAttempts только для GET"
    assert re.search(
        r"method:\s*['\"]POST['\"][^)]*retry:\s*0",
        source,
        re.DOTALL,
    ), "apiPost должен отключать retry для POST"


def _check_js_as_module(node: str, source_path: Path) -> subprocess.CompletedProcess[str]:
    """Копирует hub .js во временный .mjs и запускает node --check как ES-модуль."""
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / f"{source_path.stem}.mjs"
        shutil.copy2(source_path, dest)
        return subprocess.run(
            [node, "--check", str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )


def test_hub_js_node_syntax() -> None:
    """Регрессия: синтаксическая ошибка в hub .js ломает загрузку ES-модулей в браузере.

    Файлы проверяются как модули (копия с расширением .mjs): node --check по исходному .js
    парсит скрипт, а не модуль, и пропускает ошибки вроде незакрытой скобки
    registerModal(openModal(...)).
    """
    node = _require_node()
    js_files = _iter_hub_files(".js")
    assert js_files, "ожидались JS-файлы hub"
    failures: list[str] = []
    for path in js_files:
        result = _check_js_as_module(node, path)
        if result.returncode != 0:
            rel = path.relative_to(REPO_ROOT)
            failures.append(f"{rel}: {result.stderr or result.stdout}")
    assert failures == []


def test_detector_js_module_syntax_catches_violation() -> None:
    """Самопроверка: проверка hub .js как ES-модуля (.mjs) должна падать на незакрытой скобке.

    Регрессия: старый test_hub_js_node_syntax с node --check по .js давал ложную уверенность —
    LOCAL HUB мог не грузиться, а тест оставался зелёным.
    """
    node = _require_node()
    source = _read(ERRORS_JS)
    broken = (
        source.rstrip()
        + "\n\nfunction __syntax_probe__() {\n"
        + "  registerModal(openModal({ title: 'probe' });\n"
        + "}\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp) / "broken.mjs"
        dest.write_text(broken, encoding="utf-8")
        result = subprocess.run(
            [node, "--check", str(dest)],
            capture_output=True,
            text=True,
            check=False,
        )
    assert result.returncode != 0, (
        "детектор должен падать на незакрытой скобке вызова openModal/registerModal; "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_detector_hover_catches_violation() -> None:
    """Самопроверка: :hover вне media блока должен детектироваться."""
    bad_css = ".btn:hover { opacity: 1; }"
    assert _find_hover_violations(bad_css) == [1]
    good_css = "@media (hover: hover) { .btn:hover { opacity: 1; } }"
    assert _find_hover_violations(good_css) == []


def _extract_function_body(source: str, signature: str) -> str | None:
    """Извлекает тело function по сигнатуре (например ``function normalizeRoute(routeId)``)."""
    start = source.find(signature)
    if start == -1:
        return None
    brace = source.find("{", start)
    if brace == -1:
        return None
    depth = 0
    i = brace
    while i < len(source):
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : i]
        i += 1
    return None


def test_hub_router_unknown_hash_falls_back_to_overview() -> None:
    source = _read(ROUTER_JS)
    assert "const DEFAULT_ROUTE = 'overview'" in source
    assert "function normalizeRoute" in source

    body = _extract_function_body(source, "function normalizeRoute(routeId)")
    assert body is not None, "normalizeRoute function body must be parseable"

    falsy_guard = re.search(
        r"if\s*\(\s*!routes\[routeId\]\s*\)\s*\{?\s*return\s+DEFAULT_ROUTE",
        body,
    )
    truthy_then_default = (
        re.search(
            r"if\s*\(\s*routes\[routeId\]\s*\)\s*\{[^}]*return\s+routeId",
            body,
        )
        is not None
        and re.search(r"return\s+DEFAULT_ROUTE\s*;", body) is not None
    )
    assert falsy_guard or truthy_then_default, (
        "normalizeRoute must return DEFAULT_ROUTE only when routes[routeId] is missing"
    )

    inverted = re.search(
        r"if\s*\(\s*routes\[routeId\]\s*\)\s*\{[^}]*return\s+DEFAULT_ROUTE",
        body,
    )
    assert inverted is None, (
        "inverted normalizeRoute must not return DEFAULT_ROUTE for known routes"
    )


def test_hub_stub_helper_used_by_screens() -> None:
    assert STUB_JS.is_file(), "screens/stub.js must exist"
    stub_source = _read(STUB_JS)
    assert "export function renderStubScreen" in stub_source
    assert "STUB_DESCRIPTION" in stub_source
    violations: list[str] = []
    for name in STUB_SCREEN_FILES:
        path = HUB / "screens" / name
        source = _read(path)
        if "renderStubScreen" not in source:
            violations.append(f"{name}: missing renderStubScreen import")
        if DUPLICATE_STUB_PATTERN.search(source):
            violations.append(f"{name}: duplicate features join in description")
        if "features.join" in source:
            violations.append(f"{name}: inline features.join description")
    assert violations == []


def test_hub_create_state_panel_title_tag_contract() -> None:
    source = _read(STATES_JS)
    assert "titleTag" in source
    assert re.search(r"titleTag\s*=\s*['\"]h2['\"]", source)
    assert "titleTag: 'h3'" in source or 'titleTag: "h3"' in source


def test_hub_errors_user_messages_avoid_jargon() -> None:
    source = _read(ERRORS_JS)
    user_fields = re.findall(
        r"userMessage:\s*['\"]([^'\"]+)['\"]|userAction:\s*['\"]([^'\"]+)['\"]",
        source,
    )
    violations: list[str] = []
    for msg, action in user_fields:
        text = msg or action
        for jargon in FORBIDDEN_USER_JARGON:
            if jargon in text:
                violations.append(f"{jargon!r} in user-facing text: {text!r}")
    assert violations == []


def test_hub_connection_banner_host_wording() -> None:
    states = _read(STATES_JS)
    assert "сервером управления" in states or "хостом Router Control" in states


def test_detector_state_matrix_catches_missing_key() -> None:
    """Самопроверка: удаление ключа из HubState должно ломать матрицу."""
    source = _read(STATES_JS)
    hub_keys = _extract_top_level_keys(source, "export const HubState = Object.freeze({")
    broken = hub_keys - {"LOADING"}
    assert broken != EXPECTED_HUB_STATES


SSH_HOST_KEY_ERROR_CODES = (
    "ssh_host_key.learn_failed",
    "ssh_host_key.invalid_pin",
    "ssh_host_key.pin_conflict",
)

# Коды ошибок маршрутов, которые вызывает экран «Подключение»
# (router_discovery, connection_health, ssh_host_key, wizard_draft).
CONNECTION_ROUTE_ERROR_CODES = (
    "router_discovery.failed",
    "connection_health.failed",
    "endpoint.host_not_private",
    "router.not_found",
    "ssh_host_key.learn_failed",
    "ssh_host_key.invalid_pin",
    "ssh_host_key.pin_conflict",
    "request.validation_failed",
    "idempotency.conflict",
    "internal.error",
)

# Коды Wi-Fi-операций — отдельный перечень (экран подключения их не вызывает).
WIFI_OPERATION_ERROR_CODES = (
    "wifi.live_connection_incomplete",
    "wifi.live_connection_required",
    "wifi.live_platform_unsupported",
    "wifi.gate_a_required",
    "wifi.guest_isolation_unsupported",
    "wifi.captive_portal_unsupported",
    "feature.degraded",
    "wifi.site_survey_radio_forbidden",
    "wifi.site_survey_failed",
    "wifi.station_preview_failed",
    "wifi.ssh_host_key_mismatch",
    "wifi.credential_not_found",
    "wifi.credential_unusable",
    "wifi.credential_ref_required",
    "wifi.live_transport_failed",
)


def _extract_error_message_keys(source: str) -> set[str]:
    block_start = source.index("ERROR_MESSAGES = Object.freeze({")
    block_end = source.index("/** Префиксные правила", block_start)
    return set(re.findall(r"'([^']+)':\s*\{", source[block_start:block_end]))


def _error_entry_user_texts(source: str, code: str) -> tuple[str, str]:
    pattern = (
        rf"'{re.escape(code)}':\s*\{{\s*"
        rf"userMessage:\s*'([^']+)',\s*"
        rf"userAction:\s*'([^']+)'"
    )
    match = re.search(pattern, source)
    assert match, f"missing ERROR_MESSAGES entry for {code!r}"
    return match.group(1), match.group(2)


def _assert_ssh_host_key_no_pin_in_user_text(source: str) -> None:
    violations: list[str] = []
    for code in SSH_HOST_KEY_ERROR_CODES:
        user_message, user_action = _error_entry_user_texts(source, code)
        combined = f"{user_message} {user_action}"
        if "PIN" in combined:
            violations.append(f"{code}: contains PIN")
        if "отпечаток" not in combined:
            violations.append(f"{code}: missing отпечаток")
    assert violations == [], violations


def test_hub_errors_host_key_copy_is_about_fingerprint_not_pin() -> None:
    """Регрессия: ssh_host_key.* не должен говорить про PIN — только про отпечаток устройства."""
    _assert_ssh_host_key_no_pin_in_user_text(_read(ERRORS_JS))


def test_hub_errors_cover_connection_route_codes() -> None:
    """Регрессия: ERROR_MESSAGES покрывает коды маршрутов экрана «Подключение»."""
    source = _read(ERRORS_JS)
    keys = _extract_error_message_keys(source)
    missing = [code for code in CONNECTION_ROUTE_ERROR_CODES if code not in keys]
    assert missing == []


def test_hub_errors_cover_wifi_operation_codes() -> None:
    """Регрессия: ERROR_MESSAGES покрывает коды Wi-Fi-операций (отдельно от подключения)."""
    source = _read(ERRORS_JS)
    keys = _extract_error_message_keys(source)
    missing = [code for code in WIFI_OPERATION_ERROR_CODES if code not in keys]
    assert missing == []


def test_detector_host_key_pin_catches_violation(tmp_path: Path) -> None:
    """Самопроверка: PIN в пользовательском тексте ssh_host_key.* ловится на копии errors.js."""
    source = _read(ERRORS_JS)
    _assert_ssh_host_key_no_pin_in_user_text(source)

    broken_path = tmp_path / "errors-broken.js"
    broken_path.write_text(
        source.replace(
            "userMessage: 'Отпечаток устройства не совпал или подтверждение недоступно.'",
            "userMessage: 'Неверный PIN для ключа хоста.'",
            1,
        ),
        encoding="utf-8",
    )
    broken_source = broken_path.read_text(encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_ssh_host_key_no_pin_in_user_text(broken_source)


HUB_VAR_DECL = re.compile(r"(--hub-[a-zA-Z0-9-]+)\s*:")
HUB_VAR_USE = re.compile(r"var\((--hub-[a-zA-Z0-9-]+)\)")


def _extract_hub_token_declarations(tokens_css: str) -> set[str]:
    return set(HUB_VAR_DECL.findall(tokens_css))


def _find_undefined_hub_variables(css_text: str, global_tokens: set[str]) -> set[str]:
    local_tokens = set(HUB_VAR_DECL.findall(css_text))
    allowed = global_tokens | local_tokens
    used = set(HUB_VAR_USE.findall(css_text))
    return used - allowed


def test_hub_style_files_use_declared_css_variables() -> None:
    """Регрессия: var(--hub-…) только на токены tokens.css или локальные переменные файла."""
    global_tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    violations: list[str] = []
    for path in sorted((HUB / "styles").glob("*.css")):
        if path.name == "tokens.css":
            continue
        undefined = _find_undefined_hub_variables(_read(path), global_tokens)
        for name in sorted(undefined):
            violations.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    assert violations == []


def test_detector_undefined_css_variable_catches_violation() -> None:
    """Самопроверка: неопределённая --hub-* переменная должна детектироваться."""
    tokens = _extract_hub_token_declarations(_read(TOKENS_CSS))
    bad_css = ".x { border-radius: var(--hub-radius-md); }"
    assert "--hub-radius-md" in _find_undefined_hub_variables(bad_css, tokens)
    good_css = ".x { border-radius: var(--hub-radius-card); }"
    assert _find_undefined_hub_variables(good_css, tokens) == set()


def _css_rule_properties(css: str, selector: str) -> dict[str, str]:
    """Свойства первого CSS-правила для селектора (без @media)."""
    pattern = re.compile(rf"{re.escape(selector)}\s*\{{([^}}]*)\}}", re.MULTILINE)
    match = pattern.search(css)
    if match is None:
        return {}
    props: dict[str, str] = {}
    for decl in match.group(1).split(";"):
        if ":" not in decl:
            continue
        key, value = decl.split(":", 1)
        props[key.strip()] = value.strip()
    return props


def _assert_shell_content_positioned(css: str) -> None:
    props = _css_rule_properties(css, ".hub-shell__content")
    assert props.get("position") == "relative", props


def _assert_inline_state_shrink_wraps(css: str) -> None:
    props = _css_rule_properties(css, ".hub-state-inline")
    assert props.get("width") == "fit-content", props
    assert props.get("max-width") == "100%", props


def test_hub_shell_content_is_positioned_for_visually_hidden() -> None:
    """В-1: прокручиваемый контейнер оболочки создаёт containing block для sr-only."""
    css = _read(SHELL_CSS)
    _assert_shell_content_positioned(css)
    broken = css.replace(
        ".hub-shell__content {\n  position: relative;",
        ".hub-shell__content {",
        1,
    )
    with pytest.raises(AssertionError):
        _assert_shell_content_positioned(broken)


def test_hub_inline_state_width_matches_content() -> None:
    """В-2: строки состояний по умолчанию сжимаются по содержимому."""
    css = _read(STATES_CSS)
    _assert_inline_state_shrink_wraps(css)
    broken = css.replace("width: fit-content;", "width: auto;", 1)
    with pytest.raises(AssertionError):
        _assert_inline_state_shrink_wraps(broken)


def test_hub_state_panel_has_no_duplicate_sr_title() -> None:
    """Д-7: панель состояния не дублирует заголовок скрытым текстом."""
    source = _read(STATES_JS)
    panel_body = _extract_function_body(source, "export function createStatePanel(")
    assert panel_body is not None
    assert "hub-visually-hidden" not in panel_body


def test_hub_modal_marks_background_inert() -> None:
    """Д-5: модальное окно помечает фон aria-hidden на время показа."""
    source = _read(MODAL_JS)
    assert 'setAttribute("aria-hidden", "true")' in source
    assert 'removeAttribute("aria-hidden")' in source
    assert "getModalBackgroundRoot" in source or '.hub-shell' in source


def test_hub_link_color_token_defined_and_used() -> None:
    """Д-4: ссылки используют контрастный токен --hub-color-link."""
    tokens = _read(TOKENS_CSS)
    assert "--hub-color-link:" in tokens
    screens = _read(SCREENS_CSS)
    assert "var(--hub-color-link)" in screens
    manual_props = _css_rule_properties(screens, ".hub-connection__manual-link")
    assert manual_props.get("min-height") == "var(--hub-touch-min)", manual_props
    inline_props = _css_rule_properties(screens, ".hub-wifi__inline-link")
    assert inline_props.get("min-height") == "var(--hub-touch-min)", inline_props


def _strip_css_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _parse_css_declarations(block: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for decl in block.split(";"):
        if ":" not in decl:
            continue
        key, value = decl.split(":", 1)
        props[key.strip()] = value.strip()
    return props


def _iter_css_rules(css: str) -> list[tuple[str, dict[str, str]]]:
    """Извлекает (selector, props) из CSS, включая правила внутри @media."""
    css = _strip_css_comments(css)
    rules: list[tuple[str, dict[str, str]]] = []

    def walk(text: str, media_prefix: str = "") -> None:
        i = 0
        while i < len(text):
            while i < len(text) and text[i].isspace():
                i += 1
            if i >= len(text):
                break
            if text.startswith("@media", i):
                brace = text.find("{", i)
                if brace == -1:
                    break
                depth = 1
                j = brace + 1
                while j < len(text) and depth > 0:
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                    j += 1
                media_query = text[i:brace].strip()
                inner = text[brace + 1 : j - 1]
                walk(inner, media_prefix=f"{media_prefix}{media_query} ")
                i = j
                continue
            if text[i] == "@":
                brace = text.find("{", i)
                if brace == -1:
                    break
                depth = 1
                j = brace + 1
                while j < len(text) and depth > 0:
                    if text[j] == "{":
                        depth += 1
                    elif text[j] == "}":
                        depth -= 1
                    j += 1
                i = j
                continue
            brace = text.find("{", i)
            if brace == -1:
                break
            selector = text[i:brace].strip()
            depth = 1
            j = brace + 1
            while j < len(text) and depth > 0:
                if text[j] == "{":
                    depth += 1
                elif text[j] == "}":
                    depth -= 1
                j += 1
            block = text[brace + 1 : j - 1]
            if "{" not in selector and selector:
                full_selector = f"{media_prefix}{selector}".strip()
                rules.append((full_selector, _parse_css_declarations(block)))
            i = j

    walk(css)
    return rules


def _load_all_hub_style_rules() -> list[tuple[str, Path, dict[str, str]]]:
    loaded: list[tuple[str, Path, dict[str, str]]] = []
    for path in sorted(HUB_STYLES_DIR.glob("*.css")):
        for selector, props in _iter_css_rules(_read(path)):
            loaded.append((selector, path, props))
    return loaded


def _expand_selector_parts(selector: str) -> list[str]:
    parts: list[str] = []
    media_prefix = ""
    for raw in selector.split(","):
        part = raw.strip()
        if not part:
            continue
        media_match = re.match(r"(@media\s*\([^)]+\))\s*(.*)", part, re.IGNORECASE | re.DOTALL)
        if media_match:
            media_prefix = media_match.group(1).strip()
            remainder = media_match.group(2).strip()
            if remainder:
                parts.append(f"{media_prefix} {remainder}")
            continue
        if media_prefix:
            parts.append(f"{media_prefix} {part}")
        else:
            parts.append(part)
    return parts


def _selector_part_targets_registry_class(part: str, class_name: str) -> bool:
    bare = class_name.lstrip(".")
    class_pat = re.escape(class_name)
    bare_pat = re.escape(bare)
    suffix = r"(?:[:\s,\[{]|$)"
    if re.search(r"(?:^|[\s>+~])" + class_pat + suffix, part):
        return True
    if re.search(r"(?:^|[\s>+~])\." + bare_pat + r"(?:--|$|[:\s,\[{])", part):
        if not any(allow in part for allow in NARROW_COMPONENT_STRETCH_ALLOWLIST):
            return True
    return False


def _selector_targets_registry_class(selector: str, class_name: str) -> bool:
    for part in _expand_selector_parts(selector):
        if part in NARROW_COMPONENT_STRETCH_ALLOWLIST:
            continue
        if _selector_part_targets_registry_class(part, class_name):
            return True
    return False


def _is_allowlisted_stretch_selector(selector: str) -> bool:
    for part in selector.split(","):
        if part.strip() in NARROW_COMPONENT_STRETCH_ALLOWLIST:
            return True
    return False


def _assert_pill_rules_declare_width(rules: list[tuple[str, Path, dict[str, str]]]) -> None:
    violations: list[str] = []
    for selector, path, props in rules:
        if props.get("border-radius") != PILL_BORDER_RADIUS:
            continue
        if props.get("width"):
            continue
        rel = path.relative_to(REPO_ROOT)
        violations.append(
            f"{rel} [{selector}]: новый pill-элемент добавлен без ограничения ширины — "
            "он растянется в flex-колонке"
        )
    assert violations == []


def _assert_narrow_components_resist_stretch(
    rules: list[tuple[str, Path, dict[str, str]]],
    components_css: str,
) -> None:
    badge_system_props: dict[str, str] = {}
    btn_system_props: dict[str, str] = {}
    for selector, props in _iter_css_rules(components_css):
        if ".hub-badge" in selector and ".hub-shell__menu-bar" in selector:
            badge_system_props = props
        if selector.strip() == ".hub-btn":
            btn_system_props = props
    assert badge_system_props.get("align-self") in {"start", "flex-start"}, badge_system_props
    assert badge_system_props.get("justify-self") in {"start", "flex-start"}, badge_system_props
    assert btn_system_props.get("align-self") in {"start", "flex-start"}, btn_system_props
    assert btn_system_props.get("justify-self") in {"start", "flex-start"}, btn_system_props

    align_self_hits: dict[str, int] = {cls: 0 for cls in NARROW_COMPONENT_REGISTRY}
    stretch_violations: list[str] = []

    for selector, path, props in rules:
        rel = path.relative_to(REPO_ROOT)
        for part in _expand_selector_parts(selector):
            if part in NARROW_COMPONENT_STRETCH_ALLOWLIST:
                continue
            for class_name in NARROW_COMPONENT_REGISTRY:
                if not _selector_part_targets_registry_class(part, class_name):
                    continue
                if props.get("align-self") in {"start", "flex-start"}:
                    align_self_hits[class_name] += 1
                if props.get("width") == "100%":
                    stretch_violations.append(
                        f"{rel} [{part}]: width: 100% — {STRETCH_VIOLATION_HINT}"
                    )
                if props.get("align-self") == "stretch":
                    stretch_violations.append(
                        f"{rel} [{part}]: align-self: stretch — {STRETCH_VIOLATION_HINT}"
                    )
                if props.get("justify-self") == "stretch":
                    stretch_violations.append(
                        f"{rel} [{part}]: justify-self: stretch — {STRETCH_VIOLATION_HINT}"
                    )

    missing_align = [
        cls
        for cls, count in align_self_hits.items()
        if count == 0 and cls != ".hub-state-inline"
    ]
    assert missing_align == [], f"missing align-self for {missing_align}"
    assert align_self_hits[".hub-state-inline"] > 0, "missing align-self for .hub-state-inline"
    assert stretch_violations == [], "\n".join(stretch_violations)


def test_hub_pill_elements_declare_width() -> None:
    """И-2: каждый pill (border-radius-pill) явно ограничивает ширину.

    Ручная проверка чувствительности: уберите ``width: fit-content`` у ``.hub-badge``
    в ``components.css`` — тест обязан упасть.
    """
    rules = _load_all_hub_style_rules()
    _assert_pill_rules_declare_width(rules)
    badge_block_before = (
        ".hub-badge {\n  display: inline-flex;\n  align-items: center;\n"
        "  gap: var(--hub-space-1);\n  width: fit-content;"
    )
    badge_block_after = (
        ".hub-badge {\n  display: inline-flex;\n  align-items: center;\n"
        "  gap: var(--hub-space-1);"
    )
    broken = _read(COMPONENTS_CSS).replace(badge_block_before, badge_block_after, 1)
    with pytest.raises(AssertionError, match="новый pill-элемент"):
        _assert_pill_rules_declare_width(
            [
                (selector, COMPONENTS_CSS, props)
                for selector, props in _iter_css_rules(broken)
            ]
            + [(s, p, pr) for s, p, pr in rules if p != COMPONENTS_CSS]
        )


def test_hub_narrow_components_resist_flex_stretch() -> None:
    """И-2: реестр узких компонентов защищён от растягивания в flex/grid."""
    rules = _load_all_hub_style_rules()
    components_css = _read(COMPONENTS_CSS)
    _assert_narrow_components_resist_stretch(rules, components_css)

    btn_block_before = (
        ".hub-btn {\n  position: relative;\n  display: inline-flex;\n  align-items: center;\n"
        "  justify-content: center;\n  gap: var(--hub-space-2);\n  align-self: start;\n"
        "  justify-self: start;\n  min-height: var(--hub-button-height);"
    )
    btn_block_after = (
        ".hub-btn {\n  position: relative;\n  display: inline-flex;\n  align-items: center;\n"
        "  justify-content: center;\n  gap: var(--hub-space-2);\n  align-self: start;\n"
        "  justify-self: start;\n  min-height: var(--hub-button-height);\n  width: 100%;"
    )
    broken_width = components_css.replace(btn_block_before, btn_block_after, 1)
    broken_width_rules = [
        (selector, COMPONENTS_CSS, props)
        for selector, props in _iter_css_rules(broken_width)
    ] + [(s, p, pr) for s, p, pr in rules if p != COMPONENTS_CSS]
    with pytest.raises(AssertionError, match="width: 100%"):
        _assert_narrow_components_resist_stretch(broken_width_rules, broken_width)

    broken_align = components_css.replace(
        "  align-self: start;\n  justify-self: start;\n  min-height: var(--hub-button-height);",
        "  justify-self: start;\n  min-height: var(--hub-button-height);",
        1,
    )
    broken_align_rules = [
        (selector, COMPONENTS_CSS, props)
        for selector, props in _iter_css_rules(broken_align)
    ] + [(s, p, pr) for s, p, pr in rules if p != COMPONENTS_CSS]
    with pytest.raises(AssertionError, match="missing align-self|align-self"):
        _assert_narrow_components_resist_stretch(broken_align_rules, broken_align)

    composite_violation = (
        ".hub-btn--block, .hub-guest-wifi__quick-actions .hub-btn",
        COMPONENTS_CSS,
        {"width": "100%"},
    )
    with pytest.raises(AssertionError, match="width: 100%"):
        _assert_narrow_components_resist_stretch(
            [composite_violation] + rules,
            components_css,
        )
