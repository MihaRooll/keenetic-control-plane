"""Статические проверки PWA-обвязки LOCAL HUB (manifest, SW, иконки)."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
HUB = REPO_ROOT / "router_control_host" / "web" / "hub"
ICONS = HUB / "icons"
MANIFEST = HUB / "manifest.webmanifest"
SW = HUB / "sw.js"
GENERATOR = REPO_ROOT / "scripts" / "generate-hub-icons.py"

HUB_SCOPE = "/settings/router-control/hub/"
NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get(NODE_SKIP_ENV) == "1":
            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")
        pytest.fail(
            "node is required for hub PWA tests; install Node.js or set "
            f"{NODE_SKIP_ENV}=1 to allow skip",
        )
    return node


def _load_generator_module():
    spec = importlib.util.spec_from_file_location("generate_hub_icons", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _manifest_data() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _png_dimensions(data: bytes) -> tuple[int, int]:
    assert data.startswith(PNG_SIGNATURE)
    offset = len(PNG_SIGNATURE)
    length = struct.unpack(">I", data[offset : offset + 4])[0]
    chunk_type = data[offset + 4 : offset + 8]
    assert chunk_type == b"IHDR"
    ihdr = data[offset + 8 : offset + 8 + length]
    width, height = struct.unpack(">II", ihdr[:8])
    return width, height


def test_manifest_json_fields() -> None:
    data = _manifest_data()
    assert data["id"] == HUB_SCOPE
    assert data["start_url"] == HUB_SCOPE
    assert data["scope"] == HUB_SCOPE
    assert data["display"] == "standalone"
    assert data["background_color"] == "#0B0F1A"
    assert data["theme_color"] == "#0B0F1A"

    icons = data["icons"]
    purposes = {(icon["sizes"], icon.get("purpose", "any")) for icon in icons}
    assert ("192x192", "any") in purposes
    assert ("512x512", "any") in purposes
    assert ("512x512", "maskable") in purposes


def test_manifest_icon_files_exist() -> None:
    data = _manifest_data()
    for icon in data["icons"]:
        src = icon["src"]
        assert src.startswith(HUB_SCOPE)
        rel = src.removeprefix(HUB_SCOPE)
        path = HUB / rel
        assert path.is_file(), f"missing manifest icon: {path}"


def test_png_signatures_and_sizes() -> None:
    expected = {
        "icon-192.png": 192,
        "icon-512.png": 512,
        "icon-maskable-512.png": 512,
        "apple-touch-icon-180.png": 180,
    }
    for name, size in expected.items():
        data = (ICONS / name).read_bytes()
        assert data.startswith(PNG_SIGNATURE), name
        width, height = _png_dimensions(data)
        assert (width, height) == (size, size), name


def test_sw_no_external_urls_or_importscripts() -> None:
    source = SW.read_text(encoding="utf-8")
    assert "importScripts" not in source
    assert "http://" not in source
    assert "https://" not in source


def test_sw_api_passthrough_not_cached() -> None:
    source = SW.read_text(encoding="utf-8")
    assert "/api/" in source
    api_branch = re.search(
        r"path\.startsWith\(['\"]/api/['\"]\).*?return\s+true;",
        source,
        re.DOTALL,
    )
    assert api_branch is not None, "expected explicit /api/ passthrough guard"
    assert "cache.put" not in api_branch.group(0)

    passthrough_handler = re.search(
        r"if\s*\(\s*shouldPassthrough\(request\)\s*\)\s*\{[^}]+\}",
        source,
        re.DOTALL,
    )
    assert passthrough_handler is not None
    block = passthrough_handler.group(0)
    assert "fetch(request)" in block
    assert "cache.put" not in block


def test_sw_cache_version_and_activate_cleanup() -> None:
    source = SW.read_text(encoding="utf-8")
    assert "CACHE_VERSION" in source
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None
    assert int(version_match.group(1)) >= 7
    assert re.search(r"name\.startsWith\(['\"]local-hub-['\"]\)", source)
    assert "caches.delete" in source
    assert "activate" in source


def test_icon_svg_valid_xml_no_script() -> None:
    text = (ICONS / "icon.svg").read_text(encoding="utf-8")
    assert "<script" not in text.lower()
    root = ET.fromstring(text)
    assert root.tag.endswith("svg")


def test_generate_hub_icons_deterministic() -> None:
    gen = _load_generator_module()
    expected = gen.generate_all_icons()

    for name, generated in expected.items():
        on_disk = (ICONS / name).read_bytes()
        assert on_disk == generated, f"{name} on disk differs from generator output"

    before = {name: hashlib.sha256((ICONS / name).read_bytes()).hexdigest() for name in expected}
    result = subprocess.run(
        [sys.executable, str(GENERATOR)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    after = {name: hashlib.sha256((ICONS / name).read_bytes()).hexdigest() for name in expected}
    assert before == after


def _shell_urls_from_sw(source: str) -> list[str]:
    match = re.search(r"const SHELL_URLS = \[([\s\S]*?)\];", source)
    assert match is not None
    prefix_match = re.search(r"const HUB_PREFIX = '([^']+)';", source)
    hub_prefix = prefix_match.group(1) if prefix_match else HUB_SCOPE
    raw_entries = re.findall(r"`([^`]+)`", match.group(1))
    return [entry.replace("${HUB_PREFIX}", hub_prefix) for entry in raw_entries]


def test_sw_shell_urls_include_wifi_shared_modules() -> None:
    source = SW.read_text(encoding="utf-8")
    urls = _shell_urls_from_sw(source)
    assert any("live-connection-params.js" in url for url in urls)
    assert any("wifi-qr.js" in url for url in urls)
    assert any("wifi-ap-model.js" in url for url in urls)
    assert any("wifi-screen-parts.js" in url for url in urls)
    assert any("staff-wifi-model.js" in url for url in urls)
    assert any("guest-wifi-model.js" in url for url in urls)


def test_sw_shell_urls_exist_on_disk() -> None:
    source = SW.read_text(encoding="utf-8")
    urls = _shell_urls_from_sw(source)
    assert urls, "SHELL_URLS must list precache paths"
    for url in urls:
        rel = url.removeprefix(HUB_SCOPE).lstrip("/")
        if not rel:
            rel = "index.html"
        path = HUB / Path(rel)
        assert path.is_file(), f"missing precache asset on disk: {path}"


def _extract_brace_block(source: str, open_brace: int) -> str | None:
    """Извлекает содержимое блока ``{ ... }`` начиная с индекса открывающей ``{``."""
    if open_brace < 0 or open_brace >= len(source) or source[open_brace] != "{":
        return None
    depth = 0
    i = open_brace
    while i < len(source):
        char = source[i]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : i]
        i += 1
    return None


def _extract_function_body(source: str, signature: str) -> str | None:
    """Извлекает тело function по сигнатуре (например ``async function precacheShell(cache)``)."""
    start = source.find(signature)
    if start == -1:
        return None
    brace = source.find("{", start)
    if brace == -1:
        return None
    return _extract_brace_block(source, brace)


def _js_call_sites(body: str, name: str) -> list[int]:
    """Индексы вызовов ``name(`` в теле, исключая объявления ``function name(``."""
    pattern = re.compile(rf"(?<![\w.]){re.escape(name)}\s*\(")
    sites: list[int] = []
    for match in pattern.finditer(body):
        start = match.start()
        prefix = body[max(0, start - 48) : start]
        if re.search(rf"\bfunction\s+{re.escape(name)}\s*$", prefix):
            continue
        sites.append(start)
    return sites


def _js_has_call_site(body: str, name: str) -> bool:
    return bool(_js_call_sites(body, name))


def _extract_registration_then_body(source: str) -> str | None:
    """Извлекает тело ``.then((registration) => { ... })`` у serviceWorker.register."""
    match = re.search(
        r"\.register\s*\([\s\S]*?\)\s*\.then\s*\(\s*\(\s*registration\s*\)\s*=>\s*\{",
        source,
    )
    if not match:
        return None
    return _extract_brace_block(source, match.end() - 1)


def test_sw_precache_requires_all_shell_urls() -> None:
    source = SW.read_text(encoding="utf-8")
    body = _extract_function_body(source, "async function precacheShell(cache)")
    assert body is not None, "precacheShell function body must be parseable"
    throw_in_cond = re.search(
        r"if\s*\(\s*succeeded\s*!==\s*SHELL_URLS\.length\s*\)\s*\{[^}]*throw\s+new\s+Error",
        body,
        re.DOTALL,
    )
    assert throw_in_cond is not None, (
        "precacheShell must throw new Error when succeeded !== SHELL_URLS.length"
    )


def test_sw_install_does_not_auto_skip_waiting() -> None:
    source = SW.read_text(encoding="utf-8")
    install_match = re.search(
        r"self\.addEventListener\(['\"]install['\"],\s*\(event\)\s*=>\s*\{([\s\S]*?)\n\}\);",
        source,
    )
    assert install_match is not None, "install listener must be present"
    install_body = install_match.group(1)
    assert "skipWaiting" not in install_body, "install must not call skipWaiting automatically"


def test_sw_message_handler_accepts_hub_skip_waiting() -> None:
    source = SW.read_text(encoding="utf-8")
    assert "HUB_SKIP_WAITING" in source
    assert "SKIP_WAITING" in source


def _strip_js_comments(source: str) -> str:
    result: list[str] = []
    i = 0
    n = len(source)
    while i < n:
        if source[i : i + 2] == "//":
            i += 2
            while i < n and source[i] != "\n":
                i += 1
        elif source[i : i + 2] == "/*":
            i += 2
            end = source.find("*/", i)
            if end == -1:
                break
            i = end + 2
        else:
            result.append(source[i])
            i += 1
    return "".join(result)


def _resolve_hub_import(from_path: Path, spec: str, hub: Path) -> Path | None:
    if not spec.startswith("."):
        return None
    base = (from_path.parent / spec).resolve()
    candidates = [base, base.with_suffix(".js")]
    if not str(base).endswith(".js"):
        candidates.append(Path(f"{base}.js"))
    hub_resolved = hub.resolve()
    for candidate in candidates:
        try:
            candidate.relative_to(hub_resolved)
        except ValueError:
            continue
        if candidate.is_file():
            return candidate
    return None


def _collect_reachable_hub_js(entry: Path, hub: Path) -> set[str]:
    visited: set[Path] = set()
    queue = [entry.resolve()]
    urls: set[str] = set()
    import_re = re.compile(r"""\bfrom\s+['"]([^'"]+)['"]""")
    hub_resolved = hub.resolve()

    while queue:
        path = queue.pop(0)
        if path in visited:
            continue
        visited.add(path)
        rel = path.relative_to(hub_resolved).as_posix()
        urls.add(f"{HUB_SCOPE}{rel}")
        stripped = _strip_js_comments(path.read_text(encoding="utf-8"))
        for match in import_re.finditer(stripped):
            resolved = _resolve_hub_import(path, match.group(1), hub)
            if resolved and resolved not in visited:
                queue.append(resolved)
    return urls


def _collect_index_stylesheets(hub: Path) -> set[str]:
    index = (hub / "index.html").read_text(encoding="utf-8")
    return set(
        re.findall(
            r"""<link\s+[^>]*rel\s*=\s*["']stylesheet["'][^>]*href\s*=\s*["']([^"']+)["']""",
            index,
            re.IGNORECASE,
        ),
    )


def test_sw_shell_urls_cover_all_reachable_assets() -> None:
    sw_source = SW.read_text(encoding="utf-8")
    shell_urls = set(_shell_urls_from_sw(sw_source))

    reachable_js = _collect_reachable_hub_js(HUB / "app.js", HUB)
    reachable_css = _collect_index_stylesheets(HUB)

    missing_js = sorted(url for url in reachable_js if url not in shell_urls)
    missing_css = sorted(url for url in reachable_css if url not in shell_urls)

    assert not missing_js, f"reachable JS not in SHELL_URLS: {missing_js}"
    assert not missing_css, f"index.html CSS not in SHELL_URLS: {missing_css}"


def test_app_js_service_worker_update_flow() -> None:
    app_js = (HUB / "app.js").read_text(encoding="utf-8")
    stripped = _strip_js_comments(app_js)

    assert "controllerchange" in app_js
    assert "HUB_SKIP_WAITING" in app_js
    assert "updateNoticeShown" in app_js
    assert "reloading" in app_js
    assert "Доступно обновление интерфейса" in app_js
    assert "handleWaitingWorker" in app_js

    assert re.search(r"if\s*\(\s*!?\s*reloading\s*\)", app_js), (
        "reload must be gated by reloading flag"
    )
    assert "location.reload" in app_js

    assert "registration.waiting.postMessage" not in stripped, (
        "must not auto-post on registration.waiting without toast gate"
    )
    assert not re.search(
        r"updatefound[\s\S]{0,800}?postMessage\s*\(\s*\{\s*type:\s*['\"]SKIP_WAITING",
        stripped,
    ), "must not auto-post SKIP_WAITING inside updatefound without operator gate"
    assert not re.search(
        r"updatefound[\s\S]{0,800}?postMessage\s*\(\s*\{\s*type:\s*['\"]HUB_SKIP_WAITING",
        stripped,
    ), "must not auto-post HUB_SKIP_WAITING inside updatefound without operator gate"

    reg_then_body = _extract_registration_then_body(stripped)
    assert reg_then_body is not None, (
        "serviceWorker.register(...).then((registration) => { ... }) must be present"
    )
    assert not _js_has_call_site(reg_then_body, "requestSkipWaiting"), (
        "registration.then / updatefound must not call requestSkipWaiting directly; "
        "only handleWaitingWorker may delegate skip-waiting"
    )
    assert _js_has_call_site(reg_then_body, "handleWaitingWorker"), (
        "registration.then must delegate waiting workers to handleWaitingWorker"
    )
    updatefound_match = re.search(
        r"addEventListener\s*\(\s*['\"]updatefound['\"]\s*,\s*\(\)\s*=>\s*\{",
        reg_then_body,
    )
    assert updatefound_match is not None, "updatefound listener must be present"
    updatefound_body = _extract_brace_block(reg_then_body, updatefound_match.end() - 1)
    assert updatefound_body is not None, "updatefound listener body must be parseable"
    assert not _js_has_call_site(updatefound_body, "requestSkipWaiting"), (
        "updatefound listener must not call requestSkipWaiting directly"
    )
    assert _js_has_call_site(updatefound_body, "handleWaitingWorker"), (
        "updatefound listener must call handleWaitingWorker for installed workers"
    )

    show_update_body = _extract_function_body(app_js, "function showUpdateNotice(worker)")
    assert show_update_body is not None, "showUpdateNotice must be present"
    assert "showToast" in show_update_body
    assert "Обновить" in show_update_body
    assert "updateNoticeShown" in show_update_body
    assert "requestSkipWaiting" in show_update_body
    assert show_update_body.index("showToast") < show_update_body.index(
        "requestSkipWaiting"
    ), "requestSkipWaiting must not run before toast in showUpdateNotice"
    assert re.search(
        r"reloading\s*=\s*true[\s\S]{0,120}?requestSkipWaiting\s*\(",
        show_update_body,
    ), "skip-waiting must run only after reloading=true in toast action"

    handle_body = _extract_function_body(app_js, "function handleWaitingWorker(worker)")
    assert handle_body is not None, "handleWaitingWorker must be present"
    controller_match = re.search(
        r"if\s*\(\s*navigator\.serviceWorker\.controller\s*\)\s*\{([^}]*)\}",
        handle_body,
    )
    assert controller_match is not None, "controller-exists branch must be present"
    controller_branch = controller_match.group(1)
    assert "showUpdateNotice" in controller_branch
    assert "requestSkipWaiting" not in controller_branch, (
        "controller-exists branch must not auto-post HUB_SKIP_WAITING"
    )
    assert "postMessage" not in controller_branch
    assert _js_has_call_site(handle_body, "requestSkipWaiting"), (
        "!controller first-install path must call requestSkipWaiting inside handleWaitingWorker"
    )
    controller_block_start = handle_body.find("if (navigator.serviceWorker.controller)")
    assert controller_block_start != -1
    controller_block = _extract_brace_block(
        handle_body,
        handle_body.find("{", controller_block_start),
    )
    assert controller_block is not None
    assert not _js_has_call_site(controller_block, "requestSkipWaiting"), (
        "requestSkipWaiting must not run inside controller-exists branch"
    )

    skip_wait_body = _extract_function_body(app_js, "function requestSkipWaiting(worker)")
    assert skip_wait_body is not None, "requestSkipWaiting helper must be present"
    assert re.search(
        r"postMessage\s*\(\s*\{\s*type:\s*['\"]HUB_SKIP_WAITING",
        skip_wait_body,
    ), "HUB_SKIP_WAITING postMessage must live in requestSkipWaiting helper"


def test_sw_js_node_syntax() -> None:
    node = _require_node()
    result = subprocess.run(
        [node, "--check", str(SW)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
