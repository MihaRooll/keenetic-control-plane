"""Hub module binding guards — runtime mount (Layer 1) + static cross-module (Layer 2).

Layer 2 honest limits (docstring contract):
- Detects only free identifiers that some *other* hub module exports.
- Binding scan is file-wide, not scope-aware: a ``const subscribeConnectivity = null`` in an
  unrelated function suppresses a missing import for the whole file.
- Computed member expressions (``globalThis['subscribeConnectivity']``) are not detected.
- A deleted import of a browser global (window, document, fetch, …) or of a dependency
  outside ``router_control_host/web/hub/**`` is **out of reach**.
- Unreachable function bodies still parse as usages once comments/strings are stripped;
  Layer 1 is required for paths that never execute during mount.
- Runtime errors swallowed inside ``.catch(() => {})`` (or similar) are invisible to Layer 1;
  Layer 2 is the net for code paths the mount never reaches.
"""

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
GUARD_MJS = REPO_ROOT / "tests" / "support" / "hub_module_guard.mjs"
STAFF_WIFI_SCREEN = HUB / "screens" / "staff-wifi.js"
GUEST_WIFI_SCREEN = HUB / "screens" / "guest-wifi.js"
SHOWCASE_SCREEN = HUB / "screens" / "showcase.js"
SCREEN_BARREL = "screens/index.js"
SCREEN_HELPERS = frozenset({"screens/stub.js"})
WIFI_SCREENS = ("staff-wifi.js", "guest-wifi.js")
API_IMPORT_RE = re.compile(
    r"^import\s+\{[^}]*subscribeConnectivity[^}]*\}\s+from\s+['\"]\.\./core/api\.js['\"];?\s*$",
    re.MULTILINE,
)

JS_KEYWORDS = frozenset(
    {
        "break",
        "case",
        "catch",
        "class",
        "const",
        "continue",
        "debugger",
        "default",
        "delete",
        "do",
        "else",
        "export",
        "extends",
        "false",
        "finally",
        "for",
        "function",
        "if",
        "import",
        "in",
        "instanceof",
        "let",
        "new",
        "null",
        "return",
        "super",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "undefined",
        "var",
        "void",
        "while",
        "with",
        "yield",
        "await",
        "async",
        "of",
        "static",
        "from",
        "as",
    },
)

SKIP_DIR_NAMES = {"_adv_mut_work"}
BLOCK_OPEN_KEYWORDS = frozenset({"else", "try", "catch", "finally", "do"})


def _require_node() -> str:
    node = shutil.which("node")
    if node is None:
        if os.environ.get("HUB_TESTS_ALLOW_SKIP_NODE") == "1":
            pytest.skip("node not available (HUB_TESTS_ALLOW_SKIP_NODE=1)")
        pytest.fail(
            "node is required for hub module binding tests; install Node.js or set "
            "HUB_TESTS_ALLOW_SKIP_NODE=1 to allow skip",
        )
    return node


def _collect_hub_js_files(hub_root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(hub_root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIR_NAMES]
        for name in filenames:
            if name.endswith(".js"):
                files.append(Path(dirpath) / name)
    return sorted(files)


def _expected_screen_modules(hub_root: Path) -> list[str]:
    screens_dir = hub_root / "screens"
    modules: list[str] = []
    for path in sorted(screens_dir.glob("*.js")):
        rel = _rel_module(path, hub_root)
        if rel == SCREEN_BARREL or rel in SCREEN_HELPERS:
            continue
        modules.append(rel)
    return modules


def _rel_module(path: Path, hub_root: Path) -> str:
    return path.relative_to(hub_root).as_posix()


def _scan_template_substitution(source: str, i: int, out: list[str]) -> int:
    """Copy ``${…}`` expression text into stripped output; return index after ``}``."""
    i += 2
    depth = 1
    while i < len(source) and depth:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if ch == "`":
            out.append(" ")
            i += 1
            i = _scan_template_literal(source, i, out)
            continue
        if ch == "$" and nxt == "{":
            out.append(" ")
            i = _scan_template_substitution(source, i, out)
            continue
        if ch == "{":
            depth += 1
            out.append(ch)
        elif ch == "}":
            depth -= 1
            if depth:
                out.append(ch)
        else:
            out.append(ch)
        i += 1
    return i


def _scan_template_literal(source: str, i: int, out: list[str]) -> int:
    """Skip literal template text but preserve ``${…}`` expressions."""
    while i < len(source):
        ch = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""
        if ch == "\\":
            i += 2
            continue
        if ch == "`":
            return i + 1
        if ch == "$" and nxt == "{":
            out.append(" ")
            i = _scan_template_substitution(source, i, out)
            continue
        i += 1
    return i


def _strip_js_for_usage_scan(source: str) -> str:
    """Remove comments and literal bodies so identifier scan avoids false positives."""
    out: list[str] = []
    i = 0
    length = len(source)
    while i < length:
        ch = source[i]
        nxt = source[i + 1] if i + 1 < length else ""

        if ch == "/" and nxt == "/":
            i += 2
            while i < length and source[i] not in "\r\n":
                i += 1
            out.append(" ")
            continue
        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < length and not (source[i] == "*" and source[i + 1] == "/"):
                i += 1
            i = min(i + 2, length)
            out.append(" ")
            continue

        if ch in ("'", '"'):
            quote = ch
            i += 1
            while i < length:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == quote:
                    i += 1
                    break
                i += 1
            out.append(' "" ')
            continue

        if ch == "`":
            out.append(" ")
            i = _scan_template_literal(source, i + 1, out)
            out.append(' "" ')
            continue

        if ch == "/":
            prev = source[i - 1] if i else ""
            regex_prev = (
                "=", "(", "[", "!", ":", ",", "?", "}", ")",
                "+", "-", "*", "%", "&", "|", "^", "~", "<", ">",
            )
            if prev not in regex_prev:
                out.append(ch)
                i += 1
                continue
            i += 1
            while i < length:
                if source[i] == "\\":
                    i += 2
                    continue
                if source[i] == "/":
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue

        out.append(ch)
        i += 1

    return "".join(out)


def _extract_exported_names(source: str) -> set[str]:
    names: set[str] = set()

    for match in re.finditer(
        r"export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)",
        source,
    ):
        names.add(match.group(1))
    for _match in re.finditer(
        r"export\s+(?:async\s+)?function\s*\(\s*\)",
        source,
    ):
        pass
    for match in re.finditer(
        r"export\s+(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)",
        source,
    ):
        names.add(match.group(1))
    for match in re.finditer(
        r"export\s+(?:const|let|var|class)\s+([A-Za-z_$][\w$]*)",
        source,
    ):
        names.add(match.group(1))
    for block in re.finditer(r"export\s*\{([^}]+)\}", source):
        for part in block.group(1).split(","):
            piece = part.strip()
            if not piece:
                continue
            if " as " in piece:
                _, alias = piece.split(" as ", 1)
                names.add(alias.strip())
            else:
                names.add(piece)
    default_fn = re.search(
        r"export\s+default\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)",
        source,
    )
    if default_fn:
        names.add(default_fn.group(1))
    default_ident = re.search(
        r"export\s+default\s+([A-Za-z_$][\w$]*)",
        source,
    )
    if default_ident:
        names.add(default_ident.group(1))

    return names


def _add_binding_names(target: set[str], fragment: str) -> None:
    fragment = fragment.strip()
    if not fragment:
        return
    if fragment.startswith("{"):
        inner = fragment.strip("{} ")
        for part in inner.split(","):
            piece = part.strip()
            if not piece:
                continue
            if " as " in piece:
                _, alias = piece.split(" as ", 1)
                target.add(alias.strip())
            else:
                target.add(piece)
        return
    if fragment.startswith("["):
        inner = fragment.strip("[] ")
        for part in inner.split(","):
            piece = part.strip()
            if not piece:
                continue
            if " as " in piece:
                _, alias = piece.split(" as ", 1)
                target.add(alias.strip())
            else:
                target.add(piece)
        return
    if "=" in fragment:
        fragment = fragment.split("=", 1)[0].strip()
    target.add(fragment)


def _extract_bound_names(source: str) -> set[str]:
    bound: set[str] = set()

    for match in re.finditer(
        r"import\s+([A-Za-z_$][\w$]*)\s+from\s+['\"][^'\"]+['\"]",
        source,
    ):
        bound.add(match.group(1))
    for match in re.finditer(
        r"import\s+\{([^}]+)\}\s+from\s+['\"][^'\"]+['\"]",
        source,
    ):
        _add_binding_names(bound, "{" + match.group(1) + "}")
    for match in re.finditer(
        r"import\s+\*\s+as\s+([A-Za-z_$][\w$]*)\s+from\s+['\"][^'\"]+['\"]",
        source,
    ):
        bound.add(match.group(1))

    for match in re.finditer(
        r"(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s*\*?\s+([A-Za-z_$][\w$]*)"
        r"\s*\(([^)]*)\)",
        source,
    ):
        bound.add(match.group(1))
        params = match.group(2)
        for param in params.split(","):
            piece = param.strip()
            if not piece:
                continue
            if "=" in piece:
                piece = piece.split("=", 1)[0].strip()
            _add_binding_names(bound, piece)

    for match in re.finditer(
        r"(?:^|\n)\s*(?:export\s+)?(?:async\s+)?function\s*\(([^)]*)\)",
        source,
    ):
        for param in match.group(1).split(","):
            piece = param.strip()
            if not piece:
                continue
            if "=" in piece:
                piece = piece.split("=", 1)[0].strip()
            _add_binding_names(bound, piece)

    for match in re.finditer(
        r"(?:^|\n)\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)",
        source,
    ):
        bound.add(match.group(1))

    for match in re.finditer(
        r"(?:^|\n)\s*(?:export\s+)?(?:const|let|var)\s+([^;\n]+)",
        source,
    ):
        decl = match.group(1)
        for part in decl.split(","):
            piece = part.strip()
            if not piece:
                continue
            _add_binding_names(bound, piece)

    for match in re.finditer(r"catch\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", source):
        bound.add(match.group(1))

    for match in re.finditer(
        r"for\s*\(\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s+(?:of|in)\s+",
        source,
    ):
        bound.add(match.group(1))
    for match in re.finditer(
        r"for\s*\(\s*(?:const|let|var)\s+(\[[^\]]+\]|\{[^}]+\})\s+(?:of|in)\s+",
        source,
    ):
        _add_binding_names(bound, match.group(1))

    return bound


def _strip_export_blocks(source: str) -> str:
    source = re.sub(r"export\s*\{[^}]*\}\s*;?", " ", source)
    source = re.sub(r"export\s+\*\s+from\s+['\"][^'\"]+['\"]\s*;?", " ", source)
    return source


def _identifier_before(stripped: str, pos: int) -> str | None:
    end = pos
    while end > 0 and (stripped[end - 1].isalnum() or stripped[end - 1] in "_$"):
        end -= 1
    word = stripped[end:pos]
    return word if word else None


def _brace_opens_object_literal(stripped: str, brace_pos: int) -> bool:
    """Return True when ``{`` at ``brace_pos`` opens an object literal, not a block."""
    i = brace_pos - 1
    while i >= 0 and stripped[i].isspace():
        i -= 1
    if i < 0:
        return False

    ch = stripped[i]
    if ch in "=(,[?:{}":
        return True

    if ch == ">":
        return i > 0 and stripped[i - 1] == "="

    word = _identifier_before(stripped, i + 1)
    if word == "return":
        return True
    if word in BLOCK_OPEN_KEYWORDS:
        return False

    if ch == ")":
        j = i - 1
        while j >= 0 and stripped[j].isspace():
            j -= 1
        if j >= 0 and stripped[j] == ">":
            if j > 0 and stripped[j - 1] == "=":
                return False
        if j >= 0 and stripped[j] == "(":
            k = j - 1
            while k >= 0 and stripped[k].isspace():
                k -= 1
            if k >= 0 and (stripped[k].isalnum() or stripped[k] in "_$"):
                return False
            prev_word = _identifier_before(stripped, k + 1)
            if prev_word == "function":
                return False
            return True
        prev_word = _identifier_before(stripped, j + 1) if j >= 0 else None
        if prev_word in {"if", "for", "while", "switch", "catch", "with"}:
            return False
        if prev_word == "function" or (
            j >= 8 and stripped[j - 7 : j + 1].endswith("function")
        ):
            return False
        snippet = stripped[max(0, j - 12) : j + 1]
        if re.search(r"\bfunction\b\s*$", snippet):
            return False
        return False

    return False


def _is_object_key_position(stripped: str, start: int) -> bool:
    depth_brace = 0
    depth_paren = 0
    depth_bracket = 0
    i = start - 1
    while i >= 0:
        ch = stripped[i]
        if ch.isspace():
            i -= 1
            continue
        if ch == "{":
            if depth_brace == 0 and depth_paren == 0 and depth_bracket == 0:
                return _brace_opens_object_literal(stripped, i)
            depth_brace -= 1
        elif ch == "}":
            depth_brace += 1
        elif ch == "(":
            depth_paren -= 1
        elif ch == ")":
            depth_paren += 1
        elif ch == "[":
            depth_bracket -= 1
        elif ch == "]":
            depth_bracket += 1
        elif ch == ":" and depth_brace == 0 and depth_paren == 0 and depth_bracket == 0:
            return False
        elif ch in ",(" and depth_brace == 0 and depth_paren == 0 and depth_bracket == 0:
            return False
        i -= 1
    return False


def _is_method_shorthand(stripped: str, start: int, end: int) -> bool:
    j = end
    while j < len(stripped) and stripped[j].isspace():
        j += 1
    if j >= len(stripped) or stripped[j] != "(":
        return False
    depth = 0
    k = j
    while k < len(stripped):
        if stripped[k] == "(":
            depth += 1
        elif stripped[k] == ")":
            depth -= 1
            if depth == 0:
                k += 1
                break
        k += 1
    while k < len(stripped) and stripped[k].isspace():
        k += 1
    return k < len(stripped) and stripped[k] == "{"


def _collect_free_hub_usages(
    stripped: str,
    *,
    bound: set[str],
    export_map: dict[str, set[str]],
    module_rel: str,
) -> list[tuple[str, int]]:
    violations: list[tuple[str, int]] = []
    for match in re.finditer(r"\b([A-Za-z_$][\w$]*)\b", stripped):
        name = match.group(1)
        if name in JS_KEYWORDS or name in bound:
            continue
        if name not in export_map:
            continue
        exporters = export_map[name]
        if exporters == {module_rel}:
            continue
        start = match.start()
        if start > 0 and stripped[start - 1] == ".":
            continue
        end = match.end()
        suffix = stripped[end : end + 3]
        if re.match(r"\s*:", suffix):
            continue
        if _is_object_key_position(stripped, start):
            continue
        if _is_method_shorthand(stripped, start, match.end()):
            continue
        violations.append((name, start))
    return violations


def analyze_hub_cross_module_bindings(hub_root: Path) -> list[dict[str, object]]:
    """Return unresolved hub-export usages grouped per module.

    Honest limits:
    - File-wide binding scan (not scope-aware); see module docstring.
    - Computed member expressions are not detected.
    - Runtime errors swallowed in ``.catch()`` are invisible; Layer 1 covers mount paths.
    """
    files = _collect_hub_js_files(hub_root)
    sources = {path: path.read_text(encoding="utf-8") for path in files}

    export_map: dict[str, set[str]] = {}
    for path, source in sources.items():
        rel = _rel_module(path, hub_root)
        for name in _extract_exported_names(source):
            export_map.setdefault(name, set()).add(rel)

    findings: list[dict[str, object]] = []
    for path, source in sources.items():
        rel = _rel_module(path, hub_root)
        bound = _extract_bound_names(source)
        stripped = _strip_js_for_usage_scan(_strip_export_blocks(source))
        raw_violations = _collect_free_hub_usages(
            stripped,
            bound=bound,
            export_map=export_map,
            module_rel=rel,
        )
        if not raw_violations:
            continue
        names = sorted({name for name, _ in raw_violations})
        findings.append(
            {
                "module": rel,
                "identifiers": names,
                "count": len(raw_violations),
            },
        )
    return findings


def _copy_hub_tree(src: Path, dst: Path) -> None:
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns(*SKIP_DIR_NAMES),
    )


def _delete_wifi_api_import(hub_root: Path, screen_name: str) -> None:
    screen = hub_root / "screens" / screen_name
    text = screen.read_text(encoding="utf-8")
    text = API_IMPORT_RE.sub("", text)
    screen.write_text(text, encoding="utf-8")


def _rename_screen_render_export(hub_root: Path, screen_rel: str) -> None:
    screen = hub_root / screen_rel
    text = screen.read_text(encoding="utf-8")
    text = text.replace("export function render", "export function renderScreen")
    screen.write_text(text, encoding="utf-8")


def _drop_screen_meta_export(hub_root: Path, screen_rel: str) -> None:
    screen = hub_root / screen_rel
    text = screen.read_text(encoding="utf-8")
    text = re.sub(r"^export const meta = ", "const meta = ", text, count=1, flags=re.MULTILINE)
    screen.write_text(text, encoding="utf-8")


def _assert_all_screens_rendered(hub_root: Path, payload: dict[str, object]) -> None:
    expected = _expected_screen_modules(hub_root)
    by_module = {str(item["module"]): item for item in payload["modules"]}  # type: ignore[index]
    missing: list[str] = []
    not_ok: list[str] = []
    for rel in expected:
        entry = by_module.get(rel)
        if entry is None:
            missing.append(rel)
        elif entry.get("render") != "ok":
            not_ok.append(f"{rel} (render={entry.get('render')!r})")
    assert not missing, f"screen modules absent from guard report: {missing}"
    assert not not_ok, f"screen modules not rendered: {not_ok}"
    for wifi in ("screens/staff-wifi.js", "screens/guest-wifi.js"):
        assert by_module[wifi]["render"] == "ok", by_module[wifi]


def _run_layer1_guard(hub_root: Path) -> subprocess.CompletedProcess[str]:
    node = _require_node()
    return subprocess.run(
        [node, str(GUARD_MJS), str(hub_root)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


def test_layer2_real_tree_has_zero_cross_module_violations() -> None:
    findings = analyze_hub_cross_module_bindings(HUB)
    assert findings == [], findings


def test_layer2_red_proof_template_literal_only_usage(tmp_path: Path) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    probe = copy_root / "features" / "_guard_probe_template.js"
    probe.write_text(
        "const x = `${subscribeConnectivity}`;\n",
        encoding="utf-8",
    )
    findings = analyze_hub_cross_module_bindings(copy_root)
    assert findings, "expected static guard failure on template-only hub export usage"
    probe_rel = probe.relative_to(copy_root).as_posix()
    probe_findings = next(item for item in findings if item["module"] == probe_rel)
    assert "subscribeConnectivity" in probe_findings["identifiers"]


def test_layer2_red_proof_function_body_open_brace_usage(tmp_path: Path) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    probe = copy_root / "features" / "_guard_probe_block.js"
    probe.write_text(
        "export function probeMount() {\n"
        "  return subscribeConnectivity(() => {});\n"
        "}\n",
        encoding="utf-8",
    )
    findings = analyze_hub_cross_module_bindings(copy_root)
    rel = probe.relative_to(copy_root).as_posix()
    probe_findings = next((item for item in findings if item["module"] == rel), None)
    assert probe_findings is not None, findings
    assert "subscribeConnectivity" in probe_findings["identifiers"]


@pytest.mark.parametrize("screen_file", WIFI_SCREENS)
def test_layer2_red_proof_deleted_api_import(tmp_path: Path, screen_file: str) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    _delete_wifi_api_import(copy_root, screen_file)

    findings = analyze_hub_cross_module_bindings(copy_root)
    assert findings, "expected static guard failure on deleted import"
    rel = f"screens/{screen_file}"
    screen = next(item for item in findings if item["module"] == rel)
    assert "subscribeConnectivity" in screen["identifiers"]


def test_layer1_guard_green_on_real_tree() -> None:
    proc = _run_layer1_guard(HUB)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["ok"] is True
    _assert_all_screens_rendered(HUB, payload)


def test_layer1_red_proof_renamed_render_export(tmp_path: Path) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    _rename_screen_render_export(copy_root, "screens/staff-wifi.js")

    proc = _run_layer1_guard(copy_root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    with pytest.raises(AssertionError, match="staff-wifi"):
        _assert_all_screens_rendered(copy_root, payload)


def test_layer1_red_proof_dropped_meta_export(tmp_path: Path) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    _drop_screen_meta_export(copy_root, "screens/showcase.js")

    proc = _run_layer1_guard(copy_root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    with pytest.raises(AssertionError, match="showcase"):
        _assert_all_screens_rendered(copy_root, payload)


def test_layer1_red_proof_late_async_rejection(tmp_path: Path) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    probe = copy_root / "features" / "_guard_probe_late_reject.js"
    probe.write_text(
        "export const meta = { id: 'late-reject-probe', title: 'Late reject probe' };\n"
        "export function render(container, ctx) {\n"
        "  void ctx;\n"
        "  container.textContent = 'probe';\n"
        "  void Promise.resolve().then(() => new Promise((_r, reject) => {\n"
        "    setTimeout(() => reject(new ReferenceError('late-probe-reject')), 600);\n"
        "  }));\n"
        "  return () => {};\n"
        "}\n",
        encoding="utf-8",
    )

    proc = _run_layer1_guard(copy_root)
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined
    assert "_guard_probe_late_reject.js" in combined
    assert "late-probe-reject" in combined


@pytest.mark.parametrize("screen_file", WIFI_SCREENS)
def test_layer1_red_proof_deleted_api_import(tmp_path: Path, screen_file: str) -> None:
    copy_root = tmp_path / "hub-copy"
    _copy_hub_tree(HUB, copy_root)
    _delete_wifi_api_import(copy_root, screen_file)

    proc = _run_layer1_guard(copy_root)
    assert proc.returncode != 0, "expected runtime guard failure on deleted import"
    combined = proc.stdout + proc.stderr
    assert "subscribeConnectivity" in combined
    assert screen_file in combined
