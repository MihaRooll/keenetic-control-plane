"""Структурные и поведенческие контракты экрана «Страницы входа» LOCAL HUB."""

# ruff: noqa: E501

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
SW_JS = HUB / "sw.js"
ENTRY_SCREEN_JS = HUB / "screens" / "entry-pages.js"
ENTRY_MODEL_JS = HUB / "features" / "entry-pages-model.js"
ERRORS_JS = HUB / "core" / "errors.js"
SESSION_JS = HUB / "core" / "session.js"
HARNESS_JS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"

NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"
CYRILLIC = re.compile(r"[\u0400-\u04FF]")

FORBIDDEN_ENTRY_LITERALS = (
    "Включена",
    "Создайте свой принт",
    "Оформление заказа",
    "Гостевая сеть",
    "renderStubScreen",
    "innerHTML",
    "localStorage",
    "sessionStorage",
    "blob:",
)

FORBIDDEN_ENTRY_PAGES_JARGON = (
    "listener",
    "host:port",
    "RC_PUBLIC_ENTRY_BIND",
    "docs/OPERATOR_ENTRY_PAGES.md",
    "captive portal",
    "read-only API",
    "ревизия",
    "slug",
    "revision_id",
    "self-check",
)

GUEST_DOCUMENT = {
    "title": "Тестовая гостевая страница",
    "intro": "Добро пожаловать",
    "button_label": "Отправить",
    "fields": [
        {
            "name": "full_name",
            "label": "Имя",
            "kind": "text",
            "required": True,
        }
    ],
    "submissions_enabled": True,
}

STAFF_DOCUMENT = {
    **GUEST_DOCUMENT,
    "title": "Страница персонала",
    "roles": ["Сотрудник", "Волонтёр"],
}


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
            f"node is required for hub entry pages tests; install Node.js or set "
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


def _dom_bootstrap() -> str:
    harness_uri = HARNESS_JS.as_uri()
    return f"""
import {{ createUiDomHarness }} from {json.dumps(harness_uri)};
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
"""


def _run_entry_model_export(tmp_path: Path, *, label: str, script_body: str) -> object:
    model_uri = ENTRY_MODEL_JS.as_uri()
    script = f"const mod = await import({json.dumps(model_uri)});\n{script_body}"
    return _run_node_harness(script, tmp_path, label)


def _run_entry_screen_mount(
    tmp_path: Path,
    *,
    label: str,
    fetch_impl: str,
    extra_script: str = "",
    screen_uri: Path | None = None,
) -> object:
    screen_import = (screen_uri or ENTRY_SCREEN_JS).as_uri()
    session_uri = SESSION_JS.as_uri()
    script = (
        _dom_bootstrap()
        + f"""
globalThis.fetch = async (url, init = {{}}) => {{
  {fetch_impl}
}};

import {{ resetSession }} from {json.dumps(session_uri)};
import {{ render }} from {json.dumps(screen_import)};

resetSession();

const container = dom.document.createElement('div');
dom.document.body.appendChild(container);
const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate() {{}},
  showToast() {{}},
}});

{extra_script}

dispose();
"""
    )
    return _run_node_harness(script, tmp_path, label)


def test_entry_pages_screen_exports_meta_and_render() -> None:
    source = _read(ENTRY_SCREEN_JS)
    assert "export const meta" in source
    assert "export function render(container, ctx)" in source
    assert "id: 'entry-pages'" in source
    assert "renderStubScreen" not in source
    assert "return () => {" in source


def test_entry_pages_forbidden_literals_grep() -> None:
    combined = _read(ENTRY_SCREEN_JS) + "\n" + _read(ENTRY_MODEL_JS)
    for literal in FORBIDDEN_ENTRY_LITERALS:
        assert literal not in combined, f"forbidden literal: {literal}"


def test_entry_pages_empty_mount_honest_state(tmp_path: Path) -> None:
    """Пустой список страниц — честное empty state без «Включена»."""
    result = _run_entry_screen_mount(
        tmp_path,
        label="empty-mount",
        fetch_impl="""
  const urlStr = String(url);
  if (urlStr.includes('entry-pages') && (init.method ?? 'GET') === 'GET' && !urlStr.includes('/entry-pages/')) {
    return {
      ok: true,
      status: 200,
      headers: { get: (name) => (String(name).toLowerCase() === 'content-type' ? 'application/json' : null) },
      json: async () => ({ items: [] }),
      text: async () => '{"items":[]}',
    };
  }
  throw new Error(`unexpected fetch: ${init.method ?? 'GET'} ${urlStr}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 250));
const text = dom.collectVisibleText(container);
console.log(JSON.stringify({
  text,
  hasEnabled: text.includes('Включена'),
  hasCreateAction: text.includes('Создать страницы'),
  hasMockPrint: text.includes('Создайте свой принт'),
}));
""",
    )
    assert "Включена" not in result["text"]
    assert result["hasEnabled"] is False
    assert result["hasMockPrint"] is False
    assert result["hasCreateAction"] is True


def test_entry_pages_draft_not_published_status(tmp_path: Path) -> None:
    """Черновик без публикации — статус и выключенный toggle."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="draft-unpublished",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'page-guest-1',
          audience: 'guest',
          slug: 'abc123',
          title: 'Тестовая гостевая страница',
          has_draft: true,
          published: false,
          current_revision_id: 'rev-1',
          published_revision_id: null,
          public_path: '/p/abc123',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/page-guest-1') && !urlStr.includes('draft-preview')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'page-guest-1',
        audience: 'guest',
        slug: 'abc123',
        title: 'Тестовая гостевая страница',
        has_draft: true,
        published: false,
        current_revision_id: 'rev-1',
        published_revision_id: null,
        public_path: '/p/abc123',
        draft_document: {guest_doc},
        published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 300));
const text = dom.collectVisibleText(container);
const toggle = document.getElementById('hub-entry-pages-publish-toggle');
console.log(JSON.stringify({
  text,
  hasNotPublished: text.includes('не опубликована'),
  toggleChecked: toggle ? toggle.checked : null,
}));
""",
    )
    assert result["hasNotPublished"] is True
    assert result["toggleChecked"] is False


def test_entry_pages_guest_reachability_neutral_even_if_backend_true(tmp_path: Path) -> None:
    """guest_reachable всегда unknown в модели — даже при malicious true."""
    result = _run_entry_model_export(
        tmp_path,
        label="guest-reachability-honesty",
        script_body="""
const neutral = mod.describeGuestReachability({ guest_reachable: null });
const malicious = mod.describeGuestReachability({ guest_reachable: true });
const parsed = mod.parseSelfCheckResult({
  published: true,
  render_ok: true,
  public_zone_enabled: null,
  guest_reachable: true,
  guest_reachable_reason: 'guest_device_check_required',
});
console.log(JSON.stringify({
  neutralState: neutral.hubState,
  maliciousState: malicious.hubState,
  parsedGuestState: parsed.guestReachability.hubState,
  maliciousMessage: malicious.message,
  claimsAvailable:
    malicious.message.toLowerCase().includes('доступн') &&
    !malicious.message.toLowerCase().includes('не провер'),
  parsedClaimsSuccess: parsed.guestReachability.hubState === 'SUCCESS',
}));
""",
    )
    assert result["neutralState"] != "SUCCESS"
    assert result["maliciousState"] != "SUCCESS"
    assert result["parsedGuestState"] != "SUCCESS"
    assert result["parsedClaimsSuccess"] is False
    assert result["claimsAvailable"] is False


def test_entry_pages_public_zone_configured_true_warning_no_service_claim(tmp_path: Path) -> None:
    """public_zone_enabled:true — WARNING, без заявления что гостевая служба доступна."""
    result = _run_entry_model_export(
        tmp_path,
        label="public-zone-honesty",
        script_body="""
const configured = mod.describePublicZoneConfigured(true);
console.log(JSON.stringify({
  hubState: configured.hubState,
  message: configured.message,
  claimsAvailable:
    configured.message.toLowerCase().includes('доступн') &&
    !configured.message.toLowerCase().includes('не провер'),
}));
""",
    )
    assert result["hubState"] == "WARNING"
    assert result["claimsAvailable"] is False


def test_entry_pages_self_check_dom_shows_unknown_guest(tmp_path: Path) -> None:
    """self-check с guest_reachable:null — нейтральный текст в DOM."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="self-check-dom",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'page-guest-1', audience: 'guest', slug: 'abc', title: 'T',
          has_draft: true, published: true, current_revision_id: 'rev-1',
          published_revision_id: 'rev-1', public_path: '/p/abc',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/page-guest-1') && !urlStr.includes('draft-preview')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'page-guest-1', audience: 'guest', slug: 'abc', title: 'T',
        has_draft: true, published: true, current_revision_id: 'rev-1',
        published_revision_id: 'rev-1', public_path: '/p/abc',
        draft_document: {guest_doc}, published_document: {guest_doc},
      }}),
    }};
  }}
  if (method === 'POST' && urlStr.includes('/self-check')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        checked_from: 'operator_host',
        published: true,
        render_ok: true,
        public_zone_enabled: null,
        guest_reachable: null,
        guest_reachable_reason: 'guest_device_check_required',
        public_path: '/p/abc',
        reason_code: 'entry.render_ok',
        writes_allowed: false,
        certification_eligible: false,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 300));
const checkBtn = document.getElementById('hub-entry-pages-self-check-btn');
if (checkBtn) checkBtn.click();
await new Promise((resolve) => setTimeout(resolve, 200));
const guestRow = container.querySelector('[data-testid="entry-guest-reachability"]');
const text = guestRow ? dom.collectVisibleText(guestRow) : dom.collectVisibleText(container);
console.log(JSON.stringify({
  text,
  hasUnknown: text.includes('не проверена'),
  claimsGuestOk: /доступн.*гост/i.test(text) && !text.includes('не проверена'),
}));
""",
    )
    assert result["hasUnknown"] is True
    assert result["claimsGuestOk"] is False


def test_entry_pages_auto_open_unsupported_no_control(tmp_path: Path) -> None:
    """Автооткрытие — только текст unsupported, без рабочего toggle."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="auto-open-unsupported",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
          has_draft: true, published: false, current_revision_id: 'r1',
          published_revision_id: null, public_path: '/p/s',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/p1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
        has_draft: true, published: false, current_revision_id: 'r1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 300));
const note = container.querySelector('[data-testid="entry-auto-open-unsupported"]');
const autoOpenToggle = document.getElementById('hub-entry-pages-auto-open-toggle');
console.log(JSON.stringify({
  noteText: note ? note.textContent : '',
  hasUnsupported: note ? note.textContent.includes('не поддерживается') : false,
  hasAutoOpenToggle: !!autoOpenToggle,
}));
""",
    )
    assert result["hasUnsupported"] is True
    assert result["hasAutoOpenToggle"] is False


def test_entry_pages_client_rejects_html_before_fetch(tmp_path: Path) -> None:
    """«<» в заголовке — локальный отказ, PUT не отправляется."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="client-html-reject",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'PUT') {{
    throw new Error('PUT must not be called for invalid draft');
  }}
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
          has_draft: true, published: false, current_revision_id: 'r1',
          published_revision_id: null, public_path: '/p/s',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/p1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
        has_draft: true, published: false, current_revision_id: 'r1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 300));
const titleInput = document.getElementById('hub-entry-pages-title');
dom.simulateInput(titleInput, 'Bad <tag>');
const saveBtn = document.getElementById('hub-entry-pages-save-btn');
if (saveBtn) saveBtn.click();
await new Promise((resolve) => setTimeout(resolve, 100));
console.log(JSON.stringify({
  saveDisabled: saveBtn ? saveBtn.disabled : null,
  footerText: dom.collectVisibleText(container.querySelector('.hub-wifi__footer-left') || container),
}));
""",
    )
    assert result["saveDisabled"] is True
    assert "«<»" in result["footerText"] or "«>»" in result["footerText"]


def test_entry_pages_server_html_not_allowed_user_message(tmp_path: Path) -> None:
    """422 entry.html_not_allowed → русское сообщение из errors.js без echo."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    canary = "CANARY_HTML_ECHO_XYZ_998877"
    result = _run_entry_screen_mount(
        tmp_path,
        label="server-html-error",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'PUT' && urlStr.includes('/draft')) {{
    return {{
      ok: false,
      status: 422,
      headers: {{ get: (name) => (String(name).toLowerCase() === 'content-type' ? 'application/json' : null) }},
      json: async () => ({{
        error: {{
          code: 'entry.html_not_allowed',
          message: 'raw server {canary}',
          details: [],
        }},
      }}),
      text: async () => JSON.stringify({{ error: {{ code: 'entry.html_not_allowed', message: 'raw {canary}' }} }}),
    }};
  }}
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
          has_draft: true, published: false, current_revision_id: 'r1',
          published_revision_id: null, public_path: '/p/s',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/p1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
        has_draft: true, published: false, current_revision_id: 'r1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 300));
const introInput = document.getElementById('hub-entry-pages-intro');
dom.simulateInput(introInput, 'Valid intro changed');
const saveBtn = document.getElementById('hub-entry-pages-save-btn');
if (saveBtn && !saveBtn.disabled) saveBtn.click();
await new Promise((resolve) => setTimeout(resolve, 250));
const footerText = dom.collectVisibleText(container);
console.log(JSON.stringify({
  footerText,
  hasRussian: footerText.includes('«<»') && footerText.includes('»'),
  hasCanary: footerText.includes('CANARY_HTML_ECHO_XYZ_998877'),
}));
""",
    )
    assert result["hasRussian"] is True
    assert result["hasCanary"] is False


def test_entry_pages_preview_uses_draft_title(tmp_path: Path) -> None:
    """Предпросмотр показывает реальный заголовок черновика."""
    doc = {**GUEST_DOCUMENT, "title": "Уникальный заголовок черновика"}
    guest_doc = json.dumps(doc, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="preview-draft-title",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'p1', audience: 'guest', slug: 's', title: 'Уникальный заголовок черновика',
          has_draft: true, published: false, current_revision_id: 'r1',
          published_revision_id: null, public_path: '/p/s',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/p1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'p1', audience: 'guest', slug: 's', title: 'Уникальный заголовок черновика',
        has_draft: true, published: false, current_revision_id: 'r1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 500));
const preview = container.querySelector('[data-testid="entry-preview-body"]');
const text = preview ? dom.collectVisibleText(preview) : '';
console.log(JSON.stringify({
  text,
  hasDraftTitle: text.includes('Уникальный заголовок черновика'),
  hasMockPrint: text.includes('Создайте свой принт'),
}));
""",
    )
    assert result["hasDraftTitle"] is True
    assert result["hasMockPrint"] is False


def test_entry_pages_stale_response_does_not_overwrite(tmp_path: Path) -> None:
    """Старый detail-ответ не перезаписывает более новый render при смене вкладок."""
    guest_doc_stale = json.dumps(
        {**GUEST_DOCUMENT, "title": "STALE_OLD_TITLE"},
        ensure_ascii=False,
    )
    guest_doc_fresh = json.dumps(
        {**GUEST_DOCUMENT, "title": "FRESH_NEW_TITLE"},
        ensure_ascii=False,
    )
    staff_doc = json.dumps(
        {**GUEST_DOCUMENT, "title": "Staff page", "roles": ["Сотрудник"]},
        ensure_ascii=False,
    )
    result = _run_entry_screen_mount(
        tmp_path,
        label="stale-response",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages') && !urlStr.includes('/entry-pages/')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [
          {{
            page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'FRESH_NEW_TITLE',
            has_draft: true, published: false, current_revision_id: 'rg1',
            published_revision_id: null, public_path: '/p/g',
          }},
          {{
            page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff page',
            has_draft: true, published: false, current_revision_id: 'rs1',
            published_revision_id: null, public_path: '/p/s',
          }},
        ],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    if (!globalThis.__guestDetailFetchCount) globalThis.__guestDetailFetchCount = 0;
    globalThis.__guestDetailFetchCount += 1;
    const n = globalThis.__guestDetailFetchCount;
    const delayMs = n === 1 ? 450 : 30;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    const doc = n === 1 ? {guest_doc_stale} : {guest_doc_fresh};
    const title = n === 1 ? 'STALE_OLD_TITLE' : 'FRESH_NEW_TITLE';
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title,
        has_draft: true, published: false, current_revision_id: 'rg1',
        published_revision_id: null, public_path: '/p/g',
        draft_document: doc, published_document: null,
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/staff-1')) {{
    await new Promise((resolve) => setTimeout(resolve, 20));
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff page',
        has_draft: true, published: false, current_revision_id: 'rs1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {staff_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 80));
const staffTab = [...container.querySelectorAll('.hub-segmented__option')]
  .find((btn) => String(btn.textContent || '').includes('персонала'));
if (staffTab) staffTab.click();
await new Promise((resolve) => setTimeout(resolve, 120));
const guestTab = [...container.querySelectorAll('.hub-segmented__option')]
  .find((btn) => String(btn.textContent || '').includes('гостей'));
if (guestTab) guestTab.click();
await new Promise((resolve) => setTimeout(resolve, 700));
const preview = container.querySelector('[data-testid="entry-preview-body"]');
const text = preview ? dom.collectVisibleText(preview) : dom.collectVisibleText(container);
console.log(JSON.stringify({
  text,
  hasFresh: text.includes('FRESH_NEW_TITLE'),
  hasStale: text.includes('STALE_OLD_TITLE'),
}));
""",
    )
    assert result["hasFresh"] is True
    assert result["hasStale"] is False


def test_entry_pages_errors_js_has_entry_codes() -> None:
    source = _read(ERRORS_JS)
    for code in (
        "entry.page_not_found",
        "entry.html_not_allowed",
        "entry.validation_failed",
    ):
        assert code in source


def test_entry_pages_sw_lists_model() -> None:
    source = _read(SW_JS)
    assert "features/entry-pages-model.js" in source
    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None, "CACHE_VERSION must be present in sw.js"
    assert version_match.group(1).isdigit() and int(version_match.group(1)) > 0
    assert "features/entry-pages-model.js" in source
    shell_match = re.search(r"const\s+SHELL_URLS\s*=\s*\[([\s\S]*?)\];", source)
    assert shell_match is not None
    assert "features/entry-pages-model.js" in shell_match.group(1)


def test_entry_pages_user_strings_no_jargon() -> None:
    """Пользовательские строки экрана и модели без инженерного жаргона."""
    combined = _read(ENTRY_SCREEN_JS) + "\n" + _read(ENTRY_MODEL_JS)
    literals = re.findall(r"'([^'\\]*(?:\\.[^'\\]*)*)'", combined)
    literals += re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', combined)
    for match in re.finditer(r"`([^`]*)`", combined):
        static = re.sub(r"\$\{[^}]*\}", "", match.group(1))
        if static:
            literals.append(static)
    for literal in literals:
        if not CYRILLIC.search(literal):
            continue
        for jargon in FORBIDDEN_ENTRY_PAGES_JARGON:
            assert jargon not in literal, f"jargon {jargon!r} in: {literal!r}"


def test_entry_pages_jargon_scanner_catches_template_literals(tmp_path: Path) -> None:
    """F-8: template literal со jargon должен ловиться сканером."""
    probe = "const x = `Текст со словом listener для гостя`;"
    static = re.sub(r"\$\{[^}]*\}", "", re.search(r"`([^`]*)`", probe).group(1))
    assert "listener" in static
    assert any(jargon in static for jargon in FORBIDDEN_ENTRY_PAGES_JARGON)


def test_entry_pages_uses_shared_probe_scope_label() -> None:
    """Единая формулировка «Проверено с компьютера оператора»."""
    source = _read(ENTRY_SCREEN_JS)
    assert "DOMAIN_HOST_PROBE_SCOPE_LABEL" in source
    assert "ENTRY_OPERATOR_RENDER_SCOPE_LABEL" not in source
    assert "Проверено на компьютере оператора" not in source


def test_entry_pages_self_check_dom_rejects_guest_true(tmp_path: Path) -> None:
    """guest_reachable:true с сервера — DOM не показывает успех о доступности гостю."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="self-check-dom-guest-true",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'page-guest-1', audience: 'guest', slug: 'abc', title: 'T',
          has_draft: true, published: true, current_revision_id: 'rev-1',
          published_revision_id: 'rev-1', public_path: '/p/abc',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/page-guest-1') && !urlStr.includes('draft-preview')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'page-guest-1', audience: 'guest', slug: 'abc', title: 'T',
        has_draft: true, published: true, current_revision_id: 'rev-1',
        published_revision_id: 'rev-1', public_path: '/p/abc',
        draft_document: {guest_doc}, published_document: {guest_doc},
      }}),
    }};
  }}
  if (method === 'POST' && urlStr.includes('/self-check')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        checked_from: 'operator_host',
        published: true,
        render_ok: true,
        public_zone_enabled: null,
        guest_reachable: true,
        guest_reachable_reason: 'malicious_true',
        public_path: '/p/abc',
        reason_code: 'entry.render_ok',
        writes_allowed: false,
        certification_eligible: false,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 300));
const checkBtn = document.getElementById('hub-entry-pages-self-check-btn');
if (checkBtn) checkBtn.click();
await new Promise((resolve) => setTimeout(resolve, 200));
const guestRow = container.querySelector('[data-testid="entry-guest-reachability"]');
const text = guestRow ? dom.collectVisibleText(guestRow) : dom.collectVisibleText(container);
const successTone = guestRow ? guestRow.querySelector('[data-hub-state="SUCCESS"]') : null;
console.log(JSON.stringify({
  text,
  hasUnknown: text.includes('не проверена'),
  claimsGuestOk: /доступн.*гост/i.test(text) && !text.includes('не проверена'),
  hasSuccessTone: !!successTone,
  hasQr: !!container.querySelector('[data-testid="entry-public-qr"]'),
}));
""",
    )
    assert result["hasUnknown"] is True
    assert result["claimsGuestOk"] is False
    assert result["hasSuccessTone"] is False


def test_entry_pages_draft_survives_tab_switch(tmp_path: Path) -> None:
    """Несохранённый ввод сохраняется при переключении вкладок аудитории."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    staff_doc = json.dumps(STAFF_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="draft-tab-switch",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages') && !urlStr.includes('/entry-pages/')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [
          {{
            page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
            has_draft: true, published: false, current_revision_id: 'rg1',
            published_revision_id: null, public_path: '/p/g',
          }},
          {{
            page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff page',
            has_draft: true, published: false, current_revision_id: 'rs1',
            published_revision_id: null, public_path: '/p/s',
          }},
        ],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
        has_draft: true, published: false, current_revision_id: 'rg1',
        published_revision_id: null, public_path: '/p/g',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/staff-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff page',
        has_draft: true, published: false, current_revision_id: 'rs1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {staff_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 400));
const typed = 'Уникальный ввод оператора XYZ';
const titleInput = document.getElementById('hub-entry-pages-title');
dom.simulateInput(titleInput, typed);
const tabButtons = [...container.querySelectorAll('.hub-segmented__option')];
const staffTab = tabButtons.find((btn) => String(btn.textContent || '').includes('персонала'));
if (staffTab) staffTab.click();
await new Promise((resolve) => setTimeout(resolve, 300));
const guestTab = [...container.querySelectorAll('.hub-segmented__option')]
  .find((btn) => String(btn.textContent || '').includes('гостей'));
if (guestTab) guestTab.click();
await new Promise((resolve) => setTimeout(resolve, 300));
const restoredInput = document.getElementById('hub-entry-pages-title');
console.log(JSON.stringify({
  typedValue: restoredInput ? restoredInput.value : null,
  kept: restoredInput ? restoredInput.value === typed : false,
}));
""",
    )
    assert result["kept"] is True
    assert result["typedValue"] == "Уникальный ввод оператора XYZ"


def test_entry_pages_dirty_draft_not_clobbered_by_refresh(tmp_path: Path) -> None:
    """Фоновое обновление detail не затирает несохранённый черновик."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    server_doc = json.dumps({**GUEST_DOCUMENT, "title": "Серверный заголовок"}, ensure_ascii=False)
    staff_doc = json.dumps(STAFF_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="dirty-refresh",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages') && !urlStr.includes('/entry-pages/')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [
          {{
            page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Серверный заголовок',
            has_draft: true, published: false, current_revision_id: 'rg1',
            published_revision_id: null, public_path: '/p/g',
          }},
          {{
            page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff',
            has_draft: true, published: false, current_revision_id: 'rs1',
            published_revision_id: null, public_path: '/p/s',
          }},
        ],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    if (!globalThis.__detailFetchCount) globalThis.__detailFetchCount = 0;
    globalThis.__detailFetchCount += 1;
    const doc = globalThis.__detailFetchCount === 1
      ? {guest_doc}
      : {server_doc};
    const title = globalThis.__detailFetchCount === 1 ? 'Тестовая гостевая страница' : 'Серверный заголовок';
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title,
        has_draft: true, published: false, current_revision_id: 'rg1',
        published_revision_id: null, public_path: '/p/g',
        draft_document: doc, published_document: null,
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/staff-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff',
        has_draft: true, published: false, current_revision_id: 'rs1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {staff_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 400));
const typed = 'Черновик оператора не затирать';
dom.simulateInput(document.getElementById('hub-entry-pages-title'), typed);
const staffTab = [...container.querySelectorAll('.hub-segmented__option')]
  .find((btn) => String(btn.textContent || '').includes('персонала'));
if (staffTab) staffTab.click();
await new Promise((resolve) => setTimeout(resolve, 300));
const guestTab = [...container.querySelectorAll('.hub-segmented__option')]
  .find((btn) => String(btn.textContent || '').includes('гостей'));
if (guestTab) guestTab.click();
await new Promise((resolve) => setTimeout(resolve, 400));
const titleInput = document.getElementById('hub-entry-pages-title');
console.log(JSON.stringify({
  value: titleInput ? titleInput.value : null,
  kept: titleInput ? titleInput.value === typed : false,
  hasServerTitle: titleInput ? titleInput.value.includes('Серверный заголовок') : false,
}));
""",
    )
    assert result["kept"] is True
    assert result["hasServerTitle"] is False


def test_entry_pages_public_url_rejects_dangerous_schemes(tmp_path: Path) -> None:
    """Опасные схемы адреса отклоняются — ссылка и QR не строятся."""
    cases = [
        "javascript://alert(1)",
        "data:text/html,evil",
        "file:///etc/passwd",
        "vbscript:msgbox(1)",
    "//evil.example.com",
    "192.168.1.1:8790\njavascript:alert(1)",
]
    script_body = f"""
const cases = {json.dumps(cases)};
const results = cases.map((host) => {{
  const validation = mod.validatePublicEntryAddress(host);
  const url = mod.buildPublicEntryUrl(host, '/p/demo');
  return {{ host, valid: validation.valid, url, error: validation.error }};
}});
console.log(JSON.stringify({{ results }}));
"""
    result = _run_entry_model_export(
        tmp_path,
        label="dangerous-url-schemes",
        script_body=script_body,
    )
    for item in result["results"]:
        assert item["valid"] is False, item
        assert item["url"] is None, item
        assert item["error"], item


def test_entry_pages_public_url_accepts_http_host_port(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="valid-url",
        script_body="""
const bare = mod.buildPublicEntryUrl('192.168.1.10:8790', '/p/demo');
const https = mod.buildPublicEntryUrl('https://192.168.1.10:8790', '/p/demo');
console.log(JSON.stringify({ bare, https }));
""",
    )
    assert result["bare"] == "http://192.168.1.10:8790/p/demo"
    assert result["https"] == "https://192.168.1.10:8790/p/demo"


def test_entry_pages_derive_field_name_cyrillic(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="derive-cyrillic",
        script_body="""
const name = mod.deriveFieldName('Имя гостя', new Set(), 0);
const valid = mod.FIELD_NAME_RE.test(name);
console.log(JSON.stringify({ name, valid }));
""",
    )
    assert result["valid"] is True
    assert result["name"] == "field_1"


def test_entry_pages_derive_field_name_unique(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="derive-unique",
        script_body="""
const taken = new Set(['email']);
const a = mod.deriveFieldName('Email', taken, 0);
const b = mod.deriveFieldName('Email', new Set([a]), 1);
console.log(JSON.stringify({ a, b, distinct: a !== b }));
""",
    )
    assert result["distinct"] is True


def test_entry_pages_validate_select_requires_options(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="select-options",
        script_body="""
const doc = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: true,
  fields: [{ name: 'size', label: 'Размер', kind: 'select', required: true }],
};
const bad = mod.validateEntryDocument(doc, mod.ENTRY_AUDIENCE_GUEST);
const withOpts = mod.validateEntryDocument({
  ...doc,
  fields: [{ name: 'size', label: 'Размер', kind: 'select', required: true, options: ['S', 'M'] }],
}, mod.ENTRY_AUDIENCE_GUEST);
const textWithOpts = mod.validateEntryDocument({
  ...doc,
  fields: [{ name: 'size', label: 'Размер', kind: 'text', required: true, options: ['S'] }],
}, mod.ENTRY_AUDIENCE_GUEST);
console.log(JSON.stringify({
  badValid: bad.valid,
  withOptsValid: withOpts.valid,
  textWithOptsValid: textWithOpts.valid,
}));
""",
    )
    assert result["badValid"] is False
    assert result["withOptsValid"] is True
    assert result["textWithOptsValid"] is False


def test_entry_pages_staff_requires_role(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="staff-roles",
        script_body="""
const base = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: false, fields: [],
};
const noRoles = mod.validateEntryDocument(base, mod.ENTRY_AUDIENCE_STAFF);
const emptyRoles = mod.validateEntryDocument({ ...base, roles: [] }, mod.ENTRY_AUDIENCE_STAFF);
const ok = mod.validateEntryDocument({ ...base, roles: ['Сотрудник'] }, mod.ENTRY_AUDIENCE_STAFF);
console.log(JSON.stringify({
  noRolesValid: noRoles.valid,
  emptyRolesValid: emptyRoles.valid,
  okValid: ok.valid,
}));
""",
    )
    assert result["noRolesValid"] is False
    assert result["emptyRolesValid"] is False
    assert result["okValid"] is True


def test_entry_pages_guest_rejects_roles(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="guest-no-roles",
        script_body="""
const doc = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: false,
  fields: [], roles: ['Сотрудник'],
};
const validation = mod.validateEntryDocument(doc, mod.ENTRY_AUDIENCE_GUEST);
console.log(JSON.stringify({ valid: validation.valid, errors: validation.errors }));
""",
    )
    assert result["valid"] is False
    assert any("гостев" in err.lower() for err in result["errors"])


def test_entry_pages_field_and_role_caps(tmp_path: Path) -> None:
    result = _run_entry_model_export(
        tmp_path,
        label="caps",
        script_body="""
const mkField = (i) => ({ name: `f${i}`, label: `F${i}`, kind: 'text', required: false });
const nineFields = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: false,
  fields: Array.from({ length: 9 }, (_, i) => mkField(i)),
};
const thirteenRoles = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: false, fields: [],
  roles: Array.from({ length: 13 }, (_, i) => `R${i}`),
};
console.log(JSON.stringify({
  tooManyFields: mod.validateEntryDocument(nineFields, mod.ENTRY_AUDIENCE_GUEST).valid,
  tooManyRoles: mod.validateEntryDocument(thirteenRoles, mod.ENTRY_AUDIENCE_STAFF).valid,
  eightOk: mod.validateEntryDocument({
    ...nineFields, fields: nineFields.fields.slice(0, 8),
  }, mod.ENTRY_AUDIENCE_GUEST).valid,
}));
""",
    )
    assert result["tooManyFields"] is False
    assert result["tooManyRoles"] is False
    assert result["eightOk"] is True


def test_entry_pages_fields_editor_add_remove_dom(tmp_path: Path) -> None:
    """DOM: добавление и удаление поля формы."""
    guest_doc = json.dumps({**GUEST_DOCUMENT, "fields": [], "submissions_enabled": True}, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="fields-editor-dom",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
          has_draft: true, published: false, current_revision_id: 'r1',
          published_revision_id: null, public_path: '/p/s',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/p1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'p1', audience: 'guest', slug: 's', title: 'T',
        has_draft: true, published: false, current_revision_id: 'r1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 600));
const addBtn = container.querySelector('[data-testid="entry-add-field-btn"]');
if (addBtn) addBtn.click();
await new Promise((resolve) => setTimeout(resolve, 250));
const rowCountAfterAdd = container.querySelectorAll('.hub-entry-pages__field-row').length;
const labelInput = document.getElementById('hub-entry-pages-field-label-0');
if (labelInput) dom.simulateInput(labelInput, 'Телефон');
await new Promise((resolve) => setTimeout(resolve, 150));
const preview = container.querySelector('[data-testid="entry-preview-body"]');
const previewText = preview ? dom.collectVisibleText(preview) : '';
const removeBtn = container.querySelector('[data-testid="entry-field-remove-0"]');
if (removeBtn) removeBtn.click();
await new Promise((resolve) => setTimeout(resolve, 200));
console.log(JSON.stringify({
  rowCountAfterAdd,
  previewHasPhone: previewText.includes('Телефон'),
  rowCountAfterRemove: container.querySelectorAll('.hub-entry-pages__field-row').length,
}));
""",
    )
    assert result["rowCountAfterAdd"] == 1
    assert result["previewHasPhone"] is True
    assert result["rowCountAfterRemove"] == 0


def test_entry_pages_roles_editor_staff_dom(tmp_path: Path) -> None:
    """DOM: редактор ролей виден только на вкладке персонала."""
    staff_doc = json.dumps(STAFF_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="roles-editor-dom",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [
          {{
            page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
            has_draft: true, published: false, current_revision_id: 'rg1',
            published_revision_id: null, public_path: '/p/g',
          }},
          {{
            page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff',
            has_draft: true, published: false, current_revision_id: 'rs1',
            published_revision_id: null, public_path: '/p/s',
          }},
        ],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
        has_draft: true, published: false, current_revision_id: 'rg1',
        published_revision_id: null, public_path: '/p/g',
        draft_document: {json.dumps(GUEST_DOCUMENT, ensure_ascii=False)}, published_document: null,
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/staff-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'staff-1', audience: 'staff', slug: 's', title: 'Staff',
        has_draft: true, published: false, current_revision_id: 'rs1',
        published_revision_id: null, public_path: '/p/s',
        draft_document: {staff_doc}, published_document: null,
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 400));
const staffTab = [...container.querySelectorAll('.hub-segmented__option')]
  .find((btn) => String(btn.textContent || '').includes('персонала'));
if (staffTab) staffTab.click();
await new Promise((resolve) => setTimeout(resolve, 500));
const rolesEditor = container.querySelector('[data-testid="entry-roles-editor"]');
const roleRows = container.querySelectorAll('.hub-entry-pages__role-row');
console.log(JSON.stringify({
  hasRolesEditor: !!rolesEditor,
  roleRowCount: roleRows.length,
  text: rolesEditor ? dom.collectVisibleText(rolesEditor) : '',
}));
""",
    )
    assert result["hasRolesEditor"] is True
    assert "Сотрудник" in result["text"]
    assert "Волонтёр" in result["text"]


def test_validate_public_address_rejects_incomplete_and_dangerous(tmp_path: Path) -> None:
    """F-2: неполные и опасные адреса отклоняются без URL/QR."""
    reject_cases = [
        "1",
        "19",
        "1.2",
        "010.1.1.1",
        "http:/\\evil",
        "http://user:pass@host",
        "evil\u0430.example.com",
        "a" * 300 + ".example.com",
        "JAVASCRIPT:alert(1)",
        " 192.168.1.10:8790",
        "192.168.1.10:8790\t",
    ]
    script_body = f"""
const rejectCases = {json.dumps(reject_cases)};
const results = rejectCases.map((host) => {{
  const validation = mod.validatePublicEntryAddress(host);
  const url = mod.buildPublicEntryUrl(host, '/p/demo');
  return {{ host, valid: validation.valid, url, normalized: validation.normalizedHost }};
}});
const accept = mod.validatePublicEntryAddress('192.168.1.10:8790');
const acceptUrl = mod.buildPublicEntryUrl('192.168.1.10:8790', '/p/demo');
console.log(JSON.stringify({{ results, acceptValid: accept.valid, acceptUrl }}));
"""
    result = _run_entry_model_export(
        tmp_path,
        label="address-validator-matrix",
        script_body=script_body,
    )
    for item in result["results"]:
        assert item["valid"] is False, item
        assert item["url"] is None, item
        assert item["normalized"] is None, item
    assert result["acceptValid"] is True
    assert result["acceptUrl"] == "http://192.168.1.10:8790/p/demo"


def test_entry_pages_qr_encode_debounced_on_burst(tmp_path: Path) -> None:
    """F-3: серия ввода даёт не более одного encode для установившегося значения."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    screen_uri = json.dumps(ENTRY_SCREEN_JS.as_uri())
    session_uri = json.dumps(SESSION_JS.as_uri())
    script = (
        _dom_bootstrap()
        + f"""
globalThis.fetch = async (url, init = {{}}) => {{
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.includes('/entry-pages') && !urlStr.match(/\\/entry-pages\\/[^/?]+/)) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
          has_draft: true, published: true, current_revision_id: 'rg1',
          published_revision_id: 'rg1', public_path: '/p/g',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
        has_draft: true, published: true, current_revision_id: 'rg1',
        published_revision_id: 'rg1', public_path: '/p/g',
        draft_document: {guest_doc}, published_document: {guest_doc},
      }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
}};

import {{ resetSession }} from {session_uri};
import {{ render }} from {screen_uri};

const sampleCanvas = dom.document.createElement('canvas');
globalThis.HTMLCanvasElement = sampleCanvas.constructor;
let encodeCount = 0;
HTMLCanvasElement.prototype.getContext = function(type) {{
  if (type === '2d') {{
    encodeCount += 1;
    return {{
      fillRect() {{}},
      clearRect() {{}},
      set fillStyle(_v) {{}},
      get fillStyle() {{ return '#000'; }},
      createImageData(w, h) {{ return {{ width: w, height: h, data: new Uint8ClampedArray(w * h * 4) }}; }},
      putImageData() {{}},
    }};
  }}
  return null;
}};

resetSession();
const container = dom.document.createElement('div');
dom.document.body.appendChild(container);
const dispose = render(container, {{
  runtime: {{ adapterMode: 'fake' }},
  navigate() {{}},
  showToast() {{}},
}});

await new Promise((resolve) => setTimeout(resolve, 800));
const hostInput = container.querySelector('#hub-entry-pages-public-host')
  ?? container.querySelector('[id="hub-entry-pages-public-host"]');
if (!hostInput) throw new Error('host input missing');
const burst = '192.168.1.10:8790';
for (let i = 1; i <= burst.length; i += 1) {{
  dom.simulateInput(hostInput, burst.slice(0, i));
}}
await new Promise((resolve) => setTimeout(resolve, 500));
const qrPresent = !!container.querySelector('[data-testid="entry-public-qr"]');
dispose();
console.log(JSON.stringify({{ encodeCount, qrPresent }}));
"""
    )
    result = _run_node_harness(script, tmp_path, "qr-debounce-count")
    assert result["encodeCount"] <= 1, f"expected at most 1 encode, got {result['encodeCount']}"
    assert result["qrPresent"] is True


def test_entry_pages_unknown_descriptors_no_refusal_lexicon(tmp_path: Path) -> None:
    """F-4: unknown-дескрипторы entry-pages без refusal-лексики."""
    result = _run_entry_model_export(
        tmp_path,
        label="entry-unknown-lexicon",
        script_body="""
const refusal = ['не удалось', 'не прочитан', 'недоступ', 'ошибка', 'не совпада', 'сбой', 'отказ'];
const rows = [];
rows.push(mod.describeOperatorRenderCheck(null, true));
rows.push(mod.describeOperatorRenderCheck(null, false));
rows.push(mod.describePublicZoneConfigured(null));
rows.push(mod.describeGuestReachability(null));
rows.push(mod.parseSelfCheckResult(null).operatorRender);
rows.push(mod.parseSelfCheckResult(null).publicZone);
rows.push(mod.parseSelfCheckResult(null).guestReachability);

const violations = [];
for (const row of rows) {
  if (row.hubState !== 'EMPTY' && row.hubState !== 'WARNING') continue;
  const msg = String(row.message ?? row.label ?? '').toLowerCase();
  for (const word of refusal) {
    if (msg.includes(word)) violations.push({ message: row.message ?? row.label, word });
  }
}
console.log(JSON.stringify({ violations }));
""",
    )
    assert result["violations"] == [], f"refusal in unknown entry descriptors: {result['violations']}"


def test_entry_pages_rejects_duplicate_roles(tmp_path: Path) -> None:
    """F-7: дубликаты ролей отклоняются."""
    result = _run_entry_model_export(
        tmp_path,
        label="duplicate-roles",
        script_body="""
const base = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: false, fields: [],
};
const dup = mod.validateEntryDocument({ ...base, roles: ['A', 'A'] }, mod.ENTRY_AUDIENCE_STAFF);
const dupCase = mod.validateEntryDocument({ ...base, roles: ['Admin', ' admin '] }, mod.ENTRY_AUDIENCE_STAFF);
console.log(JSON.stringify({ dupValid: dup.valid, dupCaseValid: dupCase.valid, errors: dup.errors.concat(dupCase.errors) }));
""",
    )
    assert result["dupValid"] is False
    assert result["dupCaseValid"] is False
    assert any("уже добавлена" in err for err in result["errors"])


def test_entry_pages_rejects_duplicate_field_labels(tmp_path: Path) -> None:
    """F-7: одинаковые подписи полей отклоняются."""
    result = _run_entry_model_export(
        tmp_path,
        label="duplicate-field-labels",
        script_body="""
const doc = {
  title: 'T', intro: '', button_label: 'OK', submissions_enabled: true,
  fields: [
    { name: 'f1', label: 'Email', kind: 'text', required: true },
    { name: 'f2', label: ' email ', kind: 'text', required: false },
  ],
};
const validation = mod.validateEntryDocument(doc, mod.ENTRY_AUDIENCE_GUEST);
console.log(JSON.stringify({ valid: validation.valid, errors: validation.errors }));
""",
    )
    assert result["valid"] is False
    assert any("подпись уже используется" in err for err in result["errors"])


def test_entry_pages_captive_portal_note_single_definition() -> None:
    """F-9: captive/auto-open unsupported — одна константа."""
    entry_source = _read(ENTRY_MODEL_JS)
    diag_source = _read(HUB / "features" / "diagnostics-model.js")
    assert "export const ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE" in entry_source
    assert "ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE" in diag_source
    assert entry_source.count("Принудительное автооткрытие страницы после подключения к Wi‑Fi") == 1


def test_entry_pages_mount_layout_once_no_clear_content_wrap() -> None:
    """F-ENTRY-01/02: mount-once slots; paint не очищает contentWrap."""
    source = _read(ENTRY_SCREEN_JS)
    paint_body = _extract_function_body(source, "function paint()")
    assert paint_body is not None
    assert "mountLayoutOnce" in paint_body
    assert "clearElement(contentWrap)" not in paint_body
    assert "listRefreshing" in source
    assert "detailRefreshing" in source


def test_entry_pages_save_gates_offline() -> None:
    """Offline blocks draft save, publication toggle, and self-check before API calls."""
    source = _read(ENTRY_SCREEN_JS)
    can_save_body = _extract_function_body(source, "function canSaveDraft()")
    save_body = _extract_function_body(source, "async function handleSave()")
    publish_body = _extract_function_body(source, "async function handlePublicationToggle(")
    self_check_body = _extract_function_body(source, "async function handleSelfCheck()")
    assert can_save_body is not None
    assert save_body is not None
    assert publish_body is not None
    assert self_check_body is not None
    assert can_save_body.find("offline") < can_save_body.find("draftDirty")
    assert re.search(r"if \([^)]*\|\|\s*offline\b", save_body)
    assert save_body.find("offline") < save_body.find("saveEntryPageDraft(")
    assert re.search(r"if \([^)]*\|\|\s*offline\b", publish_body)
    assert publish_body.find("offline") < publish_body.find("publishEntryPage(")
    assert "disabled: publishing || offline || !publication.hasDraft" in source
    assert re.search(r"if \([^)]*\|\|\s*offline\b", self_check_body)
    assert self_check_body.find("offline") < self_check_body.find("selfCheckEntryPage(")


def test_entry_pages_soft_detail_refresh_skips_cold_skeleton(tmp_path: Path) -> None:
    """После save soft-refresh не ставит detailLoading skeleton при смонтированном редакторе."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="soft-save-refresh",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages') && !urlStr.includes('/entry-pages/')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
          has_draft: true, published: false, current_revision_id: 'rg1',
          published_revision_id: null, public_path: '/p/g',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
        has_draft: true, published: false, current_revision_id: 'rg1',
        published_revision_id: null, public_path: '/p/g',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  if (method === 'PUT' && urlStr.includes('/entry-pages/guest-1/draft')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ page_id: 'guest-1', current_revision_id: 'rg1' }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
await new Promise((resolve) => setTimeout(resolve, 400));
const titleInput = document.getElementById('hub-entry-pages-title');
dom.simulateInput(titleInput, 'Изменённый заголовок');
const saveBtn = document.getElementById('hub-entry-pages-save-btn');
saveBtn.disabled = false;
saveBtn.click();
await new Promise((resolve) => setTimeout(resolve, 500));
const editorStillMounted = document.getElementById('hub-entry-pages-title') !== null;
const stateSkeleton = container.querySelector('.hub-entry-pages__state-slot .hub-skeleton');
const editorValue = document.getElementById('hub-entry-pages-title')?.value ?? null;
console.log(JSON.stringify({
  editorStillMounted,
  stateSkeletonPresent: !!stateSkeleton,
  editorValue,
}));
""",
    )
    assert result["editorStillMounted"] is True
    assert result["stateSkeletonPresent"] is False
    assert result["editorValue"] == "Изменённый заголовок"


def test_entry_pages_editor_signature_includes_field_kind_and_role_digest() -> None:
    """F-1: editorSignature учитывает kind/order полей и роли, не только length."""
    source = _read(ENTRY_SCREEN_JS)
    paint_body = _extract_function_body(source, "function paint()")
    assert paint_body is not None
    sig_start = paint_body.find("const editorSignature")
    sig_end = paint_body.find("if (editorSignature !== lastEditorSignature", sig_start)
    assert sig_start != -1 and sig_end != -1
    sig_block = paint_body[sig_start:sig_end]
    assert "editorFieldsDigest()" in sig_block
    assert "editorRolesDigest()" in sig_block
    assert "fields.length" not in sig_block
    assert "roles.length" not in sig_block
    assert "field.kind" in source


def test_entry_pages_should_render_editor_keeps_mounted_on_soft_errors() -> None:
    """F-2: soft list/detail error не снимает редактор при editorMounted()."""
    source = _read(ENTRY_SCREEN_JS)
    body = _extract_function_body(source, "function shouldRenderEditor()")
    assert body is not None
    assert "editorMounted()" in body
    normalized = body.replace(" ", "")
    assert "listError&&!mounted" in normalized
    assert "detailError&&!mounted" in normalized
    refresh_body = _extract_function_body(source, "function renderRefreshSlot()")
    assert refresh_body is not None
    assert "softListError" in refresh_body or "listError && editorMounted()" in refresh_body


def test_entry_pages_soft_detail_error_keeps_editor_mounted(tmp_path: Path) -> None:
    """F-2 (mount): ошибка soft detail refresh не очищает layoutMain."""
    guest_doc = json.dumps(GUEST_DOCUMENT, ensure_ascii=False)
    result = _run_entry_screen_mount(
        tmp_path,
        label="soft-detail-error",
        fetch_impl=f"""
  const urlStr = String(url);
  const method = init.method ?? 'GET';
  if (method === 'GET' && urlStr.endsWith('/entry-pages') && !urlStr.includes('/entry-pages/')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        items: [{{
          page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
          has_draft: true, published: false, current_revision_id: 'rg1',
          published_revision_id: null, public_path: '/p/g',
        }}],
      }}),
    }};
  }}
  if (method === 'GET' && urlStr.includes('/entry-pages/guest-1')) {{
    globalThis.__entryDetailCalls = (globalThis.__entryDetailCalls ?? 0) + 1;
    if (globalThis.__entryDetailCalls > 1) {{
      return {{
        ok: false, status: 503,
        headers: {{ get: () => 'application/json' }},
        json: async () => ({{ detail: 'detail refresh failed' }}),
      }};
    }}
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{
        page_id: 'guest-1', audience: 'guest', slug: 'g', title: 'Guest',
        has_draft: true, published: false, current_revision_id: 'rg1',
        published_revision_id: null, public_path: '/p/g',
        draft_document: {guest_doc}, published_document: null,
      }}),
    }};
  }}
  if (method === 'PUT' && urlStr.includes('/entry-pages/guest-1/draft')) {{
    return {{
      ok: true, status: 200,
      headers: {{ get: () => 'application/json' }},
      json: async () => ({{ page_id: 'guest-1', current_revision_id: 'rg1' }}),
    }};
  }}
  throw new Error(`unexpected fetch: ${{method}} ${{urlStr}}`);
""",
        extra_script="""
globalThis.__entryDetailCalls = 0;
await new Promise((resolve) => setTimeout(resolve, 400));
const titleInput = document.getElementById('hub-entry-pages-title');
dom.simulateInput(titleInput, 'Сохранённый текст');
const saveBtn = document.getElementById('hub-entry-pages-save-btn');
saveBtn.disabled = false;
saveBtn.click();
await new Promise((resolve) => setTimeout(resolve, 600));
const editorStillMounted = document.getElementById('hub-entry-pages-title') !== null;
const layoutMain = container.querySelector('.hub-entry-pages__layout-main');
const layoutMainEmpty = !layoutMain || layoutMain.children.length === 0;
const refreshSlot = container.querySelector('.hub-entry-pages__refresh-slot');
console.log(JSON.stringify({
  editorStillMounted,
  layoutMainEmpty,
  refreshHasContent: !!(refreshSlot && refreshSlot.children.length > 0),
  editorValue: document.getElementById('hub-entry-pages-title')?.value ?? null,
  detailCalls: globalThis.__entryDetailCalls ?? 0,
}));
""",
    )
    assert result["editorStillMounted"] is True
    assert result["layoutMainEmpty"] is False
    assert result["detailCalls"] >= 2
    assert result["refreshHasContent"] is True
    assert result["editorValue"] == "Сохранённый текст"


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


def test_entry_pages_connectivity_offline_aborts_inflight_controllers() -> None:
    """hub-offline-abort-followups: offline aborts save/publish/selfCheck and clears busy flags."""
    source = _read(ENTRY_SCREEN_JS)
    callback = _extract_subscribe_connectivity_callback(source)
    offline_arm_start = callback.find("if (!online)")
    assert offline_arm_start != -1
    offline_arm = callback[offline_arm_start:]
    paint_idx = offline_arm.find("paint()")
    offline_block = offline_arm[:paint_idx]
    assert "saveAbort?.abort()" in offline_block
    assert "publishAbort?.abort()" in offline_block
    assert "selfCheckAbort?.abort()" in offline_block
    assert "saving = false" in offline_block
    assert "publishing = false" in offline_block
    assert "selfChecking = false" in offline_block


def test_entry_pages_save_publish_skip_success_on_abort_or_offline() -> None:
    """overview-entry-abort-residuals: save/publish skip toast, baseline, loadList when offline/aborted."""
    source = _read(ENTRY_SCREEN_JS)
    save_body = _extract_function_body(source, "async function handleSave()")
    publish_body = _extract_function_body(source, "async function handlePublicationToggle(")
    assert save_body is not None
    assert publish_body is not None
    save_after_await = save_body.split("await saveEntryPageDraft(", 1)[1]
    save_guard = save_after_await.split("savedBaseline", 1)[0]
    assert "offline || saveAbort.signal.aborted" in save_guard
    assert "return" in save_guard
    assert "showToast" not in save_guard
    assert "loadList" not in save_guard
    publish_guard_start = publish_body.find("if (offline || publishAbort.signal.aborted)")
    assert publish_guard_start != -1
    publish_guard = publish_body[publish_guard_start : publish_guard_start + 120]
    assert "return" in publish_guard
    load_idx = publish_body.find("await loadList({ soft: true })")
    guard_idx = publish_body.find("if (offline || publishAbort.signal.aborted)")
    assert guard_idx != -1 and load_idx != -1 and guard_idx < load_idx
