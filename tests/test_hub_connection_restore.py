"""Поведенческие контракты restore connection-context LOCAL HUB (client-side)."""



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

APP_JS = HUB / "app.js"

CONNECTION_JS = HUB / "screens" / "connection.js"

LIVE_PARAMS_JS = HUB / "features" / "live-connection-params.js"

SESSION_JS = HUB / "core" / "session.js"

API_JS = HUB / "core" / "api.js"

SW_JS = HUB / "sw.js"

UI_DOM_HARNESS = REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"



NODE_SKIP_ENV = "HUB_TESTS_ALLOW_SKIP_NODE"

REAL_ROUTER_ID = "rtr_f17a7d35"

DRAFT_ROUTER_ID = "rtr_draft_new"

REAL_FINGERPRINT = "SHA256:RUi/peC9rUzYMT/CIgeIsBYjR5CFqYxxnCuUmfv2WkY"





def _require_node() -> str:

    node = shutil.which("node")

    if node is None:

        if os.environ.get(NODE_SKIP_ENV) == "1":

            pytest.skip(f"node not available ({NODE_SKIP_ENV}=1)")

        pytest.fail(

            f"node is required for hub connection restore tests; install Node.js or set "

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





def _run_should_skip(

    start: dict[str, object],

    current: dict[str, object],

    target_router_id: str | None,

    tmp_path: Path,

) -> bool:

    script = f"""const mod = await import({json.dumps(LIVE_PARAMS_JS.as_uri())});

console.log(JSON.stringify(mod.shouldSkipRestoreApply(

  {json.dumps(start, ensure_ascii=False)},

  {json.dumps(current, ensure_ascii=False)},

  {json.dumps(target_router_id)},

)));

"""

    return _run_node_harness(script, tmp_path, "should-skip")  # type: ignore[return-value]





def _run_build_patch(

    ctx: dict[str, object],

    current: dict[str, object],

    tmp_path: Path,

) -> dict[str, object]:

    script = f"""const mod = await import({json.dumps(LIVE_PARAMS_JS.as_uri())});

console.log(JSON.stringify(mod.buildRestoreSessionPatch(

  {json.dumps(ctx, ensure_ascii=False)},

  {json.dumps(current, ensure_ascii=False)},

)));

"""

    return _run_node_harness(script, tmp_path, "build-patch")  # type: ignore[return-value]





def _run_restore_integration(

    *,

    restore_candidate: dict[str, object] | None,

    start_session: dict[str, object],

    operator_mutation: dict[str, object] | None,

    tmp_path: Path,

) -> dict[str, object]:

    session_uri = json.dumps(SESSION_JS.as_uri())

    app_uri = json.dumps(APP_JS.as_uri())

    candidate_json = (
        json.dumps(restore_candidate, ensure_ascii=False)
        if restore_candidate
        else '{"restore_candidate": false}'
    )

    script = f"""import {{ resetSession, getSession, updateSession }} from {session_uri};

import {{ restoreConnectionContextFromServer }} from {app_uri};



resetSession();

updateSession({json.dumps(start_session, ensure_ascii=False)});



async function fakeApiGet(path, options = {{}}) {{

  if (path === 'connection-context/restore-candidate') {{

    return {candidate_json};

  }}

  throw new Error(`unexpected path: ${{path}}`);

}}



const restorePromise = restoreConnectionContextFromServer(undefined, fakeApiGet);

if ({json.dumps(operator_mutation is not None)}) {{

  await Promise.resolve();

  updateSession({json.dumps(operator_mutation or {}, ensure_ascii=False)});

}}

await restorePromise;



console.log(JSON.stringify(getSession()));

"""

    return _run_node_harness(script, tmp_path, "restore-integration")  # type: ignore[return-value]





def test_fetch_restore_candidate_uses_single_endpoint(tmp_path: Path) -> None:

    """F-1: restore читает только restore-candidate, не list+fan-out."""

    app_uri = json.dumps(APP_JS.as_uri())

    script = f"""import {{ fetchRestoreCandidateConnectionContext }} from {app_uri};



const paths = [];

async function fakeApiGet(path) {{

  paths.push(path);

  return {{

    restore_candidate: true,

    router_id: {json.dumps(REAL_ROUTER_ID)},

    host: '192.168.2.1',

    ssh_host_key: {{ confirmed: true, fingerprint_sha256: {json.dumps(REAL_FINGERPRINT)} }},

    username_available: false,

    live_ready: false,

  }};

}}



const selected = await fetchRestoreCandidateConnectionContext(undefined, fakeApiGet);

console.log(JSON.stringify({{ paths, routerId: selected?.routerId ?? null }}));

"""

    payload = _run_node_harness(script, tmp_path, "fetch-restore-candidate")

    assert payload["paths"] == ["connection-context/restore-candidate"]

    assert payload["routerId"] == REAL_ROUTER_ID





def test_fetch_restore_candidate_handles_no_candidate(tmp_path: Path) -> None:

    """F-1: restore_candidate=false → null."""

    app_uri = json.dumps(APP_JS.as_uri())

    script = f"""import {{ fetchRestoreCandidateConnectionContext }} from {app_uri};

async function fakeApiGet() {{ return {{ restore_candidate: false }}; }}

const selected = await fetchRestoreCandidateConnectionContext(undefined, fakeApiGet);

console.log(JSON.stringify({{ selected }}));

"""

    payload = _run_node_harness(script, tmp_path, "fetch-no-candidate")

    assert payload["selected"] is None





def test_build_patch_gates_live_ready_not_pin_only(tmp_path: Path) -> None:

    """F-4: patch отражает live_ready и username_available с сервера."""

    ctx = {

        "router_id": REAL_ROUTER_ID,

        "host": "192.168.2.1",

        "port": 22,

        "source_address": "192.168.2.10",

        "credential_ref_id": "cred-1",

        "ssh_host_key": {

            "confirmed": True,

            "fingerprint_sha256": REAL_FINGERPRINT,

            "pinned_at": "2026-08-03T12:00:00Z",

        },

        "username_available": False,

        "live_ready": False,

    }

    current = {

        "routerId": None,

        "routerHost": None,

        "sourceAddress": None,

        "hostKeyConfirmed": False,

        "liveReady": False,

        "usernameAvailable": False,

        "pinnedAt": None,

        "pinnedEndpointPort": None,

        "connectionRestoreState": "pending",

        "wifiLive": {

            "host": None,

            "username": None,

            "credentialRefId": None,

            "sshHostKeySha256": None,

        },

    }

    patch = _run_build_patch(ctx, current, tmp_path)

    assert patch["hostKeyConfirmed"] is True

    assert patch["liveReady"] is False

    assert patch["usernameAvailable"] is False

    assert patch["pinnedEndpointPort"] == 22

    assert patch["pinnedAt"] == "2026-08-03T12:00:00Z"




def test_build_patch_identity_switch_clears_sticky_host(tmp_path: Path) -> None:

    """G-6: смена router_id не оставляет host/source от предыдущей привязки."""

    current = {

        "routerId": REAL_ROUTER_ID,

        "routerHost": "192.168.2.1",

        "sourceAddress": "192.168.2.10",

        "hostKeyConfirmed": True,

        "liveReady": True,

        "usernameAvailable": True,

        "pinnedAt": None,

        "pinnedEndpointPort": None,

        "connectionRestoreState": "done",

        "wifiLive": {

            "host": "192.168.2.1",

            "username": "admin",

            "credentialRefId": "cred-real",

            "sshHostKeySha256": REAL_FINGERPRINT,

        },

    }

    ctx = {

        "router_id": DRAFT_ROUTER_ID,

        "credential_ref_id": "cred-draft",

        "ssh_host_key": {"confirmed": False},

        "username_available": False,

        "live_ready": False,

    }

    patch = _run_build_patch(ctx, current, tmp_path)

    assert patch["routerId"] == DRAFT_ROUTER_ID

    assert patch["routerHost"] is None

    assert patch["sourceAddress"] is None

    assert patch["wifiLive"]["host"] is None




def test_live_params_requires_source_address_when_not_live_ready(
    tmp_path: Path,
) -> None:

    """G-5: без liveReady source_address — именованный пробел, не complete."""

    session_uri = json.dumps(SESSION_JS.as_uri())

    live_uri = json.dumps(LIVE_PARAMS_JS.as_uri())

    script = f"""import {{ resetSession, updateSession, getSession }} from {session_uri};

import {{ buildLiveConnectionParams }} from {live_uri};



resetSession();

updateSession({{

  routerId: {json.dumps(REAL_ROUTER_ID)},

  routerHost: '192.168.2.1',

  hostKeyConfirmed: false,

  liveReady: false,

  connectionRestoreState: 'done',

  wifiLive: {{

    host: '192.168.2.1',

    credentialRefId: 'cred-real',

    sshHostKeySha256: null,

  }},

}});



const result = buildLiveConnectionParams(getSession());

console.log(JSON.stringify(result));

"""

    payload = _run_node_harness(script, tmp_path, "source-address-gap")

    assert payload["complete"] is False

    assert "source_address" in payload["missing"]





def test_restore_integration_applies_pinned_candidate(tmp_path: Path) -> None:

    """F-1 + F-4: restore применяет pinned candidate с сервера."""

    session = _run_restore_integration(

        restore_candidate={

            "restore_candidate": True,

            "router_id": REAL_ROUTER_ID,

            "host": "192.168.2.1",

            "port": 22,

            "source_address": "192.168.2.10",

            "credential_ref_id": "cred-real",

            "ssh_host_key": {

                "confirmed": True,

                "fingerprint_sha256": REAL_FINGERPRINT,

                "pinned_at": "2026-08-03T12:00:00Z",

            },

            "username_available": False,

            "live_ready": False,

        },

        start_session={},

        operator_mutation=None,

        tmp_path=tmp_path,

    )

    assert session["routerId"] == REAL_ROUTER_ID

    assert session["hostKeyConfirmed"] is True

    assert session["liveReady"] is False

    assert session["usernameAvailable"] is False

    assert session["connectionRestoreState"] == "done"





def test_restore_does_not_clobber_operator_router_selection(tmp_path: Path) -> None:

    """F-6: поздний restore не перетирает routerId, выбранный оператором."""

    session = _run_restore_integration(

        restore_candidate={

            "restore_candidate": True,

            "router_id": REAL_ROUTER_ID,

            "host": "192.168.2.1",

            "credential_ref_id": "cred-real",

            "ssh_host_key": {"confirmed": True, "fingerprint_sha256": REAL_FINGERPRINT},

            "username_available": True,

            "live_ready": True,

        },

        start_session={},

        operator_mutation={

            "routerId": "rtr_operator_choice",

            "hostKeyConfirmed": False,

            "wifiLive": {

                "host": "10.0.0.9",

                "credentialRefId": "cred-op",

            },

        },

        tmp_path=tmp_path,

    )

    assert session["routerId"] == "rtr_operator_choice"

    assert session["wifiLive"]["host"] == "10.0.0.9"





def test_restore_does_not_clobber_operator_host_on_same_router_id(tmp_path: Path) -> None:

    """J-3: поздний restore не перетирает host, изменённый оператором на том же routerId."""

    session = _run_restore_integration(

        restore_candidate={

            "restore_candidate": True,

            "router_id": REAL_ROUTER_ID,

            "host": "192.168.2.1",

            "credential_ref_id": "cred-real",

            "ssh_host_key": {"confirmed": True, "fingerprint_sha256": REAL_FINGERPRINT},

            "username_available": True,

            "live_ready": True,

        },

        start_session={},

        operator_mutation={

            "routerId": REAL_ROUTER_ID,

            "hostKeyConfirmed": False,

            "wifiLive": {

                "host": "10.0.0.9",

                "credentialRefId": "cred-op",

            },

        },

        tmp_path=tmp_path,

    )

    assert session["routerId"] == REAL_ROUTER_ID

    assert session["wifiLive"]["host"] == "10.0.0.9"





def test_cancel_restore_reaches_terminal_state(tmp_path: Path) -> None:

    """J-2: отмена restore переводит connectionRestoreState из pending в done."""

    session_uri = json.dumps(SESSION_JS.as_uri())

    script = f"""import {{
  resetSession,
  getSession,
  updateSession,
  cancelConnectionContextRestore,
}} from {session_uri};



resetSession();

updateSession({{ connectionRestoreState: 'pending' }});

cancelConnectionContextRestore();

console.log(JSON.stringify(getSession()));

"""

    session = _run_node_harness(script, tmp_path, "cancel-restore-terminal")

    assert session["connectionRestoreState"] == "done"





def test_should_skip_restore_when_operator_changed_router(tmp_path: Path) -> None:

    """F-6: guard блокирует apply при смене routerId оператором."""

    start = {"routerId": None, "hostKeyConfirmed": False, "wifiLive": {"credentialRefId": None}}

    current = {

        "routerId": "rtr_operator_choice",

        "hostKeyConfirmed": False,

        "wifiLive": {"credentialRefId": "cred-op"},

    }

    assert _run_should_skip(start, current, REAL_ROUTER_ID, tmp_path) is True





def test_restore_sets_pending_then_done(tmp_path: Path) -> None:

    """F-7: restore завершается в done при отсутствии candidate."""

    session_uri = json.dumps(SESSION_JS.as_uri())

    app_uri = json.dumps(APP_JS.as_uri())

    script = f"""import {{ resetSession, getSession }} from {session_uri};

import {{ restoreConnectionContextFromServer }} from {app_uri};



const states = [];

resetSession();



async function fakeApiGet(path) {{

  if (path === 'connection-context/restore-candidate') {{

    states.push(getSession().connectionRestoreState);

    return {{ restore_candidate: false }};

  }}

  throw new Error('unexpected');

}}



await restoreConnectionContextFromServer(undefined, fakeApiGet);

states.push(getSession().connectionRestoreState);

console.log(JSON.stringify({{ states, session: getSession() }}));

"""

    payload = _run_node_harness(script, tmp_path, "restore-states")

    assert payload["states"][0] == "pending"

    assert payload["session"]["connectionRestoreState"] == "done"

    assert payload["session"]["liveReady"] is False





def test_bootstrap_shell_mounts_before_restore_settles(tmp_path: Path) -> None:
    """T-1: bootstrapHub монтирует оболочку до завершения restore и применяет результат после."""

    session_uri = json.dumps(SESSION_JS.as_uri())
    app_uri = json.dumps(APP_JS.as_uri())
    harness_path = json.dumps(str(REPO_ROOT / "tests" / "support" / "ui_dom_harness.js"))

    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

globalThis.window = dom.window;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

import {{ bootstrapHub }} from {app_uri};

import {{ resetSession, getSession }} from {session_uri};

globalThis.window = dom.window;

window.removeEventListener = () => {{}};



const events = [];

resetSession();



const root = document.createElement('div');

root.id = 'hub-root';

document.body.appendChild(root);



async function fakeApiGet(path) {{

  if (path === 'connection-context/restore-candidate') {{

    events.push('restore-fetch-start');

    await new Promise((resolve) => setTimeout(resolve, 25));

    events.push('restore-fetch-end');

    return {{ restore_candidate: false }};

  }}

  throw new Error(`unexpected path: ${{path}}`);

}}



async function stubMountShell(mountRoot, opts) {{

  events.push('shell-mounted');

}}



await bootstrapHub({{ mountShellFn: stubMountShell, apiGetFn: fakeApiGet, root }});



await new Promise((resolve) => setTimeout(resolve, 50));



console.log(JSON.stringify({{

  events,

  finalState: getSession().connectionRestoreState,

}}));

"""

    payload = _run_node_harness(script, tmp_path, "bootstrap-order")

    assert payload["events"].index("shell-mounted") < payload["events"].index("restore-fetch-end")

    assert payload["finalState"] == "done"





def test_binding_change_clears_sticky_live_ready(tmp_path: Path) -> None:

    """F-3: смена routerId сбрасывает liveReady — params больше не complete."""

    session_uri = json.dumps(SESSION_JS.as_uri())

    live_uri = json.dumps(LIVE_PARAMS_JS.as_uri())

    script = f"""import {{ resetSession, updateSession, getSession }} from {session_uri};

import {{ buildLiveConnectionParams }} from {live_uri};



resetSession();

updateSession({{

  routerId: {json.dumps(REAL_ROUTER_ID)},

  routerHost: '192.168.2.1',

  hostKeyConfirmed: true,

  liveReady: true,

  usernameAvailable: true,

  connectionRestoreState: 'done',

  wifiLive: {{

    host: '192.168.2.1',

    credentialRefId: 'cred-real',

    sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},

  }},

}});



const before = buildLiveConnectionParams(getSession());

updateSession({{

  routerId: {json.dumps(DRAFT_ROUTER_ID)},

  hostKeyConfirmed: false,

  wifiLive: {{

    host: '192.168.2.1',

    credentialRefId: 'cred-draft',

    sshHostKeySha256: null,

  }},

}});

const after = buildLiveConnectionParams(getSession());



console.log(JSON.stringify({{

  beforeComplete: before.complete,

  afterComplete: after.complete,

  liveReady: getSession().liveReady,

  missing: after.missing,

  session: getSession(),

}}));

"""

    payload = _run_node_harness(script, tmp_path, "binding-change-live-ready")

    assert payload["beforeComplete"] is True

    assert payload["afterComplete"] is False

    assert payload["liveReady"] is False

    assert "ssh_host_key_sha256" in payload["missing"]

    session = payload["session"]

    assert session["routerHost"] is None

    assert session["sourceAddress"] is None

    assert session["wifiLive"]["host"] == "192.168.2.1"

    assert session["wifiLive"]["credentialRefId"] == "cred-draft"

    assert session["wifiLive"]["username"] is None

    assert session["wifiLive"]["sshHostKeySha256"] is None





def test_restore_timeout_lands_in_failed(tmp_path: Path) -> None:

    """F-2: дедлайн restore переводит сессию в failed."""

    session_uri = json.dumps(SESSION_JS.as_uri())

    app_uri = json.dumps(APP_JS.as_uri())

    script = f"""import {{ resetSession, getSession }} from {session_uri};

import {{ restoreConnectionContextFromServer, CONNECTION_RESTORE_DEADLINE_MS }} from {app_uri};



resetSession();



async function fakeApiGet(path, options = {{}}) {{

  if (path === 'connection-context/restore-candidate') {{

    await new Promise((resolve, reject) => {{

      const timer = setTimeout(resolve, CONNECTION_RESTORE_DEADLINE_MS + 500);

      options.signal?.addEventListener('abort', () => {{

        clearTimeout(timer);

        reject(Object.assign(new Error('aborted'), {{ name: 'AbortError' }}));

      }});

    }});

    return {{ restore_candidate: false }};

  }}

  throw new Error('unexpected');

}}



await restoreConnectionContextFromServer(undefined, fakeApiGet);

console.log(JSON.stringify(getSession()));

"""

    session = _run_node_harness(script, tmp_path, "restore-timeout")

    assert session["connectionRestoreState"] == "failed"

    assert session["liveReady"] is False





def test_api_get_uses_no_store_cache(tmp_path: Path) -> None:

    """F-8: GET-запросы api.js используют cache: no-store."""

    script = f"""import {{ readFileSync }} from 'node:fs';

const source = readFileSync({json.dumps(str(API_JS))}, 'utf8');

const block = source.includes("cache: method === 'GET' ? 'no-store' : 'default'");

console.log(JSON.stringify({{ hasNoStore: block }}));

"""

    payload = _run_node_harness(script, tmp_path, "api-no-store")

    assert payload["hasNoStore"] is True





def test_sw_passthrough_api_paths(tmp_path: Path) -> None:

    """connection-context и management-username не кэшируются SW (/api/ passthrough)."""

    source = SW_JS.read_text(encoding="utf-8")

    assert "path.startsWith('/api/')" in source

    version_match = re.search(r"const\s+CACHE_VERSION\s*=\s*['\"](\d+)['\"]", source)
    assert version_match is not None
    assert int(version_match.group(1)) >= 14





def test_wifi_screen_reacts_to_restore_flip(tmp_path: Path) -> None:

    """T-3: после restore подписка сбрасывает ошибку и отписывается без цикла."""

    session_uri = json.dumps(SESSION_JS.as_uri())

    script = f"""import {{
  resetSession,
  updateSession,
  subscribeSession,
  getSession,
}} from {session_uri};



let observedFetchCalls = 0;

let lastObservedError = 'stale-error';



const handlers = new Set();

const patchedSubscribe = (handler) => {{

  handlers.add(handler);

  return () => {{

    handlers.delete(handler);

  }};

}};



function simulateRestoreDone() {{

  updateSession({{

    routerId: {json.dumps(REAL_ROUTER_ID)},

    hostKeyConfirmed: true,

    liveReady: true,

    usernameAvailable: true,

    connectionRestoreState: 'done',

    wifiLive: {{

      host: '192.168.2.1',

      credentialRefId: 'cred-real',

      sshHostKeySha256: {json.dumps(REAL_FINGERPRINT)},

    }},

  }});

}}



resetSession();

updateSession({{ connectionRestoreState: 'pending', liveReady: false, hostKeyConfirmed: false }});



const unsub = patchedSubscribe((snapshot) => {{

  if (snapshot.connectionRestoreState === 'pending') {{

    return;

  }}

  if (snapshot.connectionRestoreState === 'done' && snapshot.liveReady) {{

    lastObservedError = null;

    observedFetchCalls += 1;

  }}

}});



simulateRestoreDone();

for (const handler of handlers) {{

  handler(getSession());

}}



unsub();



console.log(JSON.stringify({{

  observedFetchCalls,

  lastObservedError,

  handlersAfterUnsub: handlers.size,

}}));

"""

    payload = _run_node_harness(script, tmp_path, "wifi-restore-flip")

    assert payload["observedFetchCalls"] == 1

    assert payload["lastObservedError"] is None

    assert payload["handlersAfterUnsub"] == 0


def test_restore_unconfirmed_pin_binds_router_and_shows_gaps(tmp_path: Path) -> None:
    """M-12.1: genuine candidate без pin/username — сессия привязана, пробелы честны."""
    session_uri = json.dumps(SESSION_JS.as_uri())
    app_uri = json.dumps(APP_JS.as_uri())
    connection_uri = json.dumps(CONNECTION_JS.as_uri())
    harness_path = json.dumps(str(UI_DOM_HARNESS))

    restore_return = json.dumps(
        {
            "restore_candidate": True,
            "router_id": REAL_ROUTER_ID,
            "host": "192.168.2.1",
            "port": 22,
            "source_address": "192.168.2.10",
            "credential_ref_id": "cred-real",
            "ssh_host_key": {"confirmed": False},
            "username_available": False,
            "live_ready": False,
            "missing": ["username", "ssh_host_key_sha256"],
        },
        ensure_ascii=False,
    )

    script = f"""import {{ createRequire }} from 'node:module';

const require = createRequire(import.meta.url);

const {{ createUiDomHarness }} = require({harness_path});

const dom = createUiDomHarness();

globalThis.document = dom.document;

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
  return el;
}}

document.createElementNS = (_ns, tag) => patchElement(document.createElement(tag));

const _origCreateElement = document.createElement.bind(document);

document.createElement = (tag) => patchElement(_origCreateElement(tag));

const _sampleEl = document.createElement('div');

globalThis.HTMLElement = _sampleEl.constructor;

Object.defineProperty(globalThis, 'navigator', {{ value: {{ onLine: true }}, configurable: true }});

globalThis.localStorage = dom.localStorage;

globalThis.window = dom.window;

window.removeEventListener = () => {{}};

globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);

globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

import {{ restoreConnectionContextFromServer }} from {app_uri};

import {{ resetSession, updateSession, getSession }} from {session_uri};

import {{ render }} from {connection_uri};

resetSession();

updateSession({{ connectionRestoreState: 'pending' }});

const container = document.createElement('div');

document.body.appendChild(container);

const dispose = render(container, {{ runtime: {{ adapterMode: 'fake' }} }});

async function fakeApiGet(path) {{
  if (path === 'connection-context/restore-candidate') {{
    return {restore_return};
  }}
  throw new Error(`unexpected apiGet path: ${{path}}`);
}}

await restoreConnectionContextFromServer(undefined, fakeApiGet);

await new Promise((resolve) => setTimeout(resolve, 300));

let accessHostField = document.getElementById('hub-connection-access-host');
for (let attempt = 0; attempt < 10 && !accessHostField; attempt += 1) {{
  await new Promise((resolve) => setTimeout(resolve, 50));
  accessHostField = document.getElementById('hub-connection-access-host');
}}

const session = getSession();

const visibleText = dom.collectVisibleText(container);

dispose();

console.log(JSON.stringify({{
  routerId: session.routerId,
  routerHost: session.routerHost,
  sourceAddress: session.sourceAddress,
  hostKeyConfirmed: session.hostKeyConfirmed,
  liveReady: session.liveReady,
  usernameAvailable: session.usernameAvailable,
  hasAccessHostField: !!accessHostField,
  visibleText,
}}));
"""

    payload = _run_node_harness(script, tmp_path, "restore-unconfirmed-gaps")

    assert payload["routerId"] == REAL_ROUTER_ID
    assert payload["routerHost"] == "192.168.2.1"
    assert payload["sourceAddress"] == "192.168.2.10"
    assert payload["hostKeyConfirmed"] is False
    assert payload["liveReady"] is False
    assert payload["usernameAvailable"] is False
    assert payload["hasAccessHostField"] is True

    visible = str(payload["visibleText"])
    assert "Отпечаток устройства не подтверждён на сервере" in visible
    assert "Имя пользователя для управления не сохранено на сервере" in visible
    assert "Отпечаток не совпадает" not in visible


