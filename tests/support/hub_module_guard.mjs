/**
 * Layer 1 — runtime import + mount guard for LOCAL HUB ESM modules.
 *
 * Imports every shipped *.js under a hub root (skips features/_adv_mut_work scratch copies),
 * then mounts every module that exports both meta and render under a DOM stub.
 *
 * Limitations (honest contract):
 * - Only exercises code paths reached during synchronous mount + async settle windows.
 * - Unreachable branches and non-hub imports are out of scope (Layer 2 in Python).
 * - ReferenceError and other rejections swallowed inside `.catch(() => {})` (or similar)
 *   are invisible here; Layer 2 is the net for code paths the mount never reaches.
 */

import { createRequire } from 'node:module';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const SKIP_DIR_NAMES = new Set(['_adv_mut_work']);
const SETTLE_MS = 400;
const FINAL_DRAIN_MS = 400;
const FETCH_TIMEOUT_MS = 5000;

const require = createRequire(import.meta.url);
const { createUiDomHarness } = require('./ui_dom_harness.js');

/**
 * @param {string} hubRoot
 * @returns {string[]}
 */
function collectHubJsFiles(hubRoot) {
  /** @type {string[]} */
  const files = [];

  /** @param {string} dir */
  function walk(dir) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (SKIP_DIR_NAMES.has(entry.name)) {
          continue;
        }
        walk(path.join(dir, entry.name));
        continue;
      }
      if (entry.isFile() && entry.name.endsWith('.js')) {
        files.push(path.join(dir, entry.name));
      }
    }
  }

  walk(hubRoot);
  return files.sort();
}

/**
 * @param {ReturnType<typeof createUiDomHarness>} dom
 */
function installGlobals(dom) {
  globalThis.addEventListener = () => {};
  globalThis.removeEventListener = () => {};
  globalThis.self = globalThis;
  globalThis.document = dom.document;
  globalThis.localStorage = dom.localStorage;

  function patchElement(el) {
    if (!el.prepend) {
      el.prepend = (...nodes) => {
        for (let i = nodes.length - 1; i >= 0; i -= 1) {
          const node = nodes[i];
          if (el.children && el.children.length > 0) {
            el.children.unshift(node);
            node.parentNode = el;
          } else {
            el.appendChild(node);
          }
        }
      };
    }
    if (!el.insertBefore) {
      el.insertBefore = (node, reference) => {
        if (!node) {
          return node;
        }
        if (node.parentNode && node.parentNode.children) {
          const existingIdx = node.parentNode.children.indexOf(node);
          if (existingIdx >= 0) {
            node.parentNode.children.splice(existingIdx, 1);
          }
        }
        if (reference == null) {
          return el.appendChild(node);
        }
        const refIdx = el.children.indexOf(reference);
        if (refIdx < 0) {
          // Match real DOM: throw rather than silently corrupt the tree.
          throw new DOMException(
            'The node before which the new node is to be inserted is not a child of this node.',
            'NotFoundError',
          );
        }
        el.children.splice(refIdx, 0, node);
        node.parentNode = el;
        return node;
      };
    }
    if (!el.replaceWith) {
      el.replaceWith = (...nodes) => {
        const parent = el.parentNode;
        if (!parent) {
          return;
        }
        const idx = parent.children.indexOf(el);
        parent.removeChild(el);
        let insertAt = idx;
        for (const node of nodes) {
          if (!node) {
            continue;
          }
          if (insertAt >= parent.children.length) {
            parent.appendChild(node);
          } else {
            parent.insertBefore(node, parent.children[insertAt]);
          }
          insertAt += 1;
        }
      };
    }
    if (!el.insertAdjacentElement) {
      el.insertAdjacentElement = (position, element) => {
        if (!element) {
          return null;
        }
        const parent = el.parentNode;
        switch (position) {
          case 'beforebegin':
            if (!parent) {
              return element;
            }
            parent.insertBefore(element, el);
            break;
          case 'afterbegin':
            el.insertBefore(element, el.firstChild);
            break;
          case 'beforeend':
            el.appendChild(element);
            break;
          case 'afterend': {
            if (!parent) {
              return element;
            }
            const idx = parent.children.indexOf(el);
            const next = idx >= 0 ? parent.children[idx + 1] ?? null : null;
            parent.insertBefore(element, next);
            break;
          }
          default:
            throw new DOMException(`Invalid insertion position "${position}".`, 'SyntaxError');
        }
        return element;
      };
    }
    if (!Object.getOwnPropertyDescriptor(el, 'id')) {
      Object.defineProperty(el, 'id', {
        get() {
          return this.attributes.id || '';
        },
        set(v) {
          this.setAttribute('id', String(v));
        },
        configurable: true,
      });
    }
    if (!el.hasChildNodes) {
      el.hasChildNodes = () => (el.children?.length ?? 0) > 0;
    }
    if (!el.contains) {
      el.contains = (target) => {
        if (!target) {
          return false;
        }
        let node = target;
        while (node) {
          if (node === el) {
            return true;
          }
          node = node.parentNode;
        }
        return false;
      };
    }
    return el;
  }

  const origCreateElement = dom.document.createElement.bind(dom.document);
  dom.document.createElement = (tag) => patchElement(origCreateElement(tag));
  dom.document.createElementNS = (_ns, tag) => patchElement(origCreateElement(tag));
  dom.document.createTextNode = (text) => {
    const node = patchElement(origCreateElement('span'));
    node.textContent = String(text ?? '');
    return node;
  };
  dom.document.addEventListener = () => {};
  dom.document.removeEventListener = () => {};

  const sampleDiv = dom.document.createElement('div');
  const sampleBtn = dom.document.createElement('button');
  const sampleInput = dom.document.createElement('input');
  const sampleSelect = dom.document.createElement('select');
  const sampleTextarea = dom.document.createElement('textarea');

  globalThis.HTMLElement = sampleDiv.constructor;
  globalThis.HTMLButtonElement = sampleBtn.constructor;
  globalThis.HTMLInputElement = sampleInput.constructor;
  globalThis.HTMLSelectElement = sampleSelect.constructor;
  globalThis.HTMLTextAreaElement = sampleTextarea.constructor;

  Object.defineProperty(globalThis, 'navigator', {
    value: { onLine: true },
    configurable: true,
  });

  globalThis.window = {
    ...dom.window,
    localStorage: dom.localStorage,
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() {
      return true;
    },
    matchMedia() {
      return { matches: false, addEventListener() {}, removeEventListener() {} };
    },
    getComputedStyle() {
      return {};
    },
  };

  globalThis.requestAnimationFrame = (fn) => setTimeout(fn, 0);
  globalThis.cancelAnimationFrame = (id) => clearTimeout(id);

  if (typeof globalThis.crypto?.randomUUID !== 'function') {
    Object.defineProperty(globalThis, 'crypto', {
      value: {
        randomUUID: () => '00000000-0000-4000-8000-000000000001',
      },
      configurable: true,
    });
  }

  globalThis.fetch = async (url, init = {}) => {
    const urlStr = String(url);
    if (urlStr.includes('192.168.2.1')) {
      throw new Error(`forbidden fetch target: ${urlStr}`);
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    if (init.signal) {
      if (init.signal.aborted) {
        clearTimeout(timer);
        throw init.signal.reason ?? new DOMException('Aborted', 'AbortError');
      }
      init.signal.addEventListener('abort', () => controller.abort(), { once: true });
    }

    await new Promise((resolve, reject) => {
      const onAbort = () => {
        clearTimeout(timer);
        reject(init.signal?.reason ?? new DOMException('Aborted', 'AbortError'));
      };
      controller.signal.addEventListener('abort', onAbort, { once: true });
      setTimeout(() => {
        controller.signal.removeEventListener('abort', onAbort);
        clearTimeout(timer);
        resolve(undefined);
      }, 0);
    });

    /** @type {Record<string, unknown>} */
    let body = { ok: true };
    if (urlStr.includes('wifi/observed-state')) {
      body = {
        access_points: [
          {
            ap_id: 'WifiMaster0/AccessPoint4',
            readable: true,
            ssid: 'Guard-Test',
            enabled_or_up: true,
            link_up: true,
            wpa_mode: 'WPA2',
            key_configured: true,
          },
        ],
      };
    } else if (urlStr.includes('routers')) {
      body = { routers: [] };
    } else if (urlStr.includes('vpn-profiles/parse-preview')) {
      body = { valid: true, profile: {} };
    } else if (urlStr.includes('vpn-profiles/')) {
      body = { id: 'vpn-guard-1', name: 'Guard profile', status: 'disconnected' };
    } else if (urlStr.includes('vpn-profiles')) {
      body = { profiles: [] };
    } else if (urlStr.includes('event-presets/') && urlStr.includes('/revisions/')) {
      body = { id: 'rev-1', html: '<p>test</p>' };
    } else if (urlStr.includes('event-presets/')) {
      body = { id: 'preset-1', name: 'Preset', latest_revision_id: 'rev-1' };
    } else if (urlStr.includes('sites/') && urlStr.includes('event-presets')) {
      body = { presets: [] };
    } else if (urlStr.includes('keendns/status')) {
      body = { bookings: [], domains: [] };
    } else if (urlStr.includes('keendns/preview')) {
      body = { actions: [] };
    } else if (urlStr.includes('keendns/apply')) {
      body = { overall: 'applied' };
    } else if (urlStr.includes('wireguard/observe')) {
      body = { interfaces: [] };
    } else if (urlStr.includes('wireguard/')) {
      body = { overall: 'applied', on_air_verification_status: 'on_air_verified', errors: [] };
    } else if (urlStr.includes('connection-context/restore-candidate')) {
      body = { restore_candidate: false };
    } else if (urlStr.includes('lab/router-discovery')) {
      body = { candidates: [] };
    } else if (urlStr.includes('lab/host-internet-probe')) {
      body = { results: [] };
    } else if (urlStr.includes('runtime.json')) {
      body = { adapterMode: 'fake' };
    } else if (urlStr.includes('/status')) {
      body = { status: 'ok' };
    }

    return {
      ok: true,
      status: 200,
      headers: {
        get(name) {
          return String(name).toLowerCase() === 'content-type' ? 'application/json' : null;
        },
      },
      json: async () => body,
      text: async () => JSON.stringify(body),
    };
  };
}

/**
 * @param {unknown} error
 */
function errorReport(error) {
  if (error instanceof Error) {
    const stackLines = error.stack ? error.stack.split('\n').slice(0, 4) : [];
    return {
      name: error.name,
      message: error.message,
      stackHead: stackLines.join('\n'),
    };
  }
  return {
    name: 'UnknownError',
    message: String(error),
    stackHead: '',
  };
}

/**
 * @param {() => void} fn
 * @param {number} ms
 */
function sleep(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * @param {unknown} error
 * @param {string} hubRoot
 * @returns {string | null}
 */
function moduleFromErrorStack(error, hubRoot) {
  if (!(error instanceof Error) || !error.stack) {
    return null;
  }
  const hubSuffix = `${path.basename(hubRoot)}/`.replace(/\\/g, '/');
  for (const line of error.stack.split('\n')) {
    const normalized = line.replace(/\\/g, '/');
    const marker = normalized.indexOf(hubSuffix);
    if (marker < 0) {
      continue;
    }
    const rel = normalized.slice(marker + hubSuffix.length);
    const match = rel.match(/^[^\s:)]+?\.js/);
    if (match) {
      return match[0];
    }
  }
  return null;
}

/**
 * @param {string} hubRoot
 */
async function runGuard(hubRoot) {
  const dom = createUiDomHarness();
  installGlobals(dom);

  const sessionMod = await import(pathToFileURL(path.join(hubRoot, 'core', 'session.js')).href);
  const { resetSession } = sessionMod;

  const files = collectHubJsFiles(hubRoot);
  /** @type {Array<Record<string, unknown>>} */
  const report = [];
  let failed = false;

  /** @type {string | null} */
  let activeMountModule = null;
  /** @type {string | null} */
  let lastRenderedModule = null;
  /** @type {Array<{ module: string | null, reason: unknown }>} */
  const asyncErrors = [];

  /** @param {unknown} reason */
  const onRejection = (reason) => {
    asyncErrors.push({
      module: moduleFromErrorStack(reason, hubRoot) ?? activeMountModule ?? lastRenderedModule,
      reason,
    });
  };
  /** @param {Error} error */
  const onException = (error) => {
    asyncErrors.push({
      module: moduleFromErrorStack(error, hubRoot) ?? activeMountModule ?? lastRenderedModule,
      reason: error,
    });
  };

  process.on('unhandledRejection', onRejection);
  process.on('uncaughtException', onException);

  for (const filePath of files) {
    const rel = path.relative(hubRoot, filePath).replace(/\\/g, '/');
    /** @type {Record<string, unknown>} */
    const entry = { module: rel, import: 'ok' };
    report.push(entry);

    /** @type {Record<string, unknown>} */
    let mod;
    try {
      mod = await import(pathToFileURL(filePath).href);
    } catch (error) {
      failed = true;
      entry.import = 'error';
      Object.assign(entry, errorReport(error));
      continue;
    }

    if (typeof mod.render !== 'function' || mod.meta == null) {
      entry.render = 'skipped';
      continue;
    }

    resetSession();
    const container = dom.document.createElement('div');
    dom.document.body.appendChild(container);

    const ctx = {
      runtime: { adapterMode: 'fake' },
      navigate() {},
      showToast() {},
    };

    activeMountModule = rel;
    lastRenderedModule = rel;
    const errorsBeforeMount = asyncErrors.length;

    try {
      const cleanup = mod.render(container, ctx);
      await sleep(SETTLE_MS);
      if (asyncErrors.length > errorsBeforeMount) {
        throw asyncErrors[errorsBeforeMount].reason;
      }
      if (typeof cleanup === 'function') {
        cleanup();
      }
      entry.render = 'ok';
    } catch (error) {
      failed = true;
      entry.render = 'error';
      Object.assign(entry, errorReport(error));
    } finally {
      activeMountModule = null;
      while (container.firstChild) {
        container.removeChild(container.firstChild);
      }
      if (container.parentNode) {
        container.parentNode.removeChild(container);
      }
    }
  }

  activeMountModule = lastRenderedModule;
  const errorsBeforeFinalDrain = asyncErrors.length;
  await sleep(FINAL_DRAIN_MS);
  activeMountModule = null;

  process.off('unhandledRejection', onRejection);
  process.off('uncaughtException', onException);

  if (asyncErrors.length > errorsBeforeFinalDrain) {
    failed = true;
    for (let idx = errorsBeforeFinalDrain; idx < asyncErrors.length; idx += 1) {
      const item = asyncErrors[idx];
      const modRel = item.module ?? 'unknown';
      /** @type {Record<string, unknown> | undefined} */
      let entry = report.find((row) => row.module === modRel);
      if (!entry) {
        entry = { module: modRel, import: 'ok' };
        report.push(entry);
      }
      if (entry.render !== 'error') {
        entry.render = 'error';
        Object.assign(entry, errorReport(item.reason));
      }
    }
  }

  const summary = {
    ok: !failed,
    hubRoot,
    moduleCount: files.length,
    renderedCount: report.filter((item) => item.render === 'ok').length,
    modules: report,
  };

  console.log(JSON.stringify(summary, null, 2));
  process.exit(failed ? 1 : 0);
}

const hubRootArg = process.argv[2];
if (!hubRootArg) {
  console.error('usage: node hub_module_guard.mjs <hub-root-directory>');
  process.exit(2);
}

const hubRoot = path.resolve(hubRootArg);
if (!fs.existsSync(hubRoot)) {
  console.error(`hub root not found: ${hubRoot}`);
  process.exit(2);
}

runGuard(hubRoot).catch((error) => {
  console.error(errorReport(error));
  process.exit(1);
});
