/**
 * Hash-роутер LOCAL HUB.
 */

import { applyScreenEnter } from './motion.js';

const DEFAULT_ROUTE = 'overview';

/**
 * @param {string} hash
 * @returns {string}
 */
function parseHash(hash) {
  const raw = (hash || '').replace(/^#/, '').replace(/^\/?/, '');
  if (!raw) {
    return DEFAULT_ROUTE;
  }
  const routeId = raw.startsWith('/') ? raw.slice(1) : raw;
  return routeId || DEFAULT_ROUTE;
}

/**
 * @param {{ routes: Record<string, { render: (container: HTMLElement, ctx: object) => (() => void)|void }>, onNavigate?: (routeId: string) => void, contentElement: HTMLElement, getContext: () => object }} options
 */
export function createRouter({ routes, onNavigate, contentElement, getContext }) {
  /** @type {string} */
  let currentRouteId = DEFAULT_ROUTE;
  /** @type {(() => void)|null} */
  let screenCleanup = null;

  /** @param {string} routeId */
  function normalizeRoute(routeId) {
    if (routes[routeId]) {
      return routeId;
    }
    return DEFAULT_ROUTE;
  }

  /** @param {string} routeId */
  function renderRoute(routeId) {
    if (typeof screenCleanup === 'function') {
      screenCleanup();
      screenCleanup = null;
    }

    while (contentElement.firstChild) {
      contentElement.removeChild(contentElement.firstChild);
    }

    const module = routes[routeId];
    if (module && typeof module.render === 'function') {
      const ctx = getContext();
      const cleanup = module.render(contentElement, ctx);
      if (typeof cleanup === 'function') {
        screenCleanup = cleanup;
      }
    }

    contentElement.scrollTop = 0;
    const enterTarget = contentElement.firstElementChild ?? contentElement;
    applyScreenEnter(enterTarget);
  }

  /** @param {string} routeId */
  function applyRoute(routeId, { replace = false } = {}) {
    const normalized = normalizeRoute(routeId);
    const targetHash = `#/${normalized}`;

    if (window.location.hash !== targetHash) {
      if (replace) {
        window.history.replaceState(null, '', targetHash);
      } else {
        window.location.hash = targetHash;
      }
      return;
    }

    if (normalized !== currentRouteId) {
      currentRouteId = normalized;
      renderRoute(normalized);
      if (typeof onNavigate === 'function') {
        onNavigate(normalized);
      }
    }
  }

  function handleHashChange() {
    const routeId = parseHash(window.location.hash);
    const normalized = normalizeRoute(routeId);

    if (normalized !== routeId) {
      window.history.replaceState(null, '', `#/${normalized}`);
    }

    if (normalized !== currentRouteId) {
      currentRouteId = normalized;
      renderRoute(normalized);
      if (typeof onNavigate === 'function') {
        onNavigate(normalized);
      }
    }
  }

  return {
    start() {
      const routeId = parseHash(window.location.hash);
      const normalized = normalizeRoute(routeId);
      if (normalized !== routeId || !window.location.hash) {
        window.history.replaceState(null, '', `#/${normalized}`);
      }
      currentRouteId = normalized;
      renderRoute(normalized);
      if (typeof onNavigate === 'function') {
        onNavigate(normalized);
      }
      window.addEventListener('hashchange', handleHashChange);
    },

    /** @param {string} routeId */
    navigate(routeId) {
      applyRoute(routeId);
    },

    currentRoute() {
      return currentRouteId;
    },

    stop() {
      window.removeEventListener('hashchange', handleHashChange);
      if (typeof screenCleanup === 'function') {
        screenCleanup();
        screenCleanup = null;
      }
    },
  };
}
