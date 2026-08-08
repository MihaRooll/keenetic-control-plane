/* LOCAL HUB service worker — кэширует только статическую оболочку PWA. */

// Поднимайте CACHE_VERSION при любом изменении файлов оболочки — иначе SW отдаст устаревшую копию из кэша.
const CACHE_VERSION = '99';
const CACHE_NAME = `local-hub-v${CACHE_VERSION}`;
const HUB_PREFIX = '/settings/router-control/hub/';

/** URL оболочки: параллельный precache; install отклоняется, если не все файлы закэшированы (all-or-nothing). */
const SHELL_URLS = [
  `${HUB_PREFIX}`,
  `${HUB_PREFIX}index.html`,
  `${HUB_PREFIX}app.js`,
  `${HUB_PREFIX}styles/tokens.css`,
  `${HUB_PREFIX}styles/base.css`,
  `${HUB_PREFIX}styles/components.css`,
  `${HUB_PREFIX}styles/states.css`,
  `${HUB_PREFIX}styles/shell.css`,
  `${HUB_PREFIX}styles/screens.css`,
  `${HUB_PREFIX}core/router.js`,
  `${HUB_PREFIX}core/session.js`,
  `${HUB_PREFIX}core/shell.js`,
  `${HUB_PREFIX}core/api.js`,
  `${HUB_PREFIX}core/errors.js`,
  `${HUB_PREFIX}core/form-submit-sync.js`,
  `${HUB_PREFIX}core/motion.js`,
  `${HUB_PREFIX}core/states.js`,
  `${HUB_PREFIX}components/badge.js`,
  `${HUB_PREFIX}components/button.js`,
  `${HUB_PREFIX}components/card.js`,
  `${HUB_PREFIX}components/details.js`,
  `${HUB_PREFIX}components/field.js`,
  `${HUB_PREFIX}components/icon.js`,
  `${HUB_PREFIX}components/index.js`,
  `${HUB_PREFIX}components/progress-ring.js`,
  `${HUB_PREFIX}components/modal.js`,
  `${HUB_PREFIX}components/toast.js`,
  `${HUB_PREFIX}components/toggle.js`,
  `${HUB_PREFIX}features/system-check.js`,
  `${HUB_PREFIX}features/overview-model.js`,
  `${HUB_PREFIX}features/overview-internet-simple.js`,
  `${HUB_PREFIX}features/overview-simple-networks.js`,
  `${HUB_PREFIX}features/overview-card-grid.js`,
  `${HUB_PREFIX}features/connection-flow.js`,
  `${HUB_PREFIX}features/live-connection-params.js`,
  `${HUB_PREFIX}features/wifi-qr.js`,
  `${HUB_PREFIX}features/wifi-ap-model.js`,
  `${HUB_PREFIX}features/wifi-screen-parts.js`,
  `${HUB_PREFIX}features/staff-wifi-model.js`,
  `${HUB_PREFIX}features/guest-wifi-model.js`,
  `${HUB_PREFIX}features/internet-source-block.js`,
  `${HUB_PREFIX}features/uplink-wifi-model.js`,
  `${HUB_PREFIX}features/vpn-model.js`,
  `${HUB_PREFIX}features/domain-model.js`,
  `${HUB_PREFIX}features/domain-simple-publish.js`,
  `${HUB_PREFIX}features/entry-pages-model.js`,
  `${HUB_PREFIX}features/diagnostics-model.js`,
  `${HUB_PREFIX}screens/overview.js`,
  `${HUB_PREFIX}screens/connection.js`,
  `${HUB_PREFIX}screens/staff-wifi.js`,
  `${HUB_PREFIX}screens/guest-wifi.js`,
  `${HUB_PREFIX}screens/internet-uplink.js`,
  `${HUB_PREFIX}screens/vpn.js`,
  `${HUB_PREFIX}screens/domain.js`,
  `${HUB_PREFIX}screens/entry-pages.js`,
  `${HUB_PREFIX}screens/diagnostics.js`,
  `${HUB_PREFIX}screens/stub.js`,
  `${HUB_PREFIX}screens/showcase.js`,
  `${HUB_PREFIX}screens/index.js`,
  `${HUB_PREFIX}manifest.webmanifest`,
  `${HUB_PREFIX}icons/icon.svg`,
  `${HUB_PREFIX}icons/icon-192.png`,
  `${HUB_PREFIX}icons/icon-512.png`,
  `${HUB_PREFIX}icons/icon-maskable-512.png`,
  `${HUB_PREFIX}icons/apple-touch-icon-180.png`,
];

/**
 * Ответ пригоден для записи в Cache Storage.
 * 401 и прочие не-200 нельзя кэшировать — иначе UI залипнет в неавторизованном состоянии.
 */
function isCacheableResponse(response) {
  return response && response.status === 200 && response.type === 'basic';
}

/**
 * Запросы, которые нельзя кэшировать и которые всегда идут в сеть как есть.
 * /api/ — данные о сети и состоянии устройства; их нельзя сохранять на диск между сессиями.
 */
function shouldPassthrough(request) {
  const url = new URL(request.url);

  if (url.origin !== self.location.origin) {
    return true;
  }
  if (request.method !== 'GET') {
    return true;
  }
  if (request.headers.has('Range')) {
    return true;
  }

  const path = url.pathname;
  if (path.startsWith('/api/')) {
    return true;
  }
  if (path === `${HUB_PREFIX}runtime.json`) {
    return true;
  }
  if (path === '/login' || path === '/logout') {
    return true;
  }

  return false;
}

/** Статические ресурсы оболочки под префиксом hub (без runtime.json). */
function isShellAsset(pathname) {
  if (!pathname.startsWith(HUB_PREFIX)) {
    return false;
  }
  if (pathname === `${HUB_PREFIX}runtime.json`) {
    return false;
  }
  if (pathname.endsWith('.js') || pathname.endsWith('.css') || pathname.endsWith('.html')) {
    return true;
  }
  if (pathname.endsWith('.webmanifest')) {
    return true;
  }
  if (pathname.startsWith(`${HUB_PREFIX}icons/`)) {
    return true;
  }
  if (pathname === HUB_PREFIX || pathname === `${HUB_PREFIX}index.html`) {
    return true;
  }
  return false;
}

async function precacheShell(cache) {
  const results = await Promise.all(
    SHELL_URLS.map(async (url) => {
      try {
        await cache.add(url);
        return true;
      } catch (_err) {
        return false;
      }
    }),
  );
  const succeeded = results.filter(Boolean).length;
  if (succeeded !== SHELL_URLS.length) {
    throw new Error(
      `precacheShell: ${succeeded}/${SHELL_URLS.length} shell assets cached`,
    );
  }
}

/** Stale-while-revalidate: отдать из кэша сразу, параллельно обновить в фоне. */
async function staleWhileRevalidate(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);

  const networkRefresh = fetch(request)
    .then((response) => {
      if (isCacheableResponse(response)) {
        cache.put(request, response.clone());
      }
      return response;
    })
    .catch(() => undefined);

  if (cached) {
    void networkRefresh;
    return cached;
  }

  const response = await networkRefresh;
  if (response) {
    return response;
  }
  return Response.error();
}

/** Навигация: сначала сеть, при офлайне — закэшированный index.html. */
async function networkFirstNavigate(request) {
  const cache = await caches.open(CACHE_NAME);
  const fallback = await cache.match(`${HUB_PREFIX}index.html`);

  try {
    const response = await fetch(request);
    if (isCacheableResponse(response)) {
      cache.put(request, response.clone());
    }
    return response;
  } catch (_err) {
    if (fallback) {
      return fallback;
    }
    return Response.error();
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_NAME);
      await precacheShell(cache);
    })(),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    (async () => {
      const names = await caches.keys();
      await Promise.all(
        names
          .filter((name) => name.startsWith('local-hub-') && name !== CACHE_NAME)
          .map((name) => caches.delete(name)),
      );
      await self.clients.claim();
    })(),
  );
});

self.addEventListener('message', (event) => {
  const type = event.data && event.data.type;
  if (type === 'HUB_SKIP_WAITING' || type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const { request } = event;

  if (shouldPassthrough(request)) {
    event.respondWith(fetch(request));
    return;
  }

  const url = new URL(request.url);

  if (request.mode === 'navigate') {
    event.respondWith(networkFirstNavigate(request));
    return;
  }

  if (isShellAsset(url.pathname)) {
    event.respondWith(staleWhileRevalidate(request));
    return;
  }

  event.respondWith(fetch(request));
});
