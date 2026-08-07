/**
 * HTTP-клиент LOCAL HUB — fetch к Router Control API без echo и без DOM.
 */

import {
  HubApiError,
  ERROR_KIND,
  resolveErrorEntry,
  resolveHttpStatusEntry,
} from './errors.js';

export const API_BASE = '/api/router-control/v1';
export const HUB_RUNTIME_URL = '/settings/router-control/hub/runtime.json';

/** @type {{ onUnauthorized: (() => void)|null, onConnectionLost: (() => void)|null, onConnectionRestored: (() => void)|null }} */
const hooks = {
  onUnauthorized: null,
  onConnectionLost: null,
  onConnectionRestored: null,
};

/** Флаг: последний запрос завершился сетевой ошибкой. */
let connectionLost = false;

/** @type {number} */
let inFlightCount = 0;

/** @type {Set<(count: number) => void>} */
const inFlightHandlers = new Set();

function notifyInFlight() {
  for (const handler of inFlightHandlers) {
    handler(inFlightCount);
  }
}

function beginInFlight() {
  inFlightCount += 1;
  notifyInFlight();
}

function endInFlight() {
  if (inFlightCount > 0) {
    inFlightCount -= 1;
  }
  notifyInFlight();
}

/**
 * @returns {number}
 */
export function getInFlightCount() {
  return inFlightCount;
}

/**
 * @param {(count: number) => void} handler
 * @returns {() => void}
 */
export function subscribeInFlight(handler) {
  inFlightHandlers.add(handler);
  handler(inFlightCount);
  return () => {
    inFlightHandlers.delete(handler);
  };
}

/**
 * Регистрация колбэков оболочки.
 * @param {{ onUnauthorized?: () => void, onConnectionLost?: () => void, onConnectionRestored?: () => void }} options
 */
export function configureApi({ onUnauthorized, onConnectionLost, onConnectionRestored } = {}) {
  if (typeof onUnauthorized === 'function') hooks.onUnauthorized = onUnauthorized;
  if (typeof onConnectionLost === 'function') hooks.onConnectionLost = onConnectionLost;
  if (typeof onConnectionRestored === 'function') hooks.onConnectionRestored = onConnectionRestored;
}

/**
 * Сброс latch без вызова onConnectionRestored (оболочка уже показала восстановление).
 */
export function clearConnectionLost() {
  connectionLost = false;
}

/**
 * @param {boolean} lost
 */
function setConnectionLost(lost) {
  if (lost && !connectionLost) {
    connectionLost = true;
    hooks.onConnectionLost?.();
  } else if (!lost && connectionLost) {
    connectionLost = false;
    hooks.onConnectionRestored?.();
  }
}

/**
 * Объединяет внешний signal с внутренним таймаутом.
 * @param {AbortSignal|undefined} userSignal
 * @param {AbortSignal} timeoutSignal
 * @returns {{ signal: AbortSignal, cleanup: () => void }}
 */
function mergeSignals(userSignal, timeoutSignal) {
  if (!userSignal) {
    return { signal: timeoutSignal, cleanup: () => {} };
  }

  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
    return { signal: AbortSignal.any([userSignal, timeoutSignal]), cleanup: () => {} };
  }

  const merged = new AbortController();

  const forwardAbort = () => {
    const reason = userSignal.aborted ? userSignal.reason : timeoutSignal.reason;
    merged.abort(reason);
  };

  if (userSignal.aborted || timeoutSignal.aborted) {
    forwardAbort();
    return { signal: merged.signal, cleanup: () => {} };
  }

  userSignal.addEventListener('abort', forwardAbort);
  timeoutSignal.addEventListener('abort', forwardAbort);

  const cleanup = () => {
    userSignal.removeEventListener('abort', forwardAbort);
    timeoutSignal.removeEventListener('abort', forwardAbort);
  };

  return { signal: merged.signal, cleanup };
}

/**
 * @param {number} ms
 * @returns {Promise<void>}
 */
function delay(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

/**
 * Разбор тела ошибки сервера в HubApiError (no-echo).
 * @param {Response} response
 * @returns {Promise<HubApiError>}
 */
async function buildApiError(response) {
  const headerRequestId = response.headers.get('X-Request-Id');
  const headerCorrelationId = response.headers.get('X-Correlation-Id');
  const httpStatus = response.status;

  let payload = null;
  try {
    const text = await response.text();
    if (text) payload = JSON.parse(text);
  } catch {
    payload = null;
  }

  if (payload?.error?.code) {
    const envelope = payload.error;
    const entry = resolveErrorEntry(envelope.code);
    return new HubApiError({
      code: envelope.code,
      httpStatus,
      userMessage: entry.userMessage,
      userAction: entry.userAction,
      serverMessage: envelope.message ?? null,
      details: Array.isArray(envelope.details) ? envelope.details : [],
      requestId: envelope.request_id ?? headerRequestId,
      correlationId: envelope.correlation_id ?? headerCorrelationId,
      kind: entry.kind,
    });
  }

  const entry = resolveHttpStatusEntry(httpStatus);
  const serverMessage =
    payload?.error?.message ??
    (typeof payload?.detail === 'string' ? payload.detail : null);

  return new HubApiError({
    code: HTTP_STATUS_CODES[httpStatus] ?? `http.${httpStatus}`,
    httpStatus,
    userMessage: entry.userMessage,
    userAction: entry.userAction,
    serverMessage,
    details: payload?.error?.details ?? [],
    requestId: headerRequestId,
    correlationId: headerCorrelationId,
    kind: entry.kind,
  });
}

/** @type {Readonly<Record<number, string>>} */
const HTTP_STATUS_CODES = Object.freeze({
  400: 'request.validation_failed',
  401: 'auth.required',
  403: 'auth.forbidden',
  404: 'resource.not_found',
  405: 'http.method_not_allowed',
  409: 'resource.conflict',
  412: 'resource.precondition_failed',
  422: 'request.validation_failed',
  503: 'service.unavailable',
});

/**
 * Один HTTP-запрос без повторов.
 * @param {string} path
 * @param {object} options
 * @returns {Promise<unknown>}
 */
async function executeRequest(path, options) {
  const {
    method = 'GET',
    body,
    signal,
    timeoutMs = 15000,
  } = options;

  const timeoutController = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    timeoutController.abort();
  }, timeoutMs);

  const { signal: combinedSignal, cleanup: releaseMergedSignal } = mergeSignals(
    signal,
    timeoutController.signal,
  );

  const url = path.startsWith('/') ? path : `${API_BASE}/${path.replace(/^\//, '')}`;
  const init = {
    method,
    credentials: 'same-origin',
    cache: method === 'GET' ? 'no-store' : 'default',
    headers: {
      Accept: 'application/json',
    },
    signal: combinedSignal,
  };

  if (body !== undefined && body !== null) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }

  beginInFlight();
  try {
    const response = await fetch(url, init);

    if (!response.ok) {
      const apiError = await buildApiError(response);

      if (response.status === 401) {
        hooks.onUnauthorized?.();
      }

      throw apiError;
    }

    setConnectionLost(false);

    if (response.status === 204) {
      return null;
    }

    const contentType = response.headers.get('Content-Type') ?? '';
    if (!contentType.includes('application/json')) {
      return null;
    }

    return await response.json();
  } catch (error) {
    if (error instanceof HubApiError) {
      throw error;
    }

    if (combinedSignal.aborted) {
      if (timedOut) {
        setConnectionLost(true);
        throw new HubApiError({
          code: 'client.timeout',
          httpStatus: null,
          userMessage: 'Сервер не ответил вовремя.',
          userAction: 'Проверьте сеть и повторите запрос.',
          serverMessage: null,
          details: [],
          requestId: null,
          correlationId: null,
          kind: ERROR_KIND.TIMEOUT,
        });
      }

      throw new HubApiError({
        code: 'client.aborted',
        httpStatus: null,
        userMessage: 'Запрос был отменён.',
        userAction: 'Повторите действие, если это необходимо.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.ABORTED,
      });
    }

    if (error instanceof TypeError) {
      setConnectionLost(true);
      throw new HubApiError({
        code: 'client.network',
        httpStatus: null,
        userMessage: 'Нет связи с сервером.',
        userAction: 'Проверьте, что iPad подключён к рабочей сети, и повторите.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.NETWORK,
      });
    }

    throw new HubApiError({
      code: 'client.unknown',
      httpStatus: null,
      userMessage: 'Не удалось выполнить запрос.',
      userAction: 'Повторите позже. Если ошибка сохраняется — обратитесь к администратору.',
      serverMessage: null,
      details: [],
      requestId: null,
      correlationId: null,
      kind: ERROR_KIND.UNKNOWN,
    });
  } finally {
    endInFlight();
    releaseMergedSignal();
    clearTimeout(timeoutId);
  }
}

/**
 * @param {string} path
 * @param {{ method?: string, body?: unknown, signal?: AbortSignal, timeoutMs?: number, retry?: number }} [options]
 * @returns {Promise<unknown>}
 */
export async function apiRequest(path, { method = 'GET', body, signal, timeoutMs = 15000, retry = 0 } = {}) {
  const normalizedMethod = method.toUpperCase();
  const maxAttempts = normalizedMethod === 'GET' ? 1 + Math.max(0, retry) : 1;

  let lastError;
  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      return await executeRequest(path, { method: normalizedMethod, body, signal, timeoutMs });
    } catch (error) {
      lastError = error;
      const isRetriable =
        error instanceof HubApiError &&
        (error.kind === ERROR_KIND.NETWORK || error.kind === ERROR_KIND.TIMEOUT);
      const hasMoreAttempts = attempt < maxAttempts - 1;

      if (!isRetriable || !hasMoreAttempts) {
        throw error;
      }

      const backoffMs = Math.min(1000 * 2 ** attempt, 8000);
      await delay(backoffMs);
    }
  }

  throw lastError;
}

/**
 * @param {string} path
 * @param {{ signal?: AbortSignal, timeoutMs?: number, retry?: number }} [options]
 * @returns {Promise<unknown>}
 */
export function apiGet(path, options = {}) {
  return apiRequest(path, { ...options, method: 'GET' });
}

/**
 * @param {string} path
 * @param {unknown} body
 * @param {{ signal?: AbortSignal, timeoutMs?: number }} [options]
 * @returns {Promise<unknown>}
 */
export function apiPost(path, body, options = {}) {
  return apiRequest(path, { ...options, method: 'POST', body, retry: 0 });
}

/**
 * @returns {Promise<{ adapterMode: string, unsafeAuthDisabled: boolean, hubVersion: string }>}
 */
export async function fetchRuntimeInfo() {
  const timeoutController = new AbortController();
  const timeoutId = setTimeout(() => timeoutController.abort(), 15000);

  beginInFlight();
  try {
    const response = await fetch(HUB_RUNTIME_URL, {
      method: 'GET',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      signal: timeoutController.signal,
    });

    if (!response.ok) {
      const apiError = await buildApiError(response);
      if (response.status === 401) {
        hooks.onUnauthorized?.();
      }
      throw apiError;
    }

    setConnectionLost(false);
    const data = await response.json();
    return {
      adapterMode: data.adapter_mode ?? 'unknown',
      unsafeAuthDisabled: Boolean(data.unsafe_auth_disabled),
      hubVersion: data.hub_version ?? '0.0.0',
    };
  } catch (error) {
    if (error instanceof HubApiError) {
      throw error;
    }
    if (timeoutController.signal.aborted) {
      setConnectionLost(true);
      throw new HubApiError({
        code: 'client.timeout',
        httpStatus: null,
        userMessage: 'Сервер не ответил вовремя.',
        userAction: 'Проверьте сеть и повторите запрос.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.TIMEOUT,
      });
    }
    if (error instanceof TypeError) {
      setConnectionLost(true);
      throw new HubApiError({
        code: 'client.network',
        httpStatus: null,
        userMessage: 'Нет связи с сервером.',
        userAction: 'Проверьте, что iPad подключён к рабочей сети, и повторите.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.NETWORK,
      });
    }
    throw error;
  } finally {
    endInFlight();
    clearTimeout(timeoutId);
  }
}

/**
 * @returns {boolean}
 */
export function isOnline() {
  return typeof navigator !== 'undefined' ? navigator.onLine : true;
}

/**
 * @param {(online: boolean) => void} handler
 * @returns {() => void}
 */
export function subscribeConnectivity(handler) {
  if (typeof window === 'undefined') {
    return () => {};
  }

  const onOnline = () => handler(true);
  const onOffline = () => handler(false);

  window.addEventListener('online', onOnline);
  window.addEventListener('offline', onOffline);

  return () => {
    window.removeEventListener('online', onOnline);
    window.removeEventListener('offline', onOffline);
  };
}
