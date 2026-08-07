/**
 * Модель данных экрана «Обзор» — сбор секций без DOM.
 * Секции загружаются независимо; падение одного эндпоинта не гасит остальные.
 */

import { apiGet, apiPost } from '../core/api.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import { HubState } from '../core/states.js';
import { buildLiveConnectionParams } from './live-connection-params.js';
import {
  buildObservedStateRequestBody,
  evaluateStaffWifiObservedReadiness,
  parseObservedAccessPoint,
} from './staff-wifi-model.js';
import { runSystemCheckWithTransientRetry } from './system-check.js';

/** @typedef {{ state: string, title: string, subtitle: string|null, badge: { label: string, tone: string }|null, note: string|null, technical: string|null, error: HubApiError|null, route: string|null, mock: boolean, checkedAt?: string|null, options?: Array<{ id: string, name: string }> }} OverviewSection */

/** @typedef {{ router: OverviewSection, systemCheck: OverviewSection, domain: OverviewSection, generatedAt: string, adapterMode: string, selectedRouterId: string|null, systemCheckFacts: import('./system-check.js').DescribedFact[]|null }} OverviewModel */

/** @typedef {{ routerId?: string|null, routerHost?: string|null, siteId?: string|null, hostKeyConfirmed?: boolean, eventPresetId?: string|null, eventPresetName?: string|null, wifiLive?: { host?: string|null, username?: string|null, credentialRefId?: string|null, sshHostKeySha256?: string|null }, wifiRoles?: { staffApId?: string|null, guestApId?: string|null } }} SessionInput */

/** @typedef {{ adapterMode?: string }} RuntimeInput */

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isClientAborted(err) {
  return err instanceof HubApiError && err.code === 'client.aborted';
}

/**
 * @param {HubApiError} err
 * @returns {string}
 */
function hubStateForError(err) {
  switch (err.kind) {
    case ERROR_KIND.NETWORK:
    case ERROR_KIND.TIMEOUT:
      return HubState.CONNECTION_LOST;
    case ERROR_KIND.FORBIDDEN:
    case ERROR_KIND.UNAUTHORIZED:
      return HubState.FORBIDDEN;
    case ERROR_KIND.UNSUPPORTED:
      return HubState.UNSUPPORTED;
    default:
      return HubState.ERROR;
  }
}

/**
 * @param {HubApiError|null} err
 * @param {{ state: string, title: string, subtitle?: string|null, note?: string|null, route?: string|null, mock?: boolean }} defaults
 * @returns {OverviewSection}
 */
function sectionFromError(err, defaults) {
  if (!err) {
    return {
      state: defaults.state,
      title: defaults.title,
      subtitle: defaults.subtitle ?? null,
      badge: null,
      note: defaults.note ?? null,
      technical: null,
      error: null,
      route: defaults.route ?? null,
      mock: defaults.mock ?? false,
    };
  }

  if (isClientAborted(err)) {
    return {
      state: defaults.state,
      title: defaults.title,
      subtitle: defaults.subtitle ?? null,
      badge: null,
      note: defaults.note ?? null,
      technical: null,
      error: err,
      route: defaults.route ?? null,
      mock: defaults.mock ?? false,
    };
  }

  const described = describeError(err);
  return {
    state: hubStateForError(err),
    title: defaults.title,
    subtitle: described.message,
    badge: null,
    note: defaults.note ?? null,
    technical: null,
    error: err,
    route: defaults.route ?? null,
    mock: defaults.mock ?? false,
  };
}

/**
 * @param {Array<{ router_id?: string, display_name?: string, vendor?: string, model?: string }>|undefined} items
 * @param {string|null|undefined} sessionRouterId
 * @returns {{ router_id?: string, display_name?: string, vendor?: string, model?: string }|null}
 */
function pickRouter(items, sessionRouterId) {
  if (!items?.length) {
    return null;
  }
  if (sessionRouterId) {
    const matched = items.find((item) => item.router_id === sessionRouterId);
    if (matched) {
      return matched;
    }
  }
  return items[0] ?? null;
}

/**
 * @param {string|null|undefined} vendor
 * @param {string|null|undefined} model
 * @returns {string}
 */
function formatVendorModel(vendor, model) {
  const hasVendor = Boolean(vendor);
  const hasModel = Boolean(model);
  if (hasVendor && hasModel) {
    return `${vendor} ${model}`;
  }
  if (hasVendor) {
    return vendor;
  }
  if (hasModel) {
    return model;
  }
  return 'Модель не указана';
}

/**
 * @param {import('./system-check.js').SystemCheckVerdict|null} verdict
 * @returns {OverviewSection}
 */
function buildSystemCheckSection(verdict, error) {
  if (error) {
    return sectionFromError(error, {
      state: HubState.WARNING,
      title: 'Готовность не определена',
      route: null,
    });
  }

  if (!verdict) {
    return {
      state: HubState.WARNING,
      title: 'Готовность не определена',
      subtitle: null,
      badge: null,
      note: null,
      technical: null,
      error: null,
      route: null,
      mock: false,
    };
  }

  return {
    state: verdict.hubState,
    title: verdict.title,
    subtitle: verdict.description,
    badge: { label: verdict.badgeLabel, tone: verdict.badgeTone },
    note: verdict.mockNote,
    technical: null,
    error: null,
    route: null,
    mock: verdict.mock,
    checkedAt: verdict.checkedAt instanceof Date ? verdict.checkedAt.toISOString() : null,
  };
}

/**
 * Применяет вердикт system-check к секции роутера (бейдж, note, state).
 * @param {OverviewSection} routerSection
 * @param {import('./system-check.js').SystemCheckVerdict|null} verdict
 * @returns {OverviewSection}
 */
export function applyVerdictToRouterSection(routerSection, verdict) {
  if (routerSection.state === HubState.EMPTY || !verdict) {
    return routerSection;
  }

  const note = verdict.host ? verdict.host : 'Адрес неизвестен';
  let badgeLabel = verdict.badgeLabel ?? 'Состояние неизвестно';
  let badgeTone = verdict.badgeTone ?? 'neutral';
  const reachableFact = verdict.facts?.find((fact) => fact.id === 'reachable');
  if (reachableFact?.value === null || reachableFact?.value === undefined) {
    badgeLabel = 'Состояние неизвестно';
    badgeTone = 'neutral';
  }

  return {
    ...routerSection,
    state: verdict.hubState ?? HubState.WARNING,
    badge: { label: badgeLabel, tone: badgeTone },
    note,
    mock: verdict.mock ?? false,
  };
}

/**
 * @param {{ display_name?: string, vendor?: string, model?: string }|null} router
 * @param {import('./system-check.js').SystemCheckVerdict|null} verdict
 * @param {HubApiError|null} routersError
 * @param {boolean} hasRouters
 * @returns {OverviewSection}
 */
function buildRouterSection(router, verdict, routersError, hasRouters) {
  if (routersError) {
    return sectionFromError(routersError, {
      state: HubState.EMPTY,
      title: 'Роутер',
      route: '#/connection',
    });
  }

  if (!hasRouters || !router) {
    return {
      state: HubState.EMPTY,
      title: 'Роутер не подключён',
      subtitle: null,
      badge: null,
      note: null,
      technical: null,
      error: null,
      route: '#/connection',
      mock: false,
    };
  }

  const baseSection = {
    state: HubState.WARNING,
    title: router.display_name ?? 'Роутер',
    subtitle: formatVendorModel(router.vendor, router.model),
    badge: null,
    note: 'Адрес неизвестен',
    technical: null,
    error: null,
    route: '#/connection',
    mock: false,
  };

  if (!verdict) {
    return baseSection;
  }

  return applyVerdictToRouterSection(baseSection, verdict);
}

/** @type {Readonly<Record<string, string>>} */
const DOMAIN_VALUE_LABELS = Object.freeze({
  unknown: 'неизвестно',
  unavailable: 'недоступно',
  disabled: 'выключено',
  reserved: 'зарезервировано',
  not_reserved: 'не зарезервировано',
  auto: 'автоматически',
  cloud: 'через облако',
  direct: 'напрямую',
});

/**
 * @param {string|null|undefined} value
 * @returns {string}
 */
function translateDomainValue(value) {
  if (typeof value !== 'string') {
    return 'неизвестно';
  }
  return DOMAIN_VALUE_LABELS[value] ?? 'неизвестно';
}

/**
 * Секция Wi‑Fi по роли без сетевого запроса — роутер не размечает роли точек доступа.
 * @param {string} title
 * @param {string} route
 * @param {string} adapterMode
 * @returns {OverviewSection}
 */
function buildUnassignedWifiRoleSection(title, route, adapterMode) {
  return {
    state: HubState.UNSUPPORTED,
    title,
    subtitle: 'Роутер не сообщает, какая сеть рабочая, а какая гостевая',
    badge: null,
    note: 'Настройка и состояние — в самом разделе.',
    technical: null,
    error: null,
    route,
    mock: adapterMode === 'fake',
  };
}

/**
 * @param {import('./staff-wifi-model.js').ParsedObservedAccessPoint} observed
 * @param {string} sectionTitle
 * @param {string} route
 * @param {string} adapterMode
 * @returns {OverviewSection}
 */
function buildWifiRoleSectionFromObserved(observed, sectionTitle, route, adapterMode) {
  const mock = adapterMode === 'fake';
  const hasSsid = observed.readable && typeof observed.ssid === 'string' && observed.ssid.trim().length > 0;
  const note = 'Настройка и состояние — в самом разделе.';

  if (hasSsid && observed.hubState === HubState.SUCCESS) {
    return {
      state: HubState.SUCCESS,
      title: observed.ssid.trim(),
      subtitle: null,
      badge: { label: observed.activeLabel, tone: observed.activeTone },
      note,
      technical: null,
      error: null,
      route,
      mock,
    };
  }

  if (hasSsid) {
    return {
      state: observed.hubState,
      title: observed.ssid.trim(),
      subtitle: observed.activeLabel,
      badge: { label: observed.activeLabel, tone: observed.activeTone },
      note,
      technical: null,
      error: null,
      route,
      mock,
    };
  }

  if (observed.readable) {
    return {
      state: HubState.WARNING,
      title: sectionTitle,
      subtitle: 'Имя сети не прочитано',
      badge: { label: observed.activeLabel, tone: observed.activeTone },
      note,
      technical: null,
      error: null,
      route,
      mock,
    };
  }

  return {
    state: HubState.WARNING,
    title: sectionTitle,
    subtitle: 'Состояние не прочитано',
    badge: null,
    note,
    technical: null,
    error: null,
    route,
    mock,
  };
}

/**
 * Запрос состояния точки доступа по идентификатору роли.
 * @param {string} apId
 * @param {string} title
 * @param {string} route
 * @param {SessionInput} session
 * @param {string} adapterMode
 * @param {AbortSignal|undefined} signal
 * @returns {Promise<OverviewSection>}
 */
async function fetchWifiRoleObservedState(apId, title, route, session, adapterMode, signal) {
  const readiness = evaluateStaffWifiObservedReadiness(session, adapterMode);
  /** @type {Record<string, string|null>|null} */
  let liveParams = null;
  if (readiness.complete) {
    const live = buildLiveConnectionParams(session);
    if (live.complete) {
      liveParams = live.params;
    }
  }

  const body = buildObservedStateRequestBody({ apIds: [apId], liveParams });
  const response = /** @type {{ access_points?: unknown[] }} */ (
    await apiPost('wifi/observed-state', body, { signal })
  );
  const first = response?.access_points?.[0];
  const observed = parseObservedAccessPoint(first);
  return buildWifiRoleSectionFromObserved(observed, title, route, adapterMode);
}

/**
 * @param {SessionInput} session
 * @param {'staffApId'|'guestApId'} roleKey
 * @param {string} title
 * @param {string} route
 * @param {AbortSignal|undefined} signal
 * @param {string} adapterMode
 * @returns {Promise<OverviewSection>}
 */
async function buildWifiRoleSection(session, roleKey, title, route, signal, adapterMode) {
  const apId = session.wifiRoles?.[roleKey] ?? null;
  if (!apId) {
    return buildUnassignedWifiRoleSection(title, route, adapterMode);
  }

  try {
    return await fetchWifiRoleObservedState(apId, title, route, session, adapterMode, signal);
  } catch (error) {
    if (error instanceof HubApiError) {
      return sectionFromError(error, {
        state: HubState.WARNING,
        title,
        route,
        note: 'Настройка и состояние — в самом разделе.',
        mock: adapterMode === 'fake',
      });
    }
    throw error;
  }
}

/**
 * @param {unknown} data
 * @param {HubApiError|null} error
 * @returns {OverviewSection}
 */
function buildVpnSection(data, error) {
  if (error) {
    return sectionFromError(error, {
      state: HubState.EMPTY,
      title: 'VPN',
      route: '#/vpn',
    });
  }

  const items = /** @type {{ items?: Array<{ display_name?: string, vpn_kind?: string }> }} */ (data)?.items ?? [];
  if (!items.length) {
    return {
      state: HubState.EMPTY,
      title: 'Профиль VPN не добавлен',
      subtitle: null,
      badge: null,
      note: null,
      technical: null,
      error: null,
      route: '#/vpn',
      mock: false,
    };
  }

  const profile = items[0];
  return {
    state: HubState.WARNING,
    title: profile.display_name ?? 'VPN',
    subtitle: null,
    badge: { label: 'Активность VPN сейчас не проверяется', tone: 'warning' },
    note: 'Система не проверяет, работает ли VPN прямо сейчас',
    technical: null,
    error: null,
    route: '#/vpn',
    mock: false,
  };
}

/**
 * @param {unknown} data
 * @param {HubApiError|null} error
 * @returns {OverviewSection}
 */
function buildDomainSection(data, error) {
  if (error) {
    return sectionFromError(error, {
      state: HubState.WARNING,
      title: 'Домен',
      subtitle: 'Состояние домена неизвестно',
      route: '#/domain',
    });
  }

  const payload = /** @type {{ feature_availability?: string, name_reservation?: string, access_mode?: string }} */ (data);
  const technicalLines = [];
  if (typeof payload?.feature_availability === 'string') {
    technicalLines.push(`Доступность функции: ${translateDomainValue(payload.feature_availability)}`);
  }
  if (typeof payload?.name_reservation === 'string') {
    technicalLines.push(`Резервирование имени: ${translateDomainValue(payload.name_reservation)}`);
  }
  if (typeof payload?.access_mode === 'string') {
    technicalLines.push(`Режим доступа: ${translateDomainValue(payload.access_mode)}`);
  }
  const technical = technicalLines.length > 0 ? technicalLines.join('\n') : null;

  return {
    state: HubState.WARNING,
    title: 'Домен',
    subtitle: 'Состояние домена неизвестно',
    badge: null,
    note: 'Проверка домена выполняется только по сохранённым данным — живой проверки в системе нет',
    technical,
    error: null,
    route: '#/domain',
    mock: false,
  };
}

/**
 * @param {Promise<T>} promise
 * @template T
 * @returns {Promise<{ data: T|null, error: HubApiError|null }>}
 */
async function settleApiCall(promise) {
  try {
    const data = await promise;
    return { data, error: null };
  } catch (error) {
    if (error instanceof HubApiError) {
      return { data: null, error };
    }
    throw error;
  }
}

/**
 * Загружает все секции экрана «Обзор».
 * @param {{ session: SessionInput, runtime: RuntimeInput, signal?: AbortSignal, onHealthAttempt?: (info: { attempt: number, maxAttempts: number }) => void }} params
 * @returns {Promise<OverviewModel>}
 */
export async function loadOverview({ session, runtime, signal, onHealthAttempt }) {
  const adapterMode = runtime?.adapterMode ?? 'unknown';

  // Единственная упорядоченная зависимость: routers до health (нужен router_id).
  let routersData = null;
  /** @type {HubApiError|null} */
  let routersError = null;
  try {
    routersData = /** @type {{ items?: Array<{ router_id?: string, display_name?: string, vendor?: string, model?: string }> }} */ (
      await apiGet('routers', { signal, retry: 1 })
    );
  } catch (error) {
    if (error instanceof HubApiError) {
      routersError = error;
    } else {
      throw error;
    }
  }

  const routerItems = routersData?.items ?? [];
  const selectedRouter = pickRouter(routerItems, session.routerId ?? null);
  const selectedRouterId = selectedRouter?.router_id ?? null;

  /** @type {boolean|null} */
  let routerPresent = null;
  if (routersError) {
    routerPresent = null;
  } else if (routerItems.length === 0) {
    routerPresent = false;
  } else {
    routerPresent = true;
  }

  // Wi‑Fi observed, VPN list и entry-pages — в enrichment на экране (overview-simple-networks / vpn wrap).
  const [systemCheckResult, domainResult] = await Promise.all([
    settleApiCall(
      runSystemCheckWithTransientRetry(
        {
          routerId: selectedRouterId,
          routerPresent,
          hostKeyConfirmed: Boolean(session.hostKeyConfirmed),
          adapterMode,
          signal,
        },
        { signal, onAttempt: onHealthAttempt },
      ),
    ),
    settleApiCall(apiPost('keendns/status', null, { signal })),
  ]);

  const verdict = systemCheckResult.data;
  const generatedAt = new Date().toISOString();

  return {
    router: buildRouterSection(
      selectedRouter,
      verdict,
      routersError,
      routerItems.length > 0,
    ),
    systemCheck: buildSystemCheckSection(verdict, systemCheckResult.error),
    domain: buildDomainSection(domainResult.data, domainResult.error),
    generatedAt,
    adapterMode,
    selectedRouterId,
    systemCheckFacts: Array.isArray(verdict?.facts) ? verdict.facts : null,
  };
}
