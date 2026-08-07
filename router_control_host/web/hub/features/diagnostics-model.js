/**
 * Модель экрана «Диагностика» — строки проверок, счётчик, оркестрация без DOM.
 * Единая правда готовности — только runSystemCheck / evaluateSystemCheck (system-check.js).
 */

import { apiPost } from '../core/api.js';
import { ERROR_KIND, HubApiError } from '../core/errors.js';
import { HubState } from '../core/states.js';
import { buildLiveConnectionParams } from './live-connection-params.js';
import {
  DOMAIN_HOST_PROBE_SCOPE_LABEL,
  describeHostHttpProbe,
  describeHostInternetProbe,
  describeHostTlsProbe,
  loadEventPreset,
  loadEventPresetRevision,
  probeLocalApplicationHttp,
  probeLocalApplicationTls,
  probeOperatorHostInternet,
} from './domain-model.js';
import {
  ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE,
  findPageByAudience,
  listEntryPages,
  parseSelfCheckResult,
  selfCheckEntryPage,
  ENTRY_AUDIENCE_GUEST,
} from './entry-pages-model.js';
import { evaluateStaffWifiObservedReadiness } from './staff-wifi-model.js';
import {
  buildObservedStateRequestBody,
  parseObservedAccessPoint,
} from './wifi-ap-model.js';
import { SystemCheckLevel, runSystemCheck } from './system-check.js';

export const DIAGNOSTICS_GROUP_ROUTER = 'router-networks';
export const DIAGNOSTICS_GROUP_HOST = 'host-probes';
export const DIAGNOSTICS_GROUP_UNSUPPORTED = 'unsupported';

export const ROUTER_INTERNET_ROW_ID = 'router-internet';
export const ROUTER_ROW_ID = 'router';
export const CREDENTIALS_ROW_ID = 'credentials';
export const STAFF_WIFI_ROW_ID = 'staff-wifi';
export const GUEST_WIFI_ROW_ID = 'guest-wifi';
export const HOST_INTERNET_ROW_ID = 'host-internet';
export const LOCAL_APP_ROW_ID = 'local-app-http';
export const LOCAL_TLS_ROW_ID = 'local-app-tls';
export const ENTRY_PAGE_ROW_ID = 'entry-page';

export const ROUTER_INTERNET_UNSUPPORTED_MESSAGE =
  'Отдельная проверка интернета роутера недоступна';

export const ROUTER_INTERNET_CHECK_FAILED_MESSAGE =
  'Не удалось проверить интернет роутера.';

export const ROUTER_INTERNET_OK_MESSAGE = 'Интернет на роутере доступен.';

export const ROUTER_INTERNET_NO_INTERNET_MESSAGE =
  'На роутере нет интернета. Откройте раздел «Интернет».';

export const CREDENTIALS_NEUTRAL_MESSAGE =
  'Доступ сохранён, права администратора не проверялись';

export const LOCAL_APP_ADDRESS_MISSING_MESSAGE =
  'Адрес локального приложения не сохранён в настройках мероприятия — проверка не выполнялась';

export const DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE =
  'Проверка не завершена — данные не получены.';

export const DIAGNOSTICS_ENTRY_PAGE_INCOMPLETE_MESSAGE =
  'Проверка страницы входа не завершена — данные не получены.';

export const DIAGNOSTICS_WIFI_STATE_UNKNOWN_MESSAGE =
  'Состояние сети не определено — данные не получены.';

export const DIAGNOSTICS_PRESET_MISSING_MESSAGE =
  'Мероприятие не выбрано — проверка локального приложения не выполнялась.';

/** @type {Readonly<RegExp>} */
export const DIAGNOSTICS_UNKNOWN_REFUSAL_WORDS_RE =
  /не удалось|не прочитан|недоступ|ошибка|не совпада|сбой|отказ/i;

export const READINESS_COUNTER_CAPTION =
  'Счётчик учитывает только проверки роутера и сетей с подтверждённым результатом: связь с роутером, рабочая и гостевая сеть. Права управления, интернет роутера и непроверенные строки не входят.';

/** @typedef {'loading'|'green'|'red'|'neutral'|'unknown'|'unsupported'} DiagnosticProvableState */

/** @typedef {{ id: string, group: string, title: string, message: string|null, hubState: string, provableState: DiagnosticProvableState, technical: string|null, apId?: string|null, ssid?: string|null }} DiagnosticRow */

/** @typedef {{ green: number, total: number, caption: string, label: string }} ReadinessCounter */

/** @typedef {{ rows: DiagnosticRow[], systemVerdict: import('./system-check.js').SystemCheckVerdict|null, counter: ReadinessCounter, bannerTone: 'success'|'warning'|'danger'|'neutral', bannerTitle: string, bannerMessage: string|null, checkedAt: Date|null, technicalLines: string[], adapterMode: string|null }} DiagnosticsSnapshot */

const EXPORT_FORBIDDEN_KEYS = Object.freeze([
  'password',
  'credential_ref',
  'credential_ref_id',
  'router_credential_ref_id',
  'psk',
  'private_key',
  'ssh_host_key',
  'ssh_host_key_sha256',
  'cookie',
]);

const UNSUPPORTED_ROWS = Object.freeze([
  {
    id: 'vpn-tunnel',
    title: 'Состояние VPN-туннеля',
    message: 'Наблюдение за туннелем в нужном формате сейчас недоступно.',
  },
  {
    id: 'vpn-egress',
    title: 'Выход трафика через VPN',
    message: 'Направление трафика через VPN сейчас не проверяется.',
  },
  {
    id: 'captive-portal',
    title: 'Принудительное автооткрытие страницы',
    message: ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE,
  },
  {
    id: 'domain-cloud',
    title: 'Публикация домена в облаке',
    message: 'Облачная публикация домена не выполняется автоматически и здесь не проверяется.',
  },
  {
    id: 'admin-rights',
    title: 'Права администратора на роутере',
    message: 'Права администратора на устройстве не проверяются — только наличие сохранённого доступа.',
  },
]);

/**
 * @param {string|null|undefined} message
 * @param {string} fallback
 * @returns {string}
 */
export function sanitizeUnknownDiagnosticMessage(message, fallback) {
  const text = String(message ?? '').trim();
  if (!text || DIAGNOSTICS_UNKNOWN_REFUSAL_WORDS_RE.test(text)) {
    return fallback;
  }
  return text;
}

/**
 * @param {ReturnType<typeof describeHostInternetProbe>|ReturnType<typeof describeHostHttpProbe>|ReturnType<typeof describeHostTlsProbe>} described
 * @param {string} fallback
 * @returns {string}
 */
function messageForHostProbeRow(described, fallback) {
  if (described.factState === 'confirmed' || described.factState === 'refuted') {
    return described.message;
  }
  return fallback;
}

/**
 * @param {DiagnosticProvableState} provableState
 * @param {string} adapterMode
 * @returns {boolean}
 */
export function isProvableForCounter(provableState, adapterMode) {
  if (adapterMode === 'fake') {
    return false;
  }
  return provableState === 'green' || provableState === 'red';
}

/**
 * @param {DiagnosticRow} row
 * @param {string|null|undefined} adapterMode
 * @returns {boolean}
 */
export function isRowCountable(row, adapterMode) {
  if (row.group !== DIAGNOSTICS_GROUP_ROUTER) {
    return false;
  }
  if (row.id === CREDENTIALS_ROW_ID || row.id === ROUTER_INTERNET_ROW_ID) {
    return false;
  }
  return isProvableForCounter(row.provableState, adapterMode ?? '');
}

/**
 * @param {DiagnosticRow} row
 * @returns {boolean}
 */
export function isExpectedGroup1CheckRow(row) {
  if (row.group !== DIAGNOSTICS_GROUP_ROUTER) {
    return false;
  }
  return row.id !== CREDENTIALS_ROW_ID && row.id !== ROUTER_INTERNET_ROW_ID;
}

/**
 * @param {DiagnosticRow[]} group1Rows
 * @param {string|null|undefined} adapterMode
 * @returns {number}
 */
export function countUnknownExpectedGroup1Rows(group1Rows, adapterMode) {
  if (adapterMode === 'fake') {
    return 0;
  }
  return group1Rows.filter(
    (row) => isExpectedGroup1CheckRow(row) && row.provableState === 'unknown',
  ).length;
}

/**
 * @param {DiagnosticRow[]} group1Rows
 * @param {string|null|undefined} adapterMode
 * @returns {ReadinessCounter}
 */
export function computeReadinessCounter(group1Rows, adapterMode) {
  const countable = group1Rows.filter((row) => isRowCountable(row, adapterMode));
  const green = countable.filter((row) => row.provableState === 'green').length;
  const total = countable.length;
  const uncheckedCount = countUnknownExpectedGroup1Rows(group1Rows, adapterMode);
  let caption = READINESS_COUNTER_CAPTION;
  if (uncheckedCount > 0) {
    caption = `${READINESS_COUNTER_CAPTION} Не проверено: ${uncheckedCount}.`;
  }
  return {
    green,
    total,
    caption,
    label: total > 0 ? `${green} из ${total}` : '—',
    uncheckedCount,
  };
}

/**
 * @param {{ systemVerdict: import('./system-check.js').SystemCheckVerdict|null, counter: ReadinessCounter, adapterMode?: string|null, group1Rows: DiagnosticRow[] }} params
 * @returns {{ tone: 'success'|'warning'|'danger'|'neutral', title: string, message: string|null }}
 */
export function computeSummaryBanner({ systemVerdict, counter, adapterMode, group1Rows }) {
  const isFake = adapterMode === 'fake';
  if (isFake) {
    return {
      tone: 'neutral',
      title: 'Демонстрационный режим',
      message: systemVerdict?.mockNote ?? 'В демонстрационном режиме результаты не считаются доказанными.',
    };
  }

  const uncheckedCount =
    counter.uncheckedCount ?? countUnknownExpectedGroup1Rows(group1Rows, adapterMode);
  const hasFailedInM = group1Rows.some(
    (row) => isRowCountable(row, adapterMode) && row.provableState === 'red',
  );
  const level = systemVerdict?.level ?? null;

  /** @type {'success'|'warning'|'danger'|'neutral'} */
  let tone = 'neutral';
  /** @type {string} */
  let title = 'Готовность не определена';
  /** @type {string|null} */
  let message = systemVerdict?.description ?? null;

  if (level === SystemCheckLevel.NO_ROUTER) {
    tone = 'neutral';
    title = 'Роутер не подключён';
    message = systemVerdict?.description ?? 'Сначала подключите роутер.';
  } else if (level === SystemCheckLevel.FAILED) {
    tone = 'neutral';
    title = 'Связь с роутером не проверена';
    message = systemVerdict?.description ?? 'Состояние связи не определено.';
  } else if (level === SystemCheckLevel.NOT_READY) {
    tone = 'danger';
    title = 'Связь с роутером не установлена';
    message = systemVerdict?.description ?? null;
  } else if (hasFailedInM) {
    tone = 'warning';
    title = 'Часть проверок роутера и сетей не пройдена';
    message = systemVerdict?.description ?? 'Не все проверки роутера и сетей подтверждены.';
  } else if (uncheckedCount > 0) {
    tone = level === SystemCheckLevel.LIMITED ? 'warning' : 'neutral';
    if (level === SystemCheckLevel.READY) {
      title = 'Связь с роутером подтверждена, но не все проверки выполнены';
    } else if (level === SystemCheckLevel.LIMITED) {
      title = 'Связь с роутером ограничена, часть проверок не выполнена';
    } else {
      title = 'Часть проверок не выполнена';
    }
    message = `Не проверено: ${uncheckedCount}.`;
  } else if (level === SystemCheckLevel.LIMITED) {
    tone = 'warning';
    title = 'Связь с роутером установлена с ограничениями';
    message = systemVerdict?.description ?? null;
  } else if (
    level === SystemCheckLevel.READY
    && counter.total > 0
    && counter.green === counter.total
  ) {
    tone = 'success';
    title = 'Связь с роутером подтверждена';
    message = systemVerdict?.description ?? 'Все учтённые проверки роутера и сетей пройдены.';
  } else if (level === SystemCheckLevel.READY) {
    tone = 'neutral';
    title = 'Связь с роутером подтверждена';
    message = systemVerdict?.description ?? null;
  } else {
    tone = 'neutral';
    title = 'Готовность не определена';
    message = systemVerdict?.description ?? 'Нажмите «Проверить систему».';
  }

  if (title === ['Система', ' готова к ', 'работе'].join('')) {
    title = 'Связь с роутером подтверждена';
  }

  if (tone === 'success' && (hasFailedInM || uncheckedCount > 0)) {
    tone = 'neutral';
  }
  if (tone === 'success' && /не пройден/i.test(title)) {
    tone = 'warning';
  }
  if ((tone === 'success' || tone === 'warning' || tone === 'danger') && /не проверен/i.test(title)) {
    tone = 'neutral';
  }

  return { tone, title, message };
}

/**
 * @typedef {{
 *   internet?: boolean|null,
 *   reliable?: boolean|null,
 *   gateway_accessible?: boolean|null,
 *   dns_accessible?: boolean|null,
 *   captive_accessible?: boolean|null,
 *   gateway_interface?: string|null,
 *   gateway_ssid?: string|null,
 *   checked_at?: string|null,
 *   read_status?: string|null,
 * }} RouterInternetObservePayload
 */

/**
 * @param {RouterInternetObservePayload|null|undefined} payload
 * @returns {RouterInternetObservePayload|null}
 */
export function normalizeRouterInternetObserve(payload) {
  if (!payload || typeof payload !== 'object') {
    return null;
  }
  const record = /** @type {Record<string, unknown>} */ (payload);
  return {
    internet: typeof record.internet === 'boolean' ? record.internet : null,
    reliable: typeof record.reliable === 'boolean' ? record.reliable : null,
    gateway_accessible:
      typeof record.gateway_accessible === 'boolean' ? record.gateway_accessible : null,
    dns_accessible: typeof record.dns_accessible === 'boolean' ? record.dns_accessible : null,
    captive_accessible:
      typeof record.captive_accessible === 'boolean' ? record.captive_accessible : null,
    gateway_interface:
      typeof record.gateway_interface === 'string' ? record.gateway_interface : null,
    gateway_ssid: typeof record.gateway_ssid === 'string' ? record.gateway_ssid : null,
    checked_at: typeof record.checked_at === 'string' ? record.checked_at : null,
    read_status: typeof record.read_status === 'string' ? record.read_status : null,
  };
}

/**
 * @param {{
 *   session: import('../core/session.js').SessionSnapshot|null|undefined,
 *   signal?: AbortSignal,
 * }} params
 * @returns {Promise<RouterInternetObservePayload|null>}
 */
export async function fetchRouterInternetObserve(params) {
  const { session, signal } = params;
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    return null;
  }
  try {
    const response = /** @type {RouterInternetObservePayload} */ (
      await apiPost('internet-status/observe', live.params, { signal })
    );
    return normalizeRouterInternetObserve(response);
  } catch {
    return normalizeRouterInternetObserve({ read_status: 'failed' });
  }
}

/**
 * @param {RouterInternetObservePayload|null|undefined} observed
 * @param {{ loading?: boolean }} [options]
 * @returns {DiagnosticRow}
 */
export function buildRouterInternetRowFromObserve(observed, options = {}) {
  if (options.loading) {
    return {
      id: ROUTER_INTERNET_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Интернет у роутера',
      message: 'Проверка…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
    };
  }
  const normalized = normalizeRouterInternetObserve(observed);
  if (!normalized || normalized.read_status !== 'ok') {
    return {
      id: ROUTER_INTERNET_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Интернет у роутера',
      message: ROUTER_INTERNET_CHECK_FAILED_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: normalized?.read_status ? `read_status: ${normalized.read_status}` : null,
    };
  }
  if (normalized.internet === true) {
    return {
      id: ROUTER_INTERNET_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Интернет у роутера',
      message: ROUTER_INTERNET_OK_MESSAGE,
      hubState: HubState.SUCCESS,
      provableState: 'green',
      technical: normalized.checked_at ? `checked_at: ${normalized.checked_at}` : null,
    };
  }
  if (normalized.internet === false) {
    return {
      id: ROUTER_INTERNET_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Интернет у роутера',
      message: ROUTER_INTERNET_NO_INTERNET_MESSAGE,
      hubState: HubState.WARNING,
      provableState: 'red',
      technical: normalized.checked_at ? `checked_at: ${normalized.checked_at}` : null,
    };
  }
  return {
    id: ROUTER_INTERNET_ROW_ID,
    group: DIAGNOSTICS_GROUP_ROUTER,
    title: 'Интернет у роутера',
    message: ROUTER_INTERNET_CHECK_FAILED_MESSAGE,
    hubState: HubState.EMPTY,
    provableState: 'unknown',
    technical: 'read_status: ok; internet: null',
  };
}

/**
 * @returns {DiagnosticRow}
 * @deprecated Use buildRouterInternetRowFromObserve after observe call.
 */
export function buildRouterInternetRow() {
  return buildRouterInternetRowFromObserve({ read_status: 'unsupported' });
}

/**
 * @param {boolean|null|undefined} credentialsPresent
 * @returns {DiagnosticRow}
 */
export function buildCredentialsRow(credentialsPresent) {
  if (credentialsPresent === true) {
    return {
      id: CREDENTIALS_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Права управления',
      message: CREDENTIALS_NEUTRAL_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'neutral',
      technical: 'facts.credentials_present: true',
    };
  }
  if (credentialsPresent === false) {
    return {
      id: CREDENTIALS_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Права управления',
      message: 'Сохранённого доступа нет. Откройте раздел «Подключение».',
      hubState: HubState.WARNING,
      provableState: 'neutral',
      technical: 'facts.credentials_present: false',
    };
  }
  return {
    id: CREDENTIALS_ROW_ID,
    group: DIAGNOSTICS_GROUP_ROUTER,
    title: 'Права управления',
    message: 'Наличие сохранённого доступа не подтверждено.',
    hubState: HubState.EMPTY,
    provableState: 'neutral',
    technical: null,
  };
}

/**
 * @param {import('./system-check.js').SystemCheckVerdict|null} verdict
 * @param {{ loading?: boolean, adapterMode?: string|null }} [options]
 * @returns {DiagnosticRow}
 */
export function buildRouterRowFromVerdict(verdict, options = {}) {
  if (options.loading) {
    return {
      id: ROUTER_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Роутер',
      message: 'Проверка связи…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
    };
  }

  if (!verdict) {
    return {
      id: ROUTER_ROW_ID,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: 'Роутер',
      message: 'Готовность не определена.',
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }

  const isFake = options.adapterMode === 'fake';
  let provableState = /** @type {DiagnosticProvableState} */ ('unknown');
  if (!isFake) {
    if (verdict.level === SystemCheckLevel.READY) {
      provableState = 'green';
    } else if (verdict.level === SystemCheckLevel.NOT_READY) {
      provableState = 'red';
    } else if (verdict.level === SystemCheckLevel.LIMITED) {
      provableState = 'red';
    } else if (
      verdict.level === SystemCheckLevel.FAILED
      || verdict.level === SystemCheckLevel.NO_ROUTER
    ) {
      provableState = 'unknown';
    }
  } else {
    provableState = 'unknown';
  }

  let hubState = verdict.hubState;
  if (
    provableState === 'unknown'
    && (verdict.level === SystemCheckLevel.FAILED || verdict.level === SystemCheckLevel.NO_ROUTER)
  ) {
    hubState = HubState.EMPTY;
  }

  return {
    id: ROUTER_ROW_ID,
    group: DIAGNOSTICS_GROUP_ROUTER,
    title: 'Роутер',
    message:
      provableState === 'unknown'
        ? sanitizeUnknownDiagnosticMessage(
            verdict.description ?? verdict.title,
            'Состояние связи не определено.',
          )
        : (verdict.description ?? verdict.title),
    hubState,
    provableState,
    technical: verdict.reasonCode ? `reason_code: ${verdict.reasonCode}` : null,
  };
}

/**
 * @param {import('./wifi-ap-model.js').ParsedObservedAccessPoint|null|undefined} observed
 * @param {{ title: string, apId: string|null, loading?: boolean, readinessReason?: string|null, apMissing?: boolean, adapterMode?: string|null, enabledOrUp?: boolean|null }} params
 * @returns {DiagnosticRow}
 */
export function buildWifiRowFromObserved(observed, params) {
  const rowId = params.title.includes('Гост') ? GUEST_WIFI_ROW_ID : STAFF_WIFI_ROW_ID;

  if (params.loading) {
    return {
      id: rowId,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: params.title,
      message: 'Чтение состояния точки доступа…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
      apId: params.apId,
    };
  }

  if (params.apMissing) {
    return {
      id: rowId,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: params.title,
      message: 'Точка доступа для этой роли не назначена.',
      hubState: HubState.UNSUPPORTED,
      provableState: 'unknown',
      technical: null,
      apId: null,
    };
  }

  if (params.readinessReason) {
    return {
      id: rowId,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: params.title,
      message: params.readinessReason,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
      apId: params.apId,
    };
  }

  if (!observed || !observed.readable) {
    return {
      id: rowId,
      group: DIAGNOSTICS_GROUP_ROUTER,
      title: params.title,
      message: observed?.ssidLabel ?? DIAGNOSTICS_WIFI_STATE_UNKNOWN_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: observed?.technicalLines?.join('\n') ?? null,
      apId: params.apId,
    };
  }

  const enabledOrUp =
    params.enabledOrUp === true || params.enabledOrUp === false ? params.enabledOrUp : null;
  const ssid = observed.ssid != null ? observed.ssid : null;
  const isFake = params.adapterMode === 'fake';

  let provableState = /** @type {DiagnosticProvableState} */ ('unknown');
  let hubState = HubState.EMPTY;
  if (!isFake) {
    if (enabledOrUp === true && ssid != null) {
      provableState = 'green';
      hubState = HubState.SUCCESS;
    } else if (enabledOrUp === false) {
      provableState = 'red';
      hubState = HubState.ERROR;
    }
  }

  return {
    id: rowId,
    group: DIAGNOSTICS_GROUP_ROUTER,
    title: params.title,
    message: ssid ?? observed.ssidLabel,
    hubState,
    provableState,
    technical: observed.technicalLines?.join('\n') ?? null,
    apId: params.apId,
    ssid,
  };
}

/**
 * @param {ReturnType<typeof describeHostInternetProbe>} described
 * @param {{ loading?: boolean }} [options]
 * @returns {DiagnosticRow}
 */
export function buildHostInternetRow(described, options = {}) {
  if (options.loading) {
    return {
      id: HOST_INTERNET_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Интернет с компьютера оператора',
      message: 'Проверка…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
    };
  }
  const provableState =
    described.factState === 'confirmed'
      ? 'green'
      : described.factState === 'refuted'
        ? 'red'
        : 'unknown';
  const message =
    provableState === 'unknown'
      ? messageForHostProbeRow(
          described,
          'Проверка интернета не выполнялась — данные не получены.',
        )
      : described.message;
  return {
    id: HOST_INTERNET_ROW_ID,
    group: DIAGNOSTICS_GROUP_HOST,
    title: described.title,
    message,
    hubState: provableState === 'unknown' ? HubState.EMPTY : described.hubState,
    provableState,
    technical: described.technical || null,
  };
}

/**
 * @param {ReturnType<typeof describeHostHttpProbe>|null} described
 * @param {{ loading?: boolean, skipped?: boolean, skipReason?: string|null, failed?: boolean, failureReason?: string|null }} [options]
 * @returns {DiagnosticRow}
 */
export function buildLocalAppHttpRow(described, options = {}) {
  if (options.failed) {
    return {
      id: LOCAL_APP_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Локальное приложение',
      message: options.failureReason ?? DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }
  if (options.skipped) {
    return {
      id: LOCAL_APP_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Локальное приложение',
      message: options.skipReason ?? LOCAL_APP_ADDRESS_MISSING_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }
  if (options.loading) {
    return {
      id: LOCAL_APP_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Локальное приложение',
      message: 'Проверка…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
    };
  }
  const provableState =
    described && described.factState === 'confirmed'
      ? 'green'
      : described && described.factState === 'refuted'
        ? 'red'
        : 'unknown';
  const message =
    provableState === 'unknown'
      ? messageForHostProbeRow(
          described ?? { factState: 'unknown', message: '' },
          DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE,
        )
      : described?.message ?? DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE;
  return {
    id: LOCAL_APP_ROW_ID,
    group: DIAGNOSTICS_GROUP_HOST,
    title: 'Локальное приложение',
    message,
    hubState: provableState === 'unknown' ? HubState.EMPTY : described.hubState,
    provableState,
    technical: described.technical || null,
  };
}

/**
 * @param {ReturnType<typeof describeHostTlsProbe>|null} described
 * @param {{ loading?: boolean, skipped?: boolean, skipReason?: string|null, failed?: boolean, failureReason?: string|null }} [options]
 * @returns {DiagnosticRow}
 */
export function buildLocalAppTlsRow(described, options = {}) {
  if (options.failed) {
    return {
      id: LOCAL_TLS_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Сертификат локального приложения',
      message: options.failureReason ?? DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }
  if (options.skipped) {
    return {
      id: LOCAL_TLS_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Сертификат локального приложения',
      message: options.skipReason ?? LOCAL_APP_ADDRESS_MISSING_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }
  if (options.loading) {
    return {
      id: LOCAL_TLS_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Сертификат локального приложения',
      message: 'Проверка…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
    };
  }
  const provableState =
    described && described.factState === 'confirmed'
      ? 'green'
      : described && described.factState === 'refuted'
        ? 'red'
        : 'unknown';
  const message =
    provableState === 'unknown'
      ? messageForHostProbeRow(
          described ?? { factState: 'unknown', message: '' },
          DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE,
        )
      : described?.message ?? DIAGNOSTICS_PROBE_INCOMPLETE_MESSAGE;
  return {
    id: LOCAL_TLS_ROW_ID,
    group: DIAGNOSTICS_GROUP_HOST,
    title: 'Сертификат локального приложения',
    message,
    hubState: provableState === 'unknown' ? HubState.EMPTY : described.hubState,
    provableState,
    technical: described.technical || null,
  };
}

/**
 * @param {ReturnType<typeof parseSelfCheckResult>['operatorRender']|null} operatorRender
 * @param {{ loading?: boolean, skipped?: boolean, skipReason?: string|null, failed?: boolean, failureReason?: string|null }} [options]
 * @returns {DiagnosticRow}
 */
export function buildEntryPageRow(operatorRender, options = {}) {
  if (options.failed) {
    return {
      id: ENTRY_PAGE_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Страница входа',
      message: options.failureReason ?? DIAGNOSTICS_ENTRY_PAGE_INCOMPLETE_MESSAGE,
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }
  if (options.skipped) {
    return {
      id: ENTRY_PAGE_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Страница входа',
      message: options.skipReason ?? 'Гостевая страница входа не создана — проверка не выполнялась.',
      hubState: HubState.EMPTY,
      provableState: 'unknown',
      technical: null,
    };
  }
  if (options.loading) {
    return {
      id: ENTRY_PAGE_ROW_ID,
      group: DIAGNOSTICS_GROUP_HOST,
      title: 'Страница входа',
      message: 'Проверка…',
      hubState: HubState.LOADING,
      provableState: 'loading',
      technical: null,
    };
  }
  const provableState =
    operatorRender && operatorRender.hubState === HubState.SUCCESS
      ? 'green'
      : operatorRender && operatorRender.hubState === HubState.ERROR
        ? 'red'
        : 'unknown';
  const message =
    provableState === 'unknown'
      ? sanitizeUnknownDiagnosticMessage(
          operatorRender?.message,
          operatorRender?.hubState === HubState.EMPTY && operatorRender?.message?.includes('не опубликована')
            ? operatorRender.message
            : 'Проверка страницы входа не выполнялась — данные не получены.',
        )
      : operatorRender?.message ?? DIAGNOSTICS_ENTRY_PAGE_INCOMPLETE_MESSAGE;
  return {
    id: ENTRY_PAGE_ROW_ID,
    group: DIAGNOSTICS_GROUP_HOST,
    title: 'Страница входа',
    message,
    hubState: provableState === 'unknown' ? HubState.EMPTY : operatorRender?.hubState ?? HubState.EMPTY,
    provableState,
    technical: null,
  };
}

/**
 * @returns {DiagnosticRow[]}
 */
export function buildUnsupportedGroupRows() {
  return UNSUPPORTED_ROWS.map((item) => ({
    id: item.id,
    group: DIAGNOSTICS_GROUP_UNSUPPORTED,
    title: item.title,
    message: item.message,
    hubState: HubState.UNSUPPORTED,
    provableState: /** @type {DiagnosticProvableState} */ ('unsupported'),
    technical: null,
  }));
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @param {Record<string, unknown>|null|undefined} revisionDocument
 * @param {string|null|undefined} [revisionIdOverride]
 * @returns {{ presetId: string, revisionId: string, hasAddress: boolean, missingReason: string|null }}
 */
export function resolveLocalApplicationProbeContext(session, revisionDocument, revisionIdOverride) {
  const presetId =
    session && typeof session.eventPresetId === 'string' ? session.eventPresetId.trim() : '';
  if (!presetId) {
    return {
      presetId: '',
      revisionId: '',
      hasAddress: false,
      missingReason: DIAGNOSTICS_PRESET_MISSING_MESSAGE,
    };
  }
  const revisionId =
    typeof revisionIdOverride === 'string' && revisionIdOverride.trim()
      ? revisionIdOverride.trim()
      : revisionDocument && typeof revisionDocument.revision_id === 'string'
        ? revisionDocument.revision_id
        : '';
  const doc =
    revisionDocument && typeof revisionDocument.canonical_document === 'object'
      ? /** @type {Record<string, unknown>} */ (revisionDocument.canonical_document)
      : null;
  const localOrderUrl =
    doc && typeof doc.local_order_url === 'string' ? doc.local_order_url.trim() : '';
  if (!localOrderUrl) {
    return {
      presetId,
      revisionId,
      hasAddress: false,
      missingReason: LOCAL_APP_ADDRESS_MISSING_MESSAGE,
    };
  }
  if (!revisionId) {
    return {
      presetId,
      revisionId: '',
      hasAddress: false,
      missingReason: 'Ревизия настроек мероприятия не найдена — проверка не выполнялась.',
    };
  }
  return { presetId, revisionId, hasAddress: true, missingReason: null };
}

/**
 * @param {unknown} value
 * @returns {unknown}
 */
function sanitizeExportString(value) {
  if (typeof value !== 'string') {
    return value;
  }
  let out = value;
  for (const blocked of EXPORT_FORBIDDEN_KEYS) {
    const pattern = new RegExp(`${blocked}\\s*[:=]\\s*\\S+`, 'gi');
    out = out.replace(pattern, `${blocked}: [redacted]`);
  }
  return out;
}

/**
 * @param {unknown} value
 * @param {string} keyPath
 * @returns {unknown}
 */
function sanitizeExportValue(value, keyPath) {
  if (typeof value === 'string') {
    return sanitizeExportString(value);
  }
  if (value == null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item, index) => sanitizeExportValue(item, `${keyPath}[${index}]`));
  }
  /** @type {Record<string, unknown>} */
  const out = {};
  for (const [key, nested] of Object.entries(/** @type {Record<string, unknown>} */ (value))) {
    const lower = key.toLowerCase();
    if (EXPORT_FORBIDDEN_KEYS.some((blocked) => lower.includes(blocked))) {
      continue;
    }
    out[key] = sanitizeExportValue(nested, keyPath ? `${keyPath}.${key}` : key);
  }
  return out;
}

/**
 * @param {DiagnosticsSnapshot|null|undefined} snapshot
 * @returns {Record<string, unknown>|null}
 */
export function buildDiagnosticsExportReport(snapshot) {
  if (!snapshot) {
    return null;
  }
  const payload = {
    exported_at: snapshot.checkedAt ? snapshot.checkedAt.toISOString() : null,
    adapter_mode: snapshot.adapterMode,
    counter: snapshot.counter,
    banner: {
      tone: snapshot.bannerTone,
      title: snapshot.bannerTitle,
      message: snapshot.bannerMessage,
    },
    rows: snapshot.rows.map((row) => ({
      id: row.id,
      group: row.group,
      title: row.title,
      message: row.message,
      hub_state: row.hubState,
      provable_state: row.provableState,
      ap_id: row.apId ?? null,
      ssid: row.ssid ?? null,
      technical: row.technical,
    })),
    system_check: snapshot.systemVerdict
      ? {
          level: snapshot.systemVerdict.level,
          hub_state: snapshot.systemVerdict.hubState,
          reason_code: snapshot.systemVerdict.reasonCode,
          mock: snapshot.systemVerdict.mock,
          facts: snapshot.systemVerdict.facts?.map((fact) => ({
            id: fact.id,
            value: fact.value,
            tone: fact.tone,
          })),
        }
      : null,
    technical_lines: snapshot.technicalLines,
  };
  return /** @type {Record<string, unknown>} */ (sanitizeExportValue(payload, ''));
}

/**
 * @param {Record<string, unknown>|null|undefined} report
 * @returns {string[]}
 */
export function findForbiddenExportKeys(report) {
  /** @type {string[]} */
  const hits = [];
  /** @param {unknown} node @param {string} path */
  function walk(node, path) {
    if (node == null || typeof node !== 'object') {
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((item, index) => walk(item, `${path}[${index}]`));
      return;
    }
    for (const key of Object.keys(/** @type {Record<string, unknown>} */ (node))) {
      const lower = key.toLowerCase();
      if (EXPORT_FORBIDDEN_KEYS.some((blocked) => lower.includes(blocked))) {
        hits.push(path ? `${path}.${key}` : key);
      }
      walk(/** @type {Record<string, unknown>} */ (node)[key], path ? `${path}.${key}` : key);
    }
  }
  walk(report, '');
  return hits;
}

/**
 * @param {Partial<DiagnosticsSnapshot>} parts
 * @param {string|null|undefined} adapterMode
 * @returns {DiagnosticsSnapshot}
 */
/**
 * @param {DiagnosticRow[]} rows
 * @returns {boolean}
 */
export function hasLoadingDiagnosticRows(rows) {
  return rows.some((row) => row.provableState === 'loading');
}

/**
 * @param {{ tone: 'success'|'warning'|'danger'|'neutral', title: string, message: string|null }} banner
 * @param {DiagnosticRow[]} rows
 * @returns {{ tone: 'success'|'warning'|'danger'|'neutral', title: string, message: string|null }}
 */
export function blockSuccessBannerWhileRowsLoading(banner, rows) {
  if (!hasLoadingDiagnosticRows(rows) || banner.tone !== 'success') {
    return banner;
  }
  return {
    tone: 'neutral',
    title: 'Проверка выполняется',
    message: banner.message ?? 'Дождитесь завершения всех проверок.',
  };
}

export function assembleDiagnosticsSnapshot(parts, adapterMode) {
  const allRows = parts.rows ?? [];
  const group1 = allRows.filter((row) => row.group === DIAGNOSTICS_GROUP_ROUTER);
  const counter = computeReadinessCounter(group1, adapterMode);
  const rawBanner = computeSummaryBanner({
    systemVerdict: parts.systemVerdict ?? null,
    counter,
    adapterMode,
    group1Rows: group1,
  });
  const banner = blockSuccessBannerWhileRowsLoading(rawBanner, allRows);
  const runComplete = parts.runComplete === true;
  /** @type {string[]} */
  const technicalLines = [];
  if (parts.systemVerdict?.reasonCode) {
    technicalLines.push(`system_check.reason_code: ${parts.systemVerdict.reasonCode}`);
  }
  for (const row of allRows) {
    if (row.technical) {
      technicalLines.push(`${row.id}: ${row.technical}`);
    }
  }
  return {
    rows: allRows,
    systemVerdict: parts.systemVerdict ?? null,
    counter,
    bannerTone: banner.tone,
    bannerTitle: banner.title,
    bannerMessage: banner.message,
    checkedAt: runComplete && parts.checkedAt instanceof Date ? parts.checkedAt : null,
    technicalLines,
    adapterMode: adapterMode ?? null,
  };
}

/**
 * @param {number} expectedGeneration
 * @param {number} currentGeneration
 * @returns {boolean}
 */
export function shouldAcceptDiagnosticsGeneration(expectedGeneration, currentGeneration) {
  return expectedGeneration === currentGeneration;
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isAborted(err) {
  if (err instanceof HubApiError && err.code === 'client.aborted') {
    return true;
  }
  return err instanceof DOMException && err.name === 'AbortError';
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isUnauthorized(err) {
  return err instanceof HubApiError && err.kind === ERROR_KIND.UNAUTHORIZED;
}

/**
 * @param {AbortSignal|undefined|null} parent
 * @param {AbortController} child
 */
function linkAbortSignals(parent, child) {
  if (!parent) {
    return;
  }
  if (parent.aborted) {
    child.abort();
    return;
  }
  parent.addEventListener('abort', () => child.abort(), { once: true });
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @param {string|null|undefined} adapterMode
 * @returns {string|null}
 */
function wifiObservedReadinessReason(session, adapterMode) {
  const readiness = evaluateStaffWifiObservedReadiness(session, adapterMode);
  if (readiness.complete) {
    return null;
  }
  if (readiness.missing?.length) {
    return `Для проверки не хватает параметров подключения: ${readiness.missing.join(', ')}.`;
  }
  return 'Параметры для чтения состояния Wi‑Fi не готовы.';
}

/**
 * Чтение observed-state с теми же параметрами, что staff/guest wifi models.
 * @param {{ apId: string, session: import('../core/session.js').SessionSnapshot|null|undefined, adapterMode?: string|null, signal?: AbortSignal }} params
 * @returns {Promise<{ observed: import('./wifi-ap-model.js').ParsedObservedAccessPoint, enabledOrUp: boolean|null }>}
 */
async function fetchWifiObservedForDiagnostics(params) {
  const { apId, session, adapterMode, signal } = params;
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
  const payload = first && typeof first === 'object' ? /** @type {Record<string, unknown>} */ (first) : {};
  const enabledOrUp =
    typeof payload.enabled_or_up === 'boolean' ? payload.enabled_or_up : null;
  return {
    observed: parseObservedAccessPoint(first),
    enabledOrUp,
  };
}

/**
 * @param {{
 *   session: import('../core/session.js').SessionSnapshot|null|undefined,
 *   adapterMode?: string|null,
 *   hostKeyConfirmed?: boolean,
 *   routerPresent?: boolean|null,
 *   routerId?: string|null,
 *   signal?: AbortSignal,
 *   generation?: number,
 *   isGenerationCurrent?: (generation: number) => boolean,
 *   onProgress?: (snapshot: DiagnosticsSnapshot) => void,
 * }} params
 * @returns {Promise<DiagnosticsSnapshot>}
 */
export async function runDiagnosticsChecks(params) {
  const {
    session,
    adapterMode = null,
    hostKeyConfirmed = false,
    routerPresent,
    routerId = session?.routerId ?? null,
    signal,
    generation = 0,
    isGenerationCurrent = (gen) => gen === generation,
    onProgress,
  } = params;

  const accept = () => isGenerationCurrent(generation);

  const emitProgress = () => {
    if (typeof onProgress !== 'function' || !accept()) {
      return;
    }
    onProgress(
      assembleDiagnosticsSnapshot(
        {
          rows: [...rows],
          systemVerdict,
          checkedAt,
          runComplete: false,
        },
        adapterMode,
      ),
    );
  };

  const runAbort = new AbortController();
  linkAbortSignals(signal, runAbort);
  const effectiveSignal = runAbort.signal;

  /** @type {HubApiError|null} */
  let authFailure = null;

  /**
   * @param {unknown} err
   * @returns {never|null}
   */
  function handleRunError(err) {
    if (isAborted(err)) {
      if (authFailure) {
        throw authFailure;
      }
      throw err;
    }
    if (!accept()) {
      throw err;
    }
    if (isUnauthorized(err) && !authFailure) {
      authFailure = err;
      runAbort.abort();
      throw authFailure;
    }
    return null;
  }

  /** @type {DiagnosticRow[]} */
  const rows = [
    buildRouterRowFromVerdict(null, { loading: true, adapterMode }),
    buildCredentialsRow(null),
    buildWifiRowFromObserved(null, { title: 'Рабочая сеть', apId: null, loading: true }),
    buildWifiRowFromObserved(null, { title: 'Гостевая сеть', apId: null, loading: true }),
    buildRouterInternetRowFromObserve(null, { loading: true }),
    buildHostInternetRow(describeHostInternetProbe(null), { loading: true }),
    buildLocalAppHttpRow(describeHostHttpProbe(null), { loading: true }),
    buildLocalAppTlsRow(describeHostTlsProbe(null), { loading: true }),
    buildEntryPageRow(parseSelfCheckResult(null).operatorRender, { loading: true }),
    ...buildUnsupportedGroupRows(),
  ];

  let systemVerdict = null;
  let checkedAt = null;

  try {
    systemVerdict = await runSystemCheck({
      routerId,
      routerPresent,
      hostKeyConfirmed,
      adapterMode,
      signal: effectiveSignal,
    });
    if (!accept()) {
      throw new DOMException('Aborted', 'AbortError');
    }
    checkedAt = systemVerdict.checkedAt;

    const credentialsPresent = systemVerdict.facts.find((f) => f.id === 'credentials_present')?.value ?? null;

    rows[0] = buildRouterRowFromVerdict(systemVerdict, { adapterMode });
    rows[1] = buildCredentialsRow(credentialsPresent);
    emitProgress();

    const staffApId = session?.wifiRoles?.staffApId ?? null;
    const guestApId = session?.wifiRoles?.guestApId ?? null;
    const wifiReadinessReason = wifiObservedReadinessReason(session, adapterMode);

    /** @type {Promise<void>[]} */
    const phaseB = [];

    phaseB.push(
      (async () => {
        try {
          if (!staffApId) {
            rows[2] = buildWifiRowFromObserved(null, {
              title: 'Рабочая сеть',
              apId: null,
              apMissing: true,
              adapterMode,
            });
            return;
          }
          if (wifiReadinessReason) {
            rows[2] = buildWifiRowFromObserved(null, {
              title: 'Рабочая сеть',
              apId: staffApId,
              readinessReason: wifiReadinessReason,
              adapterMode,
            });
            return;
          }
          try {
            const { observed, enabledOrUp } = await fetchWifiObservedForDiagnostics({
              apId: staffApId,
              session,
              adapterMode,
              signal: effectiveSignal,
            });
            if (!accept()) return;
            rows[2] = buildWifiRowFromObserved(observed, {
              title: 'Рабочая сеть',
              apId: staffApId,
              adapterMode,
              enabledOrUp,
            });
          } catch (err) {
            handleRunError(err);
            rows[2] = buildWifiRowFromObserved(null, {
              title: 'Рабочая сеть',
              apId: staffApId,
              readinessReason: DIAGNOSTICS_WIFI_STATE_UNKNOWN_MESSAGE,
              adapterMode,
            });
          }
        } finally {
          emitProgress();
        }
      })(),
    );

    phaseB.push(
      (async () => {
        try {
          if (!guestApId) {
            rows[3] = buildWifiRowFromObserved(null, {
              title: 'Гостевая сеть',
              apId: null,
              apMissing: true,
              adapterMode,
            });
            return;
          }
          if (wifiReadinessReason) {
            rows[3] = buildWifiRowFromObserved(null, {
              title: 'Гостевая сеть',
              apId: guestApId,
              readinessReason: wifiReadinessReason,
              adapterMode,
            });
            return;
          }
          try {
            const { observed, enabledOrUp } = await fetchWifiObservedForDiagnostics({
              apId: guestApId,
              session,
              adapterMode,
              signal: effectiveSignal,
            });
            if (!accept()) return;
            rows[3] = buildWifiRowFromObserved(observed, {
              title: 'Гостевая сеть',
              apId: guestApId,
              adapterMode,
              enabledOrUp,
            });
          } catch (err) {
            handleRunError(err);
            rows[3] = buildWifiRowFromObserved(null, {
              title: 'Гостевая сеть',
              apId: guestApId,
              readinessReason: DIAGNOSTICS_WIFI_STATE_UNKNOWN_MESSAGE,
              adapterMode,
            });
          }
        } finally {
          emitProgress();
        }
      })(),
    );

    phaseB.push(
      (async () => {
        try {
          const observed = await fetchRouterInternetObserve({
            session,
            signal: effectiveSignal,
          });
          if (!accept()) return;
          rows[4] = buildRouterInternetRowFromObserve(observed);
        } catch (err) {
          handleRunError(err);
          rows[4] = buildRouterInternetRowFromObserve({ read_status: 'failed' });
        } finally {
          emitProgress();
        }
      })(),
    );

    phaseB.push(
      (async () => {
        try {
          const response = await probeOperatorHostInternet({ signal: effectiveSignal });
          if (!accept()) return;
          rows[5] = buildHostInternetRow(describeHostInternetProbe(response));
        } catch (err) {
          handleRunError(err);
          rows[5] = buildHostInternetRow(describeHostInternetProbe(null));
        } finally {
          emitProgress();
        }
      })(),
    );

    phaseB.push(
      (async () => {
        try {
          const presetId =
            session && typeof session.eventPresetId === 'string' ? session.eventPresetId.trim() : '';
          if (!presetId) {
            rows[6] = buildLocalAppHttpRow(null, {
              skipped: true,
              skipReason: DIAGNOSTICS_PRESET_MISSING_MESSAGE,
            });
            rows[7] = buildLocalAppTlsRow(null, {
              skipped: true,
              skipReason: DIAGNOSTICS_PRESET_MISSING_MESSAGE,
            });
            return;
          }
          try {
            const presetMeta = await loadEventPreset({ presetId, signal: effectiveSignal });
            if (!accept()) return;
            const metaRecord =
              presetMeta && typeof presetMeta === 'object'
                ? /** @type {Record<string, unknown>} */ (presetMeta)
                : {};
            const revisionId =
              typeof metaRecord.current_revision_id === 'string'
                ? metaRecord.current_revision_id
                : '';
            let revisionPayload = null;
            if (revisionId) {
              revisionPayload = await loadEventPresetRevision({ presetId, revisionId, signal: effectiveSignal });
              if (!accept()) return;
            }
            const probeContext = resolveLocalApplicationProbeContext(session, revisionPayload, revisionId);
            if (!probeContext.hasAddress) {
              rows[6] = buildLocalAppHttpRow(null, {
                skipped: true,
                skipReason: probeContext.missingReason,
              });
              rows[7] = buildLocalAppTlsRow(null, {
                skipped: true,
                skipReason: probeContext.missingReason,
              });
              return;
            }
            const [httpResponse, tlsResponse] = await Promise.all([
              probeLocalApplicationHttp({
                presetId: probeContext.presetId,
                revisionId: probeContext.revisionId,
                signal: effectiveSignal,
              }),
              probeLocalApplicationTls({
                presetId: probeContext.presetId,
                revisionId: probeContext.revisionId,
                signal: effectiveSignal,
              }),
            ]);
            if (!accept()) return;
            rows[6] = buildLocalAppHttpRow(describeHostHttpProbe(httpResponse));
            rows[7] = buildLocalAppTlsRow(describeHostTlsProbe(tlsResponse));
          } catch (err) {
            handleRunError(err);
            rows[6] = buildLocalAppHttpRow(null, { failed: true });
            rows[7] = buildLocalAppTlsRow(null, { failed: true });
          }
        } finally {
          emitProgress();
        }
      })(),
    );

    phaseB.push(
      (async () => {
        try {
          const listPayload = await listEntryPages({ signal: effectiveSignal });
          if (!accept()) return;
          const items = Array.isArray(listPayload?.items) ? listPayload.items : [];
          const guestPage = findPageByAudience(items, ENTRY_AUDIENCE_GUEST);
          if (!guestPage || typeof guestPage.page_id !== 'string') {
            rows[8] = buildEntryPageRow(null, {
              skipped: true,
            });
            return;
          }
          const selfPayload = await selfCheckEntryPage(guestPage.page_id, { signal: effectiveSignal });
          if (!accept()) return;
          rows[8] = buildEntryPageRow(parseSelfCheckResult(selfPayload).operatorRender);
        } catch (err) {
          handleRunError(err);
          rows[8] = buildEntryPageRow(null, { failed: true });
        } finally {
          emitProgress();
        }
      })(),
    );

    await Promise.all(phaseB);
    if (authFailure) {
      throw authFailure;
    }
    if (!accept()) {
      throw new DOMException('Aborted', 'AbortError');
    }
  } catch (err) {
    if (isAborted(err) || !accept()) {
      throw err;
    }
    if (isUnauthorized(err)) {
      throw err;
    }
    if (!systemVerdict) {
      throw err;
    }
    rows[0] = buildRouterRowFromVerdict(systemVerdict, { adapterMode });
  }

  return assembleDiagnosticsSnapshot(
    {
      rows,
      systemVerdict,
      checkedAt,
      runComplete: true,
    },
    adapterMode,
  );
}

export { DOMAIN_HOST_PROBE_SCOPE_LABEL };
