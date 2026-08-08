/**
 * Модель экрана «Интернет» — подключение роутера к внешней Wi‑Fi сети (station/uplink).
 */

import { apiPost, apiRequest } from '../core/api.js';
import { HubState } from '../core/states.js';
import { createIdempotencyKey } from './connection-flow.js';
import { buildLiveConnectionParams } from './live-connection-params.js';
import {
  evaluateWifiMutationReadiness,
  registerWifiApCredential,
  revokeWifiApCredential,
} from './wifi-ap-model.js';

/** @typedef {'BAND_2_4GHZ'|'BAND_5GHZ'} UplinkWifiBand */
/** @typedef {'WifiMaster0'|'WifiMaster1'} UplinkSurveyRadio */

/** @typedef {{ ssid: string, band: UplinkWifiBand, password: string }} UplinkWifiFormDraft */

/** @typedef {{ ssid: string, band: UplinkWifiBand, surveyRadio: UplinkSurveyRadio, bandLabel: string, wpaMode: string|null, rssi: number|null, channel: number|null, open: boolean }} ParsedSurveyNetwork */

/** @typedef {{ hubState: string, success: boolean, title: string, message: string, technicalLines: string[] }} UplinkApplyVerdict */

/** @typedef {{ allowed: boolean, reasonText: string|null, missing: string[], mock: boolean }} UplinkMutationReadiness */

/** @typedef {{
 *   router_id?: string|null,
 *   mode?: string,
 *   ssid?: string,
 *   band?: UplinkWifiBand|string,
 *   station_id?: string|null,
 *   credential_ref_id?: string|null,
 *   credential_configured?: boolean,
 *   desired_active?: boolean,
 *   updated_at?: string,
 * }} RememberedUplinkPreference */

export const UPLINK_WIFI_STATION_MODE = 'WifiWan';
export const UPLINK_WIFI_DEFAULT_PRIORITY = 100;
export const UPLINK_WIFI_DEFAULT_SETTLE_SECONDS = 25;

/** Client fetch timeout for wifi/station/apply and wifi/station/teardown (ms). Matches KeenDNS/wifi apply parity (60s). */
export const UPLINK_WIFI_APPLY_TEARDOWN_TIMEOUT_MS = 60000;

export const UPLINK_WIFI_DISTINCTION_NOTE =
  'Здесь роутер сам подключается к чужой Wi‑Fi сети, чтобы получить интернет. Это не то же самое, что «Рабочая сеть» и «Гостевой Wi‑Fi» — те разделы настраивают сети, которые роутер раздаёт другим устройствам.';

export const UPLINK_WIFI_SCAN_NOTE =
  'Нажмите «Найти сети» — приложение просканирует эфир на обеих частотах (2,4 и 5 ГГц). Можно также ввести название сети вручную.';

export const UPLINK_WIFI_PASSWORD_FIELD_NOTE =
  'Пароль нужен для подключения роутера к выбранной сети. Он сохраняется только на сервере управления — на планшете не остаётся.';

export const UPLINK_WIFI_NO_OPEN_NETWORK_NOTE =
  'Сеть без пароля подключить нельзя — выберите защищённую сеть или укажите другую.';

export const UPLINK_WIFI_SETTLE_WAIT_NOTE =
  'После отправки команды роутеру нужно 20–30 секунд на проверку интернета. Не закрывайте экран, пока идёт подключение.';

export const UPLINK_WIFI_OPEN_NETWORK_BLOCKED_MESSAGE =
  'Эта сеть без пароля — роутер к ней подключиться не может. Выберите другую сеть или введите название защищённой сети вручную.';

export const UPLINK_WIFI_INTENT_STALE_MESSAGE =
  'Пока вы подтверждали действие, название сети, частота или пароль изменились — повторите подключение.';

/** Автопереподключение uplink — честный runtime-текст (не «проверено на устройстве»). */
export function describeUplinkAutoReconnectNote({
  watchdogEnabled = false,
  watchdogRunning = null,
  pollSeconds = null,
  desiredActive = null,
} = {}) {
  if (watchdogEnabled === null) {
    return 'Состояние автопереподключения неизвестно — не удалось загрузить статус с сервера управления.';
  }
  if (!watchdogEnabled) {
    return 'Автоматическое переподключение выключено — при обрыве Wi‑Fi uplink восстановите связь вручную на этом экране.';
  }
  if (desiredActive === true) {
    let note =
      'Автоматическое переподключение включено в сервере управления — повтор при обрыве без ручного подтверждения команды; работа на роутере не подтверждена.';
    if (watchdogRunning === true) {
      note += ' Цикл опроса на сервере управления работает.';
    } else if (watchdogRunning === false) {
      note += ' Цикл опроса на сервере управления сейчас не работает.';
    }
    if (typeof pollSeconds === 'number' && Number.isFinite(pollSeconds) && pollSeconds > 0) {
      note += ` Интервал опроса: ${Math.round(pollSeconds)} с.`;
    }
    return note;
  }
  if (desiredActive === false) {
    let note =
      'Процесс автопереподключения на сервере управления может быть включён, но запомненного намерения нет — при обрыве Wi‑Fi uplink сам не восстановит; сохраните сеть с автоподключением на этом экране.';
    if (watchdogRunning === true) {
      note += ' Цикл опроса на сервере управления работает.';
    } else if (watchdogRunning === false) {
      note += ' Цикл опроса на сервере управления сейчас не работает.';
    }
    if (typeof pollSeconds === 'number' && Number.isFinite(pollSeconds) && pollSeconds > 0) {
      note += ` Интервал опроса: ${Math.round(pollSeconds)} с.`;
    }
    return note;
  }
  let note =
    'Автоматическое переподключение включено в сервере управления, но намерение автоподключения ещё не загружено — при обрыве Wi‑Fi uplink неизвестно, восстановится ли связь без ручного подтверждения; работа на роутере не подтверждена.';
  if (watchdogRunning === true) {
    note += ' Цикл опроса на сервере управления работает.';
  } else if (watchdogRunning === false) {
    note += ' Цикл опроса на сервере управления сейчас не работает.';
  }
  if (typeof pollSeconds === 'number' && Number.isFinite(pollSeconds) && pollSeconds > 0) {
    note += ` Интервал опроса: ${Math.round(pollSeconds)} с.`;
  }
  return note;
}

/** @type {readonly UplinkSurveyRadio[]} */
export const UPLINK_SURVEY_RADIOS = Object.freeze(['WifiMaster0', 'WifiMaster1']);

/** @type {Readonly<Record<UplinkSurveyRadio, UplinkWifiBand>>} */
export const RADIO_TO_BAND = Object.freeze({
  WifiMaster0: 'BAND_2_4GHZ',
  WifiMaster1: 'BAND_5GHZ',
});

/** @type {Readonly<Record<UplinkWifiBand, UplinkSurveyRadio>>} */
export const BAND_TO_RADIO = Object.freeze({
  BAND_2_4GHZ: 'WifiMaster0',
  BAND_5GHZ: 'WifiMaster1',
});

/** @type {Readonly<Record<UplinkWifiBand, string>>} */
const BAND_LABELS_RU = Object.freeze({
  BAND_2_4GHZ: '2,4 ГГц',
  BAND_5GHZ: '5 ГГц',
});

/**
 * @param {UplinkSurveyRadio|string|null|undefined} radio
 * @returns {UplinkWifiBand|null}
 */
export function bandFromRadio(radio) {
  if (radio === 'WifiMaster0') return 'BAND_2_4GHZ';
  if (radio === 'WifiMaster1') return 'BAND_5GHZ';
  return null;
}

/**
 * @param {UplinkWifiBand|string|null|undefined} band
 * @returns {UplinkSurveyRadio|null}
 */
export function radioFromBand(band) {
  if (band === 'BAND_2_4GHZ') return 'WifiMaster0';
  if (band === 'BAND_5GHZ') return 'WifiMaster1';
  return null;
}

/**
 * @param {UplinkWifiBand|string|null|undefined} band
 * @returns {string}
 */
export function bandLabelRu(band) {
  if (band === 'BAND_2_4GHZ' || band === 'BAND_5GHZ') {
    return BAND_LABELS_RU[band];
  }
  return 'частота не указана';
}

/**
 * @param {Record<string, string|null>} liveParams
 * @param {Record<string, unknown>} body
 */
function attachLiveConnectionFields(liveParams, body) {
  if (liveParams.host) body.host = liveParams.host;
  if (liveParams.username) body.username = liveParams.username;
  if (liveParams.router_credential_ref_id) {
    body.router_credential_ref_id = liveParams.router_credential_ref_id;
  }
  if (liveParams.ssh_host_key_sha256) {
    body.ssh_host_key_sha256 = liveParams.ssh_host_key_sha256;
  }
  if (liveParams.source_address) body.source_address = liveParams.source_address;
  if (liveParams.router_id) body.router_id = liveParams.router_id;
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @param {UplinkSurveyRadio} radio
 * @returns {Record<string, unknown>}
 */
export function buildSiteSurveyBody(session, radio) {
  /** @type {Record<string, unknown>} */
  const body = { radio };
  const live = buildLiveConnectionParams(session);
  if (live.complete) {
    attachLiveConnectionFields(live.params, body);
  }
  return body;
}

/**
 * @param {{ ssid: string, band: UplinkWifiBand, credentialRefId: string, priority?: number }} params
 * @returns {Record<string, unknown>}
 */
export function buildStationPreviewBody({ ssid, band, credentialRefId, priority = UPLINK_WIFI_DEFAULT_PRIORITY }) {
  return {
    mode: UPLINK_WIFI_STATION_MODE,
    ssid: ssid.trim(),
    band,
    credential_ref_id: credentialRefId,
    priority,
    auth_mode: 'wpa2_psk',
  };
}

/**
 * @param {{ previewBody: Record<string, unknown>, session: import('../core/session.js').SessionSnapshot|null|undefined, uplinkSettleSeconds?: number }} params
 * @returns {Record<string, unknown>}
 */
export function buildStationApplyBody({
  previewBody,
  session,
  uplinkSettleSeconds = UPLINK_WIFI_DEFAULT_SETTLE_SECONDS,
}) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для подключения к интернету не хватает параметров живого подключения');
  }
  /** @type {Record<string, unknown>} */
  const body = {
    ...previewBody,
    confirm_live_apply: true,
    compensate_on_failure: true,
    idempotent: true,
    uplink_settle_seconds: uplinkSettleSeconds,
  };
  attachLiveConnectionFields(live.params, body);
  return body;
}

/**
 * @param {{ ssid: string, band: UplinkWifiBand, credentialRefId: string|null, session: import('../core/session.js').SessionSnapshot|null|undefined }} params
 * @returns {Record<string, unknown>}
 */
export function buildStationTeardownBody({ ssid, band, credentialRefId, session }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для отключения от внешней сети не хватает параметров живого подключения');
  }
  /** @type {Record<string, unknown>} */
  const body = {
    mode: UPLINK_WIFI_STATION_MODE,
    ssid: ssid.trim(),
    band,
    priority: UPLINK_WIFI_DEFAULT_PRIORITY,
    confirm_live_teardown: true,
  };
  if (credentialRefId) {
    body.credential_ref_id = credentialRefId;
  }
  attachLiveConnectionFields(live.params, body);
  return body;
}

/**
 * @param {unknown} network
 * @returns {boolean}
 */
export function isOpenSurveyNetwork(network) {
  const row = /** @type {Record<string, unknown>} */ (network ?? {});
  const wpaMode = typeof row.wpa_mode === 'string' ? row.wpa_mode.trim().toLowerCase() : '';
  if (wpaMode === 'open') return true;
  const authMode = typeof row.auth_mode === 'string' ? row.auth_mode.trim().toLowerCase() : '';
  if (authMode === 'open') return true;
  return row.open === true;
}

/**
 * @param {unknown} network
 * @param {UplinkSurveyRadio} surveyRadio
 * @returns {ParsedSurveyNetwork|null}
 */
export function parseSurveyNetwork(network, surveyRadio) {
  const row = /** @type {Record<string, unknown>} */ (network ?? {});
  const ssid = typeof row.ssid === 'string' ? row.ssid.trim() : '';
  if (!ssid) return null;
  const band = bandFromRadio(surveyRadio);
  if (!band) return null;
  const wpaMode = typeof row.wpa_mode === 'string' ? row.wpa_mode : null;
  const rssi = typeof row.rssi === 'number' ? row.rssi : null;
  const channel = typeof row.channel === 'number' ? row.channel : null;
  return {
    ssid,
    band,
    surveyRadio,
    bandLabel: bandLabelRu(band),
    wpaMode,
    rssi,
    channel,
    open: isOpenSurveyNetwork(row),
  };
}

/**
 * @param {Array<{ radio: UplinkSurveyRadio, networks: unknown[] }>} surveyResults
 * @returns {ParsedSurveyNetwork[]}
 */
export function mergeSurveyNetworks(surveyResults) {
  /** @type {ParsedSurveyNetwork[]} */
  const merged = [];
  /** @type {Set<string>} */
  const seen = new Set();
  for (const result of surveyResults) {
    const networks = Array.isArray(result.networks) ? result.networks : [];
    for (const network of networks) {
      const parsed = parseSurveyNetwork(network, result.radio);
      if (!parsed) continue;
      const key = `${parsed.ssid}\0${parsed.band}`;
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(parsed);
    }
  }
  merged.sort((left, right) => {
    const leftRssi = left.rssi ?? -999;
    const rightRssi = right.rssi ?? -999;
    return rightRssi - leftRssi;
  });
  return merged;
}

/**
 * @param {ParsedSurveyNetwork} network
 * @returns {string}
 */
export function formatSurveyNetworkLabel(network) {
  const signal =
    typeof network.rssi === 'number' ? `, сигнал ${network.rssi}` : '';
  const openSuffix = network.open ? ' — без пароля, подключить нельзя' : '';
  return `«${network.ssid}» (${network.bandLabel}${signal})${openSuffix}`;
}

/**
 * @param {unknown} response
 * @param {{ intent?: 'apply'|'teardown' }} [options]
 * @returns {UplinkApplyVerdict}
 */
export function parseUplinkApplyVerdict(response, { intent = 'apply' } = {}) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const overall = typeof payload.overall === 'string' ? payload.overall : 'failed';
  const uplinkStatus =
    typeof payload.uplink_verification_status === 'string'
      ? payload.uplink_verification_status
      : 'uplink_dispatched_unverified';
  const errors = Array.isArray(payload.errors)
    ? payload.errors.filter((item) => typeof item === 'string')
    : [];
  const verdictExplanation =
    payload.verdict_explanation && typeof payload.verdict_explanation === 'object'
      ? /** @type {Record<string, unknown>} */ (payload.verdict_explanation)
      : null;
  const explanationText =
    typeof verdictExplanation?.summary === 'string' ? verdictExplanation.summary : null;

  /** @type {string[]} */
  const technicalLines = [`overall: ${overall}`, `uplink_verification_status: ${uplinkStatus}`];
  if (errors.length > 0) {
    technicalLines.push(`errors: ${errors.join(', ')}`);
  }
  if (explanationText) {
    technicalLines.push(`verdict_explanation: ${explanationText}`);
  }
  if (payload.uplink_settle_seconds != null) {
    technicalLines.push(`uplink_settle_seconds: ${String(payload.uplink_settle_seconds)}`);
  }

  if (intent === 'teardown') {
    if (overall === 'applied' && uplinkStatus === 'uplink_verified_bounded') {
      return {
        hubState: HubState.SUCCESS,
        success: true,
        title: 'Отключено от внешней сети',
        message: 'Роутер отключён от сети, через которую получал интернет',
        technicalLines,
      };
    }
    if (overall === 'applied' && uplinkStatus === 'uplink_dispatched_unverified') {
      return {
        hubState: HubState.WARNING,
        success: false,
        title: 'Отключение не подтверждено',
        message:
          'Команда принята роутером, но отключение не проверено — это не считается успешным отключением',
        technicalLines,
      };
    }
    if (overall === 'verify_mismatch') {
      return {
        hubState: HubState.WARNING,
        success: false,
        title: 'Проверка не совпала',
        message: 'Роутер принял команду, но проверка отключения не совпала с ожиданием',
        technicalLines,
      };
    }
    if (overall === 'applied') {
      return {
        hubState: HubState.WARNING,
        success: false,
        title: 'Отключение не подтверждено',
        message:
          'Роутер принял команду, но отключение не подтверждено — это не считается успехом',
        technicalLines,
      };
    }
    if (overall === 'rolled_back') {
      return {
        hubState: HubState.WARNING,
        success: false,
        title: 'Отключение не завершено',
        message: 'Роутер не подтвердил отключение — прежние настройки могли сохраниться',
        technicalLines,
      };
    }
    return {
      hubState: HubState.ERROR,
      success: false,
      title: 'Не удалось отключить',
      message: 'Не удалось отключить роутер от внешней сети',
      technicalLines,
    };
  }

  if (overall === 'applied' && uplinkStatus === 'uplink_verified_bounded') {
    return {
      hubState: HubState.SUCCESS,
      success: true,
      title: 'Интернет подключён',
      message:
        'Роутер подключился к выбранной сети — интернет подтверждён в ограниченной проверке (не все сценарии проверены)',
      technicalLines,
    };
  }

  if (overall === 'applied' && uplinkStatus === 'uplink_associated_no_global') {
    return {
      hubState: HubState.WARNING,
      success: false,
      title: 'Сеть найдена, интернет не настроен',
      message:
        'Роутер связался с сетью, но маршрут в интернет не подтверждён — это не считается успешным подключением',
      technicalLines,
    };
  }

  if (overall === 'applied' && uplinkStatus === 'uplink_dispatched_unverified') {
    return {
      hubState: HubState.WARNING,
      success: false,
      title: 'Подключение не подтверждено',
      message:
        'Команда принята роутером, но интернет не проверен — это не считается успешным подключением',
      technicalLines,
    };
  }

  if (uplinkStatus === 'uplink_failed' || overall === 'failed') {
    return {
      hubState: HubState.ERROR,
      success: false,
      title: 'Не удалось подключиться',
      message: 'Роутер не смог подключиться к выбранной сети для интернета',
      technicalLines,
    };
  }

  if (overall === 'verify_mismatch') {
    return {
      hubState: HubState.WARNING,
      success: false,
      title: 'Проверка не совпала',
      message: 'Роутер принял команду, но проверка подключения не совпала с ожиданием',
      technicalLines,
    };
  }

  if (overall === 'rolled_back') {
    return {
      hubState: HubState.WARNING,
      success: false,
      title: 'Подключение отменено',
      message: 'Роутер не подтвердил подключение — система вернула прежние настройки',
      technicalLines,
    };
  }

  if (overall === 'dispatched_offline') {
    return {
      hubState: HubState.WARNING,
      success: false,
      title: 'Команда не отправлена на роутер',
      message: 'Подключение выполнено без связи с роутером — на устройстве настройки не менялись',
      technicalLines,
    };
  }

  if (overall === 'applied') {
    return {
      hubState: HubState.WARNING,
      success: false,
      title: 'Интернет не подтверждён',
      message: 'Роутер принял команду, но интернет не подтверждён — это не считается успехом',
      technicalLines,
    };
  }

  return {
    hubState: HubState.ERROR,
    success: false,
    title: 'Не удалось подключиться',
    message: 'Не удалось подключить роутер к выбранной сети для интернета',
    technicalLines,
  };
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot
 * @param {string|null|undefined} adapterMode
 * @returns {UplinkMutationReadiness}
 */
export function evaluateUplinkWifiMutationReadiness(snapshot, adapterMode) {
  return evaluateWifiMutationReadiness(snapshot, adapterMode);
}

/**
 * @param {{ ssid: string, password: string, openNetwork?: boolean }} params
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateUplinkWifiForm({ ssid, password, openNetwork = false }) {
  /** @type {string[]} */
  const errors = [];
  const trimmedSsid = typeof ssid === 'string' ? ssid.trim() : '';
  const trimmedPassword = typeof password === 'string' ? password.trim() : '';

  if (!trimmedSsid) {
    errors.push('Укажите название сети');
  } else if (trimmedSsid.length > 32) {
    errors.push('Название сети не длиннее 32 символов');
  }

  if (openNetwork) {
    errors.push(UPLINK_WIFI_OPEN_NETWORK_BLOCKED_MESSAGE);
  } else if (trimmedPassword.length < 8) {
    errors.push('Пароль сети — не короче 8 символов');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * @param {{ draft: UplinkWifiFormDraft, openNetwork?: boolean, mutationReadiness?: UplinkMutationReadiness|null }} params
 * @returns {{ canConnect: boolean, canTeardown: boolean }}
 */
export function buildUplinkWifiScreenState({ draft, openNetwork = false, mutationReadiness = null }) {
  const validation = validateUplinkWifiForm({
    ssid: draft.ssid,
    password: draft.password,
    openNetwork,
  });
  const canMutate = mutationReadiness?.allowed === true;
  return {
    canConnect: Boolean(validation.valid && canMutate),
    canTeardown: Boolean(canMutate && draft.ssid.trim().length > 0),
  };
}

/**
 * @param {{ ssid: string, band: UplinkWifiBand, hasPassword: boolean }} snapshot
 * @returns {{ ssid: string, band: UplinkWifiBand, hasPassword: boolean }}
 */
export function buildUplinkIntentSnapshot({ ssid, band, hasPassword }) {
  return {
    ssid: typeof ssid === 'string' ? ssid.trim() : '',
    band,
    hasPassword: hasPassword === true,
  };
}

/**
 * @param {{ ssid: string, band: UplinkWifiBand, hasPassword: boolean }} confirmed
 * @param {{ ssid: string, band: UplinkWifiBand, hasPassword: boolean }} current
 * @returns {boolean}
 */
export function uplinkIntentMatchesCurrent(confirmed, current) {
  return (
    confirmed.ssid === current.ssid
    && confirmed.band === current.band
    && confirmed.hasPassword === current.hasPassword
  );
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @param {AbortSignal|undefined} signal
 * @returns {Promise<ParsedSurveyNetwork[]>}
 */
export async function scanUplinkWifiNetworks(session, signal) {
  /** @type {Array<{ radio: UplinkSurveyRadio, networks: unknown[] }>} */
  const partial = [];
  /** @type {unknown[]} */
  const radioFailures = [];

  for (const radio of UPLINK_SURVEY_RADIOS) {
    try {
      const body = buildSiteSurveyBody(session, radio);
      const response = /** @type {{ networks?: unknown[] }} */ (
        await apiPost('wifi/site-survey', body, { signal })
      );
      partial.push({
        radio,
        networks: Array.isArray(response?.networks) ? response.networks : [],
      });
    } catch (error) {
      radioFailures.push({ radio, error });
    }
  }

  const merged = mergeSurveyNetworks(partial);
  if (merged.length === 0 && radioFailures.length === UPLINK_SURVEY_RADIOS.length) {
    throw radioFailures[0].error;
  }
  return merged;
}

/**
 * @param {{ previewBody: Record<string, unknown>, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export async function previewUplinkWifiConnection({ previewBody, signal }) {
  return apiPost('wifi/station/preview', previewBody, { signal });
}

/**
 * @param {{ previewBody: Record<string, unknown>, session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export async function applyUplinkWifiConnection({ previewBody, session, signal }) {
  const body = buildStationApplyBody({ previewBody, session });
  return apiPost('wifi/station/apply', body, { signal, timeoutMs: UPLINK_WIFI_APPLY_TEARDOWN_TIMEOUT_MS });
}

/**
 * @param {{ ssid: string, band: UplinkWifiBand, credentialRefId: string|null, session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export async function teardownUplinkWifiConnection({ ssid, band, credentialRefId, session, signal }) {
  const body = buildStationTeardownBody({ ssid, band, credentialRefId, session });
  return apiPost('wifi/station/teardown', body, { signal, timeoutMs: UPLINK_WIFI_APPLY_TEARDOWN_TIMEOUT_MS });
}

/**
 * @param {{ routerId: string, secret: string, signal?: AbortSignal }} params
 * @returns {Promise<string>}
 */
export async function registerUplinkWifiCredential({ routerId, secret, signal }) {
  const response = await registerWifiApCredential({
    routerId,
    secret,
    idempotencyKey: createIdempotencyKey(),
    signal,
  });
  const refId =
    typeof response?.credential_ref_id === 'string' ? response.credential_ref_id.trim() : '';
  if (!refId) {
    throw new Error('Сервер не вернул ссылку на пароль');
  }
  return refId;
}

export { revokeWifiApCredential };

/**
 * @param {UplinkWifiBand|string|null|undefined} band
 * @returns {string|null}
 */
export function stationIdForUplinkBand(band) {
  if (band === 'BAND_2_4GHZ') return 'WifiMaster0/WifiStation0';
  if (band === 'BAND_5GHZ') return 'WifiMaster1/WifiStation0';
  return null;
}

/**
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<RememberedUplinkPreference>}
 */
export async function fetchRememberedUplink({ signal } = {}) {
  return /** @type {Promise<RememberedUplinkPreference>} */ (
    await apiRequest('remembered-uplink', { signal })
  );
}

/**
 * @param {Record<string, unknown>} body
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<RememberedUplinkPreference>}
 */
export async function updateRememberedUplink(body, { signal } = {}) {
  return /** @type {Promise<RememberedUplinkPreference>} */ (
    await apiRequest('remembered-uplink', { method: 'PUT', body, signal })
  );
}

/**
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<RememberedUplinkPreference>}
 */
export async function forgetRememberedUplink({ signal } = {}) {
  return /** @type {Promise<RememberedUplinkPreference>} */ (
    await apiRequest('remembered-uplink', { method: 'DELETE', signal })
  );
}

/**
 * @param {{
 *   routerId: string,
 *   ssid: string,
 *   band: UplinkWifiBand,
 *   credentialRefId: string,
 *   signal?: AbortSignal,
 * }} params
 * @returns {Promise<RememberedUplinkPreference>}
 */
export async function persistRememberedUplinkAfterApply({
  routerId,
  ssid,
  band,
  credentialRefId,
  signal,
}) {
  return updateRememberedUplink(
    {
      router_id: routerId,
      ssid: ssid.trim(),
      band,
      station_id: stationIdForUplinkBand(band),
      credential_ref_id: credentialRefId,
      desired_active: true,
    },
    { signal },
  );
}

/**
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<RememberedUplinkPreference>}
 */
export async function deactivateRememberedUplink({ signal } = {}) {
  return updateRememberedUplink({ desired_active: false }, { signal });
}
