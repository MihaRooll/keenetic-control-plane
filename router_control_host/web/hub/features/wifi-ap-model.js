/**
 * Общая модель Wi‑Fi точки доступа — данные и сетевые вызовы без DOM.
 */

import { apiGet, apiPost, apiRequest, API_BASE } from '../core/api.js';
import {
  HubApiError,
  ERROR_KIND,
  resolveErrorEntry,
  resolveHttpStatusEntry,
} from '../core/errors.js';
import { HubState } from '../core/states.js';
import { createIdempotencyKey } from './connection-flow.js';
import {
  buildLiveConnectionParams,
  needsLiveConnectionParamsForState,
} from './live-connection-params.js';

/** @typedef {'WPA2'|'WPA3'|'WPA2_WPA3_MIXED'} WifiWpaMode */

/** @typedef {{ apId: string, label: string, band: 'BAND_2_4GHZ'|'BAND_5GHZ', bandLabel: string, pointNumber: number }} WifiApOption */

/** @typedef {{ ssid: string, wpaMode: WifiWpaMode|'', password: string }} WifiFormDraft */

/** @typedef {{ ssid?: string, wpaMode?: WifiWpaMode|'', enabled?: boolean|null }} WifiApplyReadbackExpectation */

/** @typedef {{ refId: string, apId: string, ssid: string, passwordFingerprint: string, idempotencyKey: string }} WifiCredentialRefCache */

/** @typedef {{ staff_ssid: string, guest_default_ssid: string, staff_password_credential_ref_id: string|null, staff_password_configured: boolean, guest_default_enabled: boolean, staff_ap_id: string|null, guest_ap_id: string|null, updated_at: string }} StandingNetworkPreferences */

/** @typedef {{ apId: string, band: string, bandIntent: 'BAND_2_4GHZ'|'BAND_5GHZ', ssid: string|null, ssidLabel: string, activeLabel: string, activeTone: 'success'|'neutral'|'warning', wpaMode: string, wpaModeLabel: string, readable: boolean, keyConfigured: boolean|null, technicalLines: string[], hubState: string }} ParsedObservedAccessPoint */

/** @typedef {{ hubState: string, success: boolean, refreshObserved: boolean, title: string, message: string, technicalLines: string[] }} WifiApplyVerdict */

/** @typedef {{ allowed: boolean, reasonText: string|null, missing: string[], mock: boolean }} WifiMutationReadiness */

/** Заголовок панели, когда observed-state не прочитан. */
export const WIFI_OBSERVED_UNREADABLE_TITLE = 'Состояние сети не прочитано';

/** Пояснение панели непрочитанного состояния. */
export const WIFI_OBSERVED_UNREADABLE_DESCRIPTION =
  'Роутер не отдал текущие настройки выбранной сети. Ниже можно задать параметры и включить или выключить сеть, но мы не знаем, что именно заменится на устройстве.';

/** Заголовок, когда apply прошёл, но повторное чтение не удалось. */
export const WIFI_APPLY_READBACK_FAILED_TITLE = 'Изменение отправлено, проверить не удалось';

/** Сообщение, когда apply прошёл, но повторное чтение не удалось. */
export const WIFI_APPLY_READBACK_FAILED_MESSAGE =
  'Роутер принял команду, но текущее состояние сети прочитать не удалось. Проверьте настройки вручную или нажмите «Повторить».';

/** Заголовок подтверждённого успеха после readback. */
export const WIFI_APPLY_READBACK_CONFIRMED_TITLE = 'Сохранено и проверено';

/** Заголовок подтверждённого выключения после readback. */
export const WIFI_TEARDOWN_READBACK_CONFIRMED_TITLE = 'Сеть выключена';

/** Сообщение при расхождении подтверждённого и текущего намерения. */
export const WIFI_MUTATION_INTENT_STALE_MESSAGE =
  'Настройки изменились после подтверждения. Просмотрите изменения и подтвердите заново.';

/** Apply отправлен, но пароль в CP зарегистрирован, а apply на роутер не прошёл (не readback). */
export const WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE =
  'Новый пароль сохранён в системе управления, но команда на роутер не выполнена. Повторите сохранение или проверьте связь с роутером.';

/** Заголовок промежуточного readback-poll. */
export const WIFI_APPLY_READBACK_VERIFYING_TITLE = 'Проверяем изменения на роутере';

/** Сообщение промежуточного readback-poll. */
export const WIFI_APPLY_READBACK_VERIFYING_MESSAGE =
  'Ждём, пока роутер применит настройки и отдаст актуальное состояние. Это может занять до 25 секунд.';

/**
 * Интервал между повторными чтениями observed-state после apply.
 * Согласовано с L-13 (ENGINEERING_LESSONS): одно мгновенное чтение врёт.
 */
export const WIFI_READBACK_POLL_INTERVAL_MS = 2000;

/**
 * Максимальное ожидание сходимости observed-state после apply (мс).
 * 25 с — середина lab-окна 20–30 с для settle/readback (см. ENGINEERING_LESSONS L-13).
 */
export const WIFI_READBACK_POLL_TIMEOUT_MS = 25000;

/** Клиентское сообщение при ошибке регистрации пароля (без echo сервера). */
export const WIFI_CREDENTIAL_REGISTRATION_FAILED_MESSAGE =
  'Не удалось сохранить новый пароль для сети.';

export const WIFI_CREDENTIAL_REGISTRATION_FAILED_ACTION =
  'Проверьте связь и повторите попытку.';

export const WIFI_CREDENTIAL_REF_MISSING_MESSAGE =
  'Не удалось получить ссылку на пароль — повторите попытку.';

/** Допустимые режимы защиты в форме. */
export const WPA_MODE_OPTIONS = Object.freeze([
  { value: 'WPA2', label: 'WPA2' },
  { value: 'WPA3', label: 'WPA3' },
  { value: 'WPA2_WPA3_MIXED', label: 'WPA2 и WPA3 вместе' },
]);

/** Placeholder для формы, когда текущая защита не прочитана. */
export const WPA_MODE_DRAFT_PLACEHOLDER_OPTION = Object.freeze({
  value: '',
  label: '— выберите —',
  disabled: true,
});

/** Точки доступа 3–6 на обоих диапазонах (без AP0/AP1). */
const ACCESS_POINT_NUMBERS = Object.freeze([3, 4, 5, 6]);

/** @type {Readonly<Record<string, { band: 'BAND_2_4GHZ'|'BAND_5GHZ', bandLabel: string }>>} */
const MASTER_BAND_MAP = Object.freeze({
  WifiMaster0: { band: 'BAND_2_4GHZ', bandLabel: '2,4 ГГц' },
  WifiMaster1: { band: 'BAND_5GHZ', bandLabel: '5 ГГц' },
});

/** @type {Readonly<Set<string>>} */
const KNOWN_OBSERVED_WPA_MODES = new Set(['WPA2', 'WPA3', 'WPA2_WPA3_MIXED']);

/** @type {Readonly<Record<string, string>>} */
const OBSERVED_WPA_MODE_LABELS = Object.freeze({
  WPA2: 'WPA2',
  WPA3: 'WPA3',
  WPA2_WPA3_MIXED: 'WPA2 и WPA3 вместе',
  not_configured: 'Защита не настроена',
  unrecognized: 'Защита не распознана',
  unknown: 'Защита неизвестна',
});

/** @type {Readonly<Record<string, string>>} */
const LIVE_FIELD_LABELS = Object.freeze({
  host: 'адрес роутера',
  username: 'имя пользователя',
  router_credential_ref_id: 'сохранённые учётные данные',
  ssh_host_key_sha256: 'отпечаток ключа устройства',
  source_address: 'локальный адрес этого компьютера',
});

/**
 * @param {string} apId
 * @returns {'BAND_2_4GHZ'|'BAND_5GHZ'|null}
 */
export function bandFromApId(apId) {
  if (typeof apId !== 'string') {
    return null;
  }
  const master = apId.split('/')[0];
  return MASTER_BAND_MAP[master]?.band ?? null;
}

/**
 * @returns {WifiApOption[]}
 */
export function listWifiApOptions() {
  /** @type {WifiApOption[]} */
  const options = [];
  for (const [master, meta] of Object.entries(MASTER_BAND_MAP)) {
    for (const pointNumber of ACCESS_POINT_NUMBERS) {
      options.push({
        apId: `${master}/AccessPoint${pointNumber}`,
        label: `Сеть №${pointNumber} — ${meta.bandLabel}`,
        band: meta.band,
        bandLabel: meta.bandLabel,
        pointNumber,
      });
    }
  }
  return options;
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot
 * @returns {string[]}
 */
function formatMissingLiveFields(snapshot) {
  const live = buildLiveConnectionParams(snapshot);
  if (live.complete) {
    return [];
  }
  return live.missing.map((field) => LIVE_FIELD_LABELS[field] ?? field);
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot
 * @param {string|null|undefined} adapterMode
 * @returns {WifiMutationReadiness}
 */
export function evaluateWifiMutationReadiness(snapshot, adapterMode) {
  const mock = adapterMode === 'fake';
  if (mock) {
    return {
      allowed: false,
      reasonText: 'В демонстрационном режиме изменения сети недоступны',
      missing: [],
      mock: true,
    };
  }

  const missing = formatMissingLiveFields(snapshot);
  if (missing.length > 0) {
    return {
      allowed: false,
      reasonText:
        'Чтобы менять сеть, сначала завершите подключение к роутеру на экране «Подключение»',
      missing,
      mock: false,
    };
  }

  return {
    allowed: true,
    reasonText: null,
    missing: [],
    mock: false,
  };
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot
 * @param {string|null|undefined} adapterMode
 * @returns {{ complete: boolean, missing: string[] }}
 */
export function evaluateWifiObservedReadiness(snapshot, adapterMode) {
  if (!needsLiveConnectionParamsForState(adapterMode)) {
    return { complete: true, missing: [] };
  }
  const missing = formatMissingLiveFields(snapshot);
  return { complete: missing.length === 0, missing };
}

/**
 * @param {{ apIds: string[], liveParams?: Record<string, string|null>|null }} params
 * @returns {Record<string, unknown>}
 */
export function buildObservedStateRequestBody({ apIds, liveParams }) {
  /** @type {Record<string, unknown>} */
  const body = { ap_ids: apIds };
  if (liveParams) {
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
  return body;
}

/**
 * @param {unknown} raw
 * @returns {ParsedObservedAccessPoint}
 */
export function parseObservedAccessPoint(raw) {
  const payload = /** @type {Record<string, unknown>} */ (raw ?? {});
  const apId = typeof payload.ap_id === 'string' ? payload.ap_id : '';
  const bandIntent = bandFromApId(apId) ?? 'BAND_2_4GHZ';
  const readable = payload.readable === true;
  const ssidRaw = typeof payload.ssid === 'string' ? payload.ssid : null;
  const enabledOrUp = payload.enabled_or_up === true;
  const linkUp = payload.link_up === true;
  const wpaMode = typeof payload.wpa_mode === 'string' ? payload.wpa_mode : 'unknown';
  const deviceConnected = payload.device_connected;

  let ssidLabel = 'Название сети не прочитано';
  if (!readable) {
    ssidLabel = 'Состояние не прочитано';
  } else if (ssidRaw && ssidRaw.trim()) {
    ssidLabel = ssidRaw.trim();
  }

  let activeLabel = 'Состояние не прочитано';
  let activeTone = /** @type {'success'|'neutral'|'warning'} */ ('neutral');
  let hubState = HubState.WARNING;
  if (readable) {
    if (enabledOrUp && linkUp) {
      activeLabel = 'Включена';
      activeTone = 'success';
      hubState = HubState.SUCCESS;
    } else if (enabledOrUp || linkUp) {
      activeLabel = 'Работает не полностью';
      activeTone = 'warning';
      hubState = HubState.WARNING;
    } else {
      activeLabel = 'Выключена';
      activeTone = 'neutral';
      hubState = HubState.EMPTY;
    }
  }

  /** @type {string[]} */
  const technicalLines = [`Идентификатор точки: ${apId || 'неизвестен'}`];
  if (typeof payload.band === 'string') {
    technicalLines.push(`Диапазон (observed): ${payload.band}`);
  }
  if (deviceConnected === true || deviceConnected === false) {
    technicalLines.push(
      `признак активности клиентов (device_connected): ${deviceConnected ? 'true' : 'false'}`,
    );
  }

  return {
    apId,
    band: typeof payload.band === 'string' ? payload.band : 'unknown',
    bandIntent,
    ssid: ssidRaw,
    ssidLabel,
    activeLabel,
    activeTone,
    wpaMode,
    wpaModeLabel: OBSERVED_WPA_MODE_LABELS[wpaMode] ?? OBSERVED_WPA_MODE_LABELS.unknown,
    readable,
    keyConfigured: typeof payload.key_configured === 'boolean' ? payload.key_configured : null,
    technicalLines,
    hubState,
  };
}

/**
 * @param {ParsedObservedAccessPoint|null|undefined} observed
 * @returns {boolean}
 */
export function isObservedWpaModeKnown(observed) {
  return KNOWN_OBSERVED_WPA_MODES.has(observed?.wpaMode ?? '');
}

/**
 * @param {WifiWpaMode|''|null|undefined} wpaMode
 * @returns {boolean}
 */
export function isWifiWpaModeDraftSelected(wpaMode) {
  return KNOWN_OBSERVED_WPA_MODES.has(wpaMode ?? '');
}

/**
 * @param {ParsedObservedAccessPoint|null|undefined} observed
 * @returns {string}
 */
export function wpaFieldHint(observed) {
  if (isObservedWpaModeKnown(observed)) {
    return '';
  }
  return 'Текущая защита не прочитана — по умолчанию WPA2';
}

/**
 * @param {ParsedObservedAccessPoint|null|undefined} observed
 * @returns {{ description: string, checked: boolean, unknown: boolean }}
 */
export function describeWifiNetworkToggle(observed) {
  if (!observed?.readable) {
    return { description: 'Состояние не прочитано', checked: false, unknown: true };
  }
  if (observed.activeLabel === 'Включена') {
    return { description: 'Включена', checked: true, unknown: false };
  }
  if (observed.activeLabel === 'Выключена') {
    return { description: 'Выключена', checked: false, unknown: false };
  }
  return { description: observed.activeLabel, checked: false, unknown: true };
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @returns {boolean}
 */
export function shouldResetWifiFormAfterMutation(verdict) {
  return verdict?.success === true;
}

/**
 * Whether Wi-Fi form password fields should be cleared after mutation.
 * Uses the final readback verdict — not the pre-readback apply `success` flag.
 *
 * @param {{ lastVerdict: WifiApplyVerdict|null|undefined }} params
 * @returns {boolean}
 */
export function shouldClearWifiFormPasswordAfterMutation({ lastVerdict }) {
  return Boolean(lastVerdict?.success) && shouldResetWifiFormAfterMutation(lastVerdict);
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @returns {boolean}
 */
export function shouldRefreshWifiObservedAfterMutation(verdict) {
  return verdict?.refreshObserved === true;
}

/**
 * @param {number} requestGeneration
 * @param {number} currentGeneration
 * @returns {boolean}
 */
export function shouldAcceptWifiObservedResult(requestGeneration, currentGeneration) {
  return requestGeneration === currentGeneration;
}

/**
 * @param {{ apId: string, ssid: string, wpaMode: WifiWpaMode, hasNewPassword: boolean }} params
 * @returns {{ apId: string, ssid: string, wpaMode: WifiWpaMode, hasNewPassword: boolean }}
 */
export function buildWifiMutationIntentSnapshot({ apId, ssid, wpaMode, hasNewPassword }) {
  return {
    apId,
    ssid: typeof ssid === 'string' ? ssid.trim() : '',
    wpaMode,
    hasNewPassword: Boolean(hasNewPassword),
  };
}

/**
 * @param {{ apId: string|null, draft: WifiFormDraft, hasNewPassword: boolean }} params
 * @returns {ReturnType<typeof buildWifiMutationIntentSnapshot>|null}
 */
export function currentWifiMutationIntentFromDraft({ apId, draft, hasNewPassword }) {
  if (!apId) {
    return null;
  }
  return buildWifiMutationIntentSnapshot({
    apId,
    ssid: draft.ssid,
    wpaMode: draft.wpaMode,
    hasNewPassword,
  });
}

/**
 * @param {ReturnType<typeof buildWifiMutationIntentSnapshot>|null|undefined} snapshot
 * @param {ReturnType<typeof buildWifiMutationIntentSnapshot>|null|undefined} current
 * @returns {boolean}
 */
export function wifiMutationIntentMatchesCurrent(snapshot, current) {
  if (!snapshot || !current) {
    return false;
  }
  return (
    snapshot.apId === current.apId &&
    snapshot.ssid === current.ssid &&
    snapshot.wpaMode === current.wpaMode &&
    snapshot.hasNewPassword === current.hasNewPassword
  );
}

/**
 * @param {ParsedObservedAccessPoint|null|undefined} observed
 * @returns {boolean}
 */
export function isWifiObservedUnreadable(observed) {
  return Boolean(observed && observed.readable !== true);
}

/**
 * @param {ParsedObservedAccessPoint|null|undefined} observed
 * @returns {WifiFormDraft}
 */
export function createWifiFormDraft(observed) {
  /** @type {WifiWpaMode|''} */
  const wpaMode = isObservedWpaModeKnown(observed)
    ? /** @type {WifiWpaMode} */ (observed.wpaMode)
    : '';

  return {
    ssid: observed?.readable && observed?.ssid ? observed.ssid : '',
    wpaMode,
    password: '',
  };
}

/**
 * @param {{ ssid: string, password?: string, requirePassword?: boolean }} params
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateWifiApForm({
  ssid,
  password = '',
  requirePassword = false,
  wpaMode = undefined,
}) {
  /** @type {string[]} */
  const errors = [];
  const name = typeof ssid === 'string' ? ssid : '';

  if (!name.trim()) {
    errors.push('Укажите название сети');
  } else if (name !== name.trim()) {
    errors.push('Название сети не должно начинаться или заканчиваться пробелом');
  } else if (name.trim().length > 32) {
    errors.push('Название сети не должно быть длиннее 32 символов');
  }

  const secret = typeof password === 'string' ? password : '';
  if (requirePassword && !secret) {
    errors.push('Укажите пароль сети');
  } else if (secret && secret.length < 8) {
    errors.push('Пароль должен быть не короче 8 символов');
  } else if (secret.length > 63) {
    errors.push('Пароль должен быть не длиннее 63 символов');
  }

  if (wpaMode !== undefined && !isWifiWpaModeDraftSelected(wpaMode)) {
    errors.push('Выберите режим защиты');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * @param {string} value
 * @returns {Promise<string>}
 */
async function sha256Hex(value) {
  const data = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * @param {{ apId: string, secret: string }} params
 * @returns {Promise<string>}
 */
export async function buildWifiCredentialIdempotencyKey({ apId, secret }) {
  const digest = await sha256Hex(`WifiApPsk\0${secret}`);
  return `wifi-ap-psk-${apId}-${digest.slice(0, 32)}`;
}

/**
 * @param {{ routerId: string, apId: string, ssid: string, secret: string, cached: WifiCredentialRefCache|null, signal?: AbortSignal }} params
 * @returns {Promise<{ credentialRefId: string, cache: WifiCredentialRefCache }>}
 */
export async function ensureWifiCredentialRef({
  routerId,
  apId,
  ssid,
  secret,
  cached,
  signal,
}) {
  const trimmedSsid = typeof ssid === 'string' ? ssid.trim() : '';
  const passwordFingerprint = await sha256Hex(secret);

  if (
    cached
    && cached.apId === apId
    && cached.ssid === trimmedSsid
    && cached.passwordFingerprint === passwordFingerprint
    && cached.refId
  ) {
    return { credentialRefId: cached.refId, cache: cached };
  }

  const idempotencyKey = await buildWifiCredentialIdempotencyKey({ apId, secret });
  const credResponse = await registerWifiApCredential({
    routerId,
    secret,
    idempotencyKey,
    signal,
  });
  const refId =
    typeof credResponse?.credential_ref_id === 'string'
      ? credResponse.credential_ref_id
      : null;
  if (!refId) {
    throw new HubApiError({
      code: 'client.unknown',
      httpStatus: null,
      userMessage: WIFI_CREDENTIAL_REF_MISSING_MESSAGE,
      userAction: 'Повторите попытку.',
      serverMessage: null,
      details: [],
      requestId: null,
      correlationId: null,
      kind: ERROR_KIND.UNKNOWN,
    });
  }

  const supersededRefId = cached?.refId;
  if (supersededRefId && supersededRefId !== refId) {
    await revokeWifiApCredential({
      routerId,
      credentialRefId: supersededRefId,
      signal,
    });
  }

  return {
    credentialRefId: refId,
    cache: {
      refId,
      apId,
      ssid: trimmedSsid,
      passwordFingerprint,
      idempotencyKey,
    },
  };
}

/**
 * @param {{ apId: string, ssid: string, wpaMode: WifiWpaMode, enabled: boolean, credentialRefId?: string|null, band?: 'BAND_2_4GHZ'|'BAND_5GHZ'|null }} params
 * @returns {Record<string, unknown>}
 */
export function buildWifiPreviewBody({ apId, ssid, wpaMode, enabled, credentialRefId, band = null }) {
  const resolvedBand = band ?? bandFromApId(apId);
  if (!resolvedBand) {
    throw new Error('Не удалось определить диапазон для выбранной точки доступа');
  }

  /** @type {Record<string, unknown>} */
  const body = {
    ap_id: apId,
    ssid: ssid.trim(),
    enabled,
    captive_portal: 'Disabled',
    guest_isolation: false,
    wpa_mode: wpaMode,
    band: resolvedBand,
  };

  if (credentialRefId) {
    body.credential_ref_id = credentialRefId;
  }

  return body;
}

/**
 * @param {{ action: 'save'|'enable'|'restart', observed: ParsedObservedAccessPoint|null|undefined, networkTogglePending: boolean|null|undefined }} params
 * @returns {boolean}
 */
export function deriveWifiPreviewEnabled({ action, observed, networkTogglePending }) {
  if (networkTogglePending === false) {
    return false;
  }
  if (networkTogglePending === true) {
    return true;
  }
  if (observed?.readable && observed.activeLabel === 'Выключена') {
    return action === 'enable';
  }
  return action === 'save' || action === 'enable' || action === 'restart';
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @param {boolean|null} readbackOk
 * @returns {WifiApplyVerdict|null|undefined}
 */
export function evaluateWifiApplyReadback({ observed, observedError, expected }) {
  if (observedError || !expected) {
    return null;
  }
  if (!observed?.readable) {
    return null;
  }
  const trimmedExpectedSsid =
    typeof expected.ssid === 'string' ? expected.ssid.trim() : '';
  const observedSsid = typeof observed.ssid === 'string' ? observed.ssid.trim() : '';
  if (!trimmedExpectedSsid || observedSsid !== trimmedExpectedSsid) {
    return false;
  }
  if (
    !isObservedWpaModeKnown(observed)
    || !isWifiWpaModeDraftSelected(expected.wpaMode)
    || observed.wpaMode !== expected.wpaMode
  ) {
    return false;
  }
  if (typeof expected.enabled === 'boolean') {
    const observedEnabled = observed.activeLabel === 'Включена';
    if (observedEnabled !== expected.enabled) {
      return false;
    }
  }
  return true;
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @returns {boolean}
 */
export function isWifiConfigurationApplied(verdict) {
  if (!verdict) {
    return false;
  }
  if (verdict.success === true) {
    return true;
  }
  return (
    Array.isArray(verdict.technicalLines)
    && verdict.technicalLines.some((line) => line.startsWith('overall: applied'))
  );
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @returns {boolean}
 */
function isWifiVerifyMismatchVerdict(verdict) {
  return (
    Array.isArray(verdict?.technicalLines)
    && verdict.technicalLines.some((line) => line.startsWith('overall: verify_mismatch'))
  );
}

/**
 * Server-side honest warning: client readback poll must not upgrade to full success.
 *
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @returns {boolean}
 */
function isWifiServerHonestWarningVerdict(verdict) {
  if (isWifiVerifyMismatchVerdict(verdict)) {
    return true;
  }
  if (!Array.isArray(verdict?.technicalLines)) {
    return false;
  }
  return verdict.technicalLines.some(
    (line) =>
      line.startsWith('on_air_verification_status: on_air_unverified')
      || line.startsWith('on_air_verification_status: on_air_admin_only'),
  );
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @returns {boolean}
 */
export function shouldPollWifiApplyReadback(verdict) {
  if (!verdict) {
    return false;
  }
  if (verdict.refreshObserved === true) {
    return true;
  }
  return isWifiConfigurationApplied(verdict);
}

/**
 * @returns {WifiApplyVerdict}
 */
export function buildWifiApplyReadbackVerifyingVerdict() {
  return {
    hubState: HubState.LOADING,
    success: false,
    refreshObserved: false,
    title: WIFI_APPLY_READBACK_VERIFYING_TITLE,
    message: WIFI_APPLY_READBACK_VERIFYING_MESSAGE,
    technicalLines: [],
  };
}

/**
 * @param {{ expected: { ssid?: string, wpaMode?: WifiWpaMode, enabled?: boolean }, observed: ParsedObservedAccessPoint|null, observedError: boolean }} params
 * @returns {string}
 */
export function buildWifiReadbackFailedMessage({ expected, observed, observedError }) {
  /** @type {string[]} */
  const parts = [
    'Роутер принял команду, но за отведённое время не удалось подтвердить совпадение по данным с устройства.',
  ];
  if (observedError) {
    parts.push('Повторное чтение состояния сети завершилось ошибкой.');
  } else if (!observed?.readable) {
    parts.push('Текущие настройки сети с роутера прочитать не удалось.');
  } else {
    parts.push(`Сравнение: ${describeWifiReadbackFieldComparison({ expected, observed })}.`);
  }
  parts.push(
    'Пароль Wi‑Fi с роутера прочитать нельзя — его применение ни подтверждено, ни опровергнуто.',
  );
  return parts.join(' ');
}

/**
 * @param {{ expected: { ssid?: string, wpaMode?: WifiWpaMode, enabled?: boolean }, observed: ParsedObservedAccessPoint }} params
 * @returns {string}
 */
export function describeWifiReadbackFieldComparison({ expected, observed }) {
  /** @type {string[]} */
  const items = [];
  const trimmedExpectedSsid =
    typeof expected.ssid === 'string' ? expected.ssid.trim() : '';
  const observedSsid =
    typeof observed.ssid === 'string' && observed.ssid.trim()
      ? observed.ssid.trim()
      : 'не прочитано';
  items.push(`название — ожидали «${trimmedExpectedSsid || '—'}», на роутере «${observedSsid}»`);
  const expectedWpa = isWifiWpaModeDraftSelected(expected.wpaMode) ? expected.wpaMode : '—';
  items.push(
    `защита — ожидали ${expectedWpa}, на роутере ${observed.wpaModeLabel ?? observed.wpaMode ?? 'неизвестно'}`,
  );
  if (typeof expected.enabled === 'boolean') {
    const expectedEnabled = expected.enabled ? 'включена' : 'выключена';
    let observedEnabled = 'неизвестно';
    if (observed.readable) {
      if (observed.activeLabel === 'Включена') {
        observedEnabled = 'включена';
      } else if (observed.activeLabel === 'Выключена') {
        observedEnabled = 'выключена';
      } else {
        observedEnabled = observed.activeLabel ?? 'неизвестно';
      }
    }
    items.push(`сеть — ожидали ${expectedEnabled}, на роутере ${observedEnabled}`);
  }
  return items.join('; ');
}

/**
 * @param {number} ms
 * @param {AbortSignal|undefined} signal
 * @returns {Promise<void>}
 */
function sleepMs(ms, signal) {
  if (ms <= 0) {
    return Promise.resolve();
  }
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new DOMException('Aborted', 'AbortError'));
      return;
    }
    const timer = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);
    const onAbort = () => {
      cleanup();
      reject(signal?.reason ?? new DOMException('Aborted', 'AbortError'));
    };
    const cleanup = () => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

function resolveWifiReadbackPollTiming(overrides = {}) {
  const testCfg = globalThis.__WIFI_READBACK_POLL_TEST_CONFIG__;
  return {
    intervalMs:
      typeof overrides.intervalMs === 'number'
        ? overrides.intervalMs
        : typeof testCfg?.intervalMs === 'number'
          ? testCfg.intervalMs
          : WIFI_READBACK_POLL_INTERVAL_MS,
    timeoutMs:
      typeof overrides.timeoutMs === 'number'
        ? overrides.timeoutMs
        : typeof testCfg?.timeoutMs === 'number'
          ? testCfg.timeoutMs
          : WIFI_READBACK_POLL_TIMEOUT_MS,
  };
}

/**
 * @param {{ fetchObserved: () => Promise<{ observed: ParsedObservedAccessPoint|null, observedError: boolean }>, expected: { ssid?: string, wpaMode?: WifiWpaMode, enabled?: boolean }|null|undefined, signal?: AbortSignal, intervalMs?: number, timeoutMs?: number, onPoll?: (details: { observed: ParsedObservedAccessPoint|null, observedError: boolean, attempt: number }) => void }} params
 * @returns {Promise<{ observed: ParsedObservedAccessPoint|null, observedError: boolean, readbackOk: boolean|null, timedOut: boolean, attempts: number }>}
 */
export async function pollWifiApplyReadback({
  fetchObserved,
  expected,
  signal,
  intervalMs,
  timeoutMs,
  onPoll,
}) {
  const timing = resolveWifiReadbackPollTiming({ intervalMs, timeoutMs });
  const started = Date.now();
  let attempts = 0;
  /** @type {ParsedObservedAccessPoint|null} */
  let lastObserved = null;
  let lastObservedError = false;

  while (Date.now() - started <= timing.timeoutMs) {
    if (signal?.aborted) {
      throw signal.reason ?? new DOMException('Aborted', 'AbortError');
    }
    attempts += 1;
    const { observed, observedError } = await fetchObserved();
    lastObserved = observed;
    lastObservedError = observedError;
    onPoll?.({ observed, observedError, attempt: attempts });

    const readbackOk = evaluateWifiApplyReadback({
      observed,
      observedError,
      expected,
    });
    if (readbackOk === true) {
      return {
        observed,
        observedError,
        readbackOk: true,
        timedOut: false,
        attempts,
      };
    }

    const elapsed = Date.now() - started;
    if (elapsed >= timing.timeoutMs) {
      break;
    }
    await sleepMs(Math.min(timing.intervalMs, timing.timeoutMs - elapsed), signal);
  }

  return {
    observed: lastObserved,
    observedError: lastObservedError,
    readbackOk: evaluateWifiApplyReadback({
      observed: lastObserved,
      observedError: lastObservedError,
      expected,
    }),
    timedOut: true,
    attempts,
  };
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @param {{ observed: ParsedObservedAccessPoint|null, observedError: boolean, expected: { ssid?: string, wpaMode?: WifiWpaMode, enabled?: boolean }|null|undefined, intent?: 'apply'|'teardown' }} params
 * @returns {WifiApplyVerdict|null|undefined}
 */
export function finalizeWifiApplyReadbackVerdict(
  verdict,
  { observed, observedError, expected, intent = 'apply' },
) {
  if (!shouldPollWifiApplyReadback(verdict)) {
    return verdict;
  }
  const readbackOk = evaluateWifiApplyReadback({
    observed,
    observedError,
    expected,
  });
  return applyWifiReadbackOutcome(verdict, readbackOk, {
    intent,
    observed,
    observedError,
    expected,
  });
}

/**
 * @param {WifiApplyVerdict|null|undefined} verdict
 * @param {boolean|null} readbackOk
 * @param {{ intent?: 'apply'|'teardown', observed?: ParsedObservedAccessPoint|null, observedError?: boolean, expected?: { ssid?: string, wpaMode?: WifiWpaMode, enabled?: boolean }|null }} [options]
 * @returns {WifiApplyVerdict|null|undefined}
 */
export function applyWifiReadbackOutcome(
  verdict,
  readbackOk,
  { intent = 'apply', observed = null, observedError = false, expected = null } = {},
) {
  if (!verdict || !shouldPollWifiApplyReadback(verdict)) {
    return verdict;
  }
  if (isWifiServerHonestWarningVerdict(verdict)) {
    return verdict;
  }
  if (readbackOk === true) {
    if (isWifiVerifyMismatchVerdict(verdict)) {
      return verdict;
    }
    if (intent === 'teardown') {
      return {
        ...verdict,
        hubState: HubState.SUCCESS,
        success: true,
        title: WIFI_TEARDOWN_READBACK_CONFIRMED_TITLE,
      };
    }
    return {
      ...verdict,
      hubState: HubState.SUCCESS,
      success: true,
      title: WIFI_APPLY_READBACK_CONFIRMED_TITLE,
      message:
        verdict.title === 'Сохранено с оговоркой'
          ? 'Роутер принял настройки, сеть готова к подключению'
          : 'Роутер принял настройки, сеть готова к подключению',
    };
  }
  return {
    ...verdict,
    hubState: HubState.WARNING,
    success: false,
    title: WIFI_APPLY_READBACK_FAILED_TITLE,
    message: buildWifiReadbackFailedMessage({
      expected: expected ?? {},
      observed,
      observedError,
    }),
  };
}

/**
 * @param {{ verdict: WifiApplyVerdict|null|undefined, fetchObserved: () => Promise<{ observed: ParsedObservedAccessPoint|null, observedError: boolean }>, expected: { ssid?: string, wpaMode?: WifiWpaMode, enabled?: boolean }|null|undefined, intent?: 'apply'|'teardown', signal?: AbortSignal, intervalMs?: number, timeoutMs?: number, onVerifying?: () => void }} params
 * @returns {Promise<WifiApplyVerdict|null|undefined>}
 */
export async function performWifiApplyReadbackPoll({
  verdict,
  fetchObserved,
  expected,
  intent = 'apply',
  signal,
  intervalMs,
  timeoutMs,
  onVerifying,
}) {
  if (!shouldPollWifiApplyReadback(verdict)) {
    return verdict;
  }
  onVerifying?.();
  const pollResult = await pollWifiApplyReadback({
    fetchObserved,
    expected,
    signal,
    intervalMs,
    timeoutMs,
  });
  return applyWifiReadbackOutcome(verdict, pollResult.readbackOk, {
    intent,
    observed: pollResult.observed,
    observedError: pollResult.observedError,
    expected,
  });
}

/**
 * @param {{ previewBody: Record<string, unknown>, liveParams: Record<string, string|null>, idempotent?: boolean }} params
 * @returns {Record<string, unknown>}
 */
export function buildWifiApplyBody({ previewBody, liveParams, idempotent = true }) {
  /** @type {Record<string, unknown>} */
  const body = {
    ...previewBody,
    confirm_live_apply: true,
    compensate_on_failure: true,
    idempotent,
  };

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

  return body;
}

/**
 * @param {{ apId: string, wpaMode: WifiWpaMode, liveParams: Record<string, string|null> }} params
 * @returns {Record<string, unknown>}
 */
export function buildWifiTeardownBody({ apId, wpaMode, liveParams }) {
  /** @type {Record<string, unknown>} */
  const body = {
    ap_id: apId,
    wpa_mode: wpaMode,
    confirm_live_teardown: true,
  };

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

  return body;
}

/**
 * @param {{ secret: string }} params
 * @returns {{ kind: string, secret: string }}
 */
export function buildWifiCredentialBody({ secret }) {
  return {
    kind: 'WifiApPsk',
    secret,
  };
}

/**
 * @param {unknown} response
 * @param {{ intent?: 'apply'|'teardown' }} [options]
 * @returns {WifiApplyVerdict}
 */
export function parseWifiApplyVerdict(response, { intent = 'apply' } = {}) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const overall = typeof payload.overall === 'string' ? payload.overall : 'failed';
  const onAir =
    typeof payload.on_air_verification_status === 'string'
      ? payload.on_air_verification_status
      : 'on_air_unverified';
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
  const technicalLines = [`overall: ${overall}`, `on_air_verification_status: ${onAir}`];
  if (errors.length > 0) {
    technicalLines.push(`errors: ${errors.join(', ')}`);
  }
  if (explanationText) {
    technicalLines.push(`verdict_explanation: ${explanationText}`);
  }

  const configurationApplied = overall === 'applied';

  if (overall === 'applied' && onAir === 'on_air_verified') {
    const successMessage =
      intent === 'teardown'
        ? 'Сеть выключена'
        : 'Роутер принял настройки, сеть готова к подключению';
    return {
      hubState: HubState.SUCCESS,
      success: true,
      refreshObserved: true,
      title: intent === 'teardown' ? 'Сеть выключена' : 'Сохранено',
      message: successMessage,
      technicalLines,
    };
  }

  if (errors.includes('planner.no_apply_ops')) {
    return {
      hubState: HubState.ERROR,
      success: false,
      refreshObserved: false,
      title: 'Так выключить сеть нельзя',
      message:
        'Чтобы выключить сеть, используйте переключатель «Сеть», а не кнопку «Сохранить»',
      technicalLines,
    };
  }

  if (overall === 'applied' && onAir === 'on_air_admin_only') {
    return {
      hubState: HubState.WARNING,
      success: false,
      refreshObserved: true,
      title: 'Сохранено с оговоркой',
      message:
        'Роутер принял настройки, но сеть могла ещё не появиться в списке Wi‑Fi. Проверьте с телефона — по названию и паролю или по QR-коду',
      technicalLines,
    };
  }

  if (overall === 'verify_mismatch') {
    return {
      hubState: HubState.WARNING,
      success: false,
      refreshObserved: false,
      title: 'Проверка не совпала',
      message:
        'Роутер принял команду, но первичная проверка не совпала с ожиданием по SSID, режиму защиты и состоянию сети',
      technicalLines,
    };
  }

  if (overall === 'rolled_back') {
    return {
      hubState: HubState.WARNING,
      success: false,
      refreshObserved: false,
      title: 'Настройки не изменились',
      message:
        'Роутер не подтвердил изменения — система вернула прежние название, пароль и защиту',
      technicalLines,
    };
  }

  if (overall === 'dispatched_offline') {
    return {
      hubState: HubState.WARNING,
      success: false,
      refreshObserved: false,
      title: 'Изменения не отправлены на роутер',
      message:
        'Сохранение выполнено без связи с роутером — на устройстве настройки не менялись. Проверьте подключение и повторите.',
      technicalLines,
    };
  }

  if (overall === 'unsupported_pending_verification') {
    return {
      hubState: HubState.UNSUPPORTED,
      success: false,
      refreshObserved: false,
      title: 'Сохранение пока недоступно',
      message:
        'Роутер или выбранные параметры ещё не прошли проверку — команда на устройство не отправлялась. Выберите другие настройки или обратитесь к администратору.',
      technicalLines,
    };
  }

  if (overall === 'applied') {
    return {
      hubState: HubState.WARNING,
      success: false,
      refreshObserved: true,
      title: 'Сохранено с оговоркой',
      message:
        'Роутер принял настройки, но сеть могла ещё не появиться в списке Wi‑Fi. Проверьте с телефона — по названию и паролю или по QR-коду',
      technicalLines,
    };
  }

  return {
    hubState: HubState.ERROR,
    success: false,
    refreshObserved: configurationApplied,
    title: 'Не удалось сохранить',
    message: 'Не удалось сохранить изменения сети',
    technicalLines,
  };
}

/**
 * @param {Response} response
 * @returns {Promise<HubApiError>}
 */
async function buildApiErrorFromResponse(response) {
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
    code: `http.${httpStatus}`,
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

/**
 * PUT с Idempotency-Key — api.js не принимает произвольные заголовки.
 * @param {string} path
 * @param {unknown} body
 * @param {Record<string, string>} extraHeaders
 * @param {{ signal?: AbortSignal, timeoutMs?: number }} [options]
 * @returns {Promise<unknown>}
 */
async function putWithHeaders(path, body, extraHeaders, { signal, timeoutMs = 15000 } = {}) {
  const timeoutController = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    timeoutController.abort();
  }, timeoutMs);

  /** @type {AbortSignal} */
  let combinedSignal = timeoutController.signal;
  /** @type {(() => void)|null} */
  let detachAbortListeners = null;
  if (signal) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
      combinedSignal = AbortSignal.any([signal, timeoutController.signal]);
    } else {
      const merged = new AbortController();
      const forwardAbort = () => {
        const reason = signal.aborted ? signal.reason : timeoutController.signal.reason;
        merged.abort(reason);
      };
      const onSignalAbort = () => {
        forwardAbort();
      };
      const onTimeoutAbort = () => {
        forwardAbort();
      };
      if (signal.aborted || timeoutController.signal.aborted) {
        forwardAbort();
      } else {
        signal.addEventListener('abort', onSignalAbort);
        timeoutController.signal.addEventListener('abort', onTimeoutAbort);
      }
      combinedSignal = merged.signal;
      detachAbortListeners = () => {
        signal.removeEventListener('abort', onSignalAbort);
        timeoutController.signal.removeEventListener('abort', onTimeoutAbort);
      };
    }
  }

  const url = path.startsWith('/') ? path : `${API_BASE}/${path.replace(/^\//, '')}`;
  const init = {
    method: 'PUT',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
    signal: combinedSignal,
  };

  try {
    const response = await fetch(url, init);

    if (!response.ok) {
      throw await buildApiErrorFromResponse(response);
    }

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
    clearTimeout(timeoutId);
    detachAbortListeners?.();
  }
}

/**
 * POST с Idempotency-Key — api.js не принимает произвольные заголовки.
 * @param {string} path
 * @param {unknown} body
 * @param {Record<string, string>} extraHeaders
 * @param {{ signal?: AbortSignal, timeoutMs?: number }} [options]
 * @returns {Promise<unknown>}
 */
async function postWithHeaders(path, body, extraHeaders, { signal, timeoutMs = 15000 } = {}) {
  const timeoutController = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    timeoutController.abort();
  }, timeoutMs);

  /** @type {AbortSignal} */
  let combinedSignal = timeoutController.signal;
  /** @type {(() => void)|null} */
  let detachAbortListeners = null;
  if (signal) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
      combinedSignal = AbortSignal.any([signal, timeoutController.signal]);
    } else {
      const merged = new AbortController();
      const forwardAbort = () => {
        const reason = signal.aborted ? signal.reason : timeoutController.signal.reason;
        merged.abort(reason);
      };
      const onSignalAbort = () => {
        forwardAbort();
      };
      const onTimeoutAbort = () => {
        forwardAbort();
      };
      if (signal.aborted || timeoutController.signal.aborted) {
        forwardAbort();
      } else {
        signal.addEventListener('abort', onSignalAbort);
        timeoutController.signal.addEventListener('abort', onTimeoutAbort);
      }
      combinedSignal = merged.signal;
      detachAbortListeners = () => {
        signal.removeEventListener('abort', onSignalAbort);
        timeoutController.signal.removeEventListener('abort', onTimeoutAbort);
      };
    }
  }

  const url = path.startsWith('/') ? path : `${API_BASE}/${path.replace(/^\//, '')}`;
  const init = {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
    signal: combinedSignal,
  };

  try {
    const response = await fetch(url, init);

    if (!response.ok) {
      throw await buildApiErrorFromResponse(response);
    }

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
    clearTimeout(timeoutId);
    detachAbortListeners?.();
  }
}

/**
 * @param {unknown} error
 * @returns {HubApiError}
 */
export function toWifiCredentialRegistrationError(error) {
  if (error instanceof HubApiError) {
    if (
      error.code === 'client.credential_registration_failed'
      || error.code === 'idempotency.conflict'
    ) {
      return error;
    }
  }
  /** @type {string[]} */
  const details = [];
  if (error instanceof HubApiError) {
    if (error.code) {
      details.push(`code: ${error.code}`);
    }
    if (error.httpStatus != null) {
      details.push(`http_status: ${error.httpStatus}`);
    }
    if (Array.isArray(error.details) && error.details.length > 0) {
      details.push(...error.details.map((item) => String(item)));
    }
  } else if (error instanceof Error && error.message) {
    details.push(`error: ${error.name}`);
  }
  return new HubApiError({
    code: 'client.credential_registration_failed',
    httpStatus: error instanceof HubApiError ? error.httpStatus : null,
    userMessage: WIFI_CREDENTIAL_REGISTRATION_FAILED_MESSAGE,
    userAction: WIFI_CREDENTIAL_REGISTRATION_FAILED_ACTION,
    serverMessage: null,
    details,
    requestId: error instanceof HubApiError ? error.requestId : null,
    correlationId: error instanceof HubApiError ? error.correlationId : null,
    kind: ERROR_KIND.SERVER,
  });
}

export async function registerWifiApCredential({ routerId, secret, idempotencyKey, signal }) {
  const key = idempotencyKey ?? createIdempotencyKey();
  const body = buildWifiCredentialBody({ secret });
  try {
    return /** @type {Promise<{ credential_ref_id?: string }>} */ (
      await putWithHeaders(
        `routers/${routerId}/credentials`,
        body,
        { 'Idempotency-Key': key },
        { signal },
      )
    );
  } catch (error) {
    throw toWifiCredentialRegistrationError(error);
  }
}

/**
 * @param {{ routerId: string, credentialRefId: string, signal?: AbortSignal }} params
 * @returns {Promise<void>}
 */
export async function revokeWifiApCredential({ routerId, credentialRefId, signal }) {
  const refId = typeof credentialRefId === 'string' ? credentialRefId.trim() : '';
  if (!refId) {
    return;
  }
  const idempotencyKey = `wifi-ap-psk-revoke-${refId}`;
  await postWithHeaders(
    `routers/${routerId}/credentials/${encodeURIComponent(refId)}/revoke`,
    {},
    { 'Idempotency-Key': idempotencyKey },
    { signal },
  );
}

/**
 * @param {{ apId: string, session: import('../core/session.js').SessionSnapshot|null|undefined, adapterMode?: string|null, signal?: AbortSignal }} params
 * @returns {Promise<ParsedObservedAccessPoint>}
 */
export async function fetchWifiObservedState({ apId, session, adapterMode, signal }) {
  const readiness = evaluateWifiObservedReadiness(session, adapterMode);
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
  return parseObservedAccessPoint(first);
}

/**
 * @param {{ previewBody: Record<string, unknown>, session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export async function previewWifiChanges({ previewBody, session, signal }) {
  return apiPost('wifi/preview', previewBody, { signal });
}

/**
 * @param {{ previewBody: Record<string, unknown>, session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal, idempotent?: boolean }} params
 * @returns {Promise<unknown>}
 */
export async function applyWifiChanges({ previewBody, session, signal, idempotent = true }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для применения изменений не хватает параметров живого подключения');
  }
  const body = buildWifiApplyBody({ previewBody, liveParams: live.params, idempotent });
  return apiPost('wifi/apply', body, { signal });
}

/**
 * @param {{ apId: string, wpaMode: WifiWpaMode, session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export async function teardownWifiNetwork({ apId, wpaMode, session, signal }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для отключения сети не хватает параметров живого подключения');
  }
  const body = buildWifiTeardownBody({ apId, wpaMode, liveParams: live.params });
  return apiPost('wifi/teardown', body, { signal });
}

/**
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<StandingNetworkPreferences>}
 */
export async function fetchStandingNetworkPreferences({ signal } = {}) {
  return /** @type {Promise<StandingNetworkPreferences>} */ (
    await apiGet('standing-network-preferences', { signal })
  );
}

/**
 * @param {{ staff_ssid?: string, staff_password_credential_ref_id?: string|null, guest_default_ssid?: string, staff_ap_id?: string|null, guest_ap_id?: string|null }} body
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<StandingNetworkPreferences>}
 */
export async function updateStandingNetworkPreferences(body, { signal } = {}) {
  return /** @type {Promise<StandingNetworkPreferences>} */ (
    await apiRequest('standing-network-preferences', {
      method: 'PUT',
      body,
      signal,
    })
  );
}
