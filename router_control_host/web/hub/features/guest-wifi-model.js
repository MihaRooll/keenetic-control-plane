/**
 * Модель экрана «Гостевой Wi‑Fi» — данные и сетевые вызовы без DOM.
 */

import {
  WPA_MODE_OPTIONS,
  bandFromApId,
  buildObservedStateRequestBody,
  buildWifiApplyBody,
  buildWifiCredentialBody,
  buildWifiPreviewBody,
  buildWifiTeardownBody,
  createWifiFormDraft,
  describeWifiNetworkToggle,
  evaluateWifiMutationReadiness,
  fetchWifiObservedState,
  isObservedWpaModeKnown,
  listWifiApOptions,
  parseObservedAccessPoint,
  parseWifiApplyVerdict,
  previewWifiChanges,
  applyWifiChanges,
  registerWifiApCredential,
  deriveWifiPreviewEnabled,
  applyWifiReadbackOutcome,
  evaluateWifiApplyReadback,
  finalizeWifiApplyReadbackVerdict,
  buildWifiApplyReadbackVerifyingVerdict,
  performWifiApplyReadbackPoll,
  pollWifiApplyReadback,
  shouldPollWifiApplyReadback,
  buildWifiReadbackFailedMessage,
  describeWifiReadbackFieldComparison,
  isWifiConfigurationApplied,
  isWifiWpaModeDraftSelected,
  WPA_MODE_DRAFT_PLACEHOLDER_OPTION,
  shouldAcceptWifiObservedResult,
  shouldResetWifiFormAfterMutation,
  shouldClearWifiFormPasswordAfterMutation,
  shouldRefreshWifiObservedAfterMutation,
  teardownWifiNetwork,
  validateWifiApForm,
  wpaFieldHint,
  buildWifiMutationIntentSnapshot,
  currentWifiMutationIntentFromDraft,
  wifiMutationIntentMatchesCurrent,
  isWifiObservedUnreadable,
  WIFI_OBSERVED_UNREADABLE_TITLE,
  WIFI_OBSERVED_UNREADABLE_DESCRIPTION,
  WIFI_MUTATION_INTENT_STALE_MESSAGE,
  WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
  WIFI_CREDENTIAL_REF_MISSING_MESSAGE,
  toWifiCredentialRegistrationError,
  ensureWifiCredentialRef,
  revokeWifiApCredential,
  buildWifiCredentialIdempotencyKey,
  WIFI_APPLY_READBACK_FAILED_TITLE,
  WIFI_APPLY_READBACK_FAILED_MESSAGE,
  WIFI_APPLY_READBACK_CONFIRMED_TITLE,
  fetchStandingNetworkPreferences,
  updateStandingNetworkPreferences,
} from './wifi-ap-model.js';

/** @typedef {import('./wifi-ap-model.js').WifiWpaMode} GuestWifiWpaMode */
/** @typedef {import('./wifi-ap-model.js').WifiApOption} GuestWifiAccessPointOption */
/** @typedef {import('./wifi-ap-model.js').WifiFormDraft} GuestWifiFormDraft */
/** @typedef {import('./wifi-ap-model.js').ParsedObservedAccessPoint} ParsedObservedAccessPoint */
/** @typedef {import('./wifi-ap-model.js').WifiApplyVerdict} GuestWifiApplyVerdict */
/** @typedef {import('./wifi-ap-model.js').WifiMutationReadiness} GuestWifiMutationReadiness */

/** @typedef {import('./wifi-ap-model.js').StandingNetworkPreferences} StandingNetworkPreferences */

export const GUEST_WIFI_STANDING_SSID_SEED = 'Гостевая сеть';

export const GUEST_WIFI_REMEMBER_DEFAULT_LABEL = 'Запомнить как обычное';

export const GUEST_WIFI_REMEMBER_DEFAULT_HINT =
  'Имя ниже применится только к этому проекту, пока вы не нажмёте «Запомнить как обычное».';

export const GUEST_WIFI_READABLE_SSID_UNKNOWN_NOTE =
  'Название гостевой сети на роутере не прочитано — подставленное имя по умолчанию не подставлялось.';

/** Честная строка про счётчик гостей — источника данных нет. */
export const GUEST_WIFI_GUEST_COUNTER_NOTE =
  'Роутер не сообщает, сколько гостей подключено — показать счётчик не получится';

/** Подпись честного отказа: изоляция от рабочей сети. */
export const GUEST_WIFI_ISOLATION_LABEL = 'Изоляция от рабочей сети';

/** Изоляция гостей не поддерживается роутером. */
export const GUEST_WIFI_ISOLATION_NOTE =
  'Недоступна. Отдельное имя сети и свой пароль для гостей работают, но спрятать от гостей рабочие устройства роутер не умеет — считайте, что гости могут их видеть.';

/** Подпись честного отказа: режим без пароля. */
export const GUEST_WIFI_NO_OPEN_NETWORK_LABEL = 'Режим без пароля';

/** Открытая точка доступа недоступна. */
export const GUEST_WIFI_NO_OPEN_NETWORK_NOTE =
  'Недоступен — пароль нужен даже гостям. Сделайте короткий понятный пароль и напечатайте его рядом с QR-кодом.';

/** Подпись честного отказа: лимит устройств. */
export const GUEST_WIFI_DEVICE_LIMIT_LABEL = 'Максимум устройств';

/** Лимит устройств не поддерживается. */
export const GUEST_WIFI_DEVICE_LIMIT_NOTE =
  'Роутер не принимает ограничение числа гостевых устройств. Когда гости разошлись — просто выключите гостевую сеть.';

/** Страница после подключения недоступна — альтернатива QR. */
export const GUEST_WIFI_CAPTIVE_PORTAL_NOTE =
  'Роутер не умеет её включить. Вместо неё — QR-код: гость подключается, не набирая пароль.';

/** Вступление к блоку ручной проверки гостем. */
export const GUEST_WIFI_GUEST_CHECK_INTRO =
  'Проверить сеть глазами гостя из этой панели нельзя: панель работает в вашей сети и не может подключиться к гостевой. Проверьте с телефона вручную';

/** Шаги ручной проверки гостем. */
export const GUEST_WIFI_GUEST_CHECK_STEPS = Object.freeze([
  'Отсканируйте QR-код',
  'Дождитесь подключения',
  'Откройте любой сайт',
]);

/** Результат проверки интерфейс не знает. */
export const GUEST_WIFI_GUEST_CHECK_RESULT_NOTE =
  'Панель не узнает, подключился ли гость, и не отметит проверку как пройденную.';

/** Предупреждение при совпадении гостевой и рабочей точки. */
export const GUEST_WIFI_STAFF_AP_OVERLAP_WARNING =
  'Это та же сеть, что выбрана рабочей. Настройки будут перетирать друг друга — выберите другой номер';

/** Подпись поля пароля — текущий пароль не показывается. */
export const GUEST_WIFI_PASSWORD_FIELD_NOTE =
  'Пароль с роутера не читается — для включённой сети его нужно ввести заново при каждом сохранении';

/** Пояснение, что номер в списке — не готовая сеть, а свободный слот на роутере. */
export const GUEST_WIFI_SLOT_NUMBER_NOTE =
  'Номер в списке ниже — это просто свободное место на роутере, у него ещё нет названия. Выберите любой номер и диапазон (2,4 или 5 ГГц), а настоящее название и пароль для гостей задайте в полях ниже — они появятся на устройстве только после сохранения.';

/** Допустимые режимы защиты в форме. */
export const GUEST_WIFI_WPA_MODE_OPTIONS = WPA_MODE_OPTIONS;

export {
  bandFromApId,
  buildObservedStateRequestBody,
  buildWifiApplyBody,
  buildWifiCredentialBody,
  buildWifiTeardownBody,
  isObservedWpaModeKnown,
  parseObservedAccessPoint,
  parseWifiApplyVerdict,
  registerWifiApCredential,
  buildWifiMutationIntentSnapshot,
  currentWifiMutationIntentFromDraft,
  wifiMutationIntentMatchesCurrent,
  isWifiObservedUnreadable,
  WIFI_OBSERVED_UNREADABLE_TITLE,
  WIFI_OBSERVED_UNREADABLE_DESCRIPTION,
  WIFI_MUTATION_INTENT_STALE_MESSAGE,
  WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
  WIFI_CREDENTIAL_REF_MISSING_MESSAGE,
  deriveWifiPreviewEnabled,
  applyWifiReadbackOutcome,
  evaluateWifiApplyReadback,
  finalizeWifiApplyReadbackVerdict,
  buildWifiApplyReadbackVerifyingVerdict,
  performWifiApplyReadbackPoll,
  pollWifiApplyReadback,
  shouldPollWifiApplyReadback,
  buildWifiReadbackFailedMessage,
  describeWifiReadbackFieldComparison,
  isWifiConfigurationApplied,
  isWifiWpaModeDraftSelected,
  WPA_MODE_DRAFT_PLACEHOLDER_OPTION,
  WIFI_APPLY_READBACK_FAILED_TITLE,
  WIFI_APPLY_READBACK_FAILED_MESSAGE,
  WIFI_APPLY_READBACK_CONFIRMED_TITLE,
  toWifiCredentialRegistrationError,
  ensureWifiCredentialRef,
  revokeWifiApCredential,
  buildWifiCredentialIdempotencyKey,
  fetchStandingNetworkPreferences,
  updateStandingNetworkPreferences,
};

export function listGuestWifiAccessPoints() {
  return listWifiApOptions();
}

export function evaluateGuestWifiMutationReadiness(snapshot, adapterMode) {
  return evaluateWifiMutationReadiness(snapshot, adapterMode);
}

export function guestWifiWpaFieldHint(observed) {
  return wpaFieldHint(observed);
}

export function describeGuestWifiNetworkToggle(observed) {
  return describeWifiNetworkToggle(observed);
}

export function shouldResetGuestWifiFormAfterMutation(verdict) {
  return shouldResetWifiFormAfterMutation(verdict);
}

export function shouldClearGuestWifiFormPasswordAfterMutation(params) {
  return shouldClearWifiFormPasswordAfterMutation(params);
}

export function shouldRefreshGuestWifiObservedAfterMutation(verdict) {
  return shouldRefreshWifiObservedAfterMutation(verdict);
}

export function createGuestWifiFormDraft(observed, standing = null) {
  const base = createWifiFormDraft(observed);
  if (observed?.readable) {
    if (!observed?.ssid) {
      return base;
    }
    return base;
  }
  const guestSsid =
    typeof standing?.guest_default_ssid === 'string' && standing.guest_default_ssid.trim()
      ? standing.guest_default_ssid.trim()
      : GUEST_WIFI_STANDING_SSID_SEED;
  return { ...base, ssid: guestSsid };
}

/**
 * @param {{ draftSsid: string, standing: StandingNetworkPreferences|null|undefined }} params
 * @returns {boolean}
 */
export function shouldOfferGuestRememberDefault({ draftSsid, standing }) {
  const trimmed = typeof draftSsid === 'string' ? draftSsid.trim() : '';
  if (!trimmed) {
    return false;
  }
  const standingSsid =
    typeof standing?.guest_default_ssid === 'string' ? standing.guest_default_ssid.trim() : '';
  return trimmed !== standingSsid;
}

/**
 * @param {string} ssid
 * @returns {{ guest_default_ssid: string }}
 */
export function buildGuestStandingPreferencesUpdate(ssid) {
  return { guest_default_ssid: typeof ssid === 'string' ? ssid.trim() : '' };
}

/**
 * @param {string|null} apId
 * @returns {{ guest_ap_id: string|null }}
 */
export function buildGuestApRoleUpdate(apId) {
  return { guest_ap_id: apId };
}

export function fetchGuestStandingNetworkPreferences(params) {
  return fetchStandingNetworkPreferences(params);
}

export function updateGuestStandingNetworkPreferences(body, params) {
  return updateStandingNetworkPreferences(body, params);
}

export function validateGuestWifiForm(params) {
  return validateWifiApForm(params);
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @param {string|null|undefined} guestApId
 * @returns {string|null}
 */
export function getGuestStaffApOverlapWarning(session, guestApId) {
  if (!guestApId || !session?.wifiRoles?.staffApId) {
    return null;
  }
  if (guestApId === session.wifiRoles.staffApId) {
    return GUEST_WIFI_STAFF_AP_OVERLAP_WARNING;
  }
  return null;
}

/**
 * @param {{ apId: string, ssid: string, wpaMode: GuestWifiWpaMode, enabled: boolean, credentialRefId?: string|null }} params
 * @returns {Record<string, unknown>}
 */
export function shouldAcceptGuestWifiObservedResult(requestGeneration, currentGeneration) {
  return shouldAcceptWifiObservedResult(requestGeneration, currentGeneration);
}

export function buildGuestWifiPreviewBody({ apId, ssid, wpaMode, enabled, credentialRefId }) {
  return buildWifiPreviewBody({ apId, ssid, wpaMode, enabled, credentialRefId });
}

/**
 * @param {{ observed: ParsedObservedAccessPoint|null, draft: GuestWifiFormDraft, selectedApId: string|null, mutationReadiness?: GuestWifiMutationReadiness|null }} params
 * @returns {{ canSave: boolean, canTeardown: boolean }}
 */
export function buildGuestWifiScreenState({
  observed,
  draft,
  selectedApId,
  mutationReadiness = null,
}) {
  const validation = validateGuestWifiForm({
    ssid: draft.ssid,
    password: draft.password,
    requirePassword: false,
    wpaMode: draft.wpaMode,
  });

  const canMutate = mutationReadiness?.allowed === true;
  const observedActionable = Boolean(selectedApId && observed);
  const canSave = Boolean(selectedApId && validation.valid && canMutate && observedActionable);
  const canTeardown = Boolean(selectedApId && canMutate && observedActionable);

  return { canSave, canTeardown };
}

/**
 * @param {{ observed: ParsedObservedAccessPoint|null, screen: ReturnType<typeof buildGuestWifiScreenState> }} params
 * @returns {string}
 */
export function serializeGuestWifiOperatorText({ observed, screen }) {
  const parts = [
    observed?.ssidLabel ?? '',
    observed?.activeLabel ?? '',
    GUEST_WIFI_GUEST_COUNTER_NOTE,
    GUEST_WIFI_ISOLATION_LABEL,
    GUEST_WIFI_ISOLATION_NOTE,
    GUEST_WIFI_NO_OPEN_NETWORK_LABEL,
    GUEST_WIFI_NO_OPEN_NETWORK_NOTE,
    GUEST_WIFI_DEVICE_LIMIT_LABEL,
    GUEST_WIFI_DEVICE_LIMIT_NOTE,
    GUEST_WIFI_CAPTIVE_PORTAL_NOTE,
    GUEST_WIFI_GUEST_CHECK_INTRO,
    GUEST_WIFI_GUEST_CHECK_RESULT_NOTE,
    GUEST_WIFI_PASSWORD_FIELD_NOTE,
    ...GUEST_WIFI_GUEST_CHECK_STEPS,
  ];
  if (screen.canSave || screen.canTeardown) {
    parts.push('ok');
  }
  return parts.join('\n');
}

/**
 * @param {{ observed: ParsedObservedAccessPoint|null }} params
 * @returns {string}
 */
export function serializeGuestWifiTechnicalText({ observed }) {
  if (!observed?.technicalLines?.length) {
    return '';
  }
  return observed.technicalLines.join('\n');
}

export function fetchGuestWifiObservedState(params) {
  return fetchWifiObservedState(params);
}

export function previewGuestWifiChanges(params) {
  return previewWifiChanges(params);
}

export function applyGuestWifiChanges(params) {
  return applyWifiChanges(params);
}

export function teardownGuestWifiNetwork(params) {
  return teardownWifiNetwork(params);
}
