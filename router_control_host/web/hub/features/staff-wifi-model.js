/**
 * Модель экрана «Рабочая сеть» — данные и сетевые вызовы без DOM.
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
  evaluateWifiObservedReadiness,
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
  ensureWifiCredentialRef,
  buildWifiCredentialIdempotencyKey,
  revokeWifiApCredential,
  WIFI_OBSERVED_UNREADABLE_TITLE,
  WIFI_OBSERVED_UNREADABLE_DESCRIPTION,
  WIFI_MUTATION_INTENT_STALE_MESSAGE,
  WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
  WIFI_CREDENTIAL_REF_MISSING_MESSAGE,
  WIFI_APPLY_READBACK_FAILED_TITLE,
  WIFI_APPLY_READBACK_FAILED_MESSAGE,
  WIFI_APPLY_READBACK_CONFIRMED_TITLE,
  toWifiCredentialRegistrationError,
  fetchStandingNetworkPreferences,
  updateStandingNetworkPreferences,
} from './wifi-ap-model.js';

/** @typedef {import('./wifi-ap-model.js').WifiWpaMode} StaffWifiWpaMode */
/** @typedef {import('./wifi-ap-model.js').WifiApOption} StaffWifiAccessPointOption */
/** @typedef {import('./wifi-ap-model.js').WifiFormDraft} StaffWifiFormDraft */
/** @typedef {import('./wifi-ap-model.js').ParsedObservedAccessPoint} ParsedObservedAccessPoint */
/** @typedef {import('./wifi-ap-model.js').WifiApplyVerdict} StaffWifiApplyVerdict */
/** @typedef {import('./wifi-ap-model.js').WifiMutationReadiness} StaffWifiMutationReadiness */

/** @typedef {import('./wifi-ap-model.js').StandingNetworkPreferences} StandingNetworkPreferences */

export const STAFF_WIFI_STANDING_SSID_SEED = 'Рабочая сеть';

export const STAFF_WIFI_STANDING_PASSWORD_CONFIGURED_NOTE =
  'Обычный пароль уже сохранён в модуле. Оставьте поле пустым, чтобы использовать его. Введите новый — только если хотите сменить.';

export const STAFF_WIFI_STANDING_PASSWORD_ASK_ONCE_MESSAGE =
  'Задайте пароль рабочей сети один раз — модуль запомнит его для следующих проектов.';

export const STAFF_WIFI_READABLE_SSID_UNKNOWN_NOTE =
  'Название сети на роутере не прочитано — подставленное имя по умолчанию не подставлялось.';

export const STAFF_WIFI_DISABLED_REMEDIATION_TITLE = 'Рабочая сеть выключена';

export const STAFF_WIFI_DISABLED_REMEDIATION_MESSAGE =
  'iPad и персонал не смогут подключиться, пока сеть выключена. Включите её одним действием.';

export const STAFF_WIFI_APPLY_DEFAULTS_LABEL = 'Применить обычные настройки';

export const STAFF_WIFI_PRIMARY_NETWORKS_NOTE =
  'Две основные сети роутера этот раздел не меняет — их обслуживают текущие клиенты. Меняйте только выбранную рабочую сеть';

export const STAFF_WIFI_SLOT_NUMBER_NOTE =
  'Номер в списке ниже — это просто свободное место на роутере, у него ещё нет названия. Выберите любой номер и диапазон (2,4 или 5 ГГц), а настоящее название и пароль для сотрудников задайте в полях ниже — они появятся на устройстве только после сохранения.';

export const STAFF_WIFI_CLIENT_LIST_UNSUPPORTED =
  'Роутер не сообщает, какие устройства подключены. Список и счётчик показать нечем.';

export const STAFF_WIFI_PASSWORD_FIELD_NOTE =
  'Пароль с роутера не читается — для включённой сети его нужно ввести заново при каждом сохранении';

export const STAFF_WIFI_NO_OPEN_NETWORK_NOTE =
  'Сеть без пароля этот роутер создать не может';

export const STAFF_WIFI_WPA_MODE_OPTIONS = WPA_MODE_OPTIONS;

export {
  bandFromApId,
  buildObservedStateRequestBody,
  buildWifiApplyBody,
  buildWifiCredentialBody,
  buildWifiPreviewBody,
  buildWifiTeardownBody,
  isObservedWpaModeKnown,
  parseObservedAccessPoint,
  parseWifiApplyVerdict,
  registerWifiApCredential,
  ensureWifiCredentialRef,
  revokeWifiApCredential,
  buildWifiCredentialIdempotencyKey,
  shouldRefreshWifiObservedAfterMutation,
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
  fetchStandingNetworkPreferences,
  updateStandingNetworkPreferences,
};

export function listStaffWifiAccessPoints() {
  return listWifiApOptions();
}

export function evaluateStaffWifiMutationReadiness(snapshot, adapterMode) {
  return evaluateWifiMutationReadiness(snapshot, adapterMode);
}

export function evaluateStaffWifiObservedReadiness(snapshot, adapterMode) {
  return evaluateWifiObservedReadiness(snapshot, adapterMode);
}

export function staffWifiWpaFieldHint(observed) {
  return wpaFieldHint(observed);
}

export function describeStaffWifiNetworkToggle(observed) {
  return describeWifiNetworkToggle(observed);
}

export function shouldResetStaffWifiFormAfterMutation(verdict) {
  return shouldResetWifiFormAfterMutation(verdict);
}

export function shouldClearStaffWifiFormPasswordAfterMutation(params) {
  return shouldClearWifiFormPasswordAfterMutation(params);
}

export function shouldRefreshStaffWifiObservedAfterMutation(verdict) {
  return shouldRefreshWifiObservedAfterMutation(verdict);
}

export function shouldAcceptStaffWifiObservedResult(requestGeneration, currentGeneration) {
  return shouldAcceptWifiObservedResult(requestGeneration, currentGeneration);
}

export function createStaffWifiFormDraft(observed, standing = null) {
  const base = createWifiFormDraft(observed);
  if (observed?.readable) {
    if (!observed?.ssid) {
      return base;
    }
    return base;
  }
  const standingSsid =
    typeof standing?.staff_ssid === 'string' && standing.staff_ssid.trim()
      ? standing.staff_ssid.trim()
      : STAFF_WIFI_STANDING_SSID_SEED;
  return { ...base, ssid: standingSsid };
}

/**
 * @param {StandingNetworkPreferences|null|undefined} standing
 * @returns {string}
 */
export function staffWifiPasswordFieldNote(standing) {
  if (standing?.staff_password_configured) {
    return STAFF_WIFI_STANDING_PASSWORD_CONFIGURED_NOTE;
  }
  return STAFF_WIFI_PASSWORD_FIELD_NOTE;
}

/**
 * @param {{ password: string, standing: StandingNetworkPreferences|null|undefined, draftCredentialRef: import('./wifi-ap-model.js').WifiCredentialRefCache|null, selectedApId: string|null, draftSsid: string }} params
 * @returns {{ kind: 'register', secret: string }|{ kind: 'ref', credentialRefId: string }|{ kind: 'missing' }}
 */
export function resolveStaffWifiCredentialIntent({
  password,
  standing,
  draftCredentialRef,
  selectedApId,
  draftSsid,
}) {
  const trimmed = typeof password === 'string' ? password.trim() : '';
  if (trimmed) {
    return { kind: 'register', secret: trimmed };
  }
  if (
    standing?.staff_password_configured
    && typeof standing.staff_password_credential_ref_id === 'string'
    && standing.staff_password_credential_ref_id
  ) {
    return {
      kind: 'ref',
      credentialRefId: standing.staff_password_credential_ref_id,
    };
  }
  const trimmedSsid = typeof draftSsid === 'string' ? draftSsid.trim() : '';
  if (
    draftCredentialRef?.refId
    && draftCredentialRef.apId === selectedApId
    && draftCredentialRef.ssid === trimmedSsid
  ) {
    return { kind: 'ref', credentialRefId: draftCredentialRef.refId };
  }
  return { kind: 'missing' };
}

/**
 * @param {ParsedObservedAccessPoint|null|undefined} observed
 * @returns {boolean}
 */
export function shouldShowStaffDisabledRemediation(observed) {
  return observed?.readable === true && observed.activeLabel === 'Выключена';
}

/**
 * @param {{ selectedApId: string|null, standing: StandingNetworkPreferences|null|undefined, mutationReadiness: StaffWifiMutationReadiness|null|undefined }} params
 * @returns {boolean}
 */
export function canApplyStaffStandingDefaults({ selectedApId, standing, mutationReadiness }) {
  return Boolean(
    selectedApId
    && typeof standing?.staff_ssid === 'string'
    && standing.staff_ssid.trim()
    && standing.staff_password_configured
    && mutationReadiness?.allowed === true,
  );
}

/**
 * @param {StandingNetworkPreferences} standing
 * @returns {StaffWifiFormDraft}
 */
export function buildStaffStandingDefaultsDraft(standing) {
  const ssid =
    typeof standing.staff_ssid === 'string' && standing.staff_ssid.trim()
      ? standing.staff_ssid.trim()
      : STAFF_WIFI_STANDING_SSID_SEED;
  return {
    ssid,
    wpaMode: 'WPA2',
    password: '',
  };
}

/**
 * @param {{ ssid: string, credentialRefId: string|null|undefined }} params
 * @returns {{ staff_ssid: string, staff_password_credential_ref_id: string|null }}
 */
export function buildStaffStandingPreferencesUpdate({ ssid, credentialRefId }) {
  return {
    staff_ssid: typeof ssid === 'string' ? ssid.trim() : '',
    staff_password_credential_ref_id: credentialRefId ?? null,
  };
}

/**
 * @param {string|null} apId
 * @returns {{ staff_ap_id: string|null }}
 */
export function buildStaffApRoleUpdate(apId) {
  return { staff_ap_id: apId };
}

/**
 * Whether standing preferences should be persisted after a mutation completes.
 * Uses the final readback verdict — not the pre-readback apply `success` flag.
 *
 * @param {{ lastVerdict: StaffWifiApplyVerdict|null|undefined, action: string }} params
 * @returns {boolean}
 */
export function shouldPersistStandingPreferencesAfterMutation({ lastVerdict, action }) {
  if (action === 'teardown') {
    return false;
  }
  return Boolean(lastVerdict?.success);
}

export function fetchStaffStandingNetworkPreferences(params) {
  return fetchStandingNetworkPreferences(params);
}

export function updateStaffStandingNetworkPreferences(body, params) {
  return updateStandingNetworkPreferences(body, params);
}

export function validateStaffWifiForm(params) {
  return validateWifiApForm(params);
}

export function buildStaffWifiScreenState({
  observed,
  draft,
  selectedApId,
  mutationReadiness = null,
}) {
  const validation = validateStaffWifiForm({
    ssid: draft.ssid,
    password: draft.password,
    requirePassword: false,
    wpaMode: draft.wpaMode,
  });

  const canMutate = mutationReadiness?.allowed === true;
  const observedActionable = Boolean(selectedApId && observed);
  const canSave = Boolean(selectedApId && validation.valid && canMutate && observedActionable);
  const canTeardown = Boolean(selectedApId && canMutate && observedActionable);

  return {
    canSave,
    canTeardown,
    unsupportedClientList: STAFF_WIFI_CLIENT_LIST_UNSUPPORTED,
  };
}

export function formatStaffWifiRestartTeardownFailureMessage({ teardownVerdict, observed }) {
  const stateHint = observed?.readable
    ? observed.activeLabel === 'Включена'
      ? 'Сеть, по доступным данным, сейчас включена.'
      : observed.activeLabel === 'Выключена'
        ? 'Сеть, по доступным данным, сейчас выключена.'
        : `Состояние сети: ${observed.activeLabel}.`
    : 'Точное состояние сети непрочитано — проверьте вручную.';
  const baseMessage = teardownVerdict.message.trim();
  const punctuated = /[.!?…]$/.test(baseMessage) ? baseMessage : `${baseMessage}.`;
  return `${punctuated} ${stateHint} Повторите перезапуск позже или проверьте состояние вручную.`;
}

export function serializeStaffWifiOperatorText({ observed, screen }) {
  const parts = [
    observed?.ssidLabel ?? '',
    observed?.activeLabel ?? '',
    screen.unsupportedClientList,
    STAFF_WIFI_CLIENT_LIST_UNSUPPORTED,
    STAFF_WIFI_PRIMARY_NETWORKS_NOTE,
    STAFF_WIFI_PASSWORD_FIELD_NOTE,
    STAFF_WIFI_NO_OPEN_NETWORK_NOTE,
  ];
  return parts.join('\n');
}

export function serializeStaffWifiTechnicalText({ observed }) {
  if (!observed?.technicalLines?.length) {
    return '';
  }
  return observed.technicalLines.join('\n');
}

export function fetchStaffWifiObservedState(params) {
  return fetchWifiObservedState(params);
}

export function previewStaffWifiChanges(params) {
  return previewWifiChanges(params);
}

export function applyStaffWifiChanges(params) {
  return applyWifiChanges(params);
}

export function teardownStaffWifiNetwork(params) {
  return teardownWifiNetwork(params);
}
