import {
  createBadge,
  createButton,
  createCard,
  createSelectField,
  createTechnicalDetails,
  createTextField,
  createToggle,
  openModal,
} from '../components/index.js';
import { subscribeConnectivity } from '../core/api.js';
import { syncActionButtonById } from '../core/form-submit-sync.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import { getSession, isConnectionRestorePending, subscribeSession, updateSession } from '../core/session.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
  getStateDescriptor,
} from '../core/states.js';
import { buildLiveConnectionParams, describeLiveConnectionAdvancedStatus, isConnectionRestoreFailed, liveCapabilitySubscriptionKey, needsManagementUsernameRecovery } from '../features/live-connection-params.js';
import {
  STAFF_WIFI_CLIENT_LIST_UNSUPPORTED,
  STAFF_WIFI_NO_OPEN_NETWORK_NOTE,
  STAFF_WIFI_PASSWORD_FIELD_NOTE,
  STAFF_WIFI_PRIMARY_NETWORKS_NOTE,
  STAFF_WIFI_SLOT_NUMBER_NOTE,
  STAFF_WIFI_WPA_MODE_OPTIONS,
  STAFF_WIFI_APPLY_DEFAULTS_LABEL,
  STAFF_WIFI_DISABLED_REMEDIATION_MESSAGE,
  STAFF_WIFI_DISABLED_REMEDIATION_TITLE,
  STAFF_WIFI_READABLE_SSID_UNKNOWN_NOTE,
  STAFF_WIFI_STANDING_PASSWORD_ASK_ONCE_MESSAGE,
  applyStaffWifiChanges,
  buildStaffStandingDefaultsDraft,
  buildStaffStandingPreferencesUpdate,
  canApplyStaffStandingDefaults,
  fetchStaffStandingNetworkPreferences,
  updateStaffStandingNetworkPreferences,
  resolveStaffWifiCredentialIntent,
  shouldShowStaffDisabledRemediation,
  staffWifiPasswordFieldNote,
  buildStaffWifiScreenState,
  buildWifiMutationIntentSnapshot,
  buildWifiPreviewBody,
  createStaffWifiFormDraft,
  currentWifiMutationIntentFromDraft,
  deriveWifiPreviewEnabled,
  describeStaffWifiNetworkToggle,
  ensureWifiCredentialRef,
  buildWifiApplyReadbackVerifyingVerdict,
  isObservedWpaModeKnown,
  isWifiConfigurationApplied,
  isWifiWpaModeDraftSelected,
  performWifiApplyReadbackPoll,
  shouldPollWifiApplyReadback,
  revokeWifiApCredential,
  formatStaffWifiRestartTeardownFailureMessage,
  evaluateStaffWifiMutationReadiness,
  fetchStaffWifiObservedState,
  listStaffWifiAccessPoints,
  parseWifiApplyVerdict,
  previewStaffWifiChanges,
  shouldAcceptStaffWifiObservedResult,
  shouldClearStaffWifiFormPasswordAfterMutation,
  shouldPersistStandingPreferencesAfterMutation,
  staffWifiWpaFieldHint,
  teardownStaffWifiNetwork,
  validateStaffWifiForm,
  wifiMutationIntentMatchesCurrent,
  WPA_MODE_DRAFT_PLACEHOLDER_OPTION,
  WIFI_MUTATION_INTENT_STALE_MESSAGE,
  WIFI_OBSERVED_UNREADABLE_DESCRIPTION,
  WIFI_OBSERVED_UNREADABLE_TITLE,
  WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
} from '../features/staff-wifi-model.js';
import {
  buildWifiApSelectSignature,
  buildWifiNetworkHeaderSignature,
  buildWifiSettingsFormSignature,
  buildWifiQrModalBody,
  buildWifiRiskModalBody,
  createUnsupportedCard,
  createWifiDemoBanner,
  createStaffDisabledRemediationBanner,
  createWifiNetworkHeaderCard,
  getWifiRiskConfirmLabel,
  updateButtonBusyState,
  wifiFooterStructureSignature,
} from '../features/wifi-screen-parts.js';

export const meta = {
  id: 'staff-wifi',
  title: 'Рабочая сеть',
  iconName: 'staff-wifi',
};

/** @typedef {'save'|'teardown'|'restart'|'enable'} StaffWifiRiskAction */

/** @type {Readonly<Record<string, string>>} */
const WPA_MODE_LABELS = Object.freeze({
  WPA2: 'WPA2',
  WPA3: 'WPA3',
  WPA2_WPA3_MIXED: 'WPA2 и WPA3 вместе',
});

/**
 * @param {{ message: string, action: string|null }} described
 * @returns {string}
 */
function formatErrorDescription(described) {
  if (described.action) {
    return `${described.message} ${described.action}`;
  }
  return described.message;
}

/**
 * @param {unknown} err
 * @returns {{ title: string, message: string, action: string|null, kind: string, technical: string }}
 */
function describePanelError(err) {
  if (err instanceof HubApiError && err.code === 'client.credential_registration_failed') {
    return {
      title: 'Не удалось сохранить пароль',
      message: err.userMessage,
      action: err.userAction,
      kind: err.kind,
      technical: '',
    };
  }
  return describeError(err);
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isClientAborted(err) {
  return err instanceof HubApiError && err.code === 'client.aborted';
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isAbortError(err) {
  return err instanceof DOMException && err.name === 'AbortError';
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isAborted(err) {
  return isClientAborted(err) || isAbortError(err);
}

/**
 * @param {unknown} err
 * @returns {string}
 */
function hubStateForError(err) {
  const described = describeError(err);
  switch (described.kind) {
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
 * @param {unknown} err
 * @param {boolean} isOffline
 * @returns {string}
 */
function hubStateForLoadError(err, isOffline) {
  if (isOffline) {
    return HubState.NO_INTERNET;
  }
  return hubStateForError(err);
}

/**
 * @param {{ draft: import('../features/staff-wifi-model.js').StaffWifiFormDraft, observed: import('../features/staff-wifi-model.js').ParsedObservedAccessPoint|null, action: StaffWifiRiskAction, hasNewPassword: boolean }} params
 * @returns {string[]}
 */
function buildPlannedChangeLines({ draft, observed, action, hasNewPassword }) {
  /** @type {string[]} */
  const lines = [];
  if (action === 'restart') {
    lines.push('Сеть будет временно отключена и снова включена с текущими настройками');
    lines.push('Это не перезагрузка роутера — только выбранная рабочая сеть');
  } else if (action === 'teardown') {
    lines.push('Сеть будет выключена');
    lines.push('Настройки точки доступа будут сброшены: название, пароль и шифрование');
  } else {
    const trimmedSsid = draft.ssid.trim();
    if (!observed?.readable || observed.ssid !== trimmedSsid) {
      lines.push(`Название сети: «${trimmedSsid}»`);
    }
    if (!observed?.readable || observed.wpaMode !== draft.wpaMode) {
      lines.push(`Защита: ${WPA_MODE_LABELS[draft.wpaMode] ?? draft.wpaMode}`);
    }
    if (hasNewPassword) {
      lines.push('Будет установлен новый пароль');
    }
    const previewEnabled = deriveWifiPreviewEnabled({
      action: action === 'enable' ? 'enable' : action === 'restart' ? 'restart' : 'save',
      observed,
      networkTogglePending: null,
    });
    if (previewEnabled) {
      lines.push('Сеть будет включена');
    } else if (
      (action === 'save' || action === 'restart')
      && observed?.readable
      && observed.activeLabel === 'Выключена'
    ) {
      lines.push('Сеть останется выключенной — сохранятся только параметры');
    }
  }
  if (lines.length === 0) {
    lines.push('Настройки сети будут сохранены повторно');
  }
  return lines;
}

/**
 * @param {HTMLElement} container
 * @param {{ runtime: object, navigate: (routeId: string) => void, showToast: (options: object) => void }} ctx
 * @returns {() => void}
 */
export function render(container, ctx) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  const adapterMode = ctx.runtime?.adapterMode ?? null;
  const apOptions = listStaffWifiAccessPoints();

  let generation = 0;
  let observedGeneration = 0;
  /** @type {number|null} */
  let loadObservedGeneration = null;
  /** @type {number|null} */
  let mutateGeneration = null;
  /** @type {number|null} */
  let prepareGeneration = null;
  let disposed = false;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;
  let recovering = false;

  /** @type {AbortController|null} */
  let observedAbort = null;
  /** @type {AbortController|null} */
  let mutateAbort = null;
  /** @type {AbortController|null} */
  let prepareAbort = null;

  let loadingObserved = false;
  let preparingMutation = false;
  let mutating = false;
  let formDirty = false;
  let advancedOpen = false;

  /** @type {string|null} */
  let selectedApId = getSession().wifiRoles.staffApId;
  /** @type {import('../features/staff-wifi-model.js').ParsedObservedAccessPoint|null} */
  let observed = null;
  /** @type {import('../features/staff-wifi-model.js').StaffWifiFormDraft} */
  let draft = createStaffWifiFormDraft(null, null);
  /** @type {import('../features/staff-wifi-model.js').StandingNetworkPreferences|null} */
  let standing = null;
  let loadingStanding = false;
  /** @type {unknown|null} */
  let standingError = null;
  /** @type {string} */
  let sessionPskMemory = '';
  /** @type {import('../features/wifi-ap-model.js').WifiCredentialRefCache|null} */
  let draftCredentialRef = null;
  let credentialRefGeneration = 0;
  /** @type {boolean|null} */
  let networkTogglePending = null;
  /** @type {unknown|null} */
  let observedError = null;
  /** @type {unknown|null} */
  let operationError = null;
  /** @type {(() => void)|null} */
  let operationRetry = null;
  /** @type {import('../features/staff-wifi-model.js').StaffWifiApplyVerdict|null} */
  let lastVerdict = null;
  /** @type {import('../features/staff-wifi-model.js').StaffWifiApplyVerdict|null} */
  let persistedMutationVerdict = null;
  /** @type {string[]} */
  let formErrors = [];
  let restartAwaitingApply = false;
  /** @type {string|null} */
  let pendingMutationCredentialRefId = null;

  let riskModalOpen = false;
  /** @type {ReturnType<typeof buildWifiMutationIntentSnapshot>|null} */
  let confirmedIntentSnapshot = null;

  /** @type {{ kind: string, id?: string }|null} */
  let pendingFocus = null;

  /** @type {Array<{ close: () => void }>} */
  let openModals = [];

  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-staff-wifi';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.id = 'hub-staff-wifi-screen-title';
  title.tabIndex = -1;
  title.textContent = 'Рабочая сеть';
  header.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent = 'Закрытая сеть для персонала и оборудования';
  header.appendChild(subtitle);
  screen.appendChild(header);

  const verdictSlot = document.createElement('div');
  verdictSlot.className = 'hub-wifi__verdict-slot';
  screen.appendChild(verdictSlot);

  const contentWrap = document.createElement('div');
  contentWrap.className = 'hub-wifi__content';
  screen.appendChild(contentWrap);

  let layoutMounted = false;
  /** @type {string|null} */
  let lastBannerSignature = null;
  /** @type {string|null} */
  let lastNetworkHeaderSignature = null;
  /** @type {string|null} */
  let lastApSelectSignature = null;
  /** @type {string|null} */
  let lastProgressSignature = null;
  /** @type {string|null} */
  let lastSettingsSignature = null;
  /** @type {string|null} */
  let lastSideSignature = null;
  /** @type {string|null} */
  let lastExtraSignature = null;
  /** @type {string|null} */
  let lastFooterSignature = null;
  /** @type {string|null} */
  let lastVerdictSignature = null;

  const bannerSlot = document.createElement('div');
  bannerSlot.className = 'hub-wifi__layout-banner';
  const networkHeaderSlot = document.createElement('div');
  networkHeaderSlot.className = 'hub-wifi__layout-network-header';
  const mainCol = document.createElement('div');
  mainCol.className = 'hub-wifi__layout-main';
  const sideCol = document.createElement('div');
  sideCol.className = 'hub-wifi__layout-side';
  const apSelectSlot = document.createElement('div');
  apSelectSlot.className = 'hub-wifi__ap-select-slot';
  const progressSlot = document.createElement('div');
  progressSlot.className = 'hub-wifi__progress-slot';
  const settingsSlot = document.createElement('div');
  settingsSlot.className = 'hub-wifi__settings-slot';
  const extraSlot = document.createElement('div');
  extraSlot.className = 'hub-wifi__extra-slot';

  const infoNoteWrap = document.createElement('div');
  infoNoteWrap.className = 'hub-staff-wifi__info-note';
  screen.appendChild(infoNoteWrap);

  const footer = document.createElement('footer');
  footer.className = 'hub-wifi__footer';
  const footerLeft = document.createElement('div');
  footerLeft.className = 'hub-wifi__footer-left';
  const footerRight = document.createElement('div');
  footerRight.className = 'hub-wifi__footer-right';
  footer.appendChild(footerLeft);
  footer.appendChild(footerRight);
  screen.appendChild(footer);

  container.appendChild(screen);

  function clearElement(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function hubContentEl() {
    return document.getElementById('hub-content');
  }

  function captureHubContentScroll() {
    const hubContent = hubContentEl();
    return hubContent instanceof HTMLElement ? hubContent.scrollTop : 0;
  }

  /**
   * @param {number} scrollTop
   */
  function restoreHubContentScroll(scrollTop) {
    const hubContent = hubContentEl();
    if (hubContent instanceof HTMLElement) {
      hubContent.scrollTop = scrollTop;
    }
  }

  /**
   * @param {HTMLElement} slot
   * @param {() => void} rebuild
   */
  function rebuildSlot(slot, rebuild) {
    const scrollTop = captureHubContentScroll();
    const active = document.activeElement;
    if (active instanceof HTMLElement && elementContains(slot, active)) {
      if (active.id) {
        pendingFocus = { kind: 'element-id', id: active.id };
      }
    }
    rebuild();
    restorePendingFocus();
    restoreHubContentScroll(scrollTop);
  }

  function mountLayoutOnce() {
    if (layoutMounted) {
      return;
    }
    layoutMounted = true;
    contentWrap.appendChild(bannerSlot);
    contentWrap.appendChild(networkHeaderSlot);
    contentWrap.appendChild(mainCol);
    contentWrap.appendChild(sideCol);
    ensureMainColStructure();
  }

  function elementContains(parent, child) {
    if (typeof parent.contains === 'function') {
      return parent.contains(child);
    }
    let node = child;
    while (node) {
      if (node === parent) {
        return true;
      }
      node = node.parentNode;
    }
    return false;
  }

  function ensureMainColStructure() {
    if (elementContains(mainCol, apSelectSlot)) {
      return;
    }
    mainCol.appendChild(apSelectSlot);
    mainCol.appendChild(progressSlot);
    mainCol.appendChild(settingsSlot);
    mainCol.appendChild(extraSlot);
  }

  function syncContentLayoutClasses() {
    contentWrap.classList.remove('hub-wifi__content--single-column');
    bannerSlot.hidden = !bannerSlot.hasChildNodes();
    networkHeaderSlot.hidden = !networkHeaderSlot.hasChildNodes();
    if (!sideCol.hasChildNodes()) {
      contentWrap.classList.add('hub-wifi__content--single-column');
    }
  }

  function buildBannerSignature() {
    const remediation = shouldShowStaffDisabledRemediation(observed) ? 'remediation' : 'none';
    return `${adapterMode ?? 'null'}|${remediation}`;
  }

  function buildStaffApSelectSignature() {
    return buildWifiApSelectSignature({
      selectedApId,
      observedSsidLabel: observed?.ssidLabel ?? null,
      controlsLocked: controlsLocked(),
      adapterMode,
      overlapWarning: null,
    });
  }

  function buildStaffNetworkHeaderSignature() {
    const readiness = mutationReadiness();
    const toggleState = describeStaffWifiNetworkToggle(observed);
    const toggleBusy = preparingMutation || mutating;
    const displayChecked =
      networkTogglePending !== null ? networkTogglePending : toggleState.checked;
    const displayIndeterminate =
      networkTogglePending === null && toggleState.unknown && !toggleBusy;
    const toggleDisabled =
      !selectedApId || !readiness.allowed || controlsLocked() || offline || toggleBusy;
    return buildWifiNetworkHeaderSignature({
      selectedApId,
      observedSsidLabel: observed?.ssidLabel ?? null,
      observedActiveLabel: observed?.activeLabel ?? null,
      networkTogglePending,
      toggleChecked: displayChecked,
      toggleIndeterminate: displayIndeterminate,
      toggleDisabled,
      controlsLocked: controlsLocked(),
      offline,
      stabilizeObservedLabels: preparingMutation || mutating,
    });
  }

  function buildStaffSettingsSignature() {
    return buildWifiSettingsFormSignature({
      selectedApId,
      ssid: draft.ssid,
      wpaMode: draft.wpaMode,
      hasPassword: draft.password.length > 0,
      formDirty,
      controlsLocked: controlsLocked(),
      advancedOpen,
      wpaModeKnown: isObservedWpaModeKnown(observed),
      formErrorCount: formErrors.length,
    });
  }

  function buildStaffSideSignature() {
    return selectedApId && canRenderObservedForm() ? 'staff-side' : 'empty';
  }

  function buildStaffProgressSignature() {
    const session = getSession();
    if (isConnectionRestorePending(session)) {
      return 'restore-pending';
    }
    if (isConnectionRestoreFailed(session)) {
      return 'restore-failed';
    }
    if (needsManagementUsernameRecovery(session)) {
      return 'needs-username';
    }
    if (offline && !recovering) {
      return 'offline';
    }
    if (recovering) {
      return 'recovering';
    }
    if (!selectedApId) {
      return 'no-ap';
    }
    if (preparingMutation) {
      return 'preparing';
    }
    if (mutating) {
      return 'mutating';
    }
    if (loadingObserved && !observed) {
      return 'loading-initial';
    }
    if (observedError && !isAborted(observedError) && !observed) {
      return `observed-error|${describePanelError(observedError).title}`;
    }
    if (isObservedUnreadable()) {
      return 'unreadable';
    }
    if (operationError && !isAborted(operationError)) {
      return `op-error|${describePanelError(operationError).title}`;
    }
    return 'idle';
  }

  function buildStaffExtraSignature() {
    const readiness = mutationReadiness();
    if (!readiness.allowed && readiness.reasonText && adapterMode !== 'fake') {
      return `readiness|${readiness.reasonText}`;
    }
    if (standingError && !isAborted(standingError)) {
      return `standing-load-fail|${describePanelError(standingError).title}`;
    }
    if (observed && observedError && !isAborted(observedError)) {
      return `observed-soft-fail|${describePanelError(observedError).title}`;
    }
    return 'none';
  }

  function buildStaffFooterSignature() {
    const state = screenState();
    const readiness = mutationReadiness();
    const applyDefaults = canApplyStaffStandingDefaults({
      selectedApId,
      standing,
      mutationReadiness: readiness,
    });
    return [
      selectedApId ?? 'none',
      state.canSave ? 'can-save' : 'no-save',
      state.canTeardown ? 'can-teardown' : 'no-teardown',
      applyDefaults ? 'apply-defaults' : 'no-apply-defaults',
      preparingMutation ? 'preparing' : 'idle',
      mutating ? 'mutating' : 'idle',
      offline ? 'offline' : 'online',
      controlsLocked() ? 'locked' : 'unlocked',
      readiness.reasonText ?? 'none',
    ].join('|');
  }

  function syncStaffFooterButtonsInPlace() {
    const state = screenState();
    const readiness = mutationReadiness();
    const applyDefaults = canApplyStaffStandingDefaults({
      selectedApId,
      standing,
      mutationReadiness: readiness,
    });
    syncActionButtonById('hub-staff-wifi-save-btn', {
      disabled: !state.canSave || offline || preparingMutation,
      busy: controlsLocked(),
    });
    syncActionButtonById('hub-staff-wifi-restart-btn', {
      disabled: !state.canTeardown || offline || preparingMutation,
      busy: controlsLocked(),
    });
    syncActionButtonById('hub-staff-wifi-apply-defaults-btn', {
      disabled: !applyDefaults || offline || preparingMutation || mutating,
      busy: controlsLocked(),
    });
  }

  /**
   * @param {{ summary: string, content: Node, open?: boolean, onToggle?: (open: boolean) => void }} options
   * @returns {HTMLDetailsElement}
   */
  function createSettingsSection({ summary, content, open = false, onToggle }) {
    const details = document.createElement('details');
    details.className = 'hub-wifi-settings-section';
    details.open = open;

    const summaryEl = document.createElement('summary');
    summaryEl.textContent = summary;
    details.appendChild(summaryEl);

    const body = document.createElement('div');
    body.className = 'hub-wifi-settings-section-body';
    body.appendChild(content);
    details.appendChild(body);

    details.addEventListener('toggle', () => {
      if (typeof onToggle === 'function') {
        onToggle(details.open);
      }
    });

    return details;
  }

  /**
   * @param {StaffWifiRiskAction} action
   * @returns {string}
   */
  function focusTargetIdAfterRiskConfirm(action) {
    if (action === 'save') {
      return 'hub-staff-wifi-save-btn';
    }
    return 'hub-staff-wifi-network-toggle';
  }

  function clearSessionSecrets() {
    sessionPskMemory = '';
    const pendingRef = draftCredentialRef;
    draftCredentialRef = null;
    draft = { ...draft, password: '' };
    const pwdEl = document.getElementById('hub-staff-wifi-password');
    if (pwdEl instanceof HTMLInputElement) {
      pwdEl.value = '';
    }
    const session = getSession();
    if (pendingRef?.refId && session.routerId) {
      void revokeWifiApCredential({
        routerId: session.routerId,
        credentialRefId: pendingRef.refId,
      }).catch(() => {});
    }
  }

  function revokePendingDraftCredentialRef() {
    const pendingRef = draftCredentialRef;
    const refId = pendingRef?.refId;
    const revokeGen = credentialRefGeneration;
    draftCredentialRef = null;
    const session = getSession();
    if (!refId || !session.routerId) {
      return;
    }
    void (async () => {
      if (revokeGen !== credentialRefGeneration) {
        return;
      }
      try {
        await revokeWifiApCredential({
          routerId: session.routerId,
          credentialRefId: refId,
        });
      } catch {
        /* cancel/dispose revoke is best-effort */
      }
    })();
  }

  function cancelPreparedMutation() {
    revokePendingDraftCredentialRef();
    resetToggleAfterCancel();
  }

  function clearPreparedMutation() {
    closeAllModals();
    riskModalOpen = false;
    confirmedIntentSnapshot = null;
    abortPrepare();
    if (preparingMutation) {
      preparingMutation = false;
      prepareGeneration = null;
    }
  }

  function invalidateAllOperations() {
    generation += 1;
    observedGeneration += 1;
    abortAllOperations();
    loadingObserved = false;
    preparingMutation = false;
    mutating = false;
    loadObservedGeneration = null;
    mutateGeneration = null;
    prepareGeneration = null;
  }

  function registerModal(modalRef) {
    openModals.push(modalRef);
    const originalClose = modalRef.close;
    modalRef.close = () => {
      const index = openModals.indexOf(modalRef);
      if (index >= 0) {
        openModals.splice(index, 1);
      }
      originalClose();
    };
    return modalRef;
  }

  function closeAllModals() {
    while (openModals.length > 0) {
      const modal = openModals.pop();
      modal?.close();
    }
  }

  function captureFocusBeforeRender() {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement)) {
      return;
    }
    const fieldId = active.id;
    if (fieldId === 'hub-staff-wifi-ssid' || fieldId === 'hub-staff-wifi-password') {
      pendingFocus = { kind: 'element-id', id: fieldId };
    }
  }

  function restorePendingFocus() {
    if (!pendingFocus) {
      return;
    }
    const target = pendingFocus;
    pendingFocus = null;
    if (target.kind === 'element-id' && target.id) {
      const el = document.getElementById(target.id);
      if (
        el instanceof HTMLElement
        && !((el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.disabled)
      ) {
        el.focus();
        return;
      }
      title.focus();
      return;
    }
    if (target.kind === 'first-field-error') {
      const invalid = contentWrap.querySelector('.hub-field__input[aria-invalid="true"]');
      if (invalid instanceof HTMLElement) {
        invalid.focus();
      }
    }
  }

  function abortObserved() {
    observedAbort?.abort();
  }

  function abortMutate() {
    mutateAbort?.abort();
  }

  function abortPrepare() {
    prepareAbort?.abort();
  }

  function abortAllOperations() {
    abortObserved();
    abortMutate();
    abortPrepare();
  }

  function markFormDirty() {
    formDirty = true;
    syncWifiFormFooterUi();
  }

  function syncWifiFormFooterUi() {
    if (disposed) {
      return;
    }
    const state = screenState();
    const saveDisabled = !state.canSave || offline || preparingMutation;
    syncActionButtonById('hub-staff-wifi-save-btn', {
      disabled: saveDisabled,
      busy: controlsLocked(),
    });
  }

  function syncSelectedApToSession(apId) {
    updateSession({
      wifiRoles: { staffApId: apId },
    });
  }

  function canRenderObservedForm() {
    return Boolean(selectedApId && !offline && observed);
  }

  function isObservedUnreadable() {
    return Boolean(
      selectedApId && !offline && observed && observed.readable !== true,
    );
  }

  function controlsLocked() {
    return preparingMutation || mutating || riskModalOpen;
  }

  function mutationReadiness() {
    return evaluateStaffWifiMutationReadiness(getSession(), adapterMode);
  }

  function screenState() {
    return buildStaffWifiScreenState({
      observed,
      draft,
      selectedApId,
      mutationReadiness: mutationReadiness(),
    });
  }

  /**
   * @param {StaffWifiRiskAction} action
   * @param {string[]} changeLines
   * @param {(confirmedSnapshot: ReturnType<typeof buildWifiMutationIntentSnapshot>) => Promise<void>} onConfirm
   * @param {(() => void)|undefined} onCancel
   */
  function openRiskModal(action, changeLines, onConfirm, onCancel, returnFocusTo, intentSnapshot) {
    const body = buildWifiRiskModalBody({ audience: 'staff', changeLines });

    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    let confirmed = false;
    confirmedIntentSnapshot = intentSnapshot;
    riskModalOpen = true;
    renderAll();

    const cancelBtn = createButton({
      label: 'Отмена',
      variant: 'ghost',
      onActivate: () => {
        modalRef?.close();
      },
    });

    const confirmBtn = createButton({
      label: getWifiRiskConfirmLabel(action),
      variant: action === 'teardown' ? 'danger' : 'primary',
      onActivate: () => {
        void (async () => {
          confirmed = true;
          const confirmedSnapshot = intentSnapshot;
          pendingFocus = { kind: 'element-id', id: focusTargetIdAfterRiskConfirm(action) };
          modalRef?.close();
          if (offline) {
            ctx.showToast({
              tone: 'danger',
              title: 'Нет связи с сервером управления',
              message: 'Подтвердить изменение сейчас нельзя — дождитесь восстановления связи.',
            });
            onCancel?.();
            return;
          }
          await onConfirm(confirmedSnapshot);
        })();
      },
    });

    modalRef = registerModal(
      openModal({
        title: 'Риск обрыва связи',
        description: 'Подтвердите действие только если готовы восстановить доступ другим способом.',
        body,
        tone: 'warning',
        actions: [cancelBtn, confirmBtn],
        ...(returnFocusTo instanceof HTMLElement ? { returnFocusTo } : {}),
        onClose: () => {
          riskModalOpen = false;
          confirmedIntentSnapshot = null;
          renderAll();
          if (!confirmed) {
            onCancel?.();
          }
        },
      }),
    );
  }

  function openQrModal() {
    const ssid = draft.ssid.trim() || observed?.ssidLabel || '';
    const psk = sessionPskMemory || draft.password;

    const body = buildWifiQrModalBody({
      ssid,
      psk,
      wpaMode: draft.wpaMode,
    });

    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    const closeBtn = createButton({
      label: 'Закрыть',
      variant: 'ghost',
      onActivate: () => {
        modalRef?.close();
      },
    });

    modalRef = registerModal(
      openModal({
        title: 'QR-код сети',
        description: 'Пароль не сохраняется и не попадает в адрес страницы.',
        body,
        actions: [closeBtn],
        onClose: () => {
          sessionPskMemory = '';
        },
      }),
    );
  }

  function renderDemoBanner() {
    if (adapterMode !== 'fake') {
      return null;
    }
    return createWifiDemoBanner({
      onNavigateToConnection: () => {
        ctx.navigate('connection');
      },
    });
  }

  function renderApSelection() {
    const card = createCard({
      title: 'Какую сеть считать рабочей',
      titleTag: 'h2',
      body: '',
    });
    const body = card.querySelector('.hub-card__body') ?? card;

    const note = document.createElement('p');
    note.className = 'hub-wifi__note';
    note.textContent = STAFF_WIFI_PRIMARY_NETWORKS_NOTE;
    body.appendChild(note);

    const slotNote = document.createElement('p');
    slotNote.className = 'hub-wifi__note';
    slotNote.textContent = STAFF_WIFI_SLOT_NUMBER_NOTE;
    body.appendChild(slotNote);

    const selectOptions = apOptions.map((option) => {
      let label = option.label;
      if (selectedApId === option.apId && observed?.readable && observed.ssidLabel) {
        const ssidPart =
          observed.ssidLabel !== 'Название сети не прочитано' &&
          observed.ssidLabel !== 'Состояние не прочитано'
            ? ` — ${observed.ssidLabel}`
            : '';
        label = `${option.label}${ssidPart}`;
      }
      return { value: option.apId, label };
    });

    const apField = createSelectField({
      id: 'hub-staff-wifi-ap-select',
      label: 'Номер рабочей сети',
      options: selectOptions,
      value: selectedApId ?? '',
      disabled: controlsLocked(),
      hint: 'Выбор действует до перезагрузки страницы — приложение ничего не сохраняет в браузере.',
      onChange: (event) => {
        if (event.target instanceof HTMLSelectElement) {
          const nextApId = event.target.value || null;
          if (nextApId === selectedApId) {
            return;
          }
          clearPreparedMutation();
          revokePendingDraftCredentialRef();
          sessionPskMemory = '';
          selectedApId = nextApId;
          syncSelectedApToSession(nextApId);
          observed = null;
          observedError = null;
          lastVerdict = null;
          persistedMutationVerdict = null;
          operationError = null;
          formDirty = false;
          draft = createStaffWifiFormDraft(null, standing);
          pendingFocus = { kind: 'element-id', id: 'hub-staff-wifi-ap-select' };
          renderAll();
          if (selectedApId) {
            void loadObservedFlow();
          }
        }
      },
    });
    body.appendChild(apField);
    return card;
  }

  function renderNetworkHeader() {
    const ssidTitle =
      observed?.ssidLabel && observed.ssidLabel !== 'Состояние не прочитано'
        ? observed.ssidLabel
        : 'Название сети не прочитано';

    const badge = createBadge({
      label: observed?.activeLabel ?? 'Состояние не прочитано',
      tone: observed?.activeTone ?? 'neutral',
    });

    const readiness = mutationReadiness();
    const toggleState = describeStaffWifiNetworkToggle(observed);
    const toggleBusy = preparingMutation || mutating;
    const displayChecked =
      networkTogglePending !== null ? networkTogglePending : toggleState.checked;
    const displayIndeterminate =
      networkTogglePending === null && toggleState.unknown && !toggleBusy;
    const toggleDisabled =
      !selectedApId || !readiness.allowed || controlsLocked() || offline || toggleBusy;

    const toggle = createToggle({
      id: 'hub-staff-wifi-network-toggle',
      label: 'Сеть',
      checked: displayChecked,
      indeterminate: displayIndeterminate,
      disabled: toggleDisabled,
      tone: 'success',
      onChange: (checked) => {
        networkTogglePending = checked;
        renderAll();
        if (checked) {
          void enableNetworkFlow();
        } else {
          void teardownFlow();
        }
      },
    });
    const toggleInput = toggle.querySelector('input');
    if (toggleInput) {
      toggleInput.setAttribute('aria-label', `Сеть: ${toggleState.description}`);
    }

    /** @type {HTMLElement|null} */
    let unknownActions = null;
    if (displayIndeterminate && !toggleDisabled) {
      unknownActions = document.createElement('div');
      unknownActions.className = 'hub-wifi-network__unknown-actions';
      unknownActions.appendChild(
        createButton({
          label: 'Включить сеть',
          variant: 'secondary',
          disabled: controlsLocked() || offline,
          onActivate: () => {
            networkTogglePending = true;
            renderAll();
            void enableNetworkFlow();
          },
        }),
      );
      unknownActions.appendChild(
        createButton({
          label: 'Выключить сеть',
          variant: 'danger',
          disabled: controlsLocked() || offline,
          onActivate: () => {
            networkTogglePending = false;
            renderAll();
            void teardownFlow();
          },
        }),
      );
    }

    const qrBtn = createButton({
      label: 'Показать QR-код',
      variant: 'secondary',
      iconName: 'qr',
      disabled: !selectedApId,
      onActivate: () => {
        openQrModal();
      },
    });

    return createWifiNetworkHeaderCard({
      iconName: 'staff-wifi',
      ssidTitle,
      badge,
      secondaryLine:
        'Роутер не сообщает число подключённых устройств — счётчик показать нечем.',
      toggle,
      unknownActions,
      qrButton: qrBtn,
    });
  }

  function renderSettingsCard() {
    const card = createCard({
      title: 'Настройки сети',
      titleTag: 'h2',
    });
    const body = card.querySelector('.hub-card__body') ?? card;

    const ssidError = formErrors.find(
      (err) => err.includes('назван') || err.includes('пробел') || err.includes('32'),
    );
    const passwordError = formErrors.find((err) => err.includes('парол') || err.includes('8 символ'));

    body.appendChild(
      createTextField({
        id: 'hub-staff-wifi-ssid',
        label: 'Название сети',
        value: draft.ssid,
        disabled: !selectedApId || controlsLocked(),
        error: ssidError,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            draft = { ...draft, ssid: event.target.value };
            markFormDirty();
          }
        },
      }),
    );

    body.appendChild(
      createTextField({
        id: 'hub-staff-wifi-password',
        label: 'Пароль',
        secret: true,
        autocomplete: 'new-password',
        placeholder: 'Новый пароль',
        value: draft.password,
        hint: staffWifiPasswordFieldNote(standing),
        disabled: !selectedApId || controlsLocked(),
        error: passwordError,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            draft = { ...draft, password: event.target.value };
            sessionPskMemory = event.target.value;
            markFormDirty();
          }
        },
      }),
    );

    if (observed?.readable && !observed?.ssid) {
      const ssidNote = document.createElement('p');
      ssidNote.className = 'hub-wifi__note';
      ssidNote.textContent = STAFF_WIFI_READABLE_SSID_UNKNOWN_NOTE;
      body.appendChild(ssidNote);
    }

    const wpaHint = staffWifiWpaFieldHint(observed);
    const wpaOptions =
      isObservedWpaModeKnown(observed) || isWifiWpaModeDraftSelected(draft.wpaMode)
        ? STAFF_WIFI_WPA_MODE_OPTIONS
        : [WPA_MODE_DRAFT_PLACEHOLDER_OPTION, ...STAFF_WIFI_WPA_MODE_OPTIONS];
    body.appendChild(
      createSelectField({
        id: 'hub-staff-wifi-wpa',
        label: 'Защита',
        options: wpaOptions,
        value: draft.wpaMode,
        hint: wpaHint || undefined,
        disabled: !selectedApId || controlsLocked(),
        onChange: (event) => {
          if (event.target instanceof HTMLSelectElement) {
            draft = {
              ...draft,
              wpaMode: /** @type {import('../features/staff-wifi-model.js').StaffWifiWpaMode} */ (
                event.target.value
              ),
            };
            markFormDirty();
          }
        },
      }),
    );

    const openNote = document.createElement('p');
    openNote.className = 'hub-wifi__note';
    openNote.textContent = STAFF_WIFI_NO_OPEN_NETWORK_NOTE;
    body.appendChild(openNote);

    const unsupportedWrap = document.createElement('div');
    unsupportedWrap.className = 'hub-wifi__unsupported-group';

    const hiddenRow = document.createElement('div');
    hiddenRow.className = 'hub-wifi__unsupported-row';
    const hiddenLabel = document.createElement('span');
    hiddenLabel.className = 'hub-wifi__unsupported-label';
    hiddenLabel.textContent = 'Скрывать название сети';
    hiddenRow.appendChild(hiddenLabel);
    const hiddenNote = document.createElement('span');
    hiddenNote.className = 'hub-wifi__unsupported-note';
    hiddenNote.textContent =
      'Роутер не отдаёт эту настройку через управление — измените её в веб-интерфейсе роутера';
    hiddenRow.appendChild(hiddenNote);
    unsupportedWrap.appendChild(hiddenRow);

    const routerAccessRow = document.createElement('div');
    routerAccessRow.className = 'hub-wifi__unsupported-row';
    const routerAccessLabel = document.createElement('span');
    routerAccessLabel.className = 'hub-wifi__unsupported-label';
    routerAccessLabel.textContent = 'Разрешить доступ к роутеру';
    routerAccessRow.appendChild(routerAccessLabel);
    const routerAccessNote = document.createElement('span');
    routerAccessNote.className = 'hub-wifi__unsupported-note';
    routerAccessNote.textContent =
      'Роутер не отдаёт эту настройку через управление — измените её в веб-интерфейсе роутера';
    routerAccessRow.appendChild(routerAccessNote);
    unsupportedWrap.appendChild(routerAccessRow);

    body.appendChild(unsupportedWrap);

    const advancedContent = document.createElement('div');
    advancedContent.className = 'hub-wifi__advanced-content';

    const rollbackLine = document.createElement('p');
    rollbackLine.textContent =
      'Если что-то пойдёт не так, система постарается вернуть прежние название, пароль и защиту.';
    advancedContent.appendChild(rollbackLine);

    const repeatSaveLine = document.createElement('p');
    repeatSaveLine.textContent =
      'Повторное сохранение с теми же настройками безопасно — лишних изменений не будет.';
    advancedContent.appendChild(repeatSaveLine);

    const live = buildLiveConnectionParams(getSession());
    const liveLine = document.createElement('p');
    liveLine.textContent = describeLiveConnectionAdvancedStatus(getSession(), adapterMode);
    advancedContent.appendChild(liveLine);

    const technicalNotes = [
      'compensate_on_failure: true',
      'idempotent: true (в теле запроса apply)',
    ];
    if (live.complete) {
      technicalNotes.push('live connection params: complete');
    } else if (live.missing.length > 0) {
      technicalNotes.push(`live connection params missing: ${live.missing.join(', ')}`);
    }
    advancedContent.appendChild(
      createTechnicalDetails({
        summary: 'Технические параметры сохранения',
        content: technicalNotes.join('\n'),
      }),
    );

    if (observed?.technicalLines?.length) {
      advancedContent.appendChild(
        createTechnicalDetails({
          summary: 'Технические идентификаторы',
          content: observed.technicalLines.join('\n'),
        }),
      );
    }

    const advancedDetails = createSettingsSection({
      summary: 'Расширенные настройки',
      content: advancedContent,
      open: advancedOpen,
      onToggle: (open) => {
        advancedOpen = open;
      },
    });
    body.appendChild(advancedDetails);

    return card;
  }

  function renderUnsupportedCard(title, description) {
    return createUnsupportedCard({ title, description });
  }

  function buildMutationVerdictSignature() {
    const verdictToRender = lastVerdict ?? persistedMutationVerdict;
    if (!verdictToRender) {
      return 'none';
    }
    return [
      verdictToRender.title,
      verdictToRender.success ? 'ok' : 'fail',
      verdictToRender.hubState ?? '',
      verdictToRender.message ?? '',
      String((verdictToRender.technicalLines ?? []).length),
    ].join('|');
  }

  function renderMutationVerdict() {
    const signature = buildMutationVerdictSignature();
    if (signature === lastVerdictSignature && verdictSlot.firstChild) {
      return;
    }
    lastVerdictSignature = signature;
    clearElement(verdictSlot);
    const verdictToRender = lastVerdict ?? persistedMutationVerdict;
    if (!verdictToRender) {
      verdictSlot.hidden = true;
      delete verdictSlot.dataset.verdictTitle;
      delete verdictSlot.dataset.verdictSuccess;
      return;
    }
    verdictSlot.hidden = false;
    verdictSlot.dataset.verdictTitle = verdictToRender.title;
    verdictSlot.dataset.verdictSuccess = verdictToRender.success ? 'true' : 'false';
    const verdictBlock = document.createElement('div');
    verdictBlock.className = 'hub-wifi__verdict';
    try {
      verdictBlock.appendChild(
        createInlineState({
          state: verdictToRender.hubState,
          title: verdictToRender.title,
        }),
      );
    } catch {
      const fallbackTitle = document.createElement('p');
      fallbackTitle.className = 'hub-wifi__note';
      fallbackTitle.textContent = verdictToRender.title;
      verdictBlock.appendChild(fallbackTitle);
    }
    const verdictMessage = document.createElement('p');
    verdictMessage.className = 'hub-wifi__note';
    verdictMessage.textContent = verdictToRender.message;
    verdictBlock.appendChild(verdictMessage);
    verdictSlot.appendChild(verdictBlock);
    if ((verdictToRender.technicalLines ?? []).length > 0) {
      verdictSlot.appendChild(
        createTechnicalDetails({ content: verdictToRender.technicalLines.join('\n') }),
      );
    }
  }

  function renderBannerSlot() {
    if (disposed) {
      return;
    }
    const signature = buildBannerSignature();
    if (signature === lastBannerSignature && bannerSlot.firstChild) {
      return;
    }
    lastBannerSignature = signature;
    rebuildSlot(bannerSlot, () => {
      clearElement(bannerSlot);
      const demoBanner = renderDemoBanner();
      if (demoBanner) {
        bannerSlot.appendChild(demoBanner);
      }
      if (shouldShowStaffDisabledRemediation(observed)) {
        const readiness = mutationReadiness();
        bannerSlot.appendChild(
          createStaffDisabledRemediationBanner({
            title: STAFF_WIFI_DISABLED_REMEDIATION_TITLE,
            message: STAFF_WIFI_DISABLED_REMEDIATION_MESSAGE,
            enableLabel: 'Включить рабочую сеть',
            disabled: !readiness.allowed || controlsLocked() || offline || preparingMutation || mutating,
            onEnable: () => {
              networkTogglePending = true;
              renderAll();
              void enableNetworkFlow();
            },
          }),
        );
      }
    });
  }

  function renderApSelectSlot() {
    if (disposed) {
      return;
    }
    const session = getSession();
    if (
      isConnectionRestorePending(session) ||
      isConnectionRestoreFailed(session) ||
      needsManagementUsernameRecovery(session)
    ) {
      if (apSelectSlot.firstChild) {
        clearElement(apSelectSlot);
        lastApSelectSignature = null;
      }
      return;
    }
    const signature = buildStaffApSelectSignature();
    if (signature === lastApSelectSignature && apSelectSlot.firstChild) {
      return;
    }
    lastApSelectSignature = signature;
    rebuildSlot(apSelectSlot, () => {
      clearElement(apSelectSlot);
      apSelectSlot.appendChild(renderApSelection());
    });
  }

  function renderNetworkHeaderSlot() {
    if (disposed) {
      return;
    }
    if (!canRenderObservedForm()) {
      if (networkHeaderSlot.firstChild) {
        clearElement(networkHeaderSlot);
        lastNetworkHeaderSignature = null;
      }
      return;
    }
    const signature = buildStaffNetworkHeaderSignature();
    if (signature === lastNetworkHeaderSignature && networkHeaderSlot.firstChild) {
      return;
    }
    lastNetworkHeaderSignature = signature;
    rebuildSlot(networkHeaderSlot, () => {
      clearElement(networkHeaderSlot);
      networkHeaderSlot.appendChild(renderNetworkHeader());
    });
  }

  function renderSettingsSlot() {
    if (disposed) {
      return;
    }
    if (!canRenderObservedForm()) {
      if (settingsSlot.firstChild) {
        clearElement(settingsSlot);
        lastSettingsSignature = null;
      }
      return;
    }
    const signature = buildStaffSettingsSignature();
    if (signature === lastSettingsSignature && settingsSlot.firstChild) {
      return;
    }
    lastSettingsSignature = signature;
    rebuildSlot(settingsSlot, () => {
      clearElement(settingsSlot);
      settingsSlot.appendChild(renderSettingsCard());
    });
  }

  function renderSideSlot() {
    if (disposed) {
      return;
    }
    const signature = buildStaffSideSignature();
    if (signature === 'empty') {
      if (sideCol.firstChild) {
        clearElement(sideCol);
        lastSideSignature = signature;
      }
      return;
    }
    if (signature === lastSideSignature && sideCol.firstChild) {
      return;
    }
    lastSideSignature = signature;
    rebuildSlot(sideCol, () => {
      clearElement(sideCol);
      sideCol.appendChild(
        renderUnsupportedCard(
          'Подключённые устройства',
          `${STAFF_WIFI_CLIENT_LIST_UNSUPPORTED} Отключить неизвестное устройство с этой панели нельзя.`,
        ),
      );
      sideCol.appendChild(
        renderUnsupportedCard(
          'Страница для персонала',
          'Роутер не предоставляет настройку страницы входа для персонала — раздел недоступен.',
        ),
      );
    });
  }

  function renderProgressSlot() {
    if (disposed) {
      return;
    }
    const signature = buildStaffProgressSignature();
    if (signature === lastProgressSignature && progressSlot.firstChild) {
      return;
    }
    lastProgressSignature = signature;
    rebuildSlot(progressSlot, () => {
      clearElement(progressSlot);
      const session = getSession();
      if (isConnectionRestorePending(session)) {
        const pendingState = createInlineState({
          state: HubState.LOADING,
          title: 'Проверяем сохранённое подключение на сервере',
        });
        pendingState.setAttribute('aria-live', 'polite');
        progressSlot.appendChild(pendingState);
        return;
      }
      if (isConnectionRestoreFailed(session)) {
        progressSlot.appendChild(
          createStatePanel({
            state: HubState.WARNING,
            titleTag: 'h2',
            title: 'Не удалось проверить сохранённое подключение',
            description:
              'Сервер не ответил вовремя или вернул ошибку. Откройте «Подключение» и повторите проверку или обновите страницу.',
            action: {
              label: 'Открыть «Подключение»',
              onActivate: () => {
                ctx.navigate('connection');
              },
            },
          }),
        );
        return;
      }
      if (needsManagementUsernameRecovery(session)) {
        progressSlot.appendChild(
          createStatePanel({
            state: HubState.WARNING,
            titleTag: 'h2',
            title: 'Нужно имя пользователя для управления',
            description:
              'На сервере сохранён отпечаток роутера, но не указано имя пользователя. Откройте «Подключение» и заполните одно поле — повторное подтверждение отпечатка не требуется.',
            action: {
              label: 'Открыть «Подключение»',
              onActivate: () => {
                ctx.navigate('connection');
              },
            },
          }),
        );
        return;
      }
      if (offline && !recovering) {
        progressSlot.appendChild(
          createStatePanel({
            state: HubState.NO_INTERNET,
            titleTag: 'h2',
            action: {
              label: 'Повторить',
              onActivate: () => {
                if (selectedApId) {
                  void loadObservedFlow();
                }
              },
            },
          }),
        );
      }
      if (recovering) {
        progressSlot.appendChild(
          createInlineState({
            state: HubState.RECOVERING,
            title: 'Восстанавливаем связь с сервером управления',
          }),
        );
      }
      if (!selectedApId) {
        progressSlot.appendChild(
          createStatePanel({
            state: HubState.EMPTY,
            titleTag: 'h2',
            title: 'Выберите рабочую сеть',
            description:
              'Укажите номер рабочей сети — после этого можно читать состояние и менять настройки.',
          }),
        );
        return;
      }
      if (loadingObserved && !observed) {
        progressSlot.appendChild(
          createInlineState({ state: HubState.LOADING, title: 'Читаем состояние сети с роутера' }),
        );
        progressSlot.appendChild(createSkeleton({ lines: 4, withTitle: true }));
      }
      if (observedError && !isAborted(observedError) && !observed) {
        const described = describePanelError(observedError);
        progressSlot.appendChild(
          createStatePanel({
            state: hubStateForLoadError(observedError, offline),
            titleTag: 'h2',
            title: described.title,
            description: formatErrorDescription(described),
            details: described.technical || undefined,
            action: {
              label: 'Повторить',
              onActivate: () => {
                void loadObservedFlow();
              },
            },
          }),
        );
      }
      if (isObservedUnreadable()) {
        progressSlot.appendChild(
          createInlineState({
            state: HubState.WARNING,
            title: WIFI_OBSERVED_UNREADABLE_TITLE,
          }),
        );
        const unreadableNote = document.createElement('p');
        unreadableNote.className = 'hub-wifi__note';
        unreadableNote.textContent = WIFI_OBSERVED_UNREADABLE_DESCRIPTION;
        progressSlot.appendChild(unreadableNote);
      }
      if (preparingMutation) {
        progressSlot.appendChild(
          createInlineState({ state: HubState.CONNECTING, title: 'Готовим изменения сети' }),
        );
      }
      if (mutating) {
        progressSlot.appendChild(
          createInlineState({ state: HubState.CONNECTING, title: 'Сохраняем изменения сети' }),
        );
      }
      if (operationError && !isAborted(operationError)) {
        const described = describePanelError(operationError);
        progressSlot.appendChild(
          createStatePanel({
            state: hubStateForError(operationError),
            titleTag: 'h2',
            title: described.title,
            description: formatErrorDescription(described),
            details: described.technical || undefined,
            action: operationRetry
              ? {
                  label: 'Повторить',
                  onActivate: () => {
                    operationRetry?.();
                  },
                }
              : undefined,
          }),
        );
      }
    });
  }

  function renderExtraSlot() {
    if (disposed) {
      return;
    }
    const signature = buildStaffExtraSignature();
    if (signature === 'none') {
      if (extraSlot.firstChild) {
        clearElement(extraSlot);
        lastExtraSignature = signature;
      }
      return;
    }
    if (signature === lastExtraSignature && extraSlot.firstChild) {
      return;
    }
    lastExtraSignature = signature;
    rebuildSlot(extraSlot, () => {
      clearElement(extraSlot);
      const readiness = mutationReadiness();
      if (!readiness.allowed && readiness.reasonText && adapterMode !== 'fake') {
        extraSlot.appendChild(
          createInlineState({
            state: HubState.WARNING,
            title: readiness.reasonText,
          }),
        );
        return;
      }
      if (standingError && !isAborted(standingError)) {
        const described = describePanelError(standingError);
        extraSlot.appendChild(
          createInlineState({
            state: HubState.WARNING,
            title: 'Не удалось загрузить обычные настройки',
          }),
        );
        const note = document.createElement('p');
        note.className = 'hub-wifi__note';
        note.textContent = `${formatErrorDescription(described)} Значения по умолчанию могут быть пустыми.`;
        extraSlot.appendChild(note);
        return;
      }
      if (observed && observedError && !isAborted(observedError)) {
        const described = describePanelError(observedError);
        extraSlot.appendChild(
          createInlineState({
            state: hubStateForLoadError(observedError, offline),
            title: described.title,
          }),
        );
        const note = document.createElement('p');
        note.className = 'hub-wifi__note';
        note.textContent = formatErrorDescription(described);
        extraSlot.appendChild(note);
      }
    });
  }

  function renderContent() {
    mountLayoutOnce();
    renderBannerSlot();
    renderApSelectSlot();
    renderProgressSlot();
    renderNetworkHeaderSlot();
    renderSettingsSlot();
    renderExtraSlot();
    renderSideSlot();
    syncContentLayoutClasses();
  }

  function renderInfoNote() {
    clearElement(infoNoteWrap);
    const note = document.createElement('p');
    note.className = 'hub-staff-wifi__info-text';
    note.textContent =
      'Доступ к рабочей сети выдают только сотрудникам — не делитесь паролем и QR-кодом с посторонними.';
    infoNoteWrap.appendChild(note);
  }

  function renderFooter() {
    const signature = buildStaffFooterSignature();
    const hasFooter =
      document.getElementById('hub-staff-wifi-save-btn') instanceof HTMLElement
      && document.getElementById('hub-staff-wifi-restart-btn') instanceof HTMLElement;
    if (signature === lastFooterSignature && hasFooter) {
      syncStaffFooterButtonsInPlace();
      return;
    }
    const prevSignature = lastFooterSignature;
    lastFooterSignature = signature;
    if (
      hasFooter
      && prevSignature
      && wifiFooterStructureSignature(prevSignature) === wifiFooterStructureSignature(signature)
    ) {
      syncStaffFooterButtonsInPlace();
      return;
    }

    clearElement(footerLeft);
    clearElement(footerRight);

    const state = screenState();
    const readiness = mutationReadiness();

    const restartBtn = createButton({
      label: 'Перезапустить сеть',
      variant: 'secondary',
      iconName: 'refresh',
      busy: controlsLocked(),
      disabled: !state.canTeardown || offline || preparingMutation,
      onActivate: () => {
        void restartFlow();
      },
    });
    restartBtn.id = 'hub-staff-wifi-restart-btn';
    updateButtonBusyState(restartBtn, controlsLocked(), !state.canTeardown || offline || preparingMutation);
    footerLeft.appendChild(restartBtn);

    const applyDefaults = canApplyStaffStandingDefaults({
      selectedApId,
      standing,
      mutationReadiness: readiness,
    });
    const applyDefaultsBtn = createButton({
      label: STAFF_WIFI_APPLY_DEFAULTS_LABEL,
      variant: 'secondary',
      disabled: !applyDefaults || offline || preparingMutation || mutating,
      busy: controlsLocked(),
      onActivate: () => {
        void applyStandingDefaultsFlow();
      },
    });
    applyDefaultsBtn.id = 'hub-staff-wifi-apply-defaults-btn';
    updateButtonBusyState(
      applyDefaultsBtn,
      controlsLocked(),
      !applyDefaults || offline || preparingMutation || mutating,
    );
    footerLeft.appendChild(applyDefaultsBtn);

    const saveReasonId = 'hub-staff-wifi-save-reason';
    /** @type {string|null} */
    let saveReason = null;
    if (offline) {
      saveReason = 'Нет связи с сервером управления';
    } else if (!selectedApId) {
      saveReason = 'Сначала выберите номер рабочей сети';
    } else if (!readiness.allowed) {
      saveReason = readiness.reasonText;
    } else if (!state.canSave) {
      saveReason = 'Проверьте название сети и другие поля';
    }

    if (saveReason) {
      const reasonEl = document.createElement('p');
      reasonEl.id = saveReasonId;
      reasonEl.className = 'hub-wifi__save-reason';
      reasonEl.textContent = saveReason;
      footerRight.appendChild(reasonEl);
    }

    const saveBtn = createButton({
      label: 'Сохранить изменения',
      size: 'lg',
      busy: controlsLocked(),
      disabled: !state.canSave || offline || preparingMutation,
      onActivate: () => {
        void saveFlow();
      },
    });
    saveBtn.id = 'hub-staff-wifi-save-btn';
    if (saveReason) {
      saveBtn.setAttribute('aria-describedby', saveReasonId);
    }
    updateButtonBusyState(saveBtn, controlsLocked(), !state.canSave || offline || preparingMutation);
    footerRight.appendChild(saveBtn);
  }

  function renderAll() {
    if (disposed) {
      return;
    }
    renderMutationVerdict();
    renderContent();
    renderInfoNote();
    renderFooter();
    restorePendingFocus();
  }

  async function loadStandingFlow() {
    if (disposed || offline) {
      return;
    }
    loadingStanding = true;
    renderAll();
    try {
      standing = await fetchStaffStandingNetworkPreferences();
      standingError = null;
      if (!formDirty) {
        draft = createStaffWifiFormDraft(observed, standing);
      }
    } catch (error) {
      if (!isAborted(error)) {
        standingError = error;
      }
    } finally {
      loadingStanding = false;
      if (!disposed) {
        renderAll();
      }
    }
  }

  async function loadObservedFlow() {
    if (disposed || !selectedApId || offline || isConnectionRestorePending(getSession())) {
      return;
    }
    recovering = false;
    const gen = ++observedGeneration;
    abortObserved();
    observedAbort = new AbortController();
    const myController = observedAbort;
    loadingObserved = true;
    loadObservedGeneration = gen;
    renderAll();

    try {
      const session = getSession();
      const result = await fetchStaffWifiObservedState({
        apId: selectedApId,
        session,
        adapterMode,
        signal: observedAbort.signal,
      });
      if (disposed || !shouldAcceptStaffWifiObservedResult(gen, observedGeneration)) {
        return;
      }
      observed = result;
      observedError = null;
      if (!formDirty) {
        draft = createStaffWifiFormDraft(observed, standing);
      }
    } catch (error) {
      if (disposed || !shouldAcceptStaffWifiObservedResult(gen, observedGeneration) || isAborted(error)) {
        return;
      }
      observedError = error;
    } finally {
      if (loadObservedGeneration === gen) {
        loadingObserved = false;
        loadObservedGeneration = null;
      }
      if (observedAbort === myController) {
        observedAbort = null;
      }
      if (!disposed && gen === observedGeneration) {
        renderAll();
      }
    }
  }

  /**
   * @param {StaffWifiRiskAction} action
   * @returns {boolean}
   */
  function validateMutationForm(action) {
    const trimmedPassword = draft.password.trim();
    const validation = validateStaffWifiForm({
      ssid: draft.ssid,
      password: trimmedPassword,
      requirePassword: action === 'enable' && observed?.keyConfigured === false,
      wpaMode: draft.wpaMode,
    });
    if (!validation.valid) {
      formErrors = validation.errors;
      pendingFocus = { kind: 'first-field-error' };
      renderAll();
      return false;
    }
    if (action !== 'teardown') {
      const credIntent = resolveStaffWifiCredentialIntent({
        password: trimmedPassword,
        standing,
        draftCredentialRef,
        selectedApId,
        draftSsid: draft.ssid,
      });
      if (credIntent.kind === 'missing') {
        formErrors = [STAFF_WIFI_STANDING_PASSWORD_ASK_ONCE_MESSAGE];
        pendingFocus = { kind: 'first-field-error' };
        renderAll();
        return false;
      }
    }
    formErrors = [];
    return true;
  }

  /**
   * @param {string|null|undefined} credentialRefId
   * @param {StaffWifiRiskAction} action
   * @param {{ signal?: AbortSignal }} [options]
   */
  async function persistStandingPreferencesAfterSuccess(credentialRefId, action, { signal } = {}) {
    if (!standing || action === 'teardown') {
      return;
    }
    if (!lastVerdict?.success) {
      return;
    }
    if (signal?.aborted || disposed || offline) {
      return;
    }
    const resolvedCredentialRefId =
      credentialRefId ?? standing.staff_password_credential_ref_id;
    try {
      const body = buildStaffStandingPreferencesUpdate({
        ssid: draft.ssid,
        credentialRefId: resolvedCredentialRefId,
      });
      standing = await updateStaffStandingNetworkPreferences(body, { signal });
    } catch (error) {
      if (disposed || signal?.aborted || isAborted(error)) {
        return;
      }
      operationError = error;
      operationRetry = async () => {
        if (disposed || mutating || offline) {
          return;
        }
        try {
          const body = buildStaffStandingPreferencesUpdate({
            ssid: draft.ssid,
            credentialRefId: resolvedCredentialRefId,
          });
          standing = await updateStaffStandingNetworkPreferences(body, { signal });
          operationError = null;
          operationRetry = null;
          renderAll();
          if (!(disposed || offline || signal?.aborted)) {
            ctx.showToast({
              tone: 'success',
              title: 'Обычные настройки сохранены',
              message: 'Имя и пароль по умолчанию обновлены на хосте.',
            });
          }
        } catch (retryError) {
          if (disposed || isAborted(retryError)) {
            return;
          }
          operationError = retryError;
          renderAll();
        }
      };
      ctx.showToast({
        tone: 'warning',
        title: 'Не удалось сохранить обычные настройки',
        message:
          'Настройки применены на роутере, но имя и пароль по умолчанию на хосте не обновлены — «Применить обычные» может подставить старые значения. Нажмите «Повторить».',
      });
      renderAll();
    }
  }

  /**
   * @param {StaffWifiRiskAction} action
   * @param {{ signal?: AbortSignal }} [options]
   * @returns {Promise<{ previewBody: Record<string, unknown>, hasNewPassword: boolean, trimmedPassword: string, credentialRefId: string|null }>}
   */
  async function buildMutationIntent(action, { signal = undefined } = {}) {
    const session = getSession();
    const readiness = evaluateStaffWifiMutationReadiness(session, adapterMode);
    if (!readiness.allowed || !selectedApId) {
      throw new HubApiError({
        code: 'client.unknown',
        httpStatus: null,
        userMessage: readiness.reasonText ?? 'Изменения сети сейчас недоступны',
        userAction: 'Проверьте подключение и повторите.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.UNKNOWN,
      });
    }

    const trimmedPassword = draft.password.trim();
    const hasNewPassword = trimmedPassword.length > 0;
    /** @type {string|null} */
    let credentialRefId = null;

    const credIntent = resolveStaffWifiCredentialIntent({
      password: trimmedPassword,
      standing,
      draftCredentialRef,
      selectedApId,
      draftSsid: draft.ssid,
    });

    if (credIntent.kind === 'register') {
      if (!session.routerId) {
        throw new HubApiError({
          code: 'client.unknown',
          httpStatus: null,
          userMessage: 'Не указан роутер для регистрации пароля.',
          userAction: 'Завершите подключение на соответствующем экране.',
          serverMessage: null,
          details: [],
          requestId: null,
          correlationId: null,
          kind: ERROR_KIND.UNKNOWN,
        });
      }
      const ensured = await ensureWifiCredentialRef({
        routerId: session.routerId,
        apId: selectedApId,
        ssid: draft.ssid,
        secret: credIntent.secret,
        cached: draftCredentialRef,
        signal,
      });
      credentialRefGeneration += 1;
      draftCredentialRef = ensured.cache;
      credentialRefId = ensured.credentialRefId;
    } else if (credIntent.kind === 'ref') {
      credentialRefId = credIntent.credentialRefId;
    }

    const previewBody = buildWifiPreviewBody({
      apId: selectedApId,
      ssid: draft.ssid,
      wpaMode: draft.wpaMode,
      enabled: deriveWifiPreviewEnabled({
        action,
        observed,
        networkTogglePending,
      }),
      credentialRefId,
    });

    return { previewBody, hasNewPassword, trimmedPassword, credentialRefId };
  }

  /**
   * @param {{ previewBody: Record<string, unknown>, hasNewPassword: boolean, trimmedPassword: string }} intent
   * @returns {Record<string, unknown>}
   */
  function finalizePreviewBodyForApply(intent) {
    return intent.previewBody;
  }

  /**
   * @param {ReturnType<typeof buildWifiMutationIntentSnapshot>} confirmedSnapshot
   * @param {{ hasNewPassword: boolean }} intent
   * @returns {boolean}
   */
  function assertConfirmedIntentStillValid(confirmedSnapshot, intent) {
    const current = currentWifiMutationIntentFromDraft({
      apId: selectedApId,
      draft,
      hasNewPassword: intent.hasNewPassword,
    });
    if (!wifiMutationIntentMatchesCurrent(confirmedSnapshot, current)) {
      ctx.showToast({
        tone: 'warning',
        title: 'Подтверждение устарело',
        message: WIFI_MUTATION_INTENT_STALE_MESSAGE,
      });
      resetToggleAfterCancel();
      return false;
    }
    return true;
  }

  async function executeApplyOnly(previewBody) {
    const session = getSession();
    const response = await applyStaffWifiChanges({
      previewBody,
      session,
      signal: mutateAbort?.signal,
    });
    return parseWifiApplyVerdict(response);
  }

  /**
   * @param {StaffWifiRiskAction} action
   * @returns {Promise<{ previewBody: Record<string, unknown>, hasNewPassword: boolean, trimmedPassword: string }|null>}
   */
  async function preparePreviewBeforeModal(action) {
    if (disposed || preparingMutation || mutating || offline) {
      return null;
    }
    if (!validateMutationForm(action)) {
      return null;
    }
    const gen = ++generation;
    abortPrepare();
    prepareAbort = new AbortController();
    const myController = prepareAbort;
    preparingMutation = true;
    prepareGeneration = gen;
    operationError = null;
    operationRetry = null;
    lastVerdict = null;
    persistedMutationVerdict = null;
    renderAll();

    try {
      const intent = await buildMutationIntent(action, {
        signal: prepareAbort.signal,
      });
      const session = getSession();
      await previewStaffWifiChanges({
        previewBody: intent.previewBody,
        session,
        signal: prepareAbort.signal,
      });
      if (disposed || gen !== generation) {
        return null;
      }
      pendingMutationCredentialRefId = intent.credentialRefId;
      return intent;
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return null;
      }
      operationError = error;
      operationRetry = () => {
        if (action === 'save') {
          void saveFlow();
        } else if (action === 'enable') {
          void enableNetworkFlow();
        } else if (action === 'restart') {
          void restartFlow();
        }
      };
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
      resetToggleAfterCancel();
      renderAll();
      return null;
    } finally {
      if (prepareGeneration === gen) {
        preparingMutation = false;
        prepareGeneration = null;
      }
      if (prepareAbort === myController) {
        prepareAbort = null;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
  }

  function warnRestartInterrupted() {
    ctx.showToast({
      tone: 'warning',
      title: 'Перезапуск прерван',
      message:
        'Сеть была выключена, но повторное включение не завершено. Откройте раздел снова и проверьте состояние сети.',
    });
  }

  /**
   * @param {StaffWifiRiskAction} action
   * @param {(signal: AbortSignal|undefined, applyMeta: { passwordRegistered: boolean }) => Promise<boolean>} executor
   * @param {{ ssid?: string, wpaMode?: import('../features/staff-wifi-model.js').StaffWifiWpaMode, enabled?: boolean }|null} [readbackExpectation]
   * @param {'apply'|'teardown'} [readbackIntent]
   */
  async function runMutation(action, executor, readbackExpectation = null, readbackIntent = 'apply') {
    if (disposed || mutating) {
      return;
    }
    if (offline) {
      ctx.showToast({
        tone: 'warning',
        title: 'Нет связи',
        message:
          'Связь с сервером управления пропала — операция не начата. Проверьте сеть и повторите.',
      });
      return;
    }
    recovering = false;
    const gen = ++generation;
    abortMutate();
    mutateAbort = new AbortController();
    const myController = mutateAbort;
    mutating = true;
    mutateGeneration = gen;
    operationError = null;
    operationRetry = null;
    lastVerdict = null;
    persistedMutationVerdict = null;
    renderAll();

    /** @type {{ passwordRegistered: boolean }} */
    const applyMeta = { passwordRegistered: false };

    let succeeded = false;
    try {
      succeeded = await executor(mutateAbort.signal, applyMeta);
      if (disposed || mutateGeneration !== gen) {
        if (restartAwaitingApply) {
          warnRestartInterrupted();
        }
        return;
      }
      if (shouldPollWifiApplyReadback(lastVerdict)) {
        networkTogglePending = null;
        const applyVerdict = lastVerdict;
        lastVerdict = await performWifiApplyReadbackPoll({
          verdict: applyVerdict,
          fetchObserved: async () => {
            await loadObservedFlow();
            if (!disposed && mutateGeneration === gen) {
              renderAll();
            }
            return { observed, observedError: Boolean(observedError) };
          },
          expected: readbackExpectation,
          intent: readbackIntent,
          signal: mutateAbort.signal,
          onVerifying: () => {
            lastVerdict = buildWifiApplyReadbackVerifyingVerdict();
            persistedMutationVerdict = lastVerdict;
            renderAll();
          },
        });
        if (disposed || mutateGeneration !== gen) {
          if (restartAwaitingApply) {
            warnRestartInterrupted();
          }
          return;
        }
      }
      if (
        applyMeta.passwordRegistered
        && lastVerdict
        && !lastVerdict.success
        && !isWifiConfigurationApplied(lastVerdict)
      ) {
        lastVerdict = {
          ...lastVerdict,
          message: WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
        };
      }
      persistedMutationVerdict = lastVerdict;
      if (
        lastVerdict
        && !(
          lastVerdict.success
          && (disposed || offline || myController.signal.aborted)
        )
      ) {
        ctx.showToast({
          tone: lastVerdict.success
            ? 'success'
            : (lastVerdict.hubState && Object.values(HubState).includes(lastVerdict.hubState)
              ? getStateDescriptor(lastVerdict.hubState).tone
              : 'warning'),
          title: lastVerdict.title,
          message: lastVerdict.message,
        });
        renderAll();
      }
      if (shouldClearStaffWifiFormPasswordAfterMutation({ lastVerdict })) {
        formDirty = false;
        draft = { ...draft, password: '' };
        sessionPskMemory = '';
        draftCredentialRef = null;
        const pwdEl = document.getElementById('hub-staff-wifi-password');
        if (pwdEl instanceof HTMLInputElement) {
          pwdEl.value = '';
        }
      }
      if (shouldPersistStandingPreferencesAfterMutation({ lastVerdict, action })) {
        await persistStandingPreferencesAfterSuccess(
          pendingMutationCredentialRefId,
          action,
          { signal: mutateAbort.signal },
        );
      }
    } catch (error) {
      if (disposed || mutateGeneration !== gen || isAborted(error)) {
        if (restartAwaitingApply && (disposed || mutateGeneration !== gen)) {
          warnRestartInterrupted();
        }
        return;
      }
      operationError = error;
      operationRetry = () => {
        if (action === 'save') {
          void saveFlow();
        } else if (action === 'enable') {
          void enableNetworkFlow();
        } else if (action === 'teardown') {
          void teardownFlow();
        } else if (action === 'restart') {
          void restartFlow();
        }
      };
      const described = describePanelError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
      resetToggleAfterCancel();
    } finally {
      const ownsMutation = mutateGeneration === gen;
      if (ownsMutation) {
        mutating = false;
        mutateGeneration = null;
      }
      if (mutateAbort === myController) {
        mutateAbort = null;
      }
      if (!succeeded && networkTogglePending !== null) {
        resetToggleAfterCancel();
      }
      if (!disposed && ownsMutation) {
        renderAll();
      }
    }
  }

  function resetToggleAfterCancel() {
    networkTogglePending = null;
    renderAll();
  }

  async function applyStandingDefaultsFlow() {
    if (preparingMutation || mutating) {
      return;
    }
    const readiness = mutationReadiness();
    if (
      !canApplyStaffStandingDefaults({
        selectedApId,
        standing,
        mutationReadiness: readiness,
      })
    ) {
      return;
    }
    draft = buildStaffStandingDefaultsDraft(standing);
    formDirty = true;
    renderAll();
    const action =
      observed?.readable && observed.activeLabel === 'Выключена' ? 'enable' : 'save';
    if (action === 'enable') {
      networkTogglePending = true;
      renderAll();
      await enableNetworkFlow();
      return;
    }
    await saveFlow();
  }

  async function saveFlow() {
    if (preparingMutation || mutating) {
      return;
    }
    const returnFocusTo =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const intent = await preparePreviewBeforeModal('save');
    if (!intent) {
      return;
    }
    const changeLines = buildPlannedChangeLines({
      draft,
      observed,
      action: 'save',
      hasNewPassword: intent.hasNewPassword,
    });
    const intentSnapshot = buildWifiMutationIntentSnapshot({
      apId: selectedApId,
      ssid: draft.ssid,
      wpaMode: draft.wpaMode,
      hasNewPassword: intent.hasNewPassword,
    });
    openRiskModal(
      'save',
      changeLines,
      async (confirmedSnapshot) => {
        if (!assertConfirmedIntentStillValid(confirmedSnapshot, intent)) {
          return;
        }
        await runMutation(
          'save',
          async (signal, applyMeta) => {
            const previewBody = finalizePreviewBodyForApply(intent);
            if (intent.hasNewPassword) {
              applyMeta.passwordRegistered = true;
            }
            const verdict = await executeApplyOnly(previewBody);
            lastVerdict = verdict;
            return verdict.success;
          },
          {
            ssid: intent.previewBody.ssid,
            wpaMode: draft.wpaMode,
            enabled: intent.previewBody.enabled === true,
          },
        );
      },
      cancelPreparedMutation,
      returnFocusTo,
      intentSnapshot,
    );
  }

  async function enableNetworkFlow() {
    if (preparingMutation || mutating) {
      return;
    }
    const returnFocusTo =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const intent = await preparePreviewBeforeModal('enable');
    if (!intent) {
      resetToggleAfterCancel();
      return;
    }
    const changeLines = buildPlannedChangeLines({
      draft,
      observed,
      action: 'enable',
      hasNewPassword: intent.hasNewPassword,
    });
    const intentSnapshot = buildWifiMutationIntentSnapshot({
      apId: selectedApId,
      ssid: draft.ssid,
      wpaMode: draft.wpaMode,
      hasNewPassword: intent.hasNewPassword,
    });
    openRiskModal(
      'enable',
      changeLines,
      async (confirmedSnapshot) => {
        if (!assertConfirmedIntentStillValid(confirmedSnapshot, intent)) {
          return;
        }
        await runMutation(
          'enable',
          async (signal, applyMeta) => {
            const previewBody = finalizePreviewBodyForApply(intent);
            if (intent.hasNewPassword) {
              applyMeta.passwordRegistered = true;
            }
            const verdict = await executeApplyOnly(previewBody);
            lastVerdict = verdict;
            return verdict.success;
          },
          {
            ssid: intent.previewBody.ssid,
            wpaMode: draft.wpaMode,
            enabled: intent.previewBody.enabled === true,
          },
        );
      },
      cancelPreparedMutation,
      returnFocusTo,
      intentSnapshot,
    );
  }

  async function teardownFlow() {
    if (preparingMutation || mutating) {
      return;
    }
    const returnFocusTo =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const readiness = mutationReadiness();
    if (!readiness.allowed || !selectedApId) {
      renderAll();
      return;
    }
    const changeLines = buildPlannedChangeLines({
      draft,
      observed,
      action: 'teardown',
      hasNewPassword: false,
    });
    const intentSnapshot = buildWifiMutationIntentSnapshot({
      apId: selectedApId,
      ssid: draft.ssid,
      wpaMode: draft.wpaMode,
      hasNewPassword: false,
    });
    openRiskModal(
      'teardown',
      changeLines,
      async (confirmedSnapshot) => {
        if (!assertConfirmedIntentStillValid(confirmedSnapshot, { hasNewPassword: false })) {
          return;
        }
        await runMutation(
          'teardown',
          async (signal) => {
          const session = getSession();
          const response = await teardownStaffWifiNetwork({
            apId: selectedApId,
            wpaMode: draft.wpaMode,
            session,
            signal,
          });
          lastVerdict = parseWifiApplyVerdict(response, { intent: 'teardown' });
          return lastVerdict.success;
        },
          {
            ssid:
              draft.ssid.trim()
              || (typeof observed?.ssid === 'string' ? observed.ssid.trim() : ''),
            wpaMode: draft.wpaMode,
            enabled: false,
          },
          'teardown',
        );
      },
      cancelPreparedMutation,
      returnFocusTo,
      intentSnapshot,
    );
  }

  async function restartFlow() {
    const returnFocusTo =
      document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const intent = await preparePreviewBeforeModal('restart');
    if (!intent) {
      return;
    }
    const changeLines = buildPlannedChangeLines({
      draft,
      observed,
      action: 'restart',
      hasNewPassword: intent.hasNewPassword,
    });
    const intentSnapshot = buildWifiMutationIntentSnapshot({
      apId: selectedApId,
      ssid: draft.ssid,
      wpaMode: draft.wpaMode,
      hasNewPassword: intent.hasNewPassword,
    });
    openRiskModal(
      'restart',
      changeLines,
      async (confirmedSnapshot) => {
        if (!assertConfirmedIntentStillValid(confirmedSnapshot, intent)) {
          return;
        }
        await runMutation(
          'restart',
          async (signal, applyMeta) => {
            const session = getSession();
            const teardownResponse = await teardownStaffWifiNetwork({
              apId: selectedApId,
              wpaMode: draft.wpaMode,
              session,
              signal,
            });
            const teardownVerdict = parseWifiApplyVerdict(teardownResponse, { intent: 'teardown' });
            if (!teardownVerdict.success) {
              lastVerdict = teardownVerdict;
              ctx.showToast({
                tone: 'warning',
                title: teardownVerdict.title,
                message: formatStaffWifiRestartTeardownFailureMessage({
                  teardownVerdict,
                  observed,
                }),
              });
              return false;
            }
            restartAwaitingApply = true;
            try {
              const previewBody = finalizePreviewBodyForApply(intent);
              if (intent.hasNewPassword) {
                applyMeta.passwordRegistered = true;
              }
              const verdict = await executeApplyOnly(previewBody);
              lastVerdict = verdict;
              return verdict.success;
            } finally {
              restartAwaitingApply = false;
            }
          },
          {
            ssid: intent.previewBody.ssid,
            wpaMode: draft.wpaMode,
            enabled: intent.previewBody.enabled === true,
          },
        );
      },
      cancelPreparedMutation,
      returnFocusTo,
      intentSnapshot,
    );
  }

  const unsubConnectivity = subscribeConnectivity((online) => {
    if (disposed) {
      return;
    }
    if (!online) {
      offline = true;
      recovering = false;
      invalidateAllOperations();
      captureFocusBeforeRender();
      renderAll();
      return;
    }
    offline = false;
    recovering = true;
    captureFocusBeforeRender();
    renderAll();
    if (selectedApId && !mutating && !preparingMutation) {
      void loadObservedFlow().finally(() => {
        recovering = false;
        if (!disposed) {
          renderAll();
        }
      });
    } else {
      recovering = false;
      renderAll();
    }
  });

  let trackedLiveCapabilityKey = liveCapabilitySubscriptionKey(getSession());

  const unsubSession = subscribeSession((snapshot) => {
    if (disposed) {
      return;
    }
    const nextKey = liveCapabilitySubscriptionKey(snapshot);
    if (nextKey === trackedLiveCapabilityKey) {
      return;
    }
    trackedLiveCapabilityKey = nextKey;
    if (isConnectionRestorePending(snapshot)) {
      captureFocusBeforeRender();
      renderAll();
      return;
    }
    if (selectedApId && !mutating && !preparingMutation) {
      observedError = null;
      void loadObservedFlow();
    } else {
      captureFocusBeforeRender();
      renderAll();
    }
  });

  renderAll();
  void loadStandingFlow();
  if (selectedApId && !isConnectionRestorePending(getSession())) {
    void loadObservedFlow();
  }

  return () => {
    if (restartAwaitingApply) {
      warnRestartInterrupted();
    }
    disposed = true;
    invalidateAllOperations();
    closeAllModals();
    clearSessionSecrets();
    unsubConnectivity();
    unsubSession();
  };
}
