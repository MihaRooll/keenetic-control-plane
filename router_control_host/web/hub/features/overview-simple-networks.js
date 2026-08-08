/**
 * Рабочая и гостевая сети на главном экране — без auto-apply на mount (R-3…R-6).
 */

import {
  createBadge,
  createButton,
  createIcon,
  createSelectField,
  createTextField,
  createToggle,
} from '../components/index.js';
import { readInputEventValue } from '../core/form-submit-sync.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import {
  HubState,
  createInlineState,
  createProgressPanel,
  createStatePanel,
  getStateDescriptor,
} from '../core/states.js';
import {
  GUEST_WIFI_REMEMBER_DEFAULT_HINT,
  GUEST_WIFI_REMEMBER_DEFAULT_LABEL,
  GUEST_WIFI_STANDING_SSID_SEED,
  GUEST_WIFI_WPA_MODE_OPTIONS,
  WPA_MODE_DRAFT_PLACEHOLDER_OPTION,
  applyGuestWifiChanges,
  buildGuestApRoleUpdate,
  buildGuestStandingPreferencesUpdate,
  buildGuestWifiPreviewBody,
  createGuestWifiFormDraft,
  evaluateGuestWifiMutationReadiness,
  fetchGuestWifiObservedState,
  getGuestStaffApOverlapWarning,
  guestWifiWpaFieldHint,
  isObservedWpaModeKnown,
  isWifiWpaModeDraftSelected,
  shouldOfferGuestRememberDefault,
  teardownGuestWifiNetwork,
  updateGuestStandingNetworkPreferences,
  validateGuestWifiForm,
} from './guest-wifi-model.js';
import {
  STAFF_WIFI_APPLY_DEFAULTS_LABEL,
  STAFF_WIFI_DISABLED_REMEDIATION_MESSAGE,
  STAFF_WIFI_DISABLED_REMEDIATION_TITLE,
  STAFF_WIFI_STANDING_SSID_SEED,
  applyStaffWifiChanges,
  buildStaffApRoleUpdate,
  buildStaffStandingDefaultsDraft,
  buildStaffStandingPreferencesUpdate,
  canApplyStaffStandingDefaults,
  createStaffWifiFormDraft,
  evaluateStaffWifiMutationReadiness,
  fetchStaffStandingNetworkPreferences,
  fetchStaffWifiObservedState,
  resolveStaffWifiCredentialIntent,
  shouldShowStaffDisabledRemediation,
  updateStaffStandingNetworkPreferences,
} from './staff-wifi-model.js';
import {
  buildWifiPreviewBody,
  deriveWifiPreviewEnabled,
  ensureWifiCredentialRef,
  isWifiConfigurationApplied,
  listWifiApOptions,
  parseWifiApplyVerdict,
  shouldRefreshWifiObservedAfterMutation,
  WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
} from './wifi-ap-model.js';
import {
  createOverviewStepCardActions,
  createOverviewStepCardMain,
  createOverviewStepCardMeta,
  createStepNumberBadge,
  wireOverviewCardNavigate,
} from './overview-card-grid.js';

export const OVERVIEW_NETWORKS_STAFF_TITLE = 'Рабочая сеть';
export const OVERVIEW_NETWORKS_GUEST_TITLE = 'Гостевая сеть';
export const OVERVIEW_NETWORKS_STAFF_LINK_LABEL = 'Все настройки рабочей сети';
export const OVERVIEW_NETWORKS_GUEST_LINK_LABEL = 'Все настройки гостевой сети';
export const OVERVIEW_NETWORKS_STAFF_UNASSIGNED_TITLE = 'Роутер не сообщает, какая сеть рабочая';
export const OVERVIEW_NETWORKS_GUEST_UNASSIGNED_TITLE = 'Роутер не сообщает, какая сеть гостевая';
export const OVERVIEW_NETWORKS_UNASSIGNED_NOTE = 'Настройка и состояние — в самом разделе.';

/**
 * @typedef {import('./staff-wifi-model.js').ParsedObservedAccessPoint} ParsedObservedAccessPoint
 * @typedef {import('./wifi-ap-model.js').StandingNetworkPreferences} StandingNetworkPreferences
 * @typedef {import('./wifi-ap-model.js').WifiApplyVerdict} WifiApplyVerdict
 * @typedef {import('./wifi-ap-model.js').WifiCredentialRefCache} WifiCredentialRefCache
 */

/**
 * @typedef {object} OverviewSimpleNetworksMountOptions
 * @property {HTMLElement} staffSlot
 * @property {HTMLElement} guestSlot
 * @property {() => import('../core/session.js').SessionSnapshot} getSession
 * @property {string|null|undefined} [adapterMode]
 * @property {(routeId: string) => void} navigate
 * @property {(opts: object) => void} [showToast]
 * @property {() => boolean} isRestorePending
 * @property {() => boolean} [getDisabled]
 * @property {() => AbortSignal|undefined} [getSignal]
 * @property {string} [idPrefix]
 */

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
 * @param {OverviewSimpleNetworksMountOptions} options
 * @returns {{
 *   update: () => void,
 *   destroy: () => void,
 *   loadAndUpdate: (params?: { signal?: AbortSignal }) => Promise<void>,
 * }}
 */
export function mountOverviewSimpleNetworks(options) {
  const {
    staffSlot,
    guestSlot,
    adapterMode = null,
    navigate,
    isRestorePending,
    getDisabled,
    getSignal,
    idPrefix = 'hub-overview-networks',
  } = options;

  function resolveDisabled() {
    return typeof getDisabled === 'function' && getDisabled();
  }

  /**
   * @param {{
   *   role: 'staff'|'guest',
   *   stepNumber: number,
   *   title: string,
   *   linkLabel: string,
   *   routeId: 'staff-wifi'|'guest-wifi',
   *   iconName: string,
   * }} config
   * @returns {{ card: HTMLElement, body: HTMLElement }}
   */
  function buildNetworkStepCard(config) {
    const { role, stepNumber, title, linkLabel, routeId, iconName } = config;

    const card = document.createElement('article');
    card.className = `hub-overview-step-card hub-overview-networks__${role}`;

    const header = document.createElement('div');
    header.className = 'hub-overview-step-card__header hub-overview-networks__header';
    header.appendChild(createStepNumberBadge(stepNumber));

    const heading = document.createElement('h2');
    heading.className = 'hub-overview-step-card__title';
    heading.textContent = title;
    header.appendChild(heading);

    const infoWrap = document.createElement('span');
    infoWrap.className = 'hub-overview-networks__info';
    infoWrap.appendChild(createIcon('info', { size: 16 }));
    header.appendChild(infoWrap);
    card.appendChild(header);

    const main = createOverviewStepCardMain();

    const iconFrame = document.createElement('div');
    iconFrame.className = 'hub-overview-networks__icon-frame';
    iconFrame.appendChild(createIcon(iconName, { size: 32 }));
    main.appendChild(iconFrame);

    const body = document.createElement('div');
    body.className = 'hub-overview-networks__body';
    main.appendChild(body);
    card.appendChild(main);

    const actions = createOverviewStepCardActions();
    const openBtn = createButton({
      label: 'Открыть',
      variant: 'secondary',
      onActivate: () => {
        navigate(routeId);
      },
    });
    actions.appendChild(openBtn);

    const meta = createOverviewStepCardMeta();
    const quietLink = document.createElement('a');
    quietLink.className = 'hub-overview__quiet-link';
    quietLink.href = `#/${routeId}`;
    quietLink.textContent = linkLabel;
    quietLink.addEventListener('click', (event) => {
      event.preventDefault();
      navigate(routeId);
    });
    meta.appendChild(quietLink);
    actions.appendChild(meta);
    card.appendChild(actions);

    wireOverviewCardNavigate(card, routeId, navigate);

    return { card, body };
  }

  const { card: staffCard, body: staffBody } = buildNetworkStepCard({
    role: 'staff',
    stepNumber: 5,
    title: OVERVIEW_NETWORKS_STAFF_TITLE,
    linkLabel: OVERVIEW_NETWORKS_STAFF_LINK_LABEL,
    routeId: 'staff-wifi',
    iconName: 'staff-wifi',
  });

  const { card: guestCard, body: guestBody } = buildNetworkStepCard({
    role: 'guest',
    stepNumber: 6,
    title: OVERVIEW_NETWORKS_GUEST_TITLE,
    linkLabel: OVERVIEW_NETWORKS_GUEST_LINK_LABEL,
    routeId: 'guest-wifi',
    iconName: 'guest-wifi',
  });

  staffSlot.appendChild(staffCard);
  guestSlot.appendChild(guestCard);

  /** @type {StandingNetworkPreferences|null} */
  let standing = null;
  /** @type {ParsedObservedAccessPoint|null} */
  let staffObserved = null;
  /** @type {ParsedObservedAccessPoint|null} */
  let guestObserved = null;
  /** @type {string|null} */
  let selectedStaffApId = null;
  /** @type {string|null} */
  let selectedGuestApId = null;
  /** @type {ReturnType<typeof createStaffWifiFormDraft>} */
  let staffDraft = { ssid: '', wpaMode: 'WPA2', password: '' };
  /** @type {ReturnType<typeof createGuestWifiFormDraft>} */
  let guestDraft = { ssid: '', wpaMode: 'WPA2', password: '' };
  let guestRememberDefault = false;
  /** @type {'staff'|'guest'|null} */
  let standingPersistWarningKind = null;
  let staffFormDirty = false;
  let guestFormDirty = false;
  let staffBusy = false;
  let guestBusy = false;
  let loading = false;
  let loadCompleted = false;
  /** @type {string|null} */
  let lastSignature = null;
  /** @type {{ kind: string, id?: string, selectionStart?: number, selectionEnd?: number }|null} */
  let pendingFocus = null;
  /** @type {WifiCredentialRefCache|null} */
  let staffCredentialRef = null;
  /** @type {WifiCredentialRefCache|null} */
  let guestCredentialRef = null;
  /** @type {HTMLElement & { update: (opts: object) => void }|null} */
  let activeProgressPanel = null;
  let mutationPasswordRegistered = false;

  /**
   * @param {HTMLElement} slot
   */
  function capturePendingFocus(slot) {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement) || !slot.contains(active)) {
      return;
    }
    if (active.id) {
      pendingFocus = {
        kind: 'element-id',
        id: active.id,
        selectionStart: active instanceof HTMLInputElement ? active.selectionStart : undefined,
        selectionEnd: active instanceof HTMLInputElement ? active.selectionEnd : undefined,
      };
    }
  }

  function restorePendingFocus() {
    if (!pendingFocus || pendingFocus.kind !== 'element-id' || !pendingFocus.id) {
      pendingFocus = null;
      return;
    }
    const target = pendingFocus;
    pendingFocus = null;
    const el = document.getElementById(target.id);
    if (el instanceof HTMLElement) {
      el.focus();
      if (
        el instanceof HTMLInputElement
        && typeof target.selectionStart === 'number'
        && typeof target.selectionEnd === 'number'
      ) {
        try {
          el.setSelectionRange(target.selectionStart, target.selectionEnd);
        } catch {
          // ignore
        }
      }
    }
  }

  /**
   * @returns {{ kind: 'hub-content'|'window', top: number }}
   */
  function captureScrollPosition() {
    const hubContent = document.getElementById('hub-content');
    if (hubContent instanceof HTMLElement) {
      return { kind: 'hub-content', top: hubContent.scrollTop };
    }
    return { kind: 'window', top: window.scrollY };
  }

  /**
   * @param {{ kind: 'hub-content'|'window', top: number }} saved
   */
  function restoreScrollPosition(saved) {
    if (saved.kind === 'hub-content') {
      const hubContent = document.getElementById('hub-content');
      if (hubContent instanceof HTMLElement) {
        hubContent.scrollTop = saved.top;
      }
      return;
    }
    if (typeof window.scrollTo === 'function') {
      window.scrollTo(0, saved.top);
    }
  }

  /**
   * @param {HTMLElement} slot
   * @param {string} label
   */
  function showSlotProgress(slot, label) {
    capturePendingFocus(slot);
    slot.textContent = '';
    activeProgressPanel = createProgressPanel({ mode: 'indeterminate', label });
    slot.appendChild(activeProgressPanel);
  }

  /**
   * @returns {string}
   */
  function buildContentSignature() {
    const staffStatus = staffObserved?.activeLabel ?? '';
    const guestStatus = guestObserved?.activeLabel ?? '';
    return [
      selectedStaffApId ?? '',
      selectedGuestApId ?? '',
      staffObserved?.ssid ?? '',
      guestObserved?.ssid ?? '',
      staffStatus,
      guestStatus,
      staffDraft.ssid,
      guestDraft.ssid,
      guestDraft.wpaMode,
      guestObserved?.wpaMode ?? '',
      staffDraft.password ? 'pwd' : '',
      guestDraft.password ? 'pwd' : '',
      guestRememberDefault ? '1' : '0',
      staffBusy ? '1' : '0',
      guestBusy ? '1' : '0',
      loading ? '1' : '0',
      standing?.staff_ssid ?? '',
      standing?.staff_password_configured ? '1' : '0',
      resolveDisabled() ? '1' : '0',
    ].join('|');
  }

  /**
   * @param {(options: object) => void} toast
   * @param {unknown} error
   */
  function showMutationError(toast, error) {
    if (isAborted(error)) {
      return;
    }
    const described = describeError(error);
    toast({
      tone: 'danger',
      title: described.title,
      message: described.message,
    });
  }

  /**
   * @param {'staff'|'guest'} kind
   * @param {(opts: object) => void} showToast
   */
  function showStandingPersistWarningToast(kind, showToast) {
    if (kind === 'staff') {
      showToast({
        tone: 'warning',
        title: 'Не удалось сохранить обычные настройки',
        message:
          'Настройки применены на роутере, но имя и пароль по умолчанию на хосте не обновлены — «Применить обычные» может подставить старые значения.',
      });
      return;
    }
    showToast({
      tone: 'warning',
      title: 'Не удалось запомнить обычное имя',
      message:
        'Гостевая сеть сохранена на роутере, но обычное имя не записано на хосте — в новых проектах подставится прежнее.',
    });
  }

  /**
   * @param {AbortSignal|undefined} signal
   * @returns {Promise<WifiApplyVerdict>}
   */
  async function runStaffEnable(signal) {
    const session = options.getSession();
    const readiness = evaluateStaffWifiMutationReadiness(session, adapterMode);
    if (!readiness.allowed || !selectedStaffApId) {
      throw new HubApiError({
        code: 'client.unknown',
        httpStatus: null,
        userMessage: readiness.reasonText ?? 'Включить сеть сейчас нельзя',
        userAction: 'Откройте раздел «Рабочая сеть».',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.UNKNOWN,
      });
    }

    const credIntent = resolveStaffWifiCredentialIntent({
      password: staffDraft.password,
      standing,
      draftCredentialRef: staffCredentialRef,
      selectedApId: selectedStaffApId,
      draftSsid: staffDraft.ssid,
    });

    /** @type {string|null} */
    let credentialRefId = null;
    if (credIntent.kind === 'register') {
      if (!session.routerId) {
        throw new Error('Не указан роутер');
      }
      const ensured = await ensureWifiCredentialRef({
        routerId: session.routerId,
        apId: selectedStaffApId,
        ssid: staffDraft.ssid,
        secret: credIntent.secret,
        cached: staffCredentialRef,
        signal,
      });
      staffCredentialRef = ensured.cache;
      credentialRefId = ensured.credentialRefId;
      staffDraft = { ...staffDraft, password: '' };
      mutationPasswordRegistered = true;
    } else if (credIntent.kind === 'ref') {
      credentialRefId = credIntent.credentialRefId;
    } else if (credIntent.kind === 'missing') {
      throw new HubApiError({
        code: 'client.validation',
        httpStatus: null,
        userMessage: 'Укажите пароль рабочей сети один раз',
        userAction: 'Введите пароль в поле ниже.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.VALIDATION,
      });
    }

    const previewBody = buildWifiPreviewBody({
      apId: selectedStaffApId,
      ssid: staffDraft.ssid,
      wpaMode: staffDraft.wpaMode,
      enabled: deriveWifiPreviewEnabled({
        action: 'enable',
        observed: staffObserved,
        networkTogglePending: true,
      }),
      credentialRefId,
    });

    const response = await applyStaffWifiChanges({ previewBody, session, signal });
    const verdict = parseWifiApplyVerdict(response);
    if (standing && session.routerId && verdict.success) {
      try {
        const body = buildStaffStandingPreferencesUpdate({
          ssid: staffDraft.ssid,
          credentialRefId,
        });
        standing = await updateStaffStandingNetworkPreferences(body);
      } catch {
        standingPersistWarningKind = 'staff';
      }
    }
    if (shouldRefreshWifiObservedAfterMutation(verdict)) {
      staffObserved = await fetchStaffWifiObservedState({
        apId: selectedStaffApId,
        session,
        adapterMode,
        signal,
      });
    }
    return verdict;
  }

  /**
   * @param {AbortSignal|undefined} signal
   * @returns {Promise<WifiApplyVerdict|null>}
   */
  async function runStaffApplyDefaults(signal) {
    const session = options.getSession();
    const readiness = evaluateStaffWifiMutationReadiness(session, adapterMode);
    if (!canApplyStaffStandingDefaults({
      selectedApId: selectedStaffApId,
      standing,
      mutationReadiness: readiness,
    }) || !standing) {
      return null;
    }
    staffDraft = buildStaffStandingDefaultsDraft(standing);
    const credIntent = resolveStaffWifiCredentialIntent({
      password: '',
      standing,
      draftCredentialRef: staffCredentialRef,
      selectedApId: selectedStaffApId,
      draftSsid: staffDraft.ssid,
    });
    if (credIntent.kind !== 'ref') {
      throw new HubApiError({
        code: 'client.validation',
        httpStatus: null,
        userMessage: 'Сначала задайте пароль рабочей сети',
        userAction: 'Откройте раздел «Рабочая сеть».',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.VALIDATION,
      });
    }
    const previewBody = buildWifiPreviewBody({
      apId: selectedStaffApId,
      ssid: staffDraft.ssid,
      wpaMode: staffDraft.wpaMode,
      enabled: true,
      credentialRefId: credIntent.credentialRefId,
    });
    const response = await applyStaffWifiChanges({ previewBody, session, signal });
    const verdict = parseWifiApplyVerdict(response);
    if (shouldRefreshWifiObservedAfterMutation(verdict)) {
      staffObserved = await fetchStaffWifiObservedState({
        apId: selectedStaffApId,
        session,
        adapterMode,
        signal,
      });
    }
    return verdict;
  }

  /**
   * @param {boolean} enabled
   * @param {AbortSignal|undefined} signal
   * @returns {Promise<WifiApplyVerdict>}
   */
  async function runGuestApply(enabled, signal) {
    const session = options.getSession();
    const readiness = evaluateGuestWifiMutationReadiness(session, adapterMode);
    if (!readiness.allowed || !selectedGuestApId) {
      throw new HubApiError({
        code: 'client.unknown',
        httpStatus: null,
        userMessage: readiness.reasonText ?? 'Изменения гостевой сети сейчас недоступны',
        userAction: 'Откройте раздел «Гостевая сеть».',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.UNKNOWN,
      });
    }

    if (!enabled) {
      const response = await teardownGuestWifiNetwork({
        apId: selectedGuestApId,
        wpaMode: guestDraft.wpaMode,
        session,
        signal,
      });
      const verdict = parseWifiApplyVerdict(response, { intent: 'teardown' });
      if (shouldRefreshWifiObservedAfterMutation(verdict)) {
        guestObserved = await fetchGuestWifiObservedState({
          apId: selectedGuestApId,
          session,
          adapterMode,
          signal,
        });
      }
      return verdict;
    }

    const trimmedPassword = guestDraft.password.trim();
    /** @type {string|null} */
    let credentialRefId = null;
    const requirePassword = enabled && guestObserved?.keyConfigured === false;
    const validation = validateGuestWifiForm({
      ssid: guestDraft.ssid,
      password: trimmedPassword,
      requirePassword,
      wpaMode: guestDraft.wpaMode,
    });
    if (!validation.valid) {
      throw new HubApiError({
        code: 'client.validation',
        httpStatus: null,
        userMessage: validation.errors[0] ?? 'Проверьте настройки гостевой сети',
        userAction: null,
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.VALIDATION,
      });
    }

    if (trimmedPassword) {
      if (!session.routerId) {
        throw new Error('Не указан роутер');
      }
      const ensured = await ensureWifiCredentialRef({
        routerId: session.routerId,
        apId: selectedGuestApId,
        ssid: guestDraft.ssid,
        secret: trimmedPassword,
        cached: guestCredentialRef,
        signal,
      });
      guestCredentialRef = ensured.cache;
      credentialRefId = ensured.credentialRefId;
      guestDraft = { ...guestDraft, password: '' };
      mutationPasswordRegistered = true;
    } else if (
      guestCredentialRef?.refId
      && guestCredentialRef.apId === selectedGuestApId
      && guestCredentialRef.ssid === guestDraft.ssid.trim()
    ) {
      credentialRefId = guestCredentialRef.refId;
    }

    const previewBody = buildGuestWifiPreviewBody({
      apId: selectedGuestApId,
      ssid: guestDraft.ssid,
      wpaMode: guestDraft.wpaMode,
      enabled: deriveWifiPreviewEnabled({
        action: 'enable',
        observed: guestObserved,
        networkTogglePending: true,
      }),
      credentialRefId,
    });

    const response = await applyGuestWifiChanges({ previewBody, session, signal });
    const verdict = parseWifiApplyVerdict(response);

    if (guestRememberDefault && enabled && verdict.success) {
      try {
        const body = buildGuestStandingPreferencesUpdate(guestDraft.ssid);
        standing = await updateGuestStandingNetworkPreferences(body);
      } catch {
        standingPersistWarningKind = 'guest';
      }
    }

    if (shouldRefreshWifiObservedAfterMutation(verdict)) {
      guestObserved = await fetchGuestWifiObservedState({
        apId: selectedGuestApId,
        session,
        adapterMode,
        signal,
      });
    }
    return verdict;
  }

  /**
   * @param {boolean} targetEnabled
   * @param {'staff-enable'|'staff-defaults'|'guest-toggle'} action
   */
  async function runMutation(action, targetEnabled = true) {
    if (isRestorePending()) {
      return;
    }
    if (resolveDisabled()) {
      return;
    }
    standingPersistWarningKind = null;
    mutationPasswordRegistered = false;
    const signal = typeof getSignal === 'function' ? getSignal() : undefined;
    const slot = action.startsWith('staff') ? staffBody : guestBody;
    if (action.startsWith('staff')) {
      staffBusy = true;
    } else {
      guestBusy = true;
    }
    update();
    showSlotProgress(
      slot,
      action === 'staff-enable'
        ? 'Включаем рабочую сеть…'
        : action === 'staff-defaults'
          ? 'Применяем обычные настройки…'
          : 'Сохраняем гостевую сеть…',
    );
    try {
      /** @type {WifiApplyVerdict|null} */
      let verdict = null;
      if (action === 'staff-enable') {
        verdict = await runStaffEnable(signal);
      } else if (action === 'staff-defaults') {
        verdict = await runStaffApplyDefaults(signal);
      } else {
        verdict = await runGuestApply(targetEnabled, signal);
      }
      if (
        mutationPasswordRegistered
        && verdict
        && !verdict.success
        && !isWifiConfigurationApplied(verdict)
      ) {
        verdict = {
          ...verdict,
          message: WIFI_PASSWORD_REGISTERED_APPLY_FAILED_MESSAGE,
        };
      }
      if (verdict && typeof options.showToast === 'function') {
        options.showToast({
          tone: verdict.success
            ? 'success'
            : (verdict.hubState && Object.values(HubState).includes(verdict.hubState)
              ? getStateDescriptor(verdict.hubState).tone
              : 'warning'),
          title: verdict.title,
          message: verdict.message,
        });
      }
      if (
        verdict?.success
        && standingPersistWarningKind
        && typeof options.showToast === 'function'
      ) {
        showStandingPersistWarningToast(standingPersistWarningKind, options.showToast);
        standingPersistWarningKind = null;
      }
      if (verdict?.success) {
        if (action.startsWith('staff')) {
          staffFormDirty = false;
        } else {
          guestFormDirty = false;
        }
      }
    } catch (error) {
      if (typeof options.showToast === 'function') {
        showMutationError(options.showToast, error);
      }
    } finally {
      staffBusy = false;
      guestBusy = false;
      activeProgressPanel = null;
      lastSignature = null;
      update();
    }
  }

  /**
   * @returns {Array<{ value: string, label: string }>}
   */
  function buildApSelectOptions() {
    return [
      { value: '', label: '— не назначено —' },
      ...listWifiApOptions().map((opt) => ({ value: opt.apId, label: opt.label })),
    ];
  }

  /**
   * @param {string|null} nextApId
   * @param {AbortSignal|undefined} signal
   */
  async function handleStaffApRoleChange(nextApId, signal) {
    staffBusy = true;
    update();
    try {
      standing = await updateStaffStandingNetworkPreferences(
        buildStaffApRoleUpdate(nextApId),
        { signal },
      );
      selectedStaffApId = nextApId;
      staffObserved = null;
      staffFormDirty = false;
      staffDraft = createStaffWifiFormDraft(null, standing);
      lastSignature = null;
      if (nextApId) {
        staffObserved = await fetchStaffWifiObservedState({
          apId: nextApId,
          session: options.getSession(),
          adapterMode,
          signal,
        });
        staffFormDirty = false;
        staffDraft = createStaffWifiFormDraft(staffObserved, standing);
      }
    } catch (error) {
      if (typeof options.showToast === 'function') {
        showMutationError(options.showToast, error);
      }
    } finally {
      staffBusy = false;
      lastSignature = null;
      update();
    }
  }

  /**
   * @param {string|null} nextApId
   * @param {AbortSignal|undefined} signal
   */
  async function handleGuestApRoleChange(nextApId, signal) {
    guestBusy = true;
    update();
    try {
      standing = await updateGuestStandingNetworkPreferences(
        buildGuestApRoleUpdate(nextApId),
        { signal },
      );
      selectedGuestApId = nextApId;
      guestObserved = null;
      guestFormDirty = false;
      guestDraft = createGuestWifiFormDraft(null, standing);
      if (!guestDraft.ssid?.trim()) {
        guestDraft = {
          ...guestDraft,
          ssid:
            typeof standing?.guest_default_ssid === 'string' && standing.guest_default_ssid.trim()
              ? standing.guest_default_ssid.trim()
              : GUEST_WIFI_STANDING_SSID_SEED,
        };
      }
      lastSignature = null;
      if (nextApId) {
        guestObserved = await fetchGuestWifiObservedState({
          apId: nextApId,
          session: options.getSession(),
          adapterMode,
          signal,
        });
        guestFormDirty = false;
        guestDraft = createGuestWifiFormDraft(guestObserved, standing);
        if (!guestDraft.ssid?.trim()) {
          guestDraft = {
            ...guestDraft,
            ssid:
              typeof standing?.guest_default_ssid === 'string' && standing.guest_default_ssid.trim()
                ? standing.guest_default_ssid.trim()
                : GUEST_WIFI_STANDING_SSID_SEED,
          };
        }
      }
    } catch (error) {
      if (typeof options.showToast === 'function') {
        showMutationError(options.showToast, error);
      }
    } finally {
      guestBusy = false;
      lastSignature = null;
      update();
    }
  }

  /**
   * @param {'staff'|'guest'} role
   * @param {string|null} currentApId
   * @param {boolean} busy
   */
  function renderApRoleSelect(role, currentApId, busy) {
    const isStaff = role === 'staff';
    const selectId = `${idPrefix}-${isStaff ? 'staff' : 'guest'}-ap-select`;
    const label = isStaff
      ? 'Точка доступа для рабочей сети'
      : 'Точка доступа для гостевой сети';
    const onChange = isStaff ? handleStaffApRoleChange : handleGuestApRoleChange;
    return createSelectField({
      id: selectId,
      label,
      value: currentApId ?? '',
      options: buildApSelectOptions(),
      disabled: busy || resolveDisabled(),
      onChange: (event) => {
        if (resolveDisabled()) {
          return;
        }
        if (event.target instanceof HTMLSelectElement) {
          const nextApId = event.target.value || null;
          if (nextApId === currentApId) {
            return;
          }
          const signal = typeof getSignal === 'function' ? getSignal() : undefined;
          void onChange(nextApId, signal);
        }
      },
    });
  }

  /**
   * @param {HTMLElement} el
   */
  function clearElement(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function renderStaffSlot() {
    if (activeProgressPanel && staffBusy) {
      return;
    }
    clearElement(staffBody);

    if (!loadCompleted) {
      staffBody.appendChild(
        createInlineState({ state: HubState.LOADING, title: 'Загружаем рабочую сеть…' }),
      );
    } else if (!selectedStaffApId) {
      staffBody.appendChild(
        createStatePanel({
          state: HubState.UNSUPPORTED,
          titleTag: 'p',
          title: OVERVIEW_NETWORKS_STAFF_UNASSIGNED_TITLE,
          description: OVERVIEW_NETWORKS_UNASSIGNED_NOTE,
        }),
      );
      staffBody.appendChild(renderApRoleSelect('staff', selectedStaffApId, staffBusy));
    } else if (loading && !staffObserved && selectedStaffApId) {
      staffBody.appendChild(
        createInlineState({ state: HubState.LOADING, title: 'Загружаем рабочую сеть…' }),
      );
    } else if (selectedStaffApId && staffObserved?.readable) {
      staffBody.appendChild(renderApRoleSelect('staff', selectedStaffApId, staffBusy));
      const readiness = evaluateStaffWifiMutationReadiness(options.getSession(), adapterMode);
      const staffMutationBlocked = !readiness.allowed;

      const statusRow = document.createElement('div');
      statusRow.className = 'hub-overview-networks__status-row';
      const ssidEl = document.createElement('p');
      ssidEl.className = 'hub-overview-networks__ssid';
      ssidEl.textContent = staffObserved.ssid?.trim() || STAFF_WIFI_STANDING_SSID_SEED;
      statusRow.appendChild(ssidEl);
      statusRow.appendChild(
        createBadge({ label: staffObserved.activeLabel, tone: staffObserved.activeTone }),
      );
      staffBody.appendChild(statusRow);

      if (shouldShowStaffDisabledRemediation(staffObserved)) {
        staffBody.appendChild(
          createStatePanel({
            state: HubState.WARNING,
            titleTag: 'p',
            title: STAFF_WIFI_DISABLED_REMEDIATION_TITLE,
            description: STAFF_WIFI_DISABLED_REMEDIATION_MESSAGE,
          }),
        );
        const enableBtn = createButton({
          label: 'Включить рабочую сеть',
          disabled: staffBusy || loading || resolveDisabled() || staffMutationBlocked,
          busy: staffBusy,
          onActivate: () => {
            void runMutation('staff-enable');
          },
        });
        enableBtn.id = `${idPrefix}-staff-enable`;
        staffBody.appendChild(enableBtn);
      }

      if (canApplyStaffStandingDefaults({
        selectedApId: selectedStaffApId,
        standing,
        mutationReadiness: readiness,
      })) {
        const defaultsBtn = createButton({
          label: STAFF_WIFI_APPLY_DEFAULTS_LABEL,
          variant: 'secondary',
          disabled: staffBusy || loading || resolveDisabled(),
          busy: staffBusy,
          onActivate: () => {
            void runMutation('staff-defaults');
          },
        });
        defaultsBtn.id = `${idPrefix}-staff-defaults`;
        staffBody.appendChild(defaultsBtn);
      }

      const credIntent = resolveStaffWifiCredentialIntent({
        password: staffDraft.password,
        standing,
        draftCredentialRef: staffCredentialRef,
        selectedApId: selectedStaffApId,
        draftSsid: staffDraft.ssid,
      });
      if (credIntent.kind === 'missing' || staffDraft.password) {
        staffBody.appendChild(
          createTextField({
            id: `${idPrefix}-staff-password`,
            label: 'Пароль рабочей сети',
            type: 'password',
            value: staffDraft.password,
            autocomplete: 'new-password',
            disabled: staffBusy || resolveDisabled(),
            onInput: (event) => {
              staffDraft = { ...staffDraft, password: readInputEventValue(event) };
              staffFormDirty = true;
            },
          }),
        );
      }
    } else if (selectedStaffApId) {
      staffBody.appendChild(renderApRoleSelect('staff', selectedStaffApId, staffBusy));
      staffBody.appendChild(
        createStatePanel({
          state: HubState.WARNING,
          titleTag: 'p',
          title: 'Состояние рабочей сети не прочитано',
        }),
      );
    }
  }

  function renderGuestSlot() {
    if (activeProgressPanel && guestBusy) {
      return;
    }
    clearElement(guestBody);

    if (!loadCompleted) {
      guestBody.appendChild(
        createInlineState({ state: HubState.LOADING, title: 'Загружаем гостевую сеть…' }),
      );
    } else if (!selectedGuestApId) {
      guestBody.appendChild(
        createStatePanel({
          state: HubState.UNSUPPORTED,
          titleTag: 'p',
          title: OVERVIEW_NETWORKS_GUEST_UNASSIGNED_TITLE,
          description: OVERVIEW_NETWORKS_UNASSIGNED_NOTE,
        }),
      );
      guestBody.appendChild(renderApRoleSelect('guest', selectedGuestApId, guestBusy));
    } else {
      const overlapWarning = getGuestStaffApOverlapWarning(
        { wifiRoles: { staffApId: selectedStaffApId } },
        selectedGuestApId,
      );
      if (overlapWarning) {
        const overlapEl = document.createElement('p');
        overlapEl.className = 'hub-wifi__note';
        overlapEl.textContent = overlapWarning;
        guestBody.appendChild(overlapEl);
      }

      guestBody.appendChild(renderApRoleSelect('guest', selectedGuestApId, guestBusy));

      if (loading && !guestObserved && selectedGuestApId) {
        guestBody.appendChild(
          createInlineState({ state: HubState.LOADING, title: 'Загружаем гостевую сеть…' }),
        );
      } else if (selectedGuestApId) {
        const guestReadiness = evaluateGuestWifiMutationReadiness(options.getSession(), adapterMode);
        const guestMutationBlocked = !guestReadiness.allowed;
        const enabled = guestObserved?.activeLabel === 'Включена';
        guestBody.appendChild(
          createToggle({
            id: `${idPrefix}-guest-enabled`,
            label: 'Гостевая сеть',
            checked: enabled,
            disabled: guestBusy || loading || resolveDisabled() || guestMutationBlocked,
            onChange: (checked) => {
              void runMutation('guest-toggle', checked);
            },
          }),
        );

        guestBody.appendChild(
          createTextField({
            id: `${idPrefix}-guest-ssid`,
            label: 'Имя сети',
            value: guestDraft.ssid,
            disabled: guestBusy || loading || resolveDisabled() || guestMutationBlocked,
            onInput: (event) => {
              guestDraft = { ...guestDraft, ssid: readInputEventValue(event) };
              guestFormDirty = true;
              lastSignature = buildContentSignature();
            },
          }),
        );

        if (shouldOfferGuestRememberDefault({ draftSsid: guestDraft.ssid, standing })) {
          const rememberHint = document.createElement('p');
          rememberHint.className = 'hub-wifi__note';
          rememberHint.textContent = GUEST_WIFI_REMEMBER_DEFAULT_HINT;
          guestBody.appendChild(rememberHint);
          guestBody.appendChild(
            createToggle({
              id: `${idPrefix}-guest-remember`,
              label: GUEST_WIFI_REMEMBER_DEFAULT_LABEL,
              checked: guestRememberDefault,
              disabled: guestBusy || loading || resolveDisabled() || guestMutationBlocked,
              onChange: (checked) => {
                guestRememberDefault = checked;
                lastSignature = null;
                update();
              },
            }),
          );
        }

        if (!enabled || guestObserved?.keyConfigured === false) {
          guestBody.appendChild(
            createTextField({
              id: `${idPrefix}-guest-password`,
              label: 'Пароль гостевой сети',
              type: 'password',
              value: guestDraft.password,
              autocomplete: 'new-password',
              disabled: guestBusy || loading || resolveDisabled() || guestMutationBlocked,
              onInput: (event) => {
                guestDraft = { ...guestDraft, password: readInputEventValue(event) };
                guestFormDirty = true;
              },
            }),
          );
        }

        if (!isObservedWpaModeKnown(guestObserved)) {
          const wpaOptions = isWifiWpaModeDraftSelected(guestDraft.wpaMode)
            ? GUEST_WIFI_WPA_MODE_OPTIONS
            : [WPA_MODE_DRAFT_PLACEHOLDER_OPTION, ...GUEST_WIFI_WPA_MODE_OPTIONS];
          guestBody.appendChild(
            createSelectField({
              id: `${idPrefix}-guest-wpa`,
              label: 'Защита',
              options: wpaOptions,
              value: guestDraft.wpaMode,
              hint: guestWifiWpaFieldHint(guestObserved) || undefined,
              disabled: guestBusy || loading || resolveDisabled() || guestMutationBlocked,
              onChange: (event) => {
                if (event.target instanceof HTMLSelectElement) {
                  guestDraft = { ...guestDraft, wpaMode: event.target.value };
                  guestFormDirty = true;
                  lastSignature = buildContentSignature();
                }
              },
            }),
          );
        }

        if (guestObserved?.readable) {
          const statusRow = document.createElement('div');
          statusRow.className = 'hub-overview-networks__status-row';
          statusRow.appendChild(
            createBadge({ label: guestObserved.activeLabel, tone: guestObserved.activeTone }),
          );
          guestBody.insertBefore(statusRow, guestBody.firstChild?.nextSibling ?? null);
        }
      }
    }
  }

  function update() {
    const signature = buildContentSignature();
    if (
      signature === lastSignature
      && staffSlot.querySelector('.hub-overview-step-card')
      && guestSlot.querySelector('.hub-overview-step-card')
    ) {
      return;
    }
    lastSignature = signature;
    const scrollPosition = captureScrollPosition();
    capturePendingFocus(staffSlot);
    capturePendingFocus(guestSlot);
    renderStaffSlot();
    renderGuestSlot();
    restorePendingFocus();
    restoreScrollPosition(scrollPosition);
  }

  /**
   * @param {{ signal?: AbortSignal }} [params]
   */
  async function loadAndUpdate(params = {}) {
    if (isRestorePending()) {
      return;
    }
    const { signal } = params;
    loading = true;
    lastSignature = null;
    update();
    try {
      standing = await fetchStaffStandingNetworkPreferences({ signal });
      const session = options.getSession();
      selectedStaffApId = standing?.staff_ap_id ?? null;
      selectedGuestApId = standing?.guest_ap_id ?? null;
      const tasks = [];
      if (selectedStaffApId) {
        tasks.push(
          fetchStaffWifiObservedState({
            apId: selectedStaffApId,
            session,
            adapterMode,
            signal,
          }).then((observed) => {
            staffObserved = observed;
          }),
        );
      } else {
        staffObserved = null;
      }
      if (selectedGuestApId) {
        tasks.push(
          fetchGuestWifiObservedState({
            apId: selectedGuestApId,
            session,
            adapterMode,
            signal,
          }).then((observed) => {
            guestObserved = observed;
          }),
        );
      } else {
        guestObserved = null;
      }
      await Promise.all(tasks);
      if (!staffFormDirty) {
        staffDraft = createStaffWifiFormDraft(staffObserved, standing);
      }
      if (!guestFormDirty) {
        guestDraft = createGuestWifiFormDraft(guestObserved, standing);
        if (!guestDraft.ssid?.trim()) {
          guestDraft = {
            ...guestDraft,
            ssid:
              typeof standing?.guest_default_ssid === 'string' && standing.guest_default_ssid.trim()
                ? standing.guest_default_ssid.trim()
                : GUEST_WIFI_STANDING_SSID_SEED,
          };
        }
      }
    } catch (error) {
      if (!isAborted(error) && typeof options.showToast === 'function') {
        showMutationError(options.showToast, error);
      }
    } finally {
      loading = false;
      loadCompleted = true;
      lastSignature = null;
      update();
    }
  }

  function destroy() {
    staffSlot.textContent = '';
    guestSlot.textContent = '';
  }

  update();

  return { update, destroy, loadAndUpdate };
}
