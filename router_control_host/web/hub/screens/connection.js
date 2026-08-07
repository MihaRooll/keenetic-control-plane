import {
  createBadge,
  createButton,
  createCard,
  createIcon,
  createTextField,
  createTechnicalDetails,
  openModal,
} from '../components/index.js';
import { apiGet, apiPost, subscribeConnectivity } from '../core/api.js';
import { readInputEventValue, syncActionButtonById } from '../core/form-submit-sync.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import {
  cancelConnectionContextRestore,
  getSession,
  isConnectionRestorePending,
  subscribeSession,
  updateSession,
} from '../core/session.js';
import {
  describeRestoredConnectionGaps,
  needsManagementUsernameRecovery,
  isConnectionRestoreFailed,
  formatOperatorTimestamp,
  liveCapabilitySubscriptionKey,
} from '../features/live-connection-params.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
} from '../core/states.js';
import {
  CONNECTION_CHECKLIST_FACT_ORDER,
  ACCESS_STORAGE_NOTE,
  ConnectionStep,
  buildConnectionChecklist,
  buildDraftBody,
  checkConnectionHealth,
  confirmHostKey,
  createIdempotencyKey,
  deriveVerifyHostKeyBadge,
  describeDiscovery,
  describeGroupPortOptions,
  describeHostKeyConflict,
  describeManagementAvailability,
  evaluateFinishGate,
  formatFingerprint,
  healthBindingsMatch,
  learnHostKey,
  normalizeHealthBinding,
  portSelectionKey,
  resolveGroupEndpoint,
  runDiscovery,
  createDraftRouter,
  submitManagementUsername,
  validateAccessForm,
  validateManualHost,
} from '../features/connection-flow.js';

export const meta = {
  id: 'connection',
  title: 'Подключение',
  iconName: 'connection',
};

/** @typedef {{ host: string, port: number|null, sourceAddress: string|null, routerId: string|null }} SelectedTarget */

/** @typedef {{ fingerprint: string, algorithm: string }} LearnedHostKey */

const STEP_LABELS = Object.freeze([
  { value: ConnectionStep.SEARCH, label: 'Поиск' },
  { value: ConnectionStep.ACCESS, label: 'Доступ' },
  { value: ConnectionStep.VERIFY, label: 'Проверка' },
]);

const FINGERPRINT_WARNING =
  'Отпечаток — это уникальный код устройства. Сверьте его с наклейкой на роутере, экраном устройства или документами. Подтверждайте только свой роутер: подтвердив чужой, вы откроете управление не тому устройству.';

const MANAGEMENT_USERNAME_RECOVERY_NOTE =
  'На сервере сохранён отпечаток этого роутера, но не сохранено имя пользователя для управления. Укажите его — повторное подтверждение отпечатка не требуется.';

const MANAGEMENT_USERNAME_SAVE_BTN_ID = 'hub-connection-management-username-save';
const SEARCH_NEXT_BTN_ID = 'hub-connection-search-next-btn';

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
 * @param {string} step
 * @returns {string}
 */
function stepTitleId(step) {
  return `hub-connection-step-title-${step}`;
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
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 * @param {boolean} disabled
 */
function updateButtonBusyState(button, busy, disabled) {
  button.disabled = busy || disabled;
  const content = button.querySelector('.hub-btn__content');
  const existingSpinner = button.querySelector('.hub-btn__spinner');
  const contentIcon = content?.querySelector('.hub-icon');
  if (busy) {
    button.setAttribute('aria-busy', 'true');
    button.classList.add('hub-btn--busy');
    if (!existingSpinner) {
      const spinnerWrap = document.createElement('span');
      spinnerWrap.className = 'hub-btn__spinner';
      spinnerWrap.appendChild(createIcon('spinner', { size: 18 }));
      button.appendChild(spinnerWrap);
    }
    if (contentIcon instanceof HTMLElement) {
      contentIcon.hidden = true;
    }
  } else {
    button.removeAttribute('aria-busy');
    button.classList.remove('hub-btn--busy');
    existingSpinner?.remove();
    if (contentIcon instanceof HTMLElement) {
      contentIcon.hidden = false;
    }
  }
}

/**
 * @param {string} host
 * @param {number|null} port
 * @returns {string}
 */
function formatHostAddress(host, port) {
  if (port != null) {
    return `${host}:${port}`;
  }
  return host;
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

  const sessionSnapshot = getSession();
  let currentStep = sessionSnapshot.routerId
    ? (sessionSnapshot.hostKeyConfirmed ? ConnectionStep.VERIFY : ConnectionStep.ACCESS)
    : ConnectionStep.SEARCH;
  /** @type {ConnectionStep} */
  let maxReachableStep = sessionSnapshot.hostKeyConfirmed
    ? ConnectionStep.VERIFY
    : (sessionSnapshot.routerId ? ConnectionStep.ACCESS : ConnectionStep.SEARCH);

  let generation = 0;
  /** @type {number|null} */
  let searchingGeneration = null;
  /** @type {number|null} */
  let savingAccessGeneration = null;
  /** @type {number|null} */
  let learningHostKeyGeneration = null;
  /** @type {number|null} */
  let confirmingHostKeyGeneration = null;
  /** @type {number|null} */
  let checkingHealthGeneration = null;
  let disposed = false;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;
  let recovering = false;
  let initialLoading = sessionSnapshot.routerId == null;

  /** @type {AbortController|null} */
  let discoveryAbort = null;
  /** @type {AbortController|null} */
  let accessAbort = null;
  /** @type {AbortController|null} */
  let learnHostKeyAbort = null;
  /** @type {AbortController|null} */
  let confirmHostKeyAbort = null;
  /** @type {AbortController|null} */
  let healthAbort = null;

  let searching = false;
  let savingAccess = false;
  let learningHostKey = false;
  let confirmingHostKey = false;
  let checkingHealth = false;

  /** @type {ReturnType<typeof describeDiscovery>|null} */
  let discoveryView = null;
  /** @type {unknown|null} */
  let discoveryError = null;

  /** @type {SelectedTarget|null} */
  let selectedTarget = sessionSnapshot.routerHost
    ? {
        host: sessionSnapshot.routerHost,
        port: null,
        sourceAddress: sessionSnapshot.sourceAddress ?? null,
        routerId: sessionSnapshot.routerId,
      }
    : null;

  /** @type {Record<string, number|null>} */
  let groupPortByHost = {};

  let manualMode = false;
  let manualHostValue = sessionSnapshot.routerHost ?? '';

  let accessHost = sessionSnapshot.routerHost ?? '';
  let accessUsername = sessionSnapshot.wifiLive.username ?? '';
  /** @type {string} */
  let accessPassword = '';
  let accessFormDirty = false;
  /** @type {string|null} */
  let accessIdempotencyKey = null;
  /** @type {string[]} */
  let accessErrors = [];
  /** @type {unknown|null} */
  let accessSaveError = null;
  let accessSaved = Boolean(sessionSnapshot.wifiLive.credentialRefId);
  let accessPasswordReentryNote = false;

  /** @type {string|null} */
  let activeRouterId = sessionSnapshot.routerId;
  /** @type {LearnedHostKey|null} */
  let learnedHostKey = null;
  /** @type {unknown|null} */
  let hostKeyError = null;
  /** @type {unknown|null} */
  let confirmHostKeyError = null;
  let savingManagementUsername = false;
  /** @type {unknown|null} */
  let managementUsernameError = null;
  let managementUsernameInput = '';

  /** @type {{ binding: ReturnType<typeof normalizeHealthBinding>, data: import('../features/connection-flow.js').ConnectionHealthResponse }|null} */
  let healthSnapshot = null;
  /** @type {{ binding: ReturnType<typeof normalizeHealthBinding>, error: unknown }|null} */
  let healthErrorSnapshot = null;
  let healthCheckCancelled = false;

  /** @type {{ kind: string, id?: string, step?: string }|null} */
  let pendingFocus = null;

  /**
   * @param {import('../core/session.js').SessionSnapshot} session
   * @returns {ReturnType<typeof normalizeHealthBinding>}
   */
  function getCurrentHealthBinding(session) {
    return normalizeHealthBinding({
      routerId: session.routerId ?? activeRouterId,
      routerHost: session.routerHost ?? accessHost,
      sourceAddress: session.sourceAddress ?? selectedTarget?.sourceAddress ?? null,
    });
  }

  /**
   * Health-результат действителен только для текущей привязки и вне повторной проверки.
   * @param {import('../core/session.js').SessionSnapshot} session
   * @returns {import('../features/connection-flow.js').ConnectionHealthResponse|null}
   */
  function getEffectiveHealth(session) {
    if (checkingHealth || !healthSnapshot) {
      return null;
    }
    if (!healthBindingsMatch(healthSnapshot.binding, getCurrentHealthBinding(session))) {
      return null;
    }
    return healthSnapshot.data;
  }

  /**
   * Ошибка health действительна только для текущей привязки и вне повторной проверки.
   * @param {import('../core/session.js').SessionSnapshot} session
   * @returns {unknown|null}
   */
  function getEffectiveHealthError(session) {
    if (checkingHealth || !healthErrorSnapshot) {
      return null;
    }
    if (!healthBindingsMatch(healthErrorSnapshot.binding, getCurrentHealthBinding(session))) {
      return null;
    }
    if (isAborted(healthErrorSnapshot.error)) {
      return null;
    }
    return healthErrorSnapshot.error;
  }

  /** @type {Array<{ close: () => void }>} */
  let openModals = [];

  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-connection';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.textContent = 'Подключение к роутеру';
  header.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent =
    'Найдём роутер среди известных адресов и настроим безопасное управление';
  header.appendChild(subtitle);
  screen.appendChild(header);

  const stepperNav = document.createElement('nav');
  stepperNav.className = 'hub-connection__stepper';
  stepperNav.setAttribute('aria-label', 'Шаги подключения');
  const stepperList = document.createElement('ol');
  stepperList.className = 'hub-connection__stepper-list';
  stepperNav.appendChild(stepperList);
  screen.appendChild(stepperNav);

  const contentWrap = document.createElement('div');
  contentWrap.className = 'hub-connection__content';
  screen.appendChild(contentWrap);

  const infoNoteWrap = document.createElement('div');
  infoNoteWrap.className = 'hub-connection__info-note';
  screen.appendChild(infoNoteWrap);

  const footer = document.createElement('footer');
  footer.className = 'hub-connection__footer';
  const footerLeft = document.createElement('div');
  footerLeft.className = 'hub-connection__footer-left';
  const footerRight = document.createElement('div');
  footerRight.className = 'hub-connection__footer-right';
  footer.appendChild(footerLeft);
  footer.appendChild(footerRight);
  screen.appendChild(footer);

  container.appendChild(screen);

  function clearElement(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function stepIndex(step) {
    return STEP_LABELS.findIndex((item) => item.value === step);
  }

  function canNavigateToStep(step) {
    return stepIndex(step) <= stepIndex(maxReachableStep);
  }

  function setMaxReachableStep(step) {
    if (stepIndex(step) > stepIndex(maxReachableStep)) {
      maxReachableStep = step;
    }
  }

  function goToStep(step) {
    if (!canNavigateToStep(step)) {
      return;
    }
    closeAllModals();
    pendingFocus = { kind: 'step-heading', step };
    currentStep = step;
    renderAll();
  }

  function markAccessFormDirty() {
    accessFormDirty = true;
  }

  function ensureAccessIdempotencyKey() {
    if (accessFormDirty || accessIdempotencyKey == null) {
      accessIdempotencyKey = createIdempotencyKey();
      accessFormDirty = false;
    }
    return accessIdempotencyKey;
  }

  function renderConnectionRestoreFailedPanel() {
    return createStatePanel({
      state: HubState.WARNING,
      titleTag: 'h3',
      title: 'Не удалось проверить сохранённое подключение',
      description:
        'Сервер не ответил вовремя или вернул ошибку. Обновите страницу или проверьте сеть. Если проблема сохраняется — пройдите шаги подключения заново.',
      action: {
        label: 'Обновить страницу',
        onActivate: () => {
          window.location.reload();
        },
      },
    });
  }

  /**
   * @param {import('../core/session.js').SessionSnapshot} session
   * @returns {HTMLDivElement|null}
   */
  function renderServerPinDetails(session) {
    if (!session.hostKeyConfirmed) {
      return null;
    }

    const section = document.createElement('div');
    section.className = 'hub-connection__host-key';

    const note = document.createElement('p');
    note.className = 'hub-connection__info-text';
    note.textContent =
      'Это подтверждение сохранено на сервере управления. Оно не проверяет, отвечает ли роутер прямо сейчас.';
    section.appendChild(note);

    const host = session.routerHost ?? session.wifiLive?.host;
    if (host) {
      const endpointLine = document.createElement('p');
      endpointLine.className = 'hub-connection__info-text';
      endpointLine.textContent = `Подтверждение относится к ${host} (служебное подключение к роутеру)`;
      section.appendChild(endpointLine);
      const portNote = document.createElement('p');
      portNote.className = 'hub-connection__info-text';
      portNote.textContent = 'Живые подключения всегда используют порт 22.';
      section.appendChild(portNote);
    }

    const pinnedLabel = formatOperatorTimestamp(session.pinnedAt);
    if (pinnedLabel) {
      const whenLine = document.createElement('p');
      whenLine.className = 'hub-connection__info-text';
      whenLine.textContent = `Подтверждено ${pinnedLabel}`;
      section.appendChild(whenLine);
    }

    const fingerprint = session.wifiLive?.sshHostKeySha256;
    if (fingerprint) {
      const fpLabel = document.createElement('p');
      fpLabel.className = 'hub-connection__fingerprint-label';
      fpLabel.textContent = 'Отпечаток устройства:';
      section.appendChild(fpLabel);
      const fpVal = document.createElement('code');
      fpVal.className = 'hub-connection__fingerprint-value';
      fpVal.textContent = fingerprint;
      section.appendChild(fpVal);
    }

    return section;
  }

  function syncManagementUsernameFormUi() {
    syncActionButtonById(MANAGEMENT_USERNAME_SAVE_BTN_ID, {
      disabled: offline || !managementUsernameInput.trim() || savingManagementUsername,
      busy: savingManagementUsername,
    });
  }

  function syncSearchFooterUi() {
    if (currentStep !== ConnectionStep.SEARCH || !manualMode) {
      return;
    }
    const canProceed = validateManualHost(manualHostValue).valid;
    syncActionButtonById(SEARCH_NEXT_BTN_ID, {
      disabled: !canProceed || offline,
      busy: false,
    });
  }

  function renderManagementUsernameRecovery() {
    const section = document.createElement('section');
    section.className = 'hub-connection__host-key';

    const title = document.createElement('h3');
    title.className = 'hub-connection__section-title';
    title.textContent = 'Имя пользователя для управления';
    section.appendChild(title);

    const note = document.createElement('p');
    note.className = 'hub-connection__info-text';
    note.textContent = MANAGEMENT_USERNAME_RECOVERY_NOTE;
    section.appendChild(note);

    const form = document.createElement('form');
    form.noValidate = true;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      void submitManagementUsernameFlow();
    });

    const usernameField = createTextField({
      id: 'hub-connection-management-username',
      label: 'Имя пользователя',
      value: managementUsernameInput,
      autocomplete: 'off',
      disabled: savingManagementUsername || offline,
      onInput: (event) => {
        managementUsernameInput = readInputEventValue(event);
        managementUsernameError = null;
        syncManagementUsernameFormUi();
      },
    });
    form.appendChild(usernameField);

    if (managementUsernameError && !isAborted(managementUsernameError)) {
      const described = describeError(managementUsernameError);
      form.appendChild(
        createStatePanel({
          state: hubStateForError(managementUsernameError),
          titleTag: 'h4',
          title: described.title,
          description: formatErrorDescription(described),
        }),
      );
    }

    const saveBtn = createButton({
      label: 'Сохранить имя пользователя',
      busy: savingManagementUsername,
      disabled: offline || !managementUsernameInput.trim(),
      onActivate: () => {
        void submitManagementUsernameFlow();
      },
    });
    saveBtn.type = 'submit';
    saveBtn.id = MANAGEMENT_USERNAME_SAVE_BTN_ID;
    form.appendChild(saveBtn);
    section.appendChild(form);

    return section;
  }

  async function submitManagementUsernameFlow() {
    const session = getSession();
    const routerId = session.routerId ?? activeRouterId;
    const username = managementUsernameInput.trim();
    if (!routerId || !username || savingManagementUsername || offline) {
      return;
    }

    savingManagementUsername = true;
    managementUsernameError = null;
    renderAll();

    try {
      const ctx = await submitManagementUsername({
        routerId,
        username,
      });

      managementUsernameInput = '';
      if (ctx.live_ready === true) {
        void runHealthCheckFlow();
      }
    } catch (error) {
      if (!isAborted(error)) {
        managementUsernameError = error;
      }
    } finally {
      savingManagementUsername = false;
      if (!disposed) {
        renderAll();
      }
    }
  }

  function syncAccessPasswordFromDom() {
    const pwdEl = document.getElementById('hub-connection-access-password');
    if (pwdEl instanceof HTMLInputElement) {
      accessPassword = pwdEl.value;
    }
  }

  function resetHostKeyState() {
    learnedHostKey = null;
    hostKeyError = null;
    confirmHostKeyError = null;
    updateSession({
      hostKeyConfirmed: false,
      liveReady: false,
      usernameAvailable: false,
      pinnedAt: null,
      pinnedEndpointPort: null,
      wifiLive: { sshHostKeySha256: null },
    });
  }

  function onAccessTargetChanged() {
    if (accessSaved) {
      resetHostKeyState();
      maxReachableStep = ConnectionStep.ACCESS;
      if (currentStep === ConnectionStep.VERIFY) {
        goToStep(ConnectionStep.ACCESS);
      }
    }
  }

  function clearRecovering() {
    if (recovering) {
      recovering = false;
    }
  }

  function invalidateAllOperations() {
    generation += 1;
    abortAllOperations();
    searching = false;
    savingAccess = false;
    learningHostKey = false;
    confirmingHostKey = false;
    checkingHealth = false;
    searchingGeneration = null;
    savingAccessGeneration = null;
    learningHostKeyGeneration = null;
    confirmingHostKeyGeneration = null;
    checkingHealthGeneration = null;
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

  function restorePendingFocus() {
    if (!pendingFocus) {
      return;
    }
    const target = pendingFocus;
    pendingFocus = null;
    if (target.kind === 'element-id' && target.id) {
      const el = document.getElementById(target.id);
      if (el instanceof HTMLElement) {
        el.focus();
      }
      return;
    }
    if (target.kind === 'step-heading' && target.step) {
      const el = document.getElementById(stepTitleId(target.step));
      if (el instanceof HTMLElement) {
        el.focus();
      }
      return;
    }
    if (target.kind === 'first-field-error') {
      const invalid = contentWrap.querySelector('.hub-field__input[aria-invalid="true"]');
      if (invalid instanceof HTMLElement) {
        invalid.focus();
      }
    }
  }

  /**
   * @param {string[]} errors
   * @returns {{ hostError: string|null, usernameError: string|null, passwordError: string|null }}
   */
  function splitAccessFieldErrors(errors) {
    /** @type {string|null} */
    let hostError = null;
    /** @type {string|null} */
    let usernameError = null;
    /** @type {string|null} */
    let passwordError = null;
    for (const err of errors) {
      if (err.includes('адрес') || err.includes('пробел') || err.includes('пользователя в поле')) {
        hostError = err;
      } else if (err.includes('пользов')) {
        usernameError = err;
      } else if (err.includes('парол')) {
        passwordError = err;
      }
    }
    return { hostError, usernameError, passwordError };
  }

  /**
   * @param {import('../features/connection-flow.js').ConnectionHealthResponse|null} health
   * @param {boolean} hostKeyConfirmed
   * @returns {boolean}
   */
  function isLiveDeviceReady(health, hostKeyConfirmed) {
    if (health == null || health.status === 'red' || hostKeyConfirmed !== true) {
      return false;
    }
    const facts = health.facts ?? {};
    return CONNECTION_CHECKLIST_FACT_ORDER.every((factId) => facts[factId] === true);
  }

  function abortDiscovery() {
    discoveryAbort?.abort();
  }

  function abortAccess() {
    accessAbort?.abort();
  }

  function abortLearnHostKey() {
    learnHostKeyAbort?.abort();
  }

  function abortConfirmHostKey() {
    confirmHostKeyAbort?.abort();
  }

  function abortHealth() {
    healthAbort?.abort();
  }

  function abortAllOperations() {
    abortDiscovery();
    abortAccess();
    abortLearnHostKey();
    abortConfirmHostKey();
    abortHealth();
  }

  function renderStepper() {
    clearElement(stepperList);
    const currentIdx = stepIndex(currentStep);
    const session = getSession();
    for (let i = 0; i < STEP_LABELS.length; i += 1) {
      const item = STEP_LABELS[i];
      const li = document.createElement('li');
      li.className = 'hub-connection__stepper-item';

      const stepBtn = document.createElement('button');
      stepBtn.type = 'button';
      stepBtn.className = 'hub-connection__step';
      /** @type {'done'|'current'|'upcoming'} */
      let dataState = 'upcoming';
      if (i === currentIdx) {
        dataState = 'current';
      } else if (item.value === ConnectionStep.ACCESS) {
        if (session.hostKeyConfirmed === true) {
          dataState = 'done';
        }
      } else if (i < currentIdx) {
        dataState = 'done';
      }
      stepBtn.setAttribute('data-state', dataState);
      stepBtn.disabled = !canNavigateToStep(item.value) || offline;

      const marker = document.createElement('span');
      marker.className = 'hub-connection__step-marker';
      marker.setAttribute('aria-hidden', 'true');
      if (dataState === 'done') {
        marker.appendChild(createIcon('check', { size: 18 }));
      } else {
        marker.textContent = String(i + 1);
      }
      stepBtn.appendChild(marker);

      const labelEl = document.createElement('span');
      labelEl.className = 'hub-connection__step-label';
      labelEl.textContent = item.label;
      stepBtn.appendChild(labelEl);

      if (i === currentIdx) {
        stepBtn.setAttribute('aria-current', 'step');
      }
      if (i < currentIdx) {
        stepBtn.setAttribute('aria-label', `${item.label}, шаг пройден`);
      } else {
        stepBtn.setAttribute('aria-label', item.label);
      }

      stepBtn.addEventListener('click', () => {
        goToStep(item.value);
      });

      li.appendChild(stepBtn);
      stepperList.appendChild(li);
    }
  }

  function renderAccessStorageBanner() {
    const banner = document.createElement('div');
    banner.className = 'hub-connection__info-banner';
    const iconEl = document.createElement('span');
    iconEl.className = 'hub-connection__info-icon';
    iconEl.appendChild(createIcon('info', { size: 20 }));
    banner.appendChild(iconEl);
    const note = document.createElement('p');
    note.className = 'hub-connection__info-text';
    note.textContent = ACCESS_STORAGE_NOTE;
    banner.appendChild(note);
    return banner;
  }

  function renderInfoNote() {
    clearElement(infoNoteWrap);
    if (currentStep === ConnectionStep.ACCESS) {
      const note = document.createElement('p');
      note.className = 'hub-connection__info-text';
      note.textContent = ACCESS_STORAGE_NOTE;
      infoNoteWrap.appendChild(note);
    } else if (currentStep === ConnectionStep.VERIFY) {
      infoNoteWrap.appendChild(renderAccessStorageBanner());
    }
  }

  function renderSearchStep() {
    const stepTitle = document.createElement('h2');
    stepTitle.className = 'hub-connection__section-title';
    stepTitle.id = stepTitleId(ConnectionStep.SEARCH);
    stepTitle.tabIndex = -1;
    stepTitle.textContent = 'Поиск';
    contentWrap.appendChild(stepTitle);

    if (offline && !recovering) {
      contentWrap.appendChild(
        createStatePanel({
          state: HubState.NO_INTERNET,
          titleTag: 'h2',
          action: {
            label: 'Повторить',
            onActivate: () => {
              void runDiscoveryFlow();
            },
          },
        }),
      );
      return;
    }

    if (recovering) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.RECOVERING, title: 'Восстанавливаем связь с сервером управления' }),
      );
    }

    const session = getSession();

    if (isConnectionRestorePending(session)) {
      const pendingState = createInlineState({
        state: HubState.LOADING,
        title: 'Проверяем сохранённое подключение на сервере',
      });
      pendingState.setAttribute('aria-live', 'polite');
      contentWrap.appendChild(pendingState);
      return;
    }

    if (isConnectionRestoreFailed(session)) {
      contentWrap.appendChild(renderConnectionRestoreFailedPanel());
      return;
    }

    if (initialLoading) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.LOADING, title: 'Подготавливаем экран подключения' }),
      );
      contentWrap.appendChild(createSkeleton({ lines: 3, withTitle: true }));
      return;
    }

    const searchActions = document.createElement('div');
    searchActions.className = 'hub-connection__search-actions';
    const findBtn = createButton({
      label: 'Найти роутер',
      iconName: 'connection',
      busy: searching,
      onActivate: () => {
        void runDiscoveryFlow();
      },
    });
    findBtn.id = 'hub-connection-find-btn';
    updateButtonBusyState(findBtn, searching, offline);
    searchActions.appendChild(findBtn);
    contentWrap.appendChild(searchActions);

    if (searching) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.SEARCHING, title: 'Ищем роутер среди известных и сохранённых адресов' }),
      );
    }

    if (discoveryError && !isAborted(discoveryError)) {
      const described = describeError(discoveryError);
      contentWrap.appendChild(
        createStatePanel({
          state: hubStateForLoadError(discoveryError, offline),
          titleTag: 'h2',
          title: described.title,
          description: formatErrorDescription(described),
          details: described.technical,
          action: {
            label: 'Повторить',
            onActivate: () => {
              void runDiscoveryFlow();
            },
          },
        }),
      );
    }

    if (discoveryView) {
      const boundsNote = document.createElement('p');
      boundsNote.className = 'hub-connection__bounds-note';
      boundsNote.textContent = discoveryView.boundsNote;
      contentWrap.appendChild(boundsNote);

      if (discoveryView.diagnosticsNotes.length > 0) {
        const warnBlock = document.createElement('div');
        warnBlock.className = 'hub-connection__diagnostics';
        warnBlock.appendChild(
          createInlineState({
            state: HubState.WARNING,
            title: 'Часть источников данных недоступна',
          }),
        );
        const list = document.createElement('ul');
        list.className = 'hub-connection__diagnostics-list';
        for (const note of discoveryView.diagnosticsNotes) {
          const li = document.createElement('li');
          li.textContent = note;
          list.appendChild(li);
        }
        warnBlock.appendChild(list);
        contentWrap.appendChild(warnBlock);
      }

      if (discoveryView.state === HubState.EMPTY) {
        contentWrap.appendChild(
          createStatePanel({
            state: HubState.EMPTY,
            titleTag: 'h2',
            title: 'Подходящий роутер не найден',
            description: 'Подходящий роутер не найден. Укажите адрес вручную.',
          }),
        );
      } else if (discoveryView.candidates.length > 0) {
        const fieldset = document.createElement('fieldset');
        fieldset.className = 'hub-connection__candidates';
        const legend = document.createElement('legend');
        legend.className = 'hub-connection__candidates-legend';
        legend.textContent = 'Найденные адреса управления';
        fieldset.appendChild(legend);

        for (let i = 0; i < discoveryView.candidates.length; i += 1) {
          const group = discoveryView.candidates[i];
          const inputId = `hub-connection-candidate-${i}`;
          const selectedPort = groupPortByHost[group.host] ?? group.port;
          const isGroupSelected = selectedTarget?.host === group.host && !manualMode;
          const row = document.createElement('div');
          row.className = 'hub-connection__candidate';
          const radio = document.createElement('input');
          radio.type = 'radio';
          radio.name = 'hub-connection-candidate';
          radio.id = inputId;
          radio.value = group.host;
          radio.checked = isGroupSelected;
          radio.addEventListener('change', () => {
            manualMode = false;
            const port = groupPortByHost[group.host] ?? group.port;
            const endpoint = resolveGroupEndpoint(group, port);
            const previousHost = selectedTarget?.host ?? null;
            selectedTarget = {
              host: group.host,
              port: endpoint.port,
              sourceAddress: endpoint.sourceAddress,
              routerId: endpoint.routerId,
            };
            accessHost = group.host;
            if (accessSaved && previousHost !== group.host) {
              syncAccessPasswordFromDom();
              if (!accessPassword) {
                accessPasswordReentryNote = true;
              }
              onAccessTargetChanged();
            }
            pendingFocus = { kind: 'element-id', id: inputId };
            renderAll();
          });
          row.appendChild(radio);

          const body = document.createElement('div');
          body.className = 'hub-connection__candidate-body';

          const addressLine = document.createElement('label');
          addressLine.className = 'hub-connection__candidate-address';
          addressLine.htmlFor = inputId;
          addressLine.textContent = group.host;
          body.appendChild(addressLine);
          if (group.originsSummary) {
            const originsLine = document.createElement('span');
            originsLine.className = 'hub-connection__candidate-origins';
            originsLine.textContent = group.originsSummary;
            body.appendChild(originsLine);
          }
          body.appendChild(
            createBadge({ label: group.identityText, tone: group.identityTone }),
          );
          for (const reasonText of group.reasonTexts) {
            const reasonLine = document.createElement('span');
            reasonLine.className = 'hub-connection__candidate-reason';
            reasonLine.textContent = reasonText;
            body.appendChild(reasonLine);
          }
          for (const warningText of group.warnings) {
            const warningEl = document.createElement('p');
            warningEl.className = 'hub-connection__candidate-warning';
            warningEl.textContent = warningText;
            body.appendChild(warningEl);
          }
          if (group.hasMultiplePorts) {
            const portsWrap = document.createElement('fieldset');
            portsWrap.className = 'hub-connection__candidate-ports';
            const portsLabel = document.createElement('legend');
            portsLabel.className = 'hub-connection__candidate-ports-label';
            portsLabel.textContent = 'Способ подключения';
            portsWrap.appendChild(portsLabel);
            const portOptions = describeGroupPortOptions(group);
            const selectedPortKey = portSelectionKey(selectedPort);
            for (let portIndex = 0; portIndex < portOptions.length; portIndex += 1) {
              const portOption = portOptions[portIndex];
              const portInputId = `hub-connection-candidate-${i}-port-${portIndex}`;
              const portRow = document.createElement('label');
              portRow.className = 'hub-connection__candidate-port-option';
              const portRadio = document.createElement('input');
              portRadio.type = 'radio';
              portRadio.name = `hub-connection-port-${i}`;
              portRadio.id = portInputId;
              portRadio.value = portOption.portKey;
              portRadio.checked = selectedPortKey === portOption.portKey;
              portRadio.addEventListener('click', (event) => {
                event.stopPropagation();
              });
              portRadio.addEventListener('change', (event) => {
                event.stopPropagation();
                groupPortByHost[group.host] = portOption.port;
                if (selectedTarget?.host === group.host) {
                  const endpoint = resolveGroupEndpoint(group, portOption.port);
                  selectedTarget = {
                    host: group.host,
                    port: endpoint.port,
                    sourceAddress: endpoint.sourceAddress,
                    routerId: endpoint.routerId,
                  };
                }
                pendingFocus = { kind: 'element-id', id: portInputId };
                renderAll();
              });
              portRow.appendChild(portRadio);
              const portText = document.createElement('span');
              portText.className = 'hub-connection__candidate-port-label';
              portText.textContent = portOption.label;
              portRow.appendChild(portText);
              portsWrap.appendChild(portRow);
            }
            body.appendChild(portsWrap);
          } else if (group.port != null) {
            const portLine = document.createElement('span');
            portLine.className = 'hub-connection__candidate-origin';
            portLine.textContent = `Подключение через порт ${group.port}`;
            body.appendChild(portLine);
          }
          row.appendChild(body);
          fieldset.appendChild(row);
        }
        contentWrap.appendChild(fieldset);
      }

      if (discoveryView.excluded.length > 0) {
        const excludedLines = discoveryView.excluded.map(
          (item) => `${formatHostAddress(item.host, item.port ?? null)} — ${item.text}`,
        );
        contentWrap.appendChild(createTechnicalDetails({ content: excludedLines.join('\n') }));
      }
    }

    if (manualMode) {
      const manualValidation = validateManualHost(manualHostValue);
      const manualField = createTextField({
        id: 'hub-connection-manual-host',
        label: 'Адрес роутера',
        placeholder: 'например, 192.168.0.1',
        value: manualHostValue,
        error: !manualValidation.valid && manualHostValue.trim()
          ? manualValidation.errors[0]
          : undefined,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            manualHostValue = event.target.value;
            syncSearchFooterUi();
          }
        },
      });
      contentWrap.appendChild(manualField);
    }

    if (ctx.runtime?.adapterMode === 'fake' && discoveryView?.mock) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.MOCK_MODE, title: 'Демонстрационный режим поиска' }),
      );
    }
  }

  function renderAccessStep() {
    const session = getSession();

    const stepTitle = document.createElement('h2');
    stepTitle.className = 'hub-connection__section-title';
    stepTitle.id = stepTitleId(ConnectionStep.ACCESS);
    stepTitle.tabIndex = -1;
    stepTitle.textContent = 'Доступ';
    contentWrap.appendChild(stepTitle);

    if (isConnectionRestorePending(session)) {
      const pendingState = createInlineState({
        state: HubState.LOADING,
        title: 'Проверяем сохранённое подключение на сервере',
      });
      pendingState.setAttribute('aria-live', 'polite');
      contentWrap.appendChild(pendingState);
      return;
    }

    if (isConnectionRestoreFailed(session)) {
      contentWrap.appendChild(renderConnectionRestoreFailedPanel());
      return;
    }

    if (needsManagementUsernameRecovery(session)) {
      contentWrap.appendChild(renderManagementUsernameRecovery());
      return;
    }

    const restoreGaps = describeRestoredConnectionGaps(session);
    if (restoreGaps.length > 0) {
      const gapsBanner = document.createElement('div');
      gapsBanner.className = 'hub-connection__info-banner';
      const gapsText = document.createElement('p');
      gapsText.className = 'hub-connection__info-text';
      gapsText.textContent = `${restoreGaps.join('. ')}.`;
      gapsBanner.appendChild(gapsText);
      contentWrap.appendChild(gapsBanner);
    }

    if (offline && !recovering) {
      contentWrap.appendChild(
        createStatePanel({ state: HubState.NO_INTERNET, titleTag: 'h2' }),
      );
      return;
    }

    const fieldErrors = splitAccessFieldErrors(accessErrors);

    const hostField = createTextField({
      id: 'hub-connection-access-host',
      label: 'Адрес роутера',
      value: accessHost,
      error: fieldErrors.hostError ?? undefined,
      onInput: (event) => {
        if (event.target instanceof HTMLInputElement) {
          const previousHost = accessHost;
          accessHost = event.target.value;
          markAccessFormDirty();
          if (accessSaved && previousHost !== accessHost) {
            syncAccessPasswordFromDom();
            if (!accessPassword) {
              accessPasswordReentryNote = true;
            }
            onAccessTargetChanged();
            pendingFocus = { kind: 'element-id', id: 'hub-connection-access-host' };
            renderAll();
          }
        }
      },
    });
    contentWrap.appendChild(hostField);

    const usernameField = createTextField({
      id: 'hub-connection-access-username',
      label: 'Имя пользователя',
      placeholder: 'admin',
      value: accessUsername,
      error: fieldErrors.usernameError ?? undefined,
      onInput: (event) => {
        if (event.target instanceof HTMLInputElement) {
          accessUsername = event.target.value;
          markAccessFormDirty();
        }
      },
    });
    contentWrap.appendChild(usernameField);

    const passwordField = createTextField({
      id: 'hub-connection-access-password',
      label: 'Пароль',
      secret: true,
      placeholder: '••••••••',
      value: accessPassword,
      error: fieldErrors.passwordError ?? undefined,
      onInput: (event) => {
        if (event.target instanceof HTMLInputElement) {
          accessPassword = event.target.value;
          markAccessFormDirty();
          if (accessPassword) {
            accessPasswordReentryNote = false;
          }
        }
      },
    });
    contentWrap.appendChild(passwordField);

    if (accessPasswordReentryNote) {
      const reentryNote = document.createElement('p');
      reentryNote.className = 'hub-connection__info-text';
      reentryNote.textContent = 'Пароль нужно ввести заново для нового адреса';
      contentWrap.appendChild(reentryNote);
    }

    const saveBtn = createButton({
      label: 'Сохранить доступ',
      iconName: 'connection',
      busy: savingAccess,
      onActivate: () => {
        void saveAccessFlow();
      },
    });
    updateButtonBusyState(saveBtn, savingAccess, offline);
    contentWrap.appendChild(saveBtn);

    if (savingAccess) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.CONNECTING, title: 'Сохраняем доступ на сервере управления' }),
      );
    }

    if (accessSaveError && !isAborted(accessSaveError)) {
      const described = describeError(accessSaveError);
      contentWrap.appendChild(
        createStatePanel({
          state: hubStateForError(accessSaveError),
          titleTag: 'h3',
          title: described.title,
          description: formatErrorDescription(described),
          details: described.technical,
          action: {
            label: 'Повторить',
            onActivate: () => {
              void saveAccessFlow();
            },
          },
        }),
      );
    }

    if (accessSaved && activeRouterId) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.SUCCESS, title: 'Доступ сохранён' }),
      );

      const hostKeySection = document.createElement('section');
      hostKeySection.className = 'hub-connection__host-key';
      const hostKeyTitle = document.createElement('h3');
      hostKeyTitle.className = 'hub-connection__section-title';
      hostKeyTitle.textContent = 'Отпечаток устройства';
      hostKeySection.appendChild(hostKeyTitle);

      const warnBanner = document.createElement('div');
      warnBanner.className = 'hub-connection__info-banner';
      const warnIcon = document.createElement('span');
      warnIcon.className = 'hub-connection__info-icon';
      warnIcon.appendChild(createIcon('alert', { size: 20 }));
      warnBanner.appendChild(warnIcon);
      const warnText = document.createElement('p');
      warnText.className = 'hub-connection__info-text';
      warnText.textContent = FINGERPRINT_WARNING;
      warnBanner.appendChild(warnText);
      hostKeySection.appendChild(warnBanner);

      const learnBtn = createButton({
        label: learnedHostKey ? 'Получить отпечаток снова' : 'Получить отпечаток',
        variant: 'secondary',
        busy: learningHostKey,
        onActivate: () => {
          void learnHostKeyFlow();
        },
      });
      updateButtonBusyState(learnBtn, learningHostKey, offline);
      hostKeySection.appendChild(learnBtn);

      if (learningHostKey) {
        hostKeySection.appendChild(
          createInlineState({ state: HubState.CONNECTING, title: 'Запрашиваем отпечаток устройства' }),
        );
      }

      if (hostKeyError && !isAborted(hostKeyError)) {
        const described = describeError(hostKeyError);
        hostKeySection.appendChild(
          createStatePanel({
            state: hubStateForError(hostKeyError),
            titleTag: 'h3',
            title: described.title,
            description: formatErrorDescription(described),
            details: described.technical,
            action: {
              label: 'Повторить',
              onActivate: () => {
                void learnHostKeyFlow();
              },
            },
          }),
        );
      }

      if (learnedHostKey) {
        const fpBlock = document.createElement('div');
        fpBlock.className = 'hub-connection__fingerprint';
        const fpLabel = document.createElement('p');
        fpLabel.className = 'hub-connection__fingerprint-label';
        fpLabel.textContent = 'Значение отпечатка:';
        fpBlock.appendChild(fpLabel);
        const fpValue = document.createElement('code');
        fpValue.className = 'hub-connection__fingerprint-value';
        fpValue.textContent = learnedHostKey.fingerprint;
        fpBlock.appendChild(fpValue);
        hostKeySection.appendChild(fpBlock);
        hostKeySection.appendChild(
          createTechnicalDetails({ content: `Тип ключа: ${learnedHostKey.algorithm}` }),
        );

        const confirmBtn = createButton({
          label: 'Да, это мой роутер',
          busy: confirmingHostKey,
          onActivate: () => {
            void confirmHostKeyFlow(false);
          },
        });
        updateButtonBusyState(confirmBtn, confirmingHostKey, offline);
        hostKeySection.appendChild(confirmBtn);
      }

      if (confirmingHostKey) {
        hostKeySection.appendChild(
          createInlineState({ state: HubState.CONNECTING, title: 'Подтверждаем отпечаток устройства' }),
        );
      }

      if (confirmHostKeyError && !isAborted(confirmHostKeyError)) {
        const described = describeError(confirmHostKeyError);
        hostKeySection.appendChild(
          createStatePanel({
            state: hubStateForError(confirmHostKeyError),
            titleTag: 'h3',
            title: described.title,
            description: formatErrorDescription(described),
            details: described.technical,
            action: {
              label: 'Повторить',
              onActivate: () => {
                void confirmHostKeyFlow(false);
              },
            },
          }),
        );
      }

      if (getSession().hostKeyConfirmed) {
        hostKeySection.appendChild(
          createInlineState({ state: HubState.SUCCESS, title: 'Отпечаток устройства подтверждён' }),
        );
      }

      contentWrap.appendChild(hostKeySection);
    }
  }

  function renderChecklistItem(item) {
    const row = document.createElement('li');
    row.className = 'hub-connection__checklist-item';
    if (!item.supported) {
      row.classList.add('hub-connection__checklist-item--unsupported');
    }
    row.classList.add(`hub-connection__checklist-item--${item.tone}`);

    const iconWrap = document.createElement('span');
    iconWrap.className = 'hub-connection__checklist-icon';
    /** @type {string} */
    let iconName = 'info';
    if (item.supported) {
      if (item.tone === 'success') {
        iconName = 'check';
      } else if (item.tone === 'danger') {
        iconName = 'alert';
      } else {
        iconName = 'info';
      }
    }
    iconWrap.appendChild(createIcon(iconName, { size: 20 }));
    row.appendChild(iconWrap);

    const labelEl = document.createElement('span');
    labelEl.className = 'hub-connection__checklist-label';
    labelEl.textContent = item.label;
    row.appendChild(labelEl);

    const valueEl = document.createElement('span');
    valueEl.className = 'hub-connection__checklist-value';
    valueEl.textContent = item.text;
    row.appendChild(valueEl);

    return row;
  }

  function renderVerifyStep() {
    const session = getSession();

    if (isConnectionRestorePending(session)) {
      const pendingState = createInlineState({
        state: HubState.LOADING,
        title: 'Проверяем сохранённое подключение на сервере',
      });
      pendingState.setAttribute('aria-live', 'polite');
      contentWrap.appendChild(pendingState);
      return;
    }

    if (isConnectionRestoreFailed(session)) {
      contentWrap.appendChild(renderConnectionRestoreFailedPanel());
      return;
    }

    if (offline && !recovering) {
      contentWrap.appendChild(
        createStatePanel({
          state: HubState.NO_INTERNET,
          titleTag: 'h2',
          action: {
            label: 'Повторить',
            onActivate: () => {
              void runHealthCheckFlow();
            },
          },
        }),
      );
      return;
    }

    if (recovering) {
      contentWrap.appendChild(
        createInlineState({ state: HubState.RECOVERING, title: 'Восстанавливаем связь с сервером управления' }),
      );
    }

    const routerHost = session.routerHost ?? accessHost;
    const effectiveHealth = getEffectiveHealth(session);
    const effectiveHealthError = getEffectiveHealthError(session);
    const hostKeyBadge = deriveVerifyHostKeyBadge({
      hostKeyConfirmed: session.hostKeyConfirmed,
      health: effectiveHealth,
    });

    const routerCard = document.createElement('article');
    routerCard.className = 'hub-connection__router-card';

    const routerIcon = document.createElement('span');
    routerIcon.className = 'hub-connection__router-icon';
    routerIcon.appendChild(createIcon('router', { size: 32 }));
    routerCard.appendChild(routerIcon);

    const routerMain = document.createElement('div');
    routerMain.className = 'hub-connection__router-main';

    const routerName = document.createElement('h2');
    routerName.className = 'hub-connection__router-name';
    routerName.id = stepTitleId(ConnectionStep.VERIFY);
    routerName.tabIndex = -1;
    routerName.textContent = 'Роутер управления';
    routerMain.appendChild(routerName);

    const statusBadge = createBadge({
      label: hostKeyBadge.label,
      tone: hostKeyBadge.tone,
    });
    routerMain.appendChild(statusBadge);

    const routerMeta = document.createElement('div');
    routerMeta.className = 'hub-connection__router-meta';

    const addressItem = document.createElement('span');
    addressItem.className = 'hub-connection__router-meta-item';
    addressItem.appendChild(createIcon('connection', { size: 16 }));
    const addressText = document.createElement('span');
    addressText.textContent = routerHost || 'Адрес не указан';
    addressItem.appendChild(addressText);
    routerMeta.appendChild(addressItem);

    const manageItem = document.createElement('span');
    manageItem.className = 'hub-connection__router-meta-item';
    manageItem.appendChild(createIcon('settings', { size: 16 }));
    const manageText = document.createElement('span');
    manageText.textContent = describeManagementAvailability(effectiveHealth?.writes_allowed);
    manageItem.appendChild(manageText);
    routerMeta.appendChild(manageItem);

    routerMain.appendChild(routerMeta);
    routerCard.appendChild(routerMain);

    const routerActions = document.createElement('div');
    routerActions.className = 'hub-connection__router-actions';
    const changeBtn = createButton({
      label: 'Сменить роутер',
      variant: 'secondary',
      onActivate: () => {
        openChangeRouterModal();
      },
    });
    routerActions.appendChild(changeBtn);
    routerCard.appendChild(routerActions);

    contentWrap.appendChild(routerCard);

    const pinDetails = renderServerPinDetails(session);
    if (pinDetails) {
      contentWrap.appendChild(pinDetails);
    }

    if (needsManagementUsernameRecovery(session)) {
      contentWrap.appendChild(renderManagementUsernameRecovery());
      return;
    }

    const checkCard = createCard({ title: 'Проверка соединения', titleTag: 'h3' });
    const checkBody = checkCard.querySelector('.hub-card__body') ?? checkCard;

    if (checkingHealth) {
      checkBody.appendChild(
        createInlineState({ state: HubState.CONNECTING, title: 'Проверяем связь с роутером' }),
      );
    }

    if (effectiveHealthError) {
      const described = describeError(effectiveHealthError);
      checkBody.appendChild(
        createStatePanel({
          state: hubStateForLoadError(effectiveHealthError, offline),
          titleTag: 'h3',
          title: described.title,
          description: formatErrorDescription(described),
          details: described.technical,
          action: {
            label: 'Повторить',
            onActivate: () => {
              void runHealthCheckFlow();
            },
          },
        }),
      );
    }

    if (effectiveHealth != null) {
      const checklist = buildConnectionChecklist(effectiveHealth);
      const list = document.createElement('ul');
      list.className = 'hub-connection__checklist';
      list.setAttribute('role', 'list');
      for (const item of checklist) {
        list.appendChild(renderChecklistItem(item));
      }
      checkBody.appendChild(list);
    }

    const recheckBtn = createButton({
      label: 'Проверить снова',
      variant: 'secondary',
      iconName: 'refresh',
      busy: checkingHealth,
      onActivate: () => {
        void runHealthCheckFlow();
      },
    });
    updateButtonBusyState(recheckBtn, checkingHealth, offline);
    checkBody.appendChild(recheckBtn);
    contentWrap.appendChild(checkCard);

    if (ctx.runtime?.adapterMode === 'live' && isLiveDeviceReady(effectiveHealth, session.hostKeyConfirmed)) {
      contentWrap.appendChild(createInlineState({ state: HubState.LIVE_DEVICE }));
    }

    if (healthCheckCancelled && !checkingHealth && effectiveHealth == null && !effectiveHealthError) {
      contentWrap.appendChild(
        createStatePanel({
          state: HubState.EMPTY,
          titleTag: 'h3',
          title: 'Проверка отменена',
          description: 'Повторная проверка не завершилась — нажмите «Проверить снова», чтобы продолжить.',
        }),
      );
    }

    if (effectiveHealth == null && !checkingHealth && !effectiveHealthError && !healthCheckCancelled) {
      contentWrap.appendChild(
        createStatePanel({
          state: HubState.EMPTY,
          titleTag: 'h3',
          title: 'Проверка ещё не запускалась',
          description: 'Нажмите «Проверить снова», чтобы начать проверку связи.',
        }),
      );
    }
  }

  function renderFooter() {
    clearElement(footerLeft);
    clearElement(footerRight);

    if (currentStep === ConnectionStep.SEARCH) {
      const manualLink = document.createElement('button');
      manualLink.type = 'button';
      manualLink.className = 'hub-connection__manual-link';
      manualLink.textContent = 'Настроить вручную';
      manualLink.addEventListener('click', () => {
        manualMode = true;
        pendingFocus = { kind: 'element-id', id: 'hub-connection-manual-host' };
        renderAll();
      });
      footerLeft.appendChild(manualLink);
      const canProceed = manualMode
        ? validateManualHost(manualHostValue).valid
        : selectedTarget != null && selectedTarget.host.length > 0;
      const nextReasonId = 'hub-connection-next-reason';
      /** @type {string|null} */
      let nextReasonText = null;
      if (offline) {
        nextReasonText = 'Нет связи с сервером управления — дождитесь восстановления сети';
      } else if (!canProceed) {
        nextReasonText = manualMode
          ? 'Укажите корректный адрес роутера'
          : 'Выберите адрес из списка или включите ручной ввод';
      }
      if (nextReasonText) {
        const reasonEl = document.createElement('p');
        reasonEl.id = nextReasonId;
        reasonEl.className = 'hub-connection__next-reason';
        reasonEl.textContent = nextReasonText;
        footerRight.appendChild(reasonEl);
      }
      const nextBtn = createButton({
        label: 'Далее',
        disabled: !canProceed || offline,
        onActivate: () => {
          if (manualMode) {
            const validation = validateManualHost(manualHostValue);
            if (!validation.valid) {
              accessErrors = validation.errors;
              pendingFocus = { kind: 'first-field-error' };
              renderAll();
              return;
            }
            const previousHost = selectedTarget?.host ?? null;
            selectedTarget = {
              host: manualHostValue.trim(),
              port: null,
              sourceAddress: null,
              routerId: null,
            };
            accessHost = manualHostValue.trim();
            if (accessSaved && previousHost !== accessHost) {
              syncAccessPasswordFromDom();
              if (!accessPassword) {
                accessPasswordReentryNote = true;
              }
              onAccessTargetChanged();
            }
          }
          setMaxReachableStep(ConnectionStep.ACCESS);
          goToStep(ConnectionStep.ACCESS);
        },
      });
      nextBtn.id = SEARCH_NEXT_BTN_ID;
      if (nextReasonText) {
        nextBtn.setAttribute('aria-describedby', nextReasonId);
      }
      footerRight.appendChild(nextBtn);
      return;
    }

    if (currentStep === ConnectionStep.ACCESS) {
      footerLeft.appendChild(
        createButton({
          label: 'Назад к поиску',
          variant: 'ghost',
          onActivate: () => {
            goToStep(ConnectionStep.SEARCH);
          },
        }),
      );
      return;
    }

    if (currentStep === ConnectionStep.VERIFY) {
      footerLeft.appendChild(
        createButton({
          label: 'Назад к доступу',
          variant: 'ghost',
          onActivate: () => {
            goToStep(ConnectionStep.ACCESS);
          },
        }),
      );

      const session = getSession();
      const gate = evaluateFinishGate({
        health: getEffectiveHealth(session),
        hostKeyConfirmed: session.hostKeyConfirmed,
        adapterMode: ctx.runtime?.adapterMode ?? null,
      });

      const finishReasonId = 'hub-connection-finish-reason';
      if (!gate.allowed && gate.reasonText) {
        const reasonEl = document.createElement('p');
        reasonEl.id = finishReasonId;
        reasonEl.className = 'hub-connection__finish-reason';
        reasonEl.textContent = gate.reasonText;
        footerRight.appendChild(reasonEl);
      }

      if (gate.mock) {
        footerRight.appendChild(createBadge({ tone: 'neutral', label: 'Демо-режим' }));
      }

      const finishBtn = createButton({
        label: 'Завершить настройку',
        size: 'lg',
        disabled: !gate.allowed || offline,
        onActivate: () => {
          if (!gate.allowed) {
            return;
          }
          ctx.navigate('overview');
        },
      });
      if (!gate.allowed && gate.reasonText) {
        finishBtn.setAttribute('aria-describedby', finishReasonId);
      }
      footerRight.appendChild(finishBtn);
    }
  }

  function renderContent() {
    clearElement(contentWrap);
    if (currentStep === ConnectionStep.SEARCH) {
      renderSearchStep();
    } else if (currentStep === ConnectionStep.ACCESS) {
      renderAccessStep();
    } else {
      renderVerifyStep();
    }
  }

  function renderAll() {
    if (disposed) {
      return;
    }
    renderStepper();
    renderContent();
    renderInfoNote();
    renderFooter();
    restorePendingFocus();
  }

  function openHostKeyConflictModal(conflict) {
    const body = document.createElement('div');
    body.className = 'hub-connection__conflict-body';

    const explain = document.createElement('p');
    explain.textContent = conflict.text;
    body.appendChild(explain);

    if (conflict.existingFingerprint) {
      const existingLabel = document.createElement('p');
      existingLabel.className = 'hub-connection__fingerprint-label';
      existingLabel.textContent = 'Сохранённый отпечаток:';
      body.appendChild(existingLabel);
      const existingVal = document.createElement('code');
      existingVal.className = 'hub-connection__fingerprint-value';
      existingVal.textContent = conflict.existingFingerprint;
      body.appendChild(existingVal);
    }

    if (conflict.candidateFingerprint) {
      const candidateLabel = document.createElement('p');
      candidateLabel.className = 'hub-connection__fingerprint-label';
      candidateLabel.textContent = 'Текущий отпечаток:';
      body.appendChild(candidateLabel);
      const candidateVal = document.createElement('code');
      candidateVal.className = 'hub-connection__fingerprint-value';
      candidateVal.textContent = conflict.candidateFingerprint;
      body.appendChild(candidateVal);
    }

    /** @type {{ close: () => void }|null} */
    let modalRef = null;

    const cancelBtn = createButton({
      label: 'Отмена',
      variant: 'ghost',
      onActivate: () => {
        modalRef?.close();
      },
    });

    const replaceBtn = createButton({
      label: 'Заменить отпечаток',
      variant: 'danger',
      onActivate: () => {
        modalRef?.close();
        void confirmHostKeyFlow(true);
      },
    });

    modalRef = registerModal(openModal({
      title: 'Отпечаток устройства не совпадает',
      description: 'Подтверждайте замену только если роутер действительно меняли.',
      body,
      tone: 'danger',
      actions: [cancelBtn, replaceBtn],
    }));
  }

  function openChangeRouterModal() {
    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    const cancelBtn = createButton({
      label: 'Отмена',
      variant: 'ghost',
      onActivate: () => {
        modalRef?.close();
      },
    });
    const confirmBtn = createButton({
      label: 'Сменить роутер',
      variant: 'danger',
      onActivate: () => {
        resetRouterBinding();
      },
    });
    modalRef = registerModal(openModal({
      title: 'Сменить роутер?',
      description:
        'Текущая привязка и подтверждение отпечатка будут сброшены — шаги подключения нужно пройти заново. Сохранённый доступ на сервере управления при этом не отзывается.',
      tone: 'danger',
      actions: [cancelBtn, confirmBtn],
    }));
  }

  function resetRouterBinding() {
    cancelConnectionContextRestore();
    invalidateAllOperations();
    closeAllModals();
    updateSession({
      routerId: null,
      routerHost: null,
      hostKeyConfirmed: false,
      liveReady: false,
      usernameAvailable: false,
      connectionRestoreState: 'done',
      wifiLive: {
        host: null,
        username: null,
        credentialRefId: null,
        sshHostKeySha256: null,
      },
    });
    activeRouterId = null;
    accessSaved = false;
    learnedHostKey = null;
    hostKeyError = null;
    confirmHostKeyError = null;
    accessSaveError = null;
    healthSnapshot = null;
    healthErrorSnapshot = null;
    healthCheckCancelled = false;
    discoveryView = null;
    discoveryError = null;
    selectedTarget = null;
    manualMode = false;
    manualHostValue = '';
    groupPortByHost = {};
    accessHost = '';
    accessUsername = '';
    accessPassword = '';
    accessFormDirty = false;
    accessIdempotencyKey = null;
    accessErrors = [];
    recovering = false;
    maxReachableStep = ConnectionStep.SEARCH;
    currentStep = ConnectionStep.SEARCH;
    pendingFocus = { kind: 'element-id', id: 'hub-connection-find-btn' };
    renderAll();
  }

  async function runDiscoveryFlow() {
    if (disposed || searching || offline) {
      return;
    }
    recovering = false;
    const gen = ++generation;
    abortDiscovery();
    discoveryAbort = new AbortController();
    const myController = discoveryAbort;
    searching = true;
    searchingGeneration = gen;
    discoveryError = null;
    initialLoading = false;
    renderAll();

    try {
      const response = await runDiscovery(discoveryAbort.signal);
      if (disposed || gen !== generation) {
        return;
      }
      discoveryView = describeDiscovery(response, { adapterMode: ctx.runtime?.adapterMode ?? null });
      if (discoveryView.candidates.length === 1) {
        const only = discoveryView.candidates[0];
        const port = groupPortByHost[only.host] ?? only.port;
        const endpoint = resolveGroupEndpoint(only, port);
        selectedTarget = {
          host: only.host,
          port: endpoint.port,
          sourceAddress: endpoint.sourceAddress,
          routerId: endpoint.routerId,
        };
        accessHost = only.host;
        if (!manualMode) {
          setMaxReachableStep(ConnectionStep.ACCESS);
          goToStep(ConnectionStep.ACCESS);
        }
      }
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return;
      }
      discoveryError = error;
      discoveryView = null;
    } finally {
      if (searchingGeneration === gen) {
        searching = false;
        searchingGeneration = null;
      }
      clearRecovering();
      if (discoveryAbort === myController) {
        discoveryAbort = null;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
  }

  async function saveAccessFlow() {
    if (disposed || savingAccess || offline) {
      return;
    }
    recovering = false;
    const validation = validateAccessForm({
      host: accessHost,
      username: accessUsername,
      password: accessPassword,
    });
    if (!validation.valid) {
      accessErrors = validation.errors;
      pendingFocus = { kind: 'first-field-error' };
      renderAll();
      return;
    }
    accessErrors = [];

    cancelConnectionContextRestore();

    const gen = ++generation;
    abortAccess();
    accessAbort = new AbortController();
    const myController = accessAbort;
    savingAccess = true;
    savingAccessGeneration = gen;
    accessSaveError = null;
    renderAll();

    const idempotencyKey = ensureAccessIdempotencyKey();
    const body = buildDraftBody({
      host: accessHost,
      username: accessUsername,
      password: accessPassword,
    });

    let chainLearnHostKey = false;
    try {
      const response = /** @type {{ router_id?: string, credential_ref_id?: string, username?: string }} */ (
        await createDraftRouter({
          body,
          idempotencyKey,
          signal: accessAbort.signal,
        })
      );
      if (disposed || gen !== generation) {
        return;
      }
      const routerId = response?.router_id ?? null;
      const credentialRefId = response?.credential_ref_id ?? null;
      if (!routerId || !credentialRefId) {
        throw new HubApiError({
          code: 'client.unknown',
          httpStatus: null,
          userMessage: 'Сервер вернул неполный ответ при сохранении доступа.',
          userAction: 'Повторите попытку.',
          serverMessage: null,
          details: [],
          requestId: null,
          correlationId: null,
          kind: ERROR_KIND.UNKNOWN,
        });
      }

      activeRouterId = routerId;
      accessSaved = true;
      setMaxReachableStep(ConnectionStep.ACCESS);
      accessPassword = '';
      accessPasswordReentryNote = false;
      const pwdEl = document.getElementById('hub-connection-access-password');
      if (pwdEl instanceof HTMLInputElement) {
        pwdEl.value = '';
      }
      accessFormDirty = false;
      accessIdempotencyKey = null;
      learnedHostKey = null;
      hostKeyError = null;
      confirmHostKeyError = null;

      updateSession({
        routerId,
        routerHost: accessHost.trim(),
        hostKeyConfirmed: false,
        liveReady: false,
        usernameAvailable: false,
        pinnedAt: null,
        pinnedEndpointPort: null,
        wifiLive: {
          host: accessHost.trim(),
          username: accessUsername.trim(),
          credentialRefId,
          sshHostKeySha256: null,
        },
      });
      chainLearnHostKey = true;
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return;
      }
      accessSaveError = error;
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
    } finally {
      if (savingAccessGeneration === gen) {
        savingAccess = false;
        savingAccessGeneration = null;
      }
      clearRecovering();
      if (accessAbort === myController) {
        accessAbort = null;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
    if (chainLearnHostKey && !disposed && gen === generation && !offline) {
      void learnHostKeyFlow();
    }
  }

  async function learnHostKeyFlow() {
    if (disposed || learningHostKey || offline || !activeRouterId) {
      return;
    }
    recovering = false;
    const gen = ++generation;
    abortLearnHostKey();
    learnHostKeyAbort = new AbortController();
    const myController = learnHostKeyAbort;
    learningHostKey = true;
    learningHostKeyGeneration = gen;
    learnedHostKey = null;
    hostKeyError = null;
    confirmHostKeyError = null;
    updateSession({
      hostKeyConfirmed: false,
      wifiLive: { sshHostKeySha256: null },
    });
    renderAll();

    try {
      const response = /** @type {{ fingerprint_sha256?: string, algorithm?: string }} */ (
        await learnHostKey({
          routerId: activeRouterId,
          host: accessHost.trim(),
          port: selectedTarget?.port ?? undefined,
          sourceAddress: selectedTarget?.sourceAddress,
          signal: learnHostKeyAbort.signal,
        })
      );
      if (disposed || gen !== generation) {
        return;
      }
      const fingerprint = formatFingerprint(response?.fingerprint_sha256 ?? '');
      const algorithm = typeof response?.algorithm === 'string' ? response.algorithm : '';
      if (!fingerprint || !algorithm) {
        throw new HubApiError({
          code: 'client.unknown',
          httpStatus: null,
          userMessage: 'Не удалось прочитать отпечаток устройства из ответа сервера.',
          userAction: 'Повторите запрос.',
          serverMessage: null,
          details: [],
          requestId: null,
          correlationId: null,
          kind: ERROR_KIND.UNKNOWN,
        });
      }
      learnedHostKey = { fingerprint, algorithm };
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return;
      }
      hostKeyError = error;
      learnedHostKey = null;
    } finally {
      if (learningHostKeyGeneration === gen) {
        learningHostKey = false;
        learningHostKeyGeneration = null;
      }
      clearRecovering();
      if (learnHostKeyAbort === myController) {
        learnHostKeyAbort = null;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
  }

  async function confirmHostKeyFlow(allowOverwrite) {
    if (disposed || confirmingHostKey || offline || !activeRouterId || !learnedHostKey) {
      return;
    }
    recovering = false;
    const gen = ++generation;
    abortConfirmHostKey();
    confirmHostKeyAbort = new AbortController();
    const myController = confirmHostKeyAbort;
    confirmingHostKey = true;
    confirmingHostKeyGeneration = gen;
    confirmHostKeyError = null;
    renderAll();

    try {
      await confirmHostKey({
        routerId: activeRouterId,
        fingerprintSha256: learnedHostKey.fingerprint,
        algorithm: learnedHostKey.algorithm,
        allowOverwrite,
        signal: confirmHostKeyAbort.signal,
      });
      if (disposed || gen !== generation) {
        return;
      }
      updateSession({
        hostKeyConfirmed: true,
        wifiLive: { sshHostKeySha256: learnedHostKey.fingerprint },
      });
      hostKeyError = null;
      confirmHostKeyError = null;
      setMaxReachableStep(ConnectionStep.VERIFY);
      goToStep(ConnectionStep.VERIFY);
      void runHealthCheckFlow();
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return;
      }
      const conflict = describeHostKeyConflict(error);
      if (conflict && !allowOverwrite) {
        openHostKeyConflictModal(conflict);
        return;
      }
      confirmHostKeyError = error;
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
    } finally {
      if (confirmingHostKeyGeneration === gen) {
        confirmingHostKey = false;
        confirmingHostKeyGeneration = null;
      }
      clearRecovering();
      if (confirmHostKeyAbort === myController) {
        confirmHostKeyAbort = null;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
  }

  async function runHealthCheckFlow() {
    if (disposed || checkingHealth || offline) {
      return;
    }
    const session = getSession();
    if (!session.routerId && !activeRouterId) {
      return;
    }
    const bindingAtCheckStart = getCurrentHealthBinding(session);
    recovering = false;
    const gen = ++generation;
    abortHealth();
    healthAbort = new AbortController();
    const myController = healthAbort;
    checkingHealth = true;
    checkingHealthGeneration = gen;
    healthErrorSnapshot = null;
    healthCheckCancelled = false;
    renderAll();

    try {
      const result = await checkConnectionHealth({
        routerId: session.routerId ?? activeRouterId,
        host: session.routerHost ?? accessHost,
        sourceAddress: selectedTarget?.sourceAddress,
        credentialRefId: session.wifiLive.credentialRefId,
        sshHostKeySha256: session.wifiLive.sshHostKeySha256,
        probe: true,
        signal: healthAbort.signal,
      });
      if (disposed || gen !== generation) {
        return;
      }
      healthSnapshot = {
        binding: bindingAtCheckStart,
        data: result,
      };
    } catch (error) {
      if (disposed || gen !== generation) {
        return;
      }
      if (isAborted(error)) {
        healthCheckCancelled = true;
        healthErrorSnapshot = null;
        healthSnapshot = null;
        return;
      }
      healthErrorSnapshot = {
        binding: bindingAtCheckStart,
        error,
      };
      healthSnapshot = null;
    } finally {
      if (checkingHealthGeneration === gen) {
        checkingHealth = false;
        checkingHealthGeneration = null;
        initialLoading = false;
      }
      clearRecovering();
      if (healthAbort === myController) {
        healthAbort = null;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
  }

  const unsubConnectivity = subscribeConnectivity((online) => {
    if (disposed) {
      return;
    }
    if (!online) {
      offline = true;
      recovering = false;
      renderAll();
      return;
    }
    offline = false;
    recovering = true;
    renderAll();
    if (currentStep === ConnectionStep.VERIFY && activeRouterId) {
      void runHealthCheckFlow();
    } else if (currentStep === ConnectionStep.SEARCH && discoveryView == null) {
      void runDiscoveryFlow();
    } else {
      recovering = false;
      renderAll();
    }
  });

  let trackedLiveCapabilityKey = liveCapabilitySubscriptionKey(sessionSnapshot);
  let restoreWasPending = isConnectionRestorePending(sessionSnapshot);

  /**
   * @param {import('../core/session.js').SessionSnapshot} snapshot
   */
  function syncAfterConnectionRestoreSettled(snapshot) {
    initialLoading = false;

    if (isConnectionRestoreFailed(snapshot)) {
      renderAll();
      return;
    }

    if (snapshot.routerId) {
      if (!activeRouterId) {
        activeRouterId = snapshot.routerId;
        accessSaved = Boolean(snapshot.wifiLive?.credentialRefId);
      }
      const host = snapshot.routerHost ?? snapshot.wifiLive?.host ?? '';
      if (host) {
        accessHost = host;
        selectedTarget = {
          host,
          port: snapshot.pinnedEndpointPort,
          sourceAddress: snapshot.sourceAddress,
          routerId: snapshot.routerId,
        };
      }
      accessUsername = snapshot.wifiLive?.username ?? accessUsername;

      if (needsManagementUsernameRecovery(snapshot)) {
        setMaxReachableStep(ConnectionStep.VERIFY);
        if (currentStep !== ConnectionStep.VERIFY) {
          goToStep(ConnectionStep.VERIFY);
        } else {
          renderAll();
        }
        return;
      }

      if (snapshot.hostKeyConfirmed && snapshot.liveReady) {
        setMaxReachableStep(ConnectionStep.VERIFY);
        if (currentStep !== ConnectionStep.VERIFY) {
          currentStep = ConnectionStep.VERIFY;
        }
        renderAll();
        if (!checkingHealth) {
          void runHealthCheckFlow();
        }
        return;
      }

      const targetStep = snapshot.hostKeyConfirmed ? ConnectionStep.VERIFY : ConnectionStep.ACCESS;
      setMaxReachableStep(targetStep);
      if (currentStep === ConnectionStep.SEARCH) {
        goToStep(targetStep);
      } else {
        renderAll();
      }
      return;
    }

    if (currentStep === ConnectionStep.SEARCH && !searching) {
      void runDiscoveryFlow();
    } else {
      renderAll();
    }
  }

  const unsubSession = subscribeSession((snapshot) => {
    if (disposed) {
      return;
    }
    const pendingNow = isConnectionRestorePending(snapshot);
    const restoreJustSettled = restoreWasPending && !pendingNow;
    restoreWasPending = pendingNow;

    const nextKey = liveCapabilitySubscriptionKey(snapshot);
    if (nextKey === trackedLiveCapabilityKey && !restoreJustSettled) {
      return;
    }
    trackedLiveCapabilityKey = nextKey;

    if (restoreJustSettled) {
      syncAfterConnectionRestoreSettled(snapshot);
      return;
    }

    if (snapshot.routerId && !activeRouterId) {
      activeRouterId = snapshot.routerId;
      accessSaved = Boolean(snapshot.wifiLive.credentialRefId);
    }

    if (needsManagementUsernameRecovery(snapshot)) {
      setMaxReachableStep(ConnectionStep.VERIFY);
      if (currentStep !== ConnectionStep.VERIFY) {
        goToStep(ConnectionStep.VERIFY);
      } else {
        renderAll();
      }
      return;
    }

    if (
      currentStep === ConnectionStep.VERIFY
      && snapshot.liveReady
      && snapshot.hostKeyConfirmed
      && !checkingHealth
    ) {
      void runHealthCheckFlow();
      return;
    }

    renderAll();
  });

  renderAll();

  if (
    sessionSnapshot.routerId
    && sessionSnapshot.hostKeyConfirmed
    && sessionSnapshot.liveReady
  ) {
    void runHealthCheckFlow();
  } else if (
    sessionSnapshot.routerId
    && sessionSnapshot.hostKeyConfirmed
    && needsManagementUsernameRecovery(sessionSnapshot)
  ) {
    setMaxReachableStep(ConnectionStep.VERIFY);
    currentStep = ConnectionStep.VERIFY;
    renderAll();
  } else if (!sessionSnapshot.routerId && !isConnectionRestorePending(sessionSnapshot)) {
    initialLoading = true;
    void runDiscoveryFlow();
  }

  return () => {
    disposed = true;
    invalidateAllOperations();
    closeAllModals();
    unsubConnectivity();
    unsubSession();
  };
}
