import {
  createButton,
  createCard,
  createSelectField,
  createTechnicalDetails,
  createTextField,
  openModal,
} from '../components/index.js';
import { subscribeConnectivity } from '../core/api.js';
import { syncActionButtonById } from '../core/form-submit-sync.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import { getSession, isConnectionRestorePending, subscribeSession } from '../core/session.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
  getStateDescriptor,
} from '../core/states.js';
import {
  buildLiveConnectionParams,
  describeLiveConnectionAdvancedStatus,
  isConnectionRestoreFailed,
  liveCapabilitySubscriptionKey,
  needsManagementUsernameRecovery,
} from '../features/live-connection-params.js';
import {
  mountInternetSourceAffordance,
} from '../features/internet-source-block.js';
import { fetchRouterInternetObserve } from '../features/diagnostics-model.js';
import {
  UPLINK_WIFI_DISTINCTION_NOTE,
  UPLINK_WIFI_NO_OPEN_NETWORK_NOTE,
  UPLINK_WIFI_PASSWORD_FIELD_NOTE,
  UPLINK_WIFI_SCAN_NOTE,
  UPLINK_WIFI_SETTLE_WAIT_NOTE,
  UPLINK_WIFI_INTENT_STALE_MESSAGE,
  UPLINK_WIFI_OPEN_NETWORK_BLOCKED_MESSAGE,
  applyUplinkWifiConnection,
  buildStationPreviewBody,
  buildUplinkIntentSnapshot,
  buildUplinkWifiScreenState,
  deactivateRememberedUplink,
  evaluateUplinkWifiMutationReadiness,
  fetchRememberedUplink,
  formatSurveyNetworkLabel,
  parseUplinkApplyVerdict,
  persistRememberedUplinkAfterApply,
  previewUplinkWifiConnection,
  registerUplinkWifiCredential,
  revokeWifiApCredential,
  scanUplinkWifiNetworks,
  teardownUplinkWifiConnection,
  uplinkIntentMatchesCurrent,
  validateUplinkWifiForm,
} from '../features/uplink-wifi-model.js';
import { buildRiskModalBody, createWifiDemoBanner, updateButtonBusyState } from '../features/wifi-screen-parts.js';

export const meta = {
  id: 'internet-uplink',
  title: 'Интернет',
  iconName: 'connection',
};

/** @typedef {'connect'|'teardown'} UplinkRiskAction */

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isAborted(err) {
  if (err instanceof HubApiError && err.code === 'client.aborted') return true;
  return err instanceof DOMException && err.name === 'AbortError';
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
 * @param {HTMLElement} container
 * @param {{ runtime: object, navigate: (routeId: string) => void, showToast: (options: object) => void }} ctx
 * @returns {() => void}
 */
export function render(container, ctx) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  const adapterMode = ctx.runtime?.adapterMode ?? null;

  let generation = 0;
  let disposed = false;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;
  let recovering = false;

  /** @type {AbortController|null} */
  let scanAbort = null;
  /** @type {AbortController|null} */
  let prepareAbort = null;
  /** @type {AbortController|null} */
  let mutateAbort = null;

  let scanning = false;
  let preparing = false;
  let mutating = false;
  let riskModalOpen = false;
  let advancedOpen = false;

  /** @type {import('../features/uplink-wifi-model.js').ParsedSurveyNetwork[]} */
  let scanResults = [];
  /** @type {import('../features/uplink-wifi-model.js').ParsedSurveyNetwork|null} */
  let selectedNetwork = null;
  /** @type {unknown|null} */
  let scanError = null;

  /** @type {{ ssid: string, band: import('../features/uplink-wifi-model.js').UplinkWifiBand, password: string }} */
  let draft = { ssid: '', band: 'BAND_2_4GHZ', password: '' };
  /** @type {string|null} */
  let credentialRefId = null;
  /** @type {string[]} */
  let formErrors = [];
  /** @type {unknown|null} */
  let operationError = null;
  /** @type {(() => void)|null} */
  let operationRetry = null;
  /** @type {import('../features/uplink-wifi-model.js').UplinkApplyVerdict|null} */
  let lastVerdict = null;

  /** @type {import('../features/diagnostics-model.js').RouterInternetObservePayload|null} */
  let internetObservation = null;
  /** @type {import('../features/uplink-wifi-model.js').RememberedUplinkPreference|null} */
  let rememberedUplink = null;
  let loadingInternetSource = false;
  /** @type {unknown|null} */
  let internetSourceError = null;

  /** @type {ReturnType<typeof mountInternetSourceAffordance>|null} */
  let sourceAffordance = null;
  let lastSourceSignature = '';
  let lastVerdictSignature = '';
  let lastContentSignature = '';
  let lastFooterSignature = '';
  let layoutMounted = false;

  /** @type {{ kind: 'element-id', id: string }|null} */
  let pendingFocus = null;

  /** @type {AbortController|null} */
  let observeAbort = null;

  /** @type {Array<{ close: () => void }>} */
  let openModals = [];

  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-internet-uplink';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.id = 'hub-internet-uplink-screen-title';
  title.tabIndex = -1;
  title.textContent = 'Интернет';
  header.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent = 'Подключение роутера к внешней Wi‑Fi сети';
  header.appendChild(subtitle);
  screen.appendChild(header);

  const sourceStatusSlot = document.createElement('div');
  sourceStatusSlot.className = 'hub-internet-uplink__source-slot';
  screen.appendChild(sourceStatusSlot);

  const verdictSlot = document.createElement('div');
  verdictSlot.className = 'hub-wifi__verdict-slot';
  screen.appendChild(verdictSlot);

  const contentWrap = document.createElement('div');
  contentWrap.className = 'hub-wifi__content hub-wifi__content--single-column';
  screen.appendChild(contentWrap);

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
   * @param {HTMLElement} activeEl
   * @returns {boolean}
   */
  function elementContains(slot, activeEl) {
    return slot === activeEl || slot.contains(activeEl);
  }

  function captureFocusBeforeRender() {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement)) {
      return;
    }
    const fieldId = active.id;
    if (
      fieldId === 'hub-internet-uplink-ssid'
      || fieldId === 'hub-internet-uplink-password'
      || fieldId === 'hub-internet-uplink-scan-btn'
      || fieldId === 'hub-internet-uplink-connect-btn'
      || fieldId === 'hub-internet-uplink-teardown-btn'
    ) {
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
    } else {
      captureFocusBeforeRender();
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
    sourceAffordance = mountInternetSourceAffordance(sourceStatusSlot, {
      getObservation: () => internetObservation,
      getRemembered: () => rememberedUplink,
      getBusy: () => loadingInternetSource,
      idPrefix: 'hub-internet-uplink-source',
    });
  }

  function buildSourceSignature() {
    const obs = internetObservation;
    const rem = rememberedUplink;
    return [
      loadingInternetSource ? 'loading' : 'idle',
      obs?.read_status ?? 'none',
      obs?.gateway_interface ?? '',
      obs?.internet === true ? '1' : obs?.internet === false ? '0' : '?',
      rem?.desired_active ? 'active' : 'inactive',
      rem?.ssid ?? '',
      rem?.band ?? '',
      rem?.credential_configured ? 'cred' : 'no-cred',
    ].join('|');
  }

  function renderSourceStatus() {
    mountLayoutOnce();
    const signature = buildSourceSignature();
    if (signature === lastSourceSignature && sourceStatusSlot.firstChild) {
      sourceAffordance?.update();
      return;
    }
    lastSourceSignature = signature;
    sourceAffordance?.update();
  }

  function buildVerdictSignature() {
    if (!lastVerdict) {
      return 'none';
    }
    return [
      lastVerdict.title,
      lastVerdict.success ? 'ok' : 'fail',
      lastVerdict.hubState ?? '',
      lastVerdict.message ?? '',
    ].join('|');
  }

  function buildContentSignature() {
    return [
      adapterMode ?? '',
      offline ? 'offline' : 'online',
      scanning ? 'scan' : 'idle',
      preparing ? 'prep' : 'idle',
      mutating ? 'mut' : 'idle',
      scanResults.length,
      draft.ssid,
      draft.band,
      formErrors.join(';'),
      operationError ? 'err' : 'ok',
      selectedNetwork?.ssid ?? '',
      advancedOpen ? 'adv' : 'base',
      isConnectionRestorePending(getSession()) ? 'restore' : 'ready',
    ].join('|');
  }

  function buildFooterSignature() {
    const state = screenState();
    const readiness = mutationReadiness();
    return [
      state.canConnect ? '1' : '0',
      state.canTeardown ? '1' : '0',
      readiness.allowed ? '1' : '0',
      offline ? '1' : '0',
      preparing ? '1' : '0',
      mutating ? '1' : '0',
      riskModalOpen ? '1' : '0',
    ].join('|');
  }

  function clearElement(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function controlsLocked() {
    return scanning || preparing || mutating || riskModalOpen;
  }

  function mutationReadiness() {
    return evaluateUplinkWifiMutationReadiness(getSession(), adapterMode);
  }

  function openNetworkSelected() {
    return selectedNetwork?.open === true;
  }

  function screenState() {
    return buildUplinkWifiScreenState({
      draft,
      openNetwork: openNetworkSelected(),
      mutationReadiness: mutationReadiness(),
    });
  }

  function registerModal(modalRef) {
    openModals.push(modalRef);
    const originalClose = modalRef.close;
    modalRef.close = () => {
      const index = openModals.indexOf(modalRef);
      if (index >= 0) openModals.splice(index, 1);
      originalClose();
    };
    return modalRef;
  }

  function closeAllModals() {
    while (openModals.length > 0) {
      openModals.pop()?.close();
    }
  }

  function revokePendingCredential() {
    const refId = credentialRefId;
    credentialRefId = null;
    const session = getSession();
    if (refId && session.routerId) {
      void revokeWifiApCredential({
        routerId: session.routerId,
        credentialRefId: refId,
      }).catch(() => {});
    }
  }

  function renderMutationVerdict() {
    const signature = buildVerdictSignature();
    if (signature === lastVerdictSignature && verdictSlot.firstChild) {
      return;
    }
    lastVerdictSignature = signature;
    clearElement(verdictSlot);
    if (!lastVerdict) {
      verdictSlot.hidden = true;
      return;
    }
    verdictSlot.hidden = false;
    const block = document.createElement('div');
    block.className = 'hub-wifi__verdict';
    block.appendChild(
      createInlineState({
        state: lastVerdict.hubState,
        title: lastVerdict.title,
      }),
    );
    const message = document.createElement('p');
    message.className = 'hub-wifi__note';
    message.textContent = lastVerdict.message;
    block.appendChild(message);
    verdictSlot.appendChild(block);
    if (lastVerdict.technicalLines.length > 0) {
      verdictSlot.appendChild(
        createTechnicalDetails({ content: lastVerdict.technicalLines.join('\n') }),
      );
    }
  }

  function renderScanResults(parent) {
    if (scanResults.length === 0) {
      const empty = document.createElement('p');
      empty.className = 'hub-wifi__note';
      empty.textContent = 'Сети пока не найдены — нажмите «Найти сети» или введите название вручную ниже.';
      parent.appendChild(empty);
      return;
    }

    const list = document.createElement('ul');
    list.className = 'hub-wifi__network-list';
    list.setAttribute('role', 'listbox');
    list.setAttribute('aria-label', 'Найденные сети');

    for (const network of scanResults) {
      const item = document.createElement('li');
      item.className = 'hub-wifi__network-item';
      const btn = createButton({
        label: formatSurveyNetworkLabel(network),
        variant: selectedNetwork === network ? 'primary' : 'secondary',
        disabled: controlsLocked() || network.open,
        onActivate: () => {
          if (network.open) {
            ctx.showToast({
              tone: 'warning',
              title: 'Сеть без пароля',
              message: UPLINK_WIFI_OPEN_NETWORK_BLOCKED_MESSAGE,
            });
            return;
          }
          selectedNetwork = network;
          draft = { ...draft, ssid: network.ssid, band: network.band };
          formErrors = [];
          renderAll();
        },
      });
      btn.classList.add('hub-wifi__network-select-btn');
      item.appendChild(btn);
      list.appendChild(item);
    }
    parent.appendChild(list);
  }

  function renderContent() {
    clearElement(contentWrap);

    const mainCol = document.createElement('div');
    mainCol.className = 'hub-wifi__layout-main';

    if (adapterMode === 'fake') {
      mainCol.appendChild(
        createWifiDemoBanner({
          onNavigateToConnection: () => ctx.navigate('connection'),
        }),
      );
    }

    const session = getSession();
    if (isConnectionRestorePending(session)) {
      mainCol.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: 'Проверяем сохранённое подключение на сервере',
        }),
      );
      contentWrap.appendChild(mainCol);
      return;
    }

    if (isConnectionRestoreFailed(session)) {
      mainCol.appendChild(
        createStatePanel({
          state: HubState.WARNING,
          titleTag: 'h2',
          title: 'Не удалось проверить сохранённое подключение',
          description:
            'Сервер не ответил вовремя. Откройте «Подключение» и повторите проверку.',
          action: {
            label: 'Открыть «Подключение»',
            onActivate: () => ctx.navigate('connection'),
          },
        }),
      );
      contentWrap.appendChild(mainCol);
      return;
    }

    if (needsManagementUsernameRecovery(session)) {
      mainCol.appendChild(
        createStatePanel({
          state: HubState.WARNING,
          titleTag: 'h2',
          title: 'Нужно имя пользователя для управления',
          description:
            'Откройте «Подключение» и заполните имя пользователя — повторное подтверждение отпечатка не требуется.',
          action: {
            label: 'Открыть «Подключение»',
            onActivate: () => ctx.navigate('connection'),
          },
        }),
      );
      contentWrap.appendChild(mainCol);
      return;
    }

    if (offline && !recovering) {
      mainCol.appendChild(
        createStatePanel({
          state: HubState.NO_INTERNET,
          titleTag: 'h2',
          action: {
            label: 'Повторить',
            onActivate: () => renderAll(),
          },
        }),
      );
    }

    const infoCard = createCard({ title: 'Что делает этот раздел', titleTag: 'h2' });
    const infoBody = infoCard.querySelector('.hub-card__body') ?? infoCard;
    const distinctionNote = document.createElement('p');
    distinctionNote.className = 'hub-wifi__note';
    distinctionNote.textContent = UPLINK_WIFI_DISTINCTION_NOTE;
    infoBody.appendChild(distinctionNote);
    mainCol.appendChild(infoCard);

    const scanCard = createCard({ title: 'Найти сеть рядом', titleTag: 'h2' });
    const scanBody = scanCard.querySelector('.hub-card__body') ?? scanCard;
    const scanNote = document.createElement('p');
    scanNote.className = 'hub-wifi__note';
    scanNote.textContent = UPLINK_WIFI_SCAN_NOTE;
    scanBody.appendChild(scanNote);

    const scanBtn = createButton({
      label: scanning ? 'Ищем сети…' : 'Найти сети',
      variant: 'secondary',
      iconName: 'refresh',
      busy: scanning,
      disabled: controlsLocked() || offline || isConnectionRestorePending(session),
      onActivate: () => {
        void scanFlow();
      },
    });
    scanBtn.id = 'hub-internet-uplink-scan-btn';
    scanBody.appendChild(scanBtn);

    if (scanning) {
      scanBody.appendChild(
        createInlineState({ state: HubState.LOADING, title: 'Сканируем эфир на 2,4 и 5 ГГц' }),
      );
      scanBody.appendChild(createSkeleton({ lines: 3 }));
    }

    if (scanError && !isAborted(scanError)) {
      const described = describeError(scanError);
      scanBody.appendChild(
        createStatePanel({
          state: hubStateForError(scanError),
          titleTag: 'h3',
          title: described.title,
          description: described.message,
          action: {
            label: 'Повторить сканирование',
            onActivate: () => {
              void scanFlow();
            },
          },
        }),
      );
    }

    renderScanResults(scanBody);
    mainCol.appendChild(scanCard);

    const settingsCard = createCard({ title: 'Параметры подключения', titleTag: 'h2' });
    const settingsBody = settingsCard.querySelector('.hub-card__body') ?? settingsCard;

    const ssidError = formErrors.find((err) => err.includes('назван') || err.includes('32'));
    const passwordError = formErrors.find(
      (err) => err.includes('парол') || err.includes('8 символ') || err.includes('без пароля'),
    );

    settingsBody.appendChild(
      createTextField({
        id: 'hub-internet-uplink-ssid',
        label: 'Название сети',
        value: draft.ssid,
        disabled: controlsLocked(),
        error: ssidError,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            selectedNetwork = null;
            draft = { ...draft, ssid: event.target.value };
            formErrors = [];
            renderAll();
          }
        },
      }),
    );

    settingsBody.appendChild(
      createSelectField({
        id: 'hub-internet-uplink-band',
        label: 'Частота',
        options: [
          { value: 'BAND_2_4GHZ', label: '2,4 ГГц' },
          { value: 'BAND_5GHZ', label: '5 ГГц' },
        ],
        value: draft.band,
        disabled: controlsLocked(),
        onChange: (event) => {
          if (event.target instanceof HTMLSelectElement) {
            selectedNetwork = null;
            draft = {
              ...draft,
              band: /** @type {import('../features/uplink-wifi-model.js').UplinkWifiBand} */ (
                event.target.value
              ),
            };
            renderAll();
          }
        },
      }),
    );

    settingsBody.appendChild(
      createTextField({
        id: 'hub-internet-uplink-password',
        label: 'Пароль сети',
        secret: true,
        autocomplete: 'new-password',
        value: draft.password,
        hint: UPLINK_WIFI_PASSWORD_FIELD_NOTE,
        disabled: controlsLocked() || openNetworkSelected(),
        error: passwordError,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            draft = { ...draft, password: event.target.value };
            formErrors = [];
            renderAll();
          }
        },
      }),
    );

    const openNote = document.createElement('p');
    openNote.className = 'hub-wifi__note';
    openNote.textContent = UPLINK_WIFI_NO_OPEN_NETWORK_NOTE;
    settingsBody.appendChild(openNote);

    const advancedContent = document.createElement('div');
    advancedContent.className = 'hub-wifi__advanced-content';
    const settleLine = document.createElement('p');
    settleLine.textContent = UPLINK_WIFI_SETTLE_WAIT_NOTE;
    advancedContent.appendChild(settleLine);
    const liveLine = document.createElement('p');
    liveLine.textContent = describeLiveConnectionAdvancedStatus(getSession(), adapterMode);
    advancedContent.appendChild(liveLine);
    const live = buildLiveConnectionParams(getSession());
    const technicalNotes = [`mode: ${'WifiWan'}`, 'confirm_live_apply: true'];
    if (live.complete) {
      technicalNotes.push('live connection params: complete');
    } else if (live.missing.length > 0) {
      technicalNotes.push(`live connection params missing: ${live.missing.join(', ')}`);
    }
    advancedContent.appendChild(
      createTechnicalDetails({
        summary: 'Технические параметры подключения',
        content: technicalNotes.join('\n'),
      }),
    );

    const advancedDetails = document.createElement('details');
    advancedDetails.className = 'hub-wifi-settings-section';
    advancedDetails.open = advancedOpen;
    const advancedSummary = document.createElement('summary');
    advancedSummary.textContent = 'Расширенные настройки';
    advancedDetails.appendChild(advancedSummary);
    const advancedBody = document.createElement('div');
    advancedBody.className = 'hub-wifi-settings-section-body';
    advancedBody.appendChild(advancedContent);
    advancedDetails.appendChild(advancedBody);
    advancedDetails.addEventListener('toggle', () => {
      advancedOpen = advancedDetails.open;
    });
    settingsBody.appendChild(advancedDetails);
    mainCol.appendChild(settingsCard);

    const readiness = mutationReadiness();
    if (!readiness.allowed && readiness.reasonText && adapterMode !== 'fake') {
      mainCol.appendChild(
        createInlineState({
          state: HubState.WARNING,
          title: readiness.reasonText,
        }),
      );
    }

    if (preparing) {
      mainCol.appendChild(
        createInlineState({ state: HubState.CONNECTING, title: 'Готовим подключение к интернету' }),
      );
    }

    if (mutating) {
      mainCol.appendChild(
        createInlineState({
          state: HubState.CONNECTING,
          title: 'Подключаем роутер к выбранной сети — подождите 20–30 секунд',
        }),
      );
    }

    if (operationError && !isAborted(operationError)) {
      const described =
        operationError instanceof HubApiError &&
        operationError.code === 'client.credential_registration_failed'
          ? {
              title: 'Не удалось сохранить пароль',
              message: operationError.userMessage,
              action: operationError.userAction,
              kind: operationError.kind,
              technical: '',
            }
          : describeError(operationError);
      mainCol.appendChild(
        createStatePanel({
          state: hubStateForError(operationError),
          titleTag: 'h2',
          title: described.title,
          description: described.action
            ? `${described.message} ${described.action}`
            : described.message,
          details: described.technical || undefined,
          action: operationRetry
            ? {
                label: 'Повторить',
                onActivate: () => operationRetry?.(),
              }
            : undefined,
        }),
      );
    }

    contentWrap.appendChild(mainCol);
  }

  function renderFooter() {
    clearElement(footerLeft);
    clearElement(footerRight);

    const state = screenState();
    const readiness = mutationReadiness();

    const teardownBtn = createButton({
      label: 'Отключить от внешней сети',
      variant: 'danger',
      busy: controlsLocked(),
      disabled: !state.canTeardown || offline || preparing,
      onActivate: () => {
        void teardownFlow();
      },
    });
    teardownBtn.id = 'hub-internet-uplink-teardown-btn';
    updateButtonBusyState(
      teardownBtn,
      controlsLocked(),
      !state.canTeardown || offline || preparing,
    );
    footerLeft.appendChild(teardownBtn);

    /** @type {string|null} */
    let connectReason = null;
    if (offline) {
      connectReason = 'Нет связи с сервером управления';
    } else if (!readiness.allowed) {
      connectReason = readiness.reasonText;
    } else if (openNetworkSelected()) {
      connectReason = UPLINK_WIFI_OPEN_NETWORK_BLOCKED_MESSAGE;
    } else if (!state.canConnect) {
      connectReason = 'Укажите название сети и пароль не короче 8 символов';
    }

    if (connectReason) {
      const reasonEl = document.createElement('p');
      reasonEl.id = 'hub-internet-uplink-connect-reason';
      reasonEl.className = 'hub-wifi__save-reason';
      reasonEl.textContent = connectReason;
      footerRight.appendChild(reasonEl);
    }

    const connectBtn = createButton({
      label: 'Подключить к интернету',
      size: 'lg',
      busy: controlsLocked(),
      disabled: !state.canConnect || offline || preparing,
      onActivate: () => {
        void connectFlow();
      },
    });
    connectBtn.id = 'hub-internet-uplink-connect-btn';
    if (connectReason) {
      connectBtn.setAttribute('aria-describedby', 'hub-internet-uplink-connect-reason');
    }
    syncActionButtonById('hub-internet-uplink-connect-btn', {
      disabled: !state.canConnect || offline || preparing,
      busy: controlsLocked(),
    });
    updateButtonBusyState(
      connectBtn,
      controlsLocked(),
      !state.canConnect || offline || preparing,
    );
    footerRight.appendChild(connectBtn);
  }

  function renderAll() {
    if (disposed) return;
    renderSourceStatus();
    rebuildSlot(verdictSlot, renderMutationVerdict);
    const contentSignature = buildContentSignature();
    if (contentSignature !== lastContentSignature || !contentWrap.firstChild) {
      lastContentSignature = contentSignature;
      rebuildSlot(contentWrap, renderContent);
    }
    const footerSignature = buildFooterSignature();
    if (footerSignature !== lastFooterSignature || !footerLeft.firstChild) {
      lastFooterSignature = footerSignature;
      rebuildSlot(footer, renderFooter);
    }
  }

  async function fetchInternetSourceFlow() {
    if (disposed || offline || isConnectionRestorePending(getSession())) {
      return;
    }
    const session = getSession();
    const live = buildLiveConnectionParams(session);
    if (!live.complete) {
      internetObservation = null;
      renderAll();
      return;
    }
    observeAbort?.abort();
    observeAbort = new AbortController();
    const signal = observeAbort.signal;
    loadingInternetSource = true;
    renderAll();
    try {
      const [observed, remembered] = await Promise.all([
        fetchRouterInternetObserve({ session, signal }),
        fetchRememberedUplink({ signal }),
      ]);
      if (disposed || signal.aborted) return;
      internetObservation = observed;
      rememberedUplink = remembered;
      internetSourceError = null;
    } catch (error) {
      if (disposed || isAborted(error)) return;
      internetSourceError = error;
    } finally {
      if (!disposed) {
        loadingInternetSource = false;
        renderAll();
      }
    }
  }

  async function scanFlow() {
    if (disposed || scanning || offline) return;
    const gen = ++generation;
    scanAbort?.abort();
    scanAbort = new AbortController();
    scanning = true;
    scanError = null;
    renderAll();
    try {
      const results = await scanUplinkWifiNetworks(getSession(), scanAbort.signal);
      if (disposed || gen !== generation) return;
      scanResults = results;
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) return;
      scanError = error;
      scanResults = [];
    } finally {
      if (gen === generation) {
        scanning = false;
      }
      if (!disposed && gen === generation) {
        renderAll();
      }
    }
  }

  /**
   * @param {UplinkRiskAction} action
   * @param {string[]} changeLines
   * @param {(snapshot: ReturnType<typeof buildUplinkIntentSnapshot>) => Promise<void>} onConfirm
   */
  function openRiskModal(action, changeLines, onConfirm) {
    const body = buildRiskModalBody({
      leadLines: [
        'Связь между планшетом и роутером может на время пропасть — роутер переключится на другую сеть.',
        'Страница может перестать отвечать. Настройки на роутере при этом могут уже смениться.',
        'Как вернуться: подключитесь по кабелю, через другую сеть роутера или снова откройте приложение после перезагрузки роутера.',
      ],
      changeLines,
    });

    const intentSnapshot = buildUplinkIntentSnapshot({
      ssid: draft.ssid,
      band: draft.band,
      hasPassword: draft.password.trim().length > 0,
    });

    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    let confirmed = false;
    riskModalOpen = true;
    renderAll();

    modalRef = registerModal(
      openModal({
        title: 'Риск обрыва связи',
        description: 'Подтвердите действие только если готовы восстановить доступ другим способом.',
        body,
        tone: 'warning',
        actions: [
          createButton({
            label: 'Отмена',
            variant: 'ghost',
            onActivate: () => modalRef?.close(),
          }),
          createButton({
            label: action === 'teardown' ? 'Отключить' : 'Подключить',
            variant: action === 'teardown' ? 'danger' : 'primary',
            onActivate: () => {
              void (async () => {
                confirmed = true;
                modalRef?.close();
                if (offline) {
                  ctx.showToast({
                    tone: 'danger',
                    title: 'Нет связи с сервером управления',
                    message: 'Подтвердить действие сейчас нельзя.',
                  });
                  return;
                }
                const current = buildUplinkIntentSnapshot({
                  ssid: draft.ssid,
                  band: draft.band,
                  hasPassword: draft.password.trim().length > 0,
                });
                if (!uplinkIntentMatchesCurrent(intentSnapshot, current)) {
                  ctx.showToast({
                    tone: 'warning',
                    title: 'Подтверждение устарело',
                    message: UPLINK_WIFI_INTENT_STALE_MESSAGE,
                  });
                  return;
                }
                await onConfirm(intentSnapshot);
              })();
            },
          }),
        ],
        onClose: () => {
          riskModalOpen = false;
          renderAll();
        },
      }),
    );
  }

  /**
   * @returns {Promise<{ previewBody: Record<string, unknown>, credentialRefId: string }|null>}
   */
  async function prepareConnectIntent() {
    const validation = validateUplinkWifiForm({
      ssid: draft.ssid,
      password: draft.password,
      openNetwork: openNetworkSelected(),
    });
    if (!validation.valid) {
      formErrors = validation.errors;
      renderAll();
      return null;
    }
    formErrors = [];

    const session = getSession();
    const readiness = mutationReadiness();
    if (!readiness.allowed || !session.routerId) {
      return null;
    }

    const trimmedPassword = draft.password.trim();
    const refId = await registerUplinkWifiCredential({
      routerId: session.routerId,
      secret: trimmedPassword,
      signal: prepareAbort?.signal,
    });
    credentialRefId = refId;

    const previewBody = buildStationPreviewBody({
      ssid: draft.ssid,
      band: draft.band,
      credentialRefId: refId,
    });

    await previewUplinkWifiConnection({
      previewBody,
      session,
      signal: prepareAbort?.signal,
    });

    return { previewBody, credentialRefId: refId };
  }

  async function connectFlow() {
    if (preparing || mutating) return;

    const gen = ++generation;
    prepareAbort?.abort();
    prepareAbort = new AbortController();
    preparing = true;
    operationError = null;
    operationRetry = null;
    lastVerdict = null;
    renderAll();

    /** @type {{ previewBody: Record<string, unknown>, credentialRefId: string }|null} */
    let intent = null;
    try {
      intent = await prepareConnectIntent();
      if (disposed || gen !== generation || !intent) return;
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) return;
      revokePendingCredential();
      operationError = error;
      operationRetry = () => {
        void connectFlow();
      };
      renderAll();
      return;
    } finally {
      if (gen === generation) {
        preparing = false;
        renderAll();
      }
    }

    const bandLabel = draft.band === 'BAND_5GHZ' ? '5 ГГц' : '2,4 ГГц';
    const changeLines = [
      `Роутер подключится к сети «${draft.ssid.trim()}» (${bandLabel})`,
      'Будет использован введённый пароль — он сохранён только на сервере управления',
      UPLINK_WIFI_SETTLE_WAIT_NOTE,
    ];

    openRiskModal('connect', changeLines, async () => {
      await runMutation(async () => {
        const session = getSession();
        const response = await applyUplinkWifiConnection({
          previewBody: intent.previewBody,
          session,
          signal: mutateAbort?.signal,
        });
        lastVerdict = parseUplinkApplyVerdict(response, { intent: 'apply' });
        return lastVerdict.success;
      }, 'connect');
    });
  }

  async function teardownFlow() {
    if (preparing || mutating) return;
    const trimmedSsid = draft.ssid.trim();
    if (!trimmedSsid) {
      formErrors = ['Укажите название сети для отключения'];
      renderAll();
      return;
    }

    const bandLabel = draft.band === 'BAND_5GHZ' ? '5 ГГц' : '2,4 ГГц';
    const changeLines = [
      `Роутер отключится от внешней сети «${trimmedSsid}» (${bandLabel})`,
      'Интернет через эту сеть перестанет работать на роутере',
    ];

    openRiskModal('teardown', changeLines, async () => {
      await runMutation(async () => {
        const session = getSession();
        const response = await teardownUplinkWifiConnection({
          ssid: trimmedSsid,
          band: draft.band,
          credentialRefId,
          session,
          signal: mutateAbort?.signal,
        });
        lastVerdict = parseUplinkApplyVerdict(response, { intent: 'teardown' });
        return lastVerdict.success;
      }, 'teardown');
    });
  }

  /**
   * @param {() => Promise<boolean>} executor
   * @param {'connect'|'teardown'} action
   */
  async function runMutation(executor, action) {
    if (disposed || mutating || offline) return;
    const gen = ++generation;
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    mutating = true;
    operationError = null;
    operationRetry = null;
    renderAll();

    try {
      const succeeded = await executor();
      if (disposed || gen !== generation) return;
      if (lastVerdict) {
        ctx.showToast({
          tone: lastVerdict.success
            ? 'success'
            : (lastVerdict.hubState && Object.values(HubState).includes(lastVerdict.hubState)
              ? getStateDescriptor(lastVerdict.hubState).tone
              : 'warning'),
          title: lastVerdict.title,
          message: lastVerdict.message,
        });
      }
      if (succeeded && action === 'connect') {
        draft = { ...draft, password: '' };
        const pwdEl = document.getElementById('hub-internet-uplink-password');
        if (pwdEl instanceof HTMLInputElement) pwdEl.value = '';
        const session = getSession();
        if (session.routerId && credentialRefId) {
          try {
            rememberedUplink = await persistRememberedUplinkAfterApply({
              routerId: session.routerId,
              ssid: draft.ssid,
              band: draft.band,
              credentialRefId,
              signal: mutateAbort?.signal,
            });
          } catch {
            /* remembered persistence failure must not mask apply verdict */
          }
        }
      }
      if (succeeded && action === 'teardown') {
        try {
          rememberedUplink = await deactivateRememberedUplink({
            signal: mutateAbort?.signal,
          });
        } catch (error) {
          if (disposed || gen !== generation || isAborted(error)) return;
          operationError = error;
          operationRetry = async () => {
            if (disposed || mutating || offline) return;
            try {
              rememberedUplink = await deactivateRememberedUplink({
                signal: mutateAbort?.signal,
              });
              operationError = null;
              operationRetry = null;
              void fetchInternetSourceFlow();
              renderAll();
              ctx.showToast({
                tone: 'success',
                title: 'Автоподключение отключено',
                message:
                  'Намерение сохранено — Wi‑Fi uplink не будет восстанавливаться автоматически.',
              });
            } catch (retryError) {
              if (disposed || isAborted(retryError)) return;
              operationError = retryError;
              renderAll();
            }
          };
          ctx.showToast({
            tone: 'warning',
            title: 'Не удалось отключить автоподключение',
            message:
              'Роутер отключён от сети, но намерение автоподключения не сохранено — watchdog может восстановить Wi‑Fi. Нажмите «Повторить».',
          });
        }
      }
      if (succeeded) {
        void fetchInternetSourceFlow();
      }
      renderAll();
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) return;
      operationError = error;
      operationRetry = () => {
        if (action === 'connect') void connectFlow();
        else void teardownFlow();
      };
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
    } finally {
      if (gen === generation) {
        mutating = false;
        renderAll();
      }
    }
  }

  const unsubConnectivity = subscribeConnectivity((online) => {
    if (disposed) return;
    offline = !online;
    recovering = online;
    renderAll();
    if (online) {
      recovering = false;
      renderAll();
    }
  });

  let trackedLiveKey = liveCapabilitySubscriptionKey(getSession());
  const unsubSession = subscribeSession((snapshot) => {
    if (disposed) return;
    const nextKey = liveCapabilitySubscriptionKey(snapshot);
    if (nextKey !== trackedLiveKey) {
      trackedLiveKey = nextKey;
      renderAll();
    }
  });

  renderAll();
  void fetchInternetSourceFlow();

  return () => {
    disposed = true;
    generation += 1;
    scanAbort?.abort();
    prepareAbort?.abort();
    mutateAbort?.abort();
    observeAbort?.abort();
    closeAllModals();
    revokePendingCredential();
    sourceAffordance?.destroy();
    sourceAffordance = null;
    draft = { ...draft, password: '' };
    unsubConnectivity();
    unsubSession();
  };
}
