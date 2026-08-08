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
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import { getSession, subscribeSession } from '../core/session.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
} from '../core/states.js';
import { createIdempotencyKey } from '../features/connection-flow.js';
import {
  DOMAIN_DRAFT_LINK_NOTE,
  DOMAIN_EXTERNAL_CHECK_UNSUPPORTED_TEXT,
  DOMAIN_FORWARDING_UNSUPPORTED_TEXT,
  DOMAIN_HOST_PROBE_SCOPE_LABEL,
  DOMAIN_NOT_PUBLISHED_TITLE,
  DOMAIN_PLAIN_HTTP_WARNING,
  DOMAIN_PRESET_REVISION_NOTE,
  DOMAIN_PUBLISH_HUMAN_GATE_TEXT,
  KEENDNS_ACCESS_MODE_OPTIONS,
  KEENDNS_DOMAIN_OPTIONS,
  buildDraftUrl,
  buildLocalOrderUrl,
  describeHostHttpProbe,
  describeHostInternetProbe,
  describeHostTlsProbe,
  describeDomainEventEmptyState,
  describeKeendnsStatus,
  describePreview,
  evaluateDomainPresetReadiness,
  formatDraftClipboardContent,
  loadEventPreset,
  loadEventPresetRevision,
  loadHubStatus,
  loadKeendnsStatus,
  loadSiteEventPresets,
  normalizeDomainName,
  parseLocalOrderUrl,
  previewKeendnsBooking,
  previewKeendnsDrop,
  probeLocalApplicationHttp,
  probeLocalApplicationTls,
  probeOperatorHostInternet,
  applyKeendnsBooking,
  KEENDNS_DEFAULT_ACCESS_MODE,
  resolveDomainSimpleDefaultName,
  saveLocalOrderUrl,
  validateDomainName,
} from '../features/domain-model.js';
import {
  mountDomainSimplePublishAffordance,
  openDomainPublishApplyConfirm,
  openDomainPublishHumanGate,
} from '../features/domain-simple-publish.js';
import {
  buildRiskModalBody,
  createDemoBanner,
  createWifiNetworkHeaderCard,
  updateButtonBusyState,
} from '../features/wifi-screen-parts.js';
import { drawWifiQrCanvas } from '../features/wifi-qr.js';

export const meta = {
  id: 'domain',
  title: 'Домен',
  iconName: 'domain',
};

const KEENDNS_NO_CONFIG_NOTE =
  'Роутер не отдаёт настраиваемые параметры облачного имени через это управление — здесь черновик и отправка заявки на роутер; чтение текущих параметров с роутера не поддерживается.';

const PROBE_SCOPE_DISCLAIMER =
  'Строки ниже описывают проверки с компьютера оператора, а не состояние роутера или доступность из интернета.';

const SAVE_LOCAL_NETWORK_MAX_ATTEMPTS = 2;

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
 * @param {string} hubState
 * @returns {string}
 */
function statusInlineTitle(hubState) {
  switch (hubState) {
    case HubState.SUCCESS:
      return 'Подтверждено';
    case HubState.WARNING:
      return 'Внимание';
    case HubState.ERROR:
      return 'Ошибка';
    case HubState.UNSUPPORTED:
      return 'Не поддерживается';
    case HubState.CONNECTING:
      return 'Проверка';
    case HubState.LOADING:
      return 'Загрузка';
    default:
      return 'Нет данных';
  }
}

/**
 * @param {string} text
 * @returns {Promise<boolean>}
 */
async function copyTextToClipboard(text) {
  if (typeof navigator !== 'undefined' && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      return false;
    }
  }
  return false;
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

  let statusGeneration = 0;
  let presetGeneration = 0;
  let operationGeneration = 0;
  let eventPresetsGeneration = 0;
  /** @type {number|null} */
  let saveLoadGeneration = null;
  let disposed = false;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;
  let recovering = false;

  /** @type {string|null} */
  let trackedEventPresetId = getSession()?.eventPresetId ?? null;
  /** @type {boolean|null} */
  let siteHasEventPresets = null;

  /** @type {AbortController|null} */
  let statusAbort = null;
  /** @type {AbortController|null} */
  let presetAbort = null;
  /** @type {AbortController|null} */
  let operationAbort = null;
  /** @type {AbortController|null} */
  let eventPresetsAbort = null;

  let statusLoading = true;
  let statusRefreshing = false;
  let hasLoadedStatusOnce = false;
  /** @type {unknown|null} */
  let statusError = null;
  /** @type {unknown|null} */
  let statusResponse = null;

  let presetLoading = false;
  let presetRefreshing = false;
  let hasLoadedPresetOnce = false;
  /** @type {unknown|null} */
  let presetError = null;
  /** @type {string|null} */
  let presetRevisionId = null;
  /** @type {string|null} */
  let presetEtag = null;
  /** @type {Record<string, unknown>|null} */
  let presetDocument = null;
  /** @type {string|null} */
  let savedLocalOrderUrl = null;
  /** @type {string} */
  let savedLocalPath = '/';

  let domainName = '';
  let domainSuffix = KEENDNS_DOMAIN_OPTIONS[0]?.value ?? 'keenetic.pro';
  let previewAccessMode = 'auto';
  let localHostPort = '';
  let httpsEnabled = true;
  let simpleDefaultPrefilled = false;

  /** @type {ReturnType<typeof mountDomainSimplePublishAffordance>|null} */
  let simpleAffordance = null;

  let previewing = false;
  let dropping = false;
  let probing = false;
  let savingLocal = false;
  /** @type {unknown|null} */
  let previewResponse = null;
  /** @type {unknown|null} */
  let previewError = null;
  /** @type {unknown|null} */
  let httpProbeResponse = null;
  /** @type {unknown|null} */
  let tlsProbeResponse = null;
  /** @type {unknown|null} */
  let internetProbeResponse = null;
  /** @type {unknown|null} */
  let probeError = null;

  /** @type {unknown|null} */
  let operationError = null;
  /** @type {(() => void)|null} */
  let operationRetry = null;

  let publishModalOpen = false;
  let qrModalOpen = false;
  let saveModalOpen = false;
  let dropModalOpen = false;

  /** @type {Array<{ close: () => void }>} */
  let openModals = [];
  /** @type {{ kind: string, id?: string }|null} */
  let pendingFocus = null;

  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-domain';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.id = 'hub-domain-screen-title';
  title.tabIndex = -1;
  title.textContent = 'Домен и публикация';
  header.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent = 'Черновик ссылки для приложения заказов — в интернете ещё не работает';
  header.appendChild(subtitle);
  screen.appendChild(header);

  const contentWrap = document.createElement('div');
  contentWrap.className = 'hub-domain__content hub-wifi__content';
  screen.appendChild(contentWrap);

  const footer = document.createElement('footer');
  footer.className = 'hub-domain__footer hub-wifi__footer';
  const footerLeft = document.createElement('div');
  footerLeft.className = 'hub-wifi__footer-left';
  const footerRight = document.createElement('div');
  footerRight.className = 'hub-wifi__footer-right';
  footer.appendChild(footerLeft);
  footer.appendChild(footerRight);
  screen.appendChild(footer);

  container.appendChild(screen);

  let layoutMounted = false;
  let lastBannerSignature = null;
  let lastHeaderSignature = null;
  let lastMainSignature = null;
  let lastSideSignature = null;
  let lastFooterSignature = null;

  const bannerSlot = document.createElement('div');
  bannerSlot.className = 'hub-wifi__layout-banner';
  const headerSlot = document.createElement('div');
  headerSlot.className = 'hub-wifi__layout-network-header';
  const mainCol = document.createElement('div');
  mainCol.className = 'hub-wifi__layout-main';
  const sideCol = document.createElement('div');
  sideCol.className = 'hub-wifi__layout-side';

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

  function nodeWithinSlot(slot, node) {
    if (!(node instanceof HTMLElement)) {
      return false;
    }
    if (typeof slot.contains === 'function') {
      return slot.contains(node);
    }
    let current = /** @type {Node|null} */ (node);
    while (current) {
      if (current === slot) {
        return true;
      }
      current = current.parentElement ?? current.parentNode ?? null;
    }
    return false;
  }

  /**
   * @param {HTMLElement} slot
   * @param {() => void} rebuild
   */
  function rebuildSlot(slot, rebuild) {
    const scrollTop = captureHubContentScroll();
    const active = document.activeElement;
    if (active instanceof HTMLElement && nodeWithinSlot(slot, active)) {
      if (active.id) {
        pendingFocus = { kind: 'element-id', id: active.id };
      }
    }
    while (slot.firstChild) {
      slot.removeChild(slot.firstChild);
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
    contentWrap.appendChild(headerSlot);
    contentWrap.appendChild(mainCol);
    contentWrap.appendChild(sideCol);
  }

  function settingsMounted() {
    return layoutMounted && document.getElementById('hub-domain-name') instanceof HTMLInputElement;
  }

  function syncContentLayoutClasses() {
    contentWrap.classList.remove('hub-wifi__content--single-column');
    bannerSlot.hidden = !bannerSlot.hasChildNodes();
    if (!sideCol.hasChildNodes()) {
      contentWrap.classList.add('hub-wifi__content--single-column');
    }
  }

  function clearElement(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function presetBlockedDescription() {
    return describeDomainEventEmptyState({ hasEventPresets: siteHasEventPresets }).description;
  }

  function presetReadiness() {
    return evaluateDomainPresetReadiness(getSession());
  }

  function ensureSimpleDefaultName() {
    if (!simpleDefaultPrefilled && !domainName.trim()) {
      domainName = resolveDomainSimpleDefaultName();
      simpleDefaultPrefilled = true;
    }
  }

  function destroySimpleAffordance() {
    simpleAffordance?.destroy();
    simpleAffordance = null;
  }

  function syncSimpleAffordanceDisabled() {
    simpleAffordance?.update();
  }

  /**
   * @param {{ skipIfActive?: boolean }} [options]
   */
  function syncAdvancedNameSuffixFieldsFromState(options = {}) {
    const skipIfActive = options.skipIfActive !== false;
    const active = document.activeElement;

    const nameInput = document.getElementById('hub-domain-name');
    if (nameInput instanceof HTMLInputElement) {
      if (!skipIfActive || active !== nameInput) {
        nameInput.value = domainName;
      }
    }

    const suffixSelect = document.getElementById('hub-domain-suffix');
    if (suffixSelect instanceof HTMLSelectElement) {
      if (!skipIfActive || active !== suffixSelect) {
        suffixSelect.value = domainSuffix;
      }
    }
  }

  function onDomainNameOrSuffixSoftChange() {
    simpleAffordance?.update();
    updateDraftDependentUi();
  }

  function draftUrl() {
    return buildDraftUrl({ name: domainName, domain: domainSuffix });
  }

  function mountSimpleAffordanceInto(container) {
    destroySimpleAffordance();
    ensureSimpleDefaultName();
    simpleAffordance = mountDomainSimplePublishAffordance(container, {
      getName: () => domainName,
      setName: (value) => {
        domainName = value;
        updateDraftDependentUi();
      },
      getDomain: () => domainSuffix,
      setDomain: (value) => {
        domainSuffix = value;
        updateDraftDependentUi();
      },
      getDisabled: () => controlsLocked() || offline,
      onPublishApply: () => {
        openPublishApplyModal('book');
      },
      showSuffixSelect: true,
      idPrefix: 'hub-domain-simple',
    });
  }

  function resolvePreviewMode() {
    if (
      previewAccessMode === 'auto'
      || previewAccessMode === 'cloud'
      || previewAccessMode === 'direct'
    ) {
      return previewAccessMode;
    }
    return 'auto';
  }

  /**
   * @param {number} gen
   * @param {string|null} presetId
   * @returns {boolean}
   */
  function isOperationContextCurrent(gen, presetId) {
    if (disposed || gen !== operationGeneration) {
      return false;
    }
    if (!presetId) {
      return getSession()?.eventPresetId == null;
    }
    return getSession()?.eventPresetId === presetId;
  }

  function invalidateOperationConcern() {
    operationGeneration += 1;
    operationAbort?.abort();
    operationAbort = null;
    previewing = false;
    dropping = false;
    probing = false;
    savingLocal = false;
    saveLoadGeneration = null;
    saveModalOpen = false;
    dropModalOpen = false;
    publishModalOpen = false;
    qrModalOpen = false;
  }

  function currentLocalOrderUrl() {
    return buildLocalOrderUrl({
      hostPort: localHostPort,
      https: httpsEnabled,
      path: savedLocalPath,
    });
  }

  function localAddressDirty() {
    const built = currentLocalOrderUrl();
    if (!built && !savedLocalOrderUrl) {
      return localHostPort.trim().length > 0;
    }
    return built !== savedLocalOrderUrl;
  }

  function controlsLocked() {
    return (
      previewing
      || dropping
      || probing
      || savingLocal
      || publishModalOpen
      || qrModalOpen
      || saveModalOpen
      || dropModalOpen
    );
  }

  function invalidateOperations() {
    statusGeneration += 1;
    presetGeneration += 1;
    operationGeneration += 1;
    eventPresetsGeneration += 1;
    statusAbort?.abort();
    presetAbort?.abort();
    operationAbort?.abort();
    eventPresetsAbort?.abort();
    previewing = false;
    dropping = false;
    probing = false;
    savingLocal = false;
  }

  function resetPresetDerivedState() {
    presetAbort?.abort();
    presetRevisionId = null;
    presetDocument = null;
    presetEtag = null;
    savedLocalOrderUrl = null;
    localHostPort = '';
    httpsEnabled = true;
    savedLocalPath = '/';
    presetError = null;
    presetLoading = false;
    presetRefreshing = false;
    httpProbeResponse = null;
    tlsProbeResponse = null;
    internetProbeResponse = null;
    probeError = null;
    previewResponse = null;
    previewError = null;
    operationError = null;
    operationRetry = null;
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
      if (
        el instanceof HTMLElement
        && !((el instanceof HTMLButtonElement || el instanceof HTMLInputElement) && el.disabled)
      ) {
        el.focus();
        return;
      }
    }
    title.focus();
  }

  function applyPresetRevisionData(revisionPayload) {
    const payload =
      revisionPayload && typeof revisionPayload === 'object'
        ? /** @type {Record<string, unknown>} */ (revisionPayload)
        : {};
    const document =
      payload.canonical_document && typeof payload.canonical_document === 'object'
        ? /** @type {Record<string, unknown>} */ (payload.canonical_document)
        : null;
    presetDocument = document;
    const url =
      document && typeof document.local_order_url === 'string'
        ? document.local_order_url
        : null;
    savedLocalOrderUrl = url;
    const parsed = parseLocalOrderUrl(url);
    localHostPort = parsed.hostPort ?? '';
    httpsEnabled = parsed.scheme !== 'http';
    savedLocalPath = parsed.path || '/';
  }

  async function loadEventPresetsAvailabilityFlow() {
    if (disposed) {
      return;
    }
    eventPresetsAbort?.abort();
    eventPresetsAbort = new AbortController();
    const myController = eventPresetsAbort;
    const gen = ++eventPresetsGeneration;
    try {
      const session = getSession();
      let siteId = session.siteId;
      if (!siteId) {
        const statusPayload = await loadHubStatus({ signal: myController.signal });
        if (disposed || gen !== eventPresetsGeneration) {
          return;
        }
        const statusRecord =
          statusPayload && typeof statusPayload === 'object'
            ? /** @type {Record<string, unknown>} */ (statusPayload)
            : {};
        siteId =
          typeof statusRecord.default_site_id === 'string'
            ? statusRecord.default_site_id
            : null;
      }
      if (!siteId) {
        if (!disposed && gen === eventPresetsGeneration) {
          siteHasEventPresets = null;
          renderAll();
        }
        return;
      }
      const presetsPayload = await loadSiteEventPresets({
        siteId,
        signal: myController.signal,
      });
      if (disposed || gen !== eventPresetsGeneration) {
        return;
      }
      const items =
        presetsPayload && typeof presetsPayload === 'object'
          ? /** @type {Record<string, unknown>} */ (presetsPayload).items
          : null;
      siteHasEventPresets = Array.isArray(items) && items.length > 0;
    } catch (error) {
      if (disposed || gen !== eventPresetsGeneration || isAborted(error)) {
        return;
      }
      siteHasEventPresets = null;
    } finally {
      if (eventPresetsAbort === myController) {
        eventPresetsAbort = null;
      }
      if (!disposed && gen === eventPresetsGeneration) {
        renderAll();
      }
    }
  }

  async function loadStatusFlow() {
    if (disposed) {
      return;
    }
    statusAbort?.abort();
    statusAbort = new AbortController();
    const myController = statusAbort;
    const gen = ++statusGeneration;
    if (settingsMounted() || hasLoadedStatusOnce) {
      statusLoading = false;
      statusRefreshing = true;
    } else {
      statusLoading = true;
      statusRefreshing = false;
    }
    statusError = null;
    renderAll();
    try {
      const response = await loadKeendnsStatus({ signal: myController.signal });
      if (disposed || gen !== statusGeneration) {
        return;
      }
      statusResponse = response;
    } catch (error) {
      if (disposed || gen !== statusGeneration || isAborted(error)) {
        return;
      }
      statusError = error;
    } finally {
      if (!disposed && gen === statusGeneration) {
        statusLoading = false;
        statusRefreshing = false;
        hasLoadedStatusOnce = true;
      }
      if (statusAbort === myController) {
        statusAbort = null;
      }
      if (!disposed && gen === statusGeneration) {
        renderAll();
      }
    }
  }

  async function loadPresetFlow() {
    const readiness = presetReadiness();
    if (!readiness.allowed) {
      resetPresetDerivedState();
      renderAll();
      return;
    }
    const presetId = getSession()?.eventPresetId;
    if (!presetId) {
      return;
    }
    presetAbort?.abort();
    presetAbort = new AbortController();
    const myController = presetAbort;
    const gen = ++presetGeneration;
    if (settingsMounted() || hasLoadedPresetOnce) {
      presetLoading = false;
      presetRefreshing = true;
    } else {
      presetLoading = true;
      presetRefreshing = false;
    }
    presetError = null;
    renderAll();
    try {
      const presetMeta = await loadEventPreset({ presetId, signal: myController.signal });
      if (disposed || gen !== presetGeneration) {
        return;
      }
      const metaPayload =
        presetMeta && typeof presetMeta === 'object'
          ? /** @type {Record<string, unknown>} */ (presetMeta)
          : {};
      presetEtag = typeof metaPayload.etag === 'string' ? metaPayload.etag : null;
      const revisionId =
        typeof metaPayload.current_revision_id === 'string'
          ? metaPayload.current_revision_id
          : null;
      presetRevisionId = revisionId;
      if (!revisionId) {
        presetDocument = null;
        savedLocalOrderUrl = null;
        localHostPort = '';
        return;
      }
      const revision = await loadEventPresetRevision({
        presetId,
        revisionId,
        signal: myController.signal,
      });
      if (disposed || gen !== presetGeneration) {
        return;
      }
      applyPresetRevisionData(revision);
    } catch (error) {
      if (disposed || gen !== presetGeneration || isAborted(error)) {
        return;
      }
      presetError = error;
    } finally {
      if (!disposed && gen === presetGeneration) {
        presetLoading = false;
        presetRefreshing = false;
        hasLoadedPresetOnce = true;
      }
      if (presetAbort === myController) {
        presetAbort = null;
      }
      if (!disposed && gen === presetGeneration) {
        renderAll();
      }
    }
  }

  async function runPreviewBooking() {
    if (disposed || previewing) {
      return;
    }
    const normalizedName = normalizeDomainName(domainName);
    if (!normalizedName || !domainSuffix) {
      ctx.showToast({
        tone: 'warning',
        title: 'Нужны имя и домен',
        message: 'Укажите имя и домен для предпросмотра команд.',
      });
      return;
    }
    previewing = true;
    previewError = null;
    operationError = null;
    operationRetry = null;
    renderAll();
    operationAbort?.abort();
    operationAbort = new AbortController();
    const myController = operationAbort;
    const gen = ++operationGeneration;
    const capturedPresetId = getSession()?.eventPresetId ?? null;
    try {
      const response = await previewKeendnsBooking({
        name: normalizedName,
        domain: domainSuffix,
        mode: resolvePreviewMode(),
        signal: myController.signal,
      });
      if (!isOperationContextCurrent(gen, capturedPresetId)) {
        return;
      }
      previewResponse = response;
      if (!disposed) {
        ctx.showToast({
          tone: 'warning',
          title: 'Предпросмотр готов',
          message: 'Команды не выполнялись — это только черновик заявки.',
        });
      }
    } catch (error) {
      if (!isOperationContextCurrent(gen, capturedPresetId) || isAborted(error)) {
        return;
      }
      previewError = error;
      operationError = error;
      operationRetry = () => {
        void runPreviewBooking();
      };
      const described = describeError(error);
      if (!disposed) {
        ctx.showToast({
          tone: 'danger',
          title: described.title,
          message: described.message,
        });
      }
    } finally {
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        previewing = false;
      }
      if (operationAbort === myController) {
        operationAbort = null;
      }
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        renderAll();
      }
    }
  }

  async function runPreviewDrop() {
    if (disposed || dropping) {
      return;
    }
    const normalizedName = normalizeDomainName(domainName);
    if (!normalizedName || !domainSuffix) {
      ctx.showToast({
        tone: 'warning',
        title: 'Нужны имя и домен',
        message: 'Укажите имя и домен для предпросмотра отключения.',
      });
      return;
    }
    dropping = true;
    operationError = null;
    operationRetry = null;
    renderAll();
    operationAbort?.abort();
    operationAbort = new AbortController();
    const myController = operationAbort;
    const gen = ++operationGeneration;
    const capturedPresetId = getSession()?.eventPresetId ?? null;
    try {
      const response = await previewKeendnsDrop({
        name: normalizedName,
        domain: domainSuffix,
        signal: myController.signal,
      });
      if (!isOperationContextCurrent(gen, capturedPresetId)) {
        return;
      }
      previewResponse = response;
      openPublishGateModal('drop');
    } catch (error) {
      if (!isOperationContextCurrent(gen, capturedPresetId) || isAborted(error)) {
        return;
      }
      operationError = error;
      operationRetry = () => {
        void runPreviewDrop();
      };
      const described = describeError(error);
      if (!disposed) {
        ctx.showToast({
          tone: 'danger',
          title: described.title,
          message: described.message,
        });
      }
    } finally {
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        dropping = false;
        dropModalOpen = false;
      }
      if (operationAbort === myController) {
        operationAbort = null;
      }
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        renderAll();
      }
    }
  }

  async function runProbes() {
    const readiness = presetReadiness();
    if (!readiness.allowed || !presetRevisionId) {
      ctx.showToast({
        tone: 'warning',
        title: 'Мероприятие не выбрано',
        message: readiness.reasonText ?? 'Выберите мероприятие в верхней панели.',
      });
      return;
    }
    const presetId = getSession()?.eventPresetId;
    if (!presetId || probing) {
      return;
    }
    const capturedPresetId = presetId;
    const capturedRevisionId = presetRevisionId;
    probing = true;
    probeError = null;
    httpProbeResponse = null;
    tlsProbeResponse = null;
    internetProbeResponse = null;
    operationError = null;
    operationRetry = null;
    renderAll();
    operationAbort?.abort();
    operationAbort = new AbortController();
    const myController = operationAbort;
    const gen = ++operationGeneration;

    const settleSide = () => {
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        renderAll();
      }
    };

    const httpTask = probeLocalApplicationHttp({
      presetId: capturedPresetId,
      revisionId: capturedRevisionId,
      signal: myController.signal,
    })
      .then((response) => {
        if (isOperationContextCurrent(gen, capturedPresetId)) {
          httpProbeResponse = response;
          settleSide();
        }
      })
      .catch((error) => {
        if (isOperationContextCurrent(gen, capturedPresetId) && !isAborted(error)) {
          probeError = error;
          operationError = error;
          operationRetry = () => {
            void runProbes();
          };
        }
      });

    const tlsTask = probeLocalApplicationTls({
      presetId: capturedPresetId,
      revisionId: capturedRevisionId,
      signal: myController.signal,
    })
      .then((response) => {
        if (isOperationContextCurrent(gen, capturedPresetId)) {
          tlsProbeResponse = response;
          settleSide();
        }
      })
      .catch((error) => {
        if (isOperationContextCurrent(gen, capturedPresetId) && !isAborted(error) && !probeError) {
          probeError = error;
          operationError = error;
          operationRetry = () => {
            void runProbes();
          };
        }
      });

    const internetTask = probeOperatorHostInternet({ signal: myController.signal })
      .then((response) => {
        if (isOperationContextCurrent(gen, capturedPresetId)) {
          internetProbeResponse = response;
          settleSide();
        }
      })
      .catch((error) => {
        if (isOperationContextCurrent(gen, capturedPresetId) && !isAborted(error) && !probeError) {
          probeError = error;
          operationError = error;
          operationRetry = () => {
            void runProbes();
          };
        }
      });

    try {
      await Promise.allSettled([httpTask, tlsTask, internetTask]);
    } finally {
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        probing = false;
      }
      if (operationAbort === myController) {
        operationAbort = null;
      }
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        renderAll();
      }
    }
  }

  /**
   * @param {string} idempotencyKey
   */
  async function runSaveLocalAddress(idempotencyKey) {
    if (offline) {
      ctx.showToast({
        tone: 'warning',
        title: 'Нет связи с сервером управления',
        message:
          'Сохранить локальный адрес сейчас нельзя — дождитесь восстановления связи.',
      });
      return;
    }
    const readiness = presetReadiness();
    const presetId = getSession()?.eventPresetId;
    if (!readiness.allowed || !presetId || !presetDocument || savingLocal) {
      return;
    }
    const capturedPresetId = presetId;
    const capturedDocument = presetDocument;
    const capturedEtag = presetEtag;
    const capturedRevisionId = presetRevisionId ?? '';
    const nextUrl = currentLocalOrderUrl();
    if (!nextUrl) {
      ctx.showToast({
        tone: 'warning',
        title: 'Адрес не задан',
        message: 'Укажите корректный локальный адрес в виде адрес:порт, например 192.168.1.10:8080.',
      });
      return;
    }
    savingLocal = true;
    operationError = null;
    operationRetry = null;
    renderAll();
    operationAbort?.abort();
    operationAbort = new AbortController();
    const myController = operationAbort;
    const gen = ++operationGeneration;
    saveLoadGeneration = gen;
    let networkAttempt = 0;
    try {
      for (;;) {
        if (!isOperationContextCurrent(gen, capturedPresetId)) {
          return;
        }
        try {
          await saveLocalOrderUrl({
            presetId: capturedPresetId,
            revisionId: capturedRevisionId,
            document: capturedDocument,
            localOrderUrl: nextUrl,
            etag: capturedEtag,
            idempotencyKey,
            signal: myController.signal,
          });
          break;
        } catch (error) {
          if (isAborted(error) || !isOperationContextCurrent(gen, capturedPresetId)) {
            return;
          }
          if (!(error instanceof HubApiError)) {
            throw error;
          }
          if (error.httpStatus === 409 || error.httpStatus === 412) {
            await loadPresetFlow();
            if (!isOperationContextCurrent(gen, capturedPresetId)) {
              return;
            }
            ctx.showToast({
              tone: 'warning',
              title: 'Версия настроек изменилась',
              message:
                'Настройки мероприятия обновились на сервере. Проверьте локальный адрес и сохраните снова.',
            });
            operationRetry = () => {
              openSaveLocalModal();
            };
            return;
          }
          if (error.kind === ERROR_KIND.NETWORK || error.kind === ERROR_KIND.TIMEOUT) {
            networkAttempt += 1;
            if (networkAttempt < SAVE_LOCAL_NETWORK_MAX_ATTEMPTS) {
              continue;
            }
            throw error;
          }
          throw error;
        }
      }
      if (!isOperationContextCurrent(gen, capturedPresetId)) {
        return;
      }
      savedLocalOrderUrl = nextUrl;
      if (isOperationContextCurrent(gen, capturedPresetId)) {
        ctx.showToast({
          tone: 'success',
          title: 'Локальный адрес сохранён',
          message: DOMAIN_PRESET_REVISION_NOTE,
        });
      }
      await loadPresetFlow();
    } catch (error) {
      if (!isOperationContextCurrent(gen, capturedPresetId) || isAborted(error)) {
        return;
      }
      operationError = error;
      operationRetry = () => {
        openSaveLocalModal();
      };
      const described = describeError(error);
      if (!disposed) {
        ctx.showToast({
          tone: 'danger',
          title: described.title,
          message: described.message,
        });
      }
    } finally {
      if (saveLoadGeneration === gen) {
        savingLocal = false;
        saveModalOpen = false;
        saveLoadGeneration = null;
      }
      if (operationAbort === myController) {
        operationAbort = null;
      }
      if (!disposed) {
        renderAll();
      }
    }
  }

  function openSaveLocalModal() {
    if (saveModalOpen || !localAddressDirty()) {
      return;
    }
    const body = buildRiskModalBody({
      leadLines: [
        'Будет сохранена новая версия настроек мероприятия с обновлённым адресом приложения.',
        DOMAIN_PRESET_REVISION_NOTE,
        !httpsEnabled ? DOMAIN_PLAIN_HTTP_WARNING : '',
      ].filter(Boolean),
      changeLines: [
        `Локальный адрес приложения: ${currentLocalOrderUrl() ?? 'не задан'}`,
      ],
      bodyClassName: 'hub-domain__risk-body hub-wifi__risk-body',
    });
    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    let confirmed = false;
    saveModalOpen = true;
    renderAll();
    const idempotencyKey = createIdempotencyKey();
    modalRef = registerModal(
      openModal({
        title: 'Сохранить локальный адрес',
        description: 'Сохранение не делает имя доступным в интернете и не регистрирует его в облаке.',
        body,
        tone: 'warning',
        actions: [
          createButton({
            label: 'Отмена',
            variant: 'ghost',
            onActivate: () => {
              modalRef?.close();
            },
          }),
          createButton({
            label: 'Сохранить локальный адрес',
            variant: 'primary',
            onActivate: () => {
              confirmed = true;
              pendingFocus = { kind: 'element-id', id: 'hub-domain-save-local-btn' };
              modalRef?.close();
              if (offline) {
                ctx.showToast({
                  tone: 'warning',
                  title: 'Нет связи с сервером управления',
                  message:
                    'Сохранить локальный адрес сейчас нельзя — дождитесь восстановления связи.',
                });
                return;
              }
              void runSaveLocalAddress(idempotencyKey);
            },
          }),
        ],
        onClose: () => {
          saveModalOpen = false;
          if (!confirmed) {
            restorePendingFocus();
          }
          renderAll();
        },
      }),
    );
  }

  function openPublishApplyModal(intent) {
    if (publishModalOpen || intent !== 'book') {
      if (intent === 'drop') {
        openPublishGateModal('drop');
      }
      return;
    }
    if (offline) {
      return;
    }
    publishModalOpen = true;
    operationAbort?.abort();
    operationAbort = new AbortController();
    const applySignal = operationAbort.signal;
    openDomainPublishApplyConfirm({
      openModal: (modalOptions) => registerModal(openModal(modalOptions)),
      createButton,
      showToast: ctx.showToast,
      name: domainName,
      domain: domainSuffix,
      mode: resolvePreviewMode() || KEENDNS_DEFAULT_ACCESS_MODE,
      offline,
      getSignal: () => applySignal,
      onConfirmApply: async (signal) => {
        const result = await applyKeendnsBooking({
          name: domainName,
          domain: domainSuffix,
          mode: resolvePreviewMode() || KEENDNS_DEFAULT_ACCESS_MODE,
          session: getSession(),
          signal,
        });
        if (signal?.aborted) {
          return result;
        }
        const overall =
          result && typeof result === 'object' && 'overall' in result
            ? /** @type {{ overall?: string }} */ (result).overall
            : undefined;
        if (overall === 'applied') {
          operationError = null;
        }
        return result;
      },
      onClose: () => {
        publishModalOpen = false;
        restorePendingFocus();
        renderAll();
      },
    });
  }

  function openPublishGateModal(intent) {
    if (publishModalOpen) {
      return;
    }
    publishModalOpen = true;
    openDomainPublishHumanGate({
      openModal: (modalOptions) => registerModal(openModal(modalOptions)),
      createButton,
      copyTextToClipboard,
      showToast: ctx.showToast,
      intent,
      name: domainName,
      domain: domainSuffix,
      mode: resolvePreviewMode(),
      localOrderUrl: savedLocalOrderUrl,
      onClose: () => {
        publishModalOpen = false;
        restorePendingFocus();
        renderAll();
      },
    });
  }

  function openDropConfirmModal() {
    if (dropModalOpen) {
      return;
    }
    dropModalOpen = true;
    const body = buildRiskModalBody({
      leadLines: [
        'Активная публикация имени в облаке отсюда не известна — освобождать может быть нечего.',
        'Будет подготовлен только текст заявки на отключение — облачная запись не выполняется.',
        DOMAIN_PUBLISH_HUMAN_GATE_TEXT,
      ],
      changeLines: [`Имя: ${normalizeDomainName(domainName) || 'не указано'}.${domainSuffix}`],
      bodyClassName: 'hub-domain__risk-body hub-wifi__risk-body',
    });
    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    let confirmed = false;
    modalRef = registerModal(
      openModal({
        title: 'Отключить публикацию',
        description: 'Только предпросмотр — человек выполняет отключение отдельно.',
        body,
        tone: 'warning',
        actions: [
          createButton({
            label: 'Отмена',
            variant: 'ghost',
            onActivate: () => {
              modalRef?.close();
            },
          }),
          createButton({
            label: 'Показать предпросмотр',
            variant: 'danger',
            onActivate: () => {
              confirmed = true;
              modalRef?.close();
              void runPreviewDrop();
            },
          }),
        ],
        onClose: () => {
          dropModalOpen = false;
          if (!confirmed) {
            restorePendingFocus();
          }
          renderAll();
        },
      }),
    );
  }

  function openQrModal() {
    const url = draftUrl();
    if (!url || qrModalOpen) {
      return;
    }
    qrModalOpen = true;
    const body = document.createElement('div');
    body.className = 'hub-domain__qr-body';
    const canvas = document.createElement('canvas');
    canvas.className = 'hub-wifi__qr-canvas hub-domain__qr-canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', 'QR-код черновой ссылки');
    try {
      drawWifiQrCanvas(canvas, url, { moduleSize: 6 });
      body.appendChild(canvas);
    } catch {
      const note = document.createElement('p');
      note.textContent = 'Не удалось построить QR-код для черновой ссылки.';
      body.appendChild(note);
    }
    const hint = document.createElement('p');
    hint.className = 'hub-wifi__qr-hint';
    hint.textContent = `${url}. ${DOMAIN_DRAFT_LINK_NOTE}`;
    body.appendChild(hint);
    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    modalRef = registerModal(
      openModal({
        title: 'QR-код ссылки',
        description: 'Черновик — в облаке имя не зарегистрировано.',
        body,
        actions: [
          createButton({
            label: 'Закрыть',
            variant: 'ghost',
            onActivate: () => {
              modalRef?.close();
            },
          }),
        ],
        onClose: () => {
          qrModalOpen = false;
          restorePendingFocus();
          renderAll();
        },
      }),
    );
  }

  function handleCopyLink() {
    const url = draftUrl();
    if (!url) {
      return;
    }
    void (async () => {
      const copied = await copyTextToClipboard(formatDraftClipboardContent(url));
      if (disposed) {
        return;
      }
      ctx.showToast({
        tone: copied ? 'success' : 'warning',
        title: copied ? 'Ссылка скопирована' : 'Копирование недоступно',
        message: copied
          ? 'Черновая ссылка в буфере обмена.'
          : 'Браузер не позволяет скопировать ссылку автоматически.',
      });
    })();
  }

  function handleShareLink() {
    const url = draftUrl();
    if (!url) {
      return;
    }
    if (typeof navigator !== 'undefined' && typeof navigator.share === 'function') {
      void navigator
        .share({
          title: 'Черновая ссылка приложения',
          text: DOMAIN_DRAFT_LINK_NOTE,
          url,
        })
        .catch(() => {
          handleCopyLink();
        });
      return;
    }
    handleCopyLink();
  }

  function handleOpenLink() {
    const url = draftUrl();
    if (url) {
      window.open(url, '_blank', 'noopener');
    }
  }

  function statusDescription() {
    if (statusLoading) {
      return {
        hubState: HubState.LOADING,
        title: DOMAIN_NOT_PUBLISHED_TITLE,
        message: 'Загружаем состояние публикации…',
        notes: [],
      };
    }
    if (statusError && !isAborted(statusError)) {
      const described = describeError(statusError);
      return {
        hubState: hubStateForError(statusError),
        title: DOMAIN_NOT_PUBLISHED_TITLE,
        message: described.message,
        notes: [],
      };
    }
    return describeKeendnsStatus(statusResponse);
  }

  function headerPrimaryLine() {
    const url = draftUrl();
    if (url) {
      return url;
    }
    return 'Адрес не задан';
  }

  function headerStatusLine() {
    const status = statusDescription();
    return status.message || status.title;
  }

  function updateDraftDependentUi() {
    if (disposed) {
      return;
    }
    syncAdvancedNameSuffixFieldsFromState({ skipIfActive: true });
    const headerSlot = contentWrap.querySelector('.hub-wifi__layout-network-header');
    if (headerSlot) {
      clearElement(headerSlot);
      headerSlot.appendChild(renderNetworkHeader());
    }
    const linkCard = contentWrap.querySelector('.hub-domain__link-access-card');
    if (linkCard) {
      const replacement = renderLinkAccessCard();
      linkCard.replaceWith(replacement);
    }
    const saveBtn = document.getElementById('hub-domain-save-local-btn');
    if (saveBtn instanceof HTMLButtonElement) {
      const readiness = presetReadiness();
      const localDisabled = !readiness.allowed || controlsLocked() || offline;
      const disabled = localDisabled || !localAddressDirty() || savingLocal;
      saveBtn.disabled = disabled;
      updateButtonBusyState(saveBtn, savingLocal, disabled);
    }
    const nameHint = document.getElementById('hub-domain-name-hint');
    if (nameHint) {
      const validation = validateDomainName(domainName);
      nameHint.textContent =
        domainName.trim() && !validation.valid && validation.reason ? validation.reason : '';
      nameHint.hidden = !nameHint.textContent;
    }
  }

  function linkActionDisabledReason() {
    const url = draftUrl();
    if (url) {
      return null;
    }
    const validation = validateDomainName(domainName);
    if (validation.reason) {
      return validation.reason;
    }
    if (!domainSuffix) {
      return 'Выберите домен для черновика ссылки.';
    }
    return 'Черновая ссылка недоступна.';
  }

  function renderProbeRow(described) {
    const row = document.createElement('div');
    row.className = 'hub-vpn__status-line';
    const label = document.createElement('div');
    label.className = 'hub-vpn__status-line-label';
    label.textContent = described.title;
    row.appendChild(label);
    const valueWrap = document.createElement('div');
    valueWrap.className = 'hub-vpn__status-line-value';
    valueWrap.appendChild(
      createInlineState({
        state: described.hubState,
        title: statusInlineTitle(described.hubState),
      }),
    );
    const message = document.createElement('p');
    message.className = 'hub-vpn__status-message';
    message.textContent = described.message;
    valueWrap.appendChild(message);
    if (described.technical) {
      valueWrap.appendChild(
        createTechnicalDetails({
          summary: 'Технические подробности',
          content: described.technical,
        }),
      );
    }
    row.appendChild(valueWrap);
    return row;
  }

  function headerBadgeLabel() {
    if (statusLoading) {
      return 'Проверяем…';
    }
    const payload =
      statusResponse && typeof statusResponse === 'object'
        ? /** @type {Record<string, unknown>} */ (statusResponse)
        : null;
    const featureAvailability =
      payload && typeof payload.feature_availability === 'string'
        ? payload.feature_availability
        : null;
    if (featureAvailability === 'unavailable') {
      return 'Компонент не найден';
    }
    return 'Не проверено';
  }

  function renderNetworkHeader() {
    const status = statusDescription();
    const badge = createBadge({
      label: headerBadgeLabel(),
      tone: status.hubState === HubState.WARNING ? 'warning' : 'neutral',
    });
    const url = draftUrl();
    const linkReason = linkActionDisabledReason();
    const openBtn = createButton({
      label: 'Открыть черновик',
      variant: 'secondary',
      disabled: !url || controlsLocked() || offline,
      onActivate: handleOpenLink,
    });
    const copyBtn = createButton({
      label: 'Скопировать ссылку',
      variant: 'secondary',
      disabled: !url || controlsLocked() || offline,
      onActivate: handleCopyLink,
    });
    const actionsWrap = document.createElement('div');
    actionsWrap.className = 'hub-domain__header-actions hub-wifi-network__actions';
    actionsWrap.appendChild(openBtn);
    actionsWrap.appendChild(copyBtn);
    if (linkReason) {
      const reasonEl = document.createElement('p');
      reasonEl.id = 'hub-domain-link-action-reason';
      reasonEl.className = 'hub-domain__action-reason hub-wifi__save-reason';
      reasonEl.textContent = linkReason;
      actionsWrap.appendChild(reasonEl);
      openBtn.setAttribute('aria-describedby', reasonEl.id);
      copyBtn.setAttribute('aria-describedby', reasonEl.id);
    }
    const draftNote = document.createElement('p');
    draftNote.className = 'hub-domain__draft-note';
    draftNote.textContent = DOMAIN_DRAFT_LINK_NOTE;
    const headerCard = createWifiNetworkHeaderCard({
      iconName: 'domain',
      ssidTitle: headerPrimaryLine(),
      badge,
      secondaryLine: headerStatusLine(),
      qrButton: actionsWrap,
      cardClassName: 'hub-domain__network-card hub-wifi__network-card',
    });
    const wrap = document.createElement('div');
    wrap.className = 'hub-domain__header-wrap';
    wrap.appendChild(headerCard);
    wrap.appendChild(draftNote);
    return wrap;
  }

  function renderSimplePublishSection() {
    const wrap = document.createElement('div');
    wrap.className = 'hub-domain__simple-publish-wrap';
    mountSimpleAffordanceInto(wrap);
    return wrap;
  }

  function renderSettingsCard() {
    const card = createCard({
      title: 'Настройки публикации',
      titleTag: 'h2',
    });
    const body = card.querySelector('.hub-card__body') ?? card;
    const readiness = presetReadiness();

    if ((statusLoading && !settingsMounted()) || (presetLoading && !settingsMounted())) {
      body.appendChild(createInlineState({ state: HubState.LOADING, title: 'Загружаем данные' }));
      body.appendChild(createSkeleton({ lines: 4, withTitle: false }));
      return card;
    }

    if (statusRefreshing || presetRefreshing) {
      body.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: 'Обновляем данные',
          compact: true,
        }),
      );
    }

    if (!readiness.allowed) {
      const emptyState = describeDomainEventEmptyState({ hasEventPresets: siteHasEventPresets });
      body.appendChild(
        createStatePanel({
          state: HubState.EMPTY,
          titleTag: 'h3',
          title: emptyState.title,
          description: emptyState.description,
        }),
      );
    }

    if (presetError && !isAborted(presetError)) {
      const described = describeError(presetError);
      body.appendChild(
        createStatePanel({
          state: hubStateForError(presetError),
          titleTag: 'h3',
          title: described.title,
          description: formatErrorDescription(described),
          details: described.technical || undefined,
          action: {
            label: 'Повторить',
            onActivate: () => {
              void loadPresetFlow();
            },
          },
        }),
      );
    }

    const nameValidation = validateDomainName(domainName);
    const nameHintText =
      domainName.trim() && !nameValidation.valid && nameValidation.reason
        ? nameValidation.reason
        : undefined;

    const compositeWrap = document.createElement('div');
    compositeWrap.className = 'hub-domain__name-composite';
    compositeWrap.appendChild(
      createTextField({
        id: 'hub-domain-name',
        label: 'Имя домена',
        value: domainName,
        disabled: controlsLocked() || offline,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            domainName = event.target.value;
            onDomainNameOrSuffixSoftChange();
          }
        },
      }),
    );
    compositeWrap.appendChild(
      createSelectField({
        id: 'hub-domain-suffix',
        label: 'Домен',
        value: domainSuffix,
        disabled: controlsLocked() || offline,
        options: KEENDNS_DOMAIN_OPTIONS.map((item) => ({
          value: item.value,
          label: item.label,
        })),
        onChange: (event) => {
          if (event.target instanceof HTMLSelectElement) {
            domainSuffix = event.target.value;
            onDomainNameOrSuffixSoftChange();
          }
        },
      }),
    );
    const suffixField = compositeWrap.querySelector('#hub-domain-suffix')?.closest('.hub-field');
    if (suffixField) {
      suffixField.classList.add('hub-field--suffix');
    }
    const nameHintEl = document.createElement('p');
    nameHintEl.id = 'hub-domain-name-hint';
    nameHintEl.className = 'hub-domain__note';
    nameHintEl.hidden = !nameHintText;
    if (nameHintText) {
      nameHintEl.textContent = nameHintText;
    }
    body.appendChild(compositeWrap);
    body.appendChild(nameHintEl);

    const domainListNote = document.createElement('p');
    domainListNote.className = 'hub-domain__note';
    domainListNote.textContent =
      'Список доменов взят из документации и не подтверждён на этом устройстве — перед регистрацией проверьте список разрешённых доменов на роутере.';
    body.appendChild(domainListNote);

    const localAppField = createSelectField({
      id: 'hub-domain-local-app',
      label: 'Локальное приложение',
      value: 'orders',
      disabled: true,
      options: [{ value: 'orders', label: 'Система заказов' }],
    });
    body.appendChild(localAppField);
    const localAppNote = document.createElement('p');
    localAppNote.id = 'hub-domain-local-app-note';
    localAppNote.className = 'hub-domain__note';
    localAppNote.textContent =
      'Доступно только приложение «Система заказов» — другие приложения этим экраном не настраиваются.';
    body.appendChild(localAppNote);
    const localAppSelect = localAppField.querySelector('#hub-domain-local-app');
    if (localAppSelect instanceof HTMLElement) {
      localAppSelect.setAttribute('aria-describedby', localAppNote.id);
    }

    const modeFieldWrap = document.createElement('div');
    modeFieldWrap.className = 'hub-domain__mode-field';
    modeFieldWrap.appendChild(
      createSelectField({
        id: 'hub-domain-access-mode',
        label: 'Режим доступа при регистрации',
        value: previewAccessMode,
        disabled: controlsLocked() || offline,
        options: KEENDNS_ACCESS_MODE_OPTIONS.map((item) => ({
          value: item.value,
          label: item.label,
        })),
        onChange: (event) => {
          if (event.target instanceof HTMLSelectElement) {
            previewAccessMode = event.target.value;
            renderAll();
          }
        },
      }),
    );
    const selectedModeOption = KEENDNS_ACCESS_MODE_OPTIONS.find(
      (item) => item.value === previewAccessMode,
    );
    const modeHint = document.createElement('p');
    modeHint.id = 'hub-domain-access-mode-note';
    modeHint.className = 'hub-domain__note';
    modeHint.textContent =
      selectedModeOption?.description
      ?? 'Режим по умолчанию — автоматический; перед одобрением заявки его нужно подтвердить.';
    modeFieldWrap.appendChild(modeHint);
    const modeSelect = modeFieldWrap.querySelector('#hub-domain-access-mode');
    if (modeSelect instanceof HTMLElement) {
      modeSelect.setAttribute('aria-describedby', modeHint.id);
    }
    body.appendChild(modeFieldWrap);

    const localDisabled = !readiness.allowed || controlsLocked() || offline;
    let localReason = readiness.allowed ? null : presetBlockedDescription();
    if (!localDisabled && !savedLocalOrderUrl && !localHostPort.trim()) {
      localReason = 'Адрес приложения не задан';
    }

    body.appendChild(
      createTextField({
        id: 'hub-domain-local-host',
        label: 'Локальный адрес приложения',
        value: localHostPort,
        placeholder: '192.168.1.10:8080',
        hint: 'В виде адрес:порт, например 192.168.1.10:8080',
        disabled: localDisabled,
        onInput: (event) => {
          if (event.target instanceof HTMLInputElement) {
            localHostPort = event.target.value;
            updateDraftDependentUi();
          }
        },
      }),
    );
    if (localReason && localDisabled) {
      const reasonEl = document.createElement('p');
      reasonEl.className = 'hub-domain__note';
      reasonEl.textContent = localReason;
      body.appendChild(reasonEl);
    }

    body.appendChild(
      createToggle({
        id: 'hub-domain-https',
        label: 'Защищённое соединение',
        checked: httpsEnabled,
        disabled: localDisabled,
        onChange: (checked) => {
          httpsEnabled = checked;
          if (!checked && !disposed) {
            ctx.showToast({
              tone: 'warning',
              title: 'Адрес без защиты',
              message: DOMAIN_PLAIN_HTTP_WARNING,
            });
          }
          updateDraftDependentUi();
        },
      }),
    );

    const saveDisabled = localDisabled || !localAddressDirty() || savingLocal;
    const saveBtn = createButton({
      label: savingLocal ? 'Сохраняем…' : 'Сохранить локальный адрес',
      variant: 'secondary',
      disabled: saveDisabled,
      onActivate: () => {
        openSaveLocalModal();
      },
    });
    saveBtn.id = 'hub-domain-save-local-btn';
    updateButtonBusyState(saveBtn, savingLocal, saveDisabled);
    const saveRow = document.createElement('div');
    saveRow.className = 'hub-domain__btn-row';
    saveRow.appendChild(saveBtn);
    let saveReason = null;
    if (localDisabled && !readiness.allowed) {
      saveReason = presetBlockedDescription();
    } else if (localDisabled && offline) {
      saveReason = 'Нет связи с сервером управления';
    } else if (localDisabled && controlsLocked() && !savingLocal) {
      saveReason = 'Дождитесь завершения текущей операции';
    } else if (!localAddressDirty()) {
      saveReason = 'Изменений нет — сохранять нечего.';
    }
    if (saveReason && saveDisabled) {
      const reasonEl = document.createElement('p');
      reasonEl.id = 'hub-domain-save-local-reason';
      reasonEl.className = 'hub-domain__action-reason';
      reasonEl.textContent = saveReason;
      saveRow.appendChild(reasonEl);
      saveBtn.setAttribute('aria-describedby', reasonEl.id);
    }
    body.appendChild(saveRow);

    /** @type {string[]} */
    const advancedLines = [];
    const previewDesc = previewResponse ? describePreview(previewResponse) : null;
    if (previewDesc) {
      advancedLines.push(previewDesc.message);
    }
    if (previewDesc && previewDesc.commandLines.length > 0) {
      advancedLines.push(...previewDesc.commandLines);
    } else if (!previewDesc || previewDesc.commandLines.length === 0) {
      advancedLines.push('Предпросмотр не запрашивался');
    }
    const statusDesc = statusDescription();
    if (statusDesc.notes.length > 0) {
      advancedLines.push('', 'Примечания статуса облачного имени:');
      advancedLines.push(...statusDesc.notes);
    }
    if (previewDesc) {
      const payload =
        previewResponse && typeof previewResponse === 'object'
          ? /** @type {Record<string, unknown>} */ (previewResponse)
          : null;
      const verificationStatus =
        payload && typeof payload.verification_status === 'string'
          ? payload.verification_status
          : null;
      if (verificationStatus) {
        advancedLines.push('', `verification_status: ${verificationStatus}`);
      }
      if (previewDesc.notes.length > 0) {
        advancedLines.push(...previewDesc.notes);
      }
    }
    advancedLines.push('', KEENDNS_NO_CONFIG_NOTE);

    body.appendChild(
      createTechnicalDetails({
        summary: 'Расширенные настройки',
        content: advancedLines.join('\n'),
      }),
    );

    return card;
  }

  function describeProbeRow(described, pendingReasonCode) {
    if (described) {
      return described;
    }
    return pendingReasonCode === 'host_http.pending'
      ? describeHostHttpProbe({ reason_code: pendingReasonCode })
      : pendingReasonCode === 'host_tls.pending'
        ? describeHostTlsProbe({ reason_code: pendingReasonCode })
        : describeHostInternetProbe({ reason_code: pendingReasonCode });
  }

  function describeActiveProbeRow(response, pendingReasonCode, probingActive) {
    if (response) {
      if (pendingReasonCode === 'host_http.pending') {
        return describeHostHttpProbe(response);
      }
      if (pendingReasonCode === 'host_tls.pending') {
        return describeHostTlsProbe(response);
      }
      return describeHostInternetProbe(response);
    }
    if (probingActive) {
      return {
        title:
          pendingReasonCode === 'host_http.pending'
            ? 'Локальное приложение'
            : pendingReasonCode === 'host_tls.pending'
              ? 'Сертификат локального приложения'
              : 'Интернет с компьютера оператора',
        hubState: HubState.LOADING,
        message: 'Проверка…',
        factState: 'unknown',
      };
    }
    return describeProbeRow(null, pendingReasonCode);
  }

  function renderProbeCard() {
    const card = createCard({
      title: 'Проверки с этого компьютера',
      titleTag: 'h2',
    });
    card.classList.add('hub-domain__probe-card');
    const body = card.querySelector('.hub-card__body') ?? card;

    const scope = document.createElement('p');
    scope.className = 'hub-domain__probe-scope';
    scope.textContent = DOMAIN_HOST_PROBE_SCOPE_LABEL;
    body.appendChild(scope);

    const disclaimer = document.createElement('p');
    disclaimer.className = 'hub-domain__note';
    disclaimer.textContent = PROBE_SCOPE_DISCLAIMER;
    body.appendChild(disclaimer);

    const rowsWrap = document.createElement('div');
    rowsWrap.className = 'hub-domain__probe-rows';
    rowsWrap.setAttribute('aria-live', 'polite');

    const httpDesc = describeActiveProbeRow(httpProbeResponse, 'host_http.pending', probing);
    const internetDesc = describeActiveProbeRow(
      internetProbeResponse,
      'host_internet.pending',
      probing,
    );
    const tlsDesc = describeActiveProbeRow(tlsProbeResponse, 'host_tls.pending', probing);

    rowsWrap.appendChild(renderProbeRow(httpDesc));
    rowsWrap.appendChild(renderProbeRow(internetDesc));
    rowsWrap.appendChild(renderProbeRow(tlsDesc));

    const forwardingRow = document.createElement('div');
    forwardingRow.className = 'hub-vpn__status-line';
    const forwardingLabel = document.createElement('div');
    forwardingLabel.className = 'hub-vpn__status-line-label';
    forwardingLabel.textContent = 'Переадресация';
    forwardingRow.appendChild(forwardingLabel);
    const forwardingValue = document.createElement('div');
    forwardingValue.className = 'hub-vpn__status-line-value';
    forwardingValue.appendChild(
      createInlineState({ state: HubState.UNSUPPORTED, title: 'Не поддерживается' }),
    );
    const forwardingMsg = document.createElement('p');
    forwardingMsg.className = 'hub-vpn__status-message';
    forwardingMsg.textContent = DOMAIN_FORWARDING_UNSUPPORTED_TEXT;
    forwardingValue.appendChild(forwardingMsg);
    forwardingRow.appendChild(forwardingValue);
    rowsWrap.appendChild(forwardingRow);

    const externalRow = document.createElement('div');
    externalRow.className = 'hub-vpn__status-line';
    const externalLabel = document.createElement('div');
    externalLabel.className = 'hub-vpn__status-line-label';
    externalLabel.textContent = 'Проверка из интернета';
    externalRow.appendChild(externalLabel);
    const externalValue = document.createElement('div');
    externalValue.className = 'hub-vpn__status-line-value';
    externalValue.appendChild(
      createInlineState({ state: HubState.UNSUPPORTED, title: 'Не поддерживается' }),
    );
    const externalMsg = document.createElement('p');
    externalMsg.className = 'hub-vpn__status-message';
    externalMsg.textContent = DOMAIN_EXTERNAL_CHECK_UNSUPPORTED_TEXT;
    externalValue.appendChild(externalMsg);
    externalRow.appendChild(externalValue);
    rowsWrap.appendChild(externalRow);

    body.appendChild(rowsWrap);

    if (probeError && !isAborted(probeError)) {
      const described = describeError(probeError);
      body.appendChild(
        createStatePanel({
          state: hubStateForError(probeError),
          titleTag: 'h3',
          title: described.title,
          description: formatErrorDescription(described),
          details: described.technical || undefined,
          action: {
            label: 'Повторить',
            onActivate: () => {
              void runProbes();
            },
          },
        }),
      );
    }

    const readiness = presetReadiness();
    const probeDisabled = !readiness.allowed || !presetRevisionId || probing || controlsLocked() || offline;
    let probeReason = null;
    if (!readiness.allowed) {
      probeReason = presetBlockedDescription();
    } else if (!presetRevisionId) {
      probeReason = 'Адрес приложения ещё не загружен.';
    } else if (offline) {
      probeReason = 'Нет связи с сервером управления';
    } else if (controlsLocked() && !probing) {
      probeReason = 'Дождитесь завершения текущей операции';
    }

    const probeBtn = createButton({
      label: probing ? 'Проверяем…' : 'Проверить доступность',
      variant: 'primary',
      disabled: probeDisabled,
      onActivate: () => {
        void runProbes();
      },
    });
    probeBtn.id = 'hub-domain-probe-btn';
    updateButtonBusyState(probeBtn, probing, probeDisabled);
    const probeRow = document.createElement('div');
    probeRow.className = 'hub-domain__btn-row';
    probeRow.appendChild(probeBtn);
    if (probeReason && probeDisabled) {
      const reasonEl = document.createElement('p');
      reasonEl.id = 'hub-domain-probe-action-reason';
      reasonEl.className = 'hub-domain__action-reason';
      reasonEl.textContent = probeReason;
      probeRow.appendChild(reasonEl);
      probeBtn.setAttribute('aria-describedby', reasonEl.id);
    }
    body.appendChild(probeRow);

    return card;
  }

  function renderLinkAccessCard() {
    const card = createCard({
      title: 'Доступ по ссылке',
      titleTag: 'h2',
    });
    card.classList.add('hub-domain__link-access-card');
    const body = card.querySelector('.hub-card__body') ?? card;
    const url = draftUrl();
    const linkReason = linkActionDisabledReason();

    const layout = document.createElement('div');
    layout.className = 'hub-domain__link-access';

    const qrSlot = document.createElement('div');
    qrSlot.className = 'hub-domain__link-access-qr';

    if (url) {
      const canvas = document.createElement('canvas');
      canvas.className = 'hub-wifi__qr-canvas hub-domain__qr-preview';
      canvas.setAttribute('role', 'img');
      canvas.setAttribute('aria-label', 'QR-код черновой ссылки');
      try {
        drawWifiQrCanvas(canvas, url, { moduleSize: 4 });
        qrSlot.appendChild(canvas);
      } catch {
        const note = document.createElement('p');
        note.className = 'hub-domain__note';
        note.textContent = 'Не удалось построить QR-код.';
        qrSlot.appendChild(note);
      }
      const qrCaption = document.createElement('p');
      qrCaption.className = 'hub-domain__note hub-domain__qr-caption';
      qrCaption.textContent = DOMAIN_DRAFT_LINK_NOTE;
      qrSlot.appendChild(qrCaption);
    } else {
      qrSlot.appendChild(
        createInlineState({
          state: HubState.EMPTY,
          title: 'Черновая ссылка недоступна',
        }),
      );
    }
    layout.appendChild(qrSlot);

    const actionsCol = document.createElement('div');
    actionsCol.className = 'hub-domain__link-access-actions';

    if (!url && linkReason) {
      const reasonEl = document.createElement('p');
      reasonEl.className = 'hub-domain__note';
      reasonEl.textContent = linkReason;
      actionsCol.appendChild(reasonEl);
    }

    const note = document.createElement('p');
    note.className = 'hub-domain__note';
    note.textContent = DOMAIN_DRAFT_LINK_NOTE;
    actionsCol.appendChild(note);

    const qrBtn = createButton({
      label: 'Показать QR-код',
      variant: 'secondary',
      disabled: !url || controlsLocked(),
      onActivate: openQrModal,
    });
    const shareBtn = createButton({
      label: 'Поделиться',
      variant: 'secondary',
      disabled: !url || controlsLocked() || offline,
      onActivate: handleShareLink,
    });
    actionsCol.appendChild(qrBtn);
    actionsCol.appendChild(shareBtn);
    layout.appendChild(actionsCol);
    body.appendChild(layout);

    return card;
  }

  function renderDemoBanner() {
    if (adapterMode !== 'fake') {
      return null;
    }
    return createDemoBanner({
      text:
        'Черновик ссылки и проверки с компьютера оператора доступны без живого роутера. Облачная публикация недоступна.',
      connectionHintPrefix:
        'Чтобы работать с живым устройством, завершите подключение на экране ',
      onNavigateToConnection: () => {
        ctx.navigate('connection');
      },
      wrapClassName: 'hub-domain__demo-banner hub-wifi__demo-banner',
    });
  }

  function renderFooter() {
    clearElement(footerLeft);
    clearElement(footerRight);

    if (previewing) {
      footerRight.appendChild(
        createStatePanel({
          state: HubState.CONNECTING,
          titleTag: 'h3',
          title: 'Готовим предпросмотр',
          description: 'Запрашиваем команды, которые будут переданы администратору.',
        }),
      );
    }

    if (savingLocal) {
      footerRight.appendChild(
        createStatePanel({
          state: HubState.CONNECTING,
          titleTag: 'h3',
          title: 'Сохраняем локальный адрес',
          description: 'Записываем новую версию настроек мероприятия на сервер управления.',
        }),
      );
    }

    const dropBtn = createButton({
      label: dropping ? 'Готовим…' : 'Отключить публикацию',
      variant: 'secondary',
      disabled: controlsLocked() || offline || dropping,
      onActivate: openDropConfirmModal,
    });
    footerLeft.appendChild(dropBtn);

    const previewBtn = createButton({
      label: previewing ? 'Готовим…' : 'Показать, что будет отправлено',
      variant: 'primary',
      disabled: controlsLocked() || offline || previewing,
      onActivate: () => {
        void runPreviewBooking();
      },
    });
    previewBtn.id = 'hub-domain-preview-btn';
    updateButtonBusyState(previewBtn, previewing, controlsLocked() || offline);

    const publishBtn = createButton({
      label: 'Опубликовать',
      variant: 'primary',
      disabled: controlsLocked() || offline || !validateDomainName(domainName).valid,
      onActivate: () => {
        openPublishApplyModal('book');
      },
    });

    footerRight.appendChild(previewBtn);
    footerRight.appendChild(publishBtn);
  }

  function buildBannerSignature() {
    return adapterMode === 'fake' ? 'fake' : 'live';
  }

  function buildHeaderSignature() {
    return [
      headerPrimaryLine(),
      headerStatusLine(),
      headerBadgeLabel(),
      controlsLocked() ? 'locked' : 'unlocked',
      offline ? 'offline' : 'online',
    ].join('|');
  }

  function buildMainSignature() {
    return [
      statusLoading ? 'status-loading' : statusRefreshing ? 'status-refreshing' : 'status-idle',
      presetLoading ? 'preset-loading' : presetRefreshing ? 'preset-refreshing' : 'preset-idle',
      statusError ? describeError(statusError).title : 'none',
      previewError ? describeError(previewError).title : 'none',
      operationError ? describeError(operationError).title : 'none',
      previewAccessMode,
      localHostPort,
      httpsEnabled ? 'https' : 'http',
      offline ? 'offline' : 'online',
      recovering ? 'recovering' : 'idle',
      presetReadiness().allowed ? 'ready' : 'blocked',
      siteHasEventPresets === null ? 'presets-unknown' : String(siteHasEventPresets),
      controlsLocked() ? 'locked' : 'unlocked',
    ].join('|');
  }

  function buildSideSignature() {
    return [
      probing ? 'probing' : 'idle',
      httpProbeResponse ? 'http-settled' : 'http-pending',
      tlsProbeResponse ? 'tls-settled' : 'tls-pending',
      internetProbeResponse ? 'internet-settled' : 'internet-pending',
      probeError ? describeError(probeError).title : 'none',
      draftUrl() ?? '',
      controlsLocked() ? 'locked' : 'unlocked',
    ].join('|');
  }

  function renderBannerSlot() {
    const signature = buildBannerSignature();
    if (signature === lastBannerSignature && bannerSlot.firstChild) {
      return;
    }
    lastBannerSignature = signature;
    rebuildSlot(bannerSlot, () => {
      const demoBanner = renderDemoBanner();
      if (demoBanner) {
        bannerSlot.appendChild(demoBanner);
      }
    });
  }

  function renderHeaderSlot() {
    const signature = buildHeaderSignature();
    if (signature === lastHeaderSignature && headerSlot.firstChild) {
      return;
    }
    lastHeaderSignature = signature;
    rebuildSlot(headerSlot, () => {
      headerSlot.appendChild(renderNetworkHeader());
    });
  }

  function renderMainSlot() {
    const signature = buildMainSignature();
    if (signature === lastMainSignature && mainCol.firstChild) {
      return;
    }
    lastMainSignature = signature;
    rebuildSlot(mainCol, () => {
      if (offline && !recovering) {
        mainCol.appendChild(
          createStatePanel({
            state: HubState.NO_INTERNET,
            titleTag: 'h2',
            action: {
              label: 'Повторить',
              onActivate: () => {
                void loadStatusFlow();
                void loadPresetFlow();
              },
            },
          }),
        );
      }

      if (recovering) {
        mainCol.appendChild(
          createInlineState({
            state: HubState.RECOVERING,
            title: 'Восстанавливаем связь с сервером управления',
          }),
        );
      }

      if (statusError && !statusLoading && !isAborted(statusError)) {
        const described = describeError(statusError);
        mainCol.appendChild(
          createStatePanel({
            state: hubStateForError(statusError),
            titleTag: 'h2',
            title: described.title,
            description: formatErrorDescription(described),
            details: described.technical || undefined,
            action: {
              label: 'Повторить',
              onActivate: () => {
                void loadStatusFlow();
              },
            },
          }),
        );
      }

      if (previewError && !isAborted(previewError)) {
        const described = describeError(previewError);
        mainCol.appendChild(
          createStatePanel({
            state: hubStateForError(previewError),
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

      if (operationError && !isAborted(operationError) && operationError !== previewError && operationError !== probeError) {
        const described = describeError(operationError);
        mainCol.appendChild(
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

      mainCol.appendChild(renderSimplePublishSection());
      mainCol.appendChild(renderSettingsCard());
    });
  }

  function renderSideSlot() {
    const signature = buildSideSignature();
    if (signature === lastSideSignature && sideCol.firstChild) {
      return;
    }
    lastSideSignature = signature;
    rebuildSlot(sideCol, () => {
      sideCol.appendChild(renderProbeCard());
      sideCol.appendChild(renderLinkAccessCard());
    });
  }

  function renderContent() {
    mountLayoutOnce();
    renderBannerSlot();
    renderHeaderSlot();
    renderMainSlot();
    renderSideSlot();
    syncContentLayoutClasses();
  }

  function renderAll() {
    if (disposed) {
      return;
    }
    renderContent();
    syncSimpleAffordanceDisabled();
    renderFooter();
    restorePendingFocus();
  }

  const unsubConnectivity = subscribeConnectivity((online) => {
    if (disposed) {
      return;
    }
    if (!online) {
      offline = true;
      recovering = false;
      invalidateOperations();
      renderAll();
      return;
    }
    offline = false;
    recovering = true;
    renderAll();
    if (!previewing && !probing && !savingLocal && !dropping) {
      void Promise.all([
        loadStatusFlow(),
        loadPresetFlow(),
        loadEventPresetsAvailabilityFlow(),
      ]).finally(() => {
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

  const unsubSession = subscribeSession((snapshot) => {
    if (disposed) {
      return;
    }
    const nextPresetId = snapshot.eventPresetId ?? null;
    if (nextPresetId === trackedEventPresetId) {
      return;
    }
    trackedEventPresetId = nextPresetId;
    presetGeneration += 1;
    invalidateOperationConcern();
    resetPresetDerivedState();
    closeAllModals();
    renderAll();
    void loadPresetFlow();
  });

  renderAll();
  void loadStatusFlow();
  void loadPresetFlow();
  void loadEventPresetsAvailabilityFlow();

  return () => {
    disposed = true;
    destroySimpleAffordance();
    invalidateOperations();
    closeAllModals();
    unsubConnectivity();
    unsubSession();
  };
}
