import {
  createBadge,
  createButton,
  createIcon,
  createTextField,
  openModal,
} from '../components/index.js';
import { apiGet, subscribeConnectivity } from '../core/api.js';
import { readInputEventValue } from '../core/form-submit-sync.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import {
  getSession,
  isConnectionRestorePending,
  subscribeSession,
  waitForConnectionRestoreSettle,
  retryConnectionContextRestore,
} from '../core/session.js';
import {
  isConnectionRestoreFailed,
  liveCapabilitySubscriptionKey,
  needsManagementUsernameRecovery,
} from '../features/live-connection-params.js';
import { submitManagementUsername } from '../features/connection-flow.js';
import {
  HubState,
  createInlineState,
  createProgressPanel,
  createSkeleton,
  createStatePanel,
} from '../core/states.js';
import { loadOverview, applyVerdictToRouterSection } from '../features/overview-model.js';
import { fetchRouterInternetObserve } from '../features/diagnostics-model.js';
import { mountOverviewSimpleNetworks } from '../features/overview-simple-networks.js';
import {
  mountDomainSimplePublishAffordance,
  openDomainPublishApplyConfirm,
} from '../features/domain-simple-publish.js';
import {
  applyKeendnsBooking,
  KEENDNS_DEFAULT_ACCESS_MODE,
  resolveDomainSimpleDefaultName,
  probeOperatorHostInternet,
} from '../features/domain-model.js';
import { fetchRememberedUplink } from '../features/uplink-wifi-model.js';
import {
  isEthernetLikeGatewayInterface,
  isWifiStationGatewayInterface,
  isWireguardGatewayInterface,
} from '../features/internet-source-block.js';
import {
  activateVpnProfile,
  deactivateVpnProfile,
  fetchVpnCatalogLiveStatus,
  listVpnProfiles,
  listVpnTunnelInterfaceOptions,
} from '../features/vpn-model.js';
import {
  buildDomainStatusCard,
  buildDiagnosticsStatusCard,
  buildEntryPagesStatusCard,
  buildInternetStatusCard,
  buildOverviewReadinessHeader,
  buildOverviewStatusStrip,
  buildOverviewStepCardSkeleton,
  buildOverviewVpnProfilePicker,
  buildRouterConnectionStatusCard,
  buildVpnStatusCardShell,
  computeOverviewReadiness,
  createOverviewGrid,
  createOverviewGridItem,
  vpnDeriveCardStatus,
  wireOverviewCardNavigate,
} from '../features/overview-card-grid.js';
import { runSystemCheck, SystemCheckLevel, SYSTEM_CHECK_TRANSIENT_MAX_ATTEMPTS } from '../features/system-check.js';
export const meta = {
  id: 'overview',
  title: 'Обзор',
  iconName: 'overview',
};
/** @typedef {import('../features/overview-model.js').OverviewModel} OverviewModel */
/** @typedef {import('../features/overview-model.js').OverviewSection} OverviewSection */
// Full router refresh (touches the router over SSH for system-check + internet-status + wifi/observed-state + vpn catalog) — kept infrequent to avoid overloading the router's own SSH daemon with concurrent sessions; a lightweight host-only heartbeat (see HOST_INTERNET_HEARTBEAT_INTERVAL_MS below) fills the gap and can trigger an early full refresh on a detected outage.
const REFRESH_INTERVAL_MS = 300000;
// Cheap host-side internet reachability check (no router SSH at all) — keeps the UI feeling responsive between full router refreshes and triggers an early full refresh the moment internet appears to actually drop.
const HOST_INTERNET_HEARTBEAT_INTERVAL_MS = 60000;
const OVERVIEW_SECONDARY_ENTRY_PAGES_LABEL = 'Страницы входа';
const OVERVIEW_ENTRY_PAGES_ROUTE_HREF = '#/entry-pages';
const OVERVIEW_SECONDARY_DIAGNOSTICS_LABEL = 'Диагностика';
const OVERVIEW_DIAGNOSTICS_ROUTE_HREF = '#/diagnostics';
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
 * Returns true when host heartbeat detects internet went from reachable to unreachable.
 * @param {boolean|null} lastReachable
 * @param {boolean|null} reachable
 * @returns {boolean}
 */
export function shouldRequestOverviewReloadOnHostHeartbeat(lastReachable, reachable) {
  return lastReachable === true && reachable === false;
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
 * @param {string} iso
 * @returns {string}
 */
function formatUpdatedAt(iso) {
  const date = new Date(iso);
  const time = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  return `Обновлено в ${time}`;
}
/**
 * @param {string} iso
 * @returns {string}
 */
function formatSystemCheckAt(iso) {
  const time = new Date(iso).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  return `Проверка связи: ${time}`;
}
/**
 * @param {import('../features/system-check.js').SystemCheckVerdict|null} verdict
 * @param {unknown|null} error
 * @returns {OverviewSection}
 */
function systemCheckSectionFromVerdict(verdict, error) {
  if (error) {
    if (isAborted(error)) {
      return {
        state: HubState.WARNING,
        title: 'Готовность не определена',
        subtitle: null,
        badge: null,
        note: null,
        technical: null,
        error: error instanceof HubApiError ? error : null,
        route: null,
        mock: false,
      };
    }
    const described = describeError(error);
    return {
      state: hubStateForError(error),
      title: described.title,
      subtitle: described.message,
      badge: null,
      note: null,
      technical: null,
      error: error instanceof HubApiError ? error : null,
      route: null,
      mock: false,
    };
  }
  if (!verdict) {
    return {
      state: HubState.WARNING,
      title: 'Готовность не определена',
      subtitle: null,
      badge: null,
      note: null,
      technical: null,
      error: null,
      route: null,
      mock: false,
    };
  }
  return {
    state: verdict.hubState,
    title: verdict.title,
    subtitle: verdict.description,
    badge: { label: verdict.badgeLabel, tone: verdict.badgeTone },
    note: verdict.mockNote,
    technical: null,
    error: null,
    route: null,
    mock: verdict.mock,
    checkedAt: verdict.checkedAt instanceof Date ? verdict.checkedAt.toISOString() : null,
  };
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
 * @param {import('../features/system-check.js').SystemCheckVerdict|null} verdict
 * @param {unknown|null} error
 * @param {(options: object) => void} showToast
 */
function showSystemCheckToast(verdict, error, showToast) {
  if (error) {
    if (isAborted(error)) {
      return;
    }
    const described = describeError(error);
    showToast({
      tone: 'danger',
      title: described.title,
      message: described.message,
    });
    return;
  }
  if (!verdict) {
    return;
  }
  /** @type {'success'|'warning'|'danger'} */
  let tone = 'warning';
  if (verdict.level === SystemCheckLevel.READY) {
    tone = 'success';
  } else if (
    verdict.level === SystemCheckLevel.NOT_READY
    || verdict.level === SystemCheckLevel.FAILED
  ) {
    tone = 'danger';
  }
  showToast({
    tone,
    title: verdict.title,
    message: verdict.description ?? verdict.badgeLabel,
  });
}
/**
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 * @param {boolean} isOffline
 */
function updateButtonBusyState(button, busy, isOffline) {
  button.disabled = busy || isOffline;
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
 * @param {HTMLElement} container
 * @param {{ runtime: object, navigate: (routeId: string) => void, showToast: (options: object) => void }} ctx
 * @returns {() => void}
 */
export function render(container, ctx) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }
  /** @type {OverviewModel|null} */
  let model = null;
  /** @type {unknown|null} */
  let loadError = null;
  let loading = false;
  let generation = 0;
  /** @type {string|null} */
  let activeRouterId = null;
  /** @type {AbortController|null} */
  let loadAbort = null;
  /** @type {AbortController|null} */
  let systemCheckAbort = null;
  /** @type {AbortController|null} */
  let internetObserveAbort = null;
  /** @type {import('../features/diagnostics-model.js').RouterInternetObservePayload|null} */
  let routerInternetObserve = null;
  let refreshBusy = false;
  let systemCheckRunning = false;
  /** @type {number|null} */
  let refreshBusyGeneration = null;
  /** @type {number|null} */
  let loadingGeneration = null;
  /** @type {number|null} */
  let systemCheckRunningGeneration = null;
  /** @type {string|null} */
  let lastRouterCardSignature = null;
  let lastInternetCardSignature = null;
  let lastReadinessSignature = null;
  let lastStatusStripSignature = null;
  /** @type {string|null} */
  let lastDomainCardSignature = null;
  /** @type {string|null} */
  let lastSummarySignature = null;
  /** @type {string|null} */
  let lastVpnSignature = null;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;
  let recovering = false;
  let disposed = false;
  /** @type {Promise<number|null>|null} */
  let restoreSettleLoadPromise = null;
  /** @type {Promise<number|null>|null} */
  let inFlightReloadPromise = null;
  /** @type {(HTMLElement & { update: (opts: object) => void })|null} */
  let activeProgressPanel = null;
  let managementUsernameDraft = '';
  let savingManagementUsername = false;
  /** @type {unknown|null} */
  let managementUsernameError = null;
  const OVERVIEW_MANAGEMENT_USERNAME_SAVE_BTN_ID = 'hub-overview-management-username-save';
  /** @type {AbortController|null} */
  let enrichmentAbort = null;
  /** @type {import('../features/uplink-wifi-model.js').RememberedUplinkPref|null} */
  let rememberedUplink = null;
  let internetEnrichmentBusy = false;
  let vpnEnrichmentBusy = false;
  let vpnCatalogSettled = false;
  /** @type {Array<Record<string, unknown>>} */
  let vpnCatalogItems = [];
  /** @type {Record<string, { live_probed?: boolean, live_tunnel_verification_status?: string|null, probe_error?: string|null, observed_at?: string|null, routed_through_tunnel?: boolean|null, routing_probe_status?: string|null }>} */
  let vpnLiveStatusById = {};
  /** @type {Record<string, string>} */
  let vpnActivatingProfileIds = {};
  /** @type {Record<string, string>} */
  let vpnDeactivatingProfileIds = {};
  /** @type {Record<string, string>} */
  let vpnCheckingProfileIds = {};
  let vpnMutating = false;
  /** @type {string|null} */
  let vpnSelectedProfileId = null;
  /** @type {string|null} */
  let lastVpnActiveProfileId = null;
  let domainDraftName = resolveDomainSimpleDefaultName();
  let domainDraftSuffix = 'netcraze.pro';
  /** @type {import('../features/system-check.js').DescribedFact[]|null} */
  let lastSystemCheckFacts = null;
  /** @type {ReturnType<typeof mountOverviewSimpleNetworks>|null} */
  let networksMount = null;
  /** @type {ReturnType<typeof mountDomainSimplePublishAffordance>|null} */
  let domainMount = null;
  /** @type {{ kind: string, id?: string, selectionStart?: number, selectionEnd?: number }|null} */
  let pendingFocus = null;
  /** @type {ReturnType<typeof setInterval>|null} */
  let refreshInterval = null;
  /** @type {ReturnType<typeof setInterval>|null} */
  let heartbeatInterval = null;
  /** @type {boolean|null} */
  let lastHeartbeatReachable = null;
  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-overview';
  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.textContent = 'Сеть и роутер';
  header.appendChild(title);
  const headerActions = document.createElement('div');
  headerActions.className = 'hub-overview__header-actions';
  const updatedEl = document.createElement('p');
  updatedEl.className = 'hub-overview__updated';
  updatedEl.hidden = true;
  const refreshSlot = document.createElement('div');
  refreshSlot.className = 'hub-overview__refresh-slot';
  const refreshButton = createButton({
    label: 'Обновить',
    variant: 'secondary',
    iconName: 'refresh',
    busy: false,
    onActivate: () => {
      void requestReloadOverview();
    },
  });
  refreshSlot.appendChild(refreshButton);
  headerActions.appendChild(refreshSlot);
  headerActions.appendChild(updatedEl);
  header.appendChild(headerActions);
  screen.appendChild(header);
  const connectionBannerWrap = document.createElement('div');
  connectionBannerWrap.className = 'hub-overview__connection-banner';
  screen.appendChild(connectionBannerWrap);
  const summaryWrap = document.createElement('div');
  summaryWrap.className = 'hub-overview__summary';
  screen.appendChild(summaryWrap);
  const readinessHeaderWrap = document.createElement('div');
  readinessHeaderWrap.className = 'hub-overview__readiness-header-wrap';
  screen.appendChild(readinessHeaderWrap);
  const grid = createOverviewGrid();
  screen.appendChild(grid);
  const routerGridItem = createOverviewGridItem('router');
  grid.appendChild(routerGridItem);
  const routerCardSlot = document.createElement('div');
  routerCardSlot.className = 'hub-overview__router-card-slot';
  routerGridItem.appendChild(routerCardSlot);
  const internetGridItem = createOverviewGridItem('internet');
  grid.appendChild(internetGridItem);
  const internetCardSlot = document.createElement('div');
  internetCardSlot.className = 'hub-overview__internet-card-slot';
  internetGridItem.appendChild(internetCardSlot);
  // Ordered right after Internet (not after networks) so Router/Internet/VPN always
  // form one clean 3-column row — staff/guest/entry-pages/diagnostics follow below Domain.
  // F-c2-4: kindLabel on VPN tiles comes from vpn-model tile internals — not forked here.
  const vpnGridItem = createOverviewGridItem('vpn');
  grid.appendChild(vpnGridItem);
  const vpnWrap = document.createElement('div');
  vpnWrap.className = 'hub-overview__vpn';
  vpnGridItem.appendChild(vpnWrap);
  const domainGridItem = createOverviewGridItem('domain');
  grid.appendChild(domainGridItem);
  const domainWrap = document.createElement('div');
  domainWrap.className = 'hub-overview__domain';
  domainGridItem.appendChild(domainWrap);
  const domainCardSlot = document.createElement('div');
  domainCardSlot.className = 'hub-overview__domain-card-slot';
  domainWrap.appendChild(domainCardSlot);
  const domainMountSlot = document.createElement('div');
  domainMountSlot.className = 'hub-overview__domain-mount-slot';
  domainWrap.appendChild(domainMountSlot);
  const staffGridItem = createOverviewGridItem('staff');
  grid.appendChild(staffGridItem);
  const staffSlot = document.createElement('div');
  staffSlot.className = 'hub-overview__staff-slot';
  staffGridItem.appendChild(staffSlot);
  const guestGridItem = createOverviewGridItem('guest');
  grid.appendChild(guestGridItem);
  const guestSlot = document.createElement('div');
  guestSlot.className = 'hub-overview__guest-slot';
  guestGridItem.appendChild(guestSlot);
  const entryPagesGridItem = createOverviewGridItem('entry-pages');
  grid.appendChild(entryPagesGridItem);
  const entryPagesSlot = document.createElement('div');
  entryPagesSlot.className = 'hub-overview__entry-pages-slot';
  entryPagesGridItem.appendChild(entryPagesSlot);
  const diagnosticsGridItem = createOverviewGridItem('diagnostics');
  grid.appendChild(diagnosticsGridItem);
  const diagnosticsSlot = document.createElement('div');
  diagnosticsSlot.className = 'hub-overview__diagnostics-slot';
  diagnosticsGridItem.appendChild(diagnosticsSlot);
  const statusStripWrap = document.createElement('div');
  statusStripWrap.className = 'hub-overview__status-strip-wrap';
  screen.appendChild(statusStripWrap);
  container.appendChild(screen);
  /**
   * @param {AbortSignal|undefined} signal
   * @returns {Promise<string|null>}
   */
  async function resolveRouterId(signal) {
    const session = getSession();
    if (session.routerId) {
      return session.routerId;
    }
    try {
      const routersData = /** @type {{ items?: Array<{ router_id?: string }> }} */ (
        await apiGet('routers', { signal, retry: 1 })
      );
      const items = routersData?.items ?? [];
      return items[0]?.router_id ?? null;
    } catch (error) {
      if (isAborted(error)) {
        throw error;
      }
      if (!disposed) {
        const described = describeError(error);
        ctx.showToast({
          tone: 'danger',
          title: described.title,
          message: described.message,
        });
      }
      throw error;
    }
  }
  function updateRefreshButton() {
    if (disposed) {
      return;
    }
    updateButtonBusyState(refreshButton, refreshBusy, offline);
  }
  function clearContainer(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }
  function restorePendingFocus() {
    if (!pendingFocus) {
      return;
    }
    const target = pendingFocus;
    pendingFocus = null;
    if (target.kind === 'summary-action-retry') {
      const active = document.activeElement;
      const usernameInput = connectionBannerWrap.querySelector('#hub-overview-management-username');
      if (
        active instanceof HTMLElement
        && (connectionBannerWrap.contains(active) || active === usernameInput)
      ) {
        return;
      }
      const actionBtn = summaryWrap.querySelector('.hub-state-action--primary, .hub-state-action');
      if (actionBtn instanceof HTMLElement) {
        actionBtn.focus();
      }
      return;
    }
    if (target.kind === 'element-id' && target.id) {
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
            // ignore invalid selection on some input types
          }
        }
      }
    }
  }
  /**
   * @param {() => void} rebuild
   */
  function rebuildConnectionBannerSlot(rebuild) {
    const active = document.activeElement;
    if (active instanceof HTMLElement && connectionBannerWrap.contains(active)) {
      if (active.id) {
        /** @type {{ kind: 'element-id', id: string, selectionStart?: number, selectionEnd?: number }} */
        const focus = { kind: 'element-id', id: active.id };
        if (active instanceof HTMLInputElement) {
          focus.selectionStart = active.selectionStart;
          focus.selectionEnd = active.selectionEnd;
        }
        pendingFocus = focus;
      }
    }
    clearContainer(connectionBannerWrap);
    rebuild();
    restorePendingFocus();
  }
  /**
   * @param {HTMLElement} panel
   * @param {string} actionId
   */
  function assignPrimaryActionId(panel, actionId) {
    const actionBtn = panel.querySelector('.hub-state-action--primary');
    if (actionBtn instanceof HTMLElement) {
      actionBtn.id = actionId;
    }
  }
  function syncOverviewManagementUsernameFormUi() {
    const input = connectionBannerWrap.querySelector('#hub-overview-management-username');
    if (input instanceof HTMLInputElement) {
      if (offline) {
        input.disabled = true;
        input.readOnly = false;
      } else {
        input.disabled = false;
        input.readOnly = savingManagementUsername;
      }
    }
    const saveBtn = connectionBannerWrap.querySelector(`#${OVERVIEW_MANAGEMENT_USERNAME_SAVE_BTN_ID}`);
    if (saveBtn instanceof HTMLButtonElement) {
      updateButtonBusyState(
        saveBtn,
        savingManagementUsername,
        offline || !managementUsernameDraft.trim(),
      );
    }
  }
  function syncOverviewManagementUsernameInPlace() {
    const input = connectionBannerWrap.querySelector('#hub-overview-management-username');
    if (input instanceof HTMLInputElement) {
      if (document.activeElement === input) {
        managementUsernameDraft = input.value;
      } else if (input.value !== managementUsernameDraft) {
        input.value = managementUsernameDraft;
      }
    }
    syncOverviewManagementUsernameFormUi();
  }
  /**
   * @param {string} label
   * @param {number} [attempt]
   * @param {number} [maxAttempts]
   */
  function captureSummaryPendingFocus() {
    const active = document.activeElement;
    if (!(active instanceof HTMLElement) || !summaryWrap.contains(active)) {
      return;
    }
    if (active.id) {
      /** @type {{ kind: 'element-id', id: string, selectionStart?: number, selectionEnd?: number }} */
      const focus = { kind: 'element-id', id: active.id };
      if (active instanceof HTMLInputElement) {
        focus.selectionStart = active.selectionStart;
        focus.selectionEnd = active.selectionEnd;
      }
      pendingFocus = focus;
      return;
    }
    const actionBtn = summaryWrap.querySelector('.hub-state-action--primary, .hub-state-action');
    if (actionBtn instanceof HTMLElement && (active === actionBtn || actionBtn.contains(active))) {
      pendingFocus = { kind: 'summary-action-retry' };
    }
  }
  function showRestoreOrProbeProgress(label, attempt = 1, maxAttempts = 1) {
    if (disposed) {
      return;
    }
    const signature = `progress|${label}|${attempt}|${maxAttempts}`;
    if (activeProgressPanel && lastSummarySignature === signature) {
      activeProgressPanel.update({ label });
      return;
    }
    lastSummarySignature = signature;
    captureSummaryPendingFocus();
    clearContainer(summaryWrap);
    activeProgressPanel = createProgressPanel({
      mode: 'indeterminate',
      label,
    });
    summaryWrap.appendChild(activeProgressPanel);
  }
  function clearRestoreOrProbeProgress() {
    activeProgressPanel = null;
  }
  async function retryRestoreConnection() {
    if (disposed || offline) {
      return;
    }
    showRestoreOrProbeProgress('Проверяем сохранённое подключение');
    try {
      await retryConnectionContextRestore(undefined);
      await ensureOverviewLoadedAfterRestore();
    } catch (error) {
      if (!disposed && !isAborted(error)) {
        renderConnectionBanner();
        renderSummary();
      }
    }
  }
  async function submitOverviewManagementUsername() {
    const session = getSession();
    const routerId = session.routerId ?? activeRouterId;
    const username = managementUsernameDraft.trim();
    if (!routerId || !username || savingManagementUsername || offline) {
      return;
    }
    const usernameInput = connectionBannerWrap.querySelector('#hub-overview-management-username');
    if (usernameInput instanceof HTMLInputElement && document.activeElement === usernameInput) {
      pendingFocus = {
        kind: 'element-id',
        id: usernameInput.id,
        selectionStart: usernameInput.selectionStart,
        selectionEnd: usernameInput.selectionEnd,
      };
    }
    savingManagementUsername = true;
    managementUsernameError = null;
    renderConnectionBanner();
    const usernameInputAfterRender = connectionBannerWrap.querySelector('#hub-overview-management-username');
    if (
      usernameInputAfterRender instanceof HTMLInputElement
      && document.activeElement === usernameInputAfterRender
    ) {
      pendingFocus = null;
    }
    try {
      await submitManagementUsername({ routerId, username });
      managementUsernameDraft = '';
      pendingFocus = null;
      await requestReloadOverview();
    } catch (error) {
      if (!isAborted(error)) {
        managementUsernameError = error;
      }
    } finally {
      savingManagementUsername = false;
      if (!disposed) {
        renderConnectionBanner();
      }
    }
  }
  /**
   * @returns {Promise<number|null>}
   */
  async function ensureOverviewLoadedAfterRestore() {
    if (disposed) {
      return null;
    }
    const session = getSession();
    if (!isConnectionRestorePending(session)) {
      return reloadOverviewInternal();
    }
    if (restoreSettleLoadPromise) {
      return restoreSettleLoadPromise;
    }
    restoreSettleLoadPromise = (async () => {
      try {
        showRestoreOrProbeProgress('Проверяем сохранённое подключение');
        renderConnectionBanner();
        await waitForConnectionRestoreSettle({});
        if (disposed) {
          return null;
        }
        return await reloadOverviewInternal();
      } catch (error) {
        clearRestoreOrProbeProgress();
        if (!disposed && !isAborted(error)) {
          loadError = error;
          model = null;
          lastSummarySignature = null;
          renderAll();
        }
        return null;
      } finally {
        restoreSettleLoadPromise = null;
      }
    })();
    return restoreSettleLoadPromise;
  }
  /**
   * @returns {Promise<number|null>}
   */
  async function requestReloadOverview() {
    if (disposed) {
      return null;
    }
    if (isConnectionRestorePending(getSession())) {
      return ensureOverviewLoadedAfterRestore();
    }
    return reloadOverviewInternal();
  }
  function renderOfflineNoModelPanel() {
    if (disposed) {
      return;
    }
    clearContainer(summaryWrap);
    summaryWrap.appendChild(
      createStatePanel({
        state: HubState.NO_INTERNET,
        titleTag: 'h2',
        action: {
          label: 'Повторить',
          onActivate: () => {
            void requestReloadOverview();
          },
        },
      }),
    );
    lastSummarySignature = `offline-no-model|${HubState.NO_INTERNET}`;
  }
  /**
   * @param {OverviewSection} section
   * @param {{ state: string, title?: string, description?: string }} panelOptions
   * @returns {string}
   */
  function buildSummaryContentSignature(section, panelOptions) {
    const hasError = section.error && !isAborted(section.error);
    const showLiveDevice = ctx.runtime?.adapterMode === 'live'
      && section.state === HubState.SUCCESS
      && !offline
      && !recovering
      && !systemCheckRunning;
    return [
      panelOptions.state,
      hasError ? describeError(section.error).title : section.title,
      hasError ? describeError(section.error).message : panelOptions.description ?? '',
      section.badge?.label ?? '',
      section.badge?.tone ?? '',
      section.checkedAt ?? '',
      section.mock ? '1' : '0',
      section.note ?? '',
      panelOptions.action?.label ?? '',
      showLiveDevice ? '1' : '0',
      offline ? '1' : '0',
      recovering ? '1' : '0',
      systemCheckRunning ? '1' : '0',
      loadError && !model ? 'load-error' : '',
      loading && !model ? 'loading' : '',
    ].join('|');
  }
  function renderSummarySkeleton() {
    if (disposed) {
      return;
    }
    clearContainer(summaryWrap);
    summaryWrap.appendChild(
      createInlineState({ state: HubState.LOADING, title: 'Загружаем состояние системы' }),
    );
    summaryWrap.appendChild(createSkeleton({ lines: 2, withTitle: true }));
  }
  function renderLoadErrorPanel() {
    if (disposed || !loadError) {
      return;
    }
    const described = describeError(loadError);
    const state = hubStateForLoadError(loadError, offline);
    summaryWrap.appendChild(
      createStatePanel({
        state,
        titleTag: 'h2',
        title: described.title,
        description: described.message,
        details: described.technical,
        action: {
          label: 'Повторить',
          onActivate: () => {
            void requestReloadOverview();
          },
        },
      }),
    );
  }
  function buildOverviewReadinessContext() {
    const vpnItems = vpnCatalogItems.map((item) => {
      const payload = /** @type {Record<string, unknown>} */ (item ?? {});
      const profileId =
        typeof payload.profile_id === 'string' ? payload.profile_id : '';
      const isActive = payload.is_active === true;
      const live = isActive && profileId ? vpnLiveStatusById[profileId] : null;
      return {
        is_active: isActive,
        routed_through_tunnel: live?.routed_through_tunnel ?? null,
      };
    });
    return {
      routerInternetObserve,
      vpnItems,
      domainDraftName,
      eventPresetId: getSession().eventPresetId ?? null,
      internetEnrichmentBusy,
      vpnEnrichmentBusy,
      systemCheckRunning,
    };
  }

  function renderReadinessHeader() {
    if (disposed) {
      return;
    }
    const readiness = computeOverviewReadiness(model, buildOverviewReadinessContext());
    const ringLoading =
      (loading && !model)
      || systemCheckRunning
      || internetEnrichmentBusy
      || vpnEnrichmentBusy
      || !readiness.loaded;
    const signature = [
      readiness.loaded ? '1' : '0',
      readiness.ready ?? 'null',
      loading && !model ? 'loading' : '',
      systemCheckRunning ? '1' : '0',
      internetEnrichmentBusy ? '1' : '0',
      vpnEnrichmentBusy ? '1' : '0',
    ].join('|');
    if (signature === lastReadinessSignature && readinessHeaderWrap.firstChild) {
      return;
    }
    lastReadinessSignature = signature;
    clearContainer(readinessHeaderWrap);
    readinessHeaderWrap.appendChild(
      buildOverviewReadinessHeader({
        readiness,
        loading: ringLoading,
      }),
    );
  }

  function renderStatusStrip() {
    if (disposed) {
      return;
    }
    const readiness = computeOverviewReadiness(model, buildOverviewReadinessContext());
    const signature = [
      readiness.loaded ? '1' : '0',
      readiness.ready ?? 'null',
      readiness.categories.router ? '1' : '0',
      readiness.categories.internet ? '1' : '0',
      readiness.categories.vpn ? '1' : '0',
      readiness.categories.domain ? '1' : '0',
      systemCheckRunning ? '1' : '0',
      internetEnrichmentBusy ? '1' : '0',
      vpnEnrichmentBusy ? '1' : '0',
      offline ? '1' : '0',
    ].join('|');
    if (signature === lastStatusStripSignature && statusStripWrap.firstChild) {
      return;
    }
    lastStatusStripSignature = signature;
    clearContainer(statusStripWrap);
    statusStripWrap.appendChild(
      buildOverviewStatusStrip({
        categories: readiness.categories,
        loaded: readiness.loaded,
        checkBusy: systemCheckRunning,
        onCheckAll: () => {
          void runSystemCheckOnly();
        },
      }),
    );
  }

  function mountOverviewActionSlots() {
    if (networksMount) {
      return;
    }
    networksMount = mountOverviewSimpleNetworks({
      staffSlot,
      guestSlot,
      getSession,
      adapterMode: ctx.runtime?.adapterMode ?? null,
      navigate: (routeId) => ctx.navigate(routeId),
      showToast: ctx.showToast,
      isRestorePending: () => isConnectionRestorePending(getSession()),
      getSignal: () => enrichmentAbort?.signal,
      idPrefix: 'hub-overview-networks',
    });
    domainMount = mountDomainSimplePublishAffordance(domainMountSlot, {
      getName: () => domainDraftName,
      setName: (value) => {
        domainDraftName = value;
      },
      getDomain: () => domainDraftSuffix,
      setDomain: (value) => {
        domainDraftSuffix = value;
      },
      getDisabled: () => offline,
      showSuffixSelect: true,
      idPrefix: 'hub-overview-domain',
      onPublishApply: () => {
        openDomainPublishApplyConfirm({
          openModal,
          createButton,
          showToast: ctx.showToast,
          name: domainDraftName,
          domain: domainDraftSuffix,
          mode: KEENDNS_DEFAULT_ACCESS_MODE,
          onConfirmApply: async () => {
            return applyKeendnsBooking({
              name: domainDraftName,
              domain: domainDraftSuffix,
              mode: KEENDNS_DEFAULT_ACCESS_MODE,
              session: getSession(),
            });
          },
        });
      },
    });
    entryPagesSlot.appendChild(
      buildEntryPagesStatusCard(
        (routeId) => ctx.navigate(routeId),
        OVERVIEW_SECONDARY_ENTRY_PAGES_LABEL,
        OVERVIEW_ENTRY_PAGES_ROUTE_HREF,
      ),
    );
    diagnosticsSlot.appendChild(
      buildDiagnosticsStatusCard(
        (routeId) => ctx.navigate(routeId),
        OVERVIEW_SECONDARY_DIAGNOSTICS_LABEL,
        OVERVIEW_DIAGNOSTICS_ROUTE_HREF,
      ),
    );
    renderDomainCardSlot();
  }

  function shouldShowOverviewCardSkeletons() {
    return !model && !loadError && !offline;
  }

  function shouldShowVpnCardSkeleton() {
    if (shouldShowOverviewCardSkeletons()) {
      return true;
    }
    if (vpnCatalogItems.length > 0) {
      return false;
    }
    if (model && !vpnCatalogSettled) {
      return true;
    }
    if (vpnEnrichmentBusy) {
      return true;
    }
    return false;
  }

  function showOverviewCardSkeletons() {
    lastRouterCardSignature = null;
    lastInternetCardSignature = null;
    lastVpnSignature = null;
    renderRouterCardSlot();
    renderInternetCardSlot();
    renderVpnSlot();
  }

  function renderRouterCardSlot() {
    if (disposed) {
      return;
    }
    if (shouldShowOverviewCardSkeletons()) {
      const signature = 'skeleton';
      if (signature === lastRouterCardSignature && routerCardSlot.firstChild) {
        return;
      }
      lastRouterCardSignature = signature;
      clearContainer(routerCardSlot);
      routerCardSlot.appendChild(
        buildOverviewStepCardSkeleton({ stepNumber: 1, variant: 'router' }),
      );
      return;
    }
    const section = model?.router ?? null;
    const signature = section
      ? [
        section.state,
        section.title,
        section.subtitle ?? '',
        section.badge?.label ?? '',
        section.badge?.tone ?? '',
        section.note ?? '',
        section.error ? describeError(section.error).title : '',
        model?.systemCheck?.checkedAt ?? '',
        (lastSystemCheckFacts ?? []).map((fact) => `${fact.id}:${fact.value}:${fact.tone}`).join(','),
      ].join('|')
      : 'empty';
    if (signature === lastRouterCardSignature && routerCardSlot.firstChild) {
      return;
    }
    lastRouterCardSignature = signature;
    clearContainer(routerCardSlot);
    routerCardSlot.appendChild(
      buildRouterConnectionStatusCard(section, (routeId) => ctx.navigate(routeId), {
        facts: lastSystemCheckFacts,
        checkedAt: model?.systemCheck?.checkedAt ?? null,
        onChangeClick: () => ctx.navigate('connection'),
      }),
    );
  }

  function renderInternetCardSlot() {
    if (disposed) {
      return;
    }
    if (shouldShowOverviewCardSkeletons()) {
      const signature = 'skeleton';
      if (signature === lastInternetCardSignature && internetCardSlot.firstChild) {
        return;
      }
      lastInternetCardSignature = signature;
      clearContainer(internetCardSlot);
      internetCardSlot.appendChild(
        buildOverviewStepCardSkeleton({ stepNumber: 2, variant: 'internet' }),
      );
      return;
    }
    const observation = routerInternetObserve;
    const signature = [
      internetEnrichmentBusy ? 'busy' : 'idle',
      observation?.read_status ?? '',
      observation?.internet === true ? '1' : observation?.internet === false ? '0' : 'null',
      observation?.gateway_interface ?? '',
      observation?.gateway_ssid ?? '',
      rememberedUplink?.desired_active === true ? '1' : rememberedUplink?.desired_active === false ? '0' : 'null',
      rememberedUplink?.ssid ?? '',
    ].join('|');
    if (signature === lastInternetCardSignature && internetCardSlot.firstChild) {
      return;
    }
    lastInternetCardSignature = signature;
    clearContainer(internetCardSlot);
    internetCardSlot.appendChild(
      buildInternetStatusCard({
        observation,
        rememberedUplink,
        busy: internetEnrichmentBusy,
        navigate: (routeId) => ctx.navigate(routeId),
        onChangeClick: () => ctx.navigate('internet-uplink'),
      }),
    );
  }

  function renderDomainCardSlot() {
    if (disposed) {
      return;
    }
    const section = model?.domain ?? null;
    const signature = section
      ? [
        section.state,
        section.title,
        section.subtitle ?? '',
        section.note ?? '',
        section.error ? describeError(section.error).title : '',
        domainDraftName,
        domainDraftSuffix,
        getSession().eventPresetId ?? '',
      ].join('|')
      : 'empty';
    if (signature === lastDomainCardSignature && domainCardSlot.firstChild) {
      return;
    }
    lastDomainCardSignature = signature;
    clearContainer(domainCardSlot);
    domainCardSlot.appendChild(
      buildDomainStatusCard(section, (routeId) => ctx.navigate(routeId), {
        domainDraftName,
        domainDraftSuffix,
        eventPresetId: getSession().eventPresetId ?? null,
        onChangeClick: () => ctx.navigate('domain'),
      }),
    );
  }

  /**
   * @param {string} profileId
   * @returns {string}
   */
  function resolveVpnProfileWgId(profileId) {
    const item = vpnCatalogItems.find((row) => {
      const payload = /** @type {Record<string, unknown>} */ (row ?? {});
      return payload.profile_id === profileId;
    });
    const payload = /** @type {Record<string, unknown>} */ (item ?? {});
    const assigned =
      typeof payload.assigned_wg_id === 'string' ? payload.assigned_wg_id.trim() : '';
    if (assigned) {
      return assigned;
    }
    const options = listVpnTunnelInterfaceOptions();
    return options[0]?.wgId ?? 'Wireguard5';
  }

  /**
   * @param {AbortSignal|undefined} signal
   * @param {number|null} [expectedGeneration]
   */
  async function refreshVpnCatalogAndLiveStatus(signal, expectedGeneration = null) {
    let catalogListed = false;
    try {
      const session = getSession();
      const listResponse = await listVpnProfiles({ signal });
      const payload = /** @type {Record<string, unknown>} */ (listResponse ?? {});
      vpnCatalogItems = Array.isArray(payload.items)
        ? payload.items.filter((item) => item && typeof item === 'object')
        : [];
      catalogListed = true;
      if (vpnCatalogItems.length > 0) {
        try {
          const statusResponse = await fetchVpnCatalogLiveStatus({ session, signal });
          const statusPayload = /** @type {Record<string, unknown>} */ (statusResponse ?? {});
          const rows = Array.isArray(statusPayload.items)
            ? statusPayload.items.filter((item) => item && typeof item === 'object')
            : [];
          /** @type {typeof vpnLiveStatusById} */
          const nextLive = {};
          for (const row of rows) {
            const entry = /** @type {Record<string, unknown>} */ (row ?? {});
            const profileId =
              typeof entry.profile_id === 'string' ? entry.profile_id : '';
            if (!profileId) {
              continue;
            }
            nextLive[profileId] = {
              live_probed: entry.live_probed === true,
              live_tunnel_verification_status:
                typeof entry.live_tunnel_verification_status === 'string'
                  ? entry.live_tunnel_verification_status
                  : null,
              probe_error: typeof entry.probe_error === 'string' ? entry.probe_error : null,
              observed_at: typeof entry.observed_at === 'string' ? entry.observed_at : null,
              routed_through_tunnel:
                typeof entry.routed_through_tunnel === 'boolean'
                  ? entry.routed_through_tunnel
                  : null,
              routing_probe_status:
                typeof entry.routing_probe_status === 'string'
                  ? entry.routing_probe_status
                  : null,
            };
          }
          vpnLiveStatusById = nextLive;
        } catch (liveError) {
          if (isAborted(liveError)) {
            throw liveError;
          }
          // List succeeded; optional live-status failure must not block catalog settle.
        }
      } else {
        vpnLiveStatusById = {};
      }
    } finally {
      const generationOk = expectedGeneration == null || expectedGeneration === generation;
      if (catalogListed && generationOk && !disposed) {
        vpnCatalogSettled = true;
        lastVpnSignature = null;
        renderVpnSlot();
      }
    }
  }

  /**
   * @param {string} profileId
   */
  async function runOverviewVpnActivate(profileId) {
    if (
      !profileId
      || vpnMutating
      || vpnActivatingProfileIds[profileId]
      || isConnectionRestorePending(getSession())
      || offline
    ) {
      return;
    }
    vpnMutating = true;
    vpnActivatingProfileIds = { ...vpnActivatingProfileIds, [profileId]: '1' };
    lastVpnSignature = null;
    renderVpnSlot();
    try {
      const wgId = resolveVpnProfileWgId(profileId);
      await activateVpnProfile({
        profileId,
        session: getSession(),
        wgId,
        signal: enrichmentAbort?.signal,
      });
      if (disposed) {
        return;
      }
      ctx.showToast({
        tone: 'success',
        title: 'Профиль активирован',
        message: 'Запрос отправлен — «Работает» только при подтверждённой связи туннеля.',
      });
      vpnCheckingProfileIds = { ...vpnCheckingProfileIds, [profileId]: '1' };
      lastVpnSignature = null;
      renderVpnSlot();
      await refreshVpnCatalogAndLiveStatus(enrichmentAbort?.signal);
      if (disposed) {
        return;
      }
    } catch (error) {
      if (disposed || isAborted(error)) {
        return;
      }
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
    } finally {
      const nextActivating = { ...vpnActivatingProfileIds };
      delete nextActivating[profileId];
      vpnActivatingProfileIds = nextActivating;
      const nextChecking = { ...vpnCheckingProfileIds };
      delete nextChecking[profileId];
      vpnCheckingProfileIds = nextChecking;
      vpnMutating = false;
      lastVpnSignature = null;
      if (!disposed) {
        renderVpnSlot();
      }
    }
  }

  /**
   * @param {string} profileId
   */
  async function runOverviewVpnDeactivate(profileId) {
    if (
      !profileId
      || vpnMutating
      || vpnDeactivatingProfileIds[profileId]
      || isConnectionRestorePending(getSession())
      || offline
    ) {
      return;
    }
    vpnMutating = true;
    vpnDeactivatingProfileIds = { ...vpnDeactivatingProfileIds, [profileId]: '1' };
    lastVpnSignature = null;
    renderVpnSlot();
    try {
      const wgId = resolveVpnProfileWgId(profileId);
      await deactivateVpnProfile({
        wgId,
        session: getSession(),
        signal: enrichmentAbort?.signal,
      });
      if (disposed) {
        return;
      }
      ctx.showToast({
        tone: 'success',
        title: 'Профиль отключён',
        message: 'Запрос на отключение отправлен.',
      });
      vpnCheckingProfileIds = { ...vpnCheckingProfileIds, [profileId]: '1' };
      lastVpnSignature = null;
      renderVpnSlot();
      await refreshVpnCatalogAndLiveStatus(enrichmentAbort?.signal);
      if (disposed) {
        return;
      }
    } catch (error) {
      if (disposed || isAborted(error)) {
        return;
      }
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
    } finally {
      const nextDeactivating = { ...vpnDeactivatingProfileIds };
      delete nextDeactivating[profileId];
      vpnDeactivatingProfileIds = nextDeactivating;
      const nextChecking = { ...vpnCheckingProfileIds };
      delete nextChecking[profileId];
      vpnCheckingProfileIds = nextChecking;
      vpnMutating = false;
      lastVpnSignature = null;
      if (!disposed) {
        renderVpnSlot();
      }
    }
  }

  /**
   * @param {Record<string, unknown>} item
   * @returns {Record<string, unknown>}
   */
  function projectVpnTileItem(item) {
    const payload = /** @type {Record<string, unknown>} */ (item ?? {});
    const profileId =
      typeof payload.profile_id === 'string' ? payload.profile_id : '';
    const isActive = payload.is_active === true;
    const live = isActive && profileId ? vpnLiveStatusById[profileId] : null;
    const tileChecking =
      (isActive && vpnEnrichmentBusy)
      || Boolean(vpnCheckingProfileIds[profileId]);
    /** @type {Record<string, unknown>} */
    const projected = {
      profile_id: profileId,
      display_name: payload.display_name,
      vpn_kind: payload.vpn_kind,
      validation_status: payload.validation_status,
      is_active: payload.is_active,
      assigned_wg_id: payload.assigned_wg_id,
      checking: tileChecking,
    };
    if (live) {
      projected.live_probed = live.live_probed;
      projected.live_tunnel_verification_status = live.live_tunnel_verification_status ?? null;
      projected.probe_error = live.probe_error ?? null;
      projected.observed_at = live.observed_at ?? null;
      projected.routed_through_tunnel = live.routed_through_tunnel ?? null;
      projected.routing_probe_status = live.routing_probe_status ?? null;
    }
    return projected;
  }

  /**
   * @param {Array<Record<string, unknown>>} projectedItems
   */
  function reconcileVpnSelectedProfileId(projectedItems) {
    const ids = projectedItems
      .map((item) => {
        const profileId =
          typeof item.profile_id === 'string' && item.profile_id.trim()
            ? item.profile_id.trim()
            : '';
        return profileId;
      })
      .filter(Boolean);

    const activeItem =
      projectedItems.find((item) => item.is_active === true) ?? null;
    const activeId =
      typeof activeItem?.profile_id === 'string' ? activeItem.profile_id : null;
    const firstId = ids[0] ?? null;

    if (ids.length === 0) {
      vpnSelectedProfileId = null;
      lastVpnActiveProfileId = null;
      return;
    }

    if (vpnSelectedProfileId && !ids.includes(vpnSelectedProfileId)) {
      vpnSelectedProfileId = activeId ?? firstId;
    } else if (vpnSelectedProfileId === null) {
      vpnSelectedProfileId = activeId ?? firstId;
    } else if (
      activeId !== lastVpnActiveProfileId
      && (vpnSelectedProfileId === lastVpnActiveProfileId || vpnSelectedProfileId === null)
    ) {
      vpnSelectedProfileId = activeId ?? firstId;
    }

    lastVpnActiveProfileId = activeId;
  }

  /**
   * @returns {string}
   */
  function buildVpnSlotSignature() {
    return [
      vpnCatalogItems
        .map((item) => {
          const projected = projectVpnTileItem(item);
          return [
            projected.profile_id,
            projected.is_active,
            projected.validation_status,
            projected.live_tunnel_verification_status ?? '',
            projected.routed_through_tunnel === true
              ? '1'
              : projected.routed_through_tunnel === false
                ? '0'
                : '',
            projected.routing_probe_status ?? '',
            projected.checking ? '1' : '0',
            vpnActivatingProfileIds[projected.profile_id] ? '1' : '0',
            vpnDeactivatingProfileIds[projected.profile_id] ? '1' : '0',
          ].join(':');
        })
        .join('|'),
      vpnSelectedProfileId ?? '',
    ].join('::');
  }

  function renderVpnSlot() {
    if (disposed) {
      return;
    }
    if (shouldShowVpnCardSkeleton()) {
      const signature = 'skeleton';
      if (signature === lastVpnSignature && vpnWrap.firstChild) {
        return;
      }
      lastVpnSignature = signature;
      clearContainer(vpnWrap);
      vpnWrap.appendChild(
        buildOverviewStepCardSkeleton({ stepNumber: 3, variant: 'vpn' }),
      );
      return;
    }
    const signature = buildVpnSlotSignature();
    if (signature === lastVpnSignature && vpnWrap.firstChild) {
      return;
    }
    lastVpnSignature = signature;
    const hadFocusInside = vpnWrap.contains(document.activeElement);
    /** @type {string|null} */
    let focusedId = null;
    /** @type {string|null} */
    let focusedVpnProfileId = null;
    if (hadFocusInside) {
      const active = document.activeElement;
      if (active instanceof HTMLElement) {
        if (active.id) {
          focusedId = active.id;
        }
        const profileIdAttr = active.getAttribute('data-hub-vpn-profile-id');
        if (typeof profileIdAttr === 'string' && profileIdAttr.trim()) {
          focusedVpnProfileId = profileIdAttr.trim();
        }
      }
    }
    clearContainer(vpnWrap);

    const contentSlot = document.createElement('div');
    contentSlot.className = 'hub-vpn-card__content';

    /** @type {HTMLElement|null} */
    let ctaBtn = null;

    if (vpnCatalogSettled && vpnCatalogItems.length === 0 && !vpnEnrichmentBusy) {
      contentSlot.appendChild(
        createStatePanel({
          state: HubState.EMPTY,
          titleTag: 'p',
          title: 'Профиль VPN не добавлен',
        }),
      );
    } else if (vpnCatalogItems.length > 0) {
      const projectedItems = vpnCatalogItems.map((item) => projectVpnTileItem(item));
      reconcileVpnSelectedProfileId(projectedItems);
      const activeItem =
        projectedItems.find((item) => item.is_active === true) ?? null;
      const selectedProfileId =
        typeof vpnSelectedProfileId === 'string' ? vpnSelectedProfileId : null;

      const iconFrame = document.createElement('div');
      iconFrame.className = 'hub-vpn-card__icon-frame';
      iconFrame.appendChild(createIcon('vpn', { size: 32 }));
      contentSlot.appendChild(iconFrame);

      const cardStatus = vpnDeriveCardStatus(projectedItems, {
        busy: vpnEnrichmentBusy,
        checkingProfileIds: vpnCheckingProfileIds,
      });
      const statusWrap = document.createElement('div');
      statusWrap.className = 'hub-vpn-card__status';
      statusWrap.appendChild(
        createBadge({ label: cardStatus.label, tone: cardStatus.tone }),
      );
      contentSlot.appendChild(statusWrap);

      const profilesWrap = document.createElement('div');
      profilesWrap.className = 'hub-vpn-card__profiles';
      const pickerEl = buildOverviewVpnProfilePicker({
        items: projectedItems,
        selectedProfileId: vpnSelectedProfileId,
        disabled: offline || vpnMutating || isConnectionRestorePending(getSession()),
        busyProfileIds: vpnActivatingProfileIds,
        deactivatingProfileIds: vpnDeactivatingProfileIds,
        checkingProfileIds: vpnCheckingProfileIds,
        onSelect: (profileId) => {
          vpnSelectedProfileId = profileId;
          lastVpnSignature = null;
          renderVpnSlot();
        },
      });
      profilesWrap.appendChild(pickerEl);
      for (const item of projectedItems) {
        const profileId =
          typeof item.profile_id === 'string' && item.profile_id.trim()
            ? item.profile_id.trim()
            : '';
        if (!profileId) {
          continue;
        }
        const tile = pickerEl.querySelector(`[data-hub-vpn-profile-id="${profileId}"]`);
        if (!(tile instanceof HTMLElement)) {
          continue;
        }
        if (item.is_active === true && item.routed_through_tunnel === true) {
          tile.classList.add('hub-vpn-card__tile--active');
        } else if (item.is_active === true) {
          tile.classList.add('hub-vpn-card__tile--selected');
        }
      }
      contentSlot.appendChild(profilesWrap);

      const actionDisabled =
        offline ||
        vpnMutating ||
        isConnectionRestorePending(getSession()) ||
        Object.keys(vpnActivatingProfileIds).length > 0 ||
        Object.keys(vpnDeactivatingProfileIds).length > 0;
      const activeProfileId =
        typeof activeItem?.profile_id === 'string' ? activeItem.profile_id : null;

      ctaBtn = createButton({
        label: activeProfileId ? 'Отключить VPN' : 'Подключить VPN',
        variant: 'secondary',
        size: 'md',
        disabled: actionDisabled || (!activeProfileId && !selectedProfileId),
        onActivate: () => {
          if (activeProfileId) {
            void runOverviewVpnDeactivate(activeProfileId);
          } else if (selectedProfileId) {
            void runOverviewVpnActivate(selectedProfileId);
          }
        },
      });
      ctaBtn.className = `${ctaBtn.className} hub-vpn-card__cta`;
    }

    const vpnLink = document.createElement('a');
    vpnLink.className = 'hub-overview__quiet-link';
    vpnLink.href = '#/vpn';
    vpnLink.textContent = 'Все настройки VPN';
    vpnLink.addEventListener('click', (event) => {
      event.preventDefault();
      ctx.navigate('vpn');
    });

    const card = buildVpnStatusCardShell(contentSlot);

    const actions = document.createElement('div');
    actions.className = 'hub-overview-step-card__actions';
    if (ctaBtn) {
      actions.appendChild(ctaBtn);
    }

    const meta = document.createElement('div');
    meta.className = 'hub-overview-step-card__meta';
    meta.appendChild(vpnLink);
    actions.appendChild(meta);
    card.appendChild(actions);

    vpnWrap.appendChild(card);
    wireOverviewCardNavigate(card, 'vpn', (routeId) => ctx.navigate(routeId));

    if (focusedId) {
      const el = document.getElementById(focusedId);
      if (el instanceof HTMLElement) {
        el.focus({ preventScroll: true });
        el.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        return;
      }
    }
    if (focusedVpnProfileId) {
      const tile = vpnWrap.querySelector(
        `[data-hub-vpn-profile-id="${focusedVpnProfileId}"]`,
      );
      if (tile instanceof HTMLElement) {
        tile.focus({ preventScroll: true });
        tile.scrollIntoView({ block: 'nearest', inline: 'nearest' });
      }
    }
  }

  function abortEnrichment() {
    enrichmentAbort?.abort();
    enrichmentAbort = null;
  }

  /**
   * @param {number} gen
   */
  async function runOverviewEnrichment(gen) {
    if (disposed || gen !== generation || isConnectionRestorePending(getSession())) {
      return;
    }
    abortEnrichment();
    enrichmentAbort = new AbortController();
    const signal = enrichmentAbort.signal;
    mountOverviewActionSlots();
    internetEnrichmentBusy = true;
    renderInternetCardSlot();
    renderReadinessHeader();
    renderStatusStrip();
    try {
      const session = getSession();
      const [observeResult, rememberedResult] = await Promise.all([
        fetchRouterInternetObserve({ session, signal }),
        fetchRememberedUplink({ signal }),
      ]);
      if (disposed || gen !== generation || signal.aborted) {
        return;
      }
      routerInternetObserve = observeResult;
      rememberedUplink = rememberedResult;
      renderConnectionBanner();
    } catch {
      if (disposed || gen !== generation || signal.aborted) {
        return;
      }
      routerInternetObserve = { read_status: 'failed' };
    } finally {
      internetEnrichmentBusy = false;
      if (gen === generation && !disposed) {
        renderInternetCardSlot();
        renderReadinessHeader();
        renderStatusStrip();
      }
    }
    if (disposed || gen !== generation || signal.aborted || isConnectionRestorePending(getSession())) {
      return;
    }
    await networksMount?.loadAndUpdate({ signal });
    if (disposed || gen !== generation || signal.aborted) {
      return;
    }
    vpnEnrichmentBusy = true;
    renderVpnSlot();
    renderReadinessHeader();
    renderStatusStrip();
    try {
      await refreshVpnCatalogAndLiveStatus(signal, gen);
      if (disposed || gen !== generation || signal.aborted) {
        return;
      }
    } catch {
      if (disposed || gen !== generation || signal.aborted) {
        return;
      }
    } finally {
      vpnEnrichmentBusy = false;
      if (gen === generation && !disposed) {
        lastVpnSignature = null;
        renderVpnSlot();
        renderReadinessHeader();
        renderStatusStrip();
      }
    }
  }

  /**
   * @param {OverviewSection} section
   * @returns {{ state: string, title: string, description?: string, details?: string, action?: { label: string, onActivate: () => void } }}
   */
  function buildSummaryPanelOptions(section) {
    if (offline && !recovering) {
      return { state: HubState.NO_INTERNET };
    }
    if (recovering) {
      return { state: HubState.RECOVERING };
    }
    if (systemCheckRunning) {
      return { state: HubState.CONNECTING };
    }
    const hasError = section.error && !isAborted(section.error);
    const described = hasError ? describeError(section.error) : null;
    /** @type {{ label: string, onActivate: () => void }|undefined} */
    let action;
    if (hasError) {
      action = {
        label: 'Повторить',
        onActivate: () => {
          void requestReloadOverview();
        },
      };
    } else if (section.title === 'Не удалось получить состояние системы') {
      action = {
        label: 'Повторить',
        onActivate: () => {
          void requestReloadOverview();
        },
      };
    } else if (model && model.router.state === HubState.EMPTY && !model.router.error) {
      action = {
        label: 'Подключить роутер',
        onActivate: () => ctx.navigate('connection'),
      };
    } else {
      action = {
        label: 'Проверить систему',
        onActivate: () => {
          void runSystemCheckOnly();
        },
      };
    }
    return {
      state: section.state,
      title: section.title,
      description: hasError ? described?.message : section.subtitle ?? undefined,
      details: hasError ? described?.technical : undefined,
      action,
    };
  }
  function renderSummary() {
    if (disposed) {
      return;
    }
    if (activeProgressPanel && (restoreSettleLoadPromise || systemCheckRunning)) {
      return;
    }
    if (loadError && !model) {
      const signature = `load-error|${hubStateForLoadError(loadError, offline)}|${describeError(loadError).title}`;
      if (signature === lastSummarySignature && summaryWrap.firstChild) {
        return;
      }
      lastSummarySignature = signature;
      const hadFocusInside = summaryWrap.contains(document.activeElement);
      clearContainer(summaryWrap);
      renderLoadErrorPanel();
      if (hadFocusInside) {
        const actionBtn = summaryWrap.querySelector('.hub-state-action');
        if (actionBtn instanceof HTMLElement) {
          actionBtn.focus();
        }
      }
      return;
    }
    if (!model) {
      if (offline) {
        renderOfflineNoModelPanel();
        return;
      }
      if (loading) {
        const signature = 'loading-skeleton';
        if (signature === lastSummarySignature && summaryWrap.firstChild) {
          return;
        }
        lastSummarySignature = signature;
        clearContainer(summaryWrap);
        summaryWrap.appendChild(
          createInlineState({ state: HubState.LOADING, title: 'Загружаем состояние системы' }),
        );
        summaryWrap.appendChild(createSkeleton({ lines: 2, withTitle: true }));
      }
      return;
    }
    const panelOptions = buildSummaryPanelOptions(model.systemCheck);
    const signature = buildSummaryContentSignature(model.systemCheck, panelOptions);
    if (signature === lastSummarySignature && summaryWrap.firstChild) {
      return;
    }
    lastSummarySignature = signature;
    const hadFocusInside = summaryWrap.contains(document.activeElement);
    clearContainer(summaryWrap);
    const panel = createStatePanel({
      ...panelOptions,
      titleTag: 'h2',
    });
    summaryWrap.appendChild(panel);
    if (model.systemCheck.badge && !offline && !recovering && !systemCheckRunning) {
      const titleEl = panel.querySelector('.hub-state-panel__title');
      if (titleEl instanceof HTMLElement) {
        const badgeWrap = document.createElement('div');
        badgeWrap.className = 'hub-overview__summary-badge';
        badgeWrap.appendChild(
          createBadge({
            label: model.systemCheck.badge.label,
            tone: model.systemCheck.badge.tone,
          }),
        );
        titleEl.insertAdjacentElement('afterend', badgeWrap);
      }
    }
    const checkedAt = model.systemCheck.checkedAt;
    const hasSystemCheckError = model.systemCheck.error && !isAborted(model.systemCheck.error);
    if (checkedAt && !hasSystemCheckError) {
      const checkTimeEl = document.createElement('p');
      checkTimeEl.className = 'hub-overview__check-time';
      checkTimeEl.textContent = formatSystemCheckAt(checkedAt);
      summaryWrap.appendChild(checkTimeEl);
    }
    if (model.systemCheck.mock && !offline && !recovering && !systemCheckRunning) {
      summaryWrap.appendChild(
        createInlineState({
          state: HubState.MOCK_MODE,
          title: model.systemCheck.note ?? undefined,
        }),
      );
    }
    if (
      ctx.runtime?.adapterMode === 'live'
      && model.systemCheck.state === HubState.SUCCESS
      && !offline
      && !recovering
      && !systemCheckRunning
    ) {
      summaryWrap.appendChild(createInlineState({ state: HubState.LIVE_DEVICE }));
    }
    if (hadFocusInside) {
      const actionBtn = summaryWrap.querySelector('.hub-state-action');
      if (actionBtn instanceof HTMLElement) {
        actionBtn.focus();
      }
    } else if (pendingFocus?.kind === 'summary-action-retry') {
      const active = document.activeElement;
      const usernameInput = connectionBannerWrap.querySelector('#hub-overview-management-username');
      if (
        active instanceof HTMLElement
        && (connectionBannerWrap.contains(active) || active === usernameInput)
      ) {
        pendingFocus = null;
      } else {
        restorePendingFocus();
      }
    }
  }
  /** @type {string|null} */
  let lastConnectionBannerSignature = null;
  /**
   * @param {string} errorTitle
   * @returns {HTMLElement}
   */
  function buildUsernameRecoveryBannerPanel(errorTitle) {
    const wrap = document.createElement('div');
    wrap.className = 'hub-overview__username-recovery';

    const panel = createStatePanel({
      state: HubState.WARNING,
      titleTag: 'h2',
      title: 'Нужно имя пользователя для управления',
      description:
        'На сервере сохранён отпечаток роутера. Укажите имя пользователя — повторное подтверждение отпечатка не требуется.',
      secondaryAction: {
        label: 'Открыть «Подключение»',
        onActivate: () => {
          ctx.navigate('connection');
        },
      },
    });
    wrap.appendChild(panel);

    const form = document.createElement('form');
    form.noValidate = true;
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      void submitOverviewManagementUsername();
    });

    const usernameField = createTextField({
      id: 'hub-overview-management-username',
      label: 'Имя пользователя',
      value: managementUsernameDraft,
      autocomplete: 'off',
      disabled: offline,
      readOnly: savingManagementUsername,
      onInput: (event) => {
        managementUsernameDraft = readInputEventValue(event);
        managementUsernameError = null;
        syncOverviewManagementUsernameFormUi();
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
          description: described.message,
        }),
      );
    }

    const saveBtn = createButton({
      label: 'Сохранить имя пользователя',
      busy: savingManagementUsername,
      disabled: offline || !managementUsernameDraft.trim(),
      onActivate: () => {
        void submitOverviewManagementUsername();
      },
    });
    saveBtn.type = 'submit';
    saveBtn.id = OVERVIEW_MANAGEMENT_USERNAME_SAVE_BTN_ID;
    saveBtn.classList.add('hub-overview__username-save');
    form.appendChild(saveBtn);
    wrap.appendChild(form);

    if (errorTitle) {
      wrap.dataset.errorTitle = errorTitle;
    }

    return wrap;
  }
  function renderConnectionBanner() {
    if (disposed) {
      return;
    }
    const session = getSession();
    /** @type {{ signature: string, panel: HTMLElement|null }} */
    let banner = { signature: 'none', panel: null };

    if (isConnectionRestorePending(session)) {
      if (
        lastConnectionBannerSignature === 'pending-summary-only'
        && !connectionBannerWrap.firstChild
        && connectionBannerWrap.hidden
      ) {
        return;
      }
      rebuildConnectionBannerSlot(() => {
        connectionBannerWrap.hidden = true;
      });
      lastConnectionBannerSignature = 'pending-summary-only';
      return;
    }
    if (isConnectionRestoreFailed(session)) {
      banner = {
        signature: 'failed',
        panel: (() => {
          const panel = createStatePanel({
            state: HubState.WARNING,
            titleTag: 'h2',
            title: 'Не удалось проверить сохранённое подключение',
            description:
              'Сервер не ответил вовремя или вернул ошибку. Нажмите «Повторить» — или откройте «Подключение» вручную.',
            action: {
              label: 'Повторить',
              onActivate: () => {
                void retryRestoreConnection();
              },
            },
            secondaryAction: {
              label: 'Открыть «Подключение»',
              onActivate: () => {
                ctx.navigate('connection');
              },
            },
          });
          assignPrimaryActionId(panel, 'hub-overview-restore-retry-btn');
          return panel;
        })(),
      };
    } else if (needsManagementUsernameRecovery(session)) {
      const errorTitle = managementUsernameError && !isAborted(managementUsernameError)
        ? describeError(managementUsernameError).title
        : '';
      const signature = `username-recovery|${errorTitle}`;
      if (signature === lastConnectionBannerSignature && connectionBannerWrap.firstChild) {
        syncOverviewManagementUsernameInPlace();
        return;
      }
      lastConnectionBannerSignature = signature;
      rebuildConnectionBannerSlot(() => {
        connectionBannerWrap.appendChild(buildUsernameRecoveryBannerPanel(errorTitle));
        connectionBannerWrap.hidden = false;
      });
      return;
    } else if (
      session.routerId
      && session.hostKeyConfirmed !== true
      && session.connectionRestoreState === 'done'
    ) {
      banner = {
        signature: 'host-key-unconfirmed',
        panel: (() => {
          const panel = createStatePanel({
            state: HubState.WARNING,
            titleTag: 'h2',
            title: 'Нужно подтвердить, что это ваш роутер',
            description:
              'Перед использованием подтвердите устройство один раз в разделе «Подключение».',
            action: {
              label: 'Подтвердить роутер',
              onActivate: () => {
                ctx.navigate('connection');
              },
            },
          });
          assignPrimaryActionId(panel, 'hub-overview-host-key-btn');
          return panel;
        })(),
      };
    } else if (
      routerInternetObserve?.read_status === 'ok'
      && routerInternetObserve.internet === false
    ) {
      const gatewayIface = routerInternetObserve.gateway_interface;
      const hasRecognizedRoute =
        isWifiStationGatewayInterface(gatewayIface)
        || isEthernetLikeGatewayInterface(gatewayIface)
        || isWireguardGatewayInterface(gatewayIface);
      const routeIsUp = routerInternetObserve.gateway_accessible === true && hasRecognizedRoute;
      if (!routeIsUp) {
        // Genuinely no working route — the uplink screen is the right place to fix this.
        banner = {
          signature: 'no-internet',
          panel: (() => {
            const panel = createStatePanel({
              state: HubState.WARNING,
              titleTag: 'h2',
              title: 'Нет интернета — подключить',
              description:
                'Роутер подключён, но выход в интернет не работает. Настройте подключение в разделе «Интернет».',
              action: {
                label: 'Подключить интернет',
                onActivate: () => {
                  ctx.navigate('internet-uplink');
                },
              },
            });
            assignPrimaryActionId(panel, 'hub-overview-no-internet-btn');
            return panel;
          })(),
        };
      } else {
        // A route exists and answers (often VPN) but the router's own stricter
        // internet/captive check still fails — «Подключить интернет» would be a
        // non-sequitur here (nothing to connect; the uplink screen would not help).
        const dnsNote = routerInternetObserve.dns_accessible === true
          ? 'DNS отвечает'
          : 'DNS не отвечает';
        banner = {
          signature: 'route-up-internet-check-failed',
          panel: (() => {
            const panel = createStatePanel({
              state: HubState.WARNING,
              titleTag: 'h2',
              title: 'Интернет ограничен',
              description:
                `Маршрут отвечает (${dnsNote}), но проверка роутера на полный доступ в интернет не проходит. `
                + 'Это известное ограничение конкретного соединения, а не повод настраивать Wi‑Fi заново.',
              action: {
                label: 'Подробнее про интернет',
                onActivate: () => {
                  ctx.navigate('internet-uplink');
                },
              },
            });
            assignPrimaryActionId(panel, 'hub-overview-limited-internet-btn');
            return panel;
          })(),
        };
      }
    }

    if (banner.signature === lastConnectionBannerSignature && connectionBannerWrap.firstChild) {
      return;
    }
    lastConnectionBannerSignature = banner.signature;
    rebuildConnectionBannerSlot(() => {
      if (banner.panel) {
        connectionBannerWrap.appendChild(banner.panel);
        connectionBannerWrap.hidden = false;
      } else {
        connectionBannerWrap.hidden = true;
      }
    });
  }
  function renderAll() {
    if (disposed) {
      return;
    }
    updateRefreshButton();
    renderConnectionBanner();
    if (model?.generatedAt) {
      updatedEl.textContent = formatUpdatedAt(model.generatedAt);
      updatedEl.hidden = false;
    } else {
      updatedEl.hidden = true;
    }
    renderSummary();
    renderReadinessHeader();
    mountOverviewActionSlots();
    renderRouterCardSlot();
    renderInternetCardSlot();
    renderDomainCardSlot();
    domainMount?.update();
    renderVpnSlot();
    renderStatusStrip();
  }
  function abortAllOperations() {
    loadAbort?.abort();
    systemCheckAbort?.abort();
    internetObserveAbort?.abort();
    abortEnrichment();
    const hadEnrichmentBusy = internetEnrichmentBusy || vpnEnrichmentBusy;
    internetEnrichmentBusy = false;
    vpnEnrichmentBusy = false;
    if (hadEnrichmentBusy && !disposed) {
      renderInternetCardSlot();
      renderVpnSlot();
      renderReadinessHeader();
      renderStatusStrip();
    }
  }
  /**
   * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
   * @param {AbortSignal} signal
   * @returns {Promise<void>}
   */
  async function refreshRouterInternetObserve(session, signal) {
    if (disposed || isConnectionRestorePending(session)) {
      return;
    }
    routerInternetObserve = await fetchRouterInternetObserve({ session, signal });
  }
  /**
   * @returns {Promise<number|null>}
   */
  async function reloadOverviewInternal() {
    if (disposed) {
      return null;
    }
    if (isConnectionRestorePending(getSession())) {
      return ensureOverviewLoadedAfterRestore();
    }
    if (inFlightReloadPromise) {
      return inFlightReloadPromise;
    }
    if (offline) {
      loading = false;
      if (loadingGeneration != null) {
        loadingGeneration = null;
      }
      if (!model) {
        renderOfflineNoModelPanel();
      } else {
        renderSummary();
      }
      return null;
    }
    inFlightReloadPromise = (async () => {
    const gen = ++generation;
    abortAllOperations();
    loadAbort = new AbortController();
    const myLoadController = loadAbort;
    const isInitial = model === null && loadError === null;
    loading = true;
    loadingGeneration = gen;
    loadError = null;
    if (model === null) {
      showOverviewCardSkeletons();
    }
    if (isInitial) {
      refreshBusy = false;
      refreshBusyGeneration = null;
      lastSummarySignature = null;
      renderSummarySkeleton();
      updateRefreshButton();
    } else {
      refreshBusy = true;
      refreshBusyGeneration = gen;
      updateRefreshButton();
    }
    try {
      const session = getSession();
      systemCheckRunning = true;
      systemCheckRunningGeneration = gen;
      lastSummarySignature = null;
      showRestoreOrProbeProgress('Проверяем связь с роутером', 1, SYSTEM_CHECK_TRANSIENT_MAX_ATTEMPTS);
      renderSummary();
      const nextModel = await loadOverview({
        session,
        runtime: ctx.runtime,
        signal: loadAbort.signal,
        onHealthAttempt: ({ attempt, maxAttempts }) => {
          if (disposed || gen !== generation) {
            return;
          }
          const label = attempt <= 1
            ? 'Проверяем связь с роутером'
            : `Повторная проверка связи (${attempt}/${maxAttempts})`;
          showRestoreOrProbeProgress(label, attempt, maxAttempts);
        },
      });
      if (disposed || gen !== generation) {
        return gen;
      }
      const wasNullModel = model === null;
      model = nextModel;
      loadError = null;
      activeRouterId = nextModel.selectedRouterId;
      lastSystemCheckFacts = Array.isArray(nextModel.systemCheckFacts)
        ? nextModel.systemCheckFacts
        : null;
      if (wasNullModel) {
        vpnCatalogSettled = false;
      }
      lastRouterCardSignature = null;
      if (gen === generation) {
        recovering = false;
      }
      clearRestoreOrProbeProgress();
      renderAll();
      void runOverviewEnrichment(gen);
      return gen;
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return gen;
      }
      loadError = error;
      model = null;
      lastSystemCheckFacts = null;
      if (gen === generation) {
        recovering = false;
      }
      clearRestoreOrProbeProgress();
      lastSummarySignature = null;
      lastVpnSignature = null;
      lastRouterCardSignature = null;
      lastInternetCardSignature = null;
      lastReadinessSignature = null;
      lastStatusStripSignature = null;
      lastDomainCardSignature = null;
      renderAll();
      return gen;
    } finally {
      if (systemCheckRunningGeneration === gen) {
        systemCheckRunning = false;
        systemCheckRunningGeneration = null;
      }
      if (loadingGeneration === gen) {
        loading = false;
        loadingGeneration = null;
      }
      if (refreshBusyGeneration === gen) {
        refreshBusy = false;
        refreshBusyGeneration = null;
      }
      if (!disposed) {
        updateRefreshButton();
      }
      if (loadAbort === myLoadController) {
        loadAbort = null;
      }
      if (!disposed && gen === generation) {
        renderSummary();
        renderReadinessHeader();
        renderStatusStrip();
        renderRouterCardSlot();
      }
      inFlightReloadPromise = null;
    }
    })();
    return inFlightReloadPromise;
  }
  async function runSystemCheckOnly() {
    if (disposed || offline || systemCheckRunning) {
      return;
    }
    if (isConnectionRestorePending(getSession())) {
      await ensureOverviewLoadedAfterRestore();
      return;
    }
    const gen = ++generation;
    abortAllOperations();
    systemCheckAbort = new AbortController();
    const mySystemCheckController = systemCheckAbort;
    systemCheckRunning = true;
    systemCheckRunningGeneration = gen;
    lastSummarySignature = null;
    renderSummary();
    renderReadinessHeader();
    renderStatusStrip();
    const session = getSession();
    try {
      let routerId = activeRouterId ?? model?.selectedRouterId ?? null;
      if (routerId == null) {
        routerId = await resolveRouterId(systemCheckAbort.signal);
      }
      if (disposed || gen !== generation) {
        return;
      }
      const verdict = await runSystemCheck({
        routerId,
        hostKeyConfirmed: Boolean(session.hostKeyConfirmed),
        adapterMode: ctx.runtime?.adapterMode ?? 'unknown',
        signal: systemCheckAbort.signal,
      });
      if (disposed || gen !== generation) {
        return;
      }
      if (!model) {
        showSystemCheckToast(verdict, null, ctx.showToast);
        return;
      }
      lastSystemCheckFacts = Array.isArray(verdict.facts) ? verdict.facts : null;
      model = {
        ...model,
        systemCheck: systemCheckSectionFromVerdict(verdict, null),
        router: applyVerdictToRouterSection(model.router, verdict),
      };
      lastRouterCardSignature = null;
      lastReadinessSignature = null;
      lastStatusStripSignature = null;
      showSystemCheckToast(verdict, null, ctx.showToast);
      renderSummary();
      renderReadinessHeader();
      renderRouterCardSlot();
      renderStatusStrip();
    } catch (error) {
      if (disposed || gen !== generation || isAborted(error)) {
        return;
      }
      if (model) {
        lastSystemCheckFacts = null;
        model = {
          ...model,
          systemCheck: systemCheckSectionFromVerdict(null, error),
        };
        lastRouterCardSignature = null;
        lastReadinessSignature = null;
        lastStatusStripSignature = null;
        renderSummary();
        renderRouterCardSlot();
      }
      showSystemCheckToast(null, error, ctx.showToast);
    } finally {
      if (systemCheckRunningGeneration === gen) {
        systemCheckRunning = false;
        systemCheckRunningGeneration = null;
      }
      if (systemCheckAbort === mySystemCheckController) {
        systemCheckAbort = null;
      }
      if (!disposed && gen === generation && model) {
        recovering = false;
        renderSummary();
        renderReadinessHeader();
        renderStatusStrip();
        renderRouterCardSlot();
      }
    }
  }
  function startRefreshInterval() {
    if (refreshInterval != null) {
      clearInterval(refreshInterval);
    }
    refreshInterval = setInterval(() => {
      if (!document.hidden && !offline && !disposed) {
        void requestReloadOverview();
      }
    }, REFRESH_INTERVAL_MS);
  }
  function startHeartbeatInterval() {
    if (heartbeatInterval != null) {
      clearInterval(heartbeatInterval);
    }
    heartbeatInterval = setInterval(() => {
      void runHeartbeatCheck();
    }, HOST_INTERNET_HEARTBEAT_INTERVAL_MS);
  }
  async function runHeartbeatCheck() {
    if (document.hidden || offline || disposed || isConnectionRestorePending(getSession())) {
      return;
    }
    let reachable = null;
    try {
      const result = await probeOperatorHostInternet({});
      reachable = result && typeof result === 'object' && 'internet_reachable' in result
        ? result.internet_reachable
        : null;
    } catch {
      reachable = null;
    }
    if (disposed) {
      return;
    }
    const wentDown = shouldRequestOverviewReloadOnHostHeartbeat(
      lastHeartbeatReachable,
      reachable,
    );
    lastHeartbeatReachable = reachable;
    if (wentDown) {
      void requestReloadOverview();
    }
  }
  function onVisibilityChange() {
    if (disposed) {
      return;
    }
    if (document.hidden) {
      if (refreshInterval != null) {
        clearInterval(refreshInterval);
        refreshInterval = null;
      }
      if (heartbeatInterval != null) {
        clearInterval(heartbeatInterval);
        heartbeatInterval = null;
      }
      return;
    }
    if (!offline) {
      void requestReloadOverview();
    }
    startRefreshInterval();
    startHeartbeatInterval();
  }
  let trackedConnectionBannerKey = liveCapabilitySubscriptionKey(getSession());
  const unsubSession = subscribeSession((snapshot) => {
    if (disposed) {
      return;
    }
    const nextKey = liveCapabilitySubscriptionKey(snapshot);
    if (nextKey === trackedConnectionBannerKey) {
      return;
    }
    trackedConnectionBannerKey = nextKey;
    if (isConnectionRestorePending(snapshot)) {
      return;
    }
    internetObserveAbort?.abort();
    internetObserveAbort = new AbortController();
    const observeSignal = internetObserveAbort.signal;
    void refreshRouterInternetObserve(snapshot, observeSignal)
      .then(() => {
        if (!disposed && !observeSignal.aborted && !isConnectionRestorePending(getSession())) {
          renderConnectionBanner();
        }
      })
      .catch(() => {
        if (
          !disposed
          && !observeSignal.aborted
          && !isConnectionRestorePending(getSession())
        ) {
          routerInternetObserve = { read_status: 'failed' };
          renderConnectionBanner();
        }
      });
  });
  const unsubConnectivity = subscribeConnectivity((online) => {
    if (disposed) {
      return;
    }
    if (!online) {
      offline = true;
      recovering = false;
      updateRefreshButton();
      renderSummary();
      domainMount?.update();
      return;
    }
    offline = false;
    recovering = true;
    updateRefreshButton();
    renderSummary();
    domainMount?.update();
    void requestReloadOverview();
  });
  updateRefreshButton();
  renderSummarySkeleton();
  mountOverviewActionSlots();
  if (shouldShowOverviewCardSkeletons()) {
    showOverviewCardSkeletons();
  }
  void ensureOverviewLoadedAfterRestore();
  startRefreshInterval();
  startHeartbeatInterval();
  document.addEventListener('visibilitychange', onVisibilityChange);
  return () => {
    disposed = true;
    generation += 1;
    abortAllOperations();
    networksMount?.destroy();
    domainMount?.destroy();
    if (refreshInterval != null) {
      clearInterval(refreshInterval);
    }
    if (heartbeatInterval != null) {
      clearInterval(heartbeatInterval);
      heartbeatInterval = null;
    }
    document.removeEventListener('visibilitychange', onVisibilityChange);
    unsubConnectivity();
    unsubSession();
  };
}
