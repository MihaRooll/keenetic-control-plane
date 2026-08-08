import {
  createBadge,
  createButton,
  createCard,
  createSelectField,
  createTechnicalDetails,
  createTextField,
  openModal,
} from '../components/index.js';
import { subscribeConnectivity, apiGet } from '../core/api.js';
import { syncActionButtonById } from '../core/form-submit-sync.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import { getSession } from '../core/session.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
  getStateDescriptor,
} from '../core/states.js';
import { createIdempotencyKey } from '../features/connection-flow.js';
import {
  VPN_ACTIVATE_PROGRESS_MESSAGE,
  VPN_AUTO_RECONNECT_UNSUPPORTED_NOTE,
  VPN_BACKUP_CHANNEL_UNSUPPORTED_NOTE,
  VPN_CATALOG_IMPORT_NOT_CONNECTION_NOTE,
  VPN_CATALOG_INITIAL_LOAD_MESSAGE,
  VPN_CATALOG_REFRESH_MESSAGE,
  VPN_CATALOG_REMOVE_ACTIVE_REFUSE,
  VPN_CATALOG_REMOVE_CANCEL,
  VPN_CATALOG_REMOVE_CONFIRM_ACTION,
  VPN_CATALOG_REMOVE_CONFIRM_LEAD,
  VPN_CATALOG_REMOVE_CONFIRM_TITLE,
  VPN_DEACTIVATE_PROGRESS_MESSAGE,
  VPN_HANDSHAKE_WAIT_MESSAGE,
  VPN_IMPORT_SECRETS_NOTE,
  VPN_KILL_SWITCH_UNSUPPORTED_NOTE,
  VPN_OBSERVE_PROGRESS_MESSAGE,
  VPN_POST_SETTLE_RECHECK_HINT,
  VPN_PREVIEW_PROGRESS_MESSAGE,
  VPN_RECONNECT_TEARDOWN_PROGRESS_MESSAGE,
  VPN_TEARDOWN_PROGRESS_MESSAGE,
  VPN_VALIDATE_PROGRESS_MESSAGE,
  VPN_APPLY_TIMEOUT_UNKNOWN_CONFIGURATION_MESSAGE,
  VPN_APPLY_TIMEOUT_UNKNOWN_TUNNEL_MESSAGE,
  applyVpnTunnel,
  buildVpnScreenState,
  buildWireguardApplyBody,
  buildWireguardIntentBody,
  buildWireguardIntentFromParsePreview,
  buildWireguardObserveBody,
  buildWireguardTeardownBody,
  describeConfigurationOutcome,
  describeConfigurationTechnicalLines,
  describeMissingSignals,
  describeRejectedSignals,
  describeTrafficRouting,
  describeTunnelStatus,
  describeVpnProfileItem,
  evaluatePreparedParseConnectReadiness,
  evaluateVpnMutationReadiness,
  activateVpnProfile,
  deactivateVpnProfile,
  describeVpnAutoReconnectNote,
  describeCatalogConnectionBadge,
  describeVpnProfileKeepalive,
  describeVpnProfileTileStatus,
  VPN_TUNNEL_UNVERIFIED_MESSAGE,
  VPN_PROFILE_TILE_STATUS_HONESTY_NOTE,
  createVpnProfileStatusTileGrid,
  fetchVpnCatalogLiveStatus,
  extractVpnProfileOperatorNotes,
  getVpnProfile,
  importVpnProfileToCatalog,
  listVpnProfiles,
  listVpnTunnelInterfaceOptions,
  resolveVpnProfileWgId,
  observeVpnTunnel,
  parseTunnelVerdict,
  parseVpnProfileText,
  previewVpnTunnel,
  removeVpnProfileFromCatalog,
  summarizeParsedProfile,
  teardownVpnTunnel,
  validateVpnProfile,
} from '../features/vpn-model.js';
import {
  buildRiskModalBody,
  createDemoBanner,
  createUnsupportedCard,
  createWifiNetworkHeaderCard,
  updateButtonBusyState,
} from '../features/wifi-screen-parts.js';

export const meta = {
  id: 'vpn',
  title: 'VPN',
  iconName: 'vpn',
};

/** @typedef {'connect'|'reconnect'|'disconnect'} VpnRiskAction */

/** Сообщение при устаревшем подтверждении риска. */
const VPN_MUTATION_INTENT_STALE_MESSAGE =
  'Пока открывалось окно подтверждения, выбор интерфейса или подготовленная конфигурация изменились — повторите действие.';

/**
 * @param {boolean|null} watchdogEnabled
 * @returns {string[]}
 */
function buildVpnProtectionOptions(watchdogEnabled) {
  return [
    VPN_KILL_SWITCH_UNSUPPORTED_NOTE,
    describeVpnAutoReconnectNote({ watchdogEnabled }),
    VPN_BACKUP_CHANNEL_UNSUPPORTED_NOTE,
  ];
}

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
 * @param {VpnRiskAction} action
 * @param {string} wgLabel
 * @returns {string[]}
 */
function buildVpnRiskChangeLines(action, wgLabel) {
  if (action === 'disconnect') {
    return [`${wgLabel} будет отключён на роутере`];
  }
  if (action === 'reconnect') {
    return [`${wgLabel} будет переприменён с теми же настройками`];
  }
  return [
    `${wgLabel} будет включён на роутере`,
    'Параметры сервера VPN будут отправлены на роутер',
  ];
}

/**
 * @param {VpnRiskAction} action
 * @returns {string}
 */
function vpnRiskConfirmLabel(action) {
  switch (action) {
    case 'connect':
      return 'Подключить VPN';
    case 'reconnect':
      return 'Переподключить';
    case 'disconnect':
      return 'Отключить VPN';
    default:
      return 'Подтвердить';
  }
}

/**
 * @param {string} wgId
 * @returns {string}
 */
function wgIdToLabel(wgId) {
  const option = listVpnTunnelInterfaceOptions().find((item) => item.wgId === wgId);
  return option?.label ?? wgId;
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
  const tunnelOptions = listVpnTunnelInterfaceOptions();

  let generation = 0;
  let catalogGeneration = 0;
  /** @type {number|null} */
  let catalogLoadGeneration = null;
  let observeGeneration = 0;
  /** @type {number|null} */
  let observeLoadGeneration = null;
  /** @type {number|null} */
  let mutateGeneration = null;
  /** @type {number|null} */
  let parseGeneration = null;
  /** @type {number|null} */
  let importGeneration = null;
  let disposed = false;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;
  let recovering = false;
  /** @type {boolean|null} */
  let watchdogEnabled = null;

  /** @type {AbortController|null} */
  let watchdogAbort = null;
  /** @type {AbortController|null} */
  let catalogAbort = null;
  /** @type {AbortController|null} */
  let catalogLiveStatusAbort = null;
  /** @type {AbortController|null} */
  let catalogEnrichAbort = null;
  /** @type {AbortController|null} */
  let mutateAbort = null;
  /** @type {AbortController|null} */
  let parseAbort = null;
  /** @type {AbortController|null} */
  let importAbort = null;

  let catalogLoading = false;
  let catalogLoaded = false;
  let catalogRefreshing = false;
  /** @type {unknown|null} */
  let catalogError = null;
  /** @type {Array<Record<string, unknown>>} */
  let catalogItems = [];
  /** @type {Record<string, { live_probed?: boolean, live_tunnel_verification_status?: string|null, probe_error?: string|null, observed_at?: string|null, routed_through_tunnel?: boolean|null, routing_probe_status?: string|null }>} */
  let catalogLiveStatusById = {};
  let catalogLiveChecking = false;
  /** @type {Record<string, { status: 'pending'|'ready'|'failed', detail?: Record<string, unknown> }>} */
  let catalogDetailsById = {};

  /** @type {'idle'|'observe'|'validate'|'activate'|'deactivate'|'connect'|'disconnect'|'reconnect'} */
  let longOpKind = 'idle';
  /** @type {'reconnect_teardown'|'preview'|'apply'|'teardown'|null} */
  let mutationPhase = null;

  let selectedWgId = tunnelOptions[0]?.wgId ?? 'Wireguard5';
  let wgIdUserTouched = false;
  /** @type {unknown|null} */
  let preparedParse = null;
  let lastProfileText = '';
  /** @type {string[]} */
  let preparedOperatorLines = [];
  /** @type {string[]} */
  let preparedTechnicalLines = [];

  /** @type {Record<string, unknown>} */
  let configurationResponsesByWgId = {};
  /** @type {Record<string, { tunnelVerificationStatus: string|null, technicalLines: string[] }>} */
  let tunnelOutcomesByWgId = {};
  /** @type {Record<string, boolean>} */
  let applyTimeoutUnknownByWgId = {};

  let connecting = false;
  let observing = false;
  let mutating = false;
  let parsingProfile = false;
  let importingCatalog = false;
  let riskModalOpen = false;
  let importModalOpen = false;

  /** @type {{ wgId: string, profileDigest: string|null, hasPreparedParse: boolean, action: VpnRiskAction }|null} */
  let confirmedIntentSnapshot = null;

  /** @type {unknown|null} */
  let operationError = null;
  /** @type {(() => void)|null} */
  let operationRetry = null;

  /** @type {Record<string, string>} */
  let validatingProfileIds = {};
  /** @type {Record<string, string>} */
  let activatingProfileIds = {};
  /** @type {Record<string, string>} */
  let deactivatingProfileIds = {};
  /** @type {Record<string, string>} */
  let removingProfileIds = {};

  /** @type {string|null} */
  let lastBannerSignature = null;
  /** @type {string|null} */
  let lastHeaderSignature = null;
  /** @type {string|null} */
  let lastStatusSignature = null;
  /** @type {string|null} */
  let lastActiveConfigSignature = null;
  /** @type {string|null} */
  let lastSideSignature = null;
  /** @type {string|null} */
  let lastCatalogSignature = null;
  /** @type {string|null} */
  let lastFooterSignature = null;
  /** @type {string|null} */
  let lastMainExtraSignature = null;
  let layoutMounted = false;

  /** @type {Array<{ close: () => void }>} */
  let openModals = [];
  /** @type {{ kind: string, id?: string }|null} */
  let pendingFocus = null;

  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-vpn';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.id = 'hub-vpn-screen-title';
  title.tabIndex = -1;
  title.textContent = 'VPN';
  header.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent = 'Профили VPN и туннель до сервера';
  header.appendChild(subtitle);
  screen.appendChild(header);

  const contentWrap = document.createElement('div');
  contentWrap.className = 'hub-vpn__content hub-wifi__content';
  screen.appendChild(contentWrap);

  const bannerSlot = document.createElement('div');
  bannerSlot.className = 'hub-wifi__layout-banner';

  const headerSlot = document.createElement('div');
  headerSlot.className = 'hub-wifi__layout-network-header';

  const mainCol = document.createElement('div');
  mainCol.className = 'hub-wifi__layout-main';

  const sideCol = document.createElement('div');
  sideCol.className = 'hub-wifi__layout-side';

  const catalogSlot = document.createElement('div');
  catalogSlot.className = 'hub-vpn__catalog-slot hub-wifi__layout-network-header';

  const statusSlot = document.createElement('div');
  statusSlot.id = 'hub-vpn-status-slot';
  statusSlot.className = 'hub-vpn__status-slot';

  const footer = document.createElement('footer');
  footer.className = 'hub-vpn__footer hub-wifi__footer';
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
    if (active instanceof HTMLElement && slot.contains(active)) {
      if (active.id) {
        pendingFocus = { kind: 'element-id', id: active.id };
      } else {
        const focusKey = active.getAttribute('data-hub-vpn-focus-key');
        if (focusKey) {
          pendingFocus = { kind: 'focus-key', key: focusKey };
        }
      }
    }
    rebuild();
    restorePendingFocus();
    restoreHubContentScroll(scrollTop);
  }

  /**
   * @param {Record<string, unknown>} item
   * @returns {Record<string, unknown>}
   */
  function projectCatalogTileItem(item) {
    const payload = /** @type {Record<string, unknown>} */ (item ?? {});
    const profileId =
      typeof payload.profile_id === 'string' ? payload.profile_id : '';
    const isActive = payload.is_active === true;
    const live = isActive && profileId ? catalogLiveStatusById[profileId] : null;
    /** @type {Record<string, unknown>} */
    const projected = {
      profile_id: profileId,
      display_name: payload.display_name,
      vpn_kind: payload.vpn_kind,
      validation_status: payload.validation_status,
      is_active: payload.is_active,
      assigned_wg_id: payload.assigned_wg_id,
      checking: isActive && catalogLiveChecking,
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

  function catalogItemsDigest() {
    return catalogItems
      .map((item) => {
        const projected = projectCatalogTileItem(item);
        const tileStatus = describeVpnProfileTileStatus(projected);
        const described = describeVpnProfileItem(item);
        const badge = describeCatalogConnectionBadge(item);
        const enrich = catalogDetailsById[described.id];
        let enrichPart = 'enrich:none';
        if (enrich) {
          if (enrich.status === 'pending') {
            enrichPart = 'enrich:pending';
          } else if (enrich.status === 'failed') {
            enrichPart = 'enrich:failed';
          } else if (enrich.status === 'ready' && enrich.detail) {
            const keepalive = describeVpnProfileKeepalive(enrich.detail);
            const notes = extractVpnProfileOperatorNotes(enrich.detail).join('|');
            enrichPart = `enrich:ready|${keepalive.label ?? 'none'}|${notes}`;
          }
        }
        return `${described.id}|${described.validationLabel}|${badge.label}|${tileStatus.label}|${tileStatus.kind}|${enrichPart}`;
      })
      .join(';');
  }

  /**
   * @param {unknown} detail
   * @returns {Record<string, unknown>}
   */
  function projectVpnProfileDetailForCatalog(detail) {
    const payload = /** @type {Record<string, unknown>} */ (detail ?? {});
    /** @type {Record<string, unknown>} */
    const projected = {};
    const intentFields =
      payload.wireguard_intent_fields && typeof payload.wireguard_intent_fields === 'object'
        ? /** @type {Record<string, unknown>} */ (payload.wireguard_intent_fields)
        : null;
    const metadata =
      payload.metadata && typeof payload.metadata === 'object'
        ? /** @type {Record<string, unknown>} */ (payload.metadata)
        : null;

    /** @type {Record<string, unknown>} */
    const projectedIntent = {};
    /** @type {Record<string, unknown>} */
    const projectedMetadata = {};

    if (
      intentFields
      && Object.prototype.hasOwnProperty.call(intentFields, 'peer_keepalive_interval')
    ) {
      const value = intentFields.peer_keepalive_interval;
      if (typeof value === 'number' || value === null) {
        projectedIntent.peer_keepalive_interval = value;
      }
    }
    if (
      metadata
      && Object.prototype.hasOwnProperty.call(metadata, 'peer_keepalive_interval')
    ) {
      const value = metadata.peer_keepalive_interval;
      if (typeof value === 'number' || value === null) {
        projectedMetadata.peer_keepalive_interval = value;
      }
    }
    if (Object.keys(projectedIntent).length > 0) {
      projected.wireguard_intent_fields = projectedIntent;
    }
    if (Object.keys(projectedMetadata).length > 0) {
      projected.metadata = projectedMetadata;
    }

    const operatorNotes = extractVpnProfileOperatorNotes(payload);
    if (operatorNotes.length > 0) {
      projected.operator_notes = operatorNotes;
    }

    const unsupportedFields = Array.isArray(payload.unsupported_fields)
      ? payload.unsupported_fields.filter((item) => typeof item === 'string' && item.trim())
      : [];
    if (unsupportedFields.length > 0) {
      projected.unsupported_fields = unsupportedFields;
    }

    return projected;
  }

  /**
   * @param {number} gen
   */
  async function startEnrichCatalogLiveStatus(gen) {
    catalogLiveStatusAbort?.abort();
    catalogLiveStatusAbort = new AbortController();
    const liveController = catalogLiveStatusAbort;
    const signal = liveController.signal;
    catalogLiveStatusById = {};
    catalogLiveChecking = true;
    renderCatalogSlot();

    try {
      const response = await fetchVpnCatalogLiveStatus({
        session: getSession(),
        signal,
      });
      if (disposed || gen !== catalogGeneration || signal.aborted) {
        return;
      }
      const payload = /** @type {Record<string, unknown>} */ (response ?? {});
      const rows = Array.isArray(payload.items)
        ? payload.items.filter((item) => item && typeof item === 'object')
        : [];
      /** @type {Record<string, { live_probed?: boolean, live_tunnel_verification_status?: string|null, probe_error?: string|null, observed_at?: string|null, routed_through_tunnel?: boolean|null, routing_probe_status?: string|null }>} */
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
          probe_error:
            typeof entry.probe_error === 'string' ? entry.probe_error : null,
          observed_at:
            typeof entry.observed_at === 'string' ? entry.observed_at : null,
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
      const activeProfileIds = new Set(
        catalogItems
          .map((catalogItem) => {
            const row = /** @type {Record<string, unknown>} */ (catalogItem ?? {});
            return row.is_active === true && typeof row.profile_id === 'string'
              ? row.profile_id
              : '';
          })
          .filter(Boolean),
      );
      for (const cachedProfileId of Object.keys(nextLive)) {
        if (!activeProfileIds.has(cachedProfileId)) {
          delete nextLive[cachedProfileId];
        }
      }
      catalogLiveStatusById = nextLive;
    } catch {
      if (disposed || gen !== catalogGeneration || signal.aborted) {
        return;
      }
      /** @type {typeof catalogLiveStatusById} */
      const failedLive = {};
      for (const item of catalogItems) {
        const row = /** @type {Record<string, unknown>} */ (item ?? {});
        const profileId =
          typeof row.profile_id === 'string' ? row.profile_id : '';
        if (!profileId || row.is_active !== true) {
          continue;
        }
        failedLive[profileId] = {
          live_probed: true,
          live_tunnel_verification_status: null,
          probe_error: VPN_TUNNEL_UNVERIFIED_MESSAGE,
          observed_at: null,
          routed_through_tunnel: null,
          routing_probe_status: null,
        };
      }
      catalogLiveStatusById = failedLive;
    } finally {
      if (catalogLiveStatusAbort === liveController) {
        catalogLiveStatusAbort = null;
      }
      if (disposed || gen !== catalogGeneration) {
        return;
      }
      catalogLiveChecking = false;
      renderCatalogSlot();
    }
  }

  /**
   * @param {number} gen
   */
  async function startEnrichCatalogDetails(gen) {
    catalogEnrichAbort?.abort();
    catalogEnrichAbort = new AbortController();
    const enrichController = catalogEnrichAbort;
    const signal = enrichController.signal;

    const ids = catalogItems
      .map((item) => {
        const payload = /** @type {Record<string, unknown>} */ (item ?? {});
        return typeof payload.profile_id === 'string' ? payload.profile_id : '';
      })
      .filter(Boolean);

    const tasks = ids.map(async (profileId) => {
      try {
        const detail = await getVpnProfile({ profileId, signal });
        if (signal.aborted) {
          return { profileId, status: /** @type {'failed'} */ ('failed') };
        }
        return {
          profileId,
          status: /** @type {'ready'} */ ('ready'),
          detail: projectVpnProfileDetailForCatalog(detail),
        };
      } catch {
        return { profileId, status: /** @type {'failed'} */ ('failed') };
      }
    });

    const settled = await Promise.allSettled(tasks);
    if (disposed || gen !== catalogGeneration || signal.aborted) {
      return;
    }

    /** @type {Record<string, { status: 'pending'|'ready'|'failed', detail?: Record<string, unknown> }>} */
    const nextDetails = {};
    for (const outcome of settled) {
      if (outcome.status !== 'fulfilled') {
        continue;
      }
      const result = outcome.value;
      if (result.status === 'ready' && result.detail) {
        nextDetails[result.profileId] = {
          status: 'ready',
          detail: result.detail,
        };
      } else {
        nextDetails[result.profileId] = { status: 'failed' };
      }
    }
    catalogDetailsById = nextDetails;

    renderCatalogSlot();
  }

  function buildBannerSignature() {
    const parts = [adapterMode ?? 'null', offline ? 'offline' : 'online', recovering ? 'recovering' : 'idle'];
    if (adapterMode !== 'fake' && mutationReadiness().allowed) {
      parts.push('live-device');
    }
    return parts.join('|');
  }

  function buildHeaderSignature() {
    const state = screenState();
    return [
      selectedWgId,
      headerBadgeLabel(),
      state.tunnelStatusDescription,
      controlsLocked() ? 'locked' : 'unlocked',
      offline ? 'offline' : 'online',
      state.canApply ? 'can-apply' : 'no-apply',
    ].join('|');
  }

  function buildStatusSignature() {
    const status = currentStatusLines();
    const technicalDigest = status?.technicalLines?.join('\n') ?? '';
    return [
      selectedWgId,
      longOpKind,
      mutationPhase ?? 'none',
      observing ? 'observing' : 'idle',
      connecting ? 'connecting' : 'idle',
      mutating ? 'mutating' : 'idle',
      operationError ? describeError(operationError).title : 'none',
      applyTimeoutUnknownByWgId[selectedWgId] ? 'timeout-unknown' : 'ok',
      tunnelOutcomesByWgId[selectedWgId]?.tunnelVerificationStatus ?? 'none',
      configurationResponsesByWgId[selectedWgId] ? 'has-config' : 'no-config',
      technicalDigest,
    ].join('|');
  }

  function buildActiveConfigSignature() {
    const parseDigest =
      preparedParse && typeof preparedParse === 'object'
        ? /** @type {Record<string, unknown>} */ (preparedParse).profile_digest ?? 'no-digest'
        : 'no-parse';
    return [
      selectedWgId,
      parseDigest,
      preparedOperatorLines.join(';'),
      controlsLocked() ? 'locked' : 'unlocked',
    ].join('|');
  }

  function buildSideSignature() {
    return `watchdog:${watchdogEnabled === null ? 'unknown' : String(watchdogEnabled)}`;
  }

  function buildCatalogSignature() {
    return [
      catalogItemsDigest(),
      catalogLoading ? 'loading' : 'idle',
      catalogRefreshing ? 'refreshing' : 'idle',
      catalogLoaded ? 'loaded' : 'fresh',
      catalogLiveChecking ? 'live-checking' : 'live-idle',
      catalogError ? describeError(catalogError).title : 'none',
      Object.keys(validatingProfileIds).sort().join(','),
      Object.keys(activatingProfileIds).sort().join(','),
      Object.keys(deactivatingProfileIds).sort().join(','),
      controlsLocked() ? 'locked' : 'unlocked',
      offline ? 'offline' : 'online',
    ].join('|');
  }

  function buildFooterSignature() {
    const state = screenState();
    const readiness = mutationReadiness();
    return [
      selectedWgId,
      state.canApply ? 'can-apply' : 'no-apply',
      state.canTeardown ? 'can-teardown' : 'no-teardown',
      connecting ? 'connecting' : 'idle',
      mutating ? 'mutating' : 'idle',
      longOpKind,
      mutationPhase ?? 'none',
      offline ? 'offline' : 'online',
      controlsLocked() ? 'locked' : 'unlocked',
      readiness.reasonText ?? 'none',
      preparedParse ? 'has-parse' : 'no-parse',
    ].join('|');
  }

  function footerStructureSignature(signature) {
    const parts = signature.split('|');
    // buildFooterSignature: 0-2 wg/apply/teardown; 3-6 busy-only; 7 offline; 8+ locked/reason/parse
    return parts.slice(0, 3).concat(parts.slice(7)).join('|');
  }

  function syncFooterButtonsInPlace() {
    const state = screenState();
    syncActionButtonById('hub-vpn-disconnect-btn', {
      disabled: !state.canTeardown || controlsLocked() || offline,
      busy: mutating && longOpKind === 'disconnect',
    });
    syncActionButtonById('hub-vpn-connect-btn', {
      disabled: !state.canApply || controlsLocked() || offline || connecting,
      busy: connecting,
    });
  }

  function buildMainExtraSignature() {
    if (operationError && !isAborted(operationError)) {
      return `error|${describeError(operationError).title}|${applyTimeoutUnknownByWgId[selectedWgId] ? 'timeout' : 'other'}`;
    }
    if (offline && !recovering) {
      return 'offline-panel';
    }
    if (recovering) {
      return 'recovering';
    }
    return 'none';
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
    contentWrap.appendChild(catalogSlot);
  }

  function syncContentLayoutClasses() {
    contentWrap.classList.remove('hub-wifi__content--single-column');
    bannerSlot.hidden = !bannerSlot.hasChildNodes();
    if (!sideCol.hasChildNodes()) {
      contentWrap.classList.add('hub-wifi__content--single-column');
    }
  }

  function mutationProgressMessage() {
    if (longOpKind === 'observe' || observing) {
      return VPN_OBSERVE_PROGRESS_MESSAGE;
    }
    if (longOpKind === 'validate') {
      return VPN_VALIDATE_PROGRESS_MESSAGE;
    }
    if (longOpKind === 'activate') {
      return VPN_ACTIVATE_PROGRESS_MESSAGE;
    }
    if (longOpKind === 'deactivate') {
      return VPN_DEACTIVATE_PROGRESS_MESSAGE;
    }
    if (longOpKind === 'disconnect' || mutationPhase === 'teardown') {
      return VPN_TEARDOWN_PROGRESS_MESSAGE;
    }
    if (mutationPhase === 'reconnect_teardown') {
      return VPN_RECONNECT_TEARDOWN_PROGRESS_MESSAGE;
    }
    if (mutationPhase === 'preview') {
      return VPN_PREVIEW_PROGRESS_MESSAGE;
    }
    if (mutationPhase === 'apply') {
      return VPN_HANDSHAKE_WAIT_MESSAGE;
    }
    return null;
  }

  function mutationReadiness() {
    return evaluateVpnMutationReadiness(getSession(), adapterMode);
  }

  function screenState() {
    const tunnelOutcome = tunnelOutcomesByWgId[selectedWgId];
    const parseConnectReady = preparedParse
      ? evaluatePreparedParseConnectReadiness(preparedParse).connectReady
      : false;
    return buildVpnScreenState({
      lastTunnelVerificationStatus: tunnelOutcome?.tunnelVerificationStatus ?? null,
      mutationReadiness: mutationReadiness(),
      hasPreparedIntent: parseConnectReady,
      canParseProfile: !offline,
    });
  }

  function clearOutcomesForWgId(wgId) {
    delete configurationResponsesByWgId[wgId];
    delete tunnelOutcomesByWgId[wgId];
    delete applyTimeoutUnknownByWgId[wgId];
  }

  /**
   * @param {string} wgId
   * @param {unknown} response
   */
  function storeMutationOutcome(wgId, response) {
    configurationResponsesByWgId[wgId] = response;
    delete applyTimeoutUnknownByWgId[wgId];
    const payload = /** @type {Record<string, unknown>} */ (response ?? {});
    const tunnelVerificationStatus =
      typeof payload.tunnel_verification_status === 'string'
        ? payload.tunnel_verification_status
        : null;
    const verdict = parseTunnelVerdict(response);
    tunnelOutcomesByWgId[wgId] = {
      tunnelVerificationStatus,
      technicalLines: verdict.technicalLines.filter(
        (line) =>
          !line.startsWith('overall:')
          && !line.startsWith('configuration_verification_status:')
          && !line.startsWith('interface_verification_status:'),
      ),
    };
  }

  /**
   * @param {string} wgId
   * @param {unknown} response
   */
  function storeObserveOutcome(wgId, response) {
    delete applyTimeoutUnknownByWgId[wgId];
    const payload = /** @type {Record<string, unknown>} */ (response ?? {});
    const tunnelVerificationStatus =
      typeof payload.tunnel_verification_status === 'string'
        ? payload.tunnel_verification_status
        : null;
    const verdictExplanation = payload.verdict_explanation ?? null;
    tunnelOutcomesByWgId[wgId] = {
      tunnelVerificationStatus,
      technicalLines: [
        ...(tunnelVerificationStatus
          ? [`tunnel_verification_status: ${tunnelVerificationStatus}`]
          : []),
        ...describeRejectedSignals(verdictExplanation),
        ...describeMissingSignals(verdictExplanation),
      ],
    };
  }

  function buildVpnMutationIntentSnapshot(action) {
    const payload =
      preparedParse && typeof preparedParse === 'object'
        ? /** @type {Record<string, unknown>} */ (preparedParse)
        : null;
    return {
      wgId: selectedWgId,
      profileDigest:
        payload && typeof payload.profile_digest === 'string'
          ? payload.profile_digest
          : null,
      hasPreparedParse: Boolean(preparedParse),
      action,
    };
  }

  /**
   * @param {{ wgId: string, profileDigest: string|null, hasPreparedParse: boolean, action: VpnRiskAction }} confirmedSnapshot
   * @param {VpnRiskAction} action
   * @returns {boolean}
   */
  function assertConfirmedIntentStillValid(confirmedSnapshot, action) {
    if (confirmedSnapshot.action !== action || confirmedSnapshot.wgId !== selectedWgId) {
      return false;
    }
    if (action !== 'disconnect') {
      if (!preparedParse || !confirmedSnapshot.hasPreparedParse) {
        return false;
      }
      const parseReadiness = evaluatePreparedParseConnectReadiness(preparedParse);
      if (!parseReadiness.connectReady) {
        return false;
      }
      const payload =
        preparedParse && typeof preparedParse === 'object'
          ? /** @type {Record<string, unknown>} */ (preparedParse)
          : null;
      const currentDigest =
        payload && typeof payload.profile_digest === 'string'
          ? payload.profile_digest
          : null;
      if (confirmedSnapshot.profileDigest !== currentDigest) {
        return false;
      }
    }
    if (!mutationReadiness().allowed) {
      return false;
    }
    return true;
  }

  function invalidateAllOperations() {
    generation += 1;
    catalogGeneration += 1;
    observeGeneration += 1;
    catalogAbort?.abort();
    catalogEnrichAbort?.abort();
    catalogLiveStatusAbort?.abort();
    mutateAbort?.abort();
    parseAbort?.abort();
    importAbort?.abort();
    catalogLoading = false;
    catalogRefreshing = false;
    catalogLoadGeneration = null;
    connecting = false;
    observing = false;
    mutating = false;
    longOpKind = 'idle';
    mutationPhase = null;
    parsingProfile = false;
    importingCatalog = false;
    observeLoadGeneration = null;
    mutateGeneration = null;
    parseGeneration = null;
    importGeneration = null;
    validatingProfileIds = {};
    activatingProfileIds = {};
    deactivatingProfileIds = {};
    removingProfileIds = {};
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
    if (target.kind === 'element-id' && target.id) {
      const el = document.getElementById(target.id);
      if (el instanceof HTMLElement) {
        if (
          (el instanceof HTMLButtonElement || el instanceof HTMLInputElement)
          && el.disabled
        ) {
          title.focus();
          return;
        }
        pendingFocus = null;
        el.focus();
        return;
      }
    }
    if (target.kind === 'focus-key' && target.key) {
      const el = screen.querySelector(`[data-hub-vpn-focus-key="${target.key}"]`);
      if (el instanceof HTMLElement) {
        if (
          (el instanceof HTMLButtonElement || el instanceof HTMLInputElement)
          && el.disabled
        ) {
          title.focus();
          return;
        }
        pendingFocus = null;
        el.focus();
        return;
      }
    }
    pendingFocus = null;
    title.focus();
  }

  function clearPreparedSecrets() {
    preparedParse = null;
    preparedOperatorLines = [];
    preparedTechnicalLines = [];
  }

  function controlsLocked() {
    return (
      connecting
      || observing
      || mutating
      || parsingProfile
      || importingCatalog
      || riskModalOpen
      || importModalOpen
    );
  }

  function currentStatusLines() {
    if (connecting) {
      return null;
    }
    if (applyTimeoutUnknownByWgId[selectedWgId]) {
      return {
        configuration: {
          hubState: HubState.WARNING,
          title: 'Настройка на роутере',
          message: VPN_APPLY_TIMEOUT_UNKNOWN_CONFIGURATION_MESSAGE,
        },
        tunnel: {
          hubState: HubState.WARNING,
          title: 'Связь с сервером VPN',
          message: VPN_APPLY_TIMEOUT_UNKNOWN_TUNNEL_MESSAGE,
        },
        traffic: describeTrafficRouting(),
        technicalLines: [],
        healthy: false,
      };
    }
    const configurationResponse = configurationResponsesByWgId[selectedWgId] ?? null;
    const tunnelStored = tunnelOutcomesByWgId[selectedWgId];
    const configuration = describeConfigurationOutcome(configurationResponse);
    const tunnel = describeTunnelStatus(tunnelStored?.tunnelVerificationStatus ?? null);
    /** @type {string[]} */
    const technicalLines = [
      ...describeConfigurationTechnicalLines(configurationResponse),
      ...(tunnelStored?.technicalLines ?? []),
    ];
    return {
      configuration,
      tunnel,
      traffic: describeTrafficRouting(),
      technicalLines,
      healthy: tunnelStored?.tunnelVerificationStatus === 'tunnel_healthy',
    };
  }

  function headerBadgeLabel() {
    const state = screenState();
    if (state.tunnelStatusIndicatorOn) {
      return 'Ответ сервера есть';
    }
    if (tunnelOutcomesByWgId[selectedWgId]?.tunnelVerificationStatus) {
      return 'Есть ответ observe';
    }
    return 'Не проверено';
  }

  /**
   * @param {VpnRiskAction} action
   * @param {() => Promise<void>} onConfirm
   * @param {HTMLElement|null} returnFocusTo
   */
  function openVpnRiskModal(action, onConfirm, returnFocusTo) {
    const wgLabel = wgIdToLabel(selectedWgId);
    confirmedIntentSnapshot = buildVpnMutationIntentSnapshot(action);
    const body = buildRiskModalBody({
      leadLines: [
        'Если ваш путь управления идёт через этот роутер, смена туннеля может временно оборвать связь с панелью.',
        'Применение туннеля настраивает только туннель на роутере и не направляет трафик устройств через VPN.',
        'Страница может перестать отвечать, пока роутер применяет настройки.',
        'Как вернуться: подключитесь по кабелю, через другую сеть роутера или другой путь управления, если туннель был вашим каналом связи.',
        'При сбое система пытается откатить частично применённые команды туннеля; автоматического восстановления пути управления или маршрутизации трафика устройств нет.',
      ],
      changeLines: buildVpnRiskChangeLines(action, wgLabel),
      bodyClassName: 'hub-vpn__risk-body hub-wifi__risk-body',
    });

    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    let confirmed = false;
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
      label: vpnRiskConfirmLabel(action),
      variant: action === 'disconnect' ? 'danger' : 'primary',
      onActivate: () => {
        confirmed = true;
        const confirmedSnapshot = confirmedIntentSnapshot;
        pendingFocus = {
          kind: 'element-id',
          id: action === 'disconnect' ? 'hub-vpn-disconnect-btn' : 'hub-vpn-connect-btn',
        };
        modalRef?.close();
        if (offline) {
          ctx.showToast({
            tone: 'danger',
            title: 'Нет связи с сервером управления',
            message: 'Подтвердить действие сейчас нельзя — дождитесь восстановления связи.',
          });
          return;
        }
        if (!confirmedSnapshot || !assertConfirmedIntentStillValid(confirmedSnapshot, action)) {
          ctx.showToast({
            tone: 'warning',
            title: 'Подтверждение устарело',
            message: VPN_MUTATION_INTENT_STALE_MESSAGE,
          });
          return;
        }
        void onConfirm();
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
            restorePendingFocus();
          }
        },
      }),
    );
  }

  function openImportModal(returnFocusTo) {
    if (importModalOpen || offline || !screenState().canPrepareProfile) {
      return;
    }
    importModalOpen = true;
    /** @type {HTMLTextAreaElement|null} */
    let textareaEl = null;
    /** @type {{ close: () => void }|null} */
    let modalRef = null;

    const body = document.createElement('div');
    body.className = 'hub-vpn__import-body';

    const secretsNote = document.createElement('p');
    secretsNote.className = 'hub-vpn__note';
    secretsNote.textContent = VPN_IMPORT_SECRETS_NOTE;
    body.appendChild(secretsNote);

    const textarea = document.createElement('textarea');
    textarea.className = 'hub-vpn__import-textarea';
    textarea.id = 'hub-vpn-import-textarea';
    textarea.rows = 8;
    textarea.setAttribute('aria-label', 'Текст конфигурации VPN');
    textarea.placeholder = 'Вставьте содержимое файла .conf';
    body.appendChild(textarea);
    textareaEl = textarea;

    const displayNameField = createTextField({
      id: 'hub-vpn-import-display-name',
      label: 'Название для каталога',
      value: '',
      placeholder: 'Например: офисный туннель',
    });
    body.appendChild(displayNameField);

    const parseResult = document.createElement('div');
    parseResult.className = 'hub-vpn__parse-result';
    parseResult.hidden = true;
    body.appendChild(parseResult);

    const catalogNote = document.createElement('p');
    catalogNote.className = 'hub-vpn__note';
    catalogNote.textContent = VPN_CATALOG_IMPORT_NOT_CONNECTION_NOTE;
    body.appendChild(catalogNote);

    const prepareBtn = createButton({
      label: parsingProfile ? 'Разбираем…' : 'Подготовить к подключению',
      variant: 'primary',
      disabled: parsingProfile || importingCatalog || offline || !screenState().canPrepareProfile,
      onActivate: () => {
        void runParseProfile();
      },
    });

    const catalogBtn = createButton({
      label: importingCatalog ? 'Сохраняем…' : 'Сохранить в каталог',
      variant: 'secondary',
      disabled: parsingProfile || importingCatalog || offline || !screenState().canPrepareProfile,
      onActivate: () => {
        void runCatalogImport();
      },
    });

    const closeBtn = createButton({
      label: 'Закрыть',
      variant: 'ghost',
      disabled: parsingProfile || importingCatalog,
      onActivate: () => {
        modalRef?.close();
      },
    });

    function renderParseResult(summary) {
      parseResult.hidden = false;
      clearElement(parseResult);
      for (const line of summary.operatorLines) {
        const p = document.createElement('p');
        p.className = 'hub-vpn__parse-line';
        p.textContent = line;
        parseResult.appendChild(p);
      }
      if (summary.technicalLines.length > 0) {
        parseResult.appendChild(
          createTechnicalDetails({
            summary: 'Технические подробности',
            content: summary.technicalLines.join('\n'),
          }),
        );
      }
    }

    async function runParseProfile() {
      if (
        !textareaEl
        || parsingProfile
        || importingCatalog
        || offline
        || !screenState().canPrepareProfile
      ) {
        return;
      }
      const profileText = textareaEl.value;
      lastProfileText = profileText;
      if (!profileText.trim()) {
        ctx.showToast({
          tone: 'warning',
          title: 'Нет текста конфигурации',
          message: 'Вставьте содержимое файла .conf и повторите.',
        });
        return;
      }
      parsingProfile = true;
      prepareBtn.disabled = true;
      catalogBtn.disabled = true;
      closeBtn.disabled = true;
      parseAbort?.abort();
      parseAbort = new AbortController();
      const myController = parseAbort;
      const gen = ++generation;
      parseGeneration = gen;
      try {
        const response = await parseVpnProfileText({
          profileText,
          signal: myController.signal,
        });
        if (disposed || gen !== generation) {
          return;
        }
        preparedParse = response;
        const summary = summarizeParsedProfile(response);
        preparedOperatorLines = summary.operatorLines;
        preparedTechnicalLines = summary.technicalLines;
        textareaEl.value = '';
        renderParseResult(summary);
        if (!disposed) {
          const parseReadiness = evaluatePreparedParseConnectReadiness(response);
          if (parseReadiness.connectReady) {
            ctx.showToast({
              tone: 'success',
              title: 'Конфигурация разобрана',
              message: 'Ключи сохранены только как ссылки — текст из поля удалён.',
            });
          } else {
            ctx.showToast({
              tone: 'warning',
              title: 'Конфигурация разобрана частично',
              message:
                parseReadiness.reasonText
                ?? 'Подключение недоступно — проверьте данные сервера VPN в профиле.',
            });
          }
        }
      } catch (error) {
        if (disposed || gen !== generation || isAborted(error)) {
          return;
        }
        const described = describeError(error);
        if (!disposed) {
          ctx.showToast({
            tone: 'danger',
            title: described.title,
            message: described.message,
          });
        }
      } finally {
        if (parseGeneration === gen) {
          parsingProfile = false;
          parseGeneration = null;
        }
        if (parseAbort === myController) {
          parseAbort = null;
        }
        prepareBtn.disabled =
          parsingProfile || importingCatalog || offline || !screenState().canPrepareProfile;
        catalogBtn.disabled =
          parsingProfile || importingCatalog || offline || !screenState().canPrepareProfile;
        closeBtn.disabled = parsingProfile || importingCatalog;
        if (!disposed && gen === generation) {
          renderAll();
        }
      }
    }

    async function runCatalogImport() {
      if (
        importingCatalog
        || parsingProfile
        || offline
        || !screenState().canPrepareProfile
      ) {
        return;
      }
      const displayNameEl = document.getElementById('hub-vpn-import-display-name');
      const displayName =
        displayNameEl instanceof HTMLInputElement ? displayNameEl.value.trim() : '';
      if (!displayName) {
        ctx.showToast({
          tone: 'warning',
          title: 'Нужно название',
          message: 'Укажите название профиля для каталога.',
        });
        return;
      }
      if (!preparedParse || typeof preparedParse !== 'object') {
        ctx.showToast({
          tone: 'warning',
          title: 'Сначала разберите конфигурацию',
          message: 'Нажмите «Подготовить к подключению» перед сохранением в каталог.',
        });
        return;
      }
      if (!lastProfileText.trim()) {
        ctx.showToast({
          tone: 'warning',
          title: 'Нет текста конфигурации',
          message: 'Сначала загрузите и разберите файл конфигурации.',
        });
        return;
      }
      importingCatalog = true;
      prepareBtn.disabled = true;
      catalogBtn.disabled = true;
      closeBtn.disabled = true;
      importAbort?.abort();
      importAbort = new AbortController();
      const myController = importAbort;
      const gen = ++generation;
      importGeneration = gen;
      try {
        await importVpnProfileToCatalog({
          displayName,
          profileText: lastProfileText,
          vpnKind: 'AmneziaWG',
          wgId: selectedWgId,
          idempotencyKey: createIdempotencyKey(),
          signal: myController.signal,
        });
        if (disposed || gen !== generation) {
          return;
        }
        if (!disposed) {
          ctx.showToast({
            tone: 'success',
            title: 'Профиль сохранён в каталог',
            message: VPN_CATALOG_IMPORT_NOT_CONNECTION_NOTE,
          });
        }
        modalRef?.close();
        void loadCatalogFlow();
      } catch (error) {
        if (disposed || gen !== generation || isAborted(error)) {
          return;
        }
        const described = describeError(error);
        if (!disposed) {
          ctx.showToast({
            tone: 'danger',
            title: described.title,
            message: described.message,
          });
        }
      } finally {
        if (importGeneration === gen) {
          importingCatalog = false;
          importGeneration = null;
        }
        if (importAbort === myController) {
          importAbort = null;
        }
        prepareBtn.disabled =
          parsingProfile || importingCatalog || offline || !screenState().canPrepareProfile;
        catalogBtn.disabled =
          parsingProfile || importingCatalog || offline || !screenState().canPrepareProfile;
        closeBtn.disabled = parsingProfile || importingCatalog;
        if (!disposed && gen === generation) {
          renderAll();
        }
      }
    }

    modalRef = registerModal(
      openModal({
        title: 'Загрузить конфигурацию',
        description: 'Разбор конфигурации не подключает VPN автоматически.',
        body,
        actions: [closeBtn, catalogBtn, prepareBtn],
        ...(returnFocusTo instanceof HTMLElement ? { returnFocusTo } : {}),
        onClose: () => {
          importModalOpen = false;
          parseAbort?.abort();
          importAbort?.abort();
          if (textareaEl) {
            textareaEl.value = '';
          }
          renderAll();
          restorePendingFocus();
        },
      }),
    );
  }

  async function loadWatchdogStatus() {
    if (disposed) {
      return;
    }
    watchdogAbort?.abort();
    watchdogAbort = new AbortController();
    const myController = watchdogAbort;
    try {
      const response = await apiGet('status', { signal: myController.signal });
      const payload = /** @type {Record<string, unknown>} */ (response ?? {});
      watchdogEnabled =
        typeof payload.vpn_watchdog_enabled === 'boolean'
          ? payload.vpn_watchdog_enabled
          : null;
    } catch (error) {
      if (disposed || isAborted(error)) {
        return;
      }
      watchdogEnabled = null;
    } finally {
      if (watchdogAbort === myController) {
        watchdogAbort = null;
      }
      if (!disposed) {
        renderAll();
      }
    }
  }

  async function loadCatalogFlow() {
    if (disposed || catalogLoading) {
      return;
    }
    catalogAbort?.abort();
    catalogEnrichAbort?.abort();
    catalogLiveStatusAbort?.abort();
    catalogAbort = new AbortController();
    const myController = catalogAbort;
    const gen = ++catalogGeneration;
    catalogLoadGeneration = gen;
    const isRefresh = catalogItems.length > 0 || catalogLoaded;
    catalogRefreshing = isRefresh;
    catalogLoading = true;
    catalogError = null;
    renderCatalogSlot();
    let listSucceeded = false;
    try {
      const response = await listVpnProfiles({ signal: myController.signal });
      if (disposed || gen !== catalogGeneration) {
        return;
      }
      const payload = /** @type {Record<string, unknown>} */ (response ?? {});
      catalogItems = Array.isArray(payload.items)
        ? payload.items.filter((item) => item && typeof item === 'object')
        : [];
      catalogLoaded = true;
      listSucceeded = true;
      const activeWithWg = catalogItems.filter((item) => {
        const row = /** @type {Record<string, unknown>} */ (item ?? {});
        if (row.is_active !== true) {
          return false;
        }
        const assigned =
          typeof row.assigned_wg_id === 'string' ? row.assigned_wg_id.trim() : '';
        return Boolean(assigned);
      });
      if (
        activeWithWg.length === 1 &&
        !wgIdUserTouched &&
        !controlsLocked()
      ) {
        const row = /** @type {Record<string, unknown>} */ (activeWithWg[0] ?? {});
        const resolvedWgId =
          typeof row.assigned_wg_id === 'string' ? row.assigned_wg_id.trim() : '';
        if (resolvedWgId && resolvedWgId !== selectedWgId) {
          selectedWgId = resolvedWgId;
          renderHeaderSlot();
          renderStatusSlot();
          renderActiveConfigSlot();
          renderFooter();
        }
      }
      const currentIds = new Set(
        catalogItems
          .map((item) => {
            const row = /** @type {Record<string, unknown>} */ (item ?? {});
            return typeof row.profile_id === 'string' ? row.profile_id : '';
          })
          .filter(Boolean),
      );
      for (const profileId of Object.keys(catalogDetailsById)) {
        if (!currentIds.has(profileId)) {
          delete catalogDetailsById[profileId];
        }
      }
    } catch (error) {
      if (disposed || gen !== catalogGeneration || isAborted(error)) {
        return;
      }
      catalogError = error;
    } finally {
      if (catalogLoadGeneration === gen) {
        catalogLoading = false;
        catalogRefreshing = false;
        catalogLoadGeneration = null;
      }
      if (catalogAbort === myController) {
        catalogAbort = null;
      }
      if (!disposed && gen === catalogGeneration) {
        renderCatalogSlot();
      }
    }
    if (!disposed && gen === catalogGeneration && listSucceeded) {
      void startEnrichCatalogLiveStatus(gen);
      void startEnrichCatalogDetails(gen);
    }
  }

  async function runObserveRecheck() {
    if (disposed || observing || offline || !screenState().canObserve) {
      return;
    }
    observing = true;
    longOpKind = 'observe';
    operationError = null;
    operationRetry = null;
    pendingFocus = { kind: 'element-id', id: 'hub-vpn-recheck-btn' };
    renderStatusSlot();
    renderFooter();
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    const myController = mutateAbort;
    const gen = ++observeGeneration;
    observeLoadGeneration = gen;
    try {
      const observeBody = buildWireguardObserveBody({
        wgId: selectedWgId,
        session: getSession(),
      });
      const response = await observeVpnTunnel({
        observeBody,
        signal: myController.signal,
      });
      if (disposed || gen !== observeGeneration) {
        return;
      }
      storeObserveOutcome(selectedWgId, response);
    } catch (error) {
      if (disposed || gen !== observeGeneration || isAborted(error)) {
        return;
      }
      operationError = error;
      operationRetry = () => {
        void runObserveRecheck();
      };
    } finally {
      if (observeLoadGeneration === gen) {
        observing = false;
        longOpKind = 'idle';
        observeLoadGeneration = null;
      }
      if (mutateAbort === myController) {
        mutateAbort = null;
      }
      if (!disposed && gen === observeGeneration) {
        pendingFocus = { kind: 'element-id', id: 'hub-vpn-recheck-btn' };
        renderStatusSlot();
        renderMainExtraSlot();
        renderFooter();
        restorePendingFocus();
      }
    }
  }

  /**
   * @param {VpnRiskAction} action
   */
  async function runTunnelMutation(action) {
    if (disposed || mutating) {
      return;
    }
    if (!preparedParse && action !== 'disconnect') {
      ctx.showToast({
        tone: 'warning',
        title: 'Нет подготовленной конфигурации',
        message: 'Сначала разберите файл .conf через «Загрузить конфигурацию».',
      });
      return;
    }
    if (action !== 'disconnect') {
      const parseReadiness = evaluatePreparedParseConnectReadiness(preparedParse);
      if (!parseReadiness.connectReady) {
        ctx.showToast({
          tone: 'warning',
          title: 'Подключение недоступно',
          message:
            parseReadiness.reasonText
            ?? 'В конфигурации нет данных сервера VPN — подключение недоступно',
        });
        return;
      }
    }
    const wgId = selectedWgId;
    mutating = true;
    longOpKind = action;
    if (action === 'disconnect') {
      mutationPhase = 'teardown';
    } else if (action === 'reconnect') {
      mutationPhase = 'reconnect_teardown';
    } else if (action === 'connect') {
      mutationPhase = 'preview';
    } else {
      mutationPhase = null;
    }
    connecting = action === 'connect' || action === 'reconnect';
    operationError = null;
    operationRetry = null;
    if (connecting) {
      clearOutcomesForWgId(wgId);
    }
    renderStatusSlot();
    renderFooter();
    const gen = ++generation;
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    const myController = mutateAbort;
    mutateGeneration = gen;
    try {
      if (action === 'disconnect') {
        const intentBody = preparedParse
          ? buildWireguardIntentFromParsePreview(preparedParse, wgId, false)
          : buildWireguardIntentBody({ wgId, enabled: false });
        const teardownBody = buildWireguardTeardownBody({
          intentBody,
          session: getSession(),
        });
        const response = await teardownVpnTunnel({ teardownBody, signal: myController.signal });
        if (disposed || gen !== generation || mutateGeneration !== gen) {
          return;
        }
        storeMutationOutcome(wgId, response);
        const overall =
          typeof response?.overall === 'string' ? response.overall : null;
        if (overall !== 'applied' && !disposed) {
          const outcome = describeConfigurationOutcome(response);
          const tone = getStateDescriptor(outcome.hubState).tone;
          ctx.showToast({
            tone,
            title: outcome.title,
            message: outcome.message,
          });
        } else if (!disposed) {
          ctx.showToast({
            tone: 'success',
            message: 'Отключено',
          });
        }
      } else {
        if (action === 'reconnect') {
          mutationPhase = 'reconnect_teardown';
          renderStatusSlot();
          try {
            const teardownIntent = buildWireguardIntentFromParsePreview(
              preparedParse,
              wgId,
              false,
            );
            const teardownBody = buildWireguardTeardownBody({
              intentBody: teardownIntent,
              session: getSession(),
            });
            const teardownResponse = await teardownVpnTunnel({
              teardownBody,
              signal: myController.signal,
            });
            if (disposed || gen !== generation || mutateGeneration !== gen) {
              return;
            }
            storeMutationOutcome(wgId, teardownResponse);
            const teardownOverall =
              typeof teardownResponse?.overall === 'string' ? teardownResponse.overall : null;
            if (teardownOverall !== 'applied') {
              if (!disposed) {
                const outcome = describeConfigurationOutcome(teardownResponse);
                const tone = getStateDescriptor(outcome.hubState).tone;
                ctx.showToast({
                  tone,
                  title: outcome.title,
                  message: outcome.message,
                });
              }
              return;
            }
          } catch (error) {
            if (disposed || gen !== generation || mutateGeneration !== gen || isAborted(error)) {
              return;
            }
            const described = describeError(error);
            operationError = error;
            operationRetry = () => {
              openVpnRiskModal(action, () => runTunnelMutation(action), null);
            };
            if (!disposed) {
              ctx.showToast({
                tone: 'danger',
                title: described.title,
                message: described.message,
              });
            }
            return;
          }
          if (disposed || gen !== generation || mutateGeneration !== gen) {
            return;
          }
        }
        mutationPhase = 'preview';
        renderStatusSlot();
        const intentBody = buildWireguardIntentFromParsePreview(preparedParse, wgId, true);
        await previewVpnTunnel({ intentBody, signal: myController.signal });
        if (disposed || gen !== generation || mutateGeneration !== gen) {
          return;
        }
        mutationPhase = 'apply';
        renderStatusSlot();
        const applyBody = buildWireguardApplyBody({
          intentBody,
          session: getSession(),
        });
        const response = await applyVpnTunnel({ applyBody, signal: myController.signal });
        if (disposed || gen !== generation || mutateGeneration !== gen) {
          return;
        }
        storeMutationOutcome(wgId, response);
        const overall =
          typeof response?.overall === 'string' ? response.overall : null;
        if (overall !== 'applied' && !disposed) {
          const outcome = describeConfigurationOutcome(response);
          const tone = getStateDescriptor(outcome.hubState).tone;
          ctx.showToast({
            tone,
            title: outcome.title,
            message: outcome.message,
          });
        } else {
          const stored = tunnelOutcomesByWgId[wgId];
          const healthy = stored?.tunnelVerificationStatus === 'tunnel_healthy';
          if (!healthy && !disposed) {
            ctx.showToast({
              tone: 'warning',
              title: 'Туннель применён, ответ сервера не подтверждён',
              message: VPN_POST_SETTLE_RECHECK_HINT,
            });
          }
        }
      }
    } catch (error) {
      if (disposed || gen !== generation || mutateGeneration !== gen || isAborted(error)) {
        return;
      }
      const described = describeError(error);
      if (described.kind === ERROR_KIND.TIMEOUT && (action === 'connect' || action === 'reconnect')) {
        applyTimeoutUnknownByWgId[wgId] = true;
        operationError = error;
        operationRetry = () => {
          void runObserveRecheck();
        };
        if (!disposed) {
          ctx.showToast({
            tone: 'warning',
            title: described.title,
            message:
              'Ответ сервера управления не получен вовремя. Настройки могли уже примениться — проверьте состояние.',
          });
        }
      } else {
        operationError = error;
        operationRetry = () => {
          openVpnRiskModal(action, () => runTunnelMutation(action), null);
        };
        if (!disposed) {
          ctx.showToast({
            tone: 'danger',
            title: described.title,
            message: described.message,
          });
        }
      }
    } finally {
      if (mutateGeneration === gen) {
        mutating = false;
        connecting = false;
        longOpKind = 'idle';
        mutationPhase = null;
        mutateGeneration = null;
      }
      if (mutateAbort === myController) {
        mutateAbort = null;
      }
      if (!disposed && gen === generation) {
        renderStatusSlot();
        renderMainExtraSlot();
        renderFooter();
        restorePendingFocus();
      }
    }
  }

  function statusInlineTitle(hubState) {
    switch (hubState) {
      case HubState.WARNING:
        return 'Внимание';
      case HubState.ERROR:
        return 'Ошибка';
      case HubState.UNSUPPORTED:
        return 'Не поддерживается';
      case HubState.CONNECTING:
        return 'Подключение';
      case HubState.LOADING:
        return 'Загрузка';
      default:
        return 'Нет данных';
    }
  }

  function renderStatusLine(line, index) {
    const row = document.createElement('div');
    row.className = 'hub-vpn__status-line';

    const label = document.createElement('div');
    label.className = 'hub-vpn__status-line-label';
    label.textContent = line.title;
    row.appendChild(label);

    const valueWrap = document.createElement('div');
    valueWrap.className = 'hub-vpn__status-line-value';

    valueWrap.appendChild(
      createInlineState({
        state: line.hubState,
        title: statusInlineTitle(line.hubState),
      }),
    );

    const message = document.createElement('p');
    message.className = 'hub-vpn__status-message';
    message.textContent = line.message;
    valueWrap.appendChild(message);

    if (line.technicalDetail) {
      valueWrap.appendChild(
        createTechnicalDetails({
          summary: 'Технические подробности',
          content: line.technicalDetail,
        }),
      );
    }
    row.appendChild(valueWrap);

    if (index === 1 && tunnelOutcomesByWgId[selectedWgId] && !connecting) {
      const status = currentStatusLines();
      if (status && !status.healthy) {
        const recheckDisabled =
          !screenState().canObserve || observing || controlsLocked() || offline;
        const recheckBtn = createButton({
          label: applyTimeoutUnknownByWgId[selectedWgId]
            ? 'Проверить состояние'
            : 'Проверить ещё раз',
          variant: 'secondary',
          disabled: recheckDisabled,
          busy: observing,
          onActivate: () => {
            pendingFocus = { kind: 'element-id', id: 'hub-vpn-recheck-btn' };
            void runObserveRecheck();
          },
        });
        recheckBtn.id = 'hub-vpn-recheck-btn';
        updateButtonBusyState(recheckBtn, observing, recheckDisabled);
        if (recheckDisabled) {
          const recheckReasonId = 'hub-vpn-recheck-reason';
          let recheckReason = null;
          if (offline) {
            recheckReason = 'Нет связи с сервером управления';
          } else if (!screenState().canObserve) {
            recheckReason = mutationReadiness().reasonText
              ?? 'Сначала завершите подключение к роутеру на экране «Подключение»';
          } else if (controlsLocked()) {
            recheckReason = 'Дождитесь завершения текущей операции';
          }
          if (recheckReason) {
            const reasonEl = document.createElement('p');
            reasonEl.className = 'hub-vpn__note hub-vpn__action-reason';
            reasonEl.id = recheckReasonId;
            reasonEl.textContent = recheckReason;
            valueWrap.appendChild(reasonEl);
            recheckBtn.setAttribute('aria-describedby', recheckReasonId);
          }
        }
        const hint = document.createElement('p');
        hint.className = 'hub-vpn__note';
        hint.textContent = applyTimeoutUnknownByWgId[selectedWgId]
          ? 'Повторная проверка только читает состояние на роутере, без повторной записи настроек.'
          : VPN_POST_SETTLE_RECHECK_HINT;
        valueWrap.appendChild(hint);
        valueWrap.appendChild(recheckBtn);
      }
    }

    return row;
  }

  function renderNetworkHeader() {
    const state = screenState();
    const badge = createBadge({
      label: headerBadgeLabel(),
      tone: state.tunnelStatusIndicatorOn ? 'neutral' : 'neutral',
    });

    const reconnectBtn = createButton({
      label: 'Переподключить',
      variant: 'secondary',
      disabled: !state.canApply || controlsLocked() || offline,
      busy: mutating && longOpKind === 'reconnect',
      onActivate: () => {
        const focusEl =
          document.activeElement instanceof HTMLElement ? document.activeElement : null;
        openVpnRiskModal(
          'reconnect',
          () => runTunnelMutation('reconnect'),
          focusEl,
        );
      },
    });
    reconnectBtn.id = 'hub-vpn-reconnect-btn';
    updateButtonBusyState(
      reconnectBtn,
      mutating && longOpKind === 'reconnect',
      !state.canApply || controlsLocked() || offline,
    );

    const reconnectReasonId = 'hub-vpn-reconnect-reason';
    let reconnectReason = null;
    if (!state.canApply) {
      if (offline) {
        reconnectReason = 'Нет связи с сервером управления';
      } else if (!preparedParse) {
        reconnectReason = 'Сначала подготовьте конфигурацию через «Загрузить конфигурацию».';
      } else if (mutationReadiness().reasonText) {
        reconnectReason = mutationReadiness().reasonText;
      }
    } else if (controlsLocked()) {
      reconnectReason = 'Дождитесь завершения текущей операции';
    }

    const actionsWrap = document.createElement('div');
    actionsWrap.className = 'hub-vpn__header-actions hub-wifi-network__actions';
    actionsWrap.appendChild(reconnectBtn);
    if (reconnectReason) {
      const reasonEl = document.createElement('p');
      reasonEl.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reasonEl.id = reconnectReasonId;
      reasonEl.textContent = reconnectReason;
      actionsWrap.appendChild(reasonEl);
      reconnectBtn.setAttribute('aria-describedby', reconnectReasonId);
    }

    const interfaceLabel =
      tunnelOptions.find((item) => item.wgId === selectedWgId)?.label ?? selectedWgId;

    return createWifiNetworkHeaderCard({
      iconName: 'vpn',
      ssidTitle: interfaceLabel,
      badge,
      secondaryLine: state.tunnelStatusDescription,
      qrButton: actionsWrap,
      cardClassName: 'hub-vpn__network-card hub-wifi__network-card',
    });
  }

  function renderActiveConfigurationCard() {
    const card = createCard({
      title: 'Активная конфигурация',
      titleTag: 'h2',
    });
    const body = card.querySelector('.hub-card__body') ?? card;

    const wgField = createSelectField({
      id: 'hub-vpn-wg-select',
      label: 'Интерфейс туннеля',
      value: selectedWgId,
      disabled: controlsLocked(),
      options: tunnelOptions.map((item) => ({
        value: item.wgId,
        label: item.label,
      })),
      onChange: (event) => {
        const target = /** @type {HTMLSelectElement} */ (event.target);
        if (target.value !== selectedWgId) {
          selectedWgId = target.value;
          wgIdUserTouched = true;
          renderHeaderSlot();
          renderStatusSlot();
          renderActiveConfigSlot();
          renderFooter();
          restorePendingFocus();
        }
      },
    });
    body.appendChild(wgField);

    const catalogNote = document.createElement('p');
    catalogNote.className = 'hub-vpn__note';
    catalogNote.textContent =
      'Профили каталога хранят ссылки на ключи в хранилище управления — для подключения используйте «Подключить» в списке или «Загрузить конфигурацию».';
    body.appendChild(catalogNote);

    const credWrap = document.createElement('div');
    credWrap.className = 'hub-vpn__credential-summary';
    const credTitle = document.createElement('p');
    credTitle.className = 'hub-vpn__meta-row';
    credTitle.textContent = 'Ссылки на ключи (после разбора конфигурации):';
    credWrap.appendChild(credTitle);
    if (preparedOperatorLines.length > 0) {
      const list = document.createElement('ul');
      list.className = 'hub-vpn__credential-list';
      for (const line of preparedOperatorLines.filter((entry) => entry.includes('ключ'))) {
        const li = document.createElement('li');
        li.textContent = line;
        list.appendChild(li);
      }
      if (!list.hasChildNodes()) {
        const empty = document.createElement('p');
        empty.className = 'hub-vpn__note';
        empty.textContent = 'Ссылки появятся после «Подготовить к подключению».';
        credWrap.appendChild(empty);
      } else {
        credWrap.appendChild(list);
      }
    } else {
      const empty = document.createElement('p');
      empty.className = 'hub-vpn__note';
      empty.textContent = 'Сначала загрузите и разберите конфигурацию — ключи не показываются.';
      credWrap.appendChild(empty);
    }
    body.appendChild(credWrap);

    const btnRow = document.createElement('div');
    btnRow.className = 'hub-vpn__btn-row';
    const importState = screenState();
    btnRow.appendChild(
      createButton({
        label: 'Загрузить конфигурацию',
        variant: 'secondary',
        disabled: controlsLocked() || !importState.canPrepareProfile,
        onActivate: () => {
          const focusEl =
            document.activeElement instanceof HTMLElement ? document.activeElement : null;
          openImportModal(focusEl);
        },
      }),
    );
    body.appendChild(btnRow);

    return card;
  }

  function renderProtectionUnsupportedCard() {
    const card = createUnsupportedCard({
      title: 'Защита соединения',
      description: 'Эти режимы на роутере пока недоступны через управление.',
      noteClassName: 'hub-vpn__unsupported-note hub-wifi__unsupported-note',
    });
    const body = card.querySelector('.hub-card__body') ?? card;
    const list = document.createElement('ul');
    list.className = 'hub-vpn__unsupported-list';
    for (const note of buildVpnProtectionOptions(watchdogEnabled)) {
      const li = document.createElement('li');
      li.textContent = note;
      list.appendChild(li);
    }
    body.appendChild(list);
    return card;
  }

  function renderCatalogCardBody(body) {
    if (catalogLoading && catalogItems.length === 0 && !catalogLoaded) {
      body.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: VPN_CATALOG_INITIAL_LOAD_MESSAGE,
        }),
      );
      body.appendChild(createSkeleton({ lines: 3, withTitle: false }));
      return;
    }

    if (catalogError && !isAborted(catalogError)) {
      const described = describeError(catalogError);
      body.appendChild(
        createStatePanel({
          state: hubStateForError(catalogError),
          titleTag: 'h3',
          title: described.title,
          description: formatErrorDescription(described),
          action: {
            label: 'Повторить',
            onActivate: () => {
              void loadCatalogFlow();
            },
          },
        }),
      );
      if (catalogItems.length === 0) {
        return;
      }
    }

    if (catalogLoading || catalogRefreshing) {
      body.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: VPN_CATALOG_REFRESH_MESSAGE,
        }),
      );
    }

    if (Object.keys(validatingProfileIds).length > 0) {
      body.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: VPN_VALIDATE_PROGRESS_MESSAGE,
        }),
      );
    }

    if (catalogItems.length === 0) {
      body.appendChild(
        createStatePanel({
          state: HubState.EMPTY,
          titleTag: 'h3',
          title: 'Каталог пуст',
          description:
            'Каталог пуст. Чтобы подключить VPN, загрузите и разберите файл конфигурации — импорт в каталог только сохраняет профиль для списка.',
        }),
      );
      return;
    }

    const tileItems = catalogItems.map((item) => projectCatalogTileItem(item));
    body.appendChild(
      createVpnProfileStatusTileGrid({
        items: tileItems,
        disabled: controlsLocked() || offline,
        busyProfileIds: activatingProfileIds,
        deactivatingProfileIds,
        validatingProfileIds: validatingProfileIds,
        onValidate: (profileId) => {
          pendingFocus = { kind: 'element-id', id: `hub-vpn-validate-${profileId}` };
          void validateCatalogProfile(profileId);
        },
        onActivate: (profileId) => {
          pendingFocus = { kind: 'element-id', id: `hub-vpn-activate-${profileId}` };
          void runActivateProfile(profileId);
        },
        onDeactivate: (profileId) => {
          pendingFocus = { kind: 'element-id', id: `hub-vpn-deactivate-${profileId}` };
          void runDeactivateProfile(profileId);
        },
        onRemove: (profileId) => {
          pendingFocus = { kind: 'element-id', id: `hub-vpn-remove-${profileId}` };
          openCatalogRemoveModal(profileId);
        },
      }),
    );

    for (const item of catalogItems) {
      const described = describeVpnProfileItem(item);
      const enrichEntry = catalogDetailsById[described.id];
      if (enrichEntry?.status === 'ready' && enrichEntry.detail) {
        const keepalive = describeVpnProfileKeepalive(enrichEntry.detail);
        if (keepalive.label) {
          const keepaliveNote = document.createElement('p');
          keepaliveNote.className = 'hub-vpn__note';
          keepaliveNote.textContent = keepalive.label;
          body.appendChild(keepaliveNote);
        }
        for (const note of extractVpnProfileOperatorNotes(enrichEntry.detail)) {
          const noteEl = document.createElement('p');
          noteEl.className = 'hub-vpn__note';
          noteEl.textContent = note;
          body.appendChild(noteEl);
        }
      }
    }

    const honestyNote = document.createElement('p');
    honestyNote.className = 'hub-vpn__note';
    honestyNote.textContent = VPN_PROFILE_TILE_STATUS_HONESTY_NOTE;
    body.appendChild(honestyNote);

    const catalogHint = document.createElement('p');
    catalogHint.className = 'hub-vpn__note';
    catalogHint.textContent = VPN_CATALOG_IMPORT_NOT_CONNECTION_NOTE;
    body.appendChild(catalogHint);
  }

  function renderCatalogCard() {
    const card = createCard({
      title: 'Доступные конфигурации',
      titleTag: 'h2',
    });
    const body = card.querySelector('.hub-card__body') ?? card;
    renderCatalogCardBody(body);
    return card;
  }

  async function runActivateProfile(profileId) {
    if (!profileId || activatingProfileIds[profileId] || mutating || offline) {
      return;
    }
    mutating = true;
    longOpKind = 'activate';
    activatingProfileIds = { ...activatingProfileIds, [profileId]: '1' };
    renderStatusSlot();
    renderCatalogSlot();
    renderFooter();
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    const mutationSignal = mutateAbort.signal;
    try {
      const wgId = resolveVpnProfileWgId(catalogItems, profileId, selectedWgId);
      const response = await activateVpnProfile({
        profileId,
        session: getSession(),
        wgId,
        signal: mutationSignal,
      });
      if (disposed || offline || mutationSignal.aborted) {
        return;
      }
      if (response?.activated === true) {
        const tunnelVerificationStatus =
          typeof response.tunnel_verification_status === 'string'
            ? response.tunnel_verification_status
            : null;
        const tunnelHealthy = tunnelVerificationStatus === 'tunnel_healthy';
        if (tunnelVerificationStatus != null && !tunnelHealthy) {
          ctx.showToast({
            tone: 'warning',
            title: 'Профиль активирован, ответ сервера не подтверждён',
            message: VPN_POST_SETTLE_RECHECK_HINT,
          });
        } else {
          ctx.showToast({
            tone: 'success',
            title: 'Профиль активирован',
            message: 'Запрос на подключение отправлен — проверьте состояние туннеля.',
          });
        }
      } else {
        ctx.showToast({
          tone: 'warning',
          title: 'Не активирован',
          message: 'Запрос отправлен, но подтверждения нет — проверьте состояние туннеля.',
        });
      }
      if (!offline && !mutationSignal.aborted) {
        await loadCatalogFlow();
      }
    } catch (error) {
      if (disposed || isAborted(error) || offline) {
        return;
      }
      const describedErr = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: describedErr.title,
        message: formatErrorDescription(describedErr),
      });
    } finally {
      const next = { ...activatingProfileIds };
      delete next[profileId];
      activatingProfileIds = next;
      mutating = false;
      longOpKind = 'idle';
      mutationPhase = null;
      if (!disposed) {
        pendingFocus = { kind: 'element-id', id: `hub-vpn-activate-${profileId}` };
        renderStatusSlot();
        renderCatalogSlot();
        renderFooter();
        restorePendingFocus();
      }
    }
  }

  async function runDeactivateProfile(profileId) {
    if (!profileId || deactivatingProfileIds[profileId] || mutating || offline) {
      return;
    }
    mutating = true;
    longOpKind = 'deactivate';
    deactivatingProfileIds = { ...deactivatingProfileIds, [profileId]: '1' };
    renderStatusSlot();
    renderCatalogSlot();
    renderFooter();
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    const mutationSignal = mutateAbort.signal;
    try {
      const wgId = resolveVpnProfileWgId(catalogItems, profileId, selectedWgId);
      const response = await deactivateVpnProfile({
        wgId,
        session: getSession(),
        signal: mutationSignal,
      });
      if (disposed || offline || mutationSignal.aborted) {
        return;
      }
      if (response?.deactivated === true) {
        ctx.showToast({
          tone: 'success',
          title: 'Профиль отключён',
          message: 'Запрос на отключение отправлен.',
        });
      } else {
        ctx.showToast({
          tone: 'warning',
          title: 'Не отключён',
          message: 'Запрос отправлен, но подтверждения нет — проверьте состояние туннеля.',
        });
      }
      if (!offline && !mutationSignal.aborted) {
        await loadCatalogFlow();
      }
    } catch (error) {
      if (disposed || isAborted(error) || offline) {
        return;
      }
      const describedErr = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: describedErr.title,
        message: formatErrorDescription(describedErr),
      });
    } finally {
      const next = { ...deactivatingProfileIds };
      delete next[profileId];
      deactivatingProfileIds = next;
      mutating = false;
      longOpKind = 'idle';
      mutationPhase = null;
      if (!disposed) {
        pendingFocus = { kind: 'element-id', id: `hub-vpn-deactivate-${profileId}` };
        renderStatusSlot();
        renderCatalogSlot();
        renderFooter();
        restorePendingFocus();
      }
    }
  }

  /**
   * @param {string} profileId
   */
  function openCatalogRemoveModal(profileId) {
    if (!profileId) {
      return;
    }
    const catalogItem = catalogItems.find((item) => {
      const row = /** @type {Record<string, unknown>} */ (item ?? {});
      return row.profile_id === profileId;
    });
    const payload = /** @type {Record<string, unknown>} */ (catalogItem ?? {});
    if (payload.is_active === true) {
      ctx.showToast({
        tone: 'warning',
        title: 'Профиль подключён',
        message: VPN_CATALOG_REMOVE_ACTIVE_REFUSE,
      });
      return;
    }

    const body = buildRiskModalBody({
      leadLines: [VPN_CATALOG_REMOVE_CONFIRM_LEAD],
      changeLines: [],
      bodyClassName: 'hub-vpn__risk-body hub-wifi__risk-body',
    });

    /** @type {{ close: () => void }|null} */
    let modalRef = null;
    const returnFocusTo = document.getElementById(`hub-vpn-remove-${profileId}`);

    const cancelBtn = createButton({
      label: VPN_CATALOG_REMOVE_CANCEL,
      variant: 'ghost',
      onActivate: () => {
        modalRef?.close();
      },
    });

    const confirmBtn = createButton({
      label: VPN_CATALOG_REMOVE_CONFIRM_ACTION,
      variant: 'danger',
      onActivate: () => {
        modalRef?.close();
        void runRemoveCatalogProfile(profileId);
      },
    });

    modalRef = registerModal(
      openModal({
        title: VPN_CATALOG_REMOVE_CONFIRM_TITLE,
        description: VPN_CATALOG_REMOVE_CONFIRM_LEAD,
        body,
        actions: [cancelBtn, confirmBtn],
        ...(returnFocusTo instanceof HTMLElement ? { returnFocusTo } : {}),
      }),
    );
  }

  async function runRemoveCatalogProfile(profileId) {
    if (!profileId || removingProfileIds[profileId] || offline) {
      return;
    }
    removingProfileIds = { ...removingProfileIds, [profileId]: '1' };
    renderCatalogSlot();
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    const mutationSignal = mutateAbort.signal;
    try {
      await removeVpnProfileFromCatalog({ profileId, signal: mutationSignal });
      if (disposed || offline || mutationSignal.aborted) {
        return;
      }
      ctx.showToast({
        tone: 'success',
        title: 'Профиль убран',
        message: 'Профиль исчез из списка доступных VPN.',
      });
      if (!offline && !mutationSignal.aborted) {
        await loadCatalogFlow();
      }
    } catch (error) {
      if (disposed || isAborted(error) || offline) {
        return;
      }
      const describedErr = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: describedErr.title,
        message: formatErrorDescription(describedErr),
      });
    } finally {
      const next = { ...removingProfileIds };
      delete next[profileId];
      removingProfileIds = next;
      if (!disposed) {
        pendingFocus = { kind: 'element-id', id: `hub-vpn-remove-${profileId}` };
        renderCatalogSlot();
        restorePendingFocus();
      }
    }
  }

  async function validateCatalogProfile(profileId) {
    if (!profileId || validatingProfileIds[profileId] || offline) {
      return;
    }
    validatingProfileIds = { ...validatingProfileIds, [profileId]: '1' };
    longOpKind = 'validate';
    renderCatalogSlot();
    renderFooter();
    mutateAbort?.abort();
    mutateAbort = new AbortController();
    const mutationSignal = mutateAbort.signal;
    try {
      const response = await validateVpnProfile({
        profileId,
        idempotencyKey: createIdempotencyKey(),
        signal: mutationSignal,
      });
      if (disposed || offline || mutationSignal.aborted) {
        return;
      }
      const validationStatus =
        typeof response?.validation_status === 'string' ? response.validation_status : '';
      if (validationStatus === 'Valid') {
        ctx.showToast({
          tone: 'success',
          title: 'Проверка завершена',
          message: 'Статус профиля в каталоге обновлён.',
        });
      } else {
        const described = describeVpnProfileItem(
          typeof response === 'object' && response !== null ? response : {},
        );
        ctx.showToast({
          tone: 'warning',
          title: 'Проверка не пройдена',
          message: described.validationLabel,
        });
      }
      if (!offline && !mutationSignal.aborted) {
        await loadCatalogFlow();
      }
    } catch (error) {
      if (disposed || isAborted(error) || offline) {
        return;
      }
      const described = describeError(error);
      ctx.showToast({
        tone: 'danger',
        title: described.title,
        message: described.message,
      });
    } finally {
      const next = { ...validatingProfileIds };
      delete next[profileId];
      validatingProfileIds = next;
      longOpKind = 'idle';
      if (!disposed) {
        pendingFocus = { kind: 'element-id', id: `hub-vpn-validate-${profileId}` };
        renderCatalogSlot();
        renderFooter();
        restorePendingFocus();
      }
    }
  }

  function renderDemoBanner() {
    if (adapterMode !== 'fake') {
      return null;
    }
    return createDemoBanner({
      text:
        'Каталог профилей и экран можно просмотреть без живого подключения. В демонстрационном режиме включать или отключать VPN нельзя.',
      connectionHintPrefix:
        'Чтобы менять VPN, сначала завершите подключение к роутеру на экране ',
      onNavigateToConnection: () => {
        ctx.navigate('connection');
      },
      wrapClassName: 'hub-vpn__demo-banner hub-wifi__demo-banner',
    });
  }

  function renderFooter() {
    const signature = buildFooterSignature();
    const hasFooter =
      document.getElementById('hub-vpn-disconnect-btn') instanceof HTMLElement
      && document.getElementById('hub-vpn-connect-btn') instanceof HTMLElement;
    if (signature === lastFooterSignature && hasFooter) {
      return;
    }
    const prevSignature = lastFooterSignature;
    lastFooterSignature = signature;
    if (
      hasFooter
      && prevSignature
      && footerStructureSignature(prevSignature) === footerStructureSignature(signature)
    ) {
      syncFooterButtonsInPlace();
      return;
    }

    clearElement(footerLeft);
    clearElement(footerRight);

    const state = screenState();
    const readiness = mutationReadiness();

    const disconnectBtn = createButton({
      label: 'Отключить VPN',
      variant: 'danger',
      disabled: !state.canTeardown || controlsLocked() || offline,
      busy: mutating && longOpKind === 'disconnect',
      onActivate: () => {
        const focusEl =
          document.activeElement instanceof HTMLElement ? document.activeElement : null;
        openVpnRiskModal(
          'disconnect',
          () => runTunnelMutation('disconnect'),
          focusEl,
        );
      },
    });
    disconnectBtn.id = 'hub-vpn-disconnect-btn';
    updateButtonBusyState(
      disconnectBtn,
      mutating && longOpKind === 'disconnect',
      !state.canTeardown || controlsLocked() || offline,
    );

    const disconnectReasonId = 'hub-vpn-disconnect-reason';
    let disconnectReason = null;
    if (!state.canTeardown) {
      if (offline) {
        disconnectReason = 'Нет связи с сервером управления';
      } else if (readiness.reasonText) {
        disconnectReason = readiness.reasonText;
      }
    } else if (controlsLocked()) {
      disconnectReason = 'Дождитесь завершения текущей операции';
    }

    footerLeft.appendChild(disconnectBtn);
    if (disconnectReason) {
      const reason = document.createElement('p');
      reason.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reason.id = disconnectReasonId;
      reason.textContent = disconnectReason;
      footerLeft.appendChild(reason);
      disconnectBtn.setAttribute('aria-describedby', disconnectReasonId);
    }

    const connectBtn = createButton({
      label: 'Подключить VPN',
      variant: 'primary',
      disabled: !state.canApply || controlsLocked() || offline || connecting,
      busy: connecting,
      onActivate: () => {
        const focusEl =
          document.activeElement instanceof HTMLElement ? document.activeElement : null;
        openVpnRiskModal('connect', () => runTunnelMutation('connect'), focusEl);
      },
    });
    connectBtn.id = 'hub-vpn-connect-btn';
    updateButtonBusyState(connectBtn, connecting, !state.canApply || controlsLocked() || offline);
    footerRight.appendChild(connectBtn);

    if (!state.canApply && readiness.reasonText) {
      const reason = document.createElement('p');
      reason.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reason.id = 'hub-vpn-connect-reason';
      reason.textContent = readiness.reasonText;
      footerRight.appendChild(reason);
      connectBtn.setAttribute('aria-describedby', reason.id);
    } else if (!preparedParse) {
      const reason = document.createElement('p');
      reason.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reason.id = 'hub-vpn-connect-reason';
      reason.textContent = 'Сначала подготовьте конфигурацию через «Загрузить конфигурацию».';
      footerRight.appendChild(reason);
      connectBtn.setAttribute('aria-describedby', reason.id);
    } else if (!state.canApply) {
      const parseReadiness = evaluatePreparedParseConnectReadiness(preparedParse);
      const reason = document.createElement('p');
      reason.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reason.id = 'hub-vpn-connect-reason';
      reason.textContent =
        parseReadiness.reasonText
        ?? 'Подключение недоступно — проверьте данные сервера VPN в профиле.';
      footerRight.appendChild(reason);
      connectBtn.setAttribute('aria-describedby', reason.id);
    } else if (controlsLocked()) {
      const reason = document.createElement('p');
      reason.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reason.id = 'hub-vpn-connect-reason';
      reason.textContent = 'Дождитесь завершения текущей операции';
      footerRight.appendChild(reason);
      connectBtn.setAttribute('aria-describedby', reason.id);
    } else if (offline) {
      const reason = document.createElement('p');
      reason.className = 'hub-vpn__action-reason hub-wifi__save-reason';
      reason.id = 'hub-vpn-connect-reason';
      reason.textContent = 'Нет связи с сервером управления';
      footerRight.appendChild(reason);
      connectBtn.setAttribute('aria-describedby', reason.id);
    }
  }

  function renderStatusCard() {
    const card = createCard({
      title: 'Что происходит с VPN',
      titleTag: 'h2',
    });
    card.classList.add('hub-vpn__status-card');
    const body = card.querySelector('.hub-card__body') ?? card;
    const statusLinesWrap = document.createElement('div');
    statusLinesWrap.className = 'hub-vpn__status-lines';

    const progressMessage = mutationProgressMessage();
    const showConnectingPanel = connecting && progressMessage;
    const showMutatingPanel =
      !connecting
      && mutating
      && progressMessage
      && (longOpKind === 'activate' || longOpKind === 'deactivate' || longOpKind === 'disconnect');

    if (observing && !connecting) {
      statusLinesWrap.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: VPN_OBSERVE_PROGRESS_MESSAGE,
        }),
      );
    }

    if (showConnectingPanel) {
      statusLinesWrap.appendChild(
        createStatePanel({
          state: HubState.CONNECTING,
          titleTag: 'h3',
          title: progressMessage,
          description:
            mutationPhase === 'apply'
              ? 'До ответа сервера статус туннеля не показывается — дождитесь завершения операции.'
              : 'Операция выполняется — дождитесь завершения.',
        }),
      );
    } else if (showMutatingPanel) {
      statusLinesWrap.appendChild(
        createStatePanel({
          state: HubState.LOADING,
          titleTag: 'h3',
          title: progressMessage,
          description: 'Запрос выполняется на роутере — не закрывайте экран.',
        }),
      );
    }

    if (!connecting) {
      const status = currentStatusLines();
      if (status) {
        statusLinesWrap.appendChild(renderStatusLine(status.configuration, 0));
        statusLinesWrap.appendChild(renderStatusLine(status.tunnel, 1));
        statusLinesWrap.appendChild(renderStatusLine(status.traffic, 2));
        if (status.technicalLines.length > 0) {
          const technical = createTechnicalDetails({
            summary: 'Технические подробности',
            content: status.technicalLines.join('\n'),
          });
          statusLinesWrap.appendChild(technical);
        }
      }
    }

    body.appendChild(statusLinesWrap);
    return card;
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
      if (adapterMode !== 'fake' && mutationReadiness().allowed) {
        bannerSlot.appendChild(createInlineState({ state: HubState.LIVE_DEVICE }));
      }
    });
    syncContentLayoutClasses();
  }

  function renderHeaderSlot() {
    if (disposed) {
      return;
    }
    const signature = buildHeaderSignature();
    if (signature === lastHeaderSignature && headerSlot.firstChild) {
      return;
    }
    lastHeaderSignature = signature;
    rebuildSlot(headerSlot, () => {
      clearElement(headerSlot);
      headerSlot.appendChild(renderNetworkHeader());
    });
  }

  function renderStatusSlot() {
    if (disposed) {
      return;
    }
    const signature = buildStatusSignature();
    if (signature === lastStatusSignature && statusSlot.firstChild) {
      return;
    }
    lastStatusSignature = signature;
    rebuildSlot(statusSlot, () => {
      clearElement(statusSlot);
      statusSlot.appendChild(renderStatusCard());
    });
  }

  function renderActiveConfigSlot() {
    if (disposed) {
      return;
    }
    const signature = buildActiveConfigSignature();
    /** @type {HTMLElement|null} */
    let activeConfigWrap = mainCol.querySelector('.hub-vpn__active-config-slot');
    if (!activeConfigWrap) {
      activeConfigWrap = document.createElement('div');
      activeConfigWrap.className = 'hub-vpn__active-config-slot';
      mainCol.appendChild(activeConfigWrap);
    }
    if (signature === lastActiveConfigSignature && activeConfigWrap.firstChild) {
      return;
    }
    lastActiveConfigSignature = signature;
    rebuildSlot(activeConfigWrap, () => {
      clearElement(activeConfigWrap);
      activeConfigWrap.appendChild(renderActiveConfigurationCard());
    });
  }

  function renderSideSlot() {
    if (disposed) {
      return;
    }
    const signature = buildSideSignature();
    if (signature === lastSideSignature && sideCol.firstChild) {
      return;
    }
    lastSideSignature = signature;
    rebuildSlot(sideCol, () => {
      clearElement(sideCol);
      sideCol.appendChild(renderProtectionUnsupportedCard());
    });
    syncContentLayoutClasses();
  }

  function renderCatalogSlot() {
    if (disposed) {
      return;
    }
    const signature = buildCatalogSignature();
    if (signature === lastCatalogSignature && catalogSlot.firstChild) {
      return;
    }
    lastCatalogSignature = signature;
    rebuildSlot(catalogSlot, () => {
      clearElement(catalogSlot);
      catalogSlot.appendChild(renderCatalogCard());
    });
  }

  function renderMainExtraSlot() {
    if (disposed) {
      return;
    }
    const signature = buildMainExtraSignature();
    /** @type {HTMLElement|null} */
    let extraWrap = mainCol.querySelector('.hub-vpn__main-extra-slot');
    if (signature === 'none') {
      if (extraWrap) {
        clearElement(extraWrap);
        extraWrap.remove();
      }
      lastMainExtraSignature = signature;
      return;
    }
    if (!extraWrap) {
      extraWrap = document.createElement('div');
      extraWrap.className = 'hub-vpn__main-extra-slot';
      mainCol.appendChild(extraWrap);
    }
    if (signature === lastMainExtraSignature && extraWrap.firstChild) {
      return;
    }
    lastMainExtraSignature = signature;
    rebuildSlot(extraWrap, () => {
      clearElement(extraWrap);
      if (offline && !recovering) {
        extraWrap.appendChild(
          createStatePanel({
            state: HubState.NO_INTERNET,
            titleTag: 'h2',
            action: {
              label: 'Повторить',
              onActivate: () => {
                void loadCatalogFlow();
              },
            },
          }),
        );
        return;
      }
      if (recovering) {
        extraWrap.appendChild(
          createInlineState({
            state: HubState.RECOVERING,
            title: 'Восстанавливаем связь с сервером управления',
          }),
        );
        return;
      }
      if (operationError && !isAborted(operationError)) {
        const described = describeError(operationError);
        const isTimeoutRetry =
          described.kind === ERROR_KIND.TIMEOUT && applyTimeoutUnknownByWgId[selectedWgId];
        extraWrap.appendChild(
          createStatePanel({
            state: hubStateForError(operationError),
            titleTag: 'h2',
            title: described.title,
            description: formatErrorDescription(described),
            details: described.technical || undefined,
            action: operationRetry
              ? {
                  label: isTimeoutRetry ? 'Проверить состояние' : 'Повторить',
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

  function ensureMainColStructure() {
    if (!mainCol.contains(statusSlot)) {
      mainCol.insertBefore(statusSlot, mainCol.firstChild);
    }
  }

  function renderContent() {
    mountLayoutOnce();
    ensureMainColStructure();
    renderBannerSlot();
    renderHeaderSlot();
    renderStatusSlot();
    renderActiveConfigSlot();
    renderMainExtraSlot();
    renderSideSlot();
    renderCatalogSlot();
    syncContentLayoutClasses();
  }

  function renderAll() {
    if (disposed) {
      return;
    }
    renderContent();
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
      invalidateAllOperations();
      renderAll();
      return;
    }
    offline = false;
    recovering = true;
    renderAll();
    if (!mutating && !connecting && !parsingProfile && !importingCatalog) {
      void loadCatalogFlow().finally(() => {
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

  renderAll();
  void loadWatchdogStatus();
  void loadCatalogFlow();

  return () => {
    disposed = true;
    watchdogAbort?.abort();
    catalogEnrichAbort?.abort();
    catalogLiveStatusAbort?.abort();
    invalidateAllOperations();
    closeAllModals();
    clearPreparedSecrets();
    unsubConnectivity();
  };
}
