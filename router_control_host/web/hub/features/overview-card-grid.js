/**
 * Adaptive status-card grid helpers for the overview screen.
 */

import { createBadge, createButton, createIcon } from '../components/index.js';
import { createReadinessSegmentBar } from '../components/progress-ring.js';
import { HubState } from '../core/states.js';
import { validateDomainName, buildDraftUrl, DOMAIN_DRAFT_LINK_NOTE } from './domain-model.js';
import {
  INTERNET_SOURCE_MODEM_NOTE,
  describeInternetSource,
  describeRememberedUplink,
} from './internet-source-block.js';
import { describeVpnProfileTileStatus } from './vpn-model.js';

/** @typedef {import('./overview-model.js').OverviewSection} OverviewSection */
/** @typedef {import('./system-check.js').DescribedFact} DescribedFact */

const ROUTER_PILL_ORDER = Object.freeze(['reachable', 'credentials_present', 'tuple_match']);

const ROUTER_PILL_LABELS = Object.freeze({
  reachable: 'Отвечает',
  credentials_present: 'Доступ сохранён',
  tuple_match: 'Совпадает',
});

const READINESS_CATEGORY_LABELS = Object.freeze({
  router: 'Роутер',
  internet: 'Интернет',
  vpn: 'VPN',
  domain: 'Домен',
});

/**
 * @returns {HTMLUListElement}
 */
export function createOverviewGrid() {
  const grid = document.createElement('ul');
  grid.className = 'hub-overview__grid';
  grid.setAttribute('role', 'list');
  return grid;
}

/**
 * @param {string} suffix
 * @returns {HTMLLIElement}
 */
export function createOverviewGridItem(suffix) {
  const item = document.createElement('li');
  item.className = `hub-overview__grid-item hub-overview__grid-item--${suffix}`;
  return item;
}

/**
 * @param {HTMLElement} element
 * @param {string} routeId
 * @param {(routeId: string) => void} navigate
 * @param {{ ignoreInteractive?: boolean }} [options]
 */
export function wireOverviewCardNavigate(element, routeId, navigate, options = {}) {
  const { ignoreInteractive = true } = options;
  element.classList.add('hub-overview__nav-card');
  element.tabIndex = 0;
  element.setAttribute('role', 'link');
  element.dataset.route = routeId;

  function go() {
    navigate(routeId);
  }

  element.addEventListener('click', (event) => {
    if (ignoreInteractive && event.target instanceof Element) {
      if (event.target.closest('a, button, input, select, textarea, label, [role="button"]')) {
        return;
      }
    }
    go();
  });

  element.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      if (ignoreInteractive && event.target instanceof Element) {
        if (event.target.closest('a, button, input, select, textarea, label, [role="button"]')) {
          return;
        }
      }
      event.preventDefault();
      go();
    }
  });
}

/**
 * @param {number} stepNumber
 * @returns {HTMLSpanElement}
 */
export function createStepNumberBadge(stepNumber) {
  const badge = document.createElement('span');
  badge.className = 'hub-overview-step-card__number';
  badge.textContent = String(stepNumber);
  badge.setAttribute('aria-hidden', 'true');
  return badge;
}

/**
 * @returns {HTMLDivElement}
 */
export function createOverviewStepCardMain() {
  const main = document.createElement('div');
  main.className = 'hub-overview-step-card__main';
  return main;
}

/**
 * @returns {HTMLDivElement}
 */
export function createOverviewStepCardActions() {
  const actions = document.createElement('div');
  actions.className = 'hub-overview-step-card__actions';
  return actions;
}

/**
 * @returns {HTMLDivElement}
 */
export function createOverviewStepCardMeta() {
  const meta = document.createElement('div');
  meta.className = 'hub-overview-step-card__meta';
  return meta;
}

const OVERVIEW_SKELETON_VARIANT_LABELS = Object.freeze({
  router: 'Роутер',
  internet: 'Интернет',
  vpn: 'VPN',
});

/**
 * @param {string} className
 * @returns {HTMLSpanElement}
 */
function createOverviewSkeletonBone(className) {
  const bone = document.createElement('span');
  bone.className = `hub-overview-card-skeleton__bone ${className}`;
  bone.setAttribute('aria-hidden', 'true');
  return bone;
}

/**
 * @param {number} count
 * @returns {HTMLDivElement}
 */
function createOverviewSkeletonCheckGrid(count) {
  const grid = document.createElement('div');
  grid.className = 'hub-overview-card-skeleton__checks-bone';
  grid.setAttribute('aria-hidden', 'true');
  for (let index = 0; index < count; index += 1) {
    grid.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__check-tile-bone'));
  }
  return grid;
}

/**
 * @param {{
 *   stepNumber: number,
 *   variant: 'router'|'internet'|'vpn',
 * }} options
 * @returns {HTMLElement}
 */
export function buildOverviewStepCardSkeleton({ stepNumber, variant }) {
  const label = OVERVIEW_SKELETON_VARIANT_LABELS[variant] ?? variant;

  const card = document.createElement('article');
  card.className = 'hub-overview-step-card hub-overview-card-skeleton';
  card.setAttribute('role', 'status');
  card.setAttribute('aria-busy', 'true');
  card.setAttribute('aria-label', `Загрузка: ${label}`);

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header';
  header.appendChild(createStepNumberBadge(stepNumber));
  header.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__title-bone'));
  card.appendChild(header);

  const main = createOverviewStepCardMain();
  main.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__icon-bone'));
  main.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__badge-bone'));

  if (variant === 'router') {
    main.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__info-block-bone'));
    main.appendChild(createOverviewSkeletonCheckGrid(4));
  } else if (variant === 'internet') {
    const segments = document.createElement('div');
    segments.className = 'hub-overview-card-skeleton__segments-bone';
    segments.setAttribute('aria-hidden', 'true');
    for (let index = 0; index < 3; index += 1) {
      segments.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__segment-bone'));
    }
    main.appendChild(segments);
    main.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__network-block-bone'));
    main.appendChild(createOverviewSkeletonCheckGrid(2));
  } else if (variant === 'vpn') {
    main.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__picker-bone'));
  }

  card.appendChild(main);

  const actions = createOverviewStepCardActions();
  actions.appendChild(createOverviewSkeletonBone('hub-overview-card-skeleton__cta-bone'));
  actions.appendChild(createOverviewStepCardMeta());
  card.appendChild(actions);

  return card;
}

/**
 * @param {string} label
 * @param {'success'|'warning'|'danger'|'neutral'} tone
 * @returns {HTMLSpanElement}
 */
function createFactPill(label, tone) {
  const pill = document.createElement('span');
  pill.className = `hub-overview-fact-pill hub-overview-fact-pill--${tone}`;
  pill.textContent = label;
  return pill;
}

/**
 * @param {DescribedFact[]|null|undefined} facts
 * @returns {Array<{ id: string, label: string, value: boolean|null, tone: 'success'|'warning'|'danger'|'neutral' }>}
 */
export function mapHealthFactsToRouterPills(facts) {
  const source = Array.isArray(facts) ? facts : [];
  return ROUTER_PILL_ORDER.map((id) => {
    const fact = source.find((entry) => entry.id === id);
    const value = fact?.value === true || fact?.value === false ? fact.value : null;
    const tone = fact?.tone ?? 'neutral';
    const baseLabel = ROUTER_PILL_LABELS[id] ?? id;
    const label = value === null ? `${baseLabel}: неизвестно` : baseLabel;
    return {
      id,
      label,
      value,
      tone,
    };
  });
}

/**
 * @param {'unknown'|'wifi'|'wired'|'vpn'|'modem'|null|undefined} kind
 * @returns {'wifi'|'wired'|null}
 */
export function mapInternetSourceKindToSegment(kind) {
  if (kind === 'wifi') {
    return 'wifi';
  }
  if (kind === 'wired') {
    return 'wired';
  }
  return null;
}

/**
 * @param {import('./overview-model.js').OverviewModel|null|undefined} model
 * @param {{
 *   routerInternetObserve?: { internet?: boolean|null }|null,
 *   vpnItems?: Array<{ is_active?: boolean, routed_through_tunnel?: boolean|null }>|null,
 *   domainDraftName?: string|null,
 *   eventPresetId?: string|null,
 *   internetEnrichmentBusy?: boolean,
 *   vpnEnrichmentBusy?: boolean,
 *   systemCheckRunning?: boolean,
 * }} context
 * @returns {{
 *   ready: number|null,
 *   total: number,
 *   loaded: boolean,
 *   categories: { router: boolean, internet: boolean, vpn: boolean, domain: boolean },
 * }}
 */
export function computeOverviewReadiness(model, context = {}) {
  const total = 4;
  const categories = {
    router: false,
    internet: false,
    vpn: false,
    domain: false,
  };
  if (!model) {
    return {
      ready: null,
      total,
      loaded: false,
      categories,
    };
  }

  const enrichmentBusy =
    context.internetEnrichmentBusy === true
    || context.vpnEnrichmentBusy === true
    || context.systemCheckRunning === true;
  if (enrichmentBusy) {
    return {
      ready: null,
      total,
      loaded: false,
      categories,
    };
  }

  const routerReady = model.router?.state === HubState.SUCCESS;
  const internetReady = context.routerInternetObserve?.internet === true;

  let vpnReady = false;
  const vpnItems = context.vpnItems ?? [];
  for (const item of vpnItems) {
    if (vpnIsConnectedRouted(item)) {
      vpnReady = true;
      break;
    }
  }

  const domainName = typeof context.domainDraftName === 'string' ? context.domainDraftName : '';
  const domainValidation = validateDomainName(domainName);
  const eventPresetId = context.eventPresetId ?? null;
  const domainReady = domainValidation.valid === true && eventPresetId != null;

  categories.router = routerReady;
  categories.internet = internetReady;
  categories.vpn = vpnReady;
  categories.domain = domainReady;
  const ready = Object.values(categories).filter(Boolean).length;

  return {
    ready,
    total,
    loaded: true,
    categories,
  };
}

/**
 * @param {{
 *   readiness: ReturnType<typeof computeOverviewReadiness>,
 *   loading?: boolean,
 * }} options
 * @returns {HTMLElement}
 */
export function buildOverviewReadinessHeader({ readiness, loading = false }) {
  const header = document.createElement('div');
  header.className = 'hub-overview__readiness-header';

  const title = document.createElement('h2');
  title.className = 'hub-overview__readiness-title';
  title.textContent = 'Состояние системы';
  header.appendChild(title);

  const barLoading = loading || !readiness.loaded;
  header.appendChild(
    createReadinessSegmentBar({
      categories: readiness.categories,
      value: readiness.ready,
      max: readiness.total,
      loading: barLoading,
    }),
  );

  return header;
}

const ROUTER_CHECK_TILE_LABELS = Object.freeze({
  reachable: {
    yes: 'Роутер отвечает',
    no: 'Роутер не отвечает',
    unknown: 'Роутер: неизвестно',
  },
  credentials_present: {
    yes: 'Доступ сохранён',
    no: 'Доступ не сохранён',
    unknown: 'Доступ: неизвестно',
  },
  tuple_match: {
    yes: 'Устройство совпадает',
    no: 'Устройство не совпадает',
    unknown: 'Устройство: неизвестно',
  },
});

/**
 * @param {string} id
 * @param {boolean|null|undefined} value
 * @returns {string}
 */
export function resolveRouterCheckTileLabel(id, value) {
  const labels = ROUTER_CHECK_TILE_LABELS[id];
  if (!labels) {
    if (value === true || value === false) {
      return id;
    }
    return `${id}: неизвестно`;
  }
  if (value === true) {
    return labels.yes;
  }
  if (value === false) {
    return labels.no;
  }
  return labels.unknown;
}

/**
 * @param {string|null|undefined} iso
 * @returns {string|null}
 */
function routerFormatCheckedAt(iso) {
  if (typeof iso !== 'string' || !iso.trim()) {
    return null;
  }
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return null;
  }
  const time = date.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  return `Проверено ${time}`;
}

/**
 * @param {{ id: string, value: boolean|null }} pill
 * @returns {HTMLElement}
 */
function routerCreateCheckTile(pill) {
  const tile = document.createElement('div');
  tile.className = 'hub-router-card__check-tile';
  const isUnknown = pill.value !== true && pill.value !== false;
  if (pill.value === true) {
    tile.classList.add('hub-router-card__check-tile--success');
  } else if (pill.value === false) {
    tile.classList.add('hub-router-card__check-tile--danger');
  } else {
    tile.classList.add('hub-router-card__check-tile--neutral', 'hub-router-card__check-tile--unknown');
  }

  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-router-card__check-icon';
  let iconName = 'check';
  if (pill.value === false) {
    iconName = 'alert';
  } else if (isUnknown) {
    iconName = 'info';
    iconWrap.classList.add('hub-router-card__check-icon--muted');
  }
  iconWrap.appendChild(createIcon(iconName, { size: 16 }));
  tile.appendChild(iconWrap);

  const label = document.createElement('span');
  label.className = 'hub-router-card__check-label';
  if (isUnknown) {
    label.classList.add('hub-router-card__check-label--muted');
  }
  const fallbackLabels = {
    yes: pill.id,
    no: pill.id,
    unknown: `${pill.id}: неизвестно`,
  };
  const labels = ROUTER_CHECK_TILE_LABELS[pill.id] ?? fallbackLabels;
  label.textContent = ROUTER_CHECK_TILE_LABELS[pill.id]
    ? resolveRouterCheckTileLabel(pill.id, pill.value)
    : (pill.value === true ? labels.yes : pill.value === false ? labels.no : labels.unknown);
  tile.appendChild(label);

  return tile;
}

/**
 * @param {string|null|undefined} checkedAt
 * @returns {HTMLElement}
 */
function routerCreateCheckedAtTile(checkedAt) {
  const tile = document.createElement('div');
  tile.className =
    'hub-router-card__check-tile hub-router-card__check-tile--neutral hub-router-card__check-tile--time';

  const formatted = routerFormatCheckedAt(checkedAt);
  const isUnknown = !formatted;

  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-router-card__check-icon';
  if (isUnknown) {
    iconWrap.classList.add('hub-router-card__check-icon--muted');
  }
  iconWrap.appendChild(createIcon('info', { size: 16 }));
  tile.appendChild(iconWrap);

  const label = document.createElement('span');
  label.className = 'hub-router-card__check-label';
  if (formatted) {
    label.textContent = formatted;
  } else {
    label.classList.add('hub-router-card__check-label--muted');
    label.textContent = 'Время проверки неизвестно';
  }
  tile.appendChild(label);

  return tile;
}

/**
 * @param {OverviewSection|null|undefined} section
 * @param {(routeId: string) => void} navigate
 * @param {{
 *   facts?: DescribedFact[]|null,
 *   checkedAt?: string|null,
 *   onChangeClick?: () => void,
 * }} [options]
 * @returns {HTMLElement}
 */
export function buildRouterConnectionStatusCard(section, navigate, options = {}) {
  const { facts = null, checkedAt = null, onChangeClick } = options;
  const deviceName = section?.title ?? 'Роутер';
  const subtitle = section?.subtitle ?? null;

  const card = document.createElement('article');
  card.className = 'hub-overview-step-card hub-overview__router-status-card hub-router-card';

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header hub-router-card__header';
  header.appendChild(createStepNumberBadge(1));

  const heading = document.createElement('h2');
  heading.className = 'hub-overview-step-card__title';
  heading.textContent = 'Роутер';
  header.appendChild(heading);

  const infoWrap = document.createElement('span');
  infoWrap.className = 'hub-router-card__info';
  infoWrap.appendChild(createIcon('info', { size: 16 }));
  header.appendChild(infoWrap);
  card.appendChild(header);

  const main = createOverviewStepCardMain();

  const iconFrame = document.createElement('div');
  iconFrame.className = 'hub-router-card__icon-frame';
  iconFrame.appendChild(createIcon('router', { size: 32 }));
  main.appendChild(iconFrame);

  if (section?.badge) {
    const badgeWrap = document.createElement('div');
    badgeWrap.className = 'hub-router-card__status';
    badgeWrap.appendChild(
      createBadge({
        label: section.badge.label,
        tone: section.badge.tone,
      }),
    );
    main.appendChild(badgeWrap);
  }

  const infoBlock = document.createElement('div');
  infoBlock.className = 'hub-router-card__info-block';
  const nameEl = document.createElement('p');
  nameEl.className = 'hub-router-card__device-name';
  nameEl.textContent = deviceName;
  infoBlock.appendChild(nameEl);
  if (subtitle) {
    const subEl = document.createElement('p');
    subEl.className = 'hub-router-card__device-subtitle';
    subEl.textContent = subtitle;
    infoBlock.appendChild(subEl);
  }
  main.appendChild(infoBlock);

  const checksGrid = document.createElement('div');
  checksGrid.className = 'hub-router-card__checks';
  checksGrid.setAttribute('role', 'list');
  for (const pill of mapHealthFactsToRouterPills(facts)) {
    const tile = routerCreateCheckTile(pill);
    tile.setAttribute('role', 'listitem');
    checksGrid.appendChild(tile);
  }
  const timeTile = routerCreateCheckedAtTile(checkedAt);
  timeTile.setAttribute('role', 'listitem');
  checksGrid.appendChild(timeTile);
  main.appendChild(checksGrid);

  card.appendChild(main);

  const actions = createOverviewStepCardActions();
  const changeBtn = createButton({
    label: 'Сменить роутер',
    variant: 'secondary',
    size: 'md',
    onActivate: () => {
      if (typeof onChangeClick === 'function') {
        onChangeClick();
      } else {
        navigate('connection');
      }
    },
  });
  changeBtn.className = `${changeBtn.className} hub-router-card__change`;
  actions.appendChild(changeBtn);
  actions.appendChild(createOverviewStepCardMeta());
  card.appendChild(actions);

  wireOverviewCardNavigate(card, 'connection', navigate);
  return card;
}

/**
 * @param {string|null|undefined} band
 * @returns {string|null}
 */
function internetBandLabel(band) {
  if (band === 'BAND_5GHZ') {
    return '5 ГГц';
  }
  if (band === 'BAND_2_4GHZ') {
    return '2,4 ГГц';
  }
  return null;
}

/**
 * @param {boolean} busy
 * @param {import('./internet-source-block.js').InternetSourceObservation|null} observation
 * @returns {{ label: string, tone: 'success'|'danger'|'neutral' }}
 */
function internetStatusBadgeTone(busy, observation) {
  if (busy) {
    return { label: 'Проверяем…', tone: 'neutral' };
  }
  if (observation?.internet === true) {
    return { label: 'Работает', tone: 'success' };
  }
  if (observation?.internet === false) {
    return { label: 'Нет связи', tone: 'danger' };
  }
  return { label: 'Неизвестно', tone: 'neutral' };
}

/**
 * @param {string} label
 * @param {boolean|null|undefined} value
 * @returns {HTMLElement}
 */
function internetCreateCheckTile(labels, value) {
  // Label must carry the state on its own: an icon-only signal reads as an
  // affirmative claim («Интернет доступен») even when the value is false/unknown.
  const label = value === true
    ? labels.yes
    : value === false
      ? labels.no
      : labels.unknown;
  const tile = document.createElement('div');
  tile.className = 'hub-internet-card__check-tile';
  if (value === true) {
    tile.classList.add('hub-internet-card__check-tile--success');
  } else if (value === false) {
    tile.classList.add('hub-internet-card__check-tile--danger');
  } else {
    tile.classList.add('hub-internet-card__check-tile--neutral');
  }

  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-internet-card__check-icon';
  if (value === true) {
    iconWrap.appendChild(createIcon('check', { size: 16 }));
  } else if (value === false) {
    iconWrap.appendChild(createIcon('alert', { size: 16 }));
  } else {
    const dot = document.createElement('span');
    dot.className = 'hub-internet-card__check-dot';
    iconWrap.appendChild(dot);
  }
  tile.appendChild(iconWrap);

  const labelEl = document.createElement('span');
  labelEl.className = 'hub-internet-card__check-label';
  labelEl.textContent = label;
  tile.appendChild(labelEl);

  return tile;
}

/**
 * @param {{
 *   observation?: import('./internet-source-block.js').InternetSourceObservation|null,
 *   rememberedUplink?: import('./internet-source-block.js').RememberedUplinkPref|null,
 *   busy?: boolean,
 *   navigate: (routeId: string) => void,
 *   onChangeClick?: () => void,
 * }} options
 * @returns {HTMLElement}
 */
export function buildInternetStatusCard(options) {
  const {
    observation = null,
    rememberedUplink = null,
    busy = false,
    navigate,
    onChangeClick,
  } = options;

  const card = document.createElement('article');
  card.className = 'hub-overview-step-card hub-overview__internet-status-card hub-internet-card';

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header hub-internet-card__header';
  header.appendChild(createStepNumberBadge(2));

  const heading = document.createElement('h2');
  heading.className = 'hub-overview-step-card__title';
  heading.textContent = 'Интернет';
  header.appendChild(heading);

  const infoWrap = document.createElement('span');
  infoWrap.className = 'hub-internet-card__info';
  infoWrap.appendChild(createIcon('info', { size: 16 }));
  header.appendChild(infoWrap);
  card.appendChild(header);

  const main = createOverviewStepCardMain();

  const hero = document.createElement('div');
  hero.className = 'hub-internet-card__hero';
  hero.appendChild(createIcon('connection', { size: 32 }));
  main.appendChild(hero);

  const statusWrap = document.createElement('div');
  statusWrap.className = 'hub-internet-card__status';
  const statusBadge = internetStatusBadgeTone(busy, observation);
  statusWrap.appendChild(createBadge({ label: statusBadge.label, tone: statusBadge.tone }));
  main.appendChild(statusWrap);

  const described = busy ? null : describeInternetSource(observation);
  const activeSegment = described ? mapInternetSourceKindToSegment(described.kind) : null;

  const segmentsWrap = document.createElement('div');
  segmentsWrap.className = 'hub-internet-card__segments';
  segmentsWrap.setAttribute('aria-label', 'Источник интернета');
  for (const entry of [
    { id: 'wifi', label: 'Wi‑Fi' },
    { id: 'wired', label: 'Кабель' },
    { id: 'modem', label: 'Модем', muted: true },
  ]) {
    const segment = document.createElement('span');
    segment.className = 'hub-internet-card__segment';
    if (entry.muted) {
      segment.classList.add('hub-internet-card__segment--muted');
    }
    if (activeSegment === entry.id) {
      segment.classList.add('hub-internet-card__segment--active');
    }
    segment.textContent = entry.label;
    segment.setAttribute('aria-current', activeSegment === entry.id ? 'true' : 'false');
    if (entry.id === 'modem') {
      segment.title = INTERNET_SOURCE_MODEM_NOTE;
    }
    segmentsWrap.appendChild(segment);
  }
  main.appendChild(segmentsWrap);

  if (!busy && described?.kind === 'vpn') {
    const vpnLine = document.createElement('p');
    vpnLine.className = 'hub-internet-card__current-source';
    let vpnText = `Сейчас: ${described.label}`;
    if (described.detail) {
      vpnText += ` — ${described.detail}`;
    }
    vpnLine.textContent = vpnText;
    main.appendChild(vpnLine);
  }

  const gatewayOk = !busy && observation?.read_status === 'ok';
  const gatewaySsid =
    gatewayOk && typeof observation?.gateway_ssid === 'string' && observation.gateway_ssid.trim()
      ? observation.gateway_ssid.trim()
      : '';
  const rememberedSsid =
    typeof rememberedUplink?.ssid === 'string' ? rememberedUplink.ssid.trim() : '';

  if (gatewaySsid || rememberedSsid) {
    const networkBlock = document.createElement('div');
    networkBlock.className = 'hub-internet-card__network';

    if (gatewaySsid) {
      const ssidEl = document.createElement('p');
      ssidEl.className = 'hub-internet-card__network-ssid';
      ssidEl.textContent = gatewaySsid;
      networkBlock.appendChild(ssidEl);
    } else {
      const savedLabel = document.createElement('p');
      savedLabel.className = 'hub-internet-card__network-saved-label';
      savedLabel.textContent = 'Сохранённая сеть (не подтверждена как шлюз)';
      networkBlock.appendChild(savedLabel);

      const ssidEl = document.createElement('p');
      ssidEl.className = 'hub-internet-card__network-ssid';
      ssidEl.textContent = rememberedSsid;
      networkBlock.appendChild(ssidEl);
    }

    // Band comes from remembered uplink prefs — only show when it belongs to
    // the SSID currently displayed (live gateway match, or saved-network path).
    const bandLabel =
      !gatewaySsid || rememberedSsid === gatewaySsid
        ? internetBandLabel(rememberedUplink?.band)
        : null;
    if (bandLabel) {
      const bandPill = document.createElement('span');
      bandPill.className = 'hub-internet-card__band-pill';
      bandPill.textContent = bandLabel;
      networkBlock.appendChild(bandPill);
    }

    main.appendChild(networkBlock);
  }

  const checksGrid = document.createElement('div');
  checksGrid.className = 'hub-internet-card__checks';
  checksGrid.setAttribute('role', 'list');

  let internetValue = null;
  if (!busy && (observation?.internet === true || observation?.internet === false)) {
    internetValue = observation.internet;
  }

  let autoconnectValue = null;
  if (rememberedUplink && typeof rememberedUplink.desired_active === 'boolean') {
    autoconnectValue = rememberedUplink.desired_active;
  }

  const internetTile = internetCreateCheckTile(
    {
      yes: 'Интернет доступен',
      no: 'Интернета нет',
      unknown: 'Интернет: неизвестно',
    },
    internetValue,
  );
  internetTile.setAttribute('role', 'listitem');
  checksGrid.appendChild(internetTile);

  const autoconnectTile = internetCreateCheckTile(
    {
      yes: 'Автоподключение включено',
      no: 'Автоподключение выключено',
      unknown: 'Автоподключение: неизвестно',
    },
    autoconnectValue,
  );
  autoconnectTile.setAttribute('role', 'listitem');
  checksGrid.appendChild(autoconnectTile);
  main.appendChild(checksGrid);

  card.appendChild(main);

  const actions = createOverviewStepCardActions();
  const changeBtn = createButton({
    label: 'Сменить сеть',
    variant: 'secondary',
    size: 'md',
    onActivate: () => {
      if (typeof onChangeClick === 'function') {
        onChangeClick();
      } else {
        navigate('internet-uplink');
      }
    },
  });
  changeBtn.className = `${changeBtn.className} hub-internet-card__change`;
  actions.appendChild(changeBtn);

  const meta = createOverviewStepCardMeta();
  const rememberedText = describeRememberedUplink(rememberedUplink);
  if (rememberedText) {
    const rememberedLine = document.createElement('p');
    rememberedLine.className = 'hub-internet-card__remembered';
    rememberedLine.textContent = rememberedText;
    meta.appendChild(rememberedLine);
  }
  actions.appendChild(meta);
  card.appendChild(actions);

  wireOverviewCardNavigate(card, 'internet-uplink', navigate);
  return card;
}

/**
 * @param {Set<string>|Record<string, unknown>} source
 * @param {string} profileId
 * @returns {boolean}
 */
function vpnIsSetMember(source, profileId) {
  if (source instanceof Set) {
    return source.has(profileId);
  }
  return Object.prototype.hasOwnProperty.call(source, profileId);
}

/**
 * @param {Record<string, unknown>|null|undefined} item
 * @returns {boolean}
 */
export function vpnIsConnectedRouted(item) {
  return describeVpnProfileTileStatus(item).kind === 'connected_routed';
}

/**
 * @param {Array<Record<string, unknown>>} projectedItems
 * @param {{ busy?: boolean, checkingProfileIds?: Set<string>|Record<string, unknown> }} [options]
 * @returns {{ label: string, tone: 'success'|'neutral' }}
 */
/**
 * @param {Record<string, unknown>|null|undefined} item
 * @returns {{ label: string, tone: 'success'|'danger'|'warning'|'neutral' }}
 */
export function vpnDeriveProfileQuality(item) {
  if (item?.checking === true) {
    return { label: 'Проверяем…', tone: 'neutral' };
  }
  const { kind } = describeVpnProfileTileStatus(item);
  switch (kind) {
    case 'checking':
      return { label: 'Проверяем…', tone: 'neutral' };
    case 'connected_routed':
      return { label: 'Хороший', tone: 'success' };
    case 'connected_not_routed':
      return { label: 'Слабый', tone: 'warning' };
    case 'not_working':
      return { label: 'Плохой', tone: 'danger' };
    case 'check_failed':
      return { label: 'Сбой', tone: 'warning' };
    case 'not_checked':
    default:
      return item?.is_active
        ? { label: 'Уточняется', tone: 'neutral' }
        : { label: 'Не подключён', tone: 'neutral' };
  }
}

export function vpnDeriveCardStatus(projectedItems, options = {}) {
  const { busy = false, checkingProfileIds = {} } = options;
  if (busy) {
    return { label: 'Проверяем…', tone: 'neutral' };
  }
  const anyChecking = projectedItems.some((item) => {
    const profileId =
      typeof item.profile_id === 'string' && item.profile_id.trim() ? item.profile_id.trim() : '';
    return item.checking === true || (profileId && vpnIsSetMember(checkingProfileIds, profileId));
  });
  if (anyChecking) {
    return { label: 'Проверяем…', tone: 'neutral' };
  }
  const connected = projectedItems.some((item) => vpnIsConnectedRouted(item));
  if (connected) {
    return { label: 'Подключён', tone: 'success' };
  }
  return { label: 'Не подключён', tone: 'neutral' };
}

/**
 * @param {Record<string, unknown>|null|undefined} activeItem
 * @returns {{ label: string, tone: 'success'|'danger'|'warning'|'neutral' }}
 */
function vpnTunnelFactStatus(activeItem) {
  if (!activeItem || activeItem.is_active !== true) {
    return { label: 'Туннель не активен', tone: 'neutral' };
  }
  const tunnelStatus = activeItem.live_tunnel_verification_status;
  if (tunnelStatus === 'tunnel_healthy') {
    return { label: 'Туннель активен', tone: 'success' };
  }
  if (tunnelStatus === 'tunnel_no_peer' || tunnelStatus === 'tunnel_never_handshaked') {
    return { label: 'Туннель не активен', tone: 'warning' };
  }
  return { label: 'Туннель не проверен', tone: 'neutral' };
}

/**
 * @param {Record<string, unknown>|null|undefined} activeItem
 * @returns {{ label: string, tone: 'success'|'danger'|'neutral' }}
 */
function vpnTrafficFactStatus(activeItem) {
  if (!activeItem || activeItem.is_active !== true) {
    return { label: 'Трафик не проверен', tone: 'neutral' };
  }
  if (activeItem.routing_probe_status === 'failed') {
    return { label: 'Трафик не проверен', tone: 'neutral' };
  }
  if (activeItem.routed_through_tunnel === true) {
    return { label: 'Трафик идёт через VPN', tone: 'success' };
  }
  if (activeItem.routed_through_tunnel === false) {
    return { label: 'Трафик не через VPN', tone: 'danger' };
  }
  return { label: 'Трафик не проверен', tone: 'neutral' };
}

/**
 * @param {string} label
 * @param {'success'|'danger'|'warning'|'neutral'} tone
 * @returns {HTMLElement}
 */
function vpnCreateCheckTile(label, tone) {
  const tile = document.createElement('div');
  tile.className = 'hub-vpn-card__fact-tile';
  tile.classList.add(`hub-vpn-card__fact-tile--${tone}`);

  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-vpn-card__fact-icon';
  if (tone === 'success') {
    iconWrap.appendChild(createIcon('check', { size: 16 }));
  } else if (tone === 'danger' || tone === 'warning') {
    iconWrap.appendChild(createIcon('alert', { size: 16 }));
  } else {
    const dot = document.createElement('span');
    dot.className = 'hub-vpn-card__fact-dot';
    iconWrap.appendChild(dot);
  }
  tile.appendChild(iconWrap);

  const labelEl = document.createElement('span');
  labelEl.className = 'hub-vpn-card__fact-label';
  labelEl.textContent = label;
  tile.appendChild(labelEl);

  return tile;
}

/**
 * @param {Record<string, unknown>|null|undefined} activeItem
 * @returns {HTMLElement}
 */
export function vpnBuildFactTiles(activeItem) {
  const facts = document.createElement('div');
  facts.className = 'hub-vpn-card__facts';
  facts.setAttribute('role', 'list');

  const tunnelTile = vpnCreateCheckTile(
    vpnTunnelFactStatus(activeItem).label,
    vpnTunnelFactStatus(activeItem).tone,
  );
  tunnelTile.setAttribute('role', 'listitem');
  facts.appendChild(tunnelTile);

  const trafficTile = vpnCreateCheckTile(
    vpnTrafficFactStatus(activeItem).label,
    vpnTrafficFactStatus(activeItem).tone,
  );
  trafficTile.setAttribute('role', 'listitem');
  facts.appendChild(trafficTile);

  return facts;
}

/**
 * @param {{
 *   items: Array<Record<string, unknown>>,
 *   selectedProfileId?: string|null,
 *   onSelect?: (profileId: string) => void,
 *   disabled?: boolean,
 *   busyProfileIds?: Set<string>|Record<string, unknown>,
 *   deactivatingProfileIds?: Set<string>|Record<string, unknown>,
 *   checkingProfileIds?: Set<string>|Record<string, unknown>,
 * }} options
 * @returns {HTMLElement}
 */
export function buildOverviewVpnProfilePicker(options) {
  const {
    items,
    selectedProfileId = null,
    onSelect,
    disabled = false,
    busyProfileIds = {},
    deactivatingProfileIds = {},
    checkingProfileIds = {},
  } = options;

  const picker = document.createElement('div');
  picker.className = 'hub-vpn-card__picker';

  const grid = document.createElement('div');
  grid.className = 'hub-vpn-card__picker-grid';
  grid.setAttribute('role', 'group');
  grid.setAttribute('aria-label', 'Профили VPN');

  for (const rawItem of items) {
    const item = /** @type {Record<string, unknown>} */ (rawItem ?? {});
    const profileId =
      typeof item.profile_id === 'string' && item.profile_id.trim()
        ? item.profile_id.trim()
        : '';
    if (!profileId) {
      continue;
    }

    const isActive = item.is_active === true;
    const isPicked = selectedProfileId === profileId;
    const tileBusy = vpnIsSetMember(busyProfileIds, profileId);
    const tileDeactivating = vpnIsSetMember(deactivatingProfileIds, profileId);
    const tileChecking = item.checking === true || vpnIsSetMember(checkingProfileIds, profileId);
    const tileDisabled = disabled || tileBusy || tileDeactivating || tileChecking;

    const tile = document.createElement('button');
    tile.type = 'button';
    tile.className = 'hub-vpn-card__tile';
    tile.id = `hub-overview-vpn-pick-${profileId}`;
    tile.setAttribute('data-hub-vpn-profile-id', profileId);
    tile.setAttribute('aria-pressed', isPicked ? 'true' : 'false');
    tile.disabled = tileDisabled;

    if (isPicked) {
      tile.classList.add('hub-vpn-card__tile--picked');
    }
    if (vpnIsConnectedRouted(item)) {
      tile.classList.add('hub-vpn-card__tile--active');
    } else if (isActive) {
      tile.classList.add('hub-vpn-card__tile--selected');
    }

    const iconWrap = document.createElement('span');
    iconWrap.className = 'hub-vpn-card__tile-icon';
    iconWrap.appendChild(createIcon('vpn', { size: 16 }));
    tile.appendChild(iconWrap);

    const nameEl = document.createElement('span');
    nameEl.className = 'hub-vpn-card__tile-name';
    const displayName =
      typeof item.display_name === 'string' && item.display_name.trim()
        ? item.display_name.trim()
        : profileId;
    nameEl.textContent = displayName;
    tile.appendChild(nameEl);

    const quality = vpnDeriveProfileQuality({ ...item, checking: tileChecking === true });
    const statusEl = document.createElement('span');
    statusEl.className = `hub-vpn-card__tile-status hub-vpn-card__tile-status--${quality.tone}`;
    statusEl.textContent = quality.label;
    tile.appendChild(statusEl);

    tile.addEventListener('click', () => {
      if (tileDisabled || typeof onSelect !== 'function') {
        return;
      }
      if (profileId !== selectedProfileId) {
        onSelect(profileId);
      }
    });

    grid.appendChild(tile);
  }

  picker.appendChild(grid);
  return picker;
}

/**
 * @param {HTMLElement} contentSlot
 * @returns {HTMLElement}
 */
export function buildVpnStatusCardShell(contentSlot) {
  const card = document.createElement('article');
  card.className = 'hub-overview-step-card hub-overview__vpn-status-card hub-vpn-card';

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header hub-vpn-card__header';
  header.appendChild(createStepNumberBadge(3));

  const heading = document.createElement('h2');
  heading.className = 'hub-overview-step-card__title hub-overview__vpn-heading';
  heading.textContent = 'VPN';
  header.appendChild(heading);

  const infoWrap = document.createElement('span');
  infoWrap.className = 'hub-vpn-card__info';
  infoWrap.appendChild(createIcon('info', { size: 16 }));
  header.appendChild(infoWrap);
  card.appendChild(header);

  const main = createOverviewStepCardMain();
  main.appendChild(contentSlot);
  card.appendChild(main);

  return card;
}

/**
 * @param {string} domainDraftName
 * @param {string} domainDraftSuffix
 * @returns {string}
 */
function domainFormatFqdn(domainDraftName, domainDraftSuffix) {
  const validation = validateDomainName(domainDraftName);
  const suffix = typeof domainDraftSuffix === 'string' ? domainDraftSuffix.trim().toLowerCase() : '';
  if (!validation.valid || !suffix) {
    return 'Имя не указано';
  }
  const normalizedName = typeof domainDraftName === 'string' ? domainDraftName.trim().toLowerCase() : '';
  return `${normalizedName}.${suffix}`;
}

/**
 * @param {string} label
 * @param {boolean} ready
 * @returns {HTMLElement}
 */
function domainCreateCheckTile(label, ready) {
  const tile = document.createElement('div');
  tile.className = 'hub-domain-card__check-tile';
  if (ready) {
    tile.classList.add('hub-domain-card__check-tile--success');
  } else {
    tile.classList.add('hub-domain-card__check-tile--danger');
  }

  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-domain-card__check-icon';
  if (ready) {
    iconWrap.appendChild(createIcon('check', { size: 16 }));
  } else {
    iconWrap.appendChild(createIcon('alert', { size: 16 }));
  }
  tile.appendChild(iconWrap);

  const labelEl = document.createElement('span');
  labelEl.className = 'hub-domain-card__check-label';
  labelEl.textContent = label;
  tile.appendChild(labelEl);

  return tile;
}

/**
 * @param {OverviewSection|null|undefined} section
 * @param {(routeId: string) => void} navigate
 * @param {{
 *   domainDraftName?: string,
 *   domainDraftSuffix?: string,
 *   eventPresetId?: string|null,
 *   onChangeClick?: () => void,
 * }} [options]
 * @returns {HTMLElement}
 */
export function buildDomainStatusCard(section, navigate, options = {}) {
  const {
    domainDraftName = '',
    domainDraftSuffix = '',
    eventPresetId = null,
    onChangeClick,
  } = options;
  const title = section?.title ?? 'Домен';

  const card = document.createElement('article');
  card.className = 'hub-overview-step-card hub-overview__domain-status-card hub-domain-card';

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header hub-domain-card__header';
  header.appendChild(createStepNumberBadge(4));

  const heading = document.createElement('h2');
  heading.className = 'hub-overview-step-card__title';
  heading.textContent = title;
  header.appendChild(heading);

  const infoWrap = document.createElement('span');
  infoWrap.className = 'hub-domain-card__info';
  infoWrap.appendChild(createIcon('info', { size: 16 }));
  header.appendChild(infoWrap);
  card.appendChild(header);

  const main = createOverviewStepCardMain();

  const iconFrame = document.createElement('div');
  iconFrame.className = 'hub-domain-card__icon-frame';
  iconFrame.appendChild(createIcon('domain', { size: 32 }));
  main.appendChild(iconFrame);

  const statusWrap = document.createElement('div');
  statusWrap.className = 'hub-domain-card__status';
  statusWrap.appendChild(createBadge({ label: 'Не проверено', tone: 'warning' }));
  main.appendChild(statusWrap);

  const fqdnEl = document.createElement('p');
  fqdnEl.className = 'hub-domain-card__fqdn';
  fqdnEl.textContent = domainFormatFqdn(domainDraftName, domainDraftSuffix);
  main.appendChild(fqdnEl);

  const validation = validateDomainName(domainDraftName);
  const checksGrid = document.createElement('div');
  checksGrid.className = 'hub-domain-card__checks';
  checksGrid.setAttribute('role', 'list');

  // Подпись должна меняться вместе со состоянием: «Имя подготовлено» рядом с
  // иконкой-предупреждением читается как утверждение, хотя имя как раз не готово.
  const nameTile = domainCreateCheckTile(
    validation.valid ? 'Имя подготовлено' : 'Имя не готово',
    validation.valid,
  );
  nameTile.setAttribute('role', 'listitem');
  checksGrid.appendChild(nameTile);

  const eventReady = eventPresetId != null;
  const eventTile = domainCreateCheckTile(
    eventReady ? 'Событие выбрано' : 'Событие не выбрано',
    eventReady,
  );
  eventTile.setAttribute('role', 'listitem');
  checksGrid.appendChild(eventTile);
  main.appendChild(checksGrid);

  const draftUrl = buildDraftUrl({ name: domainDraftName, domain: domainDraftSuffix });
  if (draftUrl) {
    const draftNote = document.createElement('p');
    draftNote.className = 'hub-domain-card__draft-note';
    draftNote.textContent = DOMAIN_DRAFT_LINK_NOTE;
    main.appendChild(draftNote);
  }

  if (section?.note) {
    const note = document.createElement('p');
    note.className = 'hub-domain-card__footer-note';
    note.textContent = section.note;
    main.appendChild(note);
  }

  card.appendChild(main);

  const actions = createOverviewStepCardActions();

  const verifyBtn = createButton({
    label: 'Проверить домен',
    variant: 'secondary',
    size: 'md',
    onActivate: () => {
      if (typeof onChangeClick === 'function') {
        onChangeClick();
      } else {
        navigate('domain');
      }
    },
  });
  verifyBtn.className = `${verifyBtn.className} hub-domain-card__verify`;
  actions.appendChild(verifyBtn);

  if (draftUrl) {
    const draftBtn = createButton({
      label: 'Открыть черновик',
      variant: 'secondary',
      size: 'md',
      onActivate: () => {
        window.open(draftUrl, '_blank', 'noopener');
      },
    });
    draftBtn.className = `${draftBtn.className} hub-domain-card__draft`;
    actions.appendChild(draftBtn);
  }

  const meta = createOverviewStepCardMeta();
  const quietLink = document.createElement('a');
  quietLink.className = 'hub-overview__quiet-link';
  quietLink.href = '#/domain';
  quietLink.textContent = 'Все настройки домена';
  quietLink.addEventListener('click', (event) => {
    event.preventDefault();
    navigate('domain');
  });
  meta.appendChild(quietLink);
  actions.appendChild(meta);
  card.appendChild(actions);

  wireOverviewCardNavigate(card, 'domain', navigate);
  return card;
}

/**
 * @param {(routeId: string) => void} navigate
 * @param {string} [title]
 * @param {string} [routeHref]
 * @returns {HTMLElement}
 */
export function buildEntryPagesStatusCard(
  navigate,
  title = 'Страницы входа',
  routeHref = '#/entry-pages',
) {
  const card = document.createElement('article');
  card.className =
    'hub-overview-step-card hub-overview__entry-pages-status-card hub-entry-pages-card';
  card.dataset.href = routeHref;

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header hub-entry-pages-card__header';
  header.appendChild(createStepNumberBadge(7));

  const heading = document.createElement('h2');
  heading.className = 'hub-overview-step-card__title';
  heading.textContent = title;
  header.appendChild(heading);

  const infoWrap = document.createElement('span');
  infoWrap.className = 'hub-entry-pages-card__info';
  infoWrap.appendChild(createIcon('info', { size: 16 }));
  header.appendChild(infoWrap);
  card.appendChild(header);

  const main = createOverviewStepCardMain();

  const iconFrame = document.createElement('div');
  iconFrame.className = 'hub-entry-pages-card__icon-frame';
  iconFrame.appendChild(createIcon('entry-pages', { size: 32 }));
  main.appendChild(iconFrame);

  const statusWrap = document.createElement('div');
  statusWrap.className = 'hub-entry-pages-card__status';
  statusWrap.appendChild(createBadge({ label: 'Не проверено', tone: 'warning' }));
  main.appendChild(statusWrap);

  const caption = document.createElement('p');
  caption.className = 'hub-entry-pages-card__caption';
  caption.textContent = 'Проверка на этом экране не выполняется';
  main.appendChild(caption);

  card.appendChild(main);

  const actions = createOverviewStepCardActions();
  const openBtn = createButton({
    label: 'Открыть',
    variant: 'secondary',
    onActivate: () => {
      navigate('entry-pages');
    },
  });
  actions.appendChild(openBtn);

  const meta = createOverviewStepCardMeta();
  const quietLink = document.createElement('a');
  quietLink.className = 'hub-overview__quiet-link';
  quietLink.href = routeHref;
  quietLink.textContent = 'Все настройки страниц входа';
  quietLink.addEventListener('click', (event) => {
    event.preventDefault();
    navigate('entry-pages');
  });
  meta.appendChild(quietLink);
  actions.appendChild(meta);
  card.appendChild(actions);

  wireOverviewCardNavigate(card, 'entry-pages', navigate);
  return card;
}

/**
 * @param {(routeId: string) => void} navigate
 * @param {string} [title]
 * @param {string} [routeHref]
 * @returns {HTMLElement}
 */
export function buildDiagnosticsStatusCard(
  navigate,
  title = 'Диагностика',
  routeHref = '#/diagnostics',
) {
  const card = document.createElement('article');
  card.className =
    'hub-overview-step-card hub-overview__diagnostics-status-card hub-diagnostics-card';
  card.dataset.href = routeHref;

  const header = document.createElement('div');
  header.className = 'hub-overview-step-card__header hub-diagnostics-card__header';
  header.appendChild(createStepNumberBadge(8));

  const heading = document.createElement('h2');
  heading.className = 'hub-overview-step-card__title';
  heading.textContent = title;
  header.appendChild(heading);

  const infoWrap = document.createElement('span');
  infoWrap.className = 'hub-diagnostics-card__info';
  infoWrap.appendChild(createIcon('info', { size: 16 }));
  header.appendChild(infoWrap);
  card.appendChild(header);

  const main = createOverviewStepCardMain();

  const iconFrame = document.createElement('div');
  iconFrame.className = 'hub-diagnostics-card__icon-frame';
  iconFrame.appendChild(createIcon('diagnostics', { size: 32 }));
  main.appendChild(iconFrame);

  const statusWrap = document.createElement('div');
  statusWrap.className = 'hub-diagnostics-card__status';
  statusWrap.appendChild(createBadge({ label: 'Не проверено', tone: 'warning' }));
  main.appendChild(statusWrap);

  const caption = document.createElement('p');
  caption.className = 'hub-diagnostics-card__caption';
  caption.textContent = 'Проверка на этом экране не выполняется';
  main.appendChild(caption);

  card.appendChild(main);

  const actions = createOverviewStepCardActions();
  const openBtn = createButton({
    label: 'Открыть',
    variant: 'secondary',
    onActivate: () => {
      navigate('diagnostics');
    },
  });
  actions.appendChild(openBtn);

  const meta = createOverviewStepCardMeta();
  const quietLink = document.createElement('a');
  quietLink.className = 'hub-overview__quiet-link';
  quietLink.href = routeHref;
  quietLink.textContent = 'Все настройки диагностики';
  quietLink.addEventListener('click', (event) => {
    event.preventDefault();
    navigate('diagnostics');
  });
  meta.appendChild(quietLink);
  actions.appendChild(meta);
  card.appendChild(actions);

  wireOverviewCardNavigate(card, 'diagnostics', navigate);
  return card;
}

/**
 * @param {{
 *   categories: { router: boolean, internet: boolean, vpn: boolean, domain: boolean },
 *   loaded?: boolean,
 *   onCheckAll: () => void,
 *   checkBusy?: boolean,
 *   offline?: boolean,
 *   disabled?: boolean,
 * }} options
 * @returns {HTMLElement}
 */
export function buildOverviewStatusStrip(options) {
  const {
    categories,
    loaded = true,
    onCheckAll,
    checkBusy = false,
    offline = false,
    disabled = offline,
  } = options;

  const strip = document.createElement('div');
  strip.className = 'hub-overview__status-strip';

  const indicators = document.createElement('div');
  indicators.className = 'hub-overview__status-strip-indicators';
  indicators.setAttribute('role', 'list');

  for (const key of ['router', 'internet', 'vpn', 'domain']) {
    const item = document.createElement('span');
    item.className = 'hub-overview__status-strip-indicator';
    item.setAttribute('role', 'listitem');
    if (!loaded) {
      item.classList.add('hub-overview__status-strip-indicator--loading');
    } else if (categories[key]) {
      item.classList.add('hub-overview__status-strip-indicator--ready');
    } else {
      item.classList.add('hub-overview__status-strip-indicator--pending');
    }
    item.textContent = READINESS_CATEGORY_LABELS[key] ?? key;
    indicators.appendChild(item);
  }
  strip.appendChild(indicators);

  const checkBtn = createButton({
    label: 'Проверить всё',
    variant: 'secondary',
    disabled: disabled || false,
    busy: checkBusy,
    onActivate: () => {
      onCheckAll();
    },
  });
  checkBtn.className = `${checkBtn.className} hub-overview__status-strip-action`;
  strip.appendChild(checkBtn);

  return strip;
}
