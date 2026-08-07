/**
 * Оболочка LOCAL HUB — боковое меню, верхняя панель, область контента.
 */

import { createIcon } from '../components/icon.js';
import { createButton } from '../components/button.js';
import { openModal } from '../components/modal.js';
import { showToast } from '../components/toast.js';
import { fetchRuntimeInfo, subscribeConnectivity, subscribeInFlight, isOnline, clearConnectionLost, apiGet } from './api.js';
import { getSession, updateSession } from './session.js';
import { HubState, createInlineState, getStateDescriptor } from './states.js';
import { createRouter } from './router.js';
import { menuScreens, screenMap, showcaseScreen } from '../screens/index.js';

/** @typedef {{ adapterMode: string, unsafeAuthDisabled: boolean, hubVersion: string, runtimeLoaded?: boolean }} RuntimeInfo */

/**
 * @param {RuntimeInfo} runtime
 * @returns {{ label: string, tone: string }}
 */
function resolveModeIndicator(runtime) {
  if (runtime.adapterMode === 'live') {
    const descriptor = getStateDescriptor(HubState.LIVE_DEVICE);
    return { label: descriptor.title, tone: 'success' };
  }
  if (runtime.adapterMode === 'fake') {
    const descriptor = getStateDescriptor(HubState.MOCK_MODE);
    return { label: descriptor.title, tone: 'warning' };
  }
  return { label: 'Режим неизвестен', tone: 'neutral' };
}

/**
 * @param {RuntimeInfo} runtime
 * @returns {string}
 */
function formatHubVersion(runtime) {
  if (!runtime.runtimeLoaded) {
    return '—';
  }
  const version = runtime.hubVersion;
  if (!version || version === '0.0.0' || version === 'unknown') {
    return '—';
  }
  return version;
}

/**
 * @param {RuntimeInfo} runtime
 * @returns {string}
 */
function formatAuthStatus(runtime) {
  if (!runtime.runtimeLoaded) {
    return 'неизвестно';
  }
  return runtime.unsafeAuthDisabled ? 'Отключена (режим разработки)' : 'Включена';
}

/**
 * @param {HTMLElement} parent
 * @param {string} label
 * @param {string} value
 */
function appendInfoRow(parent, label, value) {
  const row = document.createElement('div');
  row.className = 'hub-shell-info-row';

  const labelEl = document.createElement('dt');
  labelEl.className = 'hub-shell-info-row__label';
  labelEl.textContent = label;
  row.appendChild(labelEl);

  const valueEl = document.createElement('dd');
  valueEl.className = 'hub-shell-info-row__value';
  valueEl.textContent = value;
  row.appendChild(valueEl);

  parent.appendChild(row);
}

/**
 * @param {RuntimeInfo} runtime
 */
function openSystemInfoModal(runtime) {
  const mode = resolveModeIndicator(runtime);

  const body = document.createElement('dl');
  body.className = 'hub-shell-info-list';

  appendInfoRow(body, 'Режим работы', mode.label);
  appendInfoRow(body, 'Версия интерфейса', formatHubVersion(runtime));
  appendInfoRow(body, 'Авторизация', formatAuthStatus(runtime));

  const linkPara = document.createElement('p');
  linkPara.className = 'hub-shell-info-link-wrap';
  const link = document.createElement('a');
  link.href = '/settings/router-control';
  link.className = 'hub-shell-info-link';
  link.textContent = 'Открыть прежний интерфейс управления роутером';
  linkPara.appendChild(link);
  body.appendChild(linkPara);

  openModal({
    title: 'Сведения о системе',
    description: 'Текущие параметры этой панели управления.',
    body,
  });
}

/**
 * @param {HTMLElement} rootElement
 * @param {{ bridge?: { setConnectionLost?: () => void, setConnectionRestored?: () => void, onUnauthorized?: () => void }, onConnectionLost?: () => void, onConnectionRestored?: () => void, onUnauthorized?: () => void }} [options]
 * @returns {Promise<{ router: ReturnType<typeof createRouter>, runtime: RuntimeInfo, cleanup: () => void }>}
 */
export async function mountShell(rootElement, options = {}) {
  const { bridge, onConnectionLost, onConnectionRestored, onUnauthorized } = options;
  /** @type {RuntimeInfo} */
  let runtime = {
    adapterMode: 'unknown',
    unsafeAuthDisabled: false,
    hubVersion: '0.0.0',
    runtimeLoaded: false,
  };

  rootElement.className = 'hub-app hub-shell';
  rootElement.dataset.navOpen = 'false';

  const requestProgress = document.createElement('div');
  requestProgress.className = 'hub-shell__request-progress';
  requestProgress.setAttribute('role', 'progressbar');
  requestProgress.setAttribute('aria-hidden', 'true');
  requestProgress.hidden = true;
  const requestProgressBar = document.createElement('div');
  requestProgressBar.className = 'hub-shell__request-progress-bar';
  requestProgress.appendChild(requestProgressBar);

  /* ── Предупреждение об отключённой авторизации ── */
  const authBanner = document.createElement('div');
  authBanner.className = 'hub-shell-banner hub-shell-banner--auth';
  authBanner.setAttribute('role', 'alert');
  authBanner.hidden = true;
  const authBannerText = document.createElement('p');
  authBannerText.className = 'hub-shell-banner__text';
  authBannerText.textContent =
    'Авторизация отключена — режим разработки. Не используйте на мероприятии.';
  authBanner.appendChild(authBannerText);

  /* ── Полоса потери связи ── */
  const connectionBanner = document.createElement('div');
  connectionBanner.className = 'hub-shell-banner hub-shell-banner--connection';
  connectionBanner.hidden = true;

  /* ── Боковая панель ── */
  const sidebar = document.createElement('aside');
  sidebar.className = 'hub-shell__sidebar';
  sidebar.id = 'hub-sidebar';

  const sidebarBrand = document.createElement('div');
  sidebarBrand.className = 'hub-shell__brand';
  const brandIcon = document.createElement('span');
  brandIcon.className = 'hub-shell__brand-icon';
  brandIcon.appendChild(createIcon('overview', { size: 24 }));
  sidebarBrand.appendChild(brandIcon);
  const brandText = document.createElement('span');
  brandText.className = 'hub-shell__brand-text';
  brandText.textContent = 'LOCAL HUB';
  sidebarBrand.appendChild(brandText);
  sidebar.appendChild(sidebarBrand);

  const nav = document.createElement('nav');
  nav.className = 'hub-shell__nav';
  nav.setAttribute('aria-label', 'Основная навигация');

  /** @type {Record<string, HTMLAnchorElement>} */
  const navLinks = {};

  for (const screen of menuScreens) {
    const link = document.createElement('a');
    link.className = 'hub-shell__nav-link';
    link.href = `#/${screen.meta.id}`;
    link.dataset.routeId = screen.meta.id;

    const iconWrap = document.createElement('span');
    iconWrap.className = 'hub-shell__nav-icon';
    iconWrap.appendChild(createIcon(screen.meta.iconName, { size: 20 }));
    link.appendChild(iconWrap);

    const label = document.createElement('span');
    label.className = 'hub-shell__nav-label';
    label.textContent = screen.meta.title;
    link.appendChild(label);

    link.addEventListener('click', () => {
      closeMobileNav();
    });

    navLinks[screen.meta.id] = link;
    nav.appendChild(link);
  }

  sidebar.appendChild(nav);

  /* ── Оверлей мобильного меню ── */
  const navOverlay = document.createElement('div');
  navOverlay.className = 'hub-shell__nav-overlay';
  navOverlay.hidden = true;
  navOverlay.addEventListener('click', () => closeMobileNav());

  /* ── Основная колонка ── */
  const mainColumn = document.createElement('div');
  mainColumn.className = 'hub-shell__main';

  const topbar = document.createElement('header');
  topbar.className = 'hub-shell__topbar';

  const topbarLeft = document.createElement('div');
  topbarLeft.className = 'hub-shell__topbar-left';

  const menuBtn = document.createElement('button');
  menuBtn.type = 'button';
  menuBtn.className = 'hub-shell__menu-btn';
  menuBtn.setAttribute('aria-label', 'Открыть меню');
  menuBtn.setAttribute('aria-controls', 'hub-sidebar');
  menuBtn.setAttribute('aria-expanded', 'false');
  const menuIcon = document.createElement('span');
  menuIcon.className = 'hub-shell__menu-icon';
  menuIcon.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < 3; i += 1) {
    const bar = document.createElement('span');
    bar.className = 'hub-shell__menu-bar';
    menuIcon.appendChild(bar);
  }
  menuBtn.appendChild(menuIcon);
  topbarLeft.appendChild(menuBtn);

  const EVENT_DEFAULT_LABEL = 'Мероприятие не выбрано';
  const eventBtn = document.createElement('button');
  eventBtn.type = 'button';
  eventBtn.className = 'hub-shell__event';
  eventBtn.disabled = true;
  eventBtn.setAttribute('aria-disabled', 'true');
  eventBtn.title = EVENT_DEFAULT_LABEL;
  eventBtn.setAttribute('aria-label', EVENT_DEFAULT_LABEL);

  const eventLabel = document.createElement('span');
  eventLabel.className = 'hub-shell__event-label';
  eventLabel.textContent = EVENT_DEFAULT_LABEL;
  eventBtn.appendChild(eventLabel);

  const eventChevron = document.createElement('span');
  eventChevron.className = 'hub-shell__event-chevron';
  eventChevron.setAttribute('aria-hidden', 'true');
  eventChevron.appendChild(createIcon('chevron-down', { size: 16 }));
  eventBtn.appendChild(eventChevron);

  topbarLeft.appendChild(eventBtn);

  /** @type {Array<{ preset_id: string, name: string }>} */
  let loadedEventPresets = [];
  /** @type {string|null} */
  let loadedSiteId = null;

  /**
   * @param {string} reason
   */
  function setEventSelectorDisabled(reason) {
    eventBtn.disabled = true;
    eventBtn.setAttribute('aria-disabled', 'true');
    eventLabel.textContent = EVENT_DEFAULT_LABEL;
    eventBtn.title = reason;
    eventBtn.setAttribute('aria-label', `${EVENT_DEFAULT_LABEL}. ${reason}`);
    loadedEventPresets = [];
    loadedSiteId = null;
  }

  /**
   * @param {string} label
   */
  function setEventSelectorEnabled(label) {
    eventBtn.disabled = false;
    eventBtn.removeAttribute('aria-disabled');
    eventLabel.textContent = label;
    eventBtn.title = label;
    eventBtn.setAttribute(
      'aria-label',
      label === EVENT_DEFAULT_LABEL
        ? `${EVENT_DEFAULT_LABEL}. Нажмите, чтобы выбрать мероприятие`
        : `Мероприятие: ${label}. Нажмите, чтобы выбрать другое`,
    );
  }

  function openEventPresetModal() {
    if (!loadedEventPresets.length || !loadedSiteId) {
      return;
    }

    const session = getSession();
    const body = document.createElement('div');
    body.className = 'hub-shell__event-modal-list';

    /** @type {{ close: () => void }|null} */
    let modalHandle = null;

    for (const preset of loadedEventPresets) {
      const presetBtn = createButton({
        label: preset.name,
        variant: session.eventPresetId === preset.preset_id ? 'primary' : 'secondary',
        onActivate: () => {
          updateSession({
            eventPresetId: preset.preset_id,
            eventPresetName: preset.name,
            siteId: loadedSiteId,
          });
          setEventSelectorEnabled(preset.name);
          modalHandle?.close();
        },
      });
      body.appendChild(presetBtn);
    }

    modalHandle = openModal({
      title: 'Выбор мероприятия',
      description:
        'Выбор мероприятия действует только в этом сеансе и пока не меняет настройки роутера.',
      body,
    });
  }

  eventBtn.addEventListener('click', () => {
    if (!eventBtn.disabled) {
      openEventPresetModal();
    }
  });

  async function loadEventPresetsForShell() {
    try {
      const status = /** @type {{ default_site_id?: string|null }} */ (
        await apiGet('status', { retry: 1 })
      );
      const siteId = status?.default_site_id;
      if (!siteId) {
        setEventSelectorDisabled('Мероприятия не заведены');
        return;
      }

      const presetsData = /** @type {{ items?: Array<{ preset_id?: string, name?: string }> }} */ (
        await apiGet(`sites/${siteId}/event-presets`, { retry: 1 })
      );
      const items = presetsData?.items ?? [];
      const presets = items.filter(
        (item) => typeof item.preset_id === 'string' && typeof item.name === 'string',
      );

      if (!presets.length) {
        setEventSelectorDisabled('Мероприятия не заведены');
        return;
      }

      loadedEventPresets = presets.map((item) => ({
        preset_id: item.preset_id,
        name: item.name,
      }));
      loadedSiteId = siteId;

      const session = getSession();
      let displayLabel = EVENT_DEFAULT_LABEL;
      if (session.eventPresetId) {
        const matched = loadedEventPresets.find((item) => item.preset_id === session.eventPresetId);
        if (matched) {
          displayLabel = matched.name;
        } else if (session.eventPresetName) {
          displayLabel = session.eventPresetName;
        }
      }

      setEventSelectorEnabled(displayLabel);
    } catch {
      setEventSelectorDisabled('Список мероприятий недоступен');
    }
  }

  const topbarRight = document.createElement('div');
  topbarRight.className = 'hub-shell__topbar-right';

  const modeIndicator = document.createElement('div');
  modeIndicator.className = 'hub-shell__mode';
  const modeDot = document.createElement('span');
  modeDot.className = 'hub-shell__mode-dot';
  modeIndicator.appendChild(modeDot);
  const modeText = document.createElement('span');
  modeText.className = 'hub-shell__mode-text';
  modeIndicator.appendChild(modeText);
  topbarRight.appendChild(modeIndicator);

  const settingsBtn = createButton({
    variant: 'secondary',
    iconName: 'settings',
    ariaLabel: 'Сведения о системе',
    onActivate: () => openSystemInfoModal(runtime),
  });
  settingsBtn.classList.add('hub-shell__settings-btn');
  topbarRight.appendChild(settingsBtn);

  topbar.appendChild(topbarLeft);
  topbar.appendChild(topbarRight);

  const content = document.createElement('main');
  content.className = 'hub-shell__content hub-scroll';
  content.id = 'hub-content';

  mainColumn.appendChild(topbar);
  mainColumn.appendChild(content);

  rootElement.appendChild(requestProgress);
  rootElement.appendChild(authBanner);
  rootElement.appendChild(connectionBanner);
  rootElement.appendChild(sidebar);
  rootElement.appendChild(navOverlay);
  rootElement.appendChild(mainColumn);

  /** @type {ReturnType<typeof createRouter>|null} */
  let router = null;
  /** @type {HTMLElement|null} */
  let previousFocus = null;

  function updateModeIndicator() {
    const mode = resolveModeIndicator(runtime);
    modeIndicator.className = `hub-shell__mode hub-shell__mode--${mode.tone}`;
    modeText.textContent = mode.label;
  }

  function updateAuthBanner() {
    authBanner.hidden = !runtime.unsafeAuthDisabled;
  }

  function showSessionExpiredModal() {
    openModal({
      title: 'Сессия истекла',
      description: 'Ваша сессия завершилась. Войдите снова, чтобы продолжить работу.',
      actions: [
        createButton({
          label: 'Перейти на страницу входа',
          variant: 'primary',
          onActivate: () => {
            window.location.assign('/login');
          },
        }),
      ],
    });
  }

  function setConnectionLostState(lost) {
    connectionBanner.hidden = !lost;
    while (connectionBanner.firstChild) {
      connectionBanner.removeChild(connectionBanner.firstChild);
    }
    if (lost) {
      const stateKey = isOnline() ? HubState.CONNECTION_LOST : HubState.NO_INTERNET;
      connectionBanner.appendChild(createInlineState({ state: stateKey, compact: false }));
    }
  }

  const handleConnectionLost = () => {
    setConnectionLostState(true);
    onConnectionLost?.();
  };

  const handleConnectionRestored = () => {
    clearConnectionLost();
    setConnectionLostState(false);
    showToast({
      tone: 'success',
      title: 'Связь восстановлена',
      message: 'Соединение с сервером снова доступно.',
    });
    onConnectionRestored?.();
  };

  const handleUnauthorized = () => {
    showSessionExpiredModal();
    onUnauthorized?.();
  };

  if (bridge) {
    bridge.setConnectionLost = handleConnectionLost;
    bridge.setConnectionRestored = handleConnectionRestored;
    bridge.onUnauthorized = handleUnauthorized;
  }

  try {
    runtime = { ...(await fetchRuntimeInfo()), runtimeLoaded: true };
  } catch {
    /* Режим остаётся unknown — не подменяем на fake. */
  }

  updateModeIndicator();
  updateAuthBanner();
  void loadEventPresetsForShell();

  function updateNavActive(routeId) {
    for (const [id, link] of Object.entries(navLinks)) {
      const active = id === routeId;
      link.classList.toggle('hub-shell__nav-link--active', active);
      if (active) {
        link.setAttribute('aria-current', 'page');
      } else {
        link.removeAttribute('aria-current');
      }
    }
  }

  function openMobileNav() {
    rootElement.dataset.navOpen = 'true';
    menuBtn.setAttribute('aria-expanded', 'true');
    navOverlay.hidden = false;
    previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const firstLink = nav.querySelector('a');
    if (firstLink instanceof HTMLElement) {
      firstLink.focus();
    }
    document.addEventListener('keydown', handleNavKeydown);
  }

  function closeMobileNav() {
    rootElement.dataset.navOpen = 'false';
    menuBtn.setAttribute('aria-expanded', 'false');
    navOverlay.hidden = true;
    document.removeEventListener('keydown', handleNavKeydown);
    if (previousFocus) {
      previousFocus.focus();
      previousFocus = null;
    }
  }

  /** @param {KeyboardEvent} event */
  function handleNavKeydown(event) {
    if (event.key === 'Escape') {
      event.preventDefault();
      closeMobileNav();
    }
  }

  menuBtn.addEventListener('click', () => {
    if (rootElement.dataset.navOpen === 'true') {
      closeMobileNav();
    } else {
      openMobileNav();
    }
  });

  const unsubConnectivity = subscribeConnectivity((online) => {
    if (!online) {
      handleConnectionLost();
      return;
    }
    if (!connectionBanner.hidden) {
      handleConnectionRestored();
    }
  });

  let requestProgressShowTimer = null;
  let requestProgressHideTimer = null;

  const unsubInFlight = subscribeInFlight((count) => {
    if (count >= 1) {
      if (requestProgressHideTimer) {
        clearTimeout(requestProgressHideTimer);
        requestProgressHideTimer = null;
      }
      if (requestProgress.hidden) {
        if (!requestProgressShowTimer) {
          requestProgressShowTimer = setTimeout(() => {
            requestProgressShowTimer = null;
            requestProgress.hidden = false;
            requestProgress.setAttribute('aria-hidden', 'false');
            requestProgress.classList.add('hub-shell__request-progress--visible');
          }, 280);
        }
      } else if (!requestProgress.classList.contains('hub-shell__request-progress--visible')) {
        requestProgress.classList.add('hub-shell__request-progress--visible');
      }
      return;
    }

    if (requestProgressShowTimer) {
      clearTimeout(requestProgressShowTimer);
      requestProgressShowTimer = null;
    }
    if (!requestProgress.hidden && !requestProgressHideTimer) {
      requestProgress.classList.remove('hub-shell__request-progress--visible');
      requestProgressHideTimer = setTimeout(() => {
        requestProgressHideTimer = null;
        requestProgress.hidden = true;
        requestProgress.setAttribute('aria-hidden', 'true');
      }, 300);
    }
  });

  /** @type {Record<string, { render: Function }>} */
  const routes = {};
  for (const [id, screen] of Object.entries(screenMap)) {
    routes[id] = screen;
  }
  routes[showcaseScreen.meta.id] = showcaseScreen;

  const ctx = {
    get runtime() {
      return runtime;
    },
    navigate(routeId) {
      if (router) {
        router.navigate(routeId);
      }
    },
    showToast,
  };

  router = createRouter({
    routes,
    contentElement: content,
    getContext: () => ctx,
    onNavigate: (routeId) => {
      updateNavActive(routeId);
      closeMobileNav();
    },
  });

  router.start();

  const cleanup = () => {
    router?.stop();
    unsubConnectivity();
    unsubInFlight();
    if (requestProgressShowTimer) {
      clearTimeout(requestProgressShowTimer);
    }
    if (requestProgressHideTimer) {
      clearTimeout(requestProgressHideTimer);
    }
    document.removeEventListener('keydown', handleNavKeydown);
  };

  return {
    router,
    runtime,
    cleanup,
  };
}
