/**
 * Общие DOM-построители экранов Wi‑Fi — без замыканий на состояние экрана.
 */

import {
  createButton,
  createCard,
  createIcon,
} from '../components/index.js';

import { HubState, createInlineState } from '../core/states.js';

import { buildWifiQrString, drawWifiQrCanvas } from './wifi-qr.js';

/** @typedef {'save'|'teardown'|'restart'|'enable'} WifiRiskAction */

/** @typedef {'staff'|'guest'} WifiScreenAudience */

/** @type {Readonly<Record<WifiRiskAction, string>>} */
const RISK_CONFIRM_LABELS = Object.freeze({
  save: 'Сохранить изменения',
  teardown: 'Выключить сеть',
  restart: 'Перезапустить сеть',
  enable: 'Включить сеть',
});

/** @type {Readonly<Record<WifiScreenAudience, string>>} */
const RISK_AUDIENCE_WARNINGS = Object.freeze({
  staff: 'Если планшет подключён к этой сети, связь с управлением может оборваться.',
  guest:
    'Если планшет подключён к гостевой сети, связь с управлением может оборваться.',
});

/**
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 * @param {boolean} disabled
 */

export function updateButtonBusyState(button, busy, disabled) {
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
 * @param {{ leadLines: string[], changeLines: string[], bodyClassName?: string }} params
 * @returns {HTMLDivElement}
 */

export function buildRiskModalBody({ leadLines, changeLines, bodyClassName = 'hub-wifi__risk-body' }) {
  const body = document.createElement('div');
  body.className = bodyClassName;
  for (const line of leadLines) {
    const paragraph = document.createElement('p');
    paragraph.textContent = line;
    body.appendChild(paragraph);
  }
  const changesTitle = document.createElement('p');
  changesTitle.className = 'hub-wifi__risk-changes-title';
  changesTitle.textContent = 'Что изменится:';
  body.appendChild(changesTitle);
  const changesList = document.createElement('ul');
  changesList.className = 'hub-wifi__risk-changes-list';
  for (const line of changeLines) {
    const li = document.createElement('li');
    li.textContent = line;
    changesList.appendChild(li);
  }
  body.appendChild(changesList);
  return body;
}

/**
 * @param {{ audience: WifiScreenAudience, changeLines: string[], bodyClassName?: string }} params
 * @returns {HTMLDivElement}
 */

export function buildWifiRiskModalBody({ audience, changeLines, bodyClassName = 'hub-wifi__risk-body' }) {
  return buildRiskModalBody({
    leadLines: [
      RISK_AUDIENCE_WARNINGS[audience],
      'Страница может перестать отвечать. Настройки на роутере при этом могут уже смениться.',
      'Как вернуться: подключитесь к сети с новым названием и паролем (в том числе по QR-коду), по кабелю или через другую сеть роутера.',
      'Если что-то пойдёт не так, система постарается вернуть прежние название, пароль и защиту.',
    ],
    changeLines,
    bodyClassName,
  });
}

/**
 * @param {WifiRiskAction} action
 * @returns {string}
 */

export function getWifiRiskConfirmLabel(action) {
  return RISK_CONFIRM_LABELS[action] ?? 'Сохранить';
}

/**
 * @param {{ title: string, message: string, enableLabel: string, disabled: boolean, onEnable: () => void }} params
 * @returns {HTMLElement}
 */
export function createStaffDisabledRemediationBanner({
  title,
  message,
  enableLabel,
  disabled,
  onEnable,
}) {
  const wrap = document.createElement('div');
  wrap.className = 'hub-wifi__remediation-banner';
  wrap.appendChild(
    createInlineState({
      state: HubState.WARNING,
      title,
      message,
    }),
  );
  const actions = document.createElement('div');
  actions.className = 'hub-wifi__remediation-actions';
  actions.appendChild(
    createButton({
      label: enableLabel,
      variant: 'primary',
      disabled,
      onActivate: onEnable,
    }),
  );
  wrap.appendChild(actions);
  return wrap;
}

/**
 * @param {string} wpaMode
 * @returns {string}
 */
function wpaModeForQr(wpaMode) {
  if (wpaMode === 'WPA2_WPA3_MIXED') {
    return 'WPA2/WPA3';
  }
  return wpaMode;
}

/**
 * @param {{ ssid: string, psk: string, wpaMode: string, bodyClassName?: string, qrHintSuffix?: string }} params
 * @returns {HTMLDivElement}
 */

export function buildWifiQrModalBody({
  ssid,
  psk,
  wpaMode,
  bodyClassName = 'hub-wifi__qr-body',
  qrHintSuffix = 'Отсканируйте код на устройстве персонала.',
}) {
  const body = document.createElement('div');
  body.className = bodyClassName;
  if (!ssid || ssid === 'Название сети не прочитано' || ssid === 'Состояние не прочитано') {
    const note = document.createElement('p');
    note.textContent =
      'Для QR-кода нужно название сети. Укажите его в настройках или дождитесь чтения состояния с роутера.';
    body.appendChild(note);
  } else if (!psk) {
    const note = document.createElement('p');
    note.textContent =
      'Введите пароль в поле «Пароль» на этом экране — система не может показать текущий пароль, потому что роутер его не отдаёт.';
    body.appendChild(note);
  } else {
    const canvas = document.createElement('canvas');
    canvas.className = 'hub-wifi__qr-canvas';
    canvas.setAttribute('role', 'img');
    canvas.setAttribute('aria-label', `QR-код для подключения к сети ${ssid}`);
    try {
      const qrData = buildWifiQrString({
        security: wpaModeForQr(wpaMode),
        ssid,
        password: psk,
      });
      drawWifiQrCanvas(canvas, qrData);
      body.appendChild(canvas);
      const hint = document.createElement('p');
      hint.className = 'hub-wifi__qr-hint';
      hint.textContent = `Сеть «${ssid}». ${qrHintSuffix}`;
      body.appendChild(hint);
    } catch (error) {
      const note = document.createElement('p');
      note.textContent = 'Не удалось построить QR-код. Проверьте название сети и пароль.';
      body.appendChild(note);
    }
  }
  const formHint = document.createElement('p');
  formHint.className = 'hub-wifi__qr-form-hint';
  formHint.textContent =
    'QR-код строится по полям на экране, а не по фактическому состоянию роутера.';
  body.appendChild(formHint);
  return body;
}

/**
 * @param {{ text: string, connectionHintPrefix: string, connectionHintSuffix?: string, onNavigateToConnection: () => void, wrapClassName?: string, textClassName?: string, linkClassName?: string, connectionLinkLabel?: string }} params
 * @returns {HTMLDivElement}
 */

export function createDemoBanner({
  text,
  connectionHintPrefix,
  connectionHintSuffix = '.',
  onNavigateToConnection,
  wrapClassName = 'hub-wifi__demo-banner',
  textClassName = 'hub-wifi__demo-text',
  linkClassName = 'hub-wifi__inline-link',
  connectionLinkLabel = 'Подключение',
}) {
  const wrap = document.createElement('div');
  wrap.className = wrapClassName;
  wrap.appendChild(
    createInlineState({
      state: HubState.MOCK_MODE,
      title: 'Демонстрационный режим — изменения недоступны',
    }),
  );
  const intro = document.createElement('p');
  intro.className = textClassName;
  intro.textContent = text;
  wrap.appendChild(intro);
  const hint = document.createElement('p');
  hint.className = textClassName;
  hint.appendChild(document.createTextNode(connectionHintPrefix));
  const link = document.createElement('button');
  link.type = 'button';
  link.className = linkClassName;
  link.textContent = connectionLinkLabel;
  link.addEventListener('click', () => {
    onNavigateToConnection();
  });
  hint.appendChild(link);
  hint.appendChild(document.createTextNode(connectionHintSuffix));
  wrap.appendChild(hint);
  return wrap;
}

/**
 * @param {{ onNavigateToConnection: () => void }} params
 * @returns {HTMLDivElement}
 */

export function createWifiDemoBanner({ onNavigateToConnection }) {
  return createDemoBanner({
    text:
      'Состояние сети можно просмотреть без живого подключения. В демонстрационном режиме сохранять изменения нельзя — он только для просмотра.',
    connectionHintPrefix:
      'Чтобы менять настройки, сначала завершите подключение к роутеру на экране ',
    onNavigateToConnection,
  });
}

/**
 * @param {{ iconName: string, ssidTitle: string, badge: HTMLElement, secondaryLine: string, toggle?: HTMLElement|null, qrButton: HTMLElement, cardClassName?: string, unknownActions?: HTMLElement|null }} params
 * @returns {HTMLElement}
 */

export function createWifiNetworkHeaderCard({
  iconName,
  ssidTitle,
  badge,
  secondaryLine,
  toggle = null,
  qrButton,
  cardClassName = 'hub-wifi__network-card',
  unknownActions = null,
}) {
  const card = document.createElement('article');
  card.className = cardClassName;
  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-wifi-network__icon';
  iconWrap.appendChild(createIcon(iconName, { size: 32 }));
  card.appendChild(iconWrap);
  const main = document.createElement('div');
  main.className = 'hub-wifi-network__main';
  const titleRow = document.createElement('div');
  titleRow.className = 'hub-wifi-network__title-row';
  const nameEl = document.createElement('h2');
  nameEl.className = 'hub-wifi-network__name';
  nameEl.textContent = ssidTitle;
  titleRow.appendChild(nameEl);
  titleRow.appendChild(badge);
  main.appendChild(titleRow);
  const clientNote = document.createElement('p');
  clientNote.className = 'hub-wifi-network__note';
  clientNote.textContent = secondaryLine;
  main.appendChild(clientNote);
  if (unknownActions) {
    main.appendChild(unknownActions);
  }
  card.appendChild(main);
  const actions = document.createElement('div');
  actions.className = 'hub-wifi-network__actions';
  if (toggle) {
    actions.appendChild(toggle);
  }
  actions.appendChild(qrButton);
  card.appendChild(actions);
  return card;
}

/**
 * @param {{ title: string, description: string, noteClassName?: string, inlineTitle?: string }} params
 * @returns {HTMLElement}
 */

export function createUnsupportedCard({
  title,
  description,
  noteClassName = 'hub-wifi__unsupported-note',
  inlineTitle = 'Не поддерживается',
}) {
  const card = createCard({
    title,
    titleTag: 'h2',
  });
  const body = card.querySelector('.hub-card__body') ?? card;
  body.appendChild(
    createInlineState({
      state: HubState.UNSUPPORTED,
      title: inlineTitle,
    }),
  );
  const desc = document.createElement('p');
  desc.className = noteClassName;
  desc.textContent = description;
  body.appendChild(desc);
  return card;
}

/**
 * @param {string} signature
 * @param {number[]} busyIndices
 * @returns {string}
 */
export function wifiFooterStructureSignature(signature, busyIndices = [3, 4]) {
  const parts = signature.split('|');
  const busySet = new Set(busyIndices);
  return parts.filter((_, index) => !busySet.has(index)).join('|');
}

/**
 * Allowlisted digest for settings form slot — never password plaintext.
 * @param {{
 *   selectedApId: string|null,
 *   ssid: string,
 *   wpaMode: string,
 *   hasPassword: boolean,
 *   formDirty: boolean,
 *   controlsLocked: boolean,
 *   advancedOpen: boolean,
 *   wpaModeKnown: boolean,
 *   formErrorCount: number,
 * }} params
 * @returns {string}
 */
export function buildWifiSettingsFormSignature({
  selectedApId,
  ssid,
  wpaMode,
  hasPassword,
  formDirty,
  controlsLocked,
  advancedOpen,
  wpaModeKnown,
  formErrorCount,
}) {
  return [
    selectedApId ?? 'none',
    ssid.trim(),
    wpaMode,
    hasPassword ? 'has-pwd' : 'no-pwd',
    formDirty ? 'dirty' : 'clean',
    controlsLocked ? 'locked' : 'unlocked',
    advancedOpen ? 'adv-open' : 'adv-closed',
    wpaModeKnown ? 'wpa-known' : 'wpa-unknown',
    String(formErrorCount),
  ].join('|');
}

/**
 * @param {{
 *   selectedApId: string|null,
 *   observedSsidLabel: string|null,
 *   observedActiveLabel: string|null,
 *   networkTogglePending: boolean|null,
 *   toggleChecked: boolean,
 *   toggleIndeterminate: boolean,
 *   toggleDisabled: boolean,
 *   controlsLocked: boolean,
 *   offline: boolean,
 *   stabilizeObservedLabels?: boolean,
 * }} params
 * @returns {string}
 */
export function buildWifiNetworkHeaderSignature({
  selectedApId,
  observedSsidLabel,
  observedActiveLabel,
  networkTogglePending,
  toggleChecked,
  toggleIndeterminate,
  toggleDisabled,
  controlsLocked,
  offline,
  stabilizeObservedLabels = false,
}) {
  return [
    selectedApId ?? 'none',
    stabilizeObservedLabels ? 'stable-labels' : (observedSsidLabel ?? 'none'),
    stabilizeObservedLabels ? 'stable-labels' : (observedActiveLabel ?? 'none'),
    networkTogglePending === null ? 'none' : String(networkTogglePending),
    toggleChecked ? 'on' : 'off',
    toggleIndeterminate ? 'indeterminate' : 'determinate',
    toggleDisabled ? 'disabled' : 'enabled',
    controlsLocked ? 'locked' : 'unlocked',
    offline ? 'offline' : 'online',
  ].join('|');
}

/**
 * @param {{
 *   selectedApId: string|null,
 *   observedSsidLabel: string|null,
 *   controlsLocked: boolean,
 *   adapterMode: string|null,
 *   overlapWarning: string|null,
 * }} params
 * @returns {string}
 */
export function buildWifiApSelectSignature({
  selectedApId,
  observedSsidLabel,
  controlsLocked,
  adapterMode,
  overlapWarning,
}) {
  return [
    selectedApId ?? 'none',
    observedSsidLabel ?? 'none',
    controlsLocked ? 'locked' : 'unlocked',
    adapterMode ?? 'null',
    overlapWarning ? 'overlap' : 'no-overlap',
  ].join('|');
}
