/**
 * Переиспользуемый блок «источник интернета» — только observe для текущего,
 * отдельная приглушённая строка для запомненного uplink (не live gateway).
 */

import { createButton, createCard } from '../components/index.js';
import { HubState, createInlineState } from '../core/states.js';

export const INTERNET_SOURCE_UNKNOWN_LABEL = 'источник неизвестен';
export const INTERNET_SOURCE_MODEM_NOTE =
  'Модем пока не поддерживается';
export const INTERNET_SOURCE_REMEMBERED_PREFIX =
  'Запомнено для автоподключения:';

/**
 * @typedef {{
 *   internet?: boolean|null,
 *   gateway_interface?: string|null,
 *   gateway_ssid?: string|null,
 *   read_status?: string|null,
 * }} InternetSourceObservation
 */

/**
 * @typedef {{
 *   ssid?: string,
 *   band?: string,
 *   desired_active?: boolean,
 *   credential_configured?: boolean,
 * }} RememberedUplinkPref
 */

/**
 * @typedef {{
 *   kind: 'unknown'|'loading'|'wifi'|'wired'|'vpn'|'modem',
 *   label: string,
 *   detail?: string|null,
 * }} InternetSourceDescription
 */

/**
 * @param {string|null|undefined} gatewayInterface
 * @returns {boolean}
 */
export function isEthernetLikeGatewayInterface(gatewayInterface) {
  if (!gatewayInterface || typeof gatewayInterface !== 'string') {
    return false;
  }
  const value = gatewayInterface.trim();
  if (!value) {
    return false;
  }
  if (value.startsWith('GigabitEthernet')) {
    return true;
  }
  return /^Ethernet/i.test(value);
}

/**
 * @param {string|null|undefined} gatewayInterface
 * @returns {boolean}
 */
export function isWifiStationGatewayInterface(gatewayInterface) {
  if (!gatewayInterface || typeof gatewayInterface !== 'string') {
    return false;
  }
  const value = gatewayInterface.trim();
  return value.includes('WifiStation') || value.startsWith('WifiMaster');
}

/**
 * @param {string|null|undefined} gatewayInterface
 * @returns {boolean}
 */
export function isWireguardGatewayInterface(gatewayInterface) {
  if (!gatewayInterface || typeof gatewayInterface !== 'string') {
    return false;
  }
  return gatewayInterface.trim().startsWith('Wireguard');
}

/**
 * @param {InternetSourceObservation|null|undefined} observation
 * @returns {InternetSourceDescription}
 */
export function describeInternetSource(observation) {
  if (!observation) {
    return { kind: 'unknown', label: INTERNET_SOURCE_UNKNOWN_LABEL };
  }
  if (observation.read_status && observation.read_status !== 'ok') {
    return { kind: 'unknown', label: INTERNET_SOURCE_UNKNOWN_LABEL };
  }
  const gateway = observation.gateway_interface;
  if (isWifiStationGatewayInterface(gateway)) {
    const ssid =
      typeof observation.gateway_ssid === 'string'
        ? observation.gateway_ssid.trim()
        : '';
    return {
      kind: 'wifi',
      label: 'Wi‑Fi',
      detail: ssid ? `«${ssid}»` : typeof gateway === 'string' ? gateway : null,
    };
  }
  if (isEthernetLikeGatewayInterface(gateway)) {
    return {
      kind: 'wired',
      label: 'Провод',
      detail: typeof gateway === 'string' ? gateway : null,
    };
  }
  if (isWireguardGatewayInterface(gateway)) {
    return {
      kind: 'vpn',
      label: 'VPN',
      detail: typeof gateway === 'string' ? gateway : null,
    };
  }
  return { kind: 'unknown', label: INTERNET_SOURCE_UNKNOWN_LABEL };
}

/**
 * @param {RememberedUplinkPref|null|undefined} pref
 * @returns {string|null}
 */
export function describeRememberedUplink(pref) {
  if (!pref || pref.desired_active !== true) {
    return null;
  }
  const ssid = typeof pref.ssid === 'string' ? pref.ssid.trim() : '';
  if (!ssid) {
    return null;
  }
  const bandLabel =
    pref.band === 'BAND_5GHZ'
      ? '5 ГГц'
      : pref.band === 'BAND_2_4GHZ'
        ? '2,4 ГГц'
        : null;
  const bandPart = bandLabel ? ` (${bandLabel})` : '';
  const credNote = pref.credential_configured === false ? ' — пароль не сохранён' : '';
  return `${INTERNET_SOURCE_REMEMBERED_PREFIX} «${ssid}»${bandPart}${credNote}`;
}

/**
 * @typedef {object} InternetSourceAffordanceMountOptions
 * @property {() => InternetSourceObservation|null} getObservation
 * @property {() => RememberedUplinkPref|null} getRemembered
 * @property {boolean} [busy]
 * @property {() => boolean} [getBusy]
 * @property {() => void} [onOpenWifiSetup]
 * @property {string} [idPrefix]
 */

/**
 * @param {HTMLElement} container
 * @param {InternetSourceAffordanceMountOptions} options
 * @returns {{ root: HTMLElement, update: () => void, destroy: () => void }}
 */
export function mountInternetSourceAffordance(container, options) {
  const {
    getObservation,
    getRemembered,
    busy = false,
    getBusy,
    onOpenWifiSetup,
    idPrefix = 'hub-internet-source',
  } = options;

  function isBusy() {
    if (typeof getBusy === 'function') {
      return getBusy();
    }
    return busy;
  }

  const card = createCard({ title: 'Источник интернета', titleTag: 'h2' });
  card.classList.add('hub-internet-source');
  const body = card.querySelector('.hub-card__body') ?? card;

  const currentLine = document.createElement('p');
  currentLine.className = 'hub-internet-source__current';
  currentLine.id = `${idPrefix}-current`;
  body.appendChild(currentLine);

  const rememberedLine = document.createElement('p');
  rememberedLine.className = 'hub-internet-source__remembered hub-wifi__note';
  rememberedLine.id = `${idPrefix}-remembered`;
  body.appendChild(rememberedLine);

  const modemLine = document.createElement('p');
  modemLine.className = 'hub-internet-source__modem hub-wifi__note';
  modemLine.textContent = INTERNET_SOURCE_MODEM_NOTE;
  body.appendChild(modemLine);

  const actionRow = document.createElement('div');
  actionRow.className = 'hub-internet-source__actions';
  body.appendChild(actionRow);

  container.appendChild(card);

  /** @type {HTMLButtonElement|null} */
  let wifiBtn = null;

  function update() {
    if (isBusy()) {
      currentLine.textContent = '';
      currentLine.appendChild(
        createInlineState({ state: HubState.LOADING, title: 'Проверяем источник интернета…' }),
      );
    } else {
      const described = describeInternetSource(getObservation());
      currentLine.textContent = '';
      const strong = document.createElement('strong');
      strong.textContent = 'Сейчас: ';
      currentLine.appendChild(strong);
      const label = document.createElement('span');
      label.textContent = described.label;
      currentLine.appendChild(label);
      if (described.detail && described.kind !== 'unknown') {
        const tech = document.createElement('span');
        tech.className = 'hub-internet-source__technical';
        tech.textContent = ` (${described.detail})`;
        currentLine.appendChild(tech);
      }
    }

    const rememberedText = describeRememberedUplink(getRemembered());
    if (rememberedText) {
      rememberedLine.hidden = false;
      rememberedLine.textContent = rememberedText;
    } else {
      rememberedLine.hidden = true;
      rememberedLine.textContent = '';
    }

    actionRow.textContent = '';
    if (typeof onOpenWifiSetup === 'function') {
      wifiBtn = createButton({
        label: 'Настроить Wi‑Fi для интернета',
        variant: 'secondary',
        disabled: isBusy(),
        onActivate: () => onOpenWifiSetup(),
      });
      wifiBtn.id = `${idPrefix}-wifi-btn`;
      actionRow.appendChild(wifiBtn);
    } else {
      wifiBtn = null;
    }
  }

  update();

  return {
    root: card,
    update,
    destroy: () => {
      if (card.parentNode) {
        card.parentNode.removeChild(card);
      }
    },
  };
}
