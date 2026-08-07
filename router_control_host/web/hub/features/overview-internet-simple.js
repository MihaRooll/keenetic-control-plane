/**
 * Read-only internet block for overview main path (R-2/R-15).
 */

import { createCard } from '../components/index.js';
import { HubState, createInlineState } from '../core/states.js';
import {
  INTERNET_SOURCE_MODEM_NOTE,
  INTERNET_SOURCE_REMEMBERED_PREFIX,
  describeInternetSource,
  describeRememberedUplink,
} from './internet-source-block.js';

export const OVERVIEW_INTERNET_WIFI_SWITCH_HONESTY =
  'Если Wi‑Fi пропадёт, подключитесь к сети заново вручную — автоматическое восстановление связи на роутере не подтверждено.';

export const OVERVIEW_INTERNET_DETAILS_LINK_LABEL = 'Подробнее про интернет';

/**
 * @typedef {import('./internet-source-block.js').InternetSourceObservation} InternetSourceObservation
 * @typedef {import('./internet-source-block.js').RememberedUplinkPref} RememberedUplinkPref
 */

/**
 * @typedef {object} OverviewInternetSimpleMountOptions
 * @property {() => InternetSourceObservation|null} getObservation
 * @property {() => RememberedUplinkPref|null} getRemembered
 * @property {() => boolean} [getBusy]
 * @property {() => void} [onOpenDetails]
 * @property {string} [idPrefix]
 * @property {boolean} [disabled]
 */

/**
 * @param {string|null|undefined} rememberedText
 * @returns {string|null}
 */
function formatRememberedLineForOverview(rememberedText) {
  if (!rememberedText || typeof rememberedText !== 'string') {
    return null;
  }
  const trimmed = rememberedText.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.startsWith(INTERNET_SOURCE_REMEMBERED_PREFIX)) {
    const rest = trimmed.slice(INTERNET_SOURCE_REMEMBERED_PREFIX.length).trim();
    return rest ? `Сохранено на хосте: ${rest}` : null;
  }
  return `Сохранено на хосте: ${trimmed}`;
}

/**
 * @param {HTMLElement} container
 * @param {OverviewInternetSimpleMountOptions} options
 * @returns {{ root: HTMLElement, update: () => void, destroy: () => void }}
 */
export function mountOverviewInternetSimple(container, options) {
  const {
    getObservation,
    getRemembered,
    getBusy,
    onOpenDetails,
    idPrefix = 'hub-overview-internet',
    disabled = false,
  } = options;

  function isBusy() {
    return typeof getBusy === 'function' ? getBusy() : false;
  }

  const card = createCard({ title: 'Интернет', titleTag: 'h2' });
  card.classList.add('hub-overview-internet');
  const body = card.querySelector('.hub-card__body') ?? card;

  const currentLine = document.createElement('p');
  currentLine.className = 'hub-overview-internet__current';
  currentLine.id = `${idPrefix}-current`;
  body.appendChild(currentLine);

  const rememberedLine = document.createElement('p');
  rememberedLine.className = 'hub-overview-internet__remembered hub-wifi__note';
  rememberedLine.id = `${idPrefix}-remembered`;
  body.appendChild(rememberedLine);

  const honestyLine = document.createElement('p');
  honestyLine.className = 'hub-overview-internet__honesty hub-wifi__note';
  honestyLine.textContent = OVERVIEW_INTERNET_WIFI_SWITCH_HONESTY;
  body.appendChild(honestyLine);

  const modemLine = document.createElement('p');
  modemLine.className = 'hub-overview-internet__modem hub-wifi__note';
  modemLine.textContent = INTERNET_SOURCE_MODEM_NOTE;
  body.appendChild(modemLine);

  const detailsRow = document.createElement('p');
  detailsRow.className = 'hub-overview-internet__details';
  body.appendChild(detailsRow);

  container.appendChild(card);

  /** @type {HTMLAnchorElement|null} */
  let detailsLink = null;

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
    }

    const rememberedRaw = describeRememberedUplink(getRemembered());
    const rememberedText = formatRememberedLineForOverview(rememberedRaw);
    if (rememberedText) {
      rememberedLine.hidden = false;
      rememberedLine.textContent = rememberedText;
    } else {
      rememberedLine.hidden = true;
      rememberedLine.textContent = '';
    }

    detailsRow.textContent = '';
    if (typeof onOpenDetails === 'function') {
      if (!detailsLink) {
        detailsLink = document.createElement('a');
        detailsLink.className = 'hub-overview-internet__details-link';
        detailsLink.href = '#/internet-uplink';
        detailsLink.textContent = OVERVIEW_INTERNET_DETAILS_LINK_LABEL;
        detailsLink.addEventListener('click', (event) => {
          event.preventDefault();
          if (!disabled) {
            onOpenDetails();
          }
        });
      }
      detailsLink.setAttribute('aria-disabled', disabled ? 'true' : 'false');
      if (disabled) {
        detailsLink.classList.add('hub-link--disabled');
      } else {
        detailsLink.classList.remove('hub-link--disabled');
      }
      detailsRow.appendChild(detailsLink);
    }
  }

  function destroy() {
    if (card.parentNode) {
      card.parentNode.removeChild(card);
    }
  }

  update();

  return { root: card, update, destroy };
}
