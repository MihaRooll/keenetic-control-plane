/**
 * Синхронизация disabled/busy у кнопок отправки без полного re-render формы.
 * Сохраняет фокус и каретку в полях ввода (важно для iPad).
 */

import { updateButtonBusyState } from '../features/wifi-screen-parts.js';

/**
 * @param {Event|{ target?: EventTarget|null }|string|null|undefined} event
 * @returns {string}
 */
export function readInputEventValue(event) {
  const target = event && typeof event === 'object' && 'target' in event ? event.target : null;
  if (target instanceof HTMLInputElement || target instanceof HTMLTextAreaElement) {
    return target.value;
  }
  if (typeof event === 'string') {
    return event;
  }
  return '';
}

/**
 * @param {string} buttonId
 * @param {{ disabled: boolean, busy?: boolean }} state
 */
export function syncActionButtonById(buttonId, { disabled, busy = false }) {
  const button = document.getElementById(buttonId);
  if (button instanceof HTMLButtonElement) {
    updateButtonBusyState(button, busy, disabled);
  }
}
