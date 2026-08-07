/**
 * LOCAL HUB — утилиты анимации экранов (additive, reduced-motion safe via CSS tokens).
 */

/**
 * Применяет enter-анимацию к корню экрана сразу после mount (без setTimeout).
 * @param {HTMLElement} element
 */
export function applyScreenEnter(element) {
  element.classList.add('hub-screen-enter');
  requestAnimationFrame(() => {
    element.classList.add('hub-screen-enter--active');
  });
}
