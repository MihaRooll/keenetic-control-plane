import { HubState, createStatePanel } from '../core/states.js';

/** Короткое описание заглушки — без дублирования списка features. */
export const STUB_DESCRIPTION = 'Этот раздел ещё в разработке.';

/**
 * Честная заглушка экрана: короткое description + список будущих возможностей.
 * @param {HTMLElement} container
 * @param {{ title: string, subtitle?: string, features: string[] }} options
 */
export function renderStubScreen(container, { title, subtitle, features }) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  const screen = document.createElement('div');
  screen.className = 'hub-screen';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const h1 = document.createElement('h1');
  h1.className = 'hub-screen__title';
  h1.textContent = title;
  header.appendChild(h1);
  if (subtitle) {
    const sub = document.createElement('p');
    sub.className = 'hub-screen__subtitle';
    sub.textContent = subtitle;
    header.appendChild(sub);
  }
  screen.appendChild(header);

  const body = document.createElement('div');
  body.className = 'hub-screen__body';
  body.appendChild(
    createStatePanel({
      state: HubState.UNSUPPORTED,
      title: 'Экран в разработке',
      description: STUB_DESCRIPTION,
    }),
  );

  const list = document.createElement('ul');
  list.className = 'hub-screen__features';
  for (const item of features) {
    const li = document.createElement('li');
    li.textContent = item;
    list.appendChild(li);
  }
  body.appendChild(list);
  screen.appendChild(body);
  container.appendChild(screen);
}
