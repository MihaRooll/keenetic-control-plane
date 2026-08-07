/**
 * LOCAL HUB — единый механизм отображения состояний интерфейса.
 * Расширение: добавить ключ в HubState и строку в STATE_DESCRIPTORS.
 */

const SVG_NS = ['http', '://www.w3.org/2000/svg'].join('');

/** Состояния, для которых панель объявляется как alert. */
const ALERT_STATES = new Set(['ERROR', 'CONNECTION_LOST']);

export const HubState = Object.freeze({
  LOADING: 'LOADING',
  SEARCHING: 'SEARCHING',
  EMPTY: 'EMPTY',
  CONNECTING: 'CONNECTING',
  SUCCESS: 'SUCCESS',
  WARNING: 'WARNING',
  ERROR: 'ERROR',
  NO_INTERNET: 'NO_INTERNET',
  CONNECTION_LOST: 'CONNECTION_LOST',
  RECOVERING: 'RECOVERING',
  FORBIDDEN: 'FORBIDDEN',
  UNSUPPORTED: 'UNSUPPORTED',
  MOCK_MODE: 'MOCK_MODE',
  LIVE_DEVICE: 'LIVE_DEVICE',
});

export const STATE_DESCRIPTORS = Object.freeze({
  LOADING: {
    tone: 'neutral',
    title: 'Загрузка',
    description: 'Подождите, получаем данные…',
    iconName: 'spinner',
    busy: true,
    retryable: false,
  },
  SEARCHING: {
    tone: 'primary',
    title: 'Поиск роутера',
    description:
      'Ищем среди адресов, которые известны этому компьютеру, и среди уже сохранённых. Полного обхода сети не делаем. Это может занять несколько секунд.',
    iconName: 'search',
    busy: true,
    retryable: false,
  },
  EMPTY: {
    tone: 'neutral',
    title: 'Здесь пока пусто',
    description: 'Данных пока нет. Когда они появятся, вы увидите их на этом экране.',
    iconName: 'empty',
    busy: false,
    retryable: false,
  },
  CONNECTING: {
    tone: 'primary',
    title: 'Подключение',
    description: 'Устанавливаем связь с роутером. Не закрывайте приложение.',
    iconName: 'connect',
    busy: true,
    retryable: false,
  },
  SUCCESS: {
    tone: 'success',
    title: 'Готово',
    description: 'Операция выполнена успешно.',
    iconName: 'success',
    busy: false,
    retryable: false,
  },
  WARNING: {
    tone: 'warning',
    title: 'Обратите внимание',
    description: 'Есть предупреждение. Проверьте детали ниже.',
    iconName: 'warning',
    busy: false,
    retryable: false,
  },
  ERROR: {
    tone: 'danger',
    title: 'Что-то пошло не так',
    description: 'Не удалось выполнить операцию. Попробуйте ещё раз.',
    iconName: 'error',
    busy: false,
    retryable: true,
  },
  NO_INTERNET: {
    tone: 'warning',
    title: 'Нет доступа в интернет',
    description: 'Проверьте подключение iPad к сети Wi‑Fi или мобильному интернету.',
    iconName: 'no-internet',
    busy: false,
    retryable: true,
  },
  CONNECTION_LOST: {
    tone: 'danger',
    title: 'Связь с сервером управления потеряна',
    description:
      'Не удаётся связаться с хостом Router Control. Проверьте сеть и повторите.',
    iconName: 'connection-lost',
    busy: false,
    retryable: true,
  },
  RECOVERING: {
    tone: 'warning',
    title: 'Восстанавливаем связь',
    description: 'Пробуем снова подключиться к хосту Router Control. Подождите немного.',
    iconName: 'recovering',
    busy: true,
    retryable: false,
  },
  FORBIDDEN: {
    tone: 'warning',
    title: 'Недостаточно прав',
    description: 'У вашей учётной записи нет доступа к этой функции.',
    iconName: 'forbidden',
    busy: false,
    retryable: false,
  },
  UNSUPPORTED: {
    tone: 'neutral',
    title: 'Функция недоступна',
    description:
      'Эта функция не поддерживается вашим роутером или версией прошивки.',
    iconName: 'unsupported',
    busy: false,
    retryable: false,
  },
  MOCK_MODE: {
    tone: 'neutral',
    title: 'Демонстрационный режим',
    description: 'Демонстрационный режим: данные не с реального устройства.',
    iconName: 'mock',
    busy: false,
    retryable: false,
  },
  LIVE_DEVICE: {
    tone: 'success',
    title: 'Реальное устройство',
    description: 'Вы работаете с подключённым роутером.',
    iconName: 'live',
    busy: false,
    retryable: false,
  },
});

/** SVG-иконки по имени из дескриптора. */
const ICON_BUILDERS = Object.freeze({
  spinner: () => createSpinnerIcon(),
  search: () => createStaticIcon('M10.5 3a7.5 7.5 0 1 0 4.77 13.27l3.23 3.23 1.06-1.06-3.23-3.23A7.47 7.47 0 0 0 10.5 3Zm0 2a5.5 5.5 0 1 1 0 11 5.5 5.5 0 0 1 0-11Z'),
  empty: () => createStaticIcon('M5 6.5A2.5 2.5 0 0 1 7.5 4h9A2.5 2.5 0 0 1 19 6.5v11A2.5 2.5 0 0 1 16.5 20h-9A2.5 2.5 0 0 1 5 17.5v-11Zm2.5-.5a.5.5 0 0 0-.5.5v11a.5.5 0 0 0 .5.5h9a.5.5 0 0 0 .5-.5v-11a.5.5 0 0 0-.5-.5h-9ZM8 10h8v1.5H8V10Zm0 3.5h5v1.5H8V13.5Z'),
  connect: () => createStaticIcon('M8.5 11a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Zm0-2a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Zm7 8.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Zm0-2a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3ZM9.8 12.2l4.4 2.6-.8 1.4-4.4-2.6.8-1.4Z'),
  success: () => createStaticIcon('M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 2a7 7 0 1 1 0 14 7 7 0 0 1 0-14Zm3.53 4.47-4.24 4.24-2.12-2.12-1.06 1.06 3.18 3.18 5.3-5.3-1.06-1.06Z'),
  warning: () => createStaticIcon('M12 3.5 2.5 19h19L12 3.5Zm0 3.2 6.35 10.3H5.65L12 6.7ZM11 10h2v4h-2v-4Zm0 5.5h2V17h-2v-1.5Z'),
  error: () => createStaticIcon('M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 2a7 7 0 1 1 0 14 7 7 0 0 1 0-14Zm-1 4h2v5h-2V9Zm0 6.5h2V17h-2v-1.5Z'),
  'no-internet': () => createStaticIcon('M12 4.5c-3.2 0-6 1.6-7.7 4.1l1.5 1.1A8.5 8.5 0 0 1 12 6.5c1.9 0 3.6.6 5 1.7l1.5-1.1C16.9 6.1 14.6 4.5 12 4.5Zm0 4c-1.5 0-2.9.6-3.9 1.6l1.4 1.1c.6-.6 1.5-1 2.5-1s1.9.4 2.5 1l1.4-1.1c-1-1-2.4-1.6-3.9-1.6Zm0 4c-.8 0-1.5.3-2 .8l5.2 5.2c.5-.5.8-1.2.8-2 0-1.1-.9-2-2-2Zm-6.3 1.3-1.4 1.1 1.8 1.8 1.4-1.1-2-2Zm12.6 0-2 2 1.4 1.1 1.8-1.8-1.2-1.3ZM3.3 5.1 2 6.4l2.5 2.5 1.3-1.3L3.3 5.1Zm17.4 0-3.8 3.8 1.3 1.3 2.5-2.5-1.3-1.3Z'),
  'connection-lost': () => createStaticIcon('M8.5 11a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Zm0-2a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3Zm7 8.5a3.5 3.5 0 1 1 0-7 3.5 3.5 0 0 1 0 7Zm0-2a1.5 1.5 0 1 0 0-3 1.5 1.5 0 0 0 0 3ZM6 12l1.4 1.4L18 2.8l1.4 1.4L7.4 13.4 6 12Z'),
  recovering: () => createStaticIcon('M12 4a8 8 0 1 0 7.75 10h-2.1A6 6 0 1 1 12 6V4Zm0 3v4.5l3.5 2-.9 1.5L10 12.2V7h2Z'),
  forbidden: () => createStaticIcon('M8 9V7.5A4 4 0 0 1 12 3.5a4 4 0 0 1 4 4V9h1a2 2 0 0 1 2 2v7a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2v-7a2 2 0 0 1 2-2h1Zm2 0h4V7.5a2 2 0 1 0-4 0V9Zm-1 4.5v3h2v-3H9Zm4 0v3h2v-3h-2Z'),
  unsupported: () => createStaticIcon('M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Zm0 2a7 7 0 1 1 0 14 7 7 0 0 1 0-14ZM8 11.5h8v1.5H8v-1.5Z'),
  mock: () => createStaticIcon('M9 4h6l1 2h3v2h-1v9a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2V8H5V6h3l1-2Zm1.2 4L8 14h2.2l.8-2.4.8 2.4H14l-2.2-6H10.2Z'),
  live: () => createStaticIcon('M7 5h10a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2Zm0 2v10h10V7H7Zm2 2h6v1.5H9V9Zm0 3h4v1.5H9V12Z'),
});

/**
 * Возвращает дескриптор состояния или бросает ошибку для неизвестного ключа.
 * @param {string} state
 */
export function getStateDescriptor(state) {
  const descriptor = STATE_DESCRIPTORS[state];
  if (!descriptor) {
    throw new Error(`Unknown hub state: ${state}`);
  }
  return descriptor;
}

/**
 * Крупная панель состояния на весь контейнер.
 * @param {{ state: string, title?: string, titleTag?: 'h2'|'h3'|'h4'|'p', description?: string, compact?: boolean, action?: { label: string, onActivate: () => void }, secondaryAction?: { label: string, onActivate: () => void }, details?: string | Node }} options
 */
export function createStatePanel({
  state,
  title,
  titleTag = 'h2',
  description,
  compact = false,
  action,
  secondaryAction,
  details,
}) {
  const descriptor = getStateDescriptor(state);
  const panelTitle = title ?? descriptor.title;
  const panelDescription = description ?? descriptor.description;

  const panel = document.createElement('section');
  panel.className = `hub-state-panel hub-state-panel--${descriptor.tone}`;
  if (compact) {
    panel.classList.add('hub-state-panel--compact');
  }
  panel.dataset.hubState = state;

  panel.setAttribute('role', ALERT_STATES.has(state) ? 'alert' : 'status');
  if (descriptor.busy) {
    panel.setAttribute('aria-busy', 'true');
  }

  const inner = document.createElement('div');
  inner.className = 'hub-state-panel__inner';

  const iconWrap = document.createElement('div');
  iconWrap.className = 'hub-state-panel__icon';
  iconWrap.appendChild(createIconForDescriptor(descriptor));
  inner.appendChild(iconWrap);

  const resolvedTitleTag =
    titleTag === 'h3' || titleTag === 'h4' || titleTag === 'p' ? titleTag : 'h2';
  const titleEl = document.createElement(resolvedTitleTag);
  titleEl.className = 'hub-state-panel__title';
  titleEl.textContent = panelTitle;
  inner.appendChild(titleEl);

  const descEl = document.createElement('p');
  descEl.className = 'hub-state-panel__description';
  descEl.textContent = panelDescription;
  inner.appendChild(descEl);

  const actionsEl = buildActions(action, secondaryAction);
  if (actionsEl) {
    inner.appendChild(actionsEl);
  }

  const detailsEl = buildDetails(details);
  if (detailsEl) {
    inner.appendChild(detailsEl);
  }

  panel.appendChild(inner);
  return panel;
}

/**
 * Компактная строка состояния внутри карточки.
 * @param {{ state: string, title?: string, compact?: boolean, fullWidth?: boolean }} options
 */
export function createInlineState({ state, title, compact = true, fullWidth = false }) {
  const descriptor = getStateDescriptor(state);
  const inlineTitle = title ?? descriptor.title;

  const row = document.createElement('div');
  row.className = compact
    ? 'hub-state-inline hub-state-inline--compact'
    : 'hub-state-inline';
  if (fullWidth) {
    row.classList.add('hub-state-inline--full');
  }
  row.classList.add(`hub-state-inline--${descriptor.tone}`);
  row.dataset.hubState = state;
  row.setAttribute('role', ALERT_STATES.has(state) ? 'alert' : 'status');
  if (descriptor.busy) {
    row.setAttribute('aria-busy', 'true');
  }

  const iconWrap = document.createElement('span');
  iconWrap.className = 'hub-state-inline__icon';
  iconWrap.appendChild(createIconForDescriptor(descriptor, true));
  row.appendChild(iconWrap);

  const text = document.createElement('span');
  text.className = 'hub-state-inline__text';
  text.textContent = inlineTitle;
  row.appendChild(text);

  return row;
}

/**
 * Скелетон загрузки.
 * @param {{ lines?: number, withTitle?: boolean }} options
 */
export function createSkeleton({ lines = 3, withTitle = true } = {}) {
  const skeleton = document.createElement('div');
  skeleton.className = 'hub-state-skeleton';
  skeleton.setAttribute('aria-hidden', 'true');

  if (withTitle) {
    const titleBar = document.createElement('div');
    titleBar.className = 'hub-state-skeleton__line hub-state-skeleton__line--title';
    skeleton.appendChild(titleBar);
  }

  const count = Math.max(1, Math.floor(lines));
  for (let i = 0; i < count; i += 1) {
    const line = document.createElement('div');
    line.className = 'hub-state-skeleton__line';
    if (i === count - 1 && count > 1) {
      line.classList.add('hub-state-skeleton__line--short');
    }
    skeleton.appendChild(line);
  }

  return skeleton;
}

/**
 * Очищает контейнер и рендерит панель состояния.
 * @param {HTMLElement} container
 * @param {Parameters<typeof createStatePanel>[0]} options
 * @returns {HTMLElement}
 */
export function renderState(container, options) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }
  const panel = createStatePanel(options);
  container.appendChild(panel);
  return panel;
}

/**
 * Витрина всех состояний для служебного экрана.
 */
export function createStateShowcase() {
  const showcase = document.createElement('div');
  showcase.className = 'hub-state-showcase';

  const heading = document.createElement('h2');
  heading.className = 'hub-state-showcase__heading';
  heading.textContent = 'Все состояния интерфейса';
  showcase.appendChild(heading);

  for (const state of Object.keys(HubState)) {
    const item = document.createElement('article');
    item.className = 'hub-state-showcase__item';

    const label = document.createElement('p');
    label.className = 'hub-state-showcase__key';
    label.textContent = state;
    item.appendChild(label);

    item.appendChild(createStatePanel({ state, titleTag: 'h3' }));
    item.appendChild(createInlineState({ state }));
    showcase.appendChild(item);
  }

  return showcase;
}

/**
 * Панель прогресса длительной операции (indeterminate или determinate).
 * @param {{ mode?: 'indeterminate' | 'determinate', label?: string, elapsedMs?: number, expectedMs?: number, progress?: number }} [options]
 * @returns {HTMLElement & { update: (opts: object) => void }}
 */
export function createProgressPanel({
  mode = 'indeterminate',
  label = '',
  elapsedMs,
  expectedMs,
  progress,
} = {}) {
  const panel = document.createElement('div');
  panel.className = 'hub-progress-panel';

  const labelEl = document.createElement('p');
  labelEl.className = 'hub-progress-panel__label';
  labelEl.textContent = label;
  panel.appendChild(labelEl);

  const barTrack = document.createElement('div');
  barTrack.className = 'hub-progress-panel__bar';
  barTrack.setAttribute('role', 'progressbar');

  const barFill = document.createElement('div');
  barFill.className = 'hub-progress-panel__bar-fill';
  barTrack.appendChild(barFill);
  panel.appendChild(barTrack);

  const metaEl = document.createElement('p');
  metaEl.className = 'hub-progress-panel__meta';
  panel.appendChild(metaEl);

  let currentMode = mode;
  let currentProgress = progress;
  let currentElapsedMs = elapsedMs;
  let currentExpectedMs = expectedMs;

  /**
   * @param {{ mode?: string, label?: string, elapsedMs?: number, expectedMs?: number, progress?: number }} opts
   */
  function applyUpdate(opts = {}) {
    if (opts.mode === 'determinate' || opts.mode === 'indeterminate') {
      currentMode = opts.mode;
    }
    if (typeof opts.label === 'string') {
      labelEl.textContent = opts.label;
    }
    if (typeof opts.elapsedMs === 'number') {
      currentElapsedMs = opts.elapsedMs;
    }
    if (typeof opts.expectedMs === 'number') {
      currentExpectedMs = opts.expectedMs;
    }
    if (typeof opts.progress === 'number') {
      currentProgress = opts.progress;
    }

    panel.dataset.mode = currentMode;
    barTrack.dataset.mode = currentMode;

    if (currentMode === 'determinate' && typeof currentProgress === 'number') {
      const clamped = Math.min(1, Math.max(0, currentProgress));
      barFill.style.width = `${Math.round(clamped * 100)}%`;
      barTrack.setAttribute('aria-valuenow', String(Math.round(clamped * 100)));
      barTrack.setAttribute('aria-valuemin', '0');
      barTrack.setAttribute('aria-valuemax', '100');
    } else {
      barFill.style.width = '';
      barTrack.removeAttribute('aria-valuenow');
    }

    const metaParts = [];
    if (typeof currentElapsedMs === 'number') {
      metaParts.push(`Прошло: ${formatDurationMs(currentElapsedMs)}`);
    }
    if (typeof currentExpectedMs === 'number') {
      metaParts.push(`Ожидается: ${formatDurationMs(currentExpectedMs)}`);
    }
    metaEl.textContent = metaParts.join(' · ');
    metaEl.hidden = metaParts.length === 0;
  }

  panel.update = applyUpdate;
  applyUpdate({ mode, label, elapsedMs, expectedMs, progress });
  return /** @type {HTMLElement & { update: (opts: object) => void }} */ (panel);
}

/** @param {number} ms */
function formatDurationMs(ms) {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  if (min > 0) {
    return `${min}:${String(sec).padStart(2, '0')}`;
  }
  return `${sec} с`;
}

/** Создаёт иконку по дескриптору. */
function createIconForDescriptor(descriptor, inline = false) {
  const builder = ICON_BUILDERS[descriptor.iconName];
  const icon = builder ? builder() : createStaticIcon('');
  icon.classList.add(inline ? 'hub-state-icon--inline' : 'hub-state-icon');
  return icon;
}

/** Статичная SVG-иконка 24×24. */
function createStaticIcon(pathD) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '24');
  svg.setAttribute('height', '24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');

  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('fill', 'currentColor');
  path.setAttribute('d', pathD);
  svg.appendChild(path);
  return svg;
}

/** Анимированный спиннер (анимация только в CSS). */
function createSpinnerIcon() {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '24');
  svg.setAttribute('height', '24');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  svg.classList.add('hub-state-spinner');

  const circle = document.createElementNS(SVG_NS, 'circle');
  circle.setAttribute('cx', '12');
  circle.setAttribute('cy', '12');
  circle.setAttribute('r', '9');
  circle.setAttribute('fill', 'none');
  circle.setAttribute('stroke', 'currentColor');
  circle.setAttribute('stroke-width', '2.5');
  circle.setAttribute('stroke-linecap', 'round');
  circle.classList.add('hub-state-spinner__arc');
  svg.appendChild(circle);
  return svg;
}

/** Блок кнопок действий. */
function buildActions(action, secondaryAction) {
  if (!action && !secondaryAction) {
    return null;
  }

  const actions = document.createElement('div');
  actions.className = 'hub-state-panel__actions';

  if (action) {
    actions.appendChild(createActionButton(action, 'hub-state-action hub-state-action--primary'));
  }
  if (secondaryAction) {
    actions.appendChild(
      createActionButton(secondaryAction, 'hub-state-action hub-state-action--secondary'),
    );
  }
  return actions;
}

/** Кнопка действия. */
function createActionButton({ label, onActivate }, className) {
  const button = document.createElement('button');
  button.type = 'button';
  button.className = className;
  button.textContent = label;
  button.addEventListener('click', onActivate);
  return button;
}

/** Сворачиваемый блок технических подробностей. */
function buildDetails(details) {
  if (details == null || details === '') {
    return null;
  }

  const detailsEl = document.createElement('details');
  detailsEl.className = 'hub-state-panel__details';

  const summary = document.createElement('summary');
  summary.textContent = 'Технические подробности';
  detailsEl.appendChild(summary);

  const body = document.createElement('div');
  body.className = 'hub-state-panel__details-body';
  if (typeof details === 'string') {
    body.textContent = details;
  } else {
    body.appendChild(details);
  }
  detailsEl.appendChild(body);
  return detailsEl;
}
