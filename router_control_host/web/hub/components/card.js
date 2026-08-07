import { createIcon } from "./icon.js";

const VALID_TONES = new Set(["primary", "success", "warning", "danger", "neutral"]);

/**
 * @param {Node | string | null | undefined} nodeOrText
 * @returns {Node | null}
 */
function normalizeBody(nodeOrText) {
  if (nodeOrText == null) {
    return null;
  }
  if (typeof nodeOrText === "string") {
    const p = document.createElement("p");
    p.className = "hub-card__text";
    p.textContent = nodeOrText;
    return p;
  }
  return nodeOrText;
}

/**
 * @param {{ title?: string, subtitle?: string, actions?: HTMLElement[], body?: Node | string, footer?: Node | string, tone?: string, titleTag?: 'h2'|'h3'|'div' }} options
 * @returns {HTMLElement}
 */
export function createCard({ title, subtitle, actions = [], body, footer, tone, titleTag = 'h3' } = {}) {
  const card = document.createElement("article");
  card.className = "hub-card";
  if (tone && VALID_TONES.has(tone)) {
    card.classList.add(`hub-card--${tone}`);
  }

  if (title || subtitle || actions.length > 0) {
    const header = document.createElement("header");
    header.className = "hub-card__header";

    const headingWrap = document.createElement("div");
    headingWrap.className = "hub-card__heading";

    if (title) {
      const resolvedTitleTag = titleTag === 'div' ? 'div' : titleTag === 'h2' ? 'h2' : 'h3';
      const titleEl = document.createElement(resolvedTitleTag);
      titleEl.className = "hub-card__title";
      titleEl.textContent = title;
      headingWrap.appendChild(titleEl);
    }

    if (subtitle) {
      const subtitleEl = document.createElement("p");
      subtitleEl.className = "hub-card__subtitle";
      subtitleEl.textContent = subtitle;
      headingWrap.appendChild(subtitleEl);
    }

    header.appendChild(headingWrap);

    if (actions.length > 0) {
      const actionsEl = document.createElement("div");
      actionsEl.className = "hub-card__actions";
      for (const action of actions) {
        actionsEl.appendChild(action);
      }
      header.appendChild(actionsEl);
    }

    card.appendChild(header);
  }

  const bodyNode = normalizeBody(body);
  if (bodyNode) {
    const bodyEl = document.createElement("div");
    bodyEl.className = "hub-card__body";
    bodyEl.appendChild(bodyNode);
    card.appendChild(bodyEl);
  }

  const footerNode = normalizeBody(footer);
  if (footerNode) {
    const footerEl = document.createElement("footer");
    footerEl.className = "hub-card__footer";
    footerEl.appendChild(footerNode);
    card.appendChild(footerEl);
  }

  return card;
}

/**
 * @param {{ iconName?: string, title?: string, subtitle?: string, badge?: HTMLElement, metric?: string, actions?: HTMLElement[], footer?: Node | string, titleTag?: 'h2'|'h3'|'div' }} options
 * @returns {HTMLElement}
 */
export function createStatusCard({
  iconName,
  title,
  subtitle,
  badge,
  metric,
  actions = [],
  footer,
  titleTag = 'h3',
} = {}) {
  const card = document.createElement("article");
  card.className = "hub-card hub-status-card";

  const header = document.createElement("header");
  header.className = "hub-status-card__header";

  if (iconName) {
    const iconWrap = document.createElement("span");
    iconWrap.className = "hub-status-card__icon";
    iconWrap.appendChild(createIcon(iconName, { size: 24 }));
    header.appendChild(iconWrap);
  }

  const textWrap = document.createElement("div");
  textWrap.className = "hub-status-card__text";

  if (title) {
    const resolvedTitleTag = titleTag === 'div' ? 'div' : titleTag === 'h2' ? 'h2' : 'h3';
    const titleEl = document.createElement(resolvedTitleTag);
    titleEl.className = "hub-status-card__title";
    titleEl.textContent = title;
    textWrap.appendChild(titleEl);
  }

  if (subtitle) {
    const subtitleEl = document.createElement("p");
    subtitleEl.className = "hub-status-card__subtitle";
    subtitleEl.textContent = subtitle;
    textWrap.appendChild(subtitleEl);
  }

  header.appendChild(textWrap);

  if (badge) {
    header.appendChild(badge);
  }

  card.appendChild(header);

  if (metric) {
    const metricEl = document.createElement("p");
    metricEl.className = "hub-status-card__metric";
    metricEl.textContent = metric;
    card.appendChild(metricEl);
  }

  if (actions.length > 0) {
    const actionsEl = document.createElement("div");
    actionsEl.className = "hub-status-card__actions";
    for (const action of actions) {
      actionsEl.appendChild(action);
    }
    card.appendChild(actionsEl);
  }

  const footerNode = normalizeBody(footer);
  if (footerNode) {
    const footerEl = document.createElement("footer");
    footerEl.className = "hub-card__footer";
    footerEl.appendChild(footerNode);
    card.appendChild(footerEl);
  }

  return card;
}
