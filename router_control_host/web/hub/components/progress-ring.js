/**
 * Compact circular progress indicator for overview readiness (N/4).
 */

/**
 * @param {{ value?: number|null, max?: number, label?: string, loading?: boolean }} options
 * @returns {HTMLElement}
 */
export function createProgressRing({ value = null, max = 4, label, loading = false } = {}) {
  const wrap = document.createElement('div');
  wrap.className = 'hub-progress-ring';

  const showSkeleton = loading || value == null;

  if (showSkeleton) {
    wrap.classList.add('hub-progress-ring--loading');
    wrap.setAttribute('aria-busy', 'true');
    wrap.setAttribute('aria-label', 'Загружаем готовность системы');

    const skeleton = document.createElement('div');
    skeleton.className = 'hub-progress-ring__skeleton';
    skeleton.setAttribute('aria-hidden', 'true');
    wrap.appendChild(skeleton);
    return wrap;
  }

  const safeMax = max > 0 ? max : 4;
  const safeValue = Math.max(0, Math.min(value, safeMax));
  const ratio = safeValue / safeMax;
  const radius = 20;
  const circumference = 2 * Math.PI * radius;
  const dashOffset = circumference * (1 - ratio);

  wrap.setAttribute('role', 'progressbar');
  wrap.setAttribute('aria-valuenow', String(safeValue));
  wrap.setAttribute('aria-valuemin', '0');
  wrap.setAttribute('aria-valuemax', String(safeMax));

  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  // SVGElement.className is a read-only SVGAnimatedString getter — must use setAttribute/classList, not assignment.
  svg.setAttribute('class', 'hub-progress-ring__svg');
  svg.setAttribute('viewBox', '0 0 48 48');
  svg.setAttribute('aria-hidden', 'true');

  const track = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  track.setAttribute('class', 'hub-progress-ring__track');
  track.setAttribute('cx', '24');
  track.setAttribute('cy', '24');
  track.setAttribute('r', String(radius));
  track.setAttribute('fill', 'none');

  const progress = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
  progress.setAttribute('class', 'hub-progress-ring__progress');
  progress.setAttribute('cx', '24');
  progress.setAttribute('cy', '24');
  progress.setAttribute('r', String(radius));
  progress.setAttribute('fill', 'none');
  progress.setAttribute('stroke-dasharray', String(circumference));
  progress.setAttribute('stroke-dashoffset', String(dashOffset));

  svg.appendChild(track);
  svg.appendChild(progress);
  wrap.appendChild(svg);

  const text = document.createElement('span');
  text.className = 'hub-progress-ring__label';
  text.textContent = label ?? `${safeValue}/${safeMax} готово`;
  wrap.appendChild(text);

  return wrap;
}

/**
 * Horizontal N-segment readiness bar (one segment per tracked category) —
 * more legible at a glance than a small ring, used on the Overview header.
 * @param {{
 *   categories?: Record<string, boolean>|null,
 *   order?: string[],
 *   value?: number|null,
 *   max?: number,
 *   label?: string,
 *   loading?: boolean,
 * }} options
 * @returns {HTMLElement}
 */
export function createReadinessSegmentBar({
  categories = null,
  order = ['router', 'internet', 'vpn', 'domain'],
  value = null,
  max = 4,
  label,
  loading = false,
} = {}) {
  const wrap = document.createElement('div');
  wrap.className = 'hub-readiness-bar';

  const safeMax = max > 0 ? max : order.length || 4;
  const showSkeleton = loading || value == null || !categories;

  const textEl = document.createElement('span');
  textEl.className = 'hub-readiness-bar__label';
  wrap.appendChild(textEl);

  const segmentsEl = document.createElement('div');
  segmentsEl.className = 'hub-readiness-bar__segments';
  segmentsEl.setAttribute('role', 'progressbar');
  segmentsEl.setAttribute('aria-valuemin', '0');
  segmentsEl.setAttribute('aria-valuemax', String(safeMax));
  wrap.appendChild(segmentsEl);

  if (showSkeleton) {
    wrap.classList.add('hub-readiness-bar--loading');
    wrap.setAttribute('aria-busy', 'true');
    textEl.textContent = 'Загружаем готовность…';
    segmentsEl.setAttribute('aria-valuenow', '0');
    for (let i = 0; i < safeMax; i += 1) {
      const seg = document.createElement('span');
      seg.className = 'hub-readiness-bar__segment hub-readiness-bar__segment--loading';
      seg.setAttribute('aria-hidden', 'true');
      segmentsEl.appendChild(seg);
    }
    return wrap;
  }

  const safeValue = Math.max(0, Math.min(value, safeMax));
  textEl.textContent = label ?? `${safeValue} из ${safeMax} готовы`;
  segmentsEl.setAttribute('aria-valuenow', String(safeValue));

  for (const key of order) {
    const seg = document.createElement('span');
    const ready = categories[key] === true;
    seg.className = `hub-readiness-bar__segment hub-readiness-bar__segment--${ready ? 'ready' : 'pending'}`;
    seg.setAttribute('aria-hidden', 'true');
    segmentsEl.appendChild(seg);
  }

  return wrap;
}
