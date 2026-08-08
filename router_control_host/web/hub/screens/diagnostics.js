import {
  createButton,
  createCard,
  createTechnicalDetails,
} from '../components/index.js';
import { subscribeConnectivity } from '../core/api.js';
import { HubApiError, describeError } from '../core/errors.js';
import { getSession, subscribeSession } from '../core/session.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
} from '../core/states.js';
import {
  DIAGNOSTICS_GROUP_HOST,
  DIAGNOSTICS_GROUP_ROUTER,
  DIAGNOSTICS_GROUP_UNSUPPORTED,
  DOMAIN_HOST_PROBE_SCOPE_LABEL,
  READINESS_COUNTER_CAPTION,
  buildDiagnosticsExportReport,
  runDiagnosticsChecks,
  shouldAcceptDiagnosticsGeneration,
} from '../features/diagnostics-model.js';

export const meta = {
  id: 'diagnostics',
  title: 'Диагностика',
  iconName: 'diagnostics',
};

/** @typedef {import('../features/diagnostics-model.js').DiagnosticsSnapshot} DiagnosticsSnapshot */

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isClientAborted(err) {
  return err instanceof HubApiError && err.code === 'client.aborted';
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isAbortError(err) {
  return err instanceof DOMException && err.name === 'AbortError';
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isAborted(err) {
  return isClientAborted(err) || isAbortError(err);
}

/**
 * @param {Date|null|undefined} checkedAt
 * @param {{ stale?: boolean }} [options]
 * @returns {string|null}
 */
function formatLastCheckLine(checkedAt, options = {}) {
  if (!(checkedAt instanceof Date) || Number.isNaN(checkedAt.getTime())) {
    return null;
  }
  const time = checkedAt.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  if (options.stale) {
    return `Последняя успешная проверка: ${time} (данные устарели)`;
  }
  return `Последняя проверка: ${time}`;
}

/**
 * @param {import('../features/diagnostics-model.js').DiagnosticRow} row
 * @returns {HTMLElement}
 */
function createDiagnosticRow(row) {
  const wrap = document.createElement('div');
  wrap.className = 'hub-diagnostics__row';
  wrap.setAttribute('data-testid', `diagnostics-row-${row.id}`);
  wrap.appendChild(
    createInlineState({
      state: row.hubState,
      title: row.title,
      compact: false,
      fullWidth: true,
    }),
  );
  if (row.message) {
    const desc = document.createElement('p');
    desc.className = 'hub-diagnostics__row-desc';
    desc.textContent = row.message;
    wrap.appendChild(desc);
  }
  return wrap;
}

/**
 * @param {string} title
 * @param {import('../features/diagnostics-model.js').DiagnosticRow[]} rows
 * @param {string|null} [scopeLabel]
 * @returns {HTMLElement}
 */
function createDiagnosticsGroup(title, rows, scopeLabel) {
  const section = document.createElement('section');
  section.className = 'hub-diagnostics__group';

  const heading = document.createElement('h3');
  heading.className = 'hub-diagnostics__group-title';
  heading.textContent = title;
  section.appendChild(heading);

  if (scopeLabel) {
    const scope = document.createElement('p');
    scope.className = 'hub-diagnostics__group-scope';
    scope.textContent = scopeLabel;
    section.appendChild(scope);
  }

  const list = document.createElement('div');
  list.className = 'hub-diagnostics__row-list';
  for (const row of rows) {
    list.appendChild(createDiagnosticRow(row));
  }
  section.appendChild(list);
  return section;
}

/**
 * @param {string|null|undefined} [captionText]
 * @returns {HTMLElement}
 */
function createCounterCaptionElement(captionText) {
  const captionEl = document.createElement('p');
  captionEl.className = 'hub-diagnostics__summary-caption';
  captionEl.setAttribute('data-testid', 'diagnostics-counter-caption');
  captionEl.textContent = captionText ?? READINESS_COUNTER_CAPTION;
  return captionEl;
}

/**
 * @param {DiagnosticsSnapshot|null} snapshot
 * @returns {HTMLElement}
 */
function createSummaryBanner(snapshot) {
  const banner = document.createElement('div');
  banner.className = 'hub-diagnostics__summary';
  banner.setAttribute('data-testid', 'diagnostics-summary');

  const ringWrap = document.createElement('div');
  ringWrap.className = 'hub-diagnostics__ring-wrap';

  const ring = document.createElement('div');
  ring.className = 'hub-diagnostics__ring';
  if (snapshot?.bannerTone) {
    ring.classList.add(`hub-diagnostics__ring--${snapshot.bannerTone}`);
  }

  const counterEl = document.createElement('span');
  counterEl.className = 'hub-diagnostics__ring-counter';
  counterEl.setAttribute('data-testid', 'diagnostics-counter');
  counterEl.textContent = snapshot?.counter?.label ?? '—';
  ring.appendChild(counterEl);
  ringWrap.appendChild(ring);

  const textWrap = document.createElement('div');
  textWrap.className = 'hub-diagnostics__summary-text';

  const titleEl = document.createElement('p');
  titleEl.className = 'hub-diagnostics__summary-title';
  titleEl.setAttribute('data-testid', 'diagnostics-banner-title');
  titleEl.textContent = snapshot?.bannerTitle ?? 'Диагностика не запускалась';
  textWrap.appendChild(titleEl);

  if (snapshot?.bannerMessage) {
    const messageEl = document.createElement('p');
    messageEl.className = 'hub-diagnostics__summary-message';
    messageEl.textContent = snapshot.bannerMessage;
    textWrap.appendChild(messageEl);
  }

  textWrap.appendChild(
    createCounterCaptionElement(snapshot?.counter?.caption ?? READINESS_COUNTER_CAPTION),
  );

  banner.appendChild(ringWrap);
  banner.appendChild(textWrap);
  return banner;
}

/**
 * @param {DiagnosticsSnapshot|null} snapshot
 * @param {boolean} running
 * @returns {boolean}
 */
function canExportReport(snapshot, running) {
  return Boolean(!running && snapshot && snapshot.checkedAt instanceof Date);
}

/**
 * @param {DiagnosticsSnapshot} snapshot
 */
function downloadDiagnosticsReport(snapshot) {
  const report = buildDiagnosticsExportReport(snapshot);
  if (!report) {
    return;
  }
  const json = JSON.stringify(report, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'diagnostics-report.json';
  anchor.rel = 'noopener';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

/**
 * @param {import('../features/diagnostics-model.js').DiagnosticRow[]} rows
 * @returns {string}
 */
function rowsDigest(rows) {
  return rows
    .map((row) => `${row.id}|${row.provableState}|${row.hubState}|${row.message ?? ''}`)
    .join(';');
}

/**
 * @param {{ runtime: object, navigate: (routeId: string) => void, showToast: (options: object) => void }} ctx
 */
export function render(container, ctx) {
  const adapterMode = ctx?.runtime?.adapterMode ?? null;
  const navigate = typeof ctx?.navigate === 'function' ? ctx.navigate : () => {};

  let disposed = false;
  let offline = !globalThis.navigator?.onLine;
  let running = false;
  /** @type {DiagnosticsSnapshot|null} */
  let snapshot = null;
  /** @type {unknown|null} */
  let lastError = null;
  /** @type {AbortController|null} */
  let runAbort = null;
  let runGeneration = 0;

  let lastSummarySignature = null;
  let lastLeftColSignature = null;
  let lastRightColSignature = null;
  let lastManualSignature = null;
  let lastTechnicalSignature = null;
  /** @type {{ kind: string, id?: string }|null} */
  let pendingFocus = null;

  function hubContentEl() {
    return document.getElementById('hub-content');
  }

  function captureHubContentScroll() {
    const hubContent = hubContentEl();
    return hubContent instanceof HTMLElement ? hubContent.scrollTop : 0;
  }

  /**
   * @param {number} scrollTop
   */
  function restoreHubContentScroll(scrollTop) {
    const hubContent = hubContentEl();
    if (hubContent instanceof HTMLElement) {
      hubContent.scrollTop = scrollTop;
    }
  }

  function restorePendingFocus() {
    if (!pendingFocus) {
      return;
    }
    const target = pendingFocus;
    pendingFocus = null;
    if (target.kind === 'element-id' && target.id) {
      const el = document.getElementById(target.id);
      if (el instanceof HTMLElement) {
        el.focus();
      }
    }
  }

  function nodeWithinSlot(slot, node) {
    if (!(node instanceof HTMLElement)) {
      return false;
    }
    if (typeof slot.contains === 'function') {
      return slot.contains(node);
    }
    let current = /** @type {Node|null} */ (node);
    while (current) {
      if (current === slot) {
        return true;
      }
      current = current.parentElement ?? current.parentNode ?? null;
    }
    return false;
  }

  /**
   * @param {HTMLElement} slot
   * @param {() => void} rebuild
   */
  function rebuildSlot(slot, rebuild) {
    const scrollTop = captureHubContentScroll();
    const active = document.activeElement;
    if (active instanceof HTMLElement && nodeWithinSlot(slot, active)) {
      if (active.id) {
        pendingFocus = { kind: 'element-id', id: active.id };
      }
    }
    while (slot.firstChild) {
      slot.removeChild(slot.firstChild);
    }
    rebuild();
    restorePendingFocus();
    restoreHubContentScroll(scrollTop);
  }

  const screen = document.createElement('div');
  screen.className = 'hub-screen hub-diagnostics';

  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.textContent = 'Диагностика';
  screen.appendChild(title);

  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent = 'Проверка готовности системы перед мероприятием';
  screen.appendChild(subtitle);

  const headerActions = document.createElement('div');
  headerActions.className = 'hub-diagnostics__header-actions';

  const lastCheckEl = document.createElement('p');
  lastCheckEl.className = 'hub-diagnostics__last-check';
  lastCheckEl.setAttribute('data-testid', 'diagnostics-last-check');
  headerActions.appendChild(lastCheckEl);

  const rerunBtn = createButton({
    label: 'Проверить систему',
    variant: 'primary',
    id: 'hub-diagnostics-rerun-btn',
  });
  rerunBtn.addEventListener('click', () => {
    void startRun();
  });
  headerActions.appendChild(rerunBtn);
  screen.appendChild(headerActions);

  const summarySlot = document.createElement('div');
  summarySlot.className = 'hub-diagnostics__summary-slot';
  screen.appendChild(summarySlot);

  const columns = document.createElement('div');
  columns.className = 'hub-diagnostics__columns';
  const leftCol = document.createElement('div');
  leftCol.className = 'hub-diagnostics__column';
  const rightCol = document.createElement('div');
  rightCol.className = 'hub-diagnostics__column';
  columns.appendChild(leftCol);
  columns.appendChild(rightCol);
  screen.appendChild(columns);

  const manualCardSlot = document.createElement('div');
  manualCardSlot.className = 'hub-diagnostics__manual-slot';
  screen.appendChild(manualCardSlot);

  const technicalSlot = document.createElement('div');
  technicalSlot.className = 'hub-diagnostics__technical-slot';
  screen.appendChild(technicalSlot);

  container.appendChild(screen);

  function syncHeaderInPlace() {
    rerunBtn.disabled = running || offline;
    rerunBtn.setAttribute('aria-busy', running ? 'true' : 'false');
    rerunBtn.textContent = running ? 'Проверка…' : 'Проверить систему';

    const snapshotStale = Boolean(lastError && snapshot);
    const lastCheckText = formatLastCheckLine(snapshot?.checkedAt ?? null, { stale: snapshotStale });
    lastCheckEl.textContent = lastCheckText ?? '';
    lastCheckEl.hidden = !lastCheckText;
  }

  function buildSummarySignature() {
    if (running && !snapshot) {
      return 'cold-loading';
    }
    if (running && snapshot) {
      return `running-stale|${rowsDigest(snapshot.rows ?? [])}|${snapshot.bannerTone ?? ''}`;
    }
    if (lastError && !snapshot) {
      return `error-empty|${describeError(lastError).title}`;
    }
    if (lastError && snapshot) {
      return `error-stale|${describeError(lastError).title}|${snapshot.bannerTone}|${snapshot.counter?.label ?? ''}`;
    }
    if (!snapshot) {
      return 'idle-empty';
    }
    return [
      snapshot.bannerTone,
      snapshot.bannerTitle,
      snapshot.bannerMessage ?? '',
      snapshot.counter?.label ?? '',
      snapshot.counter?.caption ?? '',
    ].join('|');
  }

  function renderSummarySlot() {
    const signature = buildSummarySignature();
    if (signature === lastSummarySignature && summarySlot.firstChild) {
      return;
    }
    lastSummarySignature = signature;
    rebuildSlot(summarySlot, () => {
      if (running && !snapshot) {
        summarySlot.appendChild(createSkeleton({ lines: 2 }));
        summarySlot.appendChild(createCounterCaptionElement(READINESS_COUNTER_CAPTION));
        return;
      }

      if (running && snapshot) {
        summarySlot.appendChild(createSkeleton({ lines: 2 }));
        summarySlot.appendChild(createCounterCaptionElement(READINESS_COUNTER_CAPTION));
        return;
      }

      if (lastError && !snapshot) {
        const described = describeError(lastError);
        summarySlot.appendChild(
          createStatePanel({
            state: HubState.ERROR,
            title: described.title,
            description: described.message,
          }),
        );
        summarySlot.appendChild(createCounterCaptionElement(READINESS_COUNTER_CAPTION));
        return;
      }

      if (lastError && snapshot) {
        const described = describeError(lastError);
        summarySlot.appendChild(
          createStatePanel({
            state: HubState.ERROR,
            title: described.title,
            description: `${described.message} Ниже показан результат предыдущей успешной проверки.`,
          }),
        );
        summarySlot.appendChild(
          createCounterCaptionElement(snapshot?.counter?.caption ?? READINESS_COUNTER_CAPTION),
        );
        return;
      }

      summarySlot.appendChild(createSummaryBanner(snapshot));
    });
  }

  function renderLeftColSlot() {
    if (running && !snapshot) {
      const signature = 'cold-loading';
      if (signature === lastLeftColSignature && leftCol.firstChild) {
        return;
      }
      lastLeftColSignature = signature;
      rebuildSlot(leftCol, () => {
        leftCol.appendChild(createSkeleton({ lines: 5 }));
      });
      return;
    }

    if (running && snapshot) {
      const signature = `running-stale|${rowsDigest(snapshot.rows ?? [])}`;
      if (signature === lastLeftColSignature && leftCol.firstChild) {
        return;
      }
      lastLeftColSignature = signature;
      rebuildSlot(leftCol, () => {
        leftCol.appendChild(createSkeleton({ lines: 5 }));
      });
      return;
    }

    const rows = snapshot?.rows ?? [];
    const routerRows = rows.filter((row) => row.group === DIAGNOSTICS_GROUP_ROUTER);
    const unsupportedRows = rows.filter((row) => row.group === DIAGNOSTICS_GROUP_UNSUPPORTED);
    const signature = `${rowsDigest(routerRows)}|${rowsDigest(unsupportedRows)}`;
    if (signature === lastLeftColSignature && leftCol.firstChild) {
      return;
    }
    lastLeftColSignature = signature;
    rebuildSlot(leftCol, () => {
      leftCol.appendChild(createDiagnosticsGroup('Роутер и сети', routerRows));
      if (unsupportedRows.length > 0) {
        const unsupportedWrap = document.createElement('div');
        unsupportedWrap.className = 'hub-diagnostics__unsupported-wrap';
        unsupportedWrap.appendChild(createDiagnosticsGroup('Пока не поддерживается', unsupportedRows));
        leftCol.appendChild(unsupportedWrap);
      }
    });
  }

  function renderRightColSlot() {
    if (running && !snapshot) {
      const signature = 'cold-loading';
      if (signature === lastRightColSignature && rightCol.firstChild) {
        return;
      }
      lastRightColSignature = signature;
      rebuildSlot(rightCol, () => {
        rightCol.appendChild(createSkeleton({ lines: 4 }));
      });
      return;
    }

    if (running && snapshot) {
      const signature = `running-stale|${rowsDigest(snapshot.rows ?? [])}`;
      if (signature === lastRightColSignature && rightCol.firstChild) {
        return;
      }
      lastRightColSignature = signature;
      rebuildSlot(rightCol, () => {
        rightCol.appendChild(createSkeleton({ lines: 4 }));
      });
      return;
    }

    const rows = snapshot?.rows ?? [];
    const hostRows = rows.filter((row) => row.group === DIAGNOSTICS_GROUP_HOST);
    const signature = rowsDigest(hostRows);
    if (signature === lastRightColSignature && rightCol.firstChild) {
      return;
    }
    lastRightColSignature = signature;
    rebuildSlot(rightCol, () => {
      rightCol.appendChild(
        createDiagnosticsGroup('Проверено с компьютера оператора', hostRows, DOMAIN_HOST_PROBE_SCOPE_LABEL),
      );
    });
  }

  function renderManualSlot() {
    const exportAllowed = canExportReport(snapshot, running);
    const signature = exportAllowed ? 'export-on' : 'export-off';
    if (signature === lastManualSignature && manualCardSlot.firstChild) {
      return;
    }
    lastManualSignature = signature;
    rebuildSlot(manualCardSlot, () => {
      /** @type {HTMLElement[]} */
      const manualActions = [];

      const openGuestBtn = createButton({
        label: 'Открыть страницу гостя',
        variant: 'secondary',
      });
      openGuestBtn.addEventListener('click', () => navigate('entry-pages'));
      manualActions.push(openGuestBtn);

      const qrBtn = createButton({
        label: 'Проверить QR-код',
        variant: 'secondary',
      });
      qrBtn.addEventListener('click', () => navigate('entry-pages'));
      manualActions.push(qrBtn);

      if (exportAllowed && snapshot) {
        const exportBtn = createButton({
          label: 'Экспортировать отчёт',
          variant: 'secondary',
          id: 'hub-diagnostics-export-btn',
        });
        exportBtn.addEventListener('click', () => {
          downloadDiagnosticsReport(snapshot);
        });
        manualActions.push(exportBtn);
        manualCardSlot.appendChild(
          createCard({
            title: 'Что можно проверить вручную',
            actions: manualActions,
          }),
        );
        return;
      }

      const exportNote = document.createElement('p');
      exportNote.className = 'hub-diagnostics__manual-note';
      exportNote.textContent =
        'Экспорт отчёта станет доступен после первой завершённой проверки.';
      manualCardSlot.appendChild(
        createCard({
          title: 'Что можно проверить вручную',
          body: exportNote,
          actions: manualActions,
        }),
      );
    });
  }

  function renderTechnicalSlot() {
    const lines = snapshot?.technicalLines ?? [];
    const signature = lines.join('\n');
    if (signature === lastTechnicalSignature && (technicalSlot.firstChild || !signature)) {
      return;
    }
    lastTechnicalSignature = signature;
    rebuildSlot(technicalSlot, () => {
      if (lines.length > 0) {
        technicalSlot.appendChild(
          createTechnicalDetails({
            summary: 'Технический журнал',
            content: lines.join('\n'),
            id: 'hub-diagnostics-technical',
          }),
        );
      }
    });
  }

  function renderAll() {
    syncHeaderInPlace();
    renderSummarySlot();
    renderLeftColSlot();
    renderRightColSlot();
    renderManualSlot();
    renderTechnicalSlot();
  }

  async function startRun() {
    if (disposed || offline) {
      return;
    }
    runAbort?.abort();
    runAbort = new AbortController();
    const myGeneration = ++runGeneration;
    running = true;
    lastError = null;
    renderAll();

    const session = getSession();
    try {
      const result = await runDiagnosticsChecks({
        session,
        adapterMode,
        hostKeyConfirmed: session.hostKeyConfirmed,
        routerPresent: session.routerId != null ? true : false,
        routerId: session.routerId,
        signal: runAbort.signal,
        generation: myGeneration,
        isGenerationCurrent: (gen) =>
          !disposed && shouldAcceptDiagnosticsGeneration(gen, runGeneration),
        onProgress: (partial) => {
          if (disposed || !shouldAcceptDiagnosticsGeneration(myGeneration, runGeneration)) {
            return;
          }
          snapshot = partial;
          renderAll();
        },
      });
      if (disposed || !shouldAcceptDiagnosticsGeneration(myGeneration, runGeneration)) {
        return;
      }
      snapshot = result;
      running = false;
      renderAll();
    } catch (err) {
      if (disposed) {
        running = false;
        return;
      }
      if (isAborted(err) || !shouldAcceptDiagnosticsGeneration(myGeneration, runGeneration)) {
        // Newer run owns `running` — do not clear it.
        return;
      }
      lastError = err;
      running = false;
      renderAll();
    }
  }

  const unsubSession = subscribeSession(() => {
    if (!disposed && !running) {
      renderAll();
    }
  });

  const unsubConnectivity = subscribeConnectivity((online) => {
    offline = !online;
    if (!online) {
      runAbort?.abort();
      runGeneration += 1;
      running = false;
    }
    renderAll();
  });

  renderAll();
  void startRun();

  return () => {
    disposed = true;
    runGeneration += 1;
    runAbort?.abort();
    unsubSession();
    unsubConnectivity();
    while (container.firstChild) {
      container.removeChild(container.firstChild);
    }
  };
}
