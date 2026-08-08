import {
  createBadge,
  createButton,
  createCard,
  createSegmented,
  createSelectField,
  createTextField,
  createToggle,
} from '../components/index.js';
import { subscribeConnectivity } from '../core/api.js';
import { HubApiError, ERROR_KIND, describeError } from '../core/errors.js';
import {
  HubState,
  createInlineState,
  createSkeleton,
  createStatePanel,
} from '../core/states.js';
import { DOMAIN_HOST_PROBE_SCOPE_LABEL } from '../features/domain-model.js';
import {
  ENTRY_AUDIENCE_GUEST,
  ENTRY_AUDIENCE_LABELS,
  ENTRY_AUDIENCE_STAFF,
  ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE,
  ENTRY_FIELD_KIND_OPTIONS,
  ENTRY_LOGO_UNSUPPORTED_NOTE,
  ENTRY_MAX_FIELDS,
  ENTRY_MAX_ROLES,
  ENTRY_MAX_SELECT_OPTIONS,
  ENTRY_PAGE_NOT_WIFI_BOUND_NOTE,
  ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE,
  ENTRY_PUBLIC_ADDRESS_UNVERIFIED_NOTE,
  ENTRY_PUBLIC_LISTENER_INSTRUCTION,
  baselineDocumentFromDetail,
  buildDraftPreviewPath,
  buildPublicEntryUrl,
  deriveFieldName,
  describePublicationStatus,
  ensureEntryPage,
  entryDocumentsEqual,
  findPageByAudience,
  getEntryPageDetail,
  listEntryPages,
  parseSelfCheckResult,
  publishEntryPage,
  resolveEditorDocument,
  saveEntryPageDraft,
  selfCheckEntryPage,
  syncFieldNames,
  unpublishEntryPage,
  validateEntryDocument,
  validatePublicEntryAddress,
} from '../features/entry-pages-model.js';
import { drawWifiQrCanvas } from '../features/wifi-qr.js';

export const meta = {
  id: 'entry-pages',
  title: 'Страницы входа',
  iconName: 'entry-pages',
};

/**
 * @param {{ message: string, action: string|null }} described
 * @returns {string}
 */
function formatErrorDescription(described) {
  if (described.action) {
    return `${described.message} ${described.action}`;
  }
  return described.message;
}

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
 * @param {unknown} err
 * @returns {string}
 */
function hubStateForError(err) {
  const described = describeError(err);
  switch (described.kind) {
    case ERROR_KIND.NETWORK:
    case ERROR_KIND.TIMEOUT:
      return HubState.CONNECTION_LOST;
    case ERROR_KIND.FORBIDDEN:
    case ERROR_KIND.UNAUTHORIZED:
      return HubState.FORBIDDEN;
    case ERROR_KIND.UNSUPPORTED:
      return HubState.UNSUPPORTED;
    default:
      return HubState.ERROR;
  }
}

/**
 * @param {{ state: string, title: string, description?: string, testId?: string }} options
 * @returns {HTMLElement}
 */
function createCheckRow({ state, title, description, testId }) {
  const wrap = document.createElement('div');
  wrap.className = 'hub-entry-pages__check-row';
  if (testId) {
    wrap.setAttribute('data-testid', testId);
  }
  wrap.appendChild(createInlineState({ state, title, compact: false, fullWidth: true }));
  if (description) {
    const desc = document.createElement('p');
    desc.className = 'hub-entry-pages__check-desc';
    desc.textContent = description;
    wrap.appendChild(desc);
  }
  return wrap;
}

/**
 * @param {HTMLElement} parent
 * @param {Record<string, unknown>} draftDoc
 * @param {'guest'|'staff'} audience
 */
function renderPreviewDocument(parent, draftDoc, audience) {
  while (parent.firstChild) {
    parent.removeChild(parent.firstChild);
  }

  const title = String(draftDoc.title ?? '').trim();
  const intro = String(draftDoc.intro ?? '').trim();
  const buttonLabel = String(draftDoc.button_label ?? '').trim();

  const heading = document.createElement('h2');
  heading.className = 'hub-entry-pages__preview-title';
  heading.textContent = title || 'Заголовок не задан';
  parent.appendChild(heading);

  if (intro) {
    const introEl = document.createElement('p');
    introEl.className = 'hub-entry-pages__preview-intro';
    introEl.textContent = intro;
    parent.appendChild(introEl);
  }

  const fields = Array.isArray(draftDoc.fields) ? draftDoc.fields : [];
  if (draftDoc.submissions_enabled === true && fields.length > 0) {
    const form = document.createElement('div');
    form.className = 'hub-entry-pages__preview-form';
    if (audience === ENTRY_AUDIENCE_STAFF) {
      const roles = Array.isArray(draftDoc.roles) ? draftDoc.roles : [];
      if (roles.length > 0) {
        const roleLabel = document.createElement('span');
        roleLabel.className = 'hub-entry-pages__preview-field-label';
        roleLabel.textContent = `Роль (${String(roles[0])})`;
        form.appendChild(roleLabel);
      }
    }
    for (const field of fields) {
      if (!field || typeof field !== 'object') {
        continue;
      }
      const label = document.createElement('span');
      label.className = 'hub-entry-pages__preview-field-label';
      const fieldLabel = String(field.label ?? field.name ?? 'Поле');
      const kind = String(field.kind ?? 'text');
      if (kind === 'select' && Array.isArray(field.options) && field.options.length > 0) {
        label.textContent = `${fieldLabel} (${field.options.join(', ')})`;
      } else {
        label.textContent = fieldLabel;
      }
      form.appendChild(label);
    }
    const button = document.createElement('span');
    button.className = 'hub-entry-pages__preview-button';
    button.textContent = buttonLabel || 'Кнопка';
    form.appendChild(button);
    parent.appendChild(form);
  } else if (draftDoc.submissions_enabled === true) {
    const note = document.createElement('p');
    note.className = 'hub-entry-pages__preview-note';
    note.textContent = 'Форма без полей — добавьте поля в редакторе.';
    parent.appendChild(note);
  }

  if (!title && !intro && !buttonLabel) {
    const empty = document.createElement('p');
    empty.className = 'hub-entry-pages__preview-note';
    empty.textContent = 'Заполните черновик слева — здесь появится предпросмотр.';
    parent.appendChild(empty);
  }
}

/**
 * @param {Record<string, unknown>} document
 * @returns {Record<string, unknown>}
 */
function cloneDraftDocument(document) {
  return /** @type {Record<string, unknown>} */ (JSON.parse(JSON.stringify(document)));
}

/**
 * @param {HTMLElement} parent
 * @param {Record<string, unknown>} draftDoc
 * @param {'guest'|'staff'} audience
 * @param {() => void} markDirty
 * @param {() => void} repaint
 */
function renderFieldsEditor(parent, draftDoc, audience, markDirty, repaint) {
  const section = document.createElement('div');
  section.className = 'hub-entry-pages__fields-editor';
  section.setAttribute('data-testid', 'entry-fields-editor');

  const heading = document.createElement('h3');
  heading.className = 'hub-entry-pages__editor-subtitle';
  heading.textContent = 'Поля формы';
  section.appendChild(heading);

  if (!Array.isArray(draftDoc.fields)) {
    draftDoc.fields = [];
  }
  const fields = /** @type {Array<Record<string, unknown>>} */ (draftDoc.fields);

  fields.forEach((field, index) => {
    const row = document.createElement('div');
    row.className = 'hub-entry-pages__field-row';
    row.setAttribute('data-testid', `entry-field-row-${index}`);

    row.appendChild(
      createTextField({
        id: `hub-entry-pages-field-label-${index}`,
        label: `Поле ${index + 1}: подпись`,
        value: String(field.label ?? ''),
        onInput: (event) => {
          field.label = event.target.value;
          syncFieldNames(draftDoc);
          markDirty();
        },
      }),
    );

    row.appendChild(
      createSelectField({
        id: `hub-entry-pages-field-kind-${index}`,
        label: 'Тип',
        value: String(field.kind ?? 'text'),
        options: ENTRY_FIELD_KIND_OPTIONS.map((opt) => ({ value: opt.value, label: opt.label })),
        onChange: (event) => {
          field.kind = event.target.value;
          if (field.kind !== 'select') {
            delete field.options;
          } else if (!Array.isArray(field.options)) {
            field.options = [''];
          }
          markDirty();
          repaint();
        },
      }),
    );

    if (field.kind === 'select') {
      const optionsRaw = Array.isArray(field.options) ? field.options.join('\n') : '';
      row.appendChild(
        createTextField({
          id: `hub-entry-pages-field-options-${index}`,
          label: 'Варианты (по одному в строке, до 12)',
          value: optionsRaw,
          onInput: (event) => {
            const lines = String(event.target.value ?? '')
              .split('\n')
              .map((line) => line.trim())
              .filter((line) => line.length > 0)
              .slice(0, ENTRY_MAX_SELECT_OPTIONS);
            field.options = lines;
            markDirty();
          },
        }),
      );
    }

    row.appendChild(
      createToggle({
        id: `hub-entry-pages-field-required-${index}`,
        label: 'Обязательное',
        checked: field.required === true,
        onChange: (checked) => {
          field.required = checked;
          markDirty();
        },
      }),
    );

    const actions = document.createElement('div');
    actions.className = 'hub-entry-pages__field-actions';

    if (index > 0) {
      actions.appendChild(
        createButton({
          label: 'Выше',
          variant: 'ghost',
          onActivate: () => {
            const prev = fields[index - 1];
            fields[index - 1] = fields[index];
            fields[index] = prev;
            syncFieldNames(draftDoc);
            markDirty();
            repaint();
          },
        }),
      );
    }
    if (index < fields.length - 1) {
      actions.appendChild(
        createButton({
          label: 'Ниже',
          variant: 'ghost',
          onActivate: () => {
            const next = fields[index + 1];
            fields[index + 1] = fields[index];
            fields[index] = next;
            syncFieldNames(draftDoc);
            markDirty();
            repaint();
          },
        }),
      );
    }
    actions.appendChild(
      (() => {
        const btn = createButton({
          label: 'Удалить',
          variant: 'ghost',
          onActivate: () => {
            fields.splice(index, 1);
            syncFieldNames(draftDoc);
            markDirty();
            repaint();
          },
        });
        btn.setAttribute('data-testid', `entry-field-remove-${index}`);
        return btn;
      })(),
    );
    row.appendChild(actions);
    section.appendChild(row);
  });

  section.appendChild(
    (() => {
      const btn = createButton({
        label: 'Добавить поле',
        variant: 'secondary',
        disabled: fields.length >= ENTRY_MAX_FIELDS,
        onActivate: () => {
          if (fields.length >= ENTRY_MAX_FIELDS) {
            return;
          }
          const taken = new Set(fields.map((item) => String(item.name ?? '')));
          const nextIndex = fields.length;
          fields.push({
            label: '',
            kind: 'text',
            required: false,
            name: deriveFieldName('', taken, nextIndex),
          });
          markDirty();
          repaint();
        },
      });
      btn.setAttribute('data-testid', 'entry-add-field-btn');
      return btn;
    })(),
  );

  if (audience === ENTRY_AUDIENCE_GUEST && 'roles' in draftDoc) {
    delete draftDoc.roles;
  }

  parent.appendChild(section);
}

/**
 * @param {HTMLElement} parent
 * @param {Record<string, unknown>} draftDoc
 * @param {() => void} markDirty
 * @param {() => void} repaint
 */
function renderRolesEditor(parent, draftDoc, markDirty, repaint) {
  const section = document.createElement('div');
  section.className = 'hub-entry-pages__roles-editor';
  section.setAttribute('data-testid', 'entry-roles-editor');

  const heading = document.createElement('h3');
  heading.className = 'hub-entry-pages__editor-subtitle';
  heading.textContent = 'Роли персонала';
  section.appendChild(heading);

  if (!Array.isArray(draftDoc.roles)) {
    draftDoc.roles = ['Сотрудник'];
  }
  const roles = /** @type {string[]} */ (draftDoc.roles);

  roles.forEach((role, index) => {
    const row = document.createElement('div');
    row.className = 'hub-entry-pages__role-row';
    row.setAttribute('data-testid', `entry-role-row-${index}`);

    row.appendChild(
      createTextField({
        id: `hub-entry-pages-role-${index}`,
        label: `Роль ${index + 1}`,
        value: String(role ?? ''),
        onInput: (event) => {
          roles[index] = event.target.value;
          markDirty();
        },
      }),
    );

    const actions = document.createElement('div');
    actions.className = 'hub-entry-pages__role-actions';
    actions.appendChild(
      createButton({
        label: 'Удалить',
        variant: 'ghost',
        disabled: roles.length <= 1,
        onActivate: () => {
          if (roles.length <= 1) {
            return;
          }
          roles.splice(index, 1);
          markDirty();
          repaint();
        },
      }),
    );
    row.appendChild(actions);
    section.appendChild(row);
  });

  section.appendChild(
    (() => {
      const btn = createButton({
        label: 'Добавить роль',
        variant: 'secondary',
        disabled: roles.length >= ENTRY_MAX_ROLES,
        onActivate: () => {
          if (roles.length >= ENTRY_MAX_ROLES) {
            return;
          }
          roles.push('');
          markDirty();
          repaint();
        },
      });
      btn.setAttribute('data-testid', 'entry-add-role-btn');
      return btn;
    })(),
  );

  parent.appendChild(section);
}

/**
 * @param {HTMLElement} container
 * @param {{ runtime: object, navigate: (routeId: string) => void, showToast: (options: object) => void }} ctx
 * @returns {() => void}
 */
export function render(container, ctx) {
  while (container.firstChild) {
    container.removeChild(container.firstChild);
  }

  const adapterMode = ctx.runtime?.adapterMode ?? null;
  let generation = 0;
  let detailGeneration = 0;
  let disposed = false;
  let offline = typeof navigator !== 'undefined' ? !navigator.onLine : false;

  /** @type {AbortController|null} */
  let listAbort = null;
  /** @type {AbortController|null} */
  let detailAbort = null;
  /** @type {AbortController|null} */
  let saveAbort = null;
  /** @type {AbortController|null} */
  let publishAbort = null;
  /** @type {AbortController|null} */
  let selfCheckAbort = null;

  let listLoading = true;
  let listRefreshing = false;
  /** @type {unknown|null} */
  let listError = null;
  /** @type {Array<Record<string, unknown>>} */
  let listItems = [];

  let detailLoading = false;
  let detailRefreshing = false;
  /** @type {unknown|null} */
  let detailError = null;
  /** @type {Record<string, unknown>|null} */
  let pageDetail = null;

  /** @type {'guest'|'staff'} */
  let activeAudience = ENTRY_AUDIENCE_GUEST;
  /** @type {Record<string, unknown>} */
  let draftDocument = resolveEditorDocument(null, ENTRY_AUDIENCE_GUEST);
  /** @type {Record<string, unknown>|null} */
  let savedBaseline = null;

  /** @type {Map<'guest'|'staff', { draft: Record<string, unknown>, baseline: Record<string, unknown>|null }>} */
  const audienceDraftCache = new Map();

  let previewFrameMode = 'phone';
  let publicHostAddress = '';
  let initializing = false;

  /** @type {ReturnType<typeof setTimeout>|null} */
  let addressPaintTimer = null;
  /** @type {string|null} */
  let lastQrEncodedPayload = null;
  /** @type {HTMLCanvasElement|null} */
  let qrCanvasEl = null;
  const ADDRESS_INPUT_DEBOUNCE_MS = 300;

  let saving = false;
  /** @type {unknown|null} */
  let saveError = null;

  let publishing = false;
  /** @type {unknown|null} */
  let publishError = null;

  let selfChecking = false;
  /** @type {unknown|null} */
  let selfCheckError = null;
  /** @type {ReturnType<typeof parseSelfCheckResult>|null} */
  let selfCheckResult = null;

  let layoutMounted = false;
  let hasLoadedListOnce = false;
  let hasLoadedDetailOnce = false;
  /** @type {string|null} */
  let lastTabsSignature = null;
  /** @type {string|null} */
  let lastStateSignature = null;
  /** @type {string|null} */
  let lastEditorSignature = null;
  /** @type {string|null} */
  let lastPreviewSignature = null;
  /** @type {string|null} */
  let lastInfoSignature = null;
  /** @type {string|null} */
  let lastStaffSignature = null;
  /** @type {{ kind: string, id?: string }|null} */
  let pendingFocus = null;

  const bannerSlot = document.createElement('div');
  bannerSlot.className = 'hub-entry-pages__banner-slot';
  const stateSlot = document.createElement('div');
  stateSlot.className = 'hub-entry-pages__state-slot';
  const refreshSlot = document.createElement('div');
  refreshSlot.className = 'hub-entry-pages__refresh-slot';
  const layoutMain = document.createElement('div');
  layoutMain.className = 'hub-wifi__layout-main hub-entry-pages__layout-main';
  const layoutSide = document.createElement('div');
  layoutSide.className = 'hub-wifi__layout-side hub-entry-pages__layout-side';
  const infoStrip = document.createElement('section');
  infoStrip.className = 'hub-entry-pages__info-strip';
  const staffBlock = document.createElement('section');
  staffBlock.className = 'hub-entry-pages__staff-block';

  const screen = document.createElement('section');
  screen.className = 'hub-screen hub-entry-pages';

  const header = document.createElement('header');
  header.className = 'hub-screen__header';
  const title = document.createElement('h1');
  title.className = 'hub-screen__title';
  title.id = 'hub-entry-pages-screen-title';
  title.tabIndex = -1;
  title.textContent = 'Страницы входа';
  header.appendChild(title);
  const subtitle = document.createElement('p');
  subtitle.className = 'hub-screen__subtitle';
  subtitle.textContent = 'Куда попадут гости и сотрудники после подключения';
  header.appendChild(subtitle);
  screen.appendChild(header);

  const tabsHost = document.createElement('div');
  tabsHost.className = 'hub-entry-pages__tabs';
  screen.appendChild(tabsHost);

  const contentWrap = document.createElement('div');
  contentWrap.className = 'hub-entry-pages__content hub-wifi__content';
  screen.appendChild(contentWrap);

  const footer = document.createElement('footer');
  footer.className = 'hub-entry-pages__footer hub-wifi__footer';
  const footerLeft = document.createElement('div');
  footerLeft.className = 'hub-wifi__footer-left';
  const footerRight = document.createElement('div');
  footerRight.className = 'hub-wifi__footer-right';
  footer.appendChild(footerLeft);
  footer.appendChild(footerRight);
  screen.appendChild(footer);

  container.appendChild(screen);

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

  function mountLayoutOnce() {
    if (layoutMounted) {
      return;
    }
    layoutMounted = true;
    contentWrap.appendChild(bannerSlot);
    contentWrap.appendChild(stateSlot);
    contentWrap.appendChild(refreshSlot);
    contentWrap.appendChild(layoutMain);
    contentWrap.appendChild(layoutSide);
    contentWrap.appendChild(infoStrip);
    contentWrap.appendChild(staffBlock);
  }

  function editorMounted() {
    return layoutMounted && layoutMain.querySelector('#hub-entry-pages-title') instanceof HTMLElement;
  }

  function clearElement(el) {
    while (el.firstChild) {
      el.removeChild(el.firstChild);
    }
  }

  function activeSummary() {
    return findPageByAudience(listItems, activeAudience);
  }

  function activePageId() {
    const summary = activeSummary();
    return summary?.page_id ? String(summary.page_id) : null;
  }

  function draftDirty() {
    if (!savedBaseline) {
      syncFieldNames(draftDocument);
      const validation = validateEntryDocument(draftDocument, activeAudience);
      return validation.valid;
    }
    syncFieldNames(draftDocument);
    return !entryDocumentsEqual(draftDocument, savedBaseline);
  }

  function cacheCurrentAudienceDraft() {
    if (!activePageId() || detailLoading) {
      return;
    }
    syncFieldNames(draftDocument);
    audienceDraftCache.set(activeAudience, {
      draft: cloneDraftDocument(draftDocument),
      baseline: savedBaseline ? cloneDraftDocument(savedBaseline) : null,
    });
  }

  /**
   * @param {'guest'|'staff'} audience
   * @returns {boolean}
   */
  function restoreAudienceDraft(audience) {
    const cached = audienceDraftCache.get(audience);
    if (!cached) {
      return false;
    }
    draftDocument = cloneDraftDocument(cached.draft);
    savedBaseline = cached.baseline ? cloneDraftDocument(cached.baseline) : null;
    return true;
  }

  function applyDetailFromServer(detail, audience) {
    draftDocument = resolveEditorDocument(detail, audience);
    savedBaseline = baselineDocumentFromDetail(detail);
    audienceDraftCache.set(audience, {
      draft: cloneDraftDocument(draftDocument),
      baseline: savedBaseline ? cloneDraftDocument(savedBaseline) : null,
    });
  }

  function currentValidation() {
    syncFieldNames(draftDocument);
    return validateEntryDocument(draftDocument, activeAudience);
  }

  function canSaveDraft() {
    if (offline || saving || listLoading || detailLoading || initializing) {
      return false;
    }
    if (!draftDirty()) {
      return false;
    }
    return currentValidation().valid;
  }

  function publicationStatusForSummary(summary) {
    return describePublicationStatus(summary);
  }

  function staffSummary() {
    return findPageByAudience(listItems, ENTRY_AUDIENCE_STAFF);
  }

  async function loadList(options = {}) {
    const { soft = false } = options;
    const gen = ++generation;
    listAbort?.abort();
    listAbort = new AbortController();
    if (soft && hasLoadedListOnce) {
      listRefreshing = true;
      listLoading = false;
    } else if (!hasLoadedListOnce) {
      listLoading = true;
      listRefreshing = false;
    }
    listError = null;
    paint();

    try {
      const payload = await listEntryPages({ signal: listAbort.signal });
      if (disposed || gen !== generation) {
        return;
      }
      listItems = Array.isArray(payload?.items) ? payload.items : [];
      listLoading = false;
      listRefreshing = false;
      hasLoadedListOnce = true;
      await loadActiveDetail(gen, { soft });
    } catch (err) {
      if (isAborted(err)) {
        return;
      }
      if (disposed || gen !== generation) {
        return;
      }
      listLoading = false;
      listRefreshing = false;
      listError = err;
      paint();
    }
  }

  async function loadActiveDetail(expectedGen, options = {}) {
    const { forceApply = false, soft = false } = options;
    const pageId = activePageId();
    if (!pageId) {
      detailLoading = false;
      detailRefreshing = false;
      detailError = null;
      pageDetail = null;
      if (!restoreAudienceDraft(activeAudience)) {
        draftDocument = resolveEditorDocument(null, activeAudience);
        savedBaseline = null;
      }
      paint();
      return;
    }

    const hadDirtyDraft = draftDirty();
    if (hadDirtyDraft) {
      cacheCurrentAudienceDraft();
    }

    const gen = ++detailGeneration;
    detailAbort?.abort();
    detailAbort = new AbortController();
    detailError = null;
    if (soft && editorMounted()) {
      detailLoading = false;
      detailRefreshing = true;
    } else if (!editorMounted() && !hasLoadedDetailOnce) {
      detailLoading = true;
      detailRefreshing = false;
    } else {
      detailLoading = false;
      detailRefreshing = true;
    }
    paint();

    try {
      const detail = await getEntryPageDetail(pageId, { signal: detailAbort.signal });
      if (disposed || expectedGen !== generation || gen !== detailGeneration) {
        return;
      }
      pageDetail = detail;
      if (hadDirtyDraft && !forceApply) {
        restoreAudienceDraft(activeAudience);
      } else {
        applyDetailFromServer(detail, activeAudience);
      }
      detailLoading = false;
      detailRefreshing = false;
      hasLoadedDetailOnce = true;
      selfCheckResult = null;
      selfCheckError = null;
      paint();
    } catch (err) {
      if (isAborted(err)) {
        return;
      }
      if (disposed || expectedGen !== generation || gen !== detailGeneration) {
        return;
      }
      detailLoading = false;
      detailRefreshing = false;
      detailError = err;
      paint();
    }
  }

  async function ensureActivePage() {
    if (initializing || activePageId()) {
      return;
    }
    initializing = true;
    paint();
    try {
      const created = await ensureEntryPage(activeAudience);
      if (disposed) {
        return;
      }
      const existingIndex = listItems.findIndex((item) => item?.audience === activeAudience);
      if (existingIndex >= 0) {
        listItems[existingIndex] = created;
      } else {
        listItems.push(created);
      }
      initializing = false;
      await loadActiveDetail(generation);
    } catch (err) {
      if (isAborted(err)) {
        return;
      }
      initializing = false;
      detailError = err;
      paint();
    }
  }

  async function handleSave() {
    const pageId = activePageId();
    if (!pageId || offline || !canSaveDraft()) {
      return;
    }
    const validation = currentValidation();
    if (!validation.valid) {
      saveError = { kind: ERROR_KIND.VALIDATION, message: validation.errors[0] ?? 'Проверьте поля.' };
      paint();
      return;
    }

    saveAbort?.abort();
    saveAbort = new AbortController();
    saving = true;
    saveError = null;
    paint();

    try {
      await saveEntryPageDraft(pageId, draftDocument, { signal: saveAbort.signal });
      if (disposed) {
        return;
      }
      saving = false;
      savedBaseline = cloneDraftDocument(draftDocument);
      audienceDraftCache.set(activeAudience, {
        draft: cloneDraftDocument(draftDocument),
        baseline: cloneDraftDocument(draftDocument),
      });
      ctx.showToast?.({ tone: 'success', message: 'Черновик сохранён.' });
      await loadList({ soft: true });
    } catch (err) {
      if (isAborted(err)) {
        return;
      }
      saving = false;
      saveError = err;
      paint();
    }
  }

  async function handlePublicationToggle(nextPublished) {
    const pageId = activePageId();
    const summary = activeSummary();
    if (!pageId || !summary || publishing || offline) {
      return;
    }

    publishAbort?.abort();
    publishAbort = new AbortController();
    publishing = true;
    publishError = null;
    paint();

    try {
      if (nextPublished) {
        const revisionId = summary.current_revision_id ?? pageDetail?.current_revision_id;
        if (!revisionId) {
          throw new HubApiError({
            code: 'entry.validation_failed',
            userMessage: 'Сначала сохраните черновик, затем опубликуйте страницу.',
            userAction: 'Заполните поля и нажмите «Сохранить изменения».',
            kind: ERROR_KIND.VALIDATION,
          });
        }
        await publishEntryPage(pageId, String(revisionId), { signal: publishAbort.signal });
      } else {
        await unpublishEntryPage(pageId, { signal: publishAbort.signal });
      }
      if (disposed) {
        return;
      }
      publishing = false;
      await loadList({ soft: true });
    } catch (err) {
      if (isAborted(err)) {
        return;
      }
      publishing = false;
      publishError = err;
      paint();
    }
  }

  async function handleSelfCheck() {
    const pageId = activePageId();
    if (!pageId || selfChecking || offline) {
      return;
    }

    selfCheckAbort?.abort();
    selfCheckAbort = new AbortController();
    selfChecking = true;
    selfCheckError = null;
    paint();

    try {
      const payload = await selfCheckEntryPage(pageId, { signal: selfCheckAbort.signal });
      if (disposed) {
        return;
      }
      selfCheckResult = parseSelfCheckResult(payload);
      selfChecking = false;
      paint();
    } catch (err) {
      if (isAborted(err)) {
        return;
      }
      selfChecking = false;
      selfCheckError = err;
      paint();
    }
  }

  function openDraftPreview() {
    const pageId = activePageId();
    if (!pageId || typeof window === 'undefined') {
      return;
    }
    window.open(buildDraftPreviewPath(pageId), '_blank', 'noopener,noreferrer');
  }

  function paintTabs() {
    const signature = activeAudience;
    if (signature === lastTabsSignature && tabsHost.firstChild) {
      return;
    }
    lastTabsSignature = signature;
    clearElement(tabsHost);
    const tabs = createSegmented({
      id: 'hub-entry-pages-audience-tabs',
      label: 'Для кого страница',
      value: activeAudience,
      options: [
        { value: ENTRY_AUDIENCE_GUEST, label: ENTRY_AUDIENCE_LABELS.guest },
        { value: ENTRY_AUDIENCE_STAFF, label: ENTRY_AUDIENCE_LABELS.staff },
      ],
      onChange: (value) => {
        if (value !== ENTRY_AUDIENCE_GUEST && value !== ENTRY_AUDIENCE_STAFF) {
          return;
        }
        cacheCurrentAudienceDraft();
        activeAudience = value;
        detailError = null;
        saveError = null;
        publishError = null;
        selfCheckResult = null;
        selfCheckError = null;
        const restoredDraft = restoreAudienceDraft(activeAudience);
        if (!restoredDraft) {
          draftDocument = resolveEditorDocument(null, activeAudience);
          savedBaseline = null;
        }
        paint();
        void loadActiveDetail(generation, { soft: restoredDraft });
      },
    });
    tabsHost.appendChild(tabs);
  }

  function paintFooter() {
    let saveReason = footerLeft.querySelector('.hub-wifi__save-reason');
    if (!saveReason) {
      saveReason = document.createElement('p');
      saveReason.className = 'hub-wifi__save-reason';
      footerLeft.appendChild(saveReason);
    }
    if (saveError) {
      const described = describeError(saveError);
      saveReason.textContent = formatErrorDescription(described);
    } else if (!draftDirty()) {
      saveReason.textContent = 'Нет несохранённых изменений.';
    } else if (!currentValidation().valid) {
      saveReason.textContent = currentValidation().errors[0] ?? 'Исправьте ошибки в форме.';
    } else {
      saveReason.textContent = '';
    }

    if (!document.getElementById('hub-entry-pages-save-btn')) {
      clearElement(footerRight);
      const saveBtn = createButton({
        label: 'Сохранить изменения',
        variant: 'primary',
        onActivate: () => {
          void handleSave();
        },
      });
      saveBtn.id = 'hub-entry-pages-save-btn';
      footerRight.appendChild(saveBtn);
    }
    const saveBtn = document.getElementById('hub-entry-pages-save-btn');
    if (saveBtn instanceof HTMLButtonElement) {
      saveBtn.disabled = !canSaveDraft();
      saveBtn.setAttribute('aria-busy', saving ? 'true' : 'false');
      saveBtn.textContent = saving ? 'Сохранение…' : 'Сохранить изменения';
    }
  }

  function scheduleDebouncedPaint() {
    if (addressPaintTimer) {
      clearTimeout(addressPaintTimer);
    }
    addressPaintTimer = setTimeout(() => {
      addressPaintTimer = null;
      paint();
    }, ADDRESS_INPUT_DEBOUNCE_MS);
  }

  function renderBannerSlot() {
    const signature = adapterMode === 'fake' ? 'fake' : 'none';
    rebuildSlot(bannerSlot, () => {
      if (adapterMode !== 'fake') {
        return;
      }
      const banner = document.createElement('div');
      banner.className = 'hub-entry-pages__demo-banner hub-wifi__demo-banner';
      banner.appendChild(
        createInlineState({
          state: HubState.MOCK_MODE,
          title: 'Демонстрационный режим — данные не подтверждены',
        }),
      );
      const note = document.createElement('p');
      note.className = 'hub-wifi__demo-text';
      note.textContent =
        'Страницы входа можно настроить в интерфейсе, но в демонстрационном режиме ничего не считается доказанным на устройстве.';
      banner.appendChild(note);
      bannerSlot.appendChild(banner);
    });
  }

  function renderRefreshSlot() {
    const softListError = listError && editorMounted();
    const softDetailError = detailError && editorMounted();
    const showLoading = listRefreshing || detailRefreshing;
    const showSlot = showLoading || softListError || softDetailError;
    rebuildSlot(refreshSlot, () => {
      if (!showSlot) {
        return;
      }
      if (softListError || softDetailError) {
        const err = softDetailError ? detailError : listError;
        const described = describeError(err);
        refreshSlot.appendChild(
          createInlineState({
            state: hubStateForError(err),
            title: `${described.title}. ${formatErrorDescription(described)}`,
            compact: true,
          }),
        );
        return;
      }
      refreshSlot.appendChild(
        createInlineState({
          state: HubState.LOADING,
          title: 'Обновляем данные страницы…',
          compact: true,
        }),
      );
    });
  }

  function renderStateSlot() {
    /** @type {string} */
    let signature = 'ready';
    if (offline) {
      signature = 'offline';
    } else if (listLoading) {
      signature = 'list-loading';
    } else if (listError && !editorMounted()) {
      signature = `list-error|${describeError(listError).title}`;
    } else if (listItems.length === 0) {
      signature = 'list-empty';
    } else if (!activePageId()) {
      signature = `audience-empty|${activeAudience}`;
    } else if ((detailLoading || initializing) && !editorMounted()) {
      signature = 'detail-loading';
    } else if (detailError && !editorMounted()) {
      signature = `detail-error|${describeError(detailError).title}`;
    } else {
      signature = 'none';
    }

    if (signature === lastStateSignature && (signature === 'none' || stateSlot.firstChild)) {
      if (signature === 'none') {
        while (stateSlot.firstChild) {
          stateSlot.removeChild(stateSlot.firstChild);
        }
      }
      return;
    }
    lastStateSignature = signature;
    rebuildSlot(stateSlot, () => {
      if (offline) {
        stateSlot.appendChild(
          createStatePanel({
            state: HubState.NO_INTERNET,
            title: 'Нет сети',
            description: 'Без подключения к хосту управления данные страниц недоступны.',
          }),
        );
        return;
      }
      if (listLoading) {
        stateSlot.appendChild(createSkeleton({ lines: 6 }));
        return;
      }
      if (listError && !editorMounted()) {
        const described = describeError(listError);
        stateSlot.appendChild(
          createStatePanel({
            state: hubStateForError(listError),
            title: described.title,
            description: formatErrorDescription(described),
            action: {
              label: 'Повторить',
              onActivate: () => {
                void loadList();
              },
            },
          }),
        );
        return;
      }
      if (listItems.length === 0) {
        stateSlot.appendChild(
          createStatePanel({
            state: HubState.EMPTY,
            title: 'Страницы ещё не созданы',
            description:
              'Здесь будут страницы для гостей и персонала. Создайте их, чтобы настроить текст и ссылку.',
            action: {
              label: 'Создать страницы',
              onActivate: () => {
                void (async () => {
                  initializing = true;
                  paint();
                  try {
                    const guest = await ensureEntryPage(ENTRY_AUDIENCE_GUEST);
                    const staff = await ensureEntryPage(ENTRY_AUDIENCE_STAFF);
                    if (disposed) {
                      return;
                    }
                    listItems = [guest, staff];
                    initializing = false;
                    await loadActiveDetail(generation);
                  } catch (err) {
                    if (!isAborted(err)) {
                      listError = err;
                      initializing = false;
                      paint();
                    }
                  }
                })();
              },
            },
          }),
        );
        return;
      }
      if (!activePageId()) {
        stateSlot.appendChild(
          createStatePanel({
            state: HubState.EMPTY,
            title: `Страница «${ENTRY_AUDIENCE_LABELS[activeAudience]}» не создана`,
            description: 'Создайте страницу для этой группы.',
            action: {
              label: 'Создать страницу',
              onActivate: () => {
                void ensureActivePage();
              },
            },
          }),
        );
        return;
      }
      if ((detailLoading || initializing) && !editorMounted()) {
        stateSlot.appendChild(createSkeleton({ lines: 8 }));
        return;
      }
      if (detailError && !editorMounted()) {
        const described = describeError(detailError);
        stateSlot.appendChild(
          createStatePanel({
            state: hubStateForError(detailError),
            title: described.title,
            description: formatErrorDescription(described),
            action: {
              label: 'Повторить',
              onActivate: () => {
                void loadActiveDetail(generation);
              },
            },
          }),
        );
      }
    });
  }

  function editorFieldsDigest() {
    const fields = Array.isArray(draftDocument.fields) ? draftDocument.fields : [];
    return fields
      .map((field) => `${String(field.name ?? field.id ?? '')}:${String(field.kind ?? 'text')}`)
      .join(',');
  }

  function editorRolesDigest() {
    if (activeAudience !== ENTRY_AUDIENCE_STAFF) {
      return '';
    }
    const roles = Array.isArray(draftDocument.roles) ? draftDocument.roles : [];
    return roles.map((role) => String(role ?? '').trim()).join(',');
  }

  function shouldRenderEditor() {
    const mounted = editorMounted();
    if (offline || listItems.length === 0 || !activePageId()) {
      return false;
    }
    if (listLoading && !mounted) {
      return false;
    }
    if (listError && !mounted) {
      return false;
    }
    if (detailError && !mounted) {
      return false;
    }
    if ((detailLoading || initializing) && !mounted) {
      return false;
    }
    return true;
  }

  function paint() {
    paintTabs();
    paintFooter();
    mountLayoutOnce();
    renderBannerSlot();
    renderStateSlot();
    renderRefreshSlot();

    if (!shouldRenderEditor()) {
      while (layoutMain.firstChild) {
        layoutMain.removeChild(layoutMain.firstChild);
      }
      while (layoutSide.firstChild) {
        layoutSide.removeChild(layoutSide.firstChild);
      }
      while (infoStrip.firstChild) {
        infoStrip.removeChild(infoStrip.firstChild);
      }
      while (staffBlock.firstChild) {
        staffBlock.removeChild(staffBlock.firstChild);
      }
      lastEditorSignature = null;
      lastPreviewSignature = null;
      lastInfoSignature = null;
      lastStaffSignature = null;
      return;
    }

    const summary = activeSummary();
    const publication = publicationStatusForSummary(summary);
    const editorSignature = [
      activeAudience,
      publication.label,
      publication.published ? 'published' : 'draft',
      publishing ? 'publishing' : 'idle',
      publishError ? describeError(publishError).title : 'none',
      editorFieldsDigest(),
      editorRolesDigest(),
      draftDocument.submissions_enabled === true ? 'submissions-on' : 'submissions-off',
    ].join('|');

    if (editorSignature !== lastEditorSignature || !layoutMain.firstChild) {
      lastEditorSignature = editorSignature;
      rebuildSlot(layoutMain, () => {
        const editorCard = createCard({
          title: 'Редактор',
          body: document.createElement('div'),
        });
        const editorBody = editorCard.querySelector('.hub-card__body');
        if (!editorBody) {
          layoutMain.appendChild(editorCard);
          return;
        }
        editorBody.classList.add('hub-entry-pages__editor-body');

        const statusRow = document.createElement('div');
        statusRow.className = 'hub-entry-pages__status-row';
        const statusBadge = createBadge({
          tone: publication.hubState === HubState.SUCCESS
            ? 'success'
            : publication.hubState === HubState.WARNING
              ? 'warning'
              : 'neutral',
          label: `Статус: ${publication.label}`,
        });
        statusRow.appendChild(statusBadge);

        const publishToggle = createToggle({
          id: 'hub-entry-pages-publish-toggle',
          label: 'Опубликована',
          checked: publication.published,
          disabled: publishing || offline || !publication.hasDraft,
          onChange: (checked) => {
            void handlePublicationToggle(checked);
          },
        });
        statusRow.appendChild(publishToggle);
        editorBody.appendChild(statusRow);

        if (publishError) {
          const described = describeError(publishError);
          editorBody.appendChild(
            createCheckRow({
              state: hubStateForError(publishError),
              title: described.title,
              description: formatErrorDescription(described),
            }),
          );
        }

        const audienceFact = document.createElement('p');
        audienceFact.className = 'hub-entry-pages__fact';
        audienceFact.textContent = `Страница: ${ENTRY_AUDIENCE_LABELS[activeAudience]}`;
        editorBody.appendChild(audienceFact);

        const wifiNote = document.createElement('p');
        wifiNote.className = 'hub-entry-pages__note';
        wifiNote.textContent = ENTRY_PAGE_NOT_WIFI_BOUND_NOTE;
        editorBody.appendChild(wifiNote);

        const autoOpenNote = document.createElement('p');
        autoOpenNote.className = 'hub-entry-pages__note hub-entry-pages__unsupported-note';
        autoOpenNote.textContent = ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE;
        autoOpenNote.setAttribute('data-testid', 'entry-auto-open-unsupported');
        editorBody.appendChild(autoOpenNote);

        const logoNote = document.createElement('p');
        logoNote.className = 'hub-entry-pages__note';
        logoNote.textContent = ENTRY_LOGO_UNSUPPORTED_NOTE;
        editorBody.appendChild(logoNote);

        const markDirty = () => {
          saveError = null;
          paintFooter();
          const previewHost = layoutSide.querySelector('[data-testid="entry-preview-body"]');
          if (previewHost instanceof HTMLElement) {
            renderPreviewDocument(previewHost, draftDocument, activeAudience);
          }
        };

        editorBody.appendChild(
          createTextField({
            id: 'hub-entry-pages-title',
            label: 'Заголовок',
            value: String(draftDocument.title ?? ''),
            onInput: (event) => {
              draftDocument.title = event.target.value;
              markDirty();
            },
          }),
        );
        editorBody.appendChild(
          createTextField({
            id: 'hub-entry-pages-intro',
            label: 'Вступление',
            value: String(draftDocument.intro ?? ''),
            onInput: (event) => {
              draftDocument.intro = event.target.value;
              markDirty();
            },
          }),
        );
        editorBody.appendChild(
          createTextField({
            id: 'hub-entry-pages-button-label',
            label: 'Кнопка',
            value: String(draftDocument.button_label ?? ''),
            onInput: (event) => {
              draftDocument.button_label = event.target.value;
              markDirty();
            },
          }),
        );

        const submissionsToggle = createToggle({
          id: 'hub-entry-pages-submissions-toggle',
          label: 'Собирать ответы гостей',
          checked: draftDocument.submissions_enabled === true,
          onChange: (checked) => {
            draftDocument.submissions_enabled = checked;
            markDirty();
            paint();
          },
        });
        editorBody.appendChild(submissionsToggle);

        renderFieldsEditor(editorBody, draftDocument, activeAudience, markDirty, paint);
        if (activeAudience === ENTRY_AUDIENCE_STAFF) {
          renderRolesEditor(editorBody, draftDocument, markDirty, paint);
        }

        layoutMain.appendChild(editorCard);
      });
    }

    const previewSignature = [
      previewFrameMode,
      JSON.stringify(draftDocument),
      activeAudience,
      selfChecking ? 'checking' : 'idle',
      selfCheckError ? describeError(selfCheckError).title : 'none',
      selfCheckResult?.operatorRender?.hubState ?? 'none',
    ].join('|');

    if (previewSignature !== lastPreviewSignature || !layoutSide.firstChild) {
      lastPreviewSignature = previewSignature;
      rebuildSlot(layoutSide, () => {
        const previewCard = createCard({
          title: 'Предпросмотр',
          body: document.createElement('div'),
        });
        const previewBody = previewCard.querySelector('.hub-card__body');
        if (previewBody) {
          previewBody.classList.add('hub-entry-pages__preview-card');

          const frameSwitch = createSegmented({
            id: 'hub-entry-pages-preview-frame',
            label: 'Как выглядит',
            value: previewFrameMode,
            options: [
              { value: 'phone', label: 'Телефон' },
              { value: 'tablet', label: 'Планшет' },
            ],
            onChange: (value) => {
              previewFrameMode = value === 'tablet' ? 'tablet' : 'phone';
              paint();
            },
          });
          previewBody.appendChild(frameSwitch);

          const frame = document.createElement('div');
          frame.className = 'hub-entry-pages__preview-frame';
          frame.classList.add(
            previewFrameMode === 'tablet'
              ? 'hub-entry-pages__preview-frame--tablet'
              : 'hub-entry-pages__preview-frame--phone',
          );
          const frameInner = document.createElement('div');
          frameInner.className = 'hub-entry-pages__preview-frame-inner';
          frameInner.setAttribute('data-testid', 'entry-preview-body');
          renderPreviewDocument(frameInner, draftDocument, activeAudience);
          frame.appendChild(frameInner);
          previewBody.appendChild(frame);

          const previewActions = document.createElement('div');
          previewActions.className = 'hub-entry-pages__preview-actions';
          previewActions.appendChild(
            (() => {
              const btn = createButton({
                label: 'Открыть предпросмотр',
                variant: 'secondary',
                onActivate: openDraftPreview,
              });
              btn.id = 'hub-entry-pages-open-preview-btn';
              return btn;
            })(),
          );
          previewActions.appendChild(
            (() => {
              const btn = createButton({
                label: selfChecking ? 'Проверка…' : 'Проверить подключение',
                variant: 'secondary',
                busy: selfChecking,
                disabled: selfChecking,
                onActivate: () => {
                  void handleSelfCheck();
                },
              });
              btn.id = 'hub-entry-pages-self-check-btn';
              return btn;
            })(),
          );
          previewBody.appendChild(previewActions);

          const scopeLabel = document.createElement('p');
          scopeLabel.className = 'hub-entry-pages__probe-scope';
          scopeLabel.textContent = DOMAIN_HOST_PROBE_SCOPE_LABEL;
          previewBody.appendChild(scopeLabel);

          if (selfCheckError) {
            const described = describeError(selfCheckError);
            previewBody.appendChild(
              createCheckRow({
                state: hubStateForError(selfCheckError),
                title: described.title,
                description: formatErrorDescription(described),
              }),
            );
          } else if (selfCheckResult) {
            previewBody.appendChild(
              createCheckRow({
                state: selfCheckResult.operatorRender.hubState,
                title: selfCheckResult.operatorRender.title,
                description: selfCheckResult.operatorRender.message,
              }),
            );
            previewBody.appendChild(
              createCheckRow({
                state: selfCheckResult.guestReachability.hubState,
                title: selfCheckResult.guestReachability.title,
                description: selfCheckResult.guestReachability.message,
                testId: 'entry-guest-reachability',
              }),
            );
            previewBody.appendChild(
              createCheckRow({
                state: selfCheckResult.publicZone.hubState,
                title: selfCheckResult.publicZone.title,
                description: selfCheckResult.publicZone.message,
              }),
            );
          }
        }
        layoutSide.appendChild(previewCard);
      });
    }

    const publicPath = summary?.public_path ? String(summary.public_path) : '';
    const publicUrl = buildPublicEntryUrl(publicHostAddress, publicPath);
    const infoSignature = `${publicPath}|${publicHostAddress}|${publicUrl ?? ''}|${lastQrEncodedPayload ?? ''}`;

    if (infoSignature !== lastInfoSignature || !infoStrip.firstChild) {
      lastInfoSignature = infoSignature;
      rebuildSlot(infoStrip, () => {
        const infoTitle = document.createElement('h2');
        infoTitle.className = 'hub-entry-pages__info-title';
        infoTitle.textContent = 'Ссылка и QR для гостя';
        infoStrip.appendChild(infoTitle);

        const pathLine = document.createElement('p');
        pathLine.className = 'hub-entry-pages__fact';
        pathLine.textContent = publicPath
          ? `Короткий путь: ${publicPath}`
          : 'Короткий путь появится после создания страницы.';
        infoStrip.appendChild(pathLine);

        infoStrip.appendChild(
          createTextField({
            id: 'hub-entry-pages-public-host',
            label: 'Адрес входа для гостей в вашей сети',
            value: publicHostAddress,
            hint: ENTRY_PUBLIC_ADDRESS_UNVERIFIED_NOTE,
            error: validatePublicEntryAddress(publicHostAddress).error ?? undefined,
            onInput: (event) => {
              publicHostAddress = event.target.value;
              scheduleDebouncedPaint();
            },
          }),
        );

        const listenerInstruction = document.createElement('p');
        listenerInstruction.className = 'hub-entry-pages__note';
        listenerInstruction.textContent = ENTRY_PUBLIC_LISTENER_INSTRUCTION;
        infoStrip.appendChild(listenerInstruction);

        if (publicUrl) {
          const urlLine = document.createElement('p');
          urlLine.className = 'hub-entry-pages__fact';
          urlLine.textContent = `Полная ссылка: ${publicUrl}`;
          infoStrip.appendChild(urlLine);

          const qrWrap = document.createElement('div');
          qrWrap.className = 'hub-entry-pages__qr-wrap';
          if (qrCanvasEl && lastQrEncodedPayload === publicUrl) {
            qrWrap.appendChild(qrCanvasEl);
          } else {
            const canvas = document.createElement('canvas');
            canvas.className = 'hub-wifi__qr-canvas';
            canvas.setAttribute('aria-label', 'QR-код ссылки на страницу входа');
            canvas.setAttribute('data-testid', 'entry-public-qr');
            try {
              drawWifiQrCanvas(canvas, publicUrl, { moduleSize: 4 });
              qrCanvasEl = canvas;
              lastQrEncodedPayload = publicUrl;
              qrWrap.appendChild(canvas);
            } catch {
              qrCanvasEl = null;
              lastQrEncodedPayload = null;
              const note = document.createElement('p');
              note.textContent = 'Не удалось построить QR-код.';
              qrWrap.appendChild(note);
            }
          }
          infoStrip.appendChild(qrWrap);
        } else {
          qrCanvasEl = null;
          lastQrEncodedPayload = null;
        }
      });
    }

    const staffPage = staffSummary();
    const staffPublication = publicationStatusForSummary(staffPage);
    const staffSignature = `${staffPublication.label}|${activeAudience}|${staffPage?.page_id ?? 'none'}`;

    if (staffSignature !== lastStaffSignature || !staffBlock.firstChild) {
      lastStaffSignature = staffSignature;
      rebuildSlot(staffBlock, () => {
        const staffTitle = document.createElement('h2');
        staffTitle.className = 'hub-entry-pages__info-title';
        staffTitle.textContent = 'Страница персонала';
        staffBlock.appendChild(staffTitle);

        const staffStatus = document.createElement('p');
        staffStatus.className = 'hub-entry-pages__fact';
        staffStatus.textContent = staffPage
          ? `Статус: ${staffPublication.label}`
          : 'Статус: не создана';
        staffBlock.appendChild(staffStatus);

        if (activeAudience !== ENTRY_AUDIENCE_STAFF) {
          const staffBtn = createButton({
            label: 'Перейти к настройке',
            variant: 'secondary',
            onActivate: () => {
              cacheCurrentAudienceDraft();
              activeAudience = ENTRY_AUDIENCE_STAFF;
              if (!restoreAudienceDraft(activeAudience)) {
                draftDocument = resolveEditorDocument(null, activeAudience);
                savedBaseline = null;
              }
              paint();
              void loadActiveDetail(generation);
            },
          });
          staffBtn.id = 'hub-entry-pages-go-staff-btn';
          staffBlock.appendChild(staffBtn);
        }
      });
    }
  }


  void loadList();

  const unsubConnectivity = subscribeConnectivity((online) => {
    offline = !online;
    paint();
  });

  return () => {
    disposed = true;
    generation += 1;
    detailGeneration += 1;
    if (addressPaintTimer) {
      clearTimeout(addressPaintTimer);
      addressPaintTimer = null;
    }
    listAbort?.abort();
    detailAbort?.abort();
    saveAbort?.abort();
    publishAbort?.abort();
    selfCheckAbort?.abort();
    unsubConnectivity();
    clearElement(container);
  };
}
