/**
 * Entry pages — API, validation, and honest state descriptors.
 */

import { apiGet, apiPost, apiRequest } from '../core/api.js';
import { HubState } from '../core/states.js';

export const ENTRY_AUDIENCE_GUEST = 'guest';
export const ENTRY_AUDIENCE_STAFF = 'staff';

export const ENTRY_AUDIENCE_LABELS = Object.freeze({
  guest: 'Для гостей',
  staff: 'Для персонала',
});

export const ENTRY_PAGE_NOT_WIFI_BOUND_NOTE =
  'Страница входа не привязана к Wi‑Fi сети. Гость открывает её по ссылке или QR-коду после подключения.';

export const ENTRY_AUTO_OPEN_UNSUPPORTED_NOTE =
  'Принудительное автооткрытие страницы после подключения к Wi‑Fi на этом устройстве не поддерживается. Используйте QR-код и короткую ссылку.';

export const ENTRY_LOGO_UNSUPPORTED_NOTE =
  'Загрузка логотипа и отдельное оформление в этой версии не поддерживаются.';

export const ENTRY_PUBLIC_LISTENER_INSTRUCTION =
  'Чтобы гость открыл страницу, запустите отдельный вход для гостей на адресе вашей сети (на этом компьютере) и добавьте правило в брандмауэре, разрешающее гостям только этот порт.';

export const ENTRY_PUBLIC_ADDRESS_UNVERIFIED_NOTE =
  'Адрес вводите вы. Приложение не проверяло, что гостевые устройства смогут открыть страницу по этому адресу.';

export const ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE =
  'Укажите адрес с префиксом http или https, либо адрес компьютера с портом (например 192.168.1.10:8790).';

export const ENTRY_FIELD_KIND_OPTIONS = Object.freeze([
  { value: 'text', label: 'Текст' },
  { value: 'phone', label: 'Телефон' },
  { value: 'email', label: 'Электронная почта' },
  { value: 'select', label: 'Список вариантов' },
]);

export const ENTRY_MAX_FIELDS = 8;
export const ENTRY_MAX_ROLES = 12;
export const ENTRY_MAX_SELECT_OPTIONS = 12;

export const ENTRY_GUEST_REACHABILITY_UNKNOWN_MESSAGE =
  'Доступность страницы для гостя с его устройства не проверена. Проверку можно выполнить только с гостевого телефона или планшета.';

export const ENTRY_HTML_REJECTED_MESSAGE =
  'Символы «<» и «>» в тексте не допускаются. Используйте обычный текст.';

const FIELD_KINDS = new Set(['text', 'phone', 'email', 'select']);
export const FIELD_NAME_RE = /^[a-z][a-z0-9_]{0,31}$/;

/**
 * @param {string} label
 * @param {Set<string>|string[]} takenNames
 * @param {number} index
 * @returns {string}
 */
export function deriveFieldName(label, takenNames, index) {
  const taken = takenNames instanceof Set ? takenNames : new Set(takenNames);
  const raw = String(label ?? '').trim().toLowerCase();
  let base = raw
    .replace(/[^a-z0-9_]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_');
  if (!base || !/^[a-z]/.test(base)) {
    base = `field_${index + 1}`;
  }
  if (base.length > 32) {
    base = base.slice(0, 32);
  }
  if (!FIELD_NAME_RE.test(base)) {
    base = `field_${index + 1}`;
  }
  let candidate = base;
  let suffix = 2;
  while (taken.has(candidate)) {
    const suffixStr = `_${suffix}`;
    candidate = `${base.slice(0, Math.max(1, 32 - suffixStr.length))}${suffixStr}`;
    suffix += 1;
  }
  return candidate;
}

/**
 * @param {Record<string, unknown>} document
 */
export function syncFieldNames(document) {
  if (!document || !Array.isArray(document.fields)) {
    return;
  }
  const taken = new Set();
  document.fields.forEach((field, index) => {
    if (!field || typeof field !== 'object') {
      return;
    }
    const item = /** @type {Record<string, unknown>} */ (field);
    item.name = deriveFieldName(String(item.label ?? ''), taken, index);
    taken.add(String(item.name));
  });
}

/**
 * @param {string} value
 * @returns {boolean}
 */
export function containsHtmlMarkup(value) {
  return typeof value === 'string' && (value.includes('<') || value.includes('>'));
}

/**
 * @param {'guest'|'staff'} audience
 * @returns {Record<string, unknown>}
 */
export function createDefaultEntryDocument(audience) {
  /** @type {Record<string, unknown>} */
  const doc = {
    title: '',
    intro: '',
    button_label: '',
    fields: [],
    submissions_enabled: false,
  };
  if (audience === ENTRY_AUDIENCE_STAFF) {
    doc.roles = ['Сотрудник'];
  }
  return doc;
}

/**
 * @param {unknown} left
 * @param {unknown} right
 * @returns {boolean}
 */
export function entryDocumentsEqual(left, right) {
  try {
    return JSON.stringify(left) === JSON.stringify(right);
  } catch {
    return false;
  }
}

/**
 * @param {string} fieldPath
 * @returns {string}
 */
function userFieldLabel(fieldPath) {
  if (fieldPath === 'document') {
    return 'Документ страницы';
  }
  if (fieldPath === 'title') {
    return 'Заголовок';
  }
  if (fieldPath === 'intro') {
    return 'Вводный текст';
  }
  if (fieldPath === 'button_label') {
    return 'Кнопка';
  }
  if (fieldPath === 'fields') {
    return 'Поля формы';
  }
  if (fieldPath === 'submissions_enabled') {
    return 'Собирать ответы';
  }
  if (fieldPath === 'roles') {
    return 'Роли';
  }
  const fieldMatch = fieldPath.match(/^fields\[(\d+)\](?:\.\w+)?$/);
  if (fieldMatch) {
    return `Поле ${Number(fieldMatch[1]) + 1}`;
  }
  const roleMatch = fieldPath.match(/^roles\[(\d+)\]$/);
  if (roleMatch) {
    return `Роль ${Number(roleMatch[1]) + 1}`;
  }
  return fieldPath;
}

/**
 * @param {string} value
 * @param {{ fieldPath: string, minLen: number, maxLen: number, allowEmpty?: boolean }} rules
 * @param {string[]} errors
 * @returns {string|null}
 */
function validateStringField(value, rules, errors) {
  const label = userFieldLabel(rules.fieldPath);
  const raw = value == null ? '' : String(value);
  const stripped = raw.trim();
  if (containsHtmlMarkup(raw)) {
    errors.push(`${label}: ${ENTRY_HTML_REJECTED_MESSAGE}`);
    return null;
  }
  if (stripped.length < rules.minLen || stripped.length > rules.maxLen) {
    errors.push(`${label}: недопустимая длина`);
    return null;
  }
  if (rules.allowEmpty && stripped.length === 0) {
    return '';
  }
  return stripped;
}

/**
 * @param {unknown} raw
 * @param {number} index
 * @param {string[]} errors
 * @returns {Record<string, unknown>|null}
 */
function validateFieldItem(raw, index, errors) {
  const fieldPath = `fields[${index}]`;
  const label = userFieldLabel(fieldPath);
  if (!raw || typeof raw !== 'object') {
    errors.push(`${label}: поле должно быть объектом`);
    return null;
  }
  const item = /** @type {Record<string, unknown>} */ (raw);
  const name = validateStringField(item.name, { fieldPath: `${fieldPath}.name`, minLen: 1, maxLen: 32 }, errors);
  if (name && !FIELD_NAME_RE.test(name)) {
    errors.push(`${label}: недопустимое имя`);
  }
  validateStringField(item.label, { fieldPath: `${fieldPath}.label`, minLen: 1, maxLen: 60 }, errors);
  const kind = String(item.kind ?? '');
  if (!FIELD_KINDS.has(kind)) {
    errors.push(`${label}: недопустимый тип`);
  }
  if (typeof item.required !== 'boolean') {
    errors.push(`${label}: укажите, обязательно ли поле`);
  }
  if (kind === 'select') {
    const options = item.options;
    if (!Array.isArray(options) || options.length < 1 || options.length > 12) {
      errors.push(`${label}: нужен список из 1–12 вариантов`);
    }
  } else if ('options' in item && item.options != null) {
    errors.push(`${label}: варианты допустимы только для списка`);
  }
  return item;
}

/**
 * @param {unknown} document
 * @param {'guest'|'staff'} audience
 * @returns {{ valid: boolean, errors: string[], document: Record<string, unknown>|null }}
 */
export function validateEntryDocument(document, audience) {
  const errors = [];
  if (!document || typeof document !== 'object') {
    return { valid: false, errors: ['Документ страницы: ожидается объект'], document: null };
  }
  const raw = /** @type {Record<string, unknown>} */ (document);
  if (audience === ENTRY_AUDIENCE_GUEST && 'roles' in raw) {
    errors.push('Роли: недопустимо для гостевой страницы');
  }
  validateStringField(raw.title, { fieldPath: 'title', minLen: 1, maxLen: 120 }, errors);
  validateStringField(raw.intro ?? '', { fieldPath: 'intro', minLen: 0, maxLen: 400, allowEmpty: true }, errors);
  validateStringField(raw.button_label, { fieldPath: 'button_label', minLen: 1, maxLen: 60 }, errors);
  const fieldsRaw = raw.fields;
  if (!Array.isArray(fieldsRaw)) {
    errors.push('Поля формы: ожидается список');
  } else if (fieldsRaw.length > 8) {
    errors.push('Поля формы: не более 8 полей');
  } else {
    const seenLabels = new Set();
    fieldsRaw.forEach((field, index) => {
      validateFieldItem(field, index, errors);
      if (field && typeof field === 'object') {
        const labelKey = String(/** @type {Record<string, unknown>} */ (field).label ?? '')
          .trim()
          .toLowerCase();
        if (labelKey) {
          if (seenLabels.has(labelKey)) {
            errors.push(`${userFieldLabel(`fields[${index}]`)}: такая подпись уже используется`);
          }
          seenLabels.add(labelKey);
        }
      }
    });
  }
  if (typeof raw.submissions_enabled !== 'boolean') {
    errors.push('Собирать ответы: укажите да или нет');
  }
  if (audience === ENTRY_AUDIENCE_STAFF) {
    const rolesRaw = raw.roles;
    if (!Array.isArray(rolesRaw)) {
      errors.push('Роли: ожидается список');
    } else if (rolesRaw.length < 1 || rolesRaw.length > 12) {
      errors.push('Роли: нужно от 1 до 12');
    } else {
      const seenRoles = new Set();
      rolesRaw.forEach((role, index) => {
        const trimmed = validateStringField(
          role,
          { fieldPath: `roles[${index}]`, minLen: 1, maxLen: 40 },
          errors,
        );
        if (trimmed) {
          const roleKey = trimmed.toLowerCase();
          if (seenRoles.has(roleKey)) {
            errors.push(`${userFieldLabel(`roles[${index}]`)}: роль «${trimmed}» уже добавлена`);
          }
          seenRoles.add(roleKey);
        }
      });
    }
  }
  return {
    valid: errors.length === 0,
    errors,
    document: errors.length === 0 ? raw : null,
  };
}

/**
 * @param {Record<string, unknown>|null|undefined} summary
 * @returns {{ label: string, published: boolean, hasDraft: boolean, hubState: string }}
 */
export function describePublicationStatus(summary) {
  if (!summary) {
    return {
      label: 'Не создана',
      published: false,
      hasDraft: false,
      hubState: HubState.EMPTY,
    };
  }
  const published = Boolean(summary.published);
  const hasDraft = Boolean(summary.has_draft);
  if (published) {
    return {
      label: 'Опубликована',
      published: true,
      hasDraft,
      hubState: HubState.SUCCESS,
    };
  }
  if (hasDraft) {
    return {
      label: 'Есть черновик, не опубликована',
      published: false,
      hasDraft: true,
      hubState: HubState.WARNING,
    };
  }
  return {
    label: 'Не создана',
    published: false,
    hasDraft: false,
    hubState: HubState.EMPTY,
  };
}

/**
 * Guest reachability is never proven from operator host — ignore backend true.
 * @param {Record<string, unknown>|null|undefined} payload
 * @returns {{ hubState: string, message: string, title: string }}
 */
export function describeGuestReachability(payload) {
  void payload;
  return {
    title: 'Доступность для гостя',
    message: ENTRY_GUEST_REACHABILITY_UNKNOWN_MESSAGE,
    hubState: HubState.EMPTY,
  };
}

/**
 * @param {boolean|null|undefined} renderOk
 * @param {boolean} published
 * @returns {{ hubState: string, message: string, title: string }}
 */
export function describeOperatorRenderCheck(renderOk, published) {
  if (!published) {
    return {
      title: 'Страница открывается на этом компьютере',
      message: 'Страница не опубликована — проверка опубликованной версии не выполнялась.',
      hubState: HubState.EMPTY,
    };
  }
  if (renderOk === true) {
    return {
      title: 'Страница открывается на этом компьютере',
      message: 'Опубликованная страница открывается на этом компьютере без ошибок.',
      hubState: HubState.SUCCESS,
    };
  }
  if (renderOk === false) {
    return {
      title: 'Страница открывается на этом компьютере',
      message: 'Опубликованная страница не открывается — проверьте содержимое и опубликуйте снова.',
      hubState: HubState.ERROR,
    };
  }
  return {
    title: 'Страница открывается на этом компьютере',
    message: 'Опубликованная страница ещё не проверялась на этом компьютере.',
    hubState: HubState.EMPTY,
  };
}

/**
 * @param {boolean|null|undefined} enabled
 * @returns {{ hubState: string, message: string, title: string }}
 */
export function describePublicZoneConfigured(enabled) {
  if (enabled === true) {
    return {
      title: 'Отдельный вход для гостей',
      message: 'Адрес входа для гостей задан в настройках программы, но службу входа всё равно нужно запустить вручную.',
      hubState: HubState.WARNING,
    };
  }
  if (enabled === false) {
    return {
      title: 'Отдельный вход для гостей',
      message: 'Отдельный вход для гостей не настроен.',
      hubState: HubState.EMPTY,
    };
  }
  return {
    title: 'Отдельный вход для гостей',
    message: 'Неизвестно, запущен ли отдельный вход для гостей в вашей сети.',
    hubState: HubState.EMPTY,
  };
}

/**
 * @param {Record<string, unknown>|null|undefined} payload
 * @returns {{ operatorRender: ReturnType<typeof describeOperatorRenderCheck>, guestReachability: ReturnType<typeof describeGuestReachability>, publicZone: ReturnType<typeof describePublicZoneConfigured> }}
 */
export function parseSelfCheckResult(payload) {
  if (!payload || typeof payload !== 'object') {
    return {
      operatorRender: {
        title: 'Страница открывается на этом компьютере',
        message: 'Проверка страницы входа не выполнялась — данные не получены.',
        hubState: HubState.EMPTY,
      },
      guestReachability: describeGuestReachability(null),
      publicZone: describePublicZoneConfigured(null),
    };
  }
  const published = Boolean(payload.published);
  const renderOk = payload?.render_ok === true
    ? true
    : payload?.render_ok === false
      ? false
      : null;
  return {
    operatorRender: describeOperatorRenderCheck(renderOk, published),
    guestReachability: describeGuestReachability(payload),
    publicZone: describePublicZoneConfigured(
      payload?.public_zone_enabled === true
        ? true
        : payload?.public_zone_enabled === false
          ? false
          : null,
    ),
  };
}

const HTTP_SCHEME = ['http', '://'].join('');
const HTTPS_SCHEME = ['https', '://'].join('');
const MAX_PUBLIC_HOSTNAME_LENGTH = 253;
const MAX_PUBLIC_LABEL_LENGTH = 63;

/**
 * @param {string} host
 * @returns {boolean}
 */
function isValidIpv4Literal(host) {
  const parts = host.split('.');
  if (parts.length !== 4) {
    return false;
  }
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) {
      return false;
    }
    if (part.length > 1 && part.startsWith('0')) {
      return false;
    }
    const value = Number(part);
    if (value > 255) {
      return false;
    }
  }
  return true;
}

/**
 * @param {string} host
 * @returns {boolean}
 */
function isPartialIpv4Literal(host) {
  if (!/^\d+(?:\.\d+){0,2}$/.test(host)) {
    return false;
  }
  return host.split('.').length < 4;
}

/**
 * @param {string} host
 * @returns {boolean}
 */
function isValidIpv6Literal(host) {
  if (!/^[0-9a-fA-F:]+$/.test(host)) {
    return false;
  }
  try {
    return host.includes(':') && !host.includes('..');
  } catch {
    return false;
  }
}

/**
 * @param {string} host
 * @returns {boolean}
 */
function isValidHostname(host) {
  if (!host || host.length > MAX_PUBLIC_HOSTNAME_LENGTH) {
    return false;
  }
  if (host.endsWith('.')) {
    return false;
  }
  if (/[^\x00-\x7F]/.test(host)) {
    return false;
  }
  const labels = host.split('.');
  for (const label of labels) {
    if (!label || label.length > MAX_PUBLIC_LABEL_LENGTH) {
      return false;
    }
    if (!/^[a-zA-Z0-9-]+$/.test(label)) {
      return false;
    }
    if (label.startsWith('-') || label.endsWith('-')) {
      return false;
    }
  }
  return true;
}

/**
 * @param {string} hostAddress
 * @returns {{ valid: boolean, error: string|null, normalizedHost: string|null }}
 */
export function validatePublicEntryAddress(hostAddress) {
  const raw = String(hostAddress ?? '');
  if (raw !== raw.trim()) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }
  const trimmed = raw.trim();
  if (!trimmed) {
    return { valid: false, error: null, normalizedHost: null };
  }
  if (/[\u0000-\u001F\u007F]/.test(trimmed) || /\s/.test(trimmed)) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }
  if (/\\/.test(trimmed)) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }
  if (/^\/\//.test(trimmed)) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }

  let remainder = trimmed;
  let scheme = 'http';
  const schemeMatch = remainder.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):(.*)$/);
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    remainder = schemeMatch[2];
    if (remainder.startsWith('//')) {
      remainder = remainder.slice(2);
    } else if (remainder.startsWith('/')) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
  }

  const authority = remainder.split(/[/?#]/)[0];
  if (!authority || authority.includes('@')) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }

  let hostname = authority;
  let port = '';
  if (hostname.startsWith('[')) {
    const closeIdx = hostname.indexOf(']');
    if (closeIdx === -1) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    const ipv6 = hostname.slice(1, closeIdx);
    if (!isValidIpv6Literal(ipv6)) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    const after = hostname.slice(closeIdx + 1);
    if (after.startsWith(':')) {
      port = after.slice(1);
    } else if (after.length > 0) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    hostname = ipv6;
  } else {
    const colonIdx = hostname.lastIndexOf(':');
    if (colonIdx !== -1 && /^\d+$/.test(hostname.slice(colonIdx + 1))) {
      port = hostname.slice(colonIdx + 1);
      hostname = hostname.slice(0, colonIdx);
    }
  }

  if (!hostname) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }
  if (/^\d+$/.test(hostname)) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }
  if (isPartialIpv4Literal(hostname)) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }

  let parsedHostname = '';
  if (hostname.includes(':')) {
    if (!isValidIpv6Literal(hostname)) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    parsedHostname = hostname;
  } else if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
    if (!isValidIpv4Literal(hostname)) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    parsedHostname = hostname;
  } else if (!isValidHostname(hostname)) {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  } else {
    parsedHostname = hostname;
  }

  if (port) {
    const portNum = Number(port);
    if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
  }

  const hostPort = parsedHostname.includes(':') ? `[${parsedHostname}]` : parsedHostname;
  const hostWithPort = port ? `${hostPort}:${port}` : hostPort;
  const normalizedHost = `${scheme === 'https' ? HTTPS_SCHEME : HTTP_SCHEME}${hostWithPort}`;

  try {
    const parsed = new URL(normalizedHost);
    if (parsed.username || parsed.password) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    const parsedScheme = parsed.protocol.replace(/:$/, '').toLowerCase();
    if (parsedScheme !== 'http' && parsedScheme !== 'https') {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    if (parsed.hostname !== parsedHostname) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    if (port && parsed.port !== port) {
      return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
    }
    if (!port) {
      const defaultPort = parsedScheme === 'https' ? '443' : '80';
      if (parsed.port && parsed.port !== defaultPort) {
        return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
      }
    }
  } catch {
    return { valid: false, error: ENTRY_PUBLIC_ADDRESS_REJECTED_MESSAGE, normalizedHost: null };
  }

  return { valid: true, error: null, normalizedHost };
}

/**
 * @param {string} hostAddress
 * @param {string} publicPath
 * @returns {string|null}
 */
export function buildPublicEntryUrl(hostAddress, publicPath) {
  const path = String(publicPath ?? '').trim();
  if (!path) {
    return null;
  }
  const validation = validatePublicEntryAddress(hostAddress);
  if (!validation.valid || !validation.normalizedHost) {
    return null;
  }
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  return `${validation.normalizedHost.replace(/\/+$/, '')}${normalizedPath}`;
}

/**
 * @param {string} pageId
 * @returns {string}
 */
export function buildDraftPreviewPath(pageId) {
  return `/api/router-control/v1/entry-pages/${encodeURIComponent(pageId)}/draft-preview`;
}

/**
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<{ items: Array<Record<string, unknown>> }>}
 */
export function listEntryPages(options = {}) {
  return /** @type {Promise<{ items: Array<Record<string, unknown>> }>} */ (
    apiGet('entry-pages', options)
  );
}

/**
 * @param {'guest'|'staff'} audience
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function ensureEntryPage(audience, options = {}) {
  return /** @type {Promise<Record<string, unknown>>} */ (
    apiPost('entry-pages', { audience }, options)
  );
}

/**
 * @param {string} pageId
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function getEntryPageDetail(pageId, options = {}) {
  return /** @type {Promise<Record<string, unknown>>} */ (
    apiGet(`entry-pages/${encodeURIComponent(pageId)}`, options)
  );
}

/**
 * @param {string} pageId
 * @param {Record<string, unknown>} document
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function saveEntryPageDraft(pageId, document, options = {}) {
  return /** @type {Promise<Record<string, unknown>>} */ (
    apiRequest(`entry-pages/${encodeURIComponent(pageId)}/draft`, {
      method: 'PUT',
      body: { document },
      ...options,
    })
  );
}

/**
 * @param {string} pageId
 * @param {string} revisionId
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function publishEntryPage(pageId, revisionId, options = {}) {
  return /** @type {Promise<Record<string, unknown>>} */ (
    apiPost(`entry-pages/${encodeURIComponent(pageId)}/publish`, { revision_id: revisionId }, options)
  );
}

/**
 * @param {string} pageId
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function unpublishEntryPage(pageId, options = {}) {
  return /** @type {Promise<Record<string, unknown>>} */ (
    apiPost(`entry-pages/${encodeURIComponent(pageId)}/unpublish`, {}, options)
  );
}

/**
 * @param {string} pageId
 * @param {{ signal?: AbortSignal }} [options]
 * @returns {Promise<Record<string, unknown>>}
 */
export function selfCheckEntryPage(pageId, options = {}) {
  return /** @type {Promise<Record<string, unknown>>} */ (
    apiPost(`entry-pages/${encodeURIComponent(pageId)}/self-check`, {}, options)
  );
}

/**
 * @param {Array<Record<string, unknown>>} items
 * @param {'guest'|'staff'} audience
 * @returns {Record<string, unknown>|null}
 */
export function findPageByAudience(items, audience) {
  if (!Array.isArray(items)) {
    return null;
  }
  return items.find((item) => item?.audience === audience) ?? null;
}

/**
 * @param {Record<string, unknown>|null|undefined} detail
 * @param {'guest'|'staff'} audience
 * @returns {Record<string, unknown>}
 */
function cloneDocument(document) {
  return /** @type {Record<string, unknown>} */ (JSON.parse(JSON.stringify(document)));
}

/**
 * @param {Record<string, unknown>|null|undefined} detail
 * @param {'guest'|'staff'} audience
 * @returns {Record<string, unknown>}
 */
export function resolveEditorDocument(detail, audience) {
  const draft = detail?.draft_document;
  if (draft && typeof draft === 'object') {
    return cloneDocument(draft);
  }
  return createDefaultEntryDocument(audience);
}

/**
 * @param {Record<string, unknown>|null|undefined} detail
 * @returns {Record<string, unknown>|null}
 */
export function baselineDocumentFromDetail(detail) {
  const draft = detail?.draft_document;
  if (draft && typeof draft === 'object') {
    return cloneDocument(draft);
  }
  return null;
}
