/**
 * Модель экрана «Домен и публикация» — данные и сетевые вызовы без DOM.
 */

import { apiGet, apiPost, API_BASE } from '../core/api.js';
import { buildLiveConnectionParams } from './live-connection-params.js';
import {
  HubApiError,
  ERROR_KIND,
  resolveErrorEntry,
  resolveHttpStatusEntry,
} from '../core/errors.js';
import { HubState } from '../core/states.js';

/** @typedef {'confirmed'|'refuted'|'unknown'} HostProbeFactState */

/** @typedef {{ hubState: string, title: string, message: string, notes: string[] }} DomainStatusDescription */

/** @typedef {{ hubState: string, title: string, message: string, commandLines: string[], notes: string[] }} DomainPreviewDescription */

/** @typedef {{ hubState: string, title: string, message: string, factState: HostProbeFactState, technical: string }} HostProbeDescription */

/** Суффиксы accept-list планировщика KeenDNS — порядок как в keendns_planner.py. */
export const KEENDNS_DOMAIN_OPTIONS = Object.freeze([
  { value: 'keenetic.pro', label: 'keenetic.pro' },
  { value: 'keenetic.name', label: 'keenetic.name' },
  { value: 'keenetic.link', label: 'keenetic.link' },
  { value: 'netcraze.pro', label: 'netcraze.pro' },
  { value: 'netcraze.link', label: 'netcraze.link' },
  { value: 'netcraze.club', label: 'netcraze.club' },
  { value: 'crazedns.ru', label: 'crazedns.ru' },
]);

/** Стартовое имя для простого сценария — пример, не сохранённое на хосте. */
export const DOMAIN_SIMPLE_DEFAULT_NAME = 'promo';

/** Честность: стартовое имя — предложение, не общий дефолт проекта. */
export const DOMAIN_SIMPLE_DEFAULT_NAME_HONESTY =
  'Это стартовое предложение, а не сохранённое имя для всех проектов.';

/** Кратко, почему остаётся шаг с человеком (дополнение к SSOT-тексту гейта). */
export const DOMAIN_SIMPLE_GATE_WHY =
  'Регистрация в облаке выполняется человеком — программа только готовит заявку.';

/** Свободно/занято в облаке отсюда не проверяется. */
export const DOMAIN_SIMPLE_AVAILABILITY_UNKNOWN =
  'Свободно ли имя в облаке, отсюда неизвестно — это можно узнать только при регистрации человеком.';

/** Нейтральное подтверждение формата — не успех и не «доступно». */
export const DOMAIN_SIMPLE_FORMAT_OK =
  'Формат имени подходит для черновика ссылки.';

/** Честность после apply: dispatch ≠ cloud registration. */
export const KEENDNS_APPLY_DISPATCH_HONESTY =
  'Команда отправлена на роутер — это не означает, что имя зарегистрировано в облаке или ссылка уже работает.';

/** Заголовок после успешного dispatch (не live-proven публикация). */
export const KEENDNS_APPLY_DISPATCH_TITLE = 'Команда отправлена на роутер';

/** Режим доступа по умолчанию для book apply (docs-sourced). */
export const KEENDNS_DEFAULT_ACCESS_MODE = 'auto';

/** Подпись автоматического имени CrazeDNS с роутера (observe). */
export const DOMAIN_ROUTER_DEFAULT_FQDN_LABEL = 'Автоматическое имя CrazeDNS на роутере';

/** Подпись личного зарегистрированного имени CrazeDNS с роутера (observe). */
export const DOMAIN_ROUTER_BOOKED_FQDN_LABEL = 'Личное имя в CrazeDNS';

/** Fallback, когда apply вернул failed без деталей с устройства. */
export const KEENDNS_APPLY_FAILED_GENERIC_MESSAGE =
  'Не удалось отправить команду на роутер — публикация в облаке не выполнена.';

/** @typedef {{ default_fqdn?: string|null, ssl_valid?: boolean|null, booked_name?: string|null, booked_domain?: string|null, booked_fqdn?: string|null, access_mode?: string, name_reservation?: string, notes?: string[]|null, certification_eligible?: boolean }} KeendnsObservePayload */

/** Текст для режима «только заявка» (drop / copy path). */
export const DOMAIN_PUBLISH_HUMAN_GATE_TEXT =
  'Регистрация имени в облаке выполняется человеком, а не программой. Этот экран только готовит заявку на публикацию.';

/** Текст подтверждения apply «Опубликовать» — dispatch через программу, не human-only заявка. */
export const DOMAIN_PUBLISH_APPLY_CONFIRM_TEXT =
  'Подтверждение отправит одну команду облачной регистрации имени на роутер через программу. Успех облачной регистрации не считается подтверждённым, пока он не будет проверен отдельно.';

export const DOMAIN_HUMAN_GATE_DOC_PATH = 'docs/HUMAN_GATE_KEENDNS_CLOUD_BOOKING_20260801.md';

/** Пояснение к черновой ссылке. */
export const DOMAIN_DRAFT_LINK_NOTE =
  'Ссылка существует только как черновик для приложения заказов. Кнопка «Опубликовать» отправляет команду регистрации через программу; успех облачной регистрации отдельно не подтверждён.';

/** Маркер для буфера обмена при копировании черновой ссылки. */
export const DOMAIN_DRAFT_CLIPBOARD_MARKER = 'Черновик — ссылка пока не работает';

export const DOMAIN_NOT_PUBLISHED_TITLE = 'Публикация в облаке не выполнена';

export const DOMAIN_EXTERNAL_CHECK_UNSUPPORTED_TEXT =
  'Проверка снаружи (из интернета) не поддерживается';

export const DOMAIN_FORWARDING_UNSUPPORTED_TEXT =
  'Переадресацию через это управление проверить нельзя. Обратитесь к администратору, если она нужна.';

export const DOMAIN_HOST_PROBE_SCOPE_LABEL = 'Проверено с компьютера оператора';

export const DOMAIN_PLAIN_HTTP_WARNING =
  'Адрес приложения указан без защищённого соединения — при проверке готовности мероприятия это будет отмечено.';

export const DOMAIN_PRESET_REVISION_NOTE =
  'Новая версия настроек сохранена, но для гостей ещё не действует.';

const DOMAIN_LABEL_PATTERN = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/;
const MAX_DOMAIN_LABEL_LENGTH = 63;

// Scheme literals below build URLs from operator-entered values — not external resource references.
const HTTPS_SCHEME = 'https://';
const HTTP_SCHEME = 'http://';

const IPV4_PATTERN =
  /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/;

const DNS_HOST_PATTERN =
  /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

/** @type {Readonly<Record<string, string>>} */
const ACCESS_MODE_LABELS = Object.freeze({
  auto: 'автоматический',
  cloud: 'через облако',
  direct: 'прямой',
});

/** Режимы доступа KeenDNS для выбора оператором (документация, не подтверждено на устройстве). */
export const KEENDNS_ACCESS_MODE_OPTIONS = Object.freeze([
  {
    value: 'auto',
    label: 'Автоматический',
    description:
      'Роутер сам подбирает способ доступа. Режим по умолчанию, но перед одобрением его нужно сверить с задачей.',
  },
  {
    value: 'cloud',
    label: 'Через облако',
    description:
      'Доступ через облачный сервис Keenetic/Netcraze. Неверный режим может нарушить ожидания удалённого доступа.',
  },
  {
    value: 'direct',
    label: 'Прямой',
    description:
      'Прямой доступ к устройству. Неверный режим может открыть интерфейс управления или нарушить удалённый доступ.',
  },
]);

/** @type {Readonly<Record<string, string>>} */
const HOST_HTTP_REASON_MESSAGES = Object.freeze({
  'host_http.pending': 'Проверка приложения ещё не выполнялась. Нажмите «Проверить доступность».',
  'host_http.unparseable_url':
    'Адрес приложения не удалось разобрать. Проверьте локальный адрес и сохраните его, затем нажмите «Проверить доступность».',
  'host_http.url_not_allowed':
    'Схема адреса не поддерживается. Проверьте локальный адрес и сохраните его, затем нажмите «Проверить доступность».',
  'host_http.dns_failed':
    'Адрес приложения не найден в сети. Проверьте, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.dns_unavailable':
    'Сейчас не удалось выполнить поиск адреса приложения. Подождите немного и нажмите «Проверить доступность» снова.',
  'host_http.dns_timeout':
    'Не удалось завершить поиск адреса приложения — истекло время ожидания. Подождите немного и нажмите «Проверить доступность» снова.',
  'host_http.target_address_not_allowed':
    'Адрес приложения вне разрешённого диапазона локальной сети. Проверьте локальный адрес и сохраните его, затем нажмите «Проверить доступность».',
  'host_http.timeout':
    'Приложение не ответило вовремя. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.reachable': 'Приложение заказов ответило на запрос',
  'host_http.redirect_not_followed':
    'Приложение перенаправило запрос. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.http_error':
    'Приложение ответило с ошибкой. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.unexpected_status':
    'Ответ приложения не удалось классифицировать. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.connection_refused':
    'Приложение не принимает соединения. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.unreachable':
    'Проверка приложения не удалась. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
  'host_http.preset_not_found':
    'Мероприятие или адрес приложения не найдены. Выберите мероприятие, сохраните локальный адрес и нажмите «Проверить доступность».',
  'host_http.failed':
    'Проверка приложения не удалась. Убедитесь, что адрес сохранён и приложение запущено, затем нажмите «Проверить доступность».',
});

/** @type {Readonly<Record<string, string>>} */
const HOST_TLS_REASON_MESSAGES = Object.freeze({
  'host_tls.pending': 'Проверка сертификата ещё не выполнялась',
  'host_tls.hostname_not_allowed': 'Имя для проверки сертификата не задано — проверка не выполнялась',
  'host_tls.dns_failed': 'Адрес приложения не найден в сети — проверка сертификата не выполнялась.',
  'host_tls.dns_unavailable':
    'Сейчас не удалось выполнить поиск адреса для проверки сертификата. Подождите немного и повторите проверку сертификата.',
  'host_tls.dns_timeout':
    'Не удалось завершить поиск адреса для проверки сертификата — истекло время ожидания. Подождите немного и повторите проверку сертификата.',
  'host_tls.target_address_not_allowed':
    'Адрес приложения вне разрешённого диапазона локальной сети — проверка не выполнялась',
  'host_tls.unreachable': 'До приложения не удалось достучаться — сертификат не проверен',
  'host_tls.no_certificate': 'Сервер не предоставил сертификат — результат неизвестен',
  'host_tls.ok': 'Сертификат доверенный, имя совпадает и срок действия в порядке',
  'host_tls.untrusted_issuer': 'Сертификат недоверенный или самоподписанный — это не подтверждает готовность',
  'host_tls.certificate_expired': 'Срок действия сертификата истёк',
  'host_tls.hostname_mismatch': 'Имя в сертификате не совпадает с адресом приложения',
  'host_tls.partial': 'Сертификат проверен не полностью — результат неизвестен',
  'host_tls.preset_not_found': 'Мероприятие или адрес приложения не найдены — проверка не выполнялась',
  'host_tls.failed': 'Проверка сертификата не удалась',
});

/** @type {Readonly<Record<string, string>>} */
const HOST_INTERNET_REASON_MESSAGES = Object.freeze({
  'host_internet.pending': 'Проверка интернета ещё не выполнялась',
  'host_internet.reachable': 'С этого компьютера есть доступ в интернет',
  'host_internet.dns_unavailable':
    'Сейчас не удалось проверить DNS для доступа в интернет. Подождите немного и нажмите «Проверить доступность» снова.',
  'host_internet.dns_timeout':
    'Не удалось завершить проверку DNS для доступа в интернет — истекло время ожидания. Подождите немного и нажмите «Проверить доступность» снова.',
  'host_internet.offline_or_unreachable': 'С этого компьютера интернет недоступен',
  'host_internet.dns_failed': 'Имена в интернете не находятся — результат неизвестен',
  'host_internet.no_route': 'Маршрут в интернет с этого компьютера не найден — результат неизвестен',
  'host_internet.inconclusive':
    'Часть проверки интернета прошла успешно, часть — нет, поэтому итог неясен. Проверьте подключение к сети и нажмите «Проверить доступность» ещё раз.',
  'host_internet.failed': 'Проверка интернета не удалась',
});

/**
 * @param {string|null|undefined} raw
 * @returns {string}
 */
export function normalizeDomainName(raw) {
  if (typeof raw !== 'string') {
    return '';
  }
  return raw.trim().toLowerCase();
}

/**
 * @returns {string}
 */
export function resolveDomainSimpleDefaultName() {
  return normalizeDomainName(DOMAIN_SIMPLE_DEFAULT_NAME);
}

/**
 * @param {{ name?: string|null, domain?: string|null }} params
 * @returns {{
 *   valid: boolean,
 *   formatMessage: string|null,
 *   availabilityMessage: string,
 *   draftUrl: string|null,
 *   draftNote: string,
 * }}
 */
export function describeDomainSimpleNameState({ name, domain }) {
  const validation = validateDomainName(name);
  const draftUrl = buildDraftUrl({ name, domain });
  return {
    valid: validation.valid,
    formatMessage: validation.valid ? DOMAIN_SIMPLE_FORMAT_OK : validation.reason,
    availabilityMessage: DOMAIN_SIMPLE_AVAILABILITY_UNKNOWN,
    draftUrl,
    draftNote: DOMAIN_DRAFT_LINK_NOTE,
  };
}

/**
 * @param {string|null|undefined} raw
 * @returns {{ valid: boolean, reason: string|null }}
 */
export function validateDomainName(raw) {
  const name = normalizeDomainName(raw);
  if (!name) {
    return { valid: false, reason: 'Укажите имя для черновика ссылки.' };
  }
  if (name.length > MAX_DOMAIN_LABEL_LENGTH) {
    return {
      valid: false,
      reason:
        'Имя слишком длинное — не более 63 символов. Это ограничение экрана для сборки черновика ссылки, а не правило роутера.',
    };
  }
  if (!DOMAIN_LABEL_PATTERN.test(name)) {
    return {
      valid: false,
      reason:
        'Имя может содержать только латинские буквы, цифры и дефис и не может начинаться или заканчиваться дефисом. Это ограничение экрана для сборки черновика ссылки, а не правило роутера.',
    };
  }
  return { valid: true, reason: null };
}

/**
 * @param {{ name?: string|null, domain?: string|null }} params
 * @returns {string|null}
 */
export function buildDraftUrl({ name, domain }) {
  const validation = validateDomainName(name);
  if (!validation.valid) {
    return null;
  }
  const normalizedDomain = typeof domain === 'string' ? domain.trim().toLowerCase() : '';
  if (!normalizedDomain) {
    return null;
  }
  return `${HTTPS_SCHEME}${normalizeDomainName(name)}.${normalizedDomain}`;
}

/**
 * @param {unknown} statusResponse
 * @returns {DomainStatusDescription}
 */
export function describeKeendnsStatus(statusResponse) {
  const payload = /** @type {Record<string, unknown>} */ (statusResponse ?? {});
  const featureAvailability =
    typeof payload.feature_availability === 'string' ? payload.feature_availability : 'unknown';
  const nameReservation =
    typeof payload.name_reservation === 'string' ? payload.name_reservation : 'unknown';
  const accessMode = typeof payload.access_mode === 'string' ? payload.access_mode : 'unknown';
  const notes = Array.isArray(payload.notes)
    ? payload.notes.filter((item) => typeof item === 'string')
    : [];

  if (featureAvailability === 'unavailable') {
    return {
      hubState: HubState.WARNING,
      title: DOMAIN_NOT_PUBLISHED_TITLE,
      message:
        'На роутере нет нужного компонента для облачного имени — состояние публикации неизвестно.',
      notes,
    };
  }

  if (
    featureAvailability === 'unknown'
    && nameReservation === 'unknown'
    && accessMode === 'unknown'
  ) {
    return {
      hubState: HubState.WARNING,
      title: DOMAIN_NOT_PUBLISHED_TITLE,
      message:
        'Регистрация имени в облаке отсюда не проверялась: эта проверка работает без обращения к облаку и не может установить, зарегистрировано ли имя.',
      notes,
    };
  }

  /** @type {string[]} */
  const detailParts = [];
  if (featureAvailability !== 'unknown') {
    detailParts.push('доступность компонента не подтверждена полностью');
  }
  if (nameReservation === 'reserved') {
    detailParts.push('имя может быть зарезервировано, но публикация не подтверждена');
  } else if (nameReservation === 'not_reserved') {
    detailParts.push('имя не зарезервировано');
  }
  if (accessMode !== 'unknown') {
    detailParts.push('режим доступа не подтверждён как рабочий');
  }

  const message =
    detailParts.length > 0
      ? `Состояние публикации в облаке неизвестно: ${detailParts.join('; ')}.`
      : 'Состояние публикации в облаке неизвестно.';

  return {
    hubState: HubState.WARNING,
    title: DOMAIN_NOT_PUBLISHED_TITLE,
    message,
    notes,
  };
}

/**
 * @param {unknown} previewResponse
 * @returns {DomainPreviewDescription}
 */
export function describePreview(previewResponse) {
  const payload = /** @type {Record<string, unknown>} */ (previewResponse ?? {});
  const verificationStatus =
    typeof payload.verification_status === 'string' ? payload.verification_status : null;
  const previewOps = Array.isArray(payload.preview_ops) ? payload.preview_ops : [];
  /** @type {string[]} */
  const commandLines = [];
  for (const op of previewOps) {
    if (!op || typeof op !== 'object') {
      continue;
    }
    const entry = /** @type {Record<string, unknown>} */ (op);
    if (typeof entry.command_text === 'string' && entry.command_text.trim()) {
      commandLines.push(entry.command_text.trim());
    }
  }
  const notes = Array.isArray(payload.notes)
    ? payload.notes.filter((item) => typeof item === 'string')
    : [];

  /** @type {string} */
  let message = 'Предпросмотр команд для облачной регистрации подготовлен.';
  if (verificationStatus === 'documentation_sourced_unconfirmed') {
    message =
      'Команды взяты из документации и не подтверждены на устройстве — это только черновик заявки, не выполненная запись.';
  }

  return {
    hubState: HubState.WARNING,
    title: 'Предпросмотр публикации',
    message,
    commandLines,
    notes,
  };
}

/**
 * @param {string|null|undefined} url
 * @returns {{ scheme: string|null, host: string|null, port: number|null, hostPort: string|null, path: string, valid: boolean }}
 */
export function parseLocalOrderUrl(url) {
  const empty = {
    scheme: null,
    host: null,
    port: null,
    hostPort: null,
    path: '/',
    valid: false,
  };
  if (typeof url !== 'string' || !url.trim()) {
    return empty;
  }
  try {
    const parsed = new URL(url.trim());
    const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return empty;
    }
    const host = parsed.hostname || null;
    if (!host) {
      return empty;
    }
    const port = parsed.port ? Number(parsed.port) : scheme === 'https' ? 443 : 80;
    const hostPort =
      (scheme === 'https' && port === 443) || (scheme === 'http' && port === 80)
        ? host
        : `${host}:${port}`;
    const path = `${parsed.pathname || '/'}${parsed.search || ''}`;
    return {
      scheme,
      host,
      port,
      hostPort,
      path,
      valid: true,
    };
  } catch {
    return empty;
  }
}

/**
 * @param {string|null|undefined} hostPort
 * @returns {{ host: string|null, port: number|null, valid: boolean }}
 */
function parseHostPort(hostPort) {
  if (typeof hostPort !== 'string' || !hostPort.trim()) {
    return { host: null, port: null, valid: false };
  }
  const trimmed = hostPort.trim();
  const colonIndex = trimmed.lastIndexOf(':');
  let hostPart = trimmed;
  let portPart = null;
  if (colonIndex > 0 && colonIndex < trimmed.length - 1) {
    const maybePort = trimmed.slice(colonIndex + 1);
    if (/^\d+$/.test(maybePort)) {
      hostPart = trimmed.slice(0, colonIndex);
      portPart = maybePort;
    }
  }
  const host = hostPart.trim();
  if (!host) {
    return { host: null, port: null, valid: false };
  }
  const hostLower = host.toLowerCase();
  const hostValid = IPV4_PATTERN.test(host) || DNS_HOST_PATTERN.test(hostLower);
  if (!hostValid) {
    return { host: null, port: null, valid: false };
  }
  let port = portPart ? Number(portPart) : null;
  if (portPart != null && (!Number.isInteger(port) || port < 1 || port > 65535)) {
    return { host: null, port: null, valid: false };
  }
  return { host: hostLower, port, valid: true };
}

/**
 * @param {{ hostPort?: string|null, https?: boolean, path?: string|null }} params
 * @returns {string|null}
 */
export function buildLocalOrderUrl({ hostPort, https = true, path = null }) {
  const parsed = parseHostPort(hostPort);
  if (!parsed.valid || !parsed.host) {
    return null;
  }
  const scheme = https ? HTTPS_SCHEME : HTTP_SCHEME;
  const defaultPort = https ? 443 : 80;
  const port = parsed.port ?? defaultPort;
  const authority =
    port === defaultPort ? parsed.host : `${parsed.host}:${port}`;
  let normalizedPath = '/';
  if (typeof path === 'string' && path.trim()) {
    normalizedPath = path.startsWith('/') ? path : `/${path}`;
  }
  return `${scheme}${authority}${normalizedPath}`;
}

/**
 * @param {string|null|undefined} reasonCode
 * @param {Readonly<Record<string, string>>} map
 * @returns {string}
 */
function reasonMessage(reasonCode, map) {
  if (reasonCode && map[reasonCode]) {
    return map[reasonCode];
  }
  return 'Результат проверки неизвестен.';
}

/**
 * @param {unknown} response
 * @returns {HostProbeDescription}
 */
export function describeHostHttpProbe(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const reasonCode = typeof payload.reason_code === 'string' ? payload.reason_code : 'host_http.pending';
  const reachable = typeof payload.reachable === 'boolean' ? payload.reachable : null;
  const title = 'Локальное приложение отвечает (с компьютера оператора)';

  if (reasonCode.endsWith('target_address_not_allowed')) {
    return {
      hubState: HubState.EMPTY,
      title,
      message: HOST_HTTP_REASON_MESSAGES['host_http.target_address_not_allowed'],
      factState: 'unknown',
      technical: buildHostProbeTechnical(payload, reasonCode),
    };
  }

  if (reachable === true) {
    return {
      hubState: HubState.SUCCESS,
      title,
      message: HOST_HTTP_REASON_MESSAGES['host_http.reachable'],
      factState: 'confirmed',
      technical: buildHostProbeTechnical(payload, reasonCode),
    };
  }

  if (reachable === false) {
    return {
      hubState: HubState.ERROR,
      title,
      message: reasonMessage(reasonCode, HOST_HTTP_REASON_MESSAGES),
      factState: 'refuted',
      technical: buildHostProbeTechnical(payload, reasonCode),
    };
  }

  return {
    hubState: HubState.EMPTY,
    title,
    message: reasonMessage(reasonCode, HOST_HTTP_REASON_MESSAGES),
    factState: 'unknown',
    technical: buildHostProbeTechnical(payload, reasonCode),
  };
}

/**
 * @param {unknown} response
 * @returns {HostProbeDescription}
 */
export function describeHostTlsProbe(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const reasonCode = typeof payload.reason_code === 'string' ? payload.reason_code : 'host_tls.pending';
  const aggregateStatus =
    typeof payload.aggregate_status === 'string' ? payload.aggregate_status : 'unknown';
  const title = 'Сертификат локального приложения (с компьютера оператора)';

  /** @type {string[]} */
  const technicalLines = [buildHostProbeTechnical(payload, reasonCode)];
  const leafOnlyNote =
    'Проверен только сертификат сервера — полная цепочка не разбирается.';
  if (payload.chain_inspected === false) {
    technicalLines.push(
      'chain_inspected: false — проверен только сертификат сервера, цепочка не разбирается',
    );
  }

  if (reasonCode.endsWith('target_address_not_allowed')) {
    return {
      hubState: HubState.EMPTY,
      title,
      message: HOST_TLS_REASON_MESSAGES['host_tls.target_address_not_allowed'],
      factState: 'unknown',
      technical: technicalLines.filter(Boolean).join('\n'),
    };
  }

  if (aggregateStatus === 'ok') {
    const okMessage =
      payload.chain_inspected === false
        ? `${HOST_TLS_REASON_MESSAGES['host_tls.ok']} ${leafOnlyNote}`
        : HOST_TLS_REASON_MESSAGES['host_tls.ok'];
    return {
      hubState: HubState.SUCCESS,
      title,
      message: okMessage,
      factState: 'confirmed',
      technical: technicalLines.filter(Boolean).join('\n'),
    };
  }

  if (aggregateStatus === 'warning') {
    const baseMessage = reasonMessage(reasonCode, HOST_TLS_REASON_MESSAGES);
    const warningMessage =
      payload.chain_inspected === false ? `${baseMessage} ${leafOnlyNote}` : baseMessage;
    return {
      hubState: HubState.WARNING,
      title,
      message: warningMessage,
      factState: 'unknown',
      technical: technicalLines.filter(Boolean).join('\n'),
    };
  }

  if (aggregateStatus === 'failed') {
    const baseMessage = reasonMessage(reasonCode, HOST_TLS_REASON_MESSAGES);
    const failedMessage =
      payload.chain_inspected === false ? `${baseMessage} ${leafOnlyNote}` : baseMessage;
    return {
      hubState: HubState.ERROR,
      title,
      message: failedMessage,
      factState: 'refuted',
      technical: technicalLines.filter(Boolean).join('\n'),
    };
  }

  return {
    hubState: HubState.EMPTY,
    title,
    message: reasonMessage(reasonCode, HOST_TLS_REASON_MESSAGES),
    factState: 'unknown',
    technical: technicalLines.filter(Boolean).join('\n'),
  };
}

/**
 * @param {unknown} response
 * @returns {HostProbeDescription}
 */
export function describeHostInternetProbe(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const reasonCode =
    typeof payload.reason_code === 'string' ? payload.reason_code : 'host_internet.pending';
  const internetReachable =
    typeof payload.internet_reachable === 'boolean' ? payload.internet_reachable : null;
  const title = 'Интернет с компьютера оператора';

  if (internetReachable === true) {
    return {
      hubState: HubState.SUCCESS,
      title,
      message: HOST_INTERNET_REASON_MESSAGES['host_internet.reachable'],
      factState: 'confirmed',
      technical: buildHostProbeTechnical(payload, reasonCode),
    };
  }

  if (internetReachable === false) {
    return {
      hubState: HubState.ERROR,
      title,
      message: HOST_INTERNET_REASON_MESSAGES['host_internet.offline_or_unreachable'],
      factState: 'refuted',
      technical: buildHostProbeTechnical(payload, reasonCode),
    };
  }

  return {
    hubState: HubState.EMPTY,
    title,
    message: reasonMessage(reasonCode, HOST_INTERNET_REASON_MESSAGES),
    factState: 'unknown',
    technical: buildHostProbeTechnical(payload, reasonCode),
  };
}

/**
 * @param {Record<string, unknown>} payload
 * @param {string} reasonCode
 * @returns {string}
 */
function buildHostProbeTechnical(payload, reasonCode) {
  /** @type {string[]} */
  const lines = [`reason_code: ${reasonCode}`];
  if (typeof payload.checked_from === 'string') {
    lines.push(`checked_from: ${payload.checked_from}`);
  }
  if (typeof payload.http_status_class === 'string') {
    lines.push(`http_status_class: ${payload.http_status_class}`);
  }
  if (typeof payload.latency_ms === 'number') {
    lines.push(`latency_ms: ${payload.latency_ms}`);
  }
  if (typeof payload.aggregate_status === 'string') {
    lines.push(`aggregate_status: ${payload.aggregate_status}`);
  }
  if (typeof payload.dns_ok === 'boolean') {
    lines.push(`dns_ok: ${payload.dns_ok}`);
  }
  if (typeof payload.tcp_ok === 'boolean') {
    lines.push(`tcp_ok: ${payload.tcp_ok}`);
  }
  if (Array.isArray(payload.notes) && payload.notes.length > 0) {
    lines.push(`notes: ${payload.notes.map(String).join('; ')}`);
  }
  return lines.join('\n');
}

/**
 * @param {{ includeMode?: boolean, modeLabel?: string|null }} [params]
 * @returns {string[]}
 */
function buildHumanGateChecklistLines({ includeMode = false, modeLabel = null } = {}) {
  /** @type {string[]} */
  const lines = [
    '',
    'Что должен подтвердить человек, одобряющий заявку:',
    '- Это внешняя запись в облако Keenetic/Netcraze — программа её не выполняет без явного одобрения человека.',
    '- Вы контролируете облачный аккаунт, к которому привязано устройство (какой именно аккаунт — отсюда не установлено).',
    '- На роутере установлен компонент для облачного имени (встроенная облачная служба имён); если его нет — нужно отдельное одобрение на установку.',
  ];
  if (includeMode && modeLabel) {
    lines.push(
      `- Режим доступа «${modeLabel}» выбран оператором на экране — его нужно подтвердить перед одобрением (неверный режим может открыть интерфейс управления или нарушить удалённый доступ).`,
    );
  }
  lines.push(
    '- Список доменов взятый из документации — на целевом устройстве список разрешённых доменов на роутере нужно проверить отдельно перед регистрацией.',
    '- Вы согласны на передачу данных (имя, домен, привязка устройства) во внешнее облако вендора.',
    '- Понятен план отката: освобождение имени — отдельное одобренное действие; автоматического отката нет.',
    '- Команды ниже взяты из документации и не подтверждены на этом устройстве.',
    `- Документ для человека, одобряющего заявку: ${DOMAIN_HUMAN_GATE_DOC_PATH}`,
  );
  return lines;
}

/**
 * @param {{ name?: string|null, domain?: string|null, mode?: string|null, localOrderUrl?: string|null }} params
 * @returns {string}
 */
export function buildPublishRequestSummary({ name, domain, mode, localOrderUrl }) {
  const normalizedName = typeof name === 'string' ? normalizeDomainName(name) : '';
  const normalizedDomain = typeof domain === 'string' ? domain.trim() : '';
  const normalizedMode = typeof mode === 'string' ? mode.trim() : '';
  const modeLabel = ACCESS_MODE_LABELS[normalizedMode] ?? (normalizedMode || 'не указан');
  const bookCommand =
    normalizedName && normalizedDomain && normalizedMode
      ? `ndns book-name ${normalizedName} ${normalizedDomain} ${normalizedMode}`
      : 'команда не собрана — проверьте имя, домен и режим';

  /** @type {string[]} */
  const lines = [
    'Заявка на регистрацию имени в облаке Keenetic',
    '',
    `Имя: ${normalizedName || 'не указано'}`,
    `Домен: ${normalizedDomain || 'не указан'}`,
    `Режим доступа: ${modeLabel} (выбран оператором на экране — требует подтверждения перед одобрением)`,
    '',
    'Команда для специалиста (из документации, на этом устройстве не подтверждена):',
    bookCommand,
    ...buildHumanGateChecklistLines({ includeMode: true, modeLabel }),
  ];

  if (typeof localOrderUrl === 'string' && localOrderUrl.trim()) {
    lines.push(
      '',
      `Локальный адрес приложения (сохранённый адрес в настройках мероприятия): ${localOrderUrl.trim()}`,
    );
  }

  return lines.join('\n');
}

/**
 * @param {{ name?: string|null, domain?: string|null, localOrderUrl?: string|null }} params
 * @returns {string}
 */
export function buildReleaseRequestSummary({ name, domain, localOrderUrl }) {
  const normalizedName = typeof name === 'string' ? normalizeDomainName(name) : '';
  const normalizedDomain = typeof domain === 'string' ? domain.trim() : '';
  const dropCommand =
    normalizedName && normalizedDomain
      ? `ndns drop-name ${normalizedName} ${normalizedDomain}`
      : 'команда не собрана — проверьте имя и домен';

  /** @type {string[]} */
  const lines = [
    'Заявка на освобождение (отключение) имени в облаке Keenetic',
    '',
    `Имя: ${normalizedName || 'не указано'}`,
    `Домен: ${normalizedDomain || 'не указан'}`,
    '',
    'Команда для специалиста (из документации, на этом устройстве не подтверждена):',
    dropCommand,
    ...buildHumanGateChecklistLines(),
  ];

  if (typeof localOrderUrl === 'string' && localOrderUrl.trim()) {
    lines.push(
      '',
      `Локальный адрес приложения (сохранённый адрес в настройках мероприятия): ${localOrderUrl.trim()}`,
    );
  }

  return lines.join('\n');
}

/**
 * @param {string} url
 * @returns {string}
 */
export function formatDraftClipboardContent(url) {
  return `${DOMAIN_DRAFT_CLIPBOARD_MARKER}\n${url}`;
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @returns {{ allowed: boolean, reasonText: string|null }}
 */
export function evaluateDomainPresetReadiness(session) {
  const presetId =
    session && typeof session.eventPresetId === 'string' ? session.eventPresetId.trim() : '';
  if (!presetId) {
    return {
      allowed: false,
      reasonText: 'Чтобы менять локальный адрес приложения, выберите мероприятие в верхней панели.',
    };
  }
  return { allowed: true, reasonText: null };
}

/**
 * @param {{ hasEventPresets: boolean|null }} params
 * @returns {{ title: string, description: string }}
 */
export function describeDomainEventEmptyState({ hasEventPresets }) {
  if (hasEventPresets === false) {
    return {
      title: 'Мероприятие ещё не создано',
      description:
        'Мероприятие пока не создано. Адрес приложения хранится в настройках мероприятия — эта часть экрана станет доступна, когда мероприятие появится.',
    };
  }
  return {
    title: 'Мероприятие не выбрано',
    description:
      'Выберите мероприятие в селекторе верхней панели, чтобы задать локальный адрес приложения.',
  };
}

/**
 * @param {{ siteId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function loadSiteEventPresets({ siteId, signal }) {
  return apiGet(`sites/${siteId}/event-presets`, { signal });
}

/**
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<unknown>}
 */
export function loadHubStatus({ signal } = {}) {
  return apiGet('status', { signal });
}

/**
 * @param {Response} response
 * @returns {Promise<HubApiError>}
 */
async function buildApiErrorFromResponse(response) {
  const headerRequestId = response.headers.get('X-Request-Id');
  const headerCorrelationId = response.headers.get('X-Correlation-Id');
  const httpStatus = response.status;

  let payload = null;
  try {
    const text = await response.text();
    if (text) payload = JSON.parse(text);
  } catch {
    payload = null;
  }

  if (payload?.error?.code) {
    const envelope = payload.error;
    const entry = resolveErrorEntry(envelope.code);
    return new HubApiError({
      code: envelope.code,
      httpStatus,
      userMessage: entry.userMessage,
      userAction: entry.userAction,
      serverMessage: envelope.message ?? null,
      details: Array.isArray(envelope.details) ? envelope.details : [],
      requestId: envelope.request_id ?? headerRequestId,
      correlationId: envelope.correlation_id ?? headerCorrelationId,
      kind: entry.kind,
    });
  }

  const entry = resolveHttpStatusEntry(httpStatus);
  const serverMessage =
    payload?.error?.message ??
    (typeof payload?.detail === 'string' ? payload.detail : null);

  return new HubApiError({
    code: `http.${httpStatus}`,
    httpStatus,
    userMessage: entry.userMessage,
    userAction: entry.userAction,
    serverMessage,
    details: payload?.error?.details ?? [],
    requestId: headerRequestId,
    correlationId: headerCorrelationId,
    kind: entry.kind,
  });
}

/**
 * @param {string} path
 * @param {unknown} body
 * @param {Record<string, string>} extraHeaders
 * @param {{ signal?: AbortSignal, timeoutMs?: number }} [options]
 * @returns {Promise<unknown>}
 */
async function postWithHeaders(path, body, extraHeaders, { signal, timeoutMs = 15000 } = {}) {
  const timeoutController = new AbortController();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    timeoutController.abort();
  }, timeoutMs);

  /** @type {AbortSignal} */
  let combinedSignal = timeoutController.signal;
  /** @type {(() => void)|null} */
  let detachAbortListeners = null;
  if (signal) {
    if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {
      combinedSignal = AbortSignal.any([signal, timeoutController.signal]);
    } else {
      const merged = new AbortController();
      const forwardAbort = () => {
        const reason = signal.aborted ? signal.reason : timeoutController.signal.reason;
        merged.abort(reason);
      };
      const onSignalAbort = () => forwardAbort();
      const onTimeoutAbort = () => forwardAbort();
      if (signal.aborted || timeoutController.signal.aborted) {
        forwardAbort();
      } else {
        signal.addEventListener('abort', onSignalAbort);
        timeoutController.signal.addEventListener('abort', onTimeoutAbort);
      }
      combinedSignal = merged.signal;
      detachAbortListeners = () => {
        signal.removeEventListener('abort', onSignalAbort);
        timeoutController.signal.removeEventListener('abort', onTimeoutAbort);
      };
    }
  }

  const url = path.startsWith('/') ? path : `${API_BASE}/${path.replace(/^\//, '')}`;
  const init = {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      ...extraHeaders,
    },
    body: JSON.stringify(body),
    signal: combinedSignal,
  };

  try {
    const response = await fetch(url, init);

    if (!response.ok) {
      throw await buildApiErrorFromResponse(response);
    }

    if (response.status === 204) {
      return null;
    }

    const contentType = response.headers.get('Content-Type') ?? '';
    if (!contentType.includes('application/json')) {
      return null;
    }

    return await response.json();
  } catch (error) {
    if (error instanceof HubApiError) {
      throw error;
    }

    if (combinedSignal.aborted) {
      if (timedOut) {
        throw new HubApiError({
          code: 'client.timeout',
          httpStatus: null,
          userMessage: 'Сервер не ответил вовремя.',
          userAction: 'Проверьте сеть и повторите запрос.',
          serverMessage: null,
          details: [],
          requestId: null,
          correlationId: null,
          kind: ERROR_KIND.TIMEOUT,
        });
      }

      throw new HubApiError({
        code: 'client.aborted',
        httpStatus: null,
        userMessage: 'Запрос был отменён.',
        userAction: 'Повторите действие, если это необходимо.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.ABORTED,
      });
    }

    if (error instanceof TypeError) {
      throw new HubApiError({
        code: 'client.network',
        httpStatus: null,
        userMessage: 'Нет связи с сервером.',
        userAction: 'Проверьте, что iPad подключён к рабочей сети, и повторите.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.NETWORK,
      });
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
    detachAbortListeners?.();
  }
}

/**
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<unknown>}
 */
export function loadKeendnsStatus({ signal } = {}) {
  return apiPost('keendns/status', {}, { signal });
}

/**
 * @param {unknown} response
 * @returns {KeendnsObservePayload|null}
 */
export function normalizeKeendnsObserve(response) {
  if (!response || typeof response !== 'object') {
    return null;
  }
  const payload = /** @type {Record<string, unknown>} */ (response);
  return {
    default_fqdn:
      typeof payload.default_fqdn === 'string' && payload.default_fqdn.trim()
        ? payload.default_fqdn.trim()
        : null,
    ssl_valid: typeof payload.ssl_valid === 'boolean' ? payload.ssl_valid : null,
    booked_name:
      typeof payload.booked_name === 'string' && payload.booked_name.trim()
        ? payload.booked_name.trim()
        : null,
    booked_domain:
      typeof payload.booked_domain === 'string' && payload.booked_domain.trim()
        ? payload.booked_domain.trim()
        : null,
    booked_fqdn:
      typeof payload.booked_fqdn === 'string' && payload.booked_fqdn.trim()
        ? payload.booked_fqdn.trim()
        : null,
    access_mode: typeof payload.access_mode === 'string' ? payload.access_mode : 'unknown',
    name_reservation:
      typeof payload.name_reservation === 'string' ? payload.name_reservation : 'unknown',
    notes: Array.isArray(payload.notes)
      ? payload.notes.filter((item) => typeof item === 'string')
      : [],
  };
}

/**
 * @param {{ session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<KeendnsObservePayload|null>}
 */
export async function fetchKeendnsObserve({ session, signal }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    return null;
  }
  const response = await apiPost('keendns/observe', live.params, { signal });
  return normalizeKeendnsObserve(response);
}

/**
 * @param {{ name: string, domain: string, mode: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function previewKeendnsBooking({ name, domain, mode, signal }) {
  return apiPost(
    'keendns/preview',
    { intent_kind: 'book', name, domain, mode },
    { signal },
  );
}

/**
 * @param {{ name: string, domain: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function previewKeendnsDrop({ name, domain, signal }) {
  return apiPost('keendns/preview', { intent_kind: 'drop', name, domain }, { signal });
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot
 * @param {Record<string, unknown>} liveParams
 * @param {Record<string, unknown>} body
 */
function attachLiveConnectionFields(snapshot, liveParams, body) {
  if (liveParams.host) body.host = liveParams.host;
  if (liveParams.username) body.username = liveParams.username;
  if (liveParams.router_credential_ref_id) {
    body.router_credential_ref_id = liveParams.router_credential_ref_id;
  }
  if (liveParams.ssh_host_key_sha256) {
    body.ssh_host_key_sha256 = liveParams.ssh_host_key_sha256;
  }
  if (liveParams.source_address) body.source_address = liveParams.source_address;
  if (liveParams.router_id) body.router_id = liveParams.router_id;
  void snapshot;
}

/**
 * @param {{ name: string, domain: string, mode?: string, session: import('../core/session.js').SessionSnapshot|null|undefined }} params
 * @returns {Record<string, unknown>}
 */
export function buildKeendnsApplyBody({ name, domain, mode, session }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для публикации не хватает параметров живого подключения');
  }
  /** @type {Record<string, unknown>} */
  const body = {
    intent_kind: 'book',
    name: normalizeDomainName(name),
    domain: typeof domain === 'string' ? domain.trim().toLowerCase() : '',
    mode: mode ?? KEENDNS_DEFAULT_ACCESS_MODE,
    confirm_live_apply: true,
  };
  attachLiveConnectionFields(session, live.params, body);
  return body;
}

/**
 * @param {{ name: string, domain: string, mode?: string, session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function applyKeendnsBooking({ name, domain, mode, session, signal }) {
  const body = buildKeendnsApplyBody({ name, domain, mode, session });
  return apiPost('keendns/apply', body, { signal, timeoutMs: 60000 });
}

/**
 * @param {KeendnsObservePayload|null|undefined} observe
 * @returns {string|null}
 */
export function resolveKeendnsBookedFqdn(observe) {
  if (!observe || typeof observe !== 'object') {
    return null;
  }
  if (typeof observe.booked_fqdn === 'string' && observe.booked_fqdn.trim()) {
    return observe.booked_fqdn.trim();
  }
  const bookedName =
    typeof observe.booked_name === 'string' && observe.booked_name.trim()
      ? observe.booked_name.trim()
      : null;
  const bookedDomain =
    typeof observe.booked_domain === 'string' && observe.booked_domain.trim()
      ? observe.booked_domain.trim()
      : null;
  if (bookedName && bookedDomain) {
    return `${bookedName}.${bookedDomain}`;
  }
  return null;
}

/** @type {RegExp} */
const KEENDNS_FAILED_BOOK_FQDN_PATTERN = /failed to book\s+"([^"]+)"/i;

/**
 * @param {string} text
 * @returns {boolean}
 */
function keendnsFailureTextIndicatesNameTaken(text) {
  const lower = text.toLowerCase();
  return (
    lower.includes('not available')
    || lower.includes('taken')
    || lower.includes('failed to book')
  );
}

/**
 * @param {string[]} texts
 * @returns {string|null}
 */
function parseKeendnsTakenFqdnFromTexts(texts) {
  for (const text of texts) {
    const match = KEENDNS_FAILED_BOOK_FQDN_PATTERN.exec(text);
    if (match?.[1]?.trim()) {
      return match[1].trim();
    }
  }
  return null;
}

/**
 * @param {Record<string, unknown>} payload
 * @returns {string[]}
 */
function collectKeendnsApplyFailureTexts(payload) {
  /** @type {string[]} */
  const texts = [];

  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  for (const step of steps) {
    if (!step || typeof step !== 'object') {
      continue;
    }
    const entry = /** @type {Record<string, unknown>} */ (step);
    if (typeof entry.error === 'string' && entry.error.trim()) {
      texts.push(entry.error.trim());
    }
  }

  const logs = Array.isArray(payload.logs) ? payload.logs : [];
  for (const log of logs) {
    if (typeof log === 'string' && log.trim()) {
      texts.push(log.trim());
    }
  }

  for (const note of Array.isArray(payload.notes) ? payload.notes : []) {
    if (typeof note === 'string' && note.trim()) {
      texts.push(note.trim());
    }
  }

  return texts;
}

/**
 * @param {Record<string, unknown>} payload
 * @param {string[]} failureTexts
 * @returns {string|null}
 */
function resolveKeendnsApplyIntentFqdn(payload, failureTexts) {
  const fromFailure = parseKeendnsTakenFqdnFromTexts(failureTexts);
  if (fromFailure) {
    return fromFailure;
  }
  const name = typeof payload.name === 'string' ? normalizeDomainName(payload.name) : '';
  const domain = typeof payload.domain === 'string' ? payload.domain.trim().toLowerCase() : '';
  if (name && domain) {
    return `${name}.${domain}`;
  }
  return null;
}

/**
 * @param {string|null|undefined} fqdn
 * @returns {string}
 */
export function describeKeendnsNameTakenFailureMessage(fqdn) {
  const trimmed = typeof fqdn === 'string' ? fqdn.trim() : '';
  if (trimmed) {
    return `Имя ${trimmed} уже занято в облаке — выберите другое имя для публикации.`;
  }
  return 'Это имя уже занято в облаке — выберите другое имя для публикации.';
}

/**
 * @param {string} detail
 * @returns {string}
 */
function describeKeendnsApplyDeviceFailureMessage(detail) {
  const trimmed = detail.trim();
  const colonIdx = trimmed.indexOf(': ');
  const tail = colonIdx >= 0 ? trimmed.slice(colonIdx + 2).trim() : trimmed;
  if (keendnsFailureTextIndicatesNameTaken(tail) || keendnsFailureTextIndicatesNameTaken(trimmed)) {
    const fqdn = parseKeendnsTakenFqdnFromTexts([trimmed, tail]);
    return describeKeendnsNameTakenFailureMessage(fqdn);
  }
  if (/^[a-z0-9._-]+$/i.test(tail) && tail.includes('.')) {
    return `Не удалось зарегистрировать имя в облаке: ${tail}.`;
  }
  return `Не удалось зарегистрировать имя в облаке: ${tail || trimmed}.`;
}

/**
 * @param {unknown} applyResponse
 * @returns {{ hubState: string, title: string, message: string, notes: string[] }}
 */
export function describeKeendnsApplyOutcome(applyResponse) {
  const payload = /** @type {Record<string, unknown>} */ (applyResponse ?? {});
  const overall = typeof payload.overall === 'string' ? payload.overall : 'failed';
  const notes = Array.isArray(payload.notes)
    ? payload.notes.filter((item) => typeof item === 'string')
    : [];

  if (overall === 'failed') {
    const failureTexts = collectKeendnsApplyFailureTexts(payload);
    const indicatesTaken = failureTexts.some(keendnsFailureTextIndicatesNameTaken);
    /** @type {string} */
    let message = KEENDNS_APPLY_FAILED_GENERIC_MESSAGE;
    if (indicatesTaken) {
      message = describeKeendnsNameTakenFailureMessage(
        resolveKeendnsApplyIntentFqdn(payload, failureTexts),
      );
    } else if (failureTexts.length > 0) {
      const preferred = failureTexts.find((text) => text.includes(': ')) ?? failureTexts[0];
      message = describeKeendnsApplyDeviceFailureMessage(preferred);
    }
    return {
      hubState: HubState.ERROR,
      title: DOMAIN_NOT_PUBLISHED_TITLE,
      message,
      notes,
    };
  }

  if (overall === 'dispatched_offline') {
    return {
      hubState: HubState.WARNING,
      title: 'Команда не отправлена на роутер',
      message:
        'Команда выполнена без связи с роутером — на устройстве настройки не менялись. Проверьте подключение и повторите.',
      notes,
    };
  }

  return {
    hubState: HubState.WARNING,
    title: KEENDNS_APPLY_DISPATCH_TITLE,
    message: KEENDNS_APPLY_DISPATCH_HONESTY,
    notes,
  };
}

/**
 * @param {{ presetId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function loadEventPreset({ presetId, signal }) {
  return apiGet(`event-presets/${presetId}`, { signal });
}

/**
 * @param {{ presetId: string, revisionId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function loadEventPresetRevision({ presetId, revisionId, signal }) {
  return apiGet(`event-presets/${presetId}/revisions/${revisionId}`, { signal });
}

/**
 * @param {{ presetId: string, revisionId: string, document: Record<string, unknown>, localOrderUrl: string, etag?: string|null, idempotencyKey: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function saveLocalOrderUrl({
  presetId,
  revisionId,
  document,
  localOrderUrl,
  etag = null,
  idempotencyKey,
  signal,
}) {
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw new Error('Документ пресета должен быть непустым объектом');
  }
  const keys = Object.keys(document);
  if (keys.length === 0) {
    throw new Error('Документ пресета должен быть непустым объектом');
  }

  /** @type {Record<string, string>} */
  const headers = { 'Idempotency-Key': idempotencyKey };
  if (typeof etag === 'string' && etag.trim()) {
    headers['If-Match'] = etag.trim();
  }

  void revisionId;

  return postWithHeaders(
    `event-presets/${presetId}/revisions`,
    {
      document: {
        ...document,
        local_order_url: localOrderUrl,
      },
    },
    headers,
    { signal },
  );
}

/**
 * @param {{ presetId: string, revisionId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function probeLocalApplicationHttp({ presetId, revisionId, signal }) {
  return apiPost(
    'lab/host-http-probe',
    {
      url_ref: 'event_preset_local_order_url',
      preset_id: presetId,
      revision_id: revisionId,
    },
    { signal },
  );
}

/**
 * @param {{ presetId: string, revisionId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function probeLocalApplicationTls({ presetId, revisionId, signal }) {
  return apiPost(
    'lab/host-tls-probe',
    {
      hostname_ref: 'event_preset_local_order_host',
      preset_id: presetId,
      revision_id: revisionId,
    },
    { signal },
  );
}

/**
 * @param {{ signal?: AbortSignal }} [params]
 * @returns {Promise<unknown>}
 */
export function probeOperatorHostInternet({ signal } = {}) {
  return apiPost('lab/host-internet-probe', { targets_profile: 'default' }, { signal });
}
