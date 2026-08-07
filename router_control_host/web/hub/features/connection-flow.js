/**
 * Модель экрана «Подключение к роутеру» — данные и сетевые вызовы без DOM.
 */

import { apiPost, apiGet, API_BASE } from '../core/api.js';
import {
  HubApiError,
  ERROR_KIND,
  resolveErrorEntry,
  resolveHttpStatusEntry,
} from '../core/errors.js';
import { HubState } from '../core/states.js';
import { getSession, updateSession } from '../core/session.js';
import { FACT_LABELS, HEALTH_FACT_ORDER } from './system-check.js';

/** @typedef {'SEARCH'|'ACCESS'|'VERIFY'} ConnectionStepValue */

/** @typedef {{ host?: string, port?: number, source_address?: string|null, source_address_class?: string|null, candidate_origin?: string, router_id?: string|null, route_if_index?: number|null, route_label?: string|null, identity_state?: string, credentials_required?: boolean, writes_allowed?: boolean, reason_code?: string, facts?: object }} DiscoveryCandidate */

/** @typedef {{ host: string, port: number|null, candidateOrigin: string, originText: string, sourceAddress: string|null, identityState: string, identityText: string, identityTone: string, reasonText: string, reasonCode: string, credentialsRequired: boolean, routerId: string|null, warning: string|null, duplicateCount?: number, collapsedDraftPorts?: Array<{ port: number|null, portKey: string }>, collapsedDraftEndpoints?: Array<{ port: number|null, routerId: string|null, sourceAddress: string|null }> }} GroupedCandidateSource */

/** @typedef {{ host: string, port: number|null, sourceAddress: string|null, routerId: string|null, identityState: string, identityText: string, identityTone: string, reasonTexts: string[], warnings: string[], originsSummary: string, ports: Array<{ port: number|null, portKey: string }>, sources: GroupedCandidateSource[], hasMultiplePorts: boolean, credentialsRequired: boolean }} DiscoveryCandidateGroup */

/** @typedef {{ candidates?: DiscoveryCandidate[], excluded_candidates?: Array<{ host: string, port?: number, candidate_origin?: string, reason_code: string }>, bounds?: object, source_diagnostics?: Array<{ source: string, status: string, reason_code?: string }>, degraded_sources?: string[] }} DiscoveryResponse */

/** @typedef {{ status?: string, reason_code?: string, facts?: Record<string, boolean|null>, writes_allowed?: boolean, certification_eligible?: boolean, host?: string|null, port?: number|null, router_id?: string|null, source_address?: string|null }} ConnectionHealthResponse */

/** @typedef {{ id: string, label: string, value: boolean|null, text: string, tone: 'success'|'danger'|'neutral', supported: boolean }} ChecklistItem */

/** @typedef {{ allowed: boolean, reasonText: string|null, mock: boolean }} FinishGateVerdict */

export const ConnectionStep = Object.freeze({
  SEARCH: 'SEARCH',
  ACCESS: 'ACCESS',
  VERIFY: 'VERIFY',
});

/** Честное пояснение хранения доступа — пароль не на планшете. */
export const ACCESS_STORAGE_NOTE =
  'Пароль на планшете не хранится. Он сохраняется только на сервере управления, а приложение работает с безопасной ссылкой на эту запись.';

/** Порядок фактов в чеклисте проверки подключения. */
export const CONNECTION_CHECKLIST_FACT_ORDER = Object.freeze([
  'reachable',
  'credentials_present',
  'host_key_match',
  'tuple_match',
  'evidence_fresh',
]);

/** @type {Readonly<Record<string, string>>} */
export const CANDIDATE_ORIGIN_TEXT = Object.freeze({
  default_gateway: 'Основной адрес сети',
  known_endpoint: 'Сохранённый адрес',
  local_subnet_gateway: 'Адрес вашей сети',
});

/** @type {Readonly<Record<string, string>>} */
export const IDENTITY_STATE_TEXT = Object.freeze({
  known_match: 'Совпадает с сохранённой записью',
  known_mismatch: 'Не совпадает с сохранённой записью',
  unknown: 'Совпадение ещё не проверено',
});

/** @type {Readonly<Record<string, 'success'|'warning'|'danger'|'neutral'>>} */
const IDENTITY_STATE_TONE = Object.freeze({
  known_match: 'success',
  known_mismatch: 'danger',
  unknown: 'neutral',
});

/** @type {Readonly<Record<string, number>>} */
const CANDIDATE_ORIGIN_PRIORITY = Object.freeze({
  known_endpoint: 3,
  default_gateway: 2,
  local_subnet_gateway: 1,
});

/** @type {Readonly<Record<string, number>>} */
const IDENTITY_STATE_SEVERITY = Object.freeze({
  known_mismatch: 3,
  unknown: 2,
  known_match: 1,
});

/** @typedef {'PROVEN'|'RECORD'|'UNPROVEN'} ReasonEvidenceTier */

/** Per-reason evidence tier for group identity resolution (plan SSOT). */
/** @type {Readonly<Record<string, ReasonEvidenceTier>>} */
const REASON_EVIDENCE_TIER = Object.freeze({
  probe_tuple_match: 'PROVEN',
  probe_tuple_mismatch: 'PROVEN',
  lifecycle_identity_mismatch: 'RECORD',
  host_key_pin_mismatch: 'RECORD',
  tuple_model_mismatch: 'RECORD',
  unenrolled_host: 'UNPROVEN',
  enrollment_match_identity_unverified: 'UNPROVEN',
  enrollment_draft_model_unknown: 'UNPROVEN',
  missing_gate_a_and_pin: 'UNPROVEN',
  missing_gate_a_tuple: 'UNPROVEN',
  missing_ssh_host_key_pin: 'UNPROVEN',
  probe_without_gate_a_tuple: 'UNPROVEN',
  probe_evidence_incomplete: 'UNPROVEN',
});

const PROVEN_NEGATIVE_REASON = 'probe_tuple_mismatch';
const PROVEN_POSITIVE_REASON = 'probe_tuple_match';
const ENROLLMENT_DRAFT_REASON = 'enrollment_draft_model_unknown';
const ENROLLMENT_DRAFT_SUBORDINATE_TEXT =
  'На этом адресе есть незавершённый черновик: модель устройства ещё не записана.';

/** @type {Readonly<Record<string, string>>} */
export const CANDIDATE_REASON_TEXT = Object.freeze({
  unenrolled_host: 'Устройство ещё не добавлено в систему',
  lifecycle_identity_mismatch: 'Устройство не совпадает с сохранённой записью',
  missing_gate_a_and_pin: 'Запись устройства неполная — нужна первичная настройка',
  missing_gate_a_tuple: 'Запись устройства неполная — не хватает данных для сверки',
  tuple_model_mismatch: 'Модель устройства не совпадает с сохранённой записью',
  missing_ssh_host_key_pin: 'Отпечаток устройства ещё не сохранён',
  host_key_pin_mismatch: 'Отпечаток устройства не совпадает с сохранённым',
  enrollment_match_identity_unverified: 'Устройство найдено, но устройство ещё не подтверждено',
  enrollment_draft_model_unknown:
    'Незавершённый черновик: модель устройства ещё не записана. Выберите этот адрес и продолжите настройку.',
  probe_without_gate_a_tuple: 'Проверка невозможна — не хватает данных записи устройства',
  probe_evidence_incomplete: 'Данные проверки неполные',
  probe_tuple_match: 'Совпадает с записью по результатам проверки',
  probe_tuple_mismatch: 'Не совпадает с записью по результатам проверки',
});

/** @type {Readonly<Record<string, string>>} */
export const EXCLUDED_REASON_TEXT = Object.freeze({
  loopback_not_management_candidate: 'Адрес локального цикла не подходит для управления роутером',
  non_private_management_address: 'Адрес не из частной сети — не используется для управления',
});

/** @type {Readonly<Record<string, string>>} */
const SOURCE_LABEL_TEXT = Object.freeze({
  default_gateway: 'основной адрес сети',
  local_subnet_gateway: 'адрес вашей сети',
});

/** @type {Readonly<Record<string, string>>} */
const SOURCE_FAILURE_TEXT = Object.freeze({
  timeout: 'истёк срок ожидания',
  os_error: 'ошибка операционной системы',
  unicode_decode: 'не удалось прочитать ответ',
  json_decode: 'ответ имеет неверный формат',
  nonzero_exit: 'команда завершилась с ошибкой',
});

const UNKNOWN_REASON_TEXT = 'Требуется дополнительная проверка';
const SUBORDINATE_RECORD_PREFIX = 'Другая сохранённая запись на этом адресе';
const DEVICE_MISMATCH_WARNING =
  'Это устройство не совпадает с сохранённой записью. Подключайте только если уверены, что это ваш роутер.';
const BOUNDS_NOTE =
  'Мы ищем роутер среди адресов, которые известны этому компьютеру, и среди уже сохранённых. Полный обход всех устройств сети не выполняется.';
const FAKE_FINISH_NOTE =
  'Демонстрационный режим: завершение подключения не подтверждает готовность к записи на реальное устройство.';

/** @type {Readonly<Record<string, string>>} */
const CHECKLIST_FACT_TRUE_TEXT = Object.freeze({
  reachable: 'Роутер отвечает',
  credentials_present: 'Сохранённый доступ есть в системе',
  host_key_match: 'Отпечаток совпадает',
  tuple_match: 'Совпадает с сохранённым роутером',
  evidence_fresh: 'Проверка свежая',
});

/** @type {ReadonlyArray<{ id: string, label: string, text: string }>} */
const UNSUPPORTED_CHECKLIST_ITEMS = Object.freeze([
  {
    id: 'local_network',
    label: 'Локальная сеть',
    text: 'Система не проверяет качество локальной сети',
  },
  {
    id: 'internet',
    label: 'Доступ в интернет',
    text: 'Система не проверяет наличие интернета',
  },
  {
    id: 'signal_level',
    label: 'Уровень сигнала',
    text: 'Система не проверяет уровень сигнала',
  },
]);

/** @type {Readonly<Record<number, string>>} */
const HTTP_STATUS_CODES = Object.freeze({
  400: 'request.validation_failed',
  401: 'auth.required',
  403: 'auth.forbidden',
  404: 'resource.not_found',
  405: 'http.method_not_allowed',
  409: 'resource.conflict',
  412: 'resource.precondition_failed',
  422: 'request.validation_failed',
  503: 'service.unavailable',
});

/**
 * @param {string|null|undefined} code
 * @param {Readonly<Record<string, string>>} dictionary
 * @returns {string}
 */
function describeDictionaryCode(code, dictionary) {
  if (code && dictionary[code]) {
    return dictionary[code];
  }
  return UNKNOWN_REASON_TEXT;
}

/**
 * @param {{ source?: string, status?: string, reason_code?: string }} diagnostic
 * @returns {string|null}
 */
function describeSourceDiagnostic(diagnostic) {
  const status = diagnostic.status;
  if (status !== 'empty' && status !== 'failed') {
    return null;
  }
  const sourceLabel = SOURCE_LABEL_TEXT[diagnostic.source ?? ''] ?? 'источник маршрутов';
  if (status === 'empty') {
    return `Источник «${sourceLabel}»: адрес не найден`;
  }
  const failure = SOURCE_FAILURE_TEXT[diagnostic.reason_code ?? ''] ?? 'не удалось получить данные';
  return `Источник «${sourceLabel}»: ${failure}`;
}

/**
 * @param {string|null|undefined} stateA
 * @param {string|null|undefined} stateB
 * @returns {string}
 */
function worstIdentityState(stateA, stateB) {
  const severityA = IDENTITY_STATE_SEVERITY[stateA ?? 'unknown'] ?? 0;
  const severityB = IDENTITY_STATE_SEVERITY[stateB ?? 'unknown'] ?? 0;
  return severityA >= severityB ? (stateA ?? 'unknown') : (stateB ?? 'unknown');
}

/**
 * @param {string|null|undefined} reasonCode
 * @returns {ReasonEvidenceTier}
 */
function reasonEvidenceTier(reasonCode) {
  return REASON_EVIDENCE_TIER[reasonCode ?? ''] ?? 'UNPROVEN';
}

/**
 * UNPROVEN reason codes must not elevate a source to known_match in group resolution.
 * @param {GroupedCandidateSource} source
 * @returns {string}
 */
function effectiveIdentityStateForGrouping(source) {
  const tier = reasonEvidenceTier(source.reasonCode);
  if (tier === 'UNPROVEN' && source.identityState === 'known_match') {
    return 'unknown';
  }
  return source.identityState;
}

/**
 * @param {GroupedCandidateSource} source
 * @returns {boolean}
 */
function isProvenPositiveSource(source) {
  return (
    source.reasonCode === PROVEN_POSITIVE_REASON &&
    source.identityState === 'known_match'
  );
}

/**
 * Fail-closed: probe_tuple_mismatch always counts as proven negative.
 * @param {GroupedCandidateSource} source
 * @returns {boolean}
 */
function isProvenNegativeSource(source) {
  return source.reasonCode === PROVEN_NEGATIVE_REASON;
}

/**
 * @param {number} count
 * @returns {string|null}
 */
function formatDraftDuplicateCount(count) {
  if (count <= 1) {
    return null;
  }
  const mod10 = count % 10;
  const mod100 = count % 100;
  if (mod10 === 1 && mod100 !== 11) {
    return `${count} незавершённый черновик на этом адресе`;
  }
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 10 || mod100 >= 20)) {
    return `${count} незавершённых черновика на этом адресе`;
  }
  return `${count} незавершённых черновиков на этом адресе`;
}

/**
 * @param {GroupedCandidateSource} source
 * @returns {string}
 */
function reframeSubordinateRecordReason(source) {
  const portSuffix = source.port != null ? ` (порт ${source.port})` : '';
  const detail = source.reasonText;
  if (!detail) {
    return `${SUBORDINATE_RECORD_PREFIX}${portSuffix}`;
  }
  if (detail.startsWith(SUBORDINATE_RECORD_PREFIX)) {
    return detail;
  }
  return `${SUBORDINATE_RECORD_PREFIX}${portSuffix}: ${detail.charAt(0).toLowerCase()}${detail.slice(1)}`;
}

/**
 * Subordinate mismatch reframe applies only when the contradicting source is a
 * different stored record (or has no routerId) than the connect endpoint.
 * @param {GroupedCandidateSource} source
 * @param {string} identityState
 * @param {boolean} isDetermining
 * @param {string|null|undefined} endpointRouterId
 * @returns {boolean}
 */
function isSubordinateMismatchSource(source, identityState, isDetermining, endpointRouterId) {
  if (identityState !== 'known_match' || isDetermining || source.identityState !== 'known_mismatch') {
    return false;
  }
  if (
    source.routerId != null &&
    endpointRouterId != null &&
    source.routerId === endpointRouterId
  ) {
    return false;
  }
  return true;
}

/**
 * @param {GroupedCandidateSource[]} sources
 * @param {string} identityState
 * @param {GroupedCandidateSource|null} determiningSource
 * @param {string|null|undefined} endpointRouterId
 * @returns {{ warnings: string[], reasonTexts: string[] }}
 */
function buildGroupReasonTextsAndWarnings(
  sources,
  identityState,
  determiningSource,
  endpointRouterId,
) {
  /** @type {string[]} */
  const warnings = [];
  /** @type {string[]} */
  const reasonTexts = [];

  for (const source of sources) {
    const isDetermining = source === determiningSource;
    const subordinateMismatch = isSubordinateMismatchSource(
      source,
      identityState,
      isDetermining,
      endpointRouterId,
    );

    if (source.warning && !subordinateMismatch) {
      if (!warnings.includes(source.warning)) {
        warnings.push(source.warning);
      }
    }

    if (source.reasonText) {
      if (subordinateMismatch) {
        const reframed = reframeSubordinateRecordReason(source);
        if (reframed && !reasonTexts.includes(reframed)) {
          reasonTexts.push(reframed);
        }
        continue;
      }
      let reasonLine = source.reasonText;
      if (
        source.reasonCode === ENROLLMENT_DRAFT_REASON
        && source.routerId !== endpointRouterId
      ) {
        reasonLine = ENROLLMENT_DRAFT_SUBORDINATE_TEXT;
      } else if (identityState === 'known_mismatch' && source.reasonCode === PROVEN_POSITIVE_REASON) {
        reasonLine = UNKNOWN_REASON_TEXT;
      }
      if (!reasonTexts.includes(reasonLine)) {
        reasonTexts.push(reasonLine);
      }
    }

    if (source.duplicateCount && source.duplicateCount > 1) {
      const duplicateText = formatDraftDuplicateCount(source.duplicateCount);
      if (duplicateText && !reasonTexts.includes(duplicateText)) {
        reasonTexts.push(duplicateText);
      }
    }
  }

  return { warnings, reasonTexts };
}

/**
 * @param {GroupedCandidateSource[]} sources
 * @param {string} identityState
 * @param {GroupedCandidateSource|null} determiningSource
 * @param {GroupedCandidateSource} primary
 * @returns {GroupedCandidateSource}
 */
function resolveEndpointSource(sources, identityState, determiningSource, primary) {
  if (determiningSource) {
    const tier = reasonEvidenceTier(determiningSource.reasonCode);
    if (tier === 'PROVEN') {
      return determiningSource;
    }
    if (identityState === 'known_mismatch' && tier === 'RECORD') {
      const preferredKnown = sources.find(
        (source) =>
          source.candidateOrigin === 'known_endpoint' &&
          source.routerId &&
          source.identityState !== 'known_mismatch',
      );
      if (preferredKnown) {
        return preferredKnown;
      }
      return determiningSource;
    }
    if (identityState === 'known_match' && determiningSource.routerId) {
      return determiningSource;
    }
  }

  const knownWithRouterId = sources.find(
    (source) => source.candidateOrigin === 'known_endpoint' && source.routerId,
  );
  if (knownWithRouterId) {
    return knownWithRouterId;
  }

  return primary;
}

/**
 * @param {Map<string, { port: number|null, portKey: string }>} portMap
 * @param {number|null|undefined} port
 */
function addPortToMap(portMap, port) {
  const key = portSelectionKey(port);
  if (!portMap.has(key)) {
    portMap.set(key, { port: port ?? null, portKey: key });
  }
}

/**
 * @param {GroupedCandidateSource[]} sources
 * @returns {{ identityState: string, determiningSource: GroupedCandidateSource|null }}
 */
function resolveGroupIdentityState(sources) {
  if (sources.length === 0) {
    return { identityState: 'unknown', determiningSource: null };
  }

  const provenNegative = sources.find((source) => isProvenNegativeSource(source));
  if (provenNegative) {
    return { identityState: 'known_mismatch', determiningSource: provenNegative };
  }

  const provenPositive = sources.find((source) => isProvenPositiveSource(source));
  if (provenPositive) {
    return { identityState: 'known_match', determiningSource: provenPositive };
  }

  let identityState = effectiveIdentityStateForGrouping(sources[0]);
  /** @type {GroupedCandidateSource|null} */
  let determiningSource = sources[0];
  for (const source of sources.slice(1)) {
    const effective = effectiveIdentityStateForGrouping(source);
    const nextState = worstIdentityState(identityState, effective);
    if (
      (IDENTITY_STATE_SEVERITY[nextState] ?? 0) >
      (IDENTITY_STATE_SEVERITY[identityState] ?? 0)
    ) {
      determiningSource = source;
    } else if (
      nextState === identityState &&
      (CANDIDATE_ORIGIN_PRIORITY[source.candidateOrigin] ?? 0) >
        (CANDIDATE_ORIGIN_PRIORITY[determiningSource?.candidateOrigin ?? ''] ?? 0)
    ) {
      determiningSource = source;
    }
    identityState = nextState;
  }

  return { identityState, determiningSource };
}

/**
 * Collapse duplicate enrollment-draft sources for one host into a single detail row.
 * @param {GroupedCandidateSource[]} sources
 * @returns {GroupedCandidateSource[]}
 */
function collapseEnrollmentDraftSources(sources) {
  /** @type {GroupedCandidateSource[]} */
  const drafts = [];
  for (const source of sources) {
    if (source.reasonCode === ENROLLMENT_DRAFT_REASON) {
      drafts.push(source);
    }
  }
  if (drafts.length <= 1) {
    return sources;
  }

  const representative = drafts.find((source) => source.routerId) ?? drafts[0];

  /** @type {Map<string, { port: number|null, portKey: string }>} */
  const draftPortMap = new Map();
  for (const draft of drafts) {
    addPortToMap(draftPortMap, draft.port);
  }

  /** @type {Array<{ port: number|null, routerId: string|null, sourceAddress: string|null }>} */
  const collapsedDraftEndpoints = drafts.map((draft) => ({
    port: draft.port ?? null,
    routerId: draft.routerId ?? null,
    sourceAddress: draft.sourceAddress ?? null,
  }));

  /** @type {GroupedCandidateSource} */
  const collapsed = {
    ...representative,
    duplicateCount: drafts.length,
    collapsedDraftPorts: [...draftPortMap.values()],
    collapsedDraftEndpoints,
  };

  /** @type {GroupedCandidateSource[]} */
  const result = [];
  let inserted = false;
  for (const source of sources) {
    if (source.reasonCode === ENROLLMENT_DRAFT_REASON) {
      if (!inserted) {
        result.push(collapsed);
        inserted = true;
      }
      continue;
    }
    result.push(source);
  }
  return result;
}

/**
 * @param {number|null|undefined} port
 * @returns {string}
 */
export function portSelectionKey(port) {
  return port == null ? '__none__' : String(port);
}

/**
 * @param {string[]} originTexts
 * @returns {string}
 */
export function formatCandidateOriginsSummary(originTexts) {
  const unique = [...new Set(originTexts.filter(Boolean))];
  if (unique.length === 0) {
    return '';
  }
  const lower = unique.map((text) => `${text.charAt(0).toLowerCase()}${text.slice(1)}`);
  if (lower.length === 1) {
    return `Найден как ${lower[0]}`;
  }
  if (lower.length === 2) {
    return `Найден как ${lower[0]} и как ${lower[1]}`;
  }
  const last = lower.pop();
  return `Найден как ${lower.join(', ')}, и как ${last}`;
}

/**
 * @param {DiscoveryCandidate|null|undefined} candidate
 * @returns {GroupedCandidateSource}
 */
function describeCandidateSource(candidate) {
  const described = describeCandidate(candidate);
  const item = candidate ?? {};
  return {
    ...described,
    candidateOrigin: typeof item.candidate_origin === 'string' ? item.candidate_origin : '',
    identityState: item.identity_state ?? 'unknown',
    reasonCode: typeof item.reason_code === 'string' ? item.reason_code : '',
    sourceAddress: item.source_address ?? null,
  };
}

/**
 * Группирует кандидатов по адресу устройства для экрана поиска.
 * @param {DiscoveryCandidate[]} rawCandidates
 * @returns {DiscoveryCandidateGroup[]}
 */
export function groupDiscoveryCandidates(rawCandidates) {
  const items = Array.isArray(rawCandidates) ? rawCandidates : [];
  /** @type {Map<string, DiscoveryCandidate[]>} */
  const byHost = new Map();

  for (const candidate of items) {
    const host = typeof candidate?.host === 'string' ? candidate.host.trim() : '';
    if (!host) {
      continue;
    }
    const bucket = byHost.get(host) ?? [];
    bucket.push(candidate);
    byHost.set(host, bucket);
  }

  /** @type {DiscoveryCandidateGroup[]} */
  const groups = [];

  for (const [host, hostCandidates] of byHost) {
    let sources = hostCandidates
      .map((item) => describeCandidateSource(item))
      .sort((a, b) => {
        const priorityDiff =
          (CANDIDATE_ORIGIN_PRIORITY[b.candidateOrigin] ?? 0) -
          (CANDIDATE_ORIGIN_PRIORITY[a.candidateOrigin] ?? 0);
        if (priorityDiff !== 0) {
          return priorityDiff;
        }
        const portA = a.port ?? Number.MAX_SAFE_INTEGER;
        const portB = b.port ?? Number.MAX_SAFE_INTEGER;
        return portA - portB;
      });

    sources = collapseEnrollmentDraftSources(sources);

    const primary = sources[0];
    const { identityState, determiningSource } = resolveGroupIdentityState(sources);
    const endpointSource = resolveEndpointSource(
      sources,
      identityState,
      determiningSource,
      primary,
    );

    const identityText = IDENTITY_STATE_TEXT[identityState] ?? IDENTITY_STATE_TEXT.unknown;
    const identityTone = IDENTITY_STATE_TONE[identityState] ?? 'neutral';

    const { warnings, reasonTexts } = buildGroupReasonTextsAndWarnings(
      sources,
      identityState,
      determiningSource,
      endpointSource.routerId,
    );

    const originTextsOrdered = sources.map((source) => source.originText);
    /** @type {string[]} */
    const uniqueOriginTexts = [];
    for (const text of originTextsOrdered) {
      if (text && !uniqueOriginTexts.includes(text)) {
        uniqueOriginTexts.push(text);
      }
    }

    /** @type {Map<string, { port: number|null, portKey: string }>} */
    const portMap = new Map();
    for (const source of sources) {
      addPortToMap(portMap, source.port);
      if (Array.isArray(source.collapsedDraftPorts)) {
        for (const entry of source.collapsedDraftPorts) {
          addPortToMap(portMap, entry.port);
        }
      }
    }

    groups.push({
      host,
      port: endpointSource.port,
      sourceAddress: endpointSource.sourceAddress,
      routerId: endpointSource.routerId,
      identityState,
      identityText,
      identityTone,
      reasonTexts,
      warnings,
      originsSummary: formatCandidateOriginsSummary(uniqueOriginTexts),
      ports: [...portMap.values()],
      sources,
      hasMultiplePorts: portMap.size > 1,
      credentialsRequired: sources.some((source) => source.credentialsRequired),
    });
  }

  return groups.sort((a, b) => a.host.localeCompare(b.host));
}

/**
 * @param {DiscoveryCandidateGroup} group
 * @param {number|null|undefined} selectedPort
 * @returns {{ port: number|null, sourceAddress: string|null, routerId: string|null }}
 */
export function resolveGroupEndpoint(group, selectedPort) {
  const sources = group.sources ?? [];
  if (sources.length === 0) {
    return { port: null, sourceAddress: null, routerId: null };
  }
  const portKey = portSelectionKey(selectedPort ?? group.port);

  const directMatch = sources.find((source) => portSelectionKey(source.port) === portKey);
  if (directMatch) {
    return {
      port: directMatch.port,
      sourceAddress: directMatch.sourceAddress,
      routerId: directMatch.routerId,
    };
  }

  for (const source of sources) {
    if (!Array.isArray(source.collapsedDraftEndpoints)) {
      continue;
    }
    const draftMatch = source.collapsedDraftEndpoints.find(
      (entry) => portSelectionKey(entry.port) === portKey,
    );
    if (draftMatch) {
      return {
        port: draftMatch.port,
        sourceAddress: draftMatch.sourceAddress ?? source.sourceAddress,
        routerId: draftMatch.routerId,
      };
    }
  }

  const fallback = sources[0];
  return {
    port: fallback.port,
    sourceAddress: fallback.sourceAddress,
    routerId: fallback.routerId,
  };
}

/**
 * @param {DiscoveryCandidateGroup} group
 * @returns {Array<{ port: number|null, portKey: string, label: string }>}
 */
export function describeGroupPortOptions(group) {
  return (group.ports ?? []).map(({ port, portKey }) => {
    const matchingSources = (group.sources ?? []).filter(
      (source) => portSelectionKey(source.port) === portKey,
    );
    /** @type {string[]} */
    const origins = [];
    for (const source of matchingSources) {
      if (source.originText && !origins.includes(source.originText)) {
        origins.push(source.originText);
      }
    }
    const originsLower = origins.map((text) => `${text.charAt(0).toLowerCase()}${text.slice(1)}`);
    const roleText = originsLower.join(', ');
    if (port != null) {
      return {
        port,
        portKey,
        label: roleText ? `Порт ${port} — ${roleText}` : `Порт ${port}`,
      };
    }
    return {
      port,
      portKey,
      label: roleText ? `Без указанного порта — ${roleText}` : 'Без указанного порта',
    };
  });
}

/**
 * Преобразует ответ router-discovery для UI.
 * @param {DiscoveryResponse|null|undefined} response
 * @param {{ adapterMode?: string|null }} [options]
 * @returns {{ state: string, candidates: DiscoveryCandidateGroup[], excluded: Array<{ host: string, port?: number, text: string }>, diagnosticsNotes: string[], boundsNote: string, mock: boolean }}
 */
export function describeDiscovery(response, { adapterMode } = {}) {
  const isFake = adapterMode === 'fake';
  const payload = response ?? {};
  const rawCandidates = Array.isArray(payload.candidates) ? payload.candidates : [];
  const candidates = groupDiscoveryCandidates(rawCandidates);
  const excluded = (Array.isArray(payload.excluded_candidates) ? payload.excluded_candidates : []).map(
    (item) => ({
      host: item.host,
      port: item.port,
      text: describeDictionaryCode(item.reason_code, EXCLUDED_REASON_TEXT),
    }),
  );

  const diagnosticsNotes = (Array.isArray(payload.source_diagnostics) ? payload.source_diagnostics : [])
    .map((item) => describeSourceDiagnostic(item))
    .filter((note) => typeof note === 'string' && note.length > 0);

  const degraded = Array.isArray(payload.degraded_sources) ? payload.degraded_sources : [];
  if (degraded.length > 0 && diagnosticsNotes.length === 0) {
    diagnosticsNotes.push('Часть источников маршрутов недоступна — результаты могут быть неполными');
  }

  let state = HubState.SUCCESS;
  if (rawCandidates.length === 0) {
    state = HubState.EMPTY;
  } else if (degraded.length > 0) {
    state = HubState.WARNING;
  }

  return {
    state,
    candidates,
    excluded,
    diagnosticsNotes,
    boundsNote: BOUNDS_NOTE,
    mock: isFake,
  };
}

/**
 * @param {DiscoveryCandidate|null|undefined} candidate
 * @returns {{ host: string, port: number|null, originText: string, identityText: string, identityTone: string, reasonText: string, credentialsRequired: boolean, routerId: string|null, warning: string|null }}
 */
export function describeCandidate(candidate) {
  const item = candidate ?? {};
  const host = typeof item.host === 'string' ? item.host : '';
  const port = typeof item.port === 'number' ? item.port : null;
  const identityState = item.identity_state ?? 'unknown';
  const identityText = IDENTITY_STATE_TEXT[identityState] ?? IDENTITY_STATE_TEXT.unknown;
  const identityTone = IDENTITY_STATE_TONE[identityState] ?? 'neutral';

  let warning = null;
  if (identityState === 'known_mismatch') {
    warning = DEVICE_MISMATCH_WARNING;
  }

  return {
    host,
    port,
    originText: describeDictionaryCode(item.candidate_origin, CANDIDATE_ORIGIN_TEXT),
    identityText,
    identityTone,
    reasonText: describeDictionaryCode(item.reason_code, CANDIDATE_REASON_TEXT),
    reasonCode: typeof item.reason_code === 'string' ? item.reason_code : '',
    credentialsRequired: Boolean(item.credentials_required),
    routerId: item.router_id ?? null,
    warning,
  };
}

/**
 * @param {string|null|undefined} value
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateManualHost(value) {
  const errors = [];
  const trimmed = typeof value === 'string' ? value.trim() : '';
  if (!trimmed) {
    errors.push('Укажите адрес роутера');
  } else if (/\s/.test(trimmed)) {
    errors.push('Адрес не должен содержать пробелы');
  } else if (trimmed.includes('@')) {
    errors.push('Не указывайте имя пользователя в поле адреса');
  }
  return { valid: errors.length === 0, errors };
}

/**
 * @param {{ host?: string, username?: string, password?: string }} fields
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateAccessForm({ host, username, password }) {
  const errors = [];
  const hostResult = validateManualHost(host);
  errors.push(...hostResult.errors);

  const user = typeof username === 'string' ? username.trim() : '';
  if (!user) {
    errors.push('Укажите имя пользователя');
  }

  const secret = typeof password === 'string' ? password : '';
  if (!secret) {
    errors.push('Укажите пароль');
  }

  return { valid: errors.length === 0, errors };
}

/**
 * @returns {string}
 */
export function createIdempotencyKey() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }
  throw new Error('Невозможно создать ключ идемпотентности: нет криптографически стойкого генератора');
}

/**
 * @param {{ host: string, username: string, password: string, displayName?: string|null }} params
 * @returns {{ host: string, username: string, secret: string, display_name?: string, allow_insecure_http: boolean }}
 */
export function buildDraftBody({ host, username, password, displayName }) {
  /** @type {{ host: string, username: string, secret: string, display_name?: string, allow_insecure_http: boolean }} */
  const body = {
    host: host.trim(),
    username: username.trim(),
    secret: password,
    allow_insecure_http: false,
  };
  if (typeof displayName === 'string' && displayName.trim()) {
    body.display_name = displayName.trim();
  }
  return body;
}

/**
 * @param {string|null|undefined} value
 * @returns {string}
 */
export function formatFingerprint(value) {
  if (typeof value !== 'string') {
    return '';
  }
  return value.trim();
}

/**
 * @param {unknown} error
 * @returns {{ text: string, existingFingerprint: string|null, candidateFingerprint: string|null }|null}
 */
export function describeHostKeyConflict(error) {
  if (!(error instanceof HubApiError) || error.code !== 'ssh_host_key.pin_conflict') {
    return null;
  }
  const detail = error.details?.[0];
  /** @type {string|null} */
  let existingFingerprint = null;
  /** @type {string|null} */
  let candidateFingerprint = null;
  if (detail && typeof detail === 'object') {
    if (typeof detail.existing_fingerprint_sha256 === 'string') {
      existingFingerprint = formatFingerprint(detail.existing_fingerprint_sha256);
    }
    if (typeof detail.candidate_fingerprint_sha256 === 'string') {
      candidateFingerprint = formatFingerprint(detail.candidate_fingerprint_sha256);
    }
  }
  return {
    text:
      'Сохранённый отпечаток устройства отличается от текущего. Заменять его можно только если роутер действительно меняли или переустанавливали — иначе это может быть чужое устройство.',
    existingFingerprint,
    candidateFingerprint,
  };
}

/**
 * @param {boolean|null|undefined} raw
 * @returns {boolean|null}
 */
export function normalizeTriStateFact(raw) {
  return raw === true || raw === false ? raw : null;
}

/**
 * @param {string} factId
 * @param {boolean|null|undefined} value
 * @returns {{ text: string, tone: 'success'|'danger'|'neutral' }}
 */
export function describeChecklistFactValue(factId, value) {
  if (value === true) {
    return { text: CHECKLIST_FACT_TRUE_TEXT[factId] ?? 'Подтверждено', tone: 'success' };
  }
  if (value === false) {
    return { text: 'Не пройдено', tone: 'danger' };
  }
  return { text: 'Неизвестно', tone: 'neutral' };
}

/**
 * Бейдж привязки отпечатка на шаге «Проверка».
 * tuple_match не участвует — отдельный факт чеклиста.
 * @param {{ hostKeyConfirmed: boolean, health: ConnectionHealthResponse|null|undefined }} params
 * @returns {{ label: string, tone: 'success'|'warning'|'neutral' }}
 */
export function deriveVerifyHostKeyBadge({ hostKeyConfirmed, health }) {
  if (!hostKeyConfirmed) {
    return { label: 'Требует подтверждения', tone: 'warning' };
  }
  if (health === null || health === undefined) {
    return { label: 'Отпечаток подтверждён на сервере', tone: 'neutral' };
  }
  const value = normalizeTriStateFact(health?.facts?.host_key_match);
  if (value === true) {
    return { label: 'Привязан', tone: 'success' };
  }
  if (value === false) {
    return { label: 'Отпечаток не совпадает', tone: 'warning' };
  }
  return { label: 'Совпадение отпечатка ещё не проверено', tone: 'neutral' };
}

/**
 * Три состояния доступности управления на шаге «Проверка».
 * @param {boolean|null|undefined} writesAllowed
 * @returns {string}
 */
export function describeManagementAvailability(writesAllowed) {
  if (writesAllowed === true) {
    return 'Управление доступно';
  }
  if (writesAllowed === false) {
    return 'Управление пока недоступно';
  }
  return 'Управление не проверено';
}

/**
 * Нормализует привязку, для которой измерен результат health-check.
 * @param {{ routerId?: string|null, routerHost?: string|null, sourceAddress?: string|null }} binding
 * @returns {{ routerId: string|null, routerHost: string|null, sourceAddress: string|null }}
 */
export function normalizeHealthBinding(binding) {
  const trim = (value) => (typeof value === 'string' && value.trim() ? value.trim() : null);
  return {
    routerId: trim(binding.routerId),
    routerHost: trim(binding.routerHost),
    sourceAddress: trim(binding.sourceAddress),
  };
}

/**
 * @param {{ routerId?: string|null, routerHost?: string|null, sourceAddress?: string|null }} left
 * @param {{ routerId?: string|null, routerHost?: string|null, sourceAddress?: string|null }} right
 * @returns {boolean}
 */
export function healthBindingsMatch(left, right) {
  const normalizedLeft = normalizeHealthBinding(left);
  const normalizedRight = normalizeHealthBinding(right);
  return normalizedLeft.routerId === normalizedRight.routerId
    && normalizedLeft.routerHost === normalizedRight.routerHost
    && normalizedLeft.sourceAddress === normalizedRight.sourceAddress;
}

/**
 * @param {ConnectionHealthResponse|null|undefined} health
 * @returns {ChecklistItem[]}
 */
export function buildConnectionChecklist(health) {
  const facts = health?.facts ?? {};
  const factItems = CONNECTION_CHECKLIST_FACT_ORDER.map((id) => {
    const raw = facts[id];
    const value = normalizeTriStateFact(raw);
    const { text, tone } = describeChecklistFactValue(id, value);
    return {
      id,
      label: FACT_LABELS[id] ?? id,
      value,
      text,
      tone,
      supported: true,
    };
  });

  const unsupportedItems = UNSUPPORTED_CHECKLIST_ITEMS.map((item) => ({
    id: item.id,
    label: item.label,
    value: null,
    text: item.text,
    tone: /** @type {'neutral'} */ ('neutral'),
    supported: false,
  }));

  return [...factItems, ...unsupportedItems];
}

/**
 * Fail-closed правило завершения подключения.
 * @param {{ health: ConnectionHealthResponse|null, hostKeyConfirmed: boolean, adapterMode?: string|null }} params
 * @returns {FinishGateVerdict}
 */
export function evaluateFinishGate({ health, hostKeyConfirmed, adapterMode }) {
  const isFake = adapterMode === 'fake';

  if (health == null) {
    return {
      allowed: false,
      reasonText: 'Сначала выполните проверку подключения',
      mock: isFake,
    };
  }

  if (health.status === 'red') {
    return {
      allowed: false,
      reasonText: 'Связь с роутером не установлена — завершить подключение нельзя',
      mock: isFake,
    };
  }

  if (isFake) {
    return {
      allowed: true,
      reasonText: FAKE_FINISH_NOTE,
      mock: true,
    };
  }

  const facts = health.facts ?? {};
  const requiredFacts = HEALTH_FACT_ORDER;

  for (const factId of requiredFacts) {
    const value = facts[factId];
    if (value !== true) {
      const label = FACT_LABELS[factId] ?? factId;
      if (value === false) {
        return {
          allowed: false,
          reasonText: `Не пройдена проверка: ${label}`,
          mock: false,
        };
      }
      return {
        allowed: false,
        reasonText: `Не подтверждено: ${label}`,
        mock: false,
      };
    }
  }

  if (hostKeyConfirmed !== true) {
    return {
      allowed: false,
      reasonText: 'Подтвердите отпечаток устройства на шаге «Доступ»',
      mock: false,
    };
  }

  return {
    allowed: true,
    reasonText: null,
    mock: false,
  };
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
    code: HTTP_STATUS_CODES[httpStatus] ?? `http.${httpStatus}`,
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
 * Локальный POST с произвольными заголовками — api.js не принимает Idempotency-Key.
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
      const onSignalAbort = () => {
        forwardAbort();
      };
      const onTimeoutAbort = () => {
        forwardAbort();
      };
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

    throw new HubApiError({
      code: 'client.unknown',
      httpStatus: null,
      userMessage: 'Не удалось выполнить запрос.',
      userAction: 'Повторите позже. Если ошибка сохраняется — обратитесь к администратору.',
      serverMessage: null,
      details: [],
      requestId: null,
      correlationId: null,
      kind: ERROR_KIND.UNKNOWN,
    });
  } finally {
    clearTimeout(timeoutId);
    detachAbortListeners?.();
  }
}

/**
 * @param {AbortSignal|undefined} signal
 * @returns {Promise<DiscoveryResponse>}
 */
export function runDiscovery(signal) {
  return /** @type {Promise<DiscoveryResponse>} */ (
    apiPost(
      'lab/router-discovery',
      {
        include_default_gateway: true,
        include_known_endpoints: true,
        probe: false,
      },
      { signal },
    )
  );
}

/**
 * @param {{ body: ReturnType<typeof buildDraftBody>, idempotencyKey?: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function createDraftRouter({ body, idempotencyKey, signal }) {
  const key = idempotencyKey ?? createIdempotencyKey();
  return postWithHeaders(
    'lab/wizard-draft-router',
    body,
    { 'Idempotency-Key': key },
    { signal },
  );
}

/**
 * @param {{ routerId: string, host: string, port?: number, sourceAddress?: string|null, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function learnHostKey({ routerId, host, port = 22, sourceAddress, signal }) {
  /** @type {{ host: string, port: number, source_address?: string }} */
  const payload = { host, port };
  if (typeof sourceAddress === 'string' && sourceAddress.trim()) {
    payload.source_address = sourceAddress.trim();
  }
  return apiPost(`routers/${routerId}/ssh-host-key/learn`, payload, { signal });
}

/**
 * @param {{ routerId: string, fingerprintSha256: string, algorithm: string, allowOverwrite?: boolean, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function confirmHostKey({
  routerId,
  fingerprintSha256,
  algorithm,
  allowOverwrite = false,
  signal,
}) {
  return apiPost(
    `routers/${routerId}/ssh-host-key/confirm`,
    {
      fingerprint_sha256: fingerprintSha256,
      algorithm,
      allow_overwrite: allowOverwrite,
    },
    { signal },
  );
}

/**
 * @param {{ routerId?: string|null, host?: string|null, sourceAddress?: string|null, credentialRefId?: string|null, sshHostKeySha256?: string|null, probe?: boolean, signal?: AbortSignal }} params
 * @returns {Promise<ConnectionHealthResponse>}
 */
export function checkConnectionHealth({
  routerId,
  host,
  sourceAddress,
  credentialRefId,
  sshHostKeySha256,
  probe = true,
  signal,
}) {
  /** @type {Record<string, unknown>} */
  const body = { probe };
  if (routerId) body.router_id = routerId;
  if (host) body.host = host;
  if (sourceAddress) body.source_address = sourceAddress;
  if (credentialRefId) body.credential_ref_id = credentialRefId;
  if (sshHostKeySha256) body.ssh_host_key_sha256 = sshHostKeySha256;
  return /** @type {Promise<ConnectionHealthResponse>} */ (
    apiPost('lab/connection-health', body, { signal })
  );
}

/**
 * Сохраняет имя пользователя управления и обновляет сессию из connection-context.
 * @param {{ routerId: string, username: string, signal?: AbortSignal }} params
 * @returns {Promise<object>}
 */
export async function submitManagementUsername({ routerId, username, signal }) {
  const trimmed = typeof username === 'string' ? username.trim() : '';
  if (!routerId || !trimmed) {
    throw new HubApiError({
      code: 'request.validation_failed',
      httpStatus: null,
      userMessage: 'Укажите имя пользователя.',
      userAction: 'Заполните поле и повторите.',
      serverMessage: null,
      details: [],
      requestId: null,
      correlationId: null,
      kind: ERROR_KIND.VALIDATION,
    });
  }

  await apiPost(`routers/${routerId}/management-username`, { username: trimmed }, { signal });
  const ctx = /** @type {{
    router_id?: string,
    host?: string|null,
    port?: number|null,
    source_address?: string|null,
    credential_ref_id?: string|null,
    ssh_host_key?: {
      confirmed?: boolean,
      fingerprint_sha256?: string|null,
      pinned_at?: string|null,
    },
    username_available?: boolean,
    live_ready?: boolean,
  }} */ (
    await apiGet(`routers/${routerId}/connection-context`, { signal })
  );

  const session = getSession();
  updateSession({
    routerId: typeof ctx.router_id === 'string' ? ctx.router_id : routerId,
    routerHost: typeof ctx.host === 'string' ? ctx.host : null,
    sourceAddress:
      typeof ctx.source_address === 'string'
        ? ctx.source_address
        : null,
    hostKeyConfirmed: ctx.ssh_host_key?.confirmed === true,
    liveReady: ctx.live_ready === true,
    usernameAvailable: ctx.username_available === true,
    pinnedEndpointPort: typeof ctx.port === 'number' ? ctx.port : null,
    pinnedAt: typeof ctx.ssh_host_key?.pinned_at === 'string'
      ? ctx.ssh_host_key.pinned_at
      : null,
    connectionRestoreState: 'done',
    wifiLive: {
      host: typeof ctx.host === 'string' ? ctx.host : null,
      credentialRefId:
        typeof ctx.credential_ref_id === 'string'
          ? ctx.credential_ref_id
          : session.wifiLive.credentialRefId,
      sshHostKeySha256:
        ctx.ssh_host_key?.fingerprint_sha256 ?? session.wifiLive.sshHostKeySha256,
    },
  });

  return ctx;
}
