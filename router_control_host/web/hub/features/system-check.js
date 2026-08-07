/**
 * Единая правда о готовности системы (экран «Обзор» и будущая «Диагностика»).
 * Без DOM — только данные и сетевой вызов connection-health.
 *
 * Поле hub_available из GET /status здесь не используется — см. решение M-7
 * (main-decisions-local-hub.md): готовность выводится только из connection-health
 * и подтверждённого оператором SSH-пина в сессии.
 */

import { apiPost } from '../core/api.js';
import { HubApiError, ERROR_KIND } from '../core/errors.js';
import { HubState } from '../core/states.js';

/** @typedef {'READY'|'LIMITED'|'NOT_READY'|'NO_ROUTER'|'FAILED'} SystemCheckLevelValue */

/** @typedef {{ reachable?: boolean|null, host_key_match?: boolean|null, tuple_match?: boolean|null, credentials_present?: boolean|null, evidence_fresh?: boolean|null }} HealthFacts */

/** @typedef {{ status?: string, reason_code?: string, facts?: HealthFacts, host?: string|null, router_id?: string|null }} ConnectionHealthResponse */

/** @typedef {{ id: string, label: string, value: boolean|null, text: string, tone: 'success'|'warning'|'danger'|'neutral' }} DescribedFact */

/** @typedef {{ level: SystemCheckLevelValue, hubState: string, title: string, description: string|null, badgeLabel: string, badgeTone: 'success'|'warning'|'danger'|'neutral', reasonCode: string|null, facts: DescribedFact[], host: string|null, routerId: string|null, mock: boolean, mockNote: string|null, checkedAt: Date }} SystemCheckVerdict */

export const SystemCheckLevel = Object.freeze({
  READY: 'READY',
  LIMITED: 'LIMITED',
  NOT_READY: 'NOT_READY',
  NO_ROUTER: 'NO_ROUTER',
  FAILED: 'FAILED',
});

/** Максимум попыток health (1 первичная + 2 повтора) — только для loadOverview. */
export const SYSTEM_CHECK_TRANSIENT_MAX_ATTEMPTS = 3;

/** Retry только при транспортных сбоях (не при HTTP-success red/yellow). */
export const SYSTEM_CHECK_TRANSIENT_RETRY_KINDS = Object.freeze([
  ERROR_KIND.NETWORK,
  ERROR_KIND.TIMEOUT,
  ERROR_KIND.SERVER,
]);

export const HEALTH_FACT_ORDER = Object.freeze([
  'reachable',
  'host_key_match',
  'tuple_match',
  'credentials_present',
  'evidence_fresh',
]);

/** @type {Readonly<Record<string, string>>} */
export const FACT_LABELS = Object.freeze({
  reachable: 'Роутер отвечает',
  host_key_match: 'Отпечаток устройства',
  tuple_match: 'Это тот же роутер, что сохранён',
  credentials_present: 'Сохранённый доступ',
  evidence_fresh: 'Свежесть проверки',
});

/** @type {Readonly<Record<string, string>>} */
export const REASON_CODE_TEXT = Object.freeze({
  all_facts_healthy: 'Все проверки связи пройдены',
  unreachable: 'Роутер не отвечает. Проверьте питание и сеть, затем нажмите «Проверить систему»',
  host_key_mismatch: 'Отпечаток устройства не совпал. Откройте раздел «Подключение» и подтвердите устройство заново',
  identity_mismatch: 'Роутер не совпадает с сохранённой записью. Откройте раздел «Подключение»',
  credentials_missing: 'Сохранённого доступа нет. Откройте раздел «Подключение» и сохраните доступ заново',
  evidence_stale: 'Данные проверки устарели. Нажмите «Проверить систему»',
  reachability_unknown: 'Не удалось проверить связь. Нажмите «Проверить систему» или откройте раздел «Подключение»',
  host_key_unknown: 'Отпечаток устройства ещё не проверен',
  tuple_unknown: 'Совпадение с записью ещё не проверено',
  credentials_unknown: 'Наличие учётных данных не подтверждено',
  evidence_freshness_unknown: 'Актуальность проверки неизвестна',
  health_incomplete: 'Проверка прошла не полностью. Нажмите «Проверить систему»',
});

/** @type {Readonly<Record<string, string>>} */
const FACT_TRUE_TEXT = Object.freeze({
  reachable: 'Роутер отвечает',
  host_key_match: 'Отпечаток совпадает',
  tuple_match: 'Совпадает с сохранённым роутером',
  credentials_present: 'Сохранённый доступ есть в системе',
  evidence_fresh: 'Проверка свежая',
});

const UNKNOWN_REASON_TEXT = 'Причина не распознана';
const FAKE_MOCK_NOTE = 'Демонстрационный режим: данные не с реального роутера';

/**
 * Человекочитаемый текст reason_code без echo кода пользователю.
 * @param {string|null|undefined} code
 * @returns {string}
 */
export function describeReasonCode(code) {
  if (code && REASON_CODE_TEXT[code]) {
    return REASON_CODE_TEXT[code];
  }
  return UNKNOWN_REASON_TEXT;
}

/**
 * @param {string} factId
 * @param {boolean|null|undefined} value
 * @returns {{ text: string, tone: 'success'|'warning'|'danger'|'neutral' }}
 */
function describeFactValue(factId, value) {
  if (value === true) {
    return { text: FACT_TRUE_TEXT[factId] ?? 'Подтверждено', tone: 'success' };
  }
  if (value === false) {
    return { text: 'Не пройдено', tone: 'danger' };
  }
  return { text: 'Неизвестно', tone: 'neutral' };
}

/**
 * Преобразует facts из ответа connection-health в массив для UI.
 * @param {HealthFacts|null|undefined} facts
 * @returns {DescribedFact[]}
 */
export function describeFacts(facts) {
  const source = facts ?? {};
  return HEALTH_FACT_ORDER.map((id) => {
    const value = source[id] ?? null;
    const normalized = value === true || value === false ? value : null;
    const { text, tone } = describeFactValue(id, normalized);
    return {
      id,
      label: FACT_LABELS[id] ?? id,
      value: normalized,
      text,
      tone,
    };
  });
}

/**
 * @param {SystemCheckLevelValue} level
 * @returns {{ badgeLabel: string, badgeTone: 'success'|'warning'|'danger'|'neutral' }}
 */
function badgeForLevel(level) {
  switch (level) {
    case SystemCheckLevel.READY:
      return { badgeLabel: 'Готово', badgeTone: 'success' };
    case SystemCheckLevel.LIMITED:
      return { badgeLabel: 'Ограничено', badgeTone: 'warning' };
    case SystemCheckLevel.NOT_READY:
      return { badgeLabel: 'Не готово', badgeTone: 'danger' };
    case SystemCheckLevel.NO_ROUTER:
      return { badgeLabel: 'Нет роутера', badgeTone: 'neutral' };
    case SystemCheckLevel.FAILED:
    default:
      return { badgeLabel: 'Неизвестно', badgeTone: 'neutral' };
  }
}

/**
 * @param {Partial<SystemCheckVerdict> & Pick<SystemCheckVerdict, 'level'|'hubState'|'title'>} fields
 * @param {HealthFacts|null|undefined} rawFacts
 * @param {Date} checkedAt
 * @returns {SystemCheckVerdict}
 */
function buildVerdict(fields, rawFacts, checkedAt) {
  const level = fields.level;
  const badge = badgeForLevel(level);
  return {
    level,
    hubState: fields.hubState,
    title: fields.title,
    description: fields.description ?? null,
    badgeLabel: fields.badgeLabel ?? badge.badgeLabel,
    badgeTone: fields.badgeTone ?? badge.badgeTone,
    reasonCode: fields.reasonCode ?? null,
    facts: fields.facts ?? describeFacts(rawFacts),
    host: fields.host ?? null,
    routerId: fields.routerId ?? null,
    mock: fields.mock ?? false,
    mockNote: fields.mockNote ?? null,
    checkedAt,
  };
}

/**
 * Чистая функция вердикта готовности (M-7 + D-1).
 * READY только при status === 'green', hostKeyConfirmed === true и всех пяти facts строго true
 * (reachable, host_key_match, tuple_match, credentials_present, evidence_fresh) — см. M-7.
 * @param {{ health: ConnectionHealthResponse|null, routerPresent: boolean|null, hostKeyConfirmed: boolean, adapterMode?: string|null }} params
 * @param {boolean|null} params.routerPresent — `true`: список получен, роутер есть;
 *   `false`: список получен и пуст; `null`: наличие роутера неизвестно (список не удалось загрузить)
 * @returns {SystemCheckVerdict}
 */
export function evaluateSystemCheck({ health, routerPresent, hostKeyConfirmed, adapterMode }) {
  const checkedAt = new Date();
  const isFake = adapterMode === 'fake';

  if (routerPresent === null) {
    return buildVerdict(
      {
        level: SystemCheckLevel.FAILED,
        hubState: HubState.WARNING,
        title: 'Не удалось получить состояние системы',
        description:
          'Список роутеров сейчас недоступен — без него нельзя определить готовность. Нажмите «Повторить».',
        reasonCode: null,
        host: null,
        routerId: null,
        mock: isFake,
        mockNote: isFake ? FAKE_MOCK_NOTE : null,
      },
      null,
      checkedAt,
    );
  }

  if (routerPresent === false) {
    return buildVerdict(
      {
        level: SystemCheckLevel.NO_ROUTER,
        hubState: HubState.EMPTY,
        title: 'Роутер не подключён',
        description: 'Сначала подключите роутер — после этого появится состояние системы.',
        reasonCode: null,
        host: null,
        routerId: null,
        mock: isFake,
        mockNote: isFake ? FAKE_MOCK_NOTE : null,
      },
      null,
      checkedAt,
    );
  }

  if (health == null) {
    return buildVerdict(
      {
        level: SystemCheckLevel.FAILED,
        hubState: HubState.WARNING,
        title: 'Готовность не определена',
        description: 'Не удалось определить состояние. Нажмите «Проверить систему».',
        reasonCode: null,
        host: null,
        routerId: null,
        mock: isFake,
        mockNote: isFake ? FAKE_MOCK_NOTE : null,
      },
      null,
      checkedAt,
    );
  }

  const facts = health.facts ?? {};
  const reasonCode = health.reason_code ?? null;
  const host = health.host ?? null;
  const routerId = health.router_id ?? null;
  const describedFacts = describeFacts(facts);

  /** @type {Partial<SystemCheckVerdict> & Pick<SystemCheckVerdict, 'level'|'hubState'|'title'>} */
  let core;

  if (health.status === 'red') {
    if (facts.reachable === false) {
      core = {
        level: SystemCheckLevel.NOT_READY,
        hubState: HubState.CONNECTION_LOST,
        title: 'Нет связи с роутером',
        description: describeReasonCode(reasonCode),
        reasonCode,
        host,
        routerId,
      };
    } else {
      core = {
        level: SystemCheckLevel.NOT_READY,
        hubState: HubState.ERROR,
        title: describeReasonCode(reasonCode),
        description: null,
        reasonCode,
        host,
        routerId,
      };
    }
  } else if (health.status === 'yellow') {
    core = {
      level: SystemCheckLevel.LIMITED,
      hubState: HubState.WARNING,
      title: 'Система работает с ограничениями',
      description: describeReasonCode(reasonCode),
      reasonCode,
      host,
      routerId,
    };
  } else if (health.status === 'green') {
    if (hostKeyConfirmed !== true) {
      core = {
        level: SystemCheckLevel.LIMITED,
        hubState: HubState.WARNING,
        title: 'Нужно подтвердить, что это ваш роутер',
        description:
          'Перед использованием подтвердите устройство в разделе «Подключение». Подтверждение нужно один раз — при первом знакомстве с этим роутером.',
        reasonCode,
        host,
        routerId,
      };
    } else if (
      facts.reachable === true &&
      facts.host_key_match === true &&
      facts.tuple_match === true &&
      facts.credentials_present === true &&
      facts.evidence_fresh === true &&
      hostKeyConfirmed === true
    ) {
      core = {
        level: SystemCheckLevel.READY,
        hubState: HubState.SUCCESS,
        title: 'Система готова к работе',
        description: 'Все проверки связи пройдены',
        reasonCode,
        host,
        routerId,
      };
    } else {
      core = {
        level: SystemCheckLevel.LIMITED,
        hubState: HubState.WARNING,
        title: 'Система работает с ограничениями',
        description: describeReasonCode(reasonCode),
        reasonCode,
        host,
        routerId,
      };
    }
  } else {
    core = {
      level: SystemCheckLevel.FAILED,
      hubState: HubState.WARNING,
      title: 'Готовность не определена',
      description: 'Не удалось определить состояние. Нажмите «Проверить систему».',
      reasonCode,
      host,
      routerId,
    };
  }

  let verdict = buildVerdict(
    {
      ...core,
      facts: describedFacts,
      mock: isFake,
      mockNote: isFake ? FAKE_MOCK_NOTE : null,
    },
    facts,
    checkedAt,
  );

  // В fake READY недостижим — явная защита (решение M-7 / план §2).
  if (isFake && verdict.level === SystemCheckLevel.READY) {
    verdict = buildVerdict(
      {
        ...verdict,
        level: SystemCheckLevel.LIMITED,
        hubState: HubState.WARNING,
        title: 'Система работает с ограничениями',
        description: FAKE_MOCK_NOTE,
        badgeLabel: 'Ограничено',
        badgeTone: 'warning',
        mock: true,
        mockNote: FAKE_MOCK_NOTE,
      },
      facts,
      checkedAt,
    );
  }

  return verdict;
}

/**
 * Выполняет POST /lab/connection-health и возвращает вердикт готовности.
 * @param {{ routerId: string|null, routerPresent?: boolean|null, hostKeyConfirmed: boolean, adapterMode?: string|null, signal?: AbortSignal }} params
 * @param {boolean|null} [params.routerPresent] — если не передан: `true` при routerId, иначе `false`
 * @returns {Promise<SystemCheckVerdict>}
 */
export async function runSystemCheck({
  routerId,
  routerPresent,
  hostKeyConfirmed,
  adapterMode,
  signal,
}) {
  /** @type {boolean|null} */
  let present = routerPresent;
  if (present === undefined) {
    present = routerId != null;
  }

  if (present === null) {
    return evaluateSystemCheck({
      health: null,
      routerPresent: null,
      hostKeyConfirmed,
      adapterMode,
    });
  }

  if (present === false || routerId == null) {
    return evaluateSystemCheck({
      health: null,
      routerPresent: false,
      hostKeyConfirmed,
      adapterMode,
    });
  }

  /** @type {ConnectionHealthResponse} */
  const health = /** @type {ConnectionHealthResponse} */ (
    await apiPost(
      'lab/connection-health',
      { router_id: routerId, probe: true },
      { signal },
    )
  );

  return evaluateSystemCheck({
    health,
    routerPresent: true,
    hostKeyConfirmed,
    adapterMode,
  });
}

/**
 * @param {unknown} err
 * @returns {boolean}
 */
function isTransientHealthRetryError(err) {
  return err instanceof HubApiError
    && SYSTEM_CHECK_TRANSIENT_RETRY_KINDS.includes(err.kind);
}

/**
 * @param {number} ms
 * @param {AbortSignal|undefined} signal
 * @returns {Promise<void>}
 */
function sleepWithAbort(ms, signal) {
  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      cleanup();
      resolve();
    }, ms);

    const onAbort = () => {
      cleanup();
      const reason = signal?.reason;
      if (reason instanceof Error) {
        reject(reason);
        return;
      }
      reject(new HubApiError({
        code: 'client.aborted',
        httpStatus: null,
        userMessage: 'Запрос был отменён.',
        userAction: 'Повторите действие, если это необходимо.',
        serverMessage: null,
        details: [],
        requestId: null,
        correlationId: null,
        kind: ERROR_KIND.ABORTED,
      }));
    };

    const cleanup = () => {
      clearTimeout(timeoutId);
      signal?.removeEventListener('abort', onAbort);
    };

    if (signal?.aborted) {
      onAbort();
      return;
    }

    signal?.addEventListener('abort', onAbort);
  });
}

/**
 * Обёртка runSystemCheck с bounded retry только для overview loadOverview.
 * Не меняет семантику runSystemCheck для экрана «Подключение».
 * @param {Parameters<typeof runSystemCheck>[0]} params
 * @param {{ signal?: AbortSignal, onAttempt?: (info: { attempt: number, maxAttempts: number }) => void }} [options]
 * @returns {Promise<SystemCheckVerdict>}
 */
export async function runSystemCheckWithTransientRetry(params, options = {}) {
  const { signal, onAttempt } = options;
  const maxAttempts = SYSTEM_CHECK_TRANSIENT_MAX_ATTEMPTS;

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    if (signal?.aborted) {
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

    onAttempt?.({ attempt, maxAttempts });

    try {
      return await runSystemCheck({ ...params, signal });
    } catch (err) {
      const isLastAttempt = attempt >= maxAttempts;
      if (!isTransientHealthRetryError(err) || isLastAttempt) {
        throw err;
      }
      const backoffMs = 400 + Math.floor(Math.random() * 401);
      await sleepWithAbort(backoffMs, signal);
    }
  }

  throw new HubApiError({
    code: 'client.unknown',
    httpStatus: null,
    userMessage: 'Не удалось выполнить проверку связи.',
    userAction: 'Повторите позже.',
    serverMessage: null,
    details: [],
    requestId: null,
    correlationId: null,
    kind: ERROR_KIND.UNKNOWN,
  });
}
