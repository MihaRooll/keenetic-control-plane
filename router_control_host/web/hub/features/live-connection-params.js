/**

 * Сбор живых параметров подключения для Wi‑Fi API из снимка сессии (без DOM).

 * Секреты не собираются — только ссылка на учётные данные и отпечаток SSH-ключа.

 */



/** @typedef {{ host: string, username?: string, router_credential_ref_id: string, ssh_host_key_sha256?: string, source_address: string|null, router_id: string|null }} LiveConnectionParamsBody */



/** @typedef {{ complete: true, params: LiveConnectionParamsBody }} LiveConnectionCompleteResult */



/** @typedef {{ complete: false, missing: string[], params: Record<string, never> }} LiveConnectionIncompleteResult */



/** @typedef {LiveConnectionCompleteResult|LiveConnectionIncompleteResult} LiveConnectionParamsResult */



/** Имена полей тела запроса (зеркало WifiLiveConnectionFields на сервере). */

export const LIVE_CONNECTION_FIELD_NAMES = Object.freeze([

  'host',

  'username',

  'router_credential_ref_id',

  'ssh_host_key_sha256',

  'source_address',

  'router_id',

]);



/** Поля, которые клиент обязан передать в сессии (сервер их не выводит). */

export const CLIENT_REQUIRED_FIELD_NAMES = Object.freeze([

  'host',

  'router_credential_ref_id',

  'router_id',

]);



/** Поля, которые сервер резолвит по router_id, если оператор подтвердил пин. */

export const SERVER_RESOLVABLE_FIELD_NAMES = Object.freeze([

  'username',

  'ssh_host_key_sha256',

  'source_address',

]);



/**

 * @param {string|null|undefined} value

 * @returns {boolean}

 */

function hasNonEmptyValue(value) {

  return typeof value === 'string' && value.trim().length > 0;

}



/**

 * @param {string|null|undefined} value

 * @returns {string|null}

 */

function trimOrNull(value) {

  return hasNonEmptyValue(value) ? String(value).trim() : null;

}



/**

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @returns {boolean}

 */

function canOmitServerResolvableFields(snapshot) {

  const routerId = trimOrNull(snapshot?.routerId);

  if (snapshot?.connectionRestoreState === 'pending') {

    return false;

  }

  if (snapshot?.connectionRestoreState === 'failed') {

    return false;

  }

  return Boolean(

    routerId

    && snapshot?.liveReady === true

    && snapshot?.hostKeyConfirmed === true,

  );

}



/**

 * Нужны ли живые параметры для чтения состояния Wi‑Fi при данном режиме адаптера.

 * В демонстрационном режиме состояние читается без них; в живом — нужны.

 * @param {string|null|undefined} adapterMode

 * @returns {boolean}

 */

export function needsLiveConnectionParamsForState(adapterMode) {

  return adapterMode !== 'fake';

}



/**

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @returns {boolean}

 */

export function needsManagementUsernameRecovery(snapshot) {

  return Boolean(

    snapshot?.routerId

    && snapshot.hostKeyConfirmed

    && snapshot.usernameAvailable === false

    && snapshot.liveReady === false

    && snapshot.connectionRestoreState === 'done',

  );

}



/**

 * Честные пробелы восстановленного контекста — факты, не вердикт о готовности.

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @returns {string[]}

 */

export function describeRestoredConnectionGaps(snapshot) {

  if (!snapshot?.routerId || snapshot.connectionRestoreState !== 'done') {

    return [];

  }



  /** @type {string[]} */

  const gaps = [];



  if (snapshot.hostKeyConfirmed !== true) {

    gaps.push('Отпечаток устройства не подтверждён на сервере');

  }



  if (snapshot.usernameAvailable === false) {

    gaps.push('Имя пользователя для управления не сохранено на сервере');

  }



  return gaps;

}



/**

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @returns {boolean}

 */

export function isConnectionRestoreFailed(snapshot) {

  return snapshot?.connectionRestoreState === 'failed';

}



/**

 * @param {string|null|undefined} isoString

 * @returns {string|null}

 */

export function formatOperatorTimestamp(isoString) {

  if (!hasNonEmptyValue(isoString)) {

    return null;

  }

  const date = new Date(String(isoString));

  if (Number.isNaN(date.getTime())) {

    return null;

  }

  return new Intl.DateTimeFormat('ru-RU', {

    day: 'numeric',

    month: 'long',

    year: 'numeric',

    hour: '2-digit',

    minute: '2-digit',

  }).format(date);

}



/**

 * Честная формулировка для блока «Расширенные настройки» Wi‑Fi.

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @param {string|null|undefined} adapterMode

 * @returns {string}

 */

export function describeLiveConnectionAdvancedStatus(snapshot, adapterMode) {

  const live = buildLiveConnectionParams(snapshot);

  if (live.complete) {

    return 'На сервере сохранены все данные для подключения к роутеру — можно пробовать сохранять изменения. Это не означает, что роутер уже ответил.';

  }

  if (adapterMode === 'fake') {

    return 'В демонстрационном режиме подключение к роутеру не требуется.';

  }

  if (isConnectionRestoreFailed(snapshot)) {

    return 'Не удалось проверить сохранённое подключение на сервере — откройте «Подключение» и повторите проверку.';

  }

  if (needsManagementUsernameRecovery(snapshot)) {

    return 'Отпечаток сохранён на сервере, но не хватает имени пользователя — откройте «Подключение» и укажите его.';

  }

  return 'Чтобы менять сеть, сначала завершите подключение к роутеру на экране «Подключение».';

}



/**

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @returns {string}

 */

export function liveCapabilitySubscriptionKey(snapshot) {

  const host = trimOrNull(snapshot?.wifiLive?.host) ?? trimOrNull(snapshot?.routerHost) ?? '';

  const sourceAddress = trimOrNull(snapshot?.sourceAddress) ?? '';

  const credentialRefId = trimOrNull(snapshot?.wifiLive?.credentialRefId) ?? '';

  return [

    snapshot?.routerId ?? '',

    host,

    sourceAddress,

    credentialRefId,

    snapshot?.liveReady ? '1' : '0',

    snapshot?.hostKeyConfirmed ? '1' : '0',

    snapshot?.usernameAvailable ? '1' : '0',

    snapshot?.connectionRestoreState ?? 'idle',

  ].join('|');

}



/**

 * Собирает набор полей для живых Wi‑Fi вызовов из снимка сессии.

 * Либо полный набор, либо признак неполноты — частичный набор не возвращается.

 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot

 * @returns {LiveConnectionParamsResult}

 */

export function buildLiveConnectionParams(snapshot) {

  if (snapshot?.connectionRestoreState === 'pending') {

    return {

      complete: false,

      missing: ['connection_restore_pending'],

      params: {},

    };

  }



  if (snapshot?.connectionRestoreState === 'failed') {

    return {

      complete: false,

      missing: ['connection_restore_failed'],

      params: {},

    };

  }



  const hostKeyConfirmed = snapshot?.hostKeyConfirmed === true;

  const host = trimOrNull(snapshot?.wifiLive?.host) ?? trimOrNull(snapshot?.routerHost);

  const username = hostKeyConfirmed ? trimOrNull(snapshot?.wifiLive?.username) : null;

  const routerCredentialRefId = trimOrNull(snapshot?.wifiLive?.credentialRefId);

  const sshHostKeySha256 = hostKeyConfirmed ? trimOrNull(snapshot?.wifiLive?.sshHostKeySha256) : null;

  const sourceAddress = trimOrNull(snapshot?.sourceAddress);

  const routerId = trimOrNull(snapshot?.routerId);



  /** @type {Record<string, string|null>} */

  const raw = {

    host,

    username,

    router_credential_ref_id: routerCredentialRefId,

    ssh_host_key_sha256: sshHostKeySha256,

    source_address: sourceAddress,

    router_id: routerId,

  };



  /** @type {string[]} */

  const missing = [];

  for (const field of CLIENT_REQUIRED_FIELD_NAMES) {

    if (!raw[field]) {

      missing.push(field);

    }

  }

  if (!canOmitServerResolvableFields(snapshot)) {

    for (const field of SERVER_RESOLVABLE_FIELD_NAMES) {

      if (!raw[field]) {

        missing.push(field);

      }

    }

  }



  if (missing.length > 0) {

    return {

      complete: false,

      missing,

      params: {},

    };

  }



  /** @type {LiveConnectionParamsBody} */

  const params = {

    host: raw.host,

    router_credential_ref_id: raw.router_credential_ref_id,

    source_address: raw.source_address,

    router_id: raw.router_id,

  };

  if (raw.username) {

    params.username = raw.username;

  }

  if (raw.ssh_host_key_sha256) {

    params.ssh_host_key_sha256 = raw.ssh_host_key_sha256;

  }



  return {

    complete: true,

    params,

  };

}



/**

 * @param {import('../core/session.js').SessionSnapshot} startSession

 * @param {import('../core/session.js').SessionSnapshot} currentSession

 * @param {string|null} targetRouterId

 * @returns {boolean}

 */

/**
 * @param {import('../core/session.js').SessionSnapshot} startSession
 * @param {import('../core/session.js').SessionSnapshot} currentSession
 * @returns {boolean}
 */
function operatorDialChangedSinceRestoreStart(startSession, currentSession) {
  if (trimOrNull(startSession.routerId) !== trimOrNull(currentSession.routerId)) {
    return true;
  }

  const startHost = trimOrNull(startSession.wifiLive?.host) ?? trimOrNull(startSession.routerHost);

  const currentHost = trimOrNull(currentSession.wifiLive?.host) ?? trimOrNull(currentSession.routerHost);

  if (startHost !== currentHost) {
    return true;
  }

  if (trimOrNull(startSession.sourceAddress) !== trimOrNull(currentSession.sourceAddress)) {
    return true;
  }

  return false;
}

export function shouldSkipRestoreApply(startSession, currentSession, targetRouterId) {

  if (!targetRouterId) {

    return true;

  }



  if (

    currentSession.routerId

    && startSession.routerId

    && currentSession.routerId !== startSession.routerId

    && currentSession.routerId !== targetRouterId

  ) {

    return true;

  }



  if (

    !startSession.routerId

    && currentSession.routerId

    && currentSession.routerId !== targetRouterId

  ) {

    return true;

  }



  if (

    startSession.routerId

    && currentSession.routerId

    && currentSession.routerId !== targetRouterId

  ) {

    return true;

  }



  if (

    trimOrNull(currentSession.routerId) === trimOrNull(targetRouterId)

    && operatorDialChangedSinceRestoreStart(startSession, currentSession)

  ) {

    return true;

  }



  if (

    startSession.hostKeyConfirmed !== currentSession.hostKeyConfirmed

    && currentSession.hostKeyConfirmed === false

    && startSession.routerId === currentSession.routerId

    && currentSession.routerId === targetRouterId

  ) {

    const startCred = startSession.wifiLive?.credentialRefId ?? null;

    const currentCred = currentSession.wifiLive?.credentialRefId ?? null;

    if (startCred !== currentCred && currentCred) {

      return true;

    }

  }



  return false;

}



/**

 * @param {{

 *   router_id?: string,

 *   host?: string|null,

 *   port?: number|null,

 *   source_address?: string|null,

 *   credential_ref_id?: string|null,

 *   ssh_host_key?: {

 *     confirmed?: boolean,

 *     fingerprint_sha256?: string|null,

 *     pinned_at?: string|null,

 *   },

 *   username_available?: boolean,

 *   live_ready?: boolean,

 * }} ctx

 * @param {import('../core/session.js').SessionSnapshot} current

 * @returns {Partial<import('../core/session.js').SessionSnapshot> & { wifiLive?: Partial<import('../core/session.js').WifiLiveParams> }}

 */

export function buildRestoreSessionPatch(ctx, current) {

  const pinConfirmed = ctx.ssh_host_key?.confirmed === true;

  const liveReady = ctx.live_ready === true;

  const usernameAvailable = ctx.username_available === true;

  const incomingRouterId = typeof ctx.router_id === 'string' ? ctx.router_id : current.routerId;

  const identitySwitched = trimOrNull(incomingRouterId) !== trimOrNull(current.routerId);



  /** @type {Partial<import('../core/session.js').SessionSnapshot> & { wifiLive?: Partial<import('../core/session.js').WifiLiveParams> }} */

  const patch = {

    routerId: incomingRouterId,

    routerHost: typeof ctx.host === 'string'

      ? ctx.host

      : (identitySwitched ? null : current.routerHost),

    sourceAddress:

      typeof ctx.source_address === 'string'

        ? ctx.source_address

        : (identitySwitched ? null : current.sourceAddress),

    hostKeyConfirmed: pinConfirmed,

    liveReady,

    usernameAvailable,

    connectionRestoreState: 'done',

    pinnedEndpointPort: typeof ctx.port === 'number' ? ctx.port : null,

    pinnedAt: typeof ctx.ssh_host_key?.pinned_at === 'string'

      ? ctx.ssh_host_key.pinned_at

      : null,

    wifiLive: {

      host: typeof ctx.host === 'string'

        ? ctx.host

        : (identitySwitched ? null : current.wifiLive.host),

      credentialRefId:

        typeof ctx.credential_ref_id === 'string'

          ? ctx.credential_ref_id

          : (identitySwitched ? null : current.wifiLive.credentialRefId),

    },

  };



  if (pinConfirmed && ctx.ssh_host_key?.fingerprint_sha256) {

    patch.wifiLive.sshHostKeySha256 = ctx.ssh_host_key.fingerprint_sha256;

  }



  return patch;

}


