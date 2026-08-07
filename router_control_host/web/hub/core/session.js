/**

 * Состояние сессии оператора LOCAL HUB — только в памяти процесса (правило О-4).

 * Браузерные хранилища (в том числе постоянные) не используются: состояние живёт только в памяти вкладки (правило О-4).

 *

 * Секреты (пароли, ключи) здесь не хранятся — только opaque credentialRefId

 * и отпечаток SSH-ключа хоста; пароли задаёт экран «Подключение» и не попадают в сессию.

 */



/** @typedef {{ host: string|null, username: string|null, credentialRefId: string|null, sshHostKeySha256: string|null }} WifiLiveParams */



/** @typedef {{ staffApId: string|null, guestApId: string|null }} WifiRoles */



/** @typedef {'idle'|'pending'|'done'|'failed'} ConnectionRestoreState */



/** @typedef {{ routerId: string|null, routerHost: string|null, siteId: string|null, sourceAddress: string|null, hostKeyConfirmed: boolean, liveReady: boolean, usernameAvailable: boolean, pinnedAt: string|null, pinnedEndpointPort: number|null, connectionRestoreState: ConnectionRestoreState, eventPresetId: string|null, eventPresetName: string|null, wifiLive: WifiLiveParams, wifiRoles: WifiRoles }} SessionSnapshot */



/** @type {SessionSnapshot} */

const DEFAULT_SESSION = Object.freeze({

  routerId: null,

  routerHost: null,

  siteId: null,

  sourceAddress: null,

  hostKeyConfirmed: false,

  liveReady: false,

  usernameAvailable: false,

  pinnedAt: null,

  pinnedEndpointPort: null,

  connectionRestoreState: 'idle',

  eventPresetId: null,

  eventPresetName: null,

  wifiLive: Object.freeze({

    host: null,

    username: null,

    credentialRefId: null,

    sshHostKeySha256: null,

  }),

  wifiRoles: Object.freeze({

    staffApId: null,

    guestApId: null,

  }),

});



/** @type {SessionSnapshot} */

let session = createSessionCopy(DEFAULT_SESSION);



/** @type {Set<(snapshot: SessionSnapshot) => void>} */

const subscribers = new Set();



/** Счётчик поколений restore — поздний ответ не перетирает более новую сессию. */

let connectionRestoreGeneration = 0;



/** @type {(() => void)|null} */

let abortConnectionRestoreHandler = null;



/** @type {((signal?: AbortSignal) => Promise<void>)|null} */

let retryConnectionRestoreHandler = null;



/**

 * Глубокое копирование wifiLive и поверхностное остального снимка сессии.

 * @param {SessionSnapshot} source

 * @returns {SessionSnapshot}

 */

function createSessionCopy(source) {

  return {

    routerId: source.routerId,

    routerHost: source.routerHost,

    siteId: source.siteId,

    sourceAddress: source.sourceAddress,

    hostKeyConfirmed: source.hostKeyConfirmed,

    liveReady: source.liveReady,

    usernameAvailable: source.usernameAvailable,

    pinnedAt: source.pinnedAt,

    pinnedEndpointPort: source.pinnedEndpointPort,

    connectionRestoreState: source.connectionRestoreState,

    eventPresetId: source.eventPresetId,

    eventPresetName: source.eventPresetName,

    wifiLive: {

      host: source.wifiLive.host,

      username: source.wifiLive.username,

      credentialRefId: source.wifiLive.credentialRefId,

      sshHostKeySha256: source.wifiLive.sshHostKeySha256,

    },

    wifiRoles: {

      staffApId: source.wifiRoles.staffApId,

      guestApId: source.wifiRoles.guestApId,

    },

  };

}



/** Уведомляет подписчиков о текущем снимке сессии. */

function notifySubscribers() {

  const snapshot = getSession();

  for (const handler of subscribers) {

    handler(snapshot);

  }

}



/**

 * @param {Partial<SessionSnapshot>} patch

 * @param {SessionSnapshot} base

 * @returns {SessionSnapshot}

 */

/**
 * Поля, описывающие предыдущую привязку — сбрасываются при смене routerId,
 * если патч явно не задаёт новое значение.
 * @param {SessionSnapshot} next
 * @param {Partial<SessionSnapshot>} patch
 */
function clearIdentityBoundFields(next, patch) {
  if (patch.routerHost === undefined) {
    next.routerHost = null;
  }
  if (patch.sourceAddress === undefined) {
    next.sourceAddress = null;
  }
  if (!patch.wifiLive || patch.wifiLive.host === undefined) {
    next.wifiLive.host = null;
  }
  if (!patch.wifiLive || patch.wifiLive.credentialRefId === undefined) {
    next.wifiLive.credentialRefId = null;
  }
  if (!patch.wifiLive || patch.wifiLive.username === undefined) {
    next.wifiLive.username = null;
  }
  if (!patch.wifiLive || patch.wifiLive.sshHostKeySha256 === undefined) {
    next.wifiLive.sshHostKeySha256 = null;
  }
}

/**
 * Серверно-резолвимые live-поля недействительны без подтверждённого отпечатка.
 * @param {SessionSnapshot} next
 * @param {Partial<SessionSnapshot>} patch
 */
function clearHostKeyBoundLiveFields(next, patch) {
  if (!patch.wifiLive || patch.wifiLive.username === undefined) {
    next.wifiLive.username = null;
  }
  if (!patch.wifiLive || patch.wifiLive.sshHostKeySha256 === undefined) {
    next.wifiLive.sshHostKeySha256 = null;
  }
}

function applyBindingChangeGuards(patch, base) {

  const next = createSessionCopy(base);

  const routerIdChanging = patch.routerId !== undefined && patch.routerId !== base.routerId;

  const hostKeyReset = patch.hostKeyConfirmed === false && base.hostKeyConfirmed !== false;



  if (patch.routerId !== undefined) next.routerId = patch.routerId;

  if (patch.routerHost !== undefined) next.routerHost = patch.routerHost;

  if (patch.siteId !== undefined) next.siteId = patch.siteId;

  if (patch.sourceAddress !== undefined) next.sourceAddress = patch.sourceAddress;

  if (patch.hostKeyConfirmed !== undefined) next.hostKeyConfirmed = patch.hostKeyConfirmed;

  if (patch.liveReady !== undefined) next.liveReady = patch.liveReady;

  if (patch.usernameAvailable !== undefined) next.usernameAvailable = patch.usernameAvailable;

  if (patch.pinnedAt !== undefined) next.pinnedAt = patch.pinnedAt;

  if (patch.pinnedEndpointPort !== undefined) next.pinnedEndpointPort = patch.pinnedEndpointPort;

  if (patch.connectionRestoreState !== undefined) {

    next.connectionRestoreState = patch.connectionRestoreState;

  }

  if (patch.eventPresetId !== undefined) next.eventPresetId = patch.eventPresetId;

  if (patch.eventPresetName !== undefined) next.eventPresetName = patch.eventPresetName;



  if (routerIdChanging) {

    clearIdentityBoundFields(next, patch);

  }



  if (hostKeyReset) {

    clearHostKeyBoundLiveFields(next, patch);

  }



  if (patch.wifiLive) {

    next.wifiLive = {

      ...next.wifiLive,

      ...patch.wifiLive,

    };

  }



  if (patch.wifiRoles) {

    next.wifiRoles = {

      ...next.wifiRoles,

      ...patch.wifiRoles,

    };

  }



  if (routerIdChanging || hostKeyReset) {

    if (patch.liveReady === undefined) {

      next.liveReady = false;

    }

    if (patch.usernameAvailable === undefined) {

      next.usernameAvailable = false;

    }

    if (patch.pinnedAt === undefined) {

      next.pinnedAt = null;

    }

    if (patch.pinnedEndpointPort === undefined) {

      next.pinnedEndpointPort = null;

    }

  }



  return next;

}



/**

 * Возвращает копию текущего снимка сессии (защита от мутаций снаружи).

 * @returns {SessionSnapshot}

 */

export function getSession() {

  return createSessionCopy(session);

}



/**

 * Поверхностно обновляет сессию и уведомляет подписчиков.

 * Поле wifiLive сливается поверхностно с существующим объектом.

 * @param {Partial<SessionSnapshot> & { wifiLive?: Partial<WifiLiveParams> }} patch

 * @returns {void}

 */

export function updateSession(patch) {

  session = applyBindingChangeGuards(patch, session);

  notifySubscribers();

}



/**

 * Сбрасывает сессию к значениям по умолчанию.

 * @returns {void}

 */

export function resetSession() {

  session = createSessionCopy(DEFAULT_SESSION);

  notifySubscribers();

}



/**

 * Подписка на изменения сессии.

 * @param {(snapshot: SessionSnapshot) => void} handler

 * @returns {() => void} Функция отписки.

 */

export function subscribeSession(handler) {

  subscribers.add(handler);

  return () => {

    subscribers.delete(handler);

  };

}



/**

 * @returns {number}

 */

export function getConnectionRestoreGeneration() {

  return connectionRestoreGeneration;

}



/**

 * @param {() => void} handler

 * @returns {void}

 */

export function registerConnectionRestoreAbortHandler(handler) {

  abortConnectionRestoreHandler = handler;

}



/**

 * @param {(signal?: AbortSignal) => Promise<void>} handler

 * @returns {void}

 */

export function registerConnectionRestoreRetryHandler(handler) {

  retryConnectionRestoreHandler = handler;

}



/**

 * Повтор server-side restore (зарегистрирован app.js при bootstrap).

 * @param {AbortSignal|undefined} [signal]

 * @returns {Promise<void>}

 */

export async function retryConnectionContextRestore(signal) {

  if (!retryConnectionRestoreHandler) {

    throw new Error('Connection restore retry handler is not registered');

  }

  await retryConnectionRestoreHandler(signal);

}



/**

 * Отменяет текущий restore и блокирует применение его результата.

 * @returns {number} Новое поколение restore.

 */

export function cancelConnectionContextRestore() {

  connectionRestoreGeneration += 1;

  abortConnectionRestoreHandler?.();

  if (session.connectionRestoreState === 'pending') {

    session = applyBindingChangeGuards({ connectionRestoreState: 'done' }, session);

    notifySubscribers();

  }

  return connectionRestoreGeneration;

}



/**

 * @returns {number}

 */

export function bumpConnectionRestoreGeneration() {

  connectionRestoreGeneration += 1;

  return connectionRestoreGeneration;

}



/**

 * @param {SessionSnapshot|null|undefined} snapshot

 * @returns {boolean}

 */

export function isConnectionRestorePending(snapshot) {

  return snapshot?.connectionRestoreState === 'pending';

}



/**

 * Ожидает завершения server-side restore (pending → done|failed|idle).

 * @param {{ signal?: AbortSignal }} [options]

 * @returns {Promise<SessionSnapshot>}

 */

export function waitForConnectionRestoreSettle({ signal } = {}) {

  const current = getSession();

  if (current.connectionRestoreState !== 'pending') {

    return Promise.resolve(current);

  }



  return new Promise((resolve, reject) => {

    /** @type {(() => void)|null} */

    let unsub = null;



    const cleanup = () => {

      unsub?.();

      unsub = null;

      signal?.removeEventListener('abort', onAbort);

    };



    const onAbort = () => {

      cleanup();

      const reason = signal?.reason;

      if (reason instanceof Error) {

        reject(reason);

        return;

      }

      reject(new DOMException('Restore settle aborted', 'AbortError'));

    };



    if (signal?.aborted) {

      onAbort();

      return;

    }



    signal?.addEventListener('abort', onAbort);



    unsub = subscribeSession((snapshot) => {

      if (snapshot.connectionRestoreState !== 'pending') {

        cleanup();

        resolve(snapshot);

      }

    });

  });

}



/**

 * Проверяет, что сессия готова к живым Wi‑Fi вызовам.

 * username и sshHostKeySha256 могут отсутствовать во вкладке, если сервер их резолвит.

 * @param {SessionSnapshot|null|undefined} snapshot

 * @returns {boolean}

 */

export function hasCompleteLiveWifiParams(snapshot) {

  if (isConnectionRestorePending(snapshot)) {

    return false;

  }

  if (snapshot?.connectionRestoreState === 'failed') {

    return false;

  }

  if (!snapshot?.wifiLive) {

    return false;

  }

  const host = snapshot.wifiLive.host || snapshot.routerHost;

  const { credentialRefId } = snapshot.wifiLive;

  if (!host || !credentialRefId || !snapshot.routerId) {

    return false;

  }

  if (snapshot.liveReady === true && snapshot.hostKeyConfirmed === true) {

    return true;

  }

  const { username, sshHostKeySha256 } = snapshot.wifiLive;

  return Boolean(username && sshHostKeySha256 && snapshot.hostKeyConfirmed === true);

}


