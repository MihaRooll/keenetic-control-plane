/**



 * LOCAL HUB — точка входа приложения.



 */







import { configureApi, apiGet } from './core/api.js';

import { mountShell } from './core/shell.js';

import {

  getSession,

  updateSession,

  getConnectionRestoreGeneration,

  bumpConnectionRestoreGeneration,

  registerConnectionRestoreAbortHandler,

  registerConnectionRestoreRetryHandler,

} from './core/session.js';

import {

  shouldSkipRestoreApply,

  buildRestoreSessionPatch,

} from './features/live-connection-params.js';

import { mountToastRegion, showToast } from './components/toast.js';







/** Жёсткий предел ожидания restore — после него честный failed, не вечный pending. */

export const CONNECTION_RESTORE_DEADLINE_MS = 20000;







if (typeof navigator !== 'undefined' && 'serviceWorker' in navigator) {



  let reloading = false;
  let updateNoticeShown = false;







  navigator.serviceWorker.addEventListener('controllerchange', () => {



    if (!reloading) {
      return;
    }
    window.location.reload();



  });







  /** @param {ServiceWorker} worker */
  function requestSkipWaiting(worker) {
    worker.postMessage({ type: 'HUB_SKIP_WAITING' });
  }

  /** @param {ServiceWorker} worker */
  function showUpdateNotice(worker) {
    if (updateNoticeShown) {
      return;
    }
    updateNoticeShown = true;
    showToast({
      tone: 'warning',
      title: 'Доступно обновление интерфейса',
      timeoutMs: 0,
      action: {
        label: 'Обновить',
        onClick: () => {
          reloading = true;
          requestSkipWaiting(worker);
        },
      },
    });
  }

  /** @param {ServiceWorker|null|undefined} worker */
  function handleWaitingWorker(worker) {
    if (!worker) {
      return;
    }
    if (navigator.serviceWorker.controller) {
      showUpdateNotice(worker);
      return;
    }
    requestSkipWaiting(worker);
  }

  navigator.serviceWorker
    .register('/settings/router-control/hub/sw.js', {
      scope: '/settings/router-control/hub/',
    })
    .then((registration) => {
      if (registration.waiting) {
        handleWaitingWorker(registration.waiting);
      }

      registration.addEventListener('updatefound', () => {
        const worker = registration.installing;
        if (!worker) {
          return;
        }
        worker.addEventListener('statechange', () => {
          if (worker.state === 'installed') {
            handleWaitingWorker(registration.waiting ?? worker);
          }
        });
      });
    })
    .catch(() => {});



}







/** @type {AbortController|null} */



let activeRestoreAbortController = null;







registerConnectionRestoreAbortHandler(() => {



  activeRestoreAbortController?.abort();



  activeRestoreAbortController = null;



});



registerConnectionRestoreRetryHandler(async (signal) => {

  await restoreConnectionContextFromServer(signal);

});







/**

 * @param {AbortSignal|undefined} userSignal

 * @param {number} deadlineMs

 * @returns {{ signal: AbortSignal, cleanup: () => void }}

 */

function withRestoreDeadline(userSignal, deadlineMs) {

  const deadlineController = new AbortController();

  const timeoutId = setTimeout(() => {

    deadlineController.abort(new Error('connection_restore_deadline'));

  }, deadlineMs);



  if (!userSignal) {

    return {

      signal: deadlineController.signal,

      cleanup: () => {

        clearTimeout(timeoutId);

      },

    };

  }



  if (typeof AbortSignal !== 'undefined' && typeof AbortSignal.any === 'function') {

    return {

      signal: AbortSignal.any([userSignal, deadlineController.signal]),

      cleanup: () => {

        clearTimeout(timeoutId);

      },

    };

  }



  const merged = new AbortController();

  const forwardAbort = () => {

    const reason = userSignal.aborted ? userSignal.reason : deadlineController.signal.reason;

    merged.abort(reason);

  };



  if (userSignal.aborted || deadlineController.signal.aborted) {

    forwardAbort();

    return {

      signal: merged.signal,

      cleanup: () => {

        clearTimeout(timeoutId);

      },

    };

  }



  userSignal.addEventListener('abort', forwardAbort);

  deadlineController.signal.addEventListener('abort', forwardAbort);



  return {

    signal: merged.signal,

    cleanup: () => {

      clearTimeout(timeoutId);

      userSignal.removeEventListener('abort', forwardAbort);

      deadlineController.signal.removeEventListener('abort', forwardAbort);

    },

  };

}







/**

 * @param {AbortSignal|undefined} signal

 * @param {typeof apiGet} apiGetFn

 * @returns {Promise<{ routerId: string, ctx: object }|null>}

 */

export async function fetchRestoreCandidateConnectionContext(signal, apiGetFn = apiGet) {

  const data = /** @type {{

    restore_candidate?: boolean,

    router_id?: string,

  } & Record<string, unknown>} */ (

    await apiGetFn('connection-context/restore-candidate', { signal, retry: 1 })

  );



  if (data?.restore_candidate === false) {

    return null;

  }



  if (data?.restore_candidate === true && typeof data.router_id === 'string') {

    return {

      routerId: data.router_id,

      ctx: data,

    };

  }



  return null;

}







/**

 * Завершает restore, если поколение устарело — pending не должен зависать.

 * @param {number} expectedGeneration

 * @returns {boolean} true, если restore отменён/заменён и вызывающий должен выйти.

 */

function settleSupersededRestore(expectedGeneration) {

  if (expectedGeneration === getConnectionRestoreGeneration()) {

    return false;

  }

  if (getSession().connectionRestoreState === 'pending') {

    updateSession({ connectionRestoreState: 'done' });

  }

  return true;

}



/**

 * Восстанавливает контекст подключения с сервера при загрузке вкладки.

 * Не утверждает достижимость роутера — только факты, сохранённые на сервере.

 * @param {AbortSignal|undefined} signal

 * @param {typeof apiGet} [apiGetFn]

 * @returns {Promise<void>}

 */

export async function restoreConnectionContextFromServer(signal, apiGetFn = apiGet) {

  const generation = bumpConnectionRestoreGeneration();

  const sessionBefore = getSession();



  if (sessionBefore.routerId && sessionBefore.hostKeyConfirmed && sessionBefore.liveReady) {

    updateSession({ connectionRestoreState: 'done' });

    return;

  }



  updateSession({ connectionRestoreState: 'pending' });



  const { signal: boundedSignal, cleanup: releaseDeadline } = withRestoreDeadline(

    signal,

    CONNECTION_RESTORE_DEADLINE_MS,

  );



  try {

    const selected = await fetchRestoreCandidateConnectionContext(boundedSignal, apiGetFn);



    if (settleSupersededRestore(generation)) {

      return;

    }



    if (!selected) {

      updateSession({ connectionRestoreState: 'done', liveReady: false });

      return;

    }



    const { routerId, ctx } = selected;

    const current = getSession();



    if (settleSupersededRestore(generation)) {

      return;

    }



    if (shouldSkipRestoreApply(sessionBefore, current, routerId)) {

      updateSession({ connectionRestoreState: 'done' });

      return;

    }



    if (current.hostKeyConfirmed && current.liveReady && current.wifiLive?.sshHostKeySha256) {

      updateSession({ connectionRestoreState: 'done' });

      return;

    }



    const patch = buildRestoreSessionPatch(

      /** @type {Parameters<typeof buildRestoreSessionPatch>[0]} */ (ctx),

      current,

    );

    updateSession(patch);

  } catch {

    if (settleSupersededRestore(generation)) {

      return;

    }

    updateSession({ connectionRestoreState: 'failed', liveReady: false });

  } finally {

    releaseDeadline();

  }

}







/**

 * @param {unknown} error

 * @returns {string}

 */

function extractErrorDetails(error) {

  if (error instanceof Error) {

    return error.stack || error.message;

  }

  if (typeof error === 'string') {

    return error;

  }

  try {

    return JSON.stringify(error);

  } catch {

    return 'Неизвестная ошибка';

  }

}







/**

 * @param {unknown} error

 */

function showGlobalError(error) {

  showToast({

    tone: 'danger',

    title: 'Произошла ошибка',

    message: 'Что-то пошло не так. Попробуйте обновить страницу или повторить действие.',

    details: extractErrorDetails(error),

    timeoutMs: 0,

  });

}







/**
 * @param {{ mountShellFn?: typeof mountShell, apiGetFn?: typeof apiGet, root?: HTMLElement|null }} [options]
 * @returns {Promise<void>}
 */
export async function bootstrapHub(options = {}) {
  const {
    mountShellFn = mountShell,
    apiGetFn = apiGet,
    root = typeof document !== 'undefined' ? document.getElementById('hub-root') : null,
  } = options;

  const toastRoot = typeof document !== 'undefined' ? document.getElementById('hub-toasts') : null;

  if (toastRoot) {
    mountToastRegion(toastRoot);
  }

  if (!root) {
    return;
  }

  /** Мост для configureApi до завершения mountShell. */
  const bridge = {};

  configureApi({
    onConnectionLost: () => bridge.setConnectionLost?.(),
    onConnectionRestored: () => bridge.setConnectionRestored?.(),
    onUnauthorized: () => bridge.onUnauthorized?.(),
  });

  updateSession({ connectionRestoreState: 'pending' });

  await mountShellFn(root, { bridge });

  activeRestoreAbortController = new AbortController();

  const restoreSignal = activeRestoreAbortController.signal;

  void restoreConnectionContextFromServer(restoreSignal, apiGetFn).finally(() => {
    activeRestoreAbortController = null;
  });
}

async function bootstrap() {
  await bootstrapHub();
}







if (typeof window !== 'undefined') {

  window.addEventListener('error', (event) => {

    showGlobalError(event.error ?? event.message);

  });



  window.addEventListener('unhandledrejection', (event) => {

    showGlobalError(event.reason);

  });



  bootstrap();

}


