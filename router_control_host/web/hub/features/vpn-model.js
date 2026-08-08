/**
 * Модель экрана «VPN» — данные и сетевые вызовы без DOM.
 */

import { apiGet, apiPost, API_BASE } from '../core/api.js';
import { createBadge, createButton } from '../components/index.js';
import {
  HubApiError,
  ERROR_KIND,
  resolveErrorEntry,
  resolveHttpStatusEntry,
} from '../core/errors.js';
import { HubState } from '../core/states.js';
import { createIdempotencyKey } from './connection-flow.js';
import { buildLiveConnectionParams } from './live-connection-params.js';

/** @typedef {{ hubState: string, title: string, message: string, technicalDetail?: string }} VpnStatusLine */

/** @typedef {{ allowed: boolean, reasonText: string|null, missing: string[], mock: boolean }} VpnMutationReadiness */

/** @typedef {{ id: string, title: string, kindLabel: string, validationLabel: string, validationTone: string }} VpnProfileListItem */

/** Литералы вердикта туннеля — зеркало wireguard_apply_service.py. */
export const TUNNEL_VERIFICATION_STATUSES = Object.freeze([
  'tunnel_no_peer',
  'tunnel_never_handshaked',
  'tunnel_healthy',
  'tunnel_unverified',
]);

/** Индексы интерфейсов туннеля по умолчанию (Wireguard5–9, allowlist.py). */
const WIREGUARD_INTERFACE_INDEX_MIN = 5;
const WIREGUARD_INTERFACE_INDEX_MAX = 9;

/** Ожидание рукопожатия на сервере при apply (секунды). */
export const VPN_HANDSHAKE_SETTLE_SECONDS = 25;

/** Запас поверх settle на SSH/readback при apply/teardown (секунды). */
const VPN_APPLY_TEARDOWN_MARGIN_SECONDS = 45;

/** Клиентский таймаут apply/teardown — должен покрывать settle + запас на SSH/readback. */
export const VPN_APPLY_TEARDOWN_TIMEOUT_MS =
  (VPN_HANDSHAKE_SETTLE_SECONDS + VPN_APPLY_TEARDOWN_MARGIN_SECONDS) * 1000;

/** Строка 1: настройки не отправлялись. */
export const VPN_CONFIGURATION_NOT_SENT_MESSAGE =
  'Настройки туннеля на роутер не отправлялись';

/** Строка 1: настройки приняты. */
export const VPN_CONFIGURATION_APPLIED_MESSAGE = 'Настройки туннеля приняты роутером';

/** Строка 1: проверка не подтвердила. */
export const VPN_CONFIGURATION_VERIFY_MISMATCH_MESSAGE =
  'Роутер принял настройки, но проверка их не подтвердила';

/** Строка 1: откат. */
export const VPN_CONFIGURATION_ROLLED_BACK_MESSAGE = 'Настройки откачены обратно';

/** Строка 1: отклонено. */
export const VPN_CONFIGURATION_FAILED_MESSAGE = 'Роутер отклонил настройки туннеля';

/** Зеркало wireguard_apply_service.py — конфигурация принята устройством. */
const CONFIGURATION_ACCEPTED_STATUS = 'device_accepted_configuration';

/** Префикс наблюдаемого admin-state интерфейса при overall=applied. */
const INTERFACE_PRESENT_STATUS_PREFIX = 'interface_present_';

/** interface_absent — успех teardown при overall=applied. */
const INTERFACE_ABSENT_STATUS = 'interface_absent';

/**
 * @param {string|null} status
 * @returns {boolean}
 */
function isConfigurationAccepted(status) {
  return !status || status === CONFIGURATION_ACCEPTED_STATUS;
}

/**
 * @param {string|null} status
 * @returns {boolean}
 */
function isInterfaceObservedOk(status) {
  if (!status) {
    return true;
  }
  return (
    status.startsWith(INTERFACE_PRESENT_STATUS_PREFIX)
    || status === INTERFACE_ABSENT_STATUS
  );
}

/** Строка 2: связь не проверялась. */
export const VPN_TUNNEL_NOT_CHECKED_MESSAGE = 'Связь с сервером VPN не проверялась';

/** Строка 2: данных недостаточно. */
export const VPN_TUNNEL_UNVERIFIED_MESSAGE =
  'Проверить связь не удалось — роутер не сообщил нужных данных';

/** Строка 2: peer не найден. */
export const VPN_TUNNEL_NO_PEER_MESSAGE =
  'В туннеле не настроен сервер VPN — загрузите и разберите конфигурацию заново через «Загрузить конфигурацию».';

/** Строка 2: нет ответа. */
export const VPN_TUNNEL_NEVER_HANDSHAKED_MESSAGE = 'Ответа от сервера VPN нет';

/** Строка 2: сервер отвечает (не означает маршрутизацию трафика устройств). */
export const VPN_TUNNEL_HEALTHY_MESSAGE =
  'Сервер VPN отвечает: рукопожатие есть, данные от сервера приходят. Это не означает, что трафик устройств идёт через VPN';

/** Плитка каталога: сервер отвечает (без жаргона роутера). */
export const VPN_TUNNEL_HEALTHY_TILE_MESSAGE =
  'Сервер VPN отвечает, данные от него приходят. Это не означает, что весь трафик устройств идёт через VPN';

/** Плитка каталога: сервер отвечает и трафик роутера идёт через туннель. */
export const VPN_TUNNEL_ROUTED_TILE_MESSAGE =
  'Сервер VPN отвечает, и сейчас интернет-трафик роутера идёт через этот туннель.';

/** Плитка каталога: сервер отвечает, но трафик роутера не через туннель. */
export const VPN_TUNNEL_NOT_ROUTED_TILE_MESSAGE =
  'Сервер VPN отвечает, но интернет-трафик роутера сейчас идёт другим путём, не через этот туннель. Проверьте приоритет подключения в разделе «Все настройки VPN».';

/** Плитка каталога: сервер отвечает, приоритет канала неизвестен. */
export const VPN_TUNNEL_ROUTING_UNKNOWN_TILE_MESSAGE =
  'Сервер VPN отвечает, но роутер не сообщил, какой канал сейчас в приоритете — куда идёт трафик, не проверено.';

/** Плитка каталога: сервер отвечает, проверка маршрутизации не удалась. */
export const VPN_TUNNEL_ROUTING_CHECK_FAILED_TILE_MESSAGE =
  'Сервер VPN отвечает, но проверить, куда сейчас идёт трафик, не удалось.';

/** Expert/catalog: что означают значки статуса профиля (три состояния + честность про kill-switch). */
export const VPN_PROFILE_TILE_STATUS_HONESTY_NOTE =
  '«Работает» — только когда проверка подтвердила связь с сервером VPN и трафик роутера идёт через этот туннель. Жёлтый значок «Отвечает, не весь трафик» — туннель отвечает, но маршрут по умолчанию у другого интерфейса. «Не подключён» — профиль не активен. Ни один значок не защищает при обрыве: kill-switch на этой прошивке нет, трафик может вернуться на обычный uplink.';

/**
 * One-tap egress priority default (topology-dependent lab floor).
 * VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT — not universal; overridable via activate/import body.
 * Lab bench (M-27): beats station ip global 600 and ISP uplink 700 on observed topology.
 * NDMS rule: higher `ip global` number wins — if another interface has a higher value,
 * it still wins; raise profile priority or lower the uplink priority.
 */
export const VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT = 900;

/** Строка 3: приоритет маршрутизации настроен при подключении (≠ рукопожатие, ≠ kill-switch). */
export const VPN_TRAFFIC_ROUTING_CONFIGURED_MESSAGE =
  'Если VPN отключится, трафик может пойти в обход него — без предупреждения и без автоматической защиты. Если заметили обрыв, нажмите «Переподключить».';

/** Технические подробности приоритета маршрутизации (ip global) — вторично, в раскрывающемся блоке. */
export const VPN_TRAFFIC_ROUTING_TECHNICAL_DETAIL =
  'При подключении настраивается приоритет маршрутизации (ip global). Если у другого интерфейса приоритет ip global выше, трафик пойдёт через него, а не через VPN — повысьте приоритет профиля или понизьте приоритет обычного канала (uplink).';

/** @deprecated используйте VPN_TRAFFIC_ROUTING_CONFIGURED_MESSAGE */
export const VPN_TRAFFIC_ROUTING_UNSUPPORTED_MESSAGE = VPN_TRAFFIC_ROUTING_CONFIGURED_MESSAGE;

/** Ожидание рукопожатия при apply. */
export const VPN_HANDSHAKE_WAIT_MESSAGE =
  'Договариваемся с сервером VPN. Это занимает 20–30 секунд — не закрывайте экран';

/** Kill-switch недоступен. */
export const VPN_KILL_SWITCH_UNSUPPORTED_NOTE =
  'Остановить трафик при сбое VPN нельзя: защита при сбое VPN недоступна на этой прошивке.';

/** Автопереподключение — честный runtime-текст (не «проверено на устройстве»). */
export function describeVpnAutoReconnectNote({ watchdogEnabled = false } = {}) {
  if (watchdogEnabled === null) {
    return 'Состояние автопереподключения неизвестно — не удалось загрузить статус с сервера управления.';
  }
  if (watchdogEnabled) {
    return 'Автоматическое переподключение включено в сервере управления — повтор при сбое без ручного подтверждения команды; работа на роутере не подтверждена.';
  }
  return 'Автоматическое переподключение выключено — при сбое VPN повторите «Переподключить» вручную.';
}

/** @deprecated используйте describeVpnAutoReconnectNote */
export const VPN_AUTO_RECONNECT_UNSUPPORTED_NOTE =
  'Автоматическое переподключение VPN не поддерживается — повторите применение вручную.';

/** Резервный профиль недоступен. */
export const VPN_BACKUP_CHANNEL_UNSUPPORTED_NOTE =
  'Использовать VPN как резервный профиль нельзя: такой режим не поддерживается.';

/** Страна, задержка, внешний IP, время соединения — нет источника. */
export const VPN_GEO_LATENCY_UPTIME_UNSUPPORTED_NOTE =
  'Страна, задержка, внешний IP и время соединения не показываются — роутер не сообщает эти данные';

/** Импорт в каталог ≠ подключение. */
export const VPN_CATALOG_IMPORT_NOT_CONNECTION_NOTE =
  'Импорт в каталог сохраняет профиль для списка, но не подключает VPN и не готовит туннель к применению на роутере.';

/** Кнопка «Убрать» на плитке каталога. */
export const VPN_CATALOG_REMOVE_BUTTON_LABEL = 'Убрать';

/** Заголовок подтверждения удаления из каталога. */
export const VPN_CATALOG_REMOVE_CONFIRM_TITLE = 'Убрать профиль из списка?';

/** Текст подтверждения: каталог ≠ teardown на роутере. */
export const VPN_CATALOG_REMOVE_CONFIRM_LEAD =
  'Профиль исчезнет из списка доступных VPN. Это не снимает настройки с роутера — на роутере ничего дополнительно не меняется.';

/** Подпись кнопки подтверждения удаления из каталога. */
export const VPN_CATALOG_REMOVE_CONFIRM_ACTION = 'Убрать из списка';

/** Отмена удаления из каталога. */
export const VPN_CATALOG_REMOVE_CANCEL = 'Отмена';

/** Отказ при попытке убрать активный профиль. */
export const VPN_CATALOG_REMOVE_ACTIVE_REFUSE =
  'Этот VPN сейчас подключён. Сначала нажмите «Отключить», потом уберите профиль из списка.';

/** После клиентского таймаута apply — честное «не знаем». */
export const VPN_APPLY_TIMEOUT_UNKNOWN_CONFIGURATION_MESSAGE =
  'Не удалось дождаться ответа сервера управления. Настройки могли уже примениться на роутере — проверьте состояние, не повторяйте подключение вслепую.';

/** После клиентского таймаута apply — связь с сервером VPN не подтверждена. */
export const VPN_APPLY_TIMEOUT_UNKNOWN_TUNNEL_MESSAGE =
  'Связь с сервером VPN не подтверждена: ответ сервера управления не получен вовремя. Используйте «Проверить состояние».';

/** Подсказка после apply без подтверждённого рукопожатия (settle уже прошёл). */
export const VPN_POST_SETTLE_RECHECK_HINT =
  'Ожидание 20–30 секунд уже прошло, но ответ сервера VPN всё ещё не подтверждён — повторная проверка только читает состояние, без повторной записи.';

/** Прогресс read-only observe (не handshake). */
export const VPN_OBSERVE_PROGRESS_MESSAGE = 'Проверяем состояние туннеля…';

/** Прогресс validate профиля в каталоге (короткий, без settle-секунд). */
export const VPN_VALIDATE_PROGRESS_MESSAGE =
  'Проверяем профиль в каталоге — обычно до 15 секунд';

/** Прогресс activate профиля из каталога. */
export const VPN_ACTIVATE_PROGRESS_MESSAGE =
  'Активируем профиль на роутере — может занять до ~70 секунд';

/** Прогресс deactivate профиля из каталога. */
export const VPN_DEACTIVATE_PROGRESS_MESSAGE =
  'Отключаем профиль на роутере — может занять до ~70 секунд';

/** Прогресс teardown/disconnect туннеля. */
export const VPN_TEARDOWN_PROGRESS_MESSAGE =
  'Отключаем туннель на роутере — может занять до ~70 секунд';

/** Прогресс preview перед apply. */
export const VPN_PREVIEW_PROGRESS_MESSAGE = 'Проверяем настройки перед применением…';

/** Прогресс optional teardown перед reconnect. */
export const VPN_RECONNECT_TEARDOWN_PROGRESS_MESSAGE =
  'Отключаем прежний туннель перед переподключением…';

/** Аннотация при повторной загрузке каталога (список остаётся на экране). */
export const VPN_CATALOG_REFRESH_MESSAGE = 'Обновляем каталог профилей';

/** Первая загрузка каталога (ещё нет элементов). */
export const VPN_CATALOG_INITIAL_LOAD_MESSAGE = 'Загружаем каталог профилей';

/** Секреты при импорте. */
export const VPN_IMPORT_SECRETS_NOTE =
  'Ключи из файла конфигурации не показываются и не сохраняются в браузере — после разбора остаются только ссылки в хранилище управления.';

/** Разобранный профиль без peer_public_key — apply не сможет настроить сервер VPN. */
export const VPN_PREPARED_PARSE_MISSING_PEER_MESSAGE =
  'В конфигурации нет данных сервера VPN — подключение недоступно';

/** Нераспознанная роль credential ref в профиле. */
export const VPN_PREPARED_PARSE_UNRECOGNIZED_CREDENTIAL_ROLE_MESSAGE =
  'Профиль содержит ключ с нераспознанной ролью — подключение недоступно';

/** Индикатор туннеля при подтверждённом ответе сервера. */
export const VPN_TUNNEL_STATUS_ON_DESCRIPTION =
  'Последняя проверка показала ответ сервера VPN';

/** Индикатор туннеля без подтверждённого ответа. */
export const VPN_TUNNEL_STATUS_OFF_DESCRIPTION =
  'Ответ сервера VPN не подтверждён последней проверкой';

/** @type {Readonly<Record<string, string>>} */
const VPN_KIND_LABELS = Object.freeze({
  AmneziaWG: 'AmneziaWG',
  WireGuard: 'WireGuard',
});

/** @type {Readonly<Record<string, string>>} */
const REJECTED_SIGNAL_REASON_LINES = Object.freeze({
  interface_state_not_evidence:
    'Поле состояния интерфейса (state) проигнорировано — оно не доказывает работу туннеля',
  interface_up_not_evidence:
    'Признак «интерфейс включён» (up) проигнорирован — он не доказывает работу туннеля',
  link_not_evidence:
    'Признак связи канала (link) проигнорирован — он не доказывает работу туннеля',
  connected_not_evidence:
    'Признак connected проигнорирован — он не доказывает работу туннеля',
  peer_enabled_not_evidence:
    'Признак peer_enabled проигнорирован — он не доказывает работу туннеля',
  peer_txbytes_alone_not_evidence:
    'Исходящий трафик без входящего (txbytes) проигнорирован — сам по себе он не доказывает работу туннеля',
});

/** @type {Readonly<Record<string, string>>} */
const MISSING_SIGNAL_LABELS = Object.freeze({
  interface_readable: 'читаемость интерфейса',
  interface_state: 'состояние интерфейса',
  interface_up: 'признак up интерфейса',
  link: 'состояние канала link',
  connected: 'признак connected',
  peer_public_key: 'публичный ключ peer',
  peer_last_handshake: 'время последнего рукопожатия',
  peer_online: 'признак peer_online',
  peer_rxbytes: 'счётчик входящих байт peer',
  peer_txbytes: 'счётчик исходящих байт peer',
  peer_enabled: 'признак peer_enabled',
});

/** @type {Readonly<Record<string, string>>} */
const LIVE_FIELD_LABELS = Object.freeze({
  host: 'адрес роутера',
  username: 'имя пользователя',
  router_credential_ref_id: 'сохранённые учётные данные',
  ssh_host_key_sha256: 'отпечаток ключа устройства',
  source_address: 'локальный адрес этого компьютера',
});

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} snapshot
 * @returns {string[]}
 */
function formatMissingLiveFields(snapshot) {
  const live = buildLiveConnectionParams(snapshot);
  if (live.complete) {
    return [];
  }
  return live.missing.map((field) => LIVE_FIELD_LABELS[field] ?? field);
}

/**
 * @param {Record<string, string|null>} liveParams
 * @param {Record<string, unknown>} body
 */
function attachLiveConnectionFields(liveParams, body) {
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
}

/**
 * @param {string|null|undefined} status
 * @returns {VpnStatusLine}
 */
export function describeTunnelStatus(status) {
  switch (status) {
    case 'tunnel_unverified':
      return {
        hubState: HubState.WARNING,
        title: 'Связь с сервером VPN',
        message: VPN_TUNNEL_UNVERIFIED_MESSAGE,
      };
    case 'tunnel_no_peer':
      return {
        hubState: HubState.WARNING,
        title: 'Связь с сервером VPN',
        message: VPN_TUNNEL_NO_PEER_MESSAGE,
      };
    case 'tunnel_never_handshaked':
      return {
        hubState: HubState.WARNING,
        title: 'Связь с сервером VPN',
        message: VPN_TUNNEL_NEVER_HANDSHAKED_MESSAGE,
      };
    case 'tunnel_healthy':
      return {
        hubState: HubState.WARNING,
        title: 'Связь с сервером VPN',
        message: VPN_TUNNEL_HEALTHY_MESSAGE,
      };
    default:
      return {
        hubState: HubState.EMPTY,
        title: 'Связь с сервером VPN',
        message: VPN_TUNNEL_NOT_CHECKED_MESSAGE,
      };
  }
}

/**
 * @param {unknown} response
 * @returns {string[]}
 */
export function describeConfigurationTechnicalLines(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  /** @type {string[]} */
  const lines = [];
  const overall = typeof payload.overall === 'string' ? payload.overall : null;
  const configurationStatus =
    typeof payload.configuration_verification_status === 'string'
      ? payload.configuration_verification_status
      : null;
  const interfaceStatus =
    typeof payload.interface_verification_status === 'string'
      ? payload.interface_verification_status
      : null;

  if (overall) {
    lines.push(`overall: ${overall}`);
  }
  if (configurationStatus) {
    lines.push(`configuration_verification_status: ${configurationStatus}`);
  }
  if (interfaceStatus) {
    lines.push(`interface_verification_status: ${interfaceStatus}`);
  }
  lines.push(...describeConfigurationRollbackTechnicalLines(response));
  return lines;
}

/**
 * @param {unknown} response
 * @returns {string|null}
 */
export function describeConfigurationRollbackMessage(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const overall = typeof payload.overall === 'string' ? payload.overall : null;
  if (overall !== 'rolled_back') {
    return null;
  }

  const rollback =
    payload.rollback && typeof payload.rollback === 'object'
      ? /** @type {Record<string, unknown>} */ (payload.rollback)
      : null;
  const rollbackErrors = Array.isArray(payload.rollback_errors)
    ? payload.rollback_errors.filter((item) => typeof item === 'string')
    : [];
  const attempted = rollback?.attempted === true;
  const outcome = typeof rollback?.outcome === 'string' ? rollback.outcome : null;

  if (!attempted && outcome === 'not_attempted') {
    return 'Настройки откачены обратно — компенсирующий откат не выполнялся';
  }
  if (outcome === 'succeeded' || outcome === 'noop') {
    return 'Настройки откачены обратно — компенсирующий откат выполнен';
  }
  if (outcome === 'partial') {
    if (rollbackErrors.length > 0) {
      return (
        'Настройки откачены частично — откат выполнен не полностью, роутер может быть в промежуточном состоянии. Проверьте туннель вручную и при необходимости загрузите конфигурацию заново'
      );
    }
    return (
      'Настройки откачены частично — откат выполнен не полностью, проверьте состояние туннеля вручную'
    );
  }
  if (outcome === 'failed' || rollbackErrors.length > 0) {
    return (
      'Настройки откачены обратно, но компенсирующий откат не удался — роутер может быть в промежуточном состоянии. Проверьте туннель вручную и при необходимости загрузите конфигурацию заново'
    );
  }
  return VPN_CONFIGURATION_ROLLED_BACK_MESSAGE;
}

/**
 * @param {unknown} response
 * @returns {string[]}
 */
export function describeConfigurationRollbackTechnicalLines(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  /** @type {string[]} */
  const lines = [];
  const rollback =
    payload.rollback && typeof payload.rollback === 'object'
      ? /** @type {Record<string, unknown>} */ (payload.rollback)
      : null;
  if (rollback) {
    if (typeof rollback.attempted === 'boolean') {
      lines.push(`rollback.attempted: ${rollback.attempted}`);
    }
    if (typeof rollback.outcome === 'string') {
      lines.push(`rollback.outcome: ${rollback.outcome}`);
    }
  }
  const rollbackErrors = Array.isArray(payload.rollback_errors)
    ? payload.rollback_errors.filter((item) => typeof item === 'string')
    : [];
  if (rollbackErrors.length > 0) {
    lines.push(`rollback_errors: ${rollbackErrors.join(', ')}`);
  }
  if (typeof payload.backup_basename === 'string' && payload.backup_basename) {
    lines.push(`backup_basename: ${payload.backup_basename}`);
  }
  return lines;
}

/**
 * @param {unknown} response
 * @returns {VpnStatusLine}
 */
export function describeConfigurationOutcome(response) {
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const overall = typeof payload.overall === 'string' ? payload.overall : null;
  const configurationStatus =
    typeof payload.configuration_verification_status === 'string'
      ? payload.configuration_verification_status
      : null;
  const interfaceStatus =
    typeof payload.interface_verification_status === 'string'
      ? payload.interface_verification_status
      : null;

  if (!overall) {
    return {
      hubState: HubState.EMPTY,
      title: 'Настройка на роутере',
      message: VPN_CONFIGURATION_NOT_SENT_MESSAGE,
    };
  }

  if (overall === 'applied') {
    const needsWarning =
      !isConfigurationAccepted(configurationStatus)
      || !isInterfaceObservedOk(interfaceStatus);
    return {
      hubState: HubState.WARNING,
      title: 'Настройка на роутере',
      message: needsWarning
        ? VPN_CONFIGURATION_VERIFY_MISMATCH_MESSAGE
        : VPN_CONFIGURATION_APPLIED_MESSAGE,
    };
  }

  if (overall === 'verify_mismatch') {
    return {
      hubState: HubState.WARNING,
      title: 'Настройка на роутере',
      message: VPN_CONFIGURATION_VERIFY_MISMATCH_MESSAGE,
    };
  }

  if (overall === 'rolled_back') {
    const rollbackMessage = describeConfigurationRollbackMessage(response);
    return {
      hubState: HubState.WARNING,
      title: 'Настройка на роутере',
      message: rollbackMessage ?? VPN_CONFIGURATION_ROLLED_BACK_MESSAGE,
    };
  }

  if (overall === 'dispatched_offline') {
    return {
      hubState: HubState.WARNING,
      title: 'Настройка на роутере',
      message:
        'Настройки сохранены без связи с роутером — на устройстве туннель не менялся',
    };
  }

  if (overall === 'unsupported_pending_verification') {
    return {
      hubState: HubState.UNSUPPORTED,
      title: 'Настройка на роутере',
      message:
        'Применение туннеля пока недоступно — роутер или параметры ещё не прошли проверку',
    };
  }

  if (overall === 'failed') {
    return {
      hubState: HubState.ERROR,
      title: 'Настройка на роутере',
      message: VPN_CONFIGURATION_FAILED_MESSAGE,
    };
  }

  return {
    hubState: HubState.WARNING,
    title: 'Настройка на роутере',
    message: VPN_CONFIGURATION_NOT_SENT_MESSAGE,
  };
}

/**
 * @returns {VpnStatusLine}
 */
export function describeTrafficRouting() {
  return {
    hubState: HubState.WARNING,
    title: 'Трафик через VPN',
    message: VPN_TRAFFIC_ROUTING_CONFIGURED_MESSAGE,
    technicalDetail: VPN_TRAFFIC_ROUTING_TECHNICAL_DETAIL,
  };
}

/**
 * @param {unknown} verdictExplanation
 * @returns {string[]}
 */
export function describeRejectedSignals(verdictExplanation) {
  const payload =
    verdictExplanation && typeof verdictExplanation === 'object'
      ? /** @type {Record<string, unknown>} */ (verdictExplanation)
      : null;
  const rejected = Array.isArray(payload?.signals_rejected) ? payload.signals_rejected : [];

  /** @type {string[]} */
  const lines = [];
  for (const item of rejected) {
    if (!item || typeof item !== 'object') {
      continue;
    }
    const entry = /** @type {Record<string, unknown>} */ (item);
    const reason = typeof entry.reason === 'string' ? entry.reason : null;
    if (reason && REJECTED_SIGNAL_REASON_LINES[reason]) {
      lines.push(REJECTED_SIGNAL_REASON_LINES[reason]);
    }
  }
  return lines;
}

/**
 * @param {unknown} verdictExplanation
 * @returns {string[]}
 */
export function describeMissingSignals(verdictExplanation) {
  const payload =
    verdictExplanation && typeof verdictExplanation === 'object'
      ? /** @type {Record<string, unknown>} */ (verdictExplanation)
      : null;
  const missing = Array.isArray(payload?.signals_missing) ? payload.signals_missing : [];

  /** @type {string[]} */
  const lines = [];
  for (const item of missing) {
    const signal = typeof item === 'string' ? item : null;
    if (!signal) {
      continue;
    }
    const label = MISSING_SIGNAL_LABELS[signal] ?? signal;
    lines.push(`Роутер не сообщил: ${label}`);
  }
  return lines;
}

/**
 * @param {unknown} response
 * @param {{ intent?: string }} [options]
 * @returns {{ tunnelStatus: VpnStatusLine, configuration: VpnStatusLine, tunnel: VpnStatusLine, trafficRouting: VpnStatusLine, technicalLines: string[], healthy: boolean }}
 */
export function parseTunnelVerdict(response, { intent = 'apply' } = {}) {
  void intent;
  const payload = /** @type {Record<string, unknown>} */ (response ?? {});
  const tunnelVerificationStatus =
    typeof payload.tunnel_verification_status === 'string'
      ? payload.tunnel_verification_status
      : null;
  const configuration = describeConfigurationOutcome(response);
  const tunnelStatus = describeTunnelStatus(tunnelVerificationStatus);
  const trafficRouting = describeTrafficRouting();
  const verdictExplanation = payload.verdict_explanation ?? null;

  /** @type {string[]} */
  const technicalLines = [
    ...describeConfigurationTechnicalLines(response),
    ...(tunnelVerificationStatus
      ? [`tunnel_verification_status: ${tunnelVerificationStatus}`]
      : []),
    ...describeRejectedSignals(verdictExplanation),
    ...describeMissingSignals(verdictExplanation),
  ];

  return {
    tunnelStatus,
    configuration,
    tunnel: tunnelStatus,
    trafficRouting,
    technicalLines,
    healthy: tunnelVerificationStatus === 'tunnel_healthy',
  };
}

/**
 * @param {{ wgId: string, enabled: boolean, ascArgs?: string|null, privateKeyCredentialRefId?: string|null, presharedKeyCredentialRefId?: string|null, peerPublicKey?: string|null, peerEndpoint?: string|null, peerAllowIps?: string|null, peerKeepaliveInterval?: number|null, peerRciShape?: string|null, ipGlobalPriority?: number|null }} params
 * @returns {Record<string, unknown>}
 */
export function buildWireguardIntentBody({
  wgId,
  enabled,
  ascArgs = null,
  privateKeyCredentialRefId = null,
  presharedKeyCredentialRefId = null,
  peerPublicKey = null,
  peerEndpoint = null,
  peerAllowIps = null,
  peerKeepaliveInterval = null,
  peerRciShape = null,
  ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT,
}) {
  /** @type {Record<string, unknown>} */
  const body = {
    wg_id: wgId,
    enabled,
  };

  if (ascArgs) body.asc_args = ascArgs;
  if (privateKeyCredentialRefId) {
    body.private_key_credential_ref_id = privateKeyCredentialRefId;
  }
  if (presharedKeyCredentialRefId) {
    body.preshared_key_credential_ref_id = presharedKeyCredentialRefId;
  }
  if (peerPublicKey) body.peer_public_key = peerPublicKey;
  if (peerEndpoint) body.peer_endpoint = peerEndpoint;
  if (peerAllowIps) body.peer_allow_ips = peerAllowIps;
  if (peerKeepaliveInterval != null) {
    body.peer_keepalive_interval = peerKeepaliveInterval;
  }
  if (peerRciShape) body.peer_rci_shape = peerRciShape;
  if (ipGlobalPriority != null) body.ip_global_priority = ipGlobalPriority;

  return body;
}

/**
 * @param {{ intentBody: Record<string, unknown>, session: import('../core/session.js').SessionSnapshot|null|undefined }} params
 * @returns {Record<string, unknown>}
 */
export function buildWireguardApplyBody({ intentBody, session }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для применения туннеля не хватает параметров живого подключения');
  }

  /** @type {Record<string, unknown>} */
  const body = {
    ...intentBody,
    confirm_live_apply: true,
  };

  if (intentBody.enabled === true) {
    body.handshake_settle_seconds = VPN_HANDSHAKE_SETTLE_SECONDS;
  }

  attachLiveConnectionFields(live.params, body);
  return body;
}

/**
 * @param {{ intentBody: Record<string, unknown>, session: import('../core/session.js').SessionSnapshot|null|undefined }} params
 * @returns {Record<string, unknown>}
 */
export function buildWireguardTeardownBody({ intentBody, session }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для отключения туннеля не хватает параметров живого подключения');
  }

  /** @type {Record<string, unknown>} */
  const body = {
    ...intentBody,
    confirm_live_teardown: true,
  };

  attachLiveConnectionFields(live.params, body);
  return body;
}

/**
 * @param {{ wgId: string, peerPublicKey?: string|null, session: import('../core/session.js').SessionSnapshot|null|undefined }} params
 * @returns {Record<string, unknown>}
 */
export function buildWireguardObserveBody({ wgId, peerPublicKey = null, session }) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для проверки туннеля не хватает параметров живого подключения');
  }

  /** @type {Record<string, unknown>} */
  const body = { wg_id: wgId };
  if (peerPublicKey) body.peer_public_key = peerPublicKey;
  attachLiveConnectionFields(live.params, body);
  return body;
}

/**
 * @param {import('../core/session.js').SessionSnapshot|null|undefined} session
 * @param {string|null|undefined} adapterMode
 * @returns {VpnMutationReadiness}
 */
export function evaluateVpnMutationReadiness(session, adapterMode) {
  const mock = adapterMode === 'fake';
  if (mock) {
    return {
      allowed: false,
      reasonText: 'В демонстрационном режиме изменения VPN недоступны',
      missing: [],
      mock: true,
    };
  }

  const missing = formatMissingLiveFields(session);
  if (missing.length > 0) {
    return {
      allowed: false,
      reasonText:
        'Чтобы менять VPN, сначала завершите подключение к роутеру на экране «Подключение»',
      missing,
      mock: false,
    };
  }

  return {
    allowed: true,
    reasonText: null,
    missing: [],
    mock: false,
  };
}

/**
 * @param {{ lastTunnelVerificationStatus?: string|null, mutationReadiness?: VpnMutationReadiness|null, hasPreparedIntent?: boolean, canParseProfile?: boolean }} params
 * @returns {{ canApply: boolean, canTeardown: boolean, canObserve: boolean, canPrepareProfile: boolean, tunnelStatusIndicatorOn: boolean, tunnelStatusDescription: string }}
 */
export function buildVpnScreenState({
  lastTunnelVerificationStatus = null,
  mutationReadiness = null,
  hasPreparedIntent = false,
  canParseProfile = true,
}) {
  const canMutate = mutationReadiness?.allowed === true;
  const tunnelStatusIndicatorOn = lastTunnelVerificationStatus === 'tunnel_healthy';

  return {
    canApply: Boolean(canMutate && hasPreparedIntent),
    canTeardown: Boolean(canMutate),
    canObserve: Boolean(canMutate),
    canPrepareProfile: Boolean(canParseProfile),
    tunnelStatusIndicatorOn,
    tunnelStatusDescription: tunnelStatusIndicatorOn
      ? VPN_TUNNEL_STATUS_ON_DESCRIPTION
      : VPN_TUNNEL_STATUS_OFF_DESCRIPTION,
  };
}

/**
 * @returns {{ wgId: string, label: string }[]}
 */
export function listVpnTunnelInterfaceOptions() {
  /** @type {{ wgId: string, label: string }[]} */
  const options = [];
  for (let index = WIREGUARD_INTERFACE_INDEX_MIN; index <= WIREGUARD_INTERFACE_INDEX_MAX; index += 1) {
    options.push({
      wgId: `Wireguard${index}`,
      label: `Туннель №${index}`,
    });
  }
  return options;
}

/**
 * Resolve WireGuard interface for a catalog profile (assigned_wg_id wins over UI default).
 * @param {ReadonlyArray<Record<string, unknown>>} catalogItems
 * @param {string} profileId
 * @param {string} [fallbackWgId]
 * @returns {string}
 */
export function resolveVpnProfileWgId(catalogItems, profileId, fallbackWgId = 'Wireguard5') {
  const item = catalogItems.find((row) => {
    const payload = /** @type {Record<string, unknown>} */ (row ?? {});
    return payload.profile_id === profileId;
  });
  const payload = /** @type {Record<string, unknown>} */ (item ?? {});
  const assigned =
    typeof payload.assigned_wg_id === 'string' ? payload.assigned_wg_id.trim() : '';
  if (assigned) {
    return assigned;
  }
  const options = listVpnTunnelInterfaceOptions();
  return options[0]?.wgId ?? fallbackWgId;
}

/**
 * @param {unknown} item
 * @returns {VpnProfileListItem}
 */
export function describeVpnProfileItem(item) {
  const payload = /** @type {Record<string, unknown>} */ (item ?? {});
  const id = typeof payload.profile_id === 'string' ? payload.profile_id : '';
  const title =
    typeof payload.display_name === 'string' && payload.display_name.trim()
      ? payload.display_name.trim()
      : 'Без названия';
  const vpnKindRaw = typeof payload.vpn_kind === 'string' ? payload.vpn_kind.trim() : '';
  const vpnKind = vpnKindRaw || 'unknown';
  const validationStatus =
    typeof payload.validation_status === 'string' ? payload.validation_status : 'Pending';

  let kindLabel = 'Не указан';
  if (vpnKind !== 'unknown') {
    kindLabel = VPN_KIND_LABELS[vpnKind] ?? vpnKind;
  }

  let validationLabel = 'Не проверен';
  let validationTone = 'neutral';
  if (validationStatus === 'Valid') {
    validationLabel = 'Проверен';
    validationTone = 'neutral';
  } else if (validationStatus === 'Invalid' || validationStatus === 'UnsupportedFields') {
    validationLabel = 'Не прошёл проверку';
    validationTone = 'warning';
  }

  return {
    id,
    title,
    kindLabel,
    validationLabel,
    validationTone,
  };
}

/**
 * @param {unknown} item
 * @returns {{ label: string, tone: 'neutral'|'warning'|'danger' }}
 */
export function describeCatalogConnectionBadge(item) {
  const payload = /** @type {Record<string, unknown>} */ (item ?? {});
  if (payload.is_active !== true) {
    return { label: 'Не подключён', tone: 'neutral' };
  }
  return { label: 'Подключён', tone: 'neutral' };
}

/** @typedef {'checking'|'connected_routed'|'connected_not_routed'|'not_working'|'check_failed'|'not_checked'} VpnProfileTileStatusKind */

/** @typedef {{ kind: VpnProfileTileStatusKind, label: string, tone: 'neutral'|'warning'|'danger'|'success', detailMessage: string|null }} VpnProfileTileStatus */

/**
 * @param {unknown} item
 * @returns {VpnProfileTileStatus}
 */
export function describeVpnProfileTileStatus(item) {
  const payload = /** @type {Record<string, unknown>} */ (item ?? {});
  if (payload.is_active !== true) {
    return {
      kind: 'not_checked',
      label: 'Не подключён',
      tone: 'neutral',
      detailMessage: null,
    };
  }

  if (payload.checking === true) {
    return {
      kind: 'checking',
      label: 'Проверяем…',
      tone: 'neutral',
      detailMessage: null,
    };
  }

  const liveProbed = payload.live_probed === true;
  const liveStatus =
    typeof payload.live_tunnel_verification_status === 'string'
      ? payload.live_tunnel_verification_status
      : null;
  const probeError =
    typeof payload.probe_error === 'string' && payload.probe_error.trim()
      ? payload.probe_error.trim()
      : null;

  if (liveProbed && !probeError && liveStatus === 'tunnel_healthy') {
    if (payload.routed_through_tunnel === true) {
      return {
        kind: 'connected_routed',
        label: 'Работает',
        tone: 'success',
        detailMessage: VPN_TUNNEL_ROUTED_TILE_MESSAGE,
      };
    }
    const routingProbeStatus =
      typeof payload.routing_probe_status === 'string' ? payload.routing_probe_status : null;
    let detailMessage;
    if (routingProbeStatus === 'failed') {
      detailMessage = VPN_TUNNEL_ROUTING_CHECK_FAILED_TILE_MESSAGE;
    } else if (payload.routed_through_tunnel === false) {
      detailMessage = VPN_TUNNEL_NOT_ROUTED_TILE_MESSAGE;
    } else {
      detailMessage = VPN_TUNNEL_ROUTING_UNKNOWN_TILE_MESSAGE;
    }
    return {
      kind: 'connected_not_routed',
      label: 'Отвечает, не весь трафик',
      tone: 'warning',
      detailMessage,
    };
  }

  if (
    liveProbed
    && !probeError
    && (liveStatus === 'tunnel_never_handshaked' || liveStatus === 'tunnel_no_peer')
  ) {
    const tunnelLine = describeTunnelStatus(liveStatus);
    return {
      kind: 'not_working',
      label: 'Выбран, но не отвечает',
      tone: 'warning',
      detailMessage: tunnelLine.message,
    };
  }

  if (probeError || (liveProbed && liveStatus === 'tunnel_unverified')) {
    return {
      kind: 'check_failed',
      label: 'Не удалось проверить',
      tone: 'warning',
      detailMessage: probeError ?? VPN_TUNNEL_UNVERIFIED_MESSAGE,
    };
  }

  return {
    kind: 'not_checked',
    label: 'Выбран — статус уточняется',
    tone: 'neutral',
    detailMessage: null,
  };
}

/**
 * @param {{ session: import('../core/session.js').SessionSnapshot|null|undefined, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function fetchVpnCatalogLiveStatus({ session, signal }) {
  const live = buildLiveConnectionParams(session);
  /** @type {Record<string, unknown>} */
  const body = {};
  if (live.complete) {
    attachLiveConnectionFields(live.params, body);
  }
  return apiPost('vpn-profiles/catalog-status', body, { signal });
}

/**
 * @param {{ profileId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function removeVpnProfileFromCatalog({ profileId, signal }) {
  return apiPost(
    `vpn-profiles/${profileId}/remove`,
    { confirm_catalog_remove: true },
    { signal },
  );
}

/**
 * @param {{ items: Array<Record<string, unknown>>, onActivate: (profileId: string) => void, onDeactivate?: (profileId: string) => void, onValidate?: (profileId: string) => void, onRemove?: (profileId: string) => void, busyProfileIds?: Set<string>|Record<string, unknown>, deactivatingProfileIds?: Set<string>|Record<string, unknown>, checkingProfileIds?: Set<string>|Record<string, unknown>, validatingProfileIds?: Set<string>|Record<string, unknown>, disabled?: boolean, showMeta?: boolean }} params
 * @returns {HTMLElement}
 */
export function createVpnProfileStatusTileGrid({
  items,
  onActivate,
  onDeactivate,
  onValidate,
  onRemove,
  busyProfileIds = {},
  deactivatingProfileIds = {},
  checkingProfileIds = {},
  validatingProfileIds = {},
  disabled = false,
  showMeta = true,
}) {
  const grid = document.createElement('div');
  grid.className = 'hub-vpn__tile-grid';

  /**
   * @param {Set<string>|Record<string, unknown>} source
   * @param {string} profileId
   */
  function isSetMember(source, profileId) {
    if (source instanceof Set) {
      return source.has(profileId);
    }
    return Object.prototype.hasOwnProperty.call(source, profileId);
  }

  for (const rawItem of items) {
    const item = /** @type {Record<string, unknown>} */ (rawItem ?? {});
    const profileId =
      typeof item.profile_id === 'string' && item.profile_id.trim()
        ? item.profile_id.trim()
        : '';
    if (!profileId) {
      continue;
    }

    const described = describeVpnProfileItem(item);
    const tileStatus = describeVpnProfileTileStatus(item);
    const tileChecking = item.checking === true || isSetMember(checkingProfileIds, profileId);
    const tileBusy = isSetMember(busyProfileIds, profileId);
    const tileDeactivating = isSetMember(deactivatingProfileIds, profileId);
    const tileValidating = isSetMember(validatingProfileIds, profileId);

    const tile = document.createElement('article');
    tile.className = 'hub-vpn__tile';
    tile.setAttribute('data-hub-vpn-profile-id', profileId);

    const header = document.createElement('div');
    header.className = 'hub-vpn__tile-header';

    const title = document.createElement('h3');
    title.className = 'hub-vpn__tile-title';
    title.textContent = described.title;
    header.appendChild(title);

    header.appendChild(
      createBadge({
        label: tileStatus.label,
        tone: tileStatus.tone,
      }),
    );
    tile.appendChild(header);

    if (showMeta) {
      const meta = document.createElement('div');
      meta.className = 'hub-vpn__tile-meta';
      meta.appendChild(
        createBadge({
          label: described.validationLabel,
          tone: described.validationTone,
        }),
      );
      const kind = document.createElement('span');
      kind.className = 'hub-vpn__tile-kind';
      kind.textContent = described.kindLabel;
      meta.appendChild(kind);
      tile.appendChild(meta);
    }

    if (tileStatus.detailMessage) {
      const detail = document.createElement('p');
      detail.className = 'hub-vpn__tile-detail hub-vpn__note';
      detail.textContent = tileStatus.detailMessage;
      tile.appendChild(detail);
    }

    const actions = document.createElement('div');
    actions.className = 'hub-vpn__tile-actions';

    if (typeof onValidate === 'function') {
      const validateBtn = createButton({
        label: 'Проверить',
        variant: 'ghost',
        disabled: disabled || tileValidating || tileChecking,
        busy: tileValidating,
        onActivate: () => {
          onValidate(profileId);
        },
      });
      validateBtn.id = `hub-vpn-validate-${profileId}`;
      actions.appendChild(validateBtn);
    }

    const tileActive = item.is_active === true;

    if (!tileActive) {
      const activateBtn = createButton({
        label: 'Подключить',
        variant: 'primary',
        disabled: disabled || tileBusy || tileChecking,
        busy: tileBusy,
        onActivate: () => {
          onActivate(profileId);
        },
      });
      activateBtn.id = `hub-vpn-activate-${profileId}`;
      actions.appendChild(activateBtn);
    } else if (typeof onDeactivate === 'function') {
      const deactivateBtn = createButton({
        label: 'Отключить',
        variant: 'danger',
        disabled: disabled || tileDeactivating || tileChecking || tileBusy,
        busy: tileDeactivating,
        onActivate: () => {
          onDeactivate(profileId);
        },
      });
      deactivateBtn.id = `hub-vpn-deactivate-${profileId}`;
      actions.appendChild(deactivateBtn);
    }

    if (typeof onRemove === 'function') {
      const removeBtn = createButton({
        label: VPN_CATALOG_REMOVE_BUTTON_LABEL,
        variant: 'danger',
        disabled:
          disabled
          || tileActive
          || tileChecking
          || tileBusy
          || tileDeactivating
          || tileValidating,
        onActivate: () => {
          onRemove(profileId);
        },
      });
      removeBtn.id = `hub-vpn-remove-${profileId}`;
      actions.appendChild(removeBtn);
    }

    tile.appendChild(actions);
    grid.appendChild(tile);
  }

  return grid;
}

/**
 * @param {string|null|undefined} role
 * @returns {'private'|'preshared'|null}
 */
export function normalizeVpnCredentialRole(role) {
  if (typeof role !== 'string') {
    return null;
  }
  const normalized = role.trim().toLowerCase().replace(/[_-]/g, '');
  if (normalized === 'privatekey') {
    return 'private';
  }
  if (normalized === 'presharedkey') {
    return 'preshared';
  }
  return null;
}

/**
 * @param {unknown} preparedParse
 * @returns {string[]}
 */
export function findUnrecognizedVpnCredentialRoles(preparedParse) {
  const payload = /** @type {Record<string, unknown>} */ (preparedParse ?? {});
  const refs = Array.isArray(payload.credential_refs) ? payload.credential_refs : [];
  /** @type {string[]} */
  const unrecognized = [];
  for (const ref of refs) {
    if (!ref || typeof ref !== 'object') {
      continue;
    }
    const entry = /** @type {Record<string, unknown>} */ (ref);
    const role = typeof entry.role === 'string' ? entry.role : null;
    if (!role || normalizeVpnCredentialRole(role) !== null) {
      continue;
    }
    unrecognized.push(role);
  }
  return unrecognized;
}

/**
 * @param {unknown} preparedParse
 * @returns {{ connectReady: boolean, reasonText: string|null, warnings: string[] }}
 */
export function evaluatePreparedParseConnectReadiness(preparedParse) {
  if (!preparedParse || typeof preparedParse !== 'object') {
    return { connectReady: false, reasonText: null, warnings: [] };
  }
  /** @type {string[]} */
  const warnings = [];
  if (findUnrecognizedVpnCredentialRoles(preparedParse).length > 0) {
    warnings.push(VPN_PREPARED_PARSE_UNRECOGNIZED_CREDENTIAL_ROLE_MESSAGE);
  }
  const intent = buildWireguardIntentFromParsePreview(preparedParse, 'Wireguard5', true);
  const peerKey = intent.peer_public_key;
  if (typeof peerKey !== 'string' || !peerKey.trim()) {
    warnings.push(VPN_PREPARED_PARSE_MISSING_PEER_MESSAGE);
  }
  return {
    connectReady: warnings.length === 0,
    reasonText: warnings.length > 0 ? warnings[0] : null,
    warnings,
  };
}

/**
 * @param {unknown} preparedParse
 * @param {string} wgId
 * @param {boolean} enabled
 * @returns {Record<string, unknown>}
 */
export function buildWireguardIntentFromParsePreview(preparedParse, wgId, enabled) {
  const payload = /** @type {Record<string, unknown>} */ (preparedParse ?? {});
  const refs = Array.isArray(payload.credential_refs) ? payload.credential_refs : [];
  let privateKeyRef = null;
  let presharedKeyRef = null;
  for (const ref of refs) {
    if (!ref || typeof ref !== 'object') {
      continue;
    }
    const entry = /** @type {Record<string, unknown>} */ (ref);
    const normalizedRole = normalizeVpnCredentialRole(
      typeof entry.role === 'string' ? entry.role : null,
    );
    if (
      normalizedRole === 'private'
      && typeof entry.credential_ref_id === 'string'
    ) {
      privateKeyRef = entry.credential_ref_id;
    }
    if (
      normalizedRole === 'preshared'
      && typeof entry.credential_ref_id === 'string'
    ) {
      presharedKeyRef = entry.credential_ref_id;
    }
  }
  let ascArgs = null;
  if (Array.isArray(payload.asc9_args) && payload.asc9_args.length > 0) {
    ascArgs = payload.asc9_args.map((item) => String(item)).join(' ');
  }
  const peerPublicKey =
    typeof payload.peer_public_key === 'string' && payload.peer_public_key.trim()
      ? payload.peer_public_key.trim()
      : null;
  const peerEndpoint =
    typeof payload.peer_endpoint === 'string' && payload.peer_endpoint.trim()
      ? payload.peer_endpoint.trim()
      : null;
  const peerAllowIps =
    typeof payload.peer_allow_ips === 'string' && payload.peer_allow_ips.trim()
      ? payload.peer_allow_ips.trim()
      : null;
  return buildWireguardIntentBody({
    wgId,
    enabled,
    ascArgs,
    privateKeyCredentialRefId: privateKeyRef,
    presharedKeyCredentialRefId: presharedKeyRef,
    peerPublicKey,
    peerEndpoint,
    peerAllowIps,
  });
}

/**
 * @param {unknown} parseResponse
 * @returns {{ operatorLines: string[], technicalLines: string[] }}
 */
export function summarizeParsedProfile(parseResponse) {
  const payload = /** @type {Record<string, unknown>} */ (parseResponse ?? {});
  /** @type {string[]} */
  const operatorLines = [];
  /** @type {string[]} */
  const technicalLines = [];

  const interfaceFields = Array.isArray(payload.interface_field_names)
    ? payload.interface_field_names.filter((item) => typeof item === 'string')
    : [];
  const peerFields = Array.isArray(payload.peer_field_names)
    ? payload.peer_field_names.filter((item) => typeof item === 'string')
    : [];
  const credentialRefs = Array.isArray(payload.credential_refs) ? payload.credential_refs : [];
  const awgParamNames = Array.isArray(payload.awg_param_names)
    ? payload.awg_param_names.filter((item) => typeof item === 'string')
    : [];

  if (interfaceFields.length > 0) {
    technicalLines.push(`interface_field_names: ${interfaceFields.join(', ')}`);
    operatorLines.push('Параметры интерфейса VPN распознаны');
  }
  if (peerFields.length > 0) {
    technicalLines.push(`peer_field_names: ${peerFields.join(', ')}`);
    operatorLines.push('Параметры сервера VPN распознаны');
  }
  if (payload.endpoint_configured === true) {
    operatorLines.push('Адрес сервера VPN указан');
  } else {
    operatorLines.push('Адрес сервера VPN не указан');
  }
  if (payload.interface_address_present === true) {
    operatorLines.push('Адрес интерфейса указан в профиле');
  } else {
    operatorLines.push('Адрес интерфейса в профиле отсутствует');
  }
  if (awgParamNames.length > 0) {
    technicalLines.push(`awg_param_names: ${awgParamNames.join(', ')}`);
    operatorLines.push('Параметры обфускации распознаны');
  }
  let privateKeyStored = false;
  let presharedKeyStored = false;
  for (const ref of credentialRefs) {
    if (!ref || typeof ref !== 'object') {
      continue;
    }
    const entry = /** @type {Record<string, unknown>} */ (ref);
    const role = typeof entry.role === 'string' ? entry.role : 'unknown';
    const refId = typeof entry.credential_ref_id === 'string' ? entry.credential_ref_id : '';
    const kind = typeof entry.kind === 'string' ? entry.kind : 'unknown';
    technicalLines.push(`credential_ref: role=${role}, kind=${kind}, id=${refId}`);
    const normalizedRole = normalizeVpnCredentialRole(role);
    if (normalizedRole === 'private') {
      privateKeyStored = true;
    }
    if (normalizedRole === 'preshared') {
      presharedKeyStored = true;
    }
  }
  if (privateKeyStored) {
    operatorLines.push('Приватный ключ сохранён как ссылка в хранилище управления');
  }
  if (presharedKeyStored) {
    operatorLines.push('Общий ключ (PSK) сохранён как ссылка в хранилище управления');
  }
  for (const role of findUnrecognizedVpnCredentialRoles(parseResponse)) {
    operatorLines.push(
      `Предупреждение: нераспознанная роль ключа «${role}» — подключение будет недоступно`,
    );
  }
  const connectReadiness = evaluatePreparedParseConnectReadiness(parseResponse);
  if (!connectReadiness.connectReady && connectReadiness.reasonText) {
    operatorLines.push(connectReadiness.reasonText);
  }
  if (typeof payload.profile_digest === 'string' && payload.profile_digest) {
    technicalLines.push(`profile_digest: ${payload.profile_digest}`);
  }

  const backendOperatorNotes = Array.isArray(payload.operator_notes)
    ? payload.operator_notes.filter((item) => typeof item === 'string' && item.trim())
    : [];
  for (const note of backendOperatorNotes) {
    operatorLines.push(note);
  }

  const unsupportedFields = Array.isArray(payload.unsupported_fields)
    ? payload.unsupported_fields.filter((item) => typeof item === 'string' && item.trim())
    : [];
  if (unsupportedFields.length > 0) {
    technicalLines.push(`unsupported_fields: ${unsupportedFields.join(', ')}`);
    if (backendOperatorNotes.length === 0) {
      operatorLines.push(
        `Параметры профиля без поддержки в управлении: ${unsupportedFields.join(', ')}`,
      );
    }
  }

  return { operatorLines, technicalLines };
}

/**
 * @param {unknown} detail
 * @returns {string[]}
 */
export function extractVpnProfileOperatorNotes(detail) {
  const payload = /** @type {Record<string, unknown>} */ (detail ?? {});
  if (!Array.isArray(payload.operator_notes)) {
    return [];
  }
  return payload.operator_notes.filter((item) => typeof item === 'string' && item.trim());
}

/**
 * @param {unknown} detail
 * @returns {{ state: 'unknown'|'absent'|'present', seconds?: number, label: string|null }}
 */
export function describeVpnProfileKeepalive(detail) {
  if (!detail || typeof detail !== 'object') {
    return { state: 'unknown', label: null };
  }

  const payload = /** @type {Record<string, unknown>} */ (detail);
  const intentFields =
    payload.wireguard_intent_fields && typeof payload.wireguard_intent_fields === 'object'
      ? /** @type {Record<string, unknown>} */ (payload.wireguard_intent_fields)
      : null;
  const metadata =
    payload.metadata && typeof payload.metadata === 'object'
      ? /** @type {Record<string, unknown>} */ (payload.metadata)
      : null;

  /**
   * @param {Record<string, unknown>|null} source
   * @returns {number|null|undefined}
   */
  function readKeepalive(source) {
    if (!source || !Object.prototype.hasOwnProperty.call(source, 'peer_keepalive_interval')) {
      return undefined;
    }
    const value = source.peer_keepalive_interval;
    if (typeof value === 'number' && Number.isFinite(value)) {
      return value;
    }
    return null;
  }

  let resolved = readKeepalive(intentFields);
  if (resolved === undefined) {
    resolved = readKeepalive(metadata);
  }
  if (resolved === undefined) {
    return {
      state: 'absent',
      label: 'Автоподдержка соединения: не указана',
    };
  }
  if (resolved !== null) {
    return {
      state: 'present',
      seconds: resolved,
      label: `Автоподдержка соединения: каждые ${resolved} с`,
    };
  }
  return {
    state: 'absent',
    label: 'Автоподдержка соединения: не указана',
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
 * POST с Idempotency-Key — api.js не принимает произвольные заголовки.
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
export function listVpnProfiles({ signal } = {}) {
  return apiGet('vpn-profiles', { signal });
}

/**
 * @param {{ profileId: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function getVpnProfile({ profileId, signal }) {
  return apiGet(`vpn-profiles/${profileId}`, { signal });
}

/**
 * @param {{ profileText: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function parseVpnProfileText({ profileText, signal }) {
  return apiPost('vpn-profiles/parse-preview', { profile_text: profileText }, { signal });
}

/**
 * @param {{ displayName: string, profileText: string, vpnKind?: string, wgId?: string, ipGlobalAuto?: boolean, ipGlobalPriority?: number|null, idempotencyKey?: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function importVpnProfileToCatalog({
  displayName,
  profileText,
  vpnKind = 'AmneziaWG',
  wgId = 'Wireguard5',
  ipGlobalAuto = false,
  ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT,
  idempotencyKey,
  signal,
}) {
  const key = idempotencyKey ?? createIdempotencyKey();
  /** @type {Record<string, unknown>} */
  const body = {
    display_name: displayName,
    profile_text: profileText,
    vpn_kind: vpnKind,
    wg_id: wgId,
    ip_global_auto: ipGlobalAuto,
  };
  if (ipGlobalPriority != null) {
    body.ip_global_priority = ipGlobalPriority;
  }
  return postWithHeaders('vpn-profiles/import', body, { 'Idempotency-Key': key }, { signal });
}

/**
 * @param {{ profileId: string, session: import('../core/session.js').SessionSnapshot|null|undefined, wgId?: string|null, logicalRole?: string, ipGlobalAuto?: boolean, ipGlobalPriority?: number|null, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function activateVpnProfile({
  profileId,
  session,
  wgId = null,
  logicalRole = 'primary',
  ipGlobalAuto = false,
  ipGlobalPriority = VPN_ONE_TAP_EGRESS_PRIORITY_DEFAULT,
  signal,
}) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для активации профиля не хватает параметров живого подключения');
  }
  /** @type {Record<string, unknown>} */
  const body = {
    confirm_live_apply: true,
    logical_role: logicalRole,
    ip_global_auto: ipGlobalAuto,
  };
  if (wgId) body.wg_id = wgId;
  if (ipGlobalPriority != null) body.ip_global_priority = ipGlobalPriority;
  attachLiveConnectionFields(live.params, body);
  return apiPost(`vpn-profiles/${profileId}/activate`, body, {
    signal,
    timeoutMs: VPN_APPLY_TEARDOWN_TIMEOUT_MS,
  });
}

/**
 * @param {{ wgId: string, session: import('../core/session.js').SessionSnapshot|null|undefined, logicalRole?: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function deactivateVpnProfile({
  wgId,
  session,
  logicalRole = 'primary',
  signal,
}) {
  const live = buildLiveConnectionParams(session);
  if (!live.complete) {
    throw new Error('Для отключения профиля не хватает параметров живого подключения');
  }
  /** @type {Record<string, unknown>} */
  const body = {
    wg_id: wgId,
    confirm_live_apply: true,
    logical_role: logicalRole,
  };
  attachLiveConnectionFields(live.params, body);
  return apiPost('vpn-profiles/deactivate', body, {
    signal,
    timeoutMs: VPN_APPLY_TEARDOWN_TIMEOUT_MS,
  });
}

/**
 * @param {{ profileId: string, idempotencyKey?: string, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function validateVpnProfile({ profileId, idempotencyKey, signal }) {
  const key = idempotencyKey ?? createIdempotencyKey();
  return postWithHeaders(
    `vpn-profiles/${profileId}/validate`,
    {},
    { 'Idempotency-Key': key },
    { signal },
  );
}

/**
 * @param {{ intentBody: Record<string, unknown>, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function previewVpnTunnel({ intentBody, signal }) {
  return apiPost('wireguard/preview', intentBody, { signal });
}

/**
 * @param {{ applyBody: Record<string, unknown>, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function applyVpnTunnel({ applyBody, signal }) {
  return apiPost('wireguard/apply', applyBody, {
    signal,
    timeoutMs: VPN_APPLY_TEARDOWN_TIMEOUT_MS,
  });
}

/**
 * @param {{ teardownBody: Record<string, unknown>, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function teardownVpnTunnel({ teardownBody, signal }) {
  return apiPost('wireguard/teardown', teardownBody, {
    signal,
    timeoutMs: VPN_APPLY_TEARDOWN_TIMEOUT_MS,
  });
}

/**
 * @param {{ observeBody: Record<string, unknown>, signal?: AbortSignal }} params
 * @returns {Promise<unknown>}
 */
export function observeVpnTunnel({ observeBody, signal }) {
  return apiPost('wireguard/observe', observeBody, { signal });
}
