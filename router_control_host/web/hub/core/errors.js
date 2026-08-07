/**
 * Классификация и пользовательские тексты ошибок API (no-echo).
 * Серверный message никогда не попадает в userMessage / userAction.
 */

/** @typedef {{ userMessage: string, userAction: string, kind: string }} ErrorEntry */

export class HubApiError extends Error {
  /**
   * @param {object} options
   * @param {string|null} [options.code]
   * @param {number|null} [options.httpStatus]
   * @param {string} options.userMessage
   * @param {string|null} [options.userAction]
   * @param {string|null} [options.serverMessage]
   * @param {Array<object>} [options.details]
   * @param {string|null} [options.requestId]
   * @param {string|null} [options.correlationId]
   * @param {string} [options.kind]
   */
  constructor(options = {}) {
    super(options.userMessage ?? 'Произошла ошибка');
    this.name = 'HubApiError';
    this.code = options.code ?? null;
    this.httpStatus = options.httpStatus ?? null;
    this.userMessage = options.userMessage ?? 'Произошла ошибка';
    this.userAction = options.userAction ?? null;
    this.serverMessage = options.serverMessage ?? null;
    this.details = options.details ?? [];
    this.requestId = options.requestId ?? null;
    this.correlationId = options.correlationId ?? null;
    this.kind = options.kind ?? ERROR_KIND.UNKNOWN;
  }
}

export const ERROR_KIND = Object.freeze({
  NETWORK: 'NETWORK',
  TIMEOUT: 'TIMEOUT',
  ABORTED: 'ABORTED',
  UNAUTHORIZED: 'UNAUTHORIZED',
  FORBIDDEN: 'FORBIDDEN',
  NOT_FOUND: 'NOT_FOUND',
  CONFLICT: 'CONFLICT',
  VALIDATION: 'VALIDATION',
  UNSUPPORTED: 'UNSUPPORTED',
  SETUP: 'SETUP',
  DEVICE: 'DEVICE',
  SERVER: 'SERVER',
  UNKNOWN: 'UNKNOWN',
});

/** Точные коды сервера → пользовательский текст (без echo серверного message). */
export const ERROR_MESSAGES = Object.freeze({
  // auth / security
  'auth.required': {
    userMessage: 'Требуется вход в систему.',
    userAction: 'Войдите заново и повторите действие.',
    kind: ERROR_KIND.UNAUTHORIZED,
  },
  'auth.forbidden': {
    userMessage: 'У вас нет прав для этого действия.',
    userAction: 'Обратитесь к администратору или выберите другое действие.',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'security.configuration_blocked': {
    userMessage: 'Операция заблокирована настройками безопасности сервера.',
    userAction: 'Проверьте конфигурацию хоста или обратитесь к администратору.',
    kind: ERROR_KIND.FORBIDDEN,
  },

  // validation
  'request.validation_failed': {
    userMessage: 'Данные запроса заполнены неверно.',
    userAction: 'Проверьте поля формы и исправьте отмеченные ошибки.',
    kind: ERROR_KIND.VALIDATION,
  },
  'profile.validation_failed': {
    userMessage: 'Профиль роутера содержит недопустимые параметры.',
    userAction: 'Проверьте профиль и исправьте некорректные значения.',
    kind: ERROR_KIND.VALIDATION,
  },

  // resources
  'resource.not_found': {
    userMessage: 'Запрошенный ресурс не найден.',
    userAction: 'Обновите страницу или вернитесь к списку.',
    kind: ERROR_KIND.NOT_FOUND,
  },
  'resource.conflict': {
    userMessage: 'Действие конфликтует с текущим состоянием.',
    userAction: 'Обновите данные и повторите попытку.',
    kind: ERROR_KIND.CONFLICT,
  },
  'resource.precondition_failed': {
    userMessage: 'Не выполнены условия для этой операции.',
    userAction: 'Проверьте предварительные шаги и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },
  'router.not_found': {
    userMessage: 'Роутер не найден в системе.',
    userAction: 'Выберите другой роутер или обновите список.',
    kind: ERROR_KIND.NOT_FOUND,
  },

  // server / health / discovery
  'internal.error': {
    userMessage: 'На сервере произошла внутренняя ошибка.',
    userAction: 'Подождите немного и повторите. Если ошибка повторяется — сообщите администратору.',
    kind: ERROR_KIND.SERVER,
  },
  'connection_health.failed': {
    userMessage: 'Не удалось проверить связь с роутером.',
    userAction: 'Убедитесь, что iPad подключён к рабочей сети и роутер доступен.',
    kind: ERROR_KIND.DEVICE,
  },
  'router_discovery.failed': {
    userMessage: 'Не удалось найти роутер по таблице маршрутов и сохранённым адресам.',
    userAction: 'Проверьте подключение к сети, повторите поиск или введите адрес роутера вручную.',
    kind: ERROR_KIND.DEVICE,
  },
  'bootstrap.discovery_failed': {
    userMessage: 'Не удалось выполнить начальное обнаружение.',
    userAction: 'Проверьте сеть и повторите настройку.',
    kind: ERROR_KIND.DEVICE,
  },
  'service.unavailable': {
    userMessage: 'Сервис временно недоступен.',
    userAction: 'Подождите и повторите запрос позже.',
    kind: ERROR_KIND.SERVER,
  },

  // gates
  'gate.a_closed': {
    userMessage: 'Изменения на устройстве сейчас запрещены политикой безопасности.',
    userAction: 'Сначала завершите проверку роутера на экране «Подключение».',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'gate.mutation_forbidden': {
    userMessage: 'Изменение конфигурации роутера сейчас запрещено.',
    userAction: 'Дождитесь завершения текущей операции или проверьте права доступа.',
    kind: ERROR_KIND.FORBIDDEN,
  },

  // router identity / RCI
  'router.identity_mismatch': {
    userMessage: 'Роутер не совпадает с ожидаемой записью.',
    userAction: 'Обновите данные роутера или выполните повторную привязку.',
    kind: ERROR_KIND.CONFLICT,
  },
  'router.rci_mutation_failed': {
    userMessage: 'Не удалось применить команду к роутеру.',
    userAction: 'Проверьте параметры и повторите. При повторе — обратитесь к администратору.',
    kind: ERROR_KIND.DEVICE,
  },

  // idempotency / session
  'idempotency.conflict': {
    userMessage: 'Такой запрос уже выполнялся с другими параметрами.',
    userAction: 'Обновите страницу и отправьте запрос заново.',
    kind: ERROR_KIND.CONFLICT,
  },
  'idempotency.in_progress': {
    userMessage: 'Похожий запрос уже выполняется.',
    userAction: 'Подождите завершения и обновите статус.',
    kind: ERROR_KIND.CONFLICT,
  },
  'session_binding_mismatch': {
    userMessage: 'Сеанс работы сброшен или устарел.',
    userAction: 'Обновите страницу и повторите действие.',
    kind: ERROR_KIND.CONFLICT,
  },

  // plan
  'plan.stale': {
    userMessage: 'План устарел — данные на сервере изменились.',
    userAction: 'Обновите план и повторите операцию.',
    kind: ERROR_KIND.CONFLICT,
  },
  'plan.precondition_failed': {
    userMessage: 'План не готов к этому шагу.',
    userAction: 'Выполните необходимые подготовительные действия.',
    kind: ERROR_KIND.CONFLICT,
  },
  'plan.unbound_requires_recompile': {
    userMessage: 'План нужно пересобрать перед применением.',
    userAction: 'Пересоберите план и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },

  // job
  'job.recovery_not_allowed': {
    userMessage: 'Восстановление этой задачи сейчас невозможно.',
    userAction: 'Проверьте статус задачи или создайте новую.',
    kind: ERROR_KIND.CONFLICT,
  },
  'job.already_terminal': {
    userMessage: 'Задача уже завершена и не может быть изменена.',
    userAction: 'Обновите список задач.',
    kind: ERROR_KIND.CONFLICT,
  },

  // wifi (точные коды)
  'wifi.gate_a_required': {
    userMessage: 'Для операций с Wi‑Fi нужна предварительная проверка роутера.',
    userAction: 'Сначала завершите проверку роутера на экране «Подключение».',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'wifi.live_connection_required': {
    userMessage: 'Для Wi‑Fi не хватает параметров подключения в этой сессии.',
    userAction: 'Завершите настройку на экране «Подключение» и вернитесь сюда.',
    kind: ERROR_KIND.SETUP,
  },
  'wifi.live_connection_incomplete': {
    userMessage: 'Подключение к роутеру в сессии заполнено не полностью.',
    userAction: 'Дозаполните поля на экране «Подключение» и повторите.',
    kind: ERROR_KIND.SETUP,
  },
  'wifi.live_platform_unsupported': {
    userMessage: 'Эта Wi‑Fi операция не поддерживается на данном роутере.',
    userAction: 'Выберите другой способ или обратитесь к администратору.',
    kind: ERROR_KIND.UNSUPPORTED,
  },
  'wifi.ap_forbidden': {
    userMessage: 'Эту сеть нельзя изменить через управление.',
    userAction: 'Выберите другую сеть в списке или проверьте настройки на роутере.',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'wifi.site_survey_radio_forbidden': {
    userMessage: 'Просмотр соседних Wi‑Fi сетей для этого диапазона недоступен.',
    userAction: 'Выберите другой диапазон или измените настройки на роутере.',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'wifi.confirm_required': {
    userMessage: 'Перед сохранением Wi‑Fi нужно подтвердить действие.',
    userAction: 'Просмотрите список изменений и подтвердите операцию.',
    kind: ERROR_KIND.CONFLICT,
  },
  'wifi.credential_ref_required': {
    userMessage: 'Без пароля сохранить включённую сеть нельзя.',
    userAction: 'Введите пароль в поле «Пароль» и нажмите «Сохранить» снова.',
    kind: ERROR_KIND.CONFLICT,
  },
  'wifi.station_confirm_required': {
    userMessage: 'Для подключения Wi‑Fi-устройства нужно подтверждение.',
    userAction: 'Просмотрите параметры и подтвердите подключение.',
    kind: ERROR_KIND.CONFLICT,
  },
  'wifi.preview_failed': {
    userMessage: 'Не удалось подготовить изменения Wi‑Fi.',
    userAction: 'Проверьте параметры и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.apply_failed': {
    userMessage: 'Не удалось сохранить Wi‑Fi настройки.',
    userAction: 'Проверьте параметры и повторите. При повторе — проверьте связь с роутером.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.station_apply_failed': {
    userMessage: 'Не удалось подключить Wi‑Fi-устройство.',
    userAction: 'Проверьте параметры сети и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.site_survey_failed': {
    userMessage: 'Не удалось получить список соседних Wi‑Fi сетей.',
    userAction: 'Проверьте связь с роутером и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.station_preview_failed': {
    userMessage: 'Не удалось построить план подключения роутера к сети.',
    userAction: 'Проверьте выбранную сеть и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.ssh_host_key_mismatch': {
    userMessage: 'Отпечаток устройства не совпал — подключение отклонено.',
    userAction: 'Убедитесь, что это тот же роутер, и подтвердите отпечаток заново.',
    kind: ERROR_KIND.CONFLICT,
  },
  'wifi.credential_not_found': {
    userMessage: 'Сохранённый доступ к роутеру не найден в этой сессии.',
    userAction: 'Сохраните доступ заново на экране «Подключение».',
    kind: ERROR_KIND.SETUP,
  },
  'wifi.credential_unusable': {
    userMessage: 'Сохранённый доступ к роутеру в сессии не читается.',
    userAction: 'Сохраните доступ заново на экране «Подключение».',
    kind: ERROR_KIND.SETUP,
  },
  'wifi.live_transport_failed': {
    userMessage: 'Не удалось связаться с роутером напрямую.',
    userAction: 'Проверьте сеть и повторите позже.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.observed_state_failed': {
    userMessage: 'Не удалось получить текущее состояние Wi‑Fi.',
    userAction: 'Обновите данные или проверьте связь с роутером.',
    kind: ERROR_KIND.DEVICE,
  },
  'wifi.live_backup_unavailable': {
    userMessage: 'Не удалось создать резервную копию конфигурации перед применением.',
    userAction: 'Проверьте связь с роутером и повторите. Если ошибка сохраняется — обратитесь к администратору.',
    kind: ERROR_KIND.SERVER,
  },
  'wifi.guest_isolation_unsupported': {
    userMessage: 'Изоляция гостевой сети на этом роутере пока не поддерживается.',
    userAction: 'Настройте гостевую сеть как отдельное имя с паролем или обратитесь к администратору.',
    kind: ERROR_KIND.UNSUPPORTED,
  },
  'wifi.captive_portal_unsupported': {
    userMessage: 'Страница входа для гостевой сети на этом роутере не поддерживается.',
    userAction: 'Используйте QR-код сети — гость подключится без ручного ввода пароля.',
    kind: ERROR_KIND.UNSUPPORTED,
  },

  // wireguard
  'wireguard.wg_forbidden': {
    userMessage: 'Операции с VPN-туннелем сейчас запрещены.',
    userAction: 'Проверьте права доступа и настройки безопасности.',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'wireguard.confirm_required': {
    userMessage: 'Для применения настроек VPN нужно подтверждение.',
    userAction: 'Просмотрите предпросмотр и подтвердите операцию.',
    kind: ERROR_KIND.CONFLICT,
  },
  'wireguard.preview_failed': {
    userMessage: 'Не удалось подготовить предпросмотр настроек VPN.',
    userAction: 'Проверьте параметры туннеля и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'wireguard.apply_failed': {
    userMessage: 'Не удалось применить настройки VPN.',
    userAction: 'Проверьте параметры и повторите.',
    kind: ERROR_KIND.DEVICE,
  },

  // keendns
  'keendns.preview_failed': {
    userMessage: 'Не удалось подготовить заявку на публикацию.',
    userAction: 'Проверьте имя и домен и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'keendns.confirm_required': {
    userMessage: 'Для публикации имени нужно подтверждение.',
    userAction: 'Подтвердите операцию и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },
  'keendns.apply_failed': {
    userMessage: 'Не удалось отправить команду на роутер.',
    userAction: 'Проверьте имя, домен и подключение, затем повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'keendns.component_absent': {
    userMessage: 'На роутере нет компонента для облачного имени.',
    userAction: 'Установите компонент ndns на роутере или обратитесь к администратору.',
    kind: ERROR_KIND.DEVICE,
  },
  'keendns.inventory_unreadable': {
    userMessage: 'Не удалось прочитать список компонентов роутера.',
    userAction: 'Проверьте подключение к роутеру и повторите через несколько секунд.',
    kind: ERROR_KIND.DEVICE,
  },
  'keendns.expendable_required': {
    userMessage: 'Публикация в облаке доступна только на expendable lab.',
    userAction: 'Проверьте класс lab-роутера или обратитесь к администратору.',
    kind: ERROR_KIND.FORBIDDEN,
  },
  'keendns.live_connection_incomplete': {
    userMessage: 'Не хватает данных для подключения к роутеру.',
    userAction: 'Завершите подключение на экране «Подключение» и повторите.',
    kind: ERROR_KIND.VALIDATION,
  },
  'keendns.gate_a_required': {
    userMessage: 'Нужна свежая сертификация Gate A перед записью на роутер.',
    userAction: 'Выполните recert Gate A и повторите.',
    kind: ERROR_KIND.FORBIDDEN,
  },

  // host-side probes (operator workstation)
  'host_http.failed': {
    userMessage: 'Не удалось проверить локальное приложение с этого компьютера.',
    userAction: 'Проверьте адрес приложения и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'host_http.preset_not_found': {
    userMessage: 'Мероприятие или адрес приложения не найдены.',
    userAction: 'Выберите мероприятие и задайте локальный адрес приложения.',
    kind: ERROR_KIND.NOT_FOUND,
  },
  'host_tls.failed': {
    userMessage: 'Не удалось проверить сертификат локального приложения.',
    userAction: 'Проверьте адрес приложения и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'host_tls.preset_not_found': {
    userMessage: 'Мероприятие или адрес приложения не найдены.',
    userAction: 'Выберите мероприятие и задайте локальный адрес приложения.',
    kind: ERROR_KIND.NOT_FOUND,
  },
  'host_tls.hostname_not_allowed': {
    userMessage: 'Имя для проверки сертификата задано неверно.',
    userAction: 'Проверьте локальный адрес приложения и повторите.',
    kind: ERROR_KIND.VALIDATION,
  },
  'host_internet.failed': {
    userMessage: 'Не удалось проверить интернет с этого компьютера.',
    userAction: 'Проверьте сеть и повторите.',
    kind: ERROR_KIND.DEVICE,
  },

  // network family previews
  'vlan.preview_failed': {
    userMessage: 'Не удалось подготовить предпросмотр сетевых настроек.',
    userAction: 'Проверьте параметры и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'dhcp.preview_failed': {
    userMessage: 'Не удалось подготовить предпросмотр сетевых настроек.',
    userAction: 'Проверьте параметры и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'dns.preview_failed': {
    userMessage: 'Не удалось подготовить предпросмотр сетевых настроек.',
    userAction: 'Проверьте параметры и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'firewall.preview_failed': {
    userMessage: 'Не удалось подготовить предпросмотр правил доступа.',
    userAction: 'Проверьте правила и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'vpn.policy_routing_preview_failed': {
    userMessage: 'Не удалось подготовить предпросмотр VPN-маршрутизации.',
    userAction: 'Проверьте параметры VPN и повторите.',
    kind: ERROR_KIND.DEVICE,
  },

  // ssh host key
  'ssh_host_key.learn_failed': {
    userMessage: 'Не удалось получить отпечаток устройства.',
    userAction: 'Проверьте, что роутер включён и доступен по сети, затем повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'ssh_host_key.invalid_pin': {
    userMessage: 'Отпечаток устройства не совпал или подтверждение недоступно.',
    userAction: 'Получите отпечаток заново и подтвердите его.',
    kind: ERROR_KIND.VALIDATION,
  },
  'ssh_host_key.pin_conflict': {
    userMessage: 'Новый отпечаток устройства не совпадает с сохранённым.',
    userAction: 'Подтверждайте замену, только если роутер действительно меняли. Иначе обратитесь к администратору.',
    kind: ERROR_KIND.CONFLICT,
  },

  // traffic
  'traffic.observation_failed': {
    userMessage: 'Не удалось собрать данные о трафике.',
    userAction: 'Проверьте связь с роутером и повторите.',
    kind: ERROR_KIND.DEVICE,
  },
  'traffic.proposal_failed': {
    userMessage: 'Не удалось подготовить предложение по трафику.',
    userAction: 'Обновите данные и повторите.',
    kind: ERROR_KIND.DEVICE,
  },

  // misc
  'feature.degraded': {
    userMessage: 'Функция работает в ограниченном режиме.',
    userAction: 'Некоторые действия могут быть недоступны. Повторите позже или обратитесь к администратору.',
    kind: ERROR_KIND.UNSUPPORTED,
  },
  'commissioning.cancelled': {
    userMessage: 'Операция настройки была отменена.',
    userAction: 'Начните настройку заново, если это необходимо.',
    kind: ERROR_KIND.CONFLICT,
  },
  'publication.not_valid_offline': {
    userMessage: 'Публикация недоступна в автономном режиме.',
    userAction: 'Подключитесь к сети и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },
  'precondition.required': {
    userMessage: 'Не выполнены обязательные предварительные условия.',
    userAction: 'Выполните необходимые шаги и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },
  'revision.precondition_failed': {
    userMessage: 'Черновик ещё не готов к публикации.',
    userAction: 'Сохраните черновик и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },
  'adopt_acknowledgment_required': {
    userMessage: 'Для принятия изменений нужно явное подтверждение.',
    userAction: 'Подтвердите принятие и повторите.',
    kind: ERROR_KIND.CONFLICT,
  },
  'sealed_apply.trail_begin_failed': {
    userMessage: 'Не удалось начать защищённое применение настроек.',
    userAction: 'Повторите позже или обратитесь к администратору.',
    kind: ERROR_KIND.SERVER,
  },
  'http.method_not_allowed': {
    userMessage: 'Этот тип запроса не поддерживается.',
    userAction: 'Обновите приложение или повторите другое действие.',
    kind: ERROR_KIND.UNKNOWN,
  },

  // entry pages
  'entry.page_not_found': {
    userMessage: 'Страница входа не найдена.',
    userAction: 'Обновите список или создайте страницу заново.',
    kind: ERROR_KIND.NOT_FOUND,
  },
  'entry.revision_not_found': {
    userMessage: 'Черновик страницы не найден.',
    userAction: 'Сохраните черновик и повторите публикацию.',
    kind: ERROR_KIND.NOT_FOUND,
  },
  'entry.validation_failed': {
    userMessage: 'Содержимое страницы заполнено неверно.',
    userAction: 'Проверьте поля редактора и исправьте ошибки.',
    kind: ERROR_KIND.VALIDATION,
  },
  'entry.html_not_allowed': {
    userMessage: 'Символы «<» и «>» в тексте не допускаются.',
    userAction: 'Используйте обычный текст без символов «<» и «>».',
    kind: ERROR_KIND.VALIDATION,
  },
  'entry.not_published': {
    userMessage: 'Страница входа ещё не опубликована.',
    userAction: 'Сохраните черновик и опубликуйте страницу.',
    kind: ERROR_KIND.CONFLICT,
  },
  'entry.submissions_disabled': {
    userMessage: 'Отправка формы на этой странице отключена.',
    userAction: 'Включите приём отправок в редакторе или измените страницу.',
    kind: ERROR_KIND.CONFLICT,
  },
  'entry.rate_limited': {
    userMessage: 'Слишком много запросов к странице входа.',
    userAction: 'Подождите и повторите позже.',
    kind: ERROR_KIND.CONFLICT,
  },
  'entry.failed': {
    userMessage: 'Не удалось выполнить операцию со страницей входа.',
    userAction: 'Повторите позже. Если ошибка сохраняется — обратитесь к администратору.',
    kind: ERROR_KIND.SERVER,
  },
});

/** Префиксные правила (от более длинного к короткому) для кодов семейств. */
const PREFIX_RULES = [
  { prefix: 'wifi.', entry: {
    userMessage: 'Ошибка операции Wi‑Fi.',
    userAction: 'Проверьте параметры и связь с роутером, затем повторите.',
    kind: ERROR_KIND.DEVICE,
  }},
  { prefix: 'wireguard.', entry: {
    userMessage: 'Ошибка операции VPN.',
    userAction: 'Проверьте параметры туннеля и повторите.',
    kind: ERROR_KIND.DEVICE,
  }},
  { prefix: 'keendns.', entry: {
    userMessage: 'Ошибка при подготовке публикации.',
    userAction: 'Проверьте имя и домен и повторите.',
    kind: ERROR_KIND.DEVICE,
  }},
  { prefix: 'host_http.', entry: {
    userMessage: 'Ошибка проверки локального приложения.',
    userAction: 'Проверьте адрес приложения и повторите.',
    kind: ERROR_KIND.DEVICE,
  }},
  { prefix: 'host_tls.', entry: {
    userMessage: 'Ошибка проверки сертификата приложения.',
    userAction: 'Проверьте адрес приложения и повторите.',
    kind: ERROR_KIND.DEVICE,
  }},
  { prefix: 'host_internet.', entry: {
    userMessage: 'Ошибка проверки интернета с компьютера оператора.',
    userAction: 'Проверьте сеть и повторите.',
    kind: ERROR_KIND.DEVICE,
  }},
  { prefix: 'preset.', entry: {
    userMessage: 'Ошибка операции с мероприятием.',
    userAction: 'Обновите данные и повторите.',
    kind: ERROR_KIND.CONFLICT,
  }},
  { prefix: 'plan.', entry: {
    userMessage: 'Ошибка работы с планом изменений.',
    userAction: 'Обновите план и повторите операцию.',
    kind: ERROR_KIND.CONFLICT,
  }},
  { prefix: 'job.', entry: {
    userMessage: 'Ошибка выполнения задачи.',
    userAction: 'Проверьте статус задачи и повторите.',
    kind: ERROR_KIND.CONFLICT,
  }},
  { prefix: 'gate.', entry: {
    userMessage: 'Операция заблокирована политикой безопасности.',
    userAction: 'Проверьте условия доступа и повторите.',
    kind: ERROR_KIND.FORBIDDEN,
  }},
  { prefix: 'http.', entry: {
    userMessage: 'Запрос отклонён сервером.',
    userAction: 'Повторите позже или обратитесь к администратору.',
    kind: ERROR_KIND.UNKNOWN,
  }},
];

const UNKNOWN_ENTRY = Object.freeze({
  userMessage: 'Не удалось выполнить запрос.',
  userAction: 'Повторите позже. Если ошибка сохраняется — обратитесь к администратору.',
  kind: ERROR_KIND.UNKNOWN,
});

const CLIENT_ENTRIES = Object.freeze({
  [ERROR_KIND.NETWORK]: {
    userMessage: 'Нет связи с сервером.',
    userAction: 'Проверьте, что iPad подключён к рабочей сети, и повторите.',
    kind: ERROR_KIND.NETWORK,
  },
  [ERROR_KIND.TIMEOUT]: {
    userMessage: 'Сервер не ответил вовремя.',
    userAction: 'Проверьте сеть и повторите запрос.',
    kind: ERROR_KIND.TIMEOUT,
  },
  [ERROR_KIND.ABORTED]: {
    userMessage: 'Запрос был отменён.',
    userAction: 'Повторите действие, если это необходимо.',
    kind: ERROR_KIND.ABORTED,
  },
});

/** HTTP-статус → код ошибки (зеркало _HTTP_STATUS_MESSAGES на сервере). */
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
 * Классификация HTTP-статуса в ERROR_KIND.
 * @param {number} status
 * @returns {string}
 */
export function classifyHttpStatus(status) {
  if (status === 401) return ERROR_KIND.UNAUTHORIZED;
  if (status === 403) return ERROR_KIND.FORBIDDEN;
  if (status === 404) return ERROR_KIND.NOT_FOUND;
  if (status === 409 || status === 412) return ERROR_KIND.CONFLICT;
  if (status === 422 || status === 400) return ERROR_KIND.VALIDATION;
  if (status === 503 || status >= 500) return ERROR_KIND.SERVER;
  return ERROR_KIND.UNKNOWN;
}

/**
 * Поиск пользовательского текста по коду сервера (без echo).
 * @param {string|null|undefined} code
 * @returns {ErrorEntry}
 */
export function resolveErrorEntry(code) {
  if (code && ERROR_MESSAGES[code]) {
    return ERROR_MESSAGES[code];
  }
  if (code) {
    for (const rule of PREFIX_RULES) {
      if (code.startsWith(rule.prefix)) {
        return rule.entry;
      }
    }
  }
  return UNKNOWN_ENTRY;
}

/**
 * Поиск текста по HTTP-статусу, когда тело без error.code.
 * @param {number} status
 * @returns {ErrorEntry}
 */
export function resolveHttpStatusEntry(status) {
  const mappedCode = HTTP_STATUS_CODES[status];
  if (mappedCode && ERROR_MESSAGES[mappedCode]) {
    return ERROR_MESSAGES[mappedCode];
  }
  return {
    ...UNKNOWN_ENTRY,
    kind: classifyHttpStatus(status),
  };
}

/**
 * Единая точка для UI: заголовок, сообщение, действие, kind, technical.
 * @param {unknown} error
 * @returns {{ title: string, message: string, action: string|null, kind: string, technical: string }}
 */
export function describeError(error) {
  if (error instanceof HubApiError) {
    return {
      title: titleForKind(error.kind),
      message: error.userMessage,
      action: error.userAction,
      kind: error.kind,
      technical: toTechnicalText(error),
    };
  }

  if (isAbortError(error)) {
    const entry = CLIENT_ENTRIES[ERROR_KIND.ABORTED];
    return {
      title: titleForKind(entry.kind),
      message: entry.userMessage,
      action: entry.userAction,
      kind: entry.kind,
      technical: toTechnicalText(error),
    };
  }

  if (error instanceof TypeError) {
    const entry = CLIENT_ENTRIES[ERROR_KIND.NETWORK];
    return {
      title: titleForKind(entry.kind),
      message: entry.userMessage,
      action: entry.userAction,
      kind: entry.kind,
      technical: toTechnicalText(error),
    };
  }

  if (error && typeof error === 'object' && /** @type {{ kind?: string }} */ (error).kind === ERROR_KIND.TIMEOUT) {
    const entry = CLIENT_ENTRIES[ERROR_KIND.TIMEOUT];
    return {
      title: titleForKind(entry.kind),
      message: entry.userMessage,
      action: entry.userAction,
      kind: entry.kind,
      technical: toTechnicalText(error),
    };
  }

  return {
    title: titleForKind(ERROR_KIND.UNKNOWN),
    message: UNKNOWN_ENTRY.userMessage,
    action: UNKNOWN_ENTRY.userAction,
    kind: ERROR_KIND.UNKNOWN,
    technical: toTechnicalText(error),
  };
}

/**
 * Техническая сводка для свёрнутого блока «Технические подробности».
 * @param {unknown} error
 * @returns {string}
 */
export function toTechnicalText(error) {
  const lines = [];

  if (error instanceof HubApiError) {
    if (error.code) lines.push(`Код: ${error.code}`);
    if (error.httpStatus != null) lines.push(`HTTP: ${error.httpStatus}`);
    if (error.serverMessage) lines.push(`Сообщение сервера: ${error.serverMessage}`);
    if (error.requestId) lines.push(`Request-Id: ${error.requestId}`);
    if (error.correlationId) lines.push(`Correlation-Id: ${error.correlationId}`);
    if (error.details?.length) {
      lines.push('Details:');
      try {
        lines.push(JSON.stringify(error.details, null, 2));
      } catch {
        lines.push('[не удалось сериализовать details]');
      }
    }
    return lines.join('\n');
  }

  if (error instanceof Error) {
    lines.push(`Тип: ${error.name}`);
    if (error.message) lines.push(`Сообщение: ${error.message}`);
    return lines.join('\n');
  }

  if (error != null) {
    lines.push(String(error));
  }

  return lines.join('\n');
}

/**
 * @param {string} kind
 * @returns {string}
 */
function titleForKind(kind) {
  switch (kind) {
    case ERROR_KIND.UNAUTHORIZED:
      return 'Требуется вход';
    case ERROR_KIND.FORBIDDEN:
      return 'Доступ запрещён';
    case ERROR_KIND.NOT_FOUND:
      return 'Не найдено';
    case ERROR_KIND.VALIDATION:
      return 'Ошибка в данных';
    case ERROR_KIND.CONFLICT:
      return 'Действие не выполнено';
    case ERROR_KIND.NETWORK:
      return 'Нет связи';
    case ERROR_KIND.TIMEOUT:
      return 'Сервер долго не отвечал';
    case ERROR_KIND.ABORTED:
      return 'Отменено';
    case ERROR_KIND.DEVICE:
      return 'Проблема с роутером';
    case ERROR_KIND.SERVER:
      return 'Сервер недоступен';
    case ERROR_KIND.UNSUPPORTED:
      return 'Не поддерживается';
    case ERROR_KIND.SETUP:
      return 'Подключение не готово';
    default:
      return 'Что-то пошло не так';
  }
}

/**
 * @param {unknown} error
 * @returns {boolean}
 */
function isAbortError(error) {
  return error instanceof DOMException && error.name === 'AbortError';
}
