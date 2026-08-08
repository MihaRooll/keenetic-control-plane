/**
 * Простой двухшаговый сценарий публикации домена — композиция без состояния экрана.
 */

import {
  createButton,
  createCard,
  createSelectField,
  createTextField,
} from '../components/index.js';
import { HubApiError, describeError } from '../core/errors.js';
import { HubState } from '../core/states.js';
import {
  createStepNumberBadge,
  wireOverviewCardNavigate,
} from './overview-card-grid.js';
import {
  DOMAIN_DRAFT_LINK_NOTE,
  DOMAIN_PUBLISH_APPLY_CONFIRM_TEXT,
  DOMAIN_PUBLISH_HUMAN_GATE_TEXT,
  DOMAIN_SIMPLE_DEFAULT_NAME_HONESTY,
  DOMAIN_SIMPLE_GATE_WHY,
  DOMAIN_ROUTER_DEFAULT_FQDN_LABEL,
  KEENDNS_DEFAULT_ACCESS_MODE,
  KEENDNS_DOMAIN_OPTIONS,
  buildPublishRequestSummary,
  buildReleaseRequestSummary,
  describeDomainSimpleNameState,
  describeKeendnsApplyOutcome,
  resolveDomainSimpleDefaultName,
} from './domain-model.js';

/**
 * @typedef {object} DomainSimplePublishMountOptions
 * @property {() => string} getName
 * @property {(value: string) => void} setName
 * @property {() => string} getDomain
 * @property {(value: string) => void} setDomain
 * @property {boolean} [disabled]
 * @property {() => boolean} [getDisabled]
 * @property {() => void} onPublishApply
 * @property {boolean} [showSuffixSelect]
 * @property {string} [idPrefix]
 * @property {'full'|'overview'} [variant]
 * @property {(routeId: string) => void} [navigate]
 * @property {() => string|null} [getRouterDefaultFqdn]
 * @property {() => boolean|null} [getRouterSslValid]
 * @property {string} [title]
 */

/**
 * @typedef {object} DomainPublishHumanGateParams
 * @property {(options: object) => { close: () => void }} openModal
 * @property {(options: object) => HTMLButtonElement} createButton
 * @property {(text: string) => Promise<boolean>} copyTextToClipboard
 * @property {(options: object) => void} showToast
 * @property {'book'|'drop'} intent
 * @property {string|null|undefined} [name]
 * @property {string|null|undefined} [domain]
 * @property {string|null|undefined} [mode]
 * @property {string|null|undefined} [localOrderUrl]
 * @property {() => void} [onClose]
 */

/**
 * @param {HTMLElement} container
 * @param {DomainSimplePublishMountOptions} options
 * @returns {{
 *   root: HTMLElement,
 *   update: () => void,
 *   destroy: () => void,
 *   getDraftUrl: () => string|null,
 *   isNameValid: () => boolean,
 * }}
 */
export function mountDomainSimplePublishAffordance(container, options) {
  const {
    getName,
    setName,
    getDomain,
    setDomain,
    disabled = false,
    getDisabled,
    onPublishApply,
    showSuffixSelect = true,
    idPrefix = 'hub-domain-simple',
    variant = 'full',
    navigate,
    title = 'Домен',
    getRouterDefaultFqdn,
    getRouterSslValid,
  } = options;

  const isOverview = variant === 'overview';

  function resolveDisabled() {
    if (typeof getDisabled === 'function') {
      return getDisabled();
    }
    return disabled;
  }

  /** @type {HTMLElement} */
  let root;
  /** @type {HTMLElement} */
  let body;

  if (isOverview) {
    root = document.createElement('article');
    root.className =
      'hub-overview-step-card hub-overview__domain-compact-card hub-domain__simple-publish-card';

    const header = document.createElement('div');
    header.className = 'hub-overview-step-card__header hub-domain__compact-header';
    header.appendChild(createStepNumberBadge(4));

    const heading = document.createElement('h2');
    heading.className = 'hub-overview-step-card__title';
    heading.textContent = title;
    header.appendChild(heading);
    root.appendChild(header);

    body = document.createElement('div');
    body.className = 'hub-overview-step-card__main hub-domain__simple-publish-body';
    root.appendChild(body);

    if (typeof navigate === 'function') {
      wireOverviewCardNavigate(root, 'domain', navigate);
    }
  } else {
    const card = createCard({
      title: 'Имя для черновика',
      titleTag: 'h2',
    });
    card.classList.add('hub-domain__simple-publish-card');
    root = card;
    body = card.querySelector('.hub-card__body') ?? card;
  }

  const nameFieldWrap = document.createElement('div');
  nameFieldWrap.className = 'hub-domain__simple-name-row';
  body.appendChild(nameFieldWrap);

  /** @type {HTMLInputElement|null} */
  let nameInput = null;
  /** @type {HTMLSelectElement|null} */
  let suffixSelect = null;

  /** @type {HTMLDivElement|null} */
  let starterRow = null;
  /** @type {HTMLButtonElement|null} */
  let starterBtn = null;
  /** @type {HTMLParagraphElement|null} */
  let starterHonesty = null;
  /** @type {HTMLParagraphElement|null} */
  let availabilityLine = null;
  /** @type {HTMLDivElement|null} */
  let draftBlock = null;
  /** @type {HTMLParagraphElement|null} */
  let draftUrlEl = null;
  /** @type {HTMLParagraphElement|null} */
  let draftNoteEl = null;

  // Overview: do not mount starter/draft chrome at all — CSS `display:flex` on
  // `.hub-domain__btn-row` overrides HTML `hidden` and kept the starter visible.
  if (!isOverview) {
    starterRow = document.createElement('div');
    starterRow.className = 'hub-domain__btn-row hub-domain__simple-starter-row';
    starterBtn = createButton({
      label: 'Подставить стартовое имя',
      variant: 'secondary',
      disabled: resolveDisabled(),
      onActivate: () => {
        setName(resolveDomainSimpleDefaultName());
        if (nameInput instanceof HTMLInputElement) {
          nameInput.value = getName();
        }
        update();
      },
    });
    starterBtn.id = `${idPrefix}-starter-btn`;
    starterRow.appendChild(starterBtn);
    body.appendChild(starterRow);

    starterHonesty = document.createElement('p');
    starterHonesty.className = 'hub-domain__note hub-domain__simple-starter-honesty';
    starterHonesty.textContent = DOMAIN_SIMPLE_DEFAULT_NAME_HONESTY;
    body.appendChild(starterHonesty);
  }

  const formatLine = document.createElement('p');
  formatLine.className = 'hub-domain__note hub-domain__simple-format';
  formatLine.id = `${idPrefix}-format-line`;
  body.appendChild(formatLine);

  if (!isOverview) {
    availabilityLine = document.createElement('p');
    availabilityLine.className = 'hub-domain__note hub-domain__simple-availability';
    availabilityLine.id = `${idPrefix}-availability-line`;
    body.appendChild(availabilityLine);
  }

  const routerDefaultBlock = document.createElement('div');
  routerDefaultBlock.className = 'hub-domain__router-default';
  routerDefaultBlock.hidden = true;
  const routerDefaultLabel = document.createElement('p');
  routerDefaultLabel.className = 'hub-domain__note hub-domain__router-default-label';
  routerDefaultLabel.textContent = DOMAIN_ROUTER_DEFAULT_FQDN_LABEL;
  routerDefaultBlock.appendChild(routerDefaultLabel);
  const routerDefaultFqdn = document.createElement('p');
  routerDefaultFqdn.className = 'hub-domain__compact-fqdn hub-domain__router-default-fqdn';
  routerDefaultFqdn.id = `${idPrefix}-router-default-fqdn`;
  routerDefaultBlock.appendChild(routerDefaultFqdn);
  const routerSslHint = document.createElement('p');
  routerSslHint.className = 'hub-domain__note hub-domain__router-ssl-hint';
  routerSslHint.id = `${idPrefix}-router-ssl-hint`;
  routerSslHint.hidden = true;
  routerDefaultBlock.appendChild(routerSslHint);
  body.appendChild(routerDefaultBlock);

  const fqdnPreview = document.createElement('p');
  fqdnPreview.className = 'hub-domain__compact-fqdn';
  fqdnPreview.id = `${idPrefix}-fqdn-preview`;
  fqdnPreview.hidden = true;
  body.appendChild(fqdnPreview);

  if (!isOverview) {
    draftBlock = document.createElement('div');
    draftBlock.className = 'hub-domain__simple-draft';
    draftUrlEl = document.createElement('p');
    draftUrlEl.className = 'hub-domain__simple-draft-url';
    draftUrlEl.id = `${idPrefix}-draft-url`;
    draftBlock.appendChild(draftUrlEl);
    draftNoteEl = document.createElement('p');
    draftNoteEl.className = 'hub-domain__note hub-domain__simple-draft-note';
    draftNoteEl.textContent = DOMAIN_DRAFT_LINK_NOTE;
    draftBlock.appendChild(draftNoteEl);
    body.appendChild(draftBlock);
  }

  const ctaRow = document.createElement('div');
  ctaRow.className = 'hub-domain__btn-row hub-domain__simple-cta-row';
  const publishBtn = createButton({
    label: 'Опубликовать',
    variant: 'primary',
    disabled: resolveDisabled(),
    onActivate: () => {
      onPublishApply();
    },
  });
  publishBtn.id = `${idPrefix}-publish-btn`;
  ctaRow.appendChild(publishBtn);
  body.appendChild(ctaRow);

  /** @type {HTMLElement|null} */
  let quietLinkMeta = null;
  if (isOverview && typeof navigate === 'function') {
    quietLinkMeta = document.createElement('div');
    quietLinkMeta.className = 'hub-overview-step-card__meta hub-domain__compact-meta';
    const quietLink = document.createElement('a');
    quietLink.className = 'hub-overview__quiet-link';
    quietLink.href = '#/domain';
    quietLink.textContent = 'Все настройки домена';
    quietLink.addEventListener('click', (event) => {
      event.preventDefault();
      navigate('domain');
    });
    quietLinkMeta.appendChild(quietLink);
    root.appendChild(quietLinkMeta);
  }

  function rebuildNameField() {
    while (nameFieldWrap.firstChild) {
      nameFieldWrap.removeChild(nameFieldWrap.firstChild);
    }
    const nameField = createTextField({
      id: `${idPrefix}-name`,
      label: 'Имя',
      value: getName(),
      disabled: resolveDisabled(),
      onInput: (event) => {
        if (event.target instanceof HTMLInputElement) {
          setName(event.target.value);
          update();
        }
      },
    });
    nameFieldWrap.appendChild(nameField);
    nameInput = nameField.querySelector(`#${idPrefix}-name`);
    if (showSuffixSelect) {
      const suffixField = createSelectField({
        id: `${idPrefix}-suffix`,
        label: 'Домен',
        value: getDomain(),
        disabled: resolveDisabled(),
        options: KEENDNS_DOMAIN_OPTIONS.map((item) => ({
          value: item.value,
          label: item.label,
        })),
        onChange: (event) => {
          if (event.target instanceof HTMLSelectElement) {
            setDomain(event.target.value);
            update();
          }
        },
      });
      const suffixEl = suffixField.querySelector(`#${idPrefix}-suffix`)?.closest('.hub-field');
      if (suffixEl) {
        suffixEl.classList.add('hub-field--suffix');
      }
      nameFieldWrap.appendChild(suffixField);
      suffixSelect = suffixField.querySelector(`#${idPrefix}-suffix`);
    }
  }

  function syncFieldValuesWithoutFocusLoss() {
    const active = document.activeElement;
    const nameFocused = nameInput instanceof HTMLInputElement && active === nameInput;
    const suffixFocused = suffixSelect instanceof HTMLSelectElement && active === suffixSelect;

    if (nameInput instanceof HTMLInputElement && !nameFocused) {
      nameInput.value = getName();
    }
    if (suffixSelect instanceof HTMLSelectElement && !suffixFocused) {
      suffixSelect.value = getDomain();
    }
    const isDisabled = resolveDisabled();
    if (nameInput instanceof HTMLInputElement) {
      nameInput.disabled = isDisabled;
    }
    if (suffixSelect instanceof HTMLSelectElement) {
      suffixSelect.disabled = isDisabled;
    }
  }

  function update() {
    const state = describeDomainSimpleNameState({
      name: getName(),
      domain: getDomain(),
    });

    syncFieldValuesWithoutFocusLoss();

    const isDisabled = resolveDisabled();
    if (starterBtn) {
      starterBtn.disabled = isDisabled;
    }
    publishBtn.disabled = isDisabled || !state.valid;

    if (isOverview) {
      const routerFqdn =
        typeof getRouterDefaultFqdn === 'function' ? getRouterDefaultFqdn() : null;
      const routerSsl =
        typeof getRouterSslValid === 'function' ? getRouterSslValid() : null;

      if (typeof routerFqdn === 'string' && routerFqdn.trim()) {
        routerDefaultFqdn.textContent = routerFqdn.trim();
        routerDefaultBlock.hidden = false;
        if (routerSsl === true) {
          routerSslHint.textContent = 'SSL сертификат действителен (по данным роутера)';
          routerSslHint.hidden = false;
        } else if (routerSsl === false) {
          routerSslHint.textContent = 'SSL сертификат не действителен (по данным роутера)';
          routerSslHint.hidden = false;
        } else {
          routerSslHint.textContent = '';
          routerSslHint.hidden = true;
        }
      } else {
        routerDefaultFqdn.textContent = '';
        routerDefaultBlock.hidden = true;
        routerSslHint.textContent = '';
        routerSslHint.hidden = true;
      }

      if (state.valid && state.draftUrl) {
        const fqdn = `${getName().trim().toLowerCase()}.${getDomain().trim()}`;
        fqdnPreview.textContent = fqdn;
        fqdnPreview.hidden = false;
      } else {
        fqdnPreview.textContent = '';
        fqdnPreview.hidden = true;
      }

      if (state.formatMessage && !state.valid) {
        formatLine.textContent = state.formatMessage;
        formatLine.hidden = false;
      } else {
        formatLine.textContent = '';
        formatLine.hidden = true;
      }
      return;
    }

    if (state.formatMessage) {
      formatLine.textContent = state.formatMessage;
      formatLine.hidden = false;
    } else {
      formatLine.textContent = '';
      formatLine.hidden = true;
    }

    if (availabilityLine) {
      availabilityLine.textContent = state.availabilityMessage;
      availabilityLine.hidden = false;
    }

    if (draftUrlEl && draftNoteEl) {
      if (state.draftUrl) {
        draftUrlEl.textContent = state.draftUrl;
        draftUrlEl.hidden = false;
      } else {
        draftUrlEl.textContent = 'Черновая ссылка появится после корректного имени.';
        draftUrlEl.hidden = false;
      }
      draftNoteEl.textContent = DOMAIN_DRAFT_LINK_NOTE;
      draftNoteEl.hidden = false;
    }
  }

  function destroy() {
    if (root.parentNode) {
      root.parentNode.removeChild(root);
    }
  }

  function getDraftUrl() {
    return describeDomainSimpleNameState({
      name: getName(),
      domain: getDomain(),
    }).draftUrl;
  }

  function isNameValid() {
    return describeDomainSimpleNameState({
      name: getName(),
      domain: getDomain(),
    }).valid;
  }

  rebuildNameField();
  container.appendChild(root);
  update();

  return {
    root,
    update,
    destroy,
    getDraftUrl,
    isNameValid,
  };
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
 * @typedef {object} DomainPublishApplyConfirmParams
 * @property {(options: object) => { close: () => void }} openModal
 * @property {(options: object) => HTMLButtonElement} createButton
 * @property {(options: object) => void} showToast
 * @property {string|null|undefined} [name]
 * @property {string|null|undefined} [domain]
 * @property {string|null|undefined} [mode]
 * @property {boolean} [offline]
 * @property {() => AbortSignal|undefined} [getSignal]
 * @property {(signal: AbortSignal|undefined) => Promise<unknown>} onConfirmApply
 * @property {() => void} [onClose]
 */

/**
 * @param {DomainPublishApplyConfirmParams} params
 * @returns {{ close: () => void }}
 */
function isPublishApplyOffline(params) {
  if (params.offline === true) {
    return true;
  }
  return typeof navigator !== 'undefined' && navigator.onLine === false;
}

/**
 * @param {DomainPublishApplyConfirmParams} params
 */
function showPublishApplyOfflineToast(params) {
  if (typeof params.showToast === 'function') {
    params.showToast({
      tone: 'warning',
      title: 'Нет связи с сервером управления',
      message:
        'Отправить команду публикации сейчас нельзя — дождитесь восстановления связи.',
    });
  }
}

export function openDomainPublishApplyConfirm(params) {
  if (isPublishApplyOffline(params)) {
    showPublishApplyOfflineToast(params);
    return { close: () => {} };
  }

  const normalizedName = typeof params.name === 'string' ? params.name.trim().toLowerCase() : '';
  const normalizedDomain = typeof params.domain === 'string' ? params.domain.trim() : '';
  const mode = params.mode ?? KEENDNS_DEFAULT_ACCESS_MODE;

  const body = document.createElement('div');
  body.className = 'hub-domain__publish-body';

  const lead = document.createElement('p');
  lead.className = 'hub-domain__note hub-domain__gate-why';
  lead.textContent =
    'Одно подтверждение отправит команду облачной регистрации имени на роутер через программу.';
  body.appendChild(lead);

  const summary = document.createElement('p');
  summary.textContent = `Имя: ${normalizedName || 'не указано'}.${normalizedDomain || 'не указан'} · режим: ${mode}`;
  body.appendChild(summary);

  const confirmText = document.createElement('p');
  confirmText.textContent = DOMAIN_PUBLISH_APPLY_CONFIRM_TEXT;
  body.appendChild(confirmText);

  /** @type {{ close: () => void }|null} */
  let modalRef = null;

  modalRef = params.openModal({
    title: 'Отправить команду публикации?',
    description: 'Будет отправлена одна команда регистрации имени на роутер через программу.',
    body,
    tone: 'warning',
    actions: [
      params.createButton({
        label: 'Отмена',
        variant: 'ghost',
        onActivate: () => {
          modalRef?.close();
        },
      }),
      params.createButton({
        label: 'Опубликовать',
        variant: 'primary',
        onActivate: () => {
          void (async () => {
            if (isPublishApplyOffline(params)) {
              modalRef?.close();
              showPublishApplyOfflineToast(params);
              return;
            }
            const signal = typeof params.getSignal === 'function' ? params.getSignal() : undefined;
            try {
              const response = await params.onConfirmApply(signal);
              if (signal?.aborted) {
                return;
              }
              const outcome = describeKeendnsApplyOutcome(response);
              if (outcome.hubState === HubState.ERROR) {
                params.showToast({
                  tone: 'danger',
                  title: outcome.title,
                  message: outcome.message,
                });
              } else {
                params.showToast({
                  tone: 'warning',
                  title: outcome.title,
                  message: outcome.message,
                });
              }
            } catch (error) {
              if (isAborted(error) || signal?.aborted) {
                return;
              }
              const described = describeError(error);
              params.showToast({
                tone: 'danger',
                title: described.title,
                message: described.message,
              });
            } finally {
              modalRef?.close();
            }
          })();
        },
      }),
    ],
    onClose: () => {
      params.onClose?.();
    },
  });

  return modalRef;
}

/**
 * @param {DomainPublishHumanGateParams} params
 * @returns {{ close: () => void }}
 */
export function openDomainPublishHumanGate(params) {
  const summary =
    params.intent === 'drop'
      ? buildReleaseRequestSummary({
          name: params.name,
          domain: params.domain,
          localOrderUrl: params.localOrderUrl,
        })
      : buildPublishRequestSummary({
          name: params.name,
          domain: params.domain,
          mode: params.mode,
          localOrderUrl: params.localOrderUrl,
        });

  const body = document.createElement('div');
  body.className = 'hub-domain__publish-body';

  const whyLead = document.createElement('p');
  whyLead.className = 'hub-domain__note hub-domain__gate-why';
  whyLead.textContent = DOMAIN_SIMPLE_GATE_WHY;
  body.appendChild(whyLead);

  const gateText = document.createElement('p');
  gateText.textContent = DOMAIN_PUBLISH_HUMAN_GATE_TEXT;
  body.appendChild(gateText);

  const summaryPre = document.createElement('pre');
  summaryPre.className = 'hub-domain__publish-summary';
  summaryPre.textContent = summary;
  body.appendChild(summaryPre);

  const docRef = document.createElement('p');
  docRef.className = 'hub-domain__note';
  docRef.textContent =
    'Передайте скопированную заявку администратору — он завершит регистрацию имени.';
  body.appendChild(docRef);

  if (params.intent === 'drop') {
    const dropNote = document.createElement('p');
    dropNote.className = 'hub-domain__note';
    dropNote.textContent =
      'Предпросмотр отключения подготовлен — выполнение по-прежнему требует человека.';
    body.appendChild(dropNote);
  }

  /** @type {{ close: () => void }|null} */
  let modalRef = null;

  modalRef = params.openModal({
    title: params.intent === 'drop' ? 'Заявка на отключение публикации' : 'Заявка на публикацию',
    description: 'Программа не выполняет облачную запись.',
    body,
    actions: [
      params.createButton({
        label: 'Закрыть',
        variant: 'ghost',
        onActivate: () => {
          modalRef?.close();
        },
      }),
      params.createButton({
        label: 'Скопировать заявку',
        variant: 'primary',
        onActivate: () => {
          void (async () => {
            const copied = await params.copyTextToClipboard(summary);
            params.showToast({
              tone: copied ? 'success' : 'warning',
              title: copied ? 'Заявка скопирована' : 'Копирование недоступно',
              message: copied
                ? 'Текст заявки в буфере обмена.'
                : 'Браузер не позволяет скопировать текст автоматически — выделите его вручную.',
            });
          })();
        },
      }),
    ],
    onClose: () => {
      params.onClose?.();
    },
  });

  return modalRef;
}
