/**
 * Простой двухшаговый сценарий публикации домена — композиция без состояния экрана.
 */

import {
  createButton,
  createCard,
  createSelectField,
  createTextField,
} from '../components/index.js';
import { HubState } from '../core/states.js';
import {
  DOMAIN_DRAFT_LINK_NOTE,
  DOMAIN_PUBLISH_APPLY_CONFIRM_TEXT,
  DOMAIN_PUBLISH_HUMAN_GATE_TEXT,
  DOMAIN_SIMPLE_DEFAULT_NAME_HONESTY,
  DOMAIN_SIMPLE_GATE_WHY,
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
  } = options;

  function resolveDisabled() {
    if (typeof getDisabled === 'function') {
      return getDisabled();
    }
    return disabled;
  }

  const card = createCard({
    title: 'Имя для черновика',
    titleTag: 'h2',
  });
  card.classList.add('hub-domain__simple-publish-card');
  const body = card.querySelector('.hub-card__body') ?? card;

  const nameFieldWrap = document.createElement('div');
  nameFieldWrap.className = 'hub-domain__simple-name-row';
  body.appendChild(nameFieldWrap);

  /** @type {HTMLInputElement|null} */
  let nameInput = null;
  /** @type {HTMLSelectElement|null} */
  let suffixSelect = null;

  const starterRow = document.createElement('div');
  starterRow.className = 'hub-domain__btn-row hub-domain__simple-starter-row';
  const starterBtn = createButton({
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

  const starterHonesty = document.createElement('p');
  starterHonesty.className = 'hub-domain__note hub-domain__simple-starter-honesty';
  starterHonesty.textContent = DOMAIN_SIMPLE_DEFAULT_NAME_HONESTY;
  body.appendChild(starterHonesty);

  const formatLine = document.createElement('p');
  formatLine.className = 'hub-domain__note hub-domain__simple-format';
  formatLine.id = `${idPrefix}-format-line`;
  body.appendChild(formatLine);

  const availabilityLine = document.createElement('p');
  availabilityLine.className = 'hub-domain__note hub-domain__simple-availability';
  availabilityLine.id = `${idPrefix}-availability-line`;
  body.appendChild(availabilityLine);

  const draftBlock = document.createElement('div');
  draftBlock.className = 'hub-domain__simple-draft';
  const draftUrlEl = document.createElement('p');
  draftUrlEl.className = 'hub-domain__simple-draft-url';
  draftUrlEl.id = `${idPrefix}-draft-url`;
  draftBlock.appendChild(draftUrlEl);
  const draftNoteEl = document.createElement('p');
  draftNoteEl.className = 'hub-domain__note hub-domain__simple-draft-note';
  draftNoteEl.textContent = DOMAIN_DRAFT_LINK_NOTE;
  draftBlock.appendChild(draftNoteEl);
  body.appendChild(draftBlock);

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
    starterBtn.disabled = isDisabled;
    publishBtn.disabled = isDisabled || !state.valid;

    if (state.formatMessage) {
      formatLine.textContent = state.formatMessage;
      formatLine.hidden = false;
    } else {
      formatLine.textContent = '';
      formatLine.hidden = true;
    }

    availabilityLine.textContent = state.availabilityMessage;
    availabilityLine.hidden = false;

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

  function destroy() {
    if (card.parentNode) {
      card.parentNode.removeChild(card);
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
  container.appendChild(card);
  update();

  return {
    root: card,
    update,
    destroy,
    getDraftUrl,
    isNameValid,
  };
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
 * @property {() => Promise<unknown>} onConfirmApply
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
            try {
              const response = await params.onConfirmApply();
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
              params.showToast({
                tone: 'danger',
                title: 'Не удалось отправить команду',
                message: error instanceof Error ? error.message : 'Повторите позже.',
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
