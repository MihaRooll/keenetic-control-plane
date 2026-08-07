export { createIcon, ICON_NAMES } from "./icon.js";
export { createBadge } from "./badge.js";
export { createButton } from "./button.js";
export { createTextField, createSelectField, createSegmented } from "./field.js";
export { createToggle } from "./toggle.js";
export { createCard, createStatusCard } from "./card.js";
export { createProgressRing } from "./progress-ring.js";
export { openModal } from "./modal.js";
export { showToast, mountToastRegion } from "./toast.js";
export { createTechnicalDetails } from "./details.js";

import { createIcon, ICON_NAMES } from "./icon.js";
import { createBadge } from "./badge.js";
import { createButton } from "./button.js";
import { createTextField, createSelectField, createSegmented } from "./field.js";
import { createToggle } from "./toggle.js";
import { createCard, createStatusCard } from "./card.js";
import { createProgressRing } from "./progress-ring.js";
import { openModal } from "./modal.js";
import { showToast } from "./toast.js";
import { createTechnicalDetails } from "./details.js";

/**
 * Витрина всех компонентов для служебного экрана оболочки.
 * @returns {HTMLElement}
 */
export function createComponentShowcase() {
  const root = document.createElement("div");
  root.className = "hub-showcase";

  /* ── Бейджи ── */
  appendSection(root, "Бейджи", () => {
    const row = document.createElement("div");
    row.className = "hub-showcase__row";
    const toneLabels = {
      primary: "Основной",
      success: "Успех",
      warning: "Предупреждение",
      danger: "Ошибка",
      neutral: "Нейтральный",
    };
    for (const tone of ["primary", "success", "warning", "danger", "neutral"]) {
      row.appendChild(createBadge({ tone, label: toneLabels[tone], iconName: "check" }));
    }
    return row;
  });

  /* ── Кнопки ── */
  appendSection(root, "Кнопки", () => {
    const wrap = document.createElement("div");
    wrap.className = "hub-showcase__stack";

    const variantsRow = document.createElement("div");
    variantsRow.className = "hub-showcase__row";
    const variantLabels = {
      primary: "Основная",
      secondary: "Вторичная",
      ghost: "Прозрачная",
      danger: "Опасная",
    };
    for (const variant of ["primary", "secondary", "ghost", "danger"]) {
      variantsRow.appendChild(
        createButton({ label: variantLabels[variant], variant, iconName: "settings" })
      );
    }
    wrap.appendChild(variantsRow);

    const sizesRow = document.createElement("div");
    sizesRow.className = "hub-showcase__row";
    sizesRow.appendChild(createButton({ label: "Средняя", size: "md" }));
    sizesRow.appendChild(createButton({ label: "Большая", size: "lg" }));
    wrap.appendChild(sizesRow);

    const statesRow = document.createElement("div");
    statesRow.className = "hub-showcase__row";
    statesRow.appendChild(createButton({ label: "Отключена", disabled: true }));
    statesRow.appendChild(createButton({ label: "Загрузка", busy: true }));
    wrap.appendChild(statesRow);

    return wrap;
  });

  /* ── Поля ── */
  appendSection(root, "Поля ввода", () => {
    const wrap = document.createElement("div");
    wrap.className = "hub-showcase__stack";

    wrap.appendChild(
      createTextField({
        id: "showcase-text",
        label: "Текстовое поле",
        placeholder: "Введите значение",
        hint: "Подсказка к полю",
      })
    );

    wrap.appendChild(
      createTextField({
        id: "showcase-secret",
        label: "Секретное поле",
        secret: true,
        placeholder: "••••••••",
        value: "demo-secret",
      })
    );

    wrap.appendChild(
      createTextField({
        id: "showcase-error",
        label: "Поле с ошибкой",
        error: "Обязательное поле",
        value: "",
      })
    );

    wrap.appendChild(
      createSelectField({
        id: "showcase-select",
        label: "Выпадающий список",
        options: [
          { value: "a", label: "Вариант А" },
          { value: "b", label: "Вариант Б", note: "рекомендуется" },
        ],
        value: "a",
      })
    );

    wrap.appendChild(
      createSegmented({
        id: "showcase-segmented",
        label: "Режим доступа",
        options: [
          { value: "none", label: "Без пароля" },
          { value: "password", label: "С паролем" },
        ],
        value: "none",
      })
    );

    return wrap;
  });

  /* ── Переключатели ── */
  appendSection(root, "Переключатели", () => {
    const wrap = document.createElement("div");
    wrap.className = "hub-showcase__stack";
    wrap.appendChild(
      createToggle({
        id: "showcase-toggle-on",
        label: "Гостевая сеть",
        description: "Разрешить подключение гостей",
        checked: true,
      })
    );
    /** @type {HTMLElement|null} */
    let vpnDescRef = null;
    const vpnToggle = createToggle({
      id: "showcase-toggle-off",
      label: "VPN-туннель",
      description: "Выключен",
      checked: false,
      tone: "success",
      onChange: (checked) => {
        if (vpnDescRef) {
          vpnDescRef.textContent = checked ? "Включён" : "Выключен";
        }
      },
    });
    vpnDescRef = vpnToggle.querySelector(".hub-toggle__description");
    wrap.appendChild(vpnToggle);
    wrap.appendChild(
      createToggle({
        id: "showcase-toggle-disabled",
        label: "Недоступно",
        checked: false,
        disabled: true,
      })
    );
    return wrap;
  });

  /* ── Карточки ── */
  appendSection(root, "Карточки", () => {
    const wrap = document.createElement("div");
    wrap.className = "hub-showcase__stack";

    wrap.appendChild(
      createCard({
        title: "Основная карточка",
        subtitle: "Описание раздела",
        body: "Содержимое карточки с дополнительной информацией.",
        footer: "Нижняя область",
        actions: [createButton({ label: "Действие", variant: "ghost", size: "md" })],
        tone: "primary",
        titleTag: "div",
      })
    );

    wrap.appendChild(
      createStatusCard({
        iconName: "connection",
        title: "Подключение",
        subtitle: "Пример оформления карточки статуса",
        badge: createBadge({ tone: "neutral", label: "Пример" }),
        metric: "142 Мбит/с",
        actions: [
          createButton({ label: "Обновить", variant: "secondary", iconName: "refresh" }),
        ],
        titleTag: "div",
      })
    );

    return wrap;
  });

  /* ── Иконки ── */
  appendSection(root, "Иконки", () => {
    const grid = document.createElement("div");
    grid.className = "hub-showcase__icon-grid";
    for (const name of ICON_NAMES) {
      const cell = document.createElement("div");
      cell.className = "hub-showcase__icon-cell";
      cell.appendChild(createIcon(name, { size: 24 }));
      const label = document.createElement("span");
      label.className = "hub-showcase__icon-label";
      label.textContent = name;
      cell.appendChild(label);
      grid.appendChild(cell);
    }
    return grid;
  });

  /* ── Технические подробности ── */
  appendSection(root, "Технические подробности", () =>
    createTechnicalDetails({
      content: '{"status": "ok", "latency_ms": 12}',
    })
  );

  /* ── Модалка и тосты ── */
  appendSection(root, "Модальное окно и уведомления", () => {
    const row = document.createElement("div");
    row.className = "hub-showcase__row";

    row.appendChild(
      createButton({
        label: "Открыть модалку",
        onActivate: () => {
          openModal({
            title: "Подтверждение",
            description: "Вы уверены, что хотите продолжить?",
            body: "Это демонстрационное модальное окно.",
            actions: [
              createButton({ label: "Отмена", variant: "ghost" }),
              createButton({ label: "Продолжить", variant: "primary" }),
            ],
          });
        },
      })
    );

    row.appendChild(
      createButton({
        label: "Показать тост",
        variant: "secondary",
        onActivate: () => {
          showToast({
            tone: "success",
            title: "Готово",
            message: "Изменения сохранены",
            details: "request_id: demo-001",
          });
        },
      })
    );

    row.appendChild(
      createButton({
        label: "Тост с ошибкой",
        variant: "danger",
        onActivate: () => {
          showToast({
            tone: "danger",
            title: "Ошибка",
            message: "Не удалось выполнить операцию",
            details: "code: E_TIMEOUT\nretry_after: 30",
            timeoutMs: 0,
          });
        },
      })
    );

    return row;
  });

  return root;
}

/**
 * @param {HTMLElement} parent
 * @param {string} title
 * @param {() => HTMLElement} render
 */
function appendSection(parent, title, render) {
  const section = document.createElement("section");
  section.className = "hub-showcase__section";

  const sectionTitle = document.createElement("h2");
  sectionTitle.className = "hub-showcase__section-title";
  sectionTitle.textContent = title;
  section.appendChild(sectionTitle);

  section.appendChild(render());
  parent.appendChild(section);
}
