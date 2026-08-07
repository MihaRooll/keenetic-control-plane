import { createButton } from "./button.js";

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * @param {HTMLElement} container
 * @returns {HTMLElement[]}
 */
function getFocusableElements(container) {
  return Array.from(container.querySelectorAll(FOCUSABLE_SELECTOR)).filter(
    (el) => el.offsetParent !== null || el === document.activeElement
  );
}

/** @type {HTMLElement | null} */
let activeModalBackdrop = null;

/** @type {HTMLElement | null} */
let modalBackgroundRoot = null;

/**
 * @returns {HTMLElement | null}
 */
function getModalBackgroundRoot() {
  return document.querySelector(".hub-shell");
}

/**
 * @param {{ title?: string, description?: string, body?: Node | string, actions?: HTMLElement[], tone?: string, onClose?: () => void, initialFocus?: HTMLElement | null, returnFocusTo?: HTMLElement | null }} options
 * @returns {{ close: () => void }}
 */
export function openModal({
  title,
  description,
  body,
  actions = [],
  tone,
  onClose,
  initialFocus,
  returnFocusTo,
} = {}) {
  const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;

  const backdrop = document.createElement("div");
  backdrop.className = "hub-modal-backdrop hub-modal-backdrop--enter";
  if (tone) {
    backdrop.classList.add(`hub-modal-backdrop--${tone}`);
  }

  const dialog = document.createElement("div");
  dialog.className = "hub-modal hub-modal--enter";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");

  const titleId = `hub-modal-title-${Math.random().toString(36).slice(2, 9)}`;
  const descId = `hub-modal-desc-${Math.random().toString(36).slice(2, 9)}`;

  if (title) {
    dialog.setAttribute("aria-labelledby", titleId);
  }
  if (description) {
    dialog.setAttribute("aria-describedby", descId);
  }

  const header = document.createElement("header");
  header.className = "hub-modal__header";

  if (title) {
    const titleEl = document.createElement("h2");
    titleEl.id = titleId;
    titleEl.className = "hub-modal__title";
    titleEl.textContent = title;
    header.appendChild(titleEl);
  }

  const closeBtn = createButton({
    label: "Закрыть",
    variant: "ghost",
    ariaLabel: "Закрыть",
    onActivate: () => close(),
  });
  closeBtn.classList.add("hub-modal__close");
  header.appendChild(closeBtn);
  dialog.appendChild(header);

  if (description) {
    const descEl = document.createElement("p");
    descEl.id = descId;
    descEl.className = "hub-modal__description";
    descEl.textContent = description;
    dialog.appendChild(descEl);
  }

  if (body) {
    const bodyEl = document.createElement("div");
    bodyEl.className = "hub-modal__body";
    if (typeof body === "string") {
      bodyEl.textContent = body;
    } else {
      bodyEl.appendChild(body);
    }
    dialog.appendChild(bodyEl);
  }

  if (actions.length > 0) {
    const footer = document.createElement("footer");
    footer.className = "hub-modal__footer";
    for (const action of actions) {
      footer.appendChild(action);
    }
    dialog.appendChild(footer);
  }

  backdrop.appendChild(dialog);
  document.body.appendChild(backdrop);
  requestAnimationFrame(() => {
    backdrop.classList.add("hub-modal-backdrop--enter-active");
    dialog.classList.add("hub-modal--enter-active");
  });
  activeModalBackdrop = backdrop;

  modalBackgroundRoot = getModalBackgroundRoot();
  if (modalBackgroundRoot) {
    modalBackgroundRoot.setAttribute("aria-hidden", "true");
  }

  document.body.classList.add("hub-modal-open");

  const handleKeyDown = (event) => {
    if (event.key === "Escape") {
      event.preventDefault();
      close();
      return;
    }

    if (event.key !== "Tab") {
      return;
    }

    const focusable = getFocusableElements(dialog);
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];

    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  const handleBackdropClick = (event) => {
    if (event.target === backdrop) {
      close();
    }
  };

  backdrop.addEventListener("keydown", handleKeyDown);
  backdrop.addEventListener("click", handleBackdropClick);

  let closed = false;

  const close = () => {
    if (closed) {
      return;
    }
    closed = true;
    backdrop.removeEventListener("keydown", handleKeyDown);
    backdrop.removeEventListener("click", handleBackdropClick);
    if (backdrop.parentNode) {
      backdrop.parentNode.removeChild(backdrop);
    }
    if (activeModalBackdrop === backdrop) {
      activeModalBackdrop = null;
    }
    if (modalBackgroundRoot) {
      modalBackgroundRoot.removeAttribute("aria-hidden");
      modalBackgroundRoot = null;
    }
    document.body.classList.remove("hub-modal-open");
    const focusRestoreTarget = returnFocusTo !== undefined ? returnFocusTo : previousFocus;
    if (focusRestoreTarget instanceof HTMLElement) {
      focusRestoreTarget.focus();
    }
    if (typeof onClose === "function") {
      onClose();
    }
  };

  if (initialFocus instanceof HTMLElement) {
    initialFocus.focus();
  } else {
    const firstFocusable = getFocusableElements(dialog)[0];
    if (firstFocusable) {
      firstFocusable.focus();
    } else {
      dialog.setAttribute("tabindex", "-1");
      dialog.focus();
    }
  }

  return { close };
}
