import { createIcon } from "./icon.js";
import { createTechnicalDetails } from "./details.js";

/** @type {HTMLElement | null} */
let toastRegion = null;

/** @type {Array<{ id: number, element: HTMLElement, timer: ReturnType<typeof setTimeout> | null }>} */
const toastQueue = [];

/** @type {Array<{ id: number, element: HTMLElement, timer: ReturnType<typeof setTimeout> | null }>} */
const visibleToasts = [];

const MAX_VISIBLE = 3;
let toastCounter = 0;

/**
 * @param {HTMLElement} container
 */
export function mountToastRegion(container) {
  toastRegion = container;
  container.classList.add("hub-toast-region");
  container.setAttribute("aria-live", "polite");
  container.setAttribute("aria-relevant", "additions");
}

/**
 * @param {{ tone?: string, title?: string, message?: string, timeoutMs?: number, details?: string | Node, action?: { label: string, onClick: () => void } }} options
 */
export function showToast({ tone = "neutral", title, message, timeoutMs = 6000, details, action } = {}) {
  if (!toastRegion) {
    toastRegion = document.getElementById("hub-toasts");
    if (toastRegion) {
      mountToastRegion(toastRegion);
    }
  }
  if (!toastRegion) {
    return;
  }

  const id = ++toastCounter;
  const toast = document.createElement("div");
  const resolvedTone = ["primary", "success", "warning", "danger", "neutral"].includes(tone)
    ? tone
    : "neutral";
  toast.className = `hub-toast hub-toast--${resolvedTone} hub-toast--enter`;
  toast.setAttribute("role", "status");

  const content = document.createElement("div");
  content.className = "hub-toast__content";

  if (title) {
    const titleEl = document.createElement("p");
    titleEl.className = "hub-toast__title";
    titleEl.textContent = title;
    content.appendChild(titleEl);
  }

  if (message) {
    const messageEl = document.createElement("p");
    messageEl.className = "hub-toast__message";
    messageEl.textContent = message;
    content.appendChild(messageEl);
  }

  if (details) {
    content.appendChild(createTechnicalDetails({ content: details }));
  }

  toast.appendChild(content);

  if (action && typeof action.label === "string") {
    const actionBtn = document.createElement("button");
    actionBtn.type = "button";
    actionBtn.className = "hub-toast__action";
    actionBtn.textContent = action.label;
    actionBtn.addEventListener("click", () => {
      if (typeof action.onClick === "function") {
        action.onClick();
      }
      dismiss();
    });
    toast.appendChild(actionBtn);
  }

  const closeBtn = document.createElement("button");
  closeBtn.type = "button";
  closeBtn.className = "hub-toast__close";
  closeBtn.setAttribute("aria-label", "Закрыть");
  closeBtn.appendChild(createIcon("close", { size: 18 }));
  toast.appendChild(closeBtn);

  const entry = { id, element: toast, timer: null };

  const dismiss = () => {
    if (entry.timer) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }
    toast.classList.add("hub-toast--dismissed");
    toast.addEventListener(
      "transitionend",
      () => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
        removeFromList(visibleToasts, entry);
        removeFromList(toastQueue, entry);
        flushQueue();
      },
      { once: true }
    );
    // Фолбэк без анимации
    setTimeout(() => {
      if (toast.parentNode) {
        toast.parentNode.removeChild(toast);
        removeFromList(visibleToasts, entry);
        removeFromList(toastQueue, entry);
        flushQueue();
      }
    }, 400);
  };

  closeBtn.addEventListener("click", dismiss);

  if (timeoutMs > 0) {
    entry.timer = setTimeout(dismiss, timeoutMs);
  }

  toastQueue.push(entry);
  flushQueue();
}

/**
 * @param {Array<{ id: number }>} list
 * @param {{ id: number }} entry
 */
function removeFromList(list, entry) {
  const index = list.findIndex((item) => item.id === entry.id);
  if (index >= 0) {
    list.splice(index, 1);
  }
}

function flushQueue() {
  if (!toastRegion) {
    return;
  }

  while (visibleToasts.length < MAX_VISIBLE && toastQueue.length > 0) {
    const next = toastQueue.find((item) => !visibleToasts.includes(item));
    if (!next) {
      break;
    }
    visibleToasts.push(next);
    toastRegion.appendChild(next.element);
    requestAnimationFrame(() => {
      next.element.classList.add("hub-toast--enter-active");
    });
  }
}
