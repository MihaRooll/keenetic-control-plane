import { createIcon } from "./icon.js";

const VALID_VARIANTS = new Set(["primary", "secondary", "ghost", "danger"]);
const VALID_SIZES = new Set(["md", "lg"]);

/**
 * @param {{ label?: string, variant?: string, size?: string, iconName?: string, onActivate?: (event: Event) => void, disabled?: boolean, busy?: boolean, ariaLabel?: string, type?: string }} options
 * @returns {HTMLButtonElement}
 */
export function createButton({
  label,
  variant = "primary",
  size = "md",
  iconName,
  onActivate,
  disabled = false,
  busy = false,
  ariaLabel,
  type = "button",
} = {}) {
  const button = document.createElement("button");
  const resolvedVariant = VALID_VARIANTS.has(variant) ? variant : "primary";
  const resolvedSize = VALID_SIZES.has(size) ? size : "md";

  button.type = type;
  button.className = `hub-btn hub-btn--${resolvedVariant} hub-btn--${resolvedSize}`;
  button.disabled = disabled || busy;

  if (ariaLabel) {
    button.setAttribute("aria-label", ariaLabel);
  }

  if (busy) {
    button.setAttribute("aria-busy", "true");
    button.classList.add("hub-btn--busy");
  }

  const content = document.createElement("span");
  content.className = "hub-btn__content";

  const labelEl = document.createElement("span");
  labelEl.className = "hub-btn__label";
  labelEl.textContent = label ?? "";
  content.appendChild(labelEl);

  if (iconName && !busy) {
    content.prepend(createIcon(iconName, { size: 18 }));
  }

  button.appendChild(content);

  if (busy) {
    const spinnerWrap = document.createElement("span");
    spinnerWrap.className = "hub-btn__spinner";
    spinnerWrap.appendChild(createIcon("spinner", { size: 18 }));
    button.appendChild(spinnerWrap);
  }

  // Сохраняем ширину после первого layout
  requestAnimationFrame(() => {
    if (button.offsetWidth > 0) {
      button.style.setProperty("min-width", `${button.offsetWidth}px`);
    }
  });

  if (typeof onActivate === "function") {
    button.addEventListener("click", (event) => {
      if (button.disabled) {
        return;
      }
      onActivate(event);
    });
  }

  return button;
}
