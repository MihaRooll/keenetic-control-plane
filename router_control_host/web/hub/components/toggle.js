/**
 * @param {{ id?: string, label: string, description?: string, checked?: boolean, disabled?: boolean, indeterminate?: boolean, tone?: string, onChange?: (checked: boolean) => void }} options
 * @returns {HTMLLabelElement}
 */
export function createToggle({
  id,
  label,
  description,
  checked = false,
  disabled = false,
  indeterminate = false,
  tone = "primary",
  onChange,
} = {}) {
  const wrap = document.createElement("label");
  const resolvedTone = ["primary", "success", "warning", "danger", "neutral"].includes(tone)
    ? tone
    : "primary";
  wrap.className = `hub-toggle hub-toggle--${resolvedTone}`;
  if (disabled) {
    wrap.classList.add("hub-toggle--disabled");
  }

  const inputId = id ?? `hub-toggle-${Math.random().toString(36).slice(2, 9)}`;

  const input = document.createElement("input");
  input.type = "checkbox";
  input.id = inputId;
  input.className = "hub-toggle__input hub-visually-hidden";
  input.disabled = disabled;

  const track = document.createElement("span");
  track.className = "hub-toggle__track";
  track.setAttribute("aria-hidden", "true");

  const thumb = document.createElement("span");
  thumb.className = "hub-toggle__thumb";
  track.appendChild(thumb);

  if (indeterminate) {
    wrap.classList.add("hub-toggle--unknown");
    input.indeterminate = true;
    input.checked = false;
    input.setAttribute("role", "checkbox");
    input.setAttribute("aria-checked", "mixed");
  } else {
    input.indeterminate = false;
    input.checked = checked;
    input.setAttribute("role", "switch");
    input.setAttribute("aria-checked", checked ? "true" : "false");
  }

  const textWrap = document.createElement("span");
  textWrap.className = "hub-toggle__text";

  const labelEl = document.createElement("span");
  labelEl.className = "hub-toggle__label";
  labelEl.textContent = label ?? "";
  textWrap.appendChild(labelEl);

  if (description) {
    const descEl = document.createElement("span");
    descEl.className = "hub-toggle__description";
    descEl.textContent = description;
    textWrap.appendChild(descEl);
  }

  wrap.appendChild(input);
  wrap.appendChild(track);
  wrap.appendChild(textWrap);

  input.addEventListener("change", () => {
    if (input.indeterminate) {
      return;
    }
    const labelWrap = input.parentNode;
    if (labelWrap && labelWrap.classList) {
      labelWrap.classList.remove("hub-toggle--unknown");
    }
    input.setAttribute("role", "switch");
    input.setAttribute("aria-checked", input.checked ? "true" : "false");
    if (typeof onChange === "function") {
      onChange(input.checked);
    }
  });

  return wrap;
}
