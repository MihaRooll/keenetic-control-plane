import { createIcon } from "./icon.js";

/**
 * @param {HTMLElement} fieldRoot
 * @param {{ hint?: string, error?: string, id: string }} options
 * @returns {{ hintId?: string, errorId?: string }}
 */
function attachFieldMeta(fieldRoot, { hint, error, id }) {
  const meta = document.createElement("div");
  meta.className = "hub-field__meta";
  let hintId;
  let errorId;

  if (hint) {
    hintId = `${id}-hint`;
    const hintEl = document.createElement("p");
    hintEl.id = hintId;
    hintEl.className = "hub-field__hint";
    hintEl.textContent = hint;
    meta.appendChild(hintEl);
  }

  if (error) {
    errorId = `${id}-error`;
    const errorEl = document.createElement("p");
    errorEl.id = errorId;
    errorEl.className = "hub-field__error";
    errorEl.textContent = error;
    meta.appendChild(errorEl);
    fieldRoot.classList.add("hub-field--invalid");
  }

  if (meta.childElementCount > 0) {
    fieldRoot.appendChild(meta);
  }

  return { hintId, errorId };
}

/**
 * @param {{ id: string, label: string, value?: string, type?: string, hint?: string, error?: string, placeholder?: string, secret?: boolean, readOnly?: boolean, disabled?: boolean, autocomplete?: string, onInput?: (event: Event) => void, onChange?: (event: Event) => void }} options
 * @returns {HTMLElement}
 */
export function createTextField({
  id,
  label,
  value = "",
  type = "text",
  hint,
  error,
  placeholder,
  secret = false,
  readOnly = false,
  disabled = false,
  autocomplete,
  onInput,
  onChange,
} = {}) {
  const field = document.createElement("div");
  field.className = "hub-field";
  if (disabled) {
    field.classList.add("hub-field--disabled");
  }

  const labelEl = document.createElement("label");
  labelEl.className = "hub-field__label";
  labelEl.setAttribute("for", id);
  labelEl.textContent = label ?? "";
  field.appendChild(labelEl);

  const controlWrap = document.createElement("div");
  controlWrap.className = "hub-field__control";

  const input = document.createElement("input");
  input.id = id;
  input.className = "hub-field__input";
  input.value = value;
  input.readOnly = readOnly;
  input.disabled = disabled;

  if (placeholder) {
    input.placeholder = placeholder;
  }

  if (secret) {
    input.type = "password";
    input.autocomplete = autocomplete ?? "off";
    input.spellcheck = false;

    const toggleBtn = document.createElement("button");
    toggleBtn.type = "button";
    toggleBtn.className = "hub-field__secret-toggle";
    toggleBtn.setAttribute("aria-label", "Показать пароль");
    toggleBtn.setAttribute("aria-pressed", "false");

    let visible = false;
    const updateToggle = () => {
      input.type = visible ? "text" : "password";
      toggleBtn.setAttribute("aria-label", visible ? "Скрыть пароль" : "Показать пароль");
      toggleBtn.setAttribute("aria-pressed", visible ? "true" : "false");
      while (toggleBtn.firstChild) {
        toggleBtn.removeChild(toggleBtn.firstChild);
      }
      toggleBtn.appendChild(createIcon(visible ? "eye-off" : "eye", { size: 20 }));
    };
    updateToggle();

    toggleBtn.addEventListener("click", () => {
      visible = !visible;
      updateToggle();
      input.focus();
    });
    toggleBtn.disabled = disabled;

    controlWrap.classList.add("hub-field__control--secret");
    controlWrap.appendChild(input);
    controlWrap.appendChild(toggleBtn);
  } else {
    input.type = type;
    if (autocomplete !== undefined) {
      input.autocomplete = autocomplete;
    }
    controlWrap.appendChild(input);
  }

  field.appendChild(controlWrap);

  const { hintId, errorId } = attachFieldMeta(field, { hint, error, id });
  const describedBy = [hintId, errorId].filter(Boolean).join(" ");
  if (describedBy) {
    input.setAttribute("aria-describedby", describedBy);
  }
  if (error) {
    input.setAttribute("aria-invalid", "true");
  }

  if (typeof onInput === "function") {
    input.addEventListener("input", onInput);
  }
  if (typeof onChange === "function") {
    input.addEventListener("change", onChange);
  }

  return field;
}

/**
 * @param {{ id: string, label: string, options: Array<{ value: string, label: string, disabled?: boolean, note?: string }>, value?: string, hint?: string, error?: string, disabled?: boolean, onChange?: (event: Event) => void }} config
 * @returns {HTMLElement}
 */
export function createSelectField({
  id,
  label,
  options = [],
  value,
  hint,
  error,
  disabled = false,
  onChange,
} = {}) {
  const field = document.createElement("div");
  field.className = "hub-field";
  if (disabled) {
    field.classList.add("hub-field--disabled");
  }

  const labelEl = document.createElement("label");
  labelEl.className = "hub-field__label";
  labelEl.setAttribute("for", id);
  labelEl.textContent = label ?? "";
  field.appendChild(labelEl);

  const controlWrap = document.createElement("div");
  controlWrap.className = "hub-field__control hub-field__control--select";

  const select = document.createElement("select");
  select.id = id;
  select.className = "hub-field__select";
  select.disabled = disabled;

  for (const option of options) {
    const optionEl = document.createElement("option");
    optionEl.value = option.value;
    optionEl.textContent = option.note ? `${option.label} (${option.note})` : option.label;
    if (option.disabled) {
      optionEl.disabled = true;
    }
    select.appendChild(optionEl);
  }

  if (value !== undefined) {
    select.value = value;
  }

  controlWrap.appendChild(select);
  controlWrap.appendChild(createIcon("chevron-right", { size: 18, className: "hub-field__select-icon" }));
  field.appendChild(controlWrap);

  const { hintId, errorId } = attachFieldMeta(field, { hint, error, id });
  const describedBy = [hintId, errorId].filter(Boolean).join(" ");
  if (describedBy) {
    select.setAttribute("aria-describedby", describedBy);
  }
  if (error) {
    select.setAttribute("aria-invalid", "true");
  }

  if (typeof onChange === "function") {
    select.addEventListener("change", onChange);
  }

  return field;
}

/**
 * @param {{ id: string, label: string, options: Array<{ value: string, label: string }>, value?: string, onChange?: (value: string) => void }} config
 * @returns {HTMLElement}
 */
export function createSegmented({ id, label, options = [], value, onChange } = {}) {
  const field = document.createElement("div");
  field.className = "hub-field hub-field--segmented";

  const labelEl = document.createElement("span");
  labelEl.className = "hub-field__label";
  labelEl.id = `${id}-label`;
  labelEl.textContent = label ?? "";
  field.appendChild(labelEl);

  const group = document.createElement("div");
  group.className = "hub-segmented";
  group.setAttribute("role", "group");
  group.setAttribute("aria-labelledby", `${id}-label`);

  let currentValue = value ?? options[0]?.value ?? "";

  const buttons = [];

  const emitChange = (nextValue) => {
    currentValue = nextValue;
    for (const btn of buttons) {
      const selected = btn.dataset.value === currentValue;
      btn.setAttribute("aria-pressed", selected ? "true" : "false");
      btn.classList.toggle("hub-segmented__option--selected", selected);
    }
    if (typeof onChange === "function") {
      onChange(currentValue);
    }
  };

  for (const option of options) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "hub-segmented__option";
    btn.dataset.value = option.value;
    btn.textContent = option.label;
    btn.setAttribute("aria-pressed", option.value === currentValue ? "true" : "false");
    if (option.value === currentValue) {
      btn.classList.add("hub-segmented__option--selected");
    }
    btn.addEventListener("click", () => {
      if (option.value !== currentValue) {
        emitChange(option.value);
      }
    });
    buttons.push(btn);
    group.appendChild(btn);
  }

  field.appendChild(group);
  return field;
}
