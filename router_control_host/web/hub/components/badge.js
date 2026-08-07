import { createIcon } from "./icon.js";

const VALID_TONES = new Set(["primary", "success", "warning", "danger", "neutral"]);

/**
 * @param {{ tone?: string, label: string, iconName?: string }} options
 * @returns {HTMLSpanElement}
 */
export function createBadge({ tone = "neutral", label, iconName } = {}) {
  const badge = document.createElement("span");
  const resolvedTone = VALID_TONES.has(tone) ? tone : "neutral";
  badge.className = `hub-badge hub-badge--${resolvedTone}`;

  if (iconName) {
    badge.appendChild(createIcon(iconName, { size: 14 }));
  }

  const text = document.createElement("span");
  text.className = "hub-badge__label";
  text.textContent = label ?? "";
  badge.appendChild(text);

  return badge;
}
