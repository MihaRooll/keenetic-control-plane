/**
 * Раскрывающийся блок технических подробностей.
 * @param {{ summary?: string, content: string | Node }} options
 * @returns {HTMLDetailsElement}
 */
export function createTechnicalDetails({ summary = "Технические подробности", content } = {}) {
  const details = document.createElement("details");
  details.className = "hub-details";

  const summaryEl = document.createElement("summary");
  summaryEl.className = "hub-details__summary";
  summaryEl.textContent = summary;
  details.appendChild(summaryEl);

  const body = document.createElement("div");
  body.className = "hub-details__content";

  if (typeof content === "string") {
    const pre = document.createElement("pre");
    pre.className = "hub-details__pre";
    pre.textContent = content;
    body.appendChild(pre);
  } else if (content instanceof Node) {
    body.appendChild(content);
  }

  details.appendChild(body);
  return details;
}
