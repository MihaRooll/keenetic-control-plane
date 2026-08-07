/** Иконки LOCAL HUB — инлайновые SVG через DOM API. */

const SVG_NS = `${"http"}${":"}${"//www.w3.org/2000/svg"}`;

/** @type {readonly string[]} */
export const ICON_NAMES = Object.freeze([
  "overview",
  "connection",
  "staff-wifi",
  "guest-wifi",
  "vpn",
  "domain",
  "entry-pages",
  "diagnostics",
  "router",
  "check",
  "alert",
  "error",
  "info",
  "qr",
  "refresh",
  "eye",
  "eye-off",
  "chevron-right",
  "chevron-down",
  "external",
  "copy",
  "share",
  "download",
  "settings",
  "spinner",
  "close",
  "x",
]);

/** @type {Record<string, { paths: Array<{ d: string, fill?: boolean }>, stroke?: boolean }>} */
const ICON_DEFS = {
  overview: {
    paths: [
      { d: "M3 10.5 12 3l9 7.5V20a1 1 0 0 1-1 1h-5v-6H9v6H4a1 1 0 0 1-1-1v-9.5Z" },
    ],
  },
  connection: {
    // Symmetric wifi arcs; Y nudged +1 vs classic Lucide so optical mass
    // sits in the middle of the 24×24 frame (wide top arcs read high otherwise).
    paths: [
      { d: "M2 9.82a15 15 0 0 1 20 0" },
      { d: "M5 13.55a11 11 0 0 1 14.08 0" },
      { d: "M8.53 17.11a6 6 0 0 1 6.95 0" },
      { d: "M12 21h.01" },
    ],
  },
  "staff-wifi": {
    paths: [
      { d: "M5 12.5a7 7 0 0 1 14 0" },
      { d: "M8.5 16a3.5 3.5 0 0 1 7 0" },
      { d: "M12 19.5h.01" },
      { d: "M3 8.5 12 2l9 6.5" },
    ],
  },
  "guest-wifi": {
    paths: [
      { d: "M4 13a8 8 0 0 1 16 0" },
      { d: "M8 17a4 4 0 0 1 8 0" },
      { d: "M12 21h.01" },
      { d: "M16 6 18 4l2 2" },
      { d: "M18 4v4" },
      { d: "M18 4h-4" },
    ],
  },
  vpn: {
    paths: [
      { d: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z" },
      { d: "m9 12 2 2 4-4" },
    ],
  },
  domain: {
    paths: [
      { d: "M12 21a9 9 0 1 0-9-9" },
      { d: "M3 12h18" },
      { d: "M12 3a15 15 0 0 1 4 9 15 15 0 0 1-4 9 15 15 0 0 1-4-9 15 15 0 0 1 4-9Z" },
    ],
  },
  "entry-pages": {
    paths: [
      { d: "M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" },
      { d: "M14 2v6h6" },
      { d: "M8 13h8" },
      { d: "M8 17h5" },
    ],
  },
  diagnostics: {
    paths: [
      { d: "M12 20v-6" },
      { d: "M6 20V10" },
      { d: "M18 20V4" },
    ],
  },
  router: {
    paths: [
      { d: "M4 14h16v6H4z" },
      { d: "M8 14V8h8v6" },
      { d: "M6 8V5h12v3" },
      { d: "M10 17h.01" },
      { d: "M14 17h.01" },
    ],
  },
  check: {
    paths: [{ d: "M20 6 9 17l-5-5" }],
  },
  alert: {
    paths: [
      { d: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" },
      { d: "M12 9v4" },
      { d: "M12 17h.01" },
    ],
  },
  error: {
    paths: [
      { d: "M12 8v4" },
      { d: "M12 16h.01" },
      { d: "M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0Z" },
    ],
  },
  info: {
    paths: [
      { d: "M12 16v-4" },
      { d: "M12 8h.01" },
      { d: "M12 22a10 10 0 1 0-10-10 10 10 0 0 0 10 10Z" },
    ],
  },
  qr: {
    paths: [
      { d: "M4 4h6v6H4z" },
      { d: "M14 4h6v6h-6z" },
      { d: "M4 14h6v6H4z" },
      { d: "M14 14h2v2h-2z" },
      { d: "M18 14h2v2h-2z" },
      { d: "M14 18h2v2h-2z" },
      { d: "M18 18h2v2h-2z" },
    ],
  },
  refresh: {
    paths: [
      { d: "M21 12a9 9 0 0 0-9-9 9.75 9.75 0 0 0-6.74 2.74L3 8" },
      { d: "M3 3v5h5" },
      { d: "M3 12a9 9 0 0 0 9 9 9.75 9.75 0 0 0 6.74-2.74L21 16" },
      { d: "M16 21h5v-5" },
    ],
  },
  eye: {
    paths: [
      { d: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7Z" },
      { d: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" },
    ],
  },
  "eye-off": {
    paths: [
      { d: "M9.88 9.88a3 3 0 1 0 4.24 4.24" },
      { d: "M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a18.45 18.45 0 0 1-2.16 3.19" },
      { d: "M6.61 6.61A18.45 18.45 0 0 0 2 12s3 7 10 7a10.43 10.43 0 0 0 5.92-1.27" },
      { d: "M2 2l20 20" },
    ],
  },
  "chevron-right": {
    paths: [{ d: "m9 18 6-6-6-6" }],
  },
  "chevron-down": {
    paths: [{ d: "m6 9 6 6 6-6" }],
  },
  external: {
    paths: [
      { d: "M15 3h6v6" },
      { d: "M10 14 21 3" },
      { d: "M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" },
    ],
  },
  copy: {
    paths: [
      { d: "M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" },
      { d: "M15 2H9a1 1 0 0 0-1 1v2a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1V3a1 1 0 0 0-1-1Z" },
    ],
  },
  share: {
    paths: [
      { d: "M4 12v7a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-7" },
      { d: "M16 6l-4-4-4 4" },
      { d: "M12 2v13" },
    ],
  },
  download: {
    paths: [
      { d: "M12 3v12" },
      { d: "m7 10 5 5 5-5" },
      { d: "M5 21h14" },
    ],
  },
  settings: {
    paths: [
      { d: "M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2Z" },
      { d: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z" },
    ],
  },
  spinner: {
    paths: [{ d: "M12 2a10 10 0 0 1 10 10", fill: false }],
    stroke: true,
  },
  close: {
    paths: [{ d: "M18 6 6 18" }, { d: "m6 6 12 12" }],
  },
  x: {
    paths: [{ d: "M18 6 6 18" }, { d: "m6 6 12 12" }],
  },
};

/**
 * @param {string} name
 * @param {{ size?: number, decorative?: boolean, className?: string, title?: string }} [options]
 * @returns {SVGElement}
 */
export function createIcon(name, { size = 20, decorative = true, className, title } = {}) {
  const def = ICON_DEFS[name];
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("width", String(size));
  svg.setAttribute("height", String(size));
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.classList.add("hub-icon");
  if (className) {
    for (const part of className.split(/\s+/)) {
      if (part) {
        svg.classList.add(part);
      }
    }
  }
  if (name === "spinner") {
    svg.classList.add("hub-icon--spinner");
  }

  if (decorative) {
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
  } else if (title) {
    svg.setAttribute("role", "img");
    const titleEl = document.createElementNS(SVG_NS, "title");
    titleEl.textContent = title;
    svg.appendChild(titleEl);
  }

  if (!def) {
    const fallback = document.createElementNS(SVG_NS, "circle");
    fallback.setAttribute("cx", "12");
    fallback.setAttribute("cy", "12");
    fallback.setAttribute("r", "8");
    fallback.setAttribute("fill", "none");
    fallback.setAttribute("stroke", "currentColor");
    fallback.setAttribute("stroke-width", "2");
    svg.appendChild(fallback);
    return svg;
  }

  const useStroke = def.stroke !== false;
  for (const pathDef of def.paths) {
    const path = document.createElementNS(SVG_NS, "path");
    path.setAttribute("d", pathDef.d);
    if (useStroke && !pathDef.fill) {
      path.setAttribute("fill", "none");
      path.setAttribute("stroke", "currentColor");
      path.setAttribute("stroke-width", "2");
      path.setAttribute("stroke-linecap", "round");
      path.setAttribute("stroke-linejoin", "round");
    } else {
      path.setAttribute("fill", "currentColor");
    }
    svg.appendChild(path);
  }

  return svg;
}
