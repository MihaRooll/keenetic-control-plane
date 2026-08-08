/**
 * Router Control prototype management UI — ES module, buildless.
 * Rendering: textContent + createElement only; visuals in styles.css.
 */

const API = "/api/router-control/v1";
const THEME_KEY = "rc.prototype.theme";
const UI_MODE_KEY = "rc.prototype.uiMode";
const REQUEST_TIMEOUT_MS = 30000;
const POLL_INTERVAL_MS = 1500;
const POLL_MAX_ATTEMPTS = 20;

/** @type {{ siteId: string|null, status: object|null, recentOps: string[], recentJobs: string[] }} */
const sessionMemory = {
  siteId: null,
  status: null,
  recentOps: [],
  recentJobs: [],
};

/** @type {AbortController|null} */
let activeNavAbort = null;

function el(tag, className, attrs) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (attrs) {
    Object.entries(attrs).forEach(([k, v]) => {
      if (v !== undefined && v !== null) node.setAttribute(k, String(v));
    });
  }
  return node;
}

function text(node, value) {
  node.textContent = value == null ? "" : String(value);
  return node;
}

function append(parent, ...children) {
  children.forEach((c) => {
    if (c) parent.appendChild(c);
  });
  return parent;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
}

function verdictSignalHumanLabel(signal) {
  const labels = {
    link: "link",
    connected: "connected",
    state: "state",
    txbytes: "txbytes",
    rxbytes: "rxbytes",
    broadcast: "broadcast",
    peer_public_key: "peer public key",
    peer_last_handshake: "peer last handshake",
    peer_online: "peer online",
    peer_rxbytes: "peer rxbytes",
    peer_txbytes: "peer txbytes",
    peer_enabled: "peer enabled",
    interface_readable: "interface readable",
    interface_state: "interface state",
    interface_up: "interface up",
    associated_ssid_field_present: "associated SSID field",
    associated_ssid_matches_intent: "associated SSID match",
    internet_status: "internet status",
    gateway_status: "gateway status",
    dns_status: "DNS status",
    admin_up: "admin up",
    on_air_signal: "on-air signal",
  };
  return labels[signal] || String(signal);
}

function verdictMissingHumanLabel(code) {
  const labels = {
    readback: "readback не выполнен",
    peer_public_key: "peer public key отсутствует",
    peer_last_handshake: "peer last handshake отсутствует",
    peer_online: "peer online отсутствует",
    peer_rxbytes: "peer rxbytes отсутствует",
    associated_ssid_field: "associated SSID field отсутствует",
    associated_ssid: "associated SSID отсутствует",
    ssid_intent_match: "SSID intent match отсутствует",
    internet_status: "internet status отсутствует",
    gateway_status: "gateway status отсутствует",
    dns_status: "DNS status отсутствует",
    internet_affirmative: "internet affirmative отсутствует",
    link: "link отсутствует",
    broadcast: "broadcast отсутствует",
    on_air_signal: "on-air signal отсутствует",
    positive_handshake: "положительный handshake отсутствует",
    positive_online: "положительный peer online отсутствует",
    positive_rxbytes: "положительный rxbytes отсутствует",
    uplink_settle_performed: "uplink settle не выполнен",
  };
  return labels[code] || String(code);
}

function verdictRejectionHumanLabel(reason) {
  const labels = {
    interface_state_not_evidence:
      "interface state не доказывает туннель — обманчивый сигнал, игнорирован",
    interface_up_not_evidence:
      "interface up не доказывает туннель — обманчивый сигнал, игнорирован",
    peer_enabled_not_evidence:
      "peer enabled не доказывает туннель — обманчивый сигнал, игнорирован",
    peer_txbytes_alone_not_evidence:
      "peer txbytes без rxbytes не доказывает handshake — обманчивый сигнал, игнорирован",
    link_not_evidence: "link не использован как единственное доказательство — игнорирован",
    connected_not_evidence:
      "connected не использован как единственное доказательство — игнорирован",
    connected_with_link_down:
      "connected=true при link=down — обманчивый сигнал, не засчитан",
    state_up_with_link_down:
      "state=up при link=down — обманчивый сигнал, не засчитан",
    txbytes_without_rxbytes:
      "txbytes > 0 при rxbytes=0 — обманчивый сигнал, не засчитан",
    link_broadcast_conflict: "link и broadcast конфликтуют — сигнал отвергнут",
    auth_type_not_evidence:
      "auth-type не доказывает association — обманчивый сигнал, игнорирован",
  };
  return labels[reason] || String(reason);
}

function formatVerdictSignalValue(value) {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "true" : "false";
  return String(value);
}

function renderVerdictExplanationInto(container, explanation) {
  if (!container || !explanation || typeof explanation !== "object") return;
  const rejected = Array.isArray(explanation.signals_rejected)
    ? explanation.signals_rejected
    : [];
  const read = Array.isArray(explanation.signals_read) ? explanation.signals_read : [];
  const missing = Array.isArray(explanation.signals_missing)
    ? explanation.signals_missing
    : [];
  if (!rejected.length && !read.length && !missing.length) return;

  if (rejected.length) {
    const rejectedWrap = el("div", "verdict-explanation-rejected");
    append(
      rejectedWrap,
      text(
        el("p", "verdict-explanation-rejected-title"),
        "Отвергнутые обманчивые сигналы (не засчитаны при вердикте):",
      ),
    );
    const rejectedList = el("ul", "verdict-explanation-rejected-list");
    rejected.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const signal = item.signal ? verdictSignalHumanLabel(item.signal) : "—";
      const reason = item.reason
        ? verdictRejectionHumanLabel(item.reason)
        : "отвергнут";
      const li = el("li", "verdict-explanation-rejected-item");
      text(li, signal + ": " + reason);
      rejectedList.appendChild(li);
    });
    append(rejectedWrap, rejectedList);
    container.appendChild(rejectedWrap);
  }

  const details = el("details", "verdict-explanation-details");
  const summary = el("summary", "verdict-explanation-summary");
  text(summary, "Подробнее: объяснение вердикта");
  details.appendChild(summary);
  const body = el("div", "verdict-explanation-body");

  if (read.length) {
    append(body, text(el("p", "verdict-explanation-section-title"), "Прочитанные сигналы:"));
    const readList = el("ul", "verdict-explanation-read-list");
    read.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const li = el("li", "");
      text(
        li,
        verdictSignalHumanLabel(item.signal)
          + "="
          + formatVerdictSignalValue(item.value),
      );
      readList.appendChild(li);
    });
    append(body, readList);
  }

  if (missing.length) {
    append(body, text(el("p", "verdict-explanation-section-title"), "Недостающие для более сильного вердикта:"));
    const missingList = el("ul", "verdict-explanation-missing-list");
    missing.forEach((code) => {
      const li = el("li", "");
      text(li, verdictMissingHumanLabel(code));
      missingList.appendChild(li);
    });
    append(body, missingList);
  }

  if (rejected.length) {
    append(body, text(el("p", "verdict-explanation-section-title"), "Отвергнутые (коды):"));
    const codeList = el("ul", "verdict-explanation-rejected-code-list");
    rejected.forEach((item) => {
      if (!item || typeof item !== "object") return;
      const li = el("li", "mono");
      text(li, String(item.signal || "—") + " → " + String(item.reason || "—"));
      codeList.appendChild(li);
    });
    append(body, codeList);
  }

  append(details, body);
  container.appendChild(details);
}

function renderApplyResultWithVerdict(explanationContainer, resultBox, data) {
  if (explanationContainer) {
    clear(explanationContainer);
    if (data && data.verdict_explanation) {
      renderVerdictExplanationInto(explanationContainer, data.verdict_explanation);
    }
  }
  if (resultBox) {
    const safe = data ? sanitizeApplyResultForDisplay(data) : null;
    text(resultBox, safe ? JSON.stringify(safe, null, 2) : "");
  }
}

function uuid() {
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    return crypto.randomUUID();
  }
  return "id-" + Date.now().toString(36) + Math.random().toString(36).slice(2);
}

const HONESTY_WIFI_GUEST_ISOLATION =
  "API принимает guest_isolation; при true compile_wifi_intent_to_ops отклоняет intent "
  + "(422 wifi.guest_isolation_unsupported). Default false — OK.";
const HONESTY_WIFI_CAPTIVE_PORTAL =
  "API принимает captive_portal; при Enabled compile_wifi_intent_to_ops отклоняет intent "
  + "(422 wifi.captive_portal_unsupported). Default Disabled — OK.";
const HONESTY_STATION_AUTH_OPEN =
  "auth_mode=open не поддерживается: not yet supported: no verified open-network authentication grammar";
const HONESTY_WG_PATH_STYLE =
  "path_style — peer write REJECTED on 5.01.C.1.0-0; используйте nested_rci.";

const FIELD_MANIFEST_URL = "/settings/router-control/assets/ui-field-manifest.json";
const MANIFEST_COVERED_FAMILIES = new Set([
  "bootstrap_discovery",
  "change_plan",
  "commissioning",
  "connection_health",
  "deployment",
  "desired_revision",
  "dhcp",
  "dns",
  "enroll",
  "firewall",
  "rci_sealed",
  "router_discovery",
  "ssh_host_key",
  "traffic_discovery",
  "vlan",
  "vpn_policy_routing",
  "vpn_profile",
  "wifi_ap",
  "wifi_observed",
  "wifi_site_survey",
  "wifi_station",
  "wireguard",
  "wizard_draft",
]);

/** @type {"pending"|"loaded"|"unavailable"} */
let fieldManifestState = "pending";
/** @type {object|null} */
let fieldManifestData = null;
const fieldManifestLookupCache = {};

function resetFieldManifestLookupCache() {
  Object.keys(fieldManifestLookupCache).forEach((key) => {
    delete fieldManifestLookupCache[key];
  });
}

function setFieldManifestForTest(manifestOrNull, state) {
  resetFieldManifestLookupCache();
  if (state === "pending") {
    fieldManifestState = "pending";
    fieldManifestData = null;
    return;
  }
  if (manifestOrNull === null || state === "unavailable") {
    fieldManifestState = "unavailable";
    fieldManifestData = null;
  } else {
    fieldManifestState = "loaded";
    fieldManifestData = manifestOrNull;
  }
}

function getFieldManifestState() {
  return fieldManifestState;
}

function showManifestUnavailableBanner() {
  showBanner(
    "ui-field-manifest.json недоступен — подсказки manifest-backed полей fail-closed "
      + "(без устаревших hardcoded tips).",
    "warning",
  );
}

async function loadFieldManifest() {
  if (fieldManifestState === "loaded" || fieldManifestState === "unavailable") {
    return fieldManifestState;
  }
  try {
    const resp = await fetch(FIELD_MANIFEST_URL, { credentials: "same-origin" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    if (!data || typeof data.families !== "object") throw new Error("missing families");
    setFieldManifestForTest(data, "loaded");
    hideBanner();
  } catch (_err) {
    setFieldManifestForTest(null, "unavailable");
    showManifestUnavailableBanner();
  }
  return fieldManifestState;
}

function lookupFieldMeta(family, name) {
  if (fieldManifestState !== "loaded" || !fieldManifestData) return null;
  const cacheKey = family + ":" + name;
  if (Object.prototype.hasOwnProperty.call(fieldManifestLookupCache, cacheKey)) {
    return fieldManifestLookupCache[cacheKey];
  }
  const familyObj = fieldManifestData.families && fieldManifestData.families[family];
  let found = null;
  if (familyObj && Array.isArray(familyObj.fields)) {
    found = familyObj.fields.find((field) => field && field.name === name) || null;
  }
  fieldManifestLookupCache[cacheKey] = found;
  return found;
}

function manifestFieldTooltip(family, name) {
  if (!MANIFEST_COVERED_FAMILIES.has(family)) return null;
  if (fieldManifestState === "unavailable") {
    return "подсказки манифеста недоступны";
  }
  if (fieldManifestState !== "loaded") return null;
  const meta = lookupFieldMeta(family, name);
  if (meta && meta.tooltip) return meta.tooltip;
  return "нет в манифесте";
}

function resolveManifestTooltip(family, fieldName) {
  if (!MANIFEST_COVERED_FAMILIES.has(family)) return undefined;
  const tip = manifestFieldTooltip(family, fieldName);
  return tip || undefined;
}

function mergeManifestControlDefault(family, fieldName, opts) {
  if (opts.skipDefault) {
    return opts;
  }
  if (fieldManifestState !== "loaded" || !family || !MANIFEST_COVERED_FAMILIES.has(family)) {
    return opts;
  }
  const meta = lookupFieldMeta(family, fieldName);
  if (!meta || !Object.prototype.hasOwnProperty.call(meta, "default")) {
    return opts;
  }
  const def = meta.default;
  if (def === null) {
    if (meta.type === "boolean") {
      opts.checked = false;
    }
    return opts;
  }
  if (meta.type === "boolean") {
    opts.checked = !!def;
  } else if (meta.type === "enum" || meta.type === "string") {
    opts.value = String(def);
  } else if (meta.type === "number" || meta.type === "integer") {
    opts.value = String(def);
  }
  return opts;
}

function fieldTooltipOpts(family, fieldName, extra) {
  const opts = extra ? { ...extra } : {};
  if (family) opts.tooltip = resolveManifestTooltip(family, fieldName);
  if (family) mergeManifestControlDefault(family, fieldName, opts);
  return opts;
}

function lookupManifestFamily(family) {
  if (fieldManifestState !== "loaded" || !fieldManifestData) return null;
  const families = fieldManifestData.families;
  return families && families[family] ? families[family] : null;
}

function manifestRouteToApiPath(fullRoute, params) {
  if (!fullRoute || typeof fullRoute !== "string") return null;
  let path = fullRoute;
  if (path.startsWith(API)) {
    path = path.slice(API.length);
  }
  if (params && typeof params === "object") {
    Object.keys(params).forEach((key) => {
      path = path.replace(
        "{" + key + "}",
        encodeURIComponent(String(params[key])),
      );
    });
  }
  return path;
}

const RCI_OPERATION_LABELS = {
  fail_safe_arm: "Fail-safe arm (timer reboot 60s)",
  fail_safe_disarm: "Fail-safe disarm",
  interface_up: "Interface up",
  interface_down: "Interface down",
  configuration_save: "System configuration save",
  reboot: "System reboot",
};

function buildRciOperationOptionsFromManifest() {
  const meta = lookupFieldMeta("rci_sealed", "operation");
  if (!meta || !Array.isArray(meta.enum)) return [];
  return meta.enum.map((val) => [val, RCI_OPERATION_LABELS[val] || val]);
}

function resolveRciMutationRequest(payload) {
  const opMeta = lookupFieldMeta("rci_sealed", "operation");
  const family = lookupManifestFamily("rci_sealed");
  if (!opMeta || !family || !family.routes) {
    return { error: "RCI manifest maps недоступны" };
  }
  const op = payload.operation;
  const routeKey = opMeta.route_key_by_value && opMeta.route_key_by_value[op];
  const bodyOp = opMeta.body_operation_by_value && opMeta.body_operation_by_value[op];
  if (!routeKey || !bodyOp) {
    return { error: "Неизвестная операция или manifest mapping отсутствует" };
  }
  const fullRoute = family.routes[routeKey];
  if (!fullRoute) {
    return { error: "Маршрут manifest отсутствует для " + routeKey };
  }
  const ifaceMeta = lookupFieldMeta("rci_sealed", "interface_id");
  const requiredOps = ifaceMeta && ifaceMeta.required_when && ifaceMeta.required_when.operation;
  if (Array.isArray(requiredOps) && requiredOps.includes(op) && !payload.interface_id) {
    return { error: "interface_id обязателен для interface up/down" };
  }
  const path = manifestRouteToApiPath(fullRoute, { router_id: payload.router_id });
  if (!path) {
    return { error: "Не удалось разрешить API path" };
  }
  const body = { operation: bodyOp };
  if (Array.isArray(requiredOps) && requiredOps.includes(op)) {
    body.interface_id = payload.interface_id;
  }
  return { path, body };
}

function deriveSimpleLinkFailReason(facts) {
  if (!facts || typeof facts !== "object") return null;
  if (facts.identity_mismatch || facts.reason_code === "identity_mismatch") {
    return "Роутер отвечает, но это не тот, что был сохранён ранее.";
  }
  if (facts.host_key_mismatch || facts.reason_code === "host_key_mismatch") {
    return "SSH host-key не совпадает с сохранённым pin.";
  }
  if (facts.explicit_unreachable || facts.reason_code === "unreachable") {
    return "Роутер недоступен по сети.";
  }
  if (facts.credentials_missing || facts.reason_code === "credentials_missing") {
    return "Учётные данные для проверки отсутствуют.";
  }
  return null;
}

function simpleLinkAllFiveFactsTrue(facts) {
  return (
    facts.reachability_ok === true
    && facts.identity_consistent === true
    && facts.host_key_pinned === true
    && facts.credentials_present === true
    && facts.evidence_fresh === true
  );
}

function simpleConnectHasEnrolledTarget(linkFacts) {
  if (!linkFacts || linkFacts.no_target === true) return false;
  return linkFacts.has_enrolled_router === true || !!linkFacts.router_id;
}

function simpleConnectDisplayLabel(linkFacts) {
  if (!linkFacts) return "роутер";
  const name = linkFacts.display_name && String(linkFacts.display_name).trim();
  if (name) return name;
  const host = linkFacts.host && String(linkFacts.host).trim();
  if (host) return host;
  return "роутер";
}

function deriveSimpleConnectStep1Ux(linkFacts) {
  if (!simpleConnectHasEnrolledTarget(linkFacts)) {
    return {
      mode: "no_enrolled",
      formExpanded: true,
      showConnectedSummary: false,
      showAutoFailMessage: false,
    };
  }
  if (
    linkFacts.health_unavailable === true
    || (linkFacts.loaded === false && !linkFacts.health_status)
  ) {
    return {
      mode: "auto_fail",
      formExpanded: true,
      showConnectedSummary: false,
      showAutoFailMessage: true,
    };
  }
  const linkState = deriveSimpleLinkState(linkFacts);
  if (linkState.visual === "ok") {
    return {
      mode: "connected",
      formExpanded: false,
      showConnectedSummary: true,
      showAutoFailMessage: false,
    };
  }
  return {
    mode: "auto_fail",
    formExpanded: true,
    showConnectedSummary: false,
    showAutoFailMessage: true,
  };
}

function prefillSimpleConnectForm(form, linkFacts) {
  if (!form || !linkFacts) return;
  const hostEl = form.querySelector("#wizard-host");
  if (hostEl && linkFacts.host && !hostEl.value) hostEl.value = String(linkFacts.host);
  const nameEl = form.querySelector("#wizard-display-name");
  if (nameEl && linkFacts.display_name && !nameEl.value) {
    nameEl.value = String(linkFacts.display_name);
  }
  const portEl = form.querySelector("#wizard-port");
  if (portEl && linkFacts.port != null && linkFacts.port !== "" && !portEl.value) {
    portEl.value = String(linkFacts.port);
  }
}

function buildFieldTooltip(options) {
  const opts = options || {};
  const tooltipId = opts.id || "tooltip-" + uuid();
  const wrap = el("span", "field-tooltip-wrap");
  const trigger = el("button", "field-tooltip-trigger", {
    type: "button",
    "aria-label": "Подсказка",
    "aria-controls": tooltipId,
  });
  if (opts.testId) trigger.setAttribute("data-testid", opts.testId);
  text(trigger, "?");
  const tooltip = el("span", "field-tooltip", {
    id: tooltipId,
    role: "tooltip",
    hidden: "hidden",
  });
  if (opts.testId) tooltip.setAttribute("data-testid", opts.testId + "-content");
  text(tooltip, opts.text || "");
  let pinned = false;
  function showTooltip() {
    tooltip.removeAttribute("hidden");
  }
  function hideTooltip() {
    tooltip.setAttribute("hidden", "hidden");
  }
  function togglePinned() {
    pinned = !pinned;
    if (pinned) showTooltip();
    else hideTooltip();
  }
  trigger.addEventListener("focus", () => {
    if (!pinned) showTooltip();
  });
  trigger.addEventListener("blur", () => {
    if (!pinned) hideTooltip();
  });
  trigger.addEventListener("click", (ev) => {
    ev.preventDefault();
    togglePinned();
  });
  trigger.addEventListener("keydown", (ev) => {
    if (ev.key === " " || ev.key === "Enter") {
      ev.preventDefault();
      togglePinned();
    } else if (ev.key === "Escape") {
      pinned = false;
      hideTooltip();
    }
  });
  append(wrap, trigger, tooltip);
  return { wrap, tooltipId };
}

function buildAdvancedSettingsBlock(options) {
  const opts = options || {};
  const testId = opts.testId || "advanced-settings";
  const details = el("details", "config-advanced-settings", { "data-testid": testId });
  const summary = el("summary", "config-advanced-settings-summary");
  text(summary, opts.summaryText || "Дополнительные настройки");
  append(details, summary);
  const body = el("div", "config-advanced-settings-body");
  append(details, body);
  return { details, body, summary };
}

function appendHonestyNote(parent, noteText, testId) {
  const note = el("p", "field-honesty-note");
  if (testId) note.setAttribute("data-testid", testId);
  text(note, noteText);
  parent.appendChild(note);
  return note;
}

function appendFormField(form, name, label, type, options) {
  const opts = options || {};
  const field = el("div", "form-field");
  if (opts.testId) field.setAttribute("data-testid", opts.testId + "-field");
  const inputId = opts.id || name;
  const labelRow = el("div", "form-field-label-row");
  append(labelRow, text(el("label", "", { for: inputId }), label));
  let tooltipMeta = null;
  if (opts.tooltip) {
    tooltipMeta = buildFieldTooltip({
      id: inputId + "-tooltip",
      text: opts.tooltip,
      testId: opts.testId ? opts.testId + "-tooltip" : undefined,
    });
    append(labelRow, tooltipMeta.wrap);
  }
  append(field, labelRow);
  const input = el("input", "", {
    id: inputId,
    name: opts.omitName ? undefined : name,
    type: type || "text",
    required: opts.required ? "true" : undefined,
  });
  if (tooltipMeta) input.setAttribute("aria-describedby", tooltipMeta.tooltipId);
  if (opts.testId) input.setAttribute("data-testid", opts.testId);
  if (opts.placeholder) input.placeholder = opts.placeholder;
  if (opts.min != null) input.setAttribute("min", String(opts.min));
  if (opts.max != null) input.setAttribute("max", String(opts.max));
  if (opts.step != null) input.setAttribute("step", String(opts.step));
  if (opts.value != null && opts.value !== "") input.value = String(opts.value);
  if (opts.checked) input.checked = true;
  append(field, input);
  if (opts.honestyNote) appendHonestyNote(field, opts.honestyNote, opts.honestyTestId);
  form.appendChild(field);
  return input;
}

function appendFormSelect(form, name, label, optionsList, options) {
  const opts = options || {};
  const field = el("div", "form-field");
  if (opts.testId) field.setAttribute("data-testid", opts.testId + "-field");
  const selectId = opts.id || name;
  const labelRow = el("div", "form-field-label-row");
  append(labelRow, text(el("label", "", { for: selectId }), label));
  let tooltipMeta = null;
  if (opts.tooltip) {
    tooltipMeta = buildFieldTooltip({
      id: selectId + "-tooltip",
      text: opts.tooltip,
      testId: opts.testId ? opts.testId + "-tooltip" : undefined,
    });
    append(labelRow, tooltipMeta.wrap);
  }
  append(field, labelRow);
  const select = el("select", "", {
    id: selectId,
    name: opts.omitName ? undefined : name,
  });
  if (tooltipMeta) select.setAttribute("aria-describedby", tooltipMeta.tooltipId);
  if (opts.testId) select.setAttribute("data-testid", opts.testId);
  optionsList.forEach((entry) => {
    const val = entry[0];
    const lbl = entry[1];
    const disabled = entry[2];
    const opt = el("option", "", { value: val });
    if (disabled) opt.setAttribute("disabled", "disabled");
    text(opt, lbl);
    select.appendChild(opt);
  });
  if (opts.value != null && opts.value !== "") {
    select.value = String(opts.value);
  } else if (optionsList.length) {
    select.value = String(optionsList[0][0]);
  }
  append(field, select);
  if (opts.honestyNote) appendHonestyNote(field, opts.honestyNote, opts.honestyTestId);
  form.appendChild(field);
  return select;
}

function appendFormCheckbox(form, name, label, options) {
  const opts = options || {};
  const fieldClass = opts.fieldClass ? "form-field " + opts.fieldClass : "form-field";
  const field = el("div", fieldClass);
  if (opts.testId) field.setAttribute("data-testid", opts.testId + "-field");
  const inputId = opts.id || name;
  const input = el("input", "", {
    id: inputId,
    name: opts.omitName ? undefined : name,
    type: "checkbox",
    checked: opts.checked ? "checked" : undefined,
  });
  if (opts.testId) input.setAttribute("data-testid", opts.testId);
  let tooltipMeta = null;
  if (opts.tooltip) {
    tooltipMeta = buildFieldTooltip({
      id: inputId + "-tooltip",
      text: opts.tooltip,
      testId: opts.testId ? opts.testId + "-tooltip" : undefined,
    });
    input.setAttribute("aria-describedby", tooltipMeta.tooltipId);
  }
  append(field, input);
  const labelRow = el("div", "form-field-label-row form-field-checkbox-label");
  append(labelRow, text(el("label", "", { for: inputId }), label));
  if (tooltipMeta) append(labelRow, tooltipMeta.wrap);
  append(field, labelRow);
  if (opts.honestyNote) appendHonestyNote(field, opts.honestyNote, opts.honestyTestId);
  form.appendChild(field);
  return input;
}

const PRESET_ZONE_IDS = ["Guest", "Promo", "Staff", "AdminServer"];
const UPLINK_MODE_OPTIONS = [
  ["Ethernet", "Ethernet"],
  ["WifiWan", "WifiWan"],
  ["LocalOnly", "LocalOnly"],
  ["Lte", "Lte"],
];
const FIREWALL_ACTION_OPTIONS = [
  ["Allow", "Allow"],
  ["Deny", "Deny"],
];
const FIREWALL_DESTINATION_OPTIONS = [
  ["OrderPage", "OrderPage"],
  ["Dns", "Dns"],
  ["Dhcp", "Dhcp"],
  ["Management", "Management"],
  ["Internet", "Internet"],
  ["LocalZone", "LocalZone"],
];
const RACK_ASSET_ROLE_OPTIONS = [
  ["Router", "Router"],
  ["Hub", "Hub"],
  ["Switch", "Switch"],
  ["Printer", "Printer"],
  ["Plotter", "Plotter"],
];

function buildCollectionEditor(options) {
  const opts = options || {};
  const container = el("div", "config-collection-editor");
  if (opts.testId) container.setAttribute("data-testid", opts.testId);
  if (opts.label) {
    append(container, text(el("label", "config-collection-label"), opts.label));
  }
  const rowsHost = el("div", "config-collection-rows");
  append(container, rowsHost);
  const rowEntries = [];

  function readRows() {
    return rowEntries.map((entry) => {
      const item = {};
      opts.columns.forEach((col) => {
        const field = entry.fields[col.key];
        if (!field) return;
        if (col.type === "checkbox") {
          item[col.key] = !!field.checked;
        } else if (col.type === "number") {
          const raw = field.value != null ? String(field.value).trim() : "";
          item[col.key] = raw === "" ? null : Number(raw);
        } else {
          const raw = field.value != null ? String(field.value).trim() : "";
          if (col.optional && raw === "") return;
          item[col.key] = raw;
        }
      });
      return item;
    });
  }

  function addRow(initial) {
    const row = el("div", "config-collection-row");
    const fields = {};
    opts.columns.forEach((col) => {
      const fieldWrap = el("div", "config-collection-field");
      append(fieldWrap, text(el("label"), col.label || col.key));
      let input;
      if (col.type === "select") {
        input = el("select", "", { "data-col": col.key });
        (col.options || []).forEach(([val, lbl]) => {
          const opt = el("option", "", { value: val });
          text(opt, lbl);
          input.appendChild(opt);
        });
      } else if (col.type === "checkbox") {
        input = el("input", "", { type: "checkbox", "data-col": col.key });
      } else {
        input = el("input", "", {
          type: col.type === "number" ? "number" : "text",
          "data-col": col.key,
          placeholder: col.placeholder || "",
        });
      }
      if (initial && initial[col.key] != null) {
        if (col.type === "checkbox") input.checked = !!initial[col.key];
        else input.value = String(initial[col.key]);
      }
      fields[col.key] = input;
      append(fieldWrap, input);
      append(row, fieldWrap);
    });
    const removeBtn = el("button", "btn btn-secondary config-collection-remove", { type: "button" });
    text(removeBtn, "Remove");
    removeBtn.addEventListener("click", () => {
      const idx = rowEntries.findIndex((e) => e.row === row);
      if (idx >= 0) rowEntries.splice(idx, 1);
      rowsHost.removeChild(row);
    });
    append(row, removeBtn);
    rowsHost.appendChild(row);
    rowEntries.push({ row, fields });
    return { row, fields };
  }

  function setRows(items) {
    while (rowEntries.length) {
      const entry = rowEntries.pop();
      rowsHost.removeChild(entry.row);
    }
    (items || []).forEach((item) => addRow(item));
  }

  const addBtn = el("button", "btn btn-secondary config-collection-add", { type: "button" });
  text(addBtn, opts.addLabel || "Add");
  addBtn.addEventListener("click", () => addRow());
  append(container, addBtn);

  const minRows = opts.minRows != null ? opts.minRows : 0;
  const initial = opts.initialRows || [];
  if (initial.length) initial.forEach((item) => addRow(item));
  else for (let i = 0; i < minRows; i += 1) addRow();

  return { container, addRow, readRows, setRows, rowsHost };
}

function readFirewallRulesFromEditor(editor) {
  return editor.readRows().map((row) => ({
    action: row.action,
    destination_family: row.destination_family,
    ordinal: Number(row.ordinal),
  }));
}

function readDhcpReservationsFromEditor(editor) {
  return editor.readRows().map((row) => ({
    mac_address: row.mac_address,
    ipv4_address: row.ipv4_address,
  }));
}

function readStringListFromEditor(editor) {
  return editor.readRows().map((row) => row.address).filter(Boolean);
}

function readVpnNameServersFromEditor(editor) {
  return editor.readRows().map((row) => {
    const item = { address: row.address };
    if (row.domain) item.domain = row.domain;
    if (row.on_interface) item.on_interface = row.on_interface;
    return item;
  });
}

function parseHash() {
  const raw = (location.hash || "#dashboard").replace(/^#/, "");
  const parts = raw.split("/").filter(Boolean);
  return { view: parts[0] || "dashboard", params: parts.slice(1) };
}

function setHash(view, ...params) {
  const tail = params.length ? "/" + params.join("/") : "";
  location.hash = "#" + view + tail;
}

function rememberOp(id) {
  if (!id) return;
  sessionMemory.recentOps = [id, ...sessionMemory.recentOps.filter((x) => x !== id)].slice(0, 20);
}

function rememberJob(id) {
  if (!id) return;
  sessionMemory.recentJobs = [id, ...sessionMemory.recentJobs.filter((x) => x !== id)].slice(0, 20);
}

function toast(message) {
  if (
    typeof globalThis !== "undefined"
    && Array.isArray(globalThis.__ROUTER_CONTROL_TOAST_CAPTURE__)
  ) {
    globalThis.__ROUTER_CONTROL_TOAST_CAPTURE__.push(String(message));
  }
  const region = document.getElementById("toast-region");
  if (!region) return;
  const item = el("div", "toast");
  text(item, message);
  region.appendChild(item);
  window.setTimeout(() => {
    if (item.parentNode) item.parentNode.removeChild(item);
  }, 5000);
}

function showBanner(message, kind) {
  const banner = document.getElementById("global-banner");
  if (!banner) return;
  banner.hidden = false;
  banner.className = "global-banner" + (kind ? " is-" + kind : "");
  text(banner, message);
}

function hideBanner() {
  const banner = document.getElementById("global-banner");
  if (!banner) return;
  banner.hidden = true;
  clear(banner);
}

function writeGatesBlocked(status) {
  if (!status) return true;
  const fs = status.feature_state;
  if (fs === "SecurityBlocked" || fs === "Degraded") return true;
  const wg = status.write_gates;
  if (wg) {
    if (wg.blocked === true) return true;
    if (wg.write_certified === true && wg.blocked === false) return false;
  }
  const gates = status.gates;
  if (gates) {
    const gateB = gates.B;
    if (gateB === "open" || gateB === "WriteCertified") {
      return false;
    }
    if (gateB === "closed") return true;
  }
  return true;
}

function gateBlockReason(status) {
  if (!status) return "Статус недоступен";
  if (status.feature_state === "Degraded") return "feature.degraded — мутации заблокированы";
  if (status.feature_state === "SecurityBlocked") return "SecurityBlocked — операции записи закрыты";
  if (status.write_gates && status.write_gates.reason) return status.write_gates.reason;
  if (status.gates && status.gates.B === "closed") {
    return "Gate B closed — not WriteCertified";
  }
  return "Write gates blocked or unknown — Apply/live-write недоступны";
}

function gateADisplay(status) {
  if (status.gate_a && status.gate_a.certification) return status.gate_a.certification;
  if (status.gate_a && status.gate_a.status) return status.gate_a.status;
  if (status.gates && status.gates.A) return status.gates.A;
  return "N/A";
}

function applyTheme(mode) {
  const html = document.documentElement;
  html.setAttribute("data-theme", mode);
  localStorage.setItem(THEME_KEY, mode);
  document.querySelectorAll(".btn-theme").forEach((btn) => {
    const pressed = btn.getAttribute("data-theme-value") === mode;
    btn.setAttribute("aria-pressed", pressed ? "true" : "false");
  });
}

function initTheme() {
  const saved = localStorage.getItem(THEME_KEY) || "system";
  applyTheme(saved);
  document.querySelectorAll(".btn-theme").forEach((btn) => {
    btn.addEventListener("click", () => {
      applyTheme(btn.getAttribute("data-theme-value") || "system");
    });
  });
}

function normalizeUiMode(mode) {
  return mode === "expert" ? "expert" : "simple";
}

function applyUiMode(mode, options) {
  const opts = options || {};
  const normalized = normalizeUiMode(mode);
  const html = document.documentElement;
  html.setAttribute("data-ui-mode", normalized);
  localStorage.setItem(UI_MODE_KEY, normalized);
  document.querySelectorAll(".btn-ui-mode").forEach((btn) => {
    const pressed = btn.getAttribute("data-ui-mode-value") === normalized;
    btn.setAttribute("aria-pressed", pressed ? "true" : "false");
  });
  if (opts.navigate !== false) {
    const { view } = parseHash();
    if (normalized === "simple" && view !== "simple" && isExpertOnlyView(view)) {
      setHash("simple");
    } else if (normalized === "expert" && view === "simple" && !opts.keepView) {
      setHash("dashboard");
    }
  }
}

function isExpertOnlyView(view) {
  return view !== "simple" && view !== "settings";
}

function initUiMode() {
  const saved = normalizeUiMode(localStorage.getItem(UI_MODE_KEY) || "simple");
  applyUiMode(saved, { navigate: false });
  document.querySelectorAll(".btn-ui-mode").forEach((btn) => {
    btn.addEventListener("click", () => {
      applyUiMode(btn.getAttribute("data-ui-mode-value") || "simple");
      navigate();
    });
  });
  document.querySelectorAll(".nav-link-expert-entry").forEach((link) => {
    link.addEventListener("click", () => {
      applyUiMode("expert", { navigate: false, keepView: true });
    });
  });
}

function deriveSimpleLinkState(facts) {
  const labels = {
    ok: "Связь есть",
    fail: "Связи нет",
    unknown: "Состояние неизвестно",
  };
  if (!facts || typeof facts !== "object") {
    return { visual: "unknown", label: labels.unknown, cssClass: "is-unknown" };
  }
  const healthStatus = facts.health_status;
  if (healthStatus === "yellow") {
    return { visual: "unknown", label: labels.unknown, cssClass: "is-unknown" };
  }
  if (
    facts.host_key_mismatch ||
    facts.identity_mismatch ||
    facts.explicit_unreachable ||
    facts.credentials_missing ||
    healthStatus === "red"
  ) {
    const reason = deriveSimpleLinkFailReason(facts);
    return {
      visual: "fail",
      label: labels.fail,
      cssClass: "is-fail",
      reason: reason || undefined,
    };
  }
  const allFive = simpleLinkAllFiveFactsTrue(facts);
  if (allFive && healthStatus === "green") {
    return { visual: "ok", label: labels.ok, cssClass: "is-ok" };
  }
  return { visual: "unknown", label: labels.unknown, cssClass: "is-unknown" };
}

function classifySimpleDiscoveryIdentityState(identityState) {
  if (identityState === "known_mismatch") {
    return { action: "mismatch_msg" };
  }
  if (identityState === "unknown") {
    return { action: "unknown_msg" };
  }
  if (identityState === "known_match") {
    return { action: "success_toast" };
  }
  return { action: "unknown_msg" };
}

function clearSimpleDiscoveryCandidatePicker(container) {
  if (!container) return;
  const existing = container.querySelector("[data-testid='simple-discovery-candidates']");
  if (existing && existing.parentNode) {
    existing.parentNode.removeChild(existing);
  }
}

function appendSimpleDiscoveryIdentityOutcome(errBox, candidate) {
  const outcome = classifySimpleDiscoveryIdentityState(candidate.identity_state);
  if (outcome.action === "mismatch_msg") {
    append(
      errBox,
      text(
        el("p"),
        "Найден роутер, но identity не совпадает — укажите учётные данные для зачисления.",
      ),
    );
  } else if (outcome.action === "unknown_msg") {
    append(
      errBox,
      text(
        el("p"),
        "Найден кандидат — укажите имя пользователя и пароль для подключения.",
      ),
    );
  } else if (outcome.action === "success_toast") {
    toast("Найден известный роутер: " + candidate.host);
  }
}

function renderSimpleDiscoveryCandidatePicker(errBox, candidates, onSelect) {
  clearSimpleDiscoveryCandidatePicker(errBox);
  const panel = el("div", "simple-discovery-candidates", {
    "data-testid": "simple-discovery-candidates",
  });
  append(
    panel,
    text(
      el("p", "simple-discovery-candidates-lead"),
      "Найдено несколько кандидатов — выберите роутер:",
    ),
  );
  candidates.forEach((candidate, index) => {
    const row = el("div", "simple-discovery-candidate-row", {
      "data-testid": "simple-discovery-candidate-row-" + index,
    });
    const radioId = "simple-discovery-candidate-" + index;
    const radio = el("input", "simple-discovery-candidate-radio", {
      type: "radio",
      name: "simple-discovery-candidate",
      id: radioId,
      value: String(index),
    });
    const label = el("label", "simple-discovery-candidate-label", { for: radioId });
    const origin = candidate.candidate_origin || "unknown";
    const identity = candidate.identity_state || "unknown";
    let labelText = candidate.host + " (" + origin + ", " + identity + ")";
    if (candidate.source_address) {
      labelText += " · src " + candidate.source_address;
    }
    if (candidate.route_label) {
      labelText += " · " + candidate.route_label;
    }
    text(label, labelText);
    const selectBtn = el("button", "btn btn-secondary simple-discovery-candidate-select", {
      type: "button",
      "data-testid": "simple-discovery-candidate-select-" + index,
    });
    text(selectBtn, "Выбрать этот");
    selectBtn.addEventListener("click", () => onSelect(candidate));
    append(row, radio, label, selectBtn);
    append(panel, row);
  });
  append(errBox, panel);
}

function applySimpleDiscoveryCandidateSelection(connectSurface, candidate) {
  clearSimpleDiscoveryCandidatePicker(connectSurface.errBox);
  const hostEl = connectSurface.form.querySelector("#wizard-host");
  if (hostEl && candidate.host) hostEl.value = candidate.host;
  if (typeof candidate.source_address === "string") {
    const trimmedSource = candidate.source_address.trim();
    if (trimmedSource) {
      const sourceEl = connectSurface.form.querySelector("#wizard-source-address");
      if (sourceEl) sourceEl.value = trimmedSource;
      const healthSourceEl = document.querySelector("#simple-health-source-address");
      if (healthSourceEl) healthSourceEl.value = trimmedSource;
    }
  }
  appendSimpleDiscoveryIdentityOutcome(connectSurface.errBox, candidate);
}

function appendSimpleDiscoveryDegradedWarning(errBox, discoveryData) {
  if (!errBox || !discoveryData || typeof discoveryData !== "object") return;
  const degraded = Array.isArray(discoveryData.degraded_sources)
    ? discoveryData.degraded_sources
    : [];
  const failedDiagnostics = Array.isArray(discoveryData.source_diagnostics)
    ? discoveryData.source_diagnostics.filter((item) => item && item.status === "failed")
    : [];
  if (!degraded.length && !failedDiagnostics.length) return;
  append(
    errBox,
    text(
      el("p"),
      "Не удалось прочитать локальные маршруты — при необходимости укажите адрес вручную.",
    ),
  );
}

function handleSimpleDiscoveryCandidates(connectSurface, candidates) {
  clear(connectSurface.errBox);
  const items = Array.isArray(candidates) ? candidates : [];
  if (!items.length) {
    append(
      connectSurface.errBox,
      text(el("p"), "Кандидаты не найдены — укажите адрес вручную."),
    );
    return;
  }
  if (items.length === 1) {
    applySimpleDiscoveryCandidateSelection(connectSurface, items[0]);
    return;
  }
  renderSimpleDiscoveryCandidatePicker(connectSurface.errBox, items, (selected) => {
    applySimpleDiscoveryCandidateSelection(connectSurface, selected);
  });
}

function mapConnectionHealthToLinkFacts(healthReport) {
  const facts = { loaded: !!healthReport };
  if (!healthReport || typeof healthReport !== "object") return facts;
  facts.health_status = healthReport.status || null;
  facts.reason_code = healthReport.reason_code || null;
  const hf = healthReport.facts;
  if (!hf || typeof hf !== "object") return facts;
  if (hf.reachable === true) facts.reachability_ok = true;
  else if (hf.reachable === false) facts.explicit_unreachable = true;
  if (hf.host_key_match === true) facts.host_key_pinned = true;
  else if (hf.host_key_match === false) facts.host_key_mismatch = true;
  if (hf.tuple_match === true) facts.identity_consistent = true;
  else if (hf.tuple_match === false) facts.identity_mismatch = true;
  if (hf.credentials_present === true) facts.credentials_present = true;
  else if (hf.credentials_present === false) facts.credentials_missing = true;
  if (hf.evidence_fresh === true) facts.evidence_fresh = true;
  return facts;
}

/** @deprecated Legacy stitch — Gate A metadata alone never implies green. */
function buildSimpleLinkFactsFromApis(status, routerDetail, refreshError) {
  const facts = { loaded: !!status };
  if (refreshError) {
    facts.health_unavailable = true;
    return facts;
  }
  if (!status) return facts;
  const enrolled = status.routers_summary && status.routers_summary.enrolled > 0;
  if (enrolled) facts.has_enrolled_router = true;
  return facts;
}

async function fetchSimpleLinkFacts(overrides) {
  const opts = overrides || {};
  let routerId = null;
  let host = null;
  let displayName = null;
  let port = null;
  try {
    const { data: routers } = await apiFetch("/routers");
    const items = routers.items || [];
    if (items.length > 0 && items[0].router_id) {
      routerId = items[0].router_id;
      if (items[0].display_name) displayName = items[0].display_name;
      try {
        const { data: detail } = await apiFetch(
          "/routers/" + encodeURIComponent(items[0].router_id),
        );
        const endpoints = detail.endpoints || [];
        const enabled = endpoints.find((ep) => ep && ep.is_enabled !== false) || endpoints[0];
        if (enabled) {
          if (enabled.host) host = enabled.host;
          if (enabled.port != null) port = enabled.port;
        }
        if (!displayName && detail.display_name) displayName = detail.display_name;
      } catch (_detailErr) {
        /* endpoint host optional */
      }
    }
  } catch (_routerErr) {
    /* no enrolled router */
  }
  const enrolledMeta = {
    has_enrolled_router: !!routerId,
    router_id: routerId || undefined,
    host: host || undefined,
    display_name: displayName || undefined,
    port: port != null ? port : undefined,
  };
  if (!routerId && !host && !opts.host) {
    return { loaded: false, no_target: true, has_enrolled_router: false };
  }
  const probeMeta = lookupFieldMeta("connection_health", "probe");
  const defaultProbe =
    probeMeta && Object.prototype.hasOwnProperty.call(probeMeta, "default")
      ? !!probeMeta.default
      : true;
  const body = { probe: opts.probe != null ? !!opts.probe : defaultProbe };
  if (routerId) body.router_id = routerId;
  else if (opts.host) body.host = opts.host;
  else if (host) body.host = host;
  if (opts.credential_ref_id) body.credential_ref_id = opts.credential_ref_id;
  if (opts.source_address) body.source_address = opts.source_address;
  if (opts.ssh_host_key_sha256) body.ssh_host_key_sha256 = opts.ssh_host_key_sha256;
  try {
    const { data: health } = await apiFetch("/lab/connection-health", {
      method: "POST",
      body,
    });
    return Object.assign(mapConnectionHealthToLinkFacts(health), enrolledMeta);
  } catch (_healthErr) {
    return Object.assign({ loaded: false, health_unavailable: true }, enrolledMeta);
  }
}

function buildSimpleConnectStepSurface(options) {
  const opts = options || {};
  const linkFacts = opts.linkFacts || null;
  const stepUx = deriveSimpleConnectStep1Ux(linkFacts);
  const section = el("section", "simple-step simple-step-connect panel");
  section.setAttribute("data-testid", "simple-step-connect");
  append(section, text(el("h2", "simple-step-title"), "Шаг 1 — Подключение к роутеру"));
  if (stepUx.mode === "no_enrolled" || stepUx.mode === "auto_fail") {
    append(
      section,
      text(
        el("p", "simple-step-lead"),
        "Укажите адрес роутера, имя пользователя и пароль для подключения к панели управления.",
      ),
    );
  }
  if (stepUx.showAutoFailMessage) {
    const failMsg = el("p", "simple-connect-auto-fail field-hint", {
      "data-testid": "simple-connect-auto-fail",
    });
    text(
      failMsg,
      "Не удалось подключиться автоматически — обновите настройки или введите их заново",
    );
    append(section, failMsg);
  }
  if (stepUx.showConnectedSummary) {
    const summary = el("p", "simple-connect-summary link-state is-ok", {
      "data-testid": "simple-connect-summary",
    });
    text(summary, "Подключено: " + simpleConnectDisplayLabel(linkFacts));
    append(section, summary);
  }
  const draftUi = buildWizardDraftFormSurface({ disclosure: "simple" });
  const form = draftUi.form;
  form.classList.add("simple-connect-form");
  prefillSimpleConnectForm(form, linkFacts);
  const advanced = buildAdvancedSettingsBlock({
    testId: "simple-connect-advanced-settings",
    summaryText: "Дополнительные настройки подключения",
  });
  append(
    advanced.body,
    text(
      el("p", "field-hint simple-autodetect-honesty"),
      "Автообнаружение перечисляет кандидатов в локальной сети без live probe. "
        + "Для неизвестного или несовпадающего identity нужны учётные данные.",
    ),
  );
  const autoDetectBtn = el("button", "btn btn-secondary simple-connect-autodetect-secondary", {
    type: "button",
    "data-testid": "simple-connect-autodetect",
  });
  text(autoDetectBtn, "Автообнаружение");
  append(advanced.body, autoDetectBtn);
  appendFormCheckbox(
    advanced.body,
    "include_default_gateway",
    "Default gateway кандидат",
    fieldTooltipOpts("router_discovery", "include_default_gateway", {
      id: "simple-discovery-include-gateway",
      testId: "simple-discovery-include-gateway",
    }),
  );
  appendFormCheckbox(
    advanced.body,
    "include_known_endpoints",
    "Known endpoints кандидаты",
    fieldTooltipOpts("router_discovery", "include_known_endpoints", {
      id: "simple-discovery-include-endpoints",
      testId: "simple-discovery-include-endpoints",
    }),
  );
  appendFormCheckbox(
    advanced.body,
    "probe",
    "Identity probe кандидатов",
    fieldTooltipOpts("router_discovery", "probe", {
      id: "simple-discovery-probe",
      testId: "simple-discovery-probe",
    }),
  );
  appendFormField(
    advanced.body,
    "preferred_source_address",
    "Preferred source address",
    "text",
    fieldTooltipOpts("router_discovery", "preferred_source_address", {
      id: "simple-discovery-source-address",
      testId: "simple-discovery-source-address",
      placeholder: "192.168.2.10",
    }),
  );
  form.appendChild(advanced.details);
  const errBox = el("div", "simple-connect-error");
  form.appendChild(errBox);
  const btnRow = el("div", "btn-row");
  const submit = el("button", "btn btn-primary", {
    type: "submit",
    "data-testid": "simple-connect-submit",
  });
  text(submit, "Сохранить черновик роутера");
  append(btnRow, submit);
  form.appendChild(btnRow);
  function readDiscoveryBody() {
    const gwEl = form.querySelector("#simple-discovery-include-gateway");
    const epEl = form.querySelector("#simple-discovery-include-endpoints");
    const probeEl = form.querySelector("#simple-discovery-probe");
    const srcEl = form.querySelector("#simple-discovery-source-address");
    const body = {
      include_default_gateway: !!(gwEl && gwEl.checked),
      include_known_endpoints: !!(epEl && epEl.checked),
      probe: !!(probeEl && probeEl.checked),
    };
    if (srcEl && srcEl.value && srcEl.value.trim()) {
      body.preferred_source_address = srcEl.value.trim();
    }
    return body;
  }
  let formDetails = null;
  if (stepUx.mode === "connected") {
    formDetails = el("details", "simple-connect-form-details config-advanced-settings");
    formDetails.setAttribute("data-testid", "simple-connect-form-details");
    const editSummary = el("summary", "simple-connect-edit-summary config-advanced-settings-summary", {
      "data-testid": "simple-connect-edit",
    });
    text(editSummary, "Изменить настройки");
    formDetails.appendChild(editSummary);
    formDetails.appendChild(form);
    append(section, formDetails);
  } else {
    append(section, form);
  }
  return {
    section,
    form,
    formDetails,
    stepUx,
    errBox,
    submit,
    autoDetectBtn,
    advancedDetails: advanced.details,
    readPayload: () => draftUi.readPayload(true),
    readDiscoveryBody,
    clearSecret: () => {
      const secretEl = form.querySelector("#wizard-secret");
      if (secretEl) secretEl.value = "";
    },
  };
}

function buildSimpleLinkStepSurface(linkFacts) {
  const section = el("section", "simple-step simple-step-link panel");
  section.setAttribute("data-testid", "simple-step-link");
  append(section, text(el("h2", "simple-step-title"), "Шаг 2 — Связь"));
  append(
    section,
    text(
      el("p", "simple-step-lead"),
      "Состояние связи выводится из POST /lab/connection-health (пять фактов: reachable, host-key, tuple, "
        + "credentials, evidence freshness). HTTP 200 или «Ready» сами по себе не означают «связь есть».",
    ),
  );
  const linkState = deriveSimpleLinkState(linkFacts);
  const badge = el("div", "link-state " + linkState.cssClass, {
    "data-testid": "simple-link-state",
    "data-link-visual": linkState.visual,
  });
  text(badge, linkState.label);
  append(section, badge);
  if (linkState.reason) {
    const reasonEl = el("p", "simple-link-reason field-hint", {
      "data-testid": "simple-link-reason",
    });
    text(reasonEl, linkState.reason);
    append(section, reasonEl);
  }
  const advanced = buildAdvancedSettingsBlock({
    testId: "simple-link-advanced-settings",
  });
  appendFormCheckbox(
    advanced.body,
    "probe",
    "Live reachability probe",
    fieldTooltipOpts("connection_health", "probe", {
      id: "simple-health-probe",
      testId: "simple-health-probe",
    }),
  );
  appendFormField(
    advanced.body,
    "source_address",
    "Source address (bind)",
    "text",
    fieldTooltipOpts("connection_health", "source_address", {
      id: "simple-health-source-address",
      testId: "simple-health-source-address",
      placeholder: "192.168.2.10",
    }),
  );
  appendFormField(
    advanced.body,
    "ssh_host_key_sha256",
    "SSH host-key SHA256 pin",
    "text",
    fieldTooltipOpts("connection_health", "ssh_host_key_sha256", {
      id: "simple-health-ssh-pin",
      testId: "simple-health-ssh-pin",
      placeholder: "SHA256:…",
    }),
  );
  append(section, advanced.details);
  function readHealthProbeBody() {
    const probeEl = section.querySelector("#simple-health-probe");
    const srcEl = section.querySelector("#simple-health-source-address");
    const pinEl = section.querySelector("#simple-health-ssh-pin");
    const body = {
      probe: !!(probeEl && probeEl.checked),
    };
    if (srcEl && srcEl.value && srcEl.value.trim()) {
      body.source_address = srcEl.value.trim();
    }
    if (pinEl && pinEl.value && pinEl.value.trim()) {
      body.ssh_host_key_sha256 = pinEl.value.trim();
    }
    return body;
  }
  const refreshBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "simple-link-refresh",
  });
  text(refreshBtn, "Обновить состояние связи");
  append(section, refreshBtn);
  return { section, badge, linkState, refreshBtn, readHealthProbeBody, advancedDetails: advanced.details };
}

function buildSimpleWifiUplinkStepSurface(options) {
  const opts = options || {};
  let activeRouterId = opts.routerId ? String(opts.routerId) : "";

  function setRouterId(id) {
    activeRouterId = id ? String(id) : "";
  }
  function getRouterId() {
    return activeRouterId;
  }

  const section = el("section", "simple-step simple-step-wifi-uplink panel");
  section.setAttribute("data-testid", "simple-step-wifi-uplink");
  append(section, text(el("h2", "simple-step-title"), "Шаг 3 — Интернет (Wi‑Fi uplink роутера)"));
  append(
    section,
    text(
      el("p", "simple-step-lead"),
      "Роутер подключается к интернету как Wi‑Fi клиент (WISP) — укажите сеть провайдера "
        + "или точки доступа. Это не вход в панель управления и не гостевая Wi‑Fi.",
    ),
  );
  append(
    section,
    text(
      el("p", "field-hint simple-uplink-honesty"),
      "Предпросмотр проверяет grammar intent; runtime uplink после apply не device-verified. "
        + "grammar_verification_status ≠ uplink_verification_status.",
    ),
  );

  const scanBlock = el("div", "simple-uplink-scan-block");
  const scanBtnRow = el("div", "btn-row");
  const scanBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "simple-uplink-scan",
  });
  text(scanBtn, "Найти сети");
  append(scanBtnRow, scanBtn);
  const scanStatus = el("p", "field-hint simple-uplink-scan-status");
  scanStatus.setAttribute("data-testid", "simple-uplink-scan-status");
  scanStatus.hidden = true;
  const scanResults = el("div", "simple-uplink-network-list");
  scanResults.setAttribute("data-testid", "simple-uplink-scan-results");
  append(scanBlock, scanBtnRow, scanStatus, scanResults);

  const selectedBlock = el("div", "simple-uplink-selected-block");
  selectedBlock.hidden = true;
  const selectedSummary = el("p", "field-hint simple-uplink-selected-summary");
  text(selectedSummary, "Сеть не выбрана.");
  const enrollPasswordField = el("div", "form-field");
  enrollPasswordField.setAttribute("data-testid", "simple-uplink-enroll-password-field");
  const enrollPasswordId = "simple-uplink-enroll-password";
  append(
    enrollPasswordField,
    text(el("label", "", { for: enrollPasswordId }), "Пароль выбранной сети"),
  );
  const enrollPasswordEl = el("input", "", {
    id: enrollPasswordId,
    type: "password",
    "data-testid": "simple-uplink-enroll-password",
  });
  enrollPasswordEl.placeholder = "не сохраняется после enroll";
  append(enrollPasswordField, enrollPasswordEl);
  const enrollBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "simple-uplink-enroll",
  });
  text(enrollBtn, "Сохранить пароль");
  const openUnsupportedEl = el("p", "field-hint simple-uplink-open-unsupported");
  openUnsupportedEl.hidden = true;
  text(
    openUnsupportedEl,
    "Открытая сеть: подключение без пароля пока не поддержано — для ручного ввода укажите "
      + "другой SSID или используйте экспертный режим.",
  );
  append(selectedBlock, selectedSummary, enrollPasswordField, enrollBtn, openUnsupportedEl);

  const manualAdvanced = buildAdvancedSettingsBlock({
    testId: "simple-uplink-manual-settings",
    summaryText: "Сеть не в списке? Ввести вручную",
  });
  const manualForm = el("form", "form-grid simple-uplink-manual-form");
  appendFormField(manualForm, "ssid", "Имя сети (SSID)", "text", fieldTooltipOpts("wifi_station", "ssid", {
    id: "simple-uplink-ssid",
    testId: "simple-uplink-ssid",
    placeholder: "Venue-WiFi",
  }));
  appendFormSelect(
    manualForm,
    "band",
    "Диапазон",
    [
      ["BAND_2_4GHZ", "2,4 ГГц"],
      ["BAND_5GHZ", "5 ГГц"],
    ],
    fieldTooltipOpts("wifi_station", "band", {
      id: "simple-uplink-band",
      testId: "simple-uplink-band",
    }),
  );
  appendFormField(
    manualForm,
    "credential_ref_id",
    "Пароль сети (credential_ref)",
    "password",
    fieldTooltipOpts("wifi_station", "credential_ref_id", {
      id: "simple-uplink-credential-ref",
      testId: "simple-uplink-credential-ref",
      placeholder: "credref:…",
      omitName: true,
    }),
  );
  append(manualAdvanced.body, manualForm);

  const form = el("form", "form-grid simple-uplink-form");
  appendFormCheckbox(
    form,
    "confirm_live_apply",
    "Подтверждаю live apply Wi‑Fi uplink (может оборвать текущий интернет)",
    fieldTooltipOpts("wifi_station", "confirm_live_apply", {
      id: "simple-uplink-confirm",
      testId: "simple-uplink-confirm",
    }),
  );
  const previewPanel = el("div", "simple-uplink-preview panel-sub");
  const previewBox = el("pre", "mono config-result simple-uplink-preview-box");
  previewBox.setAttribute("data-testid", "simple-uplink-preview-result");
  append(previewPanel, previewBox);
  const resultPanel = el("div", "simple-uplink-result panel-sub");
  const resultBox = el("pre", "mono config-result simple-uplink-apply-result");
  resultBox.setAttribute("data-testid", "simple-uplink-apply-result");
  append(resultPanel, resultBox);
  const btnRow = el("div", "btn-row");
  const previewBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "simple-uplink-preview",
  });
  text(previewBtn, "Предпросмотр");
  const applyBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "simple-uplink-apply",
  });
  text(applyBtn, "Подключить (test uplink)");
  append(btnRow, previewBtn, applyBtn);
  append(
    section,
    scanBlock,
    selectedBlock,
    manualAdvanced.details,
    form,
    btnRow,
    previewPanel,
    resultPanel,
  );

  const uplinkScanState = {
    scanResults: [],
    selected: null,
    selectedIndex: -1,
    skippedNotice: "",
    lastOpenBlockedSsid: null,
  };

  function readSurveyBodyForRadio(radio) {
    const body = { radio };
    const live = resolveSimpleLiveConnectionParams();
    if (live) Object.assign(body, live);
    return body;
  }

  async function resolveActiveRouterId() {
    if (activeRouterId) return activeRouterId;
    if (
      simpleModeWizardState
      && simpleModeWizardState.linkFacts
      && simpleModeWizardState.linkFacts.router_id
    ) {
      return String(simpleModeWizardState.linkFacts.router_id);
    }
    try {
      const { data: routers } = await apiFetch("/routers");
      const items = routers.items || [];
      if (items.length > 0 && items[0].router_id) {
        return String(items[0].router_id);
      }
    } catch (_routerErr) {
      /* no enrolled router */
    }
    return "";
  }

  function setScanStatus(kind, message) {
    if (message) {
      text(scanStatus, message);
      scanStatus.hidden = false;
    } else {
      clear(scanStatus);
      scanStatus.hidden = true;
    }
    if (kind) scanStatus.setAttribute("data-scan-state", kind);
    else scanStatus.removeAttribute("data-scan-state");
  }

  function enterManualOverride() {
    uplinkScanState.selected = null;
    uplinkScanState.selectedIndex = -1;
    const ssidEl = section.querySelector("#simple-uplink-ssid");
    const currentSsid = ssidEl && ssidEl.value ? ssidEl.value.trim() : "";
    const stillOpenBlocked =
      uplinkScanState.lastOpenBlockedSsid != null
      && currentSsid === uplinkScanState.lastOpenBlockedSsid;
    if (stillOpenBlocked) {
      openUnsupportedEl.hidden = false;
      if (enrollPasswordEl) enrollPasswordEl.disabled = true;
      enrollBtn.disabled = true;
      previewBtn.disabled = true;
      applyBtn.disabled = true;
    } else {
      openUnsupportedEl.hidden = true;
      if (enrollPasswordEl) enrollPasswordEl.disabled = false;
      enrollBtn.disabled = false;
      previewBtn.disabled = false;
      applyBtn.disabled = false;
      uplinkScanState.lastOpenBlockedSsid = null;
      text(selectedSummary, "Ручной ввод параметров");
    }
    selectedBlock.hidden = false;
    renderScanResults();
  }

  function selectNetwork(net, idx) {
    uplinkScanState.selected = net;
    uplinkScanState.selectedIndex = idx != null ? idx : -1;
    const ssidEl = section.querySelector("#simple-uplink-ssid");
    const bandEl = section.querySelector("#simple-uplink-band");
    const credEl = section.querySelector("#simple-uplink-credential-ref");
    const ssidValue =
      net && net.ssid && !net.hidden ? String(net.ssid) : net && net.hidden ? "" : "";
    if (ssidEl) ssidEl.value = ssidValue;
    if (bandEl && net && net.survey_radio) {
      bandEl.value = uplinkBandForRadio(net.survey_radio);
    }
    if (credEl) credEl.value = "";
    if (enrollPasswordEl) enrollPasswordEl.value = "";
    text(
      selectedSummary,
      uplinkDisplaySsidRu(net)
        + " · "
        + (net && net.band_label ? net.band_label : uplinkRadioLabelRu(net && net.survey_radio))
        + " · "
        + uplinkSecurityLabelRu(net),
    );
    selectedBlock.hidden = false;
    const isOpen = !!(net && net.wpa_mode === "open");
    uplinkScanState.lastOpenBlockedSsid = isOpen ? ssidValue.trim() : null;
    openUnsupportedEl.hidden = !isOpen;
    if (enrollPasswordEl) enrollPasswordEl.disabled = isOpen;
    enrollBtn.disabled = isOpen;
    previewBtn.disabled = isOpen;
    applyBtn.disabled = isOpen;
    renderScanResults();
  }

  function renderScanResults() {
    clear(scanResults);
    if (uplinkScanState.skippedNotice) {
      const notice = el("p", "field-hint simple-uplink-scan-skipped");
      text(notice, uplinkScanState.skippedNotice);
      scanResults.appendChild(notice);
    }
    if (!uplinkScanState.scanResults.length) return;
    uplinkScanState.scanResults.forEach((net, idx) => {
      const row = el("button", "simple-uplink-network-row", {
        type: "button",
        "data-index": String(idx),
      });
      const ssidLine = el("span", "simple-uplink-network-ssid");
      text(ssidLine, uplinkDisplaySsidRu(net));
      const metaLine = el("span", "simple-uplink-network-meta");
      const signal = uplinkSignalLabelRu(net.signal_quality, net.rssi);
      const security = uplinkSecurityLabelRu(net);
      const band = net.band_label || uplinkRadioLabelRu(net.survey_radio);
      text(metaLine, signal + " · " + security + " · " + band);
      append(row, ssidLine, metaLine);
      if (uplinkScanState.selectedIndex === idx) row.classList.add("is-selected");
      row.addEventListener("click", () => selectNetwork(net, idx));
      scanResults.appendChild(row);
    });
  }

  async function runScan() {
    uplinkScanState.scanResults = [];
    uplinkScanState.selected = null;
    uplinkScanState.selectedIndex = -1;
    uplinkScanState.skippedNotice = "";
    uplinkScanState.lastOpenBlockedSsid = null;
    selectedBlock.hidden = true;
    const ssidEl = section.querySelector("#simple-uplink-ssid");
    const bandEl = section.querySelector("#simple-uplink-band");
    const credEl = section.querySelector("#simple-uplink-credential-ref");
    if (ssidEl) ssidEl.value = "";
    if (credEl) credEl.value = "";
    if (bandEl) bandEl.value = "BAND_2_4GHZ";
    if (enrollPasswordEl) enrollPasswordEl.value = "";
    openUnsupportedEl.hidden = true;
    if (enrollPasswordEl) enrollPasswordEl.disabled = false;
    enrollBtn.disabled = false;
    previewBtn.disabled = false;
    applyBtn.disabled = false;
    clear(scanResults);
    scanBtn.disabled = true;
    setScanStatus("loading", "Сканирование…");
    const radios = ["WifiMaster0", "WifiMaster1"];
    let skippedTotal = 0;
    const merged = [];
    const radioFailures = [];
    for (const radio of radios) {
      try {
        const { data } = await apiFetch("/wifi/site-survey", {
          method: "POST",
          body: readSurveyBodyForRadio(radio),
          idempotencyKey: uuid(),
        });
        skippedTotal += Number(data.skipped_row_count || 0);
        const nets = Array.isArray(data.networks) ? data.networks : [];
        nets.forEach((net) => {
          merged.push({
            ...net,
            survey_radio: radio,
            band_label: uplinkRadioLabelRu(radio),
          });
        });
      } catch (radioErr) {
        radioFailures.push({ radio, error: radioErr });
      }
    }
    uplinkScanState.scanResults = merged;
    if (skippedTotal > 0) {
      uplinkScanState.skippedNotice =
        "Часть строк опущена (skipped_row_count=" + String(skippedTotal) + ").";
    }
    renderScanResults();
    if (merged.length > 0) {
      let statusMsg = "Найдено сетей: " + String(merged.length);
      if (radioFailures.length > 0) {
        const failParts = radioFailures.map(
          ({ radio, error }) => uplinkRadioLabelRu(radio) + ": " + error.message,
        );
        statusMsg += ". Частичное сканирование — " + failParts.join("; ");
      }
      setScanStatus("success", statusMsg);
    } else if (radioFailures.length > 0) {
      const e = radioFailures[0].error;
      const errStatus = e.status;
      const errCode = e.code || "";
      if (errStatus === 422 && errCode === "wifi.live_connection_incomplete") {
        setScanStatus(
          "incomplete",
          "Недостаточно параметров подключения для live-сканирования. "
            + "Сначала выполните шаг 1 или введите SSID вручную.",
        );
      } else if (errStatus === 503) {
        setScanStatus(
          "incomplete",
          "Live-сканирование недоступно: " + e.message,
        );
      } else {
        setScanStatus("failed", "Ошибка сканирования: " + e.message);
      }
    } else {
      setScanStatus(
        "empty",
        "Сети не найдены. Попробуйте ещё раз или введите SSID вручную.",
      );
    }
    scanBtn.disabled = false;
  }

  async function runEnroll() {
    if (uplinkScanState.selected && uplinkScanState.selected.wpa_mode === "open") {
      toast("Открытая сеть: сохранение пароля не требуется (подключение без пароля не поддержано)");
      return;
    }
    const rid = await resolveActiveRouterId();
    const enrollValue = enrollPasswordEl && enrollPasswordEl.value ? enrollPasswordEl.value : "";
    if (!rid) {
      toast("Сначала сохраните роутер на шаге 1 (router_id)");
      return;
    }
    if (!enrollValue) {
      toast("Введите пароль Wi‑Fi сети");
      return;
    }
    enrollBtn.disabled = true;
    try {
      const { data } = await apiFetch(
        "/routers/" + encodeURIComponent(rid) + "/credentials",
        {
          method: "PUT",
          body: { kind: "WifiWanPsk", secret: enrollValue },
          idempotencyKey: uuid(),
        },
      );
      if (enrollPasswordEl) enrollPasswordEl.value = "";
      const credEl = section.querySelector("#simple-uplink-credential-ref");
      if (credEl && data.credential_ref_id) credEl.value = data.credential_ref_id;
      toast("Пароль сохранён: " + (data.credential_ref_id || "ok"));
    } catch (e) {
      if (enrollPasswordEl) enrollPasswordEl.value = "";
      toast("Ошибка сохранения пароля: " + e.message);
    } finally {
      enrollBtn.disabled = false;
    }
  }

  function readBasePayload() {
    const ssidEl = section.querySelector("#simple-uplink-ssid");
    const bandEl = section.querySelector("#simple-uplink-band");
    const credEl = section.querySelector("#simple-uplink-credential-ref");
    const payload = {
      mode: "WifiWan",
      ssid: ssidEl && ssidEl.value ? ssidEl.value.trim() : "",
      band: bandEl && bandEl.value ? bandEl.value : "BAND_2_4GHZ",
      credential_ref_id: credEl && credEl.value ? credEl.value.trim() : "",
      auth_mode: "wpa2_psk",
      compensate_on_failure: true,
      idempotent: true,
    };
    const live = resolveSimpleLiveConnectionParams();
    if (live) Object.assign(payload, live);
    return payload;
  }
  function readPreviewPayload() {
    return readBasePayload();
  }
  function readPayload(includeConfirm) {
    const payload = readBasePayload();
    if (includeConfirm) {
      const confirmEl = section.querySelector("#simple-uplink-confirm");
      payload.confirm_live_apply = !!(confirmEl && confirmEl.checked);
    }
    return payload;
  }
  function renderPreview(data) {
    renderStationApplyPlanSummary(data, previewBox);
  }
  function renderApplyResult(data) {
    renderApplyResultWithVerdict(null, resultBox, data);
  }

  ["#simple-uplink-ssid", "#simple-uplink-band", "#simple-uplink-credential-ref"].forEach(
    (sel) => {
      const manualEl = section.querySelector(sel);
      if (!manualEl) return;
      manualEl.addEventListener("input", enterManualOverride);
      manualEl.addEventListener("change", enterManualOverride);
    },
  );

  return {
    section,
    form,
    manualForm,
    scanBtn,
    enrollBtn,
    previewBtn,
    applyBtn,
    previewBox,
    resultBox,
    readPreviewPayload,
    readPayload,
    renderPreview,
    renderApplyResult,
    runScan,
    runEnroll,
    selectNetwork,
    enterManualOverride,
    setRouterId,
    getRouterId,
    readSurveyBodyForRadio,
  };
}

function buildSimpleVpnStepSurface() {
  const section = el("section", "simple-step simple-step-vpn panel");
  section.setAttribute("data-testid", "simple-step-vpn");
  append(section, text(el("h2", "simple-step-title"), "Шаг 4 — VPN"));
  append(
    section,
    text(
      el("p", "simple-step-lead"),
      "Выберите сохранённый профиль или импортируйте конфигурацию в каталог. "
        + "Туннель может быть «healthy», но маршрутизация трафика через VPN — отдельная и неподтверждённая возможность.",
    ),
  );
  append(
    section,
    text(
      el("p", "field-hint simple-vpn-traffic-honesty"),
      "Address not configured; kill-switch отклонён backend. "
        + "tunnel_healthy ≠ egress через VPN — кнопок «маршрутизировать весь трафик» или kill-switch здесь нет.",
    ),
  );
  const importUi = buildVpnImportFormSurface();
  importUi.panel.classList.add("simple-vpn-import-panel");
  const importDetails = el("details", "simple-vpn-import-details");
  importDetails.setAttribute("data-testid", "simple-vpn-import-details");
  const importSummary = el("summary", "simple-vpn-import-summary");
  text(importSummary, "Импорт конфигурации в каталог");
  importDetails.appendChild(importSummary);
  importDetails.appendChild(importUi.panel);
  append(section, importDetails);
  return { section, importUi, importDetails };
}

function buildSimpleGuestWifiStepSurface() {
  const section = el("section", "simple-step simple-step-guest-wifi panel");
  section.setAttribute("data-testid", "simple-step-guest-wifi");
  append(section, text(el("h2", "simple-step-title"), "Шаг 5 — Гостевая Wi‑Fi"));
  append(
    section,
    text(
      el("p", "simple-step-lead"),
      "Задайте имя гостевой сети и ссылку на PSK в vault. Изоляция гостей и captive portal "
        + "в этой сборке недоступны (422).",
    ),
  );
  append(
    section,
    text(
      el("p", "field-hint simple-guest-isolation-honesty"),
      HONESTY_WIFI_GUEST_ISOLATION + " Применение отправляет guest_isolation=false.",
    ),
  );
  append(
    section,
    text(
      el("p", "field-hint mono simple-guest-ap-caption"),
      "Test AP (AccessPoint3–6) — lab/test AP, не production Guest portal.",
    ),
  );
  const form = el("form", "form-grid simple-guest-wifi-form");
  appendFormField(form, "ssid", "Имя сети (SSID)", "text", fieldTooltipOpts("wifi_ap", "ssid", {
    id: "simple-guest-ssid",
    testId: "simple-guest-ssid",
    placeholder: "Guest-Lab",
  }));
  appendFormField(form, "credential_ref_id", "Пароль (credential_ref_id)", "text", fieldTooltipOpts("wifi_ap", "credential_ref_id", {
    id: "simple-guest-psk-ref",
    testId: "simple-guest-psk-ref",
    placeholder: "credref:…",
  }));
  appendFormCheckbox(form, "confirm_live_apply", "Подтверждаю live apply на test AP", fieldTooltipOpts("wifi_ap", "confirm_live_apply", {
    id: "simple-guest-confirm",
    testId: "simple-guest-confirm",
  }));
  const resultPanel = el("div", "simple-guest-result panel-sub");
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, resultBox);
  const applyBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "simple-guest-apply",
  });
  text(applyBtn, "Применить гостевую Wi‑Fi (test AP)");
  append(section, form, applyBtn, resultPanel);
  function readPayload(includeConfirm) {
    const ssidEl = form.querySelector("#simple-guest-ssid");
    const credEl = form.querySelector("#simple-guest-psk-ref");
    const confirmEl = form.querySelector("#simple-guest-confirm");
    const payload = {
      ssid: ssidEl && ssidEl.value ? ssidEl.value.trim() : "",
      credential_ref_id: credEl && credEl.value ? credEl.value.trim() : "",
      band: "BAND_2_4GHZ",
      wpa_mode: "WPA2",
      ap_id: "WifiMaster0/AccessPoint3",
      enabled: true,
      guest_isolation: false,
      captive_portal: "Disabled",
      compensate_on_failure: true,
      idempotent: true,
    };
    if (includeConfirm) {
      payload.confirm_live_apply = !!(confirmEl && confirmEl.checked);
    }
    return payload;
  }
  function renderResult(data) {
    renderApplyResultWithVerdict(null, resultBox, data);
  }
  return { section, form, applyBtn, readPayload, renderResult, resultBox };
}

function buildSimpleDomainStepSurface() {
  const section = el("section", "simple-step simple-step-domain panel");
  section.setAttribute("data-testid", "simple-domain-step");
  append(section, text(el("h2", "simple-step-title"), "Шаг 6 — Внешнее имя (домен)"));
  append(
    section,
    text(
      el("p", "simple-step-lead"),
      "Публикация внешнего имени требует облачного сервиса производителя и явного "
        + "разрешения владельца учётной записи. В этой сборке доступны только "
        + "чтение статуса и предпросмотр команд — без отправки в облако.",
    ),
  );
  append(
    section,
    text(
      el("p", "field-hint simple-domain-cloud-honesty"),
      "Облачная регистрация имени (CrazeDNS/KeenDNS) — внешняя операция T4; "
        + "требуется Human Gate и подтверждение оператора перед любой записью.",
    ),
  );
  const statusPanel = el("div", "simple-domain-status panel-sub");
  statusPanel.setAttribute("data-testid", "simple-domain-status");
  const statusBox = el("pre", "mono simple-domain-status-box");
  text(statusBox, "Статус: загрузка…");
  append(statusPanel, statusBox);
  append(section, statusPanel);

  const form = el("form", "form-grid simple-domain-preview-form");
  appendFormField(form, "name", "Имя", "text", {
    id: "simple-domain-name",
    testId: "simple-domain-name",
    placeholder: "my-router",
  });
  appendFormField(form, "domain", "Домен", "text", {
    id: "simple-domain-domain",
    testId: "simple-domain-domain",
    placeholder: "keenetic.link",
  });
  const modeField = el("div", "form-field");
  const modeLabel = el("label");
  modeLabel.setAttribute("for", "simple-domain-mode");
  text(modeLabel, "Режим доступа");
  const modeSelect = el("select", "", { id: "simple-domain-mode", "data-testid": "simple-domain-mode" });
  ["auto", "cloud", "direct"].forEach((value) => {
    const opt = el("option");
    opt.value = value;
    text(opt, value);
    modeSelect.appendChild(opt);
  });
  append(modeField, modeLabel, modeSelect);
  append(form, modeField);

  const previewBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "simple-domain-preview",
  });
  text(previewBtn, "Предпросмотр");
  const resultPanel = el("div", "simple-domain-preview-result panel-sub");
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, resultBox);
  append(section, form, previewBtn, resultPanel);

  function renderStatus(data) {
    if (!data) {
      statusBox.textContent = "Статус: неизвестен (ошибка запроса)";
      return;
    }
    const lines = [
      "feature_availability: " + (data.feature_availability || "unknown"),
      "name_reservation: " + (data.name_reservation || "unknown"),
      "access_mode: " + (data.access_mode || "unknown"),
    ];
    if (Array.isArray(data.notes) && data.notes.length) {
      lines.push("", "notes:");
      data.notes.forEach((note) => lines.push("  - " + note));
    }
    statusBox.textContent = lines.join("\n");
  }

  function readPreviewPayload() {
    const nameEl = form.querySelector("#simple-domain-name");
    const domainEl = form.querySelector("#simple-domain-domain");
    const modeEl = form.querySelector("#simple-domain-mode");
    return {
      intent_kind: "book",
      name: nameEl && nameEl.value ? nameEl.value.trim() : "",
      domain: domainEl && domainEl.value ? domainEl.value.trim() : "",
      mode: modeEl && modeEl.value ? modeEl.value : "auto",
    };
  }

  function renderPreview(data) {
    resultBox.textContent = JSON.stringify(data, null, 2);
  }

  async function fetchStatus() {
    try {
      const { data } = await apiFetch("/keendns/status", { method: "POST", body: {} });
      renderStatus(data);
    } catch (_err) {
      renderStatus(null);
    }
  }

  return {
    section,
    form,
    previewBtn,
    statusBox,
    resultBox,
    renderStatus,
    readPreviewPayload,
    renderPreview,
    fetchStatus,
  };
}

const SIMPLE_WIZARD_STEP_COUNT = 7;
const SIMPLE_WIZARD_STEP_LABELS = [
  "Подключение",
  "Связь",
  "Интернет",
  "VPN",
  "Гостевая Wi‑Fi",
  "Домен",
  "Сети",
];

const simpleWizardSessionDone = {
  3: false,
  4: false,
  5: false,
  6: false,
  7: false,
};

/** @type {{ rootEl: HTMLElement, mounted: boolean, linkFacts: object|null, liveConnection: object|null, stepNodes: HTMLElement[], stepperItems: object[], backBtn: HTMLButtonElement, nextBtn: HTMLButtonElement, currentStep: number }|null} */
let simpleModeWizardState = null;

/**
 * Complete live connection params for simple wizard survey/apply, or null when incomplete.
 * Never returns partial fields — fake fixture scan requires zero connection fields.
 * @returns {{ host: string, username: string, router_credential_ref_id: string, ssh_host_key_sha256: string, router_id?: string }|null}
 */
function resolveSimpleLiveConnectionParams() {
  const lc =
    simpleModeWizardState && simpleModeWizardState.liveConnection
      ? simpleModeWizardState.liveConnection
      : null;
  if (!lc) return null;
  const host = lc.host ? String(lc.host).trim() : "";
  const username = lc.username ? String(lc.username).trim() : "";
  const routerCredRef = lc.router_credential_ref_id
    ? String(lc.router_credential_ref_id).trim()
    : "";
  let sshPin = lc.ssh_host_key_sha256 ? String(lc.ssh_host_key_sha256).trim() : "";
  if (!sshPin) {
    const pinEl = document.getElementById("simple-health-ssh-pin");
    if (pinEl && pinEl.value && pinEl.value.trim()) {
      sshPin = pinEl.value.trim();
    }
  }
  if (!host || !username || !routerCredRef || !sshPin) return null;
  const out = {
    host,
    username,
    router_credential_ref_id: routerCredRef,
    ssh_host_key_sha256: sshPin,
  };
  const routerId = lc.router_id ? String(lc.router_id).trim() : "";
  if (routerId) out.router_id = routerId;
  return out;
}

function persistSimpleWizardLiveConnectionFromDraft(formPayload, draftData, uplinkSurface) {
  if (!draftData || !draftData.router_id) return;
  if (uplinkSurface && typeof uplinkSurface.setRouterId === "function") {
    uplinkSurface.setRouterId(draftData.router_id);
  }
  if (!simpleModeWizardState) return;
  if (!simpleModeWizardState.linkFacts) {
    simpleModeWizardState.linkFacts = {};
  }
  simpleModeWizardState.linkFacts.router_id = draftData.router_id;
  simpleModeWizardState.linkFacts.has_enrolled_router = true;
  if (!simpleModeWizardState.liveConnection) {
    simpleModeWizardState.liveConnection = {};
  }
  const lc = simpleModeWizardState.liveConnection;
  if (formPayload && formPayload.host) lc.host = formPayload.host;
  if (formPayload && formPayload.username) lc.username = formPayload.username;
  lc.router_id = draftData.router_id;
  if (draftData.credential_ref_id) {
    lc.router_credential_ref_id = draftData.credential_ref_id;
  }
}

function setSimpleWizardLiveConnectionForTest(liveConnection) {
  if (!simpleModeWizardState) {
    simpleModeWizardState = {
      mounted: false,
      liveConnection: null,
      linkFacts: null,
    };
  }
  simpleModeWizardState.liveConnection = liveConnection
    ? Object.assign({}, liveConnection)
    : null;
}

function getSimpleWizardLiveConnectionForTest() {
  if (
    !simpleModeWizardState
    || !simpleModeWizardState.liveConnection
  ) {
    return null;
  }
  return Object.assign({}, simpleModeWizardState.liveConnection);
}

function parseSimpleWizardStep(params) {
  const raw = params && params[0] ? String(params[0]) : "";
  let stepNum = 1;
  if (raw) {
    const match = raw.match(/^step-(\d+)$/i) || raw.match(/^(\d+)$/);
    if (match) stepNum = parseInt(match[1], 10);
  }
  if (!Number.isFinite(stepNum) || stepNum < 1) stepNum = 1;
  if (stepNum > SIMPLE_WIZARD_STEP_COUNT) stepNum = SIMPLE_WIZARD_STEP_COUNT;
  return stepNum;
}

function clampSimpleWizardStep(step) {
  const n = Number.isFinite(step) ? step : 1;
  return Math.max(1, Math.min(SIMPLE_WIZARD_STEP_COUNT, n));
}

function isSimpleWizardStep1Done(linkFacts) {
  return deriveSimpleConnectStep1Ux(linkFacts || {}).mode === "connected";
}

function isSimpleWizardStepDone(stepNum, linkFacts) {
  if (stepNum === 1) return isSimpleWizardStep1Done(linkFacts);
  if (stepNum === 2) return deriveSimpleLinkState(linkFacts || {}).visual === "ok";
  return !!simpleWizardSessionDone[stepNum];
}

function markSimpleWizardStepDone(stepNum) {
  if (stepNum === 2) return;
  if (stepNum >= 3 && stepNum <= SIMPLE_WIZARD_STEP_COUNT) {
    simpleWizardSessionDone[stepNum] = true;
  }
}

function refreshSimpleWizardStepperIfMounted() {
  if (!simpleModeWizardState || !simpleModeWizardState.mounted) return;
  updateSimpleWizardStepper(
    simpleModeWizardState.stepperItems,
    simpleModeWizardState.currentStep,
    simpleModeWizardState.linkFacts,
  );
}

function buildSimpleWizardStepper(linkFacts) {
  const nav = el("nav", "simple-wizard-stepper", { "aria-label": "Шаги мастера" });
  const list = el("ol", "simple-wizard-stepper-list");
  const items = [];
  for (let i = 1; i <= SIMPLE_WIZARD_STEP_COUNT; i += 1) {
    const li = el("li", "simple-wizard-stepper-item");
    const btn = el("button", "simple-wizard-stepper-btn", {
      type: "button",
      "data-testid": "simple-wizard-step-" + i,
    });
    btn.setAttribute("data-step", String(i));
    const marker = el("span", "simple-wizard-stepper-marker");
    const label = el("span", "simple-wizard-stepper-label");
    text(label, SIMPLE_WIZARD_STEP_LABELS[i - 1]);
    append(btn, marker, label);
    li.appendChild(btn);
    list.appendChild(li);
    items.push({ li, btn, marker });
  }
  nav.appendChild(list);
  return { nav, items };
}

function updateSimpleWizardStepper(stepperItems, currentStep, linkFacts) {
  stepperItems.forEach((item, idx) => {
    const stepNum = idx + 1;
    const done = isSimpleWizardStepDone(stepNum, linkFacts);
    const isCurrent = stepNum === currentStep;
    item.li.classList.toggle("is-current", isCurrent);
    item.li.classList.toggle("is-done", done && !isCurrent);
    item.li.classList.toggle("is-pending", !done && !isCurrent);
    item.btn.setAttribute("aria-current", isCurrent ? "step" : "false");
    text(item.marker, done ? "✓" : "○");
  });
}

function setSimpleWizardStepVisibility(stepNodes, currentStep) {
  stepNodes.forEach((node, idx) => {
    const stepNum = idx + 1;
    const visible = stepNum === currentStep;
    node.hidden = !visible;
    node.setAttribute("aria-hidden", visible ? "false" : "true");
    node.classList.toggle("simple-wizard-step-active", visible);
    node.classList.toggle("simple-wizard-step-inactive", !visible);
  });
}

function updateSimpleWizardNav(backBtn, nextBtn, currentStep) {
  const atFirst = currentStep <= 1;
  const atLast = currentStep >= SIMPLE_WIZARD_STEP_COUNT;
  backBtn.hidden = atFirst;
  backBtn.disabled = atFirst;
  if (atLast) {
    text(nextBtn, "Готово");
  } else {
    text(nextBtn, "Далее");
  }
  nextBtn.hidden = false;
  nextBtn.disabled = false;
}

function applySimpleWizardStepUI(currentStep, state) {
  setSimpleWizardStepVisibility(state.stepNodes, currentStep);
  updateSimpleWizardStepper(state.stepperItems, currentStep, state.linkFacts);
  updateSimpleWizardNav(state.backBtn, state.nextBtn, currentStep);
  state.currentStep = currentStep;
}

function goSimpleWizardStep(step, options) {
  const opts = options || {};
  const target = clampSimpleWizardStep(step);
  if (opts.updateHash !== false) {
    setHash("simple", "step-" + target);
  }
  if (simpleModeWizardState && simpleModeWizardState.mounted) {
    applySimpleWizardStepUI(target, simpleModeWizardState);
  }
}

function wireSimpleWizardControls(viewRoot, surface, linkFacts) {
  surface.backBtn.addEventListener("click", () => {
    if (!simpleModeWizardState) return;
    goSimpleWizardStep(simpleModeWizardState.currentStep - 1);
  });
  surface.nextBtn.addEventListener("click", () => {
    if (!simpleModeWizardState) return;
    const cur = simpleModeWizardState.currentStep;
    if (cur >= SIMPLE_WIZARD_STEP_COUNT) return;
    goSimpleWizardStep(cur + 1);
  });
  surface.stepper.items.forEach((item, idx) => {
    item.btn.addEventListener("click", () => {
      goSimpleWizardStep(idx + 1);
    });
  });
  const prevLiveConnection =
    simpleModeWizardState && simpleModeWizardState.liveConnection
      ? Object.assign({}, simpleModeWizardState.liveConnection)
      : null;
  simpleModeWizardState = {
    rootEl: viewRoot,
    mounted: true,
    linkFacts,
    liveConnection: prevLiveConnection,
    stepNodes: surface.stepNodes,
    stepperItems: surface.stepper.items,
    backBtn: surface.backBtn,
    nextBtn: surface.nextBtn,
    currentStep: surface.currentStep,
  };
}

function initSimpleWizardFromSurface(viewRoot, surface, linkFacts) {
  wireSimpleWizardControls(viewRoot, surface, linkFacts || null);
}

function buildSimpleFamiliesStepSurface() {
  const details = el("details", "simple-step simple-step-families panel");
  details.setAttribute("data-testid", "simple-step-families");
  const summary = el("summary", "simple-step-summary");
  text(summary, "Дополнительно: сетевые семейства (VLAN/DHCP/DNS/firewall)");
  details.appendChild(summary);
  const body = el("div", "simple-step-families-body");
  append(
    body,
    text(
      el("p", "field-hint"),
      "Только предпросмотр — apply для VLAN/DHCP/DNS/firewall отсутствует. "
        + "Откройте эксперт → «Настройки роутера» для preview-панелей.",
    ),
  );
  const expertLink = el("a", "btn btn-secondary nav-link-expert-entry");
  expertLink.href = "#config";
  expertLink.setAttribute("data-testid", "simple-families-expert-link");
  text(expertLink, "Эксперт: preview семейств");
  expertLink.addEventListener("click", () => {
    applyUiMode("expert", { navigate: false, keepView: true });
  });
  append(body, expertLink);
  details.appendChild(body);
  return { details };
}

function buildSimpleModeSurface(options) {
  const opts = options || {};
  const linkFacts = opts.linkFacts || null;
  const currentStep = clampSimpleWizardStep(opts.initialStep != null ? opts.initialStep : 1);
  const root = el("div", "simple-mode-root");
  append(
    root,
    pageHeader(
      "Простой режим",
      "Пошаговая настройка человеческим языком — эксперт остаётся на один клик",
    ),
  );
  const wizardShell = el("div", "simple-wizard-shell");
  const stepper = buildSimpleWizardStepper(linkFacts);
  append(wizardShell, stepper.nav);
  const steps = el("div", "simple-mode-steps simple-wizard-steps");
  const connect = buildSimpleConnectStepSurface({ linkFacts });
  const link = buildSimpleLinkStepSurface(linkFacts);
  const uplink = buildSimpleWifiUplinkStepSurface({
    routerId: linkFacts && linkFacts.router_id ? String(linkFacts.router_id) : "",
  });
  const vpn = buildSimpleVpnStepSurface();
  const guest = buildSimpleGuestWifiStepSurface();
  const domain = buildSimpleDomainStepSurface();
  const families = buildSimpleFamiliesStepSurface();
  const stepNodes = [
    connect.section,
    link.section,
    uplink.section,
    vpn.section,
    guest.section,
    domain.section,
    families.details,
  ];
  stepNodes.forEach((node, idx) => {
    node.classList.add("simple-wizard-step-panel");
    const stepNum = idx + 1;
    const visible = stepNum === currentStep;
    node.hidden = !visible;
    node.setAttribute("aria-hidden", visible ? "false" : "true");
    node.classList.toggle("simple-wizard-step-active", visible);
    node.classList.toggle("simple-wizard-step-inactive", !visible);
  });
  append(steps, ...stepNodes);
  append(wizardShell, steps);
  const navRow = el("div", "simple-wizard-nav");
  const backBtn = el("button", "btn btn-secondary simple-wizard-back", {
    type: "button",
    "data-testid": "simple-wizard-back",
  });
  text(backBtn, "Назад");
  const nextBtn = el("button", "btn btn-primary simple-wizard-next", {
    type: "button",
    "data-testid": "simple-wizard-next",
  });
  text(nextBtn, "Далее");
  append(navRow, backBtn, nextBtn);
  append(wizardShell, navRow);
  append(root, wizardShell);
  updateSimpleWizardNav(backBtn, nextBtn, currentStep);
  updateSimpleWizardStepper(stepper.items, currentStep, linkFacts);
  const expertHint = el("p", "simple-mode-expert-hint field-hint");
  text(expertHint, "Нужны все технические поля? Переключитесь на «Эксперт» в верхней панели.");
  append(root, expertHint);
  return {
    root,
    wizardShell,
    stepper,
    stepNodes,
    currentStep,
    backBtn,
    nextBtn,
    connect,
    link,
    uplink,
    vpn,
    guest,
    domain,
    families,
    deriveLinkState: () => deriveSimpleLinkState(linkFacts),
  };
}

async function renderSimpleMode(root, renderOpts) {
  const opts = renderOpts || {};
  const hashParams = parseHash().params;
  const requestedStep = clampSimpleWizardStep(
    opts.step != null ? opts.step : parseSimpleWizardStep(hashParams),
  );
  const forceRemount = opts.forceRemount === true || opts.healthProbeOverrides != null;
  if (
    !forceRemount
    && simpleModeWizardState
    && simpleModeWizardState.rootEl === root
    && simpleModeWizardState.mounted
    && root.querySelector(".simple-wizard-shell")
  ) {
    if (requestedStep !== simpleModeWizardState.currentStep) {
      goSimpleWizardStep(requestedStep, { updateHash: false });
    }
    return;
  }

  renderSkeleton(root);
  await loadFieldManifest();
  let linkFacts = null;
  try {
    linkFacts = await fetchSimpleLinkFacts(opts.healthProbeOverrides || null);
  } catch (_err) {
    linkFacts = { health_unavailable: true };
  }
  clear(root);
  const surface = buildSimpleModeSurface({ linkFacts, initialStep: requestedStep });
  append(root, surface.root);
  wireSimpleWizardControls(root, surface, linkFacts);

  surface.connect.autoDetectBtn.addEventListener("click", async () => {
    clear(surface.connect.errBox);
    const autoDetectLabel = surface.connect.autoDetectBtn.textContent;
    surface.connect.autoDetectBtn.disabled = true;
    surface.connect.autoDetectBtn.textContent = "Автообнаружение…";
    try {
      const discoveryBody = surface.connect.readDiscoveryBody();
      const { data } = await apiFetch("/lab/router-discovery", {
        method: "POST",
        body: discoveryBody,
      });
      handleSimpleDiscoveryCandidates(surface.connect, data.candidates || []);
      appendSimpleDiscoveryDegradedWarning(surface.connect.errBox, data);
    } catch (e) {
      append(surface.connect.errBox, text(el("p"), "Ошибка автообнаружения: " + e.message));
    } finally {
      surface.connect.autoDetectBtn.disabled = false;
      surface.connect.autoDetectBtn.textContent = autoDetectLabel;
    }
  });

  surface.connect.form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    clear(surface.connect.errBox);
    const payload = surface.connect.readPayload();
    if (!payload.host || !payload.username || !payload.secret) {
      append(surface.connect.errBox, text(el("p"), "Укажите адрес, имя пользователя и пароль."));
      return;
    }
    surface.connect.submit.disabled = true;
    try {
      const body = {
        host: payload.host,
        username: payload.username,
        secret: payload.secret,
        allow_insecure_http: !!payload.allow_insecure_http,
      };
      if (payload.display_name) body.display_name = payload.display_name;
      if (payload.port) body.port = parseInt(payload.port, 10);
      const { data } = await apiFetch("/lab/wizard-draft-router", {
        method: "POST",
        body,
        idempotencyKey: uuid(),
      });
      surface.connect.clearSecret();
      persistSimpleWizardLiveConnectionFromDraft(payload, data, surface.uplink);
      toast(
        "Черновик сохранён: router_id="
          + (data.router_id || "?")
          + ", credential_ref_id="
          + (data.credential_ref_id || "?"),
      );
    } catch (e) {
      surface.connect.clearSecret();
      append(surface.connect.errBox, text(el("p"), "Ошибка: " + e.message));
    } finally {
      surface.connect.submit.disabled = false;
    }
  });

  surface.link.refreshBtn.addEventListener("click", () => {
    const healthProbeOverrides = surface.link.readHealthProbeBody();
    renderSimpleMode(root, { healthProbeOverrides, step: simpleModeWizardState ? simpleModeWizardState.currentStep : 2 });
  });

  surface.uplink.scanBtn.addEventListener("click", () => {
    surface.uplink.runScan();
  });
  surface.uplink.enrollBtn.addEventListener("click", () => {
    surface.uplink.runEnroll();
  });

  surface.uplink.previewBtn.addEventListener("click", async () => {
    const payload = surface.uplink.readPreviewPayload();
    if (!payload.ssid || !payload.credential_ref_id) {
      toast("Укажите SSID и credential_ref");
      return;
    }
    try {
      const { data } = await apiFetch("/wifi/station/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      surface.uplink.renderPreview(data);
    } catch (e) {
      toast("Предпросмотр ошибка: " + e.message);
    }
  });

  surface.uplink.applyBtn.addEventListener("click", async () => {
    const payload = surface.uplink.readPayload(true);
    if (!payload.confirm_live_apply) {
      toast("Требуется confirm для live apply");
      return;
    }
    if (!payload.ssid || !payload.credential_ref_id) {
      toast("Укажите SSID и credential_ref");
      return;
    }
    try {
      const { data } = await apiFetch("/wifi/station/apply", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      surface.uplink.renderApplyResult(data);
      if (data && data.overall === "applied") {
        markSimpleWizardStepDone(3);
        refreshSimpleWizardStepperIfMounted();
      }
    } catch (e) {
      toast("Apply ошибка: " + e.message);
    }
  });

  surface.guest.applyBtn.addEventListener("click", async () => {
    const payload = surface.guest.readPayload(true);
    if (!payload.confirm_live_apply) {
      toast("Требуется confirm для live apply");
      return;
    }
    if (!payload.ssid || !payload.credential_ref_id) {
      toast("Укажите SSID и credential_ref_id");
      return;
    }
    try {
      const { data } = await apiFetch("/wifi/apply", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      surface.guest.renderResult(data);
      APPLY_TOAST_PATHS["P-wifi-apply"].toastFromResponse(data);
      if (
        data
        && data.overall === "applied"
        && data.on_air_verification_status === "on_air_verified"
      ) {
        markSimpleWizardStepDone(5);
        refreshSimpleWizardStepperIfMounted();
      }
    } catch (e) {
      toast("Apply ошибка: " + e.message);
    }
  });

  surface.domain.fetchStatus();
  surface.domain.previewBtn.addEventListener("click", async () => {
    const payload = surface.domain.readPreviewPayload();
    if (!payload.name || !payload.domain) {
      toast("Укажите имя и домен");
      return;
    }
    try {
      const { data } = await apiFetch("/keendns/preview", {
        method: "POST",
        body: payload,
      });
      surface.domain.renderPreview(data);
      const previewStatus =
        data && data.verification_status != null ? String(data.verification_status) : "unknown";
      toast("Предпросмотр: " + previewStatus);
      if (data && data.verification_status === "documentation_sourced_unconfirmed") {
        markSimpleWizardStepDone(6);
        refreshSimpleWizardStepperIfMounted();
      }
    } catch (e) {
      toast("Предпросмотр ошибка: " + e.message);
    }
  });

  const origVpnImport = surface.vpn.importUi.runImport;
  surface.vpn.importUi.runImport = async function wrappedSimpleVpnImport() {
    const data = await origVpnImport();
    if (data && data.profile_id) {
      markSimpleWizardStepDone(4);
      refreshSimpleWizardStepperIfMounted();
    }
  };
}

/** @type {((path: string, options: object) => Promise<{data: *, headers?: *, status?: number}>)|null} */
let apiFetchTestStub = null;

function setApiFetchStubForTest(fn) {
  apiFetchTestStub = fn || null;
}

function resetToastCaptureForTest() {
  if (typeof globalThis !== "undefined") {
    globalThis.__ROUTER_CONTROL_TOAST_CAPTURE__ = [];
  }
}

function getCapturedToastsForTest() {
  if (typeof globalThis !== "undefined" && Array.isArray(globalThis.__ROUTER_CONTROL_TOAST_CAPTURE__)) {
    return globalThis.__ROUTER_CONTROL_TOAST_CAPTURE__.slice();
  }
  return [];
}

async function apiFetch(path, options) {
  if (apiFetchTestStub) {
    return apiFetchTestStub(path, options);
  }
  const opts = options || {};
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  if (activeNavAbort) activeNavAbort.abort();
  activeNavAbort = controller;
  const headers = Object.assign(
    { Accept: "application/json" },
    opts.headers || {},
  );
  if (opts.body != null) {
    headers["Content-Type"] = "application/json";
  }
  if (opts.idempotencyKey) headers["Idempotency-Key"] = opts.idempotencyKey;
  if (opts.ifMatch) headers["If-Match"] = opts.ifMatch;
  if (opts.preferAsync) headers.Prefer = "respond-async";
  try {
    const resp = await fetch(API + path, {
      method: opts.method || "GET",
      credentials: "same-origin",
      headers,
      body: opts.body != null ? JSON.stringify(opts.body) : undefined,
      signal: controller.signal,
    });
    const reqId = resp.headers.get("X-Request-Id") || "";
    const corrId = resp.headers.get("X-Correlation-Id") || "";
    let data = null;
    const ct = resp.headers.get("Content-Type") || "";
    if (ct.includes("application/json")) {
      data = await resp.json();
    }
    if (!resp.ok) {
      const errCode = data && data.error ? data.error.code : "http." + resp.status;
      const errMsg = data && data.error ? data.error.message : resp.statusText;
      const err = new Error(errMsg);
      err.code = errCode;
      err.status = resp.status;
      err.requestId = reqId;
      err.correlationId = corrId;
      if (data && data.error && data.error.details) {
        err.details = data.error.details;
      }
      throw err;
    }
    return { data, headers: resp.headers, status: resp.status };
  } finally {
    window.clearTimeout(timeout);
  }
}

async function pollOperation(operationId, onUpdate) {
  for (let i = 0; i < POLL_MAX_ATTEMPTS; i += 1) {
    const { data } = await apiFetch("/operations/" + encodeURIComponent(operationId));
    if (onUpdate) onUpdate(data);
    const terminal = ["Succeeded", "Failed", "Cancelled"];
    if (terminal.includes(data.aggregate_status)) return data;
    await new Promise((r) => window.setTimeout(r, POLL_INTERVAL_MS * (1 + Math.min(i, 5) * 0.2)));
  }
  throw new Error("Таймаут опроса операции");
}

function renderSkeleton(root) {
  clear(root);
  const box = el("div", "loading-state");
  append(box, el("div", "skeleton"), el("div", "skeleton"), el("div", "skeleton"));
  root.appendChild(box);
}

function renderError(root, err, retryFn) {
  clear(root);
  const box = el("div", "error-state");
  const msg = err.requestId
    ? err.message + " (req: " + err.requestId + ")"
    : err.message;
  append(box, text(el("p"), msg));
  if (retryFn) {
    const btn = el("button", "btn btn-secondary");
    text(btn, "Повторить");
    btn.addEventListener("click", retryFn);
    append(box, btn);
  }
  root.appendChild(box);
}

function pageHeader(title, subtitle) {
  const wrap = el("header", "page-header");
  append(wrap, text(el("h1", "page-title"), title));
  if (subtitle) append(wrap, text(el("p", "page-subtitle"), subtitle));
  return wrap;
}

function gateNotice(status) {
  const note = el("div", "gate-notice");
  text(note, gateBlockReason(status));
  return note;
}

async function loadStatus() {
  const { data } = await apiFetch("/status");
  sessionMemory.status = data;
  if (data.default_site_id) sessionMemory.siteId = data.default_site_id;
  const top = document.getElementById("topbar-status");
  if (top) {
    const label = data.feature_state + " · " + data.adapter_mode + " · DB " + data.database_state;
    text(top, label);
  }
  if (writeGatesBlocked(data)) {
    showBanner(gateBlockReason(data), "blocked");
  } else {
    hideBanner();
  }
  return data;
}

async function renderDashboard(root) {
  renderSkeleton(root);
  try {
    const status = await loadStatus();
    clear(root);
    append(root, pageHeader("Обзор", "Сводка прототипа Router Control (M1–M3)"));
    if (writeGatesBlocked(status)) append(root, gateNotice(status));

    const grid = el("div", "card-grid");
    const cards = [
      ["Состояние", status.feature_state, status.feature_state === "Ready" && !writeGatesBlocked(status) ? "is-ok" : "is-blocked"],
      ["Адаптер", status.adapter_mode, ""],
      ["База данных", status.database_state, status.database_state === "Ok" ? "is-ok" : "is-warn"],
      ["Worker", status.worker_state || "Unknown", status.worker_state === "Running" ? "is-ok" : ""],
      ["Роутеры", String((status.routers_summary && status.routers_summary.total) || 0), ""],
      ["Gate A", gateADisplay(status), ""],
    ];
    cards.forEach(([title, val, cls]) => {
      const card = el("article", "card");
      append(card, text(el("h2", "card-title"), title));
      append(card, text(el("p", "card-value " + cls), val));
      grid.appendChild(card);
    });
    append(root, grid);

    const actions = el("div", "panel");
    append(actions, text(el("h2", "panel-title"), "Быстрые действия"));
    const row = el("div", "btn-row");
    [
      ["Роутеры", "routers"],
      ["Комиссионирование", "commissioning"],
      ["Пресеты", "presets"],
      ["VPN", "vpn"],
    ].forEach(([label, view]) => {
      const a = el("a", "btn btn-primary");
      a.href = "#" + view;
      text(a, label);
      row.appendChild(a);
    });
    const refresh = el("button", "btn btn-secondary");
    text(refresh, "Обновить статус");
    refresh.addEventListener("click", () => renderDashboard(root));
    row.appendChild(refresh);
    append(actions, row);
    append(root, actions);

    const recent = el("div", "panel");
    append(recent, text(el("h2", "panel-title"), "Недавние операции (сессия)"));
    if (sessionMemory.recentOps.length === 0) {
      append(recent, text(el("p", "empty-state"), "Нет операций в текущей сессии"));
    } else {
      const ul = el("ul");
      sessionMemory.recentOps.forEach((opId) => {
        const li = el("li");
        const link = el("a");
        link.href = "#operations/" + opId;
        text(link, opId);
        li.appendChild(link);
        ul.appendChild(li);
      });
      append(recent, ul);
    }
    append(root, recent);
  } catch (err) {
    renderError(root, err, () => renderDashboard(root));
  }
}

async function renderRouters(root) {
  renderSkeleton(root);
  try {
    const status = await loadStatus();
    const { data } = await apiFetch("/routers");
    clear(root);
    append(root, pageHeader("Роутеры", "Список зарегистрированных роутеров"));
    if (writeGatesBlocked(status)) append(root, gateNotice(status));

    const panel = el("div", "panel");
    append(panel, text(el("h2", "panel-title"), "Зачисление (offline/fake)"));
    const form = el("form", "form-grid");
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const name = form.querySelector('[name="display_name"]').value;
      const vendor = form.querySelector('[name="vendor"]').value;
      const model = form.querySelector('[name="model"]').value;
      const host = form.querySelector('[name="host"]').value;
      const credentialRefId = form.querySelector('[name="credential_ref_id"]').value.trim();
      if (!credentialRefId) {
        toast("Укажите CredentialRef ID (без пароля в UI)");
        return;
      }
      try {
        const { data: enroll } = await apiFetch("/routers", {
          method: "POST",
          idempotencyKey: uuid(),
          body: {
            display_name: name,
            vendor,
            model,
            endpoint: { kind: "management_https", host, port: 443 },
            credential_ref_id: credentialRefId,
          },
        });
        if (enroll.operation_id) rememberOp(enroll.operation_id);
        if (enroll.job_id) rememberJob(enroll.job_id);
        toast("Зачисление принято: " + enroll.status);
        renderRouters(root);
      } catch (e) {
        toast("Ошибка: " + e.message);
      }
    });
    [
      ["display_name", "Имя", "Lab Router"],
      ["vendor", "Vendor", "FakeVendor"],
      ["model", "Model", "Fake-1"],
      ["host", "Host", "127.0.0.1"],
    ].forEach(([name, label, placeholder]) => {
      appendFormField(form, name, label, "text", {
        id: "r-" + name,
        placeholder,
        required: true,
      });
    });
    appendFormField(form, "credential_ref_id", "CredentialRef ID", "text", {
      id: "r-credential_ref_id",
      placeholder: "credref:… (без пароля)",
      required: true,
    });
    const submit = el("button", "btn btn-primary", { type: "submit" });
    text(submit, "Зачислить");
    append(form, submit);
    append(panel, form);
    append(root, panel);

    const listPanel = el("div", "panel");
    append(listPanel, text(el("h2", "panel-title"), "Список"));
    const items = data.items || [];
    if (items.length === 0) {
      append(listPanel, text(el("p", "empty-state"), "Роутеры не найдены"));
    } else {
      const table = el("table", "data-table");
      const thead = el("thead");
      const hr = el("tr");
      ["ID", "Имя", "Lifecycle", "Certification", "Действия"].forEach((h) => {
        hr.appendChild(text(el("th"), h));
      });
      thead.appendChild(hr);
      const tbody = el("tbody");
      items.forEach((row) => {
        const tr = el("tr");
        append(tr, text(el("td", "mono"), row.router_id));
        append(tr, text(el("td"), row.display_name));
        append(tr, text(el("td"), row.lifecycle_status));
        append(tr, text(el("td"), row.certification_status));
        const td = el("td");
        const pf = el("button", "btn btn-secondary");
        text(pf, "Preflight");
        pf.addEventListener("click", async () => {
          try {
            const { data: pfData } = await apiFetch("/routers/" + encodeURIComponent(row.router_id) + "/preflight", {
              method: "POST",
              idempotencyKey: uuid(),
            });
            rememberOp(pfData.operation_id);
            rememberJob(pfData.job_id);
            toast("Preflight: " + pfData.status);
          } catch (e) {
            toast("Preflight ошибка: " + e.message);
          }
        });
        td.appendChild(pf);
        tr.appendChild(td);
        tbody.appendChild(tr);
      });
      append(table, thead, tbody);
      const wrap = el("div", "table-wrap");
      wrap.appendChild(table);
      append(listPanel, wrap);
    }
    append(root, listPanel);
  } catch (err) {
    renderError(root, err, () => renderRouters(root));
  }
}

async function renderCommissioning(root, runId) {
  renderSkeleton(root);
  try {
    const status = await loadStatus();
    const siteId = sessionMemory.siteId || status.default_site_id;
    clear(root);
    append(root, pageHeader("Комиссионирование", "Read-only MVP — без live-write/Apply"));
    append(root, gateNotice(status));

    const createPanel = el("div", "panel");
    append(createPanel, text(el("h2", "panel-title"), "Создать run"));
    const routersResp = await apiFetch("/routers");
    const first = (routersResp.data.items || [])[0];
    const defaultRouterId = first ? first.router_id : "";
    const createUi = buildCommissioningCreateFormSurface(defaultRouterId, status.adapter_mode);
    const form = createUi.form;
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const body = readCommissioningCreatePayloadFromDom(status.adapter_mode);
      if (!body.router_id) {
        toast("Укажите router_id");
        return;
      }
      try {
        const { data } = await apiFetch("/sites/" + encodeURIComponent(siteId) + "/commissioning-runs", {
          method: "POST",
          idempotencyKey: uuid(),
          body,
        });
        toast("Run создан: " + data.run_id);
        setHash("commissioning", data.run_id);
        renderCommissioning(root, data.run_id);
      } catch (e) {
        toast("Ошибка: " + e.message);
      }
    });
    const createBtn = el("button", "btn btn-primary", { type: "submit" });
    text(createBtn, "Создать run");
    append(form, createBtn);
    append(createPanel, form);
    append(root, createPanel);

    const listResp = await apiFetch("/sites/" + encodeURIComponent(siteId) + "/commissioning-runs");
    const listPanel = el("div", "panel");
    append(listPanel, text(el("h2", "panel-title"), "Runs для site " + siteId));
    const runs = listResp.data.items || [];
    if (runs.length === 0) {
      append(listPanel, text(el("p", "empty-state"), "Нет commissioning runs"));
    } else {
      const ul = el("ul");
      runs.forEach((run) => {
        const li = el("li");
        const link = el("a");
        link.href = "#commissioning/" + run.run_id;
        text(link, run.run_id + " — " + run.status);
        li.appendChild(link);
        ul.appendChild(li);
      });
      append(listPanel, ul);
    }
    append(root, listPanel);

    if (runId) {
      const detail = el("div", "panel");
      append(detail, text(el("h2", "panel-title"), "Run " + runId));
      const { data: run } = await apiFetch("/commissioning-runs/" + encodeURIComponent(runId));
      append(detail, text(el("p"), "Статус: " + run.status + " · Gate: " + (run.gate_label || "RO")));
      const btnRow = el("div", "btn-row");
      const assessBtn = el("button", "btn btn-primary");
      text(assessBtn, "Assess (read-only)");
      assessBtn.addEventListener("click", async () => {
        try {
          const asyncEl = document.getElementById("commissioning-assess-async");
          const asyncQuery = asyncEl && asyncEl.checked ? "?execution=async" : "";
          const { data: result, status: httpStatus } = await apiFetch(
            "/commissioning-runs/" + encodeURIComponent(runId) + "/assess" + asyncQuery,
            {
              method: "POST",
              idempotencyKey: uuid(),
              ifMatch: run.etag,
            },
          );
          if (httpStatus === 202) {
            toast("Assess queued (async worker — read-only, not device apply)");
          } else {
            toast("Assess выполнен (read-only, not device apply)");
          }
          if (result.run) append(detail, text(el("p"), "Новый статус: " + result.run.status));
        } catch (e) {
          toast("Assess ошибка: " + e.message);
        }
      });
      const cancelBtn = el("button", "btn btn-secondary");
      text(cancelBtn, "Отменить");
      cancelBtn.addEventListener("click", async () => {
        try {
          await apiFetch("/commissioning-runs/" + encodeURIComponent(runId) + "/cancel", {
            method: "POST",
            idempotencyKey: uuid(),
            ifMatch: run.etag,
          });
          toast("Run отменён");
          renderCommissioning(root, runId);
        } catch (e) {
          toast("Cancel ошибка: " + e.message);
        }
      });
      const reportBtn = el("button", "btn btn-secondary");
      text(reportBtn, "Отчёт readiness");
      reportBtn.addEventListener("click", async () => {
        try {
          const { data: report } = await apiFetch("/commissioning-runs/" + encodeURIComponent(runId) + "/report");
          const pre = el("pre", "mono");
          text(pre, JSON.stringify(report, null, 2));
          append(detail, pre);
        } catch (e) {
          toast("Report ошибка: " + e.message);
        }
      });
      const readinessChecksBtn = el("button", "btn btn-secondary", {
        type: "button",
        "data-testid": "commissioning-readiness-checks-btn",
      });
      text(readinessChecksBtn, "Readiness checks (read)");
      readinessChecksBtn.addEventListener("click", async () => {
        try {
          const { data: checks } = await apiFetch(
            "/commissioning-runs/" + encodeURIComponent(runId) + "/readiness-checks",
          );
          const pre = el("pre", "mono commissioning-readiness-checks");
          text(pre, JSON.stringify(checks, null, 2));
          append(detail, pre);
          toast("Readiness checks loaded (read-only MVP)");
        } catch (e) {
          toast("Readiness checks ошибка: " + e.message);
        }
      });
      const applyBtn = el("button", "btn btn-primary");
      text(applyBtn, "Apply (заблокировано)");
      applyBtn.disabled = true;
      append(btnRow, assessBtn, cancelBtn, reportBtn, readinessChecksBtn, applyBtn);
      append(detail, btnRow);
      append(root, detail);
    }
  } catch (err) {
    renderError(root, err, () => renderCommissioning(root, runId));
  }
}

function buildPresetBootstrapDocument(name) {
  const docName = name || "Safe Default Booth";
  return {
    name: docName,
    uplink: { mode: "Ethernet" },
    local_order_url: "https://orders.booth.local/",
    router_owns_l3: true,
    rack_assets: [
      {
        role: "Router",
        display_name: "Event Router",
        recommendation: "sole L3/DHCP/DNS/firewall/AP owner",
      },
      {
        role: "Hub",
        display_name: "Production Hub",
        recommendation: "application/control only; not L3 owner",
      },
      {
        role: "Switch",
        display_name: "Managed L2 Switch",
        recommendation: "managed L2 with UPS recommended",
      },
      { role: "Printer", display_name: "Label Printer", recommendation: null },
    ],
    zones: [
      {
        zone_id: "Guest",
        vlan_id: 10,
        ipv4_cidr: "10.10.10.0/24",
        ipv6_posture: "Disabled",
        management_allowed: false,
        dhcp: {
          pool_start: "10.10.10.50",
          pool_end: "10.10.10.200",
          lease_seconds: 3600,
          reservations: [],
        },
        dns: { local_fqdn: "guest.booth.local", upstream_resolvers: [] },
        wifi: {
          ssid: "Guest",
          enabled: false,
          credential_ref_id: null,
          captive_portal: "Disabled",
          guest_isolation: true,
          wpa_mode: "WPA2",
          band: "BAND_2_4GHZ",
        },
        firewall: {
          rules: [
            { action: "Allow", destination_family: "OrderPage", ordinal: 0 },
            { action: "Allow", destination_family: "Dns", ordinal: 1 },
            { action: "Allow", destination_family: "Dhcp", ordinal: 2 },
            { action: "Deny", destination_family: "Management", ordinal: 3 },
            { action: "Deny", destination_family: "Internet", ordinal: 4 },
          ],
        },
      },
      {
        zone_id: "Promo",
        vlan_id: 20,
        ipv4_cidr: "10.10.20.0/24",
        ipv6_posture: "Disabled",
        management_allowed: false,
        dhcp: {
          pool_start: "10.10.20.50",
          pool_end: "10.10.20.200",
          lease_seconds: 3600,
          reservations: [],
        },
        dns: { local_fqdn: "promo.booth.local", upstream_resolvers: [] },
        wifi: {
          ssid: "Promo-Private",
          enabled: true,
          credential_ref_id: "credref:promo-wifi",
          captive_portal: "Disabled",
          guest_isolation: false,
          wpa_mode: "WPA2",
          band: "BAND_2_4GHZ",
        },
        firewall: {
          rules: [
            { action: "Deny", destination_family: "Management", ordinal: 0 },
            { action: "Allow", destination_family: "LocalZone", ordinal: 1 },
            { action: "Allow", destination_family: "Internet", ordinal: 2 },
          ],
        },
      },
      {
        zone_id: "Staff",
        vlan_id: 30,
        ipv4_cidr: "10.10.30.0/24",
        ipv6_posture: "Disabled",
        management_allowed: false,
        dhcp: {
          pool_start: "10.10.30.50",
          pool_end: "10.10.30.200",
          lease_seconds: 3600,
          reservations: [],
        },
        dns: { local_fqdn: "staff.booth.local", upstream_resolvers: [] },
        wifi: {
          ssid: "Staff-Private",
          enabled: true,
          credential_ref_id: "credref:staff-wifi",
          captive_portal: "Disabled",
          guest_isolation: false,
          wpa_mode: "WPA2",
          band: "BAND_2_4GHZ",
        },
        firewall: {
          rules: [
            { action: "Deny", destination_family: "Management", ordinal: 0 },
            { action: "Allow", destination_family: "LocalZone", ordinal: 1 },
            { action: "Allow", destination_family: "Internet", ordinal: 2 },
          ],
        },
      },
      {
        zone_id: "AdminServer",
        vlan_id: 40,
        ipv4_cidr: "10.10.40.0/24",
        ipv6_posture: "Disabled",
        management_allowed: true,
        dhcp: {
          pool_start: "10.10.40.50",
          pool_end: "10.10.40.200",
          lease_seconds: 3600,
          reservations: [],
        },
        dns: { local_fqdn: "admin.booth.local", upstream_resolvers: [] },
        wifi: null,
        firewall: {
          rules: [
            { action: "Allow", destination_family: "Management", ordinal: 0 },
            { action: "Allow", destination_family: "LocalZone", ordinal: 1 },
            { action: "Allow", destination_family: "Internet", ordinal: 2 },
          ],
        },
      },
    ],
  };
}

function buildPresetDocumentFromForm(form, existingDoc) {
  const base = existingDoc
    ? JSON.parse(JSON.stringify(existingDoc))
    : buildPresetBootstrapDocument();
  base.name = form.querySelector('[name="preset_name"]').value;
  base.router_owns_l3 = form.querySelector('[name="router_owns_l3"]').checked;
  base.local_order_url = form.querySelector('[name="local_order_url"]').value;
  const uplinkMode = form.querySelector('[name="uplink_mode"]').value;
  base.uplink = base.uplink || { mode: "Ethernet" };
  base.uplink.mode = uplinkMode;
  if (uplinkMode === "WifiWan") {
    base.uplink.ssid = form.querySelector('[name="uplink_ssid"]').value;
    base.uplink.band = form.querySelector('[name="uplink_band"]').value;
    base.uplink.credential_ref_id = form.querySelector('[name="uplink_cred_ref"]').value;
    const bssidEl = form.querySelector('[name="uplink_bssid"]');
    const bssidVal = bssidEl && bssidEl.value ? bssidEl.value.trim() : "";
    if (bssidVal) base.uplink.bssid = bssidVal;
    else delete base.uplink.bssid;
    const priorityEl = form.querySelector('[name="uplink_priority"]');
    if (priorityEl && priorityEl.value !== "") {
      base.uplink.priority = parseInt(priorityEl.value, 10);
    }
    base.uplink.captive_portal_client = form.querySelector('[name="uplink_captive_portal_client"]').checked;
  } else {
    delete base.uplink.ssid;
    delete base.uplink.band;
    delete base.uplink.credential_ref_id;
    delete base.uplink.bssid;
    delete base.uplink.priority;
    delete base.uplink.captive_portal_client;
  }
  const rackEditor = form._rackAssetsEditor;
  base.rack_assets = rackEditor
    ? rackEditor.readRows().map((row) => {
        const asset = { role: row.role, display_name: row.display_name };
        if (row.recommendation) asset.recommendation = row.recommendation;
        return asset;
      })
    : base.rack_assets || [];
  if (!base.zones) base.zones = [];
  PRESET_ZONE_IDS.forEach((zid) => {
    let zone = base.zones.find((z) => z.zone_id === zid);
    if (!zone) zone = { zone_id: zid };
    const prefix = "zone_" + zid + "_";
    zone.zone_id = zid;
    zone.vlan_id = parseInt(form.querySelector('[name="' + prefix + 'vlan"]').value, 10);
    zone.ipv4_cidr = form.querySelector('[name="' + prefix + 'cidr"]').value;
    zone.ipv6_posture = form.querySelector('[name="' + prefix + 'ipv6_posture"]').value;
    zone.management_allowed = form.querySelector('[name="' + prefix + 'management_allowed"]').checked;
    zone.dhcp = zone.dhcp || {};
    zone.dhcp.pool_start = form.querySelector('[name="' + prefix + 'dhcp_start"]').value;
    zone.dhcp.pool_end = form.querySelector('[name="' + prefix + 'dhcp_end"]').value;
    zone.dhcp.lease_seconds = parseInt(
      form.querySelector('[name="' + prefix + 'dhcp_lease"]').value,
      10,
    );
    const dhcpResEditor = form._zoneEditors && form._zoneEditors[zid] && form._zoneEditors[zid].dhcpReservations;
    zone.dhcp.reservations = dhcpResEditor ? readDhcpReservationsFromEditor(dhcpResEditor) : [];
    zone.dns = zone.dns || {};
    zone.dns.local_fqdn = form.querySelector('[name="' + prefix + 'dns_fqdn"]').value;
    const dnsResEditor = form._zoneEditors && form._zoneEditors[zid] && form._zoneEditors[zid].dnsUpstream;
    zone.dns.upstream_resolvers = dnsResEditor ? readStringListFromEditor(dnsResEditor) : [];
    const wifiEnabledEl = form.querySelector('[name="' + prefix + 'wifi_enabled"]');
    const hasWifi = zid !== "AdminServer";
    if (hasWifi && wifiEnabledEl) {
      zone.wifi = zone.wifi || {};
      zone.wifi.ssid = form.querySelector('[name="' + prefix + 'ssid"]').value;
      zone.wifi.enabled = wifiEnabledEl.checked;
      const credVal = form.querySelector('[name="' + prefix + 'cred_ref"]').value.trim();
      zone.wifi.credential_ref_id = credVal || null;
      zone.wifi.wpa_mode = form.querySelector('[name="' + prefix + 'wpa_mode"]').value;
      zone.wifi.band = form.querySelector('[name="' + prefix + 'wifi_band"]').value;
      zone.wifi.guest_isolation = form.querySelector('[name="' + prefix + 'guest_isolation"]').checked;
      zone.wifi.captive_portal = form.querySelector('[name="' + prefix + 'captive_portal"]').value;
    } else {
      zone.wifi = null;
    }
    const fwEditor = form._zoneEditors && form._zoneEditors[zid] && form._zoneEditors[zid].firewallRules;
    zone.firewall = {
      rules: fwEditor ? readFirewallRulesFromEditor(fwEditor) : [],
    };
    const existingIdx = base.zones.findIndex((z) => z.zone_id === zid);
    if (existingIdx >= 0) base.zones[existingIdx] = zone;
    else base.zones.push(zone);
  });
  return base;
}

function fillPresetForm(form, doc) {
  if (!doc) doc = buildPresetBootstrapDocument();
  const setVal = (name, val) => {
    const input = form.querySelector('[name="' + name + '"]');
    if (!input) return;
    const isCheckbox = input.type === "checkbox" || input.getAttribute("type") === "checkbox";
    if (isCheckbox) input.checked = !!val;
    else input.value = val == null ? "" : String(val);
  };
  setVal("preset_name", doc.name);
  setVal("router_owns_l3", doc.router_owns_l3);
  setVal("local_order_url", doc.local_order_url);
  if (doc.uplink) {
    setVal("uplink_mode", doc.uplink.mode || "Ethernet");
    setVal("uplink_ssid", doc.uplink.ssid);
    setVal("uplink_band", doc.uplink.band || "BAND_2_4GHZ");
    setVal("uplink_cred_ref", doc.uplink.credential_ref_id);
    setVal("uplink_bssid", doc.uplink.bssid);
    setVal("uplink_priority", doc.uplink.priority != null ? doc.uplink.priority : 100);
    setVal("uplink_captive_portal_client", doc.uplink.captive_portal_client);
  }
  if (form._rackAssetsEditor) {
    form._rackAssetsEditor.setRows(doc.rack_assets || []);
  }
  (doc.zones || []).forEach((zone) => {
    const zid = zone.zone_id;
    const prefix = "zone_" + zid + "_";
    setVal(prefix + "cidr", zone.ipv4_cidr);
    setVal(prefix + "vlan", zone.vlan_id);
    setVal(prefix + "ipv6_posture", zone.ipv6_posture || "Disabled");
    setVal(prefix + "management_allowed", zone.management_allowed);
    if (zone.dhcp) {
      setVal(prefix + "dhcp_start", zone.dhcp.pool_start);
      setVal(prefix + "dhcp_end", zone.dhcp.pool_end);
      setVal(prefix + "dhcp_lease", zone.dhcp.lease_seconds != null ? zone.dhcp.lease_seconds : 3600);
      const dhcpResEditor = form._zoneEditors && form._zoneEditors[zid] && form._zoneEditors[zid].dhcpReservations;
      if (dhcpResEditor) dhcpResEditor.setRows(zone.dhcp.reservations || []);
    }
    if (zone.dns) {
      setVal(prefix + "dns_fqdn", zone.dns.local_fqdn);
      const dnsResEditor = form._zoneEditors && form._zoneEditors[zid] && form._zoneEditors[zid].dnsUpstream;
      if (dnsResEditor) {
        dnsResEditor.setRows((zone.dns.upstream_resolvers || []).map((addr) => ({ address: addr })));
      }
    }
    if (zone.wifi) {
      setVal(prefix + "ssid", zone.wifi.ssid);
      setVal(prefix + "wifi_enabled", zone.wifi.enabled);
      setVal(prefix + "cred_ref", zone.wifi.credential_ref_id);
      setVal(prefix + "wpa_mode", zone.wifi.wpa_mode || "WPA2");
      setVal(prefix + "wifi_band", zone.wifi.band || "BAND_2_4GHZ");
      setVal(prefix + "guest_isolation", zone.wifi.guest_isolation);
      setVal(prefix + "captive_portal", zone.wifi.captive_portal || "Disabled");
    }
    const fwEditor = form._zoneEditors && form._zoneEditors[zid] && form._zoneEditors[zid].firewallRules;
    if (fwEditor && zone.firewall && zone.firewall.rules) {
      fwEditor.setRows(zone.firewall.rules);
    }
  });
}

function buildPresetEditorFormSurface(existingDoc) {
  const form = el("form", "form-grid config-preset-editor-form");
  form._zoneEditors = {};

  appendFormField(form, "preset_name", "Название", "text", {
    id: "preset-preset_name",
    testId: "preset-name",
    tooltip: "Имя пресета события (offline catalog).",
  });
  appendFormField(form, "local_order_url", "Order URL", "url", {
    id: "preset-local_order_url",
    testId: "preset-local-order-url",
    tooltip: "HTTPS URL локальной order page для Guest zone.",
  });
  appendFormSelect(form, "uplink_mode", "Uplink", UPLINK_MODE_OPTIONS, {
    id: "preset-uplink_mode",
    testId: "preset-uplink-mode",
    tooltip: "Режим uplink: Ethernet | WifiWan | LocalOnly | Lte.",
  });
  appendFormCheckbox(form, "router_owns_l3", "Router owns L3", {
    id: "preset-router_owns_l3",
    testId: "preset-router-owns-l3",
    checked: true,
    tooltip: "Роутер — единственный L3/DHCP/DNS owner.",
  });

  const docAdvanced = buildAdvancedSettingsBlock({
    testId: "preset-doc-advanced-settings",
    summaryText: "Дополнительные настройки документа",
  });
  append(docAdvanced.body, text(el("h3", "panel-subtitle"), "WifiWan uplink"));
  appendFormField(docAdvanced.body, "uplink_ssid", "Uplink SSID", "text", {
    id: "preset-uplink_ssid",
    testId: "preset-uplink-ssid",
    tooltip: "SSID для WifiWan — обязателен при mode=WifiWan.",
  });
  appendFormSelect(
    docAdvanced.body,
    "uplink_band",
    "Uplink band",
    [
      ["BAND_2_4GHZ", "2.4 GHz"],
      ["BAND_5GHZ", "5 GHz"],
    ],
    {
      id: "preset-uplink_band",
      testId: "preset-uplink-band",
      tooltip: "Диапазон Wi‑Fi uplink.",
    },
  );
  appendFormField(docAdvanced.body, "uplink_cred_ref", "Uplink credential_ref_id", "text", {
    id: "preset-uplink_cred_ref",
    testId: "preset-uplink-cred-ref",
    placeholder: "credref:…",
    tooltip: "Credential ref для WifiWan — plaintext PSK не вводится.",
  });
  appendFormField(docAdvanced.body, "uplink_bssid", "Uplink BSSID (optional)", "text", {
    id: "preset-uplink_bssid",
    testId: "preset-uplink-bssid",
    tooltip: "Опциональный BSSID для station join.",
  });
  appendFormField(docAdvanced.body, "uplink_priority", "Uplink priority", "number", {
    id: "preset-uplink_priority",
    testId: "preset-uplink-priority",
    placeholder: "100",
    min: "0",
    max: "65535",
    tooltip: "Приоритет uplink (default 100).",
  });
  appendFormCheckbox(docAdvanced.body, "uplink_captive_portal_client", "captive_portal_client", {
    id: "preset-uplink_captive_portal_client",
    testId: "preset-uplink-captive-portal-client",
    tooltip: "Флаг captive portal client для WifiWan.",
  });
  const rackEditor = buildCollectionEditor({
    testId: "preset-rack-assets",
    label: "rack_assets",
    addLabel: "Add rack asset",
    columns: [
      { key: "role", label: "Role", type: "select", options: RACK_ASSET_ROLE_OPTIONS },
      { key: "display_name", label: "Display name", type: "text" },
      { key: "recommendation", label: "Recommendation", type: "text", optional: true },
    ],
  });
  form._rackAssetsEditor = rackEditor;
  append(docAdvanced.body, rackEditor.container);
  form.appendChild(docAdvanced.details);

  PRESET_ZONE_IDS.forEach((zid) => {
    const section = el("fieldset", "panel config-preset-zone");
    section.setAttribute("data-testid", "preset-zone-" + zid);
    append(section, text(el("legend"), "Зона " + zid));
    const prefix = "zone_" + zid + "_";
    form._zoneEditors[zid] = {};

    appendFormField(section, prefix + "vlan", "VLAN id", "number", {
      id: "preset-" + prefix + "vlan",
      testId: "preset-" + zid + "-vlan",
      tooltip: "VLAN ID зоны.",
    });
    appendFormField(section, prefix + "cidr", "IPv4 CIDR", "text", {
      id: "preset-" + prefix + "cidr",
      testId: "preset-" + zid + "-cidr",
      tooltip: "Подсеть зоны (CIDR).",
    });
    if (zid !== "AdminServer") {
      appendFormField(section, prefix + "ssid", "Wi-Fi SSID", "text", {
        id: "preset-" + prefix + "ssid",
        testId: "preset-" + zid + "-ssid",
        tooltip: "SSID Wi‑Fi AP зоны.",
      });
      appendFormCheckbox(section, prefix + "wifi_enabled", "Wi-Fi enabled", {
        id: "preset-" + prefix + "wifi_enabled",
        testId: "preset-" + zid + "-wifi-enabled",
        tooltip: "Включить Wi‑Fi AP.",
      });
      appendFormField(section, prefix + "cred_ref", "CredentialRef (ID only)", "text", {
        id: "preset-" + prefix + "cred_ref",
        testId: "preset-" + zid + "-cred-ref",
        placeholder: "credref:…",
        tooltip: "Credential ref для WPA — plaintext PSK не вводится.",
      });
    }
    appendFormField(section, prefix + "dhcp_start", "DHCP pool start", "text", {
      id: "preset-" + prefix + "dhcp_start",
      testId: "preset-" + zid + "-dhcp-start",
      tooltip: "Начало DHCP pool.",
    });
    appendFormField(section, prefix + "dhcp_end", "DHCP pool end", "text", {
      id: "preset-" + prefix + "dhcp_end",
      testId: "preset-" + zid + "-dhcp-end",
      tooltip: "Конец DHCP pool.",
    });
    appendFormField(section, prefix + "dns_fqdn", "DNS FQDN", "text", {
      id: "preset-" + prefix + "dns_fqdn",
      testId: "preset-" + zid + "-dns-fqdn",
      tooltip: "Локальный FQDN зоны.",
    });

    const zoneAdvanced = buildAdvancedSettingsBlock({
      testId: "preset-" + zid + "-advanced-settings",
      summaryText: "Дополнительные настройки зоны",
    });
    appendFormSelect(
      zoneAdvanced.body,
      prefix + "ipv6_posture",
      "IPv6 posture",
      [
        ["Disabled", "Disabled"],
        ["ObserveOnly", "ObserveOnly"],
        ["Managed", "Managed"],
      ],
      {
        id: "preset-" + prefix + "ipv6_posture",
        testId: "preset-" + zid + "-ipv6-posture",
        tooltip: "IPv6 posture зоны.",
      },
    );
    appendFormCheckbox(zoneAdvanced.body, prefix + "management_allowed", "management_allowed", {
      id: "preset-" + prefix + "management_allowed",
      testId: "preset-" + zid + "-management-allowed",
      tooltip: "Разрешён management доступ к зоне.",
    });
    if (zid !== "AdminServer") {
      appendFormSelect(
        zoneAdvanced.body,
        prefix + "wpa_mode",
        "WPA mode",
        [
          ["WPA2", "WPA2"],
          ["WPA3", "WPA3"],
          ["WPA2_WPA3_MIXED", "WPA2+WPA3 mixed"],
        ],
        {
          id: "preset-" + prefix + "wpa_mode",
          testId: "preset-" + zid + "-wpa-mode",
          tooltip: "Режим WPA для Wi‑Fi.",
        },
      );
      appendFormSelect(
        zoneAdvanced.body,
        prefix + "wifi_band",
        "Wi-Fi band",
        [
          ["BAND_2_4GHZ", "2.4 GHz"],
          ["BAND_5GHZ", "5 GHz"],
        ],
        {
          id: "preset-" + prefix + "wifi_band",
          testId: "preset-" + zid + "-wifi-band",
          tooltip: "Диапазон Wi‑Fi.",
        },
      );
      appendFormCheckbox(zoneAdvanced.body, prefix + "guest_isolation", "guest_isolation", {
        id: "preset-" + prefix + "guest_isolation",
        testId: "preset-" + zid + "-guest-isolation",
        tooltip: "Guest isolation для Wi‑Fi AP.",
      });
      appendFormSelect(
        zoneAdvanced.body,
        prefix + "captive_portal",
        "Captive portal",
        [
          ["Disabled", "Disabled"],
          ["Enabled", "Enabled"],
        ],
        {
          id: "preset-" + prefix + "captive_portal",
          testId: "preset-" + zid + "-captive-portal",
          tooltip: "Captive portal mode.",
        },
      );
    }
    appendFormField(zoneAdvanced.body, prefix + "dhcp_lease", "DHCP lease seconds", "number", {
      id: "preset-" + prefix + "dhcp_lease",
      testId: "preset-" + zid + "-dhcp-lease",
      placeholder: "3600",
      min: "60",
      max: "604800",
      tooltip: "Lease time DHCP (seconds).",
    });
    const dhcpResEditor = buildCollectionEditor({
      testId: "preset-" + zid + "-dhcp-reservations",
      label: "DHCP reservations",
      addLabel: "Add reservation",
      columns: [
        { key: "mac_address", label: "MAC", type: "text" },
        { key: "ipv4_address", label: "IPv4", type: "text" },
      ],
    });
    form._zoneEditors[zid].dhcpReservations = dhcpResEditor;
    append(zoneAdvanced.body, dhcpResEditor.container);
    const dnsUpstreamEditor = buildCollectionEditor({
      testId: "preset-" + zid + "-dns-upstream",
      label: "DNS upstream_resolvers",
      addLabel: "Add resolver",
      columns: [{ key: "address", label: "Address", type: "text" }],
    });
    form._zoneEditors[zid].dnsUpstream = dnsUpstreamEditor;
    append(zoneAdvanced.body, dnsUpstreamEditor.container);
    const fwRulesEditor = buildCollectionEditor({
      testId: "preset-" + zid + "-firewall-rules",
      label: "Firewall rules",
      addLabel: "Add rule",
      minRows: 1,
      columns: [
        { key: "action", label: "Action", type: "select", options: FIREWALL_ACTION_OPTIONS },
        {
          key: "destination_family",
          label: "Destination",
          type: "select",
          options: FIREWALL_DESTINATION_OPTIONS,
        },
        { key: "ordinal", label: "Ordinal", type: "number" },
      ],
    });
    form._zoneEditors[zid].firewallRules = fwRulesEditor;
    append(zoneAdvanced.body, fwRulesEditor.container);
    section.appendChild(zoneAdvanced.details);
    form.appendChild(section);
  });

  fillPresetForm(form, existingDoc || buildPresetBootstrapDocument());
  return { form, docAdvancedDetails: docAdvanced.details };
}

async function renderPresets(root, presetId) {
  renderSkeleton(root);
  try {
    const status = await loadStatus();
    const siteId = sessionMemory.siteId || status.default_site_id;
    clear(root);
    append(root, pageHeader("Пресеты события", "Четырёхзонная модель — offline catalog"));
    append(root, gateNotice(status));

    const createPanel = el("div", "panel");
    append(createPanel, text(el("h2", "panel-title"), "Создать safe-default"));
    const createBtn = el("button", "btn btn-primary");
    text(createBtn, "Создать пресет");
    createBtn.addEventListener("click", async () => {
      try {
        const { data } = await apiFetch("/sites/" + encodeURIComponent(siteId) + "/event-presets", {
          method: "POST",
          idempotencyKey: uuid(),
          body: { name: "Event Preset " + new Date().toISOString().slice(0, 10) },
        });
        toast("Пресет создан");
        setHash("presets", data.preset.preset_id);
        renderPresets(root, data.preset.preset_id);
      } catch (e) {
        toast("Ошибка: " + e.message);
      }
    });
    append(createPanel, createBtn);
    append(root, createPanel);

    const listResp = await apiFetch("/sites/" + encodeURIComponent(siteId) + "/event-presets");
    const listPanel = el("div", "panel");
    append(listPanel, text(el("h2", "panel-title"), "Каталог"));
    const items = listResp.data.items || [];
    if (items.length === 0) {
      append(listPanel, text(el("p", "empty-state"), "Пресеты не найдены"));
    } else {
      const ul = el("ul");
      items.forEach((p) => {
        const li = el("li");
        const link = el("a");
        link.href = "#presets/" + p.preset_id;
        text(link, p.name + " (" + p.preset_id + ")");
        li.appendChild(link);
        ul.appendChild(li);
      });
      append(listPanel, ul);
    }
    append(root, listPanel);

    if (presetId) {
      const { data: preset } = await apiFetch("/event-presets/" + encodeURIComponent(presetId));
      let revisionDoc = null;
      if (preset.current_revision_id) {
        const rev = await apiFetch(
          "/event-presets/" + encodeURIComponent(presetId) + "/revisions/" + encodeURIComponent(preset.current_revision_id),
        );
        revisionDoc = rev.data.canonical_document;
      }

      const editor = el("div", "panel");
      append(editor, text(el("h2", "panel-title"), "Редактор: " + preset.name));
      let existingDoc = revisionDoc;
      const presetEditorUi = buildPresetEditorFormSurface(existingDoc);
      const form = presetEditorUi.form;

      const btnRow = el("div", "btn-row");
      const saveBtn = el("button", "btn btn-primary", { type: "button" });
      text(saveBtn, "Сохранить revision");
      saveBtn.addEventListener("click", async () => {
        const documentPayload = buildPresetDocumentFromForm(form, existingDoc);
        try {
          const { data } = await apiFetch("/event-presets/" + encodeURIComponent(presetId) + "/revisions", {
            method: "POST",
            idempotencyKey: uuid(),
            ifMatch: preset.etag,
            body: { document: documentPayload },
          });
          existingDoc = documentPayload;
          if (data.preset && data.preset.etag) preset.etag = data.preset.etag;
          toast("Revision сохранена");
        } catch (e) {
          toast("Save ошибка: " + e.message);
        }
      });
      const validateBtn = el("button", "btn btn-secondary", { type: "button" });
      text(validateBtn, "Validate");
      validateBtn.addEventListener("click", async () => {
        try {
          const { data } = await apiFetch("/event-presets/" + encodeURIComponent(presetId) + "/validate", {
            method: "POST",
            idempotencyKey: uuid(),
          });
          toast("Validation: " + (data.valid ? "OK" : "issues"));
        } catch (e) {
          toast("Validate ошибка: " + e.message);
        }
      });
      const planBtn = el("button", "btn btn-secondary", { type: "button" });
      text(planBtn, "Plan preview");
      planBtn.addEventListener("click", async () => {
        try {
          const { data } = await apiFetch("/event-presets/" + encodeURIComponent(presetId) + "/plan-preview", {
            method: "POST",
            idempotencyKey: uuid(),
          });
          const pre = el("pre", "mono");
          text(pre, JSON.stringify(data, null, 2));
          append(editor, pre);
        } catch (e) {
          toast("Plan ошибка: " + e.message);
        }
      });
      const readinessBtn = el("button", "btn btn-secondary", { type: "button" });
      text(readinessBtn, "Readiness report");
      readinessBtn.addEventListener("click", async () => {
        try {
          const { data } = await apiFetch("/event-presets/" + encodeURIComponent(presetId) + "/readiness/report");
          const pre = el("pre", "mono");
          text(pre, JSON.stringify(data, null, 2));
          append(editor, pre);
        } catch (e) {
          toast("Readiness ошибка: " + e.message);
        }
      });
      const publishBtn = el("button", "btn btn-primary", { type: "button" });
      text(publishBtn, "Publish (immutable)");
      publishBtn.addEventListener("click", async () => {
        if (!preset.current_revision_id) {
          toast("Нет revision для publish");
          return;
        }
        try {
          const { data: pubData } = await apiFetch(
            "/event-presets/" + encodeURIComponent(presetId) + "/publications",
            {
              method: "POST",
              idempotencyKey: uuid(),
              ifMatch: preset.etag,
              body: { revision_id: preset.current_revision_id },
            },
          );
          const pubField = document.getElementById("deploy-published-preset-id");
          if (pubField && pubData.published_preset_id) {
            pubField.value = pubData.published_preset_id;
          }
          toast("Published (immutable artifact)");
        } catch (e) {
          toast("Publication ошибка: " + e.message);
        }
      });
      const deployPanel = el("section", "panel config-deploy-apply");
      append(
        deployPanel,
        text(el("h3", "panel-title"), "Deployment Confirm/Apply (FAKE)"),
      );
      append(
        deployPanel,
        text(
          el("p", "field-hint config-deploy-apply-safety"),
          "FAKE mode only — proposals/plan lifecycle в SQLite; live router write недоступен. "
            + "Confirm/Apply fake-gated (403 без RC_ALLOW_FAKE_MUTATIONS + adapter_mode=fake). "
            + "Plan items — только kind+summary; intent/secrets не отображаются.",
        ),
      );
      append(
        deployPanel,
        text(
          el("p", "field-hint"),
          "Backup artifact: metadata only (artifact_id, digest, size, verification_status) — "
            + "без storage locator и absolute paths.",
        ),
      );

      const deployForm = el("form", "form-grid config-deploy-apply-form");
      appendFormField(deployForm, "router_id", "Router ID", "text", {
        id: "deploy-router-id",
        placeholder: "rtr_…",
      });
      appendFormField(deployForm, "published_preset_id", "Published preset ID", "text", {
        id: "deploy-published-preset-id",
        placeholder: "pub_… (prefill после Publish)",
      });
      appendFormField(deployForm, "deployment_revision_id", "Deployment revision ID", "text", {
        id: "deploy-deployment-revision-id",
        placeholder: "dep_…",
      });
      appendFormField(deployForm, "observation_id", "Observation ID", "text", {
        id: "deploy-observation-id",
        placeholder: "obs_…",
      });
      appendFormField(deployForm, "revision_id", "Desired revision ID", "text", {
        id: "deploy-revision-id",
        placeholder: "rev_…",
      });
      appendFormField(deployForm, "desired_etag", "Desired revision ETag (If-Match for plan)", "text", {
        id: "deploy-desired-etag",
        placeholder: '"rev:…"',
      });
      appendFormField(deployForm, "plan_id", "Plan ID", "text", {
        id: "deploy-plan-id",
        placeholder: "plan_…",
      });
      appendFormField(deployForm, "plan_digest", "Plan digest", "text", {
        id: "deploy-plan-digest",
        placeholder: "sha256:…",
      });
      appendFormField(deployForm, "plan_etag", "Plan ETag (If-Match confirm/apply)", "text", {
        id: "deploy-plan-etag",
        placeholder: '"plan:…"',
      });
      appendFormField(deployForm, "job_id", "Job ID (load job / backup)", "text", {
        id: "deploy-job-id",
        placeholder: "job_…",
      });

      const adoptField = el("div", "form-field");
      append(
        adoptField,
        el("input", "", {
          id: "deploy-adopt-acknowledged",
          name: "adopt_acknowledged",
          type: "checkbox",
        }),
      );
      append(
        adoptField,
        text(el("label", "", { for: "deploy-adopt-acknowledged" }), "Adopt acknowledged"),
      );
      deployForm.appendChild(adoptField);

      const riskField = el("div", "form-field");
      append(
        riskField,
        el("input", "", {
          id: "deploy-risk-acknowledged",
          name: "risk_acknowledged",
          type: "checkbox",
          "data-testid": "deploy-risk-acknowledged",
        }),
      );
      append(
        riskField,
        text(el("label", "", { for: "deploy-risk-acknowledged" }), "Risk acknowledged (confirm plan)"),
      );
      deployForm.appendChild(riskField);

      const deployAdvanced = buildAdvancedSettingsBlock({
        testId: "deploy-advanced-settings",
      });
      appendFormField(
        deployAdvanced.body,
        "put_desired_reason",
        "PUT desired reason (optional)",
        "text",
        fieldTooltipOpts("desired_revision", "reason", {
          id: "deploy-put-desired-reason",
          testId: "deploy-put-desired-reason",
        }),
      );
      deployForm.appendChild(deployAdvanced.details);

      const deployResultPanel = el("div", "config-deploy-apply-result panel-sub");
      append(deployResultPanel, text(el("h4", "panel-subtitle"), "RESULTS / LOGS"));
      const deployResultBox = el("pre", "mono config-result");
      append(deployResultPanel, deployResultBox);

      function deployField(id) {
        const node = document.getElementById(id);
        return node && node.value ? node.value.trim() : "";
      }

      function setDeployField(id, value) {
        const node = document.getElementById(id);
        if (node && value != null && value !== "") {
          node.value = String(value);
        }
      }

      function renderDeployResult(data) {
        text(deployResultBox, JSON.stringify(data, null, 2));
      }

      function requireDeployRouterId() {
        const rid = deployField("deploy-router-id");
        if (!rid) {
          throw new Error("router_id required");
        }
        return rid;
      }

      function readAdoptAcknowledged() {
        const elAdopt = document.getElementById("deploy-adopt-acknowledged");
        return !!(elAdopt && elAdopt.checked);
      }

      function readRiskAcknowledged() {
        const elRisk = document.getElementById("deploy-risk-acknowledged");
        return !!(elRisk && elRisk.checked);
      }

      const deployBtnRow = el("div", "btn-row");

      const depRevBtn = el("button", "btn btn-secondary", { type: "button" });
      text(depRevBtn, "Create deployment revision");
      depRevBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const pubId = deployField("deploy-published-preset-id");
        if (!pubId) {
          toast("published_preset_id required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid) + "/deployment-revisions",
            {
              method: "POST",
              idempotencyKey: uuid(),
              body: { published_preset_id: pubId, execution_target: "Lab" },
            },
          );
          setDeployField("deploy-deployment-revision-id", data.deployment_revision_id);
          renderDeployResult(data);
          toast("Deployment revision created");
        } catch (e) {
          toast("Deployment revision ошибка: " + e.message);
        }
      });

      const depGetBtn = el("button", "btn btn-secondary", {
        type: "button",
        "data-testid": "deploy-get-deployment-revision-btn",
      });
      text(depGetBtn, "Get deployment revision");
      depGetBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const depId = deployField("deploy-deployment-revision-id");
        if (!depId) {
          toast("deployment_revision_id required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid)
              + "/deployment-revisions/" + encodeURIComponent(depId),
          );
          renderDeployResult(data);
          toast("Deployment revision loaded (SQLite only, not device apply)");
        } catch (e) {
          toast("Get deployment revision ошибка: " + e.message);
        }
      });

      const putDesiredBtn = el("button", "btn btn-secondary", {
        type: "button",
        "data-testid": "deploy-put-desired-revision-btn",
      });
      text(putDesiredBtn, "PUT desired revision");
      putDesiredBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const obsId = deployField("deploy-observation-id");
        const desiredEtag = deployField("deploy-desired-etag");
        if (!obsId) {
          toast("observation_id required");
          return;
        }
        if (!desiredEtag) {
          toast("desired ETag (If-Match) required for PUT");
          return;
        }
        const reasonEl = document.getElementById("deploy-put-desired-reason");
        const reasonVal = reasonEl && reasonEl.value ? reasonEl.value.trim() : "";
        const body = {
          based_on_observation_id: obsId,
          assignments: [],
        };
        if (reasonVal) body.reason = reasonVal;
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid) + "/desired-revision",
            {
              method: "PUT",
              idempotencyKey: uuid(),
              ifMatch: desiredEtag,
              body,
            },
          );
          setDeployField("deploy-revision-id", data.revision_id);
          setDeployField("deploy-desired-etag", data.etag);
          renderDeployResult(data);
          toast("Desired revision updated (SQLite only, not device apply)");
        } catch (e) {
          toast("PUT desired revision ошибка: " + e.message);
        }
      });

      const depReadyBtn = el("button", "btn btn-secondary", { type: "button" });
      text(depReadyBtn, "Readiness");
      depReadyBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const depId = deployField("deploy-deployment-revision-id");
        if (!depId) {
          toast("deployment_revision_id required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid)
              + "/deployment-revisions/" + encodeURIComponent(depId) + "/readiness",
          );
          renderDeployResult(data);
          toast("Readiness: write_ready=" + data.write_ready);
        } catch (e) {
          toast("Readiness ошибка: " + e.message);
        }
      });

      const desiredRevBtn = el("button", "btn btn-secondary", { type: "button" });
      text(desiredRevBtn, "Create desired revision");
      desiredRevBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const depId = deployField("deploy-deployment-revision-id");
        const obsId = deployField("deploy-observation-id");
        if (!depId || !obsId) {
          toast("deployment_revision_id и observation_id required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid) + "/desired-revisions",
            {
              method: "POST",
              idempotencyKey: uuid(),
              body: { deployment_revision_id: depId, observation_id: obsId },
            },
          );
          setDeployField("deploy-revision-id", data.revision_id);
          setDeployField("deploy-desired-etag", data.etag);
          renderDeployResult(data);
          toast("Desired revision created");
        } catch (e) {
          toast("Desired revision ошибка: " + e.message);
        }
      });

      const createPlanBtn = el("button", "btn btn-secondary", { type: "button" });
      text(createPlanBtn, "Create plan");
      createPlanBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const revId = deployField("deploy-revision-id");
        const obsId = deployField("deploy-observation-id");
        const depId = deployField("deploy-deployment-revision-id");
        const desiredEtag = deployField("deploy-desired-etag");
        if (!revId || !obsId || !depId) {
          toast("revision_id, observation_id, deployment_revision_id required");
          return;
        }
        if (!desiredEtag) {
          toast("desired ETag (If-Match) required");
          return;
        }
        try {
          const { data } = await apiFetch("/routers/" + encodeURIComponent(rid) + "/plans", {
            method: "POST",
            idempotencyKey: uuid(),
            ifMatch: desiredEtag,
            body: {
              revision_id: revId,
              observation_id: obsId,
              deployment_revision_id: depId,
              adopt_acknowledged: readAdoptAcknowledged(),
            },
          });
          setDeployField("deploy-plan-id", data.plan_id);
          setDeployField("deploy-plan-digest", data.plan_digest);
          setDeployField("deploy-plan-etag", data.etag);
          renderDeployResult(data);
          toast("Plan created");
        } catch (e) {
          toast("Create plan ошибка: " + e.message);
        }
      });

      const loadPlanBtn = el("button", "btn btn-secondary", { type: "button" });
      text(loadPlanBtn, "Load plan");
      loadPlanBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const planId = deployField("deploy-plan-id");
        if (!planId) {
          toast("plan_id required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid) + "/plans/" + encodeURIComponent(planId),
          );
          setDeployField("deploy-plan-digest", data.plan_digest);
          setDeployField("deploy-plan-etag", data.etag);
          renderDeployResult(data);
          toast("Plan loaded: " + (data.changes ? data.changes.length : 0) + " changes");
        } catch (e) {
          toast("Load plan ошибка: " + e.message);
        }
      });

      const confirmPlanBtn = el("button", "btn btn-secondary", { type: "button" });
      text(confirmPlanBtn, "Confirm plan");
      confirmPlanBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const planId = deployField("deploy-plan-id");
        const planDigest = deployField("deploy-plan-digest");
        const planEtag = deployField("deploy-plan-etag");
        if (!planId || !planDigest || !planEtag) {
          toast("plan_id, plan_digest, plan ETag required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid)
              + "/plans/" + encodeURIComponent(planId) + "/confirm",
            {
              method: "POST",
              idempotencyKey: uuid(),
              ifMatch: planEtag,
              body: {
                plan_digest: planDigest,
                adopt_acknowledged: readAdoptAcknowledged(),
                risk_acknowledged: readRiskAcknowledged(),
              },
            },
          );
          setDeployField("deploy-plan-etag", data.etag);
          renderDeployResult(data);
          toast("Plan confirmed");
        } catch (e) {
          toast("Confirm ошибка: " + e.message);
        }
      });

      const applyPlanBtn = el("button", "btn btn-primary", { type: "button" });
      text(applyPlanBtn, "Apply plan (FAKE-gated)");
      applyPlanBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        const planId = deployField("deploy-plan-id");
        const planEtag = deployField("deploy-plan-etag");
        if (!planId || !planEtag) {
          toast("plan_id и plan ETag required");
          return;
        }
        try {
          const { data, status } = await apiFetch(
            "/routers/" + encodeURIComponent(rid)
              + "/plans/" + encodeURIComponent(planId) + "/apply",
            {
              method: "POST",
              idempotencyKey: uuid(),
              ifMatch: planEtag,
            },
          );
          if (data.job_id) {
            setDeployField("deploy-job-id", data.job_id);
          }
          renderDeployResult(data);
          toast(
            "Job queued (SQLite plan queue, not device apply)"
              + (data.job_id ? " — job_id=" + data.job_id : " — HTTP " + status),
          );
        } catch (e) {
          if (e.status === 403) {
            renderDeployResult({
              error: e.message,
              code: e.code || "gate.mutation_forbidden",
              hint: "FAKE apply требует adapter_mode=fake и RC_ALLOW_FAKE_MUTATIONS=1 на host",
            });
          }
          toast("Apply ошибка: " + e.message);
        }
      });

      const loadJobBtn = el("button", "btn btn-secondary", { type: "button" });
      text(loadJobBtn, "Load job");
      loadJobBtn.addEventListener("click", async () => {
        const jobId = deployField("deploy-job-id");
        if (!jobId) {
          toast("job_id required");
          return;
        }
        try {
          const { data } = await apiFetch("/jobs/" + encodeURIComponent(jobId));
          renderDeployResult(data);
          toast("Job: " + data.status);
        } catch (e) {
          toast("Load job ошибка: " + e.message);
        }
      });

      const loadBackupBtn = el("button", "btn btn-secondary", { type: "button" });
      text(loadBackupBtn, "Load backup-artifact");
      loadBackupBtn.addEventListener("click", async () => {
        const jobId = deployField("deploy-job-id");
        if (!jobId) {
          toast("job_id required");
          return;
        }
        try {
          const { data } = await apiFetch(
            "/jobs/" + encodeURIComponent(jobId) + "/backup-artifact",
          );
          renderDeployResult(data);
          toast("Backup artifact metadata loaded");
        } catch (e) {
          toast("Backup-artifact ошибка: " + e.message);
        }
      });

      const revStateBtn = el("button", "btn btn-secondary", { type: "button" });
      text(revStateBtn, "Revision state");
      revStateBtn.addEventListener("click", async () => {
        const rid = requireDeployRouterId();
        try {
          const { data } = await apiFetch(
            "/routers/" + encodeURIComponent(rid) + "/revision-state",
          );
          renderDeployResult(data);
          toast("Revision state loaded");
        } catch (e) {
          toast("Revision state ошибка: " + e.message);
        }
      });

      append(
        deployBtnRow,
        depRevBtn,
        depGetBtn,
        depReadyBtn,
        desiredRevBtn,
        putDesiredBtn,
        createPlanBtn,
        loadPlanBtn,
        confirmPlanBtn,
        applyPlanBtn,
        loadJobBtn,
        loadBackupBtn,
        revStateBtn,
      );
      append(deployPanel, deployForm, deployBtnRow, deployResultPanel);
      append(btnRow, saveBtn, validateBtn, planBtn, readinessBtn, publishBtn);
      append(form, btnRow);
      append(editor, form);
      append(editor, deployPanel);
      append(root, editor);
    }
  } catch (err) {
    renderError(root, err, () => renderPresets(root, presetId));
  }
}

async function renderOperations(root, opId) {
  renderSkeleton(root);
  try {
    await loadStatus();
    clear(root);
    append(root, pageHeader("Операции и задания", "Статус, опрос и безопасная отмена"));

    const lookup = el("div", "panel");
    append(lookup, text(el("h2", "panel-title"), "Поиск операции"));
    const form = el("form", "form-grid");
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const id = form.querySelector('[name="operation_id"]').value;
      setHash("operations", id);
      renderOperations(root, id);
    });
    const field = el("div", "form-field");
    append(field, text(el("label"), "Operation ID"));
    const input = el("input", "", { name: "operation_id", type: "text", required: "true" });
    if (opId) input.value = opId;
    append(field, input);
    append(form, field);
    const btn = el("button", "btn btn-primary", { type: "submit" });
    text(btn, "Открыть");
    append(form, btn);
    append(lookup, form);
    append(root, lookup);

    if (opId) {
      const detail = el("div", "panel");
      const { data: op } = await apiFetch("/operations/" + encodeURIComponent(opId));
      rememberOp(opId);
      append(detail, text(el("h2", "panel-title"), "Operation " + opId));
      append(detail, text(el("p"), "Статус: " + op.aggregate_status + " · Kind: " + op.operation_kind));
      if (op.recovery_required || op.aggregate_status === "RecoveryRequired") {
        const recBanner = el("div", "recovery-banner");
        text(recBanner, "RecoveryRequired — требуется identity+read-back; blind retry запрещён");
        append(detail, recBanner);
      }

      const pollBtn = el("button", "btn btn-secondary");
      text(pollBtn, "Опросить");
      pollBtn.addEventListener("click", async () => {
        try {
          const result = await pollOperation(opId, (data) => {
            append(detail, text(el("p"), "Poll: " + data.aggregate_status));
          });
          toast("Terminal: " + result.aggregate_status);
        } catch (e) {
          toast("Poll ошибка: " + e.message);
        }
      });
      append(detail, pollBtn);

      const jobsResp = await apiFetch("/operations/" + encodeURIComponent(opId) + "/jobs");
      const jobs = jobsResp.data.items || [];
      for (const job of jobs) {
        rememberJob(job.job_id);
        const jobDetail = await apiFetch("/jobs/" + encodeURIComponent(job.job_id));
        const jd = jobDetail.data;
        append(
          detail,
          text(
            el("p"),
            "Job attempt " + jd.attempt + ": " + jd.job_id + " — " + jd.status +
              (jd.recovery_state ? " (" + jd.recovery_state + ")" : ""),
          ),
        );
        if (jd.steps && jd.steps.length > 0) {
          const stepsUl = el("ul", "job-steps");
          jd.steps.forEach((s) => {
            const li = el("li");
            text(li, s.step_kind + " → " + s.status);
            stepsUl.appendChild(li);
          });
          append(detail, stepsUl);
        }
        if (jd.status === "RecoveryRequired" && jd.recovery_actions) {
          const gateNote = el("p", "gate-notice");
          text(gateNote, "Recovery actions доступны только в fake/offline режиме");
          append(detail, gateNote);
          const resumeBtn = el("button", "btn btn-secondary");
          text(resumeBtn, "Resume (read-back)");
          resumeBtn.addEventListener("click", async () => {
            try {
              await apiFetch("/jobs/" + encodeURIComponent(jd.job_id) + "/resume", {
                method: "POST",
                idempotencyKey: uuid(),
              });
              toast("Resume queued");
              renderOperations(root, opId);
            } catch (e) {
              toast("Resume ошибка: " + e.message);
            }
          });
          append(detail, resumeBtn);
          const compBtn = el("button", "btn btn-secondary");
          text(compBtn, "Compensate");
          compBtn.addEventListener("click", async () => {
            try {
              await apiFetch("/jobs/" + encodeURIComponent(jd.job_id) + "/compensate", {
                method: "POST",
                idempotencyKey: uuid(),
              });
              toast("Compensate queued");
              renderOperations(root, opId);
            } catch (e) {
              toast("Compensate ошибка: " + e.message);
            }
          });
          append(detail, compBtn);
        }
        if (jd.status === "Queued" || jd.status === "Leased" || jd.status === "Running") {
          const cancelBtn = el("button", "btn btn-secondary");
          text(cancelBtn, "Cancel job");
          cancelBtn.addEventListener("click", async () => {
            try {
              await apiFetch("/jobs/" + encodeURIComponent(jd.job_id) + "/cancel", {
                method: "POST",
                idempotencyKey: uuid(),
              });
              toast("Cancel запрошен");
            } catch (e) {
              toast("Cancel ошибка: " + e.message);
            }
          });
          append(detail, cancelBtn);
        }
      }
      append(root, detail);
    }

    const recent = el("div", "panel");
    append(recent, text(el("h2", "panel-title"), "Недавние (сессия)"));
    if (sessionMemory.recentOps.length === 0) {
      append(recent, text(el("p", "empty-state"), "Пусто"));
    } else {
      const ul = el("ul");
      sessionMemory.recentOps.forEach((id) => {
        const li = el("li");
        const link = el("a");
        link.href = "#operations/" + id;
        text(link, id);
        li.appendChild(link);
        ul.appendChild(li);
      });
      append(recent, ul);
    }
    append(root, recent);
  } catch (err) {
    renderError(root, err, () => renderOperations(root, opId));
  }
}

async function renderVpn(root, profileId) {
  renderSkeleton(root);
  try {
    await loadFieldManifest();
    const status = await loadStatus();
    clear(root);
    append(root, pageHeader("VPN-каталог", "Метаданные и validation — без секретов"));
    const warn = el("div", "gate-notice");
    text(warn, "Catalog import хранит ключи локально/DPAPI на сервере; UI не отображает profile body, keys, PSK или endpoint. Import ≠ device apply.");
    append(root, warn);
    append(root, gateNotice(status));

    append(root, buildVpnImportFormSurface().panel);

    const listResp = await apiFetch("/vpn-profiles");
    const listPanel = el("div", "panel");
    append(listPanel, text(el("h2", "panel-title"), "Профили"));
    const items = listResp.data.items || [];
    if (items.length === 0) {
      append(listPanel, text(el("p", "empty-state"), "Профили не импортированы"));
    } else {
      const table = el("table", "data-table");
      const hr = el("tr");
      ["ID", "Имя", "Kind", "Validation", ""].forEach((h) => {
        hr.appendChild(text(el("th"), h));
      });
      const tbody = el("tbody");
      items.forEach((row) => {
        const tr = el("tr");
        append(tr, text(el("td", "mono"), row.profile_id));
        append(tr, text(el("td"), row.display_name));
        append(tr, text(el("td"), row.vpn_kind));
        append(tr, text(el("td"), row.validation_status));
        const td = el("td");
        const link = el("a", "btn btn-secondary");
        link.href = "#vpn/" + row.profile_id;
        text(link, "Открыть");
        td.appendChild(link);
        tr.appendChild(td);
        tbody.appendChild(tr);
      });
      append(table, hr, tbody);
      const wrap = el("div", "table-wrap");
      wrap.appendChild(table);
      append(listPanel, wrap);
    }
    append(root, listPanel);

    if (profileId) {
      const { data: profile } = await apiFetch("/vpn-profiles/" + encodeURIComponent(profileId));
      const detail = el("div", "panel");
      append(detail, text(el("h2", "panel-title"), profile.display_name));
      append(detail, text(el("p"), "Kind: " + profile.vpn_kind));
      append(detail, text(el("p"), "Validation: " + profile.validation_status));
      append(detail, text(el("p"), "Digest: " + profile.content_digest));
      append(detail, text(el("p"), "Parser: " + profile.parser_version));
      const valBtn = el("button", "btn btn-secondary");
      text(valBtn, "Validate");
      valBtn.addEventListener("click", async () => {
        try {
          await apiFetch("/vpn-profiles/" + encodeURIComponent(profileId) + "/validate", {
            method: "POST",
            idempotencyKey: uuid(),
          });
          toast("Validate OK");
          renderVpn(root, profileId);
        } catch (e) {
          toast("Validate ошибка: " + e.message);
        }
      });
      append(detail, valBtn);
      append(root, detail);
    }
  } catch (err) {
    renderError(root, err, () => renderVpn(root, profileId));
  }
}

function configApplyBanner(status) {
  const banner = el("div", "config-apply-banner gate-notice");
  if (writeGatesBlocked(status)) {
    text(
      banner,
      "Каталог/preset Apply заблокирован: Gate B не WriteCertified — требуется discovery shape + T4. "
        + "Bounded Wi-Fi/AWG test Apply ниже доступны при confirm и per-request connection params.",
    );
  } else {
    text(banner, gateBlockReason(status));
  }
  return banner;
}

function routerControlLabClass() {
  if (typeof window !== "undefined" && window.ROUTER_CONTROL_LAB_CLASS) {
    return String(window.ROUTER_CONTROL_LAB_CLASS);
  }
  const root = document.documentElement;
  if (root && root.dataset && root.dataset.routerControlLabClass) {
    return root.dataset.routerControlLabClass;
  }
  return "";
}

function isExpendableLabClass() {
  return routerControlLabClass() === "expendable_development_router";
}

function wifiApIndexRange(options) {
  const opts = options || {};
  const expendable = opts.expendable != null ? !!opts.expendable : isExpendableLabClass();
  return {
    apRangeStart: expendable ? 0 : 3,
    apRangeEnd: 6,
  };
}

function readWifiApplyPayloadFromDom(includeConfirm) {
  const ssidEl = document.getElementById("wifi-apply-ssid");
  const apEl = document.getElementById("wifi-apply-ap-id");
  const bandEl = document.getElementById("wifi-apply-band");
  const wpaEl = document.getElementById("wifi-apply-wpa-mode");
  const guestEl = document.getElementById("wifi-apply-guest-isolation");
  const captiveEl = document.getElementById("wifi-apply-captive");
  const enabledEl = document.getElementById("wifi-apply-enabled");
  const pskCredEl = document.getElementById("wifi-apply-psk-cred-ref");
  const hostEl = document.getElementById("wifi-apply-host");
  const userEl = document.getElementById("wifi-apply-username");
  const routerCredEl = document.getElementById("wifi-apply-router-cred-ref");
  const pinEl = document.getElementById("wifi-apply-ssh-pin");
  const sourceEl = document.getElementById("wifi-apply-source-address");
  const routerIdEl = document.getElementById("wifi-apply-router-id");
  const compensateEl = document.getElementById("wifi-apply-compensate");
  const idempotentEl = document.getElementById("wifi-apply-idempotent");
  const payload = {
    ap_id: apEl && apEl.value ? apEl.value : "",
    ssid: ssidEl && ssidEl.value ? ssidEl.value : "",
    enabled: !!(enabledEl && enabledEl.checked),
    credential_ref_id: pskCredEl && pskCredEl.value ? pskCredEl.value : null,
    band: bandEl && bandEl.value ? bandEl.value : "BAND_2_4GHZ",
    wpa_mode: wpaEl && wpaEl.value ? wpaEl.value : "WPA2",
    guest_isolation: !!(guestEl && guestEl.checked),
    captive_portal: captiveEl && captiveEl.value ? captiveEl.value : "Disabled",
    compensate_on_failure: compensateEl ? compensateEl.checked : true,
    idempotent: !!(idempotentEl && idempotentEl.checked),
  };
  const hostVal = hostEl && hostEl.value ? hostEl.value.trim() : "";
  const userVal = userEl && userEl.value ? userEl.value.trim() : "";
  const routerCredVal = routerCredEl && routerCredEl.value ? routerCredEl.value.trim() : "";
  const pinVal = pinEl && pinEl.value ? pinEl.value.trim() : "";
  const sourceVal = sourceEl && sourceEl.value ? sourceEl.value.trim() : "";
  const routerIdVal = routerIdEl && routerIdEl.value ? routerIdEl.value.trim() : "";
  if (hostVal) payload.host = hostVal;
  if (userVal) payload.username = userVal;
  if (routerCredVal) payload.router_credential_ref_id = routerCredVal;
  if (pinVal) payload.ssh_host_key_sha256 = pinVal;
  if (sourceVal) payload.source_address = sourceVal;
  if (routerIdVal) payload.router_id = routerIdVal;
  if (includeConfirm) {
    const confirmEl = document.getElementById("wifi-apply-confirm");
    payload.confirm_live_apply = !!(confirmEl && confirmEl.checked);
  }
  return payload;
}

function wifiApplyHonestySummary(data) {
  if (!data || typeof data !== "object") return "";
  const parts = [];
  const overall = data.overall;
  const primarySuccess = overall === "applied";
  if (overall) {
    parts.push("overall=" + String(overall));
  } else {
    parts.push("overall unknown");
  }
  const onAir = data.on_air_verification_status;
  if (onAir === "on_air_verified") {
    if (primarySuccess) {
      parts.push("on-air verified (link up)");
    } else {
      parts.push("on_air=on_air_verified (secondary — overall not applied)");
    }
  } else if (onAir === "on_air_admin_only") {
    parts.push("NOT on-air — admin up only (NOT success)");
  } else if (onAir === "on_air_still_broadcasting") {
    parts.push("still broadcasting after teardown (NOT success)");
  } else if (onAir === "on_air_unverified") {
    parts.push("on-air NOT verified");
  } else if (onAir) {
    parts.push("on_air: " + String(onAir));
  }
  return parts.length ? parts.join("; ") : "";
}

function awgApplyHonestySummary(data) {
  if (!data || typeof data !== "object") return "";
  const parts = [];
  const overall = data.overall;
  const primarySuccess = overall === "applied";
  if (overall) {
    parts.push("overall=" + String(overall));
  } else {
    parts.push("overall unknown");
  }
  if (data.configuration_verification_status === "device_accepted_configuration") {
    if (primarySuccess) {
      parts.push("configuration applied");
    } else {
      parts.push(
        "configuration=device_accepted_configuration (secondary — overall not applied)",
      );
    }
  }
  if (data.interface_verification_status === "interface_present_up") {
    parts.push("interface up (admin)");
  } else if (data.interface_verification_status === "interface_present_down") {
    parts.push("interface down (admin)");
  } else if (data.interface_verification_status) {
    parts.push("interface: " + data.interface_verification_status);
  }
  if (data.interface_address_verification_status === "interface_address_not_configured") {
    parts.push("interface Address NOT configured (NOT usable for VPN traffic)");
  }
  const tunnel = data.tunnel_verification_status;
  if (tunnel === "tunnel_healthy") {
    if (primarySuccess) {
      parts.push("tunnel healthy (peer handshake DEVICE-CONFIRMED — NOT egress via VPN)");
    } else {
      parts.push("tunnel=tunnel_healthy (secondary — overall not applied)");
    }
  } else if (tunnel === "tunnel_never_handshaked") {
    parts.push("tunnel never handshaked (DEVICE-CONFIRMED dead-peer — NOT working VPN)");
  } else if (tunnel === "tunnel_no_peer") {
    parts.push("tunnel: no peer observed");
  } else if (tunnel === "tunnel_unverified") {
    parts.push("tunnel NOT verified");
  }
  return parts.length ? parts.join("; ") : "";
}

function buildWifiApplyFormSurface(options) {
  const { apRangeStart, apRangeEnd } = wifiApIndexRange(options);
  const apSafetyHint = (options && options.expendable) || isExpendableLabClass()
    ? "Expendable lab: AccessPoint0–6 на WifiMaster0/1. Live apply требует confirm и per-request connection params (win32 + DPAPI). "
    : "Только bounded test AP (AccessPoint3–6). Production AP0/1/2 запрещены. "
        + "Live apply требует confirm и per-request connection params (win32 + DPAPI). ";

  const panel = el("section", "config-section panel config-wifi-apply");
  append(panel, text(el("h2", "panel-title"), "Wi-Fi Apply (test AP)"));
  append(
    panel,
    text(
      el("p", "field-hint config-wifi-apply-safety"),
      apSafetyHint
        + "WPA2/WPA3/WPA2+WPA3 mixed — device-verified grammar: authentication wpa-psk "
        + "+ encryption wpa2/wpa3 (не authentication sae).",
    ),
  );
  append(
    panel,
    text(
      el("p", "field-hint"),
      "PSK: только credential_ref_id — plaintext PSK в UI не вводится.",
    ),
  );

  const form = el("form", "form-grid config-wifi-apply-form");

  appendFormField(form, "ssid", "SSID", "text", fieldTooltipOpts("wifi_ap", "ssid", {
    id: "wifi-apply-ssid",
    testId: "wifi-apply-ssid",
    placeholder: "Staff-Test",
  }));

  appendFormField(form, "credential_ref_id", "PSK credential_ref_id", "text", fieldTooltipOpts("wifi_ap", "credential_ref_id", {
    id: "wifi-apply-psk-cred-ref",
    testId: "wifi-apply-psk-cred-ref",
    placeholder: "credref:…",
  }));

  appendFormSelect(
    form,
    "band",
    "Band",
    [
      ["BAND_2_4GHZ", "2.4 GHz"],
      ["BAND_5GHZ", "5 GHz"],
    ],
    fieldTooltipOpts("wifi_ap", "band", {
      id: "wifi-apply-band",
      testId: "wifi-apply-band",
    }),
  );

  const advanced = buildAdvancedSettingsBlock({
    testId: "wifi-apply-advanced-settings",
    summaryText: "Дополнительные настройки",
  });
  const advancedBody = advanced.body;

  const apOptions = [];
  ["WifiMaster0", "WifiMaster1"].forEach((master) => {
    for (let n = apRangeStart; n <= apRangeEnd; n += 1) {
      apOptions.push([master + "/AccessPoint" + n, master + "/AccessPoint" + n]);
    }
  });
  appendFormSelect(advancedBody, "ap_id", "Test AP", apOptions, fieldTooltipOpts("wifi_ap", "ap_id", {
    id: "wifi-apply-ap-id",
    testId: "wifi-apply-ap-id",
  }));

  appendFormSelect(
    advancedBody,
    "wpa_mode",
    "WPA mode",
    [
      ["WPA2", "WPA2 (device-verified)"],
      ["WPA3", "WPA3 (device-verified — wpa-psk + encryption wpa3)"],
      ["WPA2_WPA3_MIXED", "WPA2+WPA3 mixed (device-verified — wpa-psk + wpa2 + wpa3)"],
    ],
    fieldTooltipOpts("wifi_ap", "wpa_mode", {
      id: "wifi-apply-wpa-mode",
      testId: "wifi-apply-wpa-mode",
    }),
  );

  appendFormCheckbox(advancedBody, "enabled", "Enabled (AP up)", fieldTooltipOpts("wifi_ap", "enabled", {
    id: "wifi-apply-enabled",
    testId: "wifi-apply-enabled",
  }));

  appendFormCheckbox(advancedBody, "guest_isolation", "Guest isolation", fieldTooltipOpts("wifi_ap", "guest_isolation", {
    id: "wifi-apply-guest-isolation",
    testId: "wifi-apply-guest-isolation",
    honestyNote: HONESTY_WIFI_GUEST_ISOLATION,
    honestyTestId: "wifi-apply-guest-isolation-honesty",
  }));

  appendFormSelect(
    advancedBody,
    "captive_portal",
    "Captive portal",
    [
      ["Disabled", "Disabled"],
      ["Enabled", "Enabled"],
    ],
    fieldTooltipOpts("wifi_ap", "captive_portal", {
      id: "wifi-apply-captive",
      testId: "wifi-apply-captive",
      honestyNote: HONESTY_WIFI_CAPTIVE_PORTAL,
      honestyTestId: "wifi-apply-captive-honesty",
    }),
  );

  appendFormField(advancedBody, "router_id", "Router ID (optional)", "text", fieldTooltipOpts("wifi_ap", "router_id", {
    id: "wifi-apply-router-id",
    testId: "wifi-apply-router-id",
    placeholder: "router-uuid",
  }));

  appendFormCheckbox(advancedBody, "compensate_on_failure", "Compensate on failure", fieldTooltipOpts("wifi_ap", "compensate_on_failure", {
    id: "wifi-apply-compensate",
    testId: "wifi-apply-compensate",
  }));

  appendFormCheckbox(advancedBody, "idempotent", "Idempotent apply", fieldTooltipOpts("wifi_ap", "idempotent", {
    id: "wifi-apply-idempotent",
    testId: "wifi-apply-idempotent",
  }));

  append(
    advancedBody,
    text(el("h3", "panel-subtitle"), "Live connection (optional — per-request)"),
  );
  appendFormField(advancedBody, "host", "Router host", "text", fieldTooltipOpts("wifi_ap", "host", {
    id: "wifi-apply-host",
    testId: "wifi-apply-host",
    placeholder: "192.168.2.1",
  }));
  appendFormField(advancedBody, "username", "SSH username", "text", fieldTooltipOpts("wifi_ap", "username", {
    id: "wifi-apply-username",
    testId: "wifi-apply-username",
    placeholder: "admin",
  }));
  appendFormField(advancedBody, "router_credential_ref_id", "Router credential_ref_id", "text", fieldTooltipOpts("wifi_ap", "router_credential_ref_id", {
    id: "wifi-apply-router-cred-ref",
    testId: "wifi-apply-router-cred-ref",
    placeholder: "credref:…",
  }));
  appendFormField(advancedBody, "ssh_host_key_sha256", "SSH host key SHA256", "text", fieldTooltipOpts("wifi_ap", "ssh_host_key_sha256", {
    id: "wifi-apply-ssh-pin",
    testId: "wifi-apply-ssh-pin",
  }));
  appendFormField(advancedBody, "source_address", "Source address (optional)", "text", fieldTooltipOpts("wifi_ap", "source_address", {
    id: "wifi-apply-source-address",
    testId: "wifi-apply-source-address",
    placeholder: "192.168.2.10",
  }));

  appendFormCheckbox(advancedBody, "confirm_live_apply", "Подтверждаю live apply/teardown на test AP", fieldTooltipOpts("wifi_ap", "confirm_live_apply", {
    id: "wifi-apply-confirm",
    testId: "wifi-apply-confirm",
    fieldClass: "config-wifi-apply-confirm",
  }));

  form.appendChild(advanced.details);

  const resultPanel = el("div", "config-wifi-apply-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "RESULTS / LOGS"));
  const verdictExplanationBox = el("div", "verdict-explanation-wrap");
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, verdictExplanationBox, resultBox);

  function renderResult(data) {
    renderApplyResultWithVerdict(verdictExplanationBox, resultBox, data);
  }

  return {
    panel,
    form,
    advancedDetails: advanced.details,
    resultPanel,
    verdictExplanationBox,
    resultBox,
    readPayload: readWifiApplyPayloadFromDom,
    renderResult,
    apRangeStart,
    apRangeEnd,
  };
}

function parseAwgAscArgs(textVal) {
  const trimmed = (textVal || "").trim();
  if (!trimmed) return null;
  const parts = trimmed.split(/\s+/);
  if (parts.length !== 9) {
    throw new Error("ASC args must be exactly 9 space-separated integers");
  }
  return parts.map((p) => {
    const n = Number(p);
    if (!Number.isInteger(n) || n < 0) {
      throw new Error("ASC args must be non-negative integers");
    }
    return n;
  });
}

function readAwgApplyPayloadFromDom(includeConfirm) {
  const wgEl = document.getElementById("awg-apply-wg-id");
  const ascEl = document.getElementById("awg-apply-asc-args");
  const enabledEl = document.getElementById("awg-apply-enabled");
  const privateKeyRefEl = document.getElementById("awg-apply-private-key-ref");
  const pskRefEl = document.getElementById("awg-apply-psk-ref");
  const peerPubkeyEl = document.getElementById("awg-apply-peer-pubkey");
  const peerEndpointEl = document.getElementById("awg-apply-peer-endpoint");
  const peerAllowIpsEl = document.getElementById("awg-apply-peer-allow-ips");
  const peerKeepaliveEl = document.getElementById("awg-apply-peer-keepalive");
  const handshakeSettleEl = document.getElementById("awg-apply-handshake-settle");
  const peerRciShapeEl = document.getElementById("awg-apply-peer-rci-shape");
  const hostEl = document.getElementById("awg-apply-host");
  const userEl = document.getElementById("awg-apply-username");
  const routerCredEl = document.getElementById("awg-apply-router-cred-ref");
  const pinEl = document.getElementById("awg-apply-ssh-pin");
  const sourceEl = document.getElementById("awg-apply-source-address");
  const routerIdEl = document.getElementById("awg-apply-router-id");
  const peerRciShapeVal =
    peerRciShapeEl && peerRciShapeEl.value ? peerRciShapeEl.value : "nested_rci";
  const payload = {
    wg_id: wgEl && wgEl.value ? wgEl.value : "",
    enabled: !!(enabledEl && enabledEl.checked),
    peer_rci_shape: peerRciShapeVal,
  };
  if (ascEl && ascEl.value && ascEl.value.trim()) {
    payload.asc_args = parseAwgAscArgs(ascEl.value);
  }
  const privateKeyRefVal =
    privateKeyRefEl && privateKeyRefEl.value ? privateKeyRefEl.value.trim() : "";
  const pskRefVal = pskRefEl && pskRefEl.value ? pskRefEl.value.trim() : "";
  const peerPubkeyVal = peerPubkeyEl && peerPubkeyEl.value ? peerPubkeyEl.value.trim() : "";
  const peerEndpointVal =
    peerEndpointEl && peerEndpointEl.value ? peerEndpointEl.value.trim() : "";
  const peerAllowIpsVal =
    peerAllowIpsEl && peerAllowIpsEl.value ? peerAllowIpsEl.value.trim() : "";
  const peerKeepaliveVal =
    peerKeepaliveEl && peerKeepaliveEl.value ? peerKeepaliveEl.value.trim() : "";
  const handshakeSettleVal =
    handshakeSettleEl && handshakeSettleEl.value ? handshakeSettleEl.value.trim() : "";
  if (privateKeyRefVal) payload.private_key_credential_ref_id = privateKeyRefVal;
  if (pskRefVal) payload.preshared_key_credential_ref_id = pskRefVal;
  if (peerPubkeyVal) payload.peer_public_key = peerPubkeyVal;
  if (peerEndpointVal) payload.peer_endpoint = peerEndpointVal;
  if (peerAllowIpsVal) payload.peer_allow_ips = peerAllowIpsVal;
  if (peerKeepaliveVal) {
    const keepalive = Number(peerKeepaliveVal);
    if (!Number.isInteger(keepalive) || keepalive < 3 || keepalive > 3600) {
      throw new Error("peer_keepalive_interval must be integer 3..3600");
    }
    payload.peer_keepalive_interval = keepalive;
  }
  if (handshakeSettleVal) {
    const settle = Number(handshakeSettleVal);
    if (!Number.isFinite(settle) || settle < 0) {
      throw new Error("handshake_settle_seconds must be >= 0");
    }
    payload.handshake_settle_seconds = settle;
  }
  const hostVal = hostEl && hostEl.value ? hostEl.value.trim() : "";
  const userVal = userEl && userEl.value ? userEl.value.trim() : "";
  const routerCredVal = routerCredEl && routerCredEl.value ? routerCredEl.value.trim() : "";
  const pinVal = pinEl && pinEl.value ? pinEl.value.trim() : "";
  const sourceVal = sourceEl && sourceEl.value ? sourceEl.value.trim() : "";
  const routerIdVal = routerIdEl && routerIdEl.value ? routerIdEl.value.trim() : "";
  if (hostVal) payload.host = hostVal;
  if (userVal) payload.username = userVal;
  if (routerCredVal) payload.router_credential_ref_id = routerCredVal;
  if (pinVal) payload.ssh_host_key_sha256 = pinVal;
  if (sourceVal) payload.source_address = sourceVal;
  if (routerIdVal) payload.router_id = routerIdVal;
  if (includeConfirm) {
    const confirmEl = document.getElementById("awg-apply-confirm");
    payload.confirm_live_apply = !!(confirmEl && confirmEl.checked);
  }
  return payload;
}

function buildAwgApplyFormSurface(options) {
  const expendable = (options && options.expendable) || isExpendableLabClass();
  const wgRangeStart = expendable ? 0 : 5;
  const wgSafetyHint = expendable
    ? "Expendable lab: Wireguard interfaces 0–9. Live apply требует confirm и per-request connection params (win32 + DPAPI). "
    : "Только bounded test interfaces Wireguard5–Wireguard9. "
        + "Live apply требует confirm и per-request connection params (win32 + DPAPI). ";

  const panel = el("section", "config-section panel config-awg-apply");
  append(panel, text(el("h2", "panel-title"), "AWG Apply (test interface)"));
  append(
    panel,
    text(
      el("p", "field-hint config-awg-apply-safety"),
      wgSafetyHint + "16-arg ASC — documented, not device-verified.",
    ),
  );
  append(
    panel,
    text(
      el("p", "field-hint"),
      "ASC: 9 space-separated non-negative ints (optional). "
        + "Secrets: только credential_ref_id — plaintext private-key/psk в UI не вводится. "
        + "Peer public-key/endpoint/allow-ips/keepalive — non-secret.",
    ),
  );
  append(
    panel,
    text(
      el("p", "field-hint config-awg-apply-honesty"),
      "Apply overall=applied = configuration applied + interface admin up — "
        + "tunnel verdict отдельно (tunnel_no_peer | tunnel_never_handshaked | "
        + "tunnel_healthy | tunnel_unverified); dead-peer и tunnel_healthy "
        + "DEVICE-CONFIRMED (2026-07-31); wireguard.status:up ≠ working VPN; "
        + "interface Address NOT configured — NOT usable for VPN traffic; "
        + "handshake_settle_seconds (0 или 20–30) — опциональная пауза перед одним recheck; "
        + "не «online via VPN».",
    ),
  );

  const form = el("form", "form-grid config-awg-apply-form");

  const wgOptions = [];
  for (let n = wgRangeStart; n <= 9; n += 1) {
    wgOptions.push(["Wireguard" + n, "Wireguard" + n]);
  }
  appendFormSelect(form, "wg_id", "Test interface", wgOptions, fieldTooltipOpts("wireguard", "wg_id", {
    id: "awg-apply-wg-id",
    testId: "awg-apply-wg-id",
  }));

  appendFormField(form, "peer_public_key", "Peer public-key", "text", fieldTooltipOpts("wireguard", "peer_public_key", {
    id: "awg-apply-peer-pubkey",
    testId: "awg-apply-peer-pubkey",
    placeholder: "base64 peer public key",
  }));
  appendFormField(form, "peer_endpoint", "Peer endpoint (host:port)", "text", fieldTooltipOpts("wireguard", "peer_endpoint", {
    id: "awg-apply-peer-endpoint",
    testId: "awg-apply-peer-endpoint",
    placeholder: "vpn.example.com:51820",
  }));
  appendFormField(form, "peer_allow_ips", "Peer allow-ips", "text", fieldTooltipOpts("wireguard", "peer_allow_ips", {
    id: "awg-apply-peer-allow-ips",
    testId: "awg-apply-peer-allow-ips",
    placeholder: "10.0.0.0/24",
  }));
  appendFormField(form, "private_key_credential_ref_id", "Private-key credential_ref_id", "text", fieldTooltipOpts("wireguard", "private_key_credential_ref_id", {
    id: "awg-apply-private-key-ref",
    testId: "awg-apply-private-key-ref",
    placeholder: "credref:…",
  }));

  appendFormCheckbox(form, "confirm_live_apply", "Подтверждаю live apply/teardown на test WireGuard interface", fieldTooltipOpts("wireguard", "confirm_live_apply", {
    id: "awg-apply-confirm",
    testId: "awg-apply-confirm",
    fieldClass: "config-awg-apply-confirm",
  }));

  const advanced = buildAdvancedSettingsBlock({
    testId: "awg-apply-advanced-settings",
    summaryText: "Дополнительные настройки",
  });
  const advancedBody = advanced.body;

  appendFormField(advancedBody, "preshared_key_credential_ref_id", "Preshared-key credential_ref_id (optional)", "text", fieldTooltipOpts("wireguard", "preshared_key_credential_ref_id", {
    id: "awg-apply-psk-ref",
    testId: "awg-apply-psk-ref",
    placeholder: "credref:…",
  }));
  appendFormField(advancedBody, "asc_args_text", "ASC args (9 ints, optional)", "text", fieldTooltipOpts("wireguard", "asc_args", {
    id: "awg-apply-asc-args",
    testId: "awg-apply-asc-args",
    placeholder: "5 42 54 0 0 1 2 3 4",
  }));
  appendFormField(advancedBody, "peer_keepalive_interval", "Peer keepalive (3–3600)", "number", fieldTooltipOpts("wireguard", "peer_keepalive_interval", {
    id: "awg-apply-peer-keepalive",
    testId: "awg-apply-peer-keepalive",
    placeholder: "25",
    min: "3",
    max: "3600",
  }));
  appendFormSelect(
    advancedBody,
    "peer_rci_shape",
    "Peer RCI shape",
    [
      ["nested_rci", "nested RCI (default — device-verified (write accepted) 2026-07-24)"],
      ["path_style", "path-style (legacy — peer write REJECTED on 5.01.C.1.0-0)", true],
    ],
    fieldTooltipOpts("wireguard", "peer_rci_shape", {
      id: "awg-apply-peer-rci-shape",
      testId: "awg-apply-peer-rci-shape",
      honestyNote: HONESTY_WG_PATH_STYLE,
      honestyTestId: "awg-apply-path-style-honesty",
    }),
  );
  appendFormField(
    advancedBody,
    "handshake_settle_seconds",
    "Handshake settle seconds (0 or 20–30)",
    "number",
    fieldTooltipOpts("wireguard", "handshake_settle_seconds", {
      id: "awg-apply-handshake-settle",
      testId: "awg-apply-handshake-settle",
      placeholder: "0",
      min: "0",
      max: "30",
    }),
  );
  appendFormCheckbox(advancedBody, "enabled", "Enabled (interface up)", fieldTooltipOpts("wireguard", "enabled", {
    id: "awg-apply-enabled",
    testId: "awg-apply-enabled",
  }));
  appendFormField(advancedBody, "router_id", "Router ID (optional)", "text", fieldTooltipOpts("wireguard", "router_id", {
    id: "awg-apply-router-id",
    testId: "awg-apply-router-id",
    placeholder: "router-uuid",
  }));

  append(
    advancedBody,
    text(el("h3", "panel-subtitle"), "Live connection (optional — per-request)"),
  );
  appendFormField(advancedBody, "host", "Router host", "text", fieldTooltipOpts("wireguard", "host", {
    id: "awg-apply-host",
    testId: "awg-apply-host",
    placeholder: "192.168.2.1",
  }));
  appendFormField(advancedBody, "username", "SSH username", "text", fieldTooltipOpts("wireguard", "username", {
    id: "awg-apply-username",
    testId: "awg-apply-username",
    placeholder: "admin",
  }));
  appendFormField(advancedBody, "router_credential_ref_id", "Router credential_ref_id", "text", fieldTooltipOpts("wireguard", "router_credential_ref_id", {
    id: "awg-apply-router-cred-ref",
    testId: "awg-apply-router-cred-ref",
    placeholder: "credref:…",
  }));
  appendFormField(advancedBody, "ssh_host_key_sha256", "SSH host key SHA256", "text", fieldTooltipOpts("wireguard", "ssh_host_key_sha256", {
    id: "awg-apply-ssh-pin",
    testId: "awg-apply-ssh-pin",
  }));
  appendFormField(advancedBody, "source_address", "Source address (optional)", "text", fieldTooltipOpts("wireguard", "source_address", {
    id: "awg-apply-source-address",
    testId: "awg-apply-source-address",
    placeholder: "192.168.2.10",
  }));

  form.appendChild(advanced.details);

  const resultPanel = el("div", "config-awg-apply-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "RESULTS / LOGS"));
  const verdictExplanationBox = el("div", "verdict-explanation-wrap");
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, verdictExplanationBox, resultBox);

  function renderResult(data) {
    renderApplyResultWithVerdict(verdictExplanationBox, resultBox, data);
  }

  return {
    panel,
    form,
    advancedDetails: advanced.details,
    resultPanel,
    verdictExplanationBox,
    resultBox,
    readPayload: readAwgApplyPayloadFromDom,
    renderResult,
    wgRangeStart,
  };
}

function readUplinkStationApplyPayloadFromDom(includeConfirm, intentBase) {
  const base = intentBase || {};
  const modeEl = document.getElementById("uplink-station-mode");
  const priorityEl = document.getElementById("uplink-station-priority");
  const authModeEl = document.getElementById("uplink-station-auth-mode");
  const bssidEl = document.getElementById("uplink-station-bssid");
  const settleEl = document.getElementById("uplink-station-settle");
  const hostEl = document.getElementById("uplink-station-host");
  const userEl = document.getElementById("uplink-station-username");
  const routerCredEl = document.getElementById("uplink-station-router-cred-ref");
  const pinEl = document.getElementById("uplink-station-ssh-pin");
  const sourceEl = document.getElementById("uplink-station-source-address");
  const routerIdEl = document.getElementById("uplink-station-router-id");
  const compensateEl = document.getElementById("uplink-station-compensate");
  const idempotentEl = document.getElementById("uplink-station-idempotent");
  const payload = {
    mode: modeEl && modeEl.value ? modeEl.value : base.mode || "WifiWan",
    ssid: base.ssid || "",
    band: base.band || "BAND_2_4GHZ",
    credential_ref_id: base.credential_ref_id || null,
    priority: priorityEl && priorityEl.value ? Number(priorityEl.value) : 100,
    auth_mode: authModeEl && authModeEl.value ? authModeEl.value : "wpa2_psk",
    compensate_on_failure: compensateEl ? compensateEl.checked : true,
    idempotent: !!(idempotentEl && idempotentEl.checked),
  };
  const bssidVal = bssidEl && bssidEl.value ? bssidEl.value.trim() : "";
  if (bssidVal) payload.bssid = bssidVal;
  else if (base.bssid) payload.bssid = base.bssid;
  const settleRaw = settleEl && settleEl.value ? settleEl.value.trim() : "";
  if (settleRaw) {
    const settle = Number(settleRaw);
    if (!Number.isFinite(settle) || settle < 0) {
      throw new Error("uplink_settle_seconds must be >= 0");
    }
    payload.uplink_settle_seconds = settle;
  }
  const hostVal = hostEl && hostEl.value ? hostEl.value.trim() : "";
  const userVal = userEl && userEl.value ? userEl.value.trim() : "";
  const routerCredVal = routerCredEl && routerCredEl.value ? routerCredEl.value.trim() : "";
  const pinVal = pinEl && pinEl.value ? pinEl.value.trim() : "";
  const sourceVal = sourceEl && sourceEl.value ? sourceEl.value.trim() : "";
  const routerIdVal = routerIdEl && routerIdEl.value ? routerIdEl.value.trim() : "";
  if (hostVal) payload.host = hostVal;
  if (userVal) payload.username = userVal;
  if (routerCredVal) payload.router_credential_ref_id = routerCredVal;
  if (pinVal) payload.ssh_host_key_sha256 = pinVal;
  if (sourceVal) payload.source_address = sourceVal;
  if (routerIdVal) payload.router_id = routerIdVal;
  if (includeConfirm) {
    const confirmEl = document.getElementById("uplink-station-confirm");
    payload.confirm_live_apply = !!(confirmEl && confirmEl.checked);
  }
  return payload;
}

function buildUplinkStationApplyFormSurface() {
  const form = el("form", "form-grid uplink-station-apply-form");

  const intentSummary = el("div", "uplink-station-intent-summary");
  intentSummary.setAttribute("data-testid", "uplink-station-intent-summary");
  append(
    intentSummary,
    text(el("p", "field-hint uplink-station-intent-hint"), "Intent из scan + enroll (read-only):"),
  );
  const intentDetails = el("dl", "uplink-station-intent-details");
  intentDetails.setAttribute("data-testid", "uplink-station-intent-details");
  append(form, intentSummary, intentDetails);

  appendFormCheckbox(form, "confirm_live_apply", "Подтверждаю live station apply/teardown (может оборвать текущий uplink)", fieldTooltipOpts("wifi_station", "confirm_live_apply", {
    id: "uplink-station-confirm",
    testId: "uplink-station-confirm",
    fieldClass: "uplink-station-confirm",
  }));

  const advanced = buildAdvancedSettingsBlock({
    testId: "uplink-station-advanced-settings",
    summaryText: "Дополнительные настройки",
  });
  const advancedBody = advanced.body;

  appendFormSelect(
    advancedBody,
    "mode",
    "Station mode",
    [["WifiWan", "WifiWan (единственный поддерживаемый режим)"]],
    fieldTooltipOpts("wifi_station", "mode", {
      id: "uplink-station-mode",
      testId: "uplink-station-mode",
    }),
  );
  appendFormField(advancedBody, "priority", "Priority", "number", fieldTooltipOpts("wifi_station", "priority", {
    id: "uplink-station-priority",
    testId: "uplink-station-priority",
    placeholder: "100",
    min: "0",
    max: "65535",
    step: "1",
  }));
  appendFormSelect(
    advancedBody,
    "auth_mode",
    "Auth mode",
    [
      ["wpa2_psk", "wpa2_psk (default)"],
      ["open", "open — REJECTED (unsupported)", true],
    ],
    fieldTooltipOpts("wifi_station", "auth_mode", {
      id: "uplink-station-auth-mode",
      testId: "uplink-station-auth-mode",
      honestyNote: HONESTY_STATION_AUTH_OPEN,
      honestyTestId: "uplink-station-auth-open-honesty",
    }),
  );
  appendFormField(advancedBody, "bssid", "BSSID override (optional)", "text", fieldTooltipOpts("wifi_station", "bssid", {
    id: "uplink-station-bssid",
    testId: "uplink-station-bssid",
    placeholder: "aa:bb:cc:dd:ee:ff",
  }));
  appendFormField(advancedBody, "uplink_settle_seconds", "Uplink settle (seconds)", "number", fieldTooltipOpts("wifi_station", "uplink_settle_seconds", {
    id: "uplink-station-settle",
    testId: "uplink-station-settle",
    placeholder: "25",
    min: "0",
    max: "120",
    step: "1",
  }));
  append(
    advancedBody,
    text(
      el("p", "field-hint uplink-station-settle-hint"),
      "uplink_settle_seconds: пауза перед observe uplink (live path clamp 20–30s when >0). "
        + "Проверка занимает 20–30 секунд — DHCP + ip global + default route на station.",
    ),
  );
  appendFormField(advancedBody, "router_id", "Router ID (optional)", "text", fieldTooltipOpts("wifi_station", "router_id", {
    id: "uplink-station-router-id",
    testId: "uplink-station-router-id",
    placeholder: "router-uuid",
  }));
  appendFormCheckbox(advancedBody, "compensate_on_failure", "Compensate on failure", fieldTooltipOpts("wifi_station", "compensate_on_failure", {
    id: "uplink-station-compensate",
    testId: "uplink-station-compensate",
  }));
  appendFormCheckbox(advancedBody, "idempotent", "Idempotent apply", fieldTooltipOpts("wifi_station", "idempotent", {
    id: "uplink-station-idempotent",
    testId: "uplink-station-idempotent",
  }));

  append(
    advancedBody,
    text(el("h3", "panel-subtitle"), "Live connection (optional — per-request)"),
  );
  appendFormField(advancedBody, "host", "Router host", "text", fieldTooltipOpts("wifi_station", "host", {
    id: "uplink-station-host",
    testId: "uplink-station-host",
    placeholder: "192.168.2.1",
  }));
  appendFormField(advancedBody, "username", "SSH username", "text", fieldTooltipOpts("wifi_station", "username", {
    id: "uplink-station-username",
    testId: "uplink-station-username",
    placeholder: "admin",
  }));
  appendFormField(advancedBody, "router_credential_ref_id", "Router credential_ref_id", "text", fieldTooltipOpts("wifi_station", "router_credential_ref_id", {
    id: "uplink-station-router-cred-ref",
    testId: "uplink-station-router-cred-ref",
    placeholder: "credref:…",
  }));
  appendFormField(advancedBody, "ssh_host_key_sha256", "SSH host key SHA256", "text", fieldTooltipOpts("wifi_station", "ssh_host_key_sha256", {
    id: "uplink-station-ssh-pin",
    testId: "uplink-station-ssh-pin",
  }));
  appendFormField(advancedBody, "source_address", "Source address (optional)", "text", fieldTooltipOpts("wifi_station", "source_address", {
    id: "uplink-station-source-address",
    testId: "uplink-station-source-address",
    placeholder: "192.168.2.10",
  }));

  form.appendChild(advanced.details);

  function updateIntentSummary(intent) {
    clear(intentDetails);
    if (!intent || typeof intent !== "object") {
      append(intentDetails, text(el("p", "field-hint"), "Выберите сеть из scan и enroll password."));
      return;
    }
    const rows = [
      ["SSID", intent.ssid || "—"],
      ["Band", intent.band || "—"],
      ["credential_ref_id", intent.credential_ref_id || "—"],
      ["BSSID", intent.bssid || "—"],
    ];
    rows.forEach(([dt, dd]) => {
      append(intentDetails, text(el("dt"), dt));
      append(intentDetails, text(el("dd"), dd));
    });
  }

  return {
    form,
    advancedDetails: advanced.details,
    intentSummary,
    intentDetails,
    updateIntentSummary,
    readPayload: readUplinkStationApplyPayloadFromDom,
  };
}

function readLiveConnectionParamsFromDom(idPrefix) {
  const payload = {};
  const hostEl = document.getElementById(idPrefix + "-host");
  const userEl = document.getElementById(idPrefix + "-username");
  const routerCredEl = document.getElementById(idPrefix + "-router-cred-ref");
  const pinEl = document.getElementById(idPrefix + "-ssh-pin");
  const sourceEl = document.getElementById(idPrefix + "-source-address");
  const hostVal = hostEl && hostEl.value ? hostEl.value.trim() : "";
  const userVal = userEl && userEl.value ? userEl.value.trim() : "";
  const routerCredVal = routerCredEl && routerCredEl.value ? routerCredEl.value.trim() : "";
  const pinVal = pinEl && pinEl.value ? pinEl.value.trim() : "";
  const sourceVal = sourceEl && sourceEl.value ? sourceEl.value.trim() : "";
  if (hostVal) payload.host = hostVal;
  if (userVal) payload.username = userVal;
  if (routerCredVal) payload.router_credential_ref_id = routerCredVal;
  if (pinVal) payload.ssh_host_key_sha256 = pinVal;
  if (sourceVal) payload.source_address = sourceVal;
  return payload;
}

function appendLiveConnectionFields(advancedBody, idPrefix, manifestFamily) {
  appendFormField(advancedBody, "host", "Host", "text", fieldTooltipOpts(manifestFamily, "host", {
    id: idPrefix + "-host",
    testId: idPrefix + "-host",
  }));
  appendFormField(advancedBody, "username", "Username", "text", fieldTooltipOpts(manifestFamily, "username", {
    id: idPrefix + "-username",
    testId: idPrefix + "-username",
  }));
  appendFormField(
    advancedBody,
    "router_credential_ref_id",
    "Router credential ref",
    "text",
    fieldTooltipOpts(manifestFamily, "router_credential_ref_id", {
      id: idPrefix + "-router-cred-ref",
      testId: idPrefix + "-router-cred-ref",
    }),
  );
  appendFormField(
    advancedBody,
    "ssh_host_key_sha256",
    "SSH host key SHA256",
    "text",
    fieldTooltipOpts(manifestFamily, "ssh_host_key_sha256", {
      id: idPrefix + "-ssh-pin",
      testId: idPrefix + "-ssh-pin",
    }),
  );
  appendFormField(
    advancedBody,
    "source_address",
    "Source address",
    "text",
    fieldTooltipOpts(manifestFamily, "source_address", {
      id: idPrefix + "-source-address",
      testId: idPrefix + "-source-address",
    }),
  );
}

function formatSiteSurveyResultToast(data) {
  if (!data || typeof data !== "object") {
    return "Site-survey unknown (no result — read-only, not join)";
  }
  const transport = data.transport_security
    ? String(data.transport_security)
    : "fixture/offline";
  const count = Array.isArray(data.networks) ? data.networks.length : 0;
  return "Site-survey OK (" + transport + ", " + count + " networks — read-only, not join)";
}

function formatWifiObservedSessionToast(data) {
  if (!data || typeof data !== "object") {
    return "Observed state unknown (no result — offline-verified only)";
  }
  const transport = data.transport_security
    ? String(data.transport_security)
    : "unknown";
  if (transport === "ssh_tunnel_pinned") {
    return "Observed state refreshed (live read-only session)";
  }
  if (transport === "fixture") {
    return "Observed state refreshed (fixture/offline — offline-verified only)";
  }
  if (data.offline_verified_only === true) {
    return "Observed state refreshed (offline-verified only)";
  }
  return "Observed state refreshed (" + transport + ")";
}

function buildSiteSurveyFormSurface() {
  const form = el("form", "form-grid uplink-scan-form");
  const scanRadioField = el("div", "form-field");
  append(scanRadioField, text(el("label", "", { for: "uplink-scan-radio" }), "Radio / band"));
  const scanRadioSelect = el("select", "", { id: "uplink-scan-radio", name: "scan_radio" });
  scanRadioSelect.setAttribute("data-testid", "uplink-scan-radio");
  [
    ["both", "Both radios (2.4 + 5 GHz)"],
    ["WifiMaster0", "2.4 GHz (WifiMaster0)"],
    ["WifiMaster1", "5 GHz (WifiMaster1)"],
  ].forEach(([val, label]) => {
    const opt = el("option", "", { value: val });
    text(opt, label);
    scanRadioSelect.appendChild(opt);
  });
  append(scanRadioField, scanRadioSelect);
  form.appendChild(scanRadioField);

  const advanced = buildAdvancedSettingsBlock({
    testId: "uplink-scan-advanced-settings",
  });
  appendLiveConnectionFields(advanced.body, "uplink-scan", "wifi_site_survey");
  appendFormCheckbox(
    advanced.body,
    "allow_insecure_http",
    "Allow insecure HTTP",
    fieldTooltipOpts("wifi_site_survey", "allow_insecure_http", {
      id: "uplink-scan-allow-insecure-http",
      testId: "uplink-scan-allow-insecure-http",
    }),
  );
  form.appendChild(advanced.details);

  function readScanMode() {
    const mode = scanRadioSelect.value || "both";
    const radios = mode === "both" ? ["WifiMaster0", "WifiMaster1"] : [mode];
    return { mode, radios };
  }

  function readSurveyBodyForRadio(radio) {
    const body = { radio };
    Object.assign(body, readLiveConnectionParamsFromDom("uplink-scan"));
    const insecureEl = document.getElementById("uplink-scan-allow-insecure-http");
    if (insecureEl && insecureEl.checked) {
      body.allow_insecure_http = true;
    }
    return body;
  }

  return {
    form,
    scanRadioSelect,
    advancedDetails: advanced.details,
    readScanMode,
    readSurveyBodyForRadio,
  };
}

function buildWifiObservedFormSurface(options) {
  const opts = options || {};
  const idPrefix = opts.idPrefix || "wifi-status";
  const apRangeStart = opts.apRangeStart != null ? opts.apRangeStart : 3;
  const apRangeEnd = opts.apRangeEnd != null ? opts.apRangeEnd : 6;
  const form = el("form", "form-grid config-wifi-observed-form");
  if (opts.formTestId) form.setAttribute("data-testid", opts.formTestId);

  const apField = el("div", "form-field");
  append(apField, text(el("label", "", { for: idPrefix + "-ap-id" }), "AP to observe"));
  const apSelect = el("select", "", { id: idPrefix + "-ap-id", name: "ap_id" });
  apSelect.setAttribute("data-testid", idPrefix + "-ap-id");
  ["WifiMaster0", "WifiMaster1"].forEach((master) => {
    for (let n = apRangeStart; n <= apRangeEnd; n += 1) {
      const apId = master + "/AccessPoint" + n;
      const opt = el("option", "", { value: apId });
      text(opt, apId);
      apSelect.appendChild(opt);
    }
  });
  append(apField, apSelect);
  form.appendChild(apField);

  if (opts.showCompare) {
    const compareField = el("div", "form-field");
    append(
      compareField,
      el("input", "", {
        id: idPrefix + "-compare",
        name: "compare_desired",
        type: "checkbox",
        "data-testid": idPrefix + "-compare",
      }),
    );
    append(
      compareField,
      text(
        el("label", "", { for: idPrefix + "-compare" }),
        "Compare to Apply form intent (SSID/WPA/band/enabled)",
      ),
    );
    form.appendChild(compareField);
  }

  const advanced = buildAdvancedSettingsBlock({
    testId: idPrefix + "-advanced-settings",
  });
  appendLiveConnectionFields(advanced.body, idPrefix, "wifi_observed");
  appendFormCheckbox(
    advanced.body,
    "allow_insecure_http",
    "Allow insecure HTTP",
    fieldTooltipOpts("wifi_observed", "allow_insecure_http", {
      id: idPrefix + "-allow-insecure-http",
      testId: idPrefix + "-allow-insecure-http",
    }),
  );
  form.appendChild(advanced.details);

  function readPayload(readDesiredIntent) {
    const apId = apSelect.value || "";
    const payload = { ap_ids: apId ? [apId] : [] };
    Object.assign(payload, readLiveConnectionParamsFromDom(idPrefix));
    const insecureEl = document.getElementById(idPrefix + "-allow-insecure-http");
    if (insecureEl && insecureEl.checked) {
      payload.allow_insecure_http = true;
    }
    if (opts.showCompare && typeof readDesiredIntent === "function") {
      const compareEl = document.getElementById(idPrefix + "-compare");
      if (compareEl && compareEl.checked) {
        const desiredBundle = readDesiredIntent(apId);
        if (desiredBundle) {
          Object.assign(payload, desiredBundle);
        }
      }
    }
    return payload;
  }

  return {
    form,
    apSelect,
    advancedDetails: advanced.details,
    readPayload,
  };
}

function readTrafficEvidenceFromDom() {
  const dstEl = document.getElementById("traffic-evidence-dst");
  const protoEl = document.getElementById("traffic-evidence-proto");
  const jsonEl = document.getElementById("traffic-evidence-json");
  const dst = dstEl && dstEl.value ? dstEl.value.trim() : "";
  const proto = protoEl && protoEl.value ? protoEl.value.trim() : "";
  if (dst || proto) {
    const evidence = {};
    if (dst) evidence.dst = dst;
    if (proto) evidence.proto = proto;
    return evidence;
  }
  try {
    return JSON.parse((jsonEl && jsonEl.value) || "{}");
  } catch (_e) {
    throw new Error("Evidence JSON invalid");
  }
}

function readTrafficRouteIntentFromDom() {
  const prefixEl = document.getElementById("traffic-route-prefix");
  const jsonEl = document.getElementById("traffic-route-intent-json");
  const prefix = prefixEl && prefixEl.value ? prefixEl.value.trim() : "";
  if (prefix) {
    return { prefix };
  }
  try {
    return JSON.parse((jsonEl && jsonEl.value) || "{}");
  } catch (_e) {
    throw new Error("Route intent JSON invalid");
  }
}

function buildTrafficDiscoveryFormSurface() {
  const panel = el("section", "config-section panel config-traffic-discovery");
  append(
    panel,
    text(el("h2", "panel-title"), "TrafficDiscovery (proposals-only)"),
  );
  append(
    panel,
    text(
      el("p", "field-hint config-traffic-discovery-safety"),
      "Только proposals-only: наблюдения и route proposals сохраняются в SQLite. "
        + "Auto-apply всегда заблокирован — apply на роутер через этот UI/API недоступен.",
    ),
  );
  append(
    panel,
    text(
      el("p", "field-hint"),
      "Evidence хешируется (digest only); raw evidence и secrets не возвращаются и не хранятся.",
    ),
  );

  const form = el("form", "form-grid config-traffic-discovery-form");
  appendFormField(form, "router_id", "Router ID", "text", fieldTooltipOpts("traffic_discovery", "router_id", {
    id: "traffic-router-id",
    testId: "traffic-router-id",
    placeholder: "rtr_…",
  }));
  appendFormField(form, "evidence_dst", "Evidence destination", "text", {
    id: "traffic-evidence-dst",
    testId: "traffic-evidence-dst",
    placeholder: "10.0.0.1",
    tooltip: "Human-editable evidence.dst (simple).",
  });
  appendFormField(form, "evidence_proto", "Evidence protocol", "text", {
    id: "traffic-evidence-proto",
    testId: "traffic-evidence-proto",
    placeholder: "tcp",
    tooltip: "Human-editable evidence.proto (simple).",
  });
  appendFormField(form, "traffic_observation_id", "Observation ID (for proposal/get)", "text", fieldTooltipOpts("traffic_discovery", "traffic_observation_id", {
    id: "traffic-observation-id",
    testId: "traffic-observation-id",
    placeholder: "tobs_…",
  }));
  appendFormField(form, "route_prefix", "Route prefix", "text", {
    id: "traffic-route-prefix",
    testId: "traffic-route-prefix",
    placeholder: "10.0.0.0/24",
    tooltip: "Human-editable route_intent.prefix (simple).",
  });
  appendFormField(form, "confidence", "Confidence (0–1)", "number", fieldTooltipOpts("traffic_discovery", "confidence", {
    id: "traffic-confidence",
    testId: "traffic-confidence",
    placeholder: "0.8",
    min: "0",
    max: "1",
    step: "0.01",
  }));
  appendFormField(form, "proposal_id", "Proposal ID (for get)", "text", {
    id: "traffic-proposal-id",
    testId: "traffic-proposal-id",
    placeholder: "prop_…",
  });

  const advanced = buildAdvancedSettingsBlock({
    testId: "traffic-discovery-advanced-settings",
  });
  appendFormField(advanced.body, "source", "Source", "text", fieldTooltipOpts("traffic_discovery", "source", {
    id: "traffic-source",
    testId: "traffic-source",
    value: "offline",
  }));
  appendFormField(advanced.body, "ttl_seconds", "TTL seconds", "number", fieldTooltipOpts("traffic_discovery", "ttl_seconds", {
    id: "traffic-ttl-seconds",
    testId: "traffic-ttl-seconds",
    placeholder: "3600",
    min: "1",
    max: "86400",
  }));
  appendFormTextarea(advanced.body, "evidence_json", "Evidence JSON (advanced fallback)", {
    id: "traffic-evidence-json",
    testId: "traffic-evidence-json",
    rows: 3,
    placeholder: '{"dst":"10.0.0.1","proto":"tcp"}',
    honestyNote: "Используется только если simple dst/proto пусты.",
    honestyTestId: "traffic-evidence-json-honesty",
  });
  appendFormTextarea(advanced.body, "route_intent_json", "Route intent JSON (advanced fallback)", {
    id: "traffic-route-intent-json",
    testId: "traffic-route-intent-json",
    rows: 3,
    placeholder: '{"prefix":"10.0.0.0/24"}',
    honestyNote: "Используется только если route prefix пуст.",
    honestyTestId: "traffic-route-intent-json-honesty",
  });
  appendFormCheckbox(
    advanced.body,
    "trusted_policy",
    "Trusted policy (auto-apply still blocked)",
    fieldTooltipOpts("traffic_discovery", "trusted_policy", {
      id: "traffic-trusted-policy",
      testId: "traffic-trusted-policy",
    }),
  );
  form.appendChild(advanced.details);

  const resultPanel = el("div", "config-traffic-discovery-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "RESULTS / LOGS"));
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, resultBox);

  function renderTrafficResult(data) {
    text(resultBox, data ? JSON.stringify(data, null, 2) : "");
  }

  function readObservationPayload() {
    const routerEl = document.getElementById("traffic-router-id");
    const sourceEl = document.getElementById("traffic-source");
    const routerId = routerEl && routerEl.value ? routerEl.value.trim() : "";
    const sourceVal = sourceEl && sourceEl.value ? sourceEl.value.trim() : "offline";
    const evidence = readTrafficEvidenceFromDom();
    if (!routerId) {
      throw new Error("router_id required");
    }
    return { router_id: routerId, evidence, source: sourceVal || "offline" };
  }

  function readProposalPayload() {
    const obsEl = document.getElementById("traffic-observation-id");
    const confidenceEl = document.getElementById("traffic-confidence");
    const ttlEl = document.getElementById("traffic-ttl-seconds");
    const trustedEl = document.getElementById("traffic-trusted-policy");
    const obsId = obsEl && obsEl.value ? obsEl.value.trim() : "";
    if (!obsId) {
      throw new Error("traffic_observation_id required");
    }
    const routeIntent = readTrafficRouteIntentFromDom();
    const confidenceRaw = confidenceEl && confidenceEl.value ? confidenceEl.value.trim() : "";
    const confidence = confidenceRaw ? Number(confidenceRaw) : NaN;
    if (!Number.isFinite(confidence) || confidence < 0 || confidence > 1) {
      throw new Error("confidence must be number 0..1");
    }
    const ttlRaw = ttlEl && ttlEl.value ? ttlEl.value.trim() : "";
    const ttlSeconds = ttlRaw ? Number(ttlRaw) : 3600;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > 86400) {
      throw new Error("ttl_seconds must be integer 1..86400");
    }
    return {
      traffic_observation_id: obsId,
      route_intent: routeIntent,
      confidence,
      ttl_seconds: ttlSeconds,
      trusted_policy: !!(trustedEl && trustedEl.checked),
    };
  }

  return {
    panel,
    form,
    advancedDetails: advanced.details,
    resultPanel,
    resultBox,
    renderTrafficResult,
    readObservationPayload,
    readProposalPayload,
  };
}

function buildCommissioningCreateFormSurface(defaultRouterId, defaultMode) {
  const form = el("form", "form-grid commissioning-create-form");
  appendFormField(form, "router_id", "Router ID", "text", fieldTooltipOpts("commissioning", "router_id", {
    id: "commissioning-router-id",
    testId: "commissioning-router-id",
    required: true,
    value: defaultRouterId || "",
  }));
  appendFormField(form, "mode", "Mode (override)", "text", fieldTooltipOpts("commissioning", "mode", {
    id: "commissioning-mode",
    testId: "commissioning-mode",
    placeholder: defaultMode || "fake",
  }));
  const asyncField = el("div", "form-field");
  append(
    asyncField,
    el("input", "", {
      id: "commissioning-assess-async",
      name: "assess_async",
      type: "checkbox",
      "data-testid": "commissioning-assess-async",
    }),
  );
  append(
    asyncField,
    text(el("label", "", { for: "commissioning-assess-async" }), "Assess async (202 + worker)"),
  );
  form.appendChild(asyncField);
  return { form };
}

function readCommissioningCreatePayloadFromDom(defaultMode) {
  const routerEl = document.getElementById("commissioning-router-id");
  const modeEl = document.getElementById("commissioning-mode");
  const routerId = routerEl && routerEl.value ? routerEl.value.trim() : "";
  const modeVal = modeEl && modeEl.value ? modeEl.value.trim() : "";
  const payload = { router_id: routerId };
  if (modeVal) payload.mode = modeVal;
  else if (defaultMode) payload.mode = defaultMode;
  return payload;
}

function buildCredentialEnrollTestSurface() {
  const resultBox = el("pre", "mono config-result");
  const valueInput = el("input", "", {
    id: "cred-enroll-value",
    type: "text",
  });
  const mount = el("div", "config-credentials-test-mount");
  mount.appendChild(valueInput);
  function renderEnrollResult(data) {
    text(resultBox, data ? JSON.stringify(data, null, 2) : "");
  }
  return { mount, valueInput, resultBox, renderEnrollResult };
}

function appendFormTextarea(form, name, label, options) {
  const opts = options || {};
  const field = el("div", "form-field");
  if (opts.testId) field.setAttribute("data-testid", opts.testId + "-field");
  const inputId = opts.id || name;
  const labelRow = el("div", "form-field-label-row");
  append(labelRow, text(el("label", "", { for: inputId }), label));
  let tooltipMeta = null;
  if (opts.tooltip) {
    tooltipMeta = buildFieldTooltip({
      id: inputId + "-tooltip",
      text: opts.tooltip,
      testId: opts.testId ? opts.testId + "-tooltip" : undefined,
    });
    append(labelRow, tooltipMeta.wrap);
  }
  append(field, labelRow);
  const textarea = el("textarea", "", {
    id: inputId,
    name: opts.omitName ? undefined : name,
    rows: String(opts.rows || 4),
  });
  if (tooltipMeta) textarea.setAttribute("aria-describedby", tooltipMeta.tooltipId);
  if (opts.testId) textarea.setAttribute("data-testid", opts.testId);
  if (opts.placeholder) textarea.placeholder = opts.placeholder;
  if (opts.value != null && opts.value !== "") textarea.value = String(opts.value);
  append(field, textarea);
  if (opts.honestyNote) appendHonestyNote(field, opts.honestyNote, opts.honestyTestId);
  form.appendChild(field);
  return textarea;
}

function readVpnImportPayloadFromDom(form, includeSecrets) {
  const displayNameEl = form.querySelector("#vpn-import-display-name");
  const kindEl = form.querySelector("#vpn-import-vpn-kind");
  const docEl = form.querySelector("#vpn-import-profile-document");
  const textEl = form.querySelector("#vpn-import-profile-text");
  const privateKeyEl = form.querySelector("#vpn-import-private-key");
  const pskEl = form.querySelector("#vpn-import-preshared-key");
  const payload = {
    display_name: displayNameEl && displayNameEl.value ? displayNameEl.value.trim() : "",
    vpn_kind: kindEl && kindEl.value ? kindEl.value.trim() : "AmneziaWG",
    profile_document: {},
  };
  const docRaw = docEl && docEl.value ? docEl.value.trim() : "";
  if (docRaw) {
    try {
      payload.profile_document = JSON.parse(docRaw);
    } catch (_err) {
      payload.profile_document = {};
    }
  }
  if (textEl && textEl.value && textEl.value.trim()) {
    payload.profile_text = textEl.value.trim();
  }
  if (includeSecrets) {
    if (privateKeyEl && privateKeyEl.value) {
      payload["private" + "_key"] = privateKeyEl.value;
    }
    if (pskEl && pskEl.value) {
      payload["preshared" + "_key"] = pskEl.value;
    }
  }
  return payload;
}

function buildVpnImportFormSurface() {
  const panel = el("section", "config-section panel config-vpn-catalog-import");
  append(panel, text(el("h2", "panel-title"), "VPN catalog import"));
  append(
    panel,
    text(
      el("p", "field-hint config-vpn-import-catalog-honesty"),
      "Catalog import сохраняет metadata в SQLite/vault через POST /vpn-profiles/import — "
        + "это НЕ import/apply на устройство. Sanitized parse-only preview — отдельная панель ниже.",
    ),
  );
  const form = el("form", "form-grid config-vpn-catalog-import-form", { method: "post" });
  appendFormField(form, "display_name", "Display name", "text", fieldTooltipOpts("vpn_profile", "display_name", {
    id: "vpn-import-display-name",
    testId: "vpn-import-display-name",
    required: true,
  }));
  appendFormField(form, "vpn_kind", "VPN kind", "text", fieldTooltipOpts("vpn_profile", "vpn_kind", {
    id: "vpn-import-vpn-kind",
    testId: "vpn-import-vpn-kind",
    placeholder: "AmneziaWG",
  }));
  appendFormTextarea(form, "profile_document", "Profile document (JSON)", fieldTooltipOpts("vpn_profile", "profile_document", {
    id: "vpn-import-profile-document",
    testId: "vpn-import-profile-document",
    rows: 6,
    placeholder: '{"interface":{"listen_port":51820}}',
  }));
  appendFormTextarea(form, "profile_text", "Profile text (.conf, optional)", fieldTooltipOpts("vpn_profile", "profile_text", {
    id: "vpn-import-profile-text",
    testId: "vpn-import-profile-text",
    rows: 4,
    honestyNote: "Для one-shot parse без catalog import используйте панель «VPN/WG parse preview».",
    honestyTestId: "vpn-import-profile-text-honesty",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "vpn-import-advanced-settings",
  });
  appendFormField(advanced.body, "vpn_import_pk", "Private key (write-only)", "password", fieldTooltipOpts("vpn_profile", "private" + "_key", {
    id: "vpn-import-private-key",
    testId: "vpn-import-private-key",
    omitName: true,
  }));
  appendFormField(advanced.body, "vpn_import_psk", "Preshared key (write-only)", "password", fieldTooltipOpts("vpn_profile", "preshared" + "_key", {
    id: "vpn-import-preshared-key",
    testId: "vpn-import-preshared-key",
    omitName: true,
  }));
  form.appendChild(advanced.details);
  const resultPanel = el("div", "config-vpn-catalog-import-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "Import result (metadata only)"));
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, resultBox);
  const btnRow = el("div", "btn-row");
  const importBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "vpn-import-submit",
  });
  text(importBtn, "Import to catalog");
  function renderImportResult(data) {
    text(resultBox, data ? JSON.stringify(data, null, 2) : "");
  }
  function readPayload(includeSecrets) {
    return readVpnImportPayloadFromDom(form, includeSecrets);
  }
  const ui = {
    panel,
    form,
    advancedDetails: advanced.details,
    readPayload,
    resultBox,
    renderImportResult,
    runImport: null,
  };
  async function runImportImpl() {
    const payload = readPayload(true);
    if (!payload.display_name) {
      toast("Укажите display_name");
      return null;
    }
    const privateKeyEl = form.querySelector("#vpn-import-private-key");
    const pskEl = form.querySelector("#vpn-import-preshared-key");
    const textEl = form.querySelector("#vpn-import-profile-text");
    try {
      const { data } = await apiFetch("/vpn-profiles/import", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      if (privateKeyEl) privateKeyEl.value = "";
      if (pskEl) pskEl.value = "";
      if (textEl) textEl.value = "";
      renderImportResult(data);
      APPLY_TOAST_PATHS["P-vpn-import"].toastFromResponse(data);
      return data;
    } catch (e) {
      if (privateKeyEl) privateKeyEl.value = "";
      if (pskEl) pskEl.value = "";
      if (textEl) textEl.value = "";
      toast("Import ошибка: " + e.message);
      return null;
    }
  }
  ui.runImport = runImportImpl;
  importBtn.addEventListener("click", () => {
    ui.runImport();
  });
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    ui.runImport();
  });
  append(btnRow, importBtn);
  append(panel, form, btnRow, resultPanel);
  return ui;
}

function readRciMutationPayloadFromDom(form) {
  const routerEl = form.querySelector("#rci-router-id");
  const opEl = form.querySelector("#rci-operation");
  const ifaceEl = form.querySelector("#rci-interface-id");
  const confirmEl = form.querySelector("#rci-mutation-confirm");
  return {
    router_id: routerEl && routerEl.value ? routerEl.value.trim() : "",
    operation: opEl && opEl.value ? opEl.value : "",
    interface_id: ifaceEl && ifaceEl.value ? ifaceEl.value.trim() : "",
    confirm_rci_mutation: !!(confirmEl && confirmEl.checked),
  };
}

function buildRciMutationFormSurface(options) {
  const opts = options || {};
  const panel = el("section", "config-section panel config-rci-mutation");
  append(panel, text(el("h2", "panel-title"), "Sealed RCI mutations (FAKE)"));
  append(
    panel,
    text(
      el("p", "field-hint config-rci-mutation-safety"),
      "Только typed sealed endpoints (enum operations). FAKE mode + allow_fake_mutations; "
        + "без произвольного RCI CLI. Confirm обязателен. "
        + "Succeeded = synthetic SQLite ack (_FakeRciTransport) — NOT live device RCI.",
    ),
  );
  const form = el("form", "form-grid config-rci-mutation-form");
  appendFormField(form, "router_id", "Router ID", "text", {
    id: "rci-router-id",
    testId: "rci-router-id",
    placeholder: "rtr_…",
  });
  appendFormSelect(
    form,
    "operation",
    "Sealed operation",
    buildRciOperationOptionsFromManifest(),
    fieldTooltipOpts("rci_sealed", "operation", {
      id: "rci-operation",
      testId: "rci-operation",
      honestyNote:
        "UI выбирает sealed endpoint; тело запроса и маршрут — из manifest (body_operation_by_value, route_key_by_value).",
      honestyTestId: "rci-operation-honesty",
    }),
  );
  const advanced = buildAdvancedSettingsBlock({
    testId: "rci-mutation-advanced-settings",
  });
  appendFormField(advanced.body, "interface_id", "Interface ID (interface up/down)", "text", fieldTooltipOpts("rci_sealed", "interface_id", {
    id: "rci-interface-id",
    testId: "rci-interface-id",
    placeholder: "GigabitEthernet0",
  }));
  form.appendChild(advanced.details);
  appendFormCheckbox(form, "confirm_rci_mutation", "Подтверждаю sealed RCI mutation (особенно save/reboot)", {
    id: "rci-mutation-confirm",
    testId: "rci-mutation-confirm",
    fieldClass: "config-rci-mutation-confirm",
    honestyNote:
      "FAKE transport: Succeeded = synthetic SQLite ack (_FakeRciTransport) — NOT live device RCI.",
    honestyTestId: "rci-mutation-confirm-honesty",
  });
  const resultPanel = el("div", "config-rci-mutation-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "RESULTS / LOGS"));
  const resultBox = el("pre", "mono config-result");
  append(resultPanel, resultBox);
  const rciRouterEl = form.querySelector("#rci-router-id");
  if (rciRouterEl && opts.defaultRouterId) {
    rciRouterEl.value = opts.defaultRouterId;
  }
  function renderRciResult(data) {
    text(resultBox, data ? JSON.stringify(data, null, 2) : "");
  }
  function readPayload() {
    return readRciMutationPayloadFromDom(form);
  }
  async function runRciMutation() {
    const payload = readPayload();
    if (!payload.router_id) {
      toast("Укажите router_id");
      return;
    }
    if (!payload.confirm_rci_mutation) {
      toast("Требуется confirm для RCI mutation");
      return;
    }
    const resolved = resolveRciMutationRequest(payload);
    if (resolved.error) {
      toast(resolved.error);
      return;
    }
    try {
      const { data } = await apiFetch(resolved.path, {
        method: "POST",
        body: resolved.body,
        idempotencyKey: uuid(),
      });
      renderRciResult(data);
      toast(
        "RCI FAKE ack (not device): "
          + (data.status || "ok")
          + " — sealed endpoint only, adapter_mode=fake; Succeeded = SQLite synthetic ack",
      );
    } catch (e) {
      toast("RCI ошибка: " + e.message);
    }
  }
  const rciBtnRow = el("div", "btn-row");
  const rciExecuteBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "rci-mutation-submit",
  });
  text(rciExecuteBtn, "Execute sealed mutation");
  rciExecuteBtn.addEventListener("click", runRciMutation);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runRciMutation();
  });
  append(rciBtnRow, rciExecuteBtn);
  append(panel, form, rciBtnRow, resultPanel);
  return {
    panel,
    form,
    advancedDetails: advanced.details,
    readPayload,
    resultBox,
    renderRciResult,
    runRciMutation,
  };
}

function readWizardDraftPayloadFromDom(form, includeSecret) {
  const hostEl = form.querySelector("#wizard-host");
  const userEl = form.querySelector("#wizard-username");
  const secretEl = form.querySelector("#wizard-secret");
  const nameEl = form.querySelector("#wizard-display-name");
  const portEl = form.querySelector("#wizard-port");
  const insecureEl = form.querySelector("#wizard-insecure-http");
  const sourceEl = form.querySelector("#wizard-source-address");
  const payload = {
    host: hostEl && hostEl.value ? hostEl.value.trim() : "",
    username: userEl && userEl.value ? userEl.value.trim() : "admin",
    display_name: nameEl && nameEl.value ? nameEl.value.trim() : "",
    port: portEl && portEl.value ? portEl.value.trim() : "",
    allow_insecure_http: !!(insecureEl && insecureEl.checked),
  };
  if (sourceEl && sourceEl.value && sourceEl.value.trim()) {
    payload.source_address = sourceEl.value.trim();
  }
  if (includeSecret && secretEl && secretEl.value) {
    payload.secret = secretEl.value;
  }
  return payload;
}

function buildWizardDraftFormSurface(options) {
  const surfaceOpts = options || {};
  const isSimple = surfaceOpts.disclosure === "simple";
  const form = el("form", "form-grid wizard-form", { method: "post" });
  if (!isSimple) {
    append(
      form,
      text(
        el("p", "field-hint"),
        "Пароль отправляется one-shot в vault (поле secret); после отправки очищается.",
      ),
    );
  }
  appendFormField(form, "host", "Адрес роутера", "text", fieldTooltipOpts("wizard_draft", "host", {
    id: "wizard-host",
    testId: "wizard-host",
    placeholder: "192.168.2.1 или http://192.168.2.1",
    required: true,
  }));
  appendFormField(form, "username", "Имя пользователя", "text", fieldTooltipOpts("wizard_draft", "username", {
    id: "wizard-username",
    testId: "wizard-username",
    placeholder: "admin",
    required: true,
  }));
  appendFormField(
    form,
    "secret",
    isSimple ? "Пароль" : "Пароль (one-shot → vault)",
    "password",
    fieldTooltipOpts("wizard_draft", "secret", {
      id: "wizard-secret",
      testId: "wizard-secret",
      placeholder: isSimple ? "введите пароль" : "не сохраняется после отправки",
      omitName: true,
      required: true,
    }),
  );
  const advanced = buildAdvancedSettingsBlock({
    testId: "wizard-draft-advanced-settings",
  });
  if (!isSimple) {
    appendFormField(form, "display_name", "Отображаемое имя (необязательно)", "text", fieldTooltipOpts("wizard_draft", "display_name", {
      id: "wizard-display-name",
      testId: "wizard-display-name",
      placeholder: "Lab router",
    }));
  } else {
    appendFormField(advanced.body, "display_name", "Отображаемое имя (необязательно)", "text", fieldTooltipOpts("wizard_draft", "display_name", {
      id: "wizard-display-name",
      testId: "wizard-display-name",
      placeholder: "Lab router",
    }));
  }
  appendFormField(advanced.body, "port", "Порт (необязательно)", "text", fieldTooltipOpts("wizard_draft", "port", {
    id: "wizard-port",
    testId: "wizard-port",
    placeholder: "80 или 443",
  }));
  appendFormCheckbox(
    advanced.body,
    "allow_insecure_http",
    "Разрешить HTTP (plain)",
    fieldTooltipOpts("wizard_draft", "allow_insecure_http", {
      id: "wizard-insecure-http",
      testId: "wizard-insecure-http",
    }),
  );
  appendFormField(advanced.body, "source_address", "Source address (learn, optional)", "text", fieldTooltipOpts("ssh_host_key", "source_address", {
    id: "wizard-source-address",
    testId: "wizard-source-address",
  }));
  form.appendChild(advanced.details);
  return {
    form,
    advancedDetails: advanced.details,
    readPayload: (includeSecret) => readWizardDraftPayloadFromDom(form, includeSecret),
  };
}

function buildWizardSshHostKeyLearnBody(wizardState) {
  const state = wizardState || {};
  const learnBody = {
    host: String(state.host || "").replace(/^https?:\/\//, ""),
    port: state.port ? parseInt(state.port, 10) : 22,
  };
  if (state.sourceAddress) {
    learnBody.source_address = state.sourceAddress;
  }
  return learnBody;
}

function buildWizardSshHostKeyConfirmBody(confirmPayload) {
  const payload = confirmPayload || {};
  return {
    fingerprint_sha256: payload.fingerprint_sha256 || "",
    algorithm: payload.algorithm || "",
    allow_overwrite: !!payload.allow_overwrite,
  };
}

function readWizardHostKeyConfirmPayloadFromDom(form) {
  const fpEl = form.querySelector("#wizard-confirm-fp");
  const algEl = form.querySelector("#wizard-confirm-alg");
  const overwriteEl = form.querySelector("#wizard-allow-overwrite");
  return {
    fingerprint_sha256: fpEl && fpEl.value ? fpEl.value.trim() : "",
    algorithm: algEl && algEl.value ? algEl.value.trim() : "",
    allow_overwrite: !!(overwriteEl && overwriteEl.checked),
  };
}

function buildWizardHostKeyConfirmFormSurface() {
  const form = el("form", "form-grid wizard-form", { method: "post" });
  appendFormField(form, "confirm_fingerprint", "Подтвердите отпечаток SHA256 (точно)", "text", fieldTooltipOpts("ssh_host_key", "fingerprint_sha256", {
    id: "wizard-confirm-fp",
    testId: "wizard-confirm-fp",
  }));
  appendFormField(form, "confirm_algorithm", "Подтвердите алгоритм (точно)", "text", fieldTooltipOpts("ssh_host_key", "algorithm", {
    id: "wizard-confirm-alg",
    testId: "wizard-confirm-alg",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "wizard-confirm-advanced-settings",
  });
  appendFormCheckbox(
    advanced.body,
    "allow_overwrite",
    "Разрешить перезапись существующего pin",
    fieldTooltipOpts("ssh_host_key", "allow_overwrite", {
      id: "wizard-allow-overwrite",
      testId: "wizard-allow-overwrite",
      honestyNote: "Опасно: перезаписывает сохранённый SSH host key pin без повторного learn.",
      honestyTestId: "wizard-allow-overwrite-danger",
    }),
  );
  form.appendChild(advanced.details);
  return {
    form,
    advancedDetails: advanced.details,
    readPayload: () => readWizardHostKeyConfirmPayloadFromDom(form),
  };
}

function collectDomVisibleText(root) {
  const parts = [];
  function walk(node, insideClosedDetails) {
    if (!node || typeof node !== "object") return;
    if (node.hidden) return;
    if (node.tagName === "DETAILS") {
      if (!node.open) {
        for (const child of node.children || []) {
          if (child.tagName === "SUMMARY") walk(child, false);
        }
        return;
      }
      insideClosedDetails = false;
    }
    if (insideClosedDetails) return;
    if (node.tagName === "INPUT" || node.tagName === "SELECT") {
      if (node.value) parts.push(String(node.value));
      return;
    }
    if (node.textContent) parts.push(node.textContent);
    for (const child of node.children || []) {
      walk(child, insideClosedDetails);
    }
  }
  walk(root, false);
  return parts.join("\n");
}

function domHasMisleadingApplySuccessText(data, visibleText) {
  const honesty = wifiApplyHonestySummary(data);
  const blob = (visibleText || "") + "\n" + honesty;
  const lower = blob.toLowerCase();
  const misleading = [
    "on-air verified (link up)",
    "verified on-air",
    "configuration applied",
    "success",
  ];
  if (
    data
    && data.overall === "applied"
    && data.on_air_verification_status === "on_air_verified"
  ) {
    return false;
  }
  return misleading.some((phrase) => {
    if (phrase === "success" && lower.includes("not success")) return false;
    return lower.includes(phrase);
  });
}

async function renderConfig(root) {
  renderSkeleton(root);
  try {
    await loadFieldManifest();
    const status = await loadStatus();
    const routersResp = await apiFetch("/routers");
    const firstRouterId =
      routersResp.data.items && routersResp.data.items.length
        ? routersResp.data.items[0].router_id
        : "";
    clear(root);
    append(
      root,
      pageHeader(
        "Настройки роутера",
        "Read-only обзор, VPN-каталог, Wi-Fi/DNS validate/preview; bounded Wi-Fi/AWG test Apply — confirm + connection",
      ),
    );
    append(root, configApplyBanner(status));

    const overview = el("section", "config-section panel");
    append(overview, text(el("h2", "panel-title"), "Обзор (read-only)"));
    const overviewGrid = el("div", "card-grid");
    [
      ["Feature state", status.feature_state],
      ["Gate A", gateADisplay(status)],
      ["Gate B", (status.write_gates && status.write_gates.gate_b) || "closed"],
      ["Write certified", status.write_gates && status.write_gates.write_certified ? "yes" : "no"],
    ].forEach(([title, val]) => {
      const card = el("article", "card");
      append(card, text(el("h3", "card-title"), title));
      append(card, text(el("p", "card-value"), val == null ? "N/A" : String(val)));
      overviewGrid.appendChild(card);
    });
    append(overview, overviewGrid);

    const ifacePanel = el("div", "panel config-subpanel");
    append(ifacePanel, text(el("h3", "panel-title"), "Наблюдаемые интерфейсы"));
    const ifaceResp = await apiFetch("/observed-interfaces");
    const ifaceItems = ifaceResp.data.items || [];
    if (ifaceItems.length === 0) {
      const note = ifaceResp.data.note || "нет данных, требуется observe";
      append(ifacePanel, text(el("p", "empty-state"), note));
    } else {
      if (ifaceResp.data.artifact_name) {
        append(
          ifacePanel,
          text(el("p", "field-hint"), "Artifact: " + ifaceResp.data.artifact_name),
        );
      }
      const table = el("table", "data-table");
      const hr = el("tr");
      ["ID hash", "Role", "Type", "Link", "Connected"].forEach((h) => {
        hr.appendChild(text(el("th"), h));
      });
      const tbody = el("tbody");
      ifaceItems.forEach((row) => {
        const tr = el("tr");
        append(tr, text(el("td", "mono"), row.interface_id_hash || row.id_hash || "—"));
        append(tr, text(el("td"), row.role || "—"));
        append(tr, text(el("td"), row.interface_type || row.type || "—"));
        append(tr, text(el("td"), row.link_up != null ? String(row.link_up) : row.link || "—"));
        append(tr, text(el("td"), row.connected != null ? String(row.connected) : "—"));
        tbody.appendChild(tr);
      });
      append(table, hr, tbody);
      const wrap = el("div", "table-wrap");
      wrap.appendChild(table);
      append(ifacePanel, wrap);
    }
    append(overview, ifacePanel);
    append(root, overview);

    const vpnPanel = el("section", "config-section panel");
    append(vpnPanel, text(el("h2", "panel-title"), "VPN-профили"));
    append(
      vpnPanel,
      text(
        el("p", "field-hint"),
        "Каталог ниже — metadata only. Catalog import — панель «VPN catalog import»; "
          + "sanitized .conf preview — «VPN/WG parse preview (vault only)».",
      ),
    );
    const vpnResp = await apiFetch("/vpn-profiles");
    const vpnItems = vpnResp.data.items || [];
    if (vpnItems.length === 0) {
      append(vpnPanel, text(el("p", "empty-state"), "Профили не импортированы"));
    } else {
      const vpnTable = el("table", "data-table");
      const vpnHr = el("tr");
      ["ID", "Имя", "Kind", "Validation", "Digest"].forEach((h) => {
        vpnHr.appendChild(text(el("th"), h));
      });
      const vpnBody = el("tbody");
      vpnItems.forEach((row) => {
        const tr = el("tr");
        append(tr, text(el("td", "mono"), row.profile_id));
        append(tr, text(el("td"), row.display_name));
        append(tr, text(el("td"), row.vpn_kind));
        append(tr, text(el("td"), row.validation_status));
        append(tr, text(el("td", "mono"), row.content_digest || "—"));
        vpnBody.appendChild(tr);
      });
      append(vpnTable, vpnHr, vpnBody);
      const vpnWrap = el("div", "table-wrap");
      vpnWrap.appendChild(vpnTable);
      append(vpnPanel, vpnWrap);
    }
    append(root, vpnPanel);

    const credPanel = el("section", "config-section panel config-credentials");
    append(credPanel, text(el("h2", "panel-title"), "Credential refs (vault metadata)"));
    append(
      credPanel,
      text(
        el("p", "field-hint config-credentials-safety"),
        "Enroll отправляет значение one-shot в DPAPI/vault; UI показывает только credential_ref_id и metadata. "
          + "Секрет не рендерится, не логируется и не сохраняется в DOM после успешного enroll.",
      ),
    );
    const credForm = el("form", "form-grid config-credentials-form");
    appendFormField(credForm, "router_id", "Router ID", "text", {
      id: "cred-router-id",
      placeholder: "rtr_…",
    });
    const credKindField = el("div", "form-field");
    append(credKindField, text(el("label", "", { for: "cred-enroll-kind" }), "Kind (enroll)"));
    const credKindSelect = el("select", "", { id: "cred-enroll-kind", name: "kind" });
    [
      ["RouterManagementPassword", "RouterManagementPassword"],
    ].forEach(([val, label]) => {
      const opt = el("option", "", { value: val });
      text(opt, label);
      credKindSelect.appendChild(opt);
    });
    append(credKindField, credKindSelect);
    credForm.appendChild(credKindField);
    appendFormField(credForm, "enroll_value", "Credential value (one-shot → vault)", "text", {
      id: "cred-enroll-value",
      placeholder: "не отображается после enroll",
      omitName: true,
    });
    appendFormField(credForm, "revoke_ref_id", "Revoke credential_ref_id", "text", {
      id: "cred-revoke-ref-id",
      placeholder: "cred_…",
    });
    const credListHost = el("div", "config-credentials-list panel-sub");
    append(credListHost, text(el("h3", "panel-subtitle"), "Список refs (metadata only)"));
    const credTableWrap = el("div", "table-wrap");
    credListHost.appendChild(credTableWrap);
    const credResultPanel = el("div", "config-credentials-result panel-sub");
    append(credResultPanel, text(el("h3", "panel-subtitle"), "RESULTS / LOGS"));
    const credResultBox = el("pre", "mono config-result");
    append(credResultPanel, credResultBox);
    const credRouterEl = credForm.querySelector("#cred-router-id");
    if (credRouterEl && firstRouterId) {
      credRouterEl.value = firstRouterId;
    }

    function renderCredList(items) {
      clear(credTableWrap);
      if (!items || items.length === 0) {
        append(credTableWrap, text(el("p", "empty-state"), "Нет credential refs"));
        return;
      }
      const table = el("table", "data-table");
      const hr = el("tr");
      ["credential_ref_id", "kind", "provider", "created_at", "revoked_at"].forEach((h) => {
        hr.appendChild(text(el("th"), h));
      });
      const tbody = el("tbody");
      items.forEach((row) => {
        const tr = el("tr");
        append(tr, text(el("td", "mono"), row.credential_ref_id || "—"));
        append(tr, text(el("td"), row.kind || "—"));
        append(tr, text(el("td"), row.provider || "—"));
        append(tr, text(el("td"), row.created_at || "—"));
        append(tr, text(el("td"), row.revoked_at || "—"));
        tbody.appendChild(tr);
      });
      append(table, hr, tbody);
      credTableWrap.appendChild(table);
    }

    function renderCredResult(data) {
      text(credResultBox, JSON.stringify(data, null, 2));
    }

    async function loadCredentialList() {
      const routerEl = document.getElementById("cred-router-id");
      const routerId = routerEl && routerEl.value ? routerEl.value.trim() : "";
      if (!routerId) {
        toast("Укажите router_id");
        return;
      }
      try {
        const { data } = await apiFetch(
          "/routers/" + encodeURIComponent(routerId) + "/credentials",
        );
        renderCredList(data.items || []);
        renderCredResult(data);
        toast("Credentials loaded");
      } catch (e) {
        toast("List ошибка: " + e.message);
      }
    }

    const credBtnRow = el("div", "btn-row");
    const credListBtn = el("button", "btn btn-secondary", { type: "button" });
    text(credListBtn, "Refresh list");
    credListBtn.addEventListener("click", () => {
      loadCredentialList();
    });
    async function runCredentialEnroll() {
      const routerEl = document.getElementById("cred-router-id");
      const kindEl = document.getElementById("cred-enroll-kind");
      const valueEl = document.getElementById("cred-enroll-value");
      const routerId = routerEl && routerEl.value ? routerEl.value.trim() : "";
      const enrollValue = valueEl && valueEl.value ? valueEl.value : "";
      const kind = kindEl && kindEl.value ? kindEl.value : "RouterManagementPassword";
      if (!routerId || !enrollValue) {
        toast("router_id и credential value обязательны");
        return;
      }
      try {
        const { data } = await apiFetch(
          "/routers/" + encodeURIComponent(routerId) + "/credentials",
          {
            method: "PUT",
            body: { kind: kind, secret: enrollValue },
            idempotencyKey: uuid(),
          },
        );
        if (valueEl) valueEl.value = "";
        renderCredResult(data);
        toast("Enrolled: " + (data.credential_ref_id || "ok"));
        await loadCredentialList();
      } catch (e) {
        if (valueEl) valueEl.value = "";
        toast("Enroll ошибка: " + e.message);
      }
    }
    credForm.addEventListener("submit", (ev) => {
      ev.preventDefault();
      runCredentialEnroll();
    });
    const credEnrollBtn = el("button", "btn btn-primary", { type: "button" });
    text(credEnrollBtn, "Enroll (PUT)");
    credEnrollBtn.addEventListener("click", () => {
      runCredentialEnroll();
    });
    const credRevokeBtn = el("button", "btn btn-secondary", { type: "button" });
    text(credRevokeBtn, "Revoke (POST)");
    credRevokeBtn.addEventListener("click", async () => {
      const routerEl = document.getElementById("cred-router-id");
      const refEl = document.getElementById("cred-revoke-ref-id");
      const routerId = routerEl && routerEl.value ? routerEl.value.trim() : "";
      const refId = refEl && refEl.value ? refEl.value.trim() : "";
      if (!routerId || !refId) {
        toast("router_id и credential_ref_id обязательны");
        return;
      }
      try {
        const { data } = await apiFetch(
          "/routers/"
            + encodeURIComponent(routerId)
            + "/credentials/"
            + encodeURIComponent(refId)
            + "/revoke",
          { method: "POST", body: {}, idempotencyKey: uuid() },
        );
        renderCredResult(data);
        toast("Revoke accepted");
        await loadCredentialList();
      } catch (e) {
        toast("Revoke ошибка: " + e.message);
      }
    });
    append(credBtnRow, credListBtn, credEnrollBtn, credRevokeBtn);
    append(credPanel, credForm, credBtnRow, credListHost, credResultPanel);
    append(root, credPanel);
    if (firstRouterId) {
      loadCredentialList();
    }

    append(root, buildVpnImportFormSurface().panel);

    const vpnImportPanel = el("section", "config-section panel config-vpn-import");
    append(vpnImportPanel, text(el("h2", "panel-title"), "VPN/WG parse preview (vault only)"));
    append(
      vpnImportPanel,
      text(
        el("p", "field-hint config-vpn-import-safety"),
        "Parse-only: вставьте AmneziaWG .conf — сервер парсит один раз через /vpn-profiles/parse-preview, "
          + "кладёт ключи в DPAPI/vault и возвращает только sanitized preview "
          + "(credential_ref_id + имена полей). Это не catalog import и не apply на устройство.",
      ),
    );
    append(
      vpnImportPanel,
      text(
        el("p", "field-hint"),
        "Подсказка: credential_ref_id из preview можно вставить в поля AWG Apply ниже. "
          + "Для catalog import используйте панель «VPN catalog import» выше.",
      ),
    );
    const vpnImportForm = el("form", "form-grid config-vpn-import-form");
    const vpnTextField = el("div", "form-field");
    append(
      vpnTextField,
      text(el("label", "", { for: "vpn-parse-preview-text" }), "Profile text (.conf)"),
    );
    const vpnTextarea = el("textarea", "", {
      id: "vpn-parse-preview-text",
      rows: "8",
      "data-testid": "vpn-parse-preview-text",
    });
    append(vpnTextField, vpnTextarea);
    vpnImportForm.appendChild(vpnTextField);
    const vpnImportResultPanel = el("div", "config-vpn-import-result panel-sub");
    append(vpnImportResultPanel, text(el("h3", "panel-subtitle"), "Sanitized preview"));
    const vpnImportResultBox = el("pre", "mono config-result");
    append(vpnImportResultPanel, vpnImportResultBox);
    const vpnImportBtnRow = el("div", "btn-row");
    async function runVpnImportPreview() {
      const textEl = document.getElementById("vpn-parse-preview-text");
      const profileText = textEl && textEl.value ? textEl.value : "";
      if (!profileText.trim()) {
        toast("Вставьте profile text");
        return;
      }
      try {
        const { data } = await apiFetch("/vpn-profiles/parse-preview", {
          method: "POST",
          body: { profile_text: profileText },
        });
        if (textEl) textEl.value = "";
        text(vpnImportResultBox, JSON.stringify(data, null, 2));
        toast("Parse preview: credential_refs=" + (data.credential_refs || []).length + " (vault only, not device)");
      } catch (e) {
        if (textEl) textEl.value = "";
        toast("Parse ошибка: " + e.message);
      }
    }
    vpnImportForm.addEventListener("submit", (ev) => {
      ev.preventDefault();
      runVpnImportPreview();
    });
    const vpnImportBtn = el("button", "btn btn-primary", { type: "button" });
    text(vpnImportBtn, "Parse preview");
    vpnImportBtn.addEventListener("click", () => {
      runVpnImportPreview();
    });
    append(vpnImportBtnRow, vpnImportBtn);
    append(vpnImportPanel, vpnImportForm, vpnImportBtnRow, vpnImportResultPanel);
    append(root, vpnImportPanel);

    append(root, buildVpnPolicyPreviewFormSurface().panel);
    append(root, buildVlanPreviewFormSurface().panel);
    append(root, buildDhcpPreviewFormSurface().panel);
    append(root, buildDnsPreviewFormSurface().panel);
    append(root, buildFirewallPreviewFormSurface().panel);

    const wifiPanel = el("section", "config-section panel");
    append(
      wifiPanel,
      text(el("h2", "panel-title"), "Wi-Fi / DNS — локальный черновик + preset validate/preview"),
    );
    append(
      wifiPanel,
      text(
        el("p", "field-hint"),
        "Поля формы — локальный черновик intent (не применён, не отправлен на роутер). "
          + "Validate/Plan preview отправляют только preset id — поля черновика не участвуют в запросах.",
      ),
    );
    append(
      wifiPanel,
      text(
        el("p", "field-hint"),
        "write_ready всегда false — preset Apply/live-write закрыты; bounded Wi-Fi/AWG test Apply — отдельные панели ниже.",
      ),
    );
    const siteId = sessionMemory.siteId || status.default_site_id;
    const presetList = await apiFetch("/sites/" + encodeURIComponent(siteId) + "/event-presets");
    const presets = presetList.data.items || [];
    const form = el("form", "form-grid config-wifi-form");
    const presetField = el("div", "form-field");
    append(presetField, text(el("label", "", { for: "config-preset-id" }), "Event preset"));
    const presetSelect = el("select", "", { id: "config-preset-id", name: "preset_id" });
    const emptyOpt = el("option", "", { value: "" });
    text(emptyOpt, presets.length ? "— выберите пресет —" : "нет пресетов");
    presetSelect.appendChild(emptyOpt);
    presets.forEach((p) => {
      const opt = el("option", "", { value: p.preset_id });
      text(opt, p.name + " (" + p.preset_id + ")");
      presetSelect.appendChild(opt);
    });
    append(presetField, presetSelect);
    form.appendChild(presetField);

    appendFormField(form, "wifi_ssid", "Wi-Fi SSID", "text", { id: "config-wifi-ssid" });
    appendFormField(form, "credential_ref_id", "CredentialRef (ID only)", "text", {
      id: "config-cred-ref",
    });
    const enabledField = el("div", "form-field");
    append(
      enabledField,
      el("input", "", { id: "config-wifi-enabled", name: "wifi_enabled", type: "checkbox" }),
    );
    append(enabledField, text(el("label", "", { for: "config-wifi-enabled" }), "Wi-Fi enabled"));
    form.appendChild(enabledField);

    const captiveField = el("div", "form-field");
    append(captiveField, text(el("label", "", { for: "config-captive" }), "Captive portal"));
    const captiveSelect = el("select", "", { id: "config-captive", name: "captive_portal" });
    ["Disabled", "Enabled"].forEach((val) => {
      const opt = el("option", "", { value: val });
      text(opt, val);
      captiveSelect.appendChild(opt);
    });
    append(captiveField, captiveSelect);
    form.appendChild(captiveField);

    appendFormField(form, "dns_local_fqdn", "DNS local FQDN", "text", { id: "config-dns-fqdn" });

    const draftPanel = el("div", "config-draft panel-sub");
    append(
      draftPanel,
      text(
        el("h3", "panel-subtitle"),
        "Локальный черновик intent — только preview в UI, не отправляется на сервер",
      ),
    );
    const draftBody = el("div", "config-draft-body");
    append(draftPanel, draftBody);

    const serverResultPanel = el("div", "config-server-result panel-sub");
    append(
      serverResultPanel,
      text(el("h3", "panel-subtitle"), "Ответ сервера (validate/preview выбранного preset)"),
    );
    const resultBox = el("pre", "mono config-result");
    append(serverResultPanel, resultBox);

    function readWifiDnsDraft() {
      const ssidEl = document.getElementById("config-wifi-ssid");
      const credEl = document.getElementById("config-cred-ref");
      const enabledEl = document.getElementById("config-wifi-enabled");
      const captiveEl = document.getElementById("config-captive");
      const fqdnEl = document.getElementById("config-dns-fqdn");
      return {
        wifi_ssid: ssidEl && ssidEl.value ? ssidEl.value : "",
        credential_ref_id: credEl && credEl.value ? credEl.value : "",
        wifi_enabled: !!(enabledEl && enabledEl.checked),
        captive_portal: captiveEl && captiveEl.value ? captiveEl.value : "",
        dns_local_fqdn: fqdnEl && fqdnEl.value ? fqdnEl.value : "",
      };
    }

    function renderWifiDnsDraft(draft) {
      clear(draftBody);
      const rows = [
        ["Wi-Fi SSID", draft.wifi_ssid || "—"],
        ["CredentialRef (ID only)", draft.credential_ref_id || "—"],
        ["Wi-Fi enabled", draft.wifi_enabled ? "true" : "false"],
        ["Captive portal", draft.captive_portal || "—"],
        ["DNS local FQDN", draft.dns_local_fqdn || "—"],
      ];
      rows.forEach(([label, value]) => {
        const row = el("p", "config-draft-row");
        append(row, text(el("span", "config-draft-label"), label + ": "), text(el("span"), value));
        draftBody.appendChild(row);
      });
    }

    append(wifiPanel, form, draftPanel);

    const btnRow = el("div", "btn-row");
    const validateBtn = el("button", "btn btn-secondary", { type: "button" });
    text(validateBtn, "Validate preset");
    validateBtn.addEventListener("click", async () => {
      const presetId = presetSelect.value;
      if (!presetId) {
        toast("Выберите preset");
        return;
      }
      renderWifiDnsDraft(readWifiDnsDraft());
      try {
        const { data } = await apiFetch("/event-presets/" + encodeURIComponent(presetId) + "/validate", {
          method: "POST",
          idempotencyKey: uuid(),
        });
        text(resultBox, JSON.stringify(data, null, 2));
        toast("Validation preset " + presetId + ": write_ready=" + data.write_ready);
      } catch (e) {
        toast("Validate ошибка: " + e.message);
      }
    });
    const previewBtn = el("button", "btn btn-secondary", { type: "button" });
    text(previewBtn, "Plan preview preset");
    previewBtn.addEventListener("click", async () => {
      const presetId = presetSelect.value;
      if (!presetId) {
        toast("Выберите preset");
        return;
      }
      renderWifiDnsDraft(readWifiDnsDraft());
      try {
        const { data } = await apiFetch(
          "/event-presets/" + encodeURIComponent(presetId) + "/plan-preview",
          { method: "POST", idempotencyKey: uuid() },
        );
        text(resultBox, JSON.stringify(data, null, 2));
        toast("Plan preview preset " + presetId + ": write_ready=" + data.write_ready);
      } catch (e) {
        toast("Plan ошибка: " + e.message);
      }
    });
    append(btnRow, validateBtn, previewBtn);
    append(wifiPanel, btnRow, serverResultPanel);
    append(root, wifiPanel);

    const wifiApplyUi = buildWifiApplyFormSurface();
    const wifiApplyPanel = wifiApplyUi.panel;
    const wifiApplyForm = wifiApplyUi.form;
    const wifiApplyResultPanel = wifiApplyUi.resultPanel;
    const readWifiApplyPayload = wifiApplyUi.readPayload;
    const renderWifiApplyResult = wifiApplyUi.renderResult;
    const { apRangeStart, apRangeEnd } = wifiApplyUi;

    const wifiApplyBtnRow = el("div", "btn-row");
    const wifiPreviewBtn = el("button", "btn btn-secondary", { type: "button" });
    text(wifiPreviewBtn, "Preview plan");
    wifiPreviewBtn.addEventListener("click", async () => {
      const payload = readWifiApplyPayload(false);
      if (!payload.ap_id || !payload.ssid) {
        toast("Укажите AP и SSID");
        return;
      }
      try {
        const { data } = await apiFetch("/wifi/preview", {
          method: "POST",
          body: payload,
          idempotencyKey: uuid(),
        });
        renderWifiApplyResult(data);
        toast("Preview: " + (data.verification_status || "ok"));
      } catch (e) {
        toast("Preview ошибка: " + e.message);
      }
    });

    const wifiApplyBtn = el("button", "btn btn-primary", { type: "button" });
    text(wifiApplyBtn, "Apply");
    wifiApplyBtn.addEventListener("click", () => {
      executeWifiApplyClick(readWifiApplyPayload, renderWifiApplyResult);
    });

    const wifiTeardownBtn = el("button", "btn btn-secondary", { type: "button" });
    text(wifiTeardownBtn, "Teardown");
    wifiTeardownBtn.addEventListener("click", () => {
      executeWifiTeardownClick(readWifiApplyPayload, renderWifiApplyResult);
    });

    append(wifiApplyBtnRow, wifiPreviewBtn, wifiApplyBtn, wifiTeardownBtn);
    append(wifiApplyPanel, wifiApplyForm, wifiApplyBtnRow, wifiApplyResultPanel);
    append(root, wifiApplyPanel);

    const wifiStatusPanel = el("section", "config-section panel config-wifi-observed");
    append(
      wifiStatusPanel,
      text(el("h2", "panel-title"), "Wi-Fi Status (observed)"),
    );
    append(
      wifiStatusPanel,
      text(
        el("p", "field-hint config-wifi-observed-honesty"),
        "Read-only observed state (offline-verified only). match / differs / unknown vs desired intent. "
          + "Never shows PSK. Unreadable APs report could-not-read — not fabricated defaults.",
      ),
    );

    const wifiObservedUi = buildWifiObservedFormSurface({
      apRangeStart,
      apRangeEnd,
      showCompare: true,
    });
    const wifiStatusForm = wifiObservedUi.form;
    const readWifiObservedPayload = wifiObservedUi.readPayload;

    const wifiStatusTableWrap = el("div", "config-wifi-observed-table-wrap");
    const wifiStatusEmpty = el("p", "config-wifi-observed-empty field-hint");
    text(wifiStatusEmpty, "Could not read Wi-Fi state");
    wifiStatusEmpty.hidden = true;
    const wifiStatusTable = el("table", "config-wifi-observed-table");
    const wifiStatusThead = el("thead", "");
    const wifiStatusHeadRow = el("tr", "");
    ["AP", "SSID", "Band", "Security", "Up", "Link up", "Compare"].forEach((label) => {
      const th = el("th", "");
      text(th, label);
      wifiStatusHeadRow.appendChild(th);
    });
    wifiStatusThead.appendChild(wifiStatusHeadRow);
    wifiStatusTable.appendChild(wifiStatusThead);
    const wifiStatusTbody = el("tbody", "config-wifi-observed-tbody");
    wifiStatusTable.appendChild(wifiStatusTbody);
    append(wifiStatusTableWrap, wifiStatusEmpty, wifiStatusTable);

    function comparisonSummary(comparisons, apId) {
      if (!comparisons || !comparisons[apId]) {
        return "—";
      }
      const row = comparisons[apId];
      const parts = ["ssid", "wpa_mode", "enabled", "band"].map((field) => {
        const val = row[field];
        if (val === "match") return field + ": match";
        if (val === "differs") return field + ": differs";
        if (val === "unknown") return field + ": unknown";
        return field + ": unknown";
      });
      return parts.join("; ");
    }

    function wifiObservedSessionSummary(data) {
      return formatWifiObservedSessionToast(data);
    }

    function renderWifiObservedRows(data) {
      while (wifiStatusTbody.firstChild) {
        wifiStatusTbody.removeChild(wifiStatusTbody.firstChild);
      }
      const aps = data && Array.isArray(data.access_points) ? data.access_points : [];
      if (!aps.length) {
        wifiStatusEmpty.hidden = false;
        wifiStatusTable.hidden = true;
        return;
      }
      wifiStatusEmpty.hidden = true;
      wifiStatusTable.hidden = false;
      aps.forEach((ap) => {
        if (!ap) {
          return;
        }
        const tr = el(
          "tr",
          ap.readable
            ? "config-wifi-observed-row"
            : "config-wifi-observed-row config-wifi-observed-unreadable",
        );
        let cells;
        if (!ap.readable) {
          cells = [
            ap.ap_id || "—",
            "Could not read Wi-Fi state",
            "unknown",
            "unknown",
            "unknown",
            "unknown",
            "—",
          ];
        } else {
          cells = [
            ap.ap_id || "—",
            ap.ssid != null ? String(ap.ssid) : "unknown",
            ap.band || "unknown",
            ap.wpa_mode || "unknown",
            ap.enabled_or_up == null ? "unknown" : ap.enabled_or_up ? "up" : "down",
            ap.link_up == null
              ? "unknown"
              : ap.link_up
                ? "yes"
                : "no",
            comparisonSummary(data.comparisons, ap.ap_id),
          ];
        }
        cells.forEach((textVal) => {
          const td = el("td", "");
          text(td, textVal);
          tr.appendChild(td);
        });
        wifiStatusTbody.appendChild(tr);
      });
    }

    const wifiStatusBtnRow = el("div", "btn-row");
    const wifiStatusRefreshBtn = el("button", "btn btn-secondary", { type: "button" });
    text(wifiStatusRefreshBtn, "Refresh observed state");
    wifiStatusRefreshBtn.addEventListener("click", async () => {
      const payload = readWifiObservedPayload((apId) => {
        const applyPayload = readWifiApplyPayload(false);
        if (!applyPayload.ssid) return null;
        return {
          desired: {
            ssid: applyPayload.ssid,
            enabled: applyPayload.enabled,
            wpa_mode: applyPayload.wpa_mode,
            band: applyPayload.band,
          },
          desired_ap_id: apId,
        };
      });
      if (!payload.ap_ids || !payload.ap_ids.length) {
        toast("Укажите AP");
        return;
      }
      try {
        const { data } = await apiFetch("/wifi/observed-state", {
          method: "POST",
          body: payload,
          idempotencyKey: uuid(),
        });
        renderWifiObservedRows(data);
        toast(wifiObservedSessionSummary(data));
      } catch (e) {
        renderWifiObservedRows(null);
        toast("Could not read Wi-Fi state: " + e.message);
      }
    });
    append(wifiStatusBtnRow, wifiStatusRefreshBtn);
    append(wifiStatusPanel, wifiStatusForm, wifiStatusBtnRow, wifiStatusTableWrap);
    append(root, wifiStatusPanel);

    const awgApplyUi = buildAwgApplyFormSurface();
    const awgApplyPanel = awgApplyUi.panel;
    const awgApplyForm = awgApplyUi.form;
    const awgApplyResultPanel = awgApplyUi.resultPanel;
    const readAwgApplyPayload = awgApplyUi.readPayload;
    const renderAwgApplyResult = awgApplyUi.renderResult;
    const wgRangeStart = awgApplyUi.wgRangeStart;

    const awgApplyBtnRow = el("div", "btn-row");
    const awgPreviewBtn = el("button", "btn btn-secondary", { type: "button" });
    text(awgPreviewBtn, "Preview plan");
    awgPreviewBtn.addEventListener("click", async () => {
      let payload;
      try {
        payload = readAwgApplyPayload(false);
      } catch (e) {
        toast("ASC args: " + e.message);
        return;
      }
      if (!payload.wg_id) {
        toast("Укажите WireGuard interface");
        return;
      }
      try {
        const { data } = await apiFetch("/wireguard/preview", {
          method: "POST",
          body: payload,
          idempotencyKey: uuid(),
        });
        renderAwgApplyResult(data);
        toast("Preview: " + (data.verification_status || "ok"));
      } catch (e) {
        toast("Preview ошибка: " + e.message);
      }
    });

    const awgApplyBtn = el("button", "btn btn-primary", { type: "button" });
    text(awgApplyBtn, "Apply");
    awgApplyBtn.addEventListener("click", () => {
      executeAwgApplyClick(readAwgApplyPayload, renderAwgApplyResult);
    });

    const awgTeardownBtn = el("button", "btn btn-secondary", { type: "button" });
    text(awgTeardownBtn, "Teardown");
    awgTeardownBtn.addEventListener("click", () => {
      executeAwgTeardownClick(readAwgApplyPayload, renderAwgApplyResult);
    });

    append(awgApplyBtnRow, awgPreviewBtn, awgApplyBtn, awgTeardownBtn);
    append(awgApplyPanel, awgApplyForm, awgApplyBtnRow, awgApplyResultPanel);
    append(root, awgApplyPanel);

    const trafficUi = buildTrafficDiscoveryFormSurface();
    const trafficPanel = trafficUi.panel;
    const trafficForm = trafficUi.form;
    const renderTrafficResult = trafficUi.renderTrafficResult;
    const readTrafficObservationPayload = trafficUi.readObservationPayload;
    const readTrafficProposalPayload = trafficUi.readProposalPayload;

    const firstTrafficRouter =
      routersResp.data.items && routersResp.data.items.length
        ? routersResp.data.items[0].router_id
        : "";
    const trafficRouterEl = document.getElementById("traffic-router-id");
    if (trafficRouterEl && firstTrafficRouter) {
      trafficRouterEl.value = firstTrafficRouter;
    }

    const trafficBtnRow = el("div", "btn-row");
    const trafficObserveBtn = el("button", "btn btn-secondary", { type: "button" });
    text(trafficObserveBtn, "Record observation");
    trafficObserveBtn.addEventListener("click", async () => {
      let payload;
      try {
        payload = readTrafficObservationPayload();
      } catch (e) {
        toast("Observation: " + e.message);
        return;
      }
      try {
        const { data } = await apiFetch("/traffic/observations", {
          method: "POST",
          body: payload,
          idempotencyKey: uuid(),
        });
        renderTrafficResult(data);
        const obsField = document.getElementById("traffic-observation-id");
        if (obsField && data.traffic_observation_id) {
          obsField.value = data.traffic_observation_id;
        }
        toast("Observation recorded (digest only — proposals-only, not device apply)");
      } catch (e) {
        toast("Observation ошибка: " + e.message);
      }
    });

    const trafficProposalBtn = el("button", "btn btn-primary", { type: "button" });
    text(trafficProposalBtn, "Create proposal");
    trafficProposalBtn.addEventListener("click", async () => {
      let payload;
      try {
        payload = readTrafficProposalPayload();
      } catch (e) {
        toast("Proposal: " + e.message);
        return;
      }
      try {
        const { data } = await apiFetch("/traffic/proposals", {
          method: "POST",
          body: payload,
          idempotencyKey: uuid(),
        });
        renderTrafficResult(data);
        const propField = document.getElementById("traffic-proposal-id");
        if (propField && data.proposal_id) {
          propField.value = data.proposal_id;
        }
        toast(
          "Proposal: " + data.status + (data.auto_apply_blocked ? " (auto-apply blocked)" : ""),
        );
      } catch (e) {
        toast("Proposal ошибка: " + e.message);
      }
    });

    const trafficGetBtn = el("button", "btn btn-secondary", { type: "button" });
    text(trafficGetBtn, "Get proposal");
    trafficGetBtn.addEventListener("click", async () => {
      const propEl = document.getElementById("traffic-proposal-id");
      const propId = propEl && propEl.value ? propEl.value.trim() : "";
      if (!propId) {
        toast("Укажите proposal_id");
        return;
      }
      try {
        const { data } = await apiFetch(
          "/traffic/proposals/" + encodeURIComponent(propId),
        );
        renderTrafficResult(data);
        toast("Proposal loaded");
      } catch (e) {
        toast("Get proposal ошибка: " + e.message);
      }
    });

    append(trafficBtnRow, trafficObserveBtn, trafficProposalBtn, trafficGetBtn);
    append(trafficPanel, trafficForm, trafficBtnRow, trafficUi.resultPanel);
    append(root, trafficPanel);

    append(root, buildRciMutationFormSurface({ defaultRouterId: firstRouterId }).panel);

    const keenPanel = el("section", "config-section panel config-stub config-stub-disabled");
    append(keenPanel, text(el("h2", "panel-title"), "KeenDNS"));
    append(
      keenPanel,
      text(
        el("p", "empty-state config-stub-notice"),
        "KeenDNS недоступен в этой сборке — backend отсутствует; управление через UI не поддерживается.",
      ),
    );
    append(root, keenPanel);
  } catch (err) {
    renderError(root, err, () => renderConfig(root));
  }
}

function renderSettings(root) {
  clear(root);
  append(root, pageHeader("Настройки", "Тема, границы безопасности и поведение UI"));

  const themePanel = el("div", "panel");
  append(themePanel, text(el("h2", "panel-title"), "Тема"));
  append(themePanel, text(el("p"), "Текущая: " + (localStorage.getItem(THEME_KEY) || "system")));
  append(themePanel, text(el("p", "field-hint"), "Переключение в верхней панели. Сохраняется только ключ темы в localStorage."));
  append(root, themePanel);

  const boundary = el("div", "panel");
  append(boundary, text(el("h2", "panel-title"), "Границы безопасности"));
  append(boundary, text(el("p"), "• Аутентификация: cookie hub_admin; вход — /login, выход — POST /logout (кнопка «Выйти» в верхней панели)"));
  append(
    boundary,
    text(
      el("p"),
      "• Каталог/preset Apply/live-write заблокированы пока Gate B не WriteCertified; bounded Wi-Fi/AWG test Apply — отдельное исключение в #config",
    ),
  );
  append(boundary, text(el("p"), "• CredentialRef: list/enroll/revoke в #config; enroll one-shot → vault; UI — только ID и metadata"));
  append(boundary, text(el("p"), "• Запросы same-origin с credentials; Idempotency-Key на мутациях"));
  append(root, boundary);

  const refreshPanel = el("div", "panel");
  append(refreshPanel, text(el("h2", "panel-title"), "Обновление"));
  const btn = el("button", "btn btn-secondary");
  text(btn, "Сбросить кэш статуса");
  btn.addEventListener("click", () => {
    sessionMemory.status = null;
    toast("Кэш сброшен");
    navigate();
  });
  append(refreshPanel, btn);
  append(root, refreshPanel);
}

const WIZARD_FINDING_MESSAGES = {
  ssh_component_missing:
    "Компонент SSH не установлен. При включении компонента SSH в веб-панели роутера "
      + "автоматически выполняются пересборка образа прошивки и перезагрузка "
      + "(см. информацию о побочных эффектах ниже).",
  ssh_disabled:
    "Компонент SSH установлен, но доступ отключён — включите SSH в веб-панели роутера.",
  ssh_state_unknown:
    "Не удалось определить состояние SSH — проверьте доступность роутера и повторите.",
  firmware_below_verified_baseline:
    "Версия прошивки ниже проверенного baseline проекта (offline SSOT).",
  wifi_inventory_unavailable:
    "Инвентаризация Wi‑Fi недоступна на этом этапе обнаружения.",
  component_change_triggers_firmware_upgrade:
    "Установка компонента обновит прошивку до версии канала обновлений.",
  update_channel_not_stable:
    "Канал обновлений не stable — возможны нестабильные сборки.",
  firmware_major_version_jump:
    "Установка компонента может перейти на другую major-версию прошивки — проверьте совместимость.",
  components_listing_timeout:
    "Таймаут при чтении списка компонентов — повторите обнаружение позже.",
  components_inventory_unavailable:
    "Инвентаризация компонентов недоступна — состояние SSH по списку компонентов не определено.",
  update_channel_unknown:
    "Канал обновлений неизвестен — оценка side-effects ограничена.",
};

const WIZARD_STEPS = [
  "1. Данные доступа",
  "2. Обнаружение",
  "3. Ключ хоста",
  "4. Итог",
];

function wizardFindingText(code) {
  return WIZARD_FINDING_MESSAGES[code] || ("Найдено: " + code);
}

function wizardSshComponentFact(report) {
  if (report.ssh_component_installed === true) {
    return "SSH-компонент: установлен";
  }
  if (report.ssh_component_installed === false) {
    return "SSH-компонент: отсутствует";
  }
  return "SSH-компонент: неизвестно";
}

function wizardComponentsInventorySummary(report) {
  const inventory = report.components_inventory || {};
  const total = inventory.total_observed;
  if (typeof total !== "number") {
    return "Компоненты: —";
  }
  let text = "Компоненты: " + total;
  if (inventory.truncated) {
    text += " (показано " + (inventory.entries || []).length + ", список усечён)";
  }
  return text;
}

function renderWizardProgress(stepIndex) {
  const list = el("ol", "wizard-progress");
  WIZARD_STEPS.forEach((label, idx) => {
    const item = el("li", "wizard-progress-step");
    if (idx < stepIndex) item.classList.add("is-done");
    if (idx === stepIndex) item.classList.add("is-active");
    text(item, label);
    list.appendChild(item);
  });
  return list;
}

function renderWizardTransportHonesty(report, allowInsecureHttp) {
  if (!report) return el("span");
  const transport = report.transport_security || "";
  const certEligible = report.certification_eligible;
  const isPlainHttp =
    allowInsecureHttp
    || transport === "insecure_http"
    || transport === "plain_http"
    || transport === "http";
  if (!isPlainHttp && certEligible !== false) return el("span");
  const box = el("div", "wizard-transport-notice");
  append(
    box,
    text(
      el("p", "field-hint"),
      "Обнаружение выполнялось по незащищённому HTTP — канал не сертифицируется "
        + "(certification_eligible=false). Это допустимо для лабораторного черновика, "
        + "но не используйте такой доступ для production-управления.",
    ),
  );
  return box;
}

function renderWizardSideEffects(report) {
  const box = el("div", "wizard-side-effects");
  append(box, text(el("h3", "panel-subtitle"), "Побочные эффекты установки компонента (информационно)"));
  const effects = report.component_change_side_effects || {};
  const wouldUpgrade = report.component_change_would_upgrade_firmware;
  append(
    box,
    text(
      el("p"),
      "Пересборка прошивки, автоматическая перезагрузка и простой управления "
        + "всегда происходят при установке компонента (процесс KeeneticOS).",
    ),
  );
  if (effects.firmware_version_changes === true) {
    if (wouldUpgrade === true) {
      append(
        box,
        text(
          el("p"),
          "Версия прошивки изменится: канал "
            + (report.update_channel || "—")
            + " предлагает более новую версию "
            + (report.channel_firmware_version || "—")
            + " (установлено: "
            + (report.firmware_version || "—")
            + ").",
        ),
      );
    } else {
      append(
        box,
        text(
          el("p"),
          "Версия прошивки изменится: канал "
            + (report.update_channel || "—")
            + " предлагает более старую версию "
            + (report.channel_firmware_version || "—")
            + " (установлено: "
            + (report.firmware_version || "—")
            + "). Пересборка всё равно выполнится.",
        ),
      );
    }
  } else if (effects.firmware_version_changes === false) {
    append(
      box,
      text(
        el("p"),
        "Версия прошивки на канале "
          + (report.update_channel || "—")
          + " совпадает с установленной ("
          + (report.channel_firmware_version || report.firmware_version || "—")
          + ") — пересборка без смены версии.",
      ),
    );
  } else {
    append(
      box,
      text(el("p"),
        "Изменение версии прошивки неизвестно — канал или установленная версия не определены."),
    );
  }
  if ((report.findings || []).includes("firmware_major_version_jump")) {
    append(
      box,
      text(el("p", "field-hint"),
        "Внимание: возможен переход между major-версиями прошивки."),
    );
  }
  return box;
}

function renderWizardFindings(findings, report, allowInsecureHttp) {
  const wrap = el("div", "wizard-findings");
  append(wrap, text(el("h3", "panel-subtitle"), "Результаты проверки"));
  if (!findings || findings.length === 0) {
    append(wrap, text(el("p"), "Критичных находок нет — продолжайте к ключу хоста."));
    append(wrap, renderWizardTransportHonesty(report, allowInsecureHttp));
    return wrap;
  }
  findings.forEach((code) => {
    const item = el("div", "wizard-finding-item");
    append(item, text(el("strong"), code));
    append(item, text(el("p"), wizardFindingText(code)));
    wrap.appendChild(item);
  });
  return wrap;
}

async function renderAddRouter(root) {
  renderSkeleton(root);
  const state = {
    step: 0,
    host: "",
    username: "admin",
    port: "",
    allowInsecureHttp: false,
    sourceAddress: "",
    allowOverwrite: false,
    displayName: "",
    routerId: "",
    credentialRefId: "",
    draftIdempotencyKey: "",
    draftSucceeded: false,
    draftFingerprint: "",
    discovery: null,
    learnResult: null,
  };

  function wizardDraftFingerprint(host, username, port, allowInsecureHttp) {
    return JSON.stringify({
      host: (host || "").trim(),
      username: ((username || "admin").trim() || "admin"),
      port: (port || "").trim(),
      allowInsecureHttp: !!allowInsecureHttp,
    });
  }

  function invalidateWizardDraft() {
    state.draftSucceeded = false;
    state.routerId = "";
    state.credentialRefId = "";
    state.draftIdempotencyKey = "";
    state.draftFingerprint = "";
  }

  function discoveryHostUrl() {
    const hostRaw = state.host.trim();
    if (hostRaw.indexOf("://") >= 0) return hostRaw;
    const scheme = state.allowInsecureHttp ? "http://" : "https://";
    return scheme + hostRaw;
  }

  async function runBootstrapDiscovery() {
    const { data: discovery } = await apiFetch("/lab/bootstrap-discovery", {
      method: "POST",
      body: {
        host: discoveryHostUrl(),
        username: state.username,
        credential_ref_id: state.credentialRefId,
        allow_insecure_http: state.allowInsecureHttp,
      },
    });
    state.discovery = discovery;
  }

  async function ensureWizardDraft(secret) {
    if (state.draftSucceeded && state.routerId && state.credentialRefId) {
      return;
    }
    if (!state.draftIdempotencyKey) {
      state.draftIdempotencyKey = uuid();
    }
    const draftBody = {
      host: state.host,
      username: state.username,
      secret: secret,
      allow_insecure_http: state.allowInsecureHttp,
    };
    if (state.displayName) draftBody.display_name = state.displayName;
    if (state.port) draftBody.port = parseInt(state.port, 10);
    const { data: draft } = await apiFetch("/lab/wizard-draft-router", {
      method: "POST",
      body: draftBody,
      idempotencyKey: state.draftIdempotencyKey,
    });
    state.routerId = draft.router_id || "";
    state.credentialRefId = draft.credential_ref_id || "";
    state.draftSucceeded = true;
    state.draftFingerprint = wizardDraftFingerprint(
      state.host,
      state.username,
      state.port,
      state.allowInsecureHttp,
    );
  }

  async function paint() {
    clear(root);
    append(
      root,
      pageHeader(
        "Добавить роутер",
        "Мастер зачисления: обнаружение → ключ SSH → черновик (Gate A не открыт)",
      ),
    );
    append(root, renderWizardProgress(state.step));

    if (state.step === 0) {
      const panel = el("section", "panel wizard-panel");
      append(panel, text(el("h2", "panel-title"), "Шаг 1 — данные доступа"));
      const draftUi = buildWizardDraftFormSurface();
      const form = draftUi.form;
      const errBox = el("div", "wizard-error");
      form.appendChild(errBox);
      const submit = el("button", "btn btn-primary", { type: "submit" });
      text(submit, "Далее: обнаружение");

      function onDraftIdentityFieldChange() {
        if (state.draftSucceeded) {
          invalidateWizardDraft();
        }
      }

      const hostInput = form.querySelector("#wizard-host");
      const userInput = form.querySelector("#wizard-username");
      const secretInput = form.querySelector("#wizard-secret");
      const portInput = form.querySelector("#wizard-port");
      const insecureInput = form.querySelector("#wizard-insecure-http");
      const sourceInput = form.querySelector("#wizard-source-address");
      if (hostInput) {
        hostInput.value = state.host;
        hostInput.addEventListener("input", onDraftIdentityFieldChange);
      }
      if (userInput) {
        userInput.value = state.username;
        userInput.addEventListener("input", onDraftIdentityFieldChange);
      }
      if (secretInput) {
        secretInput.addEventListener("input", onDraftIdentityFieldChange);
      }
      if (portInput) {
        portInput.value = state.port;
        portInput.addEventListener("input", onDraftIdentityFieldChange);
      }
      if (insecureInput) {
        insecureInput.checked = state.allowInsecureHttp;
        insecureInput.addEventListener("change", onDraftIdentityFieldChange);
      }
      if (sourceInput) {
        sourceInput.value = state.sourceAddress;
      }

      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        clear(errBox);
        const draftPayload = draftUi.readPayload(true);
        state.host = draftPayload.host;
        state.username = draftPayload.username || "admin";
        const secret = draftPayload.secret || "";
        state.displayName = draftPayload.display_name || "";
        state.port = draftPayload.port || "";
        state.allowInsecureHttp = !!draftPayload.allow_insecure_http;
        state.sourceAddress = draftPayload.source_address || "";
        if (!state.host || !state.username || !secret) {
          append(errBox, text(el("p"), "Укажите адрес, имя пользователя и пароль."));
          return;
        }
        const currentFingerprint = wizardDraftFingerprint(
          state.host,
          state.username,
          state.port,
          state.allowInsecureHttp,
        );
        if (state.draftSucceeded && state.draftFingerprint !== currentFingerprint) {
          invalidateWizardDraft();
        }
        if (!state.draftIdempotencyKey) {
          state.draftIdempotencyKey = uuid();
        }
        submit.disabled = true;
        const secretEl = form.querySelector("#wizard-secret");
        try {
          if (!state.draftSucceeded) {
            await ensureWizardDraft(secret);
          }
          if (secretEl) secretEl.value = "";
          await runBootstrapDiscovery();
          state.step = 1;
          await paint();
        } catch (e) {
          if (secretEl) secretEl.value = "";
          append(errBox, text(el("p"), "Ошибка: " + e.message));
        } finally {
          submit.disabled = false;
        }
      });
      append(form, submit);
      append(panel, form);
      append(root, panel);
      return;
    }

    if (state.step === 1 && state.discovery) {
      const panel = el("section", "panel wizard-panel");
      append(panel, text(el("h2", "panel-title"), "Шаг 2 — обнаружение"));
      const report = state.discovery;
      append(
        panel,
        text(
          el("p"),
          "Модель: "
            + (report.model || "—")
            + " · Прошивка: "
            + (report.firmware_version || "—")
            + " · Канал: "
            + (report.update_channel || "—"),
        ),
      );
      append(
        panel,
        text(
          el("p"),
          wizardComponentsInventorySummary(report)
            + " · "
            + wizardSshComponentFact(report),
        ),
      );
      if (report.channel_firmware_version) {
        append(
          panel,
          text(el("p"), "Версия на канале: " + report.channel_firmware_version),
        );
      }
      append(panel, renderWizardFindings(report.findings || [], report, state.allowInsecureHttp));
      if (
        report.ssh_component_installed === false
        || (report.findings || []).includes("ssh_component_missing")
      ) {
        append(panel, renderWizardSideEffects(report));
      }
      append(
        panel,
        text(
          el("p", "field-hint"),
          "Обнаружение не открывает Gate A и не сертифицирует устройство.",
        ),
      );
      const btnRow = el("div", "btn-row");
      const backBtn = el("button", "btn btn-secondary", { type: "button" });
      text(backBtn, "Назад");
      backBtn.addEventListener("click", () => {
        state.step = 0;
        paint();
      });
      const retryBtn = el("button", "btn btn-secondary", { type: "button" });
      text(retryBtn, "Повторить обнаружение");
      retryBtn.addEventListener("click", async () => {
        retryBtn.disabled = true;
        try {
          await runBootstrapDiscovery();
          await paint();
        } catch (e) {
          toast("Обнаружение ошибка: " + e.message);
        } finally {
          retryBtn.disabled = false;
        }
      });
      const nextBtn = el("button", "btn btn-primary", { type: "button" });
      text(nextBtn, "Далее: ключ хоста");
      nextBtn.addEventListener("click", async () => {
        nextBtn.disabled = true;
        try {
          const learnBody = buildWizardSshHostKeyLearnBody(state);
          const { data: learn } = await apiFetch(
            "/routers/" + encodeURIComponent(state.routerId) + "/ssh-host-key/learn",
            {
              method: "POST",
              body: learnBody,
            },
          );
          state.learnResult = learn;
          state.step = 2;
          await paint();
        } catch (e) {
          toast("Learn ошибка: " + e.message);
          nextBtn.disabled = false;
        }
      });
      append(btnRow, backBtn, retryBtn, nextBtn);
      append(panel, btnRow);
      append(root, panel);
      return;
    }

    if (state.step === 2 && state.learnResult) {
      const panel = el("section", "panel wizard-panel");
      append(panel, text(el("h2", "panel-title"), "Шаг 3 — подтверждение ключа хоста"));
      const learn = state.learnResult;
      append(
        panel,
        text(
          el("p"),
          "Проверьте отпечаток out-of-band (экран роутера / другой канал), "
            + "затем введите его точно как показано ниже.",
        ),
      );
      append(
        panel,
        text(el("p", "mono"),
          "Алгоритм: " + (learn.algorithm || "—")),
      );
      append(
        panel,
        text(el("p", "mono"),
          "Отпечаток SHA256: " + (learn.fingerprint_sha256 || "—")),
      );
      if (learn.warning) {
        append(panel, text(el("p", "field-hint"), learn.warning));
      }
      if (state.discovery) {
        append(panel, renderWizardTransportHonesty(state.discovery, state.allowInsecureHttp));
      }
      const confirmUi = buildWizardHostKeyConfirmFormSurface();
      const form = confirmUi.form;
      const fpInput = form.querySelector("#wizard-confirm-fp");
      const algInput = form.querySelector("#wizard-confirm-alg");
      const overwriteInput = form.querySelector("#wizard-allow-overwrite");
      if (fpInput) fpInput.placeholder = learn.fingerprint_sha256 || "";
      if (algInput) algInput.placeholder = learn.algorithm || "";
      if (overwriteInput) overwriteInput.checked = state.allowOverwrite;
      const conflictBox = el("div", "wizard-pin-conflict");
      conflictBox.hidden = true;
      form.appendChild(conflictBox);
      const errBox = el("div", "wizard-error");
      form.appendChild(errBox);
      form.addEventListener("submit", async (ev) => {
        ev.preventDefault();
        clear(errBox);
        conflictBox.hidden = true;
        const confirmPayload = confirmUi.readPayload();
        const fp = confirmPayload.fingerprint_sha256;
        const alg = confirmPayload.algorithm;
        state.allowOverwrite = !!confirmPayload.allow_overwrite;
        if (fp !== (learn.fingerprint_sha256 || "") || alg !== (learn.algorithm || "")) {
          append(
            errBox,
            text(
              el("p"),
              "Отпечаток и алгоритм должны точно совпадать с результатом learn — слепое принятие запрещено.",
            ),
          );
          return;
        }
        try {
          await apiFetch(
            "/routers/" + encodeURIComponent(state.routerId) + "/ssh-host-key/confirm",
            {
              method: "POST",
              body: buildWizardSshHostKeyConfirmBody(confirmPayload),
            },
          );
          state.step = 3;
          await paint();
        } catch (e) {
          if (e.code === "ssh_host_key.pin_conflict") {
            conflictBox.hidden = false;
            append(
              conflictBox,
              text(
                el("p"),
                "Конфликт pin: для этого роутера уже сохранён другой ключ. "
                  + "Перезапись без явного подтверждения запрещена (allow_overwrite=false по умолчанию). "
                  + "Проверьте устройство или включите allow_overwrite в Advanced.",
              ),
            );
            if (e.details && e.details.length) {
              append(
                conflictBox,
                text(el("p", "mono"), JSON.stringify(e.details[0])),
              );
            }
          } else {
            append(errBox, text(el("p"), "Confirm ошибка: " + e.message));
          }
        }
      });
      const submit = el("button", "btn btn-primary", { type: "submit" });
      text(submit, "Подтвердить ключ");
      append(form, submit);
      const backBtn = el("button", "btn btn-secondary", { type: "button" });
      text(backBtn, "Назад");
      backBtn.addEventListener("click", () => {
        state.step = 1;
        paint();
      });
      append(form, backBtn);
      append(panel, form);
      append(root, panel);
      return;
    }

    if (state.step === 3) {
      const panel = el("section", "panel wizard-panel");
      append(panel, text(el("h2", "panel-title"), "Шаг 4 — итог"));
      const handoff = el("div", "wizard-handoff");
      append(
        handoff,
        text(
          el("p"),
          "Черновик создан: router_id="
            + (state.routerId || "—")
            + ", credential_ref_id="
            + (state.credentialRefId || "—"),
        ),
      );
      append(
        handoff,
        text(
          el("p"),
          "Gate A не открыт · certification_eligible=false · устройство не сертифицировано.",
        ),
      );
      append(
        handoff,
        text(
          el("p"),
          "Управление Wi‑Fi и прочие write-операции недоступны до прохождения Gate A "
            + "и полного commissioning.",
        ),
      );
      if (state.learnResult) {
        append(
          handoff,
          text(
            el("p", "mono"),
            "SSH host key: "
              + (state.learnResult.algorithm || "")
              + " "
              + (state.learnResult.fingerprint_sha256 || ""),
          ),
        );
      }
      append(panel, handoff);
      const btnRow = el("div", "btn-row");
      const routersBtn = el("a", "btn btn-secondary", { href: "#routers" });
      text(routersBtn, "К списку роутеров");
      const restartBtn = el("button", "btn btn-primary", { type: "button" });
      text(restartBtn, "Добавить ещё");
      restartBtn.addEventListener("click", () => {
        state.step = 0;
        state.routerId = "";
        state.credentialRefId = "";
        state.draftIdempotencyKey = "";
        state.draftSucceeded = false;
        state.draftFingerprint = "";
        state.discovery = null;
        state.learnResult = null;
        paint();
      });
      append(btnRow, routersBtn, restartBtn);
      append(panel, btnRow);
      append(root, panel);
    }
  }

  try {
    await loadFieldManifest();
    await paint();
  } catch (err) {
    renderError(root, err, () => renderAddRouter(root));
  }
}

function uplinkSignalLabel(quality, rssi) {
  if (quality != null && quality !== "") {
    const q = Number(quality);
    if (!Number.isNaN(q)) {
      let strength = "weak";
      if (q >= 75) strength = "strong";
      else if (q >= 50) strength = "fair";
      return q + "/100 (" + strength + ")";
    }
  }
  if (rssi != null && rssi !== "") {
    return String(rssi) + " dBm";
  }
  return "unknown";
}

function uplinkSignalLabelRu(quality, rssi) {
  if (quality != null && quality !== "") {
    const q = Number(quality);
    if (!Number.isNaN(q)) {
      if (q >= 75) return "Отличный";
      if (q >= 50) return "Хороший";
      return "Слабый";
    }
  }
  if (rssi != null && rssi !== "") {
    return String(rssi) + " dBm";
  }
  return "Неизвестно";
}

function uplinkSecurityLabelRu(network) {
  if (!network) return "Неизвестно";
  const mode = network.wpa_mode;
  if (mode === "open") return "Открытая";
  if (mode === "WPA2" || mode === "wpa2") return "WPA2";
  if (mode === "WPA3" || mode === "wpa3") return "WPA3";
  if (mode === "WPA2_WPA3_MIXED" || mode === "wpa2_wpa3_mixed") return "WPA2/WPA3";
  if (mode === "unrecognized" || mode === "unknown" || !mode) return "Неизвестно";
  return "Неизвестно";
}

function uplinkSecurityLabel(network) {
  if (!network) return "unknown";
  const mode = network.wpa_mode;
  if (mode === "open") return "open";
  if (mode === "unrecognized") return "unrecognized";
  if (mode && mode !== "unknown") return String(mode);
  return "unknown";
}

function uplinkDisplaySsid(network) {
  if (!network) return "—";
  if (network.hidden || !network.ssid) return "Hidden";
  return String(network.ssid);
}

function uplinkDisplaySsidRu(network) {
  if (!network) return "—";
  if (network.hidden || !network.ssid) return "Скрытая";
  return String(network.ssid);
}

function uplinkBandForRadio(radio) {
  if (radio === "WifiMaster1") return "BAND_5GHZ";
  return "BAND_2_4GHZ";
}

function uplinkRadioLabel(radio) {
  if (radio === "WifiMaster1") return "5 GHz";
  return "2.4 GHz";
}

function uplinkRadioLabelRu(radio) {
  if (radio === "WifiMaster1") return "5 ГГц";
  return "2,4 ГГц";
}

function uplinkStationIdForBand(band) {
  return band === "BAND_5GHZ" ? "WifiMaster1/WifiStation0" : "WifiMaster0/WifiStation0";
}

function uplinkDescribeStationOp(op) {
  if (!op || !op.operation) return "—";
  const labels = {
    wifi_station_set_ssid: "Set station SSID",
    wifi_station_encryption_enable: "Enable encryption",
    wifi_station_encryption_wpa2: "WPA2 encryption",
    wifi_station_set_wpa_psk: "Set WPA-PSK (credential_ref only)",
    wifi_station_ip_global: "IP global priority (device-exercised on station; ~20–30s settle)",
    wifi_station_ip_address_dhcp: "DHCP client address",
    wifi_station_up: "Bring station interface up",
    wifi_station_set_bssid: "Pin BSSID (help-derived; unexercised)",
  };
  return labels[op.operation] || op.operation;
}

function stationApplyHonestySummary(data) {
  if (!data || typeof data !== "object") return "";
  const parts = [];
  const overall = data.overall;
  const primarySuccess = overall === "applied";
  if (overall) {
    parts.push("overall=" + String(overall));
  } else {
    parts.push("overall unknown");
  }
  const uplink = data.uplink_verification_status;
  if (uplink === "uplink_verified_bounded") {
    if (primarySuccess) {
      parts.push("uplink verified bounded (DEVICE-CONFIRMED association — limits apply)");
    } else {
      parts.push("uplink=uplink_verified_bounded (secondary — overall not applied)");
    }
  } else if (uplink === "uplink_associated_no_global") {
    parts.push("associated but ip global missing (NOT verified bounded — NOT success)");
  } else if (uplink === "uplink_dispatched_unverified") {
    parts.push("uplink NOT verified (dispatched without observe — NOT success)");
  } else if (uplink === "uplink_failed") {
    parts.push("uplink FAILED");
  } else if (uplink) {
    parts.push("uplink: " + String(uplink));
  }
  if (data.uplink_settle_seconds != null) {
    parts.push("settle=" + String(data.uplink_settle_seconds) + "s");
  }
  return parts.length ? parts.join("; ") : "";
}

const UPLINK_READBACK_SECRET_KEYS = new Set([
  "configured_ssid",
  "associated_ssid",
  "ssid",
  "bssid",
  "wpa_psk",
  "psk",
  "password",
  "passphrase",
  "pre_shared_key",
  "credential_ref_id",
]);

const UPLINK_READBACK_FIELD_ROWS = [
  { readbackKey: "associated_ssid_field_present", signal: "associated_ssid_field_present", label: "associated SSID field present" },
  { readbackKey: "associated_network", signal: null, label: "associated network (derived)" },
  { readbackKey: "state", signal: "state", label: "interface state" },
  { readbackKey: "configured_encryption", signal: null, label: "configured encryption (show rc)" },
  { readbackKey: "associated_encryption", signal: null, label: "associated encryption (runtime)" },
  { readbackKey: "link", signal: "link", label: "link (on-wire)" },
  { readbackKey: "connected", signal: "connected", label: "connected (device flag)" },
  { readbackKey: "txbytes", signal: "txbytes", label: "txbytes" },
  { readbackKey: "rxbytes", signal: "rxbytes", label: "rxbytes" },
];

const UPLINK_VERDICT_ONLY_ROWS = [
  { signal: "associated_ssid_matches_intent", label: "associated SSID matches intent" },
  { signal: "internet_status", label: "internet status (show internet status)" },
  { signal: "gateway_status", label: "gateway status" },
  { signal: "dns_status", label: "DNS status" },
];

const UPLINK_MISSING_SIGNAL_MAP = {
  associated_ssid_field_present: ["associated_ssid_field"],
  associated_ssid_matches_intent: ["ssid_intent_match", "associated_ssid"],
  link: ["link"],
  broadcast: ["broadcast"],
  connected: ["connected"],
  state: ["state"],
  txbytes: ["txbytes"],
  rxbytes: ["rxbytes"],
  internet_status: ["internet_status", "internet_affirmative"],
  gateway_status: ["gateway_status"],
  dns_status: ["dns_status"],
};

function isUplinkReadbackSecretKey(key) {
  const norm = String(key).toLowerCase().replace(/-/g, "_");
  if (UPLINK_READBACK_SECRET_KEYS.has(norm)) return true;
  const parts = norm.split("_");
  const secretParts = new Set(["psk", "password", "passphrase", "secret", "credential"]);
  if (parts.some((part) => secretParts.has(part))) return true;
  if (norm.indexOf("private") >= 0 && norm.indexOf("key") >= 0) return true;
  if (norm.indexOf("pre") >= 0 && norm.indexOf("shared") >= 0) return true;
  return false;
}

function redactApplyResultSecrets(value) {
  if (Array.isArray(value)) {
    return value.map(redactApplyResultSecrets);
  }
  if (value && typeof value === "object") {
    const out = {};
    Object.entries(value).forEach(([key, val]) => {
      if (isUplinkReadbackSecretKey(key) && typeof val === "string" && val.trim()) {
        out[key] = "[REDACTED]";
      } else {
        out[key] = redactApplyResultSecrets(val);
      }
    });
    return out;
  }
  return value;
}

function sanitizeApplyResultForDisplay(data) {
  if (!data || typeof data !== "object") return data;
  return redactApplyResultSecrets(JSON.parse(JSON.stringify(data)));
}

const APPLY_OVERALL_FAILURE_TOAST = {
  failed: "FAILED",
  verify_mismatch: "VERIFY MISMATCH",
  rolled_back: "ROLLED BACK",
  unsupported_pending_verification: "UNSUPPORTED",
};

function applyOverallFailureToastPrefix(data, action) {
  if (!data || typeof data !== "object") return null;
  const label = APPLY_OVERALL_FAILURE_TOAST[data.overall];
  return label ? action + " " + label : null;
}

const APPLY_TOAST_POSITIVE_VERDICT = {
  uplink_verified_bounded: " verified bounded",
  on_air_verified: " verified on-air",
  tunnel_healthy: " verified tunnel",
};

const APPLY_TOAST_SUCCESS_OVERALLS = new Set([
  "applied",
]);

function applyOverallUnknownLabel(overall) {
  if (!overall) return "missing";
  return String(overall);
}

function applyFamilyToastPrefix(data, action, verdictField) {
  if (!data || typeof data !== "object") {
    return action + " unknown (no result)";
  }
  const overallPrefix = applyOverallFailureToastPrefix(data, action);
  if (overallPrefix) return overallPrefix;
  if (!APPLY_TOAST_SUCCESS_OVERALLS.has(data.overall)) {
    return action + " unknown (overall " + applyOverallUnknownLabel(data.overall) + ")";
  }
  const verdict = data[verdictField];
  const positiveSuffix =
    verdict && APPLY_TOAST_POSITIVE_VERDICT[verdict]
      ? APPLY_TOAST_POSITIVE_VERDICT[verdict]
      : null;
  if (positiveSuffix) return action + positiveSuffix;
  if (verdict === "tunnel_never_handshaked") return action + " FAILED tunnel";
  if (
    verdict === "uplink_failed"
    || verdict === "on_air_still_broadcasting"
  ) {
    return action + " FAILED";
  }
  return action + " NOT verified";
}

function stationApplyToastPrefix(data, action) {
  return applyFamilyToastPrefix(data, action, "uplink_verification_status");
}

function wifiApplyToastPrefix(data, action) {
  return applyFamilyToastPrefix(data, action, "on_air_verification_status");
}

function awgApplyToastPrefix(data, action) {
  return applyFamilyToastPrefix(data, action, "tunnel_verification_status");
}

function toastApplyFamilyResult(data, action, prefixFn, honestyFn) {
  const prefix = prefixFn(data, action);
  const honesty = honestyFn ? honestyFn(data) : "";
  toast(prefix + (honesty ? " — " + honesty : ""));
}

const APPLY_TOAST_PATHS = {
  "P-wifi-apply": {
    toastFromResponse(data) {
      toastApplyFamilyResult(data, "Apply", wifiApplyToastPrefix, wifiApplyHonestySummary);
    },
  },
  "P-wifi-teardown": {
    toastFromResponse(data) {
      toastApplyFamilyResult(data, "Teardown", wifiApplyToastPrefix, wifiApplyHonestySummary);
    },
  },
  "P-awg-apply": {
    toastFromResponse(data) {
      toastApplyFamilyResult(data, "Apply", awgApplyToastPrefix, awgApplyHonestySummary);
    },
  },
  "P-awg-teardown": {
    toastFromResponse(data) {
      toastApplyFamilyResult(data, "Teardown", awgApplyToastPrefix, awgApplyHonestySummary);
    },
  },
  "P-station-apply": {
    toastFromResponse(data) {
      toastApplyFamilyResult(data, "Apply", stationApplyToastPrefix, stationApplyHonestySummary);
    },
  },
  "P-station-teardown": {
    toastFromResponse(data) {
      toastApplyFamilyResult(data, "Teardown", stationApplyToastPrefix, stationApplyHonestySummary);
    },
  },
  "P-uplink-ap-apply": {
    toastFromResponse(data) {
      toast(buildUplinkApApplyToast(data));
    },
  },
  "P-vpn-import": {
    toastFromResponse(data) {
      toast(
        "Catalog import OK (SQLite/vault only, not device apply): profile_id="
          + (data && data.profile_id ? data.profile_id : "?"),
      );
    },
  },
};

async function executeWifiApplyClick(readPayload, renderResult) {
  const payload = readPayload(true);
  if (!payload.confirm_live_apply) {
    toast("Требуется confirm для live apply");
    return;
  }
  try {
    const { data } = await apiFetch("/wifi/apply", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    renderResult(data);
    APPLY_TOAST_PATHS["P-wifi-apply"].toastFromResponse(data);
  } catch (e) {
    toast("Apply ошибка: " + e.message);
  }
}

async function executeWifiTeardownClick(readPayload, renderResult) {
  const base = readPayload(true);
  if (!base.confirm_live_apply) {
    toast("Требуется confirm для teardown");
    return;
  }
  const payload = {
    ap_id: base.ap_id,
    wpa_mode: base.wpa_mode,
    confirm_live_teardown: true,
  };
  if (base.host) payload.host = base.host;
  if (base.username) payload.username = base.username;
  if (base.router_credential_ref_id) payload.router_credential_ref_id = base.router_credential_ref_id;
  if (base.ssh_host_key_sha256) payload.ssh_host_key_sha256 = base.ssh_host_key_sha256;
  if (base.source_address) payload.source_address = base.source_address;
  try {
    const { data } = await apiFetch("/wifi/teardown", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    renderResult(data);
    APPLY_TOAST_PATHS["P-wifi-teardown"].toastFromResponse(data);
  } catch (e) {
    toast("Teardown ошибка: " + e.message);
  }
}

async function executeAwgApplyClick(readPayload, renderResult) {
  let payload;
  try {
    payload = readPayload(true);
  } catch (e) {
    toast("ASC args: " + e.message);
    return;
  }
  if (!payload.confirm_live_apply) {
    toast("Требуется confirm для live apply");
    return;
  }
  try {
    const { data } = await apiFetch("/wireguard/apply", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    renderResult(data);
    APPLY_TOAST_PATHS["P-awg-apply"].toastFromResponse(data);
  } catch (e) {
    toast("Apply ошибка: " + e.message);
  }
}

async function executeAwgTeardownClick(readPayload, renderResult) {
  let base;
  try {
    base = readPayload(true);
  } catch (e) {
    toast("ASC args: " + e.message);
    return;
  }
  if (!base.confirm_live_apply) {
    toast("Требуется confirm для teardown");
    return;
  }
  const payload = {
    wg_id: base.wg_id,
    confirm_live_teardown: true,
    peer_rci_shape: base.peer_rci_shape || "nested_rci",
  };
  if (base.private_key_credential_ref_id) {
    payload.private_key_credential_ref_id = base.private_key_credential_ref_id;
  }
  if (base.preshared_key_credential_ref_id) {
    payload.preshared_key_credential_ref_id = base.preshared_key_credential_ref_id;
  }
  if (base.peer_public_key) payload.peer_public_key = base.peer_public_key;
  if (base.peer_endpoint) payload.peer_endpoint = base.peer_endpoint;
  if (base.peer_allow_ips) payload.peer_allow_ips = base.peer_allow_ips;
  if (base.peer_keepalive_interval !== undefined) {
    payload.peer_keepalive_interval = base.peer_keepalive_interval;
  }
  if (base.host) payload.host = base.host;
  if (base.username) payload.username = base.username;
  if (base.router_credential_ref_id) payload.router_credential_ref_id = base.router_credential_ref_id;
  if (base.ssh_host_key_sha256) payload.ssh_host_key_sha256 = base.ssh_host_key_sha256;
  if (base.source_address) payload.source_address = base.source_address;
  try {
    const { data } = await apiFetch("/wireguard/teardown", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    renderResult(data);
    APPLY_TOAST_PATHS["P-awg-teardown"].toastFromResponse(data);
  } catch (e) {
    toast("Teardown ошибка: " + e.message);
  }
}

async function executeStationApplyClick(deps) {
  const readPayload = deps.readPayload;
  const renderResult = deps.renderResult;
  const hasPreviewResult = deps.hasPreviewResult;
  const isOpenNetwork = deps.isOpenNetwork;
  if (isOpenNetwork && isOpenNetwork()) {
    toast("Open network unsupported");
    return;
  }
  let payload;
  try {
    payload = readPayload(true);
  } catch (e) {
    toast(e.message);
    return;
  }
  if (!payload.confirm_live_apply) {
    toast("Требуется confirm для station apply");
    return;
  }
  if (hasPreviewResult && !hasPreviewResult()) {
    toast("Сначала Preview join — проверьте planned ops");
    return;
  }
  try {
    const { data } = await apiFetch("/wifi/station/apply", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    renderResult(data);
    APPLY_TOAST_PATHS["P-station-apply"].toastFromResponse(data);
  } catch (e) {
    if (deps.applyErrorBox) {
      text(deps.applyErrorBox, "Apply error:\n" + e.message);
    }
    toast("Station apply ошибка: " + e.message);
  }
}

async function executeStationTeardownClick(deps) {
  const readPayload = deps.readPayload;
  const renderResult = deps.renderResult;
  const isOpenNetwork = deps.isOpenNetwork;
  if (isOpenNetwork && isOpenNetwork()) {
    toast("Open network unsupported");
    return;
  }
  let base;
  try {
    base = readPayload(false);
  } catch (e) {
    toast(e.message);
    return;
  }
  const confirmEl = document.getElementById("uplink-station-confirm");
  if (!confirmEl || !confirmEl.checked) {
    toast("Требуется confirm для station teardown");
    return;
  }
  const payload = {
    ...base,
    confirm_live_teardown: true,
  };
  const hostEl = document.getElementById("uplink-station-host");
  const userEl = document.getElementById("uplink-station-username");
  const routerCredEl = document.getElementById("uplink-station-router-cred-ref");
  const pinEl = document.getElementById("uplink-station-ssh-pin");
  const sourceEl = document.getElementById("uplink-station-source-address");
  const hostVal = hostEl && hostEl.value ? hostEl.value.trim() : "";
  const userVal = userEl && userEl.value ? userEl.value.trim() : "";
  const routerCredVal = routerCredEl && routerCredEl.value ? routerCredEl.value.trim() : "";
  const pinVal = pinEl && pinEl.value ? pinEl.value.trim() : "";
  const sourceVal = sourceEl && sourceEl.value ? sourceEl.value.trim() : "";
  if (hostVal) payload.host = hostVal;
  if (userVal) payload.username = userVal;
  if (routerCredVal) payload.router_credential_ref_id = routerCredVal;
  if (pinVal) payload.ssh_host_key_sha256 = pinVal;
  if (sourceVal) payload.source_address = sourceVal;
  try {
    const { data } = await apiFetch("/wifi/station/teardown", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    renderResult(data);
    APPLY_TOAST_PATHS["P-station-teardown"].toastFromResponse(data);
  } catch (e) {
    if (deps.applyErrorBox) {
      text(deps.applyErrorBox, "Teardown error:\n" + e.message);
    }
    toast("Station teardown ошибка: " + e.message);
  }
}

async function executeUplinkApApplyClick(resultBox) {
  const confirmEl = document.getElementById("uplink-ap-confirm");
  if (!confirmEl || !confirmEl.checked) {
    toast("confirm_live_apply required");
    return;
  }
  const apEl = document.getElementById("uplink-ap-id");
  const ssidEl = document.getElementById("uplink-ap-ssid");
  const pskEl = document.getElementById("uplink-ap-psk-ref");
  const payload = {
    ap_id: apEl && apEl.value ? apEl.value : "",
    ssid: ssidEl && ssidEl.value ? ssidEl.value : "",
    enabled: true,
    credential_ref_id: pskEl && pskEl.value ? pskEl.value : null,
    band: (apEl && apEl.value && apEl.value.indexOf("WifiMaster1") >= 0)
      ? "BAND_5GHZ"
      : "BAND_2_4GHZ",
    wpa_mode: "WPA2",
    guest_isolation: false,
    captive_portal: "Disabled",
    confirm_live_apply: true,
  };
  try {
    const { data } = await apiFetch("/wifi/apply", {
      method: "POST",
      body: payload,
      idempotencyKey: uuid(),
    });
    if (resultBox) text(resultBox, JSON.stringify(data, null, 2));
    APPLY_TOAST_PATHS["P-uplink-ap-apply"].toastFromResponse(data);
  } catch (e) {
    if (resultBox) text(resultBox, "AP apply error:\n" + e.message);
    toast("AP apply ошибка: " + e.message);
  }
}

function buildWifiApplyActionHarness(options) {
  const ui = buildWifiApplyFormSurface(options || { expendable: false });
  const readPayload = ui.readPayload;
  const renderResult = ui.renderResult;
  const btnRow = el("div", "btn-row");
  const applyBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "wifi-apply-action-btn",
  });
  text(applyBtn, "Apply");
  applyBtn.addEventListener("click", () => {
    executeWifiApplyClick(readPayload, renderResult);
  });
  const teardownBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "wifi-teardown-action-btn",
  });
  text(teardownBtn, "Teardown");
  teardownBtn.addEventListener("click", () => {
    executeWifiTeardownClick(readPayload, renderResult);
  });
  append(btnRow, applyBtn, teardownBtn);
  append(ui.panel, ui.form, btnRow, ui.resultPanel);
  return { panel: ui.panel, applyBtn, teardownBtn, ui };
}

function buildAwgApplyActionHarness(options) {
  const ui = buildAwgApplyFormSurface(options || { expendable: false });
  const readPayload = ui.readPayload;
  const renderResult = ui.renderResult;
  const btnRow = el("div", "btn-row");
  const applyBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "awg-apply-action-btn",
  });
  text(applyBtn, "Apply");
  applyBtn.addEventListener("click", () => {
    executeAwgApplyClick(readPayload, renderResult);
  });
  const teardownBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "awg-teardown-action-btn",
  });
  text(teardownBtn, "Teardown");
  teardownBtn.addEventListener("click", () => {
    executeAwgTeardownClick(readPayload, renderResult);
  });
  append(btnRow, applyBtn, teardownBtn);
  append(ui.panel, ui.form, btnRow, ui.resultPanel);
  return { panel: ui.panel, applyBtn, teardownBtn, ui };
}

function buildStationApplyActionHarness(options) {
  const opts = options || {};
  const intent = opts.intent || {
    ssid: "Venue-Test",
    band: "BAND_2_4GHZ",
    credential_ref_id: "credref:test",
  };
  const ui = buildUplinkStationApplyFormSurface();
  ui.updateIntentSummary(intent);
  const stationApplyResultBox = el("pre", "mono uplink-station-apply-result");
  function readPayload(includeConfirm) {
    return readUplinkStationApplyPayloadFromDom(includeConfirm, intent);
  }
  function renderResult(data) {
    renderApplyResultWithVerdict(null, stationApplyResultBox, data);
  }
  const hasPreview = opts.hasPreviewResult !== false;
  const stationDeps = {
    readPayload,
    renderResult,
    hasPreviewResult: () => hasPreview,
    isOpenNetwork: () => false,
    applyErrorBox: stationApplyResultBox,
  };
  const applyBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "station-apply-action-btn",
  });
  text(applyBtn, "Apply station join");
  applyBtn.addEventListener("click", () => {
    executeStationApplyClick(stationDeps);
  });
  const teardownBtn = el("button", "btn btn-secondary", {
    type: "button",
    "data-testid": "station-teardown-action-btn",
  });
  text(teardownBtn, "Teardown station");
  teardownBtn.addEventListener("click", () => {
    executeStationTeardownClick(stationDeps);
  });
  const btnRow = el("div", "btn-row");
  append(btnRow, applyBtn, teardownBtn);
  ui.form.appendChild(btnRow);
  return {
    form: ui.form,
    applyBtn,
    teardownBtn,
    ui,
    intent,
    resultBox: stationApplyResultBox,
  };
}

function buildUplinkApApplyActionHarness(options) {
  const apRangeStart = (options && options.expendable) ? 0 : 3;
  const apRangeEnd = 6;
  const panel = el("section", "uplink-section panel uplink-ap-apply-test");
  const apForm = el("form", "form-grid uplink-ap-apply-form");
  const apField = el("div", "form-field");
  append(apField, text(el("label", "", { for: "uplink-ap-id" }), "Test AP"));
  const apSelect = el("select", "", { id: "uplink-ap-id", name: "ap_id" });
  ["WifiMaster0", "WifiMaster1"].forEach((master) => {
    for (let n = apRangeStart; n <= apRangeEnd; n += 1) {
      const apId = master + "/AccessPoint" + n;
      const opt = el("option", "", { value: apId });
      text(opt, apId);
      apSelect.appendChild(opt);
    }
  });
  append(apField, apSelect);
  apForm.appendChild(apField);
  appendFormField(apForm, "ssid", "Own SSID", "text", fieldTooltipOpts("wifi_ap", "ssid", {
    id: "uplink-ap-ssid",
    placeholder: "Staff-Field",
  }));
  appendFormField(apForm, "credential_ref_id", "PSK credential_ref_id", "text", fieldTooltipOpts("wifi_ap", "credential_ref_id", {
    id: "uplink-ap-psk-ref",
    placeholder: "credref:…",
  }));
  const apConfirmField = el("div", "form-field uplink-ap-confirm");
  append(
    apConfirmField,
    el("input", "", {
      id: "uplink-ap-confirm",
      name: "confirm_live_apply",
      type: "checkbox",
    }),
  );
  append(
    apConfirmField,
    text(
      el("label", "", { for: "uplink-ap-confirm" }),
      "Подтверждаю live apply на test AP (confirm_live_apply required)",
    ),
  );
  apForm.appendChild(apConfirmField);
  const apResultBox = el("pre", "mono uplink-ap-result");
  text(apResultBox, "AP preview/apply not run.");
  const applyBtn = el("button", "btn btn-primary", {
    type: "button",
    "data-testid": "uplink-ap-apply-action-btn",
  });
  text(applyBtn, "Apply own SSID (confirm required)");
  applyBtn.addEventListener("click", () => {
    executeUplinkApApplyClick(apResultBox);
  });
  append(panel, apForm, applyBtn, apResultBox);
  return { panel, applyBtn, resultBox: apResultBox, form: apForm };
}

function formatWifiApplyToast(data, action) {
  const prefix = wifiApplyToastPrefix(data, action);
  const honesty = wifiApplyHonestySummary(data);
  return prefix + (honesty ? " — " + honesty : "");
}

function formatAwgApplyToast(data, action) {
  const prefix = awgApplyToastPrefix(data, action);
  const honesty = awgApplyHonestySummary(data);
  return prefix + (honesty ? " — " + honesty : "");
}

function formatStationApplyToast(data, action) {
  const prefix = stationApplyToastPrefix(data, action);
  const honesty = stationApplyHonestySummary(data);
  return prefix + (honesty ? " — " + honesty : "");
}

function buildUplinkApApplyToast(data) {
  return formatWifiApplyToast(data, "Apply");
}

const NETWORK_FAMILY_PREVIEW_NOT_RUN = "Preview not run yet.";

const NETWORK_FAMILY_PREVIEW_ERROR_LABELS = {
  "vlan.preview_failed": "VLAN preview",
  "dhcp.preview_failed": "DHCP preview",
  "dns.preview_failed": "DNS preview",
  "firewall.preview_failed": "Firewall preview",
};

function networkFamilyPreviewErrorHuman(code, message) {
  const label =
    NETWORK_FAMILY_PREVIEW_ERROR_LABELS[code] || "Network family preview";
  const msg = message ? String(message) : "validation failed";
  return label + " failed: " + msg;
}

function networkFamilyDescribeOp(op, index) {
  if (!op || typeof op !== "object") return String(index + 1) + ". —";
  const lines = [String(index + 1) + ". " + String(op.operation || "—")];
  Object.keys(op)
    .sort()
    .forEach((key) => {
      if (key === "operation" || key === "notes") return;
      const val = op[key];
      if (val == null) return;
      if (Array.isArray(val)) return;
      lines.push("   " + key + ": " + String(val));
    });
  const notes = Array.isArray(op.notes) ? op.notes : [];
  notes.forEach((note) => {
    lines.push("   citation: " + String(note));
  });
  return lines.join("\n");
}

function renderNetworkFamilyPreviewResult(resultBox, data, summaryFields) {
  if (!resultBox) return;
  if (!data || typeof data !== "object") {
    text(resultBox, NETWORK_FAMILY_PREVIEW_NOT_RUN);
    return;
  }
  const lines = [];
  lines.push("verification_status: " + (data.verification_status || "—"));
  const fields = Array.isArray(summaryFields) ? summaryFields : [];
  fields.forEach(({ key, label, format }) => {
    const raw = data[key];
    let display = "—";
    if (raw != null) {
      if (format === "json" && (Array.isArray(raw) || typeof raw === "object")) {
        display = JSON.stringify(raw);
      } else {
        display = String(raw);
      }
    }
    lines.push(String(label || key) + ": " + display);
  });
  lines.push("");
  lines.push("NO APPLY — offline_unverified only, NOT device-verified.");
  lines.push(
    "Grammar NOT device-certified — preview compile only, no router dispatch.",
  );
  const plannerNotes = Array.isArray(data.notes) ? data.notes : [];
  if (plannerNotes.length) {
    lines.push("");
    lines.push("planner notes:");
    plannerNotes.forEach((note) => {
      lines.push("  - " + String(note));
    });
  }
  const applyOps = Array.isArray(data.apply_ops) ? data.apply_ops : [];
  lines.push("");
  lines.push("apply_ops (" + String(applyOps.length) + ") — forward apply order:");
  if (!applyOps.length) {
    lines.push("  (none)");
  } else {
    applyOps.forEach((op, i) => {
      lines.push(networkFamilyDescribeOp(op, i));
    });
  }
  const teardownOps = Array.isArray(data.teardown_ops) ? data.teardown_ops : [];
  lines.push("");
  lines.push(
    "teardown_ops (" + String(teardownOps.length) + ") — reverse order for rollback:",
  );
  if (!teardownOps.length) {
    lines.push("  (none)");
  } else {
    teardownOps.forEach((op, i) => {
      lines.push(networkFamilyDescribeOp(op, i));
    });
  }
  text(resultBox, lines.join("\n"));
}

function appendNetworkFamilyPreviewHonestyBanners(panel) {
  append(
    panel,
    text(
      el("p", "field-hint config-network-family-preview-safety"),
      "PREVIEW ONLY — offline_unverified: grammar NOT device-certified. "
        + "NO APPLY — compile-only preview; no dispatch to router.",
    ),
  );
  append(
    panel,
    text(
      el("p", "field-hint config-network-family-preview-banner"),
      "verification_status=offline_unverified — compile-time label only; "
        + "not runtime observe and not apply success.",
    ),
  );
}

function vpnPolicyDescribeOp(op, index) {
  if (!op || typeof op !== "object") return String(index + 1) + ". —";
  const lines = [String(index + 1) + ". " + String(op.operation || "—")];
  if (op.policy_name) lines.push("   policy_name: " + String(op.policy_name));
  if (op.interface_id) lines.push("   interface_id: " + String(op.interface_id));
  if (op.name_server_address) lines.push("   name_server: " + String(op.name_server_address));
  if (op.global_priority != null) lines.push("   global_priority: " + String(op.global_priority));
  if (op.global_order != null) lines.push("   global_order: " + String(op.global_order));
  if (op.global_auto != null) lines.push("   global_auto: " + String(op.global_auto));
  const notes = Array.isArray(op.notes) ? op.notes : [];
  notes.forEach((note) => {
    lines.push("   citation: " + String(note));
  });
  return lines.join("\n");
}

function buildVlanPreviewFormSurface() {
  const panel = el("section", "config-section panel config-vlan-preview");
  append(panel, text(el("h2", "panel-title"), "VLAN preview"));
  appendNetworkFamilyPreviewHonestyBanners(panel);
  const form = el("form", "form-grid config-vlan-preview-form");
  appendFormField(form, "bridge_id", "Bridge id", "text", fieldTooltipOpts("vlan", "bridge_id", {
    id: "vlan-preview-bridge-id",
    testId: "vlan-preview-bridge-id",
    placeholder: "Bridge3",
  }));
  appendFormField(form, "zone_id", "Zone id", "text", fieldTooltipOpts("vlan", "zone_id", {
    id: "vlan-preview-zone-id",
    testId: "vlan-preview-zone-id",
    placeholder: "staff",
  }));
  appendFormField(form, "vlan_id", "VLAN id", "number", fieldTooltipOpts("vlan", "vlan_id", {
    id: "vlan-preview-vlan-id",
    testId: "vlan-preview-vlan-id",
    placeholder: "20",
    min: "1",
    max: "4094",
  }));
  appendFormField(form, "ipv4_cidr", "IPv4 CIDR", "text", fieldTooltipOpts("vlan", "ipv4_cidr", {
    id: "vlan-preview-ipv4-cidr",
    testId: "vlan-preview-ipv4-cidr",
    placeholder: "10.20.0.0/24",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "vlan-preview-advanced-settings",
  });
  appendFormField(advanced.body, "ipv4_gateway", "IPv4 gateway", "text", fieldTooltipOpts("vlan", "ipv4_gateway", {
    id: "vlan-preview-ipv4-gateway",
    testId: "vlan-preview-ipv4-gateway",
    placeholder: "10.20.0.1",
  }));
  form.appendChild(advanced.details);
  const resultBox = el("pre", "mono config-result");
  text(resultBox, NETWORK_FAMILY_PREVIEW_NOT_RUN);
  const summaryFields = [
    { key: "bridge_id", label: "bridge_id" },
    { key: "zone_id", label: "zone_id" },
    { key: "vlan_id", label: "vlan_id" },
    { key: "ipv4_cidr", label: "ipv4_cidr" },
    { key: "ipv4_gateway", label: "ipv4_gateway" },
  ];
  function readPayload() {
    const bridgeId = (document.getElementById("vlan-preview-bridge-id").value || "").trim();
    const zoneId = (document.getElementById("vlan-preview-zone-id").value || "").trim();
    const vlanRaw = (document.getElementById("vlan-preview-vlan-id").value || "").trim();
    const ipv4Cidr = (document.getElementById("vlan-preview-ipv4-cidr").value || "").trim();
    const ipv4Gateway = (document.getElementById("vlan-preview-ipv4-gateway").value || "").trim();
    if (!bridgeId) throw new Error("bridge_id required");
    if (!zoneId) throw new Error("zone_id required");
    if (!vlanRaw) throw new Error("vlan_id required");
    if (!ipv4Cidr) throw new Error("ipv4_cidr required");
    if (!ipv4Gateway) throw new Error("ipv4_gateway required");
    const vlanId = Number(vlanRaw);
    if (!Number.isInteger(vlanId)) throw new Error("vlan_id must be integer");
    return {
      bridge_id: bridgeId,
      zone_id: zoneId,
      vlan_id: vlanId,
      ipv4_cidr: ipv4Cidr,
      ipv4_gateway: ipv4Gateway,
    };
  }
  async function runPreview() {
    let payload;
    try {
      payload = readPayload();
    } catch (e) {
      toast("VLAN preview: " + e.message);
      return;
    }
    try {
      const { data } = await apiFetch("/vlan/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      renderNetworkFamilyPreviewResult(resultBox, data, summaryFields);
      toast("VLAN preview: offline_unverified — NO APPLY (not device-verified)");
    } catch (e) {
      const human = networkFamilyPreviewErrorHuman(e.code, e.message);
      text(resultBox, "Preview error:\n" + human);
      toast("VLAN preview ошибка: " + human);
    }
  }
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runPreview();
  });
  const btnRow = el("div", "btn-row");
  const btn = el("button", "btn btn-primary", { type: "button" });
  text(btn, "Preview VLAN");
  btn.addEventListener("click", runPreview);
  append(btnRow, btn);
  const resultPanel = el("div", "config-vlan-preview-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "Compiled ops (preview only)"));
  append(resultPanel, resultBox);
  append(panel, form, btnRow, resultPanel);
  return { panel, form, advancedDetails: advanced.details, readPayload, resultBox };
}

function buildDhcpPreviewFormSurface() {
  const panel = el("section", "config-section panel config-dhcp-preview");
  append(panel, text(el("h2", "panel-title"), "DHCP preview"));
  appendNetworkFamilyPreviewHonestyBanners(panel);
  const form = el("form", "form-grid config-dhcp-preview-form");
  appendFormField(form, "zone_id", "Zone id", "text", fieldTooltipOpts("dhcp", "zone_id", {
    id: "dhcp-preview-zone-id",
    testId: "dhcp-preview-zone-id",
    placeholder: "Guest",
  }));
  appendFormField(form, "pool_start", "Pool start", "text", fieldTooltipOpts("dhcp", "pool_start", {
    id: "dhcp-preview-pool-start",
    testId: "dhcp-preview-pool-start",
    placeholder: "10.10.0.100",
  }));
  appendFormField(form, "pool_end", "Pool end", "text", fieldTooltipOpts("dhcp", "pool_end", {
    id: "dhcp-preview-pool-end",
    testId: "dhcp-preview-pool-end",
    placeholder: "10.10.0.200",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "dhcp-preview-advanced-settings",
  });
  appendFormField(advanced.body, "lease_seconds", "Lease seconds", "number", fieldTooltipOpts("dhcp", "lease_seconds", {
    id: "dhcp-preview-lease-seconds",
    testId: "dhcp-preview-lease-seconds",
    placeholder: "86400",
    min: "60",
    max: "604800",
  }));
  const reservationsEditor = buildCollectionEditor({
    testId: "dhcp-preview-reservations",
    label: "Reservations",
    addLabel: "Add reservation",
    columns: [
      { key: "mac_address", label: "MAC", type: "text" },
      { key: "ipv4_address", label: "IPv4", type: "text" },
    ],
  });
  form._dhcpReservationsEditor = reservationsEditor;
  append(advanced.body, reservationsEditor.container);
  form.appendChild(advanced.details);
  const resultBox = el("pre", "mono config-result");
  text(resultBox, NETWORK_FAMILY_PREVIEW_NOT_RUN);
  const summaryFields = [
    { key: "zone_id", label: "zone_id" },
    { key: "pool_start", label: "pool_start" },
    { key: "pool_end", label: "pool_end" },
    { key: "lease_seconds", label: "lease_seconds" },
    { key: "reservations", label: "reservations", format: "json" },
  ];
  function readPayload() {
    const zoneId = (document.getElementById("dhcp-preview-zone-id").value || "").trim();
    const poolStart = (document.getElementById("dhcp-preview-pool-start").value || "").trim();
    const poolEnd = (document.getElementById("dhcp-preview-pool-end").value || "").trim();
    const leaseRaw = (document.getElementById("dhcp-preview-lease-seconds").value || "").trim();
    if (!zoneId) throw new Error("zone_id required");
    if (!poolStart) throw new Error("pool_start required");
    if (!poolEnd) throw new Error("pool_end required");
    if (!leaseRaw) throw new Error("lease_seconds required");
    const leaseSeconds = Number(leaseRaw);
    if (!Number.isInteger(leaseSeconds)) throw new Error("lease_seconds must be integer");
    return {
      zone_id: zoneId,
      pool_start: poolStart,
      pool_end: poolEnd,
      lease_seconds: leaseSeconds,
      reservations: readDhcpReservationsFromEditor(reservationsEditor),
    };
  }
  async function runPreview() {
    let payload;
    try {
      payload = readPayload();
    } catch (e) {
      toast("DHCP preview: " + e.message);
      return;
    }
    try {
      const { data } = await apiFetch("/dhcp/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      renderNetworkFamilyPreviewResult(resultBox, data, summaryFields);
      toast("DHCP preview: offline_unverified — NO APPLY (not device-verified)");
    } catch (e) {
      const human = networkFamilyPreviewErrorHuman(e.code, e.message);
      text(resultBox, "Preview error:\n" + human);
      toast("DHCP preview ошибка: " + human);
    }
  }
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runPreview();
  });
  const btnRow = el("div", "btn-row");
  const btn = el("button", "btn btn-primary", { type: "button" });
  text(btn, "Preview DHCP");
  btn.addEventListener("click", runPreview);
  append(btnRow, btn);
  const resultPanel = el("div", "config-dhcp-preview-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "Compiled ops (preview only)"));
  append(resultPanel, resultBox);
  append(panel, form, btnRow, resultPanel);
  return { panel, form, advancedDetails: advanced.details, readPayload, resultBox, reservationsEditor };
}

function buildDnsPreviewFormSurface() {
  const panel = el("section", "config-section panel config-dns-preview");
  append(panel, text(el("h2", "panel-title"), "DNS preview"));
  appendNetworkFamilyPreviewHonestyBanners(panel);
  const form = el("form", "form-grid config-dns-preview-form");
  appendFormField(form, "zone_id", "Zone id", "text", fieldTooltipOpts("dns", "zone_id", {
    id: "dns-preview-zone-id",
    testId: "dns-preview-zone-id",
    placeholder: "Guest",
  }));
  appendFormField(form, "local_fqdn", "Local FQDN", "text", fieldTooltipOpts("dns", "local_fqdn", {
    id: "dns-preview-local-fqdn",
    testId: "dns-preview-local-fqdn",
    placeholder: "order.guest.example.com",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "dns-preview-advanced-settings",
  });
  const upstreamEditor = buildCollectionEditor({
    testId: "dns-preview-upstream-resolvers",
    label: "Upstream resolvers",
    addLabel: "Add resolver",
    minRows: 1,
    initialRows: [{ address: "8.8.8.8" }],
    columns: [{ key: "address", label: "Address", type: "text" }],
  });
  form._dnsUpstreamEditor = upstreamEditor;
  append(advanced.body, upstreamEditor.container);
  form.appendChild(advanced.details);
  const resultBox = el("pre", "mono config-result");
  text(resultBox, NETWORK_FAMILY_PREVIEW_NOT_RUN);
  const summaryFields = [
    { key: "zone_id", label: "zone_id" },
    { key: "local_fqdn", label: "local_fqdn" },
    { key: "upstream_resolvers", label: "upstream_resolvers", format: "json" },
  ];
  function readPayload() {
    const zoneId = (document.getElementById("dns-preview-zone-id").value || "").trim();
    const localFqdn = (document.getElementById("dns-preview-local-fqdn").value || "").trim();
    const resolvers = readStringListFromEditor(upstreamEditor);
    if (!zoneId) throw new Error("zone_id required");
    if (!localFqdn) throw new Error("local_fqdn required");
    if (!resolvers.length) throw new Error("upstream_resolvers required");
    return { zone_id: zoneId, local_fqdn: localFqdn, upstream_resolvers: resolvers };
  }
  async function runPreview() {
    let payload;
    try {
      payload = readPayload();
    } catch (e) {
      toast("DNS preview: " + e.message);
      return;
    }
    try {
      const { data } = await apiFetch("/dns/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      renderNetworkFamilyPreviewResult(resultBox, data, summaryFields);
      toast("DNS preview: offline_unverified — NO APPLY (not device-verified)");
    } catch (e) {
      const human = networkFamilyPreviewErrorHuman(e.code, e.message);
      text(resultBox, "Preview error:\n" + human);
      toast("DNS preview ошибка: " + human);
    }
  }
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runPreview();
  });
  const btnRow = el("div", "btn-row");
  const btn = el("button", "btn btn-primary", { type: "button" });
  text(btn, "Preview DNS");
  btn.addEventListener("click", runPreview);
  append(btnRow, btn);
  const resultPanel = el("div", "config-dns-preview-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "Compiled ops (preview only)"));
  append(resultPanel, resultBox);
  append(panel, form, btnRow, resultPanel);
  return { panel, form, advancedDetails: advanced.details, readPayload, resultBox, upstreamEditor };
}

function buildFirewallPreviewFormSurface() {
  const panel = el("section", "config-section panel config-firewall-preview");
  append(panel, text(el("h2", "panel-title"), "Firewall preview"));
  appendNetworkFamilyPreviewHonestyBanners(panel);
  const form = el("form", "form-grid config-firewall-preview-form");
  appendFormField(form, "zone_id", "Zone id", "text", fieldTooltipOpts("firewall", "zone_id", {
    id: "firewall-preview-zone-id",
    testId: "firewall-preview-zone-id",
    placeholder: "Guest",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "firewall-preview-advanced-settings",
  });
  const rulesEditor = buildCollectionEditor({
    testId: "firewall-preview-rules",
    label: "Firewall rules",
    addLabel: "Add rule",
    minRows: 1,
    initialRows: [
      { action: "Allow", destination_family: "OrderPage", ordinal: 10 },
    ],
    columns: [
      { key: "action", label: "Action", type: "select", options: FIREWALL_ACTION_OPTIONS },
      {
        key: "destination_family",
        label: "Destination",
        type: "select",
        options: FIREWALL_DESTINATION_OPTIONS,
      },
      { key: "ordinal", label: "Ordinal", type: "number" },
    ],
  });
  form._firewallRulesEditor = rulesEditor;
  append(advanced.body, rulesEditor.container);
  form.appendChild(advanced.details);
  const resultBox = el("pre", "mono config-result");
  text(resultBox, NETWORK_FAMILY_PREVIEW_NOT_RUN);
  const summaryFields = [
    { key: "zone_id", label: "zone_id" },
    { key: "rules", label: "rules", format: "json" },
  ];
  function readPayload() {
    const zoneId = (document.getElementById("firewall-preview-zone-id").value || "").trim();
    const rules = readFirewallRulesFromEditor(rulesEditor);
    if (!zoneId) throw new Error("zone_id required");
    if (!rules.length) throw new Error("rules required");
    return { zone_id: zoneId, rules };
  }
  async function runPreview() {
    let payload;
    try {
      payload = readPayload();
    } catch (e) {
      toast("Firewall preview: " + e.message);
      return;
    }
    try {
      const { data } = await apiFetch("/firewall/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      renderNetworkFamilyPreviewResult(resultBox, data, summaryFields);
      toast("Firewall preview: offline_unverified — NO APPLY (not device-verified)");
    } catch (e) {
      const human = networkFamilyPreviewErrorHuman(e.code, e.message);
      text(resultBox, "Preview error:\n" + human);
      toast("Firewall preview ошибка: " + human);
    }
  }
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runPreview();
  });
  const btnRow = el("div", "btn-row");
  const btn = el("button", "btn btn-primary", { type: "button" });
  text(btn, "Preview firewall");
  btn.addEventListener("click", runPreview);
  append(btnRow, btn);
  const resultPanel = el("div", "config-firewall-preview-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "Compiled ops (preview only)"));
  append(resultPanel, resultBox);
  append(panel, form, btnRow, resultPanel);
  return { panel, form, advancedDetails: advanced.details, readPayload, resultBox, rulesEditor };
}

function buildVpnPolicyPreviewFormSurface() {
  const panel = el("section", "config-section panel config-vpn-policy-preview");
  append(panel, text(el("h2", "panel-title"), "VPN policy-routing preview"));
  append(
    panel,
    text(
      el("p", "field-hint config-vpn-policy-preview-safety"),
      "PREVIEW ONLY — help-verified grammar, NOT device-verified. "
        + "Apply-маршрута нет: компилятор показывает sealed ops и unknowns без dispatch.",
    ),
  );
  append(
    panel,
    text(
      el("p", "field-hint config-vpn-policy-preview-banner"),
      "verification_status=help_verified_grammar_unapplied — это compile-time label, "
        + "не runtime observe и не успех применения.",
    ),
  );
  const form = el("form", "form-grid config-vpn-policy-preview-form");
  appendFormField(form, "policy_name", "Policy name", "text", fieldTooltipOpts("vpn_policy_routing", "policy_name", {
    id: "vpn-policy-name",
    testId: "vpn-policy-name",
    placeholder: "vpn-uplink",
  }));
  appendFormField(form, "vpn_interface", "VPN interface", "text", fieldTooltipOpts("vpn_policy_routing", "vpn_interface", {
    id: "vpn-policy-interface",
    testId: "vpn-policy-interface",
    placeholder: "GigabitEthernet1 or Wireguard0",
  }));
  const advanced = buildAdvancedSettingsBlock({
    testId: "vpn-policy-preview-advanced-settings",
  });
  appendFormField(advanced.body, "interface_kind", "Interface kind (optional)", "text", fieldTooltipOpts("vpn_policy_routing", "interface_kind", {
    id: "vpn-policy-interface-kind",
    testId: "vpn-policy-interface-kind",
    placeholder: "wireguard",
  }));
  appendFormSelect(
    advanced.body,
    "address_configured",
    "address_configured",
    [
      ["auto", "auto (omit)"],
      ["true", "true"],
      ["false", "false"],
    ],
    fieldTooltipOpts("vpn_policy_routing", "address_configured", {
      id: "vpn-policy-address-configured",
      testId: "vpn-policy-address-configured",
      omitName: true,
    }),
  );
  appendFormSelect(
    advanced.body,
    "ip_global_mode",
    "ip_global mode",
    [
      ["auto", "auto"],
      ["priority", "priority (number below)"],
      ["order", "order (number below)"],
    ],
    fieldTooltipOpts("vpn_policy_routing", "ip_global", {
      id: "vpn-policy-ip-global",
      testId: "vpn-policy-ip-global",
      omitName: true,
    }),
  );
  appendFormField(advanced.body, "ip_global_value", "ip_global priority/order", "number", fieldTooltipOpts("vpn_policy_routing", "ip_global.priority", {
    id: "vpn-policy-ip-global-value",
    testId: "vpn-policy-ip-global-value",
    placeholder: "700",
    min: "0",
    max: "65535",
    omitName: true,
  }));
  const nameServersEditor = buildCollectionEditor({
    testId: "vpn-policy-name-servers",
    label: "name_servers",
    addLabel: "Add name server",
    columns: [
      { key: "address", label: "Address", type: "text" },
      { key: "domain", label: "Domain (optional)", type: "text", optional: true },
      { key: "on_interface", label: "on_interface (optional)", type: "text", optional: true },
    ],
  });
  form._vpnNameServersEditor = nameServersEditor;
  append(advanced.body, nameServersEditor.container);
  form.appendChild(advanced.details);
  const resultBox = el("pre", "mono config-result");
  function renderVpnPolicyPreviewResult(data) {
    if (!data || typeof data !== "object") {
      text(resultBox, "Preview not run yet.");
      return;
    }
    const lines = [];
    lines.push("verification_status: " + (data.verification_status || "—"));
    lines.push("policy_name: " + (data.policy_name || "—"));
    lines.push("vpn_interface: " + (data.vpn_interface || "—"));
    lines.push("");
    lines.push("NO APPLY — help-verified grammar only, NOT device-verified.");
    const unknowns = Array.isArray(data.unknowns) ? data.unknowns : [];
    lines.push("");
    lines.push("unknowns (" + String(unknowns.length) + "):");
    if (!unknowns.length) lines.push("  (none)");
    else unknowns.forEach((item, i) => lines.push("  " + String(i + 1) + ". " + String(item)));
    const applyOps = Array.isArray(data.apply_ops) ? data.apply_ops : [];
    lines.push("");
    lines.push("apply_ops (" + String(applyOps.length) + "):");
    applyOps.forEach((op, i) => lines.push(vpnPolicyDescribeOp(op, i)));
    const teardownOps = Array.isArray(data.teardown_ops) ? data.teardown_ops : [];
    lines.push("");
    lines.push("teardown_ops (" + String(teardownOps.length) + "):");
    teardownOps.forEach((op, i) => lines.push(vpnPolicyDescribeOp(op, i)));
    text(resultBox, lines.join("\n"));
  }
  function readPayload() {
    const policyName = (document.getElementById("vpn-policy-name").value || "").trim();
    const vpnInterface = (document.getElementById("vpn-policy-interface").value || "").trim();
    if (!policyName) throw new Error("policy_name required");
    if (!vpnInterface) throw new Error("vpn_interface required");
    const payload = { policy_name: policyName, vpn_interface: vpnInterface };
    const kindVal = (document.getElementById("vpn-policy-interface-kind").value || "").trim();
    if (kindVal) payload.interface_kind = kindVal;
    const addressMode = document.getElementById("vpn-policy-address-configured").value || "auto";
    if (addressMode === "true") payload.address_configured = true;
    else if (addressMode === "false") payload.address_configured = false;
    const ipMode = document.getElementById("vpn-policy-ip-global").value || "auto";
    if (ipMode === "auto") {
      payload.ip_global = "auto";
    } else {
      const raw = (document.getElementById("vpn-policy-ip-global-value").value || "").trim();
      const num = Number(raw);
      if (!Number.isFinite(num)) throw new Error("ip_global priority/order number required");
      payload.ip_global = ipMode === "order" ? { order: num } : { priority: num };
    }
    const nsRows = readVpnNameServersFromEditor(nameServersEditor);
    if (nsRows.length) payload.name_servers = nsRows;
    return payload;
  }
  async function runPreview() {
    let payload;
    try {
      payload = readPayload();
    } catch (e) {
      toast("VPN policy: " + e.message);
      return;
    }
    try {
      const { data } = await apiFetch("/vpn/policy-routing/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      renderVpnPolicyPreviewResult(data);
      toast("Preview: " + (data.verification_status || "ok") + " — NO APPLY (help-verified only)");
    } catch (e) {
      text(resultBox, "Preview error:\n" + e.message);
      toast("VPN policy preview ошибка: " + e.message);
    }
  }
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runPreview();
  });
  const btnRow = el("div", "btn-row");
  const btn = el("button", "btn btn-primary", { type: "button" });
  text(btn, "Preview policy-routing");
  btn.addEventListener("click", runPreview);
  append(btnRow, btn);
  const resultPanel = el("div", "config-vpn-policy-preview-result panel-sub");
  append(resultPanel, text(el("h3", "panel-subtitle"), "Compiled ops (preview only)"));
  append(resultPanel, resultBox);
  append(panel, form, btnRow, resultPanel);
  return { panel, form, advancedDetails: advanced.details, readPayload, resultBox, nameServersEditor };
}

function sanitizeUplinkReadbackDisplayValue(key, value) {
  if (value === null || value === undefined) return "—";
  if (isUplinkReadbackSecretKey(key)) {
    return "(значение скрыто — upstream SSID/секреты не выводятся в UI)";
  }
  if (typeof value === "boolean") return value ? "true" : "false";
  const text = String(value);
  if (/REDACTED/i.test(text)) return "(redacted)";
  return text;
}

function uplinkReadbackFieldValue(readback, key) {
  if (!readback || typeof readback !== "object") return undefined;
  if (Object.prototype.hasOwnProperty.call(readback, key)) return readback[key];
  if (key === "txbytes") return readback.tx_bytes;
  if (key === "rxbytes") return readback.rx_bytes;
  if (key === "link") return readback.link;
  if (key === "connected") return readback.connected;
  return undefined;
}

function classifyUplinkSignalEvidence(signal, explanation) {
  if (!signal) {
    return {
      role: "informational",
      badge: "ℹ Наблюдение",
      detail: "поле readback — не участвует в verdict signals",
    };
  }
  if (!explanation || typeof explanation !== "object") {
    return {
      role: "informational",
      badge: "ℹ Наблюдение",
      detail: "verdict_explanation отсутствует — роль сигнала неизвестна",
    };
  }
  const read = Array.isArray(explanation.signals_read) ? explanation.signals_read : [];
  const rejected = Array.isArray(explanation.signals_rejected) ? explanation.signals_rejected : [];
  const missing = Array.isArray(explanation.signals_missing) ? explanation.signals_missing : [];

  const rejectedEntry = rejected.find((item) => item && item.signal === signal);
  if (rejectedEntry) {
    const reason = rejectedEntry.reason
      ? verdictRejectionHumanLabel(rejectedEntry.reason)
      : "отвергнут — не засчитан";
    return { role: "rejected", badge: "✗ Отвергнут", detail: reason };
  }

  const readEntry = read.find((item) => item && item.signal === signal);
  if (readEntry) {
    return {
      role: "counted",
      badge: "✓ Засчитан",
      detail: "использован при формировании uplink_verification_status",
    };
  }

  const missingCodes = UPLINK_MISSING_SIGNAL_MAP[signal] || [];
  if (missingCodes.some((code) => missing.indexOf(code) >= 0)) {
    return {
      role: "missing",
      badge: "— Недостаточно",
      detail: "сигнал отсутствует или недостаточен для более сильного вердикта",
    };
  }

  return {
    role: "informational",
    badge: "ℹ Наблюдение",
    detail: "прочитано, но не засчитано как доказательство",
  };
}

function verdictOnlyRowDisplayValue(signal, explanation) {
  if (!explanation || typeof explanation !== "object") return "—";
  const read = Array.isArray(explanation.signals_read) ? explanation.signals_read : [];
  const entry = read.find((item) => item && item.signal === signal);
  if (!entry) return "—";
  return formatVerdictSignalValue(entry.value);
}

function appendUplinkReadbackEvidenceRow(tbody, fieldLabel, displayValue, signal, explanation) {
  const evidence = classifyUplinkSignalEvidence(signal, explanation);
  const tr = el("tr", "uplink-readback-row uplink-evidence-" + evidence.role);
  append(tr, text(el("td"), fieldLabel));
  append(tr, text(el("td", "mono uplink-readback-value"), displayValue));
  append(tr, text(el("td", "uplink-evidence-badge uplink-evidence-badge-" + evidence.role), evidence.badge));
  append(tr, text(el("td", "uplink-evidence-detail"), evidence.detail));
  tbody.appendChild(tr);
}

function renderUplinkStationReadbackInto(container, observe, fallbackStationId) {
  if (!container) return;
  clear(container);

  append(
    container,
    text(el("h3", "panel-subtitle"), "Venue uplink / station (upstream Wi‑Fi client readback)"),
  );
  append(
    container,
    text(
      el("p", "field-hint uplink-readback-honesty"),
      "Значения из uplink_readback после Apply/Teardown. "
        + "Колонка «Роль в вердикте» — из verdict_explanation: "
        + "✓ засчитан, ✗ отвергнут (обманчивый сигнал), ℹ только наблюдение. "
        + "connected/state/auth-type без ✓ — не доказательство работоспособности.",
    ),
  );

  const meta = el("p", "field-hint uplink-readback-meta");
  const stationId =
    observe && observe.stationId
      ? observe.stationId
      : fallbackStationId || "—";
  const statusText =
    observe && observe.verificationStatus
      ? observe.verificationStatus
      : "—";
  text(
    meta,
    "station_id: "
      + stationId
      + " · uplink_verification_status: "
      + statusText
      + (observe && observe.hasApply ? "" : " · station join не применён"),
  );
  container.appendChild(meta);

  const table = el("table", "data-table uplink-status-venue-table uplink-readback-table");
  const headRow = el("tr");
  ["Поле / сигнал", "Прочитано (readback)", "Роль в вердикте", "Пояснение"].forEach((h) => {
    headRow.appendChild(text(el("th"), h));
  });
  const tbody = el("tbody");

  if (!observe || !observe.hasApply) {
    const tr = el("tr", "uplink-readback-no-data");
    append(tr, text(el("td", "mono"), stationId));
    append(tr, text(el("td", "uplink-readback-empty"), "—"));
    append(tr, text(el("td"), "—"));
    append(
      tr,
      text(
        el("td"),
        "Данные readback отсутствуют — выполните Apply station join или Teardown",
      ),
    );
    tbody.appendChild(tr);
    append(table, headRow, tbody);
    container.appendChild(table);
    return;
  }

  const readback = observe.readback;
  const explanation = observe.explanation;

  if (!readback || typeof readback !== "object") {
    const tr = el("tr", "uplink-readback-missing");
    append(tr, text(el("td", "mono"), stationId));
    append(tr, text(el("td", "uplink-readback-empty"), "—"));
    append(tr, text(el("td"), "—"));
    append(
      tr,
      text(
        el("td"),
        "uplink_readback отсутствует в ответе — observe не выполнен или readback failed",
      ),
    );
    tbody.appendChild(tr);
    UPLINK_VERDICT_ONLY_ROWS.forEach((row) => {
      const displayValue = verdictOnlyRowDisplayValue(row.signal, explanation);
      if (displayValue === "—") return;
      appendUplinkReadbackEvidenceRow(tbody, row.label, displayValue, row.signal, explanation);
    });
    append(table, headRow, tbody);
    container.appendChild(table);
    return;
  }

  if (
    uplinkReadbackFieldValue(readback, "configured_ssid") !== undefined
    || uplinkReadbackFieldValue(readback, "associated_ssid") !== undefined
  ) {
    appendUplinkReadbackEvidenceRow(
      tbody,
      "configured SSID (show rc)",
      sanitizeUplinkReadbackDisplayValue("configured_ssid", uplinkReadbackFieldValue(readback, "configured_ssid")),
      null,
      explanation,
    );
    appendUplinkReadbackEvidenceRow(
      tbody,
      "associated SSID (runtime)",
      sanitizeUplinkReadbackDisplayValue("associated_ssid", uplinkReadbackFieldValue(readback, "associated_ssid")),
      "associated_ssid_matches_intent",
      explanation,
    );
  }

  UPLINK_READBACK_FIELD_ROWS.forEach((row) => {
    const raw = uplinkReadbackFieldValue(readback, row.readbackKey);
    if (raw === undefined && row.signal) {
      const missingCodes = UPLINK_MISSING_SIGNAL_MAP[row.signal] || [];
      const missing = explanation && Array.isArray(explanation.signals_missing)
        ? explanation.signals_missing
        : [];
      if (!missingCodes.some((code) => missing.indexOf(code) >= 0)) return;
    }
    if (raw === undefined && !row.signal) return;
    const displayValue =
      raw === undefined ? "—" : sanitizeUplinkReadbackDisplayValue(row.readbackKey, raw);
    appendUplinkReadbackEvidenceRow(tbody, row.label, displayValue, row.signal, explanation);
  });

  const authType = uplinkReadbackFieldValue(readback, "auth-type");
  const authTypeAlt = uplinkReadbackFieldValue(readback, "auth_type");
  const authVal = authType !== undefined ? authType : authTypeAlt;
  if (authVal !== undefined) {
    appendUplinkReadbackEvidenceRow(
      tbody,
      "auth-type (runtime)",
      sanitizeUplinkReadbackDisplayValue("auth_type", authVal),
      "connected",
      explanation,
    );
  }

  UPLINK_VERDICT_ONLY_ROWS.forEach((row) => {
    const displayValue = verdictOnlyRowDisplayValue(row.signal, explanation);
    if (displayValue === "—") return;
    appendUplinkReadbackEvidenceRow(tbody, row.label, displayValue, row.signal, explanation);
  });

  append(table, headRow, tbody);
  container.appendChild(table);
}

function renderStationApplyPlanSummary(previewData, targetBox) {
  if (!previewData || typeof previewData !== "object") {
    text(targetBox, "Run Preview join first to see planned ops.");
    return;
  }
  const lines = [];
  lines.push("Planned station_id: " + (previewData.station_id || "—"));
  lines.push(
    "grammar_verification_status: "
      + (previewData.grammar_verification_status || previewData.verification_status || "—"),
  );
  lines.push(
    "planned_uplink_verification_level (compile-time only): "
      + (previewData.planned_uplink_verification_level || "—"),
  );
  lines.push("");
  lines.push("Will apply these sealed ops:");
  const ops = Array.isArray(previewData.apply_ops) ? previewData.apply_ops : [];
  if (!ops.length) {
    lines.push("  (none — run preview first)");
  } else {
    ops.forEach((op, i) => {
      lines.push("  " + String(i + 1) + ". " + uplinkDescribeStationOp(op));
    });
  }
  text(targetBox, lines.join("\n"));
}

async function renderUplink(root) {
  clear(root);
  await loadFieldManifest();
  append(root, text(el("h1", "view-title"), "Uplink — полевая установка"));

  append(
    root,
    text(
      el("p", "field-hint uplink-honesty-banner"),
      "Venue Wi‑Fi client (WISP): scan → credential_ref → preview sealed ops → apply/teardown "
        + "(confirm-gated). First association bounded (5 GHz WPA2, one network); "
        + "open/captive/standby/failover unverified. "
        + "Preset planner: wifi_wan unsupported / wifi_wan_not_certified.",
    ),
  );

  let statusPayload = null;
  let routersPayload = null;
  try {
    const [statusResp, routersResp] = await Promise.all([
      apiFetch("/status"),
      apiFetch("/routers"),
    ]);
    statusPayload = statusResp.data;
    routersPayload = routersResp.data;
    sessionMemory.status = statusPayload;
  } catch (err) {
    renderError(root, err, () => renderUplink(root));
    return;
  }

  const firstRouterId =
    routersPayload && routersPayload.items && routersPayload.items[0]
      ? routersPayload.items[0].router_id
      : "";

  function uplinkLabClass() {
    if (statusPayload && statusPayload.lab_class) return String(statusPayload.lab_class);
    if (statusPayload && statusPayload.router_control_lab_class) {
      return String(statusPayload.router_control_lab_class);
    }
    return "";
  }

  function uplinkIsExpendableLab() {
    return uplinkLabClass() === "expendable_development_router";
  }

  const uplinkState = {
    scanResults: [],
    skippedNotice: "",
    selected: null,
    credentialRefId: "",
    previewResult: null,
    openNetwork: false,
    lastStationObserve: null,
  };
  let venueReadbackWrap = null;

  const scanPanel = el("section", "uplink-section panel uplink-scan");
  append(scanPanel, text(el("h2", "panel-title"), "1. Scan venue Wi‑Fi"));
  append(
    scanPanel,
    text(
      el("p", "field-hint"),
      "Read-only site-survey (WifiMaster0/1). Per-network security when RCI encryption present "
        + "(per_network_security_present); open networks shown as open — join not supported yet.",
    ),
  );

  const siteSurveyUi = buildSiteSurveyFormSurface();
  const scanForm = siteSurveyUi.form;
  const readSurveyBodyForRadio = siteSurveyUi.readSurveyBodyForRadio;
  const readScanMode = siteSurveyUi.readScanMode;
  scanForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runUplinkScan();
  });

  const scanBtnRow = el("div", "btn-row");
  const scanBtn = el("button", "btn btn-primary", { type: "submit", form: "" });
  scanBtn.setAttribute("form", "uplink-scan-form-inner");
  scanForm.id = "uplink-scan-form-inner";
  text(scanBtn, "Scan site-survey");
  scanBtn.addEventListener("click", (ev) => {
    ev.preventDefault();
    runUplinkScan();
  });
  append(scanBtnRow, scanBtn);

  const scanSkippedNotice = el("p", "field-hint uplink-scan-skipped-notice");
  scanSkippedNotice.hidden = true;
  const scanListWrap = el("div", "table-wrap uplink-scan-list");
  const scanEmpty = el("p", "empty-state uplink-scan-empty");
  text(scanEmpty, "Нажмите Scan для списка сетей.");
  append(scanListWrap, scanEmpty);

  async function runUplinkScan() {
    const { radios } = readScanMode();
    uplinkState.scanResults = [];
    uplinkState.skippedNotice = "";
    uplinkState.selected = null;
    uplinkState.previewResult = null;
    try {
      let skippedTotal = 0;
      const merged = [];
      let lastSurveyData = null;
      for (const radio of radios) {
        const { data } = await apiFetch("/wifi/site-survey", {
          method: "POST",
          body: readSurveyBodyForRadio(radio),
          idempotencyKey: uuid(),
        });
        lastSurveyData = data;
        skippedTotal += Number(data.skipped_row_count || 0);
        const nets = Array.isArray(data.networks) ? data.networks : [];
        nets.forEach((net) => {
          merged.push({
            ...net,
            survey_radio: radio,
            band_label: uplinkRadioLabel(radio),
          });
        });
      }
      uplinkState.scanResults = merged;
      if (skippedTotal > 0) {
        uplinkState.skippedNotice =
          "Notice: skipped_row_count=" + String(skippedTotal) + " (partial rows omitted).";
      }
      renderScanList();
      toast(
        formatSiteSurveyResultToast(
          lastSurveyData
            ? Object.assign({}, lastSurveyData, { networks: merged })
            : null,
        ),
      );
    } catch (e) {
      renderScanList();
      toast("Scan ошибка: " + e.message);
    }
  }

  function renderScanList() {
    clear(scanListWrap);
    if (uplinkState.skippedNotice) {
      text(scanSkippedNotice, uplinkState.skippedNotice);
      scanSkippedNotice.hidden = false;
    } else {
      scanSkippedNotice.hidden = true;
      clear(scanSkippedNotice);
    }
    if (!uplinkState.scanResults.length) {
      append(scanListWrap, scanEmpty);
      return;
    }
    const table = el("table", "data-table uplink-network-table");
    const hr = el("tr");
    ["Select", "SSID", "Signal", "Band", "Security"].forEach((h) => {
      hr.appendChild(text(el("th"), h));
    });
    const tbody = el("tbody");
    uplinkState.scanResults.forEach((net, idx) => {
      const tr = el("tr", "uplink-network-row");
      const selectTd = el("td", "");
      const pickBtn = el("button", "btn btn-secondary uplink-pick-network", {
        type: "button",
        "data-index": String(idx),
      });
      text(pickBtn, "Select");
      pickBtn.addEventListener("click", () => {
        uplinkState.selected = net;
        uplinkState.previewResult = null;
        if (selectedNetEl) {
          text(
            selectedNetEl,
            uplinkDisplaySsid(net)
              + " · "
              + net.band_label
              + " · security: "
              + uplinkSecurityLabel(net),
          );
        }
        const isOpenRow = net.wpa_mode === "open";
        if (openNetworkEl) openNetworkEl.checked = isOpenRow;
        uplinkState.openNetwork = isOpenRow;
        updateOpenUi();
        refreshStationIntentUi();
        toast("Selected: " + uplinkDisplaySsid(net));
      });
      selectTd.appendChild(pickBtn);
      tr.appendChild(selectTd);
      [
        uplinkDisplaySsid(net),
        uplinkSignalLabel(net.signal_quality, net.rssi),
        net.band_label || "unknown",
        uplinkSecurityLabel(net),
      ].forEach((cell) => {
        tr.appendChild(text(el("td"), cell));
      });
      tbody.appendChild(tr);
    });
    append(table, hr, tbody);
    scanListWrap.appendChild(table);
  }

  append(scanPanel, scanForm, scanBtnRow, scanSkippedNotice, scanListWrap);
  append(root, scanPanel);

  const credPanel = el("section", "uplink-section panel uplink-credential");
  append(credPanel, text(el("h2", "panel-title"), "2. Password → credential_ref"));
  append(
    credPanel,
    text(
      el("p", "field-hint uplink-cred-safety"),
      "Enroll one-shot → vault; UI хранит только credential_ref_id. Секрет очищается после submit.",
    ),
  );
  const selectedNetEl = el("p", "field-hint uplink-selected-network");
  text(selectedNetEl, "Сеть не выбрана — выберите из scan.");
  append(credPanel, selectedNetEl);

  const openField = el("div", "form-field uplink-open-network-field");
  const openNetworkEl = el("input", "", {
    id: "uplink-open-network",
    name: "open_network",
    type: "checkbox",
  });
  append(openField, openNetworkEl);
  append(
    openField,
    text(el("label", "", { for: "uplink-open-network" }), "Open network (no password)"),
  );
  append(credPanel, openField);

  const openUnsupportedEl = el("p", "field-hint uplink-open-unsupported");
  openUnsupportedEl.hidden = true;
  text(
    openUnsupportedEl,
    "not yet supported: no verified open-network authentication grammar",
  );
  append(credPanel, openUnsupportedEl);

  const credForm = el("form", "form-grid uplink-credential-form");
  appendFormField(credForm, "router_id", "Router ID", "text", {
    id: "uplink-router-id",
    placeholder: "rtr_…",
  });
  appendFormField(credForm, "enroll_value", "Venue Wi‑Fi password (one-shot → vault)", "password", {
    id: "uplink-enroll-value",
    placeholder: "не сохраняется после enroll",
    omitName: true,
  });
  if (firstRouterId) {
    const routerEl = credForm.querySelector("#uplink-router-id");
    if (routerEl) routerEl.value = firstRouterId;
  }

  function updateOpenUi() {
    const isOpen = !!(openNetworkEl && openNetworkEl.checked);
    uplinkState.openNetwork = isOpen;
    openUnsupportedEl.hidden = !isOpen;
    const valueEl = document.getElementById("uplink-enroll-value");
    if (valueEl) valueEl.disabled = isOpen;
    if (previewJoinBtn) {
      previewJoinBtn.disabled = isOpen;
      previewJoinBtn.hidden = isOpen;
    }
  }

  let previewJoinBtn = null;

  openNetworkEl.addEventListener("change", () => {
    updateOpenUi();
  });

  async function runUplinkEnroll() {
    if (uplinkState.openNetwork) {
      toast("Open network: password enroll не требуется");
      return;
    }
    const routerEl = document.getElementById("uplink-router-id");
    const valueEl = document.getElementById("uplink-enroll-value");
    const routerId = routerEl && routerEl.value ? routerEl.value.trim() : "";
    const enrollValue = valueEl && valueEl.value ? valueEl.value : "";
    if (!routerId || !enrollValue) {
      toast("router_id и password обязательны");
      return;
    }
    try {
      const { data } = await apiFetch(
        "/routers/" + encodeURIComponent(routerId) + "/credentials",
        {
          method: "PUT",
          body: { kind: "WifiWanPsk", secret: enrollValue },
          idempotencyKey: uuid(),
        },
      );
      if (valueEl) valueEl.value = "";
      uplinkState.credentialRefId = data.credential_ref_id || "";
      if (credRefEl) text(credRefEl, uplinkState.credentialRefId || "—");
      toast("Enrolled: " + (data.credential_ref_id || "ok"));
      refreshStationIntentUi();
    } catch (e) {
      if (valueEl) valueEl.value = "";
      toast("Enroll ошибка: " + e.message);
    }
  }

  credForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runUplinkEnroll();
  });
  const credEnrollBtn = el("button", "btn btn-primary", { type: "button" });
  text(credEnrollBtn, "Enroll password (PUT)");
  credEnrollBtn.addEventListener("click", () => {
    runUplinkEnroll();
  });
  const credRefEl = el("p", "mono uplink-cred-ref-display");
  text(credRefEl, "credential_ref_id: —");
  append(credPanel, credForm, credEnrollBtn, credRefEl);
  append(root, credPanel);

  const previewPanel = el("section", "uplink-section panel uplink-preview");
  append(previewPanel, text(el("h2", "panel-title"), "3. Preview join + station apply/teardown"));
  append(
    previewPanel,
    text(
      el("p", "field-hint uplink-join-blocked"),
      "Preview компилирует sealed ops offline "
        + "(grammar_verification_status=device_accepted_grammar; "
        + "planned_uplink_verification_level=planned_uplink_verified_bounded — compile-time label, "
        + "NOT runtime uplink_verification_status). "
        + "Apply/teardown ниже — confirm-gated; runtime uplink_verification_status "
        + "(offline: uplink_dispatched_unverified; live observe после uplink_settle_seconds 20–30s) "
        + "приходит только из ответа Apply/Teardown, не из preview.",
    ),
  );
  append(
    previewPanel,
    text(
      el("p", "field-hint uplink-station-apply-warning"),
      "ВНИМАНИЕ: Apply station может оборвать текущий uplink роутера (WAN/Wi‑Fi client). "
        + "Подтверждайте только после preview и понимания последствий.",
    ),
  );

  const previewResultBox = el("pre", "mono uplink-preview-result");
  text(previewResultBox, "Preview not run yet.");
  const stationPlanBox = el("pre", "mono uplink-station-plan-summary");
  text(stationPlanBox, "Run Preview join first to see planned ops.");

  const stationApplyUi = buildUplinkStationApplyFormSurface();
  const stationApplyForm = stationApplyUi.form;
  const updateStationIntentSummary = stationApplyUi.updateIntentSummary;

  function readUplinkStationIntentBase() {
    if (!uplinkState.selected) {
      throw new Error("Выберите сеть из scan");
    }
    const credRef =
      uplinkState.credentialRefId
      || (credRefEl && credRefEl.textContent
        ? credRefEl.textContent.replace(/^credential_ref_id:\s*/, "").trim()
        : "");
    if (!credRef || credRef === "—") {
      throw new Error("Сначала enroll password → credential_ref_id");
    }
    const ssid =
      uplinkState.selected.hidden || !uplinkState.selected.ssid
        ? "HIDDEN-NET-PLACEHOLDER"
        : String(uplinkState.selected.ssid);
    const band = uplinkBandForRadio(uplinkState.selected.survey_radio || "WifiMaster0");
    const body = {
      mode: "WifiWan",
      ssid,
      band,
      credential_ref_id: credRef,
    };
    if (uplinkState.selected.bssid) body.bssid = uplinkState.selected.bssid;
    return body;
  }

  function readUplinkStationApplyPayload(includeConfirm) {
    return readUplinkStationApplyPayloadFromDom(includeConfirm, readUplinkStationIntentBase());
  }

  function refreshStationIntentUi() {
    try {
      const base = readUplinkStationIntentBase();
      updateStationIntentSummary(base);
      const bssidEl = document.getElementById("uplink-station-bssid");
      if (bssidEl && base.bssid && !bssidEl.value) bssidEl.value = base.bssid;
    } catch (_err) {
      updateStationIntentSummary(null);
    }
  }
  refreshStationIntentUi();

  function renderStationApplyResult(data) {
    renderApplyResultWithVerdict(stationVerdictExplanationBox, stationApplyResultBox, data);
    const band =
      uplinkState.selected && uplinkState.selected.survey_radio
        ? uplinkBandForRadio(uplinkState.selected.survey_radio)
        : "BAND_2_4GHZ";
    uplinkState.lastStationObserve = {
      hasApply: true,
      readback: data && data.uplink_readback ? data.uplink_readback : null,
      explanation: data && data.verdict_explanation ? data.verdict_explanation : null,
      verificationStatus: data ? data.uplink_verification_status : null,
      stationId: data && data.station_id ? data.station_id : uplinkStationIdForBand(band),
    };
    renderUplinkStationReadbackInto(
      venueReadbackWrap,
      uplinkState.lastStationObserve,
      uplinkStationIdForBand(band),
    );
  }

  async function runUplinkPreview() {
    if (uplinkState.openNetwork) {
      if (!uplinkState.selected) {
        toast("Выберите сеть из scan");
        return;
      }
      const ssid =
        uplinkState.selected.hidden || !uplinkState.selected.ssid
          ? "OPEN-NET-PLACEHOLDER"
          : String(uplinkState.selected.ssid);
      const band = uplinkBandForRadio(uplinkState.selected.survey_radio || "WifiMaster0");
      try {
        await apiFetch("/wifi/station/preview", {
          method: "POST",
          body: {
            mode: "WifiWan",
            ssid,
            band,
            auth_mode: "open",
          },
          idempotencyKey: uuid(),
        });
        text(previewResultBox, "Unexpected: open preview should fail closed.");
      } catch (e) {
        text(
          previewResultBox,
          "Open network blocked:\n" + e.message,
        );
        toast("Open network unsupported");
      }
      return;
    }
    if (!uplinkState.selected) {
      toast("Выберите сеть из scan");
      return;
    }
    const credRef =
      uplinkState.credentialRefId
      || (credRefEl && credRefEl.textContent
        ? credRefEl.textContent.replace(/^credential_ref_id:\s*/, "").trim()
        : "");
    if (!credRef || credRef === "—") {
      toast("Сначала enroll password → credential_ref_id");
      return;
    }
    const ssid =
      uplinkState.selected.hidden || !uplinkState.selected.ssid
        ? "HIDDEN-NET-PLACEHOLDER"
        : String(uplinkState.selected.ssid);
    const band = uplinkBandForRadio(uplinkState.selected.survey_radio || "WifiMaster0");
    const body = {
      mode: "WifiWan",
      ssid,
      band,
      credential_ref_id: credRef,
    };
    if (uplinkState.selected.bssid) body.bssid = uplinkState.selected.bssid;
    try {
      const { data } = await apiFetch("/wifi/station/preview", {
        method: "POST",
        body,
        idempotencyKey: uuid(),
      });
      uplinkState.previewResult = data;
      const lines = [];
      lines.push(
        "grammar_verification_status: "
          + (data.grammar_verification_status || data.verification_status || "—"),
      );
      lines.push(
        "planned_uplink_verification_level: "
          + (data.planned_uplink_verification_level || "—"),
      );
      lines.push("station_id: " + (data.station_id || "—"));
      const ops = Array.isArray(data.apply_ops) ? data.apply_ops : [];
      lines.push("apply_ops (" + String(ops.length) + "):");
      ops.forEach((op, i) => {
        lines.push("  " + String(i + 1) + ". " + uplinkDescribeStationOp(op));
      });
      text(previewResultBox, lines.join("\n"));
      renderStationApplyPlanSummary(data, stationPlanBox);
      toast("Preview compiled — review plan before Apply");
    } catch (e) {
      text(previewResultBox, "Preview error:\n" + e.message);
      toast("Preview ошибка: " + e.message);
    }
  }

  const previewBtn = el("button", "btn btn-secondary", { type: "button" });
  text(previewBtn, "Preview join (compile only)");
  previewJoinBtn = previewBtn;
  previewBtn.addEventListener("click", () => {
    runUplinkPreview();
  });

  const stationApplyBtn = el("button", "btn btn-primary", { type: "button" });
  text(stationApplyBtn, "Apply station join");
  stationApplyBtn.addEventListener("click", () => {
    executeStationApplyClick({
      readPayload: readUplinkStationApplyPayload,
      renderResult: renderStationApplyResult,
      hasPreviewResult: () => !!uplinkState.previewResult,
      isOpenNetwork: () => uplinkState.openNetwork,
      applyErrorBox: stationApplyResultBox,
    });
  });

  const stationTeardownBtn = el("button", "btn btn-secondary", { type: "button" });
  text(stationTeardownBtn, "Teardown station");
  stationTeardownBtn.addEventListener("click", () => {
    executeStationTeardownClick({
      readPayload: () => readUplinkStationIntentBase(),
      renderResult: renderStationApplyResult,
      isOpenNetwork: () => uplinkState.openNetwork,
      applyErrorBox: stationApplyResultBox,
    });
  });

  const stationBtnRow = el("div", "btn-row");
  append(stationBtnRow, stationApplyBtn, stationTeardownBtn);
  append(
    previewPanel,
    previewBtn,
    previewResultBox,
    text(el("h3", "panel-subtitle"), "Planned ops (from preview)"),
    stationPlanBox,
    stationApplyForm,
    stationBtnRow,
    stationApplyResultPanel,
  );
  updateOpenUi();
  append(root, previewPanel);

  const apPanel = el("section", "uplink-section panel uplink-own-ssid");
  append(apPanel, text(el("h2", "panel-title"), "4. Own SSID (AP apply — device-verified test AP)"));
  const apRangeStart = uplinkIsExpendableLab() ? 0 : 3;
  const apRangeEnd = 6;
  append(
    apPanel,
    text(
      el("p", "field-hint uplink-ap-safety"),
      (uplinkIsExpendableLab()
        ? "Expendable lab: AccessPoint0–6. "
        : "Bounded test AP AccessPoint3–6 only. ")
        + "Live apply требует confirm_live_apply.",
    ),
  );

  const apForm = el("form", "form-grid uplink-ap-apply-form");
  const apField = el("div", "form-field");
  append(apField, text(el("label", "", { for: "uplink-ap-id" }), "Test AP"));
  const apSelect = el("select", "", { id: "uplink-ap-id", name: "ap_id" });
  ["WifiMaster0", "WifiMaster1"].forEach((master) => {
    for (let n = apRangeStart; n <= apRangeEnd; n += 1) {
      const apId = master + "/AccessPoint" + n;
      const opt = el("option", "", { value: apId });
      text(opt, apId);
      apSelect.appendChild(opt);
    }
  });
  append(apField, apSelect);
  apForm.appendChild(apField);

  appendFormField(apForm, "ssid", "Own SSID", "text", fieldTooltipOpts("wifi_ap", "ssid", {
    id: "uplink-ap-ssid",
    placeholder: "Staff-Field",
  }));
  appendFormField(apForm, "credential_ref_id", "PSK credential_ref_id", "text", fieldTooltipOpts("wifi_ap", "credential_ref_id", {
    id: "uplink-ap-psk-ref",
    placeholder: "credref:…",
  }));

  const apConfirmField = el("div", "form-field uplink-ap-confirm");
  append(
    apConfirmField,
    el("input", "", {
      id: "uplink-ap-confirm",
      name: "confirm_live_apply",
      type: "checkbox",
    }),
  );
  append(
    apConfirmField,
    text(
      el("label", "", { for: "uplink-ap-confirm" }),
      "Подтверждаю live apply на test AP (confirm_live_apply required)",
    ),
  );
  apForm.appendChild(apConfirmField);

  const apResultBox = el("pre", "mono uplink-ap-result");
  text(apResultBox, "AP preview/apply not run.");

  apForm.addEventListener("submit", (ev) => {
    ev.preventDefault();
    runUplinkApPreview();
  });

  async function runUplinkApPreview() {
    const apEl = document.getElementById("uplink-ap-id");
    const ssidEl = document.getElementById("uplink-ap-ssid");
    const pskEl = document.getElementById("uplink-ap-psk-ref");
    const payload = {
      ap_id: apEl && apEl.value ? apEl.value : "",
      ssid: ssidEl && ssidEl.value ? ssidEl.value : "",
      enabled: true,
      credential_ref_id: pskEl && pskEl.value ? pskEl.value : null,
      band: (apEl && apEl.value && apEl.value.indexOf("WifiMaster1") >= 0)
        ? "BAND_5GHZ"
        : "BAND_2_4GHZ",
      wpa_mode: "WPA2",
      guest_isolation: false,
      captive_portal: "Disabled",
    };
    try {
      const { data } = await apiFetch("/wifi/preview", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      text(apResultBox, JSON.stringify(data, null, 2));
      toast("AP preview compiled");
    } catch (e) {
      text(apResultBox, "AP preview error:\n" + e.message);
      toast("AP preview ошибка: " + e.message);
    }
  }

  const apBtnRow = el("div", "btn-row");
  const apPreviewBtn = el("button", "btn btn-secondary", { type: "button" });
  text(apPreviewBtn, "Preview own SSID");
  apPreviewBtn.addEventListener("click", () => {
    runUplinkApPreview();
  });
  const apApplyBtn = el("button", "btn btn-primary", { type: "button" });
  text(apApplyBtn, "Apply own SSID (confirm required)");
  apApplyBtn.addEventListener("click", () => {
    executeUplinkApApplyClick(apResultBox);
  });
  append(apBtnRow, apPreviewBtn, apApplyBtn);
  append(apPanel, apForm, apBtnRow, apResultBox);
  append(root, apPanel);

  const statusPanel = el("section", "uplink-section panel uplink-status");
  append(statusPanel, text(el("h2", "panel-title"), "5. Uplink status (observed)"));
  append(
    statusPanel,
    text(
      el("p", "field-hint uplink-status-honesty"),
      "Venue uplink (station client): таблица readback заполняется из ответа Apply/Teardown "
        + "(uplink_readback + verdict_explanation); до apply — «данные отсутствуют». "
        + "connected/state/auth-type с меткой ✗ Отвергнут — не доказательство. "
        + "Наш SSID AP (rebroadcast): Refresh → observed-state; link_up отдельно; "
        + "device_connected никогда не означает on-air.",
    ),
  );

  const statusTableWrap = el("div", "table-wrap uplink-status-table-wrap");
  venueReadbackWrap = el("div", "uplink-venue-readback-wrap");
  const statusResultBox = el("pre", "mono uplink-status-result");

  function renderUplinkStatusRows(data) {
    const apSection = el("div", "uplink-status-ap-section");
    const aps = data && Array.isArray(data.access_points) ? data.access_points : [];

    append(
      apSection,
      text(el("h3", "panel-subtitle"), "Our SSID AP (rebroadcast — observed-state)"),
    );
    const apTable = el("table", "data-table uplink-status-ap-table");
    const apHr = el("tr");
    ["AP", "SSID", "Link up (AP rebroadcast)", "device_connected (info only)"].forEach((h) => {
      apHr.appendChild(text(el("th"), h));
    });
    const apBody = el("tbody");
    if (!aps.length) {
      const emptyTr = el("tr", "uplink-status-ap-empty");
      append(
        emptyTr,
        text(el("td"), "—"),
        text(el("td"), "—"),
        text(el("td"), "—"),
        text(el("td"), "Refresh для observed-state AP"),
      );
      apBody.appendChild(emptyTr);
    } else {
      aps.forEach((ap) => {
        if (!ap || !ap.ap_id) return;
        const tr = el("tr", "uplink-status-ap-row");
        const linkUpDisplay =
          ap.link_up == null
            ? "unknown"
            : ap.link_up
              ? "up (link_up)"
              : "down (link_up)";
        const deviceConnectedDisplay =
          ap.device_connected == null
            ? "unknown"
            : String(ap.device_connected) + " (not on-air)";
        append(tr, text(el("td", "mono"), ap.ap_id || "—"));
        append(tr, text(el("td"), ap.ssid != null ? String(ap.ssid) : "unknown"));
        append(tr, text(el("td"), linkUpDisplay));
        append(tr, text(el("td"), deviceConnectedDisplay));
        apBody.appendChild(tr);
      });
    }
    append(apTable, apHr, apBody);
    apSection.appendChild(apTable);

    clear(statusTableWrap);
    const band =
      uplinkState.selected && uplinkState.selected.survey_radio
        ? uplinkBandForRadio(uplinkState.selected.survey_radio)
        : "BAND_2_4GHZ";
    renderUplinkStationReadbackInto(
      venueReadbackWrap,
      uplinkState.lastStationObserve,
      uplinkStationIdForBand(band),
    );
    append(statusTableWrap, venueReadbackWrap, apSection);
  }

  const uplinkObservedUi = buildWifiObservedFormSurface({
    idPrefix: "uplink-status",
    apRangeStart: 3,
    apRangeEnd: 3,
    formTestId: "uplink-status-observed-form",
  });
  const readUplinkObservedPayload = uplinkObservedUi.readPayload;

  const statusRefreshBtn = el("button", "btn btn-secondary", { type: "button" });
  text(statusRefreshBtn, "Refresh uplink status");
  statusRefreshBtn.addEventListener("click", async () => {
    try {
      const payload = readUplinkObservedPayload();
      const { data } = await apiFetch("/wifi/observed-state", {
        method: "POST",
        body: payload,
        idempotencyKey: uuid(),
      });
      renderUplinkStatusRows(data);
      text(statusResultBox, JSON.stringify(data, null, 2));
      toast(formatWifiObservedSessionToast(data));
    } catch (e) {
      renderUplinkStatusRows(null);
      text(statusResultBox, "Observed-state error:\n" + e.message);
      toast("Status ошибка: " + e.message);
    }
  });
  append(statusPanel, uplinkObservedUi.form, statusRefreshBtn, statusTableWrap, statusResultBox);
  renderUplinkStatusRows(null);
  append(root, statusPanel);
}

function setActiveNav(view) {
  document.querySelectorAll(".nav-link").forEach((link) => {
    const isActive = link.getAttribute("data-view") === view;
    link.classList.toggle("is-active", isActive);
    if (isActive) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
}

function navigate() {
  const { view, params } = parseHash();
  setActiveNav(view);
  const root = document.getElementById("view-root");
  if (!root) return;
  switch (view) {
    case "dashboard":
      renderDashboard(root);
      break;
    case "routers":
      renderRouters(root);
      break;
    case "add-router":
      renderAddRouter(root);
      break;
    case "commissioning":
      renderCommissioning(root, params[0]);
      break;
    case "presets":
      renderPresets(root, params[0]);
      break;
    case "operations":
      renderOperations(root, params[0]);
      break;
    case "vpn":
      renderVpn(root, params[0]);
      break;
    case "config":
      renderConfig(root);
      break;
    case "uplink":
      renderUplink(root);
      break;
    case "settings":
      renderSettings(root);
      break;
    case "simple":
      renderSimpleMode(root, { step: parseSimpleWizardStep(params) });
      break;
    default:
      if (getCurrentUiMode() === "simple") setHash("simple");
      else setHash("dashboard");
  }
}

function getCurrentUiMode() {
  return normalizeUiMode(
    (document.documentElement && document.documentElement.getAttribute("data-ui-mode"))
      || localStorage.getItem(UI_MODE_KEY)
      || "simple",
  );
}

function initShell() {
  initTheme();
  initUiMode();
  const toggle = document.getElementById("nav-toggle");
  const sidebar = document.getElementById("sidebar");
  if (toggle && sidebar) {
    toggle.addEventListener("click", () => {
      const open = sidebar.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }
  document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => {
      if (sidebar) sidebar.classList.remove("is-open");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    });
  });
  const refreshBtn = document.getElementById("refresh-btn");
  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => navigate());
  }
  window.addEventListener("hashchange", navigate);
  if (!location.hash) {
    location.hash = getCurrentUiMode() === "simple" ? "#simple" : "#dashboard";
  }
  navigate();
}

if (typeof globalThis !== "undefined" && globalThis.__ROUTER_CONTROL_UI_TEST__) {
  globalThis.__ROUTER_CONTROL_UI_TEST__ = {
    sanitizeApplyResultForDisplay,
    renderApplyResultWithVerdict,
    awgApplyToastPrefix,
    wifiApplyToastPrefix,
    stationApplyToastPrefix,
    toastApplyFamilyResult,
    APPLY_TOAST_PATHS,
    executeWifiApplyClick,
    executeWifiTeardownClick,
    executeAwgApplyClick,
    executeAwgTeardownClick,
    executeStationApplyClick,
    executeStationTeardownClick,
    executeUplinkApApplyClick,
    buildWifiApplyActionHarness,
    buildAwgApplyActionHarness,
    buildStationApplyActionHarness,
    buildUplinkApApplyActionHarness,
    setApiFetchStubForTest,
    apiFetch,
    renderStationApplyPlanSummary,
    resetToastCaptureForTest,
    getCapturedToastsForTest,
    formatWifiApplyToast,
    formatAwgApplyToast,
    formatStationApplyToast,
    buildUplinkApApplyToast,
    stationApplyHonestySummary,
    awgApplyHonestySummary,
    isUplinkReadbackSecretKey,
    networkFamilyPreviewErrorHuman,
    networkFamilyDescribeOp,
    renderNetworkFamilyPreviewResult,
    NETWORK_FAMILY_PREVIEW_NOT_RUN,
    buildFieldTooltip,
    buildAdvancedSettingsBlock,
    loadFieldManifest,
    setFieldManifestForTest,
    getFieldManifestState,
    lookupFieldMeta,
    manifestFieldTooltip,
    resolveManifestTooltip,
    fieldTooltipOpts,
    buildWifiApplyFormSurface,
    readWifiApplyPayloadFromDom,
    wifiApplyHonestySummary,
    buildAwgApplyFormSurface,
    readAwgApplyPayloadFromDom,
    parseAwgAscArgs,
    buildUplinkStationApplyFormSurface,
    readUplinkStationApplyPayloadFromDom,
    buildSiteSurveyFormSurface,
    buildWifiObservedFormSurface,
    buildTrafficDiscoveryFormSurface,
    buildCommissioningCreateFormSurface,
    readCommissioningCreatePayloadFromDom,
    readLiveConnectionParamsFromDom,
    readTrafficEvidenceFromDom,
    readTrafficRouteIntentFromDom,
    formatSiteSurveyResultToast,
    formatWifiObservedSessionToast,
    applyOverallUnknownLabel,
    buildCollectionEditor,
    buildVlanPreviewFormSurface,
    buildDhcpPreviewFormSurface,
    buildDnsPreviewFormSurface,
    buildFirewallPreviewFormSurface,
    buildVpnPolicyPreviewFormSurface,
    buildPresetBootstrapDocument,
    buildPresetEditorFormSurface,
    buildPresetDocumentFromForm,
    fillPresetForm,
    vpnPolicyDescribeOp,
    readFirewallRulesFromEditor,
    readDhcpReservationsFromEditor,
    readStringListFromEditor,
    readVpnNameServersFromEditor,
    PRESET_ZONE_IDS,
    buildVpnImportFormSurface,
    readVpnImportPayloadFromDom,
    buildRciMutationFormSurface,
    readRciMutationPayloadFromDom,
    buildRciOperationOptionsFromManifest,
    resolveRciMutationRequest,
    manifestRouteToApiPath,
    lookupManifestFamily,
    deriveSimpleLinkFailReason,
    classifySimpleDiscoveryIdentityState,
    handleSimpleDiscoveryCandidates,
    appendSimpleDiscoveryDegradedWarning,
    applySimpleDiscoveryCandidateSelection,
    renderSimpleDiscoveryCandidatePicker,
    clearSimpleDiscoveryCandidatePicker,
    simpleLinkAllFiveFactsTrue,
    simpleConnectHasEnrolledTarget,
    simpleConnectDisplayLabel,
    deriveSimpleConnectStep1Ux,
    prefillSimpleConnectForm,
    buildWizardDraftFormSurface,
    readWizardDraftPayloadFromDom,
    buildWizardSshHostKeyLearnBody,
    buildWizardSshHostKeyConfirmBody,
    buildWizardHostKeyConfirmFormSurface,
    readWizardHostKeyConfirmPayloadFromDom,
    appendFormTextarea,
    buildCredentialEnrollTestSurface,
    collectDomVisibleText,
    domHasMisleadingApplySuccessText,
    HONESTY_WIFI_GUEST_ISOLATION,
    HONESTY_WIFI_CAPTIVE_PORTAL,
    HONESTY_STATION_AUTH_OPEN,
    HONESTY_WG_PATH_STYLE,
    UI_MODE_KEY,
    deriveSimpleLinkState,
    mapConnectionHealthToLinkFacts,
    fetchSimpleLinkFacts,
    buildSimpleLinkFactsFromApis,
    buildSimpleModeSurface,
    renderSimpleMode,
    parseSimpleWizardStep,
    goSimpleWizardStep,
    clampSimpleWizardStep,
    initSimpleWizardFromSurface,
    isSimpleWizardStepDone,
    markSimpleWizardStepDone,
    SIMPLE_WIZARD_STEP_COUNT,
    buildSimpleConnectStepSurface,
    buildSimpleLinkStepSurface,
    buildSimpleWifiUplinkStepSurface,
    resolveSimpleLiveConnectionParams,
    persistSimpleWizardLiveConnectionFromDraft,
    setSimpleWizardLiveConnectionForTest,
    getSimpleWizardLiveConnectionForTest,
    buildSimpleGuestWifiStepSurface,
    buildSimpleDomainStepSurface,
    buildSimpleFamiliesStepSurface,
    applyUiMode,
    initUiMode,
    getCurrentUiMode,
    normalizeUiMode,
  };
} else {
  initShell();
}
