/**
 * Minimal DOM implementation for offline UI runtime tests (Node, no browser).
 * Supports createElement, getElementById, input/select state, details.open,
 * hidden, and visible-text serialization used by tests/test_config_ui.py.
 */
function createUiDomHarness() {
  /** @type {Map<string, object>} */
  const idMap = new Map();

  function registerNode(node) {
    const id = node.attributes && node.attributes.id;
    if (id) idMap.set(String(id), node);
    for (const child of node.children || []) {
      registerNode(child);
    }
  }

  function unregisterNode(node) {
    const id = node.attributes && node.attributes.id;
    if (id && idMap.get(String(id)) === node) idMap.delete(String(id));
  }

  function dispatchEvent(node, type, evInit) {
    const handlers = node._listeners && node._listeners[type];
    if (!handlers) return;
    const ev = evInit || { type, target: node, preventDefault() {} };
    handlers.slice().forEach((fn) => {
      try {
        fn(ev);
      } catch (_err) {
        /* test harness */
      }
    });
  }

  function findLabelAncestor(node) {
    let walk = node;
    while (walk) {
      if (String(walk.tagName || "").toUpperCase() === "LABEL") {
        return walk;
      }
      walk = walk.parentNode;
    }
    return null;
  }

  function inputType(node) {
    if (node && typeof node.type === "string" && node.type) {
      return node.type.toLowerCase();
    }
    return String(node?.attributes?.type || "text").toLowerCase();
  }

  function isCheckboxInput(node) {
    return (
      String(node.tagName || "").toUpperCase() === "INPUT"
      && inputType(node) === "checkbox"
    );
  }

  function activateCheckboxInput(input) {
    if (!input || input.disabled) return;
    if (input.indeterminate) {
      input.indeterminate = false;
      input.checked = true;
      const label = findLabelAncestor(input);
      if (label?.classList?.contains("hub-toggle--unknown")) {
        label.classList.remove("hub-toggle--unknown");
      }
    } else {
      input.checked = !input.checked;
    }
    dispatchEvent(input, "change", {
      type: "change",
      target: input,
      preventDefault() {},
    });
  }

  function runControlClickActivation(control, sourceEv) {
    let controlDefaultAllowed = true;
    const controlEv = {
      type: "click",
      target: control,
      preventDefault() {
        controlDefaultAllowed = false;
      },
    };
    dispatchEvent(control, "click", controlEv);
    if (!controlDefaultAllowed || sourceEv?.defaultPrevented) {
      return;
    }
    activateCheckboxInput(control);
  }

  function runClickActivation(origin) {
    let defaultAllowed = true;
    const ev = {
      type: "click",
      target: origin,
      preventDefault() {
        defaultAllowed = false;
      },
    };
    const path = [];
    let walk = origin;
    while (walk) {
      path.unshift(walk);
      walk = walk.parentNode;
    }
    for (const el of path) {
      dispatchEvent(el, "click", ev);
      if (!defaultAllowed) {
        return;
      }
    }
    if (!defaultAllowed) {
      return;
    }
    const label = findLabelAncestor(origin);
    if (label) {
      const input = label.querySelector("input");
      if (isCheckboxInput(input) && !input.disabled && input !== origin) {
        runControlClickActivation(input, ev);
        return;
      }
    }
    if (isCheckboxInput(origin) && !origin.disabled) {
      runControlClickActivation(origin, ev);
    }
  }

  function parseAttrSelector(selector) {
    const m = String(selector || "").match(/^\[([^\]=]+)(?:=(['"]?)([^'"\]]*)\2)?\]$/);
    if (!m) return null;
    return { attr: m[1], value: m[3] };
  }

  function buildDataset(node) {
    const ds = {};
    const attrs = node.attributes || {};
    Object.keys(attrs).forEach((key) => {
      if (key.startsWith("data-") && key.length > 5) {
        const camel = key
          .slice(5)
          .replace(/-([a-z])/g, (_m, c) => c.toUpperCase());
        ds[camel] = attrs[key];
      }
    });
    return ds;
  }

  function matchesSelector(node, selector) {
    if (!selector || !node) return false;
    const attrSel = parseAttrSelector(selector);
    if (attrSel) {
      const val = node.getAttribute(attrSel.attr);
      if (attrSel.value === undefined) return val !== null && val !== undefined;
      return val === attrSel.value;
    }
    if (selector.startsWith("#")) {
      const id = node.attributes && node.attributes.id;
      return id === selector.slice(1);
    }
    if (selector.startsWith(".")) {
      const cls = selector.slice(1);
      if (node.classList && node.classList.contains(cls)) {
        return true;
      }
      const rawClassName = typeof node.className === "string" ? node.className : "";
      return rawClassName.split(/\s+/).includes(cls);
    }
    return String(node.tagName || "").toLowerCase() === selector.toLowerCase();
  }

  function querySelectorAll(root, selector) {
    const out = [];
    function walk(node) {
      if (!node || typeof node !== "object") return;
      if (matchesSelector(node, selector)) out.push(node);
      for (const child of node.children || []) walk(child);
    }
    walk(root);
    return out;
  }

  function querySelector(root, selector) {
    const all = querySelectorAll(root, selector);
    return all.length ? all[0] : null;
  }

  function selectedOptionValue(selectNode) {
    for (const child of selectNode.children || []) {
      if (child.tagName === "OPTION" && child.selected) {
        return child.attributes && child.attributes.value != null
          ? String(child.attributes.value)
          : child.textContent || "";
      }
    }
    return "";
  }

  function setSelectValue(selectNode, value) {
    for (const child of selectNode.children || []) {
      if (child.tagName !== "OPTION") continue;
      const optVal =
        child.attributes && child.attributes.value != null
          ? String(child.attributes.value)
          : child.textContent || "";
      child.selected = optVal === String(value);
    }
  }

  function unregisterSubtree(node) {
    if (!node || typeof node !== "object") return;
    unregisterNode(node);
    for (const child of node.children || []) {
      unregisterSubtree(child);
    }
  }

  function createElement(tag) {
    const tagName = String(tag || "div").toUpperCase();
    const tagLower = tagName.toLowerCase();
    const node = {
      tagName,
      className: "",
      textContent: "",
      children: [],
      attributes: {},
      style: {},
      hidden: false,
      placeholder: "",
      _value: "",
      checked: false,
      selected: false,
      open: tagLower === "details" ? false : undefined,
      parentNode: null,
      _listeners: {},
      get dataset() {
        return buildDataset(this);
      },
      focus() {
        document._activeElement = this;
        dispatchEvent(this, "focus");
      },
      blur() {
        if (document._activeElement === this) document._activeElement = null;
        dispatchEvent(this, "blur");
      },
      addEventListener(type, fn) {
        if (!this._listeners[type]) this._listeners[type] = [];
        this._listeners[type].push(fn);
      },
      removeEventListener(type, fn) {
        if (!this._listeners[type]) return;
        this._listeners[type] = this._listeners[type].filter((item) => item !== fn);
      },
      click() {
        runClickActivation(this);
      },
      keydown(key) {
        dispatchEvent(this, "keydown", { type: "keydown", key, preventDefault() {} });
      },
      getAttribute(name) {
        if (name === "hidden" && this.hidden) return "hidden";
        if (name === "open" && this.open) return "open";
        if (name === "checked" && this.checked) return "checked";
        return Object.prototype.hasOwnProperty.call(this.attributes, name)
          ? this.attributes[name]
          : null;
      },
      setAttribute(name, value) {
        if (value === undefined || value === null) return;
        this.attributes[name] = String(value);
        if (name === "id") registerNode(this);
        if (name === "checked") this.checked = true;
        if (name === "open") this.open = true;
        if (name === "hidden") this.hidden = true;
      },
      removeAttribute(name) {
        delete this.attributes[name];
        if (name === "checked") this.checked = false;
        if (name === "open") this.open = false;
        if (name === "hidden") this.hidden = false;
      },
      classList: {
        _tokens: new Set(),
        add(...tokens) {
          tokens.forEach((t) => this._tokens.add(t));
        },
        remove(...tokens) {
          tokens.forEach((t) => this._tokens.delete(t));
        },
        toggle(token, force) {
          if (force === true) {
            this._tokens.add(token);
            return true;
          }
          if (force === false) {
            this._tokens.delete(token);
            return false;
          }
          if (this._tokens.has(token)) {
            this._tokens.delete(token);
            return false;
          }
          this._tokens.add(token);
          return true;
        },
        contains(token) {
          return this._tokens.has(token);
        },
      },
      appendChild(child) {
        if (!child) return child;
        if (child.parentNode && child.parentNode.children) {
          const idx = child.parentNode.children.indexOf(child);
          if (idx >= 0) child.parentNode.children.splice(idx, 1);
          unregisterNode(child.parentNode);
        }
        this.children.push(child);
        child.parentNode = this;
        registerNode(this);
        registerNode(child);
        return child;
      },
      removeChild(child) {
        const idx = this.children.indexOf(child);
        if (idx >= 0) this.children.splice(idx, 1);
        if (child.parentNode === this) child.parentNode = null;
        unregisterSubtree(child);
        registerNode(this);
        return child;
      },
      get firstChild() {
        return this.children[0] || null;
      },
      querySelector(sel) {
        if (matchesSelector(this, sel)) return this;
        for (const child of this.children || []) {
          const found = querySelector(child, sel);
          if (found) return found;
        }
        return null;
      },
      querySelectorAll(sel) {
        return querySelectorAll(this, sel);
      },
      closest(sel) {
        let node = this;
        while (node && typeof node === "object") {
          if (matchesSelector(node, sel)) return node;
          node = node.parentNode;
        }
        return null;
      },
    };

    Object.defineProperty(node, "disabled", {
      get() {
        return this._disabled === true || this.getAttribute("disabled") === "disabled";
      },
      set(value) {
        this._disabled = Boolean(value);
      },
      configurable: true,
    });

    if (tagLower === "input" || tagLower === "textarea") {
      node._indeterminate = false;
      node._selectionStart = 0;
      node._selectionEnd = 0;
      Object.defineProperty(node, "type", {
        get() {
          return this.attributes.type || "text";
        },
        set(value) {
          if (value === undefined || value === null || value === "") {
            delete this.attributes.type;
            return;
          }
          this.attributes.type = String(value);
        },
        configurable: true,
      });
      Object.defineProperty(node, "indeterminate", {
        get() {
          return this._indeterminate === true;
        },
        set(value) {
          this._indeterminate = Boolean(value);
        },
        configurable: true,
      });
      Object.defineProperty(node, "selectionStart", {
        get() {
          return this._selectionStart ?? this._value.length;
        },
        set(v) {
          this._selectionStart = Number(v);
        },
        configurable: true,
      });
      Object.defineProperty(node, "selectionEnd", {
        get() {
          return this._selectionEnd ?? this._value.length;
        },
        set(v) {
          this._selectionEnd = Number(v);
        },
        configurable: true,
      });
      Object.defineProperty(node, "value", {
        get() {
          return this._value;
        },
        set(v) {
          this._value = v == null ? "" : String(v);
          this._selectionStart = this._value.length;
          this._selectionEnd = this._value.length;
        },
        configurable: true,
      });
    }

    if (tagLower === "select") {
      Object.defineProperty(node, "value", {
        get() {
          return selectedOptionValue(this);
        },
        set(v) {
          setSelectValue(this, v);
        },
        configurable: true,
      });
    }

    if (tagLower === "details") {
      const summaryClick = () => {
        node.open = !node.open;
      };
      node._summaryHook = summaryClick;
    }

    Object.defineProperty(node, "className", {
      get() {
        if (this.classList && this.classList._tokens && this.classList._tokens.size > 0) {
          return Array.from(this.classList._tokens).join(" ");
        }
        return this._className || "";
      },
      set(value) {
        const tokens = String(value || "")
          .split(/\s+/)
          .filter(Boolean);
        this._className = tokens.join(" ");
        if (this.classList && this.classList._tokens) {
          this.classList._tokens = new Set(tokens);
        }
      },
      configurable: true,
    });

    return node;
  }

  const documentElement = {
    tagName: "HTML",
    className: "",
    children: [],
    attributes: {},
    dataset: {},
    setAttribute(name, value) {
      if (value === undefined || value === null) return;
      this.attributes[name] = String(value);
    },
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attributes, name)
        ? this.attributes[name]
        : null;
    },
    appendChild(child) {
      this.children.push(child);
      child.parentNode = this;
      registerNode(this);
      return child;
    },
    querySelector(sel) {
      return querySelector(this, sel);
    },
  };

  const body = createElement("body");
  documentElement.appendChild(body);

  const document = {
    documentElement,
    body,
    _activeElement: null,
    get activeElement() {
      return this._activeElement;
    },
    createElement,
    getElementById(id) {
      return idMap.get(String(id)) || null;
    },
    querySelector(sel) {
      return querySelector(documentElement, sel);
    },
    querySelectorAll(sel) {
      return querySelectorAll(documentElement, sel);
    },
  };

  function isHiddenNode(node) {
    if (!node || typeof node !== "object") return true;
    if (node.hidden) return true;
    if (node.tagName === "DETAILS" && !node.open) {
      return "summaryOnly";
    }
    return false;
  }

  function collectVisibleText(node, parts, insideClosedDetails) {
    if (!node || typeof node !== "object") return;
    if (node.hidden) return;

    let closedDetails = insideClosedDetails;
    if (node.tagName === "DETAILS") {
      if (!node.open) {
        for (const child of node.children || []) {
          if (child.tagName === "SUMMARY") {
            collectVisibleText(child, parts, false);
          }
        }
        return;
      }
      closedDetails = false;
    }
    if (closedDetails) return;

    if (node.tagName === "INPUT") {
      if (node._value) parts.push(node._value);
      return;
    }
    if (node.tagName === "SELECT") {
      parts.push(selectedOptionValue(node));
      return;
    }
    if (node.textContent) parts.push(node.textContent);
    for (const child of node.children || []) {
      collectVisibleText(child, parts, closedDetails);
    }
  }

  function collectDomTree(node, depth) {
    if (!node || typeof node !== "object") return null;
    const entry = {
      tag: String(node.tagName || "").toLowerCase(),
      id: node.attributes && node.attributes.id ? String(node.attributes.id) : null,
      classes: node.classList ? Array.from(node.classList._tokens) : [],
      hidden: !!node.hidden,
      open: node.tagName === "DETAILS" ? !!node.open : undefined,
      text: node.textContent || "",
      children: [],
    };
    if (node.tagName === "INPUT") {
      entry.type = node.attributes && node.attributes.type ? node.attributes.type : "text";
      entry.value = node._value || "";
      entry.checked = !!node.checked;
    }
    if (node.tagName === "SELECT") {
      entry.value = selectedOptionValue(node);
    }
    if (depth > 12) return entry;
    for (const child of node.children || []) {
      const childEntry = collectDomTree(child, depth + 1);
      if (childEntry) entry.children.push(childEntry);
    }
    return entry;
  }

  const storage = new Map();
  const localStorage = {
    getItem(key) {
      return storage.has(String(key)) ? storage.get(String(key)) : null;
    },
    setItem(key, value) {
      storage.set(String(key), String(value));
    },
    removeItem(key) {
      storage.delete(String(key));
    },
    clear() {
      storage.clear();
    },
  };

  return {
    document,
    localStorage,
    window: {
      ROUTER_CONTROL_LAB_CLASS: "",
      localStorage,
      addEventListener() {},
      setTimeout(fn, ms) {
        return setTimeout(fn, ms);
      },
      clearTimeout(id) {
        clearTimeout(id);
      },
    },
    idMap,
    collectVisibleText(root) {
      const parts = [];
      collectVisibleText(root || document.body, parts, false);
      return parts.join("\n");
    },
    collectDomTree(root) {
      return collectDomTree(root || document.body, 0);
    },
    toggleDetailsById(id) {
      const node = idMap.get(String(id));
      if (node && node.tagName === "DETAILS") {
        node.open = !node.open;
        return node.open;
      }
      const summary = idMap.get(String(id));
      if (summary && summary.tagName === "SUMMARY" && summary.parentNode) {
        summary.parentNode.open = !summary.parentNode.open;
        return summary.parentNode.open;
      }
      return null;
    },
    queryByTestId(testId, root) {
      return querySelector(root || documentElement, '[data-testid="' + testId + '"]');
    },
    simulateInput(input, value) {
      if (!input || typeof input !== "object") return;
      input.value = value == null ? "" : String(value);
      if (typeof input.focus === "function") {
        input.focus();
      }
      dispatchEvent(input, "input", { type: "input", target: input, preventDefault() {} });
    },
    dispatchFormSubmit(form) {
      if (!form || typeof form !== "object") return;
      dispatchEvent(form, "submit", {
        type: "submit",
        target: form,
        preventDefault() {},
        bubbles: true,
        cancelable: true,
      });
    },
  };
}

if (typeof module !== "undefined") {
  module.exports = { createUiDomHarness };
}
