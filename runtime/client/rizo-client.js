/**
 * Rizo Lang client runtime: renders a page in the browser.
 *
 * Security rules (checked by tests/client.test.ts):
 * - Elements are created only through el(). Text is always inserted as text
 *   (text nodes / textContent), never parsed as HTML: this file never uses
 *   innerHTML, outerHTML, insertAdjacentHTML, document.write or eval.
 * - el() allows a fixed list of attributes, and links only to paths on this
 *   site ("/..."), never to other sites or "javascript:".
 * - Data comes only from this site's endpoints (fetch with same-origin cookies).
 *
 * @typedef {"Text" | "Number" | "Bool" | "Email" | "Password" | "Date" | "ID"} FieldKind
 * @typedef {{ key: string, label: string, type: FieldKind }} FieldView
 * @typedef {{ key: string, kind: FieldKind, label: string, required: boolean, nullable: boolean, min?: number, max?: number, multiline: boolean }} FormField
 * @typedef {{ kind: "form", method: "POST" | "PUT" | "PATCH", endpoint: string, fields: FormField[], submit: string, prefill: string | null, then: string | null }} FormItem
 * @typedef {{ kind: "button", label: string, method: "DELETE", endpoint: string, then: string }} ButtonItem
 * @typedef {{ kind: "text", text: string }
 *   | { kind: "link", label: string, path: string }
 *   | { kind: "show", endpoint: string, mode: "list" | "one", model: string, fields: FieldView[], detail: { path: string, param: string } | null }
 *   | FormItem
 *   | ButtonItem} PageItem
 * @typedef {{ title: string, items: PageItem[], params: Record<string, string>, loggedIn: boolean, auth: boolean }} PageData
 */

const ALLOWED_ATTRIBUTES = new Set([
  "class", "href", "type", "role", "aria-live", "aria-busy", "aria-invalid", "aria-describedby",
  "for", "id", "name", "required", "minlength", "maxlength", "min", "max", "step", "autocomplete", "rows",
]);

/**
 * Create an element. Children that are strings become text nodes.
 * @param {string} tag
 * @param {Record<string, string>} attrs
 * @param {...(Node | string)} children
 * @returns {HTMLElement}
 */
export function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (!ALLOWED_ATTRIBUTES.has(name)) throw new Error(`attribute not allowed: ${name}`);
    if (name === "href" && !isInternalPath(value)) throw new Error("links must stay on this site");
    node.setAttribute(name, value);
  }
  for (const child of children) node.append(typeof child === "string" ? document.createTextNode(child) : child);
  return node;
}

/** @param {string} path */
export function isInternalPath(path) {
  return path.startsWith("/") && !path.startsWith("//") && !path.includes("\\") && !/[\u0000-\u001f]/.test(path);
}

/**
 * Fill ":name" parameters with values (URL-encoded).
 * @param {string} pattern
 * @param {Record<string, string>} values
 */
export function fillPath(pattern, values) {
  return pattern.replace(/:([a-zA-Z][a-zA-Z0-9]*)/g, (_, name) => {
    const v = values[name];
    if (v === undefined) throw new Error(`missing value for :${name}`);
    return encodeURIComponent(v);
  });
}

/**
 * Show a value as text.
 * @param {unknown} value
 * @param {FieldKind} type
 */
export function formatValue(value, type) {
  if (value === null || value === undefined) return "—";
  if (type === "Bool") return value ? "Yes" : "No";
  if (type === "Date" && typeof value === "string") {
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
  }
  return String(value);
}

/**
 * Fetch JSON from this site's API. Errors become readable messages.
 * @param {string} url
 * @returns {Promise<unknown>}
 */
async function getJson(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" }, credentials: "same-origin" });
  if (res.ok) return res.json();
  let message = "Something went wrong. Please try again.";
  if (res.status === 401) message = "Please log in to see this.";
  else if (res.status === 403) message = "You don't have permission to see this.";
  else if (res.status === 404) message = "Not found.";
  else {
    try {
      const body = /** @type {{ error?: { message?: unknown } }} */ (await res.json());
      if (typeof body.error?.message === "string") message = body.error.message;
    } catch {
      // keep the default message
    }
  }
  throw new Error(message);
}

/** @param {string} message */
function errorBox(message) {
  return el("p", { class: "rizo-error", role: "alert" }, message);
}

/**
 * One record as a list of label/value pairs.
 * @param {Record<string, unknown>} record
 * @param {FieldView[]} fields
 */
function recordView(record, fields) {
  const list = el("dl", { class: "rizo-record" });
  for (const f of fields) {
    if (f.key === "id") continue;
    list.append(el("dt", {}, f.label), el("dd", {}, formatValue(record[f.key], f.type)));
  }
  return list;
}

/**
 * @param {Extract<PageItem, { kind: "show" }>} item
 * @param {Record<string, string>} params
 */
function showItem(item, params) {
  const box = el("section", { class: "rizo-show", "aria-live": "polite", "aria-busy": "true" });
  const endpoint = fillPath(item.endpoint, params);

  if (item.mode === "one") {
    getJson(endpoint).then(
      (record) => box.append(recordView(/** @type {Record<string, unknown>} */ (record), item.fields)),
      (e) => box.append(errorBox(e instanceof Error ? e.message : String(e))),
    ).finally(() => box.setAttribute("aria-busy", "false"));
    return box;
  }

  const list = el("ul", { class: "rizo-list" });
  const empty = el("p", { class: "rizo-empty" }, "Nothing here yet.");
  const more = el("button", { type: "button", class: "rizo-more" }, "Load more");
  more.hidden = true;
  box.append(list, more);

  /** @param {string | null} after */
  const load = (after) => {
    more.hidden = true;
    box.setAttribute("aria-busy", "true");
    getJson(after === null ? endpoint : `${endpoint}?after=${encodeURIComponent(after)}`).then(
      (page) => {
        const { items, next } = /** @type {{ items: Record<string, unknown>[], next: string | null }} */ (page);
        if (items.length === 0 && after === null) box.replaceChildren(empty);
        for (const record of items) {
          const view = recordView(record, item.fields);
          const id = record["id"];
          if (item.detail !== null && typeof id === "string") {
            const href = fillPath(item.detail.path, { ...params, [item.detail.param]: id });
            list.append(el("li", {}, el("a", { href, class: "rizo-card" }, view)));
          } else {
            list.append(el("li", { class: "rizo-card" }, view));
          }
        }
        if (next !== null) {
          more.hidden = false;
          more.onclick = () => load(next);
        }
      },
      (e) => box.append(errorBox(e instanceof Error ? e.message : String(e))),
    ).finally(() => box.setAttribute("aria-busy", "false"));
  };
  load(null);
  return box;
}

/**
 * Go to a page on this site. Anything else is refused, so a crafted
 * "?next=" can never send people to another site.
 * @param {string} path
 */
export function go(path) {
  window.location.assign(isInternalPath(path) ? path : "/");
}

/** The "?next=" page to return to after logging in, if it is on this site. */
export function nextPath() {
  const next = new URLSearchParams(window.location.search).get("next");
  return next !== null && isInternalPath(next) ? next : "/";
}

/**
 * Send JSON to this site's API. Returns the parsed body (or null for 204).
 * Throws an Error with the server's message, and `field` when it names one.
 * @param {string} method
 * @param {string} url
 * @param {unknown} body
 * @returns {Promise<unknown>}
 */
async function sendJson(method, url, body) {
  /** @type {RequestInit} */
  const init = { method, headers: { Accept: "application/json" }, credentials: "same-origin" };
  if (body !== undefined) {
    init.headers = { Accept: "application/json", "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(url, init);
  if (res.status === 204) return null;
  /** @type {{ error?: { message?: unknown, field?: unknown } } & Record<string, unknown>} */
  let parsed = {};
  try {
    parsed = await res.json();
  } catch {
    // no body
  }
  if (res.ok) return parsed;
  const message = typeof parsed.error?.message === "string" ? parsed.error.message
    : res.status === 401 ? "Please log in first." : "Something went wrong. Please try again.";
  const error = new Error(message);
  /** @type {Error & { field?: string }} */ (error).field = typeof parsed.error?.field === "string" ? parsed.error.field : undefined;
  throw error;
}

const INPUT_TYPES = /** @type {Record<FieldKind, string>} */ ({
  Text: "text", Email: "email", Password: "password", Number: "number", Bool: "checkbox", Date: "datetime-local", ID: "text",
});

/** @param {number} n */
const pad = (n) => String(n).padStart(2, "0");

/**
 * An ISO date as the local "YYYY-MM-DDTHH:MM" a datetime-local input expects.
 * @param {string} iso
 */
export function toLocalInput(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/**
 * Read one input's value for the JSON body. Returns undefined to leave the field out.
 * @param {FormField} field
 * @param {HTMLInputElement | HTMLTextAreaElement} input
 * @param {boolean} partial  true for edit forms without prefill: empty means "unchanged"
 */
export function readField(field, input, partial) {
  if (field.kind === "Bool") return /** @type {HTMLInputElement} */ (input).checked;
  const raw = input.value;
  if (raw === "") {
    if (partial || field.kind === "Password") return undefined;
    return field.nullable ? null : undefined;
  }
  if (field.kind === "Number") return Number(raw);
  if (field.kind === "Date") return new Date(raw).toISOString();
  return raw;
}

/**
 * @param {FormItem} item
 * @param {Record<string, string>} params
 */
function formItem(item, params) {
  const form = el("form", { class: "rizo-form" });
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  const isLogin = item.endpoint === "/auth/login";
  /** @type {Map<string, { field: FormField, input: HTMLInputElement | HTMLTextAreaElement, error: HTMLElement }>} */
  const inputs = new Map();

  for (const field of item.fields) {
    const id = `rizo-field-${field.key}`;
    /** @type {Record<string, string>} */
    const attrs = { id, name: field.key, "aria-describedby": `${id}-error` };
    // A required checkbox would have to be ticked; for Rizo, unticked simply means false.
    if (field.required && item.method === "POST" && field.kind !== "Bool") attrs["required"] = "";
    const text = field.kind === "Text" || field.kind === "Email" || field.kind === "Password";
    if (text && field.min !== undefined) attrs["minlength"] = String(field.min);
    if (text && field.max !== undefined) attrs["maxlength"] = String(field.max);
    if (field.kind === "Number") {
      attrs["step"] = "1";
      if (field.min !== undefined) attrs["min"] = String(field.min);
      if (field.max !== undefined) attrs["max"] = String(field.max);
    }
    if (field.kind === "Password") attrs["autocomplete"] = isLogin ? "current-password" : "new-password";
    if (field.kind === "Email") attrs["autocomplete"] = isLogin ? "username" : "email";
    const input = field.multiline
      ? /** @type {HTMLTextAreaElement} */ (el("textarea", { ...attrs, rows: "6" }))
      : /** @type {HTMLInputElement} */ (el("input", { ...attrs, type: INPUT_TYPES[field.kind] }));
    const error = el("p", { class: "rizo-field-error", id: `${id}-error`, "aria-live": "polite" });
    const label = el("label", { for: id }, field.label, field.required || field.kind === "Bool" ? "" : " (optional)");
    form.append(el("div", { class: field.kind === "Bool" ? "rizo-field rizo-check" : "rizo-field" }, label, input, error));
    inputs.set(field.key, { field, input, error });
  }

  const submit = /** @type {HTMLButtonElement} */ (el("button", { type: "submit", class: "rizo-submit" }, item.submit));
  form.append(status, submit);

  let prefilled = false;
  if (item.prefill !== null) {
    getJson(fillPath(item.prefill, params)).then(
      (record) => {
        const r = /** @type {Record<string, unknown>} */ (record);
        for (const { field, input } of inputs.values()) {
          const value = r[field.key];
          if (value === undefined || value === null) continue;
          if (field.kind === "Bool") /** @type {HTMLInputElement} */ (input).checked = value === true;
          else input.value = field.kind === "Date" ? toLocalInput(String(value)) : String(value);
        }
        prefilled = true;
      },
      (e) => {
        status.textContent = e instanceof Error ? e.message : String(e);
        status.hidden = false;
      },
    );
  }

  form.onsubmit = (event) => {
    event.preventDefault();
    status.hidden = true;
    /** @type {Record<string, unknown>} */
    const body = {};
    const partial = item.method !== "POST" && !prefilled;
    for (const { field, input, error } of inputs.values()) {
      error.textContent = "";
      input.removeAttribute("aria-invalid");
      const value = readField(field, input, partial);
      if (value !== undefined) body[field.key] = value;
    }
    submit.disabled = true;
    sendJson(item.method, fillPath(item.endpoint, params), body).then(
      (result) => {
        const saved = /** @type {Record<string, unknown> | null} */ (result);
        const id = saved !== null && typeof saved["id"] === "string" ? saved["id"] : undefined;
        go(item.then === null ? nextPath() : fillPath(item.then, id === undefined ? params : { ...params, id }));
      },
      (e) => {
        submit.disabled = false;
        const err = /** @type {Error & { field?: string }} */ (e);
        const target = err.field === undefined ? undefined : inputs.get(err.field);
        if (target !== undefined) {
          target.error.textContent = err.message;
          target.input.setAttribute("aria-invalid", "true");
          target.input.focus();
        } else {
          status.textContent = err.message;
          status.hidden = false;
        }
      },
    );
  };
  return form;
}

/**
 * @param {ButtonItem} item
 * @param {Record<string, string>} params
 */
function buttonItem(item, params) {
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-danger" }, item.label));
  button.onclick = () => {
    if (!window.confirm(`${item.label}? This can't be undone.`)) return;
    button.disabled = true;
    sendJson(item.method, fillPath(item.endpoint, params), undefined).then(
      () => go(fillPath(item.then, params)),
      (e) => {
        button.disabled = false;
        status.textContent = e instanceof Error ? e.message : String(e);
        status.hidden = false;
      },
    );
  };
  return el("div", { class: "rizo-actions" }, button, status);
}

/**
 * The menu at the top of every page of an app with accounts.
 * @param {PageData} data
 */
function menu(data) {
  const nav = el("nav", { class: "rizo-nav" }, el("a", { href: "/" }, "Home"));
  if (data.loggedIn) {
    const logout = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-link" }, "Log out"));
    logout.onclick = () => {
      logout.disabled = true;
      sendJson("POST", "/auth/logout", undefined).finally(() => go("/"));
    };
    nav.append(logout);
  } else {
    const here = window.location.pathname;
    const next = isInternalPath(here) && here !== "/login" && here !== "/signup" ? `?next=${encodeURIComponent(here)}` : "";
    nav.append(el("a", { href: `/login${next}` }, "Log in"), el("a", { href: "/signup" }, "Sign up"));
  }
  return nav;
}

/** @param {PageData} data */
export function renderPage(data) {
  const main = el("main", { class: "rizo-page" });
  if (data.auth) main.append(menu(data));
  main.append(el("h1", {}, data.title));
  for (const item of data.items) {
    if (item.kind === "text") main.append(el("p", {}, item.text));
    else if (item.kind === "link") main.append(el("p", {}, el("a", { href: fillPath(item.path, data.params) }, item.label)));
    else if (item.kind === "form") main.append(formItem(item, data.params));
    else if (item.kind === "button") main.append(buttonItem(item, data.params));
    else main.append(showItem(item, data.params));
  }
  return main;
}

/** Read the page's data block and render it. */
export function start() {
  const block = document.getElementById("rizo-page");
  const app = document.getElementById("app");
  if (block === null || app === null) return;
  const data = /** @type {PageData} */ (JSON.parse(block.textContent ?? "{}"));
  app.replaceWith(renderPage(data));
}

if (typeof document !== "undefined" && document.getElementById("rizo-page") !== null) start();
