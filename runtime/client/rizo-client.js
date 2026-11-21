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
 * @typedef {{ kind: "text", text: string }
 *   | { kind: "link", label: string, path: string }
 *   | { kind: "show", endpoint: string, mode: "list" | "one", model: string, fields: FieldView[], detail: { path: string, param: string } | null }} PageItem
 * @typedef {{ title: string, items: PageItem[], params: Record<string, string>, loggedIn: boolean }} PageData
 */

const ALLOWED_ATTRIBUTES = new Set(["class", "href", "type", "role", "aria-live", "aria-busy"]);

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

/** @param {PageData} data */
export function renderPage(data) {
  const main = el("main", { class: "rizo-page" }, el("h1", {}, data.title));
  for (const item of data.items) {
    if (item.kind === "text") main.append(el("p", {}, item.text));
    else if (item.kind === "link") main.append(el("p", {}, el("a", { href: fillPath(item.path, data.params) }, item.label)));
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
