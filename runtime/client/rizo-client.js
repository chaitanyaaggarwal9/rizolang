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
 * @typedef {{ kind: "form", method: "POST" | "PUT" | "PATCH", endpoint: string, fields: FormField[], submit: string, prefill: string | null, then: string | null, done?: string }} FormItem
 * @typedef {{ kind: "button", label: string, method: "DELETE", endpoint: string, then: string }} ButtonItem
 * @typedef {{ kind: "text", text: string }
 *   | { kind: "link", label: string, path: string }
 *   | { kind: "show", endpoint: string, mode: "list" | "one", model: string, fields: FieldView[], detail: { path: string, param: string } | null }
 *   | FormItem
 *   | ButtonItem
 *   | { kind: "passkeyLogin" }
 *   | { kind: "passkeys" }
 *   | { kind: "sessions" }
 *   | { kind: "tokens" }
 *   | { kind: "yourData" }
 *   | { kind: "privacy" }
 *   | { kind: "verifyEmail" }
 *   | { kind: "newPassword", field: FormField }} PageItem
 * @typedef {{ title: string, items: PageItem[], params: Record<string, string>, loggedIn: boolean, auth: boolean, privacy?: boolean }} PageData
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
 * Go to a page on this site. Only the path changes: setting
 * location.pathname can never switch to another site or run a
 * "javascript:" URL, and anything that isn't a plain internal path
 * goes home instead. So a crafted "?next=" can't send people elsewhere.
 * @param {string} path
 */
export function go(path) {
  window.location.pathname = isInternalPath(path) ? path : "/";
}

/** The "?next=" the page was opened with, read once by start(). */
let openedWithNext = /** @type {string | null} */ (null);
/** The one-time token from an emailed link ("#token=..."), taken out of the address bar in start(). */
let openedWithToken = /** @type {string | null} */ (null);

/** The "?next=" page to return to after logging in, if it is on this site. */
export function nextPath() {
  const next = openedWithNext ?? new URLSearchParams(window.location.search).get("next");
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
 * @param {Record<string, string>} [extra] values sent with the form that are not inputs
 */
function formItem(item, params, extra = {}) {
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
    const body = { ...extra };
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
        if (item.done !== undefined) {
          form.replaceWith(el("p", { class: "rizo-done", role: "status" }, item.done));
          return;
        }
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

// -------------------------------------------------------------- passkeys

/** @param {ArrayBuffer | ArrayBufferView} data */
export function toBase64url(data) {
  const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  let text = "";
  for (const b of bytes) text += String.fromCharCode(b);
  return btoa(text).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** @param {string} text */
export function fromBase64url(text) {
  const plain = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(plain.length);
  for (let i = 0; i < plain.length; i++) bytes[i] = plain.charCodeAt(i);
  return bytes;
}

function passkeysSupported() {
  return typeof window.PublicKeyCredential === "function" && typeof navigator !== "undefined" && "credentials" in navigator;
}

/** @param {unknown} e */
function passkeyMessage(e) {
  if (e instanceof Error && (e.name === "NotAllowedError" || e.name === "AbortError")) return "The passkey request was cancelled or timed out.";
  if (e instanceof Error && e.name === "InvalidStateError") return "This device already has a passkey for your account.";
  return e instanceof Error ? e.message : String(e);
}

/** "Log in with a passkey", for the login page. */
function passkeyLoginItem() {
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  if (!passkeysSupported()) return el("p", { class: "rizo-empty" }, "This browser doesn't support passkeys.");
  const button = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-secondary" }, "Log in with a passkey"));
  button.onclick = async () => {
    button.disabled = true;
    status.hidden = true;
    try {
      const options = /** @type {{ challenge: string, rpId: string, timeout: number }} */ (await sendJson("POST", "/auth/passkeys/login-options", {}));
      const credential = /** @type {PublicKeyCredential | null} */ (await navigator.credentials.get({
        publicKey: { challenge: fromBase64url(options.challenge), rpId: options.rpId, timeout: options.timeout, userVerification: "required" },
      }));
      if (credential === null) throw new Error("No passkey was chosen.");
      const r = /** @type {AuthenticatorAssertionResponse} */ (credential.response);
      await sendJson("POST", "/auth/passkeys/login", {
        id: credential.id,
        response: {
          clientDataJSON: toBase64url(r.clientDataJSON),
          authenticatorData: toBase64url(r.authenticatorData),
          signature: toBase64url(r.signature),
          userHandle: r.userHandle === null ? null : toBase64url(r.userHandle),
        },
      });
      go(nextPath());
    } catch (e) {
      button.disabled = false;
      status.textContent = passkeyMessage(e);
      status.hidden = false;
    }
  };
  return el("div", { class: "rizo-actions" }, button, status);
}

/**
 * Confirm the email address, when the page was opened from the emailed link.
 * @param {string} token
 */
function verifyEmailItem(token) {
  const status = el("p", { role: "status" }, "Confirming your email…");
  const box = el("div", { class: "rizo-actions", "aria-live": "polite" }, status);
  sendJson("POST", "/auth/verify-email", { token }).then(
    () => {
      status.textContent = "Your email is confirmed. You can log in now.";
      box.append(el("p", {}, el("a", { href: "/login" }, "Log in")));
    },
    (e) => {
      status.setAttribute("class", "rizo-error");
      status.textContent = e instanceof Error ? e.message : String(e);
      box.append(el("p", {}, el("a", { href: "/verify-email" }, "Get a new link")));
    },
  );
  return box;
}

/**
 * Choose a new password, when the page was opened from the emailed link.
 * @param {FormField} field
 * @param {string} token
 */
function newPasswordItem(field, token) {
  const form = formItem({
    kind: "form", method: "POST", endpoint: "/auth/password-reset/confirm", fields: [field], submit: "Save new password",
    prefill: null, then: null, done: "Your password is changed, and you are logged out everywhere. You can log in now.",
  }, {}, { token });
  return el("div", {}, form, el("p", {}, el("a", { href: "/login" }, "Log in")), el("p", {}, el("a", { href: "/reset-password" }, "Get a new link")));
}

/** List, add and remove your passkeys, for the account page. */
function passkeysItem() {
  const box = el("section", { class: "rizo-show", "aria-live": "polite" }, el("h2", {}, "Passkeys"),
    el("p", {}, "Log in with your fingerprint, face or device PIN instead of a password. Nothing secret is stored on this site."));
  const list = el("ul", { class: "rizo-list" });
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  const fail = (/** @type {unknown} */ e) => {
    status.textContent = passkeyMessage(e);
    status.hidden = false;
  };

  const load = () => getJson("/auth/passkeys").then((data) => {
    const { items } = /** @type {{ items: { id: string, name: string, createdAt: string, lastUsedAt: string | null }[] }} */ (data);
    if (items.length === 0) {
      list.replaceChildren(el("li", { class: "rizo-empty" }, "You have no passkeys yet."));
      return;
    }
    list.replaceChildren(...items.map((p) => {
      const remove = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-link" }, "Remove"));
      remove.onclick = () => {
        if (!window.confirm(`Remove the passkey "${p.name}"?`)) return;
        sendJson("DELETE", `/auth/passkeys/${encodeURIComponent(p.id)}`, undefined).then(load, fail);
      };
      const used = p.lastUsedAt === null ? "never used" : `last used ${formatValue(p.lastUsedAt, "Date")}`;
      return el("li", { class: "rizo-card" }, el("strong", {}, p.name), el("p", {}, `Added ${formatValue(p.createdAt, "Date")}, ${used}.`), remove);
    }));
  }, fail);

  if (!passkeysSupported()) {
    box.append(list, el("p", { class: "rizo-empty" }, "This browser doesn't support adding passkeys."));
    load();
    return box;
  }
  const nameInput = /** @type {HTMLInputElement} */ (el("input", { id: "rizo-passkey-name", type: "text", maxlength: "60" }));
  nameInput.value = "My device";
  const add = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-submit" }, "Add a passkey"));
  add.onclick = async () => {
    add.disabled = true;
    status.hidden = true;
    try {
      const o = /** @type {{ challenge: string, rp: { id: string, name: string }, user: { id: string, name: string, displayName: string },
        pubKeyCredParams: { type: "public-key", alg: number }[], timeout: number, excludeCredentials: { type: "public-key", id: string }[],
        authenticatorSelection: AuthenticatorSelectionCriteria }} */ (await sendJson("POST", "/auth/passkeys/register-options", {}));
      const credential = /** @type {PublicKeyCredential | null} */ (await navigator.credentials.create({
        publicKey: {
          challenge: fromBase64url(o.challenge),
          rp: o.rp,
          user: { ...o.user, id: fromBase64url(o.user.id) },
          pubKeyCredParams: o.pubKeyCredParams,
          timeout: o.timeout,
          attestation: "none",
          authenticatorSelection: o.authenticatorSelection,
          excludeCredentials: o.excludeCredentials.map((c) => ({ type: c.type, id: fromBase64url(c.id) })),
        },
      }));
      if (credential === null) throw new Error("No passkey was created.");
      const r = /** @type {AuthenticatorAttestationResponse} */ (credential.response);
      await sendJson("POST", "/auth/passkeys", {
        name: nameInput.value.trim() || "Passkey",
        response: { clientDataJSON: toBase64url(r.clientDataJSON), attestationObject: toBase64url(r.attestationObject) },
      });
      await load();
    } catch (e) {
      fail(e);
    } finally {
      add.disabled = false;
    }
  };
  box.append(list,
    el("div", { class: "rizo-field" }, el("label", { for: "rizo-passkey-name" }, "Name for a new passkey"), nameInput),
    el("div", { class: "rizo-actions" }, add), status);
  load();
  return box;
}

/** API tokens for scripts and AI agents, for the account page. */
function tokensItem() {
  const box = el("section", { class: "rizo-show", "aria-live": "polite" }, el("h2", {}, "API tokens"),
    el("p", {}, "Let a script or AI agent use this site as you, on the endpoints you choose, until the token expires. It can never change your account."));
  const list = el("ul", { class: "rizo-list" });
  const form = el("div", {});
  const created = el("div", {});
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  const fail = (/** @type {unknown} */ e) => {
    status.textContent = e instanceof Error ? e.message : String(e);
    status.hidden = false;
  };
  /** @type {string[]} */
  let shownEndpoints = [];

  const load = () => getJson("/auth/tokens").then((data) => {
    const { items, endpoints } = /** @type {{ items: { id: string, name: string, endpoints: string[], expiresAt: string, lastUsedAt: string | null }[], endpoints: string[] }} */ (data);
    list.replaceChildren(...(items.length === 0 ? [el("li", { class: "rizo-empty" }, "You have no API tokens.")] : items.map((t) => {
      const revoke = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-link" }, "Revoke"));
      revoke.onclick = () => {
        if (!window.confirm(`Revoke the token "${t.name}"? Anything using it stops working.`)) return;
        sendJson("DELETE", `/auth/tokens/${encodeURIComponent(t.id)}`, undefined).then(load, fail);
      };
      const used = t.lastUsedAt === null ? "never used" : `last used ${formatValue(t.lastUsedAt, "Date")}`;
      return el("li", { class: "rizo-card" }, el("strong", {}, t.name), el("p", {}, t.endpoints.join(", ")),
        el("p", {}, `Expires ${formatValue(t.expiresAt, "Date")}, ${used}.`), revoke);
    })));
    if (endpoints.join("\n") !== shownEndpoints.join("\n")) {
      shownEndpoints = endpoints;
      form.replaceChildren(...newTokenForm(endpoints));
    }
  }, fail);

  /** @param {string[]} endpoints */
  function newTokenForm(endpoints) {
    if (endpoints.length === 0) return [el("p", { class: "rizo-empty" }, "This site has no endpoints that need a login, so tokens aren't needed.")];
    const name = /** @type {HTMLInputElement} */ (el("input", { id: "rizo-token-name", type: "text", maxlength: "60" }));
    name.value = "My agent";
    const days = /** @type {HTMLInputElement} */ (el("input", { id: "rizo-token-days", type: "number", min: "1", max: "90", step: "1" }));
    days.value = "90";
    const boxes = endpoints.map((endpoint, i) => {
      const input = /** @type {HTMLInputElement} */ (el("input", { id: `rizo-token-endpoint-${i}`, type: "checkbox" }));
      return { endpoint, input, row: el("div", { class: "rizo-field rizo-check" }, input, el("label", { for: `rizo-token-endpoint-${i}` }, endpoint)) };
    });
    const create = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-submit" }, "Create token"));
    create.onclick = () => {
      status.hidden = true;
      const chosen = boxes.filter((b) => b.input.checked).map((b) => b.endpoint);
      if (chosen.length === 0) {
        fail(new Error("Choose at least one endpoint."));
        return;
      }
      create.disabled = true;
      sendJson("POST", "/auth/tokens", { name: name.value.trim(), endpoints: chosen, days: Number(days.value) }).then((result) => {
        create.disabled = false;
        const { token } = /** @type {{ token: string }} */ (result);
        const shown = /** @type {HTMLInputElement} */ (el("input", { id: "rizo-token-value", type: "text" }));
        shown.value = token;
        shown.readOnly = true;
        created.replaceChildren(el("div", { class: "rizo-done", role: "status" },
          el("p", {}, "Copy this token now. It won't be shown again."), shown,
          el("p", {}, "Send it as: Authorization: Bearer <token>")));
        for (const b of boxes) b.input.checked = false;
        load();
      }, (e) => {
        create.disabled = false;
        fail(e);
      });
    };
    return [
      el("h2", {}, "New token"),
      el("div", { class: "rizo-field" }, el("label", { for: "rizo-token-name" }, "Name"), name),
      el("p", {}, "Endpoints it may call:"), ...boxes.map((b) => b.row),
      el("div", { class: "rizo-field" }, el("label", { for: "rizo-token-days" }, "Expires after (days, at most 90)"), days),
      el("div", { class: "rizo-actions" }, create),
    ];
  }

  box.append(list, created, form, status);
  load();
  return box;
}

/**
 * The privacy notice: what this site stores, why and for how long, and people's rights.
 * Everything comes from GET /auth/privacy and is inserted as text.
 */
function privacyItem() {
  const box = el("div", { class: "rizo-privacy", "aria-live": "polite" }, el("p", { class: "rizo-empty" }, "Loading…"));
  const list = (/** @type {string[]} */ lines) => el("ul", {}, ...lines.map((line) => el("li", {}, line)));
  const STORED = { public: "shown publicly", private: "private: never shown to others", encrypted: "private and encrypted", hashed: "stored only as a hash" };
  getJson("/auth/privacy").then((raw) => {
    const n = /** @type {{ regions: { code: string, region: string, law: string, complaint: string }[], contact: string,
      data: { name: string, account: boolean, fields: { label: string, kind: string, stored: "public" | "private" | "encrypted" | "hashed" }[], kept: string }[],
      rights: string[], cookies: string, sharing: string[], security: string[], securityLog: string }} */ (raw);
    box.replaceChildren(
      el("h2", {}, "What we store"),
      ...n.data.map((m) => el("section", { class: "rizo-show" },
        el("h3", {}, m.account ? `${m.name} (your account)` : m.name),
        list(m.fields.map((f) => `${f.label}: ${STORED[f.stored]}`)),
        el("p", {}, `Kept: ${m.kept}`))),
      el("h2", {}, "Cookies"), el("p", {}, n.cookies),
      el("h2", {}, "Who else handles your data"), list(n.sharing),
      el("h2", {}, "How we protect it"), list([...n.security, n.securityLog]),
      el("h2", {}, "Your rights"), list(n.rights),
      el("h2", {}, "Where these rules apply"), list(n.regions.map((r) => `${r.region}: ${r.law}. ${r.complaint}`)),
      el("h2", {}, "Contact"), el("p", {}, `Write to ${n.contact} about your data, to use your rights, or to make a complaint.`),
    );
  }, (e) => box.replaceChildren(errorBox(e instanceof Error ? e.message : String(e))));
  return box;
}

/** Download everything stored about you, or delete your account, for the account page. */
function yourDataItem() {
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  const download = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-secondary" }, "Download my data"));
  // The server sends the file as a download, so the page stays open.
  download.onclick = () => go("/auth/me/export");

  const password = /** @type {HTMLInputElement} */ (el("input", { id: "rizo-delete-password", type: "password", autocomplete: "current-password", maxlength: "128" }));
  const remove = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-danger" }, "Delete my account"));
  remove.onclick = () => {
    status.hidden = true;
    if (password.value === "") {
      status.textContent = "Enter your password to delete your account.";
      status.hidden = false;
      return;
    }
    if (!window.confirm("Delete your account? This can't be undone. Your posts and other records stay, credited to \"Deleted user\".")) return;
    remove.disabled = true;
    sendJson("DELETE", "/auth/me", { password: password.value }).then(() => go("/"), (e) => {
      remove.disabled = false;
      status.textContent = e instanceof Error ? e.message : String(e);
      status.hidden = false;
    });
  };
  return el("section", { class: "rizo-show" }, el("h2", {}, "Your data"),
    el("p", {}, "Download a copy of everything this site stores about you."),
    el("div", { class: "rizo-actions" }, download),
    el("h2", {}, "Delete your account"),
    el("p", {}, "Your account, devices, passkeys and API tokens are deleted. Records others may rely on, such as posts, stay and are shown as \"Deleted user\"."),
    el("div", { class: "rizo-field" }, el("label", { for: "rizo-delete-password" }, "Password"), password),
    el("div", { class: "rizo-actions" }, remove), status);
}

/** The devices this account is logged in on, for the account page. */
function sessionsItem() {
  const box = el("section", { class: "rizo-show", "aria-live": "polite" }, el("h2", {}, "Devices"),
    el("p", {}, "Where you are logged in. Log out any device you don't recognise, then change your password."));
  const list = el("ul", { class: "rizo-list" });
  const status = el("p", { class: "rizo-error", role: "alert" });
  status.hidden = true;
  const fail = (/** @type {unknown} */ e) => {
    status.textContent = e instanceof Error ? e.message : String(e);
    status.hidden = false;
  };

  const load = () => getJson("/auth/sessions").then((data) => {
    const { items } = /** @type {{ items: { id: string, device: string, createdAt: string, lastSeenAt: string, current: boolean }[] }} */ (data);
    list.replaceChildren(...items.map((s) => {
      const out = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-link" }, "Log out"));
      out.onclick = () => {
        out.disabled = true;
        sendJson("DELETE", `/auth/sessions/${encodeURIComponent(s.id)}`, undefined).then(() => (s.current ? go("/") : load()), (e) => {
          out.disabled = false;
          fail(e);
        });
      };
      const title = el("strong", {}, s.device, s.current ? " (this device)" : "");
      return el("li", { class: "rizo-card" }, title,
        el("p", {}, `Logged in ${formatValue(s.createdAt, "Date")}, last active ${formatValue(s.lastSeenAt, "Date")}.`), out);
    }));
  }, fail);

  const all = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-secondary" }, "Log out everywhere"));
  all.onclick = () => {
    if (!window.confirm("Log out on every device, including this one?")) return;
    all.disabled = true;
    sendJson("POST", "/auth/logout-all", undefined).then(() => go("/"), (e) => {
      all.disabled = false;
      fail(e);
    });
  };
  box.append(list, el("div", { class: "rizo-actions" }, all), status);
  load();
  return box;
}

/**
 * The menu at the top of every page of an app with accounts.
 * @param {PageData} data
 */
function menu(data) {
  const nav = el("nav", { class: "rizo-nav" }, el("a", { href: "/" }, "Home"));
  if (data.privacy) nav.append(el("a", { href: "/privacy" }, "Privacy"));
  if (data.loggedIn) {
    nav.append(el("a", { href: "/account" }, "Account"));
    const logout = /** @type {HTMLButtonElement} */ (el("button", { type: "button", class: "rizo-link" }, "Log out"));
    logout.onclick = () => {
      logout.disabled = true;
      sendJson("POST", "/auth/logout", undefined).finally(() => go("/"));
    };
    nav.append(logout);
  } else {
    const here = window.location.pathname;
    const next = isInternalPath(here) && !["/login", "/signup", "/verify-email", "/reset-password"].includes(here) ? `?next=${encodeURIComponent(here)}` : "";
    nav.append(el("a", { href: `/login${next}` }, "Log in"), el("a", { href: "/signup" }, "Sign up"));
  }
  return nav;
}

/** @param {PageData} data */
export function renderPage(data) {
  const main = el("main", { class: "rizo-page" });
  if (data.auth) main.append(menu(data));
  main.append(el("h1", {}, data.title));
  // Opened from an emailed link: show only what the link is for.
  const linkItem = data.items.find((item) => item.kind === "verifyEmail" || item.kind === "newPassword");
  const token = openedWithToken;
  for (const item of linkItem !== undefined && token !== null ? [linkItem] : data.items) {
    if (item.kind === "text") main.append(el("p", {}, item.text));
    else if (item.kind === "link") main.append(el("p", {}, el("a", { href: fillPath(item.path, data.params) }, item.label)));
    else if (item.kind === "form") main.append(formItem(item, data.params));
    else if (item.kind === "button") main.append(buttonItem(item, data.params));
    else if (item.kind === "passkeyLogin") main.append(passkeyLoginItem());
    else if (item.kind === "passkeys") main.append(passkeysItem());
    else if (item.kind === "sessions") main.append(sessionsItem());
    else if (item.kind === "tokens") main.append(tokensItem());
    else if (item.kind === "yourData") main.append(yourDataItem());
    else if (item.kind === "privacy") main.append(privacyItem());
    else if (item.kind === "verifyEmail") {
      if (token !== null) main.append(verifyEmailItem(token));
    } else if (item.kind === "newPassword") {
      if (token !== null) main.append(newPasswordItem(item.field, token));
    }
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
  // Keep "?next=" in memory and take it out of the address bar, so later
  // navigation (which only changes the path) lands on a clean address.
  const next = new URLSearchParams(window.location.search).get("next");
  openedWithNext = next;
  takeToken();
  if (next !== null) window.history.replaceState(null, "", window.location.pathname);
  let shown = renderPage(data);
  app.replaceWith(shown);
  // An emailed link opened in a tab that already shows this page only changes "#...", which doesn't reload it.
  if (typeof window.addEventListener === "function") {
    window.addEventListener("hashchange", () => {
      if (!takeToken()) return;
      const page = renderPage(data);
      shown.replaceWith(page);
      shown = page;
    });
  }
}

/**
 * Keep the token of an emailed link ("#token=...") in memory and take it out
 * of the address bar, so it isn't left in the history. Returns true if there was one.
 */
function takeToken() {
  if (window.location.hash === "") {
    openedWithToken = null;
    return false;
  }
  const token = new URLSearchParams(window.location.hash.slice(1)).get("token");
  openedWithToken = token !== null && /^[A-Za-z0-9_-]{43}$/.test(token) ? token : null;
  window.history.replaceState(null, "", window.location.pathname);
  return openedWithToken !== null;
}

if (typeof document !== "undefined" && document.getElementById("rizo-page") !== null) start();
