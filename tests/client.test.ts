/**
 * The browser runtime (runtime/client/rizo-client.js), tested against a small
 * fake DOM. The fake DOM throws if anything ever sets innerHTML/outerHTML, so
 * a test passing proves the runtime only creates elements and text nodes.
 */
import { readFileSync } from "node:fs";
import { afterEach, beforeAll, describe, expect, it } from "vitest";

class FakeText {
  readonly nodeType = 3;
  readonly data: string;
  constructor(data: string) {
    this.data = data;
  }
  get textContent(): string {
    return this.data;
  }
}

class FakeElement {
  readonly nodeType = 1;
  readonly attributes = new Map<string, string>();
  children: (FakeElement | FakeText)[] = [];
  parent: FakeElement | undefined;
  hidden = false;
  disabled = false;
  checked = false;
  value = "";
  onclick: (() => void) | null = null;
  onsubmit: ((e: { preventDefault(): void }) => void) | null = null;
  readonly tagName: string;
  constructor(tagName: string) {
    this.tagName = tagName;
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }
  removeAttribute(name: string): void {
    this.attributes.delete(name);
  }
  focus(): void {
    focused = this;
  }
  append(...nodes: (FakeElement | FakeText)[]): void {
    for (const n of nodes) {
      if (n instanceof FakeElement) n.parent = this;
      this.children.push(n);
    }
  }
  replaceChildren(...nodes: (FakeElement | FakeText)[]): void {
    this.children = [];
    this.append(...nodes);
  }
  replaceWith(node: FakeElement): void {
    replaced = node;
  }
  get textContent(): string {
    return this.children.map((c) => c.textContent).join("");
  }
  set textContent(text: string) {
    this.children = [new FakeText(text)];
  }
  set innerHTML(_: string) {
    throw new Error("innerHTML must never be used");
  }
  set outerHTML(_: string) {
    throw new Error("outerHTML must never be used");
  }
}

let replaced: FakeElement | undefined;
let focused: FakeElement | undefined;
const navigation: string[] = [];
let confirmAnswer = true;
const fakeLocation = {
  search: "",
  hash: "",
  current: "/",
  get pathname(): string {
    return this.current;
  },
  /** Setting pathname navigates, like in a browser. */
  set pathname(path: string) {
    navigation.push(path);
  },
};
const cleaned: string[] = [];
const fakeWindow = {
  location: fakeLocation,
  confirm: () => confirmAnswer,
  history: { replaceState: (_s: unknown, _t: string, url: string) => cleaned.push(url) },
};
const byId = new Map<string, unknown>();

function all(node: FakeElement): FakeElement[] {
  return [node, ...node.children.flatMap((c) => (c instanceof FakeElement ? all(c) : []))];
}
function texts(node: FakeElement): string[] {
  return node.children.flatMap((c) => (c instanceof FakeElement ? texts(c) : [c.data]));
}

type Client = typeof import("../runtime/client/rizo-client.js");
let client: Client;

beforeAll(async () => {
  (globalThis as { document?: unknown }).document = {
    createElement: (tag: string) => new FakeElement(tag),
    createTextNode: (text: string) => new FakeText(text),
    getElementById: (id: string) => byId.get(id) ?? null,
  };
  (globalThis as { window?: unknown }).window = fakeWindow;
  client = await import("../runtime/client/rizo-client.js");
});

afterEach(() => {
  byId.clear();
  replaced = undefined;
  focused = undefined;
  navigation.length = 0;
  confirmAnswer = true;
  fakeLocation.search = "";
  fakeLocation.hash = "";
  fakeLocation.current = "/";
  cleaned.length = 0;
});

const flush = () => new Promise((r) => setTimeout(r, 0));
const HOSTILE = `<img src=x onerror=alert(1)></script><script>alert(2)</script>`;

function stubFetch(body: unknown, status = 200): string[] {
  const urls: string[] = [];
  (globalThis as { fetch?: unknown }).fetch = async (url: string) => {
    urls.push(url);
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return urls;
}

interface Sent { url: string; method: string; body: unknown; headers: Record<string, string> }
function stubSend(body: unknown, status = 200): Sent[] {
  const sent: Sent[] = [];
  (globalThis as { fetch?: unknown }).fetch = async (url: string, init?: { method?: string; body?: string; headers?: Record<string, string> }) => {
    sent.push({ url, method: init?.method ?? "GET", body: init?.body === undefined ? undefined : JSON.parse(init.body), headers: init?.headers ?? {} });
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  return sent;
}

describe("el()", () => {
  it("inserts strings as text, never as markup", () => {
    const node = client.el("p", {}, HOSTILE) as unknown as FakeElement;
    expect(node.children).toHaveLength(1);
    expect(node.children[0]).toBeInstanceOf(FakeText);
    expect(node.textContent).toBe(HOSTILE);
  });

  it.each(["onclick", "onerror", "style", "src", "srcdoc", "formaction"])("refuses the %s attribute", (name) => {
    expect(() => client.el("a", { [name]: "x" })).toThrow(/not allowed/);
  });

  it.each(["https://evil.example", "//evil.example", "javascript:alert(1)", "data:text/html,x", "/\\evil.example", "/a\nb"])(
    "refuses to link to %j",
    (href) => {
      expect(() => client.el("a", { href })).toThrow(/stay on this site/);
    },
  );

  it("allows links to pages on this site", () => {
    expect((client.el("a", { href: "/posts/1" }) as unknown as FakeElement).attributes.get("href")).toBe("/posts/1");
  });
});

describe("helpers", () => {
  it("URL-encodes parameter values, so they can't change the path", () => {
    expect(client.fillPath("/posts/:id", { id: "../admin?x=1#y" })).toBe("/posts/..%2Fadmin%3Fx%3D1%23y");
    expect(() => client.fillPath("/posts/:id", {})).toThrow(/missing value/);
  });

  it("formats values as text", () => {
    expect(client.formatValue(null, "Text")).toBe("—");
    expect(client.formatValue(true, "Bool")).toBe("Yes");
    expect(client.formatValue(false, "Bool")).toBe("No");
    expect(client.formatValue(5, "Number")).toBe("5");
    expect(client.formatValue(HOSTILE, "Text")).toBe(HOSTILE);
  });
});

describe("rendering a page", () => {
  const fields = [
    { key: "id", label: "ID", type: "ID" },
    { key: "title", label: "Title", type: "Text" },
    { key: "published", label: "Published", type: "Bool" },
  ] as const;

  it("renders hostile titles, text and records as plain text only", async () => {
    stubFetch({ items: [{ id: "a1", title: HOSTILE, published: true }], next: null });
    const page = client.renderPage({
      title: HOSTILE,
      params: {},
      loggedIn: false,
      auth: false,
      items: [
        { kind: "text", text: HOSTILE },
        { kind: "show", endpoint: "/api/posts", mode: "list", model: "Post", fields: [...fields], detail: { path: "/posts/:id", param: "id" } },
      ],
    }) as unknown as FakeElement;
    await flush();
    const elements = all(page);
    expect(elements.map((e) => e.tagName)).not.toContain("script");
    expect(elements.map((e) => e.tagName)).not.toContain("img");
    for (const e of elements) {
      for (const name of e.attributes.keys()) expect(["class", "href", "type", "role", "aria-live", "aria-busy"]).toContain(name);
    }
    expect(texts(page).filter((t) => t === HOSTILE)).toHaveLength(3);
  });

  it("links each list item to its own page, with the id encoded", async () => {
    stubFetch({ items: [{ id: "a/b", title: "One", published: false }], next: null });
    const page = client.renderPage({
      title: "Posts", params: {}, loggedIn: false, auth: false,
      items: [{ kind: "show", endpoint: "/api/posts", mode: "list", model: "Post", fields: [...fields], detail: { path: "/posts/:id", param: "id" } }],
    }) as unknown as FakeElement;
    await flush();
    const links = all(page).filter((e) => e.tagName === "a");
    expect(links.map((a) => a.attributes.get("href"))).toEqual(["/posts/a%2Fb"]);
  });

  it("loads the next page with the cursor from the previous one", async () => {
    const urls = stubFetch({ items: [{ id: "1", title: "One", published: true }], next: "abc+/=" });
    const page = client.renderPage({
      title: "Posts", params: {}, loggedIn: false, auth: false,
      items: [{ kind: "show", endpoint: "/api/posts", mode: "list", model: "Post", fields: [...fields], detail: null }],
    }) as unknown as FakeElement;
    await flush();
    const more = all(page).find((e) => e.tagName === "button");
    expect(more?.hidden).toBe(false);
    more?.onclick?.();
    await flush();
    expect(urls).toEqual(["/api/posts", "/api/posts?after=abc%2B%2F%3D"]);
  });

  it("fills the page's parameters into the endpoint and shows one record", async () => {
    const urls = stubFetch({ id: "42", title: "Answer", published: false });
    const page = client.renderPage({
      title: "Post", params: { id: "42" }, loggedIn: false, auth: false,
      items: [{ kind: "show", endpoint: "/api/posts/:id", mode: "one", model: "Post", fields: [...fields], detail: null }],
    }) as unknown as FakeElement;
    await flush();
    expect(urls).toEqual(["/api/posts/42"]);
    expect(texts(page)).toEqual(expect.arrayContaining(["Title", "Answer", "Published", "No"]));
  });

  it("shows readable errors, never the server's raw response", async () => {
    stubFetch({ error: { message: HOSTILE } }, 500);
    const page = client.renderPage({
      title: "Post", params: { id: "1" }, loggedIn: false, auth: false,
      items: [{ kind: "show", endpoint: "/api/posts/:id", mode: "one", model: "Post", fields: [...fields], detail: null }],
    }) as unknown as FakeElement;
    await flush();
    const alert = all(page).find((e) => e.attributes.get("role") === "alert");
    expect(alert?.textContent).toBe(HOSTILE);
    expect(alert?.children[0]).toBeInstanceOf(FakeText);
  });

  it("remembers ?next= and removes it from the address bar", () => {
    fakeLocation.search = "?next=%2Fposts%2F7";
    fakeLocation.current = "/login";
    byId.set("rizo-page", { textContent: JSON.stringify({ title: "Log in", items: [], params: {}, loggedIn: false, auth: true }) });
    byId.set("app", new FakeElement("main"));
    client.start();
    expect(cleaned).toEqual(["/login"]);
    fakeLocation.search = "";
    expect(client.nextPath()).toBe("/posts/7");
    client.start(); // opened without ?next=: nothing is remembered
    expect(client.nextPath()).toBe("/");
    expect(cleaned).toEqual(["/login"]);
  });

  it("starts from the page's JSON data block", () => {
    byId.set("rizo-page", { textContent: JSON.stringify({ title: "Hi", items: [], params: {}, loggedIn: false }) });
    byId.set("app", new FakeElement("main"));
    client.start();
    expect(replaced?.tagName).toBe("main");
    expect(replaced?.textContent).toBe("Hi");
  });
});

describe("runtime source", () => {
  const source = readFileSync(new URL("../runtime/client/rizo-client.js", import.meta.url), "utf8")
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("//") && !line.trimStart().startsWith("*"))
    .join("\n");

  it.each(["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"on", "srcdoc", "location.assign", "location.href", "location.replace"])(
    "never uses %s",
    (api) => {
      expect(source).not.toContain(api);
    },
  );
});

describe("navigation", () => {
  it.each([
    ["/posts/1", "/posts/1"],
    ["//evil.example", "/"],
    ["https://evil.example", "/"],
    ["javascript:alert(1)", "/"],
    ["/\\evil.example", "/"],
  ])("go(%j) opens %j", (target, expected) => {
    client.go(target);
    expect(navigation).toEqual([expected]);
  });

  it.each([
    ["?next=%2Fposts%2F1", "/posts/1"],
    ["?next=%2F%2Fevil.example", "/"],
    ["?next=https%3A%2F%2Fevil.example", "/"],
    ["?next=javascript%3Aalert(1)", "/"],
    ["", "/"],
  ])("follows ?next= only to this site (%j)", (search, expected) => {
    fakeLocation.search = search;
    expect(client.nextPath()).toBe(expected);
  });
});

describe("forms", () => {
  const field = (key: string, kind: string, extra: Record<string, unknown> = {}) =>
    ({ key, kind, label: key, required: false, nullable: true, multiline: false, ...extra }) as never;
  const input = (props: Partial<FakeElement>) => Object.assign(new FakeElement("input"), props) as never;

  it("reads values as the API expects them", () => {
    expect(client.readField(field("n", "Number"), input({ value: "42" }), false)).toBe(42);
    expect(client.readField(field("t", "Text"), input({ value: "" }), false)).toBeNull();
    expect(client.readField(field("t", "Text", { nullable: false }), input({ value: "" }), false)).toBeUndefined();
    expect(client.readField(field("t", "Text"), input({ value: "" }), true)).toBeUndefined();
    expect(client.readField(field("p", "Password"), input({ value: "" }), false)).toBeUndefined();
    expect(client.readField(field("b", "Bool"), input({ checked: true }), false)).toBe(true);
    expect(client.readField(field("d", "Date"), input({ value: "2026-01-31T12:00" }), false)).toBe(new Date("2026-01-31T12:00").toISOString());
  });

  const formPage = (extra: Record<string, unknown> = {}) => client.renderPage({
    title: "New", params: {}, loggedIn: true, auth: false,
    items: [{
      kind: "form", method: "POST", endpoint: "/api/posts", submit: "Save", prefill: null, then: "/posts/:id",
      fields: [{ key: "title", kind: "Text", label: "Title", required: true, nullable: false, max: 200, multiline: false }],
      ...extra,
    } as never],
  }) as unknown as FakeElement;

  it("labels every input and passes limits to the browser", () => {
    const page = formPage();
    const input = all(page).find((e) => e.tagName === "input");
    const label = all(page).find((e) => e.tagName === "label");
    expect(label?.attributes.get("for")).toBe(input?.attributes.get("id"));
    expect(input?.attributes.get("maxlength")).toBe("200");
    expect(input?.attributes.has("required")).toBe(true);
  });

  it("never marks a checkbox as required (unticked means false)", () => {
    const page = formPage({ fields: [{ key: "published", kind: "Bool", label: "Published", required: true, nullable: false, multiline: false }] });
    const box = all(page).find((e) => e.tagName === "input");
    expect(box?.attributes.get("type")).toBe("checkbox");
    expect(box?.attributes.has("required")).toBe(false);
  });

  it("sends hostile input as data, then goes to the saved record", async () => {
    const sent = stubSend({ id: "new/1" }, 201);
    const page = formPage();
    const box = all(page).find((e) => e.tagName === "input");
    if (box) box.value = HOSTILE;
    all(page).find((e) => e.tagName === "form")?.onsubmit?.({ preventDefault: () => undefined });
    await flush();
    expect(sent).toEqual([{ url: "/api/posts", method: "POST", body: { title: HOSTILE }, headers: { Accept: "application/json", "Content-Type": "application/json" } }]);
    expect(navigation).toEqual(["/posts/new%2F1"]);
  });

  it("shows a server error next to its field, as text", async () => {
    stubSend({ error: { code: "validation_failed", message: HOSTILE, field: "title" } }, 400);
    const page = formPage();
    all(page).find((e) => e.tagName === "form")?.onsubmit?.({ preventDefault: () => undefined });
    await flush();
    const error = all(page).find((e) => e.attributes.get("id") === "rizo-field-title-error");
    expect(error?.children).toEqual([new FakeText(HOSTILE)]);
    expect(focused?.attributes.get("aria-invalid")).toBe("true");
    expect(navigation).toEqual([]);
  });

  it("goes to ?next= after logging in, only if it is on this site", async () => {
    stubSend({ id: "u1" });
    fakeLocation.search = "?next=%2F%2Fevil.example";
    const page = formPage({ endpoint: "/auth/login", then: null });
    all(page).find((e) => e.tagName === "form")?.onsubmit?.({ preventDefault: () => undefined });
    await flush();
    expect(navigation).toEqual(["/"]);
  });
});

describe("emailed links", () => {
  const TOKEN = "A".repeat(43);
  const password = { key: "newPassword", kind: "Password", label: "New password", required: true, nullable: false, min: 8, max: 128, multiline: false };
  const open = (title: string, items: unknown[], hash: string) => {
    fakeLocation.hash = hash;
    byId.set("rizo-page", { textContent: JSON.stringify({ title, items, params: {}, loggedIn: false, auth: true }) });
    byId.set("app", new FakeElement("main"));
    client.start();
    return replaced as FakeElement;
  };
  const resendForm = {
    kind: "form", method: "POST", endpoint: "/auth/verify-email/resend", submit: "Send a new link", prefill: null, then: null,
    fields: [{ key: "email", kind: "Email", label: "Email", required: true, nullable: false, max: 254, multiline: false }],
    done: "If this email has an account, we sent it a new link.",
  };

  it("confirms the email with the token from the link, then removes the token from the address bar", async () => {
    const sent = stubSend(null, 204);
    const page = open("Confirm your email", [{ kind: "verifyEmail" }, resendForm], `#token=${TOKEN}`);
    expect(cleaned).toEqual(["/"]);
    await flush();
    expect(sent.map((s) => [s.url, s.body])).toEqual([["/auth/verify-email", { token: TOKEN }]]);
    expect(page.textContent).toContain("Your email is confirmed");
    expect(all(page).some((e) => e.tagName === "form")).toBe(false); // only what the link is for
  });

  it("shows the link's page when a link is opened in a tab that already shows the page", async () => {
    const listeners: Record<string, () => void> = {};
    (fakeWindow as { addEventListener?: unknown }).addEventListener = (name: string, fn: () => void) => (listeners[name] = fn);
    try {
      const sent = stubSend(null, 204);
      open("Confirm your email", [{ kind: "verifyEmail" }, resendForm], "");
      expect(sent).toEqual([]);
      const first = replaced;
      fakeLocation.hash = `#token=${TOKEN}`;
      listeners["hashchange"]?.();
      await flush();
      expect(replaced).not.toBe(first);
      expect(sent.map((s) => s.body)).toEqual([{ token: TOKEN }]);
      expect(cleaned).toEqual(["/"]);
    } finally {
      delete (fakeWindow as { addEventListener?: unknown }).addEventListener;
    }
  });

  it("ignores a malformed token and shows the form to get a new link", async () => {
    const sent = stubSend(null, 204);
    const page = open("Confirm your email", [{ kind: "verifyEmail" }, resendForm], "#token=<script>");
    await flush();
    expect(sent).toEqual([]);
    expect(all(page).some((e) => e.tagName === "form")).toBe(true);
  });

  it("sends the new password with the token, and shows a message instead of leaving the page", async () => {
    const sent = stubSend(null, 204);
    const page = open("Reset your password", [{ kind: "newPassword", field: password }, resendForm], `#token=${TOKEN}`);
    const input = all(page).find((e) => e.tagName === "input");
    expect(input?.attributes.get("autocomplete")).toBe("new-password");
    if (input) input.value = "a brand new password";
    all(page).find((e) => e.tagName === "form")?.onsubmit?.({ preventDefault: () => undefined });
    await flush();
    expect(sent.map((s) => [s.url, s.body])).toEqual([["/auth/password-reset/confirm", { token: TOKEN, newPassword: "a brand new password" }]]);
    expect(replaced?.textContent).toContain("Your password is changed");
    expect(navigation).toEqual([]);
  });

  it("shows the done message after a built-in form, such as signup", async () => {
    stubSend({ message: "Check your email for a link." }, 202);
    const page = client.renderPage({ title: "Confirm", params: {}, loggedIn: false, auth: false, items: [resendForm as never] }) as unknown as FakeElement;
    all(page).find((e) => e.tagName === "form")?.onsubmit?.({ preventDefault: () => undefined });
    await flush();
    expect(replaced?.textContent).toBe("If this email has an account, we sent it a new link.");
    expect(navigation).toEqual([]);
  });
});

describe("the devices list", () => {
  it("shows each device as text, marks this one, and logs out another", async () => {
    const urls: string[] = [];
    const devices = { items: [
      { id: "a1", device: HOSTILE, createdAt: "2026-01-01T00:00:00Z", lastSeenAt: "2026-01-02T00:00:00Z", current: true },
      { id: "b/2", device: "Firefox on Windows", createdAt: "2026-01-01T00:00:00Z", lastSeenAt: "2026-01-01T00:00:00Z", current: false },
    ] };
    (globalThis as { fetch?: unknown }).fetch = async (url: string, init?: { method?: string }) => {
      urls.push(`${init?.method ?? "GET"} ${url}`);
      return { ok: true, status: init?.method === "DELETE" ? 204 : 200, json: async () => devices };
    };
    const page = client.renderPage({ title: "Your account", params: {}, loggedIn: true, auth: false, items: [{ kind: "sessions" }] }) as unknown as FakeElement;
    await flush();
    const cards = all(page).filter((e) => e.attributes.get("class") === "rizo-card");
    expect(cards).toHaveLength(2);
    expect(cards[0]?.textContent).toContain(`${HOSTILE} (this device)`);
    expect(all(cards[0] as FakeElement).find((e) => e.tagName === "strong")?.children[0]).toBeInstanceOf(FakeText);
    all(cards[1] as FakeElement).find((e) => e.tagName === "button")?.onclick?.();
    await flush();
    expect(urls).toContain("DELETE /auth/sessions/b%2F2");
    expect(navigation).toEqual([]);
  });
});

describe("buttons and the menu", () => {
  const buttonPage = () => client.renderPage({
    title: "Post", params: { id: "7" }, loggedIn: true, auth: false,
    items: [{ kind: "button", label: "Delete", method: "DELETE", endpoint: "/api/posts/:id", then: "/" }],
  }) as unknown as FakeElement;

  it("asks before deleting, and does nothing when cancelled", async () => {
    const sent = stubSend(null, 204);
    confirmAnswer = false;
    all(buttonPage()).find((e) => e.tagName === "button")?.onclick?.();
    await flush();
    expect(sent).toEqual([]);
  });

  it("deletes, then goes to the next page", async () => {
    const sent = stubSend(null, 204);
    all(buttonPage()).find((e) => e.tagName === "button")?.onclick?.();
    await flush();
    expect(sent.map((s) => `${s.method} ${s.url}`)).toEqual(["DELETE /api/posts/7"]);
    expect(navigation).toEqual(["/"]);
  });

  it("offers log in and sign up, returning to the current page", () => {
    fakeLocation.current = "/posts/7";
    const page = client.renderPage({ title: "x", params: {}, loggedIn: false, auth: true, items: [] }) as unknown as FakeElement;
    expect(all(page).filter((e) => e.tagName === "a").map((a) => a.attributes.get("href"))).toEqual(["/", "/login?next=%2Fposts%2F7", "/signup"]);
  });

  it("logs out through the API", async () => {
    const sent = stubSend(null, 204);
    const page = client.renderPage({ title: "x", params: {}, loggedIn: true, auth: true, items: [] }) as unknown as FakeElement;
    all(page).find((e) => e.tagName === "button")?.onclick?.();
    await flush();
    expect(sent.map((s) => `${s.method} ${s.url}`)).toEqual(["POST /auth/logout"]);
    expect(navigation).toEqual(["/"]);
  });
});
