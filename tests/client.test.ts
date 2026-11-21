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
  onclick: (() => void) | null = null;
  readonly tagName: string;
  constructor(tagName: string) {
    this.tagName = tagName;
  }
  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
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
  set innerHTML(_: string) {
    throw new Error("innerHTML must never be used");
  }
  set outerHTML(_: string) {
    throw new Error("outerHTML must never be used");
  }
}

let replaced: FakeElement | undefined;
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
  client = await import("../runtime/client/rizo-client.js");
});

afterEach(() => {
  byId.clear();
  replaced = undefined;
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
      title: "Posts", params: {}, loggedIn: false,
      items: [{ kind: "show", endpoint: "/api/posts", mode: "list", model: "Post", fields: [...fields], detail: { path: "/posts/:id", param: "id" } }],
    }) as unknown as FakeElement;
    await flush();
    const links = all(page).filter((e) => e.tagName === "a");
    expect(links.map((a) => a.attributes.get("href"))).toEqual(["/posts/a%2Fb"]);
  });

  it("loads the next page with the cursor from the previous one", async () => {
    const urls = stubFetch({ items: [{ id: "1", title: "One", published: true }], next: "abc+/=" });
    const page = client.renderPage({
      title: "Posts", params: {}, loggedIn: false,
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
      title: "Post", params: { id: "42" }, loggedIn: false,
      items: [{ kind: "show", endpoint: "/api/posts/:id", mode: "one", model: "Post", fields: [...fields], detail: null }],
    }) as unknown as FakeElement;
    await flush();
    expect(urls).toEqual(["/api/posts/42"]);
    expect(texts(page)).toEqual(expect.arrayContaining(["Title", "Answer", "Published", "No"]));
  });

  it("shows readable errors, never the server's raw response", async () => {
    stubFetch({ error: { message: HOSTILE } }, 500);
    const page = client.renderPage({
      title: "Post", params: { id: "1" }, loggedIn: false,
      items: [{ kind: "show", endpoint: "/api/posts/:id", mode: "one", model: "Post", fields: [...fields], detail: null }],
    }) as unknown as FakeElement;
    await flush();
    const alert = all(page).find((e) => e.attributes.get("role") === "alert");
    expect(alert?.textContent).toBe(HOSTILE);
    expect(alert?.children[0]).toBeInstanceOf(FakeText);
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

  it.each(["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "setAttribute(\"on", "srcdoc"])(
    "never uses %s",
    (api) => {
      expect(source).not.toContain(api);
    },
  );
});
