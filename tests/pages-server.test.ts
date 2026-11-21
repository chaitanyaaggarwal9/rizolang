/** Serving pages from the generated server, with a fake database. */
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { PAGE_CSP, jsonForHtml } from "../runtime/pages.ts";
import { type Db, createRequestHandler } from "../runtime/server.ts";
import { SQL, hashToken } from "../runtime/session.ts";
import { buildApp } from "../src/emit/routes.js";
import { compileOk } from "./helpers.js";

const HOSTILE = `</script><script>alert(1)</script><!--\\x`;
/** Write text as a Rizo Lang quoted string: escape backslashes first, then quotes. */
const rzText = (text: string): string => `"${text.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
const SOURCE = `auth User by email roles admin
model User {
  email: Email unique
  password: Password
  name: Text
}
model Post {
  title: Text
}
api GET /api/posts -> list Post.public {
  public
  return db.Post.list()
}
api GET /api/posts/:id -> Post.public {
  public
  return db.Post.find(id)
}
page / {
  public
  title ${rzText(HOSTILE)}
  show GET /api/posts
}
page /posts/:id {
  public
  show GET /api/posts/:id
}
page /mine {
  requires login
  title "Mine"
}
page /admin {
  requires login
  requires role admin
  title "Admin"
}
`;

const TOKEN = "a".repeat(43);
let server: Server | undefined;
afterEach(async () => {
  await new Promise((r) => server?.close(r));
});

/** A fake database: one session for TOKEN, belonging to a user with `role`. */
function fakeDb(role: string | null): Db {
  return {
    query: async (sql, values) => {
      if (sql === SQL.lookup) return { rows: values[0] === hashToken(TOKEN) ? [{ user_id: "u1" }] : [], rowCount: 1 };
      if (sql.startsWith('SELECT "role"')) return { rows: [{ role }], rowCount: 1 };
      return { rows: [], rowCount: 0 };
    },
  };
}

async function start(role: string | null = null): Promise<string> {
  const r = compileOk(SOURCE);
  const handler = createRequestHandler(buildApp(r.apis, r.auth, r.pages), { db: fakeDb(role), log: () => undefined });
  server = createServer((req, res) => void handler(req, res));
  await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
  return `http://127.0.0.1:${(server?.address() as AddressInfo).port}`;
}

const loggedIn = { headers: { Cookie: `rizo_session=${TOKEN}` } };

describe("serving pages", () => {
  it("serves pages as HTML with a strict Content-Security-Policy", async () => {
    const base = await start();
    const r = await fetch(`${base}/`);
    expect(r.status).toBe(200);
    expect(r.headers.get("content-type")).toBe("text/html; charset=utf-8");
    expect(r.headers.get("content-security-policy")).toBe(PAGE_CSP);
    expect(PAGE_CSP).toContain("script-src 'self'");
    expect(PAGE_CSP).not.toContain("unsafe");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    const html = await r.text();
    expect(html).toContain('<script type="module" src="/_rizo/client.js"></script>');
  });

  it("keeps hostile text inside the data block and escaped in the title", async () => {
    const base = await start();
    const html = await (await fetch(`${base}/`)).text();
    expect(html.match(/<script/g)).toHaveLength(2); // the data block and our module, nothing else
    expect(html).not.toContain("<script>alert");
    expect(html).toContain("<title>&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;!--\\x</title>");
    const block = /<script type="application\/json" id="rizo-page">([^<]*)<\/script>/.exec(html)?.[1];
    expect(JSON.parse(block ?? "")).toMatchObject({ title: HOSTILE });
  });

  it("escapes every character that could end a script block", () => {
    const json = jsonForHtml({ t: "</script>&\u2028\u2029<!--" });
    expect(json).not.toMatch(/[<>&\u2028\u2029]/);
    expect(JSON.parse(json)).toEqual({ t: "</script>&\u2028\u2029<!--" });
  });

  it("serves only the runtime's own files under /_rizo/", async () => {
    const base = await start();
    const js = await fetch(`${base}/_rizo/client.js`);
    expect(js.status).toBe(200);
    expect(js.headers.get("content-type")).toBe("text/javascript; charset=utf-8");
    expect(await js.text()).toContain("export function renderPage");
    expect((await fetch(`${base}/_rizo/styles.css`)).status).toBe(200);
    for (const path of ["/_rizo/server.ts", "/_rizo/%2e%2e/server.ts", "/_rizo/..%2fserver.ts", "/_rizo/client.js/", "/_rizo/"]) {
      expect((await fetch(`${base}${path}`)).status, path).toBe(404);
    }
  });

  it("checks page parameters before serving", async () => {
    const base = await start();
    expect((await fetch(`${base}/posts/00000000-0000-4000-8000-000000000000`)).status).toBe(200);
    const bad = await fetch(`${base}/posts/not-a-uuid`);
    expect(bad.status).toBe(404);
    expect(await bad.text()).not.toContain("not-a-uuid");
  });

  it("sends visitors to the login page and back, and checks roles", async () => {
    const base = await start(null);
    const r = await fetch(`${base}/mine`, { redirect: "manual" });
    expect(r.status).toBe(302);
    expect(r.headers.get("location")).toBe("/login?next=%2Fmine");
    expect((await fetch(`${base}/mine`, loggedIn)).status).toBe(200);
    expect((await fetch(`${base}/admin`, loggedIn)).status).toBe(403);
    server?.close();
    const adminBase = await start("admin");
    expect((await fetch(`${adminBase}/admin`, loggedIn)).status).toBe(200);
  });

  it("adds the built-in login and signup pages, with their forms", async () => {
    const base = await start();
    for (const [path, endpoint] of [["/login", "/auth/login"], ["/signup", "/auth/signup"]] as const) {
      const html = await (await fetch(`${base}${path}`)).text();
      const data = JSON.parse(/id="rizo-page">([^<]*)</.exec(html)?.[1] ?? "{}") as { auth: boolean; items: { kind: string; endpoint?: string; fields?: { key: string; kind: string }[] }[] };
      expect(data.auth).toBe(true);
      const form = data.items.find((i) => i.kind === "form");
      expect(form?.endpoint).toBe(endpoint);
      expect(form?.fields?.map((f) => f.kind)).toContain("Password");
    }
  });

  it("still serves the API next to pages, as JSON", async () => {
    const base = await start();
    const r = await fetch(`${base}/api/posts`);
    expect(r.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(await r.json()).toEqual({ items: [], next: null });
    expect((await fetch(`${base}/nope`)).status).toBe(404);
  });
});
