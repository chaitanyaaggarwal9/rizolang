/**
 * End-to-end tests: compile examples/blog.rz, load its schema into a fresh
 * PostgreSQL schema, run the real runtime over HTTP and attack it.
 *
 * Runs only when RIZO_TEST_DATABASE_URL is set (CI sets it). Everything
 * happens inside a temporary schema that is dropped afterwards.
 */
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRequestHandler, grantAdmins } from "../runtime/server.ts";
import type { App } from "../runtime/types.ts";
import { compile } from "../src/compiler.js";
import { buildApp } from "../src/emit/routes.js";

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];
const schema = `rizo_e2e_${randomBytes(6).toString("hex")}`;

let pool: pg.Pool;
let app: App;
let server: Server;
let base: string;
const logs: string[] = [];
const responses: string[] = [];

interface Res {
  status: number;
  body: unknown;
  headers: Headers;
  cookie: string | undefined;
}

async function call(method: string, path: string, opts: { body?: unknown; cookie?: string; headers?: Record<string, string>; raw?: string } = {}): Promise<Res> {
  const headers: Record<string, string> = { ...opts.headers };
  if (opts.cookie) headers["Cookie"] = opts.cookie;
  let payload: string | undefined = opts.raw;
  if (opts.body !== undefined) {
    payload = JSON.stringify(opts.body);
    headers["Content-Type"] ??= "application/json";
  }
  const r = await fetch(base + path, { method, headers, ...(payload !== undefined ? { body: payload } : {}) });
  const text = await r.text();
  responses.push(text, JSON.stringify([...r.headers]));
  const setCookie = r.headers.get("set-cookie") ?? undefined;
  return {
    status: r.status,
    body: text === "" ? undefined : JSON.parse(text),
    headers: r.headers,
    cookie: setCookie?.split(";")[0],
  };
}

/** The items of a paged list response. */
function items<T = Record<string, unknown>>(r: Res): T[] {
  return (r.body as { items: T[] }).items;
}

const ALICE = { email: "Alice@Example.com", password: "correct horse battery", name: "Alice", bio: "hi" };
const BOB = { email: "bob@example.com", password: "another long password", name: "Bob" };

describe.skipIf(DATABASE_URL === undefined)("end to end (PostgreSQL)", () => {
  let alice: string;
  let aliceId: string;
  let bob: string;
  let postId: string;

  beforeAll(async () => {
    const result = compile(readFileSync(new URL("../examples/blog.rz", import.meta.url), "utf8"), "blog.rz");
    if (!result.ok) throw new Error("example does not compile");
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.end();
    pool = new pg.Pool({ connectionString: DATABASE_URL, options: `-c search_path="${schema}",public` });
    await pool.query(result.output.sql);
    app = buildApp(result.apis, result.auth);
    const handler = createRequestHandler(app, {
      db: { query: (sql, values) => pool.query(sql, values) },
      log: (line) => logs.push(line),
    });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
    await pool?.query(`DROP SCHEMA "${schema}" CASCADE`);
    await pool?.end();
  });

  it("signs up, returning only public fields and a hardened session cookie", async () => {
    const r = await call("POST", "/auth/signup", { body: ALICE });
    expect(r.status).toBe(201);
    expect(Object.keys(r.body as object).sort()).toEqual(["bio", "id", "name"]);
    const setCookie = r.headers.get("set-cookie") ?? "";
    expect(setCookie).toMatch(/^rizo_session=[A-Za-z0-9_-]{43}; HttpOnly; Secure; SameSite=Lax; Path=\/; Max-Age=604800$/);
    alice = r.cookie ?? "";
    aliceId = (r.body as { id: string }).id;
  });

  it("stores the email in lowercase and the password only as an scrypt hash", async () => {
    const row = (await pool.query('SELECT "email", "password_hash" FROM "users" WHERE "id" = $1', [aliceId])).rows[0];
    expect(row.email).toBe("alice@example.com");
    expect(row.password_hash).toMatch(/^scrypt\$15\$8\$3\$/);
    expect(row.password_hash).not.toContain(ALICE.password);
    const sessions = (await pool.query('SELECT "token_hash" FROM "_rizo_sessions"')).rows;
    expect(sessions.every((s) => /^[0-9a-f]{64}$/.test(s.token_hash))).toBe(true);
    expect(sessions.some((s) => alice.includes(s.token_hash))).toBe(false);
  });

  it("rejects duplicate accounts, short passwords and unknown fields", async () => {
    expect((await call("POST", "/auth/signup", { body: { ...ALICE, email: "ALICE@example.com" } })).status).toBe(409);
    const short = await call("POST", "/auth/signup", { body: { ...BOB, password: "short" } });
    expect(short).toMatchObject({ status: 400, body: { error: { code: "validation_failed", field: "password" } } });
    const extra = await call("POST", "/auth/signup", { body: { ...BOB, isAdmin: true } });
    expect(extra).toMatchObject({ status: 400, body: { error: { field: "isAdmin" } } });
    bob = (await call("POST", "/auth/signup", { body: BOB })).cookie ?? "";
  });

  it("gives the same answer for a wrong password and an unknown account", async () => {
    const wrong = await call("POST", "/auth/login", { body: { email: ALICE.email, password: "wrong password!!" } });
    const unknown = await call("POST", "/auth/login", { body: { email: "nobody@example.com", password: "wrong password!!" } });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  it("logs in and reports the current user", async () => {
    const r = await call("POST", "/auth/login", { body: { email: "alice@example.com", password: ALICE.password } });
    expect(r.status).toBe(200);
    alice = r.cookie ?? "";
    const me = await call("GET", "/auth/me", { cookie: alice });
    expect(me.body).toEqual({ id: aliceId, name: "Alice", bio: "hi" });
    expect((await call("GET", "/auth/me")).status).toBe(401);
  });

  it("requires login and sets the owner from the session, never from the body", async () => {
    const post = { title: "Hello", body: "First post", published: true };
    expect((await call("POST", "/posts", { body: post })).status).toBe(401);
    const spoof = await call("POST", "/posts", { cookie: bob, body: { ...post, author: aliceId } });
    expect(spoof).toMatchObject({ status: 400, body: { error: { field: "author" } } });
    const r = await call("POST", "/posts", { cookie: alice, body: post });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ ...post, author: aliceId, views: null });
    postId = (r.body as { id: string }).id;
  });

  it("finds records, and rejects malformed ids before they reach SQL", async () => {
    expect((await call("GET", `/posts/${postId}`)).body).toMatchObject({ id: postId, title: "Hello" });
    expect((await call("GET", "/posts/00000000-0000-0000-0000-000000000000")).status).toBe(404);
    const inj = await call("GET", `/posts/${encodeURIComponent("1' OR '1'='1")}`);
    expect(inj).toMatchObject({ status: 400, body: { error: { code: "invalid_parameter", field: "id" } } });
  });

  it("stores SQL-looking text as plain data", async () => {
    const title = `x'); DROP TABLE "posts"; --`;
    const r = await call("POST", "/posts", { cookie: alice, body: { title, body: "b", published: false } });
    expect((r.body as { title: string }).title).toBe(title);
    expect((await pool.query('SELECT count(*)::int AS n FROM "posts"')).rows[0].n).toBe(2);
  });

  it("enforces ownership: other users get 404 for update and delete", async () => {
    expect((await call("PATCH", `/posts/${postId}`, { cookie: bob, body: { title: "Mine now" } })).status).toBe(404);
    expect((await call("DELETE", `/posts/${postId}`, { cookie: bob })).status).toBe(404);
    expect((await call("GET", `/posts/${postId}`)).body).toMatchObject({ title: "Hello" });
  });

  it("updates only the fields sent, and cannot change the owner", async () => {
    const r = await call("PATCH", `/posts/${postId}`, { cookie: alice, body: { title: "Hello again", views: 3 } });
    expect(r.body).toMatchObject({ title: "Hello again", body: "First post", published: true, views: 3, author: aliceId });
    const cleared = await call("PATCH", `/posts/${postId}`, { cookie: alice, body: { views: null } });
    expect(cleared.body).toMatchObject({ views: null });
    expect((await call("PATCH", `/posts/${postId}`, { cookie: alice, body: { title: null } })).status).toBe(400);
    expect((await call("PATCH", `/posts/${postId}`, { cookie: alice, body: { author: "x" } })).status).toBe(400);
  });

  it("filters lists by the logged-in user and by path parameters", async () => {
    const mine = await call("GET", "/my/posts", { cookie: alice });
    expect(items(mine).length).toBe(2);
    expect((await call("GET", "/my/posts", { cookie: bob })).body).toEqual({ items: [], next: null });
    const published = await call("GET", "/posts");
    expect(items<{ title: string }>(published).map((p) => p.title)).toEqual(["Hello again"]);
  });

  it("checks links and protects linked records", async () => {
    const missing = await call("POST", "/comments", { cookie: bob, body: { post: "00000000-0000-0000-0000-000000000000", body: "?" } });
    expect(missing).toMatchObject({ status: 400, body: { error: { code: "invalid_link", field: "post" } } });
    expect((await call("POST", "/comments", { cookie: bob, body: { post: postId, body: "Nice" } })).status).toBe(201);
    expect(items(await call("GET", `/posts/${postId}/comments`))).toMatchObject([{ body: "Nice", post: postId }]);
    expect((await call("DELETE", `/posts/${postId}`, { cookie: alice })).status).toBe(409);
  });

  it("deletes a record its owner owns", async () => {
    const other = await call("POST", "/posts", { cookie: alice, body: { title: "Bye", body: "b", published: false } });
    const id = (other.body as { id: string }).id;
    expect((await call("DELETE", `/posts/${id}`, { cookie: alice })).status).toBe(204);
    expect((await call("GET", `/posts/${id}`)).status).toBe(404);
  });

  it("never returns private or secret fields", async () => {
    expect((await call("GET", `/users/${aliceId}`)).body).toEqual({ id: aliceId, name: "Alice", bio: "hi" });
  });

  describe("roles", () => {
    const db = () => ({ query: (sql: string, values: unknown[]) => pool.query(sql, values) });
    let bobId: string;
    let bobPost: string;

    it("never accepts a role at signup and never returns one", async () => {
      const r = await call("POST", "/auth/signup", { body: { email: "eve@example.com", password: "long enough password", name: "Eve", role: "admin" } });
      expect(r).toMatchObject({ status: 400, body: { error: { field: "role" } } });
      expect(Object.keys((await call("GET", "/auth/me", { cookie: bob })).body as object)).not.toContain("role");
    });

    it("grants admin from RIZO_ADMIN_EMAILS only to accounts that already exist", async () => {
      expect(await grantAdmins(app, db(), [" ALICE@example.com ", "late@example.com"])).toBe(1);
      const late = await call("POST", "/auth/signup", { body: { email: "late@example.com", password: "long enough password", name: "Late" } });
      expect(late.status).toBe(201);
      expect((await call("GET", "/admin/posts", { cookie: late.cookie ?? "" })).status).toBe(403);
    });

    it("lets only the listed roles call role endpoints", async () => {
      expect((await call("GET", "/admin/posts", { cookie: bob })).status).toBe(403);
      expect((await call("GET", "/admin/posts")).status).toBe(401);
      const all = await call("GET", "/admin/posts", { cookie: alice });
      expect(all.status).toBe(200);
      expect(items<{ published: boolean }>(all).some((p) => !p.published)).toBe(true);
    });

    it("lets an admin delete posts they do not own, but not other users", async () => {
      bobId = ((await call("GET", "/auth/me", { cookie: bob })).body as { id: string }).id;
      bobPost = ((await call("POST", "/posts", { cookie: bob, body: { title: "Bob's", body: "b", published: true } })).body as { id: string }).id;
      const alicePost = ((await call("POST", "/posts", { cookie: alice, body: { title: "Alice's", body: "a", published: true } })).body as { id: string }).id;
      expect((await call("DELETE", `/posts/${alicePost}`, { cookie: bob })).status).toBe(404);
      expect((await call("DELETE", `/posts/${bobPost}`, { cookie: alice })).status).toBe(204);
    });

    it("lets only admins assign roles, never to themselves", async () => {
      const path = `/auth/users/${bobId}/role`;
      expect((await call("PUT", path, { cookie: bob, body: { role: "editor" } })).status).toBe(403);
      expect((await call("PUT", `/auth/users/${aliceId}/role`, { cookie: alice, body: { role: null } })).status).toBe(403);
      expect((await call("PUT", path, { cookie: alice, body: { role: "superuser" } })).status).toBe(400);
      expect((await call("PUT", path, { cookie: alice, body: { role: "editor", extra: 1 } })).status).toBe(400);
      expect((await call("PUT", "/auth/users/00000000-0000-0000-0000-000000000000/role", { cookie: alice, body: { role: "editor" } })).status).toBe(404);
      const ok = await call("PUT", path, { cookie: alice, body: { role: "editor" } });
      expect(ok).toMatchObject({ status: 200, body: { id: bobId, role: "editor" } });
      // The new role applies to Bob's existing session immediately.
      expect((await call("GET", "/admin/posts", { cookie: bob })).status).toBe(200);
      expect((await call("PUT", path, { cookie: alice, body: { role: null } })).body).toMatchObject({ role: null });
      expect((await call("GET", "/admin/posts", { cookie: bob })).status).toBe(403);
    });
  });

  describe("pagination", () => {
    const titles = ["d", "a", "c", "b", "e", "c"]; // includes a duplicate title
    beforeAll(async () => {
      for (const title of titles) {
        await call("POST", "/posts", { cookie: alice, body: { title, body: "x", published: true } });
      }
    });

    async function walk(path: string, limit: number): Promise<{ titles: string[]; ids: string[]; pages: number }> {
      const out = { titles: [] as string[], ids: [] as string[], pages: 0 };
      let next: string | null = "";
      while (next !== null) {
        const r = await call("GET", `${path}?limit=${limit}${next ? `&after=${next}` : ""}`);
        expect(r.status).toBe(200);
        const page = r.body as { items: { id: string; title: string }[]; next: string | null };
        expect(page.items.length).toBeLessThanOrEqual(limit);
        out.titles.push(...page.items.map((p) => p.title));
        out.ids.push(...page.items.map((p) => p.id));
        out.pages++;
        next = page.next;
      }
      return out;
    }

    it("walks every page in order, without gaps or repeats, even with equal sort values", async () => {
      const all = items<{ id: string; title: string }>(await call("GET", "/posts"));
      const walked = await walk("/posts", 2);
      expect(walked.ids).toEqual(all.map((p) => p.id));
      expect(new Set(walked.ids).size).toBe(walked.ids.length);
      // Same order as one unpaged query (PostgreSQL's own collation decides the order).
      expect(walked.titles).toEqual(all.map((p) => p.title));
      expect(walked.pages).toBe(Math.ceil(all.length / 2));
    });

    it("pages by id when no order is given, and stays correct when rows are added", async () => {
      const first = await call("GET", "/my/posts?limit=3", { cookie: alice });
      const page1 = first.body as { items: { id: string }[]; next: string };
      await call("POST", "/posts", { cookie: alice, body: { title: "late", body: "x", published: false } });
      const rest: string[] = [];
      let next: string | null = page1.next;
      while (next !== null) {
        const r = await call("GET", `/my/posts?limit=3&after=${next}`, { cookie: alice });
        const p = r.body as { items: { id: string }[]; next: string | null };
        rest.push(...p.items.map((x) => x.id));
        next = p.next;
      }
      const ids = [...page1.items.map((x) => x.id), ...rest];
      expect(new Set(ids).size).toBe(ids.length);
      expect(ids).toEqual([...ids].sort());
    });

    it("rejects bad limits, tampered cursors and unknown parameters", async () => {
      for (const q of ["limit=0", "limit=21", "limit=abc", "limit=-1", "limit=1&limit=2"]) {
        expect((await call("GET", `/posts?${q}`)).status, q).toBe(400);
      }
      const forged = (parts: unknown) => Buffer.from(JSON.stringify(parts)).toString("base64url");
      for (const after of ["!!!", "bm90IGpzb24", forged(["a"]), forged(["a", "not-a-uuid"]), forged([1, 2]), forged(["x", "y", "z"])]) {
        const r = await call("GET", `/posts?after=${after}`);
        expect(r, after).toMatchObject({ status: 400, body: { error: { field: "after" } } });
      }
      expect((await call("GET", "/posts?sort=title")).status).toBe(400);
      expect((await call("GET", `/posts/${postId}?debug=1`)).status).toBe(400);
    });

    it("never lets a cursor change the query", async () => {
      const injected = Buffer.from(JSON.stringify([`a') OR 1=1 --`, "00000000-0000-0000-0000-000000000000"])).toString("base64url");
      const r = await call("GET", `/posts?after=${injected}`);
      expect(r.status).toBe(200);
      // The text is only a value to sort against: the result is a slice of the normal list, never more.
      const all = items<{ id: string; published: boolean }>(await call("GET", "/posts")).map((p) => p.id);
      const got = items<{ id: string; published: boolean }>(r);
      expect(got.every((p) => p.published && all.includes(p.id))).toBe(true);
      expect(got.length).toBeLessThan(all.length);
    });
  });

  it("rejects cross-site writes, wrong content types, oversized and unexpected bodies", async () => {
    const evil = await call("POST", "/posts", {
      cookie: alice, body: { title: "x", body: "x", published: true }, headers: { Origin: "https://evil.example" },
    });
    expect(evil.status).toBe(403);
    const sameOrigin = await call("POST", "/posts", {
      cookie: alice, body: { title: "x", body: "x", published: false }, headers: { Origin: base },
    });
    expect(sameOrigin.status).toBe(201);
    const form = await call("POST", "/posts", { cookie: alice, raw: "title=x", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    expect(form.status).toBe(415);
    const big = await call("POST", "/posts", { cookie: alice, body: { title: "x", body: "a".repeat(1_100_000), published: true } });
    expect(big.status).toBe(413);
    const unexpected = await call("DELETE", `/posts/${postId}`, { cookie: alice, raw: "{}", headers: { "Content-Type": "application/json" } });
    expect(unexpected).toMatchObject({ status: 400, body: { error: { code: "unexpected_body" } } });
    expect((await call("POST", "/posts", { cookie: alice, raw: "{not json", headers: { "Content-Type": "application/json" } })).status).toBe(400);
  });

  it("answers unknown paths with 404 and wrong methods with 405", async () => {
    expect((await call("GET", "/nope")).status).toBe(404);
    const r = await call("PUT", "/posts");
    expect(r.status).toBe(405);
    expect(r.headers.get("allow")).toContain("GET");
  });

  it("sends security headers on every response", async () => {
    const r = await call("GET", "/posts");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
  });

  it("rate-limits repeated failed logins for an account", async () => {
    const attempt = () => call("POST", "/auth/login", { body: { email: BOB.email, password: "definitely wrong" } });
    for (let i = 0; i < 5; i++) expect((await attempt()).status).toBe(401);
    const limited = await attempt();
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("logs out and revokes the session", async () => {
    const old = alice;
    const r = await call("POST", "/auth/logout", { cookie: alice });
    expect(r.status).toBe(204);
    expect(r.headers.get("set-cookie")).toContain("Max-Age=0");
    expect((await call("GET", "/auth/me", { cookie: old })).status).toBe(401);
  });

  it("never leaks passwords, hashes or emails in responses or logs", () => {
    const everything = [...responses, ...logs].join("\n");
    for (const secret of [ALICE.password, BOB.password, "scrypt$", "alice@example.com", "Alice@Example.com", BOB.email, "password_hash"]) {
      expect(everything).not.toContain(secret);
    }
    // Logs name the route pattern, never the concrete URL or body.
    expect(logs.some((l) => l.startsWith("PATCH /posts/:id 200"))).toBe(true);
    expect(logs.join("\n")).not.toContain(postId);
    expect(logs.join("\n")).not.toContain("DROP TABLE");
  });
});
