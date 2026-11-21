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
import type { Email } from "../runtime/email.ts";
import { compile } from "../src/compiler.js";
import { SoftAuthenticator } from "./authenticator.js";
import { buildApp } from "../src/emit/routes.js";

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];
const schema = `rizo_e2e_${randomBytes(6).toString("hex")}`;

let pool: pg.Pool;
let app: App;
let server: Server;
let base: string;
const logs: string[] = [];
const responses: string[] = [];
const mail: Email[] = [];

/** The token in the newest email to this address with a link to this page. */
function linkToken(to: string, page: string): string {
  const email = [...mail].reverse().find((e) => e.to === to && e.text.includes(`${page}#token=`));
  const token = /#token=([A-Za-z0-9_-]{43})/.exec(email?.text ?? "")?.[1];
  if (token === undefined) throw new Error(`no ${page} link was emailed to ${to}`);
  return token;
}

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
const CAROL = { email: "carol@example.com", password: "carols first password", name: "Carol" };
const CAROL_NEW = "carols second password";
const BOB = { email: "bob@example.com", password: "another long password", name: "Bob" };

/** Sign up, confirm the email with the emailed link, and log in. */
async function join(account: { email: string; password: string }, address: string): Promise<{ cookie: string; id: string }> {
  const headers = { "X-Forwarded-For": address };
  expect((await call("POST", "/auth/signup", { body: account, headers })).status).toBe(202);
  const token = linkToken(account.email.toLowerCase(), "/verify-email");
  expect((await call("POST", "/auth/verify-email", { body: { token }, headers })).status).toBe(204);
  const r = await call("POST", "/auth/login", { body: { email: account.email, password: account.password }, headers });
  expect(r.status).toBe(200);
  return { cookie: r.cookie ?? "", id: (r.body as { id: string }).id };
}

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
    app = buildApp(result.apis, result.auth, result.pages);
    const handler = createRequestHandler(app, {
      db: { query: (sql, values) => pool.query(sql, values) },
      log: (line) => logs.push(line),
      mailer: async (email) => {
        mail.push(email);
      },
      publicUrl: "https://blog.example",
      // Lets a test act from its own address (X-Forwarded-For), so the per-address limits of other tests don't add up.
      trustProxy: true,
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

  it("signs up, confirms the email with a one-time link, then logs in with a hardened session cookie", async () => {
    const r = await call("POST", "/auth/signup", { body: ALICE });
    expect(r).toMatchObject({ status: 202, body: { message: "Check your email for a link." }, cookie: undefined });
    expect(mail.at(-1)).toMatchObject({ to: "alice@example.com", subject: "Confirm your email for blog.example" });
    const token = linkToken("alice@example.com", "/verify-email");
    expect(mail.at(-1)?.text).toContain(`https://blog.example/verify-email#token=${token}`);

    // Not before the email is confirmed.
    const early = await call("POST", "/auth/login", { body: { email: ALICE.email, password: ALICE.password } });
    expect(early).toMatchObject({ status: 403, body: { error: { code: "email_not_verified" } }, cookie: undefined });
    expect((await call("POST", "/auth/login", { body: { email: ALICE.email, password: "wrong password!!" } })).status).toBe(401);

    expect((await call("POST", "/auth/verify-email", { body: { token: "A".repeat(43) } })).status).toBe(400);
    expect((await call("POST", "/auth/verify-email", { body: { token } })).status).toBe(204);
    expect((await call("POST", "/auth/verify-email", { body: { token } })).body).toMatchObject({ error: { code: "invalid_link" } });

    const login = await call("POST", "/auth/login", { body: { email: ALICE.email, password: ALICE.password } });
    expect(login.status).toBe(200);
    expect(Object.keys(login.body as object).sort()).toEqual(["bio", "id", "name"]);
    expect(login.headers.get("set-cookie") ?? "").toMatch(/^rizo_session=[A-Za-z0-9_-]{43}; HttpOnly; Secure; SameSite=Lax; Path=\/; Max-Age=2592000$/);
    alice = login.cookie ?? "";
    aliceId = (login.body as { id: string }).id;
  });

  it("stores only hashes of emailed links", async () => {
    const tokens = (await pool.query('SELECT "id" FROM "_rizo_email_tokens"')).rows;
    expect(tokens.every((t) => /^[0-9a-f]{64}$/.test(t.id))).toBe(true);
    for (const email of mail) expect(tokens.some((t) => email.text.includes(t.id))).toBe(false);
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

  it("never reveals whether an email has an account: the owner gets an email instead", async () => {
    const users = async () => (await pool.query('SELECT count(*)::int AS "n" FROM "users"')).rows[0].n;
    const before = await users();
    const sent = mail.length;
    const again = await call("POST", "/auth/signup", { body: { ...ALICE, email: "ALICE@example.com", password: "someone elses password" } });
    const fresh = await call("POST", "/auth/signup", { body: { email: "zed@example.com", password: "zeds long password", name: "Zed" } });
    expect(again.status).toBe(fresh.status);
    expect(again.body).toEqual(fresh.body);
    expect(again.cookie).toBe(fresh.cookie);
    expect(await users()).toBe(before + 1);
    expect(mail.slice(sent).map((m) => [m.to, m.subject])).toEqual([
      ["alice@example.com", "You already have an account on blog.example"],
      ["zed@example.com", "Confirm your email for blog.example"],
    ]);
    expect(mail.at(-2)?.text).not.toContain("#token=");
    // The other person's password did not replace Alice's.
    expect((await call("POST", "/auth/login", { body: { email: ALICE.email, password: "someone elses password" } })).status).toBe(401);
  });

  it("rejects short passwords and unknown fields", async () => {
    const short = await call("POST", "/auth/signup", { body: { ...BOB, password: "short" } });
    expect(short).toMatchObject({ status: 400, body: { error: { code: "validation_failed", field: "password" } } });
    const extra = await call("POST", "/auth/signup", { body: { ...BOB, isAdmin: true } });
    expect(extra).toMatchObject({ status: 400, body: { error: { field: "isAdmin" } } });
    bob = (await join(BOB, "198.51.100.1")).cookie;
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
    expect((await call("POST", "/api/posts", { body: post })).status).toBe(401);
    const spoof = await call("POST", "/api/posts", { cookie: bob, body: { ...post, author: aliceId } });
    expect(spoof).toMatchObject({ status: 400, body: { error: { field: "author" } } });
    const r = await call("POST", "/api/posts", { cookie: alice, body: post });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ ...post, author: aliceId, views: null });
    postId = (r.body as { id: string }).id;
  });

  it("finds records, and rejects malformed ids before they reach SQL", async () => {
    expect((await call("GET", `/api/posts/${postId}`)).body).toMatchObject({ id: postId, title: "Hello" });
    expect((await call("GET", "/api/posts/00000000-0000-0000-0000-000000000000")).status).toBe(404);
    const inj = await call("GET", `/api/posts/${encodeURIComponent("1' OR '1'='1")}`);
    expect(inj).toMatchObject({ status: 400, body: { error: { code: "invalid_parameter", field: "id" } } });
  });

  it("stores SQL-looking text as plain data", async () => {
    const title = `x'); DROP TABLE "posts"; --`;
    const r = await call("POST", "/api/posts", { cookie: alice, body: { title, body: "b", published: false } });
    expect((r.body as { title: string }).title).toBe(title);
    expect((await pool.query('SELECT count(*)::int AS n FROM "posts"')).rows[0].n).toBe(2);
  });

  it("enforces ownership: other users get 404 for update and delete", async () => {
    expect((await call("PATCH", `/api/posts/${postId}`, { cookie: bob, body: { title: "Mine now" } })).status).toBe(404);
    expect((await call("DELETE", `/api/posts/${postId}`, { cookie: bob })).status).toBe(404);
    expect((await call("GET", `/api/posts/${postId}`)).body).toMatchObject({ title: "Hello" });
  });

  it("updates only the fields sent, and cannot change the owner", async () => {
    const r = await call("PATCH", `/api/posts/${postId}`, { cookie: alice, body: { title: "Hello again", views: 3 } });
    expect(r.body).toMatchObject({ title: "Hello again", body: "First post", published: true, views: 3, author: aliceId });
    const cleared = await call("PATCH", `/api/posts/${postId}`, { cookie: alice, body: { views: null } });
    expect(cleared.body).toMatchObject({ views: null });
    expect((await call("PATCH", `/api/posts/${postId}`, { cookie: alice, body: { title: null } })).status).toBe(400);
    expect((await call("PATCH", `/api/posts/${postId}`, { cookie: alice, body: { author: "x" } })).status).toBe(400);
  });

  it("filters lists by the logged-in user and by path parameters", async () => {
    const mine = await call("GET", "/api/my/posts", { cookie: alice });
    expect(items(mine).length).toBe(2);
    expect((await call("GET", "/api/my/posts", { cookie: bob })).body).toEqual({ items: [], next: null });
    const published = await call("GET", "/api/posts");
    expect(items<{ title: string }>(published).map((p) => p.title)).toEqual(["Hello again"]);
  });

  it("checks links and protects linked records", async () => {
    const missing = await call("POST", "/api/comments", { cookie: bob, body: { post: "00000000-0000-0000-0000-000000000000", body: "?" } });
    expect(missing).toMatchObject({ status: 400, body: { error: { code: "invalid_link", field: "post" } } });
    expect((await call("POST", "/api/comments", { cookie: bob, body: { post: postId, body: "Nice" } })).status).toBe(201);
    expect(items(await call("GET", `/api/posts/${postId}/comments`))).toMatchObject([{ body: "Nice", post: postId }]);
    expect((await call("DELETE", `/api/posts/${postId}`, { cookie: alice })).status).toBe(409);
  });

  it("deletes a record its owner owns", async () => {
    const other = await call("POST", "/api/posts", { cookie: alice, body: { title: "Bye", body: "b", published: false } });
    const id = (other.body as { id: string }).id;
    expect((await call("DELETE", `/api/posts/${id}`, { cookie: alice })).status).toBe(204);
    expect((await call("GET", `/api/posts/${id}`)).status).toBe(404);
  });

  it("never returns private or secret fields", async () => {
    expect((await call("GET", `/api/users/${aliceId}`)).body).toEqual({ id: aliceId, name: "Alice", bio: "hi" });
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
      const late = await join({ email: "late@example.com", password: "long enough password", name: "Late" } as never, "198.51.100.2");
      expect((await call("GET", "/api/admin/posts", { cookie: late.cookie })).status).toBe(403);
    });

    it("lets only the listed roles call role endpoints", async () => {
      expect((await call("GET", "/api/admin/posts", { cookie: bob })).status).toBe(403);
      expect((await call("GET", "/api/admin/posts")).status).toBe(401);
      const all = await call("GET", "/api/admin/posts", { cookie: alice });
      expect(all.status).toBe(200);
      expect(items<{ published: boolean }>(all).some((p) => !p.published)).toBe(true);
    });

    it("lets an admin delete posts they do not own, but not other users", async () => {
      bobId = ((await call("GET", "/auth/me", { cookie: bob })).body as { id: string }).id;
      bobPost = ((await call("POST", "/api/posts", { cookie: bob, body: { title: "Bob's", body: "b", published: true } })).body as { id: string }).id;
      const alicePost = ((await call("POST", "/api/posts", { cookie: alice, body: { title: "Alice's", body: "a", published: true } })).body as { id: string }).id;
      expect((await call("DELETE", `/api/posts/${alicePost}`, { cookie: bob })).status).toBe(404);
      expect((await call("DELETE", `/api/posts/${bobPost}`, { cookie: alice })).status).toBe(204);
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
      expect((await call("GET", "/api/admin/posts", { cookie: bob })).status).toBe(200);
      expect((await call("PUT", path, { cookie: alice, body: { role: null } })).body).toMatchObject({ role: null });
      expect((await call("GET", "/api/admin/posts", { cookie: bob })).status).toBe(403);
    });
  });

  it("shares rate limits between server processes through PostgreSQL", async () => {
    // A second, independent server on the same database (as when running several copies).
    const second = createRequestHandler(app, { db: { query: (sql, values) => pool.query(sql, values) }, log: () => undefined });
    const other = createServer((req, res) => void second(req, res));
    await new Promise<void>((resolve) => other.listen(0, "127.0.0.1", resolve));
    const otherBase = `http://127.0.0.1:${(other.address() as AddressInfo).port}`;
    try {
      const target = await call("POST", "/api/posts", { cookie: bob, body: { title: "For comments", body: "x", published: true } });
      const post = (target.body as { id: string }).id;
      // Alice (who hasn't commented yet) may comment 10 times per minute in
      // total, however the requests are spread over the two servers.
      const comment = (url: string, cookie = alice) =>
        fetch(`${url}/api/comments`, { method: "POST", headers: { "Content-Type": "application/json", Cookie: cookie }, body: JSON.stringify({ post, body: "hi" }) });
      const statuses: number[] = [];
      for (let i = 0; i < 10; i++) statuses.push((await comment(i % 2 === 0 ? base : otherBase)).status);
      expect(statuses).toEqual(Array(10).fill(201));
      const blocked = await comment(otherBase);
      expect(blocked.status).toBe(429);
      expect(Number(blocked.headers.get("retry-after"))).toBeGreaterThan(0);
      expect((await comment(base)).status).toBe(429);
      // Other accounts have their own budget (Bob has used 2 of his 10 this minute).
      expect((await comment(base, bob)).status).toBe(201);
      // Counters are keyed by hashes, never by raw identities.
      const keys = (await pool.query('SELECT "key" FROM "_rizo_rate_limits"')).rows.map((r) => String(r.key));
      expect(keys.length).toBeGreaterThan(0);
      expect(keys.join(" ")).not.toMatch(/127\.0\.0\.1|[0-9a-f]{8}-[0-9a-f]{4}-/);
    } finally {
      await new Promise((resolve) => other.close(resolve));
    }
  });

  it("answers every list query from its generated index, in order, at scale", async () => {
    // A realistic amount of data, so PostgreSQL plans as it would in production.
    const post = (await pool.query(
      `INSERT INTO posts (author_id, title, body, published)
       SELECT $1, 'bulk-' || md5(i::text), 'x', i % 2 = 0 FROM generate_series(1, 20000) AS i RETURNING id`,
      [aliceId],
    )).rows[0].id as string;
    await pool.query(
      `INSERT INTO comments (post_id, author_id, body) SELECT $1, $2, 'bulk' FROM generate_series(1, 20000)`,
      [post, aliceId],
    );
    await pool.query("ANALYZE posts");
    await pool.query("ANALYZE comments");
    try {
      for (const route of app.routes.filter((r) => r.result === "list")) {
        const args = route.values.map((v) =>
          v.from === "cursorSet" ? false : v.from === "pageLimit" ? 21 : v.from === "const" ? v.value
          : v.from === "me" ? aliceId : v.from === "path" ? post : null);
        const plan = JSON.stringify((await pool.query(`EXPLAIN (FORMAT JSON) ${route.sql}`, args)).rows[0]);
        expect(plan, route.pattern).toMatch(/"Node Type":"Index (Only )?Scan"/);
        expect(plan, route.pattern).not.toContain('"Node Type":"Sort"');
        expect(plan, route.pattern).not.toContain('"Node Type":"Seq Scan"');
      }
    } finally {
      await pool.query("DELETE FROM comments WHERE body = 'bulk'");
      await pool.query("DELETE FROM posts WHERE title LIKE 'bulk-%'");
    }
  });

  describe("pages", () => {
    const page = async (path: string, cookie?: string) => {
      const r = await fetch(base + path, { redirect: "manual", ...(cookie ? { headers: { Cookie: cookie } } : {}) });
      return { status: r.status, csp: r.headers.get("content-security-policy"), html: await r.text() };
    };

    it("serves the example's pages next to its API", async () => {
      const home = await page("/");
      expect(home.status).toBe(200);
      expect(home.csp).toContain("script-src 'self'");
      const data = JSON.parse(/id="rizo-page">([^<]*)</.exec(home.html)?.[1] ?? "{}") as { title: string; items: { kind: string; endpoint?: string }[] };
      expect(data.title).toBe("Rizo Blog");
      expect(data.items.find((i) => i.kind === "show")?.endpoint).toBe("/api/posts");
      expect((await page(`/posts/${postId}`)).status).toBe(200);
      expect((await page("/posts/not-an-id")).status).toBe(404);
    });

    it("serves the forms and the built-in login and signup pages", async () => {
      const r = await fetch(`${base}/posts/new`, { redirect: "manual" });
      expect(r.status).toBe(302);
      expect(r.headers.get("location")).toBe("/login?next=%2Fposts%2Fnew");
      const form = await page("/posts/new", alice);
      expect(form.status).toBe(200);
      expect(form.html).toContain('"kind":"form","method":"POST","endpoint":"/api/posts"');
      expect((await page(`/posts/${postId}/edit`, alice)).html).toContain('"prefill":"/api/posts/:id"');
      for (const path of ["/login", "/signup"]) expect((await page(path)).status).toBe(200);
    });

    it("applies login and roles to pages", async () => {
      expect((await page("/admin")).status).toBe(302);
      expect((await page("/admin", bob)).status).toBe(403);
      expect((await page("/admin", alice)).status).toBe(200);
    });
  });

  describe("pagination", () => {
    const titles = ["d", "a", "c", "b", "e", "c"]; // includes a duplicate title
    beforeAll(async () => {
      for (const title of titles) {
        await call("POST", "/api/posts", { cookie: alice, body: { title, body: "x", published: true } });
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
      const all = items<{ id: string; title: string }>(await call("GET", "/api/posts"));
      const walked = await walk("/api/posts", 2);
      expect(walked.ids).toEqual(all.map((p) => p.id));
      expect(new Set(walked.ids).size).toBe(walked.ids.length);
      // Same order as one unpaged query (PostgreSQL's own collation decides the order).
      expect(walked.titles).toEqual(all.map((p) => p.title));
      expect(walked.pages).toBe(Math.ceil(all.length / 2));
    });

    it("pages by id when no order is given, and stays correct when rows are added", async () => {
      const first = await call("GET", "/api/my/posts?limit=3", { cookie: alice });
      const page1 = first.body as { items: { id: string }[]; next: string };
      await call("POST", "/api/posts", { cookie: alice, body: { title: "late", body: "x", published: false } });
      const rest: string[] = [];
      let next: string | null = page1.next;
      while (next !== null) {
        const r = await call("GET", `/api/my/posts?limit=3&after=${next}`, { cookie: alice });
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
        expect((await call("GET", `/api/posts?${q}`)).status, q).toBe(400);
      }
      const forged = (parts: unknown) => Buffer.from(JSON.stringify(parts)).toString("base64url");
      for (const after of ["!!!", "bm90IGpzb24", forged(["a"]), forged(["a", "not-a-uuid"]), forged([1, 2]), forged(["x", "y", "z"])]) {
        const r = await call("GET", `/api/posts?after=${after}`);
        expect(r, after).toMatchObject({ status: 400, body: { error: { field: "after" } } });
      }
      expect((await call("GET", "/api/posts?sort=title")).status).toBe(400);
      expect((await call("GET", `/api/posts/${postId}?debug=1`)).status).toBe(400);
    });

    it("never lets a cursor change the query", async () => {
      const injected = Buffer.from(JSON.stringify([`a') OR 1=1 --`, "00000000-0000-0000-0000-000000000000"])).toString("base64url");
      const r = await call("GET", `/api/posts?after=${injected}`);
      expect(r.status).toBe(200);
      // The text is only a value to sort against: the result is a slice of the normal list, never more.
      const all = items<{ id: string; published: boolean }>(await call("GET", "/api/posts")).map((p) => p.id);
      const got = items<{ id: string; published: boolean }>(r);
      expect(got.every((p) => p.published && all.includes(p.id))).toBe(true);
      expect(got.length).toBeLessThan(all.length);
    });
  });

  describe("account management", () => {
    let carol: string;
    let carolId: string;
    const login = async (password: string) =>
      call("POST", "/auth/login", { body: { email: CAROL.email, password } });

    beforeAll(async () => {
      ({ cookie: carol, id: carolId } = await join(CAROL, "198.51.100.3"));
    });

    it("updates your own profile, but never the email, password or role", async () => {
      const r = await call("PATCH", "/auth/me", { cookie: carol, body: { name: "Carol B", bio: "hello" } });
      expect(r).toMatchObject({ status: 200, body: { id: carolId, name: "Carol B", bio: "hello" } });
      for (const field of ["email", "password", "role", "id"]) {
        const bad = await call("PATCH", "/auth/me", { cookie: carol, body: { [field]: "x" } });
        expect(bad, field).toMatchObject({ status: 400, body: { error: { field } } });
      }
      expect((await call("PATCH", "/auth/me", { body: { name: "x" } })).status).toBe(401);
    });

    it("changes the password only with the current one, and logs out other sessions", async () => {
      const other = (await login(CAROL.password)).cookie ?? "";
      const wrong = await call("POST", "/auth/password", { cookie: carol, body: { currentPassword: "nope nope nope", newPassword: CAROL_NEW } });
      expect(wrong).toMatchObject({ status: 403, body: { error: { field: "currentPassword" } } });
      const weak = await call("POST", "/auth/password", { cookie: carol, body: { currentPassword: CAROL.password, newPassword: "short" } });
      expect(weak).toMatchObject({ status: 400, body: { error: { field: "newPassword" } } });
      const ok = await call("POST", "/auth/password", { cookie: carol, body: { currentPassword: CAROL.password, newPassword: CAROL_NEW } });
      expect(ok.status).toBe(204);
      expect((await call("GET", "/auth/me", { cookie: carol })).status).toBe(200);
      expect((await call("GET", "/auth/me", { cookie: other })).status).toBe(401);
      expect((await login(CAROL.password)).status).toBe(401);
      expect((await login(CAROL_NEW)).status).toBe(200);
    });

    it("logs out every session", async () => {
      const a = (await login(CAROL_NEW)).cookie ?? "";
      const b = (await login(CAROL_NEW)).cookie ?? "";
      const r = await call("POST", "/auth/logout-all", { cookie: a });
      expect(r.status).toBe(204);
      expect(r.headers.get("set-cookie")).toContain("Max-Age=0");
      expect((await call("GET", "/auth/me", { cookie: a })).status).toBe(401);
      expect((await call("GET", "/auth/me", { cookie: b })).status).toBe(401);
      expect((await call("GET", "/auth/me", { cookie: carol })).status).toBe(401);
      carol = (await login(CAROL_NEW)).cookie ?? "";
    });

    it("deletes the account only with the password, and only when nothing links to it", async () => {
      const post = await call("POST", "/api/posts", { cookie: carol, body: { title: "Mine", body: "x", published: false } });
      const blocked = await call("DELETE", "/auth/me", { cookie: carol, body: { password: CAROL_NEW } });
      expect(blocked).toMatchObject({ status: 409, body: { error: { code: "in_use" } } });
      await call("DELETE", `/api/posts/${(post.body as { id: string }).id}`, { cookie: carol });
      expect((await call("DELETE", "/auth/me", { cookie: carol, body: { password: "wrong wrong wrong" } })).status).toBe(403);
      const r = await call("DELETE", "/auth/me", { cookie: carol, body: { password: CAROL_NEW } });
      expect(r.status).toBe(204);
      expect((await call("GET", "/auth/me", { cookie: carol })).status).toBe(401);
      expect((await login(CAROL_NEW)).status).toBe(401);
      expect((await call("GET", `/api/users/${carolId}`)).status).toBe(404);
    });

    it("locks out repeated wrong passwords on sensitive changes", async () => {
      const dave = (await join({ email: "dave@example.com", password: "daves long password", name: "Dave" } as never, "198.51.100.4")).cookie;
      const attempt = () => call("POST", "/auth/password", { cookie: dave, body: { currentPassword: "guess guess guess", newPassword: "whatever whatever" } });
      for (let i = 0; i < 5; i++) expect((await attempt()).status).toBe(403);
      expect((await attempt()).status).toBe(429);
    });
  });

  it("rejects cross-site writes, wrong content types, oversized and unexpected bodies", async () => {
    const evil = await call("POST", "/api/posts", {
      cookie: alice, body: { title: "x", body: "x", published: true }, headers: { Origin: "https://evil.example" },
    });
    expect(evil.status).toBe(403);
    const sameOrigin = await call("POST", "/api/posts", {
      cookie: alice, body: { title: "x", body: "x", published: false }, headers: { Origin: base },
    });
    expect(sameOrigin.status).toBe(201);
    const form = await call("POST", "/api/posts", { cookie: alice, raw: "title=x", headers: { "Content-Type": "application/x-www-form-urlencoded" } });
    expect(form.status).toBe(415);
    const big = await call("POST", "/api/posts", { cookie: alice, body: { title: "x", body: "a".repeat(1_100_000), published: true } });
    expect(big.status).toBe(413);
    const unexpected = await call("DELETE", `/api/posts/${postId}`, { cookie: alice, raw: "{}", headers: { "Content-Type": "application/json" } });
    expect(unexpected).toMatchObject({ status: 400, body: { error: { code: "unexpected_body" } } });
    expect((await call("POST", "/api/posts", { cookie: alice, raw: "{not json", headers: { "Content-Type": "application/json" } })).status).toBe(400);
  });

  it("answers unknown paths with 404 and wrong methods with 405", async () => {
    expect((await call("GET", "/nope")).status).toBe(404);
    const r = await call("PUT", "/api/posts");
    expect(r.status).toBe(405);
    expect(r.headers.get("allow")).toContain("GET");
  });

  it("sends security headers on every response", async () => {
    const r = await call("GET", "/api/posts");
    expect(r.headers.get("x-content-type-options")).toBe("nosniff");
    expect(r.headers.get("cache-control")).toBe("no-store");
    expect(r.headers.get("content-security-policy")).toContain("default-src 'none'");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
  });

  describe("passkeys", () => {
    const authenticator = new SoftAuthenticator();
    const site = () => ({ origin: base, rpId: "127.0.0.1" });
    const fromSite = () => ({ Origin: base });
    let registration: ReturnType<SoftAuthenticator["register"]>;

    it("registers a passkey for the logged-in account", async () => {
      expect((await call("POST", "/auth/passkeys/register-options", { body: {}, headers: fromSite() })).status).toBe(401);
      const options = await call("POST", "/auth/passkeys/register-options", { cookie: alice, body: {}, headers: fromSite() });
      const o = options.body as { challenge: string; rp: { id: string }; user: { id: string; name: string }; authenticatorSelection: { userVerification: string } };
      expect(o.rp.id).toBe("127.0.0.1");
      // The example's email is private, so it is never sent, not even to its owner.
      expect(o.user).toMatchObject({ id: Buffer.from(aliceId).toString("base64url"), name: "127.0.0.1 account" });
      expect(o.authenticatorSelection.userVerification).toBe("required");
      registration = authenticator.register({ challenge: o.challenge, ...site(), userId: o.user.id });
      const r = await call("POST", "/auth/passkeys", { cookie: alice, body: { name: "Test key", ...registration }, headers: fromSite() });
      expect(r).toMatchObject({ status: 201, body: { id: registration.id, name: "Test key" } });
      const list = await call("GET", "/auth/passkeys", { cookie: alice });
      expect((list.body as { items: { id: string; name: string; lastUsedAt: null }[] }).items).toMatchObject([{ id: registration.id, name: "Test key", lastUsedAt: null }]);
      // Only the public key is stored.
      const row = (await pool.query('SELECT * FROM "_rizo_passkeys"')).rows[0];
      expect(Object.keys(row).sort()).toEqual(["algorithm", "created_at", "id", "last_used_at", "name", "public_key", "sign_count", "user_id"]);
    });

    it("refuses to reuse a registration (the challenge is single-use)", async () => {
      const r = await call("POST", "/auth/passkeys", { cookie: alice, body: { name: "Again", ...registration }, headers: fromSite() });
      expect(r).toMatchObject({ status: 400, body: { error: { code: "passkey_failed" } } });
    });

    it("logs in with the passkey, and refuses a replayed login", async () => {
      const o = (await call("POST", "/auth/passkeys/login-options", { body: {}, headers: fromSite() })).body as { challenge: string; rpId: string };
      expect(o.rpId).toBe("127.0.0.1");
      const assertion = authenticator.login({ challenge: o.challenge, ...site() });
      const r = await call("POST", "/auth/passkeys/login", { body: assertion, headers: fromSite() });
      expect(r.status).toBe(200);
      expect(r.cookie).toMatch(/^rizo_session=/);
      expect(((await call("GET", "/auth/me", { cookie: r.cookie ?? "" })).body as { id: string }).id).toBe(aliceId);
      expect((await call("POST", "/auth/passkeys/login", { body: assertion, headers: fromSite() })).status).toBe(400);
    });

    it("refuses passkeys used from another site, forged ones and logins without a browser", async () => {
      const o = (await call("POST", "/auth/passkeys/login-options", { body: {}, headers: fromSite() })).body as { challenge: string };
      expect((await call("POST", "/auth/passkeys/login", { body: authenticator.login({ challenge: o.challenge, ...site() }), headers: { Origin: "https://evil.example" } })).status).toBe(403);
      const o2 = (await call("POST", "/auth/passkeys/login-options", { body: {}, headers: fromSite() })).body as { challenge: string };
      const forged = new SoftAuthenticator().login({ challenge: o2.challenge, ...site() });
      expect((await call("POST", "/auth/passkeys/login", { body: { ...forged, id: registration.id }, headers: fromSite() })).status).toBe(401);
      expect((await call("POST", "/auth/passkeys/login-options", { body: {} })).status).toBe(400);
    });

    it("lets only the owner remove a passkey, and a removed passkey stops working", async () => {
      const path = `/auth/passkeys/${registration.id}`;
      expect((await call("DELETE", path, { cookie: bob, headers: fromSite() })).status).toBe(404);
      expect((await call("DELETE", path, { cookie: alice, headers: fromSite() })).status).toBe(204);
      const o = (await call("POST", "/auth/passkeys/login-options", { body: {}, headers: fromSite() })).body as { challenge: string };
      expect((await call("POST", "/auth/passkeys/login", { body: authenticator.login({ challenge: o.challenge, ...site() }), headers: fromSite() })).status).toBe(401);
      const actions = (await pool.query(`SELECT "action", "detail" FROM "_rizo_audit" WHERE "action" LIKE 'passkey%' OR "detail" = 'passkey' ORDER BY "at", "id"`)).rows;
      expect(actions.map((a) => `${a.action}:${a.detail ?? ""}`)).toEqual(["passkey_added:Test key", "login:passkey", "login_failed:passkey", "passkey_removed:", "login_failed:passkey"]);
    });
  });

  it("rate-limits repeated failed logins for an account", async () => {
    const attempt = () => call("POST", "/auth/login", { body: { email: BOB.email, password: "definitely wrong" } });
    for (let i = 0; i < 5; i++) expect((await attempt()).status).toBe(401);
    const limited = await attempt();
    expect(limited.status).toBe(429);
    expect(Number(limited.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  describe("devices and session lifetimes", () => {
    const KIM = { email: "kim@example.com", password: "kims long password", name: "Kim" };
    const CHROME_MAC = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36";
    const FIREFOX_WIN = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0";
    const at = (ua: string) => ({ "X-Forwarded-For": "198.51.100.40", "User-Agent": ua });
    let laptop: string;
    let pc: string;
    const tokenHash = async (cookie: string) => (await import("../runtime/session.ts")).hashToken(cookie.split("=")[1] ?? "");

    beforeAll(async () => {
      await join(KIM, "198.51.100.40");
      const login = async (ua: string) =>
        (await call("POST", "/auth/login", { body: { email: KIM.email, password: KIM.password }, headers: at(ua) })).cookie ?? "";
      laptop = await login(CHROME_MAC);
      pc = await login(FIREFOX_WIN);
    });

    it("lists your devices with a label, marking this one, and never shows tokens", async () => {
      const r = await call("GET", "/auth/sessions", { cookie: laptop });
      expect(r.status).toBe(200);
      const list = items<{ id: string; device: string; current: boolean; createdAt: string; lastSeenAt: string }>(r);
      expect(list.map((s) => s.device)).toEqual(expect.arrayContaining(["Chrome on macOS", "Firefox on Windows"]));
      expect(list.filter((s) => s.current).map((s) => s.device)).toEqual(["Chrome on macOS"]);
      expect(Object.keys(list[0] ?? {}).sort()).toEqual(["createdAt", "current", "device", "id", "lastSeenAt"]);
      expect(JSON.stringify(r.body)).not.toContain(await tokenHash(laptop));
      expect((await call("GET", "/auth/sessions")).status).toBe(401);
    });

    it("logs out one device, and only your own", async () => {
      const list = items<{ id: string; device: string }>(await call("GET", "/auth/sessions", { cookie: laptop }));
      const pcId = list.find((s) => s.device === "Firefox on Windows")?.id ?? "";
      expect((await call("DELETE", `/auth/sessions/${pcId}`, { cookie: bob })).status).toBe(404);
      expect((await call("DELETE", "/auth/sessions/not-an-id", { cookie: laptop })).status).toBe(404);
      expect((await call("GET", "/auth/me", { cookie: pc })).status).toBe(200);
      const r = await call("DELETE", `/auth/sessions/${pcId}`, { cookie: laptop });
      expect(r.status).toBe(204);
      expect(r.headers.get("set-cookie")).toBeNull();
      expect((await call("GET", "/auth/me", { cookie: pc })).status).toBe(401);
      expect((await call("GET", "/auth/me", { cookie: laptop })).status).toBe(200);
      expect((await call("DELETE", `/auth/sessions/${pcId}`, { cookie: laptop })).status).toBe(404);
    });

    it("logging out this device clears the cookie", async () => {
      const phone = (await call("POST", "/auth/login", { body: { email: KIM.email, password: KIM.password }, headers: at("curl/8.0") })).cookie ?? "";
      const mine = items<{ id: string; current: boolean; device: string }>(await call("GET", "/auth/sessions", { cookie: phone })).find((s) => s.current);
      expect(mine?.device).toBe("Unknown device");
      const r = await call("DELETE", `/auth/sessions/${mine?.id}`, { cookie: phone });
      expect(r.headers.get("set-cookie")).toContain("Max-Age=0");
      expect((await call("GET", "/auth/me", { cookie: phone })).status).toBe(401);
    });

    it("ends a session after 7 days without use", async () => {
      await pool.query(`UPDATE "_rizo_sessions" SET "expires_at" = now() - interval '1 second' WHERE "token_hash" = $1`, [await tokenHash(laptop)]);
      expect((await call("GET", "/auth/me", { cookie: laptop })).status).toBe(401);
      laptop = (await call("POST", "/auth/login", { body: { email: KIM.email, password: KIM.password }, headers: at(CHROME_MAC) })).cookie ?? "";
    });

    it("keeps a used session alive for 7 more days, but never past 30 days from login", async () => {
      const hash = await tokenHash(laptop);
      const row = async () => (await pool.query(`SELECT "expires_at" - now() AS "left", "ends_at" - "created_at" AS "max", "expires_at" <= "ends_at" AS "bounded" FROM "_rizo_sessions" WHERE "token_hash" = $1`, [hash])).rows[0];
      expect((await row()).max.days).toBe(30);
      // Last used 3 days ago, with 4 days left: using it now moves the deadline to 7 days from now.
      await pool.query(`UPDATE "_rizo_sessions" SET "last_seen_at" = now() - interval '3 days', "expires_at" = now() + interval '4 days' WHERE "token_hash" = $1`, [hash]);
      expect((await call("GET", "/auth/me", { cookie: laptop })).status).toBe(200);
      const left = (await row()).left;
      expect(left.days ?? 0).toBeGreaterThanOrEqual(6);
      // Close to the 30-day maximum, use doesn't extend it further, and at the maximum it ends.
      await pool.query(`UPDATE "_rizo_sessions" SET "last_seen_at" = now() - interval '2 minutes', "ends_at" = now() + interval '1 hour' WHERE "token_hash" = $1`, [hash]);
      expect((await call("GET", "/auth/me", { cookie: laptop })).status).toBe(200);
      expect((await row()).bounded).toBe(true);
      expect(((await row()).left.hours ?? 0)).toBeLessThanOrEqual(1);
      await pool.query(`UPDATE "_rizo_sessions" SET "ends_at" = now() - interval '1 second' WHERE "token_hash" = $1`, [hash]);
      expect((await call("GET", "/auth/me", { cookie: laptop })).status).toBe(401);
    });

    it("updates last active at most once a minute", async () => {
      const cookie = (await call("POST", "/auth/login", { body: { email: KIM.email, password: KIM.password }, headers: at(CHROME_MAC) })).cookie ?? "";
      const hash = await tokenHash(cookie);
      const seen = async () => String((await pool.query(`SELECT "last_seen_at" FROM "_rizo_sessions" WHERE "token_hash" = $1`, [hash])).rows[0].last_seen_at.toISOString());
      const first = await seen();
      await call("GET", "/auth/me", { cookie });
      expect(await seen()).toBe(first);
    });
  });

  describe("email links", () => {
    const FRANK = { email: "frank@example.com", password: "franks first password", name: "Frank" };
    const at = (address: string) => ({ "X-Forwarded-For": address });

    it("sends a new confirmation link on request, and the old one stops working", async () => {
      const h = at("198.51.100.10");
      const gina = { email: "gina@example.com", password: "ginas long password", name: "Gina" };
      expect((await call("POST", "/auth/signup", { body: gina, headers: h })).status).toBe(202);
      const first = linkToken(gina.email, "/verify-email");
      const resend = await call("POST", "/auth/verify-email/resend", { body: { email: "GINA@example.com" }, headers: h });
      const unknown = await call("POST", "/auth/verify-email/resend", { body: { email: "nobody@example.com" }, headers: h });
      expect(resend).toMatchObject({ status: 202, body: unknown.body });
      const second = linkToken(gina.email, "/verify-email");
      expect(second).not.toBe(first);
      expect((await call("POST", "/auth/verify-email", { body: { token: first }, headers: h })).status).toBe(400);
      expect((await call("POST", "/auth/verify-email", { body: { token: second }, headers: h })).status).toBe(204);
      // Confirmed accounts get no more confirmation emails.
      const sent = mail.length;
      await call("POST", "/auth/verify-email/resend", { body: { email: gina.email }, headers: h });
      expect(mail.length).toBe(sent);
    });

    it("resets a forgotten password with a one-time link, and logs out every session", async () => {
      const h = at("198.51.100.11");
      const frank = await join(FRANK, "198.51.100.11");
      const r = await call("POST", "/auth/password-reset", { body: { email: FRANK.email }, headers: h });
      const unknown = await call("POST", "/auth/password-reset", { body: { email: "nobody@example.com" }, headers: h });
      expect(r).toMatchObject({ status: 202, body: unknown.body });
      expect(mail.at(-1)).toMatchObject({ to: FRANK.email, subject: "Reset your password for blog.example" });
      const token = linkToken(FRANK.email, "/reset-password");
      expect(mail.at(-1)?.text).toContain(`https://blog.example/reset-password#token=${token}`);

      // The link can't confirm an email, and a weak password is refused without using up the link.
      expect((await call("POST", "/auth/verify-email", { body: { token }, headers: h })).status).toBe(400);
      const weak = await call("POST", "/auth/password-reset/confirm", { body: { token, newPassword: "short" }, headers: h });
      expect(weak).toMatchObject({ status: 400, body: { error: { field: "newPassword" } } });

      const done = await call("POST", "/auth/password-reset/confirm", { body: { token, newPassword: "franks new password" }, headers: h });
      expect(done.status).toBe(204);
      expect((await call("GET", "/auth/me", { cookie: frank.cookie })).status).toBe(401);
      expect((await call("POST", "/auth/password-reset/confirm", { body: { token, newPassword: "franks third password" }, headers: h })).status).toBe(400);
      expect((await call("POST", "/auth/login", { body: { email: FRANK.email, password: FRANK.password }, headers: h })).status).toBe(401);
      expect((await call("POST", "/auth/login", { body: { email: FRANK.email, password: "franks new password" }, headers: h })).status).toBe(200);
    });

    it("confirms the email of an account whose password is reset", async () => {
      const h = at("198.51.100.12");
      const hana = { email: "hana@example.com", password: "hanas long password", name: "Hana" };
      await call("POST", "/auth/signup", { body: hana, headers: h });
      await call("POST", "/auth/password-reset", { body: { email: hana.email }, headers: h });
      const token = linkToken(hana.email, "/reset-password");
      expect((await call("POST", "/auth/password-reset/confirm", { body: { token, newPassword: "hanas new password" }, headers: h })).status).toBe(204);
      expect((await call("POST", "/auth/login", { body: { email: hana.email, password: "hanas new password" }, headers: h })).status).toBe(200);
    });

    it("sends at most 3 emails an hour to one account, and limits requests per address", async () => {
      const ivan = { email: "ivan@example.com", password: "ivans long password", name: "Ivan" };
      await call("POST", "/auth/signup", { body: ivan, headers: at("198.51.100.13") });
      for (let i = 0; i < 4; i++) await call("POST", "/auth/password-reset", { body: { email: ivan.email }, headers: at(`198.51.100.${20 + i}`) });
      expect(mail.filter((m) => m.to === ivan.email)).toHaveLength(3);
      const h = at("198.51.100.30");
      for (let i = 0; i < 10; i++) expect((await call("POST", "/auth/password-reset", { body: { email: `x${i}@example.com` }, headers: h })).status).toBe(202);
      expect((await call("POST", "/auth/password-reset", { body: { email: "x@example.com" }, headers: h })).status).toBe(429);
    });
  });

  it("logs out and revokes the session", async () => {
    const old = alice;
    const r = await call("POST", "/auth/logout", { cookie: alice });
    expect(r.status).toBe(204);
    expect(r.headers.get("set-cookie")).toContain("Max-Age=0");
    expect((await call("GET", "/auth/me", { cookie: old })).status).toBe(401);
  });

  it("keeps a security audit log, without secrets, readable by admins", async () => {
    const rows = (await pool.query('SELECT "action", "user_id", "target_id", "ip", "detail" FROM "_rizo_audit" ORDER BY "at", "id"')).rows;
    const bobId = ((await pool.query('SELECT "id" FROM "users" WHERE "email" = $1', [BOB.email])).rows[0] as { id: string }).id;
    const has = (action: string, extra: Record<string, unknown> = {}) =>
      rows.some((r) => r.action === action && Object.entries(extra).every(([k, v]) => r[k] === v));
    expect(has("signup", { user_id: aliceId })).toBe(true);
    expect(has("login", { user_id: aliceId })).toBe(true);
    expect(has("login_failed", { user_id: aliceId, detail: "wrong password" })).toBe(true);
    expect(has("login_failed", { user_id: null, detail: "unknown account" })).toBe(true);
    expect(has("login_blocked")).toBe(true);
    expect(has("role_changed", { user_id: aliceId, target_id: bobId, detail: "editor" })).toBe(true);
    expect(has("record_deleted", { user_id: aliceId, detail: "Post" })).toBe(true);
    expect(has("login_failed", { user_id: aliceId, detail: "email not confirmed" })).toBe(true);
    expect(has("email_verified", { user_id: aliceId })).toBe(true);
    for (const action of ["password_changed", "password_check_failed", "account_deleted", "logout_all", "logout", "password_reset_requested", "password_reset", "session_revoked"]) {
      expect(has(action), action).toBe(true);
    }
    expect(rows.every((r) => r.ip === null || /^[0-9a-f.:]+$/i.test(String(r.ip)))).toBe(true);
    // Nothing secret is ever written to the log.
    const dump = JSON.stringify(rows);
    for (const secret of [ALICE.password, BOB.password, CAROL.password, CAROL_NEW, "alice@example.com", BOB.email, "scrypt$", "rizo_session"]) {
      expect(dump).not.toContain(secret);
    }

    // Admins can read it, newest first, optionally for one account.
    const admin = (await call("POST", "/auth/login", { body: { email: ALICE.email, password: ALICE.password } })).cookie ?? "";
    const forBob = await call("GET", `/auth/audit?account=${bobId}&limit=50`, { cookie: admin });
    expect(forBob.status).toBe(200);
    const items = (forBob.body as { items: { userId: string | null; targetId: string | null; at: string }[] }).items;
    expect(items.length).toBeGreaterThan(0);
    expect(items.every((i) => i.userId === bobId || i.targetId === bobId)).toBe(true);
    expect([...items].sort((a, b) => b.at.localeCompare(a.at)).map((i) => i.at)).toEqual(items.map((i) => i.at));
    expect((await call("GET", "/auth/audit", { cookie: bob })).status).toBe(403);
    expect((await call("GET", "/auth/audit")).status).toBe(401);
    expect((await call("GET", "/auth/audit?limit=9999", { cookie: admin })).status).toBe(400);
    expect((await call("GET", "/auth/audit?account=x", { cookie: admin })).status).toBe(400);
  });

  it("deletes audit entries older than the retention period", async () => {
    await pool.query(`INSERT INTO "_rizo_audit" ("at", "action", "detail") VALUES (now() - interval '400 days', 'login', 'old')`);
    const { Audit } = await import("../runtime/audit.ts");
    await new Audit({ query: (sql, values) => pool.query(sql, values) }, () => undefined).sweep(365);
    expect((await pool.query(`SELECT count(*)::int AS n FROM "_rizo_audit" WHERE "detail" = 'old'`)).rows[0].n).toBe(0);
    expect((await pool.query(`SELECT count(*)::int AS n FROM "_rizo_audit"`)).rows[0].n).toBeGreaterThan(10);
  });

  it("never leaks passwords, hashes or emails in responses or logs", () => {
    const everything = [...responses, ...logs].join("\n");
    for (const secret of [ALICE.password, BOB.password, CAROL.password, CAROL_NEW, "daves long password", "scrypt$", "alice@example.com", "Alice@Example.com", BOB.email, "password_hash"]) {
      expect(everything).not.toContain(secret);
    }
    // Emailed tokens appear only in the emails, never in responses or logs.
    for (const email of mail) {
      const token = /#token=([A-Za-z0-9_-]{43})/.exec(email.text)?.[1];
      if (token !== undefined) expect(logs.join("\n")).not.toContain(token);
    }
    // Logs name the route pattern, never the concrete URL or body.
    expect(logs.some((l) => l.startsWith("PATCH /api/posts/:id 200"))).toBe(true);
    expect(logs.join("\n")).not.toContain(postId);
    expect(logs.join("\n")).not.toContain("DROP TABLE");
  });
});
