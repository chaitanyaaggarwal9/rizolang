import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { BusyError, dummyHash, hashPassword, verifyPassword } from "../runtime/password.ts";
import { LIMIT_SQL, Limits, limitKey } from "../runtime/limits.ts";
import { type Db, createRequestHandler } from "../runtime/server.ts";
import { SESSIONS_TABLE, clearedCookie, hashToken, newToken, readToken, sessionCookie } from "../runtime/session.ts";
import type { App, FieldSpec } from "../runtime/types.ts";
import { validateBody, validatePathParam, validateValue } from "../runtime/validate.ts";
import { SESSIONS_TABLE as COMPILER_SESSIONS_TABLE } from "../src/emit/sql.js";

const spec = (over: Partial<FieldSpec> & Pick<FieldSpec, "key" | "kind">): FieldSpec => ({ required: true, nullable: false, ...over });

describe("validation", () => {
  it.each([
    [{ key: "t", kind: "Text", max: 3 }, "abc", "abc"],
    [{ key: "t", kind: "Text", max: 3 }, "😀😀😀", "😀😀😀"],
    [{ key: "e", kind: "Email" }, "  Ann@Example.COM ", "ann@example.com"],
    [{ key: "n", kind: "Number", min: 0 }, 0, 0],
    [{ key: "b", kind: "Bool" }, false, false],
    [{ key: "i", kind: "ID" }, "8D3F1A2B-0000-4000-8000-000000000000", "8d3f1a2b-0000-4000-8000-000000000000"],
  ] as const)("accepts %j = %j", (s, raw, value) => {
    expect(validateValue(s, raw)).toEqual({ value });
  });

  it.each([
    [{ key: "t", kind: "Text", max: 3 }, "abcd"],
    [{ key: "t", kind: "Text" }, 5],
    [{ key: "t", kind: "Text" }, "a\u0000b"],
    [{ key: "e", kind: "Email" }, "not-an-email"],
    [{ key: "n", kind: "Number" }, 1.5],
    [{ key: "n", kind: "Number" }, "5"],
    [{ key: "n", kind: "Number" }, 2 ** 31],
    [{ key: "n", kind: "Number", min: 0 }, -1],
    [{ key: "b", kind: "Bool" }, "true"],
    [{ key: "d", kind: "Date" }, "2026-02-30T10:00"],
    [{ key: "d", kind: "Date" }, "yesterday"],
    [{ key: "i", kind: "ID" }, "1 OR 1=1"],
  ] as const)("rejects %j = %j", (s, raw) => {
    expect(validateValue(s, raw)).toHaveProperty("error");
  });

  it("parses ISO dates with a time zone", () => {
    const r = validateValue({ key: "d", kind: "Date" }, "2026-01-31T12:00:00Z");
    expect(r).toEqual({ value: new Date("2026-01-31T12:00:00Z") });
  });

  it("validates whole bodies: required, null, unknown keys, non-objects", () => {
    const specs = [spec({ key: "title", kind: "Text" }), spec({ key: "views", kind: "Number", required: false, nullable: true })];
    expect(validateBody(specs, { title: "x" })).toMatchObject({ ok: true });
    expect(validateBody(specs, { title: "x", views: null })).toMatchObject({ ok: true });
    expect(validateBody(specs, {})).toMatchObject({ ok: false, field: "title", message: "title is required." });
    expect(validateBody(specs, { title: null })).toMatchObject({ ok: false, message: "title cannot be null." });
    expect(validateBody(specs, { title: "x", isAdmin: true })).toMatchObject({ ok: false, field: "isAdmin" });
    expect(validateBody(specs, [])).toMatchObject({ ok: false });
    expect(validateBody(specs, null)).toMatchObject({ ok: false });
    expect(validateBody(specs, JSON.parse('{"title":"x","__proto__":{"isAdmin":true}}'))).toMatchObject({ ok: false, field: "__proto__" });
  });

  it("never echoes rejected values in messages", () => {
    const r = validateBody([spec({ key: "email", kind: "Email" })], { email: "<script>alert(1)</script>" });
    expect(JSON.stringify(r)).not.toContain("script");
  });

  it("validates path parameters by type", () => {
    expect(validatePathParam({ param: "n", kind: "Number" }, "42")).toEqual({ value: 42 });
    expect(validatePathParam({ param: "n", kind: "Number" }, "4e2")).toHaveProperty("error");
    expect(validatePathParam({ param: "b", kind: "Bool" }, "yes")).toHaveProperty("error");
    expect(validatePathParam({ param: "t", kind: "Text" }, "x".repeat(1001))).toHaveProperty("error");
  });
});

describe("passwords", () => {
  it("hashes with a random salt and verifies in constant time", async () => {
    const a = await hashPassword("correct horse battery");
    const b = await hashPassword("correct horse battery");
    expect(a).toMatch(/^scrypt\$15\$8\$3\$[A-Za-z0-9_-]{22}\$[A-Za-z0-9_-]{86}$/);
    expect(a).not.toBe(b);
    expect(await verifyPassword("correct horse battery", a)).toBe(true);
    expect(await verifyPassword("wrong", a)).toBe(false);
  });

  it("treats tampered or hostile hashes as wrong passwords", async () => {
    const real = await hashPassword("pw-pw-pw-pw");
    for (const bad of ["", "plain", "bcrypt$x", real.replace("$15$", "$30$"), real.replace("$8$3$", "$8$999$"), real.slice(0, -4)]) {
      expect(await verifyPassword("pw-pw-pw-pw", bad)).toBe(false);
    }
    expect(await verifyPassword("anything", await dummyHash())).toBe(false);
  });
});

describe("sessions", () => {
  it("creates 256-bit tokens and stores only their hash", () => {
    const t = newToken();
    expect(t).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(hashToken(t)).toMatch(/^[0-9a-f]{64}$/);
    expect(hashToken(t)).not.toContain(t);
  });

  it("reads only well-formed session cookies", () => {
    const t = newToken();
    expect(readToken(`a=1; rizo_session=${t}; b=2`)).toBe(t);
    expect(readToken("rizo_session=short")).toBeUndefined();
    expect(readToken("rizo_session=' OR 1=1 --")).toBeUndefined();
    expect(readToken(undefined)).toBeUndefined();
  });

  it("sets hardened cookie attributes", () => {
    expect(sessionCookie("t", true)).toBe("rizo_session=t; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800");
    expect(clearedCookie(true)).toContain("Max-Age=0");
  });

  it("uses the same sessions table as the schema", () => {
    expect(SESSIONS_TABLE).toBe(`"${COMPILER_SESSIONS_TABLE}"`);
  });
});

/** A fake database that understands the rate-limit SQL, like PostgreSQL would. */
function limitDb() {
  const rows = new Map<string, number>();
  return {
    rows,
    query: async (sql: string, values: unknown[]) => {
      const key = String(values[0]);
      if (sql === LIMIT_SQL.consume) {
        rows.set(key, (rows.get(key) ?? 0) + 1);
        return { rows: [{ count: rows.get(key) }], rowCount: 1 };
      }
      if (sql === LIMIT_SQL.peek) return { rows: rows.has(key) ? [{ count: rows.get(key) }] : [], rowCount: 1 };
      if (sql === LIMIT_SQL.clear) {
        for (const k of [...rows.keys()]) if (k.startsWith(key.replace(/%$/, ""))) rows.delete(k);
        return { rows: [], rowCount: 0 };
      }
      return { rows: [], rowCount: 0 };
    },
  };
}

describe("rate limits", () => {
  it("allow up to the limit in each window, then say when to retry", async () => {
    let now = 120_000; // 2 minutes after the epoch: the start of a minute window
    const db = limitDb();
    const limits = new Limits(db, () => now);
    const key = limitKey("GET /api/posts", "ip:1.2.3.4");
    expect((await limits.consume(key, 2, 60)).allowed).toBe(true);
    expect((await limits.consume(key, 2, 60)).allowed).toBe(true);
    now += 15_000;
    expect(await limits.consume(key, 2, 60)).toEqual({ allowed: false, retryAfter: 45 });
    now += 45_000; // next window
    expect((await limits.consume(key, 2, 60)).allowed).toBe(true);
  });

  it("can check and clear without counting", async () => {
    const db = limitDb();
    const limits = new Limits(db, () => 0);
    const key = limitKey("login-account", "a@b.co");
    for (let i = 0; i < 5; i++) await limits.consume(key, 5, 900);
    expect((await limits.blocked(key, 5, 900)).allowed).toBe(false);
    await limits.clear(key);
    expect((await limits.blocked(key, 5, 900)).allowed).toBe(true);
  });

  it("never stores the identity itself", () => {
    const key = limitKey("login-ip", "203.0.113.7");
    expect(key).not.toContain("203.0.113.7");
    expect(key).toMatch(/^[0-9a-f]{16}:[0-9a-f]{32}$/);
    expect(limitKey("login-ip", "203.0.113.8")).not.toBe(key);
    expect(limitKey("signup", "203.0.113.7")).not.toBe(key);
  });
});

describe("password hashing queue", () => {
  it("answers BusyError instead of piling up work", async () => {
    const attempts = Array.from({ length: 60 }, () => hashPassword("long enough password").then(() => "ok", (e) => e));
    const results = await Promise.all(attempts);
    const busy = results.filter((r) => r instanceof BusyError).length;
    expect(busy).toBeGreaterThan(0);
    expect(results.filter((r) => r === "ok").length).toBe(60 - busy);
    // The queue drains: hashing works again afterwards.
    expect(await hashPassword("long enough password")).toMatch(/^scrypt\$/);
  }, 60_000);
});

describe("request handling without a database", () => {
  let server: Server | undefined;
  afterEach(async () => {
    await new Promise((r) => server?.close(r));
  });

  const app: App = {
    auth: null,
    pages: [],
    routes: [
      {
        method: "GET", pattern: "/things/:id", path: [{ static: "things" }, { param: "id", kind: "ID" }],
        access: "public", roles: [], body: null, sql: "SELECT 1", values: [{ from: "path", name: "id" }],
        result: "one", page: null, rateLimit: { max: 120, windowSeconds: 60 }, publicKeys: ["id", "name"], model: "Thing",
      },
      {
        method: "GET", pattern: "/things/new", path: [{ static: "things" }, { static: "new" }],
        access: "public", roles: [], body: null, sql: "SELECT 2", values: [], result: "one", page: null, rateLimit: { max: 120, windowSeconds: 60 }, publicKeys: ["id"], model: "Thing",
      },
      {
        method: "GET", pattern: "/mine", path: [{ static: "mine" }],
        access: "login", roles: [], body: null, sql: "SELECT 3", values: [{ from: "me" }], result: "list", page: { max: 50, order: null }, rateLimit: { max: 120, windowSeconds: 60 }, publicKeys: ["id"], model: "Thing",
      },
    ],
  };

  async function start(db: Db, log: string[] = []): Promise<string> {
    const handler = createRequestHandler(app, { db, log: (l) => log.push(l) });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((r) => server?.listen(0, "127.0.0.1", r));
    return `http://127.0.0.1:${(server?.address() as AddressInfo).port}`;
  }

  it("copies only public keys, even if a query returns more", async () => {
    const base = await start({ query: async () => ({ rows: [{ id: "x", name: "n", password_hash: "h", secret: "s" }], rowCount: 1 }) });
    const r = await fetch(`${base}/things/8d3f1a2b-0000-4000-8000-000000000000`);
    expect(await r.json()).toEqual({ id: "x", name: "n" });
  });

  it("prefers static segments over parameters", async () => {
    const seen: string[] = [];
    const base = await start({ query: async (sql) => (seen.push(sql), { rows: [{ id: "1" }], rowCount: 1 }) });
    await fetch(`${base}/things/new`);
    expect(seen.filter((sql) => !sql.includes("_rizo_rate_limits"))).toEqual(["SELECT 2"]);
  });

  it("requires a session before running login-only queries", async () => {
    const seen: string[] = [];
    const base = await start({ query: async (sql) => (seen.push(sql), { rows: [], rowCount: 0 }) });
    const r = await fetch(`${base}/mine`);
    expect(r.status).toBe(401);
    expect(seen).toEqual([]);
  });

  it("limits each endpoint per IP address", async () => {
    const db = limitDb();
    const limited: App = { ...app, routes: app.routes.map((r) => ({ ...r, rateLimit: { max: 2, windowSeconds: 60 } })) };
    const handler = createRequestHandler(limited, { db: { query: async (sql, values) => (sql.startsWith("INSERT INTO \"_rizo_rate") || sql.startsWith("SELECT \"count\"") ? db.query(sql, values) : { rows: [{ id: "1" }], rowCount: 1 }) }, log: () => undefined });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((r) => server?.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server?.address() as AddressInfo).port}`;
    expect((await fetch(`${base}/things/new`)).status).toBe(200);
    expect((await fetch(`${base}/things/new`)).status).toBe(200);
    const third = await fetch(`${base}/things/new`);
    expect(third.status).toBe(429);
    expect(Number(third.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("refuses writes that a browser marks as coming from another site", async () => {
    const post: App = { ...app, routes: [{ ...app.routes[1]!, method: "POST" }] };
    const handler = createRequestHandler(post, { db: { query: async () => ({ rows: [{ id: "1" }], rowCount: 1 }) }, log: () => undefined });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((r) => server?.listen(0, "127.0.0.1", r));
    const base = `http://127.0.0.1:${(server?.address() as AddressInfo).port}`;
    for (const site of ["cross-site", "same-site"]) {
      expect((await fetch(`${base}/things/new`, { method: "POST", headers: { "Sec-Fetch-Site": site } })).status, site).toBe(403);
    }
    expect((await fetch(`${base}/things/new`, { method: "POST", headers: { "Sec-Fetch-Site": "same-origin" } })).status).toBe(200);
  });

  it("hides internal errors from clients and logs them without request data", async () => {
    const log: string[] = [];
    const base = await start({ query: async () => { throw new Error("connection refused"); } }, log);
    const r = await fetch(`${base}/things/8d3f1a2b-0000-4000-8000-000000000000`);
    expect(r.status).toBe(500);
    const body = (await r.json()) as { error: { message: string } };
    expect(body.error.message).not.toContain("connection");
    expect(log.join("\n")).toContain("connection refused");
    expect(log.join("\n")).not.toContain("8d3f1a2b");
  });
});
