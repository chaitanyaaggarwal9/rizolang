import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { dummyHash, hashPassword, verifyPassword } from "../runtime/password.ts";
import { RateLimiter } from "../runtime/ratelimit.ts";
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

describe("rate limiting", () => {
  it("blocks after the limit until the window passes", () => {
    let now = 0;
    const rl = new RateLimiter(2, 1000, () => now);
    rl.hit("k");
    expect(rl.retryAfter("k")).toBe(0);
    rl.hit("k");
    expect(rl.retryAfter("k")).toBe(1);
    expect(rl.retryAfter("other")).toBe(0);
    now = 1000;
    expect(rl.retryAfter("k")).toBe(0);
    rl.hit("k");
    rl.reset("k");
    expect(rl.retryAfter("k")).toBe(0);
  });
});

describe("request handling without a database", () => {
  let server: Server | undefined;
  afterEach(async () => {
    await new Promise((r) => server?.close(r));
  });

  const app: App = {
    auth: null,
    routes: [
      {
        method: "GET", pattern: "/things/:id", path: [{ static: "things" }, { param: "id", kind: "ID" }],
        access: "public", body: null, sql: "SELECT 1", values: [{ from: "path", name: "id" }],
        result: "one", publicKeys: ["id", "name"], model: "Thing",
      },
      {
        method: "GET", pattern: "/things/new", path: [{ static: "things" }, { static: "new" }],
        access: "public", body: null, sql: "SELECT 2", values: [], result: "one", publicKeys: ["id"], model: "Thing",
      },
      {
        method: "GET", pattern: "/mine", path: [{ static: "mine" }],
        access: "login", body: null, sql: "SELECT 3", values: [{ from: "me" }], result: "list", publicKeys: ["id"], model: "Thing",
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
    expect(seen).toEqual(["SELECT 2"]);
  });

  it("requires a session before running login-only queries", async () => {
    const seen: string[] = [];
    const base = await start({ query: async (sql) => (seen.push(sql), { rows: [], rowCount: 0 }) });
    const r = await fetch(`${base}/mine`);
    expect(r.status).toBe(401);
    expect(seen).toEqual([]);
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
