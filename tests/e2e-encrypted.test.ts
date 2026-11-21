/**
 * End-to-end tests for encrypted fields against PostgreSQL: the database only
 * ever holds ciphertext, the API returns plain values, and keys can rotate.
 * Runs only when RIZO_TEST_DATABASE_URL is set.
 */
import { randomBytes } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Email } from "../runtime/email.ts";
import { parseKeys } from "../runtime/encryption.ts";
import { reencrypt } from "../runtime/reencrypt.ts";
import { createRequestHandler } from "../runtime/server.ts";
import type { App } from "../runtime/types.ts";
import { buildApp } from "../src/emit/routes.js";
import { compileOk } from "./helpers.js";

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];
const schema = `rizo_enc_${randomBytes(6).toString("hex")}`;
const KEY_1 = `k1:${randomBytes(32).toString("base64")}`;
const KEY_2 = `k2:${randomBytes(32).toString("base64")}`;

const SOURCE = `auth User by email
model User {
  email: Email unique private
  password: Password
  name: Text
  phone: Text optional encrypted max 30
  displayName: Text optional
}
model Note {
  owner: User
  title: Text max 100
  secret: Text encrypted max 200
  amount: Number optional encrypted min 0
  due: Date optional encrypted
}
api POST /api/notes -> Note.public {
  requires login
  return db.Note.create(body, owner = me)
}
api GET /api/notes/:id -> Note.public {
  requires login
  requires owner owner
  return db.Note.find(id)
}
api GET /api/notes -> list Note.public {
  requires login
  return db.Note.list(owner = me, order title)
}
api PATCH /api/notes/:id -> Note.public {
  requires login
  requires owner owner
  return db.Note.update(id, body)
}
`;

describe.skipIf(DATABASE_URL === undefined)("encrypted fields end to end (PostgreSQL)", () => {
  let pool: pg.Pool;
  let app: App;
  const servers: Server[] = [];
  const mail: Email[] = [];
  const logs: string[] = [];
  let cookie = "";
  let noteId = "";

  async function start(keys: string): Promise<string> {
    const handler = createRequestHandler(app, {
      db: { query: (sql, values) => pool.query(sql, values) },
      log: (line) => logs.push(line),
      mailer: async (email) => {
        mail.push(email);
      },
      publicUrl: "https://notes.example",
      encryptionKeys: parseKeys(keys),
    });
    const server = createServer((req, res) => void handler(req, res));
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  async function call(base: string, method: string, path: string, body?: unknown): Promise<{ status: number; body: Record<string, unknown>; cookie?: string }> {
    const headers: Record<string, string> = { Cookie: cookie };
    if (body !== undefined) headers["Content-Type"] = "application/json";
    const r = await fetch(base + path, { method, headers, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) });
    const text = await r.text();
    const set = r.headers.get("set-cookie")?.split(";")[0];
    return { status: r.status, body: text === "" ? {} : JSON.parse(text), ...(set !== undefined ? { cookie: set } : {}) };
  }

  let base = "";

  beforeAll(async () => {
    const result = compileOk(SOURCE);
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.end();
    pool = new pg.Pool({ connectionString: DATABASE_URL, options: `-c search_path="${schema}",public` });
    await pool.query(result.output.sql);
    app = buildApp(result.apis, result.auth, result.pages);
    base = await start(KEY_1);

    const account = { email: "enc@example.com", password: "a long enough password", name: "Enc", phone: "+1 555 0100", displayName: "Enc E." };
    expect((await call(base, "POST", "/auth/signup", account)).status).toBe(202);
    const token = /#token=([A-Za-z0-9_-]{43})/.exec(mail.at(-1)?.text ?? "")?.[1];
    expect((await call(base, "POST", "/auth/verify-email", { token })).status).toBe(204);
    cookie = (await call(base, "POST", "/auth/login", { email: account.email, password: account.password })).cookie ?? "";
  });

  afterAll(async () => {
    for (const s of servers) await new Promise((resolve) => s.close(resolve));
    await pool?.query(`DROP SCHEMA "${schema}" CASCADE`);
    await pool?.end();
  });

  it("returns plain values, while the database holds only ciphertext", async () => {
    const r = await call(base, "POST", "/api/notes", { title: "Bank", secret: "PIN is 4321", amount: 1500, due: "2026-12-31T00:00:00Z" });
    expect(r.status).toBe(201);
    expect(r.body).toMatchObject({ title: "Bank", secret: "PIN is 4321", amount: 1500, due: "2026-12-31T00:00:00.000Z" });
    noteId = String(r.body["id"]);
    const row = (await pool.query('SELECT "title", "secret", "amount", "due" FROM "notes" WHERE "id" = $1', [noteId])).rows[0];
    expect(row.title).toBe("Bank");
    for (const column of ["secret", "amount", "due"]) {
      expect(row[column]).toMatch(/^rz1\.k1\./);
    }
    const dump = JSON.stringify((await pool.query('SELECT * FROM "notes"')).rows);
    for (const plain of ["4321", "1500", "2026-12-31"]) expect(dump).not.toContain(plain);
  });

  it("decrypts in find and list, and on the account", async () => {
    expect((await call(base, "GET", `/api/notes/${noteId}`)).body).toMatchObject({ secret: "PIN is 4321", amount: 1500 });
    expect((await call(base, "GET", "/api/notes")).body["items"]).toMatchObject([{ secret: "PIN is 4321" }]);
    expect((await call(base, "GET", "/auth/me")).body).toMatchObject({ name: "Enc", phone: "+1 555 0100", displayName: "Enc E." });
    const phone = (await pool.query('SELECT "phone" FROM "users"')).rows[0].phone;
    expect(phone).toMatch(/^rz1\.k1\./);
  });

  it("encrypts updates, keeps fields that weren't sent, and stores null as null", async () => {
    const r = await call(base, "PATCH", `/api/notes/${noteId}`, { secret: "PIN is 9999", amount: null });
    expect(r.body).toMatchObject({ secret: "PIN is 9999", amount: null, due: "2026-12-31T00:00:00.000Z" });
    const row = (await pool.query('SELECT "secret", "amount" FROM "notes" WHERE "id" = $1', [noteId])).rows[0];
    expect(row.secret).toMatch(/^rz1\.k1\./);
    expect(row.amount).toBeNull();
    expect((await call(base, "PATCH", "/auth/me", { phone: "+44 20 7946 0000" })).body).toMatchObject({ phone: "+44 20 7946 0000" });
  });

  it("still validates the plain value", async () => {
    const long = await call(base, "POST", "/api/notes", { title: "x", secret: "s".repeat(201) });
    expect(long).toMatchObject({ status: 400, body: { error: { field: "secret" } } });
    const negative = await call(base, "POST", "/api/notes", { title: "x", secret: "s", amount: -1 });
    expect(negative).toMatchObject({ status: 400, body: { error: { field: "amount" } } });
  });

  it("refuses a ciphertext moved into another column, without leaking anything", async () => {
    await pool.query('UPDATE "notes" SET "secret" = (SELECT "phone" FROM "users" LIMIT 1) WHERE "id" = $1', [noteId]);
    const r = await call(base, "GET", `/api/notes/${noteId}`);
    expect(r.status).toBe(500);
    expect(JSON.stringify(r.body)).not.toContain("+44");
    expect(logs.some((l) => l.includes("EncryptionError") && l.includes("notes.secret"))).toBe(true);
    expect(logs.join("\n")).not.toContain("+44");
    await call(base, "PATCH", `/api/notes/${noteId}`, { secret: "PIN is 9999" });
  });

  it("rotates keys: new values use the new key, and reencrypt moves the old ones", async () => {
    const rotated = await start(`${KEY_2},${KEY_1}`);
    expect((await call(rotated, "GET", `/api/notes/${noteId}`)).body).toMatchObject({ secret: "PIN is 9999" });
    const fresh = await call(rotated, "POST", "/api/notes", { title: "New", secret: "new secret" });
    expect((await pool.query('SELECT "secret" FROM "notes" WHERE "id" = $1', [fresh.body["id"]])).rows[0].secret).toMatch(/^rz1\.k2\./);

    const db = { query: (sql: string, values: unknown[]) => pool.query(sql, values) };
    const moved = await reencrypt(app, db, parseKeys(`${KEY_2},${KEY_1}`));
    expect(moved).toEqual({ updated: 3, failed: 0 }); // the old note's secret and due (its amount is null), and the phone
    const all = (await pool.query('SELECT "secret", "due" FROM "notes"')).rows.flatMap((r) => [r.secret, r.due]).filter((v) => v !== null);
    expect(all.every((v: string) => v.startsWith("rz1.k2."))).toBe(true);

    // The old key can now be removed.
    const newOnly = await start(KEY_2);
    expect((await call(newOnly, "GET", `/api/notes/${noteId}`)).body).toMatchObject({ secret: "PIN is 9999", due: "2026-12-31T00:00:00.000Z" });
    expect((await call(newOnly, "GET", "/auth/me")).body).toMatchObject({ phone: "+44 20 7946 0000" });
  });
});
