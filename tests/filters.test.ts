import { randomBytes } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRequestHandler } from "../runtime/server.ts";
import { buildApp } from "../src/emit/routes.js";
import { buildSchema } from "../src/schema.js";
import { compileErrors, compileOk } from "./helpers.js";

const SHOP = (list: string) => `model Product {
  name: Text max 100
  priceCents: Number min 0
  launched: Date
  status: Number
  note: Text optional
}
api GET /api/products -> list Product.public {
  public
  return db.Product.list(${list})
}
`;
const FULL = "priceCents >= ?min, priceCents <= ?max, name contains ?q, launched > ?since, status != 0, order priceCents";

describe("list filters", () => {
  it("compiles comparisons and optional query parameters to parameterized SQL", () => {
    const r = compileOk(SHOP(FULL));
    const route = buildApp(r.apis, r.auth).routes[0];
    expect(route?.sql).toBe(
      'SELECT "id", "name", "price_cents" AS "priceCents", "launched", "status", "note", "price_cents"::text AS "_cursor" FROM "products" WHERE ' +
        '($1::integer IS NULL OR "price_cents" >= $1::integer) AND ($2::integer IS NULL OR "price_cents" <= $2::integer) AND ' +
        '($3::text IS NULL OR strpos(lower("name"), lower($3::text)) > 0) AND ($4::timestamptz IS NULL OR "launched" > $4::timestamptz) AND ' +
        '"status" IS DISTINCT FROM $5 AND ' +
        '($6 IS NOT TRUE OR ("price_cents", "id") > ($7::integer, $8::uuid)) ORDER BY "price_cents" ASC, "id" ASC LIMIT $9',
    );
    expect(route?.query).toEqual([
      { name: "min", kind: "Number" }, { name: "max", kind: "Number" }, { name: "q", kind: "Text" }, { name: "since", kind: "Date" },
    ]);
    expect(route?.values.slice(0, 5)).toEqual([
      { from: "query", name: "min" }, { from: "query", name: "max" }, { from: "query", name: "q" }, { from: "query", name: "since" }, { from: "const", value: 0 },
    ]);
  });

  it("keeps = filters exactly as before", () => {
    const r = compileOk(SHOP("status = 1"));
    expect(buildApp(r.apis, r.auth).routes[0]?.sql).toContain('WHERE "status" = $1 AND');
    expect(buildApp(r.apis, r.auth).routes[0]).not.toHaveProperty("query");
  });

  it("indexes = columns then the sort column (so the index gives the order), or = columns then ranges without a sort", () => {
    const r = compileOk(SHOP("status = 1, priceCents >= ?min, name contains ?q, note != ?n, order launched"));
    const table = buildSchema(r.models, r.auth, true, r.apis).tables.find((t) => t.name === "products");
    expect(table?.indexes?.map((i) => i.columns)).toEqual([["status", "launched", "id"]]);
    const unsorted = compileOk(SHOP("status = 1, priceCents >= ?min, name contains ?q"));
    expect(buildSchema(unsorted.models, unsorted.auth, true, unsorted.apis).tables.find((t) => t.name === "products")?.indexes?.map((i) => i.columns))
      .toEqual([["status", "price_cents", "id"]]);
  });

  it("describes the query parameters in openapi.json", () => {
    const doc = JSON.parse(compileOk(SHOP(FULL)).output.server?.openapi ?? "{}");
    const params = doc.paths["/api/products"].get.parameters as { name: string; schema: Record<string, unknown>; description: string }[];
    expect(params.map((p) => p.name)).toEqual(["min", "max", "q", "since", "limit", "after"]);
    expect(params[2]).toMatchObject({ schema: { type: "string", minLength: 1, maxLength: 200 } });
    expect(params[3]?.schema).toEqual({ type: "string", format: "date-time" });
    expect(params[0]?.description).toContain("priceCents >= min");
  });

  it.each([
    ["contains on a Number", "priceCents contains ?q", '"contains" works on Text and Email', "Use = "],
    ["contains with a fixed value", "status = 1, name contains 5", '"contains" needs text from the request', "name contains ?q"],
    ["> on Text", "name > ?q", '">" works on Number and Date', "Use = or !="],
    ["the same filter twice", "status != 1, status != 2", '"status !=" appears more than once', "Remove the duplicate"],
    ["a page parameter name", "status = ?limit", "?limit is used for pages", "another name"],
    ["one name with two types", "priceCents >= ?x, name contains ?x", "?x is used as both Number and Text", "different name"],
  ])("refuses %s, with a fix", (_label, list, message, fix) => {
    const e = compileErrors(SHOP(list)).find((d) => d.code === "RZ0325");
    expect(e?.message).toContain(message);
    expect(e?.fix).toContain(fix);
  });

  it("treats a path parameter used with contains as plain text, not a full email address", () => {
    const r = compileOk("model Person {\n  email: Email\n}\napi GET /api/people/search/:q -> list Person.public {\n  public\n  return db.Person.list(email contains q)\n}\n");
    expect(buildApp(r.apis, r.auth).routes[0]?.path).toContainEqual({ param: "q", kind: "Text" });
  });

  it("allows text compared with = up to the field's own length", () => {
    const r = compileOk("model Doc {\n  title: Text max 500\n}\napi GET /api/docs -> list Doc.public {\n  public\n  return db.Doc.list(title = ?t)\n}\n");
    expect(buildApp(r.apis, r.auth).routes[0]?.query).toEqual([{ name: "t", kind: "Text", max: 500 }]);
  });

  it("allows query parameters only in list filters", () => {
    const e = compileErrors(`model Note {\n  title: Text\n}\napi POST /api/notes -> Note.public {\n  public\n  return db.Note.create(body, title = ?t)\n}\n`)
      .find((d) => d.code === "RZ0325");
    expect(e?.message).toContain("can only filter lists");
    const op = compileErrors(`model Note {\n  title: Text\n  n: Number\n}\napi POST /api/notes -> Note.public {\n  public\n  return db.Note.create(body, n > 1)\n}\n`)
      .find((d) => d.code === "RZ0325");
    expect(op?.message).toContain('create sets fields with "="');
  });
});

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];

describe.skipIf(DATABASE_URL === undefined)("list filters in PostgreSQL", () => {
  const schema = `rizo_filters_${randomBytes(6).toString("hex")}`;
  let pool: pg.Pool;
  let server: Server;
  let base = "";

  beforeAll(async () => {
    const r = compileOk(SHOP(FULL));
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.end();
    pool = new pg.Pool({ connectionString: DATABASE_URL, options: `-c search_path="${schema}",public` });
    await pool.query(r.output.sql);
    const rows: [string, number, string, number][] = [
      ["Blue Mug", 1200, "2026-01-10T00:00:00Z", 1],
      ["Red mug", 900, "2026-03-01T00:00:00Z", 1],
      ["Teapot 100%_off", 5000, "2026-05-01T00:00:00Z", 1],
      ["Old Mug", 800, "2025-06-01T00:00:00Z", 0],
    ];
    for (const [name, price, launched, status] of rows) {
      await pool.query(`INSERT INTO "products" ("name", "price_cents", "launched", "status") VALUES ($1, $2, $3, $4)`, [name, price, launched, status]);
    }
    const handler = createRequestHandler(buildApp(r.apis, r.auth), { db: { query: (sql, values) => pool.query(sql, values) }, log: () => undefined });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
    await pool?.query(`DROP SCHEMA "${schema}" CASCADE`);
    await pool?.end();
  });

  const names = async (query: string) => {
    const r = await fetch(`${base}/api/products${query}`);
    return { status: r.status, body: (await r.json()) as { items?: { name: string }[]; error?: { field?: string } } };
  };

  it("skips filters whose parameter is left out", async () => {
    expect((await names("")).body.items?.map((x) => x.name)).toEqual(["Red mug", "Blue Mug", "Teapot 100%_off"]);
  });

  it("applies each filter given, combined", async () => {
    expect((await names("?q=MUG")).body.items?.map((x) => x.name)).toEqual(["Red mug", "Blue Mug"]);
    expect((await names("?min=1000&max=6000")).body.items?.map((x) => x.name)).toEqual(["Blue Mug", "Teapot 100%_off"]);
    expect((await names("?since=2026-02-01T00:00:00Z&q=mug")).body.items?.map((x) => x.name)).toEqual(["Red mug"]);
  });

  it("treats % and _ in a search as plain characters", async () => {
    expect((await names("?q=%25")).body.items?.map((x) => x.name)).toEqual(["Teapot 100%_off"]);
    expect((await names("?q=_")).body.items?.map((x) => x.name)).toEqual(["Teapot 100%_off"]);
  });

  it("keeps pages working with filters", async () => {
    const first = await fetch(`${base}/api/products?q=mug&limit=1`).then((r) => r.json()) as { items: { name: string }[]; next: string };
    expect(first.items.map((x) => x.name)).toEqual(["Red mug"]);
    const second = await fetch(`${base}/api/products?q=mug&limit=1&after=${encodeURIComponent(first.next)}`).then((r) => r.json()) as { items: { name: string }[] };
    expect(second.items.map((x) => x.name)).toEqual(["Blue Mug"]);
  });

  it("rejects invalid or unknown parameters before any query runs", async () => {
    expect(await names("?min=cheap")).toMatchObject({ status: 400, body: { error: { field: "min" } } });
    expect(await names("?since=yesterday")).toMatchObject({ status: 400, body: { error: { field: "since" } } });
    expect(await names(`?q=${"x".repeat(201)}`)).toMatchObject({ status: 400, body: { error: { field: "q" } } });
    // An empty value, as a search box sends, counts as left out.
    expect((await names("?q=&min=")).body.items?.map((x) => x.name)).toEqual(["Red mug", "Blue Mug", "Teapot 100%_off"]);
    expect((await names("?price=1")).status).toBe(400);
    expect((await names("?q=a&q=b")).status).toBe(400);
    expect((await names("?q=' OR 1=1 --")).body.items).toEqual([]);
  });
});
