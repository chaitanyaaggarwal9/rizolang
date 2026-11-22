import { randomBytes } from "node:crypto";
import { type Server, createServer } from "node:http";
import type { AddressInfo } from "node:net";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseKeys } from "../runtime/encryption.ts";
import { createRequestHandler } from "../runtime/server.ts";
import { buildApp } from "../src/emit/routes.js";
import { compileErrors, compileOk } from "./helpers.js";

const BLOG = (ret: string, extraApis = "") => `model Person {
  name: Text max 100
  email: Email unique private
  phone: Text optional encrypted
}
model Post {
  author: Person
  editor: Person optional
  secretSource: Person optional private
  title: Text
}
api GET /api/posts -> ${ret} {
  public
  return db.Post.list(order title)
}
${extraApis}`;

describe("returning linked records (with)", () => {
  it("adds each linked record's public fields to the same query, by primary key", () => {
    const r = compileOk(BLOG("list Post.public with author, editor"));
    const route = buildApp(r.apis, r.auth).routes[0];
    expect(route?.sql).toBe(
      'SELECT "posts"."id", ' +
        '(SELECT jsonb_build_object(\'id\', "l1"."id", \'name\', "l1"."name", \'phone\', "l1"."phone") FROM "persons" AS "l1" WHERE "l1"."id" = "posts"."author_id") AS "author", ' +
        '(SELECT jsonb_build_object(\'id\', "l2"."id", \'name\', "l2"."name", \'phone\', "l2"."phone") FROM "persons" AS "l2" WHERE "l2"."id" = "posts"."editor_id") AS "editor", ' +
        '"posts"."title" AS "title", "title"::text AS "_cursor" FROM "posts" WHERE ($1 IS NOT TRUE OR ("title", "id") > ($2::text, $3::uuid)) ORDER BY "title" ASC, "id" ASC LIMIT $4',
    );
    expect(route?.sql).not.toContain('"email"');
    expect(route?.expanded).toEqual([
      { key: "author", publicKeys: ["id", "name", "phone"], encrypted: [{ key: "phone", aad: "persons.phone" }] },
      { key: "editor", publicKeys: ["id", "name", "phone"], encrypted: [{ key: "phone", aad: "persons.phone" }] },
    ]);
  });

  it("formats linked dates like top-level ones, and builds large records in parts", () => {
    const many = Array.from({ length: 60 }, (_, i) => `  f${i}: Text optional`).join("\n");
    const r = compileOk(`model Big {\n  born: Date\n${many}\n}\nmodel Ref {\n  big: Big\n}\napi GET /api/refs -> list Ref.public with big {\n  public\n  return db.Ref.list()\n}\n`);
    const sql = buildApp(r.apis, r.auth).routes[0]?.sql ?? "";
    expect(sql).toContain(`to_char("l1"."born" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')`);
    expect(sql.match(/jsonb_build_object\(/g)?.length).toBe(2);
    for (const part of sql.split("jsonb_build_object(").slice(1)) expect(part.split(")")[0]?.split(", ").length ?? 0).toBeLessThanOrEqual(100);
  });

  it("leaves endpoints without with exactly as before", () => {
    const r = compileOk(BLOG("list Post.public"));
    expect(buildApp(r.apis, r.auth).routes[0]?.sql).toMatch(/^SELECT "id", "author_id" AS "author"/);
    expect(buildApp(r.apis, r.auth).routes[0]).not.toHaveProperty("expanded");
  });

  it.each([
    ["a field that isn't a link", "list Post.public with title", '"title" is not a link field', "author, editor"],
    ["a private link", "list Post.public with secretSource", "is private", "author, editor"],
    ["the same link twice", "list Post.public with author, author", "listed twice", "Remove the duplicate"],
  ])("refuses %s (RZ0343), with a fix", (_label, ret, message, fix) => {
    const e = compileErrors(BLOG(ret)).find((d) => d.code === "RZ0343");
    expect(e?.message).toContain(message);
    expect(e?.fix).toContain(fix);
  });

  it("refuses with on endpoints that change records", () => {
    const e = compileErrors(BLOG("list Post.public", "api POST /api/posts -> Post.public with author {\n  public\n  return db.Post.create(body)\n}\n"))
      .find((d) => d.code === "RZ0343");
    expect(e?.message).toContain("find and list");
  });

  it("describes the linked record in openapi.json", () => {
    const doc = JSON.parse(compileOk(BLOG("list Post.public with author, editor")).output.server?.openapi ?? "{}");
    const schema = doc.components.schemas.PostPublicWithAuthorAndEditor;
    expect(schema.properties.author).toEqual({ $ref: "#/components/schemas/PersonPublic" });
    expect(schema.properties.editor).toEqual({ anyOf: [{ $ref: "#/components/schemas/PersonPublic" }, { type: "null" }] });
    expect(Object.keys(doc.components.schemas.PersonPublic.properties)).toEqual(["id", "name", "phone"]);
    expect(doc.paths["/api/posts"].get.responses["200"].content["application/json"].schema.properties.items.items).toEqual({ $ref: "#/components/schemas/PostPublicWithAuthorAndEditor" });
  });

  it("shows the linked record's first text field on pages", () => {
    const r = compileOk(`${BLOG("list Post.public with author")}page / {\n  public\n  show GET /api/posts\n}\n`);
    const show = buildApp(r.apis, r.auth, r.pages).pages[0]?.items[0];
    expect(show).toMatchObject({ kind: "show" });
    const fields = (show as unknown as { fields: { key: string; display?: string }[] }).fields;
    expect(fields.find((f) => f.key === "author")?.display).toBe("name");
    expect(fields.find((f) => f.key === "editor")?.display).toBeUndefined();
  });
});

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];

describe.skipIf(DATABASE_URL === undefined)("linked records in PostgreSQL", () => {
  const schema = `rizo_links_${randomBytes(6).toString("hex")}`;
  let pool: pg.Pool;
  let server: Server;
  let base = "";

  beforeAll(async () => {
    const r = compileOk(BLOG("list Post.public with author, editor", "api GET /api/posts/:id -> Post.public with author {\n  public\n  return db.Post.find(id)\n}\n"));
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.end();
    pool = new pg.Pool({ connectionString: DATABASE_URL, options: `-c search_path="${schema}",public` });
    await pool.query(r.output.sql);
    const keys = parseKeys(`k1:${randomBytes(32).toString("base64")}`);
    const { encryptValue } = await import("../runtime/encryption.ts");
    const ann = (await pool.query(`INSERT INTO "persons" ("name", "email", "phone") VALUES ('Ann', 'ann@example.com', $1) RETURNING "id"`, [encryptValue(keys, "persons.phone", "+1 555 0100")])).rows[0].id;
    await pool.query(`INSERT INTO "posts" ("author_id", "title") VALUES ($1, 'Hello')`, [ann]);
    const handler = createRequestHandler(buildApp(r.apis, r.auth), { db: { query: (sql, values) => pool.query(sql, values) }, log: () => undefined, encryptionKeys: keys });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => server?.close(resolve));
    await pool?.query(`DROP SCHEMA "${schema}" CASCADE`);
    await pool?.end();
  });

  it("returns the linked record's public fields, decrypted, and null for an empty optional link", async () => {
    const list = await (await fetch(`${base}/api/posts`)).json() as { items: Record<string, unknown>[] };
    const post = list.items[0] as { id: string; author: Record<string, unknown>; editor: unknown };
    expect(post.author).toEqual({ id: expect.any(String), name: "Ann", phone: "+1 555 0100" });
    expect(post.editor).toBeNull();
    expect(JSON.stringify(list)).not.toContain("ann@example.com");
    expect(Object.keys(post).sort()).toEqual(["author", "editor", "id", "title"]);
    const one = await (await fetch(`${base}/api/posts/${post.id}`)).json() as { author: { name: string } };
    expect(one.author.name).toBe("Ann");
  });
});
