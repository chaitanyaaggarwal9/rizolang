import { randomBytes } from "node:crypto";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { expireRecords } from "../runtime/privacy.ts";
import { buildApp } from "../src/emit/routes.js";
import { lex } from "../src/lexer.js";
import { planMigration } from "../src/migrations.js";
import { buildSchema } from "../src/schema.js";
import { compileErrors, compileOk, firstError } from "./helpers.js";

const ACCOUNTS = "auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n}\n";
const NOTES = (keep: string) => `${ACCOUNTS}model Note {
  owner: User
  title: Text
${keep}
}
api GET /api/notes -> list Note.public {
  requires login
  return db.Note.list(owner = me)
}
`;

describe("privacy for", () => {
  it("reads region codes such as US-CA as one word", () => {
    const r = lex("privacy for EU, US-CA, BR", "a.rz");
    expect(r.ok && r.tokens.filter((t) => t.kind === "ident").map((t) => t.text)).toEqual(["privacy", "for", "EU", "US-CA", "BR"]);
  });

  it("accepts the supported regions, in any order", () => {
    expect(compileOk(`privacy for EU, UK, IN, US-CA, BR\n${ACCOUNTS}`).privacy).toEqual(["EU", "UK", "IN", "US-CA", "BR"]);
    expect(compileOk(`${ACCOUNTS}privacy for BR\n`).privacy).toEqual(["BR"]);
    expect(compileOk(ACCOUNTS).privacy).toBeUndefined();
  });

  it("is included in the route data", () => {
    const r = compileOk(`privacy for IN, EU\n${ACCOUNTS}`);
    expect(buildApp(r.apis, r.auth, [], r.models, r.privacy).privacy).toEqual(["IN", "EU"]);
  });

  it.each([
    ["an unknown region", `privacy for EU, FR\n${ACCOUNTS}`, "RZ0341", "Use one or more of: EU, UK, IN, US-CA, BR."],
    ["a region in the wrong case", `privacy for eu\n${ACCOUNTS}`, "RZ0341", 'Write "EU".'],
    ["a repeated region", `privacy for EU, EU\n${ACCOUNTS}`, "RZ0341", "Remove the duplicate."],
    ["two privacy lines", `privacy for EU\nprivacy for UK\n${ACCOUNTS}`, "RZ0341", "on one line"],
    ["no accounts", "privacy for EU\nmodel Note {\n  title: Text\n}\n", "RZ0341", "Add an auth line"],
    ["no for", `privacy EU\n${ACCOUNTS}`, "RZ0223", "privacy for EU"],
    ["a trailing comma", `privacy for EU,\n${ACCOUNTS}`, "RZ0223", "privacy for EU"],
  ])("refuses %s", (_label, source, code, fix) => {
    const e = firstError(source);
    expect(e.code).toBe(code);
    expect(e.fix).toContain(fix);
  });
});

describe("keep", () => {
  it("reads days, months and years, singular or plural", () => {
    for (const [text, keep] of [["keep 30 days", { amount: 30, unit: "days" }], ["keep 1 year", { amount: 1, unit: "years" }], ["keep 6 months", { amount: 6, unit: "months" }]] as const) {
      expect(compileOk(NOTES(`  ${text}`)).models.find((m) => m.name === "Note")?.keep).toEqual(keep);
    }
  });

  it("still allows a field named keep", () => {
    expect(compileOk(NOTES("  keep: Bool")).models.find((m) => m.name === "Note")?.keep).toBeUndefined();
  });

  it.each([
    ["an unknown unit", NOTES("  keep 2 weeks"), "RZ0342", "days, months or years"],
    ["zero", NOTES("  keep 0 days"), "RZ0342", "from 1 to 36500 days"],
    ["more than 100 years", NOTES("  keep 101 years"), "RZ0342", "from 1 to 100 years"],
    ["two keep lines", NOTES("  keep 1 year\n  keep 2 years"), "RZ0342", "one `keep"],
    ["the account model", `auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  keep 1 year\n}\n`, "RZ0342", "Remove the keep line"],
    ["a file with no server", "model Note {\n  title: Text\n  keep 1 year\n}\n", "RZ0342", "Add the api or page blocks"],
    ["a missing number", NOTES("  keep years"), "RZ0223", "keep 2 years"],
  ])("refuses %s", (_label, source, code, fix) => {
    const e = compileErrors(source).find((d) => d.code === code);
    expect(e?.fix).toContain(fix);
  });

  it("adds a hidden, indexed creation time, which existing rows get on migration", () => {
    const r = compileOk(NOTES("  keep 30 days"));
    const table = buildSchema(r.models, r.auth, true, r.apis).tables.find((t) => t.name === "notes");
    expect(table?.columns.find((c) => c.name === "_created_at")).toMatchObject({ type: "TIMESTAMPTZ", default: "now()", notNull: true });
    expect(table?.indexes?.map((i) => i.columns)).toContainEqual(["_created_at"]);
    const before = compileOk(NOTES(""));
    const plan = planMigration(buildSchema(before.models, before.auth, true, before.apis), buildSchema(r.models, r.auth, true, r.apis));
    expect(plan.statements).toContain('ALTER TABLE "notes" ADD COLUMN "_created_at" TIMESTAMPTZ DEFAULT now() NOT NULL;');
    expect(plan.dataLoss).toEqual([]);
  });

  it("deletes expired records in batches, skipping records that others still need", () => {
    const r = compileOk(`${NOTES("  keep 30 days")}model Pin {\n  note: Note\n}\nmodel Tag {\n  note: Note optional\n}\n`);
    expect(buildApp(r.apis, r.auth, [], r.models).retention).toEqual([{
      model: "Note",
      amount: 30,
      sql: 'DELETE FROM "notes" WHERE "id" IN (SELECT "r"."id" FROM "notes" AS "r" WHERE "r"."_created_at" < now() - make_interval(days => $1) AND NOT EXISTS (SELECT 1 FROM "pins" WHERE "pins"."note_id" = "r"."id") ORDER BY "r"."_created_at" LIMIT 1000)',
    }]);
  });
});

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];

describe.skipIf(DATABASE_URL === undefined)("keep in PostgreSQL", () => {
  const schema = `rizo_keep_${randomBytes(6).toString("hex")}`;
  let pool: pg.Pool;
  const source = `${NOTES("  keep 30 days")}model Pin {\n  note: Note\n}\n`;

  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE SCHEMA "${schema}"`);
    await admin.end();
    pool = new pg.Pool({ connectionString: DATABASE_URL, options: `-c search_path="${schema}",public` });
    await pool.query(compileOk(source).output.sql);
  });

  afterAll(async () => {
    await pool?.query(`DROP SCHEMA "${schema}" CASCADE`);
    await pool?.end();
  });

  it("deletes only expired records that nothing needs, and reports how many", async () => {
    const user = (await pool.query(`INSERT INTO "users" ("email", "password_hash") VALUES ('k@example.com', 'x') RETURNING "id"`)).rows[0].id;
    const add = async (title: string, age: string) =>
      (await pool.query(`INSERT INTO "notes" ("owner_id", "title", "_created_at") VALUES ($1, $2, now() - $3::interval) RETURNING "id"`, [user, title, age])).rows[0].id;
    await add("old", "31 days");
    const pinned = await add("old but pinned", "40 days");
    await add("recent", "29 days");
    await pool.query(`INSERT INTO "pins" ("note_id") VALUES ($1)`, [pinned]);
    for (let i = 0; i < 1500; i++) await add(`bulk ${i}`, "1 year");

    const r = compileOk(source);
    const app = buildApp(r.apis, r.auth, r.pages, r.models);
    const done = await expireRecords(app, { query: (sql, values) => pool.query(sql, values) });
    expect(done).toEqual([{ model: "Note", deleted: 1501 }]);
    const left = (await pool.query(`SELECT "title" FROM "notes" ORDER BY "title"`)).rows.map((x) => x.title);
    expect(left).toEqual(["old but pinned", "recent"]);
    expect(await expireRecords(app, { query: (sql, values) => pool.query(sql, values) })).toEqual([]);
  });
});
