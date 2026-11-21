import { describe, expect, it } from "vitest";
import { initialPlan, parseSnapshot, planMigration, snapshotText } from "../src/migrations.js";
import { type Schema, buildSchema, constraintName } from "../src/schema.js";
import { compileOk } from "./helpers.js";

const schemaOf = (src: string): Schema => {
  const r = compileOk(src);
  return buildSchema(r.models, r.auth);
};

const BASE = `model User {
  email: Email unique
  name: Text max 100
}
`;
const plan = (from: string, to: string) => planMigration(schemaOf(from), schemaOf(to));

describe("migration planning", () => {
  it("creates everything in the first migration", () => {
    const p = initialPlan(schemaOf(`${BASE}model Post {\n  author: User\n}\n`));
    expect(p.slug).toBe("initial");
    expect(p.statements.filter((s) => s.startsWith("CREATE TABLE"))).toHaveLength(2);
    expect(p.statements).toContain('ALTER TABLE "posts" ADD CONSTRAINT "posts_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "users" ("id") ON DELETE RESTRICT;');
  });

  it("does nothing when nothing changed", () => {
    expect(plan(BASE, BASE).statements).toEqual([]);
  });

  it("adds optional and required fields without data loss", () => {
    const p = plan(BASE, "model User {\n  email: Email unique\n  name: Text max 100\n  bio: Text optional\n  age: Number min 0\n}\n");
    expect(p.statements).toEqual([
      'ALTER TABLE "users" ADD COLUMN "bio" TEXT CONSTRAINT "users_bio_check" CHECK (char_length("bio") <= 10000);',
      'ALTER TABLE "users" ADD COLUMN "age" INTEGER NOT NULL CONSTRAINT "users_age_check" CHECK ("age" >= 0);',
    ]);
    expect(p.dataLoss).toEqual([]);
    expect(p.slug).toBe("add_column_users_bio_and_more");
  });

  it("flags dropped fields, dropped models and type changes as data loss", () => {
    expect(plan(BASE, BASE.replace("  name: Text max 100\n", "")).dataLoss).toEqual(['column "users.name" and its values would be deleted']);
    expect(plan(`${BASE}model Tag {\n  x: Text\n}\n`, BASE).dataLoss).toEqual(['table "tags" and all its rows would be deleted']);
    const typed = plan(BASE, BASE.replace("name: Text max 100", "name: Number"));
    expect(typed.dataLoss[0]).toContain("changes type from TEXT to INTEGER");
    expect(typed.statements).toEqual(['ALTER TABLE "users" DROP COLUMN "name";', 'ALTER TABLE "users" ADD COLUMN "name" INTEGER NOT NULL;']);
  });

  it("replaces changed limits by constraint name", () => {
    const p = plan(BASE, BASE.replace("max 100", "max 200"));
    expect(p.statements).toEqual([
      'ALTER TABLE "users" DROP CONSTRAINT "users_name_check";',
      'ALTER TABLE "users" ADD CONSTRAINT "users_name_check" CHECK (char_length("name") <= 200);',
    ]);
    expect(p.dataLoss).toEqual([]);
  });

  it("adds and drops unique and required", () => {
    expect(plan(BASE, BASE.replace("Email unique", "Email")).statements).toEqual(['ALTER TABLE "users" DROP CONSTRAINT "users_email_key";']);
    expect(plan(BASE, BASE.replace("max 100", "max 100 unique")).statements).toEqual(['ALTER TABLE "users" ADD CONSTRAINT "users_name_key" UNIQUE ("name");']);
    expect(plan(BASE, BASE.replace("max 100", "max 100 optional")).statements).toEqual(['ALTER TABLE "users" ALTER COLUMN "name" DROP NOT NULL;']);
  });

  it("adds links with an index, and changes ON DELETE when a link becomes optional", () => {
    const withPost = `${BASE}model Post {\n  author: User\n}\n`;
    const added = plan(`${BASE}model Post {\n  title: Text\n}\n`, `${BASE}model Post {\n  title: Text\n  author: User optional\n}\n`);
    expect(added.statements).toContain('CREATE INDEX "posts_author_id_idx" ON "posts" ("author_id");');
    const changed = plan(withPost, withPost.replace("author: User", "author: User optional"));
    expect(changed.statements).toEqual([
      'ALTER TABLE "posts" DROP CONSTRAINT "posts_author_id_fkey";',
      'ALTER TABLE "posts" ALTER COLUMN "author_id" DROP NOT NULL;',
      'ALTER TABLE "posts" ADD CONSTRAINT "posts_author_id_fkey" FOREIGN KEY ("author_id") REFERENCES "users" ("id") ON DELETE SET NULL;',
    ]);
  });

  it("adds sessions and roles with auth, and treats removing a role as data loss", () => {
    const user = (roles: string) => `auth User by email${roles}\nmodel User {\n  email: Email unique\n  password: Password\n}\n`;
    const auth = plan("model User {\n  email: Email unique\n  password: Password\n}\n", user(""));
    expect(auth.statements.some((s) => s.includes('CREATE TABLE "_rizo_sessions"'))).toBe(true);
    expect(auth.dataLoss).toEqual([]);
    expect(plan(user(" roles admin"), user(" roles admin, editor")).dataLoss).toEqual([]);
    const removed = plan(user(" roles admin, editor"), user(" roles admin"));
    expect(removed.dataLoss).toEqual(["role editor would be removed from every account that has it"]);
    expect(removed.statements).toContain(`UPDATE "users" SET "role" = NULL WHERE "role" NOT IN ('admin');`);
  });
});

describe("snapshots", () => {
  it("round-trips", () => {
    const s = schemaOf(BASE);
    expect(parseSnapshot(snapshotText(s))).toEqual({ schema: s });
  });

  it.each([
    ["not json", "{"],
    ["wrong version", '{"version":2,"tables":[]}'],
    ["unsafe table name", '{"version":1,"tables":[{"name":"x\\"; DROP TABLE y; --","columns":[],"foreignKeys":[]}]}'],
    ["unsafe constraint name", '{"version":1,"tables":[{"name":"t","columns":[{"name":"c","type":"TEXT","unique":"k\\" CASCADE","check":null,"values":null}],"foreignKeys":[]}]}'],
    ["unsafe role", `{"version":1,"tables":[{"name":"t","columns":[{"name":"role","type":"TEXT","unique":null,"check":null,"values":["a'); DROP"]}],"foreignKeys":[]}]}`],
  ])("rejects a snapshot with %s", (_label, text) => {
    expect(parseSnapshot(text)).toHaveProperty("error");
  });
});

describe("constraint names", () => {
  it("uses PostgreSQL's default pattern, and a hash when it would be too long", () => {
    expect(constraintName("users", "email", "key")).toBe("users_email_key");
    const long = constraintName("a".repeat(40), "b".repeat(40), "check");
    expect(long.length).toBeLessThanOrEqual(63);
    expect(long).toMatch(/_[0-9a-f]{8}_check$/);
    expect(constraintName("a".repeat(40), "b".repeat(41), "check")).not.toBe(long);
  });
});
