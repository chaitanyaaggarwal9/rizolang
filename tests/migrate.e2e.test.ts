/**
 * Migrations against a real PostgreSQL database. Runs only when
 * RIZO_TEST_DATABASE_URL is set. Every test uses its own temporary schema.
 */
import { createHash, randomBytes } from "node:crypto";
import pg from "pg";
import { afterAll, describe, expect, it } from "vitest";
import { type Migration, MigrationError, migrate } from "../runtime/migrate.ts";
import { emitSchemaSql } from "../src/emit/sql.js";
import { initialPlan, migrationFile, planMigration } from "../src/migrations.js";
import { type Schema, buildSchema } from "../src/schema.js";
import { compileOk } from "./helpers.js";

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];
const schemas: string[] = [];
const clients: pg.Client[] = [];

async function freshClient(): Promise<pg.Client> {
  const name = `rizo_mig_${randomBytes(6).toString("hex")}`;
  const admin = new pg.Client({ connectionString: DATABASE_URL });
  await admin.connect();
  await admin.query(`CREATE SCHEMA "${name}"`);
  await admin.end();
  schemas.push(name);
  const c = new pg.Client({ connectionString: DATABASE_URL, options: `-c search_path="${name}",public` });
  await c.connect();
  clients.push(c);
  return c;
}

const schemaOf = (src: string): Schema => {
  const r = compileOk(src);
  return buildSchema(r.models, r.auth);
};

function toMigration(number: number, sql: string, slug: string): Migration {
  const name = `${String(number).padStart(4, "0")}_${slug}.sql`;
  return { name, sql, checksum: createHash("sha256").update(sql).digest("hex") };
}

/** Build the migration list for a series of versions of a .rz file, like repeated `rizolang build`. */
function history(versions: readonly string[]): Migration[] {
  const out: Migration[] = [];
  let prev: Schema | undefined;
  versions.forEach((src) => {
    const next = schemaOf(src);
    const plan = prev === undefined ? initialPlan(next) : planMigration(prev, next);
    if (plan.statements.length > 0) out.push(toMigration(out.length + 1, migrationFile(plan, out.length + 1, "app.rz"), plan.slug));
    prev = next;
  });
  return out;
}

/** Tables, columns and constraint names, to compare two databases. */
async function describeDb(c: pg.Client): Promise<string[]> {
  const cols = await c.query(
    `SELECT table_name, column_name, data_type, is_nullable, column_default FROM information_schema.columns
     WHERE table_schema = current_schema() AND table_name <> '_rizo_migrations' ORDER BY 1, 2`,
  );
  const cons = await c.query(
    `SELECT conrelid::regclass::text AS t, conname, contype, pg_get_constraintdef(oid) AS def FROM pg_constraint
     WHERE connamespace = current_schema()::regnamespace AND conrelid::regclass::text <> '_rizo_migrations' ORDER BY 1, 2`,
  );
  const idx = await c.query(
    `SELECT tablename, indexname FROM pg_indexes WHERE schemaname = current_schema() AND tablename <> '_rizo_migrations' ORDER BY 1, 2`,
  );
  return [...cols.rows, ...cons.rows, ...idx.rows].map((r) => JSON.stringify(r));
}

const V1 = `auth User by email
model User {
  email: Email unique
  password: Password
  name: Text max 100
}
`;
const V2 = `auth User by email roles admin, editor
model User {
  email: Email unique
  password: Password
  name: Text max 200
  bio: Text optional
}
model Post {
  author: User
  title: Text unique
}
`;
const V3 = V2.replace("  bio: Text optional\n", "  bio: Text optional\n  age: Number min 0 optional\n").replace("author: User\n", "author: User optional\n");

describe.skipIf(DATABASE_URL === undefined)("migrations (PostgreSQL)", () => {
  afterAll(async () => {
    for (const c of clients) await c.end().catch(() => undefined);
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    for (const s of schemas) await admin.query(`DROP SCHEMA "${s}" CASCADE`);
    await admin.end();
  });

  it("applies each migration once, in order", async () => {
    const c = await freshClient();
    const ms = history([V1, V2, V3]);
    expect(ms.map((m) => m.name)).toEqual(["0001_initial.sql", "0002_create_table_posts_and_more.sql", "0003_add_column_users_age_and_more.sql"]);
    expect((await migrate(c, ms.slice(0, 1))).applied).toEqual(["0001_initial.sql"]);
    expect((await migrate(c, ms)).applied).toEqual(["0002_create_table_posts_and_more.sql", "0003_add_column_users_age_and_more.sql"]);
    expect((await migrate(c, ms)).applied).toEqual([]);
  });

  it("produces exactly the same database as a fresh schema.sql", async () => {
    const migrated = await freshClient();
    await migrate(migrated, history([V1, V2, V3]));
    const fresh = await freshClient();
    await fresh.query(emitSchemaSql(schemaOf(V3), "app.rz"));
    const shape = await describeDb(fresh);
    expect(shape.length).toBeGreaterThan(25);
    expect(await describeDb(migrated)).toEqual(shape);
  });

  it("keeps existing rows when adding fields, models and links", async () => {
    const c = await freshClient();
    const ms = history([V1, V2]);
    await migrate(c, ms.slice(0, 1));
    await c.query(`INSERT INTO users (email, password_hash, name) VALUES ('a@b.co', 'h', 'Ann')`);
    await migrate(c, ms);
    expect((await c.query("SELECT email, name, bio, role FROM users")).rows).toEqual([{ email: "a@b.co", name: "Ann", bio: null, role: null }]);
  });

  it("refuses to run when an applied migration was edited or deleted", async () => {
    const c = await freshClient();
    const ms = history([V1, V2]);
    await migrate(c, ms);
    const edited = [{ ...ms[0]!, checksum: "0".repeat(64) }, ms[1]!];
    await expect(migrate(c, edited)).rejects.toThrow(/was changed after it was applied/);
    await expect(migrate(c, ms.slice(1))).rejects.toThrow(/its file is missing/);
  });

  it("rolls back a migration that does not fit the existing rows", async () => {
    const c = await freshClient();
    const ms = history([V1, V1.replace("  name: Text max 100\n", "  name: Text max 100\n  age: Number\n")]);
    await migrate(c, ms.slice(0, 1));
    await c.query(`INSERT INTO users (email, password_hash, name) VALUES ('a@b.co', 'h', 'Ann')`);
    const err = await migrate(c, ms).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(MigrationError);
    expect(String(err)).toContain("rolled back");
    expect(String(err)).toContain("make the field optional");
    const cols = await c.query(`SELECT column_name FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users'`);
    expect(cols.rows.map((r) => r.column_name)).not.toContain("age");
    expect((await c.query(`SELECT name FROM _rizo_migrations`)).rows.map((r) => r.name)).toEqual(["0001_initial.sql"]);
  });

  it("baselines a database created by v0.2 (unnamed constraints), then migrates it", async () => {
    const c = await freshClient();
    // v0.2 wrote constraints without names; PostgreSQL then picks the same default names we use.
    const oldStyle = emitSchemaSql(schemaOf(V1), "app.rz")
      .replace(/CONSTRAINT "[a-z0-9_]+" /g, "")
      .replace(/ADD CONSTRAINT "[a-z0-9_]+" FOREIGN KEY/g, "ADD FOREIGN KEY")
      .replace(/CREATE INDEX "[a-z0-9_]+" ON/g, "CREATE INDEX ON");
    await c.query(oldStyle);
    const ms = history([V1, V2]);
    const r = await migrate(c, ms, { baseline: true });
    expect(r).toEqual({ baselined: "0001_initial.sql", applied: ["0002_create_table_posts_and_more.sql"] });
    // 0002 dropped and re-created users_name_check by name, which only works if the names matched.
    const check = await c.query(`SELECT pg_get_constraintdef(oid) AS def FROM pg_constraint WHERE conname = 'users_name_check' AND connamespace = current_schema()::regnamespace`);
    expect(check.rows[0]?.def).toContain("<= 200");
    await expect(migrate(c, ms, { baseline: true })).rejects.toThrow(/only for a database that has no migrations/);
  });
});
