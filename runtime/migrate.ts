/**
 * Rizo Lang runtime: applies the SQL files in migrations/ to the database.
 *
 * - Each migration runs in its own transaction and is recorded in
 *   "_rizo_migrations" with a checksum, so it is applied exactly once.
 * - A PostgreSQL advisory lock stops two deploys from migrating at once.
 * - If an applied migration file was changed or deleted, nothing runs.
 */
import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import pg from "pg";

export const MIGRATIONS_TABLE = '"_rizo_migrations"';
const MIGRATION_FILE = /^\d{4}_[a-z0-9_]+\.sql$/;
/** Arbitrary constant identifying the rizolang migration lock. */
const LOCK_ID = 727_201_401;

export interface Migration {
  readonly name: string;
  readonly sql: string;
  readonly checksum: string;
}

export interface MigrateResult {
  readonly applied: readonly string[];
  readonly baselined: string | undefined;
}

/** Read the migration files of a directory, in order. */
export function readMigrations(dir: string): Migration[] {
  return readdirSync(dir)
    .filter((f) => MIGRATION_FILE.test(f))
    .sort()
    .map((name) => {
      const sql = readFileSync(`${dir}/${name}`, "utf8");
      return { name, sql, checksum: createHash("sha256").update(sql).digest("hex") };
    });
}

export class MigrationError extends Error {}

/** A connected client, e.g. a `pg.Client` or a client from a pool. */
export interface MigrationClient {
  query(sql: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/**
 * Apply pending migrations. With `baseline`, the first migration is recorded
 * as applied without running it (for databases created from schema.sql).
 */
export async function migrate(client: MigrationClient, migrations: readonly Migration[], options: { baseline?: boolean } = {}): Promise<MigrateResult> {
  await client.query("SELECT pg_advisory_lock($1)", [LOCK_ID]);
  try {
    await client.query(
      `CREATE TABLE IF NOT EXISTS ${MIGRATIONS_TABLE} ("name" TEXT PRIMARY KEY, "checksum" TEXT NOT NULL, "applied_at" TIMESTAMPTZ NOT NULL DEFAULT now())`,
    );
    const done = new Map(
      (await client.query(`SELECT "name", "checksum" FROM ${MIGRATIONS_TABLE}`)).rows.map((r) => [String(r["name"]), String(r["checksum"])]),
    );
    for (const [name, checksum] of done) {
      const file = migrations.find((m) => m.name === name);
      if (file === undefined) throw new MigrationError(`Migration ${name} was applied to this database but its file is missing. Restore it from version control.`);
      if (file.checksum !== checksum) {
        throw new MigrationError(`Migration ${name} was changed after it was applied. Restore the original file and put new changes in a new migration.`);
      }
    }

    let baselined: string | undefined;
    if (options.baseline) {
      const first = migrations[0];
      if (done.size > 0) throw new MigrationError("--baseline is only for a database that has no migrations recorded yet.");
      if (first === undefined) throw new MigrationError("There are no migrations to baseline.");
      await client.query(`INSERT INTO ${MIGRATIONS_TABLE} ("name", "checksum") VALUES ($1, $2)`, [first.name, first.checksum]);
      done.set(first.name, first.checksum);
      baselined = first.name;
    }

    const applied: string[] = [];
    for (const m of migrations) {
      if (done.has(m.name)) continue;
      await client.query("BEGIN");
      try {
        await client.query(m.sql);
        await client.query(`INSERT INTO ${MIGRATIONS_TABLE} ("name", "checksum") VALUES ($1, $2)`, [m.name, m.checksum]);
        await client.query("COMMIT");
      } catch (e) {
        await client.query("ROLLBACK");
        const reason = e instanceof Error ? e.message : String(e);
        throw new MigrationError(
          `Migration ${m.name} failed and was rolled back: ${reason}` +
          (/null values|violates check|could not create unique/.test(reason)
            ? "\nExisting rows do not fit the new rules. Fix or remove those rows, or make the field optional, then run again."
            : ""),
        );
      }
      applied.push(m.name);
    }
    return { applied, baselined };
  } finally {
    await client.query("SELECT pg_advisory_unlock($1)", [LOCK_ID]);
  }
}

/** Entry point used by the generated migrate.ts. */
export async function runMigrations(dirUrl: URL): Promise<void> {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url === "") {
    process.stderr.write("rizo: DATABASE_URL is not set.\n  fix: Run DATABASE_URL=postgres://user:password@localhost:5432/app node migrate.ts\n");
    process.exit(1);
  }
  const args = process.argv.slice(2);
  const unknown = args.find((a) => a !== "--baseline");
  if (unknown !== undefined) {
    process.stderr.write(`rizo: unknown option "${unknown}". The only option is --baseline.\n`);
    process.exit(1);
  }
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    const r = await migrate(client, readMigrations(fileURLToPath(dirUrl)), { baseline: args.includes("--baseline") });
    if (r.baselined !== undefined) process.stdout.write(`rizo: recorded ${r.baselined} as already applied (baseline)\n`);
    for (const name of r.applied) process.stdout.write(`rizo: applied ${name}\n`);
    if (r.applied.length === 0) process.stdout.write("rizo: database is up to date\n");
  } catch (e) {
    process.stderr.write(`rizo: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exitCode = 1;
  } finally {
    await client.end();
  }
}
