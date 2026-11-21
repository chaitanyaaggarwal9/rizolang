/**
 * Rizo Lang runtime: move encrypted values to the current key.
 *
 * To rotate keys: put a new key first in RIZO_ENCRYPTION_KEYS (keep the old
 * ones after it), restart the server, then run `node reencrypt.ts`. When it
 * reports nothing left on old keys, the old keys can be removed.
 *
 * Rows are read in batches by id and updated only if they haven't changed in
 * the meantime, so it is safe to run while the server is running.
 */
import pg from "pg";
import { type Keys, decryptValue, encryptValue, parseKeys } from "./encryption.ts";
import type { Db } from "./server.ts";
import type { App } from "./types.ts";

export interface ReencryptResult {
  /** Values moved to the current key. */
  readonly updated: number;
  /** Values that could not be decrypted with any listed key. */
  readonly failed: number;
}

export async function reencrypt(app: App, db: Db, keys: Keys): Promise<ReencryptResult> {
  let updated = 0;
  let failed = 0;
  // Values already on the current key start with this prefix. Key ids are letters and digits, so it has no LIKE wildcards.
  const current = `rz1.${keys.current}.%`;
  for (const column of app.encrypted ?? []) {
    let after = "00000000-0000-0000-0000-000000000000";
    for (;;) {
      const r = await db.query(column.select, [current, after]);
      for (const row of r.rows) {
        const id = String(row["id"]);
        try {
          const value = decryptValue(keys, column.aad, row["value"]);
          const moved = await db.query(column.update, [id, encryptValue(keys, column.aad, value), row["value"]]);
          updated += moved.rowCount ?? 0;
        } catch {
          failed++;
        }
        after = id;
      }
      if (r.rows.length < 500) break;
    }
  }
  return { updated, failed };
}

/** The `node reencrypt.ts` command. */
export async function runReencrypt(app: App): Promise<void> {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url === "") {
    process.stderr.write("rizo: DATABASE_URL is not set.\n  fix: Run DATABASE_URL=postgres://... RIZO_ENCRYPTION_KEYS=... node reencrypt.ts\n");
    process.exit(1);
  }
  let keys: Keys;
  try {
    keys = parseKeys(process.env["RIZO_ENCRYPTION_KEYS"]);
  } catch (e) {
    process.stderr.write(`rizo: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  }
  const pool = new pg.Pool({ connectionString: url, max: 2 });
  try {
    const { updated, failed } = await reencrypt(app, { query: (sql, vals) => pool.query(sql, vals) }, keys);
    process.stdout.write(`rizo: moved ${updated} value(s) to key "${keys.current}"\n`);
    if (failed > 0) {
      process.stderr.write(`rizo: ${failed} value(s) could not be decrypted with any key in RIZO_ENCRYPTION_KEYS. Keep the old keys until they are fixed.\n`);
      process.exitCode = 1;
    }
  } finally {
    await pool.end();
  }
}
