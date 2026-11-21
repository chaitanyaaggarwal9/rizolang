/**
 * Rizo Lang runtime: rate limits stored in PostgreSQL.
 *
 * Every server process shares the same counters, so limits hold when the app
 * runs on several servers. A counter is one row per (key, time window); keys
 * are SHA-256 hashes, so the table never stores raw IP addresses or ids.
 */
import { createHash } from "node:crypto";

export const LIMITS_TABLE = '"_rizo_rate_limits"';

export const LIMIT_SQL = {
  /** Count one request in the current window, and read the previous window's count. */
  consume: `WITH cur AS (
  INSERT INTO ${LIMITS_TABLE} ("key", "expires_at", "count") VALUES ($1, to_timestamp($2), 1)
  ON CONFLICT ("key") DO UPDATE SET "count" = ${LIMITS_TABLE}."count" + 1 RETURNING "count"
)
SELECT (SELECT "count" FROM cur) AS "current", (SELECT "count" FROM ${LIMITS_TABLE} WHERE "key" = $3) AS "previous"`,
  /** Read the current and previous windows without counting. */
  peek: `SELECT (SELECT "count" FROM ${LIMITS_TABLE} WHERE "key" = $1) AS "current", (SELECT "count" FROM ${LIMITS_TABLE} WHERE "key" = $2) AS "previous"`,
  clear: `DELETE FROM ${LIMITS_TABLE} WHERE "key" LIKE $1`,
  sweep: `DELETE FROM ${LIMITS_TABLE} WHERE "expires_at" < now()`,
} as const;

export interface LimitDb {
  query(sql: string, values: unknown[]): Promise<{ readonly rows: readonly Record<string, unknown>[] }>;
}

export interface LimitResult {
  readonly allowed: boolean;
  /** Seconds until the window resets. */
  readonly retryAfter: number;
}

/** A short, stable hash, so counters never contain the identity itself. */
export function limitKey(scope: string, identity: string): string {
  return `${createHash("sha256").update(scope).digest("hex").slice(0, 16)}:${createHash("sha256").update(identity).digest("hex").slice(0, 32)}`;
}

export class Limits {
  readonly #db: LimitDb;
  readonly #now: () => number;
  constructor(db: LimitDb, now: () => number = Date.now) {
    this.#db = db;
    this.#now = now;
  }

  /**
   * Sliding window: the previous window still counts, fading out as the
   * current one goes on. This stops bursts at window edges (e.g. 5 tries just
   * before a boundary and 5 more just after).
   */
  #window(windowSeconds: number) {
    const nowSeconds = this.#now() / 1000;
    const start = Math.floor(nowSeconds / windowSeconds) * windowSeconds;
    return {
      start,
      previous: start - windowSeconds,
      // Counters are kept for two windows, so the next window can still see this one.
      expires: start + 2 * windowSeconds,
      remaining: 1 - (nowSeconds - start) / windowSeconds,
      retryAfter: Math.max(1, Math.ceil(start + windowSeconds - nowSeconds)),
    };
  }

  #estimate(row: Record<string, unknown> | undefined, remaining: number): number {
    return Number(row?.["current"] ?? 0) + Number(row?.["previous"] ?? 0) * remaining;
  }

  /** Count a request. Allowed while the (sliding) count stays within `max`. */
  async consume(key: string, max: number, windowSeconds: number): Promise<LimitResult> {
    const w = this.#window(windowSeconds);
    const r = await this.#db.query(LIMIT_SQL.consume, [`${key}@${w.start}`, w.expires, `${key}@${w.previous}`]);
    return { allowed: this.#estimate(r.rows[0], w.remaining) <= max, retryAfter: w.retryAfter };
  }

  /** Check without counting: would one more attempt stay within `max`? */
  async blocked(key: string, max: number, windowSeconds: number): Promise<LimitResult> {
    const w = this.#window(windowSeconds);
    const r = await this.#db.query(LIMIT_SQL.peek, [`${key}@${w.start}`, `${key}@${w.previous}`]);
    return { allowed: this.#estimate(r.rows[0], w.remaining) + 1 <= max, retryAfter: w.retryAfter };
  }

  /** Forget a key in every window, e.g. after a successful login. */
  async clear(key: string): Promise<void> {
    await this.#db.query(LIMIT_SQL.clear, [`${key}@%`]);
  }

  /** Delete expired counters. */
  async sweep(): Promise<void> {
    await this.#db.query(LIMIT_SQL.sweep, []);
  }
}
