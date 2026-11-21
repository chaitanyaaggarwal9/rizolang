/**
 * Rizo Lang runtime: API tokens for scripts and AI agents.
 *
 * A token acts as the account that created it, but only on the endpoints
 * chosen when it was created, and only until it expires (at most 90 days).
 * It never works on /auth/* endpoints, so a token can't create tokens,
 * change the password or delete the account.
 *
 * Tokens look like `rzt_<43 base64url characters>` (32 random bytes), so
 * secret scanners can recognise them. Only SHA-256 hashes are stored, and a
 * token is shown once, when it is created.
 */
import { createHash, randomBytes } from "node:crypto";

export const TOKENS = '"_rizo_tokens"';
export const TOKEN_PREFIX = "rzt_";
/** Longest lifetime, and the default. */
export const MAX_TOKEN_DAYS = 90;
/** Most tokens one account may have. */
export const MAX_TOKENS = 20;

export const TOKEN_SQL = {
  create: `INSERT INTO ${TOKENS} ("token_hash", "user_id", "name", "endpoints", "expires_at") VALUES ($1, $2, $3, $4, now() + make_interval(days => $5)) RETURNING "id", "name", "endpoints", "created_at" AS "createdAt", "expires_at" AS "expiresAt"`,
  count: `SELECT count(*)::int AS "n" FROM ${TOKENS} WHERE "user_id" = $1 AND "expires_at" > now()`,
  /** The token's account and endpoints, and whether "last used" is due for an update. */
  lookup: `SELECT "id", "user_id", "endpoints", "last_used_at" IS NULL OR "last_used_at" < now() - interval '60 seconds' AS "stale" FROM ${TOKENS} WHERE "token_hash" = $1 AND "expires_at" > now()`,
  touch: `UPDATE ${TOKENS} SET "last_used_at" = now() WHERE "id" = $1`,
  list: `SELECT "id", "name", "endpoints", "created_at" AS "createdAt", "expires_at" AS "expiresAt", "last_used_at" AS "lastUsedAt" FROM ${TOKENS} WHERE "user_id" = $1 AND "expires_at" > now() ORDER BY "created_at" DESC, "id"`,
  remove: `DELETE FROM ${TOKENS} WHERE "id" = $1 AND "user_id" = $2 RETURNING "id"`,
  removeAll: `DELETE FROM ${TOKENS} WHERE "user_id" = $1`,
  sweep: `DELETE FROM ${TOKENS} WHERE "expires_at" <= now()`,
} as const;

/** A new token (shown once) and its hash (stored). */
export function newApiToken(): { token: string; hash: string } {
  const token = `${TOKEN_PREFIX}${randomBytes(32).toString("base64url")}`;
  return { token, hash: apiTokenHash(token) };
}

export function apiTokenHash(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Read `Authorization: Bearer rzt_...`. Returns undefined when there is no
 * Authorization header, and null when there is one but it isn't a token.
 */
export function readBearer(header: string | undefined): string | null | undefined {
  if (header === undefined) return undefined;
  const m = /^Bearer (rzt_[A-Za-z0-9_-]{43})$/.exec(header.trim());
  return m?.[1] ?? null;
}

/** The endpoints stored with a token. Anything malformed counts as none. */
export function parseEndpoints(stored: unknown): string[] {
  try {
    const list: unknown = typeof stored === "string" ? JSON.parse(stored) : undefined;
    return Array.isArray(list) && list.every((e) => typeof e === "string") ? list : [];
  } catch {
    return [];
  }
}
