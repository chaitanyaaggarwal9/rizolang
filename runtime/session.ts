/**
 * Rizo Lang runtime: login sessions.
 *
 * A session token is 32 random bytes sent to the browser in an HttpOnly,
 * Secure, SameSite=Lax cookie. Only its SHA-256 hash is stored, so a leaked
 * database does not leak usable sessions.
 */
import { createHash, randomBytes } from "node:crypto";

export const COOKIE_NAME = "rizo_session";
export const SESSION_SECONDS = 7 * 24 * 60 * 60;
export const SESSIONS_TABLE = '"_rizo_sessions"';

export const SQL = {
  create: `INSERT INTO ${SESSIONS_TABLE} ("token_hash", "user_id", "expires_at") VALUES ($1, $2, now() + make_interval(secs => $3))`,
  lookup: `SELECT "user_id" FROM ${SESSIONS_TABLE} WHERE "token_hash" = $1 AND "expires_at" > now()`,
  delete: `DELETE FROM ${SESSIONS_TABLE} WHERE "token_hash" = $1`,
  deleteExpired: `DELETE FROM ${SESSIONS_TABLE} WHERE "user_id" = $1 AND "expires_at" <= now()`,
} as const;

export function newToken(): string {
  return randomBytes(32).toString("base64url");
}

export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** Read the session token from a Cookie header. Returns undefined if absent or malformed. */
export function readToken(cookieHeader: string | undefined): string | undefined {
  if (cookieHeader === undefined) return undefined;
  for (const part of cookieHeader.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() !== COOKIE_NAME) continue;
    const value = part.slice(eq + 1).trim();
    return /^[A-Za-z0-9_-]{43}$/.test(value) ? value : undefined;
  }
  return undefined;
}

export function sessionCookie(token: string, secure: boolean): string {
  return `${COOKIE_NAME}=${token}; HttpOnly;${secure ? " Secure;" : ""} SameSite=Lax; Path=/; Max-Age=${SESSION_SECONDS}`;
}

export function clearedCookie(secure: boolean): string {
  return `${COOKIE_NAME}=; HttpOnly;${secure ? " Secure;" : ""} SameSite=Lax; Path=/; Max-Age=0`;
}
