/**
 * Rizo Lang runtime: login sessions.
 *
 * A session token is 32 random bytes sent to the browser in an HttpOnly,
 * Secure, SameSite=Lax cookie. Only its SHA-256 hash is stored, so a leaked
 * database does not leak usable sessions.
 *
 * A session ends after 7 days without use, and 30 days after login however
 * much it is used. Each device has a public id and a short label (such as
 * "Chrome on macOS", from a fixed list), so users can see where they are
 * logged in and log out one device. Neither the raw User-Agent nor the IP
 * address is stored.
 */
import { createHash, randomBytes } from "node:crypto";

export const COOKIE_NAME = "rizo_session";
/** A session ends after this long without use. */
export const IDLE_SECONDS = 7 * 24 * 60 * 60;
/** A session ends this long after login, however much it is used. */
export const MAX_SECONDS = 30 * 24 * 60 * 60;
/** "Last active" is updated at most this often, so most requests don't write. */
export const TOUCH_SECONDS = 60;
export const SESSIONS_TABLE = '"_rizo_sessions"';

export const SQL = {
  create: `INSERT INTO ${SESSIONS_TABLE} ("token_hash", "user_id", "device", "expires_at", "ends_at") VALUES ($1, $2, $3, now() + make_interval(secs => $4), now() + make_interval(secs => $5))`,
  /** The session's account, and whether "last active" is due for an update. */
  lookup: `SELECT "user_id", "last_seen_at" < now() - make_interval(secs => ${TOUCH_SECONDS}) AS "stale" FROM ${SESSIONS_TABLE} WHERE "token_hash" = $1 AND "expires_at" > now() AND "ends_at" > now()`,
  /** Record use: move the idle deadline forward, but never past the maximum. */
  touch: `UPDATE ${SESSIONS_TABLE} SET "last_seen_at" = now(), "expires_at" = LEAST(now() + make_interval(secs => $2), "ends_at") WHERE "token_hash" = $1`,
  delete: `DELETE FROM ${SESSIONS_TABLE} WHERE "token_hash" = $1`,
  deleteExpired: `DELETE FROM ${SESSIONS_TABLE} WHERE "user_id" = $1 AND ("expires_at" <= now() OR "ends_at" <= now())`,
  deleteOthers: `DELETE FROM ${SESSIONS_TABLE} WHERE "user_id" = $1 AND "token_hash" <> $2`,
  deleteAll: `DELETE FROM ${SESSIONS_TABLE} WHERE "user_id" = $1`,
  /** This account's devices, newest activity first. `current` marks the one making the request. */
  list: `SELECT "id", "device", "created_at" AS "createdAt", "last_seen_at" AS "lastSeenAt", "token_hash" = $2 AS "current" FROM ${SESSIONS_TABLE} WHERE "user_id" = $1 AND "expires_at" > now() AND "ends_at" > now() ORDER BY "last_seen_at" DESC, "id" LIMIT 100`,
  /** Log out one of your own devices. Returns its token hash, to tell whether it was this one. */
  deleteById: `DELETE FROM ${SESSIONS_TABLE} WHERE "id" = $1 AND "user_id" = $2 RETURNING "token_hash"`,
  sweep: `DELETE FROM ${SESSIONS_TABLE} WHERE "expires_at" <= now() OR "ends_at" <= now()`,
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

/** The cookie lasts as long as the longest a session can; the server ends idle sessions sooner. */
export function sessionCookie(token: string, secure: boolean): string {
  return `${COOKIE_NAME}=${token}; HttpOnly;${secure ? " Secure;" : ""} SameSite=Lax; Path=/; Max-Age=${MAX_SECONDS}`;
}

export function clearedCookie(secure: boolean): string {
  return `${COOKIE_NAME}=; HttpOnly;${secure ? " Secure;" : ""} SameSite=Lax; Path=/; Max-Age=0`;
}

const BROWSERS: readonly (readonly [RegExp, string])[] = [
  [/\bEdg(e|A|iOS)?\//, "Edge"],
  [/\b(OPR|Opera)\//, "Opera"],
  [/\bSamsungBrowser\//, "Samsung Internet"],
  [/\b(Firefox|FxiOS)\//, "Firefox"],
  [/(Chrome|CriOS|Chromium)\//, "Chrome"],
  [/\bSafari\//, "Safari"],
];
const SYSTEMS: readonly (readonly [RegExp, string])[] = [
  [/\b(iPhone|iPad|iPod)\b/, "iOS"],
  [/\bAndroid\b/, "Android"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bWindows\b/, "Windows"],
  [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
  [/\bLinux\b/, "Linux"],
];

/** A short device label from the User-Agent, built only from the fixed names above. */
export function deviceLabel(userAgent: string | undefined): string {
  const ua = (userAgent ?? "").slice(0, 512);
  const browser = BROWSERS.find(([re]) => re.test(ua))?.[1];
  const system = SYSTEMS.find(([re]) => re.test(ua))?.[1];
  if (browser !== undefined && system !== undefined) return `${browser} on ${system}`;
  return browser ?? system ?? "Unknown device";
}
