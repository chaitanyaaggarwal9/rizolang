/**
 * Rizo Lang runtime: passkey storage and challenges.
 *
 * Challenges are random 32-byte values, valid for 5 minutes and usable once.
 * Only their SHA-256 hashes are stored. The verification itself is in
 * webauthn.ts.
 */
import { createHash, randomBytes } from "node:crypto";

export const PASSKEYS = '"_rizo_passkeys"';
export const CHALLENGES = '"_rizo_challenges"';
export const CHALLENGE_SECONDS = 5 * 60;
/** Most passkeys one account may have. */
export const MAX_PASSKEYS = 20;

export const PASSKEY_SQL = {
  createChallenge: `INSERT INTO ${CHALLENGES} ("id", "purpose", "user_id", "expires_at") VALUES ($1, $2, $3, now() + make_interval(secs => $4))`,
  /** Use a challenge: it must exist, be unexpired, be for this purpose and (for registration) this account. */
  useChallenge: `DELETE FROM ${CHALLENGES} WHERE "id" = $1 AND "purpose" = $2 AND "expires_at" > now() AND "user_id" IS NOT DISTINCT FROM $3 RETURNING "id"`,
  sweepChallenges: `DELETE FROM ${CHALLENGES} WHERE "expires_at" <= now()`,
  insert: `INSERT INTO ${PASSKEYS} ("id", "user_id", "public_key", "algorithm", "sign_count", "name") VALUES ($1, $2, $3, $4, $5, $6)`,
  count: `SELECT count(*)::int AS "n" FROM ${PASSKEYS} WHERE "user_id" = $1`,
  ids: `SELECT "id" FROM ${PASSKEYS} WHERE "user_id" = $1`,
  find: `SELECT "user_id", "public_key", "algorithm", "sign_count" FROM ${PASSKEYS} WHERE "id" = $1`,
  used: `UPDATE ${PASSKEYS} SET "sign_count" = $2, "last_used_at" = now() WHERE "id" = $1`,
  list: `SELECT "id", "name", "created_at" AS "createdAt", "last_used_at" AS "lastUsedAt" FROM ${PASSKEYS} WHERE "user_id" = $1 ORDER BY "created_at", "id"`,
  remove: `DELETE FROM ${PASSKEYS} WHERE "id" = $1 AND "user_id" = $2`,
} as const;

/** A new challenge (sent to the browser) and its hash (stored). */
export function newChallenge(): { challenge: string; hash: string } {
  const challenge = randomBytes(32).toString("base64url");
  return { challenge, hash: challengeHash(challenge) };
}

export function challengeHash(challenge: string): string {
  return createHash("sha256").update(challenge).digest("hex");
}

/** Read the challenge out of the browser's clientDataJSON (verification checks it again). */
export function challengeOf(clientDataJSON: unknown): string | undefined {
  if (typeof clientDataJSON !== "string" || clientDataJSON.length > 6000 || !/^[A-Za-z0-9_-]+$/.test(clientDataJSON)) return undefined;
  try {
    const data = JSON.parse(Buffer.from(clientDataJSON, "base64url").toString("utf8")) as { challenge?: unknown };
    return typeof data.challenge === "string" && /^[A-Za-z0-9_-]{43}$/.test(data.challenge) ? data.challenge : undefined;
  } catch {
    return undefined;
  }
}
