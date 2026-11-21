/**
 * Rizo Lang runtime: people's rights over their data.
 *
 * - Export: `GET /auth/me/export` returns everything stored about the
 *   account (except its password hash), so people can see and take it.
 * - Deletion: deleting an account removes it and everything only it uses
 *   (sessions, passkeys, tokens). Records that must have an owner, such as
 *   posts, are given to one shared "Deleted user" account in the same
 *   statement, so nothing else breaks and nothing points back to the person.
 *
 * The "Deleted user" account holds only placeholders (never personal data),
 * has an address under the reserved .invalid domain and no password, so
 * nobody can ever log in as it.
 */
import { randomBytes, randomInt, randomUUID } from "node:crypto";
import type { GhostSpec, GhostValue } from "./types.ts";

export const GHOST = '"_rizo_deleted_user"';

export const GHOST_SQL = {
  find: `SELECT "user_id" FROM ${GHOST} WHERE "one"`,
  /** Only one row can exist; a second process creating one at the same time gets nothing back. */
  claim: `INSERT INTO ${GHOST} ("one", "user_id") VALUES (true, $1) ON CONFLICT ("one") DO NOTHING RETURNING "user_id"`,
} as const;

/** Most records of one model in an export. More is reported as `truncated`. */
export const EXPORT_LIMIT = 10_000;

const hex = (n: number): string => randomBytes(Math.ceil(n / 2)).toString("hex").slice(0, n);

/** The value for one field of the "Deleted user" account. */
export function ghostValue(v: GhostValue): unknown {
  switch (v.kind) {
    case "fixed": return v.value;
    case "unique": return `deleted-${hex(32)}`.slice(0, v.max);
    case "email": {
      const domain = v.max >= 30 ? "@deleted.invalid" : "@x.invalid";
      return `d${hex(Math.max(1, Math.min(32, v.max - domain.length - 1)))}${domain}`;
    }
    case "uuid": return randomUUID();
    case "number": return v.max > v.min ? randomInt(Math.max(v.min, -(2 ** 47)), Math.min(v.max, 2 ** 47 - 1) + 1) : v.min;
    case "date": return new Date(randomInt(0, 2 ** 40)).toISOString();
    case "noPassword": return "!";
  }
}

/** The values for the "Deleted user" account, keyed by JSON key (so encrypted fields can be encrypted). */
export function ghostValues(spec: GhostSpec): Map<string, unknown> {
  return new Map(spec.fields.map((f) => [f.key, ghostValue(f.value)]));
}
