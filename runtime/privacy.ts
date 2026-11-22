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
import type { App, GhostSpec, GhostValue, PrivacySpec } from "./types.ts";

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

/** Most batches of 1,000 deleted per model in one sweep, so a sweep never runs for long. */
const MAX_BATCHES = 20;

/**
 * Delete records older than their model's `keep` (run every few minutes by
 * the server). Returns how many were deleted per model. Records that other
 * records still need are skipped until those are gone.
 */
export async function expireRecords(
  app: App,
  db: { query(sql: string, values: unknown[]): Promise<{ rowCount: number | null }> },
): Promise<{ model: string; deleted: number }[]> {
  const done: { model: string; deleted: number }[] = [];
  for (const r of app.retention ?? []) {
    let deleted = 0;
    for (let batch = 0; batch < MAX_BATCHES; batch++) {
      const n = (await db.query(r.sql, [r.amount])).rowCount ?? 0;
      deleted += n;
      if (n < 1000) break;
    }
    if (deleted > 0) done.push({ model: r.model, deleted });
  }
  return done;
}

/** The laws behind each region of `privacy for`, and where people can complain. Fixed text: apps never write their own. */
export const LAWS: Readonly<Record<string, { readonly region: string; readonly law: string; readonly complaint: string }>> = {
  EU: {
    region: "European Union",
    law: "General Data Protection Regulation (GDPR)",
    complaint: "You can also complain to the data protection authority in your country.",
  },
  UK: {
    region: "United Kingdom",
    law: "UK GDPR and the Data Protection Act 2018",
    complaint: "You can also complain to the Information Commissioner's Office (ico.org.uk).",
  },
  IN: {
    region: "India",
    law: "Digital Personal Data Protection Act, 2023",
    complaint: "Write to us first: the contact below handles complaints. If we don't resolve it, you can complain to the Data Protection Board of India.",
  },
  "US-CA": {
    region: "California, United States",
    law: "California Consumer Privacy Act (CCPA), as amended by the CPRA",
    complaint: "We will not treat you differently for using these rights. You can also complain to the California Privacy Protection Agency.",
  },
  BR: {
    region: "Brazil",
    law: "Lei Geral de Proteção de Dados (LGPD)",
    complaint: "You can also complain to the Autoridade Nacional de Proteção de Dados (ANPD).",
  },
};

export interface NoticeOptions {
  /** RIZO_PRIVACY_CONTACT: where people write about their data. */
  readonly contact: string;
  /** How long security log entries are kept. */
  readonly auditRetentionDays: number;
  /** Who sends account emails: "Resend", or "development" when emails are only printed. */
  readonly emailService: string;
  /** Where uploaded files are kept: "local" or "S3-compatible storage". */
  readonly fileStorage?: string;
}

/** The privacy notice served at GET /auth/privacy and shown on the /privacy page. */
export function privacyNotice(spec: PrivacySpec, options: NoticeOptions): Record<string, unknown> {
  return {
    regions: spec.regions.map((code) => ({ code, ...LAWS[code] })),
    contact: options.contact,
    data: spec.models.map((m) => ({
      name: m.name,
      account: m.account,
      fields: m.fields,
      kept: m.keep === null
        ? (m.account ? "Until you delete your account." : "Until it is deleted, or until you delete your account (records others rely on stay, credited to \"Deleted user\").")
        : `Deleted ${m.keep.amount} ${m.keep.amount === 1 ? m.keep.unit.replace(/s$/, "") : m.keep.unit} after it is created.`,
    })),
    rights: [
      "See and download everything we store about you: use \"Download my data\" on your account page.",
      "Delete your account: use \"Delete my account\" on your account page.",
      "Correct your details, or ask anything about your data: write to the contact below.",
    ],
    cookies: "We use one cookie, rizo_session, only to keep you logged in. There is no tracking or advertising, so there is no cookie banner.",
    sharing: [
      options.emailService === "Resend"
        ? "Resend (resend.com) sends our account emails, such as email confirmation and password reset, and receives your email address to do so."
        : "Account emails are not sent to any other service.",
      "We don't sell or share your personal information, and we don't use it for advertising.",
    ],
    security: [
      "Passwords are stored only as salted hashes, so nobody can read them.",
      "Fields marked encrypted are encrypted before they reach our database.",
      "Connections and logins are protected, and every login and change to your account is recorded.",
    ],
    ...(spec.models.some((m) => m.fields.some((f) => f.kind === "File"))
      ? {
          files: [
            "Files you upload (such as photos and documents) are kept only while a record uses them, and deleted within a day after that.",
            "Location (GPS) data is removed from photos when they are uploaded.",
            options.fileStorage === "S3-compatible storage"
              ? "Files are stored in a private storage bucket with our storage provider, and only this site can read them."
              : "Files are stored on our own server.",
          ],
        }
      : {}),
    securityLog: `Security events (such as logins, password changes and deletions), with the IP address they came from, are kept for ${options.auditRetentionDays} days.`,
  };
}
