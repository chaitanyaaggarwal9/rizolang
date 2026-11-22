import { createHash } from "node:crypto";
import type { ResolvedApi, ResolvedAuth } from "./check-api.js";
import type { ResolvedField, ResolvedModel } from "./checker.js";
import { FIELD_TYPES } from "./types.js";

/**
 * A structured description of the database schema. `schema.sql`, the first
 * migration and every later migration are all generated from it, and it is
 * what `migrations/rizo-schema.json` stores between builds.
 *
 * Constraint names follow PostgreSQL's own default pattern
 * (`<table>_<column>_key`, `_check`, `_fkey`, `_idx`), so databases created
 * from earlier versions, which used unnamed constraints, match.
 */

export interface Column {
  readonly name: string;
  /** PostgreSQL type, e.g. "TEXT". */
  readonly type: string;
  readonly primaryKey: boolean;
  /** SQL default expression, e.g. "gen_random_uuid()". */
  readonly default: string | null;
  readonly notNull: boolean;
  /** Name of the UNIQUE constraint, or null. */
  readonly unique: string | null;
  readonly check: { readonly name: string; readonly expr: string } | null;
  /** For the role column: the allowed values. */
  readonly values: readonly string[] | null;
  /** A short note written above the column in schema.sql. */
  readonly comment: string | null;
  /** Holds AES-256-GCM ciphertext written by the runtime. Absent means false. */
  readonly encrypted?: true;
}

export interface ForeignKey {
  readonly name: string;
  readonly column: string;
  readonly refTable: string;
  readonly onDelete: "RESTRICT" | "SET NULL" | "CASCADE";
  /** Name of the index on the column. */
  readonly index: string;
}

/** An index the compiler adds so a list endpoint's filters and order are fast. */
export interface Index {
  readonly name: string;
  readonly columns: readonly string[];
}

export interface Table {
  readonly name: string;
  readonly columns: readonly Column[];
  readonly foreignKeys: readonly ForeignKey[];
  /** Indexes for list endpoints. Older snapshots don't have this. */
  readonly indexes?: readonly Index[];
  readonly comment: string | null;
}

export interface Schema {
  readonly version: 1;
  readonly tables: readonly Table[];
}

/** Name of the table that stores login sessions. Model tables can never start with "_". */
export const SESSIONS_TABLE = "_rizo_sessions";

const MAX_NAME = 63;

/** A constraint or index name, shortened with a hash if PostgreSQL would truncate it. */
export function constraintName(table: string, column: string, suffix: string): string {
  const full = `${table}_${column}_${suffix}`;
  if (full.length <= MAX_NAME) return full;
  const hash = createHash("sha256").update(full).digest("hex").slice(0, 8);
  return `${full.slice(0, MAX_NAME - suffix.length - hash.length - 2)}_${hash}_${suffix}`;
}

/** A role name as a SQL string literal. Role names are validated as [a-z][A-Za-z0-9]*. */
export const roleLiteral = (role: string): string => {
  if (!/^[a-z][A-Za-z0-9]*$/.test(role)) throw new Error(`unsafe role: ${role}`);
  return `'${role}'`;
};

/** Quote a compiler-validated identifier. Names contain only [a-z0-9_], so this is always safe. */
export const q = (identifier: string): string => {
  if (!/^[a-z_][a-z0-9_]*$/.test(identifier)) throw new Error(`unsafe identifier: ${identifier}`);
  return `"${identifier}"`;
};

const idColumn: Column = {
  name: "id", type: "UUID", primaryKey: true, default: "gen_random_uuid()", notNull: false,
  unique: null, check: null, values: null, comment: null,
};

/** Hidden column holding when a record was created, for models with `keep`. Fields can't start with "_", so it can't clash. */
export const CREATED_COLUMN = "_created_at";

/** Name of the table that holds rate-limit counters (apps with a server). */
export const LIMITS_TABLE = "_rizo_rate_limits";

/** Passkey tables (apps with an auth line). */
export const PASSKEYS_TABLE = "_rizo_passkeys";
export const CHALLENGES_TABLE = "_rizo_challenges";

/** Email tables (apps with an auth line): accounts waiting for their email to be confirmed, and one-time email links. */
export const UNVERIFIED_TABLE = "_rizo_unverified";
export const EMAIL_TOKENS_TABLE = "_rizo_email_tokens";

/** The one shared "Deleted user" account that keeps deleted accounts' records (apps with an auth line). */
export const GHOST_TABLE = "_rizo_deleted_user";

/** API tokens for scripts and AI agents (apps with an auth line). */
export const AGENT_TOKENS_TABLE = "_rizo_tokens";

/** Name of the security audit log table (apps with a server). */
export const AUDIT_TABLE = "_rizo_audit";

/**
 * @param server true when the app has a generated server (auth, api or pages),
 *               which needs its own tables, such as rate-limit counters.
 */
export function buildSchema(
  models: readonly ResolvedModel[],
  auth: ResolvedAuth | undefined,
  server = false,
  apis: readonly ResolvedApi[] = [],
): Schema {
  const tables: Table[] = models.map((model) => {
    const columns: Column[] = [idColumn, ...model.fields.map((f) => fieldColumn(model.table, f))];
    if (auth !== undefined && auth.model === model && auth.roles.length > 0) {
      columns.push({
        name: "role", type: "TEXT", primaryKey: false, default: null, notNull: false, unique: null,
        check: { name: constraintName(model.table, "role", "check"), expr: `${q("role")} IN (${auth.roles.map(roleLiteral).join(", ")})` },
        values: [...auth.roles],
        comment: "role: assigned by admins only, never accepted from requests or returned",
      });
    }
    const foreignKeys: ForeignKey[] = model.fields.flatMap((f) => {
      if (f.link === undefined) return [];
      const target = models.find((m) => m.name === f.link);
      if (target === undefined) throw new Error(`unresolved link ${model.name}.${f.name}`);
      return [{
        name: constraintName(model.table, f.column, "fkey"),
        column: f.column,
        refTable: target.table,
        onDelete: f.optional ? "SET NULL" : "RESTRICT",
        index: constraintName(model.table, f.column, "idx"),
      }];
    });
    const indexes = listIndexes(model, apis);
    if (model.keep !== undefined) {
      columns.push({
        name: CREATED_COLUMN, type: "TIMESTAMPTZ", primaryKey: false, default: "now()", notNull: true, unique: null, check: null, values: null,
        comment: `${CREATED_COLUMN}: when the record was created; records are deleted ${model.keep.amount} ${model.keep.unit} later (keep)`,
      });
      indexes.push({ name: constraintName(model.table, CREATED_COLUMN, "idx"), columns: [CREATED_COLUMN] });
    }
    return { name: model.table, columns, foreignKeys, indexes, comment: null };
  });

  if (auth !== undefined) {
    const t = SESSIONS_TABLE;
    const col = (name: string, type: string, extra: Partial<Column>): Column => ({
      name, type, primaryKey: false, default: null, notNull: true, unique: null, check: null, values: null, comment: null, ...extra,
    });
    tables.push({
      name: t,
      comment: "Login sessions. Only a SHA-256 hash of each session token is stored.",
      columns: [
        col("token_hash", "TEXT", { primaryKey: true, notNull: false }),
        col("user_id", "UUID", {}),
        col("created_at", "TIMESTAMPTZ", { default: "now()" }),
        // Ends after 7 days without use (moved forward on use), and never after ends_at.
        col("expires_at", "TIMESTAMPTZ", {}),
        // The public handle for listing and logging out one device: never the token hash.
        col("id", "UUID", { default: "gen_random_uuid()", unique: constraintName(t, "id", "key") }),
        col("ends_at", "TIMESTAMPTZ", { default: "now() + interval '30 days'" }),
        col("last_seen_at", "TIMESTAMPTZ", { default: "now()" }),
        col("device", "TEXT", { default: "'Unknown device'", comment: "device: a label such as \"Chrome on macOS\" from a fixed list, never the raw User-Agent" }),
      ],
      foreignKeys: [{
        name: constraintName(t, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "CASCADE", index: constraintName(t, "user_id", "idx"),
      }],
    });

    // Passkeys: only public keys are stored, so this table holds nothing secret.
    const pk = PASSKEYS_TABLE;
    tables.push({
      name: pk,
      comment: "Passkeys (WebAuthn). Only public keys: nothing here can be used to log in.",
      columns: [
        col("id", "TEXT", { primaryKey: true, notNull: false }),
        col("user_id", "UUID", {}),
        col("public_key", "TEXT", {}),
        col("algorithm", "INTEGER", {}),
        col("sign_count", "BIGINT", {}),
        col("name", "TEXT", {}),
        col("created_at", "TIMESTAMPTZ", { default: "now()" }),
        col("last_used_at", "TIMESTAMPTZ", { notNull: false }),
      ],
      foreignKeys: [{
        name: constraintName(pk, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "CASCADE", index: constraintName(pk, "user_id", "idx"),
      }],
    });
    // One-time passkey challenges (hashed), valid for a few minutes.
    tables.push({
      name: CHALLENGES_TABLE,
      comment: "One-time passkey challenges. Only hashes are stored; each is deleted when used.",
      columns: [
        col("id", "TEXT", { primaryKey: true, notNull: false }),
        col("purpose", "TEXT", {}),
        col("user_id", "UUID", { notNull: false }),
        col("expires_at", "TIMESTAMPTZ", {}),
      ],
      foreignKeys: [],
    });
    // Accounts that haven't confirmed their email yet. Accounts that existed
    // before email confirmation was added are not listed, so they stay usable.
    tables.push({
      name: UNVERIFIED_TABLE,
      comment: "Accounts whose email is not confirmed yet. They can't log in until it is.",
      columns: [
        col("user_id", "UUID", { primaryKey: true, notNull: false }),
        col("created_at", "TIMESTAMPTZ", { default: "now()" }),
      ],
      foreignKeys: [{
        name: constraintName(UNVERIFIED_TABLE, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "CASCADE", index: constraintName(UNVERIFIED_TABLE, "user_id", "idx"),
      }],
    });
    // At most one row: which account is the shared "Deleted user".
    tables.push({
      name: GHOST_TABLE,
      comment: "The shared \"Deleted user\" account. Records of deleted accounts are given to it.",
      columns: [
        col("one", "BOOLEAN", { primaryKey: true, notNull: false, default: "true", check: { name: constraintName(GHOST_TABLE, "one", "check"), expr: `${q("one")}` } }),
        col("user_id", "UUID", {}),
      ],
      foreignKeys: [{
        name: constraintName(GHOST_TABLE, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "RESTRICT", index: constraintName(GHOST_TABLE, "user_id", "idx"),
      }],
    });
    // API tokens: only hashes, each limited to chosen endpoints and an expiry.
    tables.push({
      name: AGENT_TOKENS_TABLE,
      comment: "API tokens for scripts and AI agents. Only SHA-256 hashes are stored.",
      columns: [
        col("id", "UUID", { primaryKey: true, notNull: false, default: "gen_random_uuid()" }),
        col("token_hash", "TEXT", { unique: constraintName(AGENT_TOKENS_TABLE, "token_hash", "key") }),
        col("user_id", "UUID", {}),
        col("name", "TEXT", {}),
        col("endpoints", "TEXT", { comment: "endpoints: a JSON list such as [\"GET /api/posts\"]" }),
        col("created_at", "TIMESTAMPTZ", { default: "now()" }),
        col("expires_at", "TIMESTAMPTZ", {}),
        col("last_used_at", "TIMESTAMPTZ", { notNull: false }),
      ],
      foreignKeys: [{
        name: constraintName(AGENT_TOKENS_TABLE, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "CASCADE", index: constraintName(AGENT_TOKENS_TABLE, "user_id", "idx"),
      }],
    });
    // Links sent by email (confirm the address, reset the password).
    tables.push({
      name: EMAIL_TOKENS_TABLE,
      comment: "One-time links sent by email. Only hashes are stored; each is deleted when used.",
      columns: [
        col("id", "TEXT", { primaryKey: true, notNull: false }),
        col("user_id", "UUID", {}),
        col("purpose", "TEXT", {}),
        col("expires_at", "TIMESTAMPTZ", {}),
      ],
      foreignKeys: [{
        name: constraintName(EMAIL_TOKENS_TABLE, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "CASCADE", index: constraintName(EMAIL_TOKENS_TABLE, "user_id", "idx"),
      }],
    });
  }
  if (server) {
    const col = (name: string, type: string, primaryKey = false): Column => ({
      name, type, primaryKey, default: null, notNull: !primaryKey, unique: null, check: null, values: null, comment: null,
    });
    tables.push({
      name: LIMITS_TABLE,
      comment: "Rate-limit counters, shared by every server process. Keys are hashes, never raw IP addresses.",
      columns: [col("key", "TEXT", true), col("expires_at", "TIMESTAMPTZ"), col("count", "INTEGER")],
      foreignKeys: [],
    });
    const optional = (name: string, type: string): Column => ({ ...col(name, type), notNull: false });
    tables.push({
      name: AUDIT_TABLE,
      comment: "Security audit log: logins, password and role changes, deletes. No passwords, tokens or bodies. Kept 365 days by default.",
      columns: [
        { ...col("id", "UUID", true), default: "gen_random_uuid()" },
        { ...col("at", "TIMESTAMPTZ"), default: "now()" },
        col("action", "TEXT"),
        // No foreign keys: entries must outlive the accounts and records they describe.
        optional("user_id", "UUID"),
        optional("target_id", "UUID"),
        optional("ip", "TEXT"),
        optional("detail", "TEXT"),
      ],
      foreignKeys: [],
      indexes: [
        { name: constraintName(AUDIT_TABLE, "at", "idx"), columns: ["at"] },
        { name: constraintName(AUDIT_TABLE, "user_id_at", "idx"), columns: ["user_id", "at"] },
        { name: constraintName(AUDIT_TABLE, "target_id_at", "idx"), columns: ["target_id", "at"] },
      ],
    });
  }
  return { version: 1, tables };
}

/**
 * One index per distinct list query on this model: its filter columns (in a
 * fixed order), then its sort column, then id. Equality filters followed by
 * the sort order let PostgreSQL read each page straight from the index,
 * including "Load more" (which continues after the last id).
 */
function listIndexes(model: ResolvedModel, apis: readonly ResolvedApi[]): Index[] {
  const out = new Map<string, Index>();
  for (const api of apis) {
    const q = api.query;
    if (q.action !== "list" || q.model !== model) continue;
    const filters = q.filters.map((f) => f.field.column).sort();
    const columns = [...filters, ...(q.order.field === undefined ? [] : [q.order.field.column]), "id"];
    if (columns.length === 1) continue; // only id: the primary key already covers it
    const key = columns.join(",");
    if (!out.has(key)) out.set(key, { name: constraintName(model.table, columns.join("_"), "idx"), columns });
  }
  return [...out.values()];
}

export function createListIndex(table: string, index: Index): string {
  return `CREATE INDEX ${q(index.name)} ON ${q(table)} (${index.columns.map(q).join(", ")});`;
}

function fieldColumn(table: string, f: ResolvedField): Column {
  const info = FIELD_TYPES[f.type];
  const col = q(f.column);
  if (f.encrypted) {
    // The database only sees ciphertext. Limits and formats are checked by
    // the runtime before encrypting.
    return {
      name: f.column, type: "TEXT", primaryKey: false, default: null, notNull: !f.optional,
      unique: null, check: null, values: null, encrypted: true,
      comment: `${f.name}: encrypted with AES-256-GCM by the server; the database never sees the value`,
    };
  }
  const checks: string[] = [];
  if (info.secret) {
    // Password limits apply to the plain-text input, not to the stored hash.
  } else if (info.length !== undefined) {
    checks.push(...rangeChecks(`char_length(${col})`, f.min !== undefined && f.min > 0 ? f.min : undefined, f.max));
  } else if (info.valueRange !== undefined) {
    checks.push(...rangeChecks(col, f.min, f.max));
  }
  if (f.type === "Email") {
    checks.push(`${col} = lower(${col})`);
    checks.push(`${col} ~ '^[^@[:space:]]+@[^@[:space:]]+[.][^@[:space:]]+$'`);
  }
  return {
    name: f.column,
    type: info.sql,
    primaryKey: false,
    default: null,
    notNull: !f.optional,
    unique: f.unique ? constraintName(table, f.column, "key") : null,
    check: checks.length > 0 ? { name: constraintName(table, f.column, "check"), expr: checks.join(" AND ") } : null,
    values: null,
    comment: info.secret ? `${f.name}: stored only as a salted hash, never as plain text` : null,
  };
}

function rangeChecks(expr: string, min: number | undefined, max: number | undefined): string[] {
  if (min !== undefined && max !== undefined) return [`${expr} BETWEEN ${min} AND ${max}`];
  if (min !== undefined) return [`${expr} >= ${min}`];
  if (max !== undefined) return [`${expr} <= ${max}`];
  return [];
}

// ---------------------------------------------------------------- rendering

export function columnDefinition(c: Column): string {
  const parts = [`${q(c.name)} ${c.type}`];
  if (c.primaryKey) parts.push("PRIMARY KEY");
  if (c.default !== null) parts.push(`DEFAULT ${c.default}`);
  if (c.notNull) parts.push("NOT NULL");
  if (c.unique !== null) parts.push(`CONSTRAINT ${q(c.unique)} UNIQUE`);
  if (c.check !== null) parts.push(`CONSTRAINT ${q(c.check.name)} CHECK (${c.check.expr})`);
  return parts.join(" ");
}

export function createTable(t: Table): string {
  const lines = t.columns.map((c) => `${c.comment !== null ? `  -- ${c.comment}\n` : ""}  ${columnDefinition(c)}`);
  return `${t.comment !== null ? `-- ${t.comment}\n` : ""}CREATE TABLE ${q(t.name)} (\n${lines.join(",\n")}\n);`;
}

export function addForeignKey(table: string, fk: ForeignKey): string {
  return `ALTER TABLE ${q(table)} ADD CONSTRAINT ${q(fk.name)} FOREIGN KEY (${q(fk.column)}) REFERENCES ${q(fk.refTable)} (${q("id")}) ON DELETE ${fk.onDelete};`;
}

export function createIndex(table: string, fk: ForeignKey): string {
  return `CREATE INDEX ${q(fk.index)} ON ${q(table)} (${q(fk.column)});`;
}

/** Statements that create the whole schema. Foreign keys come last, so tables may link in any order. */
export function createStatements(schema: Schema): string[] {
  const out = schema.tables.map(createTable);
  for (const t of schema.tables) {
    for (const fk of t.foreignKeys) out.push(addForeignKey(t.name, fk), createIndex(t.name, fk));
  }
  for (const t of schema.tables) {
    for (const index of t.indexes ?? []) out.push(createListIndex(t.name, index));
  }
  return out;
}
