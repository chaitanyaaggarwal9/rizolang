import { createHash } from "node:crypto";
import type { ResolvedAuth } from "./check-api.js";
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
}

export interface ForeignKey {
  readonly name: string;
  readonly column: string;
  readonly refTable: string;
  readonly onDelete: "RESTRICT" | "SET NULL" | "CASCADE";
  /** Name of the index on the column. */
  readonly index: string;
}

export interface Table {
  readonly name: string;
  readonly columns: readonly Column[];
  readonly foreignKeys: readonly ForeignKey[];
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

export function buildSchema(models: readonly ResolvedModel[], auth: ResolvedAuth | undefined): Schema {
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
    return { name: model.table, columns, foreignKeys, comment: null };
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
        col("expires_at", "TIMESTAMPTZ", {}),
      ],
      foreignKeys: [{
        name: constraintName(t, "user_id", "fkey"), column: "user_id", refTable: auth.model.table,
        onDelete: "CASCADE", index: constraintName(t, "user_id", "idx"),
      }],
    });
  }
  return { version: 1, tables };
}

function fieldColumn(table: string, f: ResolvedField): Column {
  const info = FIELD_TYPES[f.type];
  const col = q(f.column);
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
  return out;
}
