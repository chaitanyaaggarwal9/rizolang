import {
  type ForeignKey,
  type Schema,
  type Table,
  addForeignKey,
  columnDefinition,
  createListIndex,
  createIndex,
  createStatements,
  createTable,
  q,
  roleLiteral,
} from "./schema.js";
import { VERSION } from "./version.js";

/**
 * Migration planning: compare the schema from the last build (the snapshot in
 * migrations/rizo-schema.json) with the schema of this build, and produce the
 * SQL that turns one into the other.
 *
 * Changes that would destroy data (dropping a table or column, changing a
 * column's type, removing a role) are listed in `dataLoss`; the CLI refuses
 * them unless `--allow-data-loss` is given.
 */

export interface MigrationPlan {
  /** SQL statements, in order. Empty when nothing changed. */
  readonly statements: readonly string[];
  /** One line per change, for the migration header and the CLI output. */
  readonly summary: readonly string[];
  /** Changes that destroy data. */
  readonly dataLoss: readonly string[];
  /** A short name for the migration file, e.g. "add_posts_views". */
  readonly slug: string;
}

export const SNAPSHOT_FILE = "rizo-schema.json";
export const MIGRATION_FILE = /^(\d{4})_([a-z0-9_]+)\.sql$/;

export function initialPlan(schema: Schema): MigrationPlan {
  return {
    statements: createStatements(schema),
    summary: schema.tables.map((t) => `create table ${t.name}`),
    dataLoss: [],
    slug: "initial",
  };
}

export function planMigration(prev: Schema, next: Schema): MigrationPlan {
  const statements: string[] = [];
  const summary: string[] = [];
  const dataLoss: string[] = [];
  const prevTables = new Map(prev.tables.map((t) => [t.name, t]));
  const nextTables = new Map(next.tables.map((t) => [t.name, t]));
  const fkKey = (fk: ForeignKey): string => `${fk.name}|${fk.column}|${fk.refTable}|${fk.onDelete}`;

  // 1. Drop foreign keys that change or disappear, before any table or column goes.
  for (const t of prev.tables) {
    const nt = nextTables.get(t.name);
    for (const fk of t.foreignKeys) {
      const kept = nt?.foreignKeys.find((x) => fkKey(x) === fkKey(fk));
      if (kept === undefined && nt !== undefined && nt.columns.some((c) => c.name === fk.column)) {
        statements.push(`ALTER TABLE ${q(t.name)} DROP CONSTRAINT ${q(fk.name)};`);
      }
    }
  }

  // 2. Drop tables that are gone.
  for (const t of prev.tables) {
    if (!nextTables.has(t.name)) {
      statements.push(`DROP TABLE ${q(t.name)};`);
      summary.push(`drop table ${t.name}`);
      if (!t.name.startsWith("_rizo_")) dataLoss.push(`table "${t.name}" and all its rows would be deleted`);
    }
  }

  // 3. Create new tables.
  for (const t of next.tables) {
    if (!prevTables.has(t.name)) {
      statements.push(createTable(t));
      summary.push(`create table ${t.name}`);
    }
  }

  // 4. Change columns of tables that stay.
  for (const nt of next.tables) {
    const pt = prevTables.get(nt.name);
    if (pt === undefined) continue;
    columnChanges(pt, nt, statements, summary, dataLoss);
  }

  // 5. List indexes: drop the ones no list uses any more, create new ones.
  for (const pt of prev.tables) {
    const nt = nextTables.get(pt.name);
    if (nt === undefined) continue; // dropped with the table
    for (const index of pt.indexes ?? []) {
      if (!(nt.indexes ?? []).some((x) => x.name === index.name)) {
        // IF EXISTS: dropping a column in the same migration already removed its indexes.
        statements.push(`DROP INDEX IF EXISTS ${q(index.name)};`);
        summary.push(`drop index ${index.name}`);
      }
    }
  }
  for (const nt of next.tables) {
    const pt = prevTables.get(nt.name);
    for (const index of nt.indexes ?? []) {
      if (!(pt?.indexes ?? []).some((x) => x.name === index.name)) {
        statements.push(createListIndex(nt.name, index));
        summary.push(`add index on ${nt.name} (${index.columns.join(", ")})`);
      }
    }
  }

  // 6. Add new or changed foreign keys and their indexes.
  for (const nt of next.tables) {
    const pt = prevTables.get(nt.name);
    for (const fk of nt.foreignKeys) {
      const old = pt?.foreignKeys.find((x) => x.name === fk.name);
      if (old !== undefined && fkKey(old) === fkKey(fk)) continue;
      statements.push(addForeignKey(nt.name, fk));
      summary.push(`${old === undefined ? "add" : "change"} link ${nt.name}.${fk.column} -> ${fk.refTable}`);
      const columnExisted = pt?.columns.some((c) => c.name === fk.column) ?? false;
      if (old === undefined || !columnExisted) statements.push(createIndex(nt.name, fk));
    }
  }

  return { statements, summary, dataLoss, slug: slugFor(summary) };
}

function columnChanges(pt: Table, nt: Table, statements: string[], summary: string[], dataLoss: string[]): void {
  const t = q(nt.name);
  const prevCols = new Map(pt.columns.map((c) => [c.name, c]));
  const nextCols = new Map(nt.columns.map((c) => [c.name, c]));

  for (const c of pt.columns) {
    if (!nextCols.has(c.name)) {
      statements.push(`ALTER TABLE ${t} DROP COLUMN ${q(c.name)};`);
      summary.push(`drop column ${nt.name}.${c.name}`);
      dataLoss.push(`column "${nt.name}.${c.name}" and its values would be deleted`);
    }
  }
  for (const c of nt.columns) {
    const old = prevCols.get(c.name);
    if (old === undefined) {
      statements.push(`ALTER TABLE ${t} ADD COLUMN ${columnDefinition(c)};`);
      summary.push(`add column ${nt.name}.${c.name}`);
      continue;
    }
    if (old.type !== c.type || old.primaryKey !== c.primaryKey) {
      // A type change cannot keep the values safely: replace the column.
      statements.push(`ALTER TABLE ${t} DROP COLUMN ${q(c.name)};`, `ALTER TABLE ${t} ADD COLUMN ${columnDefinition(c)};`);
      summary.push(`change type of ${nt.name}.${c.name} from ${old.type} to ${c.type}`);
      dataLoss.push(`column "${nt.name}.${c.name}" changes type from ${old.type} to ${c.type}; its values would be deleted`);
      continue;
    }
    const removedValues = (old.values ?? []).filter((v) => !(c.values ?? []).includes(v));
    if (removedValues.length > 0) {
      dataLoss.push(`role${removedValues.length > 1 ? "s" : ""} ${removedValues.join(", ")} would be removed from every account that has ${removedValues.length > 1 ? "them" : "it"}`);
    }
    if (old.check !== null && (c.check === null || old.check.name !== c.check.name || old.check.expr !== c.check.expr)) {
      statements.push(`ALTER TABLE ${t} DROP CONSTRAINT ${q(old.check.name)};`);
    }
    if (removedValues.length > 0) {
      const kept = c.values ?? [];
      statements.push(kept.length > 0
        ? `UPDATE ${t} SET ${q(c.name)} = NULL WHERE ${q(c.name)} NOT IN (${kept.map(roleLiteral).join(", ")});`
        : `UPDATE ${t} SET ${q(c.name)} = NULL;`);
    }
    if (c.check !== null && (old.check === null || old.check.name !== c.check.name || old.check.expr !== c.check.expr)) {
      statements.push(`ALTER TABLE ${t} ADD CONSTRAINT ${q(c.check.name)} CHECK (${c.check.expr});`);
      summary.push(`change limits of ${nt.name}.${c.name}`);
    }
    if (old.unique !== c.unique) {
      if (old.unique !== null) statements.push(`ALTER TABLE ${t} DROP CONSTRAINT ${q(old.unique)};`);
      if (c.unique !== null) statements.push(`ALTER TABLE ${t} ADD CONSTRAINT ${q(c.unique)} UNIQUE (${q(c.name)});`);
      summary.push(`${c.unique !== null ? "add" : "drop"} unique on ${nt.name}.${c.name}`);
    }
    if (old.notNull !== c.notNull) {
      statements.push(`ALTER TABLE ${t} ALTER COLUMN ${q(c.name)} ${c.notNull ? "SET" : "DROP"} NOT NULL;`);
      summary.push(`make ${nt.name}.${c.name} ${c.notNull ? "required" : "optional"}`);
    }
    if (old.default !== c.default) {
      statements.push(`ALTER TABLE ${t} ALTER COLUMN ${q(c.name)} ${c.default === null ? "DROP DEFAULT" : `SET DEFAULT ${c.default}`};`);
    }
  }
}

function slugFor(summary: readonly string[]): string {
  const first = summary[0] ?? "changes";
  const slug = first.replace(/[^a-z0-9]+/gi, "_").replace(/^_|_$/g, "").toLowerCase().slice(0, 40).replace(/_$/, "");
  return summary.length > 1 ? `${slug}_and_more` : slug;
}

/** The text of a migration file. Each file runs inside one transaction (see runtime/migrate.ts). */
export function migrationFile(plan: MigrationPlan, number: number, sourceFile: string): string {
  return [
    `-- Migration ${String(number).padStart(4, "0")}, generated by rizolang ${VERSION} from ${sourceFile}.`,
    "-- Do not edit a migration after it has been applied; make a new one instead.",
    ...plan.summary.map((s) => `--   ${s}`),
    ...(plan.dataLoss.length > 0 ? ["-- WARNING: this migration deletes data (built with --allow-data-loss):", ...plan.dataLoss.map((d) => `--   ${d}`)] : []),
    "",
    plan.statements.join("\n\n"),
    "",
  ].join("\n");
}

/** Read and check a snapshot. Returns an error message for anything unexpected. */
export function parseSnapshot(text: string): { schema: Schema } | { error: string } {
  let data: unknown;
  try {
    data = JSON.parse(text);
  } catch {
    return { error: "it is not valid JSON" };
  }
  const s = data as Partial<Schema>;
  if (typeof s !== "object" || s === null || s.version !== 1 || !Array.isArray(s.tables)) {
    return { error: "it is not a rizolang schema snapshot (version 1)" };
  }
  for (const t of s.tables) {
    if (typeof t?.name !== "string" || !Array.isArray(t.columns) || !Array.isArray(t.foreignKeys)) {
      return { error: "a table entry is malformed" };
    }
    // Every name from the snapshot may end up in SQL (DROP CONSTRAINT ...), so all are checked.
    const names: unknown[] = [t.name];
    const roleOk = (v: unknown): boolean => typeof v === "string" && /^[a-z][A-Za-z0-9]*$/.test(v);
    for (const c of t.columns) {
      if (typeof c?.name !== "string" || typeof c.type !== "string" || !/^[A-Z]+$/.test(c.type)) return { error: `a column of "${t.name}" is malformed` };
      names.push(c.name, ...(c.unique !== null ? [c.unique] : []), ...(c.check !== null ? [c.check?.name] : []));
      if (c.values !== null && (!Array.isArray(c.values) || !c.values.every(roleOk))) return { error: `the role list of "${t.name}" is malformed` };
    }
    for (const fk of t.foreignKeys) names.push(fk?.name, fk?.column, fk?.refTable, fk?.index);
    if (t.indexes !== undefined) {
      if (!Array.isArray(t.indexes)) return { error: `the indexes of "${t.name}" are malformed` };
      for (const index of t.indexes) {
        if (!Array.isArray(index?.columns)) return { error: `an index of "${t.name}" is malformed` };
        names.push(index.name, ...index.columns);
      }
    }
    for (const n of names) {
      if (typeof n !== "string" || !/^[a-z_][a-z0-9_]*$/.test(n)) return { error: `name ${JSON.stringify(n)} in "${String(t.name)}" is not allowed` };
    }
  }
  return { schema: s as Schema };
}

export function snapshotText(schema: Schema): string {
  return `${JSON.stringify(schema, null, 2)}\n`;
}
