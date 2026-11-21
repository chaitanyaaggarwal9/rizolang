import type { FieldDecl, ModelDecl, Modifier, Program } from "./ast.js";
import { type ResolvedApi, type ResolvedAuth, checkApis, checkAuth } from "./check-api.js";
import { type ResolvedPage, checkPages } from "./check-page.js";
import { type Diagnostic, type Span, didYouMean, diagnostic } from "./diagnostics.js";
import { FIELD_TYPES, FIELD_TYPE_NAMES, type FieldTypeName, TYPE_ALIASES, isFieldTypeName } from "./types.js";

/** A fully validated model, ready for the emitters. */
export interface ResolvedModel {
  readonly name: string;
  /** PostgreSQL table name, e.g. "blog_posts". */
  readonly table: string;
  /** Explicitly declared fields (the automatic `id` is not included). */
  readonly fields: readonly ResolvedField[];
}

export interface ResolvedField {
  readonly name: string;
  /** PostgreSQL column name, e.g. "password_hash". */
  readonly column: string;
  /** Field type. A link to another model has type "ID" and `link` set. */
  readonly type: FieldTypeName;
  /** For links: the name of the model this field points to. */
  readonly link: string | undefined;
  readonly unique: boolean;
  readonly optional: boolean;
  /** Excluded from public types (but not hashed). */
  readonly private: boolean;
  /** Effective lower limit (length or value), after defaults. */
  readonly min: number | undefined;
  /** Effective upper limit (length or value), after defaults. */
  readonly max: number | undefined;
}

export type CheckResult =
  | {
      readonly ok: true;
      readonly models: readonly ResolvedModel[];
      readonly auth: ResolvedAuth | undefined;
      readonly apis: readonly ResolvedApi[];
      readonly pages: readonly ResolvedPage[];
    }
  | { readonly ok: false; readonly diagnostics: readonly Diagnostic[] };

/** Model names that would clash with built-in types in generated code. */
const RESERVED_MODEL_NAMES: readonly string[] = [
  ...FIELD_TYPE_NAMES, "PasswordHash", "String", "Boolean", "Object", "Array", "Promise", "Record",
  "Error", "Map", "Set", "Symbol", "BigInt", "Function", "JSON", "Math", "Partial", "Readonly",
];

/** PostgreSQL truncates identifiers longer than this, which could merge names. */
const MAX_IDENTIFIER_LENGTH = 63;

export function toSnakeCase(name: string): string {
  return name
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .replace(/([A-Z])([A-Z][a-z])/g, "$1_$2")
    .toLowerCase();
}

export function tableName(modelName: string): string {
  const snake = toSnakeCase(modelName);
  if (/(s|x|z|ch|sh)$/.test(snake)) return `${snake}es`;
  if (/[^aeiou]y$/.test(snake)) return `${snake.slice(0, -1)}ies`;
  return `${snake}s`;
}

export function columnName(fieldName: string, type: FieldTypeName, isLink = false): string {
  const snake = toSnakeCase(fieldName);
  if (isLink) return `${snake}_id`;
  return FIELD_TYPES[type].secret ? `${snake}_hash` : snake;
}

/** True for fields that must never appear in a public type or response. */
export function isHidden(f: ResolvedField): boolean {
  return FIELD_TYPES[f.type].secret || f.private;
}

/**
 * Field names that clearly hold a password. Storing these as Text would keep
 * them in plain text and expose them in public types, so they must use Password.
 */
export function looksLikePassword(fieldName: string): boolean {
  return /^(password|passwd|pwd|passcode|passphrase)$/i.test(fieldName) ||
    /(Password|Passwd|Passcode|Passphrase)$/.test(fieldName);
}

const pascal = (s: string): string => s.charAt(0).toUpperCase() + s.slice(1);
const camel = (s: string): string => s.charAt(0).toLowerCase() + s.slice(1);

/**
 * Validates names, types and modifiers. Collects every error it finds so the
 * author can fix them all in one pass.
 */
export function check(program: Program, file: string): CheckResult {
  const errors: Diagnostic[] = [];
  const err = (code: string, span: Span, message: string, fix: string): void => {
    errors.push(diagnostic(code, file, span, message, fix));
  };

  const models: ResolvedModel[] = [];
  const seenModels = new Map<string, ModelDecl>();
  const seenTables = new Map<string, ModelDecl>();
  const seenTypeNames = new Map<string, ModelDecl>();
  const modelNames = program.models.map((m) => m.name);

  for (const model of program.models) {
    checkModelName(model);
    const fields = model.fields.flatMap((f) => {
      const r = checkField(model, f);
      return r === undefined ? [] : [r];
    });
    if (model.fields.length === 0) {
      err("RZ0313", model.nameSpan, `Model "${model.name}" has no fields.`,
        `Add at least one field, for example \`name: Text\`, or remove the model.`);
    }
    checkColumnCollisions(model, fields);
    models.push({ name: model.name, table: tableName(model.name), fields });
  }

  // Endpoint checks need resolved models; skip them if any model is invalid,
  // since their errors would only repeat the model errors.
  if (errors.length > 0) return { ok: false, diagnostics: errors };
  const auth = checkAuth(program.auths, models, err);
  const apis = checkApis(program.apis, models, auth, program.auths.length > 0, err);
  const pages = checkPages(program.pages, auth, apis, program.auths.length > 0, err);
  return errors.length > 0 ? { ok: false, diagnostics: errors } : { ok: true, models, auth, apis, pages };

  function checkModelName(model: ModelDecl): void {
    const { name, nameSpan } = model;
    if (!/^[A-Z]/.test(name)) {
      err("RZ0309", nameSpan, `Model name "${name}" must start with a capital letter.`,
        `Rename it to "${pascal(name)}". Model names use PascalCase, like BlogPost.`);
    }
    if (RESERVED_MODEL_NAMES.includes(name)) {
      err("RZ0311", nameSpan, `"${name}" is a reserved name and cannot be used as a model name.`,
        `Choose a more specific name, for example "${name}Record".`);
    }
    const dup = seenModels.get(name);
    if (dup !== undefined) {
      err("RZ0306", nameSpan, `Model "${name}" is already defined on line ${dup.nameSpan.line}.`,
        "Rename one of the two models or merge their fields.");
      return;
    }
    seenModels.set(name, model);

    const table = tableName(name);
    const otherTable = seenTables.get(table);
    if (otherTable !== undefined) {
      err("RZ0312", nameSpan,
        `Model "${name}" and model "${otherTable.name}" would both use the database table "${table}".`,
        "Rename one of the two models so their names differ by more than letter case.");
    } else {
      seenTables.set(table, model);
    }
    if (table.length > MAX_IDENTIFIER_LENGTH) {
      err("RZ0314", nameSpan, `Model name "${name}" is too long for a database table name.`,
        `Use a shorter name (the table name "${table}" must be at most ${MAX_IDENTIFIER_LENGTH} characters).`);
    }
    for (const typeName of [name, `${name}Public`, `${name}Input`]) {
      const other = seenTypeNames.get(typeName);
      if (other !== undefined && other !== model) {
        err("RZ0312", nameSpan,
          `Model "${name}" clashes with model "${other.name}": both would generate the TypeScript type "${typeName}".`,
          `Rename model "${name}". Model names must not end in "Public" or "Input" when the shorter model exists.`);
      }
      seenTypeNames.set(typeName, model);
    }
  }

  function checkField(model: ModelDecl, field: FieldDecl): ResolvedField | undefined {
    let ok = true;
    const where = `${model.name}.${field.name}`;

    if (!/^[a-z]/.test(field.name)) {
      ok = false;
      err("RZ0310", field.nameSpan, `Field name "${field.name}" must start with a lowercase letter.`,
        `Rename it to "${camel(field.name)}". Field names use camelCase, like firstName.`);
    }
    if (field.name === "id") {
      ok = false;
      err("RZ0308", field.nameSpan, `Field name "id" is reserved in model "${model.name}".`,
        "Remove this field: every model gets `id: ID` automatically. To store another record's ID, use a name like userId.");
    }
    const dup = model.fields.find((f) => f.name === field.name);
    if (dup !== undefined && dup !== field) {
      ok = false;
      err("RZ0307", field.nameSpan, `Field "${where}" is already defined on line ${dup.nameSpan.line}.`,
        "Remove or rename one of the two fields.");
    }

    const isLink = modelNames.includes(field.typeName) && !isFieldTypeName(field.typeName);
    if (!isFieldTypeName(field.typeName) && !isLink) {
      const alias = TYPE_ALIASES[field.typeName];
      const guess = alias ?? didYouMean(field.typeName, [...FIELD_TYPE_NAMES, ...modelNames]);
      const models = modelNames.length > 0 ? `, or a model name (${modelNames.join(", ")})` : "";
      err("RZ0301", field.typeSpan, `Unknown field type "${field.typeName}" on field "${where}".`,
        guess !== undefined
          ? `Use "${guess}" instead. Valid types: ${FIELD_TYPE_NAMES.join(", ")}${models}.`
          : `Use one of: ${FIELD_TYPE_NAMES.join(", ")}${models}.`);
      return undefined;
    }
    // A link is stored as the linked record's ID.
    const type: FieldTypeName = isLink ? "ID" : (field.typeName as FieldTypeName);
    const info = FIELD_TYPES[type];

    if (type !== "Password" && looksLikePassword(field.name)) {
      err("RZ0315", field.typeSpan, `Field "${where}" looks like a password but has type ${type}.`,
        `Use the Password type so it is hashed and never returned: \`${field.name}: Password\`.`);
      return undefined;
    }

    const seen = new Map<string, Modifier>();
    let min: number | undefined;
    let max: number | undefined;
    let minMod: Modifier | undefined;
    for (const m of field.modifiers) {
      if (seen.has(m.kind)) {
        ok = false;
        err("RZ0303", m.span, `Modifier "${m.kind}" appears more than once on field "${where}".`,
          `Remove the extra "${m.kind}".`);
        continue;
      }
      seen.set(m.kind, m);
      if (!info.modifiers.includes(m.kind)) {
        ok = false;
        const reason = info.disallowedReason?.[m.kind] ?? "";
        const shown = isLink ? `link (${field.typeName})` : type;
        const why = isLink && (m.kind === "min" || m.kind === "max") ? "A link has no size or range. " : reason ? `${reason} ` : "";
        err("RZ0302", m.span, `Modifier "${m.kind}" is not allowed on ${shown} field "${where}".`,
          `${why}Remove "${m.kind}". ${isLink ? "Links" : type} allow: ${info.modifiers.join(", ")}.`);
        continue;
      }
      if (m.kind === "min" || m.kind === "max") {
        if (!checkLimit(type, where, m.kind, m.value, m.valueSpan)) {
          ok = false;
          continue;
        }
        if (m.kind === "min") {
          min = m.value;
          minMod = m;
        } else {
          max = m.value;
        }
      }
    }

    const length = info.length;
    const effMin = min ?? (length !== undefined && length.defaultMin > 0 ? length.defaultMin : undefined);
    const effMax = max ?? length?.defaultMax;
    if (effMin !== undefined && effMax !== undefined && effMin > effMax) {
      ok = false;
      const span = minMod !== undefined && minMod.kind === "min" ? minMod.valueSpan : field.typeSpan;
      err("RZ0304", span, `On field "${where}", min (${effMin}) is greater than max (${effMax}).`,
        `Make min less than or equal to max${max === undefined ? `, or add \`max ${effMin}\` or higher` : ""}.`);
    }

    if (!ok) return undefined;
    return {
      name: field.name,
      column: columnName(field.name, type, isLink),
      type,
      link: isLink ? field.typeName : undefined,
      unique: seen.has("unique"),
      optional: seen.has("optional"),
      private: seen.has("private"),
      min: effMin,
      max: effMax,
    };
  }

  function checkLimit(type: FieldTypeName, where: string, kind: "min" | "max", value: number, span: Span): boolean {
    const info = FIELD_TYPES[type];
    const range = info.length ?? info.valueRange;
    if (range === undefined) return true;
    let lowest = range.lowest;
    // A maximum length of 0 would make every value invalid.
    if (info.length !== undefined && kind === "max") lowest = Math.max(lowest, 1);
    if (value >= lowest && value <= range.highest) return true;
    const unit = info.length !== undefined ? " characters" : "";
    const why = type === "Password" && kind === "min" && value < range.lowest
      ? ` Passwords must be at least ${range.lowest} characters long.`
      : "";
    err("RZ0305", span, `"${kind} ${value}" is out of range for ${type} field "${where}".${why}`,
      `Use a ${kind} between ${lowest} and ${range.highest}${unit}.`);
    return false;
  }

  function checkColumnCollisions(model: ModelDecl, fields: readonly ResolvedField[]): void {
    const columns = new Map<string, string>([["id", "id"]]);
    for (const f of fields) {
      const decl = model.fields.find((d) => d.name === f.name);
      const span = decl?.nameSpan ?? model.nameSpan;
      const other = columns.get(f.column);
      if (other !== undefined) {
        err("RZ0312", span,
          `Field "${model.name}.${f.name}" and field "${model.name}.${other}" would both use the database column "${f.column}".`,
          `Rename "${f.name}".${f.column.endsWith("_hash") || other.endsWith("Hash") ? " Password fields are stored in a column named <field>_hash." : ""}`);
      } else {
        columns.set(f.column, f.name);
      }
      if (f.column.length > MAX_IDENTIFIER_LENGTH) {
        err("RZ0314", span, `Field name "${f.name}" is too long for a database column name.`,
          `Use a shorter name (the column "${f.column}" must be at most ${MAX_IDENTIFIER_LENGTH} characters).`);
      }
    }
  }
}
