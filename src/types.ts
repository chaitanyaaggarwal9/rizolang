import type { ModifierKind } from "./ast.js";

/**
 * The field type table: the single source of truth for what each Rizo Lang
 * field type compiles to and which modifiers it accepts.
 */

export type FieldTypeName = "Text" | "Number" | "Bool" | "Email" | "Password" | "Date" | "ID";

export interface LengthRule {
  /** Applied when no `min` is written (0 = no lower limit). */
  readonly defaultMin: number;
  /** Applied when no `max` is written. */
  readonly defaultMax: number;
  /** Smallest value `min`/`max` may be set to. */
  readonly lowest: number;
  /** Largest value `min`/`max` may be set to. */
  readonly highest: number;
}

export interface FieldTypeInfo {
  readonly sql: string;
  /** TypeScript type in the stored (server-side) type. */
  readonly ts: string;
  /** TypeScript type in the input type (what a client sends). */
  readonly tsInput: string;
  readonly modifiers: readonly ModifierKind[];
  /** For text-like types: min/max limit the length in characters. */
  readonly length?: LengthRule;
  /** For numbers: min/max limit the value. */
  readonly valueRange?: { readonly lowest: number; readonly highest: number };
  /** Never included in public types. */
  readonly secret: boolean;
  /** Human-readable reason a modifier is not allowed, keyed by modifier. */
  readonly disallowedReason?: Partial<Record<ModifierKind, string>>;
}

export const INT32_MIN = -2147483648;
export const INT32_MAX = 2147483647;

export const FIELD_TYPES: Readonly<Record<FieldTypeName, FieldTypeInfo>> = {
  Text: {
    sql: "TEXT", ts: "string", tsInput: "string",
    modifiers: ["unique", "optional", "min", "max"],
    length: { defaultMin: 0, defaultMax: 10_000, lowest: 0, highest: 1_000_000 },
    secret: false,
  },
  Number: {
    sql: "INTEGER", ts: "number", tsInput: "number",
    modifiers: ["unique", "optional", "min", "max"],
    valueRange: { lowest: INT32_MIN, highest: INT32_MAX },
    secret: false,
  },
  Bool: {
    sql: "BOOLEAN", ts: "boolean", tsInput: "boolean",
    modifiers: ["optional"],
    secret: false,
    disallowedReason: {
      unique: "A Bool has only two values, so it cannot be unique.",
      min: "A Bool has no size or range.",
      max: "A Bool has no size or range.",
    },
  },
  Email: {
    sql: "TEXT", ts: "string", tsInput: "string",
    modifiers: ["unique", "optional", "min", "max"],
    length: { defaultMin: 3, defaultMax: 254, lowest: 3, highest: 254 },
    secret: false,
  },
  Password: {
    sql: "TEXT", ts: "PasswordHash", tsInput: "string",
    modifiers: ["optional", "min", "max"],
    length: { defaultMin: 8, defaultMax: 128, lowest: 8, highest: 128 },
    secret: true,
    disallowedReason: {
      unique: "Passwords are stored as salted hashes, so they cannot be unique.",
    },
  },
  Date: {
    sql: "TIMESTAMPTZ", ts: "Date", tsInput: "Date",
    modifiers: ["unique", "optional"],
    secret: false,
    disallowedReason: {
      min: "Date ranges are not supported yet.",
      max: "Date ranges are not supported yet.",
    },
  },
  ID: {
    sql: "UUID", ts: "string", tsInput: "string",
    modifiers: ["unique", "optional"],
    secret: false,
    disallowedReason: {
      min: "An ID is a fixed-size UUID and has no range.",
      max: "An ID is a fixed-size UUID and has no range.",
    },
  },
};

export const FIELD_TYPE_NAMES = Object.keys(FIELD_TYPES) as FieldTypeName[];

export function isFieldTypeName(name: string): name is FieldTypeName {
  return Object.hasOwn(FIELD_TYPES, name);
}

/** Type names from other languages, mapped to the Rizo Lang type to use instead. */
export const TYPE_ALIASES: Readonly<Record<string, FieldTypeName>> = {
  String: "Text", string: "Text", Str: "Text", str: "Text", Varchar: "Text", varchar: "Text", Char: "Text",
  text: "Text",
  Int: "Number", int: "Number", Integer: "Number", integer: "Number", Float: "Number", float: "Number",
  Double: "Number", Decimal: "Number", number: "Number", BigInt: "Number",
  Boolean: "Bool", boolean: "Bool", bool: "Bool",
  DateTime: "Date", Datetime: "Date", Timestamp: "Date", timestamp: "Date", date: "Date", Time: "Date",
  UUID: "ID", Uuid: "ID", uuid: "ID", Id: "ID", id: "ID",
  email: "Email", EmailAddress: "Email",
  password: "Password", Hash: "Password",
};
