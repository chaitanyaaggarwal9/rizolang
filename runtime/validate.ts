/**
 * Rizo Lang runtime: input validation.
 *
 * Every value from a request (body fields and path parameters) passes through
 * here before it reaches a query. Anything unexpected is rejected with a
 * message that names the field; values are never echoed back.
 */
import type { FieldKind, FieldSpec, PathPart } from "./types.ts";

export type Validated =
  | { readonly ok: true; readonly values: ReadonlyMap<string, unknown> }
  | { readonly ok: false; readonly field: string; readonly message: string };

const INT32_MIN = -2147483648;
const INT32_MAX = 2147483647;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
/** Date, or date and time with a required time zone. */
const ISO_DATE = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2}))?$/;
/** Path parameters of type Text are capped so URLs cannot carry huge values. */
const MAX_PATH_TEXT = 1000;

/** Length in Unicode code points, matching PostgreSQL's char_length(). */
const length = (s: string): number => [...s].length;

function describeKind(kind: FieldKind): string {
  switch (kind) {
    case "Text": return "text";
    case "Password": return "text";
    case "Email": return "an email address";
    case "Number": return "a whole number";
    case "Bool": return "true or false";
    case "Date": return "an ISO 8601 date such as 2026-01-31T12:00:00Z";
    case "ID": return "an ID (UUID)";
  }
}

/** Validate one value. Returns the value to store, or an error message. */
export function validateValue(spec: Omit<FieldSpec, "required" | "nullable">, raw: unknown): { value: unknown } | { error: string } {
  const { key, kind } = spec;
  const bad = (): { error: string } => ({ error: `${key} must be ${describeKind(kind)}.` });
  switch (kind) {
    case "Text":
    case "Password": {
      if (typeof raw !== "string") return bad();
      if (raw.includes("\u0000")) return { error: `${key} contains a character that is not allowed.` };
      const n = length(raw);
      if (spec.min !== undefined && n < spec.min) return { error: `${key} must be at least ${spec.min} characters.` };
      if (spec.max !== undefined && n > spec.max) return { error: `${key} must be at most ${spec.max} characters.` };
      return { value: raw };
    }
    case "Email": {
      if (typeof raw !== "string") return bad();
      const email = raw.trim().toLowerCase();
      const n = length(email);
      if (!EMAIL.test(email)) return bad();
      if (spec.min !== undefined && n < spec.min) return { error: `${key} must be at least ${spec.min} characters.` };
      if (spec.max !== undefined && n > spec.max) return { error: `${key} must be at most ${spec.max} characters.` };
      return { value: email };
    }
    case "Number": {
      if (typeof raw !== "number" || !Number.isInteger(raw) || raw < INT32_MIN || raw > INT32_MAX) return bad();
      if (spec.min !== undefined && raw < spec.min) return { error: `${key} must be at least ${spec.min}.` };
      if (spec.max !== undefined && raw > spec.max) return { error: `${key} must be at most ${spec.max}.` };
      return { value: raw };
    }
    case "Bool":
      return typeof raw === "boolean" ? { value: raw } : bad();
    case "Date": {
      if (typeof raw !== "string" || !ISO_DATE.test(raw)) return bad();
      const d = new Date(raw);
      return Number.isNaN(d.getTime()) ? bad() : { value: d };
    }
    case "ID":
      return typeof raw === "string" && UUID.test(raw) ? { value: raw.toLowerCase() } : bad();
  }
}

/**
 * Validate a JSON request body against the endpoint's fields.
 * `partial` is used for updates: every field is optional.
 */
export function validateBody(specs: readonly FieldSpec[], body: unknown): Validated {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, field: "", message: "The request body must be a JSON object." };
  }
  const allowed = new Set(specs.map((s) => s.key));
  for (const key of Object.keys(body)) {
    if (!allowed.has(key)) {
      const shown = key.length > 50 ? `${key.slice(0, 50)}…` : key;
      return {
        ok: false,
        field: shown,
        message: `Unknown field "${shown}". Allowed fields: ${[...allowed].join(", ") || "none"}.`,
      };
    }
  }
  const values = new Map<string, unknown>();
  const record = body as Record<string, unknown>;
  for (const spec of specs) {
    if (!Object.hasOwn(record, spec.key)) {
      if (spec.required) return { ok: false, field: spec.key, message: `${spec.key} is required.` };
      continue;
    }
    const raw = record[spec.key];
    if (raw === null) {
      if (!spec.nullable) return { ok: false, field: spec.key, message: `${spec.key} cannot be null.` };
      values.set(spec.key, null);
      continue;
    }
    const r = validateValue(spec, raw);
    if ("error" in r) return { ok: false, field: spec.key, message: r.error };
    values.set(spec.key, r.value);
  }
  return { ok: true, values };
}

/** Validate a decoded path parameter. */
export function validatePathParam(part: Extract<PathPart, { param: string }>, raw: string): { value: unknown } | { error: string } {
  const key = part.param;
  switch (part.kind) {
    case "Number":
      if (!/^-?\d{1,10}$/.test(raw)) return { error: `${key} must be a whole number.` };
      return validateValue({ key, kind: "Number" }, Number(raw));
    case "Bool":
      if (raw !== "true" && raw !== "false") return { error: `${key} must be true or false.` };
      return { value: raw === "true" };
    case "Text":
      return validateValue({ key, kind: "Text", min: 1, max: MAX_PATH_TEXT }, raw);
    default:
      return validateValue({ key, kind: part.kind }, raw);
  }
}

/** Longest value of a text query parameter (a search). */
export const MAX_QUERY_TEXT = 200;

/** Validate an optional query parameter of a list endpoint (`?q=...`). */
export function validateQueryParam(name: string, kind: "ID" | "Number" | "Bool" | "Text" | "Email" | "Date", raw: string, max = MAX_QUERY_TEXT): { value: unknown } | { error: string } {
  switch (kind) {
    case "Number":
      if (!/^-?\d{1,10}$/.test(raw)) return { error: `${name} must be a whole number.` };
      return validateValue({ key: name, kind: "Number" }, Number(raw));
    case "Bool":
      return raw === "true" || raw === "false" ? { value: raw === "true" } : { error: `${name} must be true or false.` };
    case "Text":
      return validateValue({ key: name, kind: "Text", min: 1, max }, raw);
    default:
      return validateValue({ key: name, kind }, raw);
  }
}
