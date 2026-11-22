import { type CompareOp,
  QUERY_ACTIONS,
  type RoleRef,
  type ApiDecl,
  type AuthDecl,
  type HttpMethod,
  type QueryAction,
  type QueryArg,
  type Value,
} from "./ast.js";
import { type ResolvedField, type ResolvedModel, isHidden } from "./checker.js";
import { type Span, didYouMean } from "./diagnostics.js";
import type { FieldTypeName } from "./types.js";

/**
 * Checks `auth` and `api` declarations. The rules here are what make
 * endpoints safe by construction:
 *   - every endpoint says `public` or `requires login`;
 *   - endpoints return only `.public` views;
 *   - a link to the auth model is set by the server (`= me`), never by the client;
 *   - `requires owner` turns into a WHERE clause, so it cannot be bypassed,
 *     and it is required to change or delete records that belong to users;
 *   - GET never changes data.
 */

export interface ResolvedAuth {
  readonly model: ResolvedModel;
  /** The `by` field: Email, unique, required. */
  readonly loginField: ResolvedField;
  readonly passwordField: ResolvedField;
  /** Declared roles (`roles admin, editor`); empty when roles are not used. */
  readonly roles: readonly string[];
}

export type PathSegment =
  | { readonly kind: "static"; readonly value: string }
  | { readonly kind: "param"; readonly name: string };

/** Types a path parameter can have, inferred from where it is used. */
export type ParamType = "ID" | "Number" | "Bool" | "Text" | "Email";

export interface PathParam {
  readonly name: string;
  readonly type: ParamType;
}

export type ResolvedValue =
  | { readonly kind: "me" }
  | { readonly kind: "param"; readonly name: string }
  | { readonly kind: "int"; readonly value: number }
  | { readonly kind: "bool"; readonly value: boolean }
  /** An optional query parameter (`?q`): when it is missing, the filter is skipped. */
  | { readonly kind: "query"; readonly name: string };

export interface FieldValue {
  readonly field: ResolvedField;
  readonly value: ResolvedValue;
  /** How a list filter compares (always "=" in create). */
  readonly op: CompareOp;
}

/** An optional query parameter of a list endpoint (`?q`), and the type its value must have. */
export interface QueryParam {
  readonly name: string;
  readonly type: "ID" | "Number" | "Bool" | "Text" | "Email" | "Date";
  /** For Text compared with =: the field's own max length. */
  readonly max?: number;
}

export type ResolvedQuery =
  | { readonly action: "find"; readonly model: ResolvedModel; readonly idParam: string }
  | {
      readonly action: "list";
      readonly model: ResolvedModel;
      readonly filters: readonly FieldValue[];
      /** Query parameters the filters use (`?q`). */
      readonly queryParams: readonly QueryParam[];
      /** Undefined field means "order by id". */
      readonly order: { readonly field: ResolvedField | undefined; readonly descending: boolean };
      readonly limit: number;
    }
  | {
      readonly action: "create";
      readonly model: ResolvedModel;
      /** Fields taken from the request body. */
      readonly bodyFields: readonly ResolvedField[];
      /** Fields set by the server (`author = me`). */
      readonly assigns: readonly FieldValue[];
    }
  | {
      readonly action: "update";
      readonly model: ResolvedModel;
      readonly idParam: string;
      /** Fields that may be changed; all are optional in the body. */
      readonly bodyFields: readonly ResolvedField[];
    }
  | { readonly action: "delete"; readonly model: ResolvedModel; readonly idParam: string };

export interface ResolvedApi {
  readonly method: HttpMethod;
  readonly path: string;
  readonly segments: readonly PathSegment[];
  readonly params: readonly PathParam[];
  readonly access: "public" | "login";
  /** Link field that must equal the logged-in user (`requires owner author`). */
  readonly owner: ResolvedField | undefined;
  /** Roles that may act even when they are not the owner (`requires owner author or role admin`). */
  readonly ownerBypassRoles: readonly string[];
  /** The caller must have one of these roles (`requires role admin, editor`); empty for no role check. */
  readonly roles: readonly string[];
  readonly returns: "one" | "list" | "none";
  readonly query: ResolvedQuery;
  /** `with author`: link fields whose records (their public fields) are returned too. */
  readonly expand: readonly { readonly field: ResolvedField; readonly model: ResolvedModel }[];
  /** Requests allowed per window, per account (logged in) or per IP address (logged out). */
  readonly rateLimit: RateLimit;
}

export interface RateLimit {
  readonly max: number;
  readonly windowSeconds: number;
}

/** Every endpoint gets this limit unless it has its own `limit` line. */
export const DEFAULT_RATE_LIMIT: RateLimit = { max: 120, windowSeconds: 60 };
const RATE_UNITS: Readonly<Record<string, number>> = { second: 1, minute: 60, hour: 3600, day: 86_400 };
const MAX_RATE = 100_000;

type Err = (code: string, span: Span, message: string, fix: string) => void;

export const DEFAULT_LIST_LIMIT = 50;
export const MAX_ROLES = 20;
export const MAX_LIST_LIMIT = 100;

const METHOD_FOR_ACTION: Readonly<Record<QueryAction, readonly HttpMethod[]>> = {
  find: ["GET"],
  list: ["GET"],
  create: ["POST"],
  update: ["PUT", "PATCH"],
  delete: ["DELETE"],
};

const PARAM_TYPES: readonly FieldTypeName[] = ["ID", "Number", "Bool", "Text", "Email"];
const RESERVED_PARAM_NAMES: readonly string[] = ["me", "body"];

// ------------------------------------------------------------------- auth

export function checkAuth(auths: readonly AuthDecl[], models: readonly ResolvedModel[], err: Err): ResolvedAuth | undefined {
  for (const extra of auths.slice(1)) {
    err("RZ0317", extra.span, "Only one auth line is allowed.", "Remove this line. A file has at most one `auth <Model> by <field>`.");
  }
  const a = auths[0];
  if (a === undefined) return undefined;

  const model = models.find((m) => m.name === a.model);
  if (model === undefined) {
    unknownModel(a.model, a.modelSpan, models, err);
    return undefined;
  }
  let ok = true;
  const loginField = model.fields.find((f) => f.name === a.field);
  if (loginField === undefined) {
    ok = false;
    err("RZ0317", a.fieldSpan, `Model "${model.name}" has no field "${a.field}" to log in with.`,
      `Add \`${a.field}: Email unique\` to ${model.name}, or log in by an existing Email field.`);
  } else if (loginField.type !== "Email" || loginField.link !== undefined) {
    ok = false;
    err("RZ0317", a.fieldSpan, `Users log in by "${model.name}.${a.field}", so it must have type Email.`,
      `Change the field to \`${a.field}: Email unique\`.`);
  } else if (!loginField.unique || loginField.optional) {
    ok = false;
    err("RZ0317", a.fieldSpan, `"${model.name}.${a.field}" must be unique and required to log in with it.`,
      `Declare it as \`${a.field}: Email unique\` (with unique and without optional).`);
  }
  const passwords = model.fields.filter((f) => f.type === "Password");
  const passwordField = passwords[0];
  if (passwordField === undefined) {
    ok = false;
    err("RZ0317", a.modelSpan, `Model "${model.name}" needs a Password field to log in.`,
      `Add \`password: Password\` to ${model.name}.`);
  } else if (passwords.length > 1) {
    ok = false;
    err("RZ0317", a.modelSpan, `Model "${model.name}" has ${passwords.length} Password fields; auth needs exactly one.`,
      "Keep one Password field on the auth model.");
  } else if (passwordField.optional) {
    ok = false;
    err("RZ0317", a.modelSpan, `"${model.name}.${passwordField.name}" must be required to log in with it.`,
      `Remove optional: \`${passwordField.name}: Password\`.`);
  }
  for (const self of model.fields.filter((f) => f.link === model.name && !f.optional)) {
    ok = false;
    err("RZ0317", a.modelSpan, `"${model.name}.${self.name}" links to ${model.name} and is required, so signup could never fill it.`,
      `Make it optional: \`${self.name}: ${model.name} optional\`.`);
  }
  const roles: string[] = [];
  if (a.roles.length > 0) {
    if (model.fields.some((f) => f.name === "role" || f.column === "role")) {
      ok = false;
      err("RZ0317", a.modelSpan, `Model "${model.name}" has a field named "role", which roles need for themselves.`,
        "Rename that field, for example to `jobTitle`.");
    }
    for (const r of a.roles) {
      if (!/^[a-z][A-Za-z0-9]*$/.test(r.name)) {
        ok = false;
        err("RZ0317", r.span, `Role name "${r.name}" must be camelCase.`, `Write it as "${r.name.charAt(0).toLowerCase()}${r.name.slice(1)}".`);
      } else if (roles.includes(r.name)) {
        ok = false;
        err("RZ0317", r.span, `Role "${r.name}" is listed twice.`, "Remove the duplicate.");
      } else {
        roles.push(r.name);
      }
    }
    if (!roles.includes("admin")) {
      ok = false;
      err("RZ0317", a.modelSpan, "The roles must include admin.",
        `Add admin to the list: \`auth ${a.model} by ${a.field} roles admin${roles.length > 0 ? `, ${roles.join(", ")}` : ""}\`. Admins assign the other roles.`);
    }
    if (roles.length > MAX_ROLES) {
      ok = false;
      err("RZ0317", a.modelSpan, `There are ${roles.length} roles; at most ${MAX_ROLES} are allowed.`, "Use fewer roles.");
    }
  }
  if (!ok || loginField === undefined || passwordField === undefined) return undefined;
  return { model, loginField, passwordField, roles };
}

function unknownModel(name: string, span: Span, models: readonly ResolvedModel[], err: Err): void {
  const names = models.map((m) => m.name);
  const guess = didYouMean(name, names);
  err("RZ0316", span, `Unknown model "${name}".`,
    guess !== undefined
      ? `Did you mean "${guess}"?`
      : names.length > 0 ? `Use one of the models in this file: ${names.join(", ")}.` : `Declare it first: \`model ${name} { ... }\`.`);
}

// -------------------------------------------------------------------- api

export function checkApis(
  apis: readonly ApiDecl[],
  models: readonly ResolvedModel[],
  auth: ResolvedAuth | undefined,
  authDeclared: boolean,
  err: Err,
): ResolvedApi[] {
  const resolved: ResolvedApi[] = [];
  const routes = new Map<string, ApiDecl>();

  for (const api of apis) {
    const r = checkApi(api);
    if (r === undefined) continue;
    const first = r.segments[0];
    if (auth?.roles.includes("admin") === true && first?.kind === "static" && first.value === "admin") {
      err("RZ0322", api.pathSpan, "Paths under /admin are reserved for the built-in admin pages, because the auth line has the admin role.",
        `Choose a different first path segment, for example \`${api.method} /api${api.path}\`.`);
      continue;
    }
    const key = `${r.method} /${r.segments.map((s) => (s.kind === "param" ? ":" : s.value)).join("/")}`;
    const dup = routes.get(key);
    if (dup !== undefined) {
      err("RZ0324", api.pathSpan, `Endpoint "${api.method} ${api.path}" is already defined on line ${dup.span.line}.`,
        "Remove one of the two endpoints, or give them different paths.");
      continue;
    }
    routes.set(key, api);
    resolved.push(r);
  }
  return resolved;

  function checkApi(api: ApiDecl): ResolvedApi | undefined {
    const name = `${api.method} ${api.path}`;
    const segments = checkPath(api);
    if (segments === undefined) return undefined;
    const pathParams = new Set(segments.flatMap((s) => (s.kind === "param" ? [s.name] : [])));

    // --- access statements
    const stmts = api.statements;
    const publics = stmts.filter((s) => s.kind === "public");
    const logins = stmts.filter((s) => s.kind === "requiresLogin");
    const owners = stmts.flatMap((s) => (s.kind === "requiresOwner" ? [s] : []));
    const roleStmts = stmts.flatMap((s) => (s.kind === "requiresRole" ? [s] : []));
    const returns = stmts.flatMap((s) => (s.kind === "return" ? [s] : []));
    let ok = true;

    for (const group of [publics, logins, owners, roleStmts]) {
      for (const extra of group.slice(1)) {
        ok = false;
        err("RZ0318", extra.span, `This access rule appears more than once in endpoint "${name}".`, "Remove the duplicate line.");
      }
    }
    const firstPublic = publics[0];
    if (firstPublic !== undefined && (logins.length > 0 || owners.length > 0 || roleStmts.length > 0)) {
      ok = false;
      err("RZ0318", firstPublic.span, `Endpoint "${name}" is marked public but also requires login.`,
        "Remove `public` if only logged-in users may call it, or remove the `requires` lines.");
    } else if (publics.length === 0 && logins.length === 0) {
      ok = false;
      err("RZ0318", api.methodSpan, `Endpoint "${name}" does not say who may call it.`,
        owners.length > 0 || roleStmts.length > 0
          ? `Add \`requires login\` above \`requires ${owners.length > 0 ? "owner" : "role"}\`.`
          : "Add `requires login` for logged-in users only, or `public` if anyone may call it.");
    }
    if ((logins.length > 0 || owners.length > 0 || roleStmts.length > 0) && !authDeclared) {
      ok = false;
      err("RZ0319", (logins[0] ?? owners[0] ?? roleStmts[0] ?? api).span, `Endpoint "${name}" requires login, but there is no auth line.`,
        "Add `auth User by email` (using your user model and its Email field) at the top level.");
    }
    const access: "public" | "login" = publics.length > 0 ? "public" : "login";

    // --- rate limit
    const limits = stmts.flatMap((s) => (s.kind === "limit" ? [s] : []));
    for (const extra of limits.slice(1)) {
      ok = false;
      err("RZ0339", extra.span, `Endpoint "${name}" has more than one limit line.`, "Keep one `limit ... per ...` line.");
    }
    let rateLimit = DEFAULT_RATE_LIMIT;
    const lim = limits[0];
    if (lim !== undefined) {
      const seconds = RATE_UNITS[lim.unit];
      if (seconds === undefined) {
        ok = false;
        const guess = didYouMean(lim.unit.replace(/s$/, ""), Object.keys(RATE_UNITS));
        err("RZ0339", lim.unitSpan, `"${lim.unit}" is not a time unit.`,
          guess !== undefined ? `Write \`per ${guess}\`.` : "Use second, minute, hour or day, for example `limit 20 per minute`.");
      } else if (lim.count < 1 || lim.count > MAX_RATE) {
        ok = false;
        err("RZ0339", lim.countSpan, `A limit of ${lim.count} is out of range.`, `Use a number from 1 to ${MAX_RATE}.`);
      } else {
        rateLimit = { max: lim.count, windowSeconds: seconds };
      }
    }

    const roleList = (refs: readonly RoleRef[]): string[] => {
      const out: string[] = [];
      for (const r of refs) {
        if (auth === undefined) continue; // the auth line itself is invalid; it has its own error
        if (auth.roles.length === 0) {
          ok = false;
          err("RZ0332", r.span, `Role "${r.name}" is used, but the auth line declares no roles.`,
            `Declare roles on the auth line: \`auth ${auth.model.name} by ${auth.loginField.name} roles admin${r.name === "admin" ? "" : `, ${r.name}`}\`.`);
        } else if (!auth.roles.includes(r.name)) {
          ok = false;
          const guess = didYouMean(r.name, auth.roles);
          err("RZ0332", r.span, `Unknown role "${r.name}".`,
            guess !== undefined ? `Did you mean "${guess}"? Roles: ${auth.roles.join(", ")}.` : `Use one of the declared roles: ${auth.roles.join(", ")}.`);
        } else if (!out.includes(r.name)) {
          out.push(r.name);
        }
      }
      return out;
    };
    const requiredRoles = roleList(roleStmts[0]?.roles ?? []);

    // --- return statement
    const ret = returns[0];
    if (ret === undefined) {
      err("RZ0320", api.endSpan, `Endpoint "${name}" has no return line.`,
        "Add a return line as the last statement, for example `return db.Post.find(id)`.");
      return undefined;
    }
    for (const extra of returns.slice(1)) {
      ok = false;
      err("RZ0320", extra.span, `Endpoint "${name}" has more than one return line.`, "Keep exactly one return line.");
    }
    if (stmts[stmts.length - 1] !== ret) {
      ok = false;
      err("RZ0320", ret.span, `The return line must be the last statement in endpoint "${name}".`,
        "Move the access rules (public, requires ...) above the return line.");
    }

    // --- query
    const q = ret.query;
    const model = models.find((m) => m.name === q.model);
    if (model === undefined) {
      unknownModel(q.model, q.modelSpan, models, err);
      return undefined;
    }
    if (!(QUERY_ACTIONS as readonly string[]).includes(q.action)) {
      const guess = didYouMean(q.action, QUERY_ACTIONS);
      err("RZ0325", q.actionSpan, `Unknown query action "${q.action}".`,
        guess !== undefined ? `Did you mean "${guess}"? Actions: ${QUERY_ACTIONS.join(", ")}.` : `Use one of: ${QUERY_ACTIONS.join(", ")}.`);
      return undefined;
    }
    const action = q.action as QueryAction;
    const allowed = METHOD_FOR_ACTION[action];
    if (!allowed.includes(api.method)) {
      ok = false;
      err("RZ0328", api.methodSpan, `"${action}" cannot be used with ${api.method}.`,
        `Use ${allowed.join(" or ")} for ${action}${action === "find" || action === "list" ? "" : ": GET requests must never change data"}.`);
    }
    if (auth !== undefined && model === auth.model && (action === "create" || action === "update" || action === "delete")) {
      ok = false;
      err("RZ0327", q.actionSpan, `Endpoints cannot ${action} ${model.name} records.`,
        `${model.name} is the auth model. Accounts are created through POST /auth/signup; changing or deleting them is not supported yet.`);
    }

    const params = new Map<string, { type: ParamType; span: Span }>();
    const usedParams = new Set<string>();
    const useParam = (pname: string, type: ParamType, span: Span): boolean => {
      if (!pathParams.has(pname)) {
        const list = [...pathParams];
        err("RZ0323", span, `"${pname}" is not a parameter of path "${api.path}".`,
          list.length > 0
            ? `Use one of the path parameters (${list.join(", ")}), or add \`:${pname}\` to the path.`
            : `Add \`:${pname}\` to the path, for example \`${api.path === "/" ? "" : api.path}/:${pname}\`.`);
        return false;
      }
      usedParams.add(pname);
      const prev = params.get(pname);
      if (prev !== undefined && prev.type !== type) {
        err("RZ0325", span, `Path parameter "${pname}" is used as both ${prev.type} and ${type}.`,
          "Use a separate path parameter for each value.");
        return false;
      }
      params.set(pname, { type, span });
      return true;
    };
    const field = (fname: string, span: Span): ResolvedField | undefined => {
      const f = model.fields.find((x) => x.name === fname);
      if (f === undefined) {
        const guess = didYouMean(fname, model.fields.map((x) => x.name));
        err("RZ0325", span, `Model "${model.name}" has no field "${fname}".`,
          fname === "id"
            ? `To get one record by id, use \`db.${model.name}.find(id)\`.`
            : guess !== undefined ? `Did you mean "${guess}"?` : `Fields of ${model.name}: ${model.fields.map((x) => x.name).join(", ")}.`);
      }
      return f;
    };
    const value = (f: ResolvedField, v: Value, inList = false, paramType?: ParamType): ResolvedValue | undefined => {
      const where = `${model.name}.${f.name}`;
      if (v.kind === "query") {
        if (!inList) {
          err("RZ0325", v.span, `Query parameters such as ?${v.name} can only filter lists.`,
            "Set fields from body, me or a path parameter instead.");
          return undefined;
        }
        return { kind: "query", name: v.name };
      }
      if (v.kind === "name" && v.name === "me") {
        if (!authDeclared) {
          err("RZ0319", v.span, `"me" means the logged-in user, but there is no auth line.`,
            "Add `auth User by email` at the top level.");
          return undefined;
        }
        if (auth === undefined) return undefined;
        if (f.link !== auth.model.name) {
          err("RZ0325", v.span, `"me" is the logged-in ${auth.model.name}; it cannot be compared with "${where}".`,
            `Use me only with a field that links to ${auth.model.name}, such as \`author: ${auth.model.name}\`.`);
          return undefined;
        }
        if (access === "public") {
          err("RZ0330", v.span, `"me" cannot be used in a public endpoint.`,
            "Replace `public` with `requires login`.");
          return undefined;
        }
        return { kind: "me" };
      }
      if (v.kind === "name") {
        if (!PARAM_TYPES.includes(f.type) || f.type === "Password") {
          err("RZ0325", v.span, `"${where}" has type ${f.type} and cannot be matched against a path parameter.`,
            "Filter by a Text, Email, Number, Bool, ID or link field instead.");
          return undefined;
        }
        return useParam(v.name, paramType ?? (f.type as ParamType), v.span) ? { kind: "param", name: v.name } : undefined;
      }
      if (v.kind === "int") {
        if (f.type !== "Number") {
          err("RZ0325", v.span, `"${where}" has type ${f.link ? `link (${f.link})` : f.type}, so it can't be compared with the number ${v.value}.`,
            "Compare Number fields with numbers, and Bool fields with true or false.");
          return undefined;
        }
        return { kind: "int", value: v.value };
      }
      if (f.type !== "Bool") {
        err("RZ0325", v.span, `"${where}" has type ${f.link ? `link (${f.link})` : f.type}, so it can't be compared with ${v.value}.`,
          "Compare Bool fields with true or false.");
        return undefined;
      }
      return { kind: "bool", value: v.value };
    };
    const idArg = (args: readonly QueryArg[], usage: string): string | undefined => {
      const a = args[0];
      if (a === undefined || a.kind !== "name" || a.name === "body" || a.name === "me") {
        err("RZ0325", a?.span ?? q.actionSpan, `${action} needs the path parameter holding the record's id.`,
          `Write \`${usage}\`, with \`:id\` in the path.`);
        return undefined;
      }
      return useParam(a.name, "ID", a.span) ? a.name : undefined;
    };
    const authLinks = auth === undefined ? [] : model.fields.filter((f) => f.link === auth.model.name);

    let query: ResolvedQuery | undefined;
    switch (action) {
      case "find":
      case "delete": {
        const usage = `db.${model.name}.${action}(id)`;
        if (q.args.length !== 1) {
          err("RZ0325", q.actionSpan, `${action} takes exactly one argument.`, `Write \`${usage}\`.`);
          break;
        }
        const id = idArg(q.args, usage);
        if (id !== undefined) query = { action, model, idParam: id };
        break;
      }
      case "update": {
        const usage = `db.${model.name}.update(id, body)`;
        const second = q.args[1];
        if (q.args.length !== 2 || second === undefined || second.kind !== "name" || second.name !== "body") {
          err("RZ0325", q.actionSpan, "update takes the id parameter and body.", `Write \`${usage}\`.`);
          break;
        }
        const id = idArg(q.args, usage);
        const bodyFields = model.fields.filter((f) => !authLinks.includes(f));
        if (bodyFields.length === 0) {
          err("RZ0325", q.actionSpan, `Model "${model.name}" has no fields that can be updated.`,
            "Links to the auth model cannot be changed. Remove this endpoint or add fields to the model.");
          break;
        }
        if (id !== undefined) query = { action, model, idParam: id, bodyFields };
        break;
      }
      case "create": {
        const first = q.args[0];
        if (first === undefined || first.kind !== "name" || first.name !== "body") {
          err("RZ0325", first?.span ?? q.actionSpan, "create must take body as its first argument.",
            `Write \`db.${model.name}.create(body)\`${authLinks[0] ? ` or \`db.${model.name}.create(body, ${authLinks[0].name} = me)\`` : ""}.`);
          break;
        }
        const assigns: FieldValue[] = [];
        let good = true;
        for (const a of q.args.slice(1)) {
          if (a.kind !== "assign") {
            good = false;
            err("RZ0325", a.span, "After body, create only takes `field = value` assignments.",
              `Example: \`db.${model.name}.create(body${authLinks[0] ? `, ${authLinks[0].name} = me` : ""})\`.`);
            continue;
          }
          const f = field(a.field, a.fieldSpan);
          if (f === undefined) { good = false; continue; }
          if (assigns.some((x) => x.field === f)) {
            good = false;
            err("RZ0325", a.fieldSpan, `"${f.name}" is assigned more than once.`, "Remove the duplicate assignment.");
            continue;
          }
          if (f.type === "Password") {
            good = false;
            err("RZ0325", a.fieldSpan, `Password field "${f.name}" cannot be set to a fixed value.`,
              "Passwords always come from the request body.");
            continue;
          }
          if (a.op !== "=") {
            good = false;
            err("RZ0325", a.opSpan, `create sets fields with "=", not "${a.op}".`, `Write \`${f.name} = value\`.`);
            continue;
          }
          const v = value(f, a.value);
          if (v === undefined) { good = false; continue; }
          if (authLinks.includes(f) && v.kind !== "me") {
            good = false;
            err("RZ0326", a.value.span, `"${model.name}.${f.name}" links to the auth model, so it can only be set to me.`,
              `Write \`${f.name} = me\`. Records always belong to the user who creates them.`);
            continue;
          }
          assigns.push({ field: f, value: v, op: "=" });
        }
        for (const f of authLinks) {
          if (!assigns.some((x) => x.field === f)) {
            good = false;
            err("RZ0326", q.actionSpan, `"${model.name}.${f.name}" links to the auth model, so the server must set it.`,
              `Write \`db.${model.name}.create(body, ${f.name} = me)\`. Otherwise a client could create records owned by someone else.`);
          }
        }
        if (good) query = { action, model, bodyFields: model.fields.filter((f) => !assigns.some((x) => x.field === f)), assigns };
        break;
      }
      case "list": {
        const filters: FieldValue[] = [];
        const queryParams: QueryParam[] = [];
        let order: { field: ResolvedField | undefined; descending: boolean } = { field: undefined, descending: false };
        let orderSeen = false;
        let limit: number | undefined;
        let good = true;
        for (const a of q.args) {
          if (a.kind === "name") {
            good = false;
            err("RZ0325", a.span, `list does not take "${a.name}" as an argument.`,
              `Filter with \`field = value\`, for example \`db.${model.name}.list(${authLinks[0] ? `${authLinks[0].name} = me` : "published = true"})\`.`);
          } else if (a.kind === "limit") {
            if (limit !== undefined) {
              good = false;
              err("RZ0325", a.span, "limit appears more than once.", "Keep one limit.");
            } else if (a.value < 1 || a.value > MAX_LIST_LIMIT) {
              good = false;
              err("RZ0325", a.valueSpan, `limit ${a.value} is out of range.`, `Use a limit between 1 and ${MAX_LIST_LIMIT}.`);
            } else {
              limit = a.value;
            }
          } else if (a.kind === "order") {
            if (orderSeen) {
              good = false;
              err("RZ0325", a.span, "order appears more than once.", "Keep one order.");
              continue;
            }
            orderSeen = true;
            const f = field(a.field, a.fieldSpan);
            if (f === undefined) { good = false; continue; }
            if (isHidden(f)) {
              good = false;
              err("RZ0325", a.fieldSpan, `Cannot order by hidden field "${model.name}.${f.name}".`,
                "Ordering by a private or Password field would reveal its values. Order by a public field.");
              continue;
            }
            if (f.encrypted) {
              good = false;
              err("RZ0340", a.fieldSpan, `Cannot order by encrypted field "${model.name}.${f.name}".`,
                "The database only sees encrypted values, so it can't sort by them. Order by a field that isn't encrypted.");
              continue;
            }
            if (f.optional) {
              good = false;
              err("RZ0325", a.fieldSpan, `Cannot order by optional field "${model.name}.${f.name}".`,
                "Pages are built from the sort value, so every record needs one. Order by a required field, or remove optional from it.");
              continue;
            }
            order = { field: f, descending: a.descending };
          } else {
            const f = field(a.field, a.fieldSpan);
            if (f === undefined) { good = false; continue; }
            if (isHidden(f)) {
              good = false;
              err("RZ0325", a.fieldSpan, `Cannot filter by hidden field "${model.name}.${f.name}".`,
                "Filtering by a private or Password field would reveal its values. Filter by a public field.");
              continue;
            }
            if (f.encrypted) {
              good = false;
              err("RZ0340", a.fieldSpan, `Cannot filter by encrypted field "${model.name}.${f.name}".`,
                "The database only sees encrypted values, so it can't compare them. Filter by a field that isn't encrypted.");
              continue;
            }
            if (filters.some((x) => x.field === f && x.op === a.op)) {
              good = false;
              err("RZ0325", a.fieldSpan, `"${f.name} ${a.op}" appears more than once.`, "Remove the duplicate filter.");
              continue;
            }
            if (a.op === "contains" && a.value.kind !== "query" && a.value.kind !== "name") {
              good = false;
              err("RZ0325", a.value.span, `"contains" needs text from the request.`, `Write \`${f.name} contains ?q\` to search with \`?q=...\`.`);
              continue;
            }
            const v = value(f, a.value, true, a.op === "contains" ? "Text" : undefined);
            if (v === undefined) { good = false; continue; }
            const where = `${model.name}.${f.name}`;
            const kind = f.link !== undefined ? `a link (${f.link})` : `a ${f.type}`;
            if (a.op === "contains" && (f.link !== undefined || (f.type !== "Text" && f.type !== "Email"))) {
              good = false;
              err("RZ0325", a.opSpan, `"contains" works on Text and Email fields, but "${where}" is ${kind}.`, "Use = to match the whole value.");
              continue;
            }
            if (a.op === "contains" && v.kind !== "query" && v.kind !== "param") {
              good = false;
              err("RZ0325", a.value.span, `"contains" needs text from the request.`, `Write \`${f.name} contains ?q\` to search with \`?q=...\`.`);
              continue;
            }
            if ((a.op === "<" || a.op === "<=" || a.op === ">" || a.op === ">=") && (f.link !== undefined || (f.type !== "Number" && f.type !== "Date"))) {
              good = false;
              err("RZ0325", a.opSpan, `"${a.op}" works on Number and Date fields, but "${where}" is ${kind}.`, "Use = or != instead.");
              continue;
            }
            if (v.kind === "query") {
              const type: QueryParam["type"] = a.op === "contains" ? "Text" : f.type === "Password" ? "Text" : f.type;
              const prev = queryParams.find((x) => x.name === v.name);
              if (v.name === "limit" || v.name === "after") {
                good = false;
                err("RZ0325", a.value.span, `?${v.name} is used for pages.`, "Choose another name, for example ?minViews.");
                continue;
              }
              if (params.has(v.name)) {
                good = false;
                err("RZ0325", a.value.span, `"${v.name}" is a path parameter.`, `Write \`${v.name}\` without "?", or choose another name.`);
                continue;
              }
              if (prev !== undefined && prev.type !== type) {
                good = false;
                err("RZ0325", a.value.span, `?${v.name} is used as both ${prev.type} and ${type}.`, "Use a different name for each.");
                continue;
              }
              const max = a.op !== "contains" && type === "Text" && f.max !== undefined && f.max > 200 ? { max: f.max } : {};
              if (prev === undefined) queryParams.push({ name: v.name, type, ...max });
            }
            filters.push({ field: f, value: v, op: a.op });
          }
        }
        if (good) query = { action, model, filters, queryParams, order, limit: limit ?? DEFAULT_LIST_LIMIT };
        break;
      }
    }

    // --- owner
    let owner: ResolvedField | undefined;
    const ownerStmt = owners[0];
    if (ownerStmt !== undefined && auth !== undefined) {
      const f = model.fields.find((x) => x.name === ownerStmt.field);
      if (action !== "find" && action !== "update" && action !== "delete") {
        ok = false;
        err("RZ0329", ownerStmt.span, `requires owner cannot be used with ${action}.`,
          action === "list"
            ? `Filter the list instead: \`db.${model.name}.list(${ownerStmt.field} = me)\`.`
            : `For create, set the owner instead: \`db.${model.name}.create(body, ${ownerStmt.field} = me)\`.`);
      } else if (f === undefined || f.link !== auth.model.name) {
        ok = false;
        const candidates = authLinks.map((x) => x.name);
        err("RZ0329", ownerStmt.fieldSpan,
          f === undefined
            ? `Model "${model.name}" has no field "${ownerStmt.field}".`
            : `"${model.name}.${f.name}" does not link to ${auth.model.name}, so it cannot name an owner.`,
          candidates.length > 0
            ? `Use a field that links to ${auth.model.name}: ${candidates.join(", ")}.`
            : `Add a link to ${model.name}, for example \`owner: ${auth.model.name}\`, and write \`requires owner owner\`.`);
      } else {
        owner = f;
      }
    }

    // Changing a record that belongs to a user must check that it is the caller's.
    if ((action === "update" || action === "delete") && ownerStmt === undefined && roleStmts.length === 0 && authLinks.length > 0) {
      ok = false;
      const link = authLinks[0]?.name ?? "author";
      err("RZ0331", q.actionSpan, `Endpoint "${name}" can ${action} any ${model.name}, including ones that belong to other users.`,
        access === "public"
          ? `Replace \`public\` with \`requires login\` and \`requires owner ${link}\`, so only the owner can ${action} it.`
          : `Add \`requires owner ${link}\` below \`requires login\`, so only the owner can ${action} it.`);
    }

    // --- return type
    const expected = action === "list" ? "list" : action === "delete" ? "none" : "one";
    const rt = api.returns;
    if (rt === undefined && expected !== "none") {
      ok = false;
      err("RZ0321", api.pathSpan, `Endpoint "${name}" returns data but does not declare its type.`,
        `Add the return type after the path: \`api ${api.method} ${api.path} -> ${expected === "list" ? "list " : ""}${model.name}.public {\`.`);
    } else if (rt !== undefined && expected === "none") {
      ok = false;
      err("RZ0321", rt.span, `delete returns nothing, so endpoint "${name}" cannot declare a return type.`,
        `Remove \`-> ${rt.list ? "list " : ""}${rt.model}.${rt.view}\`.`);
    } else if (rt !== undefined) {
      if (rt.view !== "public") {
        ok = false;
        err("RZ0321", rt.viewSpan, `Endpoints can only return public data, not "${rt.model}.${rt.view}".`,
          `Write \`-> ${rt.list ? "list " : ""}${rt.model}.public\`. Public views never contain passwords or private fields.`);
      } else if (rt.model !== model.name || rt.list !== (expected === "list")) {
        ok = false;
        const want = `${expected === "list" ? "list " : ""}${model.name}.public`;
        err("RZ0321", rt.span, `Endpoint "${name}" returns ${want} but declares ${rt.list ? "list " : ""}${rt.model}.public.`,
          `Change the return type to \`-> ${want}\`.`);
      }
    }

    // --- with: linked records returned too
    const expand: { field: ResolvedField; model: ResolvedModel }[] = [];
    for (const w of rt?.with ?? []) {
      const f = model.fields.find((x) => x.name === w.name);
      const links = model.fields.filter((x) => x.link !== undefined && !isHidden(x)).map((x) => x.name);
      const fix = links.length > 0 ? `Links of ${model.name} that can be returned: ${links.join(", ")}.` : `${model.name} has no public links to return.`;
      if (action !== "find" && action !== "list") {
        ok = false;
        err("RZ0343", w.span, `"with" works only on endpoints that read records (find and list).`, `Remove \`with ${w.name}\`.`);
      } else if (f === undefined || f.link === undefined) {
        ok = false;
        err("RZ0343", w.span, `"${w.name}" is not a link field of ${model.name}.`, fix);
      } else if (isHidden(f)) {
        ok = false;
        err("RZ0343", w.span, `"${model.name}.${f.name}" is private, so its record can't be returned.`, fix);
      } else if (expand.some((x) => x.field === f)) {
        ok = false;
        err("RZ0343", w.span, `"${w.name}" is listed twice after "with".`, "Remove the duplicate.");
      } else {
        const target = models.find((m) => m.name === f.link);
        if (target !== undefined) expand.push({ field: f, model: target });
      }
    }

    // --- every path parameter is used
    for (const p of pathParams) {
      if (!usedParams.has(p) && query !== undefined) {
        ok = false;
        err("RZ0323", api.pathSpan, `Path parameter ":${p}" is never used in endpoint "${name}".`,
          `Use it in the query (for example \`db.${model.name}.find(${p})\`) or remove it from the path.`);
      }
    }

    if (!ok || query === undefined) return undefined;
    return {
      method: api.method,
      path: api.path,
      segments,
      params: [...params].map(([pname, p]) => ({ name: pname, type: p.type })),
      access,
      owner,
      ownerBypassRoles: ownerStmt === undefined ? [] : roleList(ownerStmt.orRoles),
      roles: requiredRoles,
      rateLimit,
      returns: expected,
      query,
      expand,
    };
  }

  function checkPath(api: ApiDecl): PathSegment[] | undefined {
    return parseRoutePath(api.path, api.pathSpan, err);
  }

}

/** Reserved first path segments: login endpoints and the page runtime's files. */
const RESERVED_SEGMENTS: readonly string[] = ["auth", "_rizo"];

/**
 * Validate a route path (for endpoints and pages) and split it into segments.
 * Reports RZ0322 and returns undefined when the path is not allowed.
 */
export function parseRoutePath(p: string, span: Span, err: Err): PathSegment[] | undefined {
  const bad = (message: string, fix: string): undefined => {
    err("RZ0322", span, message, fix);
    return undefined;
  };
  if (p === "/") return [];
  if (p.endsWith("/")) return bad(`Path "${p}" ends with "/".`, `Remove the trailing slash: \`${p.replace(/\/+$/, "")}\`.`);
  const segments: PathSegment[] = [];
  const seen = new Set<string>();
  for (const raw of p.slice(1).split("/")) {
    if (raw === "") return bad(`Path "${p}" contains an empty segment ("//").`, "Remove the extra slash.");
    if (raw.startsWith(":")) {
      const pname = raw.slice(1);
      if (!/^[a-z][A-Za-z0-9]*$/.test(pname)) {
        return bad(`Path parameter "${raw}" must be a camelCase name.`, "Write parameters like `:id` or `:userId`.");
      }
      if (RESERVED_PARAM_NAMES.includes(pname)) {
        return bad(`"${pname}" is reserved and cannot be a path parameter.`, "Choose another name, such as `:userId`.");
      }
      if (seen.has(pname)) return bad(`Path parameter ":${pname}" appears twice in "${p}".`, "Give each parameter a different name.");
      seen.add(pname);
      segments.push({ kind: "param", name: pname });
    } else {
      if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(raw)) {
        return bad(`Path segment "${raw}" is not allowed.`,
          `Use lowercase letters, digits and single hyphens, for example \`${raw.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || "posts"}\`.`);
      }
      segments.push({ kind: "static", value: raw });
    }
  }
  const first = segments[0];
  if (first?.kind === "static" && RESERVED_SEGMENTS.includes(first.value)) {
    return bad(`Paths under /${first.value} are reserved${first.value === "auth" ? " for login and signup" : " for the page runtime"}.`,
      "Choose a different first path segment.");
  }
  return segments;
}

/** The shape of a path for comparisons: parameters become ":". */
export function pathShape(segments: readonly PathSegment[]): string {
  return `/${segments.map((s) => (s.kind === "param" ? ":" : s.value)).join("/")}`;
}
