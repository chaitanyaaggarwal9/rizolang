/**
 * `rizolang audit`: review a valid .rz file for risky choices.
 *
 * The compiler already refuses what is always wrong (raw SQL, missing access
 * rules, owners taken from request bodies...). The audit points out what is
 * allowed but often a mistake, with the exact location and a concrete fix,
 * so a person or an AI can decide. Findings are warnings (likely a problem)
 * or notes (worth a look). Nothing is written.
 */
import type { ApiDecl, Program } from "./ast.js";
import type { ResolvedApi } from "./check-api.js";
import type { ResolvedField, ResolvedModel } from "./checker.js";
import { type CompileResult, compile } from "./compiler.js";
import { type Diagnostic, type Span, diagnostic } from "./diagnostics.js";
import { lex } from "./lexer.js";
import { parse } from "./parser.js";

export interface Finding extends Diagnostic {
  readonly level: "warning" | "note";
}

export interface AuditSummary {
  readonly endpoints: number;
  readonly public: number;
  readonly login: number;
  readonly withRoles: number;
  readonly warnings: number;
  readonly notes: number;
}

export type AuditResult =
  | { readonly ok: true; readonly findings: readonly Finding[]; readonly summary: AuditSummary }
  | { readonly ok: false; readonly diagnostics: readonly Diagnostic[] };

/** Field names that usually hold personal or sensitive data. */
const SENSITIVE = /phone|mobile|address|street|postcode|postalcode|zipcode|birth|dob|ssn|socialsecurity|passport|nationalid|taxid|iban|cardnumber|creditcard|salary|income|health|medical|diagnosis|religion|ethnicity|latitude|longitude|ipaddress/i;
/** Field names that usually hold secrets, which should never be returned. */
const SECRET = /secret|token|apikey|privatekey|pin$|pincode|otp/i;

/** More than this many requests a minute on a public endpoint is worth a look. */
const LOOSE_RATE = 300;

export function audit(source: string, file: string): AuditResult {
  const compiled: CompileResult = compile(source, file);
  if (!compiled.ok) return { ok: false, diagnostics: compiled.diagnostics };
  // The checked program has no source locations, so the syntax tree is read again for them.
  const lexed = lex(source, file);
  const parsed = lexed.ok ? parse(lexed.tokens, file) : undefined;
  if (parsed === undefined || !parsed.ok) throw new Error("a valid program failed to parse again");
  const program: Program = parsed.program;
  const { models, auth, apis } = compiled;

  const findings: Finding[] = [];
  const add = (level: Finding["level"], code: string, span: Span, message: string, fix: string): void => {
    findings.push({ ...diagnostic(code, file, span, message, fix), level });
  };
  const declOf = (api: ResolvedApi): ApiDecl | undefined => program.apis.find((d) => d.method === api.method && d.path === api.path);
  const fieldSpan = (model: ResolvedModel, field: ResolvedField): Span =>
    program.models.find((m) => m.name === model.name)?.fields.find((f) => f.name === field.name)?.nameSpan ?? { line: 1, col: 1, length: 1 };
  const publicModels = new Set(apis.filter((a) => a.access === "public" && a.returns !== "none").map((a) => a.query.model.name));

  for (const api of apis) {
    const decl = declOf(api);
    if (decl === undefined) continue;
    const name = `${api.method} ${api.path}`;
    const model = api.query.model.name;
    const action = api.query.action;

    if (api.access === "public" && (action === "create" || action === "update" || action === "delete")) {
      const verb = action === "create" ? "create" : action === "update" ? "change" : "delete";
      add("warning", "RA01", decl.methodSpan, `Endpoint "${name}" is public, so anyone on the internet can ${verb} ${model} records without an account.`,
        `Replace \`public\` with \`requires login\`${action === "create" ? "" : ", plus `requires owner <field>` or `requires role admin`"}, unless that is really intended.`);
    }

    if (auth !== undefined && api.access === "public" && action === "list" && api.query.model === auth.model) {
      add("warning", "RA05", decl.pathSpan, `Endpoint "${name}" is public and lists every ${model}, so anyone can collect your users.`,
        "Add `requires login` and `requires role admin`, or remove the endpoint and show one account at a time with find.");
    }

    if (api.access === "login" && (action === "update" || action === "delete") && api.owner === undefined && api.roles.length === 0) {
      add("warning", "RA06", decl.methodSpan, `Any logged-in user can ${action === "update" ? "change" : "delete"} any ${model} with "${name}".`,
        `Add \`requires role admin\`, or give ${model} a link to the account model and add \`requires owner <field>\`.`);
    }

    if (api.access === "public") {
      const perMinute = (api.rateLimit.max * 60) / api.rateLimit.windowSeconds;
      if (perMinute > LOOSE_RATE) {
        const stmt = decl.statements.find((s) => s.kind === "limit");
        add("note", "RA07", stmt?.span ?? decl.methodSpan,
          `Endpoint "${name}" is public and allows about ${Math.round(perMinute)} requests a minute from one address.`,
          `Unless clients really need that many, use a lower limit, such as \`limit ${LOOSE_RATE / 5} per minute\`.`);
      }
    }
  }

  for (const model of models) {
    for (const field of model.fields) {
      if (field.link !== undefined || field.type === "Password" || field.type === "Bool") continue;
      const where = `${model.name}.${field.name}`;
      const span = fieldSpan(model, field);
      if (SECRET.test(field.name) && !field.private) {
        add("warning", "RA02", span, `Field "${where}" looks like a secret, but it is returned by every endpoint that shows ${model.name}.`,
          `Add \`private\` (and \`encrypted\`), or use the Password type if it is checked but never read back.`);
      } else if (SENSITIVE.test(field.name) && !field.private) {
        add("warning", "RA02", span, `Field "${where}" looks like personal data, but it is returned by every endpoint that shows ${model.name}.`,
          "Add `private` to keep it out of responses, and `encrypted` to keep it unreadable in the database and backups.");
      } else if ((SENSITIVE.test(field.name) || SECRET.test(field.name)) && !field.encrypted) {
        add("note", "RA03", span, `Field "${where}" looks sensitive and is private, but it is stored as plain text.`,
          "Add `encrypted` so the database and its backups never hold the value (it can't then be unique, filtered or sorted).");
      } else if (field.type === "Email" && !field.private && publicModels.has(model.name)) {
        add("warning", "RA04", span, `Field "${where}" is returned by public endpoints, so anyone can collect these email addresses.`,
          "Add `private` to the field. Accounts still log in with it.");
      }
    }
  }

  findings.sort((a, b) => a.span.line - b.span.line || a.span.col - b.span.col);
  return {
    ok: true,
    findings,
    summary: {
      endpoints: apis.length,
      public: apis.filter((a) => a.access === "public").length,
      login: apis.filter((a) => a.access === "login").length,
      withRoles: apis.filter((a) => a.roles.length > 0 || a.ownerBypassRoles.length > 0).length,
      warnings: findings.filter((f) => f.level === "warning").length,
      notes: findings.filter((f) => f.level === "note").length,
    },
  };
}
