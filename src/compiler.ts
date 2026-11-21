import type { ResolvedApi, ResolvedAuth } from "./check-api.js";
import type { ResolvedPage } from "./check-page.js";
import { type ResolvedModel, check } from "./checker.js";
import { type Diagnostic, diagnostic, sourceLines } from "./diagnostics.js";
import { emitOpenApi } from "./emit/openapi.js";
import { emitMigrate, emitPackageJson, emitReencrypt, emitRoutes, emitServer, emitTsconfig } from "./emit/routes.js";
import { emitSql } from "./emit/sql.js";
import { emitTypeScript } from "./emit/typescript.js";
import { lex } from "./lexer.js";
import { FUTURE_BLOCKS, parse } from "./parser.js";

/** The generated backend. Present only when the file has an auth line or api blocks. */
export interface ServerOutput {
  /** dist/routes.ts: every endpoint as data, with SQL fixed at compile time. */
  readonly routes: string;
  /** dist/server.ts: the entry point. */
  readonly server: string;
  /** dist/package.json */
  readonly packageJson: string;
  /** dist/tsconfig.json */
  readonly tsconfig: string;
  /** dist/migrate.ts: applies migrations/ to the database. */
  readonly migrate: string;
  /** OpenAPI 3.1 description of the endpoints. */
  readonly openapi: string;
  /** Only for apps with encrypted fields. */
  readonly reencrypt?: string;
}

export interface CompileOutput {
  /** Contents of dist/schema.sql */
  readonly sql: string;
  /** Contents of dist/types.ts */
  readonly typescript: string;
  readonly server: ServerOutput | undefined;
}

export type CompileResult =
  | {
      readonly ok: true;
      readonly models: readonly ResolvedModel[];
      readonly auth: ResolvedAuth | undefined;
      readonly apis: readonly ResolvedApi[];
      readonly pages: readonly ResolvedPage[];
      readonly output: CompileOutput;
    }
  | { readonly ok: false; readonly diagnostics: readonly Diagnostic[] };

/**
 * Compile one .rz source file. Pipeline: lex -> parse -> check -> emit.
 * `file` is used in error messages and generated headers.
 */
export function compile(source: string, file: string): CompileResult {
  const lexed = lex(source, file);
  if (!lexed.ok) {
    // A block from a later milestone (e.g. `page /home`) may contain characters
    // the lexer rejects. Report the missing feature, not the character.
    const future = findFutureBlock(source, file, lexed.diagnostic.span.line);
    return { ok: false, diagnostics: [future ?? lexed.diagnostic] };
  }

  const parsed = parse(lexed.tokens, file);
  if (!parsed.ok) return { ok: false, diagnostics: [parsed.diagnostic] };

  const checked = check(parsed.program, file);
  if (!checked.ok) return { ok: false, diagnostics: checked.diagnostics };

  // The file name is echoed into generated comments; keep it to one printable line.
  const label = file.replace(/[^\x20-\x7e]/g, "?");
  const { models, auth, apis, pages } = checked;
  const hasServer = auth !== undefined || apis.length > 0 || pages.length > 0;
  return {
    ok: true,
    models,
    auth,
    apis,
    pages,
    output: {
      sql: emitSql(models, auth, label, hasServer, apis),
      typescript: emitTypeScript(models, auth, label),
      server: hasServer
        ? {
            routes: emitRoutes(apis, auth, pages, label),
            server: emitServer(label),
            packageJson: emitPackageJson(),
            tsconfig: emitTsconfig(),
            migrate: emitMigrate(label),
            openapi: emitOpenApi(apis, auth, label),
            ...(models.some((m) => m.fields.some((f) => f.encrypted)) ? { reencrypt: emitReencrypt(label) } : {}),
          }
        : undefined,
    },
  };
}

function findFutureBlock(source: string, file: string, upToLine: number): Diagnostic | undefined {
  const lines = sourceLines(source);
  for (let i = 0; i < upToLine && i < lines.length; i++) {
    const m = /^(\s*)([a-z]+)\s+[^:\s]/.exec(lines[i] ?? "");
    const indent = m?.[1];
    const word = m?.[2];
    if (indent !== undefined && word !== undefined && FUTURE_BLOCKS.includes(word)) {
      return diagnostic("RZ0211", file, { line: i + 1, col: indent.length + 1, length: word.length },
        `"${word}" blocks are not available yet.`,
        "This version of Rizo Lang supports model, auth and api blocks. Remove this block for now.");
    }
  }
  return undefined;
}
