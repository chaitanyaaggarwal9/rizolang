import { type ResolvedModel, check } from "./checker.js";
import type { Diagnostic } from "./diagnostics.js";
import { emitSql } from "./emit/sql.js";
import { emitTypeScript } from "./emit/typescript.js";
import { lex } from "./lexer.js";
import { FUTURE_BLOCKS, parse } from "./parser.js";
import { diagnostic, sourceLines } from "./diagnostics.js";

export interface CompileOutput {
  /** Contents of dist/schema.sql */
  readonly sql: string;
  /** Contents of dist/types.ts */
  readonly typescript: string;
}

export type CompileResult =
  | { readonly ok: true; readonly models: readonly ResolvedModel[]; readonly output: CompileOutput }
  | { readonly ok: false; readonly diagnostics: readonly Diagnostic[] };

/**
 * Compile one .rz source file. Pipeline: lex -> parse -> check -> emit.
 * `file` is used in error messages and generated headers.
 */
export function compile(source: string, file: string): CompileResult {
  const lexed = lex(source, file);
  if (!lexed.ok) {
    // A block from a later milestone (e.g. `api GET /users`) contains characters
    // the model lexer rejects. Report the missing feature, not the character.
    const future = findFutureBlock(source, file, lexed.diagnostic.span.line);
    return { ok: false, diagnostics: [future ?? lexed.diagnostic] };
  }

  const parsed = parse(lexed.tokens, file);
  if (!parsed.ok) return { ok: false, diagnostics: [parsed.diagnostic] };

  const checked = check(parsed.program, file);
  if (!checked.ok) return { ok: false, diagnostics: checked.diagnostics };

  // The file name is echoed into generated comments; keep it to one printable line.
  const label = file.replace(/[^\x20-\x7e]/g, "?");
  return {
    ok: true,
    models: checked.models,
    output: {
      sql: emitSql(checked.models, label),
      typescript: emitTypeScript(checked.models, label),
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
        "This version of Rizo Lang supports only model blocks. Remove this block for now.");
    }
  }
  return undefined;
}
