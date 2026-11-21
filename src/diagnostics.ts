/**
 * Diagnostics: every error the compiler reports says WHAT went wrong,
 * WHERE (file, line, column) and HOW to fix it.
 *
 * Printed format (stable, parseable by humans, AIs and editors):
 *
 *   users.rz:3:9 error RZ0301: Unknown field type "String".
 *     3 |   name: String
 *       |         ^^^^^^
 *     fix: Use "Text" for text values.
 */

/** A source location. `line` and `col` are 1-based; `length` is in characters. */
export interface Span {
  readonly line: number;
  readonly col: number;
  readonly length: number;
}

export interface Diagnostic {
  /** Stable error code, e.g. "RZ0301". See docs/SPEC.md for the full list. */
  readonly code: string;
  /** What went wrong, as one sentence. */
  readonly message: string;
  /** File name as given to the compiler. */
  readonly file: string;
  /** Where it went wrong. */
  readonly span: Span;
  /** How to fix it, as one concrete instruction. */
  readonly fix: string;
}

export function diagnostic(
  code: string,
  file: string,
  span: Span,
  message: string,
  fix: string,
): Diagnostic {
  return { code, file, span, message, fix };
}

/** Split source into lines the same way the lexer counts them. */
export function sourceLines(source: string): string[] {
  return source.split(/\r\n|\r|\n/);
}

export function formatDiagnostic(d: Diagnostic, source?: string, level: "error" | "warning" | "note" = "error"): string {
  const out: string[] = [
    `${d.file}:${d.span.line}:${d.span.col} ${level} ${d.code}: ${d.message}`,
  ];
  if (source !== undefined) {
    const text = sourceLines(source)[d.span.line - 1];
    if (text !== undefined) {
      const num = String(d.span.line);
      const gutter = " ".repeat(num.length);
      // Tabs count as one column, so show them as one space to keep the caret aligned.
      out.push(`  ${num} | ${text.replace(/\t/g, " ")}`);
      out.push(
        `  ${gutter} | ${" ".repeat(Math.max(0, d.span.col - 1))}${"^".repeat(Math.max(1, d.span.length))}`,
      );
    }
  }
  out.push(`  fix: ${d.fix}`);
  return out.join("\n");
}

/** Levenshtein distance, used for "did you mean" suggestions. */
function distance(a: string, b: string): number {
  const prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let diag = prev[0] ?? 0;
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const up = prev[j] ?? 0;
      const left = prev[j - 1] ?? 0;
      prev[j] = Math.min(up + 1, left + 1, diag + (a[i - 1] === b[j - 1] ? 0 : 1));
      diag = up;
    }
  }
  return prev[b.length] ?? 0;
}

/** Return the closest candidate to `word`, or undefined if nothing is close. */
export function didYouMean(word: string, candidates: readonly string[]): string | undefined {
  const lower = word.toLowerCase();
  const exact = candidates.find((c) => c.toLowerCase() === lower);
  if (exact !== undefined) return exact;
  let best: string | undefined;
  let bestScore = Infinity;
  for (const c of candidates) {
    const score = distance(lower, c.toLowerCase());
    if (score < bestScore) {
      best = c;
      bestScore = score;
    }
  }
  const limit = word.length <= 4 ? 1 : 2;
  return bestScore <= limit ? best : undefined;
}
