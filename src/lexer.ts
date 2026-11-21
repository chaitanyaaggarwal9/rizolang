import { type Diagnostic, type Span, diagnostic } from "./diagnostics.js";

export type TokenKind = "ident" | "int" | "lbrace" | "rbrace" | "colon" | "eof";

export interface Token {
  readonly kind: TokenKind;
  readonly text: string;
  /** Numeric value, only for "int" tokens. */
  readonly value: number;
  readonly span: Span;
}

export type LexResult =
  | { readonly ok: true; readonly tokens: readonly Token[] }
  | { readonly ok: false; readonly diagnostic: Diagnostic };

/** Integers may have at most this many digits (enough for any 32-bit value). */
const MAX_DIGITS = 10;

/** Targeted advice for characters people (and AIs) commonly type by habit. */
const CHARACTER_FIXES: Readonly<Record<string, string>> = {
  ",": "Rizo Lang does not use commas. Put each field on its own line.",
  ";": "Rizo Lang does not use semicolons. Remove it.",
  "_": "Names may contain only letters and digits. Use camelCase (userName) for fields and PascalCase (BlogPost) for models.",
  "?": 'Mark optional fields with the optional modifier: `nickname: Text optional`.',
  "(": "Write limits as modifiers, not arguments: `name: Text max 100`.",
  ")": "Write limits as modifiers, not arguments: `name: Text max 100`.",
  "@": "Write modifiers without @: `email: Email unique`.",
  "=": "Default values are not supported. Remove the `=` and the value after it.",
  '"': "Quoted text is not used in model blocks. Remove the quotes.",
  "'": "Quoted text is not used in model blocks. Remove the quotes.",
  "[": "Lists are not supported yet. Use a single value.",
  "]": "Lists are not supported yet. Use a single value.",
  "/": "Comments start with two slashes: `// like this`.",
  "#": "Comments start with two slashes: `// like this`.",
};

const isLetter = (c: string | undefined): boolean => c !== undefined && /[A-Za-z]/.test(c);
const isDigit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";
const isAlnum = (c: string | undefined): boolean => isLetter(c) || isDigit(c);

export function lex(rawSource: string, file: string): LexResult {
  // Normalize line endings so line/column numbers are the same on every OS.
  const src = rawSource.replace(/\r\n|\r/g, "\n");
  const tokens: Token[] = [];
  let i = 0;
  let line = 1;
  let col = 1;

  const push = (kind: TokenKind, text: string, value = 0): void => {
    tokens.push({ kind, text, value, span: { line, col, length: text.length } });
    i += text.length;
    col += text.length;
  };

  while (i < src.length) {
    const c = src[i];
    if (c === "\n") {
      i++;
      line++;
      col = 1;
    } else if (c === " " || c === "\t") {
      i++;
      col++;
    } else if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") {
        i++;
        col++;
      }
    } else if (isLetter(c)) {
      let j = i;
      while (isAlnum(src[j])) j++;
      push("ident", src.slice(i, j));
    } else if (isDigit(c) || (c === "-" && isDigit(src[i + 1]))) {
      let j = c === "-" ? i + 1 : i;
      while (isDigit(src[j])) j++;
      const text = src.slice(i, j);
      const digits = text.replace("-", "");
      if (src[j] === "." && isDigit(src[j + 1])) {
        let k = j + 1;
        while (isDigit(src[k])) k++;
        return fail("RZ0102", { line, col, length: k - i },
          `Decimal number "${src.slice(i, k)}" is not allowed here.`,
          `Use a whole number, such as ${text}.`);
      }
      if (isLetter(src[j]) || src[j] === "_") {
        let k = j;
        while (isAlnum(src[k]) || src[k] === "_") k++;
        return fail("RZ0102", { line, col, length: k - i },
          `Invalid number "${src.slice(i, k)}".`,
          `Write the number on its own, followed by a space or a new line, such as ${text}.`);
      }
      if (digits.length > MAX_DIGITS) {
        return fail("RZ0102", { line, col, length: text.length },
          `Number "${text}" is too large.`,
          "Use a number between -2147483648 and 2147483647.");
      }
      push("int", text, Number(text));
    } else if (c === "{") {
      push("lbrace", c);
    } else if (c === "}") {
      push("rbrace", c);
    } else if (c === ":") {
      push("colon", c);
    } else {
      const ch = String.fromCodePoint(src.codePointAt(i) ?? 0);
      const shown = /^[\x21-\x7e]$/.test(ch)
        ? `"${ch}"`
        : `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
      return fail("RZ0101", { line, col, length: 1 },
        `Unexpected character ${shown}.`,
        CHARACTER_FIXES[ch] ??
          "Remove it. Model blocks may contain only letters, digits, {, }, :, - and // comments.");
    }
  }
  tokens.push({ kind: "eof", text: "", value: 0, span: { line, col, length: 1 } });
  return { ok: true, tokens };

  function fail(code: string, span: Span, message: string, fix: string): LexResult {
    return { ok: false, diagnostic: diagnostic(code, file, span, message, fix) };
  }
}
