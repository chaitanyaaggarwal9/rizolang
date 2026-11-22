import { type Diagnostic, type Span, diagnostic } from "./diagnostics.js";

export type TokenKind =
  | "ident"
  | "int"
  | "path"
  | "string"
  | "lbrace"
  | "rbrace"
  | "lparen"
  | "rparen"
  | "colon"
  | "comma"
  | "dot"
  | "equals"
  | "arrow"
  | "eof";

export interface Token {
  readonly kind: TokenKind;
  /** The token as written; for "string" tokens, the decoded text without quotes. */
  readonly text: string;
  /** Numeric value, only for "int" tokens. */
  readonly value: number;
  readonly span: Span;
}

export type LexResult =
  | { readonly ok: true; readonly tokens: readonly Token[] }
  | { readonly ok: false; readonly diagnostic: Diagnostic };

/** Longest text allowed in quotes, in characters. */
export const MAX_TEXT = 200;

/** Integers may have at most this many digits (enough for any 32-bit value). */
const MAX_DIGITS = 10;

/** Targeted advice for characters people (and AIs) commonly type by habit. */
const CHARACTER_FIXES: Readonly<Record<string, string>> = {
  ";": "Rizo Lang does not use semicolons. Remove it.",
  "_": "Names may contain only letters and digits. Use camelCase (userName) for fields and PascalCase (BlogPost) for models.",
  "?": 'Mark optional fields with the optional modifier: `nickname: Text optional`.',
  "@": "Write modifiers without @: `email: Email unique`.",
  "'": 'Write text in double quotes: "Latest posts".',
  "[": "Lists are not supported. To return many records, write `-> list Post.public`.",
  "]": "Lists are not supported. To return many records, write `-> list Post.public`.",
  "#": "Comments start with two slashes: `// like this`.",
  "&": "Combine filters with commas: `db.Post.list(author = me, published = true)`.",
  "|": "Rizo Lang has no `or`. Write separate api blocks instead.",
  "!": "Rizo Lang has no `!=`. Filters compare with `=` only.",
  "<": "Only `=` comparisons are supported in filters.",
  ">": "Only `=` comparisons are supported in filters. The return arrow is written `->`.",
  "-": "A minus sign must be followed by a digit (-5), and the return arrow is written `->`.",
};

const isLetter = (c: string | undefined): boolean => c !== undefined && /[A-Za-z]/.test(c);
const isDigit = (c: string | undefined): boolean => c !== undefined && c >= "0" && c <= "9";
const isAlnum = (c: string | undefined): boolean => isLetter(c) || isDigit(c);
/** Characters a URL path token may contain. The checker validates paths strictly. */
const isPathChar = (c: string | undefined): boolean => c !== undefined && /[A-Za-z0-9/:_-]/.test(c);

const SINGLE: Readonly<Record<string, TokenKind>> = {
  "{": "lbrace",
  "}": "rbrace",
  "(": "lparen",
  ")": "rparen",
  ":": "colon",
  ",": "comma",
  ".": "dot",
  "=": "equals",
};

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
    } else if (c === '"') {
      // Quoted text: one line, only \" and \\ escapes, no control characters.
      let j = i + 1;
      let value = "";
      for (;;) {
        const d = src[j];
        if (d === undefined || d === "\n") {
          return fail("RZ0103", { line, col, length: j - i },
            "Quoted text is not closed on this line.", 'End the text with a double quote on the same line: "like this".');
        }
        if (d === '"') break;
        if (d === "\\") {
          const e = src[j + 1];
          if (e !== '"' && e !== "\\") {
            return fail("RZ0103", { line, col: col + (j - i), length: 2 },
              `"\\${e ?? ""}" is not allowed in quoted text.`, 'Only \\" (a double quote) and \\\\ (a backslash) can be escaped. Remove the backslash.');
          }
          value += e;
          j += 2;
          continue;
        }
        if (d < " " || d === "\u007f") {
          return fail("RZ0103", { line, col: col + (j - i), length: 1 },
            "Quoted text contains a control character.", "Remove it. Text must be printable characters on one line.");
        }
        value += d;
        j++;
      }
      const raw = src.slice(i, j + 1);
      if ([...value].length > MAX_TEXT) {
        return fail("RZ0103", { line, col, length: raw.length },
          `Quoted text is ${[...value].length} characters long; at most ${MAX_TEXT} are allowed.`, "Shorten the text.");
      }
      tokens.push({ kind: "string", text: value, value: 0, span: { line, col, length: raw.length } });
      i += raw.length;
      col += raw.length;
    } else if (c === "/") {
      let j = i;
      // Inside a path, "//" is part of the path (the checker reports the empty
      // segment). A comment after a path must be separated by a space.
      while (isPathChar(src[j])) j++;
      push("path", src.slice(i, j));
    } else if (isLetter(c)) {
      let j = i;
      while (isAlnum(src[j])) j++;
      // A region code such as US-CA (in `privacy for ...`) is one word.
      if (/^[A-Z]{2}-[A-Z]{2}\b/.test(src.slice(i, i + 6)) && j === i + 2 && !isAlnum(src[i + 5])) j = i + 5;
      push("ident", src.slice(i, j));
    } else if (c === "-" && src[i + 1] === ">") {
      push("arrow", "->");
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
    } else if (c !== undefined && SINGLE[c] !== undefined) {
      push(SINGLE[c], c);
    } else {
      const ch = String.fromCodePoint(src.codePointAt(i) ?? 0);
      const shown = /^[\x21-\x7e]$/.test(ch)
        ? `"${ch}"`
        : `U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}`;
      return fail("RZ0101", { line, col, length: 1 },
        `Unexpected character ${shown}.`,
        CHARACTER_FIXES[ch] ??
          "Remove it. Rizo Lang uses only letters, digits, paths like /posts/:id, the symbols { } ( ) : , . = -> and // comments.");
    }
  }
  tokens.push({ kind: "eof", text: "", value: 0, span: { line, col, length: 1 } });
  return { ok: true, tokens };

  function fail(code: string, span: Span, message: string, fix: string): LexResult {
    return { ok: false, diagnostic: diagnostic(code, file, span, message, fix) };
  }
}
