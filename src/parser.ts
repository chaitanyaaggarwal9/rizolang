import { MODIFIER_NAMES, type FieldDecl, type ModelDecl, type Modifier, type Program } from "./ast.js";
import { type Diagnostic, type Span, didYouMean, diagnostic } from "./diagnostics.js";
import type { Token } from "./lexer.js";
import { FIELD_TYPE_NAMES } from "./types.js";

export type ParseResult =
  | { readonly ok: true; readonly program: Program }
  | { readonly ok: false; readonly diagnostic: Diagnostic };

/** Block keywords planned for later milestones. */
export const FUTURE_BLOCKS: readonly string[] = ["api", "page", "component", "enum", "import", "type", "test"];

/** Words from other languages that people write instead of `model`. */
const MODEL_LOOKALIKES: readonly string[] = ["Model", "MODEL", "class", "struct", "table", "interface", "entity", "schema"];

class ParseError extends Error {
  constructor(readonly diagnostic: Diagnostic) {
    super(diagnostic.message);
  }
}

function describe(t: Token): string {
  switch (t.kind) {
    case "eof": return "the end of the file";
    case "ident": return `"${t.text}"`;
    case "int": return `the number ${t.text}`;
    default: return `"${t.text}"`;
  }
}

/**
 * Recursive-descent parser. Stops at the first syntax error, because later
 * errors after a syntax error are usually noise.
 */
export function parse(tokens: readonly Token[], file: string): ParseResult {
  let pos = 0;
  const last = tokens[tokens.length - 1];
  if (last === undefined || last.kind !== "eof") throw new Error("token stream must end with eof");

  const peek = (offset = 0): Token => tokens[Math.min(pos + offset, tokens.length - 1)] ?? last;
  const next = (): Token => {
    const t = peek();
    if (pos < tokens.length - 1) pos++;
    return t;
  };
  function fail(code: string, span: Span, message: string, fix: string): never {
    throw new ParseError(diagnostic(code, file, span, message, fix));
  }

  function parseProgram(): Program {
    const models: ModelDecl[] = [];
    while (peek().kind !== "eof") {
      const t = peek();
      if (t.kind === "ident" && t.text === "model") {
        models.push(parseModel());
      } else if (t.kind === "ident" && FUTURE_BLOCKS.includes(t.text)) {
        fail("RZ0211", t.span, `"${t.text}" blocks are not available yet.`,
          "This version of Rizo Lang supports only model blocks. Remove this block for now.");
      } else if (t.kind === "ident" && MODEL_LOOKALIKES.includes(t.text)) {
        fail("RZ0201", t.span, `Expected "model" but found "${t.text}".`,
          "Start each block with the lowercase keyword model: `model User { ... }`.");
      } else {
        fail("RZ0201", t.span, `Expected "model" but found ${describe(t)}.`,
          "Every top-level block must start with the keyword model: `model User { ... }`.");
      }
    }
    return { models };
  }

  function parseModel(): ModelDecl {
    next(); // the `model` keyword
    const nameTok = peek();
    if (nameTok.kind !== "ident") {
      fail("RZ0202", nameTok.span, `Expected a model name after "model" but found ${describe(nameTok)}.`,
        "Give the model a PascalCase name: `model User { ... }`.");
    }
    next();
    const brace = peek();
    if (brace.kind !== "lbrace") {
      fail("RZ0203", brace.span, `Expected "{" after model name "${nameTok.text}" but found ${describe(brace)}.`,
        `Open the model body with a brace: \`model ${nameTok.text} {\`.`);
    }
    next();

    const fields: FieldDecl[] = [];
    let lastFieldLine = -1;
    for (;;) {
      const t = peek();
      if (t.kind === "rbrace") {
        next();
        break;
      }
      if (t.kind === "eof") {
        fail("RZ0210", brace.span, `Model "${nameTok.text}" is missing its closing "}".`,
          `Add } on its own line after the last field of ${nameTok.text}.`);
      }
      if (t.kind === "ident" && t.text === "model" && peek(1).kind === "ident") {
        fail("RZ0210", brace.span, `Model "${nameTok.text}" is missing its closing "}" before the next model.`,
          `Add } on its own line after the last field of ${nameTok.text}.`);
      }
      if (t.kind !== "ident") {
        fail("RZ0204", t.span, `Expected a field name or "}" in model "${nameTok.text}" but found ${describe(t)}.`,
          "Write one field per line as `name: Type`, and close the model with }.");
      }
      if (t.span.line === lastFieldLine) {
        fail("RZ0209", t.span, `Field "${t.text}" must start on a new line.`,
          "Put each field on its own line.");
      }
      const field = parseField(nameTok.text);
      fields.push(field);
      lastFieldLine = peek(-1).span.line;
    }
    return { name: nameTok.text, nameSpan: nameTok.span, fields };
  }

  function parseField(modelName: string): FieldDecl {
    const nameTok = next();
    const colon = peek();
    if (colon.kind !== "colon") {
      const hint = colon.kind === "ident" && colon.span.line === nameTok.span.line
        ? `Add a colon between the name and the type: \`${nameTok.text}: ${colon.text}\`.`
        : `Write the field as \`${nameTok.text}: Type\`, for example \`${nameTok.text}: Text\`.`;
      fail("RZ0205", colon.span, `Expected ":" after field name "${nameTok.text}" but found ${describe(colon)}.`, hint);
    }
    next();
    const typeTok = peek();
    if (typeTok.kind !== "ident" || typeTok.span.line !== colon.span.line) {
      fail("RZ0206", typeTok.span.line === colon.span.line ? typeTok.span : { ...colon.span, col: colon.span.col + 1 },
        `Expected a field type after "${nameTok.text}:".`,
        `Write the type on the same line. Valid types: ${FIELD_TYPE_NAMES.join(", ")}.`);
    }
    next();

    const modifiers: Modifier[] = [];
    let prev = typeTok;
    while (peek().kind !== "eof" && peek().span.line === prev.span.line) {
      const t = peek();
      if (t.kind === "rbrace") break;
      if (t.kind !== "ident") {
        fail("RZ0212", t.span, `Unexpected ${describe(t)} after field "${nameTok.text}".`,
          `After the type, write only modifiers: ${MODIFIER_NAMES.join(", ")}. Example: \`${nameTok.text}: ${typeTok.text} max 100\`.`);
      }
      next();
      if (t.text === "unique" || t.text === "optional") {
        modifiers.push({ kind: t.text, span: t.span });
        prev = t;
      } else if (t.text === "min" || t.text === "max") {
        const num = peek();
        if (num.kind !== "int" || num.span.line !== t.span.line) {
          fail("RZ0208", num.span.line === t.span.line ? num.span : t.span,
            `Expected a whole number after "${t.text}".`,
            `Write the limit as a number: \`${t.text} 100\`.`);
        }
        next();
        modifiers.push({ kind: t.text, value: num.value, span: t.span, valueSpan: num.span });
        prev = num;
      } else {
        const guess = didYouMean(t.text, MODIFIER_NAMES);
        fail("RZ0207", t.span, `Unknown modifier "${t.text}" on field "${modelName}.${nameTok.text}".`,
          guess !== undefined
            ? `Did you mean "${guess}"? Valid modifiers: ${MODIFIER_NAMES.join(", ")}.`
            : `Valid modifiers: ${MODIFIER_NAMES.join(", ")}. Put each field on its own line.`);
      }
    }
    return {
      name: nameTok.text,
      nameSpan: nameTok.span,
      typeName: typeTok.text,
      typeSpan: typeTok.span,
      modifiers,
    };
  }

  try {
    return { ok: true, program: parseProgram() };
  } catch (e) {
    if (e instanceof ParseError) return { ok: false, diagnostic: e.diagnostic };
    throw e;
  }
}
