import {
  HTTP_METHODS,
  MODIFIER_NAMES,
  type ApiDecl,
  type AuthDecl,
  type FieldDecl,
  type HttpMethod,
  type ModelDecl,
  type PageDecl,
  type PageStatement,
  type TextRef,
  type Modifier,
  type Program,
  type Query,
  type QueryArg,
  type ReturnType,
  type RoleRef,
  type Statement,
  type Value,
} from "./ast.js";
import { type Diagnostic, type Span, didYouMean, diagnostic } from "./diagnostics.js";
import type { Token, TokenKind } from "./lexer.js";
import { FIELD_TYPE_NAMES } from "./types.js";

export type ParseResult =
  | { readonly ok: true; readonly program: Program }
  | { readonly ok: false; readonly diagnostic: Diagnostic };

/** Block keywords planned for later milestones. */
export const FUTURE_BLOCKS: readonly string[] = ["component", "enum", "import", "type", "test"];

const PAGE_WORDS: readonly string[] = ["public", "requires", "title", "text", "link", "show", "form", "button", "then"];

/** Words from other languages that people write instead of `model`. */
const MODEL_LOOKALIKES: readonly string[] = ["Model", "MODEL", "class", "struct", "table", "interface", "entity", "schema"];
/** Words people write instead of `api`. */
const API_LOOKALIKES: readonly string[] = ["API", "Api", "route", "endpoint", "get", "post", "put", "patch", "delete", "GET", "POST", "PUT", "PATCH", "DELETE"];

const STATEMENT_WORDS: readonly string[] = ["public", "requires", "limit", "return"];

/** Advice for a stray token after a field type, keyed by token kind. */
const FIELD_TOKEN_FIXES: Partial<Record<TokenKind, string>> = {
  comma: "Rizo Lang does not use commas between fields. Put each field on its own line.",
  string: "Quoted text is only allowed in page blocks.",
  lparen: "Write limits as modifiers, not arguments: `name: Text max 100`.",
  equals: "Default values are not supported. Remove the `=` and the value after it.",
};

class ParseError extends Error {
  readonly diagnostic: Diagnostic;
  constructor(d: Diagnostic) {
    super(d.message);
    this.diagnostic = d;
  }
}

function describe(t: Token): string {
  switch (t.kind) {
    case "eof": return "the end of the file";
    case "int": return `the number ${t.text}`;
    case "path": return `the path ${t.text}`;
    case "string": return `the text "${t.text.length > 30 ? `${t.text.slice(0, 30)}…` : t.text}"`;
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

  const peek = (offset = 0): Token => tokens[Math.max(0, Math.min(pos + offset, tokens.length - 1))] ?? last;
  const next = (): Token => {
    const t = peek();
    if (pos < tokens.length - 1) pos++;
    return t;
  };
  const isWord = (t: Token, word: string): boolean => t.kind === "ident" && t.text === word;
  function fail(code: string, span: Span, message: string, fix: string): never {
    throw new ParseError(diagnostic(code, file, span, message, fix));
  }

  function parseProgram(): Program {
    const models: ModelDecl[] = [];
    const auths: AuthDecl[] = [];
    const apis: ApiDecl[] = [];
    const pages: PageDecl[] = [];
    while (peek().kind !== "eof") {
      const t = peek();
      if (isWord(t, "model")) {
        models.push(parseModel());
      } else if (isWord(t, "auth")) {
        auths.push(parseAuth());
      } else if (isWord(t, "api")) {
        apis.push(parseApi());
      } else if (isWord(t, "page")) {
        pages.push(parsePage());
      } else if (t.kind === "ident" && FUTURE_BLOCKS.includes(t.text)) {
        fail("RZ0211", t.span, `"${t.text}" blocks are not available yet.`,
          "This version of Rizo Lang supports model, auth and api blocks. Remove this block for now.");
      } else if (t.kind === "ident" && MODEL_LOOKALIKES.includes(t.text)) {
        fail("RZ0201", t.span, `Expected "model" but found "${t.text}".`,
          "Start each model with the lowercase keyword model: `model User { ... }`.");
      } else if (t.kind === "ident" && API_LOOKALIKES.includes(t.text)) {
        fail("RZ0201", t.span, `Expected "api" but found "${t.text}".`,
          "Start each endpoint with the lowercase keyword api: `api GET /posts -> list Post.public { ... }`.");
      } else {
        fail("RZ0201", t.span, `Expected "model", "auth", "api" or "page" but found ${describe(t)}.`,
          t.kind === "string" ? "Quoted text belongs inside a page block, for example `title \"Posts\"`." : "Every top-level block starts with model, auth, api or page.");
      }
    }
    return { models, auths, apis, pages };
  }

  // ---------------------------------------------------------------- models

  function parseModel(): ModelDecl {
    next(); // `model`
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
    let lastLine = -1;
    for (;;) {
      const t = peek();
      if (t.kind === "rbrace") {
        next();
        break;
      }
      checkUnclosed(t, brace.span, `Model "${nameTok.text}"`, `the last field of ${nameTok.text}`);
      if (t.kind !== "ident") {
        fail("RZ0204", t.span, `Expected a field name or "}" in model "${nameTok.text}" but found ${describe(t)}.`,
          "Write one field per line as `name: Type`, and close the model with }.");
      }
      if (t.span.line === lastLine) {
        fail("RZ0209", t.span, `Field "${t.text}" must start on a new line.`, "Put each field on its own line.");
      }
      fields.push(parseField(nameTok.text));
      lastLine = peek(-1).span.line;
    }
    return { name: nameTok.text, nameSpan: nameTok.span, fields };
  }

  /** Report a missing `}` when the file ends or the next block starts. */
  function checkUnclosed(t: Token, openSpan: Span, what: string, after: string): void {
    if (t.kind === "eof") {
      fail("RZ0210", openSpan, `${what} is missing its closing "}".`, `Add } on its own line after ${after}.`);
    }
    const startsBlock = (isWord(t, "model") && peek(1).kind === "ident") ||
      (isWord(t, "page") && peek(1).kind === "path") ||
      (isWord(t, "api") && peek(1).kind === "ident" && peek(2).kind === "path") ||
      (isWord(t, "auth") && peek(1).kind === "ident" && isWord(peek(2), "by"));
    if (startsBlock) {
      fail("RZ0210", openSpan, `${what} is missing its closing "}" before the next block.`,
        `Add } on its own line after ${after}.`);
    }
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
        `Write the type on the same line. Valid types: ${FIELD_TYPE_NAMES.join(", ")}, or the name of another model.`);
    }
    next();

    const modifiers: Modifier[] = [];
    let prev = typeTok;
    while (peek().kind !== "eof" && peek().span.line === prev.span.line) {
      const t = peek();
      if (t.kind === "rbrace") break;
      if (t.kind !== "ident") {
        fail("RZ0212", t.span, `Unexpected ${describe(t)} after field "${nameTok.text}".`,
          FIELD_TOKEN_FIXES[t.kind] ??
            `After the type, write only modifiers: ${MODIFIER_NAMES.join(", ")}. Example: \`${nameTok.text}: ${typeTok.text} max 100\`.`);
      }
      next();
      if (t.text === "unique" || t.text === "optional" || t.text === "private") {
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
    return { name: nameTok.text, nameSpan: nameTok.span, typeName: typeTok.text, typeSpan: typeTok.span, modifiers };
  }

  // ------------------------------------------------------------------ auth

  function parseAuth(): AuthDecl {
    const kw = next(); // `auth`
    const model = peek();
    const by = peek(1);
    const field = peek(2);
    const sameLine = (t: Token): boolean => t.span.line === kw.span.line;
    if (model.kind !== "ident" || !sameLine(model) || !isWord(by, "by") || !sameLine(by) ||
        field.kind !== "ident" || !sameLine(field)) {
      const bad = model.kind !== "ident" || !sameLine(model) ? model : !isWord(by, "by") || !sameLine(by) ? by : field;
      fail("RZ0218", sameLine(bad) ? bad.span : kw.span, `Expected \`auth <Model> by <field>\` but found ${describe(bad)}.`,
        "Write the auth line as `auth User by email`, where User has `email: Email unique` and a Password field.");
    }
    next();
    next();
    next();
    let roles: RoleRef[] = [];
    if (isWord(peek(), "roles") && sameLine(peek())) {
      const rolesTok = next();
      roles = parseRoleList(rolesTok, "auth User by email roles admin, editor");
    }
    return { span: kw.span, model: model.text, modelSpan: model.span, field: field.text, fieldSpan: field.span, roles };
  }

  /** One or more role names on the same line as `after`, separated by commas. */
  function parseRoleList(after: Token, example: string): RoleRef[] {
    const roles: RoleRef[] = [];
    for (;;) {
      const t = peek();
      if (t.kind !== "ident" || t.span.line !== after.span.line) {
        fail("RZ0219", t.span.line === after.span.line ? t.span : after.span,
          `Expected a role name after "${peek(-1).text}".`, `Write role names separated by commas: \`${example}\`.`);
      }
      next();
      roles.push({ name: t.text, span: t.span });
      if (peek().kind !== "comma" || peek().span.line !== after.span.line) break;
      next();
    }
    return roles;
  }

  // ------------------------------------------------------------------ page

  function parsePage(): PageDecl {
    const kw = next(); // `page`
    const pathTok = peek();
    if (pathTok.kind !== "path") {
      fail("RZ0214", pathTok.span, `Expected a path starting with "/" after "page" but found ${describe(pathTok)}.`,
        "Write the page's path, for example `page /posts {`.");
    }
    next();
    const brace = peek();
    if (brace.kind !== "lbrace") {
      fail("RZ0203", brace.span, `Expected "{" after the page path but found ${describe(brace)}.`,
        `Open the page body with a brace: \`page ${pathTok.text} {\`.`);
    }
    next();
    const statements: PageStatement[] = [];
    let lastLine = -1;
    for (;;) {
      const t = peek();
      if (t.kind === "rbrace") break;
      checkUnclosed(t, brace.span, `Page "${pathTok.text}"`, "its last line");
      if (t.span.line === lastLine) {
        fail("RZ0209", t.span, `${describe(t)} must start on a new line.`, "Put each statement on its own line.");
      }
      statements.push(parsePageStatement());
      lastLine = peek(-1).span.line;
      const after = peek();
      if (after.kind !== "rbrace" && after.kind !== "eof" && after.span.line === lastLine) {
        fail("RZ0212", after.span, `Unexpected ${describe(after)} at the end of the line.`, "Put each statement on its own line.");
      }
    }
    const end = next();
    return { span: kw.span, path: pathTok.text, pathSpan: pathTok.span, statements, endSpan: end.span };
  }

  function parseText(after: Token, example: string): TextRef {
    const t = peek();
    if (t.kind !== "string" || t.span.line !== after.span.line) {
      fail("RZ0221", t.span.line === after.span.line ? t.span : after.span,
        `Expected quoted text after "${after.text}".`, `Write the text in double quotes: \`${example}\`.`);
    }
    next();
    return { text: t.text, span: t.span };
  }

  function parsePageStatement(): PageStatement {
    const t = peek();
    if (t.kind !== "ident" || !PAGE_WORDS.includes(t.text)) {
      const guess = t.kind === "ident" ? didYouMean(t.text, PAGE_WORDS) : undefined;
      fail("RZ0220", t.span, `Unexpected ${describe(t)} in a page block.`,
        guess !== undefined
          ? `Did you mean "${guess}"? A page contains: public or requires login, title, text, link, show, form, button and then go lines.`
          : "A page contains: public or requires login, title \"...\", text \"...\", link \"...\" /path, show GET /api/path, form POST /api/path, button \"...\" DELETE /api/path, and then go /path.");
    }
    next();
    switch (t.text) {
      case "public":
        return { kind: "public", span: t.span };
      case "requires": {
        const what = peek();
        if (isWord(what, "login") && what.span.line === t.span.line) {
          next();
          return { kind: "requiresLogin", span: t.span };
        }
        if (isWord(what, "role") && what.span.line === t.span.line) {
          next();
          return { kind: "requiresRole", span: t.span, roles: parseRoleList(what, "requires role admin") };
        }
        return fail("RZ0220", what.span.line === t.span.line ? what.span : t.span,
          `Expected "login" or "role <name>" after "requires".`, "Write `requires login` or `requires role admin`. Pages have no `requires owner`; the data's endpoint decides that.");
      }
      case "title":
        return { kind: "title", span: t.span, text: parseText(t, 'title "Latest posts"') };
      case "text":
        return { kind: "text", span: t.span, text: parseText(t, 'text "Welcome to my blog."') };
      case "link": {
        const label = parseText(t, 'link "Write a post" /posts/new');
        const p = peek();
        if (p.kind !== "path" || p.span.line !== t.span.line) {
          fail("RZ0214", p.span.line === t.span.line ? p.span : t.span, "Expected a page path after the link text.",
            `Write the page to link to: \`link "${label.text}" /posts\`.`);
        }
        next();
        return { kind: "link", span: t.span, label, path: p.text, pathSpan: p.span };
      }
      case "then": {
        const go = peek();
        const p = peek(1);
        if (!isWord(go, "go") || go.span.line !== t.span.line || p.kind !== "path" || p.span.line !== t.span.line) {
          fail("RZ0220", go.span.line === t.span.line ? go.span : t.span, `Expected "go /path" after "then".`,
            "Say which page to open after the form or button succeeds, for example `then go /posts/:id`.");
        }
        next();
        next();
        return { kind: "thenGo", span: t.span, path: p.text, pathSpan: p.span };
      }
      default: {
        // show, form and button: [button "label"] METHOD /path
        const label = t.text === "button" ? parseText(t, 'button "Delete" DELETE /api/posts/:id') : undefined;
        const m = peek();
        const p = peek(1);
        if (m.kind !== "ident" || m.span.line !== t.span.line || p.kind !== "path" || p.span.line !== t.span.line) {
          const example = t.text === "show" ? "show GET /api/posts" : t.text === "form" ? "form POST /api/posts" : 'button "Delete" DELETE /api/posts/:id';
          fail("RZ0220", m.span.line === t.span.line ? m.span : t.span, `Expected an HTTP method and an endpoint path after "${t.text}".`,
            `Name the endpoint, for example \`${example}\`.`);
        }
        next();
        next();
        const base = { span: t.span, method: m.text, methodSpan: m.span, path: p.text, pathSpan: p.span };
        if (t.text === "form") return { kind: "form", ...base };
        if (label !== undefined) return { kind: "button", label, ...base };
        return { kind: "show", ...base };
      }
    }
  }

  // ------------------------------------------------------------------- api

  function parseApi(): ApiDecl {
    const kw = next(); // `api`
    const methodTok = peek();
    const upper = methodTok.text.toUpperCase();
    if (methodTok.kind !== "ident" || !(HTTP_METHODS as readonly string[]).includes(methodTok.text)) {
      const fix = methodTok.kind === "ident" && (HTTP_METHODS as readonly string[]).includes(upper)
        ? `HTTP methods are uppercase: \`api ${upper} ...\`.`
        : `Use one of: ${HTTP_METHODS.join(", ")}. Example: \`api GET /posts -> list Post.public { ... }\`.`;
      fail("RZ0213", methodTok.span, `Expected an HTTP method after "api" but found ${describe(methodTok)}.`, fix);
    }
    next();
    const pathTok = peek();
    if (pathTok.kind !== "path") {
      fail("RZ0214", pathTok.span, `Expected a path starting with "/" after "${methodTok.text}" but found ${describe(pathTok)}.`,
        "Write the path after the method, for example `/posts` or `/posts/:id`.");
    }
    next();

    let returns: ReturnType | undefined;
    if (peek().kind === "arrow") {
      next();
      returns = parseReturnType();
    }

    const brace = peek();
    if (brace.kind !== "lbrace") {
      const fix = returns === undefined && brace.kind === "ident"
        ? `Write the return type after an arrow: \`api ${methodTok.text} ${pathTok.text} -> ${brace.text}.public {\`.`
        : `Open the endpoint body with a brace: \`api ${methodTok.text} ${pathTok.text}${returns ? " -> ..." : ""} {\`.`;
      fail("RZ0203", brace.span, `Expected "{" after the endpoint path but found ${describe(brace)}.`, fix);
    }
    next();

    const statements: Statement[] = [];
    let lastLine = -1;
    for (;;) {
      const t = peek();
      if (t.kind === "rbrace") break;
      checkUnclosed(t, brace.span, `Endpoint "${methodTok.text} ${pathTok.text}"`, "its last line");
      if (t.span.line === lastLine) {
        fail("RZ0209", t.span, `${describe(t)} must start on a new line.`, "Put each statement on its own line.");
      }
      statements.push(parseStatement());
      lastLine = peek(-1).span.line;
    }
    const end = next();
    return {
      span: kw.span,
      method: methodTok.text as HttpMethod,
      methodSpan: methodTok.span,
      path: pathTok.text,
      pathSpan: pathTok.span,
      returns,
      statements,
      endSpan: end.span,
    };
  }

  function parseReturnType(): ReturnType {
    const start = peek();
    let list = false;
    if (isWord(start, "list")) {
      list = true;
      next();
    }
    const model = peek();
    if (model.kind !== "ident") {
      fail("RZ0215", model.span, `Expected a return type after "->" but found ${describe(model)}.`,
        "Write `-> Post.public` for one record or `-> list Post.public` for many.");
    }
    next();
    const dot = peek();
    const view = peek(1);
    if (dot.kind !== "dot" || view.kind !== "ident") {
      fail("RZ0215", model.span, `Return type "${model.text}" must say which view to return.`,
        `Endpoints may only return public data. Write \`-> ${list ? "list " : ""}${model.text}.public\`.`);
    }
    next();
    next();
    const span = { ...start.span, length: view.span.col + view.span.length - start.span.col };
    return { list, model: model.text, modelSpan: model.span, view: view.text, viewSpan: view.span, span };
  }

  function parseStatement(): Statement {
    const t = peek();
    if (t.kind !== "ident" || !STATEMENT_WORDS.includes(t.text)) {
      const guess = t.kind === "ident" ? didYouMean(t.text, STATEMENT_WORDS) : undefined;
      fail("RZ0216", t.span, `Unexpected ${describe(t)} in an api block.`,
        guess !== undefined
          ? `Did you mean "${guess}"? An api block contains: public or requires login, optional requires role / requires owner lines, and one return line.`
          : "An api block contains: public or requires login, optional requires role / requires owner lines, and one return line.");
    }
    next();
    let stmt: Statement;
    if (t.text === "public") {
      stmt = { kind: "public", span: t.span };
    } else if (t.text === "limit") {
      const n = peek();
      const per = peek(1);
      const unit = peek(2);
      const sameLine = (x: Token) => x.span.line === t.span.line;
      if (n.kind !== "int" || !sameLine(n) || !isWord(per, "per") || !sameLine(per) || unit.kind !== "ident" || !sameLine(unit)) {
        fail("RZ0222", sameLine(n) ? n.span : t.span, `Expected "<number> per <minute|hour|...>" after "limit".`,
          "Write the endpoint's rate limit as `limit 20 per minute`. Units: second, minute, hour, day.");
      }
      next();
      next();
      next();
      stmt = { kind: "limit", span: t.span, count: n.value, countSpan: n.span, unit: unit.text, unitSpan: unit.span };
    } else if (t.text === "requires") {
      const what = peek();
      if (isWord(what, "login") && what.span.line === t.span.line) {
        next();
        stmt = { kind: "requiresLogin", span: { ...t.span, length: what.span.col + what.span.length - t.span.col } };
      } else if (isWord(what, "owner") && what.span.line === t.span.line) {
        next();
        const field = peek();
        if (field.kind !== "ident" || field.span.line !== t.span.line) {
          fail("RZ0216", what.span, `Expected a field name after "requires owner".`,
            "Name the link field that points to the owner, for example `requires owner author`.");
        }
        next();
        let orRoles: RoleRef[] = [];
        if (isWord(peek(), "or") && peek().span.line === t.span.line) {
          next();
          const roleKw = peek();
          if (!isWord(roleKw, "role") || roleKw.span.line !== t.span.line) {
            fail("RZ0216", roleKw.span.line === t.span.line ? roleKw.span : t.span, `Expected "role" after "or".`,
              `Write \`requires owner ${field.text} or role admin\`.`);
          }
          next();
          orRoles = parseRoleList(roleKw, `requires owner ${field.text} or role admin`);
        }
        stmt = { kind: "requiresOwner", span: t.span, field: field.text, fieldSpan: field.span, orRoles };
      } else if (isWord(what, "role") && what.span.line === t.span.line) {
        next();
        stmt = { kind: "requiresRole", span: t.span, roles: parseRoleList(what, "requires role admin") };
      } else {
        fail("RZ0216", what.span.line === t.span.line ? what.span : t.span,
          `Expected "login", "role <name>" or "owner <field>" after "requires".`,
          "Write `requires login`, `requires role admin` or `requires owner author`.");
      }
    } else {
      stmt = { kind: "return", span: t.span, query: parseQuery(t) };
    }
    const after = peek();
    if (after.kind !== "rbrace" && after.kind !== "eof" && after.span.line === peek(-1).span.line) {
      fail("RZ0212", after.span, `Unexpected ${describe(after)} after "${t.text}".`, "Put each statement on its own line.");
    }
    return stmt;
  }

  function parseQuery(returnTok: Token): Query {
    const db = peek();
    const queryFix = "Write a query such as `return db.Post.find(id)`, `return db.Post.list()` or `return db.Post.create(body)`.";
    if (!isWord(db, "db") || db.span.line !== returnTok.span.line) {
      fail("RZ0217", db.span.line === returnTok.span.line ? db.span : returnTok.span,
        `Expected a database query after "return" but found ${describe(db)}.`, queryFix);
    }
    next();
    const expect = (kind: TokenKind, what: string): Token => {
      const t = peek();
      if (t.kind !== kind) fail("RZ0217", t.span, `Expected ${what} in query but found ${describe(t)}.`, queryFix);
      return next();
    };
    expect("dot", '"."');
    const model = expect("ident", "a model name");
    expect("dot", '"."');
    const action = expect("ident", "an action (find, list, create, update or delete)");
    expect("lparen", '"("');
    const args: QueryArg[] = [];
    if (peek().kind !== "rparen") {
      for (;;) {
        args.push(parseArg());
        if (peek().kind === "comma") {
          next();
          continue;
        }
        break;
      }
    }
    const close = expect("rparen", '"," or ")"');
    return {
      span: { ...db.span, length: close.span.line === db.span.line ? close.span.col + 1 - db.span.col : 1 },
      model: model.text,
      modelSpan: model.span,
      action: action.text,
      actionSpan: action.span,
      args,
    };
  }

  function parseArg(): QueryArg {
    const t = peek();
    if (t.kind !== "ident") {
      fail("RZ0217", t.span, `Unexpected ${describe(t)} in query arguments.`,
        "Arguments are a path parameter (id), body, `field = value`, `order field desc` or `limit 20`, separated by commas.");
    }
    next();
    if (peek().kind === "equals") {
      next();
      return { kind: "assign", field: t.text, fieldSpan: t.span, value: parseValue(), span: t.span };
    }
    if (t.text === "order" && peek().kind === "ident") {
      const field = next();
      let descending = false;
      if (isWord(peek(), "desc") || isWord(peek(), "asc")) descending = next().text === "desc";
      return { kind: "order", field: field.text, fieldSpan: field.span, descending, span: t.span };
    }
    if (t.text === "limit") {
      const n = peek();
      if (n.kind !== "int") {
        fail("RZ0217", n.span, `Expected a number after "limit" but found ${describe(n)}.`, "Write `limit 20`.");
      }
      next();
      return { kind: "limit", value: n.value, valueSpan: n.span, span: t.span };
    }
    return { kind: "name", name: t.text, span: t.span };
  }

  function parseValue(): Value {
    const t = peek();
    if (t.kind === "int") {
      next();
      return { kind: "int", value: t.value, span: t.span };
    }
    if (t.kind === "ident") {
      next();
      if (t.text === "true" || t.text === "false") return { kind: "bool", value: t.text === "true", span: t.span };
      return { kind: "name", name: t.text, span: t.span };
    }
    return fail("RZ0217", t.span, `Expected a value after "=" but found ${describe(t)}.`,
      "A value is `me`, a path parameter such as `userId`, a whole number, `true` or `false`.");
  }

  try {
    return { ok: true, program: parseProgram() };
  } catch (e) {
    if (e instanceof ParseError) return { ok: false, diagnostic: e.diagnostic };
    throw e;
  }
}
