import { describe, expect, it } from "vitest";
import { lex } from "../src/lexer.js";

function tokens(src: string) {
  const r = lex(src, "t.rz");
  if (!r.ok) throw new Error(r.diagnostic.message);
  return r.tokens;
}

function lexError(src: string) {
  const r = lex(src, "t.rz");
  if (r.ok) throw new Error("expected lex error");
  return r.diagnostic;
}

describe("lexer", () => {
  it("produces tokens with 1-based line and column", () => {
    const t = tokens("model User {\n  name: Text max 100\n}");
    expect(t.map((x) => x.kind)).toEqual([
      "ident", "ident", "lbrace", "ident", "colon", "ident", "ident", "int", "rbrace", "eof",
    ]);
    const name = t[3];
    expect(name?.text).toBe("name");
    expect(name?.span).toEqual({ line: 2, col: 3, length: 4 });
    expect(t[7]?.value).toBe(100);
  });

  it("skips // comments", () => {
    const t = tokens("// header\nmodel A { // trailing\n}");
    expect(t.map((x) => x.text)).toEqual(["model", "A", "{", "}", ""]);
  });

  it("parses negative numbers", () => {
    const t = tokens("min -5");
    expect(t[1]?.value).toBe(-5);
  });

  it("treats CRLF and LF identically", () => {
    const a = tokens("model A {\r\n  x: Text\r\n}");
    const b = tokens("model A {\n  x: Text\n}");
    expect(a.map((x) => x.span)).toEqual(b.map((x) => x.span));
  });

  it.each([
    [";", "semicolons"],
    ["_", "camelCase"],
    ["?", "optional"],
    ["@", "without @"],
    ["#", "two slashes"],
    ["!", "`=` only"],
  ])("rejects %s with a targeted fix", (ch, hint) => {
    const d = lexError(`model A {\n  x${ch}`);
    expect(d.code).toBe("RZ0101");
    expect(d.span).toEqual({ line: 2, col: 4, length: 1 });
    expect(d.fix).toContain(hint);
  });

  it("lexes the punctuation used by api blocks", () => {
    const t = tokens("api GET /posts/:id -> Post.public {\n  return db.Post.list(author = me, limit 5)\n}");
    expect(t.map((x) => x.kind)).toEqual([
      "ident", "ident", "path", "arrow", "ident", "dot", "ident", "lbrace",
      "ident", "ident", "dot", "ident", "dot", "ident", "lparen", "ident", "equals", "ident", "comma", "ident", "int", "rparen",
      "rbrace", "eof",
    ]);
    expect(t[2]).toMatchObject({ text: "/posts/:id", span: { line: 1, col: 9, length: 10 } });
  });

  it("ends a path at a comment", () => {
    expect(tokens("/posts // all posts").map((x) => x.text)).toEqual(["/posts", ""]);
  });

  it("rejects decimals", () => {
    const d = lexError("max 1.5");
    expect(d.code).toBe("RZ0102");
    expect(d.span.col).toBe(5);
    expect(d.fix).toContain("whole number");
  });

  it("rejects numbers glued to letters", () => {
    expect(lexError("max 100abc").code).toBe("RZ0102");
  });

  it("rejects numbers that are too long", () => {
    expect(lexError("max 99999999999").code).toBe("RZ0102");
  });

  it("reports non-ASCII characters by code point", () => {
    const d = lexError("model Café {}");
    expect(d.message).toContain("U+00E9");
  });
});
