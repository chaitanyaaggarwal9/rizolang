import { describe, expect, it } from "vitest";
import { lex } from "../src/lexer.js";
import { parse } from "../src/parser.js";
import { firstError } from "./helpers.js";

function program(src: string) {
  const l = lex(src, "t.rz");
  if (!l.ok) throw new Error(l.diagnostic.message);
  const p = parse(l.tokens, "t.rz");
  if (!p.ok) throw new Error(p.diagnostic.message);
  return p.program;
}

describe("parser", () => {
  it("parses models, fields and modifiers", () => {
    const p = program(`
model User {
  email: Email unique
  name: Text min 1 max 100 optional
}
model Post {
  title: Text
}`);
    expect(p.models.map((m) => m.name)).toEqual(["User", "Post"]);
    const user = p.models[0];
    expect(user?.fields.map((f) => [f.name, f.typeName])).toEqual([["email", "Email"], ["name", "Text"]]);
    expect(user?.fields[1]?.modifiers).toMatchObject([
      { kind: "min", value: 1 },
      { kind: "max", value: 100 },
      { kind: "optional" },
    ]);
  });

  it("accepts an empty file", () => {
    expect(program("// nothing here\n").models).toEqual([]);
  });

  it("accepts a closing brace on the last field's line", () => {
    expect(program("model A {\n  x: Text }").models[0]?.fields).toHaveLength(1);
  });

  it("requires the model keyword", () => {
    const d = firstError("Model User {\n  x: Text\n}");
    expect(d).toMatchObject({ code: "RZ0201", span: { line: 1, col: 1 } });
    expect(d.fix).toContain("lowercase keyword model");
  });

  it("rejects api blocks for now, even when they contain characters the lexer rejects", () => {
    const d = firstError("model User {\n  x: Text\n}\n\napi GET /users/:id -> User.public\n");
    expect(d).toMatchObject({ code: "RZ0211", span: { line: 5, col: 1, length: 3 } });
  });

  it("does not mistake a field named like a future keyword for a block", () => {
    expect(firstError("model A {\n  page: Number,\n}").code).toBe("RZ0101");
  });

  it("requires a model name", () => {
    expect(firstError("model {\n}")).toMatchObject({ code: "RZ0202", span: { line: 1, col: 7 } });
  });

  it("requires an opening brace", () => {
    expect(firstError("model User\n  x: Text\n}")).toMatchObject({ code: "RZ0203", span: { line: 2, col: 3 } });
  });

  it("reports a missing colon with the exact fix", () => {
    const d = firstError("model User {\n  name Text\n}");
    expect(d).toMatchObject({ code: "RZ0205", span: { line: 2, col: 8 } });
    expect(d.fix).toContain("`name: Text`");
  });

  it("reports a missing type", () => {
    expect(firstError("model User {\n  name:\n}")).toMatchObject({ code: "RZ0206", span: { line: 2, col: 8 } });
  });

  it("reports unknown modifiers with a suggestion", () => {
    const d = firstError("model User {\n  name: Text maxx 5\n}");
    expect(d).toMatchObject({ code: "RZ0207", span: { line: 2, col: 14 } });
    expect(d.fix).toContain('"max"');
  });

  it("requires a number after min/max", () => {
    expect(firstError("model User {\n  name: Text max\n}")).toMatchObject({ code: "RZ0208", span: { line: 2, col: 14 } });
  });

  it("reports a missing closing brace at the opening brace", () => {
    expect(firstError("model User {\n  name: Text\n")).toMatchObject({ code: "RZ0210", span: { line: 1, col: 12 } });
  });

  it("reports a missing closing brace before the next model", () => {
    expect(firstError("model A {\n  x: Text\nmodel B {\n  y: Text\n}").code).toBe("RZ0210");
  });

  it("rejects stray tokens after a field type", () => {
    expect(firstError("model A {\n  x: Text 5\n}")).toMatchObject({ code: "RZ0212", span: { line: 2, col: 11 } });
  });
});
