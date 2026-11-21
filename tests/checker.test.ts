import { describe, expect, it } from "vitest";
import { tableName, toSnakeCase } from "../src/checker.js";
import { compileErrors, compileOk, firstError } from "./helpers.js";

const model = (body: string, name = "User") => `model ${name} {\n${body}\n}\n`;

describe("naming", () => {
  it.each([
    ["firstName", "first_name"],
    ["userID", "user_id"],
    ["htmlURLPath", "html_url_path"],
    ["address2Line", "address2_line"],
    ["name", "name"],
  ])("snake_cases %s -> %s", (input, out) => {
    expect(toSnakeCase(input)).toBe(out);
  });

  it.each([
    ["User", "users"],
    ["BlogPost", "blog_posts"],
    ["Category", "categories"],
    ["Address", "addresses"],
    ["Box", "boxes"],
    ["Day", "days"],
  ])("pluralizes table for %s -> %s", (input, out) => {
    expect(tableName(input)).toBe(out);
  });

  it("requires PascalCase model names", () => {
    const d = firstError(model("  x: Text", "user"));
    expect(d.code).toBe("RZ0309");
    expect(d.fix).toContain('"User"');
  });

  it("requires camelCase field names", () => {
    const d = firstError(model("  Name: Text"));
    expect(d.code).toBe("RZ0310");
    expect(d.fix).toContain('"name"');
  });

  it("reserves the id field", () => {
    expect(firstError(model("  id: ID")).code).toBe("RZ0308");
  });

  it("reserves built-in model names", () => {
    expect(firstError(model("  x: Text", "Date")).code).toBe("RZ0311");
  });

  it("rejects duplicate models and fields", () => {
    expect(firstError(model("  x: Text", "A") + model("  y: Text", "A")).code).toBe("RZ0306");
    const d = firstError(model("  x: Text\n  x: Number"));
    expect(d).toMatchObject({ code: "RZ0307", span: { line: 3 } });
    expect(d.message).toContain("line 2");
  });

  it("rejects models whose tables collide", () => {
    expect(firstError(model("  x: Text", "Box") + model("  y: Text", "Boxe")).code).toBe("RZ0312");
  });

  it("rejects models whose generated TypeScript types collide", () => {
    expect(firstError(model("  x: Text", "User") + model("  y: Text", "UserPublic")).code).toBe("RZ0312");
  });

  it("rejects a field that collides with a password hash column", () => {
    const d = firstError(model("  password: Password\n  passwordHash: Text"));
    expect(d.code).toBe("RZ0312");
    expect(d.message).toContain("password_hash");
  });

  it("rejects empty models", () => {
    expect(firstError("model Empty {\n}").code).toBe("RZ0313");
  });

  it("rejects names too long for PostgreSQL", () => {
    expect(firstError(model(`  a${"b".repeat(70)}: Text`)).code).toBe("RZ0314");
  });
});

describe("types and modifiers", () => {
  it("accepts every field type", () => {
    const { models } = compileOk(model(
      "  a: Text\n  b: Number\n  c: Bool\n  d: Email\n  e: Password\n  f: Date\n  g: ID",
    ));
    expect(models[0]?.fields.map((f) => f.type)).toEqual(["Text", "Number", "Bool", "Email", "Password", "Date", "ID"]);
  });

  it("applies default limits", () => {
    const { models } = compileOk(model("  a: Text\n  b: Email\n  c: Password\n  d: Number"));
    expect(models[0]?.fields.map((f) => [f.min, f.max])).toEqual([
      [undefined, 10000], [3, 254], [8, 128], [undefined, undefined],
    ]);
  });

  it.each([
    ["  ok: Bool unique", "RZ0302"],
    ["  ok: Bool max 3", "RZ0302"],
    ["  ok: Date min 1", "RZ0302"],
    ["  ok: ID max 1", "RZ0302"],
    ["  ok: Password unique", "RZ0302"],
    ["  ok: Text unique unique", "RZ0303"],
    ["  ok: Text max 5 max 6", "RZ0303"],
    ["  ok: Text min 10 max 5", "RZ0304"],
    ["  ok: Password min 20 max 10", "RZ0304"],
    ["  ok: Password max 6", "RZ0305"],
    ["  ok: Text max 0", "RZ0305"],
    ["  ok: Text max 2000000", "RZ0305"],
    ["  ok: Email max 300", "RZ0305"],
    ["  ok: Password min 4", "RZ0305"],
    ["  ok: Password max 500", "RZ0305"],
    ["  ok: Number max 3000000000", "RZ0305"],
  ])("rejects `%s` with %s", (body, code) => {
    expect(firstError(model(body)).code).toBe(code);
  });

  it("explains why a Password cannot be unique", () => {
    expect(firstError(model("  pw: Password unique")).fix).toContain("hashes");
  });

  it("allows negative Number limits", () => {
    expect(compileOk(model("  temp: Number min -50 max 60")).models[0]?.fields[0]).toMatchObject({ min: -50, max: 60 });
  });

  it("collects all checker errors in one pass", () => {
    const errs = compileErrors(model("  Name: Text\n  age: Strng\n  pw: Password unique"));
    expect(errs.map((e) => e.code)).toEqual(["RZ0310", "RZ0301", "RZ0302"]);
  });
});
