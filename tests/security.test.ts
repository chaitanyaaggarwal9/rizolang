/**
 * Security tests. These prove the guarantees in docs/SPEC.md:
 *   1. A Password field never appears in a public type.
 *   2. Invalid syntax produces a clear error with the exact line and column.
 *   3. Unknown field types are rejected and no output is produced.
 *   4. Names cannot inject SQL.
 */
import { describe, expect, it } from "vitest";
import { compile } from "../src/compiler.js";
import { FIELD_TYPE_NAMES, FIELD_TYPES } from "../src/types.js";
import { compileOk, firstError, interfaceBody, propertyNames } from "./helpers.js";

/** Small deterministic PRNG so failures are reproducible. */
function rng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s * 1664525 + 1013904223) >>> 0;
    return s / 2 ** 32;
  };
}

function randomSchema(seed: number): { source: string; passwordFields: Map<string, string[]> } {
  const rand = rng(seed);
  const pick = <T>(xs: readonly T[]): T => xs[Math.floor(rand() * xs.length)] as T;
  const words = ["password", "secret", "pin", "name", "email", "token", "pass", "hash", "key", "note", "login", "code"];
  const passwordFields = new Map<string, string[]>();
  const blocks: string[] = [];
  const modelCount = 1 + Math.floor(rand() * 4);
  for (let m = 0; m < modelCount; m++) {
    const modelName = `Model${m}`;
    const fields: string[] = [];
    const secrets: string[] = [];
    const fieldCount = 1 + Math.floor(rand() * 8);
    for (let f = 0; f < fieldCount; f++) {
      const name = `${pick(words)}${f}`;
      // Bias toward Password so most models contain at least one.
      const type = rand() < 0.35 ? "Password" : pick(FIELD_TYPE_NAMES);
      const optional = rand() < 0.3 ? " optional" : "";
      if (type === "Password") secrets.push(name);
      fields.push(`  ${name}: ${type}${optional}`);
    }
    passwordFields.set(modelName, secrets);
    blocks.push(`model ${modelName} {\n${fields.join("\n")}\n}`);
  }
  return { source: blocks.join("\n\n"), passwordFields };
}

describe("security: Password never appears in a public type", () => {
  it("is excluded from the public type of a simple model", () => {
    const { output } = compileOk("model User {\n  email: Email\n  password: Password\n}");
    const pub = interfaceBody(output.typescript, "UserPublic");
    expect(propertyNames(pub)).toEqual(["id", "email"]);
    expect(pub).not.toMatch(/password/i);
    expect(pub).not.toContain("PasswordHash");
  });

  it("is excluded whatever the field is called and however many there are", () => {
    const { output } = compileOk(
      "model Account {\n  login: Text\n  secret: Password\n  recoveryPin: Password optional\n  token: Password min 20\n}",
    );
    const pub = interfaceBody(output.typescript, "AccountPublic");
    expect(propertyNames(pub)).toEqual(["id", "login"]);
    expect(pub).not.toContain("PasswordHash");
  });

  it("holds for 500 randomly generated schemas", () => {
    for (let seed = 1; seed <= 500; seed++) {
      const { source, passwordFields } = randomSchema(seed);
      const result = compile(source, "random.rz");
      if (!result.ok) throw new Error(`seed ${seed} failed to compile:\n${source}`);
      for (const [model, secrets] of passwordFields) {
        const pub = interfaceBody(result.output.typescript, `${model}Public`);
        const props = propertyNames(pub);
        for (const s of secrets) {
          expect(props, `seed ${seed}: ${model}Public must not contain ${s}`).not.toContain(s);
        }
        expect(pub).not.toContain("PasswordHash");
        // Every non-secret field is still present.
        const stored = propertyNames(interfaceBody(result.output.typescript, model));
        expect(props).toEqual(stored.filter((p) => !secrets.includes(p)));
      }
    }
  });

  it("is never stored as plain text: the column is always <name>_hash", () => {
    const { output } = compileOk("model User {\n  password: Password\n}");
    expect(output.sql).toContain('"password_hash" TEXT NOT NULL');
    expect(output.sql).not.toMatch(/"password" /);
  });

  it.each(["password: Text", "pwd: Text", "adminPassword: Text optional", "passphrase: Number"])(
    "rejects a password-like field with the wrong type: %s",
    (line) => {
      const d = firstError(`model User {\n  ${line}\n}`);
      expect(d.code).toBe("RZ0315");
      expect(d.fix).toContain(": Password`");
    },
  );

  it("does not flag fields that merely mention passwords", () => {
    compileOk("model User {\n  passwordHint: Text\n  passwordChangedAt: Date optional\n}");
  });

  it("only Password is marked secret in the type table", () => {
    const secret = FIELD_TYPE_NAMES.filter((t) => FIELD_TYPES[t].secret);
    expect(secret).toEqual(["Password"]);
  });
});

describe("security: invalid syntax gives a clear error with line and column", () => {
  it.each([
    ["missing colon", "model User {\n  email Email\n}", "RZ0205", 2, 9],
    ["comma", "model User {\n  email: Email,\n}", "RZ0101", 2, 15],
    ["snake_case name", "model User {\n  first_name: Text\n}", "RZ0101", 2, 8],
    ["unknown modifier", "model User {\n  email: Email uniq\n}", "RZ0207", 2, 16],
    ["missing brace", "model User\n  email: Email\n}", "RZ0203", 2, 3],
    ["two fields on one line", "model User {\n  a: Text b: Text\n}", "RZ0207", 2, 11],
    ["unclosed model", "model User {\n  email: Email\n", "RZ0210", 1, 12],
    ["tab indentation", "model User {\n\temail Email\n}", "RZ0205", 2, 8],
  ])("%s", (_label, source, code, line, col) => {
    const d = firstError(source);
    expect(d.code).toBe(code);
    expect(d.span.line).toBe(line);
    expect(d.span.col).toBe(col);
    expect(d.file).toBe("test.rz");
  });
});

describe("security: unknown field types are rejected", () => {
  it.each([
    ["String", "Text"],
    ["Int", "Number"],
    ["Boolean", "Bool"],
    ["DateTime", "Date"],
    ["UUID", "ID"],
    ["text", "Text"],
    ["Emial", "Email"],
    ["Passwrd", "Password"],
  ])("rejects %s and suggests %s", (bad, good) => {
    const d = firstError(`model User {\n  field: ${bad}\n}`);
    expect(d.code).toBe("RZ0301");
    expect(d.span).toEqual({ line: 2, col: 10, length: bad.length });
    expect(d.message).toContain(`"${bad}"`);
    expect(d.fix).toContain(`"${good}"`);
  });

  it("lists the valid types when there is no close match", () => {
    const d = firstError("model User {\n  field: Banana\n}");
    expect(d.fix).toBe("Use one of: Text, Number, Bool, Email, Password, Date, ID.");
  });

  it("produces no output at all when any type is unknown", () => {
    const r = compile("model User {\n  ok: Text\n  bad: Json\n}", "t.rz");
    expect(r.ok).toBe(false);
    expect("output" in r).toBe(false);
  });
});

describe("security: names cannot inject SQL", () => {
  it.each([
    'model User {\n  name"; DROP TABLE users; --: Text\n}',
    "model User {\n  name': Text\n}",
    "model Us-er {\n  name: Text\n}",
    "model User {\n  na me: Text\n}",
  ])("rejects %j", (source) => {
    expect(compile(source, "t.rz").ok).toBe(false);
  });

  it("every emitted identifier contains only safe characters", () => {
    const { output } = compileOk("model User {\n  firstName: Text\n  password: Password\n}");
    const quoted = [...output.sql.matchAll(/"([^"]*)"/g)].map((m) => m[1]);
    for (const id of quoted) expect(id).toMatch(/^[a-z0-9_]+$/);
  });

  it("sanitizes the source file name echoed into generated comments", () => {
    const r = compile("model A {\n  x: Text\n}", "evil\nDROP TABLE x;.rz");
    if (!r.ok) throw new Error("expected success");
    expect(r.output.sql).not.toContain("\nDROP");
    expect(r.output.typescript).not.toContain("\nDROP");
  });
});
