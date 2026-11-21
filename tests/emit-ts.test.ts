import { describe, expect, it } from "vitest";
import { compileOk, interfaceBody } from "./helpers.js";

const tsOf = (src: string) => compileOk(src).output.typescript;

describe("TypeScript emitter", () => {
  const ts = tsOf(`model User {
  email: Email unique
  password: Password min 12
  name: Text max 100
  age: Number optional
}`);

  it("emits the stored type with a branded password hash", () => {
    expect(interfaceBody(ts, "User")).toBe(
      [
        "  readonly id: string;",
        "  readonly email: string;",
        "  readonly password: PasswordHash;",
        "  readonly name: string;",
        "  readonly age: number | null;",
      ].join("\n"),
    );
    expect(ts).toContain("export type PasswordHash = string & { readonly [passwordHashBrand]: true };");
  });

  it("emits the public type without the password", () => {
    expect(interfaceBody(ts, "UserPublic")).toBe(
      [
        "  readonly id: string;",
        "  readonly email: string;",
        "  readonly name: string;",
        "  readonly age: number | null;",
      ].join("\n"),
    );
  });

  it("emits the input type with plain-text password and documented limits", () => {
    const body = interfaceBody(ts, "UserInput");
    expect(body).not.toContain("id:");
    expect(body).toContain("readonly password: string;");
    expect(body).toContain("12 to 128 characters");
    expect(body).toContain("readonly age?: number | null;");
    expect(body).toContain("At most 100 characters.");
  });

  it("maps Bool, Date and ID", () => {
    const body = interfaceBody(tsOf("model A {\n  b: Bool\n  d: Date\n  i: ID\n}"), "A");
    expect(body).toContain("readonly b: boolean;");
    expect(body).toContain("readonly d: Date;");
    expect(body).toContain("readonly i: string;");
  });
});
