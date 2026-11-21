import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { run } from "../src/cli.js";
import { VERSION } from "../src/version.js";

let dir: string;
let out: string;
let err: string;

const cli = (...argv: string[]) =>
  run(argv, { cwd: dir, stdout: (s) => (out += s), stderr: (s) => (err += s) });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "rizolang-"));
  out = "";
  err = "";
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe("rizolang build", () => {
  it("writes dist/schema.sql and dist/types.ts", () => {
    writeFileSync(join(dir, "app.rz"), "model User {\n  email: Email unique\n  password: Password\n}\n");
    expect(cli("build", "app.rz")).toBe(0);
    expect(out).toContain("1 model");
    const sql = readFileSync(join(dir, "dist", "schema.sql"), "utf8");
    const ts = readFileSync(join(dir, "dist", "types.ts"), "utf8");
    expect(sql).toContain('CREATE TABLE "users"');
    expect(ts).toContain("export interface UserPublic");
    expect(err).toBe("");
  });

  it("prints formatted errors and writes nothing on failure", () => {
    writeFileSync(join(dir, "bad.rz"), "model User {\n  name: String\n}\n");
    expect(cli("build", "bad.rz")).toBe(1);
    expect(err).toContain("bad.rz:2:9 error RZ0301");
    expect(err).toContain("  2 |   name: String");
    expect(err).toContain("    |         ^^^^^^");
    expect(err).toContain('fix: Use "Text" instead.');
    expect(err).toContain("No files were written.");
    expect(existsSync(join(dir, "dist"))).toBe(false);
  });

  it("rejects files without the .rz extension", () => {
    expect(cli("build", "app.txt")).toBe(1);
    expect(err).toContain("RZ0902");
  });

  it("reports missing files", () => {
    expect(cli("build", "missing.rz")).toBe(1);
    expect(err).toContain("RZ0901");
  });

  it("reports unknown commands and missing arguments", () => {
    expect(cli("compile", "a.rz")).toBe(1);
    expect(err).toContain("RZ0903");
    err = "";
    expect(cli("build")).toBe(1);
    expect(err).toContain("RZ0903");
  });

  it("prints help and version", () => {
    expect(cli("--help")).toBe(0);
    expect(out).toContain("rizolang build <file.rz>");
    out = "";
    expect(cli("--version")).toBe(0);
    expect(out.trim()).toBe(VERSION);
  });

  it("keeps VERSION in sync with package.json", () => {
    const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string };
    expect(VERSION).toBe(pkg.version);
  });

  it("compiles the bundled example", () => {
    const example = readFileSync(new URL("../examples/blog.rz", import.meta.url), "utf8");
    writeFileSync(join(dir, "blog.rz"), example);
    expect(cli("build", "blog.rz")).toBe(0);
  });
});
