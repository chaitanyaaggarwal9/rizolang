import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
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

describe("rizolang build: migrations", () => {
  const V1 = "auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  name: Text\n}\napi GET /users/:id -> User.public {\n  public\n  return db.User.find(id)\n}\n";
  const write = (src: string) => writeFileSync(join(dir, "app.rz"), src);
  const migrations = () => readdirSync(join(dir, "migrations")).sort();

  it("writes the first migration and a snapshot, and copies migrations next to the server", () => {
    write(V1);
    expect(cli("build", "app.rz")).toBe(0);
    expect(migrations()).toEqual(["0001_initial.sql", "rizo-schema.json"]);
    expect(out).toContain("New migration: migrations/0001_initial.sql");
    expect(readdirSync(join(dir, "dist", "migrations"))).toEqual(["0001_initial.sql"]);
    expect(readFileSync(join(dir, "dist", "migrate.ts"), "utf8")).toContain("runMigrations");
    expect(existsSync(join(dir, "dist", "runtime", "migrate.ts"))).toBe(true);
  });

  it("writes nothing new when the models did not change", () => {
    write(V1);
    cli("build", "app.rz");
    out = "";
    expect(cli("build", "app.rz")).toBe(0);
    expect(migrations()).toEqual(["0001_initial.sql", "rizo-schema.json"]);
    expect(out).not.toContain("New migration");
  });

  it("numbers the next migration and updates the snapshot", () => {
    write(V1);
    cli("build", "app.rz");
    write(V1.replace("  name: Text\n", "  name: Text\n  bio: Text optional\n"));
    expect(cli("build", "app.rz")).toBe(0);
    expect(migrations()).toEqual(["0001_initial.sql", "0002_add_column_users_bio.sql", "rizo-schema.json"]);
    const sql = readFileSync(join(dir, "migrations", "0002_add_column_users_bio.sql"), "utf8");
    expect(sql).toContain('ALTER TABLE "users" ADD COLUMN "bio" TEXT');
    expect(readFileSync(join(dir, "migrations", "rizo-schema.json"), "utf8")).toContain('"bio"');
  });

  it("refuses to delete data, and writes no files at all", () => {
    write(V1);
    cli("build", "app.rz");
    const before = readFileSync(join(dir, "dist", "types.ts"), "utf8");
    write(V1.replace("  name: Text\n", ""));
    expect(cli("build", "app.rz")).toBe(1);
    expect(err).toContain("error RZ0904: This change would delete data:");
    expect(err).toContain('column "users.name" and its values would be deleted');
    expect(err).toContain("--allow-data-loss");
    expect(migrations()).toEqual(["0001_initial.sql", "rizo-schema.json"]);
    expect(readFileSync(join(dir, "dist", "types.ts"), "utf8")).toBe(before);
  });

  it("deletes data only with --allow-data-loss, and says so in the migration", () => {
    write(V1);
    cli("build", "app.rz");
    write(V1.replace("  name: Text\n", ""));
    expect(cli("build", "app.rz", "--allow-data-loss")).toBe(0);
    const sql = readFileSync(join(dir, "migrations", "0002_drop_column_users_name.sql"), "utf8");
    expect(sql).toContain("WARNING: this migration deletes data");
    expect(sql).toContain('ALTER TABLE "users" DROP COLUMN "name";');
  });

  it("rejects unknown options", () => {
    write(V1);
    expect(cli("build", "app.rz", "--force")).toBe(1);
    expect(err).toContain("RZ0903");
  });

  it("stops when the snapshot is damaged or missing", () => {
    write(V1);
    cli("build", "app.rz");
    writeFileSync(join(dir, "migrations", "rizo-schema.json"), "{}");
    expect(cli("build", "app.rz")).toBe(1);
    expect(err).toContain("RZ0905");
    err = "";
    rmSync(join(dir, "migrations", "rizo-schema.json"));
    expect(cli("build", "app.rz")).toBe(1);
    expect(err).toContain("no rizo-schema.json");
  });
});
