import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { devSettings, runDev } from "../src/dev.js";

const app = (extra: Partial<{ auth: boolean; privacy: boolean; encrypted: boolean }> = {}) =>
  ({ port: 3000, auth: true, privacy: false, encrypted: false, ...extra });

describe("rizolang dev settings", () => {
  it("fills in development defaults only where nothing is set, and says so", () => {
    const s = devSettings({ DATABASE_URL: "postgres://x" }, app(), () => "k");
    expect(s.env).toMatchObject({ PORT: "3000", HOST: "127.0.0.1", RIZO_PUBLIC_URL: "http://localhost:3000", RIZO_EMAIL_DEV: "1", DATABASE_URL: "postgres://x" });
    expect(s.notes).toHaveLength(2);
    expect(s.notes.join("\n")).toContain("emails are printed here");
  });

  it("keeps the developer's own settings", () => {
    const s = devSettings({ RIZO_PUBLIC_URL: "https://mine.example", RIZO_EMAIL_API_KEY: "re_x", RIZO_EMAIL_FROM: "a@b.co" }, app(), () => "k");
    expect(s.env["RIZO_PUBLIC_URL"]).toBe("https://mine.example");
    expect(s.env["RIZO_EMAIL_DEV"]).toBeUndefined();
    expect(s.notes).toEqual([]);
  });

  it("adds a placeholder privacy contact and a local encryption key only when the app needs them", () => {
    expect(devSettings({}, app({ auth: false }), () => "k").env).not.toHaveProperty("RIZO_PRIVACY_CONTACT");
    const s = devSettings({}, app({ privacy: true, encrypted: true }), () => "c2VjcmV0");
    expect(s.env).toMatchObject({ RIZO_PRIVACY_CONTACT: "privacy@example.com", RIZO_ENCRYPTION_KEYS: "dev:c2VjcmV0" });
    expect(s.notes.join("\n")).not.toContain("c2VjcmV0");
    expect(s.notes.join("\n")).toContain("never use it in production");
  });
});

describe("rizolang dev arguments", () => {
  const capture = () => {
    let err = "";
    return { io: { cwd: process.cwd(), stdout: () => undefined, stderr: (t: string) => (err += t) }, err: () => err };
  };

  it.each([
    ["no database", ["app.rz"], {}, "RZ0906", "DATABASE_URL=postgres://"],
    ["no file", [], { DATABASE_URL: "postgres://x" }, "RZ0903", "rizolang dev app.rz"],
    ["a bad port", ["app.rz", "--port", "99999"], { DATABASE_URL: "postgres://x" }, "RZ0903", "--port 3000"],
    ["an unknown option", ["app.rz", "--watch"], { DATABASE_URL: "postgres://x" }, "RZ0903", "--port"],
    ["a missing file", ["missing.rz"], { DATABASE_URL: "postgres://x" }, "RZ0901", "path is correct"],
  ])("stops at once for %s, with a fix", async (_label, argv, env, code, fix) => {
    const c = capture();
    expect(await runDev(argv, c.io, env)).toBe(1);
    expect(c.err()).toContain(code);
    expect(c.err()).toContain(fix);
  });
});

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];
const BIN = fileURLToPath(new URL("../build/src/bin.js", import.meta.url));

describe.skipIf(DATABASE_URL === undefined || !existsSync(BIN))("rizolang dev with PostgreSQL", () => {
  const dir = join(fileURLToPath(new URL(".", import.meta.url)), `.dev-tmp-${randomBytes(4).toString("hex")}`);
  const dbName = `rizo_dev_${randomBytes(4).toString("hex")}`;
  const dbUrl = (() => {
    const u = new URL(DATABASE_URL ?? "postgres://localhost");
    u.pathname = `/${dbName}`;
    return u.toString();
  })();
  let child: ChildProcess;
  let output = "";
  let port = 0;

  const waitFor = async (text: string, count = 1): Promise<void> => {
    for (let i = 0; i < 200; i++) {
      if (output.split(text).length - 1 >= count) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`timed out waiting for "${text}":\n${output}`);
  };

  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${dbName}"`);
    await admin.end();
    port = await new Promise<number>((done) => {
      const s = createServer().listen(0, () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => done(p));
      });
    });
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "src", "app.rz"), "model Note {\n  title: Text\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list()\n}\n");
    // The .rz file is in a subfolder: dev must use dist/ in the current folder, as build does.
    child = spawn(process.execPath, [BIN, "dev", "src/app.rz", "--port", String(port)], { cwd: dir, env: { ...process.env, DATABASE_URL: dbUrl } });
    child.stdout?.on("data", (d) => (output += String(d)));
    child.stderr?.on("data", (d) => (output += String(d)));
  }, 30_000);

  afterAll(async () => {
    if (child.exitCode === null) {
      child.kill("SIGINT");
      await new Promise((r) => child.once("exit", r));
    }
    rmSync(dir, { recursive: true, force: true });
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
    await admin.end();
  });

  it("builds, migrates and serves the app", async () => {
    await waitFor("running at");
    expect(await (await fetch(`http://127.0.0.1:${port}/api/notes`)).json()).toEqual({ items: [], next: null });
    expect(output).toContain("applied 0001_initial.sql");
  }, 30_000);

  it("rebuilds, migrates and restarts when the file is saved", async () => {
    writeFileSync(join(dir, "src", "app.rz"), "model Note {\n  title: Text\n  body: Text optional\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list()\n}\napi POST /api/notes -> Note.public {\n  public\n  return db.Note.create(body)\n}\n");
    await waitFor("running at", 2);
    const r = await fetch(`http://127.0.0.1:${port}/api/notes`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ title: "a", body: "b" }) });
    expect(r.status).toBe(201);
    expect(output).toContain("applied 0002_add_column_notes_body.sql");
  }, 30_000);

  it("keeps the running server when the saved file has errors", async () => {
    writeFileSync(join(dir, "src", "app.rz"), "model Note {\n  title: String\n}\n");
    await waitFor("the running server is unchanged");
    expect(output).toContain("error RZ0301");
    expect((await fetch(`http://127.0.0.1:${port}/api/notes`)).status).toBe(200);
  }, 30_000);

  it("stops the server on Ctrl+C", async () => {
    child.kill("SIGINT");
    await new Promise((r) => child.once("exit", r));
    await expect(fetch(`http://127.0.0.1:${port}/api/notes`)).rejects.toThrow();
  }, 30_000);
});
