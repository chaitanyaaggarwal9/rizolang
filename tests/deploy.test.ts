import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { request } from "node:http";
import { createServer as createNetServer } from "node:net";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createRequestHandler } from "../runtime/server.ts";
import { compileOk } from "./helpers.js";
import { buildApp } from "../src/emit/routes.js";

describe("the health check", () => {
  const app = buildApp(compileOk("model Note {\n  title: Text\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list()\n}\n").apis, undefined);
  const ask = async (db: { query: () => Promise<never> | Promise<{ rows: []; rowCount: 0 }> }, shuttingDown = false) => {
    const handler = createRequestHandler(app, { db: db as never, log: () => undefined, shuttingDown: () => shuttingDown });
    const server = (await import("node:http")).createServer((req, res) => void handler(req, res));
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const res = await fetch(`http://127.0.0.1:${port}/_rizo/health`);
    const body = await res.json();
    await new Promise((r) => server.close(r));
    return { status: res.status, body };
  };

  it("answers ok when the database answers", async () => {
    expect(await ask({ query: async () => ({ rows: [], rowCount: 0 }) })).toEqual({ status: 200, body: { status: "ok" } });
  });

  it("answers 503 when the database fails or hangs, or while shutting down, and says nothing else", async () => {
    expect(await ask({ query: () => Promise.reject(new Error("connection refused at 10.0.0.5")) })).toEqual({ status: 503, body: { status: "unavailable" } });
    expect(await ask({ query: () => new Promise(() => undefined) })).toEqual({ status: 503, body: { status: "unavailable" } });
    expect(await ask({ query: async () => ({ rows: [], rowCount: 0 }) }, true)).toEqual({ status: 503, body: { status: "unavailable" } });
  }, 10_000);
});

describe("the generated Dockerfile", () => {
  const out = compileOk("model Note {\n  title: Text\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list()\n}\n").output.server;

  it("installs only pg, runs as a non-root user, listens on all interfaces and checks health", () => {
    const docker = out?.dockerfile ?? "";
    expect(docker).toMatch(/^FROM node:24-alpine$/m);
    expect(docker).toContain("RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund");
    expect(docker).toMatch(/^USER node$/m);
    expect(docker).toContain("ENV HOST=0.0.0.0 PORT=3000");
    expect(docker).toContain("/_rizo/health");
    expect(docker).toMatch(/^CMD \["node", "server.ts"\]$/m);
    expect(docker.indexOf("USER node")).toBeLessThan(docker.indexOf("CMD"));
  });

  it("keeps installed packages and local secrets out of the image", () => {
    expect(out?.dockerignore.split("\n")).toEqual(expect.arrayContaining(["node_modules", ".dev-encryption-key", ".env"]));
  });
});

const DATABASE_URL = process.env["RIZO_TEST_DATABASE_URL"];
const BIN = fileURLToPath(new URL("../build/src/bin.js", import.meta.url));

describe.skipIf(DATABASE_URL === undefined || !existsSync(BIN))("graceful shutdown of a generated server", () => {
  const dir = join(fileURLToPath(new URL(".", import.meta.url)), `.dev-tmp-${randomBytes(4).toString("hex")}`);
  const dbName = `rizo_stop_${randomBytes(4).toString("hex")}`;
  const dbUrl = (() => {
    const u = new URL(DATABASE_URL ?? "postgres://localhost");
    u.pathname = `/${dbName}`;
    return u.toString();
  })();
  let server: ChildProcess;
  let output = "";
  let port = 0;

  beforeAll(async () => {
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`CREATE DATABASE "${dbName}"`);
    await admin.end();
    mkdirSync(dir);
    copyFileSync(fileURLToPath(new URL("../examples/blog.rz", import.meta.url)), join(dir, "blog.rz"));
    expect(spawnSync(process.execPath, [BIN, "build", "blog.rz"], { cwd: dir }).status).toBe(0);
    expect(spawnSync(process.execPath, ["migrate.ts"], { cwd: join(dir, "dist"), env: { ...process.env, DATABASE_URL: dbUrl } }).status).toBe(0);
    port = await new Promise<number>((done) => {
      const s = createNetServer().listen(0, () => {
        const p = (s.address() as { port: number }).port;
        s.close(() => done(p));
      });
    });
    server = spawn(process.execPath, ["server.ts"], {
      cwd: join(dir, "dist"),
      env: { ...process.env, DATABASE_URL: dbUrl, PORT: String(port), RIZO_PUBLIC_URL: `http://localhost:${port}`, RIZO_EMAIL_DEV: "1", RIZO_PRIVACY_CONTACT: "privacy@example.com" },
    });
    server.stdout?.on("data", (d) => (output += String(d)));
    server.stderr?.on("data", (d) => (output += String(d)));
    for (let i = 0; i < 100 && !output.includes("listening"); i++) await new Promise((r) => setTimeout(r, 100));
  }, 30_000);

  afterAll(async () => {
    if (server.exitCode === null) server.kill("SIGKILL");
    rmSync(dir, { recursive: true, force: true });
    const admin = new pg.Client({ connectionString: DATABASE_URL });
    await admin.connect();
    await admin.query(`DROP DATABASE IF EXISTS "${dbName}" WITH (FORCE)`);
    await admin.end();
  });

  it("is healthy while running", async () => {
    expect(await (await fetch(`http://127.0.0.1:${port}/_rizo/health`)).json()).toEqual({ status: "ok" });
  });

  it("finishes a request in progress after SIGTERM, then stops cleanly", async () => {
    const body = JSON.stringify({ email: "slow@example.com", password: "a long enough password", name: "Slow" });
    const response = new Promise<number>((done, failed) => {
      const req = request({ host: "127.0.0.1", port, method: "POST", path: "/auth/signup", headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(body) } },
        (res) => {
          res.resume();
          done(res.statusCode ?? 0);
        });
      req.on("error", failed);
      req.write(body.slice(0, 10));
      // The request is in progress: stop the server, then send the rest of the body.
      setTimeout(() => {
        server.kill("SIGTERM");
        setTimeout(() => req.end(body.slice(10)), 500);
      }, 300);
    });
    expect(await response).toBe(202);
    const code = await new Promise((r) => server.once("exit", r));
    expect(code).toBe(0);
    expect(output).toContain("rizo: shutting down, finishing requests in progress...");
    expect(output).toContain("rizo: stopped");
    await expect(fetch(`http://127.0.0.1:${port}/_rizo/health`)).rejects.toThrow();
    expect(readFileSync(join(dir, "dist", "Dockerfile"), "utf8")).toContain("FROM node:24-alpine");
  }, 30_000);
});
