/**
 * `rizolang dev app.rz`: build, migrate and run the app locally, and do it
 * again whenever the .rz file is saved.
 *
 * It only fills in development settings that are not already set, and says
 * which ones it filled in. Builds that would delete data are still refused
 * without --allow-data-loss, because migrations are committed and later run
 * in production.
 */
import { type ChildProcess, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, unwatchFile, watchFile, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { connect } from "node:net";
import { dirname, join, resolve } from "node:path";
import { type CliIo, OUT_DIR, run } from "./cli.js";
import { compile } from "./compiler.js";

export interface DevSettings {
  readonly env: Record<string, string>;
  /** One line per setting that was filled in, to tell the developer. */
  readonly notes: readonly string[];
}

/**
 * The environment for the dev server: the developer's own settings, plus
 * development defaults for whatever the app needs and isn't set.
 */
export function devSettings(
  env: Readonly<Record<string, string | undefined>>,
  app: { readonly port: number; readonly auth: boolean; readonly privacy: boolean; readonly encrypted: boolean },
  encryptionKey: () => string,
): DevSettings {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (v !== undefined) out[k] = v;
  const notes: string[] = [];
  const fill = (key: string, value: string, why: string): void => {
    if (out[key] !== undefined && out[key] !== "") return;
    out[key] = value;
    notes.push(`${key}=${key === "RIZO_ENCRYPTION_KEYS" ? "(a local key, kept in dist/.dev-encryption-key)" : value}: ${why}`);
  };
  out["PORT"] = String(app.port);
  out["HOST"] ??= "127.0.0.1";
  if (app.auth) {
    fill("RIZO_PUBLIC_URL", `http://localhost:${app.port}`, "links in emails point to this machine");
    if ((out["RIZO_EMAIL_API_KEY"] ?? "") === "") fill("RIZO_EMAIL_DEV", "1", "emails are printed here instead of sent");
  }
  if (app.privacy) fill("RIZO_PRIVACY_CONTACT", "privacy@example.com", "a placeholder; set your real address before deploying");
  if (app.encrypted) fill("RIZO_ENCRYPTION_KEYS", `dev:${encryptionKey()}`, "for local data only; never use it in production");
  return { env: out, notes };
}

/** Read the local encryption key, creating it the first time. */
function localKey(distDir: string): string {
  const file = join(distDir, ".dev-encryption-key");
  if (existsSync(file)) return readFileSync(file, "utf8").trim();
  const key = randomBytes(32).toString("base64");
  writeFileSync(file, `${key}\n`, { mode: 0o600 });
  return key;
}

/** Wait until the server accepts connections. False if it exits first, or after 15 seconds. */
async function listening(server: ChildProcess, port: number, host: string): Promise<boolean> {
  for (let i = 0; i < 150; i++) {
    if (server.exitCode !== null || server.signalCode !== null) return false;
    const open = await new Promise<boolean>((done) => {
      const socket = connect({ port, host: host === "::" || host === "0.0.0.0" ? "127.0.0.1" : host });
      socket.once("connect", () => { socket.destroy(); done(true); });
      socket.once("error", () => done(false));
    });
    if (open) return true;
    await new Promise((r) => setTimeout(r, 100));
  }
  return false;
}

/** Run a command and wait for it. Resolves with its exit code. */
function runChild(command: string, args: readonly string[], cwd: string, env: Record<string, string>): Promise<number> {
  return new Promise((done) => {
    const child = spawn(command, args, { cwd, env, stdio: "inherit", shell: process.platform === "win32" && command === "npm" });
    child.on("exit", (code) => done(code ?? 1));
    child.on("error", () => done(1));
  });
}

export async function runDev(argv: readonly string[], io: CliIo, env: Readonly<Record<string, string | undefined>> = process.env): Promise<number> {
  const say = (text: string): void => io.stdout(`rizolang dev: ${text}\n`);
  const fail = (code: string, message: string, fix: string): number => {
    io.stderr(`rizolang: error ${code}: ${message}\n  fix: ${fix}\n`);
    return 1;
  };
  const flags = argv.filter((a) => a.startsWith("--"));
  const files = argv.filter((a, i) => !a.startsWith("--") && argv[i - 1] !== "--port");
  const unknown = flags.find((f) => f !== "--allow-data-loss" && f !== "--port");
  if (unknown !== undefined) return fail("RZ0903", `Unknown option "${unknown}".`, "The options of dev are --port <number> and --allow-data-loss.");
  const portArg = argv[argv.indexOf("--port") + 1];
  const port = argv.includes("--port") ? Number(portArg) : Number(env["PORT"] ?? "3000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) return fail("RZ0903", "The port must be a whole number from 1 to 65535.", "Run `rizolang dev app.rz --port 3000`.");
  const file = files[0];
  if (files.length !== 1 || file === undefined || !file.endsWith(".rz")) {
    return fail("RZ0903", "The dev command needs exactly one .rz file.", "Run `rizolang dev app.rz`.");
  }
  if ((env["DATABASE_URL"] ?? "") === "") {
    return fail("RZ0906", "rizolang dev needs a database: DATABASE_URL is not set.",
      "Start PostgreSQL on this machine, create a database, then run `DATABASE_URL=postgres://localhost:5432/myapp rizolang dev app.rz`.");
  }
  const path = resolve(io.cwd, file);
  const distDir = join(dirname(path), OUT_DIR);
  const buildArgs = ["build", file, ...(flags.includes("--allow-data-loss") ? ["--allow-data-loss"] : [])];

  let server: ChildProcess | undefined;
  const stopServer = (): Promise<void> => new Promise((done) => {
    if (server === undefined || server.exitCode !== null) return done();
    server.once("exit", () => done());
    server.kill("SIGTERM");
  });

  /**
   * Build, migrate and (re)start. Returns false if anything failed (a running
   * server is then left as it was), and "fatal" when watching can't help.
   */
  const cycle = async (): Promise<boolean | "fatal"> => {
    let source: string;
    try {
      source = readFileSync(path, "utf8");
    } catch {
      fail("RZ0901", `Cannot read file "${file}".`, "Check that the file exists and that the path is correct.");
      return "fatal";
    }
    const checked = compile(source, file);
    if (checked.ok && checked.output.server === undefined) {
      fail("RZ0907", `${file} has no auth line, api or page blocks, so there is no server to run.`,
        "Add an api or page block, or use `rizolang build` to get the schema and types only.");
      return "fatal";
    }
    if (run(buildArgs, io) !== 0) {
      say(server === undefined ? "fix the errors above and save; the server starts when the file builds." : "fix the errors above and save; the running server is unchanged.");
      return false;
    }
    if (!checked.ok) return false;
    try {
      createRequire(join(distDir, "package.json")).resolve("pg");
    } catch {
      say("installing pg (the generated app's only dependency) in dist/ ...");
      if (await runChild("npm", ["install", "--no-audit", "--no-fund"], distDir, { ...process.env } as Record<string, string>) !== 0) {
        fail("RZ0906", "Could not install pg in dist/.", "Run `npm install` in dist/ and look at the error it prints.");
        return false;
      }
    }
    const settings = devSettings(env, {
      port,
      auth: checked.auth !== undefined,
      privacy: checked.privacy !== undefined,
      encrypted: checked.models.some((m) => m.fields.some((f) => f.encrypted)),
    }, () => localKey(distDir));
    if (await runChild(process.execPath, ["migrate.ts"], distDir, settings.env) !== 0) {
      say("the migration failed (see above); the running server is unchanged.");
      return false;
    }
    await stopServer();
    for (const note of settings.notes) say(`using ${note}`);
    const started = spawn(process.execPath, ["server.ts"], { cwd: distDir, env: settings.env, stdio: "inherit" });
    server = started;
    if (!(await listening(started, port, settings.env["HOST"] ?? "127.0.0.1"))) {
      say(`the server stopped while starting (see above). Fix it and save ${file} to try again.`);
      return false;
    }
    say(`running at http://localhost:${port} (saving ${file} rebuilds and restarts; Ctrl+C stops)`);
    return true;
  };

  if ((await cycle()) === "fatal") return 1;
  let busy = false;
  let again = false;
  const onChange = async (): Promise<void> => {
    if (busy) {
      again = true;
      return;
    }
    busy = true;
    say(`${file} changed, rebuilding...`);
    await cycle();
    busy = false;
    if (again) {
      again = false;
      await onChange();
    }
  };
  watchFile(path, { interval: 300 }, (now, before) => {
    if (now.mtimeMs !== before.mtimeMs) void onChange();
  });
  return new Promise((done) => {
    const quit = (): void => {
      unwatchFile(path);
      void stopServer().then(() => done(0));
    };
    process.once("SIGINT", quit);
    process.once("SIGTERM", quit);
  });
}
