import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { audit } from "./audit.js";
import { compile } from "./compiler.js";
import { MIGRATION_FILE, SNAPSHOT_FILE, type MigrationPlan, initialPlan, migrationFile, parseSnapshot, planMigration, snapshotText } from "./migrations.js";
import { buildSchema } from "./schema.js";
import { type Diagnostic, formatDiagnostic } from "./diagnostics.js";
import { VERSION } from "./version.js";

export interface CliIo {
  /** Directory that `dist/` is created in. */
  readonly cwd: string;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export const OUT_DIR = "dist";
export const MIGRATIONS_DIR = "migrations";
/** Error code for a build that would delete data without --allow-data-loss. */
const DATA_LOSS_CODE = "RZ0904";

const USAGE = `rizolang ${VERSION}

Usage:
  rizolang build <file.rz> [--allow-data-loss] [--json]
      Compile to ${OUT_DIR}/ (schema.sql, types.ts and, with auth or api blocks, a Node.js server),
      and write a migration to ${MIGRATIONS_DIR}/ when the models changed. Changes that would
      delete data are refused unless --allow-data-loss is given.
      --json prints one JSON object (the result, or every error with its code, line, column
      and fix) instead of text, for editors and AI agents.
  rizolang audit <file.rz> [--json]
      Review the file for risky choices (public writes, personal data that isn't private,
      loose rate limits...) and print each with its location and a fix. Writes nothing.
      Exits with 1 when there are warnings, so it can run in CI.
  rizolang dev <file.rz> [--port 3000] [--allow-data-loss]
      For local development, with DATABASE_URL set: build, apply migrations and run the server
      with development settings (printed emails, localhost links), then rebuild and restart
      whenever the file is saved.
  rizolang --version         Print the version
  rizolang --help            Print this help`;

/** Files the build owns in dist/ besides schema.sql and types.ts. Removed before each build. */
const SERVER_FILES = ["routes.ts", "server.ts", "migrate.ts", "reencrypt.ts", "openapi.json", "package.json", "tsconfig.json"];
const RUNTIME_DIR = "runtime";

/** Locate the runtime sources shipped with the compiler (works from src/ and build/src/). */
export function runtimeSourceDir(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 4; i++) {
    const candidate = join(dir, RUNTIME_DIR);
    if (existsSync(join(candidate, "server.ts"))) return candidate;
    dir = dirname(dir);
  }
  throw new Error("rizolang runtime sources not found; the installation is incomplete");
}

/** One error as `--json` prints it. Location fields are null for errors that aren't about a line of the file. */
export interface JsonError {
  readonly code: string;
  readonly message: string;
  readonly fix: string;
  readonly file: string | null;
  readonly line: number | null;
  readonly column: number | null;
  readonly length: number | null;
}

function jsonError(d: Diagnostic): JsonError {
  return { code: d.code, message: d.message, fix: d.fix, file: d.file, line: d.span.line, column: d.span.col, length: d.span.length };
}

function printJson(io: CliIo, value: unknown): void {
  io.stdout(`${JSON.stringify({ rizolang: VERSION, ...(value as object) })}\n`);
}

/** Runs the CLI and returns the process exit code. Never throws for user errors. */
export function run(argv: readonly string[], io: CliIo): number {
  const [command, ...rest] = argv;
  const flags = rest.filter((a) => a.startsWith("--"));
  const files = rest.filter((a) => !a.startsWith("--"));
  const json = flags.includes("--json");
  /** Report an error that isn't about a line of the file, and fail. */
  const usageError = (code: string, message: string, fix: string, file: string | null = null): number => {
    if (json) printJson(io, { ok: false, errors: [{ code, message, fix, file, line: null, column: null, length: null } satisfies JsonError] });
    else io.stderr(`rizolang: error ${code}: ${message}\n  fix: ${fix}\n`);
    return 1;
  };

  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    io.stdout(`${USAGE}\n`);
    return command === undefined ? 1 : 0;
  }
  if (command === "--version" || command === "-v") {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  if (command !== "build" && command !== "audit") {
    return usageError("RZ0903", `Unknown command "${command}".`,
      "Run `rizolang build <file.rz>`, `rizolang audit <file.rz>` or `rizolang dev <file.rz>`.");
  }
  if (command === "audit") return runAudit(io, files, flags, json, usageError);
  const unknownFlag = flags.find((f) => f !== "--allow-data-loss" && f !== "--json");
  if (unknownFlag !== undefined) {
    return usageError("RZ0903", `Unknown option "${unknownFlag}".`, "The options are --allow-data-loss and --json.");
  }
  const allowDataLoss = flags.includes("--allow-data-loss");
  if (files.length !== 1 || files[0] === undefined) {
    return usageError("RZ0903", "The build command needs exactly one .rz file.",
      "Run `rizolang build <file.rz>`, for example `rizolang build app.rz`.");
  }
  const file = files[0];
  if (!file.endsWith(".rz")) {
    return usageError("RZ0902", `"${file}" is not a Rizo Lang file.`,
      "Rizo Lang source files must end in .rz, for example app.rz.");
  }

  let source: string;
  try {
    source = readFileSync(resolve(io.cwd, file), "utf8");
  } catch {
    return usageError("RZ0901", `Cannot read file "${file}".`,
      "Check that the file exists and that the path is correct.");
  }

  const result = compile(source, file);
  if (!result.ok) {
    if (json) {
      printJson(io, { ok: false, errors: result.diagnostics.map(jsonError) });
      return 1;
    }
    const count = result.diagnostics.length;
    io.stderr(result.diagnostics.map((d) => formatDiagnostic(d, source)).join("\n\n"));
    io.stderr(`\n\nBuild failed with ${count} error${count === 1 ? "" : "s"}. No files were written.\n`);
    return 1;
  }

  // Plan the migration before writing anything, so a refused build leaves no files behind.
  const migDir = join(io.cwd, MIGRATIONS_DIR);
  const schema = buildSchema(result.models, result.auth, result.output.server !== undefined, result.apis);
  const existing = existsSync(migDir) ? readdirSync(migDir).filter((f) => MIGRATION_FILE.test(f)).sort() : [];
  let plan: MigrationPlan;
  const snapshotPath = join(migDir, SNAPSHOT_FILE);
  // Read directly instead of checking existence first, so the file cannot change in between.
  let snapshot: string | undefined;
  try {
    snapshot = readFileSync(snapshotPath, "utf8");
  } catch (e) {
    if ((e as { code?: unknown }).code !== "ENOENT") {
      return usageError("RZ0905", `Cannot read ${MIGRATIONS_DIR}/${SNAPSHOT_FILE}.`, "Check the file's permissions.");
    }
  }
  if (snapshot !== undefined) {
    const parsed = parseSnapshot(snapshot);
    if ("error" in parsed) {
      return usageError("RZ0905", `${MIGRATIONS_DIR}/${SNAPSHOT_FILE} cannot be used: ${parsed.error}.`,
        `Restore it from version control. It must match the last migration in ${MIGRATIONS_DIR}/.`);
    }
    plan = planMigration(parsed.schema, schema);
  } else if (existing.length > 0) {
    return usageError("RZ0905", `${MIGRATIONS_DIR}/ has migration files but no ${SNAPSHOT_FILE}.`,
      `Restore ${MIGRATIONS_DIR}/${SNAPSHOT_FILE} from version control. Without it, rizolang cannot tell what changed.`);
  } else {
    plan = initialPlan(schema);
  }
  if (plan.dataLoss.length > 0 && !allowDataLoss) {
    if (json) {
      printJson(io, {
        ok: false,
        errors: [{
          code: DATA_LOSS_CODE,
          message: "This change would delete data.",
          fix: `To keep the data, undo the change in ${file}. If you really want to delete it, back up the database, then build with --allow-data-loss.`,
          file, line: null, column: null, length: null,
        } satisfies JsonError],
        dataLoss: plan.dataLoss,
      });
      return 1;
    }
    io.stderr(
      `${file} error ${DATA_LOSS_CODE}: This change would delete data:\n${plan.dataLoss.map((d) => `  - ${d}`).join("\n")}\n` +
      `  fix: To keep the data, undo that change in ${file}. Renaming is not supported yet: keep the old name.\n` +
      `       If you really want to delete it, back up the database, then run \`rizolang build ${file} --allow-data-loss\`.\n` +
      "\nBuild stopped. No files were written.\n",
    );
    return 1;
  }

  // Record the migration and the new snapshot.
  let migrationNote = "";
  let migration: { file: string; changes: readonly string[] } | null = null;
  if (plan.statements.length > 0) {
    const last = existing[existing.length - 1];
    const number = last === undefined ? 1 : Number(MIGRATION_FILE.exec(last)?.[1] ?? "0") + 1;
    const name = `${String(number).padStart(4, "0")}_${plan.slug}.sql`;
    mkdirSync(migDir, { recursive: true });
    try {
      // "wx": never overwrite an existing migration.
      writeFileSync(join(migDir, name), migrationFile(plan, number, file.replace(/[^\x20-\x7e]/g, "?")), { flag: "wx" });
    } catch {
      return usageError("RZ0905", `${MIGRATIONS_DIR}/${name} already exists.`,
        `Another build may be running, or ${MIGRATIONS_DIR}/ was changed by hand. Restore it from version control and build again.`);
    }
    writeFileSync(snapshotPath, snapshotText(schema));
    existing.push(name);
    migrationNote = `\nNew migration: ${MIGRATIONS_DIR}/${name}\n${plan.summary.map((s) => `  - ${s}`).join("\n")}\n`;
    migration = { file: `${MIGRATIONS_DIR}/${name}`, changes: plan.summary };
  }
  const outDir = join(io.cwd, OUT_DIR);
  mkdirSync(outDir, { recursive: true });
  // Remove server files from a previous build so they never go stale.
  for (const f of SERVER_FILES) rmSync(join(outDir, f), { force: true });
  rmSync(join(outDir, RUNTIME_DIR), { recursive: true, force: true });
  rmSync(join(outDir, MIGRATIONS_DIR), { recursive: true, force: true });

  const { output } = result;
  writeFileSync(join(outDir, "schema.sql"), output.sql);
  writeFileSync(join(outDir, "types.ts"), output.typescript);
  const written = [`${OUT_DIR}/schema.sql`, `${OUT_DIR}/types.ts`];
  if (output.server !== undefined) {
    writeFileSync(join(outDir, "routes.ts"), output.server.routes);
    writeFileSync(join(outDir, "server.ts"), output.server.server);
    writeFileSync(join(outDir, "package.json"), output.server.packageJson);
    writeFileSync(join(outDir, "tsconfig.json"), output.server.tsconfig);
    writeFileSync(join(outDir, "openapi.json"), output.server.openapi);
    const src = runtimeSourceDir();
    mkdirSync(join(outDir, RUNTIME_DIR));
    for (const f of readdirSync(src).filter((n) => n.endsWith(".ts") && !n.endsWith(".test.ts"))) {
      writeFileSync(join(outDir, RUNTIME_DIR, f), readFileSync(join(src, f)));
    }
    // The browser runtime for pages: one script and one stylesheet.
    mkdirSync(join(outDir, RUNTIME_DIR, "client"));
    for (const f of ["rizo-client.js", "styles.css"]) {
      writeFileSync(join(outDir, RUNTIME_DIR, "client", f), readFileSync(join(src, "client", f)));
    }
    written.push(`${OUT_DIR}/server.ts`, `${OUT_DIR}/routes.ts`, `${OUT_DIR}/openapi.json`, `${OUT_DIR}/runtime/`);
  }
  if (output.server !== undefined) {
    writeFileSync(join(outDir, "migrate.ts"), output.server.migrate);
    if (output.server.reencrypt !== undefined) {
      writeFileSync(join(outDir, "reencrypt.ts"), output.server.reencrypt);
      written.push(`${OUT_DIR}/reencrypt.ts`);
    }
    mkdirSync(join(outDir, MIGRATIONS_DIR));
    for (const f of existing) writeFileSync(join(outDir, MIGRATIONS_DIR, f), readFileSync(join(migDir, f)));
  }

  const n = result.models.length;
  const e = result.apis.length;
  if (json) {
    printJson(io, { ok: true, file, models: n, endpoints: e, pages: result.pages.length, auth: result.auth !== undefined, written, migration, dataLoss: plan.dataLoss });
    return 0;
  }
  io.stdout(
    `Built ${file}: ${n} model${n === 1 ? "" : "s"}${e > 0 ? `, ${e} endpoint${e === 1 ? "" : "s"}` : ""}${result.auth ? ", auth" : ""} -> ${written.join(", ")}\n${migrationNote}`,
  );
  return 0;
}

/** `rizolang audit <file.rz>`: report risky choices without writing anything. */
function runAudit(
  io: CliIo,
  files: readonly string[],
  flags: readonly string[],
  json: boolean,
  usageError: (code: string, message: string, fix: string) => number,
): number {
  const unknownFlag = flags.find((f) => f !== "--json");
  if (unknownFlag !== undefined) return usageError("RZ0903", `Unknown option "${unknownFlag}".`, "The only option of audit is --json.");
  const file = files[0];
  if (files.length !== 1 || file === undefined) {
    return usageError("RZ0903", "The audit command needs exactly one .rz file.", "Run `rizolang audit <file.rz>`, for example `rizolang audit app.rz`.");
  }
  if (!file.endsWith(".rz")) return usageError("RZ0902", `"${file}" is not a Rizo Lang file.`, "Rizo Lang source files must end in .rz, for example app.rz.");
  let source: string;
  try {
    source = readFileSync(resolve(io.cwd, file), "utf8");
  } catch {
    return usageError("RZ0901", `Cannot read file "${file}".`, "Check that the file exists and that the path is correct.");
  }
  const result = audit(source, file);
  if (!result.ok) {
    if (json) printJson(io, { ok: false, errors: result.diagnostics.map(jsonError) });
    else io.stderr(`${result.diagnostics.map((d) => formatDiagnostic(d, source)).join("\n\n")}\n\nFix these errors first: the audit needs a file that builds.\n`);
    return 1;
  }
  const { findings, summary } = result;
  if (json) {
    printJson(io, { ok: summary.warnings === 0, file, findings: findings.map((f) => ({ level: f.level, ...jsonError(f) })), summary });
    return summary.warnings === 0 ? 0 : 1;
  }
  const lines = findings.map((f) => formatDiagnostic(f, source, f.level));
  const counts = `${summary.endpoints} endpoint${summary.endpoints === 1 ? "" : "s"} (${summary.public} public, ${summary.login} need a login, ${summary.withRoles} with roles)`;
  const verdict = findings.length === 0
    ? "No findings."
    : `${summary.warnings} warning${summary.warnings === 1 ? "" : "s"} and ${summary.notes} note${summary.notes === 1 ? "" : "s"}.`;
  io.stdout(`${lines.length > 0 ? `${lines.join("\n\n")}\n\n` : ""}Audited ${file}: ${counts}. ${verdict}\n`);
  return summary.warnings === 0 ? 0 : 1;
}
