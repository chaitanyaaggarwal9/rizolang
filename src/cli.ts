import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compile } from "./compiler.js";
import { MIGRATION_FILE, SNAPSHOT_FILE, type MigrationPlan, initialPlan, migrationFile, parseSnapshot, planMigration, snapshotText } from "./migrations.js";
import { buildSchema } from "./schema.js";
import { formatDiagnostic } from "./diagnostics.js";
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
  rizolang build <file.rz> [--allow-data-loss]
      Compile to ${OUT_DIR}/ (schema.sql, types.ts and, with auth or api blocks, a Node.js server),
      and write a migration to ${MIGRATIONS_DIR}/ when the models changed. Changes that would
      delete data are refused unless --allow-data-loss is given.
  rizolang --version         Print the version
  rizolang --help            Print this help`;

/** Files the build owns in dist/ besides schema.sql and types.ts. Removed before each build. */
const SERVER_FILES = ["routes.ts", "server.ts", "migrate.ts", "package.json", "tsconfig.json"];
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

function usageError(io: CliIo, code: string, message: string, fix: string): number {
  io.stderr(`rizolang: error ${code}: ${message}\n  fix: ${fix}\n`);
  return 1;
}

/** Runs the CLI and returns the process exit code. Never throws for user errors. */
export function run(argv: readonly string[], io: CliIo): number {
  const [command, ...rest] = argv;

  if (command === undefined || command === "--help" || command === "-h" || command === "help") {
    io.stdout(`${USAGE}\n`);
    return command === undefined ? 1 : 0;
  }
  if (command === "--version" || command === "-v") {
    io.stdout(`${VERSION}\n`);
    return 0;
  }
  if (command !== "build") {
    return usageError(io, "RZ0903", `Unknown command "${command}".`,
      "Run `rizolang build <file.rz>`.");
  }
  const flags = rest.filter((a) => a.startsWith("--"));
  const files = rest.filter((a) => !a.startsWith("--"));
  const unknownFlag = flags.find((f) => f !== "--allow-data-loss");
  if (unknownFlag !== undefined) {
    return usageError(io, "RZ0903", `Unknown option "${unknownFlag}".`, "The only option is --allow-data-loss.");
  }
  const allowDataLoss = flags.includes("--allow-data-loss");
  if (files.length !== 1 || files[0] === undefined) {
    return usageError(io, "RZ0903", "The build command needs exactly one .rz file.",
      "Run `rizolang build <file.rz>`, for example `rizolang build app.rz`.");
  }
  const file = files[0];
  if (!file.endsWith(".rz")) {
    return usageError(io, "RZ0902", `"${file}" is not a Rizo Lang file.`,
      "Rizo Lang source files must end in .rz, for example app.rz.");
  }

  let source: string;
  try {
    source = readFileSync(resolve(io.cwd, file), "utf8");
  } catch {
    return usageError(io, "RZ0901", `Cannot read file "${file}".`,
      "Check that the file exists and that the path is correct.");
  }

  const result = compile(source, file);
  if (!result.ok) {
    const count = result.diagnostics.length;
    io.stderr(result.diagnostics.map((d) => formatDiagnostic(d, source)).join("\n\n"));
    io.stderr(`\n\nBuild failed with ${count} error${count === 1 ? "" : "s"}. No files were written.\n`);
    return 1;
  }

  // Plan the migration before writing anything, so a refused build leaves no files behind.
  const migDir = join(io.cwd, MIGRATIONS_DIR);
  const schema = buildSchema(result.models, result.auth);
  const existing = existsSync(migDir) ? readdirSync(migDir).filter((f) => MIGRATION_FILE.test(f)).sort() : [];
  let plan: MigrationPlan;
  const snapshotPath = join(migDir, SNAPSHOT_FILE);
  // Read directly instead of checking existence first, so the file cannot change in between.
  let snapshot: string | undefined;
  try {
    snapshot = readFileSync(snapshotPath, "utf8");
  } catch (e) {
    if ((e as { code?: unknown }).code !== "ENOENT") {
      return usageError(io, "RZ0905", `Cannot read ${MIGRATIONS_DIR}/${SNAPSHOT_FILE}.`, "Check the file's permissions.");
    }
  }
  if (snapshot !== undefined) {
    const parsed = parseSnapshot(snapshot);
    if ("error" in parsed) {
      return usageError(io, "RZ0905", `${MIGRATIONS_DIR}/${SNAPSHOT_FILE} cannot be used: ${parsed.error}.`,
        `Restore it from version control. It must match the last migration in ${MIGRATIONS_DIR}/.`);
    }
    plan = planMigration(parsed.schema, schema);
  } else if (existing.length > 0) {
    return usageError(io, "RZ0905", `${MIGRATIONS_DIR}/ has migration files but no ${SNAPSHOT_FILE}.`,
      `Restore ${MIGRATIONS_DIR}/${SNAPSHOT_FILE} from version control. Without it, rizolang cannot tell what changed.`);
  } else {
    plan = initialPlan(schema);
  }
  if (plan.dataLoss.length > 0 && !allowDataLoss) {
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
  if (plan.statements.length > 0) {
    const last = existing[existing.length - 1];
    const number = last === undefined ? 1 : Number(MIGRATION_FILE.exec(last)?.[1] ?? "0") + 1;
    const name = `${String(number).padStart(4, "0")}_${plan.slug}.sql`;
    mkdirSync(migDir, { recursive: true });
    try {
      // "wx": never overwrite an existing migration.
      writeFileSync(join(migDir, name), migrationFile(plan, number, file.replace(/[^\x20-\x7e]/g, "?")), { flag: "wx" });
    } catch {
      return usageError(io, "RZ0905", `${MIGRATIONS_DIR}/${name} already exists.`,
        `Another build may be running, or ${MIGRATIONS_DIR}/ was changed by hand. Restore it from version control and build again.`);
    }
    writeFileSync(snapshotPath, snapshotText(schema));
    existing.push(name);
    migrationNote = `\nNew migration: ${MIGRATIONS_DIR}/${name}\n${plan.summary.map((s) => `  - ${s}`).join("\n")}\n`;
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
    written.push(`${OUT_DIR}/server.ts`, `${OUT_DIR}/routes.ts`, `${OUT_DIR}/runtime/`);
  }
  if (output.server !== undefined) {
    writeFileSync(join(outDir, "migrate.ts"), output.server.migrate);
    mkdirSync(join(outDir, MIGRATIONS_DIR));
    for (const f of existing) writeFileSync(join(outDir, MIGRATIONS_DIR, f), readFileSync(join(migDir, f)));
  }

  const n = result.models.length;
  const e = result.apis.length;
  io.stdout(
    `Built ${file}: ${n} model${n === 1 ? "" : "s"}${e > 0 ? `, ${e} endpoint${e === 1 ? "" : "s"}` : ""}${result.auth ? ", auth" : ""} -> ${written.join(", ")}\n${migrationNote}`,
  );
  return 0;
}
