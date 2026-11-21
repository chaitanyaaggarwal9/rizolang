import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { compile } from "./compiler.js";
import { formatDiagnostic } from "./diagnostics.js";
import { VERSION } from "./version.js";

export interface CliIo {
  /** Directory that `dist/` is created in. */
  readonly cwd: string;
  readonly stdout: (text: string) => void;
  readonly stderr: (text: string) => void;
}

export const OUT_DIR = "dist";

const USAGE = `rizolang ${VERSION}

Usage:
  rizolang build <file.rz>   Compile to ${OUT_DIR}/ (schema.sql, types.ts and, with auth or api blocks, a Node.js server)
  rizolang --version         Print the version
  rizolang --help            Print this help`;

/** Files the build owns in dist/ besides schema.sql and types.ts. Removed before each build. */
const SERVER_FILES = ["routes.ts", "server.ts", "package.json", "tsconfig.json"];
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
  if (rest.length !== 1 || rest[0] === undefined) {
    return usageError(io, "RZ0903", "The build command needs exactly one .rz file.",
      "Run `rizolang build <file.rz>`, for example `rizolang build app.rz`.");
  }
  const file = rest[0];
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

  const outDir = join(io.cwd, OUT_DIR);
  mkdirSync(outDir, { recursive: true });
  // Remove server files from a previous build so they never go stale.
  for (const f of SERVER_FILES) rmSync(join(outDir, f), { force: true });
  rmSync(join(outDir, RUNTIME_DIR), { recursive: true, force: true });

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
    written.push(`${OUT_DIR}/server.ts`, `${OUT_DIR}/routes.ts`, `${OUT_DIR}/runtime/`);
  }
  const n = result.models.length;
  const e = result.apis.length;
  io.stdout(
    `Built ${file}: ${n} model${n === 1 ? "" : "s"}${e > 0 ? `, ${e} endpoint${e === 1 ? "" : "s"}` : ""}${result.auth ? ", auth" : ""} -> ${written.join(", ")}\n`,
  );
  return 0;
}
