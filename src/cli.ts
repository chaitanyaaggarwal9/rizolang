import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
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
  rizolang build <file.rz>   Compile models to ${OUT_DIR}/schema.sql and ${OUT_DIR}/types.ts
  rizolang --version         Print the version
  rizolang --help            Print this help`;

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
  writeFileSync(join(outDir, "schema.sql"), result.output.sql);
  writeFileSync(join(outDir, "types.ts"), result.output.typescript);
  const n = result.models.length;
  io.stdout(`Built ${file}: ${n} model${n === 1 ? "" : "s"} -> ${OUT_DIR}/schema.sql, ${OUT_DIR}/types.ts\n`);
  return 0;
}
