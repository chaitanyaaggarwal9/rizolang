#!/usr/bin/env node
import { run } from "./cli.js";
import { runDev } from "./dev.js";

const argv = process.argv.slice(2);
const io = {
  cwd: process.cwd(),
  stdout: (text: string) => void process.stdout.write(text),
  stderr: (text: string) => void process.stderr.write(text),
};

if (argv[0] === "dev") {
  // Long-running: builds, migrates and runs the app until Ctrl+C.
  void runDev(argv.slice(1), io).then((code) => {
    process.exitCode = code;
  });
} else {
  process.exitCode = run(argv, io);
}
