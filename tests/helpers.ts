import { expect } from "vitest";
import { type CompileResult, compile } from "../src/compiler.js";
import type { Diagnostic } from "../src/diagnostics.js";

export function compileOk(source: string): Extract<CompileResult, { ok: true }> {
  const r = compile(source, "test.rz");
  if (!r.ok) {
    throw new Error(`expected success, got:\n${r.diagnostics.map((d) => `${d.code} ${d.message}`).join("\n")}`);
  }
  return r;
}

export function compileErrors(source: string): readonly Diagnostic[] {
  const r = compile(source, "test.rz");
  if (r.ok) throw new Error("expected compile errors, but compilation succeeded");
  for (const d of r.diagnostics) {
    // Every error must say what, where and how to fix it.
    expect(d.message.length).toBeGreaterThan(0);
    expect(d.fix.length).toBeGreaterThan(0);
    expect(d.span.line).toBeGreaterThanOrEqual(1);
    expect(d.span.col).toBeGreaterThanOrEqual(1);
    expect(d.code).toMatch(/^RZ\d{4}$/);
  }
  return r.diagnostics;
}

export function firstError(source: string): Diagnostic {
  const [d] = compileErrors(source);
  if (d === undefined) throw new Error("no diagnostics");
  return d;
}

/** Return the body of `export interface <name> { ... }` from generated TypeScript. */
export function interfaceBody(ts: string, name: string): string {
  const m = new RegExp(`export interface ${name} \\{\\n([\\s\\S]*?)\\n\\}`).exec(ts);
  if (m?.[1] === undefined) throw new Error(`interface ${name} not found`);
  return m[1];
}

/** Property names declared in an interface body. */
export function propertyNames(body: string): string[] {
  return [...body.matchAll(/^\s+readonly (\w+)\??:/gm)].map((m) => m[1] ?? "");
}
