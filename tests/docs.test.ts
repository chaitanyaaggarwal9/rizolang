/** Keeps docs/SPEC.md and docs/SPEC-COMPACT.md in sync with the compiler. */
import { readdirSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { compile } from "../src/compiler.js";

const read = (p: string) => readFileSync(new URL(`../${p}`, import.meta.url), "utf8");
const spec = read("docs/SPEC.md");
const readme = read("README.md");
const compact = read("docs/SPEC-COMPACT.md");

function sourceFiles(dir: string): string[] {
  return readdirSync(new URL(`../${dir}`, import.meta.url), { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sourceFiles(`${dir}/${e.name}`) : [`${dir}/${e.name}`],
  );
}

const wrapField = (line: string) => `model Example {\n  ${line}\n}\n`;

/** The models from SPEC §3, which the spec's api examples use. */
const PRELUDE = `auth User by email
model User {
  email: Email unique private
  password: Password
  name: Text max 100
}
model Post {
  author: User
  title: Text max 200
  published: Bool
}
api GET /api/posts -> list Post.public {
  public
  return db.Post.list()
}
api GET /api/posts/:id -> Post.public {
  public
  return db.Post.find(id)
}
api POST /api/posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}
api PATCH /api/posts/:id -> Post.public {
  requires login
  requires owner author
  return db.Post.update(id, body)
}
api DELETE /api/posts/:id {
  requires login
  requires owner author
  return db.Post.delete(id)
}
`;
const isBlock = (s: string) => /^(model|auth|api|page)\b/m.test(s.trimStart());
/** Compile a snippet: whole blocks as they are (api blocks with the §3 models), single fields inside a model. */
const asFile = (s: string): string => {
  const t = s.trimStart();
  if (t.startsWith("auth") && !t.includes("model")) return PRELUDE; // the bare auth line from SPEC §4
  if (/^(api|page)\b/m.test(t) && !/^model\b/m.test(t)) return PRELUDE + s;
  return isBlock(s) ? s : wrapField(s.split("\n").join("\n  "));
};

describe("docs", () => {
  it("documents every error code the compiler can produce, and no others", () => {
    const used = new Set(sourceFiles("src").flatMap((f) => [...read(f).matchAll(/"(RZ\d{4})"/g)].map((m) => m[1])));
    const documented = new Set([...spec.matchAll(/^\| (RZ\d{4}) \|/gm)].map((m) => m[1]));
    expect([...documented].sort()).toEqual([...used].sort());
  });

  it("keeps the compact spec under 1,500 words", () => {
    expect(compact.split(/\s+/).filter(Boolean).length).toBeLessThan(1500);
  });

  it("the main examples in both specs compile", () => {
    const blocks = [spec, compact, readme].flatMap((d) => [...d.matchAll(/```rizo\n([\s\S]*?)```/g)].map((m) => m[1] ?? ""));
    const full = blocks.filter((b) => !b.includes("// Wrong") && !b.includes("→") && (isBlock(b) || b.trimStart().startsWith("// ")));
    expect(full.length).toBeGreaterThanOrEqual(5);
    for (const b of full) expect(compile(asFile(b), "doc.rz").ok, b).toBe(true);
  });

  it("every Wrong → Right pair in the compact spec behaves as documented", () => {
    const section = /## Wrong → Right\n+```rizo\n([\s\S]*?)```/.exec(compact)?.[1] ?? "";
    const pairs = [...section.matchAll(/^(.+?)\s+→\s+(.+)$/gm)]
      .map((m) => [m[1]?.trim() ?? "", m[2]?.trim() ?? ""] as const);
    expect(pairs.length).toBeGreaterThan(10);
    for (const [wrong, right] of pairs) {
      if (wrong.startsWith("model")) {
        expect(compile(`${wrong}\n  x: Text\n}`, "doc.rz").ok, wrong).toBe(false);
        expect(compile(`${right}\n  x: Text\n}`, "doc.rz").ok, right).toBe(true);
        continue;
      }
      expect(compile(wrapField(wrong), "doc.rz").ok, wrong).toBe(false);
      if (!right.startsWith("(")) expect(compile(wrapField(right), "doc.rz").ok, right).toBe(true);
    }
  });

  it("every 'Wrong' snippet in SPEC.md fails and every 'Right' snippet compiles", () => {
    const blocks = [...spec.matchAll(/```rizo\n\/\/ Wrong\n([\s\S]*?)\n\n\/\/ Right\n([\s\S]*?)```/g)];
    expect(blocks.length).toBeGreaterThanOrEqual(8);
    for (const [, wrong = "", right = ""] of blocks) {
      // Each wrong line must fail on its own.
      if (isBlock(wrong)) {
        expect(compile(asFile(wrong), "doc.rz").ok, wrong).toBe(false);
      } else {
        for (const line of wrong.split("\n").filter((l) => l.trim())) {
          expect(compile(wrapField(line.trim()), "doc.rz").ok, line).toBe(false);
        }
      }
      expect(compile(asFile(right), "doc.rz").ok, right).toBe(true);
    }
  });
});
