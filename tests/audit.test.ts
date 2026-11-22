import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { audit } from "../src/audit.js";
import { run } from "../src/cli.js";

const RISKY = `auth User by email

model User {
  email: Email unique
  password: Password
  phone: Text optional
  birthDate: Date optional private
  apiToken: Text optional
}

model Tag {
  name: Text
}

api GET /api/users -> list User.public {
  public
  limit 1000 per minute
  return db.User.list()
}

api POST /api/tags -> Tag.public {
  public
  return db.Tag.create(body)
}

api DELETE /api/tags/:id {
  requires login
  return db.Tag.delete(id)
}
`;

const findings = (source: string) => {
  const r = audit(source, "app.rz");
  if (!r.ok) throw new Error("expected a valid file");
  return r;
};

describe("rizolang audit", () => {
  it("finds no warnings in the example blog, only a note that posts are kept forever", () => {
    const r = findings(readFileSync(new URL("../examples/blog.rz", import.meta.url), "utf8"));
    expect(r.findings.map((f) => [f.level, f.code, f.message])).toEqual([["note", "RA08", "Post records belong to accounts and are kept until someone deletes them."]]);
    expect(r.summary).toEqual({ endpoints: 10, public: 4, login: 6, withRoles: 2, warnings: 0, notes: 1 });
  });

  it("notes models that belong to accounts but have no keep, only with privacy rules", () => {
    const base = "auth User by email\nmodel User {\n  email: Email unique private\n  password: Password\n}\nmodel Message {\n  sender: User\n  body: Text\n}\napi GET /api/messages -> list Message.public {\n  requires login\n  return db.Message.list(sender = me)\n}\n";
    expect(findings(base).findings).toEqual([]);
    expect(findings(`privacy for EU\n${base}`).findings.map((f) => f.code)).toEqual(["RA08"]);
    expect(findings(`privacy for EU\n${base.replace("  body: Text\n", "  body: Text\n  keep 1 year\n")}`).findings).toEqual([]);
  });

  it("points at each risky choice, in file order, with a fix", () => {
    const r = findings(RISKY);
    expect(r.findings.map((f) => [f.level, f.code, f.span.line, f.span.col])).toEqual([
      ["warning", "RA04", 4, 3],
      ["warning", "RA02", 6, 3],
      ["note", "RA03", 7, 3],
      ["warning", "RA02", 8, 3],
      ["warning", "RA05", 15, 9],
      ["note", "RA07", 17, 3],
      ["warning", "RA01", 21, 5],
      ["warning", "RA06", 26, 5],
    ]);
    for (const f of r.findings) expect(f.fix.length).toBeGreaterThan(20);
    expect(r.summary).toMatchObject({ warnings: 6, notes: 2 });
  });

  it("goes quiet once each problem is fixed", () => {
    const fixed = RISKY
      .replace("email: Email unique", "email: Email unique private")
      .replace("phone: Text optional", "phone: Text optional private encrypted")
      .replace("birthDate: Date optional private", "birthDate: Date optional private encrypted")
      .replace("apiToken: Text optional", "apiToken: Text optional private encrypted")
      .replace("  public\n  limit 1000 per minute\n", "  requires login\n  requires role admin\n")
      .replace("auth User by email", "auth User by email roles admin")
      .replace("api POST /api/tags -> Tag.public {\n  public", "api POST /api/tags -> Tag.public {\n  requires login")
      .replace("api DELETE /api/tags/:id {\n  requires login", "api DELETE /api/tags/:id {\n  requires login\n  requires role admin");
    expect(findings(fixed).findings).toEqual([]);
  });

  it("counts models returned through with as public (RA04 for their emails)", () => {
    const src = "auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  name: Text\n}\nmodel Post {\n  author: User\n  title: Text\n}\napi GET /api/posts -> list Post.public with author {\n  public\n  return db.Post.list()\n}\n";
    expect(findings(src).findings.map((f) => f.code)).toContain("RA04");
  });

  it("returns the compile errors for a file that doesn't build", () => {
    const r = audit("model User {\n  name: String\n}\n", "bad.rz");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.diagnostics[0]?.code).toBe("RZ0301");
  });
});

describe("the audit command", () => {
  const withFile = (source: string, argv: string[]) => {
    const dir = mkdtempSync(join(tmpdir(), "rizolang-audit-"));
    let out = "";
    let err = "";
    try {
      writeFileSync(join(dir, "app.rz"), source);
      const code = run(argv, { cwd: dir, stdout: (s) => (out += s), stderr: (s) => (err += s) });
      return { code, out, err, files: readFileSync(join(dir, "app.rz"), "utf8") === source };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  it("prints findings like compiler errors, exits 1 on warnings, and writes nothing", () => {
    const r = withFile(RISKY, ["audit", "app.rz"]);
    expect(r.code).toBe(1);
    expect(r.out).toContain("app.rz:21:5 warning RA01:");
    expect(r.out).toContain("  21 | api POST /api/tags -> Tag.public {");
    expect(r.out).toContain("app.rz:7:3 note RA03:");
    expect(r.out).toContain("Audited app.rz: 3 endpoints (2 public, 1 need a login, 0 with roles). 6 warnings and 2 notes.");
    expect(r.err).toBe("");
  });

  it("exits 0 when there are only notes", () => {
    const r = withFile("model Note {\n  title: Text\n  phone: Text private\n}\napi GET /api/notes -> list Note.public {\n  public\n  return db.Note.list()\n}\n", ["audit", "app.rz"]);
    expect(r.code).toBe(0);
    expect(r.out).toContain("0 warnings and 1 note.");
  });

  it("prints one JSON object with --json", () => {
    const r = withFile(RISKY, ["audit", "app.rz", "--json"]);
    expect(r.code).toBe(1);
    const doc = JSON.parse(r.out) as { ok: boolean; findings: Record<string, unknown>[]; summary: Record<string, number> };
    expect(doc.ok).toBe(false);
    expect(doc.findings[0]).toEqual({ level: "warning", code: "RA04", message: expect.any(String), fix: expect.any(String), file: "app.rz", line: 4, column: 3, length: 5 });
    expect(doc.summary).toMatchObject({ warnings: 6, notes: 2 });
  });

  it("refuses unknown options and files that don't build", () => {
    expect(withFile(RISKY, ["audit", "app.rz", "--allow-data-loss"]).err).toContain("The only option of audit is --json.");
    const bad = withFile("model User {\n  name: String\n}\n", ["audit", "app.rz"]);
    expect(bad.code).toBe(1);
    expect(bad.err).toContain("the audit needs a file that builds");
  });
});
