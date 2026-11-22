import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { deflateSync } from "node:zlib";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { asset, renderMessage, renderPage } from "../runtime/pages.ts";
import { run } from "../src/cli.js";
import { buildApp } from "../src/emit/routes.js";
import { compileErrors, compileOk, firstError } from "./helpers.js";

const APP = (site: string) => `${site}
model Note {
  title: Text
}
api GET /api/notes -> list Note.public {
  public
  return db.Note.list()
}
page / {
  public
  title "Notes"
  show GET /api/notes
}
`;

/** A real 1x1 PNG. */
function png(): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    return Buffer.concat([len, Buffer.from(type), data, Buffer.alloc(4)]);
  };
  const ihdr = Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0]);
  return Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), chunk("IHDR", ihdr), chunk("IDAT", deflateSync(Buffer.from([0, 0, 0, 0]))), chunk("IEND", Buffer.alloc(0))]);
}

describe("the site line", () => {
  it("sets the name, color and logo", () => {
    const r = compileOk(APP('site "Rizo Notes" color teal logo "brand/logo.png"'));
    expect(r.site).toEqual({ name: "Rizo Notes", color: "teal", logo: "brand/logo.png" });
    expect(buildApp(r.apis, r.auth, r.pages, r.models, r.privacy, r.site).site).toEqual({ name: "Rizo Notes", color: "teal", logo: "/_rizo/logo.png" });
    expect(compileOk(APP('site "Plain"')).site).toEqual({ name: "Plain", color: "blue", logo: undefined });
    expect(compileOk(APP("")).site).toBeUndefined();
  });

  it.each([
    ["two site lines", 'site "A"\nsite "B"', "Only one site line"],
    ["an unknown color", 'site "A" color neon', "blue, teal, green, purple, pink, red, orange, gray"],
    ["an empty name", 'site "  "', "1 to 60 characters"],
    ["an SVG logo", 'site "A" logo "logo.svg"', "SVG files can contain scripts"],
    ["a logo outside the folder", 'site "A" logo "../secret.png"', "same folder"],
    ["an absolute logo path", 'site "A" logo "/etc/logo.png"', "same folder"],
    ["a logo that isn't an image", 'site "A" logo "logo.txt"', "same folder"],
  ])("refuses %s (RZ0344), with a fix", (_label, line, text) => {
    const e = compileErrors(APP(line)).find((d) => d.code === "RZ0344");
    expect(`${e?.message} ${e?.fix}`).toContain(text);
  });

  it("reports a malformed line (RZ0223) and a missing name (RZ0221)", () => {
    expect(firstError(APP('site "A" colour teal')).code).toBe("RZ0223");
    expect(firstError(APP("site Notes")).code).toBe("RZ0221");
  });
});

describe("branded pages", () => {
  const page = { pattern: "/", path: [], access: "public", roles: [], title: "Notes", items: [] } as const;

  it("put the site name in the title and the color on <body>, and the brand in the page data", () => {
    const html = renderPage(page, {}, false, false, false, { name: "Rizo <Notes>", color: "teal", logo: "/_rizo/logo.png" });
    expect(html).toContain("<title>Notes · Rizo &lt;Notes&gt;</title>");
    expect(html).toContain('<body class="rizo-color-teal">');
    expect(html).toContain('"site":{"name":"Rizo \\u003cNotes\\u003e","logo":"/_rizo/logo.png"}');
    expect(renderMessage("Page not found", "x", { name: "Rizo", color: "red" })).toContain('<body class="rizo-color-red">');
  });

  it("are unchanged without a site line, and ignore a color that isn't in the palette", () => {
    expect(renderPage(page, {}, false, false)).toContain("<title>Notes</title>\n");
    expect(renderPage(page, {}, false, false)).toContain("<body>");
    expect(renderPage(page, {}, false, false, false, { name: "X", color: "evil\" onload=\"x" })).toContain("<body>");
  });
});

describe("building with a logo", () => {
  let dir: string;
  let out: string;
  let err: string;
  const cli = (...argv: string[]) => run(argv, { cwd: dir, stdout: (s) => (out += s), stderr: (s) => (err += s) });

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "rizolang-site-"));
    out = "";
    err = "";
    writeFileSync(join(dir, "app.rz"), APP('site "Rizo Notes" color teal logo "logo.png"'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it("copies a real image to dist/, where the server serves it", () => {
    writeFileSync(join(dir, "logo.png"), png());
    expect(cli("build", "app.rz")).toBe(0);
    expect(readFileSync(join(dir, "dist", "runtime", "client", "logo.png"))).toEqual(png());
  });

  it.each([
    ["a missing file", null, "Cannot read the logo file"],
    ["a file that isn't really a PNG", Buffer.from("<svg onload=alert(1)>"), "isn't a real PNG, JPEG or WebP"],
    ["a file over 256 KB", Buffer.concat([png(), Buffer.alloc(300 * 1024)]), "at most 256 KB"],
  ])("refuses %s (RZ0908) and writes nothing", (_label, bytes, message) => {
    if (bytes !== null) writeFileSync(join(dir, "logo.png"), bytes);
    expect(cli("build", "app.rz")).toBe(1);
    expect(err).toContain("RZ0908");
    expect(err).toContain(message);
    expect(existsSync(join(dir, "dist"))).toBe(false);
  });
});

describe("serving the logo", () => {
  it("serves only the fixed logo names, and nothing when there is no logo", () => {
    expect(asset("/_rizo/logo.gif")).toBeUndefined();
    expect(asset("/_rizo/../package.json")).toBeUndefined();
    // The source runtime has no logo file, as in an app without one.
    expect(asset("/_rizo/logo.png")).toBeUndefined();
  });
});
