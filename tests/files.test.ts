/**
 * File uploads (Milestone 10, part 4): the File type in the compiler, and the
 * runtime's file handling (type detection, location removal, storage, request
 * signing, cleanup). Uploading and serving over HTTP against PostgreSQL is in
 * tests/e2e.test.ts ("file uploads").
 */
import { mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { crc32 } from "node:zlib";
import { describe, expect, it } from "vitest";
import { type FileStore, detectFile, fileStoreFromEnv, localStore, removeLocation, s3Store, scrubExif, signV4 } from "../runtime/files.ts";

/** A stored file read whole, or undefined. */
async function read(store: FileStore, name: string): Promise<Buffer | undefined> {
  const f = await store.open(name);
  return f === undefined ? undefined : Buffer.concat(await f.stream.toArray());
}
import { sweepFiles } from "../runtime/server.ts";
import { buildSchema } from "../src/schema.js";
import { planMigration } from "../src/migrations.js";
import { buildApp } from "../src/emit/routes.js";
import { compileErrors, compileOk } from "./helpers.js";

// ------------------------------------------------------------ sample files

/** A TIFF (EXIF) block: orientation 6, and a GPS directory with a latitude of 51/1, 30/1, 1234/100. */
function exifBlock(le: boolean): Buffer {
  const b = Buffer.alloc(120);
  const w16 = (v: number, at: number) => (le ? b.writeUInt16LE(v, at) : b.writeUInt16BE(v, at));
  const w32 = (v: number, at: number) => (le ? b.writeUInt32LE(v, at) : b.writeUInt32BE(v, at));
  b.write(le ? "II" : "MM", 0, "latin1");
  w16(42, 2);
  w32(8, 4); // IFD0 at 8
  w16(2, 8); // two entries
  w16(0x0112, 10); w16(3, 12); w32(1, 14); w16(6, 18); // Orientation = 6
  w16(0x8825, 22); w16(4, 24); w32(1, 26); w32(38, 30); // GPS IFD at 38
  w32(0, 34); // no next IFD
  w16(2, 38); // two GPS entries
  w16(0x0001, 40); w16(2, 42); w32(2, 44); b.write("N\0", 48, "latin1"); // GPSLatitudeRef "N"
  w16(0x0002, 52); w16(5, 54); w32(3, 56); w32(68, 60); // GPSLatitude, 3 rationals at 68
  w32(0, 64);
  [51, 1, 30, 1, 1234, 100].forEach((v, i) => w32(v, 68 + i * 4));
  return b;
}

function latitudeLeft(b: Buffer): boolean {
  // 1234 as a 32-bit number, in either byte order.
  return b.includes(Buffer.from([0x00, 0x00, 0x04, 0xd2])) || b.includes(Buffer.from([0xd2, 0x04, 0x00, 0x00]));
}

function jpegWithGps(le = false): Buffer {
  const exif = Buffer.concat([Buffer.from("Exif\0\0", "latin1"), exifBlock(le)]);
  const app1 = Buffer.alloc(4);
  app1.writeUInt16BE(0xffe1, 0);
  app1.writeUInt16BE(exif.length + 2, 2);
  const xmpBody = Buffer.from("http://ns.adobe.com/xap/1.0/\0<x:xmpmeta><exif:GPSLatitude>51,30.2N</exif:GPSLatitude></x:xmpmeta>", "latin1");
  const xmp = Buffer.alloc(4);
  xmp.writeUInt16BE(0xffe1, 0);
  xmp.writeUInt16BE(xmpBody.length + 2, 2);
  return Buffer.concat([Buffer.from([0xff, 0xd8]), app1, exif, xmp, xmpBody, Buffer.from([0xff, 0xda, 0x00, 0x02, 0x11, 0x22, 0xff, 0xd9])]);
}

function pngChunk(type: string, data: Buffer): Buffer {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);
  head.write(type, 4, "latin1");
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([head.subarray(4), data])) >>> 0, 0);
  return Buffer.concat([head, data, crc]);
}

function pngWithGps(): Buffer {
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk("IHDR", Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0])),
    pngChunk("eXIf", exifBlock(false)),
    pngChunk("IDAT", Buffer.from([0x78, 0x9c, 0x63, 0x60, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01])),
    pngChunk("IEND", Buffer.alloc(0)),
  ]);
}

function webpWithGps(): Buffer {
  const chunk = (type: string, data: Buffer) => {
    const head = Buffer.alloc(8);
    head.write(type, 0, "latin1");
    head.writeUInt32LE(data.length, 4);
    return Buffer.concat([head, data, data.length % 2 === 1 ? Buffer.alloc(1) : Buffer.alloc(0)]);
  };
  const body = Buffer.concat([chunk("VP8X", Buffer.alloc(10)), chunk("EXIF", exifBlock(true)), chunk("XMP ", Buffer.from("<x>GPS 51N</x>", "latin1"))]);
  const head = Buffer.alloc(12);
  head.write("RIFF", 0, "latin1");
  head.writeUInt32LE(body.length + 4, 4);
  head.write("WEBP", 8, "latin1");
  return Buffer.concat([head, body]);
}

// ---------------------------------------------------------------- the type

describe("File fields: compiling", () => {
  const app = (fields: string, api = "") => `auth User by email
model User {
  email: Email unique
  password: Password
}
model Post {
  author: User
${fields}
}
api POST /api/posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}
${api}`;

  it("accepts image, pdf and size limits, defaulting to both kinds and 10 MB", () => {
    const r = compileOk(app("  photo: File image max 2mb\n  receipt: File pdf max 500kb optional\n  any: File optional"));
    const post = r.models.find((m) => m.name === "Post");
    expect(post?.fields.map((f) => [f.name, f.accept, f.max])).toEqual([
      ["author", undefined, undefined],
      ["photo", ["png", "jpg", "webp", "gif"], 2 * 1024 * 1024],
      ["receipt", ["pdf"], 500 * 1024],
      ["any", ["png", "jpg", "webp", "gif", "pdf"], 10 * 1024 * 1024],
    ]);
  });

  it.each([
    ["  photo: File max 5", "RZ0345", "needs a unit"],
    ["  photo: File max 11mb", "RZ0345", "from 1kb to 10mb"],
    ["  photo: File max 0kb", "RZ0345", "from 1kb to 10mb"],
    ["  title: Text max 5mb", "RZ0345", "only for File fields"],
    ["  photo: File unique", "RZ0302", "unique"],
    ["  photo: File encrypted", "RZ0302", "encrypted"],
    ["  photo: File min 1kb", "RZ0302", "min"],
    ["  title: Text image", "RZ0302", "image"],
  ])("refuses %j (%s)", (fields, code, text) => {
    const errors = compileErrors(app(fields));
    expect(errors[0]).toMatchObject({ code, message: expect.stringContaining(text) });
  });

  it("refuses File fields in filters and order", () => {
    const list = (q: string) => app("  photo: File optional\n  title: Text", `api GET /api/posts -> list Post.public {\n  public\n  return db.Post.list(${q})\n}`);
    expect(compileErrors(list("order photo"))[0]?.message).toContain("Cannot order by File field");
    expect(compileErrors(list("photo = ?p"))[0]?.message).toContain("Cannot filter by File field");
  });

  it("needs a login: no File fields without an auth line, on a public endpoint body, or required on the account", () => {
    expect(compileErrors("model Post {\n  photo: File\n}")[0]).toMatchObject({ code: "RZ0346", message: expect.stringContaining("needs an auth line") });
    const open = app("  photo: File").replace("requires login\n  return db.Post.create(body, author = me)", "public\n  return db.Post.create(body)").replace("  author: User\n", "");
    expect(compileErrors(open)[0]).toMatchObject({ code: "RZ0346", message: expect.stringContaining("public") });
    const account = "auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  avatar: File image\n}";
    expect(compileErrors(account)[0]).toMatchObject({ code: "RZ0346", fix: expect.stringContaining("avatar: File image optional") });
  });

  it("stores the address in a checked column that links to _rizo_files", () => {
    const r = compileOk(app("  photo: File image"));
    expect(r.output.sql).toContain(`"photo" TEXT NOT NULL CONSTRAINT "posts_photo_check" CHECK ("photo" ~ '^/_rizo/files/[0-9a-f]{32}[.](png|jpg|webp|gif)$')`);
    expect(r.output.sql).toContain('FOREIGN KEY ("photo") REFERENCES "_rizo_files" ("id") ON DELETE RESTRICT');
    expect(r.output.sql).toContain('FOREIGN KEY ("user_id") REFERENCES "users" ("id") ON DELETE SET NULL');
  });

  it("treats changing a field to or from File as a type change that loses data", () => {
    const before = compileOk(app("  photo: Text"));
    const after = compileOk(app("  photo: File"));
    const plan = planMigration(buildSchema(before.models, before.auth, true), buildSchema(after.models, after.auth, true));
    expect(plan.dataLoss.join(" ")).toContain("changes type from TEXT to File");
    const added = planMigration(buildSchema(before.models, before.auth, true), buildSchema(compileOk(app("  photo: Text\n  image: File optional")).models, after.auth, true));
    expect(added.dataLoss).toEqual([]);
    expect(added.statements.join("\n")).toContain('CREATE TABLE "_rizo_files"');
  });

  it("lists upload addresses with who may upload, and leaves File fields out of signup", () => {
    const source = `auth User by email roles admin, editor
model User {
  email: Email unique
  password: Password
  avatar: File image optional
}
model Post {
  author: User
  cover: File image
  scan: File pdf optional
}
api POST /api/posts -> Post.public {
  requires login
  requires role editor
  return db.Post.create(body, author = me)
}`;
    const r = compileOk(source);
    const built = buildApp(r.apis, r.auth, r.pages, r.models);
    expect(built.files?.uploads.map((u) => [u.path, u.field, u.roles, u.endpoints])).toEqual([
      ["users/avatar", "users.avatar", [], []],
      ["posts/cover", "posts.cover", ["editor"], ["POST /api/posts"]],
      ["posts/scan", "posts.scan", ["editor"], ["POST /api/posts"]],
    ]);
    expect(built.auth?.signup.body.map((f) => f.key)).toEqual(["email", "password"]);
    expect(built.auth?.account.profile?.files).toEqual([{ key: "avatar", field: "users.avatar", current: { sql: 'SELECT 1 FROM "users" WHERE "id" = $1 AND "avatar" = $2', id: { from: "me" } } }]);
    expect(built.files?.sweepSql).toContain(`NOT EXISTS (SELECT 1 FROM "users" WHERE "users"."avatar" = "f"."id") AND NOT EXISTS (SELECT 1 FROM "posts" WHERE "posts"."cover" = "f"."id") AND NOT EXISTS (SELECT 1 FROM "posts" WHERE "posts"."scan" = "f"."id")`);
  });

  it("describes uploads in openapi.json", () => {
    const r = compileOk(app("  photo: File image max 2mb"));
    const doc = JSON.parse(r.output.server?.openapi ?? "{}") as { paths: Record<string, Record<string, { requestBody?: { content: object }; responses?: object }>> };
    const upload = doc.paths["/_rizo/uploads/posts/photo"]?.["post"];
    expect(Object.keys(upload?.requestBody?.content ?? {})).toEqual(["image/png", "image/jpeg", "image/webp", "image/gif"]);
    expect(Object.keys(upload?.responses ?? {})).toEqual(expect.arrayContaining(["201", "413", "415"]));
  });
});

// ------------------------------------------------------------ the runtime

describe("File fields: content and location data", () => {
  it("recognises files only by their content", () => {
    expect(detectFile(pngWithGps())).toEqual({ ext: "png", type: "image/png" });
    expect(detectFile(jpegWithGps())).toEqual({ ext: "jpg", type: "image/jpeg" });
    expect(detectFile(webpWithGps())).toEqual({ ext: "webp", type: "image/webp" });
    expect(detectFile(Buffer.from("GIF89a\x01\x00\x01\x00", "latin1"))?.ext).toBe("gif");
    expect(detectFile(Buffer.from("%PDF-1.7\n", "latin1"))?.ext).toBe("pdf");
    for (const bad of ['<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', "<!doctype html><script>alert(1)</script>", "", "RIFF....WAVE", "\x89PNG\r\n\x1a\n"]) {
      expect(detectFile(Buffer.from(bad, "latin1"))).toBeUndefined();
    }
  });

  it("removes GPS from JPEG EXIF and blanks XMP, keeping the orientation and the size", () => {
    for (const le of [false, true]) {
      const before = jpegWithGps(le);
      expect(latitudeLeft(before)).toBe(true);
      const after = removeLocation(before, "jpg");
      expect(after.length).toBe(before.length);
      expect(latitudeLeft(after)).toBe(false);
      expect(after.toString("latin1")).not.toContain("GPSLatitude");
      // Orientation (tag 0x0112, value 6) is still there.
      expect(after.includes(le ? Buffer.from([0x12, 0x01, 0x03, 0x00]) : Buffer.from([0x01, 0x12, 0x00, 0x03]))).toBe(true);
      expect(after.subarray(after.length - 8)).toEqual(before.subarray(before.length - 8)); // image data untouched
      expect(before).toEqual(jpegWithGps(le)); // the input is not changed
    }
  });

  it("neutralises PNG eXIf chunks with a valid checksum, and scrubs WebP EXIF and XMP", () => {
    const png = removeLocation(pngWithGps(), "png");
    expect(latitudeLeft(png)).toBe(false);
    expect(png.toString("latin1")).not.toContain("eXIf");
    const at = png.indexOf("rzMt", 0, "latin1");
    const length = png.readUInt32BE(at - 4);
    expect(png.readUInt32BE(at + 4 + length)).toBe(crc32(png.subarray(at, at + 4 + length)) >>> 0);
    const webp = removeLocation(webpWithGps(), "webp");
    expect(latitudeLeft(webp)).toBe(false);
    expect(webp.toString("latin1")).not.toContain("GPS 51N");
  });

  it("never throws on a tiny or hostile EXIF block", () => {
    for (const tiff of ["II*\0", "MM", "II*\0\xff\xff\xff\xff", "Exif\0\0II", ""]) expect(() => scrubExif(Buffer.from(tiff, "latin1"))).not.toThrow();
    const tiny = Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x0c, ...Buffer.from("Exif\0\0II*\0", "latin1"), 0xff, 0xd9]);
    expect(() => removeLocation(tiny, "jpg")).not.toThrow();
    for (let n = 0; n < 2000; n++) {
      const junk = Buffer.from(Array.from({ length: 4 + (n % 60) }, (_, i) => (n * 31 + i * 17) & 0xff));
      junk.write(n % 2 === 0 ? "II" : "MM", 0, "latin1");
      expect(() => scrubExif(junk)).not.toThrow();
    }
  });

  it("also cleans images appended after the first (MPF), and EXIF or XMP stored as PNG text", () => {
    const second = jpegWithGps(true);
    const both = removeLocation(Buffer.concat([jpegWithGps(false), second]), "jpg");
    expect(latitudeLeft(both)).toBe(false);
    const raw = Buffer.concat([
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      pngChunk("IHDR", Buffer.from([0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0])),
      pngChunk("tEXt", Buffer.from("Raw profile type exif\0GPSLatitude 51N", "latin1")),
      pngChunk("tEXt", Buffer.from("Comment\0kept", "latin1")),
      pngChunk("IEND", Buffer.alloc(0)),
    ]);
    const cleaned = removeLocation(raw, "png").toString("latin1");
    expect(cleaned).not.toContain("GPSLatitude");
    expect(cleaned).toContain("Comment\0kept");
  });

  it("zeroes an EXIF block it can't read, and survives truncated files", () => {
    const broken = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe1, 0x00, 0x10]), Buffer.from("Exif\0\0XX\0\0\0\0\0\0\0\0", "latin1"), Buffer.from([0xff, 0xd9])]);
    expect(removeLocation(broken, "jpg").subarray(12, 20)).toEqual(Buffer.alloc(8));
    for (const sample of [jpegWithGps(), pngWithGps(), webpWithGps()]) {
      for (let cut = 0; cut < sample.length; cut += 7) {
        expect(() => removeLocation(sample.subarray(0, cut), detectFile(sample)?.ext ?? "")).not.toThrow();
      }
    }
  });
});

describe("File fields: storage", () => {
  it("signs S3 requests exactly as AWS's published Signature V4 example", () => {
    const empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const auth = signV4({
      method: "GET", path: "/test.txt", payloadHash: empty, region: "us-east-1", service: "s3",
      headers: { host: "examplebucket.s3.amazonaws.com", range: "bytes=0-9", "x-amz-content-sha256": empty, "x-amz-date": "20130524T000000Z" },
      accessKeyId: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    });
    expect(auth).toBe("AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
  });

  it("talks to S3-compatible storage with signed, path-style requests, and turns failures into StorageError", async () => {
    const calls: { url: string; method: string; headers: Record<string, string> }[] = [];
    let status = 200;
    const fake = (async (url: URL, init: RequestInit) => {
      calls.push({ url: String(url), method: String(init.method), headers: init.headers as Record<string, string> });
      return new Response(init.method === "GET" && status === 200 ? "data" : null, { status, headers: init.method === "GET" && status === 200 ? { "content-length": "4" } : {} });
    }) as unknown as typeof fetch;
    const store = s3Store({ endpoint: "https://r2.example.com", bucket: "my-files", region: "auto", accessKeyId: "AK", secretAccessKey: "SK" }, fake, () => Date.UTC(2026, 10, 22));
    const name = `${"a".repeat(32)}.png`;
    await store.put(name, Buffer.from("png"), "image/png");
    expect(calls[0]).toMatchObject({ url: `https://r2.example.com/my-files/${name}`, method: "PUT" });
    expect(calls[0]?.headers["x-amz-date"]).toBe("20261122T000000Z");
    expect(calls[0]?.headers["authorization"]).toMatch(/^AWS4-HMAC-SHA256 Credential=AK\/20261122\/auto\/s3\/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=[0-9a-f]{64}$/);
    expect((await read(store, name))?.toString()).toBe("data");
    status = 404;
    expect(await read(store, name)).toBeUndefined();
    await store.remove(name);
    status = 500;
    await expect(store.put(name, Buffer.from("x"), "image/png")).rejects.toThrow("file storage answered 500");
    await expect(store.open("../../etc/passwd")).rejects.toThrow("invalid file name");
  });

  it("keeps local files under their random name only, and never overwrites one", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rizo-files-"));
    const store = localStore(join(dir, "uploads"));
    const name = `${"b".repeat(32)}.pdf`;
    await store.put(name, Buffer.from("%PDF-1"), "application/pdf");
    await expect(store.put(name, Buffer.from("other"), "application/pdf")).rejects.toThrow();
    expect((await read(store, name))?.toString()).toBe("%PDF-1");
    expect(await read(store, `${"c".repeat(32)}.pdf`)).toBeUndefined();
    await expect(store.open("../secret.pdf")).rejects.toThrow("invalid file name");
    await store.remove(name);
    expect(readdirSync(join(dir, "uploads"))).toEqual([]);
  });

  it("chooses storage from the environment, with clear errors", () => {
    const local = fileStoreFromEnv({ RIZO_UPLOAD_DIR: "/tmp/x" });
    expect("store" in local ? local.store.kind : local.error).toBe("local");
    expect(fileStoreFromEnv({ RIZO_S3_BUCKET: "b" })).toEqual({ error: "RIZO_S3_BUCKET is set, but RIZO_S3_REGION, RIZO_S3_ACCESS_KEY_ID, RIZO_S3_SECRET_ACCESS_KEY are not." });
    const full = { RIZO_S3_BUCKET: "b", RIZO_S3_REGION: "eu-west-1", RIZO_S3_ACCESS_KEY_ID: "a", RIZO_S3_SECRET_ACCESS_KEY: "s" };
    expect("store" in fileStoreFromEnv(full)).toBe(true);
    expect(fileStoreFromEnv({ ...full, RIZO_S3_ENDPOINT: "http://minio.example.com" })).toEqual({ error: "RIZO_S3_ENDPOINT must use https (http is allowed only for localhost)." });
    expect("store" in fileStoreFromEnv({ ...full, RIZO_S3_ENDPOINT: "http://localhost:9000" })).toBe(true);
  });

  it("deletes swept files from storage, and tracks a file again when storage fails, so the next run retries", async () => {
    const r = compileOk("auth User by email\nmodel User {\n  email: Email unique\n  password: Password\n  avatar: File optional\n}");
    const app = buildApp(r.apis, r.auth, r.pages, r.models);
    const removed: string[] = [];
    const lines: string[] = [];
    const queries: { sql: string; values: unknown[] }[] = [];
    const names = [`${"d".repeat(32)}.png`, `${"e".repeat(32)}.pdf`];
    const db = {
      query: async (sql: string, values: unknown[]) => {
        queries.push({ sql, values });
        return sql.startsWith("DELETE") ? { rows: names.map((n) => ({ id: `/_rizo/files/${n}`, type: "image/png" })), rowCount: 2 } : { rows: [], rowCount: 1 };
      },
    };
    const store = {
      kind: "test", put: async () => undefined, open: async () => undefined,
      remove: async (n: string) => { removed.push(n); if (n.endsWith(".pdf")) throw new Error("down"); },
    };
    expect(await sweepFiles(app, db, store, (l) => lines.push(l))).toBe(2);
    expect(removed).toEqual(names);
    expect(lines).toEqual(["could not delete a file from test: down"]);
    expect(queries.filter((q) => q.sql.startsWith("INSERT")).map((q) => q.values)).toEqual([[`/_rizo/files/${names[1]}`, "image/png", ""]]);
  });

});
