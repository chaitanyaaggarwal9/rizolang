/**
 * Rizo Lang runtime: uploaded files.
 *
 * - What a file is comes from its content (its first bytes), never from its
 *   name or the Content-Type a client sends. Only PNG, JPEG, WebP, GIF and PDF
 *   are recognised, so SVG, HTML and scripts can never be stored.
 * - Location (GPS) data is removed from photos before they are stored.
 * - Files are stored under a random name: on local disk (RIZO_UPLOAD_DIR), or
 *   in S3-compatible storage (RIZO_S3_BUCKET and friends), signed with AWS
 *   Signature V4 using node:crypto only. They are always served through the app.
 */
import { createHash, createHmac } from "node:crypto";
import { createReadStream } from "node:fs";
import { mkdir, rm, stat, writeFile } from "node:fs/promises";
import { Readable } from "node:stream";
import { join, resolve } from "node:path";
import { crc32 } from "node:zlib";

export const FILES_TABLE = '"_rizo_files"';

/** The SQL for tracking uploads. Values are always parameters. */
export const FILE_SQL = {
  insert: `INSERT INTO ${FILES_TABLE} ("id", "user_id", "field", "type", "size") VALUES ($1, $2, $3, $4, $5)`,
  /** Is $1 a file that $3 uploaded for field $2? */
  owned: `SELECT 1 FROM ${FILES_TABLE} WHERE "id" = $1 AND "field" = $2 AND "user_id" = $3`,
  find: `SELECT "type" FROM ${FILES_TABLE} WHERE "id" = $1`,
  /** A file whose stored copy couldn't be deleted: tracked again, for no field, so the next sweep retries. */
  retry: `INSERT INTO ${FILES_TABLE} ("id", "user_id", "field", "type", "size", "created_at") VALUES ($1, NULL, $3, $2, 0, now() - make_interval(days => 1)) ON CONFLICT ("id") DO NOTHING`,
} as const;

/** A stored file's name: 128 random bits as hex, and the extension of its real type. */
export const FILE_NAME = /^[0-9a-f]{32}\.(png|jpg|webp|gif|pdf)$/;

export const FILE_TYPES: Readonly<Record<string, string>> = {
  png: "image/png", jpg: "image/jpeg", webp: "image/webp", gif: "image/gif", pdf: "application/pdf",
};

/** The type of a file from its first bytes, or undefined if it is none of the allowed ones. */
export function detectFile(b: Buffer): { ext: string; type: string } | undefined {
  const starts = (sig: readonly number[], at = 0): boolean => sig.every((x, i) => b[at + i] === x);
  const ascii = (at: number, text: string): boolean => b.length >= at + text.length && b.toString("latin1", at, at + text.length) === text;
  let ext: string | undefined;
  if (starts([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) && ascii(12, "IHDR")) ext = "png";
  else if (starts([0xff, 0xd8, 0xff])) ext = "jpg";
  else if (ascii(0, "GIF87a") || ascii(0, "GIF89a")) ext = "gif";
  else if (ascii(0, "RIFF") && ascii(8, "WEBP")) ext = "webp";
  else if (ascii(0, "%PDF-")) ext = "pdf";
  return ext === undefined ? undefined : { ext, type: FILE_TYPES[ext] ?? "application/octet-stream" };
}

// ------------------------------------------------------------ location data

/** Bytes per value of each TIFF field type (BYTE, ASCII, SHORT, LONG, RATIONAL, ...). */
const TIFF_SIZES: Readonly<Record<number, number>> = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8, 11: 4, 12: 8 };

/**
 * Empty the GPS part of an EXIF (TIFF) block in place: every GPS value is
 * zeroed and the GPS directory is left with no entries. The rest (such as the
 * photo's orientation) is kept. A block that can't be read is zeroed whole.
 */
export function scrubExif(t: Buffer): void {
  const block = t.length >= 6 && t.toString("latin1", 0, 6) === "Exif\0\0" ? t.subarray(6) : t;
  const order = block.toString("latin1", 0, 2);
  if (order !== "II" && order !== "MM") {
    block.fill(0);
    return;
  }
  const le = order === "II";
  const u16 = (at: number): number => (at >= 0 && at + 2 <= block.length ? (le ? block.readUInt16LE(at) : block.readUInt16BE(at)) : -1);
  const u32 = (at: number): number => (at >= 0 && at + 4 <= block.length ? (le ? block.readUInt32LE(at) : block.readUInt32BE(at)) : -1);
  const ifd0 = u32(4);
  const count = u16(ifd0);
  if (ifd0 < 8 || count < 0 || ifd0 + 2 + count * 12 > block.length) {
    block.fill(0);
    return;
  }
  let gps = -1;
  for (let k = 0; k < count; k++) if (u16(ifd0 + 2 + k * 12) === 0x8825) gps = u32(ifd0 + 2 + k * 12 + 8);
  if (gps === -1) return;
  const entries = u16(gps);
  if (gps < 8 || entries < 0 || gps + 2 + entries * 12 > block.length) {
    block.fill(0);
    return;
  }
  for (let j = 0; j < entries; j++) {
    const e = gps + 2 + j * 12;
    const size = (TIFF_SIZES[u16(e + 2)] ?? 1) * Math.max(0, u32(e + 4));
    const at = u32(e + 8);
    if (size > 4 && at >= 0 && at + size <= block.length) block.fill(0, at, at + size);
    block.fill(0, e, e + 12);
  }
  if (le) block.writeUInt16LE(0, gps);
  else block.writeUInt16BE(0, gps);
}

const XMP_JPEG = ["http://ns.adobe.com/xap/1.0/\0", "http://ns.adobe.com/xmp/extension/\0"];

/**
 * A copy of the file without location data: GPS is removed from EXIF, and
 * XMP metadata (which can repeat it) is blanked. Pixels are never touched,
 * and the file keeps its size and structure.
 */
export function removeLocation(input: Buffer, ext: string): Buffer {
  const b = Buffer.from(input);
  if (ext === "jpg") {
    let i = 2;
    while (i + 4 <= b.length && b[i] === 0xff) {
      const marker = b[i + 1] ?? 0;
      if (marker === 0xff) { i++; continue; }
      if (marker === 0xda || marker === 0xd9) break; // image data starts: no more metadata
      if ((marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { i += 2; continue; }
      const end = i + 2 + b.readUInt16BE(i + 2);
      if (end > b.length) break;
      if (marker === 0xe1) {
        const data = b.subarray(i + 4, end);
        if (data.toString("latin1", 0, 6) === "Exif\0\0") scrubExif(data);
        const xmp = XMP_JPEG.find((ns) => data.toString("latin1", 0, ns.length) === ns);
        if (xmp !== undefined) data.fill(0x20, xmp.length);
      }
      i = end;
    }
    // Phones may append more images (MPF, gain maps) after the first, each with its own metadata.
    for (const ns of ["Exif\0\0", ...XMP_JPEG]) {
      for (let k = b.indexOf(ns, i, "latin1"); k !== -1; k = b.indexOf(ns, k + 1, "latin1")) {
        if (k < 4 || b[k - 4] !== 0xff || b[k - 3] !== 0xe1) continue;
        const end = Math.min(b.length, k - 2 + b.readUInt16BE(k - 2));
        const data = b.subarray(k, end);
        if (ns.startsWith("Exif")) scrubExif(data);
        else data.fill(0x20, ns.length);
      }
    }
  } else if (ext === "png") {
    let i = 8;
    while (i + 12 <= b.length) {
      const length = b.readUInt32BE(i);
      const type = b.toString("latin1", i + 4, i + 8);
      const end = i + 8 + length;
      if (end + 4 > b.length || type === "IEND") break;
      // XMP, and EXIF or XMP that some tools store as text ("Raw profile type exif").
      const keyword = b.toString("latin1", i + 8, Math.min(end, i + 8 + 80)).split("\0")[0] ?? "";
      const isMetadata = ["tEXt", "zTXt", "iTXt"].includes(type) && (keyword === "XML:com.adobe.xmp" || keyword.startsWith("Raw profile type"));
      if (type === "eXIf" || isMetadata) {
        // Turn it into a private chunk that every decoder skips, with no content.
        b.write("rzMt", i + 4, "latin1");
        b.fill(0, i + 8, end);
        b.writeUInt32BE(crc32(b.subarray(i + 4, end)) >>> 0, end);
      }
      i = end + 4;
    }
  } else if (ext === "webp") {
    let i = 12;
    while (i + 8 <= b.length) {
      const type = b.toString("latin1", i, i + 4);
      const length = b.readUInt32LE(i + 4);
      const end = i + 8 + length;
      if (end > b.length) break;
      if (type === "EXIF") scrubExif(b.subarray(i + 8, end));
      if (type === "XMP ") b.fill(0x20, i + 8, end);
      i = end + (length % 2);
    }
  }
  return b;
}

// ------------------------------------------------------------------ storage

export class StorageError extends Error {}

export interface FileStore {
  /** "local" or "S3-compatible storage", for messages. */
  readonly kind: string;
  put(name: string, body: Buffer, type: string): Promise<void>;
  /** The file as a stream (never read whole into memory), or undefined if it doesn't exist. */
  open(name: string): Promise<{ readonly stream: Readable; readonly size: number } | undefined>;
  remove(name: string): Promise<void>;
}

function checkName(name: string): void {
  if (!FILE_NAME.test(name)) throw new StorageError("invalid file name");
}

/** Files in one folder, readable only by the server's own user. */
export function localStore(dir: string): FileStore {
  const root = resolve(dir);
  return {
    kind: "local",
    async put(name, body) {
      checkName(name);
      await mkdir(root, { recursive: true, mode: 0o700 });
      await writeFile(join(root, name), body, { flag: "wx", mode: 0o600 });
    },
    async open(name) {
      checkName(name);
      const path = join(root, name);
      try {
        const { size } = await stat(path);
        return { stream: createReadStream(path), size };
      } catch (e) {
        if ((e as { code?: string }).code === "ENOENT") return undefined;
        throw e;
      }
    },
    async remove(name) {
      checkName(name);
      await rm(join(root, name), { force: true });
    },
  };
}

export interface S3Config {
  /** e.g. https://s3.eu-west-1.amazonaws.com or https://<account>.r2.cloudflarestorage.com */
  readonly endpoint: string;
  readonly bucket: string;
  readonly region: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
}

const sha256 = (data: string | Buffer): string => createHash("sha256").update(data).digest("hex");
const hmac = (key: string | Buffer, data: string): Buffer => createHmac("sha256", key).update(data).digest();

/** RFC 3986 encoding, as Signature V4 needs it. */
const uriEncode = (s: string): string => encodeURIComponent(s).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);

/**
 * AWS Signature Version 4 for one request. `headers` must include host,
 * x-amz-date and x-amz-content-sha256. Returns the Authorization header.
 */
export function signV4(req: {
  readonly method: string;
  readonly path: string;
  readonly query?: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly payloadHash: string;
  readonly region: string;
  readonly service: string;
  readonly accessKeyId: string;
  readonly secretAccessKey: string;
}): string {
  const amzDate = req.headers["x-amz-date"] ?? "";
  const day = amzDate.slice(0, 8);
  const names = Object.keys(req.headers).map((h) => h.toLowerCase()).sort();
  const canonicalHeaders = names.map((h) => `${h}:${String(req.headers[h]).trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalPath = req.path.split("/").map((s) => uriEncode(decodeURIComponent(s))).join("/");
  const canonical = [req.method, canonicalPath, req.query ?? "", canonicalHeaders, signedHeaders, req.payloadHash].join("\n");
  const scope = `${day}/${req.region}/${req.service}/aws4_request`;
  const toSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n");
  const key = hmac(hmac(hmac(hmac(`AWS4${req.secretAccessKey}`, day), req.region), req.service), "aws4_request");
  const signature = createHmac("sha256", key).update(toSign).digest("hex");
  return `AWS4-HMAC-SHA256 Credential=${req.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

/** Files in an S3-compatible bucket (path-style addresses), which stays private: the app serves them. */
export function s3Store(config: S3Config, fetcher: typeof fetch = fetch, now: () => number = Date.now): FileStore {
  const base = new URL(config.endpoint);
  const request = async (method: string, name: string, body?: Buffer, type?: string): Promise<Response> => {
    checkName(name);
    const url = new URL(`${base.pathname.replace(/\/$/, "")}/${uriEncode(config.bucket)}/${name}`, base);
    const amzDate = new Date(now()).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
    const payloadHash = sha256(body ?? "");
    const headers: Record<string, string> = { host: url.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash };
    if (type !== undefined) headers["content-type"] = type;
    const authorization = signV4({ method, path: url.pathname, headers, payloadHash, region: config.region, service: "s3", accessKeyId: config.accessKeyId, secretAccessKey: config.secretAccessKey });
    const { host: _host, ...sent } = headers;
    try {
      // A plain Uint8Array copy: a valid fetch body under every TypeScript lib setting.
      return await fetcher(url, { method, headers: { ...sent, authorization }, ...(body !== undefined ? { body: new Uint8Array(body) } : {}), signal: AbortSignal.timeout(15_000) });
    } catch {
      throw new StorageError(`${method} to file storage failed`);
    }
  };
  return {
    kind: "S3-compatible storage",
    async put(name, body, type) {
      const r = await request("PUT", name, body, type);
      if (!r.ok) throw new StorageError(`file storage answered ${r.status} to PUT`);
    },
    async open(name) {
      const r = await request("GET", name);
      if (r.status === 404) return undefined;
      if (!r.ok || r.body === null) throw new StorageError(`file storage answered ${r.status} to GET`);
      const size = Number(r.headers.get("content-length") ?? "-1");
      return { stream: Readable.fromWeb(r.body as import("node:stream/web").ReadableStream), size };
    },
    async remove(name) {
      const r = await request("DELETE", name);
      if (!r.ok && r.status !== 404) throw new StorageError(`file storage answered ${r.status} to DELETE`);
    },
  };
}

/**
 * The store from the environment: S3-compatible storage when RIZO_S3_BUCKET
 * is set (then the other RIZO_S3_* variables are required), otherwise the
 * folder RIZO_UPLOAD_DIR (default ./uploads).
 */
export function fileStoreFromEnv(env: Readonly<Record<string, string | undefined>>): { store: FileStore } | { error: string } {
  const bucket = env["RIZO_S3_BUCKET"]?.trim() ?? "";
  if (bucket === "") return { store: localStore(env["RIZO_UPLOAD_DIR"]?.trim() || "./uploads") };
  const region = env["RIZO_S3_REGION"]?.trim() ?? "";
  const accessKeyId = env["RIZO_S3_ACCESS_KEY_ID"]?.trim() ?? "";
  const secretAccessKey = env["RIZO_S3_SECRET_ACCESS_KEY"]?.trim() ?? "";
  const endpoint = env["RIZO_S3_ENDPOINT"]?.trim() || (region !== "" ? `https://s3.${region}.amazonaws.com` : "");
  const missing = [["RIZO_S3_REGION", region], ["RIZO_S3_ACCESS_KEY_ID", accessKeyId], ["RIZO_S3_SECRET_ACCESS_KEY", secretAccessKey]]
    .filter(([, v]) => v === "").map(([k]) => k);
  if (missing.length > 0) return { error: `RIZO_S3_BUCKET is set, but ${missing.join(", ")} ${missing.length > 1 ? "are" : "is"} not.` };
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return { error: "RIZO_S3_ENDPOINT is not a valid URL, such as https://s3.eu-west-1.amazonaws.com." };
  }
  if (url.protocol !== "https:" && !["localhost", "127.0.0.1", "[::1]"].includes(url.hostname)) {
    return { error: "RIZO_S3_ENDPOINT must use https (http is allowed only for localhost)." };
  }
  return { store: s3Store({ endpoint: url.toString(), bucket, region, accessKeyId, secretAccessKey }) };
}
