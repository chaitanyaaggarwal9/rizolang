/**
 * Rizo Lang runtime: the HTTP server.
 *
 * Request flow: security headers -> route match -> origin check -> session ->
 * path parameters -> body validation -> password hashing -> parameterized
 * query -> response with public fields only -> one log line.
 *
 * Logs contain the method, the route pattern (not the concrete URL), the
 * status, the duration and a request id. Never bodies, cookies or values.
 */
import { randomBytes, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import type { Readable } from "node:stream";
import pg from "pg";
import { BusyError, hashPassword, dummyHash, verifyPassword } from "./password.ts";
import { Audit, DEFAULT_AUDIT_RETENTION_DAYS } from "./audit.ts";
import { type Keys, decryptValue, encryptValue, parseKeys } from "./encryption.ts";
import { CHANGE_SECONDS, EMAIL_SQL, type Mailer, MESSAGES, RESET_SECONDS, type TokenPurpose, VERIFY_SECONDS, emailConfig, emailTokenHash, newEmailToken, readEmailToken } from "./email.ts";
import { Limits, limitKey } from "./limits.ts";
import { CHALLENGE_SECONDS, MAX_PASSKEYS, PASSKEY_SQL, challengeHash, challengeOf, newChallenge } from "./passkeys.ts";
import { EXPORT_LIMIT, GHOST_SQL, expireRecords, ghostValues, privacyNotice } from "./privacy.ts";
import { MAX_TOKENS, MAX_TOKEN_DAYS, TOKEN_SQL, agentTokenHash, newAgentToken, parseEndpoints, readBearer } from "./tokens.ts";
import { PasskeyError, SUPPORTED_ALGORITHMS, verifyAssertion, verifyRegistration } from "./webauthn.ts";
import { IDLE_SECONDS, MAX_SECONDS, SQL, clearedCookie, deviceLabel, hashToken, newToken, readToken, sessionCookie } from "./session.ts";
import { PAGE_HEADERS, asset, renderMessage, renderPage } from "./pages.ts";
import { FILE_NAME, FILE_SQL, type FileStore, StorageError, detectFile, fileStoreFromEnv, removeLocation } from "./files.ts";
import type { AdminModel, App, EncryptedField, FieldKind, FileField, UploadSpec, FieldSpec, PageRoute, PathPart, Route, ValueSource } from "./types.ts";
import { validateBody, validatePathParam, validateQueryParam, validateValue } from "./validate.ts";

export interface QueryResult {
  readonly rows: readonly Record<string, unknown>[];
  readonly rowCount: number | null;
}

/** The database connection. In production this is a `pg.Pool`. */
export interface Db {
  query(sql: string, values: unknown[]): Promise<QueryResult>;
}

export interface ServerOptions {
  readonly db: Db;
  /** Where log lines go. Defaults to stdout. */
  readonly log?: (line: string) => void;
  /** Extra origins allowed to send state-changing requests, e.g. "https://app.example.com". */
  readonly allowedOrigins?: readonly string[];
  /** Mark the session cookie Secure. Only turn off for local development over http. */
  readonly secureCookies?: boolean;
  /** Use the first X-Forwarded-For address as the client IP (only behind a trusted proxy). */
  readonly trustProxy?: boolean;
  readonly now?: () => number;
  /** Sends emails (address confirmation, password reset). Required for apps with an auth line in production. */
  readonly mailer?: Mailer;
  /** The app's public address, used in links in emails, e.g. "https://blog.example". */
  readonly publicUrl?: string;
  /** RIZO_PRIVACY_CONTACT, shown in the privacy notice. Required for apps with `privacy for`. */
  readonly privacyContact?: string;
  /** How long audit entries are kept, for the privacy notice. */
  readonly auditRetentionDays?: number;
  /** True once the server is shutting down: the health check then answers 503. */
  readonly shuttingDown?: () => boolean;
  /** The app's OpenAPI document (dist/openapi.json), served at /_rizo/openapi.json. */
  readonly openapi?: string;
  /** "Resend", or "development" when emails are only printed (RIZO_EMAIL_DEV=1). */
  readonly emailService?: "Resend" | "development";
  /** Keys for encrypted fields (from RIZO_ENCRYPTION_KEYS). Required when the app has any. */
  readonly encryptionKeys?: Keys;
  /** Where uploaded files are kept (local folder or S3-compatible storage). Required when the app has File fields. */
  readonly fileStore?: FileStore;
}

/** Largest accepted request body. */
export const MAX_BODY_BYTES = 1024 * 1024;

const SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Cross-Origin-Resource-Policy": "same-origin",
};

/** An error that becomes an HTTP response. `message` is shown to the client. */
class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly field: string | undefined;
  readonly headers: Readonly<Record<string, string>>;
  constructor(status: number, code: string, message: string, field?: string, headers: Record<string, string> = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.field = field;
    this.headers = headers;
  }
}

interface Matched {
  readonly route: Route;
  readonly params: ReadonlyMap<string, unknown>;
}

interface AuthRoute {
  readonly path: string;
  readonly methods: readonly string[];
}
const AUTH_ROUTES: readonly AuthRoute[] = [
  { path: "/auth/signup", methods: ["POST"] },
  { path: "/auth/login", methods: ["POST"] },
  { path: "/auth/logout", methods: ["POST"] },
  { path: "/auth/logout-all", methods: ["POST"] },
  { path: "/auth/password", methods: ["POST"] },
  { path: "/auth/me", methods: ["GET", "PATCH", "DELETE"] },
  { path: "/auth/me/export", methods: ["GET"] },
  { path: "/auth/privacy", methods: ["GET"] },
  { path: "/auth/audit", methods: ["GET"] },
  { path: "/auth/sessions", methods: ["GET"] },
  { path: "/auth/tokens", methods: ["GET", "POST"] },
  { path: "/auth/verify-email", methods: ["POST"] },
  { path: "/auth/verify-email/resend", methods: ["POST"] },
  { path: "/auth/password-reset", methods: ["POST"] },
  { path: "/auth/password-reset/confirm", methods: ["POST"] },
  { path: "/auth/email", methods: ["POST"] },
  { path: "/auth/email/confirm", methods: ["POST"] },
];

/** What signup and the email endpoints always answer, whether or not the account exists. */
const CHECK_EMAIL = { message: "Check your email for a link." };

interface Page {
  /** Validated query parameters of the list's filters (`?q`); missing ones are absent. */
  readonly filters: ReadonlyMap<string, unknown>;
  readonly limit: number;
  readonly cursor?: { readonly value?: string; readonly id: string };
}

/** Uploads allowed per account per hour, and file downloads per address per minute. */
const UPLOADS_PER_HOUR = 60;
const FILE_READS_PER_MINUTE = 600;
/** At most this many uploads (held in memory while checked) and file downloads at once, per process. */
const MAX_UPLOADS_IN_FLIGHT = 8;
const MAX_DOWNLOADS_IN_FLIGHT = 200;

/** "5 MB" or "500 KB". */
export function formatBytes(n: number): string {
  return n >= 1024 * 1024 && n % (1024 * 1024) === 0 ? `${n / (1024 * 1024)} MB` : `${Math.round(n / 1024)} KB`;
}

/** Records per page on the admin pages. */
const ADMIN_PAGE = 50;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_CURSOR = 2048;

/** A cursor is base64url(JSON) of [sortValue, id], or [id] when sorted by id. */
export function encodeCursor(parts: readonly string[]): string {
  return Buffer.from(JSON.stringify(parts), "utf8").toString("base64url");
}

/** Decode and check a cursor. Returns undefined for anything malformed. */
export function decodeCursor(raw: string, order: FieldKind | null): { value?: string; id: string } | undefined {
  if (raw.length === 0 || raw.length > MAX_CURSOR || !/^[A-Za-z0-9_-]+$/.test(raw)) return undefined;
  let parts: unknown;
  try {
    parts = JSON.parse(Buffer.from(raw, "base64url").toString("utf8"));
  } catch {
    return undefined;
  }
  if (!Array.isArray(parts) || !parts.every((x) => typeof x === "string")) return undefined;
  const strings = parts as string[];
  const id = strings[strings.length - 1];
  if (id === undefined || !UUID_RE.test(id)) return undefined;
  if (order === null) return strings.length === 1 ? { id } : undefined;
  const value = strings[0];
  if (strings.length !== 2 || value === undefined || value.includes("\u0000")) return undefined;
  const valid =
    order === "Number" ? /^-?\d{1,10}$/.test(value)
    : order === "Bool" ? value === "true" || value === "false"
    : order === "ID" ? UUID_RE.test(value)
    : true; // Text, Email, Date: PostgreSQL checks the value when it is cast back.
  return valid ? { value, id } : undefined;
}

/** Copy only the listed keys. Responses never rely on the query alone to hide data. */
function pick(row: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) if (Object.hasOwn(row, k)) out[k] = row[k];
  return out;
}

const article = (word: string): string => (/^[AEIOU]/i.test(word) ? "An" : "A");
const camel = (snake: string): string => snake.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase());

export function createRequestHandler(app: App, options: ServerOptions): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
  const { db } = options;
  const log = options.log ?? ((line: string) => process.stdout.write(`${line}\n`));
  const secure = options.secureCookies ?? true;
  const now = options.now ?? Date.now;
  const allowedOrigins = new Set(options.allowedOrigins ?? []);

  const limits = new Limits(db, now);
  const mailer: Mailer = options.mailer ?? (async () => {
    throw new Error("email is not configured");
  });
  const publicUrl = options.publicUrl ?? "http://localhost";
  /** Endpoints an API token may be made for: every endpoint that needs a login. */
  const tokenEndpoints = app.routes.filter((r) => r.access === "login").map((r) => `${r.method} ${r.pattern}`);

  function encryptionKeys(): Keys {
    if (options.encryptionKeys === undefined) throw new Error("this app has encrypted fields, but no encryption keys were given");
    return options.encryptionKeys;
  }

  /** Encrypt the encrypted fields of validated body values, just before they become SQL parameters. */
  function seal(values: ReadonlyMap<string, unknown>, fields: readonly EncryptedField[] | undefined): ReadonlyMap<string, unknown> {
    if (fields === undefined || fields.length === 0) return values;
    const out = new Map(values);
    for (const f of fields) {
      const v = out.get(f.key);
      if (v !== undefined && v !== null) out.set(f.key, encryptValue(encryptionKeys(), f.aad, v));
    }
    return out;
  }

  /** Copy only public keys from a row, decrypting encrypted fields; linked records (`with`) the same way. */
  function reveal(
    row: Record<string, unknown>,
    keys: readonly string[],
    fields: readonly EncryptedField[] | undefined,
    expanded: Route["expanded"] = undefined,
  ): Record<string, unknown> {
    const out = pick(row, keys);
    for (const x of expanded ?? []) {
      const linked = out[x.key];
      out[x.key] = linked !== null && typeof linked === "object" ? reveal(linked as Record<string, unknown>, x.publicKeys, x.encrypted) : null;
    }
    for (const f of fields ?? []) {
      const v = out[f.key];
      if (v !== undefined && v !== null) out[f.key] = decryptValue(encryptionKeys(), f.aad, v);
    }
    return out;
  }
  const audit = new Audit(db, log);
  let uploadsInFlight = 0;
  let downloadsInFlight = 0;
  const LOGIN_WINDOW = 15 * 60;

  /**
   * Run a rate-limit check. If the counter table can't be reached, the
   * request is allowed and the problem logged: a database hiccup must not
   * lock everyone out.
   */
  async function limited(check: () => Promise<{ allowed: boolean; retryAfter: number }>): Promise<{ allowed: boolean; retryAfter: number }> {
    try {
      return await check();
    } catch (e) {
      log(`warning rate limit check failed: ${describeError(e)}`);
      return { allowed: true, retryAfter: 0 };
    }
  }
  const notVerified = (): HttpError =>
    new HttpError(403, "email_not_verified", "Confirm your email address first, with the link we emailed you. You can ask for a new link.");
  const tooMany = (retryAfter: number, message: string): HttpError =>
    new HttpError(429, "too_many_requests", message, undefined, { "Retry-After": String(retryAfter) });

  return async (req, res) => {
    const started = now();
    const requestId = randomUUID();
    const method = req.method ?? "GET";
    let pattern = "-";
    let status = 500;
    try {
      const url = new URL(req.url ?? "/", "http://localhost");
      const auth = app.auth;
      if (auth !== null && url.pathname.startsWith("/auth/")) {
        pattern = url.pathname;
        status = await handleAuth(req, res, url.pathname, method);
      } else if (method === "POST" && url.pathname.startsWith("/_rizo/uploads/")) {
        const spec = app.files?.uploads.find((u) => `/_rizo/uploads/${u.path}` === url.pathname);
        if (spec === undefined) throw new HttpError(404, "not_found", "No upload address matches this path.");
        pattern = url.pathname;
        status = await upload(req, res, spec);
      } else if (method === "GET" && url.pathname.startsWith("/_rizo/files/")) {
        // Never log the address itself: knowing it is what gives access to the file.
        pattern = "/_rizo/files/:name";
        status = await serveFile(req, res, url.pathname);
      } else if (method === "GET" && url.pathname === "/_rizo/health") {
        pattern = url.pathname;
        status = await health(res);
      } else if (method === "GET" && url.pathname.startsWith("/_rizo/")) {
        pattern = url.pathname;
        status = serveAsset(res, url.pathname);
      } else if (method === "GET" && pageFor(url.pathname) !== undefined) {
        const found = pageFor(url.pathname);
        if (found === undefined) throw new Error("unreachable");
        pattern = found.page.pattern;
        status = await servePage(req, res, found.page, found.parts, url.pathname);
      } else {
        const { route, params } = match(method, url.pathname);
        pattern = route.pattern;
        status = await handleRoute(req, res, route, params, url.searchParams);
      }
    } catch (caught) {
      const e = caught instanceof BusyError
        ? new HttpError(503, "busy", "The server is busy. Try again in a moment.", undefined, { "Retry-After": "2" })
        : (caught as { code?: unknown } | null)?.code === "57014"
          ? new HttpError(503, "timeout", "The request took too long. Please try again.", undefined, { "Retry-After": "2" })
          : caught;
      if (e instanceof HttpError) {
        status = e.status;
        send(res, e.status, { error: { code: e.code, message: e.message, ...(e.field ? { field: e.field } : {}) } }, e.headers);
      } else {
        status = 500;
        log(`error id=${requestId} ${describeError(e)}`);
        if (!res.headersSent) {
          send(res, 500, { error: { code: "internal_error", message: `Something went wrong. Request id: ${requestId}.` } });
        } else {
          res.destroy();
        }
      }
    } finally {
      log(`${method} ${pattern} ${status} ${now() - started}ms id=${requestId}`);
    }
  };

  // -------------------------------------------------------------- routing

  /** Split a URL path into decoded segments. */
  function splitPath(pathname: string): string[] {
    try {
      return pathname === "/" ? [] : pathname.slice(1).split("/").map(decodeURIComponent);
    } catch {
      throw new HttpError(400, "bad_path", "The URL path is not valid.");
    }
  }

  /** How well a route path matches: the number of static segments, or undefined. */
  function score(path: readonly PathPart[], parts: readonly string[]): number | undefined {
    if (path.length !== parts.length) return undefined;
    let n = 0;
    for (let i = 0; i < path.length; i++) {
      const p = path[i];
      const value = parts[i] ?? "";
      if (p === undefined) return undefined;
      if ("static" in p) {
        if (p.static !== value) return undefined;
        n++;
      } else if (value === "") {
        return undefined;
      }
    }
    return n;
  }

  /** The page for a GET request, unless a GET endpoint matches at least as well. */
  function pageFor(pathname: string): { page: PageRoute; parts: string[] } | undefined {
    if (app.pages.length === 0) return undefined;
    const parts = splitPath(pathname);
    let best: { page: PageRoute; score: number } | undefined;
    for (const page of app.pages) {
      const s = score(page.path, parts);
      if (s !== undefined && (best === undefined || s > best.score)) best = { page, score: s };
    }
    if (best === undefined) return undefined;
    for (const route of app.routes) {
      const s = route.method === "GET" ? score(route.path, parts) : undefined;
      if (s !== undefined && s >= best.score) return undefined;
    }
    return { page: best.page, parts };
  }

  /**
   * For hosting platforms and load balancers: 200 when the database answers
   * within 2 seconds, 503 otherwise or while shutting down. It says nothing
   * else about the app.
   */
  async function health(res: ServerResponse): Promise<number> {
    const unavailable = (): number => send(res, 503, { status: "unavailable" }, { "Retry-After": "5" });
    if (options.shuttingDown?.() === true) return unavailable();
    const ok = await Promise.race([
      db.query(HEALTH_SQL, []).then(() => true, () => false),
      new Promise<boolean>((done) => setTimeout(() => done(false), 2000).unref()),
    ]);
    return ok ? send(res, 200, { status: "ok" }) : unavailable();
  }

  function serveAsset(res: ServerResponse, pathname: string): number {
    if (pathname === "/_rizo/openapi.json" && options.openapi !== undefined) {
      // For agents and tools: what every endpoint takes and returns, and who may call it.
      res.writeHead(200, { ...SECURITY_HEADERS, "Cache-Control": "no-cache" });
      res.end(options.openapi);
      return 200;
    }
    const a = asset(pathname);
    if (a === undefined) throw new HttpError(404, "not_found", "No file matches this path.");
    res.writeHead(200, {
      "Content-Type": a.type,
      "Cache-Control": "public, max-age=3600",
      "X-Content-Type-Options": "nosniff",
      "Cross-Origin-Resource-Policy": "same-origin",
    });
    res.end(a.body);
    return 200;
  }

  async function servePage(req: IncomingMessage, res: ServerResponse, page: PageRoute, parts: readonly string[], pathname: string): Promise<number> {
    const html = (status: number, body: string): number => {
      res.writeHead(status, PAGE_HEADERS);
      res.end(body);
      return status;
    };
    const pageGate = await limited(() => limits.consume(limitKey(`page ${page.pattern}`, clientIp(req)), DEFAULT_RATE, 60));
    if (!pageGate.allowed) {
      res.setHeader("Retry-After", String(pageGate.retryAfter));
      return html(429, renderMessage("Too many requests", `Please wait ${pageGate.retryAfter} seconds and try again.`, app.site));
    }
    const params: Record<string, string> = {};
    for (let i = 0; i < page.path.length; i++) {
      const p = page.path[i];
      if (p === undefined || !("param" in p)) continue;
      const r = validatePathParam(p, parts[i] ?? "");
      if ("error" in r) return html(404, renderMessage("Page not found", "There is no page at this address.", app.site));
      params[p.param] = String(r.value);
    }
    const me = await currentUser(req);
    if (page.access === "login" && me === undefined) {
      if (app.pages.some((p) => p.pattern === "/login")) {
        // Back to this page after logging in. The login page only follows internal paths.
        res.writeHead(302, { ...PAGE_HEADERS, Location: `/login?next=${encodeURIComponent(pathname)}` });
        res.end();
        return 302;
      }
      return html(401, renderMessage("Please log in", "You need to log in to see this page.", app.site));
    }
    const role = me !== undefined && (page.roles.length > 0 || app.admin !== undefined) ? await roleOf(me) : null;
    if (page.roles.length > 0 && (role === null || !page.roles.includes(role))) {
      return html(403, renderMessage("Not allowed", "You don't have permission to see this page.", app.site));
    }
    // Admins see a link to the admin pages in the menu.
    const admin = app.admin !== undefined && role === "admin" && app.pages.some((p) => p.pattern === "/admin");
    return html(200, renderPage(page, params, me !== undefined, app.auth !== null, app.privacy !== undefined, app.site, admin));
  }

  function match(method: string, pathname: string): Matched {
    const parts = splitPath(pathname);
    let best: { route: Route; score: number } | undefined;
    const allow = new Set<string>();
    for (const route of app.routes) {
      if (route.path.length !== parts.length) continue;
      let score = 0;
      let ok = true;
      route.path.forEach((p, i) => {
        if ("static" in p) {
          if (p.static === parts[i]) score++;
          else ok = false;
        } else if ((parts[i] ?? "") === "") {
          ok = false;
        }
      });
      if (!ok) continue;
      allow.add(route.method);
      if (route.method === method && (best === undefined || score > best.score)) best = { route, score };
    }
    if (best === undefined) {
      if (allow.size > 0) {
        throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: [...allow].join(", ") });
      }
      throw new HttpError(404, "not_found", "No endpoint matches this path.");
    }
    const params = new Map<string, unknown>();
    best.route.path.forEach((p, i) => {
      if ("param" in p) {
        const r = validatePathParam(p, parts[i] ?? "");
        if ("error" in r) throw new HttpError(400, "invalid_parameter", r.error, p.param);
        params.set(p.param, r.value);
      }
    });
    return { route: best.route, params };
  }

  // ------------------------------------------------------------- requests

  /** Reject cross-site state-changing requests (defense in depth on top of SameSite cookies). */
  function checkOrigin(req: IncomingMessage, method: string): void {
    if (method === "GET") return;
    const origin = req.headers.origin;
    if (origin !== undefined && allowedOrigins.has(origin)) return;
    // Browsers say where a request comes from. Anything but this site itself
    // ("same-origin") or a typed-in address ("none") is refused.
    const site = req.headers["sec-fetch-site"];
    if (site !== undefined && site !== "same-origin" && site !== "none") {
      throw new HttpError(403, "forbidden_origin", "Requests from other sites are not allowed.");
    }
    if (origin === undefined) return;
    let host: string;
    try {
      host = new URL(origin).host;
    } catch {
      throw new HttpError(403, "forbidden_origin", "Requests from this origin are not allowed.");
    }
    if (host !== req.headers.host) throw new HttpError(403, "forbidden_origin", "Requests from this origin are not allowed.");
  }

  async function readJson(req: IncomingMessage): Promise<unknown> {
    const type = (req.headers["content-type"] ?? "").split(";")[0]?.trim().toLowerCase();
    if (type !== "application/json") {
      throw new HttpError(415, "unsupported_media_type", 'Send the body as JSON with "Content-Type: application/json".');
    }
    const declared = Number(req.headers["content-length"] ?? "0");
    if (declared > MAX_BODY_BYTES) throw new HttpError(413, "body_too_large", "The request body is too large.");
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      const buf = chunk as Buffer;
      size += buf.length;
      if (size > MAX_BODY_BYTES) throw new HttpError(413, "body_too_large", "The request body is too large.");
      chunks.push(buf);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
    } catch {
      throw new HttpError(400, "invalid_json", "The request body is not valid JSON.");
    }
  }

  function hasBody(req: IncomingMessage): boolean {
    return Number(req.headers["content-length"] ?? "0") > 0 || req.headers["transfer-encoding"] !== undefined;
  }

  async function body(req: IncomingMessage, specs: readonly FieldSpec[]): Promise<Map<string, unknown>> {
    const v = validateBody(specs, await readJson(req));
    if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
    const values = new Map(v.values);
    for (const spec of specs) {
      const value = values.get(spec.key);
      if (spec.kind === "Password" && typeof value === "string") values.set(spec.key, await hashPassword(value));
    }
    return values;
  }

  /**
   * Query string handling. Only list endpoints accept parameters, and only
   * `limit` and `after`; anything else is rejected.
   */
  function readPage(route: Route, search: URLSearchParams): Page | undefined {
    const declared = route.query ?? [];
    const allowed = route.page === null ? [] : ["limit", "after", ...declared.map((x) => x.name)];
    for (const key of new Set(search.keys())) {
      const shown = key.length > 50 ? `${key.slice(0, 50)}…` : key;
      if (!allowed.includes(key)) {
        throw new HttpError(400, "unknown_parameter",
          allowed.length > 0 ? `Unknown query parameter "${shown}". Allowed: ${allowed.join(", ")}.` : `This endpoint takes no query parameters (got "${shown}").`, shown);
      }
      if (search.getAll(key).length > 1) throw new HttpError(400, "unknown_parameter", `Query parameter "${key}" appears more than once.`, key);
    }
    if (route.page === null) return undefined;
    const filters = new Map<string, unknown>();
    for (const param of declared) {
      const raw = search.get(param.name);
      // Left out or empty (a search box sent with nothing in it): the filter is skipped.
      if (raw === null || raw === "") continue;
      const v = validateQueryParam(param.name, param.kind, raw, param.max);
      if (!("value" in v)) throw new HttpError(400, "invalid_parameter", v.error, param.name);
      filters.set(param.name, v.value);
    }
    const max = route.page.max;
    const rawLimit = search.get("limit");
    let limit = max;
    if (rawLimit !== null) {
      limit = /^\d{1,4}$/.test(rawLimit) ? Number(rawLimit) : 0;
      if (limit < 1 || limit > max) throw new HttpError(400, "invalid_parameter", `limit must be a whole number from 1 to ${max}.`, "limit");
    }
    const rawAfter = search.get("after");
    if (rawAfter === null) return { limit, filters };
    const cursor = decodeCursor(rawAfter, route.page.order);
    if (cursor === undefined) throw new HttpError(400, "invalid_parameter", "after is not a valid cursor. Use the next value from the previous page.", "after");
    return { limit, cursor, filters };
  }

  // ---------------------------------------------------------------- files

  /**
   * A File value in a body must be a file the caller uploaded for this field,
   * or (on update) the record's current file. Otherwise anyone could attach,
   * and keep alive, a file someone else uploaded.
   */
  async function checkFiles(files: readonly FileField[] | undefined, bodyValues: ReadonlyMap<string, unknown>, params: ReadonlyMap<string, unknown>, me: string | undefined): Promise<void> {
    for (const f of files ?? []) {
      const value = bodyValues.get(f.key);
      if (typeof value !== "string") continue;
      if (me !== undefined && (await db.query(FILE_SQL.owned, [value, f.field, me])).rows.length > 0) continue;
      if (f.current !== undefined) {
        const [id] = values([f.current.id], params, new Map(), me, null);
        if (id !== undefined && id !== null && (await db.query(f.current.sql, [id, value])).rows.length > 0) continue;
      }
      throw new HttpError(400, "validation_failed", `${f.key} must be a file you uploaded for it. Upload the file first, then send the url it returns.`, f.key);
    }
  }

  /** The logged-in user for an upload: the session, or an API token allowed an endpoint that takes the field. */
  async function uploader(req: IncomingMessage, spec: UploadSpec): Promise<string | undefined> {
    const bearer = readBearer(req.headers.authorization);
    if (bearer === undefined) return currentUser(req);
    const invalid = new HttpError(401, "invalid_token", "This API token is not valid or has expired. Create a new one on your account page.");
    if (bearer === null) throw invalid;
    const row = (await db.query(TOKEN_SQL.lookup, [agentTokenHash(bearer)])).rows[0];
    if (row === undefined) throw invalid;
    const allowed = parseEndpoints(row["endpoints"]);
    if (!spec.endpoints.some((e) => allowed.includes(e))) {
      throw new HttpError(403, "token_not_allowed", `This API token can't upload files for ${spec.field}. Create a token that includes an endpoint that takes it: ${spec.endpoints.join(", ") || "none"}.`);
    }
    if (row["stale"] === true) await db.query(TOKEN_SQL.touch, [row["id"]]);
    const userId = String(row["user_id"]);
    await audit.record({ action: "token_used", userId, ip: clientIp(req), detail: `POST /_rizo/uploads/${spec.path}` });
    return userId;
  }

  /** POST /_rizo/uploads/<model>/<field>: the raw file as the body. */
  async function upload(req: IncomingMessage, res: ServerResponse, spec: UploadSpec): Promise<number> {
    checkOrigin(req, "POST");
    const store = options.fileStore;
    if (store === undefined) throw new HttpError(503, "storage_unavailable", "File storage is not configured on this server.", undefined, { "Retry-After": "60" });
    const ipGate = await limited(() => limits.consume(limitKey(`POST /_rizo/uploads/${spec.path}`, clientIp(req)), DEFAULT_RATE, 60));
    if (!ipGate.allowed) throw tooMany(ipGate.retryAfter, `Too many requests. Try again in ${ipGate.retryAfter} seconds.`);
    const me = await uploader(req, spec);
    if (me === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    if (spec.roles.length > 0) {
      const role = await roleOf(me);
      if (role === null || !spec.roles.includes(role)) throw new HttpError(403, "forbidden", "You do not have permission to do this.");
    }
    const gate = await limited(() => limits.consume(limitKey("upload", me), UPLOADS_PER_HOUR, 3600));
    if (!gate.allowed) throw tooMany(gate.retryAfter, `You can upload ${UPLOADS_PER_HOUR} files an hour. Try again later.`);
    // Uploads are held in memory while they are checked, so only a few run at once.
    if (uploadsInFlight >= MAX_UPLOADS_IN_FLIGHT) throw new HttpError(503, "busy", "The server is busy. Try again in a moment.", undefined, { "Retry-After": "2" });
    uploadsInFlight++;
    try {
      return await receiveUpload(req, res, spec, store, me);
    } finally {
      uploadsInFlight--;
    }
  }

  async function receiveUpload(req: IncomingMessage, res: ServerResponse, spec: UploadSpec, store: FileStore, me: string): Promise<number> {
    const tooBig = new HttpError(413, "file_too_large", `The file is too large. The limit is ${formatBytes(spec.max)}.`);
    if (Number(req.headers["content-length"] ?? "0") > spec.max) throw tooBig;
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of req) {
      const buf = chunk as Buffer;
      size += buf.length;
      if (size > spec.max) throw tooBig;
      chunks.push(buf);
    }
    const data = Buffer.concat(chunks);
    const kind = detectFile(data);
    if (kind === undefined || !spec.accept.includes(kind.ext)) {
      throw new HttpError(415, "unsupported_file", `This file type is not allowed here. Allowed: ${spec.accept.join(", ")}. The type is read from the file's content, not its name.`);
    }
    const stored = removeLocation(data, kind.ext);
    const name = `${randomBytes(16).toString("hex")}.${kind.ext}`;
    try {
      await store.put(name, stored, kind.type);
    } catch (e) {
      log(`error file storage (${store.kind}): ${e instanceof StorageError ? e.message : describeError(e)}`);
      throw new HttpError(503, "storage_unavailable", "The file couldn't be stored. Please try again.", undefined, { "Retry-After": "5" });
    }
    const url = `/_rizo/files/${name}`;
    try {
      await db.query(FILE_SQL.insert, [url, me, spec.field, kind.type, stored.length]);
    } catch (e) {
      // Without its row, nothing would ever delete the stored file.
      await store.remove(name).catch(() => undefined);
      throw e;
    }
    return send(res, 201, { url, type: kind.type, size: stored.length });
  }

  /** GET /_rizo/files/<name>: anyone with the address may read the file, and the address only appears where the field is returned. */
  async function serveFile(req: IncomingMessage, res: ServerResponse, pathname: string): Promise<number> {
    const name = pathname.slice("/_rizo/files/".length);
    const notFound = new HttpError(404, "not_found", "No file matches this address.");
    if (!FILE_NAME.test(name) || options.fileStore === undefined) throw notFound;
    const gate = await limited(() => limits.consume(limitKey("GET /_rizo/files", clientIp(req)), FILE_READS_PER_MINUTE, 60));
    if (!gate.allowed) throw tooMany(gate.retryAfter, `Too many requests. Try again in ${gate.retryAfter} seconds.`);
    const row = (await db.query(FILE_SQL.find, [pathname])).rows[0];
    if (row === undefined) throw notFound;
    // Files are streamed, so a slow reader holds little memory; still, only so many are sent at once.
    if (downloadsInFlight >= MAX_DOWNLOADS_IN_FLIGHT) throw new HttpError(503, "busy", "The server is busy. Try again in a moment.", undefined, { "Retry-After": "2" });
    let file: { readonly stream: Readable; readonly size: number } | undefined;
    try {
      file = await options.fileStore.open(name);
    } catch (e) {
      log(`error file storage (${options.fileStore.kind}): ${e instanceof StorageError ? e.message : describeError(e)}`);
      throw new HttpError(503, "storage_unavailable", "The file can't be read right now. Please try again.", undefined, { "Retry-After": "5" });
    }
    if (file === undefined) throw notFound;
    const { stream, size } = file;
    downloadsInFlight++;
    const type = String(row["type"]);
    res.writeHead(200, {
      "Content-Type": type,
      ...(size >= 0 ? { "Content-Length": String(size) } : {}),
      // Files can never run as a page: no scripts, a sandbox, and PDFs are downloaded rather than opened here.
      "Content-Security-Policy": "default-src 'none'; sandbox; frame-ancestors 'none'",
      "Content-Disposition": type === "application/pdf" ? `attachment; filename="${name}"` : "inline",
      "X-Content-Type-Options": "nosniff",
      "Cross-Origin-Resource-Policy": "same-origin",
      "Referrer-Policy": "no-referrer",
      "Cache-Control": "private, max-age=3600",
    });
    // A reader that stops reading is dropped after a minute.
    res.setTimeout(60_000, () => res.destroy());
    await new Promise<void>((done) => {
      res.once("close", () => {
        downloadsInFlight--;
        stream.destroy();
        done();
      });
      stream.once("error", (e) => {
        log(`error file storage (${options.fileStore?.kind ?? "-"}): ${describeError(e)}`);
        res.destroy();
      });
      stream.pipe(res);
    });
    return 200;
  }

  /** The role of a user, or null. Read from the database on every request, so changes apply at once. */
  async function roleOf(userId: string): Promise<string | null> {
    const auth = app.auth;
    if (auth === null || auth.roleSql === "") return null;
    const r = await db.query(auth.roleSql, [userId]);
    const role = r.rows[0]?.["role"];
    return typeof role === "string" && auth.roles.includes(role) ? role : null;
  }

  async function currentUser(req: IncomingMessage): Promise<string | undefined> {
    const token = readToken(req.headers.cookie);
    if (token === undefined) return undefined;
    const hash = hashToken(token);
    const r = await db.query(SQL.lookup, [hash]);
    const id = r.rows[0]?.["user_id"];
    if (typeof id !== "string") return undefined;
    // Using a session keeps it alive for another 7 days (up to its 30-day maximum).
    if (r.rows[0]?.["stale"] === true) await db.query(SQL.touch, [hash, IDLE_SECONDS]);
    return id;
  }

  async function startSession(req: IncomingMessage, res: ServerResponse, userId: string): Promise<void> {
    const token = newToken();
    await db.query(SQL.deleteExpired, [userId]);
    await db.query(SQL.create, [hashToken(token), userId, deviceLabel(req.headers["user-agent"]), IDLE_SECONDS, MAX_SECONDS]);
    res.setHeader("Set-Cookie", sessionCookie(token, secure));
  }

  function clientIp(req: IncomingMessage): string {
    if (options.trustProxy) {
      const fwd = req.headers["x-forwarded-for"];
      const first = (Array.isArray(fwd) ? fwd[0] : fwd)?.split(",")[0]?.trim();
      if (first) return first;
    }
    return req.socket.remoteAddress ?? "unknown";
  }

  function values(
    sources: readonly ValueSource[],
    params: ReadonlyMap<string, unknown>,
    bodyValues: ReadonlyMap<string, unknown>,
    me: string | undefined,
    role: string | null,
    page?: Page,
  ): unknown[] {
    return sources.map((s) => {
      switch (s.from) {
        case "path": return params.get(s.name);
        case "me": return me;
        case "body": return bodyValues.get(s.key) ?? null;
        case "provided": return bodyValues.has(s.key);
        case "const": return s.value;
        case "hasRole": return role !== null && s.roles.includes(role);
        case "cursorSet": return page?.cursor !== undefined;
        case "cursorValue": return page?.cursor?.value ?? null;
        case "cursorId": return page?.cursor?.id ?? null;
        case "pageLimit": return (page?.limit ?? 0) + 1;
        case "query": return page?.filters.get(s.name) ?? null;
      }
    });
  }

  async function run(sql: string, vals: unknown[], model: string): Promise<QueryResult> {
    try {
      return await db.query(sql, vals);
    } catch (e) {
      const err = e as { code?: string; detail?: string };
      const column = /^Key \(([a-z0-9_]+)\)/.exec(err.detail ?? "")?.[1];
      const field = column === undefined ? undefined : camel(column.replace(/_id$/, "").replace(/_hash$/, ""));
      switch (err.code) {
        case "23505":
          throw new HttpError(409, "already_exists", `${article(model)} ${model} with this ${field ?? "value"} already exists.`, field);
        case "23503":
          throw sql.startsWith("DELETE")
            ? new HttpError(409, "in_use", `This ${model} cannot be deleted because other records link to it.`)
            : new HttpError(400, "invalid_link", `${field ?? "A linked record"} refers to a record that does not exist.`, field);
        case "57014":
          throw new HttpError(503, "timeout", "The request took too long. Please try again.", undefined, { "Retry-After": "2" });
        case "23514":
        case "23502":
        case "22P02":
        case "22007":
        case "22008":
        case "22001":
          throw new HttpError(400, "validation_failed", "A value is not valid.");
        default:
          throw e;
      }
    }
  }

  async function handleRoute(
    req: IncomingMessage,
    res: ServerResponse,
    route: Route,
    params: ReadonlyMap<string, unknown>,
    search: URLSearchParams,
  ): Promise<number> {
    checkOrigin(req, route.method);
    const page = readPage(route, search);
    let me: string | undefined;
    if (route.access === "login") {
      me = await caller(req, route);
      if (me === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    }
    // Rate limit: per account when logged in, per IP address otherwise.
    const identity = me !== undefined ? `user:${me}` : `ip:${clientIp(req)}`;
    const gate = await limited(() => limits.consume(limitKey(`${route.method} ${route.pattern}`, identity), route.rateLimit.max, route.rateLimit.windowSeconds));
    if (!gate.allowed) throw tooMany(gate.retryAfter, `Too many requests. Try again in ${gate.retryAfter} seconds.`);

    const needsRole = route.roles.length > 0 || route.values.some((v) => v.from === "hasRole");
    const role = needsRole && me !== undefined ? await roleOf(me) : null;
    if (route.roles.length > 0 && (role === null || !route.roles.includes(role))) {
      throw new HttpError(403, "forbidden", "You do not have permission to do this.");
    }
    let bodyValues: ReadonlyMap<string, unknown> = new Map();
    if (route.body === null) {
      if (hasBody(req)) throw new HttpError(400, "unexpected_body", "This endpoint does not accept a request body.");
    } else {
      bodyValues = seal(await body(req, route.body), route.encrypted);
    }
    await checkFiles(route.files, bodyValues, params, me);
    const r = await run(route.sql, values(route.values, params, bodyValues, me, role, page), route.model);
    switch (route.result) {
      case "list": {
        const limit = page?.limit ?? r.rows.length;
        const rows = r.rows.slice(0, limit);
        const last = rows[rows.length - 1];
        const next = r.rows.length > limit && last !== undefined
          ? encodeCursor(route.page?.order ? [String(last["_cursor"]), String(last["id"])] : [String(last["id"])])
          : null;
        return send(res, 200, { items: rows.map((row) => reveal(row, route.publicKeys, route.encrypted, route.expanded)), next });
      }
      case "created":
        return send(res, 201, reveal(r.rows[0] ?? {}, route.publicKeys, route.encrypted, route.expanded));
      case "one": {
        const row = r.rows[0];
        if (row === undefined) throw new HttpError(404, "not_found", `${route.model} not found.`);
        return send(res, 200, reveal(row, route.publicKeys, route.encrypted, route.expanded));
      }
      case "none": {
        if ((r.rowCount ?? 0) === 0) throw new HttpError(404, "not_found", `${route.model} not found.`);
        const idSource = route.values.find((v) => v.from === "path");
        const target = idSource?.from === "path" ? params.get(idSource.name) : undefined;
        await audit.record({ action: "record_deleted", userId: me, targetId: typeof target === "string" ? target : undefined, ip: clientIp(req), detail: route.model });
        res.writeHead(204, SECURITY_HEADERS).end();
        return 204;
      }
    }
  }

  /**
   * Who is calling an endpoint that needs a login: the API token in the
   * Authorization header if there is one (only for the endpoints it was
   * made for), otherwise the session cookie.
   */
  async function caller(req: IncomingMessage, route: Route): Promise<string | undefined> {
    const bearer = readBearer(req.headers.authorization);
    if (bearer === undefined) return currentUser(req);
    const invalid = new HttpError(401, "invalid_token", "This API token is not valid or has expired. Create a new one on your account page.");
    if (bearer === null) throw invalid;
    const row = (await db.query(TOKEN_SQL.lookup, [agentTokenHash(bearer)])).rows[0];
    if (row === undefined) throw invalid;
    const userId = String(row["user_id"]);
    const endpoint = `${route.method} ${route.pattern}`;
    if (!parseEndpoints(row["endpoints"]).includes(endpoint)) {
      throw new HttpError(403, "token_not_allowed", `This API token can't call ${endpoint}. Create a token that includes it.`);
    }
    if (row["stale"] === true) await db.query(TOKEN_SQL.touch, [row["id"]]);
    await audit.record({ action: "token_used", userId, ip: clientIp(req), detail: endpoint });
    return userId;
  }

  async function tokens(req: IncomingMessage, res: ServerResponse, method: string): Promise<number> {
    const me = await requireUser(req);
    if (method === "GET") {
      const r = await db.query(TOKEN_SQL.list, [me]);
      const items = r.rows.map((row) => ({ ...pick(row, ["id", "name", "createdAt", "expiresAt", "lastUsedAt"]), endpoints: parseEndpoints(row["endpoints"]) }));
      return send(res, 200, { items, endpoints: tokenEndpoints });
    }
    const raw = await readJson(req) as Record<string, unknown> | null;
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new HttpError(400, "validation_failed", "Send a JSON object with name and endpoints.");
    for (const key of Object.keys(raw)) {
      if (!["name", "endpoints", "days"].includes(key)) throw new HttpError(400, "validation_failed", `Unknown field "${key.slice(0, 50)}". Allowed: name, endpoints, days.`, key.slice(0, 50));
    }
    const name = typeof raw["name"] === "string" ? raw["name"].trim() : "";
    if (name.length < 1 || name.length > 60) throw new HttpError(400, "validation_failed", "name must be 1 to 60 characters.", "name");
    const list = raw["endpoints"];
    if (!Array.isArray(list) || list.length === 0 || list.length > tokenEndpoints.length || !list.every((e) => typeof e === "string" && tokenEndpoints.includes(e))) {
      throw new HttpError(400, "validation_failed", `endpoints must be a list of endpoints that need a login, such as ${JSON.stringify(tokenEndpoints[0] ?? "GET /api/...")}.`, "endpoints");
    }
    const days = raw["days"] ?? MAX_TOKEN_DAYS;
    if (typeof days !== "number" || !Number.isInteger(days) || days < 1 || days > MAX_TOKEN_DAYS) {
      throw new HttpError(400, "validation_failed", `days must be a whole number from 1 to ${MAX_TOKEN_DAYS}.`, "days");
    }
    const count = Number((await db.query(TOKEN_SQL.count, [me])).rows[0]?.["n"] ?? 0);
    if (count >= MAX_TOKENS) throw new HttpError(409, "too_many_tokens", `You can have at most ${MAX_TOKENS} API tokens. Revoke one first.`);
    const { token, hash } = newAgentToken();
    const r = await db.query(TOKEN_SQL.create, [hash, me, name, JSON.stringify([...new Set(list as string[])]), days]);
    const row = r.rows[0] ?? {};
    await audit.record({ action: "token_created", userId: me, ip: clientIp(req) });
    // The token is shown this once; only its hash is kept.
    return send(res, 201, { ...pick(row, ["id", "name", "createdAt", "expiresAt"]), endpoints: parseEndpoints(row["endpoints"]), token });
  }

  /** DELETE /auth/tokens/:id: revoke one of your own tokens. */
  async function revokeToken(req: IncomingMessage, res: ServerResponse, method: string, rawId: string): Promise<number> {
    if (method !== "DELETE") throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: "DELETE" });
    checkOrigin(req, method);
    const me = await requireUser(req);
    const r = UUID_RE.test(rawId) ? await db.query(TOKEN_SQL.remove, [rawId.toLowerCase(), me]) : { rows: [] };
    if (r.rows.length === 0) throw new HttpError(404, "not_found", "Token not found.");
    await audit.record({ action: "token_revoked", userId: me, ip: clientIp(req) });
    res.writeHead(204, SECURITY_HEADERS).end();
    return 204;
  }

  /**
   * The shared "Deleted user" account, created the first time it is needed.
   * Only one can ever exist: if two processes create one at the same time,
   * the loser removes its own and uses the winner's.
   */
  async function deletedUser(): Promise<string | undefined> {
    const auth = app.auth;
    const spec = auth?.account.ghost;
    if (auth === null || spec === null || spec === undefined) return undefined;
    const found = (await db.query(GHOST_SQL.find, [])).rows[0]?.["user_id"];
    if (typeof found === "string") return found;
    const values = seal(ghostValues(spec), auth.encrypted);
    const created = String((await db.query(spec.sql, spec.fields.map((f) => values.get(f.key)))).rows[0]?.["id"]);
    const claimed = (await db.query(GHOST_SQL.claim, [created])).rows[0]?.["user_id"];
    if (typeof claimed === "string") return claimed;
    await db.query(spec.removeSql, [created]);
    const winner = (await db.query(GHOST_SQL.find, [])).rows[0]?.["user_id"];
    return typeof winner === "string" ? winner : undefined;
  }

  // ----------------------------------------------------------------- auth

  async function requireUser(req: IncomingMessage): Promise<string> {
    const me = await currentUser(req);
    if (me === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    return me;
  }

  /**
   * Check the logged-in user's password before a sensitive change. Wrong
   * guesses count toward the same per-account lockout as login.
   */
  async function confirmPassword(userId: string, password: string, field: string): Promise<void> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    const key = limitKey("password-check", userId);
    const gate = await limited(() => limits.blocked(key, 5, LOGIN_WINDOW));
    if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many wrong passwords. Try again later.");
    const r = await db.query(auth.account.hashSql, [userId]);
    const stored = r.rows[0]?.["hash"];
    const valid = await verifyPassword(password, typeof stored === "string" ? stored : await dummyHash());
    if (!valid) {
      await limited(() => limits.consume(key, 5, LOGIN_WINDOW));
      await audit.record({ action: "password_check_failed", userId, detail: field });
      throw new HttpError(403, "invalid_credentials", "The password is incorrect.", field);
    }
    await limited(async () => (await limits.clear(key), { allowed: true, retryAfter: 0 }));
  }

  // ---------------------------------------------------------------- email

  /**
   * Send an email in the background. The response never waits for it or
   * depends on it, so it can't reveal whether an account exists. Failures
   * are logged without the address.
   */
  function deliver(to: string, message: { subject: string; text: string }): void {
    mailer({ to, ...message }).catch((e: unknown) => log(`warning email not sent: ${describeError(e)}`));
  }

  /** At most 3 emails per hour to one account, so nobody can flood someone's inbox. Over the limit, nothing is sent. */
  async function mayEmail(userId: string): Promise<boolean> {
    return (await limited(() => limits.consume(limitKey("email-to", userId), 3, 3600))).allowed;
  }

  /** Email a new one-time link. Earlier links for the same purpose stop working. */
  async function sendLink(userId: string, to: string, purpose: TokenPurpose): Promise<void> {
    if (!(await mayEmail(userId))) return;
    const { token, hash } = newEmailToken();
    await db.query(EMAIL_SQL.deleteTokens, [userId, purpose]);
    await db.query(EMAIL_SQL.createToken, [hash, userId, purpose, purpose === "verify" ? VERIFY_SECONDS : RESET_SECONDS]);
    deliver(to, purpose === "verify" ? MESSAGES.verify(publicUrl, token) : MESSAGES.reset(publicUrl, token));
  }

  /** Use a one-time link from an email. */
  async function useLink(value: unknown, purpose: TokenPurpose): Promise<string> {
    const token = readEmailToken(value);
    const r = token === undefined ? { rows: [] } : await db.query(EMAIL_SQL.useToken, [emailTokenHash(token), purpose]);
    const userId = r.rows[0]?.["user_id"];
    if (typeof userId !== "string") {
      throw new HttpError(400, "invalid_link", "This link is not valid or has expired. Ask for a new one.", "token");
    }
    return userId;
  }

  async function unverified(userId: string): Promise<boolean> {
    return (await db.query(EMAIL_SQL.isUnverified, [userId])).rows.length > 0;
  }

  /** The account with this login email, if there is one. */
  async function accountFor(email: string): Promise<string | undefined> {
    const auth = app.auth;
    if (auth === null) return undefined;
    const id = (await db.query(auth.loginSql, [email])).rows[0]?.["id"];
    return typeof id === "string" ? id : undefined;
  }

  /** Read `{ "<login field>": ... }` from the body. */
  async function emailFrom(req: IncomingMessage): Promise<string> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    const v = validateBody([{ key: auth.loginKey, kind: "Email", required: true, nullable: false, max: 254 }], await readJson(req));
    if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
    return String(v.values.get(auth.loginKey));
  }

  /** Requests that send email: 10 per hour per address, on top of the per-account limit. */
  async function emailGate(ip: string): Promise<void> {
    const gate = await limited(() => limits.consume(limitKey("email-ip", ip), 10, 3600));
    if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many requests. Try again later.");
  }

  // ------------------------------------------------------------- passkeys

  /**
   * The site a passkey belongs to comes from the request's Origin header,
   * which checkOrigin() has already matched against this server's host.
   */
  function passkeySite(req: IncomingMessage): { origin: string; rpId: string } {
    const origin = req.headers.origin;
    if (origin === undefined) throw new HttpError(400, "passkey_failed", "Passkeys can only be used from a browser.");
    let rpId: string;
    try {
      rpId = new URL(origin).hostname;
    } catch {
      throw new HttpError(400, "passkey_failed", "Passkeys can only be used from a browser.");
    }
    return { origin, rpId };
  }

  /** Use a one-time challenge named in the browser's response. */
  async function useChallenge(clientDataJSON: unknown, purpose: "register" | "login", userId: string | null): Promise<string> {
    const challenge = challengeOf(clientDataJSON);
    const r = challenge === undefined ? { rows: [] } : await db.query(PASSKEY_SQL.useChallenge, [challengeHash(challenge), purpose, userId]);
    if (challenge === undefined || r.rows.length === 0) {
      throw new HttpError(400, "passkey_failed", "This passkey request has expired. Please try again.");
    }
    return challenge;
  }

  async function passkeys(req: IncomingMessage, res: ServerResponse, path: string, method: string): Promise<number> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    checkOrigin(req, method);
    const ip = clientIp(req);
    const one = /^\/auth\/passkeys\/([A-Za-z0-9_-]{16,1400})$/.exec(path);
    const allow = (expected: string): void => {
      if (method !== expected) throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: expected });
    };

    if (path === "/auth/passkeys/login-options") {
      allow("POST");
      const gate = await limited(() => limits.consume(limitKey("passkey-options", ip), 30, 60));
      if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many requests. Try again later.");
      const site = passkeySite(req);
      const { challenge, hash } = newChallenge();
      await db.query(PASSKEY_SQL.createChallenge, [hash, "login", null, CHALLENGE_SECONDS]);
      return send(res, 200, { challenge, rpId: site.rpId, timeout: CHALLENGE_SECONDS * 1000, userVerification: "required" });
    }

    if (path === "/auth/passkeys/login") {
      allow("POST");
      const ipKey = limitKey("login-ip", ip);
      const byIp = await limited(() => limits.blocked(ipKey, 20, LOGIN_WINDOW));
      if (!byIp.allowed) {
        await audit.record({ action: "login_blocked", ip, detail: "passkey" });
        throw tooMany(byIp.retryAfter, "Too many login attempts. Try again later.");
      }
      const body = await readJson(req) as { id?: unknown; response?: Record<string, unknown> };
      const site = passkeySite(req);
      const fail = async (userId?: string): Promise<never> => {
        await limited(() => limits.consume(ipKey, 20, LOGIN_WINDOW));
        await audit.record({ action: "login_failed", userId, ip, detail: "passkey" });
        throw new HttpError(401, "invalid_credentials", "That passkey can't be used to log in here.");
      };
      if (typeof body !== "object" || body === null || typeof body.id !== "string" || typeof body.response !== "object" || body.response === null) {
        throw new HttpError(400, "validation_failed", "Send the passkey response from the browser.");
      }
      const challenge = await useChallenge(body.response["clientDataJSON"], "login", null);
      const stored = (await db.query(PASSKEY_SQL.find, [body.id])).rows[0];
      if (stored === undefined) return fail();
      const userId = String(stored["user_id"]);
      try {
        const count = verifyAssertion(
          { clientDataJSON: body.response["clientDataJSON"], authenticatorData: body.response["authenticatorData"], signature: body.response["signature"] },
          { publicKey: String(stored["public_key"]), algorithm: Number(stored["algorithm"]), signCount: Number(stored["sign_count"]) },
          { challenge, ...site },
        );
        await db.query(PASSKEY_SQL.used, [body.id, count]);
      } catch (e) {
        if (e instanceof PasskeyError) return fail(userId);
        throw e;
      }
      if (await unverified(userId)) throw notVerified();
      await startSession(req, res, userId);
      await audit.record({ action: "login", userId, ip, detail: "passkey" });
      const me = await db.query(auth.meSql, [userId]);
      return send(res, 200, reveal(me.rows[0] ?? {}, auth.publicKeys, auth.encrypted));
    }

    // Everything else is for managing your own passkeys.
    const me = await requireUser(req);

    if (path === "/auth/passkeys/register-options") {
      allow("POST");
      const site = passkeySite(req);
      const login = auth.nameSql === "" ? undefined : (await db.query(auth.nameSql, [me])).rows[0]?.["name"];
      const name = typeof login === "string" ? login : `${site.rpId} account`;
      const existing = (await db.query(PASSKEY_SQL.ids, [me])).rows.map((r) => ({ type: "public-key", id: String(r["id"]) }));
      const { challenge, hash } = newChallenge();
      await db.query(PASSKEY_SQL.createChallenge, [hash, "register", me, CHALLENGE_SECONDS]);
      return send(res, 200, {
        challenge,
        rp: { id: site.rpId, name: site.rpId },
        user: { id: Buffer.from(me).toString("base64url"), name, displayName: name },
        pubKeyCredParams: SUPPORTED_ALGORITHMS.map((alg) => ({ type: "public-key", alg })),
        timeout: CHALLENGE_SECONDS * 1000,
        attestation: "none",
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        excludeCredentials: existing,
      });
    }

    if (path === "/auth/passkeys" && method === "POST") {
      const body = await readJson(req) as { response?: Record<string, unknown>; name?: unknown };
      if (typeof body !== "object" || body === null || typeof body.response !== "object" || body.response === null) {
        throw new HttpError(400, "validation_failed", "Send the passkey response from the browser.");
      }
      const name = body.name === undefined ? "Passkey" : body.name;
      if (typeof name !== "string" || [...name].length < 1 || [...name].length > 60 || /[\u0000-\u001f]/.test(name)) {
        throw new HttpError(400, "validation_failed", "name must be 1 to 60 characters.", "name");
      }
      const site = passkeySite(req);
      const challenge = await useChallenge(body.response["clientDataJSON"], "register", me);
      if (Number((await db.query(PASSKEY_SQL.count, [me])).rows[0]?.["n"] ?? 0) >= MAX_PASSKEYS) {
        throw new HttpError(409, "too_many_passkeys", `An account can have at most ${MAX_PASSKEYS} passkeys. Remove one first.`);
      }
      let passkey;
      try {
        passkey = verifyRegistration(
          { clientDataJSON: body.response["clientDataJSON"], attestationObject: body.response["attestationObject"] },
          { challenge, ...site },
        );
      } catch (e) {
        if (e instanceof PasskeyError) throw new HttpError(400, "passkey_failed", e.message);
        throw e;
      }
      try {
        await db.query(PASSKEY_SQL.insert, [passkey.credentialId, me, passkey.publicKey, passkey.algorithm, passkey.signCount, name]);
      } catch (e) {
        if ((e as { code?: string }).code === "23505") throw new HttpError(409, "already_exists", "This passkey is already registered.");
        throw e;
      }
      await audit.record({ action: "passkey_added", userId: me, ip, detail: name.slice(0, 60) });
      return send(res, 201, { id: passkey.credentialId, name });
    }

    if (path === "/auth/passkeys") {
      allow("GET");
      return send(res, 200, { items: (await db.query(PASSKEY_SQL.list, [me])).rows });
    }

    if (one !== null) {
      allow("DELETE");
      const r = await db.query(PASSKEY_SQL.remove, [one[1], me]);
      if ((r.rowCount ?? 0) === 0) throw new HttpError(404, "not_found", "Passkey not found.");
      await audit.record({ action: "passkey_removed", userId: me, ip });
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }
    throw new HttpError(404, "not_found", "No endpoint matches this path.");
  }

  /**
   * The built-in admin endpoints, admins only (session cookie, never API tokens):
   * GET /auth/admin/<slug>?q=&after= lists records (public fields, 50 at a time),
   * and DELETE /auth/admin/<slug>/:id deletes one. Deleting an account works as
   * DELETE /auth/me does, but never your own account or another admin's.
   */
  async function adminRecords(req: IncomingMessage, res: ServerResponse, method: string, model: AdminModel, rawId: string | undefined): Promise<number> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    const allowed = rawId === undefined ? "GET" : "DELETE";
    if (method !== allowed) throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: allowed });
    checkOrigin(req, method);
    const me = await requireUser(req);
    if ((await roleOf(me)) !== "admin") throw new HttpError(403, "forbidden", "You do not have permission to do this.");
    if (hasBody(req)) throw new HttpError(400, "unexpected_body", "This endpoint does not accept a request body.");

    if (rawId === undefined) {
      const search = new URL(req.url ?? "/", "http://localhost").searchParams;
      for (const key of new Set(search.keys())) {
        if (key !== "q" && key !== "after") throw new HttpError(400, "unknown_parameter", "Allowed query parameters: q, after.", key.slice(0, 50));
        if (search.getAll(key).length > 1) throw new HttpError(400, "unknown_parameter", `Query parameter "${key}" appears more than once.`, key);
      }
      const rawQ = search.get("q");
      let q: unknown = null;
      if (rawQ !== null && rawQ !== "") {
        const v = validateQueryParam("q", "Text", rawQ);
        if (!("value" in v)) throw new HttpError(400, "invalid_parameter", v.error, "q");
        q = v.value;
      }
      const rawAfter = search.get("after");
      const after = rawAfter === null ? undefined : decodeCursor(rawAfter, null);
      if (rawAfter !== null && after === undefined) throw new HttpError(400, "invalid_parameter", "after is not a valid cursor. Use the next value from the previous page.", "after");
      const r = await run(model.listSql, [q, after?.id ?? null, ADMIN_PAGE + 1], model.name);
      const rows = r.rows.slice(0, ADMIN_PAGE);
      const last = rows[rows.length - 1];
      const next = r.rows.length > ADMIN_PAGE && last !== undefined ? encodeCursor([String(last["id"])]) : null;
      return send(res, 200, { items: rows.map((row) => reveal(row, model.publicKeys, model.encrypted)), next });
    }

    let decoded: string;
    try {
      decoded = decodeURIComponent(rawId);
    } catch {
      throw new HttpError(400, "bad_path", "The URL path is not valid.");
    }
    const parsed = validatePathParam({ param: "id", kind: "ID" }, decoded);
    if ("error" in parsed) throw new HttpError(400, "invalid_parameter", parsed.error, "id");
    const id = String(parsed.value);
    const ip = clientIp(req);
    if (!model.account) {
      const r = await run(model.deleteSql, [id], model.name);
      if ((r.rowCount ?? 0) === 0) throw new HttpError(404, "not_found", `${model.name} not found.`);
      await audit.record({ action: "record_deleted", userId: me, targetId: id, ip, detail: model.name });
    } else {
      if (id === me) throw new HttpError(403, "forbidden", "You cannot delete your own account here. Use the account page.");
      const adminMessage = "Admins can't be deleted here. Remove their admin role first.";
      const target = (await db.query(auth.roleSql, [id])).rows[0];
      if (target === undefined) throw new HttpError(404, "not_found", `${model.name} not found.`);
      if (target["role"] === "admin") throw new HttpError(403, "forbidden", adminMessage);
      const ghost = auth.account.ghost === null ? undefined : await deletedUser();
      if (ghost === id) throw new HttpError(409, "in_use", "This account can't be deleted.");
      let r: QueryResult;
      try {
        // As with DELETE /auth/me: records that must have an owner go to "Deleted user" in the same
        // statement. The statement itself skips admins, in case the role changed since the check above.
        r = await run(model.deleteSql, ghost === undefined ? [id] : [id, ghost], auth.model);
      } catch (e) {
        if (e instanceof HttpError && e.code === "in_use") {
          throw new HttpError(409, "in_use", "This account still owns records that can't be kept without it. Delete them first, then delete the account.");
        }
        throw e;
      }
      if ((r.rowCount ?? 0) === 0) {
        if ((await roleOf(id)) === "admin") throw new HttpError(403, "forbidden", adminMessage);
        throw new HttpError(404, "not_found", `${model.name} not found.`);
      }
      await audit.record({ action: "account_deleted", userId: me, targetId: id, ip, detail: "admin" });
    }
    res.writeHead(204, SECURITY_HEADERS).end();
    return 204;
  }

  /** PUT /auth/users/:id/role, admins only. Body: { "role": "<role>" } or { "role": null }. */
  async function setRole(req: IncomingMessage, res: ServerResponse, method: string, rawId: string): Promise<number> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    if (method !== "PUT") throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: "PUT" });
    checkOrigin(req, method);
    const me = await currentUser(req);
    if (me === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    if ((await roleOf(me)) !== "admin") throw new HttpError(403, "forbidden", "You do not have permission to do this.");
    let decoded: string;
    try {
      decoded = decodeURIComponent(rawId);
    } catch {
      throw new HttpError(400, "bad_path", "The URL path is not valid.");
    }
    const id = validatePathParam({ param: "id", kind: "ID" }, decoded);
    if ("error" in id) throw new HttpError(400, "invalid_parameter", id.error, "id");
    if (id.value === me) throw new HttpError(403, "forbidden", "You cannot change your own role.");
    const raw = await readJson(req);
    if (typeof raw !== "object" || raw === null || Array.isArray(raw) || Object.keys(raw).join() !== "role") {
      throw new HttpError(400, "validation_failed", 'Send exactly one field: { "role": "<role>" } or { "role": null }.', "role");
    }
    const role = (raw as { role: unknown }).role;
    if (role !== null && (typeof role !== "string" || !auth.roles.includes(role))) {
      throw new HttpError(400, "validation_failed", `role must be one of: ${auth.roles.join(", ")}, or null.`, "role");
    }
    const r = await db.query(auth.setRoleSql, [id.value, role]);
    const row = r.rows[0];
    if (row === undefined) throw new HttpError(404, "not_found", `${auth.model} not found.`);
    await audit.record({ action: "role_changed", userId: me, targetId: String(id.value), ip: clientIp(req), detail: role ?? "none" });
    return send(res, 200, { id: row["id"], role: row["role"] });
  }

  /** DELETE /auth/sessions/:id: log out one of your own devices. */
  async function logOutDevice(req: IncomingMessage, res: ServerResponse, method: string, rawId: string): Promise<number> {
    if (method !== "DELETE") throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: "DELETE" });
    checkOrigin(req, method);
    const me = await requireUser(req);
    if (!UUID_RE.test(rawId)) throw new HttpError(404, "not_found", "Session not found.");
    const r = await db.query(SQL.deleteById, [rawId.toLowerCase(), me]);
    const removed = r.rows[0]?.["token_hash"];
    if (typeof removed !== "string") throw new HttpError(404, "not_found", "Session not found.");
    await audit.record({ action: "session_revoked", userId: me, ip: clientIp(req) });
    if (removed === hashToken(readToken(req.headers.cookie) ?? "")) res.setHeader("Set-Cookie", clearedCookie(secure));
    res.writeHead(204, SECURITY_HEADERS).end();
    return 204;
  }

  async function handleAuth(req: IncomingMessage, res: ServerResponse, path: string, method: string): Promise<number> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    // Every account endpoint has the default limit per address, on top of its own stricter ones.
    // The counter is per route (ids replaced by :id); unknown paths answer 404 without one.
    const adminPath = /^\/auth\/admin\/([a-z0-9-]+)(?:\/([^/]+))?$/.exec(path);
    const adminModel = adminPath === null ? undefined : app.admin?.find((m) => m.slug === adminPath[1]);
    const route = /^\/auth\/users\/[^/]+\/role$/.test(path) ? "/auth/users/:id/role"
      : /^\/auth\/(tokens|sessions|passkeys)\/[^/]+$/.test(path) ? path.replace(/\/[^/]+$/, "/:id")
      : adminModel !== undefined ? `/auth/admin/${adminModel.slug}${adminPath?.[2] !== undefined ? "/:id" : ""}`
      : AUTH_ROUTES.some((r) => r.path === path) || path === "/auth/passkeys" ? path
      : undefined;
    if (route === undefined) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    const authGate = await limited(() => limits.consume(limitKey(`auth ${method} ${route}`, clientIp(req)), DEFAULT_RATE, 60));
    if (!authGate.allowed) throw tooMany(authGate.retryAfter, `Too many requests. Try again in ${authGate.retryAfter} seconds.`);
    if (path === "/auth/passkeys" || path.startsWith("/auth/passkeys/")) return passkeys(req, res, path, method);
    if (adminModel !== undefined) return adminRecords(req, res, method, adminModel, adminPath?.[2]);
    const tokenRoute = /^\/auth\/tokens\/([^/]+)$/.exec(path);
    if (tokenRoute !== null) return revokeToken(req, res, method, tokenRoute[1] ?? "");
    const sessionRoute = /^\/auth\/sessions\/([^/]+)$/.exec(path);
    if (sessionRoute !== null) return logOutDevice(req, res, method, sessionRoute[1] ?? "");
    const roleRoute = /^\/auth\/users\/([^/]+)\/role$/.exec(path);
    if (roleRoute !== null && auth.roles.length > 0) return setRole(req, res, method, roleRoute[1] ?? "");
    const known = AUTH_ROUTES.find((r) => r.path === path);
    if (known === undefined) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    const methods = known.methods.filter((m) => !(path === "/auth/me" && m === "PATCH" && auth.account.profile === null));
    if (!methods.includes(method)) {
      throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: methods.join(", ") });
    }
    checkOrigin(req, method);
    const ip = clientIp(req);

    if (path === "/auth/signup") {
      const gate = await limited(() => limits.consume(limitKey("signup", ip), 10, 3600));
      if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many signups. Try again later.");
      // The answer is the same whether or not the email already has an account,
      // so signup can't be used to find out who has one. The owner of an
      // existing account gets an email instead.
      const bodyValues = await body(req, auth.signup.body);
      const email = String(bodyValues.get(auth.loginKey));
      const existing = await accountFor(email);
      if (existing !== undefined) {
        if (await mayEmail(existing)) deliver(email, MESSAGES.alreadyRegistered(publicUrl));
        return send(res, 202, CHECK_EMAIL);
      }
      let created: string;
      try {
        const r = await run(auth.signup.sql, values(auth.signup.values, new Map(), seal(bodyValues, auth.encrypted), undefined, null), auth.model);
        created = String(r.rows[0]?.["id"]);
      } catch (e) {
        // Someone signed up with the same email at the same moment.
        if (e instanceof HttpError && e.code === "already_exists" && e.field === auth.loginKey) return send(res, 202, CHECK_EMAIL);
        throw e;
      }
      await audit.record({ action: "signup", userId: created, ip });
      await sendLink(created, email, "verify");
      return send(res, 202, CHECK_EMAIL);
    }

    if (path === "/auth/verify-email") {
      const gate = await limited(() => limits.consume(limitKey("email-link", ip), 30, 3600));
      if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many requests. Try again later.");
      const raw = await readJson(req) as { token?: unknown } | null;
      const userId = await useLink(raw?.token, "verify");
      await db.query(EMAIL_SQL.markVerified, [userId]);
      await audit.record({ action: "email_verified", userId, ip });
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    if (path === "/auth/verify-email/resend") {
      await emailGate(ip);
      const email = await emailFrom(req);
      const userId = await accountFor(email);
      if (userId !== undefined && (await unverified(userId))) await sendLink(userId, email, "verify");
      return send(res, 202, CHECK_EMAIL);
    }

    if (path === "/auth/password-reset") {
      await emailGate(ip);
      const email = await emailFrom(req);
      const userId = await accountFor(email);
      if (userId !== undefined) {
        await audit.record({ action: "password_reset_requested", userId, ip });
        await sendLink(userId, email, "reset");
      }
      return send(res, 202, CHECK_EMAIL);
    }

    if (path === "/auth/email") {
      // Change the login email: needs the password, and takes effect only when
      // the link sent to the new address is opened. The answer is the same
      // whether or not the new address already has an account.
      const me = await requireUser(req);
      await emailGate(ip);
      const loginSpec = auth.signup.body.find((f) => f.key === auth.loginKey);
      const v = validateBody(
        [{ ...(loginSpec ?? { kind: "Email", max: 254 }), key: "newEmail", required: true, nullable: false }, { key: "password", kind: "Text", required: true, nullable: false, max: 128 }],
        await readJson(req),
      );
      if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
      await confirmPassword(me, String(v.values.get("password")), "password");
      const newEmail = String(v.values.get("newEmail"));
      if ((await accountFor(newEmail)) === undefined && (await mayEmail(me))) {
        const { token, hash } = newEmailToken();
        await db.query(EMAIL_SQL.deleteTokens, [me, "email"]);
        await db.query(EMAIL_SQL.createEmailChange, [hash, me, CHANGE_SECONDS, newEmail]);
        deliver(newEmail, MESSAGES.changeEmail(publicUrl, token));
      }
      return send(res, 202, CHECK_EMAIL);
    }

    if (path === "/auth/email/confirm") {
      const gate = await limited(() => limits.consume(limitKey("email-link", ip), 30, 3600));
      if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many requests. Try again later.");
      const raw = await readJson(req) as { token?: unknown } | null;
      const token = readEmailToken(raw?.token);
      const row = token === undefined ? undefined : (await db.query(EMAIL_SQL.useEmailChange, [emailTokenHash(token)])).rows[0];
      const userId = row?.["user_id"];
      const newEmail = row?.["new_email"];
      if (typeof userId !== "string" || typeof newEmail !== "string") {
        throw new HttpError(400, "invalid_link", "This link is not valid or has expired. Ask for a new one on your account page.", "token");
      }
      const old = (await db.query(auth.account.emailSql, [userId])).rows[0]?.["email"];
      try {
        await run(auth.account.setEmailSql, [userId, newEmail], auth.model);
      } catch (e) {
        if (e instanceof HttpError && e.code === "already_exists") throw new HttpError(409, "already_exists", "Another account uses this email now. Choose a different one.");
        throw e;
      }
      // The new address is proven to work, so the account counts as confirmed. Links sent to
      // the old address (a password reset, say) stop working: that mailbox may not be the owner's.
      await db.query(EMAIL_SQL.markVerified, [userId]);
      await db.query(EMAIL_SQL.deleteAllTokens, [userId]);
      await audit.record({ action: "email_changed", userId, ip });
      if (typeof old === "string") deliver(old, MESSAGES.emailChanged(publicUrl));
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    if (path === "/auth/password-reset/confirm") {
      const gate = await limited(() => limits.consume(limitKey("email-link", ip), 30, 3600));
      if (!gate.allowed) throw tooMany(gate.retryAfter, "Too many requests. Try again later.");
      const v = validateBody(
        [{ key: "token", kind: "Text", required: true, nullable: false, max: 100 }, auth.account.password],
        await readJson(req),
      );
      if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
      const hash = await hashPassword(String(v.values.get("newPassword")));
      const userId = await useLink(v.values.get("token"), "reset");
      await db.query(auth.account.setPasswordSql, [userId, hash]);
      // Whoever knew the old password is logged out everywhere, and the link
      // proved the email works, so the account counts as confirmed.
      await db.query(SQL.deleteAll, [userId]);
      await db.query(TOKEN_SQL.removeAll, [userId]);
      // Every other pending link (another reset, or an email change someone else asked for) stops working.
      await db.query(EMAIL_SQL.deleteAllTokens, [userId]);
      await db.query(EMAIL_SQL.markVerified, [userId]);
      await audit.record({ action: "password_reset", userId, ip });
      res.setHeader("Set-Cookie", clearedCookie(secure));
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    if (path === "/auth/login") {
      const raw = await readJson(req);
      const v = validateBody(
        [
          { key: auth.loginKey, kind: "Text", required: true, nullable: false, max: 254 },
          { key: auth.passwordKey, kind: "Text", required: true, nullable: false, max: 128 },
        ],
        raw,
      );
      if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
      const email = validateValue({ key: auth.loginKey, kind: "Email" }, v.values.get(auth.loginKey));
      const password = String(v.values.get(auth.passwordKey));
      const account = "value" in email ? String(email.value) : "";
      const ipKey = limitKey("login-ip", ip);
      const accountKey = limitKey("login-account", account);
      const byIp = await limited(() => limits.blocked(ipKey, 20, LOGIN_WINDOW));
      const byAccount = await limited(() => limits.blocked(accountKey, 5, LOGIN_WINDOW));
      if (!byIp.allowed || !byAccount.allowed) {
        await audit.record({ action: "login_blocked", ip, detail: byAccount.allowed ? "address" : "account" });
        throw tooMany(Math.max(byIp.retryAfter, byAccount.retryAfter), "Too many login attempts. Try again later.");
      }

      const r = account === "" ? { rows: [], rowCount: 0 } : await db.query(auth.loginSql, [account]);
      const row = r.rows[0];
      const hash = typeof row?.["hash"] === "string" ? row["hash"] : await dummyHash();
      const valid = await verifyPassword(password, hash);
      if (!valid || row === undefined) {
        await limited(() => limits.consume(ipKey, 20, LOGIN_WINDOW));
        await limited(() => limits.consume(accountKey, 5, LOGIN_WINDOW));
        // The account id is recorded when the account exists, to spot attacks on it.
        await audit.record({ action: "login_failed", userId: row === undefined ? undefined : String(row["id"]), ip, detail: row === undefined ? "unknown account" : "wrong password" });
        throw new HttpError(401, "invalid_credentials", `The ${auth.loginKey} or ${auth.passwordKey} is incorrect.`);
      }
      await limited(async () => (await limits.clear(accountKey), { allowed: true, retryAfter: 0 }));
      const userId = String(row["id"]);
      if (await unverified(userId)) {
        await audit.record({ action: "login_failed", userId, ip, detail: "email not confirmed" });
        throw notVerified();
      }
      await startSession(req, res, userId);
      await audit.record({ action: "login", userId, ip });
      const me = await db.query(auth.meSql, [userId]);
      return send(res, 200, reveal(me.rows[0] ?? {}, auth.publicKeys, auth.encrypted));
    }

    if (path === "/auth/password") {
      const me = await requireUser(req);
      const v = validateBody(
        [{ key: "currentPassword", kind: "Text", required: true, nullable: false, max: 128 }, auth.account.password],
        await readJson(req),
      );
      if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
      await confirmPassword(me, String(v.values.get("currentPassword")), "currentPassword");
      await db.query(auth.account.setPasswordSql, [me, await hashPassword(String(v.values.get("newPassword")))]);
      // Everyone else using this account is logged out; this session stays.
      await db.query(SQL.deleteOthers, [me, hashToken(readToken(req.headers.cookie) ?? "")]);
      // Pending emailed links (such as an email change) were asked for before the change: cancel them.
      await db.query(EMAIL_SQL.deleteAllTokens, [me]);
      await audit.record({ action: "password_changed", userId: me, ip });
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    if (path === "/auth/logout-all") {
      const me = await requireUser(req);
      await db.query(SQL.deleteAll, [me]);
      await audit.record({ action: "logout_all", userId: me, ip });
      res.setHeader("Set-Cookie", clearedCookie(secure));
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    if (path === "/auth/me" && method === "PATCH" && auth.account.profile !== null) {
      const me = await requireUser(req);
      const profile = auth.account.profile;
      const bodyValues = seal(await body(req, profile.body), auth.encrypted);
      await checkFiles(profile.files, bodyValues, new Map(), me);
      const r = await run(profile.sql, values(profile.values, new Map(), bodyValues, me, null), auth.model);
      const row = r.rows[0];
      if (row === undefined) throw new HttpError(401, "login_required", "You need to log in.");
      return send(res, 200, reveal(row, auth.publicKeys, auth.encrypted));
    }

    if (path === "/auth/me" && method === "DELETE") {
      const me = await requireUser(req);
      const v = validateBody([{ key: "password", kind: "Text", required: true, nullable: false, max: 128 }], await readJson(req));
      if (!v.ok) throw new HttpError(400, "validation_failed", v.message, v.field || undefined);
      await confirmPassword(me, String(v.values.get("password")), "password");
      const ghost = auth.account.ghost === null ? undefined : await deletedUser();
      if (ghost === me) throw new HttpError(409, "in_use", "This account can't be deleted.");
      try {
        // Records that must have an owner go to the "Deleted user" account in the same statement.
        await run(auth.account.deleteSql, ghost === undefined ? [me] : [me, ghost], auth.model);
      } catch (e) {
        if (e instanceof HttpError && e.code === "in_use") {
          throw new HttpError(409, "in_use", "This account still owns records that can't be kept without it. Delete them first, then delete the account.");
        }
        throw e;
      }
      await audit.record({ action: "account_deleted", userId: me, targetId: me, ip });
      res.setHeader("Set-Cookie", clearedCookie(secure));
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    if (path === "/auth/privacy") {
      // The privacy notice: public, generated from the app's models and fixed text.
      if (app.privacy === undefined) throw new HttpError(404, "not_found", "This app has no privacy line.");
      return send(res, 200, privacyNotice(app.privacy, {
        contact: options.privacyContact ?? "",
        auditRetentionDays: options.auditRetentionDays ?? DEFAULT_AUDIT_RETENTION_DAYS,
        emailService: options.mailer === undefined || options.emailService === "development" ? "development" : "Resend",
        ...(options.fileStore !== undefined ? { fileStorage: options.fileStore.kind } : {}),
      }));
    }

    if (path === "/auth/me/export") {
      // Everything stored about you, except your password hash. Not for API tokens: /auth/* needs the session cookie.
      const me = await requireUser(req);
      const gate = await limited(() => limits.consume(limitKey("export", me), 5, 3600));
      if (!gate.allowed) throw tooMany(gate.retryAfter, "You can download your data 5 times an hour. Try again later.");
      const account = (await db.query(auth.export.account.sql, [me])).rows[0];
      if (account === undefined) throw new HttpError(401, "login_required", "You need to log in.");
      const records: Record<string, unknown[]> = {};
      const truncated: string[] = [];
      for (const part of auth.export.records) {
        const rows = (await db.query(part.sql, [me])).rows;
        if (rows.length > EXPORT_LIMIT) truncated.push(part.model);
        records[part.model] = rows.slice(0, EXPORT_LIMIT).map((row) => reveal(row, Object.keys(row), part.encrypted));
      }
      const list = async (sql: string, keys: readonly string[]) => (await db.query(sql, [me, ""])).rows.map((row) => pick(row, keys));
      const data = {
        exportedAt: new Date(now()).toISOString(),
        account: reveal(account, Object.keys(account), auth.encrypted),
        records,
        ...(truncated.length > 0 ? { truncated } : {}),
        devices: await list(SQL.list, ["device", "createdAt", "lastSeenAt"]),
        passkeys: (await db.query(PASSKEY_SQL.list, [me])).rows.map((row) => pick(row, ["name", "createdAt", "lastUsedAt"])),
        apiTokens: (await db.query(TOKEN_SQL.list, [me])).rows.map((row) => ({ ...pick(row, ["name", "createdAt", "expiresAt", "lastUsedAt"]), endpoints: parseEndpoints(row["endpoints"]) })),
        securityLog: (await audit.recent(me, 500)).map((row) => pick(row, ["at", "action", "ip", "detail"])),
      };
      await audit.record({ action: "data_exported", userId: me, ip });
      return send(res, 200, data, { "Content-Disposition": 'attachment; filename="my-data.json"' });
    }

    if (path === "/auth/tokens") return tokens(req, res, method);

    if (path === "/auth/sessions") {
      const me = await requireUser(req);
      const r = await db.query(SQL.list, [me, hashToken(readToken(req.headers.cookie) ?? "")]);
      return send(res, 200, { items: r.rows.map((row) => pick(row, ["id", "device", "createdAt", "lastSeenAt", "current"])) });
    }

    if (path === "/auth/audit") {
      // Admins only: the newest entries, optionally for one account (?account=<id>).
      const me = await requireUser(req);
      if (!auth.roles.includes("admin") || (await roleOf(me)) !== "admin") throw new HttpError(403, "forbidden", "You do not have permission to do this.");
      const url = new URL(req.url ?? "/", "http://localhost");
      for (const key of new Set(url.searchParams.keys())) {
        if (key !== "account" && key !== "limit") throw new HttpError(400, "unknown_parameter", "Allowed query parameters: account, limit.", key.slice(0, 50));
      }
      const account = url.searchParams.get("account");
      if (account !== null && !("value" in validatePathParam({ param: "account", kind: "ID" }, account))) {
        throw new HttpError(400, "invalid_parameter", "account must be an ID (UUID).", "account");
      }
      const rawLimit = url.searchParams.get("limit") ?? "100";
      const limit = /^\d{1,3}$/.test(rawLimit) ? Number(rawLimit) : 0;
      if (limit < 1 || limit > 500) throw new HttpError(400, "invalid_parameter", "limit must be a whole number from 1 to 500.", "limit");
      return send(res, 200, { items: await audit.recent(account, limit) });
    }

    if (path === "/auth/logout") {
      const token = readToken(req.headers.cookie);
      if (token !== undefined) {
        const who = await currentUser(req);
        await db.query(SQL.delete, [hashToken(token)]);
        if (who !== undefined) await audit.record({ action: "logout", userId: who, ip });
      }
      res.setHeader("Set-Cookie", clearedCookie(secure));
      res.writeHead(204, SECURITY_HEADERS).end();
      return 204;
    }

    // GET /auth/me
    const userId = await currentUser(req);
    if (userId === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    const r = await db.query(auth.meSql, [userId]);
    const row = r.rows[0];
    if (row === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    return send(res, 200, reveal(row, auth.publicKeys, auth.encrypted));
  }
}

/** One line for the log: the error's code or name and message. Never request data. */
function describeError(e: unknown): string {
  if (!(e instanceof Error)) return "non-error thrown";
  const code = (e as { code?: unknown }).code;
  return `${typeof code === "string" ? `${code} ` : ""}${e.name}: ${e.message}`;
}

function send(res: ServerResponse, status: number, payload: unknown, headers: Readonly<Record<string, string>> = {}): number {
  res.writeHead(status, { ...SECURITY_HEADERS, ...headers });
  res.end(JSON.stringify(payload));
  return status;
}

/**
 * Delete files that no record has used for a day: first their rows (a record
 * can't link to a file whose row is gone), then the files in storage. Up to
 * 1,000 per run. Returns how many were deleted.
 */
export async function sweepFiles(app: App, db: Db, store: FileStore, log: (line: string) => void): Promise<number> {
  const sql = app.files?.sweepSql;
  if (sql === undefined) return 0;
  let total = 0;
  for (let batch = 0; batch < 10; batch++) {
    let rows: readonly Record<string, unknown>[];
    try {
      rows = (await db.query(sql, [])).rows;
    } catch (e) {
      // A file was used again at the same moment (foreign key): try again on the next run.
      if ((e as { code?: string }).code === "23503") return total;
      throw e;
    }
    for (const row of rows) {
      const name = String(row["id"]).slice("/_rizo/files/".length);
      try {
        await store.remove(name);
      } catch (e) {
        log(`could not delete a file from ${store.kind}: ${e instanceof Error ? e.message : String(e)}`);
        // Put back a row that nothing can use (it is for no field), so the next run tries again.
        await db.query(FILE_SQL.retry, [row["id"], row["type"] ?? "application/octet-stream", ""]).catch(() => undefined);
      }
    }
    total += rows.length;
    if (rows.length < 100) break;
  }
  return total;
}

/**
 * Give the admin role to existing accounts with these login emails. Accounts
 * created later are not affected, so nobody can claim admin by signing up
 * with a listed email. Returns the number of accounts changed.
 */
export async function grantAdmins(app: App, db: Db, emails: readonly string[]): Promise<number> {
  const auth = app.auth;
  if (auth === null || !auth.roles.includes("admin") || auth.grantAdminSql === "") return 0;
  const list = emails.map((e) => e.trim().toLowerCase()).filter(Boolean);
  if (list.length === 0) return 0;
  const r = await db.query(auth.grantAdminSql, [list]);
  return r.rowCount ?? 0;
}

/** Requests a minute per address for account endpoints and pages (the same default as api endpoints). */
const DEFAULT_RATE = 120;

/** The health check's only query. */
const HEALTH_SQL = "SELECT 1";

/** How long requests in flight get to finish after SIGTERM, before the process exits anyway. */
export const SHUTDOWN_SECONDS = 10;

/** Default limit for one database query, in milliseconds. */
export const DEFAULT_STATEMENT_TIMEOUT_MS = 5000;

/**
 * Database connection settings from environment variables. Every query the
 * app runs is cancelled by PostgreSQL after the statement timeout, so one slow
 * query can't tie up the database.
 */
export function poolConfig(env: Readonly<Record<string, string | undefined>>): {
  connectionString: string;
  max: number;
  statement_timeout: number;
} {
  const url = env["DATABASE_URL"] ?? "";
  const max = Number(env["RIZO_DB_POOL_SIZE"] ?? "10");
  const timeout = Number(env["RIZO_DB_STATEMENT_TIMEOUT_MS"] ?? String(DEFAULT_STATEMENT_TIMEOUT_MS));
  if (!Number.isInteger(max) || max < 1 || max > 1000) throw new Error("RIZO_DB_POOL_SIZE must be a whole number from 1 to 1000");
  if (!Number.isInteger(timeout) || timeout < 100 || timeout > 600_000) {
    throw new Error("RIZO_DB_STATEMENT_TIMEOUT_MS must be a whole number from 100 to 600000");
  }
  return { connectionString: url, max, statement_timeout: timeout };
}

/** Start the server. Configuration comes from environment variables. */
export function startServer(app: App): void {
  const url = process.env["DATABASE_URL"];
  if (url === undefined || url === "") {
    process.stderr.write(
      "rizo: DATABASE_URL is not set.\n  fix: Start the server with DATABASE_URL=postgres://user:password@localhost:5432/app node server.ts\n",
    );
    process.exit(1);
  }
  const insecure = process.env["RIZO_DEV_INSECURE_COOKIES"] === "1";
  if (insecure) process.stderr.write("rizo: WARNING: session cookies are not marked Secure. Use this only for local development over http.\n");
  let config: ReturnType<typeof poolConfig>;
  try {
    config = poolConfig(process.env);
  } catch (e) {
    process.stderr.write(`rizo: ${e instanceof Error ? e.message : String(e)}\n`);
    process.exit(1);
  }
  let email: ReturnType<typeof emailConfig> | undefined;
  if (app.auth !== null) {
    try {
      email = emailConfig(process.env, (text) => process.stdout.write(text));
    } catch (e) {
      process.stderr.write(`rizo: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(1);
    }
    if (email.dev) process.stderr.write("rizo: WARNING: RIZO_EMAIL_DEV=1, so emails are printed here instead of sent. Use this only for local development.\n");
  }
  let privacyContact: string | undefined;
  if (app.privacy !== undefined) {
    const contact = validateValue({ key: "RIZO_PRIVACY_CONTACT", kind: "Email" }, process.env["RIZO_PRIVACY_CONTACT"] ?? "");
    if (!("value" in contact)) {
      process.stderr.write(
        "rizo: RIZO_PRIVACY_CONTACT is not set to an email address, but this app declares privacy rules.\n" +
          "  fix: Set RIZO_PRIVACY_CONTACT to the address people should write to about their data, e.g. RIZO_PRIVACY_CONTACT=privacy@blog.example. It is shown on the privacy page.\n",
      );
      process.exit(1);
    }
    privacyContact = String(contact.value);
  }
  let encryptionKeys: Keys | undefined;
  if ((app.encrypted ?? []).length > 0) {
    try {
      encryptionKeys = parseKeys(process.env["RIZO_ENCRYPTION_KEYS"]);
    } catch (e) {
      process.stderr.write(`rizo: ${e instanceof Error ? e.message : String(e)}\n`);
      process.exit(1);
    }
  }
  let fileStore: FileStore | undefined;
  if (app.files !== undefined) {
    const found = fileStoreFromEnv(process.env);
    if ("error" in found) {
      process.stderr.write(`rizo: ${found.error}\n  fix: Set RIZO_S3_BUCKET, RIZO_S3_REGION, RIZO_S3_ACCESS_KEY_ID and RIZO_S3_SECRET_ACCESS_KEY (and RIZO_S3_ENDPOINT outside AWS), or unset RIZO_S3_BUCKET to keep files in RIZO_UPLOAD_DIR.\n`);
      process.exit(1);
    }
    fileStore = found.store;
    process.stdout.write(`rizo: files are stored in ${fileStore.kind === "local" ? `the folder ${process.env["RIZO_UPLOAD_DIR"]?.trim() || "./uploads"}` : "S3-compatible storage"}\n`);
  }
  let openapi: string | undefined;
  try {
    openapi = readFileSync(new URL("../openapi.json", import.meta.url), "utf8");
  } catch {
    openapi = undefined;
  }
  const pool = new pg.Pool(config);
  let shuttingDown = false;
  const handler = createRequestHandler(app, {
    shuttingDown: () => shuttingDown,
    ...(openapi === undefined ? {} : { openapi }),
    ...(encryptionKeys === undefined ? {} : { encryptionKeys }),
    ...(fileStore === undefined ? {} : { fileStore }),
    ...(privacyContact === undefined ? {} : { privacyContact }),
    ...(email === undefined ? {} : { emailService: email.dev ? "development" as const : "Resend" as const }),
    auditRetentionDays: Number(process.env["RIZO_AUDIT_RETENTION_DAYS"] ?? String(DEFAULT_AUDIT_RETENTION_DAYS)),
    ...(email === undefined ? {} : { mailer: email.mailer, publicUrl: email.publicUrl }),
    db: { query: (sql, vals) => pool.query(sql, vals) },
    secureCookies: !insecure,
    trustProxy: process.env["RIZO_TRUST_PROXY"] === "1",
    allowedOrigins: (process.env["RIZO_ALLOWED_ORIGINS"] ?? "").split(",").map((s) => s.trim()).filter(Boolean),
  });
  const server = createServer((req, res) => void handler(req, res));
  // Delete expired rate-limit counters every ten minutes.
  const sweeper = new Limits({ query: (sql, vals) => pool.query(sql, vals) });
  const auditLog = new Audit({ query: (sql, vals) => pool.query(sql, vals) }, (line) => process.stderr.write(`rizo: ${line}\n`));
  const retention = Number(process.env["RIZO_AUDIT_RETENTION_DAYS"] ?? String(DEFAULT_AUDIT_RETENTION_DAYS));
  if (!Number.isInteger(retention) || retention < 1 || retention > 3650) {
    process.stderr.write("rizo: RIZO_AUDIT_RETENTION_DAYS must be a whole number from 1 to 3650\n");
    process.exit(1);
  }
  // Delete expired rate-limit counters and audit entries older than the retention period.
  const sweep = (): void => {
    void sweeper.sweep().catch(() => undefined);
    if (app.auth !== null) {
      void pool.query(PASSKEY_SQL.sweepChallenges).catch(() => undefined);
      void pool.query(EMAIL_SQL.sweepTokens).catch(() => undefined);
      void pool.query(SQL.sweep).catch(() => undefined);
      void pool.query(TOKEN_SQL.sweep).catch(() => undefined);
    }
    void auditLog.sweep(retention).catch(() => undefined);
    // Records past their model's `keep`, each batch recorded in the audit log.
    void expireRecords(app, { query: (sql, vals) => pool.query(sql, vals) }).then(
      (done) => Promise.all(done.map((d) => auditLog.record({ action: "records_expired", detail: `${d.model}: ${d.deleted}` }))),
      (e: unknown) => process.stderr.write(`rizo: could not delete expired records: ${describeError(e)}\n`),
    );
    // Files no record uses any more (and uploads never used), after a day.
    if (fileStore !== undefined) {
      void sweepFiles(app, { query: (sql, vals) => pool.query(sql, vals) }, fileStore, (line) => process.stderr.write(`rizo: ${line}\n`)).catch(
        (e: unknown) => process.stderr.write(`rizo: could not delete unused files: ${describeError(e)}\n`),
      );
    }
  };
  setInterval(sweep, 10 * 60_000).unref();
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  const port = Number(process.env["PORT"] ?? "3000");
  const host = process.env["HOST"] ?? "127.0.0.1";
  const adminEmails = (process.env["RIZO_ADMIN_EMAILS"] ?? "").split(",");
  if (adminEmails.some((e) => e.trim() !== "")) {
    if (app.auth === null || !app.auth.roles.includes("admin")) {
      process.stderr.write("rizo: RIZO_ADMIN_EMAILS is set, but this app declares no roles. Ignoring it.\n");
    } else {
      grantAdmins(app, { query: (sql, vals) => pool.query(sql, vals) }, adminEmails).then(
        (n) => {
          process.stdout.write(`rizo: RIZO_ADMIN_EMAILS granted admin to ${n} existing account(s)\n`);
          if (n > 0) void auditLog.record({ action: "admin_granted", detail: `${n} existing account(s) from RIZO_ADMIN_EMAILS` });
        },
        (e: unknown) => process.stderr.write(`rizo: could not apply RIZO_ADMIN_EMAILS: ${describeError(e)}\n`),
      );
    }
  }
  server.listen(port, host, () => process.stdout.write(`rizo: listening on http://${host}:${port}\n`));
  // Graceful shutdown: stop taking connections (the health check now says 503),
  // let requests in flight finish, then close the database pool. If they take
  // longer than SHUTDOWN_SECONDS, exit anyway.
  const stop = (): void => {
    if (shuttingDown) return;
    shuttingDown = true;
    process.stdout.write("rizo: shutting down, finishing requests in progress...\n");
    const force = setTimeout(() => {
      process.stderr.write(`rizo: requests still running after ${SHUTDOWN_SECONDS} seconds; stopping anyway\n`);
      process.exit(1);
    }, SHUTDOWN_SECONDS * 1000);
    force.unref();
    server.close(() => {
      void pool.end().finally(() => {
        process.stdout.write("rizo: stopped\n");
        process.exit(0);
      });
    });
    server.closeIdleConnections();
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
