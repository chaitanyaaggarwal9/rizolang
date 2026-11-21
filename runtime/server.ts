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
import { randomUUID } from "node:crypto";
import { type IncomingMessage, type ServerResponse, createServer } from "node:http";
import pg from "pg";
import { hashPassword, dummyHash, verifyPassword } from "./password.ts";
import { RateLimiter } from "./ratelimit.ts";
import { SESSION_SECONDS, SQL, clearedCookie, hashToken, newToken, readToken, sessionCookie } from "./session.ts";
import type { App, FieldSpec, Route, ValueSource } from "./types.ts";
import { validateBody, validatePathParam, validateValue } from "./validate.ts";

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

interface AuthRoutes {
  readonly method: string;
  readonly path: string;
}
const AUTH_ROUTES: readonly AuthRoutes[] = [
  { method: "POST", path: "/auth/signup" },
  { method: "POST", path: "/auth/login" },
  { method: "POST", path: "/auth/logout" },
  { method: "GET", path: "/auth/me" },
];

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

  const loginByIp = new RateLimiter(20, 15 * 60_000, now);
  const loginByAccount = new RateLimiter(5, 15 * 60_000, now);
  const signupByIp = new RateLimiter(10, 60 * 60_000, now);

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
      } else {
        const { route, params } = match(method, url.pathname);
        pattern = route.pattern;
        status = await handleRoute(req, res, route, params);
      }
    } catch (e) {
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

  function match(method: string, pathname: string): Matched {
    let parts: string[];
    try {
      parts = pathname === "/" ? [] : pathname.slice(1).split("/").map(decodeURIComponent);
    } catch {
      throw new HttpError(400, "bad_path", "The URL path is not valid.");
    }
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
    if (origin === undefined) return;
    if (allowedOrigins.has(origin)) return;
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

  async function currentUser(req: IncomingMessage): Promise<string | undefined> {
    const token = readToken(req.headers.cookie);
    if (token === undefined) return undefined;
    const r = await db.query(SQL.lookup, [hashToken(token)]);
    const id = r.rows[0]?.["user_id"];
    return typeof id === "string" ? id : undefined;
  }

  async function startSession(res: ServerResponse, userId: string): Promise<void> {
    const token = newToken();
    await db.query(SQL.deleteExpired, [userId]);
    await db.query(SQL.create, [hashToken(token), userId, SESSION_SECONDS]);
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

  function values(sources: readonly ValueSource[], params: ReadonlyMap<string, unknown>, bodyValues: ReadonlyMap<string, unknown>, me: string | undefined): unknown[] {
    return sources.map((s) => {
      switch (s.from) {
        case "path": return params.get(s.name);
        case "me": return me;
        case "body": return bodyValues.get(s.key) ?? null;
        case "provided": return bodyValues.has(s.key);
        case "const": return s.value;
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
        case "23514":
        case "23502":
        case "22P02":
        case "22001":
          throw new HttpError(400, "validation_failed", "A value is not valid.");
        default:
          throw e;
      }
    }
  }

  async function handleRoute(req: IncomingMessage, res: ServerResponse, route: Route, params: ReadonlyMap<string, unknown>): Promise<number> {
    checkOrigin(req, route.method);
    let me: string | undefined;
    if (route.access === "login") {
      me = await currentUser(req);
      if (me === undefined) throw new HttpError(401, "login_required", "You need to log in.");
    }
    let bodyValues: ReadonlyMap<string, unknown> = new Map();
    if (route.body === null) {
      if (hasBody(req)) throw new HttpError(400, "unexpected_body", "This endpoint does not accept a request body.");
    } else {
      bodyValues = await body(req, route.body);
    }
    const r = await run(route.sql, values(route.values, params, bodyValues, me), route.model);
    switch (route.result) {
      case "list":
        return send(res, 200, r.rows.map((row) => pick(row, route.publicKeys)));
      case "created":
        return send(res, 201, pick(r.rows[0] ?? {}, route.publicKeys));
      case "one": {
        const row = r.rows[0];
        if (row === undefined) throw new HttpError(404, "not_found", `${route.model} not found.`);
        return send(res, 200, pick(row, route.publicKeys));
      }
      case "none":
        if ((r.rowCount ?? 0) === 0) throw new HttpError(404, "not_found", `${route.model} not found.`);
        res.writeHead(204, SECURITY_HEADERS).end();
        return 204;
    }
  }

  // ----------------------------------------------------------------- auth

  async function handleAuth(req: IncomingMessage, res: ServerResponse, path: string, method: string): Promise<number> {
    const auth = app.auth;
    if (auth === null) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    const known = AUTH_ROUTES.find((r) => r.path === path);
    if (known === undefined) throw new HttpError(404, "not_found", "No endpoint matches this path.");
    if (known.method !== method) {
      throw new HttpError(405, "method_not_allowed", `This path does not support ${method}.`, undefined, { Allow: known.method });
    }
    checkOrigin(req, method);
    const ip = clientIp(req);

    if (path === "/auth/signup") {
      const wait = signupByIp.retryAfter(ip);
      if (wait > 0) throw new HttpError(429, "too_many_requests", "Too many signups. Try again later.", undefined, { "Retry-After": String(wait) });
      signupByIp.hit(ip);
      const bodyValues = await body(req, auth.signup.body);
      const r = await run(auth.signup.sql, values(auth.signup.values, new Map(), bodyValues, undefined), auth.model);
      const row = r.rows[0] ?? {};
      await startSession(res, String(row["id"]));
      return send(res, 201, pick(row, auth.publicKeys));
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
      const wait = Math.max(loginByIp.retryAfter(ip), loginByAccount.retryAfter(account));
      if (wait > 0) throw new HttpError(429, "too_many_requests", "Too many login attempts. Try again later.", undefined, { "Retry-After": String(wait) });

      const r = account === "" ? { rows: [], rowCount: 0 } : await db.query(auth.loginSql, [account]);
      const row = r.rows[0];
      const hash = typeof row?.["hash"] === "string" ? row["hash"] : await dummyHash();
      const valid = await verifyPassword(password, hash);
      if (!valid || row === undefined) {
        loginByIp.hit(ip);
        loginByAccount.hit(account);
        throw new HttpError(401, "invalid_credentials", `The ${auth.loginKey} or ${auth.passwordKey} is incorrect.`);
      }
      loginByAccount.reset(account);
      const userId = String(row["id"]);
      await startSession(res, userId);
      const me = await db.query(auth.meSql, [userId]);
      return send(res, 200, pick(me.rows[0] ?? {}, auth.publicKeys));
    }

    if (path === "/auth/logout") {
      const token = readToken(req.headers.cookie);
      if (token !== undefined) await db.query(SQL.delete, [hashToken(token)]);
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
    return send(res, 200, pick(row, auth.publicKeys));
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
  const pool = new pg.Pool({ connectionString: url, max: Number(process.env["RIZO_DB_POOL_SIZE"] ?? "10") });
  const handler = createRequestHandler(app, {
    db: { query: (sql, vals) => pool.query(sql, vals) },
    secureCookies: !insecure,
    trustProxy: process.env["RIZO_TRUST_PROXY"] === "1",
    allowedOrigins: (process.env["RIZO_ALLOWED_ORIGINS"] ?? "").split(",").map((s) => s.trim()).filter(Boolean),
  });
  const server = createServer((req, res) => void handler(req, res));
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  const port = Number(process.env["PORT"] ?? "3000");
  const host = process.env["HOST"] ?? "127.0.0.1";
  server.listen(port, host, () => process.stdout.write(`rizo: listening on http://${host}:${port}\n`));
  const stop = (): void => {
    server.close(() => void pool.end());
  };
  process.on("SIGTERM", stop);
  process.on("SIGINT", stop);
}
