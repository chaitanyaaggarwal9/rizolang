<div align="center">

# Rizo Lang

**A modern, simple and secure web language for the AI era.**

Write your data models and endpoints in a few readable lines. Rizo Lang compiles them into a PostgreSQL schema, TypeScript types and a ready-to-run Node.js server, with login, validation and permission checks built in.

[![CI](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/ci.yml/badge.svg)](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/ci.yml)
[![CodeQL](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/codeql.yml/badge.svg)](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/codeql.yml)
[![npm](https://img.shields.io/npm/v/rizolang)](https://www.npmjs.com/package/rizolang)
[![Socket Badge](https://badge.socket.dev/npm/package/rizolang)](https://socket.dev/npm/package/rizolang)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

![.rz Language](https://img.shields.io/badge/.rz-language-0ea5e9)
![Full-Stack](https://img.shields.io/badge/full--stack-web-8b5cf6)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Open Source](https://img.shields.io/badge/open%20source-Apache--2.0-10b981)
[![npm](https://img.shields.io/npm/v/rizolang?color=cb3837&logo=npm)](https://www.npmjs.com/package/rizolang)

[Website](https://rizobot.com) · [Language spec](docs/SPEC.md) · [Compact spec for AI](docs/SPEC-COMPACT.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md)

</div>

---

## Contents

- [Why Rizo Lang?](#why-rizo-lang)
- [A quick look](#a-quick-look)
- [What the compiler generates](#what-the-compiler-generates)
- [Getting started](#getting-started)
- [Language tour](#language-tour)
- [Security model](#security-model)
- [Error messages](#error-messages)
- [Using Rizo Lang with AI](#using-rizo-lang-with-ai)
- [Project status and roadmap](#project-status-and-roadmap)
- [Project structure](#project-structure)
- [Development](#development)
- [Contributing, security and license](#contributing-security-and-license)

---

## Why Rizo Lang?

Most security bugs in web apps are ordinary mistakes:
- a query built from text,
- a password returned in a response,
- an endpoint that forgot to check who is calling,
- a user editing someone else's data.

Rizo Lang is designed so those mistakes **cannot be written**, not just discouraged.

| Principle | What it means in practice |
|-----------|---------------------------|
| **Dangerous mistakes are impossible** | There is no raw SQL. Every query is generated and parameterized. |
| **Strict and clear** | Static types everywhere. Every error says what went wrong, where (file:line:column) and how to fix it. |
| **Small** | The whole language fits in a [short spec](docs/SPEC.md) that an AI can learn from in one read. |
| **Secure by default** | Passwords are hashed and never returned. Input is validated automatically. Login and ownership are part of the syntax. |
| **AI-first** | The [compact spec](docs/SPEC-COMPACT.md) works as a system prompt, so even small models can write correct Rizo Lang. |

Rizo Lang is part of the [Rizo](https://rizobot.com) ecosystem, alongside **Rizo**, a source-available BYOK AI coding assistant for VS Code. It compiles into technology you already use. Its only runtime is a small, readable library that is copied into your project.

---

## A quick look

```rizo
// app.rz: a small blog
auth User by email

model User {
  email: Email unique private
  password: Password min 12
  name: Text max 100
}

model Post {
  author: User
  title: Text min 1 max 200
  body: Text
  published: Bool
}

api GET /api/posts -> list Post.public {
  public
  return db.Post.list(published = true, order title, limit 20)
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

page / {
  public
  title "My blog"
  show GET /api/posts/feed
}

api GET /api/posts/feed -> list Post.public {
  public
  return db.Post.list(published = true)
}
```

```sh
rizolang build app.rz
```

That's a complete backend:
- **Accounts:** signup, login, logout and sessions.
- **Validation:** every request body and path parameter is checked against your models.
- **Ownership:** only a post's author can change or delete it. Everyone else gets 404.
- **Privacy:** emails and passwords are never returned by any endpoint.
- **Web pages:** `page /` is a real web page listing the posts, with no HTML to write and no way to inject any.

---

## What the compiler generates

`rizolang build app.rz` writes everything to `dist/`:

| File | What it is |
|------|------------|
| `schema.sql` | PostgreSQL tables with `NOT NULL`, `UNIQUE`, `CHECK` and foreign-key constraints, plus the sessions table |
| `types.ts` | TypeScript types: `User` (server-only), `UserPublic` (safe to return) and `UserInput` (what clients send) |
| `routes.ts` | Every endpoint as plain data, **with its SQL written out in full** so you can review exactly what runs |
| `server.ts` | The entry point: `node server.ts` |
| `openapi.json` | An OpenAPI 3.1 description of every endpoint, with its access rules, also served at `/_rizo/openapi.json` for agents and tools |
| `runtime/` | A small Rizo runtime: validation, sessions, password hashing and the HTTP server |
| `migrate.ts`, `migrations/` | Applies your project's migrations to the database |
| `Dockerfile`, `.dockerignore` | A container image: Node.js 24 on Alpine, only `pg` installed, a non-root user and a health check |
| `reencrypt.ts` | Only with `encrypted` fields: moves stored values to a new encryption key |
| `package.json`, `tsconfig.json` | Installs the only dependency, the [`pg`](https://www.npmjs.com/package/pg) driver, and type-checks the app |

A file with only models (no `auth`, `api` or `page`) produces just `schema.sql` and `types.ts` in `dist/`, plus its migrations. `rizolang check app.rz` checks a file without writing anything.

Part of the `PATCH /api/posts/:id` route above, as it appears in `routes.ts`:

```ts
{
  method: 'PATCH',
  pattern: '/api/posts/:id',
  access: 'login',
  sql: 'UPDATE "posts" SET "title" = CASE WHEN $3 THEN $4 ELSE "title" END, ... WHERE "id" = $1 AND "author_id" = $2 RETURNING "id", "author_id" AS "author", ...',
  values: [{ from: 'path', name: 'id' }, { from: 'me' }, ...],
}
```

---

## Getting started

### Requirements

- **Node.js 22.12+** to run the compiler. The generated server needs **22.18+**, which runs TypeScript directly; Node 24 LTS is recommended.
- **PostgreSQL 13+**

### Install the compiler

Rizo Lang is on npm as [`rizolang`](https://www.npmjs.com/package/rizolang):

```sh
npx rizolang build app.rz          # run without installing
npm install --save-dev rizolang    # or add it to your project
```

To build from source instead:

```sh
git clone https://github.com/chaitanyaaggarwal9/rizolang.git
cd rizolang
npm ci
npm run build
npm link              # optional: makes the `rizolang` command available everywhere
```

### Build and run an app

For development, one command builds, applies migrations, runs the server with development settings, and restarts it whenever you save:

```sh
DATABASE_URL=postgres://user:pass@localhost:5432/app npx rizolang dev app.rz
```

For production, run the steps yourself:

```sh
npx rizolang build app.rz
cd dist
npm install
export DATABASE_URL=postgres://user:pass@localhost:5432/app
node migrate.ts
RIZO_PUBLIC_URL=http://localhost:3000 RIZO_EMAIL_DEV=1 node server.ts
```

- `npm install` installs `pg`, the only dependency.
- To deploy with Docker: `docker build -t my-app dist`, then `docker run --rm -e DATABASE_URL=... my-app node migrate.ts` and `docker run -p 3000:3000 -e DATABASE_URL=... my-app` (with your other settings). Health checks go to `/_rizo/health`, and `docker stop` lets requests in progress finish.
- `node migrate.ts` creates or updates the tables.
- Apps that declare `privacy for` also need `RIZO_PRIVACY_CONTACT=privacy@yourdomain.com`, the address shown on the privacy page.
- Apps with accounts send email (to confirm addresses and reset passwords). `RIZO_EMAIL_DEV=1` prints emails in the terminal instead, for local development. In production, set `RIZO_EMAIL_API_KEY` and `RIZO_EMAIL_FROM` for [Resend](https://resend.com) and your real `RIZO_PUBLIC_URL`.

When you change your models, run `rizolang build` again. It writes the change as a new file in `migrations/` (commit that folder), and `node migrate.ts` applies it.

Changes that would delete data are refused unless you add `--allow-data-loss`. That covers removing a field or model, changing a field's type, adding or removing `encrypted`, and removing a role.

### Try it

```sh
# Sign up. The server prints the confirmation email, with a link ending in #token=...
curl -H 'Content-Type: application/json' \
  -d '{"email":"ann@example.com","password":"correct horse battery","name":"Ann"}' \
  http://127.0.0.1:3000/auth/signup

# Confirm the email with the token from that link (or open the link in a browser)
curl -H 'Content-Type: application/json' -d '{"token":"PASTE-THE-TOKEN"}' \
  http://127.0.0.1:3000/auth/verify-email

# Log in (curl keeps the session cookie in ./jar)
curl -c jar -H 'Content-Type: application/json' \
  -d '{"email":"ann@example.com","password":"correct horse battery"}' \
  http://127.0.0.1:3000/auth/login

# Create a post as Ann
curl -b jar -H 'Content-Type: application/json' \
  -d '{"title":"Hello","body":"First post","published":true}' \
  http://127.0.0.1:3000/api/posts

# Anyone can list published posts, one page at a time
curl 'http://127.0.0.1:3000/api/posts?limit=10'
# → { "items": [...], "next": "<cursor>" }; get the next page with ?limit=10&after=<cursor>
```

> Session cookies are marked `Secure`, so they are only sent over https. Browsers and curl treat `localhost` and `127.0.0.1` as secure, so the steps above work locally as written. Only if you test over plain http on another host, start the server with `RIZO_DEV_INSECURE_COOKIES=1`. Never use this setting in production.

### Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `DATABASE_URL` | (required) | PostgreSQL connection string |
| `PORT` / `HOST` | `3000` / `127.0.0.1` | Where the server listens |
| `RIZO_ALLOWED_ORIGINS` | none | Extra origins allowed to send POST, PUT, PATCH or DELETE requests (comma-separated) |
| `RIZO_TRUST_PROXY` | off | `1` to read the client IP from `X-Forwarded-For` (only behind a trusted proxy) |
| `RIZO_DB_POOL_SIZE` | `10` | Maximum number of database connections (1–1000) |
| `RIZO_DB_STATEMENT_TIMEOUT_MS` | `5000` | Longest time one query may run, in milliseconds (100–600000) |
| `RIZO_AUDIT_RETENTION_DAYS` | `365` | How long security audit entries are kept (1–3650 days) |
| `RIZO_ADMIN_EMAILS` | none | Makes these **existing** accounts admins at startup (sign up first) |
| `RIZO_DEV_INSECURE_COOKIES` | off | `1` to allow cookies over http. For local development only |
| `RIZO_PUBLIC_URL` | (required with accounts) | The app's address, used in emailed links, e.g. `https://blog.example` |
| `RIZO_EMAIL_API_KEY` / `RIZO_EMAIL_FROM` | (required with accounts) | Resend API key, and a sender on your verified domain |
| `RIZO_PRIVACY_CONTACT` | (required with `privacy for`) | The address people write to about their data, shown on the privacy page |
| `RIZO_ENCRYPTION_KEYS` | (required with `encrypted` fields) | `id:key` pairs, e.g. `k1:` plus the output of `openssl rand -base64 32`. The first key encrypts; all of them decrypt |
| `RIZO_EMAIL_DEV` | off | `1` to print emails instead of sending them. For local development only |
| `RIZO_UPLOAD_DIR` | `./uploads` | Where uploaded files are kept (apps with `File` fields), unless `RIZO_S3_BUCKET` is set |
| `RIZO_S3_BUCKET`, `RIZO_S3_REGION`, `RIZO_S3_ACCESS_KEY_ID`, `RIZO_S3_SECRET_ACCESS_KEY`, `RIZO_S3_ENDPOINT` | none | Keep uploaded files in S3-compatible storage (AWS S3, Cloudflare R2, Backblaze B2, MinIO). The endpoint defaults to AWS for the region |

---

## Language tour

The [full spec](docs/SPEC.md) is the reference. This is the short version.

### Models and field types

```rizo
model User {
  email: Email unique private
  password: Password min 12
  name: Text max 100
  age: Number min 0 optional
  isAdmin: Bool
  birthday: Date optional
}
```

| Type | Stores | Notes |
|------|--------|-------|
| `Text` | text | At most 10,000 characters unless you set `max` |
| `Number` | whole number (32-bit) | Use cents for money |
| `Bool` | `true` / `false` | |
| `Email` | email address | Trimmed, lowercased and checked |
| `Password` | salted scrypt hash | Never stored as plain text and never returned |
| `Date` | date and time (UTC) | ISO 8601 in JSON |
| `ID` | UUID | |
| `File` | an uploaded image or PDF | `photo: File image max 5mb optional`. Stored on disk or in S3-compatible storage |
| *a model name* | a link, e.g. `author: User` | A foreign key to that model |

Every model gets an `id` automatically.

**Modifiers:**
- `unique`: no two records share the value.
- `optional`: the value may be missing.
- `private`: stored, but never returned.
- `encrypted`: encrypted by the server before it reaches the database (Text, Email, Number, Date). It can't be unique, filtered or sorted, and needs `RIZO_ENCRYPTION_KEYS`.
- `min N` / `max N`: the length for text, the value for numbers, the size for files (`max 5mb`).
- `image` / `pdf`: what a `File` field may hold (neither means both).

**Files.** Clients upload the file itself to `POST /_rizo/uploads/posts/photo`, then send the url it returns as the field's value; generated pages do both for you. The type is read from the file's content (never SVG or HTML), location data is removed from photos, only the uploader can attach a file, and files no record uses are deleted after a day. Files go to `RIZO_UPLOAD_DIR` (default `./uploads`), or to an S3-compatible bucket with `RIZO_S3_BUCKET`.

### Login

```rizo
auth User by email
```

This one line adds signup, login and logout (`/auth/signup`, `/auth/login`, `/auth/logout`), plus account management:
- `GET` and `PATCH /auth/me` to read and edit your profile,
- `POST /auth/password` to change your password, which logs out your other sessions,
- `POST /auth/logout-all` to log out everywhere, and `GET /auth/sessions` / `DELETE /auth/sessions/:id` to see your devices and log out one,
- `GET /auth/me/export` to download everything stored about you, and `DELETE /auth/me` to delete your account (posts and other records that need an owner stay, credited to "Deleted user"),
- email confirmation (required before the first login), password reset by email, and changing the login email (confirmed by a link to the new address),
- editing the profile and changing the password on the built-in `/account` page,
- passkeys (fingerprint, face or device PIN), managed on the built-in `/account` page,
- API tokens for scripts and AI agents (`Authorization: Bearer rzt_...`), each limited to the endpoints you choose, for at most 90 days.

Changing the password and deleting the account need the current password.

Add roles with `auth User by email roles admin, editor`, then protect endpoints with `requires role admin`, or with `requires owner author or role admin` so admins can act on anyone's records. Admins assign roles through `PUT /auth/users/:id/role`, and get built-in `/admin` pages to search, browse and delete the records of every model (public fields only, with every deletion in the audit log). To make the first admin, sign up, then restart the server with `RIZO_ADMIN_EMAILS=you@example.com`.

**Built in:**
- Secure session cookies, with only a hash of each token stored in the database. Sessions end after 7 days unused, or 30 days after login.
- Rate limits on login and signup.
- The same response for a wrong password and an unknown account, and the same for signing up with a new or a taken email, so callers can't find out which emails are registered.
- One-time emailed links, stored only as hashes and kept out of logs.

### Pages

```rizo
page /posts/:id {
  public
  title "A post"
  show GET /api/posts/:id
}

page /posts/new {
  requires login
  title "Write a post"
  form POST /api/posts
  then go /posts/:id
}
```

**How pages work:**
- Pages are generated from your endpoints: lists with "Load more", single records, text and links.
- **Forms** (`form POST`, `PUT` or `PATCH`) and **delete buttons** (`button "Delete" DELETE ...`) are built from the endpoint's body, with the same limits checked in the browser and on the server. Edit forms start with the current values.
- Brand the pages with one line: `site "Rizo Blog" color teal logo "logo.png"`.
- Apps with an `auth` line get `/login`, `/signup` and a log-in/log-out menu. Pages that need a login send visitors to log in and then bring them back.
- You never write HTML or browser code. All text is inserted as plain text, and pages are served with a strict Content-Security-Policy.
- A page is never more open than the data it shows: a page showing a `requires login` endpoint must also say `requires login`.
- By convention, endpoints live under `/api` so they don't clash with page paths.

### Endpoints

```
api <METHOD> <path> -> Model.public {
  public | requires login
  requires role admin, editor        // optional
  requires owner <link field>        // optional; "or role admin" lets admins act too
  return db.Model.<action>(...)
}
```

| Action | Method | Example |
|--------|--------|---------|
| `find` | GET | `db.Post.find(id)` |
| `list` | GET | `db.Post.list(author = me, order title desc, limit 20)`, which returns pages: `{ "items": [...], "next": "<cursor>" }`. Filters can also use `!=`, `<`, `>`, `contains` and optional query parameters: `db.Post.list(title contains ?q, views >= ?minViews)`. Add `with author` after the return type to get each linked author's public fields too |
| `create` | POST | `db.Post.create(body, author = me)` |
| `update` | PUT / PATCH | `db.Post.update(id, body)` |
| `delete` | DELETE | `db.Post.delete(id)` |

The compiler enforces these rules:
- Every endpoint must say `public` or `requires login`. There is no default.
- Endpoints can only return `.public` views.
- A record's owner is always `me`, the logged-in user. It is never taken from the request body.
- `requires owner author` is enforced inside the SQL query, so someone else's record looks exactly like a missing one.
- `GET` endpoints can never change data.

---

## Security model

| Threat | How Rizo Lang prevents it |
|--------|---------------------------|
| SQL injection | All SQL is written at compile time. Request data only fills `$1, $2, …` parameters. |
| Leaking passwords or private data | Password and `private` fields are never selected for responses, and the runtime copies only public keys. |
| Plain-text or weak passwords | scrypt with a random salt. A minimum length of 8, and you can only raise it. |
| Missing login checks | Every endpoint must declare `public` or `requires login`. |
| Privilege escalation | Roles are never accepted from requests. Only admins assign them, never to themselves. `RIZO_ADMIN_EMAILS` only promotes accounts that already exist. |
| Editing someone else's data (IDOR) | `requires owner` becomes part of the `WHERE` clause. Owners are set from the session. |
| Mass assignment | Unknown body fields are rejected. Ownership links are never accepted from clients. |
| Malicious uploads | File types are read from the content, so SVG, HTML and scripts are refused. Files are served with `nosniff` and a sandbox policy from unguessable addresses, and only their uploader can attach them. Photo location data is removed. |
| CSRF | `SameSite=Lax` cookies, JSON-only bodies, and `Sec-Fetch-Site` plus `Origin` checks on every POST, PUT, PATCH and DELETE. |
| Slow queries and table scans | The compiler creates the right index for every list's filters and order (about 280× faster on 200,000 rows in our test), and every query is cancelled after 5 seconds. |
| Bots, scrapers and brute force | Every endpoint is rate-limited (120/min by default, `limit 10 per minute` to tighten), with counters shared across servers in PostgreSQL. Login, signup and password checks have stricter limits, and password hashing is queued so a login flood can't stall the server. |
| Phishing and stolen passwords | Built-in passkeys (fingerprint, face or device PIN) on every app with a login. A passkey only works on the site that created it, and the server keeps only the public key. |
| Over-powered AI agents | API tokens are limited to the endpoints you pick, expire within 90 days, can be revoked, never work on account endpoints, and every use is in the audit log. |
| Privacy laws (GDPR, UK GDPR, India's DPDP, CCPA, LGPD) | Declare the regions you serve (`privacy for EU, UK, IN, US-CA, BR`) and the app publishes a privacy page generated from your models: what is stored and how, for how long, cookies, who else handles data, rights and where to complain. `keep 2 years` deletes a model's records automatically. It helps with the technical parts; it isn't legal advice. |
| Privacy rights requests | Every app lets people download all their data and delete their account from the `/account` page, with no code to write. Deleted accounts leave no personal data behind. |
| Stolen databases and backups | Mark sensitive fields `encrypted`: the server encrypts them with AES-256-GCM before they reach the database, and keys can be rotated with `node reencrypt.ts`. |
| Account enumeration | Identical responses and timing for an unknown account and a wrong password. Signup and password reset answer the same whether or not the email has an account; the owner gets an email instead. |
| Fake and throwaway sign-ups | Accounts confirm their email before they can log in. One-time links are hashed, expire, and are kept out of logs. |
| Accidental data loss | Migrations that would drop data are refused unless you pass `--allow-data-loss`. Each migration runs in a transaction, and edited migrations are detected. |
| Attacks nobody notices | A security audit log records logins, failed and blocked logins, password and role changes, and deletes, with no secrets. Admins read it at `GET /auth/audit`, and entries are kept for a year. |
| Leaky logs | Logs contain only the method, route pattern, status, time and request id. |
| Cross-site scripting (XSS) | Pages contain no HTML or code. All text is inserted as text (never `innerHTML`), links stay on the site, and a strict CSP allows only the site's own script. |
| Clickjacking and sniffing | A strict CSP, plus `X-Frame-Options: DENY`, `nosniff` and `no-store` on every response. |

Every guarantee is tested, in [`tests/security.test.ts`](tests/security.test.ts) and in the end-to-end suite [`tests/e2e.test.ts`](tests/e2e.test.ts), which attacks a real server backed by PostgreSQL. Found a hole? Please [report it privately](SECURITY.md).

---

## Error messages

Every error has a code, an exact location and a concrete fix. Real output from `rizolang build`:

```
app.rz:14:5 error RZ0318: Endpoint "GET /posts" does not say who may call it.
  14 | api GET /posts -> list Post.public {
     |     ^^^
  fix: Add `requires login` for logged-in users only, or `public` if anyone may call it.

app.rz:20:18 error RZ0326: "Post.author" links to the auth model, so the server must set it.
  20 |   return db.Post.create(body)
     |                  ^^^^^^
  fix: Write `db.Post.create(body, author = me)`. Otherwise a client could create records owned by someone else.

Build failed with 2 errors. No files were written.
```

For editors and AI agents, `rizolang build app.rz --json` prints the same errors as one line of JSON:

```json
{"rizolang":"0.7.0","ok":false,"errors":[{"code":"RZ0318","message":"Endpoint \"GET /posts\" does not say who may call it.","fix":"Add `requires login` for logged-in users only, or `public` if anyone may call it.","file":"app.rz","line":14,"column":5,"length":3}]}
```

The full list of error codes is in the [spec](docs/SPEC.md#8-errors).

---

## Using Rizo Lang with AI

Rizo Lang is designed to be written by AI models as well as people:
- [`docs/SPEC-COMPACT.md`](docs/SPEC-COMPACT.md) is under 1,500 words. Paste it into any model's system prompt.
- Error messages include a `fix:` line that a model can apply directly, and `rizolang build app.rz --json` returns them as JSON. `rizolang check app.rz --json` does the same without writing any files.
- `rizolang audit app.rz` reviews a file for risky choices that are allowed but often a mistake (public writes, personal data that isn't `private`, loose rate limits…), each with its location and a fix. It exits with 1 on warnings, so it can run in CI.
- Every generated app describes its API in `openapi.json` (also served at `/_rizo/openapi.json`), and AI agents call it with API tokens limited to the endpoints you choose.
- The Rizo VS Code extension ([rizobot.com](https://rizobot.com)) will detect `.rz` files and load the spec automatically.

---

## Project status and roadmap

Rizo Lang is in **early development**, so expect the language to change before 1.0.

- [x] **Milestone 1:** models, compiled to a PostgreSQL schema and TypeScript types ([v0.1.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.1.0))
- [x] **Milestone 2:** `auth`, `api` endpoints, links, `private` fields and a generated Node.js server ([v0.2.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.2.0))
- [x] **Milestone 3:** roles, pagination, account management and migrations ([v0.3.1](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.3.1))
- [x] **Milestone 4:** pages, forms, delete buttons, and built-in login and signup pages ([v0.4.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.4.0))
- [x] **Milestones 5–8** ([v0.5.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.5.0)):
  - hardening: rate limits on every endpoint, automatic indexes, query time limits, a security audit log,
  - accounts: passkeys, email confirmation and password reset, `encrypted` fields, sessions and devices,
  - AI agents: scoped API tokens, OpenAPI, `build --json`, `rizolang audit`,
  - privacy for the regions you declare (EU, UK, India, California, Brazil): data download and deletion, `keep` retention, a generated privacy page
- [x] **Milestone 9** ([v0.6.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.6.0)): profile, email and password changes on the account page, search and richer list filters, `rizolang dev`, a health check, graceful shutdown and a generated `Dockerfile`
- [x] Publish the compiler to npm ([`rizolang`](https://www.npmjs.com/package/rizolang))
- [x] **Milestone 10** ([v0.7.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.7.0)): linked records (`with`), site branding, built-in admin pages and file uploads
- [ ] A VS Code extension with syntax highlighting

See [CHANGELOG.md](CHANGELOG.md) for what changed in each version.

---

## Project structure

```
rizolang/
├── src/                 # the compiler
│   ├── lexer.ts         #   source text → tokens
│   ├── parser.ts        #   tokens → syntax tree (hand-written recursive descent)
│   ├── checker.ts       #   models: types, modifiers, links, names
│   ├── check-api.ts     #   auth and api: access, ownership, queries
│   ├── emit/            #   SQL, TypeScript types and routes
│   └── cli.ts           #   `rizolang build`
├── runtime/             # copied into every generated app (validation, sessions, server, pages)
│   └── client/          #   the browser runtime and default styles
├── tests/               # unit, security, docs and end-to-end tests
├── docs/                # SPEC.md and SPEC-COMPACT.md
└── examples/blog.rz     # a complete example app
```

---

## Development

```sh
npm ci                 # install the exact locked dependencies
npm test               # run all tests (end-to-end tests are skipped without a database)
npm run typecheck      # strict type checking
npm run build          # compile the compiler to build/

# Run the end-to-end tests against a PostgreSQL database you control.
# They create and drop their own temporary schema.
RIZO_TEST_DATABASE_URL=postgres://user:pass@localhost:5432/dev npm test
```

The compiler has **zero runtime dependencies**, and every dev dependency is pinned to an exact version. CI runs:
- the tests on Node 22, 24 and 26,
- the end-to-end suite and a real server against PostgreSQL 17,
- CodeQL,
- dependency review.

---

## Contributing, security and license

- **Contributing:** contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md), and propose language changes in an issue first.
- **Code of Conduct:** this project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
- **Security:** please report vulnerabilities privately, as described in [SECURITY.md](SECURITY.md).
- **License:** [Apache License 2.0](LICENSE).

<div align="center">

Made for the [Rizo](https://rizobot.com) ecosystem.

</div>
