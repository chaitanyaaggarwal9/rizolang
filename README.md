<div align="center">

# Rizo Lang

**A modern, simple and secure web language for the AI era.**

Write your data models and endpoints in a few readable lines. Rizo Lang compiles them into a PostgreSQL schema, TypeScript types and a ready-to-run Node.js server, with login, validation and permission checks built in.

[![CI](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/ci.yml/badge.svg)](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/ci.yml)
[![CodeQL](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/codeql.yml/badge.svg)](https://github.com/chaitanyaaggarwal9/rizolang/actions/workflows/codeql.yml)
[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

![.rz Language](https://img.shields.io/badge/.rz-language-0ea5e9)
![Full-Stack](https://img.shields.io/badge/full--stack-web-8b5cf6)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?logo=postgresql&logoColor=white)
![Open Source](https://img.shields.io/badge/open%20source-Apache--2.0-10b981)

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

Rizo Lang is part of the [Rizo](https://rizobot.com) ecosystem, alongside **Rizo**, an open-source BYOK AI coding assistant for VS Code. It compiles into technology you already use. Its only runtime is a small, readable library that is copied into your project.

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

api GET /posts -> list Post.public {
  public
  return db.Post.list(published = true, order title, limit 20)
}

api POST /posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}

api PATCH /posts/:id -> Post.public {
  requires login
  requires owner author
  return db.Post.update(id, body)
}

api DELETE /posts/:id {
  requires login
  requires owner author
  return db.Post.delete(id)
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

---

## What the compiler generates

`rizolang build app.rz` writes everything to `dist/`:

| File | What it is |
|------|------------|
| `schema.sql` | PostgreSQL tables with `NOT NULL`, `UNIQUE`, `CHECK` and foreign-key constraints, plus the sessions table |
| `types.ts` | TypeScript types: `User` (server-only), `UserPublic` (safe to return) and `UserInput` (what clients send) |
| `routes.ts` | Every endpoint as plain data, **with its SQL written out in full** so you can review exactly what runs |
| `server.ts` | The entry point: `node server.ts` |
| `runtime/` | A small Rizo runtime: validation, sessions, password hashing and the HTTP server |
| `package.json`, `tsconfig.json` | Installs the only dependency, the [`pg`](https://www.npmjs.com/package/pg) driver, and type-checks the app |

A file with only models (no `auth` or `api`) produces just `schema.sql` and `types.ts`.

Part of the `PATCH /posts/:id` route above, as it appears in `routes.ts`:

```ts
{
  method: 'PATCH',
  pattern: '/posts/:id',
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

Rizo Lang is not published to npm yet. Build it from source:

```sh
git clone https://github.com/chaitanyaaggarwal9/rizolang.git
cd rizolang
npm ci
npm run build
npm link              # optional: makes the `rizolang` command available everywhere
```

### Build and run an app

```sh
rizolang build app.rz                 # or: node path/to/rizolang/build/src/bin.js build app.rz
cd dist
npm install                           # installs pg
psql "$DATABASE_URL" -f schema.sql    # create the tables
DATABASE_URL=postgres://user:pass@localhost:5432/app node server.ts
```

### Try it

```sh
# Sign up (this also logs you in; curl keeps the session cookie in ./jar)
curl -c jar -H 'Content-Type: application/json' \
  -d '{"email":"ann@example.com","password":"correct horse battery","name":"Ann"}' \
  http://127.0.0.1:3000/auth/signup

# Create a post as Ann
curl -b jar -H 'Content-Type: application/json' \
  -d '{"title":"Hello","body":"First post","published":true}' \
  http://127.0.0.1:3000/posts

# Anyone can list published posts, one page at a time
curl 'http://127.0.0.1:3000/posts?limit=10'
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
| `RIZO_DB_POOL_SIZE` | `10` | Maximum number of database connections |
| `RIZO_ADMIN_EMAILS` | none | Makes these **existing** accounts admins at startup (sign up first) |
| `RIZO_DEV_INSECURE_COOKIES` | off | `1` to allow cookies over http. For local development only |

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
| *a model name* | a link, e.g. `author: User` | A foreign key to that model |

Every model gets an `id` automatically.

**Modifiers:**
- `unique`: no two records share the value.
- `optional`: the value may be missing.
- `private`: stored, but never returned.
- `min N` / `max N`: the length for text, the value for numbers.

### Login

```rizo
auth User by email
```

This one line adds `POST /auth/signup`, `POST /auth/login`, `POST /auth/logout` and `GET /auth/me`.

Add roles with `auth User by email roles admin, editor`, then protect endpoints with `requires role admin`, or with `requires owner author or role admin` so admins can act on anyone's records. Admins assign roles through `PUT /auth/users/:id/role`. To make the first admin, sign up, then restart the server with `RIZO_ADMIN_EMAILS=you@example.com`.

**Built in:**
- Secure session cookies, with only a hash of each token stored in the database.
- Rate limits on login and signup.
- The same response for a wrong password and an unknown account, so callers can't find out which emails are registered.

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
| `list` | GET | `db.Post.list(author = me, order title desc, limit 20)`, which returns pages: `{ "items": [...], "next": "<cursor>" }` |
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
| CSRF | `SameSite=Lax` cookies, JSON-only bodies and an `Origin` check on every POST, PUT, PATCH and DELETE. |
| Brute force | Rate limits on login and signup. |
| Account enumeration at login | Identical responses and timing for an unknown account and a wrong password. |
| Leaky logs | Logs contain only the method, route pattern, status, time and request id. |
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

The full list of error codes is in the [spec](docs/SPEC.md#8-errors).

---

## Using Rizo Lang with AI

Rizo Lang is designed to be written by AI models as well as people:
- [`docs/SPEC-COMPACT.md`](docs/SPEC-COMPACT.md) is under 1,500 words. Paste it into any model's system prompt.
- Error messages include a `fix:` line that a model can apply directly.
- The Rizo VS Code extension ([rizobot.com](https://rizobot.com)) will detect `.rz` files and load the spec automatically.

---

## Project status and roadmap

Rizo Lang is in **early development**, so expect the language to change before 1.0.

- [x] **Milestone 1:** models, compiled to a PostgreSQL schema and TypeScript types ([v0.1.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.1.0))
- [x] **Milestone 2:** `auth`, `api` endpoints, links, `private` fields and a generated Node.js server ([v0.2.0](https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.2.0))
- [ ] **Milestone 3** (in progress): roles ✓, pagination ✓, account management, migrations
- [ ] **Milestone 4:** frontend `page` blocks compiled to HTML and TypeScript
- [ ] Publish the compiler to npm, and a VS Code extension with syntax highlighting

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
├── runtime/             # copied into every generated app (validation, sessions, server)
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
