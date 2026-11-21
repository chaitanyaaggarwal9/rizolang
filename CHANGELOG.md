# Changelog

All notable changes to Rizo Lang are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may include breaking language changes.

## [Unreleased]

### Added

- Milestone 5, part 1: abuse protection.
  - Every endpoint is rate-limited: 120 requests per minute by default, per account or per IP address. `limit 20 per minute` (second, minute, hour or day) sets an endpoint's own limit, and over-limit requests get 429 with `Retry-After`.
  - Rate-limit counters live in PostgreSQL (`_rizo_rate_limits`, added by migration), so limits hold across several server processes. Login, signup and password-check limits moved there too. Keys are hashes, never raw IP addresses.
  - Password hashing runs at most two at a time; a full queue answers 503 with `Retry-After`.
  - `Sec-Fetch-Site` checks reject cross-site writes, in addition to the `Origin` check.
- New errors RZ0222 and RZ0339.
- Milestone 5, part 2: speed and stability.
  - Automatic indexes: one per distinct `list` filter and order, ending in `id`, created and removed by migrations. On 200,000 posts, the example's home-page query went from 10.2 ms (full scan) to 0.036 ms.
  - Every query is cancelled after 5 seconds (`RIZO_DB_STATEMENT_TIMEOUT_MS`) and answered with 503 and `Retry-After`.
  - Rate limits use a sliding window, so a burst at a window edge (for example 5 login guesses just before and 5 just after) is no longer possible.
- Milestone 5, part 3: security audit log.
  - The `_rizo_audit` table (added by migration) records sign-ups, logins, failed and blocked logins, logouts, password changes and failed password checks, account deletions, role changes, admins granted at startup, and records deleted through endpoints. Each entry holds the time, actor, target, IP address and a short fixed detail, and never a secret.
  - Admins read it at `GET /auth/audit` (`?account=`, `?limit=`).
  - Entries are deleted after `RIZO_AUDIT_RETENTION_DAYS` (365 by default). A failed write never breaks the action.
- Milestone 6, part 1: passkeys.
  - Every app with an `auth` line supports passkeys alongside passwords, with no change to the `.rz` file. Users add and remove them on the new built-in `/account` page and log in with "Log in with a passkey" on `/login`.
  - New endpoints under `/auth/passkeys`, and the `_rizo_passkeys` and `_rizo_challenges` tables (added by migration).
  - Verification uses only `node:crypto` and a small strict CBOR decoder, with no new dependencies. It checks single-use 5-minute challenges, origin, site id, user verification, signature, and the signature counter (copied keys are refused). ES256 and RS256 keys.
  - Adding and removing passkeys and passkey logins are recorded in the audit log.
  - `/account` is now a reserved page path.
- Milestone 6, part 2: email confirmation and password reset.
  - **Breaking:** accounts must confirm their email before they can log in. `POST /auth/signup` now answers 202 with the same message whether or not the email already has an account, and no longer logs in. Existing accounts count as confirmed.
  - **Breaking:** apps with an `auth` line need `RIZO_PUBLIC_URL`, plus `RIZO_EMAIL_API_KEY` and `RIZO_EMAIL_FROM` (Resend), or `RIZO_EMAIL_DEV=1` for local development. The server refuses to start without them.
  - New endpoints: `POST /auth/verify-email`, `/auth/verify-email/resend`, `/auth/password-reset` and `/auth/password-reset/confirm`. A reset logs out every session.
  - New built-in pages `/verify-email` and `/reset-password` (now reserved), and links to them on `/login`.
  - Signing up with an email that has an account emails its owner instead, so signup can't be used to find out who has an account.
  - Links are one-time, expire (24 hours to confirm, 1 hour to reset), are stored only as hashes, and carry the token after `#` so it never reaches logs. At most 3 emails an hour go to one account.
  - The `_rizo_unverified` and `_rizo_email_tokens` tables, added by migration. Emails are sent with `fetch`, with no new dependencies.
- Milestone 6, part 3: encrypted fields.
  - New `encrypted` modifier for Text, Email, Number and Date fields. The server encrypts values with AES-256-GCM (random IV, bound to the table and column) before they are written, and decrypts them when they are read, so the database and its backups hold only ciphertext. Limits are still checked on the plain value.
  - Keys come from `RIZO_ENCRYPTION_KEYS` (`id:key` pairs; the first encrypts, all decrypt). An app with encrypted fields refuses to start without them.
  - Key rotation: put a new key first, then run the generated `node reencrypt.ts` to move stored values to it.
  - New error RZ0340: an encrypted field can't be unique, the login field, a list filter or an order.
  - Adding or removing `encrypted` on an existing field replaces its column, so it needs `--allow-data-loss`.
- Milestone 6, part 4: sessions and devices.
  - Sessions end after 7 days without use, and 30 days after login however much they are used. The cookie's `Max-Age` is now 30 days; the server enforces the idle limit.
  - `GET /auth/sessions` lists the devices you are logged in on, each with a label such as "Chrome on macOS" (from fixed names only; the raw User-Agent and IP address are not stored), and `DELETE /auth/sessions/:id` logs one out. Recorded in the audit log.
  - The built-in `/account` page lists your devices, with "Log out" for each and "Log out everywhere".
  - "Last active" is updated at most once a minute. The `_rizo_sessions` table gets `id`, `ends_at`, `last_seen_at` and `device` columns, added by migration; existing sessions keep working.

## [0.4.0] - 2026-11-21

Milestone 4: web pages, forms and built-in login pages, generated from your endpoints.

### Added

- Milestone 4, part 1: `page` blocks.
  - Pages have `public` or `requires login` (with optional `requires role`), `title "..."`, `text "..."`, `link "..." /path` and `show GET /api/...`.
  - Lists have "Load more", single records are shown as fields, and lists link automatically to the page that shows one record.
  - The generated server serves pages with a strict Content-Security-Policy. The browser runtime (`/_rizo/client.js`) never uses `innerHTML`.
- Milestone 4, part 2: forms and buttons.
  - `form POST|PUT|PATCH /api/...` builds a form from the endpoint's body: labels, required fields and limits, checked in the browser and on the server. Edit forms are prefilled.
  - `button "..." DELETE /api/...` deletes after a confirmation.
  - `then go /path` says where to go afterwards; `:id` can come from the saved record.
  - Apps with an auth line get built-in `/login` and `/signup` pages and a log-in/log-out menu. Login-only pages redirect to `/login?next=...`, and `next` is followed only to pages on the same site.
- Quoted text, allowed only in pages.
- New errors RZ0103, RZ0220, RZ0221 and RZ0333–RZ0338.

### Changed

- The example app's endpoints moved under `/api`, the convention when a file has pages. It is now a complete blog in the browser: list, read, write, edit and delete posts, log in and sign up.

## [0.3.1] - 2026-11-21

The first npm release of Milestone 3. v0.3.0 was released on GitHub only; 0.3.1 has the same language and compiler.

### Security

- Releases are now **staged** on npm. A new version goes live only after the maintainer approves it with two-factor authentication.

## [0.3.0] - 2026-11-21

Milestone 3: roles, pagination, account management and migrations.

### Added

- Roles: `auth User by email roles admin, editor`, `requires role admin, editor`, and `requires owner author or role admin`.
  - Roles are stored in a hidden `role` column that only accepts the declared names, and are never accepted from requests or returned.
  - Admins assign roles with `PUT /auth/users/:id/role`, but never to themselves.
  - `RIZO_ADMIN_EMAILS` makes existing accounts admins at startup.
- New errors RZ0219 and RZ0332.
- Pagination: `list` endpoints accept `?limit=` and `?after=<cursor>`, using keyset pagination on the sort field and `id`. The cursor only fills query parameters.

- Account management:
  - `PATCH /auth/me` edits your own profile.
  - `POST /auth/password` changes your password with the current one, and logs out your other sessions.
  - `POST /auth/logout-all` logs out every session.
  - `DELETE /auth/me` deletes your account with your password.
  - Wrong passwords count toward the login lockout.

- Migrations:
  - `rizolang build` writes numbered migrations and a schema snapshot to `migrations/`.
  - Changes that would delete data are refused unless `--allow-data-loss` is given (RZ0904).
  - The generated `migrate.ts` applies migrations, each in its own transaction, under a lock, with checksums. `--baseline` adopts databases created from `schema.sql`.
  - New errors RZ0904 and RZ0905.

### Changed

- **Breaking:** `list` endpoints now return `{ "items": [...], "next": "<cursor>" | null }` instead of a bare array. `limit N` is now the largest page size, and also the default.
- **Breaking:** ordering by an `optional` field is a compile error (RZ0325).
- Every endpoint now rejects unknown or repeated query parameters with 400.
- Schema constraints and indexes now have explicit names, which follow PostgreSQL's default pattern.

## [0.2.0] - 2026-11-20

### Added

- Milestone 2:
  - `auth User by email`: signup, login, logout and `/auth/me`, with server-side sessions in HttpOnly, Secure, SameSite=Lax cookies, scrypt password hashing and login rate limits.
  - `api` blocks with `public` / `requires login`, `requires owner <link>` and the queries `find`, `list`, `create`, `update` and `delete`.
  - Links between models (`author: User`), stored as foreign keys.
  - The `private` modifier: the field is stored but never returned.
  - A generated Node.js server (`routes.ts`, `server.ts`, `runtime/`). All SQL is written at compile time, and only `$n` parameters come from requests.
  - New errors RZ0213–RZ0218 and RZ0316–RZ0331. RZ0331 rejects `update` or `delete` of user-owned records without `requires owner`.
- End-to-end tests against PostgreSQL, run in CI, plus a type-check and smoke run of the generated server.
- Contributor guide, Code of Conduct, issue and pull request templates, and CODEOWNERS.
- CodeQL and dependency review workflows, and Dependabot updates for npm and GitHub Actions.

### Changed

- Commas and parentheses are now part of the syntax (for query arguments). A comma after a field is now reported as RZ0212 instead of RZ0101.
- The compiler's entry point moved to `build/src/bin.js`.

### Security

- Dependency install scripts are disabled (`.npmrc`), and CI verifies npm registry signatures.

## [0.1.0] - 2026-11-20

### Added

- Milestone 1: `model` blocks compile to a PostgreSQL schema and TypeScript types.
- Field types `Text`, `Number`, `Bool`, `Email`, `Password`, `Date`, `ID`, and modifiers `unique`, `optional`, `min`, `max`.
- Public types (`User.public`) never contain Password fields.
- `rizolang build file.rz` CLI.
- Language spec (`docs/SPEC.md`) and compact spec for AI system prompts (`docs/SPEC-COMPACT.md`).
- CI on Node 22, 24 and 26, plus a PostgreSQL schema check.

[Unreleased]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.1.0
