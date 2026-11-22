# Changelog

All notable changes to Rizo Lang are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may include breaking language changes.

## [Unreleased]

### Added

- Milestone 9, part 2: the account page.
  - `/account` starts with forms to edit the profile, change the login email and change the password.
  - Changing the login email (`POST /auth/email`, with the password) sends a one-time link to the new address. Nothing changes until it is opened on the new built-in `/confirm-email` page (`POST /auth/email/confirm`); then the old address is told, and the change is recorded in the audit log. A taken address gets the same answer and no link.
  - Edit forms (PATCH) now send only the fields that changed, so a private field that isn't shown is never cleared. Built-in edit forms stay on the page after saving, with a "saved" message.
  - `/confirm-email` is now a reserved page path.

- Milestone 9, part 3: more list filters.
  - Besides `=`, list filters can use `!=`, `<`, `<=`, `>`, `>=` (Number and Date fields) and `contains` (Text and Email: case-insensitive, with `%` and `_` as plain characters).
  - `?name` is an optional query parameter: `db.Post.list(title contains ?q, views >= ?minViews)` reads `/api/posts?q=...&minViews=...`, skipping each filter that is left out. Values are validated against the field's type before any query runs, and are always SQL parameters. `openapi.json` lists them.
  - Automatic indexes put `=` columns first, then range columns, then the sort column.

- Milestone 9, part 4: `rizolang dev app.rz`.
  - With `DATABASE_URL` set, it builds, installs `pg` in `dist/` the first time, applies migrations and starts the server on port 3000 (`--port`), filling in development settings that aren't set and saying which: localhost links, printed emails, a placeholder privacy contact, and a local encryption key in `dist/.dev-encryption-key`.
  - Saving the `.rz` file rebuilds, migrates and restarts. If the file has errors, they are printed and the running server keeps going. It announces the address only once the server accepts connections. Data-loss changes still need `--allow-data-loss`. Ctrl+C stops everything.
  - New CLI errors RZ0906 (no `DATABASE_URL`) and RZ0907 (nothing to run).

### Changed

- The compact spec is shorter (about 1,300 words instead of 1,480), with the same rules, so there is room for new features under its 1,500-word limit.

## [0.5.0] - 2026-11-21

Milestones 5 to 8: hardening, accounts, tools for AI agents, and privacy rules for the regions you declare.

### Upgrading from 0.4.0

This release has breaking changes. Rebuild your app (`rizolang build app.rz`), apply the new migration (`node migrate.ts`), then check the following.
- **New required settings** for apps with an `auth` line: `RIZO_PUBLIC_URL`, plus `RIZO_EMAIL_API_KEY` and `RIZO_EMAIL_FROM` for [Resend](https://resend.com) (or `RIZO_EMAIL_DEV=1` for local development). Apps with `encrypted` fields need `RIZO_ENCRYPTION_KEYS`, and apps with `privacy for` need `RIZO_PRIVACY_CONTACT`. The server refuses to start without them and says which one to fix.
- **Signup** answers 202 and no longer logs in: new accounts confirm their email first. Existing accounts count as confirmed.
- **Deleting an account** no longer refuses while records link to it: those records are credited to a "Deleted user" account.
- **Sessions** end after 7 days without use, or 30 days after login.
- **Every endpoint is rate-limited** (120 requests a minute by default; set your own with `limit 20 per minute`).
- **Newly reserved page paths:** `/account`, `/verify-email`, `/reset-password` and `/privacy`.

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
- Milestone 7, part 1: API tokens for scripts and AI agents.
  - Users create tokens on the `/account` page or with `POST /auth/tokens`, choosing a name, the endpoints the token may call (any endpoint that needs a login) and an expiry of 1–90 days (90 by default). The token (`rzt_...`) is shown once; only its hash is stored.
  - Agents send `Authorization: Bearer rzt_...`. A token acts as its account only on its endpoints (others answer 403), never on `/auth/*`, and stops working when it expires or is revoked (`DELETE /auth/tokens/:id`). A password reset revokes every token of the account.
  - Creating, using (with the endpoint) and revoking tokens are recorded in the audit log. The `_rizo_tokens` table is added by migration.
- Milestone 7, part 2: OpenAPI.
  - Every build writes `dist/openapi.json` (OpenAPI 3.1), generated from the same route data the server runs on, and the server serves it at `/_rizo/openapi.json`.
  - It describes each endpoint's parameters, exact request body (with limits, no extra fields), public response fields and errors, how to log in (session cookie or API token), and Rizo's rules as `x-rizo-access`, `x-rizo-roles`, `x-rizo-owner` and `x-rizo-rate-limit`.
  - `openapi.json` declares `servers: [{ "url": "/" }]` (the server that serves it), as Redocly's recommended rules require.
- Milestone 7, part 3: `rizolang build --json`.
  - Prints one line of JSON instead of text: on failure, every error with its code, message, fix, file, line, column and length (location fields are null for command-line problems, and refused data-loss builds list `dataLoss`); on success, what was built, the files written and the new migration. Exit codes are unchanged, and nothing goes to stderr.
- Milestone 7, part 4: `rizolang audit app.rz`.
  - Reviews a file that builds for choices that are allowed but often a mistake, and prints each with its location and a fix, as warnings or notes: public endpoints that change data (RA01), fields that look like personal data or secrets but aren't `private` (RA02) or aren't `encrypted` (RA03), public email addresses (RA04), public lists of all accounts (RA05), login-only updates and deletes without an owner or role check (RA06), and loose rate limits on public endpoints (RA07).
  - Writes nothing, supports `--json`, and exits with 1 on warnings so it can run in CI.

- Milestone 8, part 1: your data.
  - `GET /auth/me/export` returns everything stored about the account as a `my-data.json` download: every field except the password hash (private and encrypted fields included), the records of every model that link to it, devices, passkeys, API tokens and the account's security log. At most 5 times an hour; recorded in the audit log.
  - **Changed:** `DELETE /auth/me` no longer refuses while records link to the account. Records that need an owner are given to one shared "Deleted user" account in the same statement, which holds only placeholders and can't be logged into. The `_rizo_deleted_user` table is added by migration.
  - The `/account` page has "Download my data" and "Delete my account" (with the password and a confirmation).

- Milestone 8, part 2: `privacy for` and `keep`.
  - `privacy for EU, UK, IN, US-CA, BR` names the regions an app serves (GDPR, UK GDPR, India's DPDP Act, California's CCPA, Brazil's LGPD). It needs an `auth` line.
  - `keep 2 years` (days, months or years) in a model deletes its records that long after they were created: every 10 minutes, at most 1,000 at a time, recorded in the audit log, skipping records that others still need. It adds a hidden, indexed `_created_at` column by migration.
  - New errors RZ0223, RZ0341 and RZ0342.

- Milestone 8, part 3: the privacy notice.
  - With `privacy for`, the app publishes a privacy notice generated from its models, with fixed wording: `GET /auth/privacy` and, in apps with pages, a built-in `/privacy` page linked from every page's menu. It lists what is stored and how (public, private, encrypted, hashed), how long records are kept, cookies (one login cookie, so no banner), Resend for emails, that data isn't sold or shared, security and log retention, people's rights, and each region's law and where to complain.
  - `RIZO_PRIVACY_CONTACT` is required with `privacy for`; the server refuses to start without it. `/privacy` is now a reserved page path.
  - New audit note RA08: with `privacy for`, a model whose records belong to accounts but have no `keep`.

### Fixed

- Signup SQL no longer crashes the compiler when the auth model has a camelCase field, such as `displayName` (introduced earlier in this release cycle).

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

[Unreleased]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.1.0
