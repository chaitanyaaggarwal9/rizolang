# Changelog

All notable changes to Rizo Lang are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may include breaking language changes.

## [Unreleased]

### Added

- Milestone 4, part 1: `page` blocks.
  - Pages have `public` or `requires login` (with optional `requires role`), `title "..."`, `text "..."`, `link "..." /path` and `show GET /api/...`.
  - Lists have "Load more", single records are shown as fields, and lists link automatically to the page that shows one record.
  - The generated server serves pages with a strict Content-Security-Policy. The browser runtime (`/_rizo/client.js`) never uses `innerHTML`.
- Quoted text, allowed only in pages.
- New errors RZ0103, RZ0220, RZ0221 and RZ0333–RZ0337.

### Changed

- The example app's endpoints moved under `/api`, the convention when a file has pages.

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

[Unreleased]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.1.0
