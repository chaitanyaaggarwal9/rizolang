# Changelog

All notable changes to Rizo Lang are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may include breaking language changes.

## [Unreleased]

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

[Unreleased]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/chaitanyaaggarwal9/rizolang/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/chaitanyaaggarwal9/rizolang/releases/tag/v0.1.0
