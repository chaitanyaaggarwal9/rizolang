# Rizo Lang: guidance for AI coding sessions

Rizo Lang is a secure, simple, full-stack web language for the AI era. Source files use the `.rz` extension. It belongs to the Rizo ecosystem (https://rizobot.com), alongside Rizo, an open-source BYOK AI coding assistant for VS Code. It compiles into existing technology and does not have its own runtime.

## Core design principles (never violate these)

1. **Dangerous mistakes must be impossible, not just unlikely.** For example, there is no way to write raw SQL or build a query from text, so SQL injection cannot happen.
2. **Very strict and very clear.** Strong static types. Every error message must say what went wrong, where (file, line, column) and how to fix it, so both AI and humans can correct mistakes quickly.
3. **Small.** The whole language must be explainable in a short spec (5–10 pages), so an AI can learn it from the docs alone.
4. **Secure by default.**
   - Passwords are hashed automatically and can never be returned in an API response or logged.
   - All inputs are validated automatically.
   - Login and permission checks are part of the syntax.
5. **AI-first documentation.** The spec must work as a system prompt. When the Rizo VS Code extension detects a `.rz` file, it will include the spec, so any model (even small, cheap ones) can write Rizo Lang correctly without prior training.

## Compile targets

- Backend: Node.js + TypeScript
- Database: PostgreSQL, always through parameterized queries
- Frontend: plain HTML + TypeScript (later milestone)

## Compiler tech

- TypeScript on Node.js, in strict mode (see `tsconfig.json`).
- Hand-written lexer and recursive-descent parser. Never use a parser generator.
- Tests use Vitest.
- Keep dependencies to an absolute minimum. The compiler has **zero runtime dependencies**, and every dev dependency is pinned to an exact version. Generated apps depend only on `pg` (pinned), which the maintainer approved.
- License: Apache 2.0.

## Project layout

- `src/lexer.ts` → `src/parser.ts` (builds an AST, see `src/ast.ts`) → `src/checker.ts` (models) and `src/check-api.ts` (auth and api) → `src/emit/{sql,typescript,routes}.ts`, orchestrated by `src/compiler.ts`.
- `src/schema.ts` describes the database schema, including one index per distinct `list` query (filter columns, order column, then `id`). `src/emit/sql.ts` renders it, and `src/migrations.ts` compares it with `migrations/rizo-schema.json` to plan migrations. Anything that would drop data must be listed in `dataLoss`, so that the CLI refuses it without `--allow-data-loss`.
- `src/check-page.ts` checks `page` blocks. `runtime/pages.ts` serves them, and `runtime/client/rizo-client.js` renders them in the browser. That file is plain JavaScript with JSDoc types, checked by `tsconfig.client.json`. It must never use innerHTML, outerHTML, insertAdjacentHTML, document.write or eval: elements are created only through `el()`, and `tests/client.test.ts` enforces this.
- `runtime/` is copied verbatim into every generated app (`dist/runtime/`). It must stay small, readable, free of dependencies other than `pg`, and use erasable TypeScript only (Node runs it with type stripping). The runtime never builds SQL: all SQL comes from `routes.ts`, generated at compile time.
- `src/types.ts` is the single source of truth for field types, their SQL/TS mappings and allowed modifiers.
- `src/diagnostics.ts` holds the error format. Every diagnostic has a code, a span, a message and a fix.
- `src/cli.ts` and `src/bin.ts` contain the `rizolang build file.rz` command, which writes to `./dist`.
- `docs/SPEC.md` is the full spec. `docs/SPEC-COMPACT.md` is a version of it under 1,500 words for small-context models.

## Rules for changing the language

- **The spec is the contract.** Any language change must update `docs/SPEC.md`, `docs/SPEC-COMPACT.md` and the tests in the same change. If code and spec disagree, that is a bug.
- New errors get a new `RZxxxx` code, are added to the table in SPEC.md, and must include a concrete `fix`.
- Security guarantees (SPEC §7) need a test in `tests/security.test.ts`, and runtime behaviour needs one in `tests/e2e.test.ts` (run with `RIZO_TEST_DATABASE_URL`).
- Never emit SQL built from user-controlled text. Identifiers come only from validated names (letters and digits) and are always double-quoted. Values, from Milestone 2 on, always go through parameters.
- TypeScript types are structural: a `User` can be assigned to `UserPublic` without error. The runtime therefore selects only public columns in SQL **and** copies only `publicKeys` into responses. Never rely on types alone to strip secrets.
- Access control is never optional: every endpoint declares `public` or `requires login`, ownership checks live in the SQL `WHERE` clause, and links to the auth model are set from the session (`= me`), never from request bodies.
- If a design decision is unclear, ask the maintainer instead of guessing.

## Commands

- `npm test`: run all tests (`RIZO_TEST_DATABASE_URL=postgres://... npm test` also runs the end-to-end tests)
- `npm run typecheck`: run strict type checking over src and tests
- `npm run build`: compile the compiler to `build/`
- `node build/src/bin.js build examples/blog.rz`: try it out

## Current milestone

Milestones 1–4 are complete (v0.4.0): models, `auth`, `api` blocks, links, `private` fields, roles, pagination, account management, migrations, and web pages with forms. Maintainer decisions that still apply:
- `api` blocks use braces, like `model` blocks.
- Sessions are server-side, stored as hashed tokens in `_rizo_sessions` and sent in an HttpOnly cookie.
- Generated apps use `pg` plus the runtime copied into `dist/`.
- List endpoints return `{ items, next }` with keyset pagination.
- Changes that would delete data need `--allow-data-loss`.
- `RIZO_ADMIN_EMAILS` only promotes accounts that already exist.
- Pages are generated from endpoints (`show`, `form`, `button`); there are no HTML templates. Quoted text is allowed only in pages.
- The browser runtime is plain JavaScript with JSDoc types (no build step, no new dependencies), served by the same Node server as the API. It navigates only by setting `location.pathname`.

Releases are published to npm by `.github/workflows/publish.yml`: the workflow stages the version, and the maintainer approves it on npm with two-factor authentication (see CONTRIBUTING.md, "Releasing").

Don't start new language features until the maintainer chooses the next milestone.
