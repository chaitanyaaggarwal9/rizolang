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
- Keep dependencies to an absolute minimum. The compiler has **zero runtime dependencies**, and every dev dependency is pinned to an exact version.
- License: Apache 2.0.

## Project layout

- `src/lexer.ts` → `src/parser.ts` (builds an AST, see `src/ast.ts`) → `src/checker.ts` → `src/emit/{sql,typescript}.ts`, orchestrated by `src/compiler.ts`.
- `src/types.ts` is the single source of truth for field types, their SQL/TS mappings and allowed modifiers.
- `src/diagnostics.ts` holds the error format. Every diagnostic has a code, a span, a message and a fix.
- `src/cli.ts` and `src/bin.ts` contain the `rizolang build file.rz` command, which writes to `./dist`.
- `docs/SPEC.md` is the full spec. `docs/SPEC-COMPACT.md` is a version of it under 1,500 words for small-context models.

## Rules for changing the language

- **The spec is the contract.** Any language change must update `docs/SPEC.md`, `docs/SPEC-COMPACT.md` and the tests in the same change. If code and spec disagree, that is a bug.
- New errors get a new `RZxxxx` code, are added to the table in SPEC.md, and must include a concrete `fix`.
- Security guarantees (SPEC §8) need a test in `tests/security.test.ts`.
- Never emit SQL built from user-controlled text. Identifiers come only from validated names (letters and digits) and are always double-quoted. Values, from Milestone 2 on, always go through parameters.
- TypeScript types are structural: a `User` can be assigned to `UserPublic` without error. Runtime code (Milestone 2+) must therefore select or copy only public fields explicitly. It must never rely on types alone to strip secrets.
- If a design decision is unclear, ask the maintainer instead of guessing.

## Commands

- `npm test`: run all tests
- `npm run typecheck`: run strict type checking over src and tests
- `npm run build`: compile the compiler to `build/`
- `node build/bin.js build examples/blog.rz`: try it out

## Current milestone

Milestone 1 covers only `model` blocks, compiled to a PostgreSQL schema and TypeScript types. Do not implement `api` routes or frontend until the maintainer starts Milestone 2.
