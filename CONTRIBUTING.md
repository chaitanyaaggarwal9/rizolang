# Contributing to Rizo Lang

Thanks for your interest in Rizo Lang! This guide explains how to propose changes and what a pull request needs before it can be merged.

By taking part, you agree to follow our [Code of Conduct](CODE_OF_CONDUCT.md).

> **Found a security problem?** Do not open an issue or pull request. Report it privately as described in [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Report a bug** with the [bug report form](https://github.com/chaitanyaaggarwal9/rizolang/issues/new?template=bug_report.yml).
- **Propose a language change** with the [language proposal form](https://github.com/chaitanyaaggarwal9/rizolang/issues/new?template=language_proposal.yml). Please do this *before* writing code, because every change to the language is a design decision.
- **Improve the docs**, error messages or tests. Small, focused pull requests are welcome without an issue first.

## Development setup

You need Node.js 22.12 or newer. The version used for development is in `.nvmrc`.

```sh
git clone https://github.com/chaitanyaaggarwal9/rizolang.git
cd rizolang
npm ci                 # install the exact locked dependencies
npm test               # run all tests
npm run typecheck      # strict type checking
npm run build          # compile the compiler to build/
node build/bin.js build examples/blog.rz
```

`.npmrc` turns off dependency install scripts and saves dependency versions exactly.

## How the code is organized

| Path                     | What it does                                                        |
|--------------------------|---------------------------------------------------------------------|
| `src/lexer.ts`           | Turns source text into tokens                                        |
| `src/parser.ts`          | Hand-written recursive-descent parser that builds the AST (`src/ast.ts`) |
| `src/checker.ts`         | Validates names, types and modifiers, and collects every error        |
| `src/types.ts`           | The single source of truth for field types and their mappings       |
| `src/emit/`              | Generates PostgreSQL (`sql.ts`) and TypeScript (`typescript.ts`)    |
| `src/diagnostics.ts`     | The error format: code, location, message and fix                   |
| `src/cli.ts`, `src/bin.ts` | The `rizolang` command                                            |
| `docs/SPEC.md`           | The language specification                                          |
| `docs/SPEC-COMPACT.md`   | Short spec for AI system prompts (under 1,500 words)                |
| `tests/`                 | Vitest tests, including `security.test.ts` and `docs.test.ts`       |

## Rules every change must follow

These rules come from the project's design principles (see [CLAUDE.md](CLAUDE.md)) and are enforced in review.

1. **The spec is the contract.** If you change the language, update `docs/SPEC.md`, `docs/SPEC-COMPACT.md` and the tests in the same pull request. `tests/docs.test.ts` fails if they drift apart.
2. **Every error is actionable.** A new error needs:
   - a new `RZxxxx` code, added to the table in `docs/SPEC.md`,
   - a precise location,
   - a concrete `fix` line.
3. **Security guarantees are tested.** Anything that touches passwords, public types, generated SQL or input validation needs a test in `tests/security.test.ts`.
4. **No SQL from text.** Generated SQL must never contain user-controlled text. Identifiers come only from validated names and are always quoted. Values (from Milestone 2 on) always go through query parameters.
5. **Never rely on types alone to hide secrets.** TypeScript types are structural, so runtime code must copy or select public fields explicitly.
6. **No new dependencies without discussion.** The compiler has zero runtime dependencies. Open an issue before adding any package, including dev dependencies. Every version is pinned exactly.
7. **Keep it small.** A feature that makes the spec much longer needs a strong reason.

## Pull requests

1. Fork the repository and create a branch from `main`.
2. Make your change, with tests.
3. Run `npm run typecheck && npm test` locally.
4. Open a pull request and fill in the template.

Every pull request needs two things before it can be merged:

- **Passing CI.** This includes tests on Node 22, 24 and 26, a PostgreSQL schema check, CodeQL analysis and dependency review.
- **Approval from a code owner.** See [.github/CODEOWNERS](.github/CODEOWNERS).

The `main` branch is protected: nobody can push to it directly, force-push to it or delete it.

### Commit messages

- Write a short summary line in the imperative mood ("Add Email length check", not "Added…").
- If the reason for the change isn't obvious, add a blank line and a short explanation.

### AI-assisted contributions

Contributions written with AI tools are welcome. You are responsible for every line you submit: read it, test it, and make sure it follows the rules above.

## License

By contributing, you agree that your contributions are licensed under the [Apache License 2.0](LICENSE), the same license as the project.
