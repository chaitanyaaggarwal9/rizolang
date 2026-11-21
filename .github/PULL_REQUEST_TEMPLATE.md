## What does this change?

<!-- One or two sentences. Link the issue: "Fixes #123". -->

## Why?

<!-- The problem this solves. For language changes, link the approved proposal. -->

## Checklist

- [ ] `npm run typecheck && npm test` passes locally
- [ ] Tests added or updated for the change
- [ ] If the language changed: `docs/SPEC.md` **and** `docs/SPEC-COMPACT.md` are updated
- [ ] New errors have an `RZxxxx` code, a precise location and a concrete `fix`, and are listed in the SPEC.md table
- [ ] Anything touching passwords, public types, SQL or validation has a test in `tests/security.test.ts`
- [ ] No new dependencies (or the new dependency was agreed in an issue and is pinned to an exact version)
- [ ] `CHANGELOG.md` updated under "Unreleased" (for user-visible changes)

<!-- Security vulnerabilities must not be reported in pull requests. See SECURITY.md. -->
