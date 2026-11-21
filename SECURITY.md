# Security Policy

Security is a core design goal of Rizo Lang. A bug that lets generated code leak passwords, skip validation, or run injected SQL is treated as a critical issue.

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for security problems.**

Report vulnerabilities privately through GitHub's private vulnerability reporting:

1. Go to this repository's **Security** tab.
2. Click **Report a vulnerability**.
3. Describe the problem. If you can, include:
   - the Rizo Lang version (`rizolang --version`),
   - a minimal `.rz` file that shows the issue,
   - the generated output, and what you expected instead,
   - the impact, if you know it (for example: "password hash appears in `UserPublic`").

Only you and the maintainers can see the report.

## What to expect

- We aim to acknowledge reports within 5 business days.
- We will keep you informed while we investigate and fix the problem.
- Once a fix is released, we will publish a GitHub Security Advisory and credit you, unless you prefer to stay anonymous.

## Scope

In scope:

- The `rizolang` compiler, the code it generates and the runtime copied into generated apps (`runtime/`).
- Any case where a guarantee in [docs/SPEC.md §7](docs/SPEC.md#7-security-guarantees) does not hold, for example:
  - a way to reach data without the required login or ownership,
  - a password, hash or private field appearing in a response or log,
  - request data changing a SQL query,
  - a way around validation, rate limits or the cross-site check.

Out of scope:

- Vulnerabilities in PostgreSQL, Node.js or other third-party software. Please report those to their maintainers.
- Problems that need someone to edit the generated files by hand.

## Supported versions

Rizo Lang is in early development. Only the latest released version receives security fixes.
