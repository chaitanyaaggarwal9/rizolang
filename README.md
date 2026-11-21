# Rizo Lang

**A secure, simple, full-stack web language for the AI era.**

Rizo Lang is part of the [Rizo](https://rizobot.com) ecosystem, alongside **Rizo**, an open-source BYOK AI coding assistant for VS Code. Rizo Lang compiles into technology you already use:

- **Database:** PostgreSQL, always through parameterized queries
- **Backend:** Node.js + TypeScript
- **Frontend:** plain HTML + TypeScript (planned)

Rizo Lang is designed so that dangerous mistakes are impossible:

- There is no raw SQL.
- Passwords are hashed automatically and can never appear in a public API type.
- Every error says what went wrong, where it happened and how to fix it.

The whole language fits in a short spec that doubles as a system prompt, so even small AI models can write it correctly.

> **Status:** early development (Milestone 1). Only `model` blocks are supported for now.

## Example

```rizo
// app.rz
model User {
  email: Email unique
  password: Password min 12
  name: Text max 100
}
```

```sh
rizolang build app.rz
```

This produces:

- `dist/schema.sql`: a PostgreSQL table with `NOT NULL`, `UNIQUE` and `CHECK` constraints. The password is stored as `password_hash`.
- `dist/types.ts`: three TypeScript types.
  - `User`: the stored record, server-only.
  - `UserPublic`: safe for API responses. It never contains the password.
  - `UserInput`: the data needed to create a user.

Mistakes get precise errors:

```
app.rz:5:9 error RZ0301: Unknown field type "String" on field "User.name".
  5 |   name: String max 100
    |         ^^^^^^
  fix: Use "Text" instead. Valid types: Text, Number, Bool, Email, Password, Date, ID.
```

## Documentation

- [Language specification](docs/SPEC.md)
- [Compact specification](docs/SPEC-COMPACT.md): a short version for AI system prompts

## Development

Requires Node.js 22.12 or newer.

```sh
npm install
npm test               # run the test suite
npm run typecheck      # strict type checking
npm run build          # compile the compiler to build/
node build/bin.js build examples/blog.rz
```

The compiler has no runtime dependencies. It uses a hand-written lexer and a recursive-descent parser.

## Security

Please report vulnerabilities privately. See [SECURITY.md](SECURITY.md).

## Links

- Website: [rizobot.com](https://rizobot.com)
- Rizo, the AI coding assistant for VS Code: see [rizobot.com](https://rizobot.com)

## License

[Apache License 2.0](LICENSE)
