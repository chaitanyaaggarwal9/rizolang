# Rizo Lang (compact spec, v0.1)

You are writing Rizo Lang (`.rz` files). Follow these rules exactly. Only `model` blocks exist in this version. Do NOT write `api`, `page`, SQL or TypeScript in `.rz` files.

## Syntax

```rizo
// comment
model User {
  email: Email unique
  password: Password min 12
  name: Text max 100
  bio: Text max 500 optional
  isAdmin: Bool
}

model BlogPost {
  authorId: ID
  title: Text min 1 max 200
  views: Number min 0
  publishedAt: Date optional
}
```

- A block starts with the lowercase keyword `model`, then a PascalCase name (`BlogPost`), then `{`, and ends with `}`.
- Write one field per line: `name: Type modifiers...`. Do not use commas or semicolons.
- Field names are camelCase (`firstName`). Names contain only letters and digits, with no `_` or `-`.
- Every model gets `id: ID` automatically. Never declare `id`.
- A model needs at least one field. Model and field names must be unique.
- Comments use `//` only.

## Types (exactly seven)

| Type       | Meaning                                                    | Modifiers allowed           |
|------------|------------------------------------------------------------|-----------------------------|
| `Text`     | text, max 10000 chars by default                           | unique optional min max     |
| `Number`   | whole number (32-bit). No decimals; use cents for money    | unique optional min max     |
| `Bool`     | true/false                                                 | optional                    |
| `Email`    | email address, 3–254 chars, stored lowercase               | unique optional min max     |
| `Password` | hashed automatically, never returned by APIs, 8–128 chars  | optional min max            |
| `Date`     | date and time (UTC)                                        | unique optional             |
| `ID`       | UUID, e.g. another record's id                             | unique optional             |

## Modifiers

- `unique`: no two records share the value.
- `optional`: the value may be null. Fields are required by default.
- `min N` / `max N`: length in characters for Text, Email and Password, and the value for Number. N is a whole number.
- Each modifier appears at most once per field. `min` must be ≤ `max`.
- Allowed limits: Text max 1–1000000; Email 3–254; Password 8–128; Number −2147483648 to 2147483647.

## Generated output

`rizolang build app.rz` writes `dist/schema.sql` (PostgreSQL) and `dist/types.ts`. For each model it generates three types:

- `User`: the stored record. Server-only, and holds the password hash.
- `User.public` (`UserPublic`): safe to return from an API. Password fields are always removed.
- `User.input` (`UserInput`): what a client sends to create a record, with a plain-text password that gets hashed.

Tables are snake_case plurals (`BlogPost` → `blog_posts`), and columns are snake_case (`firstName` → `first_name`). A Password field `password` is stored as `password_hash`.

## Errors

The format is `file.rz:LINE:COL error RZxxxx: message`, followed by a `fix:` line. Apply the fix exactly as written.

## Wrong → Right

```rizo
name: String          →  name: Text
age: Int              →  age: Number
active: Boolean       →  active: Bool
createdAt: DateTime   →  createdAt: Date
userId: UUID          →  userId: ID
email: Email,         →  email: Email
name: Text(100)       →  name: Text max 100
email: Email @unique  →  email: Email unique
nickname?: Text       →  nickname: Text optional
first_name: Text      →  firstName: Text
model user {          →  model User {
id: ID                →  (remove it; id is automatic)
password: Text        →  password: Password
password: Password unique  →  password: Password
password: Password min 4   →  password: Password min 8
price: Number min 0.5      →  priceCents: Number min 50
isAdmin: Bool max 1        →  isAdmin: Bool
```

## Checklist before answering

1. Only `model` blocks are allowed, and each has at least one field.
2. Every type is one of: Text, Number, Bool, Email, Password, Date, ID.
3. Each field is on its own line, with no commas, semicolons or `@`.
4. Model names are PascalCase, field names are camelCase, and no field is named `id`.
5. Passwords always use the `Password` type. A field named `password` or ending in `Password` must be `Password` (the compiler enforces this).
