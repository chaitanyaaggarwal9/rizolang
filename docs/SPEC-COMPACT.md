# Rizo Lang (compact spec, v0.2)

You are writing Rizo Lang (`.rz` files). Follow these rules exactly. A file contains only `model` blocks, at most one `auth` line, and `api` blocks. Never write SQL, TypeScript or `page` blocks in `.rz` files.

## Example

```rizo
// comment
auth User by email

model User {
  email: Email unique private
  password: Password min 12
  name: Text max 100
}

model Post {
  author: User
  title: Text min 1 max 200
  views: Number min 0 optional
  published: Bool
}

api GET /posts -> list Post.public {
  public
  return db.Post.list(published = true, order title, limit 20)
}

api GET /posts/:id -> Post.public {
  public
  return db.Post.find(id)
}

api POST /posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}

api PATCH /posts/:id -> Post.public {
  requires login
  requires owner author
  return db.Post.update(id, body)
}

api DELETE /posts/:id {
  requires login
  requires owner author
  return db.Post.delete(id)
}
```

## Models

- Write `model Name {` with a PascalCase name, one field per line as `name: Type modifiers`, then `}`. No commas or semicolons.
- Field names are camelCase. Names contain only letters and digits.
- Every model gets `id: ID` automatically. Never declare `id`.

| Type       | Meaning                                         | Modifiers allowed                   |
|------------|-------------------------------------------------|-------------------------------------|
| `Text`     | text, max 10000 chars by default                | unique optional private min max     |
| `Number`   | whole number (32-bit). Use cents for money      | unique optional private min max     |
| `Bool`     | true/false                                      | optional private                    |
| `Email`    | email address, 3–254 chars, stored lowercase    | unique optional private min max     |
| `Password` | hashed, never returned, 8–128 chars             | optional min max                    |
| `Date`     | date and time (UTC)                             | unique optional private             |
| `ID`       | UUID                                            | unique optional private             |
| *Model*    | link to another model, e.g. `author: User`      | unique optional private             |

Modifiers:
- `unique`: no two records share the value.
- `optional`: the value may be null.
- `private`: never returned by the API.
- `min N` / `max N`: the length for text, the value for Number.

A field named `password` (or ending in `Password`) must have the type `Password`.

## auth

`auth User by email` turns on accounts. User needs `email: Email unique` and one `Password` field. It adds `POST /auth/signup`, `POST /auth/login`, `POST /auth/logout` and `GET /auth/me`. Sessions use a secure cookie. Don't write your own login endpoints.

## api

```
api METHOD /path/:param -> Model.public {
  public            (or: requires login)
  requires owner <link field>     (optional)
  return db.Model.action(arguments)
}
```

- Every endpoint has **exactly one** of `public` or `requires login`.
- `requires owner author` lets only the record's owner act; others get 404. It needs `requires login`, and it works with find, update and delete. It is **required** on update and delete of a model that links to the auth model.
- The return type is `-> Model.public` or `-> list Model.public`, and there is none for delete. Only `.public` can be returned.
- Paths use lowercase segments and `:camelCase` parameters. Every parameter must be used. `/auth` is reserved.

| Action                          | Method       | Result             |
|---------------------------------|--------------|--------------------|
| `db.M.find(id)`                 | GET          | one record or 404  |
| `db.M.list(filters, order f desc, limit N)` | GET | list (limit ≤ 100, default 50) |
| `db.M.create(body)`             | POST         | 201 new record     |
| `db.M.update(id, body)`         | PUT or PATCH | changed record or 404 |
| `db.M.delete(id)`               | DELETE       | 204 or 404         |

- Filters are `field = value`. A value is `me`, a path parameter, a number, `true` or `false`.
- `body` is the validated JSON request body.
- A link to the auth model must be set with `= me` in create, and is never taken from body.
- You cannot create, update or delete the auth model through `api`.

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

In api blocks:
- Every endpoint needs `public` or `requires login`; never leave it out.
- Write `db.Post.create(body, author = me)`, not `db.Post.create(body)`.
- Write `-> Post.public`, not `-> Post`.
- Use `api DELETE /posts/:id`, not `api GET /posts/:id/delete`.
- Write `requires owner author` on update and delete of user-owned records.

## Checklist before answering

1. Only `model`, `auth` and `api` blocks, with one item per line.
2. Every type is Text, Number, Bool, Email, Password, Date, ID or a model name.
3. Model names are PascalCase, field names are camelCase, and no field is named `id`.
4. Every endpoint has `public` or `requires login`, a matching method and one `return` line.
5. Owned records use `author = me` on create and `requires owner` on update and delete.
