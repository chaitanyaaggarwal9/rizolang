# Rizo Lang (compact spec, v0.4)

You are writing Rizo Lang (`.rz` files). Follow these rules exactly. A file contains `model` blocks, at most one `auth` line, `api` blocks and `page` blocks. Never write SQL, HTML or JavaScript in `.rz` files.

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
| `Text`     | text, max 10000 chars by default                | unique optional private encrypted min max |
| `Number`   | whole number (32-bit). Use cents for money      | unique optional private encrypted min max |
| `Bool`     | true/false                                      | optional private                    |
| `Email`    | email address, 3–254 chars, stored lowercase    | unique optional private encrypted min max |
| `Password` | hashed, never returned, 8–128 chars             | optional min max                    |
| `Date`     | date and time (UTC)                             | unique optional private encrypted   |
| `ID`       | UUID                                            | unique optional private             |
| *Model*    | link to another model, e.g. `author: User`      | unique optional private             |

Modifiers:
- `unique`: no two records share the value.
- `optional`: the value may be null.
- `private`: never returned by the API.
- `encrypted`: stored encrypted; the API still sees the plain value. Never use it with unique, on the login field, or in list filters or order. Use it for sensitive data such as phone numbers.
- `min N` / `max N`: the length for text, the value for Number.

A field named `password` (or ending in `Password`) must have the type `Password`.

## auth

`auth User by email` turns on accounts. User needs `email: Email unique` and one `Password` field. It adds `POST /auth/signup` (emails a confirmation link; login works after it is confirmed), password reset by email, `POST /auth/login`, `POST /auth/logout`, `POST /auth/logout-all`, `GET /auth/me`, `PATCH /auth/me` (edit profile), `POST /auth/password` and `DELETE /auth/me`. Sessions use a secure cookie. Don't write your own login endpoints.

Roles: `auth User by email roles admin, editor` (must include admin). Admins assign roles with `PUT /auth/users/:id/role`. Never add a `role` field yourself; it is hidden and never comes from request bodies.

## api

```
api METHOD /path/:param -> Model.public {
  public            (or: requires login)
  requires role admin, editor     (optional; needs requires login)
  requires owner <link field>     (optional; add "or role admin" to let admins act too)
  return db.Model.action(arguments)
}
```

- Every endpoint has **exactly one** of `public` or `requires login`.
- `requires role admin` gives 403 to users without that role.
- Every endpoint is rate-limited (120 per minute by default). Add `limit 10 per minute` (units: second, minute, hour, day) for endpoints that need a tighter limit, such as comments or messages.
- `requires owner author` lets only the record's owner act; others get 404. It needs `requires login`, and it works with find, update and delete. It is **required** on update and delete of a model that links to the auth model.
- The return type is `-> Model.public` or `-> list Model.public`, and there is none for delete. Only `.public` can be returned.
- Paths use lowercase segments and `:camelCase` parameters. Every parameter must be used. `/auth` is reserved.

| Action                          | Method       | Result             |
|---------------------------------|--------------|--------------------|
| `db.M.find(id)`                 | GET          | one record or 404  |
| `db.M.list(filters, order f desc, limit N)` | GET | `{ items, next }` page (limit ≤ 100, default 50) |
| `db.M.create(body)`             | POST         | 201 new record     |
| `db.M.update(id, body)`         | PUT or PATCH | changed record or 404 |
| `db.M.delete(id)`               | DELETE       | 204 or 404         |

- Filters are `field = value`. A value is `me`, a path parameter, a number, `true` or `false`.
- `body` is the validated JSON request body.
- `list` returns pages: clients call `?limit=10`, then `?after=<next>`. You can't order by an optional field.
- A link to the auth model must be set with `= me` in create, and is never taken from body.
- You cannot create, update or delete the auth model through `api`.

## page

```rizo
page /posts/:id {
  public                       // or: requires login (then optional: requires role admin)
  title "A post"
  text "Any paragraph."
  link "Log in" /login
  show GET /api/posts/:id
}
```

- Pages are generated from endpoints. Never write HTML. Quoted text is only allowed in pages: one line, at most 200 characters.
- Put endpoints under `/api`. A page can't share a path with an endpoint. `/login`, `/signup`, `/account`, `/verify-email` and `/reset-password` are reserved.
- `show` takes one GET endpoint from the file. Page `:params` fill the endpoint's params by name, and every page param must be used.
- A page must be at least as strict as what it shows: use `requires login` if the endpoint does.
- Lists link to a page that shows one record of the same model.
- `form POST /api/posts` (or PUT or PATCH) builds a form from the endpoint's body. `button "Delete" DELETE /api/posts/:id` deletes. Each page has at most one form or button, followed by `then go /path` (`:id` can be the saved record).
- With an auth line, `/login`, `/signup`, `/account` (passkeys), `/verify-email`, `/reset-password` and a log-in/log-out menu are built in. Don't write login, passkey or email pages.

## Migrations

`rizolang build` writes `migrations/NNNN_*.sql` when models change. Removing a model or field, changing a field's type, or removing a role is refused (RZ0904). Never rename a field; add a new one instead. Apply migrations with `node migrate.ts`.

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

1. Only `model`, `auth`, `api` and `page` blocks, with one item per line.
2. Every type is Text, Number, Bool, Email, Password, Date, ID or a model name.
3. Model names are PascalCase, field names are camelCase, and no field is named `id`.
4. Every endpoint has `public` or `requires login`, a matching method and one `return` line.
5. Owned records use `author = me` on create and `requires owner` on update and delete.
