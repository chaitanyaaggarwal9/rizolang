# Rizo Lang (compact spec, v0.7)

You are writing Rizo Lang (`.rz` files). Follow these rules exactly. A file contains `model` blocks, at most one each of the `auth`, `privacy` and `site` lines, `api` blocks and `page` blocks. Never write SQL, HTML or JavaScript.

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

api GET /api/posts -> list Post.public {
  public
  return db.Post.list(published = true, order title, limit 20)
}

api POST /api/posts -> Post.public {
  requires login
  return db.Post.create(body, author = me)
}

api PATCH /api/posts/:id -> Post.public {
  requires login
  requires owner author
  return db.Post.update(id, body)
}

api DELETE /api/posts/:id {
  requires login
  requires owner author
  return db.Post.delete(id)
}
```

## Models

- `model Name {` (PascalCase), one field per line as `name: Type modifiers`, then `}`. No commas or semicolons.
- Field names are camelCase, letters and digits only. Every model gets `id: ID` automatically; never declare it.

| Type       | Meaning                                         | Modifiers allowed                   |
|------------|-------------------------------------------------|-------------------------------------|
| `Text`     | text, max 10000 chars by default                | unique optional private encrypted min max |
| `Number`   | whole number (32-bit). Use cents for money      | unique optional private encrypted min max |
| `Bool`     | true/false                                      | optional private                    |
| `Email`    | email address, 3–254 chars, stored lowercase    | unique optional private encrypted min max |
| `Password` | hashed, never returned, 8–128 chars             | optional min max                    |
| `Date`     | date and time (UTC)                             | unique optional private encrypted   |
| `ID`       | UUID                                            | unique optional private             |
| `File`     | uploaded image or PDF                           | optional private image pdf max      |
| *Model*    | link to another model, e.g. `author: User`      | unique optional private             |

Modifiers:
- `unique`: no two records share the value.
- `optional`: the value may be null.
- `private`: never returned by the API.
- `encrypted`: stored encrypted; the API sees the plain value. Use it for data such as phone numbers. Never with unique, on the login field, or in list filters or order.
- `min N` / `max N`: the length for text, the value for Number. File: `max 5mb` (up to 10mb).
- `image` / `pdf`: what a File holds (neither: both).

File fields need auth and `requires login` endpoints, and must be optional on User. Clients upload first (`POST /_rizo/uploads/posts/photo`) and send the returned url.

A field named `password` (or ending in `Password`) must have the type `Password`.

## auth

`auth User by email` turns on accounts. User needs `email: Email unique` and one required `Password` field; a link from User to User must be optional. Everything account-related is built in under `/auth`: signup with email confirmation, login, logout, password reset, profile (`PATCH /auth/me`), email and password changes, devices, data export and deletion. Never write your own login or account endpoints. AI agents use API tokens limited to chosen endpoints.

Roles: `auth User by email roles admin, editor` (must include admin). Admins assign roles with `PUT /auth/users/:id/role` and get built-in `/admin` pages; never use `/admin` paths. Never add a `role` field; it is hidden.

## privacy

`privacy for EU, UK, IN, US-CA, BR` (one line, needs auth) names the regions served and publishes a /privacy page. In a model, `keep 2 years` (or days, months) deletes records that long after creation; not on the auth model.

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
- Default: 120 requests a minute. Add `limit 10 per minute` (second, minute, hour, day) where tighter fits.
- `requires owner author` lets only the record's owner act (others get 404). It works with find, update and delete (on list, filter with `author = me`), and is **required** on update and delete of a model that links to the auth model, unless the endpoint has `requires role`.
- The return type is `-> Model.public` or `-> list Model.public`, and there is none for delete. Only `.public` can be returned. On find and list, `-> list Post.public with author` also returns each linked author's public fields.
- Paths use lowercase segments and `:camelCase` parameters. Every parameter must be used. `/auth` is reserved.

| Action                          | Method       | Result             |
|---------------------------------|--------------|--------------------|
| `db.M.find(id)`                 | GET          | one record or 404  |
| `db.M.list(filters, order f desc, limit N)` | GET | `{ items, next }` page (limit ≤ 100, default 50) |
| `db.M.create(body)`             | POST         | 201 new record     |
| `db.M.update(id, body)`         | PUT or PATCH | changed record or 404 |
| `db.M.delete(id)`               | DELETE       | 204 or 404         |

- Filters are `field = value`, also `!=`, `<`, `<=`, `>`, `>=` (Number, Date) and `contains` (Text, Email). A value is `me`, a path parameter, a number, `true`, `false` or `?name`, an optional query parameter (never `?limit` or `?after`): `title contains ?q` reads `?q=...` and is skipped when left out. `contains` takes only `?name` or a path parameter. Private, Password and File fields can't be filtered or ordered.
- `body` is the validated JSON request body.
- `list` returns pages: clients call `?limit=10`, then `?after=<next>`. You can't order by an optional field.
- `create(body, published = false)` sets fields the client can't; a link to the auth model must be set this way with `= me`, never from body.
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

- Pages are generated from endpoints. Never write HTML. Quoted text (one line, at most 200 characters) is only allowed in pages and the site line.
- Optional top-level line: `site "My App" color teal logo "logo.png"` (colors: blue, teal, green, purple, pink, red, orange, gray; logo: PNG, JPEG or WebP, never SVG).
- Put endpoints under `/api`. A page can't share a path with an endpoint.
- `show` takes one GET endpoint from the file. Page `:params` fill the endpoint's params by name, and every page param must be used.
- A page must be at least as strict as what it shows: use `requires login` if the endpoint does, and one of its roles if it has `requires role`.
- `form POST /api/posts` (or PUT or PATCH) builds a form from the endpoint's body. `button "Delete" DELETE /api/posts/:id` deletes. Each page has at most one form or button, followed by `then go /path` (`:id` can be the saved record).
- With an auth line, `/login`, `/signup`, `/account`, `/verify-email`, `/reset-password`, `/confirm-email`, `/privacy` (with privacy) and a menu are built in and reserved. Never write login, account or email pages.

## Migrations

`rizolang build` writes `migrations/NNNN_*.sql` when models change. Removing a model or field, changing a type, adding or removing `encrypted`, or removing a role is refused (RZ0904). Never rename a field; add a new one, `optional` on existing models. `rizolang check app.rz` checks without writing; fix every `rizolang audit app.rz` warning. `rizolang dev app.rz` runs it locally.

## Errors

`file.rz:LINE:COL error RZxxxx: message`, then a `fix:` line. Apply the fix exactly. `--json` prints errors as JSON.

## Wrong → Right

```rizo
name: String          →  name: Text
age: Int              →  age: Number
active: Boolean       →  active: Bool
createdAt: DateTime   →  createdAt: Date
userId: UUID          →  userId: ID
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
```

In api blocks: write `-> Post.public`, not `-> Post`, and `api DELETE /api/posts/:id`, not `api GET /api/posts/:id/delete`.

## Checklist before answering

1. Only `model`, `auth`, `privacy`, `site`, `api` and `page`, with one item per line.
2. Every type is Text, Number, Bool, Email, Password, Date, ID or a model name.
3. Model names are PascalCase, field names are camelCase, and no field is named `id`.
4. Every endpoint has `public` or `requires login`, a matching method and one `return` line.
5. Owned records use `author = me` on create and `requires owner` on update and delete.
