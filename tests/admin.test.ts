/**
 * The built-in admin pages (Milestone 10, part 3): which apps get them, what
 * their SQL selects, which paths they reserve, and what the server sends.
 * Behaviour against a real database is in tests/e2e.test.ts ("built-in admin pages").
 */
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";
import { createRequestHandler, type Db } from "../runtime/server.ts";
import { hashToken, SQL } from "../runtime/session.ts";
import { buildApp } from "../src/emit/routes.js";
import { compileErrors, compileOk } from "./helpers.js";

const SOURCE = `
auth User by email roles admin, editor

model User {
  email: Email unique private
  password: Password min 12
  name: Text max 100
  phone: Text max 30 optional encrypted
}

model BlogPost {
  author: User
  title: Text max 200
  notes: Text max 500 private
  published: Bool
}

api GET /api/posts -> list BlogPost.public {
  public
  return db.BlogPost.list(published = true)
}

page / {
  public
  show GET /api/posts
}
`;

const build = (source: string) => {
  const r = compileOk(source);
  return buildApp(r.apis, r.auth, r.pages, r.models, r.privacy, r.site);
};

describe("admin pages: which apps get them", () => {
  it("adds every model, with endpoints and pages, when the auth line has the admin role", () => {
    const app = build(SOURCE);
    expect(app.admin?.map((m) => [m.name, m.slug, m.account])).toEqual([["User", "users", true], ["BlogPost", "blog-posts", false]]);
    const pages = app.pages.filter((p) => p.pattern.startsWith("/admin"));
    expect(pages.map((p) => p.pattern)).toEqual(["/admin", "/admin/users", "/admin/blog-posts"]);
    for (const p of pages) expect(p).toMatchObject({ access: "login", roles: ["admin"] });
    expect(pages[1]?.items).toContainEqual(expect.objectContaining({ kind: "admin", slug: "users", account: true, roles: ["admin", "editor"] }));
    expect(pages[2]?.items).toContainEqual(expect.objectContaining({ kind: "admin", slug: "blog-posts", account: false, roles: [] }));
  });

  it("adds nothing without roles (roles always include admin)", () => {
    const app = build(SOURCE.replace("auth User by email roles admin, editor", "auth User by email"));
    expect(app.admin).toBeUndefined();
    expect(app.pages.some((p) => p.pattern.startsWith("/admin"))).toBe(false);
  });

  it("adds the endpoints but no pages to an app without pages", () => {
    const app = build(SOURCE.replace(/page \/ \{[\s\S]*$/, ""));
    expect(app.admin).toHaveLength(2);
    expect(app.pages).toEqual([]);
  });
});

describe("admin pages: SQL", () => {
  const app = build(SOURCE);
  const users = app.admin?.find((m) => m.name === "User");
  const posts = app.admin?.find((m) => m.name === "BlogPost");

  it("selects only public fields (and the role, for accounts), in id order, with parameters only", () => {
    expect(posts?.listSql).toBe(
      'SELECT "id", "author_id" AS "author", "title", "published" FROM "blog_posts" WHERE ($1::text IS NULL OR "id"::text = lower($1::text) OR strpos(lower("title"), lower($1::text)) > 0) AND ($2::uuid IS NULL OR "id" > $2::uuid) ORDER BY "id" LIMIT $3',
    );
    expect(posts?.publicKeys).toEqual(["id", "author", "title", "published"]);
    expect(users?.publicKeys).toEqual(["id", "name", "phone", "role"]);
    expect(users?.listSql).toContain(', "role" FROM "users"');
    expect(users?.listSql).not.toMatch(/"email"|password/);
    expect(users?.encrypted).toEqual([{ key: "phone", aad: "users.phone" }]);
  });

  it("never searches private or encrypted fields", () => {
    expect(users?.listSql).toContain('strpos(lower("name"), lower($1::text))');
    expect(users?.listSql).not.toContain('lower("phone")');
    expect(posts?.listSql).not.toContain("notes");
  });

  it("deletes one record by id", () => {
    expect(posts?.deleteSql).toBe('DELETE FROM "blog_posts" WHERE "id" = $1');
  });

  it("deletes accounts like DELETE /auth/me, but skips admins inside the statement", () => {
    const guard = `"role" IS DISTINCT FROM 'admin'`;
    expect(users?.deleteSql).toBe(
      `WITH "moved1" AS (UPDATE "blog_posts" SET "author_id" = $2 WHERE "author_id" = $1 AND EXISTS (SELECT 1 FROM "users" WHERE "id" = $1 AND ${guard})) DELETE FROM "users" WHERE "id" = $1 AND ${guard}`,
    );
    // DELETE /auth/me itself is unchanged.
    expect(app.auth?.account.deleteSql).toBe('WITH "moved1" AS (UPDATE "blog_posts" SET "author_id" = $2 WHERE "author_id" = $1) DELETE FROM "users" WHERE "id" = $1');
  });
});

describe("admin pages: reserved paths", () => {
  it("reserves pages under /admin", () => {
    for (const path of ["/admin", "/admin/stats", "/admin/:id"]) {
      const errors = compileErrors(`${SOURCE}\npage ${path} {\n  requires login\n  requires role admin\n  title "Mine"\n}\n`);
      expect(errors[0]).toMatchObject({ code: "RZ0334", message: expect.stringContaining("built-in admin pages") });
    }
  });

  it("reserves endpoints under /admin, and suggests /api", () => {
    const errors = compileErrors(`${SOURCE}\napi GET /admin/posts -> list BlogPost.public {\n  requires login\n  requires role admin\n  return db.BlogPost.list()\n}\n`);
    expect(errors[0]).toMatchObject({ code: "RZ0322", fix: expect.stringContaining("/api/admin/posts") });
  });

  it("leaves /admin free without roles", () => {
    const source = SOURCE.replace(" roles admin, editor", "");
    expect(() => compileOk(`${source}\npage /admin {\n  requires login\n  title "Mine"\n}\n`)).not.toThrow();
  });

  it("lets pages link to /admin", () => {
    expect(() => compileOk(SOURCE.replace("show GET /api/posts", 'show GET /api/posts\n  link "Admin" /admin'))).not.toThrow();
  });
});

describe("admin pages: server", () => {
  let server: Server | undefined;
  const stop = async () => {
    const s = server;
    server = undefined;
    if (s !== undefined) await new Promise((resolve) => s.close(resolve));
  };
  afterEach(stop);
  const TOKEN = "t".repeat(43);

  /** One session for TOKEN (user u1, with `role`); list queries return a row with extra columns. */
  async function start(role: string | null): Promise<{ base: string; queries: string[] }> {
    const queries: string[] = [];
    const db: Db = {
      query: async (sql, values) => {
        queries.push(sql);
        if (sql === SQL.lookup) return { rows: values[0] === hashToken(TOKEN) ? [{ user_id: "11111111-1111-4111-8111-111111111111" }] : [], rowCount: 1 };
        if (sql.startsWith('SELECT "role"')) return { rows: [{ role }], rowCount: 1 };
        if (sql.startsWith('SELECT "id", "author_id"')) {
          return { rows: [{ id: "22222222-2222-4222-8222-222222222222", author: "u", title: "T", published: true, notes: "leak", password_hash: "leak" }], rowCount: 1 };
        }
        return { rows: [], rowCount: 0 };
      },
    };
    const handler = createRequestHandler(build(SOURCE), { db, log: () => undefined });
    server = createServer((req, res) => void handler(req, res));
    await new Promise<void>((resolve) => server?.listen(0, "127.0.0.1", resolve));
    return { base: `http://127.0.0.1:${(server?.address() as AddressInfo).port}`, queries };
  }
  const cookie = { headers: { Cookie: `rizo_session=${TOKEN}` } };

  it("copies only the public keys into responses, even if the query returned more", async () => {
    const { base } = await start("admin");
    const r = await fetch(`${base}/auth/admin/blog-posts`, cookie);
    expect(r.status).toBe(200);
    const text = await r.text();
    expect(JSON.parse(text)).toEqual({ items: [{ id: "22222222-2222-4222-8222-222222222222", author: "u", title: "T", published: true }], next: null });
    expect(text).not.toContain("leak");
  });

  it("refuses everyone but admins before running any query on the model", async () => {
    for (const role of [null, "editor"]) {
      const { base, queries } = await start(role);
      expect((await fetch(`${base}/auth/admin/blog-posts`, cookie)).status).toBe(403);
      expect((await fetch(`${base}/auth/admin/blog-posts`)).status).toBe(401);
      expect(queries.some((q) => q.includes('"blog_posts"'))).toBe(false);
      await stop();
    }
  });

  it("answers 404 for unknown models, and refuses cross-site deletes", async () => {
    const { base } = await start("admin");
    expect((await fetch(`${base}/auth/admin/secrets`, cookie)).status).toBe(404);
    expect((await fetch(`${base}/auth/admin/Blog_Posts`, cookie)).status).toBe(404);
    const cross = await fetch(`${base}/auth/admin/blog-posts/22222222-2222-4222-8222-222222222222`, {
      method: "DELETE", headers: { ...cookie.headers, "Sec-Fetch-Site": "cross-site" },
    });
    expect(cross.status).toBe(403);
  });

  it("shows the Admin menu link only to admins", async () => {
    const admin = await start("admin");
    expect(await (await fetch(`${admin.base}/`, cookie)).text()).toContain('"admin":true');
    await stop();
    const editor = await start("editor");
    expect(await (await fetch(`${editor.base}/`, cookie)).text()).not.toContain('"admin"');
  });
});
