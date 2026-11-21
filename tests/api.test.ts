import { describe, expect, it } from "vitest";
import { compileErrors, compileOk, firstError } from "./helpers.js";

const MODELS = `auth User by email

model User {
  email: Email unique private
  password: Password
  name: Text
}

model Post {
  author: User
  title: Text
  published: Bool
  views: Number optional
  note: Text private
}
`;
/** Line number of the first line after MODELS. */
const L = MODELS.split("\n").length;

const withApi = (api: string, models = MODELS) => `${models}${api}\n`;

describe("parsing api and auth blocks", () => {
  it("parses a complete endpoint", () => {
    const { apis } = compileOk(withApi(`api GET /posts/:id -> Post.public {
  public
  return db.Post.find(id)
}`));
    expect(apis[0]).toMatchObject({
      method: "GET",
      path: "/posts/:id",
      segments: [{ kind: "static", value: "posts" }, { kind: "param", name: "id" }],
      params: [{ name: "id", type: "ID" }],
      access: "public",
      returns: "one",
      query: { action: "find", idParam: "id" },
    });
  });

  it.each([
    ["api get /posts -> list Post.public {\n  public\n  return db.Post.list()\n}", "RZ0213", "uppercase"],
    ["api FETCH /posts {\n}", "RZ0213", "GET, POST"],
    ["api GET posts {\n}", "RZ0214", "/posts"],
    ["api GET /posts -> {\n}", "RZ0215", "Post.public"],
    ["api GET /posts -> Post {\n}", "RZ0215", "Post.public"],
    ["api GET /posts/:id Post.public {\n}", "RZ0203", "-> Post.public"],
    ["api GET /posts -> list Post.public {\n  publik\n}", "RZ0216", '"public"'],
    ["api GET /posts -> list Post.public {\n  requires admin\n}", "RZ0216", "requires login"],
    ["api GET /posts -> list Post.public {\n  public\n  return Post.list()\n}", "RZ0217", "db.Post"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(limit)\n}", "RZ0217", "limit 20"],
    ["api GET /posts -> list Post.public {\n  public return db.Post.list()\n}", "RZ0212", "own line"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list()\n", "RZ0210", "}"],
  ])("rejects %j with %s", (src, code, fix) => {
    const d = firstError(withApi(src));
    expect(d.code).toBe(code);
    expect(d.fix).toContain(fix);
  });

  it("reports the auth line with the exact location", () => {
    const d = firstError("auth User email\nmodel User {\n  email: Email unique\n  password: Password\n}");
    expect(d).toMatchObject({ code: "RZ0218", span: { line: 1, col: 11 } });
  });

  it("suggests api for common route keywords", () => {
    expect(firstError("route GET /posts {\n}").fix).toContain("api");
  });
});

describe("access rules", () => {
  it("requires every endpoint to say public or requires login", () => {
    const d = firstError(withApi("api GET /posts -> list Post.public {\n  return db.Post.list()\n}"));
    expect(d).toMatchObject({ code: "RZ0318", span: { line: L, col: 5 } });
    expect(d.fix).toContain("public");
  });

  it("rejects public together with requires login", () => {
    expect(firstError(withApi("api GET /posts -> list Post.public {\n  public\n  requires login\n  return db.Post.list()\n}")).code).toBe("RZ0318");
  });

  it("rejects duplicate access lines", () => {
    expect(firstError(withApi("api GET /posts -> list Post.public {\n  public\n  public\n  return db.Post.list()\n}")).code).toBe("RZ0318");
  });

  it("requires login before requires owner", () => {
    const d = firstError(withApi("api DELETE /posts/:id {\n  requires owner author\n  return db.Post.delete(id)\n}"));
    expect(d.code).toBe("RZ0318");
    expect(d.fix).toContain("requires login");
  });

  it("requires an auth line for login", () => {
    const d = firstError("model Note {\n  text: Text\n}\napi GET /notes -> list Note.public {\n  requires login\n  return db.Note.list()\n}");
    expect(d.code).toBe("RZ0319");
    expect(d.fix).toContain("auth User by email");
  });

  it("rejects me in a public endpoint", () => {
    expect(firstError(withApi("api GET /posts -> list Post.public {\n  public\n  return db.Post.list(author = me)\n}")).code).toBe("RZ0330");
  });
});

describe("return lines and types", () => {
  it.each([
    ["api GET /posts -> list Post.public {\n  public\n}", "RZ0320"],
    ["api GET /posts -> list Post.public {\n  return db.Post.list()\n  public\n}", "RZ0320"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list()\n  return db.Post.list()\n}", "RZ0320"],
    ["api GET /posts {\n  public\n  return db.Post.list()\n}", "RZ0321"],
    ["api GET /posts -> Post.public {\n  public\n  return db.Post.list()\n}", "RZ0321"],
    ["api GET /posts/:id -> list Post.public {\n  public\n  return db.Post.find(id)\n}", "RZ0321"],
    ["api GET /posts/:id -> User.public {\n  public\n  return db.Post.find(id)\n}", "RZ0321"],
    ["api DELETE /posts/:id -> Post.public {\n  requires login\n  requires owner author\n  return db.Post.delete(id)\n}", "RZ0321"],
  ])("rejects %j with %s", (src, code) => {
    expect(firstError(withApi(src)).code).toBe(code);
  });

  it("only allows the public view to be returned", () => {
    const d = firstError(withApi("api GET /users/:id -> User.input {\n  public\n  return db.User.find(id)\n}"));
    expect(d.code).toBe("RZ0321");
    expect(d.fix).toContain("User.public");
  });
});

describe("queries", () => {
  it.each([
    ["api GET /posts -> list Blog.public {\n  public\n  return db.Blog.list()\n}", "RZ0316"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.all()\n}", "RZ0325"],
    ["api GET /posts/:id -> Post.public {\n  public\n  return db.Post.find()\n}", "RZ0325"],
    ["api GET /posts/:id -> Post.public {\n  public\n  return db.Post.find(id, id)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(colour = 1)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(title = 5)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(published = 1)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(limit 500)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(limit 5, limit 6)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(note = 1)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  public\n  return db.Post.list(order note)\n}", "RZ0325"],
    ["api GET /posts -> list Post.public {\n  requires login\n  return db.Post.list(title = me)\n}", "RZ0325"],
    ["api PATCH /posts/:id -> Post.public {\n  requires login\n  return db.Post.update(id)\n}", "RZ0325"],
    ["api POST /posts -> Post.public {\n  requires login\n  return db.Post.create(author = me)\n}", "RZ0325"],
  ])("rejects %j with %s", (src, code) => {
    expect(firstError(withApi(src)).code).toBe(code);
  });

  it("does not allow ordering by optional fields, which pages could not resume after", () => {
    const d = firstError(withApi("api GET /posts -> list Post.public {\n  public\n  return db.Post.list(order views)\n}"));
    expect(d.code).toBe("RZ0325");
    expect(d.message).toContain("optional");
  });

  it("accepts filters, ordering and limits", () => {
    const { apis } = compileOk(withApi(
      "api GET /users/:userId/posts -> list Post.public {\n  public\n  return db.Post.list(author = userId, published = true, order title desc, limit 10)\n}",
    ));
    expect(apis[0]?.query).toMatchObject({ action: "list", limit: 10, order: { descending: true } });
    expect(apis[0]?.params).toEqual([{ name: "userId", type: "ID" }]);
  });
});

describe("paths and parameters", () => {
  it.each([
    ["/posts/", "trailing slash"],
    ["/posts//x", "empty segment"],
    ["/Posts", "lowercase"],
    ["/blog_posts", "lowercase"],
    ["/posts/:Id", "camelCase"],
    ["/posts/:me", "reserved"],
    ["/posts/:id/:id", "twice"],
  ])("rejects %s", (path, hint) => {
    const d = firstError(withApi(`api GET ${path} -> list Post.public {\n  public\n  return db.Post.list()\n}`));
    expect(d.code).toBe("RZ0322");
    expect(`${d.message} ${d.fix}`.toLowerCase()).toContain(hint.toLowerCase());
  });

  it("reserves /auth for login endpoints", () => {
    expect(firstError(withApi("api GET /auth/users -> list User.public {\n  public\n  return db.User.list()\n}")).code).toBe("RZ0322");
  });

  it("rejects unknown and unused path parameters", () => {
    expect(firstError(withApi("api GET /posts/:id -> Post.public {\n  public\n  return db.Post.find(postId)\n}")).code).toBe("RZ0323");
    expect(firstError(withApi("api GET /posts/:id -> list Post.public {\n  public\n  return db.Post.list()\n}")).code).toBe("RZ0323");
  });

  it("rejects duplicate routes, even with different parameter names", () => {
    const d = firstError(withApi(
      "api GET /posts/:id -> Post.public {\n  public\n  return db.Post.find(id)\n}\napi GET /posts/:postId -> Post.public {\n  public\n  return db.Post.find(postId)\n}",
    ));
    expect(d.code).toBe("RZ0324");
    expect(d.message).toContain(`line ${L}`);
  });
});

describe("safety rules", () => {
  it("requires links to the auth model to be set to me on create", () => {
    const d = firstError(withApi("api POST /posts -> Post.public {\n  requires login\n  return db.Post.create(body)\n}"));
    expect(d.code).toBe("RZ0326");
    expect(d.fix).toContain("author = me");
  });

  it("does not allow the owner to be set from a path parameter", () => {
    expect(firstError(withApi("api POST /users/:userId/posts -> Post.public {\n  requires login\n  return db.Post.create(body, author = userId)\n}")).code).toBe("RZ0326");
  });

  it.each(["create(body)", "update(id, body)", "delete(id)"])("does not allow %s on the auth model", (call) => {
    const method = call.startsWith("create") ? "POST" : call.startsWith("update") ? "PATCH" : "DELETE";
    const path = call.startsWith("create") ? "/users" : "/users/:id";
    const ret = call.startsWith("delete") ? "" : " -> User.public";
    const errs = compileErrors(withApi(`api ${method} ${path}${ret} {\n  requires login\n  return db.User.${call}\n}`));
    expect(errs.map((e) => e.code)).toContain("RZ0327");
  });

  it.each([
    ["GET", "create(body, author = me)", "/posts"],
    ["POST", "list()", "/posts"],
    ["GET", "delete(id)", "/posts/:id"],
    ["PUT", "find(id)", "/posts/:id"],
  ])("rejects %s with %s", (method, call, path) => {
    const errs = compileErrors(withApi(`api ${method} ${path} -> Post.public {\n  requires login\n  return db.Post.${call}\n}`));
    expect(errs.map((e) => e.code)).toContain("RZ0328");
  });

  it.each([
    ["api GET /posts -> list Post.public {\n  requires login\n  requires owner author\n  return db.Post.list()\n}", "Filter the list"],
    ["api GET /posts/:id -> Post.public {\n  requires login\n  requires owner title\n  return db.Post.find(id)\n}", "author"],
    ["api GET /posts/:id -> Post.public {\n  requires login\n  requires owner writer\n  return db.Post.find(id)\n}", "author"],
  ])("rejects invalid requires owner: %j", (src, fix) => {
    const d = firstError(withApi(src));
    expect(d.code).toBe("RZ0329");
    expect(d.fix).toContain(fix);
  });
});

describe("owned records", () => {
  it.each([
    ["api PATCH /posts/:id -> Post.public {\n  requires login\n  return db.Post.update(id, body)\n}", "requires owner author"],
    ["api DELETE /posts/:id {\n  requires login\n  return db.Post.delete(id)\n}", "requires owner author"],
    ["api DELETE /posts/:id {\n  public\n  return db.Post.delete(id)\n}", "Replace `public`"],
  ])("requires an ownership check to change or delete them: %j", (src, fix) => {
    const d = firstError(withApi(src));
    expect(d.code).toBe("RZ0331");
    expect(d.fix).toContain(fix);
  });

  it("does not require ownership for models that do not belong to users", () => {
    compileOk(withApi("api DELETE /tags/:id {\n  requires login\n  return db.Tag.delete(id)\n}", `${MODELS}model Tag {\n  name: Text\n}\n`));
  });
});

describe("auth line", () => {
  const user = (fields: string) => `auth User by email\nmodel User {\n${fields}\n}\n`;
  it.each([
    [user("  email: Email unique"), "Password"],
    [user("  email: Email\n  password: Password"), "unique"],
    [user("  email: Text unique\n  password: Password"), "Email"],
    [user("  email: Email unique optional\n  password: Password"), "unique"],
    [user("  login: Email unique\n  password: Password"), "email: Email unique"],
    [user("  email: Email unique\n  password: Password optional"), "optional"],
    [user("  email: Email unique\n  password: Password\n  pin: Password"), "one Password"],
    [user("  email: Email unique\n  password: Password\n  invitedBy: User"), "optional"],
    [`${user("  email: Email unique\n  password: Password")}auth User by email\n`, "at most one"],
  ])("rejects an invalid auth model (%#)", (src, fix) => {
    const d = firstError(src);
    expect(d.code).toBe("RZ0317");
    expect(`${d.message} ${d.fix}`).toContain(fix);
  });

  it("rejects an unknown auth model", () => {
    expect(firstError("auth Account by email\nmodel User {\n  email: Email unique\n  password: Password\n}").code).toBe("RZ0316");
  });
});

describe("links and private fields", () => {
  it("resolves links to other models, in any order", () => {
    const { models } = compileOk("model Comment {\n  post: Post\n}\nmodel Post {\n  parent: Post optional\n}");
    expect(models[0]?.fields[0]).toMatchObject({ name: "post", type: "ID", link: "Post", column: "post_id" });
    expect(models[1]?.fields[0]).toMatchObject({ link: "Post", optional: true });
  });

  it("suggests model names for unknown types", () => {
    const d = firstError("model Comment {\n  post: Posts\n}\nmodel Post {\n  title: Text\n}");
    expect(d.code).toBe("RZ0301");
    expect(d.fix).toContain('"Post"');
  });

  it("does not allow min or max on links, or private on passwords", () => {
    expect(firstError("model A {\n  b: B max 3\n}\nmodel B {\n  x: Text\n}").code).toBe("RZ0302");
    expect(firstError("model A {\n  password: Password private\n}").code).toBe("RZ0302");
  });

  it("detects a link column clashing with an ID field", () => {
    expect(firstError("model A {\n  b: B\n  bId: ID\n}\nmodel B {\n  x: Text\n}").code).toBe("RZ0312");
  });
});

describe("roles", () => {
  const ROLES = MODELS.replace("auth User by email", "auth User by email roles admin, editor");

  it("parses roles and role requirements", () => {
    const { auth, apis } = compileOk(withApi(`api GET /drafts -> list Post.public {
  requires login
  requires role admin, editor
  return db.Post.list(published = false)
}
api DELETE /posts/:id {
  requires login
  requires owner author or role admin
  return db.Post.delete(id)
}`, ROLES));
    expect(auth?.roles).toEqual(["admin", "editor"]);
    expect(apis[0]).toMatchObject({ roles: ["admin", "editor"], ownerBypassRoles: [] });
    expect(apis[1]).toMatchObject({ roles: [], ownerBypassRoles: ["admin"], owner: { name: "author" } });
  });

  it("adds a hidden role column that only accepts declared roles", () => {
    const { output } = compileOk(ROLES);
    expect(output.sql).toContain(`"role" TEXT CONSTRAINT "users_role_check" CHECK ("role" IN ('admin', 'editor'))`);
    expect(output.typescript).toContain('readonly role: "admin" | "editor" | null;');
    expect(output.typescript.split("export interface UserPublic")[1]?.split("}")[0]).not.toContain("role");
    expect(output.typescript.split("export interface UserInput")[1]?.split("}")[0]).not.toContain("role");
  });

  it("lets admins delete owned records without requires owner", () => {
    compileOk(withApi("api DELETE /posts/:id {\n  requires login\n  requires role admin\n  return db.Post.delete(id)\n}", ROLES));
  });

  it.each([
    ["auth User by email roles editor", "must include admin"],
    ["auth User by email roles admin, admin", "twice"],
    ["auth User by email roles admin, Editor", "camelCase"],
  ])("rejects invalid role declarations: %s", (line, hint) => {
    const d = firstError(MODELS.replace("auth User by email", line));
    expect(d.code).toBe("RZ0317");
    expect(`${d.message} ${d.fix}`).toContain(hint);
  });

  it("rejects a role list with a missing name", () => {
    expect(firstError(MODELS.replace("auth User by email", "auth User by email roles admin,")).code).toBe("RZ0219");
  });

  it("rejects a field named role when roles are declared", () => {
    const src = ROLES.replace("  name: Text\n}", "  name: Text\n  role: Text\n}");
    expect(firstError(src).code).toBe("RZ0317");
  });

  it.each([
    ["api GET /drafts -> list Post.public {\n  requires login\n  requires role editr\n  return db.Post.list()\n}", ROLES, '"editor"'],
    ["api GET /drafts -> list Post.public {\n  requires login\n  requires role admin\n  return db.Post.list()\n}", MODELS, "roles admin"],
  ])("rejects unknown or undeclared roles (%#)", (api, models, fix) => {
    const d = firstError(withApi(api, models));
    expect(d.code).toBe("RZ0332");
    expect(d.fix).toContain(fix);
  });

  it("requires login with requires role, and rejects public", () => {
    expect(firstError(withApi("api GET /drafts -> list Post.public {\n  requires role admin\n  return db.Post.list()\n}", ROLES)).fix).toContain("requires login");
    expect(firstError(withApi("api GET /drafts -> list Post.public {\n  public\n  requires role admin\n  return db.Post.list()\n}", ROLES)).code).toBe("RZ0318");
  });
});
