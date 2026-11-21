import { describe, expect, it } from "vitest";
import { lex } from "../src/lexer.js";
import { buildApp } from "../src/emit/routes.js";
import { compileOk, firstError } from "./helpers.js";

const BASE = `auth User by email roles admin

model User {
  email: Email unique private
  password: Password
  name: Text
}

model Post {
  author: User
  title: Text
}

api GET /api/posts -> list Post.public {
  public
  return db.Post.list(order title)
}

api GET /api/posts/:id -> Post.public {
  public
  return db.Post.find(id)
}

api GET /api/my/posts -> list Post.public {
  requires login
  return db.Post.list(author = me)
}

api GET /api/admin/users -> list User.public {
  requires login
  requires role admin
  return db.User.list()
}
`;
/** First line number after BASE. */
const L = BASE.split("\n").length;
const withPages = (pages: string) => `${BASE}${pages}\n`;

describe("quoted text", () => {
  const lexed = (src: string) => lex(src, "t.rz");

  it("decodes escapes and keeps everything else as written", () => {
    const r = lexed('title "Say \\"hi\\" to <b>me</b> \\\\ ok"');
    expect(r.ok && r.tokens[1]).toMatchObject({ kind: "string", text: 'Say "hi" to <b>me</b> \\ ok', span: { col: 7 } });
  });

  it.each([
    ['title "never closed', "not closed"],
    ['title "line\nbreak"', "not closed"],
    ['title "bad \\n escape"', "is not allowed"],
    ['title "tab\there"', "control character"],
    [`title "${"x".repeat(201)}"`, "at most 200"],
  ])("rejects %j", (src, message) => {
    const r = lexed(src);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.diagnostic.code).toBe("RZ0103");
      expect(r.diagnostic.message).toContain(message);
    }
  });

  it("is only allowed in pages", () => {
    expect(firstError('model A {\n  x: Text "hi"\n}').fix).toContain("page blocks");
    expect(firstError('"hello"').fix).toContain("page block");
  });
});

describe("page blocks", () => {
  it("parses and resolves a page with text, links and a list", () => {
    const { pages } = compileOk(withPages(`page / {
  public
  title "Latest posts"
  text "Welcome!"
  link "My posts" /mine
  show GET /api/posts
}
page /mine {
  requires login
  show GET /api/my/posts
}
page /posts/:id {
  public
  show GET /api/posts/:id
}`));
    expect(pages[0]).toMatchObject({ path: "/", access: "public", title: "Latest posts", params: [] });
    expect(pages[0]?.items.map((i) => i.kind)).toEqual(["text", "link", "show"]);
    const show = pages[0]?.items[2];
    expect(show?.kind === "show" && show.mode).toBe("list");
    // The list links each post to the page that shows one post.
    expect(show?.kind === "show" && show.detail).toEqual({ path: "/posts/:id", param: "id" });
    expect(pages[1]).toMatchObject({ title: "Mine", access: "login" });
    expect(pages[2]).toMatchObject({ params: [{ name: "id", type: "ID" }], title: "Posts" });
  });

  it("shows only public fields, with readable labels", () => {
    const { pages, apis, auth } = compileOk(withPages("page / {\n  public\n  show GET /api/posts\n}"));
    const show = buildApp(apis, auth, pages).pages[0]?.items[0];
    expect(show).toMatchObject({ kind: "show", endpoint: "/api/posts", mode: "list", model: "Post" });
    expect(show?.kind === "show" && show.fields.map((f) => f.key)).toEqual(["id", "author", "title"]);
    const users = compileOk(withPages("page /admin {\n  requires login\n  requires role admin\n  show GET /api/admin/users\n}"));
    const userShow = buildApp(users.apis, users.auth, users.pages).pages[0]?.items[0];
    expect(userShow?.kind === "show" && userShow.fields.map((f) => f.key)).toEqual(["id", "name"]);
  });

  it.each([
    ["page / {\n  title \"x\"\n}", "RZ0333", "public"],
    ["page / {\n  public\n  requires login\n}", "RZ0333", "public"],
    ["page / {\n  requires role admin\n}", "RZ0333", "requires login"],
    ["page / {\n  public\n  title \"a\"\n  title \"b\"\n}", "RZ0337", "duplicate"],
    ["page / {\n  public\n  show GET /api/posts\n  show GET /api/posts\n}", "RZ0337", "second page"],
    ["page /api/posts {\n  public\n}", "RZ0334", "/api"],
    ["page / {\n  public\n}\npage / {\n  public\n}", "RZ0334", "Remove one"],
    ["page /login {\n  public\n}", "RZ0334", "different path"],
    ["page /verify-email {\n  public\n}", "RZ0334", "reserved for the built-in verify-email page"],
    ["page /reset-password {\n  public\n}", "RZ0334", "reserved for the built-in reset-password page"],
    ["page /_rizo/x {\n  public\n}", "RZ0322", "not allowed"],
    ["page / {\n  public\n  show GET /api/post\n}", "RZ0335", "/api/posts"],
    ["page / {\n  public\n  show POST /api/posts\n}", "RZ0335", "GET"],
    ["page / {\n  public\n  show GET /api/my/posts\n}", "RZ0335", "requires login"],
    ["page / {\n  requires login\n  show GET /api/admin/users\n}", "RZ0335", "requires role admin"],
    ["page / {\n  public\n  show GET /api/posts/:id\n}", "RZ0335", "/:id"],
    ["page /posts/:id {\n  public\n}", "RZ0323", "never used"],
    ["page / {\n  public\n  link \"x\" /nowhere\n}", "RZ0336", "no page"],
    ["page / {\n  public\n  bogus\n}", "RZ0220", "A page contains"],
    ["page / {\n  public\n  titel \"x\"\n}", "RZ0220", '"title"'],
    ["page / {\n  public\n  title Posts\n}", "RZ0221", 'title "'],
  ])("rejects %j with %s", (src, code, fix) => {
    const d = firstError(withPages(src));
    expect(d.code).toBe(code);
    expect(`${d.message} ${d.fix}`).toContain(fix);
  });

  it("reports page errors at the right place", () => {
    expect(firstError(withPages("page / {\n  public\n  show GET /api/post\n}")).span).toMatchObject({ line: L + 2, col: 12 });
  });

  it("allows links to the built-in login page only when there is an auth line", () => {
    compileOk(withPages("page / {\n  public\n  link \"Log in\" /login\n}"));
    expect(firstError("page / {\n  public\n  link \"Log in\" /login\n}").code).toBe("RZ0336");
  });

  it("works without any endpoints or auth", () => {
    const r = compileOk('page / {\n  public\n  title "Hello"\n  text "A static page."\n}');
    expect(r.output.server?.routes).toContain("pages:");
  });
});

describe("forms and buttons", () => {
  const APP = `${BASE}
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

page /posts/:id {
  public
  show GET /api/posts/:id
}

page / {
  public
  show GET /api/posts
}
`;
  const withApp = (pages: string) => `${APP}${pages}\n`;
  const app = (pages: string) => {
    const r = compileOk(withApp(pages));
    return buildApp(r.apis, r.auth, r.pages);
  };

  it("builds a create form from the endpoint's body, going to the saved record", () => {
    const a = app("page /new {\n  requires login\n  form POST /api/posts\n  then go /posts/:id\n}");
    const form = a.pages.find((p) => p.pattern === "/new")?.items[0];
    expect(form).toMatchObject({ kind: "form", method: "POST", endpoint: "/api/posts", submit: "Save", prefill: null, then: "/posts/:id" });
    // The owner link is never a form field: the server sets it from the session.
    expect(form?.kind === "form" && form.fields.map((f) => [f.key, f.label, f.required])).toEqual([["title", "Title", true]]);
  });

  it("prefills edit forms from the GET endpoint on the same path", () => {
    const a = app("page /posts/:id/edit {\n  requires login\n  form PATCH /api/posts/:id\n  then go /posts/:id\n}");
    const form = a.pages.find((p) => p.pattern === "/posts/:id/edit")?.items[0];
    expect(form).toMatchObject({ kind: "form", method: "PATCH", prefill: "/api/posts/:id", submit: "Save changes" });
  });

  it("builds a delete button", () => {
    const a = app("page /posts/:id/delete {\n  requires login\n  button \"Delete post\" DELETE /api/posts/:id\n  then go /\n}");
    expect(a.pages.find((p) => p.pattern === "/posts/:id/delete")?.items[0]).toEqual({
      kind: "button", label: "Delete post", method: "DELETE", endpoint: "/api/posts/:id", then: "/",
    });
  });

  it("adds the built-in login and signup pages to apps with auth and pages", () => {
    const a = app("");
    const login = a.pages.find((p) => p.pattern === "/login");
    expect(login?.items[0]).toMatchObject({ kind: "form", endpoint: "/auth/login", then: null });
    const signup = a.pages.find((p) => p.pattern === "/signup")?.items[0];
    expect(signup?.kind === "form" && signup.fields.map((f) => f.key)).toEqual(["email", "password", "name"]);
    expect(buildApp([], undefined, []).pages).toEqual([]);
  });

  it.each([
    ["page /new {\n  requires login\n  form GET /api/posts\n  then go /\n}", "RZ0335", "POST, PUT or PATCH"],
    ["page /new {\n  requires login\n  form POST /api/post\n  then go /\n}", "RZ0335", "POST /api/posts"],
    ["page /new {\n  public\n  form POST /api/posts\n  then go /\n}", "RZ0335", "requires login"],
    ["page /x/:id {\n  requires login\n  button \"Go\" POST /api/posts\n  then go /\n}", "RZ0335", "DELETE"],
    ["page /new {\n  requires login\n  form POST /api/posts\n  form POST /api/posts\n  then go /\n}", "RZ0337", "at most one"],
    ["page /new {\n  requires login\n  form POST /api/posts\n}", "RZ0338", "then go"],
    ["page /new {\n  public\n  then go /\n}", "RZ0338", "no form or button"],
    ["page /new {\n  requires login\n  form POST /api/posts\n  then go /nowhere\n}", "RZ0338", "no page"],
    ["page /x/:id {\n  requires login\n  button \"Delete\" DELETE /api/posts/:id\n  then go /posts/:other\n}", "RZ0338", ":other"],
    ["page /new {\n  requires login\n  form POST /api/posts\n  then /\n}", "RZ0220", "then go"],
    ["page /new {\n  requires login\n  button DELETE /api/posts/:id\n}", "RZ0221", "button"],
  ])("rejects %j with %s", (src, code, fix) => {
    const d = firstError(withApp(src));
    expect(d.code).toBe(code);
    expect(`${d.message} ${d.fix}`).toContain(fix);
  });
});
