import type { PageDecl, RoleRef } from "./ast.js";
import {
  type ParamType,
  type PathParam,
  type PathSegment,
  type ResolvedApi,
  type ResolvedAuth,
  parseRoutePath,
  pathShape,
} from "./check-api.js";
import { type ResolvedField, type ResolvedModel, isHidden } from "./checker.js";
import { type Span, didYouMean } from "./diagnostics.js";
import type { FieldTypeName } from "./types.js";

/**
 * Checks `page` blocks. Pages never contain markup or code: they say what to
 * show (`show GET /api/posts`), and the compiler generates the HTML. The rules
 * here keep pages consistent with the endpoints they use:
 *   - every page says `public` or `requires login`;
 *   - a page is never more open than the data it shows;
 *   - pages and endpoints never share a path;
 *   - every link points to a page that exists.
 */

type Err = (code: string, span: Span, message: string, fix: string) => void;

/** How one field of a shown record is displayed. */
export interface FieldView {
  readonly key: string;
  readonly label: string;
  readonly type: FieldTypeName;
  /** For links: the linked model's name. */
  readonly link: string | undefined;
}

export type PageItem =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "link"; readonly label: string; readonly path: string }
  | {
      readonly kind: "show";
      readonly api: ResolvedApi;
      readonly mode: "list" | "one";
      readonly fields: readonly FieldView[];
      /** For lists: the page that shows one record, e.g. "/posts/:id", with its parameter name. */
      readonly detail: { readonly path: string; readonly param: string } | undefined;
    }
  /** A form that creates or updates a record; edit forms are prefilled from a GET on the same path. */
  | { readonly kind: "form"; readonly api: ResolvedApi; readonly prefill: ResolvedApi | undefined }
  /** A button that deletes a record. */
  | { readonly kind: "button"; readonly api: ResolvedApi; readonly label: string };

export interface ResolvedPage {
  readonly path: string;
  readonly segments: readonly PathSegment[];
  readonly params: readonly PathParam[];
  readonly access: "public" | "login";
  readonly roles: readonly string[];
  readonly title: string;
  readonly items: readonly PageItem[];
  /** Where to go after the page's form or button succeeds. */
  readonly then: string | undefined;
}

/** Page paths the built-in login and signup pages will use (part 2). */
const RESERVED_PAGES: readonly string[] = ["/login", "/signup", "/account", "/verify-email", "/reset-password", "/privacy"];

/** "publishedAt" → "Published at". */
export function labelFor(name: string): string {
  const words = name.replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/([A-Z])([A-Z][a-z])/g, "$1 $2").toLowerCase();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

/** A title from the path: "/" → "Home", "/blog-posts/:id" → "Blog posts". */
function titleFor(segments: readonly PathSegment[]): string {
  const last = [...segments].reverse().find((s) => s.kind === "static");
  return last === undefined || last.kind !== "static" ? "Home" : labelFor(last.value.replace(/-/g, " "));
}

export function checkPages(
  pages: readonly PageDecl[],
  auth: ResolvedAuth | undefined,
  apis: readonly ResolvedApi[],
  authDeclared: boolean,
  err: Err,
): ResolvedPage[] {
  const apiShapes = new Set(apis.map((a) => pathShape(a.segments)));
  const seen = new Map<string, PageDecl>();
  const parsed: { decl: PageDecl; segments: PathSegment[] }[] = [];

  // Paths first, so links can refer to any page in the file.
  for (const decl of pages) {
    const segments = parseRoutePath(decl.path, decl.pathSpan, err);
    if (segments === undefined) continue;
    const shape = pathShape(segments);
    const dup = seen.get(shape);
    if (dup !== undefined) {
      err("RZ0334", decl.pathSpan, `Page "${decl.path}" is already defined on line ${dup.span.line}.`, "Remove one of the two pages, or give them different paths.");
      continue;
    }
    if (apiShapes.has(shape)) {
      err("RZ0334", decl.pathSpan, `Page "${decl.path}" has the same path as an endpoint.`,
        `Pages and endpoints can't share a path. Put the endpoint under /api, for example \`api GET /api${decl.path === "/" ? "" : decl.path}\`.`);
      continue;
    }
    if (authDeclared && RESERVED_PAGES.includes(shape)) {
      err("RZ0334", decl.pathSpan, `Page "${decl.path}" is reserved for the built-in ${shape.slice(1)} page.`, "Choose a different path.");
      continue;
    }
    seen.set(shape, decl);
    parsed.push({ decl, segments });
  }

  const resolved: ResolvedPage[] = [];
  for (const { decl, segments } of parsed) {
    const r = checkPage(decl, segments);
    if (r !== undefined) resolved.push(r);
  }
  // Lists link each record to the page that shows it, when there is one.
  return resolved.map((page) => ({ ...page, items: page.items.map((item) => withDetail(item, resolved)) }));

  function checkPage(decl: PageDecl, segments: PathSegment[]): ResolvedPage | undefined {
    const name = `page ${decl.path}`;
    let ok = true;
    const st = decl.statements;
    const publics = st.filter((s) => s.kind === "public");
    const logins = st.filter((s) => s.kind === "requiresLogin");
    const roleStmts = st.flatMap((s) => (s.kind === "requiresRole" ? [s] : []));
    const titles = st.flatMap((s) => (s.kind === "title" ? [s] : []));
    const shows = st.flatMap((s) => (s.kind === "show" ? [s] : []));

    for (const group of [publics, logins, roleStmts, titles, shows]) {
      for (const extra of group.slice(1)) {
        ok = false;
        err(extra.kind === "title" || extra.kind === "show" ? "RZ0337" : "RZ0333", extra.span,
          `This line appears more than once in ${name}.`,
          extra.kind === "show" ? "A page shows one endpoint. Make a second page for other data." : "Remove the duplicate line.");
      }
    }
    const firstPublic = publics[0];
    if (firstPublic !== undefined && (logins.length > 0 || roleStmts.length > 0)) {
      ok = false;
      err("RZ0333", firstPublic.span, `${name} is marked public but also requires login.`, "Remove `public`, or remove the `requires` lines.");
    } else if (publics.length === 0 && logins.length === 0) {
      ok = false;
      err("RZ0333", decl.pathSpan, `${name} does not say who may see it.`,
        roleStmts.length > 0 ? "Add `requires login` above `requires role`." : "Add `public` if anyone may see it, or `requires login`.");
    }
    if ((logins.length > 0 || roleStmts.length > 0) && !authDeclared) {
      ok = false;
      err("RZ0319", (logins[0] ?? roleStmts[0] ?? decl).span, `${name} requires login, but there is no auth line.`,
        "Add `auth User by email` at the top level.");
    }
    const access: "public" | "login" = publics.length > 0 ? "public" : "login";
    const roles = roleNames(roleStmts[0]?.roles ?? []);

    const pageParams = new Set(segments.flatMap((s) => (s.kind === "param" ? [s.name] : [])));
    const paramTypes = new Map<string, ParamType>();
    const items: PageItem[] = [];

    /** Find and check the endpoint a show, form or button uses. */
    const endpoint = (use: "show" | "form" | "button", method: string, methodSpan: Span, path: string, pathSpan: Span, span: Span): ResolvedApi | undefined => {
      const allowed: readonly string[] = use === "show" ? ["GET"] : use === "form" ? ["POST", "PUT", "PATCH"] : ["DELETE"];
      if (!allowed.includes(method)) {
        err("RZ0335", methodSpan, `A ${use} can't use ${method}.`,
          use === "show" ? `Write \`show GET ${path}\`. Changing data needs a form or button.`
          : use === "form" ? `Forms create or change records: use POST, PUT or PATCH, for example \`form POST ${path}\`.`
          : `Buttons delete records: use DELETE, for example \`button "Delete" DELETE ${path}\`.`);
        return undefined;
      }
      const api = apis.find((a) => a.method === method && a.path === path);
      if (api === undefined) {
        const same = apis.filter((a) => allowed.includes(a.method)).map((a) => `${a.method} ${a.path}`);
        const guess = didYouMean(`${method} ${path}`, same);
        err("RZ0335", pathSpan, `There is no endpoint "${method} ${path}" to ${use === "show" ? "show" : "use"}.`,
          guess !== undefined ? `Did you mean "${guess}"?` : same.length > 0 ? `Use one of: ${same.join(", ")}.` : `Declare it first: \`api ${method} ${path} ... { ... }\`.`);
        return undefined;
      }
      let good = true;
      for (const p of api.params) {
        if (!pageParams.has(p.name)) {
          good = false;
          err("RZ0335", pathSpan, `"${method} ${api.path}" needs :${p.name}, but ${name} has no :${p.name}.`,
            `Give the page the same parameter, for example \`page ${decl.path === "/" ? "" : decl.path}/:${p.name}\`.`);
        } else {
          paramTypes.set(p.name, p.type);
        }
      }
      if (api.access === "login" && access === "public") {
        good = false;
        err("RZ0335", span, `${name} is public, but "${method} ${api.path}" requires login, so visitors would only see an error.`,
          "Replace `public` with `requires login`, or make the endpoint public.");
      }
      if (api.roles.length > 0 && (roles.length === 0 || roles.some((r) => !api.roles.includes(r)))) {
        good = false;
        err("RZ0335", span, `"${method} ${api.path}" requires role ${api.roles.join(" or ")}, but ${name} lets in users without it.`,
          `Add \`requires role ${api.roles.join(", ")}\` to the page.`);
      }
      return good ? api : undefined;
    };

    for (const s of st) {
      if (s.kind === "text") items.push({ kind: "text", text: s.text.text });
      if (s.kind === "link") {
        const target = parseRoutePath(s.path, s.pathSpan, err);
        if (target === undefined) { ok = false; continue; }
        const exists = parsed.some((p) => pathShape(p.segments) === pathShape(target));
        const builtIn = authDeclared && RESERVED_PAGES.includes(pathShape(target));
        if (!exists && !builtIn) {
          ok = false;
          const guess = didYouMean(s.path, parsed.map((p) => p.decl.path));
          err("RZ0336", s.pathSpan, `There is no page "${s.path}" to link to.`,
            guess !== undefined ? `Did you mean "${guess}"?` : `Add \`page ${s.path} { ... }\`, or link to an existing page.`);
          continue;
        }
        const missing = target.flatMap((t) => (t.kind === "param" && !pageParams.has(t.name) ? [t.name] : []));
        if (missing.length > 0) {
          ok = false;
          err("RZ0336", s.pathSpan, `The link needs :${missing.join(", :")}, which ${name} does not have.`,
            "Link to pages whose parameters this page also has. Lists link to each record's page automatically.");
          continue;
        }
        items.push({ kind: "link", label: s.label.text, path: s.path });
      }
      if (s.kind === "show" || s.kind === "form" || s.kind === "button") {
        const api = endpoint(s.kind, s.method, s.methodSpan, s.path, s.pathSpan, s.span);
        if (api === undefined) { ok = false; continue; }
        if (s.kind === "show") {
          items.push({ kind: "show", api, mode: api.returns === "list" ? "list" : "one", fields: fieldsOf(api.query.model), detail: undefined });
        } else if (s.kind === "form") {
          // Edit forms start from the current record when a GET endpoint on the same path exists.
          const prefill = api.query.action === "update"
            ? apis.find((a) => a.method === "GET" && a.path === api.path && a.returns === "one")
            : undefined;
          items.push({ kind: "form", api, prefill });
        } else {
          items.push({ kind: "button", api, label: s.label.text });
        }
      }
    }

    // Forms and buttons: at most one per page, followed by `then go`.
    const actions = st.flatMap((s) => (s.kind === "form" || s.kind === "button" ? [s] : []));
    const thens = st.flatMap((s) => (s.kind === "thenGo" ? [s] : []));
    for (const extra of actions.slice(1)) {
      ok = false;
      err("RZ0337", extra.span, `${name} has more than one form or button.`, "A page has at most one form or button. Make a separate page for the other one.");
    }
    for (const extra of thens.slice(1)) {
      ok = false;
      err("RZ0337", extra.span, `\`then go\` appears more than once in ${name}.`, "Remove the duplicate line.");
    }
    const action = actions[0];
    const thenGo = thens[0];
    if (action !== undefined && thenGo === undefined) {
      ok = false;
      err("RZ0338", action.span, `${name} does not say where to go after the ${action.kind} succeeds.`,
        `Add a line such as \`then go ${action.kind === "button" ? "/" : "/posts/:id"}\` below the ${action.kind}.`);
    }
    if (thenGo !== undefined && action === undefined) {
      ok = false;
      err("RZ0338", thenGo.span, `\`then go\` in ${name} has no form or button to follow.`, "Remove it, or add a form or button.");
    }
    if (thenGo !== undefined && action !== undefined) {
      const target = parseRoutePath(thenGo.path, thenGo.pathSpan, err);
      if (target === undefined) {
        ok = false;
      } else if (!parsed.some((p) => pathShape(p.segments) === pathShape(target))) {
        ok = false;
        const guess = didYouMean(thenGo.path, parsed.map((p) => p.decl.path));
        err("RZ0338", thenGo.pathSpan, `There is no page "${thenGo.path}" to go to.`,
          guess !== undefined ? `Did you mean "${guess}"?` : `Add \`page ${thenGo.path} { ... }\`, or choose an existing page.`);
      } else {
        // Forms return the saved record, so :id can come from it; everything else comes from this page.
        const fromResult = action.kind === "form" ? ["id"] : [];
        const missing = target.flatMap((t) => (t.kind === "param" && !pageParams.has(t.name) && !fromResult.includes(t.name) ? [t.name] : []));
        if (missing.length > 0) {
          ok = false;
          err("RZ0338", thenGo.pathSpan, `\`then go ${thenGo.path}\` needs :${missing.join(", :")}, which ${name} does not have.`,
            action.kind === "form"
              ? "Use this page's parameters, or :id for the record the form saved."
              : "Use this page's parameters, or go to a page without parameters, such as `/`.");
        }
      }
    }

    for (const p of pageParams) {
      if (!paramTypes.has(p)) {
        ok = false;
        err("RZ0323", decl.pathSpan, `Path parameter ":${p}" is never used in ${name}.`,
          `Use it in the page's show line (for example \`show GET /api/posts/:${p}\`), or remove it from the path.`);
      }
    }

    if (!ok) return undefined;
    return {
      path: decl.path,
      segments,
      params: [...pageParams].map((p) => ({ name: p, type: paramTypes.get(p) ?? "Text" })),
      access,
      roles,
      title: titles[0]?.text.text ?? titleFor(segments),
      items,
      then: thens[0]?.path,
    };
  }

  function roleNames(refs: readonly RoleRef[]): string[] {
    const out: string[] = [];
    for (const r of refs) {
      if (auth === undefined) continue;
      if (!auth.roles.includes(r.name)) {
        const guess = didYouMean(r.name, auth.roles);
        err("RZ0332", r.span, auth.roles.length === 0 ? `Role "${r.name}" is used, but the auth line declares no roles.` : `Unknown role "${r.name}".`,
          auth.roles.length === 0 ? `Declare roles on the auth line: \`... roles admin\`.` : guess !== undefined ? `Did you mean "${guess}"?` : `Use one of: ${auth.roles.join(", ")}.`);
      } else if (!out.includes(r.name)) {
        out.push(r.name);
      }
    }
    return out;
  }

  function fieldsOf(model: ResolvedModel): FieldView[] {
    const visible = model.fields.filter((f: ResolvedField) => !isHidden(f));
    return [
      { key: "id", label: "ID", type: "ID", link: undefined },
      ...visible.map((f) => ({ key: f.name, label: labelFor(f.name), type: f.type, link: f.link })),
    ];
  }

  function withDetail(item: PageItem, all: readonly ResolvedPage[]): PageItem {
    if (item.kind !== "show" || item.mode !== "list") return item;
    const model = item.api.query.model;
    for (const page of all) {
      for (const other of page.items) {
        if (other.kind !== "show" || other.mode !== "one" || other.api.query.model !== model) continue;
        if (other.api.query.action !== "find" || page.params.length !== 1) continue;
        const idParam = other.api.query.idParam;
        if (page.params[0]?.name === idParam) return { ...item, detail: { path: page.path, param: idParam } };
      }
    }
    return item;
  }
}
