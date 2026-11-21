import type { Span } from "./diagnostics.js";

/** Syntax tree produced by the parser. Names and types are not validated yet. */

export interface Program {
  readonly models: readonly ModelDecl[];
  readonly auths: readonly AuthDecl[];
  readonly apis: readonly ApiDecl[];
  readonly pages: readonly PageDecl[];
}

export interface ModelDecl {
  readonly name: string;
  readonly nameSpan: Span;
  readonly fields: readonly FieldDecl[];
}

export interface FieldDecl {
  readonly name: string;
  readonly nameSpan: Span;
  /** A field type (Text, Email, ...) or the name of another model (a link). */
  readonly typeName: string;
  readonly typeSpan: Span;
  readonly modifiers: readonly Modifier[];
}

export type Modifier =
  | { readonly kind: "unique" | "optional" | "private"; readonly span: Span }
  | { readonly kind: "min" | "max"; readonly value: number; readonly span: Span; readonly valueSpan: Span };

export type ModifierKind = Modifier["kind"];

export const MODIFIER_NAMES: readonly ModifierKind[] = ["unique", "optional", "private", "min", "max"];

/** A role name as written, e.g. `admin`. */
export interface RoleRef {
  readonly name: string;
  readonly span: Span;
}

/** `auth User by email` or `auth User by email roles admin, editor` */
export interface AuthDecl {
  readonly span: Span;
  readonly model: string;
  readonly modelSpan: Span;
  readonly field: string;
  readonly fieldSpan: Span;
  readonly roles: readonly RoleRef[];
}

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"] as const;
export type HttpMethod = (typeof HTTP_METHODS)[number];

/** `api GET /posts/:id -> Post.public { ... }` */
export interface ApiDecl {
  readonly span: Span;
  readonly method: HttpMethod;
  readonly methodSpan: Span;
  readonly path: string;
  readonly pathSpan: Span;
  /** Undefined when the endpoint returns nothing (`api DELETE /posts/:id { ... }`). */
  readonly returns: ReturnType | undefined;
  readonly statements: readonly Statement[];
  /** Span of the closing brace, for errors about missing statements. */
  readonly endSpan: Span;
}

export interface ReturnType {
  readonly list: boolean;
  readonly model: string;
  readonly modelSpan: Span;
  /** The word after the dot; must be "public". */
  readonly view: string;
  readonly viewSpan: Span;
  readonly span: Span;
}

export type Statement =
  | { readonly kind: "public"; readonly span: Span }
  | { readonly kind: "requiresLogin"; readonly span: Span }
  /** `requires owner author` or `requires owner author or role admin` */
  | { readonly kind: "requiresOwner"; readonly span: Span; readonly field: string; readonly fieldSpan: Span; readonly orRoles: readonly RoleRef[] }
  /** `requires role admin` or `requires role admin, editor` (any of) */
  | { readonly kind: "requiresRole"; readonly span: Span; readonly roles: readonly RoleRef[] }
  | { readonly kind: "return"; readonly span: Span; readonly query: Query };

export const QUERY_ACTIONS = ["find", "list", "create", "update", "delete"] as const;
export type QueryAction = (typeof QUERY_ACTIONS)[number];

/** `db.Post.list(author = me, order title desc, limit 20)` */
export interface Query {
  readonly span: Span;
  readonly model: string;
  readonly modelSpan: Span;
  readonly action: string;
  readonly actionSpan: Span;
  readonly args: readonly QueryArg[];
}

export type QueryArg =
  /** A bare name: a path parameter (`id`) or `body`. */
  | { readonly kind: "name"; readonly name: string; readonly span: Span }
  /** `field = value` */
  | { readonly kind: "assign"; readonly field: string; readonly fieldSpan: Span; readonly value: Value; readonly span: Span }
  /** `order field` or `order field desc` */
  | { readonly kind: "order"; readonly field: string; readonly fieldSpan: Span; readonly descending: boolean; readonly span: Span }
  /** `limit 20` */
  | { readonly kind: "limit"; readonly value: number; readonly valueSpan: Span; readonly span: Span };

export type Value =
  | { readonly kind: "name"; readonly name: string; readonly span: Span }
  | { readonly kind: "int"; readonly value: number; readonly span: Span }
  | { readonly kind: "bool"; readonly value: boolean; readonly span: Span };

/** Quoted text as written in a page, e.g. `"Latest posts"`. */
export interface TextRef {
  readonly text: string;
  readonly span: Span;
}

/** `page /posts { ... }` */
export interface PageDecl {
  readonly span: Span;
  readonly path: string;
  readonly pathSpan: Span;
  readonly statements: readonly PageStatement[];
  readonly endSpan: Span;
}

export type PageStatement =
  | { readonly kind: "public"; readonly span: Span }
  | { readonly kind: "requiresLogin"; readonly span: Span }
  | { readonly kind: "requiresRole"; readonly span: Span; readonly roles: readonly RoleRef[] }
  /** `title "Latest posts"` */
  | { readonly kind: "title"; readonly span: Span; readonly text: TextRef }
  /** `text "Welcome!"` */
  | { readonly kind: "text"; readonly span: Span; readonly text: TextRef }
  /** `link "Write a post" /posts/new` */
  | { readonly kind: "link"; readonly span: Span; readonly label: TextRef; readonly path: string; readonly pathSpan: Span }
  /** `show GET /api/posts` */
  | { readonly kind: "show"; readonly span: Span; readonly method: string; readonly methodSpan: Span; readonly path: string; readonly pathSpan: Span }
  /** `form POST /api/posts` */
  | { readonly kind: "form"; readonly span: Span; readonly method: string; readonly methodSpan: Span; readonly path: string; readonly pathSpan: Span }
  /** `button "Delete" DELETE /api/posts/:id` */
  | { readonly kind: "button"; readonly span: Span; readonly label: TextRef; readonly method: string; readonly methodSpan: Span; readonly path: string; readonly pathSpan: Span }
  /** `then go /posts/:id` */
  | { readonly kind: "thenGo"; readonly span: Span; readonly path: string; readonly pathSpan: Span };
