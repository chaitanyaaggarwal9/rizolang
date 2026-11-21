import type { Span } from "./diagnostics.js";

/** Syntax tree produced by the parser. Names and types are not validated yet. */

export interface Program {
  readonly models: readonly ModelDecl[];
}

export interface ModelDecl {
  readonly name: string;
  readonly nameSpan: Span;
  readonly fields: readonly FieldDecl[];
}

export interface FieldDecl {
  readonly name: string;
  readonly nameSpan: Span;
  readonly typeName: string;
  readonly typeSpan: Span;
  readonly modifiers: readonly Modifier[];
}

export type Modifier =
  | { readonly kind: "unique" | "optional"; readonly span: Span }
  | { readonly kind: "min" | "max"; readonly value: number; readonly span: Span; readonly valueSpan: Span };

export type ModifierKind = Modifier["kind"];

export const MODIFIER_NAMES: readonly ModifierKind[] = ["unique", "optional", "min", "max"];
