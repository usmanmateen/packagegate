import traverse, { type Binding, type NodePath } from "@babel/traverse";
import * as t from "@babel/types";
import type { SourceLocation } from "@packagegate/shared";
import type { AnalysisLimits } from "./limits.js";

/**
 * Capability resolution through scope bindings.
 *
 * This is the correctness centrepiece of the analyser. A text search for
 * `exec(` is wrong in both directions: it misses
 * `const { exec: run } = require("child_process")` and it fires on a local
 * helper that happens to be called `exec`. Both errors are common in real
 * packages, and both are trivially induced on purpose by anyone who has read
 * a grep-based scanner.
 *
 * So every resolution goes through Babel's scope analysis:
 *
 *  - A module import creates a **binding**, and we remember the binding
 *    *object*, not the name it happened to be given.
 *  - A use site is resolved by asking its own scope for the binding of that
 *    name. A shadowing declaration returns a different binding object, which
 *    is not in our map, so it resolves to nothing.
 *  - A bare identifier with **no** binding at all is a global, which is how
 *    `process`, `eval`, `fetch` and friends are recognised — and how a
 *    parameter named `process` is correctly *not* recognised.
 *
 * What this does not do is documented in `docs/STATIC_ANALYSIS.md`: no
 * cross-file resolution, no constant folding of module names built from
 * fragments, no analysis of values passed through function boundaries.
 */

/** How a module binding entered the file. Affects nothing but evidence text. */
export type ImportStyle =
  | "require"
  | "require-member"
  | "import"
  | "import-namespace"
  | "import-default"
  | "dynamic-import"
  | "alias";

/** A local name that is known to refer to (part of) an imported module. */
export interface ModuleBinding {
  /** Normalised module specifier: `node:child_process` → `child_process`. */
  readonly module: string;
  /**
   * The member of the module this name refers to, or `undefined` when the name
   * refers to the module namespace itself. Nested members are dotted:
   * `fs.promises.readFile` yields `promises.readFile`.
   */
  readonly member: string | undefined;
  readonly localName: string;
  readonly style: ImportStyle;
  /** Assignment hops between the original import and this name. */
  readonly aliasDepth: number;
  readonly declaration: SourceLocation;
}

/** The result of resolving an expression to something the rules care about. */
export interface ResolvedTarget {
  /** `"module"` for imported code, `"global"` for ambient identifiers. */
  readonly kind: "module" | "global";
  /** Module specifier, or the global's root name (`process`, `globalThis`). */
  readonly module: string;
  /** Member path, e.g. `exec`, `promises.readFile`, `env.NPM_TOKEN`. */
  readonly member: string | undefined;
  readonly aliasDepth: number;
  /**
   * True when any step of the resolution went through computed member access
   * whose key was not a literal (`cp[name]`). The target is then a guess about
   * the object, never about the member, and confidence must reflect that.
   */
  readonly computed: boolean;
  /** Where the underlying import was declared, when there was one. */
  readonly declaration?: SourceLocation;
}

/** Strip the `node:` scheme so `node:fs` and `fs` are one capability. */
export function normaliseModuleSpecifier(specifier: string): string {
  return specifier.startsWith("node:") ? specifier.slice(5) : specifier;
}

function locationOf(node: t.Node, filePath: string): SourceLocation {
  const loc = node.loc;
  if (loc === null || loc === undefined) {
    return { filePath, startLine: 1, endLine: 1 };
  }
  return {
    filePath,
    startLine: loc.start.line,
    endLine: loc.end.line,
    startColumn: loc.start.column,
    endColumn: loc.end.column,
  };
}

/** `a.b.c` → `"a.b.c"`, but only for non-computed literal paths. */
function joinMember(prefix: string | undefined, next: string): string {
  return prefix === undefined ? next : `${prefix}.${next}`;
}

/**
 * The static property name of a member expression, or `undefined` when the key
 * is computed from a non-literal. `obj["exec"]` is fully static despite being
 * computed — the concealment only matters when the key is not a literal.
 */
function staticPropertyName(
  node: t.MemberExpression | t.OptionalMemberExpression,
): { readonly name: string; readonly viaComputedLiteral: boolean } | undefined {
  if (!node.computed) {
    return t.isIdentifier(node.property)
      ? { name: node.property.name, viaComputedLiteral: false }
      : undefined;
  }
  if (t.isStringLiteral(node.property)) {
    return { name: node.property.value, viaComputedLiteral: true };
  }
  return undefined;
}

/**
 * Is this call `require("literal")`? Requires that `require` is *not* locally
 * bound, so a package defining its own `require` helper does not get its calls
 * misattributed to Node's module loader.
 */
function requireTarget(path: NodePath<t.Node>): string | undefined {
  const node = path.node;
  if (!t.isCallExpression(node)) return undefined;
  if (!t.isIdentifier(node.callee, { name: "require" })) return undefined;
  if (path.scope.getBinding("require") !== undefined) return undefined;
  const first = node.arguments[0];
  if (first === undefined || !t.isStringLiteral(first)) return undefined;
  return normaliseModuleSpecifier(first.value);
}

/** `import("literal")`, in either of Babel's two representations. */
function dynamicImportTarget(node: t.Node): string | undefined {
  if (t.isImportExpression(node)) {
    return t.isStringLiteral(node.source)
      ? normaliseModuleSpecifier(node.source.value)
      : undefined;
  }
  if (t.isCallExpression(node) && t.isImport(node.callee)) {
    const first = node.arguments[0];
    return first !== undefined && t.isStringLiteral(first)
      ? normaliseModuleSpecifier(first.value)
      : undefined;
  }
  return undefined;
}

/** Unwrap `await x` and `(x)` so `const fs = await import("fs")` resolves. */
function unwrap(node: t.Node): t.Node {
  let current = node;
  // Bounded: at most a handful of wrappers, and the loop always descends.
  for (let depth = 0; depth < 8; depth += 1) {
    if (t.isAwaitExpression(current)) {
      current = current.argument;
      continue;
    }
    if (t.isTSAsExpression(current) || t.isTSNonNullExpression(current)) {
      current = current.expression;
      continue;
    }
    if (t.isParenthesizedExpression(current)) {
      current = current.expression;
      continue;
    }
    return current;
  }
  return current;
}

export class CapabilityResolver {
  private readonly bindings = new Map<Binding, ModuleBinding>();

  private constructor(private readonly filePath: string) {}

  /**
   * Walk the file once and record every local name that refers to an imported
   * module. Alias chains (`const e = cp.exec`) are resolved by repeating the
   * pass until it stops learning anything new, bounded by `maxAliasDepth` so a
   * crafted file cannot make this loop long.
   */
  static collect(
    ast: t.File,
    filePath: string,
    limits: AnalysisLimits,
  ): CapabilityResolver {
    const resolver = new CapabilityResolver(filePath);

    // Pass 1: direct imports. These need no iteration.
    traverse(ast, {
      ImportDeclaration: (path) => {
        resolver.recordImportDeclaration(path);
      },
      VariableDeclarator: (path) => {
        resolver.recordVariableDeclarator(path, 0);
      },
    });

    // Passes 2..n: names derived from names already known. Each pass can only
    // add bindings, and the loop stops as soon as a pass adds none. Skipped
    // entirely when the file imports nothing, which is the common case.
    for (
      let hop = 1;
      resolver.bindings.size > 0 && hop <= limits.maxAliasDepth;
      hop += 1
    ) {
      const before = resolver.bindings.size;
      traverse(ast, {
        VariableDeclarator: (path) => {
          resolver.recordVariableDeclarator(path, hop);
        },
      });
      if (resolver.bindings.size === before) break;
    }

    return resolver;
  }

  /** Every module binding found, for import inventory and evidence. */
  moduleBindings(): readonly ModuleBinding[] {
    return [...this.bindings.values()];
  }

  /** True when this file imports the given module under any name. */
  importsModule(module: string): boolean {
    for (const binding of this.bindings.values()) {
      if (binding.module === module) return true;
    }
    return false;
  }

  private remember(
    path: NodePath<t.Node>,
    localName: string,
    value: Omit<ModuleBinding, "localName" | "declaration">,
  ): void {
    const binding = path.scope.getBinding(localName);
    if (binding === undefined) return;
    if (this.bindings.has(binding)) return;
    this.bindings.set(binding, {
      ...value,
      localName,
      declaration: locationOf(binding.identifier, this.filePath),
    });
  }

  private recordImportDeclaration(path: NodePath<t.ImportDeclaration>): void {
    const module = normaliseModuleSpecifier(path.node.source.value);
    for (const specifier of path.node.specifiers) {
      if (t.isImportSpecifier(specifier)) {
        // `import { exec as run }` — `imported` is `exec`, `local` is `run`.
        const imported = specifier.imported;
        const memberName = t.isIdentifier(imported) ? imported.name : imported.value;
        this.remember(path, specifier.local.name, {
          module,
          member: memberName,
          style: "import",
          aliasDepth: 0,
        });
      } else if (t.isImportNamespaceSpecifier(specifier)) {
        this.remember(path, specifier.local.name, {
          module,
          member: undefined,
          style: "import-namespace",
          aliasDepth: 0,
        });
      } else if (t.isImportDefaultSpecifier(specifier)) {
        // For CommonJS builtins reached through ESM interop, the default export
        // *is* the namespace object — `import fs from "fs"; fs.readFileSync(…)`
        // is the overwhelmingly common shape and must resolve.
        this.remember(path, specifier.local.name, {
          module,
          member: undefined,
          style: "import-default",
          aliasDepth: 0,
        });
      }
    }
  }

  private recordVariableDeclarator(
    path: NodePath<t.VariableDeclarator>,
    hop: number,
  ): void {
    const init = path.node.init;
    if (init === null || init === undefined) return;
    const initPath = path.get("init") as unknown as NodePath<t.Node>;

    const source = this.describeInitialiser(initPath, hop);
    if (source === undefined) return;

    const id = path.node.id;

    if (t.isIdentifier(id)) {
      this.remember(path, id.name, {
        module: source.module,
        member: source.member,
        style: source.style,
        aliasDepth: source.aliasDepth,
      });
      return;
    }

    if (t.isObjectPattern(id)) {
      // `const { exec } = …` and `const { exec: run } = …`. Only meaningful
      // when the right-hand side is a namespace: destructuring a *member*
      // yields properties of that member, which we do not model.
      if (source.member !== undefined && source.style !== "import-namespace") {
        // Still model one level: `const { readFile } = fs.promises`.
        this.recordObjectPattern(path, id, source, source.member);
        return;
      }
      this.recordObjectPattern(path, id, source, undefined);
    }
  }

  private recordObjectPattern(
    path: NodePath<t.VariableDeclarator>,
    pattern: t.ObjectPattern,
    source: { module: string; aliasDepth: number },
    memberPrefix: string | undefined,
  ): void {
    for (const property of pattern.properties) {
      if (!t.isObjectProperty(property)) continue;
      const key = property.key;
      const keyName = t.isIdentifier(key)
        ? key.name
        : t.isStringLiteral(key)
          ? key.value
          : undefined;
      if (keyName === undefined) continue;
      if (!t.isIdentifier(property.value)) continue;

      this.remember(path, property.value.name, {
        module: source.module,
        member: joinMember(memberPrefix, keyName),
        style: memberPrefix === undefined ? "require-member" : "alias",
        aliasDepth: source.aliasDepth,
      });
    }
  }

  /**
   * What does this initialiser expression refer to? Handles `require(…)`,
   * `import(…)`, member access on either, and any already-known local name.
   */
  private describeInitialiser(
    path: NodePath<t.Node>,
    hop: number,
  ):
    | {
        module: string;
        member: string | undefined;
        style: ImportStyle;
        aliasDepth: number;
      }
    | undefined {
    const node = unwrap(path.node);

    const required = requireTarget(path);
    if (required !== undefined) {
      return { module: required, member: undefined, style: "require", aliasDepth: 0 };
    }

    const imported = dynamicImportTarget(node);
    if (imported !== undefined) {
      return {
        module: imported,
        member: undefined,
        style: "dynamic-import",
        aliasDepth: 0,
      };
    }

    // `const exec = require("child_process").exec` and `const e = cp.exec`.
    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      const property = staticPropertyName(node);
      if (property === undefined) return undefined;
      const objectPath = path.get("object") as unknown as NodePath<t.Node>;
      const base = this.describeInitialiser(objectPath, hop);
      if (base === undefined) return undefined;
      return {
        module: base.module,
        member: joinMember(base.member, property.name),
        style: base.aliasDepth === 0 ? "require-member" : "alias",
        aliasDepth: base.aliasDepth,
      };
    }

    // `const cp2 = cp` — only on later passes, and only up to maxAliasDepth.
    if (t.isIdentifier(node) && hop > 0) {
      const known = this.lookupIdentifier(path, node.name);
      if (known === undefined) return undefined;
      if (known.aliasDepth >= hop) return undefined;
      return {
        module: known.module,
        member: known.member,
        style: "alias",
        aliasDepth: known.aliasDepth + 1,
      };
    }

    return undefined;
  }

  private lookupIdentifier(
    path: NodePath<t.Node>,
    name: string,
  ): ModuleBinding | undefined {
    const binding = path.scope.getBinding(name);
    if (binding === undefined) return undefined;
    return this.bindings.get(binding);
  }

  /**
   * Resolve an expression — typically a call's callee — to a module capability
   * or a global.
   *
   * Returns `undefined` for anything not traceable to an import or a global,
   * which is the honest answer for a locally-defined function.
   */
  resolve(path: NodePath<t.Node>, limits: AnalysisLimits): ResolvedTarget | undefined {
    return this.resolveInner(path, limits, 0, false);
  }

  private resolveInner(
    path: NodePath<t.Node>,
    limits: AnalysisLimits,
    depth: number,
    computed: boolean,
  ): ResolvedTarget | undefined {
    if (depth > limits.maxMemberDepth) return undefined;
    const node = unwrap(path.node);

    if (t.isIdentifier(node)) {
      const known = this.lookupIdentifier(path, node.name);
      if (known !== undefined) {
        return {
          kind: "module",
          module: known.module,
          member: known.member,
          aliasDepth: known.aliasDepth,
          computed,
          declaration: known.declaration,
        };
      }
      // No binding anywhere in scope ⇒ ambient global. A shadowed name has a
      // binding and therefore never reaches here.
      if (path.scope.getBinding(node.name) === undefined) {
        return {
          kind: "global",
          module: node.name,
          member: undefined,
          aliasDepth: 0,
          computed,
        };
      }
      return undefined;
    }

    // Direct `require("fs").readFileSync(…)` with no intermediate variable.
    const required = requireTarget(path);
    if (required !== undefined) {
      return {
        kind: "module",
        module: required,
        member: undefined,
        aliasDepth: 0,
        computed,
      };
    }
    const imported = dynamicImportTarget(node);
    if (imported !== undefined) {
      return {
        kind: "module",
        module: imported,
        member: undefined,
        aliasDepth: 0,
        computed,
      };
    }

    if (t.isMemberExpression(node) || t.isOptionalMemberExpression(node)) {
      const objectPath = path.get("object") as unknown as NodePath<t.Node>;
      const property = staticPropertyName(node);
      const base = this.resolveInner(
        objectPath,
        limits,
        depth + 1,
        computed || property === undefined,
      );
      if (base === undefined) return undefined;

      // `globalThis.process` is `process`; collapse it so one rule covers both.
      if (
        base.kind === "global" &&
        base.module === "globalThis" &&
        base.member === undefined
      ) {
        if (property === undefined) {
          return { ...base, computed: true };
        }
        return {
          kind: "global",
          module: property.name,
          member: undefined,
          aliasDepth: 0,
          computed,
        };
      }

      if (property === undefined) {
        // Computed access with a non-literal key: the object is known, the
        // member is not. Rules must treat this as a weaker observation.
        return { ...base, computed: true };
      }

      return {
        ...base,
        member: joinMember(base.member, property.name),
        computed: base.computed,
      };
    }

    return undefined;
  }
}
