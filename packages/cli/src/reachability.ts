import { parseSource, DEFAULT_ANALYSIS_LIMITS } from "@packagegate/static-analyser";
import type * as t from "@babel/types";

/**
 * Install-time reachability.
 *
 * A package ships everything the publisher chose to include: sources, bundled
 * output, test suites, fixtures, documentation samples. Only some of it can
 * actually run when the package is installed or required.
 *
 * This module answers one narrow question — **which files are reachable from a
 * declared entrypoint or an install lifecycle script?** — so that the
 * completeness verdict can distinguish "we could not parse code that runs" from
 * "we could not parse a file nothing points at".
 *
 * ## Why not just skip `test/`?
 *
 * Because a path heuristic is trivially defeated. A package that puts its
 * payload in `test/` or `__fixtures__/` would get a free pass. Reachability is
 * computed from the manifest and the static import graph, so a package whose
 * entrypoint genuinely lives under `test/` is still fully reachable, and a file
 * is only unreachable when nothing declared actually points at it.
 *
 * ## The security tradeoff, stated plainly
 *
 * **Unreachable does not mean inert.** This graph is built from static
 * specifiers. A `require(someVariable)` we cannot resolve, a path assembled at
 * runtime, or a consumer deep-importing an internal path all reach code this
 * analysis calls unreachable.
 *
 * Three things keep that honest:
 *
 * 1. Unreachable files are still **fully analysed**. Reachability never
 *    suppresses a finding, a behaviour chain or a risk contribution — it only
 *    affects how a *parse failure* is weighed in the completeness verdict.
 * 2. When any unresolvable dynamic import is seen, `unresolvedDynamicImport`
 *    is set, and the caller falls back to treating everything as reachable.
 * 3. With no usable manifest, the function returns `null`, meaning "assume
 *    everything is reachable". It fails closed: a package cannot suppress the
 *    completeness signal by shipping a broken or entrypoint-free manifest.
 */

export interface ReachabilityInput {
  /** Parsed package.json, if one was available and valid. */
  readonly manifest: Record<string, unknown> | undefined;
  readonly files: readonly { readonly path: string; readonly content: string }[];
  /** Files referenced by install lifecycle scripts. Always reachable. */
  readonly lifecycleReferencedFiles: readonly string[];
}

export interface ReachabilitySet {
  has(path: string): boolean;
  readonly size: number;
  /** True when a dynamic import target could not be resolved statically. */
  readonly unresolvedDynamicImport: boolean;
}

const CANDIDATE_EXTENSIONS = [
  "",
  ".js",
  ".cjs",
  ".mjs",
  ".json",
  ".ts",
  ".cts",
  ".mts",
  ".jsx",
  ".tsx",
  "/index.js",
  "/index.cjs",
  "/index.mjs",
  "/index.ts",
  "/index.json",
];

/** Collect every string leaf of an `exports`/`bin` value, which may nest. */
function collectStringLeaves(value: unknown, out: string[], depth = 0): void {
  if (depth > 8) return;
  if (typeof value === "string") {
    out.push(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const entry of value) collectStringLeaves(entry, out, depth + 1);
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const entry of Object.values(value)) collectStringLeaves(entry, out, depth + 1);
  }
}

/** Normalise a manifest or specifier path to a package-relative form. */
function normalise(candidate: string): string {
  let path = candidate.replace(/\\/g, "/");
  while (path.startsWith("./")) path = path.slice(2);
  if (path.startsWith("/")) path = path.slice(1);
  // Collapse `a/b/../c` without touching the filesystem.
  const parts: string[] = [];
  for (const segment of path.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") parts.pop();
    else parts.push(segment);
  }
  return parts.join("/");
}

function resolveToFile(
  candidate: string,
  known: ReadonlySet<string>,
): string | undefined {
  const base = normalise(candidate);
  if (base === "") return undefined;
  for (const extension of CANDIDATE_EXTENSIONS) {
    const attempt = normalise(base + extension);
    if (known.has(attempt)) return attempt;
  }
  return undefined;
}

const PARSEABLE_RE = /\.(?:[cm]?js|jsx|[cm]?ts|tsx)$/i;

interface LocalImports {
  readonly specifiers: string[];
  readonly unresolvedDynamic: boolean;
}

/**
 * Extract relative import/require specifiers from one file.
 *
 * Bare specifiers (`lodash`) resolve into `node_modules` and are deliberately
 * not followed — a sibling file that happens to share the name is a different
 * thing entirely.
 */
function localImportsOf(content: string, path: string): LocalImports {
  const specifiers: string[] = [];
  let unresolvedDynamic = false;

  const outcome = parseSource(path, content, DEFAULT_ANALYSIS_LIMITS);
  if (!outcome.ok) return { specifiers, unresolvedDynamic };

  const record = (value: unknown): void => {
    if (typeof value === "string") {
      if (value.startsWith(".")) specifiers.push(value);
    } else {
      unresolvedDynamic = true;
    }
  };

  // A shallow walk over the program body and nested expressions is enough:
  // we only need module-level edges, not full semantics.
  const visit = (node: t.Node | null | undefined, depth: number): void => {
    if (node === null || node === undefined || depth > 40) return;
    const anyNode = node as unknown as Record<string, unknown>;

    if (node.type === "ImportDeclaration" || node.type === "ExportAllDeclaration") {
      const source = (anyNode["source"] as t.StringLiteral | undefined)?.value;
      record(source);
    } else if (node.type === "ExportNamedDeclaration") {
      const source = (anyNode["source"] as t.StringLiteral | null | undefined)?.value;
      if (source !== undefined) record(source);
    } else if (node.type === "CallExpression") {
      const callee = anyNode["callee"] as t.Node | undefined;
      const args = (anyNode["arguments"] as t.Node[] | undefined) ?? [];
      const isRequire = callee?.type === "Identifier" && callee.name === "require";
      const isImport = callee?.type === "Import";
      if (isRequire || isImport) {
        const first = args[0];
        record(first?.type === "StringLiteral" ? first.value : undefined);
      }
    }

    for (const key of Object.keys(anyNode)) {
      if (key === "loc" || key === "leadingComments" || key === "trailingComments")
        continue;
      const child = anyNode[key];
      if (Array.isArray(child)) {
        for (const item of child) {
          if (item !== null && typeof item === "object" && "type" in item) {
            visit(item as t.Node, depth + 1);
          }
        }
      } else if (child !== null && typeof child === "object" && "type" in child) {
        visit(child as t.Node, depth + 1);
      }
    }
  };

  visit(outcome.parsed.ast.program, 0);
  return { specifiers, unresolvedDynamic };
}

/**
 * Compute the set of install-reachable files.
 *
 * Returns `null` when reachability cannot be established, which the caller must
 * read as "treat every file as reachable".
 */
export function computeInstallReachable(
  input: ReachabilityInput,
): ReachabilitySet | null {
  const known = new Set(input.files.map((f) => normalise(f.path)));
  const contentByPath = new Map(input.files.map((f) => [normalise(f.path), f.content]));

  const roots: string[] = [];
  const manifest = input.manifest;
  if (manifest !== undefined) {
    for (const field of ["main", "module", "browser", "types", "typings"]) {
      const value = manifest[field];
      if (typeof value === "string") roots.push(value);
    }
    collectStringLeaves(manifest["exports"], roots);
    collectStringLeaves(manifest["bin"], roots);
  }
  for (const referenced of input.lifecycleReferencedFiles) roots.push(referenced);

  // No declared entrypoint means we cannot compute reachability. Fail closed
  // rather than declaring the whole package unreachable.
  if (roots.length === 0) return null;

  const resolvedRoots = roots
    .map((root) => resolveToFile(root, known))
    .filter((v): v is string => v !== undefined);

  // Entrypoints that resolve to nothing we extracted also mean we cannot trust
  // the graph — a `files` allowlist may have excluded them.
  if (resolvedRoots.length === 0) return null;

  const reachable = new Set<string>();
  const queue = [...resolvedRoots];
  let unresolvedDynamicImport = false;

  while (queue.length > 0) {
    const current = queue.pop();
    if (current === undefined || reachable.has(current)) continue;
    reachable.add(current);

    if (!PARSEABLE_RE.test(current)) continue;
    const content = contentByPath.get(current);
    if (content === undefined) continue;

    const { specifiers, unresolvedDynamic } = localImportsOf(content, current);
    if (unresolvedDynamic) unresolvedDynamicImport = true;

    const base = current.includes("/") ? current.slice(0, current.lastIndexOf("/")) : "";
    for (const specifier of specifiers) {
      const joined = base === "" ? specifier : `${base}/${specifier}`;
      const target = resolveToFile(joined, known);
      if (target !== undefined && !reachable.has(target)) queue.push(target);
    }
  }

  return {
    has: (path: string) => reachable.has(normalise(path)),
    size: reachable.size,
    unresolvedDynamicImport,
  };
}
