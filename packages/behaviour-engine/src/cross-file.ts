import traverse, { type NodePath } from "@babel/traverse";
import * as t from "@babel/types";
import { createHash } from "node:crypto";
import type { BehaviourChain, Finding } from "@packagegate/shared";
import { parseSource, DEFAULT_ANALYSIS_LIMITS } from "@packagegate/static-analyser";
import type { SourceFileInput } from "./types.js";

/**
 * Limited cross-file dataflow for literal local imports.
 *
 * Supports: `export function collect() { return process.env }` imported and
 * passed to a network sink. Co-occurrence across files without a call edge
 * does not produce a chain. Never executes package code.
 */

const MAX_MODULES = 32;

interface FunctionSummary {
  readonly name: string;
  readonly returnsEnv: boolean;
}

function localSpecifier(value: string): string | undefined {
  if (!value.startsWith("./")) return undefined;
  let normalised = value.slice(2);
  if (
    !normalised.endsWith(".js") &&
    !normalised.endsWith(".mjs") &&
    !normalised.endsWith(".cjs") &&
    !normalised.endsWith(".ts")
  ) {
    normalised = `${normalised}.js`;
  }
  if (normalised.includes("..") || normalised.startsWith("/")) return undefined;
  return normalised;
}

function isProcessEnvNode(node: t.Node): boolean {
  if (!t.isMemberExpression(node)) return false;
  if (
    t.isIdentifier(node.object, { name: "process" }) &&
    t.isIdentifier(node.property, { name: "env" }) &&
    !node.computed
  ) {
    return true;
  }
  return isProcessEnvNode(node.object);
}

function summariseFile(ast: t.File): FunctionSummary[] {
  const summaries: FunctionSummary[] = [];

  const consider = (name: string, path: NodePath<t.Function>): void => {
    let returnsEnv = false;
    path.traverse({
      ReturnStatement(returnPath) {
        const arg = returnPath.node.argument;
        if (arg && isProcessEnvNode(arg)) returnsEnv = true;
      },
    });
    summaries.push({ name, returnsEnv });
  };

  traverse(ast, {
    FunctionDeclaration(path: NodePath<t.FunctionDeclaration>) {
      const name = path.node.id?.name;
      if (name === undefined) return;
      consider(name, path);
      if (summaries.length >= 32) path.stop();
    },
    AssignmentExpression(path) {
      if (summaries.length >= 32) return;
      const { left, right } = path.node;
      if (!t.isFunctionExpression(right) && !t.isArrowFunctionExpression(right)) return;
      if (
        !t.isMemberExpression(left) ||
        !t.isIdentifier(left.property) ||
        left.computed
      ) {
        return;
      }
      const name = left.property.name;
      const fnPath = path.get("right");
      if (fnPath.isFunction()) consider(name, fnPath);
    },
  });

  return summaries;
}

function resolveLocal(spec: string, files: Map<string, string>): string | undefined {
  if (files.has(spec)) return spec;
  const stem = spec.replace(/\.js$/, "");
  for (const candidate of [`${stem}.js`, `${stem}.mjs`, `${stem}.cjs`, `${stem}.ts`]) {
    if (files.has(candidate)) return candidate;
  }
  return undefined;
}

function isNetworkArgSink(call: t.CallExpression): boolean {
  const { callee } = call;
  if (t.isIdentifier(callee, { name: "fetch" })) return true;
  if (t.isMemberExpression(callee) && t.isIdentifier(callee.property)) {
    return ["request", "get", "post", "write", "end", "send"].includes(
      callee.property.name,
    );
  }
  return false;
}

/**
 * True when `name` is called and its return value reaches a network sink argument.
 */
function envCallReachesNetwork(ast: t.File, localNames: ReadonlySet<string>): boolean {
  let hit = false;
  traverse(ast, {
    CallExpression(path) {
      if (hit) return;
      // Pattern: sink(collect())
      for (const arg of path.node.arguments) {
        if (
          t.isCallExpression(arg) &&
          t.isIdentifier(arg.callee) &&
          localNames.has(arg.callee.name) &&
          isNetworkArgSink(path.node)
        ) {
          hit = true;
          return;
        }
      }
      // Pattern: const data = collect(); sink(data)
      if (
        t.isIdentifier(path.node.callee) &&
        localNames.has(path.node.callee.name) &&
        path.parentPath.isVariableDeclarator() &&
        t.isIdentifier(path.parentPath.node.id)
      ) {
        const bindingName = path.parentPath.node.id.name;
        const binding = path.parentPath.scope.getBinding(bindingName);
        if (binding === undefined) return;
        for (const ref of binding.referencePaths) {
          const callParent = ref.findParent((p) => p.isCallExpression());
          if (
            callParent?.isCallExpression() &&
            isNetworkArgSink(callParent.node) &&
            callParent.node.arguments.some(
              (a) => t.isIdentifier(a) && a.name === bindingName,
            )
          ) {
            hit = true;
            return;
          }
        }
      }
    },
  });
  return hit;
}

export function analyseCrossFileChains(args: {
  readonly files: readonly SourceFileInput[];
  readonly findings: readonly Finding[];
}): BehaviourChain[] {
  const filesByPath = new Map(args.files.map((f) => [f.path, f.content]));
  const paths = [...filesByPath.keys()].sort().slice(0, MAX_MODULES);
  const summariesByFile = new Map<string, FunctionSummary[]>();
  const astByFile = new Map<string, t.File>();

  for (const path of paths) {
    const content = filesByPath.get(path);
    if (content === undefined) continue;
    const parsed = parseSource(path, content, DEFAULT_ANALYSIS_LIMITS);
    if (!parsed.ok) continue;
    astByFile.set(path, parsed.parsed.ast);
    summariesByFile.set(path, summariseFile(parsed.parsed.ast));
  }

  const chains: BehaviourChain[] = [];
  const seen = new Set<string>();

  for (const importerPath of paths) {
    const ast = astByFile.get(importerPath);
    if (ast === undefined) continue;

    traverse(ast, {
      ImportDeclaration(path) {
        const spec = localSpecifier(path.node.source.value);
        if (spec === undefined) return;
        const importedPath = resolveLocal(spec, filesByPath);
        if (importedPath === undefined) return;

        const envExporters = (summariesByFile.get(importedPath) ?? []).filter(
          (s) => s.returnsEnv,
        );
        if (envExporters.length === 0) return;

        const localNames = new Set<string>();
        for (const s of path.node.specifiers) {
          if (!t.isImportSpecifier(s)) continue;
          const imported = s.imported;
          if (!t.isIdentifier(imported)) continue;
          if (envExporters.some((e) => e.name === imported.name)) {
            localNames.add(s.local.name);
          }
        }
        maybeEmitCrossFileChain({
          importerPath,
          importedPath,
          localNames,
          envExporters,
          ast,
          findings: args.findings,
          chains,
          seen,
        });
      },
      VariableDeclarator(path) {
        // const { collect } = require("./collect.js")
        const init = path.get("init");
        if (!init.isCallExpression()) return;
        if (!t.isIdentifier(init.node.callee, { name: "require" })) return;
        const arg = init.node.arguments[0];
        if (!arg || !t.isStringLiteral(arg)) return;
        const spec = localSpecifier(arg.value);
        if (spec === undefined) return;
        const importedPath = resolveLocal(spec, filesByPath);
        if (importedPath === undefined) return;
        const envExporters = (summariesByFile.get(importedPath) ?? []).filter(
          (s) => s.returnsEnv,
        );
        if (envExporters.length === 0) return;
        if (!t.isObjectPattern(path.node.id)) return;
        const localNames = new Set<string>();
        for (const prop of path.node.id.properties) {
          if (!t.isObjectProperty(prop)) continue;
          const key = prop.key;
          const value = prop.value;
          if (!t.isIdentifier(key) || !t.isIdentifier(value)) continue;
          if (envExporters.some((e) => e.name === key.name)) {
            localNames.add(value.name);
          }
        }
        maybeEmitCrossFileChain({
          importerPath,
          importedPath,
          localNames,
          envExporters,
          ast,
          findings: args.findings,
          chains,
          seen,
        });
      },
    });
  }

  return chains;
}

function maybeEmitCrossFileChain(args: {
  importerPath: string;
  importedPath: string;
  localNames: Set<string>;
  envExporters: FunctionSummary[];
  ast: t.File;
  findings: readonly Finding[];
  chains: BehaviourChain[];
  seen: Set<string>;
}): void {
  if (args.localNames.size === 0) return;
  if (!envCallReachesNetwork(args.ast, args.localNames)) return;

  const envFinding = args.findings.find(
    (f) =>
      f.location.filePath === args.importedPath &&
      (f.category === "ENVIRONMENT_ACCESS" ||
        f.category === "CREDENTIAL_RELATED_ACCESS"),
  );
  const netFinding = args.findings.find(
    (f) =>
      f.location.filePath === args.importerPath &&
      (f.category === "NETWORK_ACCESS" || f.category === "NETWORK_DESTINATION"),
  );
  if (envFinding === undefined || netFinding === undefined) return;

  const id = createHash("sha256")
    .update(
      `xf\0${args.importedPath}\0${args.importerPath}\0${envFinding.id}\0${netFinding.id}`,
    )
    .digest("hex")
    .slice(0, 32);
  if (args.seen.has(id)) return;
  args.seen.add(id);

  args.chains.push({
    id,
    source: "ENVIRONMENT_ACCESS",
    transformations: [],
    sink: "NETWORK_REQUEST",
    confidence: "MEDIUM",
    links: [
      {
        kind: "RETURN_VALUE",
        via: args.envExporters[0]?.name,
        description: `Function in ${args.importedPath} returns environment data`,
        location: envFinding.location,
      },
      {
        kind: "ARGUMENT_FLOW",
        description: `Importer ${args.importerPath} passes that value to a network sink`,
        location: netFinding.location,
      },
    ],
    supportingFindingIds: [envFinding.id, netFinding.id],
    filePaths: [args.importedPath, args.importerPath],
    rationale: `Environment data returned from ${args.importedPath} reaches a network sink in ${args.importerPath}.`,
    metadata: { chainType: "CROSS_FILE_ENV_TO_NETWORK", crossFile: true },
  });
}
