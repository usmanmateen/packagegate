import type { NodePath } from "@babel/traverse";
import * as t from "@babel/types";
import type { ResolvedTarget } from "../bindings.js";
import type { RuleContext } from "./types.js";

/** The callee of a call, as a path, so it can be resolved through scope. */
export function calleePath(
  path: NodePath<t.CallExpression | t.NewExpression | t.OptionalCallExpression>,
): NodePath<t.Node> {
  return path.get("callee");
}

/**
 * The compile-time-known string value of a node, or `undefined`.
 *
 * Handles literals and template literals with no interpolation, plus
 * concatenation of those. Anything else is genuinely unknown at analysis time
 * and must be reported as unknown rather than guessed at — a guessed value
 * would become "evidence" for something we never actually saw.
 */
export function staticStringValue(node: t.Node, depth = 0): string | undefined {
  if (depth > 6) return undefined;
  if (t.isStringLiteral(node)) return node.value;
  if (t.isTemplateLiteral(node)) {
    if (node.expressions.length > 0) return undefined;
    const only = node.quasis[0];
    if (only === undefined) return undefined;
    // Babel reports `cooked` as null for a quasi with an invalid escape.
    return only.value.cooked ?? undefined;
  }
  if (t.isBinaryExpression(node, { operator: "+" })) {
    if (!t.isExpression(node.left)) return undefined;
    const left = staticStringValue(node.left, depth + 1);
    const right = staticStringValue(node.right, depth + 1);
    if (left === undefined || right === undefined) return undefined;
    return left + right;
  }
  return undefined;
}

/** Does the resolved target name this module (ignoring which member)? */
export function isModule(target: ResolvedTarget, modules: ReadonlySet<string>): boolean {
  return target.kind === "module" && modules.has(target.module);
}

/**
 * The member name to test against a capability table.
 *
 * `fs.promises.readFile` and `require("fs/promises").readFile` are the same
 * capability written two ways, so the `promises.` prefix is stripped and
 * `fs/promises` is folded into `fs` by the caller.
 */
export function effectiveMember(target: ResolvedTarget): string | undefined {
  if (target.member === undefined) return undefined;
  return target.member.startsWith("promises.")
    ? target.member.slice("promises.".length)
    : target.member;
}

/** Nodes examined when scanning one argument subtree. Bounds crafted input. */
const SUBTREE_NODE_BUDGET = 2_000;

/**
 * Does this expression subtree contain a call that satisfies `predicate`?
 *
 * Used for the narrow, defensible form of composition this package is willing
 * to claim: the fetched or decoded value is *syntactically an operand* of the
 * sink, e.g. `eval(atob(blob))`. That is a data relationship visible in one
 * expression, not an inference from two things existing in the same file.
 * Anything looser belongs to the behaviour engine, with its own evidence rules.
 */
export function subtreeContainsCall(
  path: NodePath<t.Node>,
  ctx: RuleContext,
  predicate: (target: ResolvedTarget, callPath: NodePath<t.Node>) => boolean,
): boolean {
  let found = false;
  let visited = 0;

  const check = (callPath: NodePath<t.CallExpression | t.NewExpression>): void => {
    if (found) return;
    const target = ctx.resolver.resolve(calleePath(callPath), ctx.limits);
    if (target !== undefined && predicate(target, callPath)) found = true;
  };

  if (path.isCallExpression() || path.isNewExpression()) check(path);

  path.traverse({
    enter(inner: NodePath<t.Node>) {
      visited += 1;
      if (visited > SUBTREE_NODE_BUDGET || found) {
        inner.stop();
        return;
      }
      if (inner.isCallExpression() || inner.isNewExpression()) check(inner);
    },
  });

  return found;
}

/** Argument paths of a call, as generic node paths. */
export function argumentPaths(
  path: NodePath<t.CallExpression | t.NewExpression>,
): NodePath<t.Node>[] {
  return path.get("arguments");
}

/**
 * True when an options object literal in `args` sets `shell: true` — the
 * difference between handing argv to the kernel and handing a string to `sh`.
 */
export function hasShellOption(path: NodePath<t.CallExpression>): boolean {
  for (const argument of path.node.arguments) {
    if (!t.isObjectExpression(argument)) continue;
    for (const property of argument.properties) {
      if (!t.isObjectProperty(property)) continue;
      const key = property.key;
      const name = t.isIdentifier(key)
        ? key.name
        : t.isStringLiteral(key)
          ? key.value
          : "";
      if (name !== "shell") continue;
      if (t.isBooleanLiteral(property.value, { value: true })) return true;
      if (t.isStringLiteral(property.value)) return true;
    }
  }
  return false;
}

/**
 * Recover statically known string values that may reach a process-execution
 * argument. Supports string/template literals at the call site, and identifiers
 * bound to one or more constant string assignments (including platform
 * branches). Does not expand interpolations or non-constant writes.
 */
export function recoverableStringArguments(
  argPath: NodePath<t.Node> | undefined,
): string[] {
  if (argPath === undefined) return [];
  const direct = staticStringValue(argPath.node);
  if (direct !== undefined) return [direct];

  if (!argPath.isIdentifier()) return [];
  const binding = argPath.scope.getBinding(argPath.node.name);
  if (binding === undefined) return [];

  const values = new Set<string>();

  if (binding.path.isVariableDeclarator()) {
    const init = binding.path.node.init;
    if (init !== undefined && init !== null) {
      const value = staticStringValue(init);
      if (value !== undefined) values.add(value);
    }
  }

  for (const write of binding.constantViolations.slice(0, 32)) {
    if (!write.isAssignmentExpression() || write.node.operator !== "=") continue;
    const value = staticStringValue(write.node.right);
    if (value !== undefined) values.add(value);
  }

  for (const ref of binding.referencePaths.slice(0, 64)) {
    const parent = ref.parentPath;
    if (
      parent?.isAssignmentExpression() &&
      parent.node.operator === "=" &&
      parent.get("left") === ref
    ) {
      const value = staticStringValue(parent.node.right);
      if (value !== undefined) values.add(value);
    }
  }

  return [...values].slice(0, 8);
}
