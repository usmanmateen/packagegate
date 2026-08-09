import traverse, { type NodePath } from "@babel/traverse";
import type * as t from "@babel/types";
import { environmentAccessRule, environmentSpreadRule } from "./environment.js";
import { dynamicExecutionRule, nativeCodeRule } from "./dynamic-execution.js";
import { encodedPayloadRule } from "./encoding.js";
import { filesystemRule, sensitivePathRule } from "./filesystem.js";
import { networkCapabilityRule, networkDestinationRule } from "./network.js";
import { createObfuscationRule } from "./obfuscation.js";
import { processExecutionRule } from "./process-execution.js";
import { nativeLoaderRule, systemInformationRule } from "./system-info.js";
import type { Rule, RuleContext } from "./types.js";

export type { Rule, RuleContext } from "./types.js";

/**
 * The rule set, instantiated per file.
 *
 * Most rules are stateless singletons. The obfuscation rule counts occurrences
 * within a file, so it is constructed fresh each time — sharing that state
 * between files would let one bundled vendor file put another file's name on a
 * fingerprint finding.
 */
export function createRules(): Rule[] {
  return [
    processExecutionRule,
    environmentAccessRule,
    environmentSpreadRule,
    networkCapabilityRule,
    networkDestinationRule,
    filesystemRule,
    sensitivePathRule,
    dynamicExecutionRule,
    encodedPayloadRule,
    systemInformationRule,
    createObfuscationRule(),
    nativeCodeRule,
    nativeLoaderRule,
  ];
}

/** Why a traversal ended. `"complete"` is the only outcome that saw every node. */
export type TraversalOutcome = "complete" | "node-budget" | "time-budget";

/** How often the wall-clock budget is checked, in nodes. */
const TIME_CHECK_INTERVAL = 4_096;

/**
 * Run every rule in a single traversal.
 *
 * One walk serves all rules, so analysis cost is proportional to file size
 * rather than to rule count — which is what makes the node budget in
 * `limits.ts` a meaningful defence rather than a per-rule inconvenience.
 *
 * A rule that throws must not take the file, the package or the scan with it,
 * so each dispatch is guarded and the failure is surfaced through the returned
 * error list rather than swallowed.
 */
export function runRules(
  ast: t.File,
  rules: readonly Rule[],
  ctx: RuleContext,
): { outcome: TraversalOutcome; nodesVisited: number; ruleErrors: string[] } {
  const callHandlers: NonNullable<Rule["visitors"]["CallExpression"]>[] = [];
  const newHandlers: NonNullable<Rule["visitors"]["NewExpression"]>[] = [];
  const memberHandlers: NonNullable<Rule["visitors"]["MemberExpression"]>[] = [];
  const stringHandlers: NonNullable<Rule["visitors"]["StringLiteral"]>[] = [];
  const templateHandlers: NonNullable<Rule["visitors"]["TemplateLiteral"]>[] = [];
  const identifierHandlers: NonNullable<Rule["visitors"]["Identifier"]>[] = [];
  const arrayHandlers: NonNullable<Rule["visitors"]["ArrayExpression"]>[] = [];

  for (const rule of rules) {
    const { visitors } = rule;
    if (visitors.CallExpression) callHandlers.push(visitors.CallExpression);
    if (visitors.NewExpression) newHandlers.push(visitors.NewExpression);
    if (visitors.MemberExpression) memberHandlers.push(visitors.MemberExpression);
    if (visitors.StringLiteral) stringHandlers.push(visitors.StringLiteral);
    if (visitors.TemplateLiteral) templateHandlers.push(visitors.TemplateLiteral);
    if (visitors.Identifier) identifierHandlers.push(visitors.Identifier);
    if (visitors.ArrayExpression) arrayHandlers.push(visitors.ArrayExpression);
  }

  const ruleErrors: string[] = [];
  const startedAt = Date.now();
  let nodesVisited = 0;
  let outcome: TraversalOutcome = "complete";

  const guard = <P>(handler: (path: P, ctx: RuleContext) => void, path: P): void => {
    try {
      handler(path, ctx);
    } catch (error: unknown) {
      // Not a silent catch: the message is returned to the caller and ends up
      // in the file's analysis report, so a broken rule is visible rather than
      // quietly reducing coverage.
      const message = error instanceof Error ? error.message : String(error);
      if (ruleErrors.length < 20) ruleErrors.push(message);
    }
  };

  traverse(ast, {
    enter(path: NodePath<t.Node>) {
      nodesVisited += 1;

      if (nodesVisited > ctx.limits.maxNodesPerFile) {
        outcome = "node-budget";
        path.stop();
        return;
      }
      if (
        nodesVisited % TIME_CHECK_INTERVAL === 0 &&
        Date.now() - startedAt > ctx.limits.maxFileMillis
      ) {
        outcome = "time-budget";
        path.stop();
        return;
      }

      if (path.isCallExpression()) {
        for (const handler of callHandlers) guard(handler, path);
      } else if (path.isNewExpression()) {
        for (const handler of newHandlers) guard(handler, path);
      } else if (path.isMemberExpression()) {
        for (const handler of memberHandlers) guard(handler, path);
      } else if (path.isStringLiteral()) {
        for (const handler of stringHandlers) guard(handler, path);
      } else if (path.isTemplateLiteral()) {
        for (const handler of templateHandlers) guard(handler, path);
      } else if (path.isIdentifier()) {
        for (const handler of identifierHandlers) guard(handler, path);
      } else if (path.isArrayExpression()) {
        for (const handler of arrayHandlers) guard(handler, path);
      }
    },
  });

  return { outcome, nodesVisited, ruleErrors };
}
