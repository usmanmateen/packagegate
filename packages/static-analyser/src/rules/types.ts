import type { NodePath } from "@babel/traverse";
import type * as t from "@babel/types";
import type { Confidence, SourceLocation } from "@packagegate/shared";
import type { CapabilityResolver, ResolvedTarget } from "../bindings.js";
import type { FindingEmitter } from "../emitter.js";
import type { AnalysisLimits } from "../limits.js";
import type { FindingDraft } from "../types.js";

/**
 * What a rule is given.
 *
 * Rules receive resolution and emission as services and own neither. They also
 * receive the file's *text*, but only so they can quote it — there is no file
 * handle, no path resolution and no I/O anywhere in this package.
 */
export interface RuleContext {
  readonly filePath: string;
  readonly source: string;
  readonly limits: AnalysisLimits;
  readonly resolver: CapabilityResolver;
  readonly emitter: FindingEmitter;
  /** Informational; must never influence severity. */
  readonly minified: boolean;
  /** True when the file is reachable from an install lifecycle script. */
  readonly installReachable: boolean;
}

/**
 * The node types rules may subscribe to.
 *
 * Deliberately a closed list. One traversal serves every rule, so the cost of
 * analysis stays proportional to file size rather than to rule count, and the
 * node budget in `limits.ts` means something.
 */
export interface RuleVisitors {
  CallExpression?: (path: NodePath<t.CallExpression>, ctx: RuleContext) => void;
  NewExpression?: (path: NodePath<t.NewExpression>, ctx: RuleContext) => void;
  MemberExpression?: (path: NodePath<t.MemberExpression>, ctx: RuleContext) => void;
  StringLiteral?: (path: NodePath<t.StringLiteral>, ctx: RuleContext) => void;
  TemplateLiteral?: (path: NodePath<t.TemplateLiteral>, ctx: RuleContext) => void;
  Identifier?: (path: NodePath<t.Identifier>, ctx: RuleContext) => void;
  ArrayExpression?: (path: NodePath<t.ArrayExpression>, ctx: RuleContext) => void;
}

export interface Rule {
  /** Stable prefix for every finding this rule produces. */
  readonly id: string;
  readonly visitors: RuleVisitors;
}

/** Babel location → the shared `SourceLocation`, with a safe fallback. */
export function locationOf(node: t.Node, filePath: string): SourceLocation {
  const loc = node.loc;
  if (loc === null || loc === undefined) {
    // Nodes produced by error recovery can lack position information. Line 1 is
    // wrong but bounded and honest — the alternative is dropping the finding.
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

/**
 * Confidence from how the target was resolved, following the tiers in
 * `docs/RISK_MODEL.md` §4.3 collapsed onto the shared three-value scale.
 *
 * This answers "are we sure the code does this", never "is this bad".
 */
export function confidenceFor(target: ResolvedTarget): Confidence {
  if (target.computed) return "MEDIUM";
  if (target.aliasDepth === 0) return "HIGH";
  if (target.aliasDepth <= 2) return "HIGH";
  return "MEDIUM";
}

/** Human-readable description of how a name was resolved, for evidence. */
export function bindingEvidenceText(target: ResolvedTarget): string {
  const qualified =
    target.member === undefined ? target.module : `${target.module}.${target.member}`;
  if (target.kind === "global") return `resolved to the global \`${qualified}\``;
  const viaAlias =
    target.aliasDepth > 0 ? ` through ${String(target.aliasDepth)} alias hop(s)` : "";
  return `resolved to \`${qualified}\` from an import of \`${target.module}\`${viaAlias}`;
}

/** Convenience: emit a draft whose snippet is the node's own source range. */
export function emitAt(
  ctx: RuleContext,
  node: t.Node,
  draft: Omit<FindingDraft, "location" | "rawSnippet">,
): void {
  ctx.emitter.emit({
    ...draft,
    location: locationOf(node, ctx.filePath),
    rawSnippet: "",
  });
}
