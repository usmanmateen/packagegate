import type { NodePath } from "@babel/traverse";
import type * as t from "@babel/types";
import type { Evidence, Severity } from "@packagegate/shared";
import type { ResolvedTarget } from "../bindings.js";
import {
  DECODE_GLOBALS,
  DYNAMIC_EXECUTION_GLOBALS,
  NETWORK_GLOBALS,
  NETWORK_MODULES,
  NETWORK_PACKAGES,
  VM_EXECUTION_MEMBERS,
  VM_MODULE,
} from "./catalogue.js";
import {
  argumentPaths,
  calleePath,
  effectiveMember,
  staticStringValue,
  subtreeContainsCall,
} from "./helpers.js";
import {
  bindingEvidenceText,
  emitAt,
  locationOf,
  type Rule,
  type RuleContext,
} from "./types.js";

/**
 * Turning data into running code.
 *
 * `eval` and `new Function` are MEDIUM on their own: template engines, DI
 * containers, polyfill loaders and source-map tooling all use them, and a
 * scanner that treats them as damning flags a large slice of the ecosystem.
 *
 * What earns a HIGH is *what is being executed*. When the operand of the sink
 * syntactically contains a decode or a network read, the package is executing
 * content that a reviewer cannot see in the file — a narrower and much more
 * defensible claim than "obfuscated". Note the restriction: the relationship
 * has to be visible in one expression. Anything requiring inference across
 * statements is the behaviour engine's job, under its own evidence rules.
 */

const RULE_PREFIX = "js/dynamic-execution";

/** Decode entry points recognised as "content the reader cannot see". */
function isDecodeTarget(target: ResolvedTarget, callPath: NodePath<t.Node>): boolean {
  if (target.kind === "global") {
    if (DECODE_GLOBALS.has(target.module) && target.member === undefined) return true;
    if (target.module === "Buffer" && target.member === "from") {
      return bufferEncodingArgument(callPath) !== undefined;
    }
    if (target.module === "String" && target.member === "fromCharCode") return true;
    return false;
  }
  return target.module === "zlib" || target.module === "querystring";
}

function isNetworkTarget(target: ResolvedTarget): boolean {
  if (target.kind === "global") {
    return NETWORK_GLOBALS.has(target.module) && target.member === undefined;
  }
  return NETWORK_MODULES.has(target.module) || NETWORK_PACKAGES.has(target.module);
}

/** `Buffer.from(data, "base64")` — the encoding argument, when it is literal. */
function bufferEncodingArgument(path: NodePath<t.Node>): string | undefined {
  if (!path.isCallExpression()) return undefined;
  const second = path.node.arguments[1];
  if (second === undefined) return undefined;
  const encoding = staticStringValue(second);
  if (encoding === undefined) return undefined;
  const lowered = encoding.toLowerCase();
  return lowered === "base64" || lowered === "hex" || lowered === "base64url"
    ? lowered
    : undefined;
}

function classifyOperand(
  operand: NodePath<t.Node> | undefined,
  ctx: RuleContext,
): { decoded: boolean; fetched: boolean; literal: boolean } {
  if (operand === undefined) return { decoded: false, fetched: false, literal: false };
  return {
    decoded: subtreeContainsCall(operand, ctx, isDecodeTarget),
    fetched: subtreeContainsCall(operand, ctx, (target) => isNetworkTarget(target)),
    literal: staticStringValue(operand.node) !== undefined,
  };
}

function emitSink(
  node: t.Node,
  ctx: RuleContext,
  sinkName: string,
  operand: NodePath<t.Node> | undefined,
  extraEvidence: Evidence[],
): void {
  const { decoded, fetched, literal } = classifyOperand(operand, ctx);

  let severity: Severity = "MEDIUM";
  let category: "DYNAMIC_CODE_EXECUTION" | "REMOTE_CODE_FETCH" = "DYNAMIC_CODE_EXECUTION";
  let ruleId = `${RULE_PREFIX}/dynamic-code`;
  let title = `Dynamic code execution via ${sinkName}`;
  let description =
    `The package executes code built at runtime using \`${sinkName}\`. Template engines, ` +
    "dependency injection and polyfill loaders use this legitimately; it is reported " +
    "because the executed text is not visible in the source.";

  if (fetched) {
    severity = "HIGH";
    category = "REMOTE_CODE_FETCH";
    ruleId = `${RULE_PREFIX}/remote-code-execution`;
    title = `Remotely fetched content executed via ${sinkName}`;
    description =
      `The operand of \`${sinkName}\` syntactically contains a network read, so content ` +
      "retrieved at runtime is executed directly. The relationship is visible in a single " +
      "expression rather than inferred. This is the dropper shape, and it is also how some " +
      "plugin loaders work.";
  } else if (decoded) {
    severity = "HIGH";
    ruleId = `${RULE_PREFIX}/encoded-code`;
    title = `Encoded content executed via ${sinkName}`;
    description =
      `The operand of \`${sinkName}\` syntactically contains a decode step, so the executed ` +
      "text is concealed from anyone reading the file. This is a narrower claim than " +
      '"obfuscated code": it is executable content that the source deliberately does not show.';
  } else if (literal) {
    // A literal operand is fully readable, so the concealment argument does not
    // apply at all.
    severity = "LOW";
    description =
      `The package executes a string literal using \`${sinkName}\`. The executed text is ` +
      "readable in the source.";
  }

  emitAt(ctx, node, {
    ruleId,
    category,
    title,
    description,
    severity,
    confidence: "HIGH",
    evidence: [
      {
        kind: "AST_NODE",
        description: `Call to \`${sinkName}\``,
        location: locationOf(node, ctx.filePath),
        value: sinkName,
      },
      ...extraEvidence,
    ],
    metadata: { sink: sinkName, operandDecoded: decoded, operandFetched: fetched },
  });
}

export const dynamicExecutionRule: Rule = {
  id: RULE_PREFIX,
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;

      const args = argumentPaths(path);

      if (
        target.kind === "global" &&
        target.member === undefined &&
        DYNAMIC_EXECUTION_GLOBALS.has(target.module)
      ) {
        emitSink(path.node, ctx, target.module, args[0], []);
        return;
      }

      const member = effectiveMember(target);
      if (
        target.kind === "module" &&
        target.module === VM_MODULE &&
        member !== undefined &&
        VM_EXECUTION_MEMBERS.has(member)
      ) {
        emitSink(path.node, ctx, `vm.${member}`, args[0], [
          {
            kind: "BINDING",
            description: bindingEvidenceText(target),
            ...(target.declaration === undefined ? {} : { location: target.declaration }),
          },
        ]);
        return;
      }

      // `require(expr)` where `expr` is not a literal: the module that will be
      // loaded cannot be determined statically, and a written-then-required
      // file is a documented way to run downloaded code.
      if (
        target.kind === "global" &&
        target.module === "require" &&
        target.member === undefined
      ) {
        const first = args[0];
        if (first === undefined) return;
        if (staticStringValue(first.node) !== undefined) return;
        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/dynamic-require`,
          category: "DYNAMIC_CODE_EXECUTION",
          title: "Module loaded from a runtime-constructed specifier",
          description:
            "`require` is called with a value computed at runtime, so which module is loaded " +
            "cannot be determined from the source. Plugin systems and platform shims do this; " +
            "so does loading a file that was just written to disk.",
          severity: "MEDIUM",
          confidence: "HIGH",
          evidence: [
            {
              kind: "AST_NODE",
              description: "`require` with a non-literal specifier",
              location: locationOf(path.node, ctx.filePath),
            },
          ],
          metadata: { specifierIsLiteral: false },
        });
      }
    },

    NewExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;

      if (
        target.kind === "global" &&
        target.member === undefined &&
        target.module === "Function"
      ) {
        // `new Function(args…, body)` — the body is the last argument.
        const args = argumentPaths(path);
        emitSink(path.node, ctx, "new Function", args[args.length - 1], []);
        return;
      }

      const member = effectiveMember(target);
      if (
        target.kind === "module" &&
        target.module === VM_MODULE &&
        member !== undefined &&
        VM_EXECUTION_MEMBERS.has(member)
      ) {
        const args = argumentPaths(path);
        emitSink(path.node, ctx, `new vm.${member}`, args[0], [
          { kind: "BINDING", description: bindingEvidenceText(target) },
        ]);
      }
    },
  },
};

/** `process.dlopen` and `require("….node")`: loading compiled native code. */
export const nativeCodeRule: Rule = {
  id: "js/native",
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;

      if (
        target.kind === "global" &&
        target.module === "process" &&
        target.member === "dlopen"
      ) {
        emitAt(ctx, path.node, {
          ruleId: "js/native/dlopen",
          category: "NATIVE_BINARY",
          title: "Native addon loaded via process.dlopen",
          description:
            "The package loads a compiled native addon directly. Native code is outside the " +
            "reach of this analyser entirely — see the coverage note in " +
            "`docs/STATIC_ANALYSIS.md`.",
          severity: "MEDIUM",
          confidence: "HIGH",
          evidence: [
            {
              kind: "AST_NODE",
              description: "Call to `process.dlopen`",
              location: locationOf(path.node, ctx.filePath),
            },
          ],
          metadata: {},
        });
        return;
      }

      if (
        target.kind === "global" &&
        target.module === "require" &&
        target.member === undefined
      ) {
        const first = argumentPaths(path)[0];
        const specifier = first === undefined ? undefined : staticStringValue(first.node);
        if (specifier === undefined || !specifier.endsWith(".node")) return;
        emitAt(ctx, path.node, {
          ruleId: "js/native/require-addon",
          category: "NATIVE_BINARY",
          title: "Compiled native addon required",
          description:
            "The package requires a `.node` addon. This is how every native module in the " +
            "ecosystem works; it is recorded because the addon's behaviour is not analysable " +
            "from JavaScript source.",
          severity: "LOW",
          confidence: "HIGH",
          evidence: [
            {
              kind: "STRING_LITERAL",
              description: "Native addon specifier",
              location: locationOf(path.node, ctx.filePath),
              value: specifier,
            },
          ],
          metadata: { specifier },
        });
      }
    },
  },
};
