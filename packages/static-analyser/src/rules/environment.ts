import type { NodePath } from "@babel/traverse";
import * as t from "@babel/types";
import type { Severity } from "@packagegate/shared";
import { MUNDANE_ENVIRONMENT_NAMES, SECRET_ENVIRONMENT_NAMES } from "./catalogue.js";
import { argumentPaths, calleePath } from "./helpers.js";
import { emitAt, locationOf, type Rule, type RuleContext } from "./types.js";

/**
 * Environment access.
 *
 * This rule is the clearest demonstration that severity and confidence are
 * different axes. `process.env.NODE_ENV` is detected with total certainty —
 * HIGH confidence — and means essentially nothing — LOW severity. Two hundred
 * such reads are worth about three points out of a hundred
 * (`docs/RISK_MODEL.md` §6.3), and they must not be allowed to look like
 * anything else.
 *
 * Three distinct observations are made, because they have different meanings:
 *
 *  - a **named** read of an ordinary variable: inventory,
 *  - a named read of a variable that *is a credential*: purposeful, because the
 *    package told us exactly what it wants,
 *  - **enumeration** of the whole environment: you enumerate when you do not
 *    know what you are looking for, which is a different purpose profile.
 */

const RULE_PREFIX = "js/environment";

/** `Object.keys` and friends: whole-object access to an environment. */
const ENUMERATION_MEMBERS: ReadonlySet<string> = new Set([
  "keys",
  "values",
  "entries",
  "assign",
  "getOwnPropertyNames",
  "fromEntries",
]);

/** Is this path exactly the expression `process.env`? */
function isProcessEnv(path: NodePath<t.Node>, ctx: RuleContext): boolean {
  const target = ctx.resolver.resolve(path, ctx.limits);
  return (
    target !== undefined &&
    target.kind === "global" &&
    target.module === "process" &&
    target.member === "env"
  );
}

function severityForName(name: string): { severity: Severity; targeted: boolean } {
  if (SECRET_ENVIRONMENT_NAMES.has(name)) return { severity: "HIGH", targeted: true };
  return { severity: "LOW", targeted: false };
}

export const environmentAccessRule: Rule = {
  id: RULE_PREFIX,
  visitors: {
    MemberExpression(path, ctx) {
      const objectPath = path.get("object") as unknown as NodePath<t.Node>;
      if (!isProcessEnv(objectPath, ctx)) return;

      // `process.env[name]` where `name` is not a literal: we know the
      // environment was read, we do not know which variable. Report it as
      // exactly that rather than pretending to know more.
      const property = path.node.property;
      const computedUnknown = path.node.computed && !t.isStringLiteral(property);

      const variableName = path.node.computed
        ? t.isStringLiteral(property)
          ? property.value
          : undefined
        : t.isIdentifier(property)
          ? property.name
          : undefined;

      if (variableName === undefined) {
        if (!computedUnknown) return;
        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/env-read-computed`,
          category: "ENVIRONMENT_ACCESS",
          title: "Environment variable read with a computed name",
          description:
            "The package reads `process.env` using a key computed at runtime, so which " +
            "variable is read cannot be determined from the source.",
          severity: "LOW",
          confidence: "MEDIUM",
          evidence: [
            {
              kind: "AST_NODE",
              description: "Computed member access on `process.env`",
              location: locationOf(path.node, ctx.filePath),
            },
          ],
          metadata: { computed: true },
        });
        return;
      }

      const { severity, targeted } = severityForName(variableName);
      const mundane = MUNDANE_ENVIRONMENT_NAMES.has(variableName);

      emitAt(ctx, path.node, {
        ruleId: targeted
          ? `${RULE_PREFIX}/env-read-credential`
          : `${RULE_PREFIX}/env-read`,
        category: targeted ? "CREDENTIAL_RELATED_ACCESS" : "ENVIRONMENT_ACCESS",
        title: targeted
          ? `Credential environment variable read: ${variableName}`
          : `Environment variable read: ${variableName}`,
        description: targeted
          ? `The package reads \`process.env.${variableName}\`, an environment variable that ` +
            "conventionally holds a credential. Publishing tools, deployment CLIs and cloud " +
            "SDKs read these legitimately; what matters is where the value goes."
          : `The package reads \`process.env.${variableName}\`.` +
            (mundane
              ? " This variable describes the environment and is read by most of the ecosystem."
              : ""),
        severity,
        // Detection here is exact: a literal property on a global that is not
        // shadowed. Certainty about the read says nothing about its meaning.
        confidence: "HIGH",
        evidence: [
          {
            kind: "AST_NODE",
            description: `Read of \`process.env.${variableName}\``,
            location: locationOf(path.node, ctx.filePath),
            value: variableName,
          },
        ],
        metadata: { variable: variableName, targeted, mundane },
      });
    },

    CallExpression(path, ctx) {
      // `Object.keys(process.env)`, `JSON.stringify(process.env)`,
      // `Object.assign({}, process.env)`.
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined || target.kind !== "global") return;

      const isEnumeration =
        (target.module === "Object" &&
          target.member !== undefined &&
          ENUMERATION_MEMBERS.has(target.member)) ||
        (target.module === "JSON" && target.member === "stringify");
      if (!isEnumeration) return;

      for (const argument of argumentPaths(path)) {
        if (!isProcessEnv(argument, ctx)) continue;
        emitEnumeration(path.node, ctx, `${target.module}.${target.member ?? ""}`);
        return;
      }
    },
  },
};

function emitEnumeration(node: t.Node, ctx: RuleContext, via: string): void {
  emitAt(ctx, node, {
    ruleId: `${RULE_PREFIX}/env-enumeration`,
    category: "ENVIRONMENT_ACCESS",
    title: "Whole environment enumerated",
    description:
      `The package passes \`process.env\` as a whole to \`${via}\`. Bulk access has a ` +
      "different purpose profile from named access — configuration libraries, CI reporters " +
      "and crash reporters do it legitimately, but so does collection.",
    severity: "MEDIUM",
    confidence: "HIGH",
    evidence: [
      {
        kind: "AST_NODE",
        description: `\`process.env\` passed to \`${via}\``,
        location: locationOf(node, ctx.filePath),
        value: via,
      },
    ],
    metadata: { via },
  });
}

/** Spread of the environment: `{ ...process.env }`. */
export const environmentSpreadRule: Rule = {
  id: `${RULE_PREFIX}/spread`,
  visitors: {
    MemberExpression(path, ctx) {
      const parent = path.parentPath;
      if (parent === null || !parent.isSpreadElement()) return;
      if (!isProcessEnv(path, ctx)) return;
      emitEnumeration(parent.node, ctx, "object spread");
    },
  },
};
