import type { NodePath } from "@babel/traverse";
import * as t from "@babel/types";
import { sanitiseInlineValue } from "@packagegate/shared";
import { calleePath, staticStringValue } from "./helpers.js";
import { emitAt, locationOf, type Rule, type RuleContext } from "./types.js";

/**
 * Obfuscation signals.
 *
 * The single most important thing this file does is *not* fire on minified
 * code. Bundled, minified `dist/` output is how a large share of the registry
 * ships; treating it as suspicious means treating "uses a build step" as
 * suspicious, and `docs/RISK_MODEL.md` §6.5 gives it weight zero on purpose.
 *
 * What is left is three narrow, defensible claims:
 *
 *  - **Bidi and invisible control characters in source.** These make a human
 *    reviewer see something different from what the parser sees. That is an
 *    attack on code review itself, not a formatting choice.
 *  - **A specific obfuscator fingerprint.** `_0x`-prefixed hex identifiers in
 *    quantity are the obfuscator.io family's signature. This is a tool
 *    fingerprint, not "looks minified" — minifiers produce short sequential
 *    names, never this shape.
 *  - **Dynamic dispatch of a sensitive API.** `globalThis[decoded]` and
 *    `process["e" + "nv"]` exist to defeat exactly the resolution this
 *    analyser performs. Hiding is worth reporting when what is hidden matters.
 */

const RULE_PREFIX = "js/obfuscation";

/**
 * Bidirectional and invisible formatting characters.
 *
 * Listed by code point rather than as literal characters so that this source
 * file cannot itself be made to lie about its contents.
 */
const BIDI_CONTROL_CODE_POINTS: ReadonlySet<number> = new Set([
  0x202a,
  0x202b,
  0x202c,
  0x202d,
  0x202e, // LRE RLE PDF LRO RLO
  0x2066,
  0x2067,
  0x2068,
  0x2069, // LRI RLI FSI PDI
  0x200e,
  0x200f, // LRM RLM
  0x061c, // Arabic letter mark
]);

/** Zero-width characters, which can hide content inside an identifier. */
const INVISIBLE_CODE_POINTS: ReadonlySet<number> = new Set([
  0x200b, 0x200c, 0x200d, 0xfeff, 0x2060,
]);

/**
 * Number of `_0x…` identifiers required before the obfuscator fingerprint is
 * reported. One such name is a coincidence; dozens are a tool.
 */
const OBFUSCATOR_IDENTIFIER_THRESHOLD = 8;

/**
 * The obfuscator.io identifier shape. Regex is appropriate here because the
 * subject is a single already-parsed identifier name, and the pattern is a
 * fixed prefix plus a bounded character class.
 */
const HEX_IDENTIFIER_PATTERN = /^_0x[0-9a-f]{4,8}$/;

/** Sensitive roots worth reporting when reached by computed access. */
const SENSITIVE_DISPATCH_ROOTS: ReadonlySet<string> = new Set([
  "process",
  "globalThis",
  "global",
  "Function",
  "Reflect",
]);

interface ObfuscationState {
  hexIdentifiers: Set<string>;
  reportedHexFingerprint: boolean;
  reportedBidi: boolean;
}

/**
 * Per-file state. The analyser creates one rule instance per file precisely so
 * that counts like "how many `_0x` identifiers" cannot leak between files.
 */
export function createObfuscationRule(): Rule {
  const state: ObfuscationState = {
    hexIdentifiers: new Set(),
    reportedHexFingerprint: false,
    reportedBidi: false,
  };

  return {
    id: RULE_PREFIX,
    visitors: {
      Identifier(path, ctx) {
        const name = path.node.name;

        if (!state.reportedHexFingerprint && HEX_IDENTIFIER_PATTERN.test(name)) {
          state.hexIdentifiers.add(name);
          if (state.hexIdentifiers.size >= OBFUSCATOR_IDENTIFIER_THRESHOLD) {
            state.reportedHexFingerprint = true;
            emitAt(ctx, path.node, {
              ruleId: `${RULE_PREFIX}/obfuscator-fingerprint`,
              category: "OBFUSCATION_SIGNAL",
              title: "Identifier naming matches a known JavaScript obfuscator",
              description:
                `The file contains ${String(state.hexIdentifiers.size)} identifiers of the form ` +
                "`_0x…` with hexadecimal suffixes, the signature of the obfuscator.io family. " +
                "This is deliberate concealment of logic from a reader, which is a different " +
                "thing from minification for size — minifiers produce short sequential names. " +
                "Licence-protection and anti-tamper wrappers use these tools legitimately.",
              severity: "MEDIUM",
              confidence: "HIGH",
              evidence: [
                {
                  kind: "MEASUREMENT",
                  description: `${String(state.hexIdentifiers.size)} distinct \`_0x\` hex identifiers`,
                  location: locationOf(path.node, ctx.filePath),
                  value: sanitiseInlineValue(name, 40),
                },
              ],
              metadata: { distinctHexIdentifiers: state.hexIdentifiers.size },
            });
          }
        }

        if (!state.reportedBidi) {
          const offending = findControlCodePoint(name);
          if (offending !== undefined) {
            state.reportedBidi = true;
            emitBidi(path.node, ctx, offending, "identifier");
          }
        }
      },

      StringLiteral(path, ctx) {
        if (state.reportedBidi) return;
        const raw = path.node.value;
        if (raw.length > ctx.limits.maxLiteralScanLength) return;
        const offending = findBidiCodePoint(raw);
        if (offending === undefined) return;
        state.reportedBidi = true;
        emitBidi(path.node, ctx, offending, "string literal");
      },

      MemberExpression(path, ctx) {
        if (!path.node.computed) return;
        const property = path.node.property;
        // A literal key is fully readable; only a computed, non-literal key
        // conceals which member is reached.
        if (t.isStringLiteral(property)) return;
        if (t.isNumericLiteral(property)) return;
        if (staticStringValue(property) !== undefined) {
          // `process["e" + "nv"]` folds to a known member but is written to
          // defeat a reader and a naive scanner. Report it as dispatch.
          reportDynamicDispatch(path, ctx, true);
          return;
        }
        reportDynamicDispatch(path, ctx, false);
      },

      CallExpression(path, ctx) {
        // `Reflect.get(process, decoded)` reaches a member without ever writing
        // one, and is not covered by the member-expression case.
        const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
        if (target === undefined) return;
        if (target.kind !== "global" || target.module !== "Reflect") return;
        if (target.member !== "get") return;
        const first = path.node.arguments[0];
        if (first === undefined || !t.isIdentifier(first)) return;
        if (!SENSITIVE_DISPATCH_ROOTS.has(first.name)) return;
        const second = path.node.arguments[1];
        if (second !== undefined && t.isStringLiteral(second)) return;

        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/dynamic-dispatch`,
          category: "OBFUSCATION_SIGNAL",
          title: `Property of \`${first.name}\` reached via Reflect.get with a computed key`,
          description:
            "A sensitive object is accessed through a reflective call with a key that is not " +
            "a literal, so which property is read cannot be determined from the source. " +
            "Plugin systems and isomorphic shims do this; so does evasion of static analysis.",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          evidence: [
            {
              kind: "AST_NODE",
              description: `\`Reflect.get(${first.name}, …)\` with a non-literal key`,
              location: locationOf(path.node, ctx.filePath),
              value: first.name,
            },
          ],
          metadata: { root: first.name, via: "Reflect.get" },
        });
      },
    },
  };
}

function reportDynamicDispatch(
  path: NodePath<t.MemberExpression>,
  ctx: RuleContext,
  folded: boolean,
): void {
  const objectPath = path.get("object") as unknown as NodePath<t.Node>;
  const target = ctx.resolver.resolve(objectPath, ctx.limits);
  if (target === undefined) return;
  if (target.kind !== "global" || target.member !== undefined) return;
  if (!SENSITIVE_DISPATCH_ROOTS.has(target.module)) return;

  emitAt(ctx, path.node, {
    ruleId: `${RULE_PREFIX}/dynamic-dispatch`,
    category: "OBFUSCATION_SIGNAL",
    title: `Property of \`${target.module}\` reached by computed access`,
    description: folded
      ? `A property of \`${target.module}\` is reached with a key assembled from string ` +
        "fragments. The result is readable to a compiler and not to a reader, and the only " +
        "purpose of writing it this way is to avoid being matched."
      : `A property of \`${target.module}\` is reached with a key computed at runtime, so ` +
        "which property is read cannot be determined from the source. Plugin systems and " +
        "feature detection do this legitimately.",
    severity: "MEDIUM",
    confidence: folded ? "HIGH" : "MEDIUM",
    evidence: [
      {
        kind: "AST_NODE",
        description: `Computed access on the global \`${target.module}\``,
        location: locationOf(path.node, ctx.filePath),
        value: target.module,
      },
    ],
    metadata: { root: target.module, keyFolded: folded },
  });
}

function emitBidi(
  node: t.Node,
  ctx: RuleContext,
  codePoint: number,
  where: string,
): void {
  const hex = codePoint.toString(16).toUpperCase().padStart(4, "0");
  emitAt(ctx, node, {
    ruleId: `${RULE_PREFIX}/bidi-or-invisible`,
    category: "OBFUSCATION_SIGNAL",
    title: `Bidirectional or invisible control character in ${where} (U+${hex})`,
    description:
      `The source contains U+${hex}, a character that changes how text is displayed without ` +
      "changing how it is parsed. Code containing these reads differently to a human than it " +
      "executes, which is an attack on review rather than a coding style.",
    severity: "MEDIUM",
    confidence: "HIGH",
    evidence: [
      {
        kind: "AST_NODE",
        description: `Control character U+${hex} in ${where}`,
        location: locationOf(node, ctx.filePath),
        value: `U+${hex}`,
      },
    ],
    metadata: { codePoint: `U+${hex}`, where },
  });
}

function findBidiCodePoint(value: string): number | undefined {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code !== undefined && BIDI_CONTROL_CODE_POINTS.has(code)) return code;
  }
  return undefined;
}

function findControlCodePoint(value: string): number | undefined {
  for (const character of value) {
    const code = character.codePointAt(0);
    if (code === undefined) continue;
    if (BIDI_CONTROL_CODE_POINTS.has(code) || INVISIBLE_CODE_POINTS.has(code))
      return code;
  }
  return undefined;
}
