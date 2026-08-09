import * as t from "@babel/types";
import type { Severity } from "@packagegate/shared";
import { sanitiseInlineValue } from "@packagegate/shared";
import { CIPHER_MEMBERS, CRYPTO_MODULE, DECODE_GLOBALS } from "./catalogue.js";
import {
  argumentPaths,
  calleePath,
  effectiveMember,
  staticStringValue,
} from "./helpers.js";
import {
  confidenceFor,
  emitAt,
  locationOf,
  type Rule,
  type RuleContext,
} from "./types.js";

/**
 * Encoded payloads and high-entropy literals.
 *
 * Both are weak signals held deliberately weak. Base64 is how JavaScript ships
 * binary data, and a long random-looking string is as likely to be an embedded
 * font, a WASM module, a test fixture or a certificate as anything else.
 *
 * `docs/RISK_MODEL.md` §6.5 is explicit about the principle: obfuscation
 * attacks the *denominator*. Its correct effect is reduced coverage and reduced
 * confidence, not increased severity. Points are earned only by the narrower
 * claim — encoded content that is then *executed* — and that claim is made in
 * `dynamic-execution.ts`, where the execution is actually visible.
 */

const RULE_PREFIX = "js/encoding";

/** Minimum literal length before entropy is worth measuring at all. */
const ENTROPY_MIN_LENGTH = 96;

/**
 * Bits per character above which a string is "random-looking". Base64 of
 * compressed data lands around 5.5–6.0; English prose sits near 4.0; source
 * code and long identifiers sit lower still.
 */
const ENTROPY_THRESHOLD = 5.0;

/** Shannon entropy in bits per character. */
export function shannonEntropy(value: string): number {
  if (value.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

/**
 * Does this literal look like a base64 or hex blob? Checked on the character
 * set rather than by decoding — decoding attacker-controlled data would be
 * pointless work and the character set is the discriminating property anyway.
 */
function encodingShape(value: string): "base64" | "hex" | undefined {
  let base64Chars = 0;
  let hexChars = 0;
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    const isDigit = code >= 0x30 && code <= 0x39;
    const isUpper = code >= 0x41 && code <= 0x5a;
    const isLower = code >= 0x61 && code <= 0x7a;
    const isBase64Extra =
      code === 0x2b || code === 0x2f || code === 0x3d || code === 0x2d || code === 0x5f;
    if (isDigit || isUpper || isLower || isBase64Extra) base64Chars += 1;
    if (isDigit || (code >= 0x41 && code <= 0x46) || (code >= 0x61 && code <= 0x66)) {
      hexChars += 1;
    }
  }
  if (hexChars === value.length && value.length % 2 === 0) return "hex";
  if (base64Chars / value.length > 0.98) return "base64";
  return undefined;
}

export const encodedPayloadRule: Rule = {
  id: RULE_PREFIX,
  visitors: {
    CallExpression(path, ctx) {
      const target = ctx.resolver.resolve(calleePath(path), ctx.limits);
      if (target === undefined) return;
      const member = effectiveMember(target);

      // `Buffer.from(x, "base64")` / `Buffer.from(x, "hex")`.
      if (target.kind === "global" && target.module === "Buffer" && member === "from") {
        const second = argumentPaths(path)[1]?.node;
        const encoding = second === undefined ? undefined : staticStringValue(second);
        if (encoding === undefined) return;
        const lowered = encoding.toLowerCase();
        if (lowered !== "base64" && lowered !== "hex" && lowered !== "base64url") return;
        emitDecode(path.node, ctx, `Buffer.from(…, "${lowered}")`, lowered);
        return;
      }

      // `atob(…)`, and `unescape(…)` in the classic `unescape(escape(atob(x)))`
      // shape used to smuggle non-ASCII through base64.
      if (
        target.kind === "global" &&
        member === undefined &&
        DECODE_GLOBALS.has(target.module)
      ) {
        emitDecode(path.node, ctx, target.module, "base64");
        return;
      }

      // `String.fromCharCode(…)` with many numeric arguments is character-code
      // assembly of a string that the source deliberately does not spell out.
      if (
        target.kind === "global" &&
        target.module === "String" &&
        member === "fromCharCode"
      ) {
        const args = path.node.arguments;
        if (args.length < 8) return;
        if (!args.every((argument) => t.isNumericLiteral(argument))) return;
        emitDecode(path.node, ctx, "String.fromCharCode", "char-codes");
        return;
      }

      // `x.toString("base64")`/`Buffer#toString("hex")` is encoding, not
      // decoding; recorded at the lowest severity because it is how binary data
      // is transported everywhere.
      if (
        target.kind === "module" &&
        target.module === CRYPTO_MODULE &&
        member !== undefined &&
        CIPHER_MEMBERS.has(member)
      ) {
        emitAt(ctx, path.node, {
          ruleId: `${RULE_PREFIX}/cipher`,
          category: "CRYPTOGRAPHIC_OPERATION",
          title: `Cryptographic operation via crypto.${member}`,
          description:
            "The package encrypts or decrypts data. Recorded as inventory; encryption before " +
            "an outbound request is more interesting than encryption on its own.",
          severity: "INFO",
          confidence: confidenceFor(target),
          evidence: [
            {
              kind: "AST_NODE",
              description: `Call to \`crypto.${member}\``,
              location: locationOf(path.node, ctx.filePath),
              value: member,
            },
          ],
          metadata: { module: target.module, member },
        });
      }
    },

    StringLiteral(path, ctx) {
      // Minified bundles legitimately contain large encoded blobs, and this
      // rule would fire on nearly every one of them. Skipping them keeps the
      // signal honest rather than manufacturing volume — consistent with
      // minification never being treated as evidence.
      if (ctx.minified) return;

      const value = path.node.value;
      if (value.length < ENTROPY_MIN_LENGTH) return;
      if (value.length > ctx.limits.maxLiteralScanLength) return;

      const shape = encodingShape(value);
      if (shape === undefined) return;

      const entropy = shannonEntropy(value);
      if (entropy < ENTROPY_THRESHOLD) return;

      emitAt(ctx, path.node, {
        ruleId: `${RULE_PREFIX}/high-entropy-literal`,
        category: "HIGH_ENTROPY_PAYLOAD",
        title: `High-entropy ${shape} literal (${String(value.length)} characters)`,
        description:
          "A long, random-looking literal appears in the source. Embedded WASM, fonts, " +
          "certificates, icons and test fixtures all look exactly like this, so on its own " +
          "this means very little; it matters only if the value is later decoded and run.",
        severity: "LOW",
        // A measurement, not a resolution. We are certain about the entropy and
        // uncertain about what the data is, which is what MEDIUM records.
        confidence: "MEDIUM",
        evidence: [
          {
            kind: "MEASUREMENT",
            description: `Shannon entropy ${entropy.toFixed(2)} bits/char over ${String(value.length)} characters`,
            location: locationOf(path.node, ctx.filePath),
            value: sanitiseInlineValue(value.slice(0, 64), 64),
          },
        ],
        metadata: { entropy: Number(entropy.toFixed(3)), length: value.length, shape },
      });
    },
  },
};

function emitDecode(node: t.Node, ctx: RuleContext, via: string, encoding: string): void {
  const severity: Severity = "LOW";
  emitAt(ctx, node, {
    ruleId: `${RULE_PREFIX}/decode`,
    category: "ENCODED_PAYLOAD",
    title: `Encoded data decoded via ${via}`,
    description:
      `The package decodes ${encoding} data using \`${via}\`. Decoding is ubiquitous and ` +
      "means nothing by itself; it is recorded so that a decode feeding an execution sink " +
      "or an outbound request can be recognised.",
    severity,
    confidence: "HIGH",
    evidence: [
      {
        kind: "AST_NODE",
        description: `Decode via \`${via}\``,
        location: locationOf(node, ctx.filePath),
        value: via,
      },
    ],
    metadata: { via, encoding },
  });
}
