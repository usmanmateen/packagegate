import { z } from "zod";
import { ConfidenceSchema, SourceLocationSchema } from "./primitives.js";

/**
 * Behaviour chains are PackageGate's flagship signal and the easiest thing to
 * get dishonestly wrong. A chain asserts that data flows from a *source*,
 * through zero or more *transformations*, into a *sink*.
 *
 * The rule that matters: a chain is never emitted because a source and a sink
 * both happen to appear in the same package, or even the same file. There must
 * be a demonstrable relationship, recorded in {@link ChainLink.kind}, that a
 * reviewer can check against the cited lines.
 *
 * This is conservative relationship inference over bindings and argument
 * positions. It is deliberately NOT whole-program taint analysis, and must
 * never be described as such.
 */

/** Where interesting data originates. */
export const CHAIN_SOURCES = [
  "ENVIRONMENT_ACCESS",
  "SENSITIVE_FILE_READ",
  "FILESYSTEM_READ",
  "SYSTEM_INFORMATION",
  "ENCODED_CONSTANT",
  "REMOTE_DOWNLOAD",
  "PROCESS_OUTPUT",
] as const;
export const ChainSourceSchema = z.enum(CHAIN_SOURCES);
export type ChainSource = z.infer<typeof ChainSourceSchema>;

/** What happens to the data on the way to the sink. */
export const CHAIN_TRANSFORMATIONS = [
  "OBJECT_COLLECTION",
  "JSON_SERIALIZATION",
  "STRING_CONCATENATION",
  "BASE64_ENCODE",
  "BASE64_DECODE",
  "HEX_ENCODE",
  "HEX_DECODE",
  "COMPRESSION",
  "ENCRYPTION",
  "HASHING",
  "TEMPLATE_INTERPOLATION",
] as const;
export const ChainTransformationSchema = z.enum(CHAIN_TRANSFORMATIONS);
export type ChainTransformation = z.infer<typeof ChainTransformationSchema>;

/** Where the data ends up. Sinks are what make a source interesting. */
export const CHAIN_SINKS = [
  "NETWORK_REQUEST",
  "SOCKET_WRITE",
  "FILESYSTEM_WRITE",
  "EXECUTABLE_WRITE",
  "PROCESS_EXECUTION",
  "DYNAMIC_EVALUATION",
] as const;
export const ChainSinkSchema = z.enum(CHAIN_SINKS);
export type ChainSink = z.infer<typeof ChainSinkSchema>;

/**
 * How two steps in a chain were connected. This is the honesty mechanism: the
 * reviewer can see exactly what inference was made, and the risk engine can
 * weight weak linkages lower.
 */
export const CHAIN_LINK_KINDS = [
  /** The same resolved binding is written at one step and read at the next. */
  "SHARED_BINDING",
  /** The value of one step appears directly as an argument to the next. */
  "ARGUMENT_FLOW",
  /** The next step reads a property of the previous step's value. */
  "PROPERTY_ACCESS",
  /** The previous step's return value is awaited/assigned then used. */
  "RETURN_VALUE",
  /** Steps occur in the same function with no proven dataflow between them. */
  "SEQUENTIAL_IN_SCOPE",
] as const;
export const ChainLinkKindSchema = z.enum(CHAIN_LINK_KINDS);
export type ChainLinkKind = z.infer<typeof ChainLinkKindSchema>;

/**
 * `SEQUENTIAL_IN_SCOPE` is the weakest linkage and proves only proximity.
 * A chain relying on it can never exceed LOW confidence, enforced by
 * {@link maxConfidenceForLinks}.
 */
export const WEAK_LINK_KINDS: readonly ChainLinkKind[] = ["SEQUENTIAL_IN_SCOPE"];

export const ChainLinkSchema = z.object({
  kind: ChainLinkKindSchema,
  /** The binding or expression that carries the relationship, if named. */
  via: z.string().optional(),
  /** Statement a reviewer can verify against the cited location. */
  description: z.string().min(1),
  location: SourceLocationSchema,
});
export type ChainLink = z.infer<typeof ChainLinkSchema>;

export const BehaviourChainSchema = z.object({
  id: z.string().min(1),
  source: ChainSourceSchema,
  transformations: z.array(ChainTransformationSchema),
  sink: ChainSinkSchema,
  confidence: ConfidenceSchema,
  /** Every link that justifies this chain. Must be non-empty. */
  links: z.array(ChainLinkSchema).min(1),
  /** Findings that constitute the steps. Must be non-empty. */
  supportingFindingIds: z.array(z.string().min(1)).min(1),
  /** Files touched by the chain, package-relative. */
  filePaths: z.array(z.string().min(1)).min(1),
  /** Plain-language explanation for an analyst. No verdict language. */
  rationale: z.string().min(1),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type BehaviourChain = z.infer<typeof BehaviourChainSchema>;

/**
 * Ceiling on chain confidence given its weakest link. A chain is only as
 * trustworthy as the loosest inference holding it together.
 */
export function maxConfidenceForLinks(
  links: readonly Pick<ChainLink, "kind">[],
): "LOW" | "MEDIUM" | "HIGH" {
  if (links.length === 0) return "LOW";
  if (links.some((link) => WEAK_LINK_KINDS.includes(link.kind))) return "LOW";
  const allStrong = links.every(
    (link) => link.kind === "SHARED_BINDING" || link.kind === "ARGUMENT_FLOW",
  );
  return allStrong ? "HIGH" : "MEDIUM";
}
