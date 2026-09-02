import { MODIFIER_CEILING, MODIFIER_FLOOR, MODIFIER_VALUES } from "./weights.js";
import { clampModifiers } from "./saturation.js";
import type { IntelligenceTier } from "./types.js";

export interface ModifierResult {
  readonly total: number;
  readonly entries: readonly { id: string; value: number; rationale: string }[];
}

/**
 * Stage 5 — negative evidence modifiers (§4.8).
 *
 * MVP implements M1 only; additional modifiers are reserved for future inputs.
 */
export function computeModifiers(args: {
  integrityVerified?: boolean;
  intelligenceTier?: IntelligenceTier[];
  knownMalware?: boolean;
  maxChainConfidence: number;
}): ModifierResult {
  const entries: { id: string; value: number; rationale: string }[] = [];

  const laneIBlock =
    args.knownMalware === true ||
    args.intelligenceTier?.includes("AUTHORITATIVE_MALWARE") === true ||
    args.intelligenceTier?.includes("CORROBORATED_MALWARE") === true;

  const highConfidenceChain = args.maxChainConfidence >= 0.8;

  if (laneIBlock || highConfidenceChain) {
    return { total: 0, entries };
  }

  if (args.integrityVerified === true) {
    entries.push({
      id: "M1",
      value: MODIFIER_VALUES.M1,
      rationale:
        "Downloaded artefact integrity was verified before use, reducing dropper-shaped risk.",
    });
  }

  const total = clampModifiers(
    entries.reduce((sum, entry) => sum + entry.value, 0),
    MODIFIER_FLOOR,
    MODIFIER_CEILING,
  );

  return { total, entries };
}
