import type { RiskContribution } from "@packagegate/shared";
import { cooccurrenceRule, resolveChains } from "./chains.js";
import { computeModifiers } from "./modifiers.js";
import type { RiskEngineInput, ScoringBreakdown } from "./types.js";
import { CHAIN_PATTERNS } from "./weights.js";

/**
 * Build explainable contributions that reconcile to rawTotal.
 */
export function buildContributions(
  input: RiskEngineInput,
  breakdown: ScoringBreakdown,
): RiskContribution[] {
  const contributions: RiskContribution[] = [];
  const chains = input.chains ?? [];
  const { evidenced } = resolveChains(chains);

  for (const family of breakdown.familyBreakdown) {
    if (family.decayedPoints <= 0) continue;
    const findingIds = family.ruleScores.flatMap((rule) => [...rule.findingIds]);
    contributions.push({
      id: `family:${family.family}`,
      kind: "FINDING",
      label: `Family ${family.family} behavioural breadth`,
      points: family.decayedPoints,
      rationale:
        `Family ${family.family} saturated to ${family.rawFamilyScore.toFixed(2)} ` +
        `points with cross-family decay rank ${String(family.decayRank)}.`,
      findingIds,
      chainIds: [],
    });
  }

  if (breakdown.chainSaturated > 0) {
    const chainIds = evidenced.map((entry) => entry.chain.id);
    const patternLabels = [
      ...new Set(evidenced.map((entry) => entry.patternId)),
    ]
      .map((id) => CHAIN_PATTERNS[id]?.label ?? id)
      .join("; ");

    contributions.push({
      id: "chains:saturated",
      kind: "BEHAVIOUR_CHAIN",
      label: "Evidence-backed behaviour chains",
      points: breakdown.chainSaturated,
      rationale:
        `${String(evidenced.length)} evidenced chain(s) saturated: ${patternLabels}.`,
      findingIds: [],
      chainIds,
    });
  }

  const modifiers = computeModifiers({
    integrityVerified: input.integrityVerified,
    intelligenceTier: input.intelligenceTier,
    knownMalware: input.knownMalware,
    maxChainConfidence: breakdown.maxChainConfidence,
  });

  for (const modifier of modifiers.entries) {
    contributions.push({
      id: `modifier:${modifier.id}`,
      kind: "ADJUSTMENT",
      label: `${modifier.id} modifier`,
      points: modifier.value,
      rationale: modifier.rationale,
      findingIds: [],
      chainIds: [],
    });
  }

  if (
    input.knownMalware === true ||
    input.intelligenceTier?.includes("AUTHORITATIVE_MALWARE") === true ||
    input.intelligenceTier?.includes("CORROBORATED_MALWARE") === true
  ) {
    contributions.push({
      id: "intelligence:known-malware",
      kind: "KNOWN_INTELLIGENCE",
      label: "Authoritative malware intelligence",
      points: 0,
      rationale:
        "Known malware intelligence forces BLOCK independently of the behavioural score.",
      findingIds: [],
      chainIds: [],
      intelligenceSource: "Lane I intelligence feed",
    });
  }

  const k1 = cooccurrenceRule();
  if (
    k1 !== undefined &&
    breakdown.familyBreakdown.some(
      (entry) => entry.family === "K" && entry.decayedPoints > 0,
    )
  ) {
    const existing = contributions.find((entry) => entry.id === "family:K");
    if (existing !== undefined) {
      existing.rationale =
        "Co-occurrence without evidenced dataflow (family K); cannot unlock BLOCK.";
    }
  }

  return contributions;
}
