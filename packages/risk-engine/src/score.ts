import type { Finding } from "@packagegate/shared";
import { cooccurrenceRule, resolveChains } from "./chains.js";
import { perOccurrenceContribution } from "./factors.js";
import { mapFindingToRule } from "./map-finding.js";
import { computeModifiers } from "./modifiers.js";
import {
  applyStructuralCap,
  decayFactorForRank,
  saturateChains,
  saturateFamily,
  saturateRule,
} from "./saturation.js";
import type {
  FamilyBreakdownEntry,
  RiskEngineInput,
  RuleOccurrenceContribution,
  ScoringBreakdown,
} from "./types.js";
import {
  CHAIN_SATURATION_CAP,
  CROSS_FAMILY_DECAY,
  FAMILY_CAPS,
  type FamilyId,
  kappaForRule,
  type RuleWeight,
} from "./weights.js";

interface GroupedRuleFindings {
  readonly rule: RuleWeight;
  findings: Finding[];
}

/**
 * Compute the full behavioural score breakdown (Lane II).
 */
export function computeScoringBreakdown(input: RiskEngineInput): ScoringBreakdown {
  const chains = input.chains ?? [];
  const { evidenced, cooccurrenceFindingIds } = resolveChains(chains);

  const grouped = groupFindingsByRule(input.findings);

  if (cooccurrenceFindingIds.length > 0 && evidenced.length === 0) {
    const k1 = cooccurrenceRule();
    if (k1 !== undefined) {
      const syntheticFindings = input.findings.filter((finding) =>
        cooccurrenceFindingIds.includes(finding.id),
      );
      if (syntheticFindings.length > 0) {
        grouped.set(k1.id, { rule: k1, findings: syntheticFindings });
      }
    }
  }

  const ruleScores: RuleOccurrenceContribution[] = [];
  const familyRuleTotals = new Map<FamilyId, number>();

  for (const { rule, findings } of grouped.values()) {
    const contributions = findings.map((finding) =>
      perOccurrenceContribution(rule, finding),
    );
    const perOccurrenceTotal = rule.presence
      ? Math.max(0, ...contributions)
      : contributions.reduce((sum, value) => sum + value, 0);

    const saturated = saturateRule(perOccurrenceTotal, kappaForRule(rule));
    if (saturated <= 0) continue;

    ruleScores.push({
      ruleId: rule.id,
      family: rule.family,
      findingIds: findings.map((finding) => finding.id),
      perOccurrenceTotal,
      saturated,
    });

    familyRuleTotals.set(
      rule.family,
      (familyRuleTotals.get(rule.family) ?? 0) + saturated,
    );
  }

  const familyRawScores = new Map<FamilyId, number>();
  for (const [family, ruleTotal] of familyRuleTotals.entries()) {
    familyRawScores.set(family, saturateFamily(ruleTotal, FAMILY_CAPS[family]));
  }

  const sortedFamilies = [...familyRawScores.entries()].sort(
    (left, right) => right[1] - left[1],
  );

  const familyBreakdown: FamilyBreakdownEntry[] = sortedFamilies.map(
    ([family, rawFamilyScore], index) => {
      const decayRank = index + 1;
      const decayFactor = decayFactorForRank(decayRank, CROSS_FAMILY_DECAY);
      return {
        family,
        rawFamilyScore,
        decayRank,
        decayFactor,
        decayedPoints: rawFamilyScore * decayFactor,
        ruleScores: ruleScores.filter((entry) => entry.family === family),
      };
    },
  );

  const breadthRaw = familyBreakdown.reduce((sum, entry) => sum + entry.decayedPoints, 0);

  const chainRaw = evidenced.reduce((sum, entry) => sum + entry.rawContribution, 0);
  const evidencedChainCount = evidenced.length;
  const maxChainConfidence =
    evidenced.length === 0
      ? 0
      : Math.max(...evidenced.map((entry) => entry.confidenceNumeric));

  const chainSaturated = saturateChains(
    chainRaw,
    CHAIN_SATURATION_CAP,
    evidencedChainCount,
  );

  const modifiers = computeModifiers({
    integrityVerified: input.integrityVerified,
    intelligenceTier: input.intelligenceTier,
    knownMalware: input.knownMalware,
    maxChainConfidence,
  });

  const rawTotal = breadthRaw + chainSaturated + modifiers.total;
  const score = applyStructuralCap(rawTotal, evidencedChainCount);

  return {
    breadthRaw,
    chainRaw,
    chainSaturated,
    modifierTotal: modifiers.total,
    rawTotal,
    structuralCap: evidencedChainCount >= 2 ? 100 : evidencedChainCount === 1 ? 89 : 74,
    score,
    familyBreakdown,
    evidencedChainCount,
    maxChainConfidence,
  };
}

function groupFindingsByRule(
  findings: readonly Finding[],
): Map<string, GroupedRuleFindings> {
  const grouped = new Map<string, GroupedRuleFindings>();

  for (const finding of findings) {
    const rule = mapFindingToRule(finding);
    if (rule === null || rule.weight === 0) continue;

    const existing = grouped.get(rule.id);
    if (existing === undefined) {
      grouped.set(rule.id, { rule, findings: [finding] });
      continue;
    }
    existing.findings.push(finding);
  }

  return grouped;
}

/** Family-level points for CLI display. */
export function familyContributions(
  breakdown: ScoringBreakdown,
): readonly { family: string; points: number }[] {
  return breakdown.familyBreakdown.map((entry) => ({
    family: entry.family,
    points: entry.decayedPoints,
  }));
}
