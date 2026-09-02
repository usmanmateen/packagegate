import type { RiskAssessment } from "@packagegate/shared";
import { contributionsReconcile } from "@packagegate/shared";
import { buildContributions } from "./contributions.js";
import { decideVerdict } from "./decision.js";
import { computeScoringBreakdown } from "./score.js";
import type { RiskEngineInput } from "./types.js";
import { ENGINE_VERSION } from "./weights.js";

const DEFAULT_SCANNER_VERSION = "static-analyser/0.1.0";
const DEFAULT_RULES_VERSION = "static-rules/0.1.0";

/**
 * Assess package risk deterministically from findings, chains and coverage.
 */
export function assessRisk(input: RiskEngineInput): RiskAssessment {
  const analysisCoverage = input.analysisCoverage ?? 1;
  const breakdown = computeScoringBreakdown(input);
  const contributions = buildContributions(input, breakdown);

  if (!contributionsReconcile(contributions, breakdown.rawTotal)) {
    throw new Error("Risk contributions do not reconcile to rawTotal — scoring bug");
  }

  const verdict = decideVerdict({
    score: breakdown.score,
    knownMalware: input.knownMalware,
    intelligenceTier: input.intelligenceTier,
    analysisCoverage,
    evidencedChainCount: breakdown.evidencedChainCount,
    maxChainConfidence: breakdown.maxChainConfidence,
  });

  const knownMalware =
    input.knownMalware === true ||
    input.intelligenceTier?.includes("AUTHORITATIVE_MALWARE") === true ||
    input.intelligenceTier?.includes("CORROBORATED_MALWARE") === true;

  return {
    score: breakdown.score,
    recommendation: verdict.recommendation,
    classification: verdict.classification,
    contributions,
    rawTotal: breakdown.rawTotal,
    knownMalware,
    scannerVersion: input.scannerVersion ?? DEFAULT_SCANNER_VERSION,
    rulesVersion: input.rulesVersion ?? DEFAULT_RULES_VERSION,
    computedAt: new Date().toISOString(),
  };
}

export { ENGINE_VERSION };
