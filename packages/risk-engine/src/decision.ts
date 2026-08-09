import type { RiskClassification, RiskRecommendation } from "@packagegate/shared";
import { COVERAGE_FLOOR } from "./weights.js";
import type { IntelligenceTier } from "./types.js";

export interface DecisionResult {
  readonly recommendation: RiskRecommendation;
  readonly classification: RiskClassification;
}

/**
 * Decision function from `docs/RISK_MODEL.md` §8.
 */
export function decideVerdict(args: {
  score: number;
  knownMalware?: boolean;
  intelligenceTier?: IntelligenceTier[];
  analysisCoverage: number;
  evidencedChainCount: number;
  maxChainConfidence: number;
}): DecisionResult {
  const laneI =
    args.knownMalware === true ||
    args.intelligenceTier?.includes("AUTHORITATIVE_MALWARE") === true ||
    args.intelligenceTier?.includes("CORROBORATED_MALWARE") === true;

  if (laneI) {
    return { recommendation: "BLOCK", classification: "KNOWN_MALWARE" };
  }

  if (args.analysisCoverage < COVERAGE_FLOOR) {
    return {
      recommendation: "REVIEW",
      classification: "INSUFFICIENT_EVIDENCE",
    };
  }

  if (
    args.score >= 90 &&
    args.evidencedChainCount >= 2 &&
    args.maxChainConfidence >= 0.8
  ) {
    return {
      recommendation: "BLOCK",
      classification: "HIGH_RISK_BEHAVIOUR",
    };
  }

  if (args.score >= 50) {
    return {
      recommendation: "REVIEW",
      classification: "HIGH_RISK_BEHAVIOUR",
    };
  }

  if (args.score >= 25) {
    return { recommendation: "REVIEW", classification: "SUSPICIOUS" };
  }

  return { recommendation: "ALLOW", classification: "LOW_RISK" };
}
