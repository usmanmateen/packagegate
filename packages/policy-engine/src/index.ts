import type {
  AnalysisCompleteness,
  AnalysisCompletenessStatus,
  PolicyDecision,
  PolicyReason,
  RiskRecommendation,
  ThreatIntelligenceStatus,
} from "@packagegate/shared";

export const POLICY_ENGINE_VERSION = "policy-engine/1.0.0";

export interface PolicyEngineInput {
  readonly behaviouralRecommendation: RiskRecommendation;
  readonly analysisCompleteness: AnalysisCompleteness;
  readonly threatIntelligence?: ThreatIntelligenceStatus;
}

/**
 * Deterministic policy combining behavioural risk, analysis completeness, and
 * threat intelligence — without mutating the behavioural score.
 */
export function decidePolicy(input: PolicyEngineInput): PolicyDecision {
  const threat = input.threatIntelligence ?? "NONE";
  const reasons: PolicyReason[] = [];

  if (threat === "KNOWN_MALICIOUS") {
    reasons.push({
      code: "KNOWN_MALICIOUS_INTELLIGENCE",
      message:
        "Trusted threat intelligence reports an exact malicious match for this package version.",
    });
    return {
      behaviouralRecommendation: input.behaviouralRecommendation,
      analysisCompleteness: input.analysisCompleteness.status,
      threatIntelligence: threat,
      finalAction: "BLOCK",
      reasons,
    };
  }

  if (threat === "KNOWN_VULNERABLE") {
    reasons.push({
      code: "KNOWN_VULNERABILITY_CONTEXT",
      message:
        "Vulnerability intelligence is present for context only and does not alone imply malware.",
    });
  }

  const behaviouralCode =
    input.behaviouralRecommendation === "ALLOW"
      ? "BEHAVIOURAL_ALLOW"
      : input.behaviouralRecommendation === "REVIEW"
        ? "BEHAVIOURAL_REVIEW"
        : "BEHAVIOURAL_BLOCK";
  reasons.push({
    code: behaviouralCode,
    message: `Behavioural recommendation is ${input.behaviouralRecommendation}.`,
  });

  let finalAction: RiskRecommendation = input.behaviouralRecommendation;

  if (input.behaviouralRecommendation === "BLOCK") {
    return {
      behaviouralRecommendation: input.behaviouralRecommendation,
      analysisCompleteness: input.analysisCompleteness.status,
      threatIntelligence: threat,
      finalAction: "BLOCK",
      reasons,
    };
  }

  if (input.analysisCompleteness.status === "INSUFFICIENT") {
    reasons.push({
      code: "INSUFFICIENT_ANALYSIS",
      message:
        "Static analysis coverage was insufficient to support an ALLOW decision.",
    });
    finalAction = escalate(finalAction, "REVIEW");
  } else if (
    input.analysisCompleteness.status === "DEGRADED" &&
    hasSecurityRelevantGap(input.analysisCompleteness)
  ) {
    reasons.push({
      code: "DEGRADED_EXECUTABLE_ANALYSIS",
      message:
        "Security-relevant executable source was not fully analysed; behavioural score does not include unseen behaviour.",
    });
    if (input.behaviouralRecommendation === "ALLOW") {
      finalAction = "REVIEW";
    }
  }

  return {
    behaviouralRecommendation: input.behaviouralRecommendation,
    analysisCompleteness: input.analysisCompleteness.status,
    threatIntelligence: threat,
    finalAction,
    reasons,
  };
}

function escalate(
  current: RiskRecommendation,
  floor: RiskRecommendation,
): RiskRecommendation {
  const order = { ALLOW: 0, REVIEW: 1, BLOCK: 2 } as const;
  return order[current] >= order[floor] ? current : floor;
}

/**
 * Gaps that matter for policy: skipped/unparsed executable JS/TS, especially
 * when lifecycle-reachable or opaque. README parse failures do not qualify.
 */
export function hasSecurityRelevantGap(
  completeness: AnalysisCompleteness,
): boolean {
  return completeness.reasons.some((reason) => {
    if (reason.executableSource === true) return true;
    if (reason.lifecycleReachable === true && reason.executableSource !== false) {
      return true;
    }
    return (
      reason.code === "SOURCE_CONTENT_LIMIT_EXCEEDED" ||
      reason.code === "OPAQUE_PAYLOAD" ||
      reason.code === "CONTENT_LIMIT_EXCEEDED" ||
      reason.code === "ANALYSIS_BUDGET_EXHAUSTED"
    );
  });
}

export function statusLabel(status: AnalysisCompletenessStatus): string {
  return status;
}
