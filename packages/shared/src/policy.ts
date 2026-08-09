import { z } from "zod";
import { AnalysisCompletenessStatusSchema } from "./completeness.js";
import { RiskRecommendationSchema } from "./risk.js";

/**
 * Final operational action is a separate lane from behavioural risk.
 *
 * Behavioural recommendation answers "how much attention do the observed
 * behaviours deserve?". Final policy may escalate for incomplete visibility or
 * trusted threat intelligence without rewriting the behavioural score.
 */

export const THREAT_INTELLIGENCE_STATUSES = [
  "NONE",
  "KNOWN_MALICIOUS",
  "KNOWN_VULNERABLE",
  "UNKNOWN",
] as const;
export const ThreatIntelligenceStatusSchema = z.enum(THREAT_INTELLIGENCE_STATUSES);
export type ThreatIntelligenceStatus = z.infer<typeof ThreatIntelligenceStatusSchema>;

export const FinalActionSchema = RiskRecommendationSchema;
export type FinalAction = z.infer<typeof FinalActionSchema>;

export const POLICY_REASON_CODES = [
  "BEHAVIOURAL_ALLOW",
  "BEHAVIOURAL_REVIEW",
  "BEHAVIOURAL_BLOCK",
  "DEGRADED_EXECUTABLE_ANALYSIS",
  "INSUFFICIENT_ANALYSIS",
  "KNOWN_MALICIOUS_INTELLIGENCE",
  "KNOWN_VULNERABILITY_CONTEXT",
] as const;
export const PolicyReasonCodeSchema = z.enum(POLICY_REASON_CODES);
export type PolicyReasonCode = z.infer<typeof PolicyReasonCodeSchema>;

export const PolicyReasonSchema = z.object({
  code: PolicyReasonCodeSchema,
  message: z.string().min(1),
});
export type PolicyReason = z.infer<typeof PolicyReasonSchema>;

export const PolicyDecisionSchema = z.object({
  behaviouralRecommendation: RiskRecommendationSchema,
  analysisCompleteness: AnalysisCompletenessStatusSchema,
  threatIntelligence: ThreatIntelligenceStatusSchema,
  finalAction: FinalActionSchema,
  reasons: z.array(PolicyReasonSchema).min(1),
});
export type PolicyDecision = z.infer<typeof PolicyDecisionSchema>;
