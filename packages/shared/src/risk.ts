import { z } from "zod";

/**
 * The deterministic risk model.
 *
 * Hard constraints, enforced structurally rather than by convention:
 *
 *  - The score is computed by code, never by a language model.
 *  - Every point in the final score traces to exactly one
 *    {@link RiskContribution}, and the contributions must sum to the score.
 *  - Known intelligence (advisories, malware records) is carried in its own
 *    contribution kind so it never dissolves into the heuristic total. An
 *    analyst can always see whether a score came from "GitHub says this is
 *    malware" or "our heuristics are suspicious".
 */

export const RISK_RECOMMENDATIONS = ["ALLOW", "REVIEW", "BLOCK"] as const;
export const RiskRecommendationSchema = z.enum(RISK_RECOMMENDATIONS);
export type RiskRecommendation = z.infer<typeof RiskRecommendationSchema>;

export const RISK_CLASSIFICATIONS = [
  "KNOWN_MALWARE",
  "HIGH_RISK_BEHAVIOUR",
  "SUSPICIOUS",
  "LOW_RISK",
  "INSUFFICIENT_EVIDENCE",
] as const;
export const RiskClassificationSchema = z.enum(RISK_CLASSIFICATIONS);
export type RiskClassification = z.infer<typeof RiskClassificationSchema>;

/**
 * What produced a contribution. The distinction is not cosmetic: it is how the
 * product keeps authoritative intelligence separate from heuristic suspicion.
 */
export const CONTRIBUTION_KINDS = [
  /** An individual finding. Deliberately low value on its own. */
  "FINDING",
  /** An evidence-backed behaviour chain. Worth more than its parts. */
  "BEHAVIOUR_CHAIN",
  /** An authoritative advisory or malware record from a named feed. */
  "KNOWN_INTELLIGENCE",
  /** A security-relevant change against the previous published version. */
  "VERSION_DELTA",
  /** A negative adjustment, e.g. saturation of repetitive low-value findings. */
  "ADJUSTMENT",
] as const;
export const ContributionKindSchema = z.enum(CONTRIBUTION_KINDS);
export type ContributionKind = z.infer<typeof ContributionKindSchema>;

export const RiskContributionSchema = z.object({
  id: z.string().min(1),
  kind: ContributionKindSchema,
  /** Short label as shown in the score breakdown, e.g. "Environment → network chain". */
  label: z.string().min(1),
  /** Signed points. Negative values are adjustments such as saturation. */
  points: z.number(),
  /** One sentence a sceptical security engineer would accept. */
  rationale: z.string().min(1),
  findingIds: z.array(z.string()).default([]),
  chainIds: z.array(z.string()).default([]),
  /** Named source for KNOWN_INTELLIGENCE contributions, e.g. "GitHub Advisories". */
  intelligenceSource: z.string().optional(),
});
export type RiskContribution = z.infer<typeof RiskContributionSchema>;

export const RiskAssessmentSchema = z
  .object({
    /** Clamped 0–100 after summing contributions. */
    score: z.number().min(0).max(100),
    recommendation: RiskRecommendationSchema,
    classification: RiskClassificationSchema,
    contributions: z.array(RiskContributionSchema),
    /**
     * Raw sum before clamping to 0–100. Retained so a 100 score does not hide
     * how far past the ceiling the evidence went.
     */
    rawTotal: z.number(),
    /**
     * True when authoritative intelligence identified this exact
     * package@version as malicious. Never inferred from heuristics.
     */
    knownMalware: z.boolean(),
    /** Versions of the code and rules that produced this score, for reproducibility. */
    scannerVersion: z.string().min(1),
    rulesVersion: z.string().min(1),
    computedAt: z.string().datetime(),
  })
  .refine(
    (assessment) => assessment.classification !== "KNOWN_MALWARE" || assessment.knownMalware,
    {
      message:
        "KNOWN_MALWARE classification requires knownMalware=true from an authoritative feed; heuristics alone must never produce it",
      path: ["classification"],
    },
  );
export type RiskAssessment = z.infer<typeof RiskAssessmentSchema>;

/**
 * Verify that a breakdown actually explains its score. Used in tests and as a
 * runtime assertion in the engine — a breakdown that does not reconcile is a
 * bug, and shipping one would make the whole "explainable" claim false.
 */
export function contributionsReconcile(
  contributions: readonly Pick<RiskContribution, "points">[],
  rawTotal: number,
): boolean {
  const sum = contributions.reduce((total, contribution) => total + contribution.points, 0);
  return Math.abs(sum - rawTotal) < 1e-9;
}

/** Clamp a raw total into the reportable 0–100 range. */
export function clampScore(rawTotal: number): number {
  if (Number.isNaN(rawTotal)) return 0;
  return Math.max(0, Math.min(100, Math.round(rawTotal)));
}
