/**
 * Optional ML assessment lane — separate from deterministic behavioural risk.
 *
 * ML ranks suspicious composition; it does not invent deterministic evidence
 * (URLs, dataflow edges, file paths) that PackageGate did not observe.
 */

import { z } from "zod";

export const ML_ASSESSMENT_STATUSES = [
  "DISABLED",
  "AVAILABLE",
  "ERROR",
] as const;
export const MlAssessmentStatusSchema = z.enum(ML_ASSESSMENT_STATUSES);
export type MlAssessmentStatus = z.infer<typeof MlAssessmentStatusSchema>;

export const MlPredictedBehaviourSchema = z.object({
  behaviour: z.string().min(1),
  probability: z.number().min(0).max(1),
});
export type MlPredictedBehaviour = z.infer<typeof MlPredictedBehaviourSchema>;

export const MlTopSliceSchema = z.object({
  file: z.string().min(1),
  startLine: z.number().int().min(1),
  endLine: z.number().int().min(1),
  score: z.number().min(0).max(1),
  predictedBehaviours: z.array(MlPredictedBehaviourSchema).default([]),
  deterministicEvidenceRefs: z.array(z.string()).default([]),
});
export type MlTopSlice = z.infer<typeof MlTopSliceSchema>;

export const MlInputCompletenessSchema = z.object({
  slicesAvailable: z.number().int().min(0),
  slicesUsed: z.number().int().min(0),
  truncationOccurred: z.boolean(),
});
export type MlInputCompleteness = z.infer<typeof MlInputCompletenessSchema>;

export const MlAssessmentSchema = z.object({
  status: MlAssessmentStatusSchema,
  modelId: z.string().optional(),
  modelVersion: z.string().optional(),
  featureSchemaVersion: z.number().int().positive().optional(),
  maliciousProbability: z.number().min(0).max(1).optional(),
  calibratedProbability: z.number().min(0).max(1).optional(),
  uncertainty: z.number().min(0).max(1).optional(),
  predictedBehaviours: z.array(MlPredictedBehaviourSchema).default([]),
  topSlices: z.array(MlTopSliceSchema).default([]),
  inputCompleteness: MlInputCompletenessSchema.optional(),
  supportsReviewEscalation: z.boolean().default(false),
  errorMessage: z.string().optional(),
});
export type MlAssessment = z.infer<typeof MlAssessmentSchema>;

export function disabledMlAssessment(): MlAssessment {
  return {
    status: "DISABLED",
    predictedBehaviours: [],
    topSlices: [],
    supportsReviewEscalation: false,
  };
}
