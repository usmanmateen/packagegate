import { z } from "zod";

/**
 * How complete the static investigation was — a visibility lane, not a
 * maliciousness signal. Incomplete analysis must never be scored as behaviour.
 */

export const ANALYSIS_COMPLETENESS_STATUSES = [
  "COMPLETE",
  "DEGRADED",
  "INSUFFICIENT",
] as const;
export const AnalysisCompletenessStatusSchema = z.enum(ANALYSIS_COMPLETENESS_STATUSES);
export type AnalysisCompletenessStatus = z.infer<
  typeof AnalysisCompletenessStatusSchema
>;

export const ANALYSIS_COMPLETENESS_REASON_CODES = [
  "SOURCE_CONTENT_LIMIT_EXCEEDED",
  "CONTENT_LIMIT_EXCEEDED",
  "UNPARSED_SOURCE",
  "UNSUPPORTED_LANGUAGE",
  "UNSUPPORTED_RUNTIME",
  "PARSER_FAILURE",
  "DYNAMIC_MODULE_TARGET",
  "OPAQUE_PAYLOAD",
  "ANALYSIS_BUDGET_EXHAUSTED",
] as const;
export const AnalysisCompletenessReasonCodeSchema = z.enum(
  ANALYSIS_COMPLETENESS_REASON_CODES,
);
export type AnalysisCompletenessReasonCode = z.infer<
  typeof AnalysisCompletenessReasonCodeSchema
>;

export const AnalysisCompletenessReasonSchema = z.object({
  code: AnalysisCompletenessReasonCodeSchema,
  path: z.string().min(1).optional(),
  message: z.string().min(1),
  sizeBytes: z.number().int().min(0).optional(),
  retainedBytes: z.number().int().min(0).optional(),
  /** True when a lifecycle script statically references this path. */
  lifecycleReachable: z.boolean().optional(),
  /** True when the path looks like executable JS/TS source. */
  executableSource: z.boolean().optional(),
  metadata: z.record(z.string(), z.unknown()).default({}),
});
export type AnalysisCompletenessReason = z.infer<
  typeof AnalysisCompletenessReasonSchema
>;

export const AnalysisCompletenessSchema = z.object({
  status: AnalysisCompletenessStatusSchema,
  reasons: z.array(AnalysisCompletenessReasonSchema).default([]),
  /**
   * Fraction of analysable executable source files fully AST-analysed.
   * Kept for backwards compatibility with the risk coverage floor.
   */
  coverageRatio: z.number().min(0).max(1),
});
export type AnalysisCompleteness = z.infer<typeof AnalysisCompletenessSchema>;
