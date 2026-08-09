import type { RiskRecommendation } from "@packagegate/shared";

export const EVALUATION_LABELS = [
  "EXPECTED_BENIGN",
  "MALICIOUS",
  "SYNTHETIC_SUSPICIOUS",
  "UNKNOWN",
] as const;
export type EvaluationLabel = (typeof EVALUATION_LABELS)[number];

export const MISS_REASON_CODES = [
  "SHELL_SEMANTICS_GAP",
  "LIFECYCLE_REACHABILITY_GAP",
  "SOURCE_DETECTION_GAP",
  "DATAFLOW_GAP",
  "CROSS_FILE_GAP",
  "FILE_BUDGET_GAP",
  "OPAQUE_PAYLOAD",
  "PARSER_FAILURE",
  "UNSUPPORTED_RUNTIME",
  "NATIVE_PAYLOAD",
  "THREAT_INTEL_ONLY",
  "UNKNOWN",
] as const;
export type MissReasonCode = (typeof MISS_REASON_CODES)[number];

export type SampleSourceKind = "REGISTRY" | "FIXTURE" | "LOCAL_TGZ";

export interface EvaluationSample {
  readonly id: string;
  readonly label: EvaluationLabel;
  readonly kind: SampleSourceKind;
  /** Registry/fixture spec or relative path under malware-root. */
  readonly artifact: string;
  readonly notes?: string;
  /** If true, sample requires --malware-root and is never auto-downloaded. */
  readonly requiresMalwareRoot?: boolean;
}

export interface EvaluationManifest {
  readonly version: number;
  readonly samples: readonly EvaluationSample[];
}

export interface EvaluationSampleResult {
  readonly id: string;
  readonly label: EvaluationLabel;
  readonly status: "COMPLETED" | "SKIPPED" | "FAILED";
  readonly skipReason?: string;
  readonly failureReason?: string;
  readonly behaviouralScore?: number;
  readonly behaviouralRecommendation?: RiskRecommendation;
  readonly finalAction?: RiskRecommendation;
  readonly completeness?: string;
  readonly findingCount?: number;
  readonly chainCount?: number;
  readonly durationMs?: number;
  readonly missReason?: MissReasonCode;
  /** Intervention-positive means REVIEW or BLOCK. */
  readonly interventionPositive?: boolean;
}

export interface ConfusionMatrix {
  readonly tp: number;
  readonly tn: number;
  readonly fp: number;
  readonly fn: number;
  readonly sampleCount: number;
  readonly precision: number | null;
  readonly recall: number | null;
  readonly falsePositiveRate: number | null;
  readonly falseNegativeRate: number | null;
}

export interface EvaluationReport {
  readonly results: readonly EvaluationSampleResult[];
  readonly matrix: ConfusionMatrix;
  readonly missReasons: Readonly<Partial<Record<MissReasonCode, number>>>;
  readonly disclaimer: string;
}
