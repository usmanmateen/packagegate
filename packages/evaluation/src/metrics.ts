import type { RiskRecommendation } from "@packagegate/shared";
import type {
  ConfusionMatrix,
  EvaluationLabel,
  EvaluationSampleResult,
  MissReasonCode,
} from "./types.js";

/** REVIEW or BLOCK counts as an intervention-positive outcome. */
export function isInterventionPositive(action: RiskRecommendation): boolean {
  return action === "REVIEW" || action === "BLOCK";
}

/**
 * Classify one completed labelled sample into a confusion-matrix cell.
 * SKIPPED/FAILED/UNKNOWN samples return null (not counted).
 */
export function classifyOutcome(
  label: EvaluationLabel,
  finalAction: RiskRecommendation,
): "TP" | "TN" | "FP" | "FN" | null {
  if (label === "UNKNOWN") return null;
  const positive = isInterventionPositive(finalAction);

  if (label === "MALICIOUS" || label === "SYNTHETIC_SUSPICIOUS") {
    return positive ? "TP" : "FN";
  }
  if (label === "EXPECTED_BENIGN") {
    return positive ? "FP" : "TN";
  }
  return null;
}

export function buildConfusionMatrix(
  results: readonly EvaluationSampleResult[],
): ConfusionMatrix {
  let tp = 0;
  let tn = 0;
  let fp = 0;
  let fn = 0;

  for (const result of results) {
    if (result.status !== "COMPLETED" || result.finalAction === undefined) continue;
    const cell = classifyOutcome(result.label, result.finalAction);
    if (cell === "TP") tp += 1;
    else if (cell === "TN") tn += 1;
    else if (cell === "FP") fp += 1;
    else if (cell === "FN") fn += 1;
  }

  const sampleCount = tp + tn + fp + fn;
  const precision = tp + fp === 0 ? null : tp / (tp + fp);
  const recall = tp + fn === 0 ? null : tp / (tp + fn);
  const falsePositiveRate = fp + tn === 0 ? null : fp / (fp + tn);
  const falseNegativeRate = fn + tp === 0 ? null : fn / (fn + tp);

  return {
    tp,
    tn,
    fp,
    fn,
    sampleCount,
    precision,
    recall,
    falsePositiveRate,
    falseNegativeRate,
  };
}

export function tallyMissReasons(
  results: readonly EvaluationSampleResult[],
): Partial<Record<MissReasonCode, number>> {
  const counts: Partial<Record<MissReasonCode, number>> = {};
  for (const result of results) {
    if (result.status !== "COMPLETED") continue;
    if (result.finalAction === undefined) continue;
    if (classifyOutcome(result.label, result.finalAction) !== "FN") continue;
    const reason = result.missReason ?? "UNKNOWN";
    counts[reason] = (counts[reason] ?? 0) + 1;
  }
  return counts;
}
