import type { Confidence, Finding } from "@packagegate/shared";
import {
  CONFIDENCE_HARD_GATE,
  CONFIDENCE_NUMERIC,
  type RuleWeight,
} from "./weights.js";

/**
 * Map shared confidence enum to numeric extractor certainty (§4.3).
 */
export function confidenceToNumeric(confidence: Confidence): number {
  return CONFIDENCE_NUMERIC[confidence];
}

/**
 * Per-occurrence contribution before saturation (§4.1).
 *
 * MVP defaults: location, reachability and novelty factors are 1.0 unless
 * finding metadata overrides them.
 */
export function perOccurrenceContribution(
  rule: RuleWeight,
  finding: Finding,
): number {
  if (rule.weight === 0) return 0;

  let confidence = confidenceToNumeric(finding.confidence);
  if (finding.metadata.minifiedSource === true) {
    confidence *= 0.7;
  }
  if (confidence < CONFIDENCE_HARD_GATE) return 0;

  const locationFactor = readNumericMetadata(finding, "locationFactor", 1);
  const reachabilityFactor = readNumericMetadata(finding, "reachabilityFactor", 1);
  const noveltyFactor = finding.metadata.novelInVersion === true ? 1.35 : 1;

  return (
    rule.weight * confidence * locationFactor * reachabilityFactor * noveltyFactor
  );
}

function readNumericMetadata(
  finding: Finding,
  key: string,
  fallback: number,
): number {
  const value = finding.metadata[key];
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}
