export { assessRisk, ENGINE_VERSION } from "./assess.js";
export { mapFindingToRule } from "./map-finding.js";
export { computeScoringBreakdown, familyContributions } from "./score.js";
export {
  saturateRule,
  saturateFamily,
  saturateChains,
  B3_RULE_SATURATION_TABLE,
} from "./saturation.js";
export { decideVerdict } from "./decision.js";
export { confidenceToNumeric, perOccurrenceContribution } from "./factors.js";
export { resolveChainPattern, linkageFactorForLinks } from "./chains.js";
export type { RiskEngineInput, ScoringBreakdown, FamilyBreakdownEntry } from "./types.js";
export {
  WEIGHTS_VERSION,
  RULE_WEIGHTS,
  FAMILY_CAPS,
  CHAIN_PATTERNS,
  COVERAGE_FLOOR,
} from "./weights.js";
