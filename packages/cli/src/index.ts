export { scanPackage, SCANNER_VERSION } from "./scan.js";
export { scanLocalTarball } from "./scan-tarball.js";
export { investigateSources } from "./investigate.js";
export { investigateExtractedPackage } from "./pipeline.js";
export { formatInvestigationReport } from "./report.js";
export { formatInvestigationJson, investigationToJson } from "./output/json.js";
export {
  createTheme,
  shouldUseColor,
  recommendationStyle,
  classificationStyle,
  severityStyle,
  confidenceStyle,
  stripAnsi,
} from "./output/theme.js";
export type { Theme, ThemeOptions, StyleKind } from "./output/theme.js";
export {
  SAFETY_DISCLAIMER,
  type InvestigationResult,
  type AcquisitionInfo,
  type AcquisitionSource,
} from "./types.js";
