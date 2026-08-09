export { scanPackage, SCANNER_VERSION } from "./scan.js";
export { investigateSources } from "./investigate.js";
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
} from "./types.js";
