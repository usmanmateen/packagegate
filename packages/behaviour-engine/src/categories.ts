import type { FindingCategory } from "@packagegate/shared";

/** Finding categories that indicate interesting data origins. */
export const SOURCE_CATEGORIES: ReadonlySet<FindingCategory> = new Set([
  "ENVIRONMENT_ACCESS",
  "CREDENTIAL_RELATED_ACCESS",
  "SENSITIVE_FILE_ACCESS",
  "ENCODED_PAYLOAD",
]);

/** Finding categories that indicate dangerous destinations. */
export const SINK_CATEGORIES: ReadonlySet<FindingCategory> = new Set([
  "NETWORK_ACCESS",
  "DYNAMIC_CODE_EXECUTION",
  "PROCESS_EXECUTION",
  "FILESYSTEM_WRITE",
]);

export function hasSourceFinding(
  findings: readonly { category: FindingCategory }[],
): boolean {
  return findings.some((finding) => SOURCE_CATEGORIES.has(finding.category));
}

export function hasSinkFinding(
  findings: readonly { category: FindingCategory }[],
): boolean {
  return findings.some((finding) => SINK_CATEGORIES.has(finding.category));
}
