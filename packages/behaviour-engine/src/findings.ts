import type { Finding, FindingCategory, SourceLocation } from "@packagegate/shared";
import { SOURCE_CATEGORIES, SINK_CATEGORIES } from "./categories.js";
import { locationsOverlap } from "./location.js";

/** Group findings by their file path. */
export function groupFindingsByFile(
  findings: readonly Finding[],
): Map<string, Finding[]> {
  const grouped = new Map<string, Finding[]>();
  for (const finding of findings) {
    const filePath = finding.location.filePath;
    const existing = grouped.get(filePath);
    if (existing === undefined) {
      grouped.set(filePath, [finding]);
    } else {
      existing.push(finding);
    }
  }
  return grouped;
}

/** Findings whose category and location match an analysis step. */
export function matchFindings(
  findings: readonly Finding[],
  categories: ReadonlySet<FindingCategory>,
  location: SourceLocation,
): Finding[] {
  return findings.filter(
    (finding) =>
      categories.has(finding.category) && locationsOverlap(finding.location, location),
  );
}

export function matchSourceFindings(
  findings: readonly Finding[],
  location: SourceLocation,
): Finding[] {
  return matchFindings(findings, SOURCE_CATEGORIES, location);
}

export function matchSinkFindings(
  findings: readonly Finding[],
  location: SourceLocation,
): Finding[] {
  return matchFindings(findings, SINK_CATEGORIES, location);
}

/** Index input files by path for quick lookup. */
export function indexFiles(
  files: readonly { path: string; content: string }[],
): Map<string, string> {
  return new Map(files.map((file) => [file.path, file.content]));
}
