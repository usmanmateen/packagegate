import type { Theme } from "./output/theme.js";
import { createTheme } from "./output/theme.js";
import type { SecurityDiff } from "@packagegate/shared";

export function formatSecurityDiffReport(
  diff: SecurityDiff,
  options: { readonly color?: boolean; readonly theme?: Theme } = {},
): string {
  const theme =
    options.theme ?? createTheme({ enabled: options.color === true });
  const lines: string[] = [];
  const push = (line = ""): void => {
    lines.push(line);
  };

  push(theme.heading("PACKAGEGATE SECURITY DIFF"));
  push(theme.muted("========================="));
  push("");
  push(`Package:   ${theme.heading(diff.packageName)}`);
  push(
    `Versions:  ${theme.info(diff.fromVersion)} ${theme.muted("→")} ${theme.info(diff.toVersion)}`,
  );
  push(
    `Change:    ${
      diff.changeSignificance === "LOW"
        ? theme.muted(diff.changeSignificance)
        : theme.warning(diff.changeSignificance)
    } significance`,
  );
  push("");

  push(theme.heading("Lifecycle"));
  push(theme.muted("---------"));
  if (diff.lifecycleAdded.length === 0 && diff.lifecycleRemoved.length === 0) {
    push(theme.muted("  No install-lifecycle changes."));
  } else {
    for (const script of diff.lifecycleAdded) {
      push(`  ${theme.warning("+")} ${theme.info(script.name)}: ${theme.muted(script.command)}`);
    }
    for (const script of diff.lifecycleRemoved) {
      push(`  ${theme.muted("-")} ${script.name}: ${script.command}`);
    }
  }
  push("");

  push(theme.heading("Findings"));
  push(theme.muted("--------"));
  if (diff.findingsAdded.length === 0 && diff.findingsRemoved.length === 0) {
    push(theme.muted("  No semantic finding changes."));
  } else {
    for (const finding of diff.findingsAdded.slice(0, 15)) {
      push(
        `  ${theme.warning("+")} ${theme.info(finding.category)} — ${finding.title}`,
      );
    }
    for (const finding of diff.findingsRemoved.slice(0, 10)) {
      push(`  ${theme.muted("-")} ${finding.category} — ${finding.title}`);
    }
  }
  push("");

  push(theme.heading("Behaviour chains"));
  push(theme.muted("----------------"));
  if (diff.chainsAdded.length === 0 && diff.chainsRemoved.length === 0) {
    push(theme.muted("  No chain changes."));
  } else {
    for (const chain of diff.chainsAdded) {
      const label =
        typeof chain.metadata.chainType === "string"
          ? chain.metadata.chainType
          : `${chain.source}→${chain.sink}`;
      push(
        `  ${theme.warning("+")} ${theme.emphasis(label)} [${theme.colourConfidence(chain.confidence, chain.confidence)}]`,
      );
      push(`    ${theme.muted(chain.rationale)}`);
    }
    for (const chain of diff.chainsRemoved) {
      const label =
        typeof chain.metadata.chainType === "string"
          ? chain.metadata.chainType
          : `${chain.source}→${chain.sink}`;
      push(`  ${theme.muted("-")} ${label}`);
    }
  }
  push("");

  if (diff.opaqueSourcesAdded.length > 0) {
    push(theme.heading("Opaque / large source"));
    push(theme.muted("---------------------"));
    for (const opaque of diff.opaqueSourcesAdded) {
      push(
        `  ${theme.warning("+")} ${opaque.path}` +
          (opaque.sizeBytes === undefined
            ? ""
            : ` (${theme.muted(`${String(opaque.sizeBytes)} bytes`)})`),
      );
    }
    push("");
  }

  if (diff.destinationsAdded.length > 0) {
    push(theme.heading("Network destinations added"));
    for (const dest of diff.destinationsAdded.slice(0, 10)) {
      push(`  ${theme.warning("+")} ${theme.info(dest)}`);
    }
    push("");
  }

  push(theme.heading("Risk delta"));
  push(theme.muted("----------"));
  push(
    `  Before: ${theme.colourRiskScore(diff.riskBefore.score, diff.riskBefore.recommendation)} ${theme.colourRecommendation(diff.riskBefore.recommendation)}`,
  );
  push(
    `  After:  ${theme.colourRiskScore(diff.riskAfter.score, diff.riskAfter.recommendation)} ${theme.colourRecommendation(diff.riskAfter.recommendation)}`,
  );
  const deltaSign = diff.riskDelta >= 0 ? "+" : "";
  push(`  Delta:  ${theme.info(`${deltaSign}${String(diff.riskDelta)}`)}`);
  push("");

  push(theme.heading("Policy"));
  push(theme.muted("------"));
  push(
    `  Completeness: ${diff.completenessBefore.status} ${theme.muted("→")} ${diff.completenessAfter.status}`,
  );
  push(
    `  Final:        ${theme.colourRecommendation(diff.policyBefore.finalAction)} ${theme.muted("→")} ${theme.colourRecommendation(diff.policyAfter.finalAction)}`,
  );
  push("");

  push(theme.heading("Investigation summary"));
  push(theme.muted("---------------------"));
  push(`  ${diff.summary}`);
  push("");
  push(
    theme.muted(
      "Security diffs describe capability changes between versions. They are not malware verdicts.",
    ),
  );

  return lines.join("\n");
}
