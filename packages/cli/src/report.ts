import type { InvestigationResult } from "./types.js";

/**
 * Human-readable investigation report for demos and terminal review.
 *
 * Writes to a string so the CLI can print it and tests can assert on it
 * without depending on process.stdout.
 */
export function formatInvestigationReport(result: InvestigationResult): string {
  const lines: string[] = [];
  const push = (line = ""): void => {
    lines.push(line);
  };

  push("PACKAGEGATE INVESTIGATION");
  push("=========================");
  push("");
  push(`Package:        ${result.resolved.name}@${result.resolved.version}`);
  push(`Requested:      ${result.requestedSpec}`);
  push(`Duration:       ${String(result.durationMs)}ms`);
  push("");

  push("Artifact");
  push("--------");
  const integrity =
    result.artifact.integrityVerified === true
      ? "Integrity verified"
      : result.artifact.integrityVerified === false
        ? "Integrity MISMATCH"
        : "Integrity not declared";
  push(`  ${integrity}`);
  push(`  SHA-256: ${result.artifact.sha256}`);
  push(`  Files extracted: ${String(result.artifact.fileCount)}`);
  push(`  Files analysed:  ${String(result.files.filter((file) => file.analysed).length)}`);
  push(
    `  Analysis coverage: ${(result.analysisCoverage * 100).toFixed(1)}%`,
  );
  push("");

  push("Lifecycle scripts");
  push("-----------------");
  if (result.lifecycleScripts.length === 0) {
    push("  (none)");
  } else {
    for (const script of result.lifecycleScripts) {
      const flag = script.runsOnInstall ? " [install]" : "";
      push(`  ${script.name}${flag}: ${script.command}`);
    }
  }
  push("");

  push(`Findings (${String(result.findings.length)})`);
  push("--------");
  if (result.findings.length === 0) {
    push("  No rule matches in the code that was analysed.");
    push(`  ${result.disclaimer}`);
  } else {
    const byCategory = new Map<string, number>();
    for (const finding of result.findings) {
      byCategory.set(finding.category, (byCategory.get(finding.category) ?? 0) + 1);
    }
    const summary = [...byCategory.entries()]
      .sort((left, right) => right[1] - left[1])
      .map(([category, count]) => `${category}=${String(count)}`)
      .join(", ");
    push(`  By category: ${summary}`);
    push("");
    const sample = result.findings.slice(0, 20);
    for (const finding of sample) {
      push(
        `  [${finding.severity}/${finding.confidence}] ${finding.category} — ${finding.title}`,
      );
      push(
        `    ${finding.location.filePath}:${String(finding.location.startLine)}  (${finding.ruleId})`,
      );
    }
    if (result.findings.length > sample.length) {
      push(`  … and ${String(result.findings.length - sample.length)} more`);
    }
  }
  push("");

  if (result.parseFailures.length > 0) {
    push(`Parse failures (${String(result.parseFailures.length)})`);
    push("--------------");
    for (const failure of result.parseFailures.slice(0, 10)) {
      push(`  ${failure.filePath}: ${failure.reason}`);
    }
    push("");
  }

  push(`Behaviour chains (${String(result.behaviourChains.length)})`);
  push("----------------");
  if (result.behaviourChains.length === 0) {
    push("  None with evidenced dataflow.");
  } else {
    for (const chain of result.behaviourChains) {
      const transforms =
        chain.transformations.length === 0
          ? ""
          : ` → ${chain.transformations.join(" → ")}`;
      push(
        `  ${chain.source}${transforms} → ${chain.sink}  [${chain.confidence}]`,
      );
      push(`    ${chain.rationale}`);
      for (const link of chain.links) {
        push(
          `    link/${link.kind}: ${link.description} @ ${link.location.filePath}:${String(link.location.startLine)}`,
        );
      }
    }
  }
  push("");

  push("Risk");
  push("----");
  push(`  Score:            ${String(result.risk.score)} / 100`);
  push(`  Recommendation:   ${result.risk.recommendation}`);
  push(`  Classification:   ${result.risk.classification}`);
  push("");

  push("Risk breakdown");
  push("--------------");
  const breakdown = result.scoringBreakdown;
  push(`  Breadth (B):          ${breakdown.breadthRaw.toFixed(2)}`);
  push(`  Chains (X):           ${breakdown.chainSaturated.toFixed(2)}`);
  push(`  Modifiers (M):        ${breakdown.modifierTotal.toFixed(2)}`);
  push(`  Structural cap:       ${String(breakdown.structuralCap)}`);
  push(`  Raw total:            ${breakdown.rawTotal.toFixed(2)}`);
  push(`  Final score:          ${String(breakdown.score)}`);
  if (breakdown.familyBreakdown.length > 0) {
    push("  Families (after decay):");
    for (const family of breakdown.familyBreakdown.slice(0, 8)) {
      push(
        `    ${family.family}: ${family.decayedPoints.toFixed(2)} (rank ${String(family.decayRank)}, factor ${family.decayFactor.toFixed(2)})`,
      );
    }
  }
  push("");
  push("Contributions");
  push("-------------");
  for (const contribution of result.risk.contributions.slice(0, 15)) {
    const sign = contribution.points >= 0 ? "+" : "";
    push(
      `  ${contribution.label.padEnd(36)} ${sign}${contribution.points.toFixed(2)}`,
    );
  }
  if (result.risk.contributions.length > 15) {
    push(`  … and ${String(result.risk.contributions.length - 15)} more`);
  }
  push("");
  push(result.disclaimer);
  push("");
  push(
    `scanner=${result.scannerVersion}  rules=${result.rulesVersion}  risk=${result.risk.scannerVersion}`,
  );

  return lines.join("\n");
}
