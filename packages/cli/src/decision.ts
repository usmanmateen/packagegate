import type { InvestigationResult } from "./types.js";

/**
 * Analyst-facing reasons for the final policy action.
 * Separate lanes stay visible — behavioural score is never rewritten here.
 */
export function buildDecisionExplanation(result: InvestigationResult): string[] {
  const lines: string[] = [];
  lines.push(`Final action: ${result.policy.finalAction}`);

  const installChains = result.behaviourChains.filter(
    (chain) =>
      chain.metadata.chainType === "INSTALL_TIME_REMOTE_EXECUTION" ||
      (chain.source === "REMOTE_DOWNLOAD" &&
        chain.sink === "PROCESS_EXECUTION" &&
        chain.metadata.installTimeRooted === true),
  );
  if (installChains.length > 0) {
    for (const chain of installChains.slice(0, 3)) {
      lines.push(
        `${chain.confidence}-confidence install-time remote execution chain: ${chain.rationale}`,
      );
    }
  } else if (result.behaviourChains.length > 0) {
    lines.push(
      `Behavioural chains observed: ${String(result.behaviourChains.length)} (${result.behaviourChains
        .map((c) => {
          const typed = c.metadata.chainType;
          return typeof typed === "string" ? typed : `${c.source}→${c.sink}`;
        })
        .slice(0, 3)
        .join(", ")}).`,
    );
  } else {
    lines.push(
      `Behavioural recommendation ${result.risk.recommendation} at score ${String(result.risk.score)} with no evidenced behaviour chain.`,
    );
  }

  lines.push(
    `Analysis completeness: ${result.analysisCompleteness.status}` +
      (result.analysisCompleteness.reasons[0]
        ? ` (${result.analysisCompleteness.reasons[0].code}${
            result.analysisCompleteness.reasons[0].path
              ? ` @ ${result.analysisCompleteness.reasons[0].path}`
              : ""
          })`
        : ""),
  );

  const intel = result.threatIntelligence;
  if (intel.status === "NONE") {
    lines.push("Threat intelligence: NONE");
  } else {
    lines.push(
      `Threat intelligence: ${intel.status}` +
        (intel.matches[0]
          ? ` via ${intel.matches[0].source} (${intel.matches[0].matchedBy})`
          : intel.lookupFailed
            ? " (lookup failed)"
            : ""),
    );
  }

  for (const reason of result.policy.reasons) {
    lines.push(`Policy: ${reason.code} — ${reason.message}`);
  }

  lines.push(
    "This decision does not establish malicious intent by itself when behavioural evidence is incomplete.",
  );
  return lines;
}
