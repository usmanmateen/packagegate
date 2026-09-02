import type { BehaviourChain, Confidence, Severity } from "@packagegate/shared";
import type { Theme } from "./output/theme.js";
import { createTheme } from "./output/theme.js";
import type { AcquisitionInfo, InvestigationResult } from "./types.js";

export interface ReportOptions {
  /**
   * When true/false, force colour. When omitted, colour is off so library
   * callers and tests get plain text; the CLI enables colour via TTY checks.
   */
  readonly color?: boolean;
  readonly theme?: Theme;
}

/** Human labels for chain nodes — display only; underlying enums unchanged. */
const CHAIN_NODE_LABELS: Readonly<Record<string, string>> = {
  ENVIRONMENT_ACCESS: "process.env",
  SENSITIVE_FILE_READ: "sensitive file",
  FILESYSTEM_READ: "fs.read",
  SYSTEM_INFORMATION: "host info",
  ENCODED_CONSTANT: "encoded payload",
  REMOTE_DOWNLOAD: "remote download",
  PROCESS_OUTPUT: "process output",
  OBJECT_COLLECTION: "collect",
  JSON_SERIALIZATION: "JSON.stringify",
  STRING_CONCATENATION: "concat",
  BASE64_ENCODE: "base64 encode",
  BASE64_DECODE: "base64 decode",
  HEX_ENCODE: "hex encode",
  HEX_DECODE: "hex decode",
  COMPRESSION: "compress",
  ENCRYPTION: "encrypt",
  HASHING: "hash",
  TEMPLATE_INTERPOLATION: "template",
  NETWORK_REQUEST: "https.request",
  SOCKET_WRITE: "socket.write",
  FILESYSTEM_WRITE: "fs.write",
  EXECUTABLE_WRITE: "executable write",
  PROCESS_EXECUTION: "child_process",
  DYNAMIC_EVALUATION: "eval",
};

function nodeLabel(node: string): string {
  return CHAIN_NODE_LABELS[node] ?? node;
}

function formatFindingBadge(
  severity: Severity,
  confidence: Confidence,
  theme: Theme,
): string {
  const severityPart = theme.colourSeverity(severity, `${severity} severity`);
  const confidencePart = theme.colourConfidence(confidence, `${confidence} confidence`);
  return `[${severityPart} · ${confidencePart}]`;
}

function formatSourceLine(acquisition: AcquisitionInfo, theme: Theme): string {
  switch (acquisition.source) {
    case "REGISTRY":
      return theme.info("npm registry");
    case "LOCAL":
      return theme.warning("Local tarball");
    case "FIXTURE":
      return theme.info("Inert fixture");
    default: {
      const _exhaustive: never = acquisition.source;
      return _exhaustive;
    }
  }
}

function formatIntegrityLines(result: InvestigationResult, theme: Theme): string[] {
  const lines: string[] = [];
  const { acquisition } = result;

  if (acquisition.suppliedDigest?.matched === true) {
    lines.push(theme.success("✓ Supplied SHA-256 verified"));
  }

  switch (acquisition.registryIntegrity.status) {
    case "VERIFIED":
      lines.push(theme.success("✓ Registry integrity verified"));
      break;
    case "UNSUPPORTED":
      lines.push(theme.warning("⚠ Registry integrity unsupported"));
      break;
    case "NOT_DECLARED":
      lines.push(theme.warning("? Registry integrity not declared"));
      break;
    case "NOT_APPLICABLE":
      lines.push(theme.warning("⚠ Registry integrity not verified"));
      lines.push(theme.muted(`  ${acquisition.registryIntegrity.reason}`));
      break;
    default: {
      const _exhaustive: never = acquisition.registryIntegrity.status;
      return _exhaustive;
    }
  }

  return lines;
}

function formatChainPath(chain: BehaviourChain, theme: Theme): string {
  const nodes = [chain.source, ...chain.transformations, chain.sink];
  const arrow = theme.muted(" → ");
  const rendered = nodes.map((node, index) => {
    const label = nodeLabel(node);
    const isEndpoint = index === 0 || index === nodes.length - 1;
    if (!isEndpoint) return theme.info(label);
    return theme.emphasis(label);
  });
  return rendered.join(arrow);
}

/**
 * Human-readable investigation report for demos and terminal review.
 *
 * Writes to a string so the CLI can print it and tests can assert on it
 * without depending on process.stdout. Colour is optional and never affects
 * the underlying investigation data.
 */
export function formatInvestigationReport(
  result: InvestigationResult,
  options: ReportOptions = {},
): string {
  const theme =
    options.theme ??
    createTheme({
      enabled: options.color === true,
    });

  const lines: string[] = [];
  const push = (line = ""): void => {
    lines.push(line);
  };

  push(theme.heading("PACKAGEGATE INVESTIGATION"));
  push(theme.muted("========================="));
  push("");
  const packageId = `${result.resolved.name}@${result.resolved.version}`;
  push(`Package:          ${theme.heading(packageId)}`);
  push(`Source:           ${formatSourceLine(result.acquisition, theme)}`);
  if (result.acquisition.localPath !== undefined) {
    push(`Artifact path:    ${theme.info(result.acquisition.localPath)}`);
  } else {
    push(`Requested:        ${theme.info(result.requestedSpec)}`);
  }
  push(`Duration:         ${theme.muted(`${String(result.durationMs)}ms`)}`);
  push("");

  push(theme.heading("Artifact"));
  push(theme.muted("--------"));
  for (const line of formatIntegrityLines(result, theme)) {
    push(`  ${line}`);
  }
  push(`  ${theme.muted("SHA-256:")} ${theme.info(result.artifact.sha256)}`);
  push(
    `  ${theme.muted("Files extracted:")} ${theme.info(String(result.artifact.fileCount))}`,
  );
  push(
    `  ${theme.muted("Files analysed:")}  ${theme.info(String(result.files.filter((file) => file.analysed).length))}`,
  );
  push(
    `  ${theme.muted("Analysis coverage:")} ${theme.info(`${(result.analysisCoverage * 100).toFixed(1)}%`)}`,
  );
  push("");

  push(theme.heading("Lifecycle scripts"));
  push(theme.muted("-----------------"));
  if (result.lifecycleScripts.length === 0) {
    push(theme.muted("  (none)"));
  } else {
    for (const script of result.lifecycleScripts) {
      const flag = script.runsOnInstall ? theme.warning(" [install]") : "";
      push(`  ${theme.info(script.name)}${flag}: ${theme.muted(script.command)}`);
    }
  }
  push("");

  push(theme.heading(`Findings (${String(result.findings.length)})`));
  push(theme.muted("--------"));
  if (result.findings.length === 0) {
    push(theme.success("  No rule matches in the code that was analysed."));
    push(`  ${theme.muted(result.disclaimer)}`);
  } else {
    const byCategory = new Map<string, number>();
    for (const finding of result.findings) {
      byCategory.set(finding.category, (byCategory.get(finding.category) ?? 0) + 1);
    }
    const summary = [...byCategory.entries()]
      .sort((left, right) => right[1] - left[1])
      .map(([category, count]) => `${category}=${String(count)}`)
      .join(", ");
    push(`  ${theme.muted("By category:")} ${theme.info(summary)}`);
    push("");
    const sample = result.findings.slice(0, 20);
    for (const finding of sample) {
      push(
        `  ${formatFindingBadge(finding.severity, finding.confidence, theme)} ${theme.info(finding.category)} — ${finding.title}`,
      );
      push(
        `    ${theme.muted(`${finding.location.filePath}:${String(finding.location.startLine)}`)}  ${theme.muted(`(${finding.ruleId})`)}`,
      );
    }
    if (result.findings.length > sample.length) {
      push(theme.muted(`  … and ${String(result.findings.length - sample.length)} more`));
    }
  }
  push("");

  if (result.parseFailures.length > 0) {
    push(theme.warning(`Parse failures (${String(result.parseFailures.length)})`));
    push(theme.muted("--------------"));
    for (const failure of result.parseFailures.slice(0, 10)) {
      push(`  ${theme.muted(failure.filePath)}: ${theme.warning(failure.reason)}`);
    }
    push("");
  }

  push(theme.heading(`Behaviour chains (${String(result.behaviourChains.length)})`));
  push(theme.muted("----------------"));
  if (result.behaviourChains.length === 0) {
    push(theme.success("  None with evidenced dataflow."));
    push(
      theme.muted(
        "  (No evidenced chain was established — this is not proof the package is safe.)",
      ),
    );
  } else {
    for (const chain of result.behaviourChains) {
      const path = formatChainPath(chain, theme);
      const confidenceTag = theme.colourConfidence(chain.confidence, chain.confidence);
      const marker =
        result.risk.recommendation === "BLOCK" ? theme.danger("●") : theme.warning("●");
      push(`  ${marker} ${path}  [${confidenceTag}]`);
      push(`    ${theme.muted(chain.rationale)}`);
      for (const link of chain.links) {
        push(
          `    ${theme.muted(`link/${link.kind}:`)} ${link.description} ${theme.muted(`@ ${link.location.filePath}:${String(link.location.startLine)}`)}`,
        );
      }
    }
  }
  push("");

  push(theme.heading("Analysis completeness"));
  push(theme.muted("---------------------"));
  const completeness = result.analysisCompleteness;
  if (completeness.status === "COMPLETE") {
    push(`  ${theme.success("COMPLETE")}`);
  } else if (completeness.status === "DEGRADED") {
    push(`  ${theme.warning(`⚠ ${completeness.status}`)}`);
  } else {
    push(`  ${theme.danger(`⚠ ${completeness.status}`)}`);
  }
  push(
    `  ${theme.muted("Coverage ratio:")} ${theme.info(`${(completeness.coverageRatio * 100).toFixed(1)}%`)}`,
  );
  if (completeness.reasons.length === 0) {
    push(theme.muted("  No completeness gaps recorded."));
  } else {
    for (const reason of completeness.reasons.slice(0, 8)) {
      const pathBit = reason.path === undefined ? "" : ` ${theme.muted(reason.path)}`;
      push(`  ${theme.warning("•")} ${reason.code}${pathBit}`);
      push(`    ${theme.muted(reason.message)}`);
      if (reason.lifecycleReachable === true) {
        push(`    ${theme.warning("Lifecycle reachable: yes")}`);
      }
      if (reason.sizeBytes !== undefined) {
        push(`    ${theme.muted(`Size: ${String(reason.sizeBytes)} bytes`)}`);
      }
    }
    if (completeness.reasons.length > 8) {
      push(theme.muted(`  … and ${String(completeness.reasons.length - 8)} more`));
    }
  }
  push(
    theme.muted(
      "  Behavioural score does not include behaviour in unanalysed executable source.",
    ),
  );
  push("");

  push(theme.heading("Behavioural risk"));
  push(theme.muted("----------------"));
  const scoreText = theme.colourRiskScore(result.risk.score, result.risk.recommendation);
  push(`  Score:            ${scoreText} ${theme.muted("/ 100")}`);
  push(`  Recommendation:   ${theme.colourRecommendation(result.risk.recommendation)}`);
  push(`  Classification:   ${theme.colourClassification(result.risk.classification)}`);
  push("");

  push(theme.heading("ML analysis"));
  push(theme.muted("-----------"));
  if (result.ml.status === "DISABLED") {
    push(theme.muted("  Status: DISABLED (deterministic lanes only)"));
  } else if (result.ml.status === "ERROR") {
    push(`  Status: ${theme.warning("ERROR")}`);
    if (result.ml.errorMessage) {
      push(`  ${theme.muted(result.ml.errorMessage)}`);
    }
  } else {
    push(`  Status: ${theme.info(result.ml.status)}`);
    if (result.ml.modelId) {
      push(
        `  Model:  ${theme.info(result.ml.modelId)}${result.ml.modelVersion ? ` (${result.ml.modelVersion})` : ""}`,
      );
    }
    const prob = result.ml.calibratedProbability ?? result.ml.maliciousProbability;
    if (prob !== undefined) {
      push(
        `  Malicious-pattern probability: ${theme.info((prob * 100).toFixed(0) + "%")}${
          result.ml.calibratedProbability !== undefined
            ? theme.muted(" (calibrated)")
            : ""
        }`,
      );
    }
    push(
      theme.muted(
        "  ML ranks suspicious composition; it does not invent deterministic evidence.",
      ),
    );
    for (const slice of result.ml.topSlices.slice(0, 3)) {
      push(
        `  • ${theme.info(slice.file)}:${String(slice.startLine)}–${String(slice.endLine)} (score ${(slice.score * 100).toFixed(0)}%)`,
      );
    }
  }
  push("");

  push(theme.heading("Final policy"));
  push(theme.muted("------------"));
  push(
    `  Analysis completeness: ${
      result.policy.analysisCompleteness === "COMPLETE"
        ? theme.success(result.policy.analysisCompleteness)
        : theme.warning(result.policy.analysisCompleteness)
    }`,
  );
  push(
    `  Threat intelligence:   ${
      result.threatIntelligence.status === "KNOWN_MALICIOUS" ||
      result.threatIntelligence.status === "KNOWN_COMPROMISED"
        ? theme.danger(result.threatIntelligence.status)
        : theme.muted(result.threatIntelligence.status)
    }`,
  );
  if (result.threatIntelligence.matches[0]) {
    const match = result.threatIntelligence.matches[0];
    push(
      `  Intel match:           ${theme.info(match.source)} (${match.matchedBy} / ${match.referenceId})`,
    );
  }
  if (result.threatIntelligence.lookupFailed) {
    push(
      `  ${theme.warning("⚠ Threat intelligence lookup failed — behavioural result retained.")}`,
    );
  }
  push(
    `  Final action:          ${theme.colourRecommendation(result.policy.finalAction)}`,
  );
  for (const reason of result.policy.reasons) {
    push(`  ${theme.muted(`• ${reason.code}:`)} ${reason.message}`);
  }
  push("");

  push(theme.heading("Decision"));
  push(theme.muted("--------"));
  for (const line of result.decisionExplanation) {
    push(`  ${theme.muted("•")} ${line}`);
  }
  push("");

  push(theme.heading("Risk breakdown"));
  push(theme.muted("--------------"));
  const breakdown = result.scoringBreakdown;
  push(
    `  ${theme.muted("Breadth (B):")}          ${theme.info(breakdown.breadthRaw.toFixed(2))}`,
  );
  push(
    `  ${theme.muted("Chains (X):")}           ${theme.info(breakdown.chainSaturated.toFixed(2))}`,
  );
  push(
    `  ${theme.muted("Modifiers (M):")}        ${theme.info(breakdown.modifierTotal.toFixed(2))}`,
  );
  push(
    `  ${theme.muted("Structural cap:")}       ${theme.info(String(breakdown.structuralCap))}`,
  );
  push(
    `  ${theme.muted("Raw total:")}            ${theme.info(breakdown.rawTotal.toFixed(2))}`,
  );
  push(
    `  ${theme.muted("Final score:")}          ${theme.colourRiskScore(breakdown.score, result.risk.recommendation)}`,
  );
  if (breakdown.familyBreakdown.length > 0) {
    push(theme.muted("  Families (after decay):"));
    for (const family of breakdown.familyBreakdown.slice(0, 8)) {
      push(
        `    ${theme.info(family.family)}: ${theme.info(family.decayedPoints.toFixed(2))} ${theme.muted(`(rank ${String(family.decayRank)}, factor ${family.decayFactor.toFixed(2)})`)}`,
      );
    }
  }
  push("");
  push(theme.heading("Contributions"));
  push(theme.muted("-------------"));
  for (const contribution of result.risk.contributions.slice(0, 15)) {
    const sign = contribution.points >= 0 ? "+" : "";
    const points = `${sign}${contribution.points.toFixed(2)}`;
    const pointsStyled =
      contribution.points < 0
        ? theme.success(points)
        : contribution.points > 0
          ? theme.info(points)
          : theme.muted(points);
    push(`  ${contribution.label.padEnd(36)} ${pointsStyled}`);
  }
  if (result.risk.contributions.length > 15) {
    push(theme.muted(`  … and ${String(result.risk.contributions.length - 15)} more`));
  }
  push("");
  push(theme.muted(result.disclaimer));
  push("");
  push(
    theme.muted(
      `scanner=${result.scannerVersion}  rules=${result.rulesVersion}  risk=${result.risk.scannerVersion}`,
    ),
  );

  return lines.join("\n");
}
