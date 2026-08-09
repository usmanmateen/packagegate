import type { InvestigationResult } from "../types.js";

/**
 * Machine-readable investigation payload.
 *
 * Must never include ANSI escape sequences — callers serialise this object
 * with `JSON.stringify` for `--json` output.
 */
export function investigationToJson(result: InvestigationResult): unknown {
  return {
    requestedSpec: result.requestedSpec,
    resolved: result.resolved,
    metadata: {
      name: result.metadata.name,
      version: result.metadata.version,
      description: result.metadata.description,
      license: result.metadata.license,
      repositoryUrl: result.metadata.repositoryUrl,
      deprecated: result.metadata.deprecated,
      scripts: result.metadata.scripts,
      dist: result.metadata.dist,
    },
    artifact: result.artifact,
    lifecycleScripts: result.lifecycleScripts,
    files: result.files,
    findings: result.findings,
    parseFailures: result.parseFailures,
    behaviourChains: result.behaviourChains,
    risk: result.risk,
    scoringBreakdown: result.scoringBreakdown,
    analysisCoverage: result.analysisCoverage,
    startedAt: result.startedAt,
    completedAt: result.completedAt,
    durationMs: result.durationMs,
    scannerVersion: result.scannerVersion,
    rulesVersion: result.rulesVersion,
    disclaimer: result.disclaimer,
  };
}

export function formatInvestigationJson(result: InvestigationResult): string {
  return `${JSON.stringify(investigationToJson(result), null, 2)}\n`;
}
