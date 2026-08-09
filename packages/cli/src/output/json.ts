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
    acquisition: {
      source: result.acquisition.source,
      ...(result.acquisition.localPath === undefined
        ? {}
        : { localPath: result.acquisition.localPath }),
      registryIntegrity: result.acquisition.registryIntegrity,
      ...(result.acquisition.suppliedDigest === undefined
        ? {}
        : { suppliedDigest: result.acquisition.suppliedDigest }),
    },
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
    artifact: {
      ...result.artifact,
      integrity: {
        status: result.acquisition.registryIntegrity.status,
        reason: result.acquisition.registryIntegrity.reason,
        ...(result.acquisition.suppliedDigest === undefined
          ? {}
          : {
              suppliedSha256: result.acquisition.suppliedDigest.expectedSha256,
              suppliedSha256Matched: result.acquisition.suppliedDigest.matched,
            }),
      },
    },
    lifecycleScripts: result.lifecycleScripts,
    files: result.files,
    findings: result.findings,
    parseFailures: result.parseFailures,
    behaviourChains: result.behaviourChains,
    risk: result.risk,
    behaviouralRisk: {
      score: result.risk.score,
      recommendation: result.risk.recommendation,
      classification: result.risk.classification,
    },
    scoringBreakdown: result.scoringBreakdown,
    analysisCoverage: result.analysisCoverage,
    analysisCompleteness: result.analysisCompleteness,
    threatIntelligence: result.threatIntelligence,
    finalPolicy: result.policy,
    policy: result.policy,
    decisionExplanation: result.decisionExplanation,
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
