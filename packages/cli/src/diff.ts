import type { SecurityDiff } from "@packagegate/shared";
import {
  compareInvestigations,
  type DiffableInvestigation,
} from "@packagegate/version-diff";
import { scanPackage } from "./scan.js";
import type { InvestigationResult } from "./types.js";

export function toDiffable(result: InvestigationResult): DiffableInvestigation {
  return {
    resolved: result.resolved,
    lifecycleScripts: result.lifecycleScripts,
    findings: result.findings,
    behaviourChains: result.behaviourChains,
    analysisCompleteness: result.analysisCompleteness,
    risk: {
      score: result.risk.score,
      recommendation: result.risk.recommendation,
    },
    policy: result.policy,
    files: result.files,
  };
}

/**
 * Security semantic diff between two package versions.
 * Both sides are acquired through the existing static investigation pipeline.
 */
export async function diffPackages(
  fromSpec: string,
  toSpec: string,
): Promise<{
  readonly before: InvestigationResult;
  readonly after: InvestigationResult;
  readonly diff: SecurityDiff;
}> {
  const before = await scanPackage(fromSpec);
  const after = await scanPackage(toSpec);
  if (before.resolved.name !== after.resolved.name) {
    throw new Error(
      `diff requires the same package name (got ${before.resolved.name} vs ${after.resolved.name})`,
    );
  }
  const diff = compareInvestigations(toDiffable(before), toDiffable(after));
  return { before, after, diff };
}

export function diffInvestigations(
  before: InvestigationResult,
  after: InvestigationResult,
): SecurityDiff {
  return compareInvestigations(toDiffable(before), toDiffable(after));
}
