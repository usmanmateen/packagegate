import { decidePolicy } from "@packagegate/policy-engine";
import { disabledMlAssessment, type MlAssessment } from "@packagegate/shared";
import { buildDecisionExplanation } from "../decision.js";
import type { InvestigationResult } from "../types.js";
import { exportPackageGateMlRecord } from "./export.js";
import { createMlProviderFromEnv, LocalMlProvider, type MlProvider } from "./provider.js";

export interface ApplyMlOptions {
  readonly enabled?: boolean;
  readonly provider?: MlProvider;
  readonly sourceByPath?: ReadonlyMap<string, string>;
}

/**
 * Attach optional ML assessment without mutating behavioural risk.
 * Failures leave deterministic results intact.
 */
export async function withMlAssessment(
  result: InvestigationResult,
  options: ApplyMlOptions = {},
): Promise<InvestigationResult> {
  const envMode = (process.env.PACKAGEGATE_ML ?? "disabled").toLowerCase();
  const enabled =
    options.enabled === true ||
    envMode === "local" ||
    envMode === "1" ||
    envMode === "true";

  if (!enabled) {
    return finalise(result, disabledMlAssessment());
  }

  // --ml defaults to the local Python worker; PACKAGEGATE_ML=local does the same.
  const provider =
    options.provider ??
    (envMode === "disabled" || envMode === "0" || envMode === "false"
      ? new LocalMlProvider()
      : createMlProviderFromEnv());

  const exportRecord = exportPackageGateMlRecord(result, {
    sourceByPath: options.sourceByPath,
  });
  const ml = await provider.assess(exportRecord);
  return finalise(result, ml);
}

function finalise(result: InvestigationResult, ml: MlAssessment): InvestigationResult {
  const policy = decidePolicy({
    behaviouralRecommendation: result.risk.recommendation,
    analysisCompleteness: result.analysisCompleteness,
    threatIntelligence: result.threatIntelligence.status,
    mlSupportsReviewEscalation: ml.supportsReviewEscalation === true,
  });

  const next: InvestigationResult = {
    ...result,
    ml,
    policy,
    decisionExplanation: [],
  };
  return {
    ...next,
    decisionExplanation: buildDecisionExplanation(next),
  };
}
